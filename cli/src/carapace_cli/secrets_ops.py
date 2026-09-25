"""Sealing secrets locally and managing them on the server.

The plaintext is sealed on this machine to the KMS key of the *verified*
enclave (from the pin), never to a key the server merely claims; the
server's key is fetched too and must match, or nothing is sealed. The
policy is bound into the envelope's owner signature and AAD, so the server
cannot widen it.
"""

from __future__ import annotations

import hmac
import uuid
from dataclasses import dataclass
from typing import Any

from carapace_cli.errors import CarapaceError, VerificationError
from carapace_cli.pin import EnclavePin, now_seconds
from carapace_cli.session import ServerClient
from carapace_cli.verify import check_server_kms_key
from carapace_crypto import (
    Envelope,
    EnvelopeError,
    OwnerKey,
    seal,
    verify_envelope_signature,
)

SECRET_PLACEHOLDER = "{secret}"  # noqa: S105 - a template marker
POLICY_VERSION = 1
ALLOWED_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
)
INJECTION_KINDS = frozenset({"header", "query", "basic_auth"})
DEFAULT_TEMPLATE = "Bearer {secret}"  # noqa: S105 - a template marker


class PolicyError(CarapaceError):
    """The requested injection policy is invalid."""


def build_policy(
    *,
    hosts: list[str],
    host_suffixes: list[str],
    methods: list[str],
    inject_kind: str,
    inject_name: str | None,
    template: str,
    ports: list[int] | None = None,
    limits: dict[str, int] | None = None,
) -> dict[str, Any]:
    """An injection policy v1. The enclave re-validates it strictly."""
    rules = [{"match": "exact", "value": h.lower()} for h in hosts]
    for suffix in host_suffixes:
        if not suffix.startswith("."):
            raise PolicyError(f"host suffix must start with '.': {suffix!r}")
        rules.append({"match": "suffix", "value": suffix.lower()})
    if not rules:
        raise PolicyError("at least one --host or --host-suffix is required")
    normalized_methods = sorted({m.upper() for m in methods})
    if not normalized_methods or not set(normalized_methods) <= ALLOWED_METHODS:
        raise PolicyError(f"methods must be among {sorted(ALLOWED_METHODS)}")
    if inject_kind not in INJECTION_KINDS:
        raise PolicyError(f"injection kind must be one of {sorted(INJECTION_KINDS)}")
    if template.count(SECRET_PLACEHOLDER) != 1:
        raise PolicyError("the template must contain {secret} exactly once")
    inject: dict[str, Any] = {"kind": inject_kind, "template": template}
    if inject_kind == "basic_auth":
        if inject_name is not None:
            raise PolicyError("basic_auth takes no --inject-name")
    elif not inject_name:
        raise PolicyError(f"{inject_kind} injection needs --inject-name")
    else:
        inject["name"] = inject_name
    policy: dict[str, Any] = {
        "v": POLICY_VERSION,
        "hosts": rules,
        "schemes": ["https"],
        "methods": normalized_methods,
        "inject": inject,
    }
    if ports:
        policy["ports"] = sorted(set(ports))
    if limits:
        policy["limits"] = dict(limits)
    return policy


@dataclass(frozen=True)
class SecretInfo:
    id: str
    name: str
    version: int
    owner_fingerprint: str
    policy: dict[str, Any]


def add_secret(
    server: ServerClient,
    owner_key: OwnerKey,
    pin: EnclavePin,
    *,
    name: str,
    policy: dict[str, Any],
    plaintext: bytearray,
) -> SecretInfo:
    """Seal ``plaintext`` to the pinned enclave's KMS key and upload it.

    The caller owns ``plaintext`` and should zero it afterwards.
    """
    check_server_kms_key(
        server,
        attested_pem=pin.kms_public_key_pem,
        attested_version=pin.kms_key_version,
    )
    secret_id = str(uuid.uuid4())
    try:
        envelope = seal(
            pin.kms_public_key_pem,
            secret_id,
            server.user_id,
            policy,
            plaintext,
            owner_key=owner_key,
            version=now_seconds(),
            kms_key_version=pin.kms_key_version,
        )
    except EnvelopeError as exc:
        raise CarapaceError(f"cannot seal secret: {exc}") from None
    body = server.post(
        "/v1/secrets", json={"name": name, "envelope": envelope.to_dict()}
    )
    return _secret_info(body)


def list_secrets(server: ServerClient) -> list[SecretInfo]:
    return [_secret_info(item) for item in server.get("/v1/secrets")]


def resolve_secret_id(server: ServerClient, ref: str) -> str:
    """``ref`` is a secret UUID or a unique secret name."""
    try:
        return str(uuid.UUID(ref))
    except ValueError:
        pass
    matches = [s.id for s in list_secrets(server) if s.name == ref]
    if not matches:
        raise CarapaceError(f"no secret named {ref!r}")
    if len(matches) > 1:
        raise CarapaceError(f"several secrets are named {ref!r}; use the id")
    return matches[0]


def verified_secret_version(
    server: ServerClient, owner_key: OwnerKey, ref: str
) -> tuple[str, int]:
    """The id and current envelope version of one of *our* secrets.

    The envelope is signature-checked and must be signed by ``owner_key``,
    so a server cannot hand us a lower version floor for someone else's
    (or a forged) envelope.
    """
    secret_id = resolve_secret_id(server, ref)
    detail = server.get(f"/v1/secrets/{secret_id}")
    try:
        envelope = Envelope.from_dict(detail["envelope"])
        verify_envelope_signature(envelope)
    except (EnvelopeError, KeyError, TypeError):
        raise VerificationError(f"secret {secret_id} has an invalid envelope") from None
    if not hmac.compare_digest(envelope.owner_pk, owner_key.public_key):
        raise VerificationError(f"secret {secret_id} was not sealed by your owner key")
    if envelope.secret_id != secret_id:
        raise VerificationError(f"secret {secret_id} holds another secret's envelope")
    return secret_id, envelope.version


def _secret_info(body: Any) -> SecretInfo:
    try:
        return SecretInfo(
            id=str(body["id"]),
            name=str(body["name"]),
            version=int(body["version"]),
            owner_fingerprint=str(body["owner_fingerprint"]),
            policy=dict(body["policy"]),
        )
    except (KeyError, TypeError, ValueError):
        raise CarapaceError("server returned a malformed secret") from None
