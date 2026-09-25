"""Owner-signed grants: what an API key may use, and until when.

A grant is issued by the owner's CLI for one API key and stored on the
untrusted server next to that key's lookup hash. The enclave fetches it,
checks that it chains to the key the agent presented, and only then fetches
and opens envelopes::

    body = {
      "v": 1,
      "owner_pk": base64(32-byte Ed25519 public key),
      "key_bind": base64(ApiKey.bind_hash),
      "secrets":  {"<secret_id>": <min envelope version>, ...},
      "iat": <unix seconds>,
      "exp": <unix seconds>
    }
    sig  = Ed25519(owner_seed, "carapace-grant-v1" || 0x0A || canonical_json(body))
    wire = body + {"sig": base64(sig)}

``secrets`` maps each secret the key may use to the lowest envelope version
the enclave may accept for it. An empty map is a *tombstone*: a newer grant
that authorizes nothing, which an honest server serves in place of the old
one and a per-boot cache (:mod:`carapace_crypto.freshness`) remembers.

Freshness: ``exp - iat`` is capped at ``MAX_GRANT_TTL_SECONDS``. Whatever a
malicious server withholds (a narrower grant, a tombstone, a re-sealed
secret's new version floor) takes effect at the latest when the grant it
keeps serving expires. That bound is the whole freshness guarantee across
enclave boots; the CLI can renew grants automatically while the owner key
is available.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any

from carapace_crypto.apikey import ApiKey
from carapace_crypto.canonical import (
    MAX_SAFE_INTEGER,
    CanonicalJSONError,
    load_json_object,
)
from carapace_crypto.encoding import b64_decode_strict, b64_encode_std
from carapace_crypto.ownerkey import (
    PUBLIC_KEY_SIZE,
    SIGNATURE_SIZE,
    OwnerKey,
    SignatureError,
    fingerprints_match,
    validate_public_key,
    verify_object,
)

GRANT_VERSION = 1
GRANT_CONTEXT = b"carapace-grant-v1"
HASH_SIZE = 32
MAX_GRANT_SECRETS = 100
MAX_SECRET_ID_LENGTH = 256
DEFAULT_GRANT_TTL_SECONDS = 30 * 24 * 3600
MAX_GRANT_TTL_SECONDS = 90 * 24 * 3600
# How far in the future ``iat`` may lie before the grant is rejected.
CLOCK_SKEW_SECONDS = 300
GRANT_FIELDS = frozenset({"v", "owner_pk", "key_bind", "secrets", "iat", "exp", "sig"})


class GrantError(ValueError):
    """The grant is malformed."""


class GrantSignatureError(GrantError):
    """The owner signature does not verify."""


class GrantKeyMismatchError(GrantError):
    """The grant was not issued for the presented API key."""


class GrantExpiredError(GrantError):
    """The grant has expired, or is not yet valid."""


class GrantScopeError(GrantError):
    """The grant does not cover the requested secret."""


@dataclass(frozen=True, slots=True)
class Grant:
    """A parsed grant. Trust its fields only after :func:`verify_grant`."""

    owner_pk: bytes
    key_bind: bytes
    secrets: dict[str, int]
    iat: int
    exp: int
    sig: bytes
    v: int = GRANT_VERSION

    def signed_body(self) -> dict[str, Any]:
        return {
            "v": self.v,
            "owner_pk": b64_encode_std(self.owner_pk),
            "key_bind": b64_encode_std(self.key_bind),
            "secrets": dict(self.secrets),
            "iat": self.iat,
            "exp": self.exp,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.signed_body(), "sig": b64_encode_std(self.sig)}

    def min_version_for(self, secret_id: str) -> int:
        """The version floor for ``secret_id``. Raises :class:`GrantScopeError`."""
        try:
            return self.secrets[secret_id]
        except KeyError:
            raise GrantScopeError("grant does not cover this secret") from None

    @classmethod
    def from_json(cls, data: bytes | str) -> Grant:
        """Parse JSON text, rejecting duplicate keys. Raises :class:`GrantError`."""
        try:
            return cls.from_dict(load_json_object(data))
        except CanonicalJSONError as exc:
            raise GrantError(str(exc)) from exc

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Grant:
        """Parse the output of :meth:`to_dict`. Shape only; see :func:`verify_grant`."""
        if not isinstance(data, dict):
            raise GrantError("grant must be a JSON object")
        if set(data) != GRANT_FIELDS:
            raise GrantError("grant has missing or unknown fields")
        if data.get("v") != GRANT_VERSION or type(data.get("v")) is not int:
            raise GrantError(f"unsupported grant version: {data.get('v')!r}")
        grant = cls(
            owner_pk=_owner_pk(data.get("owner_pk")),
            key_bind=_b64d(data.get("key_bind"), "key_bind", HASH_SIZE),
            secrets=_require_secrets(data.get("secrets")),
            iat=_require_time(data.get("iat"), "iat"),
            exp=_require_time(data.get("exp"), "exp"),
            sig=_b64d(data.get("sig"), "sig", SIGNATURE_SIZE),
        )
        _check_lifetime(grant)
        return grant


def create_grant(
    owner_key: OwnerKey,
    api_key: ApiKey,
    secrets: dict[str, int],
    *,
    now: int,
    ttl_seconds: int = DEFAULT_GRANT_TTL_SECONDS,
    previous_iat: int | None = None,
) -> Grant:
    """Issue a grant for ``api_key`` covering ``secrets`` (id -> version floor).

    ``api_key.fingerprint`` must be ``owner_key``'s: a grant can only be
    issued by the key an API key names. Pass ``secrets={}`` for a tombstone.

    ``previous_iat`` is the ``iat`` of the grant this one replaces, if any.
    The new ``iat`` is forced strictly above it so that the enclave's
    per-boot cache treats the replacement as newer even when both are issued
    within the same second (create-then-revoke, renew-then-narrow).

    Raises:
        GrantError: On bad inputs, including a TTL above the format's cap.
    """
    if not fingerprints_match(owner_key.public_key, api_key.fingerprint):
        raise GrantKeyMismatchError("API key names a different owner key")
    iat = _require_time(now, "now")
    if previous_iat is not None:
        iat = max(iat, _require_time(previous_iat, "previous_iat") + 1)
    unsigned = Grant(
        owner_pk=owner_key.public_key,
        key_bind=api_key.bind_hash,
        secrets=_require_secrets(secrets),
        iat=iat,
        exp=_require_time(iat + ttl_seconds, "exp"),
        sig=b"",
    )
    _check_lifetime(unsigned)
    sig = owner_key.sign_object(GRANT_CONTEXT, unsigned.signed_body())
    return Grant(**{**_fields(unsigned), "sig": sig})


def verify_grant_signature(grant: Grant) -> Grant:
    """Check only that ``grant.sig`` verifies under ``grant.owner_pk``.

    For holders of a grant but not the raw API key, such as the control-plane
    server checking what an owner uploads. This is *not* authorization: it
    says nothing about which key the grant is for, whether that key names
    ``owner_pk``, or whether the grant is current. The enclave must call
    :func:`verify_grant`.

    Raises:
        GrantSignatureError: The key is invalid or the signature does not
            verify.
    """
    try:
        verify_object(grant.owner_pk, GRANT_CONTEXT, grant.signed_body(), grant.sig)
    except SignatureError as exc:
        raise GrantSignatureError(str(exc)) from exc
    return grant


def verify_grant(grant: Grant, api_key: ApiKey, *, now: int) -> Grant:
    """Check that ``grant`` authorizes ``api_key`` right now.

    The chain: the API key names an owner fingerprint; ``owner_pk`` must have
    that fingerprint; the signature must verify under ``owner_pk``; and the
    grant must be bound to this key's bind hash. Then the lifetime is checked.
    The caller still calls :meth:`Grant.min_version_for` for the secret and
    records ``iat`` in its per-boot :class:`~carapace_crypto.freshness.MonotonicCache`.

    Raises:
        GrantKeyMismatchError: Wrong owner fingerprint or wrong key.
        GrantSignatureError: Signature does not verify.
        GrantExpiredError: Outside ``[iat - skew, exp)``.
    """
    now = _require_time(now, "now")
    try:
        owner_matches = fingerprints_match(grant.owner_pk, api_key.fingerprint)
    except SignatureError as exc:
        # A small-order or malformed key on a directly constructed Grant.
        raise GrantKeyMismatchError(f"grant owner key is invalid: {exc}") from exc
    if not owner_matches:
        raise GrantKeyMismatchError("grant owner key does not match the API key")
    verify_grant_signature(grant)
    if not hmac.compare_digest(grant.key_bind, api_key.bind_hash):
        raise GrantKeyMismatchError("grant is bound to a different API key")
    _check_lifetime(grant)
    if now >= grant.exp:
        raise GrantExpiredError("grant has expired")
    if grant.iat > now + CLOCK_SKEW_SECONDS:
        raise GrantExpiredError("grant is not yet valid")
    return grant


def _check_lifetime(grant: Grant) -> None:
    if grant.exp <= grant.iat:
        raise GrantError("exp must be after iat")
    if grant.exp - grant.iat > MAX_GRANT_TTL_SECONDS:
        raise GrantError(f"grant lifetime exceeds {MAX_GRANT_TTL_SECONDS} seconds")


def _require_secrets(value: Any) -> dict[str, int]:
    if not isinstance(value, dict) or len(value) > MAX_GRANT_SECRETS:
        raise GrantError(f"secrets must be an object with <= {MAX_GRANT_SECRETS} keys")
    for secret_id, floor in value.items():
        if not isinstance(secret_id, str) or not (
            0 < len(secret_id) <= MAX_SECRET_ID_LENGTH
        ):
            raise GrantError("secret ids must be non-empty strings")
        if type(floor) is not int or not 1 <= floor <= MAX_SAFE_INTEGER:
            raise GrantError("version floors must be positive safe integers")
    return dict(value)


def _require_time(value: Any, name: str) -> int:
    if type(value) is not int or not 0 < value <= MAX_SAFE_INTEGER:
        raise GrantError(f"{name} must be a positive safe integer")
    return value


def _b64d(value: Any, name: str, size: int) -> bytes:
    try:
        data = b64_decode_strict(value, name=name)
    except ValueError as exc:
        raise GrantError(str(exc)) from exc
    if len(data) != size:
        raise GrantError(f"{name} must be {size} bytes")
    return data


def _owner_pk(value: Any) -> bytes:
    owner_pk = _b64d(value, "owner_pk", PUBLIC_KEY_SIZE)
    try:
        validate_public_key(owner_pk)
    except SignatureError as exc:
        raise GrantError(f"owner_pk: {exc}") from exc
    return owner_pk


def _fields(grant: Grant) -> dict[str, Any]:
    return {name: getattr(grant, name) for name in Grant.__slots__}
