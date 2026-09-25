"""API keys for agents: mint, list, renew and revoke.

The raw key is generated here and shown once; the server stores only its
lookup hash and the owner-signed grant. Renewals and revocations re-sign
the grant from the stored one (:func:`carapace_crypto.reissue_grant`),
which checks that grant's signature under our owner key first.

Revocation: the server marks the key revoked *and* holds a tombstone grant
(same key, no secrets, newer ``iat``) so that an enclave boot which already
cached the old grant stops honouring it. Neither stops a server that is
itself malicious before the old grant expires; only rotating the credential
at the provider is a hard cutoff. See :data:`REVOKE_WARNING`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any

from carapace_cli.errors import CarapaceError, VerificationError
from carapace_cli.pin import now_seconds
from carapace_cli.session import ServerClient
from carapace_crypto import (
    ApiKey,
    Grant,
    GrantError,
    OwnerKey,
    create_grant,
    reissue_grant,
    verify_grant_signature,
)
from carapace_crypto.grant import DEFAULT_GRANT_TTL_SECONDS

REVOKE_WARNING = (
    "Revoked. The server now refuses this key and serves a tombstone grant.\n"
    "This is NOT a hard cutoff: a compromised server could keep serving the "
    "old grant until it expires. Rotate the credential at the provider for a "
    "guaranteed cutoff."
)


@dataclass(frozen=True)
class ApiKeyInfo:
    id: str
    name: str
    key_prefix: str
    secret_ids: list[str]
    grant: Grant
    grant_valid: bool
    revoked: bool

    @property
    def grant_exp(self) -> int:
        return self.grant.exp


def create_api_key(
    server: ServerClient,
    owner_key: OwnerKey,
    *,
    name: str,
    secret_versions: dict[str, int],
    ttl_seconds: int = DEFAULT_GRANT_TTL_SECONDS,
) -> tuple[str, ApiKeyInfo]:
    """Mint a key, sign its grant and register both. Returns the raw key once.

    ``secret_versions`` maps secret ids to version floors, normally each
    secret's current (signature-checked) version.
    """
    api_key = ApiKey.generate(owner_key)
    try:
        grant = create_grant(
            owner_key,
            api_key,
            secret_versions,
            now=now_seconds(),
            ttl_seconds=ttl_seconds,
        )
    except GrantError as exc:
        raise CarapaceError(f"cannot create grant: {exc}") from None
    body = server.post(
        "/v1/api-keys",
        json={
            "name": name,
            "lookup_hash": api_key.lookup_hash.hex(),
            "grant": grant.to_dict(),
        },
    )
    return api_key.raw, _key_info(body, owner_key)


def list_api_keys(server: ServerClient, owner_key: OwnerKey) -> list[ApiKeyInfo]:
    return [_key_info(item, owner_key) for item in server.get("/v1/api-keys")]


def find_api_key(server: ServerClient, owner_key: OwnerKey, key_id: str) -> ApiKeyInfo:
    for info in list_api_keys(server, owner_key):
        if info.id == key_id:
            return info
    raise CarapaceError(f"no API key with id {key_id}")


def revoke_api_key(server: ServerClient, owner_key: OwnerKey, key_id: str) -> None:
    """Push a tombstone grant and revoke the key server-side, in one call."""
    info = find_api_key(server, owner_key, key_id)
    tombstone = _reissue(owner_key, info, {})
    server.post(f"/v1/api-keys/{key_id}/revoke", json={"grant": tombstone.to_dict()})


def renew_api_key(
    server: ServerClient,
    owner_key: OwnerKey,
    key_id: str,
    *,
    ttl_seconds: int = DEFAULT_GRANT_TTL_SECONDS,
) -> ApiKeyInfo:
    """Re-sign the same scope with a fresh lifetime."""
    info = find_api_key(server, owner_key, key_id)
    if info.revoked:
        raise CarapaceError("the key is revoked")
    renewed = _reissue(owner_key, info, info.grant.secrets, ttl_seconds=ttl_seconds)
    body = server.call(
        "PUT", f"/v1/api-keys/{key_id}/grant", json={"grant": renewed.to_dict()}
    )
    return _key_info(body, owner_key)


def _reissue(
    owner_key: OwnerKey,
    info: ApiKeyInfo,
    secrets: dict[str, int],
    *,
    ttl_seconds: int = DEFAULT_GRANT_TTL_SECONDS,
) -> Grant:
    if not info.grant_valid:
        raise VerificationError(
            "the server's stored grant is not signed by your owner key; "
            "refusing to re-sign it"
        )
    try:
        return reissue_grant(
            owner_key, info.grant, secrets, now=now_seconds(), ttl_seconds=ttl_seconds
        )
    except GrantError as exc:
        raise VerificationError(f"cannot re-sign grant: {exc}") from None


def _key_info(body: Any, owner_key: OwnerKey) -> ApiKeyInfo:
    try:
        grant = Grant.from_dict(body["grant"])
        info = ApiKeyInfo(
            id=str(body["id"]),
            name=str(body["name"]),
            key_prefix=str(body["key_prefix"]),
            secret_ids=[str(s) for s in body["secret_ids"]],
            grant=grant,
            grant_valid=_grant_is_ours(grant, owner_key),
            revoked=body["revoked_at"] is not None,
        )
    except (GrantError, KeyError, TypeError):
        raise CarapaceError("server returned a malformed API key") from None
    return info


def _grant_is_ours(grant: Grant, owner_key: OwnerKey) -> bool:
    if not hmac.compare_digest(grant.owner_pk, owner_key.public_key):
        return False
    try:
        verify_grant_signature(grant)
    except GrantError:
        return False
    return True
