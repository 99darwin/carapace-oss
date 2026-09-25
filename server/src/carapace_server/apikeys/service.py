"""Register, re-grant, revoke and look up client-minted API keys.

The server never generates or sees a raw key. It stores the lookup hash
the owner's CLI computed and the owner-signed grant, and checks the grant
(shape, signature, the caller's own owner key, the caller's own secrets)
as defense in depth. It cannot check ``key_bind``, which needs the raw key;
the enclave does. No billing or quota checks.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from carapace_crypto import (
    Grant,
    GrantError,
    GrantSignatureError,
    verify_grant_signature,
)
from carapace_crypto.grant import CLOCK_SKEW_SECONDS
from carapace_server.apikeys.models import ApiKey
from carapace_server.db import utcnow
from carapace_server.ids import parse_canonical_uuid
from carapace_server.ownerkeys.service import find_active_owner_key
from carapace_server.store.models import Secret

KEY_PREFIX_TAG = "cpk_"
KEY_PREFIX_FINGERPRINT_CHARS = 8


class ApiKeyError(ValueError):
    """Invalid request. Messages are safe to show the owner."""


class ApiKeyConflictError(Exception):
    """The lookup hash is already registered."""


class ApiKeyNotFoundError(Exception):
    """No such live key for this user (or at all)."""


class StaleGrantError(Exception):
    """The grant's ``iat`` does not exceed the stored grant's."""


def _unix_now() -> int:
    return int(utcnow().timestamp())


def _parse_signed_grant(grant_wire: dict[str, Any]) -> Grant:
    """``Grant.from_dict`` plus the owner signature under its own ``owner_pk``."""
    try:
        grant = verify_grant_signature(Grant.from_dict(grant_wire))
    except GrantSignatureError:
        raise ApiKeyError("grant signature does not verify") from None
    except GrantError as exc:
        raise ApiKeyError(f"invalid grant: {exc}") from None
    return grant


def _check_grant_times(grant: Grant, now: int) -> None:
    if grant.exp <= now:
        raise ApiKeyError("grant has expired")
    if grant.iat > now + CLOCK_SKEW_SECONDS:
        raise ApiKeyError("grant iat is in the future")


def _check_same_key(api_key: ApiKey, grant: Grant) -> None:
    """A replacement grant is for the same API key under the same owner key."""
    if grant.owner_pk != api_key.owner_key.public_key:
        raise ApiKeyError("grant is signed by a different owner key")
    if grant.to_dict()["key_bind"] != api_key.grant_json.get("key_bind"):
        raise ApiKeyError("grant is bound to a different API key")


async def _owned_secrets(
    db: AsyncSession, user_id: uuid.UUID, grant: Grant
) -> list[Secret]:
    try:
        wanted = {parse_canonical_uuid(secret_id) for secret_id in grant.secrets}
    except ValueError:
        raise ApiKeyError("grant secret ids must be canonical UUIDs") from None
    if not wanted:
        return []
    owned = (
        await db.scalars(
            select(Secret).where(Secret.id.in_(wanted), Secret.owner_id == user_id)
        )
    ).all()
    if len(owned) != len(wanted):
        raise ApiKeyError("one or more secrets not found")
    return list(owned)


def _grant_columns(grant: Grant) -> dict[str, Any]:
    return {
        "grant_json": grant.to_dict(),
        "grant_iat": grant.iat,
        "grant_exp": grant.exp,
    }


async def _get_live_key(
    db: AsyncSession, user_id: uuid.UUID, api_key_id: uuid.UUID
) -> ApiKey:
    api_key = await db.get(ApiKey, api_key_id)
    if api_key is None or api_key.user_id != user_id or api_key.revoked_at is not None:
        raise ApiKeyNotFoundError(str(api_key_id))
    return api_key


async def create_api_key(
    db: AsyncSession,
    user_id: uuid.UUID,
    *,
    name: str,
    lookup_hash: str,
    grant_wire: dict[str, Any],
) -> ApiKey:
    """Register a key by its lookup hash, with its first grant."""
    grant = _parse_signed_grant(grant_wire)
    _check_grant_times(grant, _unix_now())
    if not grant.secrets:
        raise ApiKeyError("grant must cover at least one secret")
    owner_key = await find_active_owner_key(db, user_id, grant.owner_pk)
    if owner_key is None:
        raise ApiKeyError("grant is not signed by one of your active owner keys")
    secrets = await _owned_secrets(db, user_id, grant)
    api_key = ApiKey(
        user_id=user_id,
        owner_key=owner_key,
        key_hash=lookup_hash,
        key_prefix=KEY_PREFIX_TAG
        + owner_key.fingerprint[:KEY_PREFIX_FINGERPRINT_CHARS],
        name=name,
        secrets=secrets,
        **_grant_columns(grant),
    )
    db.add(api_key)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise ApiKeyConflictError("lookup hash already registered") from exc
    return api_key


async def update_grant(
    db: AsyncSession,
    user_id: uuid.UUID,
    api_key_id: uuid.UUID,
    grant_wire: dict[str, Any],
) -> ApiKey:
    """Replace a live key's grant with a strictly newer one.

    The ``iat`` comparison is part of the ``UPDATE`` so concurrent writes
    cannot move a key back to an older grant.
    """
    api_key = await _get_live_key(db, user_id, api_key_id)
    grant = _parse_signed_grant(grant_wire)
    _check_grant_times(grant, _unix_now())
    _check_same_key(api_key, grant)
    if api_key.owner_key.retired_at is not None:
        raise ApiKeyError("grant is not signed by one of your active owner keys")
    secrets = await _owned_secrets(db, user_id, grant)
    result = await db.execute(
        update(ApiKey)
        .where(
            ApiKey.id == api_key.id,
            ApiKey.revoked_at.is_(None),
            ApiKey.grant_iat < grant.iat,
        )
        .values(**_grant_columns(grant))
    )
    if result.rowcount != 1:
        await db.rollback()
        raise StaleGrantError("grant iat must increase")
    api_key.secrets = secrets
    await db.commit()
    await db.refresh(api_key)
    return api_key


async def revoke_api_key(
    db: AsyncSession,
    user_id: uuid.UUID,
    api_key_id: uuid.UUID,
    tombstone_wire: dict[str, Any] | None = None,
) -> None:
    """Mark the key revoked and, if given, store a tombstone as its grant.

    A tombstone is a grant for the same key (same ``owner_pk`` and
    ``key_bind``) with no secrets and a strictly higher ``iat``, checked
    like ``update_grant`` except that it may be signed by a retired owner
    key: the enclave does not know about retirement, so grants under a
    retired key stay usable there until they expire, and the tombstone is
    the only thing that stops them early.
    """
    api_key = await _get_live_key(db, user_id, api_key_id)
    values: dict[str, Any] = {"revoked_at": utcnow()}
    statement = update(ApiKey).where(
        ApiKey.id == api_key.id, ApiKey.revoked_at.is_(None)
    )
    if tombstone_wire is not None:
        grant = _parse_signed_grant(tombstone_wire)
        _check_grant_times(grant, _unix_now())
        _check_same_key(api_key, grant)
        if grant.secrets:
            raise ApiKeyError("a tombstone grant must not cover any secrets")
        values |= _grant_columns(grant)
        statement = statement.where(ApiKey.grant_iat < grant.iat)
    result = await db.execute(statement.values(**values))
    if result.rowcount != 1:
        await db.rollback()
        if tombstone_wire is not None:
            raise StaleGrantError("grant iat must increase")
        raise ApiKeyNotFoundError(str(api_key_id))
    api_key.secrets = []
    await db.commit()


async def list_api_keys(db: AsyncSession, user_id: uuid.UUID) -> Sequence[ApiKey]:
    result = await db.scalars(
        select(ApiKey)
        .where(ApiKey.user_id == user_id, ApiKey.revoked_at.is_(None))
        .order_by(ApiKey.created_at.desc())
    )
    return result.all()


async def find_grant(db: AsyncSession, lookup_hash: str) -> dict[str, Any] | None:
    """The key's current stored grant, or None if the lookup hash is unknown.

    Deliberately unfiltered: a revoked key's grant (its tombstone, if one
    was sent), an expired grant and a grant that does not cover the secret
    the agent asked for are all returned. The enclave checks revocation,
    expiry and scope itself from the signed grant, and it can only record a
    tombstone or a narrowed grant in its per-boot monotonic cache if the
    server hands it over. Touches ``last_used_at``.
    """
    result = await db.execute(
        update(ApiKey)
        .where(ApiKey.key_hash == lookup_hash)
        .values(last_used_at=utcnow())
        .returning(ApiKey.grant_json)
        .execution_options(synchronize_session=False)
    )
    grant_json = result.scalar_one_or_none()
    await db.commit()
    return grant_json
