"""Create, list, revoke and check API keys. No billing or quota checks."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import exists, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from carapace_server.apikeys.models import KEY_PREFIX_LENGTH, ApiKey, api_key_secrets
from carapace_server.db import utcnow
from carapace_server.store.models import Secret

KEY_TAG = "cpk_"
KEY_RANDOM_BYTES = 32


class ApiKeyError(ValueError):
    """Invalid create request. Messages are safe to show the owner."""


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _generate_raw_key() -> str:
    return KEY_TAG + secrets.token_urlsafe(KEY_RANDOM_BYTES)


async def create_api_key(
    db: AsyncSession,
    user_id: uuid.UUID,
    *,
    name: str,
    secret_ids: Sequence[uuid.UUID],
    expires_at: datetime | None,
) -> tuple[ApiKey, str]:
    """Return the new key and its raw value. The raw value is never stored."""
    wanted = set(secret_ids)
    if not wanted:
        raise ApiKeyError("at least one secret is required")
    if expires_at is not None and expires_at <= utcnow():
        raise ApiKeyError("expires_at must be in the future")
    owned = (
        await db.scalars(
            select(Secret).where(Secret.id.in_(wanted), Secret.owner_id == user_id)
        )
    ).all()
    if len(owned) != len(wanted):
        raise ApiKeyError("one or more secrets not found")
    raw_key = _generate_raw_key()
    api_key = ApiKey(
        user_id=user_id,
        key_hash=hash_api_key(raw_key),
        key_prefix=raw_key[:KEY_PREFIX_LENGTH],
        name=name,
        expires_at=expires_at,
        secrets=list(owned),
    )
    db.add(api_key)
    await db.commit()
    return api_key, raw_key


async def list_api_keys(db: AsyncSession, user_id: uuid.UUID) -> Sequence[ApiKey]:
    result = await db.scalars(
        select(ApiKey)
        .where(ApiKey.user_id == user_id, ApiKey.revoked_at.is_(None))
        .order_by(ApiKey.created_at.desc())
    )
    return result.all()


async def revoke_api_key(
    db: AsyncSession, user_id: uuid.UUID, api_key_id: uuid.UUID
) -> bool:
    result = await db.execute(
        update(ApiKey)
        .where(
            ApiKey.id == api_key_id,
            ApiKey.user_id == user_id,
            ApiKey.revoked_at.is_(None),
        )
        .values(revoked_at=utcnow())
    )
    await db.commit()
    return result.rowcount == 1


async def is_key_allowed_for_secret(
    db: AsyncSession, key_hash: str, secret_id: uuid.UUID
) -> bool:
    """True if the key is live and scoped to the secret. Touches last_used_at.

    Called by the enclave with the key's hash, so the server never needs to
    see a raw key after creation.
    """
    now = utcnow()
    in_scope = exists().where(
        api_key_secrets.c.api_key_id == ApiKey.id,
        api_key_secrets.c.secret_id == secret_id,
    )
    result = await db.execute(
        update(ApiKey)
        .where(
            ApiKey.key_hash == key_hash,
            ApiKey.revoked_at.is_(None),
            (ApiKey.expires_at.is_(None)) | (ApiKey.expires_at > now),
            in_scope,
        )
        .values(last_used_at=now)
    )
    await db.commit()
    return result.rowcount == 1
