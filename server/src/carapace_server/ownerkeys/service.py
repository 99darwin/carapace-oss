"""Register, list and retire owner public keys."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from carapace_crypto import fingerprint
from carapace_server.auth.models import User
from carapace_server.db import utcnow
from carapace_server.ownerkeys.models import OwnerKey

# Retired keys count too: otherwise retire-and-register would let one tenant
# churn through fingerprints and the enclave's per-owner cache.
MAX_OWNER_KEYS_PER_USER = 10


class OwnerKeyConflictError(Exception):
    """The public key is already registered (by anyone)."""


class OwnerKeyLimitError(Exception):
    """The account already has ``MAX_OWNER_KEYS_PER_USER`` keys."""


class OwnerKeyNotFoundError(Exception):
    """No such owner key for this user (or at all)."""


async def register_owner_key(
    db: AsyncSession, user_id: uuid.UUID, public_key: bytes
) -> OwnerKey:
    """Store a public key for ``user_id``. No proof of possession is required:
    a key whose seed the caller does not hold cannot sign anything, so
    registering it grants nothing. That holds only for keys that pass
    ``validate_public_key``, which ``OwnerKeyCreate`` and ``fingerprint``
    both enforce.

    Raises:
        OwnerKeyLimitError: The account is at ``MAX_OWNER_KEYS_PER_USER``.
        OwnerKeyConflictError: The public key is already registered.
        SignatureError: ``public_key`` is not a valid owner key.
    """
    # Serialize concurrent registrations per user (a no-op on SQLite, whose
    # writers are serialized anyway) so the cap cannot be raced past.
    await db.execute(select(User.id).where(User.id == user_id).with_for_update())
    count = await db.scalar(
        select(func.count()).select_from(OwnerKey).where(OwnerKey.user_id == user_id)
    )
    if (count or 0) >= MAX_OWNER_KEYS_PER_USER:
        await db.rollback()
        raise OwnerKeyLimitError("owner key limit reached")
    owner_key = OwnerKey(
        user_id=user_id,
        public_key=public_key,
        fingerprint=fingerprint(public_key).hex(),
    )
    db.add(owner_key)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise OwnerKeyConflictError("owner key already registered") from exc
    return owner_key


async def list_owner_keys(db: AsyncSession, user_id: uuid.UUID) -> Sequence[OwnerKey]:
    result = await db.scalars(
        select(OwnerKey)
        .where(OwnerKey.user_id == user_id)
        .order_by(OwnerKey.created_at, OwnerKey.id)
    )
    return result.all()


async def retire_owner_key(
    db: AsyncSession, user_id: uuid.UUID, owner_key_id: uuid.UUID
) -> OwnerKey:
    """Refuse new envelopes and grants under this key. Idempotent."""
    owner_key = await db.get(OwnerKey, owner_key_id)
    if owner_key is None or owner_key.user_id != user_id:
        raise OwnerKeyNotFoundError(str(owner_key_id))
    if owner_key.retired_at is None:
        owner_key.retired_at = utcnow()
        await db.commit()
    return owner_key


async def find_active_owner_key(
    db: AsyncSession, user_id: uuid.UUID, public_key: bytes
) -> OwnerKey | None:
    """The caller's registered, non-retired key with these public bytes."""
    return await db.scalar(
        select(OwnerKey).where(
            OwnerKey.user_id == user_id,
            OwnerKey.public_key == public_key,
            OwnerKey.retired_at.is_(None),
        )
    )
