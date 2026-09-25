"""DB-backed access-token revocation list."""

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from carapace_server.auth.models import TokenBlacklistEntry
from carapace_server.auth.tokens import (
    AccessClaims,
    blacklist_token,
    is_blacklisted,
    purge_expired_blacklist,
)
from carapace_server.db import utcnow

pytestmark = pytest.mark.anyio


def _claims(expires_in: timedelta) -> AccessClaims:
    return AccessClaims(
        user_id=uuid.uuid4(), jti=str(uuid.uuid4()), expires_at=utcnow() + expires_in
    )


async def _count(db: AsyncSession) -> int:
    return await db.scalar(select(func.count()).select_from(TokenBlacklistEntry))


async def test_blacklisted_token_is_detected(db: AsyncSession) -> None:
    claims = _claims(timedelta(minutes=5))
    assert not await is_blacklisted(db, claims.jti)
    await blacklist_token(db, claims)
    await db.commit()
    assert await is_blacklisted(db, claims.jti)


async def test_blacklist_is_idempotent(db: AsyncSession) -> None:
    claims = _claims(timedelta(minutes=5))
    await blacklist_token(db, claims)
    await db.commit()
    await blacklist_token(db, claims)
    await db.commit()
    assert await _count(db) == 1


async def test_already_expired_token_is_not_stored(db: AsyncSession) -> None:
    await blacklist_token(db, _claims(timedelta(seconds=-1)))
    await db.commit()
    assert await _count(db) == 0


async def test_expired_entries_are_ignored_and_purged(db: AsyncSession) -> None:
    live = _claims(timedelta(minutes=5))
    await blacklist_token(db, live)
    stale_jti = str(uuid.uuid4())
    db.add(TokenBlacklistEntry(jti=stale_jti, expires_at=utcnow() - timedelta(1)))
    await db.commit()

    assert not await is_blacklisted(db, stale_jti)
    await purge_expired_blacklist(db)
    await db.commit()
    assert await _count(db) == 1
    assert await is_blacklisted(db, live.jti)
