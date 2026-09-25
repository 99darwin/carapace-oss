"""Access-token JWTs and the DB-backed revocation list."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from carapace_server.auth.models import TokenBlacklistEntry
from carapace_server.config import Settings
from carapace_server.db import utcnow

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_TYPE = "access"  # noqa: S105 - claim value, not a secret
REQUIRED_CLAIMS = ["exp", "iat", "sub", "iss", "aud", "jti", "type"]


class InvalidTokenError(Exception):
    """The access token is malformed, forged, expired or of the wrong type."""


@dataclass(frozen=True)
class AccessClaims:
    user_id: uuid.UUID
    jti: str
    expires_at: datetime


def create_access_token(settings: Settings, user_id: uuid.UUID) -> str:
    now = utcnow()
    payload = {
        "sub": str(user_id),
        "type": ACCESS_TOKEN_TYPE,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
        "jti": str(uuid.uuid4()),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }
    return jwt.encode(payload, settings.jwt_key, algorithm=JWT_ALGORITHM)


def decode_access_token(
    settings: Settings, token: str, *, verify_exp: bool = True
) -> AccessClaims:
    """Verify signature, issuer, audience, type and (optionally) expiry."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_key,
            algorithms=[JWT_ALGORITHM],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": REQUIRED_CLAIMS, "verify_exp": verify_exp},
        )
        if payload["type"] != ACCESS_TOKEN_TYPE:
            raise InvalidTokenError("not an access token")
        return AccessClaims(
            user_id=uuid.UUID(payload["sub"]),
            jti=str(payload["jti"]),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=UTC),
        )
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise InvalidTokenError("invalid access token") from exc


async def blacklist_token(db: AsyncSession, claims: AccessClaims) -> None:
    """Revoke an access token until its natural expiry. Caller commits."""
    if claims.expires_at <= utcnow():
        return
    exists = await db.scalar(
        select(TokenBlacklistEntry.id).where(TokenBlacklistEntry.jti == claims.jti)
    )
    if exists is None:
        db.add(TokenBlacklistEntry(jti=claims.jti, expires_at=claims.expires_at))


async def is_blacklisted(db: AsyncSession, jti: str) -> bool:
    entry = await db.scalar(
        select(TokenBlacklistEntry.id).where(
            TokenBlacklistEntry.jti == jti,
            TokenBlacklistEntry.expires_at > utcnow(),
        )
    )
    return entry is not None


async def purge_expired_blacklist(db: AsyncSession) -> None:
    await db.execute(
        delete(TokenBlacklistEntry).where(TokenBlacklistEntry.expires_at <= utcnow())
    )
