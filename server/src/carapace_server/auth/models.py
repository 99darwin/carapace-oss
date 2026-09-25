"""Account and session tables.

Email is stored in plaintext (normalized, unique). It is not a secret: the
operator can already see who has an account, and the server is untrusted by
design, so sealing it would only add a key the server holds anyway. Secrets
never touch these tables.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, Enum, ForeignKey, Integer, LargeBinary, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from carapace_server.db import Base, UTCDateTime, utcnow

EMAIL_MAX_LENGTH = 320


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(
        String(EMAIL_MAX_LENGTH), unique=True, nullable=False
    )
    display_name: Mapped[str | None] = mapped_column(String(100))
    # bcrypt(base64(sha256(password))); never the password itself.
    password_hash: Mapped[bytes | None] = mapped_column(LargeBinary(60))
    passkey_credential_id: Mapped[bytes | None] = mapped_column(
        LargeBinary(1023), unique=True
    )
    passkey_public_key: Mapped[bytes | None] = mapped_column(LargeBinary)
    passkey_sign_count: Mapped[int] = mapped_column(Integer, default=0)
    passkey_transports: Mapped[list[str] | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class RefreshToken(Base):
    """Refresh tokens are stored as SHA-256 hashes and rotated on use."""

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    user_agent: Mapped[str | None] = mapped_column(String(512))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class ChallengeType(enum.StrEnum):
    REGISTER = "register"
    AUTHENTICATE = "authenticate"


class WebAuthnChallenge(Base):
    """Single-use passkey challenge with a short TTL."""

    __tablename__ = "webauthn_challenges"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(EMAIL_MAX_LENGTH), index=True)
    challenge_type: Mapped[ChallengeType] = mapped_column(
        Enum(
            ChallengeType,
            name="challenge_type",
            values_callable=lambda e: [m.value for m in e],
        )
    )
    challenge: Mapped[bytes] = mapped_column(LargeBinary(64))
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)


class TokenBlacklistEntry(Base):
    """Revoked access-token IDs, kept until the token would have expired."""

    __tablename__ = "token_blacklist"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    jti: Mapped[str] = mapped_column(String(36), unique=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
