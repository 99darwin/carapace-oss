"""API keys that let an agent use specific secrets through the enclave.

Only the SHA-256 of a key is stored. The raw key is shown once at creation.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Column, ForeignKey, String, Table, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from carapace_server.db import Base, UTCDateTime, utcnow
from carapace_server.store.models import Secret

KEY_PREFIX_LENGTH = 12
API_KEY_NAME_MAX_LENGTH = 200

api_key_secrets = Table(
    "api_key_secrets",
    Base.metadata,
    Column(
        "api_key_id",
        Uuid,
        ForeignKey("api_keys.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "secret_id",
        Uuid,
        ForeignKey("secrets.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    ),
)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    # First characters of the raw key, for display only.
    key_prefix: Mapped[str] = mapped_column(String(KEY_PREFIX_LENGTH))
    name: Mapped[str] = mapped_column(String(API_KEY_NAME_MAX_LENGTH))
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    secrets: Mapped[list[Secret]] = relationship(
        secondary=api_key_secrets, lazy="selectin"
    )
