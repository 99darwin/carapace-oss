"""Sealed secrets. The server stores ciphertext it has no way to open."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, LargeBinary, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from carapace_server.db import Base, UTCDateTime, utcnow

SECRET_NAME_MAX_LENGTH = 200
KMS_KEY_VERSION_MAX_LENGTH = 512
WRAPPED_DEK_MAX_BYTES = 512
NONCE_BYTES = 12


class Secret(Base):
    """One envelope-v1 secret.

    ``id`` is chosen by the client because it is bound into the AAD. The
    policy is stored in cleartext for the enclave to read, but editing it
    here breaks decryption, which is why it can only change together with a
    fresh envelope.
    """

    __tablename__ = "secrets"
    __table_args__ = (UniqueConstraint("owner_id", "name"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(SECRET_NAME_MAX_LENGTH))
    policy_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    aad_hash: Mapped[str] = mapped_column(String(64))
    kms_key_version: Mapped[str | None] = mapped_column(
        String(KMS_KEY_VERSION_MAX_LENGTH)
    )
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary(WRAPPED_DEK_MAX_BYTES))
    nonce: Mapped[bytes] = mapped_column(LargeBinary(NONCE_BYTES))
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=utcnow, onupdate=utcnow
    )
