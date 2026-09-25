"""API keys that let an agent use specific secrets through the enclave.

The owner's CLI mints the key (``carapace_crypto.ApiKey``) and signs a grant
for it. The server stores only the key's lookup hash and the grant, both
supplied by the client; it never generates or sees a raw key. The grant is
what the enclave trusts, after checking it chains to the key the agent
presents. ``api_key_secrets`` is a derived index of the current grant's
``secrets``, rewritten on every grant write.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, Column, ForeignKey, String, Table, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from carapace_server.db import Base, UTCDateTime, utcnow
from carapace_server.ownerkeys.models import OwnerKey
from carapace_server.store.models import Secret

KEY_PREFIX_LENGTH = 12
LOOKUP_HASH_HEX_LENGTH = 64
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
    owner_key_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("owner_keys.id", ondelete="CASCADE"), index=True
    )
    # Hex of ``carapace_crypto.ApiKey.lookup_hash``.
    key_hash: Mapped[str] = mapped_column(String(LOOKUP_HASH_HEX_LENGTH), unique=True)
    # ``cpk_`` plus the first 8 hex of the owner fingerprint; public, display
    # only.
    key_prefix: Mapped[str] = mapped_column(String(KEY_PREFIX_LENGTH))
    name: Mapped[str] = mapped_column(String(API_KEY_NAME_MAX_LENGTH))
    # The current owner-signed grant, exactly as ``Grant.to_dict()`` emits it.
    grant_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    grant_iat: Mapped[int] = mapped_column(BigInteger)
    grant_exp: Mapped[int] = mapped_column(BigInteger)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    owner_key: Mapped[OwnerKey] = relationship(lazy="selectin")
    secrets: Mapped[list[Secret]] = relationship(
        secondary=api_key_secrets, lazy="selectin"
    )
