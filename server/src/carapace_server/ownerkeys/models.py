"""Owner public keys. The matching private seeds never leave owners' devices.

Every envelope and grant the server stores must be signed by one of the
caller's registered, non-retired owner keys. The enclave does its own check
against the fingerprint in the agent's API key; this table only lets the
server refuse obvious garbage and show owners which keys they have.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, LargeBinary, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from carapace_crypto.ownerkey import FINGERPRINT_SIZE, PUBLIC_KEY_SIZE
from carapace_server.db import Base, UTCDateTime, utcnow

FINGERPRINT_HEX_LENGTH = 2 * FINGERPRINT_SIZE


class OwnerKey(Base):
    __tablename__ = "owner_keys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    public_key: Mapped[bytes] = mapped_column(LargeBinary(PUBLIC_KEY_SIZE), unique=True)
    # Hex of ``carapace_crypto.fingerprint(public_key)``; derived, public.
    fingerprint: Mapped[str] = mapped_column(
        String(FINGERPRINT_HEX_LENGTH), unique=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    retired_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
