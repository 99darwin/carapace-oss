"""Enclave boots and the signed receipts they emit, stored verbatim.

The server signs nothing. It keeps what the enclave sent so owners can
verify chains and signatures offline against the boot's attested key.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    ForeignKey,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from carapace_server.db import Base, UTCDateTime, utcnow

HASH_HEX_LENGTH = 64
IMAGE_DIGEST_LENGTH = 71  # "sha256:" + 64 hex
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64


class EnclaveBoot(Base):
    """One enclave boot.

    ``boot_id`` is the hex ``sha256(tls_spki_der || receipt_pubkey)``, which
    is also the ``eat_nonce`` in the boot's attestation token.
    """

    __tablename__ = "enclave_boots"

    boot_id: Mapped[str] = mapped_column(String(HASH_HEX_LENGTH), primary_key=True)
    attestation_token: Mapped[str] = mapped_column(Text)
    receipt_pubkey: Mapped[bytes] = mapped_column(LargeBinary(ED25519_PUBLIC_KEY_BYTES))
    tls_cert_pem: Mapped[str] = mapped_column(Text)
    image_digest: Mapped[str] = mapped_column(String(IMAGE_DIGEST_LENGTH))
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Receipt(Base):
    __tablename__ = "receipts"
    __table_args__ = (UniqueConstraint("boot_id", "seq"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    boot_id: Mapped[str] = mapped_column(
        String(HASH_HEX_LENGTH), ForeignKey("enclave_boots.boot_id")
    )
    seq: Mapped[int] = mapped_column(BigInteger)
    prev_hash: Mapped[str] = mapped_column(String(HASH_HEX_LENGTH))
    # sha256 of the signed bytes; the next receipt's prev_hash.
    hash: Mapped[str] = mapped_column(String(HASH_HEX_LENGTH))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    signature: Mapped[bytes] = mapped_column(LargeBinary(ED25519_SIGNATURE_BYTES))
    # Derived from payload["secret_id"] at ingest, for owner queries. No
    # foreign keys: receipts outlive the secrets and users they mention.
    secret_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
