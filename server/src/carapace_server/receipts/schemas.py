"""Wire formats for receipts and boots."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from carapace_server.canonical import canonical_json, reject_floats
from carapace_server.receipts.models import (
    ED25519_PUBLIC_KEY_BYTES,
    ED25519_SIGNATURE_BYTES,
)
from carapace_server.store.envelope import b64decode_strict

HexHash = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
MAX_RECEIPTS_PER_BATCH = 100
MAX_CERT_PEM_LENGTH = 16 * 1024
MAX_PAYLOAD_BYTES = 16 * 1024


def _decode_exact(value: str, size: int, what: str) -> bytes:
    raw = b64decode_strict(value)
    if len(raw) != size:
        raise ValueError(f"{what} must be {size} bytes")
    return raw


class BootRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    receipt_pubkey: str
    tls_cert_pem: str = Field(max_length=MAX_CERT_PEM_LENGTH)

    @field_validator("receipt_pubkey")
    @classmethod
    def _pubkey(cls, value: str) -> str:
        _decode_exact(value, ED25519_PUBLIC_KEY_BYTES, "receipt_pubkey")
        return value


class ReceiptIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    boot_id: HexHash
    seq: int = Field(ge=0, le=2**53 - 1)
    prev_hash: HexHash
    payload: dict[str, Any]
    signature: str

    @field_validator("payload")
    @classmethod
    def _payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        reject_floats(value)
        try:
            encoded = canonical_json(value)
        except UnicodeEncodeError:
            raise ValueError("payload is not valid UTF-8") from None
        if len(encoded) > MAX_PAYLOAD_BYTES:
            raise ValueError(f"payload exceeds {MAX_PAYLOAD_BYTES} bytes")
        return value

    @field_validator("signature")
    @classmethod
    def _signature(cls, value: str) -> str:
        _decode_exact(value, ED25519_SIGNATURE_BYTES, "signature")
        return value


class ReceiptBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    receipts: list[ReceiptIn] = Field(min_length=1, max_length=MAX_RECEIPTS_PER_BATCH)


class KeyCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_hash: HexHash
    secret_id: uuid.UUID


class BootOut(BaseModel):
    boot_id: str
    attestation_token: str
    receipt_pubkey: str
    tls_cert_pem: str
    image_digest: str
    first_seen: datetime


class ReceiptOut(BaseModel):
    boot_id: str
    seq: int
    prev_hash: str
    hash: str
    payload: dict[str, Any]
    signature: str


class ReceiptPage(BaseModel):
    boots: list[BootOut]
    receipts: list[ReceiptOut]
    next_cursor: str | None
