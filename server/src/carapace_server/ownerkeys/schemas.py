"""Request and response bodies for /v1/owner-keys."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from carapace_crypto import SignatureError, validate_public_key
from carapace_crypto.encoding import b64_decode_strict


class OwnerKeyCreate(BaseModel):
    """A raw Ed25519 public key, standard padded base64.

    ``validate_public_key`` rejects small-order and non-canonical points:
    OpenSSL accepts a small-order key, and under one the signature
    ``R = identity, S = 0`` verifies over any message, so such a key would
    let anyone "sign" envelopes and grants for this account.
    """

    model_config = ConfigDict(extra="forbid")

    public_key: str

    @field_validator("public_key")
    @classmethod
    def _public_key(cls, value: str) -> str:
        try:
            validate_public_key(b64_decode_strict(value, name="public_key"))
        except SignatureError as exc:
            raise ValueError(f"public_key: {exc}") from None
        return value


class OwnerKeyResponse(BaseModel):
    id: uuid.UUID
    public_key: str
    fingerprint: str
    created_at: datetime
    retired_at: datetime | None
