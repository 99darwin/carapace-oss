"""Shape checks for envelope v1 as serialized by ``carapace_crypto``.

The server validates structure only. It cannot decrypt, so it cannot tell a
well-formed envelope from garbage of the right size, and it does not try.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from carapace_server.store.models import (
    KMS_KEY_VERSION_MAX_LENGTH,
    NONCE_BYTES,
    WRAPPED_DEK_MAX_BYTES,
)

ENVELOPE_VERSION = 1
# RSA-OAEP output equals the modulus size; envelope v1 needs >= 3072 bits.
WRAPPED_DEK_MIN_BYTES = 384
GCM_TAG_BYTES = 16
MAX_PLAINTEXT_BYTES = 64 * 1024
MAX_POLICY_BYTES = 16 * 1024


def b64decode_strict(value: str) -> bytes:
    """Standard padded base64 (RFC 4648 section 4), rejecting junk."""
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64") from exc


def b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def canonical_json(value: dict[str, Any]) -> bytes:
    """Same encoding as ``carapace_crypto.canonical`` for the inputs it accepts.

    Floats are rejected up front (``_reject_floats``), which is the only
    divergence that matters for policies.
    """
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("floats are not allowed in policies")
    if isinstance(value, dict):
        for item in value.values():
            _reject_floats(item)
    elif isinstance(value, list):
        for item in value:
            _reject_floats(item)


def compute_aad_hash(
    secret_id: uuid.UUID, owner_id: uuid.UUID, policy: dict[str, Any]
) -> str:
    """Hex SHA-256 of the envelope v1 AAD input."""
    bound = {
        "v": ENVELOPE_VERSION,
        "secret_id": str(secret_id),
        "owner_id": str(owner_id),
        "policy": policy,
    }
    return hashlib.sha256(canonical_json(bound)).hexdigest()


class EnvelopeV1(BaseModel):
    """``Envelope.to_dict()`` output, with lengths checked."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    v: int
    secret_id: uuid.UUID
    owner_id: uuid.UUID
    policy: dict[str, Any]
    kms_key_version: str | None = Field(
        default=None, max_length=KMS_KEY_VERSION_MAX_LENGTH
    )
    wrapped: str
    nonce: str
    ct: str

    @field_validator("v")
    @classmethod
    def _version(cls, value: int) -> int:
        if value != ENVELOPE_VERSION:
            raise ValueError(f"unsupported envelope version {value}")
        return value

    @field_validator("policy")
    @classmethod
    def _policy(cls, value: dict[str, Any]) -> dict[str, Any]:
        _reject_floats(value)
        if len(canonical_json(value)) > MAX_POLICY_BYTES:
            raise ValueError("policy too large")
        return value

    @field_validator("wrapped")
    @classmethod
    def _wrapped(cls, value: str) -> str:
        size = len(b64decode_strict(value))
        if not WRAPPED_DEK_MIN_BYTES <= size <= WRAPPED_DEK_MAX_BYTES:
            raise ValueError("wrapped key has an invalid length")
        return value

    @field_validator("nonce")
    @classmethod
    def _nonce(cls, value: str) -> str:
        if len(b64decode_strict(value)) != NONCE_BYTES:
            raise ValueError("nonce must be 12 bytes")
        return value

    @field_validator("ct")
    @classmethod
    def _ct(cls, value: str) -> str:
        size = len(b64decode_strict(value))
        if not GCM_TAG_BYTES <= size <= MAX_PLAINTEXT_BYTES + GCM_TAG_BYTES:
            raise ValueError("ciphertext has an invalid length")
        return value
