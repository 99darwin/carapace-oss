"""Request and response bodies for /v1/secrets."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    PlainValidator,
    model_validator,
)

from carapace_crypto import (
    Envelope,
    EnvelopeError,
    canonical_json,
    verify_envelope_signature,
)
from carapace_server.ids import parse_canonical_uuid
from carapace_server.store.models import (
    KMS_KEY_VERSION_MAX_LENGTH,
    SECRET_NAME_MAX_LENGTH,
    WRAPPED_DEK_MAX_BYTES,
)

# Tighter than the format's 64 KiB header cap; policies are small.
MAX_POLICY_BYTES = 16 * 1024

SecretName = Field(min_length=1, max_length=SECRET_NAME_MAX_LENGTH)


def parse_signed_envelope(value: Any) -> Envelope:
    """Parse and signature-check an envelope with ``carapace_crypto``.

    The signature is checked against the envelope's own ``owner_pk`` here;
    whether that key belongs to the caller is checked in the service. This
    is defense in depth: the enclave repeats every check against the
    fingerprint in the agent's API key, which the server never sees.

    The server-side limits on top of the format keep the rebuilt envelope
    identical to the signed one (canonical UUID strings) and fit the
    database columns.

    Raises:
        ValueError: On any shape, signature or limit failure.
    """
    if not isinstance(value, dict):
        raise ValueError("envelope must be a JSON object")
    try:
        envelope = Envelope.from_dict(value)
        verify_envelope_signature(envelope)
    except EnvelopeError as exc:
        raise ValueError(f"invalid envelope: {exc}") from None
    parse_canonical_uuid(envelope.secret_id)
    parse_canonical_uuid(envelope.owner_id)
    if len(envelope.wrapped) > WRAPPED_DEK_MAX_BYTES:
        raise ValueError("wrapped key has an invalid length")
    kms_key_version = envelope.kms_key_version
    if kms_key_version is not None and not (
        0 < len(kms_key_version) <= KMS_KEY_VERSION_MAX_LENGTH
    ):
        raise ValueError("kms_key_version has an invalid length")
    if len(canonical_json(envelope.policy)) > MAX_POLICY_BYTES:
        raise ValueError("policy too large")
    return envelope


SignedEnvelope = Annotated[
    Envelope,
    PlainValidator(parse_signed_envelope, json_schema_input_type=dict[str, Any]),
]


class SecretCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = SecretName
    envelope: SignedEnvelope


class SecretUpdate(BaseModel):
    """Rename and/or replace the envelope.

    There is deliberately no ``policy`` field: the policy is bound into the
    AAD and the owner signature, so changing it means re-sealing on the
    client and sending a new envelope with a higher ``version``.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(
        default=None, min_length=1, max_length=SECRET_NAME_MAX_LENGTH
    )
    envelope: SignedEnvelope | None = None

    @model_validator(mode="after")
    def _not_empty(self) -> SecretUpdate:
        if self.name is None and self.envelope is None:
            raise ValueError("nothing to update")
        return self


class SecretSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    policy: dict[str, Any] = Field(
        validation_alias=AliasChoices("policy_json", "policy")
    )
    version: int
    owner_fingerprint: str
    kms_key_version: str | None
    created_at: datetime
    updated_at: datetime


class SecretDetail(SecretSummary):
    envelope: dict[str, Any]
