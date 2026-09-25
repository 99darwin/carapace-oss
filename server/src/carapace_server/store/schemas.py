"""Request and response bodies for /v1/secrets."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, model_validator

from carapace_server.store.envelope import EnvelopeV1
from carapace_server.store.models import SECRET_NAME_MAX_LENGTH

SecretName = Field(min_length=1, max_length=SECRET_NAME_MAX_LENGTH)


class SecretCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = SecretName
    envelope: EnvelopeV1


class SecretUpdate(BaseModel):
    """Rename and/or replace the envelope.

    There is deliberately no ``policy`` field: the policy is bound into the
    AAD, so changing it means re-sealing on the client and sending a new
    envelope.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(
        default=None, min_length=1, max_length=SECRET_NAME_MAX_LENGTH
    )
    envelope: EnvelopeV1 | None = None

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
    aad_hash: str
    kms_key_version: str | None
    created_at: datetime
    updated_at: datetime


class SecretDetail(SecretSummary):
    envelope: dict[str, Any]
