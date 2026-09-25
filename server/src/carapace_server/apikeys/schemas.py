"""Request and response bodies for /v1/api-keys."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from carapace_server.apikeys.models import API_KEY_NAME_MAX_LENGTH

LookupHash = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class ApiKeyCreate(BaseModel):
    """Register a key the owner minted. ``grant`` is ``Grant.to_dict()``."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=API_KEY_NAME_MAX_LENGTH)
    lookup_hash: LookupHash
    grant: dict[str, Any]


class GrantUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grant: dict[str, Any]


class ApiKeyRevoke(BaseModel):
    """Optional tombstone: a newer grant for the same key with no secrets."""

    model_config = ConfigDict(extra="forbid")

    grant: dict[str, Any] | None = None


class ApiKeyResponse(BaseModel):
    id: uuid.UUID
    name: str
    key_prefix: str
    owner_fingerprint: str
    secret_ids: list[uuid.UUID]
    grant: dict[str, Any]
    grant_iat: int
    grant_exp: int
    last_used_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime
