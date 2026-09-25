"""Request and response bodies for /v1/api-keys."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from carapace_server.apikeys.models import API_KEY_NAME_MAX_LENGTH

MAX_SECRETS_PER_KEY = 100


class ApiKeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=API_KEY_NAME_MAX_LENGTH)
    secret_ids: list[uuid.UUID] = Field(min_length=1, max_length=MAX_SECRETS_PER_KEY)
    expires_at: AwareDatetime | None = None


class ApiKeyResponse(BaseModel):
    id: uuid.UUID
    name: str
    key_prefix: str
    secret_ids: list[uuid.UUID]
    expires_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime


class ApiKeyCreated(ApiKeyResponse):
    """Includes the raw key. It is returned exactly once."""

    api_key: str
