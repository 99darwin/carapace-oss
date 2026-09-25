"""/v1/api-keys: owner management of agent API keys."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Request, status

from carapace_server.apikeys import service
from carapace_server.apikeys.models import ApiKey
from carapace_server.apikeys.schemas import (
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyResponse,
)
from carapace_server.auth.deps import CurrentUser
from carapace_server.db import DbSession
from carapace_server.ratelimit import limiter

router = APIRouter(prefix="/v1/api-keys", tags=["api-keys"])


def _response(api_key: ApiKey) -> ApiKeyResponse:
    return ApiKeyResponse(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        secret_ids=sorted(s.id for s in api_key.secrets),
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        created_at=api_key.created_at,
    )


@router.post("", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def create_api_key(
    request: Request, body: ApiKeyCreate, user: CurrentUser, db: DbSession
) -> ApiKeyCreated:
    try:
        api_key, raw_key = await service.create_api_key(
            db,
            user.id,
            name=body.name,
            secret_ids=body.secret_ids,
            expires_at=body.expires_at,
        )
    except service.ApiKeyError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    return ApiKeyCreated(**_response(api_key).model_dump(), api_key=raw_key)


@router.get("")
async def list_api_keys(user: CurrentUser, db: DbSession) -> list[ApiKeyResponse]:
    return [_response(k) for k in await service.list_api_keys(db, user.id)]


@router.delete("/{api_key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    api_key_id: uuid.UUID, user: CurrentUser, db: DbSession
) -> None:
    if not await service.revoke_api_key(db, user.id, api_key_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
