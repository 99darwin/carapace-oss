"""/v1/api-keys: owner management of client-minted agent API keys."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Request, status

from carapace_server.apikeys import service
from carapace_server.apikeys.models import ApiKey
from carapace_server.apikeys.schemas import (
    ApiKeyCreate,
    ApiKeyResponse,
    ApiKeyRevoke,
    GrantUpdate,
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
        owner_fingerprint=api_key.owner_key.fingerprint,
        secret_ids=sorted(s.id for s in api_key.secrets),
        grant=api_key.grant_json,
        grant_iat=api_key.grant_iat,
        grant_exp=api_key.grant_exp,
        last_used_at=api_key.last_used_at,
        revoked_at=api_key.revoked_at,
        created_at=api_key.created_at,
    )


def _bad_request(exc: service.ApiKeyError) -> HTTPException:
    return HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))


def _not_found() -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, "Not found")


def _stale() -> HTTPException:
    return HTTPException(
        status.HTTP_409_CONFLICT, "Grant iat must exceed the stored grant's"
    )


@router.post("", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def create_api_key(
    request: Request, body: ApiKeyCreate, user: CurrentUser, db: DbSession
) -> ApiKeyResponse:
    try:
        api_key = await service.create_api_key(
            db,
            user.id,
            name=body.name,
            lookup_hash=body.lookup_hash,
            grant_wire=body.grant,
        )
    except service.ApiKeyError as exc:
        raise _bad_request(exc) from None
    except service.ApiKeyConflictError:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Key already registered"
        ) from None
    return _response(api_key)


@router.get("")
async def list_api_keys(user: CurrentUser, db: DbSession) -> list[ApiKeyResponse]:
    return [_response(k) for k in await service.list_api_keys(db, user.id)]


@router.put("/{api_key_id}/grant")
@limiter.limit("30/minute")
async def update_grant(
    request: Request,
    api_key_id: uuid.UUID,
    body: GrantUpdate,
    user: CurrentUser,
    db: DbSession,
) -> ApiKeyResponse:
    try:
        api_key = await service.update_grant(db, user.id, api_key_id, body.grant)
    except service.ApiKeyNotFoundError:
        raise _not_found() from None
    except service.ApiKeyError as exc:
        raise _bad_request(exc) from None
    except service.StaleGrantError:
        raise _stale() from None
    return _response(api_key)


@router.post("/{api_key_id}/revoke", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("30/minute")
async def revoke_api_key(
    request: Request,
    api_key_id: uuid.UUID,
    user: CurrentUser,
    db: DbSession,
    body: Annotated[ApiKeyRevoke | None, Body()] = None,
) -> None:
    tombstone = body.grant if body is not None else None
    try:
        await service.revoke_api_key(db, user.id, api_key_id, tombstone)
    except service.ApiKeyNotFoundError:
        raise _not_found() from None
    except service.ApiKeyError as exc:
        raise _bad_request(exc) from None
    except service.StaleGrantError:
        raise _stale() from None
