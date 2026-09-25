"""/v1/owner-keys: owners register the public halves of their signing keys."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Request, status

from carapace_crypto.encoding import b64_decode_strict, b64_encode_std
from carapace_server.auth.deps import CurrentUser
from carapace_server.db import DbSession
from carapace_server.ownerkeys import service
from carapace_server.ownerkeys.models import OwnerKey
from carapace_server.ownerkeys.schemas import OwnerKeyCreate, OwnerKeyResponse
from carapace_server.ratelimit import limiter

router = APIRouter(prefix="/v1/owner-keys", tags=["owner-keys"])


def _response(owner_key: OwnerKey) -> OwnerKeyResponse:
    return OwnerKeyResponse(
        id=owner_key.id,
        public_key=b64_encode_std(owner_key.public_key),
        fingerprint=owner_key.fingerprint,
        created_at=owner_key.created_at,
        retired_at=owner_key.retired_at,
    )


@router.post("", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def register_owner_key(
    request: Request, body: OwnerKeyCreate, user: CurrentUser, db: DbSession
) -> OwnerKeyResponse:
    public_key = b64_decode_strict(body.public_key, name="public_key")
    try:
        owner_key = await service.register_owner_key(db, user.id, public_key)
    except service.OwnerKeyConflictError:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Owner key already registered"
        ) from None
    except service.OwnerKeyLimitError:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"At most {service.MAX_OWNER_KEYS_PER_USER} owner keys per account",
        ) from None
    return _response(owner_key)


@router.get("")
async def list_owner_keys(user: CurrentUser, db: DbSession) -> list[OwnerKeyResponse]:
    return [_response(k) for k in await service.list_owner_keys(db, user.id)]


@router.post("/{owner_key_id}/retire")
@limiter.limit("10/minute")
async def retire_owner_key(
    request: Request, owner_key_id: uuid.UUID, user: CurrentUser, db: DbSession
) -> OwnerKeyResponse:
    try:
        owner_key = await service.retire_owner_key(db, user.id, owner_key_id)
    except service.OwnerKeyNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found") from None
    return _response(owner_key)
