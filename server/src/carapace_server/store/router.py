"""/v1/secrets: owner CRUD over sealed envelopes."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Request, status

from carapace_server.auth.deps import CurrentUser
from carapace_server.db import DbSession
from carapace_server.ratelimit import limiter
from carapace_server.store import service
from carapace_server.store.models import Secret
from carapace_server.store.schemas import (
    SecretCreate,
    SecretDetail,
    SecretSummary,
    SecretUpdate,
)

router = APIRouter(prefix="/v1/secrets", tags=["secrets"])


def _not_found() -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, "Not found")


def _conflict() -> HTTPException:
    return HTTPException(status.HTTP_409_CONFLICT, "Secret id or name in use")


def _mismatch() -> HTTPException:
    return HTTPException(
        status.HTTP_422_UNPROCESSABLE_CONTENT,
        "Envelope secret_id/owner_id do not match this secret",
    )


def _detail(secret: Secret) -> SecretDetail:
    summary = SecretSummary.model_validate(secret)
    return SecretDetail(**summary.model_dump(), envelope=service.envelope_dict(secret))


@router.post("", status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
async def create_secret(
    request: Request, body: SecretCreate, user: CurrentUser, db: DbSession
) -> SecretDetail:
    try:
        secret = await service.create_secret(db, user.id, body.name, body.envelope)
    except service.EnvelopeMismatchError:
        raise _mismatch() from None
    except service.SecretConflictError:
        raise _conflict() from None
    return _detail(secret)


@router.get("")
async def list_secrets(user: CurrentUser, db: DbSession) -> list[SecretSummary]:
    secrets = await service.list_secrets(db, user.id)
    return [SecretSummary.model_validate(s) for s in secrets]


@router.get("/{secret_id}")
async def get_secret(
    secret_id: uuid.UUID, user: CurrentUser, db: DbSession
) -> SecretDetail:
    try:
        return _detail(await service.get_secret(db, user.id, secret_id))
    except service.SecretNotFoundError:
        raise _not_found() from None


@router.patch("/{secret_id}")
@limiter.limit("30/minute")
async def update_secret(
    request: Request,
    secret_id: uuid.UUID,
    body: SecretUpdate,
    user: CurrentUser,
    db: DbSession,
) -> SecretDetail:
    try:
        secret = await service.update_secret(
            db, user.id, secret_id, name=body.name, envelope=body.envelope
        )
    except service.SecretNotFoundError:
        raise _not_found() from None
    except service.EnvelopeMismatchError:
        raise _mismatch() from None
    except service.SecretConflictError:
        raise _conflict() from None
    return _detail(secret)


@router.delete("/{secret_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_secret(secret_id: uuid.UUID, user: CurrentUser, db: DbSession) -> None:
    try:
        await service.delete_secret(db, user.id, secret_id)
    except service.SecretNotFoundError:
        raise _not_found() from None
