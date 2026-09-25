"""Owner-scoped CRUD for sealed secrets."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from carapace_server.store.envelope import (
    EnvelopeV1,
    b64decode_strict,
    b64encode,
    compute_aad_hash,
)
from carapace_server.store.models import Secret


class SecretNotFoundError(Exception):
    """No such secret for this owner (or at all)."""


class SecretConflictError(Exception):
    """The id or the name is already taken."""


class EnvelopeMismatchError(Exception):
    """The envelope is bound to a different secret id or owner."""


def envelope_dict(secret: Secret) -> dict[str, Any]:
    """Rebuild the ``Envelope.to_dict()`` form for clients and the enclave."""
    return {
        "v": 1,
        "secret_id": str(secret.id),
        "owner_id": str(secret.owner_id),
        "policy": secret.policy_json,
        "kms_key_version": secret.kms_key_version,
        "wrapped": b64encode(secret.wrapped_dek),
        "nonce": b64encode(secret.nonce),
        "ct": b64encode(secret.ciphertext),
    }


def _apply_envelope(secret: Secret, envelope: EnvelopeV1) -> None:
    secret.policy_json = envelope.policy
    secret.aad_hash = compute_aad_hash(
        envelope.secret_id, envelope.owner_id, envelope.policy
    )
    secret.kms_key_version = envelope.kms_key_version
    secret.wrapped_dek = b64decode_strict(envelope.wrapped)
    secret.nonce = b64decode_strict(envelope.nonce)
    secret.ciphertext = b64decode_strict(envelope.ct)


def _check_binding(
    envelope: EnvelopeV1, secret_id: uuid.UUID, owner_id: uuid.UUID
) -> None:
    if envelope.secret_id != secret_id or envelope.owner_id != owner_id:
        raise EnvelopeMismatchError("envelope is bound to another secret or owner")


async def _commit_or_conflict(db: AsyncSession) -> None:
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise SecretConflictError("secret id or name already exists") from exc


async def create_secret(
    db: AsyncSession, owner_id: uuid.UUID, name: str, envelope: EnvelopeV1
) -> Secret:
    _check_binding(envelope, envelope.secret_id, owner_id)
    if await db.get(Secret, envelope.secret_id) is not None:
        raise SecretConflictError("secret id already exists")
    secret = Secret(id=envelope.secret_id, owner_id=owner_id, name=name)
    _apply_envelope(secret, envelope)
    db.add(secret)
    await _commit_or_conflict(db)
    return secret


async def get_secret(
    db: AsyncSession, owner_id: uuid.UUID, secret_id: uuid.UUID
) -> Secret:
    secret = await db.get(Secret, secret_id)
    if secret is None or secret.owner_id != owner_id:
        raise SecretNotFoundError(str(secret_id))
    return secret


async def list_secrets(db: AsyncSession, owner_id: uuid.UUID) -> Sequence[Secret]:
    result = await db.scalars(
        select(Secret).where(Secret.owner_id == owner_id).order_by(Secret.name)
    )
    return result.all()


async def update_secret(
    db: AsyncSession,
    owner_id: uuid.UUID,
    secret_id: uuid.UUID,
    *,
    name: str | None,
    envelope: EnvelopeV1 | None,
) -> Secret:
    secret = await get_secret(db, owner_id, secret_id)
    if envelope is not None:
        _check_binding(envelope, secret_id, owner_id)
        _apply_envelope(secret, envelope)
    if name is not None:
        secret.name = name
    await _commit_or_conflict(db)
    return secret


async def delete_secret(
    db: AsyncSession, owner_id: uuid.UUID, secret_id: uuid.UUID
) -> None:
    secret = await get_secret(db, owner_id, secret_id)
    await db.delete(secret)
    await db.commit()
