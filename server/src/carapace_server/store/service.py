"""Owner-scoped CRUD for sealed, owner-signed secrets."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from carapace_crypto import Envelope, b64_encode_std
from carapace_server.ownerkeys.service import find_active_owner_key
from carapace_server.store.models import Secret


class SecretNotFoundError(Exception):
    """No such secret for this owner (or at all)."""


class SecretConflictError(Exception):
    """The id or the name is already taken."""


class EnvelopeMismatchError(Exception):
    """The envelope is bound to a different secret id or owner."""


class UnknownOwnerKeyError(Exception):
    """The envelope is not signed by one of the caller's active owner keys."""


class StaleVersionError(Exception):
    """The envelope's version does not exceed the stored one."""


def envelope_dict(secret: Secret) -> dict[str, Any]:
    """Rebuild the signed ``Envelope.to_dict()`` form, byte for byte.

    Every column is the decoded value of a signed field, so the result
    verifies under ``owner_pk`` exactly as the client sent it.
    """
    return {
        "v": 1,
        "secret_id": str(secret.id),
        "owner_id": str(secret.owner_id),
        "owner_pk": b64_encode_std(secret.owner_pk),
        "version": secret.version,
        "policy": secret.policy_json,
        "kms_key_version": secret.kms_key_version,
        "wrapped": b64_encode_std(secret.wrapped_dek),
        "nonce": b64_encode_std(secret.nonce),
        "ct": b64_encode_std(secret.ciphertext),
        "sig": b64_encode_std(secret.signature),
    }


def _envelope_columns(envelope: Envelope) -> dict[str, Any]:
    return {
        "policy_json": envelope.policy,
        "owner_pk": envelope.owner_pk,
        "version": envelope.version,
        "signature": envelope.sig,
        "kms_key_version": envelope.kms_key_version,
        "wrapped_dek": envelope.wrapped,
        "nonce": envelope.nonce,
        "ciphertext": envelope.ct,
    }


async def _check_binding(
    db: AsyncSession, envelope: Envelope, secret_id: uuid.UUID, owner_id: uuid.UUID
) -> None:
    """The envelope names this secret and caller, under a key they hold.

    ``SignedEnvelope`` already verified the signature under
    ``envelope.owner_pk`` and required canonical UUID strings.
    """
    if envelope.secret_id != str(secret_id) or envelope.owner_id != str(owner_id):
        raise EnvelopeMismatchError("envelope is bound to another secret or owner")
    if await find_active_owner_key(db, owner_id, envelope.owner_pk) is None:
        raise UnknownOwnerKeyError("envelope owner key is not registered and active")


async def _commit_or_conflict(db: AsyncSession) -> None:
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise SecretConflictError("secret id or name already exists") from exc


async def create_secret(
    db: AsyncSession, owner_id: uuid.UUID, name: str, envelope: Envelope
) -> Secret:
    secret_id = uuid.UUID(envelope.secret_id)
    await _check_binding(db, envelope, secret_id, owner_id)
    if await db.get(Secret, secret_id) is not None:
        raise SecretConflictError("secret id already exists")
    secret = Secret(
        id=secret_id, owner_id=owner_id, name=name, **_envelope_columns(envelope)
    )
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
    envelope: Envelope | None,
) -> Secret:
    """Rename and/or replace the envelope.

    A replacement must carry a strictly higher ``version``. The comparison
    is part of the ``UPDATE`` so two concurrent uploads cannot both win.
    """
    secret = await get_secret(db, owner_id, secret_id)
    values: dict[str, Any] = {}
    statement = update(Secret).where(
        Secret.id == secret_id, Secret.owner_id == owner_id
    )
    if envelope is not None:
        await _check_binding(db, envelope, secret_id, owner_id)
        values |= _envelope_columns(envelope)
        statement = statement.where(Secret.version < envelope.version)
    if name is not None:
        values["name"] = name
    try:
        result = await db.execute(statement.values(**values))
    except IntegrityError as exc:
        await db.rollback()
        raise SecretConflictError("secret name already exists") from exc
    if result.rowcount != 1:
        await db.rollback()
        if envelope is not None:
            raise StaleVersionError("envelope version must increase")
        raise SecretNotFoundError(str(secret_id))
    await _commit_or_conflict(db)
    await db.refresh(secret)
    return secret


async def delete_secret(
    db: AsyncSession, owner_id: uuid.UUID, secret_id: uuid.UUID
) -> None:
    secret = await get_secret(db, owner_id, secret_id)
    await db.delete(secret)
    await db.commit()
