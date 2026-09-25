"""Boot registration, receipt ingest, and owner queries."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from carapace_crypto import b64_decode_strict
from carapace_server.attestation import Attestation
from carapace_server.receipts.chain import (
    GENESIS_PREV_HASH,
    boot_id_for,
    is_valid_signature,
    receipt_hash,
    signed_bytes,
)
from carapace_server.receipts.models import EnclaveBoot, Receipt
from carapace_server.receipts.schemas import BootRegistration, ReceiptIn
from carapace_server.store.models import Secret

CURSOR_SEPARATOR = ":"


class BootRejectedError(Exception):
    """The certificate is unusable or the nonce does not bind these keys."""


class ReceiptRejectedError(Exception):
    """Bad signature, wrong boot, or a gap or fork in the chain."""


class ReceiptConflictError(Exception):
    """A different receipt is already stored at this position."""


def _spki_der(tls_cert_pem: str) -> bytes:
    try:
        cert = x509.load_pem_x509_certificate(tls_cert_pem.encode())
    except ValueError as exc:
        raise BootRejectedError("invalid TLS certificate") from exc
    return cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )


async def register_boot(
    db: AsyncSession, attestation: Attestation, registration: BootRegistration
) -> tuple[EnclaveBoot, bool]:
    """Store a boot whose attestation nonce binds its TLS and receipt keys.

    Returns the boot and whether it was newly created.
    """
    pubkey = b64_decode_strict(registration.receipt_pubkey, name="receipt_pubkey")
    boot_id = boot_id_for(_spki_der(registration.tls_cert_pem), pubkey)
    if boot_id not in attestation.nonces:
        raise BootRejectedError("eat_nonce does not bind these keys")
    existing = await db.get(EnclaveBoot, boot_id)
    if existing is not None:
        return existing, False
    boot = EnclaveBoot(
        boot_id=boot_id,
        attestation_token=attestation.token,
        receipt_pubkey=pubkey,
        tls_cert_pem=registration.tls_cert_pem,
        image_digest=attestation.image_digest,
    )
    db.add(boot)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return await db.get(EnclaveBoot, boot_id), False
    return boot, True


async def find_boot(db: AsyncSession, nonces: Sequence[str]) -> EnclaveBoot | None:
    """The registered boot this attestation token belongs to, if any."""
    return await db.scalar(
        select(EnclaveBoot).where(EnclaveBoot.boot_id.in_(nonces)).limit(1)
    )


def _uuid_or_none(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value))
    except ValueError:
        return None


async def _owner_of(
    db: AsyncSession, payload: dict[str, Any]
) -> tuple[uuid.UUID | None, uuid.UUID | None]:
    """The secret and owner a receipt belongs to.

    The ``owner_id`` the enclave signed wins. It comes from the AAD-bound
    envelope the enclave actually used, so it is authoritative even when the
    secret has since been deleted or its client-chosen id has been re-created
    by another account; consulting the table first would hand the previous
    owner's receipts to the squatter. The stored secret is only a fallback
    for receipts that carry no ``owner_id``.
    """
    secret_id = _uuid_or_none(payload.get("secret_id"))
    if secret_id is None:
        return None, None
    owner_id = _uuid_or_none(payload.get("owner_id"))
    if owner_id is None:
        owner_id = await db.scalar(
            select(Secret.owner_id).where(Secret.id == secret_id)
        )
    return secret_id, owner_id


async def _chain_tip(db: AsyncSession, boot_id: str) -> tuple[int, str]:
    last = await db.scalar(
        select(Receipt)
        .where(Receipt.boot_id == boot_id)
        .order_by(Receipt.seq.desc())
        .limit(1)
    )
    return (last.seq + 1, last.hash) if last else (0, GENESIS_PREV_HASH)


async def _stage(
    db: AsyncSession, boot: EnclaveBoot, receipts: Sequence[ReceiptIn]
) -> int:
    next_seq, tip = await _chain_tip(db, boot.boot_id)
    accepted = 0
    for receipt in receipts:
        if receipt.boot_id != boot.boot_id:
            raise ReceiptRejectedError("receipt belongs to another boot")
        message = signed_bytes(
            receipt.boot_id, receipt.seq, receipt.prev_hash, receipt.payload
        )
        signature = b64_decode_strict(receipt.signature, name="signature")
        if not is_valid_signature(boot.receipt_pubkey, message, signature):
            raise ReceiptRejectedError(f"bad signature at seq {receipt.seq}")
        digest = receipt_hash(message)
        if receipt.seq < next_seq:
            stored = await db.scalar(
                select(Receipt.hash).where(
                    Receipt.boot_id == boot.boot_id, Receipt.seq == receipt.seq
                )
            )
            if stored != digest:
                raise ReceiptConflictError(f"different receipt at seq {receipt.seq}")
            continue  # idempotent retry
        if receipt.seq != next_seq or receipt.prev_hash != tip:
            raise ReceiptRejectedError(f"chain broken at seq {receipt.seq}")
        secret_id, owner_id = await _owner_of(db, receipt.payload)
        db.add(
            Receipt(
                boot_id=boot.boot_id,
                seq=receipt.seq,
                prev_hash=receipt.prev_hash,
                hash=digest,
                payload=receipt.payload,
                signature=signature,
                secret_id=secret_id,
                owner_id=owner_id,
            )
        )
        next_seq, tip = receipt.seq + 1, digest
        accepted += 1
    return accepted


async def ingest_receipts(
    db: AsyncSession, boot: EnclaveBoot, receipts: Sequence[ReceiptIn]
) -> int:
    """Append a batch atomically. Returns how many receipts were new."""
    try:
        accepted = await _stage(db, boot, receipts)
        await db.commit()
    except (ReceiptRejectedError, ReceiptConflictError):
        await db.rollback()
        raise
    except IntegrityError as exc:
        await db.rollback()
        raise ReceiptConflictError("concurrent append") from exc
    return accepted


def parse_cursor(cursor: str) -> tuple[str, int]:
    boot_id, _, seq = cursor.partition(CURSOR_SEPARATOR)
    return boot_id, int(seq)


async def owner_receipts(
    db: AsyncSession,
    owner_id: uuid.UUID,
    *,
    secret_id: uuid.UUID | None,
    after: tuple[str, int] | None,
    limit: int,
) -> tuple[list[Receipt], list[EnclaveBoot], str | None]:
    query = select(Receipt).where(Receipt.owner_id == owner_id)
    if secret_id is not None:
        query = query.where(Receipt.secret_id == secret_id)
    if after is not None:
        boot_id, seq = after
        query = query.where(
            or_(
                Receipt.boot_id > boot_id,
                and_(Receipt.boot_id == boot_id, Receipt.seq > seq),
            )
        )
    rows = list(
        await db.scalars(query.order_by(Receipt.boot_id, Receipt.seq).limit(limit + 1))
    )
    page, more = rows[:limit], len(rows) > limit
    boot_ids = {r.boot_id for r in page}
    boots = list(
        await db.scalars(
            select(EnclaveBoot)
            .where(EnclaveBoot.boot_id.in_(boot_ids))
            .order_by(EnclaveBoot.first_seen)
        )
    )
    last = page[-1] if more else None
    cursor = f"{last.boot_id}{CURSOR_SEPARATOR}{last.seq}" if last else None
    return page, boots, cursor
