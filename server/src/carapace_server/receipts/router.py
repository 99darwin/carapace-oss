"""/v1/receipts: an owner's receipts plus the boots that signed them."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

from carapace_crypto import b64_encode_std
from carapace_server.auth.deps import CurrentUser
from carapace_server.db import DbSession
from carapace_server.receipts import service
from carapace_server.receipts.models import EnclaveBoot, Receipt
from carapace_server.receipts.schemas import BootOut, ReceiptOut, ReceiptPage

router = APIRouter(prefix="/v1/receipts", tags=["receipts"])

DEFAULT_PAGE_SIZE = 200
MAX_PAGE_SIZE = 1000
CURSOR_PATTERN = r"^[0-9a-f]{64}:[0-9]{1,16}$"


def boot_out(boot: EnclaveBoot) -> BootOut:
    return BootOut(
        boot_id=boot.boot_id,
        attestation_token=boot.attestation_token,
        receipt_pubkey=b64_encode_std(boot.receipt_pubkey),
        tls_cert_pem=boot.tls_cert_pem,
        image_digest=boot.image_digest,
        first_seen=boot.first_seen,
    )


def receipt_out(receipt: Receipt) -> ReceiptOut:
    return ReceiptOut(
        boot_id=receipt.boot_id,
        seq=receipt.seq,
        prev_hash=receipt.prev_hash,
        hash=receipt.hash,
        payload=receipt.payload,
        signature=b64_encode_std(receipt.signature),
    )


@router.get("")
async def list_receipts(
    user: CurrentUser,
    db: DbSession,
    secret_id: uuid.UUID | None = None,
    cursor: Annotated[str | None, Query(pattern=CURSOR_PATTERN)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
) -> ReceiptPage:
    """Receipts are verbatim, so the CLI can check signatures offline.

    A boot's chain interleaves every owner's receipts, so an owner sees
    ``seq`` gaps where other owners' receipts sit.
    """
    try:
        after = service.parse_cursor(cursor) if cursor else None
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid cursor") from None
    receipts, boots, next_cursor = await service.owner_receipts(
        db, user.id, secret_id=secret_id, after=after, limit=limit
    )
    return ReceiptPage(
        boots=[boot_out(b) for b in boots],
        receipts=[receipt_out(r) for r in receipts],
        next_cursor=next_cursor,
    )
