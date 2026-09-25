"""/internal/*: the enclave's view of the server.

Everything here requires an attestation token, and everything but boot
registration a request signature from the boot's receipt key. Nothing here can reveal a
plaintext secret, because the server has none: the enclave fetches
owner-signed envelopes and grants, which it verifies itself, and uploads
signed receipts.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response, status

from carapace_server.apikeys.service import find_grant
from carapace_server.db import DbSession
from carapace_server.internal.deps import EnclaveAttestation, RegisteredBoot
from carapace_server.ratelimit import limiter
from carapace_server.receipts import service as receipts
from carapace_server.receipts.schemas import BootRegistration, KeyCheck, ReceiptBatch
from carapace_server.store.models import Secret
from carapace_server.store.service import envelope_dict

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal", tags=["internal"], include_in_schema=False)

# Enclaves are few and share NAT addresses; this only caps runaway clients.
INTERNAL_RATE_LIMIT = "1200/minute"


@router.post("/boots")
@limiter.limit(INTERNAL_RATE_LIMIT)
async def register_boot(
    request: Request,
    body: BootRegistration,
    attestation: EnclaveAttestation,
    db: DbSession,
    response: Response,
) -> dict[str, str]:
    try:
        boot, created = await receipts.register_boot(db, attestation, body)
    except receipts.BootRejectedError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None
    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return {"boot_id": boot.boot_id}


@router.get("/secrets/{secret_id}")
@limiter.limit(INTERNAL_RATE_LIMIT)
async def get_envelope(
    request: Request, secret_id: uuid.UUID, _boot: RegisteredBoot, db: DbSession
) -> dict[str, Any]:
    secret = await db.get(Secret, secret_id)
    if secret is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    return envelope_dict(secret)


@router.post("/keys/verify")
@limiter.limit(INTERNAL_RATE_LIMIT)
async def verify_key(
    request: Request, body: KeyCheck, _boot: RegisteredBoot, db: DbSession
) -> dict[str, Any]:
    """Return the key's current owner-signed grant, or 404 for an unknown key.

    Deliberately not a yes/no answer: a boolean from the server is not
    evidence. Revoked keys (whose grant may be a tombstone), expired grants
    and grants that do not cover ``secret_id`` are all returned, so the
    enclave decides from the signature and can record tombstones and
    narrowed grants in its monotonic cache. ``secret_id`` is only logged.
    """
    grant = await find_grant(db, body.key_hash)
    logger.debug(
        "key check for secret %s: %s", body.secret_id, "known" if grant else "unknown"
    )
    if grant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    return {"grant": grant}


@router.post("/receipts")
@limiter.limit(INTERNAL_RATE_LIMIT)
async def upload_receipts(
    request: Request, body: ReceiptBatch, boot: RegisteredBoot, db: DbSession
) -> dict[str, int]:
    try:
        accepted = await receipts.ingest_receipts(db, boot, body.receipts)
    except receipts.ReceiptRejectedError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None
    except receipts.ReceiptConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    return {"accepted": accepted}
