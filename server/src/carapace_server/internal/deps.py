"""Authentication for /internal/*.

Every call carries a Confidential Space attestation token. Registering a
boot binds that token's nonce to the boot's TLS and receipt keys. After
that, a token alone is not enough: owners can read boots' tokens from
/v1/receipts (they need them to verify receipts offline), so every other
call must also be signed with the boot's receipt key.

    message   = "carapace-internal-v1\n" METHOD "\n" PATH[?QUERY] "\n"
                TIMESTAMP "\n" hex(sha256(body))
    X-Carapace-Timestamp: unix seconds, within REQUEST_MAX_AGE_SECONDS
    X-Carapace-Signature: base64(Ed25519(receipt_key, message))
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from carapace_server.attestation import (
    Attestation,
    AttestationError,
    AttestationVerifier,
)
from carapace_server.db import DbSession
from carapace_server.receipts.chain import is_valid_signature
from carapace_server.receipts.models import EnclaveBoot
from carapace_server.receipts.service import find_boot
from carapace_server.store.envelope import b64decode_strict

logger = logging.getLogger(__name__)
_bearer = HTTPBearer(auto_error=False)

REQUEST_SIGNATURE_CONTEXT = b"carapace-internal-v1"
REQUEST_MAX_AGE_SECONDS = 60
MAX_SIGNATURE_HEADER_LENGTH = 128


async def require_attestation(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Attestation:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Attestation required")
    verifier: AttestationVerifier = request.app.state.attestation_verifier
    try:
        return await verifier.verify(credentials.credentials)
    except AttestationError as exc:
        # The reason names a claim, never token contents.
        logger.warning("attestation rejected: %s", exc)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Attestation rejected"
        ) from None


EnclaveAttestation = Annotated[Attestation, Depends(require_attestation)]


def request_signing_bytes(method: str, path: str, timestamp: int, body: bytes) -> bytes:
    """The bytes an enclave signs for an /internal call (after registration)."""
    return b"\n".join(
        (
            REQUEST_SIGNATURE_CONTEXT,
            method.upper().encode(),
            path.encode(),
            str(timestamp).encode(),
            hashlib.sha256(body).hexdigest().encode(),
        )
    )


def _path_with_query(request: Request) -> str:
    query = request.url.query
    return f"{request.url.path}?{query}" if query else request.url.path


async def _has_valid_request_signature(
    request: Request, boot: EnclaveBoot, timestamp: int, signature: str
) -> bool:
    if abs(time.time() - timestamp) > REQUEST_MAX_AGE_SECONDS:
        return False
    if len(signature) > MAX_SIGNATURE_HEADER_LENGTH:
        return False
    try:
        raw_signature = b64decode_strict(signature)
    except ValueError:
        return False
    message = request_signing_bytes(
        request.method, _path_with_query(request), timestamp, await request.body()
    )
    return is_valid_signature(boot.receipt_pubkey, message, raw_signature)


async def require_registered_boot(
    request: Request,
    attestation: EnclaveAttestation,
    db: DbSession,
    x_carapace_timestamp: Annotated[int | None, Header()] = None,
    x_carapace_signature: Annotated[str | None, Header()] = None,
) -> EnclaveBoot:
    """A registered boot, proven to hold its receipt key on this request."""
    boot = await find_boot(db, attestation.nonces)
    if boot is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Boot not registered")
    if x_carapace_timestamp is None or x_carapace_signature is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Request signature required")
    if not await _has_valid_request_signature(
        request, boot, x_carapace_timestamp, x_carapace_signature
    ):
        logger.warning("request signature rejected for boot %s", boot.boot_id)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Request signature rejected")
    return boot


RegisteredBoot = Annotated[EnclaveBoot, Depends(require_registered_boot)]
