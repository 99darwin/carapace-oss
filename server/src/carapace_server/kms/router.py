"""/v1/kms/public-key: the key clients seal envelopes to.

The server is untrusted, so this is only a hint: the CLI refuses to seal
unless it equals the KMS key reported by an enclave it has verified over the
attested TLS channel. It exists so that a mismatch (a compromised or
misconfigured server) is detected rather than silently trusted either way.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from carapace_server.auth.deps import AppSettings, CurrentUser

router = APIRouter(prefix="/v1/kms", tags=["kms"])


class KmsPublicKey(BaseModel):
    public_key_pem: str
    key_version: str


@router.get("/public-key")
async def kms_public_key(_: CurrentUser, settings: AppSettings) -> KmsPublicKey:
    if settings.kms_public_key_pem is None or settings.kms_key_version is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "KMS public key is not configured"
        )
    return KmsPublicKey(
        public_key_pem=settings.kms_public_key_pem,
        key_version=settings.kms_key_version,
    )
