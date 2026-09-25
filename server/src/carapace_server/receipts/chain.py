"""Receipt wire format, shared by ingest checks and offline verifiers.

    signed = canonical_json({"boot_id", "seq", "prev_hash", "payload"})
    hash   = sha256(signed).hex()
    sig    = Ed25519(receipt_key, signed)

The first receipt of a boot has ``seq`` 0 and ``prev_hash`` of 64 zeros.
"""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from carapace_server.canonical import canonical_json

GENESIS_PREV_HASH = "0" * 64


def boot_id_for(tls_spki_der: bytes, receipt_pubkey: bytes) -> str:
    return hashlib.sha256(tls_spki_der + receipt_pubkey).hexdigest()


def signed_bytes(
    boot_id: str, seq: int, prev_hash: str, payload: dict[str, Any]
) -> bytes:
    return canonical_json(
        {"boot_id": boot_id, "seq": seq, "prev_hash": prev_hash, "payload": payload}
    )


def receipt_hash(message: bytes) -> str:
    return hashlib.sha256(message).hexdigest()


def is_valid_signature(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True
