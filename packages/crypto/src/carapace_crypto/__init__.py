"""Carapace cryptographic primitives.

- Envelope encryption v1 (AES-256-GCM data key wrapped with RSA-OAEP-SHA256)
- Canonical JSON for authenticated data
- Ed25519 signing and verification
- SHA-256 hashing and HMAC
- AES-GCM symmetric encryption
- Base64/hex encoding helpers
"""

from carapace_crypto.canonical import CanonicalJSONError, canonical_json
from carapace_crypto.encoding import b64_decode, b64_encode, hex_decode, hex_encode
from carapace_crypto.envelope import (
    Envelope,
    EnvelopeDecryptionError,
    EnvelopeError,
    compute_aad,
    open_with_dek_unwrapper,
    rsa_oaep_unwrapper,
    seal,
)
from carapace_crypto.hashing import hmac_sha256, sha256, sha256_hex
from carapace_crypto.signing import KeyPair, PublicKey, Signature
from carapace_crypto.symmetric import decrypt_aes_gcm, encrypt_aes_gcm

__all__ = [
    "CanonicalJSONError",
    "Envelope",
    "EnvelopeDecryptionError",
    "EnvelopeError",
    "KeyPair",
    "PublicKey",
    "Signature",
    "b64_decode",
    "b64_encode",
    "canonical_json",
    "compute_aad",
    "decrypt_aes_gcm",
    "encrypt_aes_gcm",
    "hex_decode",
    "hex_encode",
    "hmac_sha256",
    "open_with_dek_unwrapper",
    "rsa_oaep_unwrapper",
    "seal",
    "sha256",
    "sha256_hex",
]

__version__ = "0.1.0"
