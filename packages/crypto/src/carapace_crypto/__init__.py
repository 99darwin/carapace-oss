"""Carapace cryptographic primitives.

- Envelope encryption v1 (AES-256-GCM data key wrapped with RSA-OAEP-SHA256,
  owner-signed with Ed25519)
- Owner signing keys, API keys and owner-signed grants
- Canonical JSON for authenticated data, with a duplicate-key-rejecting loader
- Ed25519 signing and verification
- SHA-256 hashing, tagged hashing and HMAC
- AES-GCM symmetric encryption
- Strict base64/hex encoding helpers
"""

from carapace_crypto.apikey import ApiKey, ApiKeyError
from carapace_crypto.canonical import (
    CanonicalJSONError,
    canonical_json,
    load_json_object,
)
from carapace_crypto.encoding import (
    b64_decode,
    b64_decode_strict,
    b64_encode,
    b64_encode_std,
    hex_decode,
    hex_encode,
)
from carapace_crypto.envelope import (
    Envelope,
    EnvelopeDecryptionError,
    EnvelopeError,
    EnvelopeSignatureError,
    EnvelopeStaleError,
    compute_aad,
    open_with_dek_unwrapper,
    rsa_oaep_unwrapper,
    seal,
    verify_envelope_signature,
)
from carapace_crypto.freshness import MonotonicCache, StaleError
from carapace_crypto.grant import (
    Grant,
    GrantError,
    GrantExpiredError,
    GrantKeyMismatchError,
    GrantScopeError,
    GrantSignatureError,
    create_grant,
    reissue_grant,
    verify_grant,
    verify_grant_signature,
)
from carapace_crypto.hashing import hmac_sha256, sha256, sha256_hex, tagged_sha256
from carapace_crypto.ownerkey import (
    OwnerKey,
    SignatureError,
    fingerprint,
    validate_public_key,
)
from carapace_crypto.signing import KeyPair, PublicKey, Signature
from carapace_crypto.symmetric import decrypt_aes_gcm, encrypt_aes_gcm

__all__ = [
    "ApiKey",
    "ApiKeyError",
    "CanonicalJSONError",
    "Envelope",
    "EnvelopeDecryptionError",
    "EnvelopeError",
    "EnvelopeSignatureError",
    "EnvelopeStaleError",
    "Grant",
    "GrantError",
    "GrantExpiredError",
    "GrantKeyMismatchError",
    "GrantScopeError",
    "GrantSignatureError",
    "KeyPair",
    "MonotonicCache",
    "OwnerKey",
    "PublicKey",
    "Signature",
    "SignatureError",
    "StaleError",
    "b64_decode",
    "b64_decode_strict",
    "b64_encode",
    "b64_encode_std",
    "canonical_json",
    "compute_aad",
    "create_grant",
    "reissue_grant",
    "decrypt_aes_gcm",
    "encrypt_aes_gcm",
    "fingerprint",
    "hex_decode",
    "hex_encode",
    "hmac_sha256",
    "load_json_object",
    "open_with_dek_unwrapper",
    "rsa_oaep_unwrapper",
    "seal",
    "sha256",
    "sha256_hex",
    "tagged_sha256",
    "validate_public_key",
    "verify_envelope_signature",
    "verify_grant",
    "verify_grant_signature",
]

__version__ = "0.1.0"
