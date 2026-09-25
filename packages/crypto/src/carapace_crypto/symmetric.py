"""Symmetric encryption utilities.

Provides AES-GCM encryption/decryption for:
- Encrypting audit logs before leaving enclave
- Local encrypted storage
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constants
NONCE_SIZE = 12  # 96 bits, recommended for AES-GCM
KEY_SIZE = 32  # 256 bits


@dataclass(frozen=True, slots=True)
class EncryptedData:
    """Container for encrypted data with its nonce.

    The nonce is required for decryption and must be stored
    alongside the ciphertext.
    """

    nonce: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        """Serialize to bytes (nonce || ciphertext)."""
        return self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> EncryptedData:
        """Deserialize from bytes."""
        if len(data) < NONCE_SIZE:
            raise ValueError("Data too short to contain nonce")
        return cls(nonce=data[:NONCE_SIZE], ciphertext=data[NONCE_SIZE:])


def generate_key() -> bytes:
    """Generate a random 256-bit AES key.

    Returns:
        32-byte random key.
    """
    return os.urandom(KEY_SIZE)


def encrypt_aes_gcm(
    key: bytes,
    plaintext: bytes,
    associated_data: bytes | None = None,
) -> EncryptedData:
    """Encrypt data using AES-256-GCM.

    AES-GCM provides both confidentiality and authenticity.
    The nonce is randomly generated and included in the output.

    Args:
        key: 32-byte AES key.
        plaintext: Data to encrypt.
        associated_data: Optional additional authenticated data (AAD).
                        This data is authenticated but not encrypted.

    Returns:
        EncryptedData containing nonce and ciphertext.

    Raises:
        ValueError: If key is wrong size.

    Example:
        >>> key = generate_key()
        >>> encrypted = encrypt_aes_gcm(key, b"secret message")
        >>> decrypt_aes_gcm(key, encrypted)
        b'secret message'
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    return EncryptedData(nonce=nonce, ciphertext=ciphertext)


def decrypt_aes_gcm(
    key: bytes,
    encrypted: EncryptedData,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt data using AES-256-GCM.

    Args:
        key: 32-byte AES key (same as used for encryption).
        encrypted: EncryptedData containing nonce and ciphertext.
        associated_data: Optional AAD (must match what was used during encryption).

    Returns:
        Decrypted plaintext.

    Raises:
        ValueError: If key is wrong size.
        cryptography.exceptions.InvalidTag: If authentication fails
            (data was tampered with or wrong key/AAD).

    Example:
        >>> key = generate_key()
        >>> encrypted = encrypt_aes_gcm(key, b"secret", b"context")
        >>> decrypt_aes_gcm(key, encrypted, b"context")
        b'secret'
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(encrypted.nonce, encrypted.ciphertext, associated_data)
