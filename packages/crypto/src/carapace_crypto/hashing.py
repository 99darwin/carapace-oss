"""Hashing utilities.

Provides SHA-256 hashing and HMAC-SHA256 for:
- Receipt hashing (tamper detection)
- Merkle tree node hashing
- Message authentication
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module


def sha256(data: bytes) -> bytes:
    """Compute SHA-256 hash of data.

    Args:
        data: Bytes to hash.

    Returns:
        32-byte SHA-256 digest.

    Example:
        >>> sha256(b"hello").hex()[:16]
        '2cf24dba5fb0a30e'
    """
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash and return as hex string.

    Args:
        data: Bytes to hash.

    Returns:
        64-character hex string.

    Example:
        >>> sha256_hex(b"hello")[:16]
        '2cf24dba5fb0a30e'
    """
    return hashlib.sha256(data).hexdigest()


def tagged_sha256(tag: bytes, data: bytes) -> bytes:
    """Domain-separated SHA-256: ``sha256(tag || 0x0A || data)``.

    ``tag`` is an ASCII context string such as ``b"carapace-key-bind-v1"``
    and must not contain a newline, so the framing is unambiguous. Every hash
    that a signature or lookup depends on uses a distinct tag; two different
    tags never share a preimage in practice.

    Raises:
        ValueError: If ``tag`` is empty or contains a newline.
    """
    if not tag or b"\n" in tag:
        raise ValueError("tag must be a non-empty string without newlines")
    return hashlib.sha256(tag + b"\n" + data).digest()


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA256.

    Args:
        key: Secret key for HMAC.
        message: Message to authenticate.

    Returns:
        32-byte HMAC digest.

    Example:
        >>> hmac_sha256(b"secret", b"message").hex()[:16]
        '2df787886e2e6d5e'
    """
    return hmac_module.new(key, message, hashlib.sha256).digest()


def hmac_sha256_verify(key: bytes, message: bytes, expected: bytes) -> bool:
    """Verify HMAC-SHA256 in constant time.

    Args:
        key: Secret key used to create the HMAC.
        message: Original message.
        expected: Expected HMAC digest to verify against.

    Returns:
        True if HMAC matches, False otherwise.
    """
    computed = hmac_sha256(key, message)
    return hmac_module.compare_digest(computed, expected)
