"""Encoding utilities.

Provides base64 and hex encoding/decoding for:
- Serializing signatures and hashes
- Safe transport of binary data
"""

from __future__ import annotations

import base64


def b64_encode(data: bytes) -> str:
    """Encode bytes to URL-safe base64 string (no padding).

    Args:
        data: Bytes to encode.

    Returns:
        URL-safe base64 string without padding.

    Example:
        >>> b64_encode(b"hello")
        'aGVsbG8'
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64_decode(encoded: str) -> bytes:
    """Decode URL-safe base64 string to bytes.

    Handles both padded and unpadded input.

    Args:
        encoded: Base64 string (padded or unpadded).

    Returns:
        Decoded bytes.

    Example:
        >>> b64_decode('aGVsbG8')
        b'hello'
    """
    # Add padding if needed
    padding = 4 - (len(encoded) % 4)
    if padding != 4:
        encoded += "=" * padding
    return base64.urlsafe_b64decode(encoded)


def hex_encode(data: bytes) -> str:
    """Encode bytes to lowercase hex string.

    Args:
        data: Bytes to encode.

    Returns:
        Lowercase hex string.

    Example:
        >>> hex_encode(b"\\x00\\xff")
        '00ff'
    """
    return data.hex()


def hex_decode(encoded: str) -> bytes:
    """Decode hex string to bytes.

    Args:
        encoded: Hex string (case-insensitive).

    Returns:
        Decoded bytes.

    Raises:
        ValueError: If the string is not valid hex.

    Example:
        >>> hex_decode('00ff')
        b'\\x00\\xff'
    """
    return bytes.fromhex(encoded)
