"""Encoding utilities.

Provides base64 and hex encoding/decoding for:
- Serializing signatures and hashes
- Safe transport of binary data

Every decoder here is strict: non-alphabet characters, bad padding and
non-canonical trailing bits are rejected, so a value has exactly one
encoding. Anything that feeds a signature or hash check must decode through
one of these.
"""

from __future__ import annotations

import base64
import binascii


def b64_encode(data: bytes) -> str:
    """Encode bytes to URL-safe base64 string (no padding).

    Example:
        >>> b64_encode(b"hello")
        'aGVsbG8'
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64_decode(encoded: str) -> bytes:
    """Decode URL-safe base64, padded or unpadded, strictly.

    Raises:
        ValueError: On non-alphabet characters, wrong padding or a
            non-canonical encoding.

    Example:
        >>> b64_decode('aGVsbG8')
        b'hello'
    """
    unpadded = encoded.rstrip("=")
    required_padding = -len(unpadded) % 4
    if required_padding == 3:  # length 1 mod 4 encodes nothing
        raise ValueError("invalid base64 length")
    if len(encoded) - len(unpadded) not in (0, required_padding):
        raise ValueError("invalid base64 padding")
    padded = unpadded + "=" * required_padding
    try:
        data = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("invalid base64") from exc
    if b64_encode(data) != unpadded:
        raise ValueError("non-canonical base64")
    return data


def b64_decode_strict(value: object, *, name: str = "value") -> bytes:
    """Decode standard padded base64 (RFC 4648 section 4), rejecting junk.

    ``value`` may be any JSON value; anything but a canonical base64 string
    raises. This is the decoder for every binary field of a signed object.

    Raises:
        ValueError: If ``value`` is not a canonically encoded string.
    """
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a base64 string")
    try:
        data = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ValueError(f"{name} is not valid base64") from exc
    if base64.b64encode(data).decode("ascii") != value:
        raise ValueError(f"{name} is not canonical base64")
    return data


def b64_encode_std(data: bytes) -> str:
    """Encode bytes as standard padded base64 (RFC 4648 section 4)."""
    return base64.b64encode(data).decode("ascii")


def hex_encode(data: bytes) -> str:
    """Encode bytes to lowercase hex string.

    Example:
        >>> hex_encode(b"\\x00\\xff")
        '00ff'
    """
    return data.hex()


def hex_decode(encoded: str) -> bytes:
    """Decode hex string to bytes.

    Raises:
        ValueError: If the string is not valid hex.

    Example:
        >>> hex_decode('00ff')
        b'\\x00\\xff'
    """
    return bytes.fromhex(encoded)
