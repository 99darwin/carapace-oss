"""Bounded decoding of upstream response bodies.

The executor asks for ``Accept-Encoding: identity``, but a server may still
answer with ``gzip`` or ``deflate``. Decoding happens here, one raw chunk at a
time, using zlib's ``max_length`` so that no chunk can inflate past the policy
cap before the cap is checked. A 32 KiB gzip bomb therefore costs 32 KiB of
memory, not the 80 MiB it would cost if the whole chunk were inflated first.

Chained codings (``gzip, gzip``) and anything other than gzip, deflate or
identity are refused: an honest server never sends them in reply to
``Accept-Encoding: identity``, and refusing is cheaper than reasoning about
nested bombs.
"""

from __future__ import annotations

import zlib
from collections.abc import Iterable

DECODABLE_ENCODINGS = frozenset({"identity", "gzip", "deflate"})
_GZIP_WBITS = zlib.MAX_WBITS | 16
_RAW_DEFLATE_WBITS = -zlib.MAX_WBITS


class UnsupportedEncodingError(ValueError):
    """The response uses a content coding this decoder will not handle."""


class DecodeError(ValueError):
    """The compressed body is corrupt."""


class OutputTooLargeError(ValueError):
    """Decoding would exceed the policy's response cap."""


def content_encoding(values: Iterable[str]) -> str:
    """Return the single content coding applied to a body.

    ``values`` are the raw ``Content-Encoding`` header values. Empty and
    ``identity`` tokens are ignored. Raises :class:`UnsupportedEncodingError`
    for chained codings or any coding outside :data:`DECODABLE_ENCODINGS`.
    """
    codings = [token.strip().lower() for value in values for token in value.split(",")]
    codings = [coding for coding in codings if coding and coding != "identity"]
    if not codings:
        return "identity"
    if len(codings) > 1 or codings[0] not in DECODABLE_ENCODINGS:
        raise UnsupportedEncodingError("unsupported content coding")
    return codings[0]


class BoundedDecoder:
    """Streaming decoder for one content coding with a hard output cap.

    ``decode`` and ``flush`` together never return more than ``cap`` bytes;
    the call that would cross the cap raises :class:`OutputTooLargeError`
    before the excess is materialized.
    """

    def __init__(self, encoding: str, cap: int) -> None:
        if encoding not in DECODABLE_ENCODINGS:
            raise UnsupportedEncodingError("unsupported content coding")
        if cap < 0:
            raise ValueError("cap must be non-negative")
        self._remaining = cap
        self._inflater: zlib._Decompress | None = None
        # RFC 9110 says ``deflate`` is zlib-wrapped, but raw deflate streams
        # are common in the wild. The first chunk decides which one this is.
        self._try_raw_deflate = encoding == "deflate"
        if encoding == "gzip":
            self._inflater = zlib.decompressobj(_GZIP_WBITS)
        elif encoding == "deflate":
            self._inflater = zlib.decompressobj()

    def decode(self, data: bytes) -> bytes:
        """Decode one raw chunk, returning whatever plaintext it yields."""
        if self._inflater is None:
            return self._take(data)
        out = bytearray()
        while data:
            out += self._take(self._inflate(data))
            data = self._inflater.unconsumed_tail
        return bytes(out)

    def flush(self) -> bytes:
        """Return any plaintext still buffered once the raw stream ends."""
        if self._inflater is None:
            return b""
        try:
            return self._take(self._inflater.flush())
        except zlib.error:
            raise DecodeError("corrupt compressed body") from None

    def _inflate(self, data: bytes) -> bytes:
        assert self._inflater is not None  # noqa: S101 - narrowed by callers
        # ``max_length`` of 0 means unlimited, so always ask for at least one
        # byte more than the cap: reaching it proves the body is too large.
        max_length = self._remaining + 1
        try:
            piece = self._inflater.decompress(data, max_length)
        except zlib.error:
            if not self._try_raw_deflate:
                raise DecodeError("corrupt compressed body") from None
            self._try_raw_deflate = False
            self._inflater = zlib.decompressobj(_RAW_DEFLATE_WBITS)
            return self._inflate(data)
        self._try_raw_deflate = False
        return piece

    def _take(self, piece: bytes) -> bytes:
        if len(piece) > self._remaining:
            raise OutputTooLargeError("response exceeds cap")
        self._remaining -= len(piece)
        return piece
