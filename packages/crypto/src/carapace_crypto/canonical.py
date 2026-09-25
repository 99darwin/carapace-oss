"""Canonical JSON encoding used to derive authenticated data.

Envelope v1 binds a secret to its policy by hashing a canonical JSON
serialization. Every client (Python CLI, enclave, any future SDK) must produce
byte-identical output, so the encoding is deliberately narrow:

* The top-level value must be an object.
* Allowed value types: object (``dict`` with ``str`` keys), array (``list`` or
  ``tuple``), string, integer, ``true``/``false``, ``null``.
* Floats are rejected, including NaN and the infinities. Integers must lie in
  the IEEE-754 safe range ``[-(2**53 - 1), 2**53 - 1]`` so JavaScript clients
  round-trip them exactly.
* Object keys are sorted by their UTF-16 code units, as RFC 8785 §3.2.3
  requires (and as JavaScript's default string sort does). This differs from
  code point order only for keys outside the BMP.
* No insignificant whitespace: separators are ``,`` and ``:``.
* Strings are emitted as UTF-8 with no ``\\u`` escaping of non-ASCII
  characters. Only ``"``, ``\\`` and control characters U+0000..U+001F are
  escaped; ``\\b \\t \\n \\f \\r`` use their short forms and the rest use
  lowercase ``\\u00xx``. Unicode is not normalized. Lone surrogates are
  rejected.
* Nesting deeper than ``MAX_DEPTH`` is rejected.

This matches RFC 8785 (JCS) for every input it accepts.
"""

from __future__ import annotations

import json
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1
MAX_DEPTH = 32
# Largest JSON document ``load_json_object`` will parse.
MAX_JSON_BYTES = 256 * 1024


class CanonicalJSONError(ValueError):
    """Raised when a value cannot be canonically encoded."""


def canonical_json(value: dict[str, Any]) -> bytes:
    """Encode ``value`` as canonical JSON (UTF-8 bytes).

    Raises:
        CanonicalJSONError: If the value contains unsupported types, floats,
            out-of-range integers, non-string keys, lone surrogates, or is
            nested too deeply.
    """
    if not isinstance(value, dict):
        raise CanonicalJSONError("top-level value must be a JSON object")
    _validate(value, depth=0)
    text = json.dumps(
        _sorted(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=False,
        separators=(",", ":"),
    )
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalJSONError("strings must not contain lone surrogates") from exc


def load_json_object(
    data: bytes | str, *, max_bytes: int = MAX_JSON_BYTES
) -> dict[str, Any]:
    """Parse a JSON object from untrusted input, rejecting duplicate keys.

    ``json.loads`` silently keeps the last of two equal keys, so a stored
    document could carry one ``policy`` for a validator and another for the
    consumer. Everything that verifies a signature or hash over a parsed
    object must parse it through this function.

    Raises:
        CanonicalJSONError: If the input is too large, is not valid JSON, is
            not an object, or repeats a key in any object.
    """
    if isinstance(data, str):
        data = data.encode("utf-8", errors="surrogatepass")
    if len(data) > max_bytes:
        raise CanonicalJSONError(f"JSON document exceeds {max_bytes} bytes")
    try:
        value = json.loads(data, object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, RecursionError) as exc:
        # ``json.JSONDecodeError`` is a ``ValueError``; the message from a
        # duplicate key is our own and worth keeping.
        raise CanonicalJSONError(f"invalid JSON: {exc}") from None
    if not isinstance(value, dict):
        raise CanonicalJSONError("top-level value must be a JSON object")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key!r}")
        result[key] = value
    return result


def _utf16_key(key: str) -> bytes:
    # Big-endian UTF-16 compares bytewise in code-unit order. Lone surrogates
    # are rejected later, when the output is encoded as UTF-8.
    return key.encode("utf-16-be", errors="surrogatepass")


def _sorted(value: Any) -> Any:
    """Rebuild ``value`` with every object's keys in RFC 8785 order."""
    if isinstance(value, dict):
        return {k: _sorted(value[k]) for k in sorted(value, key=_utf16_key)}
    if isinstance(value, (list, tuple)):
        return [_sorted(item) for item in value]
    return value


def _validate(value: Any, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalJSONError(f"nesting deeper than {MAX_DEPTH}")
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalJSONError("integer outside the safe range")
        return
    if isinstance(value, float):
        raise CanonicalJSONError("floats are not allowed")
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJSONError("object keys must be strings")
            _validate(item, depth + 1)
        return
    raise CanonicalJSONError(f"unsupported type: {type(value).__name__}")
