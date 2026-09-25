"""Canonical JSON, byte-compatible with ``carapace_crypto.canonical``.

Used for envelope AAD hashes and receipt signatures. Callers must reject
floats first (``reject_floats``); for every other JSON value this matches
RFC 8785 and the crypto package.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def reject_floats(value: Any) -> None:
    """Raise ValueError if a float appears anywhere in ``value``."""
    if isinstance(value, float):
        raise ValueError("floats are not allowed in canonical JSON")
    if isinstance(value, dict):
        for item in value.values():
            reject_floats(item)
    elif isinstance(value, list):
        for item in value:
            reject_floats(item)
