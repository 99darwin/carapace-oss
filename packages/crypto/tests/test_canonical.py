"""Tests for canonical JSON."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from carapace_crypto.canonical import (
    MAX_DEPTH,
    MAX_SAFE_INTEGER,
    CanonicalJSONError,
    canonical_json,
)

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "envelope_v1.json").read_text()
)


@pytest.mark.parametrize("vector", VECTORS["canonical_json"], ids=lambda v: v["name"])
def test_vectors(vector: dict[str, Any]) -> None:
    expected = base64.b64decode(vector["canonical_b64"])
    assert canonical_json(vector["value"]) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"b": 1, "a": [1, "x", None, True]}, b'{"a":[1,"x",null,true],"b":1}'),
        ({"k": "café"}, '{"k":"café"}'.encode()),
        ({"k": "  "}, '{"k":"  "}'.encode()),
        ({"k": "\x00\x1f\x7f"}, b'{"k":"\\u0000\\u001f\x7f"}'),
        ({"k": "\b\t\n\f\r"}, b'{"k":"\\b\\t\\n\\f\\r"}'),
        ({"k": 'a"b\\c/d'}, b'{"k":"a\\"b\\\\c/d"}'),
        ({"B": 0, "a": 0, "é": 0}, '{"B":0,"a":0,"é":0}'.encode()),
        ({"t": (1, 2)}, b'{"t":[1,2]}'),
        ({"n": -0}, b'{"n":0}'),
    ],
)
def test_encoding(value: dict[str, Any], expected: bytes) -> None:
    assert canonical_json(value) == expected


def test_key_order_is_code_point_order() -> None:
    # U+FF61 sorts after U+1F511 in UTF-16 but before it by code point.
    encoded = canonical_json({"\U0001f511": 1, "｡": 2})
    assert encoded == '{"｡":2,"\U0001f511":1}'.encode()


def test_insertion_order_irrelevant() -> None:
    assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})


@pytest.mark.parametrize(
    "value",
    [
        {"f": 1.0},
        {"f": float("nan")},
        {"f": float("inf")},
        {"f": [float("-inf")]},
        {"i": MAX_SAFE_INTEGER + 1},
        {"i": -(MAX_SAFE_INTEGER + 1)},
        {1: "non-string key"},
        {"b": b"bytes"},
        {"s": {1, 2}},
        {"s": "\ud800"},
        {"\udfff": 1},
    ],
)
def test_rejects(value: dict[Any, Any]) -> None:
    with pytest.raises(CanonicalJSONError):
        canonical_json(value)


@pytest.mark.parametrize("value", [[], "x", 1, None])
def test_rejects_non_object_top_level(value: Any) -> None:
    with pytest.raises(CanonicalJSONError):
        canonical_json(value)


def test_depth_limit() -> None:
    nested: dict[str, Any] = {}
    cursor = nested
    for _ in range(MAX_DEPTH + 1):
        cursor["x"] = {}
        cursor = cursor["x"]
    with pytest.raises(CanonicalJSONError):
        canonical_json(nested)


def test_safe_integer_bounds_accepted() -> None:
    value = {"hi": MAX_SAFE_INTEGER, "lo": -MAX_SAFE_INTEGER}
    assert canonical_json(value) == b'{"hi":9007199254740991,"lo":-9007199254740991}'
