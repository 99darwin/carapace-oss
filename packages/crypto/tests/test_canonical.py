"""Tests for canonical JSON."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from carapace_crypto.canonical import (
    MAX_DEPTH,
    MAX_JSON_BYTES,
    MAX_SAFE_INTEGER,
    CanonicalJSONError,
    canonical_json,
    load_json_object,
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


def test_key_order_is_utf16_code_unit_order() -> None:
    # RFC 8785 §3.2.3: U+1F511 (surrogates D83D DD11) sorts before U+FF61,
    # although it is the larger code point. Output matches JCS implementations
    # and ``JSON.stringify`` over ``Object.keys(o).sort()``.
    encoded = canonical_json({"｡": 2, "\U0001f511": 1})
    assert encoded == '{"\U0001f511":1,"｡":2}'.encode()


def test_nested_key_order() -> None:
    value = {"z": {"b": [{"y": 1, "x": 2}], "a": None}, "a": 0}
    assert canonical_json(value) == b'{"a":0,"z":{"a":null,"b":[{"x":2,"y":1}]}}'


def test_rfc8785_sorting_example() -> None:
    # RFC 8785 §3.2.3 key-sorting example (values replaced for brevity).
    keys = ["\u20ac", "\r", "\ufb33", "1", "\U0001f600", "\u0080", "\u00f6"]
    encoded = canonical_json({key: 0 for key in keys}).decode()
    expected = ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\U0001f600", "\ufb33"]
    assert list(json.loads(encoded)) == expected


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


class TestLoadJsonObject:
    def test_parses_text_and_bytes(self) -> None:
        assert load_json_object('{"a": [1, {"b": null}]}') == {"a": [1, {"b": None}]}
        assert load_json_object(b'{"caf\xc3\xa9": true}') == {"café": True}

    @pytest.mark.parametrize(
        "text",
        [
            '{"a": 1, "a": 2}',
            '{"a": {"b": 1, "b": 2}}',
            '{"a": [{"b": 1, "b": 1}]}',
            '{"a": 1, "a": 1}',
        ],
    )
    def test_rejects_duplicate_keys(self, text: str) -> None:
        with pytest.raises(CanonicalJSONError, match="duplicate"):
            load_json_object(text)

    @pytest.mark.parametrize("text", ["[]", "1", '"s"', "null", "", "{", "{} {}"])
    def test_rejects_non_objects_and_invalid(self, text: str) -> None:
        with pytest.raises(CanonicalJSONError):
            load_json_object(text)

    def test_size_cap(self) -> None:
        padding = "x" * (MAX_JSON_BYTES - len('{"k":""}'))
        assert load_json_object('{"k":"' + padding + '"}') == {"k": padding}
        with pytest.raises(CanonicalJSONError, match="exceeds"):
            load_json_object('{"k":"' + padding + 'x"}')
        with pytest.raises(CanonicalJSONError, match="exceeds"):
            load_json_object("{}", max_bytes=1)

    def test_deep_nesting_is_an_error_not_a_crash(self) -> None:
        with pytest.raises(CanonicalJSONError):
            load_json_object("[" * 100_000 + "]" * 100_000)
