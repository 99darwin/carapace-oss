"""Tests for secret redaction in every encoding."""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import quote, quote_plus

import pytest

from carapace_enclave.egress.redact import REDACTED, Redactor, secret_forms

from .conftest import SECRET


def _encodings(value: bytes) -> dict[str, bytes]:
    text = value.decode()
    return {
        "raw": value,
        "b64": base64.b64encode(value),
        "b64_unpadded": base64.b64encode(value).rstrip(b"="),
        "b64url": base64.urlsafe_b64encode(value),
        "b64url_unpadded": base64.urlsafe_b64encode(value).rstrip(b"="),
        "pct": quote(text, safe="").encode(),
        "pct_lower": re.sub(
            "%[0-9A-F]{2}", lambda m: m[0].lower(), quote(text, safe="")
        ).encode(),
        "pct_slash_safe": quote(text, safe="/").encode(),
        "pct_plus": quote_plus(text, safe="").encode(),
        "json": json.dumps(text)[1:-1].encode(),
        "json_slash": json.dumps(text)[1:-1].replace("/", "\\/").encode(),
    }


@pytest.mark.parametrize("kind", sorted(_encodings(SECRET)))
def test_redacts_each_encoding(kind: str) -> None:
    encoded = _encodings(SECRET)[kind]
    body = b'{"echo":"' + encoded + b'","ok":true}'
    out, count = Redactor([SECRET]).redact(body)
    assert count == 1
    assert out == b'{"echo":"' + REDACTED + b'","ok":true}'


def test_json_unicode_escape_forms() -> None:
    secret = "tøken-välue-1234".encode()
    redactor = Redactor([secret])
    ascii_form = json.dumps(secret.decode())[1:-1].encode()
    assert b"\\u00f8" in ascii_form
    upper_form = re.sub(
        rb"\\u([0-9a-f]{4})", lambda m: b"\\u" + m[1].upper(), ascii_form
    )
    assert upper_form != ascii_form
    for form in (ascii_form, upper_form):
        assert redactor.redact(b"x" + form + b"y") == (b"x" + REDACTED + b"y", 1)


@pytest.mark.parametrize("prefix", [b"", b"u", b"us", b"user:", b"a:bc"])
@pytest.mark.parametrize("encode", [base64.b64encode, base64.urlsafe_b64encode])
def test_redacts_secret_embedded_in_larger_base64(prefix: bytes, encode) -> None:  # type: ignore[no-untyped-def]
    blob = encode(prefix + SECRET + b":trailing-data")
    out, count = Redactor([SECRET]).redact(blob)
    assert count >= 1
    assert REDACTED in out
    # Nothing that decodes back to the secret survives.
    assert SECRET not in out


def test_multiple_occurrences_are_counted() -> None:
    body = SECRET + b" and " + base64.b64encode(SECRET) + b" and " + SECRET
    out, count = Redactor([SECRET]).redact(body)
    assert count == 3
    assert SECRET not in out


def test_rendered_template_is_redacted_whole() -> None:
    rendered = b"Bearer " + SECRET
    out, count = Redactor([SECRET, rendered]).redact(b"got: " + rendered)
    assert (out, count) == (b"got: " + REDACTED, 1)


def test_headers_redacted_including_names() -> None:
    headers = [
        (b"X-Echo", SECRET),
        (b"X-" + base64.b64encode(SECRET).rstrip(b"="), b"1"),
        (b"Content-Type", b"application/json"),
    ]
    out, count = Redactor([SECRET]).redact_headers(headers)
    assert count == 2
    assert out[0] == (b"X-Echo", REDACTED)
    assert out[1] == (b"X-" + REDACTED, b"1")
    assert out[2] == (b"Content-Type", b"application/json")


def test_unrelated_data_untouched() -> None:
    body = b"hello world " * 100
    assert Redactor([SECRET]).redact(body) == (body, 0)


@pytest.mark.parametrize("gap", [b" ", b"  ", b"\t", b" \t "])
def test_header_value_redacted_across_line_fold(gap: bytes) -> None:
    # h11 turns an obsolete line fold into whitespace inside the value.
    folded = b"Bearer " + SECRET[:7] + gap + SECRET[7:20] + gap + SECRET[20:]
    out, count = Redactor([SECRET]).redact_headers([(b"X-Echo", folded)])
    assert out == [(b"X-Echo", b"Bearer " + REDACTED)]
    assert count == 1


def test_header_value_fold_tolerance_does_not_touch_body() -> None:
    folded = SECRET[:7] + b" " + SECRET[7:]
    assert Redactor([SECRET]).redact(folded) == (folded, 0)


def test_forms_are_longest_first() -> None:
    forms = secret_forms([SECRET])
    assert forms == sorted(forms, key=lambda f: (-len(f), f))
    assert b"" not in forms


def test_empty_values_rejected() -> None:
    with pytest.raises(ValueError):
        Redactor([b""])


@pytest.mark.parametrize("form", [SECRET.hex(), SECRET.hex().upper()])
def test_redacts_hex(form: str) -> None:
    assert Redactor([SECRET]).redact(form.encode()) == (REDACTED, 1)
