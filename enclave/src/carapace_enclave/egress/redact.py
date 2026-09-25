"""Remove a secret from upstream responses before the agent sees them.

The secret is matched in these forms:

- raw bytes
- base64, standard and URL-safe, padded and unpadded, including when it is
  embedded at any byte alignment inside a longer base64 blob (so
  ``base64("user:" + secret)`` is caught)
- percent-encoded (``quote`` and ``quote_plus``, upper- and lowercase hex)
- JSON string escaped (ASCII-only and UTF-8, ``\\/`` and upper-hex ``\\u``)
- hex, lower- and uppercase

Not covered: UTF-16, HTML entities, case-changed or otherwise transformed
reflections, and nested encodings (e.g. percent-encoded base64).

Bodies are redacted after being fully buffered (the executor enforces the
response cap), so a secret split across stream chunks is still caught.
Matching is a single left-to-right pass over a longest-first alternation, so
replaced text is never re-scanned.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable
from urllib.parse import quote_from_bytes, quote_plus

REDACTED = b"[REDACTED]"
# Base64 fragments shorter than this would redact unrelated data.
MIN_BASE64_CORE = 8

_B64_ALPHABETS = (base64.b64encode, base64.urlsafe_b64encode)
_B64_SKIP_LEADING = {0: 0, 1: 2, 2: 3}
_UPPER_U_ESCAPE = re.compile(rb"\\u([0-9a-f]{4})")


def _base64_forms(value: bytes) -> set[bytes]:
    forms: set[bytes] = set()
    for encode in _B64_ALPHABETS:
        full = encode(value)
        forms.update({full, full.rstrip(b"=")})
        for offset, skip in _B64_SKIP_LEADING.items():
            # Characters that depend only on ``value`` when it starts
            # ``offset`` bytes into a 3-byte group of a larger blob.
            encoded = encode(b"\x00" * offset + value).rstrip(b"=")
            end = len(encoded) - (1 if (offset + len(value)) % 3 else 0)
            core = encoded[skip:end]
            if len(core) >= MIN_BASE64_CORE:
                forms.add(core)
    return forms


def _percent_forms(value: bytes) -> set[bytes]:
    forms = {
        quote_from_bytes(value, safe="").encode("ascii"),
        quote_from_bytes(value, safe="/").encode("ascii"),
        quote_plus(value, safe="").encode("ascii"),
    }
    lowered = {re.sub(rb"%[0-9A-F]{2}", lambda m: m[0].lower(), f) for f in forms}
    return forms | lowered


def _json_forms(value: bytes) -> set[bytes]:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return set()
    forms: set[bytes] = set()
    for ensure_ascii in (True, False):
        escaped = json.dumps(text, ensure_ascii=ensure_ascii)[1:-1].encode("utf-8")
        forms.add(escaped)
        forms.add(escaped.replace(b"/", b"\\/"))
        forms.add(_UPPER_U_ESCAPE.sub(lambda m: b"\\u" + m[1].upper(), escaped))
    return forms


def secret_forms(values: Iterable[bytes]) -> list[bytes]:
    """All encodings to redact, longest first."""
    forms: set[bytes] = set()
    for value in values:
        if not value:
            continue
        forms.add(value)
        forms |= _base64_forms(value)
        forms |= _percent_forms(value)
        forms |= _json_forms(value)
        forms |= {value.hex().encode("ascii"), value.hex().upper().encode("ascii")}
    forms.discard(b"")
    return sorted(forms, key=lambda form: (-len(form), form))


class Redactor:
    """Compiled redaction for one secret (and its rendered injection values)."""

    def __init__(self, values: Iterable[bytes]) -> None:
        forms = secret_forms(values)
        if not forms:
            raise ValueError("nothing to redact")
        self._pattern = re.compile(b"|".join(re.escape(form) for form in forms))

    def redact(self, data: bytes) -> tuple[bytes, int]:
        """Return ``(redacted, count)``."""
        return self._pattern.subn(REDACTED, data)

    def redact_headers(
        self, headers: Iterable[tuple[bytes, bytes]]
    ) -> tuple[list[tuple[bytes, bytes]], int]:
        total = 0
        result: list[tuple[bytes, bytes]] = []
        for name, value in headers:
            clean_name, name_hits = self.redact(name)
            clean_value, value_hits = self.redact(value)
            total += name_hits + value_hits
            result.append((clean_name, clean_value))
        return result, total
