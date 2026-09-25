"""Tests for owner signing keys."""

from __future__ import annotations

import hashlib

import pytest

from carapace_crypto.canonical import canonical_json
from carapace_crypto.ownerkey import (
    FINGERPRINT_SIZE,
    OwnerKey,
    SignatureError,
    fingerprint,
    fingerprints_match,
    signing_input,
    verify_object,
)

OWNER = OwnerKey.from_seed(bytes(range(32)))
OTHER = OwnerKey.from_seed(bytes(range(32, 64)))
CONTEXT = b"carapace-test-v1"
BODY = {"b": 1, "a": {"z": [1, 2], "y": "text"}}


class TestKeys:
    def test_generate_and_rebuild_from_seed(self) -> None:
        key = OwnerKey.generate()
        rebuilt = OwnerKey.from_seed(key.seed)
        assert rebuilt.public_key == key.public_key
        assert rebuilt.fingerprint == key.fingerprint
        assert len(key.seed) == 32
        assert len(key.public_key) == 32

    @pytest.mark.parametrize("seed", [b"", b"x" * 31, b"x" * 33])
    def test_from_seed_rejects_bad_length(self, seed: bytes) -> None:
        with pytest.raises(SignatureError):
            OwnerKey.from_seed(seed)

    def test_repr_hides_seed(self) -> None:
        text = repr(OWNER)
        assert OWNER.seed.hex() not in text
        assert OWNER.fingerprint.hex() in text


class TestFingerprint:
    def test_is_truncated_tagged_hash(self) -> None:
        expected = hashlib.sha256(b"carapace-owner-fp-v1\n" + OWNER.public_key)
        assert fingerprint(OWNER.public_key) == expected.digest()[:FINGERPRINT_SIZE]
        assert len(OWNER.fingerprint) == 16

    def test_match(self) -> None:
        assert fingerprints_match(OWNER.public_key, OWNER.fingerprint)
        assert not fingerprints_match(OTHER.public_key, OWNER.fingerprint)
        assert not fingerprints_match(OWNER.public_key, OWNER.fingerprint[:15])

    @pytest.mark.parametrize("key", [b"", b"x" * 31, "x" * 32])
    def test_rejects_bad_public_key(self, key: object) -> None:
        with pytest.raises(SignatureError):
            fingerprint(key)  # type: ignore[arg-type]


class TestSignatures:
    def test_sign_then_verify(self) -> None:
        sig = OWNER.sign_object(CONTEXT, BODY)
        assert len(sig) == 64
        verify_object(OWNER.public_key, CONTEXT, BODY, sig)

    def test_signing_input_format(self) -> None:
        assert signing_input(CONTEXT, BODY) == CONTEXT + b"\n" + canonical_json(BODY)

    def test_body_key_order_is_irrelevant(self) -> None:
        sig = OWNER.sign_object(CONTEXT, BODY)
        reordered = {"a": {"y": "text", "z": [1, 2]}, "b": 1}
        verify_object(OWNER.public_key, CONTEXT, reordered, sig)

    def test_wrong_context_fails(self) -> None:
        sig = OWNER.sign_object(CONTEXT, BODY)
        with pytest.raises(SignatureError):
            verify_object(OWNER.public_key, b"carapace-other-v1", BODY, sig)

    def test_wrong_key_fails(self) -> None:
        sig = OWNER.sign_object(CONTEXT, BODY)
        with pytest.raises(SignatureError):
            verify_object(OTHER.public_key, CONTEXT, BODY, sig)

    def test_edited_body_fails(self) -> None:
        sig = OWNER.sign_object(CONTEXT, BODY)
        with pytest.raises(SignatureError):
            verify_object(OWNER.public_key, CONTEXT, {**BODY, "b": 2}, sig)

    @pytest.mark.parametrize("context", [b"", b"has\nnewline", b"trailing\n"])
    def test_rejects_bad_context(self, context: bytes) -> None:
        with pytest.raises(SignatureError):
            OWNER.sign_object(context, BODY)
        with pytest.raises(SignatureError):
            verify_object(OWNER.public_key, context, BODY, b"\x00" * 64)

    def test_context_cannot_bleed_into_body(self) -> None:
        # Canonical JSON escapes newlines, so context + "\n" + body can be
        # split at exactly one place.
        message = signing_input(CONTEXT, {"k": "line\nbreak"})
        assert message.count(b"\n") == 1

    @pytest.mark.parametrize("sig", [b"", b"\x00" * 63, b"\x00" * 65])
    def test_rejects_bad_signature_length(self, sig: bytes) -> None:
        with pytest.raises(SignatureError):
            verify_object(OWNER.public_key, CONTEXT, BODY, sig)

    def test_rejects_uncanonicalizable_body(self) -> None:
        with pytest.raises(SignatureError):
            OWNER.sign_object(CONTEXT, {"f": 1.5})
