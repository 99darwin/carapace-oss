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
    validate_public_key,
    verify_object,
)
from carapace_crypto.signing import KeyPair

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


_P = 2**255 - 19
_Y8 = 2707385501144840649318225287225658788936804267575313519463743609750303402022
# Every encoding of a small-order point, both signs of x.
_SMALL_ORDER_Y = [0, 1, _Y8, _P - _Y8, _P - 1, _P, _P + 1]
SMALL_ORDER_KEYS = [
    (y | sign).to_bytes(32, "little") for y in _SMALL_ORDER_Y for sign in (0, 1 << 255)
]
IDENTITY_PK = (1).to_bytes(32, "little")
# R = identity, S = 0: satisfies [S]B == R + [k]A for any message when A is
# the identity, because [k]A is the identity too.
UNIVERSAL_SIG = IDENTITY_PK + bytes(32)


class TestWeakPublicKeys:
    def test_openssl_alone_accepts_a_universal_signature(self) -> None:
        # Why validate_public_key exists: without it, anyone could "sign"
        # any object for this key. Guards against a library change too.
        message = signing_input(CONTEXT, BODY)
        assert KeyPair.verify(IDENTITY_PK, UNIVERSAL_SIG, message)

    @pytest.mark.parametrize("public_key", SMALL_ORDER_KEYS)
    def test_small_order_keys_are_rejected(self, public_key: bytes) -> None:
        with pytest.raises(SignatureError, match="small-order"):
            validate_public_key(public_key)
        with pytest.raises(SignatureError):
            fingerprint(public_key)
        with pytest.raises(SignatureError):
            verify_object(public_key, CONTEXT, BODY, UNIVERSAL_SIG)

    @pytest.mark.parametrize("y", [_P + 2, _P + 18, 2**255 - 1])
    def test_non_canonical_encodings_are_rejected(self, y: int) -> None:
        with pytest.raises(SignatureError, match="canonical"):
            validate_public_key(y.to_bytes(32, "little"))

    def test_generated_keys_are_accepted(self) -> None:
        for _ in range(200):
            validate_public_key(OwnerKey.generate().public_key)

    @pytest.mark.parametrize("value", [b"", b"\x00" * 31, "a" * 32, None])
    def test_wrong_type_or_length_is_rejected(self, value: object) -> None:
        with pytest.raises(SignatureError, match="32 bytes"):
            validate_public_key(value)  # type: ignore[arg-type]
