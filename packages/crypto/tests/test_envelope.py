"""Tests for envelope encryption v1."""

from __future__ import annotations

import base64
import copy
import dataclasses
import hashlib
import json
from functools import cache
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from carapace_crypto.canonical import canonical_json
from carapace_crypto.envelope import (
    _MAX_B64_CHARS,
    DEK_SIZE,
    MAX_AAD_INPUT_BYTES,
    MAX_PLAINTEXT_BYTES,
    MAX_RSA_BITS,
    Envelope,
    EnvelopeDecryptionError,
    EnvelopeError,
    _seal,
    compute_aad,
    open_with_dek_unwrapper,
    rsa_oaep_unwrapper,
    seal,
)

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "envelope_v1.json").read_text()
)
SECRET_ID = "11111111-1111-4111-8111-111111111111"
OWNER_ID = "22222222-2222-4222-8222-222222222222"
PLAINTEXT = b"sk-live-not-a-real-secret"
POLICY: dict[str, Any] = {
    "v": 1,
    "hosts": [{"match": "exact", "value": "api.github.com"}],
    "schemes": ["https"],
    "methods": ["GET"],
    "ports": [443],
    "inject": {"kind": "header", "name": "Authorization", "template": "{secret}"},
    "limits": {"req_bytes": 1024, "resp_bytes": 4096, "rpm": 60, "timeout_s": 30},
}


@cache
def _private_key() -> rsa.RSAPrivateKey:
    pem = VECTORS["rsa_private_key_pkcs8_pem"].encode("ascii")
    key = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    return key


@cache
def _other_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def _oversized_public_pem() -> bytes:
    # A syntactically valid public key just past MAX_RSA_BITS. The modulus is
    # not a real RSA modulus; only the size check is exercised, and generating
    # a genuine key of this size would take minutes.
    modulus = (1 << (MAX_RSA_BITS + 7)) | 1
    return (
        rsa.RSAPublicNumbers(65537, modulus)
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def _public_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _sealed() -> Envelope:
    return seal(_public_pem(_private_key()), SECRET_ID, OWNER_ID, POLICY, PLAINTEXT)


def _open(envelope: Envelope, **overrides: Any) -> bytes:
    # Expected identity comes from the (simulated) authenticated request,
    # never from the envelope under test.
    args = {"expected_secret_id": SECRET_ID, "expected_owner_id": OWNER_ID}
    args.update(overrides)
    plaintext, policy = open_with_dek_unwrapper(
        envelope, rsa_oaep_unwrapper(_private_key()), **args
    )
    assert policy == envelope.policy
    return plaintext


def _padded_policy(aad_input_bytes: int) -> dict[str, Any]:
    """Return POLICY plus a pad so the canonical AAD input has the given size."""
    bound = {
        "v": 1,
        "secret_id": SECRET_ID,
        "owner_id": OWNER_ID,
        "policy": {**POLICY, "pad": ""},
    }
    room = aad_input_bytes - len(canonical_json(bound))
    return {**POLICY, "pad": "x" * room}


def _flip(data: bytes, index: int = 0) -> bytes:
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


class TestRoundTrip:
    def test_seal_then_open(self) -> None:
        assert _open(_sealed()) == PLAINTEXT

    def test_accepts_bytearray_plaintext(self) -> None:
        envelope = seal(
            _public_pem(_private_key()),
            SECRET_ID,
            OWNER_ID,
            POLICY,
            bytearray(PLAINTEXT),
        )
        assert _open(envelope) == PLAINTEXT

    def test_serialization_round_trip(self) -> None:
        envelope = _sealed()
        wire = json.loads(json.dumps(envelope.to_dict()))
        restored = Envelope.from_dict(wire)
        assert restored == envelope
        assert _open(restored) == PLAINTEXT

    def test_fresh_dek_and_nonce_each_time(self) -> None:
        first, second = _sealed(), _sealed()
        assert first.nonce != second.nonce
        assert first.ct != second.ct
        assert first.wrapped != second.wrapped

    def test_accepts_3072_bit_key(self) -> None:
        key = _other_private_key()
        envelope = seal(_public_pem(key), SECRET_ID, OWNER_ID, POLICY, PLAINTEXT)
        opened, _ = open_with_dek_unwrapper(
            envelope,
            rsa_oaep_unwrapper(key),
            expected_secret_id=SECRET_ID,
            expected_owner_id=OWNER_ID,
        )
        assert opened == PLAINTEXT

    def test_returns_authenticated_policy_copy(self) -> None:
        envelope = _sealed()
        _, policy = open_with_dek_unwrapper(
            envelope,
            rsa_oaep_unwrapper(_private_key()),
            expected_secret_id=SECRET_ID,
            expected_owner_id=OWNER_ID,
        )
        assert policy == POLICY
        policy["methods"].append("DELETE")
        assert envelope.policy == POLICY

    def test_seal_does_not_alias_caller_policy(self) -> None:
        policy = copy.deepcopy(POLICY)
        envelope = seal(
            _public_pem(_private_key()), SECRET_ID, OWNER_ID, policy, PLAINTEXT
        )
        policy["methods"].append("DELETE")
        assert envelope.policy == POLICY
        assert _open(envelope) == PLAINTEXT


class TestTampering:
    """Every stored field is authenticated: any change must fail to open."""

    def test_widened_policy_in_storage_fails(self) -> None:
        envelope = _sealed()
        widened = copy.deepcopy(envelope.policy)
        widened["hosts"].append({"match": "suffix", "value": ".attacker.test"})
        tampered = dataclasses.replace(envelope, policy=widened)
        with pytest.raises(EnvelopeDecryptionError):
            _open(tampered)

    def test_nested_policy_edit_fails(self) -> None:
        envelope = _sealed()
        edited = copy.deepcopy(envelope.policy)
        edited["limits"]["resp_bytes"] = 10**9
        with pytest.raises(EnvelopeDecryptionError):
            _open(dataclasses.replace(envelope, policy=edited))

    def test_stored_policy_key_order_does_not_matter(self) -> None:
        envelope = _sealed()
        reordered = {
            key: (dict(reversed(value.items())) if isinstance(value, dict) else value)
            for key, value in reversed(list(envelope.policy.items()))
        }
        assert _open(dataclasses.replace(envelope, policy=reordered)) == PLAINTEXT

    @pytest.mark.parametrize(
        ("field", "expected_field"),
        [("secret_id", "expected_secret_id"), ("owner_id", "expected_owner_id")],
    )
    def test_relabeled_envelope_fails(self, field: str, expected_field: str) -> None:
        # A malicious store relabels owner A's envelope as owner B's and serves
        # it to owner B's request: the labels match, the AAD does not.
        tampered = dataclasses.replace(_sealed(), **{field: "someone-else"})
        with pytest.raises(EnvelopeDecryptionError):
            _open(tampered, **{expected_field: "someone-else"})

    @pytest.mark.parametrize("field", ["expected_secret_id", "expected_owner_id"])
    def test_expected_identity_mismatch_fails(self, field: str) -> None:
        with pytest.raises(EnvelopeError, match="expected"):
            _open(_sealed(), **{field: "someone-else"})

    @pytest.mark.parametrize("index", [0, -1])
    def test_tampered_ciphertext_fails(self, index: int) -> None:
        envelope = _sealed()
        tampered = dataclasses.replace(envelope, ct=_flip(envelope.ct, index))
        with pytest.raises(EnvelopeDecryptionError):
            _open(tampered)

    def test_truncated_ciphertext_fails(self) -> None:
        envelope = _sealed()
        with pytest.raises(EnvelopeDecryptionError):
            _open(dataclasses.replace(envelope, ct=envelope.ct[:-1]))

    def test_tampered_nonce_fails(self) -> None:
        envelope = _sealed()
        tampered = dataclasses.replace(envelope, nonce=_flip(envelope.nonce))
        with pytest.raises(EnvelopeDecryptionError):
            _open(tampered)

    def test_tampered_wrapped_key_fails(self) -> None:
        envelope = _sealed()
        tampered = dataclasses.replace(envelope, wrapped=_flip(envelope.wrapped, 7))
        with pytest.raises(EnvelopeDecryptionError):
            _open(tampered)

    def test_wrapped_key_from_other_envelope_fails(self) -> None:
        first, second = _sealed(), _sealed()
        tampered = dataclasses.replace(first, wrapped=second.wrapped)
        with pytest.raises(EnvelopeDecryptionError):
            _open(tampered)

    def test_wrong_private_key_fails(self) -> None:
        envelope = _sealed()
        with pytest.raises(EnvelopeDecryptionError):
            open_with_dek_unwrapper(
                envelope,
                rsa_oaep_unwrapper(_other_private_key()),
                expected_secret_id=SECRET_ID,
                expected_owner_id=OWNER_ID,
            )

    def test_unwrapper_returning_wrong_length_fails(self) -> None:
        with pytest.raises(EnvelopeDecryptionError):
            open_with_dek_unwrapper(
                _sealed(),
                lambda _: b"\x00" * 16,
                expected_secret_id=SECRET_ID,
                expected_owner_id=OWNER_ID,
            )

    def test_unwrapper_errors_propagate(self) -> None:
        def failing_unwrap(_: bytes) -> bytes:
            raise ConnectionError("kms unavailable")

        with pytest.raises(ConnectionError):
            open_with_dek_unwrapper(
                _sealed(),
                failing_unwrap,
                expected_secret_id=SECRET_ID,
                expected_owner_id=OWNER_ID,
            )

    def test_unsupported_version_rejected(self) -> None:
        with pytest.raises(EnvelopeError):
            _open(dataclasses.replace(_sealed(), v=2))


class TestInputValidation:
    def test_rejects_small_rsa_key(self) -> None:
        small = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(EnvelopeError, match="3072"):
            seal(_public_pem(small), SECRET_ID, OWNER_ID, POLICY, PLAINTEXT)

    def test_rejects_oversized_rsa_key(self) -> None:
        # seal and open must agree on the accepted key range; without this
        # check seal produced envelopes that from_dict/open then rejected.
        with pytest.raises(EnvelopeError, match=str(MAX_RSA_BITS)):
            seal(_oversized_public_pem(), SECRET_ID, OWNER_ID, POLICY, PLAINTEXT)

    def test_rejects_oversized_policy(self) -> None:
        policy = _padded_policy(MAX_AAD_INPUT_BYTES + 1)
        with pytest.raises(EnvelopeError, match="AAD input"):
            seal(_public_pem(_private_key()), SECRET_ID, OWNER_ID, policy, PLAINTEXT)

    def test_accepts_policy_at_aad_limit(self) -> None:
        policy = _padded_policy(MAX_AAD_INPUT_BYTES)
        envelope = seal(
            _public_pem(_private_key()), SECRET_ID, OWNER_ID, policy, PLAINTEXT
        )
        assert _open(envelope) == PLAINTEXT

    def test_from_dict_rejects_oversized_policy(self) -> None:
        wire = _sealed().to_dict()
        wire["policy"] = _padded_policy(MAX_AAD_INPUT_BYTES + 1)
        with pytest.raises(EnvelopeError, match="AAD input"):
            Envelope.from_dict(wire)

    def test_from_dict_rejects_overlong_base64_before_decoding(self) -> None:
        wire = _sealed().to_dict()
        wire["ct"] = "A" * (_MAX_B64_CHARS + 4)
        with pytest.raises(EnvelopeError, match="too long"):
            Envelope.from_dict(wire)

    def test_to_dict_does_not_alias_policy(self) -> None:
        envelope = _sealed()
        envelope.to_dict()["policy"]["methods"].append("DELETE")
        assert envelope.policy == POLICY

    def test_rejects_non_rsa_key(self) -> None:
        pem = (
            ec.generate_private_key(ec.SECP256R1())
            .public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        with pytest.raises(EnvelopeError, match="RSA"):
            seal(pem, SECRET_ID, OWNER_ID, POLICY, PLAINTEXT)

    def test_rejects_garbage_pem(self) -> None:
        with pytest.raises(EnvelopeError):
            seal(b"not a key", SECRET_ID, OWNER_ID, POLICY, PLAINTEXT)

    @pytest.mark.parametrize("size", [0, MAX_PLAINTEXT_BYTES + 1])
    def test_rejects_bad_plaintext_size(self, size: int) -> None:
        with pytest.raises(EnvelopeError):
            seal(_public_pem(_private_key()), SECRET_ID, OWNER_ID, POLICY, b"x" * size)

    @pytest.mark.parametrize("bad_id", ["", None, 5])
    def test_rejects_bad_ids(self, bad_id: Any) -> None:
        with pytest.raises(EnvelopeError):
            seal(_public_pem(_private_key()), bad_id, OWNER_ID, POLICY, PLAINTEXT)

    def test_rejects_float_in_policy(self) -> None:
        with pytest.raises(EnvelopeError):
            seal(
                _public_pem(_private_key()),
                SECRET_ID,
                OWNER_ID,
                {**POLICY, "limits": {"timeout_s": 1.5}},
                PLAINTEXT,
            )

    @pytest.mark.parametrize(
        "mutation",
        [
            {"v": 2},
            {"v": True},  # bool is an int subclass and True == 1
            {"v": "1"},
            {"policy": []},
            {"nonce": "AAAA"},
            {"ct": "not base64!"},
            {"wrapped": None},
            {"kms_key_version": 1},
            {"secret_id": ""},
            {"policy": {"limits": {"timeout_s": 60.0}}},
            {"policy": {"n": 2**53}},
            {"ct": base64.b64encode(b"x" * (MAX_PLAINTEXT_BYTES + 17)).decode()},
            {"ct": base64.b64encode(b"x" * 16).decode()},
            {"wrapped": base64.b64encode(b"x" * 256).decode()},
            {"wrapped": base64.b64encode(b"x" * 1025).decode()},
        ],
    )
    def test_from_dict_rejects_malformed(self, mutation: dict[str, Any]) -> None:
        with pytest.raises(EnvelopeError):
            Envelope.from_dict({**_sealed().to_dict(), **mutation})


class TestVectors:
    @pytest.mark.parametrize("vector", VECTORS["envelopes"], ids=lambda v: v["name"])
    def test_vector(self, vector: dict[str, Any]) -> None:
        dek = bytes.fromhex(vector["dek_hex"])
        nonce = bytes.fromhex(vector["nonce_hex"])
        plaintext = base64.b64decode(vector["plaintext_b64"])
        aad_input = base64.b64decode(vector["aad_input_b64"])
        envelope = Envelope.from_dict(vector["envelope"])

        assert hashlib.sha256(aad_input).hexdigest() == vector["aad_hex"]
        aad = compute_aad(vector["secret_id"], vector["owner_id"], vector["policy"])
        assert aad.hex() == vector["aad_hex"]
        assert rsa_oaep_unwrapper(_private_key())(envelope.wrapped) == dek
        assert envelope.nonce == nonce
        assert base64.b64decode(vector["ct_b64"]) == envelope.ct
        assert AESGCM(dek).encrypt(nonce, plaintext, aad) == envelope.ct
        opened, policy = open_with_dek_unwrapper(
            envelope,
            rsa_oaep_unwrapper(_private_key()),
            expected_secret_id=vector["secret_id"],
            expected_owner_id=vector["owner_id"],
        )
        assert opened == plaintext
        assert policy == vector["policy"]

    @pytest.mark.parametrize("vector", VECTORS["tamper"], ids=lambda v: v["name"])
    def test_tamper_vector_is_rejected(self, vector: dict[str, Any]) -> None:
        calls: list[bytes] = []
        real_unwrap = rsa_oaep_unwrapper(_private_key())

        def counting_unwrap(wrapped: bytes) -> bytes:
            calls.append(wrapped)
            return real_unwrap(wrapped)

        def attempt() -> None:
            envelope = Envelope.from_dict(vector["envelope"])
            open_with_dek_unwrapper(
                envelope,
                counting_unwrap,
                expected_secret_id=vector["expected_secret_id"],
                expected_owner_id=vector["expected_owner_id"],
            )

        if vector["outcome"] == "reject_malformed":
            with pytest.raises(EnvelopeError) as info:
                attempt()
            assert not isinstance(info.value, EnvelopeDecryptionError)
            assert calls == [], "malformed envelopes must not reach the unwrapper"
        else:
            assert vector["outcome"] == "reject_authentication"
            with pytest.raises(EnvelopeDecryptionError):
                attempt()
            assert len(calls) == 1

    def test_tamper_vectors_cover_required_cases(self) -> None:
        names = {v["name"] for v in VECTORS["tamper"]}
        required = {
            "policy-widened-hosts",
            "relabeled-owner",
            "relabeled-secret",
            "truncated-ct",
            "version-bool",
        }
        assert required <= names

    @pytest.mark.parametrize("vector", VECTORS["envelopes"], ids=lambda v: v["name"])
    def test_seal_is_deterministic_given_rng(self, vector: dict[str, Any]) -> None:
        pool = bytes.fromhex(vector["dek_hex"]) + bytes.fromhex(vector["nonce_hex"])
        chunks = iter([pool[:DEK_SIZE], pool[DEK_SIZE:]])
        envelope = _seal(
            VECTORS["rsa_public_key_pem"],
            vector["secret_id"],
            vector["owner_id"],
            vector["policy"],
            base64.b64decode(vector["plaintext_b64"]),
            kms_key_version=vector["envelope"]["kms_key_version"],
            random_bytes=lambda _: next(chunks),
        )
        assert envelope.to_dict()["ct"] == vector["ct_b64"]
