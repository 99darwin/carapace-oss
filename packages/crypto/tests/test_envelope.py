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
from carapace_crypto.envelope import (
    DEK_SIZE,
    MAX_PLAINTEXT_BYTES,
    Envelope,
    EnvelopeDecryptionError,
    EnvelopeError,
    _seal,
    compute_aad,
    open_with_dek_unwrapper,
    rsa_oaep_unwrapper,
    seal,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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


def _public_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _sealed() -> Envelope:
    return seal(_public_pem(_private_key()), SECRET_ID, OWNER_ID, POLICY, PLAINTEXT)


def _open(envelope: Envelope, **overrides: Any) -> bytes:
    args = {
        "secret_id": envelope.secret_id,
        "owner_id": envelope.owner_id,
        "policy": envelope.policy,
    }
    args.update(overrides)
    return open_with_dek_unwrapper(envelope, rsa_oaep_unwrapper(_private_key()), **args)


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
        opened = open_with_dek_unwrapper(
            envelope, rsa_oaep_unwrapper(key), SECRET_ID, OWNER_ID, POLICY
        )
        assert opened == PLAINTEXT


class TestTampering:
    """Every stored field is authenticated: any change must fail to open."""

    def test_widened_policy_in_storage_fails(self) -> None:
        envelope = _sealed()
        widened = copy.deepcopy(envelope.policy)
        widened["hosts"].append({"match": "suffix", "value": ".attacker.test"})
        tampered = dataclasses.replace(envelope, policy=widened)
        # The enclave enforces the stored policy, so it passes that one in.
        with pytest.raises(EnvelopeDecryptionError):
            _open(tampered)

    def test_expected_policy_mismatch_fails(self) -> None:
        widened = {**POLICY, "methods": ["GET", "DELETE"]}
        with pytest.raises(EnvelopeError):
            _open(_sealed(), policy=widened)

    def test_policy_key_order_does_not_matter(self) -> None:
        reordered = dict(reversed(list(POLICY.items())))
        assert _open(_sealed(), policy=reordered) == PLAINTEXT

    @pytest.mark.parametrize("field", ["secret_id", "owner_id"])
    def test_swapped_identity_in_storage_fails(self, field: str) -> None:
        tampered = dataclasses.replace(_sealed(), **{field: "someone-else"})
        with pytest.raises(EnvelopeDecryptionError):
            _open(tampered)

    @pytest.mark.parametrize("field", ["secret_id", "owner_id"])
    def test_expected_identity_mismatch_fails(self, field: str) -> None:
        with pytest.raises(EnvelopeError):
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
                SECRET_ID,
                OWNER_ID,
                POLICY,
            )

    def test_unwrapper_returning_wrong_length_fails(self) -> None:
        with pytest.raises(EnvelopeDecryptionError):
            open_with_dek_unwrapper(
                _sealed(), lambda _: b"\x00" * 16, SECRET_ID, OWNER_ID, POLICY
            )

    def test_unwrapper_errors_propagate(self) -> None:
        def failing_unwrap(_: bytes) -> bytes:
            raise ConnectionError("kms unavailable")

        with pytest.raises(ConnectionError):
            open_with_dek_unwrapper(
                _sealed(), failing_unwrap, SECRET_ID, OWNER_ID, POLICY
            )

    def test_unsupported_version_rejected(self) -> None:
        with pytest.raises(EnvelopeError):
            _open(dataclasses.replace(_sealed(), v=2))


class TestInputValidation:
    def test_rejects_small_rsa_key(self) -> None:
        small = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(EnvelopeError, match="3072"):
            seal(_public_pem(small), SECRET_ID, OWNER_ID, POLICY, PLAINTEXT)

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
        with pytest.raises(ValueError):
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
            {"policy": []},
            {"nonce": "AAAA"},
            {"ct": "not base64!"},
            {"wrapped": None},
            {"kms_key_version": 1},
            {"secret_id": ""},
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
        opened = open_with_dek_unwrapper(
            envelope,
            rsa_oaep_unwrapper(_private_key()),
            vector["secret_id"],
            vector["owner_id"],
            vector["policy"],
        )
        assert opened == plaintext

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
