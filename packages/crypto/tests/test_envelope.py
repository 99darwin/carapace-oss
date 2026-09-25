"""Tests for envelope encryption v1 (owner-signed)."""

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
from carapace_crypto.encoding import b64_encode_std
from carapace_crypto.envelope import (
    _MAX_B64_CHARS,
    DEK_SIZE,
    ENVELOPE_CONTEXT,
    MAX_AAD_INPUT_BYTES,
    MAX_PLAINTEXT_BYTES,
    MAX_RSA_BITS,
    Envelope,
    EnvelopeDecryptionError,
    EnvelopeError,
    EnvelopeSignatureError,
    EnvelopeStaleError,
    _seal,
    compute_aad,
    open_with_dek_unwrapper,
    rsa_oaep_unwrapper,
    seal,
    verify_envelope_signature,
)
from carapace_crypto.grant import GRANT_CONTEXT
from carapace_crypto.ownerkey import OwnerKey, fingerprint, signing_input
from carapace_crypto.signing import KeyPair

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "envelope_v1.json").read_text()
)
SECRET_ID = "11111111-1111-4111-8111-111111111111"
OWNER_ID = "22222222-2222-4222-8222-222222222222"
PLAINTEXT = b"sk-live-not-a-real-secret"
VERSION = 10
OWNER = OwnerKey.from_seed(bytes(range(32)))
ATTACKER = OwnerKey.from_seed(bytes(range(32, 64)))
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


def _sealed(
    *,
    owner: OwnerKey = OWNER,
    version: int = VERSION,
    secret_id: str = SECRET_ID,
    owner_id: str = OWNER_ID,
    policy: dict[str, Any] = POLICY,
    plaintext: bytes | bytearray = PLAINTEXT,
    key: rsa.RSAPrivateKey | None = None,
) -> Envelope:
    return seal(
        _public_pem(key or _private_key()),
        secret_id,
        owner_id,
        policy,
        plaintext,
        owner_key=owner,
        version=version,
    )


class _CountingUnwrapper:
    """Records whether the (simulated) KMS call was reached."""

    def __init__(self, key: rsa.RSAPrivateKey | None = None) -> None:
        self.calls = 0
        self._unwrap = rsa_oaep_unwrapper(key or _private_key())

    def __call__(self, wrapped: bytes) -> bytes:
        self.calls += 1
        return self._unwrap(wrapped)


def _open(
    envelope: Envelope, unwrap: Any = None, **overrides: Any
) -> tuple[bytes, dict[str, Any]]:
    # Expected identity comes from the agent's verified grant in production,
    # never from the envelope under test.
    args: dict[str, Any] = {
        "expected_secret_id": SECRET_ID,
        "expected_owner_pk": OWNER.public_key,
        "min_version": 1,
    }
    args.update(overrides)
    return open_with_dek_unwrapper(
        envelope, unwrap or rsa_oaep_unwrapper(_private_key()), **args
    )


def _resigned(envelope: Envelope, signer: OwnerKey = OWNER) -> Envelope:
    """Re-sign an edited envelope as if the signer had produced it."""
    sig = signer.sign_object(ENVELOPE_CONTEXT, envelope.signed_body())
    return dataclasses.replace(envelope, sig=sig)


def _padded_policy(aad_input_bytes: int) -> dict[str, Any]:
    """Return POLICY plus a pad so the canonical AAD input has the given size."""
    bound = {
        "v": 1,
        "secret_id": SECRET_ID,
        "owner_id": OWNER_ID,
        "owner_pk": b64_encode_std(OWNER.public_key),
        "version": VERSION,
        "policy": {**POLICY, "pad": ""},
    }
    room = aad_input_bytes - len(canonical_json(bound))
    return {**POLICY, "pad": "x" * room}


def _flip(data: bytes, index: int = 0) -> bytes:
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


class TestRoundTrip:
    def test_seal_then_open(self) -> None:
        plaintext, policy = _open(_sealed())
        assert plaintext == PLAINTEXT
        assert policy == POLICY

    def test_accepts_bytearray_plaintext(self) -> None:
        assert _open(_sealed(plaintext=bytearray(PLAINTEXT)))[0] == PLAINTEXT

    def test_serialization_round_trip(self) -> None:
        envelope = _sealed()
        restored = Envelope.from_json(json.dumps(envelope.to_dict()))
        assert restored == envelope
        assert _open(restored)[0] == PLAINTEXT

    def test_signature_verifies_standalone(self) -> None:
        envelope = _sealed()
        verify_envelope_signature(envelope)
        assert envelope.owner_pk == OWNER.public_key
        assert fingerprint(envelope.owner_pk) == OWNER.fingerprint

    def test_signing_input_is_context_newline_canonical_body(self) -> None:
        envelope = _sealed()
        expected = b"carapace-envelope-v1\n" + canonical_json(envelope.signed_body())
        assert signing_input(ENVELOPE_CONTEXT, envelope.signed_body()) == expected
        assert KeyPair.verify(OWNER.public_key, envelope.sig, expected)

    def test_fresh_dek_and_nonce_each_time(self) -> None:
        first, second = _sealed(), _sealed()
        assert first.nonce != second.nonce
        assert first.ct != second.ct
        assert first.wrapped != second.wrapped
        assert first.sig != second.sig

    def test_accepts_3072_bit_key(self) -> None:
        key = _other_private_key()
        envelope = _sealed(key=key)
        assert _open(envelope, rsa_oaep_unwrapper(key))[0] == PLAINTEXT

    def test_version_at_floor_is_accepted(self) -> None:
        assert _open(_sealed(), min_version=VERSION)[0] == PLAINTEXT

    def test_returns_authenticated_policy_copy(self) -> None:
        envelope = _sealed()
        _, policy = _open(envelope)
        policy["methods"].append("DELETE")
        assert envelope.policy == POLICY

    def test_seal_does_not_alias_caller_policy(self) -> None:
        policy = copy.deepcopy(POLICY)
        envelope = _sealed(policy=policy)
        policy["methods"].append("DELETE")
        assert envelope.policy == POLICY
        assert _open(envelope)[0] == PLAINTEXT

    def test_stored_policy_key_order_does_not_matter(self) -> None:
        envelope = _sealed()
        reordered = {
            key: (dict(reversed(value.items())) if isinstance(value, dict) else value)
            for key, value in reversed(list(envelope.policy.items()))
        }
        restored = dataclasses.replace(envelope, policy=reordered)
        assert _open(restored)[0] == PLAINTEXT


class TestSubstitution:
    """A store writer cannot swap in an envelope of their own, or roll back."""

    def test_attacker_sealed_envelope_under_victim_ids_is_rejected(self) -> None:
        forged = _sealed(owner=ATTACKER, policy={**POLICY, "hosts": []})
        unwrap = _CountingUnwrapper()
        with pytest.raises(EnvelopeError, match="expected owner key"):
            _open(forged, unwrap)
        assert unwrap.calls == 0

    def test_owner_pk_swapped_and_resigned_is_rejected(self) -> None:
        # Attacker rewrites owner_pk to their own key and signs. The enclave's
        # expected key comes from the agent's API key, not from the envelope.
        envelope = dataclasses.replace(_sealed(), owner_pk=ATTACKER.public_key)
        forged = _resigned(envelope, ATTACKER)
        verify_envelope_signature(forged)  # internally consistent...
        with pytest.raises(EnvelopeError, match="expected owner key"):
            _open(forged)  # ...but not the key the agent's grant names

    def test_attacker_signature_over_owner_pk_is_rejected(self) -> None:
        forged = _resigned(_sealed(), ATTACKER)
        with pytest.raises(EnvelopeSignatureError):
            _open(forged)

    def test_rollback_below_grant_floor_is_rejected(self) -> None:
        old = _sealed(version=VERSION)
        unwrap = _CountingUnwrapper()
        with pytest.raises(EnvelopeStaleError):
            _open(old, unwrap, min_version=VERSION + 1)
        assert unwrap.calls == 0

    def test_signature_under_wrong_context_is_rejected(self) -> None:
        envelope = _sealed()
        sig = OWNER.sign_object(GRANT_CONTEXT, envelope.signed_body())
        with pytest.raises(EnvelopeSignatureError):
            _open(dataclasses.replace(envelope, sig=sig))

    def test_signature_without_context_is_rejected(self) -> None:
        envelope = _sealed()
        raw = KeyPair.from_private_bytes(OWNER.seed)
        sig = raw.sign(canonical_json(envelope.signed_body()))
        with pytest.raises(EnvelopeSignatureError):
            _open(dataclasses.replace(envelope, sig=sig))

    def test_expected_secret_mismatch_is_rejected(self) -> None:
        with pytest.raises(EnvelopeError, match="expected secret"):
            _open(_sealed(), expected_secret_id="someone-else")

    def test_expected_owner_pk_must_be_32_bytes(self) -> None:
        with pytest.raises(EnvelopeError):
            _open(_sealed(), expected_owner_pk=OWNER.public_key[:31])

    @pytest.mark.parametrize("bad", [0, True, -1, "1"])
    def test_bad_min_version_is_rejected(self, bad: Any) -> None:
        with pytest.raises(EnvelopeError):
            _open(_sealed(), min_version=bad)


class TestTampering:
    """Every stored field is signed and every header field is AAD."""

    @pytest.mark.parametrize(
        "edit",
        [
            {"policy": {**POLICY, "hosts": [{"match": "suffix", "value": ".x"}]}},
            {"policy": {**POLICY, "limits": {**POLICY["limits"], "rpm": 10**6}}},
            {"owner_id": "someone-else"},
            {"version": VERSION + 1},
            {"kms_key_version": "2"},
        ],
        ids=["policy-hosts", "policy-limits", "owner_id", "version", "kms_key"],
    )
    def test_edit_fails_signature_before_unwrap(self, edit: dict[str, Any]) -> None:
        unwrap = _CountingUnwrapper()
        with pytest.raises(EnvelopeSignatureError):
            _open(dataclasses.replace(_sealed(), **edit), unwrap)
        assert unwrap.calls == 0

    def test_relabeled_secret_fails_signature(self) -> None:
        relabeled = dataclasses.replace(_sealed(), secret_id="other")
        with pytest.raises(EnvelopeSignatureError):
            _open(relabeled, expected_secret_id="other")

    @pytest.mark.parametrize("field", ["ct", "nonce", "wrapped", "sig"])
    def test_flipped_binary_field_fails_signature(self, field: str) -> None:
        envelope = _sealed()
        flipped = dataclasses.replace(
            envelope, **{field: _flip(getattr(envelope, field), 3)}
        )
        with pytest.raises(EnvelopeSignatureError):
            _open(flipped)

    def test_resigned_widened_policy_fails_aad(self) -> None:
        # If the owner key leaks, a widened policy is still bound by the AEAD.
        envelope = _sealed()
        widened = copy.deepcopy(envelope.policy)
        widened["hosts"].append({"match": "suffix", "value": ".attacker.test"})
        with pytest.raises(EnvelopeDecryptionError):
            _open(_resigned(dataclasses.replace(envelope, policy=widened)))

    @pytest.mark.parametrize(
        ("field", "expected_field"),
        [("secret_id", "expected_secret_id"), ("owner_id", None)],
    )
    def test_resigned_relabel_fails_aad(
        self, field: str, expected_field: str | None
    ) -> None:
        tampered = _resigned(dataclasses.replace(_sealed(), **{field: "other"}))
        overrides = {expected_field: "other"} if expected_field else {}
        with pytest.raises(EnvelopeDecryptionError):
            _open(tampered, **overrides)

    @pytest.mark.parametrize("index", [0, -1])
    def test_resigned_tampered_ciphertext_fails_aead(self, index: int) -> None:
        envelope = _sealed()
        tampered = _resigned(
            dataclasses.replace(envelope, ct=_flip(envelope.ct, index))
        )
        with pytest.raises(EnvelopeDecryptionError):
            _open(tampered)

    def test_resigned_truncated_ciphertext_fails_aead(self) -> None:
        envelope = _sealed()
        with pytest.raises(EnvelopeDecryptionError):
            _open(_resigned(dataclasses.replace(envelope, ct=envelope.ct[:-1])))

    def test_resigned_tampered_nonce_fails_aead(self) -> None:
        envelope = _sealed()
        tampered = _resigned(dataclasses.replace(envelope, nonce=_flip(envelope.nonce)))
        with pytest.raises(EnvelopeDecryptionError):
            _open(tampered)

    def test_resigned_wrapped_key_from_other_envelope_fails(self) -> None:
        first, second = _sealed(), _sealed()
        with pytest.raises(EnvelopeDecryptionError):
            _open(_resigned(dataclasses.replace(first, wrapped=second.wrapped)))

    def test_wrong_private_key_fails(self) -> None:
        with pytest.raises(EnvelopeDecryptionError):
            _open(_sealed(), rsa_oaep_unwrapper(_other_private_key()))

    def test_unwrapper_returning_wrong_length_fails(self) -> None:
        with pytest.raises(EnvelopeDecryptionError):
            _open(_sealed(), lambda _: b"\x00" * 16)

    def test_unwrapper_errors_propagate(self) -> None:
        def failing_unwrap(_: bytes) -> bytes:
            raise ConnectionError("kms unavailable")

        with pytest.raises(ConnectionError):
            _open(_sealed(), failing_unwrap)

    def test_unsupported_version_rejected(self) -> None:
        with pytest.raises(EnvelopeError):
            _open(dataclasses.replace(_sealed(), v=2))


class TestInputValidation:
    def test_rejects_small_rsa_key(self) -> None:
        small = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(EnvelopeError, match="3072"):
            _sealed(key=small)

    def test_rejects_oversized_rsa_key(self) -> None:
        with pytest.raises(EnvelopeError, match=str(MAX_RSA_BITS)):
            seal(
                _oversized_public_pem(),
                SECRET_ID,
                OWNER_ID,
                POLICY,
                PLAINTEXT,
                owner_key=OWNER,
                version=VERSION,
            )

    def test_rejects_oversized_policy(self) -> None:
        with pytest.raises(EnvelopeError, match="AAD input"):
            _sealed(policy=_padded_policy(MAX_AAD_INPUT_BYTES + 1))

    def test_accepts_policy_at_aad_limit(self) -> None:
        envelope = _sealed(policy=_padded_policy(MAX_AAD_INPUT_BYTES))
        assert _open(envelope)[0] == PLAINTEXT

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

    def test_from_json_rejects_duplicate_keys(self) -> None:
        text = json.dumps(_sealed().to_dict())
        with pytest.raises(EnvelopeError, match="duplicate"):
            Envelope.from_json('{"policy":{},' + text[1:])

    @pytest.mark.parametrize("text", ["[]", "null", "{", "", '"x"'])
    def test_from_json_rejects_non_objects(self, text: str) -> None:
        with pytest.raises(EnvelopeError):
            Envelope.from_json(text)

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
            seal(
                pem, SECRET_ID, OWNER_ID, POLICY, PLAINTEXT, owner_key=OWNER, version=1
            )

    def test_rejects_garbage_pem(self) -> None:
        with pytest.raises(EnvelopeError):
            seal(
                b"not a key",
                SECRET_ID,
                OWNER_ID,
                POLICY,
                PLAINTEXT,
                owner_key=OWNER,
                version=1,
            )

    @pytest.mark.parametrize("size", [0, MAX_PLAINTEXT_BYTES + 1])
    def test_rejects_bad_plaintext_size(self, size: int) -> None:
        with pytest.raises(EnvelopeError):
            _sealed(plaintext=b"x" * size)

    @pytest.mark.parametrize("bad_id", ["", None, 5])
    def test_rejects_bad_ids(self, bad_id: Any) -> None:
        with pytest.raises(EnvelopeError):
            _sealed(secret_id=bad_id)

    @pytest.mark.parametrize("bad_version", [0, -1, True, "1", 2**53])
    def test_rejects_bad_version(self, bad_version: Any) -> None:
        with pytest.raises(EnvelopeError):
            _sealed(version=bad_version)

    def test_rejects_float_in_policy(self) -> None:
        with pytest.raises(EnvelopeError):
            _sealed(policy={**POLICY, "limits": {"timeout_s": 1.5}})

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
            {"version": 0},
            {"version": True},
            {"version": "10"},
            {"owner_pk": base64.b64encode(b"x" * 31).decode()},
            {"owner_pk": base64.urlsafe_b64encode(b"\xfb" * 32).decode()},
            {"sig": None},
            {"sig": base64.b64encode(b"x" * 63).decode()},
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

    def test_from_dict_rejects_unpadded_signature(self) -> None:
        wire = _sealed().to_dict()
        wire["sig"] = wire["sig"].rstrip("=")
        with pytest.raises(EnvelopeError):
            Envelope.from_dict(wire)


class TestVectors:
    @pytest.mark.parametrize("vector", VECTORS["envelopes"], ids=lambda v: v["name"])
    def test_vector(self, vector: dict[str, Any]) -> None:
        owner_pk = bytes.fromhex(VECTORS["owner"]["public_key_hex"])
        dek = bytes.fromhex(vector["dek_hex"])
        nonce = bytes.fromhex(vector["nonce_hex"])
        plaintext = base64.b64decode(vector["plaintext_b64"])
        aad_input = base64.b64decode(vector["aad_input_b64"])
        envelope = Envelope.from_dict(vector["envelope"])

        assert hashlib.sha256(aad_input).hexdigest() == vector["aad_hex"]
        assert compute_aad(envelope.header()).hex() == vector["aad_hex"]
        assert canonical_json(envelope.header()) == aad_input
        assert envelope.owner_pk == owner_pk
        assert fingerprint(owner_pk).hex() == VECTORS["owner"]["fingerprint_hex"]
        assert rsa_oaep_unwrapper(_private_key())(envelope.wrapped) == dek
        assert envelope.nonce == nonce
        assert base64.b64decode(vector["ct_b64"]) == envelope.ct
        aad = bytes.fromhex(vector["aad_hex"])
        assert AESGCM(dek).encrypt(nonce, plaintext, aad) == envelope.ct

        signing_bytes = base64.b64decode(vector["signing_input_b64"])
        assert signing_input(ENVELOPE_CONTEXT, envelope.signed_body()) == signing_bytes
        assert signing_bytes.startswith(b"carapace-envelope-v1\n")
        assert KeyPair.verify(owner_pk, envelope.sig, signing_bytes)

        opened, policy = open_with_dek_unwrapper(
            envelope,
            rsa_oaep_unwrapper(_private_key()),
            expected_secret_id=vector["secret_id"],
            expected_owner_pk=owner_pk,
            min_version=vector["version"],
        )
        assert opened == plaintext
        assert policy == vector["policy"]

    @pytest.mark.parametrize("vector", VECTORS["tamper"], ids=lambda v: v["name"])
    def test_tamper_vector_is_rejected(self, vector: dict[str, Any]) -> None:
        unwrap = _CountingUnwrapper()
        outcome = vector["outcome"]

        try:
            if "envelope_json" in vector:
                envelope = Envelope.from_json(vector["envelope_json"])
            else:
                envelope = Envelope.from_dict(vector["envelope"])
        except EnvelopeError as exc:
            assert outcome == "reject_malformed", f"unexpected parse failure: {exc}"
            assert not isinstance(exc, (EnvelopeSignatureError, EnvelopeStaleError))
            return
        assert outcome != "reject_malformed", "malformed vector parsed"

        with pytest.raises(EnvelopeError) as info:
            open_with_dek_unwrapper(
                envelope,
                unwrap,
                expected_secret_id=vector["expected_secret_id"],
                expected_owner_pk=bytes.fromhex(vector["expected_owner_pk_hex"]),
                min_version=vector["min_version"],
            )
        error = info.value
        if outcome == "reject_signature":
            assert not isinstance(error, (EnvelopeStaleError, EnvelopeDecryptionError))
            assert unwrap.calls == 0, "must not reach KMS before the signature check"
        elif outcome == "reject_stale":
            assert isinstance(error, EnvelopeStaleError)
            assert unwrap.calls == 0
        else:
            assert outcome == "reject_authentication"
            assert isinstance(error, EnvelopeDecryptionError)
            assert unwrap.calls == 1

    def test_tamper_vectors_cover_required_cases(self) -> None:
        names = {v["name"] for v in VECTORS["tamper"]}
        required = {
            "policy-widened",
            "relabeled-owner",
            "relabeled-secret",
            "substituted-by-other-owner",
            "owner-pk-swapped",
            "signed-under-grant-context",
            "signed-without-context",
            "version-rollback",
            "resigned-policy-widened",
            "resigned-truncated-ct",
            "duplicate-json-key",
            "version-bool",
        }
        assert required <= names

    @pytest.mark.parametrize("vector", VECTORS["envelopes"], ids=lambda v: v["name"])
    def test_seal_is_deterministic_given_rng(self, vector: dict[str, Any]) -> None:
        owner = OwnerKey.from_seed(bytes.fromhex(VECTORS["owner"]["seed_hex"]))
        pool = bytes.fromhex(vector["dek_hex"]) + bytes.fromhex(vector["nonce_hex"])
        chunks = iter([pool[:DEK_SIZE], pool[DEK_SIZE:]])
        envelope = _seal(
            VECTORS["rsa_public_key_pem"],
            vector["secret_id"],
            vector["owner_id"],
            vector["policy"],
            base64.b64decode(vector["plaintext_b64"]),
            owner_key=owner,
            version=vector["version"],
            kms_key_version=vector["envelope"]["kms_key_version"],
            random_bytes=lambda _: next(chunks),
        )
        assert envelope.to_dict()["ct"] == vector["ct_b64"]
        assert envelope.header() == Envelope.from_dict(vector["envelope"]).header()
