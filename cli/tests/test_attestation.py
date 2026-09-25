"""Attestation token rules: issuer, signature, claims, digest."""

from __future__ import annotations

import json
import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from carapace_cli import VerificationError
from carapace_cli.attestation import (
    ATTESTATION_AUDIENCE,
    GOOGLE_ISSUER,
    TrustPolicy,
    verify_attestation_token,
)
from carapace_enclave_mock import MockLauncher
from carapace_enclave_mock.launcher import MOCK_IMAGE_DIGEST

NONCE = "ab" * 32
GOOGLE_KID = "google-key-1"
OTHER_DIGEST = "sha256:" + "11" * 32


@pytest.fixture(scope="module")
def launcher() -> MockLauncher:
    return MockLauncher.generate()


@pytest.fixture(scope="module")
def google_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _mock_policy(launcher: MockLauncher, *digests: str) -> TrustPolicy:
    return TrustPolicy(
        allowed_digests=frozenset(digests or {MOCK_IMAGE_DIGEST}),
        mock_key_pem=launcher.public_pem,
    )


def _google_policy(google_key: rsa.RSAPrivateKey) -> TrustPolicy:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(google_key.public_key()))
    jwks = {"keys": [jwk | {"kid": GOOGLE_KID, "alg": "RS256", "use": "sig"}]}
    return TrustPolicy(
        allowed_digests=frozenset({MOCK_IMAGE_DIGEST}), jwks_fetcher=lambda: jwks
    )


def _mock_token(launcher: MockLauncher, **overrides: Any) -> str:
    claims = launcher.claims(ATTESTATION_AUDIENCE, [NONCE]) | overrides
    return launcher.sign({k: v for k, v in claims.items() if v is not None})


def _google_token(
    launcher: MockLauncher, key: rsa.RSAPrivateKey, **overrides: Any
) -> str:
    claims = launcher.claims(ATTESTATION_AUDIENCE, [NONCE])
    claims |= {"iss": GOOGLE_ISSUER} | overrides
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": GOOGLE_KID})


def _verify(token: str, policy: TrustPolicy, **kwargs: Any) -> Any:
    return verify_attestation_token(
        token, policy, audiences=[ATTESTATION_AUDIENCE], nonce=NONCE, **kwargs
    )


def test_mock_token_verifies_in_insecure_mock_mode(launcher) -> None:
    claims = _verify(_mock_token(launcher), _mock_policy(launcher))
    assert claims.image_digest == MOCK_IMAGE_DIGEST
    assert claims.issuer == "mock://local"


def test_mock_token_is_refused_without_insecure_mock(launcher, google_key) -> None:
    with pytest.raises(VerificationError, match="--insecure-mock"):
        _verify(_mock_token(launcher), _google_policy(google_key))


def test_insecure_mock_refuses_google_issuer(launcher, google_key) -> None:
    token = _google_token(launcher, google_key)
    with pytest.raises(VerificationError, match="accepts only the mock"):
        _verify(token, _mock_policy(launcher))


def test_insecure_mock_refuses_other_issuers(launcher) -> None:
    token = _mock_token(launcher, iss="https://evil.example.net")
    with pytest.raises(VerificationError, match="accepts only the mock"):
        _verify(token, _mock_policy(launcher))


def test_mock_token_signed_by_another_key_is_refused(launcher) -> None:
    other = MockLauncher.generate()
    with pytest.raises(VerificationError, match="rejected"):
        _verify(_mock_token(other), _mock_policy(launcher))


def test_google_token_verifies_with_jwks(launcher, google_key) -> None:
    token = _google_token(launcher, google_key)
    claims = _verify(token, _google_policy(google_key))
    assert claims.issuer == GOOGLE_ISSUER


def test_google_token_with_unknown_kid_is_refused(launcher, google_key) -> None:
    token = jwt.encode(
        launcher.claims(ATTESTATION_AUDIENCE, [NONCE]) | {"iss": GOOGLE_ISSUER},
        google_key,
        algorithm="RS256",
        headers={"kid": "unknown"},
    )
    with pytest.raises(VerificationError, match="not in Google's JWKS"):
        _verify(token, _google_policy(google_key))


def test_google_issuer_signed_by_another_key_is_refused(launcher, google_key) -> None:
    impostor = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _google_token(launcher, impostor)
    with pytest.raises(VerificationError, match="rejected"):
        _verify(token, _google_policy(google_key))


def test_non_rs256_is_refused(launcher) -> None:
    token = jwt.encode(
        launcher.claims(ATTESTATION_AUDIENCE, [NONCE]), "k" * 32, algorithm="HS256"
    )
    with pytest.raises(VerificationError, match="RS256"):
        _verify(token, _mock_policy(launcher))


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"hwmodel": "GCP_INTEL_TDX_DEBUG"}, "hardware model"),
        ({"swname": "GCE"}, "Confidential Space"),
        ({"dbgstat": "enabled"}, "debuggable"),
        ({"secboot": False}, "secure boot"),
        ({"aud": "https://other"}, "(?i)audience"),
        ({"eat_nonce": "cd" * 32}, "nonce"),
        ({"exp": int(time.time()) - 3600}, "(?i)expired"),
        ({"exp": None}, "exp"),
        (
            {
                "submods": {
                    "confidential_space": {"support_attributes": ["LATEST"]},
                    "container": {"image_digest": MOCK_IMAGE_DIGEST},
                }
            },
            "STABLE",
        ),
    ],
)
def test_bad_claims_are_refused(launcher, overrides, message) -> None:
    with pytest.raises(VerificationError, match=message):
        _verify(_mock_token(launcher, **overrides), _mock_policy(launcher))


def test_nonce_list_is_accepted(launcher) -> None:
    token = _mock_token(launcher, eat_nonce=["cd" * 32, NONCE])
    assert _verify(token, _mock_policy(launcher))


def test_expiry_can_be_skipped_for_audits(launcher) -> None:
    token = _mock_token(launcher, exp=int(time.time()) - 3600)
    assert _verify(token, _mock_policy(launcher), check_expiry=False)


def test_digest_outside_allowlist_is_refused(launcher) -> None:
    with pytest.raises(VerificationError, match="not in the allowlist"):
        _verify(_mock_token(launcher), _mock_policy(launcher, OTHER_DIGEST))


def test_empty_allowlist_is_refused() -> None:
    with pytest.raises(VerificationError, match="--allow-digest"):
        TrustPolicy(allowed_digests=frozenset())


def test_malformed_digest_is_refused() -> None:
    with pytest.raises(VerificationError, match="sha256"):
        TrustPolicy(allowed_digests=frozenset({"latest"}))
