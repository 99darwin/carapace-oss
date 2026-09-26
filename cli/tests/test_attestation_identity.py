"""Deployment identity claims: project, service account, server URL, KMS key."""

from __future__ import annotations

import copy
import json
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from carapace_cli import VerificationError
from carapace_cli.attestation import (
    ATTESTATION_AUDIENCE,
    GOOGLE_ISSUER,
    TrustPolicy,
    canonical_url,
    verify_attestation_token,
)
from carapace_enclave_mock import MOCK_KMS_KEY_VERSION, MockLauncher
from carapace_enclave_mock.launcher import (
    MOCK_IMAGE_DIGEST,
    MOCK_PROJECT_ID,
    MOCK_SERVICE_ACCOUNT,
)

NONCE = "ab" * 32
GOOGLE_KID = "google-key-1"
SERVER_URL = "https://api.example.com"
OTHER_KMS_KEY = MOCK_KMS_KEY_VERSION.replace("Versions/1", "Versions/2")
IDENTITY = {
    "project_id": MOCK_PROJECT_ID,
    "service_account": MOCK_SERVICE_ACCOUNT,
    "control_plane_url": SERVER_URL,
    "kms_key_name": MOCK_KMS_KEY_VERSION,
}


@pytest.fixture(scope="module")
def launcher() -> MockLauncher:
    return MockLauncher.generate(
        env={
            "CONTROL_PLANE_URL": SERVER_URL,
            "KMS_KEY_NAME": MOCK_KMS_KEY_VERSION,
            "WIF_AUDIENCE": "carapace-sts-test",
        }
    )


def _policy(launcher: MockLauncher, **identity: Any) -> TrustPolicy:
    return TrustPolicy(
        allowed_digests=frozenset({MOCK_IMAGE_DIGEST}),
        mock_key_pem=launcher.public_pem,
        **identity,
    )


def _claims(launcher: MockLauncher) -> dict[str, Any]:
    return copy.deepcopy(launcher.claims(ATTESTATION_AUDIENCE, [NONCE]))


def _verify(token: str, policy: TrustPolicy) -> Any:
    return verify_attestation_token(
        token, policy, audiences=[ATTESTATION_AUDIENCE], nonce=NONCE
    )


# How to remove, or change, the claim each policy field is checked against.
def _drop_project(claims: dict[str, Any]) -> None:
    del claims["submods"]["gce"]


def _drop_service_account(claims: dict[str, Any]) -> None:
    del claims["google_service_accounts"]


def _drop_control_plane_url(claims: dict[str, Any]) -> None:
    del claims["submods"]["container"]["env"]["CONTROL_PLANE_URL"]


def _drop_kms_key(claims: dict[str, Any]) -> None:
    del claims["submods"]["container"]["env"]["KMS_KEY_NAME"]


def _other_project(claims: dict[str, Any]) -> None:
    claims["submods"]["gce"]["project_id"] = "attacker-project"


def _other_service_account(claims: dict[str, Any]) -> None:
    claims["google_service_accounts"] = ["x@attacker-project.iam.gserviceaccount.com"]


def _other_control_plane_url(claims: dict[str, Any]) -> None:
    claims["submods"]["container"]["env"]["CONTROL_PLANE_URL"] = "https://evil.test"


def _other_kms_key(claims: dict[str, Any]) -> None:
    claims["submods"]["container"]["env"]["KMS_KEY_NAME"] = OTHER_KMS_KEY


FIELDS = [
    ("project_id", _drop_project, _other_project, "GCP project"),
    ("service_account", _drop_service_account, _other_service_account, "run as"),
    (
        "control_plane_url",
        _drop_control_plane_url,
        _other_control_plane_url,
        "control plane URL",
    ),
    ("kms_key_name", _drop_kms_key, _other_kms_key, "KMS key"),
]
FIELD_IDS = [name for name, *_ in FIELDS]


@pytest.mark.parametrize(("name", "drop", "change", "message"), FIELDS, ids=FIELD_IDS)
def test_matching_claim_is_accepted(launcher, name, drop, change, message) -> None:
    policy = _policy(launcher, **{name: IDENTITY[name]})
    assert _verify(launcher.sign(_claims(launcher)), policy)


@pytest.mark.parametrize(("name", "drop", "change", "message"), FIELDS, ids=FIELD_IDS)
def test_missing_claim_is_refused(launcher, name, drop, change, message) -> None:
    claims = _claims(launcher)
    drop(claims)
    with pytest.raises(VerificationError, match=message):
        _verify(launcher.sign(claims), _policy(launcher, **{name: IDENTITY[name]}))


@pytest.mark.parametrize(("name", "drop", "change", "message"), FIELDS, ids=FIELD_IDS)
def test_mismatched_claim_is_refused(launcher, name, drop, change, message) -> None:
    claims = _claims(launcher)
    change(claims)
    with pytest.raises(VerificationError, match=message):
        _verify(launcher.sign(claims), _policy(launcher, **{name: IDENTITY[name]}))


@pytest.mark.parametrize(("name", "drop", "change", "message"), FIELDS, ids=FIELD_IDS)
def test_other_fields_do_not_mask_a_mismatch(
    launcher, name, drop, change, message
) -> None:
    claims = _claims(launcher)
    change(claims)
    with pytest.raises(VerificationError, match=message):
        _verify(launcher.sign(claims), _policy(launcher, **IDENTITY))


def test_full_identity_is_accepted(launcher) -> None:
    claims = _verify(launcher.sign(_claims(launcher)), _policy(launcher, **IDENTITY))
    assert claims.image_digest == MOCK_IMAGE_DIGEST


def test_digest_only_policy_ignores_identity_claims(launcher) -> None:
    claims = _claims(launcher)
    for drop in (_drop_project, _drop_service_account):
        drop(claims)
    del claims["submods"]["container"]["env"]
    assert _verify(launcher.sign(claims), _policy(launcher))


def test_env_that_is_not_an_object_is_a_missing_claim(launcher) -> None:
    claims = _claims(launcher)
    claims["submods"]["container"]["env"] = ["CONTROL_PLANE_URL=" + SERVER_URL]
    with pytest.raises(VerificationError, match="does not state"):
        _verify(launcher.sign(claims), _policy(launcher, **IDENTITY))


def test_malformed_kms_claim_is_a_missing_claim(launcher) -> None:
    claims = _claims(launcher)
    claims["submods"]["container"]["env"]["KMS_KEY_NAME"] = "projects/x"
    with pytest.raises(VerificationError, match="does not state the enclave's KMS"):
        _verify(launcher.sign(claims), _policy(launcher, **IDENTITY))


def test_service_account_must_be_listed_not_a_substring(launcher) -> None:
    claims = _claims(launcher)
    claims["google_service_accounts"] = MOCK_SERVICE_ACCOUNT  # a string, not a list
    with pytest.raises(VerificationError, match="run as"):
        _verify(launcher.sign(claims), _policy(launcher, **IDENTITY))


def test_identity_is_checked_for_google_tokens(launcher) -> None:
    google_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(google_key.public_key()))
    jwks = {"keys": [jwk | {"kid": GOOGLE_KID, "alg": "RS256", "use": "sig"}]}
    policy = TrustPolicy(
        allowed_digests=frozenset({MOCK_IMAGE_DIGEST}),
        jwks_fetcher=lambda: jwks,
        **IDENTITY,
    )
    claims = _claims(launcher) | {"iss": GOOGLE_ISSUER}
    good = jwt.encode(
        claims, google_key, algorithm="RS256", headers={"kid": GOOGLE_KID}
    )
    assert _verify(good, policy).issuer == GOOGLE_ISSUER
    _other_project(claims)
    bad = jwt.encode(claims, google_key, algorithm="RS256", headers={"kid": GOOGLE_KID})
    with pytest.raises(VerificationError, match="GCP project"):
        _verify(bad, policy)


# -- URL normalisation -------------------------------------------------------------


@pytest.mark.parametrize(
    "attested",
    [
        "https://api.example.com/",
        "HTTPS://API.Example.com",
        "https://api.example.com:443",
    ],
)
def test_control_plane_url_is_compared_normalised(launcher, attested) -> None:
    claims = _claims(launcher)
    claims["submods"]["container"]["env"]["CONTROL_PLANE_URL"] = attested
    policy = _policy(launcher, control_plane_url="https://api.example.com/")
    assert _verify(launcher.sign(claims), policy)


@pytest.mark.parametrize(
    "attested",
    [
        "http://api.example.com",
        "https://api.example.com:8443",
        "https://api.example.com.evil.test",
        "https://api.example.com/other",
        "https://user@api.example.com",
        "not a url",
    ],
)
def test_other_control_plane_urls_are_refused(launcher, attested) -> None:
    claims = _claims(launcher)
    claims["submods"]["container"]["env"]["CONTROL_PLANE_URL"] = attested
    with pytest.raises(VerificationError, match="control plane URL"):
        _verify(launcher.sign(claims), _policy(launcher, control_plane_url=SERVER_URL))


def test_canonical_url_keeps_non_default_ports() -> None:
    assert canonical_url("http://127.0.0.1:8000/") == "http://127.0.0.1:8000"


# -- policy values -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("project_id", "Bad_Project", "project id"),
        ("project_id", "", "project id"),
        ("service_account", "not-an-email", "service account"),
        ("control_plane_url", "ftp://api.example.com", "invalid URL"),
        ("control_plane_url", "https://api.example.com?x=1", "plain base URL"),
        ("kms_key_name", "projects/p/keyRings/r/cryptoKeys/k", "key version"),
        ("kms_key_name", MOCK_KMS_KEY_VERSION + "/x", "key version"),
    ],
)
def test_malformed_policy_values_are_refused(field, value, message) -> None:
    with pytest.raises(VerificationError, match=message):
        TrustPolicy(allowed_digests=frozenset({MOCK_IMAGE_DIGEST}), **{field: value})
