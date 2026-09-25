"""Confidential Space token verification: every claim the KMS policy checks."""

import base64
import json
import time
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from carapace_server.attestation import (
    AttestationError,
    AttestationVerifier,
)
from carapace_server.config import GOOGLE_ATTESTATION_ISSUER, Settings

pytestmark = pytest.mark.anyio

AUDIENCE = "https://server.example.com"
DISCOVERY = "https://issuer.test/.well-known/openid-configuration"
JWKS_URI = "https://issuer.test/jwks"
NONCE = "ab" * 32
PROJECT = "example-project"
SERVICE_ACCOUNT = "enclave@example.iam.gserviceaccount.com"


class FakeKeyServer:
    """Stands in for Google's discovery document and JWKS."""

    def __init__(self, key: rsa.RSAPrivateKey, kid: str) -> None:
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        self.jwks = {"keys": [{**jwk, "kid": kid, "alg": "RS256", "use": "sig"}]}
        self.calls: list[str] = []

    async def fetch(self, url: str) -> dict[str, Any]:
        self.calls.append(url)
        if url == DISCOVERY:
            return {"issuer": GOOGLE_ATTESTATION_ISSUER, "jwks_uri": JWKS_URI}
        if url == JWKS_URI:
            return self.jwks
        raise AssertionError(f"unexpected fetch {url}")


@pytest.fixture
def google_settings(image_digest: str) -> Settings:
    return Settings(
        mode="dev",
        public_url=AUDIENCE,
        allowed_image_digests=[image_digest],
        attestation_project_id=PROJECT,
        attestation_service_account=SERVICE_ACCOUNT,
    )


@pytest.fixture
def signer(signer_factory, attestation_rsa_key):
    return signer_factory(attestation_rsa_key, GOOGLE_ATTESTATION_ISSUER, AUDIENCE)


@pytest.fixture
def key_server(attestation_rsa_key) -> FakeKeyServer:
    return FakeKeyServer(attestation_rsa_key, "test-key-1")


@pytest.fixture
def verifier(google_settings: Settings, key_server: FakeKeyServer):
    return AttestationVerifier(
        google_settings, fetch_json=key_server.fetch, discovery_url=DISCOVERY
    )


async def test_valid_token_accepted(verifier, signer, image_digest) -> None:
    attestation = await verifier.verify(signer.token(NONCE))
    assert attestation.nonces == (NONCE,)
    assert attestation.image_digest == image_digest


async def test_nonce_list_accepted(verifier, signer) -> None:
    attestation = await verifier.verify(signer.token([NONCE, "cd" * 32]))
    assert attestation.nonces == (NONCE, "cd" * 32)


async def test_jwks_is_cached(verifier, signer, key_server) -> None:
    await verifier.verify(signer.token(NONCE))
    await verifier.verify(signer.token(NONCE))
    assert key_server.calls == [DISCOVERY, JWKS_URI]


def _submods(image_digest: str, **changes: Any) -> dict[str, Any]:
    submods = {
        "confidential_space": {"support_attributes": ["STABLE"]},
        "container": {"image_digest": image_digest},
        "gce": {"project_id": PROJECT},
    }
    submods.update(changes)
    return submods


BAD_CLAIMS = {
    "wrong_audience": {"aud": "https://other.example.com"},
    "wrong_issuer": {"iss": "https://issuer.example"},
    "expired": {"exp": int(time.time()) - 3600},
    "debug_enabled": {"dbgstat": "enabled"},
    "wrong_hwmodel": {"hwmodel": "GCP_INTEL_TDX"},
    "wrong_swname": {"swname": "GCE"},
    "no_secure_boot": {"secboot": False},
    "missing_nonce": {"eat_nonce": None},
    "empty_nonce_list": {"eat_nonce": []},
    "non_string_nonce": {"eat_nonce": [1]},
    "wrong_service_account": {"google_service_accounts": ["x@example.com"]},
}


@pytest.mark.parametrize("overrides", BAD_CLAIMS.values(), ids=BAD_CLAIMS.keys())
async def test_bad_claims_rejected(verifier, signer, overrides) -> None:
    claims = signer.claims(NONCE, **overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    with pytest.raises(AttestationError):
        await verifier.verify(signer.sign(claims))


BAD_SUBMODS = {
    "wrong_digest": {"container": {"image_digest": "sha256:" + "00" * 32}},
    "missing_digest": {"container": {}},
    "not_stable": {"confidential_space": {"support_attributes": ["LATEST"]}},
    "wrong_project": {"gce": {"project_id": "someone-else"}},
}


@pytest.mark.parametrize("changes", BAD_SUBMODS.values(), ids=BAD_SUBMODS.keys())
async def test_bad_submods_rejected(verifier, signer, image_digest, changes) -> None:
    token = signer.token(NONCE, submods=_submods(image_digest, **changes))
    with pytest.raises(AttestationError):
        await verifier.verify(token)


async def test_unknown_kid_rejected(verifier, signer) -> None:
    token = signer.sign(signer.claims(NONCE), kid="rotated-away")
    with pytest.raises(AttestationError, match="unknown signing key"):
        await verifier.verify(token)


async def test_foreign_signature_rejected(verifier, signer_factory) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = signer_factory(other, GOOGLE_ATTESTATION_ISSUER, AUDIENCE).token(NONCE)
    with pytest.raises(AttestationError):
        await verifier.verify(forged)


def _b64url(data: dict[str, Any]) -> str:
    raw = json.dumps(data).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


async def test_alg_none_rejected(verifier, signer) -> None:
    header = {"alg": "none", "kid": "test-key-1", "typ": "JWT"}
    token = f"{_b64url(header)}.{_b64url(signer.claims(NONCE))}."
    with pytest.raises(AttestationError):
        await verifier.verify(token)


async def test_hs256_rejected(verifier, signer) -> None:
    token = jwt.encode(
        signer.claims(NONCE),
        "k" * 32,
        algorithm="HS256",
        headers={"kid": "test-key-1"},
    )
    with pytest.raises(AttestationError):
        await verifier.verify(token)


async def test_garbage_rejected(verifier) -> None:
    with pytest.raises(AttestationError):
        await verifier.verify("not-a-jwt")


async def test_oversized_token_rejected(verifier) -> None:
    with pytest.raises(AttestationError, match="too large"):
        await verifier.verify("a" * (17 * 1024))


async def test_mock_issuer_accepted_in_dev(enclave_settings, mock_signer) -> None:
    verifier = AttestationVerifier(enclave_settings)
    attestation = await verifier.verify(mock_signer.token(NONCE))
    assert attestation.nonces == (NONCE,)


async def test_mock_issuer_rejected_in_prod(enclave_settings, mock_signer) -> None:
    # Config refuses this combination; bypass validation to prove the
    # verifier refuses it too.
    prod = enclave_settings.model_copy(update={"mode": "prod"})
    verifier = AttestationVerifier(prod)
    with pytest.raises(AttestationError, match="outside dev"):
        await verifier.verify(mock_signer.token(NONCE))


async def test_mock_token_rejected_by_google_verifier(verifier, mock_signer) -> None:
    with pytest.raises(AttestationError):
        await verifier.verify(mock_signer.token(NONCE))


async def test_key_fetch_failure_rejected(google_settings, signer) -> None:
    async def broken(url: str) -> dict[str, Any]:
        return {}

    verifier = AttestationVerifier(
        google_settings, fetch_json=broken, discovery_url=DISCOVERY
    )
    with pytest.raises(AttestationError, match="unknown signing key"):
        await verifier.verify(signer.token(NONCE))


async def test_unknown_kids_are_throttled(verifier, signer, key_server) -> None:
    for i in range(5):
        with pytest.raises(AttestationError):
            await verifier.verify(signer.sign(signer.claims(NONCE), kid=f"k{i}"))
    assert key_server.calls == [DISCOVERY, JWKS_URI]


async def test_failed_refresh_is_throttled(google_settings, signer) -> None:
    calls: list[str] = []

    async def failing(url: str) -> dict[str, Any]:
        calls.append(url)
        raise httpx.ConnectError("down")

    verifier = AttestationVerifier(
        google_settings, fetch_json=failing, discovery_url=DISCOVERY
    )
    for _ in range(3):
        with pytest.raises(AttestationError):
            await verifier.verify(signer.token(NONCE))
    assert calls == [DISCOVERY]
