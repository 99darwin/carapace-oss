"""DEV ONLY: a fake Confidential Space launcher that signs its own tokens.

It answers ``POST /v1/token`` like the real launcher and mints RS256 tokens
shaped like Confidential Space's, with ``iss = mock://local``. A dev-mode
server trusts them when configured with :attr:`MockLauncher.public_pem`.

Serve it to :class:`~carapace_enclave.attestation.token.LauncherClient`
through :meth:`MockLauncher.transport`; there is no socket.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

MOCK_ISSUER = "mock://local"
MOCK_KEY_ID = "mock-key-1"
MOCK_IMAGE_DIGEST = "sha256:" + "00" * 32
MOCK_PROJECT_ID = "carapace-dev"
MOCK_SERVICE_ACCOUNT = "enclave@carapace-dev.iam.gserviceaccount.com"
TOKEN_LIFETIME_SECONDS = 3600
MAX_NONCES = 6
MIN_NONCE_LENGTH = 10
MAX_NONCE_LENGTH = 74


@dataclass
class MockLauncher:
    """Mints Confidential Space-shaped tokens with a local RSA key.

    ``overrides`` replaces claims in every token and ``audience_override``
    replaces the requested audience; tests use them to play a tampering
    launcher. ``requests`` records each request body.
    """

    signing_key: rsa.RSAPrivateKey
    image_digest: str = MOCK_IMAGE_DIGEST
    project_id: str = MOCK_PROJECT_ID
    service_account: str = MOCK_SERVICE_ACCOUNT
    clock: Callable[[], float] = time.time
    overrides: dict[str, Any] = field(default_factory=dict)
    requests: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def generate(cls, **kwargs: Any) -> MockLauncher:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return cls(signing_key=key, **kwargs)

    @property
    def public_pem(self) -> str:
        return (
            self.signing_key.public_key()
            .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            .decode("ascii")
        )

    def claims(self, audience: str, nonces: list[str]) -> dict[str, Any]:
        now = int(self.clock())
        claims: dict[str, Any] = {
            "iss": MOCK_ISSUER,
            "sub": "https://www.googleapis.com/compute/v1/projects/mock/instances/0",
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + TOKEN_LIFETIME_SECONDS,
            "eat_nonce": nonces[0] if len(nonces) == 1 else nonces,
            "swname": "CONFIDENTIAL_SPACE",
            "swversion": ["mock"],
            "hwmodel": "GCP_AMD_SEV",
            "dbgstat": "disabled-since-boot",
            "secboot": True,
            "google_service_accounts": [self.service_account],
            "submods": {
                "confidential_space": {"support_attributes": ["LATEST", "STABLE"]},
                "container": {"image_digest": self.image_digest},
                "gce": {"project_id": self.project_id},
            },
        }
        claims.update(self.overrides)
        return claims

    def sign(self, claims: dict[str, Any]) -> str:
        return jwt.encode(
            claims, self.signing_key, algorithm="RS256", headers={"kid": MOCK_KEY_ID}
        )

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.method != "POST" or request.url.path != "/v1/token":
            return httpx.Response(404)
        try:
            body = json.loads(request.content)
        except ValueError:
            return httpx.Response(400, text="invalid JSON")
        self.requests.append(body)
        audience = body.get("audience")
        nonces = body.get("nonces") or []
        if not isinstance(audience, str) or not audience:
            return httpx.Response(400, text="audience required")
        if body.get("token_type") != "OIDC":
            return httpx.Response(400, text="unsupported token_type")
        if not isinstance(nonces, list) or not 1 <= len(nonces) <= MAX_NONCES:
            return httpx.Response(400, text="1 to 6 nonces required")
        for nonce in nonces:
            if not isinstance(nonce, str):
                return httpx.Response(400, text="nonce must be a string")
            if not MIN_NONCE_LENGTH <= len(nonce.encode()) <= MAX_NONCE_LENGTH:
                return httpx.Response(400, text="nonce length out of range")
        return httpx.Response(200, text=self.sign(self.claims(audience, nonces)))

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)
