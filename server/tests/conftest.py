"""Shared fixtures: a dev-mode app on a throwaway SQLite file."""

import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import FastAPI
from server_support import (
    Account,
    create_account,
    create_secret,
    make_envelope,
    register,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from carapace_server.app import create_app
from carapace_server.config import MOCK_ATTESTATION_ISSUER, Settings
from carapace_server.db import create_engine, create_sessionmaker
from carapace_server.models import Base


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        mode="dev",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        public_url="http://localhost:8000",
        bcrypt_rounds=4,
        rate_limit_enabled=False,
        # Most tests need several accounts; test_registration.py covers the
        # closed default.
        allow_signup=True,
    )


@pytest.fixture
async def sessionmaker(
    settings: Settings,
) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = create_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield create_sessionmaker(engine)
    await engine.dispose()


@pytest.fixture
async def db(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    async with sessionmaker() as session:
        yield session


@pytest.fixture
def app(settings: Settings, sessionmaker: async_sessionmaker[AsyncSession]) -> FastAPI:
    application = create_app(settings)
    application.state.sessionmaker = sessionmaker
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
def register_user():
    return register


@pytest.fixture
async def alice(client: httpx.AsyncClient) -> Account:
    return await create_account(client, "alice@example.com")


@pytest.fixture
async def bob(client: httpx.AsyncClient) -> Account:
    return await create_account(client, "bob@example.com")


@pytest.fixture
def envelope_factory():
    return make_envelope


@pytest.fixture
def new_secret():
    return create_secret


# -- enclave attestation ------------------------------------------------------

IMAGE_DIGEST = "sha256:" + "ab" * 32
ATTESTATION_KEY_ID = "test-key-1"


@dataclass
class AttestationSigner:
    """Mints Confidential Space-shaped tokens with a local RSA key."""

    private_key: rsa.RSAPrivateKey
    issuer: str
    audience: str

    @property
    def public_pem(self) -> str:
        return (
            self.private_key.public_key()
            .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            .decode()
        )

    def claims(self, nonce: str | list[str], **overrides: Any) -> dict[str, Any]:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": self.audience,
            "iat": now,
            "nbf": now,
            "exp": now + 3600,
            "eat_nonce": nonce,
            "swname": "CONFIDENTIAL_SPACE",
            "hwmodel": "GCP_AMD_SEV",
            "dbgstat": "disabled-since-boot",
            "secboot": True,
            "google_service_accounts": ["enclave@example.iam.gserviceaccount.com"],
            "submods": {
                "confidential_space": {"support_attributes": ["LATEST", "STABLE"]},
                "container": {"image_digest": IMAGE_DIGEST},
                "gce": {"project_id": "example-project"},
            },
        }
        claims.update(overrides)
        return claims

    def sign(self, claims: dict[str, Any], **headers: Any) -> str:
        headers = {"kid": ATTESTATION_KEY_ID, **headers}
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers=headers)

    def token(self, nonce: str | list[str], **overrides: Any) -> str:
        return self.sign(self.claims(nonce, **overrides))


@pytest.fixture(scope="session")
def attestation_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def mock_signer(attestation_rsa_key: rsa.RSAPrivateKey) -> AttestationSigner:
    return AttestationSigner(
        attestation_rsa_key, MOCK_ATTESTATION_ISSUER, "http://localhost:8000"
    )


@pytest.fixture
def enclave_settings(tmp_path: Path, mock_signer: AttestationSigner) -> Settings:
    """Dev settings that accept mock-issuer tokens for IMAGE_DIGEST."""
    return Settings(
        mode="dev",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        public_url="http://localhost:8000",
        bcrypt_rounds=4,
        rate_limit_enabled=False,
        allow_signup=True,
        attestation_issuer=MOCK_ATTESTATION_ISSUER,
        mock_attestation_public_key_pem=mock_signer.public_pem,
        allowed_image_digests=[IMAGE_DIGEST],
    )


@pytest.fixture
def image_digest() -> str:
    return IMAGE_DIGEST


@pytest.fixture
def signer_factory() -> type[AttestationSigner]:
    return AttestationSigner
