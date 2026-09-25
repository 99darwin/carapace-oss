"""Shared fixtures: a dev-mode app on a throwaway SQLite file, and helpers."""

import base64
import os
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from carapace_server.app import create_app
from carapace_server.config import Settings
from carapace_server.db import create_engine, create_sessionmaker
from carapace_server.models import Base

STRONG_PASSWORD = "Correct-Horse-9-Battery"  # noqa: S105


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


async def register(
    client: httpx.AsyncClient, email: str, password: str = STRONG_PASSWORD
) -> dict:
    response = await client.post(
        "/v1/auth/register", json={"email": email, "password": password}
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.fixture
def register_user():
    return register


DEFAULT_POLICY = {
    "v": 1,
    "hosts": [{"match": "exact", "value": "api.example.com"}],
    "schemes": ["https"],
}


def make_envelope(
    owner_id: str,
    secret_id: str | None = None,
    policy: dict | None = None,
    wrapped_len: int = 512,
) -> dict:
    """Random bytes shaped like envelope v1. The server cannot tell."""
    return {
        "v": 1,
        "secret_id": secret_id or str(uuid.uuid4()),
        "owner_id": owner_id,
        "policy": policy if policy is not None else DEFAULT_POLICY,
        "kms_key_version": "projects/p/keys/k/cryptoKeyVersions/1",
        "wrapped": base64.b64encode(os.urandom(wrapped_len)).decode(),
        "nonce": base64.b64encode(os.urandom(12)).decode(),
        "ct": base64.b64encode(os.urandom(48)).decode(),
    }


@dataclass
class Account:
    user_id: str
    headers: dict[str, str]


async def create_account(client: httpx.AsyncClient, email: str) -> Account:
    tokens = await register(client, email)
    return Account(
        user_id=tokens["user_id"],
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )


async def create_secret(
    client: httpx.AsyncClient, account: Account, name: str = "github"
) -> dict:
    response = await client.post(
        "/v1/secrets",
        json={"name": name, "envelope": make_envelope(account.user_id)},
        headers=account.headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


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
