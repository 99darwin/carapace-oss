"""Shared fixtures: a dev-mode app on a throwaway SQLite file."""

from collections.abc import AsyncIterator
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
