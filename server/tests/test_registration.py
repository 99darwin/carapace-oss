"""Registration is closed by default: one account, with the setup token (#52)."""

import asyncio
import hashlib
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from carapace_server.app import create_app
from carapace_server.auth.models import InstanceClaim, User
from carapace_server.auth.service import (
    REGISTRATION_CLOSED,
    SETUP_TOKEN_INVALID,
    AuthService,
)
from carapace_server.config import ConfigError, Settings

pytestmark = pytest.mark.anyio

PASSWORD = "Correct-Horse-9-Battery"  # noqa: S105
SETUP_TOKEN = "setup-token-for-tests-" + "x" * 22  # noqa: S105
SETUP_TOKEN_SHA256 = hashlib.sha256(SETUP_TOKEN.encode()).hexdigest()
FORBIDDEN = 403


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "mode": "dev",
        "database_url": f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        "public_url": "http://localhost:8000",
        "bcrypt_rounds": 4,
        "rate_limit_enabled": False,
        "setup_token_sha256": SETUP_TOKEN_SHA256,
    }
    values.update(overrides)
    return Settings(**values)


async def _client(
    settings: Settings, sessionmaker: async_sessionmaker[AsyncSession]
) -> AsyncIterator[httpx.AsyncClient]:
    app: FastAPI = create_app(settings)
    app.state.sessionmaker = sessionmaker
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
async def closed(
    tmp_path: Path, sessionmaker: async_sessionmaker[AsyncSession]
) -> AsyncIterator[httpx.AsyncClient]:
    """A server with signup off and a setup token configured."""
    async for client in _client(_settings(tmp_path), sessionmaker):
        yield client


async def _register(
    client: httpx.AsyncClient, email: str, token: str | None = SETUP_TOKEN
) -> httpx.Response:
    body = {"email": email, "password": PASSWORD}
    if token is not None:
        body["setup_token"] = token
    return await client.post("/v1/auth/register", json=body)


async def _count(db: AsyncSession, model: type) -> int:
    return await db.scalar(select(func.count()).select_from(model))


async def test_first_account_registers_and_the_second_is_refused(
    closed: httpx.AsyncClient, db: AsyncSession
) -> None:
    first = await _register(closed, "owner@example.com")
    assert first.status_code == 201, first.text

    second = await _register(closed, "stranger@example.com")
    assert second.status_code == FORBIDDEN
    assert second.json()["detail"] == REGISTRATION_CLOSED

    assert await _count(db, User) == 1
    claim = await db.scalar(select(InstanceClaim))
    assert str(claim.user_id) == first.json()["user_id"]


@pytest.mark.parametrize(
    "token", [None, "wrong-token", SETUP_TOKEN.upper(), SETUP_TOKEN + "x"]
)
async def test_missing_or_wrong_setup_token_is_refused(
    closed: httpx.AsyncClient, db: AsyncSession, token: str | None
) -> None:
    response = await _register(closed, "owner@example.com", token)
    assert response.status_code == FORBIDDEN
    assert response.json()["detail"] == SETUP_TOKEN_INVALID
    assert await _count(db, User) == 0
    assert await _count(db, InstanceClaim) == 0


async def test_setup_token_is_single_use(
    closed: httpx.AsyncClient, db: AsyncSession
) -> None:
    assert (await _register(closed, "owner@example.com")).status_code == 201
    reused = await _register(closed, "attacker@example.com")
    assert reused.status_code == FORBIDDEN
    assert reused.json()["detail"] == REGISTRATION_CLOSED
    # The owner cannot re-register either, and learns nothing new.
    again = await _register(closed, "owner@example.com")
    assert again.status_code == FORBIDDEN
    assert await _count(db, User) == 1


async def test_login_still_works_when_closed(closed: httpx.AsyncClient) -> None:
    await _register(closed, "owner@example.com")
    response = await closed.post(
        "/v1/auth/login", json={"email": "owner@example.com", "password": PASSWORD}
    )
    assert response.status_code == 200


async def test_concurrent_first_registrations_one_wins(
    closed: httpx.AsyncClient,
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both pass the read check before either inserts; the claim decides."""
    barrier = asyncio.Barrier(2)
    original = AuthService.ensure_registration_open

    async def check_then_wait(self: AuthService) -> None:
        await original(self)
        await barrier.wait()

    monkeypatch.setattr(AuthService, "ensure_registration_open", check_then_wait)
    responses = await asyncio.gather(
        _register(closed, "owner@example.com"),
        _register(closed, "attacker@example.com"),
    )
    codes = sorted(r.status_code for r in responses)
    assert codes == [201, FORBIDDEN], [r.text for r in responses]
    refused = next(r for r in responses if r.status_code == FORBIDDEN)
    assert refused.json()["detail"] == REGISTRATION_CLOSED
    assert await _count(db, User) == 1
    assert await _count(db, InstanceClaim) == 1


async def test_claim_holds_without_the_read_check(
    closed: httpx.AsyncClient,
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The database constraint alone keeps a second first account out."""

    async def skip(self: AuthService) -> None:
        return None

    monkeypatch.setattr(AuthService, "ensure_registration_open", skip)
    assert (await _register(closed, "owner@example.com")).status_code == 201
    second = await _register(closed, "attacker@example.com")
    assert second.status_code == FORBIDDEN
    assert second.json()["detail"] == REGISTRATION_CLOSED
    assert await _count(db, User) == 1


async def test_passkey_registration_is_closed_too(
    closed: httpx.AsyncClient,
) -> None:
    await _register(closed, "owner@example.com")
    options = await closed.post(
        "/v1/auth/passkey/register/options", json={"email": "pk@example.com"}
    )
    assert options.status_code == FORBIDDEN
    assert options.json()["detail"] == REGISTRATION_CLOSED
    register = await closed.post(
        "/v1/auth/passkey/register",
        json={"email": "pk@example.com", "credential": {}},
    )
    # No challenge was issued, so this fails before the gate.
    assert register.status_code in {400, FORBIDDEN}


async def test_allow_signup_opens_registration(
    tmp_path: Path,
    sessionmaker: async_sessionmaker[AsyncSession],
    db: AsyncSession,
) -> None:
    settings = _settings(tmp_path, allow_signup=True)
    async for client in _client(settings, sessionmaker):
        for email in ("a@example.com", "b@example.com", "c@example.com"):
            response = await _register(client, email, token=None)
            assert response.status_code == 201, response.text
    assert await _count(db, User) == 3


async def test_prod_without_a_setup_token_fails_closed(
    tmp_path: Path,
    sessionmaker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path, setup_token_sha256=None)
    # Prod settings need Postgres and more; only the gate reads the mode.
    monkeypatch.setattr(settings, "mode", "prod")
    async for client in _client(settings, sessionmaker):
        response = await _register(client, "owner@example.com", token="anything")
        assert response.status_code == FORBIDDEN
        assert response.json()["detail"] == SETUP_TOKEN_INVALID


async def test_dev_without_a_setup_token_takes_the_first_account(
    tmp_path: Path, sessionmaker: async_sessionmaker[AsyncSession]
) -> None:
    settings = _settings(tmp_path, setup_token_sha256=None)
    async for client in _client(settings, sessionmaker):
        assert (await _register(client, "a@example.com", None)).status_code == 201
        second = await _register(client, "b@example.com", None)
        assert second.status_code == FORBIDDEN
        assert second.json()["detail"] == REGISTRATION_CLOSED


def test_signup_is_off_by_default() -> None:
    assert Settings(mode="dev").allow_signup is False


@pytest.mark.parametrize("value", ["abc", "g" * 64, SETUP_TOKEN])
def test_setup_token_sha256_must_be_a_digest(value: str) -> None:
    with pytest.raises((ConfigError, ValueError)):
        Settings(mode="dev", setup_token_sha256=value)


def test_setup_token_sha256_is_normalized() -> None:
    settings = Settings(mode="dev", setup_token_sha256=SETUP_TOKEN_SHA256.upper())
    assert settings.setup_token_sha256 == SETUP_TOKEN_SHA256
    assert Settings(mode="dev", setup_token_sha256="").setup_token_sha256 is None
