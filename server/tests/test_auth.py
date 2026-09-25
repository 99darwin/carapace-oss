"""Password auth, token rotation, logout and bearer validation.

Ported from the orchestrator's test_auth.py; KMS sealing, NextAuth exchange
and admin roles are gone.
"""

import uuid
from datetime import timedelta

import httpx
import jwt
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from carapace_server.auth.models import User
from carapace_server.config import Settings
from carapace_server.db import utcnow

pytestmark = pytest.mark.anyio

PASSWORD = "Correct-Horse-9-Battery"  # noqa: S105


async def test_register_with_password(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/v1/auth/register",
        json={"email": "new@example.com", "password": PASSWORD, "display_name": "N"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 15 * 60
    assert {"access_token", "refresh_token", "user_id"} <= data.keys()


@pytest.mark.parametrize(
    "password",
    [
        "Sh0rt!",
        "correct-horse-9-battery",
        "CORRECT-HORSE-9-BATTERY",
        "CorrectHorse9Battery",
        "Correct-Horse-Battery",
    ],
)
async def test_register_rejects_weak_passwords(
    client: httpx.AsyncClient, password: str
) -> None:
    response = await client.post(
        "/v1/auth/register", json={"email": "weak@example.com", "password": password}
    )
    assert response.status_code == 422


async def test_register_requires_password(client: httpx.AsyncClient) -> None:
    response = await client.post("/v1/auth/register", json={"email": "a@example.com"})
    assert response.status_code == 422


async def test_register_rejects_unknown_fields(client: httpx.AsyncClient) -> None:
    response = await client.post(
        "/v1/auth/register",
        json={"email": "a@example.com", "password": PASSWORD, "is_admin": True},
    )
    assert response.status_code == 422


async def test_register_duplicate_email_is_case_insensitive(
    client: httpx.AsyncClient, register_user
) -> None:
    await register_user(client, "Dup@Example.com")
    response = await client.post(
        "/v1/auth/register", json={"email": "dup@example.COM", "password": PASSWORD}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Registration failed"


async def test_password_and_email_storage(
    client: httpx.AsyncClient, db: AsyncSession, register_user
) -> None:
    await register_user(client, "Stored@Example.com")
    user = await db.scalar(select(User).where(User.email == "stored@example.com"))
    assert user is not None
    assert user.password_hash.startswith(b"$2b$")
    assert PASSWORD.encode() not in user.password_hash


async def test_login_with_password(client: httpx.AsyncClient, register_user) -> None:
    await register_user(client, "login@example.com")
    response = await client.post(
        "/v1/auth/login", json={"email": "LOGIN@example.com", "password": PASSWORD}
    )
    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"


@pytest.mark.parametrize(
    ("email", "password"),
    [("login@example.com", "Wrong-Horse-9-Battery"), ("nobody@example.com", PASSWORD)],
)
async def test_login_failures_are_indistinguishable(
    client: httpx.AsyncClient, register_user, email: str, password: str
) -> None:
    await register_user(client, "login@example.com")
    response = await client.post(
        "/v1/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


async def test_login_passkey_only_account_rejects_password(
    client: httpx.AsyncClient, db: AsyncSession
) -> None:
    db.add(User(email="passkey@example.com", passkey_sign_count=0))
    await db.commit()
    response = await client.post(
        "/v1/auth/login", json={"email": "passkey@example.com", "password": PASSWORD}
    )
    assert response.status_code == 401


async def test_refresh_rotates_tokens(client: httpx.AsyncClient, register_user) -> None:
    original = (await register_user(client, "refresh@example.com"))["refresh_token"]

    response = await client.post("/v1/auth/refresh", json={"refresh_token": original})
    assert response.status_code == 200
    rotated = response.json()["refresh_token"]
    assert rotated != original

    reuse = await client.post("/v1/auth/refresh", json={"refresh_token": original})
    assert reuse.status_code == 401
    assert reuse.json()["detail"] == "Invalid or expired refresh token"

    again = await client.post("/v1/auth/refresh", json={"refresh_token": rotated})
    assert again.status_code == 200


async def test_refresh_invalid_token(client: httpx.AsyncClient) -> None:
    response = await client.post("/v1/auth/refresh", json={"refresh_token": "nope"})
    assert response.status_code == 401


async def test_logout_revokes_refresh_and_access(
    client: httpx.AsyncClient, register_user
) -> None:
    tokens = await register_user(client, "logout@example.com")
    auth = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert (await client.get("/v1/auth/me", headers=auth)).status_code == 200

    response = await client.post(
        "/v1/auth/logout",
        json={
            "refresh_token": tokens["refresh_token"],
            "access_token": tokens["access_token"],
        },
    )
    assert response.status_code == 204
    assert (await client.get("/v1/auth/me", headers=auth)).status_code == 401
    refresh = await client.post(
        "/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert refresh.status_code == 401


async def test_logout_ignores_forged_access_token(
    client: httpx.AsyncClient, register_user
) -> None:
    tokens = await register_user(client, "forged@example.com")
    response = await client.post(
        "/v1/auth/logout",
        json={"refresh_token": tokens["refresh_token"], "access_token": "a.b.c"},
    )
    assert response.status_code == 204


async def test_me_returns_profile(client: httpx.AsyncClient, register_user) -> None:
    tokens = await register_user(client, "me@example.com")
    response = await client.get(
        "/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "me@example.com"
    assert body["has_password"] is True
    assert body["has_passkey"] is False
    assert "password_hash" not in body


async def test_access_token_claims(
    client: httpx.AsyncClient, settings: Settings, register_user
) -> None:
    tokens = await register_user(client, "claims@example.com")
    claims = jwt.decode(
        tokens["access_token"],
        settings.jwt_key,
        algorithms=["HS256"],
        audience="carapace-api",
    )
    assert claims["iss"] == "carapace-server"
    assert claims["type"] == "access"
    assert claims["sub"] == tokens["user_id"]
    uuid.UUID(claims["jti"])


def _forge(settings: Settings, key: str | None = None, **overrides: object) -> str:
    now = utcnow()
    claims = {
        "sub": str(uuid.uuid4()),
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "jti": str(uuid.uuid4()),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }
    claims.update(overrides)
    return jwt.encode(claims, key or settings.jwt_key, algorithm="HS256")


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "someone-else"},
        {"iss": "someone-else"},
        {"type": "refresh"},
        {"exp": utcnow() - timedelta(minutes=1)},
        {"key": "x" * 48},
    ],
    ids=["aud", "iss", "type", "expired", "wrong-key"],
)
async def test_me_rejects_bad_tokens(
    client: httpx.AsyncClient, settings: Settings, register_user, overrides: dict
) -> None:
    tokens = await register_user(client, "bad@example.com")
    good = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    token = _forge(settings, sub=good["sub"], **overrides)
    response = await client.get(
        "/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401


async def test_me_rejects_alg_none(client: httpx.AsyncClient, register_user) -> None:
    tokens = await register_user(client, "none@example.com")
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    token = jwt.encode(claims, key=None, algorithm="none")
    response = await client.get(
        "/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401


async def test_me_requires_auth(client: httpx.AsyncClient) -> None:
    assert (await client.get("/v1/auth/me")).status_code == 401


async def test_rate_limit_applies(client: httpx.AsyncClient, app) -> None:
    from carapace_server.ratelimit import limiter

    limiter.reset()
    limiter.enabled = True
    try:
        codes = [
            (
                await client.post(
                    "/v1/auth/login",
                    json={"email": "rl@example.com", "password": PASSWORD},
                )
            ).status_code
            for _ in range(11)
        ]
    finally:
        limiter.enabled = False
        limiter.reset()
    assert codes[:10] == [401] * 10
    assert codes[10] == 429
