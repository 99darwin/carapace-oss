"""API keys: creation, hashing at rest, revocation and secret scoping."""

import uuid
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from carapace_server.apikeys.models import ApiKey
from carapace_server.apikeys.service import hash_api_key, is_key_allowed_for_secret
from carapace_server.db import utcnow

pytestmark = pytest.mark.anyio


async def _create_key(
    client: httpx.AsyncClient, account, secret_ids: list[str], **extra
) -> httpx.Response:
    return await client.post(
        "/v1/api-keys",
        json={"name": "agent", "secret_ids": secret_ids, **extra},
        headers=account.headers,
    )


async def test_create_returns_raw_key_once_and_stores_hash(
    client: httpx.AsyncClient, alice, db: AsyncSession, new_secret
) -> None:
    secret = await new_secret(client, alice)
    response = await _create_key(client, alice, [secret["id"]])
    assert response.status_code == 201
    body = response.json()
    raw_key = body["api_key"]
    assert raw_key.startswith("cpk_")
    assert body["key_prefix"] == raw_key[:12]
    assert body["secret_ids"] == [secret["id"]]

    row = await db.scalar(select(ApiKey).where(ApiKey.id == uuid.UUID(body["id"])))
    assert row.key_hash == hash_api_key(raw_key)
    assert raw_key not in {row.key_hash, row.key_prefix}

    listing = (await client.get("/v1/api-keys", headers=alice.headers)).json()
    assert [k["id"] for k in listing] == [body["id"]]
    assert "api_key" not in listing[0]


async def test_create_rejects_foreign_or_missing_secrets(
    client: httpx.AsyncClient, alice, bob, new_secret
) -> None:
    bobs = await new_secret(client, bob)
    mine = await new_secret(client, alice)
    foreign = await _create_key(client, alice, [mine["id"], bobs["id"]])
    assert foreign.status_code == 400
    missing = await _create_key(client, alice, [str(uuid.uuid4())])
    assert missing.status_code == 400
    empty = await _create_key(client, alice, [])
    assert empty.status_code == 422


async def test_create_rejects_past_expiry(
    client: httpx.AsyncClient, alice, new_secret
) -> None:
    secret = await new_secret(client, alice)
    past = (utcnow() - timedelta(minutes=1)).isoformat()
    response = await _create_key(client, alice, [secret["id"]], expires_at=past)
    assert response.status_code == 400


async def test_scope_enforcement(
    client: httpx.AsyncClient, alice, db: AsyncSession, new_secret
) -> None:
    in_scope = await new_secret(client, alice, "in")
    out_of_scope = await new_secret(client, alice, "out")
    raw_key = (await _create_key(client, alice, [in_scope["id"]])).json()["api_key"]
    key_hash = hash_api_key(raw_key)

    assert await is_key_allowed_for_secret(db, key_hash, uuid.UUID(in_scope["id"]))
    assert not await is_key_allowed_for_secret(
        db, key_hash, uuid.UUID(out_of_scope["id"])
    )
    assert not await is_key_allowed_for_secret(
        db, hash_api_key("cpk_wrong"), uuid.UUID(in_scope["id"])
    )


async def test_revoked_key_is_denied(
    client: httpx.AsyncClient, alice, bob, db: AsyncSession, new_secret
) -> None:
    secret = await new_secret(client, alice)
    created = (await _create_key(client, alice, [secret["id"]])).json()
    url = f"/v1/api-keys/{created['id']}"

    assert (await client.delete(url, headers=bob.headers)).status_code == 404
    assert (await client.delete(url, headers=alice.headers)).status_code == 204
    assert (await client.delete(url, headers=alice.headers)).status_code == 404
    assert (await client.get("/v1/api-keys", headers=alice.headers)).json() == []
    assert not await is_key_allowed_for_secret(
        db, hash_api_key(created["api_key"]), uuid.UUID(secret["id"])
    )


async def test_expired_key_is_denied(
    client: httpx.AsyncClient, alice, db: AsyncSession, new_secret
) -> None:
    secret = await new_secret(client, alice)
    created = (await _create_key(client, alice, [secret["id"]])).json()
    row = await db.get(ApiKey, uuid.UUID(created["id"]))
    row.expires_at = utcnow() - timedelta(seconds=1)
    await db.commit()
    assert not await is_key_allowed_for_secret(
        db, hash_api_key(created["api_key"]), uuid.UUID(secret["id"])
    )


async def test_deleting_secret_removes_it_from_scope(
    client: httpx.AsyncClient, alice, db: AsyncSession, new_secret
) -> None:
    secret = await new_secret(client, alice)
    raw_key = (await _create_key(client, alice, [secret["id"]])).json()["api_key"]
    await client.delete(f"/v1/secrets/{secret['id']}", headers=alice.headers)
    listing = (await client.get("/v1/api-keys", headers=alice.headers)).json()
    assert listing[0]["secret_ids"] == []
    assert not await is_key_allowed_for_secret(
        db, hash_api_key(raw_key), uuid.UUID(secret["id"])
    )
