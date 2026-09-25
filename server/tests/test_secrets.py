"""Owner CRUD over sealed envelopes: shape checks and isolation."""

import base64
import os
import uuid

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from carapace_server.store.envelope import compute_aad_hash
from carapace_server.store.models import Secret

pytestmark = pytest.mark.anyio


async def test_create_and_read_round_trips_envelope(
    client: httpx.AsyncClient, alice, db: AsyncSession, envelope_factory
) -> None:
    envelope = envelope_factory(alice.user_id)
    response = await client.post(
        "/v1/secrets",
        json={"name": "github", "envelope": envelope},
        headers=alice.headers,
    )
    assert response.status_code == 201
    body = response.json()
    assert body["id"] == envelope["secret_id"]
    assert body["envelope"] == envelope
    assert body["aad_hash"] == compute_aad_hash(
        uuid.UUID(envelope["secret_id"]),
        uuid.UUID(alice.user_id),
        envelope["policy"],
    )

    fetched = await client.get(f"/v1/secrets/{body['id']}", headers=alice.headers)
    assert fetched.json()["envelope"] == envelope
    row = await db.get(Secret, uuid.UUID(body["id"]))
    assert row.ciphertext == base64.b64decode(envelope["ct"])


async def test_list_returns_metadata_only(
    client: httpx.AsyncClient, alice, new_secret
) -> None:
    await new_secret(client, alice, "b")
    await new_secret(client, alice, "a")
    listing = (await client.get("/v1/secrets", headers=alice.headers)).json()
    assert [s["name"] for s in listing] == ["a", "b"]
    assert all("envelope" not in s for s in listing)


def _b64(size: int) -> str:
    return base64.b64encode(os.urandom(size)).decode()


@pytest.mark.parametrize(
    "overrides",
    [
        {"v": 2},
        {"nonce": _b64(16)},
        {"wrapped": _b64(256)},
        {"wrapped": _b64(1024)},
        {"ct": _b64(8)},
        {"ct": "not base64!"},
        {"ct": base64.urlsafe_b64encode(b"\xfb" * 48).decode()},
        {"policy": {"limits": {"timeout_s": 1.5}}},
        {"policy": "not-an-object"},
        {"secret_id": "not-a-uuid"},
        {"extra": "field"},
    ],
    ids=[
        "version",
        "nonce-length",
        "wrapped-short",
        "wrapped-long",
        "ct-short",
        "ct-garbage",
        "ct-urlsafe",
        "policy-float",
        "policy-type",
        "secret-id",
        "extra",
    ],
)
async def test_create_rejects_malformed_envelopes(
    client: httpx.AsyncClient, alice, overrides: dict, envelope_factory
) -> None:
    envelope = envelope_factory(alice.user_id) | overrides
    response = await client.post(
        "/v1/secrets",
        json={"name": "x", "envelope": envelope},
        headers=alice.headers,
    )
    assert response.status_code == 422


async def test_create_rejects_envelope_for_another_owner(
    client: httpx.AsyncClient, alice, bob, envelope_factory
) -> None:
    response = await client.post(
        "/v1/secrets",
        json={"name": "x", "envelope": envelope_factory(bob.user_id)},
        headers=alice.headers,
    )
    assert response.status_code == 422


async def test_create_conflicts(
    client: httpx.AsyncClient, alice, bob, envelope_factory, new_secret
) -> None:
    first = await new_secret(client, alice, "dup")
    same_name = await client.post(
        "/v1/secrets",
        json={"name": "dup", "envelope": envelope_factory(alice.user_id)},
        headers=alice.headers,
    )
    assert same_name.status_code == 409
    stolen_id = envelope_factory(bob.user_id, secret_id=first["id"])
    same_id = await client.post(
        "/v1/secrets",
        json={"name": "other", "envelope": stolen_id},
        headers=bob.headers,
    )
    assert same_id.status_code == 409
    other_owner_same_name = await new_secret(client, bob, "dup")
    assert other_owner_same_name["name"] == "dup"


async def test_owner_isolation(
    client: httpx.AsyncClient, alice, bob, new_secret
) -> None:
    secret = await new_secret(client, alice)
    url = f"/v1/secrets/{secret['id']}"
    assert (await client.get(url, headers=bob.headers)).status_code == 404
    rename = await client.patch(url, json={"name": "mine"}, headers=bob.headers)
    assert rename.status_code == 404
    assert (await client.delete(url, headers=bob.headers)).status_code == 404
    assert (await client.get("/v1/secrets", headers=bob.headers)).json() == []
    assert (await client.get(url, headers=alice.headers)).status_code == 200


async def test_requires_auth(client: httpx.AsyncClient) -> None:
    assert (await client.get("/v1/secrets")).status_code == 401


async def test_patch_rename(client: httpx.AsyncClient, alice, new_secret) -> None:
    secret = await new_secret(client, alice)
    response = await client.patch(
        f"/v1/secrets/{secret['id']}", json={"name": "renamed"}, headers=alice.headers
    )
    assert response.status_code == 200
    assert response.json()["name"] == "renamed"
    assert response.json()["envelope"] == secret["envelope"]


async def test_patch_policy_alone_is_rejected(
    client: httpx.AsyncClient, alice, new_secret
) -> None:
    secret = await new_secret(client, alice)
    response = await client.patch(
        f"/v1/secrets/{secret['id']}",
        json={"policy": {"v": 1, "hosts": []}},
        headers=alice.headers,
    )
    assert response.status_code == 422


async def test_patch_empty_is_rejected(
    client: httpx.AsyncClient, alice, new_secret
) -> None:
    secret = await new_secret(client, alice)
    response = await client.patch(
        f"/v1/secrets/{secret['id']}", json={}, headers=alice.headers
    )
    assert response.status_code == 422


async def test_patch_replaces_envelope(
    client: httpx.AsyncClient, alice, envelope_factory, new_secret
) -> None:
    secret = await new_secret(client, alice)
    policy = {"v": 1, "hosts": [{"match": "exact", "value": "api.other.com"}]}
    envelope = envelope_factory(alice.user_id, secret_id=secret["id"], policy=policy)
    response = await client.patch(
        f"/v1/secrets/{secret['id']}",
        json={"envelope": envelope},
        headers=alice.headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["policy"] == policy
    assert body["envelope"] == envelope
    assert body["aad_hash"] != secret["aad_hash"]


async def test_patch_rejects_envelope_bound_elsewhere(
    client: httpx.AsyncClient, alice, envelope_factory, new_secret
) -> None:
    secret = await new_secret(client, alice)
    envelope = envelope_factory(alice.user_id)  # different secret_id
    response = await client.patch(
        f"/v1/secrets/{secret['id']}",
        json={"envelope": envelope},
        headers=alice.headers,
    )
    assert response.status_code == 422


async def test_delete(client: httpx.AsyncClient, alice, new_secret) -> None:
    secret = await new_secret(client, alice)
    url = f"/v1/secrets/{secret['id']}"
    assert (await client.delete(url, headers=alice.headers)).status_code == 204
    assert (await client.get(url, headers=alice.headers)).status_code == 404
