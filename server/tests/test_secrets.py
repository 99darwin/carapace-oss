"""Owner CRUD over owner-signed envelopes: validation, versions, isolation."""

import base64
import os
import uuid

import httpx
import pytest
from server_support import PLAINTEXT, kms_private_key
from sqlalchemy.ext.asyncio import AsyncSession

from carapace_crypto import (
    Envelope,
    OwnerKey,
    open_with_dek_unwrapper,
    rsa_oaep_unwrapper,
)
from carapace_server.store.models import Secret

pytestmark = pytest.mark.anyio


async def test_create_and_read_round_trips_signed_envelope(
    client: httpx.AsyncClient,
    alice,
    db: AsyncSession,
    envelope_factory,
) -> None:
    envelope = envelope_factory(alice, version=7)
    response = await client.post(
        "/v1/secrets",
        json={"name": "github", "envelope": envelope},
        headers=alice.headers,
    )
    assert response.status_code == 201
    body = response.json()
    assert body["id"] == envelope["secret_id"]
    assert body["envelope"] == envelope
    assert body["version"] == 7
    assert body["owner_fingerprint"] == alice.owner_key.fingerprint.hex()
    assert "aad_hash" not in body

    fetched = await client.get(f"/v1/secrets/{body['id']}", headers=alice.headers)
    stored = Envelope.from_dict(fetched.json()["envelope"])
    # What the server rebuilds from its columns still verifies and decrypts,
    # so it is byte for byte what the owner signed.
    plaintext, _ = open_with_dek_unwrapper(
        stored,
        rsa_oaep_unwrapper(kms_private_key()),
        expected_secret_id=envelope["secret_id"],
        expected_owner_pk=alice.owner_key.public_key,
        min_version=7,
    )
    assert plaintext == PLAINTEXT
    row = await db.get(Secret, uuid.UUID(body["id"]))
    assert row is not None
    assert row.ciphertext == base64.b64decode(envelope["ct"])
    assert row.signature == base64.b64decode(envelope["sig"])


async def test_list_returns_metadata_only(
    client: httpx.AsyncClient, alice, new_secret
) -> None:
    await new_secret(client, alice, "b")
    await new_secret(client, alice, "a")
    listing = (await client.get("/v1/secrets", headers=alice.headers)).json()
    assert [s["name"] for s in listing] == ["a", "b"]
    assert all("envelope" not in s for s in listing)
    assert {s["owner_fingerprint"] for s in listing} == {
        alice.owner_key.fingerprint.hex()
    }


def _b64(size: int) -> str:
    return base64.b64encode(os.urandom(size)).decode()


@pytest.mark.parametrize(
    "overrides",
    [
        {"v": 2},
        {"version": 0},
        {"version": True},
        {"version": 2},
        {"nonce": _b64(16)},
        {"wrapped": _b64(256)},
        {"ct": _b64(8)},
        {"ct": "not base64!"},
        {"ct": base64.urlsafe_b64encode(b"\xfb" * 48).decode()},
        {"policy": {"limits": {"timeout_s": 1.5}}},
        {"policy": "not-an-object"},
        {"policy": {"v": 1, "hosts": []}},
        {"secret_id": "not-a-uuid"},
        {"secret_id": str(uuid.uuid4())},
        {"owner_pk": _b64(31)},
        {"owner_pk": _b64(32)},
        {"sig": _b64(64)},
        {"sig": _b64(63)},
        {"extra": "field"},
    ],
    ids=[
        "format-version",
        "version-zero",
        "version-bool",
        "version-edited",
        "nonce-length",
        "wrapped-short",
        "ct-short",
        "ct-garbage",
        "ct-urlsafe",
        "policy-float",
        "policy-type",
        "policy-edited",
        "secret-id-garbage",
        "secret-id-edited",
        "owner-pk-length",
        "owner-pk-swapped",
        "sig-forged",
        "sig-length",
        "extra",
    ],
)
async def test_create_rejects_malformed_or_tampered_envelopes(
    client: httpx.AsyncClient, alice, overrides: dict, envelope_factory
) -> None:
    envelope = envelope_factory(alice) | overrides
    response = await client.post(
        "/v1/secrets",
        json={"name": "x", "envelope": envelope},
        headers=alice.headers,
    )
    assert response.status_code == 422


async def test_create_rejects_missing_signature(
    client: httpx.AsyncClient, alice, envelope_factory
) -> None:
    envelope = envelope_factory(alice)
    del envelope["sig"]
    response = await client.post(
        "/v1/secrets",
        json={"name": "x", "envelope": envelope},
        headers=alice.headers,
    )
    assert response.status_code == 422


async def test_create_rejects_non_canonical_ids(
    client: httpx.AsyncClient, alice, envelope_factory
) -> None:
    """Validly signed, but the rebuilt envelope would not match the signature."""
    upper_id = str(uuid.uuid4()).upper()
    envelope = envelope_factory(alice, secret_id=upper_id)
    response = await client.post(
        "/v1/secrets",
        json={"name": "x", "envelope": envelope},
        headers=alice.headers,
    )
    assert response.status_code == 422


async def test_create_rejects_oversized_policy(
    client: httpx.AsyncClient, alice, envelope_factory
) -> None:
    policy = {"v": 1, "note": "x" * (17 * 1024)}
    response = await client.post(
        "/v1/secrets",
        json={"name": "x", "envelope": envelope_factory(alice, policy=policy)},
        headers=alice.headers,
    )
    assert response.status_code == 422


async def test_create_rejects_envelope_for_another_owner(
    client: httpx.AsyncClient, alice, bob, envelope_factory
) -> None:
    response = await client.post(
        "/v1/secrets",
        json={"name": "x", "envelope": envelope_factory(alice, owner_id=bob.user_id)},
        headers=alice.headers,
    )
    assert response.status_code == 422


async def test_create_rejects_unknown_owner_key(
    client: httpx.AsyncClient, alice, envelope_factory
) -> None:
    envelope = envelope_factory(alice, owner_key=OwnerKey.generate())
    response = await client.post(
        "/v1/secrets",
        json={"name": "x", "envelope": envelope},
        headers=alice.headers,
    )
    assert response.status_code == 422
    assert "owner key" in response.json()["detail"]


async def test_create_rejects_another_users_owner_key(
    client: httpx.AsyncClient, alice, bob, envelope_factory
) -> None:
    """Bob's registered key is not Alice's, even on an envelope naming Alice."""
    envelope = envelope_factory(alice, owner_key=bob.owner_key)
    response = await client.post(
        "/v1/secrets",
        json={"name": "x", "envelope": envelope},
        headers=alice.headers,
    )
    assert response.status_code == 422


async def test_create_rejects_retired_owner_key(
    client: httpx.AsyncClient, alice, envelope_factory
) -> None:
    retire = f"/v1/owner-keys/{alice.owner_key_id}/retire"
    assert (await client.post(retire, headers=alice.headers)).status_code == 200
    response = await client.post(
        "/v1/secrets",
        json={"name": "x", "envelope": envelope_factory(alice)},
        headers=alice.headers,
    )
    assert response.status_code == 422


async def test_create_conflicts(
    client: httpx.AsyncClient, alice, bob, envelope_factory, new_secret
) -> None:
    first = await new_secret(client, alice, "dup")
    same_name = await client.post(
        "/v1/secrets",
        json={"name": "dup", "envelope": envelope_factory(alice)},
        headers=alice.headers,
    )
    assert same_name.status_code == 409
    taken_id = envelope_factory(bob, secret_id=first["id"])
    same_id = await client.post(
        "/v1/secrets",
        json={"name": "other", "envelope": taken_id},
        headers=bob.headers,
    )
    assert same_id.status_code == 409
    other_owner_same_name = await new_secret(client, bob, "dup")
    assert other_owner_same_name["name"] == "dup"


async def test_owner_isolation(
    client: httpx.AsyncClient, alice, bob, envelope_factory, new_secret
) -> None:
    secret = await new_secret(client, alice)
    url = f"/v1/secrets/{secret['id']}"
    assert (await client.get(url, headers=bob.headers)).status_code == 404
    rename = await client.patch(url, json={"name": "mine"}, headers=bob.headers)
    assert rename.status_code == 404
    replace = await client.patch(
        url,
        json={"envelope": envelope_factory(bob, secret_id=secret["id"], version=9)},
        headers=bob.headers,
    )
    assert replace.status_code == 404
    assert (await client.delete(url, headers=bob.headers)).status_code == 404
    assert (await client.get("/v1/secrets", headers=bob.headers)).json() == []
    kept = await client.get(url, headers=alice.headers)
    assert kept.json()["envelope"] == secret["envelope"]


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


async def test_patch_rename_conflict(
    client: httpx.AsyncClient, alice, new_secret
) -> None:
    await new_secret(client, alice, "taken")
    secret = await new_secret(client, alice, "free")
    response = await client.patch(
        f"/v1/secrets/{secret['id']}", json={"name": "taken"}, headers=alice.headers
    )
    assert response.status_code == 409


@pytest.mark.parametrize(
    "body",
    [{}, {"policy": {"v": 1, "hosts": []}}],
    ids=["empty", "policy-alone"],
)
async def test_patch_rejects_bodies_without_changes(
    client: httpx.AsyncClient, alice, new_secret, body: dict
) -> None:
    secret = await new_secret(client, alice)
    response = await client.patch(
        f"/v1/secrets/{secret['id']}", json=body, headers=alice.headers
    )
    assert response.status_code == 422


async def test_patch_replaces_envelope_with_higher_version(
    client: httpx.AsyncClient, alice, envelope_factory, new_secret
) -> None:
    secret = await new_secret(client, alice)
    policy = {"v": 1, "hosts": [{"match": "exact", "value": "api.other.com"}]}
    envelope = envelope_factory(alice, secret_id=secret["id"], policy=policy, version=2)
    response = await client.patch(
        f"/v1/secrets/{secret['id']}",
        json={"envelope": envelope, "name": "rotated"},
        headers=alice.headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["policy"] == policy
    assert body["envelope"] == envelope
    assert body["version"] == 2
    assert body["name"] == "rotated"


@pytest.mark.parametrize("stale_version", [5, 4], ids=["same", "lower"])
async def test_patch_rejects_non_increasing_version(
    client: httpx.AsyncClient, alice, envelope_factory, stale_version: int
) -> None:
    current = envelope_factory(alice, version=5)
    created = await client.post(
        "/v1/secrets",
        json={"name": "github", "envelope": current},
        headers=alice.headers,
    )
    assert created.status_code == 201
    url = f"/v1/secrets/{current['secret_id']}"
    stale = envelope_factory(
        alice, secret_id=current["secret_id"], version=stale_version
    )
    response = await client.patch(
        url, json={"envelope": stale, "name": "ignored"}, headers=alice.headers
    )
    assert response.status_code == 409
    kept = (await client.get(url, headers=alice.headers)).json()
    assert kept["name"] == "github"
    assert kept["envelope"] == current


async def test_patch_rejects_envelope_under_unknown_owner_key(
    client: httpx.AsyncClient, alice, envelope_factory, new_secret
) -> None:
    secret = await new_secret(client, alice)
    envelope = envelope_factory(
        alice, secret_id=secret["id"], version=2, owner_key=OwnerKey.generate()
    )
    response = await client.patch(
        f"/v1/secrets/{secret['id']}",
        json={"envelope": envelope},
        headers=alice.headers,
    )
    assert response.status_code == 422


async def test_patch_rejects_envelope_bound_elsewhere(
    client: httpx.AsyncClient, alice, envelope_factory, new_secret
) -> None:
    secret = await new_secret(client, alice)
    envelope = envelope_factory(alice, version=2)  # a different secret_id
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
