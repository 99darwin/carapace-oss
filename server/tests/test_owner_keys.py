"""Owner public keys: registration, listing, retirement and isolation."""

import base64
import os
import uuid

import httpx
import pytest
from server_support import register_owner_key

from carapace_crypto import OwnerKey, b64_encode_std
from carapace_server.ownerkeys.service import MAX_OWNER_KEYS_PER_USER

pytestmark = pytest.mark.anyio


async def test_register_list_and_retire(client: httpx.AsyncClient, alice) -> None:
    second = OwnerKey.generate()
    response = await register_owner_key(client, alice.headers, second)
    assert response.status_code == 201
    body = response.json()
    assert body["public_key"] == b64_encode_std(second.public_key)
    assert body["fingerprint"] == second.fingerprint.hex()
    assert body["retired_at"] is None

    listing = (await client.get("/v1/owner-keys", headers=alice.headers)).json()
    assert [k["id"] for k in listing] == [alice.owner_key_id, body["id"]]

    url = f"/v1/owner-keys/{body['id']}/retire"
    retired = await client.post(url, headers=alice.headers)
    assert retired.status_code == 200
    first_retired_at = retired.json()["retired_at"]
    assert first_retired_at is not None
    again = await client.post(url, headers=alice.headers)
    assert again.json()["retired_at"] == first_retired_at


async def test_public_key_is_unique_across_users(
    client: httpx.AsyncClient, alice, bob
) -> None:
    mine = await register_owner_key(client, alice.headers, alice.owner_key)
    assert mine.status_code == 409
    theirs = await register_owner_key(client, bob.headers, alice.owner_key)
    assert theirs.status_code == 409


@pytest.mark.parametrize(
    "public_key",
    [
        base64.b64encode(os.urandom(31)).decode(),
        base64.b64encode(os.urandom(33)).decode(),
        base64.urlsafe_b64encode(b"\xfb" * 32).decode(),
        "not base64!",
    ],
    ids=["short", "long", "urlsafe", "garbage"],
)
async def test_rejects_malformed_public_keys(
    client: httpx.AsyncClient, alice, public_key: str
) -> None:
    response = await client.post(
        "/v1/owner-keys", json={"public_key": public_key}, headers=alice.headers
    )
    assert response.status_code == 422


async def test_isolation(client: httpx.AsyncClient, alice, bob) -> None:
    url = f"/v1/owner-keys/{alice.owner_key_id}/retire"
    assert (await client.post(url, headers=bob.headers)).status_code == 404
    missing = f"/v1/owner-keys/{uuid.uuid4()}/retire"
    assert (await client.post(missing, headers=alice.headers)).status_code == 404
    bobs = (await client.get("/v1/owner-keys", headers=bob.headers)).json()
    assert [k["id"] for k in bobs] == [bob.owner_key_id]


async def test_requires_auth(client: httpx.AsyncClient) -> None:
    assert (await client.get("/v1/owner-keys")).status_code == 401


# Encodings of small-order points: identity (y = 1), order 2 (y = p - 1),
# order 4 (y = 0), plus a non-canonical y >= p. OpenSSL would accept them
# and under each a fixed signature verifies over every message.
_FIELD_PRIME = 2**255 - 19
WEAK_PUBLIC_KEYS = [
    (1).to_bytes(32, "little"),
    (_FIELD_PRIME - 1).to_bytes(32, "little"),
    bytes(32),
    (_FIELD_PRIME + 5).to_bytes(32, "little"),
]


@pytest.mark.parametrize(
    "public_key", WEAK_PUBLIC_KEYS, ids=["identity", "order-2", "order-4", "y>=p"]
)
async def test_rejects_weak_public_keys(
    client: httpx.AsyncClient, alice, public_key: bytes
) -> None:
    response = await client.post(
        "/v1/owner-keys",
        json={"public_key": b64_encode_std(public_key)},
        headers=alice.headers,
    )
    assert response.status_code == 422


async def test_caps_keys_per_account_including_retired(
    client: httpx.AsyncClient, alice, bob
) -> None:
    # alice already has one key; retire it to show retired keys still count.
    retire = f"/v1/owner-keys/{alice.owner_key_id}/retire"
    assert (await client.post(retire, headers=alice.headers)).status_code == 200
    for _ in range(MAX_OWNER_KEYS_PER_USER - 1):
        response = await register_owner_key(client, alice.headers, OwnerKey.generate())
        assert response.status_code == 201
    over = await register_owner_key(client, alice.headers, OwnerKey.generate())
    assert over.status_code == 409
    assert "owner keys" in over.json()["detail"]
    other_user = await register_owner_key(client, bob.headers, OwnerKey.generate())
    assert other_user.status_code == 201
