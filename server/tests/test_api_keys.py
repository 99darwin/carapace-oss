"""API keys: client-minted keys, owner-signed grants, re-grant and revoke."""

import time
import uuid

import httpx
import pytest
from server_support import mint_grant, post_api_key, register_owner_key
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from carapace_crypto import OwnerKey
from carapace_server.apikeys.models import ApiKey, api_key_secrets
from carapace_server.apikeys.service import find_grant

pytestmark = pytest.mark.anyio


async def _registered_key(client: httpx.AsyncClient, account, secret_ids: list[str]):
    """Mint, grant and register a key; return ``(api_key, grant, body)``."""
    api_key, grant = mint_grant(account, {sid: 1 for sid in secret_ids})
    response = await post_api_key(client, account, api_key, grant)
    assert response.status_code == 201, response.text
    return api_key, grant, response.json()


async def test_create_stores_lookup_hash_and_grant_only(
    client: httpx.AsyncClient, alice, db: AsyncSession, new_secret
) -> None:
    secret = await new_secret(client, alice)
    api_key, grant = mint_grant(alice, {secret["id"]: 1})
    response = await post_api_key(client, alice, api_key, grant)
    assert response.status_code == 201
    body = response.json()
    assert api_key.raw not in response.text
    assert "api_key" not in body
    fingerprint_hex = alice.owner_key.fingerprint.hex()
    assert body["key_prefix"] == "cpk_" + fingerprint_hex[:8]
    assert api_key.raw.startswith(body["key_prefix"])
    assert body["owner_fingerprint"] == fingerprint_hex
    assert body["secret_ids"] == [secret["id"]]
    assert body["grant"] == grant.to_dict()
    assert (body["grant_iat"], body["grant_exp"]) == (grant.iat, grant.exp)

    row = await db.scalar(select(ApiKey).where(ApiKey.id == uuid.UUID(body["id"])))
    assert row is not None
    assert row.key_hash == api_key.lookup_hash.hex()

    listing = await client.get("/v1/api-keys", headers=alice.headers)
    assert api_key.raw not in listing.text
    assert [k["id"] for k in listing.json()] == [body["id"]]


async def test_find_grant_returns_current_grant_for_known_keys_only(
    client: httpx.AsyncClient, alice, db: AsyncSession, new_secret
) -> None:
    secret = await new_secret(client, alice)
    api_key, grant, _ = await _registered_key(client, alice, [secret["id"]])
    lookup = api_key.lookup_hash.hex()

    assert await find_grant(db, lookup) == grant.to_dict()
    assert await find_grant(db, "0" * 64) is None

    row = await db.scalar(select(ApiKey).where(ApiKey.key_hash == lookup))
    assert row is not None
    assert row.last_used_at is not None


async def test_find_grant_returns_expired_grants(
    client: httpx.AsyncClient, alice, db: AsyncSession, new_secret
) -> None:
    secret = await new_secret(client, alice)
    api_key, _, _ = await _registered_key(client, alice, [secret["id"]])
    lookup = api_key.lookup_hash.hex()
    await db.execute(
        update(ApiKey)
        .where(ApiKey.key_hash == lookup)
        .values(grant_exp=int(time.time()) - 1)
    )
    await db.commit()
    # Expiry is the enclave's call, from the signed ``exp``.
    assert await find_grant(db, lookup) is not None


async def test_create_rejects_secrets_the_user_does_not_own(
    client: httpx.AsyncClient, alice, bob, new_secret
) -> None:
    bobs = await new_secret(client, bob)
    mine = await new_secret(client, alice)
    for secrets in ({bobs["id"]: 1}, {mine["id"]: 1, bobs["id"]: 1}):
        api_key, grant = mint_grant(alice, secrets)
        response = await post_api_key(client, alice, api_key, grant)
        assert response.status_code == 400
    missing_key, missing_grant = mint_grant(alice, {str(uuid.uuid4()): 1})
    response = await post_api_key(client, alice, missing_key, missing_grant)
    assert response.status_code == 400


async def test_create_rejects_grant_signed_by_another_users_key(
    client: httpx.AsyncClient, alice, bob, new_secret
) -> None:
    secret = await new_secret(client, alice)
    api_key, grant = mint_grant(alice, {secret["id"]: 1}, owner_key=bob.owner_key)
    response = await post_api_key(client, alice, api_key, grant)
    assert response.status_code == 400


async def test_create_rejects_unregistered_owner_key(
    client: httpx.AsyncClient, alice, new_secret
) -> None:
    secret = await new_secret(client, alice)
    api_key, grant = mint_grant(alice, {secret["id"]: 1}, owner_key=OwnerKey.generate())
    response = await post_api_key(client, alice, api_key, grant)
    assert response.status_code == 400


async def test_create_rejects_retired_owner_key(
    client: httpx.AsyncClient, alice, new_secret
) -> None:
    secret = await new_secret(client, alice)
    retired = OwnerKey.generate()
    registered = await register_owner_key(client, alice.headers, retired)
    retire = f"/v1/owner-keys/{registered.json()['id']}/retire"
    assert (await client.post(retire, headers=alice.headers)).status_code == 200
    api_key, grant = mint_grant(alice, {secret["id"]: 1}, owner_key=retired)
    response = await post_api_key(client, alice, api_key, grant)
    assert response.status_code == 400


@pytest.mark.parametrize(
    "tamper",
    ["sig", "secrets", "iat", "shape"],
)
async def test_create_rejects_bad_grants(
    client: httpx.AsyncClient, alice, new_secret, tamper: str
) -> None:
    secret = await new_secret(client, alice)
    other = await new_secret(client, alice, "other")
    api_key, grant = mint_grant(alice, {secret["id"]: 1})
    wire = grant.to_dict()
    if tamper == "sig":
        _, foreign = mint_grant(alice, {secret["id"]: 1})
        wire["sig"] = foreign.to_dict()["sig"]
    elif tamper == "secrets":
        wire["secrets"] = {secret["id"]: 1, other["id"]: 1}
    elif tamper == "iat":
        wire["iat"] += 1
    else:
        wire["v"] = 2
    response = await post_api_key(client, alice, api_key, wire)
    assert response.status_code == 400


async def test_create_rejects_expired_and_future_grants(
    client: httpx.AsyncClient, alice, new_secret
) -> None:
    secret = await new_secret(client, alice)
    now = int(time.time())
    expired_key, expired = mint_grant(
        alice, {secret["id"]: 1}, now=now - 7200, ttl_seconds=3600
    )
    response = await post_api_key(client, alice, expired_key, expired)
    assert response.status_code == 400
    future_key, future = mint_grant(alice, {secret["id"]: 1}, now=now + 3600)
    response = await post_api_key(client, alice, future_key, future)
    assert response.status_code == 400


async def test_create_rejects_empty_grant(client: httpx.AsyncClient, alice) -> None:
    api_key, grant = mint_grant(alice, {})
    response = await post_api_key(client, alice, api_key, grant)
    assert response.status_code == 400


async def test_create_rejects_non_canonical_secret_ids(
    client: httpx.AsyncClient, alice, new_secret
) -> None:
    secret = await new_secret(client, alice)
    api_key, grant = mint_grant(alice, {secret["id"].upper(): 1})
    response = await post_api_key(client, alice, api_key, grant)
    assert response.status_code == 400


async def test_create_rejects_malformed_lookup_hash(
    client: httpx.AsyncClient, alice, new_secret
) -> None:
    secret = await new_secret(client, alice)
    api_key, grant = mint_grant(alice, {secret["id"]: 1})
    for lookup_hash in ("ab" * 31, "zz" * 32, api_key.lookup_hash.hex().upper()):
        response = await client.post(
            "/v1/api-keys",
            json={"name": "x", "lookup_hash": lookup_hash, "grant": grant.to_dict()},
            headers=alice.headers,
        )
        assert response.status_code == 422


async def test_duplicate_lookup_hash_conflicts(
    client: httpx.AsyncClient, alice, new_secret
) -> None:
    secret = await new_secret(client, alice)
    api_key, grant, _ = await _registered_key(client, alice, [secret["id"]])
    _, again = mint_grant(alice, {secret["id"]: 1}, api_key=api_key)
    response = await post_api_key(client, alice, api_key, again, name="dup")
    assert response.status_code == 409


async def test_put_grant_requires_increasing_iat(
    client: httpx.AsyncClient, alice, db: AsyncSession, new_secret
) -> None:
    first = await new_secret(client, alice, "first")
    second = await new_secret(client, alice, "second")
    api_key, grant, body = await _registered_key(client, alice, [first["id"]])
    url = f"/v1/api-keys/{body['id']}/grant"

    _, newer = mint_grant(
        alice, {second["id"]: 3}, api_key=api_key, previous_iat=grant.iat
    )
    response = await client.put(
        url, json={"grant": newer.to_dict()}, headers=alice.headers
    )
    assert response.status_code == 200
    assert response.json()["secret_ids"] == [second["id"]]
    assert response.json()["grant_iat"] == newer.iat
    assert await find_grant(db, api_key.lookup_hash.hex()) == newer.to_dict()

    for iat in (newer.iat, newer.iat - 1):
        _, stale = mint_grant(alice, {first["id"]: 1}, api_key=api_key, now=iat)
        response = await client.put(
            url, json={"grant": stale.to_dict()}, headers=alice.headers
        )
        assert response.status_code == 409
    kept = (await client.get("/v1/api-keys", headers=alice.headers)).json()
    assert kept[0]["grant"] == newer.to_dict()


async def test_put_grant_rejects_a_different_key_or_owner(
    client: httpx.AsyncClient, alice, new_secret
) -> None:
    secret = await new_secret(client, alice)
    api_key, grant, body = await _registered_key(client, alice, [secret["id"]])
    url = f"/v1/api-keys/{body['id']}/grant"

    _, other_key_grant = mint_grant(alice, {secret["id"]: 1}, previous_iat=grant.iat)
    response = await client.put(
        url, json={"grant": other_key_grant.to_dict()}, headers=alice.headers
    )
    assert response.status_code == 400

    second_owner_key = OwnerKey.generate()
    registered = await register_owner_key(client, alice.headers, second_owner_key)
    assert registered.status_code == 201
    _, other_owner_grant = mint_grant(
        alice,
        {secret["id"]: 1},
        owner_key=second_owner_key,
        previous_iat=grant.iat,
    )
    response = await client.put(
        url, json={"grant": other_owner_grant.to_dict()}, headers=alice.headers
    )
    assert response.status_code == 400


async def test_put_grant_rejects_foreign_secrets(
    client: httpx.AsyncClient, alice, bob, new_secret
) -> None:
    mine = await new_secret(client, alice)
    bobs = await new_secret(client, bob)
    api_key, grant, body = await _registered_key(client, alice, [mine["id"]])
    _, widened = mint_grant(
        alice, {mine["id"]: 1, bobs["id"]: 1}, api_key=api_key, previous_iat=grant.iat
    )
    response = await client.put(
        f"/v1/api-keys/{body['id']}/grant",
        json={"grant": widened.to_dict()},
        headers=alice.headers,
    )
    assert response.status_code == 400


async def test_other_users_cannot_touch_keys(
    client: httpx.AsyncClient, alice, bob, new_secret
) -> None:
    secret = await new_secret(client, alice)
    api_key, grant, body = await _registered_key(client, alice, [secret["id"]])
    _, newer = mint_grant(
        alice, {secret["id"]: 1}, api_key=api_key, previous_iat=grant.iat
    )
    put = await client.put(
        f"/v1/api-keys/{body['id']}/grant",
        json={"grant": newer.to_dict()},
        headers=bob.headers,
    )
    assert put.status_code == 404
    revoke = await client.post(f"/v1/api-keys/{body['id']}/revoke", headers=bob.headers)
    assert revoke.status_code == 404
    listing = await client.get("/v1/api-keys", headers=bob.headers)
    assert listing.json() == []
    assert grant.to_dict()["key_bind"] not in listing.text
    missing = await client.post(
        f"/v1/api-keys/{uuid.uuid4()}/revoke", headers=alice.headers
    )
    assert missing.status_code == 404


async def test_revoke_without_tombstone(
    client: httpx.AsyncClient, alice, db: AsyncSession, new_secret
) -> None:
    secret = await new_secret(client, alice)
    api_key, grant, body = await _registered_key(client, alice, [secret["id"]])
    url = f"/v1/api-keys/{body['id']}/revoke"
    assert (await client.post(url, headers=alice.headers)).status_code == 204
    assert (await client.post(url, headers=alice.headers)).status_code == 404
    # Without a tombstone the last real grant is all there is to serve; the
    # enclave only learns of the revocation when that grant expires.
    assert await find_grant(db, api_key.lookup_hash.hex()) == grant.to_dict()
    assert (await client.get("/v1/api-keys", headers=alice.headers)).json() == []
    _, newer = mint_grant(
        alice, {secret["id"]: 1}, api_key=api_key, previous_iat=grant.iat
    )
    put = await client.put(
        f"/v1/api-keys/{body['id']}/grant",
        json={"grant": newer.to_dict()},
        headers=alice.headers,
    )
    assert put.status_code == 404


async def test_revoke_with_tombstone(
    client: httpx.AsyncClient, alice, db: AsyncSession, new_secret
) -> None:
    secret = await new_secret(client, alice)
    api_key, grant, body = await _registered_key(client, alice, [secret["id"]])
    _, tombstone = mint_grant(alice, {}, api_key=api_key, previous_iat=grant.iat)
    response = await client.post(
        f"/v1/api-keys/{body['id']}/revoke",
        json={"grant": tombstone.to_dict()},
        headers=alice.headers,
    )
    assert response.status_code == 204

    row = await db.scalar(select(ApiKey).where(ApiKey.id == uuid.UUID(body["id"])))
    assert row is not None
    assert row.revoked_at is not None
    assert row.grant_json == tombstone.to_dict()
    assert row.grant_iat == tombstone.iat
    scope = await db.scalars(
        select(api_key_secrets.c.secret_id).where(
            api_key_secrets.c.api_key_id == row.id
        )
    )
    assert scope.all() == []
    # Served as-is so the enclave's monotonic cache records the revocation.
    assert await find_grant(db, api_key.lookup_hash.hex()) == tombstone.to_dict()


async def test_revoke_rejects_bad_tombstones(
    client: httpx.AsyncClient, alice, new_secret
) -> None:
    secret = await new_secret(client, alice)
    api_key, grant, body = await _registered_key(client, alice, [secret["id"]])
    url = f"/v1/api-keys/{body['id']}/revoke"

    _, not_empty = mint_grant(
        alice, {secret["id"]: 1}, api_key=api_key, previous_iat=grant.iat
    )
    response = await client.post(
        url, json={"grant": not_empty.to_dict()}, headers=alice.headers
    )
    assert response.status_code == 400

    _, stale = mint_grant(alice, {}, api_key=api_key, now=grant.iat)
    response = await client.post(
        url, json={"grant": stale.to_dict()}, headers=alice.headers
    )
    assert response.status_code == 409

    _, other_key = mint_grant(alice, {}, previous_iat=grant.iat)
    response = await client.post(
        url, json={"grant": other_key.to_dict()}, headers=alice.headers
    )
    assert response.status_code == 400

    # None of the rejected tombstones revoked the key.
    listing = (await client.get("/v1/api-keys", headers=alice.headers)).json()
    assert [k["id"] for k in listing] == [body["id"]]


async def test_tombstone_may_be_signed_by_retired_owner_key(
    client: httpx.AsyncClient, alice, new_secret
) -> None:
    secret = await new_secret(client, alice)
    api_key, grant, body = await _registered_key(client, alice, [secret["id"]])
    retire = f"/v1/owner-keys/{alice.owner_key_id}/retire"
    assert (await client.post(retire, headers=alice.headers)).status_code == 200

    _, newer = mint_grant(
        alice, {secret["id"]: 1}, api_key=api_key, previous_iat=grant.iat
    )
    put = await client.put(
        f"/v1/api-keys/{body['id']}/grant",
        json={"grant": newer.to_dict()},
        headers=alice.headers,
    )
    assert put.status_code == 400

    _, tombstone = mint_grant(alice, {}, api_key=api_key, previous_iat=grant.iat)
    response = await client.post(
        f"/v1/api-keys/{body['id']}/revoke",
        json={"grant": tombstone.to_dict()},
        headers=alice.headers,
    )
    assert response.status_code == 204


async def test_deleting_a_secret_removes_it_from_scope(
    client: httpx.AsyncClient, alice, new_secret
) -> None:
    secret = await new_secret(client, alice)
    _, _, body = await _registered_key(client, alice, [secret["id"]])
    delete = await client.delete(f"/v1/secrets/{secret['id']}", headers=alice.headers)
    assert delete.status_code == 204
    listing = (await client.get("/v1/api-keys", headers=alice.headers)).json()
    assert listing[0]["id"] == body["id"]
    assert listing[0]["secret_ids"] == []


async def test_requires_auth(client: httpx.AsyncClient) -> None:
    assert (await client.get("/v1/api-keys")).status_code == 401
