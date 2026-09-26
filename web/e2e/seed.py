"""Seed a migrated database for the Playwright smoke test.

Everything a user creates goes through the in-process app, sealed and signed
with ``carapace_crypto`` exactly as the CLI would. Boots and receipts come
from an enclave, so they are inserted directly with a real receipt chain and
a self-signed stand-in attestation token.

Usage: ``python seed.py <sqlite database url>``. Test data only.
"""

from __future__ import annotations

import asyncio
import sys
import time
import uuid

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from carapace_crypto import ApiKey, OwnerKey, b64_encode_std, create_grant, seal
from carapace_server.app import create_app
from carapace_server.config import Settings
from carapace_server.db import create_engine, create_sessionmaker
from carapace_server.receipts.chain import (
    GENESIS_PREV_HASH,
    receipt_hash,
    signed_bytes,
)
from carapace_server.receipts.models import EnclaveBoot, Receipt

EMAIL = "e2e@example.com"
PASSWORD = "Correct-Horse-9-Battery"  # noqa: S105 - throwaway test account
SECRET_NAME = "github"  # noqa: S105 - a display name
API_KEY_NAME = "ci-agent"
POLICY = {
    "v": 1,
    "hosts": [{"match": "exact", "value": "api.github.com"}],
    "schemes": ["https"],
}
IMAGE_DIGEST = "sha256:" + "ab" * 32
BOOT_ID = "cd" * 32
RECEIPTS = 3


def _rsa_key(bits: int) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


async def _post(client: httpx.AsyncClient, path: str, **kwargs) -> dict:
    response = await client.post(path, **kwargs)
    if response.status_code != 201:
        raise SystemExit(f"{path}: {response.status_code} {response.text}")
    return response.json()


async def _seed_via_api(client: httpx.AsyncClient) -> tuple[str, str]:
    tokens = await _post(
        client, "/v1/auth/register", json={"email": EMAIL, "password": PASSWORD}
    )
    user_id = tokens["user_id"]
    client.headers["Authorization"] = f"Bearer {tokens['access_token']}"
    owner_key = OwnerKey.generate()
    public_key = b64_encode_std(owner_key.public_key)
    await _post(client, "/v1/owner-keys", json={"public_key": public_key})

    secret_id = str(uuid.uuid4())
    envelope = seal(
        _pem(_rsa_key(3072)),
        secret_id,
        user_id,
        POLICY,
        b"not-a-real-token",
        owner_key=owner_key,
        version=1,
    )
    await _post(
        client,
        "/v1/secrets",
        json={"name": SECRET_NAME, "envelope": envelope.to_dict()},
    )
    api_key = ApiKey.generate(owner_key)
    grant = create_grant(owner_key, api_key, {secret_id: 1}, now=int(time.time()))
    await _post(
        client,
        "/v1/api-keys",
        json={
            "name": API_KEY_NAME,
            "lookup_hash": api_key.lookup_hash.hex(),
            "grant": grant.to_dict(),
        },
    )
    return user_id, secret_id


def _attestation_token() -> str:
    now = int(time.time())
    claims = {
        "iss": "mock://local",
        "aud": "carapace-attestation",
        "iat": now,
        "exp": now + 3600,
        "eat_nonce": BOOT_ID,
        "hwmodel": "GCP_AMD_SEV",
        "swname": "CONFIDENTIAL_SPACE",
        "dbgstat": "disabled-since-boot",
        "secboot": True,
        "submods": {"container": {"image_digest": IMAGE_DIGEST}},
    }
    return jwt.encode(claims, _rsa_key(2048), algorithm="RS256")


def _boot_and_receipts(user_id: str, secret_id: str) -> list[object]:
    receipt_key = Ed25519PrivateKey.generate()
    public = receipt_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    rows: list[object] = [
        EnclaveBoot(
            boot_id=BOOT_ID,
            attestation_token=_attestation_token(),
            receipt_pubkey=public,
            tls_cert_pem="(seeded, no certificate)",
            image_digest=IMAGE_DIGEST,
        )
    ]
    prev_hash = GENESIS_PREV_HASH
    for seq in range(RECEIPTS):
        payload = {
            "owner_id": user_id,
            "secret_id": secret_id,
            "method": "GET",
            "host": "api.github.com",
            "status": 200,
        }
        message = signed_bytes(BOOT_ID, seq, prev_hash, payload)
        rows.append(
            Receipt(
                boot_id=BOOT_ID,
                seq=seq,
                prev_hash=prev_hash,
                hash=receipt_hash(message),
                payload=payload,
                signature=receipt_key.sign(message),
                secret_id=uuid.UUID(secret_id),
                owner_id=uuid.UUID(user_id),
            )
        )
        prev_hash = receipt_hash(message)
    return rows


async def main(database_url: str) -> None:
    settings = Settings(mode="dev", database_url=database_url, rate_limit_enabled=False)
    engine = create_engine(database_url)
    sessionmaker = create_sessionmaker(engine)
    app = create_app(settings)
    app.state.sessionmaker = sessionmaker
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://seed"
        ) as client:
            user_id, secret_id = await _seed_via_api(client)
        async with sessionmaker() as db:
            db.add_all(_boot_and_receipts(user_id, secret_id))
            await db.commit()
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
