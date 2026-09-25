"""Test helpers shared by the server tests.

A plain module rather than conftest, which ``--import-mode=importlib`` makes
unimportable; the root ``pyproject.toml`` puts this directory on
``pythonpath``. Only one copy is ever imported, so the cached test KMS key
is the same everywhere.
"""

import functools
import time
import uuid
from dataclasses import dataclass

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from carapace_crypto import ApiKey, Grant, OwnerKey, b64_encode_std, create_grant, seal

STRONG_PASSWORD = "Correct-Horse-9-Battery"  # noqa: S105


async def register(
    client: httpx.AsyncClient, email: str, password: str = STRONG_PASSWORD
) -> dict:
    response = await client.post(
        "/v1/auth/register", json={"email": email, "password": password}
    )
    assert response.status_code == 201, response.text
    return response.json()


DEFAULT_POLICY = {
    "v": 1,
    "hosts": [{"match": "exact", "value": "api.example.com"}],
    "schemes": ["https"],
}
KMS_KEY_VERSION = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
PLAINTEXT = b"ghp_example_token"


@functools.cache
def kms_private_key() -> rsa.RSAPrivateKey:
    """Stand-in for the Cloud KMS key; generated once per test session."""
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def kms_public_pem() -> bytes:
    return (
        kms_private_key()
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


@dataclass
class Account:
    user_id: str
    headers: dict[str, str]
    owner_key: OwnerKey
    owner_key_id: str


def make_envelope(
    account: Account,
    secret_id: str | None = None,
    policy: dict | None = None,
    version: int = 1,
    *,
    owner_id: str | None = None,
    owner_key: OwnerKey | None = None,
) -> dict:
    """A real owner-signed envelope, sealed to the test KMS key."""
    return seal(
        kms_public_pem(),
        secret_id or str(uuid.uuid4()),
        owner_id or account.user_id,
        policy if policy is not None else DEFAULT_POLICY,
        PLAINTEXT,
        owner_key=owner_key or account.owner_key,
        version=version,
        kms_key_version=KMS_KEY_VERSION,
    ).to_dict()


async def register_owner_key(
    client: httpx.AsyncClient, headers: dict[str, str], owner_key: OwnerKey
) -> httpx.Response:
    return await client.post(
        "/v1/owner-keys",
        json={"public_key": b64_encode_std(owner_key.public_key)},
        headers=headers,
    )


async def create_account(client: httpx.AsyncClient, email: str) -> Account:
    tokens = await register(client, email)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    owner_key = OwnerKey.generate()
    response = await register_owner_key(client, headers, owner_key)
    assert response.status_code == 201, response.text
    return Account(
        user_id=tokens["user_id"],
        headers=headers,
        owner_key=owner_key,
        owner_key_id=response.json()["id"],
    )


async def create_secret(
    client: httpx.AsyncClient, account: Account, name: str = "github"
) -> dict:
    response = await client.post(
        "/v1/secrets",
        json={"name": name, "envelope": make_envelope(account)},
        headers=account.headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


def mint_grant(
    account: Account,
    secrets: dict[str, int],
    *,
    api_key: ApiKey | None = None,
    owner_key: OwnerKey | None = None,
    previous_iat: int | None = None,
    now: int | None = None,
    ttl_seconds: int = 3600,
) -> tuple[ApiKey, Grant]:
    """What the CLI does: mint a key (unless given) and sign a grant for it."""
    owner_key = owner_key or account.owner_key
    api_key = api_key or ApiKey.generate(owner_key)
    grant = create_grant(
        owner_key,
        api_key,
        secrets,
        now=now if now is not None else int(time.time()),
        ttl_seconds=ttl_seconds,
        previous_iat=previous_iat,
    )
    return api_key, grant


async def post_api_key(
    client: httpx.AsyncClient,
    account: Account,
    api_key: ApiKey,
    grant: Grant | dict,
    name: str = "agent",
) -> httpx.Response:
    wire = grant.to_dict() if isinstance(grant, Grant) else grant
    return await client.post(
        "/v1/api-keys",
        json={"name": name, "lookup_hash": api_key.lookup_hash.hex(), "grant": wire},
        headers=account.headers,
    )
