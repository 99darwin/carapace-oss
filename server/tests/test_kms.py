"""/v1/kms/public-key and the settings behind it."""

from collections.abc import AsyncIterator

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import ValidationError
from server_support import Account, create_account

from carapace_server.app import create_app
from carapace_server.config import Settings

pytestmark = pytest.mark.anyio

KEY_VERSION = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"


def _public_pem(bits: int) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return (
        key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


@pytest.fixture(scope="module")
def kms_pem() -> str:
    return _public_pem(3072)


@pytest.fixture
async def kms_client(
    settings: Settings, sessionmaker, kms_pem: str
) -> AsyncIterator[httpx.AsyncClient]:
    configured = settings.model_copy(
        update={"kms_public_key_pem": kms_pem, "kms_key_version": KEY_VERSION}
    )
    app = create_app(configured)
    app.state.sessionmaker = sessionmaker
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_serves_the_configured_key(kms_client, kms_pem: str) -> None:
    account: Account = await create_account(kms_client, "kms@example.com")
    response = await kms_client.get("/v1/kms/public-key", headers=account.headers)
    assert response.status_code == 200
    assert response.json() == {"public_key_pem": kms_pem, "key_version": KEY_VERSION}


async def test_requires_authentication(kms_client) -> None:
    response = await kms_client.get("/v1/kms/public-key")
    assert response.status_code == 401


async def test_unconfigured_is_404(client, alice: Account) -> None:
    response = await client.get("/v1/kms/public-key", headers=alice.headers)
    assert response.status_code == 404


def test_rejects_a_weak_key() -> None:
    with pytest.raises(ValidationError, match="between 3072 and 8192"):
        Settings(
            mode="dev",
            kms_public_key_pem=_public_pem(2048),
            kms_key_version=KEY_VERSION,
        )


def test_rejects_a_key_without_a_version(kms_pem: str) -> None:
    with pytest.raises(ValidationError, match="set together"):
        Settings(mode="dev", kms_public_key_pem=kms_pem)
