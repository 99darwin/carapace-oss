"""Passkey ceremonies against a software ES256 authenticator."""

import base64
import hashlib
import json
import secrets
import struct
from dataclasses import dataclass, field

import cbor2
import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from carapace_server.config import Settings

pytestmark = pytest.mark.anyio

FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04
FLAG_ATTESTED_DATA = 0x40
COSE_EC2_P256_ES256 = {1: 2, 3: -7, -1: 1}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass
class SoftwareAuthenticator:
    rp_id: str
    origin: str
    key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    credential_id: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    sign_count: int = 0
    user_verified: bool = True

    @property
    def _user_flags(self) -> int:
        verified = FLAG_USER_VERIFIED if self.user_verified else 0
        return FLAG_USER_PRESENT | verified

    def _client_data(self, kind: str, challenge: str, origin: str | None) -> bytes:
        data = {"type": kind, "challenge": challenge, "origin": origin or self.origin}
        return json.dumps(data).encode()

    def _auth_data(self, flags: int, attested: bytes = b"") -> bytes:
        rp_hash = hashlib.sha256(self.rp_id.encode()).digest()
        return rp_hash + bytes([flags]) + struct.pack(">I", self.sign_count) + attested

    def create(self, options: dict, origin: str | None = None) -> dict:
        numbers = self.key.public_key().public_numbers()
        cose_key = {
            **COSE_EC2_P256_ES256,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
        attested = (
            bytes(16)
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + cbor2.dumps(cose_key)
        )
        auth_data = self._auth_data(self._user_flags | FLAG_ATTESTED_DATA, attested)
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        return {
            "id": _b64url(self.credential_id),
            "rawId": _b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64url(client_data),
                "attestationObject": _b64url(attestation),
                "transports": ["internal"],
            },
        }

    def get(self, options: dict, credential_id: bytes | None = None) -> dict:
        self.sign_count += 1
        auth_data = self._auth_data(self._user_flags)
        client_data = self._client_data("webauthn.get", options["challenge"], None)
        signed = auth_data + hashlib.sha256(client_data).digest()
        signature = self.key.sign(signed, ec.ECDSA(hashes.SHA256()))
        raw_id = credential_id or self.credential_id
        return {
            "id": _b64url(raw_id),
            "rawId": _b64url(raw_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64url(client_data),
                "authenticatorData": _b64url(auth_data),
                "signature": _b64url(signature),
            },
        }


@pytest.fixture
def authenticator(settings: Settings) -> SoftwareAuthenticator:
    return SoftwareAuthenticator(
        rp_id=settings.webauthn_rp_id, origin=settings.webauthn_origin
    )


async def _options(client: httpx.AsyncClient, path: str, email: str) -> dict:
    response = await client.post(path, json={"email": email})
    assert response.status_code == 200, response.text
    return response.json()["options"]


async def _register(
    client: httpx.AsyncClient, authenticator: SoftwareAuthenticator, email: str
) -> httpx.Response:
    options = await _options(client, "/v1/auth/passkey/register/options", email)
    return await client.post(
        "/v1/auth/passkey/register",
        json={"email": email, "credential": authenticator.create(options)},
    )


async def _login(
    client: httpx.AsyncClient, credential_factory, email: str
) -> httpx.Response:
    options = await _options(client, "/v1/auth/passkey/login/options", email)
    return await client.post(
        "/v1/auth/passkey/login",
        json={"email": email, "credential": credential_factory(options)},
    )


async def test_register_and_login(
    client: httpx.AsyncClient, authenticator: SoftwareAuthenticator
) -> None:
    registered = await _register(client, authenticator, "pk@example.com")
    assert registered.status_code == 201, registered.text

    first = await _login(client, authenticator.get, "pk@example.com")
    assert first.status_code == 200, first.text
    second = await _login(client, authenticator.get, "pk@example.com")
    assert second.status_code == 200

    me = await client.get(
        "/v1/auth/me",
        headers={"Authorization": f"Bearer {second.json()['access_token']}"},
    )
    assert me.json()["has_passkey"] is True
    assert me.json()["has_password"] is False


async def test_registration_rejects_wrong_origin(
    client: httpx.AsyncClient, authenticator: SoftwareAuthenticator
) -> None:
    email = "origin@example.com"
    options = await _options(client, "/v1/auth/passkey/register/options", email)
    credential = authenticator.create(options, origin="https://evil.example")
    response = await client.post(
        "/v1/auth/passkey/register", json={"email": email, "credential": credential}
    )
    assert response.status_code == 400


async def test_options_require_user_verification(client: httpx.AsyncClient) -> None:
    creation = await _options(client, "/v1/auth/passkey/register/options", "uv@x.io")
    request = await _options(client, "/v1/auth/passkey/login/options", "uv@x.io")
    assert creation["authenticatorSelection"]["userVerification"] == "required"
    assert request["userVerification"] == "required"


async def test_registration_requires_user_verification(
    client: httpx.AsyncClient, authenticator: SoftwareAuthenticator
) -> None:
    authenticator.user_verified = False
    response = await _register(client, authenticator, "presence@example.com")
    assert response.status_code == 400


async def test_login_requires_user_verification(
    client: httpx.AsyncClient, authenticator: SoftwareAuthenticator
) -> None:
    """A stolen authenticator (user present, not verified) must not sign in."""
    email = "stolen@example.com"
    assert (await _register(client, authenticator, email)).status_code == 201
    authenticator.user_verified = False
    response = await _login(client, authenticator.get, email)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


async def test_registration_challenge_is_single_use(
    client: httpx.AsyncClient, authenticator: SoftwareAuthenticator
) -> None:
    email = "once@example.com"
    options = await _options(client, "/v1/auth/passkey/register/options", email)
    credential = authenticator.create(options)
    body = {"email": email, "credential": credential}
    first = await client.post("/v1/auth/passkey/register", json=body)
    assert first.status_code == 201
    replay = await client.post("/v1/auth/passkey/register", json=body)
    assert replay.status_code == 400


async def test_register_options_rejects_existing_account(
    client: httpx.AsyncClient, register_user
) -> None:
    await register_user(client, "taken@example.com")
    response = await client.post(
        "/v1/auth/passkey/register/options", json={"email": "taken@example.com"}
    )
    assert response.status_code == 400


async def test_login_rejects_other_key(
    client: httpx.AsyncClient, authenticator: SoftwareAuthenticator, settings: Settings
) -> None:
    await _register(client, authenticator, "victim@example.com")
    attacker = SoftwareAuthenticator(
        rp_id=settings.webauthn_rp_id,
        origin=settings.webauthn_origin,
        credential_id=authenticator.credential_id,
    )
    response = await _login(client, attacker.get, "victim@example.com")
    assert response.status_code == 401


async def test_login_rejects_replayed_assertion(
    client: httpx.AsyncClient, authenticator: SoftwareAuthenticator
) -> None:
    email = "replay@example.com"
    await _register(client, authenticator, email)
    options = await _options(client, "/v1/auth/passkey/login/options", email)
    body = {"email": email, "credential": authenticator.get(options)}
    assert (await client.post("/v1/auth/passkey/login", json=body)).status_code == 200
    replay = await client.post("/v1/auth/passkey/login", json=body)
    assert replay.status_code == 401


async def test_login_options_do_not_reveal_accounts(
    client: httpx.AsyncClient,
) -> None:
    first = await _options(client, "/v1/auth/passkey/login/options", "ghost@x.io")
    second = await _options(client, "/v1/auth/passkey/login/options", "ghost@x.io")
    other = await _options(client, "/v1/auth/passkey/login/options", "other@x.io")
    decoy = first["allowCredentials"][0]["id"]
    assert len(_b64url_decode(decoy)) == 32
    assert second["allowCredentials"][0]["id"] == decoy
    assert other["allowCredentials"][0]["id"] != decoy


async def test_login_unknown_account_fails(
    client: httpx.AsyncClient, authenticator: SoftwareAuthenticator
) -> None:
    response = await _login(client, authenticator.get, "ghost@example.com")
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"
