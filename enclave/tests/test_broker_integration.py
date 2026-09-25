"""End to end: the enclave broker against the real control plane, in process.

The server app runs on a throwaway SQLite file with the mock attestation
issuer; the enclave talks to it through ``httpx.ASGITransport`` with real
attestation tokens (from the mock launcher), real request signatures, real
owner-signed envelopes sealed to the local KMS key and real grants. Tamper
tests edit the database directly, playing a compromised control plane.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from server_support import Account, create_account, mint_grant, post_api_key
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from carapace_crypto import ApiKey, Envelope, seal
from carapace_enclave.attestation import LauncherClient, TokenSource
from carapace_enclave.attestation.identity import BootIdentity
from carapace_enclave.attestation.token import ATTESTATION_AUDIENCE, AttestationToken
from carapace_enclave.broker import AUTH_FAILURES_PER_PEER_PER_MINUTE, BrokerError
from carapace_enclave.clock import TrustedClock
from carapace_enclave.egress import AgentRequest
from carapace_enclave.runtime import boot
from carapace_enclave.server import EnclaveServices
from carapace_enclave.server_client import ControlPlaneClient, ControlPlaneError
from carapace_enclave_mock import MOCK_KMS_KEY_VERSION, LocalRsaDecrypter, MockLauncher
from carapace_enclave_mock.launcher import MOCK_IMAGE_DIGEST
from carapace_server.apikeys.models import ApiKey as ApiKeyRow
from carapace_server.app import create_app
from carapace_server.config import MOCK_ATTESTATION_ISSUER, Settings
from carapace_server.db import create_engine, create_sessionmaker
from carapace_server.models import Base
from carapace_server.store.models import Secret

from .conftest import SECRET, SERVER_URL, FakeResolver, Upstream, make_executor

pytestmark = pytest.mark.anyio

POLICY: dict[str, Any] = {
    "v": 1,
    "hosts": [{"match": "exact", "value": "api.github.com"}],
    "schemes": ["https"],
    "methods": ["GET", "POST"],
    "inject": {
        "kind": "header",
        "name": "Authorization",
        "template": "Bearer {secret}",
    },
}
UPSTREAM_URL = "https://api.github.com/user"


@dataclass
class ControlPlane:
    """The server app and a way to reach it, as a user and as an enclave."""

    transport: httpx.ASGITransport
    user: httpx.AsyncClient
    sessionmaker: async_sessionmaker[AsyncSession]


@dataclass
class Enclave:
    services: EnclaveServices
    identity: BootIdentity
    tokens: TokenSource
    clock: TrustedClock
    upstream: Upstream


@pytest.fixture
async def control_plane(
    tmp_path: Path, mock_launcher: MockLauncher
) -> AsyncIterator[ControlPlane]:
    settings = Settings(
        mode="dev",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'server.db'}",
        public_url=SERVER_URL,
        bcrypt_rounds=4,
        rate_limit_enabled=False,
        attestation_issuer=MOCK_ATTESTATION_ISSUER,
        mock_attestation_public_key_pem=mock_launcher.public_pem,
        allowed_image_digests=[MOCK_IMAGE_DIGEST],
    )
    engine = create_engine(settings.database_url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app = create_app(settings)
    app.state.sessionmaker = create_sessionmaker(engine)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=SERVER_URL) as user:
        yield ControlPlane(transport, user, app.state.sessionmaker)
    await engine.dispose()


def _echo(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=b'{"login":"octocat"}')


async def _boot(
    control_plane: ControlPlane,
    mock_launcher: MockLauncher,
    decrypter: LocalRsaDecrypter,
    upstream: Upstream,
) -> Enclave:
    identity = BootIdentity.generate()
    clock = TrustedClock()
    tokens = TokenSource(
        LauncherClient(transport=mock_launcher.transport()),
        clock,
        nonce=identity.boot_id,
    )
    services = await boot(
        control_plane_url=SERVER_URL,
        identity=identity,
        tokens=tokens,
        clock=clock,
        decrypter=decrypter,
        executor=make_executor(upstream, FakeResolver()),
        control_plane_transport=control_plane.transport,
    )
    return Enclave(services, identity, tokens, clock, upstream)


@pytest.fixture
async def enclave(
    control_plane: ControlPlane,
    mock_launcher: MockLauncher,
    kms_decrypter: LocalRsaDecrypter,
) -> Enclave:
    return await _boot(control_plane, mock_launcher, kms_decrypter, Upstream(_echo))


def _envelope(
    account: Account,
    decrypter: LocalRsaDecrypter,
    *,
    secret_id: str,
    version: int = 1,
    policy: dict[str, Any] | None = None,
    kms_key_version: str = MOCK_KMS_KEY_VERSION,
) -> dict[str, Any]:
    return seal(
        decrypter.public_key_pem().encode("ascii"),
        secret_id,
        account.user_id,
        policy or POLICY,
        SECRET,
        owner_key=account.owner_key,
        version=version,
        kms_key_version=kms_key_version,
    ).to_dict()


async def _store_secret(
    control_plane: ControlPlane,
    account: Account,
    decrypter: LocalRsaDecrypter,
    **kwargs: Any,
) -> str:
    secret_id = str(uuid.uuid4())
    response = await control_plane.user.post(
        "/v1/secrets",
        json={
            "name": f"s-{secret_id[:8]}",
            "envelope": _envelope(account, decrypter, secret_id=secret_id, **kwargs),
        },
        headers=account.headers,
    )
    assert response.status_code == 201, response.text
    return secret_id


@dataclass
class Setup:
    account: Account
    secret_id: str
    api_key: ApiKey


@pytest.fixture
async def setup(control_plane: ControlPlane, kms_decrypter: LocalRsaDecrypter) -> Setup:
    account = await create_account(control_plane.user, "owner@example.com")
    secret_id = await _store_secret(control_plane, account, kms_decrypter)
    api_key, grant = mint_grant(account, {secret_id: 1})
    response = await post_api_key(control_plane.user, account, api_key, grant)
    assert response.status_code == 201, response.text
    return Setup(account, secret_id, api_key)


def _request(**overrides: Any) -> AgentRequest:
    fields: dict[str, Any] = {"method": "GET", "url": UPSTREAM_URL, "headers": []}
    fields.update(overrides)
    return AgentRequest(**fields)


async def _handle(enclave: Enclave, setup: Setup, **overrides: Any) -> Any:
    raw_key = overrides.pop("raw_key", setup.api_key.raw)
    secret_id = overrides.pop("secret_id", setup.secret_id)
    peer = overrides.pop("peer", "")
    return await enclave.services.broker.handle(
        raw_key, secret_id, _request(**overrides), peer=peer
    )


async def _refused(enclave: Enclave, setup: Setup, **overrides: Any) -> BrokerError:
    with pytest.raises(BrokerError) as info:
        await _handle(enclave, setup, **overrides)
    return info.value


async def _owner_receipts(control_plane: ControlPlane, account: Account) -> list:
    response = await control_plane.user.get("/v1/receipts", headers=account.headers)
    assert response.status_code == 200, response.text
    return response.json()["receipts"]


# -- the happy path -------------------------------------------------------------


async def test_request_is_brokered_and_receipted(
    control_plane: ControlPlane, enclave: Enclave, setup: Setup
) -> None:
    result = await _handle(enclave, setup)

    assert result.status == 200
    assert result.body == b'{"login":"octocat"}'
    (sent,) = enclave.upstream.requests
    assert sent.headers["authorization"] == f"Bearer {SECRET.decode()}"

    await enclave.services.receipts.flush()
    assert enclave.services.receipts.pending == 0
    (receipt,) = await _owner_receipts(control_plane, setup.account)
    assert receipt["boot_id"] == enclave.identity.boot_id
    assert receipt["seq"] == 0
    payload = receipt["payload"]
    assert payload["outcome"] == "ok"
    assert payload["secret_id"] == setup.secret_id
    assert payload["owner_id"] == setup.account.user_id
    assert payload["request"]["host"] == "api.github.com"
    assert payload["request"]["status"] == 200
    assert SECRET.decode() not in str(receipt)


async def test_receipt_chain_continues_across_uploads(
    control_plane: ControlPlane, enclave: Enclave, setup: Setup
) -> None:
    for _ in range(3):
        await _handle(enclave, setup)
        await enclave.services.receipts.flush()
    receipts = await _owner_receipts(control_plane, setup.account)
    assert sorted(r["seq"] for r in receipts) == [0, 1, 2]


async def test_egress_denial_is_receipted(
    control_plane: ControlPlane, enclave: Enclave, setup: Setup
) -> None:
    error = await _refused(enclave, setup, url="https://evil.example.net/")
    assert error.status == 403
    assert error.code.startswith("egress_denied:")
    assert enclave.upstream.requests == []

    await enclave.services.receipts.flush()
    (receipt,) = await _owner_receipts(control_plane, setup.account)
    assert receipt["payload"]["outcome"] == "denied"


async def test_dek_is_cached_across_requests(
    enclave: Enclave, setup: Setup, kms_decrypter: LocalRsaDecrypter, monkeypatch
) -> None:
    calls = []
    original = kms_decrypter.unwrap

    def counting(wrapped: bytes) -> bytes:
        calls.append(wrapped)
        return original(wrapped)

    monkeypatch.setattr(kms_decrypter, "unwrap", counting)
    await _handle(enclave, setup)
    await _handle(enclave, setup)
    assert len(calls) == 1


# -- the agent's key ------------------------------------------------------------


async def test_malformed_api_key_is_unauthorized(
    enclave: Enclave, setup: Setup
) -> None:
    error = await _refused(enclave, setup, raw_key="cpk_not-a-key")
    assert (error.status, error.code) == (401, "invalid_api_key")


async def test_unknown_api_key_is_forbidden(enclave: Enclave, setup: Setup) -> None:
    stranger = ApiKey.generate(setup.account.owner_key)
    error = await _refused(enclave, setup, raw_key=stranger.raw)
    assert (error.status, error.code) == (403, "forbidden")


async def test_secret_outside_the_grant_is_forbidden(
    control_plane: ControlPlane,
    enclave: Enclave,
    setup: Setup,
    kms_decrypter: LocalRsaDecrypter,
) -> None:
    other = await _store_secret(control_plane, setup.account, kms_decrypter)
    error = await _refused(enclave, setup, secret_id=other)
    assert error.status == 403
    assert enclave.upstream.requests == []


async def test_non_canonical_secret_id_is_rejected(
    enclave: Enclave, setup: Setup
) -> None:
    error = await _refused(enclave, setup, secret_id=setup.secret_id.upper())
    assert (error.status, error.code) == (400, "invalid_secret_id")


async def test_revoked_key_is_forbidden(
    control_plane: ControlPlane, enclave: Enclave, setup: Setup
) -> None:
    listed = await control_plane.user.get("/v1/api-keys", headers=setup.account.headers)
    (key,) = listed.json()
    response = await control_plane.user.post(
        f"/v1/api-keys/{key['id']}/revoke", headers=setup.account.headers
    )
    assert response.status_code == 204, response.text
    error = await _refused(enclave, setup)
    assert (error.status, error.code) == (403, "forbidden")


async def test_peer_is_throttled_after_repeated_refusals(
    enclave: Enclave, setup: Setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    stranger = ApiKey.generate(setup.account.owner_key)
    for _ in range(AUTH_FAILURES_PER_PEER_PER_MINUTE):
        error = await _refused(enclave, setup, raw_key=stranger.raw, peer="a")
        assert error.status == 403

    async def not_reached(*_args: Any, **_kwargs: Any) -> bytes:
        raise AssertionError("throttled peer must not reach the control plane")

    monkeypatch.setattr(ControlPlaneClient, "fetch_grant", not_reached)
    error = await _refused(enclave, setup, raw_key=stranger.raw, peer="a")
    assert (error.status, error.code) == (429, "rate_limited")
    # The address is throttled as a whole, valid key or not ...
    error = await _refused(enclave, setup, peer="a")
    assert error.status == 429
    monkeypatch.undo()
    # ... while another address is untouched.
    assert (await _handle(enclave, setup, peer="b")).status == 200


async def test_verified_requests_never_count_against_the_peer(
    enclave: Enclave, setup: Setup
) -> None:
    for _ in range(AUTH_FAILURES_PER_PEER_PER_MINUTE):
        error = await _refused(enclave, setup, url="https://evil.example/", peer="a")
        assert error.code.startswith("egress_denied:")
    assert (await _handle(enclave, setup, peer="a")).status == 200


# -- a lying control plane ------------------------------------------------------


async def test_bad_owner_signature_is_refused(
    control_plane: ControlPlane, enclave: Enclave, setup: Setup
) -> None:
    async with control_plane.sessionmaker() as db:
        secret = await db.get(Secret, uuid.UUID(setup.secret_id))
        assert secret is not None
        secret.policy_json = {
            **secret.policy_json,
            "hosts": [{"match": "exact", "value": "evil.example.net"}],
        }
        await db.commit()

    error = await _refused(enclave, setup, url="https://evil.example.net/")
    assert (error.status, error.code) == (502, "store_error")
    assert enclave.upstream.requests == []


async def test_forged_signature_bytes_are_refused(
    control_plane: ControlPlane, enclave: Enclave, setup: Setup
) -> None:
    async with control_plane.sessionmaker() as db:
        secret = await db.get(Secret, uuid.UUID(setup.secret_id))
        assert secret is not None
        secret.signature = bytes(64)
        await db.commit()

    error = await _refused(enclave, setup)
    assert (error.status, error.code) == (502, "store_error")


async def test_grant_bound_to_another_key_is_refused(
    control_plane: ControlPlane, enclave: Enclave, setup: Setup
) -> None:
    """The server hands key B's holder a grant that was signed for key A."""
    key_b, _ = mint_grant(setup.account, {setup.secret_id: 1})
    async with control_plane.sessionmaker() as db:
        await db.execute(
            update(ApiKeyRow)
            .where(ApiKeyRow.key_hash == setup.api_key.lookup_hash.hex())
            .values(key_hash=key_b.lookup_hash.hex())
        )
        await db.commit()

    error = await _refused(enclave, setup, raw_key=key_b.raw)
    assert (error.status, error.code) == (403, "forbidden")
    assert enclave.upstream.requests == []


async def test_grant_from_another_owner_key_is_refused(
    control_plane: ControlPlane, enclave: Enclave, setup: Setup
) -> None:
    """Served for this key: a valid grant, but from an owner key it does not name."""
    intruder = await create_account(control_plane.user, "intruder@example.com")
    _, forged = mint_grant(intruder, {setup.secret_id: 1})
    await _replace_grant(control_plane, setup.api_key, forged.to_dict())

    error = await _refused(enclave, setup)
    assert (error.status, error.code) == (403, "forbidden")


async def _replace_grant(
    control_plane: ControlPlane, api_key: ApiKey, wire: dict[str, Any]
) -> None:
    async with control_plane.sessionmaker() as db:
        await db.execute(
            update(ApiKeyRow)
            .where(ApiKeyRow.key_hash == api_key.lookup_hash.hex())
            .values(grant_json=wire, grant_iat=wire["iat"], grant_exp=wire["exp"])
        )
        await db.commit()


async def test_expired_grant_is_refused(
    control_plane: ControlPlane, enclave: Enclave, setup: Setup
) -> None:
    long_ago = int(time.time()) - 7200
    _, expired = mint_grant(
        setup.account,
        {setup.secret_id: 1},
        api_key=setup.api_key,
        now=long_ago,
        ttl_seconds=600,
    )
    await _replace_grant(control_plane, setup.api_key, expired.to_dict())

    error = await _refused(enclave, setup)
    assert (error.status, error.code) == (403, "forbidden")


async def test_grant_rollback_is_refused(
    control_plane: ControlPlane, enclave: Enclave, setup: Setup
) -> None:
    """After seeing a newer grant, the enclave will not accept the older one."""
    async with control_plane.sessionmaker() as db:
        row = (
            await db.execute(
                ApiKeyRow.__table__.select().where(
                    ApiKeyRow.key_hash == setup.api_key.lookup_hash.hex()
                )
            )
        ).one()
    older = dict(row.grant_json)
    _, newer = mint_grant(
        setup.account,
        {setup.secret_id: 1},
        api_key=setup.api_key,
        previous_iat=older["iat"],
        now=older["iat"] + 10,
    )
    await _replace_grant(control_plane, setup.api_key, newer.to_dict())
    await _handle(enclave, setup)

    await _replace_grant(control_plane, setup.api_key, older)
    error = await _refused(enclave, setup)
    assert (error.status, error.code) == (403, "forbidden")


async def test_envelope_rollback_is_refused(
    control_plane: ControlPlane,
    enclave: Enclave,
    setup: Setup,
    kms_decrypter: LocalRsaDecrypter,
) -> None:
    v2 = _envelope(setup.account, kms_decrypter, secret_id=setup.secret_id, version=2)
    response = await control_plane.user.patch(
        f"/v1/secrets/{setup.secret_id}",
        json={"envelope": v2},
        headers=setup.account.headers,
    )
    assert response.status_code == 200, response.text
    await _handle(enclave, setup)

    v1 = _envelope(setup.account, kms_decrypter, secret_id=setup.secret_id)
    async with control_plane.sessionmaker() as db:
        secret = await db.get(Secret, uuid.UUID(setup.secret_id))
        assert secret is not None
        old = Envelope.from_dict(v1)
        secret.version = old.version
        secret.signature = old.sig
        secret.wrapped_dek = old.wrapped
        secret.nonce = old.nonce
        secret.ciphertext = old.ct
        await db.commit()

    error = await _refused(enclave, setup)
    assert (error.status, error.code) == (502, "store_error")


async def test_min_version_in_grant_is_enforced(
    control_plane: ControlPlane, enclave: Enclave, setup: Setup
) -> None:
    _, demanding = mint_grant(
        setup.account, {setup.secret_id: 5}, api_key=setup.api_key
    )
    await _replace_grant(control_plane, setup.api_key, demanding.to_dict())
    error = await _refused(enclave, setup)
    assert (error.status, error.code) == (502, "store_error")


async def test_envelope_for_another_kms_key_is_refused(
    control_plane: ControlPlane,
    kms_decrypter: LocalRsaDecrypter,
    enclave: Enclave,
) -> None:
    account = await create_account(control_plane.user, "rotated@example.com")
    secret_id = await _store_secret(
        control_plane,
        account,
        kms_decrypter,
        kms_key_version=MOCK_KMS_KEY_VERSION.replace(
            "cryptoKeyVersions/1", "cryptoKeyVersions/2"
        ),
    )
    api_key, grant = mint_grant(account, {secret_id: 1})
    assert (await post_api_key(control_plane.user, account, api_key, grant)).is_success

    with pytest.raises(BrokerError) as info:
        await enclave.services.broker.handle(api_key.raw, secret_id, _request())
    assert (info.value.status, info.value.code) == (502, "store_error")


# -- attestation as seen by the control plane -----------------------------------


class _FixedTokens:
    """Hands the client one token regardless of the audience it asks for."""

    def __init__(self, token: AttestationToken) -> None:
        self._token = token

    def get(self, audience: str) -> AttestationToken:
        return self._token


def _client(
    control_plane: ControlPlane,
    identity: BootIdentity,
    tokens: Any,
    clock: TrustedClock,
) -> ControlPlaneClient:
    return ControlPlaneClient(
        base_url=SERVER_URL,
        tokens=tokens,
        identity=identity,
        clock=clock,
        transport=control_plane.transport,
    )


async def test_server_refuses_wrong_audience(
    control_plane: ControlPlane, enclave: Enclave
) -> None:
    """A token minted for ``/attestation`` cannot authenticate to the server."""
    token = enclave.tokens.get(ATTESTATION_AUDIENCE)
    client = _client(
        control_plane, enclave.identity, _FixedTokens(token), enclave.clock
    )
    with pytest.raises(ControlPlaneError) as info:
        await client.fetch_envelope(str(uuid.uuid4()))
    assert info.value.status == 401
    await client.aclose()


async def test_server_refuses_wrong_nonce(
    control_plane: ControlPlane,
    mock_launcher: MockLauncher,
    enclave: Enclave,
) -> None:
    """A registered boot's token, signed for by a different receipt key."""
    impostor = BootIdentity.generate()
    client = _client(control_plane, impostor, enclave.tokens, enclave.clock)
    with pytest.raises(ControlPlaneError) as info:
        await client.fetch_envelope(str(uuid.uuid4()))
    assert info.value.status == 401

    # And a boot the server never registered cannot register under
    # another boot's nonce either.
    with pytest.raises(ControlPlaneError) as info:
        await client.register_boot()
    assert info.value.status == 422
    await client.aclose()


async def test_unregistered_boot_is_refused(
    control_plane: ControlPlane, mock_launcher: MockLauncher
) -> None:
    identity = BootIdentity.generate()
    clock = TrustedClock()
    tokens = TokenSource(
        LauncherClient(transport=mock_launcher.transport()),
        clock,
        nonce=identity.boot_id,
    )
    client = _client(control_plane, identity, tokens, clock)
    with pytest.raises(ControlPlaneError) as info:
        await client.fetch_envelope(str(uuid.uuid4()))
    assert info.value.status == 403
    await client.aclose()


async def test_boot_fails_on_unapproved_image(
    control_plane: ControlPlane,
    mock_launcher: MockLauncher,
    kms_decrypter: LocalRsaDecrypter,
) -> None:
    mock_launcher.image_digest = "sha256:" + "11" * 32
    with pytest.raises(ControlPlaneError):
        await _boot(control_plane, mock_launcher, kms_decrypter, Upstream(_echo))
