"""Receipts, the control-plane client, the HTTPS app, TLS and entrypoint checks."""

from __future__ import annotations

import base64
import json
import socket
import ssl
import tempfile
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from carapace_enclave import __main__ as entrypoint
from carapace_enclave.attestation import TokenSource
from carapace_enclave.attestation.identity import BootIdentity
from carapace_enclave.attestation.token import (
    ATTESTATION_AUDIENCE,
    AttestationError,
    check_token,
)
from carapace_enclave.broker import BrokerError, canonical_secret_id
from carapace_enclave.clock import TrustedClock
from carapace_enclave.egress import AgentRequest, EgressResult, ReceiptMetadata
from carapace_enclave.receipts import (
    GENESIS_PREV_HASH,
    MAX_BATCH,
    ReceiptLog,
    ReceiptLogUnavailableError,
)
from carapace_enclave.runtime import ConfigurationError, EnclaveConfig
from carapace_enclave.server import EnclaveServices, create_app
from carapace_enclave.server_client import (
    MAX_RESPONSE_BYTES,
    ControlPlaneClient,
    ControlPlaneError,
    ControlPlaneNotFoundError,
    request_signing_bytes,
)
from carapace_enclave.tls import server_ssl_context
from carapace_enclave_mock import MOCK_KMS_KEY_VERSION
from carapace_server.internal.deps import (
    request_signing_bytes as server_request_signing_bytes,
)
from carapace_server.receipts.chain import receipt_hash, signed_bytes

from .conftest import BOOT_NONCE, SERVER_URL, WIF_AUDIENCE

pytestmark = pytest.mark.anyio

KMS_KEY = MOCK_KMS_KEY_VERSION


# -- receipts -------------------------------------------------------------------


class FakeUploader:
    def __init__(self, *failures: int | None) -> None:
        self.failures = list(failures)
        self.batches: list[list[dict[str, Any]]] = []

    async def upload_receipts(self, receipts: list[dict[str, Any]]) -> bytes:
        if self.failures:
            status = self.failures.pop(0)
            raise ControlPlaneError("upload failed", status)
        self.batches.append(list(receipts))
        return b"{}"


def _log(uploader: FakeUploader, **kwargs: Any) -> tuple[ReceiptLog, BootIdentity]:
    identity = BootIdentity.generate()
    return ReceiptLog(identity=identity, client=uploader, **kwargs), identity


def test_receipt_chain_matches_server_format() -> None:
    log, identity = _log(FakeUploader())
    first = log.append({"n": 1})
    second = log.append({"n": 2})

    assert first["seq"] == 0
    assert first["prev_hash"] == GENESIS_PREV_HASH
    message = signed_bytes(identity.boot_id, 0, GENESIS_PREV_HASH, {"n": 1})
    Ed25519PublicKey.from_public_bytes(identity.receipt_pubkey).verify(
        base64.b64decode(first["signature"]), message
    )
    assert second["seq"] == 1
    assert second["prev_hash"] == receipt_hash(message)


async def test_receipts_upload_in_order_and_batches() -> None:
    uploader = FakeUploader()
    log, _ = _log(uploader)
    for n in range(MAX_BATCH + 5):
        log.append({"n": n})
    await log.flush()
    assert [len(batch) for batch in uploader.batches] == [MAX_BATCH, 5]
    assert [r["seq"] for batch in uploader.batches for r in batch] == list(
        range(MAX_BATCH + 5)
    )
    assert log.pending == 0


async def test_transient_upload_failure_keeps_receipts() -> None:
    uploader = FakeUploader(503)
    log, _ = _log(uploader)
    log.append({"n": 0})
    with pytest.raises(ControlPlaneError):
        await log.flush()
    assert log.pending == 1
    log.check_available()
    await log.flush()
    assert log.pending == 0


@pytest.mark.parametrize("status", [409, 422])
async def test_rejected_chain_fails_closed(status: int) -> None:
    log, _ = _log(FakeUploader(status))
    log.append({"n": 0})
    with pytest.raises(ControlPlaneError):
        await log.flush()
    with pytest.raises(ReceiptLogUnavailableError):
        log.check_available()


def test_full_backlog_fails_closed() -> None:
    log, _ = _log(FakeUploader(), max_pending=2)
    log.append({})
    log.check_available()
    log.append({})
    with pytest.raises(ReceiptLogUnavailableError):
        log.check_available()


# -- control-plane client -------------------------------------------------------


def test_request_signing_matches_server() -> None:
    args = ("post", "/internal/keys/verify?x=1", 1_700_000_000, b'{"a":1}')
    assert request_signing_bytes(*args) == server_request_signing_bytes(*args)


def _client(
    tokens: TokenSource, clock: TrustedClock, handler: Any
) -> ControlPlaneClient:
    return ControlPlaneClient(
        base_url=SERVER_URL,
        tokens=tokens,
        identity=BootIdentity.generate(),
        clock=clock,
        transport=httpx.MockTransport(handler),
    )


async def test_client_signs_and_authenticates(
    tokens: TokenSource, clock: TrustedClock
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b'{"grant":{}}')

    client = _client(tokens, clock, handler)
    assert await client.fetch_grant(b"\x01" * 32, "s") == b'{"grant":{}}'
    (request,) = seen
    token = request.headers["authorization"].removeprefix("Bearer ")
    assert check_token(token, audience=SERVER_URL, nonce=BOOT_NONCE)
    timestamp = int(request.headers["x-carapace-timestamp"])
    message = server_request_signing_bytes(
        "POST", "/internal/keys/verify", timestamp, request.content
    )
    Ed25519PublicKey.from_public_bytes(client._identity.receipt_pubkey).verify(
        base64.b64decode(request.headers["x-carapace-signature"]), message
    )
    assert json.loads(request.content) == {"key_hash": "01" * 32, "secret_id": "s"}
    await client.aclose()


async def test_client_registration_is_unsigned(
    tokens: TokenSource, clock: TrustedClock
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201)

    client = _client(tokens, clock, handler)
    await client.register_boot()
    assert "x-carapace-signature" not in seen[0].headers
    await client.aclose()


async def test_client_errors_carry_status_not_body(
    tokens: TokenSource, clock: TrustedClock
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        status = 404 if "secrets" in request.url.path else 500
        return httpx.Response(status, content=b"leaky detail")

    client = _client(tokens, clock, handler)
    with pytest.raises(ControlPlaneNotFoundError):
        await client.fetch_envelope("00000000-0000-4000-8000-000000000000")
    with pytest.raises(ControlPlaneError) as info:
        await client.upload_receipts([])
    assert info.value.status == 500
    assert "leaky" not in str(info.value)
    await client.aclose()


async def test_client_caps_response_size(
    tokens: TokenSource, clock: TrustedClock
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))

    client = _client(tokens, clock, handler)
    with pytest.raises(ControlPlaneError, match="too large"):
        await client.upload_receipts([])
    await client.aclose()


async def test_client_unreachable(tokens: TokenSource, clock: TrustedClock) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client = _client(tokens, clock, handler)
    with pytest.raises(ControlPlaneError) as info:
        await client.upload_receipts([])
    assert info.value.status is None
    assert info.value.__context__ is None
    await client.aclose()


# -- the enclave HTTPS app ------------------------------------------------------


class FakeBroker:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[tuple[str, str, AgentRequest]] = []
        self.peers: list[str] = []

    async def handle(
        self, raw_key: str, secret_id: str, request: AgentRequest, *, peer: str = ""
    ) -> EgressResult:
        self.calls.append((raw_key, secret_id, request))
        self.peers.append(peer)
        if self.error is not None:
            raise self.error
        return EgressResult(
            status=201,
            headers=[("content-type", "application/json")],
            body=b'{"ok":true}',
            metadata=ReceiptMetadata(
                method=request.method,
                host="api.github.com",
                path_hash="0" * 64,
                bytes_out=0,
                bytes_in=11,
                redactions=0,
                status=201,
            ),
        )


def _app_client(tokens: TokenSource, broker: FakeBroker) -> httpx.AsyncClient:
    services = EnclaveServices(
        identity=BootIdentity.generate(),
        tokens=tokens,
        broker=broker,  # type: ignore[arg-type]
        receipts=None,  # type: ignore[arg-type]
        kms_public_key_pem="-----BEGIN PUBLIC KEY-----\n",
        kms_key_version=KMS_KEY,
    )
    app = create_app(services, background=False)
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://enclave"
    )


async def test_attestation_endpoint(tokens: TokenSource) -> None:
    async with _app_client(tokens, FakeBroker()) as client:
        response = await client.get("/attestation")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    token = check_token(body["token"], audience=ATTESTATION_AUDIENCE, nonce=BOOT_NONCE)
    assert token.raw == body["token"]
    assert body["kms_key_version"] == KMS_KEY
    assert set(body) == {
        "token",
        "boot_id",
        "tls_cert_pem",
        "receipt_pubkey",
        "kms_public_key_pem",
        "kms_key_version",
    }


async def test_attestation_endpoint_unavailable(tokens: TokenSource) -> None:
    def fail(audience: str) -> Any:
        raise AttestationError("launcher down")

    tokens.get = fail  # type: ignore[method-assign]
    async with _app_client(tokens, FakeBroker()) as client:
        response = await client.get("/attestation")
    assert response.status_code == 503
    assert response.json() == {"error": "attestation_unavailable"}


async def test_agent_request_round_trip(tokens: TokenSource) -> None:
    broker = FakeBroker()
    async with _app_client(tokens, broker) as client:
        response = await client.post(
            "/v1/request",
            headers={"Authorization": "Bearer cpk_x"},
            json={
                "secret_id": "sid",
                "method": "POST",
                "url": "https://api.github.com/x",
                "headers": [["accept", "application/json"]],
                "body": base64.b64encode(b"hi").decode(),
            },
        )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "status": 201,
        "headers": [["content-type", "application/json"]],
        "body": base64.b64encode(b'{"ok":true}').decode(),
    }
    ((raw_key, secret_id, request),) = broker.calls
    assert (raw_key, secret_id) == ("cpk_x", "sid")
    assert request.headers == [("accept", "application/json")]
    assert request.body == b"hi"
    assert broker.peers == ["127.0.0.1"]  # the ASGI transport's default client


@pytest.mark.parametrize(
    ("headers", "payload", "status", "code"),
    [
        ({}, {}, 401, "invalid_api_key"),
        ({"Authorization": "Basic x"}, {}, 401, "invalid_api_key"),
        ({"Authorization": "Bearer k"}, {"secret_id": "s"}, 400, "invalid_request"),
        (
            {"Authorization": "Bearer k"},
            {"secret_id": "s", "method": "GET", "url": "u", "extra": 1},
            400,
            "invalid_request",
        ),
        (
            {"Authorization": "Bearer k"},
            {"secret_id": "s", "method": "GET", "url": "u", "body": "not base64!"},
            400,
            "invalid_request",
        ),
        (
            {"Authorization": "Bearer k"},
            {"secret_id": "s", "method": "GET", "url": "u", "headers": [["a"]]},
            400,
            "invalid_request",
        ),
    ],
)
async def test_agent_request_rejects_bad_input(
    tokens: TokenSource,
    headers: dict[str, str],
    payload: dict[str, Any],
    status: int,
    code: str,
) -> None:
    broker = FakeBroker()
    async with _app_client(tokens, broker) as client:
        response = await client.post("/v1/request", headers=headers, json=payload)
    assert (response.status_code, response.json()) == (status, {"error": code})
    assert broker.calls == []


async def test_agent_request_too_large(tokens: TokenSource) -> None:
    async with _app_client(tokens, FakeBroker()) as client:
        response = await client.post(
            "/v1/request",
            headers={"Authorization": "Bearer k", "Content-Length": str(1 << 30)},
            content=b"{}",
        )
    assert response.status_code == 413


async def test_broker_refusal_is_passed_through(tokens: TokenSource) -> None:
    broker = FakeBroker(BrokerError(403, "forbidden"))
    async with _app_client(tokens, broker) as client:
        response = await client.post(
            "/v1/request",
            headers={"Authorization": "Bearer k"},
            json={"secret_id": "s", "method": "GET", "url": "u"},
        )
    assert (response.status_code, response.json()) == (403, {"error": "forbidden"})


async def test_agent_request_without_attestation_is_unavailable(
    tokens: TokenSource,
) -> None:
    broker = FakeBroker(AttestationError("launcher down"))
    async with _app_client(tokens, broker) as client:
        response = await client.post(
            "/v1/request",
            headers={"Authorization": "Bearer k"},
            json={"secret_id": "s", "method": "GET", "url": "u"},
        )
    assert response.status_code == 503
    assert response.json() == {"error": "attestation_unavailable"}


def test_canonical_secret_id() -> None:
    value = "0f8fad5b-d9cb-469f-a165-70867728950e"
    assert canonical_secret_id(value) == value
    for bad in (value.upper(), value.replace("-", ""), "x", None):
        with pytest.raises(BrokerError):
            canonical_secret_id(bad)


# -- TLS ------------------------------------------------------------------------


def test_tls_context_serves_the_boot_certificate() -> None:
    identity = BootIdentity.generate()
    server_context = server_ssl_context(identity)
    client_context = ssl.create_default_context(cadata=identity.tls_cert_pem)
    client_context.check_hostname = False

    left, right = socket.socketpair()
    with left, right:
        server_side = server_context.wrap_socket(
            left, server_side=True, do_handshake_on_connect=False
        )
        client_side = client_context.wrap_socket(right, do_handshake_on_connect=False)
        server_side.setblocking(False)
        client_side.setblocking(False)
        done = {"server": False, "client": False}
        for _ in range(100):
            for name, side in (("client", client_side), ("server", server_side)):
                if done[name]:
                    continue
                try:
                    side.do_handshake()
                    done[name] = True
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    pass
            if all(done.values()):
                break
        assert all(done.values())
        peer = client_side.getpeercert(binary_form=True)
        assert ssl.DER_cert_to_PEM_cert(peer).strip() == identity.tls_cert_pem.strip()


# -- configuration and entrypoint -----------------------------------------------

GOOD_ENV = {
    "CONTROL_PLANE_URL": "https://cp.example.com",
    "KMS_KEY_NAME": KMS_KEY,
    "WIF_AUDIENCE": WIF_AUDIENCE,
}


def test_config_from_env() -> None:
    config = EnclaveConfig.from_env(GOOD_ENV)
    assert config.control_plane_url == "https://cp.example.com"


@pytest.mark.parametrize(
    "change",
    [
        {"CONTROL_PLANE_URL": ""},
        {"CONTROL_PLANE_URL": "http://cp.example.com"},
        {"CONTROL_PLANE_URL": "https://user:pw@cp.example.com"},
        {"CONTROL_PLANE_URL": "https://cp.example.com/?a=1"},
        {"KMS_KEY_NAME": "projects/p/locations/l/keyRings/r/cryptoKeys/k"},
        {"WIF_AUDIENCE": ATTESTATION_AUDIENCE},
        {"WIF_AUDIENCE": "https://cp.example.com"},
    ],
)
def test_config_rejects(change: dict[str, str]) -> None:
    with pytest.raises(ConfigurationError):
        EnclaveConfig.from_env({**GOOD_ENV, **change})


def test_dev_config_allows_http() -> None:
    env = {**GOOD_ENV, "CONTROL_PLANE_URL": "http://localhost:8000"}
    EnclaveConfig.from_env(env, require_https=False)


def test_launcher_socket_is_required(tmp_path: Path) -> None:
    with pytest.raises(entrypoint.NoLauncherError):
        entrypoint.require_launcher_socket(str(tmp_path / "missing.sock"))
    plain = tmp_path / "file"
    plain.write_bytes(b"")
    with pytest.raises(entrypoint.NoLauncherError):
        entrypoint.require_launcher_socket(str(plain))


def test_launcher_socket_accepts_a_socket() -> None:
    # AF_UNIX paths are short on macOS, too short for pytest's tmp_path.
    with tempfile.TemporaryDirectory(dir="/tmp") as directory:
        path = f"{directory}/s"
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(path)
            entrypoint.require_launcher_socket(path)


def test_entrypoint_fails_hard_without_env(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    for name in GOOD_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(entrypoint, "configure_logging", lambda: None)
    assert entrypoint.run() == 1
    assert "ConfigurationError" in caplog.text


def test_entrypoint_fails_hard_without_launcher(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    for name, value in GOOD_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(entrypoint, "configure_logging", lambda: None)
    real = entrypoint.require_launcher_socket
    monkeypatch.setattr(
        entrypoint,
        "require_launcher_socket",
        lambda: real("/nonexistent/teeserver.sock"),
    )
    assert entrypoint.run() == 1
    assert "NoLauncherError" in caplog.text
