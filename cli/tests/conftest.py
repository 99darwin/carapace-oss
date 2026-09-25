"""A real server and a real TLS enclave on loopback sockets, in process.

One background thread runs an asyncio loop hosting both uvicorn servers:
the control plane over plain HTTP (loopback only, which the CLI allows) and
the enclave over TLS with its boot key, exactly as ``runtime.serve`` does.
The enclave boots against the server over the socket with mock attestation
tokens and a local KMS key. Upstream calls go to a recording mock
transport; nothing leaves the machine.

Tests drive the synchronous CLI and SDK from the test thread and use
:meth:`Stack.run` for anything that must happen on the loop (database
edits, receipt flushes).
"""

from __future__ import annotations

import asyncio
import io
import socket
import ssl
import sys
import threading
from collections.abc import Callable, Coroutine, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

import httpx
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa

from carapace_cli.main import main
from carapace_enclave.attestation import LauncherClient, TokenSource
from carapace_enclave.attestation.identity import BootIdentity
from carapace_enclave.clock import TrustedClock
from carapace_enclave.egress import EgressExecutor, URLFilter
from carapace_enclave.runtime import boot
from carapace_enclave.server import EnclaveServices
from carapace_enclave.server import create_app as create_enclave
from carapace_enclave.tls import server_ssl_context
from carapace_enclave_mock import MOCK_KMS_KEY_VERSION, LocalRsaDecrypter, MockLauncher
from carapace_enclave_mock.launcher import MOCK_IMAGE_DIGEST
from carapace_server.app import create_app as create_server
from carapace_server.config import MOCK_ATTESTATION_ISSUER, Settings
from carapace_server.db import create_engine, create_sessionmaker
from carapace_server.models import Base

T = TypeVar("T")
PUBLIC_IP = "93.184.216.34"
PASSWORD = "Correct-Horse-9-Battery"
STARTUP_TIMEOUT_SECONDS = 20.0


class Upstream:
    """Records what the enclave sends upstream and answers via ``handler``."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.handler: Callable[[httpx.Request], httpx.Response] = lambda _: (
            httpx.Response(200, content=b'{"login":"octocat"}')
        )

    def factory(self) -> httpx.AsyncBaseTransport:
        def record(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            response = self.handler(request)
            # Hand back an unread stream, as a real transport would.
            return httpx.Response(
                response.status_code, headers=response.headers, stream=response.stream
            )

        return httpx.MockTransport(record)


async def _public_resolver(host: str, port: int) -> list[str]:
    return [PUBLIC_IP]


@dataclass
class Stack:
    loop: asyncio.AbstractEventLoop
    server_url: str
    enclave_url: str
    server_settings: Settings
    server_app: Any
    sessionmaker: Any
    services: EnclaveServices
    identity: BootIdentity
    launcher: MockLauncher
    upstream: Upstream
    config_dir: Path
    mock_key_path: Path
    stdin: list[bytes] = field(default_factory=list)

    def run(self, coro: Coroutine[Any, Any, T]) -> T:
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(
            STARTUP_TIMEOUT_SECONDS
        )

    def flush_receipts(self) -> None:
        self.run(self.services.receipts.flush())

    def cli(
        self, *argv: str, stdin: bytes = b"", config_dir: Path | None = None
    ) -> tuple[int, str, str]:
        """Run ``carapace`` with piped stdin; returns (code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        original = sys.stdin
        sys.stdin = io.TextIOWrapper(io.BytesIO(stdin), encoding="utf-8")
        try:
            code = main(
                ["--config-dir", str(config_dir or self.config_dir), *argv],
                out=out,
                err=err,
            )
        finally:
            sys.stdin = original
        return code, out.getvalue(), err.getvalue()

    def verify_args(self) -> list[str]:
        return [
            "verify",
            "--enclave",
            self.enclave_url,
            "--allow-digest",
            MOCK_IMAGE_DIGEST,
            "--insecure-mock",
            "--mock-issuer-key",
            str(self.mock_key_path),
        ]


def _bound_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    return sock


async def _start(server: uvicorn.Server, sock: socket.socket) -> asyncio.Task[None]:
    task = asyncio.create_task(server.serve(sockets=[sock]))
    while not server.started:
        if task.done():
            task.result()
        await asyncio.sleep(0.01)
    return task


def _uvicorn(app: Any, **kwargs: Any) -> uvicorn.Server:
    config = uvicorn.Config(
        app,
        lifespan="off",
        log_config=None,
        access_log=False,
        http="h11",
        loop="asyncio",
        **kwargs,
    )
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
    return server


@pytest.fixture(scope="session")
def kms_decrypter() -> LocalRsaDecrypter:
    return LocalRsaDecrypter.generate()


@pytest.fixture(scope="session")
def launcher_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def stack(
    tmp_path: Path, kms_decrypter: LocalRsaDecrypter, launcher_key: rsa.RSAPrivateKey
) -> Iterator[Stack]:
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    server_sock, enclave_sock = _bound_socket(), _bound_socket()
    server_url = f"http://127.0.0.1:{server_sock.getsockname()[1]}"
    enclave_url = f"https://127.0.0.1:{enclave_sock.getsockname()[1]}"
    launcher = MockLauncher(signing_key=launcher_key)
    mock_key_path = tmp_path / "mock-issuer.pem"
    mock_key_path.write_text(launcher.public_pem)
    settings = Settings(
        mode="dev",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'server.db'}",
        public_url=server_url,
        bcrypt_rounds=4,
        rate_limit_enabled=False,
        attestation_issuer=MOCK_ATTESTATION_ISSUER,
        mock_attestation_public_key_pem=launcher.public_pem,
        allowed_image_digests=[MOCK_IMAGE_DIGEST],
        kms_public_key_pem=kms_decrypter.public_key_pem(),
        kms_key_version=MOCK_KMS_KEY_VERSION,
    )
    upstream = Upstream()
    servers: list[tuple[uvicorn.Server, asyncio.Task[None]]] = []

    async def start() -> Stack:
        engine = create_engine(settings.database_url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        app = create_server(settings)
        app.state.sessionmaker = create_sessionmaker(engine)
        control = _uvicorn(app)
        servers.append((control, await _start(control, server_sock)))

        identity = BootIdentity.generate()
        clock = TrustedClock()
        tokens = TokenSource(
            LauncherClient(transport=launcher.transport()),
            clock,
            nonce=identity.boot_id,
        )
        services = await boot(
            control_plane_url=server_url,
            identity=identity,
            tokens=tokens,
            clock=clock,
            decrypter=kms_decrypter,
            executor=EgressExecutor(
                url_filter=URLFilter(_public_resolver),
                transport_factory=upstream.factory,
            ),
        )
        context = server_ssl_context(identity)

        def ssl_factory(_config: object, _default: object) -> ssl.SSLContext:
            return context

        enclave = _uvicorn(
            create_enclave(services, background=False),
            ssl_context_factory=ssl_factory,
            proxy_headers=False,
        )
        servers.append((enclave, await _start(enclave, enclave_sock)))
        return Stack(
            loop=loop,
            server_url=server_url,
            enclave_url=enclave_url,
            server_settings=settings,
            server_app=app,
            sessionmaker=app.state.sessionmaker,
            services=services,
            identity=identity,
            launcher=launcher,
            upstream=upstream,
            config_dir=tmp_path / "config",
            mock_key_path=mock_key_path,
        )

    async def stop() -> None:
        for server, task in reversed(servers):
            server.should_exit = True
            await task

    try:
        yield asyncio.run_coroutine_threadsafe(start(), loop).result(
            STARTUP_TIMEOUT_SECONDS
        )
    finally:
        asyncio.run_coroutine_threadsafe(stop(), loop).result(STARTUP_TIMEOUT_SECONDS)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(STARTUP_TIMEOUT_SECONDS)
        loop.close()


@pytest.fixture
def owner(stack: Stack) -> Stack:
    """A signed-up user with a registered, unencrypted owner key."""
    code, _, err = stack.cli("init", "--no-passphrase")
    assert code == 0, err
    code, _, err = stack.cli(
        "signup",
        "--server",
        stack.server_url,
        "--email",
        "owner@example.com",
        "--password-stdin",
        stdin=PASSWORD.encode() + b"\n",
    )
    assert code == 0, err
    return stack


@pytest.fixture
def verified(owner: Stack) -> Stack:
    code, _, err = owner.cli(*owner.verify_args())
    assert code == 0, err
    return owner
