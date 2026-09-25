"""Shared fixtures for egress tests. No test touches the real network."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpcore
import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from carapace_enclave.attestation import LauncherClient, TokenSource
from carapace_enclave.clock import TrustedClock
from carapace_enclave.egress import EgressExecutor, InjectionPolicy, URLFilter
from carapace_enclave_mock import LocalRsaDecrypter, MockLauncher

SECRET = b"s3cr3t-T0KEN/with+base64?chars=="
PUBLIC_IP = "93.184.216.34"


def make_policy(**overrides: Any) -> InjectionPolicy:
    data: dict[str, Any] = {
        "v": 1,
        "hosts": [
            {"match": "exact", "value": "api.github.com"},
            {"match": "suffix", "value": ".example.com"},
        ],
        "schemes": ["https"],
        "methods": ["GET", "POST"],
        "ports": [443, 8443],
        "inject": {
            "kind": "header",
            "name": "Authorization",
            "template": "Bearer {secret}",
        },
        "limits": {
            "req_bytes": 1024,
            "resp_bytes": 4096,
            "rpm": 60,
            "timeout_s": 5,
        },
    }
    data.update(overrides)
    return InjectionPolicy.model_validate(data)


class FakeResolver:
    """Returns scripted answers in order and records every lookup."""

    def __init__(self, *answers: list[str]) -> None:
        self._answers = list(answers) or [[PUBLIC_IP]]
        self.calls: list[tuple[str, int]] = []

    async def __call__(self, host: str, port: int) -> list[str]:
        self.calls.append((host, port))
        index = min(len(self.calls) - 1, len(self._answers) - 1)
        return self._answers[index]


class Upstream:
    """httpx MockTransport that records requests and replies via ``handler``."""

    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self.handler = handler
        self.requests: list[httpx.Request] = []

    def factory(self) -> httpx.AsyncBaseTransport:
        def record(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            response = self.handler(request)
            if response.is_stream_consumed:
                # ``httpx.Response(content=bytes)`` is read at construction.
                # A real transport never pre-reads, so hand the executor the
                # raw stream, as httpcore would.
                response = httpx.Response(
                    response.status_code,
                    headers=response.headers,
                    stream=response.stream,
                )
            return response

        return httpx.MockTransport(record)


class RawUpstream:
    """The real httpcore/h11 transport fed scripted wire bytes, no sockets.

    Use this for anything that depends on HTTP/1.1 parsing (obsolete line
    folds, reason phrases, trailers) that ``MockTransport`` bypasses.
    """

    def __init__(self, *wire: bytes) -> None:
        self.wire = list(wire)

    def factory(self) -> httpx.AsyncBaseTransport:
        transport = httpx.AsyncHTTPTransport(retries=0, http1=True, http2=False)
        transport._pool._network_backend = httpcore.AsyncMockBackend(self.wire)
        return transport


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def resolver() -> FakeResolver:
    return FakeResolver()


def make_executor(
    upstream: Upstream, resolver: FakeResolver | None = None
) -> EgressExecutor:
    return EgressExecutor(
        url_filter=URLFilter(resolver or FakeResolver()),
        transport_factory=upstream.factory,
    )


# -- attestation and KMS --------------------------------------------------------

BOOT_NONCE = "b0" * 32
SERVER_URL = "http://localhost:8000"
WIF_AUDIENCE = (
    "//iam.googleapis.com/projects/123456789/locations/global"
    "/workloadIdentityPools/carapace-attest/providers/confidential-space"
)


@pytest.fixture(scope="session")
def launcher_signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def mock_launcher(launcher_signing_key: rsa.RSAPrivateKey) -> MockLauncher:
    return MockLauncher(signing_key=launcher_signing_key)


@pytest.fixture
def clock() -> TrustedClock:
    return TrustedClock()


@pytest.fixture
def tokens(mock_launcher: MockLauncher, clock: TrustedClock) -> TokenSource:
    launcher = LauncherClient(transport=mock_launcher.transport())
    return TokenSource(launcher, clock, nonce=BOOT_NONCE)


@pytest.fixture(scope="session")
def kms_decrypter() -> LocalRsaDecrypter:
    return LocalRsaDecrypter.generate()
