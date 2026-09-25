"""Shared fixtures for egress tests. No test touches the real network."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest

from carapace_enclave.egress import EgressExecutor, InjectionPolicy, URLFilter

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
            return self.handler(request)

        return httpx.MockTransport(record)


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
