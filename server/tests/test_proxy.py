"""Client address behind trusted proxies: X-Forwarded-For and rate limits."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.requests import Request
from starlette.types import Receive, Scope, Send

from carapace_server.app import create_app
from carapace_server.config import Settings
from carapace_server.proxy import ForwardedClientMiddleware, forwarded_client_host
from carapace_server.ratelimit import client_bucket, limiter

PASSWORD = "Correct-Horse-9-Battery"  # noqa: S105
LOGIN_LIMIT = 10
# httpx's ASGI transport presents every request from this peer address.
ASGI_PEER = "127.0.0.1"
CLIENT_A = "203.0.113.7"
CLIENT_B = "203.0.113.8"
# One IPv6 client's /64, and the next one over.
CLIENT_V6_PREFIX = "2001:db8:1:2"
OTHER_V6_PREFIX = "2001:db8:1:3"


# --- forwarded_client_host ---------------------------------------------------


@pytest.mark.parametrize(
    ("values", "hops", "expected"),
    [
        (["203.0.113.7"], 1, "203.0.113.7"),
        # The leftmost entries are client-supplied; only the last hop counts.
        (["10.0.0.1, 203.0.113.7"], 1, "203.0.113.7"),
        (["10.0.0.1, 8.8.8.8, 203.0.113.7"], 1, "203.0.113.7"),
        # Two hops: the client is second from the right.
        (["10.0.0.1, 203.0.113.7, 198.51.100.2"], 2, "203.0.113.7"),
        # Multiple header lines are one comma-joined list, in order.
        (["10.0.0.1", "203.0.113.7"], 1, "203.0.113.7"),
        (["10.0.0.1, 10.0.0.2", "203.0.113.7"], 1, "203.0.113.7"),
        # Ports are dropped and IPv6 is canonicalised.
        (["203.0.113.7:4321"], 1, "203.0.113.7"),
        (["2001:DB8::0001"], 1, "2001:db8::1"),
        (["[2001:db8::1]"], 1, "2001:db8::1"),
        (["[2001:db8::1]:443"], 1, "2001:db8::1"),
        # IPv4-mapped IPv6 is the same client as the plain IPv4 form.
        (["::ffff:203.0.113.7"], 1, "203.0.113.7"),
        (["[::ffff:203.0.113.7]:443"], 1, "203.0.113.7"),
        ([" 203.0.113.7 "], 1, "203.0.113.7"),
    ],
)
def test_client_is_the_entry_the_trusted_hop_appended(
    values: list[str], hops: int, expected: str
) -> None:
    assert forwarded_client_host(values, trusted_hops=hops) == expected


@pytest.mark.parametrize(
    ("values", "hops"),
    [
        ([], 1),
        ([""], 1),
        # A shorter chain than the configured hops: never fall back to a
        # client-supplied entry further left.
        (["203.0.113.7"], 2),
        (["10.0.0.1, 203.0.113.7"], 3),
        # The trusted hop's entry is not an IP address.
        (["10.0.0.1, evil"], 1),
        (["10.0.0.1, "], 1),
        (["10.0.0.1, [2001:db8::1"], 1),
        (["10.0.0.1, [2001:db8::1]junk"], 1),
        (["10.0.0.1, 203.0.113.7:port"], 1),
        (["10.0.0.1, example.com"], 1),
        (["10.0.0.1, 203.0.113.7, "], 1),
        # An empty entry where the client should be, with a hop beyond it.
        (["10.0.0.1, , 198.51.100.2"], 2),
    ],
)
def test_unusable_chain_keeps_the_peer_address(values: list[str], hops: int) -> None:
    assert forwarded_client_host(values, trusted_hops=hops) is None


@pytest.mark.parametrize("hops", [0, -1])
def test_at_least_one_hop_is_required(hops: int) -> None:
    with pytest.raises(ValueError, match="at least 1"):
        forwarded_client_host(["203.0.113.7"], trusted_hops=hops)
    with pytest.raises(ValueError, match="at least 1"):
        ForwardedClientMiddleware(_echo_client, trusted_hops=hops)


# --- the middleware, at the ASGI scope ----------------------------------------


async def _echo_client(scope: Scope, receive: Receive, send: Send) -> None:
    client = scope.get("client")
    body = (client[0] if client else "").encode()
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": body})


async def _scope_client(hops: int, headers: list[tuple[str, str]]) -> str:
    app = ForwardedClientMiddleware(_echo_client, trusted_hops=hops)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        response = await c.get("/", headers=headers)
    return response.text


@pytest.mark.anyio
async def test_middleware_rewrites_the_client_from_the_trusted_entry() -> None:
    assert await _scope_client(1, [("x-forwarded-for", f"10.0.0.1, {CLIENT_A}")]) == (
        CLIENT_A
    )


@pytest.mark.anyio
async def test_middleware_keeps_the_peer_without_a_usable_entry() -> None:
    assert await _scope_client(1, []) == ASGI_PEER
    assert await _scope_client(1, [("x-forwarded-for", "not-an-ip")]) == ASGI_PEER
    assert await _scope_client(2, [("x-forwarded-for", CLIENT_A)]) == ASGI_PEER


# --- rate-limit buckets on the real app --------------------------------------


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Overrides conftest's: one trusted proxy hop, as on Cloud Run."""
    return Settings(
        mode="dev",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'test.db'}",
        public_url="http://localhost:8000",
        bcrypt_rounds=4,
        rate_limit_enabled=False,
        trusted_proxy_hops=1,
    )


@pytest.fixture
async def direct_client(
    settings: Settings, sessionmaker: async_sessionmaker[AsyncSession]
) -> AsyncIterator[httpx.AsyncClient]:
    """The same app with no trusted hop: the default configuration."""
    app: FastAPI = create_app(settings.model_copy(update={"trusted_proxy_hops": 0}))
    app.state.sessionmaker = sessionmaker
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@contextlib.contextmanager
def rate_limiting() -> Iterator[None]:
    limiter.reset()
    limiter.enabled = True
    try:
        yield
    finally:
        limiter.enabled = False
        limiter.reset()


async def _login(client: httpx.AsyncClient, forwarded_for: str) -> int:
    response = await client.post(
        "/v1/auth/login",
        json={"email": "rl@example.com", "password": PASSWORD},
        headers={"X-Forwarded-For": forwarded_for},
    )
    return response.status_code


@pytest.mark.anyio
async def test_spoofed_leftmost_entry_does_not_change_the_bucket(
    client: httpx.AsyncClient,
) -> None:
    """One caller behind the proxy cannot dodge its limit by varying XFF."""
    with rate_limiting():
        codes = [
            await _login(client, f"10.0.0.{i}, {CLIENT_A}")
            for i in range(LOGIN_LIMIT + 1)
        ]
    assert codes[:LOGIN_LIMIT] == [401] * LOGIN_LIMIT
    assert codes[LOGIN_LIMIT] == 429


@pytest.mark.anyio
async def test_callers_behind_the_proxy_get_separate_buckets(
    client: httpx.AsyncClient,
) -> None:
    """Exhausting the limit as one client leaves every other client alone."""
    with rate_limiting():
        for _ in range(LOGIN_LIMIT):
            assert await _login(client, CLIENT_A) == 401
        assert await _login(client, CLIENT_A) == 429
        assert await _login(client, f"{CLIENT_A}, {CLIENT_B}") == 401
        assert await _login(client, CLIENT_B) == 401


@pytest.mark.anyio
async def test_ipv6_client_cannot_rotate_within_its_prefix(
    client: httpx.AsyncClient,
) -> None:
    """Addresses in one /64 share a bucket; the next /64 does not."""
    with rate_limiting():
        codes = [
            await _login(client, f"{CLIENT_V6_PREFIX}::{i:x}")
            for i in range(1, LOGIN_LIMIT + 2)
        ]
        assert await _login(client, f"{OTHER_V6_PREFIX}::1") == 401
    assert codes[:LOGIN_LIMIT] == [401] * LOGIN_LIMIT
    assert codes[LOGIN_LIMIT] == 429


@pytest.mark.parametrize(
    ("address", "bucket"),
    [
        (CLIENT_A, CLIENT_A),
        (f"{CLIENT_V6_PREFIX}::1", f"{CLIENT_V6_PREFIX}::/64"),
        (f"{CLIENT_V6_PREFIX}:ffff:ffff:ffff:ffff", f"{CLIENT_V6_PREFIX}::/64"),
        (f"{OTHER_V6_PREFIX}::1", f"{OTHER_V6_PREFIX}::/64"),
        # Not an IP address (a unix socket peer): used as is.
        ("/tmp/carapace.sock", "/tmp/carapace.sock"),  # noqa: S108
    ],
)
def test_client_bucket(address: str, bucket: str) -> None:
    scope = {"type": "http", "client": (address, 0), "headers": []}
    assert client_bucket(Request(scope)) == bucket


@pytest.mark.anyio
async def test_without_trusted_hops_the_header_is_ignored(
    direct_client: httpx.AsyncClient,
) -> None:
    """Default: every request keys on the peer, whatever XFF says."""
    with rate_limiting():
        codes = [
            await _login(direct_client, f"203.0.113.{i}")
            for i in range(LOGIN_LIMIT + 1)
        ]
    assert codes[:LOGIN_LIMIT] == [401] * LOGIN_LIMIT
    assert codes[LOGIN_LIMIT] == 429


def test_trusted_proxy_hops_defaults_to_zero_and_refuses_negatives() -> None:
    assert Settings(mode="dev").trusted_proxy_hops == 0
    with pytest.raises(ValidationError):
        Settings(mode="dev", trusted_proxy_hops=-1)
