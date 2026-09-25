"""The client address behind a trusted reverse proxy.

Rate limits and session records key on ``request.client``. Behind Cloud Run
(or any reverse proxy) that is the proxy's address, so every caller would
share one rate-limit bucket and one client could exhaust the login and auth
limits for everyone.

Each proxy hop appends the address it accepted the connection from to
``X-Forwarded-For``. With ``trusted_hops`` proxies in front of the server
the real client is therefore the entry ``trusted_hops`` from the right;
Cloud Run's frontend is one hop and appends the client as the last entry.
The count is of appended entries, not devices: a Google external load
balancer in front of Cloud Run appends two (client, then its own address).
Everything left of that entry is client-supplied and never used. When the
header has fewer entries than expected, or the entry is not an IP address,
the peer address is kept: an unexpected chain degrades to the shared bucket,
never to a client-chosen key.

This replaces uvicorn's ``--proxy-headers`` handling, which trusts the peer
address rather than a hop count and, with ``--forwarded-allow-ips='*'``,
takes the leftmost (client-supplied) entry.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

FORWARDED_FOR_HEADER = "x-forwarded-for"
# X-Forwarded-For carries no port; ASGI wants one, and 0 means unknown.
UNKNOWN_PORT = 0
# What may follow a host: nothing, or a decimal port.
PORT_SUFFIX = re.compile(r"(:[0-9]{1,5})?")


def forwarded_client_host(
    forwarded_for: Sequence[str], *, trusted_hops: int
) -> str | None:
    """The client address appended by the outermost trusted proxy.

    ``forwarded_for`` holds every ``X-Forwarded-For`` header value in wire
    order; multiple header lines are equivalent to one comma-joined value.
    Returns ``None`` when the chain is shorter than ``trusted_hops`` or the
    chosen entry is not an IP address, so the caller keeps the peer address.
    """
    if trusted_hops < 1:
        raise ValueError("trusted_hops must be at least 1")
    entries = [entry.strip() for entry in ",".join(forwarded_for).split(",")]
    if len(entries) < trusted_hops:
        return None
    return _parse_ip(entries[-trusted_hops])


def _parse_ip(entry: str) -> str | None:
    """A canonical IP address from ``host``, ``host:port`` or ``[v6]:port``.

    IPv4-mapped IPv6 addresses collapse to their IPv4 form so one client is
    one key however the proxy spells it.
    """
    host = entry
    if entry.startswith("["):
        end = entry.find("]")
        if end == -1 or not PORT_SUFFIX.fullmatch(entry[end + 1 :]):
            return None
        host = entry[1:end]
    elif entry.count(":") == 1:
        host, _, port = entry.rpartition(":")
        if not PORT_SUFFIX.fullmatch(f":{port}"):
            return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    return str(ip)


class ForwardedClientMiddleware:
    """Set ``scope["client"]`` from the trusted ``X-Forwarded-For`` entry.

    Pure ASGI so the rewritten address is what every later middleware,
    dependency and route (including the rate limiter's key function) sees.
    """

    def __init__(self, app: ASGIApp, *, trusted_hops: int) -> None:
        if trusted_hops < 1:
            raise ValueError("trusted_hops must be at least 1")
        self.app = app
        self.trusted_hops = trusted_hops

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in {"http", "websocket"}:
            values = Headers(scope=scope).getlist(FORWARDED_FOR_HEADER)
            host = forwarded_client_host(values, trusted_hops=self.trusted_hops)
            if host is not None:
                scope["client"] = (host, UNKNOWN_PORT)
        await self.app(scope, receive, send)
