"""In-process rate limiting (no Redis).

Limits are per client, keyed on ``request.client``. Behind a reverse proxy
that is the proxy's address unless ``CARAPACE_TRUSTED_PROXY_HOPS`` is set,
in which case ``proxy.ForwardedClientMiddleware`` replaces it with the
entry the outermost trusted proxy appended to ``X-Forwarded-For``. Nothing
here reads the header, so a client-supplied value never picks the bucket.

An IPv6 client usually holds a whole /64 and could rotate through it for a
fresh bucket per request, so IPv6 addresses are bucketed by /64. With
several server replicas each keeps its own counters.
"""

from __future__ import annotations

import ipaddress

from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

IPV6_BUCKET_PREFIX = 64


def client_bucket(request: Request) -> str:
    """The rate-limit key: the client's IPv4 address or IPv6 /64."""
    address = get_remote_address(request)
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address
    if isinstance(ip, ipaddress.IPv6Address):
        return str(ipaddress.ip_network((ip, IPV6_BUCKET_PREFIX), strict=False))
    return address


limiter = Limiter(key_func=client_bucket, storage_uri="memory://")
