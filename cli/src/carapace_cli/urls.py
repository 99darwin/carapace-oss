"""URL rules shared by the server and enclave clients."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from carapace_cli.errors import CarapaceError

LOOPBACK_HOSTS = frozenset({"localhost"})


def is_loopback(host: str) -> bool:
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_base_url(url: str, *, what: str, allow_loopback_http: bool) -> str:
    """Strip a trailing slash and check the scheme.

    ``https`` is required. Plain ``http`` is allowed only for loopback hosts
    and only where ``allow_loopback_http`` says so (a local dev server);
    bearer tokens would otherwise cross the network in the clear.

    Raises:
        CarapaceError: On a malformed URL or a disallowed scheme.
    """
    parts = urlsplit(url)
    if not parts.hostname or parts.username or parts.password:
        raise CarapaceError(f"invalid {what} URL")
    if parts.query or parts.fragment:
        raise CarapaceError(f"{what} URL must not have a query or fragment")
    if parts.scheme == "http":
        if not (allow_loopback_http and is_loopback(parts.hostname)):
            raise CarapaceError(f"{what} URL must use https")
    elif parts.scheme != "https":
        raise CarapaceError(f"{what} URL must use https")
    return url.rstrip("/")
