"""SSRF protection: parse an agent URL and resolve it to one pinned public IP.

Ported from the previous enclave's URL filter, narrowed for the egress proxy:

- HTTPS only; no userinfo, fragments, backslashes, whitespace or non-ASCII.
- Hostnames are normalized (see :mod:`hostname`); IP literals in any notation
  (dotted, decimal, hex, octal, bracketed IPv6) are rejected outright.
- Internal and metadata hostnames are blocked before DNS.
- DNS is resolved once. If *any* returned address is non-public the request
  is refused (a mixed answer is a rebinding signal), otherwise the first
  address is returned so the caller connects to exactly that IP.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from carapace_enclave.egress.hostname import HostnameError, normalize_hostname

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Awaitable[list[str]]]

HTTPS_DEFAULT_PORT = 443

# Checked in addition to ``not ip.is_global``; these are global per IANA but
# can tunnel to or embed private IPv4 space.
MAX_URL_LENGTH = 8 * 1024

BLOCKED_RANGES = tuple(
    ipaddress.ip_network(net)
    for net in (
        "64:ff9b::/96",  # NAT64 well-known prefix
        "64:ff9b:1::/48",  # Local-use NAT64
        "2002::/16",  # 6to4
        "2001::/32",  # Teredo
        "::/96",  # IPv4-compatible (deprecated)
        "100.64.0.0/10",  # Carrier-grade NAT
        "198.18.0.0/15",  # Benchmarking
    )
)

BLOCKED_DOMAIN_SUFFIXES = (
    ".internal",
    ".local",
    ".localhost",
    ".localdomain",
    ".intranet",
    ".corp",
    ".lan",
    ".home",
    ".private",
    ".arpa",
)
BLOCKED_HOSTS = frozenset({"localhost", "metadata", "instance-data"})


class URLFilterError(Exception):
    """Raised when a URL is refused. ``reason`` is safe to show the agent."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"URL blocked: {reason}")


@dataclass(frozen=True, slots=True)
class ParsedURL:
    host: str  # normalized
    port: int
    target: str  # path + optional "?query", as sent by the agent


@dataclass(frozen=True, slots=True)
class PinnedTarget:
    url: ParsedURL
    ip: str


def parse_url(url: str) -> ParsedURL:
    """Parse and validate an agent-supplied URL without touching the network."""
    if len(url) > MAX_URL_LENGTH:
        raise URLFilterError("URL too long")
    if any(ch.isspace() or ord(ch) < 0x20 for ch in url):
        raise URLFilterError("URL must not contain whitespace or controls")
    if "\\" in url or "\x7f" in url:
        raise URLFilterError("URL contains forbidden characters")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise URLFilterError("invalid URL") from exc
    if port == 0:
        # ``urlsplit`` accepts ``:0``; it must not silently become 443.
        raise URLFilterError("invalid port")
    # Only the hostname may be non-ASCII (IDN); it is IDNA-encoded below.
    if not (parts.scheme + parts.path + parts.query + parts.fragment).isascii():
        raise URLFilterError("URL must be ASCII outside the hostname")
    if parts.scheme != "https":
        raise URLFilterError("only https URLs are allowed")
    if "@" in parts.netloc:
        raise URLFilterError("userinfo is not allowed")
    if parts.fragment or "#" in url:
        raise URLFilterError("fragments are not allowed")
    if parts.netloc.startswith("[") or not parts.hostname:
        raise URLFilterError("IP literals are not allowed")
    try:
        host = normalize_hostname(parts.hostname)
    except HostnameError as exc:
        raise URLFilterError(str(exc)) from exc
    target = parts.path or "/"
    if not target.startswith("/"):
        raise URLFilterError("invalid path")
    if parts.query or url.endswith("?"):
        target = f"{target}?{parts.query}"
    return ParsedURL(host=host, port=port or HTTPS_DEFAULT_PORT, target=target)


def is_public_ip(ip: IPAddress) -> bool:
    """True only for globally routable unicast addresses."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if not ip.is_global or ip.is_multicast:
        return False
    return not any(ip.version == net.version and ip in net for net in BLOCKED_RANGES)


def check_hostname(host: str) -> None:
    """Refuse internal and metadata names before any DNS lookup."""
    if host in BLOCKED_HOSTS or host.startswith("metadata."):
        raise URLFilterError("internal or metadata host")
    if any(host.endswith(suffix) for suffix in BLOCKED_DOMAIN_SUFFIXES):
        raise URLFilterError("internal domain suffix")


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


class URLFilter:
    """Resolves an allowlisted URL to one safe IP. The resolver is injectable."""

    def __init__(self, resolver: Resolver = system_resolver) -> None:
        self._resolver = resolver

    async def pin(self, url: ParsedURL) -> PinnedTarget:
        check_hostname(url.host)
        try:
            addresses = await self._resolver(url.host, url.port)
        except (OSError, UnicodeError) as exc:
            raise URLFilterError("could not resolve hostname") from exc
        if not addresses:
            raise URLFilterError("could not resolve hostname")
        parsed: list[IPAddress] = []
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address.split("%", 1)[0])
            except ValueError as exc:
                raise URLFilterError("resolver returned an invalid address") from exc
            if not is_public_ip(ip):
                raise URLFilterError("hostname resolves to a non-public address")
            parsed.append(ip)
        return PinnedTarget(url=url, ip=str(parsed[0]))
