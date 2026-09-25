"""Hostname normalization shared by the policy model and the executor.

Policies and requests are compared only in normalized form: lowercase ASCII
(IDNA 2008 / UTS 46 A-labels), no trailing dot, LDH labels. IP literals are
not hostnames and are rejected here; the policy never allowlists an IP.
"""

from __future__ import annotations

import re

import idna

MAX_HOSTNAME_LENGTH = 253
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class HostnameError(ValueError):
    """Raised for hostnames that cannot be normalized."""


def normalize_hostname(host: str) -> str:
    """Return the canonical form of ``host`` or raise :class:`HostnameError`.

    ``Api.GitHub.com.`` and ``api.github.com`` normalize to the same value;
    ``bücher.example`` becomes ``xn--bcher-kva.example``.
    """
    if not host:
        raise HostnameError("empty hostname")
    if host.endswith("."):
        host = host[:-1]
    if not host.isascii():
        try:
            host = idna.encode(host, uts46=True).decode("ascii")
        except idna.IDNAError as exc:
            raise HostnameError("invalid internationalized hostname") from exc
    host = host.lower()
    if len(host) > MAX_HOSTNAME_LENGTH:
        raise HostnameError("hostname too long")
    labels = host.split(".")
    if not all(_LABEL.match(label) for label in labels):
        raise HostnameError("hostname has an invalid label")
    if labels[-1].isdigit() or labels[-1].startswith("0x"):
        # Covers dotted-quad, decimal (2130706433) and hex (0x7f000001) forms.
        raise HostnameError("IP literals are not allowed")
    if any(label.startswith("xn--") for label in labels):
        try:
            idna.decode(host)
        except idna.IDNAError as exc:
            raise HostnameError("invalid punycode label") from exc
    return host
