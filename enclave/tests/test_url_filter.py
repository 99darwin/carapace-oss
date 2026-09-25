"""Tests for URL parsing and SSRF protection (ported and extended)."""

from __future__ import annotations

import ipaddress
import socket

import pytest

from carapace_enclave.egress.url_filter import (
    URLFilter,
    URLFilterError,
    is_public_ip,
    parse_url,
    system_resolver,
)

from .conftest import PUBLIC_IP, FakeResolver

pytestmark = pytest.mark.anyio


class TestParseURL:
    def test_basic(self) -> None:
        url = parse_url("https://API.GitHub.com./repos/x?per_page=5")
        assert url.host == "api.github.com"
        assert url.port == 443
        assert url.target == "/repos/x?per_page=5"

    def test_explicit_port_and_empty_path(self) -> None:
        url = parse_url("https://api.github.com:8443")
        assert (url.port, url.target) == (8443, "/")

    def test_fullwidth_dots_normalize(self) -> None:
        assert parse_url("https://api\uff0egithub\uff0ecom/").host == "api.github.com"

    def test_scheme_case_insensitive(self) -> None:
        assert parse_url("HTTPS://api.github.com/").host == "api.github.com"

    def test_idn(self) -> None:
        assert parse_url("https://bücher.example/").host == "xn--bcher-kva.example"

    @pytest.mark.parametrize(
        "url",
        [
            "http://api.github.com/",
            "ftp://api.github.com/",
            "file:///etc/passwd",
            "https://api.github.com/caf\u00e9",
            "https://api.github.com/?q=\u00e9",
            "//api.github.com/",
            "https://user:pw@api.github.com/",
            "https://api.github.com@evil.test/",
            "https://api.github.com/#frag",
            "https://api.github.com\\@evil.test/",
            "https:\\\\api.github.com\\path",
            "https://api.github.com/\x00",
            "https://api.github.com/ path",
            " https://api.github.com/",
            "https://api.github.com/\n",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://2130706433/",
            "https://0x7f000001/",
            "https://0177.0.0.1/",
            "https://api.github.com:99999/",
            "https://api.github.com:abc/",
            "https:///path",
            "https://api.github.com\uff0f@evil.test/",  # NFKC -> '/'
            "https://evil.test\uff03@api.github.com/",  # NFKC -> '#'
        ],
    )
    def test_rejects(self, url: str) -> None:
        with pytest.raises(URLFilterError):
            parse_url(url)


class TestIsPublicIP:
    @pytest.mark.parametrize(
        "ip",
        [
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "127.0.0.1",
            "127.255.255.255",
            "169.254.169.254",  # cloud metadata
            "0.0.0.0",  # noqa: S104 - address under test, not a bind
            "100.64.0.1",  # carrier-grade NAT
            "192.0.2.1",  # TEST-NET-1
            "198.18.0.1",  # benchmarking
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a00:1",  # NAT64 of 10.0.0.1
            "2002:7f00:1::",  # 6to4 of 127.0.0.1
            "2001::1",  # Teredo
            "2001:db8::1",  # documentation
        ],
    )
    def test_blocks(self, ip: str) -> None:
        assert not is_public_ip(ipaddress.ip_address(ip))

    @pytest.mark.parametrize(
        "ip",
        ["8.8.8.8", "1.1.1.1", PUBLIC_IP, "2606:4700:4700::1111", "::ffff:8.8.8.8"],
    )
    def test_allows(self, ip: str) -> None:
        assert is_public_ip(ipaddress.ip_address(ip))


class TestURLFilterPin:
    async def test_returns_first_public_ip(self) -> None:
        resolver = FakeResolver([PUBLIC_IP, "1.1.1.1"])
        pinned = await URLFilter(resolver).pin(parse_url("https://api.github.com/"))
        assert pinned.ip == PUBLIC_IP
        assert resolver.calls == [("api.github.com", 443)]

    @pytest.mark.parametrize(
        "answer",
        [
            ["10.0.0.1"],
            ["169.254.169.254"],
            ["::ffff:127.0.0.1"],
            [PUBLIC_IP, "127.0.0.1"],  # mixed answer: rebinding signal
            ["fe80::1%eth0"],
            ["not-an-ip"],
            [],
        ],
    )
    async def test_rejects_bad_answers(self, answer: list[str]) -> None:
        with pytest.raises(URLFilterError):
            await URLFilter(FakeResolver(answer)).pin(parse_url("https://a.example/"))

    @pytest.mark.parametrize(
        "host",
        [
            "metadata.google.internal",
            "service.internal",
            "printer.local",
            "app.default.svc.cluster.local",
            "localhost",
            "x.localhost",
            "1.0.0.127.in-addr.arpa",
            "metadata",
        ],
    )
    async def test_blocks_internal_names_before_dns(self, host: str) -> None:
        resolver = FakeResolver()
        with pytest.raises(URLFilterError):
            await URLFilter(resolver).pin(parse_url(f"https://{host}/"))
        assert resolver.calls == []

    async def test_resolution_failure(self) -> None:
        async def failing(host: str, port: int) -> list[str]:
            raise socket.gaierror("no such host")

        with pytest.raises(URLFilterError, match="resolve"):
            await URLFilter(failing).pin(parse_url("https://a.example/"))

    async def test_system_resolver_shape(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_getaddrinfo(*args: object, **kwargs: object) -> list[object]:
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443, 0, 0)),
            ]

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        assert await system_resolver("a.example", 443) == ["8.8.8.8", "::1"]
