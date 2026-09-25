"""Tests for the egress executor. All upstreams are httpx.MockTransport."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest

from carapace_enclave.egress import (
    AgentRequest,
    EgressDenied,
    EgressError,
    EgressExecutor,
    URLFilter,
)
from carapace_enclave.egress.redact import REDACTED

from .conftest import PUBLIC_IP, SECRET, FakeResolver, Upstream, make_policy

pytestmark = pytest.mark.anyio

URL = "https://api.github.com/repos/x?page=2"


def ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"ok": True})


async def run(
    request: AgentRequest,
    handler: Any = ok,
    resolver: FakeResolver | None = None,
    secret: bytes = SECRET,
    **policy: Any,
) -> tuple[Any, Upstream]:
    upstream = Upstream(handler)
    executor = EgressExecutor(
        url_filter=URLFilter(resolver or FakeResolver()),
        transport_factory=upstream.factory,
    )
    result = await executor.execute(make_policy(**policy), secret, request)
    return result, upstream


async def deny(request: AgentRequest, **kwargs: Any) -> tuple[str, Upstream]:
    upstream = Upstream(ok)
    executor = EgressExecutor(
        url_filter=URLFilter(kwargs.pop("resolver", FakeResolver())),
        transport_factory=upstream.factory,
    )
    secret = kwargs.pop("secret", SECRET)
    with pytest.raises(EgressDenied) as exc_info:
        await executor.execute(make_policy(**kwargs), secret, request)
    assert upstream.requests == []
    assert SECRET.decode() not in str(exc_info.value)
    return exc_info.value.code, upstream


class TestHappyPath:
    async def test_pins_ip_and_sets_sni_and_host(self) -> None:
        result, upstream = await run(AgentRequest("get", URL))
        assert result.status == 200
        (sent,) = upstream.requests
        assert sent.url.host == PUBLIC_IP
        assert sent.url.scheme == "https"
        assert sent.url.raw_path == b"/repos/x?page=2"
        assert sent.headers["host"] == "api.github.com"
        assert sent.extensions["sni_hostname"] == "api.github.com"
        assert sent.headers["authorization"] == "Bearer " + SECRET.decode()
        assert sent.headers["accept-encoding"] == "identity"
        assert sent.method == "GET"

    async def test_non_default_port_in_host_header(self) -> None:
        _, upstream = await run(AgentRequest("GET", "https://a.example.com:8443/"))
        (sent,) = upstream.requests
        assert sent.headers["host"] == "a.example.com:8443"
        assert sent.url.port == 8443

    async def test_host_normalized_before_allowlist(self) -> None:
        resolver = FakeResolver()
        result, _ = await run(
            AgentRequest("GET", "https://API.GitHub.com./x"), resolver=resolver
        )
        assert result.metadata.host == "api.github.com"
        assert resolver.calls == [("api.github.com", 443)]

    async def test_receipt_metadata(self) -> None:
        body = b'{"q":1}'
        result, _ = await run(AgentRequest("POST", URL, body=body))
        meta = result.metadata
        assert meta.method == "POST"
        assert meta.host == "api.github.com"
        assert meta.path_hash == hashlib.sha256(b"/repos/x?page=2").hexdigest()
        assert meta.status == 200
        assert meta.bytes_out == len(body)
        assert meta.bytes_in == len(result.body)
        assert meta.redactions == 0

    async def test_query_injection(self) -> None:
        inject = {"kind": "query", "name": "key", "template": "{secret}"}
        _, upstream = await run(AgentRequest("GET", URL), inject=inject)
        (sent,) = upstream.requests
        assert sent.url.params["page"] == "2"
        assert sent.url.params["key"] == SECRET.decode()
        assert "authorization" not in sent.headers

    async def test_query_injection_refuses_duplicate_param(self) -> None:
        inject = {"kind": "query", "name": "page", "template": "{secret}"}
        code, _ = await deny(AgentRequest("GET", URL), inject=inject)
        assert code == "query_param_rejected"

    async def test_basic_auth_injection(self) -> None:
        inject = {"kind": "basic_auth", "template": "bot:{secret}"}
        _, upstream = await run(AgentRequest("GET", URL), inject=inject)
        expected = base64.b64encode(b"bot:" + SECRET).decode()
        assert upstream.requests[0].headers["authorization"] == f"Basic {expected}"

    async def test_agent_headers_forwarded(self) -> None:
        request = AgentRequest("GET", URL, headers={"Accept": "application/json"})
        _, upstream = await run(request)
        assert upstream.requests[0].headers["accept"] == "application/json"


class TestDenials:
    @pytest.mark.parametrize(
        ("url", "code"),
        [
            ("https://evilgithub.com/", "host_not_allowed"),
            ("https://github.com/", "host_not_allowed"),
            ("https://api.github.com.evil.test/", "host_not_allowed"),
            ("https://example.com/", "host_not_allowed"),
            ("https://xexample.com/", "host_not_allowed"),
            ("http://api.github.com/", "url_rejected"),
            ("ftp://api.github.com/", "url_rejected"),
            ("https://api.github.com:8080/", "port_not_allowed"),
            ("https://127.0.0.1/", "url_rejected"),
            ("https://[::1]/", "url_rejected"),
            ("https://u:p@api.github.com/", "url_rejected"),
        ],
    )
    async def test_url_denials(self, url: str, code: str) -> None:
        assert (await deny(AgentRequest("GET", url)))[0] == code

    @pytest.mark.parametrize("method", ["DELETE", "PUT", "CONNECT", "TRACE", "FOO"])
    async def test_method_denied(self, method: str) -> None:
        assert (await deny(AgentRequest(method, URL)))[0] == "method_not_allowed"

    async def test_request_body_cap(self) -> None:
        request = AgentRequest("POST", URL, body=b"x" * 1025)
        assert (await deny(request))[0] == "request_too_large"

    @pytest.mark.parametrize(
        "headers",
        [
            {"Host": "evil.test"},
            {"host": "evil.test"},
            {"Authorization": "Bearer attacker"},
            {"authorization": "x"},
            {"Proxy-Authorization": "x"},
            {"Content-Length": "0"},
            {"Transfer-Encoding": "chunked"},
            {"Connection": "keep-alive"},
            {"TE": "trailers"},
            {"Upgrade": "h2c"},
            {"Expect": "100-continue"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "evil.test"},
            {"Forwarded": "for=127.0.0.1"},
            {"Accept-Encoding": "gzip"},
            {"X-Ok": "a\r\nHost: evil.test"},
            {"X-Ok": "a\nb"},
            {"X-Ok": "a\x00b"},
            {"X-Ok": "café"},
            {"X Bad": "1"},
            {"X-Bad:": "1"},
            {"": "1"},
        ],
    )
    async def test_header_smuggling_rejected(self, headers: dict[str, str]) -> None:
        assert (await deny(AgentRequest("GET", URL, headers=headers)))[0] in {
            "header_rejected"
        }

    async def test_basic_auth_blocks_agent_authorization(self) -> None:
        inject = {"kind": "basic_auth", "template": "bot:{secret}"}
        request = AgentRequest("GET", URL, headers={"Authorization": "x"})
        assert (await deny(request, inject=inject))[0] == "header_rejected"

    async def test_too_many_headers(self) -> None:
        headers = [(f"X-H{i}", "1") for i in range(65)]
        assert (await deny(AgentRequest("GET", URL, headers=headers)))[0] == (
            "too_many_headers"
        )

    async def test_headers_too_large(self) -> None:
        headers = [("X-Big", "a" * 17_000)]
        assert (await deny(AgentRequest("GET", URL, headers=headers)))[0] == (
            "headers_too_large"
        )

    @pytest.mark.parametrize(
        "request_",
        [
            AgentRequest("GET", "https://api.github.com/{secret}"),
            AgentRequest("GET", "https://api.github.com/?k={secret}"),
            AgentRequest("POST", URL, body=b'{"k":"{secret}"}'),
            AgentRequest("GET", URL, headers={"X-Echo": "{secret}"}),
        ],
    )
    async def test_placeholder_rejected(self, request_: AgentRequest) -> None:
        assert (await deny(request_))[0] == "placeholder_not_allowed"

    @pytest.mark.parametrize("secret", [b"short", b"has\r\nnewline-secret"])
    async def test_unusable_secret(self, secret: bytes) -> None:
        code, _ = await deny(AgentRequest("GET", URL), secret=secret)
        assert code in {"secret_too_short", "secret_not_injectable"}


class TestSSRF:
    @pytest.mark.parametrize(
        "answer",
        [["10.0.0.5"], ["169.254.169.254"], ["::1"], [PUBLIC_IP, "192.168.0.1"]],
    )
    async def test_private_resolution_denied(self, answer: list[str]) -> None:
        code, _ = await deny(AgentRequest("GET", URL), resolver=FakeResolver(answer))
        assert code == "url_rejected"

    async def test_dns_rebinding_resolves_once(self) -> None:
        # First answer is public, any later answer would be internal. The
        # executor must resolve once and connect to the pinned IP.
        resolver = FakeResolver([PUBLIC_IP], ["127.0.0.1"])
        _, upstream = await run(AgentRequest("GET", URL), resolver=resolver)
        assert len(resolver.calls) == 1
        assert upstream.requests[0].url.host == PUBLIC_IP

    async def test_denied_host_never_resolved(self) -> None:
        resolver = FakeResolver()
        await deny(AgentRequest("GET", "https://evilgithub.com/"), resolver=resolver)
        assert resolver.calls == []


class TestResponses:
    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    async def test_redirect_not_followed(self, status: int) -> None:
        location = "https://evil.test/steal?token=" + SECRET.decode()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, headers={"Location": location})

        result, upstream = await run(AgentRequest("GET", URL), handler=handler)
        assert len(upstream.requests) == 1
        assert result.status == status
        headers = {k.lower(): v for k, v in result.headers}
        assert headers["location"] == (
            "https://evil.test/steal?token=" + REDACTED.decode()
        )
        assert result.metadata.redactions == 1

    async def test_body_and_header_redaction_counted(self) -> None:
        b64 = base64.b64encode(SECRET).decode()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"X-Echo": request.headers["authorization"]},
                json={"raw": SECRET.decode(), "b64": b64},
            )

        result, _ = await run(AgentRequest("GET", URL), handler=handler)
        assert SECRET not in result.body
        assert b64.encode() not in result.body
        assert {k.lower(): v for k, v in result.headers}["x-echo"] == REDACTED.decode()
        assert result.metadata.redactions == 3

    async def test_secret_split_across_chunks(self) -> None:
        async def chunks() -> AsyncIterator[bytes]:
            yield b"prefix " + SECRET[:5]
            yield SECRET[5:12]
            yield SECRET[12:] + b" suffix"

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=chunks())

        result, _ = await run(AgentRequest("GET", URL), handler=handler)
        assert result.body == b"prefix " + REDACTED + b" suffix"
        assert result.metadata.redactions == 1

    async def test_response_size_cap(self) -> None:
        async def chunks() -> AsyncIterator[bytes]:
            for _ in range(10):
                yield b"x" * 1000

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=chunks())

        with pytest.raises(EgressError) as exc_info:
            await run(AgentRequest("GET", URL), handler=handler)
        assert exc_info.value.code == "response_too_large"
        assert exc_info.value.metadata.status == 200

    async def test_response_at_cap_allowed(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"x" * 4096)

        result, _ = await run(AgentRequest("GET", URL), handler=handler)
        assert result.metadata.bytes_in == 4096

    async def test_cookies_and_framing_headers_dropped(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Set-Cookie": "sid=abc", "Connection": "close"},
                content=b"ok",
            )

        result, _ = await run(AgentRequest("GET", URL), handler=handler)
        names = {name.lower() for name, _ in result.headers}
        assert not names & {"set-cookie", "connection", "content-length"}

    async def test_transport_error_does_not_leak(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(f"cannot reach {request.url}")

        with pytest.raises(EgressError) as exc_info:
            await run(AgentRequest("GET", URL), handler=handler)
        err = exc_info.value
        assert err.code == "upstream_ConnectError"
        assert err.__cause__ is None
        assert err.__context__ is None
        assert SECRET.decode() not in str(err)

    async def test_timeout(self) -> None:
        import anyio

        async def slow() -> AsyncIterator[bytes]:
            await anyio.sleep(5)
            yield b"late"

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=slow())

        limits = {"req_bytes": 1024, "resp_bytes": 4096, "rpm": 60, "timeout_s": 1}
        with pytest.raises(EgressError) as exc_info:
            await run(AgentRequest("GET", URL), handler=handler, limits=limits)
        assert exc_info.value.code == "timeout"


class TestReviewHardening:
    @pytest.mark.parametrize("encoding", ["x-gzip", "br", "zstd", "gzip, compress"])
    async def test_unsupported_content_encoding_refused(self, encoding: str) -> None:
        async def body() -> AsyncIterator[bytes]:
            yield b"opaque"

        def handler(request: httpx.Request) -> httpx.Response:
            # Streamed, as on a real connection: nothing is decoded before the
            # executor inspects the headers.
            return httpx.Response(
                200, headers={"Content-Encoding": encoding}, content=body()
            )

        with pytest.raises(EgressError) as exc_info:
            await run(AgentRequest("GET", URL), handler=handler)
        assert exc_info.value.code == "unsupported_content_encoding"

    async def test_gzip_is_decoded_then_redacted(self) -> None:
        import gzip

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"Content-Encoding": "gzip"},
                content=gzip.compress(b'{"k":"' + SECRET + b'"}'),
            )

        result, _ = await run(AgentRequest("GET", URL), handler=handler)
        assert result.body == b'{"k":"' + REDACTED + b'"}'

    @pytest.mark.parametrize(
        "secret", [b" leading-space-secret", b"trailing-space-secret ", b"tab\tsecret1"]
    )
    async def test_secret_not_valid_field_value(self, secret: bytes) -> None:
        inject = {"kind": "header", "name": "X-Key", "template": "{secret}"}
        code, _ = await deny(AgentRequest("GET", URL), secret=secret, inject=inject)
        assert code == "secret_not_injectable"

    async def test_error_has_no_exception_context(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(f"cannot reach {request.url}")

        with pytest.raises(EgressError) as exc_info:
            await run(AgentRequest("GET", URL), handler=handler)
        assert exc_info.value.__context__ is None
        assert exc_info.value.__cause__ is None

    async def test_overlong_url_denied(self) -> None:
        request = AgentRequest("GET", "https://api.github.com/" + "a" * 70_000)
        assert (await deny(request))[0] == "url_rejected"

    @pytest.mark.parametrize(
        "query", ["?key=agent", "?KEY=agent", "?a=1;key=agent", "?x=1&Key="]
    )
    async def test_query_param_shadowing_refused(self, query: str) -> None:
        inject = {"kind": "query", "name": "key", "template": "{secret}"}
        request = AgentRequest("GET", "https://api.github.com/r" + query)
        assert (await deny(request, inject=inject))[0] == "query_param_rejected"
