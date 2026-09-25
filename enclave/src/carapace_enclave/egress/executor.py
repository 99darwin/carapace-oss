"""Generic credential-injecting egress executor.

One request in, one response out. For each agent request the executor:

1. Parses the URL (HTTPS only) and checks the host against the policy
   allowlist, then the method and port.
2. Rejects agent headers that could redirect, smuggle or impersonate the
   injected credential, and any ``{secret}`` placeholder in the request.
3. Resolves DNS once through :class:`URLFilter` and connects to that IP, with
   TLS SNI and ``Host`` set to the allowlisted hostname (certificate
   verification uses the hostname, not the IP).
4. Injects the secret, sends the request without following redirects, and
   streams the response up to the policy's byte cap.
5. Redacts the secret from response headers and body.

Errors never include the secret or the outgoing URL.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote_from_bytes

import httpx

from carapace_enclave.egress.policy import (
    FORBIDDEN_INJECTION_HEADERS,
    SECRET_PLACEHOLDER,
    InjectionPolicy,
    is_token,
)
from carapace_enclave.egress.redact import Redactor
from carapace_enclave.egress.url_filter import (
    HTTPS_DEFAULT_PORT,
    PinnedTarget,
    URLFilter,
    URLFilterError,
    parse_url,
)

MIN_SECRET_BYTES = 8
MAX_REQUEST_HEADERS = 64
MAX_HEADER_BYTES = 16 * 1024
_PLACEHOLDER = SECRET_PLACEHOLDER.encode("ascii")
_UNSAFE_SECRET_BYTES = frozenset(b"\r\n\x00")
# Response headers dropped before returning: hop-by-hop, framing (the body is
# decoded and rewritten), and cookies (a session cookie is a credential).
_DROPPED_RESPONSE_HEADERS = frozenset(
    {
        b"connection",
        b"keep-alive",
        b"transfer-encoding",
        b"content-encoding",
        b"content-length",
        b"set-cookie",
        b"set-cookie2",
        b"proxy-authenticate",
        b"trailer",
        b"upgrade",
    }
)

TransportFactory = Callable[[], httpx.AsyncBaseTransport]


def _default_transport() -> httpx.AsyncBaseTransport:
    # A fresh transport per request: pooled connections are keyed by IP, and
    # must never be reused under a different SNI hostname.
    return httpx.AsyncHTTPTransport(retries=0, http1=True, http2=False)


class EgressDenied(Exception):
    """The request violates the policy. ``code`` is safe to return to agents."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class EgressError(Exception):
    """The upstream request failed after passing policy checks."""

    def __init__(self, code: str, metadata: ReceiptMetadata) -> None:
        self.code = code
        self.metadata = metadata
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class AgentRequest:
    method: str
    url: str
    headers: Sequence[tuple[str, str]] | Mapping[str, str] = ()
    body: bytes = b""


@dataclass(frozen=True, slots=True)
class ReceiptMetadata:
    method: str
    host: str
    path_hash: str  # sha256 hex of the agent's path+query, before injection
    status: int | None = None
    bytes_in: int = 0  # response body bytes received (decoded)
    bytes_out: int = 0  # request body bytes sent
    redactions: int = 0


@dataclass(frozen=True, slots=True)
class EgressResult:
    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    metadata: ReceiptMetadata | None = None


class EgressExecutor:
    def __init__(
        self,
        url_filter: URLFilter | None = None,
        transport_factory: TransportFactory = _default_transport,
    ) -> None:
        self._url_filter = url_filter or URLFilter()
        self._transport_factory = transport_factory

    async def execute(
        self,
        policy: InjectionPolicy,
        secret: bytes | bytearray,
        request: AgentRequest,
    ) -> EgressResult:
        """Run one agent request. Raises EgressDenied or EgressError."""
        if len(secret) < MIN_SECRET_BYTES:
            raise EgressDenied("secret_too_short")
        if _UNSAFE_SECRET_BYTES.intersection(secret):
            raise EgressDenied("secret_not_injectable")

        method = request.method.upper()
        try:
            url = parse_url(request.url)
        except URLFilterError as exc:
            raise EgressDenied("url_rejected", exc.reason) from None
        if not policy.allows_host(url.host):
            raise EgressDenied("host_not_allowed", url.host)
        if method not in policy.methods:
            raise EgressDenied("method_not_allowed", method)
        if url.port not in policy.ports:
            raise EgressDenied("port_not_allowed", str(url.port))
        if len(request.body) > policy.limits.req_bytes:
            raise EgressDenied("request_too_large")
        headers = _validate_headers(request.headers, policy)
        if _PLACEHOLDER in url.target.encode() or _PLACEHOLDER in request.body:
            raise EgressDenied("placeholder_not_allowed")

        metadata = ReceiptMetadata(
            method=method,
            host=url.host,
            path_hash=hashlib.sha256(url.target.encode("ascii")).hexdigest(),
            bytes_out=len(request.body),
        )
        try:
            pinned = await self._url_filter.pin(url)
        except URLFilterError as exc:
            raise EgressDenied("url_rejected", exc.reason) from None

        rendered = policy.inject.template.encode("ascii").replace(
            _PLACEHOLDER, bytes(secret)
        )
        target, headers = _inject(policy, rendered, url.target, headers)
        redactor = Redactor(_redaction_values(policy, bytes(secret), rendered))

        try:
            async with asyncio.timeout(policy.limits.timeout_s):
                return await self._send(
                    pinned,
                    method,
                    target,
                    headers,
                    request.body,
                    policy,
                    redactor,
                    metadata,
                )
        except TimeoutError:
            raise EgressError("timeout", metadata) from None
        except httpx.HTTPError as exc:
            # Never chain: httpx exceptions can carry the injected URL.
            raise EgressError(f"upstream_{type(exc).__name__}", metadata) from None

    async def _send(
        self,
        pinned: PinnedTarget,
        method: str,
        target: bytes,
        headers: list[tuple[bytes, bytes]],
        body: bytes,
        policy: InjectionPolicy,
        redactor: Redactor,
        metadata: ReceiptMetadata,
    ) -> EgressResult:
        url = pinned.url
        host_header = url.host
        if url.port != HTTPS_DEFAULT_PORT:
            host_header = f"{url.host}:{url.port}"
        headers = [
            (b"Host", host_header.encode("ascii")),
            (b"Accept-Encoding", b"identity"),
            *headers,
        ]
        request = httpx.Request(
            method,
            httpx.URL(scheme="https", host=pinned.ip, port=url.port, raw_path=target),
            headers=headers,
            content=body,
            extensions={"sni_hostname": url.host},
        )
        cap = policy.limits.resp_bytes
        async with httpx.AsyncClient(
            transport=self._transport_factory(),
            follow_redirects=False,
            trust_env=False,
            timeout=policy.limits.timeout_s,
        ) as client:
            response = await client.send(request, stream=True)
            try:
                chunks: list[bytes] = []
                received = 0
                async for chunk in response.aiter_bytes():
                    received += len(chunk)
                    if received > cap:
                        raise EgressError(
                            "response_too_large",
                            dataclasses.replace(metadata, status=response.status_code),
                        )
                    chunks.append(chunk)
            finally:
                await response.aclose()

        body_out, body_hits = redactor.redact(b"".join(chunks))
        kept = [
            (name, value)
            for name, value in response.headers.raw
            if name.lower() not in _DROPPED_RESPONSE_HEADERS
        ]
        headers_out, header_hits = redactor.redact_headers(kept)
        return EgressResult(
            status=response.status_code,
            headers=[
                (n.decode("latin-1"), v.decode("latin-1")) for n, v in headers_out
            ],
            body=body_out,
            metadata=dataclasses.replace(
                metadata,
                status=response.status_code,
                bytes_in=received,
                redactions=body_hits + header_hits,
            ),
        )


def _validate_headers(
    raw: Sequence[tuple[str, str]] | Mapping[str, str], policy: InjectionPolicy
) -> list[tuple[bytes, bytes]]:
    items = list(raw.items()) if isinstance(raw, Mapping) else list(raw)
    if len(items) > MAX_REQUEST_HEADERS:
        raise EgressDenied("too_many_headers")
    injected = policy.inject.header_name
    result: list[tuple[bytes, bytes]] = []
    size = 0
    for name, value in items:
        if not isinstance(name, str) or not isinstance(value, str):
            raise EgressDenied("header_rejected", "headers must be strings")
        lowered = name.lower()
        if not is_token(name):
            raise EgressDenied("header_rejected", "invalid header name")
        if (
            lowered in FORBIDDEN_INJECTION_HEADERS
            or lowered.startswith("proxy-")
            or lowered == injected
        ):
            raise EgressDenied("header_rejected", lowered)
        if any(ch in value for ch in "\r\n\x00") or not value.isascii():
            raise EgressDenied("header_rejected", f"invalid value for {lowered}")
        if SECRET_PLACEHOLDER in value or SECRET_PLACEHOLDER in name:
            raise EgressDenied("placeholder_not_allowed")
        size += len(name) + len(value)
        result.append((name.encode("ascii"), value.encode("ascii")))
    if size > MAX_HEADER_BYTES:
        raise EgressDenied("headers_too_large")
    return result


def _inject(
    policy: InjectionPolicy,
    rendered: bytes,
    target: str,
    headers: list[tuple[bytes, bytes]],
) -> tuple[bytes, list[tuple[bytes, bytes]]]:
    inject = policy.inject
    name = inject.name or ""
    if inject.kind == "header":
        return target.encode("ascii"), [*headers, (name.encode("ascii"), rendered)]
    if inject.kind == "basic_auth":
        value = b"Basic " + base64.b64encode(rendered)
        return target.encode("ascii"), [*headers, (b"Authorization", value)]
    path, _, query = target.partition("?")
    existing = {key for key, _ in parse_qsl(query, keep_blank_values=True)}
    if name in existing:
        raise EgressDenied("query_param_rejected", name)
    param = f"{name}=".encode() + quote_from_bytes(rendered, safe="").encode()
    joined = f"{path}?{query}&" if query else f"{path}?"
    return joined.encode("ascii") + param, headers


def _redaction_values(
    policy: InjectionPolicy, secret: bytes, rendered: bytes
) -> list[bytes]:
    values = [secret, rendered]
    if policy.inject.kind == "basic_auth":
        values.append(base64.b64encode(rendered))
    return values
