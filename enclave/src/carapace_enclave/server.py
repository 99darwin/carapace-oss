"""The enclave's HTTPS API.

- ``GET /attestation``: a fresh Confidential Space token (audience
  ``carapace-attestation``, nonce = boot id) with the TLS certificate,
  receipt key and KMS public key it vouches for. Clients check the token,
  then that ``sha256(spki || receipt_pubkey)`` is its nonce and that the
  TLS session they are on uses that certificate.
- ``POST /v1/request``: ``Authorization: Bearer cpk_...`` and a JSON body
  ``{secret_id, method, url, headers, body}`` (``body`` is base64). Returns
  ``{status, headers, body}`` from upstream, secret redacted, or
  ``{"error": code}``.
- ``GET /healthz``.

Served over TLS with the boot key (see :mod:`carapace_enclave.tls`).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationError,
)
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from carapace_crypto import b64_decode_strict, b64_encode_std
from carapace_enclave.attestation.identity import BootIdentity
from carapace_enclave.attestation.token import (
    ATTESTATION_AUDIENCE,
    AttestationError,
    TokenSource,
)
from carapace_enclave.broker import Broker, BrokerError
from carapace_enclave.egress import AgentRequest
from carapace_enclave.receipts import ReceiptLog

logger = logging.getLogger(__name__)

# The largest policy request body (10 MiB) in base64, plus JSON framing.
MAX_AGENT_BODY_BYTES = 14 * 1024 * 1024
MAX_HEADERS = 64
TOKEN_REFRESH_INTERVAL_SECONDS = 15 * 60
BEARER_PREFIX = "Bearer "


def _decode_body(value: object) -> bytes:
    return b64_decode_strict(value, name="body")


class AgentRequestIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    secret_id: str = Field(max_length=64)
    method: str = Field(min_length=1, max_length=16)
    url: str = Field(min_length=1, max_length=8 * 1024)
    headers: list[tuple[str, str]] = Field(default_factory=list, max_length=MAX_HEADERS)
    body: Annotated[bytes, BeforeValidator(_decode_body)] = b""


@dataclass(frozen=True, slots=True)
class EnclaveServices:
    identity: BootIdentity
    tokens: TokenSource
    broker: Broker
    receipts: ReceiptLog
    kms_public_key_pem: str
    kms_key_version: str


def _error(status: int, code: str) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=status)


async def _read_limited(request: Request, limit: int) -> bytes | None:
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > limit):
        return None
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def create_app(services: EnclaveServices, *, background: bool = True) -> Starlette:
    """The ASGI app. ``background`` runs the receipt uploader and token refresh."""

    async def attestation(_: Request) -> JSONResponse:
        try:
            token = await asyncio.to_thread(services.tokens.get, ATTESTATION_AUDIENCE)
        except AttestationError as exc:
            logger.error("attestation token unavailable: %s", exc)
            return _error(503, "attestation_unavailable")
        return JSONResponse(
            {
                "token": token.raw,
                "boot_id": services.identity.boot_id,
                "tls_cert_pem": services.identity.tls_cert_pem,
                "receipt_pubkey": b64_encode_std(services.identity.receipt_pubkey),
                "kms_public_key_pem": services.kms_public_key_pem,
                "kms_key_version": services.kms_key_version,
            },
            headers={"Cache-Control": "no-store"},
        )

    async def agent_request(request: Request) -> JSONResponse:
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith(BEARER_PREFIX):
            return _error(401, "invalid_api_key")
        raw = await _read_limited(request, MAX_AGENT_BODY_BYTES)
        if raw is None:
            return _error(413, "request_too_large")
        try:
            parsed = AgentRequestIn.model_validate_json(raw)
        except ValidationError:
            return _error(400, "invalid_request")
        try:
            result = await services.broker.handle(
                authorization.removeprefix(BEARER_PREFIX),
                parsed.secret_id,
                AgentRequest(
                    method=parsed.method,
                    url=parsed.url,
                    headers=parsed.headers,
                    body=parsed.body,
                ),
            )
        except BrokerError as exc:
            return _error(exc.status, exc.code)
        return JSONResponse(
            {
                "status": result.status,
                "headers": [list(pair) for pair in result.headers],
                "body": b64_encode_std(result.body),
            },
            headers={"Cache-Control": "no-store"},
        )

    async def healthz(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        if not background:
            yield
            return
        tasks = [
            asyncio.create_task(services.receipts.run()),
            asyncio.create_task(_refresh_tokens(services.tokens)),
        ]
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            with contextlib.suppress(Exception):
                await services.receipts.flush()

    return Starlette(
        routes=[
            Route("/attestation", attestation, methods=["GET"]),
            Route("/v1/request", agent_request, methods=["POST"]),
            Route("/healthz", healthz, methods=["GET"]),
        ],
        lifespan=lifespan,
    )


async def _refresh_tokens(tokens: TokenSource) -> None:
    """Keep every audience's token, and so the clock floor, current."""
    while True:
        await asyncio.sleep(TOKEN_REFRESH_INTERVAL_SECONDS)
        try:
            await asyncio.to_thread(tokens.refresh_all)
        except AttestationError as exc:
            logger.warning("token refresh failed: %s", exc)
