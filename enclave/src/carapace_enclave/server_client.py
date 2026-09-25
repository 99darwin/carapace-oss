"""The enclave's client for the control plane's ``/internal`` API.

Every call carries an attestation token whose audience is the control-plane
URL. Every call except boot registration is also signed with the boot's
receipt key, exactly as ``carapace_server.internal.deps`` checks it::

    message = "carapace-internal-v1\\n" METHOD "\\n" PATH[?QUERY] "\\n"
              TIMESTAMP "\\n" hex(sha256(body))

The server is untrusted: responses are size-capped and returned as bytes
for the caller to verify, and errors carry a status, never a body.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from typing import Any

import httpx

from carapace_crypto import b64_encode_std
from carapace_enclave.attestation.identity import BootIdentity
from carapace_enclave.attestation.token import TokenSource
from carapace_enclave.clock import TrustedClock

REQUEST_SIGNATURE_CONTEXT = b"carapace-internal-v1"
MAX_RESPONSE_BYTES = 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 10.0

BOOTS_PATH = "/internal/boots"
KEYS_VERIFY_PATH = "/internal/keys/verify"
RECEIPTS_PATH = "/internal/receipts"
SECRETS_PATH = "/internal/secrets/{secret_id}"


class ControlPlaneError(Exception):
    """The control plane failed or refused. ``status`` is None if unreachable."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class ControlPlaneNotFoundError(ControlPlaneError):
    """404: an unknown key or secret."""


def request_signing_bytes(method: str, path: str, timestamp: int, body: bytes) -> bytes:
    """The bytes signed for an ``/internal`` call; mirrors the server."""
    return b"\n".join(
        (
            REQUEST_SIGNATURE_CONTEXT,
            method.upper().encode("ascii"),
            path.encode("ascii"),
            str(timestamp).encode("ascii"),
            hashlib.sha256(body).hexdigest().encode("ascii"),
        )
    )


def _json_body(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


class ControlPlaneClient:
    """Authenticated, signed calls to ``/internal``. Async; one per boot."""

    def __init__(
        self,
        *,
        base_url: str,
        tokens: TokenSource,
        identity: BootIdentity,
        clock: TrustedClock,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._audience = base_url
        self._tokens = tokens
        self._identity = identity
        self._clock = clock
        self._client = httpx.AsyncClient(
            base_url=base_url,
            transport=transport,
            timeout=REQUEST_TIMEOUT_SECONDS,
            follow_redirects=False,
            trust_env=False,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def register_boot(self) -> None:
        """Bind this boot's TLS and receipt keys to its attestation nonce."""
        body = _json_body(
            {
                "receipt_pubkey": b64_encode_std(self._identity.receipt_pubkey),
                "tls_cert_pem": self._identity.tls_cert_pem,
            }
        )
        await self._call("POST", BOOTS_PATH, body, label="boots", signed=False)

    async def fetch_grant(self, lookup_hash: bytes, secret_id: str) -> bytes:
        """The raw ``{"grant": ...}`` response for a key. 404 raises NotFound."""
        body = _json_body({"key_hash": lookup_hash.hex(), "secret_id": secret_id})
        return await self._call("POST", KEYS_VERIFY_PATH, body, label="keys/verify")

    async def fetch_envelope(self, secret_id: str) -> bytes:
        """The raw envelope JSON for ``secret_id``. 404 raises NotFound."""
        path = SECRETS_PATH.format(secret_id=uuid.UUID(secret_id))
        return await self._call("GET", path, b"", label="secrets")

    async def upload_receipts(self, receipts: list[dict[str, Any]]) -> bytes:
        body = _json_body({"receipts": receipts})
        return await self._call("POST", RECEIPTS_PATH, body, label="receipts")

    async def _call(
        self, method: str, path: str, body: bytes, *, label: str, signed: bool = True
    ) -> bytes:
        token = await asyncio.to_thread(self._tokens.get, self._audience)
        headers = {"Authorization": f"Bearer {token.raw}"}
        if body:
            headers["Content-Type"] = "application/json"
        request = self._client.build_request(
            method, path, content=body, headers=headers
        )
        if signed:
            # Sign the path exactly as it goes on the wire, query included.
            timestamp = self._clock.now()
            message = request_signing_bytes(
                method, request.url.raw_path.decode("ascii"), timestamp, body
            )
            request.headers["X-Carapace-Timestamp"] = str(timestamp)
            request.headers["X-Carapace-Signature"] = b64_encode_std(
                self._identity.receipt_key.sign(message)
            )
        failure: str | None = None
        try:
            response = await self._client.send(request, stream=True)
        except httpx.HTTPError as exc:
            # Raised outside the except block so no context (which could
            # hold request headers) is chained.
            failure = type(exc).__name__
        if failure is not None:
            raise ControlPlaneError(f"control plane unreachable: {failure}")
        try:
            return await _read_capped(response, f"{method} {label}")
        finally:
            await response.aclose()


async def _read_capped(response: httpx.Response, where: str) -> bytes:
    status = response.status_code
    if status == httpx.codes.NOT_FOUND:
        raise ControlPlaneNotFoundError(f"{where}: not found", status)
    if not 200 <= status < 300:
        raise ControlPlaneError(f"{where}: HTTP {status}", status)
    chunks: list[bytes] = []
    size = 0
    try:
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise ControlPlaneError(f"{where}: response too large", status)
            chunks.append(chunk)
    except httpx.HTTPError:
        raise ControlPlaneError(f"{where}: response interrupted", status) from None
    return b"".join(chunks)
