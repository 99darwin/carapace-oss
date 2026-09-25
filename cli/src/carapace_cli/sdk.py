"""Python SDK: make an HTTP request through the enclave with a secret.

    from carapace_cli import Client

    client = Client()  # CARAPACE_API_KEY, pin from `carapace verify`
    response = client.request(SECRET_ID, "GET", "https://api.github.com/user")
    print(response.status, response.json())

The API key comes from the ``api_key`` argument or ``CARAPACE_API_KEY``,
never from a file this module writes or a log line. Every call goes over
TLS pinned to the enclave certificate that ``carapace verify`` attested.
"""

from __future__ import annotations

import json as jsonlib
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from carapace_cli.errors import CarapaceError, EnclaveError
from carapace_cli.files import default_config_dir
from carapace_cli.pin import (
    REQUEST_TIMEOUT_SECONDS,
    EnclavePin,
    load_pin,
    pinned_client,
)
from carapace_crypto import ApiKey, ApiKeyError, b64_decode_strict, b64_encode_std

API_KEY_ENV = "CARAPACE_API_KEY"
MAX_ENCLAVE_RESPONSE_BYTES = 40 * 1024 * 1024

HeadersInput = Mapping[str, str] | Iterable[tuple[str, str]]


@dataclass(frozen=True)
class Response:
    """The upstream response, as relayed by the enclave (secret redacted)."""

    status: int
    headers: list[tuple[str, str]]
    content: bytes = field(repr=False)

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return None

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return jsonlib.loads(self.content)


class Client:
    """Requests through the pinned enclave with one API key."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        config_dir: Path | None = None,
        pin: EnclavePin | None = None,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        raw = api_key if api_key is not None else os.environ.get(API_KEY_ENV)
        if not raw:
            raise CarapaceError(f"no API key: pass api_key or set {API_KEY_ENV}")
        try:
            self._api_key = ApiKey.parse(raw.strip())
        except ApiKeyError:
            raise CarapaceError("the API key is malformed") from None
        self._pin = pin or load_pin(config_dir or default_config_dir())
        self._timeout = timeout

    def __repr__(self) -> str:
        return f"Client(enclave={self._pin.enclave_url!r}, api_key=<redacted>)"

    def request(
        self,
        secret_id: str,
        method: str,
        url: str,
        *,
        headers: HeadersInput | None = None,
        body: bytes | None = None,
        json: Any = None,
    ) -> Response:
        """Send ``method url`` upstream with ``secret_id`` injected by policy.

        Raises:
            EnclaveError: The enclave refused (bad key, out-of-policy URL,
                rate limit...) or the upstream call failed.
            PinError: The enclave's certificate is not the pinned one.
        """
        if body is not None and json is not None:
            raise ValueError("pass body or json, not both")
        header_list = _header_list(headers)
        if json is not None:
            body = jsonlib.dumps(json).encode()
            if not any(k.lower() == "content-type" for k, _ in header_list):
                header_list.append(("Content-Type", "application/json"))
        payload = {
            "secret_id": secret_id,
            "method": method.upper(),
            "url": url,
            "headers": [list(pair) for pair in header_list],
            "body": b64_encode_std(body or b""),
        }
        with pinned_client(
            self._pin.enclave_url, self._pin.tls_cert_pem, timeout=self._timeout
        ) as client:
            response = client.post(
                "/v1/request",
                json=payload,
                headers={"Authorization": f"Bearer {self._api_key.raw}"},
            )
        return _parse_response(response.status_code, response.content)


def _header_list(headers: HeadersInput | None) -> list[tuple[str, str]]:
    if headers is None:
        return []
    items = headers.items() if isinstance(headers, Mapping) else headers
    return [(str(k), str(v)) for k, v in items]


def _parse_response(status: int, content: bytes) -> Response:
    if len(content) > MAX_ENCLAVE_RESPONSE_BYTES:
        raise EnclaveError(status, "response_too_large")
    try:
        data = jsonlib.loads(content)
    except (UnicodeDecodeError, ValueError):
        raise EnclaveError(status, "malformed_response") from None
    if not isinstance(data, dict):
        raise EnclaveError(status, "malformed_response")
    if status != 200:
        code = data.get("error")
        raise EnclaveError(status, code[:64] if isinstance(code, str) else "error")
    try:
        return Response(
            status=int(data["status"]),
            headers=[(str(k), str(v)) for k, v in data["headers"]],
            content=b64_decode_strict(data["body"], name="body"),
        )
    except (KeyError, TypeError, ValueError):
        raise EnclaveError(status, "malformed_response") from None
