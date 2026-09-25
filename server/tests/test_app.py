"""Application-wide guards: body size cap and non-echoing validation errors."""

import json
from collections.abc import AsyncIterator

import httpx
import pytest

from carapace_server.app import create_app
from carapace_server.config import MIN_MAX_REQUEST_BODY_BYTES, Settings

pytestmark = pytest.mark.anyio

JSON = {"Content-Type": "application/json"}


@pytest.fixture
async def small_body_client(
    settings: Settings, sessionmaker
) -> AsyncIterator[httpx.AsyncClient]:
    """The app with the smallest body cap the settings allow."""
    capped = settings.model_copy(
        update={"max_request_body_bytes": MIN_MAX_REQUEST_BODY_BYTES}
    )
    app = create_app(capped)
    app.state.sessionmaker = sessionmaker
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def _padded_json(total_bytes: int) -> bytes:
    prefix = b'{"email": "x@example.com", "password": "'
    suffix = b'"}'
    return prefix + b"a" * (total_bytes - len(prefix) - len(suffix)) + suffix


async def test_declared_oversized_body_is_413(small_body_client) -> None:
    body = _padded_json(MIN_MAX_REQUEST_BODY_BYTES + 1)
    response = await small_body_client.post(
        "/v1/auth/register", content=body, headers=JSON
    )
    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}


async def test_streamed_oversized_body_is_413(small_body_client) -> None:
    """No Content-Length: the cap applies as the chunks arrive."""
    chunk = b"a" * 1024

    async def chunks() -> AsyncIterator[bytes]:
        yield b'{"email": "x@example.com", "password": "'
        for _ in range(MIN_MAX_REQUEST_BODY_BYTES // len(chunk) + 1):
            yield chunk
        yield b'"}'

    response = await small_body_client.post(
        "/v1/auth/register", content=chunks(), headers=JSON
    )
    assert response.status_code == 413
    assert "content-length" not in response.request.headers


async def test_body_at_the_cap_is_processed(small_body_client) -> None:
    body = _padded_json(MIN_MAX_REQUEST_BODY_BYTES)
    response = await small_body_client.post(
        "/v1/auth/register", content=body, headers=JSON
    )
    # Reached the route: rejected by validation, not by the cap.
    assert response.status_code == 422


def test_settings_reject_cap_below_floor() -> None:
    with pytest.raises(ValueError):
        Settings(mode="dev", max_request_body_bytes=MIN_MAX_REQUEST_BODY_BYTES - 1)


async def test_validation_errors_do_not_echo_input(client: httpx.AsyncClient) -> None:
    secret = "hunter2-do-not-reflect"
    response = await client.post(
        "/v1/auth/register", json={"email": "not-an-email", "password": secret}
    )
    assert response.status_code == 422
    assert secret not in response.text
    assert "not-an-email" not in response.text
    for error in response.json()["detail"]:
        assert set(error) == {"type", "loc", "msg"}


async def test_deeply_nested_input_is_rejected_not_500(
    client: httpx.AsyncClient, alice
) -> None:
    """The C JSON decoder accepts thousands of levels; nothing after it may
    recurse into them (FastAPI's default 422 handler did, and crashed)."""
    nested: dict = {"v": 1}
    cursor = nested
    for _ in range(5000):
        cursor["x"] = {}
        cursor = cursor["x"]
    headers = {**alice.headers, **JSON}
    body = json.dumps({"name": "x", "envelope": {"policy": nested}})
    response = await client.post("/v1/secrets", content=body, headers=headers)
    assert response.status_code == 422
    body = json.dumps({"name": "x", "lookup_hash": "0" * 64, "grant": nested})
    response = await client.post("/v1/api-keys", content=body, headers=headers)
    assert response.status_code == 400
