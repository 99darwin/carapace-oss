"""The built web UI is served with security headers; the API is not."""

from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError

from carapace_server.app import create_app
from carapace_server.config import Settings
from carapace_server.web import CONTENT_SECURITY_POLICY

pytestmark = pytest.mark.anyio

INDEX = "<!doctype html><title>Carapace</title>"


@pytest.fixture
def web_dir(tmp_path: Path) -> Path:
    root = tmp_path / "dist"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text(INDEX)
    (root / "assets" / "index-abc123.js").write_text("export {};")
    return root


def _client(settings: Settings, app_state: FastAPI) -> httpx.AsyncClient:
    app = create_app(settings)
    app.state.sessionmaker = app_state.state.sessionmaker
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.fixture
def web_settings(settings: Settings, web_dir: Path) -> Settings:
    return settings.model_copy(update={"web_dir": web_dir})


def _assert_security_headers(response: httpx.Response) -> None:
    assert response.headers["content-security-policy"] == CONTENT_SECURITY_POLICY
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    assert "camera=()" in response.headers["permissions-policy"]


def test_csp_is_strict() -> None:
    directives = dict(d.split(" ", 1) for d in CONTENT_SECURITY_POLICY.split("; "))
    assert directives["default-src"] == "'none'"
    assert directives["script-src"] == "'self'"
    assert directives["frame-ancestors"] == "'none'"
    assert directives["require-trusted-types-for"] == "'script'"
    assert "unsafe" not in CONTENT_SECURITY_POLICY


async def test_index_headers(web_settings, app) -> None:
    async with _client(web_settings, app) as client:
        for path in ("/", "/index.html"):
            response = await client.get(path)
            assert response.status_code == 200
            assert response.text == INDEX
            _assert_security_headers(response)
            assert response.headers["cache-control"] == "no-cache"
            assert "strict-transport-security" not in response.headers


async def test_hashed_assets_are_immutable(web_settings, app) -> None:
    async with _client(web_settings, app) as client:
        response = await client.get("/assets/index-abc123.js")
    assert response.status_code == 200
    _assert_security_headers(response)
    assert "immutable" in response.headers["cache-control"]


async def test_missing_file_and_bad_method_keep_headers(web_settings, app) -> None:
    async with _client(web_settings, app) as client:
        missing = await client.get("/assets/nope.js")
        post = await client.post("/")
        traversal = await client.get("/../pyproject.toml")
    assert missing.status_code == 404
    assert missing.headers["cache-control"] == "no-cache"
    assert post.status_code == 405
    assert traversal.status_code == 404
    for response in (missing, post, traversal):
        _assert_security_headers(response)


async def test_hsts_only_for_https(web_settings, app) -> None:
    https = web_settings.model_copy(update={"public_url": "https://c.example"})
    async with _client(https, app) as client:
        response = await client.get("/")
    assert "max-age=" in response.headers["strict-transport-security"]


async def test_api_routes_win_and_skip_headers(web_settings, app, alice) -> None:
    async with _client(web_settings, app) as client:
        health = await client.get("/healthz")
        secrets = await client.get("/v1/secrets", headers=alice.headers)
    assert health.json() == {"status": "ok"}
    assert secrets.status_code == 200
    for response in (health, secrets):
        assert "content-security-policy" not in response.headers
        assert "access-control-allow-origin" not in response.headers


async def test_no_web_dir_serves_nothing(client) -> None:
    response = await client.get("/")
    assert response.status_code == 404
    assert "content-security-policy" not in response.headers


def test_web_dir_must_exist(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        Settings(mode="dev", web_dir=tmp_path / "missing")
