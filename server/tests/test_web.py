"""The built web UI is served with security headers; the API is not."""

import os
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from pydantic import ValidationError

from carapace_server.app import create_app
from carapace_server.config import Settings
from carapace_server.web import (
    CONTENT_SECURITY_POLICY,
    WebMount,
    is_hidden,
    is_reserved,
    route_prefixes,
)

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
    assert directives["trusted-types"] == "'none'"
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


async def test_dotfiles_and_outside_symlinks_are_not_served(
    web_settings, web_dir, tmp_path, app
) -> None:
    (web_dir / ".env").write_text("CARAPACE_JWT_SECRET=x")
    (web_dir / ".well-known").mkdir()
    (web_dir / ".well-known" / "x.txt").write_text("hidden")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    (web_dir / "assets" / "link.txt").symlink_to(outside)
    async with _client(web_settings, app) as client:
        responses = [
            await client.get(path)
            for path in ("/.env", "/.well-known/x.txt", "/assets/link.txt")
        ]
    for response in responses:
        assert response.status_code == 404, response.request.url
        assert "CARAPACE" not in response.text
        _assert_security_headers(response)


@pytest.mark.parametrize(
    ("path", "hidden"),
    [(".", False), ("index.html", False), (".env", True), ("a/.b/c", True)],
)
def test_is_hidden(path: str, hidden: bool) -> None:
    assert is_hidden(os.path.normpath(path)) is hidden


# (method, path): the API's own answer, which enabling the UI must not change.
API_MISSES = (
    ("GET", "/v1/auth/login"),  # wrong method: 405 with Allow
    ("POST", "/healthz"),
    ("GET", "/v1/nope"),  # unknown API path: JSON 404
    ("GET", "/v1/secrets/"),  # trailing slash: redirect
)


async def test_enabling_the_ui_changes_no_api_response(settings, web_settings, app):
    async def probe(config: Settings) -> list[tuple[int, str | None, str | None]]:
        async with _client(config, app) as client:
            responses = [
                await client.request(method, path) for method, path in API_MISSES
            ]
        return [
            (r.status_code, r.headers.get("content-type"), r.headers.get("allow"))
            for r in responses
        ]

    without_ui = await probe(settings)
    with_ui = await probe(web_settings)
    assert with_ui == without_ui
    assert [status for status, _, _ in with_ui] == [405, 405, 404, 307]
    assert with_ui[0] == (405, "application/json", "POST")
    async with _client(web_settings, app) as client:
        response = await client.get("/v1/nope")
        assert response.json() == {"detail": "Not Found"}
        assert "content-security-policy" not in response.headers


def test_the_ui_mount_reserves_every_api_root(web_settings) -> None:
    mounts = [
        r for r in create_app(web_settings).router.routes if isinstance(r, WebMount)
    ]
    assert len(mounts) == 1
    assert {"/v1", "/healthz"} <= mounts[0].reserved
    assert "/" not in mounts[0].reserved


def test_route_prefixes() -> None:
    assert route_prefixes(["/v1/secrets", "/v1", "/healthz", "", "x", "/"]) == {
        "/v1",
        "/healthz",
    }


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/v1", True),
        ("/v1/secrets", True),
        ("/v1x", False),
        ("/healthz", True),
        ("/", False),
        ("/assets/index-abc123.js", False),
    ],
)
def test_is_reserved(path: str, expected: bool) -> None:
    assert is_reserved(path, {"/v1", "/healthz"}) is expected
