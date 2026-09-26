"""Serve the built web UI with strict security headers.

The headers go on static responses only. API responses are JSON consumed by
``fetch`` and never rendered, and adding a CSP there would only get in the
way of the CLI. There is deliberately no CORS: the UI is same-origin, and
the Vite dev server proxies ``/v1`` in development.
"""

from __future__ import annotations

import os
from collections.abc import Iterable

from starlette.exceptions import HTTPException
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Match, Mount
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Scope

CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self'",
        "connect-src 'self'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "require-trusted-types-for 'script'",
        # No policy may be created, so nothing can launder a string into
        # a DOM sink: React and Vite's output need none.
        "trusted-types 'none'",
    )
)
PERMISSIONS_POLICY = ", ".join(
    f"{feature}=()"
    for feature in (
        "accelerometer",
        "camera",
        "clipboard-read",
        "geolocation",
        "gyroscope",
        "magnetometer",
        "microphone",
        "payment",
        "usb",
    )
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": PERMISSIONS_POLICY,
}
HSTS_VALUE = "max-age=63072000; includeSubDomains"
# Vite puts a content hash in every file name under assets/.
HASHED_ASSETS_PREFIX = "assets" + os.sep
IMMUTABLE_CACHE = "public, max-age=31536000, immutable"
REVALIDATE_CACHE = "no-cache"


def is_hidden(path: str) -> bool:
    """True if any component of the normalised path is a dotfile.

    ``StaticFiles`` serves anything under the directory, so a stray
    ``.env`` or ``.git`` copied next to the build would be public. The root
    itself normalises to ``"."`` and is not hidden.
    """
    return any(part.startswith(".") and part != "." for part in path.split(os.sep))


class SecureStaticFiles(StaticFiles):
    """``StaticFiles`` that adds security and cache headers to every response.

    Error responses (404, 405) get the same headers, so a missing path never
    renders without the CSP. Dotfiles are never served.
    """

    def __init__(self, *, directory: str | os.PathLike[str], hsts: bool) -> None:
        super().__init__(directory=directory, html=True)
        self._hsts = hsts

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            if is_hidden(path):
                raise HTTPException(status_code=404)
            response = await super().get_response(path, scope)
        except HTTPException as exc:
            response = PlainTextResponse(exc.detail, status_code=exc.status_code)
        response.headers.update(SECURITY_HEADERS)
        if self._hsts:
            response.headers["Strict-Transport-Security"] = HSTS_VALUE
        is_hashed = path.startswith(HASHED_ASSETS_PREFIX) and response.status_code < 400
        response.headers["Cache-Control"] = (
            IMMUTABLE_CACHE if is_hashed else REVALIDATE_CACHE
        )
        return response


def route_prefixes(paths: Iterable[str]) -> frozenset[str]:
    """The first segment of each path: ``/v1/secrets`` and ``/v1`` give ``/v1``.

    Empty paths and anything not rooted at ``/`` contribute nothing.
    """
    prefixes: set[str] = set()
    for path in paths:
        if not path.startswith("/"):
            continue
        segment = path.split("/", 2)[1]
        if segment:
            prefixes.add("/" + segment)
    return frozenset(prefixes)


def is_reserved(path: str, prefixes: Iterable[str]) -> bool:
    """True if ``path`` is one of ``prefixes`` or lies under one of them."""
    return any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)


def _route_path(scope: Scope) -> str:
    """The path the router matches on: ``scope["path"]`` minus its root_path."""
    path: str = scope["path"]
    root_path: str = scope.get("root_path", "")
    if not root_path or not path.startswith(root_path):
        return path
    rest = path[len(root_path) :]
    return rest if rest == "" or rest.startswith("/") else path


class WebMount(Mount):
    """A ``Mount("/")`` for the UI that leaves the API's paths to the router.

    The router takes the first full match, and a mount at ``/`` fully
    matches every path. Without this, any request no API route fully
    matched would land on the UI: a wrong method would get its plain-text
    404 instead of the API's JSON 405 with ``Allow``, an unknown ``/v1``
    path a plain-text 404 instead of the JSON one, and a trailing slash no
    redirect at all. Declining every path under a prefix the API owns
    keeps those responses exactly as they are without the UI.
    """

    def __init__(self, app: ASGIApp, *, reserved: Iterable[str]) -> None:
        super().__init__("/", app=app, name="web")
        self.reserved = frozenset(reserved)

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        if scope["type"] in ("http", "websocket") and is_reserved(
            _route_path(scope), self.reserved
        ):
            return Match.NONE, {}
        return super().matches(scope)
