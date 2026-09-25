"""The control-plane session: login, token storage and authenticated calls.

Tokens live in ``session.json`` (0600) next to the owner key. The access
token is refreshed once on a 401 using the refresh token, and the rotated
pair is written back atomically. Tokens never appear in messages or logs.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from carapace_cli.errors import (
    NotLoggedInError,
    ServerError,
    StorageError,
    network_errors,
)
from carapace_cli.files import read_private_json, write_private_json
from carapace_cli.urls import normalize_base_url

SESSION_FILE = "session.json"
REQUEST_TIMEOUT_SECONDS = 30.0
MAX_DETAIL_CHARS = 300


@dataclass
class Session:
    server_url: str
    user_id: str
    access_token: str
    refresh_token: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_url": self.server_url,
            "user_id": self.user_id,
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
        }

    def __repr__(self) -> str:
        return f"Session(server_url={self.server_url!r}, user_id={self.user_id!r})"


def session_path(config_dir: Path) -> Path:
    return config_dir / SESSION_FILE


def load_session(config_dir: Path) -> Session:
    path = session_path(config_dir)
    if not path.exists():
        raise NotLoggedInError("not logged in; run: carapace login")
    try:
        data = read_private_json(path)
        return Session(
            server_url=str(data["server_url"]),
            user_id=str(data["user_id"]),
            access_token=str(data["access_token"]),
            refresh_token=str(data["refresh_token"]),
        )
    except (KeyError, StorageError) as exc:
        raise NotLoggedInError(f"session file is unusable: {exc}") from None


def save_session(config_dir: Path, session: Session) -> None:
    write_private_json(session_path(config_dir), session.to_dict())


def _session_from_tokens(server_url: str, body: Any) -> Session:
    try:
        return Session(
            server_url=server_url,
            user_id=str(body["user_id"]),
            access_token=str(body["access_token"]),
            refresh_token=str(body["refresh_token"]),
        )
    except (KeyError, TypeError):
        raise ServerError(200, "malformed token response") from None


def raise_for_status(response: httpx.Response) -> None:
    if response.is_success:
        return
    detail: Any = None
    with contextlib.suppress(ValueError, AttributeError):
        detail = response.json().get("detail")
    if not isinstance(detail, str):
        detail = response.reason_phrase or "error"
    raise ServerError(response.status_code, detail[:MAX_DETAIL_CHARS])


def authenticate(
    server_url: str,
    email: str,
    password: str,
    *,
    register: bool = False,
    transport: httpx.BaseTransport | None = None,
) -> Session:
    """Log in (or register) and return a new session. Does not save it."""
    server_url = normalize_base_url(server_url, what="server", allow_loopback_http=True)
    path = "/v1/auth/register" if register else "/v1/auth/login"
    with (
        network_errors("server"),
        httpx.Client(
            base_url=server_url,
            timeout=REQUEST_TIMEOUT_SECONDS,
            transport=transport,
            follow_redirects=False,
        ) as client,
    ):
        response = client.post(path, json={"email": email, "password": password})
    raise_for_status(response)
    return _session_from_tokens(server_url, _json(response))


class ServerClient:
    """Authenticated JSON calls to the control plane for one session."""

    def __init__(
        self,
        config_dir: Path,
        *,
        session: Session | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._config_dir = config_dir
        self.session = session or load_session(config_dir)
        self._http = httpx.Client(
            base_url=self.session.server_url,
            timeout=REQUEST_TIMEOUT_SECONDS,
            transport=transport,
            follow_redirects=False,
        )

    @property
    def server_url(self) -> str:
        return self.session.server_url

    @property
    def user_id(self) -> str:
        return self.session.user_id

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> ServerClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def get(self, path: str, **kwargs: Any) -> Any:
        return self.call("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Any:
        return self.call("POST", path, **kwargs)

    def call(self, method: str, path: str, **kwargs: Any) -> Any:
        """Send one request; returns the parsed JSON body, or None for 204."""
        with network_errors("server"):
            response = self._send(method, path, **kwargs)
            if response.status_code == httpx.codes.UNAUTHORIZED:
                self._refresh()
                response = self._send(method, path, **kwargs)
        raise_for_status(response)
        if response.status_code == httpx.codes.NO_CONTENT or not response.content:
            return None
        return _json(response)

    def logout(self) -> None:
        with network_errors("server"):
            response = self._http.post(
                "/v1/auth/logout",
                json={
                    "refresh_token": self.session.refresh_token,
                    "access_token": self.session.access_token,
                },
            )
        if response.status_code not in (httpx.codes.NO_CONTENT, 401):
            raise_for_status(response)

    def _send(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self.session.access_token}"}
        return self._http.request(method, path, headers=headers, **kwargs)

    def _refresh(self) -> None:
        response = self._http.post(
            "/v1/auth/refresh", json={"refresh_token": self.session.refresh_token}
        )
        if not response.is_success:
            raise NotLoggedInError("session expired; run: carapace login")
        self.session = _session_from_tokens(self.session.server_url, _json(response))
        save_session(self._config_dir, self.session)


def _json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        raise ServerError(response.status_code, "response is not JSON") from None
