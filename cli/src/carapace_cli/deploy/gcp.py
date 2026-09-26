"""A small Google Cloud REST client on httpx, authenticated with ADC.

The deploy flow needs a handful of calls across Resource Manager, Cloud
Billing, KMS, Storage, Compute and Artifact Registry. Plain REST keeps the
dependency to ``google-auth`` and makes every call easy to mock with an
``httpx.MockTransport``. Access tokens are sent only to ``*.googleapis.com``
and never appear in messages.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterator
from typing import Any, Protocol

import httpx

from carapace_cli.errors import CarapaceError, network_errors

CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
ADC_LOGIN_HINT = "run: gcloud auth application-default login"
REQUEST_TIMEOUT_SECONDS = 60.0
MAX_MESSAGE_CHARS = 300
MAX_PAGES = 20
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_CONFLICT = 409
SERVICE_DISABLED_REASON = "SERVICE_DISABLED"
GOOGLE_API_SUFFIX = ".googleapis.com"

RESOURCE_MANAGER = "https://cloudresourcemanager.googleapis.com/v1"
BILLING = "https://cloudbilling.googleapis.com/v1"
KMS = "https://cloudkms.googleapis.com/v1"
COMPUTE = "https://compute.googleapis.com/compute/v1"
STORAGE = "https://storage.googleapis.com/storage/v1"
SERVICE_USAGE = "https://serviceusage.googleapis.com/v1"
RUN = "https://run.googleapis.com/v2"


class GcpError(CarapaceError):
    """A Google API call failed. ``str(exc)`` holds Google's message only."""

    def __init__(self, status: int, message: str, *, reason: str = "") -> None:
        super().__init__(f"Google API returned {status}: {message}")
        self.status = status
        self.reason = reason

    @property
    def service_disabled(self) -> bool:
        return self.reason == SERVICE_DISABLED_REASON


class CredentialsError(CarapaceError):
    """No usable Application Default Credentials."""


class TokenSource(Protocol):
    def token(self) -> str: ...

    @property
    def quota_project(self) -> str | None: ...


class AdcTokenSource:
    """Application Default Credentials via ``google-auth``, refreshed lazily."""

    def __init__(self) -> None:
        try:
            google_auth = importlib.import_module("google.auth")
            exceptions = importlib.import_module("google.auth.exceptions")
            self._request = importlib.import_module("google.auth.transport.requests")
        except ImportError:
            raise CredentialsError(
                "google-auth is missing; install carapace-cli[deploy]"
            ) from None
        self._refresh_error = exceptions.RefreshError
        try:
            self._credentials, _ = google_auth.default(scopes=[CLOUD_PLATFORM_SCOPE])
        except exceptions.DefaultCredentialsError:
            raise CredentialsError(
                f"no Application Default Credentials; {ADC_LOGIN_HINT}"
            ) from None

    @property
    def quota_project(self) -> str | None:
        return getattr(self._credentials, "quota_project_id", None)

    def token(self) -> str:
        if not self._credentials.valid:
            try:
                self._credentials.refresh(self._request.Request())
            except self._refresh_error:
                raise CredentialsError(
                    f"Application Default Credentials expired; {ADC_LOGIN_HINT}"
                ) from None
        return str(self._credentials.token)


def _error_from(response: httpx.Response) -> GcpError:
    try:
        error = response.json().get("error", {})
    except ValueError:
        error = {}
    if not isinstance(error, dict):
        error = {}
    message = str(error.get("message") or response.reason_phrase)
    reason = ""
    for detail in error.get("details") or []:
        if isinstance(detail, dict) and detail.get("reason"):
            reason = str(detail["reason"])
            break
    return GcpError(response.status_code, message[:MAX_MESSAGE_CHARS], reason=reason)


class GcpApi:
    """Authenticated JSON calls to Google APIs."""

    def __init__(
        self,
        tokens: TokenSource,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._tokens = tokens
        self._client = httpx.Client(
            transport=transport,
            timeout=REQUEST_TIMEOUT_SECONDS,
            trust_env=False,
            follow_redirects=False,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> GcpApi:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def access_token(self) -> str:
        return self._tokens.token()

    def request(
        self,
        method: str,
        url: str,
        *,
        json: Any = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """The JSON response body; raises :class:`GcpError` on HTTP errors."""
        host = httpx.URL(url).host
        if httpx.URL(url).scheme != "https" or not host.endswith(GOOGLE_API_SUFFIX):
            raise CarapaceError(f"refusing to send credentials to {host!r}")
        headers = {"Authorization": f"Bearer {self._tokens.token()}"}
        quota_project = self._tokens.quota_project
        if quota_project:
            headers["x-goog-user-project"] = quota_project
        with network_errors("Google API"):
            response = self._client.request(
                method, url, json=json, params=params, headers=headers
            )
        if not response.is_success:
            raise _error_from(response)
        if not response.content:
            return {}
        body = response.json()
        return body if isinstance(body, dict) else {}

    def get(self, url: str, **params: str) -> dict[str, Any]:
        return self.request("GET", url, params=params or None)

    def get_or_none(self, url: str) -> dict[str, Any] | None:
        try:
            return self.get(url)
        except GcpError as exc:
            if exc.status == HTTP_NOT_FOUND:
                return None
            raise

    def paged(self, url: str, key: str, **params: str) -> Iterator[dict[str, Any]]:
        """Items under ``key`` across ``nextPageToken`` pages (bounded)."""
        token = ""
        for _ in range(MAX_PAGES):
            page = self.get(url, **params, **({"pageToken": token} if token else {}))
            yield from page.get(key) or []
            token = str(page.get("nextPageToken") or "")
            if not token:
                return

    # -- preflight ---------------------------------------------------------------

    def list_projects(self) -> list[dict[str, Any]]:
        return list(
            self.paged(
                f"{RESOURCE_MANAGER}/projects",
                "projects",
                filter="lifecycleState:ACTIVE",
            )
        )

    def get_project(self, project_id: str) -> dict[str, Any] | None:
        return self.get_or_none(f"{RESOURCE_MANAGER}/projects/{project_id}")

    def billing_enabled(self, project_id: str) -> bool:
        info = self.get(f"{BILLING}/projects/{project_id}/billingInfo")
        return info.get("billingEnabled") is True

    def missing_permissions(self, project_id: str, permissions: list[str]) -> list[str]:
        granted = (
            self.request(
                "POST",
                f"{RESOURCE_MANAGER}/projects/{project_id}:testIamPermissions",
                json={"permissions": permissions},
            ).get("permissions")
            or []
        )
        return [p for p in permissions if p not in set(granted)]

    def hsm_locations(self, project_id: str) -> set[str]:
        locations = self.paged(
            f"{KMS}/projects/{project_id}/locations", "locations", pageSize="100"
        )
        return {
            str(location.get("locationId"))
            for location in locations
            if (location.get("metadata") or {}).get("hsmAvailable") is True
        }

    def machine_type_available(
        self, project_id: str, zone: str, machine_type: str
    ) -> bool:
        url = (
            f"{COMPUTE}/projects/{project_id}/zones/{zone}/machineTypes/{machine_type}"
        )
        return self.get_or_none(url) is not None
