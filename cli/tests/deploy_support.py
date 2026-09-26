"""Fakes for the deploy tests: Google APIs over a mock transport, and input.

Nothing here reaches the network. :class:`FakeGoogle` answers requests by
``(method, url prefix)`` and records every request it saw.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from carapace_cli.deploy.gcp import GcpApi
from carapace_cli.deploy.interview import Interview

PROJECT = "carapace-selfhost"
PROJECT_NUMBER = "123456789012"
FAKE_ACCESS_TOKEN = "fake-access-token"

Handler = Callable[[httpx.Request], httpx.Response]


class StaticTokens:
    quota_project: str | None = None

    def token(self) -> str:
        return FAKE_ACCESS_TOKEN


def ok(body: Any = None, status: int = 200) -> httpx.Response:
    return httpx.Response(status, content=json.dumps(body or {}).encode())


def google_error(status: int, message: str, reason: str = "") -> httpx.Response:
    details = [{"reason": reason}] if reason else []
    return ok({"error": {"message": message, "details": details}}, status)


def disabled(service: str) -> httpx.Response:
    return google_error(403, f"{service} has not been used", "SERVICE_DISABLED")


@dataclass
class FakeGoogle:
    routes: list[tuple[str, str, Handler]] = field(default_factory=list)
    requests: list[httpx.Request] = field(default_factory=list)

    def on(self, method: str, url_prefix: str, response: Handler | httpx.Response):
        handler = response if callable(response) else (lambda _r, _x=response: _x)
        # Later routes win, so a test can override a default.
        self.routes.insert(0, (method, url_prefix, handler))
        return self

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)  # prefixes may include the query string
        for method, prefix, handler in self.routes:
            if request.method == method and url.startswith(prefix):
                return handler(request)
        return google_error(404, f"unexpected {request.method} {url}")

    def api(self) -> GcpApi:
        return GcpApi(StaticTokens(), transport=httpx.MockTransport(self.handle))

    def called(self, method: str, url_prefix: str) -> list[httpx.Request]:
        return [
            r
            for r in self.requests
            if r.method == method and str(r.url).startswith(url_prefix)
        ]


RM = "https://cloudresourcemanager.googleapis.com/v1"
BILLING = "https://cloudbilling.googleapis.com/v1"
KMS = "https://cloudkms.googleapis.com/v1"
COMPUTE = "https://compute.googleapis.com/compute/v1"


def healthy_project(google: FakeGoogle | None = None) -> FakeGoogle:
    """A project where every preflight check passes."""
    google = google or FakeGoogle()

    def grant_all(request: httpx.Request) -> httpx.Response:
        return ok({"permissions": json.loads(request.content)["permissions"]})

    return (
        google.on(
            "GET",
            f"{RM}/projects?",
            ok({"projects": [{"projectId": PROJECT, "name": "Carapace"}]}),
        )
        .on(
            "GET",
            f"{RM}/projects/{PROJECT}",
            ok(
                {
                    "projectId": PROJECT,
                    "projectNumber": PROJECT_NUMBER,
                    "lifecycleState": "ACTIVE",
                }
            ),
        )
        .on(
            "GET",
            f"{BILLING}/projects/{PROJECT}/billingInfo",
            ok({"billingEnabled": True}),
        )
        .on("POST", f"{RM}/projects/{PROJECT}:testIamPermissions", grant_all)
        .on(
            "GET",
            f"{KMS}/projects/{PROJECT}/locations",
            ok(
                {
                    "locations": [
                        {
                            "locationId": "us-central1",
                            "metadata": {"hsmAvailable": True},
                        },
                        {
                            "locationId": "europe-west1",
                            "metadata": {"hsmAvailable": True},
                        },
                        {"locationId": "us-west1", "metadata": {"hsmAvailable": False}},
                    ]
                }
            ),
        )
        .on(
            "GET",
            f"{COMPUTE}/projects/{PROJECT}/zones/",
            ok({"name": "n2d-standard-2"}),
        )
    )


def scripted(*answers: str, interactive: bool = True, yes: bool = False) -> Interview:
    """An interview that reads ``answers`` line by line and writes to a buffer."""
    return Interview(
        interactive=interactive,
        assume_yes=yes,
        stream_in=io.StringIO("".join(f"{a}\n" for a in answers)),
        stream_out=io.StringIO(),
    )


def transcript(interview: Interview) -> str:
    out = interview.stream_out
    assert isinstance(out, io.StringIO)
    return out.getvalue()
