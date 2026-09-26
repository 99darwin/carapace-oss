"""Fakes for the deploy tests: Google APIs over a mock transport, and input.

Nothing here reaches the network. :class:`FakeGoogle` answers requests by
``(method, url prefix)`` and records every request it saw.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx

from carapace_cli.deploy.gcp import GcpApi
from carapace_cli.deploy.interview import Interview
from carapace_cli.deploy.polling import Clock
from carapace_cli.errors import CarapaceError

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


STORAGE = "https://storage.googleapis.com/storage/v1"
SERVICE_USAGE = "https://serviceusage.googleapis.com/v1"
RUN = "https://run.googleapis.com/v2"
REGION = "us-central1"
PREFIX = "c1x"
KEY_NAME = (
    f"projects/{PROJECT}/locations/{REGION}/keyRings/{PREFIX}-keyring"
    f"/cryptoKeys/{PREFIX}-secrets"
)
KEY_VERSION = f"{KEY_NAME}/cryptoKeyVersions/1"
SERVER_URL = "https://c1x-server-123.us-central1.run.app"
ENCLAVE_URL = "https://203.0.113.7:8443"
REGISTRY = f"{REGION}-docker.pkg.dev/{PROJECT}/{PREFIX}"
OLD_DIGEST = "sha256:" + "01" * 32
NEW_DIGEST = "sha256:" + "02" * 32
SERVER_DIGEST = "sha256:" + "03" * 32


def deployable_project(google: FakeGoogle | None = None) -> FakeGoogle:
    """Preflight passes, state APIs are on, the key and migration succeed."""
    google = healthy_project(google)
    location = f"{KMS}/projects/{PROJECT}/locations/{REGION}"
    return (
        google.on(
            "GET",
            f"{SERVICE_USAGE}/projects/{PROJECT}/services/",
            ok({"state": "ENABLED"}),
        )
        .on("GET", f"{STORAGE}/b/", ok(_healthy_bucket()))
        .on("GET", f"{location}/keyRings/", ok({"purpose": "ENCRYPT_DECRYPT"}))
        .on("GET", f"{KMS}/{KEY_VERSION}", ok({"state": "ENABLED"}))
        .on(
            "GET",
            f"{RUN}/projects/{PROJECT}/locations/{REGION}/jobs/",
            ok({"latestCreatedExecution": {"completionStatus": "EXECUTION_SUCCEEDED"}}),
        )
    )


def _healthy_bucket() -> dict[str, Any]:
    return {
        "projectNumber": PROJECT_NUMBER,
        "iamConfiguration": {
            "uniformBucketLevelAccess": {"enabled": True},
            "publicAccessPrevention": "enforced",
        },
        "versioning": {"enabled": True},
    }


@dataclass
class FakeStack:
    """A Pulumi stack in memory: config, and a log of every ``up``."""

    initial: dict[str, str] = field(default_factory=dict)
    fail_on_up: int | None = None
    ups: list[dict[str, str]] = field(default_factory=list)
    destroyed: bool = False

    def __post_init__(self) -> None:
        self._config = dict(self.initial)

    def config(self) -> dict[str, str]:
        return dict(self._config)

    def set_config(self, values: Mapping[str, str]) -> None:
        self._config.update(values)

    def up(self) -> dict[str, Any]:
        if self.fail_on_up is not None and len(self.ups) + 1 == self.fail_on_up:
            self.fail_on_up = None
            raise CarapaceError("pulumi failed: simulated")
        self.ups.append(self.config())
        return self.outputs()

    def destroy(self) -> None:
        self.destroyed = True

    def outputs(self) -> dict[str, Any]:
        outputs: dict[str, Any] = {
            "kms_key_name": KEY_NAME,
            "kms_key_version_name": KEY_VERSION,
            "image_registry": REGISTRY,
            "enclave_service_account": (
                f"{PREFIX}-enclave@{PROJECT}.iam.gserviceaccount.com"
            ),
            "server_url": SERVER_URL,
            "control_plane_url": SERVER_URL,
        }
        if self._config.get("carapace:deploy_workloads") == "true":
            outputs |= {
                "migration_job": f"{PREFIX}-migrate",
                "enclave_url": ENCLAVE_URL,
            }
        return outputs


def instant_clock() -> Clock:
    """A clock whose sleeps advance time without waiting."""
    now = [0.0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    return Clock(sleep=sleep, monotonic=lambda: now[0])
