"""The Pulumi state backend: bucket, key and APIs, against :class:`FakeGoogle`."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from deploy_support import (
    KMS,
    PREFIX,
    PROJECT,
    PROJECT_NUMBER,
    REGION,
    SERVICE_USAGE,
    STORAGE,
    FakeGoogle,
    deployable_project,
    google_error,
    instant_clock,
    ok,
)

from carapace_cli.deploy.preflight import Target
from carapace_cli.deploy.state import (
    StateBackendError,
    ensure_state_backend,
    state_backend_for,
)

TARGET = Target(PROJECT, PROJECT_NUMBER, REGION, f"{REGION}-a", PREFIX, ("a@b.io",))
BUCKET = f"{PROJECT}-carapace-state"
STATE_KEY = (
    f"projects/{PROJECT}/locations/{REGION}/keyRings/carapace-state"
    "/cryptoKeys/pulumi-state"
)


def _backend(google: FakeGoogle) -> None:
    api, clock = google.api(), instant_clock()
    ensure_state_backend(api, TARGET, say=lambda _: None, clock=clock)


def test_backend_names() -> None:
    backend = state_backend_for(TARGET)
    assert backend.url == f"gs://{BUCKET}"
    assert backend.secrets_provider == f"gcpkms://{STATE_KEY}"


def test_existing_backend_is_reused_without_writes() -> None:
    google = deployable_project()
    _backend(google)
    assert {r.method for r in google.requests} == {"GET"}


def test_fresh_project_creates_everything() -> None:
    location = f"{KMS}/projects/{PROJECT}/locations/{REGION}"
    created: set[str] = set()

    def exists_once_created(name: str, body: dict[str, Any]):
        def handler(_request: httpx.Request) -> httpx.Response:
            return ok(body) if name in created else google_error(404, "none")

        return handler

    def create(name: str):
        def handler(request: httpx.Request) -> httpx.Response:
            created.add(name)
            return ok(json.loads(request.content or b"{}"))

        return handler

    google = (
        deployable_project()
        .on("GET", f"{SERVICE_USAGE}/projects/{PROJECT}/services/", ok({}))
        .on(
            "POST",
            f"{SERVICE_USAGE}/projects/{PROJECT}/services:batchEnable",
            ok({"name": "operations/op1"}),
        )
        .on("GET", f"{SERVICE_USAGE}/operations/op1", ok({"done": True}))
        .on("GET", f"{STORAGE}/b/", exists_once_created("bucket", {}))
        .on("POST", f"{STORAGE}/b?", create("bucket"))
        .on("GET", f"{location}/keyRings/", exists_once_created("ring", {}))
        .on("POST", f"{location}/keyRings?", create("ring"))
        .on(
            "GET",
            f"{KMS}/{STATE_KEY}",
            exists_once_created("key", {"purpose": "ENCRYPT_DECRYPT"}),
        )
        .on("POST", f"{location}/keyRings/carapace-state/cryptoKeys?", create("key"))
    )
    _backend(google)
    assert created == {"bucket", "ring", "key"}
    enable = google.called("POST", f"{SERVICE_USAGE}/projects/{PROJECT}")[0]
    assert json.loads(enable.content)["serviceIds"] == [
        "storage.googleapis.com",
        "cloudkms.googleapis.com",
    ]
    bucket = json.loads(google.called("POST", f"{STORAGE}/b?")[0].content)
    assert bucket["iamConfiguration"]["publicAccessPrevention"] == "enforced"
    assert bucket["versioning"] == {"enabled": True}
    key = json.loads(google.called("POST", f"{location}/keyRings/carapace")[0].content)
    assert key["purpose"] == "ENCRYPT_DECRYPT"
    assert key["versionTemplate"]["protectionLevel"] == "SOFTWARE"


def test_bucket_of_another_project_is_refused() -> None:
    foreign = deployable_project().on(
        "GET", f"{STORAGE}/b/", ok({"projectNumber": "999"})
    )
    with pytest.raises(StateBackendError, match="belongs to project number 999"):
        _backend(foreign)
    unreadable = deployable_project().on(
        "GET", f"{STORAGE}/b/", google_error(403, "forbidden")
    )
    with pytest.raises(StateBackendError, match="cannot read it"):
        _backend(unreadable)


def test_bucket_name_taken_elsewhere_is_refused() -> None:
    google = (
        deployable_project()
        .on("GET", f"{STORAGE}/b/", google_error(404, "none"))
        .on("POST", f"{STORAGE}/b?", google_error(409, "exists"))
    )
    with pytest.raises(StateBackendError, match="taken by another project"):
        _backend(google)


def test_key_created_by_a_concurrent_run_is_accepted() -> None:
    location = f"{KMS}/projects/{PROJECT}/locations/{REGION}"
    seen: list[str] = []

    def first_missing(_request: httpx.Request) -> httpx.Response:
        seen.append("get")
        if len(seen) == 1:
            return google_error(404, "none")
        return ok({"purpose": "ENCRYPT_DECRYPT"})

    google = (
        deployable_project()
        .on("GET", f"{KMS}/{STATE_KEY}", first_missing)
        .on("POST", f"{location}/keyRings/", google_error(409, "exists"))
    )
    _backend(google)
    assert seen == ["get", "get"]


def test_failed_service_enable_is_reported() -> None:
    google = (
        deployable_project()
        .on("GET", f"{SERVICE_USAGE}/projects/{PROJECT}/services/", ok({}))
        .on(
            "POST",
            f"{SERVICE_USAGE}/projects/{PROJECT}/services:batchEnable",
            ok({"name": "operations/op1", "done": True, "error": {"message": "no"}}),
        )
    )
    with pytest.raises(Exception, match="enabling .* failed: no"):
        _backend(google)


def test_weak_bucket_settings_are_fixed() -> None:
    google = (
        deployable_project()
        .on("GET", f"{STORAGE}/b/", ok({"projectNumber": PROJECT_NUMBER}))
        .on("PATCH", f"{STORAGE}/b/{BUCKET}", ok({}))
    )
    _backend(google)
    patch = json.loads(google.called("PATCH", STORAGE)[0].content)
    assert patch["iamConfiguration"]["uniformBucketLevelAccess"] == {"enabled": True}


def test_state_key_with_wrong_purpose_is_refused() -> None:
    google = deployable_project().on(
        "GET", f"{KMS}/{STATE_KEY}", ok({"purpose": "ASYMMETRIC_DECRYPT"})
    )
    with pytest.raises(StateBackendError, match="ENCRYPT_DECRYPT"):
        _backend(google)
