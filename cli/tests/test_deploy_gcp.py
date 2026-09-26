"""The Google REST client: host allow-list, errors, ADC and paging.

Every call goes to :class:`FakeGoogle`; nothing reaches the network.
"""

from __future__ import annotations

import httpx
import pytest
from deploy_support import PROJECT, RM, FakeGoogle, disabled, healthy_project, ok

from carapace_cli.deploy import gcp
from carapace_cli.errors import CarapaceError


def test_client_refuses_to_send_tokens_elsewhere() -> None:
    api = FakeGoogle().api()
    for url in ("https://evil.example.com/x", "http://kms.googleapis.com/v1"):
        with pytest.raises(CarapaceError, match="refusing"):
            api.get(url)


def test_errors_carry_status_reason_and_no_token() -> None:
    google = FakeGoogle().on("GET", RM, disabled("Resource Manager"))
    with pytest.raises(gcp.GcpError) as caught:
        google.api().get(f"{RM}/projects/x")
    assert caught.value.status == 403 and caught.value.service_disabled
    assert "fake-access-token" not in str(caught.value)


def test_missing_adc_says_how_to_log_in(monkeypatch: pytest.MonkeyPatch) -> None:
    google_auth = pytest.importorskip("google.auth")
    exceptions = pytest.importorskip("google.auth.exceptions")

    def no_credentials(**_: object) -> None:
        raise exceptions.DefaultCredentialsError("none")

    monkeypatch.setattr(google_auth, "default", no_credentials)
    with pytest.raises(gcp.CredentialsError, match="application-default login"):
        gcp.AdcTokenSource()


def test_paging_follows_next_page_token() -> None:
    def page(request: httpx.Request) -> httpx.Response:
        if "pageToken=two" in str(request.url):
            return ok({"projects": [{"projectId": "p-two"}]})
        return ok({"projects": [{"projectId": "p-one"}], "nextPageToken": "two"})

    google = FakeGoogle().on("GET", f"{RM}/projects?", page)
    ids = [p["projectId"] for p in google.api().list_projects()]
    assert ids == ["p-one", "p-two"]


def test_preflight_queries() -> None:
    api = healthy_project().api()
    assert api.get_project(PROJECT)["projectNumber"]
    assert api.get_project("missing-project") is None
    assert api.billing_enabled(PROJECT)
    assert api.missing_permissions(PROJECT, ["a.b.c"]) == []
    assert api.hsm_locations(PROJECT) == {"us-central1", "europe-west1"}
    assert api.machine_type_available(PROJECT, "us-central1-a", "n2d-standard-2")


def test_quota_project_header(monkeypatch: pytest.MonkeyPatch) -> None:
    google = FakeGoogle().on("GET", RM, ok({}))

    class Tokens:
        quota_project = "billing-project"

        def token(self) -> str:
            return "t"

    api = gcp.GcpApi(Tokens(), transport=httpx.MockTransport(google.handle))
    api.get(f"{RM}/x")
    assert google.requests[0].headers["x-goog-user-project"] == "billing-project"
