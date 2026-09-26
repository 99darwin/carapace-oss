"""Deployment records, re-runs and ``carapace destroy``, against fakes.

Google calls go to :class:`FakeGoogle` and the stack is a
:class:`FakeStack`; no ``pulumi`` process runs and nothing reaches the
network.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest
from deploy_support import (
    NEW_DIGEST,
    PREFIX,
    PROJECT,
    REGION,
    SERVER_DIGEST,
    FakeGoogle,
    FakeStack,
    deployable_project,
    disabled,
    google_error,
    healthy_project,
    instant_clock,
    scripted,
)
from first_run_support import fake_first_run

from carapace_cli.deploy import command
from carapace_cli.deploy.destroy import UNPROTECTED, run_destroy
from carapace_cli.deploy.gcp import STORAGE
from carapace_cli.deploy.preflight import (
    ExistingDeployment,
    Flags,
    PreflightError,
    Target,
    run_preflight,
)
from carapace_cli.deploy.record import (
    RecordError,
    check_stack_config,
    read_record,
    record_name,
    write_record,
)
from carapace_cli.main import main

EMAIL = "a@b.io"
ZONE = f"{REGION}-a"
TARGET = Target(PROJECT, "1", REGION, ZONE, PREFIX, (EMAIL,))
DEPLOY_FLAGS = [
    "--enclave-digest",
    NEW_DIGEST,
    "--server-digest",
    SERVER_DIGEST,
    "--password-stdin",
    "--no-passphrase",
    "--yes",
]


def recorded(google: FakeGoogle) -> FakeGoogle:
    write_record(google.api(), TARGET)
    return google


def live_stack() -> FakeStack:
    return FakeStack(
        initial={
            "gcp:project": PROJECT,
            "gcp:region": REGION,
            "gcp:zone": ZONE,
            "carapace:prefix": PREFIX,
            "carapace:deploy_workloads": "true",
            "carapace:enclave_image_digest": NEW_DIGEST,
        }
    )


def run_cli(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    google: FakeGoogle,
    stack: FakeStack,
    *argv: str,
) -> tuple[int, str]:
    monkeypatch.setattr(
        command,
        "default_services",
        lambda: command.Services(
            gcp=google.api,
            stack=lambda target, backend, ctx: stack,
            clock=instant_clock(),
            first_run=fake_first_run(),
        ),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    out, err = io.StringIO(), io.StringIO()
    code = main(["--config-dir", str(tmp_path), *argv], out=out, err=err)
    return code, err.getvalue()


def destroy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    google: FakeGoogle,
    stack: FakeStack,
    *argv: str,
) -> tuple[int, str]:
    return run_cli(
        monkeypatch,
        tmp_path,
        google,
        stack,
        "destroy",
        "--project",
        PROJECT,
        "--prefix",
        PREFIX,
        *argv,
    )


# -- the record ----------------------------------------------------------------


def test_record_round_trip() -> None:
    google = recorded(deployable_project())
    assert record_name(PREFIX) in google.objects
    existing = read_record(google.api(), PROJECT, PREFIX)
    assert existing == ExistingDeployment(REGION, ZONE, (EMAIL,))
    assert read_record(google.api(), PROJECT, "other") is None


@pytest.mark.parametrize(
    "change",
    [
        {"version": 2},
        {"prefix": "other"},
        {"region": "mars-central1"},
        {"zone": "europe-west1-b"},
        {"zone": f"{REGION}-a/../../b"},
        {"alert_emails": []},
    ],
)
def test_bad_record_is_refused(change: dict[str, Any]) -> None:
    google = recorded(deployable_project())
    google.objects[record_name(PREFIX)] |= change
    with pytest.raises(RecordError):
        read_record(google.api(), PROJECT, PREFIX)


def test_missing_stack_config_is_refused() -> None:
    with pytest.raises(RecordError, match="not on this machine"):
        check_stack_config({}, TARGET, is_existing=True)
    check_stack_config({}, TARGET, is_existing=False)
    moved = {"carapace:prefix": PREFIX, "gcp:region": "us-east1"}
    with pytest.raises(RecordError, match="cannot move"):
        check_stack_config(moved, TARGET, is_existing=True)


def test_stack_config_of_another_project_is_refused() -> None:
    # Pulumi.<prefix>.yaml is shared across projects, so the same prefix in
    # a second project would act on that file's project.
    elsewhere = live_stack().config() | {"gcp:project": "other-project"}
    for is_existing in (True, False):
        with pytest.raises(RecordError, match="belongs to the deployment in"):
            check_stack_config(elsewhere, TARGET, is_existing=is_existing)


def test_deploy_with_another_projects_config_changes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    google = deployable_project()
    stack = FakeStack(initial=live_stack().config() | {"gcp:project": "other-proj"})
    code, output = run_cli(
        monkeypatch, tmp_path, google, stack, "deploy", "--project", PROJECT,
        "--prefix", PREFIX, "--alert-email", EMAIL, *DEPLOY_FLAGS,
    )  # fmt: skip
    assert code != 0
    assert "belongs to the deployment in other-proj" in output
    assert not stack.ups
    assert stack.config()["gcp:project"] == "other-proj"
    assert record_name(PREFIX) not in google.objects


def test_live_stack_without_local_config_is_never_bootstrapped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Another machine: the backend has the live stack, this machine has no
    # Pulumi.<prefix>.yaml, and the record cannot be read (or is gone).
    google = deployable_project().on(
        "GET",
        f"{STORAGE}/b/{PROJECT}-carapace-state/o/",
        google_error(403, "Permission denied on the object"),
    )
    stack = FakeStack(initial={}, state=live_stack().config())
    code, output = run_cli(
        monkeypatch, tmp_path, google, stack, "deploy", "--project", PROJECT,
        "--prefix", PREFIX, "--alert-email", EMAIL, *DEPLOY_FLAGS,
    )  # fmt: skip
    assert code != 0
    assert "not on this machine" in output
    assert not stack.ups
    assert stack.config() == {}


# -- re-runs -------------------------------------------------------------------


def preflight(google: FakeGoogle, flags: Flags) -> tuple[Target, Any]:
    api = google.api()
    return run_preflight(
        api,
        scripted(interactive=False),
        flags,
        find_existing=lambda project, prefix: read_record(api, project, prefix),
    )


def test_rerun_defaults_to_the_recorded_location_and_emails() -> None:
    google = recorded(deployable_project())
    target, report = preflight(google, Flags(project=PROJECT, prefix=PREFIX))
    assert (target.region, target.zone, target.alert_emails) == (
        REGION,
        ZONE,
        (EMAIL,),
    )
    assert report.existing is not None


def test_rerun_cannot_move_the_deployment() -> None:
    google = recorded(deployable_project())
    flags = Flags(project=PROJECT, prefix=PREFIX, region="europe-west1")
    with pytest.raises(PreflightError, match="cannot move"):
        preflight(google, flags)


def test_unreadable_state_bucket_is_a_warning() -> None:
    google = healthy_project().on(
        "GET", f"{STORAGE}/b/", disabled("storage.googleapis.com")
    )
    flags = Flags(project=PROJECT, prefix=PREFIX, alert_emails=(EMAIL,))
    _, report = preflight(google, flags)
    assert report.existing is None
    assert any("earlier deployment" in warning for warning in report.warnings)


def test_second_deploy_is_shown_as_an_update(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    google, stack = deployable_project(), FakeStack()
    first = ["deploy", "--project", PROJECT, "--prefix", PREFIX]
    code, output = run_cli(
        monkeypatch, tmp_path, google, stack, *first, "--alert-email", EMAIL,
        *DEPLOY_FLAGS,
    )  # fmt: skip
    assert code == 0, output
    assert "Existing deployment" not in output
    assert google.objects[record_name(PREFIX)]["zone"] == ZONE
    code, output = run_cli(monkeypatch, tmp_path, google, stack, *first, *DEPLOY_FLAGS)
    assert code == 0, output
    assert f"Existing deployment: stack {PREFIX!r}" in output
    assert "skipping the bootstrap" in output


# -- destroy -------------------------------------------------------------------


def test_destroy_requires_the_typed_project(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    google, stack = recorded(deployable_project()), live_stack()
    code, output = destroy(monkeypatch, tmp_path, google, stack)
    assert code != 0
    assert f"pass --confirm-project {PROJECT}" in output
    code, output = destroy(
        monkeypatch, tmp_path, google, stack, "--confirm-project", "other"
    )
    assert code == command.EXIT_DECLINED
    assert "Nothing was changed" in output
    assert not stack.ups and not stack.destroyed
    assert record_name(PREFIX) in google.objects


def test_destroy_lifts_protection_then_destroys(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    google, stack = recorded(deployable_project()), live_stack()
    code, output = destroy(
        monkeypatch, tmp_path, google, stack, "--confirm-project", PROJECT
    )
    assert code == 0, output
    assert "can restore the version" in output
    assert f"gs://{PROJECT}-carapace-state" in output
    assert len(stack.ups) == 1
    assert all(stack.ups[0][key] == "false" for key in UNPROTECTED)
    assert stack.destroyed
    assert record_name(PREFIX) not in google.objects


def test_destroy_without_a_record_changes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stack = live_stack()
    code, output = destroy(
        monkeypatch, tmp_path, deployable_project(), stack, "--confirm-project",
        PROJECT,
    )  # fmt: skip
    assert code != 0
    assert "pulumi destroy" in output
    assert not stack.ups and not stack.destroyed


def test_destroy_never_ups_with_another_projects_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The same prefix deployed into two projects from one machine leaves
    # Pulumi.<prefix>.yaml naming the second; a destroy of the first must
    # not run the protection-lifting up with it.
    google = recorded(deployable_project())
    stack = FakeStack(initial=live_stack().config() | {"gcp:project": "other-proj"})
    code, output = destroy(
        monkeypatch, tmp_path, google, stack, "--confirm-project", PROJECT
    )
    assert code != 0
    assert "belongs to the deployment in other-proj" in output
    assert not stack.ups and not stack.destroyed
    assert record_name(PREFIX) in google.objects


def test_destroy_without_the_stack_config_changes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    google, stack = recorded(deployable_project()), FakeStack()
    code, output = destroy(
        monkeypatch, tmp_path, google, stack, "--confirm-project", PROJECT
    )
    assert code != 0
    assert "not on this machine" in output
    assert not stack.ups and not stack.destroyed


def test_resumed_destroy_skips_the_protection_up() -> None:
    stack = live_stack()
    stack.set_config(UNPROTECTED)
    run_destroy(stack, say=lambda _: None)
    assert not stack.ups and stack.destroyed
