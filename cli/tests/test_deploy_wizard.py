"""``carapace deploy`` up to the confirmation: interview, preflight, summary.

Every Google call goes to :class:`FakeGoogle`; nothing reaches the network.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from deploy_support import (
    BILLING,
    COMPUTE,
    KMS,
    PROJECT,
    PROJECT_NUMBER,
    RM,
    FakeGoogle,
    disabled,
    google_error,
    healthy_project,
    ok,
    scripted,
    transcript,
)

from carapace_cli.deploy import command
from carapace_cli.deploy.interview import (
    InvalidInputError,
    MissingInputError,
)
from carapace_cli.deploy.preflight import (
    PREFIX_PATTERN,
    Flags,
    PreflightError,
    PreflightReport,
    Target,
    run_preflight,
    validate_emails,
    validate_prefix,
    validate_zone,
)
from carapace_cli.deploy.summary import render_summary
from carapace_cli.main import main

REPO_ROOT = Path(__file__).resolve().parents[2]
EMAIL = "ops@example.com"
DIGEST = "sha256:" + "ab" * 32
DIGEST_FLAGS = ("--enclave-digest", DIGEST, "--server-digest", DIGEST)
FULL_FLAGS = Flags(project=PROJECT, region="europe-west1", alert_emails=(EMAIL,))


# -- validators -----------------------------------------------------------------


def test_prefix_pattern_matches_infra_config() -> None:
    # Read, not imported: infra's package needs pulumi, which is optional.
    source = (REPO_ROOT / "infra" / "pulumi" / "components" / "config.py").read_text()
    assert f'PREFIX_PATTERN = re.compile(r"{PREFIX_PATTERN.pattern}")' in source


@pytest.mark.parametrize("bad", ["", " , ", "a@", "a@b", "x y@z.com", "A <a@b.io>"])
def test_bad_emails_rejected(bad: str) -> None:
    with pytest.raises(InvalidInputError):
        validate_emails(bad)


def test_several_emails() -> None:
    assert validate_emails(" a@x.io, b@y.org, ") == "a@x.io,b@y.org"


@pytest.mark.parametrize("bad", ["ab", "Carapace", "gcp-carapace", "a" * 21, "x-"])
def test_bad_prefixes_rejected(bad: str) -> None:
    with pytest.raises(InvalidInputError):
        validate_prefix(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "us-east1-b",
        "us-central1-",
        "us-central1-a/../b",
        "us-central1-A",
        "us-central1-a\n",
        "us-central1-a --flag",
    ],
)
def test_bad_zones_rejected(bad: str) -> None:
    # The zone goes into a Compute API path and the stack config.
    with pytest.raises(InvalidInputError, match="not in region"):
        validate_zone("us-central1", bad)
    assert validate_zone("us-central1", "us-central1-f") == "us-central1-f"


# -- preflight -----------------------------------------------------------------


def test_interactive_preflight_happy_path() -> None:
    google = healthy_project()
    # project 1 of the list, default prefix, region by value, emails
    interview = scripted("1", "", "europe-west1", EMAIL)
    target, report = run_preflight(google.api(), interview, Flags())
    assert target == Target(
        project=PROJECT,
        project_number=PROJECT_NUMBER,
        region="europe-west1",
        zone="europe-west1-b",
        prefix="carapace",
        alert_emails=(EMAIL,),
    )
    assert report.warnings == []
    shown = transcript(interview)
    # Regions without HSM are not offered.
    assert "europe-west1" in shown and "us-west1" not in shown
    assert all(
        r.headers["Authorization"] == "Bearer fake-access-token"
        for r in google.requests
    )


def test_non_interactive_preflight_uses_flags_without_listing() -> None:
    google = healthy_project()
    interview = scripted(interactive=False)
    target, _ = run_preflight(google.api(), interview, FULL_FLAGS)
    assert (target.region, target.zone) == ("europe-west1", "europe-west1-b")
    assert not google.called("GET", f"{RM}/projects?")
    assert not google.called("GET", f"{KMS}/projects/{PROJECT}/locations")


def test_non_interactive_preflight_requires_project_and_email() -> None:
    interview = scripted(interactive=False)
    with pytest.raises(MissingInputError, match="--project"):
        run_preflight(healthy_project().api(), interview, Flags())
    with pytest.raises(MissingInputError, match="--alert-email"):
        run_preflight(healthy_project().api(), interview, Flags(project=PROJECT))


def test_missing_project_fails() -> None:
    google = healthy_project().on(
        "GET", f"{RM}/projects/{PROJECT}", google_error(404, "not found")
    )
    with pytest.raises(PreflightError, match="does not exist"):
        run_preflight(google.api(), scripted(interactive=False), FULL_FLAGS)


def test_inactive_project_fails() -> None:
    google = healthy_project().on(
        "GET",
        f"{RM}/projects/{PROJECT}",
        ok({"projectId": PROJECT, "lifecycleState": "DELETE_REQUESTED"}),
    )
    with pytest.raises(PreflightError, match="not active"):
        run_preflight(google.api(), scripted(interactive=False), FULL_FLAGS)


def test_billing_off_fails() -> None:
    google = healthy_project().on(
        "GET", f"{BILLING}/projects/{PROJECT}/billingInfo", ok({})
    )
    with pytest.raises(PreflightError, match="billing is not enabled"):
        run_preflight(google.api(), scripted(interactive=False), FULL_FLAGS)


def test_missing_permissions_are_listed() -> None:
    google = healthy_project().on(
        "POST",
        f"{RM}/projects/{PROJECT}:testIamPermissions",
        ok({"permissions": ["storage.buckets.create"]}),
    )
    with pytest.raises(PreflightError, match="cloudkms.keyRings.create"):
        run_preflight(google.api(), scripted(interactive=False), FULL_FLAGS)


def test_checks_that_cannot_run_become_warnings() -> None:
    google = (
        healthy_project()
        .on("GET", f"{BILLING}/projects/{PROJECT}/billingInfo", disabled("Billing"))
        .on("GET", f"{COMPUTE}/projects/{PROJECT}/zones/", disabled("Compute"))
    )
    _, report = run_preflight(google.api(), scripted(interactive=False), FULL_FLAGS)
    assert len(report.warnings) == 2
    assert "billing" in report.warnings[0]


def test_unsupported_region_and_wrong_zone_fail() -> None:
    interview = scripted(interactive=False)
    with pytest.raises(InvalidInputError, match="not a region"):
        run_preflight(
            healthy_project().api(),
            interview,
            Flags(project=PROJECT, region="me-central2", alert_emails=(EMAIL,)),
        )
    with pytest.raises(InvalidInputError, match="not in region"):
        run_preflight(
            healthy_project().api(),
            interview,
            Flags(
                project=PROJECT,
                region="us-central1",
                zone="us-east1-b",
                alert_emails=(EMAIL,),
            ),
        )


def test_zone_without_n2d_fails() -> None:
    google = healthy_project().on(
        "GET", f"{COMPUTE}/projects/{PROJECT}/zones/", google_error(404, "no")
    )
    with pytest.raises(PreflightError, match="not offered"):
        run_preflight(google.api(), scripted(interactive=False), FULL_FLAGS)


# -- summary and command ---------------------------------------------------------


def _target() -> Target:
    return Target(
        PROJECT, PROJECT_NUMBER, "us-central1", "us-central1-a", "c1x", (EMAIL,)
    )


def test_summary_states_cost_risk_and_warnings() -> None:
    report = PreflightReport(warnings=["could not confirm billing"])
    text = render_summary(_target(), report, images="release v1.2.0")
    assert "$80/month" in text
    assert "Owner or Editor" in text and "dedicated project" in text
    assert f"gs://{PROJECT}-carapace-state" in text
    assert "could not confirm billing" in text
    assert "release v1.2.0" in text


def _run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, google: FakeGoogle, *argv: str
) -> tuple[int, str]:
    monkeypatch.setattr(
        command, "default_services", lambda: command.Services(gcp=google.api)
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(""))  # not a TTY
    out, err = io.StringIO(), io.StringIO()
    code = main(["--config-dir", str(tmp_path), "deploy", *argv], out=out, err=err)
    return code, out.getvalue() + err.getvalue()


def _read_only(google: FakeGoogle) -> bool:
    return all(
        r.method == "GET" or r.url.path.endswith(":testIamPermissions")
        for r in google.requests
    )


def test_deploy_without_yes_in_a_script_changes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    google = healthy_project()
    code, output = _run(
        monkeypatch,
        tmp_path,
        google,
        "--project",
        PROJECT,
        "--alert-email",
        EMAIL,
        *DIGEST_FLAGS,
    )
    assert code == 1
    assert "pass --yes" in output
    assert "$80/month" in output
    assert _read_only(google)


def test_deploy_script_missing_email_fails_fast(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    google = healthy_project()
    code, output = _run(monkeypatch, tmp_path, google, "--project", PROJECT, "-y")
    assert code == 1
    assert "--alert-email is required in non-interactive mode" in output
    assert _read_only(google)


def test_deploy_declined_interactively(monkeypatch: pytest.MonkeyPatch) -> None:
    class Ctx:
        def __init__(self) -> None:
            self.config_dir = Path("unused")
            self.err = io.StringIO()
            self.lines: list[str] = []

        def say(self, message: str) -> None:
            self.lines.append(message)

    interview = scripted("n", interactive=True)
    monkeypatch.setattr(command, "make_interview", lambda _a, _c: interview)
    monkeypatch.setattr(
        command, "default_services", lambda: command.Services(gcp=healthy_project().api)
    )
    args = command.argparse.Namespace(
        project=PROJECT,
        region="us-central1",
        zone=None,
        prefix="c1x",
        alert_email=[EMAIL],
        enclave_digest=DIGEST,
        server_digest=DIGEST,
        release=None,
        release_repo="99darwin/carapace-oss",
        build=False,
        non_interactive=False,
        yes=False,
    )
    ctx = Ctx()
    assert command.cmd_deploy(args, ctx) == command.EXIT_DECLINED
    assert ctx.lines[-1] == "Aborted. Nothing was changed."
    assert "Deploy to carapace-selfhost now? [y/N]" in transcript(interview)
