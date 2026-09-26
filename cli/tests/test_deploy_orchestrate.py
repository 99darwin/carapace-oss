"""Bootstrap, key wait, workloads and resume, against fakes.

Google calls go to :class:`FakeGoogle` and the stack is a
:class:`FakeStack`; no ``pulumi`` process runs and nothing reaches the
network.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest
from deploy_support import (
    KEY_VERSION,
    KMS,
    NEW_DIGEST,
    OLD_DIGEST,
    PREFIX,
    PROJECT,
    PROJECT_NUMBER,
    REGION,
    RUN,
    SERVER_DIGEST,
    FakeGoogle,
    FakeStack,
    deployable_project,
    instant_clock,
    ok,
)
from first_run_support import fake_first_run

from carapace_cli.deploy import command
from carapace_cli.deploy.orchestrate import (
    PLACEHOLDER_DIGEST,
    DeployStepError,
    Images,
    PrebuiltImages,
    rollout_steps,
    run_deploy,
)
from carapace_cli.deploy.polling import PollTimeoutError
from carapace_cli.deploy.preflight import Target
from carapace_cli.main import main

TARGET = Target(PROJECT, PROJECT_NUMBER, REGION, f"{REGION}-a", PREFIX, ("a@b.io",))
IMAGES = Images(enclave_digest=NEW_DIGEST, server_digest=SERVER_DIGEST)


def _deploy(google: FakeGoogle, stack: FakeStack) -> dict[str, Any]:
    return run_deploy(
        TARGET,
        api=google.api(),
        stack=stack,
        images=PrebuiltImages(images=IMAGES),
        clock=instant_clock(),
        say=lambda _: None,
    ).outputs


def test_first_deploy_bootstraps_then_deploys_workloads() -> None:
    stack = FakeStack()
    outputs = _deploy(deployable_project(), stack)
    bootstrap, workloads = stack.ups
    assert bootstrap["carapace:deploy_workloads"] == "false"
    assert json.loads(bootstrap["carapace:allowed_digests"]) == [NEW_DIGEST]
    assert bootstrap["gcp:zone"] == f"{REGION}-a"
    assert json.loads(bootstrap["carapace:alert_emails"]) == ["a@b.io"]
    assert workloads["carapace:deploy_workloads"] == "true"
    assert workloads["carapace:enclave_image_digest"] == NEW_DIGEST
    assert workloads["carapace:server_image_digest"] == SERVER_DIGEST
    assert json.loads(workloads["carapace:allowed_digests"]) == [NEW_DIGEST]
    assert outputs["enclave_url"].startswith("https://")


def test_unknown_enclave_digest_bootstraps_with_placeholder() -> None:
    class LaterImages:
        def enclave_digest_hint(self) -> None:
            return None

        def publish(self, registry: str) -> Images:
            assert registry.endswith(f"/{PROJECT}/{PREFIX}")
            return IMAGES

    stack = FakeStack()
    run_deploy(
        TARGET,
        api=deployable_project().api(),
        stack=stack,
        images=LaterImages(),
        clock=instant_clock(),
        say=lambda _: None,
    )
    assert json.loads(stack.ups[0]["carapace:allowed_digests"]) == [PLACEHOLDER_DIGEST]
    assert json.loads(stack.ups[-1]["carapace:allowed_digests"]) == [NEW_DIGEST]


def test_live_update_never_bootstraps_and_rolls_in_three_steps() -> None:
    live = {
        "carapace:deploy_workloads": "true",
        "carapace:enclave_image_digest": OLD_DIGEST,
        "carapace:allowed_digests": json.dumps([OLD_DIGEST]),
    }
    stack = FakeStack(initial=live)
    _deploy(deployable_project(), stack)
    assert all(up["carapace:deploy_workloads"] == "true" for up in stack.ups)
    plan = [
        (
            json.loads(up["carapace:allowed_digests"]),
            up["carapace:enclave_image_digest"],
        )
        for up in stack.ups
    ]
    assert plan == [
        ([OLD_DIGEST, NEW_DIGEST], OLD_DIGEST),
        ([OLD_DIGEST, NEW_DIGEST], NEW_DIGEST),
        ([NEW_DIGEST], NEW_DIGEST),
    ]


def test_same_digest_update_is_one_up() -> None:
    live = {
        "carapace:deploy_workloads": "true",
        "carapace:enclave_image_digest": NEW_DIGEST,
    }
    assert rollout_steps(live, NEW_DIGEST) == [([NEW_DIGEST], NEW_DIGEST)]


def test_resume_after_a_failed_switch_finishes_the_rollout() -> None:
    live = {
        "carapace:deploy_workloads": "true",
        "carapace:enclave_image_digest": OLD_DIGEST,
        "carapace:allowed_digests": json.dumps([OLD_DIGEST]),
    }
    stack = FakeStack(initial=live, fail_on_up=2)
    google = deployable_project()
    with pytest.raises(Exception, match="simulated"):
        _deploy(google, stack)
    # The failed up left the switch half-applied in config; re-run.
    _deploy(google, stack)
    assert stack.config()["carapace:enclave_image_digest"] == NEW_DIGEST
    assert json.loads(stack.config()["carapace:allowed_digests"]) == [NEW_DIGEST]


def test_resume_after_failed_bootstrap_reuses_allowed_digests() -> None:
    stack = FakeStack(fail_on_up=1)
    google = deployable_project()
    with pytest.raises(Exception, match="simulated"):
        _deploy(google, stack)
    _deploy(google, stack)
    assert [up["carapace:deploy_workloads"] for up in stack.ups] == ["false", "true"]


def test_key_wait_polls_until_enabled() -> None:
    states = iter(["PENDING_GENERATION", "PENDING_GENERATION", "ENABLED"])
    google = deployable_project().on(
        "GET", f"{KMS}/{KEY_VERSION}", lambda _r: ok({"state": next(states)})
    )
    _deploy(google, FakeStack())
    assert len(google.called("GET", f"{KMS}/{KEY_VERSION}")) == 3


def test_key_wait_fails_fast_and_times_out() -> None:
    failed = deployable_project().on(
        "GET", f"{KMS}/{KEY_VERSION}", ok({"state": "GENERATION_FAILED"})
    )
    with pytest.raises(DeployStepError, match="GENERATION_FAILED"):
        _deploy(failed, FakeStack())
    stuck = deployable_project().on(
        "GET", f"{KMS}/{KEY_VERSION}", ok({"state": "PENDING_GENERATION"})
    )
    with pytest.raises(PollTimeoutError, match="run the same command again"):
        _deploy(stuck, FakeStack())


def test_failed_migration_fails_the_deploy() -> None:
    google = deployable_project().on(
        "GET",
        f"{RUN}/projects/{PROJECT}/locations/{REGION}/jobs/{PREFIX}-migrate",
        ok(
            {
                "latestCreatedExecution": {
                    "name": "exec-1",
                    "completionStatus": "EXECUTION_FAILED",
                }
            }
        ),
    )
    with pytest.raises(DeployStepError, match="exec-1 ended EXECUTION_FAILED"):
        _deploy(google, FakeStack())


def test_deploy_command_end_to_end(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    google = deployable_project()
    stack = FakeStack()
    opened: list[Any] = []

    def open_stack(target, backend, ctx) -> FakeStack:
        opened.append((target, backend))
        return stack

    monkeypatch.setattr(
        command,
        "default_services",
        lambda: command.Services(
            gcp=google.api,
            stack=open_stack,
            clock=instant_clock(),
            first_run=fake_first_run(),
        ),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    out, err = io.StringIO(), io.StringIO()
    code = main(
        [
            "--config-dir",
            str(tmp_path),
            "deploy",
            "--project",
            PROJECT,
            "--prefix",
            PREFIX,
            "--alert-email",
            "a@b.io",
            "--enclave-digest",
            NEW_DIGEST,
            "--server-digest",
            SERVER_DIGEST,
            "--password-stdin",
            "--no-passphrase",
            "--yes",
        ],
        out=out,
        err=err,
    )
    assert code == 0, err.getvalue()
    assert "enclave_url: https://203.0.113.7:8443" in err.getvalue()
    target, backend = opened[0]
    assert target.zone == f"{REGION}-a"
    assert backend.bucket == f"{PROJECT}-carapace-state"
    assert len(stack.ups) == 2
    assert (tmp_path / "enclave.json").exists()
    assert "Verified and pinned the enclave" in err.getvalue()
