"""Bootstrap, key wait, workloads and resume, against fakes.

Google calls go to :class:`FakeGoogle` and the stack is a
:class:`FakeStack`; no ``pulumi`` process runs and nothing reaches the
network.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable
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
    running_enclave_digest,
)
from carapace_cli.deploy.polling import PollTimeoutError
from carapace_cli.deploy.preflight import Target
from carapace_cli.main import main

TARGET = Target(PROJECT, PROJECT_NUMBER, REGION, f"{REGION}-a", PREFIX, ("a@b.io",))
IMAGES = Images(enclave_digest=NEW_DIGEST, server_digest=SERVER_DIGEST)


def _deploy(
    google: FakeGoogle, stack: FakeStack, say: Callable[[str], None] = lambda _: None
) -> dict[str, Any]:
    return run_deploy(
        TARGET,
        api=google.api(),
        stack=stack,
        images=PrebuiltImages(images=IMAGES),
        clock=instant_clock(),
        say=say,
    ).outputs


STALE_CONFIG = {
    "carapace:deploy_workloads": "true",
    "carapace:enclave_image_digest": OLD_DIGEST,
    "carapace:allowed_digests": json.dumps([OLD_DIGEST]),
}


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


def test_live_state_without_local_config_is_never_bootstrapped() -> None:
    # The backend runs the workloads; this machine's config does not know.
    live = {
        "carapace:deploy_workloads": "true",
        "carapace:enclave_image_digest": OLD_DIGEST,
    }
    for local in ({}, {"carapace:deploy_workloads": "false"}):
        stack = FakeStack(initial=local, state=live)
        with pytest.raises(DeployStepError, match="a bootstrap would delete them"):
            _deploy(deployable_project(), stack)
        assert not stack.ups


def test_live_stack_with_matching_config_skips_the_bootstrap() -> None:
    live = {
        "carapace:deploy_workloads": "true",
        "carapace:enclave_image_digest": NEW_DIGEST,
        "carapace:allowed_digests": json.dumps([NEW_DIGEST]),
    }
    stack = FakeStack(initial=live)
    said: list[str] = []
    _deploy(deployable_project(), stack, said.append)
    assert "Workloads are already deployed; skipping the bootstrap." in said
    assert [up["carapace:deploy_workloads"] for up in stack.ups] == ["true"]


def test_stale_config_with_empty_state_bootstraps_without_old_digest() -> None:
    # A destroy by an older CLI left the config file but emptied the state.
    stack = FakeStack(initial=STALE_CONFIG, state={})
    said: list[str] = []
    outputs = _deploy(deployable_project(), stack, said.append)
    assert any("ignoring its stale digests" in line for line in said)
    assert not any("skipping the bootstrap" in line for line in said)
    bootstrap, *workloads = stack.ups
    assert bootstrap["carapace:deploy_workloads"] == "false"
    assert bootstrap["carapace:enclave_image_digest"] == ""
    assert workloads, "the workloads step ran no up"
    # No up of the new deployment trusts the old enclave, not even briefly.
    assert all(
        json.loads(up["carapace:allowed_digests"]) == [NEW_DIGEST] for up in stack.ups
    )
    assert all(up["carapace:enclave_image_digest"] == NEW_DIGEST for up in workloads)
    assert outputs["enclave_url"].startswith("https://")


def test_stale_config_with_unknown_digest_bootstraps_with_placeholder() -> None:
    class LaterImages:
        def enclave_digest_hint(self) -> None:
            return None

        def publish(self, registry: str) -> Images:
            return IMAGES

    stack = FakeStack(initial=STALE_CONFIG, state={})
    run_deploy(
        TARGET,
        api=deployable_project().api(),
        stack=stack,
        images=LaterImages(),
        clock=instant_clock(),
        say=lambda _: None,
    )
    allowed = [json.loads(up["carapace:allowed_digests"]) for up in stack.ups]
    assert allowed[0] == [PLACEHOLDER_DIGEST]
    assert all(OLD_DIGEST not in digests for digests in allowed)


def test_rerun_after_failed_first_workloads_up_resumes_without_bootstrap() -> None:
    # The bootstrap finished, then the first workloads up failed: the config
    # says live, the state has bootstrap outputs but no enclave_url. The
    # workloads step resumes; a second bootstrap would gain nothing.
    stack = FakeStack(fail_on_up=2)
    google = deployable_project()
    with pytest.raises(Exception, match="simulated"):
        _deploy(google, stack)
    said: list[str] = []
    _deploy(google, stack, said.append)
    assert "The last deploy stopped before the workloads ran; " in " ".join(said)
    assert not any("stale digests" in line for line in said)
    assert [up["carapace:deploy_workloads"] for up in stack.ups] == ["false", "true"]
    assert all(
        json.loads(up["carapace:allowed_digests"]) == [NEW_DIGEST] for up in stack.ups
    )


def test_config_that_says_live_over_a_state_with_outputs_never_bootstraps() -> None:
    # Whatever the state's outputs say about the workloads (here: nothing),
    # a config that says they run is never answered with a
    # deploy_workloads=false up: were the enclave_url output merely
    # missing, that up would delete the live VM and Cloud Run.
    bootstrapped = {"carapace:deploy_workloads": "false"}
    stack = FakeStack(initial=STALE_CONFIG, state=bootstrapped)
    said: list[str] = []
    _deploy(deployable_project(), stack, said.append)
    assert any("resuming the workloads step" in line for line in said)
    assert stack.ups, "the deploy ran no up"
    assert all(up["carapace:deploy_workloads"] == "true" for up in stack.ups)
    # No workloads ran, so there is no previous digest to roll from: the
    # stale one in the config is not it.
    assert [json.loads(up["carapace:allowed_digests"]) for up in stack.ups] == [
        [NEW_DIGEST]
    ]


LIVE_DIGEST = "sha256:" + "04" * 32


def test_stale_config_digest_never_enters_a_live_rollout() -> None:
    # The stack was destroyed and redeployed from another machine (its
    # enclave now runs LIVE_DIGEST); this machine's config file still names
    # the dead deployment's OLD_DIGEST. The rollout starts from what the
    # state runs, so the dead enclave's digest is never allowed again.
    live = {
        "carapace:deploy_workloads": "true",
        "carapace:enclave_image_digest": LIVE_DIGEST,
        "carapace:allowed_digests": json.dumps([LIVE_DIGEST]),
    }
    stack = FakeStack(initial=STALE_CONFIG, state=live)
    _deploy(deployable_project(), stack)
    plan = [
        (
            json.loads(up["carapace:allowed_digests"]),
            up["carapace:enclave_image_digest"],
        )
        for up in stack.ups
    ]
    assert plan == [
        ([LIVE_DIGEST, NEW_DIGEST], LIVE_DIGEST),
        ([LIVE_DIGEST, NEW_DIGEST], NEW_DIGEST),
        ([NEW_DIGEST], NEW_DIGEST),
    ]
    assert all(OLD_DIGEST not in json.dumps(up) for up in stack.ups)


def test_running_enclave_digest_comes_from_the_state_only() -> None:
    reference = f"{REGION}-docker.pkg.dev/{PROJECT}/{PREFIX}/enclave@{OLD_DIGEST}"
    live = {"enclave_url": "https://203.0.113.7:8443"}
    assert running_enclave_digest(live | {"enclave_image_reference": reference}) == (
        OLD_DIGEST
    )
    # Not live: the reference, even if present, is not a running enclave.
    assert running_enclave_digest({"enclave_image_reference": reference}) is None
    # Live but unparseable: no digest to roll from rather than a guess.
    for bad in ("", "enclave", "enclave@sha256:short", "enclave@" + "0" * 71):
        assert running_enclave_digest(live | {"enclave_image_reference": bad}) is None


def test_bootstrap_ignores_allowed_digests_when_state_is_empty() -> None:
    # Not live, but the digests in the file belong to no stack in the state.
    leftover = {
        "carapace:deploy_workloads": "false",
        "carapace:allowed_digests": json.dumps([OLD_DIGEST]),
    }
    stack = FakeStack(initial=leftover, state={})
    _deploy(deployable_project(), stack)
    assert all(
        json.loads(up["carapace:allowed_digests"]) == [NEW_DIGEST] for up in stack.ups
    )


def test_missing_bootstrap_outputs_fail_with_a_clear_error() -> None:
    class NoOutputsStack(FakeStack):
        def up(self) -> dict[str, Any]:
            super().up()
            return {}

    with pytest.raises(DeployStepError, match="kms_key_version_name"):
        _deploy(deployable_project(), NoOutputsStack())


def test_missing_workloads_outputs_fail_with_a_clear_error() -> None:
    class NoMigrationStack(FakeStack):
        def up(self) -> dict[str, Any]:
            outputs = super().up()
            outputs.pop("migration_job", None)
            return outputs

    with pytest.raises(DeployStepError, match="migration_job"):
        _deploy(deployable_project(), NoMigrationStack())


def test_same_digest_update_is_one_up() -> None:
    assert rollout_steps(NEW_DIGEST, NEW_DIGEST) == [([NEW_DIGEST], NEW_DIGEST)]
    assert rollout_steps(None, NEW_DIGEST) == [([NEW_DIGEST], NEW_DIGEST)]


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
