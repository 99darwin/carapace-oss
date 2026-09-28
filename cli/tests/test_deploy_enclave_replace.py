"""The preview gate before a workloads ``up`` replaces the live enclave VM.

The stack is a :class:`FakeStack` whose preview reports what its next
``up`` would do to the VM; no ``pulumi`` process runs.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from deploy_support import (
    ENCLAVE_VM_URN,
    FULL_STACK_URNS,
    NEW_DIGEST,
    OLD_DIGEST,
    PREFIX,
    PROJECT,
    PROJECT_NUMBER,
    REGION,
    ROOT_STACK_URN,
    SERVER_DIGEST,
    FakeStack,
    deployable_project,
    instant_clock,
    replace_gate,
    scripted,
    state_resources,
    transcript,
)
from first_run_support import fake_first_run

from carapace_cli.deploy import command
from carapace_cli.deploy.enclave_replace import (
    ALLOW_FLAG,
    BOOT_DISK,
    METADATA,
    REMOVED,
    UNKNOWN,
    EnclaveReplaceDeclined,
    EnclaveReplaceError,
    EnclaveReplaceGate,
    replace_causes,
)
from carapace_cli.deploy.infra import PulumiError
from carapace_cli.deploy.interview import Interview, MissingInputError
from carapace_cli.deploy.orchestrate import (
    Deployment,
    Images,
    PrebuiltImages,
    run_deploy,
)
from carapace_cli.deploy.preflight import Target
from carapace_cli.deploy.pulumi_runner import PreviewStep
from carapace_cli.main import main

TARGET = Target(PROJECT, PROJECT_NUMBER, REGION, f"{REGION}-a", PREFIX, ("a@b.io",))
INSTANCE_TYPE = "gcp:compute/instance:Instance"
QUESTION = "Replace the enclave VM now?"


def live(digest: str = NEW_DIGEST) -> dict[str, str]:
    """The config of a stack whose workloads run enclave ``digest``."""
    return {
        "carapace:deploy_workloads": "true",
        "carapace:enclave_image_digest": digest,
        "carapace:allowed_digests": json.dumps([digest]),
    }


def deploy(
    stack: FakeStack,
    gate: EnclaveReplaceGate,
    *,
    enclave: str = NEW_DIGEST,
) -> Deployment:
    return run_deploy(
        TARGET,
        api=deployable_project().api(),
        stack=stack,
        images=PrebuiltImages(Images(enclave, SERVER_DIGEST)),
        clock=instant_clock(),
        say=lambda _: None,
        replace_gate=gate,
    )


def interactive(*answers: str) -> Interview:
    return scripted(*answers, interactive=True)


# -- when nothing is replaced -------------------------------------------------


def test_an_update_that_keeps_the_vm_asks_nothing() -> None:
    stack = FakeStack(initial=live())
    interview = interactive()  # no answers: a prompt would fail
    said: list[str] = []
    deploy(stack, replace_gate(interview, said=said))
    assert len(stack.previews) == 1 and len(stack.ups) == 1
    assert QUESTION not in transcript(interview)
    assert not any("replaces the enclave VM" in line for line in said)
    assert stack.replacements == 0


def test_a_first_deploy_is_never_previewed() -> None:
    stack = FakeStack()
    deploy(stack, replace_gate(interactive()))
    assert stack.previews == []
    assert [up["carapace:deploy_workloads"] for up in stack.ups] == ["false", "true"]


def test_a_resume_with_no_vm_in_the_state_is_not_previewed() -> None:
    # A replacement whose create failed left no VM: nothing to take down.
    stack = FakeStack(
        initial=live(),
        boot_image_drift=True,
        resources_in_state=state_resources(FULL_STACK_URNS),
    )
    deploy(stack, replace_gate())
    assert stack.previews == []
    assert len(stack.ups) == 1


# -- a new Confidential Space boot image --------------------------------------


def test_boot_image_drift_is_explained_and_declining_changes_nothing() -> None:
    stack = FakeStack(initial=live(), boot_image_drift=True)
    interview = interactive("n")
    said: list[str] = []
    with pytest.raises(EnclaveReplaceDeclined, match="was not replaced"):
        deploy(stack, replace_gate(interview, said=said))
    assert stack.ups == [] and stack.replacements == 0
    assert QUESTION in transcript(interview)
    (announcement,) = [line for line in said if "replaces the enclave VM" in line]
    assert "new Confidential Space boot image" in announcement
    assert "down for a few minutes" in announcement


def test_boot_image_drift_goes_ahead_on_yes() -> None:
    stack = FakeStack(initial=live(), boot_image_drift=True)
    deploy(stack, replace_gate(interactive("y")))
    assert len(stack.ups) == 1 and stack.replacements == 1


def test_a_run_that_cannot_prompt_is_refused_naming_the_flag() -> None:
    for interview in (
        scripted(interactive=False),
        # --yes confirms the deploy, not the replacement.
        scripted(interactive=False, yes=True),
    ):
        stack = FakeStack(initial=live(), boot_image_drift=True)
        with pytest.raises(MissingInputError, match=ALLOW_FLAG):
            deploy(stack, replace_gate(interview))
        assert stack.ups == []


def test_yes_does_not_skip_the_question() -> None:
    stack = FakeStack(initial=live(), boot_image_drift=True)
    interview = scripted("n", interactive=True, yes=True)
    with pytest.raises(EnclaveReplaceDeclined):
        deploy(stack, replace_gate(interview))
    assert QUESTION in transcript(interview) and stack.ups == []


def test_the_flag_lets_a_run_that_cannot_prompt_go_ahead() -> None:
    stack = FakeStack(initial=live(), boot_image_drift=True)
    said: list[str] = []
    deploy(stack, replace_gate(allow=True, said=said))
    assert len(stack.ups) == 1 and stack.replacements == 1
    assert f"{ALLOW_FLAG} given; going ahead." in said


# -- a new enclave digest ------------------------------------------------------


def test_a_new_enclave_digest_is_announced_but_not_asked() -> None:
    stack = FakeStack(initial=live(OLD_DIGEST))
    said: list[str] = []
    deploy(stack, replace_gate(said=said))  # cannot prompt, no flag
    assert len(stack.ups) == 3 and len(stack.previews) == 3
    assert stack.replacements == 1
    (announcement,) = [line for line in said if "replaces the enclave VM" in line]
    assert "enclave image digest changes" in announcement
    assert "boot image" not in announcement


def test_a_new_digest_with_a_new_boot_image_asks_once() -> None:
    stack = FakeStack(initial=live(OLD_DIGEST), boot_image_drift=True)
    with pytest.raises(MissingInputError, match=ALLOW_FLAG):
        deploy(stack, replace_gate())
    assert stack.ups == []

    stack = FakeStack(initial=live(OLD_DIGEST), boot_image_drift=True)
    interview = interactive("y")
    deploy(stack, replace_gate(interview))
    assert transcript(interview).count(QUESTION) == 1
    assert len(stack.ups) == 3
    # The first step takes the new boot image, the second the new digest.
    assert stack.replacements == 2


def test_an_unexpected_replace_in_a_later_step_is_refused() -> None:
    # Google publishes a new image after the rollout's first up.
    stack = FakeStack(initial=live(OLD_DIGEST), drift_after_ups=1)
    interview = interactive("y")
    with pytest.raises(EnclaveReplaceError, match="later step.*bootDisk"):
        deploy(stack, replace_gate(interview))
    assert len(stack.ups) == 1 and stack.replacements == 0
    assert QUESTION not in transcript(interview)


def test_the_flag_does_not_cover_a_later_surprise() -> None:
    stack = FakeStack(initial=live(OLD_DIGEST), drift_after_ups=1)
    with pytest.raises(EnclaveReplaceError, match="not applied"):
        deploy(stack, replace_gate(allow=True))
    assert len(stack.ups) == 1


def test_a_metadata_change_without_a_new_digest_is_asked() -> None:
    # Same digest, yet the metadata changes: the rollout's last step, or
    # an input other than the digest (say the control plane URL).
    gate = replace_gate(interactive("n"))
    stack = FakeStack(initial=live())
    stack.set_config({"carapace:enclave_image_digest": OLD_DIGEST})
    with pytest.raises(EnclaveReplaceDeclined):
        gate.check(stack, digest_changes=False)


# -- the preview failing -------------------------------------------------------


def test_a_failed_preview_stops_before_any_up() -> None:
    stack = FakeStack(
        initial=live(),
        preview_error=PulumiError("pulumi preview did not print a JSON preview"),
    )
    with pytest.raises(PulumiError, match="did not print a JSON preview"):
        deploy(stack, replace_gate(allow=True))
    assert stack.ups == [] and len(stack.previews) == 1


# -- reading the causes --------------------------------------------------------


def step(op: str, **kwargs: object) -> PreviewStep:
    return PreviewStep(op=op, urn=ENCLAVE_VM_URN, type=INSTANCE_TYPE, **kwargs)  # type: ignore[arg-type]


def test_replace_causes_reads_every_replacing_op() -> None:
    root = PreviewStep("same", ROOT_STACK_URN, "pulumi:pulumi:Stack")
    assert replace_causes([root, step("same"), step("update")]) == frozenset()
    for op in ("replace", "create-replacement", "delete-replaced"):
        assert replace_causes([step(op, replace_reasons=("metadata",))]) == {METADATA}
    assert replace_causes([step("delete")]) == {REMOVED}
    # No reason given: still a replacement, never "nothing".
    assert replace_causes([step("replace")]) == {UNKNOWN}


def test_replace_causes_falls_back_to_the_detailed_diff() -> None:
    detailed = {
        "bootDisk.initializeParams.image": "update-replace",
        "labels": "update",
        'metadata["tee-image-reference"]': "update-replace",
    }
    assert replace_causes([step("replace", detailed_diff=detailed)]) == {
        BOOT_DISK,
        METADATA,
    }


def test_other_resources_being_replaced_are_not_the_gates_concern() -> None:
    other = PreviewStep(
        "replace",
        ENCLAVE_VM_URN.replace(INSTANCE_TYPE, "gcp:compute/address:Address"),
        "gcp:compute/address:Address",
        replace_reasons=("name",),
    )
    assert replace_causes([other]) == frozenset()


def test_an_unknown_cause_is_named_and_asked() -> None:
    class Replacing(FakeStack):
        def preview(self) -> list[PreviewStep]:
            return [step("replace", replace_reasons=("zone",))]

    said: list[str] = []
    with pytest.raises(MissingInputError, match=ALLOW_FLAG):
        replace_gate(said=said).check(Replacing(initial=live()), digest_changes=True)
    assert any("its zone input(s) change" in line for line in said)


# -- the command ---------------------------------------------------------------

DEPLOY = [
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
]


def run_cli(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stack: FakeStack, *extra: str
) -> tuple[int, str]:
    google = deployable_project()
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
    err = io.StringIO()
    code = main(
        ["--config-dir", str(tmp_path), *DEPLOY, *extra], out=io.StringIO(), err=err
    )
    return code, err.getvalue()


def test_deploy_rerun_after_a_new_boot_image_needs_the_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stack = FakeStack()
    code, output = run_cli(monkeypatch, tmp_path, stack)
    assert code == 0, output
    assert stack.previews == []
    ups = len(stack.ups)

    stack.boot_image_drift = True
    code, output = run_cli(monkeypatch, tmp_path, stack)
    assert code != 0
    assert f"pass {ALLOW_FLAG}" in output
    assert "new Confidential Space boot image" in output
    assert len(stack.ups) == ups and stack.replacements == 0

    code, output = run_cli(monkeypatch, tmp_path, stack, ALLOW_FLAG)
    assert code == 0, output
    assert len(stack.ups) == ups + 1 and stack.replacements == 1
