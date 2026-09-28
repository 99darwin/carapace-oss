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
    BOOT_IMAGES,
    ENCLAVE_VM_URN,
    FULL_STACK_URNS,
    NEW_BOOT_IMAGE,
    NEW_DIGEST,
    OLD_BOOT_IMAGE,
    OLD_DIGEST,
    PREFIX,
    PROJECT,
    PROJECT_NUMBER,
    REGION,
    ROOT_STACK_URN,
    SERVER_DIGEST,
    FakeGoogle,
    FakeStack,
    boot_image_family,
    deployable_project,
    instant_clock,
    replace_gate,
    scripted,
    state_resources,
    transcript,
)
from first_run_support import fake_first_run

from carapace_cli.deploy import command
from carapace_cli.deploy.boot_image import BOOT_IMAGE_KEY, FAMILY_URL
from carapace_cli.deploy.enclave_replace import (
    ALLOW_FLAG,
    BOOT_DISK,
    IMAGE_REFERENCE_PATH,
    METADATA,
    REMOVED,
    UNKNOWN,
    EnclaveReplaceDeclined,
    EnclaveReplaceError,
    EnclaveReplaceGate,
    only_image_reference_changes,
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
NEWER_BOOT_IMAGE = f"{BOOT_IMAGES}confidential-space-251100"


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
    google: FakeGoogle | None = None,
) -> Deployment:
    return run_deploy(
        TARGET,
        api=(google or deployable_project()).api(),
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


def test_a_rerun_after_a_failed_boot_image_replacement_is_not_asked() -> None:
    """The replacement deleted the VM, then its create hit a stockout: the
    VM stays in the state pending replacement. There is nothing left to
    take down, so the rerun that creates it is neither previewed nor
    asked."""
    stack = FakeStack(
        initial=live(),
        boot_image_drift=True,
        stockout_zones=frozenset({TARGET.zone}),
    )
    with pytest.raises(PulumiError, match="run the same command again"):
        deploy(stack, replace_gate(allow=True))
    vm = stack.vm()
    assert vm is not None and vm.pending_replacement
    assert stack.stockouts == [TARGET.zone]
    previews = len(stack.previews)

    stack.stockout_zones = frozenset()
    interview = interactive()  # no answers: a prompt would fail
    deploy(stack, replace_gate(interview))
    assert len(stack.previews) == previews
    assert QUESTION not in transcript(interview)
    vm = stack.vm()
    assert vm is not None and not vm.pending_replacement
    assert vm.outputs["bootDisk"]["initializeParams"]["image"] == NEW_BOOT_IMAGE


def test_an_empty_state_export_stops_the_gate() -> None:
    # The workloads step runs after the bootstrap: an empty export is a
    # broken read, never "no VM".
    stack = FakeStack(initial=live(), resources_in_state=[])
    with pytest.raises(PulumiError, match="listed no resources"):
        replace_gate(allow=True).check(stack, digest_changes=False)
    assert stack.previews == [] and stack.ups == []


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


def test_a_new_digest_with_a_new_boot_image_is_one_replacement() -> None:
    """The rollout step that moves the VM to the new digest takes the new
    boot image too: one outage, which the user chose, so nothing is asked."""
    stack = FakeStack(initial=live(OLD_DIGEST), boot_image_drift=True)
    said: list[str] = []
    deploy(stack, replace_gate(said=said))  # cannot prompt, no flag
    assert len(stack.ups) == 3 and stack.replacements == 1
    # Step 1 keeps the VM's image; step 2 moves digest and image together.
    assert [up[BOOT_IMAGE_KEY] for up in stack.ups] == [
        OLD_BOOT_IMAGE,
        NEW_BOOT_IMAGE,
        NEW_BOOT_IMAGE,
    ]
    (announcement,) = [line for line in said if "replaces the enclave VM" in line]
    assert "enclave image digest changes" in announcement
    assert "new Confidential Space boot image" in announcement


def test_the_boot_image_is_resolved_once_and_pinned_for_every_step() -> None:
    """Google publishing an image mid-deploy changes nothing: every preview
    and every `up` evaluate the image the deploy resolved first, never the
    program's own family lookup."""
    google = deployable_project().on(
        "GET", FAMILY_URL, boot_image_family(NEW_BOOT_IMAGE, NEWER_BOOT_IMAGE)
    )
    stack = FakeStack(
        initial=live(OLD_DIGEST) | {BOOT_IMAGE_KEY: NEW_BOOT_IMAGE},
        family_image=NEWER_BOOT_IMAGE,
    )
    deploy(stack, replace_gate(), google=google)
    lookups = [r for r in google.requests if str(r.url).startswith(FAMILY_URL)]
    assert len(lookups) == 1
    pins = {config[BOOT_IMAGE_KEY] for config in [*stack.previews, *stack.ups]}
    assert pins == {NEW_BOOT_IMAGE}
    assert len(stack.ups) == 3 and stack.replacements == 1


class LateSurprise(FakeStack):
    """After the first `up`, the preview replaces the VM for a cause no
    earlier preview showed (its zone input)."""

    def preview(self) -> list[PreviewStep]:
        steps = super().preview()
        if not self.ups:
            return steps
        return [*steps, step("replace", replace_reasons=("zone",))]


def test_an_unexpected_replace_in_a_later_step_is_refused() -> None:
    stack = LateSurprise(initial=live(OLD_DIGEST))
    interview = interactive("y")
    with pytest.raises(EnclaveReplaceError, match="later step.*zone"):
        deploy(stack, replace_gate(interview))
    assert len(stack.ups) == 1 and stack.replacements == 0
    assert QUESTION not in transcript(interview)


def test_the_flag_does_not_cover_a_later_surprise() -> None:
    stack = LateSurprise(initial=live(OLD_DIGEST))
    with pytest.raises(EnclaveReplaceError, match="not applied"):
        deploy(stack, replace_gate(allow=True))
    assert len(stack.ups) == 1


class Previewing(FakeStack):
    """A live stack whose preview replaces the VM as ``vm_step`` says."""

    def __init__(self, vm_step: PreviewStep) -> None:
        super().__init__(initial=live())
        self.vm_step = vm_step

    def preview(self) -> list[PreviewStep]:
        return [self.vm_step]


IMAGE_REFERENCE_REPLACE = {IMAGE_REFERENCE_PATH: "update-replace"}


def test_a_digest_step_changing_the_image_reference_alone_is_not_asked() -> None:
    stack = Previewing(
        step(
            "replace",
            replace_reasons=("metadata",),
            detailed_diff=IMAGE_REFERENCE_REPLACE,
        )
    )
    replace_gate().check(stack, digest_changes=True)


def test_a_digest_step_changing_other_metadata_is_asked() -> None:
    # A tee-env-* key moving in the digest step is not the change the user
    # chose by picking the images.
    stack = Previewing(
        step(
            "replace",
            replace_reasons=("metadata",),
            detailed_diff=IMAGE_REFERENCE_REPLACE
            | {'metadata["tee-env-CONTROL_PLANE_URL"]': "update-replace"},
        )
    )
    said: list[str] = []
    with pytest.raises(MissingInputError, match=ALLOW_FLAG):
        replace_gate(said=said).check(stack, digest_changes=True)
    assert any("its metadata changes" in line for line in said)


def test_a_digest_step_without_a_detailed_diff_is_asked() -> None:
    # Without detailedDiff the metadata key cannot be told: fail closed.
    stack = Previewing(step("replace", replace_reasons=("metadata",)))
    with pytest.raises(MissingInputError, match=ALLOW_FLAG):
        replace_gate().check(stack, digest_changes=True)


def test_only_image_reference_changes_reads_metadata_replace_paths() -> None:
    boot = {"bootDisk.initializeParams.image": "update-replace"}
    assert only_image_reference_changes(
        [step("replace", detailed_diff=IMAGE_REFERENCE_REPLACE | boot)]
    )
    # An in-place metadata update is not a replace path.
    assert only_image_reference_changes(
        [
            step(
                "replace",
                detailed_diff=IMAGE_REFERENCE_REPLACE
                | {'metadata["tee-env-X"]': "update"},
            )
        ]
    )
    assert not only_image_reference_changes([step("replace", detailed_diff=boot)])
    assert not only_image_reference_changes([step("replace")])
    assert not only_image_reference_changes(
        [step("replace", detailed_diff={"metadata": "update-replace"})]
    )


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

    # The VM booted an image older than the one the family now names.
    stack.set_vm(image=OLD_BOOT_IMAGE)
    code, output = run_cli(monkeypatch, tmp_path, stack)
    assert code != 0
    assert f"pass {ALLOW_FLAG}" in output
    assert "new Confidential Space boot image" in output
    assert len(stack.ups) == ups and stack.replacements == 0

    code, output = run_cli(monkeypatch, tmp_path, stack, ALLOW_FLAG)
    assert code == 0, output
    assert len(stack.ups) == ups + 1 and stack.replacements == 1
