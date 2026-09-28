"""Preview a live workloads ``up`` and confirm before it replaces the VM.

The enclave VM (``components/enclave_vm.py``) is replaced, deleting the
old one first, when its metadata changes (``replace_on_changes``; the
metadata holds the enclave image reference) or its boot image does (the
boot disk image is ForceNew). The boot image is kept current on purpose:
WIF requires the ``STABLE`` support attribute, which Google drops from
old images. The deploy resolves the newest image once and pins it in the
stack config before any preview (:mod:`carapace_cli.deploy.boot_image`),
so a preview and the ``up`` after it evaluate the same image. Since the
CLI runs ``up --yes --skip-preview``, a new image would otherwise take
the enclave down for a few minutes, unannounced.

Before each workloads ``up`` on a stack whose state holds a live VM, the
deploy previews the ``up``. A replacement of the VM is always announced,
with its cause. What is expected is allowed without a question: in the
rollout step that moves the VM to the new enclave digest the user asked
for, a replacement whose metadata change is the enclave image reference
alone, and, folded into that same replacement, a new boot image. Anything
else (a new boot image without a new digest, another metadata key, a
removal, or any other cause) needs a yes at a prompt or, without one,
``--allow-enclave-replace``; ``--yes`` does not cover it. The question is
asked at most once per deploy, before the first ``up`` that touches the
live VM: a later rollout step that would replace the VM for a cause not
expected or already accepted is refused before its ``up``.

First deploys and bootstraps have no VM in the state and are not gated,
and neither is a VM pending replacement: Pulumi already deleted it (a
replacement whose create failed), so there is nothing left to take down.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from carapace_cli.deploy.infra import PulumiError
from carapace_cli.deploy.interview import Interview
from carapace_cli.deploy.pulumi_runner import PreviewStep, StackHandle
from carapace_cli.deploy.zones import ENCLAVE_INSTANCE_TYPE, live_zonal_resource_urns
from carapace_cli.errors import CarapaceError

ALLOW_FLAG = "--allow-enclave-replace"
# Ops that take the VM away: the logical replace, its two physical halves
# (shown with --show-replacement-steps), and a plain delete.
REPLACING_OPS = frozenset({"replace", "create-replacement", "delete-replaced"})
DELETE_OP = "delete"
REPLACE_KIND_SUFFIX = "-replace"
# Causes, keyed by the top-level input of gcp:compute/instance:Instance.
BOOT_DISK = "bootDisk"
METADATA = "metadata"
REMOVED = "(removed)"
UNKNOWN = "(unknown)"
PATH_ROOT = re.compile(r"^[^.\[]+")
# The one metadata key a new enclave digest changes (build_enclave_metadata
# in components/enclave_vm.py), as Pulumi writes the path in detailedDiff.
IMAGE_REFERENCE_PATH = 'metadata["tee-image-reference"]'
DOWNTIME = (
    "The enclave is down for a few minutes while the VM is deleted and "
    "recreated (the enclave URL is kept)."
)


class EnclaveReplaceError(CarapaceError):
    """The enclave VM would be replaced without the user's consent."""


class EnclaveReplaceDeclined(CarapaceError):
    """The user answered no; nothing was applied."""


def _root(path: str) -> str:
    match = PATH_ROOT.match(path)
    return match.group(0) if match else path


def replace_causes(steps: Iterable[PreviewStep]) -> frozenset[str]:
    """Why the preview replaces or deletes the enclave VM; empty if it does not.

    Each cause is a top-level input of the instance. Pulumi's
    ``replaceReasons`` are used, with the paths ``detailedDiff`` marks as
    ``*-replace`` as a fallback; a replacement with neither is
    :data:`UNKNOWN`, never "no cause".
    """
    causes: set[str] = set()
    for step in _vm_steps(steps):
        if step.op == DELETE_OP:
            causes.add(REMOVED)
            continue
        reasons = {_root(reason) for reason in step.replace_reasons}
        reasons |= {_root(path) for path in _replace_paths(step)}
        causes |= reasons or {UNKNOWN}
    return frozenset(causes)


def only_image_reference_changes(steps: Iterable[PreviewStep]) -> bool:
    """Whether the enclave image reference is the only metadata that forces
    the replacement, as ``detailedDiff`` says.

    A step with no detailed metadata path does not qualify: the cause
    cannot be told apart from another key (say a ``tee-env-*``) changing.
    """
    paths = {
        path
        for step in _vm_steps(steps)
        if step.op != DELETE_OP
        for path in _replace_paths(step)
        if _root(path) == METADATA
    }
    return paths == {IMAGE_REFERENCE_PATH}


def _vm_steps(steps: Iterable[PreviewStep]) -> list[PreviewStep]:
    """The steps that replace or delete the enclave VM."""
    return [
        step
        for step in steps
        if step.type == ENCLAVE_INSTANCE_TYPE
        and (step.op == DELETE_OP or step.op in REPLACING_OPS)
    ]


def _replace_paths(step: PreviewStep) -> list[str]:
    return [
        path
        for path, kind in step.detailed_diff.items()
        if kind.endswith(REPLACE_KIND_SUFFIX)
    ]


def describe_causes(causes: frozenset[str], *, digest_changes: bool) -> str:
    """One clause per cause, for the line that announces the replacement."""
    phrases: list[str] = []
    if BOOT_DISK in causes:
        phrases.append(
            "Google published a new Confidential Space boot image (the image "
            "is kept current: attestation requires a STABLE one)"
        )
    if METADATA in causes:
        phrases.append(
            "the enclave image digest changes"
            if digest_changes
            else "its metadata changes (enclave image, control plane URL, "
            "KMS key or WIF audience)"
        )
    if REMOVED in causes:
        phrases.append("the update would delete it")
    if UNKNOWN in causes:
        phrases.append("pulumi gave no reason")
    others = sorted(causes - {BOOT_DISK, METADATA, REMOVED, UNKNOWN})
    if others:
        phrases.append(f"its {', '.join(others)} input(s) change")
    return "; ".join(phrases)


@dataclass
class EnclaveReplaceGate:
    """Confirms, once per deploy, a replacement of the live enclave VM.

    ``allow`` is ``--allow-enclave-replace``: consent given up front, for
    runs that cannot prompt. ``accepted`` holds the causes the user
    already agreed to in this deploy; ``previewed`` is set once the first
    ``up`` on the live VM was previewed, after which nothing is asked.
    """

    interview: Interview
    allow: bool
    say: Callable[[str], None]
    accepted: frozenset[str] = frozenset()
    previewed: bool = field(default=False)

    def check(self, stack: StackHandle, *, digest_changes: bool) -> None:
        """Preview the next ``up``; return only if it may run.

        ``digest_changes`` says this ``up`` moves the live VM to another
        enclave digest, which the user asked for by choosing the images.
        That step also carries the newest boot image (see
        :func:`carapace_cli.deploy.orchestrate.deploy_workloads`), so a new
        boot image costs no outage of its own there.

        Raises:
            EnclaveReplaceDeclined: The user answered no.
            EnclaveReplaceError: A later step would replace the VM for a
                cause not accepted.
            MissingInputError: The run cannot prompt and ``allow`` is off.
            PulumiError: The state lists no resource at all, or the preview
                failed or printed no usable digest.
        """
        resources = stack.resources()
        if not resources:
            # The workloads step runs after the bootstrap, so its state is
            # never empty; an empty export is not read as "no VM".
            raise PulumiError(
                "pulumi stack export listed no resources before the workloads "
                "step; nothing was changed. Check `pulumi stack export`, then "
                "run the same command again"
            )
        if not live_zonal_resource_urns(resources):
            return
        self.say("Previewing the update of the live enclave VM...")
        steps = stack.preview()
        causes = replace_causes(steps)
        first = not self.previewed
        self.previewed = True
        if not causes:
            return
        # A digest step whose metadata change is more than the image
        # reference (say a tee-env-* key) is not the change the user chose.
        expected_digest = digest_changes and only_image_reference_changes(steps)
        self.say(
            "This update replaces the enclave VM: "
            f"{describe_causes(causes, digest_changes=expected_digest)}. "
            f"{DOWNTIME}"
        )
        expected = {METADATA, BOOT_DISK} if expected_digest else set()
        unaccepted = causes - expected - self.accepted
        if not unaccepted:
            return
        if not first:
            raise EnclaveReplaceError(
                "a later step of this deploy would replace the enclave VM for "
                f"a cause not confirmed ({', '.join(sorted(unaccepted))}); "
                "that step was not applied. Run the same command again to "
                "review it"
            )
        if self.allow:
            self.say(f"{ALLOW_FLAG} given; going ahead.")
        # --yes confirms the deploy, not taking the enclave down for a
        # cause the user may not know about.
        elif not dataclasses.replace(self.interview, assume_yes=False).confirm(
            "Replace the enclave VM now?", flag=ALLOW_FLAG
        ):
            raise EnclaveReplaceDeclined(
                "this update was not applied and the enclave VM was not "
                f"replaced. Run the same command again, or pass {ALLOW_FLAG}, "
                "when the downtime suits you"
            )
        self.accepted = self.accepted | causes
