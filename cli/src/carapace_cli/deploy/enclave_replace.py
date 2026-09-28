"""Preview a live workloads ``up`` and confirm before it replaces the VM.

The enclave VM (``components/enclave_vm.py``) is replaced, deleting the
old one first, when its metadata changes (``replace_on_changes``; the
metadata holds the enclave image reference) or its boot image does (the
image is resolved from the Confidential Space family on every ``up``,
and the boot disk image is ForceNew). The image is kept fresh on
purpose: WIF requires the ``STABLE`` support attribute, which Google
drops from old images. So any run after Google publishes a new image
would take the enclave down for a few minutes, unannounced, since the
CLI runs ``up --yes --skip-preview``.

Before each workloads ``up`` on a stack whose state holds the VM, the
deploy previews the ``up``. A replacement of the VM is always announced,
with its cause. What is expected is allowed without a question: a
replacement caused by the metadata alone, in the rollout step that moves
the VM to the new enclave digest the user asked for. Anything else (a new
boot image, or any other cause) needs a yes at a prompt or, without one,
``--allow-enclave-replace``; ``--yes`` does not cover it. The question is
asked at most once per deploy, before the first ``up`` that touches the
live VM: a later rollout step that would replace the VM for a cause not
expected or already accepted is refused before its ``up``. (A cause that
shows up only then appeared during the deploy, say a boot image Google
published between two steps, and the user has not seen it.)

First deploys and bootstraps have no VM in the state and are not gated.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from carapace_cli.deploy.interview import Interview
from carapace_cli.deploy.pulumi_runner import PreviewStep, StackHandle
from carapace_cli.deploy.zones import ENCLAVE_INSTANCE_TYPE, zonal_resource_urns
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
    for step in steps:
        if step.type != ENCLAVE_INSTANCE_TYPE:
            continue
        if step.op == DELETE_OP:
            causes.add(REMOVED)
            continue
        if step.op not in REPLACING_OPS:
            continue
        reasons = {_root(reason) for reason in step.replace_reasons}
        reasons |= {
            _root(path)
            for path, kind in step.detailed_diff.items()
            if kind.endswith(REPLACE_KIND_SUFFIX)
        }
        causes |= reasons or {UNKNOWN}
    return frozenset(causes)


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

        Raises:
            EnclaveReplaceDeclined: The user answered no.
            EnclaveReplaceError: A later step would replace the VM for a
                cause not accepted.
            MissingInputError: The run cannot prompt and ``allow`` is off.
            PulumiError: The preview failed or printed no usable digest.
        """
        if not zonal_resource_urns(stack.resources()):
            return
        self.say("Previewing the update of the live enclave VM...")
        causes = replace_causes(stack.preview())
        first = not self.previewed
        self.previewed = True
        if not causes:
            return
        self.say(
            "This update replaces the enclave VM: "
            f"{describe_causes(causes, digest_changes=digest_changes)}. "
            f"{DOWNTIME}"
        )
        expected = {METADATA} if digest_changes else set()
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
