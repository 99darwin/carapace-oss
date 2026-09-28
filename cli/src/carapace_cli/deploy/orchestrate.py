"""The deploy's Pulumi steps: bootstrap, key wait, images, workloads.

Each step reads the stack's current config first, so running the command
again after a failure resumes where it stopped instead of starting over.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from carapace_cli.deploy.gcp import KMS, RUN, GcpApi
from carapace_cli.deploy.interview import InvalidInputError
from carapace_cli.deploy.polling import Clock, poll_until
from carapace_cli.deploy.preflight import Target
from carapace_cli.deploy.pulumi_runner import StackHandle
from carapace_cli.deploy.zones import ZoneFallback, up_with_zone_fallback
from carapace_cli.errors import CarapaceError

DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
# Allowed during bootstrap only when the enclave digest is not known yet
# (a local build needs the registry first). No image has this digest, so it
# grants nothing; the workloads step replaces it.
PLACEHOLDER_DIGEST = "sha256:" + "0" * 64
KEY_TIMEOUT_SECONDS = 900.0
KEY_POLL_SECONDS = 10.0
KEY_PENDING_STATES = frozenset({"PENDING_GENERATION", "PENDING_IMPORT"})
MIGRATION_TIMEOUT_SECONDS = 900.0
MIGRATION_POLL_SECONDS = 10.0
MIGRATION_PENDING = frozenset({"EXECUTION_PENDING", "EXECUTION_RUNNING"})
MIGRATION_SUCCEEDED = "EXECUTION_SUCCEEDED"
TRUE = "true"
FALSE = "false"
# Deletion protection on the KMS key and the database. Only `carapace
# destroy` turns it off; every deploy sets it on again, so a config file
# left behind by an interrupted destroy cannot bring a deployment up
# unprotected.
PROTECTED = {
    "carapace:protect_kms_key": TRUE,
    "carapace:db_deletion_protection": TRUE,
}
# The config of a stack with nothing deployed in its state: a new, protected
# stack that bootstraps. Set after a destroy whose ``stack rm`` failed, and
# when a deploy finds a config file that outlived its stack. The digests
# are cleared because a bootstrap reuses the allowed ones (to resume after
# a failure), and a dead deployment's enclave must never be trusted by a
# new one.
FRESH_STACK = {
    **PROTECTED,
    "carapace:deploy_workloads": FALSE,
    "carapace:allowed_digests": "[]",
    "carapace:enclave_image_digest": "",
}
# The outputs run_deploy reads after each step.
BOOTSTRAP_OUTPUTS = ("kms_key_version_name", "image_registry")
WORKLOADS_OUTPUTS = ("migration_job",)


class DeployStepError(CarapaceError):
    """A deploy step finished in a state that cannot succeed."""


@dataclass(frozen=True)
class Images:
    enclave_digest: str
    server_digest: str


class ImageSource(Protocol):
    def enclave_digest_hint(self) -> str | None:
        """The enclave digest, if known before the registry exists."""
        ...

    def publish(self, registry: str) -> Images:
        """Put both images into ``registry`` and return their digests."""
        ...


def validate_digest(value: str) -> str:
    if not DIGEST_PATTERN.fullmatch(value):
        raise InvalidInputError(f"{value!r} is not a sha256:<64 hex> image digest")
    return value


def base_config(target: Target) -> dict[str, str]:
    """The keys the deploy owns. Other keys the user set are left alone."""
    return {
        "gcp:project": target.project,
        "gcp:region": target.region,
        # Always explicit: the default, <region>-a, is not valid everywhere.
        "gcp:zone": target.zone,
        "carapace:prefix": target.prefix,
        "carapace:alert_emails": json.dumps(list(target.alert_emails)),
        **PROTECTED,
    }


def allowed_digests(config: dict[str, str]) -> list[str]:
    value = json.loads(config.get("carapace:allowed_digests") or "[]")
    return [str(digest) for digest in value] if isinstance(value, list) else []


def workloads_live(config: dict[str, str]) -> bool:
    """Whether the local config says the workloads are deployed."""
    return config.get("carapace:deploy_workloads", TRUE) == TRUE and bool(
        config.get("carapace:enclave_image_digest")
    )


def state_has_workloads(outputs: Mapping[str, Any]) -> bool:
    """Whether the stack's state, in the backend, runs the workloads.

    The enclave URL is an output only while ``deploy_workloads`` is true,
    so it tells the truth even when the local config file is missing.
    """
    return bool(outputs.get("enclave_url"))


def bootstrap(
    stack: StackHandle,
    target: Target,
    *,
    enclave_digest: str | None,
    say: Callable[[str], None],
) -> dict[str, Any]:
    """``up`` with ``deploy_workloads=false``, unless workloads may run.

    A bootstrap on a live stack would delete the VM and Cloud Run, so an
    update goes straight to the workloads step. Whether the workloads run
    is decided by the state in the backend, not by the local config alone:
    a machine without ``Pulumi.<prefix>.yaml`` must not bootstrap a live
    stack, and a config file that outlived its stack (say, after a destroy
    that did not remove it) must not skip the bootstrap or carry the dead
    deployment's digests into the new one.

    The bootstrap ``up`` never runs while the config says the workloads
    run and the state has any outputs. Without ``enclave_url`` among them
    the first workloads ``up`` failed, and the workloads step resumes it:
    it creates what is missing and deletes nothing, so a merely missing
    output cannot turn the resume into a bootstrap that deletes a live VM.
    """
    current = stack.config()
    outputs = stack.outputs()
    is_live = state_has_workloads(outputs)
    if is_live and not workloads_live(current):
        raise DeployStepError(
            f"stack {target.prefix!r} runs workloads, but the config on this "
            "machine does not say so; a bootstrap would delete them. Copy "
            f"infra/pulumi/Pulumi.{target.prefix}.yaml from the machine that "
            "deployed, then run the same command again"
        )
    if workloads_live(current) and outputs:
        say(
            "Workloads are already deployed; skipping the bootstrap."
            if is_live
            else "The last deploy stopped before the workloads ran; resuming "
            "the workloads step."
        )
        return outputs
    if workloads_live(current):
        say(
            f"infra/pulumi/Pulumi.{target.prefix}.yaml says workloads run, but "
            "the stack's state is empty; ignoring its stale digests."
        )
        stack.set_config(FRESH_STACK)
        current = stack.config()
    allowed = _resumable_digests(current, outputs) or [
        enclave_digest or PLACEHOLDER_DIGEST
    ]
    say("Bootstrap: KMS, identity, database, registry and network...")
    stack.set_config(
        {
            **base_config(target),
            "carapace:deploy_workloads": FALSE,
            "carapace:allowed_digests": json.dumps(allowed),
        }
    )
    return stack.up()


def _resumable_digests(config: dict[str, str], outputs: Mapping[str, Any]) -> list[str]:
    """The config's allowed digests, if a bootstrap to resume is in the state.

    An empty state has nothing to resume, so digests in the config file
    are left over from another stack and are not trusted.
    """
    return allowed_digests(config) if outputs else []


def require_outputs(
    outputs: Mapping[str, Any], names: tuple[str, ...], *, step: str
) -> None:
    """Fail with a clear error if ``step`` left any of ``names`` unset."""
    missing = [name for name in names if not outputs.get(name)]
    if missing:
        raise DeployStepError(
            f"the {step} finished without the stack outputs "
            f"{', '.join(missing)}; check `pulumi stack output` and the "
            "Pulumi log above, then run the same command again"
        )


def wait_for_key(
    api: GcpApi, version_name: str, *, clock: Clock, say: Callable[[str], None]
) -> None:
    """Wait for the HSM key version to be ``ENABLED``."""
    say("Waiting for the HSM key version to be ENABLED...")

    def enabled() -> bool | None:
        state = api.get(f"{KMS}/{version_name}").get("state")
        if state == "ENABLED":
            return True
        if state in KEY_PENDING_STATES:
            return None
        raise DeployStepError(f"KMS key version {version_name} is {state}")

    poll_until(
        enabled,
        what="the HSM key version",
        timeout_seconds=KEY_TIMEOUT_SECONDS,
        interval_seconds=KEY_POLL_SECONDS,
        clock=clock,
    )


def running_enclave_digest(outputs: Mapping[str, Any]) -> str | None:
    """The digest of the enclave the state runs; None while none does.

    Read from the state's ``enclave_image_reference`` output, never from
    the local config: ``Pulumi.<prefix>.yaml`` can be older than the stack
    (copied from another machine, or kept across a destroy and redeploy),
    and a rollout that started from its digest would move the live VM
    onto a dead deployment's image and let it decrypt again.
    """
    if not state_has_workloads(outputs):
        return None
    reference = str(outputs.get("enclave_image_reference") or "")
    digest = reference.rpartition("@")[2]
    return digest if DIGEST_PATTERN.fullmatch(digest) else None


def rollout_steps(previous: str | None, new_digest: str) -> list[tuple[list[str], str]]:
    """``(allowed_digests, enclave_image_digest)`` for each ``up``.

    Switching a live enclave takes three, as in SELF_HOST.md: allow the new
    digest, move the VM to it, then drop the old one. The old enclave keeps
    decrypting until the new one runs. Each step is safe to repeat.
    ``previous`` is the digest the state runs, or None without workloads.
    """
    steps: list[tuple[list[str], str]] = []
    if previous and previous != new_digest:
        both = [previous, new_digest]
        steps += [(both, previous), (both, new_digest)]
    steps.append(([new_digest], new_digest))
    return steps


def deploy_workloads(
    stack: StackHandle,
    target: Target,
    images: Images,
    *,
    say: Callable[[str], None],
    fallback: ZoneFallback | None = None,
) -> tuple[dict[str, Any], Target]:
    """Each rollout ``up``; the target returned has the zone that worked.

    With ``fallback``, an ``up`` that fails because the zone is out of
    capacity for a VM the state does not hold (never created, or deleted
    for its replacement) moves to another zone of the region (see
    :mod:`carapace_cli.deploy.zones`); later steps stay there.
    """
    outputs: dict[str, Any] = {}
    steps = rollout_steps(
        running_enclave_digest(stack.outputs()), images.enclave_digest
    )
    for number, (allowed, enclave) in enumerate(steps, start=1):
        say(f"Workloads ({number}/{len(steps)}): enclave {enclave[:19]}...")
        stack.set_config(
            {
                **base_config(target),
                "carapace:deploy_workloads": TRUE,
                "carapace:allowed_digests": json.dumps(allowed),
                "carapace:enclave_image_digest": enclave,
                "carapace:server_image_digest": images.server_digest,
            }
        )
        outputs, target = up_with_zone_fallback(
            stack, target, fallback=fallback, say=say
        )
    return outputs, target


def check_migration(api: GcpApi, target: Target, job: str, *, clock: Clock) -> None:
    """The migration job's latest execution must have succeeded.

    Pulumi already waits for the execution it starts. This check also
    catches an earlier failed run on a re-run with no changes.
    """
    name = job
    if not job.startswith("projects/"):
        name = f"projects/{target.project}/locations/{target.region}/jobs/{job}"

    def finished() -> dict[str, Any] | None:
        execution = api.get(f"{RUN}/{name}").get("latestCreatedExecution") or {}
        status = execution.get("completionStatus")
        if not execution or status in MIGRATION_PENDING:
            return None
        return execution

    execution = poll_until(
        finished,
        what=f"migration job {name}",
        timeout_seconds=MIGRATION_TIMEOUT_SECONDS,
        interval_seconds=MIGRATION_POLL_SECONDS,
        clock=clock,
    )
    if execution.get("completionStatus") != MIGRATION_SUCCEEDED:
        raise DeployStepError(
            f"migration {execution.get('name', name)} ended "
            f"{execution.get('completionStatus')}; see its logs in Cloud Run"
        )


@dataclass(frozen=True)
class Deployment:
    """The stack's outputs, the images it now runs and where it runs them."""

    outputs: dict[str, Any]
    images: Images
    target: Target


def run_deploy(
    target: Target,
    *,
    api: GcpApi,
    stack: StackHandle,
    images: ImageSource,
    clock: Clock,
    say: Callable[[str], None],
    zone_fallback: ZoneFallback | None = None,
) -> Deployment:
    """Bootstrap, key wait, images, workloads, migration check. Resumable.

    ``zone_fallback`` lets the workloads step move the enclave VM to
    another zone of the region when its zone is out of capacity.
    """
    outputs = bootstrap(
        stack, target, enclave_digest=images.enclave_digest_hint(), say=say
    )
    require_outputs(outputs, BOOTSTRAP_OUTPUTS, step="bootstrap")
    wait_for_key(api, str(outputs["kms_key_version_name"]), clock=clock, say=say)
    published = images.publish(str(outputs["image_registry"]))
    outputs, target = deploy_workloads(
        stack, target, published, say=say, fallback=zone_fallback
    )
    require_outputs(outputs, WORKLOADS_OUTPUTS, step="workloads step")
    check_migration(api, target, str(outputs["migration_job"]), clock=clock)
    return Deployment(outputs=outputs, images=published, target=target)


@dataclass(frozen=True)
class PrebuiltImages:
    """Digests of images the user already pushed to the stack's registry."""

    images: Images

    def enclave_digest_hint(self) -> str | None:
        return self.images.enclave_digest

    def publish(self, registry: str) -> Images:
        return self.images
