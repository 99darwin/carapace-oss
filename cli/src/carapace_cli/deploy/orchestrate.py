"""The deploy's Pulumi steps: bootstrap, key wait, images, workloads.

Each step reads the stack's current config first, so running the command
again after a failure resumes where it stopped instead of starting over.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from carapace_cli.deploy.gcp import KMS, RUN, GcpApi
from carapace_cli.deploy.interview import InvalidInputError
from carapace_cli.deploy.polling import Clock, poll_until
from carapace_cli.deploy.preflight import Target
from carapace_cli.deploy.pulumi_runner import StackHandle
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
    }


def allowed_digests(config: dict[str, str]) -> list[str]:
    value = json.loads(config.get("carapace:allowed_digests") or "[]")
    return [str(digest) for digest in value] if isinstance(value, list) else []


def workloads_live(config: dict[str, str]) -> bool:
    return config.get("carapace:deploy_workloads", TRUE) == TRUE and bool(
        config.get("carapace:enclave_image_digest")
    )


def bootstrap(
    stack: StackHandle,
    target: Target,
    *,
    enclave_digest: str | None,
    say: Callable[[str], None],
) -> dict[str, Any]:
    """``up`` with ``deploy_workloads=false``, unless workloads already run.

    A bootstrap on a live stack would delete the VM and Cloud Run, so an
    update goes straight to the workloads step.
    """
    current = stack.config()
    if workloads_live(current):
        say("Workloads are already deployed; skipping the bootstrap.")
        return stack.outputs()
    allowed = allowed_digests(current) or [enclave_digest or PLACEHOLDER_DIGEST]
    say("Bootstrap: KMS, identity, database, registry and network...")
    stack.set_config(
        {
            **base_config(target),
            "carapace:deploy_workloads": FALSE,
            "carapace:allowed_digests": json.dumps(allowed),
        }
    )
    return stack.up()


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


def rollout_steps(
    current: dict[str, str], new_digest: str
) -> list[tuple[list[str], str]]:
    """``(allowed_digests, enclave_image_digest)`` for each ``up``.

    Switching a live enclave takes three, as in SELF_HOST.md: allow the new
    digest, move the VM to it, then drop the old one. The old enclave keeps
    decrypting until the new one runs. Each step is safe to repeat.
    """
    previous = current.get("carapace:enclave_image_digest") or ""
    steps: list[tuple[list[str], str]] = []
    if workloads_live(current) and previous != new_digest:
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
) -> dict[str, Any]:
    outputs: dict[str, Any] = {}
    steps = rollout_steps(stack.config(), images.enclave_digest)
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
        outputs = stack.up()
    return outputs


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


def run_deploy(
    target: Target,
    *,
    api: GcpApi,
    stack: StackHandle,
    images: ImageSource,
    clock: Clock,
    say: Callable[[str], None],
) -> dict[str, Any]:
    """Bootstrap, key wait, images, workloads, migration check. Resumable."""
    outputs = bootstrap(
        stack, target, enclave_digest=images.enclave_digest_hint(), say=say
    )
    wait_for_key(api, str(outputs["kms_key_version_name"]), clock=clock, say=say)
    published = images.publish(str(outputs["image_registry"]))
    outputs = deploy_workloads(stack, target, published, say=say)
    check_migration(api, target, str(outputs["migration_job"]), clock=clock)
    return outputs


@dataclass(frozen=True)
class PrebuiltImages:
    """Digests of images the user already pushed to the stack's registry."""

    images: Images

    def enclave_digest_hint(self) -> str | None:
        return self.images.enclave_digest

    def publish(self, registry: str) -> Images:
        return self.images
