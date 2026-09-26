"""``carapace destroy``: tear a deployment down, after an explicit warning.

The stack's deletion protection (``protect_kms_key``,
``db_deletion_protection``) is turned off with one ``up`` and then
``pulumi destroy`` runs. The state bucket and state key are not Pulumi
resources and are kept, so the same project can be deployed again.

After a successful destroy the CLI cleans up what only the dead deployment
used: the empty Pulumi stack with its local config file, and the session
and enclave pin in the config directory when they name this deployment's
server and enclave. The owner key is never removed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from carapace_cli.deploy.pulumi_runner import StackHandle
from carapace_cli.deploy.summary import state_bucket_name
from carapace_cli.errors import CarapaceError, StorageError
from carapace_cli.files import (
    FileIdentity,
    read_private_json,
    regular_file_identity,
    remove_private,
)
from carapace_cli.ownerkey_store import owner_key_path
from carapace_cli.pin import pin_path
from carapace_cli.session import session_path
from carapace_cli.urls import normalize_base_url


class DestroyError(CarapaceError):
    """There is no deployment to destroy."""


UNPROTECTED = {
    "carapace:protect_kms_key": "false",
    "carapace:db_deletion_protection": "false",
}
# A stack that could not be removed keeps its config file; these values
# make the next deploy with its prefix bootstrap a new, protected stack.
FRESH_STACK = {
    "carapace:protect_kms_key": "true",
    "carapace:db_deletion_protection": "true",
    "carapace:deploy_workloads": "false",
}

# From docs/SELF_HOST.md, "Teardown".
DESTROY_WARNING = """\
This deletes the enclave VM, Cloud Run, the Cloud SQL database and its
secrets, the service accounts and the IAM change alert of stack {prefix!r}
in {project}.

KMS keys cannot be deleted. Destroy schedules the HSM key version for
destruction; Google waits 30 days by default before it is destroyed.
During that window anyone with cloudkms.cryptoKeyVersions.restore on the
project (an Owner, or a KMS admin) can restore the version and decrypt
every secret sealed to it, and the audit logging and alert that would
report it are already gone. Treat every stored secret, and every database
backup, as readable by a project Owner until then. If the secrets matter,
rotate them at their providers first, or delete the whole project.

Kept: the state bucket gs://{bucket} and its KMS key, the key ring names,
workload identity pools (soft-deleted for 30 days, so a redeploy within
that window needs another prefix), and images, backups and logs under
their own retention rules."""


def destroy_warning(project: str, prefix: str) -> str:
    return DESTROY_WARNING.format(
        prefix=prefix, project=project, bucket=state_bucket_name(project)
    )


def run_destroy(stack: StackHandle, *, say: Callable[[str], None]) -> None:
    """Lift deletion protection, then destroy every resource of the stack.

    Both steps are idempotent, so a failed destroy is resumed by running
    the same command again.
    """
    if any(stack.config().get(key) != value for key, value in UNPROTECTED.items()):
        say("Turning off deletion protection on the KMS key and database...")
        stack.set_config(UNPROTECTED)
        stack.up()
    say("Destroying the stack...")
    stack.destroy()


def remove_stack(
    stack: StackHandle, *, prefix: str, say: Callable[[str], None]
) -> None:
    """``pulumi stack rm`` after a destroy; a failure is reported, not raised.

    The resources are gone either way. A stack left behind is empty; its
    config is reset so that a new deploy bootstraps rather than resuming.
    """
    try:
        stack.remove()
    except CarapaceError as exc:
        say(f"Could not remove the empty Pulumi stack {prefix!r}: {exc}.")
        try:
            stack.set_config(FRESH_STACK)
        except CarapaceError as reset_exc:
            say(
                f"Could not reset its config either ({reset_exc}); delete "
                f"infra/pulumi/Pulumi.{prefix}.yaml before deploying {prefix!r} "
                "again."
            )
        else:
            say(f"A new deploy with prefix {prefix!r} will start from scratch.")
        return
    say(f"Removed the Pulumi stack {prefix!r} and its local config.")


@dataclass(frozen=True)
class DeploymentUrls:
    """The server and enclave URLs of a deployment, as the CLI stores them."""

    server_urls: frozenset[str]
    enclave_urls: frozenset[str]


def _normalized(values: list[Any], what: str) -> frozenset[str]:
    urls: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value:
            continue
        try:
            urls.add(normalize_base_url(value, what=what, allow_loopback_http=False))
        except CarapaceError:
            continue
    return frozenset(urls)


def deployment_urls(outputs: Mapping[str, Any]) -> DeploymentUrls:
    """Read from the stack outputs before they are destroyed."""
    return DeploymentUrls(
        server_urls=_normalized(
            [outputs.get("control_plane_url"), outputs.get("server_url")], "server"
        ),
        enclave_urls=_normalized([outputs.get("enclave_url")], "enclave"),
    )


@dataclass(frozen=True)
class _LocalFile:
    path: Path
    label: str
    url_field: str
    urls: frozenset[str]


class _KeepConfigDir(Exception):
    """A reason to leave the whole config directory as it is."""


def _check_owned(local: _LocalFile) -> FileIdentity | None:
    """The file's identity if it belongs to the deployment; None if absent.

    Raises:
        _KeepConfigDir: The file is not a regular file, is unreadable, or
            names another deployment.
    """
    try:
        identity = regular_file_identity(local.path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _KeepConfigDir(f"cannot inspect {local.path}: {exc.strerror}") from None
    if identity is None:
        raise _KeepConfigDir(f"{local.path} is not a regular file")
    try:
        value = read_private_json(local.path).get(local.url_field)
    except StorageError as exc:
        raise _KeepConfigDir(f"cannot read the {local.label}: {exc}") from None
    if not local.urls:
        raise _KeepConfigDir(
            f"the stack had no {local.url_field} to match the {local.label} with"
        )
    if not isinstance(value, str) or value not in local.urls:
        raise _KeepConfigDir(f"the {local.label} is for {value!r}, another deployment")
    return identity


def forget_deployment(config_dir: Path, urls: DeploymentUrls) -> list[str]:
    """Remove the session and enclave pin, if they are this deployment's.

    Either both files that exist belong to the destroyed deployment and
    are removed, or nothing is touched. Symlinks and other non-regular
    files are never followed or removed. The owner key is always kept.
    Returns the lines to show the user.
    """
    files = (
        _LocalFile(session_path(config_dir), "session", "server_url", urls.server_urls),
        _LocalFile(
            pin_path(config_dir), "enclave pin", "enclave_url", urls.enclave_urls
        ),
    )
    try:
        owned = [(local, _check_owned(local)) for local in files]
    except _KeepConfigDir as reason:
        lines = [f"Left {config_dir} untouched: {reason}."]
    else:
        lines = _remove_owned(owned)
    if owner_key_path(config_dir).exists():
        lines.append(
            f"Kept the owner key {owner_key_path(config_dir)}: it is your signing "
            "identity and may be registered with other deployments."
        )
    return lines


def _remove_owned(owned: list[tuple[_LocalFile, FileIdentity | None]]) -> list[str]:
    lines: list[str] = []
    for local, identity in owned:
        if identity is None:
            continue
        try:
            remove_private(local.path, identity=identity)
        except (StorageError, OSError) as exc:
            lines.append(f"Kept the {local.label} {local.path}: {exc}")
            continue
        lines.append(f"Removed the destroyed deployment's {local.label} {local.path}.")
    return lines
