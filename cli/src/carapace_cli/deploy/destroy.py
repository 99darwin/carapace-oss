"""``carapace destroy``: tear a deployment down, after an explicit warning.

The stack's deletion protection (``protect_kms_key``,
``db_deletion_protection``) is turned off with one ``up`` and then
``pulumi destroy`` runs. The state bucket and state key are not Pulumi
resources and are kept, so the same project can be deployed again.
"""

from __future__ import annotations

from collections.abc import Callable

from carapace_cli.deploy.pulumi_runner import StackHandle
from carapace_cli.deploy.summary import state_bucket_name
from carapace_cli.errors import CarapaceError


class DestroyError(CarapaceError):
    """There is no deployment to destroy."""


UNPROTECTED = {
    "carapace:protect_kms_key": "false",
    "carapace:db_deletion_protection": "false",
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
