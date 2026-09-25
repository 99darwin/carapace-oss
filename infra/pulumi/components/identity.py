"""Service accounts for the enclave VM and the server, with minimal roles.

Neither account gets any KMS decrypt permission. The enclave decrypts only
through the WIF principalSet (see ``wif.py``); the server can read the public
key (granted in the key policy, ``kms.py``) and nothing more.

No ``roles/iam.serviceAccountUser`` binding is created. The identity running
``pulumi up`` needs ``iam.serviceAccounts.actAs`` on both accounts to attach
them to the VM and the Cloud Run service; a project owner already has it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import pulumi
import pulumi_gcp as gcp

ENCLAVE_PROJECT_ROLES: tuple[str, ...] = (
    "roles/logging.logWriter",
    "roles/artifactregistry.reader",
    "roles/confidentialcomputing.workloadUser",
)
SERVER_PROJECT_ROLES: tuple[str, ...] = ("roles/cloudsql.client",)


@dataclass(frozen=True)
class ServiceIdentities:
    enclave: gcp.serviceaccount.Account
    server: gcp.serviceaccount.Account
    enclave_grants: dict[str, gcp.projects.IAMMember]
    server_grants: dict[str, gcp.projects.IAMMember]

    @property
    def enclave_member(self) -> pulumi.Output[str]:
        return self.enclave.email.apply(lambda email: f"serviceAccount:{email}")

    @property
    def server_member(self) -> pulumi.Output[str]:
        return self.server.email.apply(lambda email: f"serviceAccount:{email}")


def _grant_project_roles(
    *,
    name: str,
    project: str,
    account: gcp.serviceaccount.Account,
    roles: Sequence[str],
) -> dict[str, gcp.projects.IAMMember]:
    return {
        role: gcp.projects.IAMMember(
            f"{name}-{role.split('/')[-1].replace('.', '-')}",
            project=project,
            role=role,
            member=account.email.apply(lambda email: f"serviceAccount:{email}"),
        )
        for role in roles
    }


def create_service_identities(
    *, prefix: str, project: str, depends_on: Sequence[pulumi.Resource] = ()
) -> ServiceIdentities:
    opts = pulumi.ResourceOptions(depends_on=list(depends_on))
    enclave = gcp.serviceaccount.Account(
        f"{prefix}-enclave-sa",
        account_id=f"{prefix}-enclave",
        display_name="Carapace enclave VM (no KMS access)",
        opts=opts,
    )
    server = gcp.serviceaccount.Account(
        f"{prefix}-server-sa",
        account_id=f"{prefix}-server",
        display_name="Carapace server (public key only)",
        opts=opts,
    )
    enclave_grants = _grant_project_roles(
        name=f"{prefix}-enclave",
        project=project,
        account=enclave,
        roles=ENCLAVE_PROJECT_ROLES,
    )
    server_grants = _grant_project_roles(
        name=f"{prefix}-server",
        project=project,
        account=server,
        roles=SERVER_PROJECT_ROLES,
    )
    return ServiceIdentities(
        enclave=enclave,
        server=server,
        enclave_grants=enclave_grants,
        server_grants=server_grants,
    )
