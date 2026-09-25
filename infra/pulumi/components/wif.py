"""Workload Identity Federation gate for Confidential Space attestation tokens.

The enclave presents its Confidential Space attestation token to STS through
this pool. Only tokens meeting every clause of ``build_attribute_condition``
are exchanged, and KMS decrypt is granted to the resulting ``principalSet`` for
specific image digests. No service account is impersonated.

Claim names follow Google's Confidential Space token claims reference.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import pulumi
import pulumi_gcp as gcp

CONFIDENTIAL_SPACE_ISSUER = "https://confidentialcomputing.googleapis.com"
REQUIRED_HWMODEL = "GCP_AMD_SEV"
REQUIRED_SWNAME = "CONFIDENTIAL_SPACE"
REQUIRED_DBGSTAT = "disabled-since-boot"
REQUIRED_SUPPORT_ATTRIBUTE = "STABLE"

# google.subject is limited to 127 bytes; the raw ``sub`` claim (a full GCE
# instance URL) can exceed that, so use Google's documented compact form.
ATTRIBUTE_MAPPING: dict[str, str] = {
    "google.subject": (
        '"gcpcs::" + assertion.submods.container.image_digest'
        ' + "::" + assertion.submods.gce.project_number'
        ' + "::" + assertion.submods.gce.instance_id'
    ),
    "attribute.image_digest": "assertion.submods.container.image_digest",
}


@dataclass(frozen=True)
class WorkloadIdentity:
    pool: gcp.iam.WorkloadIdentityPool
    provider: gcp.iam.WorkloadIdentityPoolProvider
    provider_name: pulumi.Output[str]
    principal_sets: pulumi.Output[list[str]]


def _cel_string(value: str) -> str:
    if "'" in value or "\\" in value:
        raise ValueError(f"refusing to embed unsafe value in CEL: {value!r}")
    return f"'{value}'"


def build_attribute_condition(
    *, project_id: str, enclave_sa_email: str, allowed_digests: Sequence[str]
) -> str:
    """Return the CEL condition every attestation token must satisfy."""
    if not allowed_digests:
        raise ValueError("allowed_digests must not be empty")
    digests = ", ".join(_cel_string(digest) for digest in allowed_digests)
    clauses = [
        f"assertion.swname == {_cel_string(REQUIRED_SWNAME)}",
        f"assertion.hwmodel == {_cel_string(REQUIRED_HWMODEL)}",
        f"assertion.dbgstat == {_cel_string(REQUIRED_DBGSTAT)}",
        "assertion.secboot == true",
        f"{_cel_string(REQUIRED_SUPPORT_ATTRIBUTE)}"
        " in assertion.submods.confidential_space.support_attributes",
        f"assertion.submods.container.image_digest in [{digests}]",
        f"assertion.submods.gce.project_id == {_cel_string(project_id)}",
        f"{_cel_string(enclave_sa_email)} in assertion.google_service_accounts",
    ]
    return " && ".join(clauses)


def build_principal_set(*, project_number: str, pool_id: str, digest: str) -> str:
    return (
        f"principalSet://iam.googleapis.com/projects/{project_number}"
        f"/locations/global/workloadIdentityPools/{pool_id}"
        f"/attribute.image_digest/{digest}"
    )


def create_workload_identity(
    *,
    prefix: str,
    project_id: str,
    project_number: pulumi.Input[str],
    enclave_sa_email: pulumi.Input[str],
    allowed_digests: Sequence[str],
    audience: str,
    depends_on: Sequence[pulumi.Resource] = (),
) -> WorkloadIdentity:
    """Create the attestation pool and OIDC provider, in code."""
    pool_id = f"{prefix}-attest"
    pool = gcp.iam.WorkloadIdentityPool(
        f"{prefix}-attestation-pool",
        workload_identity_pool_id=pool_id,
        display_name="Carapace enclave attestation",
        description="Confidential Space tokens from the Carapace enclave",
        opts=pulumi.ResourceOptions(depends_on=list(depends_on)),
    )
    condition = pulumi.Output.from_input(enclave_sa_email).apply(
        lambda email: build_attribute_condition(
            project_id=project_id,
            enclave_sa_email=email,
            allowed_digests=allowed_digests,
        )
    )
    provider = gcp.iam.WorkloadIdentityPoolProvider(
        f"{prefix}-attestation-provider",
        workload_identity_pool_id=pool.workload_identity_pool_id,
        workload_identity_pool_provider_id="confidential-space",
        display_name="Confidential Space",
        attribute_mapping=ATTRIBUTE_MAPPING,
        attribute_condition=condition,
        oidc={
            "issuer_uri": CONFIDENTIAL_SPACE_ISSUER,
            "allowed_audiences": [audience],
        },
    )
    # Derived from the pool's output so the key binding waits for the pool.
    principal_sets = pulumi.Output.all(
        project_number, pool.workload_identity_pool_id
    ).apply(
        lambda args: [
            build_principal_set(project_number=args[0], pool_id=args[1], digest=d)
            for d in allowed_digests
        ]
    )
    return WorkloadIdentity(
        pool=pool,
        provider=provider,
        provider_name=provider.name,
        principal_sets=principal_sets,
    )
