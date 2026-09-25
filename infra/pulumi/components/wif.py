"""Workload Identity Federation gate for Confidential Space attestation tokens.

The enclave requests a Confidential Space token whose audience is this
stack's STS audience (by default the provider's full resource name) and
presents it to STS through this pool. That audience is the only one the
provider accepts. Tokens with the launcher's default audience or the
client-facing ``carapace-attestation`` audience are published by the enclave
and must never be exchangeable, and neither may the enclave-to-server token
(audience: the control plane URL), which the untrusted server receives as a
bearer token. Only tokens meeting every clause of
``build_attribute_condition`` are exchanged, and KMS decrypt is granted to the
resulting ``principalSet`` for specific image digests. No service account is
impersonated.

Claim names follow Google's Confidential Space token claims reference.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import pulumi
import pulumi_gcp as gcp

from components.config import FORBIDDEN_WIF_AUDIENCES, reject_server_audience

CONFIDENTIAL_SPACE_ISSUER = "https://confidentialcomputing.googleapis.com"
REQUIRED_HWMODEL = "GCP_AMD_SEV"
REQUIRED_SWNAME = "CONFIDENTIAL_SPACE"
REQUIRED_DBGSTAT = "disabled-since-boot"
REQUIRED_SUPPORT_ATTRIBUTE = "STABLE"
PROVIDER_ID = "confidential-space"
# Launch-time env override the condition pins (see enclave_vm.py).
CONTROL_PLANE_URL_ENV = "CONTROL_PLANE_URL"

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
    sts_audience: pulumi.Output[str]


def _cel_string(value: str) -> str:
    if "'" in value or "\\" in value:
        raise ValueError(f"refusing to embed unsafe value in CEL: {value!r}")
    return f"'{value}'"


def build_attribute_condition(
    *,
    project_id: str,
    enclave_sa_email: str,
    allowed_digests: Sequence[str],
    audience: str,
    control_plane_url: str,
) -> str:
    """Return the CEL condition every attestation token must satisfy."""
    if not control_plane_url:
        raise ValueError("control_plane_url must not be empty")
    if not allowed_digests:
        raise ValueError("allowed_digests must not be empty")
    if audience in FORBIDDEN_WIF_AUDIENCES:
        raise ValueError(f"audience {audience!r} must never be accepted by WIF")
    # Runs on the resolved URL, so the derived Cloud Run URL is covered too.
    reject_server_audience(audience, control_plane_url)
    digests = ", ".join(_cel_string(digest) for digest in allowed_digests)
    clauses = [
        # ``aud`` is a single string in Confidential Space tokens.
        f"assertion.aud == {_cel_string(audience)}",
        f"assertion.swname == {_cel_string(REQUIRED_SWNAME)}",
        f"assertion.hwmodel == {_cel_string(REQUIRED_HWMODEL)}",
        f"assertion.dbgstat == {_cel_string(REQUIRED_DBGSTAT)}",
        "assertion.secboot == true",
        f"{_cel_string(REQUIRED_SUPPORT_ATTRIBUTE)}"
        " in assertion.submods.confidential_space.support_attributes",
        f"assertion.submods.container.image_digest in [{digests}]",
        f"assertion.submods.gce.project_id == {_cel_string(project_id)}",
        f"{_cel_string(enclave_sa_email)} in assertion.google_service_accounts",
        # The allowed image can be booted by anyone who can create VMs in this
        # project. Pinning the control plane stops a project Editor from
        # pointing a decrypting enclave at a server of their own.
        f"assertion.submods.container.env.{CONTROL_PLANE_URL_ENV}"
        f" == {_cel_string(control_plane_url)}",
    ]
    return " && ".join(clauses)


def build_principal_set(*, project_number: str, pool_id: str, digest: str) -> str:
    return (
        f"principalSet://iam.googleapis.com/projects/{project_number}"
        f"/locations/global/workloadIdentityPools/{pool_id}"
        f"/attribute.image_digest/{digest}"
    )


def build_provider_audience(*, project_number: str, pool_id: str) -> str:
    """Default STS audience: the provider's full resource name."""
    return (
        f"//iam.googleapis.com/projects/{project_number}/locations/global"
        f"/workloadIdentityPools/{pool_id}/providers/{PROVIDER_ID}"
    )


def create_workload_identity(
    *,
    prefix: str,
    project_id: str,
    project_number: pulumi.Input[str],
    enclave_sa_email: pulumi.Input[str],
    allowed_digests: Sequence[str],
    audience: str | None,
    control_plane_url: pulumi.Input[str],
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
    sts_audience = (
        pulumi.Output.from_input(audience)
        if audience
        else pulumi.Output.from_input(project_number).apply(
            lambda number: build_provider_audience(
                project_number=number, pool_id=pool_id
            )
        )
    )
    condition = pulumi.Output.all(
        enclave_sa_email, sts_audience, control_plane_url
    ).apply(
        lambda args: build_attribute_condition(
            project_id=project_id,
            enclave_sa_email=args[0],
            allowed_digests=allowed_digests,
            audience=args[1],
            control_plane_url=args[2],
        )
    )
    provider = gcp.iam.WorkloadIdentityPoolProvider(
        f"{prefix}-attestation-provider",
        workload_identity_pool_id=pool.workload_identity_pool_id,
        workload_identity_pool_provider_id=PROVIDER_ID,
        display_name="Confidential Space",
        attribute_mapping=ATTRIBUTE_MAPPING,
        attribute_condition=condition,
        oidc={
            "issuer_uri": CONFIDENTIAL_SPACE_ISSUER,
            "allowed_audiences": sts_audience.apply(lambda aud: [aud]),
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
        sts_audience=sts_audience,
    )
