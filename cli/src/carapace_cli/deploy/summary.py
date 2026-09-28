"""The summary shown before ``carapace deploy`` changes anything."""

from __future__ import annotations

from carapace_cli.deploy.infra import default_enclave_machine_type
from carapace_cli.deploy.preflight import PreflightReport, Target

MONTHLY_COST_USD = 80
STOPPED_VM_MONTHLY_COST_USD = 40

RESIDUAL_RISK = (
    "Residual risk (THREAT_MODEL.md R1): anyone with Owner on this project,\n"
    "or on its folder or organization, can grant themselves a KMS role and\n"
    "decrypt every secret without the enclave. An alert emails you when that\n"
    "happens, but it does not prevent it. Deploy into a new, dedicated project\n"
    "and keep its Owners, and any Cloud KMS roles, to yourself."
)


def state_bucket_name(project: str) -> str:
    """Project ids are globally unique, so this bucket name usually is too."""
    return f"{project}-carapace-state"


def render_summary(
    target: Target,
    report: PreflightReport,
    *,
    images: str,
    existing: str | None = None,
) -> str:
    lines = [
        "Carapace will be deployed to:",
        f"  project  {target.project} (number {target.project_number or '?'})",
        f"  region   {target.region}, zone {target.zone}",
        f"  prefix   {target.prefix}",
        f"  alerts   {', '.join(target.alert_emails)}",
        f"  images   {images}",
    ]
    if existing:
        lines += ["", f"Existing deployment: {existing}"]
    lines += [
        "",
        "It creates (details in docs/SELF_HOST.md):",
        f"  - Pulumi state in gs://{state_bucket_name(target.project)}, encrypted",
        "    with a Cloud KMS key in key ring carapace-state",
        f"  - an HSM key {target.prefix}-keyring/{target.prefix}-secrets. KMS keys",
        "    cannot be deleted; destroy only schedules the version's destruction",
        "  - a workload identity pool, two service accounts, an Artifact Registry",
        "    repository, KMS Data Access logs and an IAM change alert",
        f"  - a Confidential VM ({default_enclave_machine_type()}) with a static "
        "external IP,",
        "    open on tcp:8443 only",
        "  - a Cloud Run service and migration job, Cloud SQL Postgres (public IP,",
        "    TLS only, no authorized networks) and two Secret Manager secrets",
        "",
        f"Estimated cost: about ${MONTHLY_COST_USD}/month at list prices "
        f"(about ${STOPPED_VM_MONTHLY_COST_USD} with the VM stopped).",
        "",
        RESIDUAL_RISK,
    ]
    if report.warnings:
        lines += ["", "Warnings (checks that could not run):"]
        lines += [f"  - {warning}" for warning in report.warnings]
    return "\n".join(lines)
