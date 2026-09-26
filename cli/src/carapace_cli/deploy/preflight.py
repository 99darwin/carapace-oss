"""Read-only checks and questions before ``carapace deploy`` changes anything.

Nothing here creates or modifies a resource. A check that cannot run (for
example because an API is not enabled in a fresh project yet) becomes a
warning in the summary instead of a failure. A check that runs and fails
stops the deploy.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from carapace_cli.attestation import PROJECT_ID_PATTERN
from carapace_cli.deploy.gcp import GcpApi, GcpError
from carapace_cli.deploy.interview import Interview, InvalidInputError
from carapace_cli.errors import CarapaceError

# Regions with both N2D Confidential VMs (AMD SEV) and Cloud KMS HSM, from
# Google's published availability, each with one zone that offers N2D.
# ``gcp:zone`` defaults to ``<region>-a``, which does not exist everywhere,
# so the zone is always set explicitly.
REGION_ZONES: dict[str, str] = {
    "us-central1": "us-central1-a",
    "us-east1": "us-east1-b",
    "us-east4": "us-east4-a",
    "us-west1": "us-west1-a",
    "us-west4": "us-west4-a",
    "northamerica-northeast1": "northamerica-northeast1-a",
    "southamerica-east1": "southamerica-east1-a",
    "europe-west1": "europe-west1-b",
    "europe-west2": "europe-west2-a",
    "europe-west3": "europe-west3-a",
    "europe-west4": "europe-west4-a",
    "asia-east1": "asia-east1-a",
    "asia-northeast1": "asia-northeast1-a",
    "asia-south1": "asia-south1-a",
    "asia-southeast1": "asia-southeast1-a",
    "australia-southeast1": "australia-southeast1-a",
}
DEFAULT_REGION = "us-central1"
DEFAULT_PREFIX = "carapace"
ENCLAVE_MACHINE_TYPE = "n2d-standard-2"
MAX_LISTED_PROJECTS = 30

# What the stack creates, one representative permission per kind of
# resource. A project Owner has all of them.
REQUIRED_PERMISSIONS: list[str] = [
    "resourcemanager.projects.setIamPolicy",
    "serviceusage.services.enable",
    "storage.buckets.create",
    "cloudkms.keyRings.create",
    "cloudkms.cryptoKeys.create",
    "cloudkms.cryptoKeyVersions.viewPublicKey",
    "iam.serviceAccounts.create",
    "iam.serviceAccounts.actAs",
    "iam.workloadIdentityPools.create",
    "compute.instances.create",
    "compute.addresses.create",
    "compute.firewalls.create",
    "run.services.create",
    "run.jobs.run",
    "cloudsql.instances.create",
    "secretmanager.secrets.create",
    "artifactregistry.repositories.create",
    "monitoring.alertPolicies.create",
]

# Same rule as infra/pulumi/components/config.py (a test keeps them equal).
PREFIX_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,18}[a-z0-9]$")
# GCP zones: the region plus one letter. The zone goes into a Compute API
# path and the stack config, so its characters are checked, not only the
# region it names.
ZONE_PATTERN = re.compile(r"^[a-z]+-[a-z]+[0-9]+-[a-z]$")
# Deliberately plain: one address, no display name, no quoting.
EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


class PreflightError(CarapaceError):
    """A check ran and failed; the deploy must not continue."""


def validate_project_id(value: str) -> str:
    if not PROJECT_ID_PATTERN.fullmatch(value):
        raise InvalidInputError(f"{value!r} is not a GCP project id")
    return value


def validate_region(value: str) -> str:
    if value not in REGION_ZONES:
        raise InvalidInputError(
            f"{value!r} is not a region with both N2D Confidential VMs and "
            f"Cloud KMS HSM; pick one of: {', '.join(sorted(REGION_ZONES))}"
        )
    return value


def validate_zone(region: str, zone: str) -> str:
    """A well-formed zone of ``region``."""
    if not ZONE_PATTERN.fullmatch(zone) or not zone.startswith(f"{region}-"):
        raise InvalidInputError(f"zone {zone!r} is not in region {region!r}")
    return zone


def validate_prefix(value: str) -> str:
    if not PREFIX_PATTERN.fullmatch(value) or value.startswith("gcp-"):
        raise InvalidInputError(
            f"prefix {value!r} must be 3-20 chars of lowercase letters, digits "
            "or '-', start with a letter, and not start with 'gcp-'"
        )
    return value


def validate_email(value: str) -> str:
    if not EMAIL_PATTERN.fullmatch(value):
        raise InvalidInputError(f"{value!r} is not an email address")
    return value


def validate_emails(value: str) -> str:
    """A comma-separated list of at least one address."""
    emails = [part.strip() for part in value.split(",") if part.strip()]
    if not emails:
        raise InvalidInputError("at least one alert email is required")
    return ",".join(validate_email(email) for email in emails)


@dataclass(frozen=True)
class Target:
    """Where and what to deploy, as the interview settled it."""

    project: str
    project_number: str
    region: str
    zone: str
    prefix: str
    alert_emails: tuple[str, ...]


@dataclass(frozen=True)
class ExistingDeployment:
    """Where an earlier deploy put the stack with this prefix."""

    region: str
    zone: str
    alert_emails: tuple[str, ...]


# (project, prefix) -> the earlier deployment, or None for a new one.
ExistingLookup = Callable[[str, str], ExistingDeployment | None]


@dataclass
class PreflightReport:
    warnings: list[str] = field(default_factory=list)
    existing: ExistingDeployment | None = None

    def warn(self, message: str) -> None:
        self.warnings.append(message)


@dataclass(frozen=True)
class Flags:
    """The values given on the command line; ``None`` means ask."""

    project: str | None = None
    region: str | None = None
    zone: str | None = None
    prefix: str | None = None
    alert_emails: tuple[str, ...] = ()


def _project_options(api: GcpApi, report: PreflightReport) -> list[tuple[str, str]]:
    try:
        projects = api.list_projects()
    except GcpError as exc:
        report.warn(f"could not list your projects ({exc}); type the id instead")
        return []
    projects.sort(key=lambda p: str(p.get("projectId")))
    return [
        (str(p.get("projectId")), str(p.get("name") or ""))
        for p in projects[:MAX_LISTED_PROJECTS]
        if p.get("projectId")
    ]


def choose_project(
    api: GcpApi, interview: Interview, flags: Flags, report: PreflightReport
) -> tuple[str, str]:
    """The project id and number, after checking it exists and is visible."""
    project = interview.choose(
        "GCP project to deploy into (use a new, dedicated project)",
        flag="--project",
        value=flags.project,
        options=(
            _project_options(api, report)
            if interview.interactive and flags.project is None
            else []
        ),
        validate=validate_project_id,
    )
    info = api.get_project(project)
    if info is None:
        raise PreflightError(f"project {project!r} does not exist or you cannot see it")
    if info.get("lifecycleState", "ACTIVE") != "ACTIVE":
        raise PreflightError(f"project {project!r} is not active")
    return project, str(info.get("projectNumber") or "")


def check_billing(api: GcpApi, project: str, report: PreflightReport) -> None:
    try:
        enabled = api.billing_enabled(project)
    except GcpError as exc:
        report.warn(f"could not confirm that billing is enabled ({exc})")
        return
    if not enabled:
        raise PreflightError(
            f"billing is not enabled on {project!r}; link a billing account first"
        )


def check_permissions(api: GcpApi, project: str, report: PreflightReport) -> None:
    try:
        missing = api.missing_permissions(project, REQUIRED_PERMISSIONS)
    except GcpError as exc:
        report.warn(f"could not check your permissions ({exc})")
        return
    if missing:
        raise PreflightError(
            f"you lack permissions on {project!r} that the deploy needs "
            f"(Owner has them all): {', '.join(missing)}"
        )


def _region_options(
    api: GcpApi, project: str, report: PreflightReport
) -> list[tuple[str, str]]:
    regions = sorted(REGION_ZONES)
    try:
        hsm = api.hsm_locations(project)
    except GcpError as exc:
        report.warn(f"could not list KMS HSM locations ({exc}); using known list")
        hsm = set(regions)
    return [(region, "") for region in regions if region in hsm]


def choose_location(
    api: GcpApi,
    interview: Interview,
    flags: Flags,
    project: str,
    report: PreflightReport,
) -> tuple[str, str]:
    """The region and zone, with N2D confirmed in the zone when possible.

    An existing deployment's region and zone are the defaults, and cannot
    be changed: the stack would replace every resource, and the state key
    lives in the region.
    """
    existing = report.existing
    options = (
        _region_options(api, project, report)
        if interview.interactive and flags.region is None and existing is None
        else []
    )
    region = interview.choose(
        "Region (N2D Confidential VM and Cloud KMS HSM)",
        flag="--region",
        value=flags.region,
        options=options,
        default=existing.region if existing else DEFAULT_REGION,
        validate=validate_region,
    )
    if existing:
        zone = flags.zone or existing.zone
        if (region, zone) != (existing.region, existing.zone):
            raise PreflightError(
                f"this deployment is in {existing.region} ({existing.zone}) and "
                "cannot move; pass another --prefix for a new deployment"
            )
        return region, zone
    zone = validate_zone(region, flags.zone or REGION_ZONES[region])
    try:
        available = api.machine_type_available(project, zone, ENCLAVE_MACHINE_TYPE)
    except GcpError as exc:
        report.warn(f"could not confirm {ENCLAVE_MACHINE_TYPE} in {zone} ({exc})")
        return region, zone
    if not available:
        raise PreflightError(f"{ENCLAVE_MACHINE_TYPE} is not offered in {zone}")
    return region, zone


def run_preflight(
    api: GcpApi,
    interview: Interview,
    flags: Flags,
    *,
    find_existing: ExistingLookup | None = None,
) -> tuple[Target, PreflightReport]:
    """Ask every question and run every check. Changes nothing.

    ``find_existing`` looks up an earlier deploy of the same prefix; its
    settings become the defaults and the report's ``existing``.
    """
    report = PreflightReport()
    project, number = choose_project(api, interview, flags, report)
    check_billing(api, project, report)
    check_permissions(api, project, report)
    prefix = interview.ask(
        "Resource name prefix",
        flag="--prefix",
        value=flags.prefix,
        default=DEFAULT_PREFIX,
        validate=validate_prefix,
    )
    if find_existing is not None:
        try:
            report.existing = find_existing(project, prefix)
        except GcpError as exc:
            # A fresh project may not have Cloud Storage enabled yet.
            report.warn(f"could not look for an earlier deployment ({exc})")
    region, zone = choose_location(api, interview, flags, project, report)
    existing_emails = report.existing.alert_emails if report.existing else ()
    emails = interview.ask(
        "Email for security alerts (comma-separated for several)",
        flag="--alert-email",
        value=",".join(flags.alert_emails) if flags.alert_emails else None,
        default=",".join(existing_emails) or None,
        validate=validate_emails,
    )
    target = Target(
        project=project,
        project_number=number,
        region=region,
        zone=zone,
        prefix=prefix,
        alert_emails=tuple(emails.split(",")),
    )
    return target, report
