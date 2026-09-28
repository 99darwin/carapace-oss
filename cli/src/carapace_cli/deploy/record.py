"""The deployment record: where a prefix was deployed, kept in the state bucket.

Pulumi keeps stack config in ``infra/pulumi/Pulumi.<prefix>.yaml`` on the
machine that ran it, and its state cannot be read before the stack is
opened. A re-run and ``carapace destroy`` need the region, zone and alert
emails first, read-only, so the deploy writes them to
``gs://<project>-carapace-state/carapace/deployments/<prefix>.json``. The
record holds no secret.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import quote

from carapace_cli.deploy.gcp import HTTP_NOT_FOUND, STORAGE, GcpApi, GcpError
from carapace_cli.deploy.interview import InvalidInputError
from carapace_cli.deploy.preflight import (
    REGION_ZONES,
    ExistingDeployment,
    Target,
    validate_emails,
    validate_zone,
)
from carapace_cli.deploy.summary import state_bucket_name
from carapace_cli.errors import CarapaceError

STORAGE_UPLOAD = "https://storage.googleapis.com/upload/storage/v1"
RECORD_VERSION = 1


class RecordError(CarapaceError):
    """A deployment record is unreadable or disagrees with the stack."""


def record_name(prefix: str) -> str:
    return f"carapace/deployments/{prefix}.json"


def _object_url(project: str, prefix: str) -> str:
    bucket = state_bucket_name(project)
    return f"{STORAGE}/b/{bucket}/o/{quote(record_name(prefix), safe='')}"


def parse_record(
    body: dict[str, Any], *, project: str, prefix: str
) -> ExistingDeployment:
    where = f"the deployment record for {prefix!r}"
    if body.get("version") != RECORD_VERSION:
        raise RecordError(f"{where} has an unknown version")
    if (body.get("project"), body.get("prefix")) != (project, prefix):
        raise RecordError(f"{where} names another project or prefix")
    region, zone = str(body.get("region", "")), str(body.get("zone", ""))
    emails = body.get("alert_emails")
    if not isinstance(emails, list) or not emails:
        raise RecordError(f"{where} has no alert emails")
    try:
        if region not in REGION_ZONES:
            raise InvalidInputError(f"{region!r} is not a supported region")
        validate_zone(region, zone)
        checked = validate_emails(",".join(str(email) for email in emails))
    except InvalidInputError as exc:
        raise RecordError(f"{where} is invalid: {exc}") from None
    return ExistingDeployment(region, zone, tuple(checked.split(",")))


def read_record(api: GcpApi, project: str, prefix: str) -> ExistingDeployment | None:
    """The record, or None if the bucket or the record does not exist."""
    try:
        body = api.get(_object_url(project, prefix), alt="media")
    except GcpError as exc:
        if exc.status == HTTP_NOT_FOUND:
            return None
        raise
    return parse_record(body, project=project, prefix=prefix)


def write_record(api: GcpApi, target: Target) -> None:
    body = {
        "version": RECORD_VERSION,
        "project": target.project,
        "prefix": target.prefix,
        "region": target.region,
        "zone": target.zone,
        "alert_emails": list(target.alert_emails),
    }
    api.request(
        "POST",
        f"{STORAGE_UPLOAD}/b/{state_bucket_name(target.project)}/o",
        json=body,
        params={"uploadType": "media", "name": record_name(target.prefix)},
    )


def delete_record(api: GcpApi, project: str, prefix: str) -> None:
    try:
        api.request("DELETE", _object_url(project, prefix))
    except GcpError as exc:
        if exc.status != HTTP_NOT_FOUND:
            raise


def check_stack_config(
    config: dict[str, str],
    target: Target,
    *,
    is_existing: bool,
    zonal_resources: Callable[[], list[str]] | None = None,
) -> None:
    """Refuse a stack whose local config is missing or elsewhere.

    ``Pulumi.<prefix>.yaml`` lives on the machine that deployed. Without
    it, an ``up`` would bootstrap a live stack and delete its workloads.
    A stack deployed elsewhere (say, by hand) cannot move either.

    The file is named after the prefix alone, so one machine holds one
    deployment per prefix: a config that names another project belongs to
    that project's stack, and an ``up`` with it would act on the wrong
    project.

    The region never changes. The zone may change while the state holds
    no live zonal resource (the enclave VM, see zones.py): nothing that
    exists is in a zone. A VM pending replacement (deleted, its
    replacement not created) is not live. ``zonal_resources`` lists the
    URNs of the live ones; without it a zone change is refused.
    """
    if is_existing and config.get("carapace:prefix") != target.prefix:
        raise RecordError(
            f"infra/pulumi/Pulumi.{target.prefix}.yaml, the stack's config, is "
            "not on this machine; run the command where the deployment was "
            "made, or copy that file here first"
        )
    current_project = config.get("gcp:project")
    if current_project and current_project != target.project:
        raise RecordError(
            f"infra/pulumi/Pulumi.{target.prefix}.yaml on this machine belongs "
            f"to the deployment in {current_project}, not {target.project}; a "
            "prefix's config file is shared across projects, so use another "
            "--prefix for a second project"
        )
    current_region = config.get("gcp:region")
    if current_region and current_region != target.region:
        raise RecordError(
            f"stack {target.prefix!r} has gcp:region {current_region}, not "
            f"{target.region}; a deployment cannot move to another region. "
            "Pass the same --region, or another --prefix"
        )
    current_zone = config.get("gcp:zone")
    if not current_zone or current_zone == target.zone:
        return
    zonal = zonal_resources() if zonal_resources is not None else None
    if zonal is None:
        reason = "its resources could not be checked"
    elif zonal:
        names = ", ".join(urn.rpartition("::")[2] for urn in zonal)
        reason = f"it has zonal resources there ({names}) that cannot move"
    else:
        return
    raise RecordError(
        f"stack {target.prefix!r} has gcp:zone {current_zone}, not "
        f"{target.zone}, and {reason}. Pass --zone {current_zone}, or another "
        "--prefix"
    )


def describe_existing(existing: ExistingDeployment, target: Target) -> str:
    return (
        f"stack {target.prefix!r} in gs://{state_bucket_name(target.project)} "
        f"({existing.region}). This run updates or resumes it; live workloads "
        "are not bootstrapped again."
    )
