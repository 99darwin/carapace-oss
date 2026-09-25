"""Enable the Google Cloud APIs the deployment depends on."""

from __future__ import annotations

import pulumi_gcp as gcp

REQUIRED_SERVICES: tuple[str, ...] = (
    "compute.googleapis.com",
    "cloudkms.googleapis.com",
    "confidentialcomputing.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "run.googleapis.com",
    "sqladmin.googleapis.com",
    "artifactregistry.googleapis.com",
    "logging.googleapis.com",
    "secretmanager.googleapis.com",
    "monitoring.googleapis.com",
)


def enable_apis(prefix: str) -> list[gcp.projects.Service]:
    """Enable every required API. Disabling on destroy is left to the owner."""
    return [
        gcp.projects.Service(
            f"{prefix}-api-{service.split('.')[0]}",
            service=service,
            disable_on_destroy=False,
            disable_dependent_services=False,
        )
        for service in REQUIRED_SERVICES
    ]
