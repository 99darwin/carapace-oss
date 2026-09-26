"""The Pulumi state backend: a GCS bucket and a ``gcpkms://`` secrets key.

Both are created here, through REST and before Pulumi runs, because Pulumi
cannot create the place it keeps its own state. Every step is idempotent.
Neither is a Pulumi resource, so ``carapace destroy`` leaves them in place.
See docs/design/deploy.md for why this is not Pulumi Cloud, a passphrase or
the HSM key.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from carapace_cli.deploy.gcp import (
    HTTP_CONFLICT,
    HTTP_FORBIDDEN,
    KMS,
    SERVICE_USAGE,
    STORAGE,
    GcpApi,
    GcpError,
)
from carapace_cli.deploy.polling import Clock, poll_until
from carapace_cli.deploy.preflight import Target
from carapace_cli.deploy.summary import state_bucket_name
from carapace_cli.errors import CarapaceError

STATE_KEY_RING = "carapace-state"
STATE_KEY = "pulumi-state"
# The state APIs must work before Pulumi enables the rest.
STATE_SERVICES = ("storage.googleapis.com", "cloudkms.googleapis.com")
ENABLE_TIMEOUT_SECONDS = 300.0
ENABLE_POLL_SECONDS = 5.0

BUCKET_SETTINGS: dict[str, Any] = {
    "iamConfiguration": {
        "uniformBucketLevelAccess": {"enabled": True},
        "publicAccessPrevention": "enforced",
    },
    # An earlier state can be recovered after a bad write.
    "versioning": {"enabled": True},
}
STATE_KEY_SETTINGS: dict[str, Any] = {
    "purpose": "ENCRYPT_DECRYPT",
    "versionTemplate": {
        "protectionLevel": "SOFTWARE",
        "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
    },
}


class StateBackendError(CarapaceError):
    """The state bucket or key exists but cannot safely be used."""


@dataclass(frozen=True)
class StateBackend:
    bucket: str
    key_name: str

    @property
    def url(self) -> str:
        return f"gs://{self.bucket}"

    @property
    def secrets_provider(self) -> str:
        return f"gcpkms://{self.key_name}"


def state_backend_for(target: Target) -> StateBackend:
    key_ring = f"projects/{target.project}/locations/{target.region}/keyRings"
    return StateBackend(
        bucket=state_bucket_name(target.project),
        key_name=f"{key_ring}/{STATE_KEY_RING}/cryptoKeys/{STATE_KEY}",
    )


def ensure_services(api: GcpApi, project: str, *, clock: Clock) -> None:
    services = f"{SERVICE_USAGE}/projects/{project}/services"
    missing = [
        name
        for name in STATE_SERVICES
        if api.get(f"{services}/{name}").get("state") != "ENABLED"
    ]
    if not missing:
        return
    operation = api.request(
        "POST", f"{services}:batchEnable", json={"serviceIds": missing}
    )

    def finished() -> dict[str, Any] | None:
        current = operation
        if not current.get("done"):
            current = api.get(f"{SERVICE_USAGE}/{operation['name']}")
        if not current.get("done"):
            return None
        if current.get("error"):
            message = (current["error"] or {}).get("message", "unknown error")
            raise CarapaceError(f"enabling {', '.join(missing)} failed: {message}")
        return current

    poll_until(
        finished,
        what=f"{', '.join(missing)} to be enabled",
        timeout_seconds=ENABLE_TIMEOUT_SECONDS,
        interval_seconds=ENABLE_POLL_SECONDS,
        clock=clock,
    )


def ensure_bucket(api: GcpApi, target: Target, bucket: str) -> None:
    try:
        existing = api.get_or_none(f"{STORAGE}/b/{bucket}")
    except GcpError as exc:
        if exc.status != HTTP_FORBIDDEN:
            raise
        raise StateBackendError(
            f"bucket {bucket!r} exists but you cannot read it; it probably "
            "belongs to another project"
        ) from None
    if existing is None:
        try:
            api.request(
                "POST",
                f"{STORAGE}/b",
                params={"project": target.project},
                json={"name": bucket, "location": target.region, **BUCKET_SETTINGS},
            )
        except GcpError as exc:
            if exc.status != HTTP_CONFLICT:
                raise
            raise StateBackendError(
                f"bucket name {bucket!r} is taken by another project"
            ) from None
        return
    # Never keep state in someone else's bucket.
    number = str(existing.get("projectNumber") or "")
    if target.project_number and number != target.project_number:
        raise StateBackendError(
            f"bucket {bucket!r} belongs to project number {number or '?'}, "
            f"not {target.project}"
        )
    if not _has_settings(existing):
        api.request("PATCH", f"{STORAGE}/b/{bucket}", json=BUCKET_SETTINGS)


def _has_settings(bucket: dict[str, Any]) -> bool:
    iam = bucket.get("iamConfiguration") or {}
    return (
        (iam.get("uniformBucketLevelAccess") or {}).get("enabled") is True
        and iam.get("publicAccessPrevention") == "enforced"
        and (bucket.get("versioning") or {}).get("enabled") is True
    )


def _create_if_missing(
    api: GcpApi, url: str, create: Callable[[], object]
) -> dict[str, Any]:
    existing = api.get_or_none(url)
    if existing is not None:
        return existing
    try:
        create()
    except GcpError as exc:
        # Lost a race with a concurrent run; the resource is there now.
        if exc.status != HTTP_CONFLICT:
            raise
    return api.get(url)


def ensure_state_key(api: GcpApi, target: Target, key_name: str) -> None:
    location = f"{KMS}/projects/{target.project}/locations/{target.region}"
    ring_url = f"{location}/keyRings/{STATE_KEY_RING}"
    _create_if_missing(
        api,
        ring_url,
        lambda: api.request(
            "POST", f"{location}/keyRings", params={"keyRingId": STATE_KEY_RING}
        ),
    )
    key = _create_if_missing(
        api,
        f"{KMS}/{key_name}",
        lambda: api.request(
            "POST",
            f"{ring_url}/cryptoKeys",
            params={"cryptoKeyId": STATE_KEY},
            json=STATE_KEY_SETTINGS,
        ),
    )
    if key.get("purpose") != "ENCRYPT_DECRYPT":
        raise StateBackendError(f"{key_name} is not a symmetric ENCRYPT_DECRYPT key")


def ensure_state_backend(
    api: GcpApi, target: Target, *, say: Callable[[str], None], clock: Clock
) -> StateBackend:
    backend = state_backend_for(target)
    say(f"State: {backend.url}, secrets encrypted with {backend.key_name}")
    ensure_services(api, target.project, clock=clock)
    ensure_bucket(api, target, backend.bucket)
    ensure_state_key(api, target, backend.key_name)
    return backend
