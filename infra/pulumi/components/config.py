"""Typed, validated stack configuration.

All validation happens here, before any resource is declared, so a bad config
fails the deployment immediately instead of half-creating infrastructure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import pulumi

DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
# A bare https origin: lowercase host and optional port, nothing after it.
# Also keeps the value safe to embed in the WIF condition's CEL.
CONTROL_PLANE_URL_PATTERN = re.compile(r"^https://[a-z0-9.-]+(:[0-9]{1,5})?$")
# Short enough that every derived ID stays within GCP limits (service account
# IDs max 30 chars, WIF pool/provider IDs max 32 chars).
PREFIX_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,18}[a-z0-9]$")
# The launcher's default token audience. Never accepted by WIF: the enclave
# publishes tokens, so an accepted default audience would let anyone holding a
# published token exchange it for decrypt access.
LAUNCHER_DEFAULT_AUDIENCE = "https://sts.googleapis.com"
# Audience of the client-facing token served at GET /attestation. Never
# accepted by WIF, for the same reason.
ATTESTATION_AUDIENCE = "carapace-attestation"
FORBIDDEN_WIF_AUDIENCES = frozenset({LAUNCHER_DEFAULT_AUDIENCE, ATTESTATION_AUDIENCE})
# The enclave VM's machine type unless carapace:enclave_machine_type says
# otherwise. N2D: AMD SEV. The CLI reads this line (not an import: the CLI
# does not depend on pulumi) to pick zones that offer it, so keep it a
# plain string literal.
DEFAULT_ENCLAVE_MACHINE_TYPE = "n2d-standard-2"


class ConfigError(ValueError):
    """Raised when stack configuration is invalid or unsafe."""


def validate_digest(digest: str) -> str:
    """Return ``digest`` if it is a full sha256 image digest, else raise."""
    if not DIGEST_PATTERN.fullmatch(digest):
        raise ConfigError(
            f"image digest {digest!r} must look like 'sha256:<64 hex chars>'; "
            "tags are not accepted"
        )
    return digest


def validate_control_plane_url(url: str) -> str:
    """Return ``url`` if it is a bare ``https://host[:port]`` origin, else raise.

    The value is the server's public URL, the audience of enclave-to-server
    tokens and a clause of the WIF condition, so it must match byte for byte
    everywhere. A path or trailing slash would make that fragile.
    """
    if not CONTROL_PLANE_URL_PATTERN.fullmatch(url):
        raise ConfigError(
            f"control_plane_url {url!r} must be a bare lowercase https origin "
            "such as 'https://api.example.com', with no path or trailing slash"
        )
    return url


def reject_server_audience(wif_audience: str | None, control_plane_url: str) -> None:
    """Refuse a WIF audience equal to the enclave-to-server token audience.

    The enclave authenticates to the untrusted server with a bearer token whose
    audience is the server's URL. If WIF accepted that audience, the server
    could exchange the tokens it receives at STS and decrypt every secret.
    """
    if wif_audience is not None and wif_audience == control_plane_url:
        raise ConfigError(
            f"wif_audience {wif_audience!r} equals the control plane URL, the "
            "audience of enclave-to-server tokens; the server must never be able "
            "to exchange those tokens for decrypt access"
        )


def build_image_reference(repository: str, digest: str) -> str:
    """Build ``<repository>@<digest>``, refusing tag-based references.

    The attestation guarantee depends on the VM running exactly the image whose
    digest the KMS key is bound to, so a mutable tag is never acceptable.
    """
    if not repository or "@" in repository:
        raise ConfigError(f"invalid image repository {repository!r}")
    last_segment = repository.rsplit("/", 1)[-1]
    if ":" in last_segment:
        raise ConfigError(
            f"image repository {repository!r} contains a tag; "
            "pass the repository without a tag and pin by digest"
        )
    return f"{repository}@{validate_digest(digest)}"


@dataclass(frozen=True)
class StackConfig:
    """Everything the program needs; nothing is hardcoded to a project."""

    project: str
    prefix: str
    region: str
    zone: str
    allowed_digests: list[str]
    enclave_image_digest: str
    server_image_digest: str
    image_registry: str | None = None
    # None derives the provider resource name, which is stack-specific.
    wif_audience: str | None = None
    control_plane_url: str | None = None
    enclave_machine_type: str = DEFAULT_ENCLAVE_MACHINE_TYPE
    db_tier: str = "db-f1-micro"
    server_min_instances: int = 0
    server_max_instances: int = 2
    protect_kms_key: bool = True
    db_deletion_protection: bool = True
    deploy_workloads: bool = True
    enable_iam_alerts: bool = True
    alert_emails: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.project:
            raise ConfigError("gcp:project must be set")
        if not PREFIX_PATTERN.fullmatch(self.prefix):
            raise ConfigError(
                f"prefix {self.prefix!r} must be 3-20 chars of lowercase "
                "letters, digits or '-', starting with a letter"
            )
        if self.prefix.startswith("gcp-"):
            raise ConfigError("prefix must not start with 'gcp-' (reserved)")
        if not self.allowed_digests:
            raise ConfigError("allowed_digests must list at least one digest")
        for digest in self.allowed_digests:
            validate_digest(digest)
        if len(set(self.allowed_digests)) != len(self.allowed_digests):
            raise ConfigError("allowed_digests contains duplicates")
        if self.deploy_workloads:
            validate_digest(self.enclave_image_digest)
            validate_digest(self.server_image_digest)
            if self.enclave_image_digest not in self.allowed_digests:
                raise ConfigError(
                    "enclave_image_digest is not in allowed_digests; the VM "
                    "would boot but could never decrypt"
                )
        if self.server_min_instances < 0:
            raise ConfigError("server_min_instances must be >= 0")
        if self.server_max_instances < max(1, self.server_min_instances):
            raise ConfigError("server_max_instances must be >= min and >= 1")
        if self.wif_audience is not None and (
            not self.wif_audience or self.wif_audience in FORBIDDEN_WIF_AUDIENCES
        ):
            raise ConfigError(
                f"wif_audience {self.wif_audience!r} is not allowed; it must be "
                "stack-specific and never a published token's audience"
            )
        if self.control_plane_url is not None:
            validate_control_plane_url(self.control_plane_url)
            # The derived URL is checked again in build_attribute_condition.
            reject_server_audience(self.wif_audience, self.control_plane_url)
        if self.enable_iam_alerts and not self.alert_emails:
            raise ConfigError(
                "IAM change alerts are on by default and need at least one "
                "alert_emails entry; set enable_iam_alerts to false only if "
                "you watch Cloud Audit Logs another way"
            )


def load_config() -> StackConfig:
    """Read and validate the current stack's config."""
    gcp = pulumi.Config("gcp")
    cfg = pulumi.Config()
    region = gcp.get("region") or "us-central1"
    return StackConfig(
        project=gcp.require("project"),
        prefix=cfg.get("prefix") or "carapace",
        region=region,
        zone=gcp.get("zone") or f"{region}-a",
        allowed_digests=cfg.require_object("allowed_digests"),
        enclave_image_digest=cfg.get("enclave_image_digest") or "",
        server_image_digest=cfg.get("server_image_digest") or "",
        image_registry=cfg.get("image_registry"),
        wif_audience=cfg.get("wif_audience"),
        control_plane_url=cfg.get("control_plane_url"),
        enclave_machine_type=(
            cfg.get("enclave_machine_type") or DEFAULT_ENCLAVE_MACHINE_TYPE
        ),
        db_tier=cfg.get("db_tier") or "db-f1-micro",
        server_min_instances=cfg.get_int("server_min_instances") or 0,
        server_max_instances=cfg.get_int("server_max_instances") or 2,
        protect_kms_key=_get_bool(cfg, "protect_kms_key", default=True),
        db_deletion_protection=_get_bool(cfg, "db_deletion_protection", default=True),
        deploy_workloads=_get_bool(cfg, "deploy_workloads", default=True),
        enable_iam_alerts=_get_bool(cfg, "enable_iam_alerts", default=True),
        alert_emails=cfg.get_object("alert_emails") or [],
    )


def _get_bool(cfg: pulumi.Config, key: str, *, default: bool) -> bool:
    value = cfg.get_bool(key)
    return default if value is None else value
