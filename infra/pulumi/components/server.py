"""Untrusted control plane: Artifact Registry, Cloud SQL and Cloud Run.

The server stores ciphertext, policy and receipts. It never sees plaintext,
so it runs as an ordinary Cloud Run service with public ingress; auth is done
by the application. The database password is generated here, stored only in
Secret Manager, and injected into Cloud Run as a secret reference.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import pulumi
import pulumi_gcp as gcp
import pulumi_random as random

from components.config import build_image_reference

POSTGRES_VERSION = "POSTGRES_16"
# Shared-core tiers such as db-f1-micro exist only in the ENTERPRISE edition;
# Postgres 16+ otherwise defaults to ENTERPRISE_PLUS.
SQL_EDITION = "ENTERPRISE"
DB_NAME = "carapace"
DB_USER = "carapace"
DB_PASSWORD_LENGTH = 40
CLOUDSQL_MOUNT_PATH = "/cloudsql"
CONTAINER_PORT = 8080
SERVER_MODE = "prod"


@dataclass(frozen=True)
class Registry:
    repository: gcp.artifactregistry.Repository
    url: pulumi.Output[str]


@dataclass(frozen=True)
class Database:
    instance: gcp.sql.DatabaseInstance
    password_secret: gcp.secretmanager.Secret
    password_version: gcp.secretmanager.SecretVersion
    password_access: gcp.secretmanager.SecretIamMember
    user: gcp.sql.User


def create_registry(
    *, prefix: str, project: str, region: str, depends_on: list[pulumi.Resource]
) -> Registry:
    repository = gcp.artifactregistry.Repository(
        f"{prefix}-images",
        repository_id=prefix,
        location=region,
        format="DOCKER",
        description="Carapace enclave and server images",
        opts=pulumi.ResourceOptions(depends_on=depends_on),
    )
    url = repository.repository_id.apply(
        lambda repo_id: f"{region}-docker.pkg.dev/{project}/{repo_id}"
    )
    return Registry(repository=repository, url=url)


def create_database(
    *,
    prefix: str,
    region: str,
    tier: str,
    deletion_protection: bool,
    server_sa_email: pulumi.Input[str],
    depends_on: list[pulumi.Resource],
) -> Database:
    instance = gcp.sql.DatabaseInstance(
        f"{prefix}-db",
        region=region,
        database_version=POSTGRES_VERSION,
        deletion_protection=deletion_protection,
        settings={
            "tier": tier,
            "edition": SQL_EDITION,
            "availability_type": "ZONAL",
            "deletion_protection_enabled": deletion_protection,
            "backup_configuration": {"enabled": True},
            # Public IP with no authorized networks: only IAM-authorized
            # Cloud SQL connector clients (the Cloud Run volume) can connect.
            "ip_configuration": {
                "ipv4_enabled": True,
                "ssl_mode": "ENCRYPTED_ONLY",
            },
        },
        opts=pulumi.ResourceOptions(depends_on=depends_on),
    )
    gcp.sql.Database(f"{prefix}-db-carapace", name=DB_NAME, instance=instance.name)
    password = random.RandomPassword(
        f"{prefix}-db-password", length=DB_PASSWORD_LENGTH, special=False
    )
    user = gcp.sql.User(
        f"{prefix}-db-user",
        name=DB_USER,
        instance=instance.name,
        password=password.result,
    )
    secret = gcp.secretmanager.Secret(
        f"{prefix}-db-password-secret",
        secret_id=f"{prefix}-db-password",
        replication={"auto": {}},
        opts=pulumi.ResourceOptions(depends_on=depends_on),
    )
    version = gcp.secretmanager.SecretVersion(
        f"{prefix}-db-password-version",
        secret=secret.id,
        secret_data=password.result,
    )
    password_access = gcp.secretmanager.SecretIamMember(
        f"{prefix}-server-db-password-access",
        secret_id=secret.id,
        role="roles/secretmanager.secretAccessor",
        member=pulumi.Output.concat("serviceAccount:", server_sa_email),
    )
    return Database(
        instance=instance,
        password_secret=secret,
        password_version=version,
        password_access=password_access,
        user=user,
    )


def build_server_env(
    *,
    connection_name: pulumi.Input[str],
    kms_key_name: pulumi.Input[str],
    allowed_digests: Sequence[str],
) -> list[dict[str, pulumi.Input[str]]]:
    """Plain (non-secret) environment for the server container."""
    values: dict[str, pulumi.Input[str]] = {
        "CARAPACE_MODE": SERVER_MODE,
        "DB_HOST": pulumi.Output.concat(CLOUDSQL_MOUNT_PATH, "/", connection_name),
        "DB_NAME": DB_NAME,
        "DB_USER": DB_USER,
        "KMS_KEY_NAME": kms_key_name,
        "ALLOWED_IMAGE_DIGESTS": ",".join(allowed_digests),
    }
    return [{"name": name, "value": value} for name, value in values.items()]


def create_server_service(
    *,
    prefix: str,
    region: str,
    image_repository: str,
    image_digest: str,
    service_account_email: pulumi.Input[str],
    database: Database,
    kms_key_name: pulumi.Input[str],
    allowed_digests: Sequence[str],
    min_instances: int,
    max_instances: int,
) -> gcp.cloudrunv2.Service:
    image = build_image_reference(image_repository, image_digest)
    plain_env = build_server_env(
        connection_name=database.instance.connection_name,
        kms_key_name=kms_key_name,
        allowed_digests=allowed_digests,
    )
    secret_env = {
        "name": "DB_PASSWORD",
        "value_source": {
            "secret_key_ref": {
                "secret": database.password_secret.secret_id,
                "version": database.password_version.version,
            }
        },
    }
    return gcp.cloudrunv2.Service(
        f"{prefix}-server",
        name=f"{prefix}-server",
        location=region,
        ingress="INGRESS_TRAFFIC_ALL",
        # Public API; authentication is enforced by the application.
        invoker_iam_disabled=True,
        deletion_protection=False,
        template={
            "service_account": service_account_email,
            "scaling": {
                "min_instance_count": min_instances,
                "max_instance_count": max_instances,
            },
            "volumes": [
                {
                    "name": "cloudsql",
                    "cloud_sql_instance": {
                        "instances": [database.instance.connection_name]
                    },
                }
            ],
            "containers": [
                {
                    "image": image,
                    "ports": {"container_port": CONTAINER_PORT},
                    "envs": [*plain_env, secret_env],
                    "volume_mounts": [
                        {"name": "cloudsql", "mount_path": CLOUDSQL_MOUNT_PATH}
                    ],
                }
            ],
        },
        opts=pulumi.ResourceOptions(
            depends_on=[database.password_access, database.user]
        ),
    )
