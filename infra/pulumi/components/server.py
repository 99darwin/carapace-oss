"""Untrusted control plane: Artifact Registry, Cloud SQL and Cloud Run.

The server stores ciphertext, policy and receipts. It never sees plaintext,
so it runs as an ordinary Cloud Run service with public ingress; auth is done
by the application. The database URL (which embeds a generated password) and
the JWT signing secret are generated here, stored only in Secret Manager, and
injected into Cloud Run as secret references.

Every environment variable name matches a ``CARAPACE_*`` setting in
``server/src/carapace_server/config.py``. ``tests/test_server_env_contract.py``
fails if the two drift apart.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import quote

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
# The server refuses anything shorter than 32 characters.
JWT_SECRET_LENGTH = 64
CLOUDSQL_MOUNT_PATH = "/cloudsql"
CONTAINER_PORT = 8080
SERVER_MODE = "prod"
SERVER_ENV_PREFIX = "CARAPACE_"
SECRET_ACCESSOR_ROLE = "roles/secretmanager.secretAccessor"  # noqa: S105


@dataclass(frozen=True)
class Registry:
    repository: gcp.artifactregistry.Repository
    url: pulumi.Output[str]


@dataclass(frozen=True)
class ServerSecret:
    """A Secret Manager secret that only the server service account can read."""

    secret: gcp.secretmanager.Secret
    version: gcp.secretmanager.SecretVersion
    access: gcp.secretmanager.SecretIamMember

    def env(self, name: str) -> dict[str, object]:
        """Cloud Run env entry that references this secret, never its value."""
        return {
            "name": name,
            "value_source": {
                "secret_key_ref": {
                    "secret": self.secret.secret_id,
                    "version": self.version.version,
                }
            },
        }


@dataclass(frozen=True)
class Database:
    instance: gcp.sql.DatabaseInstance
    url_secret: ServerSecret
    user: gcp.sql.User


def server_service_name(prefix: str) -> str:
    return f"{prefix}-server"


def build_server_url(*, service_name: str, project_number: str, region: str) -> str:
    """Cloud Run's deterministic URL for a service.

    It is known before the service exists, so one value can serve as the
    server's ``CARAPACE_PUBLIC_URL``, the enclave's ``CONTROL_PLANE_URL`` and a
    clause of the WIF condition.
    """
    return f"https://{service_name}-{project_number}.{region}.run.app"


def build_database_url(*, password: str, connection_name: str) -> str:
    """asyncpg URL that connects through the Cloud SQL unix socket volume."""
    return (
        f"postgresql+asyncpg://{DB_USER}:{quote(password, safe='')}@/{DB_NAME}"
        f"?host={CLOUDSQL_MOUNT_PATH}/{connection_name}"
    )


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


def create_server_secret(
    *,
    name: str,
    value: pulumi.Input[str],
    accessor_email: pulumi.Input[str],
    depends_on: Sequence[pulumi.Resource] = (),
) -> ServerSecret:
    """Store ``value`` in Secret Manager, readable only by ``accessor_email``."""
    secret = gcp.secretmanager.Secret(
        f"{name}-secret",
        secret_id=name,
        replication={"auto": {}},
        opts=pulumi.ResourceOptions(depends_on=list(depends_on)),
    )
    version = gcp.secretmanager.SecretVersion(
        f"{name}-version",
        secret=secret.id,
        secret_data=pulumi.Output.secret(value),
    )
    access = gcp.secretmanager.SecretIamMember(
        f"{name}-access",
        secret_id=secret.id,
        role=SECRET_ACCESSOR_ROLE,
        member=pulumi.Output.concat("serviceAccount:", accessor_email),
    )
    return ServerSecret(secret=secret, version=version, access=access)


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
    database_url = pulumi.Output.all(password.result, instance.connection_name).apply(
        lambda args: build_database_url(password=args[0], connection_name=args[1])
    )
    url_secret = create_server_secret(
        name=f"{prefix}-database-url",
        value=database_url,
        accessor_email=server_sa_email,
        depends_on=depends_on,
    )
    return Database(instance=instance, url_secret=url_secret, user=user)


def create_jwt_secret(
    *,
    prefix: str,
    server_sa_email: pulumi.Input[str],
    depends_on: Sequence[pulumi.Resource] = (),
) -> ServerSecret:
    """Generate the server's JWT signing secret and store it in Secret Manager."""
    value = random.RandomPassword(
        f"{prefix}-jwt-secret-value", length=JWT_SECRET_LENGTH, special=False
    )
    return create_server_secret(
        name=f"{prefix}-jwt-secret",
        value=value.result,
        accessor_email=server_sa_email,
        depends_on=depends_on,
    )


def build_server_env(
    *,
    public_url: pulumi.Input[str],
    allowed_digests: Sequence[str],
    attestation_project_id: str,
    attestation_service_account: pulumi.Input[str],
    kms_public_key_pem: pulumi.Input[str],
    kms_key_version: pulumi.Input[str],
) -> list[dict[str, pulumi.Input[str]]]:
    """Plain (non-secret) environment for the server container.

    The KMS public key and version name are public values: the server serves
    them at ``/v1/kms/public-key`` and clients only trust them if they match
    what the attested enclave reports.
    """
    values: dict[str, pulumi.Input[str]] = {
        "MODE": SERVER_MODE,
        "PUBLIC_URL": public_url,
        "ALLOWED_IMAGE_DIGESTS": ",".join(allowed_digests),
        "ATTESTATION_PROJECT_ID": attestation_project_id,
        "ATTESTATION_SERVICE_ACCOUNT": attestation_service_account,
        "KMS_PUBLIC_KEY_PEM": kms_public_key_pem,
        "KMS_KEY_VERSION": kms_key_version,
    }
    return [
        {"name": f"{SERVER_ENV_PREFIX}{name}", "value": value}
        for name, value in values.items()
    ]


def create_server_service(
    *,
    prefix: str,
    region: str,
    image_repository: str,
    image_digest: str,
    service_account_email: pulumi.Input[str],
    database: Database,
    jwt_secret: ServerSecret,
    public_url: pulumi.Input[str],
    allowed_digests: Sequence[str],
    attestation_project_id: str,
    enclave_sa_email: pulumi.Input[str],
    kms_public_key_pem: pulumi.Input[str],
    kms_key_version: pulumi.Input[str],
    min_instances: int,
    max_instances: int,
    depends_on: Sequence[pulumi.Resource] = (),
) -> gcp.cloudrunv2.Service:
    image = build_image_reference(image_repository, image_digest)
    plain_env = build_server_env(
        public_url=public_url,
        allowed_digests=allowed_digests,
        attestation_project_id=attestation_project_id,
        attestation_service_account=enclave_sa_email,
        kms_public_key_pem=kms_public_key_pem,
        kms_key_version=kms_key_version,
    )
    secret_env = [
        database.url_secret.env(f"{SERVER_ENV_PREFIX}DATABASE_URL"),
        jwt_secret.env(f"{SERVER_ENV_PREFIX}JWT_SECRET"),
    ]
    return gcp.cloudrunv2.Service(
        f"{prefix}-server",
        name=server_service_name(prefix),
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
                    "envs": [*plain_env, *secret_env],
                    "volume_mounts": [
                        {"name": "cloudsql", "mount_path": CLOUDSQL_MOUNT_PATH}
                    ],
                }
            ],
        },
        opts=pulumi.ResourceOptions(
            depends_on=[
                database.url_secret.access,
                jwt_secret.access,
                database.user,
                *depends_on,
            ]
        ),
    )
