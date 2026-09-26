"""Untrusted control plane: Artifact Registry, Cloud SQL and Cloud Run.

The server stores ciphertext, policy and receipts. It never sees plaintext,
so it runs as an ordinary Cloud Run service with public ingress; auth is done
by the application. A Cloud Run job runs the alembic migrations from the same
image, with the same environment, before each new server image is rolled out.
The database URL (which embeds a generated password) and the JWT signing
secret are generated here, stored only in Secret Manager, and injected into
Cloud Run as secret references.

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
CLOUDSQL_VOLUME_MOUNT = {"name": "cloudsql", "mount_path": CLOUDSQL_MOUNT_PATH}
CONTAINER_PORT = 8080
SERVER_MODE = "prod"
# Cloud Run's frontend is the one proxy between the client and the
# container; it appends the client address as the last X-Forwarded-For
# entry. The server keys rate limits on that entry (never a client-supplied
# one) instead of the frontend's address, which every caller would share.
CLOUD_RUN_PROXY_HOPS = 1
SERVER_ENV_PREFIX = "CARAPACE_"
SECRET_ACCESSOR_ROLE = "roles/secretmanager.secretAccessor"  # noqa: S105
# Overrides the image's entrypoint; server/Dockerfile copies alembic.ini to
# this path (server/tests/test_image_build.py checks it).
MIGRATION_COMMAND = ("/usr/bin/python3",)
MIGRATION_ARGS = ("-m", "alembic", "-c", "/app/server/alembic.ini", "upgrade", "head")
MIGRATION_TIMEOUT = "600s"
# Hex suffix of the execution name; job name + token must stay under 63 chars.
MIGRATION_TOKEN_BYTES = 8


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
    sql_database: gcp.sql.Database
    url_secret: ServerSecret
    user: gcp.sql.User


@dataclass(frozen=True)
class ServerWorkloads:
    service: gcp.cloudrunv2.Service
    migration_job: gcp.cloudrunv2.Job


def server_service_name(prefix: str) -> str:
    return f"{prefix}-server"


def migration_job_name(prefix: str) -> str:
    return f"{prefix}-migrate"


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
        opts=pulumi.ResourceOptions(protect=deletion_protection, depends_on=depends_on),
    )
    # deletion_protection only guards the instance at delete time, after its
    # dependents are gone. protect makes Pulumi refuse the whole plan up
    # front, so a protected stack can neither be half-destroyed nor have its
    # role or database replaced (ABANDON, below, would strand the old one).
    # carapace destroy lifts both with an up targeted at the protected
    # resources in the state (cli deploy/destroy.py).
    protected = pulumi.ResourceOptions(protect=deletion_protection)
    # Both are removed with the instance. Deleting them first fails: the
    # role owns the migrated tables, and the server holds connections.
    # ABANDON also applies on replacement (a new DB_NAME, DB_USER or user
    # type): the old database keeps its tables and the old role its password.
    # Rotate the password by replacing the RandomPassword, never the User.
    sql_database = gcp.sql.Database(
        f"{prefix}-db-carapace",
        name=DB_NAME,
        instance=instance.name,
        deletion_policy="ABANDON",
        opts=protected,
    )
    password = random.RandomPassword(
        f"{prefix}-db-password", length=DB_PASSWORD_LENGTH, special=False
    )
    user = gcp.sql.User(
        f"{prefix}-db-user",
        name=DB_USER,
        instance=instance.name,
        password=password.result,
        deletion_policy="ABANDON",
        opts=protected,
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
    return Database(
        instance=instance, sql_database=sql_database, url_secret=url_secret, user=user
    )


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
        "TRUSTED_PROXY_HOPS": str(CLOUD_RUN_PROXY_HOPS),
    }
    return [
        {"name": f"{SERVER_ENV_PREFIX}{name}", "value": value}
        for name, value in values.items()
    ]


def _cloudsql_volume(database: Database) -> dict[str, object]:
    return {
        "name": "cloudsql",
        "cloud_sql_instance": {"instances": [database.instance.connection_name]},
    }


def create_migration_job(
    *,
    prefix: str,
    region: str,
    image: str,
    service_account_email: pulumi.Input[str],
    envs: Sequence[dict[str, object]],
    database: Database,
    depends_on: Sequence[pulumi.Resource] = (),
) -> gcp.cloudrunv2.Job:
    """A job that runs ``alembic upgrade head`` from the server image.

    It gets exactly the server's environment and Cloud SQL volume, so the
    database URL comes from the same Secret Manager reference. A new execution
    token is drawn whenever the image changes; Pulumi then runs the job and
    waits for it to succeed, and the service is updated only after that.
    """
    token = random.RandomId(
        f"{prefix}-migrate-token",
        byte_length=MIGRATION_TOKEN_BYTES,
        keepers={"image": image},
    )
    return gcp.cloudrunv2.Job(
        f"{prefix}-migrate",
        name=migration_job_name(prefix),
        location=region,
        deletion_protection=False,
        run_execution_token=token.hex,
        template={
            # One task, no retries: alembic runs each migration in a
            # transaction, and two runners must never race on the schema.
            "task_count": 1,
            "parallelism": 1,
            "template": {
                "service_account": service_account_email,
                "max_retries": 0,
                "timeout": MIGRATION_TIMEOUT,
                "volumes": [_cloudsql_volume(database)],
                "containers": [
                    {
                        "image": image,
                        "commands": list(MIGRATION_COMMAND),
                        "args": list(MIGRATION_ARGS),
                        "envs": list(envs),
                        "volume_mounts": [CLOUDSQL_VOLUME_MOUNT],
                    }
                ],
            },
        },
        opts=pulumi.ResourceOptions(
            depends_on=[
                database.url_secret.access,
                database.user,
                database.sql_database,
                *depends_on,
            ]
        ),
    )


def create_server_workloads(
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
) -> ServerWorkloads:
    """The server service and its migration job, from one pinned image."""
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
    envs = [*plain_env, *secret_env]
    # The server's settings refuse to load in prod without every required
    # variable, so the job needs the JWT secret too even though it never
    # signs anything.
    migration_job = create_migration_job(
        prefix=prefix,
        region=region,
        image=image,
        service_account_email=service_account_email,
        envs=envs,
        database=database,
        depends_on=[jwt_secret.access, *depends_on],
    )
    service = gcp.cloudrunv2.Service(
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
            "volumes": [_cloudsql_volume(database)],
            "containers": [
                {
                    "image": image,
                    "ports": {"container_port": CONTAINER_PORT},
                    "envs": envs,
                    "volume_mounts": [CLOUDSQL_VOLUME_MOUNT],
                }
            ],
        },
        opts=pulumi.ResourceOptions(
            depends_on=[
                database.url_secret.access,
                jwt_secret.access,
                database.user,
                migration_job,
                *depends_on,
            ]
        ),
    )
    return ServerWorkloads(service=service, migration_job=migration_job)
