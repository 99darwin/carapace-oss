"""Compose every component into one deployment."""

from __future__ import annotations

import pulumi
import pulumi_gcp as gcp

from components.apis import enable_apis
from components.config import StackConfig
from components.enclave_vm import (
    build_enclave_url,
    create_enclave_network,
    create_enclave_vm,
)
from components.identity import create_service_identities, grant_image_pull
from components.kms import (
    bind_key_policy,
    create_kms_key,
    enable_kms_data_access_logs,
)
from components.monitoring import create_iam_change_alert
from components.server import (
    build_server_url,
    create_database,
    create_jwt_secret,
    create_registry,
    create_server_workloads,
    server_service_name,
)
from components.wif import create_workload_identity


def deploy(cfg: StackConfig) -> dict[str, pulumi.Input[object]]:
    """Declare all resources and return the stack outputs."""
    apis = enable_apis(cfg.prefix)
    project = gcp.organizations.get_project_output(project_id=cfg.project)
    # One value everywhere: the server's CARAPACE_PUBLIC_URL (the audience of
    # enclave-to-server tokens), the enclave's CONTROL_PLANE_URL, and the WIF
    # condition. Cloud Run's deterministic URL is known before the service
    # exists, so the WIF gate can pin it even in bootstrap mode.
    control_plane_url: pulumi.Output[str] = (
        pulumi.Output.from_input(cfg.control_plane_url)
        if cfg.control_plane_url
        else project.number.apply(
            lambda number: build_server_url(
                service_name=server_service_name(cfg.prefix),
                project_number=number,
                region=cfg.region,
            )
        )
    )

    identities = create_service_identities(
        prefix=cfg.prefix, project=cfg.project, depends_on=apis
    )
    kms_key = create_kms_key(
        prefix=cfg.prefix,
        location=cfg.region,
        protect=cfg.protect_kms_key,
        depends_on=apis,
    )
    kms_audit = enable_kms_data_access_logs(
        prefix=cfg.prefix, project=cfg.project, depends_on=apis
    )
    workload_identity = create_workload_identity(
        prefix=cfg.prefix,
        project_id=cfg.project,
        project_number=project.number,
        enclave_sa_email=identities.enclave.email,
        allowed_digests=cfg.allowed_digests,
        audience=cfg.wif_audience,
        control_plane_url=control_plane_url,
        depends_on=apis,
    )
    key_policy = bind_key_policy(
        prefix=cfg.prefix,
        kms_key=kms_key,
        decrypter_members=workload_identity.principal_sets,
        public_key_viewers=identities.server_member.apply(lambda m: [m]),
    )

    registry = create_registry(
        prefix=cfg.prefix, project=cfg.project, region=cfg.region, depends_on=apis
    )
    image_pull = grant_image_pull(
        prefix=cfg.prefix,
        repository=registry.repository,
        member=identities.enclave_member,
    )
    database = create_database(
        prefix=cfg.prefix,
        region=cfg.region,
        tier=cfg.db_tier,
        deletion_protection=cfg.db_deletion_protection,
        server_sa_email=identities.server.email,
        depends_on=apis,
    )
    jwt_secret = create_jwt_secret(
        prefix=cfg.prefix, server_sa_email=identities.server.email, depends_on=apis
    )
    network = create_enclave_network(
        prefix=cfg.prefix, region=cfg.region, depends_on=apis
    )

    outputs: dict[str, pulumi.Input[object]] = {
        "kms_key_name": kms_key.key_name,
        "kms_key_version_name": kms_key.key_version_name,
        "wif_provider_name": workload_identity.provider_name,
        "wif_principal_sets": workload_identity.principal_sets,
        "wif_audience": workload_identity.sts_audience,
        "enclave_service_account": identities.enclave.email,
        "server_service_account": identities.server.email,
        "enclave_ip": network.address.address,
        "image_registry": registry.url,
        "db_connection_name": database.instance.connection_name,
        "database_url_secret": database.url_secret.secret.id,
        "jwt_secret": jwt_secret.secret.id,
        "allowed_digests": cfg.allowed_digests,
        "server_url": control_plane_url,
        "control_plane_url": control_plane_url,
    }

    if cfg.enable_iam_alerts:
        create_iam_change_alert(
            prefix=cfg.prefix,
            key_ring_name=kms_key.key_ring.id,
            project_number=project.number,
            pool_id=workload_identity.pool.workload_identity_pool_id,
            enclave_sa_email=identities.enclave.email,
            enclave_sa_unique_id=identities.enclave.unique_id,
            emails=cfg.alert_emails,
        )

    if not cfg.deploy_workloads:
        return outputs

    # Must match create_registry's URL; built eagerly so image references can
    # be validated before any workload resource is declared.
    image_registry = (
        cfg.image_registry or f"{cfg.region}-docker.pkg.dev/{cfg.project}/{cfg.prefix}"
    )
    server = create_server_workloads(
        prefix=cfg.prefix,
        region=cfg.region,
        image_repository=f"{image_registry}/server",
        image_digest=cfg.server_image_digest,
        service_account_email=identities.server.email,
        database=database,
        jwt_secret=jwt_secret,
        public_url=control_plane_url,
        allowed_digests=cfg.allowed_digests,
        attestation_project_id=cfg.project,
        enclave_sa_email=identities.enclave.email,
        min_instances=cfg.server_min_instances,
        max_instances=cfg.server_max_instances,
        depends_on=[identities.server_grants["roles/cloudsql.client"]],
    )
    enclave = create_enclave_vm(
        prefix=cfg.prefix,
        zone=cfg.zone,
        machine_type=cfg.enclave_machine_type,
        image_repository=f"{image_registry}/enclave",
        image_digest=cfg.enclave_image_digest,
        service_account_email=identities.enclave.email,
        network=network,
        control_plane_url=control_plane_url,
        kms_key_name=kms_key.key_version_name,
        wif_audience=workload_identity.sts_audience,
        # Boot only once the VM can pull, attest and have the key released,
        # and once every decrypt it makes will be logged.
        depends_on=[
            *identities.enclave_grants.values(),
            image_pull,
            workload_identity.provider,
            key_policy,
            kms_audit,
        ],
    )
    outputs.update(
        {
            "enclave_image_reference": enclave.image_reference,
            "migration_job": server.migration_job.name,
            "enclave_url": network.address.address.apply(build_enclave_url),
        }
    )
    return outputs
