"""Compose every component into one deployment."""

from __future__ import annotations

import pulumi
import pulumi_gcp as gcp

from components.apis import enable_apis
from components.config import StackConfig
from components.enclave_vm import create_enclave_network, create_enclave_vm
from components.identity import create_service_identities
from components.kms import bind_key_policy, create_kms_key
from components.monitoring import create_iam_change_alert
from components.server import create_database, create_registry, create_server_service
from components.wif import create_workload_identity


def deploy(cfg: StackConfig) -> dict[str, pulumi.Input[object]]:
    """Declare all resources and return the stack outputs."""
    apis = enable_apis(cfg.prefix)
    project = gcp.organizations.get_project_output(project_id=cfg.project)

    identities = create_service_identities(
        prefix=cfg.prefix, project=cfg.project, depends_on=apis
    )
    kms_key = create_kms_key(
        prefix=cfg.prefix,
        location=cfg.region,
        protect=cfg.protect_kms_key,
        depends_on=apis,
    )
    workload_identity = create_workload_identity(
        prefix=cfg.prefix,
        project_id=cfg.project,
        project_number=project.number,
        enclave_sa_email=identities.enclave.email,
        allowed_digests=cfg.allowed_digests,
        audience=cfg.wif_audience,
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
    database = create_database(
        prefix=cfg.prefix,
        region=cfg.region,
        tier=cfg.db_tier,
        deletion_protection=cfg.db_deletion_protection,
        server_sa_email=identities.server.email,
        depends_on=apis,
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
        "db_password_secret": database.password_secret.id,
        "allowed_digests": cfg.allowed_digests,
    }

    if cfg.enable_iam_alerts:
        create_iam_change_alert(
            prefix=cfg.prefix,
            key_ring_name=kms_key.key_ring.id,
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
    server = create_server_service(
        prefix=cfg.prefix,
        region=cfg.region,
        image_repository=f"{image_registry}/server",
        image_digest=cfg.server_image_digest,
        service_account_email=identities.server.email,
        database=database,
        kms_key_name=kms_key.key_version_name,
        allowed_digests=cfg.allowed_digests,
        min_instances=cfg.server_min_instances,
        max_instances=cfg.server_max_instances,
        depends_on=[identities.server_grants["roles/cloudsql.client"]],
    )
    control_plane_url = cfg.control_plane_url or server.uri
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
        # Boot only once the VM can attest and the key can be released.
        depends_on=[
            *identities.enclave_grants.values(),
            workload_identity.provider,
            key_policy,
        ],
    )
    outputs.update(
        {
            "server_url": server.uri,
            "control_plane_url": control_plane_url,
            "enclave_image_reference": enclave.image_reference,
            "enclave_url": network.address.address.apply(lambda ip: f"https://{ip}"),
        }
    )
    return outputs
