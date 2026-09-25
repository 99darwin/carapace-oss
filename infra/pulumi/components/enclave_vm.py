"""The enclave: one Confidential Space VM with a static IP, reachable on 8443.

The VM has a public IP by design: agents connect to it directly over TLS that
is pinned through attestation, keeping the server out of the data path. The
VPC is dedicated and has exactly one ingress rule (tcp:8443). There is no SSH
rule, and the Confidential Space production image has no SSH access anyway.

Why 8443 and not 443: the image runs as a non-root user, and the launcher
runs it in the VM's network namespace with no ambient capabilities, so it
cannot bind a port below 1024. The launcher opens (and, for a namespaced
container, forwards) only the ports the image ``EXPOSE``s, each to the same
port number, and a VPC firewall rule cannot translate ports either. So one
number is used end to end: the enclave listens on it, the image exposes it,
the firewall allows it, and clients connect to ``https://<ip>:8443``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import pulumi
import pulumi_gcp as gcp

from components.config import build_image_reference

# Production family only; the debug family reports dbgstat=enabled and could
# never pass the WIF condition anyway.
CONFIDENTIAL_SPACE_IMAGE_PROJECT = "confidential-space-images"
CONFIDENTIAL_SPACE_IMAGE_FAMILY = "confidential-space"
CONFIDENTIAL_INSTANCE_TYPE = "SEV"
# Must equal ENCLAVE_PORT in enclave/src/carapace_enclave/runtime.py and the
# EXPOSE in enclave/Dockerfile (tests on both sides check this).
INGRESS_PORT = 8443
ANY_IPV4 = "0.0.0.0/0"
SUBNET_CIDR = "10.10.0.0/24"
BOOT_DISK_GB = 20
# The launcher only honours overrides the image's launch policy allows; keep
# this list identical to the policy baked into the enclave image. A wrong value
# for any of them can only make decryption fail, never widen access.
ALLOWED_ENV_OVERRIDES: frozenset[str] = frozenset(
    {"CONTROL_PLANE_URL", "KMS_KEY_NAME", "WIF_AUDIENCE"}
)


@dataclass(frozen=True)
class EnclaveNetwork:
    network: gcp.compute.Network
    subnet: gcp.compute.Subnetwork
    firewall: gcp.compute.Firewall
    address: gcp.compute.Address


@dataclass(frozen=True)
class EnclaveVm:
    instance: gcp.compute.Instance
    image_reference: str


def enclave_network_tag(prefix: str) -> str:
    return f"{prefix}-enclave"


def build_enclave_url(ip: str) -> str:
    """The URL clients use to reach the enclave; the port is always explicit."""
    return f"https://{ip}:{INGRESS_PORT}"


def build_enclave_metadata(
    *, image_reference: str, env: dict[str, str]
) -> dict[str, str]:
    """Return Confidential Space launcher metadata, enforcing the override list."""
    if "@sha256:" not in image_reference:
        raise ValueError("tee-image-reference must be pinned by digest")
    unexpected = set(env) - ALLOWED_ENV_OVERRIDES
    if unexpected:
        raise ValueError(f"env overrides not allowed: {sorted(unexpected)}")
    metadata = {
        "tee-image-reference": image_reference,
        # Forwards container stdout/stderr to Cloud Logging (the reason the VM
        # SA has logging.logWriter). The image's launch policy must permit it,
        # and the enclave must never log secret material.
        "tee-container-log-redirect": "true",
    }
    metadata.update({f"tee-env-{key}": value for key, value in env.items()})
    return metadata


def create_enclave_network(
    *, prefix: str, region: str, depends_on: list[pulumi.Resource]
) -> EnclaveNetwork:
    opts = pulumi.ResourceOptions(depends_on=depends_on)
    network = gcp.compute.Network(
        f"{prefix}-vpc",
        name=f"{prefix}-vpc",
        auto_create_subnetworks=False,
        opts=opts,
    )
    subnet = gcp.compute.Subnetwork(
        f"{prefix}-enclave-subnet",
        name=f"{prefix}-enclave",
        network=network.id,
        region=region,
        ip_cidr_range=SUBNET_CIDR,
    )
    firewall = gcp.compute.Firewall(
        f"{prefix}-allow-enclave-https",
        name=f"{prefix}-allow-enclave-https",
        network=network.id,
        direction="INGRESS",
        allows=[{"protocol": "tcp", "ports": [str(INGRESS_PORT)]}],
        source_ranges=[ANY_IPV4],
        target_tags=[enclave_network_tag(prefix)],
    )
    address = gcp.compute.Address(
        f"{prefix}-enclave-ip",
        name=f"{prefix}-enclave-ip",
        region=region,
        address_type="EXTERNAL",
        opts=opts,
    )
    return EnclaveNetwork(
        network=network, subnet=subnet, firewall=firewall, address=address
    )


def create_enclave_vm(
    *,
    prefix: str,
    zone: str,
    machine_type: str,
    image_repository: str,
    image_digest: str,
    service_account_email: pulumi.Input[str],
    network: EnclaveNetwork,
    control_plane_url: pulumi.Input[str],
    kms_key_name: pulumi.Input[str],
    wif_audience: pulumi.Input[str],
    depends_on: Sequence[pulumi.Resource] = (),
) -> EnclaveVm:
    # Validated eagerly: a tag-only reference fails before any resource exists.
    image_reference = build_image_reference(image_repository, image_digest)
    metadata = pulumi.Output.all(control_plane_url, kms_key_name, wif_audience).apply(
        lambda args: build_enclave_metadata(
            image_reference=image_reference,
            env={
                "CONTROL_PLANE_URL": args[0],
                "KMS_KEY_NAME": args[1],
                "WIF_AUDIENCE": args[2],
            },
        )
    )
    # Resolved to a concrete image so a new Confidential Space release shows up
    # as a diff (and a VM replacement) instead of silently aging in place.
    boot_image = gcp.compute.get_image_output(
        family=CONFIDENTIAL_SPACE_IMAGE_FAMILY,
        project=CONFIDENTIAL_SPACE_IMAGE_PROJECT,
    ).self_link
    instance = gcp.compute.Instance(
        f"{prefix}-enclave",
        name=f"{prefix}-enclave",
        zone=zone,
        machine_type=machine_type,
        tags=[enclave_network_tag(prefix)],
        boot_disk={
            "initialize_params": {
                "image": boot_image,
                "size": BOOT_DISK_GB,
            }
        },
        confidential_instance_config={
            "confidential_instance_type": CONFIDENTIAL_INSTANCE_TYPE,
        },
        shielded_instance_config={
            "enable_secure_boot": True,
            "enable_vtpm": True,
            "enable_integrity_monitoring": True,
        },
        scheduling={"on_host_maintenance": "TERMINATE", "automatic_restart": True},
        network_interfaces=[
            {
                "subnetwork": network.subnet.id,
                "access_configs": [{"nat_ip": network.address.address}],
            }
        ],
        service_account={
            "email": service_account_email,
            "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
        },
        metadata=metadata,
        allow_stopping_for_update=True,
        # The launcher reads metadata only at boot, so an image or env change
        # must recreate the VM. Delete first: the static IP and name are fixed.
        opts=pulumi.ResourceOptions(
            depends_on=[network.firewall, *depends_on],
            replace_on_changes=["metadata"],
            delete_before_replace=True,
        ),
    )
    return EnclaveVm(instance=instance, image_reference=image_reference)
