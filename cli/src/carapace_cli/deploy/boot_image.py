"""The Confidential Space boot image, resolved once per deploy and pinned.

The enclave VM boots Google's Confidential Space image, and a new image
replaces the VM (the boot disk image is ForceNew). The image is kept
current on purpose: WIF requires the ``STABLE`` support attribute, which
Google drops from old images. Left to the Pulumi program, the image would
be looked up from its family on every program run, so it could change
between the preview the deploy shows the user and the ``up`` that
follows, and replace the VM unannounced.

So the CLI looks the family up once per deploy, here, and pins the
result in the stack config (``carapace:boot_image``) before any preview:
the preview and the ``up`` then read the same image. The program uses
the pin when it is set, and the family otherwise (a manual ``pulumi up``).

The image is part of the trust root, so a pin must name an image of the
``confidential-space-images`` project, never another project's, and
never a debug image (whose attestation WIF refuses anyway).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from carapace_cli.deploy.gcp import COMPUTE, GcpApi
from carapace_cli.deploy.pulumi_runner import StateResource
from carapace_cli.deploy.zones import ENCLAVE_INSTANCE_TYPE, live_zonal_resources
from carapace_cli.errors import CarapaceError

BOOT_IMAGE_KEY = "carapace:boot_image"
IMAGE_PROJECT = "confidential-space-images"
# Production family only: the debug family reports dbgstat=enabled.
IMAGE_FAMILY = "confidential-space"
FAMILY_URL = f"{COMPUTE}/projects/{IMAGE_PROJECT}/global/images/family/{IMAGE_FAMILY}"
# A selfLink (as Compute and the provider write it) or a bare path, of an
# image in IMAGE_PROJECT. Must match BOOT_IMAGE_PATTERN in
# infra/pulumi/components/config.py.
BOOT_IMAGE_PATTERN = re.compile(
    r"^(?:https://(?:www|compute)\.googleapis\.com/compute/v1/)?"
    rf"projects/{IMAGE_PROJECT}/global/images/"
    r"[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$"
)
DEBUG_MARKER = "debug"


class BootImageError(CarapaceError):
    """The boot image is not a production Confidential Space image."""


def validate_boot_image(value: str) -> str:
    """Return ``value`` if it names a production Confidential Space image."""
    name = value.rpartition("/")[2]
    if not BOOT_IMAGE_PATTERN.fullmatch(value) or DEBUG_MARKER in name:
        raise BootImageError(
            f"{value[:200]!r} is not an image of the {IMAGE_PROJECT} project's "
            f"{IMAGE_FAMILY} family"
        )
    return value


def latest_boot_image(api: GcpApi) -> str:
    """The newest image of the Confidential Space family, as a selfLink."""
    image = api.get(FAMILY_URL)
    if image.get("family") != IMAGE_FAMILY:
        raise BootImageError(
            f"Compute returned an image outside the {IMAGE_FAMILY} family"
        )
    return validate_boot_image(str(image.get("selfLink") or ""))


def _vm_image(outputs: Mapping[str, Any]) -> str | None:
    boot_disk = outputs.get("bootDisk")
    params = boot_disk.get("initializeParams") if isinstance(boot_disk, dict) else None
    image = params.get("image") if isinstance(params, dict) else None
    if not isinstance(image, str):
        return None
    try:
        return validate_boot_image(image)
    except BootImageError:
        return None


def running_boot_image(
    resources: Sequence[StateResource], config: Mapping[str, str]
) -> str | None:
    """The image the live enclave VM booted; None without a live VM.

    Read from the VM's state, which tells the truth even when the config
    pins another image (say, one whose replacement the user declined),
    and from the config's pin when the state does not say. None too when
    neither names a valid image: the caller then uses the latest one,
    and the gate asks before it replaces the VM.
    """
    vms = [
        r for r in live_zonal_resources(resources) if r.type == ENCLAVE_INSTANCE_TYPE
    ]
    if not vms:
        return None
    image = _vm_image(vms[0].outputs)
    if image is not None:
        return image
    try:
        return validate_boot_image(config.get(BOOT_IMAGE_KEY, ""))
    except BootImageError:
        return None
