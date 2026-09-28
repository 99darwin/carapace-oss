"""The Confidential Space boot image: validated, resolved once, and read
back from the state."""

from __future__ import annotations

import pytest
from deploy_support import (
    BOOT_IMAGES,
    ENCLAVE_VM_URN,
    NEW_BOOT_IMAGE,
    OLD_BOOT_IMAGE,
    FakeGoogle,
    FakeStack,
    deployable_project,
    ok,
    vm_outputs,
)

from carapace_cli.deploy.boot_image import (
    BOOT_IMAGE_KEY,
    FAMILY_URL,
    BootImageError,
    latest_boot_image,
    running_boot_image,
    validate_boot_image,
)
from carapace_cli.deploy.pulumi_runner import StateResource

LIVE = {"carapace:deploy_workloads": "true"}
PATH = "projects/confidential-space-images/global/images/"


@pytest.mark.parametrize(
    "image",
    [
        NEW_BOOT_IMAGE,
        f"https://compute.googleapis.com/compute/v1/{PATH}confidential-space-251000",
        f"{PATH}confidential-space-251000",
    ],
)
def test_production_images_are_accepted(image: str) -> None:
    assert validate_boot_image(image) == image


@pytest.mark.parametrize(
    "image",
    [
        "",
        f"{BOOT_IMAGES}confidential-space-debug-251000",
        NEW_BOOT_IMAGE.replace("confidential-space-images", "attacker-project"),
        NEW_BOOT_IMAGE.replace("www.googleapis.com", "evil.example"),
        f"http://www.googleapis.com/compute/v1/{PATH}confidential-space-251000",
        f"{BOOT_IMAGES}family/confidential-space",
        f"{BOOT_IMAGES}../../../other/global/images/x",
        f"{NEW_BOOT_IMAGE}\n",
        f"{BOOT_IMAGES}Confidential-Space",
    ],
)
def test_other_images_are_refused(image: str) -> None:
    with pytest.raises(BootImageError):
        validate_boot_image(image)


def family(body: dict[str, object]) -> FakeGoogle:
    return deployable_project().on("GET", FAMILY_URL, ok(body))


def test_the_latest_image_comes_from_the_family() -> None:
    google = deployable_project()
    assert latest_boot_image(google.api()) == NEW_BOOT_IMAGE
    (lookup,) = [r for r in google.requests if str(r.url).startswith(FAMILY_URL)]
    assert lookup.method == "GET"


@pytest.mark.parametrize(
    "body",
    [
        {"family": "confidential-space-debug", "selfLink": NEW_BOOT_IMAGE},
        {"selfLink": NEW_BOOT_IMAGE},
        {"family": "confidential-space", "selfLink": OLD_BOOT_IMAGE + "-debug"},
        {"family": "confidential-space"},
        {
            "family": "confidential-space",
            "selfLink": NEW_BOOT_IMAGE.replace("confidential-space-images", "x"),
        },
    ],
)
def test_an_unexpected_family_answer_is_refused(body: dict[str, object]) -> None:
    with pytest.raises(BootImageError):
        latest_boot_image(family(body).api())


def vm(image: object, *, pending: bool = False) -> StateResource:
    outputs = vm_outputs(zone="z", image="")
    outputs["bootDisk"]["initializeParams"]["image"] = image
    return StateResource(
        ENCLAVE_VM_URN,
        ENCLAVE_VM_URN.split("::")[2],
        False,
        outputs,
        pending_replacement=pending,
    )


def test_the_running_image_is_the_live_vms() -> None:
    stack = FakeStack(initial=LIVE, boot_image_drift=True)
    pinned = {BOOT_IMAGE_KEY: NEW_BOOT_IMAGE}
    # The state wins over a pin whose replacement never ran.
    assert running_boot_image(stack.resources(), pinned) == OLD_BOOT_IMAGE


def test_the_running_image_falls_back_to_a_valid_pin() -> None:
    pinned = {BOOT_IMAGE_KEY: NEW_BOOT_IMAGE}
    assert running_boot_image([vm(None)], pinned) == NEW_BOOT_IMAGE
    assert running_boot_image([vm("not-an-image")], pinned) == NEW_BOOT_IMAGE
    assert running_boot_image([vm(None)], {BOOT_IMAGE_KEY: "x"}) is None
    assert running_boot_image([vm(None)], {}) is None


def test_no_live_vm_has_no_running_image() -> None:
    pinned = {BOOT_IMAGE_KEY: NEW_BOOT_IMAGE}
    assert running_boot_image([], pinned) is None
    assert running_boot_image([vm(OLD_BOOT_IMAGE, pending=True)], pinned) is None
