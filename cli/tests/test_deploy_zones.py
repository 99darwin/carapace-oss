"""Zone capacity: stockout detection, zone fallback, zone and region changes.

Google calls go to :class:`FakeGoogle` and the stack is a
:class:`FakeStack` that fails an ``up`` creating the enclave VM in a zone
out of capacity, with the message a real deploy printed. No ``pulumi``
process runs and nothing reaches the network.
"""

from __future__ import annotations

import io
import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
from deploy_support import (
    COMPUTE,
    ENCLAVE_VM_URN,
    NEW_DIGEST,
    OLD_DIGEST,
    PREFIX,
    PROJECT,
    PROJECT_NUMBER,
    REGION,
    SERVER_DIGEST,
    STOCKOUT_MESSAGE,
    FakeGoogle,
    FakeStack,
    deployable_project,
    google_error,
    instant_clock,
    ok,
    replace_gate,
    scripted,
    stockout_output,
)
from first_run_support import fake_first_run

from carapace_cli.deploy import command
from carapace_cli.deploy.infra import (
    MACHINE_TYPE_CONFIG_KEY,
    PulumiError,
    default_enclave_machine_type,
    enclave_machine_type,
    locate_infra,
)
from carapace_cli.deploy.orchestrate import (
    Deployment,
    Images,
    PrebuiltImages,
    run_deploy,
)
from carapace_cli.deploy.preflight import (
    Flags,
    PreflightError,
    Target,
    run_preflight,
)
from carapace_cli.deploy.record import (
    RecordError,
    check_stack_config,
    read_record,
    record_name,
    write_record,
)
from carapace_cli.deploy.zones import (
    ZONAL_RESOURCE_TYPES,
    ZoneCapacityError,
    ZoneFallback,
    is_zone_capacity_error,
    live_zonal_resource_urns,
    ordered_zones,
    zone_fallback,
)
from carapace_cli.main import main

MACHINE = "n2d-standard-2"
ZONE_A, ZONE_B, ZONE_C = f"{REGION}-a", f"{REGION}-b", f"{REGION}-c"
ZONE_D, ZONE_F = f"{REGION}-d", f"{REGION}-f"
# The zones of the region that are UP and offer MACHINE, in order.
OFFERING = [ZONE_A, ZONE_B, ZONE_F]
TARGET = Target(PROJECT, PROJECT_NUMBER, REGION, ZONE_A, PREFIX, ("a@b.io",))
IMAGES = Images(enclave_digest=NEW_DIGEST, server_digest=SERVER_DIGEST)
ZONES_URL = f"{COMPUTE}/projects/{PROJECT}/zones"


def zone_item(name: str, status: str = "UP", region: str = REGION) -> dict[str, str]:
    return {
        "name": name,
        "status": status,
        "region": f"{COMPUTE}/projects/{PROJECT}/regions/{region}",
    }


# Out of order and over two pages: c does not offer MACHINE, d is DOWN,
# us-east1-b is in another region, and the last name is not a zone.
ZONE_PAGES = [
    [zone_item(ZONE_F), zone_item(ZONE_C), zone_item(ZONE_D, status="DOWN")],
    [
        zone_item(ZONE_B),
        zone_item("us-east1-b", region="us-east1"),
        zone_item(ZONE_A),
        zone_item("../../x"),
    ],
]
OFFERED_BY = {ZONE_A, ZONE_B, ZONE_D, ZONE_F, "us-east1-b"}


def with_zones(google: FakeGoogle) -> FakeGoogle:
    """Compute's zone list and machine types, as ZONE_PAGES describe them."""

    def handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/machineTypes/" in path:
            zone = path.split("/zones/", 1)[1].split("/", 1)[0]
            if zone in OFFERED_BY and path.endswith(f"/machineTypes/{MACHINE}"):
                return ok({"name": MACHINE})
            return google_error(404, "machine type not found")
        if request.url.params.get("pageToken") == "two":
            return ok({"items": ZONE_PAGES[1]})
        return ok({"items": ZONE_PAGES[0], "nextPageToken": "two"})

    return google.on("GET", ZONES_URL, handle)


def zone_listings(google: FakeGoogle) -> list[httpx.Request]:
    return [r for r in google.requests if r.url.path.endswith("/zones")]


def deploy(
    google: FakeGoogle,
    stack: FakeStack,
    said: list[str] | None = None,
    *,
    fallback: bool = True,
) -> Deployment:
    api = google.api()
    lines = said if said is not None else []
    return run_deploy(
        TARGET,
        api=api,
        stack=stack,
        images=PrebuiltImages(images=IMAGES),
        clock=instant_clock(),
        say=lines.append,
        replace_gate=replace_gate(),
        zone_fallback=(
            zone_fallback(api, stack, project=PROJECT, machine_type=MACHINE)
            if fallback
            else None
        ),
    )


def recorded_zone(google: FakeGoogle) -> str:
    return str(google.objects[record_name(PREFIX)]["zone"])


# -- telling a stockout from other failures -----------------------------------


def test_the_real_stockout_message_is_a_capacity_error() -> None:
    assert is_zone_capacity_error(STOCKOUT_MESSAGE.format(zone=ZONE_A))
    assert is_zone_capacity_error(stockout_output(ZONE_A))
    for text in (
        "ZONE_RESOURCE_POOL_EXHAUSTED_WITH_DETAILS: no n2d-standard-2 left",
        "code: zone_resource_pool_exhausted",
        f"A n2d-standard-2 VM instance is currently unavailable in the {ZONE_B} "
        "zone, because of insufficient capacity",
    ):
        assert is_zone_capacity_error(text), text


def test_other_failures_are_not_capacity_errors() -> None:
    for text in (
        "Quota 'N2D_CPUS' exceeded. Limit: 0.0 in region us-central1.",
        "error: quota exceeded",
        "Required 'compute.instances.create' permission for 'projects/p'",
        "The resource 'projects/p/zones/us-central1-a' is not ready",
        "",
    ):
        assert not is_zone_capacity_error(text), text


def test_ordered_zones_start_with_the_requested_one() -> None:
    offered = [ZONE_F, ZONE_A, "us-east1-b", "bogus", ZONE_B]
    assert ordered_zones(ZONE_B, REGION, offered) == [ZONE_B, ZONE_A, ZONE_F]
    assert ordered_zones(ZONE_A, REGION, []) == [ZONE_A]


def test_zonal_resources_are_the_enclave_vm_only() -> None:
    stack = FakeStack(initial={"carapace:deploy_workloads": "true", "gcp:zone": ZONE_A})
    assert live_zonal_resource_urns(stack.resources()) == [ENCLAVE_VM_URN]
    bootstrapped = FakeStack(initial={"gcp:zone": ZONE_A})
    assert live_zonal_resource_urns(bootstrapped.resources()) == []


RESOURCE_CALL = re.compile(r"\bgcp\.([a-z0-9_]+)\.([A-Z]\w*)\(")
ZONAL_CLASSES = {"compute.Instance"}
# Regional or global. Cloud SQL runs in a zone Google picks in the region;
# nothing in the program names it, so gcp:zone never reaches it.
NON_ZONAL_CLASSES = {
    "artifactregistry.Repository",
    "artifactregistry.RepositoryIamMember",
    "cloudrunv2.Job",
    "cloudrunv2.Service",
    "compute.Address",
    "compute.Firewall",
    "compute.Network",
    "compute.Subnetwork",
    "iam.WorkloadIdentityPool",
    "iam.WorkloadIdentityPoolProvider",
    "kms.CryptoKey",
    "kms.CryptoKeyIAMPolicy",
    "kms.KeyRing",
    "kms.KeyRingIAMPolicy",
    "monitoring.AlertPolicy",
    "monitoring.NotificationChannel",
    "projects.IAMAuditConfig",
    "projects.IAMMember",
    "projects.Service",
    "secretmanager.Secret",
    "secretmanager.SecretIamMember",
    "secretmanager.SecretVersion",
    "serviceaccount.Account",
    "sql.Database",
    "sql.DatabaseInstance",
    "sql.User",
}


def test_every_resource_the_program_declares_is_classified() -> None:
    infra = locate_infra()
    sources = [infra / "__main__.py", *sorted((infra / "components").glob("*.py"))]
    declared = {
        f"{module}.{cls}"
        for source in sources
        for module, cls in RESOURCE_CALL.findall(source.read_text(encoding="utf-8"))
    }
    unclassified = declared - ZONAL_CLASSES - NON_ZONAL_CLASSES
    assert not unclassified, f"say whether these are zonal: {sorted(unclassified)}"
    assert "compute.Instance" in declared
    tokens = {
        f"gcp:{module}/{cls[0].lower()}{cls[1:]}:{cls}"
        for module, cls in (name.split(".") for name in ZONAL_CLASSES)
    }
    assert tokens == ZONAL_RESOURCE_TYPES


# -- the machine type comes from the program ----------------------------------


def test_machine_type_comes_from_the_program() -> None:
    assert default_enclave_machine_type() == MACHINE
    assert enclave_machine_type({}) == MACHINE
    assert enclave_machine_type({MACHINE_TYPE_CONFIG_KEY: "c3d-standard-4"}) == (
        "c3d-standard-4"
    )
    for bad in ("../zones/x", "N2D", "n2d standard"):
        with pytest.raises(PulumiError, match="not a Compute machine type"):
            enclave_machine_type({MACHINE_TYPE_CONFIG_KEY: bad})


def test_a_program_without_the_constant_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "components").mkdir()
    (tmp_path / "components" / "config.py").write_text("OTHER = 'x'\n")
    with pytest.raises(PulumiError, match="DEFAULT_ENCLAVE_MACHINE_TYPE"):
        default_enclave_machine_type(tmp_path)


# -- listing the zones --------------------------------------------------------


def test_zone_listing_keeps_up_zones_of_the_region_that_offer_the_type() -> None:
    google = with_zones(FakeGoogle())
    assert google.api().zones_offering(PROJECT, REGION, MACHINE) == OFFERING
    assert google.api().zones_offering(PROJECT, "us-east1", MACHINE) == ["us-east1-b"]
    assert google.api().zones_offering(PROJECT, REGION, "c3d-standard-4") == []


# -- falling back --------------------------------------------------------------


def test_stockout_falls_back_to_the_next_zone_and_pins_it() -> None:
    google = with_zones(deployable_project())
    stack = FakeStack(stockout_zones=frozenset({ZONE_A}))
    said: list[str] = []
    deployment = deploy(google, stack, said)
    assert stack.stockouts == [ZONE_A]
    assert deployment.target.zone == ZONE_B
    assert stack.config()["gcp:zone"] == ZONE_B
    assert stack.ups[-1]["gcp:zone"] == ZONE_B
    assert recorded_zone(google) == ZONE_B
    assert f"{ZONE_A} has no capacity for {MACHINE} now; trying {ZONE_B}." in said
    assert deployment.outputs["enclave_url"].startswith("https://")


def test_fallback_goes_through_the_zones_in_order() -> None:
    google = with_zones(deployable_project())
    stack = FakeStack(stockout_zones=frozenset({ZONE_A, ZONE_B}))
    said: list[str] = []
    deployment = deploy(google, stack, said)
    assert stack.stockouts == [ZONE_A, ZONE_B]
    assert deployment.target.zone == ZONE_F
    assert [line for line in said if "no capacity" in line] == [
        f"{ZONE_A} has no capacity for {MACHINE} now; trying {ZONE_B}.",
        f"{ZONE_B} has no capacity for {MACHINE} now; trying {ZONE_F}.",
    ]
    assert recorded_zone(google) == ZONE_F


def test_all_zones_out_of_capacity_is_a_clear_error() -> None:
    google = with_zones(deployable_project())
    stack = FakeStack(stockout_zones=frozenset(OFFERING))
    with pytest.raises(ZoneCapacityError) as caught:
        deploy(google, stack)
    message = str(caught.value)
    assert f"tried {ZONE_A}, {ZONE_B}, {ZONE_F}" in message
    assert "no VM was created" in message
    assert "--prefix" in message and "later" in message
    assert stack.stockouts == OFFERING
    # Back to the zone asked for, so a later run starts there.
    assert stack.config()["gcp:zone"] == ZONE_A
    assert recorded_zone(google) == ZONE_A
    assert not live_zonal_resource_urns(stack.resources())


def test_a_region_with_one_zone_offering_it_fails_without_moving() -> None:
    google = with_zones(deployable_project())
    stack = FakeStack(stockout_zones=frozenset({ZONE_A}))
    fallback_api = google.api()
    with pytest.raises(ZoneCapacityError, match=f"tried {ZONE_A}\\)"):
        run_deploy(
            TARGET,
            api=google.api(),
            stack=stack,
            images=PrebuiltImages(images=IMAGES),
            clock=instant_clock(),
            say=lambda _: None,
            replace_gate=replace_gate(),
            zone_fallback=zone_fallback(
                fallback_api, stack, project=PROJECT, machine_type="c3d-standard-4"
            ),
        )
    assert stack.config()["gcp:zone"] == ZONE_A
    assert record_name(PREFIX) not in google.objects


def test_unlistable_zones_end_the_fallback_with_a_clear_error() -> None:
    google = deployable_project().on(
        "GET", ZONES_URL, google_error(403, "compute.zones.list denied")
    )
    stack = FakeStack(stockout_zones=frozenset({ZONE_A}))
    with pytest.raises(ZoneCapacityError, match="could not be listed"):
        deploy(google, stack)
    assert stack.config()["gcp:zone"] == ZONE_A


def test_a_failure_that_is_not_capacity_never_falls_back() -> None:
    google = with_zones(deployable_project())
    # The second up is the workloads step.
    stack = FakeStack(fail_on_up=2, fail_output="error: Quota 'N2D_CPUS' exceeded")
    with pytest.raises(PulumiError, match="simulated"):
        deploy(google, stack)
    assert zone_listings(google) == []
    assert stack.config()["gcp:zone"] == ZONE_A


def test_no_zone_fallback_reports_the_stockout_as_it_is() -> None:
    google = with_zones(deployable_project())
    stack = FakeStack(stockout_zones=frozenset({ZONE_A}))
    with pytest.raises(PulumiError) as caught:
        deploy(google, stack, fallback=False)
    assert is_zone_capacity_error(caught.value.output)
    assert zone_listings(google) == []
    assert stack.stockouts == [ZONE_A]
    assert stack.config()["gcp:zone"] == ZONE_A


LIVE_CONFIG = {
    "gcp:project": PROJECT,
    "gcp:region": REGION,
    "gcp:zone": ZONE_A,
    "carapace:prefix": PREFIX,
    "carapace:deploy_workloads": "true",
    "carapace:enclave_image_digest": OLD_DIGEST,
    "carapace:allowed_digests": json.dumps([OLD_DIGEST]),
}


def vm_zones(stack: FakeStack) -> list[str]:
    return [
        str(r.outputs["zone"]) for r in stack.resources() if r.urn == ENCLAVE_VM_URN
    ]


def test_a_replaced_vm_whose_create_hit_a_stockout_moves_in_the_same_run() -> None:
    """A new image replaces the VM, delete first. A stockout on the create
    leaves the deleted VM in the state, pending replacement, so the
    replacement goes to another zone in the same run: waiting for a later
    run would only leave the deployment without an enclave for longer."""
    google = with_zones(deployable_project())
    stack = FakeStack(initial=LIVE_CONFIG, stockout_zones=frozenset({ZONE_A}))
    assert vm_zones(stack) == [ZONE_A]
    said: list[str] = []
    deployment = deploy(google, stack, said)
    assert stack.stockouts == [ZONE_A]
    assert deployment.target.zone == ZONE_B
    assert vm_zones(stack) == [ZONE_B]
    assert stack.config()["gcp:zone"] == ZONE_B
    assert recorded_zone(google) == ZONE_B
    # Step 1 kept the old VM in place; step 2's replacement and step 3
    # ran in the new zone.
    assert [up["gcp:zone"] for up in stack.ups] == [ZONE_A, ZONE_B, ZONE_B]
    assert (
        f"The enclave VM in {ZONE_A} was deleted for its replacement, which the "
        "zone has no capacity for now; the replacement moves."
    ) in said
    assert f"{ZONE_A} has no capacity for {MACHINE} now; trying {ZONE_B}." in said


def test_a_rerun_over_a_vm_pending_replacement_moves_it() -> None:
    """A run without the fallback left the VM pending replacement. The
    rerun creates it, without a preview, and may move it: nothing
    is left in the old zone."""
    google = with_zones(deployable_project())
    live = LIVE_CONFIG | {
        "carapace:enclave_image_digest": NEW_DIGEST,
        "carapace:allowed_digests": json.dumps([NEW_DIGEST]),
    }
    stack = FakeStack(
        initial=live, boot_image_drift=True, stockout_zones=frozenset({ZONE_A})
    )
    with pytest.raises(PulumiError, match="run the same command again"):
        run_deploy(
            TARGET,
            api=google.api(),
            stack=stack,
            images=PrebuiltImages(images=IMAGES),
            clock=instant_clock(),
            say=lambda _: None,
            replace_gate=replace_gate(allow=True),
        )
    vm = stack.vm()
    assert vm is not None and vm.pending_replacement
    assert live_zonal_resource_urns(stack.resources()) == []
    previews = len(stack.previews)

    deployment = deploy(google, stack)
    assert len(stack.previews) == previews
    assert stack.stockouts == [ZONE_A, ZONE_A]
    assert deployment.target.zone == ZONE_B
    assert vm_zones(stack) == [ZONE_B]
    vm = stack.vm()
    assert vm is not None and not vm.pending_replacement
    assert recorded_zone(google) == ZONE_B


def test_a_vm_still_in_the_state_after_a_stockout_never_moves() -> None:
    """An update of a live VM can hit a stockout too (a start after a
    stop) and leaves the VM in the state: nothing moves, whatever pulumi
    printed. The state after the failure decides, not the message."""
    google = with_zones(deployable_project())
    live = LIVE_CONFIG | {
        "carapace:enclave_image_digest": NEW_DIGEST,
        "carapace:allowed_digests": json.dumps([NEW_DIGEST]),
    }
    stack = FakeStack(initial=live, fail_on_up=1, fail_output=stockout_output(ZONE_A))
    with pytest.raises(PulumiError, match="simulated") as caught:
        deploy(google, stack)
    assert is_zone_capacity_error(caught.value.output)
    assert vm_zones(stack) == [ZONE_A]
    assert zone_listings(google) == []
    assert stack.config()["gcp:zone"] == ZONE_A
    assert record_name(PREFIX) not in google.objects


def test_a_failed_restore_of_the_requested_zone_is_reported() -> None:
    """When every zone fails and the requested zone cannot be pinned again,
    the error says which zone the deployment still names."""
    google = with_zones(deployable_project())
    stack = FakeStack(stockout_zones=frozenset(OFFERING))
    api = google.api()
    real = zone_fallback(api, stack, project=PROJECT, machine_type=MACHINE)
    pinned: list[str] = []

    def pin(target: Target) -> None:
        pinned.append(target.zone)
        if target.zone == ZONE_A:
            raise RecordError("the state bucket is gone")
        real.pin(target)

    with pytest.raises(ZoneCapacityError) as caught:
        run_deploy(
            TARGET,
            api=api,
            stack=stack,
            images=PrebuiltImages(images=IMAGES),
            clock=instant_clock(),
            say=lambda _: None,
            replace_gate=replace_gate(),
            zone_fallback=ZoneFallback(
                machine_type=MACHINE, offered=real.offered, pin=pin
            ),
        )
    assert pinned == [ZONE_B, ZONE_F, ZONE_A]
    message = str(caught.value)
    assert f"tried {ZONE_A}, {ZONE_B}, {ZONE_F}" in message
    assert f"still names {ZONE_F}" in message
    assert "the state bucket is gone" in message
    assert stack.config()["gcp:zone"] == ZONE_F
    assert recorded_zone(google) == ZONE_F


def test_pulumi_output_stays_out_of_the_error_text() -> None:
    """The output is only for classifying the failure; what the user and
    any log see of the error is its message."""
    exc = PulumiError(
        "pulumi up failed: Duration: 1m3s", output=stockout_output(ZONE_A)
    )
    shown = f"{exc} {exc!r} {exc.args}"
    assert "Diagnostics" not in shown
    assert "resources available" not in shown
    assert is_zone_capacity_error(exc.output)


def test_an_unchanged_vm_is_left_where_it_is() -> None:
    google = with_zones(deployable_project())
    live = LIVE_CONFIG | {
        "carapace:enclave_image_digest": NEW_DIGEST,
        "carapace:allowed_digests": json.dumps([NEW_DIGEST]),
    }
    stack = FakeStack(initial=live, stockout_zones=frozenset({ZONE_A}))
    deployment = deploy(google, stack)
    assert deployment.target.zone == ZONE_A
    assert stack.stockouts == []


# -- zone and region changes ----------------------------------------------------

STACK_CONFIG = {
    "gcp:project": PROJECT,
    "gcp:region": REGION,
    "gcp:zone": ZONE_A,
    "carapace:prefix": PREFIX,
}
TARGET_B = Target(PROJECT, PROJECT_NUMBER, REGION, ZONE_B, PREFIX, ("a@b.io",))


def test_zone_change_is_allowed_without_zonal_resources() -> None:
    check_stack_config(
        STACK_CONFIG, TARGET_B, is_existing=True, zonal_resources=lambda: []
    )


def test_zone_change_is_refused_with_the_vm_in_the_state() -> None:
    with pytest.raises(RecordError, match=f"zonal resources there \\({PREFIX}-enclave"):
        check_stack_config(
            STACK_CONFIG,
            TARGET_B,
            is_existing=True,
            zonal_resources=lambda: [ENCLAVE_VM_URN],
        )


def test_zone_change_is_allowed_with_only_a_vm_pending_replacement() -> None:
    pending = FakeStack(initial=LIVE_CONFIG)
    pending.set_vm(pending=True)
    assert live_zonal_resource_urns(pending.resources()) == []
    check_stack_config(
        STACK_CONFIG,
        TARGET_B,
        is_existing=True,
        zonal_resources=lambda: live_zonal_resource_urns(pending.resources()),
    )


def test_zone_change_is_refused_when_the_state_is_not_checked() -> None:
    with pytest.raises(RecordError, match="could not be checked"):
        check_stack_config(STACK_CONFIG, TARGET_B, is_existing=True)


def test_region_change_is_always_refused() -> None:
    elsewhere = Target(
        PROJECT, PROJECT_NUMBER, "europe-west1", "europe-west1-b", PREFIX, ()
    )
    with pytest.raises(RecordError, match="cannot move to another region"):
        check_stack_config(
            STACK_CONFIG, elsewhere, is_existing=True, zonal_resources=lambda: []
        )


def preflight(google: FakeGoogle, flags: Flags) -> tuple[Target, Any]:
    api = google.api()
    return run_preflight(
        api,
        scripted(interactive=False),
        flags,
        find_existing=lambda project, prefix: read_record(api, project, prefix),
    )


def test_preflight_lets_a_rerun_pick_another_zone_of_its_region() -> None:
    google = with_zones(deployable_project())
    write_record(google.api(), TARGET)
    target, _ = preflight(google, Flags(project=PROJECT, prefix=PREFIX, zone=ZONE_B))
    assert (target.region, target.zone) == (REGION, ZONE_B)


def test_preflight_refuses_another_region_for_a_rerun() -> None:
    google = with_zones(deployable_project())
    write_record(google.api(), TARGET)
    flags = Flags(project=PROJECT, prefix=PREFIX, region="europe-west1")
    with pytest.raises(PreflightError, match="cannot move to another region"):
        preflight(google, flags)


def test_preflight_lists_zones_that_offer_the_machine_type() -> None:
    google = with_zones(deployable_project())
    flags = Flags(project=PROJECT, prefix=PREFIX, zone=ZONE_C, alert_emails=("a@b.io",))
    with pytest.raises(PreflightError) as caught:
        preflight(google, flags)
    assert str(caught.value) == (
        f"{MACHINE} is not offered in {ZONE_C}; zones of {REGION} that offer it: "
        f"{', '.join(OFFERING)}"
    )


# -- the command ----------------------------------------------------------------

DEPLOY = [
    "deploy",
    "--project",
    PROJECT,
    "--prefix",
    PREFIX,
    "--alert-email",
    "a@b.io",
    "--enclave-digest",
    NEW_DIGEST,
    "--server-digest",
    SERVER_DIGEST,
    "--password-stdin",
    "--no-passphrase",
    "--yes",
]


def run_cli(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    google: FakeGoogle,
    stack: FakeStack,
    *argv: str,
) -> tuple[int, str]:
    monkeypatch.setattr(
        command,
        "default_services",
        lambda: command.Services(
            gcp=google.api,
            stack=lambda target, backend, ctx: stack,
            clock=instant_clock(),
            first_run=fake_first_run(),
        ),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    out, err = io.StringIO(), io.StringIO()
    code = main(["--config-dir", str(tmp_path), *argv], out=out, err=err)
    return code, err.getvalue()


def test_deploy_falls_back_and_later_runs_stay_in_the_new_zone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    google = with_zones(deployable_project())
    stack = FakeStack(stockout_zones=frozenset({ZONE_A}))
    code, output = run_cli(monkeypatch, tmp_path, google, stack, *DEPLOY)
    assert code == 0, output
    assert f"{ZONE_A} has no capacity for {MACHINE} now; trying {ZONE_B}." in output
    assert f"zone: {ZONE_B} ({ZONE_A} had no capacity); later runs use it" in output
    assert recorded_zone(google) == ZONE_B
    assert stack.config()["gcp:zone"] == ZONE_B

    code, output = run_cli(monkeypatch, tmp_path, google, stack, *DEPLOY)
    assert code == 0, output
    assert "no capacity" not in output
    assert stack.stockouts == [ZONE_A]
    assert stack.ups[-1]["gcp:zone"] == ZONE_B


def test_deploy_honours_no_zone_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    google = with_zones(deployable_project())
    stack = FakeStack(stockout_zones=frozenset({ZONE_A}))
    code, output = run_cli(
        monkeypatch, tmp_path, google, stack, *DEPLOY, "--no-zone-fallback"
    )
    assert code != 0
    assert "pulumi up failed" in output
    assert "trying" not in output
    assert zone_listings(google) == []
    assert stack.stockouts == [ZONE_A]
    assert stack.config()["gcp:zone"] == ZONE_A
    assert recorded_zone(google) == ZONE_A
