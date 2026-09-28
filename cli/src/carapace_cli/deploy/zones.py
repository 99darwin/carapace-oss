"""Zone capacity: tell a stockout from other failures, and try another zone.

Google can run out of a machine type in one zone (a "stockout") while the
region's other zones still have it. Only the enclave VM is zonal: the KMS
key, registry, static IP, subnet and Cloud SQL are regional or global, and
the provider's ``gcp:zone`` is used by nothing else (``components/`` sets
the zone on the VM alone, and Cloud SQL picks its own zone in the region).
So while the state holds no VM, the zone can change without touching
anything that exists, and a workloads ``up`` that failed for capacity can
be run again in another zone of the same region. The region never
changes: its resources would all be replaced, and a key ring can never be
deleted.

A VM that is in the state is never moved: an update of a live VM that
fails for capacity (a start after a stop) leaves it in the state and is
reported as it is. What decides is the state after the failed ``up``, not
before it: a replacement deletes the VM first (``delete_before_replace``
in ``components/enclave_vm.py``), so a stockout on its create leaves no
VM, and waiting for a later run to move it would only leave the
deployment without an enclave for longer.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from typing import Any

from carapace_cli.deploy.gcp import GcpApi, GcpError
from carapace_cli.deploy.infra import PulumiError
from carapace_cli.deploy.interview import InvalidInputError
from carapace_cli.deploy.preflight import Target, validate_zone
from carapace_cli.deploy.pulumi_runner import StackHandle, StateResource
from carapace_cli.deploy.record import write_record
from carapace_cli.errors import CarapaceError

# What Compute Engine reports when a zone is out of capacity for a VM, from
# https://cloud.google.com/compute/docs/resource-error. Matched without
# case against pulumi's output. The first also covers
# ZONE_RESOURCE_POOL_EXHAUSTED_WITH_DETAILS.
ZONE_CAPACITY_ERROR_PATTERNS: tuple[str, ...] = (
    "ZONE_RESOURCE_POOL_EXHAUSTED",
    "does not have enough resources available to fulfill the request",
    "is currently unavailable in the",
)
ENCLAVE_INSTANCE_TYPE = "gcp:compute/instance:Instance"
# Every zonal resource type infra/pulumi declares (a test reads components/
# and fails on a resource type it has not classified). The boot disk is
# part of the instance, not a resource of its own.
ZONAL_RESOURCE_TYPES: frozenset[str] = frozenset({ENCLAVE_INSTANCE_TYPE})
ZONE_KEY = "gcp:zone"


class ZoneCapacityError(CarapaceError):
    """No zone of the region could take the enclave VM."""


def is_zone_capacity_error(text: str) -> bool:
    lowered = text.lower()
    return any(pattern.lower() in lowered for pattern in ZONE_CAPACITY_ERROR_PATTERNS)


def zonal_resource_urns(resources: Sequence[StateResource]) -> list[str]:
    """The URNs of the zonal resources in the state."""
    return [r.urn for r in resources if r.type in ZONAL_RESOURCE_TYPES]


def ordered_zones(requested: str, region: str, offered: Sequence[str]) -> list[str]:
    """``requested`` first, then the other valid zones of ``region`` by name."""
    others: set[str] = set()
    for zone in offered:
        try:
            others.add(validate_zone(region, zone))
        except InvalidInputError:
            continue
    others.discard(requested)
    return [requested, *sorted(others)]


@dataclass(frozen=True)
class ZoneFallback:
    """How the workloads step moves the enclave VM to another zone.

    ``offered`` lists the region's zones that are UP and offer
    ``machine_type``; it runs only after a stockout. ``pin`` makes a zone
    the deployment's (stack config and deployment record) before an
    ``up`` tries it, so an ``up`` that fails for another reason leaves
    both naming the zone the VM may now be in.
    """

    machine_type: str
    offered: Callable[[str], list[str]]
    pin: Callable[[Target], None]


def zone_fallback(
    api: GcpApi, stack: StackHandle, *, project: str, machine_type: str
) -> ZoneFallback:
    """The fallback of a real deploy: Compute's zone list, record and config."""

    def offered(region: str) -> list[str]:
        return api.zones_offering(project, region, machine_type)

    def pin(target: Target) -> None:
        stack.set_config({ZONE_KEY: target.zone})
        write_record(api, target)

    return ZoneFallback(machine_type=machine_type, offered=offered, pin=pin)


def _failed_for_capacity(exc: PulumiError, stack: StackHandle) -> bool:
    """A stockout that left no zonal resource in the state."""
    if not is_zone_capacity_error(f"{exc}\n{exc.output}"):
        return False
    return not zonal_resource_urns(stack.resources())


def up_with_zone_fallback(
    stack: StackHandle,
    target: Target,
    *,
    fallback: ZoneFallback | None,
    say: Callable[[str], None],
) -> tuple[dict[str, Any], Target]:
    """``up``, then the region's other zones while it fails for capacity.

    Returns the outputs and the target with the zone that worked. Nothing
    moves when ``fallback`` is None, when the failure is not a stockout,
    or when the state still holds a zonal resource after it (an update
    of a live VM). A VM the state held before the ``up`` and not after
    it was deleted for its replacement; the replacement is then created
    in another zone, and the user is told the VM moved.
    """
    if fallback is None:
        return stack.up(), target
    had_zonal = bool(zonal_resource_urns(stack.resources()))
    try:
        return stack.up(), target
    except PulumiError as exc:
        if not _failed_for_capacity(exc, stack):
            raise
    if had_zonal:
        say(
            f"The enclave VM in {target.zone} was deleted for its replacement, "
            "which the zone has no capacity for now; the replacement moves."
        )
    return _try_other_zones(stack, target, fallback=fallback, say=say)


def _try_other_zones(
    stack: StackHandle,
    requested: Target,
    *,
    fallback: ZoneFallback,
    say: Callable[[str], None],
) -> tuple[dict[str, Any], Target]:
    machine = fallback.machine_type
    try:
        zones = ordered_zones(
            requested.zone, requested.region, fallback.offered(requested.region)
        )
    except GcpError as exc:
        raise ZoneCapacityError(
            f"{requested.zone} has no capacity for {machine} now, and the "
            f"other zones of {requested.region} could not be listed ({exc}). "
            f"Run the same command again later, or pass another --zone of "
            f"{requested.region}"
        ) from None
    tried = [requested.zone]
    note = ""
    for zone in zones[1:]:
        say(f"{tried[-1]} has no capacity for {machine} now; trying {zone}.")
        target = replace(requested, zone=zone)
        fallback.pin(target)
        try:
            return stack.up(), target
        except PulumiError as exc:
            if not _failed_for_capacity(exc, stack):
                raise
        tried.append(zone)
    if len(tried) > 1:
        # Nothing zonal exists, so the requested zone is pinned again and
        # a later run starts there.
        try:
            fallback.pin(requested)
        except CarapaceError as exc:
            note = (
                f" The deployment still names {tried[-1]}; moving it back to "
                f"{requested.zone} failed ({exc})."
            )
    raise ZoneCapacityError(
        f"no zone of {requested.region} has capacity for {machine} now "
        f"(tried {', '.join(tried)}); no VM was created. Run the same command "
        "again later, or deploy in another region with a new --prefix (a "
        f"deployment cannot change region).{note}"
    )
