"""Fakes for the deploy tests: Google APIs over a mock transport, and input.

Nothing here reaches the network. :class:`FakeGoogle` answers requests by
``(method, url prefix)`` and records every request it saw.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.parse import unquote

import httpx

from carapace_cli.deploy.boot_image import BOOT_IMAGE_KEY, FAMILY_URL
from carapace_cli.deploy.enclave_replace import IMAGE_REFERENCE_PATH, EnclaveReplaceGate
from carapace_cli.deploy.gcp import GcpApi
from carapace_cli.deploy.infra import PulumiError
from carapace_cli.deploy.interview import Interview
from carapace_cli.deploy.polling import Clock
from carapace_cli.deploy.pulumi_runner import PreviewStep, StateResource
from carapace_cli.errors import CarapaceError

PROJECT = "carapace-selfhost"
PROJECT_NUMBER = "123456789012"
FAKE_ACCESS_TOKEN = "fake-access-token"

Handler = Callable[[httpx.Request], httpx.Response]


class StaticTokens:
    quota_project: str | None = None

    def token(self) -> str:
        return FAKE_ACCESS_TOKEN


def ok(body: Any = None, status: int = 200) -> httpx.Response:
    return httpx.Response(status, content=json.dumps(body or {}).encode())


def google_error(status: int, message: str, reason: str = "") -> httpx.Response:
    details = [{"reason": reason}] if reason else []
    return ok({"error": {"message": message, "details": details}}, status)


def disabled(service: str) -> httpx.Response:
    return google_error(403, f"{service} has not been used", "SERVICE_DISABLED")


@dataclass
class FakeGoogle:
    routes: list[tuple[str, str, Handler]] = field(default_factory=list)
    requests: list[httpx.Request] = field(default_factory=list)
    # Objects in the state bucket, by name (see with_state_objects).
    objects: dict[str, Any] = field(default_factory=dict)

    def on(self, method: str, url_prefix: str, response: Handler | httpx.Response):
        handler = response if callable(response) else (lambda _r, _x=response: _x)
        # Later routes win, so a test can override a default.
        self.routes.insert(0, (method, url_prefix, handler))
        return self

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)  # prefixes may include the query string
        for method, prefix, handler in self.routes:
            if request.method == method and url.startswith(prefix):
                return handler(request)
        return google_error(404, f"unexpected {request.method} {url}")

    def api(self) -> GcpApi:
        return GcpApi(StaticTokens(), transport=httpx.MockTransport(self.handle))

    def called(self, method: str, url_prefix: str) -> list[httpx.Request]:
        return [
            r
            for r in self.requests
            if r.method == method and str(r.url).startswith(url_prefix)
        ]


RM = "https://cloudresourcemanager.googleapis.com/v1"
BILLING = "https://cloudbilling.googleapis.com/v1"
KMS = "https://cloudkms.googleapis.com/v1"
COMPUTE = "https://compute.googleapis.com/compute/v1"


def healthy_project(google: FakeGoogle | None = None) -> FakeGoogle:
    """A project where every preflight check passes."""
    google = google or FakeGoogle()

    def grant_all(request: httpx.Request) -> httpx.Response:
        return ok({"permissions": json.loads(request.content)["permissions"]})

    return (
        google.on(
            "GET",
            f"{RM}/projects?",
            ok({"projects": [{"projectId": PROJECT, "name": "Carapace"}]}),
        )
        .on(
            "GET",
            f"{RM}/projects/{PROJECT}",
            ok(
                {
                    "projectId": PROJECT,
                    "projectNumber": PROJECT_NUMBER,
                    "lifecycleState": "ACTIVE",
                }
            ),
        )
        .on(
            "GET",
            f"{BILLING}/projects/{PROJECT}/billingInfo",
            ok({"billingEnabled": True}),
        )
        .on("POST", f"{RM}/projects/{PROJECT}:testIamPermissions", grant_all)
        .on(
            "GET",
            f"{KMS}/projects/{PROJECT}/locations",
            ok(
                {
                    "locations": [
                        {
                            "locationId": "us-central1",
                            "metadata": {"hsmAvailable": True},
                        },
                        {
                            "locationId": "europe-west1",
                            "metadata": {"hsmAvailable": True},
                        },
                        {"locationId": "us-west1", "metadata": {"hsmAvailable": False}},
                    ]
                }
            ),
        )
        .on(
            "GET",
            f"{COMPUTE}/projects/{PROJECT}/zones/",
            ok({"name": "n2d-standard-2"}),
        )
    )


def scripted(*answers: str, interactive: bool = True, yes: bool = False) -> Interview:
    """An interview that reads ``answers`` line by line and writes to a buffer."""
    return Interview(
        interactive=interactive,
        assume_yes=yes,
        stream_in=io.StringIO("".join(f"{a}\n" for a in answers)),
        stream_out=io.StringIO(),
    )


def replace_gate(
    interview: Interview | None = None,
    *,
    allow: bool = False,
    said: list[str] | None = None,
) -> EnclaveReplaceGate:
    """The deploy's enclave replace gate; by default it cannot prompt."""
    return EnclaveReplaceGate(
        interview=interview or scripted(interactive=False),
        allow=allow,
        say=said.append if said is not None else lambda _: None,
    )


def transcript(interview: Interview) -> str:
    out = interview.stream_out
    assert isinstance(out, io.StringIO)
    return out.getvalue()


STORAGE = "https://storage.googleapis.com/storage/v1"
SERVICE_USAGE = "https://serviceusage.googleapis.com/v1"
RUN = "https://run.googleapis.com/v2"
REGION = "us-central1"
PREFIX = "c1x"
KEY_NAME = (
    f"projects/{PROJECT}/locations/{REGION}/keyRings/{PREFIX}-keyring"
    f"/cryptoKeys/{PREFIX}-secrets"
)
KEY_VERSION = f"{KEY_NAME}/cryptoKeyVersions/1"
IAM = "https://iam.googleapis.com/v1"
# What a destroyed deployment of PREFIX leaves behind. The ring's URL is
# a prefix of KEY_NAME's; deployable_project adds the key's routes later,
# and later routes win.
KEY_RING_URL = f"{KMS}/projects/{PROJECT}/locations/{REGION}/keyRings/{PREFIX}-keyring"
POOL_URL = (
    f"{IAM}/projects/{PROJECT}/locations/global/workloadIdentityPools/{PREFIX}-attest"
)
SERVER_URL = "https://c1x-server-123.us-central1.run.app"
ENCLAVE_URL = "https://203.0.113.7:8443"
REGISTRY = f"{REGION}-docker.pkg.dev/{PROJECT}/{PREFIX}"
OLD_DIGEST = "sha256:" + "01" * 32
NEW_DIGEST = "sha256:" + "02" * 32
SERVER_DIGEST = "sha256:" + "03" * 32
BOOT_IMAGES = (
    "https://www.googleapis.com/compute/v1/projects/confidential-space-images"
    "/global/images/"
)
# A VM that booted OLD_BOOT_IMAGE runs behind the family's newest image.
OLD_BOOT_IMAGE = f"{BOOT_IMAGES}confidential-space-250900"
NEW_BOOT_IMAGE = f"{BOOT_IMAGES}confidential-space-251000"


def boot_image_family(*images: str) -> Handler:
    """The family's newest image, one per lookup; the last one repeats."""
    queue = list(images or (NEW_BOOT_IMAGE,))

    def handle(_request: httpx.Request) -> httpx.Response:
        image = queue.pop(0) if len(queue) > 1 else queue[0]
        return ok(
            {
                "name": image.rpartition("/")[2],
                "family": "confidential-space",
                "selfLink": image,
                "status": "READY",
            }
        )

    return handle


def deployable_project(google: FakeGoogle | None = None) -> FakeGoogle:
    """Preflight passes, state APIs are on, the key and migration succeed."""
    google = healthy_project(google)
    location = f"{KMS}/projects/{PROJECT}/locations/{REGION}"
    (
        # The prefix was never used: no key ring, no pool (see leftovers).
        google.on("GET", KEY_RING_URL, google_error(404, "KeyRing not found"))
        .on("GET", POOL_URL, google_error(404, "pool not found"))
        .on(
            "GET",
            f"{SERVICE_USAGE}/projects/{PROJECT}/services/",
            ok({"state": "ENABLED"}),
        )
        .on("GET", f"{STORAGE}/b/", ok(_healthy_bucket()))
        .on(
            "GET",
            f"{location}/keyRings/carapace-state",
            ok({"purpose": "ENCRYPT_DECRYPT"}),
        )
        .on("GET", f"{KMS}/{KEY_VERSION}", ok({"state": "ENABLED"}))
        .on(
            "GET",
            f"{RUN}/projects/{PROJECT}/locations/{REGION}/jobs/",
            ok({"latestCreatedExecution": {"completionStatus": "EXECUTION_SUCCEEDED"}}),
        )
        .on("GET", FAMILY_URL, boot_image_family())
    )
    return with_state_objects(google)


STORAGE_UPLOAD = "https://storage.googleapis.com/upload/storage/v1"


def with_state_objects(google: FakeGoogle) -> FakeGoogle:
    """Objects in the state bucket, kept in ``google.objects``."""
    objects = f"{STORAGE}/b/{PROJECT}-carapace-state/o/"

    def name_of(request: httpx.Request) -> str:
        return unquote(request.url.raw_path.decode().split("/o/", 1)[1].split("?")[0])

    def read(request: httpx.Request) -> httpx.Response:
        name = name_of(request)
        if name not in google.objects:
            return google_error(404, f"No such object: {name}")
        return ok(google.objects[name])

    def write(request: httpx.Request) -> httpx.Response:
        name = request.url.params["name"]
        google.objects[name] = json.loads(request.content)
        return ok({"name": name})

    def delete(request: httpx.Request) -> httpx.Response:
        if google.objects.pop(name_of(request), None) is None:
            return google_error(404, "No such object")
        return ok(None, 204)

    return (
        google.on("GET", objects, read)
        .on("POST", f"{STORAGE_UPLOAD}/b/{PROJECT}-carapace-state/o", write)
        .on("DELETE", objects, delete)
    )


def _healthy_bucket() -> dict[str, Any]:
    return {
        "projectNumber": PROJECT_NUMBER,
        "iamConfiguration": {
            "uniformBucketLevelAccess": {"enabled": True},
            "publicAccessPrevention": "enforced",
        },
        "versioning": {"enabled": True},
    }


def urn(type_: str, name: str) -> str:
    return f"urn:pulumi:{PREFIX}::carapace::{type_}::{name}"


KEY_RING_URN = urn("gcp:kms/keyRing:KeyRing", f"{PREFIX}-keyring")
CRYPTO_KEY_URN = urn("gcp:kms/cryptoKey:CryptoKey", f"{PREFIX}-secrets-key")
DB_INSTANCE_URN = urn("gcp:sql/databaseInstance:DatabaseInstance", f"{PREFIX}-db")
DB_URN = urn("gcp:sql/database:Database", f"{PREFIX}-db-carapace")
DB_USER_URN = urn("gcp:sql/user:User", f"{PREFIX}-db-user")
KMS_URNS = (KEY_RING_URN, CRYPTO_KEY_URN)
DB_URNS = (DB_INSTANCE_URN, DB_URN, DB_USER_URN)
# Resources no deletion protection applies to.
UNPROTECTED_URNS = (
    urn("gcp:projects/service:Service", f"{PREFIX}-api-sqladmin"),
    urn("gcp:serviceaccount/account:Account", f"{PREFIX}-enclave"),
)


def state_resources(
    urns: Sequence[str], *, kms_protected: bool = True, db_protected: bool = True
) -> list[StateResource]:
    """The state entries of ``urns``, protected as the flags say."""
    resources: list[StateResource] = []
    for resource_urn in urns:
        type_ = resource_urn.split("::")[2]
        protected = kms_protected if resource_urn in KMS_URNS else db_protected
        outputs: dict[str, Any] = {"name": resource_urn.split("::")[-1]}
        if resource_urn == DB_INSTANCE_URN:
            outputs |= {
                "deletionProtection": db_protected,
                "settings": {"deletionProtectionEnabled": db_protected},
            }
        resources.append(
            StateResource(
                urn=resource_urn,
                type=type_,
                protect=protected and resource_urn not in UNPROTECTED_URNS,
                outputs=outputs,
            )
        )
    return resources


FULL_STACK_URNS = (*UNPROTECTED_URNS, *KMS_URNS, *DB_URNS)
# The enclave VM, the one zonal resource; in the state once workloads run.
ENCLAVE_VM_URN = urn("gcp:compute/instance:Instance", f"{PREFIX}-enclave")
ROOT_STACK_URN = urn("pulumi:pulumi:Stack", f"carapace-{PREFIX}")
# Verbatim from a real `carapace deploy` in us-central1 (2026-09-28), with
# the zone made a placeholder.
STOCKOUT_MESSAGE = (
    "Error waiting for instance to create: The zone "
    "'projects/throwaway-carapace/zones/{zone}' does not have enough "
    "resources available to fulfill the request. Try a different zone, or "
    "try again later. A n2d-standard-2 VM instance is currently unavailable "
    "in the {zone} zone."
)


def stockout_output(zone: str) -> str:
    """The tail of `pulumi up` output after the VM create hit a stockout."""
    return "\n".join(
        [
            "Diagnostics:",
            f"  gcp:compute:Instance ({PREFIX}-enclave):",
            "    error: 1 error occurred:",
            f"    \t* {STOCKOUT_MESSAGE.format(zone=zone)}",
            "",
            f"  pulumi:pulumi:Stack (carapace-{PREFIX}):",
            "    error: update failed",
            "",
            "Resources:",
            "    41 unchanged",
            "",
            "Duration: 1m3s",
        ]
    )


@dataclass
class FakeStack:
    """A Pulumi stack in memory: local config, backend state, every ``up``.

    ``initial`` is the local config file, and also the state unless
    ``state`` is given (a stack deployed from another machine has state
    but no local config). Outputs come from the state, as
    ``pulumi stack output`` reads them from the backend, and a stack that
    was never ``up`` has none. ``half_created`` is a first ``up`` that
    failed after creating resources: the state tracks them, but exports
    no outputs until an ``up`` finishes.

    The enclave VM in the state carries the boot image it booted. The
    program boots ``carapace:boot_image`` when the config pins one, and
    ``family_image`` (its own family lookup) otherwise.
    """

    initial: dict[str, str] = field(default_factory=dict)
    state: dict[str, str] | None = None
    half_created: bool = False
    # The resources in the state; a live stack has every one of them.
    resources_in_state: list[StateResource] | None = None
    fail_on_up: int | None = None
    # What pulumi printed before the `fail_on_up` failure.
    fail_output: str = ""
    # Zones out of capacity: an `up` that would create the VM there fails.
    stockout_zones: frozenset[str] = frozenset()
    # The zone of each `up` that hit a stockout.
    stockouts: list[str] = field(default_factory=list)
    fail_on_up_targets: bool = False
    fail_on_unprotect: bool = False
    fail_on_remove: bool = False
    # The VM in the state booted OLD_BOOT_IMAGE, older than the newest one.
    boot_image_drift: bool = False
    # What the program's own family lookup returns (no pin in the config).
    family_image: str = NEW_BOOT_IMAGE
    preview_error: CarapaceError | None = None
    # The config each `pulumi preview` ran with.
    previews: list[dict[str, str]] = field(default_factory=list)
    # How many `up`s replaced the VM.
    replacements: int = 0
    ups: list[dict[str, str]] = field(default_factory=list)
    # The URNs of each targeted up, with the config it ran with.
    targeted_ups: list[tuple[list[str], dict[str, str]]] = field(default_factory=list)
    # How many times `pulumi state unprotect --all` ran.
    unprotects: int = 0
    destroyed: bool = False
    removed: bool = False

    def __post_init__(self) -> None:
        self._config = dict(self.initial)
        self._state = dict(self.initial if self.state is None else self.state)
        if self.resources_in_state is not None:
            self._resources = list(self.resources_in_state)
        elif self._state and not self.half_created:
            self._resources = self._program_resources(FULL_STACK_URNS, self._state)
            if self.boot_image_drift:
                self.set_vm(image=OLD_BOOT_IMAGE)
        else:
            self._resources = []

    def _program_resources(
        self, urns: Sequence[str], config: Mapping[str, str] | None = None
    ) -> list[StateResource]:
        """``urns`` as the program declares them with ``config`` (default:
        the current one), plus the enclave VM while workloads run."""
        config = self._config if config is None else config
        resources = state_resources(
            urns,
            kms_protected=config.get("carapace:protect_kms_key") != "false",
            db_protected=config.get("carapace:db_deletion_protection") != "false",
        )
        if config.get("carapace:deploy_workloads") == "true":
            resources.append(
                StateResource(
                    urn=ENCLAVE_VM_URN,
                    type=ENCLAVE_VM_URN.split("::")[2],
                    protect=False,
                    outputs=vm_outputs(
                        zone=config.get("gcp:zone", ""),
                        image=self._program_image(config),
                    ),
                )
            )
        return resources

    def _program_image(self, config: Mapping[str, str]) -> str:
        return config.get(BOOT_IMAGE_KEY) or self.family_image

    def vm(self) -> StateResource | None:
        """The enclave VM's entry in the state, live or pending replacement."""
        return next((r for r in self._resources if r.urn == ENCLAVE_VM_URN), None)

    def set_vm(self, *, image: str | None = None, pending: bool | None = None):
        vm = self.vm()
        assert vm is not None
        outputs = dict(vm.outputs)
        if image is not None:
            outputs = vm_outputs(zone=str(outputs.get("zone", "")), image=image)
        updated = replace(
            vm,
            outputs=outputs,
            pending_replacement=(
                vm.pending_replacement if pending is None else pending
            ),
        )
        self._resources = [
            updated if r.urn == ENCLAVE_VM_URN else r for r in self._resources
        ]

    def _replace_diff(self) -> dict[str, str]:
        """Why the next `up` replaces the live VM, as the provider's
        detailed diff says: a new boot image, or new metadata (the enclave
        digest)."""
        vm = self.vm()
        if vm is None or vm.pending_replacement:
            return {}
        if self._config.get("carapace:deploy_workloads") != "true":
            return {}
        diff: dict[str, str] = {}
        booted = vm.outputs["bootDisk"]["initializeParams"]["image"]
        if booted != self._program_image(self._config):
            diff["bootDisk.initializeParams.image"] = "update-replace"
        if self._state.get("carapace:enclave_image_digest") != self._config.get(
            "carapace:enclave_image_digest"
        ):
            diff[IMAGE_REFERENCE_PATH] = "update-replace"
        return diff

    def _replace_reasons(self) -> list[str]:
        return sorted(
            {path.split(".")[0].split("[")[0] for path in self._replace_diff()}
        )

    def preview(self) -> list[PreviewStep]:
        """`pulumi preview --json`: the root stack and the VM's step."""
        self.previews.append(self.config())
        if self.preview_error is not None:
            raise self.preview_error
        steps = [PreviewStep(op="same", urn=ROOT_STACK_URN, type="pulumi:pulumi:Stack")]
        reasons = self._replace_reasons()
        if reasons:
            steps.append(
                PreviewStep(
                    op="replace",
                    urn=ENCLAVE_VM_URN,
                    type=ENCLAVE_VM_URN.split("::")[2],
                    replace_reasons=tuple(reasons),
                    diff_reasons=tuple(reasons),
                    detailed_diff=self._replace_diff(),
                )
            )
        return steps

    def _hit_stockout(self) -> None:
        """Fail as a VM create in a zone out of capacity does.

        The VM is created when it is missing or pending replacement, and
        replaced (deleted first, as the program's delete_before_replace
        says) when its image or metadata changes. As in Pulumi, a VM
        deleted for a replacement whose create fails stays in the state,
        marked pending replacement, until a later `up` creates it.
        """
        config = self._config
        zone = config.get("gcp:zone", "")
        if config.get("carapace:deploy_workloads") != "true":
            return
        if zone not in self.stockout_zones:
            return
        vm = self.vm()
        live = vm is not None and not vm.pending_replacement
        if live and not self._replace_reasons():
            return
        if vm is not None:
            self.set_vm(pending=True)
        self.stockouts.append(zone)
        raise PulumiError(
            "pulumi up failed: Duration: 1m3s; fix the cause and run the same "
            "command again to resume",
            output=stockout_output(zone),
        )

    def config(self) -> dict[str, str]:
        return dict(self._config)

    def set_config(self, values: Mapping[str, str]) -> None:
        self._config.update(values)

    def up(self) -> dict[str, Any]:
        if self.fail_on_up is not None and len(self.ups) + 1 == self.fail_on_up:
            self.fail_on_up = None
            raise PulumiError("pulumi failed: simulated", output=self.fail_output)
        replaces = bool(self._replace_reasons())
        self._hit_stockout()
        if replaces:
            self.replacements += 1
        self.ups.append(self.config())
        self._state = self.config()
        self._resources = self._program_resources(FULL_STACK_URNS)
        self.half_created = False
        return self.outputs()

    def up_targets(self, urns: Sequence[str]) -> None:
        """Only the targets change; nothing missing from the state is made.

        The program declares FULL_STACK_URNS: a target it does not declare
        would be deleted by the real engine, so the fake refuses it too.
        """
        if self.fail_on_up_targets:
            self.fail_on_up_targets = False
            raise CarapaceError("pulumi up failed: simulated")
        tracked = {resource.urn for resource in self._resources}
        missing = [target for target in urns if target not in tracked]
        assert not missing, f"a targeted up would create {missing}"
        undeclared = [target for target in urns if target not in FULL_STACK_URNS]
        assert not undeclared, f"a targeted up would delete {undeclared}"
        self.targeted_ups.append((list(urns), self.config()))
        declared = {
            resource.urn: resource
            for resource in self._program_resources(FULL_STACK_URNS)
        }
        self._resources = [
            replace(
                resource,
                protect=declared[resource.urn].protect,
                outputs=declared[resource.urn].outputs,
            )
            if resource.urn in urns
            else resource
            for resource in self._resources
        ]

    def unprotect_all(self) -> None:
        """``pulumi state unprotect --all``: a state edit, no program run."""
        if self.fail_on_unprotect:
            self.fail_on_unprotect = False
            raise CarapaceError("pulumi state unprotect failed: simulated")
        self.unprotects += 1
        self._resources = [
            replace(resource, protect=False) for resource in self._resources
        ]

    def resources(self) -> list[StateResource]:
        return list(self._resources)

    def destroy(self) -> None:
        """Refused, like ``pulumi destroy``, while anything is protected."""
        still_protected = [
            resource.urn
            for resource in self._resources
            if resource.protect or resource.outputs.get("deletionProtection") is True
        ]
        if still_protected:
            raise CarapaceError(f"pulumi destroy failed: {still_protected} protected")
        self.destroyed = True
        self._state = {}
        self._resources = []
        self.half_created = False

    def has_resources(self) -> bool:
        return self.half_created or bool(self._state)

    def remove(self) -> None:
        """``pulumi stack rm``: the local config file goes with the stack."""
        if self.fail_on_remove:
            raise CarapaceError("pulumi stack rm failed: simulated")
        self.removed = True
        self._config = {}

    def outputs(self) -> dict[str, Any]:
        if not self._state or self.half_created:
            return {}
        outputs: dict[str, Any] = {
            "kms_key_name": KEY_NAME,
            "kms_key_version_name": KEY_VERSION,
            "image_registry": REGISTRY,
            "enclave_service_account": (
                f"{PREFIX}-enclave@{PROJECT}.iam.gserviceaccount.com"
            ),
            "server_url": SERVER_URL,
            "control_plane_url": SERVER_URL,
        }
        if self._state.get("carapace:deploy_workloads") == "true":
            digest = self._state.get("carapace:enclave_image_digest", "")
            outputs |= {
                "migration_job": f"{PREFIX}-migrate",
                "enclave_url": ENCLAVE_URL,
                # As the program exports it: the reference the VM boots.
                "enclave_image_reference": f"{REGISTRY}/enclave@{digest}",
            }
        return outputs


def vm_outputs(*, zone: str, image: str) -> dict[str, Any]:
    """The enclave VM's outputs as ``stack export`` shows them (in part)."""
    return {"zone": zone, "bootDisk": {"initializeParams": {"image": image}}}


def instant_clock() -> Clock:
    """A clock whose sleeps advance time without waiting."""
    now = [0.0]

    def sleep(seconds: float) -> None:
        now[0] += seconds

    return Clock(sleep=sleep, monotonic=lambda: now[0])
