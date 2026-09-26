"""A new stack refuses a prefix whose key ring or WIF pool is left over.

Google calls go to :class:`FakeGoogle` and the stack is a
:class:`FakeStack`; no ``pulumi`` process runs and nothing reaches the
network.
"""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

import pytest
from deploy_support import (
    KEY_RING_URL,
    KEY_VERSION,
    KMS,
    NEW_DIGEST,
    POOL_URL,
    PREFIX,
    PROJECT,
    PROJECT_NUMBER,
    REGION,
    SERVER_DIGEST,
    FakeGoogle,
    FakeStack,
    deployable_project,
    google_error,
    instant_clock,
    ok,
)
from first_run_support import fake_first_run

from carapace_cli.deploy import command
from carapace_cli.deploy.preflight import (
    KEY_RING_GET_PERMISSION,
    POOL_GET_PERMISSION,
    REQUIRED_PERMISSIONS,
    PreflightError,
    Target,
    attestation_pool_id,
    check_prefix_unused,
    key_ring_id,
)
from carapace_cli.deploy.record import record_name, write_record
from carapace_cli.main import main

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPONENTS = REPO_ROOT / "infra" / "pulumi" / "components"
ZONE = f"{REGION}-a"
TARGET = Target(PROJECT, PROJECT_NUMBER, REGION, ZONE, PREFIX, ("a@b.io",))
KEY_RING = {"name": f"projects/{PROJECT}/locations/{REGION}/keyRings/{PREFIX}-keyring"}
DELETED_POOL = {"name": f"{PREFIX}-attest", "state": "DELETED"}
ACTIVE_POOL = {"name": f"{PREFIX}-attest", "state": "ACTIVE"}
DEPLOY_ARGS = [
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


def run_deploy_cli(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    google: FakeGoogle,
    stack: FakeStack,
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
    code = main(["--config-dir", str(tmp_path), *DEPLOY_ARGS], out=out, err=err)
    return code, err.getvalue()


def with_leftovers(
    *, ring: dict[str, str] | None = None, pool: dict[str, str] | None = None
) -> FakeGoogle:
    """A deployable project where the key ring and/or pool already exist."""
    google = deployable_project()
    if ring is not None:
        google.on("GET", KEY_RING_URL, ok(ring))
    if pool is not None:
        google.on("GET", POOL_URL, ok(pool))
    # The ring's URL prefixes the key's; keep the key's own route in front.
    return google.on("GET", f"{KMS}/{KEY_VERSION}", ok({"state": "ENABLED"}))


def looked_up(google: FakeGoogle) -> bool:
    """Whether the ring or pool itself was read (the key's URL is longer)."""
    return any(str(r.url) in (KEY_RING_URL, POOL_URL) for r in google.requests)


# -- names ----------------------------------------------------------------------


def test_names_match_infra_components() -> None:
    # Read, not imported: infra's package needs pulumi, which is optional.
    kms = (COMPONENTS / "kms.py").read_text()
    wif = (COMPONENTS / "wif.py").read_text()
    assert 'name=f"{prefix}-keyring",' in kms
    assert 'pool_id = f"{prefix}-attest"' in wif
    assert key_ring_id("p1x") == "p1x-keyring"
    assert attestation_pool_id("p1x") == "p1x-attest"
    assert KEY_RING_URL.endswith(f"/keyRings/{key_ring_id(PREFIX)}")
    assert POOL_URL.endswith(f"/workloadIdentityPools/{attestation_pool_id(PREFIX)}")


def test_lookup_permissions_are_in_the_preflight_check() -> None:
    assert KEY_RING_GET_PERMISSION in REQUIRED_PERMISSIONS
    assert POOL_GET_PERMISSION in REQUIRED_PERMISSIONS


# -- check_prefix_unused --------------------------------------------------------


def test_unused_prefix_passes() -> None:
    google = deployable_project()
    check_prefix_unused(google.api(), TARGET)
    assert google.called("GET", KEY_RING_URL)
    assert google.called("GET", POOL_URL)


def test_existing_key_ring_is_refused() -> None:
    google = with_leftovers(ring=KEY_RING)
    with pytest.raises(PreflightError) as caught:
        check_prefix_unused(google.api(), TARGET)
    message = str(caught.value)
    assert f"KMS key ring {PREFIX}-keyring in {REGION} exists" in message
    assert "pool" not in message
    assert "another --prefix" in message


@pytest.mark.parametrize(
    ("pool", "expected"),
    [
        (DELETED_POOL, f"pool {PREFIX}-attest is soft-deleted"),
        (ACTIVE_POOL, f"pool {PREFIX}-attest exists"),
    ],
)
def test_existing_pool_in_any_state_is_refused(
    pool: dict[str, str], expected: str
) -> None:
    google = with_leftovers(pool=pool)
    with pytest.raises(PreflightError, match="another --prefix") as caught:
        check_prefix_unused(google.api(), TARGET)
    assert expected in str(caught.value)
    assert "key ring" not in str(caught.value)


def test_both_leftovers_are_named() -> None:
    google = with_leftovers(ring=KEY_RING, pool=DELETED_POOL)
    with pytest.raises(PreflightError) as caught:
        check_prefix_unused(google.api(), TARGET)
    assert f"{PREFIX}-keyring" in str(caught.value)
    assert f"{PREFIX}-attest is soft-deleted" in str(caught.value)


@pytest.mark.parametrize(
    ("url", "permission"),
    [(KEY_RING_URL, KEY_RING_GET_PERMISSION), (POOL_URL, POOL_GET_PERMISSION)],
)
def test_forbidden_lookup_fails_closed_and_names_the_permission(
    url: str, permission: str
) -> None:
    google = deployable_project().on(
        "GET", url, google_error(403, f"Permission '{permission}' denied")
    )
    with pytest.raises(PreflightError) as caught:
        check_prefix_unused(google.api(), TARGET)
    message = str(caught.value)
    assert "Google API returned 403" in message
    assert f"the deploy needs {permission} on the project" in message
    assert "not deployed without this check" in message


@pytest.mark.parametrize("url", [KEY_RING_URL, POOL_URL])
def test_server_error_fails_closed(url: str) -> None:
    google = deployable_project().on("GET", url, google_error(500, "backend error"))
    with pytest.raises(PreflightError) as caught:
        check_prefix_unused(google.api(), TARGET)
    message = str(caught.value)
    assert "Google API returned 500: backend error" in message
    assert "needs" not in message


# -- cmd_deploy -----------------------------------------------------------------


def test_new_stack_with_leftover_prefix_is_refused_before_any_up(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    google = with_leftovers(pool=DELETED_POOL)
    stack = FakeStack()
    code, err = run_deploy_cli(monkeypatch, tmp_path, google, stack)
    assert code != 0
    assert re.search(rf"pool {PREFIX}-attest is soft-deleted", err)
    assert not stack.ups
    # No record: a later run is still treated as new and checked again.
    assert record_name(PREFIX) not in google.objects


def test_new_stack_with_forbidden_lookup_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    google = deployable_project().on(
        "GET", KEY_RING_URL, google_error(403, "Permission denied")
    )
    stack = FakeStack()
    code, err = run_deploy_cli(monkeypatch, tmp_path, google, stack)
    assert code != 0
    assert KEY_RING_GET_PERMISSION in err
    assert not stack.ups


def test_new_stack_with_free_prefix_deploys(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    google = deployable_project()
    stack = FakeStack()
    code, err = run_deploy_cli(monkeypatch, tmp_path, google, stack)
    assert code == 0, err
    assert google.called("GET", KEY_RING_URL)
    assert google.called("GET", POOL_URL)
    assert len(stack.ups) == 2


def test_new_stack_enables_the_iam_api_before_the_pool_lookup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    services = f"https://serviceusage.googleapis.com/v1/projects/{PROJECT}/services"
    google = (
        deployable_project()
        .on("GET", f"{services}/iam.googleapis.com", ok({"state": "DISABLED"}))
        .on("POST", f"{services}:batchEnable", ok({"name": "operations/op1"}))
        .on(
            "GET",
            "https://serviceusage.googleapis.com/v1/operations/op1",
            ok({"done": True}),
        )
    )
    code, err = run_deploy_cli(monkeypatch, tmp_path, google, FakeStack())
    assert code == 0, err
    enable = google.called("POST", f"{services}:batchEnable")
    assert [json.loads(r.content) for r in enable] == [
        {"serviceIds": ["iam.googleapis.com"]}
    ]
    assert google.requests.index(enable[0]) < google.requests.index(
        google.called("GET", POOL_URL)[0]
    )


def test_existing_deployment_is_not_checked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A live stack owns its key ring and pool; both exist and that is fine.
    google = with_leftovers(ring=KEY_RING, pool=ACTIVE_POOL)
    write_record(google.api(), TARGET)
    stack = FakeStack(
        initial={
            "gcp:project": PROJECT,
            "gcp:region": REGION,
            "gcp:zone": ZONE,
            "carapace:prefix": PREFIX,
            "carapace:deploy_workloads": "true",
            "carapace:enclave_image_digest": NEW_DIGEST,
        }
    )
    code, err = run_deploy_cli(monkeypatch, tmp_path, google, stack)
    assert code == 0, err
    assert not looked_up(google)


def test_live_state_without_a_record_is_not_checked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The backend's outputs, not the record, say the stack exists.
    google = with_leftovers(ring=KEY_RING)
    stack = FakeStack(
        initial={
            "gcp:project": PROJECT,
            "gcp:region": REGION,
            "gcp:zone": ZONE,
            "carapace:prefix": PREFIX,
            "carapace:deploy_workloads": "true",
            "carapace:enclave_image_digest": NEW_DIGEST,
        }
    )
    code, err = run_deploy_cli(monkeypatch, tmp_path, google, stack)
    assert code == 0, err
    assert not looked_up(google)


def test_resume_of_a_failed_first_run_is_not_checked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The first `up` made the key ring and pool, then failed before any
    # outputs: they are this stack's own, and the record says so.
    google = with_leftovers(ring=KEY_RING, pool=ACTIVE_POOL)
    write_record(google.api(), TARGET)
    stack = FakeStack()
    code, err = run_deploy_cli(monkeypatch, tmp_path, google, stack)
    assert code == 0, err
    assert not looked_up(google)
