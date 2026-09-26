"""The deploy's first run: owner key, account, verify and pin, against fakes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from deploy_support import (
    ENCLAVE_URL,
    KEY_NAME,
    KEY_VERSION,
    NEW_DIGEST,
    PROJECT,
    SERVER_URL,
    FakeStack,
    instant_clock,
    scripted,
)
from first_run_support import PASSWORD, FakeControlPlane, FakeEnclave, fake_first_run

from carapace_cli.deploy.first_run import (
    AccountFlags,
    DeploymentIdentity,
    FirstRunError,
    FirstRunServices,
    PreparedAccount,
    complete_first_run,
    prepare_account,
)
from carapace_cli.deploy.interview import Interview, MissingInputError
from carapace_cli.deploy.polling import PollTimeoutError
from carapace_cli.errors import VerificationError
from carapace_cli.files import read_private_json
from carapace_cli.ownerkey_store import (
    is_passphrase_protected,
    owner_key_path,
    save_owner_key,
)
from carapace_cli.pin import pin_path
from carapace_cli.session import Session, save_session, session_path
from carapace_crypto import OwnerKey

EMAIL = "owner@example.com"
SCRIPT_FLAGS = AccountFlags(email=None, password_stdin=True, no_passphrase=True)
NO_FLAGS = AccountFlags(email=None, password_stdin=False, no_passphrase=False)
PASSPHRASE = "a long passphrase"


def outputs() -> dict[str, Any]:
    stack = FakeStack(initial={"carapace:deploy_workloads": "true"})
    return stack.outputs()


def prepare(
    config_dir: Path,
    services: FirstRunServices,
    flags: AccountFlags = SCRIPT_FLAGS,
    interview: Interview | None = None,
) -> PreparedAccount:
    return prepare_account(
        config_dir,
        flags,
        interview or Interview(interactive=False),
        services,
        default_email=EMAIL,
    )


def finish(
    account: PreparedAccount,
    services: FirstRunServices,
    lines: list[str] | None = None,
) -> None:
    complete_first_run(
        account,
        project=PROJECT,
        outputs=outputs(),
        enclave_digest=NEW_DIGEST,
        services=services,
        clock=instant_clock(),
        say=(lines if lines is not None else []).append,
    )


def run(config_dir: Path, services: FirstRunServices) -> None:
    finish(prepare(config_dir, services), services)


def test_first_run_creates_key_account_session_and_pin(tmp_path: Path) -> None:
    server, enclave = FakeControlPlane(), FakeEnclave()
    run(tmp_path, fake_first_run(server, enclave))
    assert server.users == {EMAIL: PASSWORD}
    assert len(server.owner_keys) == 1
    key_file = read_private_json(owner_key_path(tmp_path))
    assert server.owner_keys[0]["public_key"] == key_file["public_key"]
    assert read_private_json(session_path(tmp_path))["server_url"] == SERVER_URL
    pin = read_private_json(pin_path(tmp_path))
    assert pin["enclave_url"] == ENCLAVE_URL
    assert pin["kms_key_version"] == KEY_VERSION
    # verify trusted exactly the digest this deploy published.
    assert enclave.policies[0].allowed_digests == frozenset({NEW_DIGEST})


def test_first_run_pins_the_deployment_identity(tmp_path: Path) -> None:
    enclave = FakeEnclave()
    run(tmp_path, fake_first_run(enclave=enclave))
    policy = enclave.policies[0]
    stack = outputs()
    assert policy.project_id == PROJECT
    assert policy.service_account == stack["enclave_service_account"]
    assert policy.control_plane_url == SERVER_URL
    # The enclave's KMS_KEY_NAME is the key version, not the crypto key.
    assert policy.kms_key_name == KEY_VERSION
    pin = read_private_json(pin_path(tmp_path))
    assert pin["project_id"] == PROJECT
    assert pin["kms_key_name"] == KEY_VERSION


def test_rerun_reuses_the_session_and_asks_nothing(tmp_path: Path) -> None:
    server = FakeControlPlane()
    services = fake_first_run(server)
    run(tmp_path, services)
    account = prepare(tmp_path, services, flags=NO_FLAGS)
    assert account.email is None and account.password is None
    finish(account, services)
    assert server.calls("/v1/auth/register") == 1
    posts = [r for r in server.requests if r.method == "POST"]
    assert sum(1 for r in posts if r.url.path == "/v1/owner-keys") == 1


def test_existing_account_logs_in(tmp_path: Path) -> None:
    server = FakeControlPlane(users={EMAIL: PASSWORD})
    lines: list[str] = []
    services = fake_first_run(server)
    finish(prepare(tmp_path, services), services, lines)
    assert f"Logged in as {EMAIL}." in lines
    assert session_path(tmp_path).exists()


def test_wrong_password_for_an_existing_account(tmp_path: Path) -> None:
    server = FakeControlPlane(users={EMAIL: "Another-Password-1"})
    services = fake_first_run(server)
    with pytest.raises(FirstRunError, match="already has an account"):
        run(tmp_path, services)
    assert not session_path(tmp_path).exists()
    assert not pin_path(tmp_path).exists()


def test_waits_for_the_server_and_the_enclave(tmp_path: Path) -> None:
    server, enclave = FakeControlPlane(unavailable=3), FakeEnclave(booting=4)
    lines: list[str] = []
    services = fake_first_run(server, enclave)
    finish(prepare(tmp_path, services), services, lines)
    assert pin_path(tmp_path).exists()
    assert any("the enclave is not ready yet" in line for line in lines)


def test_an_enclave_that_never_attests_times_out(tmp_path: Path) -> None:
    services = fake_first_run(enclave=FakeEnclave(booting=1000))
    with pytest.raises(PollTimeoutError, match="run the same command again"):
        run(tmp_path, services)
    assert not pin_path(tmp_path).exists()


def test_another_kms_key_version_is_never_pinned(tmp_path: Path) -> None:
    enclave = FakeEnclave(kms_key_version=f"{KEY_NAME}/cryptoKeyVersions/2")
    with pytest.raises(VerificationError, match="not the one this deploy created"):
        run(tmp_path, fake_first_run(enclave=enclave))
    assert not pin_path(tmp_path).exists()


def test_another_deployments_config_is_not_replaced(tmp_path: Path) -> None:
    other = Session("https://other.example", "u", "a", "r")
    save_session(tmp_path, other)
    server = FakeControlPlane()
    services = fake_first_run(server)
    with pytest.raises(FirstRunError, match="use another --config-dir"):
        run(tmp_path, services)
    assert not server.requests
    assert read_private_json(session_path(tmp_path))["server_url"] == other.server_url


def test_scripts_must_pass_the_secret_flags(tmp_path: Path) -> None:
    services = fake_first_run()
    with pytest.raises(MissingInputError, match="--no-passphrase"):
        prepare(tmp_path, services, flags=NO_FLAGS)
    save_owner_key(owner_key_path(tmp_path), OwnerKey.generate())
    with pytest.raises(MissingInputError, match="--password-stdin is required"):
        prepare(tmp_path, services, flags=NO_FLAGS)


def test_interactive_first_run_prompts_for_secrets(tmp_path: Path) -> None:
    answers = {
        "New owner key passphrase: ": PASSPHRASE,
        "Account password (new, or the existing one): ": PASSWORD,
    }
    server = FakeControlPlane()
    services = fake_first_run(server, answers=answers)
    interview = scripted("me@example.com", interactive=True)
    finish(prepare(tmp_path, services, flags=NO_FLAGS, interview=interview), services)
    assert server.users == {"me@example.com": PASSWORD}
    assert is_passphrase_protected(owner_key_path(tmp_path))


def test_protected_key_is_unlocked_before_the_deploy(tmp_path: Path) -> None:
    owner_key = OwnerKey.generate()
    save_owner_key(owner_key_path(tmp_path), owner_key, passphrase=PASSPHRASE)
    services = fake_first_run(answers={"Owner key passphrase: ": PASSPHRASE})
    account = prepare(tmp_path, services)
    assert account.owner_key is not None
    assert account.owner_key.public_key == owner_key.public_key
    assert not account.is_new_owner_key


def test_identity_requires_a_version_of_the_stack_key() -> None:
    identity = DeploymentIdentity.from_outputs(PROJECT, outputs())
    assert identity.kms_key_name == KEY_NAME
    bad = outputs() | {"kms_key_version_name": "projects/x/cryptoKeyVersions/1"}
    with pytest.raises(FirstRunError, match="not of its KMS key"):
        DeploymentIdentity.from_outputs(PROJECT, bad)
    with pytest.raises(FirstRunError, match="control_plane_url"):
        DeploymentIdentity.from_outputs(PROJECT, outputs() | {"control_plane_url": ""})


def test_prepared_account_hides_secrets(tmp_path: Path) -> None:
    account = prepare(tmp_path, fake_first_run())
    assert account.password == PASSWORD
    assert PASSWORD not in repr(account)
