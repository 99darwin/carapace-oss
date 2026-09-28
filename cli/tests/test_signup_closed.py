"""Closed registration from the CLI's side (#52): signup, deploy's first run."""

from __future__ import annotations

import functools
import hashlib
import io
import json
from pathlib import Path

import httpx
import pytest
from deploy_support import NEW_DIGEST, PROJECT, FakeStack, instant_clock
from first_run_support import PASSWORD, FakeControlPlane, fake_first_run

from carapace_cli import main as cli_main
from carapace_cli.deploy.first_run import (
    SETUP_TOKEN_SHA256_KEY,
    AccountFlags,
    FirstRunError,
    PreparedAccount,
    complete_first_run,
    prepare_account,
    setup_token_config,
    setup_token_sha256,
)
from carapace_cli.deploy.interview import Interview
from carapace_cli.errors import (
    REGISTRATION_CLOSED,
    SETUP_TOKEN_INVALID,
    RegistrationRefusedError,
    ServerError,
)
from carapace_cli.session import authenticate, session_path

EMAIL = "owner@example.com"
SERVER = "https://server.test"
TOKEN = "a-setup-token-for-the-tests"  # noqa: S105
FLAGS = AccountFlags(email=None, password_stdin=True, no_passphrase=True)


def reply(status: int, detail: str) -> httpx.MockTransport:
    return httpx.MockTransport(
        lambda request: httpx.Response(status, json={"detail": detail})
    )


# -- session.authenticate -----------------------------------------------------------


def test_the_setup_token_is_sent_only_when_registering() -> None:
    server = FakeControlPlane()
    transport = server.transport()
    authenticate(
        SERVER, EMAIL, PASSWORD, register=True, setup_token=TOKEN, transport=transport
    )
    authenticate(SERVER, EMAIL, PASSWORD, setup_token=TOKEN, transport=transport)
    bodies = [json.loads(request.content) for request in server.requests]
    assert bodies[0]["setup_token"] == TOKEN
    assert "setup_token" not in bodies[1]


def test_no_setup_token_leaves_the_field_out() -> None:
    server = FakeControlPlane()
    authenticate(SERVER, EMAIL, PASSWORD, register=True, transport=server.transport())
    assert "setup_token" not in json.loads(server.requests[0].content)


def test_a_closed_registration_says_to_log_in() -> None:
    with pytest.raises(RegistrationRefusedError) as caught:
        authenticate(
            SERVER,
            EMAIL,
            PASSWORD,
            register=True,
            transport=reply(403, REGISTRATION_CLOSED),
        )
    assert caught.value.is_closed
    assert caught.value.status == 403
    assert "carapace login" in str(caught.value)


def test_a_bad_setup_token_says_so_without_echoing_it() -> None:
    with pytest.raises(RegistrationRefusedError) as caught:
        authenticate(
            SERVER,
            EMAIL,
            PASSWORD,
            register=True,
            setup_token=TOKEN,
            transport=reply(403, SETUP_TOKEN_INVALID),
        )
    assert not caught.value.is_closed
    assert "setup token" in str(caught.value)
    assert TOKEN not in str(caught.value)


def test_other_403s_stay_plain_server_errors() -> None:
    with pytest.raises(ServerError) as caught:
        authenticate(
            SERVER, EMAIL, PASSWORD, register=True, transport=reply(403, "Forbidden")
        )
    assert not isinstance(caught.value, RegistrationRefusedError)
    # A login is never reported as a refused registration.
    with pytest.raises(ServerError) as login:
        authenticate(SERVER, EMAIL, PASSWORD, transport=reply(403, REGISTRATION_CLOSED))
    assert not isinstance(login.value, RegistrationRefusedError)


# -- carapace signup ----------------------------------------------------------------


def run_signup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    server: FakeControlPlane,
    *extra: str,
    command: str = "signup",
) -> tuple[int, str]:
    monkeypatch.setattr(
        cli_main,
        "authenticate",
        functools.partial(authenticate, transport=server.transport()),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    err = io.StringIO()
    argv = ["--config-dir", str(tmp_path), command, "--server", SERVER]
    argv += ["--email", EMAIL, "--password-stdin", *extra]
    code = cli_main.main(argv, out=io.StringIO(), err=err)
    return code, err.getvalue()


def test_signup_on_a_closed_server_prints_a_clear_message(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = FakeControlPlane(users={"first@example.com": PASSWORD})
    code, output = run_signup(monkeypatch, tmp_path, server)
    assert code == cli_main.EXIT_ERROR
    assert "registration refused" in output
    assert "carapace login" in output
    assert not session_path(tmp_path).exists()


def test_signup_reads_the_setup_token_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = FakeControlPlane(setup_token_sha256=setup_token_sha256(TOKEN))
    monkeypatch.setenv(cli_main.SETUP_TOKEN_ENV, TOKEN)
    code, output = run_signup(monkeypatch, tmp_path, server)
    assert code == 0, output
    assert server.setup_tokens == [TOKEN]
    assert TOKEN not in output


def test_signup_prompts_for_the_setup_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = FakeControlPlane(setup_token_sha256=setup_token_sha256(TOKEN))
    monkeypatch.delenv(cli_main.SETUP_TOKEN_ENV, raising=False)
    prompts: list[str] = []

    def prompt(text: str, *, confirm: bool = False) -> str:
        prompts.append(text)
        return TOKEN

    monkeypatch.setattr(cli_main, "prompt_hidden", prompt)
    code, output = run_signup(monkeypatch, tmp_path, server, "--setup-token")
    assert code == 0, output
    assert prompts == ["Setup token: "]
    assert server.setup_tokens == [TOKEN]


def test_signup_with_a_wrong_setup_token_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = FakeControlPlane(setup_token_sha256=setup_token_sha256(TOKEN))
    monkeypatch.setenv(cli_main.SETUP_TOKEN_ENV, "not-the-token")
    code, output = run_signup(monkeypatch, tmp_path, server)
    assert code == cli_main.EXIT_ERROR
    assert "setup token is missing or wrong" in output
    assert "not-the-token" not in output
    assert not server.users


def test_login_never_sends_the_setup_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    server = FakeControlPlane(users={EMAIL: PASSWORD})
    monkeypatch.setenv(cli_main.SETUP_TOKEN_ENV, TOKEN)
    code, output = run_signup(monkeypatch, tmp_path, server, command="login")
    assert code == 0, output
    for request in server.requests:
        assert TOKEN.encode() not in request.content


# -- carapace deploy: the first run --------------------------------------------------


def prepare(config_dir: Path, server: FakeControlPlane) -> PreparedAccount:
    return prepare_account(
        config_dir,
        FLAGS,
        Interview(interactive=False),
        fake_first_run(server),
        default_email=EMAIL,
    )


def finish(account: PreparedAccount, server: FakeControlPlane) -> list[str]:
    lines: list[str] = []
    complete_first_run(
        account,
        project=PROJECT,
        outputs=FakeStack(initial={"carapace:deploy_workloads": "true"}).outputs(),
        enclave_digest=NEW_DIGEST,
        services=fake_first_run(server),
        clock=instant_clock(),
        say=lines.append,
    )
    return lines


def test_a_new_account_gets_a_fresh_hidden_setup_token(tmp_path: Path) -> None:
    server = FakeControlPlane()
    first = prepare(tmp_path / "a", server)
    second = prepare(tmp_path / "b", server)
    assert first.setup_token and second.setup_token
    assert first.setup_token != second.setup_token
    assert len(first.setup_token) >= 43  # 32 random bytes, base64url
    assert first.setup_token not in repr(first)
    digest = hashlib.sha256(first.setup_token.encode()).hexdigest()
    assert setup_token_config(first) == {SETUP_TOKEN_SHA256_KEY: digest}


def test_an_existing_session_needs_no_setup_token(tmp_path: Path) -> None:
    server = FakeControlPlane()
    finish(prepare(tmp_path, server), server)
    again = prepare(tmp_path, server)
    assert again.setup_token is None
    assert setup_token_config(again) == {}


def test_first_run_claims_the_server_with_its_token(tmp_path: Path) -> None:
    server = FakeControlPlane()
    account = prepare(tmp_path, server)
    assert account.setup_token is not None
    server.setup_token_sha256 = setup_token_sha256(account.setup_token)
    lines = finish(account, server)
    assert f"Created the account {EMAIL}." in lines
    assert server.setup_tokens == [account.setup_token]
    assert not any(account.setup_token in line for line in lines)


def test_first_run_on_a_claimed_server_logs_in(tmp_path: Path) -> None:
    server = FakeControlPlane(
        users={EMAIL: PASSWORD}, setup_token_sha256=setup_token_sha256(TOKEN)
    )
    lines = finish(prepare(tmp_path, server), server)
    assert f"Logged in as {EMAIL}." in lines
    assert session_path(tmp_path).exists()


def test_first_run_with_a_stale_setup_token_fails_clearly(tmp_path: Path) -> None:
    server = FakeControlPlane(setup_token_sha256=setup_token_sha256(TOKEN))
    account = prepare(tmp_path, server)
    with pytest.raises(FirstRunError, match="refused this deploy's setup token"):
        finish(account, server)
    assert not server.users
    assert not session_path(tmp_path).exists()
