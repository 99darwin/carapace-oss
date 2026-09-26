"""Account password rules: the CLI's copy is pinned to the server's."""

from __future__ import annotations

import io
from collections.abc import Iterator
from pathlib import Path

import pydantic
import pytest
from deploy_support import scripted
from first_run_support import PASSWORD, FakeControlPlane, fake_first_run

import carapace_cli.main as cli_main
from carapace_cli.deploy.first_run import AccountFlags, prepare_account
from carapace_cli.errors import CarapaceError
from carapace_cli.passwords import (
    PASSWORD_MAX_CHARS,
    PASSWORD_MIN_CHARS,
    PASSWORD_RULES,
    WeakPasswordError,
    check_password,
    password_problem,
)
from carapace_server.auth import schemas

STRONG = "Correct-Horse-9"  # a test value
SAMPLES = [
    STRONG,
    "short-A9",
    "correct-horse-9",
    "CORRECT-HORSE-9",
    "Correct-Horse-X",
    "CorrectHorse99",
    "Correct Horse 9",
    "Ünïcode-Horse-9",
    "Aa1-" + "x" * (PASSWORD_MAX_CHARS - 4),
    "Aa1-" + "x" * (PASSWORD_MAX_CHARS - 3),
]
NO_FLAGS = AccountFlags(email=None, password_stdin=False, no_passphrase=True)


def test_rules_are_the_servers() -> None:
    assert PASSWORD_MIN_CHARS == schemas.PASSWORD_MIN_LENGTH
    assert PASSWORD_MAX_CHARS == schemas.PASSWORD_MAX_LENGTH
    assert PASSWORD_RULES == schemas._PASSWORD_RULES


@pytest.mark.parametrize("password", SAMPLES)
def test_cli_accepts_exactly_what_the_server_accepts(password: str) -> None:
    try:
        schemas.RegisterRequest(email="a@example.com", password=password)
        server_accepts = True
    except pydantic.ValidationError:
        server_accepts = False
    assert (password_problem(password) is None) == server_accepts


def test_every_missing_rule_is_named_but_never_the_value() -> None:
    weak = "lowercase only here"
    with pytest.raises(WeakPasswordError) as caught:
        check_password(weak)
    message = str(caught.value)
    assert "an uppercase letter, a digit" in message
    assert weak not in message
    assert "12 to 128 characters" in str(password_problem("Aa1-"))


def answers(*values: str) -> Iterator[str]:
    yield from values


def test_deploy_prompt_asks_again_for_a_weak_password(tmp_path: Path) -> None:
    replies = answers("too-weak", "no digits Here!", STRONG)
    services = fake_first_run(FakeControlPlane())
    services.prompt = lambda text, *, confirm=False: next(replies)
    interview = scripted("me@example.com", interactive=True)
    out = io.StringIO()
    interview.stream_out = out
    account = prepare_account(
        tmp_path, NO_FLAGS, interview, services, default_email="me@example.com"
    )
    assert account.password == STRONG
    assert "12 to 128 characters" in out.getvalue()
    assert "must contain a digit" in out.getvalue()


def test_deploy_prompt_gives_up_after_three_weak_passwords(tmp_path: Path) -> None:
    services = fake_first_run()
    services.prompt = lambda text, *, confirm=False: "weak"
    interview = scripted("me@example.com", interactive=True)
    interview.stream_out = io.StringIO()
    with pytest.raises(WeakPasswordError, match="after 3 attempts"):
        prepare_account(
            tmp_path, NO_FLAGS, interview, services, default_email="me@example.com"
        )


def test_deploy_rejects_a_weak_password_on_stdin(tmp_path: Path) -> None:
    services = fake_first_run()
    services.password_from_stdin = lambda: "weak-password"
    flags = AccountFlags(email=None, password_stdin=True, no_passphrase=True)
    with pytest.raises(WeakPasswordError, match="must contain an uppercase"):
        prepare_account(
            tmp_path,
            flags,
            scripted("me@example.com"),
            services,
            default_email="x@y.io",
        )


class Reached(CarapaceError):
    """The command got as far as the server."""


def run_auth(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, command: str, *extra: str
) -> tuple[int, str, list[str]]:
    """``carapace <command>``; the passwords that would reach the server."""
    sent: list[str] = []

    def authenticate(server: str, email: str, password: str, **_: object) -> None:
        sent.append(password)
        raise Reached("reached the server")

    monkeypatch.setattr(cli_main, "authenticate", authenticate)
    err = io.StringIO()
    argv = ["--config-dir", str(tmp_path), command, "--server", "https://x.test"]
    argv += ["--email", "a@example.com", *extra]
    code = cli_main.main(argv, out=io.StringIO(), err=err)
    return code, err.getvalue(), sent


def test_signup_asks_again_for_a_weak_password(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    replies = answers("weak", STRONG)
    monkeypatch.setattr(
        cli_main, "read_password", lambda *, from_stdin, confirm=False: next(replies)
    )
    _, output, sent = run_auth(monkeypatch, tmp_path, "signup")
    assert sent == [STRONG]
    assert "12 to 128 characters" in output


def test_signup_refuses_a_weak_password_on_stdin_before_sending_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("alllowercase-but-long\n"))
    code, output, sent = run_auth(monkeypatch, tmp_path, "signup", "--password-stdin")
    assert code != 0 and not sent
    assert "must contain an uppercase letter, a digit" in output


def test_login_does_not_apply_the_signup_rules(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("weak\n"))
    _, _, sent = run_auth(monkeypatch, tmp_path, "login", "--password-stdin")
    assert sent == ["weak"]


def test_first_run_support_password_meets_the_rules() -> None:
    assert password_problem(PASSWORD) is None
