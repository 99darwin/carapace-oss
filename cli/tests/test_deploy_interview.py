"""The deploy interview: flags first, questions only on a terminal.

Answers come from a scripted stream; nothing waits on real input.
"""

from __future__ import annotations

import io

import pytest
from deploy_support import scripted, transcript

from carapace_cli.deploy.interview import (
    Interview,
    InvalidInputError,
    MissingInputError,
)

PROJECT = "carapace-selfhost"
EMAIL = "ops@example.com"


def is_email(value: str) -> str:
    if "@" not in value:
        raise InvalidInputError(f"{value!r} is not an email address")
    return value


def is_short(value: str) -> str:
    if len(value) > 3:
        raise InvalidInputError("too long")
    return value


def test_flag_value_is_validated_not_asked() -> None:
    interview = scripted()
    with pytest.raises(InvalidInputError):
        interview.ask("Prefix", flag="--prefix", value="toolong", validate=is_short)
    assert transcript(interview) == ""


def test_non_interactive_missing_flag_names_the_flag() -> None:
    interview = scripted(interactive=False)
    with pytest.raises(MissingInputError, match="--alert-email is required"):
        interview.ask("Email", flag="--alert-email", value=None)


def test_non_interactive_uses_the_default() -> None:
    interview = scripted(interactive=False)
    assert interview.ask("Prefix", flag="--prefix", value=None, default="c1x") == "c1x"


def test_interactive_reasks_until_valid_then_gives_up() -> None:
    interview = scripted("nope", "ops@example.com")
    assert interview.ask("E", flag="--e", value=None, validate=is_email) == (EMAIL)
    assert "is not an email address" in transcript(interview)

    stubborn = scripted("a", "b", "c", "d")
    with pytest.raises(InvalidInputError, match="no valid answer for --e"):
        stubborn.ask("E", flag="--e", value=None, validate=is_email)


def test_end_of_input_never_hangs() -> None:
    with pytest.raises(MissingInputError, match="input ended"):
        scripted().ask("E", flag="--e", value=None)


def test_choose_accepts_number_or_value() -> None:
    options = [("alpha", ""), ("beta", "")]
    assert scripted("2").choose("Pick", flag="--x", value=None, options=options) == (
        "beta"
    )
    assert scripted("gamma").choose(
        "Pick", flag="--x", value=None, options=options
    ) == ("gamma")
    with pytest.raises(InvalidInputError):
        scripted("9", "9", "9").choose("Pick", flag="--x", value=None, options=options)


def test_confirm_defaults_to_no_and_needs_yes_when_scripted() -> None:
    assert scripted("").confirm("Go?") is False
    assert scripted("y").confirm("Go?") is True
    assert scripted(interactive=False, yes=True).confirm("Go?") is True
    with pytest.raises(MissingInputError, match="pass --yes"):
        scripted(interactive=False).confirm("Go?")


def test_confirm_typed_requires_exact_value() -> None:
    kwargs = {"expected": PROJECT, "flag": "--confirm-project"}
    assert scripted(PROJECT).confirm_typed("Type it", value=None, **kwargs)
    assert not scripted("y").confirm_typed("Type it", value=None, **kwargs)
    assert not scripted(yes=True).confirm_typed("Type", value="other", **kwargs)
    with pytest.raises(MissingInputError, match="--confirm-project"):
        scripted(interactive=False, yes=True).confirm_typed(
            "Type it", value=None, **kwargs
        )


def test_no_tty_means_non_interactive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert not Interview.from_args(non_interactive=False, assume_yes=False).interactive
