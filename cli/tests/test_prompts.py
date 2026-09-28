"""Hidden prompts read the terminal, not stdin, and never echo."""

from __future__ import annotations

import getpass
import io
import os
import sys
import warnings

import pytest

from carapace_cli import CarapaceError, prompts


def _answers(monkeypatch: pytest.MonkeyPatch, *values: str) -> list[str]:
    asked: list[str] = []
    queue = list(values)

    def fake_getpass(prompt: str = "") -> str:
        asked.append(prompt)
        return queue.pop(0)

    monkeypatch.setattr(prompts.getpass, "getpass", fake_getpass)
    return asked


def test_piped_stdin_still_prompts_at_the_terminal(monkeypatch) -> None:
    # `printf secret | carapace secret add …`: stdin is a pipe, the
    # passphrase comes from the terminal.
    monkeypatch.setattr(sys, "stdin", io.StringIO("piped secret"))
    monkeypatch.setattr(prompts, "has_terminal", lambda: True)
    asked = _answers(monkeypatch, "passphrase")
    assert prompts.prompt_hidden("Owner key passphrase: ") == "passphrase"
    assert asked == ["Owner key passphrase: "]
    assert sys.stdin.read() == "piped secret"


def test_no_terminal_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(prompts, "has_terminal", lambda: False)
    asked = _answers(monkeypatch, "never read")
    with pytest.raises(CarapaceError, match="must be entered at a terminal"):
        prompts.prompt_hidden("Owner key passphrase: ")
    assert asked == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX /dev/tty")
def test_has_terminal_needs_dev_tty(monkeypatch) -> None:
    def no_tty(path, flags, *args):
        raise OSError("no controlling terminal")

    monkeypatch.setattr(prompts.os, "open", no_tty)
    assert prompts.has_terminal() is False


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX /dev/tty")
def test_has_terminal_ignores_stdin(monkeypatch) -> None:
    opened: list[str] = []
    real_open = os.open

    def fake_open(path, flags, *args):
        opened.append(path)
        return real_open(os.devnull, os.O_RDONLY)

    monkeypatch.setattr(prompts.os, "open", fake_open)
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert prompts.has_terminal() is True
    assert opened == ["/dev/tty"]


def test_echoing_fallback_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(prompts, "has_terminal", lambda: True)

    def echoing_getpass(prompt: str = "") -> str:
        warnings.warn("Can not control echo", getpass.GetPassWarning, stacklevel=1)
        return "echoed passphrase"

    monkeypatch.setattr(prompts.getpass, "getpass", echoing_getpass)
    with pytest.raises(CarapaceError, match="must be entered at a terminal"):
        prompts.prompt_hidden("Owner key passphrase: ")


def test_confirmation_must_match(monkeypatch) -> None:
    monkeypatch.setattr(prompts, "has_terminal", lambda: True)
    _answers(monkeypatch, "one", "two")
    with pytest.raises(CarapaceError, match="do not match"):
        prompts.prompt_hidden("New owner key passphrase: ", confirm=True)


def test_confirmed_value_is_returned(monkeypatch) -> None:
    monkeypatch.setattr(prompts, "has_terminal", lambda: True)
    asked = _answers(monkeypatch, "same", "same")
    assert prompts.prompt_hidden("Password: ", confirm=True) == "same"
    assert asked == ["Password: ", "Repeat to confirm: "]
