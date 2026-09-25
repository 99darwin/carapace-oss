"""Reading secrets from the terminal or stdin, never from argv."""

from __future__ import annotations

import getpass
import sys
from typing import BinaryIO

from carapace_cli.errors import CarapaceError
from carapace_crypto.envelope import MAX_PLAINTEXT_BYTES


def prompt_hidden(prompt: str, *, confirm: bool = False) -> str:
    """Prompt without echo. Refuses when stdin is not a terminal."""
    if not sys.stdin.isatty():
        raise CarapaceError(f"{prompt.strip(': ')} must be entered at a terminal")
    value = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repeat to confirm: ") != value:
        raise CarapaceError("the two entries do not match")
    return value


def read_secret_value(stream: BinaryIO | None = None) -> bytearray:
    """The secret to seal, from a hidden prompt or piped stdin.

    From a pipe, one trailing newline is dropped (``echo`` adds one). The
    result is a bytearray so the caller can zero it after sealing.
    """
    if stream is None and sys.stdin.isatty():
        value = bytearray(prompt_hidden("Secret value: ", confirm=True).encode("utf-8"))
    else:
        source = stream if stream is not None else sys.stdin.buffer
        value = bytearray(source.read(MAX_PLAINTEXT_BYTES + 2))
        if value.endswith(b"\r\n"):
            del value[-2:]
        elif value.endswith(b"\n"):
            del value[-1:]
    if not value:
        raise CarapaceError("the secret is empty")
    if len(value) > MAX_PLAINTEXT_BYTES:
        zero(value)
        raise CarapaceError(f"the secret exceeds {MAX_PLAINTEXT_BYTES} bytes")
    return value


def read_password(*, from_stdin: bool, confirm: bool = False) -> str:
    if from_stdin:
        line = sys.stdin.readline()
        password = line.rstrip("\r\n")
        if not password:
            raise CarapaceError("no password on stdin")
        return password
    return prompt_hidden("Password: ", confirm=confirm)


def zero(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0
