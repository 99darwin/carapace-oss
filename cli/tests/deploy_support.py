"""Helpers for the deploy tests. Nothing here reaches the network."""

from __future__ import annotations

import io

from carapace_cli.deploy.interview import Interview


def scripted(*answers: str, interactive: bool = True, yes: bool = False) -> Interview:
    """An interview that reads ``answers`` line by line and writes to a buffer."""
    return Interview(
        interactive=interactive,
        assume_yes=yes,
        stream_in=io.StringIO("".join(f"{a}\n" for a in answers)),
        stream_out=io.StringIO(),
    )


def transcript(interview: Interview) -> str:
    out = interview.stream_out
    assert isinstance(out, io.StringIO)
    return out.getvalue()
