"""Bounded polling for the deploy's long-running Google operations."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from carapace_cli.errors import CarapaceError


class PollTimeoutError(CarapaceError):
    """A condition did not become true in time."""


@dataclass(frozen=True)
class Clock:
    """Time sources, replaced in tests so nothing actually sleeps."""

    sleep: Callable[[float], None] = time.sleep
    monotonic: Callable[[], float] = time.monotonic


def poll_until[T](
    check: Callable[[], T | None],
    *,
    what: str,
    timeout_seconds: float,
    interval_seconds: float,
    clock: Clock,
) -> T:
    """The first non-``None`` result of ``check``; raises after the timeout.

    ``check`` raises to stop early on a state that can never succeed.
    """
    deadline = clock.monotonic() + timeout_seconds
    while True:
        result = check()
        if result is not None:
            return result
        if clock.monotonic() >= deadline:
            raise PollTimeoutError(
                f"timed out after {timeout_seconds:.0f}s waiting for {what}; "
                "run the same command again to resume"
            )
        clock.sleep(interval_seconds)
