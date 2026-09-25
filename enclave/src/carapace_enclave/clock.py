"""The enclave's notion of "now".

The VM operator controls the guest clock. The enclave therefore takes
``now = max(vm_clock, iat of the latest attestation token)`` and never lets
it decrease within a boot (see "Clock" in ``docs/design/owner-signing.md``).
Attestation tokens are issued against Google's clock, so the operator cannot
turn the enclave's view of time back past the last token it fetched.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable


class TrustedClock:
    """Monotonic, attestation-floored unix time in whole seconds."""

    __slots__ = ("_floor", "_lock", "_wall")

    def __init__(self, wall: Callable[[], float] = time.time) -> None:
        self._wall = wall
        self._floor = 0
        self._lock = threading.Lock()

    def observe_attested(self, iat: int) -> None:
        """Raise the floor to an attestation token's ``iat``."""
        if type(iat) is not int:
            raise TypeError("iat must be an int")
        with self._lock:
            self._floor = max(self._floor, iat)

    def now(self) -> int:
        with self._lock:
            self._floor = max(self._floor, int(self._wall()))
            return self._floor
