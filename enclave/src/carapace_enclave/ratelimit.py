"""In-memory sliding-window rate limits, bounded in the number of keys.

The enclave keeps no state across boots and trusts no shared store, so
limits live in process memory. Every limiter holds at most ``max_keys``
windows and evicts the least recently used, so an attacker who invents keys
costs memory up to that bound and no further.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Hashable

WINDOW_SECONDS = 60.0
DEFAULT_MAX_KEYS = 10_000


class RateLimiter:
    """At most ``limit`` events per ``window`` seconds for each key."""

    def __init__(
        self,
        *,
        window: float = WINDOW_SECONDS,
        max_keys: int = DEFAULT_MAX_KEYS,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if window <= 0 or max_keys < 1:
            raise ValueError("window and max_keys must be positive")
        self._window = window
        self._max_keys = max_keys
        self._monotonic = monotonic
        self._events: OrderedDict[Hashable, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def acquire(self, key: Hashable, limit: int) -> bool:
        """Record one event for ``key`` if under ``limit``; report success."""
        if limit < 1:
            return False
        now = self._monotonic()
        with self._lock:
            events = self._events.get(key)
            if events is None:
                events = self._events[key] = deque()
            self._events.move_to_end(key)
            while events and events[0] <= now - self._window:
                events.popleft()
            if len(events) >= limit:
                return False
            events.append(now)
            while len(self._events) > self._max_keys:
                self._events.popitem(last=False)
            return True

    def count(self, key: Hashable) -> int:
        """Events recorded for ``key`` within the current window.

        Read-only: nothing is recorded and no window is created, so probing
        a key that was never seen costs no memory.
        """
        now = self._monotonic()
        with self._lock:
            events = self._events.get(key)
            if events is None:
                return 0
            while events and events[0] <= now - self._window:
                events.popleft()
            return len(events)
