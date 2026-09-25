"""Per-boot rollback detection for the enclave.

Grants carry ``iat`` and envelopes carry ``version``. Both are chosen by the
owner and only ever increase for a given key or secret. The enclave records
the highest value it has verified for each and refuses anything lower, so an
untrusted server cannot roll a running enclave back to an older grant or
envelope it has already seen replaced.

The cache lives in enclave memory and starts empty at every boot, so it
protects only *within* a boot. Across boots, freshness comes from grant
expiry and the per-secret minimum version pinned in each grant; see
``docs/design/owner-signing.md``.

Call :meth:`MonotonicCache.observe` only after the object's signature has
verified. Recording an unverified value would let the server plant a huge
one and deny service to the real objects.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Hashable

DEFAULT_MAX_ENTRIES = 100_000


class StaleError(ValueError):
    """A verified object is older than one already seen this boot."""


class MonotonicCache:
    """Highest value seen per ``(namespace, key)``, bounded in size."""

    __slots__ = ("_entries", "_max_entries")

    def __init__(self, *, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._entries: OrderedDict[tuple[str, Hashable], int] = OrderedDict()
        self._max_entries = max_entries

    def observe(self, namespace: str, key: Hashable, value: int) -> None:
        """Record ``value`` for ``key``, refusing anything below the maximum.

        Raises:
            StaleError: If a higher value was already recorded this boot.
        """
        slot = (namespace, key)
        seen = self._entries.get(slot)
        if seen is not None and value < seen:
            raise StaleError(f"{namespace} rolled back from {seen} to {value}")
        self._entries[slot] = value if seen is None else max(seen, value)
        self._entries.move_to_end(slot)
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)

    def __len__(self) -> int:
        return len(self._entries)
