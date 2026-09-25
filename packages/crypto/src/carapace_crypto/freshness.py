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

Entries are partitioned by owner fingerprint and each partition has its own
LRU bound, so one tenant's traffic can neither evict another tenant's
entries nor plant a value under another tenant's secret id. A malicious
server can still flush a partition by driving traffic under that many
*distinct* owner keys between two of the victim's requests, which is why
this is a best-effort bound within a boot and not the guarantee.

Call :meth:`MonotonicCache.observe` only after the object's signature has
verified against the owner whose fingerprint you pass. Recording an
unverified value would let the server plant a huge one and deny service to
the real objects.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Hashable

DEFAULT_MAX_OWNERS = 10_000
DEFAULT_MAX_ENTRIES_PER_OWNER = 1_000

_Bucket = OrderedDict[tuple[str, Hashable], int]


class StaleError(ValueError):
    """A verified object is older than one already seen this boot."""


class MonotonicCache:
    """Highest value seen per ``(owner, namespace, key)``, bounded per owner."""

    __slots__ = ("_lock", "_max_entries_per_owner", "_max_owners", "_owners")

    def __init__(
        self,
        *,
        max_owners: int = DEFAULT_MAX_OWNERS,
        max_entries_per_owner: int = DEFAULT_MAX_ENTRIES_PER_OWNER,
    ) -> None:
        if max_owners < 1 or max_entries_per_owner < 1:
            raise ValueError("cache bounds must be positive")
        self._owners: OrderedDict[bytes, _Bucket] = OrderedDict()
        self._max_owners = max_owners
        self._max_entries_per_owner = max_entries_per_owner
        self._lock = threading.Lock()

    def observe(self, owner: bytes, namespace: str, key: Hashable, value: int) -> None:
        """Record ``value`` for ``key`` under ``owner``, refusing anything lower.

        ``owner`` is the fingerprint the object verified against.

        Raises:
            StaleError: If a higher value was already recorded this boot.
            TypeError: If ``value`` is not an ``int`` (``bool`` included); a
                NaN would compare false both ways and disable the slot.
        """
        if type(value) is not int:
            raise TypeError("value must be an int")
        with self._lock:
            bucket = self._owners.get(owner)
            if bucket is None:
                bucket = self._owners[owner] = OrderedDict()
            self._owners.move_to_end(owner)
            slot = (namespace, key)
            seen = bucket.get(slot)
            if seen is not None and value < seen:
                raise StaleError(f"{namespace} rolled back from {seen} to {value}")
            bucket[slot] = value if seen is None else max(seen, value)
            bucket.move_to_end(slot)
            while len(bucket) > self._max_entries_per_owner:
                bucket.popitem(last=False)
            while len(self._owners) > self._max_owners:
                self._owners.popitem(last=False)

    def __len__(self) -> int:
        with self._lock:
            return sum(len(bucket) for bucket in self._owners.values())
