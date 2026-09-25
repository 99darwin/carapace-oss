"""A short-lived cache of unwrapped data keys, in wipeable buffers.

Keyed by ``(owner_pk, secret_id, version, sig)``: the signature covers the
wrapped key, so a re-sealed or substituted envelope never hits an entry
made for another. Entries live at most ``DEK_TTL_SECONDS``. The freshness
argument in ``docs/design/owner-signing.md`` depends on that bound: KMS
access is what ends when attestation can no longer be refreshed, so no DEK
may outlive it by more than a minute.

Only the cache's own ``bytearray`` copies can be wiped. The ``bytes``
handed to :func:`carapace_crypto.open_with_dek_unwrapper` are immutable and
are left to the garbage collector.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable

from carapace_crypto import Envelope
from carapace_enclave.secure_memory import secure_zero

DEK_TTL_SECONDS = 60.0
DEFAULT_MAX_ENTRIES = 1_000

CacheKey = tuple[bytes, str, int, bytes]


def dek_cache_key(envelope: Envelope) -> CacheKey:
    return (envelope.owner_pk, envelope.secret_id, envelope.version, envelope.sig)


class DekCache:
    """Maps envelope identity to its unwrapped DEK for at most a minute."""

    def __init__(
        self,
        *,
        ttl: float = DEK_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 0 < ttl <= DEK_TTL_SECONDS:
            raise ValueError(f"ttl must be in (0, {DEK_TTL_SECONDS}]")
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._ttl = ttl
        self._max_entries = max_entries
        self._monotonic = monotonic
        self._entries: OrderedDict[CacheKey, tuple[bytearray, float]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: CacheKey) -> bytes | None:
        """A copy of the cached DEK, or ``None`` if absent or expired."""
        with self._lock:
            self._expire()
            entry = self._entries.get(key)
            if entry is None:
                return None
            self._entries.move_to_end(key)
            return bytes(entry[0])

    def put(self, key: CacheKey, dek: bytes) -> None:
        with self._lock:
            self._drop(key)
            self._entries[key] = (bytearray(dek), self._monotonic())
            while len(self._entries) > self._max_entries:
                _, (old, _) = self._entries.popitem(last=False)
                secure_zero(old)

    def clear(self) -> None:
        with self._lock:
            for buffer, _ in self._entries.values():
                secure_zero(buffer)
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            self._expire()
            return len(self._entries)

    def _drop(self, key: CacheKey) -> None:
        entry = self._entries.pop(key, None)
        if entry is not None:
            secure_zero(entry[0])

    def _expire(self) -> None:
        cutoff = self._monotonic() - self._ttl
        # get() reorders for LRU, so expiry scans every entry (at most
        # max_entries) rather than stopping at the first fresh one.
        for key in [k for k, (_, at) in self._entries.items() if at <= cutoff]:
            self._drop(key)
