"""Best-effort wiping of secret buffers.

Only mutable buffers can be wiped. Python ``bytes`` and ``str`` are
immutable, and every conversion to them makes a copy that lingers until the
allocator reuses its memory. Keep secrets in ``bytearray`` for as long as
possible, convert only at the last moment, and wipe the ``bytearray`` in a
``finally`` block (or with :func:`wiped`). This narrows the window in which a
secret sits in memory; it does not close it.
"""

from __future__ import annotations

import ctypes
from collections.abc import Iterator
from contextlib import contextmanager


def secure_zero(buffer: bytearray | memoryview) -> None:
    """Overwrite ``buffer`` with zeros in place.

    ``ctypes.memset`` writes the underlying memory directly, so the zeroing
    cannot be skipped as a dead store.

    Raises:
        TypeError: If ``buffer`` is not a writable ``bytearray`` or
            ``memoryview``.
    """
    if isinstance(buffer, memoryview):
        if buffer.readonly:
            raise TypeError("cannot wipe a read-only memoryview")
        buffer = buffer.cast("B")
    elif not isinstance(buffer, bytearray):
        raise TypeError(f"cannot wipe {type(buffer).__name__}")
    size = len(buffer)
    if size == 0:
        return
    view = (ctypes.c_char * size).from_buffer(buffer)
    try:
        ctypes.memset(ctypes.addressof(view), 0, size)
    finally:
        # Release the buffer export so the bytearray can be resized again.
        del view


@contextmanager
def wiped(buffer: bytearray) -> Iterator[bytearray]:
    """Yield ``buffer`` and wipe it on exit, even on error."""
    try:
        yield buffer
    finally:
        secure_zero(buffer)
