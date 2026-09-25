"""Signed, hash-chained receipts for every brokered action.

Wire format (``carapace_server.receipts.chain``)::

    signed = canonical_json({"boot_id", "seq", "prev_hash", "payload"})
    hash   = sha256(signed).hex()
    sig    = Ed25519(receipt_key, signed)

The first receipt of a boot has ``seq`` 0 and ``prev_hash`` of 64 zeros.

Receipts are signed in the request path and uploaded in order by
:meth:`ReceiptLog.flush`, in batches. The log fails closed: once the backlog
reaches ``max_pending``, or the server rejects the chain (which a retry
cannot fix), :meth:`ReceiptLog.check_available` refuses further actions, so
nothing runs that could not be receipted.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
from collections import deque
from typing import Any

from carapace_crypto import b64_encode_std, canonical_json, sha256_hex
from carapace_enclave.attestation.identity import BootIdentity
from carapace_enclave.server_client import ControlPlaneClient, ControlPlaneError

logger = logging.getLogger(__name__)

GENESIS_PREV_HASH = "0" * 64
MAX_BATCH = 100
DEFAULT_MAX_PENDING = 1_000
FLUSH_INTERVAL_SECONDS = 2.0
# The server's answers when the chain itself is wrong; retrying cannot help.
FATAL_STATUSES = frozenset({409, 422})


class ReceiptLogUnavailableError(Exception):
    """Receipts cannot currently be recorded; refuse the action."""


class ReceiptLog:
    """This boot's receipt chain and its upload queue."""

    def __init__(
        self,
        *,
        identity: BootIdentity,
        client: ControlPlaneClient,
        max_pending: int = DEFAULT_MAX_PENDING,
    ) -> None:
        self._identity = identity
        self._client = client
        self._max_pending = max_pending
        self._seq = 0
        self._prev_hash = GENESIS_PREV_HASH
        self._pending: deque[dict[str, Any]] = deque()
        self._failed = False
        self._lock = threading.Lock()
        self._flush_lock = asyncio.Lock()
        self._wakeup = asyncio.Event()

    @property
    def pending(self) -> int:
        return len(self._pending)

    def check_available(self) -> None:
        """Raise unless a new action could be receipted and uploaded."""
        if self._failed:
            raise ReceiptLogUnavailableError("receipt chain was rejected")
        if len(self._pending) >= self._max_pending:
            raise ReceiptLogUnavailableError("receipt backlog is full")

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Sign ``payload`` as the next receipt and queue it for upload.

        Never refuses: the action it records has already happened. Callers
        gate *new* actions with :meth:`check_available`.
        """
        with self._lock:
            body = {
                "boot_id": self._identity.boot_id,
                "seq": self._seq,
                "prev_hash": self._prev_hash,
                "payload": payload,
            }
            signed = canonical_json(body)
            receipt = {
                **body,
                "signature": b64_encode_std(self._identity.receipt_key.sign(signed)),
            }
            self._seq += 1
            self._prev_hash = sha256_hex(signed)
            self._pending.append(receipt)
        self._wakeup.set()
        return receipt

    async def flush(self) -> None:
        """Upload everything pending, oldest first. Raises ControlPlaneError."""
        async with self._flush_lock:
            while self._pending and not self._failed:
                batch = [self._pending[i] for i in range(min(MAX_BATCH, self.pending))]
                try:
                    await self._client.upload_receipts(batch)
                except ControlPlaneError as exc:
                    if exc.status in FATAL_STATUSES:
                        self._failed = True
                        logger.error("receipt chain rejected: %s", exc)
                    raise
                for _ in batch:
                    self._pending.popleft()

    async def run(self) -> None:
        """Flush whenever receipts arrive, and retry on an interval."""
        while not self._failed:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wakeup.wait(), FLUSH_INTERVAL_SECONDS)
            self._wakeup.clear()
            try:
                await self.flush()
            except ControlPlaneError as exc:
                logger.warning("receipt upload failed: %s", exc)
