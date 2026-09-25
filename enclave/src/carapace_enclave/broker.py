"""The credential broker: one agent request in, one upstream response out.

Implements the enclave verification algorithm of
``docs/design/owner-signing.md`` step for step. The API key the agent
presents is the root of trust: it names the owner fingerprint, the grant
must chain to it, and the envelope must be signed by the grant's owner key.
Nothing the control plane says is believed until a signature from that key
vouches for it.

Errors separate "your key" (4xx) from "the store" (5xx) and never carry
grant, envelope, policy or secret contents.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from carapace_crypto import (
    ApiKey,
    ApiKeyError,
    CanonicalJSONError,
    Envelope,
    EnvelopeError,
    Grant,
    GrantError,
    MonotonicCache,
    StaleError,
    load_json_object,
    open_with_dek_unwrapper,
    verify_envelope_signature,
    verify_grant,
)
from carapace_enclave.attestation.kms import DekDecrypter, KmsError, require_key_version
from carapace_enclave.clock import TrustedClock
from carapace_enclave.dek_cache import DekCache, dek_cache_key
from carapace_enclave.egress import (
    AgentRequest,
    EgressDenied,
    EgressError,
    EgressExecutor,
    EgressResult,
    InjectionPolicy,
    ReceiptMetadata,
)
from carapace_enclave.ratelimit import RateLimiter
from carapace_enclave.receipts import ReceiptLog, ReceiptLogUnavailableError
from carapace_enclave.secure_memory import secure_zero
from carapace_enclave.server_client import (
    ControlPlaneClient,
    ControlPlaneError,
    ControlPlaneNotFoundError,
)

logger = logging.getLogger(__name__)

RECEIPT_PAYLOAD_VERSION = 1
# Per owner fingerprint, counted only after the grant verifies, so that
# nobody can exhaust another owner's budget with a key they do not hold.
REQUESTS_PER_OWNER_PER_MINUTE = 600
# KMS calls (DEK cache misses) per owner fingerprint.
KMS_UNWRAPS_PER_OWNER_PER_MINUTE = 60
# Refused authorizations (401/403 before any secret is touched) per peer
# address. Every unverified request costs one control-plane call out of a
# budget the server meters per enclave, so without this a flood of invented
# keys from one address takes the enclave down for every owner. Verified
# requests are never counted: a busy fleet behind one address is unaffected.
AUTH_FAILURES_PER_PEER_PER_MINUTE = 30
_AUTH_FAILURE_STATUSES = frozenset({401, 403})


class BrokerError(Exception):
    """A refusal to return to the agent. ``code`` is a fixed, safe string."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


def _unauthorized() -> BrokerError:
    return BrokerError(401, "invalid_api_key")


def _forbidden() -> BrokerError:
    return BrokerError(403, "forbidden")


def _store_error() -> BrokerError:
    return BrokerError(502, "store_error")


def _rate_limited() -> BrokerError:
    return BrokerError(429, "rate_limited")


class _KmsRateLimitedError(Exception):
    pass


def canonical_secret_id(value: object) -> str:
    """``value`` if it is a UUID in canonical lowercase form, else 400."""
    try:
        parsed = uuid.UUID(value) if isinstance(value, str) else None
    except ValueError:
        parsed = None
    if parsed is None or str(parsed) != value:
        raise BrokerError(400, "invalid_secret_id")
    return value


@dataclass(frozen=True, slots=True)
class _Verified:
    """Everything a receipt says about who authorized an action."""

    secret_id: str
    owner_id: str
    owner_fp: str
    envelope_version: int
    grant_iat: int


class Broker:
    """Verifies, unwraps, executes and receipts agent requests."""

    def __init__(
        self,
        *,
        client: ControlPlaneClient,
        decrypter: DekDecrypter,
        executor: EgressExecutor,
        receipts: ReceiptLog,
        clock: TrustedClock,
        cache: MonotonicCache | None = None,
        deks: DekCache | None = None,
        limiter: RateLimiter | None = None,
    ) -> None:
        self._client = client
        self._decrypter = decrypter
        self._executor = executor
        self._receipts = receipts
        self._clock = clock
        self._cache = cache or MonotonicCache()
        self._deks = deks or DekCache()
        self._limiter = limiter or RateLimiter()

    async def handle(
        self, raw_key: str, secret_id: str, request: AgentRequest, *, peer: str = ""
    ) -> EgressResult:
        """Run one request. Raises :class:`BrokerError`.

        ``peer`` is the agent's network address as the transport saw it; it
        only meters refused authorizations and is never trusted for anything.
        """
        peer_key = ("peer", peer)
        if self._limiter.count(peer_key) >= AUTH_FAILURES_PER_PEER_PER_MINUTE:
            raise _rate_limited()
        try:
            key, secret_id, grant, floor = await self._authorize(raw_key, secret_id)
        except BrokerError as exc:
            if exc.status in _AUTH_FAILURE_STATUSES:
                self._limiter.acquire(peer_key, AUTH_FAILURES_PER_PEER_PER_MINUTE)
            raise
        envelope = await self._verified_envelope(key, grant, secret_id)  # 7-8
        policy = self._policy(envelope)
        if not self._limiter.acquire(
            ("policy", key.fingerprint, secret_id), policy.limits.rpm
        ):
            raise _rate_limited()
        plaintext = await self._open(key, grant, envelope, secret_id, floor)  # 9
        verified = _Verified(
            secret_id=secret_id,
            owner_id=envelope.owner_id,
            owner_fp=key.fingerprint.hex(),
            envelope_version=envelope.version,
            grant_iat=grant.iat,
        )
        return await self._execute(policy, plaintext, request, verified)  # 10

    async def _authorize(
        self, raw_key: str, secret_id: str
    ) -> tuple[ApiKey, str, Grant, int]:
        """Steps 1-6: the key, the canonical secret id, its grant and floor."""
        try:
            key = ApiKey.parse(raw_key)  # 1
        except ApiKeyError:
            raise _unauthorized() from None
        secret_id = canonical_secret_id(secret_id)
        try:
            self._receipts.check_available()
        except ReceiptLogUnavailableError as exc:
            logger.error("refusing request: %s", exc)
            raise BrokerError(503, "receipts_unavailable") from None

        now = self._clock.now()
        grant = await self._verified_grant(key, secret_id, now=now)  # 2-5
        try:
            floor = grant.min_version_for(secret_id)  # 6
        except GrantError:
            raise _forbidden() from None
        return key, secret_id, grant, floor

    async def _verified_grant(self, key: ApiKey, secret_id: str, *, now: int) -> Grant:
        try:
            raw = await self._client.fetch_grant(key.lookup_hash, secret_id)
        except ControlPlaneNotFoundError:
            raise _forbidden() from None
        except ControlPlaneError as exc:
            logger.warning("grant fetch failed: %s", exc)
            raise _store_error() from None
        try:
            wire = load_json_object(raw)
        except CanonicalJSONError:
            raise _store_error() from None
        if set(wire) != {"grant"}:
            raise _store_error()
        try:
            grant = Grant.from_dict(wire["grant"])
            verify_grant(grant, key, now=now)
        except GrantError as exc:
            logger.info("grant rejected: %s", type(exc).__name__)
            raise _forbidden() from None
        if not self._limiter.acquire(
            ("owner", key.fingerprint), REQUESTS_PER_OWNER_PER_MINUTE
        ):
            raise _rate_limited()
        try:
            self._cache.observe(key.fingerprint, "grant", key.lookup_hash, grant.iat)
        except StaleError:
            logger.warning("grant rollback refused")
            raise _forbidden() from None
        return grant

    async def _verified_envelope(
        self, key: ApiKey, grant: Grant, secret_id: str
    ) -> Envelope:
        try:
            envelope = Envelope.from_json(await self._client.fetch_envelope(secret_id))
            if not hmac.compare_digest(envelope.owner_pk, grant.owner_pk):
                raise EnvelopeError("envelope owner does not match the grant")
            # Checked before the cache records a version under ``secret_id``,
            # so another of the owner's envelopes cannot raise its floor.
            if envelope.secret_id != secret_id:
                raise EnvelopeError("envelope belongs to another secret")
            verify_envelope_signature(envelope)
            self._cache.observe(
                key.fingerprint, "envelope", secret_id, envelope.version
            )
        except (ControlPlaneError, EnvelopeError, StaleError) as exc:
            logger.warning("envelope rejected: %s", type(exc).__name__)
            raise _store_error() from None
        return envelope

    def _policy(self, envelope: Envelope) -> InjectionPolicy:
        try:
            require_key_version(envelope.kms_key_version, self._decrypter.key_version)
            return InjectionPolicy.model_validate(envelope.policy)
        except (KmsError, ValidationError) as exc:
            logger.warning("envelope unusable: %s", type(exc).__name__)
            raise _store_error() from None

    async def _open(
        self,
        key: ApiKey,
        grant: Grant,
        envelope: Envelope,
        secret_id: str,
        floor: int,
    ) -> bytearray:
        try:
            plaintext, _ = await asyncio.to_thread(
                open_with_dek_unwrapper,
                envelope,
                self._unwrapper(envelope, key.fingerprint),
                expected_secret_id=secret_id,
                expected_owner_pk=grant.owner_pk,
                min_version=floor,
            )
        except _KmsRateLimitedError:
            raise _rate_limited() from None
        except (EnvelopeError, KmsError) as exc:
            logger.warning("envelope open failed: %s", type(exc).__name__)
            raise _store_error() from None
        # ``plaintext`` is immutable and cannot be wiped; keep only this copy.
        return bytearray(plaintext)

    def _unwrapper(
        self, envelope: Envelope, owner_fp: bytes
    ) -> Callable[[bytes], bytes]:
        cache_key = dek_cache_key(envelope)

        def unwrap(wrapped: bytes) -> bytes:
            cached = self._deks.get(cache_key)
            if cached is not None:
                return cached
            if not self._limiter.acquire(
                ("kms", owner_fp), KMS_UNWRAPS_PER_OWNER_PER_MINUTE
            ):
                raise _KmsRateLimitedError
            dek = self._decrypter.unwrap(wrapped)
            self._deks.put(cache_key, dek)
            return dek

        return unwrap

    async def _execute(
        self,
        policy: InjectionPolicy,
        secret: bytearray,
        request: AgentRequest,
        verified: _Verified,
    ) -> EgressResult:
        try:
            result = await self._executor.execute(policy, secret, request)
        except EgressDenied as exc:
            self._receipt(verified, "denied", exc.code, None)
            raise BrokerError(403, f"egress_denied:{exc.code}") from None
        except EgressError as exc:
            self._receipt(verified, "error", exc.code, exc.metadata)
            raise BrokerError(502, f"egress_failed:{exc.code}") from None
        finally:
            secure_zero(secret)
        self._receipt(verified, "ok", None, result.metadata)
        return result

    def _receipt(
        self,
        verified: _Verified,
        outcome: str,
        code: str | None,
        metadata: ReceiptMetadata | None,
    ) -> None:
        payload: dict[str, Any] = {
            "v": RECEIPT_PAYLOAD_VERSION,
            "ts": self._clock.now(),
            "secret_id": verified.secret_id,
            "owner_id": verified.owner_id,
            "owner_fp": verified.owner_fp,
            "envelope_version": verified.envelope_version,
            "grant_iat": verified.grant_iat,
            "outcome": outcome,
        }
        if code is not None:
            payload["code"] = code
        if metadata is not None:
            payload["request"] = {
                "method": metadata.method,
                "host": metadata.host,
                "path_hash": metadata.path_hash,
                "bytes_out": metadata.bytes_out,
                "bytes_in": metadata.bytes_in,
                "redactions": metadata.redactions,
                **({"status": metadata.status} if metadata.status is not None else {}),
            }
        self._receipts.append(payload)
