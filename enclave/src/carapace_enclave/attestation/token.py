"""Confidential Space attestation tokens from the TEE launcher.

The launcher serves ``POST /v1/token`` on a Unix socket inside the VM and
answers with a Google-signed OIDC token whose ``aud`` and ``eat_nonce`` are
the ones requested. Every token this enclave requests carries its boot id
(see :mod:`carapace_enclave.attestation.identity`) as the only nonce.

Three audiences are in use and must never be mixed, because every token
the enclave hands out is effectively public:

- ``carapace-attestation`` for the token served at ``GET /attestation``;
- the control-plane URL for tokens sent to the server's ``/internal`` API;
- ``WIF_AUDIENCE`` for tokens exchanged at Google STS for KMS access.

If the WIF audience equalled either of the others, anyone who fetched a
published token could exchange it for KMS decrypt access.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from carapace_crypto import b64_decode, load_json_object
from carapace_enclave.clock import TrustedClock

LAUNCHER_SOCKET = "/run/container_launcher/teeserver.sock"
LAUNCHER_TOKEN_PATH = "/v1/token"  # noqa: S105 - a path
LAUNCHER_TIMEOUT_SECONDS = 10.0
ATTESTATION_AUDIENCE = "carapace-attestation"
# The launcher's default audience; STS accepts it unless the provider pins
# its own, so it must never be requested or accepted as the WIF audience.
LAUNCHER_DEFAULT_AUDIENCE = "https://sts.googleapis.com"
FORBIDDEN_WIF_AUDIENCES = frozenset({ATTESTATION_AUDIENCE, LAUNCHER_DEFAULT_AUDIENCE})

# Confidential Space accepts up to six nonces of 10 to 74 bytes each.
MIN_NONCE_LENGTH = 10
MAX_NONCE_LENGTH = 74
MAX_TOKEN_BYTES = 64 * 1024
# Launcher tokens live about an hour. Refresh well before that: the design
# requires a fresh token (and clock floor) at least hourly.
REFRESH_AFTER_SECONDS = 30 * 60
MIN_REMAINING_SECONDS = 5 * 60


class AttestationError(Exception):
    """A token could not be obtained or does not match what was requested.

    Messages name a claim or an HTTP status, never token contents.
    """


@dataclass(frozen=True, slots=True, repr=False)
class AttestationToken:
    raw: str
    audience: str
    nonces: tuple[str, ...]
    iat: int
    exp: int

    def __repr__(self) -> str:
        return f"AttestationToken(audience={self.audience!r}, iat={self.iat})"


def validate_audiences(*, control_plane_url: str, wif_audience: str) -> None:
    """Refuse any configuration in which two token audiences coincide.

    Raises:
        AttestationError: If the audiences overlap or the WIF audience is one
            that published tokens carry.
    """
    parts = urlsplit(control_plane_url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise AttestationError("control-plane URL must be an http(s) URL")
    if not wif_audience:
        raise AttestationError("WIF audience is required")
    if wif_audience in FORBIDDEN_WIF_AUDIENCES:
        raise AttestationError("WIF audience must not be a published audience")
    if wif_audience == control_plane_url:
        raise AttestationError("WIF audience must differ from the control-plane URL")
    if control_plane_url in FORBIDDEN_WIF_AUDIENCES:
        raise AttestationError("control-plane URL collides with a reserved audience")


def _validate_nonce(nonce: str) -> str:
    if not isinstance(nonce, str) or not nonce.isascii():
        raise AttestationError("nonce must be an ASCII string")
    if not MIN_NONCE_LENGTH <= len(nonce) <= MAX_NONCE_LENGTH:
        raise AttestationError("nonce length is outside launcher limits")
    return nonce


def token_claims(raw: str) -> dict[str, Any]:
    """Decode a JWT payload *without* verifying its signature.

    Only for tokens that came straight from the launcher, which is part of
    the trusted computing base. Relying parties verify signatures themselves.
    """
    parts = raw.split(".")
    if len(parts) != 3 or not all(parts):
        raise AttestationError("token is not a JWT")
    try:
        return load_json_object(b64_decode(parts[1]))
    except ValueError:  # CanonicalJSONError and binascii.Error included
        raise AttestationError("token payload is not a JSON object") from None


def _int_claim(claims: dict[str, Any], name: str) -> int:
    value = claims.get(name)
    if type(value) is not int or value < 0:
        raise AttestationError(f"claim rejected: {name}")
    return value


def check_token(raw: str, *, audience: str, nonce: str) -> AttestationToken:
    """Check that a launcher token is the one requested.

    Raises:
        AttestationError: If ``aud`` or ``eat_nonce`` differ from the request,
            or ``iat``/``exp`` are malformed.
    """
    claims = token_claims(raw)
    if claims.get("aud") != audience:
        raise AttestationError("claim rejected: aud")
    raw_nonces = claims.get("eat_nonce")
    nonces = (raw_nonces,) if isinstance(raw_nonces, str) else raw_nonces
    if not isinstance(nonces, list | tuple) or nonce not in nonces:
        raise AttestationError("claim rejected: eat_nonce")
    iat, exp = _int_claim(claims, "iat"), _int_claim(claims, "exp")
    if exp <= iat:
        raise AttestationError("claim rejected: exp")
    return AttestationToken(
        raw=raw, audience=audience, nonces=tuple(nonces), iat=iat, exp=exp
    )


class LauncherClient:
    """Talks to the Confidential Space launcher over its Unix socket.

    ``transport`` replaces the socket in tests and in the dev mock.
    """

    def __init__(
        self,
        transport: httpx.BaseTransport | None = None,
        *,
        socket_path: str = LAUNCHER_SOCKET,
        timeout: float = LAUNCHER_TIMEOUT_SECONDS,
    ) -> None:
        self._client = httpx.Client(
            transport=transport or httpx.HTTPTransport(uds=socket_path, retries=0),
            base_url="http://localhost",
            timeout=timeout,
            trust_env=False,
        )

    def fetch(self, audience: str, nonces: Sequence[str]) -> str:
        """Return a raw token for ``audience`` carrying exactly ``nonces``."""
        body = {
            "audience": audience,
            "token_type": "OIDC",
            "nonces": [_validate_nonce(n) for n in nonces],
        }
        try:
            response = self._client.post(LAUNCHER_TOKEN_PATH, json=body)
        except httpx.HTTPError as exc:
            raise AttestationError(
                f"launcher unreachable: {type(exc).__name__}"
            ) from None
        if response.status_code != httpx.codes.OK:
            raise AttestationError(f"launcher returned HTTP {response.status_code}")
        if len(response.content) > MAX_TOKEN_BYTES:
            raise AttestationError("launcher token is too large")
        try:
            return response.content.decode("ascii").strip()
        except UnicodeDecodeError:
            raise AttestationError("launcher token is not ASCII") from None

    def close(self) -> None:
        self._client.close()


class TokenSource:
    """Validated, cached tokens per audience, all bound to one boot nonce.

    Every fetched token raises the :class:`TrustedClock` floor to its
    ``iat``. A token's age is measured on the monotonic clock, which the
    operator cannot set back the way it can set the wall clock.
    Thread-safe: google-auth calls :meth:`get` from worker threads.
    """

    def __init__(
        self,
        launcher: LauncherClient,
        clock: TrustedClock,
        *,
        nonce: str,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._launcher = launcher
        self._clock = clock
        self._nonce = _validate_nonce(nonce)
        self._monotonic = monotonic
        self._cache: dict[str, tuple[AttestationToken, float]] = {}
        self._lock = threading.Lock()

    @property
    def nonce(self) -> str:
        return self._nonce

    def _is_fresh(self, token: AttestationToken, fetched_at: float) -> bool:
        age = self._monotonic() - fetched_at
        return (
            age < REFRESH_AFTER_SECONDS
            and self._clock.now() < token.exp - MIN_REMAINING_SECONDS
        )

    def get(self, audience: str) -> AttestationToken:
        """A token for ``audience``, fetched anew when the cached one ages."""
        with self._lock:
            cached = self._cache.get(audience)
            if cached is not None and self._is_fresh(*cached):
                return cached[0]
            raw = self._launcher.fetch(audience, [self._nonce])
            token = check_token(raw, audience=audience, nonce=self._nonce)
            self._clock.observe_attested(token.iat)
            self._cache[audience] = (token, self._monotonic())
            return token

    def refresh_all(self) -> None:
        """Refetch every audience in use; keeps the clock floor current."""
        with self._lock:
            audiences = list(self._cache)
            self._cache.clear()
        for audience in audiences:
            self.get(audience)
