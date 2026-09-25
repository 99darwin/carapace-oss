"""Verification of Confidential Space attestation tokens.

Enclaves authenticate to ``/internal/*`` with the OIDC token Confidential
Space issues for a custom audience (this server's ``public_url``). A token is
accepted only if it is signed by the configured issuer and its claims match
what the infrastructure's KMS policy requires: production Confidential Space
image, allowed hardware, debugging disabled since boot, Secure Boot, an
allowed container image digest and, when configured, the expected project and
service account.

The mock issuer (``mock://local``) verifies against a configured public key
instead of Google's JWKS. Config refuses it outside dev mode; this module
checks again so a misconfigured verifier cannot accept it either.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from carapace_server.config import MOCK_ATTESTATION_ISSUER, Settings

logger = logging.getLogger(__name__)

DISCOVERY_URL = (
    "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration"
)
TOKEN_ALGORITHM = "RS256"  # noqa: S105 - JWS algorithm name
MAX_TOKEN_BYTES = 16 * 1024
CLOCK_SKEW_SECONDS = 30
JWKS_TTL_SECONDS = 3600
JWKS_MIN_REFRESH_SECONDS = 60
HTTP_TIMEOUT_SECONDS = 10

EXPECTED_SWNAME = "CONFIDENTIAL_SPACE"
EXPECTED_DBGSTAT = "disabled-since-boot"
REQUIRED_SUPPORT_ATTRIBUTE = "STABLE"
REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "eat_nonce"]

FetchJson = Callable[[str], Awaitable[dict[str, Any]]]


class AttestationError(Exception):
    """The token is not an acceptable attestation. Safe to log, not to echo."""


@dataclass(frozen=True)
class Attestation:
    token: str
    nonces: tuple[str, ...]
    image_digest: str


async def fetch_json_https(url: str) -> dict[str, Any]:
    if not url.startswith("https://"):
        raise AttestationError("refusing non-https key discovery URL")
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


class JwksCache:
    """Google's signing keys, cached, refetched on expiry or an unknown kid.

    Fetches are throttled on every attempt, successful or not, so tokens
    with made-up key IDs cause at most one fetch per minute, and requests
    waiting on the lock skip a refresh another request just made. A failed
    refresh keeps serving the keys already held.
    """

    def __init__(self, fetch_json: FetchJson, discovery_url: str) -> None:
        self._fetch_json = fetch_json
        self._discovery_url = discovery_url
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at = float("-inf")
        self._attempted_at = float("-inf")
        self._lock = asyncio.Lock()

    def _needs_refresh(self, kid: str) -> bool:
        now = time.monotonic()
        if now - self._attempted_at <= JWKS_MIN_REFRESH_SECONDS:
            return False
        stale = now - self._fetched_at > JWKS_TTL_SECONDS
        return stale or kid not in self._keys

    async def get(self, kid: str) -> jwt.PyJWK:
        if self._needs_refresh(kid):
            async with self._lock:
                # Another request may have refreshed while we waited.
                if self._needs_refresh(kid):
                    await self._refresh()
        key = self._keys.get(kid)
        if key is None:
            raise AttestationError("unknown signing key")
        return key

    async def _refresh(self) -> None:
        self._attempted_at = time.monotonic()
        try:
            discovery = await self._fetch_json(self._discovery_url)
            jwks = await self._fetch_json(discovery["jwks_uri"])
            keys = jwt.PyJWKSet.from_dict(jwks).keys
        except (httpx.HTTPError, KeyError, TypeError, ValueError, jwt.PyJWTError) as e:
            logger.warning("attestation key refresh failed: %s", type(e).__name__)
            return
        self._keys = {k.key_id: k for k in keys if k.key_id}
        self._fetched_at = time.monotonic()


class AttestationVerifier:
    def __init__(
        self,
        settings: Settings,
        fetch_json: FetchJson = fetch_json_https,
        discovery_url: str = DISCOVERY_URL,
    ) -> None:
        self._settings = settings
        self._jwks = JwksCache(fetch_json, discovery_url)

    async def verify(self, token: str) -> Attestation:
        """Verify signature and claims. Every failure is an AttestationError."""
        try:
            return await self._verify(token)
        except (jwt.PyJWTError, ValueError) as exc:
            raise AttestationError(f"invalid token: {type(exc).__name__}") from exc

    async def _verify(self, token: str) -> Attestation:
        if len(token) > MAX_TOKEN_BYTES:
            raise AttestationError("token too large")
        claims = jwt.decode(
            token,
            await self._signing_key(token),
            algorithms=[TOKEN_ALGORITHM],
            audience=self._settings.public_url,
            issuer=self._settings.attestation_issuer,
            leeway=CLOCK_SKEW_SECONDS,
            options={"require": REQUIRED_CLAIMS},
        )
        return Attestation(
            token=token,
            nonces=_nonces(claims),
            image_digest=self._check_claims(claims),
        )

    async def _signing_key(self, token: str) -> Any:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != TOKEN_ALGORITHM:
            raise AttestationError("unexpected token algorithm")
        if self._settings.attestation_issuer == MOCK_ATTESTATION_ISSUER:
            if self._settings.mode != "dev":
                raise AttestationError("mock issuer outside dev mode")
            pem = self._settings.mock_attestation_public_key_pem or ""
            return load_pem_public_key(pem.encode())
        kid = header.get("kid")
        if not isinstance(kid, str):
            raise AttestationError("token has no key id")
        return await self._jwks.get(kid)

    def _check_claims(self, claims: dict[str, Any]) -> str:
        """Check platform claims and return the container image digest."""
        settings = self._settings
        submods = _mapping(claims.get("submods"))
        support = _mapping(submods.get("confidential_space")).get("support_attributes")
        digest = _mapping(submods.get("container")).get("image_digest")
        checks = (
            (claims.get("swname") == EXPECTED_SWNAME, "swname"),
            (claims.get("hwmodel") in settings.allowed_hwmodels, "hwmodel"),
            (claims.get("dbgstat") == EXPECTED_DBGSTAT, "dbgstat"),
            (claims.get("secboot") is True, "secboot"),
            (
                isinstance(support, list) and REQUIRED_SUPPORT_ATTRIBUTE in support,
                "support_attributes",
            ),
            (digest in settings.allowed_image_digests, "image_digest"),
        )
        for ok, name in checks:
            if not ok:
                raise AttestationError(f"claim rejected: {name}")
        if settings.attestation_project_id is not None:
            project = _mapping(submods.get("gce")).get("project_id")
            if project != settings.attestation_project_id:
                raise AttestationError("claim rejected: project_id")
        if settings.attestation_service_account is not None:
            accounts = claims.get("google_service_accounts")
            if not isinstance(accounts, list) or (
                settings.attestation_service_account not in accounts
            ):
                raise AttestationError("claim rejected: google_service_accounts")
        return digest


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _nonces(claims: dict[str, Any]) -> tuple[str, ...]:
    raw = claims.get("eat_nonce")
    values = [raw] if isinstance(raw, str) else raw
    if not isinstance(values, list) or not values:
        raise AttestationError("claim rejected: eat_nonce")
    if not all(isinstance(v, str) for v in values):
        raise AttestationError("claim rejected: eat_nonce")
    return tuple(values)
