"""Confidential Space attestation tokens, checked on the client.

A token is accepted only if all of these hold:

- RS256, signed by Google's Confidential Space JWKS (issuer
  ``https://confidentialcomputing.googleapis.com``), or, with the loudly
  labelled ``--insecure-mock`` option only, by a mock key the user supplies
  for the ``mock://local`` issuer. Each mode refuses the other's issuer.
- ``aud`` is one of the expected audiences and ``eat_nonce`` holds the
  expected nonce.
- ``swname`` is ``CONFIDENTIAL_SPACE``, ``hwmodel`` is allowed, ``dbgstat``
  is ``disabled-since-boot``, ``secboot`` is true and the Confidential Space
  image carries the ``STABLE`` support attribute.
- ``submods.container.image_digest`` is in the user's allowlist.

What is *not* checked: any release signature (Sigstore/cosign, Rekor).
Digests come only from ``--allow-digest``; the user compares them against
the CI build output themselves. Without one, verification refuses to run.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Collection
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt

from carapace_cli.errors import VerificationError

GOOGLE_ISSUER = "https://confidentialcomputing.googleapis.com"
GOOGLE_DISCOVERY_URL = f"{GOOGLE_ISSUER}/.well-known/openid-configuration"
GOOGLE_JWKS_HOST_SUFFIX = ".googleapis.com"
MOCK_ISSUER = "mock://local"
ATTESTATION_AUDIENCE = "carapace-attestation"
ALGORITHM = "RS256"
REQUIRED_CLAIMS = ("exp", "iat", "iss", "aud", "eat_nonce")
ALLOWED_HWMODELS = frozenset({"GCP_AMD_SEV"})
REQUIRED_SUPPORT_ATTRIBUTE = "STABLE"
LEEWAY_SECONDS = 60
IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
FETCH_TIMEOUT_SECONDS = 15.0
MAX_FETCH_BYTES = 256 * 1024

COSIGN_NOT_VERIFIED_NOTICE = (
    "NOTE: this version of the CLI does not verify release signatures "
    "(cosign/Rekor). Only the digests you pass with --allow-digest are "
    "trusted: compare each one against the digest printed by the release "
    "build in CI before passing it."
)
INSECURE_MOCK_BANNER = (
    "!!! INSECURE MOCK MODE: trusting a locally supplied attestation key for "
    "issuer mock://local. This proves NOTHING about hardware or code. "
    "Never use it with real secrets. !!!"
)

JwksFetcher = Callable[[], dict[str, Any]]


def validate_digest(digest: str) -> str:
    if not IMAGE_DIGEST_PATTERN.match(digest):
        raise VerificationError(f"image digest must be sha256:<64 hex>: {digest!r}")
    return digest


@dataclass(frozen=True)
class TrustPolicy:
    """What the user trusts: image digests and one attestation issuer.

    ``mock_key_pem`` set means insecure mock mode: only ``mock://local``
    tokens signed by that key are accepted. Otherwise only Google's issuer
    is, with keys from ``jwks_fetcher`` (default: Google's live JWKS).
    """

    allowed_digests: frozenset[str]
    mock_key_pem: str | None = None
    jwks_fetcher: JwksFetcher | None = field(default=None, compare=False)

    def __post_init__(self) -> None:
        if not self.allowed_digests:
            raise VerificationError("no trusted image digests: pass --allow-digest")
        for digest in self.allowed_digests:
            validate_digest(digest)

    @property
    def insecure_mock(self) -> bool:
        return self.mock_key_pem is not None


@dataclass(frozen=True)
class AttestedClaims:
    issuer: str
    image_digest: str
    hwmodel: str
    iat: int
    exp: int


def verify_attestation_token(
    token: str,
    policy: TrustPolicy,
    *,
    audiences: Collection[str],
    nonce: str,
    check_expiry: bool = True,
) -> AttestedClaims:
    """Check signature, issuer, audience, nonce, claims and image digest.

    ``check_expiry=False`` is for auditing past boots, whose tokens have
    long expired; everything else is still checked.

    Raises:
        VerificationError: On any failure.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise VerificationError(f"malformed attestation token: {exc}") from None
    if header.get("alg") != ALGORITHM:
        raise VerificationError("attestation token must be RS256")
    issuer, key = _issuer_and_key(token, header, policy)
    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[ALGORITHM],
            audience=list(audiences),
            issuer=issuer,
            leeway=LEEWAY_SECONDS,
            options={"require": list(REQUIRED_CLAIMS), "verify_exp": check_expiry},
        )
    except jwt.PyJWTError as exc:
        raise VerificationError(f"attestation token rejected: {exc}") from None
    _check_nonce(claims.get("eat_nonce"), nonce)
    return _check_claims(claims, policy)


def _issuer_and_key(
    token: str, header: dict[str, Any], policy: TrustPolicy
) -> tuple[str, Any]:
    try:
        unverified_iss = jwt.decode(token, options={"verify_signature": False}).get(
            "iss"
        )
    except jwt.PyJWTError as exc:
        raise VerificationError(f"malformed attestation token: {exc}") from None
    if policy.mock_key_pem is not None:
        if unverified_iss != MOCK_ISSUER:
            raise VerificationError(
                "--insecure-mock accepts only the mock://local issuer; "
                f"refusing token from {unverified_iss!r}"
            )
        return MOCK_ISSUER, policy.mock_key_pem
    if unverified_iss != GOOGLE_ISSUER:
        raise VerificationError(
            f"untrusted attestation issuer {unverified_iss!r}"
            + (" (mock tokens need --insecure-mock)" if unverified_iss else "")
        )
    kid = header.get("kid")
    if not isinstance(kid, str):
        raise VerificationError("attestation token has no key id")
    fetch = policy.jwks_fetcher or fetch_google_jwks
    try:
        jwks = jwt.PyJWKSet.from_dict(fetch())
    except jwt.PyJWTError as exc:
        raise VerificationError(f"invalid Google JWKS: {exc}") from None
    for jwk in jwks.keys:
        if jwk.key_id == kid:
            return GOOGLE_ISSUER, jwk.key
    raise VerificationError("attestation token key id is not in Google's JWKS")


def _check_nonce(value: Any, expected: str) -> None:
    nonces = value if isinstance(value, list) else [value]
    if expected not in nonces:
        raise VerificationError("attestation nonce does not match")


def _check_claims(claims: dict[str, Any], policy: TrustPolicy) -> AttestedClaims:
    if claims.get("swname") != "CONFIDENTIAL_SPACE":
        raise VerificationError("not a Confidential Space workload")
    hwmodel = claims.get("hwmodel")
    if hwmodel not in ALLOWED_HWMODELS:
        raise VerificationError(f"hardware model {hwmodel!r} is not allowed")
    if claims.get("dbgstat") != "disabled-since-boot":
        raise VerificationError("the workload is debuggable")
    if claims.get("secboot") is not True:
        raise VerificationError("secure boot is not enabled")
    submods = claims.get("submods")
    if not isinstance(submods, dict):
        raise VerificationError("attestation token has no submods")
    space = submods.get("confidential_space")
    attributes = space.get("support_attributes") if isinstance(space, dict) else None
    if not isinstance(attributes, list) or REQUIRED_SUPPORT_ATTRIBUTE not in attributes:
        raise VerificationError("the Confidential Space image is not STABLE")
    container = submods.get("container")
    digest = container.get("image_digest") if isinstance(container, dict) else None
    if not isinstance(digest, str) or digest not in policy.allowed_digests:
        raise VerificationError(f"image digest {digest!r} is not in the allowlist")
    return AttestedClaims(
        issuer=claims["iss"],
        image_digest=digest,
        hwmodel=hwmodel,
        iat=int(claims["iat"]),
        exp=int(claims["exp"]),
    )


# -- fetching --------------------------------------------------------------------


def fetch_google_jwks() -> dict[str, Any]:
    """Google's Confidential Space JWKS, via OIDC discovery over web PKI."""
    discovery = _fetch_json(GOOGLE_DISCOVERY_URL)
    jwks_uri = discovery.get("jwks_uri")
    parts = urlsplit(jwks_uri) if isinstance(jwks_uri, str) else None
    if (
        parts is None
        or parts.scheme != "https"
        or not (parts.hostname or "").endswith(GOOGLE_JWKS_HOST_SUFFIX)
    ):
        raise VerificationError("unexpected jwks_uri in Google's discovery document")
    return _fetch_json(jwks_uri)


def _fetch_json(url: str) -> dict[str, Any]:
    try:
        with (
            httpx.Client(timeout=FETCH_TIMEOUT_SECONDS, trust_env=False) as client,
            client.stream("GET", url) as response,
        ):
            if not response.is_success:
                raise VerificationError(f"GET {url} returned {response.status_code}")
            body = _read_limited(response)
    except httpx.HTTPError as exc:
        raise VerificationError(f"cannot fetch {url}: {type(exc).__name__}") from None
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise VerificationError(f"{url} did not return JSON") from None
    if not isinstance(value, dict):
        raise VerificationError(f"{url} did not return a JSON object")
    return value


def _read_limited(response: httpx.Response) -> bytes:
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_bytes():
        size += len(chunk)
        if size > MAX_FETCH_BYTES:
            raise VerificationError("response too large")
        chunks.append(chunk)
    return b"".join(chunks)
