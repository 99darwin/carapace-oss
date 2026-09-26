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
- For each deployment identity value the policy sets, the matching claim is
  present and equal: ``submods.gce.project_id``, the enclave service account
  in ``google_service_accounts``, and the container env's
  ``CONTROL_PLANE_URL`` (compared as normalised URLs) and ``KMS_KEY_NAME``.
  Without them, any genuine Confidential Space VM running an allowed digest
  passes, whichever project or deployment it belongs to.

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
from carapace_crypto.kms import is_kms_key_version_name

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
# GCP project ids: 6-30 chars, lowercase letters, digits and hyphens.
PROJECT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
SERVICE_ACCOUNT_PATTERN = re.compile(r"^[a-z0-9-]{6,30}@[a-z0-9.-]+$")
# Launch-time env overrides the enclave reads (enclave/.../runtime.py).
CONTROL_PLANE_URL_ENV = "CONTROL_PLANE_URL"
KMS_KEY_NAME_ENV = "KMS_KEY_NAME"
DEFAULT_PORTS = {"https": 443, "http": 80}
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


def canonical_url(url: str) -> str:
    """``url`` with a lowercase scheme and host, no default port, no slash.

    Raises:
        VerificationError: Not a plain http(s) base URL.
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise VerificationError(f"invalid URL {url!r}") from None
    scheme, host = parts.scheme.lower(), parts.hostname
    if scheme not in DEFAULT_PORTS or not host:
        raise VerificationError(f"invalid URL {url!r}")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise VerificationError(f"URL must be a plain base URL: {url!r}")
    if ":" in host:
        # ``hostname`` strips the brackets of an IPv6 literal. Without them
        # ``[::1]:8443`` and ``[::1:8443]`` (another address, port 443)
        # would canonicalise to the same string.
        host = f"[{host}]"
    netloc = host if port in (None, DEFAULT_PORTS[scheme]) else f"{host}:{port}"
    return f"{scheme}://{netloc}{parts.path.rstrip('/')}"


@dataclass(frozen=True)
class TrustPolicy:
    """What the user trusts: image digests, one issuer, one deployment.

    ``mock_key_pem`` set means insecure mock mode: only ``mock://local``
    tokens signed by that key are accepted. Otherwise only Google's issuer
    is, with keys from ``jwks_fetcher`` (default: Google's live JWKS).

    The deployment identity fields are optional here (a digest-only policy
    is valid for callers that pin the deployment another way), but each one
    that is set must match its claim or the token is refused.
    ``kms_key_name`` is the full ``.../cryptoKeyVersions/N`` name the
    enclave is launched with as ``KMS_KEY_NAME``.
    """

    allowed_digests: frozenset[str]
    mock_key_pem: str | None = None
    jwks_fetcher: JwksFetcher | None = field(default=None, compare=False)
    project_id: str | None = None
    service_account: str | None = None
    control_plane_url: str | None = None
    kms_key_name: str | None = None

    def __post_init__(self) -> None:
        if not self.allowed_digests:
            raise VerificationError("no trusted image digests: pass --allow-digest")
        for digest in self.allowed_digests:
            validate_digest(digest)
        if self.project_id is not None and not PROJECT_ID_PATTERN.fullmatch(
            self.project_id
        ):
            raise VerificationError(f"{self.project_id!r} is not a GCP project id")
        if self.service_account is not None and not SERVICE_ACCOUNT_PATTERN.fullmatch(
            self.service_account
        ):
            raise VerificationError(
                f"{self.service_account!r} is not a service account email"
            )
        if self.control_plane_url is not None:
            object.__setattr__(
                self, "control_plane_url", canonical_url(self.control_plane_url)
            )
        if self.kms_key_name is not None and not is_kms_key_version_name(
            self.kms_key_name
        ):
            raise VerificationError(
                f"{self.kms_key_name!r} is not a KMS key version name "
                "(projects/.../cryptoKeys/.../cryptoKeyVersions/N)"
            )

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
    _check_identity(claims, submods, container, policy)
    return AttestedClaims(
        issuer=claims["iss"],
        image_digest=digest,
        hwmodel=hwmodel,
        iat=int(claims["iat"]),
        exp=int(claims["exp"]),
    )


def _check_identity(
    claims: dict[str, Any],
    submods: dict[str, Any],
    container: dict[str, Any],
    policy: TrustPolicy,
) -> None:
    """Refuse a token from another deployment. Unset fields are not checked."""
    if policy.project_id is not None:
        gce = submods.get("gce")
        project = gce.get("project_id") if isinstance(gce, dict) else None
        _require_equal("GCP project", project, policy.project_id)
    if policy.service_account is not None:
        accounts = claims.get("google_service_accounts")
        if not isinstance(accounts, list) or policy.service_account not in accounts:
            raise VerificationError(
                f"the enclave does not run as {policy.service_account!r} "
                f"(google_service_accounts: {accounts!r})"
            )
    env = container.get("env")
    if policy.control_plane_url is not None:
        url = env.get(CONTROL_PLANE_URL_ENV) if isinstance(env, dict) else None
        try:
            attested = canonical_url(url) if isinstance(url, str) else None
        except VerificationError:
            attested = None
        _require_equal("control plane URL", attested, policy.control_plane_url)
    if policy.kms_key_name is not None:
        key = env.get(KMS_KEY_NAME_ENV) if isinstance(env, dict) else None
        if not is_kms_key_version_name(key):
            key = None
        _require_equal("KMS key", key, policy.kms_key_name)


def _require_equal(what: str, attested: object, expected: str) -> None:
    if attested is None:
        raise VerificationError(
            f"the attestation token does not state the enclave's {what}; "
            f"expected {expected!r}"
        )
    if attested != expected:
        raise VerificationError(
            f"the enclave's {what} is {attested!r}, not {expected!r}"
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
