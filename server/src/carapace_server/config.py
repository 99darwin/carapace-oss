"""Server configuration.

Everything comes from ``CARAPACE_*`` environment variables. The default mode
is ``prod``, which refuses to start without an explicit database, JWT secret
and public URL. ``dev`` mode fills in local defaults, including a random
per-process JWT secret, so no secret value ever lives in source.
"""

from __future__ import annotations

import re
import secrets
from functools import lru_cache
from typing import Annotated, Any, Literal
from urllib.parse import urlparse

from pydantic import (
    DirectoryPath,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from carapace_crypto import EnvelopeError
from carapace_crypto.envelope import load_rsa_public_key
from carapace_crypto.kms import is_kms_key_version_name

MIN_JWT_SECRET_LENGTH = 32
MIN_PROD_BCRYPT_ROUNDS = 12
DEV_DATABASE_URL = "sqlite+aiosqlite:///./carapace-local.db"
DEV_PUBLIC_URL = "http://localhost:8000"
# Largest request body accepted. The default is well above the largest
# legitimate body (a sealed envelope is about 110 KiB; a batch of 100
# receipts with 16 KiB payloads about 1.7 MiB) and small enough that
# parsing one request cannot exhaust memory. The floor keeps an
# operator's override from rejecting every envelope.
DEFAULT_MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024
MIN_MAX_REQUEST_BODY_BYTES = 256 * 1024

GOOGLE_ATTESTATION_ISSUER = "https://confidentialcomputing.googleapis.com"
# Local mock enclave only. Never accepted outside dev mode.
MOCK_ATTESTATION_ISSUER = "mock://local"
IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

CommaList = Annotated[list[str], NoDecode]

PROD_REQUIRED_SETTINGS = (
    "database_url",
    "public_url",
    "jwt_secret",
    "allowed_image_digests",
    "attestation_project_id",
    "attestation_service_account",
)


class ConfigError(ValueError):
    """Raised when settings are missing or unsafe for the selected mode."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CARAPACE_", extra="ignore")

    mode: Literal["dev", "prod"] = "prod"
    database_url: str | None = None
    # Externally visible base URL, e.g. https://server.example.com. Also the
    # audience enclaves must request for their attestation tokens.
    public_url: str | None = None

    jwt_secret: SecretStr | None = None
    jwt_issuer: str = "carapace-server"
    jwt_audience: str = "carapace-api"
    access_token_minutes: int = Field(default=15, ge=1, le=60)
    refresh_token_days: int = Field(default=30, ge=1, le=90)

    bcrypt_rounds: int = Field(default=12, ge=4, le=16)
    webauthn_rp_id: str | None = None
    webauthn_rp_name: str = "Carapace"
    # Browser origin for passkey ceremonies; defaults to public_url.
    webauthn_origin: str | None = None

    # Enclave attestation (Confidential Space tokens on /internal/*). The
    # expected audience is public_url.
    attestation_issuer: str = GOOGLE_ATTESTATION_ISSUER
    allowed_image_digests: CommaList = Field(default_factory=list)
    allowed_hwmodels: CommaList = Field(default_factory=lambda: ["GCP_AMD_SEV"])
    # Pin tokens to one GCP project and enclave service account; the enclave
    # image is public, so anyone could otherwise run it and attest.
    attestation_project_id: str | None = None
    attestation_service_account: str | None = None
    mock_attestation_public_key_pem: str | None = None

    # The Cloud KMS public key clients seal envelopes to, served at
    # /v1/kms/public-key. Clients only use it if it matches the key the
    # attested enclave reports, so a wrong value here fails closed.
    kms_public_key_pem: str | None = None
    # Full projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/N
    # name, exactly as the enclave reports it.
    kms_key_version: str | None = None

    rate_limit_enabled: bool = True
    # How many X-Forwarded-For entries the trusted proxies in front of the
    # server append; each hop normally appends the address it accepted the
    # connection from (Cloud Run's frontend appends one, a Google external
    # load balancer before it two). Rate limits and session records then
    # key on that entry instead of the proxy's address. 0 keys on the peer
    # address and ignores the header entirely. See ``proxy.py``.
    trusted_proxy_hops: int = Field(default=0, ge=0)
    cleanup_interval_seconds: int = Field(default=3600, ge=10)
    max_request_body_bytes: int = Field(
        default=DEFAULT_MAX_REQUEST_BODY_BYTES, ge=MIN_MAX_REQUEST_BODY_BYTES
    )
    # Built web UI (``web/dist``). When set, it is served at ``/`` after
    # every API route; unset, the server is API-only.
    web_dir: DirectoryPath | None = None

    @field_validator("allowed_image_digests", "allowed_hwmodels", mode="before")
    @classmethod
    def _split_commas(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("allowed_image_digests")
    @classmethod
    def _check_digests(cls, value: list[str]) -> list[str]:
        bad = [d for d in value if not IMAGE_DIGEST_PATTERN.match(d)]
        if bad:
            raise ConfigError(f"image digests must be sha256:<64 hex>: {bad}")
        return value

    @field_validator("kms_public_key_pem")
    @classmethod
    def _check_kms_public_key(cls, value: str | None) -> str | None:
        if value is None:
            return value
        try:
            load_rsa_public_key(value)
        except EnvelopeError as exc:
            raise ConfigError(f"kms_public_key_pem: {exc}") from None
        return value

    @field_validator("kms_key_version")
    @classmethod
    def _check_kms_key_version(cls, value: str | None) -> str | None:
        if value is not None and not is_kms_key_version_name(value):
            raise ConfigError(
                "kms_key_version must be a full cryptoKeyVersions resource name"
            )
        return value

    @model_validator(mode="after")
    def _apply_mode(self) -> Settings:
        self._check_attestation_issuer()
        if (self.kms_public_key_pem is None) != (self.kms_key_version is None):
            raise ConfigError(
                "kms_public_key_pem and kms_key_version must be set together"
            )
        if self.mode == "dev":
            self._fill_dev_defaults()
        else:
            self._require_prod_settings()
        if self.webauthn_origin is None:
            self.webauthn_origin = self.public_url
        if self.webauthn_rp_id is None:
            self.webauthn_rp_id = urlparse(self.public_url).hostname
        return self

    def _fill_dev_defaults(self) -> None:
        self.database_url = self.database_url or DEV_DATABASE_URL
        self.public_url = self.public_url or DEV_PUBLIC_URL
        if self.jwt_secret is None:
            self.jwt_secret = SecretStr(secrets.token_urlsafe(48))

    def _check_attestation_issuer(self) -> None:
        is_mock = self.attestation_issuer == MOCK_ATTESTATION_ISSUER
        if not is_mock and self.attestation_issuer != GOOGLE_ATTESTATION_ISSUER:
            raise ConfigError("unsupported attestation_issuer")
        if self.mode != "dev" and (is_mock or self.mock_attestation_public_key_pem):
            raise ConfigError("the mock attestation issuer is only allowed in dev")
        if is_mock and not self.mock_attestation_public_key_pem:
            raise ConfigError("mock issuer requires mock_attestation_public_key_pem")

    def _require_prod_settings(self) -> None:
        missing = [name for name in PROD_REQUIRED_SETTINGS if not getattr(self, name)]
        if missing:
            env = ", ".join(f"CARAPACE_{m.upper()}" for m in missing)
            raise ConfigError(f"prod mode requires {env}")
        if self.database_url.startswith("sqlite"):
            raise ConfigError("prod mode requires a Postgres database_url")
        if urlparse(self.public_url).scheme != "https":
            raise ConfigError("prod mode requires an https public_url")
        if len(self.jwt_secret.get_secret_value()) < MIN_JWT_SECRET_LENGTH:
            raise ConfigError(
                f"jwt_secret must be at least {MIN_JWT_SECRET_LENGTH} characters"
            )
        if self.bcrypt_rounds < MIN_PROD_BCRYPT_ROUNDS:
            raise ConfigError(
                f"prod mode requires bcrypt_rounds >= {MIN_PROD_BCRYPT_ROUNDS}"
            )

    @property
    def jwt_key(self) -> str:
        # Validator guarantees this is set in both modes.
        assert self.jwt_secret is not None  # noqa: S101
        return self.jwt_secret.get_secret_value()


@lru_cache
def get_settings() -> Settings:
    return Settings()
