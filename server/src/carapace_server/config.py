"""Server configuration.

Everything comes from ``CARAPACE_*`` environment variables. The default mode
is ``prod``, which refuses to start without an explicit database, JWT secret
and public URL. ``dev`` mode fills in local defaults, including a random
per-process JWT secret, so no secret value ever lives in source.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import Literal
from urllib.parse import urlparse

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

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

    rate_limit_enabled: bool = True
    cleanup_interval_seconds: int = Field(default=3600, ge=10)
    max_request_body_bytes: int = Field(
        default=DEFAULT_MAX_REQUEST_BODY_BYTES, ge=MIN_MAX_REQUEST_BODY_BYTES
    )

    @model_validator(mode="after")
    def _apply_mode(self) -> Settings:
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

    def _require_prod_settings(self) -> None:
        missing = [
            name
            for name in ("database_url", "public_url", "jwt_secret")
            if getattr(self, name) is None
        ]
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
