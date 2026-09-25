"""Settings fail fast in prod and never ship a default secret."""

import pytest
from pydantic import ValidationError

from carapace_server.config import Settings

PROD_ENV = {
    "CARAPACE_MODE": "prod",
    "CARAPACE_DATABASE_URL": "postgresql+asyncpg://db.internal/carapace",
    "CARAPACE_PUBLIC_URL": "https://server.example.com",
    "CARAPACE_JWT_SECRET": "x" * 48,
}


@pytest.fixture
def prod_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for key in list(PROD_ENV) + ["CARAPACE_BCRYPT_ROUNDS"]:
        monkeypatch.delenv(key, raising=False)
    for key, value in PROD_ENV.items():
        monkeypatch.setenv(key, value)
    return monkeypatch


def test_prod_settings_load(prod_env: pytest.MonkeyPatch) -> None:
    settings = Settings()
    assert settings.mode == "prod"
    assert settings.webauthn_rp_id == "server.example.com"
    assert settings.webauthn_origin == "https://server.example.com"


def test_default_mode_is_prod(prod_env: pytest.MonkeyPatch) -> None:
    prod_env.delenv("CARAPACE_MODE")
    assert Settings().mode == "prod"


@pytest.mark.parametrize(
    "missing", ["CARAPACE_DATABASE_URL", "CARAPACE_PUBLIC_URL", "CARAPACE_JWT_SECRET"]
)
def test_prod_requires_settings(prod_env: pytest.MonkeyPatch, missing: str) -> None:
    prod_env.delenv(missing)
    with pytest.raises(ValidationError, match=missing):
        Settings()


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("CARAPACE_DATABASE_URL", "sqlite+aiosqlite:///x.db", "Postgres"),
        ("CARAPACE_PUBLIC_URL", "http://server.example.com", "https"),
        ("CARAPACE_JWT_SECRET", "short", "at least"),
        ("CARAPACE_BCRYPT_ROUNDS", "10", "bcrypt_rounds"),
    ],
)
def test_prod_rejects_unsafe_values(
    prod_env: pytest.MonkeyPatch, key: str, value: str, message: str
) -> None:
    prod_env.setenv(key, value)
    with pytest.raises(ValidationError, match=message):
        Settings()


def test_dev_mode_generates_random_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CARAPACE_JWT_SECRET", raising=False)
    first = Settings(mode="dev")
    second = Settings(mode="dev")
    assert len(first.jwt_key) >= 32
    assert first.jwt_key != second.jwt_key
    assert first.database_url.startswith("sqlite")
