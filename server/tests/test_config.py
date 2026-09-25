"""Settings fail fast in prod and never ship a default secret."""

import pytest
from pydantic import ValidationError

from carapace_server.config import Settings

PROD_ENV = {
    "CARAPACE_MODE": "prod",
    "CARAPACE_DATABASE_URL": "postgresql+asyncpg://db.internal/carapace",
    "CARAPACE_PUBLIC_URL": "https://server.example.com",
    "CARAPACE_JWT_SECRET": "x" * 48,
    "CARAPACE_ALLOWED_IMAGE_DIGESTS": f"sha256:{'a' * 64}, sha256:{'b' * 64}",
    "CARAPACE_ATTESTATION_PROJECT_ID": "example-project",
    "CARAPACE_ATTESTATION_SERVICE_ACCOUNT": "enclave@example.iam.gserviceaccount.com",
}
EXTRA_ENV = (
    "CARAPACE_BCRYPT_ROUNDS",
    "CARAPACE_ATTESTATION_ISSUER",
    "CARAPACE_MOCK_ATTESTATION_PUBLIC_KEY_PEM",
    "CARAPACE_ALLOWED_HWMODELS",
)


@pytest.fixture
def prod_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for key in (*PROD_ENV, *EXTRA_ENV):
        monkeypatch.delenv(key, raising=False)
    for key, value in PROD_ENV.items():
        monkeypatch.setenv(key, value)
    return monkeypatch


def test_prod_settings_load(prod_env: pytest.MonkeyPatch) -> None:
    settings = Settings()
    assert settings.mode == "prod"
    assert settings.webauthn_rp_id == "server.example.com"
    assert settings.webauthn_origin == "https://server.example.com"
    assert settings.allowed_image_digests == [
        f"sha256:{'a' * 64}",
        f"sha256:{'b' * 64}",
    ]
    assert settings.allowed_hwmodels == ["GCP_AMD_SEV"]


def test_default_mode_is_prod(prod_env: pytest.MonkeyPatch) -> None:
    prod_env.delenv("CARAPACE_MODE")
    assert Settings().mode == "prod"


@pytest.mark.parametrize(
    "missing",
    [
        "CARAPACE_DATABASE_URL",
        "CARAPACE_PUBLIC_URL",
        "CARAPACE_JWT_SECRET",
        "CARAPACE_ALLOWED_IMAGE_DIGESTS",
        "CARAPACE_ATTESTATION_PROJECT_ID",
        "CARAPACE_ATTESTATION_SERVICE_ACCOUNT",
    ],
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
        ("CARAPACE_ALLOWED_IMAGE_DIGESTS", "latest", "sha256"),
        ("CARAPACE_ATTESTATION_ISSUER", "mock://local", "only allowed in dev"),
        ("CARAPACE_ATTESTATION_ISSUER", "https://issuer.example", "unsupported"),
        ("CARAPACE_MOCK_ATTESTATION_PUBLIC_KEY_PEM", "pem", "only allowed in dev"),
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


def test_mock_issuer_allowed_in_dev_with_key() -> None:
    settings = Settings(
        mode="dev",
        attestation_issuer="mock://local",
        mock_attestation_public_key_pem="pem",
    )
    assert settings.attestation_issuer == "mock://local"


def test_mock_issuer_requires_key() -> None:
    with pytest.raises(ValidationError, match="requires"):
        Settings(mode="dev", attestation_issuer="mock://local")
