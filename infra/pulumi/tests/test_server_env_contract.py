"""The server's Cloud Run env must match the settings the server reads.

The server's settings ignore unknown variables (``extra="ignore"``), so a
misspelled or unprefixed name would be dropped silently and the server would
refuse to start in prod, or start without a setting it needs. This test reads
the server's settings source with ``ast`` (the infra venv does not install the
server package) and checks the env the stack declares against it.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytest.importorskip("pulumi_gcp")

from harness import make_config, run_stack  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
SERVER_CONFIG = REPO_ROOT / "server" / "src" / "carapace_server" / "config.py"
SETTINGS_CLASS = "Settings"
REQUIRED_TUPLE = "PROD_REQUIRED_SETTINGS"
SECRET_SETTINGS = ("database_url", "jwt_secret")
# Not prod-required by the server, but without them /v1/kms/public-key is a
# 404 and ``carapace verify`` fails against the deployment. Both are public.
KMS_SETTINGS = ("kms_public_key_pem", "kms_key_version")


def _parse_server_config() -> ast.Module:
    # Fail, never skip: a moved file must not silently disable the check.
    assert SERVER_CONFIG.is_file(), f"server settings not found at {SERVER_CONFIG}"
    return ast.parse(SERVER_CONFIG.read_text(encoding="utf-8"))


def _settings_class(module: ast.Module) -> ast.ClassDef:
    for node in module.body:
        if isinstance(node, ast.ClassDef) and node.name == SETTINGS_CLASS:
            return node
    raise AssertionError(f"class {SETTINGS_CLASS} not found in {SERVER_CONFIG}")


def _settings_fields(module: ast.Module) -> set[str]:
    return {
        node.target.id
        for node in _settings_class(module).body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }


def _env_prefix(module: ast.Module) -> str:
    for node in ast.walk(_settings_class(module)):
        if isinstance(node, ast.keyword) and node.arg == "env_prefix":
            return ast.literal_eval(node.value)
    raise AssertionError(f"env_prefix not found on {SETTINGS_CLASS}")


def _prod_required(module: ast.Module) -> tuple[str, ...]:
    for node in module.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == REQUIRED_TUPLE
        ):
            return tuple(ast.literal_eval(node.value))
    raise AssertionError(f"{REQUIRED_TUPLE} not found in {SERVER_CONFIG}")


@pytest.fixture(scope="module")
def server_config() -> ast.Module:
    return _parse_server_config()


@pytest.fixture(scope="module")
def server_envs() -> dict[str, dict]:
    mocks, _ = run_stack(make_config())
    service = mocks.one("gcp:cloudrunv2/service:Service").inputs
    envs = service["template"]["containers"][0]["envs"]
    return {env["name"]: env for env in envs}


def test_every_env_name_is_a_server_setting(server_config, server_envs) -> None:
    prefix = _env_prefix(server_config)
    fields = _settings_fields(server_config)
    assert prefix == "CARAPACE_"
    unknown = sorted(
        name
        for name in server_envs
        if not name.startswith(prefix) or name[len(prefix) :].lower() not in fields
    )
    assert unknown == [], f"env names the server would ignore: {unknown}"


def test_every_prod_required_setting_is_provided(server_config, server_envs) -> None:
    prefix = _env_prefix(server_config)
    required = _prod_required(server_config)
    assert required, f"{REQUIRED_TUPLE} is empty"
    missing = sorted(
        name for name in required if f"{prefix}{name.upper()}" not in server_envs
    )
    assert missing == [], f"prod-required settings not set: {missing}"


def test_credentials_come_from_secret_manager(server_config, server_envs) -> None:
    prefix = _env_prefix(server_config)
    for setting in SECRET_SETTINGS:
        env = server_envs[f"{prefix}{setting.upper()}"]
        assert env.get("value") is None, f"{setting} must not be a plain value"
        assert env["valueSource"]["secretKeyRef"]["secret"], setting


def test_kms_public_key_settings_are_plain_values(server_config, server_envs) -> None:
    prefix = _env_prefix(server_config)
    fields = _settings_fields(server_config)
    for setting in KMS_SETTINGS:
        assert setting in fields, f"server no longer reads {setting}"
        env = server_envs.get(f"{prefix}{setting.upper()}")
        assert env is not None, f"{setting} is not set on the server"
        assert "valueSource" not in env, f"{setting} is public; keep it plain"
        assert isinstance(env.get("value"), str), setting
        assert env["value"], setting
