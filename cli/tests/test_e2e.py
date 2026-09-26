"""End to end: CLI and SDK against the real server and a real TLS enclave."""

from __future__ import annotations

import datetime
import stat
import uuid
import warnings

import pytest
from cli_support import SECRET_VALUE, UPSTREAM_URL, add_github_secret, create_key
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from carapace_cli import Client, EnclaveError, InsecureMockWarning, PinError
from carapace_cli.files import write_private_json
from carapace_cli.pin import IDENTITY_FIELDS, load_pin, pin_path
from carapace_enclave_mock import MOCK_KMS_KEY_VERSION
from carapace_enclave_mock.launcher import (
    MOCK_IMAGE_DIGEST,
    MOCK_PROJECT_ID,
    MOCK_SERVICE_ACCOUNT,
)
from carapace_server.apikeys.models import ApiKey
from carapace_server.apikeys.service import is_tombstone

# The test stack's pin is a mock pin by construction; the SDK's warning about
# it is asserted once, in test_sdk_warns_when_it_loads_an_insecure_mock_pin.
pytestmark = pytest.mark.filterwarnings("ignore::carapace_cli.InsecureMockWarning")


def test_full_flow(verified) -> None:
    stack = verified
    secret_id = add_github_secret(stack)
    api_key = create_key(stack, "github")

    client = Client(api_key, config_dir=stack.config_dir)
    response = client.request(secret_id, "GET", UPSTREAM_URL)

    assert response.status == 200
    assert response.json() == {"login": "octocat"}
    sent = stack.upstream.requests[-1]
    assert sent.headers["authorization"] == "Bearer " + SECRET_VALUE.decode()

    stack.flush_receipts()
    code, out, err = stack.cli("audit", "verify")
    assert code == 0, out + err
    assert "OK: 1 receipts" in out


def test_config_files_are_private(verified) -> None:
    stack = verified
    add_github_secret(stack)
    for path in stack.config_dir.iterdir():
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600, (path.name, oct(mode))
    assert stat.S_IMODE(stack.config_dir.stat().st_mode) == 0o700


def test_secret_value_never_printed(verified) -> None:
    stack = verified
    code, out, err = stack.cli(
        "secret", "add", "gh", "--host", "api.github.com", stdin=SECRET_VALUE
    )
    assert code == 0, err
    for text in (out, err):
        assert SECRET_VALUE.decode() not in text


def test_secret_add_prints_the_insecure_mock_banner(verified) -> None:
    code, _, err = verified.cli(
        "secret", "add", "gh", "--host", "api.github.com", stdin=SECRET_VALUE
    )
    assert code == 0, err
    assert "INSECURE" in err


def test_sdk_warns_when_it_loads_an_insecure_mock_pin(verified) -> None:
    stack = verified
    add_github_secret(stack)
    api_key = create_key(stack, "github")
    with pytest.warns(InsecureMockWarning):
        Client(api_key, config_dir=stack.config_dir)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        Client(api_key, pin=load_pin(stack.config_dir))
    for path in stack.config_dir.iterdir():
        assert SECRET_VALUE not in path.read_bytes()


def test_cli_request_command(verified, tmp_path) -> None:
    stack = verified
    add_github_secret(stack)
    key_file = tmp_path / "agent.key"
    code, _, err = stack.cli(
        "key", "create", "agent", "--secret", "github", "--output", str(key_file)
    )
    assert code == 0, err
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600

    code, out, err = stack.cli(
        "request", "github", "GET", UPSTREAM_URL, "--api-key-file", str(key_file)
    )
    assert code == 0, err
    assert '"octocat"' in out
    assert "HTTP 200" in err
    assert "INSECURE" in err


def test_host_outside_policy_is_refused(verified) -> None:
    stack = verified
    secret_id = add_github_secret(stack)
    client = Client(create_key(stack, "github"), config_dir=stack.config_dir)
    with pytest.raises(EnclaveError) as info:
        client.request(secret_id, "GET", "https://evil.example.net/")
    assert info.value.status == 403
    assert stack.upstream.requests == []


def test_revoked_key_is_refused(verified) -> None:
    stack = verified
    secret_id = add_github_secret(stack)
    api_key = create_key(stack, "github")
    client = Client(api_key, config_dir=stack.config_dir)
    assert client.request(secret_id, "GET", UPSTREAM_URL).status == 200

    code, out, _ = stack.cli("key", "list")
    assert code == 0
    key_id = out.split()[0]
    assert "active grant=ok" in out

    code, _, err = stack.cli("key", "revoke", key_id)
    assert code == 0, err
    assert "rotate" in err.lower()
    code, out, _ = stack.cli("key", "list")
    assert key_id not in out  # the server lists live keys only
    row = stack.run(_api_key_row(stack, key_id))
    assert row.revoked_at is not None
    assert is_tombstone(row.grant_json)

    with pytest.raises(EnclaveError) as info:
        client.request(secret_id, "GET", UPSTREAM_URL)
    assert info.value.status in (401, 403)


async def _api_key_row(stack, key_id: str) -> ApiKey:
    async with stack.sessionmaker() as db:
        row = await db.get(ApiKey, uuid.UUID(key_id))
        assert row is not None
        return row


def test_unknown_secret_for_key_is_refused(verified) -> None:
    code, _, err = verified.cli("key", "create", "agent", "--secret", "nope")
    assert code == 1
    assert err.startswith("error:")


def test_secret_add_requires_a_pin(owner) -> None:
    code, _, err = owner.cli(
        "secret", "add", "gh", "--host", "api.github.com", stdin=SECRET_VALUE
    )
    assert code == 1
    assert "verify" in err


def test_pinned_certificate_mismatch_is_refused(verified) -> None:
    stack = verified
    secret_id = add_github_secret(stack)
    api_key = create_key(stack, "github")

    pin = load_pin(stack.config_dir)
    other = _self_signed_pem()
    data = pin.to_dict() | {"tls_cert_pem": other}
    write_private_json(pin_path(stack.config_dir), data)
    client = Client(api_key, config_dir=stack.config_dir)
    with pytest.raises(PinError):
        client.request(secret_id, "GET", UPSTREAM_URL)
    assert stack.upstream.requests == []


def _self_signed_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "impostor")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


# -- verify flags ------------------------------------------------------------------


def test_verify_prints_the_insecure_mock_banner(owner) -> None:
    code, out, err = owner.cli(*owner.verify_args())
    assert code == 0, err
    assert "INSECURE" in err
    assert "cosign" in err.lower()
    assert load_pin(owner.config_dir).insecure_mock


def test_verify_without_insecure_mock_refuses_the_mock_enclave(owner) -> None:
    args = owner.verify_args()
    mock_flag = args.index("--insecure-mock")
    del args[mock_flag : mock_flag + 3]  # and --mock-issuer-key <path>
    code, _, err = owner.cli(*args)
    assert code == 1
    assert "--insecure-mock" in err
    assert not pin_path(owner.config_dir).exists()


def test_verify_pins_the_deployment_identity(verified) -> None:
    pin = load_pin(verified.config_dir)
    assert pin.project_id == MOCK_PROJECT_ID
    assert pin.service_account == MOCK_SERVICE_ACCOUNT
    assert pin.control_plane_url == verified.server_url
    assert pin.kms_key_name == pin.kms_key_version == MOCK_KMS_KEY_VERSION
    assert pin_path(verified.config_dir).read_text().count('"v": 2') == 1


@pytest.mark.parametrize("flag", ["--project-id", "--service-account", "--kms-key"])
def test_verify_without_an_identity_flag_fails_closed(owner, flag) -> None:
    args = owner.verify_args()
    del args[args.index(flag) : args.index(flag) + 2]
    code, _, err = owner.cli(*args)
    assert code == 1
    assert "deployment identity" in err
    assert not pin_path(owner.config_dir).exists()


def test_verify_with_an_empty_control_plane_url_fails_closed(owner) -> None:
    """An empty flag is refused, not silently replaced by the server URL."""
    code, _, err = owner.cli(*owner.verify_args(), "--control-plane-url", "")
    assert code == 1
    assert "invalid URL ''" in err
    assert not pin_path(owner.config_dir).exists()


@pytest.mark.parametrize(
    ("flag", "value", "message"),
    [
        ("--project-id", "attacker-project", "GCP project"),
        ("--service-account", "enclave@attacker.iam.gserviceaccount.com", "run as"),
        ("--kms-key", MOCK_KMS_KEY_VERSION[:-1] + "2", "KMS key"),
        ("--control-plane-url", "https://evil.example.com", "control plane URL"),
    ],
)
def test_verify_refuses_another_deployment(owner, flag, value, message) -> None:
    code, _, err = owner.cli(*owner.verify_args(), flag, value)
    assert code == 1
    assert message in err
    assert not pin_path(owner.config_dir).exists()


def test_verify_refuses_an_enclave_reporting_another_kms_key(owner) -> None:
    """The token names one key but the enclave serves with another."""
    other = MOCK_KMS_KEY_VERSION[:-1] + "2"
    owner.launcher.env["KMS_KEY_NAME"] = other
    args = owner.verify_args()
    args[args.index(MOCK_KMS_KEY_VERSION)] = other
    code, _, err = owner.cli(*args)
    assert code == 1
    assert "the enclave reports KMS key" in err
    assert not pin_path(owner.config_dir).exists()


def test_v1_pin_is_refused_with_a_reverify_hint(verified) -> None:
    data = load_pin(verified.config_dir).to_dict() | {"v": 1}
    for name in IDENTITY_FIELDS:
        del data[name]
    write_private_json(pin_path(verified.config_dir), data)
    code, _, err = verified.cli("audit", "verify")
    assert code == 1
    assert "re-run carapace verify" in err
    with pytest.raises(PinError, match="predates deployment identity"):
        load_pin(verified.config_dir)


@pytest.mark.parametrize("name", ["project_id", "kms_key_name"])
def test_v2_pin_without_identity_is_malformed(verified, name) -> None:
    data = load_pin(verified.config_dir).to_dict() | {name: None}
    write_private_json(pin_path(verified.config_dir), data)
    with pytest.raises(PinError, match="malformed"):
        load_pin(verified.config_dir)


def test_verify_without_a_digest_fails_closed(owner) -> None:
    args = [a for a in owner.verify_args() if a not in ("--allow-digest",)]
    args.remove(MOCK_IMAGE_DIGEST)
    code, _, err = owner.cli(*args)
    assert code == 1
    assert "no trusted image digests" in err


def test_verify_with_another_digest_is_refused(owner) -> None:
    args = owner.verify_args()
    args[args.index(MOCK_IMAGE_DIGEST)] = "sha256:" + "11" * 32
    code, _, err = owner.cli(*args)
    assert code == 1
    assert "not in the allowlist" in err


def test_insecure_mock_requires_the_issuer_key(owner) -> None:
    args = owner.verify_args()[:-2]
    code, _, err = owner.cli(*args)
    assert code == 1
    assert "--mock-issuer-key" in err


def test_mock_issuer_key_requires_insecure_mock(owner) -> None:
    args = [a for a in owner.verify_args() if a != "--insecure-mock"]
    code, _, err = owner.cli(*args)
    assert code == 1
    assert "only valid with --insecure-mock" in err


def test_verify_refuses_plain_http_enclave(owner) -> None:
    args = owner.verify_args()
    args[args.index(owner.enclave_url)] = owner.enclave_url.replace("https", "http")
    code, _, err = owner.cli(*args)
    assert code == 1
    assert "https" in err
