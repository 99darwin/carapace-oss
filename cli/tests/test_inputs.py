"""Command input handling: init output, policies, secret input, SDK redaction."""

from __future__ import annotations

import base64
import io

import pytest

from carapace_cli import CarapaceError, Client
from carapace_cli.main import main
from carapace_cli.ownerkey_store import load_owner_key
from carapace_cli.pin import EnclavePin
from carapace_cli.prompts import read_secret_value
from carapace_cli.secrets_ops import PolicyError, build_policy


def test_init_never_prints_the_seed(tmp_path) -> None:
    out, err = io.StringIO(), io.StringIO()
    config = tmp_path / "config"
    code = main(
        ["--config-dir", str(config), "init", "--no-passphrase"], out=out, err=err
    )
    assert code == 0, err.getvalue()
    key = load_owner_key(config / "owner-key.json")
    for text in (out.getvalue(), err.getvalue()):
        assert key.seed.hex() not in text.lower()
        assert base64.b64encode(key.seed).decode() not in text


# -- policies and input ------------------------------------------------------------


def _policy(**overrides):
    args = {
        "hosts": ["API.GitHub.com"],
        "host_suffixes": [],
        "methods": ["get"],
        "inject_kind": "header",
        "inject_name": "Authorization",
        "template": "Bearer {secret}",
    } | overrides
    return build_policy(**args)


def test_policy_is_normalized() -> None:
    policy = _policy(host_suffixes=[".githubusercontent.com"], ports=[443, 443])
    assert policy["hosts"] == [
        {"match": "exact", "value": "api.github.com"},
        {"match": "suffix", "value": ".githubusercontent.com"},
    ]
    assert policy["methods"] == ["GET"]
    assert policy["ports"] == [443]
    assert policy["schemes"] == ["https"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"hosts": []},
        {"host_suffixes": ["github.com"]},
        {"methods": ["CONNECT"]},
        {"template": "Bearer"},
        {"template": "{secret}{secret}"},
        {"inject_kind": "cookie"},
        {"inject_name": None},
        {"inject_kind": "basic_auth"},
    ],
)
def test_bad_policies_are_refused(overrides) -> None:
    with pytest.raises(PolicyError):
        _policy(**overrides)


def test_secret_value_from_pipe() -> None:
    value = read_secret_value(io.BytesIO(b"s3cret\n"))
    assert value == bytearray(b"s3cret")
    assert isinstance(value, bytearray)


@pytest.mark.parametrize("raw", [b"", b"\n", b"x" * (64 * 1024 + 1)])
def test_bad_secret_values_are_refused(raw) -> None:
    with pytest.raises(CarapaceError):
        read_secret_value(io.BytesIO(raw))


# -- SDK redaction -----------------------------------------------------------------


def _pin() -> EnclavePin:
    return EnclavePin(
        enclave_url="https://127.0.0.1:1",
        tls_cert_pem="",
        receipt_pubkey="",
        boot_id="",
        image_digest="",
        kms_public_key_pem="",
        kms_key_version="",
        allowed_digests=(),
        insecure_mock=False,
        mock_key_pem=None,
        verified_at=0,
    )


def test_client_repr_hides_the_api_key() -> None:
    raw = "cpk_" + "ab" * 16 + "_" + "cd" * 32
    client = Client(raw, pin=_pin())
    assert raw not in repr(client)
    assert "cd" * 32 not in repr(client)


def test_client_reads_key_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("CARAPACE_API_KEY", "cpk_" + "ab" * 16 + "_" + "cd" * 32)
    assert Client(pin=_pin())


def test_malformed_api_key_is_not_echoed() -> None:
    with pytest.raises(CarapaceError) as info:
        Client("cpk_not-a-real-key-SENSITIVE", pin=_pin())
    assert "SENSITIVE" not in str(info.value)
