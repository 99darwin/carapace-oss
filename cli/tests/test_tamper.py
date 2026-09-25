"""A lying server, enclave or network: every tamper must be refused.

Covers the milestone's required cases (swapped KMS key, wrong nonce,
forged receipts, edited policy) plus a few neighbours.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any

import pytest
from cli_support import SECRET_VALUE, UPSTREAM_URL, add_github_secret, create_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from carapace_cli import Client, EnclaveError, VerificationError
from carapace_cli.attestation import TrustPolicy
from carapace_cli.pin import pin_path
from carapace_cli.verify import (
    AttestationDocument,
    check_attestation,
    fetch_attestation,
)
from carapace_crypto import canonical_json
from carapace_enclave_mock.launcher import MOCK_IMAGE_DIGEST
from carapace_server.store.models import Secret


def _other_kms_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return (
        key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )


def _swap_server_kms(stack: Any, **update: str) -> None:
    stack.server_app.state.settings = stack.server_settings.model_copy(update=update)


def _secret_names(stack: Any) -> list[str]:
    code, out, err = stack.cli("secret", "list")
    assert code == 0, err
    return [line.split()[1] for line in out.splitlines() if line.strip()]


# -- swapped KMS public key -----------------------------------------------------


def test_verify_refuses_swapped_server_kms_key(owner) -> None:
    _swap_server_kms(owner, kms_public_key_pem=_other_kms_pem())
    code, _, err = owner.cli(*owner.verify_args())
    assert code == 1
    assert "KMS public key differs" in err
    assert not pin_path(owner.config_dir).exists()


def test_verify_refuses_swapped_kms_key_version(owner) -> None:
    _swap_server_kms(owner, kms_key_version="projects/x/cryptoKeyVersions/9")
    code, _, err = owner.cli(*owner.verify_args())
    assert code == 1
    assert "KMS key version differs" in err


def test_secret_add_refuses_kms_key_swapped_after_pinning(verified) -> None:
    _swap_server_kms(verified, kms_public_key_pem=_other_kms_pem())
    code, out, err = verified.cli(
        "secret", "add", "gh", "--host", "api.github.com", stdin=SECRET_VALUE
    )
    assert code == 1
    assert "refusing to seal" in err
    _swap_server_kms(verified)
    assert _secret_names(verified) == []


# -- wrong nonce ------------------------------------------------------------------


@pytest.fixture
def attestation(stack) -> tuple[AttestationDocument, bytes, TrustPolicy]:
    peer_der, document = fetch_attestation(stack.enclave_url)
    policy = TrustPolicy(
        allowed_digests=frozenset({MOCK_IMAGE_DIGEST}),
        mock_key_pem=stack.launcher.public_pem,
    )
    return document, peer_der, policy


def _replace(document: AttestationDocument, **fields: str) -> AttestationDocument:
    return AttestationDocument(**{**document.__dict__, **fields})


def test_genuine_attestation_passes(attestation) -> None:
    document, peer_der, policy = attestation
    assert check_attestation(document, peer_der, policy) == MOCK_IMAGE_DIGEST


def test_token_with_wrong_nonce_is_refused(stack, attestation) -> None:
    document, peer_der, policy = attestation
    claims = stack.launcher.claims("carapace-attestation", ["ab" * 32])
    forged = _replace(document, token=stack.launcher.sign(claims))
    with pytest.raises(VerificationError, match="nonce does not match"):
        check_attestation(forged, peer_der, policy)


def test_swapped_receipt_key_breaks_the_nonce(attestation) -> None:
    document, peer_der, policy = attestation
    other = base64.b64encode(os.urandom(32)).decode("ascii")
    with pytest.raises(VerificationError, match="wrong nonce"):
        check_attestation(_replace(document, receipt_pubkey=other), peer_der, policy)


def test_boot_id_claimed_for_other_keys_is_refused(attestation) -> None:
    document, peer_der, policy = attestation
    with pytest.raises(VerificationError, match="wrong nonce"):
        check_attestation(_replace(document, boot_id="cd" * 32), peer_der, policy)


def test_certificate_other_than_the_attested_one_is_refused(attestation) -> None:
    document, _, policy = attestation
    with pytest.raises(VerificationError, match="not the attested one"):
        check_attestation(document, b"not the peer", policy)


def test_token_for_another_audience_is_refused(stack, attestation) -> None:
    document, peer_der, policy = attestation
    claims = stack.launcher.claims(stack.server_url, [document.boot_id])
    forged = _replace(document, token=stack.launcher.sign(claims))
    with pytest.raises(VerificationError, match="(?i)audience"):
        check_attestation(forged, peer_der, policy)


# -- forged receipts ------------------------------------------------------------


@pytest.fixture
def receipts_file(verified, tmp_path: Path) -> Path:
    stack = verified
    secret_id = add_github_secret(stack)
    client = Client(create_key(stack, "github"), config_dir=stack.config_dir)
    for _ in range(3):
        assert client.request(secret_id, "GET", UPSTREAM_URL).status == 200
    stack.flush_receipts()
    path = tmp_path / "receipts.json"
    code, _, err = stack.cli("audit", "fetch", "--output", str(path))
    assert code == 0, err
    return path


def _edit(path: Path, change: Any) -> None:
    pages = json.loads(path.read_text())
    change(pages[0])
    path.write_text(json.dumps(pages))


def _audit(stack: Any, path: Path) -> tuple[int, str]:
    code, out, err = stack.cli("audit", "verify", "--file", str(path))
    return code, out + err


def test_untampered_receipts_verify(verified, receipts_file) -> None:
    code, out = _audit(verified, receipts_file)
    assert code == 0, out
    assert "OK: 3 receipts from 1 attested boots verified, 0 gaps" in out


def _flip_signature(page: dict[str, Any]) -> None:
    sig = bytearray(base64.b64decode(page["receipts"][1]["signature"]))
    sig[0] ^= 1
    page["receipts"][1]["signature"] = base64.b64encode(bytes(sig)).decode()


def _drop_signature(page: dict[str, Any]) -> None:
    page["receipts"][1]["signature"] = ""


def _edit_payload(page: dict[str, Any]) -> None:
    page["receipts"][1]["payload"]["outcome"] = "denied"


def _rehash_edited_payload(page: dict[str, Any]) -> None:
    receipt = page["receipts"][1]
    receipt["payload"]["request"]["host"] = "evil.example.net"
    signed = canonical_json(
        {k: receipt[k] for k in ("boot_id", "seq", "prev_hash", "payload")}
    )
    receipt["hash"] = hashlib.sha256(signed).hexdigest()


def _forge_with_other_key(page: dict[str, Any]) -> None:
    receipt = page["receipts"][1]
    receipt["payload"]["outcome"] = "denied"
    signed = canonical_json(
        {k: receipt[k] for k in ("boot_id", "seq", "prev_hash", "payload")}
    )
    receipt["signature"] = base64.b64encode(
        Ed25519PrivateKey.generate().sign(signed)
    ).decode()


def _break_chain(page: dict[str, Any]) -> None:
    page["receipts"][2]["prev_hash"] = "11" * 32


def _swap_boot_key(page: dict[str, Any]) -> None:
    page["boots"][0]["receipt_pubkey"] = base64.b64encode(os.urandom(32)).decode()


def _unattested_boot(page: dict[str, Any]) -> None:
    page["boots"][0]["attestation_token"] = "e30.e30.e30"


@pytest.mark.parametrize(
    "tamper",
    [
        _flip_signature,
        _drop_signature,
        _edit_payload,
        _rehash_edited_payload,
        _forge_with_other_key,
        _break_chain,
        _swap_boot_key,
        _unattested_boot,
    ],
)
def test_tampered_receipts_fail_audit(verified, receipts_file, tamper) -> None:
    _edit(receipts_file, tamper)
    code, out = _audit(verified, receipts_file)
    assert code != 0, out
    assert "FAIL" in out
    assert "FAILED" in out


def test_withheld_receipt_is_reported_as_a_gap(verified, receipts_file) -> None:
    _edit(receipts_file, lambda page: page["receipts"].pop(1))
    code, out = _audit(verified, receipts_file)
    assert code == 0, out
    assert "2 receipts from 1 attested boots verified, 1 gaps" in out


# -- edited policy -----------------------------------------------------------------


async def _edit_secret(stack: Any, secret_id: str, **changes: Any) -> None:
    async with stack.sessionmaker() as db:
        secret = await db.get(Secret, uuid.UUID(secret_id))
        assert secret is not None
        for name, value in changes.items():
            setattr(secret, name, value(secret) if callable(value) else value)
        await db.commit()


@pytest.fixture
def agent(verified) -> tuple[Any, str, Client]:
    secret_id = add_github_secret(verified)
    client = Client(create_key(verified, "github"), config_dir=verified.config_dir)
    return verified, secret_id, client


def test_edited_policy_hosts_are_refused_by_the_enclave(agent) -> None:
    stack, secret_id, client = agent
    stack.run(
        _edit_secret(
            stack,
            secret_id,
            policy_json=lambda s: {
                **s.policy_json,
                "hosts": [{"match": "exact", "value": "evil.example.net"}],
            },
        )
    )
    with pytest.raises(EnclaveError) as info:
        client.request(secret_id, "GET", "https://evil.example.net/")
    assert (info.value.status, info.value.code) == (502, "store_error")
    assert stack.upstream.requests == []


def test_edited_ciphertext_is_refused_by_the_enclave(agent) -> None:
    stack, secret_id, client = agent
    stack.run(
        _edit_secret(
            stack,
            secret_id,
            ciphertext=lambda s: bytes([s.ciphertext[0] ^ 1]) + s.ciphertext[1:],
        )
    )
    with pytest.raises(EnclaveError) as info:
        client.request(secret_id, "GET", UPSTREAM_URL)
    assert info.value.status >= 400
    assert stack.upstream.requests == []
