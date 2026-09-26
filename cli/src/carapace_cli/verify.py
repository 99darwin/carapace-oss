"""``carapace verify``: attest the enclave, cross-check KMS, pin it.

1. Learn the certificate the enclave presents (unverified handshake, no
   data sent), then fetch ``/attestation`` over a connection pinned to it.
2. The attested ``tls_cert_pem`` must be that same certificate.
3. ``boot_id`` must equal ``sha256(tls_spki_der || receipt_pubkey)``.
4. The attestation token must verify (see :mod:`carapace_cli.attestation`)
   with audience ``carapace-attestation`` and nonce ``boot_id``, including
   the deployment identity: project, service account, control plane URL and
   KMS key. A policy without all four is refused.
5. The KMS key version the enclave reports must be the pinned one, and the
   KMS public key the server hands out must equal the one the enclave
   reported over the attested channel, version included.

Only then is the pin written. Any failure raises and nothing is saved.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from carapace_cli.attestation import (
    ATTESTATION_AUDIENCE,
    TrustPolicy,
    verify_attestation_token,
)
from carapace_cli.errors import EnclaveError, VerificationError
from carapace_cli.pin import (
    EnclavePin,
    der_to_pem,
    fetch_peer_certificate,
    now_seconds,
    pem_to_der,
    pinned_client,
)
from carapace_cli.session import ServerClient
from carapace_cli.urls import normalize_base_url
from carapace_crypto import EnvelopeError, b64_decode_strict
from carapace_crypto.envelope import load_rsa_public_key

RECEIPT_PUBKEY_BYTES = 32
MAX_ATTESTATION_BYTES = 64 * 1024
ATTESTATION_FIELDS = frozenset(
    {
        "token",
        "boot_id",
        "tls_cert_pem",
        "receipt_pubkey",
        "kms_public_key_pem",
        "kms_key_version",
    }
)


@dataclass(frozen=True)
class AttestationDocument:
    token: str
    boot_id: str
    tls_cert_pem: str
    receipt_pubkey: str
    kms_public_key_pem: str
    kms_key_version: str

    @classmethod
    def parse(cls, raw: bytes) -> AttestationDocument:
        if len(raw) > MAX_ATTESTATION_BYTES:
            raise VerificationError("attestation response too large")
        try:
            data = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise VerificationError("attestation response is not JSON") from None
        if not isinstance(data, dict) or set(data) != ATTESTATION_FIELDS:
            raise VerificationError("attestation response has unexpected fields")
        if not all(isinstance(v, str) for v in data.values()):
            raise VerificationError("attestation response fields must be strings")
        return cls(**data)


def boot_id_for(cert_pem: str, receipt_pubkey: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    spki = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(spki + receipt_pubkey).hexdigest()


def kms_keys_match(pem_a: str, pem_b: str) -> bool:
    """Same RSA key, compared as SPKI DER (PEM formatting may differ)."""
    try:
        der_a, der_b = (
            load_rsa_public_key(pem).public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
            for pem in (pem_a, pem_b)
        )
    except EnvelopeError:
        return False
    return hmac.compare_digest(der_a, der_b)


def fetch_server_kms_key(server: ServerClient) -> tuple[str, str]:
    body: Any = server.get("/v1/kms/public-key")
    if not isinstance(body, dict):
        raise VerificationError("server returned a malformed KMS key")
    pem, version = body.get("public_key_pem"), body.get("key_version")
    if not isinstance(pem, str) or not isinstance(version, str):
        raise VerificationError("server returned a malformed KMS key")
    return pem, version


def check_server_kms_key(
    server: ServerClient, *, attested_pem: str, attested_version: str
) -> None:
    """Refuse unless the server's KMS key is the attested enclave's.

    Raises:
        VerificationError: On any mismatch.
    """
    pem, version = fetch_server_kms_key(server)
    if not kms_keys_match(pem, attested_pem):
        raise VerificationError(
            "the server's KMS public key differs from the attested enclave's; "
            "refusing to seal to it"
        )
    if version != attested_version:
        raise VerificationError(
            "the server's KMS key version differs from the attested enclave's"
        )


def fetch_attestation(enclave_url: str) -> tuple[bytes, AttestationDocument]:
    """The peer certificate DER and the attestation served over it."""
    peer_der = fetch_peer_certificate(enclave_url)
    with pinned_client(enclave_url, der_to_pem(peer_der)) as client:
        response = client.get("/attestation")
        if not response.is_success:
            raise EnclaveError(response.status_code, "attestation_unavailable")
        return peer_der, AttestationDocument.parse(response.content)


def check_attestation(
    document: AttestationDocument, peer_der: bytes, policy: TrustPolicy
) -> str:
    """Checks 2-4 from the module docstring. Returns the image digest."""
    if not hmac.compare_digest(pem_to_der(document.tls_cert_pem), peer_der):
        raise VerificationError("the enclave's TLS certificate is not the attested one")
    try:
        receipt_pubkey = b64_decode_strict(document.receipt_pubkey, name="receipt")
    except ValueError:
        raise VerificationError("invalid receipt public key") from None
    if len(receipt_pubkey) != RECEIPT_PUBKEY_BYTES:
        raise VerificationError("invalid receipt public key")
    expected = boot_id_for(document.tls_cert_pem, receipt_pubkey)
    if not hmac.compare_digest(expected, document.boot_id):
        raise VerificationError(
            "boot id does not bind the TLS and receipt keys (wrong nonce)"
        )
    claims = verify_attestation_token(
        document.token,
        policy,
        audiences=[ATTESTATION_AUDIENCE],
        nonce=expected,
    )
    try:
        load_rsa_public_key(document.kms_public_key_pem)
    except EnvelopeError as exc:
        raise VerificationError(f"attested KMS key is unusable: {exc}") from None
    return claims.image_digest


def verify_enclave(
    enclave_url: str, server: ServerClient, policy: TrustPolicy
) -> EnclavePin:
    """Run every check and return the pin to save. Raises on any failure."""
    project_id, service_account, control_plane_url, kms_key_name = _required_identity(
        policy
    )
    enclave_url = normalize_base_url(
        enclave_url, what="enclave", allow_loopback_http=False
    )
    peer_der, document = fetch_attestation(enclave_url)
    image_digest = check_attestation(document, peer_der, policy)
    if document.kms_key_version != kms_key_name:
        raise VerificationError(
            f"the enclave reports KMS key {document.kms_key_version!r}, "
            f"not {kms_key_name!r}"
        )
    check_server_kms_key(
        server,
        attested_pem=document.kms_public_key_pem,
        attested_version=document.kms_key_version,
    )
    return EnclavePin(
        enclave_url=enclave_url,
        tls_cert_pem=document.tls_cert_pem,
        receipt_pubkey=document.receipt_pubkey,
        boot_id=document.boot_id,
        image_digest=image_digest,
        kms_public_key_pem=document.kms_public_key_pem,
        kms_key_version=document.kms_key_version,
        allowed_digests=tuple(sorted(policy.allowed_digests)),
        insecure_mock=policy.insecure_mock,
        mock_key_pem=policy.mock_key_pem,
        verified_at=now_seconds(),
        project_id=project_id,
        service_account=service_account,
        control_plane_url=control_plane_url,
        kms_key_name=kms_key_name,
    )


def _required_identity(policy: TrustPolicy) -> tuple[str, str, str, str]:
    """The four deployment identity values; a pin is never made without them."""
    project_id, service_account = policy.project_id, policy.service_account
    control_plane_url, kms_key_name = policy.control_plane_url, policy.kms_key_name
    if (
        project_id is None
        or service_account is None
        or control_plane_url is None
        or kms_key_name is None
    ):
        raise VerificationError(
            "a pin needs the deployment identity: pass --project-id, "
            "--service-account, --kms-key and --control-plane-url"
        )
    return project_id, service_account, control_plane_url, kms_key_name


def trust_policy_from_pin(pin: EnclavePin) -> TrustPolicy:
    return TrustPolicy(
        allowed_digests=frozenset(pin.allowed_digests),
        mock_key_pem=pin.mock_key_pem,
        project_id=pin.project_id,
        service_account=pin.service_account,
        control_plane_url=pin.control_plane_url,
        kms_key_name=pin.kms_key_name,
    )
