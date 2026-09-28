"""The verified enclave, pinned locally, and TLS clients bound to it.

``carapace verify`` writes ``enclave.json`` (0600) once the attestation
checks pass. Every later call to the enclave trusts exactly that one
self-signed certificate: it is the only trust anchor in the TLS context
(hostname checking is off because the certificate names no host), and each
response is checked again against the pinned DER before its body is read.

The pin also records the deployment identity ``verify`` enforced (GCP
project, enclave service account, control plane URL, KMS key version), so
``audit verify`` checks past boots against the same deployment. Version 1
pins predate those checks and are refused rather than upgraded: nothing in
them says which deployment was verified, and filling the fields in now
would claim a check that never ran.
"""

from __future__ import annotations

import hmac
import socket
import ssl
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from carapace_cli.errors import NetworkError, PinError, StorageError, network_errors
from carapace_cli.files import read_private_json, write_private_json

PIN_FILE = "enclave.json"
PIN_VERSION = 2
PIN_VERSION_WITHOUT_IDENTITY = 1
IDENTITY_FIELDS = ("project_id", "service_account", "control_plane_url", "kms_key_name")
DEFAULT_HTTPS_PORT = 443
CONNECT_TIMEOUT_SECONDS = 10.0
REQUEST_TIMEOUT_SECONDS = 150.0


@dataclass(frozen=True)
class EnclavePin:
    enclave_url: str
    tls_cert_pem: str
    receipt_pubkey: str
    boot_id: str
    image_digest: str
    kms_public_key_pem: str
    kms_key_version: str
    allowed_digests: tuple[str, ...]
    insecure_mock: bool
    mock_key_pem: str | None
    verified_at: int
    project_id: str
    service_account: str
    control_plane_url: str
    kms_key_name: str

    @property
    def cert_der(self) -> bytes:
        return pem_to_der(self.tls_cert_pem)

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": PIN_VERSION,
            "enclave_url": self.enclave_url,
            "tls_cert_pem": self.tls_cert_pem,
            "receipt_pubkey": self.receipt_pubkey,
            "boot_id": self.boot_id,
            "image_digest": self.image_digest,
            "kms_public_key_pem": self.kms_public_key_pem,
            "kms_key_version": self.kms_key_version,
            "allowed_digests": list(self.allowed_digests),
            "insecure_mock": self.insecure_mock,
            "mock_key_pem": self.mock_key_pem,
            "verified_at": self.verified_at,
            "project_id": self.project_id,
            "service_account": self.service_account,
            "control_plane_url": self.control_plane_url,
            "kms_key_name": self.kms_key_name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnclavePin:
        if data.get("v") == PIN_VERSION_WITHOUT_IDENTITY:
            raise PinError(
                "this enclave pin predates deployment identity checks; re-run "
                "carapace verify with --project-id, --service-account and --kms-key"
            )
        if data.get("v") != PIN_VERSION:
            raise PinError("unsupported enclave pin version")
        try:
            pin = cls(
                enclave_url=str(data["enclave_url"]),
                tls_cert_pem=str(data["tls_cert_pem"]),
                receipt_pubkey=str(data["receipt_pubkey"]),
                boot_id=str(data["boot_id"]),
                image_digest=str(data["image_digest"]),
                kms_public_key_pem=str(data["kms_public_key_pem"]),
                kms_key_version=str(data["kms_key_version"]),
                allowed_digests=tuple(str(d) for d in data["allowed_digests"]),
                insecure_mock=data["insecure_mock"] is True,
                mock_key_pem=data.get("mock_key_pem"),
                verified_at=int(data["verified_at"]),
                **{name: _required_str(data, name) for name in IDENTITY_FIELDS},
            )
        except (KeyError, TypeError, ValueError):
            raise PinError("enclave pin file is malformed") from None
        if pin.insecure_mock != (pin.mock_key_pem is not None):
            raise PinError("enclave pin file is inconsistent")
        pin.cert_der  # noqa: B018 - parse now so a bad pin fails early
        return pin


def _required_str(data: dict[str, Any], name: str) -> str:
    value = data[name]
    if not isinstance(value, str) or not value:
        raise ValueError(name)
    return value


def pin_path(config_dir: Path) -> Path:
    return config_dir / PIN_FILE


def save_pin(config_dir: Path, pin: EnclavePin) -> None:
    write_private_json(pin_path(config_dir), pin.to_dict())


def load_pin(config_dir: Path) -> EnclavePin:
    path = pin_path(config_dir)
    if not path.exists():
        raise PinError("no verified enclave; run: carapace verify")
    try:
        return EnclavePin.from_dict(read_private_json(path))
    except StorageError as exc:
        raise PinError(f"cannot load enclave pin: {exc}") from None


def pem_to_der(pem: str) -> bytes:
    try:
        return x509.load_pem_x509_certificate(pem.encode("ascii")).public_bytes(
            Encoding.DER
        )
    except (ValueError, UnicodeEncodeError):
        raise PinError("invalid certificate PEM") from None


def der_to_pem(der: bytes) -> str:
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        raise PinError("enclave presented an invalid certificate") from None
    return cert.public_bytes(Encoding.PEM).decode("ascii")


def pinned_ssl_context(cert_pem: str) -> ssl.SSLContext:
    """A client context whose only trust anchor is ``cert_pem``."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # The enclave certificate is self-signed with no SAN; identity comes
    # from the pin, not from a name.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=cert_pem)
    return context


def _peer_check_hook(expected_der: bytes):  # noqa: ANN202
    def check(response: httpx.Response) -> None:
        stream = response.extensions.get("network_stream")
        ssl_object = stream.get_extra_info("ssl_object") if stream else None
        peer = ssl_object.getpeercert(True) if ssl_object is not None else None
        if peer is None or not hmac.compare_digest(peer, expected_der):
            response.close()
            raise PinError("enclave TLS certificate does not match the pin")

    return check


@contextmanager
def pinned_client(
    enclave_url: str, cert_pem: str, *, timeout: float = REQUEST_TIMEOUT_SECONDS
) -> Iterator[httpx.Client]:
    """An httpx client that talks only to the enclave holding ``cert_pem``.

    ``trust_env=False``: no proxy, netrc or CA-bundle settings from the
    environment apply.
    """
    expected = pem_to_der(cert_pem)
    with (
        network_errors("enclave", pinned=True),
        httpx.Client(
            base_url=enclave_url,
            verify=pinned_ssl_context(cert_pem),
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(timeout, connect=CONNECT_TIMEOUT_SECONDS),
            event_hooks={"response": [_peer_check_hook(expected)]},
        ) as client,
    ):
        yield client


def fetch_peer_certificate(enclave_url: str) -> bytes:
    """The certificate the enclave presents, before anything is trusted.

    This handshake does not verify the peer and sends no application data:
    it only learns which certificate to pin. :func:`verify_enclave` then
    fetches the attestation over a pinned connection and requires the
    attested certificate to be this one, so a man in the middle presenting
    its own certificate is rejected there.
    """
    parts = urlsplit(enclave_url)
    host = parts.hostname
    if host is None:
        raise PinError("invalid enclave URL")
    port = parts.port or DEFAULT_HTTPS_PORT
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection(
                (host, port), timeout=CONNECT_TIMEOUT_SECONDS
            ) as raw,
            context.wrap_socket(raw, server_hostname=None) as tls,
        ):
            der = tls.getpeercert(True)
    except ssl.SSLError as exc:
        raise PinError(
            f"TLS handshake with the enclave failed: {type(exc).__name__}"
        ) from None
    except OSError as exc:
        # Refused, timed out or unreachable: nothing was presented, so there
        # is nothing to reject. A freshly booted enclave looks like this
        # until its server listens; callers may retry.
        raise NetworkError(
            f"cannot connect to the enclave: {type(exc).__name__}"
        ) from None
    if not der:
        raise PinError("enclave presented no certificate")
    return der


def now_seconds() -> int:
    return int(time.time())
