"""Per-boot keys, bound to the attestation token by ``eat_nonce``.

At boot the enclave generates a TLS key (with a self-signed certificate) and
an Ed25519 receipt key, entirely in memory. Its boot id is

    boot_id = hex(sha256(tls_spki_der || receipt_pubkey))

and every attestation token it requests carries ``boot_id`` as its nonce, so
a verifier who checks the token also learns which TLS and receipt keys the
attested workload holds. The server derives the same value at
``POST /internal/boots``.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.x509.oid import NameOID

from carapace_crypto import KeyPair, sha256_hex

CERT_COMMON_NAME = "carapace-enclave"
CERT_LIFETIME = datetime.timedelta(days=365)
CERT_BACKDATE = datetime.timedelta(minutes=5)


def boot_id_for(tls_spki_der: bytes, receipt_pubkey: bytes) -> str:
    return sha256_hex(tls_spki_der + receipt_pubkey)


def _self_signed_cert(key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CERT_COMMON_NAME)])
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - CERT_BACKDATE)
        .not_valid_after(now + CERT_LIFETIME)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .sign(key, hashes.SHA256())
    )


@dataclass(frozen=True, slots=True, repr=False)
class BootIdentity:
    """This boot's TLS and receipt keys. Never leaves enclave memory."""

    tls_key: ec.EllipticCurvePrivateKey
    tls_cert_pem: str
    receipt_key: KeyPair
    boot_id: str

    @classmethod
    def generate(cls) -> BootIdentity:
        tls_key = ec.generate_private_key(ec.SECP256R1())
        cert = _self_signed_cert(tls_key)
        receipt_key = KeyPair.generate()
        spki = tls_key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        return cls(
            tls_key=tls_key,
            tls_cert_pem=cert.public_bytes(Encoding.PEM).decode("ascii"),
            receipt_key=receipt_key,
            boot_id=boot_id_for(spki, receipt_key.public_key_bytes),
        )

    @property
    def receipt_pubkey(self) -> bytes:
        return self.receipt_key.public_key_bytes

    def tls_key_pem(self) -> bytearray:
        """The TLS private key as PEM, in a buffer the caller must wipe."""
        return bytearray(
            self.tls_key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
        )

    def __repr__(self) -> str:
        return f"BootIdentity(boot_id={self.boot_id})"
