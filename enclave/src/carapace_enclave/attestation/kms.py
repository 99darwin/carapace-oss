"""Unwrapping data keys with Cloud KMS, authorized by attestation.

The enclave has no service account key and no application default
credentials. Its only credential is a Confidential Space token with the
``WIF_AUDIENCE`` audience, which Google STS exchanges (through the stack's
workload identity pool) for an access token that the KMS key policy lets
decrypt. The token comes from :class:`TokenSource` through a
``SubjectTokenSupplier``: nothing is written to disk and google-auth never
falls back to ambient credentials.

Everything that needs a KMS key goes through :class:`DekDecrypter`, so tests
and the dev mock can substitute a local RSA key.
"""

from __future__ import annotations

import hmac
import secrets
from typing import Any, Protocol

import google_crc32c
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from google.api_core import exceptions as api_exceptions
from google.auth import exceptions as auth_exceptions
from google.auth import identity_pool
from google.cloud import kms

from carapace_crypto.kms import is_kms_key_version_name
from carapace_enclave.attestation.token import (
    AttestationError,
    TokenSource,
)
from carapace_enclave.secure_memory import secure_zero

KMS_ALGORITHM = "RSA_DECRYPT_OAEP_4096_SHA256"
KMS_KEY_BITS = 4096
STS_TOKEN_URL = "https://sts.googleapis.com/v1/token"  # noqa: S105 - a URL
JWT_SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"  # noqa: S105
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
KMS_TIMEOUT_SECONDS = 15.0
PROBE_BYTES = 32


class KmsError(Exception):
    """KMS refused, failed, or answered with something unverifiable.

    Messages name the failure class, never key material or plaintext.
    """


class DekDecrypter(Protocol):
    """An RSA-OAEP-SHA256 private key the enclave can use but never holds."""

    @property
    def key_version(self) -> str:
        """The full ``.../cryptoKeyVersions/N`` resource name."""
        ...

    def unwrap(self, wrapped: bytes) -> bytes:
        """Decrypt a wrapped data key. Raises :class:`KmsError`."""
        ...

    def public_key_pem(self) -> str:
        """The public half, as PEM. Raises :class:`KmsError`."""
        ...


def validate_key_version_name(name: str) -> str:
    """Refuse anything but a full crypto key *version* resource name."""
    if not is_kms_key_version_name(name):
        raise KmsError("KMS key name must be a full cryptoKeyVersions resource name")
    return name


def require_key_version(envelope_key_version: str | None, configured: str) -> None:
    """Check an envelope's ``kms_key_version`` before any KMS call.

    ``None`` means "the enclave's key". Anything else must be exactly the
    configured version; the enclave never builds a resource name from
    server-supplied data.
    """
    if envelope_key_version is not None and envelope_key_version != configured:
        raise KmsError("envelope is wrapped under a different KMS key version")


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def verify_round_trip(decrypter: DekDecrypter, public_key_pem: str) -> None:
    """Prove that ``public_key_pem`` belongs to the key ``decrypter`` uses.

    Encrypts random bytes to the public key and decrypts them through the
    decrypter. Only the matching private key can return them, so a
    substituted public key (which would make clients seal secrets to someone
    else) is caught before the enclave publishes it.

    Raises:
        KmsError: If the key is not 4096-bit RSA or the round trip fails.
    """
    try:
        public_key = load_pem_public_key(public_key_pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        raise KmsError("KMS public key is not a PEM public key") from None
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise KmsError("KMS public key is not RSA")
    if public_key.key_size != KMS_KEY_BITS:
        raise KmsError(f"KMS public key must be {KMS_KEY_BITS}-bit RSA")
    probe = bytearray(secrets.token_bytes(PROBE_BYTES))
    returned = bytearray()
    try:
        returned = bytearray(
            decrypter.unwrap(public_key.encrypt(bytes(probe), _oaep()))
        )
        if not hmac.compare_digest(returned, probe):
            raise KmsError("KMS public key does not match the decrypting key")
    finally:
        secure_zero(probe)
        secure_zero(returned)


def _crc32c(data: bytes) -> int:
    return google_crc32c.value(data)


class LauncherTokenSupplier(identity_pool.SubjectTokenSupplier):
    """Feeds launcher tokens with the WIF audience to google-auth's STS flow."""

    def __init__(self, tokens: TokenSource, audience: str) -> None:
        self._tokens = tokens
        self._audience = audience

    def get_subject_token(self, context: Any, request: Any) -> str:
        try:
            return self._tokens.get(self._audience).raw
        except AttestationError as exc:
            # google-auth wraps supplier failures as RefreshError.
            raise auth_exceptions.RefreshError(str(exc)) from None


def federated_credentials(
    tokens: TokenSource, wif_audience: str
) -> identity_pool.Credentials:
    """Workload identity federation credentials backed only by the launcher."""
    return identity_pool.Credentials(
        audience=wif_audience,
        subject_token_type=JWT_SUBJECT_TOKEN_TYPE,
        token_url=STS_TOKEN_URL,
        subject_token_supplier=LauncherTokenSupplier(tokens, wif_audience),
        scopes=[CLOUD_PLATFORM_SCOPE],
    )


class CloudKmsDecrypter:
    """:class:`DekDecrypter` backed by Cloud KMS ``asymmetricDecrypt``.

    Blocking; call it from a worker thread in async code.
    """

    def __init__(
        self,
        *,
        key_version: str,
        wif_audience: str,
        tokens: TokenSource,
        client: kms.KeyManagementServiceClient | None = None,
    ) -> None:
        self._key_version = validate_key_version_name(key_version)
        if client is None:
            client = kms.KeyManagementServiceClient(
                credentials=federated_credentials(tokens, wif_audience)
            )
        self._client = client

    @property
    def key_version(self) -> str:
        return self._key_version

    def unwrap(self, wrapped: bytes) -> bytes:
        try:
            response = self._client.asymmetric_decrypt(
                request={
                    "name": self._key_version,
                    "ciphertext": wrapped,
                    "ciphertext_crc32c": _crc32c(wrapped),
                },
                timeout=KMS_TIMEOUT_SECONDS,
            )
        except (api_exceptions.GoogleAPIError, auth_exceptions.GoogleAuthError) as exc:
            raise KmsError(f"KMS decrypt failed: {type(exc).__name__}") from None
        if not response.verified_ciphertext_crc32c:
            raise KmsError("KMS did not verify the ciphertext checksum")
        if response.plaintext_crc32c != _crc32c(response.plaintext):
            raise KmsError("KMS plaintext checksum mismatch")
        return response.plaintext

    def public_key_pem(self) -> str:
        try:
            response = self._client.get_public_key(
                request={"name": self._key_version}, timeout=KMS_TIMEOUT_SECONDS
            )
        except (api_exceptions.GoogleAPIError, auth_exceptions.GoogleAuthError) as exc:
            raise KmsError(
                f"KMS public key fetch failed: {type(exc).__name__}"
            ) from None
        if response.name and response.name != self._key_version:
            raise KmsError("KMS returned a different key version")
        if response.algorithm.name != KMS_ALGORITHM:
            raise KmsError(f"KMS key algorithm must be {KMS_ALGORITHM}")
        if response.pem_crc32c != _crc32c(response.pem.encode("ascii")):
            raise KmsError("KMS public key checksum mismatch")
        return response.pem
