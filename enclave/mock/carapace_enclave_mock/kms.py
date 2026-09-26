"""DEV ONLY: a :class:`DekDecrypter` backed by an in-process RSA key."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from carapace_crypto import EnvelopeDecryptionError, rsa_oaep_unwrapper
from carapace_enclave.attestation.kms import (
    KMS_KEY_BITS,
    KmsError,
    validate_key_version_name,
)

MOCK_KMS_KEY_VERSION = (
    "projects/example-project/locations/global/keyRings/mock"
    "/cryptoKeys/dek-wrap/cryptoKeyVersions/1"
)


class LocalRsaDecrypter:
    """Unwraps with a local RSA-4096 key, as Cloud KMS would with its own."""

    def __init__(
        self,
        private_key: rsa.RSAPrivateKey,
        *,
        key_version: str = MOCK_KMS_KEY_VERSION,
    ) -> None:
        self._key_version = validate_key_version_name(key_version)
        self._private_key = private_key
        self._unwrap = rsa_oaep_unwrapper(private_key)
        self.calls = 0

    @classmethod
    def generate(cls, *, key_version: str = MOCK_KMS_KEY_VERSION) -> LocalRsaDecrypter:
        key = rsa.generate_private_key(public_exponent=65537, key_size=KMS_KEY_BITS)
        return cls(key, key_version=key_version)

    @property
    def key_version(self) -> str:
        return self._key_version

    def unwrap(self, wrapped: bytes) -> bytes:
        self.calls += 1
        try:
            return self._unwrap(wrapped)
        except EnvelopeDecryptionError:
            raise KmsError("KMS decrypt failed: InvalidArgument") from None

    def public_key_pem(self) -> str:
        return (
            self._private_key.public_key()
            .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            .decode("ascii")
        )
