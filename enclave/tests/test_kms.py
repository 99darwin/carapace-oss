"""KMS unwrapping: resource-name checks, integrity checks, WIF wiring."""

import json
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs

import google_crc32c
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from google.api_core import exceptions as api_exceptions
from google.auth import exceptions as auth_exceptions
from google.cloud import kms

from carapace_crypto import OwnerKey, open_with_dek_unwrapper, seal
from carapace_enclave.attestation import (
    CloudKmsDecrypter,
    KmsError,
    TokenSource,
    require_key_version,
    validate_key_version_name,
    verify_round_trip,
)
from carapace_enclave.attestation.kms import (
    JWT_SUBJECT_TOKEN_TYPE,
    LauncherTokenSupplier,
    federated_credentials,
)
from carapace_enclave.attestation.token import token_claims
from carapace_enclave_mock import MOCK_KMS_KEY_VERSION, LocalRsaDecrypter

from .conftest import BOOT_NONCE, WIF_AUDIENCE

ALGORITHM = kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm
OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
)


def _pem(key: rsa.RSAPrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


# -- resource names ---------------------------------------------------------------


def test_valid_key_version_name() -> None:
    assert validate_key_version_name(MOCK_KMS_KEY_VERSION) == MOCK_KMS_KEY_VERSION


@pytest.mark.parametrize(
    "name",
    [
        "",
        MOCK_KMS_KEY_VERSION.rsplit("/cryptoKeyVersions", 1)[0],  # key, not version
        MOCK_KMS_KEY_VERSION.replace("/1", "/0"),
        MOCK_KMS_KEY_VERSION + "/extra",
        MOCK_KMS_KEY_VERSION.replace("keyRings/mock", "keyRings/../x"),
        MOCK_KMS_KEY_VERSION + "\n",
        "projects/Bad_Project/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
    ],
)
def test_invalid_key_version_names(name: str) -> None:
    with pytest.raises(KmsError):
        validate_key_version_name(name)


def test_envelope_key_version_must_match() -> None:
    require_key_version(None, MOCK_KMS_KEY_VERSION)
    require_key_version(MOCK_KMS_KEY_VERSION, MOCK_KMS_KEY_VERSION)
    other = MOCK_KMS_KEY_VERSION.replace("/1", "/2")
    with pytest.raises(KmsError, match="different KMS key version"):
        require_key_version(other, MOCK_KMS_KEY_VERSION)


# -- public key round trip --------------------------------------------------------


def test_round_trip_accepts_matching_key(kms_decrypter: LocalRsaDecrypter) -> None:
    verify_round_trip(kms_decrypter, kms_decrypter.public_key_pem())


def test_round_trip_rejects_substituted_key(
    kms_decrypter: LocalRsaDecrypter,
) -> None:
    impostor = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    with pytest.raises(KmsError):
        verify_round_trip(kms_decrypter, _pem(impostor))


def test_round_trip_rejects_small_key(kms_decrypter: LocalRsaDecrypter) -> None:
    small = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    with pytest.raises(KmsError, match="4096"):
        verify_round_trip(kms_decrypter, _pem(small))


def test_round_trip_rejects_garbage(kms_decrypter: LocalRsaDecrypter) -> None:
    with pytest.raises(KmsError, match="PEM"):
        verify_round_trip(kms_decrypter, "not a key")


def test_local_decrypter_unwraps_sealed_dek(kms_decrypter: LocalRsaDecrypter) -> None:
    owner = OwnerKey.generate()
    envelope = seal(
        kms_decrypter.public_key_pem(),
        "s1",
        "o1",
        {},
        b"plaintext-secret",
        owner_key=owner,
        version=1,
        kms_key_version=kms_decrypter.key_version,
    )
    plaintext, _ = open_with_dek_unwrapper(
        envelope,
        kms_decrypter.unwrap,
        expected_secret_id="s1",
        expected_owner_pk=owner.public_key,
        min_version=1,
    )
    assert plaintext == b"plaintext-secret"
    # Like Cloud KMS, a bad ciphertext is a KMS failure, not tampering.
    with pytest.raises(KmsError):
        kms_decrypter.unwrap(b"\x00" * 512)


# -- Cloud KMS client -------------------------------------------------------------


def _crc(data: bytes) -> int:
    return google_crc32c.value(data)


@dataclass
class FakeKmsClient:
    """Stands in for KeyManagementServiceClient; decrypts with a local key."""

    private_key: rsa.RSAPrivateKey
    tamper: dict[str, Any] = field(default_factory=dict)
    error: Exception | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    def asymmetric_decrypt(
        self, request: dict[str, Any], timeout: float
    ) -> kms.AsymmetricDecryptResponse:
        self.calls.append(request)
        if self.error:
            raise self.error
        ciphertext = request["ciphertext"]
        verified = request["ciphertext_crc32c"] == _crc(ciphertext)
        plaintext = LocalRsaDecrypter(self.private_key).unwrap(ciphertext)
        fields = {
            "plaintext": plaintext,
            "plaintext_crc32c": _crc(plaintext),
            "verified_ciphertext_crc32c": verified,
        }
        return kms.AsymmetricDecryptResponse(**(fields | self.tamper))

    def get_public_key(self, request: dict[str, Any], timeout: float) -> kms.PublicKey:
        self.calls.append(request)
        if self.error:
            raise self.error
        pem = _pem(self.private_key)
        fields = {
            "pem": pem,
            "pem_crc32c": _crc(pem.encode()),
            "algorithm": ALGORITHM.RSA_DECRYPT_OAEP_4096_SHA256,
            "name": request["name"],
        }
        return kms.PublicKey(**(fields | self.tamper))


@pytest.fixture(scope="module")
def kms_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def _decrypter(client: FakeKmsClient, tokens: TokenSource) -> CloudKmsDecrypter:
    return CloudKmsDecrypter(
        key_version=MOCK_KMS_KEY_VERSION,
        wif_audience=WIF_AUDIENCE,
        tokens=tokens,
        client=client,  # type: ignore[arg-type]
    )


def test_cloud_unwrap_and_public_key(
    kms_key: rsa.RSAPrivateKey, tokens: TokenSource
) -> None:
    client = FakeKmsClient(kms_key)
    decrypter = _decrypter(client, tokens)
    verify_round_trip(decrypter, decrypter.public_key_pem())
    assert {c["name"] for c in client.calls} == {MOCK_KMS_KEY_VERSION}
    assert client.calls[1]["ciphertext_crc32c"] == _crc(client.calls[1]["ciphertext"])


@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        ({"verified_ciphertext_crc32c": False}, "ciphertext checksum"),
        ({"plaintext_crc32c": 1}, "plaintext checksum"),
    ],
)
def test_cloud_unwrap_integrity(
    kms_key: rsa.RSAPrivateKey, tokens: TokenSource, tamper: dict, message: str
) -> None:
    decrypter = _decrypter(FakeKmsClient(kms_key, tamper=tamper), tokens)
    wrapped = kms_key.public_key().encrypt(secrets.token_bytes(32), OAEP)
    with pytest.raises(KmsError, match=message):
        decrypter.unwrap(wrapped)


@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        ({"algorithm": ALGORITHM.RSA_DECRYPT_OAEP_3072_SHA256}, "algorithm"),
        ({"pem_crc32c": 7}, "checksum"),
        ({"name": MOCK_KMS_KEY_VERSION.replace("/1", "/2")}, "different key"),
    ],
)
def test_cloud_public_key_checks(
    kms_key: rsa.RSAPrivateKey, tokens: TokenSource, tamper: dict, message: str
) -> None:
    decrypter = _decrypter(FakeKmsClient(kms_key, tamper=tamper), tokens)
    with pytest.raises(KmsError, match=message):
        decrypter.public_key_pem()


@pytest.mark.parametrize(
    "error",
    [
        api_exceptions.PermissionDenied("denied: secret-looking detail"),
        api_exceptions.InvalidArgument("bad ciphertext"),
        auth_exceptions.RefreshError("sts said no"),
    ],
)
def test_cloud_errors_are_opaque(
    kms_key: rsa.RSAPrivateKey, tokens: TokenSource, error: Exception
) -> None:
    decrypter = _decrypter(FakeKmsClient(kms_key, error=error), tokens)
    with pytest.raises(KmsError) as excinfo:
        decrypter.unwrap(b"x" * 512)
    assert str(excinfo.value) == f"KMS decrypt failed: {type(error).__name__}"
    assert excinfo.value.__cause__ is None
    with pytest.raises(KmsError, match="public key fetch failed"):
        decrypter.public_key_pem()


# -- workload identity federation -------------------------------------------------


def test_supplier_uses_wif_audience_only(tokens: TokenSource) -> None:
    supplier = LauncherTokenSupplier(tokens, WIF_AUDIENCE)
    claims = token_claims(supplier.get_subject_token(None, None))
    assert claims["aud"] == WIF_AUDIENCE
    assert claims["eat_nonce"] == BOOT_NONCE


def test_supplier_surfaces_attestation_failure_as_refresh_error(
    tokens: TokenSource, mock_launcher
) -> None:
    mock_launcher.overrides = {"aud": "carapace-attestation"}
    supplier = LauncherTokenSupplier(tokens, WIF_AUDIENCE)
    with pytest.raises(auth_exceptions.RefreshError, match="aud"):
        supplier.get_subject_token(None, None)


class _StsResponse:
    status = 200
    headers: dict[str, str] = {}  # noqa: RUF012

    def __init__(self, body: dict[str, Any]) -> None:
        self.data = json.dumps(body).encode()


class RecordingSts:
    """A google.auth transport that answers the STS exchange locally."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, url: str, method: str = "GET", body: Any = None, **kw: Any):
        self.calls.append({"url": url, "method": method, "body": body})
        return _StsResponse(
            {
                "access_token": "federated-access-token",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "Bearer",
                "expires_in": 3600,
            }
        )


def test_federated_credentials_exchange_launcher_token(tokens: TokenSource) -> None:
    credentials = federated_credentials(tokens, WIF_AUDIENCE)
    sts = RecordingSts()
    credentials.refresh(sts)
    assert credentials.token == "federated-access-token"
    [call] = sts.calls
    assert call["url"] == "https://sts.googleapis.com/v1/token"
    body = call["body"]
    form = parse_qs(body.decode() if isinstance(body, bytes) else body)
    assert form["audience"] == [WIF_AUDIENCE]
    assert form["subject_token_type"] == [JWT_SUBJECT_TOKEN_TYPE]
    subject = token_claims(form["subject_token"][0])
    assert subject["aud"] == WIF_AUDIENCE
    # No impersonation and no file-based credential source.
    assert credentials.service_account_email is None
    assert credentials.info.get("credential_source") is None


def test_federated_credentials_fail_closed_on_bad_token(
    tokens: TokenSource, mock_launcher
) -> None:
    mock_launcher.overrides = {"eat_nonce": "ff" * 32}
    credentials = federated_credentials(tokens, WIF_AUDIENCE)
    sts = RecordingSts()
    with pytest.raises(auth_exceptions.RefreshError):
        credentials.refresh(sts)
    assert sts.calls == []
