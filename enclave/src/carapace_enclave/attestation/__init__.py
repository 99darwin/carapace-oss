"""Boot identity, attestation tokens and attested KMS access."""

from carapace_enclave.attestation.identity import BootIdentity, boot_id_for
from carapace_enclave.attestation.kms import (
    CloudKmsDecrypter,
    DekDecrypter,
    KmsError,
    require_key_version,
    validate_key_version_name,
    verify_round_trip,
)
from carapace_enclave.attestation.token import (
    ATTESTATION_AUDIENCE,
    AttestationError,
    AttestationToken,
    LauncherClient,
    TokenSource,
    check_token,
    validate_audiences,
)

__all__ = [
    "ATTESTATION_AUDIENCE",
    "AttestationError",
    "AttestationToken",
    "BootIdentity",
    "CloudKmsDecrypter",
    "DekDecrypter",
    "KmsError",
    "LauncherClient",
    "TokenSource",
    "boot_id_for",
    "check_token",
    "require_key_version",
    "validate_audiences",
    "validate_key_version_name",
    "verify_round_trip",
]
