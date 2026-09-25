"""DEV ONLY: stand-ins for Confidential Space and Cloud KMS.

This directory lives outside ``enclave/src`` on purpose: it is not part of
the ``carapace-enclave`` wheel and never enters the enclave image. Tests
import it through pytest's ``pythonpath``. Nothing it produces is trusted by
a production server: tokens carry ``iss = mock://local``, which a server in
``prod`` mode refuses, and the "KMS" is an RSA key in process memory.
"""

from carapace_enclave_mock.kms import MOCK_KMS_KEY_VERSION, LocalRsaDecrypter
from carapace_enclave_mock.launcher import (
    MOCK_ISSUER,
    MOCK_KEY_ID,
    MockLauncher,
)

__all__ = [
    "MOCK_ISSUER",
    "MOCK_KEY_ID",
    "MOCK_KMS_KEY_VERSION",
    "LocalRsaDecrypter",
    "MockLauncher",
]
