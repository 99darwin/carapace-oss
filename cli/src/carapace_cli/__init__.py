"""Carapace command-line client and Python SDK.

The SDK entry point is :class:`Client`; see :mod:`carapace_cli.sdk`.
"""

from carapace_cli.errors import (
    CarapaceError,
    EnclaveError,
    NetworkError,
    PinError,
    ServerError,
    VerificationError,
)
from carapace_cli.sdk import Client, Response

__all__ = [
    "CarapaceError",
    "Client",
    "EnclaveError",
    "NetworkError",
    "PinError",
    "Response",
    "ServerError",
    "VerificationError",
]
