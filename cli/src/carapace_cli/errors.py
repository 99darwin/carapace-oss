"""Errors the CLI and SDK raise.

Messages never include secret values, API keys, tokens or passphrases:
they are shown to users and may end up in logs or bug reports.
"""

from __future__ import annotations

import ssl
from collections.abc import Iterator
from contextlib import contextmanager

import httpx


class CarapaceError(Exception):
    """Base class. ``str(exc)`` is safe to show and log."""


class StorageError(CarapaceError):
    """A local file is missing, unreadable, or has unsafe permissions."""


class OwnerKeyError(CarapaceError):
    """The owner key is missing, corrupt, or the passphrase is wrong."""


class ServerError(CarapaceError):
    """The control-plane server returned an error."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"server returned {status}: {detail}")
        self.status = status
        self.detail = detail


# The server's stable 403 details for a refused registration (#52).
REGISTRATION_CLOSED = "Registration is closed"
SETUP_TOKEN_INVALID = "Invalid setup token"  # noqa: S105 - a message, not a token


class RegistrationRefusedError(ServerError):
    """The server refused a new account: closed, or a bad setup token."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(status, detail)
        if detail == REGISTRATION_CLOSED:
            hint = (
                "this server already has its account. Log in with "
                "`carapace login`, or ask the operator to enable "
                "signup (CARAPACE_ALLOW_SIGNUP=true)"
            )
        else:
            hint = (
                "the setup token is missing or wrong. Pass --setup-token "
                "(or set CARAPACE_SETUP_TOKEN) with the token whose SHA-256 "
                "is the server's CARAPACE_SETUP_TOKEN_SHA256"
            )
        self.args = (f"registration refused: {hint}",)

    @property
    def is_closed(self) -> bool:
        return self.detail == REGISTRATION_CLOSED


class NotLoggedInError(CarapaceError):
    """No session, or the session can no longer be refreshed."""


class NetworkError(CarapaceError):
    """The server or enclave could not be reached."""


class VerificationError(CarapaceError):
    """An attestation, pin, KMS key, grant or receipt check failed.

    Always fail closed on this error: nothing it guards may be used.
    """


class PinError(VerificationError):
    """No enclave pin, or the enclave presented a different certificate."""


class EnclaveError(CarapaceError):
    """The enclave refused or failed a request."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(f"enclave returned {status}: {code}")
        self.status = status
        self.code = code


def _is_cert_failure(exc: BaseException) -> bool:
    seen: BaseException | None = exc
    while seen is not None:
        if isinstance(seen, ssl.SSLCertVerificationError):
            return True
        seen = seen.__cause__ or seen.__context__
    return False


@contextmanager
def network_errors(what: str, *, pinned: bool = False) -> Iterator[None]:
    """Turn httpx transport failures into :class:`CarapaceError`.

    With ``pinned``, a certificate verification failure means the peer is
    not the pinned enclave and raises :class:`PinError`. Messages carry only
    the exception type: httpx messages can include URLs.
    """
    try:
        yield
    except httpx.TransportError as exc:
        if pinned and _is_cert_failure(exc):
            raise PinError(f"{what} TLS certificate does not match the pin") from None
        raise NetworkError(f"cannot reach the {what}: {type(exc).__name__}") from None
