"""Boot identity and launcher tokens, including a tampering launcher."""

import time

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from carapace_enclave.attestation import (
    ATTESTATION_AUDIENCE,
    AttestationError,
    BootIdentity,
    LauncherClient,
    TokenSource,
    check_token,
    validate_audiences,
)
from carapace_enclave.attestation.token import REFRESH_AFTER_SECONDS
from carapace_enclave.clock import TrustedClock
from carapace_enclave_mock import MOCK_ISSUER, MockLauncher
from carapace_server.receipts.chain import boot_id_for as server_boot_id_for

from .conftest import BOOT_NONCE, SERVER_URL, WIF_AUDIENCE

# -- boot identity ----------------------------------------------------------------


def test_boot_id_matches_server_derivation() -> None:
    identity = BootIdentity.generate()
    cert = x509.load_pem_x509_certificate(identity.tls_cert_pem.encode())
    spki = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    assert identity.boot_id == server_boot_id_for(spki, identity.receipt_pubkey)
    assert len(identity.receipt_pubkey) == 32


def test_boot_identity_is_fresh_and_redacted() -> None:
    first, second = BootIdentity.generate(), BootIdentity.generate()
    assert first.boot_id != second.boot_id
    assert repr(first) == f"BootIdentity(boot_id={first.boot_id})"
    pem = first.tls_key_pem()
    assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")


# -- launcher tokens --------------------------------------------------------------


def test_fetch_requests_audience_and_nonce(
    tokens: TokenSource, mock_launcher: MockLauncher
) -> None:
    token = tokens.get(SERVER_URL)
    assert mock_launcher.requests == [
        {"audience": SERVER_URL, "token_type": "OIDC", "nonces": [BOOT_NONCE]}
    ]
    claims = jwt.decode(
        token.raw,
        mock_launcher.signing_key.public_key(),
        algorithms=["RS256"],
        audience=SERVER_URL,
    )
    assert claims["iss"] == MOCK_ISSUER
    assert claims["eat_nonce"] == BOOT_NONCE
    assert token.audience == SERVER_URL
    assert token.nonces == (BOOT_NONCE,)
    assert BOOT_NONCE not in repr(token) and token.raw not in repr(token)


def test_audiences_are_cached_separately(
    tokens: TokenSource, mock_launcher: MockLauncher
) -> None:
    server = tokens.get(SERVER_URL)
    public = tokens.get(ATTESTATION_AUDIENCE)
    assert tokens.get(SERVER_URL) is server
    assert tokens.get(ATTESTATION_AUDIENCE) is public
    assert [r["audience"] for r in mock_launcher.requests] == [
        SERVER_URL,
        ATTESTATION_AUDIENCE,
    ]


def test_wrong_audience_from_launcher_is_rejected(
    tokens: TokenSource, mock_launcher: MockLauncher
) -> None:
    # A launcher (or a man in the middle on its socket) that hands back a
    # token for another audience must not be used, least of all published.
    mock_launcher.overrides = {"aud": WIF_AUDIENCE}
    with pytest.raises(AttestationError, match="aud"):
        tokens.get(ATTESTATION_AUDIENCE)


def test_wrong_nonce_from_launcher_is_rejected(
    tokens: TokenSource, mock_launcher: MockLauncher
) -> None:
    mock_launcher.overrides = {"eat_nonce": "c1" * 32}
    with pytest.raises(AttestationError, match="eat_nonce"):
        tokens.get(SERVER_URL)


def test_missing_nonce_is_rejected(
    tokens: TokenSource, mock_launcher: MockLauncher
) -> None:
    mock_launcher.overrides = {"eat_nonce": None}
    with pytest.raises(AttestationError, match="eat_nonce"):
        tokens.get(SERVER_URL)


def test_nonce_among_several_is_accepted(mock_launcher: MockLauncher) -> None:
    raw = mock_launcher.sign(mock_launcher.claims(SERVER_URL, ["a1" * 20, BOOT_NONCE]))
    token = check_token(raw, audience=SERVER_URL, nonce=BOOT_NONCE)
    assert token.nonces == ("a1" * 20, BOOT_NONCE)


@pytest.mark.parametrize(
    "overrides",
    [{"iat": "now"}, {"exp": None}, {"iat": 10, "exp": 10}, {"iat": True}],
)
def test_malformed_times_are_rejected(
    mock_launcher: MockLauncher, overrides: dict
) -> None:
    claims = mock_launcher.claims(SERVER_URL, [BOOT_NONCE]) | overrides
    raw = jwt.encode(claims, mock_launcher.signing_key, algorithm="RS256")
    with pytest.raises(AttestationError):
        check_token(raw, audience=SERVER_URL, nonce=BOOT_NONCE)


@pytest.mark.parametrize("raw", ["", "a.b", "a..c", "a.!!!.c", "a.W10.c"])
def test_non_jwt_is_rejected(raw: str) -> None:
    with pytest.raises(AttestationError):
        check_token(raw, audience=SERVER_URL, nonce=BOOT_NONCE)


def test_token_feeds_clock_floor(mock_launcher: MockLauncher) -> None:
    future = time.time() + 7 * 24 * 3600
    mock_launcher.clock = lambda: future
    clock = TrustedClock()
    source = TokenSource(
        LauncherClient(transport=mock_launcher.transport()), clock, nonce=BOOT_NONCE
    )
    source.get(SERVER_URL)
    assert clock.now() == int(future)


def test_token_refreshes_on_monotonic_age(mock_launcher: MockLauncher) -> None:
    ticks = [0.0]
    source = TokenSource(
        LauncherClient(transport=mock_launcher.transport()),
        TrustedClock(),
        nonce=BOOT_NONCE,
        monotonic=lambda: ticks[0],
    )
    first = source.get(SERVER_URL)
    ticks[0] = REFRESH_AFTER_SECONDS - 1
    assert source.get(SERVER_URL) is first
    ticks[0] = REFRESH_AFTER_SECONDS
    assert source.get(SERVER_URL) is not first
    assert len(mock_launcher.requests) == 2


def test_refresh_all_refetches(
    tokens: TokenSource, mock_launcher: MockLauncher
) -> None:
    tokens.get(SERVER_URL)
    tokens.get(ATTESTATION_AUDIENCE)
    tokens.refresh_all()
    assert len(mock_launcher.requests) == 4


def test_launcher_error_status() -> None:
    launcher = LauncherClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(503, text="x"))
    )
    with pytest.raises(AttestationError, match="HTTP 503"):
        launcher.fetch(SERVER_URL, [BOOT_NONCE])


def test_launcher_unreachable() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no socket", request=request)

    launcher = LauncherClient(transport=httpx.MockTransport(refuse))
    with pytest.raises(AttestationError, match="unreachable: ConnectError"):
        launcher.fetch(SERVER_URL, [BOOT_NONCE])


def test_missing_socket_fails(tmp_path) -> None:
    launcher = LauncherClient(socket_path=str(tmp_path / "missing.sock"))
    with pytest.raises(AttestationError, match="unreachable"):
        launcher.fetch(SERVER_URL, [BOOT_NONCE])


@pytest.mark.parametrize("nonce", ["short", "x" * 75, "ñ" * 20])
def test_nonce_limits(nonce: str, mock_launcher: MockLauncher) -> None:
    launcher = LauncherClient(transport=mock_launcher.transport())
    with pytest.raises(AttestationError, match="nonce"):
        launcher.fetch(SERVER_URL, [nonce])
    assert mock_launcher.requests == []


# -- audience separation ----------------------------------------------------------


def test_valid_audiences() -> None:
    validate_audiences(control_plane_url=SERVER_URL, wif_audience=WIF_AUDIENCE)


@pytest.mark.parametrize(
    ("server", "wif"),
    [
        (SERVER_URL, ATTESTATION_AUDIENCE),
        (SERVER_URL, "https://sts.googleapis.com"),
        (SERVER_URL, SERVER_URL),
        (SERVER_URL, ""),
        ("carapace-attestation", WIF_AUDIENCE),
        ("ftp://server", WIF_AUDIENCE),
    ],
)
def test_overlapping_audiences_are_refused(server: str, wif: str) -> None:
    with pytest.raises(AttestationError):
        validate_audiences(control_plane_url=server, wif_audience=wif)
