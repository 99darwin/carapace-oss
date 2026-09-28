"""The deploy's last step: owner key, account, attested enclave, CLI config.

After the stack is up, ``carapace deploy`` leaves the CLI ready to use:

1. An owner key in the config directory (created if there is none).
2. A session on the new server: sign up, or log in if the account exists.
   The owner key is registered before the session is saved, so a saved
   session always means a registered key. Registration on the server is
   closed once it has an account (#52); the first sign-up proves it is
   this deploy's with a one-time setup token. The token is generated here,
   before the deploy, and kept only in memory: the stack gets its SHA-256
   (see :func:`setup_token_sha256`), the server gets the token once.
3. ``verify`` against the enclave, trusting exactly the image digest this
   deploy published, in this deploy's project, service account, control
   plane and KMS key, retried while the VM and Cloud Run start.
4. The pin saved only if the attested KMS key version is the one the stack
   created.

Every input (email, password, passphrase) is collected by
:func:`prepare_account` before anything is deployed, so a script missing a
flag fails in seconds, not after the deploy. Each step is idempotent, so a
failed run resumes by running ``carapace deploy`` again.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from carapace_cli.attestation import TrustPolicy
from carapace_cli.deploy.interview import (
    Interview,
    InvalidInputError,
    MissingInputError,
)
from carapace_cli.deploy.polling import Clock, poll_until
from carapace_cli.deploy.preflight import validate_email
from carapace_cli.errors import (
    CarapaceError,
    EnclaveError,
    NetworkError,
    RegistrationRefusedError,
    ServerError,
    StorageError,
    VerificationError,
)
from carapace_cli.files import read_private_json
from carapace_cli.owner import register_owner_key
from carapace_cli.ownerkey_store import (
    MIN_PASSPHRASE_CHARS,
    load_owner_key,
    owner_key_path,
    save_owner_key,
)
from carapace_cli.passwords import ask_new_password, check_password
from carapace_cli.pin import IDENTITY_FIELDS, EnclavePin, pin_path, save_pin
from carapace_cli.prompts import prompt_hidden, read_password
from carapace_cli.session import (
    ServerClient,
    Session,
    authenticate,
    load_session,
    save_session,
    session_path,
)
from carapace_cli.urls import normalize_base_url
from carapace_cli.verify import verify_enclave
from carapace_crypto import OwnerKey

# The VM boots, pulls and attests in a few minutes; Cloud Run cold-starts.
READY_TIMEOUT_SECONDS = 900.0
READY_POLL_SECONDS = 15.0
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_TOO_MANY_REQUESTS = 429
HTTP_SERVER_ERROR = 500
SETUP_TOKEN_BYTES = 32
SETUP_TOKEN_SHA256_KEY = "carapace:setup_token_sha256"  # noqa: S105
IDENTITY_OUTPUTS = (
    "enclave_service_account",
    "control_plane_url",
    "kms_key_name",
    "kms_key_version_name",
)


class FirstRunError(CarapaceError):
    """The CLI could not be connected to the new deployment."""


@dataclass(frozen=True)
class DeploymentIdentity:
    """What this deploy created, which the pinned enclave must match."""

    project: str
    enclave_service_account: str
    control_plane_url: str
    kms_key_name: str
    kms_key_version_name: str

    @classmethod
    def from_outputs(
        cls, project: str, outputs: Mapping[str, Any]
    ) -> DeploymentIdentity:
        values = {name: outputs.get(name) for name in IDENTITY_OUTPUTS}
        missing = [name for name, value in values.items() if not value]
        if missing or not all(isinstance(v, str) for v in values.values()):
            raise FirstRunError(
                f"the stack outputs lack {', '.join(missing) or 'string values'}; "
                "run `carapace deploy` again"
            )
        identity = cls(project=project, **values)
        prefix = f"{identity.kms_key_name}/cryptoKeyVersions/"
        if not identity.kms_key_version_name.startswith(prefix):
            raise FirstRunError("the stack's KMS key version is not of its KMS key")
        return identity


def trust_policy_for(enclave_digest: str, identity: DeploymentIdentity) -> TrustPolicy:
    """What ``verify`` accepts for this deployment.

    The published digest, run in this project as this deploy's enclave
    service account, reporting to this control plane with this KMS key
    version (the value the enclave is launched with as ``KMS_KEY_NAME``).
    """
    return TrustPolicy(
        allowed_digests=frozenset({enclave_digest}),
        project_id=identity.project,
        service_account=identity.enclave_service_account,
        control_plane_url=identity.control_plane_url,
        kms_key_name=identity.kms_key_version_name,
    )


def check_pin_identity(
    pin: EnclavePin, identity: DeploymentIdentity, *, enclave_digest: str
) -> None:
    """Refuse a pin that is not this deployment's enclave.

    Raises:
        VerificationError: The attested image, KMS key version, or any of the
            pinned deployment identity fields differs.
    """
    if pin.image_digest != enclave_digest:
        raise VerificationError(
            f"the enclave runs {pin.image_digest}, not the deployed {enclave_digest}"
        )
    if pin.kms_key_version != identity.kms_key_version_name:
        raise VerificationError(
            "the enclave's KMS key version is not the one this deploy created; "
            "refusing to pin it"
        )
    expected = trust_policy_for(enclave_digest, identity)
    for name in IDENTITY_FIELDS:
        if getattr(pin, name) != getattr(expected, name):
            raise VerificationError(
                f"the pin's {name} is {getattr(pin, name)!r}, not this "
                f"deployment's {getattr(expected, name)!r}; refusing to pin it"
            )


class Authenticator(Protocol):
    def __call__(
        self,
        server_url: str,
        email: str,
        password: str,
        *,
        register: bool = False,
        setup_token: str | None = None,
    ) -> Session: ...


class HiddenPrompt(Protocol):
    def __call__(self, prompt: str, *, confirm: bool = False) -> str: ...


def _default_server(config_dir: Path, session: Session) -> ServerClient:
    return ServerClient(config_dir, session=session)


def _password_from_stdin() -> str:
    return read_password(from_stdin=True)


@dataclass
class FirstRunServices:
    """Everything the first run reaches; tests replace each one."""

    authenticate: Authenticator = authenticate
    server: Callable[[Path, Session], ServerClient] = _default_server
    verify: Callable[[str, ServerClient, TrustPolicy], EnclavePin] = verify_enclave
    prompt: HiddenPrompt = prompt_hidden
    password_from_stdin: Callable[[], str] = _password_from_stdin


@dataclass(frozen=True)
class AccountFlags:
    email: str | None
    password_stdin: bool
    no_passphrase: bool


@dataclass
class PreparedAccount:
    """Inputs gathered before the deploy. Secrets are kept out of ``repr``."""

    config_dir: Path
    email: str | None
    password: str | None = field(default=None, repr=False)
    # Generated (``is_new_owner_key``) or loaded; None until it is needed.
    owner_key: OwnerKey | None = field(default=None, repr=False)
    is_new_owner_key: bool = False
    passphrase: str | None = field(default=None, repr=False)
    # The one-time token that claims a fresh server; only its hash is stored.
    setup_token: str | None = field(default=None, repr=False)


def new_setup_token() -> str:
    """A 256-bit token for the first registration. Never written anywhere."""
    return secrets.token_urlsafe(SETUP_TOKEN_BYTES)


def setup_token_sha256(token: str) -> str:
    """What the server is configured with: the token's SHA-256, in hex.

    Not a secret: the token has 256 bits, so its hash reveals nothing usable.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def setup_token_config(account: PreparedAccount) -> dict[str, str]:
    """The stack config for this run's setup token: its hash, if any.

    Only a run that signs up a new account has a token. Other runs leave
    the stored hash alone; the server ignores it once it has its account.
    """
    if account.setup_token is None:
        return {}
    return {SETUP_TOKEN_SHA256_KEY: setup_token_sha256(account.setup_token)}


def _load_owner_key(config_dir: Path, services: FirstRunServices) -> OwnerKey:
    return load_owner_key(
        owner_key_path(config_dir),
        passphrase=lambda: services.prompt("Owner key passphrase: "),
    )


def _new_passphrase(
    flags: AccountFlags, interview: Interview, services: FirstRunServices
) -> str | None:
    if flags.no_passphrase:
        return None
    if not interview.interactive:
        raise MissingInputError(
            "a new owner key needs a passphrase: pass --no-passphrase in "
            "non-interactive mode, or run `carapace init` first"
        )
    passphrase = services.prompt("New owner key passphrase: ", confirm=True)
    if len(passphrase) < MIN_PASSPHRASE_CHARS:
        raise InvalidInputError(
            f"the passphrase must be at least {MIN_PASSPHRASE_CHARS} characters"
        )
    return passphrase


def _password(
    flags: AccountFlags, interview: Interview, services: FirstRunServices
) -> str:
    if flags.password_stdin:
        return check_password(services.password_from_stdin())
    if not interview.interactive:
        raise MissingInputError("--password-stdin is required in non-interactive mode")
    return ask_new_password(
        lambda: services.prompt(
            "Account password (new, or the existing one): ", confirm=True
        ),
        interview.say,
    )


def prepare_account(
    config_dir: Path,
    flags: AccountFlags,
    interview: Interview,
    services: FirstRunServices,
    *,
    default_email: str,
) -> PreparedAccount:
    """Ask for everything the first run needs. Writes nothing.

    An existing session is reused, so no email or password is asked for.
    """
    account = PreparedAccount(config_dir=config_dir, email=None)
    has_session = session_path(config_dir).exists()
    if not owner_key_path(config_dir).exists():
        account.owner_key, account.is_new_owner_key = OwnerKey.generate(), True
        account.passphrase = _new_passphrase(flags, interview, services)
    elif not has_session:
        # A new account needs the key registered: unlock it now, not later.
        account.owner_key = _load_owner_key(config_dir, services)
    if has_session:
        return account
    account.email = interview.ask(
        "Email for your account on the new server",
        flag="--account-email",
        value=flags.email,
        default=default_email,
        validate=validate_email,
    )
    account.password = _password(flags, interview, services)
    account.setup_token = new_setup_token()
    return account


def _read_field(path: Path, name: str) -> str:
    try:
        return str(read_private_json(path).get(name))
    except StorageError as exc:
        raise FirstRunError(f"cannot read {path}: {exc}") from None


def check_config_dir(config_dir: Path, *, server_url: str, enclave_url: str) -> None:
    """Never replace a session or pin that belongs to another deployment."""
    hint = "use another --config-dir for this deployment"
    if session_path(config_dir).exists():
        existing = load_session(config_dir).server_url
        if existing != server_url:
            raise FirstRunError(f"{config_dir} is logged in to {existing}; {hint}")
    if pin_path(config_dir).exists():
        pinned = _read_field(pin_path(config_dir), "enclave_url")
        if pinned != enclave_url:
            raise FirstRunError(f"{config_dir} is pinned to {pinned}; {hint}")


def is_transient(exc: CarapaceError) -> bool:
    """Errors a starting server or enclave gives; anything else is final."""
    if isinstance(exc, NetworkError | EnclaveError):
        return True
    return isinstance(exc, ServerError) and (
        exc.status >= HTTP_SERVER_ERROR or exc.status == HTTP_TOO_MANY_REQUESTS
    )


def retry_transient[T](
    action: Callable[[], T], *, what: str, clock: Clock, say: Callable[[str], None]
) -> T:
    def attempt() -> T | None:
        try:
            return action()
        except CarapaceError as exc:
            if not is_transient(exc):
                raise
            say(f"  {what} is not ready yet ({exc}); retrying...")
            return None

    return poll_until(
        attempt,
        what=what,
        timeout_seconds=READY_TIMEOUT_SECONDS,
        interval_seconds=READY_POLL_SECONDS,
        clock=clock,
    )


def sign_in(
    services: FirstRunServices,
    server_url: str,
    email: str,
    password: str,
    *,
    setup_token: str | None,
    say: Callable[[str], None],
) -> Session:
    """Sign up with the setup token; if the server is taken, log in.

    A closed registration (the server already has its account) or a 400
    (signup is open and the email is taken) falls through to a login.
    """
    try:
        session = services.authenticate(
            server_url, email, password, register=True, setup_token=setup_token
        )
        say(f"Created the account {email}.")
        return session
    except RegistrationRefusedError as exc:
        if not exc.is_closed:
            raise FirstRunError(
                f"{server_url} refused this deploy's setup token; its "
                "setup_token_sha256 is not the one this run set. Run "
                "`carapace deploy` again"
            ) from None
        is_closed = True
    except ServerError as exc:
        if exc.status != HTTP_BAD_REQUEST:
            raise
        is_closed = False
    try:
        session = services.authenticate(server_url, email, password)
    except ServerError as exc:
        if exc.status != HTTP_UNAUTHORIZED:
            raise
        if is_closed:
            raise FirstRunError(
                f"{server_url} already has its account and {email} cannot "
                "log in to it. If you did not create that account, see "
                "SELF_HOST.md § Upgrading a server that was open."
            ) from None
        raise FirstRunError(
            f"{email} already has an account on {server_url} and this is not "
            "its password"
        ) from None
    say(f"Logged in as {email}.")
    return session


def _registered_public_keys(server: ServerClient) -> set[str]:
    records = server.get("/v1/owner-keys") or []
    return {
        str(record.get("public_key"))
        for record in records
        if isinstance(record, dict) and not record.get("retired_at")
    }


def _stored_public_key(config_dir: Path) -> str:
    """The owner key file's public half, read without its passphrase.

    Stored in the same standard base64 the server lists it in.
    """
    return _read_field(owner_key_path(config_dir), "public_key")


def ensure_owner_key_registered(
    server: ServerClient, account: PreparedAccount, services: FirstRunServices
) -> None:
    """Register the owner key unless the server already has it."""
    if account.owner_key is None:
        if _stored_public_key(account.config_dir) in _registered_public_keys(server):
            return
        account.owner_key = _load_owner_key(account.config_dir, services)
    register_owner_key(server, account.owner_key)


def complete_first_run(
    account: PreparedAccount,
    *,
    project: str,
    outputs: Mapping[str, Any],
    enclave_digest: str,
    services: FirstRunServices,
    clock: Clock,
    say: Callable[[str], None],
) -> EnclavePin:
    """Connect the CLI in ``account.config_dir`` to the deployment."""
    identity = DeploymentIdentity.from_outputs(project, outputs)
    server_url = normalize_base_url(
        identity.control_plane_url, what="server", allow_loopback_http=False
    )
    enclave_url = normalize_base_url(
        str(outputs.get("enclave_url") or ""), what="enclave", allow_loopback_http=False
    )
    config_dir = account.config_dir
    check_config_dir(config_dir, server_url=server_url, enclave_url=enclave_url)
    if account.is_new_owner_key and account.owner_key is not None:
        path = owner_key_path(config_dir)
        save_owner_key(path, account.owner_key, passphrase=account.passphrase)
        say(f"Owner key written to {path} (mode 0600). Back this file up.")
    email, password = account.email, account.password
    new_session = email is not None and password is not None
    if email is not None and password is not None:
        session = retry_transient(
            lambda: sign_in(
                services,
                server_url,
                email,
                password,
                setup_token=account.setup_token,
                say=say,
            ),
            what="the server",
            clock=clock,
            say=say,
        )
    else:
        session = load_session(config_dir)
    with services.server(config_dir, session) as server:

        def register() -> bool:
            ensure_owner_key_registered(server, account, services)
            return True

        retry_transient(register, what="the server", clock=clock, say=say)
        if new_session:
            save_session(config_dir, server.session)
        say("Verifying the enclave's attestation...")
        policy = trust_policy_for(enclave_digest, identity)
        pin = retry_transient(
            lambda: services.verify(enclave_url, server, policy),
            what="the enclave",
            clock=clock,
            say=say,
        )
    check_pin_identity(pin, identity, enclave_digest=enclave_digest)
    save_pin(config_dir, pin)
    say(f"Verified and pinned the enclave in {pin_path(config_dir)}.")
    return pin
