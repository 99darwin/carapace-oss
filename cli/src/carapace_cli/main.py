"""The ``carapace`` command.

Secrets, passwords and passphrases are never accepted as arguments: they
are read from a hidden prompt or from stdin, so they stay out of shell
history and process listings. API keys for ``request`` come from
``CARAPACE_API_KEY`` or a 0600 file.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, TextIO

from carapace_cli.attestation import (
    COSIGN_NOT_VERIFIED_NOTICE,
    INSECURE_MOCK_BANNER,
    TrustPolicy,
    validate_digest,
)
from carapace_cli.audit import (
    fetch_receipt_pages,
    load_receipt_file,
    verify_receipts,
)
from carapace_cli.deploy.command import add_deploy_commands
from carapace_cli.errors import CarapaceError, StorageError
from carapace_cli.files import default_config_dir, read_private, write_private
from carapace_cli.keys import (
    REVOKE_WARNING,
    create_api_key,
    list_api_keys,
    revoke_api_key,
)
from carapace_cli.owner import register_owner_key
from carapace_cli.ownerkey_store import (
    is_passphrase_protected,
    load_owner_key,
    owner_key_path,
    save_owner_key,
)
from carapace_cli.pin import EnclavePin, load_pin, pin_path, save_pin
from carapace_cli.prompts import prompt_hidden, read_password, read_secret_value, zero
from carapace_cli.sdk import API_KEY_ENV, Client
from carapace_cli.secrets_ops import (
    DEFAULT_TEMPLATE,
    add_secret,
    build_policy,
    list_secrets,
    resolve_secret_id,
    verified_secret_version,
)
from carapace_cli.session import (
    ServerClient,
    authenticate,
    save_session,
    session_path,
)
from carapace_cli.verify import trust_policy_from_pin, verify_enclave
from carapace_crypto import OwnerKey
from carapace_crypto.grant import DEFAULT_GRANT_TTL_SECONDS, MAX_GRANT_TTL_SECONDS

SECONDS_PER_DAY = 24 * 3600
EXIT_ERROR = 1
EXIT_INTERRUPTED = 130


class Context:
    def __init__(self, config_dir: Path, out: TextIO, err: TextIO) -> None:
        self.config_dir = config_dir
        self.out = out
        self.err = err

    def say(self, message: str) -> None:
        print(message, file=self.err)

    def owner_key(self) -> OwnerKey:
        path = owner_key_path(self.config_dir)
        return load_owner_key(
            path, passphrase=lambda: prompt_hidden("Owner key passphrase: ")
        )

    def server(self) -> ServerClient:
        return ServerClient(self.config_dir)

    def pin(self) -> EnclavePin:
        """The pinned enclave, with the mock banner if it was never attested.

        Every command that seals to, calls or audits the enclave loads the
        pin here, so an ``--insecure-mock`` pin is never used silently.
        """
        pin = load_pin(self.config_dir)
        if pin.insecure_mock:
            self.say(INSECURE_MOCK_BANNER)
        return pin


# -- commands ---------------------------------------------------------------------


def cmd_init(args: argparse.Namespace, ctx: Context) -> int:
    path = owner_key_path(ctx.config_dir)
    passphrase = None
    if not args.no_passphrase:
        passphrase = prompt_hidden("New owner key passphrase: ", confirm=True)
    owner_key = OwnerKey.generate()
    save_owner_key(path, owner_key, passphrase=passphrase)
    ctx.say(f"Owner key written to {path} (mode 0600).")
    ctx.say("Back this file up: losing it means re-sealing every secret.")
    print(f"fingerprint {owner_key.fingerprint.hex()}", file=ctx.out)
    return 0


def _login(args: argparse.Namespace, ctx: Context, *, register: bool) -> int:
    password = read_password(from_stdin=args.password_stdin, confirm=register)
    session = authenticate(args.server, args.email, password, register=register)
    save_session(ctx.config_dir, session)
    ctx.say(
        f"Logged in to {session.server_url}; tokens in {session_path(ctx.config_dir)}"
    )
    if owner_key_path(ctx.config_dir).exists():
        with ServerClient(ctx.config_dir, session=session) as server:
            record = register_owner_key(server, ctx.owner_key())
        ctx.say(f"Owner key {record.get('fingerprint')} is registered.")
    else:
        ctx.say(
            "No owner key yet: run `carapace init`, then `carapace owner register`."
        )
    return 0


def cmd_signup(args: argparse.Namespace, ctx: Context) -> int:
    return _login(args, ctx, register=True)


def cmd_login(args: argparse.Namespace, ctx: Context) -> int:
    return _login(args, ctx, register=False)


def cmd_logout(_: argparse.Namespace, ctx: Context) -> int:
    with ctx.server() as server:
        server.logout()
    session_path(ctx.config_dir).unlink(missing_ok=True)
    ctx.say("Logged out.")
    return 0


def cmd_owner_register(_: argparse.Namespace, ctx: Context) -> int:
    with ctx.server() as server:
        record = register_owner_key(server, ctx.owner_key())
    print(f"registered {record.get('fingerprint')}", file=ctx.out)
    return 0


def cmd_owner_show(_: argparse.Namespace, ctx: Context) -> int:
    path = owner_key_path(ctx.config_dir)
    owner_key = ctx.owner_key()
    protected = is_passphrase_protected(path)
    print(f"fingerprint {owner_key.fingerprint.hex()}", file=ctx.out)
    print(f"file        {path}", file=ctx.out)
    print(f"passphrase  {'yes' if protected else 'no'}", file=ctx.out)
    return 0


def cmd_verify(args: argparse.Namespace, ctx: Context) -> int:
    digests = {validate_digest(d) for d in args.allow_digest}
    ctx.say(COSIGN_NOT_VERIFIED_NOTICE)
    mock_key_pem = None
    if args.insecure_mock:
        if not args.mock_issuer_key:
            raise CarapaceError("--insecure-mock requires --mock-issuer-key")
        try:
            mock_key_pem = Path(args.mock_issuer_key).read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError) as exc:
            raise CarapaceError(f"cannot read --mock-issuer-key: {exc}") from None
        ctx.say(INSECURE_MOCK_BANNER)
    elif args.mock_issuer_key:
        raise CarapaceError("--mock-issuer-key is only valid with --insecure-mock")
    with ctx.server() as server:
        policy = TrustPolicy(
            allowed_digests=frozenset(digests),
            mock_key_pem=mock_key_pem,
            project_id=args.project_id,
            service_account=args.service_account,
            # The deployment's CONTROL_PLANE_URL is the server's public URL.
            # Only an omitted flag defaults; an empty one is refused.
            control_plane_url=(
                server.server_url
                if args.control_plane_url is None
                else args.control_plane_url
            ),
            kms_key_name=args.kms_key,
        )
        pin = verify_enclave(args.enclave, server, policy)
    save_pin(ctx.config_dir, pin)
    if pin.insecure_mock:
        ctx.say(INSECURE_MOCK_BANNER)
    ctx.say(f"Pinned in {pin_path(ctx.config_dir)}.")
    print(f"verified {pin.enclave_url}", file=ctx.out)
    print(f"boot_id  {pin.boot_id}", file=ctx.out)
    print(f"image    {pin.image_digest}", file=ctx.out)
    print(f"kms_key  {pin.kms_key_version}", file=ctx.out)
    print(f"project  {pin.project_id}", file=ctx.out)
    print(f"account  {pin.service_account}", file=ctx.out)
    print(f"server   {pin.control_plane_url}", file=ctx.out)
    return 0


def cmd_secret_add(args: argparse.Namespace, ctx: Context) -> int:
    policy = build_policy(
        hosts=args.host,
        host_suffixes=args.host_suffix,
        methods=args.method or ["GET"],
        inject_kind=args.inject,
        inject_name=_injection_name(args),
        template=args.template,
        ports=args.port,
    )
    pin = ctx.pin()
    owner_key = ctx.owner_key()
    with ctx.server() as server:
        plaintext = read_secret_value()
        try:
            info = add_secret(
                server,
                owner_key,
                pin,
                name=args.name,
                policy=policy,
                plaintext=plaintext,
            )
        finally:
            zero(plaintext)
    print(f"{info.id} {info.name} version {info.version}", file=ctx.out)
    return 0


def _injection_name(args: argparse.Namespace) -> str | None:
    if args.inject_name is not None or args.inject != "header":
        return args.inject_name
    return "Authorization"


def cmd_secret_list(_: argparse.Namespace, ctx: Context) -> int:
    with ctx.server() as server:
        for info in list_secrets(server):
            hosts = ",".join(h["value"] for h in info.policy.get("hosts", []))
            print(f"{info.id} {info.name} v{info.version} {hosts}", file=ctx.out)
    return 0


def cmd_key_create(args: argparse.Namespace, ctx: Context) -> int:
    owner_key = ctx.owner_key()
    with ctx.server() as server:
        versions = dict(
            verified_secret_version(server, owner_key, ref) for ref in args.secret
        )
        raw, info = create_api_key(
            server,
            owner_key,
            name=args.name,
            secret_versions=versions,
            ttl_seconds=_ttl(args.ttl_days),
        )
    if args.output:
        write_private(Path(args.output), raw.encode("ascii") + b"\n")
        ctx.say(f"API key {info.id} written to {args.output} (mode 0600).")
    else:
        ctx.say(f"API key {info.id} created. It is shown once; store it now.")
        print(raw, file=ctx.out)
    return 0


def _ttl(days: int | None) -> int:
    if days is None:
        return DEFAULT_GRANT_TTL_SECONDS
    ttl = days * SECONDS_PER_DAY
    if not 0 < ttl <= MAX_GRANT_TTL_SECONDS:
        raise CarapaceError(
            f"--ttl-days must be 1..{MAX_GRANT_TTL_SECONDS // SECONDS_PER_DAY}"
        )
    return ttl


def cmd_key_list(_: argparse.Namespace, ctx: Context) -> int:
    owner_key = ctx.owner_key()
    with ctx.server() as server:
        for info in list_api_keys(server, owner_key):
            state = "revoked" if info.revoked else "active"
            grant = "ok" if info.grant_valid else "INVALID-SIGNATURE"
            print(
                f"{info.id} {info.name} {info.key_prefix} {state} grant={grant} "
                f"exp={info.grant_exp} secrets={','.join(info.secret_ids)}",
                file=ctx.out,
            )
    return 0


def cmd_key_revoke(args: argparse.Namespace, ctx: Context) -> int:
    owner_key = ctx.owner_key()
    with ctx.server() as server:
        revoke_api_key(server, owner_key, args.key_id)
    ctx.say(REVOKE_WARNING)
    return 0


def cmd_request(args: argparse.Namespace, ctx: Context) -> int:
    api_key = _read_api_key(args.api_key_file)
    secret_id = args.secret
    if not _is_uuid(secret_id):
        with ctx.server() as server:
            secret_id = resolve_secret_id(server, secret_id)
    headers = [_parse_header(h) for h in args.header]
    body = _read_body(args.data_file)
    client = Client(api_key, pin=ctx.pin())
    response = client.request(
        secret_id, args.method, args.url, headers=headers, body=body
    )
    ctx.say(f"HTTP {response.status}")
    buffer = getattr(ctx.out, "buffer", None)
    if buffer is None:
        ctx.out.write(response.text)
    else:
        ctx.out.flush()
        buffer.write(response.content)
        buffer.flush()
    return 0


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def _read_api_key(path: str | None) -> str | None:
    if path is None:
        return None  # Client falls back to CARAPACE_API_KEY.
    try:
        return read_private(Path(path)).decode("ascii").strip()
    except (StorageError, UnicodeDecodeError) as exc:
        raise CarapaceError(f"cannot read API key file: {exc}") from None


def _parse_header(raw: str) -> tuple[str, str]:
    name, sep, value = raw.partition(":")
    if not sep or not name.strip():
        raise CarapaceError(f"headers must look like 'Name: value': {raw!r}")
    return name.strip(), value.strip()


def _read_body(path: str | None) -> bytes | None:
    if path is None:
        return None
    if path == "-":
        return sys.stdin.buffer.read()
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise CarapaceError(f"cannot read {path}: {exc.strerror}") from None


def cmd_audit_fetch(args: argparse.Namespace, ctx: Context) -> int:
    with ctx.server() as server:
        secret_id = resolve_secret_id(server, args.secret) if args.secret else None
        pages = list(fetch_receipt_pages(server, secret_id=secret_id))
    write_private(Path(args.output), (json.dumps(pages, indent=1) + "\n").encode())
    ctx.say(f"Wrote {sum(len(p.get('receipts', [])) for p in pages)} receipts.")
    return 0


def cmd_audit_verify(args: argparse.Namespace, ctx: Context) -> int:
    pin = ctx.pin()
    owner_key = ctx.owner_key()
    with ctx.server() as server:
        server_url = server.server_url
        if args.file:
            pages: list[dict[str, Any]] = load_receipt_file(Path(args.file))
        else:
            secret_id = resolve_secret_id(server, args.secret) if args.secret else None
            pages = list(fetch_receipt_pages(server, secret_id=secret_id))
    report = verify_receipts(
        pages,
        policy=trust_policy_from_pin(pin),
        server_url=server_url,
        owner_fingerprint=owner_key.fingerprint.hex(),
    )
    for failure in report.failures:
        print(f"FAIL {failure}", file=ctx.out)
    print(
        f"{'OK' if report.ok else 'FAILED'}: {report.receipts} receipts from "
        f"{report.boots} attested boots verified, {report.gaps} gaps "
        "(other owners' receipts, or withheld)",
        file=ctx.out,
    )
    return 0 if report.ok else EXIT_ERROR


# -- parser ------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="carapace", description="Carapace client: seal, grant, request, audit."
    )
    parser.add_argument(
        "--config-dir", type=Path, help="default: $CARAPACE_CONFIG_DIR or XDG"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="generate the owner signing key")
    init.add_argument("--no-passphrase", action="store_true")
    init.set_defaults(handler=cmd_init)

    for name, handler in (("signup", cmd_signup), ("login", cmd_login)):
        cmd = sub.add_parser(name, help=f"{name} to a Carapace server")
        cmd.add_argument("--server", required=True)
        cmd.add_argument("--email", required=True)
        cmd.add_argument("--password-stdin", action="store_true")
        cmd.set_defaults(handler=handler)
    sub.add_parser("logout").set_defaults(handler=cmd_logout)

    owner = sub.add_parser("owner", help="owner key").add_subparsers(
        dest="owner_command", required=True
    )
    owner.add_parser("register").set_defaults(handler=cmd_owner_register)
    owner.add_parser("show").set_defaults(handler=cmd_owner_show)

    verify = sub.add_parser("verify", help="attest and pin the enclave")
    verify.add_argument("--enclave", required=True, help="https://host:port")
    verify.add_argument(
        "--allow-digest",
        action="append",
        default=[],
        help="sha256:<hex> image digest to trust; compare it with the CI build",
    )
    verify.add_argument(
        "--insecure-mock",
        action="store_true",
        help="INSECURE: trust a local mock attestation key (dev only)",
    )
    verify.add_argument("--mock-issuer-key", help="PEM public key of the mock")
    verify.add_argument(
        "--project-id", help="GCP project the enclave must run in (required)"
    )
    verify.add_argument(
        "--service-account",
        help="service account email the enclave must run as (required)",
    )
    verify.add_argument(
        "--kms-key",
        help="KMS key version the enclave must use: "
        "projects/.../cryptoKeys/.../cryptoKeyVersions/N (required)",
    )
    verify.add_argument(
        "--control-plane-url",
        help="server URL the enclave must report to (default: the logged-in server)",
    )
    verify.set_defaults(handler=cmd_verify)

    secret = sub.add_parser("secret").add_subparsers(
        dest="secret_command", required=True
    )
    add = secret.add_parser("add", help="seal a secret from stdin or a prompt")
    add.add_argument("name")
    add.add_argument("--host", action="append", default=[])
    add.add_argument("--host-suffix", action="append", default=[])
    add.add_argument("--method", action="append")
    add.add_argument("--port", action="append", type=int)
    add.add_argument(
        "--inject", choices=["header", "query", "basic_auth"], default="header"
    )
    add.add_argument("--inject-name")
    add.add_argument("--template", default=DEFAULT_TEMPLATE)
    add.set_defaults(handler=cmd_secret_add)
    secret.add_parser("list").set_defaults(handler=cmd_secret_list)

    key = sub.add_parser("key", help="agent API keys").add_subparsers(
        dest="key_command", required=True
    )
    create = key.add_parser("create")
    create.add_argument("name")
    create.add_argument("--secret", action="append", required=True)
    create.add_argument("--ttl-days", type=int)
    create.add_argument("--output", help="write the key to this 0600 file")
    create.set_defaults(handler=cmd_key_create)
    key.add_parser("list").set_defaults(handler=cmd_key_list)
    revoke = key.add_parser("revoke")
    revoke.add_argument("key_id")
    revoke.set_defaults(handler=cmd_key_revoke)

    request = sub.add_parser(
        "request", help=f"call through the enclave (API key: ${API_KEY_ENV})"
    )
    request.add_argument("secret")
    request.add_argument("method")
    request.add_argument("url")
    request.add_argument("-H", "--header", action="append", default=[])
    request.add_argument("--data-file", help="request body file, or - for stdin")
    request.add_argument("--api-key-file", help="0600 file holding the API key")
    request.set_defaults(handler=cmd_request)

    audit = sub.add_parser("audit").add_subparsers(dest="audit_command", required=True)
    audit_verify = audit.add_parser("verify", help="verify receipts offline")
    audit_verify.add_argument("--secret")
    audit_verify.add_argument("--file", help="pages saved by `audit fetch`")
    audit_verify.set_defaults(handler=cmd_audit_verify)
    audit_fetch = audit.add_parser("fetch", help="save receipts for offline checks")
    audit_fetch.add_argument("--secret")
    audit_fetch.add_argument("--output", required=True)
    audit_fetch.set_defaults(handler=cmd_audit_fetch)

    add_deploy_commands(sub)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    ctx = Context(
        args.config_dir or default_config_dir(), out or sys.stdout, err or sys.stderr
    )
    handler: Callable[[argparse.Namespace, Context], int] = args.handler
    try:
        return handler(args, ctx)
    except CarapaceError as exc:
        print(f"error: {exc}", file=ctx.err)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
