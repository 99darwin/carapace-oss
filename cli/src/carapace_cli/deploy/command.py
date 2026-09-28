"""``carapace deploy``: interview, preflight, summary, confirm, deploy.

The command's collaborators (the GCP client, the Pulumi stack, HTTP to
GitHub and the registries, signature checks, local processes and the
clock) come from :class:`Services`, so tests replace every external call
with a fake.
"""

from __future__ import annotations

import argparse
import functools
import os
import shutil
import tempfile
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, TextIO

import httpx

from carapace_cli.deploy import pulumi_runner
from carapace_cli.deploy.destroy import (
    DestroyError,
    deployment_urls,
    destroy_warning,
    forget_deployment,
    remove_stack,
    run_destroy,
)
from carapace_cli.deploy.enclave_replace import (
    ALLOW_FLAG,
    EnclaveReplaceDeclined,
    EnclaveReplaceGate,
)
from carapace_cli.deploy.first_run import (
    AccountFlags,
    FirstRunServices,
    complete_first_run,
    prepare_account,
    setup_token_config,
)
from carapace_cli.deploy.gcp import AdcTokenSource, GcpApi
from carapace_cli.deploy.images import (
    DEFAULT_RELEASE_REPO,
    HTTP_TIMEOUT_SECONDS,
    BuiltImages,
    GitHubReleases,
    ImageError,
    Registries,
    ReleaseImages,
    SignatureVerifier,
    fetch_release,
    sigstore_verify,
    validate_repo,
    validate_tag,
)
from carapace_cli.deploy.infra import enclave_machine_type
from carapace_cli.deploy.interview import Interview, InvalidInputError
from carapace_cli.deploy.orchestrate import (
    FRESH_STACK,
    Images,
    ImageSource,
    PrebuiltImages,
    base_config,
    run_deploy,
    validate_digest,
)
from carapace_cli.deploy.polling import Clock
from carapace_cli.deploy.preflight import (
    DEFAULT_PREFIX,
    Flags,
    Target,
    check_prefix_unused,
    run_preflight,
    validate_prefix,
    validate_project_id,
)
from carapace_cli.deploy.pulumi_runner import (
    ProcessRunner,
    StackHandle,
    locate_infra,
    run_process,
)
from carapace_cli.deploy.record import (
    check_stack_config,
    delete_record,
    describe_existing,
    read_record,
    write_record,
)
from carapace_cli.deploy.state import (
    StateBackend,
    ensure_services,
    ensure_state_backend,
    state_backend_for,
)
from carapace_cli.deploy.summary import render_summary, state_bucket_name
from carapace_cli.deploy.zones import live_zonal_resource_urns, zone_fallback

EXIT_DECLINED = 1
# The stack enables it too, but a new stack's prefix check reads a WIF
# pool first, and a fresh project may not have the IAM API on yet.
PREFIX_CHECK_SERVICES = ("iam.googleapis.com",)


class CommandContext(Protocol):
    @property
    def config_dir(self) -> Path: ...

    @property
    def err(self) -> TextIO: ...

    def say(self, message: str) -> None: ...


StackFactory = Callable[[Target, StateBackend, CommandContext], StackHandle]


def open_pulumi_stack(
    target: Target, backend: StateBackend, ctx: CommandContext
) -> StackHandle:
    """The real stack: ``pulumi`` in ``infra/pulumi``, output to stderr."""
    return pulumi_runner.open_stack(target, backend, on_output=ctx.err.write)


@dataclass
class Services:
    """Factories for everything that talks to the outside world."""

    gcp: Callable[[], GcpApi]
    stack: StackFactory = open_pulumi_stack
    clock: Clock = Clock()
    # None means the network; tests pass an httpx.MockTransport.
    transport: httpx.BaseTransport | None = None
    verify: SignatureVerifier = sigstore_verify
    run: ProcessRunner = run_process
    which: Callable[[str], str | None] = shutil.which
    first_run: FirstRunServices = field(default_factory=FirstRunServices)


def default_services() -> Services:
    return Services(gcp=lambda: GcpApi(AdcTokenSource()))


def make_interview(args: argparse.Namespace, ctx: CommandContext) -> Interview:
    interview = Interview.from_args(
        non_interactive=args.non_interactive, assume_yes=args.yes
    )
    interview.stream_out = ctx.err
    return interview


def account_flags(args: argparse.Namespace) -> AccountFlags:
    return AccountFlags(
        email=args.account_email,
        password_stdin=args.password_stdin,
        no_passphrase=args.no_passphrase,
    )


def flags_from(args: argparse.Namespace) -> Flags:
    return Flags(
        project=args.project,
        region=args.region,
        zone=args.zone,
        prefix=args.prefix,
        alert_emails=tuple(args.alert_email),
    )


def ask_images(args: argparse.Namespace, interview: Interview) -> Images:
    """Digests of images already pushed to the stack's registry."""
    return Images(
        enclave_digest=interview.ask(
            "Enclave image digest (already in the registry)",
            flag="--enclave-digest",
            value=args.enclave_digest,
            validate=validate_digest,
        ),
        server_digest=interview.ask(
            "Server image digest (already in the registry)",
            flag="--server-digest",
            value=args.server_digest,
            validate=validate_digest,
        ),
    )


def image_mode(args: argparse.Namespace) -> str:
    """``release`` (the default), ``build`` or ``prebuilt``; one at most."""
    prebuilt = args.enclave_digest is not None or args.server_digest is not None
    chosen = [
        name
        for name, given in (
            ("--release", args.release is not None),
            ("--build", args.build),
            ("--enclave-digest/--server-digest", prebuilt),
        )
        if given
    ]
    if len(chosen) > 1:
        raise InvalidInputError(f"{' and '.join(chosen)} cannot be combined")
    return "build" if args.build else "prebuilt" if prebuilt else "release"


def require_tool(services: Services, name: str, why: str) -> str:
    executable = services.which(name)
    if executable is None:
        raise ImageError(f"{why} needs {name} on PATH")
    return executable


def cosign_checker(services: Services) -> Callable[[list[str]], bool | None]:
    """Run ``cosign`` if installed: True if it verified, None if absent."""

    def check(arguments: list[str]) -> bool | None:
        executable = services.which("cosign")
        if executable is None:
            return None
        result = services.run(
            [executable, *arguments],
            cwd=Path.cwd(),
            env=dict(os.environ),
            on_output=None,
        )
        return result.code == 0

    return check


def release_images(
    args: argparse.Namespace,
    interview: Interview,
    services: Services,
    registries: Registries,
    *,
    ctx: CommandContext,
    cleanup: ExitStack,
) -> tuple[ImageSource, str]:
    """The release's signed manifest, verified before the summary."""
    repo = validate_repo(args.release_repo)
    client = cleanup.enter_context(
        httpx.Client(
            transport=services.transport,
            timeout=HTTP_TIMEOUT_SECONDS,
            follow_redirects=True,
            trust_env=False,
        )
    )
    releases = GitHubReleases(client)
    tag = interview.ask(
        f"Release of {repo} to deploy",
        flag="--release",
        value=args.release,
        default=None if args.release else releases.latest_tag(repo),
        validate=validate_tag,
    )
    release = fetch_release(releases, services.verify, repo=repo, tag=tag)
    ctx.say(f"Verified the signature of {repo} release {tag}.")
    source = ReleaseImages(
        release=release,
        repo=repo,
        registries=registries,
        cosign=cosign_checker(services),
        say=ctx.say,
    )
    description = (
        f"release {tag} of {repo} (commit {release.commit[:12]}), "
        f"enclave {release.digest} (signature verified), server {tag}"
    )
    return source, description


def choose_images(
    args: argparse.Namespace,
    interview: Interview,
    services: Services,
    api: GcpApi,
    *,
    ctx: CommandContext,
    cleanup: ExitStack,
) -> tuple[ImageSource, str]:
    """The image source and the line the summary shows for it."""
    mode = image_mode(args)
    if mode == "prebuilt":
        images = ask_images(args, interview)
        return PrebuiltImages(images), (
            f"enclave {images.enclave_digest}, server {images.server_digest} "
            "(already in the registry)"
        )
    registries = Registries(token=api.access_token, transport=services.transport)
    cleanup.callback(registries.close)
    if mode == "release":
        return release_images(
            args, interview, services, registries, ctx=ctx, cleanup=cleanup
        )
    workdir = cleanup.enter_context(tempfile.TemporaryDirectory(prefix="carapace-"))
    source = BuiltImages(
        root=locate_infra().parents[1],
        workdir=Path(workdir),
        docker=require_tool(services, "docker", "--build"),
        git=require_tool(services, "git", "--build"),
        run=services.run,
        registries=registries,
        say=ctx.say,
        on_output=ctx.err.write,
    )
    return source, "built from this checkout with docker buildx (after confirming)"


def start_fresh_stack(
    stack: StackHandle,
    config: dict[str, str],
    target: Target,
    *,
    say: Callable[[str], None],
) -> None:
    """A record with no state and no local config: start the stack fresh.

    A run that failed before its first ``up`` finished leaves the record
    but no outputs. Without outputs no workloads run, so a missing local
    config cannot let a bootstrap delete anything. The stack starts from
    the fresh values, never a digest from an older config. A config that
    is present is left to the bootstrap, which checks it against the
    state.
    """
    if config.get("carapace:prefix") == target.prefix:
        return
    say(
        f"The record for {target.prefix!r} has no deployed stack behind it "
        f"and infra/pulumi/Pulumi.{target.prefix}.yaml is missing; starting "
        "a fresh stack."
    )
    stack.set_config(FRESH_STACK)


def refuse_reused_prefix(api: GcpApi, target: Target, *, clock: Clock) -> None:
    """For a new stack: stop if the prefix names a destroyed deployment's
    key ring or WIF pool, before any ``up`` creates half a stack."""
    ensure_services(api, target.project, clock=clock, names=PREFIX_CHECK_SERVICES)
    check_prefix_unused(api, target)


def cmd_deploy(args: argparse.Namespace, ctx: CommandContext) -> int:
    interview = make_interview(args, ctx)
    services = default_services()
    with services.gcp() as api, ExitStack() as cleanup:
        target, report = run_preflight(
            api,
            interview,
            flags_from(args),
            find_existing=functools.partial(read_record, api),
        )
        images, description = choose_images(
            args, interview, services, api, ctx=ctx, cleanup=cleanup
        )
        existing = report.existing
        ctx.say(
            render_summary(
                target,
                report,
                images=description,
                existing=describe_existing(existing, target) if existing else None,
            )
        )
        ctx.say(
            "Then the CLI signs up (or logs in) on the new server, verifies the "
            f"enclave and saves its config in {ctx.config_dir}."
        )
        if not interview.confirm(f"Deploy to {target.project} now?"):
            ctx.say("Aborted. Nothing was changed.")
            return EXIT_DECLINED
        account = prepare_account(
            ctx.config_dir,
            account_flags(args),
            interview,
            services.first_run,
            default_email=target.alert_emails[0],
        )
        backend = ensure_state_backend(api, target, say=ctx.say, clock=services.clock)
        stack = services.stack(target, backend, ctx)
        # The record can be unreadable, gone, or left behind by a failed
        # run; the backend's state, not the record, decides what exists.
        has_state = bool(stack.outputs())
        config = stack.config()
        check_stack_config(
            config,
            target,
            is_existing=has_state,
            zonal_resources=lambda: live_zonal_resource_urns(stack.resources()),
        )
        # New: the state tracks nothing, so no key ring or pool is this
        # stack's own. A first `up` that failed leaves its resources in the
        # state, and is resumed; a record alone vouches for nothing, since
        # a destroy whose record delete failed leaves one behind.
        if not has_state and not stack.has_resources():
            refuse_reused_prefix(api, target, clock=services.clock)
        if report.existing is not None and not has_state:
            start_fresh_stack(stack, config, target, say=ctx.say)
        # The record is written once the stack has its config, so a re-run
        # that finds the record also finds the config.
        stack.set_config(base_config(target) | setup_token_config(account))
        write_record(api, target)
        fallback = (
            None
            if args.no_zone_fallback
            else zone_fallback(
                api,
                stack,
                project=target.project,
                machine_type=enclave_machine_type(stack.config()),
            )
        )
        gate = EnclaveReplaceGate(
            interview=interview, allow=args.allow_enclave_replace, say=ctx.say
        )
        try:
            deployment = run_deploy(
                target,
                api=api,
                stack=stack,
                images=images,
                clock=services.clock,
                say=ctx.say,
                replace_gate=gate,
                zone_fallback=fallback,
            )
        except EnclaveReplaceDeclined as exc:
            ctx.say(f"Aborted: {exc}.")
            return EXIT_DECLINED
    ctx.say("Deployed.")
    if deployment.target.zone != target.zone:
        ctx.say(
            f"  zone: {deployment.target.zone} ({target.zone} had no capacity); "
            "later runs use it"
        )
    for name in ("enclave_url", "server_url", "kms_key_version_name"):
        ctx.say(f"  {name}: {deployment.outputs.get(name, '?')}")
    complete_first_run(
        account,
        project=target.project,
        outputs=deployment.outputs,
        enclave_digest=deployment.images.enclave_digest,
        services=services.first_run,
        clock=services.clock,
        say=ctx.say,
    )
    ctx.say("Ready: add a secret with `carapace secret add`.")
    return 0


def cmd_destroy(args: argparse.Namespace, ctx: CommandContext) -> int:
    # No --yes: only the typed project id confirms a destroy.
    interview = Interview.from_args(
        non_interactive=args.non_interactive, assume_yes=False
    )
    interview.stream_out = ctx.err
    services = default_services()
    with services.gcp() as api:
        project = interview.ask(
            "GCP project to destroy the deployment in",
            flag="--project",
            value=args.project,
            validate=validate_project_id,
        )
        prefix = interview.ask(
            "Resource name prefix",
            flag="--prefix",
            value=args.prefix,
            default=DEFAULT_PREFIX,
            validate=validate_prefix,
        )
        existing = read_record(api, project, prefix)
        if existing is None:
            raise DestroyError(
                f"no deployment {prefix!r} was made by `carapace deploy` in "
                f"{project}; destroy a stack deployed by hand with "
                "`pulumi destroy` (docs/SELF_HOST.md)"
            )
        target = Target(
            project=project,
            project_number="",
            region=existing.region,
            zone=existing.zone,
            prefix=prefix,
            alert_emails=existing.alert_emails,
        )
        ctx.say(destroy_warning(project, prefix))
        if not interview.confirm_typed(
            f"Type the project id ({project}) to destroy this deployment",
            expected=project,
            flag="--confirm-project",
            value=args.confirm_project,
        ):
            ctx.say("Aborted. Nothing was changed.")
            return EXIT_DECLINED
        stack = services.stack(target, state_backend_for(target), ctx)
        check_stack_config(
            stack.config(),
            target,
            is_existing=True,
            zonal_resources=lambda: live_zonal_resource_urns(stack.resources()),
        )
        # Read before the destroy: afterwards the stack has no outputs.
        urls = deployment_urls(stack.outputs())
        run_destroy(stack, say=ctx.say)
        # The record goes first: while it exists, `carapace destroy` can be
        # run again to resume, and once it is gone a deploy starts fresh.
        delete_record(api, project, prefix)
        remove_stack(stack, prefix=prefix, say=ctx.say)
    for line in forget_deployment(ctx.config_dir, urls):
        ctx.say(line)
    ctx.say(
        f"Destroyed. Kept the state bucket gs://{state_bucket_name(project)} and "
        "its KMS key, so the project can be deployed again."
    )
    return 0


def add_interview_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--project", help="GCP project id")
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="never prompt; a missing required flag is an error "
        "(implied when stdin is not a terminal)",
    )


def add_deploy_commands(sub: argparse._SubParsersAction) -> None:
    deploy = sub.add_parser(
        "deploy", help="deploy Carapace into your own GCP project (interactive)"
    )
    add_interview_flags(deploy)
    deploy.add_argument("--region", help="default: us-central1")
    deploy.add_argument("--zone", help="default: a zone of --region with N2D")
    deploy.add_argument(
        "--no-zone-fallback",
        action="store_true",
        help="if the zone is out of capacity for the enclave VM, stop instead "
        "of trying the region's other zones",
    )
    deploy.add_argument(
        ALLOW_FLAG,
        action="store_true",
        help="if the update would replace or delete the live enclave VM for "
        "a cause other than the new enclave digest (a new Confidential Space "
        "image, other metadata, a removal, or a cause pulumi does not give), "
        "go ahead without asking; --yes does not cover it. Only the first "
        "update of the VM is covered: a later rollout step that would replace "
        "it for a new cause is still refused",
    )
    deploy.add_argument("--prefix", help="resource name prefix (default: carapace)")
    deploy.add_argument(
        "--alert-email",
        action="append",
        default=[],
        help="security alert recipient; repeat for several",
    )
    deploy.add_argument(
        "--release",
        help="release tag whose signed images to deploy (default: the latest)",
    )
    deploy.add_argument(
        "--release-repo",
        default=DEFAULT_RELEASE_REPO,
        help=f"GitHub repository of the release (default: {DEFAULT_RELEASE_REPO})",
    )
    deploy.add_argument(
        "--build",
        action="store_true",
        help="build both images from this checkout with docker buildx instead",
    )
    deploy.add_argument(
        "--enclave-digest",
        help="use an enclave image already in the stack's registry, by digest",
    )
    deploy.add_argument(
        "--server-digest",
        help="use a server image already in the stack's registry, by digest",
    )
    deploy.add_argument(
        "--account-email",
        help="email of your account on the new server (default: the first "
        "--alert-email)",
    )
    deploy.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the account password from the first line of stdin",
    )
    deploy.add_argument(
        "--no-passphrase",
        action="store_true",
        help="if a new owner key is created, leave it unencrypted",
    )
    deploy.add_argument(
        "--yes", "-y", action="store_true", help="skip the final confirmation"
    )
    deploy.set_defaults(handler=cmd_deploy)

    destroy = sub.add_parser(
        "destroy", help="destroy a deployment made by `carapace deploy`"
    )
    add_interview_flags(destroy)
    destroy.add_argument("--prefix", help="resource name prefix (default: carapace)")
    destroy.add_argument(
        "--confirm-project",
        metavar="PROJECT",
        help="the project id again, to confirm without a prompt",
    )
    destroy.set_defaults(handler=cmd_destroy)
