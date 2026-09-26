"""``carapace deploy``: interview, preflight, summary, confirm, deploy.

The command's collaborators (the GCP client, the Pulumi stack and the
clock) come from :class:`Services`, so tests replace every external call
with a fake.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, TextIO

from carapace_cli.deploy import pulumi_runner
from carapace_cli.deploy.gcp import AdcTokenSource, GcpApi
from carapace_cli.deploy.interview import Interview
from carapace_cli.deploy.orchestrate import (
    Images,
    PrebuiltImages,
    run_deploy,
    validate_digest,
)
from carapace_cli.deploy.polling import Clock
from carapace_cli.deploy.preflight import Flags, Target, run_preflight
from carapace_cli.deploy.pulumi_runner import StackHandle
from carapace_cli.deploy.state import StateBackend, ensure_state_backend
from carapace_cli.deploy.summary import render_summary

EXIT_DECLINED = 1


class CommandContext(Protocol):
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


def default_services() -> Services:
    return Services(gcp=lambda: GcpApi(AdcTokenSource()))


def make_interview(args: argparse.Namespace, ctx: CommandContext) -> Interview:
    interview = Interview.from_args(
        non_interactive=args.non_interactive, assume_yes=args.yes
    )
    interview.stream_out = ctx.err
    return interview


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


def cmd_deploy(args: argparse.Namespace, ctx: CommandContext) -> int:
    interview = make_interview(args, ctx)
    services = default_services()
    with services.gcp() as api:
        target, report = run_preflight(api, interview, flags_from(args))
        images = ask_images(args, interview)
        ctx.say(
            render_summary(
                target,
                report,
                images=f"enclave {images.enclave_digest}, "
                f"server {images.server_digest}",
            )
        )
        if not interview.confirm(f"Deploy to {target.project} now?"):
            ctx.say("Aborted. Nothing was changed.")
            return EXIT_DECLINED
        backend = ensure_state_backend(api, target, say=ctx.say, clock=services.clock)
        stack = services.stack(target, backend, ctx)
        outputs = run_deploy(
            target,
            api=api,
            stack=stack,
            images=PrebuiltImages(images),
            clock=services.clock,
            say=ctx.say,
        )
    ctx.say("Deployed.")
    for name in ("enclave_url", "server_url", "kms_key_version_name"):
        ctx.say(f"  {name}: {outputs.get(name, '?')}")
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
    deploy.add_argument("--prefix", help="resource name prefix (default: carapace)")
    deploy.add_argument(
        "--alert-email",
        action="append",
        default=[],
        help="security alert recipient; repeat for several",
    )
    deploy.add_argument("--enclave-digest", help="sha256 digest in the registry")
    deploy.add_argument("--server-digest", help="sha256 digest in the registry")
    deploy.add_argument(
        "--yes", "-y", action="store_true", help="skip the final confirmation"
    )
    deploy.set_defaults(handler=cmd_deploy)
