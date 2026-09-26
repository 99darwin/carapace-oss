"""``carapace deploy``: interview, preflight, summary, confirm, deploy.

The command's collaborators (the GCP client, and later the Pulumi runner and
the image copier) come from :class:`Services`, so tests replace every
external call with a fake.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, TextIO

from carapace_cli.deploy.gcp import AdcTokenSource, GcpApi
from carapace_cli.deploy.interview import Interview
from carapace_cli.deploy.preflight import Flags, PreflightReport, Target, run_preflight
from carapace_cli.deploy.summary import render_summary
from carapace_cli.errors import CarapaceError

EXIT_DECLINED = 1


class CommandContext(Protocol):
    @property
    def err(self) -> TextIO: ...

    def say(self, message: str) -> None: ...


@dataclass
class Services:
    """Factories for everything that talks to the outside world."""

    gcp: Callable[[], GcpApi]


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


def execute(
    target: Target,
    report: PreflightReport,
    *,
    api: GcpApi,
    interview: Interview,
    ctx: CommandContext,
) -> int:
    """Create the deployment. Lands with the state backend (stacked PR)."""
    raise CarapaceError("deploying is not implemented in this build yet")


def cmd_deploy(args: argparse.Namespace, ctx: CommandContext) -> int:
    interview = make_interview(args, ctx)
    with default_services().gcp() as api:
        target, report = run_preflight(api, interview, flags_from(args))
        ctx.say(render_summary(target, report, images="published release"))
        if not interview.confirm(f"Deploy to {target.project} now?"):
            ctx.say("Aborted. Nothing was changed.")
            return EXIT_DECLINED
        return execute(target, report, api=api, interview=interview, ctx=ctx)


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
    deploy.add_argument(
        "--yes", "-y", action="store_true", help="skip the final confirmation"
    )
    deploy.set_defaults(handler=cmd_deploy)
