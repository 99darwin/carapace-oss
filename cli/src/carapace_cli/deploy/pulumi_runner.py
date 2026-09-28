"""Run ``infra/pulumi`` with the ``pulumi`` CLI, as SELF_HOST.md does by hand.

The CLI runs ``pulumi`` as a subprocess in the checkout's ``infra/pulumi``
directory, so the program, its virtualenv (``Pulumi.yaml`` names ``venv``)
and its pinned providers are exactly the manual path's. The Pulumi Python
SDK is deliberately not a dependency of this CLI: it caps ``protobuf``
below the version the enclave ships, and one workspace lock cannot hold
both.

State goes to the GCS backend with the ``gcpkms://`` secrets provider from
:mod:`carapace_cli.deploy.state`; no Pulumi Cloud account is involved.
No command runs with ``--show-secrets``, so secret values stay masked in
the streamed output and are never returned.
"""

from __future__ import annotations

import itertools
import json
import os
import re
import shutil
import subprocess
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from carapace_cli.deploy.infra import PulumiError, locate_infra
from carapace_cli.deploy.preflight import Target
from carapace_cli.deploy.state import StateBackend

PULUMI_MAJOR = 3
PULUMI_INSTALL_URL = "https://www.pulumi.com/docs/iac/download-install/"
PULUMI_ENV = {"PULUMI_SKIP_UPDATE_CHECK": "true"}
# `preview --json` prints one JSON document (the preview digest) when this
# is off, and a stream of engine events when it is on; the parser reads
# the digest, so it is always set off.
PREVIEW_ENV = {"PULUMI_ENABLE_STREAMING_JSON_PREVIEW": "false"}
# Lines of output kept to explain a failure; the rest already streamed.
# Enough to hold the diagnostics pulumi prints after a failed `up`, which
# tell a zone out of capacity from other failures.
ERROR_TAIL_LINES = 60
# What `pulumi stack output --json` prints in place of a secret output.
MASKED_OUTPUT = "[secret]"  # noqa: S105 - a placeholder, not a credential
VERSION_PATTERN = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")
RESUME_HINT = "fix the cause and run the same command again to resume"
# What `pulumi destroy` prints after a successful destroy. The CLI removes
# the stack itself, so the hint to run `pulumi stack rm` is not shown.
STACK_RM_HINT = (
    "The resources in the stack have been deleted, but the history and configuration",
    "If you want to remove the stack completely, run `pulumi stack rm",
)


URN_PREFIX = "urn:pulumi:"
ROOT_STACK_TYPE = "pulumi:pulumi:Stack"
PREVIEW_HINT = "nothing was changed; fix the cause and run the same command again"


@dataclass(frozen=True)
class StateResource:
    """One resource as the backend's state tracks it (``stack export``).

    ``outputs`` are as exported: a secret output is ciphertext, never its
    value. They are kept out of the repr so that neither ciphertext nor
    plain outputs end up in a traceback or an error message.
    """

    urn: str
    type: str
    protect: bool
    outputs: Mapping[str, Any] = field(repr=False)


@dataclass(frozen=True)
class PreviewStep:
    """One step of ``pulumi preview --json``, without any property value.

    Only what decides whether a resource is replaced, and why, is kept:
    the operation, the resource, and the names of the properties that
    differ. The old and new states the digest also carries are dropped,
    so no value (masked or not) outlives the parse.
    """

    op: str
    urn: str
    type: str
    replace_reasons: tuple[str, ...] = ()
    diff_reasons: tuple[str, ...] = ()
    # Property path -> diff kind ("update", "update-replace", ...).
    detailed_diff: Mapping[str, str] = field(default_factory=dict)


class StackHandle(Protocol):
    """What the deploy needs from a stack; faked in tests."""

    def config(self) -> dict[str, str]: ...

    def set_config(self, values: Mapping[str, str]) -> None: ...

    def up(self) -> dict[str, Any]: ...

    def preview(self) -> list[PreviewStep]: ...

    def up_targets(self, urns: Sequence[str]) -> None: ...

    def unprotect_all(self) -> None: ...

    def destroy(self) -> None: ...

    def remove(self) -> None: ...

    def outputs(self) -> dict[str, Any]: ...

    def has_resources(self) -> bool: ...

    def resources(self) -> list[StateResource]: ...


@dataclass(frozen=True)
class Completed:
    code: int
    output: str


class ProcessRunner(Protocol):
    def __call__(
        self,
        argv: list[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        on_output: Callable[[str], None] | None,
    ) -> Completed: ...


def run_process(
    argv: list[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    on_output: Callable[[str], None] | None,
) -> Completed:
    """Run ``argv`` without a shell; stream lines to ``on_output`` if given.

    A streamed command keeps only its last lines, enough to explain a
    failure; the user already saw the rest.
    """
    with subprocess.Popen(  # noqa: S603 - argv built in this module, no shell
        argv,
        cwd=cwd,
        env=dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    ) as process:
        stdout = process.stdout
        if stdout is None:
            raise PulumiError("could not read pulumi's output")
        if on_output is None:
            output = stdout.read()
        else:
            tail: deque[str] = deque(maxlen=ERROR_TAIL_LINES)
            for line in stdout:
                on_output(line)
                tail.append(line)
            output = "".join(tail)
        return Completed(process.wait(), output)


@dataclass(frozen=True)
class Captured:
    """A finished command's stdout and stderr, kept apart."""

    code: int
    stdout: str
    stderr: str = field(repr=False)


class ProcessCapture(Protocol):
    def __call__(
        self, argv: list[str], *, cwd: Path, env: Mapping[str, str]
    ) -> Captured: ...


def capture_process(argv: list[str], *, cwd: Path, env: Mapping[str, str]) -> Captured:
    """Run ``argv`` without a shell; return stdout and stderr separately.

    For commands whose stdout is a document to parse: anything pulumi or
    a plugin writes to stderr (warnings, plugin downloads) stays out of it.
    """
    result = subprocess.run(  # noqa: S603 - argv built in this module, no shell
        argv,
        cwd=cwd,
        env=dict(env),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    return Captured(result.returncode, result.stdout, result.stderr)


def pulumi_env(backend: StateBackend | None = None) -> dict[str, str]:
    env = {**os.environ, **PULUMI_ENV}
    if backend is not None:
        env["PULUMI_BACKEND_URL"] = backend.url
    return env


def find_pulumi(
    *, run: ProcessRunner, which: Callable[[str], str | None] = shutil.which
) -> str:
    """The ``pulumi`` executable on PATH; it must be major version 3.

    The CLI never downloads Pulumi itself: fetching and running an
    installer is a step the user should take knowingly.
    """
    executable = which("pulumi")
    if executable is None:
        raise PulumiError(
            f"the pulumi CLI is not on PATH; install Pulumi {PULUMI_MAJOR}.x "
            f"({PULUMI_INSTALL_URL}) and run the same command again"
        )
    result = run(
        [executable, "version"], cwd=Path.cwd(), env=pulumi_env(), on_output=None
    )
    reported = result.output.strip()
    match = VERSION_PATTERN.match(reported)
    if result.code != 0 or not match or int(match.group(1)) != PULUMI_MAJOR:
        raise PulumiError(
            f"{executable} is not a usable Pulumi {PULUMI_MAJOR}.x "
            f"(it reported {reported[:40]!r})"
        )
    return executable


def _is_subcommand(arg: str) -> bool:
    return not arg.startswith("-")


@dataclass
class PulumiStack:
    """A :class:`StackHandle` that runs ``pulumi`` in ``infra/pulumi``."""

    executable: str
    infra: Path
    stack: str
    backend: StateBackend
    on_output: Callable[[str], None]
    run: ProcessRunner = field(default=run_process)
    capture: ProcessCapture = field(default=capture_process)

    def _pulumi(
        self,
        *args: str,
        stream: bool = False,
        scoped: bool = True,
        hint: str = RESUME_HINT,
        on_output: Callable[[str], None] | None = None,
    ) -> str:
        argv = [self.executable, *args, "--non-interactive"]
        if scoped:
            argv += ["--stack", self.stack]
        result = self.run(
            argv,
            cwd=self.infra,
            env=pulumi_env(self.backend),
            on_output=(on_output or self.on_output) if stream else None,
        )
        if result.code != 0:
            lines = [line for line in result.output.splitlines() if line.strip()]
            detail = lines[-1].strip() if lines else f"exit code {result.code}"
            command = " ".join(itertools.takewhile(_is_subcommand, args[:2]))
            # Only a streamed command's tail is kept: those lines already
            # went to the terminal. A quiet command's output is whole and
            # can be the state (`stack export`) or the config, which stay
            # out of exceptions.
            raise PulumiError(
                f"pulumi {command} failed: {detail}; {hint}",
                output=result.output if stream else "",
            )
        return result.output

    def _json(self, *args: str) -> dict[str, Any]:
        return _decode(self._pulumi(*args, "--json"), command=args[0])

    def select(self) -> None:
        """Select the stack, creating it with the KMS secrets provider."""
        self._pulumi(
            "stack",
            "select",
            "--create",
            "--secrets-provider",
            self.backend.secrets_provider,
        )

    def install(self) -> None:
        """Create ``infra/pulumi/venv`` and the providers, when missing."""
        self._pulumi("install", stream=True, scoped=False)

    def config(self) -> dict[str, str]:
        """Plain config values; secret ones are left out, never decrypted."""
        return {
            key: str(entry["value"])
            for key, entry in self._json("config").items()
            if isinstance(entry, dict)
            and not entry.get("secret")
            and entry.get("value") is not None
        }

    def set_config(self, values: Mapping[str, str]) -> None:
        pairs: list[str] = []
        for key, value in values.items():
            pairs += ["--plaintext", f"{key}={value}"]
        self._pulumi("config", "set-all", *pairs)

    def up(self) -> dict[str, Any]:
        self._pulumi("up", "--yes", "--skip-preview", stream=True)
        return self.outputs()

    def preview(self) -> list[PreviewStep]:
        """``pulumi preview --json``: what the next ``up`` would do.

        Never ``--show-secrets``: secret values stay masked in the digest,
        and the parse keeps no value at all. stderr is kept apart from the
        JSON and passed to the terminal, as a streamed command's output
        is. A failed preview or output that is not a preview digest raises
        :class:`PulumiError`, whose message holds none of pulumi's output.
        """
        argv = [
            self.executable,
            "preview",
            "--json",
            "--non-interactive",
            "--stack",
            self.stack,
        ]
        result = self.capture(
            argv, cwd=self.infra, env={**pulumi_env(self.backend), **PREVIEW_ENV}
        )
        for line in result.stderr.splitlines(keepends=True):
            self.on_output(line)
        if result.code != 0:
            for message in _preview_errors(result.stdout):
                self.on_output(message if message.endswith("\n") else message + "\n")
            raise PulumiError(
                f"pulumi preview failed (exit code {result.code}); see its "
                f"output above; {PREVIEW_HINT}"
            )
        return parse_preview(result.stdout)

    def up_targets(self, urns: Sequence[str]) -> None:
        """``pulumi up`` on exactly ``urns``, which the state already tracks.

        The program still runs, but the engine only steps the targets:
        every untargeted resource missing from the state is a "skipped
        create" and is never created, and a target that would need one
        fails the update instead (no ``--target-dependents``). The
        targets get their new inputs and resource options; every other
        resource keeps its old state. Each target names one resource: a
        ``*`` would make it a glob, which can match resources the state
        lacks and create them.
        """
        if not urns:
            raise PulumiError("a targeted pulumi up needs at least one target")
        targets: list[str] = []
        for urn in urns:
            if not urn.startswith(URN_PREFIX) or "*" in urn:
                raise PulumiError(f"{urn!r} is not a Pulumi URN naming one resource")
            targets += ["--target", urn]
        self._pulumi("up", "--yes", "--skip-preview", *targets, stream=True)

    def unprotect_all(self) -> None:
        """Clear ``protect`` on every resource in the state.

        ``pulumi state unprotect --all`` edits the state in the backend
        and nothing else: the program does not run, so nothing can be
        created or changed, whatever type the protected resources are.
        """
        self._pulumi("state", "unprotect", "--all", "--yes")

    def destroy(self) -> None:
        self._pulumi(
            "destroy",
            "--yes",
            "--skip-preview",
            stream=True,
            on_output=self._without_stack_rm_hint,
        )

    def remove(self) -> None:
        """``pulumi stack rm``: the stack's history and its local config file.

        Only an empty stack is removed (no ``--force``), and the config file
        ``Pulumi.<stack>.yaml`` goes with it (no ``--preserve-config``), so
        a later deploy with the same prefix starts from a new stack.
        """
        self._pulumi(
            "stack",
            "rm",
            "--yes",
            self.stack,
            scoped=False,
            hint="the stack's resources are already deleted",
        )

    def _without_stack_rm_hint(self, line: str) -> None:
        if not line.strip().startswith(STACK_RM_HINT):
            self.on_output(line)

    def outputs(self) -> dict[str, Any]:
        """Stack outputs, with secret outputs left out."""
        return {
            name: value
            for name, value in self._json("stack", "output").items()
            if value != MASKED_OUTPUT
        }

    def has_resources(self) -> bool:
        """Whether the state in the backend tracks any resource.

        Outputs are exported only by an ``up`` that finished, but every
        resource an ``up`` created is checkpointed even when it fails, so
        this tells a stack that owns half a deployment from one that owns
        nothing.
        """
        return bool(self._exported_resources())

    def resources(self) -> list[StateResource]:
        """Every resource the state in the backend tracks."""
        resources: list[StateResource] = []
        for entry in self._exported_resources():
            if not isinstance(entry, dict):
                raise PulumiError("pulumi stack export printed a malformed resource")
            urn, type_ = entry.get("urn"), entry.get("type")
            outputs = entry.get("outputs") or {}
            if (
                not isinstance(urn, str)
                or not isinstance(type_, str)
                or not isinstance(outputs, dict)
            ):
                raise PulumiError("pulumi stack export printed a malformed resource")
            resources.append(
                StateResource(
                    urn=urn,
                    type=type_,
                    protect=entry.get("protect") is True,
                    outputs=outputs,
                )
            )
        return resources

    def _exported_resources(self) -> list[Any]:
        """``stack export`` prints the deployment to stdout (it has no
        ``--json``) with secrets as ciphertext; ``--show-secrets`` is never
        passed.
        """
        export = _decode(self._pulumi("stack", "export"), command="stack export")
        deployment = export.get("deployment")
        if not isinstance(deployment, dict):
            return []
        resources = deployment.get("resources")
        if resources is None:
            return []
        if not isinstance(resources, list):
            raise PulumiError("pulumi stack export printed malformed resources")
        return resources


def _decode(output: str, *, command: str) -> dict[str, Any]:
    try:
        value = json.loads(output or "{}")
    except json.JSONDecodeError:
        raise PulumiError(f"pulumi {command} did not print JSON") from None
    if not isinstance(value, dict):
        raise PulumiError(f"pulumi {command} printed {type(value).__name__}")
    return value


def urn_type(urn: str) -> str:
    """The resource type a URN names; its parents' types are dropped.

    ``urn:pulumi:<stack>::<project>::<parent$...$type>::<name>``
    """
    parts = urn.split("::", 3)
    if len(parts) != 4 or not urn.startswith(URN_PREFIX):
        raise PulumiError(
            f"pulumi preview printed a malformed resource URN; {PREVIEW_HINT}"
        )
    return parts[2].rpartition("$")[2]


def _preview_digest(output: str) -> dict[str, Any]:
    try:
        value = json.loads(output)
    except json.JSONDecodeError:
        raise PulumiError(
            f"pulumi preview did not print a JSON preview; {PREVIEW_HINT}"
        ) from None
    if not isinstance(value, dict):
        raise PulumiError(
            f"pulumi preview printed {type(value).__name__}, not a preview; "
            f"{PREVIEW_HINT}"
        )
    return value


def _preview_errors(output: str) -> list[str]:
    """The error diagnostics of a failed preview's digest, if it printed one.

    A failure in the program is reported in the digest, not on stderr.
    Pulumi masks secret values in diagnostics as everywhere else.
    """
    try:
        diagnostics = _preview_digest(output).get("diagnostics")
    except PulumiError:
        return []
    if not isinstance(diagnostics, list):
        return []
    return [
        entry["message"]
        for entry in diagnostics
        if isinstance(entry, dict)
        and entry.get("severity") == "error"
        and isinstance(entry.get("message"), str)
    ]


def _names(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PulumiError(f"pulumi preview printed a malformed step; {PREVIEW_HINT}")
    return tuple(value)


def _detailed_diff(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PulumiError(f"pulumi preview printed a malformed step; {PREVIEW_HINT}")
    kinds: dict[str, str] = {}
    for path, diff in value.items():
        kind = diff.get("kind") if isinstance(diff, dict) else None
        if not isinstance(path, str) or not isinstance(kind, str):
            raise PulumiError(
                f"pulumi preview printed a malformed step; {PREVIEW_HINT}"
            )
        kinds[path] = kind
    return kinds


def parse_preview(output: str) -> list[PreviewStep]:
    """The steps of the digest ``pulumi preview --json`` prints.

    The shape is Pulumi's ``display.PreviewDigest`` (``pkg/display/json.go``):
    ``steps[]`` with ``op``, ``urn``, ``replaceReasons``, ``diffReasons``
    and ``detailedDiff`` (path -> ``{kind, inputDiff}``). The root stack's
    step is always in it, so a digest without one is not trusted: output
    that merely parses as JSON must not read as "nothing changes".
    """
    steps = _preview_digest(output).get("steps")
    if not isinstance(steps, list):
        raise PulumiError(f"pulumi preview printed no steps; {PREVIEW_HINT}")
    parsed: list[PreviewStep] = []
    for step in steps:
        if not isinstance(step, dict):
            raise PulumiError(
                f"pulumi preview printed a malformed step; {PREVIEW_HINT}"
            )
        op, urn = step.get("op"), step.get("urn")
        if not isinstance(op, str) or not op or not isinstance(urn, str):
            raise PulumiError(
                f"pulumi preview printed a malformed step; {PREVIEW_HINT}"
            )
        parsed.append(
            PreviewStep(
                op=op,
                urn=urn,
                type=urn_type(urn),
                replace_reasons=_names(step.get("replaceReasons")),
                diff_reasons=_names(step.get("diffReasons")),
                detailed_diff=_detailed_diff(step.get("detailedDiff")),
            )
        )
    if not any(step.type == ROOT_STACK_TYPE for step in parsed):
        raise PulumiError(
            f"pulumi preview printed no step for the stack; {PREVIEW_HINT}"
        )
    return parsed


def open_stack(
    target: Target,
    backend: StateBackend,
    *,
    on_output: Callable[[str], None],
    run: ProcessRunner = run_process,
    capture: ProcessCapture = capture_process,
) -> PulumiStack:
    """Select or create the stack named after the prefix, in the GCS backend."""
    stack = PulumiStack(
        executable=find_pulumi(run=run),
        infra=locate_infra(),
        stack=target.prefix,
        backend=backend,
        on_output=on_output,
        run=run,
        capture=capture,
    )
    stack.select()
    stack.install()
    return stack
