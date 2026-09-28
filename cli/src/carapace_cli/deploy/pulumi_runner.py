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


class StackHandle(Protocol):
    """What the deploy needs from a stack; faked in tests."""

    def config(self) -> dict[str, str]: ...

    def set_config(self, values: Mapping[str, str]) -> None: ...

    def up(self) -> dict[str, Any]: ...

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


def open_stack(
    target: Target,
    backend: StateBackend,
    *,
    on_output: Callable[[str], None],
    run: ProcessRunner = run_process,
) -> PulumiStack:
    """Select or create the stack named after the prefix, in the GCS backend."""
    stack = PulumiStack(
        executable=find_pulumi(run=run),
        infra=locate_infra(),
        stack=target.prefix,
        backend=backend,
        on_output=on_output,
        run=run,
    )
    stack.select()
    stack.install()
    return stack
