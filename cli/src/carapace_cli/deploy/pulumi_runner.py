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
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from carapace_cli.deploy.preflight import Target
from carapace_cli.deploy.state import StateBackend
from carapace_cli.errors import CarapaceError

INFRA_DIR_ENV = "CARAPACE_INFRA_DIR"
PULUMI_MAJOR = 3
PULUMI_INSTALL_URL = "https://www.pulumi.com/docs/iac/download-install/"
PULUMI_ENV = {"PULUMI_SKIP_UPDATE_CHECK": "true"}
# Lines of output kept to explain a failure; the rest already streamed.
ERROR_TAIL_LINES = 20
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


class PulumiError(CarapaceError):
    """The Pulumi CLI or program could not run."""


class StackHandle(Protocol):
    """What the deploy needs from a stack; faked in tests."""

    def config(self) -> dict[str, str]: ...

    def set_config(self, values: Mapping[str, str]) -> None: ...

    def up(self) -> dict[str, Any]: ...

    def destroy(self) -> None: ...

    def remove(self) -> None: ...

    def outputs(self) -> dict[str, Any]: ...


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


def locate_infra() -> Path:
    """``infra/pulumi`` in the checkout this CLI runs from, or the override."""
    override = os.environ.get(INFRA_DIR_ENV)
    # cli/src/carapace_cli/deploy/ -> repository root
    infra = Path(override) if override else Path(__file__).parents[4] / "infra/pulumi"
    infra = infra.resolve()
    if not (infra / "Pulumi.yaml").is_file() or not (infra / "__main__.py").is_file():
        raise PulumiError(
            f"the Pulumi program is not at {infra}; run carapace from a "
            f"checkout of the repository or set {INFRA_DIR_ENV}"
        )
    return infra


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
            raise PulumiError(f"pulumi {command} failed: {detail}; {hint}")
        return result.output

    def _json(self, *args: str) -> dict[str, Any]:
        output = self._pulumi(*args, "--json")
        try:
            value = json.loads(output or "{}")
        except json.JSONDecodeError:
            raise PulumiError(f"pulumi {args[0]} did not print JSON") from None
        if not isinstance(value, dict):
            raise PulumiError(f"pulumi {args[0]} printed {type(value).__name__}")
        return value

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
