"""Where the Pulumi program lives, and the defaults it declares.

The CLI runs ``infra/pulumi`` from the checkout it was installed from. It
does not import the program (that needs the Pulumi SDK, which is not a
dependency of the CLI), so a default the CLI must agree with is read from
the program's source instead of being copied here.
"""

from __future__ import annotations

import ast
import functools
import os
import re
from pathlib import Path

from carapace_cli.errors import CarapaceError

INFRA_DIR_ENV = "CARAPACE_INFRA_DIR"
STACK_CONFIG_MODULE = Path("components") / "config.py"
MACHINE_TYPE_CONSTANT = "DEFAULT_ENCLAVE_MACHINE_TYPE"
# The stack config key that overrides the default (components/config.py).
MACHINE_TYPE_CONFIG_KEY = "carapace:enclave_machine_type"
# A Compute machine type name; it goes into a Compute API path.
MACHINE_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


class PulumiError(CarapaceError):
    """The Pulumi CLI or program could not run.

    ``output`` holds the last lines pulumi printed, which the user already
    saw streamed. It is kept out of ``str(exc)`` and only used to tell
    one kind of failure from another.
    """

    def __init__(self, message: str, *, output: str = "") -> None:
        super().__init__(message)
        self.output = output


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


@functools.cache
def read_string_constant(module: Path, name: str) -> str:
    """The value of ``NAME = "literal"`` at the top level of ``module``."""
    try:
        tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
    except (OSError, SyntaxError, ValueError) as exc:
        raise PulumiError(f"could not read {module}: {exc}") from None
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        value = node.value
        if (
            name in names
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and value.value
        ):
            return value.value
    raise PulumiError(f"{module} does not define {name} as a string literal")


def default_enclave_machine_type(infra: Path | None = None) -> str:
    """The machine type the program gives the enclave VM by default."""
    root = infra or locate_infra()
    return read_string_constant(root / STACK_CONFIG_MODULE, MACHINE_TYPE_CONSTANT)


def enclave_machine_type(config: dict[str, str], infra: Path | None = None) -> str:
    """The machine type the stack's enclave VM gets: its config, or the default."""
    value = config.get(MACHINE_TYPE_CONFIG_KEY) or default_enclave_machine_type(infra)
    if not MACHINE_TYPE_PATTERN.fullmatch(value):
        raise PulumiError(f"{value!r} is not a Compute machine type")
    return value
