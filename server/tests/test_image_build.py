"""Guards for the server image (server/Dockerfile).

These tests read files only; they never build an image or touch the network.
"""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from carapace_server.__main__ import DEFAULT_PORT

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_DIR = REPO_ROOT / "server"
DOCKERFILE = SERVER_DIR / "Dockerfile"
DOCKERIGNORE = SERVER_DIR / "Dockerfile.dockerignore"
LOCK_FILE = SERVER_DIR / "requirements.lock"
INFRA_SERVER = REPO_ROOT / "infra" / "pulumi" / "components" / "server.py"
UV_EXPORT_ARGS = (
    "export",
    "--package",
    "carapace-server",
    "--no-dev",
    "--frozen",
    "--no-emit-workspace",
    "--no-header",
    "--no-annotate",
    "--format",
    "requirements-txt",
)
PINNED_IMAGE = re.compile(r"^\S+@sha256:[0-9a-f]{64}$")
# A numeric, non-zero uid[:gid]. Names are refused on purpose: "root" would
# pass a "not 0" check, and a name needs /etc/passwd resolution at runtime.
UNPRIVILEGED_USER = re.compile(r"^[1-9][0-9]*(:[1-9][0-9]*)?$")
UNPRIVILEGED_PORT_START = 1024
SECRET_WORDS = re.compile(r"SECRET|PASSWORD|TOKEN|DATABASE_URL|PRIVATE", re.I)
# What the image must contain: the package, its workspace dependency, and
# what `alembic upgrade head` needs.
REQUIRED_COPIES = {
    "server/src/carapace_server": "/app/site-packages/carapace_server",
    "packages/crypto/src/carapace_crypto": "/app/site-packages/carapace_crypto",
    "server/alembic.ini": "/app/server/alembic.ini",
    "server/migrations": "/app/server/migrations",
}


def _instructions() -> list[tuple[str, str]]:
    """Return (INSTRUCTION, arguments) pairs with continuations joined."""
    joined = re.sub(r"\\\n", " ", DOCKERFILE.read_text())
    instructions = []
    for line in joined.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        keyword, _, rest = stripped.partition(" ")
        instructions.append((keyword.upper(), rest.strip()))
    return instructions


def _final_stage() -> list[tuple[str, str]]:
    instructions = _instructions()
    froms = [i for i, (keyword, _) in enumerate(instructions) if keyword == "FROM"]
    return instructions[max(froms) + 1 :]


def _build_args() -> dict[str, str]:
    args = {}
    for keyword, rest in _instructions():
        if keyword == "ARG" and "=" in rest:
            key, _, value = rest.partition("=")
            args[key] = value
    return args


def _context_copies() -> list[tuple[list[str], str]]:
    """(sources, destination) of every COPY that reads the build context."""
    copies = []
    for keyword, rest in _instructions():
        if keyword != "COPY" or rest.startswith("--from="):
            continue
        parts = [p for p in rest.split() if not p.startswith("--")]
        copies.append((parts[:-1], parts[-1]))
    return copies


def _copy_map() -> dict[str, str]:
    return {
        source.rstrip("/"): destination.rstrip("/")
        for sources, destination in _context_copies()
        for source in sources
    }


def _infra_constant(name: str) -> object:
    tree = ast.parse(INFRA_SERVER.read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} not found in {INFRA_SERVER}")


def test_base_images_are_pinned_by_digest() -> None:
    args = _build_args()
    froms = [rest for keyword, rest in _instructions() if keyword == "FROM"]
    assert len(froms) == 2, "expected a build stage and a runtime stage"
    for line in froms:
        image = line.split()[0]
        match = re.fullmatch(r"\$\{(\w+)\}", image)
        resolved = args[match.group(1)] if match else image
        assert PINNED_IMAGE.match(resolved), resolved
    assert "distroless" in args["RUNTIME_IMAGE"]
    assert ":nonroot@" in args["RUNTIME_IMAGE"]


def test_no_unpinned_frontend() -> None:
    first = DOCKERFILE.read_text().splitlines()[0]
    assert not first.lower().startswith("# syntax=")


def test_runs_as_a_numeric_non_root_user() -> None:
    users = [rest for keyword, rest in _final_stage() if keyword == "USER"]
    assert users, "the runtime stage must set USER"
    assert UNPRIVILEGED_USER.fullmatch(users[-1]), users[-1]


def test_listen_port_matches_entrypoint_and_infra() -> None:
    """Cloud Run sets $PORT to the infra's container port; all three agree."""
    exposed = [rest for keyword, rest in _final_stage() if keyword == "EXPOSE"]
    assert exposed == [f"{DEFAULT_PORT}/tcp"]
    assert _infra_constant("CONTAINER_PORT") == DEFAULT_PORT
    assert DEFAULT_PORT >= UNPRIVILEGED_PORT_START


def test_entrypoint_is_the_server_module() -> None:
    entrypoints = [rest for keyword, rest in _final_stage() if keyword == "ENTRYPOINT"]
    assert entrypoints == ['["/usr/bin/python3", "-m", "carapace_server"]']


def test_no_secrets_in_the_image() -> None:
    """Secrets reach the container only as Secret Manager references."""
    for keyword, rest in _instructions():
        if keyword in {"ENV", "ARG", "LABEL"}:
            names = re.findall(r"(\w+)=", rest) or [rest.split()[0]]
            for name in names:
                assert not SECRET_WORDS.search(name), f"{keyword} {name}"
    for source in _copy_map():
        assert ".env" not in source, source


def test_every_required_path_is_copied() -> None:
    copies = _copy_map()
    for source, destination in REQUIRED_COPIES.items():
        assert copies.get(source) == destination, source


def test_copy_sources_are_explicit_and_allowed_by_dockerignore() -> None:
    rules = [
        line
        for line in DOCKERIGNORE.read_text().splitlines()
        if line and not line.startswith("#")
    ]
    assert rules[0] == "*", "the dockerignore must deny everything first"
    allowed = {line[1:].rstrip("/") for line in rules if line.startswith("!")}
    for source in _copy_map():
        assert source in allowed, f"{source} missing from dockerignore"
        assert source not in {".", "server", "server/src", "packages"}, source


def test_workspace_dependencies_are_copied() -> None:
    """A new workspace dependency must be added to the include list."""
    project = tomllib.loads((SERVER_DIR / "pyproject.toml").read_text())
    names = [
        re.split(r"[\s<>=!~;\[]", dep, maxsplit=1)[0]
        for dep in project["project"]["dependencies"]
    ]
    copied = _copy_map().values()
    for name in (n for n in names if n.startswith("carapace-")):
        package_dir = name.replace("-", "_")
        assert f"/app/site-packages/{package_dir}" in copied, name


def test_migration_job_config_path_is_in_the_image() -> None:
    """The infra job runs alembic against a config file this image ships."""
    args = _infra_constant("MIGRATION_ARGS")
    assert isinstance(args, tuple)
    config_path = args[args.index("-c") + 1]
    assert config_path in _copy_map().values()
    assert _infra_constant("MIGRATION_COMMAND") == ("/usr/bin/python3",)
    # alembic.ini finds the scripts relative to itself.
    assert "script_location = %(here)s/migrations" in (
        (SERVER_DIR / "alembic.ini").read_text()
    )


def test_lock_pins_every_requirement_with_hashes() -> None:
    blocks = re.split(r"\n(?=\S)", LOCK_FILE.read_text().strip())
    assert blocks
    for block in blocks:
        requirement = block.splitlines()[0]
        assert re.match(r"^[A-Za-z0-9._-]+==\S+( ; [^\\]+)? \\$", requirement), (
            requirement
        )
        assert "--hash=sha256:" in block, requirement
        assert not requirement.startswith(("-e", "carapace")), requirement


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is not installed")
def test_lock_matches_uv_export() -> None:
    uv = shutil.which("uv")
    assert uv is not None
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [uv, *UV_EXPORT_ARGS],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == LOCK_FILE.read_text(), (
        "server/requirements.lock is stale; regenerate with: uv "
        + " ".join(UV_EXPORT_ARGS)
        + " -o server/requirements.lock"
    )


# --- .github/workflows/server-image.yml -----------------------------------

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "server-image.yml"


def test_workflow_is_read_only_except_the_tag_gated_push() -> None:
    text = WORKFLOW.read_text()
    assert re.search(r"^permissions:\n  contents: read\n", text, re.MULTILINE)
    assert text.count("packages: write") == 1
    assert "contents: write" not in text
    assert "startsWith(github.ref, 'refs/tags/v')" in text
    assert "compare/${DEFAULT_BRANCH}...${commit}" in text
    assert "pull_request_target" not in text


def test_workflow_never_expands_github_context_in_shell() -> None:
    """github.* values go through env, never into run: text."""
    run_indent: int | None = None
    for line in WORKFLOW.read_text().splitlines():
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if line.lstrip().startswith("run:"):
            run_indent = indent
        elif run_indent is not None and indent <= run_indent:
            run_indent = None
        if run_indent is not None:
            assert "${{" not in line, line.strip()
