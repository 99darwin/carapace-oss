"""Guards for the reproducible enclave image (enclave/Dockerfile).

These tests read files only; they never build an image or touch the network.
"""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import re
import shutil
import subprocess
import tarfile
import tomllib
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ENCLAVE_DIR = REPO_ROOT / "enclave"
DOCKERFILE = ENCLAVE_DIR / "Dockerfile"
DOCKERIGNORE = ENCLAVE_DIR / "Dockerfile.dockerignore"
LOCK_FILE = ENCLAVE_DIR / "requirements.lock"
INFRA_ENCLAVE_VM = REPO_ROOT / "infra" / "pulumi" / "components" / "enclave_vm.py"
DIGEST_SCRIPT = REPO_ROOT / "scripts" / "oci_image_digest.py"
UV_EXPORT_ARGS = (
    "export",
    "--package",
    "carapace-enclave",
    "--no-dev",
    "--frozen",
    "--no-emit-workspace",
    "--no-header",
    "--no-annotate",
    "--format",
    "requirements-txt",
)
PINNED_IMAGE = re.compile(r"^\S+@sha256:[0-9a-f]{64}$")
LABEL_PREFIX = "tee.launch_policy."
LOG_REDIRECT_VALUES = frozenset({"always", "debugonly", "never"})


def _dockerfile_instructions() -> list[tuple[str, str]]:
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


def _labels() -> dict[str, str]:
    labels: dict[str, str] = {}
    for keyword, rest in _dockerfile_instructions():
        if keyword == "LABEL":
            for key, value in re.findall(r'(\S+?)="([^"]*)"', rest):
                labels[key] = value
    return labels


def _build_args() -> dict[str, str]:
    args = {}
    for keyword, rest in _dockerfile_instructions():
        if keyword == "ARG" and "=" in rest:
            key, _, value = rest.partition("=")
            args[key] = value
    return args


def _copy_sources() -> list[str]:
    """Sources of every COPY that reads the build context."""
    sources = []
    for keyword, rest in _dockerfile_instructions():
        if keyword != "COPY" or rest.startswith("--from="):
            continue
        parts = [p for p in rest.split() if not p.startswith("--")]
        sources.extend(parts[:-1])
    return sources


def _infra_env_overrides() -> set[str]:
    tree = ast.parse(INFRA_ENCLAVE_VM.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign | ast.Assign):
            targets = [node.target] if isinstance(node, ast.AnnAssign) else node.targets
            names = {t.id for t in targets if isinstance(t, ast.Name)}
            if "ALLOWED_ENV_OVERRIDES" in names and node.value is not None:
                return {
                    n.value
                    for n in ast.walk(node.value)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str)
                }
    raise AssertionError("ALLOWED_ENV_OVERRIDES not found in enclave_vm.py")


def test_launch_policy_env_overrides_match_infra() -> None:
    labels = _labels()
    allowed = labels[LABEL_PREFIX + "allow_env_override"].split(",")
    assert len(allowed) == len(set(allowed))
    assert set(allowed) == _infra_env_overrides()


def test_launch_policy_is_otherwise_closed() -> None:
    labels = _labels()
    policy = {k for k in labels if k.startswith(LABEL_PREFIX)}
    assert policy == {
        LABEL_PREFIX + "allow_env_override",
        LABEL_PREFIX + "allow_cmd_override",
        LABEL_PREFIX + "log_redirect",
    }
    assert labels[LABEL_PREFIX + "allow_cmd_override"] == "false"
    assert labels[LABEL_PREFIX + "log_redirect"] in LOG_REDIRECT_VALUES


def test_base_images_are_pinned_by_digest() -> None:
    args = _build_args()
    froms = [rest for keyword, rest in _dockerfile_instructions() if keyword == "FROM"]
    assert len(froms) == 2
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


def test_copy_sources_are_explicit_and_mock_free() -> None:
    sources = _copy_sources()
    assert sources, "no COPY instructions found"
    allowed = {
        line[1:].rstrip("/")
        for line in DOCKERIGNORE.read_text().splitlines()
        if line.startswith("!")
    }
    for source in sources:
        assert "mock" not in source.lower(), source
        assert source.rstrip("/") in allowed, f"{source} missing from dockerignore"
        # Whole-tree copies would pull in enclave/src/carapace_enclave/mock.
        assert source.rstrip("/") not in {
            ".",
            "enclave",
            "enclave/src",
            "enclave/src/carapace_enclave",
        }
    rules = [
        line
        for line in DOCKERIGNORE.read_text().splitlines()
        if line and not line.startswith("#")
    ]
    assert rules[0] == "*", "the dockerignore must deny everything first"


def test_workspace_dependencies_are_copied() -> None:
    """A new workspace dependency must be added to the include list."""
    project = tomllib.loads((ENCLAVE_DIR / "pyproject.toml").read_text())
    names = [
        re.split(r"[\s<>=!~;\[]", dep, maxsplit=1)[0]
        for dep in project["project"]["dependencies"]
    ]
    workspace = [n for n in names if n.startswith("carapace-")]
    sources = _copy_sources()
    for name in workspace:
        package_dir = name.replace("-", "_")
        assert any(package_dir in source for source in sources), name


def test_lock_pins_every_requirement_with_hashes() -> None:
    blocks = re.split(r"\n(?=\S)", LOCK_FILE.read_text().strip())
    assert blocks
    for block in blocks:
        requirement = block.splitlines()[0]
        assert re.match(r"^[A-Za-z0-9._-]+==\S+ \\$", requirement), requirement
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
        "enclave/requirements.lock is stale; regenerate with: uv "
        + " ".join(UV_EXPORT_ARGS)
        + " -o enclave/requirements.lock"
    )


# --- .github/workflows/enclave-image.yml ----------------------------------

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "enclave-image.yml"
GITHUB_DIR = REPO_ROOT / ".github"
SHA_PINNED_USES = re.compile(r"^\s*-?\s*uses:\s*(\./\S+|\S+@[0-9a-f]{40})\s*(#.*)?$")


def _workflow_files() -> list[Path]:
    workflows = sorted((GITHUB_DIR / "workflows").glob("*.yml"))
    actions = sorted((GITHUB_DIR / "actions").glob("*/action.yml"))
    assert workflows and actions
    return workflows + actions


def test_every_action_is_pinned_to_a_commit_sha() -> None:
    for path in _workflow_files():
        for line in path.read_text().splitlines():
            if "uses:" in line:
                assert SHA_PINNED_USES.match(line), f"{path.name}: {line.strip()}"


def test_workflows_never_run_untrusted_code_with_secrets() -> None:
    for path in _workflow_files():
        assert "pull_request_target" not in path.read_text(), path.name


def test_image_workflow_has_read_only_default_permissions() -> None:
    text = WORKFLOW.read_text()
    assert re.search(r"^permissions:\n  contents: read\n", text, re.MULTILINE)
    # Write scopes exist only on the tag-gated publish job.
    assert text.count("contents: write") == 1
    assert "startsWith(github.ref, 'refs/tags/v')" in text


def test_publish_requires_the_tag_commit_on_the_default_branch() -> None:
    text = WORKFLOW.read_text()
    assert "compare/${DEFAULT_BRANCH}...${commit}" in text
    assert "identical|behind" in text


def test_publish_never_rewrites_a_release_manifest() -> None:
    text = WORKFLOW.read_text()
    assert "--clobber" not in text
    assert "release manifests are immutable" in text
    # Annotated tags: the manifest records the commit, not the tag object.
    assert "git rev-parse 'HEAD^{commit}'" in text
    assert '--arg commit "$GITHUB_SHA"' not in text


def test_github_context_never_reaches_shell_inline() -> None:
    """Untrusted github.* values go through env, never into run: text."""
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


# --- scripts/oci_image_digest.py ------------------------------------------


def _load_digest_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("oci_image_digest", DIGEST_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
IMAGE_DIGEST = "sha256:" + "1" * 64
ATTESTATION_DIGEST = "sha256:" + "2" * 64
INDEX_DIGEST = "sha256:" + "3" * 64


def _write_layout(path: Path, files: dict[str, dict]) -> Path:
    with tarfile.open(path, "w") as archive:
        for name, content in files.items():
            data = json.dumps(content).encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def _buildx_layout(tmp_path: Path, manifests: list[dict]) -> Path:
    return _write_layout(
        tmp_path / "image.tar",
        {
            "index.json": {
                "manifests": [{"mediaType": OCI_INDEX, "digest": INDEX_DIGEST}]
            },
            f"blobs/sha256/{'3' * 64}": {"manifests": manifests},
        },
    )


IMAGE_DESCRIPTOR = {
    "mediaType": OCI_MANIFEST,
    "digest": IMAGE_DIGEST,
    "platform": {"os": "linux", "architecture": "amd64"},
}
ATTESTATION_DESCRIPTOR = {
    "mediaType": OCI_MANIFEST,
    "digest": ATTESTATION_DIGEST,
    "platform": {"os": "unknown", "architecture": "unknown"},
    "annotations": {
        "vnd.docker.reference.type": "attestation-manifest",
        "vnd.docker.reference.digest": IMAGE_DIGEST,
    },
}


def test_digest_script_picks_image_manifest_over_attestations(
    tmp_path: Path,
) -> None:
    script = _load_digest_script()
    layout = _buildx_layout(tmp_path, [IMAGE_DESCRIPTOR, ATTESTATION_DESCRIPTOR])
    assert script.image_manifest_digest(str(layout)) == IMAGE_DIGEST
    assert script.main([str(layout)]) == 0


def test_digest_script_accepts_a_lone_manifest(tmp_path: Path) -> None:
    script = _load_digest_script()
    layout = _write_layout(
        tmp_path / "image.tar",
        {
            "index.json": {
                "manifests": [{"mediaType": OCI_MANIFEST, **{"digest": IMAGE_DIGEST}}]
            }
        },
    )
    assert script.image_manifest_digest(str(layout)) == IMAGE_DIGEST


@pytest.mark.parametrize(
    "manifests",
    [
        [ATTESTATION_DESCRIPTOR],
        [IMAGE_DESCRIPTOR, {**IMAGE_DESCRIPTOR, "digest": "sha256:" + "4" * 64}],
        [{**IMAGE_DESCRIPTOR, "platform": {"os": "linux", "architecture": "arm64"}}],
    ],
)
def test_digest_script_refuses_ambiguous_or_missing_images(
    tmp_path: Path, manifests: list[dict]
) -> None:
    script = _load_digest_script()
    layout = _buildx_layout(tmp_path, manifests)
    with pytest.raises(script.OciLayoutError):
        script.image_manifest_digest(str(layout))
    assert script.main([str(layout)]) == 1
