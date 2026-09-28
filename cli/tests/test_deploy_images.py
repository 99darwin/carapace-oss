"""Image sources: the verified release and the local build, fully faked.

GitHub, ghcr.io and Artifact Registry are in-memory fakes behind one
``httpx.MockTransport``; signature checks, docker, git and cosign are
fakes too. Nothing reaches the network or runs a real tool.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
from deploy_support import (
    FAKE_ACCESS_TOKEN,
    PREFIX,
    PROJECT,
    REGISTRY,
    FakeStack,
    deployable_project,
    instant_clock,
)
from first_run_support import fake_first_run
from registry_support import (
    AR_HOST,
    FakeRegistry,
    Image,
    make_image,
    make_index,
    oci_layout,
)

from carapace_cli.deploy import command
from carapace_cli.deploy.images import (
    ACTIONS_ISSUER,
    BUILDKIT_IMAGE,
    BuiltImages,
    GitHubReleases,
    ImageError,
    Registries,
    ReleaseImages,
    buildx_driver,
    fetch_release,
    sigstore_verify,
)
from carapace_cli.deploy.pulumi_runner import Completed
from carapace_cli.deploy.registry import GHCR
from carapace_cli.main import main

REPO = "99darwin/carapace-oss"
TAG = "v1.2.0"
COMMIT = "c" * 40
ENCLAVE_IDENTITY = (
    f"https://github.com/{REPO}/.github/workflows/enclave-image.yml@refs/tags/{TAG}"
)
ASSET_HOST = "release-assets.githubusercontent.com"
DEST = REGISTRY.partition("/")[2]
DOCKER_BUILD = ["/bin/docker", "buildx", "build"]


def release_json(digest: str, *, tag: str = TAG, commit: str = COMMIT) -> bytes:
    body = {"tag": tag, "digest": digest, "commit": commit, "epoch": 1700000000}
    return json.dumps(body).encode()


@dataclass
class World:
    """GitHub, ghcr.io and Artifact Registry in memory."""

    enclave: Image = field(default_factory=lambda: make_image("enclave"))
    server: Image = field(default_factory=lambda: make_image("server"))
    manifest: bytes | None = None
    ghcr: FakeRegistry = field(default_factory=lambda: FakeRegistry(GHCR))
    ar: FakeRegistry = field(
        default_factory=lambda: FakeRegistry(
            AR_HOST, basic=("oauth2accesstoken", FAKE_ACCESS_TOKEN)
        )
    )
    github: list[httpx.Request] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.ghcr.add(f"{REPO}/enclave", self.enclave)
        self.ghcr.add(f"{REPO}/server", self.server)
        index = make_index(self.server, attestation=make_image("att", layers=1))
        self.ghcr.tag_index(f"{REPO}/server", TAG, index)
        if self.manifest is None:
            self.manifest = release_json(self.enclave.digest)

    def _github(self, request: httpx.Request) -> httpx.Response:
        self.github.append(request)
        path = request.url.path
        if request.url.host == "api.github.com":
            return httpx.Response(200, json={"tag_name": TAG})
        if request.url.host == ASSET_HOST:
            name = path.rsplit("/", 1)[1]
            body = self.manifest if name == f"{TAG}.json" else b'{"bundle": 1}'
            return httpx.Response(200, content=body)
        if path.startswith(f"/{REPO}/releases/download/{TAG}/"):
            location = f"https://{ASSET_HOST}/{path.rsplit('/', 1)[1]}"
            return httpx.Response(302, headers={"Location": location})
        return httpx.Response(404)

    def transport(self) -> httpx.MockTransport:
        def route(request: httpx.Request) -> httpx.Response:
            host = request.url.host
            if host == GHCR:
                return self.ghcr.handle(request)
            if host == AR_HOST:
                return self.ar.handle(request)
            return self._github(request)

        return httpx.MockTransport(route)


@dataclass
class FakeVerifier:
    valid: bool = True
    calls: list[dict[str, Any]] = field(default_factory=list)

    def __call__(
        self, payload: bytes, bundle: bytes, *, identity: str, issuer: str
    ) -> None:
        self.calls.append({"payload": payload, "identity": identity, "issuer": issuer})
        if not self.valid:
            raise ImageError("the release signature does not verify")


def releases(world: World) -> GitHubReleases:
    client = httpx.Client(transport=world.transport(), follow_redirects=True)
    return GitHubReleases(client)


def test_release_is_verified_against_the_exact_workflow_identity() -> None:
    world, verifier = World(), FakeVerifier()
    release = fetch_release(releases(world), verifier, repo=REPO, tag=TAG)
    assert release.digest == world.enclave.digest and release.commit == COMMIT
    assert verifier.calls == [
        {
            "payload": world.manifest,
            "identity": ENCLAVE_IDENTITY,
            "issuer": ACTIONS_ISSUER,
        }
    ]
    assert releases(world).latest_tag(REPO) == TAG
    assert not any("authorization" in r.headers for r in world.github)


def test_bad_signature_stops_before_the_manifest_is_used() -> None:
    world = World(manifest=b"not even json")
    with pytest.raises(ImageError, match="does not verify"):
        fetch_release(releases(world), FakeVerifier(valid=False), repo=REPO, tag=TAG)


@pytest.mark.parametrize(
    ("manifest", "message"),
    [
        (release_json("sha256:" + "a" * 64, tag="v0.9.0"), "signed for tag 'v0.9.0'"),
        (release_json("sha256:short"), "no sha256 image digest"),
        (release_json("sha256:" + "a" * 64, commit="HEAD"), "no commit id"),
        (b"[1]", "not an object"),
    ],
)
def test_signed_manifest_fields_are_checked(manifest: bytes, message: str) -> None:
    world = World(manifest=manifest)
    with pytest.raises(ImageError, match=message):
        fetch_release(releases(world), FakeVerifier(), repo=REPO, tag=TAG)


def release_source(
    world: World, cosign: Callable[[list[str]], bool | None], lines: list[str]
) -> ReleaseImages:
    release = fetch_release(releases(world), FakeVerifier(), repo=REPO, tag=TAG)
    registries = Registries(lambda: FAKE_ACCESS_TOKEN, transport=world.transport())
    return ReleaseImages(release, REPO, registries, cosign, lines.append)


def test_release_publish_copies_both_images_by_digest() -> None:
    world, lines, cosign_args = World(), [], []

    def cosign(arguments: list[str]) -> bool:
        cosign_args.append(arguments)
        return True

    images = release_source(world, cosign, lines).publish(REGISTRY)
    assert images.enclave_digest == world.enclave.digest
    assert images.server_digest == world.server.digest
    assert (f"{DEST}/enclave", world.enclave.digest) in world.ar.manifests
    assert (f"{DEST}/server", world.server.digest) in world.ar.manifests
    identity = cosign_args[0][cosign_args[0].index("--certificate-identity") + 1]
    assert identity.endswith(f"/server-image.yml@refs/tags/{TAG}")
    assert cosign_args[0][-1] == f"{GHCR}/{REPO}/server@{world.server.digest}"


def test_server_signature_is_optional_but_never_ignored() -> None:
    lines: list[str] = []
    release_source(World(), lambda _args: None, lines).publish(REGISTRY)
    assert any("cosign is not installed" in line for line in lines)
    with pytest.raises(ImageError, match="not signed by the release"):
        release_source(World(), lambda _args: False, []).publish(REGISTRY)


def inspect_output(name: str, driver: str) -> str:
    return (
        f"Name:          {name}\nDriver:        {driver}\n"
        f"Last Activity: 2026-09-26 00:00:00 +0000 UTC\n\n"
        f"Nodes:\nName:             {name}0\nStatus:           running\n"
    )


@dataclass
class FakeDocker:
    """Answers ``git log`` and ``docker buildx`` by writing an OCI layout.

    ``builders`` maps buildx builder names to drivers; ``current`` is the
    one ``docker buildx inspect`` (no name) reports.
    """

    images: dict[str, Image]
    fail: bool = False
    builders: dict[str, str] = field(
        default_factory=lambda: {"desktop-linux": "docker-container"}
    )
    current: str = "desktop-linux"
    create_fails: bool = False
    calls: list[list[str]] = field(default_factory=list)

    def _buildx(self, arguments: list[str]) -> Completed:
        if arguments[0] == "inspect":
            name = arguments[1] if len(arguments) > 1 else self.current
            if name not in self.builders:
                return Completed(1, f"ERROR: no builder {name!r} found\n")
            return Completed(0, inspect_output(name, self.builders[name]))
        if self.create_fails:
            return Completed(1, "ERROR: permission denied\n")
        name = arguments[arguments.index("--name") + 1]
        self.builders[name] = arguments[arguments.index("--driver") + 1]
        return Completed(0, f"{name}\n")

    def builds(self) -> list[list[str]]:
        return [argv for argv in self.calls if argv[:3] == DOCKER_BUILD]

    def __call__(
        self,
        argv: list[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        on_output: Callable[[str], None] | None,
    ) -> Completed:
        self.calls.append(argv)
        if argv[0] == "/bin/git":
            return Completed(0, "1700000000\n")
        if argv[:3] != DOCKER_BUILD:
            return self._buildx(argv[2:])
        if self.fail:
            return Completed(1, "ERROR: failed to solve\n")
        name = argv[argv.index("--file") + 1].split("/")[0]
        output = argv[argv.index("--output") + 1]
        dest = output.split("dest=")[1].split(",")[0]
        oci_layout(Path(dest), self.images[name], attestation=make_image("a", layers=1))
        return Completed(0, "")


def built_source(world: World, docker: FakeDocker, tmp_path: Path) -> BuiltImages:
    return BuiltImages(
        root=tmp_path,
        workdir=tmp_path,
        docker="/bin/docker",
        git="/bin/git",
        run=docker,
        registries=Registries(lambda: FAKE_ACCESS_TOKEN, transport=world.transport()),
        say=lambda _: None,
        on_output=lambda _: None,
    )


def test_build_uploads_the_local_images(tmp_path: Path) -> None:
    world = World()
    docker = FakeDocker({"enclave": world.enclave, "server": world.server})
    source = built_source(world, docker, tmp_path)
    assert source.enclave_digest_hint() == world.enclave.digest
    images = source.publish(REGISTRY)
    assert images.server_digest == world.server.digest
    assert (f"{DEST}/enclave", world.enclave.digest) in world.ar.manifests
    builds = docker.builds()
    assert len(builds) == 2  # the enclave is built once, not again on publish
    assert "--builder" not in builds[0]  # the current builder exports OCI
    assert "SOURCE_DATE_EPOCH=1700000000" in builds[0]
    assert "--platform" in builds[0] and "linux/amd64" in builds[0]
    assert not world.ghcr.requests


def test_failed_build_is_reported(tmp_path: Path) -> None:
    docker = FakeDocker({}, fail=True)
    with pytest.raises(ImageError, match="docker buildx failed for the enclave"):
        built_source(World(), docker, tmp_path).enclave_digest_hint()


def test_docker_driver_builds_with_a_created_carapace_builder(
    tmp_path: Path,
) -> None:
    world = World()
    docker = FakeDocker(
        {"enclave": world.enclave, "server": world.server},
        builders={"default": "docker"},
        current="default",
    )
    source = built_source(world, docker, tmp_path)
    source.publish(REGISTRY)
    create = [argv for argv in docker.calls if argv[2:3] == ["create"]]
    assert create == [
        [
            "/bin/docker",
            "buildx",
            "create",
            "--name",
            "carapace",
            "--driver",
            "docker-container",
            "--driver-opt",
            f"image={BUILDKIT_IMAGE}",
        ]
    ]
    for build in docker.builds():
        assert build[3:5] == ["--builder", "carapace"]
    # The builder is chosen once, not per image.
    inspects = [argv for argv in docker.calls if argv[2:3] == ["inspect"]]
    assert len(inspects) == 2


def test_existing_carapace_builder_is_reused(tmp_path: Path) -> None:
    world = World()
    docker = FakeDocker(
        {"enclave": world.enclave, "server": world.server},
        builders={"default": "docker", "carapace": "docker-container"},
        current="default",
    )
    built_source(world, docker, tmp_path).enclave_digest_hint()
    assert not any(argv[2:3] == ["create"] for argv in docker.calls)
    assert docker.builds()[0][3:5] == ["--builder", "carapace"]


def test_builder_that_cannot_be_created_names_the_command(tmp_path: Path) -> None:
    docker = FakeDocker(
        {}, builders={"default": "docker"}, current="default", create_fails=True
    )
    with pytest.raises(ImageError) as caught:
        built_source(World(), docker, tmp_path).enclave_digest_hint()
    expected = (
        "`docker buildx create --name carapace --driver docker-container "
        f"--driver-opt image={BUILDKIT_IMAGE}`"
    )
    assert expected in str(caught.value)
    assert not docker.builds()


def test_carapace_builder_with_the_docker_driver_is_refused(tmp_path: Path) -> None:
    docker = FakeDocker(
        {}, builders={"default": "docker", "carapace": "docker"}, current="default"
    )
    with pytest.raises(ImageError, match="docker buildx rm carapace"):
        built_source(World(), docker, tmp_path).enclave_digest_hint()
    assert not docker.builds()


def test_missing_buildx_is_reported(tmp_path: Path) -> None:
    docker = FakeDocker({}, builders={}, current="default")
    with pytest.raises(ImageError, match="needs docker buildx"):
        built_source(World(), docker, tmp_path).enclave_digest_hint()


def test_created_builder_pins_the_release_workflows_buildkit() -> None:
    action = Path(__file__).parents[2] / ".github/actions/build-enclave/action.yml"
    assert f"driver-opts: image={BUILDKIT_IMAGE}\n" in action.read_text()


@pytest.mark.parametrize(
    ("output", "driver"),
    [
        (inspect_output("default", "docker"), "docker"),
        (inspect_output("x", "docker-container"), "docker-container"),
        ("Name: x\n", None),
        ("", None),
    ],
)
def test_buildx_driver_is_read_from_inspect(output: str, driver: str | None) -> None:
    assert buildx_driver(output) == driver


def not_found_releases() -> GitHubReleases:
    """GitHub as an unauthenticated client sees a private repository."""
    transport = httpx.MockTransport(lambda _request: httpx.Response(404))
    return GitHubReleases(httpx.Client(transport=transport))


@pytest.mark.parametrize(
    ("fetch", "expected"),
    [
        (lambda github: github.latest_tag(REPO), "no published release of"),
        (
            lambda github: fetch_release(github, FakeVerifier(), repo=REPO, tag=TAG),
            f"no {TAG}.json in release {TAG} of",
        ),
    ],
    ids=["latest", "tagged"],
)
def test_missing_release_explains_private_repos_and_build(
    fetch: Callable[[GitHubReleases], object], expected: str
) -> None:
    with pytest.raises(ImageError) as caught:
        fetch(not_found_releases())
    message = str(caught.value)
    assert expected in message and REPO in message
    assert "private" in message and "--build" in message
    assert "404" not in message


def deploy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    world: World,
    stack: FakeStack,
    *argv: str,
    verifier: FakeVerifier | None = None,
) -> tuple[int, str]:
    monkeypatch.setattr(
        command,
        "default_services",
        lambda: command.Services(
            gcp=deployable_project().api,
            stack=lambda *_args: stack,
            clock=instant_clock(),
            transport=world.transport(),
            verify=verifier or FakeVerifier(),
            which=lambda _name: None,
            first_run=fake_first_run(),
        ),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    out, err = io.StringIO(), io.StringIO()
    base = ["--project", PROJECT, "--prefix", PREFIX, "--alert-email", "a@b.io"]
    base += ["--password-stdin", "--no-passphrase"]
    code = main(
        ["--config-dir", str(tmp_path), "deploy", *base, *argv], out=out, err=err
    )
    return code, out.getvalue() + err.getvalue()


def test_deploy_defaults_to_the_latest_verified_release(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    world, stack = World(), FakeStack()
    code, output = deploy(monkeypatch, tmp_path, world, stack, "--yes")
    assert code == 0, output
    assert f"release {TAG} of {REPO}" in output
    assert "signature verified" in output
    # The bootstrap already allows the verified digest: no placeholder.
    assert json.loads(stack.ups[0]["carapace:allowed_digests"]) == [
        world.enclave.digest
    ]
    assert stack.ups[-1]["carapace:server_image_digest"] == world.server.digest
    assert (f"{DEST}/server", world.server.digest) in world.ar.manifests
    # The CLI pinned the enclave running exactly the verified release digest.
    pin = json.loads((tmp_path / "enclave.json").read_text())
    assert pin["image_digest"] == world.enclave.digest


def test_unverified_release_changes_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    world, stack = World(), FakeStack()
    code, output = deploy(
        monkeypatch,
        tmp_path,
        world,
        stack,
        "--release",
        TAG,
        "--yes",
        verifier=FakeVerifier(valid=False),
    )
    assert code != 0 and "does not verify" in output
    assert "$92/month" not in output
    assert not stack.ups and not world.ar.requests


def test_image_flags_are_mutually_exclusive(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, output = deploy(
        monkeypatch, tmp_path, World(), FakeStack(), "--build", "--release", TAG
    )
    assert code != 0
    assert "--release and --build cannot be combined" in output


def test_build_without_docker_fails_before_the_summary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    code, output = deploy(monkeypatch, tmp_path, World(), FakeStack(), "--build")
    assert code != 0
    assert "--build needs docker on PATH" in output
    assert "$92/month" not in output


def test_sigstore_verify_rejects_a_malformed_bundle_offline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sigstore.verify import Verifier

    def no_network() -> None:
        raise AssertionError("the trust root must not be fetched")

    monkeypatch.setattr(Verifier, "production", staticmethod(no_network))
    with pytest.raises(ImageError, match="does not verify"):
        sigstore_verify(
            b"{}", b'{"bundle": 1}', identity=ENCLAVE_IDENTITY, issuer=ACTIONS_ISSUER
        )
