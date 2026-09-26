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
    BuiltImages,
    GitHubReleases,
    ImageError,
    Registries,
    ReleaseImages,
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


@dataclass
class FakeDocker:
    """Answers ``git log`` and ``docker buildx`` by writing an OCI layout."""

    images: dict[str, Image]
    fail: bool = False
    calls: list[list[str]] = field(default_factory=list)

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
    builds = [argv for argv in docker.calls if argv[0] == "/bin/docker"]
    assert len(builds) == 2  # the enclave is built once, not again on publish
    assert "SOURCE_DATE_EPOCH=1700000000" in builds[0]
    assert "--platform" in builds[0] and "linux/amd64" in builds[0]
    assert not world.ghcr.requests


def test_failed_build_is_reported(tmp_path: Path) -> None:
    docker = FakeDocker({}, fail=True)
    with pytest.raises(ImageError, match="docker buildx failed for the enclave"):
        built_source(World(), docker, tmp_path).enclave_digest_hint()


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
        ),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    out, err = io.StringIO(), io.StringIO()
    base = ["--project", PROJECT, "--prefix", PREFIX, "--alert-email", "a@b.io"]
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
    assert "$80/month" not in output
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
    assert "$80/month" not in output


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
