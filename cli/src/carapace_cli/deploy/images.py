"""Where the deploy's images come from: a verified release, or a local build.

Release (the default): ``releases/<tag>.json`` from the GitHub release names
the enclave digest. Its sigstore bundle must verify against the release
workflow's exact identity before the digest is trusted, so a tampered
release asset or registry cannot choose the enclave. Both images are then
copied by digest from ghcr.io into the stack's Artifact Registry.

Build (``--build``): ``docker buildx`` writes each image to an OCI layout
tarball, and the same copier uploads it. Docker never needs registry
credentials.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import httpx

from carapace_cli.deploy.interview import InvalidInputError
from carapace_cli.deploy.orchestrate import DIGEST_PATTERN, Images
from carapace_cli.deploy.pulumi_runner import Completed, ProcessRunner
from carapace_cli.deploy.registry import (
    GHCR,
    INDEXES,
    OciLayoutSource,
    RegistryClient,
    RegistrySource,
    access_token_credentials,
    copy_image,
    platform_digest,
    registry_client,
    sha256_digest,
    split_registry,
)
from carapace_cli.errors import CarapaceError, network_errors

DEFAULT_RELEASE_REPO = "99darwin/carapace-oss"
GITHUB = "https://github.com"
GITHUB_API = "https://api.github.com"
ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"
ENCLAVE_WORKFLOW = ".github/workflows/enclave-image.yml"
SERVER_WORKFLOW = ".github/workflows/server-image.yml"
REPO_PATTERN = re.compile(r"^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$")
TAG_PATTERN = re.compile(r"^v[0-9A-Za-z._-]+$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MAX_RELEASE_FILE_BYTES = 1024 * 1024
HTTP_TIMEOUT_SECONDS = 60.0
HTTP_NOT_FOUND = 404
PLATFORM = {"os": "linux", "architecture": "amd64"}
IMAGE_NAMES = ("enclave", "server")
# Docker's default driver cannot write the OCI layout tarballs --build needs.
DOCKER_DRIVER = "docker"
BUILDER_NAME = "carapace"
# The BuildKit the release workflow pins (.github/actions/build-enclave): the
# image bytes depend on it, so a --build digest can match the release's.
BUILDKIT_IMAGE = (
    "moby/buildkit:v0.33.0"
    "@sha256:6c2fa84a6b61ccd72899dde4239f8d5717f05f9a8ca6f3cad185fb1a95a94de3"
)
CREATE_BUILDER_ARGS = (
    "create",
    "--name",
    BUILDER_NAME,
    "--driver",
    "docker-container",
    "--driver-opt",
    f"image={BUILDKIT_IMAGE}",
)

RegistryFactory = Callable[[str], RegistryClient]


class ImageError(CarapaceError):
    """A release could not be verified, or an image could not be built."""


class SignatureVerifier(Protocol):
    def __call__(
        self, payload: bytes, bundle: bytes, *, identity: str, issuer: str
    ) -> None:
        """Raise :class:`ImageError` unless ``bundle`` signs ``payload``."""
        ...


def sigstore_verify(
    payload: bytes, bundle: bytes, *, identity: str, issuer: str
) -> None:
    """Verify a ``cosign sign-blob --bundle`` bundle with the sigstore library.

    Uses the public-good Fulcio/Rekor trust root, fetched and checked by
    TUF, and requires the certificate's SAN and issuer to match exactly.
    """
    try:
        from sigstore.errors import Error as SigstoreError
        from sigstore.models import Bundle
        from sigstore.verify import Verifier, policy
    except ImportError:  # pragma: no cover - the deploy extra is missing
        raise ImageError(
            "verifying a release needs the deploy extra: "
            "pip install 'carapace-cli[deploy]'"
        ) from None
    try:
        # Parse first: a malformed bundle fails without fetching the trust root.
        parsed = Bundle.from_json(bundle)
        Verifier.production().verify_artifact(
            payload, parsed, policy.Identity(identity=identity, issuer=issuer)
        )
    except (SigstoreError, ValueError) as exc:
        raise ImageError(
            f"the release signature does not verify ({type(exc).__name__}); "
            "do not deploy this release"
        ) from None


@dataclass(frozen=True)
class ReleaseManifest:
    tag: str
    digest: str
    commit: str


def workflow_identity(repo: str, workflow: str, tag: str) -> str:
    return f"{GITHUB}/{repo}/{workflow}@refs/tags/{tag}"


def validate_repo(value: str) -> str:
    if not REPO_PATTERN.fullmatch(value):
        raise InvalidInputError(f"{value!r} is not an <owner>/<repo> repository")
    return value


def validate_tag(value: str) -> str:
    if not TAG_PATTERN.fullmatch(value):
        raise InvalidInputError(f"{value!r} is not a release tag like v1.2.0")
    return value


def parse_release_manifest(raw: bytes, tag: str) -> ReleaseManifest:
    """The signed ``{tag, digest, commit, epoch}``; every field is checked."""
    try:
        value: Any = json.loads(raw)
    except json.JSONDecodeError:
        raise ImageError(f"{tag}.json is not JSON") from None
    if not isinstance(value, dict):
        raise ImageError(f"{tag}.json is not an object")
    if value.get("tag") != tag:
        raise ImageError(f"{tag}.json is signed for tag {value.get('tag')!r}")
    digest, commit = str(value.get("digest", "")), str(value.get("commit", ""))
    if not DIGEST_PATTERN.fullmatch(digest):
        raise ImageError(f"{tag}.json has no sha256 image digest")
    if not COMMIT_PATTERN.fullmatch(commit):
        raise ImageError(f"{tag}.json has no commit id")
    return ReleaseManifest(tag, digest, commit)


@dataclass
class GitHubReleases:
    """Public release metadata and assets. No credentials are sent."""

    client: httpx.Client

    def _get(self, url: str, *, not_found: str) -> httpx.Response:
        with network_errors("GitHub"):
            response = self.client.get(url)
        if response.url.scheme != "https":
            raise ImageError("GitHub redirected a release download off https")
        if response.status_code == HTTP_NOT_FOUND:
            raise ImageError(
                f"{not_found}: either the repository is private (release "
                "downloads are unauthenticated, so a private repository "
                "looks empty) or it has no such release. Deploy from a "
                "checkout of the repository with --build instead"
            )
        if not response.is_success:
            raise ImageError(f"GitHub returned {response.status_code} for {url}")
        if len(response.content) > MAX_RELEASE_FILE_BYTES:
            raise ImageError(f"{url} is too large")
        return response

    def latest_tag(self, repo: str) -> str:
        body = self._get(
            f"{GITHUB_API}/repos/{repo}/releases/latest",
            not_found=f"GitHub has no published release of {repo}",
        ).json()
        return validate_tag(str(body.get("tag_name", "")))

    def asset(self, repo: str, tag: str, name: str) -> bytes:
        return self._get(
            f"{GITHUB}/{repo}/releases/download/{tag}/{name}",
            not_found=f"GitHub has no {name} in release {tag} of {repo}",
        ).content


def fetch_release(
    releases: GitHubReleases,
    verify: SignatureVerifier,
    *,
    repo: str,
    tag: str,
) -> ReleaseManifest:
    """Download ``<tag>.json`` and its bundle; verify before parsing."""
    payload = releases.asset(repo, tag, f"{tag}.json")
    bundle = releases.asset(repo, tag, f"{tag}.json.sigstore.json")
    verify(
        payload,
        bundle,
        identity=workflow_identity(repo, ENCLAVE_WORKFLOW, tag),
        issuer=ACTIONS_ISSUER,
    )
    return parse_release_manifest(payload, tag)


@dataclass
class ReleaseImages:
    """An :class:`ImageSource` copying a verified release from ghcr.io."""

    release: ReleaseManifest
    repo: str
    registries: RegistryFactory
    cosign: Callable[[list[str]], bool | None]
    say: Callable[[str], None]

    def enclave_digest_hint(self) -> str | None:
        return self.release.digest

    def _ghcr_repo(self, name: str) -> str:
        return f"{self.repo.lower()}/{name}"

    def server_digest(self, ghcr: RegistryClient) -> str:
        """The ``linux/amd64`` image that ``server:<tag>`` serves."""
        raw, media_type = ghcr.manifest(self._ghcr_repo("server"), self.release.tag)
        if media_type in INDEXES:
            return platform_digest(json.loads(raw), **PLATFORM)
        return sha256_digest(raw)

    def check_server_signature(self, digest: str) -> None:
        """``cosign verify`` the server image, if cosign is installed.

        The server is outside the TCB (it cannot decrypt, and ``verify``
        catches a wrong key), so a missing cosign is reported, not fatal.
        """
        verified = self.cosign(
            [
                "verify",
                "--certificate-identity",
                workflow_identity(self.repo, SERVER_WORKFLOW, self.release.tag),
                "--certificate-oidc-issuer",
                ACTIONS_ISSUER,
                f"{GHCR}/{self._ghcr_repo('server')}@{digest}",
            ]
        )
        if verified is None:
            self.say(
                "  cosign is not installed: the server image signature was not "
                "checked (the server is outside the TCB)."
            )
        elif not verified:
            raise ImageError(f"the server image {digest} is not signed by the release")

    def publish(self, registry: str) -> Images:
        host, path = split_registry(registry)
        ghcr, dest = self.registries(GHCR), self.registries(host)
        server = self.server_digest(ghcr)
        self.check_server_signature(server)
        for name, digest in zip(
            IMAGE_NAMES, (self.release.digest, server), strict=True
        ):
            self.say(f"Copying {name} {digest[:19]} into {host}...")
            source = RegistrySource(ghcr, self._ghcr_repo(name))
            copy_image(source, dest, f"{path}/{name}", digest, say=self.say)
        return Images(enclave_digest=self.release.digest, server_digest=server)


def buildx_driver(inspect_output: str) -> str | None:
    """The builder's driver from ``docker buildx inspect`` output."""
    for line in inspect_output.splitlines():
        key, _, value = line.partition(":")
        if key.strip() == "Driver":
            return value.strip() or None
    return None


@dataclass
class BuiltImages:
    """An :class:`ImageSource` building both images from this checkout.

    Each image goes to an OCI layout tarball in ``workdir`` (the caller
    owns and removes it), built for ``linux/amd64`` with the commit time as
    ``SOURCE_DATE_EPOCH``, like the release workflow.
    """

    root: Path
    workdir: Path
    docker: str
    git: str
    run: ProcessRunner
    registries: RegistryFactory
    say: Callable[[str], None]
    on_output: Callable[[str], None]
    _built: dict[str, str] = field(default_factory=dict)
    _builder: list[str] | None = None

    def _source_date_epoch(self) -> str:
        result = self.run(
            [self.git, "log", "-1", "--format=%ct", "HEAD"],
            cwd=self.root,
            env=dict(os.environ),
            on_output=None,
        )
        epoch = result.output.strip()
        if result.code != 0 or not epoch.isdigit():
            raise ImageError("--build needs a git checkout of the repository")
        return epoch

    def _tarball(self, name: str) -> Path:
        return self.workdir / f"{name}.tar"

    def _buildx(self, *arguments: str) -> Completed:
        return self.run(
            [self.docker, "buildx", *arguments],
            cwd=self.root,
            env=dict(os.environ),
            on_output=None,
        )

    def _choose_builder(self) -> list[str]:
        """``--builder`` arguments for a builder that can export OCI layouts.

        Docker's default ``docker`` driver cannot, so when the current
        builder uses it, a dedicated ``docker-container`` builder named
        ``carapace`` is used, and created if it does not exist.
        """
        current = self._buildx("inspect")
        if current.code != 0:
            raise ImageError(
                "--build needs docker buildx: `docker buildx inspect` failed"
            )
        if buildx_driver(current.output) != DOCKER_DRIVER:
            return []
        dedicated = self._buildx("inspect", BUILDER_NAME)
        if dedicated.code == 0:
            if buildx_driver(dedicated.output) == DOCKER_DRIVER:
                raise ImageError(
                    f"the buildx builder {BUILDER_NAME!r} uses the docker driver, "
                    "which cannot export OCI images; remove it with "
                    f"`docker buildx rm {BUILDER_NAME}` and run again"
                )
            return ["--builder", BUILDER_NAME]
        self.say(
            "The current buildx builder uses the docker driver, which cannot "
            f"export OCI images; creating the {BUILDER_NAME!r} builder "
            "(docker-container driver)..."
        )
        if self._buildx(*CREATE_BUILDER_ARGS).code != 0:
            raise ImageError(
                f"could not create the {BUILDER_NAME!r} buildx builder; create "
                f"it with `docker buildx {' '.join(CREATE_BUILDER_ARGS)}` "
                "and run again"
            )
        return ["--builder", BUILDER_NAME]

    def _build(self, name: str) -> str:
        if name in self._built:
            return self._built[name]
        if self._builder is None:
            self._builder = self._choose_builder()
        self.say(f"Building the {name} image with docker buildx...")
        argv = [
            self.docker,
            "buildx",
            "build",
            *self._builder,
            "--file",
            f"{name}/Dockerfile",
            "--platform",
            "linux/amd64",
            "--build-arg",
            f"SOURCE_DATE_EPOCH={self._source_date_epoch()}",
            "--output",
            f"type=oci,dest={self._tarball(name)},rewrite-timestamp=true",
            ".",
        ]
        result = self.run(
            argv, cwd=self.root, env=dict(os.environ), on_output=self.on_output
        )
        if result.code != 0:
            raise ImageError(f"docker buildx failed for the {name} image")
        index = OciLayoutSource(self._tarball(name)).index()
        self._built[name] = platform_digest(index, **PLATFORM)
        return self._built[name]

    def enclave_digest_hint(self) -> str | None:
        return self._build("enclave")

    def publish(self, registry: str) -> Images:
        host, path = split_registry(registry)
        dest = self.registries(host)
        digests: list[str] = []
        for name in IMAGE_NAMES:
            digest = self._build(name)
            self.say(f"Uploading {name} {digest[:19]} into {host}...")
            source = OciLayoutSource(self._tarball(name))
            copy_image(source, dest, f"{path}/{name}", digest, say=self.say)
            digests.append(digest)
        return Images(enclave_digest=digests[0], server_digest=digests[1])


@dataclass
class Registries:
    """One client per registry host; only Artifact Registry gets the token."""

    token: Callable[[], str]
    transport: httpx.BaseTransport | None = None
    clients: dict[str, RegistryClient] = field(default_factory=dict)

    def __call__(self, host: str) -> RegistryClient:
        if host not in self.clients:
            credentials = None if host == GHCR else access_token_credentials(self.token)
            self.clients[host] = registry_client(
                host, credentials=credentials, transport=self.transport
            )
        return self.clients[host]

    def close(self) -> None:
        for registry in self.clients.values():
            registry.client.close()
