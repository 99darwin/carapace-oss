"""Copy an image by digest into Artifact Registry, without crane or docker.

A small OCI distribution client on httpx: it pulls a platform image
manifest and its blobs from a source (ghcr.io anonymously, or a local OCI
layout tarball from ``--build``) and pushes them to the stack's Artifact
Registry repository with the caller's ADC token.

The manifest **bytes** are copied unchanged, so the digest cannot change:
the source bytes must hash to the requested digest before anything is
pushed, every blob is hashed while it streams, and the registry's
``Docker-Content-Digest`` must equal the digest afterwards. Blobs that are
already there are skipped, so a re-run is cheap.
"""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
from collections.abc import Callable, Iterable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import httpx

from carapace_cli.errors import CarapaceError, network_errors

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
IMAGE_MANIFESTS = frozenset({OCI_MANIFEST, DOCKER_MANIFEST})
INDEXES = frozenset({OCI_INDEX, DOCKER_LIST})
MANIFEST_ACCEPT = ", ".join(sorted(IMAGE_MANIFESTS | INDEXES))
# buildx marks attestation manifests in an index with this annotation.
REFERENCE_TYPE_ANNOTATION = "vnd.docker.reference.type"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
REQUEST_TIMEOUT_SECONDS = 300.0
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
GHCR = "ghcr.io"
ARTIFACT_REGISTRY_SUFFIX = "-docker.pkg.dev"
# Artifact Registry's documented user name for an OAuth access token.
ACCESS_TOKEN_USER = "oauth2accesstoken"  # noqa: S105 - a user name
HTTP_OK = 200
HTTP_UNAUTHORIZED = 401
HTTP_NOT_FOUND = 404
REDIRECTS = frozenset({301, 302, 303, 307, 308})

Credentials = Callable[[], tuple[str, str]]


class RegistryError(CarapaceError):
    """A registry call failed, or an image did not match its digest."""


@dataclass(frozen=True)
class Descriptor:
    media_type: str
    digest: str
    size: int


def sha256_digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _descriptor(value: Any) -> Descriptor:
    if not isinstance(value, dict):
        raise RegistryError("malformed descriptor in image manifest")
    digest, size = str(value.get("digest", "")), value.get("size")
    if not DIGEST_PATTERN.fullmatch(digest) or not isinstance(size, int) or size < 0:
        raise RegistryError(f"malformed descriptor {digest[:80]!r} in image manifest")
    return Descriptor(str(value.get("mediaType", "")), digest, size)


def image_blobs(raw: bytes) -> list[Descriptor]:
    """The config and layer descriptors of an image manifest (not an index)."""
    manifest = json.loads(raw)
    if not isinstance(manifest, dict) or manifest.get("mediaType") in INDEXES:
        raise RegistryError("expected an image manifest, got an index")
    layers = manifest.get("layers")
    if not isinstance(layers, list):
        raise RegistryError("image manifest has no layers")
    return [_descriptor(manifest.get("config")), *map(_descriptor, layers)]


def platform_digest(index: dict[str, Any], *, os: str, architecture: str) -> str:
    """The one image manifest in ``index`` for the platform, ignoring attestations."""
    found = [
        str(item.get("digest"))
        for item in index.get("manifests") or []
        if isinstance(item, dict)
        and (item.get("platform") or {}).get("os") == os
        and (item.get("platform") or {}).get("architecture") == architecture
        and REFERENCE_TYPE_ANNOTATION not in (item.get("annotations") or {})
    ]
    if len(found) != 1 or not DIGEST_PATTERN.fullmatch(found[0]):
        raise RegistryError(
            f"expected one {os}/{architecture} image in the index, found {len(found)}"
        )
    return found[0]


class BlobSource(Protocol):
    def manifest(self, reference: str) -> tuple[bytes, str]:
        """Raw manifest bytes and media type."""
        ...

    def blob(self, digest: str) -> AbstractContextManager[Iterable[bytes]]: ...


def _parse_challenge(header: str) -> dict[str, str]:
    scheme, _, params = header.partition(" ")
    if scheme.lower() != "bearer":
        raise RegistryError(f"unsupported registry auth scheme {scheme[:20]!r}")
    return dict(re.findall(r'(\w+)="([^"]*)"', params))


@dataclass
class RegistryClient:
    """Distribution API calls to one host, with the bearer-token handshake.

    Credentials are only ever sent to the registry host itself: a token
    realm on any other host is refused, and redirects (ghcr.io serves blobs
    from a CDN) are followed without the Authorization header.
    """

    host: str
    client: httpx.Client
    credentials: Credentials | None = None
    _tokens: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.host != GHCR and not self.host.endswith(ARTIFACT_REGISTRY_SUFFIX):
            raise RegistryError(f"refusing to talk to registry {self.host!r}")

    def _token(self, challenge: dict[str, str], scope: str) -> str:
        realm = httpx.URL(challenge.get("realm", ""))
        if realm.scheme != "https" or realm.host != self.host:
            raise RegistryError(f"refusing token realm on {realm.host!r}")
        params = {"service": challenge.get("service", self.host), "scope": scope}
        auth = self.credentials() if self.credentials else None
        with network_errors(f"registry {self.host}"):
            response = self.client.get(realm, params=params, auth=auth)
        if not response.is_success:
            raise RegistryError(f"{self.host} refused a token ({response.status_code})")
        body = response.json()
        token = body.get("token") or body.get("access_token")
        if not token:
            raise RegistryError(f"{self.host} returned no token")
        return str(token)

    def request(
        self,
        method: str,
        url: str,
        *,
        scope: str,
        stream: bool = False,
        retry_auth: bool = True,
        **kwargs: Any,
    ) -> httpx.Response:
        """One call; on 401 fetch a token for ``scope`` and retry once.

        A call with a one-shot (streamed) body passes ``retry_auth=False``
        and must hold a token for ``scope`` already.
        """
        if not url.startswith("https://"):
            url = f"https://{self.host}{url}"
        if httpx.URL(url).host != self.host:
            raise RegistryError(f"refusing to follow {self.host} to another host")
        for attempt in range(2):
            headers = dict(kwargs.pop("headers", None) or {})
            if scope in self._tokens:
                headers["Authorization"] = f"Bearer {self._tokens[scope]}"
            with network_errors(f"registry {self.host}"):
                request = self.client.build_request(
                    method, url, headers=headers, **kwargs
                )
                response = self.client.send(request, stream=stream)
            if response.status_code != HTTP_UNAUTHORIZED or attempt or not retry_auth:
                return response
            response.close()
            challenge = _parse_challenge(response.headers.get("www-authenticate", ""))
            self._tokens[scope] = self._token(challenge, scope)
            kwargs["headers"] = headers
        raise AssertionError("unreachable")  # pragma: no cover

    def _fail(self, response: httpx.Response, what: str) -> RegistryError:
        response.close()
        return RegistryError(f"{self.host}: {what} failed ({response.status_code})")

    def manifest(self, repo: str, reference: str) -> tuple[bytes, str]:
        response = self.request(
            "GET",
            f"/v2/{repo}/manifests/{reference}",
            scope=f"repository:{repo}:pull",
            headers={"Accept": MANIFEST_ACCEPT},
        )
        if response.status_code != HTTP_OK:
            raise self._fail(response, f"reading {repo}:{reference}")
        if len(response.content) > MAX_MANIFEST_BYTES:
            raise RegistryError(f"{repo}:{reference} manifest is too large")
        media_type = response.headers.get("content-type", "").split(";")[0].strip()
        return response.content, media_type

    def has_blob(self, repo: str, digest: str) -> bool:
        response = self.request(
            "HEAD", f"/v2/{repo}/blobs/{digest}", scope=f"repository:{repo}:pull"
        )
        if response.status_code in (HTTP_OK, HTTP_NOT_FOUND):
            return response.status_code == HTTP_OK
        raise self._fail(response, f"checking blob {digest[:19]}")

    @contextmanager
    def blob(self, repo: str, digest: str) -> Iterator[Iterable[bytes]]:
        response = self.request(
            "GET",
            f"/v2/{repo}/blobs/{digest}",
            scope=f"repository:{repo}:pull",
            stream=True,
        )
        try:
            if response.status_code in REDIRECTS:
                location = httpx.URL(response.headers.get("location", ""))
                response.close()
                if location.scheme != "https":
                    raise RegistryError(f"{self.host} redirected a blob off https")
                # A fresh request: the Authorization header stays behind.
                with network_errors("registry blob storage"):
                    response = self.client.send(
                        self.client.build_request("GET", location), stream=True
                    )
            if response.status_code != HTTP_OK:
                raise self._fail(response, f"reading blob {digest[:19]}")
            yield response.iter_bytes(CHUNK_BYTES)
        finally:
            response.close()

    def upload_blob(self, repo: str, blob: Descriptor, chunks: Iterable[bytes]) -> None:
        scope = f"repository:{repo}:pull,push"
        started = self.request("POST", f"/v2/{repo}/blobs/uploads/", scope=scope)
        location = started.headers.get("location")
        if started.status_code != 202 or not location:
            raise self._fail(started, f"starting upload of {blob.digest[:19]}")
        url = httpx.URL(location)
        if not url.is_absolute_url:
            url = httpx.URL(f"https://{self.host}").join(location)
        finished = self.request(
            "PUT",
            str(url.copy_merge_params({"digest": blob.digest})),
            scope=scope,
            retry_auth=False,
            content=chunks,
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": str(blob.size),
            },
        )
        if finished.status_code != 201:
            raise self._fail(finished, f"uploading blob {blob.digest[:19]}")

    def put_manifest(self, repo: str, digest: str, raw: bytes, media_type: str) -> str:
        """Push by digest; returns the digest the registry computed."""
        response = self.request(
            "PUT",
            f"/v2/{repo}/manifests/{digest}",
            scope=f"repository:{repo}:pull,push",
            content=raw,
            headers={"Content-Type": media_type},
        )
        if response.status_code != 201:
            raise self._fail(response, f"pushing manifest {digest[:19]}")
        return response.headers.get("docker-content-digest", "")


@dataclass
class RegistrySource:
    """A :class:`BlobSource` reading one repository of a registry."""

    registry: RegistryClient
    repo: str

    def manifest(self, reference: str) -> tuple[bytes, str]:
        return self.registry.manifest(self.repo, reference)

    def blob(self, digest: str) -> AbstractContextManager[Iterable[bytes]]:
        return self.registry.blob(self.repo, digest)


@dataclass
class OciLayoutSource:
    """A :class:`BlobSource` reading an OCI layout tarball (buildx ``type=oci``)."""

    path: Path

    def _member(self, archive: tarfile.TarFile, digest: str) -> Any:
        if not DIGEST_PATTERN.fullmatch(digest):
            raise RegistryError(f"unsupported digest {digest[:80]!r}")
        member = archive.extractfile(f"blobs/sha256/{digest.removeprefix('sha256:')}")
        if member is None:
            raise RegistryError(f"{self.path} has no blob {digest[:19]}")
        return member

    def index(self) -> dict[str, Any]:
        with tarfile.open(self.path) as archive:
            member = archive.extractfile("index.json")
            if member is None:
                raise RegistryError(f"{self.path} is not an OCI layout")
            top = json.load(member)
            # buildx wraps the image index in a one-entry top-level index.
            entries = top.get("manifests") or []
            if len(entries) == 1 and entries[0].get("mediaType") in INDEXES:
                return json.load(self._member(archive, entries[0]["digest"]))
            return top

    def manifest(self, reference: str) -> tuple[bytes, str]:
        with tarfile.open(self.path) as archive:
            raw = self._member(archive, reference).read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise RegistryError(f"manifest {reference[:19]} is too large")
        return raw, str(json.loads(raw).get("mediaType") or OCI_MANIFEST)

    @contextmanager
    def blob(self, digest: str) -> Iterator[Iterable[bytes]]:
        with tarfile.open(self.path) as archive:
            member = self._member(archive, digest)
            yield iter(lambda: member.read(CHUNK_BYTES), b"")


def _verified(chunks: Iterable[bytes], blob: Descriptor) -> Iterator[bytes]:
    """Pass ``chunks`` through; fail the upload if they are not ``blob``."""
    hasher, size = hashlib.sha256(), 0
    for chunk in chunks:
        hasher.update(chunk)
        size += len(chunk)
        if size > blob.size:
            raise RegistryError(f"blob {blob.digest[:19]} is larger than declared")
        yield chunk
    if size != blob.size or f"sha256:{hasher.hexdigest()}" != blob.digest:
        raise RegistryError(f"blob {blob.digest[:19]} does not match its digest")


def copy_image(
    source: BlobSource,
    dest: RegistryClient,
    dest_repo: str,
    digest: str,
    *,
    say: Callable[[str], None],
) -> None:
    """Copy the image manifest ``digest`` and its blobs, verifying every byte."""
    raw, media_type = source.manifest(digest)
    if sha256_digest(raw) != digest:
        raise RegistryError(f"source manifest does not hash to {digest}")
    if media_type not in IMAGE_MANIFESTS:
        raise RegistryError(f"{digest[:19]} is a {media_type!r}, not an image")
    blobs = image_blobs(raw)
    for number, blob in enumerate(blobs, start=1):
        if dest.has_blob(dest_repo, blob.digest):
            continue
        say(f"  {dest_repo}: blob {number}/{len(blobs)} ({blob.size} bytes)")
        with source.blob(blob.digest) as chunks:
            dest.upload_blob(dest_repo, blob, _verified(chunks, blob))
    pushed = dest.put_manifest(dest_repo, digest, raw, media_type)
    if pushed != digest:
        raise RegistryError(
            f"{dest.host} stored the manifest as {pushed or 'unknown'}, not {digest}"
        )


def registry_client(
    host: str, *, credentials: Credentials | None = None, transport: Any = None
) -> RegistryClient:
    client = httpx.Client(
        transport=transport,
        timeout=REQUEST_TIMEOUT_SECONDS,
        trust_env=False,
        follow_redirects=False,
    )
    return RegistryClient(host=host, client=client, credentials=credentials)


def split_registry(image_registry: str) -> tuple[str, str]:
    """``<region>-docker.pkg.dev/<project>/<repo>`` into host and path."""
    host, _, path = image_registry.partition("/")
    if not host.endswith(ARTIFACT_REGISTRY_SUFFIX) or not path:
        raise RegistryError(f"unexpected image registry {image_registry!r}")
    return host, path


def access_token_credentials(token: Callable[[], str]) -> Credentials:
    return lambda: (ACCESS_TOKEN_USER, token())
