"""An in-memory OCI registry over ``httpx.MockTransport`` for the image tests.

It speaks enough of the distribution API for :mod:`carapace_cli.deploy.
registry`: the bearer-token handshake, manifests, blob HEAD and GET (with
an optional redirect to a CDN host), monolithic uploads and manifest PUT.
Nothing here reaches the network.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from carapace_cli.deploy.registry import (
    OCI_INDEX,
    OCI_MANIFEST,
    REFERENCE_TYPE_ANNOTATION,
    sha256_digest,
)

GHCR_REPO = "99darwin/carapace-oss"
CDN = "pkg-containers.githubusercontent.com"
AR_HOST = "us-central1-docker.pkg.dev"
FAKE_ADC_TOKEN = "fake-adc-token"  # noqa: S105 - a test value


@dataclass
class Image:
    manifest: bytes
    digest: str
    blobs: dict[str, bytes]


def make_image(seed: str, *, layers: int = 2) -> Image:
    config = json.dumps({"seed": seed}).encode()
    contents = [f"{seed}-layer-{n}".encode() * 50 for n in range(layers)]
    blobs = {sha256_digest(b): b for b in [config, *contents]}

    def descriptor(data: bytes, media_type: str) -> dict[str, Any]:
        return {
            "mediaType": media_type,
            "digest": sha256_digest(data),
            "size": len(data),
        }

    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": descriptor(config, "application/vnd.oci.image.config.v1+json"),
            "layers": [
                descriptor(c, "application/vnd.oci.image.layer.v1.tar+gzip")
                for c in contents
            ],
        }
    ).encode()
    return Image(manifest, sha256_digest(manifest), blobs)


def make_index(image: Image, *, attestation: Image | None = None) -> bytes:
    entries: list[dict[str, Any]] = [
        {
            "mediaType": OCI_MANIFEST,
            "digest": image.digest,
            "size": len(image.manifest),
            "platform": {"os": "linux", "architecture": "amd64"},
        }
    ]
    if attestation is not None:
        entries.append(
            {
                "mediaType": OCI_MANIFEST,
                "digest": attestation.digest,
                "size": len(attestation.manifest),
                "platform": {"os": "unknown", "architecture": "unknown"},
                "annotations": {REFERENCE_TYPE_ANNOTATION: "attestation-manifest"},
            }
        )
    return json.dumps(
        {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": entries}
    ).encode()


@dataclass
class FakeRegistry:
    """One registry host; ``basic`` is the credential its token endpoint wants."""

    host: str
    basic: tuple[str, str] | None = None
    redirect_blobs: bool = False
    manifests: dict[tuple[str, str], tuple[bytes, str]] = field(default_factory=dict)
    blobs: dict[tuple[str, str], bytes] = field(default_factory=dict)
    requests: list[httpx.Request] = field(default_factory=list)
    stored_digest_override: str | None = None
    realm_host: str | None = None
    uploads: int = 0

    def add(self, repo: str, image: Image, *, tag: str | None = None) -> None:
        self.manifests[(repo, image.digest)] = (image.manifest, OCI_MANIFEST)
        if tag:
            self.manifests[(repo, tag)] = (image.manifest, OCI_MANIFEST)
        for digest, data in image.blobs.items():
            self.blobs[(repo, digest)] = data

    def tag_index(self, repo: str, tag: str, index: bytes) -> None:
        self.manifests[(repo, tag)] = (index, OCI_INDEX)

    def _challenge(self, scope: str) -> httpx.Response:
        realm = f"https://{self.realm_host or self.host}/token"
        header = f'Bearer realm="{realm}",service="{self.host}",scope="{scope}"'
        return httpx.Response(401, headers={"WWW-Authenticate": header})

    def _token(self, request: httpx.Request) -> httpx.Response:
        if self.basic is not None:
            user, password = self.basic
            expected = base64.b64encode(f"{user}:{password}".encode()).decode()
            if request.headers.get("authorization") != f"Basic {expected}":
                return httpx.Response(403)
        scope = request.url.params.get("scope", "")
        return httpx.Response(200, json={"token": f"tok:{scope}"})

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == CDN:
            return httpx.Response(200, content=self.blobs[("cdn", request.url.path)])
        if request.url.path == "/token":
            return self._token(request)
        match = re.fullmatch(r"/v2/(.+)/(manifests|blobs)/(.+)", request.url.path)
        upload = re.fullmatch(r"/v2/(.+)/blobs/uploads/(.*)", request.url.path)
        repo = (upload or match).group(1) if (upload or match) else ""
        push = request.method in ("POST", "PUT")
        scope = f"repository:{repo}:pull" + (",push" if push else "")
        if request.headers.get("authorization") != f"Bearer tok:{scope}":
            return self._challenge(scope)
        if upload:
            return self._upload(request, repo, upload.group(2))
        assert match is not None
        kind, reference = match.group(2), match.group(3)
        if kind == "manifests":
            return self._manifest(request, repo, reference)
        return self._blob(request, repo, reference)

    def _upload(
        self, request: httpx.Request, repo: str, session: str
    ) -> httpx.Response:
        if request.method == "POST":
            self.uploads += 1
            location = f"/v2/{repo}/blobs/uploads/{self.uploads}?state=s"
            return httpx.Response(202, headers={"Location": location})
        digest = request.url.params["digest"]
        data = request.read()
        assert request.headers["content-length"] == str(len(data))
        if sha256_digest(data) != digest:
            return httpx.Response(400)
        self.blobs[(repo, digest)] = data
        return httpx.Response(201)

    def _manifest(
        self, request: httpx.Request, repo: str, reference: str
    ) -> httpx.Response:
        if request.method == "PUT":
            data = request.read()
            stored = self.stored_digest_override or sha256_digest(data)
            content_type = request.headers["content-type"]
            self.manifests[(repo, reference)] = (data, content_type)
            return httpx.Response(201, headers={"Docker-Content-Digest": stored})
        if (repo, reference) not in self.manifests:
            return httpx.Response(404)
        data, media_type = self.manifests[(repo, reference)]
        return httpx.Response(200, content=data, headers={"Content-Type": media_type})

    def _blob(self, request: httpx.Request, repo: str, digest: str) -> httpx.Response:
        if (repo, digest) not in self.blobs:
            return httpx.Response(404)
        if request.method == "HEAD":
            return httpx.Response(200)
        if self.redirect_blobs:
            path = f"/{digest}"
            self.blobs[("cdn", path)] = self.blobs[(repo, digest)]
            return httpx.Response(307, headers={"Location": f"https://{CDN}{path}"})
        return httpx.Response(200, content=self.blobs[(repo, digest)])


def transport(*registries: FakeRegistry) -> httpx.MockTransport:
    by_host = {registry.host: registry for registry in registries}

    def route(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        registry = by_host.get(host) or next(
            r for r in registries if r.redirect_blobs and host == CDN
        )
        return registry.handle(request)

    return httpx.MockTransport(route)


def oci_layout(path: Path, image: Image, *, attestation: Image | None = None) -> Path:
    """A buildx-style OCI layout tarball: a top index wrapping the image index."""
    index = make_index(image, attestation=attestation)
    top = {
        "schemaVersion": 2,
        "manifests": [
            {"mediaType": OCI_INDEX, "digest": sha256_digest(index), "size": len(index)}
        ],
    }
    files: dict[str, bytes] = {"index.json": json.dumps(top).encode()}
    for data in [index, image.manifest, *image.blobs.values()]:
        files[f"blobs/sha256/{hashlib.sha256(data).hexdigest()}"] = data
    if attestation is not None:
        files[f"blobs/sha256/{attestation.digest.removeprefix('sha256:')}"] = (
            attestation.manifest
        )
    with tarfile.open(path, "w") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path
