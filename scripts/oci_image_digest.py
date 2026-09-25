"""Print the platform image manifest digest from an OCI image layout tarball.

``docker buildx build --output type=oci,dest=<tar>`` writes an OCI layout
whose top-level entry is usually an index holding the image manifest plus
provenance and SBOM attestation manifests. The attestations record builder
details, so the index digest differs between two otherwise identical builds.
The digest of record is therefore the image manifest for one platform, which
is also the digest the enclave VM runs and the WIF policy allows.

Usage: python scripts/oci_image_digest.py <image.tar> [--platform linux/amd64]

Standard library only, so it runs on a bare CI runner.
"""

from __future__ import annotations

import argparse
import json
import sys
import tarfile
from typing import Any

INDEX_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)
MANIFEST_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
)
REFERENCE_TYPE_ANNOTATION = "vnd.docker.reference.type"
MAX_NESTING = 4


class OciLayoutError(ValueError):
    """The tarball is not an OCI layout with exactly one matching image."""


def _read_json(archive: tarfile.TarFile, name: str) -> dict[str, Any]:
    member = archive.extractfile(name)
    if member is None:
        raise OciLayoutError(f"{name} is not a regular file")
    return json.load(member)


def _blob(archive: tarfile.TarFile, digest: str) -> dict[str, Any]:
    algorithm, _, hex_digest = digest.partition(":")
    if algorithm != "sha256" or not hex_digest:
        raise OciLayoutError(f"unsupported digest {digest!r}")
    return _read_json(archive, f"blobs/sha256/{hex_digest}")


def _is_attestation(descriptor: dict[str, Any]) -> bool:
    annotations = descriptor.get("annotations") or {}
    return REFERENCE_TYPE_ANNOTATION in annotations


def _matches(descriptor: dict[str, Any], os_name: str, architecture: str) -> bool:
    platform = descriptor.get("platform") or {}
    return platform.get("os") == os_name and platform.get("architecture") == (
        architecture
    )


def _collect(
    archive: tarfile.TarFile,
    descriptors: list[dict[str, Any]],
    os_name: str,
    architecture: str,
    depth: int,
) -> list[str]:
    if depth > MAX_NESTING:
        raise OciLayoutError("index nesting is too deep")
    found: list[str] = []
    for descriptor in descriptors:
        media_type = descriptor.get("mediaType")
        if _is_attestation(descriptor):
            continue
        if media_type in INDEX_MEDIA_TYPES:
            nested = _blob(archive, descriptor["digest"]).get("manifests", [])
            found.extend(_collect(archive, nested, os_name, architecture, depth + 1))
        elif media_type in MANIFEST_MEDIA_TYPES:
            # A lone manifest at the top level carries no platform; accept it.
            if depth == 0 or _matches(descriptor, os_name, architecture):
                found.append(descriptor["digest"])
    return found


def image_manifest_digest(tar_path: str, platform: str = "linux/amd64") -> str:
    """Return the single image manifest digest for ``platform``."""
    os_name, _, architecture = platform.partition("/")
    with tarfile.open(tar_path) as archive:
        top = _read_json(archive, "index.json").get("manifests", [])
        digests = sorted(set(_collect(archive, top, os_name, architecture, 0)))
    if len(digests) != 1:
        raise OciLayoutError(
            f"expected one {platform} image manifest, found {len(digests)}"
        )
    return digests[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("tarball")
    parser.add_argument("--platform", default="linux/amd64")
    args = parser.parse_args(argv)
    try:
        print(image_manifest_digest(args.tarball, args.platform))
    except (OciLayoutError, KeyError, OSError, tarfile.TarError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
