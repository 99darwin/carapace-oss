"""Copying an image by digest, against the in-memory registry."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from registry_support import (
    AR_HOST,
    CDN,
    FAKE_ADC_TOKEN,
    GHCR_REPO,
    FakeRegistry,
    make_image,
    make_index,
    oci_layout,
    transport,
)

from carapace_cli.deploy.registry import (
    GHCR,
    OciLayoutSource,
    RegistryError,
    RegistrySource,
    access_token_credentials,
    copy_image,
    platform_digest,
    registry_client,
    sha256_digest,
    split_registry,
)

DEST_REPO = "carapace-selfhost/c1x/enclave"
SOURCE_REPO = f"{GHCR_REPO}/enclave"


def registries(*, redirect: bool = False) -> tuple[FakeRegistry, FakeRegistry]:
    ghcr = FakeRegistry(GHCR, redirect_blobs=redirect)
    ar = FakeRegistry(AR_HOST, basic=("oauth2accesstoken", FAKE_ADC_TOKEN))
    return ghcr, ar


def copy(
    ghcr: FakeRegistry, ar: FakeRegistry, digest: str, lines: list[str] | None = None
) -> None:
    mock = transport(ghcr, ar)
    source = RegistrySource(registry_client(GHCR, transport=mock), SOURCE_REPO)
    dest = registry_client(
        AR_HOST,
        credentials=access_token_credentials(lambda: FAKE_ADC_TOKEN),
        transport=mock,
    )
    copy_image(
        source, dest, DEST_REPO, digest, say=(lines if lines is not None else []).append
    )


def test_copy_keeps_the_manifest_bytes_and_digest() -> None:
    ghcr, ar = registries(redirect=True)
    image = make_image("enclave")
    ghcr.add(SOURCE_REPO, image)
    copy(ghcr, ar, image.digest)
    assert ar.manifests[(DEST_REPO, image.digest)][0] == image.manifest
    for digest, data in image.blobs.items():
        assert ar.blobs[(DEST_REPO, digest)] == data
    # The CDN never sees a credential; ghcr.io gets an anonymous token.
    cdn = [r for r in ghcr.requests if r.url.host == CDN]
    assert cdn and all("authorization" not in r.headers for r in cdn)
    token_calls = [r for r in ghcr.requests if r.url.path == "/token"]
    assert all("authorization" not in r.headers for r in token_calls)


def test_blobs_already_present_are_skipped() -> None:
    ghcr, ar = registries()
    image = make_image("enclave")
    ghcr.add(SOURCE_REPO, image)
    ar.add(DEST_REPO, image)
    lines: list[str] = []
    copy(ghcr, ar, image.digest, lines)
    assert ar.uploads == 0 and lines == []
    assert not any(
        r.url.path.startswith(f"/v2/{SOURCE_REPO}/blobs") for r in ghcr.requests
    )


def test_tampered_source_manifest_is_refused_before_any_push() -> None:
    ghcr, ar = registries()
    image, other = make_image("enclave"), make_image("evil")
    ghcr.add(SOURCE_REPO, other)
    ghcr.manifests[(SOURCE_REPO, image.digest)] = ghcr.manifests[
        (SOURCE_REPO, other.digest)
    ]
    with pytest.raises(RegistryError, match="does not hash to"):
        copy(ghcr, ar, image.digest)
    assert not ar.requests


def test_tampered_blob_fails_the_upload() -> None:
    ghcr, ar = registries()
    image = make_image("enclave")
    ghcr.add(SOURCE_REPO, image)
    layer = next(iter(image.blobs))
    ghcr.blobs[(SOURCE_REPO, layer)] = b"x" * len(image.blobs[layer])
    with pytest.raises(RegistryError, match="does not match its digest"):
        copy(ghcr, ar, image.digest)
    assert (DEST_REPO, image.digest) not in ar.manifests


def test_registry_storing_another_digest_is_an_error() -> None:
    ghcr, ar = registries()
    image = make_image("enclave")
    ghcr.add(SOURCE_REPO, image)
    ar.stored_digest_override = "sha256:" + "f" * 64
    with pytest.raises(RegistryError, match="stored the manifest as sha256:fff"):
        copy(ghcr, ar, image.digest)


def test_index_digest_is_not_copied_as_an_image() -> None:
    ghcr, ar = registries()
    image = make_image("enclave")
    ghcr.add(SOURCE_REPO, image)
    index = make_index(image)
    ghcr.tag_index(SOURCE_REPO, sha256_digest(index), index)
    with pytest.raises(RegistryError, match="not an image"):
        copy(ghcr, ar, sha256_digest(index))


def test_wrong_artifact_registry_credentials_are_refused() -> None:
    ghcr, ar = registries()
    image = make_image("enclave")
    ghcr.add(SOURCE_REPO, image)
    ar.basic = ("oauth2accesstoken", "another-token")
    with pytest.raises(RegistryError, match="refused a token"):
        copy(ghcr, ar, image.digest)


def test_credentials_never_go_to_another_host() -> None:
    ghcr, ar = registries()
    ar.realm_host = "evil.example"
    image = make_image("enclave")
    ghcr.add(SOURCE_REPO, image)
    with pytest.raises(RegistryError, match="refusing token realm"):
        copy(ghcr, ar, image.digest)
    assert not [r for r in ar.requests if r.url.path == "/token"]
    with pytest.raises(RegistryError, match="refusing to talk"):
        registry_client("registry.example")


def test_platform_digest_ignores_attestations() -> None:
    image, attestation = make_image("enclave"), make_image("att", layers=1)
    index = json.loads(make_index(image, attestation=attestation))
    assert platform_digest(index, os="linux", architecture="amd64") == image.digest
    with pytest.raises(RegistryError, match="found 0"):
        platform_digest(index, os="linux", architecture="arm64")


def test_oci_layout_source_copies_a_local_build(tmp_path: Path) -> None:
    image, attestation = make_image("built"), make_image("att", layers=1)
    layout = OciLayoutSource(
        oci_layout(tmp_path / "enclave.tar", image, attestation=attestation)
    )
    digest = platform_digest(layout.index(), os="linux", architecture="amd64")
    assert digest == image.digest
    _, ar = registries()
    dest = registry_client(
        AR_HOST,
        credentials=access_token_credentials(lambda: FAKE_ADC_TOKEN),
        transport=transport(ar),
    )
    copy_image(layout, dest, DEST_REPO, digest, say=lambda _: None)
    assert ar.manifests[(DEST_REPO, digest)][0] == image.manifest


def test_split_registry() -> None:
    assert split_registry(f"{AR_HOST}/p/c1x") == (AR_HOST, "p/c1x")
    with pytest.raises(RegistryError):
        split_registry("ghcr.io/p/c1x")


def test_transport_errors_are_reported_without_urls() -> None:
    def broken(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom https://ghcr.io/secret-path")

    client = registry_client(GHCR, transport=httpx.MockTransport(broken))
    with pytest.raises(Exception, match="cannot reach the registry ghcr.io") as info:
        client.manifest(SOURCE_REPO, "latest")
    assert "secret-path" not in str(info.value)
