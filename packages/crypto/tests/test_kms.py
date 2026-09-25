"""Cloud KMS crypto key version resource names."""

from __future__ import annotations

import pytest

from carapace_crypto.kms import is_kms_key_version_name

VALID = (
    "projects/carapace-dev/locations/global/keyRings/mock"
    "/cryptoKeys/dek-wrap/cryptoKeyVersions/1"
)


@pytest.mark.parametrize(
    "name",
    [
        VALID,
        VALID.replace("/1", "/42"),
        "projects/example-project/locations/us-central1/keyRings/cptest-keyring"
        "/cryptoKeys/cptest-secrets/cryptoKeyVersions/1",
    ],
)
def test_accepts_full_version_names(name: str) -> None:
    assert is_kms_key_version_name(name)


@pytest.mark.parametrize(
    "name",
    [
        None,
        1,
        "",
        VALID.rsplit("/cryptoKeyVersions", 1)[0],
        VALID.replace("/1", "/0"),
        VALID.replace("/1", "/01"),
        VALID + "/extra",
        VALID + "\n",
        "\n" + VALID,
        VALID.replace("keyRings/mock", "keyRings/../x"),
        VALID.replace("carapace-dev", "Bad_Project"),
        VALID.replace("carapace-dev", "p"),
        VALID.replace("global", "Global"),
        "projects/x/cryptoKeyVersions/9",
        VALID.replace("/1", "/" + "9" * 20),
    ],
)
def test_rejects_anything_else(name: object) -> None:
    assert not is_kms_key_version_name(name)
