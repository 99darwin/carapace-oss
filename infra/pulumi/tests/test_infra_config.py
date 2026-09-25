"""Config and pure-function validation (no resources declared)."""

import pytest

pytest.importorskip("pulumi_gcp")

from components.config import ConfigError, build_image_reference  # noqa: E402
from components.enclave_vm import build_enclave_metadata  # noqa: E402
from components.kms import build_key_policy  # noqa: E402
from harness import DIGEST_A, DIGEST_B, make_config  # noqa: E402

REPO = "us-docker.pkg.dev/example-project/carapace/enclave"


def test_image_reference_is_pinned_by_digest() -> None:
    assert build_image_reference(REPO, DIGEST_A) == f"{REPO}@{DIGEST_A}"


@pytest.mark.parametrize("digest", ["latest", "v1.0.0", "sha256:abc", ""])
def test_image_reference_refuses_tags_and_short_digests(digest: str) -> None:
    with pytest.raises(ConfigError):
        build_image_reference(REPO, digest)


@pytest.mark.parametrize("repository", [f"{REPO}:latest", f"{REPO}@{DIGEST_A}", ""])
def test_image_reference_refuses_tagged_repository(repository: str) -> None:
    with pytest.raises(ConfigError):
        build_image_reference(repository, DIGEST_A)


def test_vm_metadata_refuses_tag_only_reference() -> None:
    with pytest.raises(ValueError, match="digest"):
        build_enclave_metadata(image_reference=f"{REPO}:latest", env={})


def test_vm_metadata_refuses_unlisted_env_overrides() -> None:
    with pytest.raises(ValueError, match="not allowed"):
        build_enclave_metadata(
            image_reference=f"{REPO}@{DIGEST_A}",
            env={"KMS_KEY_NAME": "k", "DEBUG": "1"},
        )


def test_config_rejects_tag_as_enclave_digest() -> None:
    with pytest.raises(ConfigError):
        make_config(enclave_image_digest="latest")


def test_config_rejects_enclave_digest_outside_allowed_list() -> None:
    with pytest.raises(ConfigError, match="allowed_digests"):
        make_config(allowed_digests=[DIGEST_B])


def test_config_requires_at_least_one_allowed_digest() -> None:
    with pytest.raises(ConfigError):
        make_config(allowed_digests=[], deploy_workloads=False)


def test_config_rejects_malformed_allowed_digest() -> None:
    with pytest.raises(ConfigError):
        make_config(allowed_digests=[DIGEST_A, "sha256:short"])


@pytest.mark.parametrize("prefix", ["ab", "Carapace", "gcp-x", "a" * 21, "x_y"])
def test_config_rejects_bad_prefix(prefix: str) -> None:
    with pytest.raises(ConfigError):
        make_config(prefix=prefix)


def test_config_alerts_require_recipients() -> None:
    with pytest.raises(ConfigError):
        make_config(enable_iam_alerts=True, alert_emails=[])


def test_key_policy_refuses_non_principal_set_decrypter() -> None:
    with pytest.raises(ValueError, match="principalSet"):
        build_key_policy(["serviceAccount:x@example.com"], [])
