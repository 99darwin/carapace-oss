"""Config and pure-function validation (no resources declared)."""

import pytest

pytest.importorskip("pulumi_gcp")

from components.config import (  # noqa: E402
    ConfigError,
    StackConfig,
    build_image_reference,
    validate_control_plane_url,
)
from components.enclave_vm import build_enclave_metadata  # noqa: E402
from components.kms import build_key_policy  # noqa: E402
from components.server import build_database_url, build_server_url  # noqa: E402
from components.wif import (  # noqa: E402
    build_attribute_condition,
    build_provider_audience,
)
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


@pytest.mark.parametrize(
    "audience", ["", "https://sts.googleapis.com", "carapace-attestation"]
)
def test_config_rejects_exchangeable_public_audiences(audience: str) -> None:
    with pytest.raises(ConfigError):
        make_config(wif_audience=audience)


@pytest.mark.parametrize(
    "audience", ["https://sts.googleapis.com", "carapace-attestation"]
)
def test_attribute_condition_refuses_public_audiences(audience: str) -> None:
    with pytest.raises(ValueError, match="never be accepted"):
        build_attribute_condition(
            project_id="example-project",
            enclave_sa_email="e@example-project.iam.gserviceaccount.com",
            allowed_digests=["sha256:" + "a" * 64],
            audience=audience,
            control_plane_url="https://api.example.com",
        )


def test_config_rejects_wif_audience_equal_to_control_plane_url() -> None:
    url = "https://api.example.com"
    with pytest.raises(ConfigError, match="enclave-to-server"):
        make_config(wif_audience=url, control_plane_url=url)
    assert make_config(wif_audience="carapace-sts-test", control_plane_url=url)


def test_attribute_condition_refuses_the_server_audience() -> None:
    """Covers the derived server URL, which the config cannot see."""
    with pytest.raises(ValueError, match="enclave-to-server"):
        build_attribute_condition(
            project_id="example-project",
            enclave_sa_email="e@example-project.iam.gserviceaccount.com",
            allowed_digests=["sha256:" + "a" * 64],
            audience="https://cptest-server-42.us-central1.run.app",
            control_plane_url="https://cptest-server-42.us-central1.run.app",
        )


def test_attribute_condition_requires_a_control_plane_url() -> None:
    with pytest.raises(ValueError, match="control_plane_url"):
        build_attribute_condition(
            project_id="example-project",
            enclave_sa_email="e@example-project.iam.gserviceaccount.com",
            allowed_digests=["sha256:" + "a" * 64],
            audience="carapace-sts-test",
            control_plane_url="",
        )


def test_provider_audience_is_the_provider_resource_name() -> None:
    assert build_provider_audience(project_number="42", pool_id="p-attest") == (
        "//iam.googleapis.com/projects/42/locations/global"
        "/workloadIdentityPools/p-attest/providers/confidential-space"
    )


def test_iam_alerts_are_on_by_default() -> None:
    assert StackConfig.__dataclass_fields__["enable_iam_alerts"].default is True
    with pytest.raises(ConfigError, match="alert_emails"):
        make_config(alert_emails=[])
    assert make_config(enable_iam_alerts=False, alert_emails=[])


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.com",
        "https://api.example.com/",
        "https://api.example.com/v1",
        "https://API.example.com",
        "https://user@api.example.com",
        "https://api.example.com?x=1",
        "https://api.example.com'",
        "",
    ],
)
def test_config_rejects_non_origin_control_plane_url(url: str) -> None:
    with pytest.raises(ConfigError, match="control_plane_url"):
        make_config(control_plane_url=url)


@pytest.mark.parametrize(
    "url", ["https://api.example.com", "https://api.example.com:8443"]
)
def test_config_accepts_bare_https_origin(url: str) -> None:
    assert validate_control_plane_url(url) == url
    assert make_config(control_plane_url=url).control_plane_url == url


def test_database_url_uses_the_cloud_sql_socket_and_quotes_the_password() -> None:
    url = build_database_url(password="p@ss/w:rd", connection_name="p:r:i")
    assert url == (
        "postgresql+asyncpg://carapace:p%40ss%2Fw%3Ard@/carapace?host=/cloudsql/p:r:i"
    )


def test_server_url_is_cloud_runs_deterministic_url() -> None:
    assert build_server_url(
        service_name="carapace-server", project_number="42", region="us-central1"
    ) == ("https://carapace-server-42.us-central1.run.app")
