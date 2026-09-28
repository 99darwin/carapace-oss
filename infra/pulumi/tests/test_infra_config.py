"""Config and pure-function validation (no resources declared)."""

import json
from dataclasses import dataclass

import pytest

pytest.importorskip("pulumi_gcp")

from components.config import (  # noqa: E402
    ConfigError,
    StackConfig,
    build_image_reference,
    validate_boot_image,
    validate_control_plane_url,
)
from components.enclave_vm import (  # noqa: E402
    ALLOWED_ENV_OVERRIDES,
    build_enclave_metadata,
)
from components.kms import (  # noqa: E402
    KEY_ALGORITHM,
    KmsPublicKeyError,
    build_key_policy,
    select_public_key_pem,
)
from components.server import build_database_url, build_server_url  # noqa: E402
from components.wif import (  # noqa: E402
    build_attribute_condition,
    build_provider_audience,
)
from harness import DIGEST_A, DIGEST_B, make_config  # noqa: E402

REPO = "us-docker.pkg.dev/example-project/carapace/enclave"
KMS_KEY_VERSION = (
    "projects/example-project/locations/us-central1/keyRings/k"
    "/cryptoKeys/c/cryptoKeyVersions/1"
)


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


def test_key_policy_makes_every_decrypter_a_public_key_viewer() -> None:
    decrypter = "principalSet://iam.googleapis.com/projects/1/x/" + DIGEST_A
    server = "serviceAccount:server@example.com"
    policy = json.loads(build_key_policy([decrypter], [server]))
    bindings = {b["role"]: b["members"] for b in policy["bindings"]}
    assert bindings == {
        "roles/cloudkms.cryptoKeyDecrypter": [decrypter],
        "roles/cloudkms.publicKeyViewer": sorted([decrypter, server]),
    }


def test_key_policy_refuses_non_principal_set_decrypter() -> None:
    with pytest.raises(ValueError, match="principalSet"):
        build_key_policy(["serviceAccount:x@example.com"], [])


PRINCIPAL_SET = "principalSet://iam.googleapis.com/projects/1/x/" + DIGEST_A


@pytest.mark.parametrize("viewer", ["allUsers", "allAuthenticatedUsers"])
def test_key_policy_refuses_public_viewers(viewer: str) -> None:
    with pytest.raises(ValueError, match="must not be public"):
        build_key_policy([PRINCIPAL_SET], [viewer])


@pytest.mark.parametrize(
    "viewer",
    [
        "",
        "server@example.com",
        "serviceAccount:",
        "serviceAccount:server",
        "serviceAccount:server@example.com ",
        "serviceAccount: server@example.com",
        "serviceAccount:a@b@example.com",
        "domain:example.com",
        "deleted:serviceAccount:server@example.com?uid=1",
        "principal://iam.googleapis.com/projects/1/x",
        "principalSet://",
        "principalSet://evil.example.com/projects/1/x",
        "allusers",
        None,
    ],
)
def test_key_policy_refuses_malformed_viewers(viewer: object) -> None:
    with pytest.raises(ValueError, match="viewer"):
        build_key_policy([PRINCIPAL_SET], [viewer])


def test_key_policy_refuses_malformed_decrypter() -> None:
    with pytest.raises(ValueError, match="principalSet"):
        build_key_policy(["principalSet://"], [])


@pytest.mark.parametrize(
    "viewer",
    [
        "serviceAccount:cptest-server@example-project.iam.gserviceaccount.com",
        "user:ops@example.com",
        "group:kms-viewers@example.com",
    ],
)
def test_key_policy_accepts_single_identity_viewers(viewer: str) -> None:
    policy = json.loads(build_key_policy([PRINCIPAL_SET], [viewer]))
    bindings = {b["role"]: b["members"] for b in policy["bindings"]}
    assert viewer in bindings["roles/cloudkms.publicKeyViewer"]


KEY_VERSION = (
    "projects/example-project/locations/us-central1/keyRings/r"
    "/cryptoKeys/k/cryptoKeyVersions/1"
)
PEM = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"


@dataclass(frozen=True)
class _PublicKey:
    pem: str
    algorithm: str = KEY_ALGORITHM


def _select(**overrides: object) -> str:
    args: dict[str, object] = {
        "name": KEY_VERSION,
        "algorithm": KEY_ALGORITHM,
        "public_keys": [_PublicKey(PEM)],
        "expected_name": KEY_VERSION,
    }
    args.update(overrides)
    return select_public_key_pem(**args)


def test_public_key_pem_is_taken_from_the_expected_version() -> None:
    assert _select() == PEM


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"name": KEY_VERSION.replace("/1", "/2")}, "expected"),
        ({"algorithm": "RSA_DECRYPT_OAEP_2048_SHA256"}, "algorithm"),
        ({"public_keys": []}, "no public key"),
        ({"public_keys": [_PublicKey(PEM), _PublicKey(PEM)]}, "no public key"),
        ({"public_keys": [_PublicKey("not a pem")]}, "not a PEM"),
        ({"public_keys": [object()]}, "not a PEM"),
    ],
)
def test_public_key_pem_fails_closed(overrides: dict, match: str) -> None:
    with pytest.raises(KmsPublicKeyError, match=match):
        _select(**overrides)


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
            kms_key_name=KMS_KEY_VERSION,
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
            kms_key_name=KMS_KEY_VERSION,
        )


def test_attribute_condition_requires_a_control_plane_url() -> None:
    with pytest.raises(ValueError, match="control_plane_url"):
        build_attribute_condition(
            project_id="example-project",
            enclave_sa_email="e@example-project.iam.gserviceaccount.com",
            allowed_digests=["sha256:" + "a" * 64],
            audience="carapace-sts-test",
            control_plane_url="",
            kms_key_name=KMS_KEY_VERSION,
        )


def test_attribute_condition_requires_a_kms_key() -> None:
    with pytest.raises(ValueError, match="kms_key_name"):
        build_attribute_condition(
            project_id="example-project",
            enclave_sa_email="e@example-project.iam.gserviceaccount.com",
            allowed_digests=["sha256:" + "a" * 64],
            audience="carapace-sts-test",
            control_plane_url="https://api.example.com",
            kms_key_name="",
        )


def test_attribute_condition_pins_every_launch_override() -> None:
    condition = build_attribute_condition(
        project_id="example-project",
        enclave_sa_email="e@example-project.iam.gserviceaccount.com",
        allowed_digests=["sha256:" + "a" * 64],
        audience="carapace-sts-test",
        control_plane_url="https://api.example.com",
        kms_key_name=KMS_KEY_VERSION,
    )
    env = "assertion.submods.container.env"
    for name in sorted(ALLOWED_ENV_OVERRIDES):
        assert f"{env}.{name} == '" in condition
    assert f"{env}.KMS_KEY_NAME == '{KMS_KEY_VERSION}'" in condition
    assert f"{env}.WIF_AUDIENCE == 'carapace-sts-test'" in condition


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


BOOT_IMAGE = (
    "https://www.googleapis.com/compute/v1/projects/confidential-space-images"
    "/global/images/confidential-space-251000"
)


@pytest.mark.parametrize(
    "image",
    [
        BOOT_IMAGE,
        "projects/confidential-space-images/global/images/confidential-space-251000",
    ],
)
def test_boot_image_accepts_confidential_space_images(image: str) -> None:
    assert validate_boot_image(image) == image
    assert make_config(boot_image=image).boot_image == image


@pytest.mark.parametrize(
    "image",
    [
        "",
        BOOT_IMAGE.replace("confidential-space-images", "attacker-project"),
        "projects/attacker/global/images/confidential-space-251000",
        BOOT_IMAGE.replace("confidential-space-251000", "confidential-space-debug-1"),
        BOOT_IMAGE.replace("https://www.googleapis.com", "https://evil.example"),
        BOOT_IMAGE + "/../../../../other/global/images/x",
        "projects/confidential-space-images/global/images/family/confidential-space",
        BOOT_IMAGE + "\n",
    ],
)
def test_boot_image_refuses_anything_else(image: str) -> None:
    with pytest.raises(ConfigError, match="boot_image"):
        validate_boot_image(image)
    with pytest.raises(ConfigError, match="boot_image"):
        make_config(boot_image=image)
