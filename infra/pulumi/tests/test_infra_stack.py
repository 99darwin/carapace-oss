"""Security properties of the full stack, asserted against Pulumi mocks."""

import json

import pytest

pytest.importorskip("pulumi_gcp")

from components.wif import build_principal_set  # noqa: E402
from harness import (  # noqa: E402
    CONFIDENTIAL_SPACE_IMAGE,
    DIGEST_A,
    DIGEST_B,
    ENCLAVE_SA_UNIQUE_ID,
    PROJECT_ID,
    PROJECT_NUMBER,
    Recorded,
    RecordingMocks,
    make_config,
    run_stack,
)

KEY_POLICY = "gcp:kms/cryptoKeyIAMPolicy:CryptoKeyIAMPolicy"
PROJECT_IAM = "gcp:projects/iAMMember:IAMMember"
INSTANCE = "gcp:compute/instance:Instance"
FIREWALL = "gcp:compute/firewall:Firewall"
PROVIDER = "gcp:iam/workloadIdentityPoolProvider:WorkloadIdentityPoolProvider"
ENCLAVE_MEMBER = f"serviceAccount:cptest-enclave@{PROJECT_ID}.iam.gserviceaccount.com"
SERVER_MEMBER = f"serviceAccount:cptest-server@{PROJECT_ID}.iam.gserviceaccount.com"
STS_AUDIENCE = (
    "//iam.googleapis.com/projects/123456789012/locations/global"
    "/workloadIdentityPools/cptest-attest/providers/confidential-space"
)
KEY_RING_ID = "projects/example-project/locations/us-central1/keyRings/cptest-keyring"


@pytest.fixture(scope="module")
def stack() -> tuple[RecordingMocks, dict]:
    return run_stack(make_config())


def _key_bindings(mocks: RecordingMocks) -> dict[str, list[str]]:
    policy = json.loads(mocks.one(KEY_POLICY).inputs["policyData"])
    return {b["role"]: b["members"] for b in policy["bindings"]}


def _iam_grants(mocks: RecordingMocks) -> list[tuple[str, str]]:
    """Every (role, member) pair declared anywhere in the stack."""
    grants = [
        (r.inputs["role"], r.inputs["member"])
        for r in mocks.resources
        if "role" in r.inputs and "member" in r.inputs
    ]
    for role, members in _key_bindings(mocks).items():
        grants.extend((role, member) for member in members)
    return grants


def test_kms_key_is_hsm_asymmetric_decrypt(stack) -> None:
    mocks, _ = stack
    key = mocks.one("gcp:kms/cryptoKey:CryptoKey").inputs
    assert key["purpose"] == "ASYMMETRIC_DECRYPT"
    assert key["versionTemplate"] == {
        "algorithm": "RSA_DECRYPT_OAEP_4096_SHA256",
        "protectionLevel": "HSM",
    }


def test_decrypter_is_only_the_digest_principal_sets(stack) -> None:
    mocks, outputs = stack
    expected = sorted(
        build_principal_set(
            project_number=PROJECT_NUMBER, pool_id="cptest-attest", digest=digest
        )
        for digest in (DIGEST_A, DIGEST_B)
    )
    literal_a = (
        "principalSet://iam.googleapis.com/projects/123456789012/locations/global"
        "/workloadIdentityPools/cptest-attest/attribute.image_digest/sha256:" + "a" * 64
    )
    assert literal_a in expected
    bindings = _key_bindings(mocks)
    assert bindings["roles/cloudkms.cryptoKeyDecrypter"] == expected
    assert sorted(outputs["wif_principal_sets"]) == expected
    decrypt_grants = [
        member
        for role, member in _iam_grants(mocks)
        if role
        in {
            "roles/cloudkms.cryptoKeyDecrypter",
            "roles/cloudkms.cryptoKeyEncrypterDecrypter",
        }
    ]
    assert sorted(decrypt_grants) == expected
    assert not mocks.of_type("gcp:kms/cryptoKeyIAMMember:CryptoKeyIAMMember")
    assert not mocks.of_type("gcp:kms/cryptoKeyIAMBinding:CryptoKeyIAMBinding")


def test_key_policy_has_no_other_bindings(stack) -> None:
    mocks, _ = stack
    bindings = _key_bindings(mocks)
    assert set(bindings) == {
        "roles/cloudkms.cryptoKeyDecrypter",
        "roles/cloudkms.publicKeyViewer",
    }
    assert bindings["roles/cloudkms.publicKeyViewer"] == [SERVER_MEMBER]


def test_server_sa_has_no_decrypt_role(stack) -> None:
    mocks, _ = stack
    server_roles = {role for role, m in _iam_grants(mocks) if m == SERVER_MEMBER}
    assert server_roles == {
        "roles/cloudkms.publicKeyViewer",
        "roles/cloudsql.client",
        "roles/secretmanager.secretAccessor",
    }


def test_enclave_sa_has_no_kms_role(stack) -> None:
    mocks, _ = stack
    enclave_roles = {role for role, m in _iam_grants(mocks) if m == ENCLAVE_MEMBER}
    assert enclave_roles == {
        "roles/logging.logWriter",
        "roles/artifactregistry.reader",
        "roles/confidentialcomputing.workloadUser",
    }
    assert not any("cloudkms" in role for role in enclave_roles)


def test_no_impersonation_grants(stack) -> None:
    mocks, _ = stack
    roles = {role for role, _ in _iam_grants(mocks)}
    assert "roles/iam.serviceAccountUser" not in roles
    assert "roles/iam.workloadIdentityUser" not in roles
    assert "roles/iam.serviceAccountTokenCreator" not in roles
    assert not mocks.of_type("gcp:serviceaccount/iAMMember:IAMMember")
    assert not mocks.of_type("gcp:serviceaccount/iAMBinding:IAMBinding")


def test_no_authoritative_project_iam(stack) -> None:
    mocks, _ = stack
    assert not mocks.of_type("gcp:projects/iAMBinding:IAMBinding")
    assert not mocks.of_type("gcp:projects/iAMPolicy:IAMPolicy")


def test_key_ring_policy_is_authoritative_and_empty(stack) -> None:
    mocks, _ = stack
    ring_policy = mocks.one("gcp:kms/keyRingIAMPolicy:KeyRingIAMPolicy").inputs
    assert json.loads(ring_policy["policyData"]) == {"bindings": []}
    assert ring_policy["keyRingId"] == KEY_RING_ID
    assert not mocks.of_type("gcp:kms/keyRingIAMMember:KeyRingIAMMember")
    assert not mocks.of_type("gcp:kms/keyRingIAMBinding:KeyRingIAMBinding")


def test_wif_condition_requires_every_attestation_clause(stack) -> None:
    mocks, _ = stack
    provider = mocks.one(PROVIDER).inputs
    condition = provider["attributeCondition"]
    for clause in (
        "assertion.swname == 'CONFIDENTIAL_SPACE'",
        "assertion.hwmodel == 'GCP_AMD_SEV'",
        "assertion.dbgstat == 'disabled-since-boot'",
        "assertion.secboot == true",
        "'STABLE' in assertion.submods.confidential_space.support_attributes",
        f"assertion.submods.gce.project_id == '{PROJECT_ID}'",
        f"assertion.submods.container.image_digest in ['{DIGEST_A}', '{DIGEST_B}']",
        f"'cptest-enclave@{PROJECT_ID}.iam.gserviceaccount.com'"
        " in assertion.google_service_accounts",
    ):
        assert clause in condition
    assert condition.startswith(f"assertion.aud == '{STS_AUDIENCE}' && ")
    assert "||" not in condition
    assert provider["oidc"]["issuerUri"] == (
        "https://confidentialcomputing.googleapis.com"
    )
    assert provider["attributeMapping"]["attribute.image_digest"] == (
        "assertion.submods.container.image_digest"
    )


def test_wif_accepts_only_the_stack_audience(stack) -> None:
    mocks, outputs = stack
    allowed = mocks.one(PROVIDER).inputs["oidc"]["allowedAudiences"]
    assert allowed == [STS_AUDIENCE]
    assert "https://sts.googleapis.com" not in allowed
    assert "carapace-attestation" not in allowed
    assert outputs["wif_audience"] == STS_AUDIENCE


def test_wif_audience_override_is_used_verbatim() -> None:
    mocks, outputs = run_stack(make_config(wif_audience="carapace-sts-selfhost"))
    provider = mocks.one(PROVIDER).inputs
    assert provider["oidc"]["allowedAudiences"] == ["carapace-sts-selfhost"]
    assert "assertion.aud == 'carapace-sts-selfhost'" in provider["attributeCondition"]
    assert outputs["wif_audience"] == "carapace-sts-selfhost"


def test_firewall_allows_only_443(stack) -> None:
    mocks, _ = stack
    firewall = mocks.one(FIREWALL).inputs
    assert firewall["direction"] == "INGRESS"
    assert firewall["allows"] == [{"protocol": "tcp", "ports": ["443"]}]
    assert "denies" not in firewall
    instance = mocks.one(INSTANCE).inputs
    assert firewall["targetTags"] == instance["tags"]


def test_vm_is_confidential_space_with_digest_pinned_image(stack) -> None:
    mocks, _ = stack
    instance = mocks.one(INSTANCE).inputs
    assert instance["confidentialInstanceConfig"] == {"confidentialInstanceType": "SEV"}
    assert instance["shieldedInstanceConfig"]["enableSecureBoot"] is True
    image = instance["bootDisk"]["initializeParams"]["image"]
    assert image == CONFIDENTIAL_SPACE_IMAGE
    metadata = instance["metadata"]
    assert metadata["tee-image-reference"].endswith(f"/enclave@{DIGEST_A}")
    env_keys = {k for k in metadata if k.startswith("tee-env-")}
    assert env_keys == {
        "tee-env-CONTROL_PLANE_URL",
        "tee-env-KMS_KEY_NAME",
        "tee-env-WIF_AUDIENCE",
    }
    assert metadata["tee-env-KMS_KEY_NAME"].endswith("/cryptoKeyVersions/1")
    assert metadata["tee-env-WIF_AUDIENCE"] == STS_AUDIENCE


def test_database_password_never_in_outputs(stack) -> None:
    mocks, outputs = stack
    assert "mock-password" not in json.dumps(outputs, default=str)
    service = mocks.one("gcp:cloudrunv2/service:Service").inputs
    envs = service["template"]["containers"][0]["envs"]
    password_env = next(e for e in envs if e["name"] == "DB_PASSWORD")
    assert "value" not in password_env
    assert "secretKeyRef" in password_env["valueSource"]


def test_server_runs_by_digest_and_scales_to_zero(stack) -> None:
    mocks, _ = stack
    template = mocks.one("gcp:cloudrunv2/service:Service").inputs["template"]
    assert "@sha256:" in template["containers"][0]["image"]
    assert template["scaling"]["minInstanceCount"] == 0
    envs = {e["name"]: e.get("value") for e in template["containers"][0]["envs"]}
    assert envs["CARAPACE_MODE"] == "prod"
    assert envs["ALLOWED_IMAGE_DIGESTS"] == f"{DIGEST_A},{DIGEST_B}"


def test_cloud_sql_is_small_and_zonal(stack) -> None:
    mocks, _ = stack
    settings = mocks.one("gcp:sql/databaseInstance:DatabaseInstance").inputs["settings"]
    assert settings["tier"] == "db-f1-micro"
    assert settings["availabilityType"] == "ZONAL"
    assert settings["ipConfiguration"].get("authorizedNetworks") in (None, [])


def test_iam_change_alert_watches_decrypt_path(stack) -> None:
    mocks, outputs = stack
    policy = mocks.one("gcp:monitoring/alertPolicy:AlertPolicy").inputs
    log_filter = policy["conditions"][0]["conditionMatchedLog"]["filter"]
    assert '"SetIamPolicy"' in log_filter
    # The key ring path is a prefix of the key path, so both are matched.
    assert f'protoPayload.resourceName:"{KEY_RING_ID}"' in log_filter
    assert outputs["kms_key_name"].startswith(KEY_RING_ID + "/")
    assert 'resourceName:"workloadIdentityPools/cptest-attest"' in log_filter
    enclave_email = ENCLAVE_MEMBER.removeprefix("serviceAccount:")
    assert f'resourceName:"serviceAccounts/{enclave_email}"' in log_filter
    assert f'resourceName:"serviceAccounts/{ENCLAVE_SA_UNIQUE_ID}"' in log_filter


def _resources(**overrides: object) -> list[Recorded]:
    mocks, _ = run_stack(make_config(**overrides))
    return mocks.resources


def test_alerts_are_optional() -> None:
    types = {r.typ for r in _resources(enable_iam_alerts=False, alert_emails=[])}
    assert "gcp:monitoring/alertPolicy:AlertPolicy" not in types


def test_bootstrap_mode_skips_workloads() -> None:
    types = {
        r.typ
        for r in _resources(
            deploy_workloads=False, enclave_image_digest="", server_image_digest=""
        )
    }
    assert INSTANCE not in types
    assert "gcp:cloudrunv2/service:Service" not in types
    assert KEY_POLICY in types


def test_digest_rollover_binds_each_digest() -> None:
    mocks, _ = run_stack(make_config(allowed_digests=[DIGEST_A]))
    members = _key_bindings(mocks)["roles/cloudkms.cryptoKeyDecrypter"]
    assert len(members) == 1
    assert members[0].endswith(f"/attribute.image_digest/{DIGEST_A}")


@pytest.mark.parametrize("protect", [True, False])
def test_kms_key_protect_option_follows_config(monkeypatch, protect: bool) -> None:
    import pulumi_gcp as gcp

    seen: list[bool] = []
    original = gcp.kms.CryptoKey

    def recording_crypto_key(*args, opts=None, **kwargs):
        seen.append(bool(opts and opts.protect))
        return original(*args, opts=opts, **kwargs)

    monkeypatch.setattr(gcp.kms, "CryptoKey", recording_crypto_key)
    run_stack(make_config(protect_kms_key=protect))
    assert seen == [protect]
    assert make_config().protect_kms_key is True


def _record_depends_on(monkeypatch, module, cls_name: str) -> list[list]:
    seen: list[list] = []
    original = getattr(module, cls_name)

    def recording(*args, opts=None, **kwargs):
        seen.append(list(opts.depends_on or []) if opts else [])
        return original(*args, opts=opts, **kwargs)

    monkeypatch.setattr(module, cls_name, recording)
    return seen


def test_workloads_wait_for_their_iam(monkeypatch) -> None:
    import pulumi_gcp as gcp

    grants: list = []
    key_policies: list = []
    original_member = gcp.projects.IAMMember
    original_policy = gcp.kms.CryptoKeyIAMPolicy

    def recording_member(name, *args, **kwargs):
        resource = original_member(name, *args, **kwargs)
        grants.append((kwargs.get("role"), resource))
        return resource

    def recording_policy(*args, **kwargs):
        resource = original_policy(*args, **kwargs)
        key_policies.append(resource)
        return resource

    monkeypatch.setattr(gcp.projects, "IAMMember", recording_member)
    monkeypatch.setattr(gcp.kms, "CryptoKeyIAMPolicy", recording_policy)
    vm_deps = _record_depends_on(monkeypatch, gcp.compute, "Instance")
    run_deps = _record_depends_on(monkeypatch, gcp.cloudrunv2, "Service")
    run_stack(make_config())

    by_role = {role: resource for role, resource in grants}
    assert len(vm_deps) == 1 and len(run_deps) == 1
    assert by_role["roles/confidentialcomputing.workloadUser"] in vm_deps[0]
    assert key_policies[0] in vm_deps[0]
    assert by_role["roles/cloudsql.client"] in run_deps[0]
