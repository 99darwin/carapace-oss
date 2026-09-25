"""Security properties of the full stack, asserted against Pulumi mocks."""

import ast
import json
from pathlib import Path

import pytest

pytest.importorskip("pulumi_gcp")

import pulumi  # noqa: E402

from components.enclave_vm import INGRESS_PORT  # noqa: E402
from components.wif import build_principal_set  # noqa: E402
from harness import (  # noqa: E402
    CONFIDENTIAL_SPACE_IMAGE,
    DIGEST_A,
    DIGEST_B,
    ENCLAVE_SA_UNIQUE_ID,
    GET_KEY_VERSION_TOKEN,
    KMS_PUBLIC_KEY_PEM,
    PROJECT_ID,
    PROJECT_NUMBER,
    STATIC_IP,
    Recorded,
    RecordingMocks,
    make_config,
    run_stack,
)

KEY_POLICY = "gcp:kms/cryptoKeyIAMPolicy:CryptoKeyIAMPolicy"
KEY_RING_POLICY = "gcp:kms/keyRingIAMPolicy:KeyRingIAMPolicy"
# The only authoritative policies the stack may declare; both are parsed.
AUTHORITATIVE_POLICIES = frozenset({KEY_POLICY, KEY_RING_POLICY})
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
SERVER_URL = f"https://cptest-server-{PROJECT_NUMBER}.us-central1.run.app"
REPOSITORY_IAM = "gcp:artifactregistry/repositoryIamMember:RepositoryIamMember"
# Pulumi's wire encoding of a secret value: {SECRET_SIG: SECRET_SIG_VALUE, ...}.
SECRET_SIG = pulumi.runtime.rpc._special_sig_key
SECRET_SIG_VALUE = pulumi.runtime.rpc._special_secret_sig
DECRYPT_ROLES = frozenset(
    {"roles/cloudkms.cryptoKeyDecrypter", "roles/cloudkms.cryptoKeyEncrypterDecrypter"}
)
ENCLAVE_RUNTIME = (
    Path(__file__).resolve().parents[3]
    / "enclave"
    / "src"
    / "carapace_enclave"
    / "runtime.py"
)


@pytest.fixture(scope="module")
def stack() -> tuple[RecordingMocks, dict]:
    return run_stack(make_config())


def _key_bindings(mocks: RecordingMocks) -> dict[str, list[str]]:
    policy = json.loads(mocks.one(KEY_POLICY).inputs["policyData"])
    return {b["role"]: b["members"] for b in policy["bindings"]}


def _policy_grants(resource: Recorded) -> list[tuple[str, str]]:
    policy = json.loads(resource.inputs["policyData"])
    return [
        (binding["role"], member)
        for binding in policy["bindings"]
        for member in binding["members"]
    ]


def _iam_grants(mocks: RecordingMocks) -> list[tuple[str, str]]:
    """Every (role, member) pair declared anywhere in the stack.

    Fails closed: a grant shape this function cannot enumerate (a plural
    ``members`` binding, or any authoritative policy other than the two KMS
    policies) is an error, never silently skipped, so the tests built on it
    cannot miss a grant.
    """
    grants: list[tuple[str, str]] = []
    for resource in mocks.resources:
        label = f"{resource.typ} ({resource.name})"
        lowered = resource.typ.lower()
        is_policy = "policyData" in resource.inputs or "iampolicy" in lowered
        if "members" in resource.inputs or "iambinding" in lowered:
            raise AssertionError(f"plural-members IAM binding: {label}")
        if is_policy:
            if resource.typ not in AUTHORITATIVE_POLICIES:
                raise AssertionError(f"unexpected authoritative IAM policy: {label}")
            grants.extend(_policy_grants(resource))
            continue
        has_role, has_member = "role" in resource.inputs, "member" in resource.inputs
        if has_role != has_member:
            raise AssertionError(f"IAM grant without a single member: {label}")
        if has_role:
            grants.append((resource.inputs["role"], resource.inputs["member"]))
    return grants


def _mocks_with(*resources: Recorded) -> RecordingMocks:
    mocks = RecordingMocks()
    mocks.resources.extend(resources)
    return mocks


def test_iam_grants_include_both_authoritative_kms_policies() -> None:
    policy = json.dumps({"bindings": [{"role": "r", "members": ["a", "b"]}]})
    mocks = _mocks_with(
        Recorded(KEY_POLICY, "key", {"policyData": policy}),
        Recorded(KEY_RING_POLICY, "ring", {"policyData": policy}),
        Recorded(PROJECT_IAM, "member", {"role": "s", "member": "c"}),
    )
    assert sorted(_iam_grants(mocks)) == [
        ("r", "a"),
        ("r", "a"),
        ("r", "b"),
        ("r", "b"),
        ("s", "c"),
    ]


@pytest.mark.parametrize(
    "resource",
    [
        Recorded("gcp:kms/cryptoKeyIAMBinding:CryptoKeyIAMBinding", "b", {}),
        Recorded("gcp:projects/iAMBinding:IAMBinding", "b", {"role": "r"}),
        Recorded(
            "gcp:storage/bucketIAMBinding:BucketIAMBinding",
            "b",
            {"role": "r", "members": ["x"]},
        ),
        Recorded("gcp:example/thing:Thing", "b", {"role": "r", "members": ["x"]}),
        Recorded(
            "gcp:projects/iAMPolicy:IAMPolicy", "p", {"policyData": '{"bindings":[]}'}
        ),
        Recorded(
            "gcp:secretmanager/secretIamPolicy:SecretIamPolicy",
            "p",
            {"policyData": '{"bindings":[]}'},
        ),
        Recorded("gcp:serviceaccount/iAMPolicy:IAMPolicy", "p", {}),
        Recorded(PROJECT_IAM, "m", {"role": "r"}),
    ],
    ids=lambda r: f"{r.typ}:{sorted(r.inputs)}",
)
def test_iam_grants_fail_closed_on_unknown_grant_shapes(resource: Recorded) -> None:
    with pytest.raises(AssertionError, match="IAM"):
        _iam_grants(_mocks_with(resource))


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
    decrypters = bindings["roles/cloudkms.cryptoKeyDecrypter"]
    assert bindings["roles/cloudkms.publicKeyViewer"] == sorted(
        [*decrypters, SERVER_MEMBER]
    )


def test_attested_enclave_can_read_the_public_key(stack) -> None:
    """The boot self-test calls GetPublicKey with the enclave's federated
    credentials, so every attested principalSet must hold publicKeyViewer."""
    mocks, outputs = stack
    viewers = _key_bindings(mocks)["roles/cloudkms.publicKeyViewer"]
    principal_sets = sorted(outputs["wif_principal_sets"])
    assert len(principal_sets) == 2
    for principal_set in principal_sets:
        assert principal_set in viewers
    # No other federated principal and no VM service account is a viewer.
    assert sorted(set(viewers) - {SERVER_MEMBER}) == principal_sets
    assert ENCLAVE_MEMBER not in viewers


def test_public_key_viewers_follow_digest_rollover() -> None:
    mocks, _ = run_stack(make_config(allowed_digests=[DIGEST_A]))
    bindings = _key_bindings(mocks)
    (principal_set,) = bindings["roles/cloudkms.cryptoKeyDecrypter"]
    assert principal_set.endswith(f"/attribute.image_digest/{DIGEST_A}")
    assert bindings["roles/cloudkms.publicKeyViewer"] == sorted(
        [principal_set, SERVER_MEMBER]
    )


def test_no_service_account_can_decrypt(stack) -> None:
    mocks, _ = stack
    for member in (SERVER_MEMBER, ENCLAVE_MEMBER):
        roles = {role for role, m in _iam_grants(mocks) if m == member}
        assert not roles & DECRYPT_ROLES, member


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


def _enclave_listen_port() -> int:
    """ENCLAVE_PORT from the enclave runtime, read without importing it (the
    infra venv does not install the enclave package)."""
    assert ENCLAVE_RUNTIME.is_file(), f"enclave runtime not found: {ENCLAVE_RUNTIME}"
    tree = ast.parse(ENCLAVE_RUNTIME.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "ENCLAVE_PORT" for t in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError("ENCLAVE_PORT not found in the enclave runtime")


def test_infra_port_matches_enclave_listen_port() -> None:
    assert INGRESS_PORT == _enclave_listen_port() == 8443


def test_firewall_allows_only_the_enclave_port(stack) -> None:
    mocks, _ = stack
    firewall = mocks.one(FIREWALL).inputs
    assert firewall["direction"] == "INGRESS"
    assert firewall["allows"] == [{"protocol": "tcp", "ports": ["8443"]}]
    assert "denies" not in firewall
    # Reachable from anywhere by design: authorization is the API key and
    # the attested TLS pin, not the network. Pinned so a change is a diff.
    assert firewall["sourceRanges"] == ["0.0.0.0/0"]
    assert "sourceTags" not in firewall
    assert "sourceServiceAccounts" not in firewall
    instance = mocks.one(INSTANCE).inputs
    assert firewall["targetTags"] == instance["tags"]
    # No second path in: one VPC rule and no hierarchical or network policies.
    assert not [r for r in mocks.resources if "FirewallPolicy" in r.typ]


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


def _server_env(mocks: RecordingMocks) -> dict[str, str | None]:
    template = mocks.one("gcp:cloudrunv2/service:Service").inputs["template"]
    return {e["name"]: e.get("value") for e in template["containers"][0]["envs"]}


def test_generated_secrets_never_in_outputs_or_plain_env(stack) -> None:
    mocks, outputs = stack
    assert "mock-password" not in json.dumps(outputs, default=str)
    service = mocks.one("gcp:cloudrunv2/service:Service").inputs
    envs = service["template"]["containers"][0]["envs"]
    assert "mock-password" not in json.dumps(envs)
    by_name = {e["name"]: e for e in envs}
    secret_ids = {}
    for name in ("CARAPACE_DATABASE_URL", "CARAPACE_JWT_SECRET"):
        assert "value" not in by_name[name]
        secret_ids[name] = by_name[name]["valueSource"]["secretKeyRef"]["secret"]
    assert secret_ids == {
        "CARAPACE_DATABASE_URL": "cptest-database-url",
        "CARAPACE_JWT_SECRET": "cptest-jwt-secret",
    }


def test_secrets_are_readable_only_by_the_server(stack) -> None:
    mocks, _ = stack
    accessors = mocks.of_type("gcp:secretmanager/secretIamMember:SecretIamMember")
    assert sorted(a.inputs["secretId"] for a in accessors) == [
        f"projects/{PROJECT_ID}/secrets/cptest-database-url",
        f"projects/{PROJECT_ID}/secrets/cptest-jwt-secret",
    ]
    assert {a.inputs["member"] for a in accessors} == {SERVER_MEMBER}
    assert {a.inputs["role"] for a in accessors} == {
        "roles/secretmanager.secretAccessor"
    }


def test_database_url_secret_targets_the_cloud_sql_socket(stack) -> None:
    mocks, _ = stack
    versions = mocks.of_type("gcp:secretmanager/secretVersion:SecretVersion")
    assert len(versions) == 2
    # Every secret value reaches the engine wrapped as a Pulumi secret.
    assert all(
        v.inputs["secretData"].get(SECRET_SIG) == SECRET_SIG_VALUE for v in versions
    )
    database_url = next(
        v.inputs["secretData"]["value"]
        for v in versions
        if v.inputs["secret"].endswith("/cptest-database-url")
    )
    assert database_url == (
        "postgresql+asyncpg://carapace:mock-password@/carapace"
        f"?host=/cloudsql/{PROJECT_ID}:region:db-instance"
    )


def test_server_runs_by_digest_and_scales_to_zero(stack) -> None:
    mocks, _ = stack
    template = mocks.one("gcp:cloudrunv2/service:Service").inputs["template"]
    assert "@sha256:" in template["containers"][0]["image"]
    assert template["scaling"]["minInstanceCount"] == 0
    envs = _server_env(mocks)
    assert envs["CARAPACE_MODE"] == "prod"
    assert envs["CARAPACE_ALLOWED_IMAGE_DIGESTS"] == f"{DIGEST_A},{DIGEST_B}"
    assert envs["CARAPACE_ATTESTATION_PROJECT_ID"] == PROJECT_ID
    assert envs["CARAPACE_ATTESTATION_SERVICE_ACCOUNT"] == (
        ENCLAVE_MEMBER.removeprefix("serviceAccount:")
    )


def test_server_advertises_the_enclaves_kms_key(stack) -> None:
    """``carapace verify`` compares /v1/kms/public-key with the key the
    attested enclave reports, so the server must name the same version."""
    mocks, outputs = stack
    envs = _server_env(mocks)
    metadata = mocks.one(INSTANCE).inputs["metadata"]
    key_version = metadata["tee-env-KMS_KEY_NAME"]
    assert envs["CARAPACE_KMS_KEY_VERSION"] == key_version
    assert key_version == outputs["kms_key_version_name"]
    assert key_version == (
        f"{KEY_RING_ID}/cryptoKeys/cptest-secrets/cryptoKeyVersions/1"
    )
    assert envs["CARAPACE_KMS_PUBLIC_KEY_PEM"] == KMS_PUBLIC_KEY_PEM
    (lookup,) = [c for c in mocks.calls if c.token == GET_KEY_VERSION_TOKEN]
    assert lookup.args == {
        "cryptoKey": outputs["kms_key_name"],
        "version": 1,
    }


def test_bootstrap_does_not_read_the_kms_public_key() -> None:
    mocks, _ = run_stack(
        make_config(
            deploy_workloads=False, enclave_image_digest="", server_image_digest=""
        )
    )
    assert not [c for c in mocks.calls if c.token == GET_KEY_VERSION_TOKEN]


def _pins_control_plane(condition: str, url: str) -> bool:
    return f"assertion.submods.container.env.CONTROL_PLANE_URL == '{url}'" in (
        condition
    )


def test_one_control_plane_url_everywhere(stack) -> None:
    mocks, outputs = stack
    metadata = mocks.one(INSTANCE).inputs["metadata"]
    condition = mocks.one(PROVIDER).inputs["attributeCondition"]
    assert _server_env(mocks)["CARAPACE_PUBLIC_URL"] == SERVER_URL
    assert metadata["tee-env-CONTROL_PLANE_URL"] == SERVER_URL
    assert _pins_control_plane(condition, SERVER_URL)
    assert outputs["server_url"] == outputs["control_plane_url"] == SERVER_URL


def test_control_plane_url_override_is_used_everywhere() -> None:
    url = "https://api.example.com"
    mocks, outputs = run_stack(make_config(control_plane_url=url))
    assert _server_env(mocks)["CARAPACE_PUBLIC_URL"] == url
    assert mocks.one(INSTANCE).inputs["metadata"]["tee-env-CONTROL_PLANE_URL"] == url
    assert _pins_control_plane(mocks.one(PROVIDER).inputs["attributeCondition"], url)
    assert outputs["control_plane_url"] == url


def test_bootstrap_still_pins_the_control_plane_url() -> None:
    mocks, _ = run_stack(
        make_config(
            deploy_workloads=False, enclave_image_digest="", server_image_digest=""
        )
    )
    condition = mocks.one(PROVIDER).inputs["attributeCondition"]
    assert _pins_control_plane(condition, SERVER_URL)


def test_kms_data_access_logs_are_enabled(stack) -> None:
    mocks, _ = stack
    audit = mocks.one("gcp:projects/iAMAuditConfig:IAMAuditConfig").inputs
    assert audit["service"] == "cloudkms.googleapis.com"
    assert audit["project"] == PROJECT_ID
    assert audit["auditLogConfigs"] == [{"logType": "DATA_READ"}]


def test_image_pull_is_scoped_to_the_stack_repository(stack) -> None:
    mocks, _ = stack
    project_roles = {r.inputs["role"] for r in mocks.of_type(PROJECT_IAM)}
    assert "roles/artifactregistry.reader" not in project_roles
    pull = mocks.one(REPOSITORY_IAM).inputs
    assert pull["role"] == "roles/artifactregistry.reader"
    assert pull["member"] == ENCLAVE_MEMBER
    assert pull["repository"] == "cptest"
    assert pull["location"] == "us-central1"
    assert pull["project"] == PROJECT_ID


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
    assert (
        '(protoPayload.serviceName="cloudkms.googleapis.com"'
        ' AND protoPayload.methodName="AsymmetricDecrypt"'
        f' AND protoPayload.resourceName:"{KEY_RING_ID}"'
        " AND NOT protoPayload.authenticationInfo.principalSubject:"
        f'"/projects/{PROJECT_NUMBER}/locations/global'
        '/workloadIdentityPools/cptest-attest/")'
    ) in log_filter
    # The alert's own blind spots: log routing and alerting configuration.
    assert (
        '(protoPayload.serviceName="logging.googleapis.com"'
        ' AND protoPayload.methodName:("Sink" OR "Exclusion" OR "Bucket"'
        ' OR "Settings"))'
    ) in log_filter
    assert (
        '(protoPayload.serviceName="monitoring.googleapis.com"'
        ' AND protoPayload.methodName:("AlertPolicy" OR "NotificationChannel"))'
    ) in log_filter


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
    dep_types = {type(dep).__name__ for dep in vm_deps[0]}
    assert {"RepositoryIamMember", "IAMAuditConfig"} <= dep_types
    assert by_role["roles/cloudsql.client"] in run_deps[0]


def test_enclave_url_names_the_enclave_port(stack) -> None:
    _, outputs = stack
    assert outputs["enclave_url"] == f"https://{STATIC_IP}:8443"
