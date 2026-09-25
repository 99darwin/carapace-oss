"""The alembic migration job, asserted against Pulumi mocks."""

import json

import pytest

pytest.importorskip("pulumi_gcp")

from components.server import (  # noqa: E402
    MIGRATION_ARGS,
    MIGRATION_COMMAND,
    migration_job_name,
)
from harness import (  # noqa: E402
    MIGRATION_TOKEN,
    PROJECT_ID,
    RecordingMocks,
    make_config,
    run_stack,
)

JOB = "gcp:cloudrunv2/job:Job"
SERVICE = "gcp:cloudrunv2/service:Service"
RANDOM_ID = "random:index/randomId:RandomId"
SERVER_SA = f"cptest-server@{PROJECT_ID}.iam.gserviceaccount.com"
# Cloud Run: the job name plus the execution token must stay under 63 chars.
MAX_EXECUTION_NAME = 62
LONGEST_PREFIX = "a" * 20


@pytest.fixture(scope="module")
def stack() -> tuple[RecordingMocks, dict]:
    return run_stack(make_config())


def _job(mocks: RecordingMocks) -> dict:
    return mocks.one(JOB).inputs


def _job_container(mocks: RecordingMocks) -> dict:
    return _job(mocks)["template"]["template"]["containers"][0]


def _service_container(mocks: RecordingMocks) -> dict:
    return mocks.one(SERVICE).inputs["template"]["containers"][0]


def test_job_runs_alembic_upgrade_head_from_the_server_image(stack) -> None:
    mocks, _ = stack
    job = _job(mocks)
    container = _job_container(mocks)
    assert job["name"] == "cptest-migrate"
    assert container["image"] == _service_container(mocks)["image"]
    assert "@sha256:" in container["image"]
    assert container["commands"] == list(MIGRATION_COMMAND)
    assert container["args"] == list(MIGRATION_ARGS)
    assert container["args"][-2:] == ["upgrade", "head"]


def test_job_gets_the_database_url_exactly_as_the_service_does(stack) -> None:
    mocks, _ = stack
    job_envs = _job_container(mocks)["envs"]
    assert job_envs == _service_container(mocks)["envs"]
    by_name = {e["name"]: e for e in job_envs}
    for name in ("CARAPACE_DATABASE_URL", "CARAPACE_JWT_SECRET"):
        assert "value" not in by_name[name]
        assert "secretKeyRef" in by_name[name]["valueSource"]
    assert (
        by_name["CARAPACE_DATABASE_URL"]["valueSource"]["secretKeyRef"]["secret"]
        == "cptest-database-url"
    )
    assert "mock-password" not in json.dumps(_job(mocks))


def test_job_uses_the_server_identity_and_cloud_sql_socket(stack) -> None:
    mocks, _ = stack
    job_task = _job(mocks)["template"]["template"]
    service = mocks.one(SERVICE).inputs["template"]
    assert job_task["serviceAccount"] == SERVER_SA == service["serviceAccount"]
    assert job_task["volumes"] == service["volumes"]
    assert (
        _job_container(mocks)["volumeMounts"]
        == (_service_container(mocks)["volumeMounts"])
    )


def test_job_never_runs_concurrently_or_retries(stack) -> None:
    mocks, _ = stack
    job = _job(mocks)
    assert job["template"]["taskCount"] == 1
    assert job["template"]["parallelism"] == 1
    assert job["template"]["template"]["maxRetries"] == 0


def test_job_reruns_whenever_the_image_changes(stack) -> None:
    mocks, _ = stack
    token = mocks.one(RANDOM_ID).inputs
    assert token["keepers"] == {"image": _job_container(mocks)["image"]}
    # run_execution_token (not start_): Pulumi waits for the execution to
    # succeed, so a failed migration stops the deploy.
    assert _job(mocks)["runExecutionToken"] == MIGRATION_TOKEN
    assert "startExecutionToken" not in _job(mocks)


def test_execution_name_fits_for_the_longest_prefix() -> None:
    token_hex_chars = len(MIGRATION_TOKEN)
    name = migration_job_name(LONGEST_PREFIX)
    assert len(name) + 1 + token_hex_chars <= MAX_EXECUTION_NAME


def test_migration_job_is_an_output(stack) -> None:
    _, outputs = stack
    assert outputs["migration_job"] == "cptest-migrate"


def test_bootstrap_mode_has_no_job() -> None:
    mocks, outputs = run_stack(
        make_config(
            deploy_workloads=False, enclave_image_digest="", server_image_digest=""
        )
    )
    assert not mocks.of_type(JOB)
    assert "migration_job" not in outputs


def test_service_rolls_out_only_after_the_job(monkeypatch) -> None:
    import pulumi_gcp as gcp

    jobs: list = []
    job_deps: list[list] = []
    service_deps: list[list] = []
    original_job = gcp.cloudrunv2.Job
    original_service = gcp.cloudrunv2.Service

    def recording_job(*args, opts=None, **kwargs):
        job_deps.append(list(opts.depends_on or []) if opts else [])
        job = original_job(*args, opts=opts, **kwargs)
        jobs.append(job)
        return job

    def recording_service(*args, opts=None, **kwargs):
        service_deps.append(list(opts.depends_on or []) if opts else [])
        return original_service(*args, opts=opts, **kwargs)

    monkeypatch.setattr(gcp.cloudrunv2, "Job", recording_job)
    monkeypatch.setattr(gcp.cloudrunv2, "Service", recording_service)
    run_stack(make_config())

    assert len(jobs) == 1 and len(service_deps) == 1
    assert jobs[0] in service_deps[0]
    dep_types = {type(dep).__name__ for dep in job_deps[0]}
    # Secret access, the database user and the database itself, and the
    # project-level cloudsql.client grant.
    assert {"SecretIamMember", "User", "Database", "IAMMember"} <= dep_types
