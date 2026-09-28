"""The ``pulumi`` CLI wrapper, against a fake process runner.

No Pulumi CLI runs: every command goes to :class:`FakePulumi`, which
records the argv and environment and answers like the CLI would.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from deploy_support import PREFIX, PROJECT, PROJECT_NUMBER, REGION

from carapace_cli.deploy import pulumi_runner
from carapace_cli.deploy.infra import INFRA_DIR_ENV
from carapace_cli.deploy.preflight import Target
from carapace_cli.deploy.pulumi_runner import (
    Captured,
    Completed,
    PreviewStep,
    PulumiError,
    PulumiStack,
    StateResource,
    capture_process,
    find_pulumi,
    locate_infra,
    open_stack,
    parse_preview,
    run_process,
)
from carapace_cli.deploy.state import state_backend_for
from carapace_cli.deploy.zones import is_zone_capacity_error

REPO = Path(__file__).resolve().parents[2]
INFRA = REPO / "infra" / "pulumi"
TARGET = Target(PROJECT, PROJECT_NUMBER, REGION, f"{REGION}-a", PREFIX, ("a@b.io",))
BACKEND = state_backend_for(TARGET)
ROOT_URN = f"urn:pulumi:{PREFIX}::carapace::pulumi:pulumi:Stack::s"
KEY_URN = f"urn:pulumi:{PREFIX}::carapace::gcp:kms/cryptoKey:CryptoKey::k"
DB_URN = f"urn:pulumi:{PREFIX}::carapace::gcp:sql/databaseInstance:DatabaseInstance::d"
VM_URN = f"urn:pulumi:{PREFIX}::carapace::gcp:compute/instance:Instance::c1x-enclave"
# The shape of `pulumi preview --json` (display.PreviewDigest in Pulumi's
# pkg/display/json.go): the logical replace of the VM with its reasons,
# and the root stack's step, which is always there. The states carry
# values; a secret one is masked, never shown.
PREVIEW_DIGEST: dict[str, object] = {
    "config": {"carapace:prefix": PREFIX, "carapace:db": "[secret]"},
    "steps": [
        {
            "op": "same",
            "urn": ROOT_URN,
            "oldState": {"urn": ROOT_URN, "type": "pulumi:pulumi:Stack"},
            "newState": {"urn": ROOT_URN, "type": "pulumi:pulumi:Stack"},
            "detailedDiff": None,
        },
        {
            "op": "replace",
            "urn": VM_URN,
            "provider": "urn:pulumi:c1x::carapace::pulumi:providers:gcp::default",
            "oldState": {"inputs": {"metadata": {"k": "[secret]"}}},
            "newState": {"inputs": {"metadata": {"k": "[secret]"}}},
            "diffReasons": ["bootDisk", "metadata"],
            "replaceReasons": ["bootDisk"],
            "detailedDiff": {
                "bootDisk.initializeParams.image": {
                    "kind": "update-replace",
                    "inputDiff": True,
                },
                "metadata": {"kind": "update", "inputDiff": True},
            },
        },
    ],
    "diagnostics": [],
    "duration": 5000000000,
    "changeSummary": {"replace": 1, "same": 1},
}


@dataclass
class Call:
    argv: list[str]
    cwd: Path
    env: dict[str, str]
    streamed: bool


@dataclass
class FakePulumi:
    """Answers by subcommand; ``fail`` makes one subcommand exit 1."""

    config: dict[str, dict[str, object]] = field(default_factory=dict)
    outputs: dict[str, object] = field(default_factory=dict)
    # What `pulumi stack export` prints: the deployment, secrets encrypted.
    export: dict[str, object] = field(default_factory=lambda: {"version": 3})
    version: str = "v3.217.1"
    fail: str | None = None
    # Extra lines `pulumi destroy` streams after its progress.
    destroy_output: list[str] = field(default_factory=list)
    # What `pulumi preview --json` prints, on stdout and stderr apart.
    preview_stdout: str = field(default_factory=lambda: json.dumps(PREVIEW_DIGEST))
    preview_stderr: str = ""
    preview_code: int = 0
    calls: list[Call] = field(default_factory=list)

    def capture(
        self, argv: list[str], *, cwd: Path, env: Mapping[str, str]
    ) -> Captured:
        self.calls.append(Call(argv, cwd, dict(env), False))
        assert argv[1] == "preview", "only the preview is captured"
        return Captured(self.preview_code, self.preview_stdout, self.preview_stderr)

    def __call__(
        self,
        argv: list[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        on_output: Callable[[str], None] | None,
    ) -> Completed:
        self.calls.append(Call(argv, cwd, dict(env), on_output is not None))
        command = " ".join(arg for arg in argv[1:3] if not arg.startswith("-"))
        if self.fail and command.startswith(self.fail):
            if on_output:
                on_output("Updating (c1x)\n")
            return Completed(1, "lots of output\n  error: quota exceeded\n\n")
        if on_output:
            on_output("progress\n")
            if command == "destroy":
                for line in self.destroy_output:
                    on_output(line)
        if command == "version":
            return Completed(0, f"{self.version}\n")
        if command == "config" and "--json" in argv:
            return Completed(0, json.dumps(self.config))
        if command == "stack output":
            return Completed(0, json.dumps(self.outputs))
        if command == "stack export":
            return Completed(0, json.dumps(self.export))
        return Completed(0, "")

    def argv(self, command: str) -> list[str]:
        return next(
            c.argv for c in self.calls if " ".join(c.argv[1:]).startswith(command)
        )


def stack(fake: FakePulumi, lines: list[str] | None = None) -> PulumiStack:
    sink = lines if lines is not None else []
    return PulumiStack(
        executable="/bin/pulumi",
        infra=INFRA,
        stack=PREFIX,
        backend=BACKEND,
        on_output=sink.append,
        run=fake,
        capture=fake.capture,
    )


def test_open_stack_selects_with_kms_secrets_and_installs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pulumi_runner.shutil, "which", lambda _name: "/bin/pulumi")
    fake = FakePulumi()
    open_stack(TARGET, BACKEND, on_output=print, run=fake)
    assert [c.argv[1] for c in fake.calls] == ["version", "stack", "install"]
    select = fake.argv("stack select")
    assert select[select.index("--secrets-provider") + 1] == (
        f"gcpkms://projects/{PROJECT}/locations/{REGION}/keyRings/carapace-state"
        "/cryptoKeys/pulumi-state"
    )
    assert "--create" in select and select[select.index("--stack") + 1] == PREFIX
    assert "--stack" not in fake.argv("install")
    for call in fake.calls[1:]:
        assert call.cwd == INFRA
        assert call.env["PULUMI_BACKEND_URL"] == f"gs://{PROJECT}-carapace-state"
        assert call.env["PULUMI_SKIP_UPDATE_CHECK"] == "true"
        assert "--non-interactive" in call.argv


def test_no_command_ever_shows_secrets() -> None:
    fake = FakePulumi(outputs={"server_url": "https://s", "db": "[secret]"})
    handle = stack(fake)
    handle.config()
    handle.set_config({"carapace:prefix": PREFIX})
    assert handle.up() == {"server_url": "https://s"}
    handle.has_resources()
    handle.resources()
    handle.up_targets([DB_URN])
    handle.unprotect_all()
    handle.preview()
    handle.destroy()
    assert fake.calls
    assert not any("--show-secrets" in call.argv for call in fake.calls)


def test_has_resources_reads_the_state_export() -> None:
    root = {"urn": f"urn:pulumi:{PREFIX}::carapace::pulumi:pulumi:Stack::s"}
    fake = FakePulumi(export={"version": 3, "deployment": {"resources": [root]}})
    assert stack(fake).has_resources()
    export = fake.argv("stack export")
    assert export[export.index("--stack") + 1] == PREFIX
    assert "--show-secrets" not in export and "--json" not in export
    # Never deployed, destroyed, or exported without a deployment: nothing.
    for empty in (
        {"version": 3},
        {"version": 3, "deployment": None},
        {"version": 3, "deployment": {"manifest": {}, "resources": []}},
    ):
        assert not stack(FakePulumi(export=empty)).has_resources()


def test_up_targets_passes_each_urn_and_nothing_else() -> None:
    lines: list[str] = []
    fake = FakePulumi()
    stack(fake, lines).up_targets([KEY_URN, DB_URN])
    (call,) = fake.calls
    assert call.argv == [
        "/bin/pulumi",
        "up",
        "--yes",
        "--skip-preview",
        "--target",
        KEY_URN,
        "--target",
        DB_URN,
        "--non-interactive",
        "--stack",
        PREFIX,
    ]
    assert call.streamed and lines == ["progress\n"]
    assert "--target-dependents" not in call.argv
    assert "--show-secrets" not in call.argv


def test_up_targets_refuses_no_targets_a_non_urn_or_a_glob() -> None:
    fake = FakePulumi()
    with pytest.raises(PulumiError, match="at least one target"):
        stack(fake).up_targets([])
    with pytest.raises(PulumiError, match="not a Pulumi URN"):
        stack(fake).up_targets(["--target-dependents"])
    # A `*` makes --target a glob, which can match, and so create, what
    # the state lacks.
    for glob in ("urn:pulumi:*", f"urn:pulumi:{PREFIX}::carapace::gcp:*::*"):
        with pytest.raises(PulumiError, match="not a Pulumi URN"):
            stack(fake).up_targets([DB_URN, glob])
    assert not fake.calls, "an untargeted up ran"


def test_unprotect_all_edits_the_state_without_the_program() -> None:
    lines: list[str] = []
    fake = FakePulumi()
    stack(fake, lines).unprotect_all()
    (call,) = fake.calls
    assert call.argv == [
        "/bin/pulumi",
        "state",
        "unprotect",
        "--all",
        "--yes",
        "--non-interactive",
        "--stack",
        PREFIX,
    ]
    assert call.cwd == INFRA and not call.streamed and not lines
    assert call.env["PULUMI_BACKEND_URL"] == f"gs://{PROJECT}-carapace-state"


def test_failed_unprotect_is_a_resumable_error_that_names_it() -> None:
    fake = FakePulumi(fail="state unprotect")
    with pytest.raises(PulumiError, match="state unprotect failed: .*run the same"):
        stack(fake).unprotect_all()


def test_state_resource_repr_leaves_the_outputs_out() -> None:
    # Outputs hold ciphertext and plain values alike; neither belongs in a
    # traceback or an error message that shows the resource.
    resource = StateResource(DB_URN, "t", True, {"ciphertext": "AAAA", "ip": "1"})
    assert "AAAA" not in repr(resource) and "ip" not in repr(resource)
    assert DB_URN in repr(resource)


def test_failed_targeted_up_is_a_resumable_error() -> None:
    fake = FakePulumi(fail="up")
    with pytest.raises(PulumiError, match="pulumi up failed: .*run the same"):
        stack(fake).up_targets([DB_URN])


def test_resources_reads_type_protect_and_outputs_from_the_export() -> None:
    db = {
        "urn": DB_URN,
        "type": "gcp:sql/databaseInstance:DatabaseInstance",
        "protect": True,
        "outputs": {"deletionProtection": True},
    }
    plain = {"urn": ROOT_URN, "type": "pulumi:pulumi:Stack"}
    fake = FakePulumi(export={"version": 3, "deployment": {"resources": [db, plain]}})
    assert stack(fake).resources() == [
        StateResource(DB_URN, db["type"], True, {"deletionProtection": True}),
        StateResource(ROOT_URN, "pulumi:pulumi:Stack", False, {}),
    ]
    export = fake.argv("stack export")
    assert "--show-secrets" not in export
    assert stack(FakePulumi()).resources() == []
    for garbled in ([{"urn": DB_URN}], ["x"], {"a": 1}):
        bad = FakePulumi(export={"version": 3, "deployment": {"resources": garbled}})
        with pytest.raises(PulumiError, match="malformed"):
            stack(bad).resources()


def test_resources_read_a_pending_replacement() -> None:
    vm = {"urn": VM_URN, "type": "gcp:compute/instance:Instance"}
    fake = FakePulumi(
        export={
            "version": 3,
            "deployment": {
                "resources": [
                    vm | {"pendingReplacement": True},
                    vm,
                    # Only a JSON true marks it; anything else is live.
                    vm | {"pendingReplacement": "true"},
                    vm | {"pendingReplacement": False},
                ]
            },
        }
    )
    assert [r.pending_replacement for r in stack(fake).resources()] == [
        True,
        False,
        False,
        False,
    ]


def test_has_resources_fails_on_garbled_export() -> None:
    class Garbled(FakePulumi):
        def __call__(self, argv, **kwargs) -> Completed:  # type: ignore[override]
            return Completed(0, "[]")

    with pytest.raises(PulumiError, match="stack export printed list"):
        stack(Garbled()).has_resources()


def test_up_and_destroy_stream_and_skip_prompts() -> None:
    lines: list[str] = []
    fake = FakePulumi()
    handle = stack(fake, lines)
    handle.up()
    handle.destroy()
    for command in ("up", "destroy"):
        argv = fake.argv(command)
        assert "--yes" in argv and "--skip-preview" in argv
    assert lines == ["progress\n", "progress\n"]


def test_destroy_hides_the_stack_rm_hint_only() -> None:
    lines: list[str] = []
    fake = FakePulumi(
        destroy_output=[
            "Resources:\n",
            "    - 42 deleted\n",
            "The resources in the stack have been deleted, but the history and "
            "configuration associated with the stack are still maintained. \n",
            "If you want to remove the stack completely, run "
            f"`pulumi stack rm {PREFIX}`.\n",
            "warning: something real\n",
        ]
    )
    stack(fake, lines).destroy()
    assert lines == [
        "progress\n",
        "Resources:\n",
        "    - 42 deleted\n",
        "warning: something real\n",
    ]


def test_remove_runs_stack_rm_without_force_or_preserved_config() -> None:
    fake = FakePulumi()
    stack(fake).remove()
    (call,) = fake.calls
    assert call.argv == [
        "/bin/pulumi",
        "stack",
        "rm",
        "--yes",
        PREFIX,
        "--non-interactive",
    ]
    assert call.cwd == INFRA
    assert call.env["PULUMI_BACKEND_URL"] == f"gs://{PROJECT}-carapace-state"
    assert not call.streamed


def test_failed_stack_rm_is_an_error_that_names_it() -> None:
    fake = FakePulumi(fail="stack rm")
    with pytest.raises(PulumiError, match="pulumi stack rm failed: error: quota"):
        stack(fake).remove()


def test_config_reads_plain_values_and_skips_secrets() -> None:
    fake = FakePulumi(
        config={
            "carapace:prefix": {"value": PREFIX, "secret": False},
            "carapace:db": {"secret": True},
            "gcp:zone": {"value": "us-central1-a"},
        }
    )
    assert stack(fake).config() == {
        "carapace:prefix": PREFIX,
        "gcp:zone": "us-central1-a",
    }


def test_set_config_marks_every_value_plaintext() -> None:
    fake = FakePulumi()
    emails = json.dumps(["a@b.io"])
    stack(fake).set_config({"carapace:prefix": PREFIX, "carapace:alert_emails": emails})
    argv = fake.argv("config set-all")
    assert argv[3:7] == [
        "--plaintext",
        f"carapace:prefix={PREFIX}",
        "--plaintext",
        f"carapace:alert_emails={emails}",
    ]


def test_failure_becomes_a_short_resumable_error() -> None:
    fake = FakePulumi(fail="up")
    with pytest.raises(PulumiError, match="pulumi up failed: error: quota exceeded;"):
        stack(fake).up()


def test_non_json_output_is_an_error() -> None:
    class Garbled(FakePulumi):
        def __call__(self, argv, **kwargs) -> Completed:  # type: ignore[override]
            return Completed(0, "not json")

    with pytest.raises(PulumiError, match="did not print JSON"):
        stack(Garbled()).outputs()


def test_missing_or_wrong_pulumi_is_refused() -> None:
    with pytest.raises(PulumiError, match="not on PATH"):
        find_pulumi(run=FakePulumi(), which=lambda _name: None)
    with pytest.raises(PulumiError, match="not a usable Pulumi 3.x"):
        find_pulumi(run=FakePulumi(version="v4.0.0"), which=lambda _: "/bin/pulumi")
    with pytest.raises(PulumiError, match="not a usable"):
        find_pulumi(run=FakePulumi(fail="version"), which=lambda _: "/bin/pulumi")
    assert find_pulumi(run=FakePulumi(), which=lambda _: "/bin/pulumi")


def test_locate_infra_finds_the_checkout_or_the_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv(INFRA_DIR_ENV, raising=False)
    assert locate_infra() == INFRA
    monkeypatch.setenv(INFRA_DIR_ENV, str(tmp_path))
    with pytest.raises(PulumiError, match="CARAPACE_INFRA_DIR"):
        locate_infra()


def test_run_process_streams_without_a_shell(tmp_path: Path) -> None:
    lines: list[str] = []
    script = "import sys; print('one'); print('two', file=sys.stderr); sys.exit(3)"
    result = run_process(
        [sys.executable, "-u", "-c", script],
        cwd=tmp_path,
        env={},
        on_output=lines.append,
    )
    assert result == Completed(3, "one\ntwo\n")
    assert lines == ["one\n", "two\n"]
    quiet = run_process(
        [sys.executable, "-c", "print('x')"], cwd=tmp_path, env={}, on_output=None
    )
    assert quiet == Completed(0, "x\n")


def test_failure_keeps_pulumi_output_for_classifying_it() -> None:
    with pytest.raises(PulumiError) as caught:
        stack(FakePulumi(fail="up")).up()
    assert "quota exceeded" in caught.value.output
    assert not is_zone_capacity_error(f"{caught.value}\n{caught.value.output}")


def test_a_quiet_command_failure_keeps_no_output() -> None:
    """`stack export` prints the whole state; a failure keeps only its
    last line in the message, as before, and none of it as output."""
    with pytest.raises(PulumiError) as caught:
        stack(FakePulumi(fail="stack export")).resources()
    assert str(caught.value).startswith(
        "pulumi stack export failed: error: quota exceeded"
    )
    assert caught.value.output == ""


# -- pulumi preview --------------------------------------------------------------


def test_preview_runs_json_preview_and_never_shows_secrets() -> None:
    lines: list[str] = []
    fake = FakePulumi(preview_stderr="warning: a plugin was downloaded\n")
    steps = stack(fake, lines).preview()
    (call,) = fake.calls
    assert call.argv == [
        "/bin/pulumi",
        "preview",
        "--json",
        "--non-interactive",
        "--stack",
        PREFIX,
    ]
    assert "--show-secrets" not in call.argv
    assert call.cwd == INFRA
    assert call.env["PULUMI_BACKEND_URL"] == f"gs://{PROJECT}-carapace-state"
    # The digest, not a stream of events, whatever the environment says.
    assert call.env["PULUMI_ENABLE_STREAMING_JSON_PREVIEW"] == "false"
    # stderr goes to the terminal, never into the JSON.
    assert lines == ["warning: a plugin was downloaded\n"]
    assert [step.op for step in steps] == ["same", "replace"]


def test_preview_steps_keep_reasons_and_no_values() -> None:
    _root, vm = parse_preview(json.dumps(PREVIEW_DIGEST))
    assert vm == PreviewStep(
        op="replace",
        urn=VM_URN,
        type="gcp:compute/instance:Instance",
        replace_reasons=("bootDisk",),
        diff_reasons=("bootDisk", "metadata"),
        detailed_diff={
            "bootDisk.initializeParams.image": "update-replace",
            "metadata": "update",
        },
    )
    assert "[secret]" not in repr(vm)


def test_preview_reads_a_child_resource_type_from_its_urn() -> None:
    child = f"urn:pulumi:{PREFIX}::carapace::my:comp$gcp:compute/instance:Instance::v"
    digest = {
        "steps": [{"op": "same", "urn": ROOT_URN}, {"op": "update", "urn": child}]
    }
    assert parse_preview(json.dumps(digest))[1].type == (
        "gcp:compute/instance:Instance"
    )


@pytest.mark.parametrize(
    "stdout",
    [
        "",
        "not json",
        # stderr merged into stdout would look like this.
        "warning: something\n" + json.dumps(PREVIEW_DIGEST),
        "[]",
        json.dumps({"config": {}}),
        # Parses, but lacks the root stack: not a preview digest.
        json.dumps({"steps": []}),
        json.dumps({"steps": [{"op": "replace", "urn": VM_URN}]}),
        json.dumps({"steps": "all"}),
        json.dumps({"steps": [{"urn": ROOT_URN}]}),
        json.dumps({"steps": [{"op": "same", "urn": "not-a-urn"}]}),
        json.dumps(
            {
                "steps": [
                    {"op": "same", "urn": ROOT_URN},
                    {"op": "replace", "urn": VM_URN, "replaceReasons": "bootDisk"},
                ]
            }
        ),
        json.dumps(
            {
                "steps": [
                    {"op": "same", "urn": ROOT_URN},
                    {"op": "replace", "urn": VM_URN, "detailedDiff": {"a": "b"}},
                ]
            }
        ),
    ],
)
def test_unusable_preview_output_fails_closed(stdout: str) -> None:
    fake = FakePulumi(preview_stdout=stdout)
    with pytest.raises(PulumiError, match="nothing was changed") as caught:
        stack(fake).preview()
    assert caught.value.output == ""


def test_failed_preview_says_so_without_pulumi_output_in_the_error() -> None:
    lines: list[str] = []
    digest = {
        "steps": [{"op": "same", "urn": ROOT_URN}],
        "diagnostics": [
            {"message": "error: program failed: KeyError x\n", "severity": "error"},
            {"message": "just info\n", "severity": "info"},
        ],
    }
    fake = FakePulumi(
        preview_code=255,
        preview_stdout=json.dumps(digest),
        preview_stderr="error: preview failed\n",
    )
    with pytest.raises(PulumiError) as caught:
        stack(fake, lines).preview()
    message = str(caught.value)
    assert message.startswith("pulumi preview failed (exit code 255)")
    assert "nothing was changed" in message
    assert "KeyError" not in message and "preview failed\n" not in message
    assert caught.value.output == ""
    # The causes reach the terminal instead.
    assert lines == [
        "error: preview failed\n",
        "error: program failed: KeyError x\n",
    ]


def test_a_successful_preview_shows_its_warnings_verbatim() -> None:
    lines: list[str] = []
    digest = PREVIEW_DIGEST | {
        "diagnostics": [
            {"message": "warning: deprecated input\n", "severity": "warning"},
            {"message": "just info\n", "severity": "info"},
            {"message": "no newline", "severity": "warning"},
        ]
    }
    fake = FakePulumi(preview_stdout=json.dumps(digest))
    steps = stack(fake, lines).preview()
    assert [step.op for step in steps] == ["same", "replace"]
    assert lines == ["warning: deprecated input\n", "no newline\n"]


def test_capture_process_keeps_stdout_and_stderr_apart(tmp_path: Path) -> None:
    script = "import sys; print('{}'); print('warn', file=sys.stderr); sys.exit(2)"
    result = capture_process([sys.executable, "-c", script], cwd=tmp_path, env={})
    assert result == Captured(2, "{}\n", "warn\n")
    assert "warn" not in repr(result)
