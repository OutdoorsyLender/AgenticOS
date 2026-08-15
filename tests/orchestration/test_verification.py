"""Controller-owned deterministic verification contracts."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from agenticos.orchestration.verification import (
    VERIFICATION_RESULT_SCHEMA,
    FailureClassification,
    ReadonlyProcessEvidence,
    VerificationClassification,
    VerificationExitClassification,
    VerificationResult,
    VerificationController,
    VerifierRegistry,
    VerifierSpec,
    VerificationError,
    verification_failure_fingerprint,
)
from agenticos.orchestration.verifier_worker import run as run_verifier_worker
from agenticos.orchestration.models import TaskStatus
from agenticos.sandbox.containment import ContainmentState
from agenticos.sandbox.runtime_boundary import M4AProfile
from tests.orchestration.test_execution import (
    FakeCheckpoint,
    FakeWorkspaceManager,
    _board,
    _capture,
    _dispatch,
    _process_result,
    _receipt,
    _reservation,
)


def _spec(**changes: object) -> VerifierSpec:
    values: dict[str, object] = {
        "verifier_id": "demo-fixture-v1",
        "executable": "/usr/bin/python3",
        "argv": (
            "/usr/bin/python3",
            "/opt/agenticos/worker.py",
            "--scenario",
            "CHECK_FEATURE",
        ),
        "working_directory": "/workspace",
        "timeout_seconds": 5,
        "max_stdout_bytes": 4096,
        "max_stderr_bytes": 4096,
        "pass_exit_codes": (0,),
        "fail_exit_codes": (1,),
        "fixture_id": "demo-feature-v1",
    }
    values.update(changes)
    return VerifierSpec(**values)  # type: ignore[arg-type]


def _evidence() -> ReadonlyProcessEvidence:
    return ReadonlyProcessEvidence(
        containment_unit="aos-task-project-verify-1.scope",
        cgroup_path="/sys/fs/cgroup/user.slice/aos-task-project-verify-1.scope",
        pid=101,
        process_group_id=101,
        start_time_ticks=202,
        boot_id="boot-id",
        policy_digest="a" * 64,
        namespace_digest="b" * 64,
        workspace_device=10,
        workspace_inode=20,
    )


def _result(**changes: object) -> VerificationResult:
    values: dict[str, object] = {
        "schema": VERIFICATION_RESULT_SCHEMA,
        "verifier_id": _spec().verifier_id,
        "verifier_spec_digest": _spec().spec_digest,
        "project_id": "project-d",
        "task_id": "build-d",
        "task_generation": 2,
        "attempt": 1,
        "controller_epoch": 4,
        "checkpoint_digest": "c" * 64,
        "classification": VerificationClassification.PASS,
        "failure_classification": None,
        "exit_classification": VerificationExitClassification.EXITED,
        "exit_code": 0,
        "stdout_sha256": "d" * 64,
        "stdout_byte_count": 2,
        "stdout_inline": "ok",
        "stderr_sha256": "e" * 64,
        "stderr_byte_count": 0,
        "stderr_inline": "",
        "timed_out": False,
        "cancelled": False,
        "process_evidence": _evidence(),
        "failure_fingerprint": None,
    }
    values.update(changes)
    return VerificationResult(**values)  # type: ignore[arg-type]


def test_verifier_spec_identity_is_canonical_and_registry_owned() -> None:
    spec = _spec()
    assert VerifierSpec.from_dict(spec.to_dict()) == spec
    assert len(spec.spec_digest) == 64
    assert replace(spec, timeout_seconds=6).spec_digest != spec.spec_digest

    registry = VerifierRegistry((spec,))
    assert registry.resolve(spec.verifier_id, spec_digest=spec.spec_digest) == spec
    with pytest.raises(VerificationError, match="UNKNOWN_VERIFIER"):
        registry.resolve("agent-chosen")
    with pytest.raises(VerificationError, match="VERIFIER_SPEC_MISMATCH"):
        registry.resolve(spec.verifier_id, spec_digest="f" * 64)


@pytest.mark.parametrize(
    "changes",
    [
        {"executable": "python3"},
        {"argv": ()},
        {"argv": ("/usr/bin/python3", "-c", "print('agent command')")},
        {"executable": "/bin/sh", "argv": ("/bin/sh", "script")},
        {"executable": "/bin/bash", "argv": ("/bin/bash", "script")},
        {"working_directory": "/tmp"},
        {"pass_exit_codes": (0, 1), "fail_exit_codes": (1,)},
        {"max_stdout_bytes": 0},
        {"timeout_seconds": 0},
    ],
)
def test_verifier_spec_rejects_shells_interpolation_and_ambiguous_policy(
    changes: dict[str, object],
) -> None:
    with pytest.raises(VerificationError):
        _spec(**changes)


def test_verifier_spec_rejects_unknown_fields() -> None:
    raw = _spec().to_dict()
    raw["model_argv"] = ["/bin/true"]
    with pytest.raises(VerificationError, match="UNKNOWN_FIELDS"):
        VerifierSpec.from_dict(raw)


def test_semantic_failure_fingerprint_uses_only_bounded_controller_evidence() -> None:
    first = verification_failure_fingerprint(
        verifier_id="demo-fixture-v1",
        verifier_spec_digest="a" * 64,
        checkpoint_digest="b" * 64,
        exit_code=1,
        stdout_sha256="c" * 64,
        stderr_sha256="d" * 64,
    )
    replay = verification_failure_fingerprint(
        verifier_id="demo-fixture-v1",
        verifier_spec_digest="a" * 64,
        checkpoint_digest="b" * 64,
        exit_code=1,
        stdout_sha256="c" * 64,
        stderr_sha256="d" * 64,
    )
    changed = verification_failure_fingerprint(
        verifier_id="demo-fixture-v1",
        verifier_spec_digest="a" * 64,
        checkpoint_digest="b" * 64,
        exit_code=1,
        stdout_sha256="e" * 64,
        stderr_sha256="d" * 64,
    )
    assert first == replay
    assert first != changed
    assert len(first) == 64
    with pytest.raises(VerificationError):
        verification_failure_fingerprint(
            verifier_id="x" * 129,
            verifier_spec_digest="a" * 64,
            checkpoint_digest="b" * 64,
            exit_code=1,
            stdout_sha256="c" * 64,
            stderr_sha256="d" * 64,
        )


def test_verification_result_is_strict_typed_and_digest_bound() -> None:
    result = _result()
    assert VerificationResult.from_dict(result.to_dict()) == result
    assert len(result.result_digest) == 64
    assert replace(result, stdout_inline="OK").result_digest != result.result_digest

    fingerprint = verification_failure_fingerprint(
        verifier_id=result.verifier_id,
        verifier_spec_digest=result.verifier_spec_digest,
        checkpoint_digest=result.checkpoint_digest,
        exit_code=1,
        stdout_sha256=result.stdout_sha256,
        stderr_sha256=result.stderr_sha256,
    )
    failed = _result(
        classification=VerificationClassification.FAIL,
        failure_classification=FailureClassification.VERIFICATION_FAILURE,
        exit_code=1,
        failure_fingerprint=fingerprint,
    )
    assert failed.failure_fingerprint == fingerprint


@pytest.mark.parametrize(
    "changes",
    [
        {
            "classification": VerificationClassification.PASS,
            "failure_classification": FailureClassification.VERIFICATION_FAILURE,
        },
        {
            "classification": VerificationClassification.FAIL,
            "failure_classification": FailureClassification.VERIFICATION_FAILURE,
            "exit_code": 1,
            "failure_fingerprint": None,
        },
        {
            "classification": VerificationClassification.INFRASTRUCTURE_ERROR,
            "failure_classification": FailureClassification.TIMEOUT,
            "timed_out": True,
            "exit_classification": VerificationExitClassification.TIMEOUT,
            "exit_code": 0,
        },
        {"stdout_byte_count": 3},
        {"stdout_inline": "x" * 4097},
    ],
)
def test_verification_result_rejects_inconsistent_or_unbounded_claims(
    changes: dict[str, object],
) -> None:
    with pytest.raises(VerificationError):
        _result(**changes)


def test_failure_classification_is_complete_and_authoritative() -> None:
    assert {item.value for item in FailureClassification} == {
        "VERIFICATION_FAILURE",
        "REVIEW_BLOCKING_FINDING",
        "RETRYABLE_INFRASTRUCTURE_FAILURE",
        "TERMINAL_INFRASTRUCTURE_FAILURE",
        "MALFORMED_AGENT_OUTPUT",
        "STALE_IDENTITY",
        "CHECKPOINT_MISMATCH",
        "WORKSPACE_MUTATION_DURING_READONLY_STAGE",
        "TIMEOUT",
        "CANCELLED",
        "CONTAINMENT_FAILURE",
        "REPAIR_BUDGET_EXHAUSTED",
    }


def test_fixed_verifier_worker_measures_feature_bytes_without_model_commands(
    tmp_path,
) -> None:
    assert run_verifier_worker("CHECK_FEATURE", tmp_path) == 1
    (tmp_path / "feature.txt").write_bytes(b"broken\n")
    assert run_verifier_worker("CHECK_FEATURE", tmp_path) == 1
    (tmp_path / "feature.txt").write_bytes(b"fixed\n")
    assert run_verifier_worker("CHECK_FEATURE", tmp_path) == 0
    assert run_verifier_worker("PASS", tmp_path) == 0
    assert run_verifier_worker("FAIL", tmp_path) == 1
    assert run_verifier_worker("INFRA_ERROR", tmp_path) == 70
    assert run_verifier_worker("UNKNOWN", tmp_path) == 70


@pytest.mark.parametrize(
    "scenario",
    ["MUTATE_CREATE", "MUTATE_WRITE", "MUTATE_RENAME", "MUTATE_DELETE"],
)
def test_fixed_verifier_worker_never_mistakes_successful_mutation_for_pass(
    tmp_path, scenario: str
) -> None:
    (tmp_path / "feature.txt").write_bytes(b"fixed\n")
    assert run_verifier_worker(scenario, tmp_path) == 74


class _PreparedVerifier:
    def __init__(self, process, *, receipt=None, on_wait=None) -> None:
        self.receipt = receipt or replace(
            _receipt(),
            executable=_spec().executable,
            argv=_spec().argv,
        )
        self.process = process
        self.on_wait = on_wait
        self.terminal = False
        self.cancelled = False

    def release(self, receipt, nonce) -> None:
        assert receipt == self.receipt
        assert nonce == self.receipt.reservation.release_nonce

    def wait(self, timeout=None, **_kwargs):
        if self.on_wait is not None:
            self.on_wait()
        self.terminal = True
        return self.process

    def request_cancel(self) -> None:
        self.cancelled = True

    def cancel(self):
        self.cancelled = True
        self.terminal = True
        return replace(self.process, exit_code=None, signal=9)


class _VerifierRunner:
    def __init__(self, prepared: _PreparedVerifier, *, profile=M4AProfile.INSPECT) -> None:
        self.profile = profile
        self.prepared = prepared
        self.calls: list[str] = []

    def prepare(self, argv, **kwargs):
        self.calls.append("prepare")
        assert tuple(argv) == _spec().argv
        assert kwargs["cwd"] == "/workspace"
        assert kwargs["env"] == {}
        return self.prepared


def _verification_controller() -> VerificationController:
    return VerificationController(VerifierRegistry((_spec(),)))


@pytest.mark.parametrize(
    ("exit_code", "classification", "failure"),
    [
        (0, VerificationClassification.PASS, None),
        (1, VerificationClassification.FAIL, FailureClassification.VERIFICATION_FAILURE),
        (70, VerificationClassification.INFRASTRUCTURE_ERROR, FailureClassification.TERMINAL_INFRASTRUCTURE_FAILURE),
    ],
)
def test_controller_classifies_measured_exit_by_registered_policy(
    exit_code, classification, failure
) -> None:
    checkpoint = FakeCheckpoint("a" * 64)
    process = replace(
        _process_result(exit_code=exit_code),
        stdout="ok",
        stderr="",
        _stdout_bytes=b"ok",
        containment_state=ContainmentState.TERMINATED.value,
    )
    result = _verification_controller().verify(
        board=_board(status=TaskStatus.VERIFYING),
        dispatch=_dispatch(),
        checkpoint=checkpoint,
        verifier_id=_spec().verifier_id,
        runner=_VerifierRunner(_PreparedVerifier(process)),
        reservation=_reservation(),
        workspace_manager=FakeWorkspaceManager([_capture(checkpoint), _capture(checkpoint)]),
        repo_path=Path("/repo"),
    )
    assert result.classification is classification
    assert result.failure_classification is failure
    assert (result.failure_fingerprint is not None) is (
        classification is VerificationClassification.FAIL
    )
    assert result.checkpoint_digest == checkpoint.checkpoint_digest
    assert result.process_evidence is not None


@pytest.mark.parametrize(
    ("board", "dispatch", "checkpoint", "code"),
    [
        (_board(status=TaskStatus.IN_PROGRESS), _dispatch(), FakeCheckpoint("a" * 64), "STALE_IDENTITY"),
        (_board(status=TaskStatus.VERIFYING), _dispatch(task_generation=3), FakeCheckpoint("a" * 64), "STALE_IDENTITY"),
        (_board(status=TaskStatus.VERIFYING), _dispatch(), FakeCheckpoint("f" * 64), "CHECKPOINT_MISMATCH"),
    ],
)
def test_stale_or_mismatched_binding_is_rejected_before_verifier_launch(
    board, dispatch, checkpoint, code
) -> None:
    runner = _VerifierRunner(_PreparedVerifier(_process_result()))
    with pytest.raises(VerificationError, match=code):
        _verification_controller().verify(
            board=board,
            dispatch=dispatch,
            checkpoint=checkpoint,
            verifier_id=_spec().verifier_id,
            runner=runner,
            reservation=_reservation(),
            workspace_manager=FakeWorkspaceManager([]),
            repo_path=Path("/repo"),
        )
    assert runner.calls == []


def test_build_profile_is_rejected_before_readonly_stage_launch() -> None:
    runner = _VerifierRunner(_PreparedVerifier(_process_result()), profile=M4AProfile.BUILD)
    with pytest.raises(VerificationError, match="READONLY_PROFILE_REQUIRED"):
        _verification_controller().verify(
            board=_board(status=TaskStatus.VERIFYING), dispatch=_dispatch(),
            checkpoint=FakeCheckpoint("a" * 64), verifier_id=_spec().verifier_id,
            runner=runner, reservation=_reservation(),
            workspace_manager=FakeWorkspaceManager([]), repo_path=Path("/repo"),
        )
    assert runner.calls == []


def test_readonly_workspace_change_is_security_failure_not_semantic_repair() -> None:
    before = FakeCheckpoint("a" * 64)
    changed = FakeCheckpoint("f" * 64)
    result = _verification_controller().verify(
        board=_board(status=TaskStatus.VERIFYING), dispatch=_dispatch(), checkpoint=before,
        verifier_id=_spec().verifier_id,
        runner=_VerifierRunner(_PreparedVerifier(_process_result(exit_code=1))),
        reservation=_reservation(),
        workspace_manager=FakeWorkspaceManager([_capture(changed), _capture(changed)]),
        repo_path=Path("/repo"),
    )
    assert result.classification is VerificationClassification.INFRASTRUCTURE_ERROR
    assert result.failure_classification is FailureClassification.WORKSPACE_MUTATION_DURING_READONLY_STAGE
    assert result.failure_fingerprint is None


def test_timeout_output_limit_and_late_pass_after_cancel_are_infrastructure_failures() -> None:
    checkpoint = FakeCheckpoint("a" * 64)
    cases = [
        (
            replace(_process_result(exit_code=None, timed_out=True), containment_state=ContainmentState.TERMINATED.value),
            None,
            FailureClassification.TIMEOUT,
        ),
        (
            replace(_process_result(), output_limit_exceeded=True, containment_state=ContainmentState.TERMINATED.value),
            None,
            FailureClassification.TERMINAL_INFRASTRUCTURE_FAILURE,
        ),
    ]
    for process, on_wait, expected in cases:
        result = _verification_controller().verify(
            board=_board(status=TaskStatus.VERIFYING), dispatch=_dispatch(), checkpoint=checkpoint,
            verifier_id=_spec().verifier_id,
            runner=_VerifierRunner(_PreparedVerifier(process, on_wait=on_wait)),
            reservation=_reservation(),
            workspace_manager=FakeWorkspaceManager([_capture(checkpoint), _capture(checkpoint)]),
            repo_path=Path("/repo"),
        )
        assert result.classification is VerificationClassification.INFRASTRUCTURE_ERROR
        assert result.failure_classification is expected

    controller = _verification_controller()
    prepared = _PreparedVerifier(_process_result(exit_code=0), on_wait=controller.request_cancel)
    cancelled = controller.verify(
        board=_board(status=TaskStatus.VERIFYING), dispatch=_dispatch(), checkpoint=checkpoint,
        verifier_id=_spec().verifier_id, runner=_VerifierRunner(prepared),
        reservation=_reservation(),
        workspace_manager=FakeWorkspaceManager([_capture(checkpoint), _capture(checkpoint)]),
        repo_path=Path("/repo"),
    )
    assert cancelled.classification is VerificationClassification.INFRASTRUCTURE_ERROR
    assert cancelled.failure_classification is FailureClassification.CANCELLED


def test_receipt_command_mismatch_is_containment_failure_and_is_cancelled() -> None:
    checkpoint = FakeCheckpoint("a" * 64)
    prepared = _PreparedVerifier(
        _process_result(), receipt=replace(_receipt(), argv=("/usr/bin/python3", "/wrong.py"))
    )
    result = _verification_controller().verify(
        board=_board(status=TaskStatus.VERIFYING), dispatch=_dispatch(), checkpoint=checkpoint,
        verifier_id=_spec().verifier_id, runner=_VerifierRunner(prepared),
        reservation=_reservation(),
        workspace_manager=FakeWorkspaceManager([_capture(checkpoint), _capture(checkpoint)]),
        repo_path=Path("/repo"),
    )
    assert result.failure_classification is FailureClassification.CONTAINMENT_FAILURE
    assert prepared.cancelled is True


def test_non_utf8_verifier_output_is_bounded_digest_evidence_not_a_crash() -> None:
    checkpoint = FakeCheckpoint("a" * 64)
    process = replace(
        _process_result(exit_code=0),
        stdout="",
        _stdout_bytes=b"\xff",
        containment_state=ContainmentState.TERMINATED.value,
    )
    result = _verification_controller().verify(
        board=_board(status=TaskStatus.VERIFYING),
        dispatch=_dispatch(),
        checkpoint=checkpoint,
        verifier_id=_spec().verifier_id,
        runner=_VerifierRunner(_PreparedVerifier(process)),
        reservation=_reservation(),
        workspace_manager=FakeWorkspaceManager(
            [_capture(checkpoint), _capture(checkpoint)]
        ),
        repo_path=Path("/repo"),
    )
    assert result.classification is VerificationClassification.PASS
    assert result.stdout_byte_count == 1
    assert result.stdout_inline == "\ufffd"
