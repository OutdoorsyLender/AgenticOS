"""Durable split-phase execution binding and restart recovery tests."""

from __future__ import annotations

from dataclasses import dataclass, replace
import os
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from agenticos.orchestration.board import BoardSnapshot
from agenticos.orchestration.execution import (
    ExecutionError,
    ExecutionLedger,
    ExecutionOutcome,
    ExecutionState,
    SyntheticBuildController,
    create_containment_reservation,
)
from agenticos.orchestration.models import (
    BOARD_SCHEMA,
    BaselineIdentity,
    BoardTask,
    ProjectRecord,
    ProjectStatus,
    Role,
    RunLimits,
    TaskStatus,
    TaskType,
    WorkspaceIdentityRef,
)
from agenticos.orchestration.canonical import canonical_json_line
from agenticos.orchestration.protocol import (
    AGENT_PROTOCOL_SCHEMA,
    AgentCapability,
    AgentTaskRequest,
    DispatchIdentity,
    ProtocolLimits,
    ResultStatus,
)
from agenticos.orchestration.synthetic import (
    SyntheticScenario,
    build_synthetic_fixture,
)
from agenticos.orchestration.workspace import (
    WorkspaceLeaseAdmission,
    WorkspaceLeaseError,
    LEASE_IDENTITY_SCHEMA,
    WorkspaceLeaseIdentity,
    WorkspaceLeaseLedger,
    WorkspaceLeaseState,
)
from agenticos.sandbox.containment import (
    CancellationConfig,
    ContainmentState,
    ScopeEvidence,
    ScopeEvidenceState,
)
from agenticos.sandbox.models import (
    CONTAINMENT_RESERVATION_SCHEMA,
    PREPARED_PROCESS_RECEIPT_SCHEMA,
    ContainmentReservation,
    PreparedProcessReceipt,
    ProcessIdentity,
    ProcessResult,
)
from agenticos.sandbox.m4a_runner import NamespaceLandlockRunner
from agenticos.sandbox.worktree import (
    WorkspaceCaptureCompleteness,
    WorkspaceReuseDecision,
)


WORKSPACE = WorkspaceIdentityRef("workspace-c", 2, "reservation-c")


def _dispatch(**changes: object) -> DispatchIdentity:
    values: dict[str, object] = {
        "project_id": "project-c",
        "task_id": "build-c",
        "task_generation": 2,
        "attempt": 1,
        "controller_epoch": 4,
        "lease_epoch": 1,
        "dispatch_nonce": "1" * 32,
        "repository_id": "repo-c",
        "baseline_commit": "b" * 40,
        "workspace_id": WORKSPACE.workspace_id,
        "workspace_generation": WORKSPACE.generation,
        "reservation_id": WORKSPACE.reservation_id,
        "checkpoint_digest": "a" * 64,
    }
    values.update(changes)
    return DispatchIdentity(**values)  # type: ignore[arg-type]


def _lease_identity(**changes: object) -> WorkspaceLeaseIdentity:
    dispatch = _dispatch()
    values: dict[str, object] = {
        "schema": LEASE_IDENTITY_SCHEMA,
        "project_id": dispatch.project_id,
        "task_id": dispatch.task_id,
        "task_generation": dispatch.task_generation,
        "attempt": dispatch.attempt,
        "controller_epoch": dispatch.controller_epoch,
        "lease_epoch": dispatch.lease_epoch,
        "workspace": WORKSPACE,
        "dispatch_nonce": dispatch.dispatch_nonce,
        "pre_checkpoint_digest": dispatch.checkpoint_digest,
    }
    values.update(changes)
    return WorkspaceLeaseIdentity(**values)  # type: ignore[arg-type]


def _reservation(**changes: object) -> ContainmentReservation:
    dispatch = _dispatch()
    values: dict[str, object] = {
        "schema": CONTAINMENT_RESERVATION_SCHEMA,
        "project_id": dispatch.project_id,
        "task_id": dispatch.task_id,
        "task_generation": dispatch.task_generation,
        "attempt": dispatch.attempt,
        "controller_epoch": dispatch.controller_epoch,
        "lease_epoch": dispatch.lease_epoch,
        "dispatch_nonce": dispatch.dispatch_nonce,
        "unit_name": "aos-task-project-c-build-c-2-1-1",
        "release_nonce": "2" * 32,
    }
    values.update(changes)
    return ContainmentReservation(**values)  # type: ignore[arg-type]


def _receipt(**changes: object) -> PreparedProcessReceipt:
    reservation = _reservation()
    values: dict[str, object] = {
        "schema": PREPARED_PROCESS_RECEIPT_SCHEMA,
        "reservation": reservation,
        "process_identity": ProcessIdentity(222, 222, 333, "boot-c"),
        "cgroup_path": "/sys/fs/cgroup/user.slice/" + reservation.scope_name,
        "child_cgroup": "/user.slice/" + reservation.scope_name,
        "namespace_ids": (("ipc", 1), ("mnt", 2), ("net", 3), ("pid", 4), ("user", 5), ("uts", 6)),
        "policy_digest": "c" * 64,
        "workspace_destination": "/workspace",
        "workspace_device": 10,
        "workspace_inode": 20,
        "workspace_file_type": 0o040000,
        "executable": "/usr/bin/python3",
        "argv": ("/usr/bin/python3", "/opt/agenticos/worker.py"),
        "prepared_at": "2026-08-14T12:00:00+00:00",
    }
    values.update(changes)
    return PreparedProcessReceipt(**values)  # type: ignore[arg-type]


def _board(**task_changes: object) -> BoardSnapshot:
    project = ProjectRecord(
        BOARD_SCHEMA,
        "project-c",
        "Execute one synthetic build.",
        BaselineIdentity("repo-c", "b" * 40),
        WORKSPACE,
        ProjectStatus.ACTIVE,
        None,
        3,
        4,
        1,
        RunLimits(),
        1,
        100_000,
        1,
        "d" * 64,
    )
    values: dict[str, object] = {
        "schema": BOARD_SCHEMA,
        "task_id": "build-c",
        "project_id": "project-c",
        "title": "Build synthetic fixture",
        "description": "Mutate one controlled workspace.",
        "task_type": TaskType.BUILD,
        "priority": 50,
        "dependencies": (),
        "acceptance_criteria": ("Workspace edit is captured.",),
        "preferred_role": Role.BUILDER,
        "assigned_role": Role.BUILDER,
        "status": TaskStatus.IN_PROGRESS,
        "attempt_count": 1,
        "max_attempts": 3,
        "creation_sequence": 1,
        "creator": "CONTROLLER",
        "parent_task_id": None,
        "root_task_id": "build-c",
        "generation": 2,
        "workspace": WORKSPACE,
        "lease_epoch": 1,
        "block_reason": None,
        "terminal_reason": None,
        "repair_failure_fingerprint": None,
        "satisfying_descendant_id": None,
        "verification_result_digest": None,
        "review_result_digest": None,
    }
    values.update(task_changes)
    return BoardSnapshot.create(project, (BoardTask(**values),))  # type: ignore[arg-type]


@dataclass(frozen=True)
class FakeCheckpoint:
    checkpoint_digest: str
    repository_id: str = "repo-c"
    task_id: str = "build-c"
    generation: int = 2
    baseline_commit_sha: str = "b" * 40
    reservation_digest: str = "reservation-c"
    worktree_device: int = 10
    worktree_inode: int = 20
    capture_completeness: WorkspaceCaptureCompleteness = WorkspaceCaptureCompleteness.COMPLETE


def _capture(checkpoint: FakeCheckpoint):
    return SimpleNamespace(
        decision=WorkspaceReuseDecision.REUSABLE,
        checkpoint=checkpoint,
        failure=None,
    )


def _process_result(*, exit_code: int | None = 0, timed_out: bool = False) -> ProcessResult:
    return ProcessResult(
        pid=111,
        argv=["/usr/bin/python3", "/opt/agenticos/worker.py"],
        exit_code=exit_code,
        signal=None if exit_code is not None else 9,
        stdout="",
        stderr="",
        timed_out=timed_out,
        started_at="start",
        finished_at="finish",
        process_group_id=111,
        identity=ProcessIdentity(111, 111, 123, "boot-c"),
        containment_unit=_reservation().scope_name,
        containment_cgroup=_receipt().cgroup_path,
        containment_state=ContainmentState.TERMINATED.value,
    )


def _agent_request() -> AgentTaskRequest:
    return AgentTaskRequest(
        schema=AGENT_PROTOCOL_SCHEMA,
        identity=_dispatch(),
        role=Role.BUILDER,
        provider_id="synthetic",
        model_id="deterministic-workspace-v1",
        workspace_mount="/workspace",
        instructions="Run one deterministic Slice C scenario.",
        acceptance_criteria=("Stable checkpoint is captured.",),
        context_manifest=(),
        capabilities=(AgentCapability.READ_WORKSPACE, AgentCapability.WRITE_WORKSPACE),
        limits=ProtocolLimits(
            max_events=16,
            max_event_bytes=16_384,
            max_output_bytes=131_072,
            max_context_entries=1,
            max_context_bytes=1024,
            max_processes=4,
            max_runtime_seconds=10,
        ),
    )


class FakePrepared:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls
        self.receipt = _receipt()
        self.terminal = False
        self.released = False
        self.cleanup_proven = False

    def release(self, receipt, nonce) -> None:
        assert receipt == self.receipt
        assert nonce == self.receipt.reservation.release_nonce
        self.calls.append("release")
        self.released = True

    def wait(self, timeout=None, **_kwargs) -> ProcessResult:
        self.calls.append("wait")
        self.terminal = True
        return _process_result()

    def cancel(self) -> ProcessResult:
        self.calls.append("cancel")
        self.terminal = True
        return _process_result(exit_code=None)

    def request_cancel(self) -> None:
        self.calls.append("signal")


class FakeRunner:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls
        self.prepared = FakePrepared(calls)

    def prepare(self, argv, **kwargs):
        assert kwargs["reservation"] == _reservation()
        self.calls.append("prepare")
        return self.prepared


class FakeWorkspaceManager:
    def __init__(self, captures) -> None:
        self.captures = list(captures)
        self.calls = 0

    def capture_checkpoint(self, repo_path, task_id, generation):
        self.calls += 1
        return self.captures.pop(0)


def _active_lease(tmp_path) -> WorkspaceLeaseLedger:
    ledger = WorkspaceLeaseLedger(tmp_path / "leases", "project-c")
    identity = _lease_identity()
    admission = WorkspaceLeaseAdmission.issue(
        board=_board(),
        identity=identity,
        checkpoint_capture=_capture(FakeCheckpoint("a" * 64)),
    )
    ledger.acquire(identity, admission)
    return ledger


def _record_started(ledger: ExecutionLedger):
    reserved = ledger.record_containment_reserved(
        _lease_identity(), _reservation()
    )
    return ledger.record_process_started(
        _lease_identity(), _receipt(), expected=reserved
    )


def test_execution_ledger_persists_exact_process_receipt_and_hash_chain(tmp_path) -> None:
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    reserved = ledger.record_containment_reserved(_lease_identity(), _reservation())
    assert reserved.state is ExecutionState.CONTAINMENT_RESERVED
    started = ledger.record_process_started(
        _lease_identity(), _receipt(), expected=reserved
    )
    assert started.state is ExecutionState.PROCESS_STARTED
    assert started.receipt == _receipt()
    released = ledger.append(ExecutionState.RELEASED, expected=started)
    assert released.previous_record_digest == started.record_digest
    assert ExecutionLedger(tmp_path / "execution", _dispatch()).recover() == released

    with pytest.raises(ExecutionError, match="EXECUTION_ALREADY_RECORDED"):
        ledger.record_containment_reserved(_lease_identity(), _reservation())


def test_execution_ledger_rejects_mismatched_binding_without_controller(tmp_path) -> None:
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    with pytest.raises(ExecutionError, match="DISPATCH_BINDING_MISMATCH"):
        ledger.record_containment_reserved(
            replace(_lease_identity(), dispatch_nonce="f" * 32), _reservation()
        )
    assert ledger.recover() is None


def test_execution_storage_leaf_is_windows_safe_for_legal_colon_identifiers(tmp_path) -> None:
    dispatch = _dispatch(project_id="project:c", task_id="build:c")
    ledger = ExecutionLedger(tmp_path / "execution", dispatch)
    assert ":" not in ledger.root.name
    assert ledger.root.name.startswith("execution-")


def test_controller_reservation_factory_is_bound_and_cryptographically_unique() -> None:
    first = create_containment_reservation(_dispatch())
    second = create_containment_reservation(_dispatch())
    assert first != second
    assert first.unit_name != second.unit_name
    assert first.release_nonce != second.release_nonce
    assert first.project_id == _dispatch().project_id
    assert first.dispatch_nonce == _dispatch().dispatch_nonce


def test_controller_orders_durable_receipt_before_release_and_wait(tmp_path) -> None:
    calls: list[str] = []
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch(), write_observer=lambda state: calls.append("durable:" + state.value))
    controller = SyntheticBuildController(ledger)
    runner = FakeRunner(calls)
    lease = _active_lease(tmp_path)
    checkpoint = FakeCheckpoint("a" * 64)
    manager = FakeWorkspaceManager([_capture(checkpoint), _capture(checkpoint)])

    outcome = controller.execute(
        board=_board(),
        dispatch=_dispatch(),
        lease_ledger=lease,
        pre_checkpoint=checkpoint,
        runner=runner,
        reservation=_reservation(),
        argv=["/usr/bin/python3", "/opt/agenticos/worker.py"],
        workspace_manager=manager,
        repo_path=Path("/synthetic/repo"),
        timeout=5.0,
    )

    assert calls[:5] == [
        "durable:CONTAINMENT_RESERVED",
        "prepare",
        "durable:PROCESS_STARTED",
        "release",
        "durable:RELEASED",
    ]
    assert calls[5:7] == ["wait", "durable:PROCESS_TERMINATED"]
    assert outcome.process_result.exit_code == 0
    assert outcome.first_checkpoint == outcome.second_checkpoint == checkpoint
    assert ledger.recover().state is ExecutionState.TERMINAL_CAPTURED
    assert lease.recover().state is WorkspaceLeaseState.RELEASED


def test_wait_failure_after_proven_drain_still_captures_terminal_workspace(
    tmp_path,
) -> None:
    calls: list[str] = []
    runner = FakeRunner(calls)

    def failed_wait(timeout=None, **_kwargs):
        runner.prepared.cleanup_proven = True
        runner.prepared.terminal = True
        raise RuntimeError("wait failed after complete cleanup")

    runner.prepared.wait = failed_wait  # type: ignore[method-assign]
    checkpoint = FakeCheckpoint("a" * 64)
    lease = _active_lease(tmp_path)
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())

    with pytest.raises(
        ExecutionError, match="PROCESS_WAIT_FAILED_AFTER_PROVEN_DRAIN"
    ):
        SyntheticBuildController(ledger).execute(
            board=_board(),
            dispatch=_dispatch(),
            lease_ledger=lease,
            pre_checkpoint=checkpoint,
            runner=runner,
            reservation=_reservation(),
            argv=["/usr/bin/python3"],
            workspace_manager=FakeWorkspaceManager(
                [_capture(checkpoint), _capture(checkpoint)]
            ),
            repo_path=Path("/repo"),
            timeout=5.0,
        )

    assert ledger.recover().state is ExecutionState.TERMINAL_CAPTURED
    assert ledger.records()[-2].terminal_status == "FAILED"
    assert lease.recover().state is WorkspaceLeaseState.RELEASED


def test_wait_failure_with_ambiguous_cleanup_fences_execution_and_lease(
    tmp_path,
) -> None:
    calls: list[str] = []
    runner = FakeRunner(calls)

    def failed_wait(timeout=None, **_kwargs):
        raise RuntimeError("cleanup could not be proven")

    runner.prepared.wait = failed_wait  # type: ignore[method-assign]
    lease = _active_lease(tmp_path)
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())

    with pytest.raises(ExecutionError, match="PROCESS_WAIT_FAILED"):
        SyntheticBuildController(ledger).execute(
            board=_board(),
            dispatch=_dispatch(),
            lease_ledger=lease,
            pre_checkpoint=FakeCheckpoint("a" * 64),
            runner=runner,
            reservation=_reservation(),
            argv=["/usr/bin/python3"],
            workspace_manager=FakeWorkspaceManager([]),
            repo_path=Path("/repo"),
            timeout=5.0,
        )

    assert ledger.recover().state is ExecutionState.RECOVERY_REQUIRED
    assert lease.recover().state is WorkspaceLeaseState.RECOVERY_REQUIRED


def test_receipt_persistence_failure_cancels_before_release_and_requires_unchanged_workspace(tmp_path, monkeypatch) -> None:
    calls: list[str] = []
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    controller = SyntheticBuildController(ledger)
    runner = FakeRunner(calls)
    lease = _active_lease(tmp_path)
    checkpoint = FakeCheckpoint("a" * 64)
    manager = FakeWorkspaceManager([_capture(checkpoint), _capture(checkpoint)])

    monkeypatch.setattr(ledger, "record_process_started", lambda *args, **kwargs: (_ for _ in ()).throw(ExecutionError("DURABLE_WRITE_FAILED")))
    with pytest.raises(ExecutionError, match="PROCESS_RECEIPT_PERSISTENCE_FAILED"):
        controller.execute(
            board=_board(), dispatch=_dispatch(), lease_ledger=lease,
            pre_checkpoint=checkpoint, runner=runner, reservation=_reservation(),
            argv=["/usr/bin/python3"], workspace_manager=manager,
            repo_path=Path("/synthetic/repo"), timeout=5.0,
        )

    assert calls == ["prepare", "cancel"]
    assert lease.recover().state is WorkspaceLeaseState.CANCELLED


def test_persistence_failure_with_workspace_change_fails_closed_recovery_required(tmp_path, monkeypatch) -> None:
    calls: list[str] = []
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    controller = SyntheticBuildController(ledger)
    runner = FakeRunner(calls)
    lease = _active_lease(tmp_path)
    pre = FakeCheckpoint("a" * 64)
    changed = FakeCheckpoint("f" * 64)
    manager = FakeWorkspaceManager([_capture(changed), _capture(changed)])
    monkeypatch.setattr(ledger, "record_process_started", lambda *args, **kwargs: (_ for _ in ()).throw(ExecutionError("DURABLE_WRITE_FAILED")))

    with pytest.raises(ExecutionError, match="WORKSPACE_CHANGED_BEFORE_DURABLE_RELEASE"):
        controller.execute(
            board=_board(), dispatch=_dispatch(), lease_ledger=lease,
            pre_checkpoint=pre, runner=runner, reservation=_reservation(),
            argv=["/usr/bin/python3"], workspace_manager=manager,
            repo_path=Path("/synthetic/repo"), timeout=5.0,
        )
    assert lease.recover().state is WorkspaceLeaseState.RECOVERY_REQUIRED


def test_lease_cancellation_between_receipt_and_release_never_executes_payload(
    tmp_path,
) -> None:
    calls: list[str] = []
    lease = _active_lease(tmp_path)

    def observer(state: ExecutionState) -> None:
        calls.append("durable:" + state.value)
        if state is ExecutionState.PROCESS_STARTED:
            lease.begin_cancellation(
                _lease_identity(), reason="owner cancelled before release"
            )

    ledger = ExecutionLedger(
        tmp_path / "execution", _dispatch(), write_observer=observer
    )
    checkpoint = FakeCheckpoint("a" * 64)
    outcome = SyntheticBuildController(ledger).execute(
        board=_board(),
        dispatch=_dispatch(),
        lease_ledger=lease,
        pre_checkpoint=checkpoint,
        runner=FakeRunner(calls),
        reservation=_reservation(),
        argv=["/usr/bin/python3"],
        workspace_manager=FakeWorkspaceManager(
            [_capture(checkpoint), _capture(checkpoint)]
        ),
        repo_path=Path("/repo"),
        timeout=5.0,
    )

    assert "release" not in calls
    assert "cancel" in calls
    assert outcome.terminal_record.state is ExecutionState.TERMINAL_CAPTURED
    assert ledger.records()[-2].terminal_status == "CANCELLED"
    assert lease.recover().state is WorkspaceLeaseState.CANCELLED


def test_process_aware_cancellation_commits_before_signal_and_terminalizes(
    tmp_path,
) -> None:
    calls: list[str] = []
    entered_wait = threading.Event()
    cancelled = threading.Event()
    finish_wait = threading.Event()

    class BlockingPrepared(FakePrepared):
        def wait(self, timeout=None, **_kwargs):
            calls.append("wait")
            entered_wait.set()
            assert cancelled.wait(2.0)
            assert finish_wait.wait(2.0)
            self.terminal = True
            return _process_result(exit_code=None)

        def request_cancel(self):
            calls.append("signal")
            cancelled.set()

    runner = FakeRunner(calls)
    runner.prepared = BlockingPrepared(calls)
    checkpoint = FakeCheckpoint("a" * 64)
    lease = _active_lease(tmp_path)
    ledger = ExecutionLedger(
        tmp_path / "execution",
        _dispatch(),
        write_observer=lambda state: calls.append("durable:" + state.value),
    )
    controller = SyntheticBuildController(ledger)
    outcome: list[ExecutionOutcome] = []

    def execute() -> None:
        outcome.append(
            controller.execute(
                board=_board(),
                dispatch=_dispatch(),
                lease_ledger=lease,
                pre_checkpoint=checkpoint,
                runner=runner,
                reservation=_reservation(),
                argv=["/usr/bin/python3"],
                workspace_manager=FakeWorkspaceManager(
                    [_capture(checkpoint), _capture(checkpoint)]
                ),
                repo_path=Path("/repo"),
                timeout=5.0,
            )
        )

    thread = threading.Thread(target=execute)
    thread.start()
    assert entered_wait.wait(2.0)
    cancellation = controller.request_cancel(reason="owner cancellation")
    repeated = controller.request_cancel(reason="repeated owner cancellation")
    assert lease.recover().state is WorkspaceLeaseState.CANCELLING
    finish_wait.set()
    thread.join(2.0)

    assert not thread.is_alive()
    assert cancellation.state is ExecutionState.CANCEL_REQUESTED
    assert repeated == cancellation
    assert calls.index("signal") > calls.index("wait")
    assert calls.index("signal") > calls.index("durable:CANCEL_REQUESTED")
    assert outcome[0].terminal_record.state is ExecutionState.TERMINAL_CAPTURED
    assert ledger.records()[-2].terminal_status == "CANCELLED"
    assert lease.recover().state is WorkspaceLeaseState.CANCELLED


def test_output_overflow_commits_cancellation_and_cannot_be_late_success(
    tmp_path,
) -> None:
    calls: list[str] = []
    runner = FakeRunner(calls)

    def overflow_wait(timeout=None, *, cancellation_observer, **_kwargs):
        cancellation_observer()
        return replace(_process_result(), output_limit_exceeded=True)

    runner.prepared.wait = overflow_wait  # type: ignore[method-assign]
    checkpoint = FakeCheckpoint("a" * 64)
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())

    SyntheticBuildController(ledger).execute(
        board=_board(),
        dispatch=_dispatch(),
        lease_ledger=_active_lease(tmp_path),
        pre_checkpoint=checkpoint,
        runner=runner,
        reservation=_reservation(),
        argv=["/usr/bin/python3"],
        workspace_manager=FakeWorkspaceManager(
            [_capture(checkpoint), _capture(checkpoint)]
        ),
        repo_path=Path("/repo"),
        timeout=5.0,
        request=_agent_request(),
    )

    assert ExecutionState.CANCEL_REQUESTED in [item.state for item in ledger.records()]
    assert ledger.records()[-2].terminal_status == "CANCELLED"


@pytest.mark.skipif(os.name == "nt", reason="M4A pipe draining is Linux-native")
def test_hostile_stdout_stderr_are_incrementally_bounded_before_reap() -> None:
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import os; os.write(1, b'x' * 2000000); os.write(2, b'y' * 2000000)",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, stderr, overflow = (
            NamespaceLandlockRunner._communicate_process_bounded(
                process, 5.0, 4096
            )
        )
        assert overflow is True
        assert len(stdout) + len(stderr) == 4096
    finally:
        process.kill()
        process.communicate(timeout=5.0)


def test_process_aware_cancel_immediately_before_release_never_uses_unbound_state(
    tmp_path, monkeypatch
) -> None:
    calls: list[str] = []
    lease = _active_lease(tmp_path)
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    controller = SyntheticBuildController(ledger)
    original_authorize = lease.authorize_execution

    def cancel_then_authorize(identity, callback):
        controller.request_cancel(reason="cancel at release fence")
        return original_authorize(identity, callback)

    monkeypatch.setattr(lease, "authorize_execution", cancel_then_authorize)
    checkpoint = FakeCheckpoint("a" * 64)
    outcome = controller.execute(
        board=_board(),
        dispatch=_dispatch(),
        lease_ledger=lease,
        pre_checkpoint=checkpoint,
        runner=FakeRunner(calls),
        reservation=_reservation(),
        argv=["/usr/bin/python3"],
        workspace_manager=FakeWorkspaceManager(
            [_capture(checkpoint), _capture(checkpoint)]
        ),
        repo_path=Path("/repo"),
        timeout=5.0,
    )

    assert "release" not in calls
    assert "signal" in calls
    assert outcome.terminal_record.state is ExecutionState.TERMINAL_CAPTURED
    assert ledger.records()[-2].terminal_status == "CANCELLED"


def test_terminal_capture_failure_marks_execution_and_lease_recovery_required(tmp_path) -> None:
    calls: list[str] = []
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    lease = _active_lease(tmp_path)
    failed_capture = SimpleNamespace(
        decision=WorkspaceReuseDecision.CAPTURE_FAILED,
        checkpoint=None,
        failure=SimpleNamespace(kind="SYNTHETIC"),
    )

    with pytest.raises(ExecutionError, match="TERMINAL_CHECKPOINT_INCOMPLETE"):
        SyntheticBuildController(ledger).execute(
            board=_board(), dispatch=_dispatch(), lease_ledger=lease,
            pre_checkpoint=FakeCheckpoint("a" * 64), runner=FakeRunner(calls),
            reservation=_reservation(), argv=["/usr/bin/python3"],
            workspace_manager=FakeWorkspaceManager([failed_capture]),
            repo_path=Path("/repo"), timeout=5.0,
        )

    assert ledger.recover().state is ExecutionState.RECOVERY_REQUIRED
    assert lease.recover().state is WorkspaceLeaseState.RECOVERY_REQUIRED


def test_restart_reconciles_lease_after_terminal_record_persisted_first(
    tmp_path, monkeypatch
) -> None:
    calls: list[str] = []
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    lease = _active_lease(tmp_path)
    checkpoint = FakeCheckpoint("a" * 64)
    controller = SyntheticBuildController(ledger)
    original_release = lease.release

    def fail_release(*_args, **_kwargs):
        raise WorkspaceLeaseError("DURABLE_LEASE_WRITE_FAILED")

    monkeypatch.setattr(lease, "release", fail_release)
    with pytest.raises(WorkspaceLeaseError, match="DURABLE_LEASE_WRITE_FAILED"):
        controller.execute(
            board=_board(),
            dispatch=_dispatch(),
            lease_ledger=lease,
            pre_checkpoint=checkpoint,
            runner=FakeRunner(calls),
            reservation=_reservation(),
            argv=["/usr/bin/python3"],
            workspace_manager=FakeWorkspaceManager(
                [_capture(checkpoint), _capture(checkpoint)]
            ),
            repo_path=Path("/repo"),
            timeout=5.0,
        )
    assert ledger.recover().state is ExecutionState.TERMINAL_CAPTURED
    assert lease.recover().state is WorkspaceLeaseState.EXECUTING

    monkeypatch.setattr(lease, "release", original_release)
    recovered = controller.recover(
        backend=FakeBackend(exact_cgroup=None, populated=None),
        cancellation=CancellationConfig(0.01, 0.01, 0.05, 0.001),
        lease_ledger=lease,
        workspace_manager=FakeWorkspaceManager([]),
        repo_path=Path("/repo"),
        pre_checkpoint=checkpoint,
        proc_root=tmp_path / "empty-proc",
    )

    assert recovered.state is ExecutionState.TERMINAL_CAPTURED
    assert lease.recover().state is WorkspaceLeaseState.RELEASED


@pytest.mark.parametrize(
    "board",
    [
        _board(status=TaskStatus.READY, attempt_count=0),
        _board(attempt_count=2),
        _board(lease_epoch=2),
        _board(generation=3),
    ],
)
def test_dispatch_board_lease_and_precheckpoint_must_bind_before_prepare(tmp_path, board) -> None:
    calls: list[str] = []
    controller = SyntheticBuildController(ExecutionLedger(tmp_path / "execution", _dispatch()))
    with pytest.raises(ExecutionError, match="DISPATCH_BINDING_MISMATCH"):
        controller.execute(
            board=board, dispatch=_dispatch(), lease_ledger=_active_lease(tmp_path),
            pre_checkpoint=FakeCheckpoint("a" * 64), runner=FakeRunner(calls),
            reservation=_reservation(), argv=["/usr/bin/python3"],
            workspace_manager=FakeWorkspaceManager([]), repo_path=Path("/repo"),
            timeout=5.0,
        )
    assert calls == []


class FakeBackend:
    def __init__(
        self,
        *,
        exact_cgroup: bool | None = True,
        populated: bool | None = True,
        scope_unknown: bool = False,
    ) -> None:
        self.exact_cgroup = exact_cgroup
        self.populated = populated
        self.scope_unknown = scope_unknown
        self.signals: list[str] = []

    def scope_evidence(self, unit):
        if self.scope_unknown:
            return ScopeEvidence(ScopeEvidenceState.UNKNOWN, None, "injected")
        if self.exact_cgroup is None:
            return ScopeEvidence(ScopeEvidenceState.ABSENT, None, "injected")
        path = Path(
            _receipt().cgroup_path
            if self.exact_cgroup
            else "/sys/fs/cgroup/wrong.scope"
        )
        return ScopeEvidence(ScopeEvidenceState.PRESENT, path, "injected")

    def control_group(self, unit):
        if self.exact_cgroup is None:
            return None
        return Path(_receipt().cgroup_path if self.exact_cgroup else "/sys/fs/cgroup/wrong.scope")

    def cgroup_populated(self, path):
        return self.populated

    def signal_unit(self, unit, sig):
        self.signals.append(sig)
        self.populated = False

    def cgroup_kill(self, path):
        self.populated = False
        return True

    def stop_unit(self, unit):
        self.exact_cgroup = None


def _recovery_evidence(tmp_path):
    checkpoint = FakeCheckpoint("a" * 64)
    return {
        "lease_ledger": _active_lease(tmp_path),
        "workspace_manager": FakeWorkspaceManager(
            [_capture(checkpoint), _capture(checkpoint)]
        ),
        "repo_path": Path("/repo"),
        "pre_checkpoint": checkpoint,
    }


def test_restart_reconciles_exact_live_identity_without_redispatch_and_cancellation_wins(tmp_path, monkeypatch) -> None:
    dispatch = _dispatch()
    ledger = ExecutionLedger(tmp_path / "execution", dispatch)
    _record_started(ledger)
    ledger.append(ExecutionState.RELEASED, expected=ledger.recover())
    controller = SyntheticBuildController(ledger)
    backend = FakeBackend()
    monkeypatch.setattr(ProcessIdentity, "matches_current", lambda self, proc_root="/proc": True)
    proc_root = tmp_path / "proc"
    (proc_root / "222").mkdir(parents=True)
    (proc_root / "222" / "stat").write_text("synthetic stat evidence\n")
    (proc_root / "222" / "cgroup").write_text(
        "0::" + _receipt().child_cgroup + "\n"
    )

    recovered = controller.recover(
        backend=backend,
        cancellation=CancellationConfig(0.01, 0.01, 0.05, 0.001),
        proc_root=proc_root,
        **_recovery_evidence(tmp_path),
    )

    assert recovered.state is ExecutionState.TERMINAL_CAPTURED
    assert ledger.records()[-2].terminal_status == "CANCELLED"
    assert backend.signals == ["SIGINT"]
    states = [record.state for record in ledger.records()]
    assert states[-3:] == [
        ExecutionState.CANCEL_REQUESTED,
        ExecutionState.PROCESS_TERMINATED,
        ExecutionState.TERMINAL_CAPTURED,
    ]


@pytest.mark.parametrize("exact_cgroup,identity_matches", [(False, True), (True, False)])
def test_restart_identity_or_cgroup_mismatch_fails_closed_without_signalling(
    tmp_path, monkeypatch, exact_cgroup: bool, identity_matches: bool
) -> None:
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    _record_started(ledger)
    controller = SyntheticBuildController(ledger)
    backend = FakeBackend(exact_cgroup=exact_cgroup)
    monkeypatch.setattr(ProcessIdentity, "matches_current", lambda self, proc_root="/proc": identity_matches)
    proc_root = tmp_path / "proc"
    (proc_root / "222").mkdir(parents=True)
    (proc_root / "222" / "stat").write_text("synthetic stat evidence\n")
    (proc_root / "222" / "cgroup").write_text(
        "0::" + _receipt().child_cgroup + "\n"
    )

    recovered = controller.recover(
        backend=backend,
        cancellation=CancellationConfig(0.01, 0.01, 0.05, 0.001),
        proc_root=proc_root,
        **_recovery_evidence(tmp_path),
    )

    assert recovered.state is ExecutionState.RECOVERY_REQUIRED
    assert backend.signals == []


def test_restart_process_cgroup_membership_mismatch_fails_closed_without_signal(
    tmp_path, monkeypatch
) -> None:
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    _record_started(ledger)
    controller = SyntheticBuildController(ledger)
    backend = FakeBackend()
    monkeypatch.setattr(ProcessIdentity, "matches_current", lambda self, proc_root="/proc": True)
    proc_root = tmp_path / "proc"
    (proc_root / "222").mkdir(parents=True)
    (proc_root / "222" / "stat").write_text("synthetic stat evidence\n")
    (proc_root / "222" / "cgroup").write_text("0::/user.slice/wrong.scope\n")

    recovered = controller.recover(
        backend=backend,
        cancellation=CancellationConfig(0.01, 0.01, 0.05, 0.001),
        proc_root=proc_root,
        **_recovery_evidence(tmp_path),
    )

    assert recovered.state is ExecutionState.RECOVERY_REQUIRED
    assert backend.signals == []


def test_restart_reconciles_provably_gone_pid_and_collected_cgroup_without_redispatch(
    tmp_path,
) -> None:
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    _record_started(ledger)
    backend = FakeBackend(exact_cgroup=None, populated=None)

    recovered = SyntheticBuildController(ledger).recover(
        backend=backend,
        cancellation=CancellationConfig(0.01, 0.01, 0.05, 0.001),
        proc_root=tmp_path / "empty-proc",
        **_recovery_evidence(tmp_path),
    )

    assert recovered.state is ExecutionState.TERMINAL_CAPTURED
    assert ledger.records()[-2].terminal_status == "FAILED"
    assert backend.signals == []


def test_restart_drains_orphan_descendants_in_exact_populated_scope_and_captures(
    tmp_path,
) -> None:
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    started = _record_started(ledger)
    ledger.append(ExecutionState.RELEASED, expected=started)
    backend = FakeBackend(exact_cgroup=True, populated=True)
    evidence = _recovery_evidence(tmp_path)

    recovered = SyntheticBuildController(ledger).recover(
        backend=backend,
        cancellation=CancellationConfig(0.01, 0.01, 0.05, 0.001),
        proc_root=tmp_path / "empty-proc",
        **evidence,
    )

    assert recovered.state is ExecutionState.TERMINAL_CAPTURED
    assert ledger.records()[-2].terminal_status == "CANCELLED"
    assert backend.signals
    assert backend.exact_cgroup is None
    assert evidence["lease_ledger"].recover().state is WorkspaceLeaseState.CANCELLED


def test_cancellation_intent_dominates_late_success_record(tmp_path) -> None:
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    started = _record_started(ledger)
    cancelled = ledger.append(ExecutionState.CANCEL_REQUESTED, expected=started, detail="owner cancel")

    terminal = ledger.append(
        ExecutionState.PROCESS_TERMINATED,
        expected=cancelled,
        terminal_status="SUCCEEDED",
    )

    assert terminal.terminal_status == "CANCELLED"


def test_restart_before_measured_receipt_drains_recorded_reservation_and_captures(
    tmp_path,
) -> None:
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    ledger.record_containment_reserved(_lease_identity(), _reservation())
    backend = FakeBackend(exact_cgroup=None, populated=None)
    evidence = _recovery_evidence(tmp_path)

    recovered = SyntheticBuildController(ledger).recover(
        backend=backend,
        cancellation=CancellationConfig(0.01, 0.01, 0.05, 0.001),
        proc_root=tmp_path / "empty-proc",
        **evidence,
    )

    assert recovered.state is ExecutionState.TERMINAL_CAPTURED
    assert ledger.records()[-2].terminal_status == "CANCELLED"
    assert evidence["lease_ledger"].recover().state is WorkspaceLeaseState.CANCELLED


def test_restart_before_receipt_with_ambiguous_cgroup_population_fails_closed(
    tmp_path,
) -> None:
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    ledger.record_containment_reserved(_lease_identity(), _reservation())
    evidence = _recovery_evidence(tmp_path)

    recovered = SyntheticBuildController(ledger).recover(
        backend=FakeBackend(exact_cgroup=True, populated=None),
        cancellation=CancellationConfig(0.01, 0.01, 0.05, 0.001),
        proc_root=tmp_path / "empty-proc",
        **evidence,
    )

    assert recovered.state is ExecutionState.RECOVERY_REQUIRED
    assert evidence["lease_ledger"].recover().state is WorkspaceLeaseState.RECOVERY_REQUIRED


def test_restart_before_receipt_with_unknown_scope_lookup_fails_closed(
    tmp_path,
) -> None:
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    ledger.record_containment_reserved(_lease_identity(), _reservation())
    evidence = _recovery_evidence(tmp_path)

    recovered = SyntheticBuildController(ledger).recover(
        backend=FakeBackend(scope_unknown=True),
        cancellation=CancellationConfig(0.01, 0.01, 0.05, 0.001),
        proc_root=tmp_path / "empty-proc",
        **evidence,
    )

    assert recovered.state is ExecutionState.RECOVERY_REQUIRED
    assert evidence["lease_ledger"].recover().state is WorkspaceLeaseState.RECOVERY_REQUIRED


def test_missing_process_with_existing_ambiguous_cgroup_fails_closed(
    tmp_path,
) -> None:
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    _record_started(ledger)
    evidence = _recovery_evidence(tmp_path)

    recovered = SyntheticBuildController(ledger).recover(
        backend=FakeBackend(exact_cgroup=True, populated=None),
        cancellation=CancellationConfig(0.01, 0.01, 0.05, 0.001),
        proc_root=tmp_path / "empty-proc",
        **evidence,
    )

    assert recovered.state is ExecutionState.RECOVERY_REQUIRED
    assert evidence["lease_ledger"].recover().state is WorkspaceLeaseState.RECOVERY_REQUIRED


def test_absent_scope_with_populated_recorded_cgroup_never_terminalizes(
    tmp_path,
) -> None:
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    _record_started(ledger)
    evidence = _recovery_evidence(tmp_path)

    recovered = SyntheticBuildController(ledger).recover(
        backend=FakeBackend(exact_cgroup=None, populated=True),
        cancellation=CancellationConfig(0.01, 0.01, 0.05, 0.001),
        proc_root=tmp_path / "empty-proc",
        **evidence,
    )

    assert recovered.state is ExecutionState.RECOVERY_REQUIRED
    assert evidence["lease_ledger"].recover().state is WorkspaceLeaseState.RECOVERY_REQUIRED


@pytest.mark.parametrize("delete_all", [False, True])
def test_execution_tail_rejects_suffix_or_all_record_deletion(
    tmp_path, delete_all: bool
) -> None:
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())
    started = _record_started(ledger)
    ledger.append(ExecutionState.RELEASED, expected=started)
    records = sorted(ledger.root.glob("*.execution.json"))
    for path in records if delete_all else records[-1:]:
        path.unlink()

    with pytest.raises(ExecutionError, match="EXECUTION_TAIL_ROLLBACK"):
        ledger.recover()


def test_controller_validates_exact_worker_bytes_and_binds_agent_result(tmp_path) -> None:
    request = _agent_request()
    fixture = build_synthetic_fixture(request, SyntheticScenario.NO_OP)
    assert fixture.result is not None
    raw = b"".join(fixture.events) + canonical_json_line(fixture.result.to_dict())
    process = replace(_process_result(), _stdout_bytes=raw)
    calls: list[str] = []
    runner = FakeRunner(calls)
    runner.prepared.wait = lambda timeout=None, **kwargs: process  # type: ignore[method-assign]
    checkpoint = FakeCheckpoint("a" * 64)
    controller = SyntheticBuildController(ExecutionLedger(tmp_path / "execution", _dispatch()))

    outcome = controller.execute(
        board=_board(), dispatch=_dispatch(), lease_ledger=_active_lease(tmp_path),
        pre_checkpoint=checkpoint, runner=runner, reservation=_reservation(),
        argv=["/usr/bin/python3"],
        workspace_manager=FakeWorkspaceManager([_capture(checkpoint), _capture(checkpoint)]),
        repo_path=Path("/repo"), timeout=5.0, request=request,
    )

    assert outcome.agent_result is not None
    assert outcome.agent_result.status is ResultStatus.NO_OP
    assert outcome.protocol_rejection_code is None


def test_malformed_worker_bytes_are_terminal_failure_not_success(tmp_path) -> None:
    process = replace(_process_result(), _stdout_bytes=b'{"invalid":\xff}\n')
    calls: list[str] = []
    runner = FakeRunner(calls)
    runner.prepared.wait = lambda timeout=None, **kwargs: process  # type: ignore[method-assign]
    checkpoint = FakeCheckpoint("a" * 64)
    ledger = ExecutionLedger(tmp_path / "execution", _dispatch())

    outcome = SyntheticBuildController(ledger).execute(
        board=_board(), dispatch=_dispatch(), lease_ledger=_active_lease(tmp_path),
        pre_checkpoint=checkpoint, runner=runner, reservation=_reservation(),
        argv=["/usr/bin/python3"],
        workspace_manager=FakeWorkspaceManager([_capture(checkpoint), _capture(checkpoint)]),
        repo_path=Path("/repo"), timeout=5.0, request=_agent_request(),
    )

    assert outcome.agent_result is None
    assert outcome.protocol_rejection_code is not None
    assert ledger.records()[-2].terminal_status == "FAILED"
