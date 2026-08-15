"""Durable exclusive fenced workspace lease contract."""

from __future__ import annotations

import concurrent.futures
from dataclasses import replace
import threading
from types import SimpleNamespace

import pytest

from agenticos.orchestration.models import TaskStatus, WorkspaceIdentityRef
from agenticos.sandbox.worktree import (
    WorkspaceCaptureCompleteness,
    WorkspaceReuseDecision,
)
from agenticos.orchestration.workspace import (
    LEASE_ADMISSION_SCHEMA,
    LEASE_IDENTITY_SCHEMA,
    WorkspaceLeaseAdmission,
    WorkspaceLeaseError,
    WorkspaceLeaseIdentity,
    WorkspaceLeaseLedger,
    WorkspaceLeaseState,
)


def _identity(*, lease_epoch: int = 1, controller_epoch: int = 4) -> WorkspaceLeaseIdentity:
    return WorkspaceLeaseIdentity(
        schema=LEASE_IDENTITY_SCHEMA,
        project_id="project-c",
        task_id="build-c",
        task_generation=2,
        attempt=1,
        controller_epoch=controller_epoch,
        lease_epoch=lease_epoch,
        workspace=WorkspaceIdentityRef("repo-workspace-c", 2, "reservation-c"),
        dispatch_nonce="1" * 32,
        pre_checkpoint_digest="a" * 64,
    )


def _admission(identity: WorkspaceLeaseIdentity) -> WorkspaceLeaseAdmission:
    return WorkspaceLeaseAdmission(
        LEASE_ADMISSION_SCHEMA,
        identity.project_id,
        identity.task_id,
        identity.task_generation,
        identity.attempt,
        identity.controller_epoch,
        identity.lease_epoch,
        identity.workspace,
        identity.dispatch_nonce,
        "repo-c",
        "b" * 40,
        identity.pre_checkpoint_digest,
        identity.workspace.reservation_id,
        1,
        2,
    )


def _acquire(
    ledger: WorkspaceLeaseLedger, identity: WorkspaceLeaseIdentity
):
    return ledger.acquire(identity, _admission(identity))


def _cancel(
    ledger: WorkspaceLeaseLedger, identity: WorkspaceLeaseIdentity
):
    ledger.begin_cancellation(identity, reason="cancellation started")
    return ledger.cancel(identity, reason="cancellation safely completed")


def test_lease_identity_is_strict_and_round_trips() -> None:
    identity = _identity()
    assert WorkspaceLeaseIdentity.from_dict(identity.to_dict()) == identity

    for changed in (
        {"lease_epoch": 0},
        {"attempt": 0},
        {"dispatch_nonce": "not-hex"},
        {"pre_checkpoint_digest": "a" * 63},
    ):
        with pytest.raises(ValueError):
            replace(identity, **changed)


def test_only_one_active_lease_and_epochs_are_monotonic(tmp_path) -> None:
    ledger = WorkspaceLeaseLedger(tmp_path, "project-c")
    first = _acquire(ledger, _identity())
    assert first.state is WorkspaceLeaseState.ACTIVE
    assert ledger.require_active(first.identity) == first

    with pytest.raises(WorkspaceLeaseError, match="LEASE_ALREADY_ACTIVE"):
        _acquire(ledger, replace(_identity(), task_id="other-task"))

    released = ledger.release(first.identity, reason="synthetic complete")
    assert released.state is WorkspaceLeaseState.RELEASED
    second_identity = _identity(lease_epoch=2, controller_epoch=5)
    second = _acquire(ledger, second_identity)
    assert second.state is WorkspaceLeaseState.ACTIVE
    assert second.previous_record_digest == released.record_digest

    with pytest.raises(WorkspaceLeaseError, match="LEASE_EPOCH_NOT_MONOTONIC"):
        ledger.begin_cancellation(
            replace(second_identity, lease_epoch=1), reason="forged"
        )


@pytest.mark.parametrize(
    ("operation", "state"),
    [
        ("release", WorkspaceLeaseState.RELEASED),
        ("mark_stale", WorkspaceLeaseState.STALE),
        ("require_recovery", WorkspaceLeaseState.RECOVERY_REQUIRED),
    ],
)
def test_exact_active_identity_controls_every_terminal_transition(
    tmp_path, operation: str, state: WorkspaceLeaseState
) -> None:
    ledger = WorkspaceLeaseLedger(tmp_path, "project-c")
    identity = _identity()
    _acquire(ledger, identity)
    forged = replace(identity, dispatch_nonce="f" * 32)

    with pytest.raises(WorkspaceLeaseError, match="LEASE_IDENTITY_MISMATCH"):
        getattr(ledger, operation)(forged, reason="forged")

    terminal = getattr(ledger, operation)(identity, reason="bounded reason")
    assert terminal.state is state
    assert terminal.reason == "bounded reason"
    with pytest.raises(WorkspaceLeaseError, match="LEASE_NOT_ACTIVE"):
        ledger.require_active(identity)


def test_recovery_validates_complete_immutable_hash_chain(tmp_path) -> None:
    ledger = WorkspaceLeaseLedger(tmp_path, "project-c")
    identity = _identity()
    _acquire(ledger, identity)
    cancelling = ledger.begin_cancellation(identity, reason="cancellation started")
    terminal = ledger.cancel(identity, reason="cancellation safely completed")

    recovered = WorkspaceLeaseLedger(tmp_path, "project-c").recover()
    assert recovered == terminal
    assert cancelling.state is WorkspaceLeaseState.CANCELLING
    assert recovered.previous_record_digest == cancelling.record_digest

    first_path = sorted((tmp_path / "project-c").glob("*.json"))[0]
    raw = bytearray(first_path.read_bytes())
    raw[raw.index(b"project-c")] = ord("P")
    first_path.write_bytes(bytes(raw))
    with pytest.raises(
        WorkspaceLeaseError,
        match="NONCANONICAL_OR_CORRUPT_RECORD|LEASE_RECORD_DIGEST_MISMATCH",
    ):
        ledger.recover()


def test_recovery_required_blocks_new_execution_authority(tmp_path) -> None:
    ledger = WorkspaceLeaseLedger(tmp_path, "project-c")
    identity = _identity()
    _acquire(ledger, identity)
    ledger.require_recovery(identity, reason="ambiguous process identity")

    with pytest.raises(WorkspaceLeaseError, match="RECOVERY_REQUIRED"):
        _acquire(ledger, _identity(lease_epoch=2, controller_epoch=5))


def test_wrong_project_workspace_or_epoch_fails_closed(tmp_path) -> None:
    ledger = WorkspaceLeaseLedger(tmp_path, "project-c")
    first = _identity()
    _acquire(ledger, first)
    ledger.release(first, reason="done")

    for candidate, code in (
        (replace(first, lease_epoch=2, project_id="project-d"), "PROJECT_IDENTITY_MISMATCH"),
        (replace(first, lease_epoch=2, workspace=WorkspaceIdentityRef("other", 2, "reservation-c")), "WORKSPACE_IDENTITY_MISMATCH"),
        (replace(first, lease_epoch=2, controller_epoch=3), "CONTROLLER_EPOCH_ROLLBACK"),
        (replace(first, lease_epoch=3, controller_epoch=5), "LEASE_EPOCH_NOT_MONOTONIC"),
    ):
        with pytest.raises(WorkspaceLeaseError, match=code):
            _acquire(ledger, candidate)


def test_concurrent_acquire_has_exactly_one_winner(tmp_path) -> None:
    def acquire(task_id: str) -> str:
        ledger = WorkspaceLeaseLedger(tmp_path, "project-c", lock_timeout=5.0)
        try:
            _acquire(ledger, replace(_identity(), task_id=task_id))
            return "won"
        except WorkspaceLeaseError as exc:
            return exc.code

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(acquire, ("build-one", "build-two")))

    assert sorted(outcomes) == ["LEASE_ALREADY_ACTIVE", "won"]


def test_record_and_diagnostic_bounds_fail_closed(tmp_path) -> None:
    ledger = WorkspaceLeaseLedger(tmp_path, "project-c", max_records=2, max_record_bytes=4096)
    identity = _identity()
    _acquire(ledger, identity)
    with pytest.raises(WorkspaceLeaseError, match="INVALID_REASON"):
        ledger.release(identity, reason="x" * 1025)
    ledger.release(identity, reason="done")
    with pytest.raises(WorkspaceLeaseError, match="LEASE_RECORD_LIMIT"):
        _acquire(ledger, _identity(lease_epoch=2, controller_epoch=5))


def test_unknown_files_and_truncated_records_are_not_ignored(tmp_path) -> None:
    ledger = WorkspaceLeaseLedger(tmp_path, "project-c")
    _acquire(ledger, _identity())
    lease_root = tmp_path / "project-c"
    (lease_root / "surprise.txt").write_text("ignored? no")
    with pytest.raises(WorkspaceLeaseError, match="UNKNOWN_LEASE_ENTRY"):
        ledger.recover()


@pytest.mark.parametrize("delete_all", [False, True])
def test_independent_tail_rejects_suffix_or_all_record_deletion(
    tmp_path, delete_all: bool
) -> None:
    ledger = WorkspaceLeaseLedger(tmp_path, "project-c")
    identity = _identity()
    _acquire(ledger, identity)
    _cancel(ledger, identity)
    records = sorted((tmp_path / "project-c").glob("*.lease.json"))
    for path in records if delete_all else records[-1:]:
        path.unlink()

    with pytest.raises(WorkspaceLeaseError, match="LEASE_TAIL_ROLLBACK"):
        ledger.recover()


def test_execution_authorization_is_durable_and_fenced_against_cancellation(
    tmp_path,
) -> None:
    ledger = WorkspaceLeaseLedger(tmp_path, "project-c")
    identity = _identity()
    _acquire(ledger, identity)
    seen: list[WorkspaceLeaseState] = []

    executing, value = ledger.authorize_execution(
        identity, lambda: seen.append(ledger._recover_unlocked().state) or "released"
    )

    assert value == "released"
    assert seen == [WorkspaceLeaseState.EXECUTING]
    assert executing.state is WorkspaceLeaseState.EXECUTING
    ledger.begin_cancellation(identity, reason="process-aware cancellation")
    ledger.cancel(identity, reason="process drain proven")
    assert ledger.recover().state is WorkspaceLeaseState.CANCELLED


def test_cancelling_lease_blocks_reacquire_through_callback_and_terminal_capture(
    tmp_path,
) -> None:
    ledger = WorkspaceLeaseLedger(tmp_path, "project-c", lock_timeout=2.0)
    identity = _identity()
    _acquire(ledger, identity)
    entered = threading.Event()
    finish = threading.Event()

    def drain() -> str:
        entered.set()
        assert finish.wait(2.0)
        return "drained"

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        cancellation = pool.submit(
            ledger.cancel_with_callback,
            identity,
            reason="owner cancellation",
            callback=drain,
        )
        assert entered.wait(2.0)
        reacquire = pool.submit(
            _acquire, ledger, _identity(lease_epoch=2, controller_epoch=5)
        )
        finish.set()
        cancelling, result = cancellation.result(timeout=2.0)
        with pytest.raises(WorkspaceLeaseError, match="LEASE_ALREADY_ACTIVE"):
            reacquire.result(timeout=2.0)

    assert result == "drained"
    assert cancelling.state is WorkspaceLeaseState.CANCELLING
    assert ledger.recover().state is WorkspaceLeaseState.CANCELLING
    with pytest.raises(WorkspaceLeaseError, match="LEASE_ALREADY_ACTIVE"):
        _acquire(ledger, _identity(lease_epoch=2, controller_epoch=5))
    ledger.cancel(identity, reason="terminal checkpoint captured")
    assert _acquire(
        ledger, _identity(lease_epoch=2, controller_epoch=5)
    ).state is WorkspaceLeaseState.ACTIVE


def test_cancel_callback_failure_durably_fences_lease_for_recovery(tmp_path) -> None:
    ledger = WorkspaceLeaseLedger(tmp_path, "project-c")
    identity = _identity()
    _acquire(ledger, identity)

    def failed_drain() -> None:
        raise RuntimeError("ambiguous drain")

    with pytest.raises(RuntimeError, match="ambiguous drain"):
        ledger.cancel_with_callback(
            identity,
            reason="owner cancellation",
            callback=failed_drain,
        )

    assert ledger.recover().state is WorkspaceLeaseState.RECOVERY_REQUIRED
    with pytest.raises(WorkspaceLeaseError, match="RECOVERY_REQUIRED"):
        _acquire(ledger, _identity(lease_epoch=2, controller_epoch=5))


def test_admission_issue_rejects_incomplete_or_mismatched_checkpoint() -> None:
    identity = _identity()
    task = SimpleNamespace(
        project_id=identity.project_id,
        task_id=identity.task_id,
        generation=identity.task_generation,
        attempt_count=identity.attempt,
        lease_epoch=identity.lease_epoch,
        workspace=identity.workspace,
    )
    project = SimpleNamespace(
        project_id=identity.project_id,
        controller_epoch=identity.controller_epoch,
        lease_epoch=identity.lease_epoch,
        workspace=identity.workspace,
        baseline=SimpleNamespace(repository_id="repo-c", commit_sha="b" * 40),
    )
    board = SimpleNamespace(project=project, task=lambda _task_id: task)
    checkpoint = SimpleNamespace(
        capture_completeness=WorkspaceCaptureCompleteness.INCOMPLETE,
        repository_id="repo-c",
        baseline_commit_sha="b" * 40,
        task_id=identity.task_id,
        generation=identity.task_generation,
        reservation_digest=identity.workspace.reservation_id,
        checkpoint_digest=identity.pre_checkpoint_digest,
        worktree_device=1,
        worktree_inode=2,
    )
    capture = SimpleNamespace(
        decision=WorkspaceReuseDecision.REUSABLE, checkpoint=checkpoint
    )

    with pytest.raises(WorkspaceLeaseError, match="LEASE_ADMISSION_EVIDENCE_MISMATCH"):
        WorkspaceLeaseAdmission.issue(
            board=board, identity=identity, checkpoint_capture=capture
        )


def test_repair_lease_binds_checkpoint_to_project_workspace_not_child_task() -> None:
    identity = replace(_identity(), task_id="repair-c", task_generation=7)
    task = SimpleNamespace(
        project_id=identity.project_id,
        task_id=identity.task_id,
        generation=identity.task_generation,
        attempt_count=identity.attempt,
        lease_epoch=identity.lease_epoch,
        workspace=identity.workspace,
        status=TaskStatus.IN_PROGRESS,
    )
    project = SimpleNamespace(
        project_id=identity.project_id,
        controller_epoch=identity.controller_epoch,
        lease_epoch=identity.lease_epoch,
        workspace=identity.workspace,
        baseline=SimpleNamespace(repository_id="repo-c", commit_sha="b" * 40),
    )
    checkpoint = SimpleNamespace(
        capture_completeness=WorkspaceCaptureCompleteness.COMPLETE,
        repository_id="repo-c",
        baseline_commit_sha="b" * 40,
        task_id=identity.workspace.workspace_id,
        generation=identity.workspace.generation,
        reservation_digest=identity.workspace.reservation_id,
        checkpoint_digest=identity.pre_checkpoint_digest,
        worktree_device=1,
        worktree_inode=2,
    )
    capture = SimpleNamespace(
        decision=WorkspaceReuseDecision.REUSABLE, checkpoint=checkpoint
    )
    board = SimpleNamespace(project=project, task=lambda _task_id: task)

    admitted = WorkspaceLeaseAdmission.issue(
        board=board, identity=identity, checkpoint_capture=capture
    )

    assert admitted.task_id == "repair-c"
    assert admitted.workspace == identity.workspace

    checkpoint.capture_completeness = WorkspaceCaptureCompleteness.COMPLETE
    capture.decision = WorkspaceReuseDecision.NOT_REUSABLE
    with pytest.raises(WorkspaceLeaseError, match="LEASE_ADMISSION_EVIDENCE_MISMATCH"):
        WorkspaceLeaseAdmission.issue(
            board=board, identity=identity, checkpoint_capture=capture
        )
