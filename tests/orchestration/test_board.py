from __future__ import annotations

from dataclasses import replace

import pytest

from agenticos.orchestration.board import (
    AcceptedBoardMutation,
    BoardAuthority,
    BoardSnapshot,
    BoardTransitionEngine,
    MutationRejectionCode,
    RejectedBoardMutation,
    PROJECT_TRANSITIONS,
    TASK_TRANSITIONS,
)
from agenticos.orchestration.journal import JournalError, TransactionJournal
from agenticos.orchestration.models import (
    BlockReason,
    ProjectStatus,
    TaskStatus,
    TerminalReason,
)
from tests.orchestration.test_models import project, task


def board(*tasks):
    return BoardSnapshot.create(project(), tasks)


def test_transition_tables_are_total() -> None:
    assert set(TASK_TRANSITIONS) == set(TaskStatus)
    assert set(PROJECT_TRANSITIONS) == set(ProjectStatus)
    authority = BoardTransitionEngine(board(task(status=TaskStatus.READY)))
    for target in TaskStatus:
        result = authority.transition_task(
            expected_revision=0,
            task_id="task-1",
            target=target,
            terminal_reason=TerminalReason.COMPLETED if target is TaskStatus.DONE else (
                TerminalReason.CONTROLLER_FAILURE if target is TaskStatus.FAILED else (
                    TerminalReason.CANCELLED_BY_OWNER if target is TaskStatus.CANCELLED else None
                )
            ),
            block_reason=BlockReason.OWNER_DECISION_REQUIRED if target is TaskStatus.BLOCKED else None,
        )
        assert isinstance(result, (AcceptedBoardMutation, RejectedBoardMutation))


def test_valid_task_transition_increments_attempt_and_revision() -> None:
    authority = BoardTransitionEngine(board(task(status=TaskStatus.READY)))
    result = authority.transition_task(0, "task-1", TaskStatus.IN_PROGRESS)
    assert isinstance(result, AcceptedBoardMutation)
    assert result.snapshot.revision == 1
    assert result.snapshot.task("task-1").attempt_count == 1
    assert authority.snapshot == result.snapshot


def test_impossible_duplicate_and_invalid_status_transitions_are_typed_rejections() -> None:
    authority = BoardTransitionEngine(board(task(status=TaskStatus.DONE, terminal_reason=TerminalReason.COMPLETED)))
    impossible = authority.transition_task(0, "task-1", TaskStatus.READY)
    duplicate = authority.transition_task(0, "task-1", TaskStatus.DONE)
    invalid = authority.transition_task(0, "task-1", "DONE")  # type: ignore[arg-type]
    assert [impossible.code, duplicate.code, invalid.code] == [
        MutationRejectionCode.IMPOSSIBLE_TRANSITION,
        MutationRejectionCode.DUPLICATE_TRANSITION,
        MutationRejectionCode.INVALID_STATUS,
    ]
    assert authority.snapshot.revision == 0


def test_stale_revision_and_attempt_exhaustion_are_rejected() -> None:
    authority = BoardTransitionEngine(board(task(status=TaskStatus.READY, attempt_count=1, max_attempts=1)))
    stale = authority.transition_task(1, "task-1", TaskStatus.IN_PROGRESS)
    exhausted = authority.transition_task(0, "task-1", TaskStatus.IN_PROGRESS)
    assert stale.code is MutationRejectionCode.STALE_REVISION
    assert exhausted.code is MutationRejectionCode.ATTEMPTS_EXHAUSTED


def test_board_rejects_duplicate_missing_self_and_cyclic_dependencies() -> None:
    with pytest.raises(ValueError, match="DUPLICATE_TASK_ID"):
        board(task(), task())
    with pytest.raises(ValueError, match="MISSING_DEPENDENCY"):
        board(task(dependencies=("missing",)))
    with pytest.raises(ValueError, match="SELF_DEPENDENCY"):
        board(task(dependencies=("task-1",)))
    first = task(task_id="task-1", root_task_id="task-1", dependencies=("task-2",))
    second = task(task_id="task-2", root_task_id="task-2", dependencies=("task-1",), creation_sequence=2)
    with pytest.raises(ValueError, match="DEPENDENCY_CYCLE"):
        board(first, second)


def test_repair_lineage_is_validated_but_does_not_create_dependency_cycle() -> None:
    parent = task(task_id="task-1", root_task_id="task-1")
    repair = task(
        task_id="task-2",
        root_task_id="task-1",
        parent_task_id="task-1",
        creation_sequence=2,
        repair_failure_fingerprint="c" * 64,
    )
    snapshot = board(parent, repair)
    assert snapshot.task("task-2").dependencies == ()


def test_ready_derivation_is_deterministic_and_atomic() -> None:
    done = task(
        task_id="task-1",
        root_task_id="task-1",
        status=TaskStatus.DONE,
        terminal_reason=TerminalReason.COMPLETED,
    )
    later = task(
        task_id="task-2",
        root_task_id="task-2",
        dependencies=("task-1",),
        creation_sequence=2,
    )
    independent = task(task_id="task-3", root_task_id="task-3", creation_sequence=3)
    authority = BoardTransitionEngine(board(done, later, independent))
    result = authority.derive_ready(0)
    assert isinstance(result, AcceptedBoardMutation)
    assert [item.task_id for item in result.changed_tasks] == ["task-2", "task-3"]
    assert all(item.status is TaskStatus.READY for item in result.changed_tasks)
    assert result.snapshot.revision == 1


def test_project_transition_is_authoritative_and_reason_checked() -> None:
    authority = BoardTransitionEngine(board())
    active = authority.transition_project(0, ProjectStatus.ACTIVE)
    assert isinstance(active, AcceptedBoardMutation)
    blocked = authority.transition_project(
        1,
        ProjectStatus.OWNER_BLOCKED,
        terminal_reason=TerminalReason.OWNER_DECISION_REQUIRED,
    )
    assert isinstance(blocked, AcceptedBoardMutation)
    assert blocked.snapshot.project.status is ProjectStatus.OWNER_BLOCKED
    resumed = authority.transition_project(2, ProjectStatus.ACTIVE)
    assert isinstance(resumed, RejectedBoardMutation)
    assert resumed.code is MutationRejectionCode.IMPOSSIBLE_TRANSITION


def test_project_failure_cannot_encode_owner_block_or_completion() -> None:
    for reason in (TerminalReason.COMPLETED, TerminalReason.OWNER_DECISION_REQUIRED):
        engine = BoardTransitionEngine(board())
        rejected = engine.transition_project(0, ProjectStatus.FAILED, terminal_reason=reason)
        assert isinstance(rejected, RejectedBoardMutation)
        assert rejected.code is MutationRejectionCode.INVALID_REASON


def test_durable_board_authority_journals_before_replacing_snapshot(tmp_path, monkeypatch) -> None:
    journal = TransactionJournal(tmp_path, "project-1")
    authority = BoardAuthority.create(journal, board(task(status=TaskStatus.READY)), transaction_id="tx-init")
    before = authority.snapshot
    accepted = authority.transition_task(0, "task-1", TaskStatus.IN_PROGRESS, transaction_id="tx-start")
    assert isinstance(accepted, AcceptedBoardMutation)
    assert journal.recover().snapshot == authority.snapshot
    assert authority.snapshot.project.transition_sequence == 2
    assert authority.snapshot.project.transition_digest != "0" * 64

    def fail_commit(*args, **kwargs):
        raise JournalError("SIMULATED_DURABILITY_FAILURE")

    monkeypatch.setattr(journal, "commit", fail_commit)
    durable_before_failure = authority.snapshot
    with pytest.raises(JournalError, match="SIMULATED_DURABILITY_FAILURE"):
        authority.transition_task(
            authority.snapshot.revision,
            "task-1",
            TaskStatus.FAILED,
            terminal_reason=TerminalReason.CONTROLLER_FAILURE,
            transaction_id="tx-fail",
        )
    assert authority.snapshot == durable_before_failure
