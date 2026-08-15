from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from agenticos.orchestration.models import (
    BOARD_SCHEMA,
    BaselineIdentity,
    BlockReason,
    BoardTask,
    ControllerValidationError,
    ProjectRecord,
    ProjectStatus,
    Role,
    RunLimits,
    TaskStatus,
    TaskType,
    TerminalReason,
    WorkspaceIdentityRef,
)


def baseline() -> BaselineIdentity:
    return BaselineIdentity(repository_id="repo-1", commit_sha="a" * 40)


def workspace() -> WorkspaceIdentityRef:
    return WorkspaceIdentityRef(
        workspace_id="workspace-1", generation=1, reservation_id="reservation-1"
    )


def project() -> ProjectRecord:
    return ProjectRecord(
        schema=BOARD_SCHEMA,
        project_id="project-1",
        goal="Build the bounded controller authority core.",
        baseline=baseline(),
        workspace=workspace(),
        status=ProjectStatus.CREATED,
        terminal_reason=None,
        board_revision=0,
        controller_epoch=1,
        lease_epoch=0,
        limits=RunLimits(),
        started_at_unix_ms=1_000,
        deadline_unix_ms=61_000,
        transition_sequence=0,
        transition_digest="0" * 64,
    )


def task(**changes: object) -> BoardTask:
    values: dict[str, object] = {
        "schema": BOARD_SCHEMA,
        "task_id": "task-1",
        "project_id": "project-1",
        "title": "Implement records",
        "description": "Create bounded immutable values.",
        "task_type": TaskType.BUILD,
        "priority": 50,
        "dependencies": (),
        "acceptance_criteria": ("All focused tests pass.",),
        "preferred_role": Role.BUILDER,
        "assigned_role": None,
        "status": TaskStatus.BACKLOG,
        "attempt_count": 0,
        "max_attempts": 3,
        "creation_sequence": 1,
        "creator": "CONTROLLER",
        "parent_task_id": None,
        "root_task_id": "task-1",
        "generation": 1,
        "workspace": workspace(),
        "lease_epoch": 0,
        "block_reason": None,
        "terminal_reason": None,
        "repair_failure_fingerprint": None,
        "satisfying_descendant_id": None,
        "verification_result_digest": None,
        "review_result_digest": None,
        "stage_result_digest": None,
    }
    values.update(changes)
    return BoardTask(**values)  # type: ignore[arg-type]


def test_valid_records_are_frozen_and_round_trip_strictly() -> None:
    original = project()
    assert ProjectRecord.from_dict(original.to_dict()) == original
    assert BoardTask.from_dict(task().to_dict()) == task()
    with pytest.raises(FrozenInstanceError):
        original.status = ProjectStatus.ACTIVE  # type: ignore[misc]


def test_required_task_lifecycle_is_exact() -> None:
    assert {item.value for item in TaskStatus} == {
        "BACKLOG",
        "READY",
        "IN_PROGRESS",
        "VERIFYING",
        "REVIEW",
        "WAITING_REPAIR",
        "BLOCKED",
        "DONE",
        "FAILED",
        "CANCELLED",
    }


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("task_id", "bad task", "INVALID_IDENTIFIER"),
        ("title", "x" * 201, "TEXT_LIMIT_EXCEEDED"),
        ("priority", 101, "INVALID_PRIORITY"),
        ("dependencies", tuple(f"task-{i}" for i in range(65)), "COUNT_LIMIT_EXCEEDED"),
        ("attempt_count", 4, "ATTEMPT_LIMIT_EXCEEDED"),
        ("root_task_id", "other-root", "INVALID_REPAIR_LINEAGE"),
    ],
)
def test_invalid_task_values_are_rejected(field: str, value: object, code: str) -> None:
    with pytest.raises(ControllerValidationError) as caught:
        task(**{field: value})
    assert caught.value.code == code


def test_invalid_enum_and_unknown_fields_are_rejected() -> None:
    raw = task().to_dict()
    raw["status"] = "MODEL_SAYS_DONE"
    with pytest.raises(ControllerValidationError, match="INVALID_ENUM"):
        BoardTask.from_dict(raw)
    raw = task().to_dict()
    raw["command"] = "git push"
    with pytest.raises(ControllerValidationError, match="UNKNOWN_FIELDS"):
        BoardTask.from_dict(raw)


def test_terminal_and_block_reasons_are_state_consistent() -> None:
    with pytest.raises(ControllerValidationError, match="INVALID_STATE_REASON"):
        task(status=TaskStatus.DONE, terminal_reason=None)
    with pytest.raises(ControllerValidationError, match="INVALID_STATE_REASON"):
        task(status=TaskStatus.BLOCKED, block_reason=None)
    blocked = task(status=TaskStatus.BLOCKED, block_reason=BlockReason.OWNER_DECISION_REQUIRED)
    failed = task(status=TaskStatus.FAILED, terminal_reason=TerminalReason.ATTEMPTS_EXHAUSTED)
    assert blocked.block_reason is BlockReason.OWNER_DECISION_REQUIRED
    assert failed.terminal_reason is TerminalReason.ATTEMPTS_EXHAUSTED
    with pytest.raises(ControllerValidationError, match="INVALID_STATE_REASON"):
        task(status=TaskStatus.DONE, terminal_reason=TerminalReason.CONTROLLER_FAILURE)


def test_dependency_edges_are_distinct_from_repair_lineage() -> None:
    repair = task(
        task_id="repair-1",
        dependencies=("prerequisite",),
        parent_task_id="task-1",
        root_task_id="task-1",
        repair_failure_fingerprint="b" * 64,
    )
    assert repair.dependencies == ("prerequisite",)
    assert repair.parent_task_id == "task-1"
    assert repair.parent_task_id not in repair.dependencies


def test_project_deadline_and_workspace_generation_are_bounded() -> None:
    with pytest.raises(ControllerValidationError, match="INVALID_TIME_RANGE"):
        replace(project(), deadline_unix_ms=999)
    with pytest.raises(ControllerValidationError, match="INVALID_INTEGER"):
        WorkspaceIdentityRef("workspace-1", True, "reservation-1")


@pytest.mark.parametrize(
    "reason",
    [TerminalReason.COMPLETED, TerminalReason.OWNER_DECISION_REQUIRED, TerminalReason.CANCELLED_BY_OWNER],
)
def test_project_failed_rejects_non_failure_reasons(reason: TerminalReason) -> None:
    with pytest.raises(ControllerValidationError, match="INVALID_STATE_REASON"):
        replace(project(), status=ProjectStatus.FAILED, terminal_reason=reason)


def test_stage_result_digest_is_strict_and_round_trips() -> None:
    completed = task(
        task_type=TaskType.RESEARCH,
        preferred_role=Role.RESEARCHER,
        status=TaskStatus.DONE,
        terminal_reason=TerminalReason.COMPLETED,
        stage_result_digest="d" * 64,
    )
    assert BoardTask.from_dict(completed.to_dict()) == completed
    with pytest.raises(ControllerValidationError, match="INVALID_DIGEST"):
        task(stage_result_digest="model-says-done")
