"""Controller-owned board validation and total state-transition authority."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from .models import (
    BlockReason,
    BoardTask,
    ControllerValidationError,
    ProjectRecord,
    ProjectStatus,
    TaskStatus,
    TerminalReason,
    require_exact_fields,
)

TASK_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.BACKLOG: frozenset({TaskStatus.READY, TaskStatus.BLOCKED, TaskStatus.CANCELLED}),
    TaskStatus.READY: frozenset({TaskStatus.IN_PROGRESS, TaskStatus.BLOCKED, TaskStatus.CANCELLED}),
    TaskStatus.IN_PROGRESS: frozenset({TaskStatus.VERIFYING, TaskStatus.REVIEW, TaskStatus.DONE, TaskStatus.WAITING_REPAIR, TaskStatus.BLOCKED, TaskStatus.FAILED, TaskStatus.CANCELLED}),
    TaskStatus.VERIFYING: frozenset({TaskStatus.REVIEW, TaskStatus.WAITING_REPAIR, TaskStatus.BLOCKED, TaskStatus.FAILED, TaskStatus.CANCELLED}),
    TaskStatus.REVIEW: frozenset({TaskStatus.DONE, TaskStatus.WAITING_REPAIR, TaskStatus.BLOCKED, TaskStatus.FAILED, TaskStatus.CANCELLED}),
    TaskStatus.WAITING_REPAIR: frozenset({TaskStatus.DONE, TaskStatus.BLOCKED, TaskStatus.FAILED, TaskStatus.CANCELLED}),
    TaskStatus.BLOCKED: frozenset({TaskStatus.READY, TaskStatus.FAILED, TaskStatus.CANCELLED}),
    TaskStatus.DONE: frozenset(),
    TaskStatus.FAILED: frozenset(),
    TaskStatus.CANCELLED: frozenset(),
}

PROJECT_TRANSITIONS: dict[ProjectStatus, frozenset[ProjectStatus]] = {
    ProjectStatus.CREATED: frozenset({ProjectStatus.ACTIVE, ProjectStatus.OWNER_BLOCKED, ProjectStatus.FAILED, ProjectStatus.CANCELLED}),
    ProjectStatus.ACTIVE: frozenset({ProjectStatus.OWNER_BLOCKED, ProjectStatus.DONE, ProjectStatus.FAILED, ProjectStatus.CANCELLED}),
    # Autonomous transitions stop here. A later explicit owner-resume operation
    # must create a new controller epoch before returning to ACTIVE.
    ProjectStatus.OWNER_BLOCKED: frozenset(),
    ProjectStatus.DONE: frozenset(),
    ProjectStatus.FAILED: frozenset(),
    ProjectStatus.CANCELLED: frozenset(),
}


class MutationRejectionCode(str, Enum):
    STALE_REVISION = "STALE_REVISION"
    UNKNOWN_TASK = "UNKNOWN_TASK"
    INVALID_STATUS = "INVALID_STATUS"
    DUPLICATE_TRANSITION = "DUPLICATE_TRANSITION"
    IMPOSSIBLE_TRANSITION = "IMPOSSIBLE_TRANSITION"
    INVALID_REASON = "INVALID_REASON"
    ATTEMPTS_EXHAUSTED = "ATTEMPTS_EXHAUSTED"
    INVALID_BOARD = "INVALID_BOARD"
    NO_STATE_CHANGE = "NO_STATE_CHANGE"


@dataclass(frozen=True, slots=True)
class BoardSnapshot:
    project: ProjectRecord
    tasks: tuple[BoardTask, ...]

    @property
    def revision(self) -> int:
        return self.project.board_revision

    @classmethod
    def create(cls, project: ProjectRecord, tasks: tuple[BoardTask, ...] | list[BoardTask]) -> BoardSnapshot:
        if not isinstance(project, ProjectRecord):
            raise ControllerValidationError("INVALID_PROJECT")
        ordered = tuple(sorted(tasks, key=lambda item: (item.creation_sequence, item.task_id)))
        cls._validate(project, ordered)
        return cls(project=project, tasks=ordered)

    @staticmethod
    def _validate(project: ProjectRecord, tasks: tuple[BoardTask, ...]) -> None:
        ids = [item.task_id for item in tasks]
        if len(tasks) > project.limits.max_tasks:
            raise ControllerValidationError("PROJECT_TASK_LIMIT")
        if len(ids) != len(set(ids)):
            raise ControllerValidationError("DUPLICATE_TASK_ID")
        sequences = [item.creation_sequence for item in tasks]
        if len(sequences) != len(set(sequences)):
            raise ControllerValidationError("DUPLICATE_CREATION_SEQUENCE")
        by_id = {item.task_id: item for item in tasks}
        for item in tasks:
            if item.project_id != project.project_id:
                raise ControllerValidationError("CROSS_PROJECT_TASK")
            if item.task_id in item.dependencies:
                raise ControllerValidationError("SELF_DEPENDENCY")
            for dependency in item.dependencies:
                if dependency not in by_id:
                    raise ControllerValidationError("MISSING_DEPENDENCY", dependency)
            if item.parent_task_id is not None:
                parent = by_id.get(item.parent_task_id)
                if parent is None:
                    raise ControllerValidationError("MISSING_REPAIR_PARENT")
                if parent.root_task_id != item.root_task_id:
                    raise ControllerValidationError("INVALID_REPAIR_LINEAGE")
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(task_id: str) -> None:
            if task_id in visiting:
                raise ControllerValidationError("DEPENDENCY_CYCLE")
            if task_id in visited:
                return
            visiting.add(task_id)
            for dependency in by_id[task_id].dependencies:
                visit(dependency)
            visiting.remove(task_id)
            visited.add(task_id)

        for task_id in ids:
            visit(task_id)

    def task(self, task_id: str) -> BoardTask:
        for item in self.tasks:
            if item.task_id == task_id:
                return item
        raise KeyError(task_id)

    def to_dict(self) -> dict[str, object]:
        return {"project": self.project.to_dict(), "tasks": [item.to_dict() for item in self.tasks]}

    @classmethod
    def from_dict(cls, raw: object) -> BoardSnapshot:
        value = require_exact_fields(raw, {"project", "tasks"})
        if type(value["tasks"]) is not list:
            raise ControllerValidationError("INVALID_TASK_LIST")
        return cls.create(ProjectRecord.from_dict(value["project"]), tuple(BoardTask.from_dict(item) for item in value["tasks"]))


@dataclass(frozen=True, slots=True)
class AcceptedBoardMutation:
    snapshot: BoardSnapshot
    changed_tasks: tuple[BoardTask, ...] = ()


@dataclass(frozen=True, slots=True)
class RejectedBoardMutation:
    code: MutationRejectionCode
    revision: int
    detail: str = ""


class BoardTransitionEngine:
    """Pure staging engine; its candidate snapshot is never durable authority."""

    def __init__(self, snapshot: BoardSnapshot) -> None:
        if not isinstance(snapshot, BoardSnapshot):
            raise TypeError("snapshot must be BoardSnapshot")
        self._snapshot = snapshot

    @property
    def snapshot(self) -> BoardSnapshot:
        return self._snapshot

    def _reject(self, code: MutationRejectionCode, detail: str = "") -> RejectedBoardMutation:
        return RejectedBoardMutation(code, self._snapshot.revision, detail)

    def _revision_ok(self, expected: int) -> RejectedBoardMutation | None:
        if type(expected) is not int or expected != self._snapshot.revision:
            return self._reject(MutationRejectionCode.STALE_REVISION)
        return None

    def transition_task(
        self,
        expected_revision: int,
        task_id: str,
        target: TaskStatus,
        *,
        terminal_reason: TerminalReason | None = None,
        block_reason: BlockReason | None = None,
    ) -> AcceptedBoardMutation | RejectedBoardMutation:
        if (stale := self._revision_ok(expected_revision)) is not None:
            return stale
        if not isinstance(target, TaskStatus):
            return self._reject(MutationRejectionCode.INVALID_STATUS)
        try:
            current = self._snapshot.task(task_id)
        except KeyError:
            return self._reject(MutationRejectionCode.UNKNOWN_TASK)
        if current.status is target:
            return self._reject(MutationRejectionCode.DUPLICATE_TRANSITION)
        if target not in TASK_TRANSITIONS[current.status]:
            return self._reject(MutationRejectionCode.IMPOSSIBLE_TRANSITION)
        terminal = target in {TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.CANCELLED}
        blocked = target is TaskStatus.BLOCKED
        if terminal != (terminal_reason is not None) or blocked != (block_reason is not None):
            return self._reject(MutationRejectionCode.INVALID_REASON)
        attempt_count = current.attempt_count
        if target is TaskStatus.IN_PROGRESS:
            if attempt_count >= current.max_attempts:
                return self._reject(MutationRejectionCode.ATTEMPTS_EXHAUSTED)
            attempt_count += 1
        try:
            updated = replace(
                current,
                status=target,
                attempt_count=attempt_count,
                terminal_reason=terminal_reason,
                block_reason=block_reason,
            )
            return self._replace_tasks((updated,))
        except ControllerValidationError as exc:
            return self._reject(MutationRejectionCode.INVALID_REASON, exc.code)

    def transition_project(
        self,
        expected_revision: int,
        target: ProjectStatus,
        *,
        terminal_reason: TerminalReason | None = None,
    ) -> AcceptedBoardMutation | RejectedBoardMutation:
        if (stale := self._revision_ok(expected_revision)) is not None:
            return stale
        if not isinstance(target, ProjectStatus):
            return self._reject(MutationRejectionCode.INVALID_STATUS)
        current = self._snapshot.project
        if current.status is target:
            return self._reject(MutationRejectionCode.DUPLICATE_TRANSITION)
        if target not in PROJECT_TRANSITIONS[current.status]:
            return self._reject(MutationRejectionCode.IMPOSSIBLE_TRANSITION)
        terminal = target in {ProjectStatus.OWNER_BLOCKED, ProjectStatus.DONE, ProjectStatus.FAILED, ProjectStatus.CANCELLED}
        if terminal != (terminal_reason is not None):
            return self._reject(MutationRejectionCode.INVALID_REASON)
        if target is ProjectStatus.OWNER_BLOCKED and terminal_reason is not TerminalReason.OWNER_DECISION_REQUIRED:
            return self._reject(MutationRejectionCode.INVALID_REASON)
        try:
            new_project = replace(current, status=target, terminal_reason=terminal_reason, board_revision=current.board_revision + 1)
            self._snapshot = BoardSnapshot.create(new_project, self._snapshot.tasks)
        except ControllerValidationError as exc:
            return self._reject(MutationRejectionCode.INVALID_REASON, exc.code)
        return AcceptedBoardMutation(self._snapshot)

    def derive_ready(self, expected_revision: int) -> AcceptedBoardMutation | RejectedBoardMutation:
        if (stale := self._revision_ok(expected_revision)) is not None:
            return stale
        by_id = {item.task_id: item for item in self._snapshot.tasks}
        changed = tuple(
            replace(item, status=TaskStatus.READY)
            for item in self._snapshot.tasks
            if item.status is TaskStatus.BACKLOG
            and all(by_id[dependency].status is TaskStatus.DONE for dependency in item.dependencies)
        )
        if not changed:
            return self._reject(MutationRejectionCode.NO_STATE_CHANGE)
        return self._replace_tasks(changed)

    def add_tasks(self, expected_revision: int, tasks: tuple[BoardTask, ...]) -> AcceptedBoardMutation | RejectedBoardMutation:
        if (stale := self._revision_ok(expected_revision)) is not None:
            return stale
        if not tasks:
            return self._reject(MutationRejectionCode.NO_STATE_CHANGE)
        try:
            combined = self._snapshot.tasks + tasks
            new_project = replace(self._snapshot.project, board_revision=self._snapshot.revision + 1)
            candidate = BoardSnapshot.create(new_project, combined)
        except ControllerValidationError as exc:
            return self._reject(MutationRejectionCode.INVALID_BOARD, exc.code)
        self._snapshot = candidate
        return AcceptedBoardMutation(candidate, tasks)

    def _replace_tasks(self, changed: tuple[BoardTask, ...]) -> AcceptedBoardMutation:
        replacements = {item.task_id: item for item in changed}
        tasks = tuple(replacements.get(item.task_id, item) for item in self._snapshot.tasks)
        project = replace(self._snapshot.project, board_revision=self._snapshot.revision + 1)
        self._snapshot = BoardSnapshot.create(project, tasks)
        ordered = tuple(self._snapshot.task(item.task_id) for item in changed)
        return AcceptedBoardMutation(self._snapshot, ordered)


class BoardAuthority:
    """Durable board authority that publishes state only after journal COMMIT."""

    def __init__(self, journal: object, snapshot: BoardSnapshot) -> None:
        self._journal = journal
        self._snapshot = snapshot

    @classmethod
    def create(
        cls,
        journal: object,
        snapshot: BoardSnapshot,
        *,
        transaction_id: str,
    ) -> BoardAuthority:
        recovered = journal.initialize(snapshot, transaction_id=transaction_id)  # type: ignore[attr-defined]
        return cls(journal, recovered.snapshot)

    @classmethod
    def recover(cls, journal: object) -> BoardAuthority:
        recovered = journal.recover()  # type: ignore[attr-defined]
        return cls(journal, recovered.snapshot)

    @property
    def snapshot(self) -> BoardSnapshot:
        return self._snapshot

    def transition_task(
        self,
        expected_revision: int,
        task_id: str,
        target: TaskStatus,
        *,
        transaction_id: str,
        terminal_reason: TerminalReason | None = None,
        block_reason: BlockReason | None = None,
    ) -> AcceptedBoardMutation | RejectedBoardMutation:
        staged = BoardTransitionEngine(self._snapshot).transition_task(
            expected_revision,
            task_id,
            target,
            terminal_reason=terminal_reason,
            block_reason=block_reason,
        )
        return self._commit_staged(staged, transaction_id)

    def transition_project(
        self,
        expected_revision: int,
        target: ProjectStatus,
        *,
        transaction_id: str,
        terminal_reason: TerminalReason | None = None,
    ) -> AcceptedBoardMutation | RejectedBoardMutation:
        staged = BoardTransitionEngine(self._snapshot).transition_project(
            expected_revision,
            target,
            terminal_reason=terminal_reason,
        )
        return self._commit_staged(staged, transaction_id)

    def derive_ready(
        self,
        expected_revision: int,
        *,
        transaction_id: str,
    ) -> AcceptedBoardMutation | RejectedBoardMutation:
        staged = BoardTransitionEngine(self._snapshot).derive_ready(expected_revision)
        return self._commit_staged(staged, transaction_id)

    def add_tasks(
        self,
        expected_revision: int,
        tasks: tuple[BoardTask, ...],
        *,
        transaction_id: str,
    ) -> AcceptedBoardMutation | RejectedBoardMutation:
        staged = BoardTransitionEngine(self._snapshot).add_tasks(expected_revision, tasks)
        return self._commit_staged(staged, transaction_id)

    def _commit_staged(
        self,
        staged: AcceptedBoardMutation | RejectedBoardMutation,
        transaction_id: str,
    ) -> AcceptedBoardMutation | RejectedBoardMutation:
        if isinstance(staged, RejectedBoardMutation):
            return staged
        prior = self._snapshot
        recovered = self._journal.commit(  # type: ignore[attr-defined]
            prior,
            staged.snapshot,
            transaction_id=transaction_id,
        )
        self._snapshot = recovered.snapshot
        changed = tuple(self._snapshot.task(item.task_id) for item in staged.changed_tasks)
        return AcceptedBoardMutation(self._snapshot, changed)
