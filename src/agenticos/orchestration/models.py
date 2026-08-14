"""Immutable bounded records owned by the orchestration controller."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, ClassVar

BOARD_SCHEMA = "AOSBOARD/1"
MAX_IDENTIFIER_BYTES = 128
MAX_TITLE_BYTES = 200
MAX_DESCRIPTION_BYTES = 4096
MAX_GOAL_BYTES = 8192
MAX_CRITERIA = 32
MAX_CRITERION_BYTES = 1024
MAX_DEPENDENCIES = 64
MAX_TASKS = 128
MAX_UNSIGNED_64 = (1 << 64) - 1

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA40_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA64_RE = re.compile(r"[0-9a-f]{64}\Z")


class ControllerValidationError(ValueError):
    """Stable fail-closed validation error for controller-owned values."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class ProjectStatus(str, Enum):
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    OWNER_BLOCKED = "OWNER_BLOCKED"
    DONE = "DONE"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class TaskStatus(str, Enum):
    BACKLOG = "BACKLOG"
    READY = "READY"
    IN_PROGRESS = "IN_PROGRESS"
    VERIFYING = "VERIFYING"
    REVIEW = "REVIEW"
    WAITING_REPAIR = "WAITING_REPAIR"
    BLOCKED = "BLOCKED"
    DONE = "DONE"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class TaskType(str, Enum):
    RESEARCH = "RESEARCH"
    PLAN = "PLAN"
    BUILD = "BUILD"
    REPAIR = "REPAIR"
    DOCUMENT = "DOCUMENT"


class Role(str, Enum):
    RESEARCHER = "RESEARCHER"
    PLANNER = "PLANNER"
    BUILDER = "BUILDER"
    VERIFIER = "VERIFIER"
    REVIEWER = "REVIEWER"


class BlockReason(str, Enum):
    OWNER_DECISION_REQUIRED = "OWNER_DECISION_REQUIRED"
    PERMISSION_REQUIRED = "PERMISSION_REQUIRED"
    CREDENTIAL_REQUIRED = "CREDENTIAL_REQUIRED"
    PAYMENT_REQUIRED = "PAYMENT_REQUIRED"
    SAFETY_LIMIT_REQUIRES_OWNER = "SAFETY_LIMIT_REQUIRES_OWNER"
    DEPENDENCY_BLOCKED = "DEPENDENCY_BLOCKED"


class TerminalReason(str, Enum):
    COMPLETED = "COMPLETED"
    OWNER_DECISION_REQUIRED = "OWNER_DECISION_REQUIRED"
    CANCELLED_BY_OWNER = "CANCELLED_BY_OWNER"
    ATTEMPTS_EXHAUSTED = "ATTEMPTS_EXHAUSTED"
    DEPENDENCY_FAILED = "DEPENDENCY_FAILED"
    INVALID_CONTROLLER_STATE = "INVALID_CONTROLLER_STATE"
    JOURNAL_CORRUPTION = "JOURNAL_CORRUPTION"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    CONTROLLER_FAILURE = "CONTROLLER_FAILURE"


def require_identifier(name: str, value: object) -> str:
    if type(value) is not str or len(value.encode("utf-8")) > MAX_IDENTIFIER_BYTES:
        raise ControllerValidationError("INVALID_IDENTIFIER", name)
    if not _IDENTIFIER_RE.fullmatch(value):
        raise ControllerValidationError("INVALID_IDENTIFIER", name)
    return value


def require_text(name: str, value: object, max_bytes: int, *, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value):
        raise ControllerValidationError("INVALID_TEXT", name)
    if len(value.encode("utf-8")) > max_bytes:
        raise ControllerValidationError("TEXT_LIMIT_EXCEEDED", name)
    return value


def require_uint(name: str, value: object, *, minimum: int = 0, maximum: int = MAX_UNSIGNED_64) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ControllerValidationError("INVALID_INTEGER", name)
    return value


def require_digest(name: str, value: object, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if type(value) is not str or not _SHA64_RE.fullmatch(value):
        raise ControllerValidationError("INVALID_DIGEST", name)
    return value


def require_enum(enum_type: type[Enum], name: str, value: object) -> Enum:
    if isinstance(value, enum_type):
        return value
    if type(value) is not str:
        raise ControllerValidationError("INVALID_ENUM", name)
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ControllerValidationError("INVALID_ENUM", name) from exc


def require_exact_fields(raw: object, expected: set[str]) -> dict[str, Any]:
    if type(raw) is not dict:
        raise ControllerValidationError("INVALID_OBJECT")
    actual = set(raw)
    if actual != expected:
        extra = sorted(actual - expected)
        missing = sorted(expected - actual)
        code = "UNKNOWN_FIELDS" if extra else "MISSING_FIELDS"
        raise ControllerValidationError(code, f"extra={extra};missing={missing}")
    if any(type(key) is not str for key in raw):
        raise ControllerValidationError("INVALID_OBJECT_KEY")
    return raw


@dataclass(frozen=True, slots=True)
class BaselineIdentity:
    repository_id: str
    commit_sha: str

    def __post_init__(self) -> None:
        require_identifier("repository_id", self.repository_id)
        if type(self.commit_sha) is not str or not _SHA40_RE.fullmatch(self.commit_sha):
            raise ControllerValidationError("INVALID_COMMIT_SHA")

    def to_dict(self) -> dict[str, object]:
        return {"repository_id": self.repository_id, "commit_sha": self.commit_sha}

    @classmethod
    def from_dict(cls, raw: object) -> BaselineIdentity:
        value = require_exact_fields(raw, {"repository_id", "commit_sha"})
        return cls(repository_id=value["repository_id"], commit_sha=value["commit_sha"])


@dataclass(frozen=True, slots=True)
class WorkspaceIdentityRef:
    """Opaque future binding only; this record grants no workspace authority."""

    workspace_id: str
    generation: int
    reservation_id: str

    def __post_init__(self) -> None:
        require_identifier("workspace_id", self.workspace_id)
        require_uint("generation", self.generation, minimum=1)
        require_identifier("reservation_id", self.reservation_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "workspace_id": self.workspace_id,
            "generation": self.generation,
            "reservation_id": self.reservation_id,
        }

    @classmethod
    def from_dict(cls, raw: object) -> WorkspaceIdentityRef:
        value = require_exact_fields(raw, {"workspace_id", "generation", "reservation_id"})
        return cls(**value)


@dataclass(frozen=True, slots=True)
class RunLimits:
    max_tasks: int = MAX_TASKS
    max_total_attempts: int = 512
    max_repair_depth: int = 8
    max_events_per_attempt: int = 256
    max_event_bytes: int = 65_536
    max_output_bytes: int = 1_048_576
    max_context_entries: int = 64
    max_context_bytes: int = 262_144
    max_processes: int = 32
    max_runtime_seconds: int = 3_600

    _MAXIMA: ClassVar[dict[str, int]] = {
        "max_tasks": MAX_TASKS,
        "max_total_attempts": 4096,
        "max_repair_depth": 32,
        "max_events_per_attempt": 4096,
        "max_event_bytes": 1_048_576,
        "max_output_bytes": 16_777_216,
        "max_context_entries": 1024,
        "max_context_bytes": 16_777_216,
        "max_processes": 256,
        "max_runtime_seconds": 86_400,
    }

    def __post_init__(self) -> None:
        for name, maximum in self._MAXIMA.items():
            require_uint(name, getattr(self, name), minimum=1, maximum=maximum)

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self._MAXIMA}

    @classmethod
    def from_dict(cls, raw: object) -> RunLimits:
        value = require_exact_fields(raw, set(cls._MAXIMA))
        return cls(**value)


@dataclass(frozen=True, slots=True)
class ProjectRecord:
    schema: str
    project_id: str
    goal: str
    baseline: BaselineIdentity
    workspace: WorkspaceIdentityRef
    status: ProjectStatus
    terminal_reason: TerminalReason | None
    board_revision: int
    controller_epoch: int
    lease_epoch: int
    limits: RunLimits
    started_at_unix_ms: int
    deadline_unix_ms: int
    transition_sequence: int
    transition_digest: str

    def __post_init__(self) -> None:
        if self.schema != BOARD_SCHEMA:
            raise ControllerValidationError("INVALID_SCHEMA")
        require_identifier("project_id", self.project_id)
        require_text("goal", self.goal, MAX_GOAL_BYTES)
        if not isinstance(self.baseline, BaselineIdentity) or not isinstance(self.workspace, WorkspaceIdentityRef):
            raise ControllerValidationError("INVALID_IDENTITY")
        if not isinstance(self.status, ProjectStatus):
            raise ControllerValidationError("INVALID_ENUM", "status")
        for name, minimum in (("board_revision", 0), ("controller_epoch", 1), ("lease_epoch", 0), ("started_at_unix_ms", 0), ("deadline_unix_ms", 1), ("transition_sequence", 0)):
            require_uint(name, getattr(self, name), minimum=minimum)
        require_digest("transition_digest", self.transition_digest)
        if self.deadline_unix_ms <= self.started_at_unix_ms:
            raise ControllerValidationError("INVALID_TIME_RANGE")
        if not isinstance(self.limits, RunLimits):
            raise ControllerValidationError("INVALID_LIMITS")
        terminal = self.status in {ProjectStatus.OWNER_BLOCKED, ProjectStatus.DONE, ProjectStatus.FAILED, ProjectStatus.CANCELLED}
        if terminal != (self.terminal_reason is not None):
            raise ControllerValidationError("INVALID_STATE_REASON")
        if self.status is ProjectStatus.OWNER_BLOCKED and self.terminal_reason is not TerminalReason.OWNER_DECISION_REQUIRED:
            raise ControllerValidationError("INVALID_STATE_REASON")
        if self.status is ProjectStatus.DONE and self.terminal_reason is not TerminalReason.COMPLETED:
            raise ControllerValidationError("INVALID_STATE_REASON")
        if self.status is ProjectStatus.CANCELLED and self.terminal_reason is not TerminalReason.CANCELLED_BY_OWNER:
            raise ControllerValidationError("INVALID_STATE_REASON")
        if self.status is ProjectStatus.FAILED and self.terminal_reason in {
            TerminalReason.COMPLETED,
            TerminalReason.OWNER_DECISION_REQUIRED,
            TerminalReason.CANCELLED_BY_OWNER,
        }:
            raise ControllerValidationError("INVALID_STATE_REASON")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "project_id": self.project_id,
            "goal": self.goal,
            "baseline": self.baseline.to_dict(),
            "workspace": self.workspace.to_dict(),
            "status": self.status.value,
            "terminal_reason": self.terminal_reason.value if self.terminal_reason else None,
            "board_revision": self.board_revision,
            "controller_epoch": self.controller_epoch,
            "lease_epoch": self.lease_epoch,
            "limits": self.limits.to_dict(),
            "started_at_unix_ms": self.started_at_unix_ms,
            "deadline_unix_ms": self.deadline_unix_ms,
            "transition_sequence": self.transition_sequence,
            "transition_digest": self.transition_digest,
        }

    @classmethod
    def from_dict(cls, raw: object) -> ProjectRecord:
        names = set(cls.__dataclass_fields__)
        value = require_exact_fields(raw, names)
        return cls(
            **{
                **value,
                "baseline": BaselineIdentity.from_dict(value["baseline"]),
                "workspace": WorkspaceIdentityRef.from_dict(value["workspace"]),
                "status": require_enum(ProjectStatus, "status", value["status"]),
                "terminal_reason": None if value["terminal_reason"] is None else require_enum(TerminalReason, "terminal_reason", value["terminal_reason"]),
                "limits": RunLimits.from_dict(value["limits"]),
            }
        )


@dataclass(frozen=True, slots=True)
class BoardTask:
    schema: str
    task_id: str
    project_id: str
    title: str
    description: str
    task_type: TaskType
    priority: int
    dependencies: tuple[str, ...]
    acceptance_criteria: tuple[str, ...]
    preferred_role: Role
    assigned_role: Role | None
    status: TaskStatus
    attempt_count: int
    max_attempts: int
    creation_sequence: int
    creator: str
    parent_task_id: str | None
    root_task_id: str
    generation: int
    workspace: WorkspaceIdentityRef
    lease_epoch: int
    block_reason: BlockReason | None
    terminal_reason: TerminalReason | None
    repair_failure_fingerprint: str | None
    satisfying_descendant_id: str | None
    verification_result_digest: str | None
    review_result_digest: str | None

    def __post_init__(self) -> None:
        if self.schema != BOARD_SCHEMA:
            raise ControllerValidationError("INVALID_SCHEMA")
        for name in ("task_id", "project_id", "root_task_id", "creator"):
            require_identifier(name, getattr(self, name))
        require_text("title", self.title, MAX_TITLE_BYTES)
        require_text("description", self.description, MAX_DESCRIPTION_BYTES)
        if not isinstance(self.task_type, TaskType) or not isinstance(self.preferred_role, Role):
            raise ControllerValidationError("INVALID_ENUM")
        if self.assigned_role is not None and not isinstance(self.assigned_role, Role):
            raise ControllerValidationError("INVALID_ENUM", "assigned_role")
        if not isinstance(self.status, TaskStatus):
            raise ControllerValidationError("INVALID_ENUM", "status")
        if type(self.priority) is not int or not 0 <= self.priority <= 100:
            raise ControllerValidationError("INVALID_PRIORITY")
        if type(self.dependencies) is not tuple or len(self.dependencies) > MAX_DEPENDENCIES:
            raise ControllerValidationError("COUNT_LIMIT_EXCEEDED", "dependencies")
        if len(set(self.dependencies)) != len(self.dependencies):
            raise ControllerValidationError("DUPLICATE_DEPENDENCY")
        for dependency in self.dependencies:
            require_identifier("dependency", dependency)
        if type(self.acceptance_criteria) is not tuple or not 1 <= len(self.acceptance_criteria) <= MAX_CRITERIA:
            raise ControllerValidationError("COUNT_LIMIT_EXCEEDED", "acceptance_criteria")
        for criterion in self.acceptance_criteria:
            require_text("acceptance_criterion", criterion, MAX_CRITERION_BYTES)
        require_uint("attempt_count", self.attempt_count)
        require_uint("max_attempts", self.max_attempts, minimum=1, maximum=32)
        if self.attempt_count > self.max_attempts:
            raise ControllerValidationError("ATTEMPT_LIMIT_EXCEEDED")
        require_uint("creation_sequence", self.creation_sequence, minimum=1)
        require_uint("generation", self.generation, minimum=1)
        require_uint("lease_epoch", self.lease_epoch)
        if not isinstance(self.workspace, WorkspaceIdentityRef):
            raise ControllerValidationError("INVALID_IDENTITY")
        if self.parent_task_id is None:
            if self.root_task_id != self.task_id:
                raise ControllerValidationError("INVALID_REPAIR_LINEAGE")
            if self.repair_failure_fingerprint is not None:
                raise ControllerValidationError("INVALID_REPAIR_LINEAGE")
        else:
            require_identifier("parent_task_id", self.parent_task_id)
            require_digest("repair_failure_fingerprint", self.repair_failure_fingerprint)
        for name in ("satisfying_descendant_id",):
            value = getattr(self, name)
            if value is not None:
                require_identifier(name, value)
        for name in ("verification_result_digest", "review_result_digest"):
            require_digest(name, getattr(self, name), allow_none=True)
        if self.block_reason is not None and not isinstance(self.block_reason, BlockReason):
            raise ControllerValidationError("INVALID_ENUM", "block_reason")
        if self.terminal_reason is not None and not isinstance(self.terminal_reason, TerminalReason):
            raise ControllerValidationError("INVALID_ENUM", "terminal_reason")
        blocked = self.status is TaskStatus.BLOCKED
        terminal = self.status in {TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.CANCELLED}
        if blocked != (self.block_reason is not None) or terminal != (self.terminal_reason is not None):
            raise ControllerValidationError("INVALID_STATE_REASON")
        if blocked and self.terminal_reason is not None:
            raise ControllerValidationError("INVALID_STATE_REASON")
        if self.status is TaskStatus.DONE and self.terminal_reason is not TerminalReason.COMPLETED:
            raise ControllerValidationError("INVALID_STATE_REASON")
        if self.status is TaskStatus.CANCELLED and self.terminal_reason is not TerminalReason.CANCELLED_BY_OWNER:
            raise ControllerValidationError("INVALID_STATE_REASON")
        if self.status is TaskStatus.FAILED and self.terminal_reason in {
            TerminalReason.COMPLETED,
            TerminalReason.OWNER_DECISION_REQUIRED,
            TerminalReason.CANCELLED_BY_OWNER,
        }:
            raise ControllerValidationError("INVALID_STATE_REASON")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "task_id": self.task_id,
            "project_id": self.project_id,
            "title": self.title,
            "description": self.description,
            "task_type": self.task_type.value,
            "priority": self.priority,
            "dependencies": list(self.dependencies),
            "acceptance_criteria": list(self.acceptance_criteria),
            "preferred_role": self.preferred_role.value,
            "assigned_role": self.assigned_role.value if self.assigned_role else None,
            "status": self.status.value,
            "attempt_count": self.attempt_count,
            "max_attempts": self.max_attempts,
            "creation_sequence": self.creation_sequence,
            "creator": self.creator,
            "parent_task_id": self.parent_task_id,
            "root_task_id": self.root_task_id,
            "generation": self.generation,
            "workspace": self.workspace.to_dict(),
            "lease_epoch": self.lease_epoch,
            "block_reason": self.block_reason.value if self.block_reason else None,
            "terminal_reason": self.terminal_reason.value if self.terminal_reason else None,
            "repair_failure_fingerprint": self.repair_failure_fingerprint,
            "satisfying_descendant_id": self.satisfying_descendant_id,
            "verification_result_digest": self.verification_result_digest,
            "review_result_digest": self.review_result_digest,
        }

    @classmethod
    def from_dict(cls, raw: object) -> BoardTask:
        names = set(cls.__dataclass_fields__)
        value = require_exact_fields(raw, names)
        return cls(
            **{
                **value,
                "task_type": require_enum(TaskType, "task_type", value["task_type"]),
                "preferred_role": require_enum(Role, "preferred_role", value["preferred_role"]),
                "assigned_role": None if value["assigned_role"] is None else require_enum(Role, "assigned_role", value["assigned_role"]),
                "status": require_enum(TaskStatus, "status", value["status"]),
                "dependencies": tuple(value["dependencies"]),
                "acceptance_criteria": tuple(value["acceptance_criteria"]),
                "workspace": WorkspaceIdentityRef.from_dict(value["workspace"]),
                "block_reason": None if value["block_reason"] is None else require_enum(BlockReason, "block_reason", value["block_reason"]),
                "terminal_reason": None if value["terminal_reason"] is None else require_enum(TerminalReason, "terminal_reason", value["terminal_reason"]),
            }
        )
