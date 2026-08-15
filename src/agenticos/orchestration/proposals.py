"""Strict untrusted planner/reviewer proposal types and controller compilation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .board import AcceptedBoardMutation, BoardAuthority
from .models import (
    BOARD_SCHEMA,
    MAX_CRITERIA,
    MAX_CRITERION_BYTES,
    MAX_DEPENDENCIES,
    MAX_DESCRIPTION_BYTES,
    MAX_TASKS,
    MAX_TITLE_BYTES,
    BoardTask,
    Role,
    TaskStatus,
    TaskType,
    require_enum,
    require_exact_fields,
    require_identifier,
    require_text,
)
from .protocol import EvidenceRef

PLANNER_SCHEMA = "AOSPLAN/1"
REVIEW_SCHEMA = "AOSREVIEW/1"
MAX_REVIEW_FINDINGS = 32
MAX_REVIEW_TEXT_BYTES = 2048


class ProposalCompilationError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


def _convert(exc: Exception, fallback: str = "INVALID_PROPOSAL") -> ProposalCompilationError:
    return ProposalCompilationError(getattr(exc, "code", fallback))


def _exact(raw: object, names: set[str]) -> dict[str, Any]:
    try:
        return require_exact_fields(raw, names)
    except ValueError as exc:
        raise _convert(exc) from exc


@dataclass(frozen=True, slots=True)
class ProposedTask:
    local_id: str
    title: str
    description: str
    task_type: TaskType
    dependencies: tuple[str, ...]
    acceptance_criteria: tuple[str, ...]
    preferred_role: Role
    priority: int

    def __post_init__(self) -> None:
        try:
            require_identifier("local_id", self.local_id)
            require_text("title", self.title, MAX_TITLE_BYTES)
            require_text("description", self.description, MAX_DESCRIPTION_BYTES)
            if not isinstance(self.task_type, TaskType) or not isinstance(self.preferred_role, Role):
                raise ProposalCompilationError("INVALID_ENUM")
            if type(self.priority) is not int or not 0 <= self.priority <= 100:
                raise ProposalCompilationError("INVALID_PRIORITY")
            if type(self.dependencies) is not tuple or len(self.dependencies) > MAX_DEPENDENCIES:
                raise ProposalCompilationError("DEPENDENCY_LIMIT")
            for dependency in self.dependencies:
                require_identifier("dependency", dependency)
            if type(self.acceptance_criteria) is not tuple or not 1 <= len(self.acceptance_criteria) <= MAX_CRITERIA:
                raise ProposalCompilationError("ACCEPTANCE_CRITERIA_LIMIT")
            for criterion in self.acceptance_criteria:
                require_text("criterion", criterion, MAX_CRITERION_BYTES)
        except ProposalCompilationError:
            raise
        except ValueError as exc:
            raise _convert(exc) from exc

    def to_dict(self) -> dict[str, object]:
        return {
            "local_id": self.local_id, "title": self.title, "description": self.description,
            "task_type": self.task_type.value, "dependencies": list(self.dependencies),
            "acceptance_criteria": list(self.acceptance_criteria),
            "preferred_role": self.preferred_role.value, "priority": self.priority,
        }

    @classmethod
    def from_dict(cls, raw: object) -> ProposedTask:
        value = _exact(raw, set(cls.__dataclass_fields__))
        try:
            task_type = require_enum(TaskType, "task_type", value["task_type"])
            role = require_enum(Role, "preferred_role", value["preferred_role"])
            return cls(
                **{**value, "task_type": task_type, "preferred_role": role,
                   "dependencies": tuple(value["dependencies"]),
                   "acceptance_criteria": tuple(value["acceptance_criteria"])}
            )
        except ProposalCompilationError:
            raise
        except (ValueError, TypeError) as exc:
            raise ProposalCompilationError("INVALID_ENUM" if getattr(exc, "code", "") == "INVALID_ENUM" else "INVALID_PROPOSAL_SHAPE") from exc


@dataclass(frozen=True, slots=True)
class PlannerProposal:
    schema: str
    tasks: tuple[ProposedTask, ...]

    def __post_init__(self) -> None:
        if self.schema != PLANNER_SCHEMA:
            raise ProposalCompilationError("INVALID_SCHEMA")
        if type(self.tasks) is not tuple or len(self.tasks) > MAX_TASKS:
            raise ProposalCompilationError("PROPOSAL_TASK_LIMIT")
        if not self.tasks or any(not isinstance(item, ProposedTask) for item in self.tasks):
            raise ProposalCompilationError("INVALID_PROPOSAL_TASKS")

    def to_dict(self) -> dict[str, object]:
        return {"schema": self.schema, "tasks": [item.to_dict() for item in self.tasks]}

    @classmethod
    def from_dict(cls, raw: object) -> PlannerProposal:
        value = _exact(raw, {"schema", "tasks"})
        if type(value["tasks"]) is not list:
            raise ProposalCompilationError("INVALID_PROPOSAL_TASKS")
        return cls(schema=value["schema"], tasks=tuple(ProposedTask.from_dict(item) for item in value["tasks"]))


@dataclass(frozen=True, slots=True)
class ProposalCompilationResult:
    accepted: bool
    authoritative_task_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PlannerCompilationPolicy:
    """Controller-owned policy; proposal fields are advisory within these bounds."""

    allowed_task_types: tuple[TaskType, ...] = (TaskType.BUILD, TaskType.DOCUMENT)
    maximum_priority: int = 80

    def role_for(self, task_type: TaskType) -> Role:
        if task_type in {TaskType.BUILD, TaskType.DOCUMENT}:
            return Role.BUILDER
        raise ProposalCompilationError("TASK_TYPE_NOT_ALLOWED")

    def acceptance_for(self, task_type: TaskType) -> tuple[str, ...]:
        if task_type is TaskType.BUILD:
            return ("Controller-registered verification policy must pass.",)
        if task_type is TaskType.DOCUMENT:
            return ("Controller-registered documentation policy must pass.",)
        raise ProposalCompilationError("TASK_TYPE_NOT_ALLOWED")


DEFAULT_PLANNER_POLICY = PlannerCompilationPolicy()


def _validate_proposal_dag(proposal: PlannerProposal) -> None:
    local_ids = [item.local_id for item in proposal.tasks]
    if len(local_ids) != len(set(local_ids)):
        raise ProposalCompilationError("DUPLICATE_PROPOSAL_ID")
    by_id = {item.local_id: item for item in proposal.tasks}
    for item in proposal.tasks:
        if len(item.dependencies) != len(set(item.dependencies)):
            raise ProposalCompilationError("DUPLICATE_PROPOSAL_DEPENDENCY")
        if item.local_id in item.dependencies:
            raise ProposalCompilationError("SELF_PROPOSAL_DEPENDENCY")
        for dependency in item.dependencies:
            if dependency not in by_id:
                raise ProposalCompilationError("MISSING_PROPOSAL_DEPENDENCY", dependency)
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(local_id: str) -> None:
        if local_id in visiting:
            raise ProposalCompilationError("PROPOSAL_DEPENDENCY_CYCLE")
        if local_id in visited:
            return
        visiting.add(local_id)
        for dependency in by_id[local_id].dependencies:
            visit(dependency)
        visiting.remove(local_id)
        visited.add(local_id)

    for local_id in local_ids:
        visit(local_id)


def compile_planner_proposal(
    authority: BoardAuthority,
    *,
    expected_revision: int,
    proposal: PlannerProposal,
    transaction_id: str,
    policy: PlannerCompilationPolicy = DEFAULT_PLANNER_POLICY,
    plan_task_id: str | None = None,
    stage_result_digest: str | None = None,
) -> ProposalCompilationResult:
    if not isinstance(authority, BoardAuthority) or not isinstance(proposal, PlannerProposal) or not isinstance(policy, PlannerCompilationPolicy):
        raise ProposalCompilationError("INVALID_COMPILER_INPUT")
    if expected_revision != authority.snapshot.revision:
        raise ProposalCompilationError("STALE_REVISION")
    if (plan_task_id is None) != (stage_result_digest is None):
        raise ProposalCompilationError("INVALID_PLAN_STAGE_BINDING")
    _validate_proposal_dag(proposal)
    if len(authority.snapshot.tasks) + len(proposal.tasks) > authority.snapshot.project.limits.max_tasks:
        raise ProposalCompilationError("PROJECT_TASK_LIMIT")
    for item in proposal.tasks:
        if item.task_type not in policy.allowed_task_types:
            raise ProposalCompilationError("TASK_TYPE_NOT_ALLOWED")
        if item.priority > policy.maximum_priority:
            raise ProposalCompilationError("PRIORITY_POLICY_REJECTED")
        if item.preferred_role is not policy.role_for(item.task_type):
            raise ProposalCompilationError("ROLE_POLICY_MISMATCH")
    next_sequence = max((item.creation_sequence for item in authority.snapshot.tasks), default=0) + 1
    local_to_authoritative = {
        item.local_id: f"task-{next_sequence + index:06d}" for index, item in enumerate(proposal.tasks)
    }
    existing = {item.task_id for item in authority.snapshot.tasks}
    if existing & set(local_to_authoritative.values()):
        raise ProposalCompilationError("CONTROLLER_ID_COLLISION")
    compiled = tuple(
        BoardTask(
            schema=BOARD_SCHEMA,
            task_id=local_to_authoritative[item.local_id],
            project_id=authority.snapshot.project.project_id,
            title=item.title,
            description=item.description,
            task_type=item.task_type,
            priority=item.priority,
            dependencies=tuple(local_to_authoritative[dependency] for dependency in item.dependencies),
            acceptance_criteria=policy.acceptance_for(item.task_type),
            preferred_role=policy.role_for(item.task_type),
            assigned_role=None,
            status=TaskStatus.BACKLOG,
            attempt_count=0,
            max_attempts=3,
            creation_sequence=next_sequence + index,
            creator="CONTROLLER_COMPILER",
            parent_task_id=None,
            root_task_id=local_to_authoritative[item.local_id],
            generation=1,
            workspace=authority.snapshot.project.workspace,
            lease_epoch=0,
            block_reason=None,
            terminal_reason=None,
            repair_failure_fingerprint=None,
            satisfying_descendant_id=None,
            verification_result_digest=None,
            review_result_digest=None,
        )
        for index, item in enumerate(proposal.tasks)
    )
    if plan_task_id is None:
        mutation = authority.add_tasks(
            expected_revision, compiled, transaction_id=transaction_id
        )
    else:
        mutation = authority.complete_stage_with_tasks(
            expected_revision,
            plan_task_id,
            compiled,
            result_digest=stage_result_digest,  # type: ignore[arg-type]
            transaction_id=transaction_id,
        )
    if not isinstance(mutation, AcceptedBoardMutation):
        raise ProposalCompilationError("AUTHORITATIVE_BOARD_REJECTED", mutation.detail)
    return ProposalCompilationResult(True, tuple(item.task_id for item in compiled))


class ReviewVerdict(str, Enum):
    PASS = "PASS"
    BLOCKING = "BLOCKING"


@dataclass(frozen=True, slots=True)
class ReviewFinding:
    code: str
    message: str

    def __post_init__(self) -> None:
        try:
            require_identifier("finding.code", self.code)
            require_text("finding.message", self.message, MAX_REVIEW_TEXT_BYTES)
        except ValueError as exc:
            raise _convert(exc, "INVALID_REVIEW_FINDING") from exc

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}

    @classmethod
    def from_dict(cls, raw: object) -> ReviewFinding:
        return cls(**_exact(raw, {"code", "message"}))


@dataclass(frozen=True, slots=True)
class ReviewerProposal:
    schema: str
    verdict: ReviewVerdict
    findings: tuple[ReviewFinding, ...]
    repair_recommendation: str | None
    evidence_refs: tuple[EvidenceRef, ...]

    def __post_init__(self) -> None:
        if self.schema != REVIEW_SCHEMA:
            raise ProposalCompilationError("INVALID_SCHEMA")
        if not isinstance(self.verdict, ReviewVerdict):
            raise ProposalCompilationError("INVALID_ENUM")
        if type(self.findings) is not tuple or len(self.findings) > MAX_REVIEW_FINDINGS:
            raise ProposalCompilationError("REVIEW_FINDING_LIMIT")
        if any(not isinstance(item, ReviewFinding) for item in self.findings):
            raise ProposalCompilationError("INVALID_REVIEW_FINDING")
        if type(self.evidence_refs) is not tuple or len(self.evidence_refs) > 32 or any(not isinstance(item, EvidenceRef) for item in self.evidence_refs):
            raise ProposalCompilationError("REVIEW_EVIDENCE_LIMIT")
        if self.repair_recommendation is not None:
            try:
                require_text("repair_recommendation", self.repair_recommendation, MAX_REVIEW_TEXT_BYTES)
            except ValueError as exc:
                raise ProposalCompilationError("REVIEW_TEXT_LIMIT") from exc
        if self.verdict is ReviewVerdict.PASS and (self.findings or self.repair_recommendation is not None):
            raise ProposalCompilationError("PASS_WITH_BLOCKING_CONTENT")
        if self.verdict is ReviewVerdict.BLOCKING and not self.findings:
            raise ProposalCompilationError("BLOCKING_WITHOUT_FINDING")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema, "verdict": self.verdict.value,
            "findings": [item.to_dict() for item in self.findings],
            "repair_recommendation": self.repair_recommendation,
            "evidence_refs": [item.to_dict() for item in self.evidence_refs],
        }

    @classmethod
    def from_dict(cls, raw: object) -> ReviewerProposal:
        value = _exact(raw, set(cls.__dataclass_fields__))
        try:
            verdict = require_enum(ReviewVerdict, "verdict", value["verdict"])
        except ValueError as exc:
            raise ProposalCompilationError("INVALID_ENUM") from exc
        if type(value["findings"]) is not list or type(value["evidence_refs"]) is not list:
            raise ProposalCompilationError("INVALID_REVIEW_SHAPE")
        return cls(
            schema=value["schema"], verdict=verdict,
            findings=tuple(ReviewFinding.from_dict(item) for item in value["findings"]),
            repair_recommendation=value["repair_recommendation"],
            evidence_refs=tuple(EvidenceRef.from_dict(item) for item in value["evidence_refs"]),
        )
