"""Bounded controller-owned continuation for the synthetic autonomous loop."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Callable, Protocol

from .board import AcceptedBoardMutation, BoardAuthority, BoardSnapshot
from .canonical import canonical_json_bytes
from .journal import TransactionJournal
from .models import (
    BOARD_SCHEMA,
    BaselineIdentity,
    BoardTask,
    ProjectRecord,
    ProjectStatus,
    Role,
    RunLimits,
    TaskStatus,
    TaskType,
    TerminalReason,
    WorkspaceIdentityRef,
    require_digest,
)
from .proposals import PlannerProposal, ProposalCompilationError, compile_planner_proposal
from .repair import RepairBudgetPolicy, RepairController
from .review import ReviewClassification, ReviewResult
from .verification import VerificationClassification, VerificationResult
from agenticos.sandbox.worktree import (
    WorktreeValidationError,
    acquire_repository_lock,
)

MAX_SCHEDULER_STEPS = 10_000


class SchedulerError(RuntimeError):
    """Stable typed scheduler failure."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail[:4096]
        super().__init__(f"{code}: {self.detail}" if self.detail else code)


@dataclass(frozen=True, slots=True)
class SchedulerLimits:
    max_steps: int = 128

    def __post_init__(self) -> None:
        if type(self.max_steps) is not int or not 1 <= self.max_steps <= MAX_SCHEDULER_STEPS:
            raise SchedulerError("INVALID_SCHEDULER_LIMIT")


@dataclass(frozen=True, slots=True)
class ResearchStageResult:
    result_digest: str
    content: bytes

    def __post_init__(self) -> None:
        require_digest("result_digest", self.result_digest)
        if type(self.content) is not bytes or hashlib.sha256(self.content).hexdigest() != self.result_digest:
            raise SchedulerError("INVALID_RESEARCH_RESULT")


@dataclass(frozen=True, slots=True)
class PlanningStageResult:
    result_digest: str
    proposal: PlannerProposal

    def __post_init__(self) -> None:
        require_digest("result_digest", self.result_digest)
        if not isinstance(self.proposal, PlannerProposal):
            raise SchedulerError("INVALID_PLANNING_RESULT")
        actual = hashlib.sha256(canonical_json_bytes(self.proposal.to_dict())).hexdigest()
        if actual != self.result_digest:
            raise SchedulerError("INVALID_PLANNING_RESULT")


class ExecutionClassification(str):
    SUCCESS = "SUCCESS"
    INFRASTRUCTURE_FAILURE = "INFRASTRUCTURE_FAILURE"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True, slots=True)
class ExecutionStageResult:
    task_id: str
    task_generation: int
    attempt: int
    controller_epoch: int
    lease_epoch: int
    classification: str
    checkpoint_digest: str | None
    evidence_digest: str
    payload: object | None

    def __post_init__(self) -> None:
        if self.classification not in {
            ExecutionClassification.SUCCESS,
            ExecutionClassification.INFRASTRUCTURE_FAILURE,
            ExecutionClassification.CANCELLED,
        }:
            raise SchedulerError("INVALID_EXECUTION_CLASSIFICATION")
        require_digest("evidence_digest", self.evidence_digest)
        require_digest(
            "checkpoint_digest",
            self.checkpoint_digest,
            allow_none=self.classification != ExecutionClassification.SUCCESS,
        )


@dataclass(frozen=True, slots=True)
class FinalizationEvidence:
    stable_checkpoint: bool
    checkpoint_digest: str | None
    active_execution: bool
    residue_free: bool

    def __post_init__(self) -> None:
        if any(type(value) is not bool for value in (
            self.stable_checkpoint, self.active_execution, self.residue_free
        )):
            raise SchedulerError("INVALID_FINALIZATION_EVIDENCE")
        require_digest(
            "checkpoint_digest",
            self.checkpoint_digest,
            allow_none=not self.stable_checkpoint,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "stable_checkpoint": self.stable_checkpoint,
            "checkpoint_digest": self.checkpoint_digest,
            "active_execution": self.active_execution,
            "residue_free": self.residue_free,
        }

    @property
    def evidence_digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class SchedulerEvent:
    sequence: int
    kind: str
    task_id: str | None
    message: str


@dataclass(frozen=True, slots=True)
class SchedulerResult:
    snapshot: BoardSnapshot
    events: tuple[SchedulerEvent, ...]
    steps: int
    final_checkpoint_digest: str | None


class StageDriver(Protocol):
    def run_research(self, snapshot: BoardSnapshot, task: BoardTask) -> ResearchStageResult: ...
    def run_plan(self, snapshot: BoardSnapshot, task: BoardTask, research_digest: str) -> PlanningStageResult: ...
    def reconcile_execution(self, snapshot: BoardSnapshot, task: BoardTask) -> ExecutionStageResult | None: ...
    def run_execution(self, snapshot: BoardSnapshot, task: BoardTask) -> ExecutionStageResult: ...
    def record_execution_success(self, authority: BoardAuthority, task_id: str, result: ExecutionStageResult, transaction_id: str) -> None: ...
    def run_verification(self, snapshot: BoardSnapshot, task: BoardTask) -> VerificationResult: ...
    def run_review(self, snapshot: BoardSnapshot, task: BoardTask, verification_result_digest: str) -> ReviewResult: ...
    def finalize_project(self, snapshot: BoardSnapshot) -> FinalizationEvidence: ...


def _bootstrap_task(
    *,
    project: ProjectRecord,
    task_id: str,
    title: str,
    description: str,
    task_type: TaskType,
    priority: int,
    dependencies: tuple[str, ...],
    role: Role,
    status: TaskStatus,
    sequence: int,
) -> BoardTask:
    return BoardTask(
        schema=BOARD_SCHEMA,
        task_id=task_id,
        project_id=project.project_id,
        title=title,
        description=description,
        task_type=task_type,
        priority=priority,
        dependencies=dependencies,
        acceptance_criteria=(
            "Controller validates one bounded provider-neutral result.",
        ),
        preferred_role=role,
        assigned_role=role,
        status=status,
        attempt_count=0,
        max_attempts=3,
        creation_sequence=sequence,
        creator="CONTROLLER",
        parent_task_id=None,
        root_task_id=task_id,
        generation=1,
        workspace=project.workspace,
        lease_epoch=0,
        block_reason=None,
        terminal_reason=None,
        repair_failure_fingerprint=None,
        satisfying_descendant_id=None,
        verification_result_digest=None,
        review_result_digest=None,
        stage_result_digest=None,
    )


def create_project(
    *,
    journal_root: Path,
    project_id: str,
    goal: str,
    baseline: BaselineIdentity,
    workspace: WorkspaceIdentityRef,
    limits: RunLimits,
    started_at_unix_ms: int,
    deadline_unix_ms: int,
) -> BoardAuthority:
    """Create the controller-owned bootstrap board from inert bounded goal text."""
    project = ProjectRecord(
        schema=BOARD_SCHEMA,
        project_id=project_id,
        goal=goal,
        baseline=baseline,
        workspace=workspace,
        status=ProjectStatus.CREATED,
        terminal_reason=None,
        board_revision=0,
        controller_epoch=1,
        lease_epoch=0,
        limits=limits,
        started_at_unix_ms=started_at_unix_ms,
        deadline_unix_ms=deadline_unix_ms,
        transition_sequence=0,
        transition_digest="0" * 64,
    )
    research = _bootstrap_task(
        project=project,
        task_id="bootstrap-research",
        title="Research owner goal",
        description="Produce one bounded deterministic research artifact.",
        task_type=TaskType.RESEARCH,
        priority=100,
        dependencies=(),
        role=Role.RESEARCHER,
        status=TaskStatus.READY,
        sequence=1,
    )
    plan = _bootstrap_task(
        project=project,
        task_id="bootstrap-plan",
        title="Plan authoritative work",
        description="Propose one bounded dependency DAG for controller compilation.",
        task_type=TaskType.PLAN,
        priority=90,
        dependencies=(research.task_id,),
        role=Role.PLANNER,
        status=TaskStatus.BACKLOG,
        sequence=2,
    )
    authority = BoardAuthority.create(
        TransactionJournal(Path(journal_root), project_id),
        BoardSnapshot.create(project, (research, plan)),
        transaction_id="tx-bootstrap-create",
    )
    activated = authority.transition_project(
        authority.snapshot.revision,
        ProjectStatus.ACTIVE,
        transaction_id="tx-bootstrap-activate",
    )
    if not isinstance(activated, AcceptedBoardMutation):
        raise SchedulerError("PROJECT_ACTIVATION_REJECTED", activated.detail)
    return authority


def select_next_ready(snapshot: BoardSnapshot) -> BoardTask | None:
    """Select from authoritative READY state; adapter/model output is irrelevant."""
    if not isinstance(snapshot, BoardSnapshot):
        raise SchedulerError("INVALID_BOARD_SNAPSHOT")
    ready = tuple(item for item in snapshot.tasks if item.status is TaskStatus.READY)
    if not ready:
        return None
    return min(ready, key=lambda item: (-item.priority, item.creation_sequence, item.task_id))


class AutonomousScheduler:
    """Small serialized continuation loop over durable board authority."""

    _ACTIVE = frozenset(
        {TaskStatus.IN_PROGRESS, TaskStatus.VERIFYING, TaskStatus.REVIEW}
    )

    def __init__(
        self,
        *,
        authority: BoardAuthority,
        driver: StageDriver,
        limits: SchedulerLimits = SchedulerLimits(),
        now_unix_ms: Callable[[], int],
        repair_policy: RepairBudgetPolicy = RepairBudgetPolicy(),
        controller_lock_timeout: float = 30.0,
    ) -> None:
        if not isinstance(authority, BoardAuthority):
            raise SchedulerError("INVALID_BOARD_AUTHORITY")
        self.authority = authority
        self.driver = driver
        self.limits = limits
        self.now_unix_ms = now_unix_ms
        self.repair_policy = repair_policy
        if (
            isinstance(controller_lock_timeout, bool)
            or not isinstance(controller_lock_timeout, (int, float))
            or not 0 < controller_lock_timeout <= 30.0
        ):
            raise SchedulerError("INVALID_CONTROLLER_LOCK_TIMEOUT")
        self.controller_lock_timeout = float(controller_lock_timeout)
        self.controller_lock_path = (
            authority.journal_root.parent
            / f".{authority.snapshot.project.project_id}.controller.lock"
        )
        self.repair_controller = RepairController()
        self._events: list[SchedulerEvent] = []
        self._final_checkpoint_digest = authority.snapshot.project.final_checkpoint_digest

    def _emit(self, kind: str, task_id: str | None, message: str) -> None:
        encoded = message.encode("utf-8")
        if len(encoded) > 1024:
            message = encoded[:1024].decode("utf-8", errors="ignore")
        self._events.append(
            SchedulerEvent(len(self._events) + 1, kind, task_id, message)
        )

    def _tx(self, action: str) -> str:
        sequence = self.authority.snapshot.project.transition_sequence + 1
        safe = "".join(char if char.isalnum() else "-" for char in action)[:48]
        return f"tx-scheduler-{sequence:06d}-{safe}"

    @staticmethod
    def _accepted(value, code: str) -> AcceptedBoardMutation:
        if not isinstance(value, AcceptedBoardMutation):
            raise SchedulerError(code, getattr(value, "detail", ""))
        return value

    def _transition_project(self, status: ProjectStatus, reason: TerminalReason) -> None:
        mutation = self.authority.transition_project(
            self.authority.snapshot.revision,
            status,
            terminal_reason=reason,
            transaction_id=self._tx(f"project-{status.value.lower()}"),
        )
        self._accepted(mutation, "PROJECT_TRANSITION_REJECTED")

    def _fail_task(self, task: BoardTask, reason: TerminalReason) -> None:
        mutation = self.authority.transition_task(
            self.authority.snapshot.revision,
            task.task_id,
            TaskStatus.FAILED,
            terminal_reason=reason,
            transaction_id=self._tx(f"fail-{task.task_id}"),
        )
        self._accepted(mutation, "TASK_FAILURE_REJECTED")
        self._emit("TASK_FAILED", task.task_id, f"{task.task_id} failed: {reason.value}")

    def _validate_execution_binding(
        self, task: BoardTask, result: ExecutionStageResult
    ) -> None:
        project = self.authority.snapshot.project
        if not all((
            result.task_id == task.task_id,
            result.task_generation == task.generation,
            result.attempt == task.attempt_count,
            result.controller_epoch == project.controller_epoch,
            result.lease_epoch == task.lease_epoch == project.lease_epoch,
        )):
            raise SchedulerError("STALE_EXECUTION_RESULT")

    def _handle_research(self, task: BoardTask) -> None:
        result = self.driver.run_research(self.authority.snapshot, task)
        if not isinstance(result, ResearchStageResult):
            raise SchedulerError("INVALID_RESEARCH_RESULT")
        mutation = self.authority.record_stage_success(
            self.authority.snapshot.revision,
            task.task_id,
            result_digest=result.result_digest,
            transaction_id=self._tx("research-complete"),
        )
        self._accepted(mutation, "RESEARCH_RESULT_REJECTED")
        self._emit("RESEARCH_COMPLETED", task.task_id, "Research completed")

    def _handle_plan(self, task: BoardTask) -> None:
        research = self.authority.snapshot.task("bootstrap-research")
        if research.status is not TaskStatus.DONE or research.stage_result_digest is None:
            raise SchedulerError("RESEARCH_CONTEXT_MISSING")
        result = self.driver.run_plan(
            self.authority.snapshot, task, research.stage_result_digest
        )
        if not isinstance(result, PlanningStageResult):
            raise SchedulerError("INVALID_PLANNING_RESULT")
        compiled = compile_planner_proposal(
            self.authority,
            expected_revision=self.authority.snapshot.revision,
            proposal=result.proposal,
            transaction_id=self._tx("plan-complete"),
            plan_task_id=task.task_id,
            stage_result_digest=result.result_digest,
        )
        self._emit(
            "PLAN_COMPLETED",
            task.task_id,
            f"Planning completed; board created with {len(compiled.authoritative_task_ids)} tasks",
        )

    def _handle_execution(self, task: BoardTask) -> None:
        result = self.driver.reconcile_execution(self.authority.snapshot, task)
        if result is None:
            result = self.driver.run_execution(self.authority.snapshot, task)
        if not isinstance(result, ExecutionStageResult):
            raise SchedulerError("INVALID_EXECUTION_RESULT")
        self._validate_execution_binding(task, result)
        if result.classification == ExecutionClassification.SUCCESS:
            self.driver.record_execution_success(
                self.authority,
                task.task_id,
                result,
                self._tx(f"execution-complete-{task.task_id}"),
            )
            if self.authority.snapshot.task(task.task_id).status is not TaskStatus.VERIFYING:
                raise SchedulerError("EXECUTION_ADVANCEMENT_MISSING")
            self._emit("BUILD_COMPLETED", task.task_id, f"{task.task_id} BUILD completed")
            return
        if result.classification == ExecutionClassification.CANCELLED:
            mutation = self.authority.transition_task(
                self.authority.snapshot.revision,
                task.task_id,
                TaskStatus.CANCELLED,
                terminal_reason=TerminalReason.CANCELLED_BY_OWNER,
                transaction_id=self._tx(f"cancel-{task.task_id}"),
            )
            self._accepted(mutation, "TASK_CANCELLATION_REJECTED")
            self._emit("TASK_CANCELLED", task.task_id, f"{task.task_id} cancelled")
            return
        self._fail_task(task, TerminalReason.CONTROLLER_FAILURE)

    def _handle_verification(self, task: BoardTask) -> None:
        if task.execution_checkpoint_digest is None or task.execution_evidence_digest is None:
            raise SchedulerError("EXECUTION_EVIDENCE_MISSING")
        result = self.driver.run_verification(self.authority.snapshot, task)
        if not isinstance(result, VerificationResult):
            raise SchedulerError("INVALID_VERIFICATION_RESULT")
        if result.checkpoint_digest != task.execution_checkpoint_digest:
            raise SchedulerError("VERIFICATION_CHECKPOINT_MISMATCH")
        if result.classification is VerificationClassification.PASS:
            self.repair_controller.record_verification_pass(
                authority=self.authority,
                task_id=task.task_id,
                result=result,
                transaction_id=self._tx(f"verification-pass-{task.task_id}"),
            )
            self._emit("VERIFY_PASSED", task.task_id, f"{task.task_id} VERIFY passed")
            return
        if result.classification is VerificationClassification.FAIL:
            outcome = self.repair_controller.create_for_verification_failure(
                authority=self.authority,
                parent_task_id=task.task_id,
                result=result,
                policy=self.repair_policy,
                now_unix_ms=self.now_unix_ms(),
                transaction_id=self._tx(f"verification-repair-{task.task_id}"),
            )
            self._emit("VERIFY_FAILED", task.task_id, f"{task.task_id} VERIFY failed")
            if outcome.repair_task_id is not None:
                self._emit("REPAIR_CREATED", outcome.repair_task_id, f"{outcome.repair_task_id} automatically created")
            return
        self._fail_task(task, TerminalReason.CONTROLLER_FAILURE)

    def _handle_review(self, task: BoardTask) -> None:
        if task.verification_result_digest is None:
            raise SchedulerError("VERIFICATION_RESULT_MISSING")
        result = self.driver.run_review(
            self.authority.snapshot, task, task.verification_result_digest
        )
        if not isinstance(result, ReviewResult):
            raise SchedulerError("INVALID_REVIEW_RESULT")
        if result.classification is ReviewClassification.PASS:
            waiting_ancestors = {
                item.task_id
                for item in self.authority.snapshot.tasks
                if item.status is TaskStatus.WAITING_REPAIR
            }
            self.repair_controller.satisfy_lineage(
                authority=self.authority,
                task_id=task.task_id,
                result=result,
                transaction_id=self._tx(f"review-pass-{task.task_id}"),
            )
            self._emit("REVIEW_PASSED", task.task_id, f"{task.task_id} REVIEW passed")
            for ancestor_id in sorted(waiting_ancestors):
                ancestor = self.authority.snapshot.task(ancestor_id)
                if (
                    ancestor.status is TaskStatus.DONE
                    and ancestor.satisfying_descendant_id == task.task_id
                ):
                    self._emit(
                        "TASK_SATISFIED",
                        ancestor.task_id,
                        f"{ancestor.task_id} satisfied by {task.task_id}",
                    )
            return
        if result.classification is ReviewClassification.BLOCKING:
            outcome = self.repair_controller.create_for_review_failure(
                authority=self.authority,
                parent_task_id=task.task_id,
                result=result,
                policy=self.repair_policy,
                now_unix_ms=self.now_unix_ms(),
                transaction_id=self._tx(f"review-repair-{task.task_id}"),
            )
            self._emit("REVIEW_BLOCKED", task.task_id, f"{task.task_id} REVIEW blocked")
            if outcome.repair_task_id is not None:
                self._emit("REPAIR_CREATED", outcome.repair_task_id, f"{outcome.repair_task_id} automatically created")
            return
        self._fail_task(task, TerminalReason.CONTROLLER_FAILURE)

    def _handle_active(self, task: BoardTask) -> None:
        if task.status is TaskStatus.IN_PROGRESS:
            if task.task_type is TaskType.RESEARCH:
                self._handle_research(task)
            elif task.task_type is TaskType.PLAN:
                self._handle_plan(task)
            else:
                self._handle_execution(task)
        elif task.status is TaskStatus.VERIFYING:
            self._handle_verification(task)
        elif task.status is TaskStatus.REVIEW:
            self._handle_review(task)
        else:
            raise SchedulerError("INVALID_ACTIVE_STAGE")

    def _terminal_result(self, steps: int) -> SchedulerResult:
        return SchedulerResult(
            self.authority.snapshot,
            tuple(self._events),
            steps,
            self._final_checkpoint_digest,
        )

    def _stop_requested(self, stop_after: str | None) -> bool:
        return bool(
            stop_after is not None
            and any(event.kind == stop_after for event in self._events)
        )

    def run(self, *, stop_after: str | None = None) -> SchedulerResult:
        if stop_after is not None and (type(stop_after) is not str or not stop_after):
            raise SchedulerError("INVALID_STOP_BOUNDARY")
        try:
            with acquire_repository_lock(
                self.controller_lock_path,
                timeout=self.controller_lock_timeout,
            ):
                return self._run_locked(stop_after=stop_after)
        except WorktreeValidationError as exc:
            raise SchedulerError("CONTROLLER_LOCK_UNAVAILABLE", str(exc)) from exc

    def _run_locked(self, *, stop_after: str | None) -> SchedulerResult:
        self._emit(
            "PROJECT_CREATED",
            None,
            f"Project {self.authority.snapshot.project.project_id} created",
        )
        for step in range(1, self.limits.max_steps + 1):
            snapshot = self.authority.snapshot
            project = snapshot.project
            if project.status in {
                ProjectStatus.DONE,
                ProjectStatus.FAILED,
                ProjectStatus.CANCELLED,
                ProjectStatus.OWNER_BLOCKED,
            }:
                return self._terminal_result(step - 1)
            if self.now_unix_ms() >= project.deadline_unix_ms:
                active = tuple(item for item in snapshot.tasks if item.status in self._ACTIVE)
                if len(active) > 1:
                    self._transition_project(ProjectStatus.FAILED, TerminalReason.INVALID_CONTROLLER_STATE)
                    self._emit("PROJECT_FAILED", None, "Multiple active stages at deadline")
                    return self._terminal_result(step)
                if active:
                    current = active[0]
                    if (
                        current.status is TaskStatus.IN_PROGRESS
                        and current.task_type not in {TaskType.RESEARCH, TaskType.PLAN}
                    ):
                        try:
                            reconciled = self.driver.reconcile_execution(snapshot, current)
                            if reconciled is not None:
                                self._validate_execution_binding(current, reconciled)
                                if reconciled.classification == ExecutionClassification.SUCCESS:
                                    self.driver.record_execution_success(
                                        self.authority,
                                        current.task_id,
                                        reconciled,
                                        self._tx(f"deadline-reconcile-{current.task_id}"),
                                    )
                        except (SchedulerError, ProposalCompilationError):
                            pass
                    current = self.authority.snapshot.task(current.task_id)
                    if current.status in self._ACTIVE:
                        self._fail_task(current, TerminalReason.RESOURCE_LIMIT)
                self._transition_project(ProjectStatus.FAILED, TerminalReason.RESOURCE_LIMIT)
                self._emit("PROJECT_FAILED", None, "Project deadline exhausted")
                return self._terminal_result(step)

            failed = tuple(item for item in snapshot.tasks if item.status is TaskStatus.FAILED)
            if failed:
                reason = failed[0].terminal_reason or TerminalReason.CONTROLLER_FAILURE
                self._transition_project(ProjectStatus.FAILED, reason)
                self._emit("PROJECT_FAILED", None, f"Project failed after {failed[0].task_id}")
                return self._terminal_result(step)
            cancelled = tuple(item for item in snapshot.tasks if item.status is TaskStatus.CANCELLED)
            if cancelled:
                self._transition_project(ProjectStatus.CANCELLED, TerminalReason.CANCELLED_BY_OWNER)
                self._emit("PROJECT_CANCELLED", None, "Project cancelled")
                return self._terminal_result(step)

            active = tuple(item for item in snapshot.tasks if item.status in self._ACTIVE)
            if len(active) > 1:
                self._transition_project(ProjectStatus.FAILED, TerminalReason.INVALID_CONTROLLER_STATE)
                self._emit("PROJECT_FAILED", None, "Multiple active stages")
                return self._terminal_result(step)
            if active:
                try:
                    self._handle_active(active[0])
                except (SchedulerError, ProposalCompilationError) as exc:
                    current = self.authority.snapshot.task(active[0].task_id)
                    if current.status in self._ACTIVE:
                        self._fail_task(current, TerminalReason.CONTROLLER_FAILURE)
                    self._emit(
                        "STAGE_REJECTED",
                        active[0].task_id,
                        f"{active[0].task_id} rejected: {getattr(exc, 'code', type(exc).__name__)}",
                    )
                if self._stop_requested(stop_after):
                    return self._terminal_result(step)
                continue

            ready_candidates = tuple(
                item
                for item in snapshot.tasks
                if item.status is TaskStatus.BACKLOG
                and all(snapshot.task(dep).status is TaskStatus.DONE for dep in item.dependencies)
            )
            if ready_candidates:
                mutation = self.authority.derive_ready(
                    snapshot.revision,
                    transaction_id=self._tx("derive-ready"),
                )
                accepted = self._accepted(mutation, "READY_DERIVATION_REJECTED")
                for item in accepted.changed_tasks:
                    self._emit("TASK_READY", item.task_id, f"{item.task_id} READY")
                if self._stop_requested(stop_after):
                    return self._terminal_result(step)
                continue

            task = select_next_ready(snapshot)
            if task is not None:
                attempts = sum(item.attempt_count for item in snapshot.tasks)
                if attempts >= project.limits.max_total_attempts:
                    self._transition_project(ProjectStatus.FAILED, TerminalReason.RESOURCE_LIMIT)
                    self._emit("PROJECT_FAILED", None, "Total attempt limit exhausted")
                    return self._terminal_result(step)
                mutation = self.authority.transition_task(
                    snapshot.revision,
                    task.task_id,
                    TaskStatus.IN_PROGRESS,
                    transaction_id=self._tx(f"start-{task.task_id}"),
                )
                self._accepted(mutation, "TASK_START_REJECTED")
                self._emit("TASK_STARTED", task.task_id, f"{task.task_id} {task.task_type.value} started")
                if self._stop_requested(stop_after):
                    return self._terminal_result(step)
                continue

            if snapshot.tasks and all(item.status is TaskStatus.DONE for item in snapshot.tasks):
                evidence = self.driver.finalize_project(snapshot)
                if (
                    not isinstance(evidence, FinalizationEvidence)
                    or not evidence.stable_checkpoint
                    or evidence.active_execution
                    or not evidence.residue_free
                    or evidence.checkpoint_digest is None
                ):
                    self._transition_project(ProjectStatus.FAILED, TerminalReason.CONTROLLER_FAILURE)
                    self._emit("PROJECT_FAILED", None, "Final workspace evidence incomplete")
                    return self._terminal_result(step)
                mutation = self.authority.complete_project(
                    snapshot.revision,
                    checkpoint_digest=evidence.checkpoint_digest,
                    evidence_digest=evidence.evidence_digest,
                    transaction_id=self._tx("project-done"),
                )
                self._accepted(mutation, "PROJECT_COMPLETION_REJECTED")
                self._final_checkpoint_digest = evidence.checkpoint_digest
                self._emit("PROJECT_DONE", None, "PROJECT DONE")
                return self._terminal_result(step)

            self._transition_project(ProjectStatus.FAILED, TerminalReason.INVALID_CONTROLLER_STATE)
            self._emit("PROJECT_FAILED", None, "No READY task and project nonterminal")
            return self._terminal_result(step)

        if self.authority.snapshot.project.status is ProjectStatus.ACTIVE:
            self._transition_project(ProjectStatus.FAILED, TerminalReason.RESOURCE_LIMIT)
            self._emit("PROJECT_FAILED", None, "Maximum scheduler steps exhausted")
        return self._terminal_result(self.limits.max_steps)
