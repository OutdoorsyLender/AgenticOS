"""Idempotent controller repair creation and root-lineage budgets."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from pathlib import Path

from .board import AcceptedBoardMutation, BoardAuthority
from .canonical import canonical_json_bytes
from .execution import (
    ExecutionLedger,
    ExecutionOutcome,
    ExecutionState,
    SyntheticBuildController,
    create_containment_reservation,
)
from .models import (
    BOARD_SCHEMA,
    BoardTask,
    ControllerValidationError,
    Role,
    TaskStatus,
    TaskType,
    require_uint,
)
from .review import ReviewClassification, ReviewResult
from .protocol import (
    AGENT_PROTOCOL_SCHEMA,
    AgentCapability,
    AgentTaskRequest,
    ContextItem,
    ContextKind,
    DispatchIdentity,
    ProtocolLimits,
    ResultStatus,
)
from .synthetic import SyntheticScenario, build_synthetic_workspace_argv
from .verification import FailureClassification, VerificationClassification, VerificationResult
from .workspace import (
    LEASE_IDENTITY_SCHEMA,
    WorkspaceLeaseAdmission,
    WorkspaceLeaseIdentity,
    WorkspaceLeaseLedger,
    WorkspaceLeaseState,
)
from agenticos.sandbox.runtime_boundary import M4AProfile


class RepairError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail[:4096]
        super().__init__(f"{code}: {self.detail}" if self.detail else code)


@dataclass(frozen=True, slots=True)
class RepairBudgetPolicy:
    max_repair_tasks: int = 8
    max_distinct_fingerprints: int = 8
    max_repeated_fingerprint_count: int = 1
    max_consecutive_failures: int = 8

    def __post_init__(self) -> None:
        try:
            for name in self.__dataclass_fields__:
                require_uint(name, getattr(self, name), maximum=128)
        except ControllerValidationError as exc:
            raise RepairError(exc.code, exc.detail) from exc


@dataclass(frozen=True, slots=True)
class RepairBudgetUsage:
    total_attempts: int
    repair_depth: int
    repair_tasks: int
    distinct_failure_fingerprints: int
    repeated_fingerprint_count: int
    consecutive_failures: int
    total_tasks: int
    deadline_exhausted: bool


@dataclass(frozen=True, slots=True)
class RepairCreationOutcome:
    created: bool
    repair_task_id: str | None
    failure_classification: FailureClassification | None
    budget_usage: RepairBudgetUsage


@dataclass(frozen=True, slots=True)
class LineageSatisfactionOutcome:
    applied: bool
    satisfying_task_id: str


@dataclass(frozen=True, slots=True)
class RepairExecutionOutcome:
    dispatch: DispatchIdentity
    request: AgentTaskRequest
    lease: WorkspaceLeaseIdentity
    pre_checkpoint_digest: str
    terminal_status: str
    execution: ExecutionOutcome


class SyntheticRepairAdapter:
    """One explicit controller-built L2 repair dispatch; never selects work."""

    _SCENARIOS = frozenset(
        {SyntheticScenario.REPAIR_FEATURE, SyntheticScenario.REPAIR_REVIEW}
    )

    def __init__(self, scenario: SyntheticScenario) -> None:
        if scenario not in self._SCENARIOS:
            raise RepairError("INVALID_REPAIR_SCENARIO")
        self.scenario = scenario

    @staticmethod
    def _protocol_limits(board) -> ProtocolLimits:
        limits = board.project.limits
        return ProtocolLimits(
            max_events=limits.max_events_per_attempt,
            max_event_bytes=limits.max_event_bytes,
            max_output_bytes=limits.max_output_bytes,
            max_context_entries=limits.max_context_entries,
            max_context_bytes=limits.max_context_bytes,
            max_processes=limits.max_processes,
            max_runtime_seconds=limits.max_runtime_seconds,
        )

    def execute(
        self,
        *,
        board,
        repair_task_id: str,
        checkpoint_capture: object,
        lease_ledger: WorkspaceLeaseLedger,
        execution_root: Path,
        runner: object,
        workspace_manager: object,
        repo_path: Path,
        timeout: float,
    ) -> RepairExecutionOutcome:
        try:
            task = board.task(repair_task_id)
            checkpoint = checkpoint_capture.checkpoint
        except (AttributeError, KeyError):
            raise RepairError("INVALID_REPAIR_EXECUTION_INPUT") from None
        if (
            task.task_type is not TaskType.REPAIR
            or task.status is not TaskStatus.IN_PROGRESS
            or task.assigned_role is not Role.BUILDER
            or board.project.lease_epoch != task.lease_epoch
            or checkpoint is None
            or getattr(runner, "profile", None) is not M4AProfile.BUILD
        ):
            raise RepairError("INVALID_REPAIR_EXECUTION_INPUT")
        nonce = secrets.token_hex(16)
        dispatch = DispatchIdentity(
            project_id=task.project_id,
            task_id=task.task_id,
            task_generation=task.generation,
            attempt=task.attempt_count,
            controller_epoch=board.project.controller_epoch,
            lease_epoch=task.lease_epoch,
            dispatch_nonce=nonce,
            repository_id=board.project.baseline.repository_id,
            baseline_commit=board.project.baseline.commit_sha,
            workspace_id=task.workspace.workspace_id,
            workspace_generation=task.workspace.generation,
            reservation_id=task.workspace.reservation_id,
            checkpoint_digest=checkpoint.checkpoint_digest,
        )
        request = AgentTaskRequest(
            schema=AGENT_PROTOCOL_SCHEMA,
            identity=dispatch,
            role=Role.BUILDER,
            provider_id="synthetic-repair",
            model_id="deterministic-repair-v1",
            workspace_mount="/workspace",
            instructions=(
                "Apply only the fixed controller-selected deterministic repair "
                "inside /workspace."
            ),
            acceptance_criteria=task.acceptance_criteria,
            context_manifest=(ContextItem(
                ContextKind.WORKSPACE_MANIFEST,
                "pre-repair-checkpoint",
                checkpoint.checkpoint_digest,
                64,
            ),),
            capabilities=(
                AgentCapability.READ_CONTEXT,
                AgentCapability.READ_WORKSPACE,
                AgentCapability.WRITE_WORKSPACE,
            ),
            limits=self._protocol_limits(board),
        )
        lease = WorkspaceLeaseIdentity(
            LEASE_IDENTITY_SCHEMA,
            dispatch.project_id,
            dispatch.task_id,
            dispatch.task_generation,
            dispatch.attempt,
            dispatch.controller_epoch,
            dispatch.lease_epoch,
            task.workspace,
            dispatch.dispatch_nonce,
            dispatch.checkpoint_digest,
        )
        admission = WorkspaceLeaseAdmission.issue(
            board=board, identity=lease, checkpoint_capture=checkpoint_capture
        )
        lease_ledger.acquire(lease, admission)
        reservation = create_containment_reservation(dispatch)
        controller = SyntheticBuildController(ExecutionLedger(execution_root, dispatch))
        outcome = controller.execute(
            board=board,
            dispatch=dispatch,
            lease_ledger=lease_ledger,
            pre_checkpoint=checkpoint,
            runner=runner,
            reservation=reservation,
            argv=build_synthetic_workspace_argv(request, self.scenario),
            workspace_manager=workspace_manager,
            repo_path=repo_path,
            timeout=timeout,
            request=request,
        )
        records = controller.ledger.records()
        if (
            len(records) < 2
            or records[-1] != outcome.terminal_record
            or records[-1].state is not ExecutionState.TERMINAL_CAPTURED
            or records[-2].state is not ExecutionState.PROCESS_TERMINATED
        ):
            raise RepairError("REPAIR_TERMINAL_EVIDENCE_MISSING")
        lease_record = lease_ledger.recover()
        if (
            lease_record is None
            or lease_record.identity != lease
            or lease_record.state
            not in {WorkspaceLeaseState.RELEASED, WorkspaceLeaseState.CANCELLED}
        ):
            raise RepairError("REPAIR_LEASE_TERMINAL_EVIDENCE_MISSING")
        return RepairExecutionOutcome(
            dispatch,
            request,
            lease,
            checkpoint.checkpoint_digest,
            records[-2].terminal_status,  # type: ignore[arg-type]
            outcome,
        )


class RepairController:
    """Stage-specific repair authority; it never selects or executes a next task."""

    @staticmethod
    def _depth(snapshot, task: BoardTask) -> int:
        by_id = {item.task_id: item for item in snapshot.tasks}
        depth = 0
        current = task
        seen: set[str] = set()
        while current.parent_task_id is not None:
            if current.task_id in seen:
                raise RepairError("INVALID_REPAIR_LINEAGE")
            seen.add(current.task_id)
            depth += 1
            current = by_id[current.parent_task_id]
        return depth

    @classmethod
    def _usage(
        cls,
        snapshot,
        parent: BoardTask,
        fingerprint: str,
        *,
        now_unix_ms: int,
    ) -> RepairBudgetUsage:
        lineage = tuple(
            item for item in snapshot.tasks if item.root_task_id == parent.root_task_id
        )
        fingerprints = tuple(
            item.repair_failure_fingerprint
            for item in lineage
            if item.repair_failure_fingerprint is not None
        )
        return RepairBudgetUsage(
            total_attempts=sum(item.attempt_count for item in lineage),
            repair_depth=cls._depth(snapshot, parent) + 1,
            repair_tasks=sum(item.parent_task_id is not None for item in lineage),
            distinct_failure_fingerprints=len(set(fingerprints) | {fingerprint}),
            repeated_fingerprint_count=fingerprints.count(fingerprint) + 1,
            consecutive_failures=cls._depth(snapshot, parent) + 1,
            total_tasks=len(snapshot.tasks),
            deadline_exhausted=now_unix_ms >= snapshot.project.deadline_unix_ms,
        )

    @staticmethod
    def _exhausted(snapshot, usage: RepairBudgetUsage, policy: RepairBudgetPolicy) -> bool:
        limits = snapshot.project.limits
        return any(
            (
                usage.total_attempts + 1 > limits.max_total_attempts,
                usage.repair_depth > limits.max_repair_depth,
                usage.repair_tasks + 1 > policy.max_repair_tasks,
                usage.distinct_failure_fingerprints > policy.max_distinct_fingerprints,
                usage.repeated_fingerprint_count > policy.max_repeated_fingerprint_count,
                usage.consecutive_failures > policy.max_consecutive_failures,
                usage.total_tasks + 1 > limits.max_tasks,
                usage.deadline_exhausted,
            )
        )

    @staticmethod
    def _validate_result_binding(parent: BoardTask, result: object) -> None:
        if not all(
            (
                result.project_id == parent.project_id,
                result.task_id == parent.task_id,
                result.task_generation == parent.generation,
                result.attempt == parent.attempt_count,
            )
        ):
            raise RepairError("STALE_IDENTITY")

    @staticmethod
    def _validate_controller_epoch(authority: BoardAuthority, result: object) -> None:
        if result.controller_epoch != authority.snapshot.project.controller_epoch:
            raise RepairError("STALE_IDENTITY")

    @staticmethod
    def _task_id(root_task_id: str, fingerprint: str) -> str:
        digest = hashlib.sha256(
            canonical_json_bytes(
                {"root_task_id": root_task_id, "failure_fingerprint": fingerprint}
            )
        ).hexdigest()
        return f"repair-{digest[:32]}"

    @classmethod
    def _create(
        cls,
        *,
        authority: BoardAuthority,
        parent_task_id: str,
        fingerprint: str,
        result_digest: str,
        verification_result_digest: str | None,
        policy: RepairBudgetPolicy,
        now_unix_ms: int,
        transaction_id: str,
    ) -> RepairCreationOutcome:
        snapshot = authority.snapshot
        try:
            parent = snapshot.task(parent_task_id)
        except KeyError:
            raise RepairError("UNKNOWN_TASK") from None
        same = tuple(
            item
            for item in snapshot.tasks
            if item.root_task_id == parent.root_task_id
            and item.repair_failure_fingerprint == fingerprint
        )
        usage = cls._usage(snapshot, parent, fingerprint, now_unix_ms=now_unix_ms)
        if same:
            direct = tuple(item for item in same if item.parent_task_id == parent.task_id)
            if len(direct) == 1:
                return RepairCreationOutcome(False, direct[0].task_id, None, usage)
        if cls._exhausted(snapshot, usage, policy) or same:
            mutation = authority.fail_repair_budget(
                snapshot.revision,
                parent.task_id,
                result_digest=result_digest,
                verification_result_digest=verification_result_digest,
                transaction_id=transaction_id,
            )
            if not isinstance(mutation, AcceptedBoardMutation):
                raise RepairError("AUTHORITATIVE_BOARD_REJECTED", mutation.detail)
            return RepairCreationOutcome(
                False, None, FailureClassification.REPAIR_BUDGET_EXHAUSTED, usage
            )
        task_id = cls._task_id(parent.root_task_id, fingerprint)
        if any(item.task_id == task_id for item in snapshot.tasks):
            raise RepairError("REPAIR_TASK_ID_COLLISION")
        child = BoardTask(
            schema=BOARD_SCHEMA,
            task_id=task_id,
            project_id=parent.project_id,
            title=f"Repair {parent.title}"[:200],
            description="Repair the controller-measured failure without changing controller authority.",
            task_type=TaskType.REPAIR,
            priority=parent.priority,
            dependencies=parent.dependencies,
            acceptance_criteria=(
                f"Resolve failure fingerprint {fingerprint}.",
                "Pass controller-owned verification and independent review.",
            ),
            preferred_role=Role.BUILDER,
            assigned_role=Role.BUILDER,
            status=TaskStatus.READY,
            attempt_count=0,
            max_attempts=parent.max_attempts,
            creation_sequence=max(item.creation_sequence for item in snapshot.tasks) + 1,
            creator="CONTROLLER",
            parent_task_id=parent.task_id,
            root_task_id=parent.root_task_id,
            generation=max(item.generation for item in snapshot.tasks if item.root_task_id == parent.root_task_id) + 1,
            workspace=parent.workspace,
            lease_epoch=snapshot.project.lease_epoch,
            block_reason=None,
            terminal_reason=None,
            repair_failure_fingerprint=fingerprint,
            satisfying_descendant_id=None,
            verification_result_digest=None,
            review_result_digest=None,
        )
        mutation = authority.create_repair(
            snapshot.revision,
            parent.task_id,
            child,
            result_digest=result_digest,
            verification_result_digest=verification_result_digest,
            transaction_id=transaction_id,
        )
        if not isinstance(mutation, AcceptedBoardMutation):
            raise RepairError("AUTHORITATIVE_BOARD_REJECTED", mutation.detail)
        return RepairCreationOutcome(True, child.task_id, None, usage)

    def create_for_verification_failure(
        self,
        *,
        authority: BoardAuthority,
        parent_task_id: str,
        result: VerificationResult,
        policy: RepairBudgetPolicy,
        now_unix_ms: int,
        transaction_id: str,
    ) -> RepairCreationOutcome:
        if (
            not isinstance(result, VerificationResult)
            or result.classification is not VerificationClassification.FAIL
            or result.failure_classification is not FailureClassification.VERIFICATION_FAILURE
            or result.failure_fingerprint is None
        ):
            raise RepairError("INELIGIBLE_REPAIR_FAILURE")
        parent = authority.snapshot.task(parent_task_id)
        self._validate_result_binding(parent, result)
        self._validate_controller_epoch(authority, result)
        return self._create(
            authority=authority, parent_task_id=parent_task_id,
            fingerprint=result.failure_fingerprint, result_digest=result.result_digest,
            verification_result_digest=None, policy=policy,
            now_unix_ms=now_unix_ms, transaction_id=transaction_id,
        )

    def create_for_review_failure(
        self,
        *,
        authority: BoardAuthority,
        parent_task_id: str,
        result: ReviewResult,
        policy: RepairBudgetPolicy,
        now_unix_ms: int,
        transaction_id: str,
    ) -> RepairCreationOutcome:
        if (
            not isinstance(result, ReviewResult)
            or result.classification is not ReviewClassification.BLOCKING
            or result.failure_classification is not FailureClassification.REVIEW_BLOCKING_FINDING
            or result.failure_fingerprint is None
        ):
            raise RepairError("INELIGIBLE_REPAIR_FAILURE")
        parent = authority.snapshot.task(parent_task_id)
        self._validate_result_binding(parent, result)
        self._validate_controller_epoch(authority, result)
        if parent.verification_result_digest != result.verification_result_digest:
            raise RepairError("STALE_VERIFICATION_RESULT")
        return self._create(
            authority=authority, parent_task_id=parent_task_id,
            fingerprint=result.failure_fingerprint, result_digest=result.result_digest,
            verification_result_digest=result.verification_result_digest,
            policy=policy, now_unix_ms=now_unix_ms, transaction_id=transaction_id,
        )

    def record_verification_pass(
        self,
        *,
        authority: BoardAuthority,
        task_id: str,
        result: VerificationResult,
        transaction_id: str,
    ) -> bool:
        if (
            not isinstance(result, VerificationResult)
            or result.classification is not VerificationClassification.PASS
        ):
            raise RepairError("VERIFICATION_NOT_PASS")
        task = authority.snapshot.task(task_id)
        self._validate_result_binding(task, result)
        self._validate_controller_epoch(authority, result)
        if (
            task.status is TaskStatus.REVIEW
            and task.verification_result_digest == result.result_digest
        ):
            return False
        if task.status is not TaskStatus.VERIFYING:
            raise RepairError("STALE_IDENTITY")
        mutation = authority.record_verification_pass(
            authority.snapshot.revision,
            task_id,
            result_digest=result.result_digest,
            transaction_id=transaction_id,
        )
        if not isinstance(mutation, AcceptedBoardMutation):
            raise RepairError("AUTHORITATIVE_BOARD_REJECTED", mutation.detail)
        return True

    def record_execution_success(
        self,
        *,
        authority: BoardAuthority,
        task_id: str,
        result: RepairExecutionOutcome,
        transaction_id: str,
    ) -> bool:
        if not isinstance(result, RepairExecutionOutcome):
            raise RepairError("INVALID_REPAIR_EXECUTION_RESULT")
        task = authority.snapshot.task(task_id)
        dispatch = result.dispatch
        execution = result.execution
        agent_result = execution.agent_result
        valid_binding = (
            task.task_type is TaskType.REPAIR,
            task.status is TaskStatus.IN_PROGRESS,
            dispatch.project_id == task.project_id,
            dispatch.task_id == task.task_id,
            dispatch.task_generation == task.generation,
            dispatch.attempt == task.attempt_count,
            dispatch.controller_epoch == authority.snapshot.project.controller_epoch,
            dispatch.lease_epoch
            == task.lease_epoch
            == authority.snapshot.project.lease_epoch,
            dispatch.workspace_id == task.workspace.workspace_id,
            dispatch.workspace_generation == task.workspace.generation,
            dispatch.reservation_id == task.workspace.reservation_id,
            dispatch.checkpoint_digest == result.pre_checkpoint_digest,
            result.lease.task_id == task.task_id,
            result.lease.dispatch_nonce == dispatch.dispatch_nonce,
            execution.terminal_record.dispatch == dispatch,
            execution.terminal_record.state is ExecutionState.TERMINAL_CAPTURED,
            execution.first_checkpoint == execution.second_checkpoint,
            execution.first_checkpoint.checkpoint_digest
            == execution.terminal_record.checkpoint_digest,
            execution.first_checkpoint.checkpoint_digest
            != result.pre_checkpoint_digest,
            result.terminal_status == "SUCCEEDED",
            execution.process_result.exit_code == 0,
            not execution.process_result.timed_out,
            not execution.process_result.output_limit_exceeded,
            execution.protocol_rejection_code is None,
            agent_result is not None,
            agent_result.identity == dispatch if agent_result is not None else False,
            agent_result.status is ResultStatus.SUCCEEDED
            if agent_result is not None
            else False,
        )
        if not all(valid_binding):
            raise RepairError("INVALID_REPAIR_EXECUTION_RESULT")
        mutation = authority.record_execution_success(
            authority.snapshot.revision,
            task_id,
            checkpoint_digest=execution.first_checkpoint.checkpoint_digest,
            evidence_digest=execution.terminal_record.record_digest,
            transaction_id=transaction_id,
        )
        if not isinstance(mutation, AcceptedBoardMutation):
            raise RepairError("AUTHORITATIVE_BOARD_REJECTED", mutation.detail)
        return True

    def satisfy_lineage(
        self,
        *,
        authority: BoardAuthority,
        task_id: str,
        result: ReviewResult,
        transaction_id: str,
    ) -> LineageSatisfactionOutcome:
        if (
            not isinstance(result, ReviewResult)
            or result.classification is not ReviewClassification.PASS
        ):
            raise RepairError("REVIEW_NOT_PASS")
        task = authority.snapshot.task(task_id)
        self._validate_result_binding(task, result)
        self._validate_controller_epoch(authority, result)
        if (
            task.status is TaskStatus.DONE
            and task.terminal_reason is not None
            and task.review_result_digest == result.result_digest
        ):
            return LineageSatisfactionOutcome(False, task.task_id)
        if (
            task.status is not TaskStatus.REVIEW
            or task.verification_result_digest != result.verification_result_digest
        ):
            raise RepairError("STALE_VERIFICATION_RESULT")
        mutation = authority.satisfy_lineage(
            authority.snapshot.revision,
            task.task_id,
            verification_result_digest=result.verification_result_digest,
            review_result_digest=result.result_digest,
            transaction_id=transaction_id,
        )
        if not isinstance(mutation, AcceptedBoardMutation):
            raise RepairError("AUTHORITATIVE_BOARD_REJECTED", mutation.detail)
        return LineageSatisfactionOutcome(True, task.task_id)
