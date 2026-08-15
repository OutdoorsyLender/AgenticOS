from __future__ import annotations

from dataclasses import replace
import hashlib

import pytest

from agenticos.orchestration.board import BoardSnapshot
from agenticos.orchestration.models import (
    ProjectStatus,
    BlockReason,
    Role,
    RunLimits,
    TaskStatus,
    TaskType,
)
from agenticos.orchestration.scheduler import (
    AutonomousScheduler,
    ExecutionClassification,
    ExecutionStageResult,
    FinalizationEvidence,
    PlanningStageResult,
    ResearchStageResult,
    SchedulerError,
    SchedulerLimits,
    create_project,
    select_next_ready,
)
from agenticos.orchestration.canonical import canonical_json_bytes
from agenticos.orchestration.proposals import (
    PLANNER_SCHEMA,
    REVIEW_SCHEMA,
    PlannerProposal,
    ProposedTask,
    ReviewFinding,
    ReviewerProposal,
    ReviewVerdict,
)
from agenticos.orchestration.review import (
    REVIEW_RESULT_SCHEMA,
    ReviewClassification,
    ReviewResult,
    ReviewerExecutionIdentity,
)
from agenticos.orchestration.verification import (
    VERIFICATION_RESULT_SCHEMA,
    FailureClassification,
    ReadonlyProcessEvidence,
    VerificationClassification,
    VerificationExitClassification,
    VerificationResult,
)
from agenticos.sandbox.worktree import acquire_repository_lock
from tests.orchestration.test_models import baseline, project, task, workspace


def test_create_project_owns_bootstrap_identity_dependencies_and_limits(tmp_path) -> None:
    limits = RunLimits(max_tasks=12, max_total_attempts=20)
    authority = create_project(
        journal_root=tmp_path / "journal",
        project_id="demo-001",
        goal="Add the requested feature to the fixture application.",
        baseline=baseline(),
        workspace=workspace(),
        limits=limits,
        started_at_unix_ms=1_000,
        deadline_unix_ms=61_000,
    )
    snapshot = authority.snapshot
    assert snapshot.project.status is ProjectStatus.ACTIVE
    assert snapshot.project.goal == "Add the requested feature to the fixture application."
    assert snapshot.project.baseline == baseline()
    assert snapshot.project.workspace == workspace()
    assert snapshot.project.limits == limits
    assert snapshot.project.board_revision == 1
    assert [item.task_id for item in snapshot.tasks] == [
        "bootstrap-research",
        "bootstrap-plan",
    ]
    research, plan = snapshot.tasks
    assert (research.task_type, research.preferred_role, research.status) == (
        TaskType.RESEARCH,
        Role.RESEARCHER,
        TaskStatus.READY,
    )
    assert (plan.task_type, plan.preferred_role, plan.status) == (
        TaskType.PLAN,
        Role.PLANNER,
        TaskStatus.BACKLOG,
    )
    assert plan.dependencies == (research.task_id,)


def test_create_project_rejects_goal_as_authority_or_mutable_limit_input(tmp_path) -> None:
    with pytest.raises(ValueError, match="TEXT_LIMIT_EXCEEDED"):
        create_project(
            journal_root=tmp_path / "journal",
            project_id="demo-001",
            goal="x" * 8193,
            baseline=baseline(),
            workspace=workspace(),
            limits=RunLimits(),
            started_at_unix_ms=1_000,
            deadline_unix_ms=61_000,
        )
    raw_goal = "$(git push) C:\\host\\path /host/path"
    authority = create_project(
        journal_root=tmp_path / "literal-journal",
        project_id="demo-002",
        goal=raw_goal,
        baseline=baseline(),
        workspace=workspace(),
        limits=RunLimits(),
        started_at_unix_ms=1_000,
        deadline_unix_ms=61_000,
    )
    assert authority.snapshot.project.goal == raw_goal
    assert all(raw_goal not in item.description for item in authority.snapshot.tasks)


def test_ready_selection_is_priority_then_creation_sequence_then_task_id() -> None:
    source = replace(project(), status=ProjectStatus.ACTIVE)
    ready = (
        task(task_id="task-z", root_task_id="task-z", status=TaskStatus.READY),
        task(
            task_id="task-b",
            root_task_id="task-b",
            status=TaskStatus.READY,
            priority=70,
            creation_sequence=3,
        ),
        task(
            task_id="task-a",
            root_task_id="task-a",
            status=TaskStatus.READY,
            priority=70,
            creation_sequence=2,
        ),
    )
    assert select_next_ready(BoardSnapshot.create(source, ready)).task_id == "task-a"
    tied = tuple(replace(item, creation_sequence=index + 1) for index, item in enumerate((
        task(task_id="task-b", root_task_id="task-b", status=TaskStatus.READY, priority=70),
        task(task_id="task-a", root_task_id="task-a", status=TaskStatus.READY, priority=70),
    )))
    tied = (replace(tied[0], creation_sequence=1), replace(tied[1], creation_sequence=2))
    assert select_next_ready(BoardSnapshot.create(source, tied)).task_id == "task-b"


def test_ready_selection_returns_none_and_never_uses_adapter_choice() -> None:
    source = replace(project(), status=ProjectStatus.ACTIVE)
    backlog = task(status=TaskStatus.BACKLOG)
    assert select_next_ready(BoardSnapshot.create(source, (backlog,))) is None
    assert "next_task_id" not in backlog.to_dict()


@pytest.mark.parametrize("value", [0, -1, True, 10_001])
def test_scheduler_step_limit_is_strict_and_bounded(value) -> None:
    with pytest.raises(SchedulerError, match="INVALID_SCHEDULER_LIMIT"):
        SchedulerLimits(max_steps=value)


def test_scheduler_authority_is_exported_from_orchestration_package() -> None:
    import agenticos.orchestration as orchestration

    assert orchestration.AutonomousScheduler is AutonomousScheduler
    assert orchestration.SchedulerLimits is SchedulerLimits


def _process_evidence(label: str) -> ReadonlyProcessEvidence:
    return ReadonlyProcessEvidence(
        containment_unit=f"aos-task-{label}.scope",
        cgroup_path=f"/sys/fs/cgroup/{label}",
        pid=100,
        process_group_id=100,
        start_time_ticks=10,
        boot_id="12345678-1234-1234-1234-123456789abc",
        policy_digest="1" * 64,
        namespace_digest="2" * 64,
        workspace_device=1,
        workspace_inode=2,
    )


class _AutonomousFakeDriver:
    def __init__(self) -> None:
        self.execution_counts: dict[str, int] = {}
        self.checkpoints: dict[str, str] = {}
        self.verifications: dict[str, VerificationResult] = {}
        self.review_counts: dict[str, int] = {}
        self.research_count = 0
        self.plan_count = 0

    def run_research(self, snapshot, task) -> ResearchStageResult:
        self.research_count += 1
        content = b'{"note":"bounded research"}'
        return ResearchStageResult(hashlib.sha256(content).hexdigest(), content)

    def run_plan(self, snapshot, task, research_digest: str) -> PlanningStageResult:
        self.plan_count += 1
        assert research_digest == snapshot.task("bootstrap-research").stage_result_digest
        proposal = PlannerProposal(
            PLANNER_SCHEMA,
            (
                ProposedTask(
                    "feature",
                    "Implement feature",
                    "Implement the bounded fixture feature.",
                    TaskType.BUILD,
                    (),
                    ("Verifier passes.",),
                    Role.BUILDER,
                    50,
                ),
                ProposedTask(
                    "follow-up",
                    "Complete follow-up",
                    "Complete dependent bounded work.",
                    TaskType.DOCUMENT,
                    ("feature",),
                    ("Verifier passes.",),
                    Role.BUILDER,
                    40,
                ),
            ),
        )
        digest = hashlib.sha256(canonical_json_bytes(proposal.to_dict())).hexdigest()
        return PlanningStageResult(digest, proposal)

    def reconcile_execution(self, snapshot, task) -> ExecutionStageResult | None:
        return None

    def run_execution(self, snapshot, task) -> ExecutionStageResult:
        self.execution_counts[task.task_id] = self.execution_counts.get(task.task_id, 0) + 1
        checkpoint = hashlib.sha256(f"checkpoint:{task.task_id}".encode()).hexdigest()
        self.checkpoints[task.task_id] = checkpoint
        return ExecutionStageResult(
            task.task_id,
            task.generation,
            task.attempt_count,
            snapshot.project.controller_epoch,
            task.lease_epoch,
            ExecutionClassification.SUCCESS,
            checkpoint,
            hashlib.sha256(f"execution:{task.task_id}".encode()).hexdigest(),
            None,
        )

    def record_execution_success(self, authority, task_id, result, transaction_id: str) -> None:
        mutation = authority.record_execution_success(
            authority.snapshot.revision,
            task_id,
            checkpoint_digest=result.checkpoint_digest,
            evidence_digest=result.evidence_digest,
            transaction_id=transaction_id,
        )
        assert mutation.snapshot.task(task_id).status is TaskStatus.VERIFYING

    def run_verification(self, snapshot, task) -> VerificationResult:
        semantic_fail = task.task_id == "task-000003"
        result = VerificationResult(
            VERIFICATION_RESULT_SCHEMA,
            "demo-verifier",
            "3" * 64,
            task.project_id,
            task.task_id,
            task.generation,
            task.attempt_count,
            snapshot.project.controller_epoch,
            self.checkpoints[task.task_id],
            VerificationClassification.FAIL if semantic_fail else VerificationClassification.PASS,
            FailureClassification.VERIFICATION_FAILURE if semantic_fail else None,
            VerificationExitClassification.EXITED,
            1 if semantic_fail else 0,
            hashlib.sha256(b"").hexdigest(),
            0,
            "",
            hashlib.sha256(b"").hexdigest(),
            0,
            "",
            False,
            False,
            _process_evidence("verify"),
            hashlib.sha256(b"feature-failure").hexdigest() if semantic_fail else None,
        )
        self.verifications[task.task_id] = result
        return result

    def run_review(self, snapshot, task, verification_result_digest: str) -> ReviewResult:
        verification = self.verifications[task.task_id]
        assert verification.result_digest == verification_result_digest
        self.review_counts[task.task_id] = self.review_counts.get(task.task_id, 0) + 1
        blocking = task.task_type is TaskType.REPAIR and task.generation == 2
        proposal = (
            ReviewerProposal(
                REVIEW_SCHEMA,
                ReviewVerdict.BLOCKING,
                (ReviewFinding("DEFINED_REVIEW_FINDING", "Add the review remediation."),),
                "Apply the bounded review repair.",
                (),
            )
            if blocking
            else ReviewerProposal(REVIEW_SCHEMA, ReviewVerdict.PASS, (), None, ())
        )
        proposal_digest = hashlib.sha256(canonical_json_bytes(proposal.to_dict())).hexdigest()
        return ReviewResult(
            REVIEW_RESULT_SCHEMA,
            task.project_id,
            task.task_id,
            task.generation,
            task.attempt_count,
            snapshot.project.controller_epoch,
            self.checkpoints[task.task_id],
            verification.result_digest,
            ReviewClassification.BLOCKING if blocking else ReviewClassification.PASS,
            FailureClassification.REVIEW_BLOCKING_FINDING if blocking else None,
            ReviewerExecutionIdentity(
                f"adapter-{task.generation}",
                f"session-{task.generation}",
                f"{task.generation:x}" * 32,
                f"aos-task-review-{task.generation}.scope",
            ),
            proposal,
            proposal_digest,
            None,
            _process_evidence("review"),
            hashlib.sha256(b"review-failure").hexdigest() if blocking else None,
        )

    def finalize_project(self, snapshot) -> FinalizationEvidence:
        return FinalizationEvidence(
            stable_checkpoint=True,
            checkpoint_digest=hashlib.sha256(b"final-checkpoint").hexdigest(),
            active_execution=False,
            residue_free=True,
        )


def test_scheduler_runs_repair_review_dependency_path_without_human_input(tmp_path) -> None:
    authority = create_project(
        journal_root=tmp_path / "journal",
        project_id="demo-001",
        goal="Add the requested feature to the fixture application.",
        baseline=baseline(),
        workspace=workspace(),
        limits=RunLimits(max_tasks=16, max_total_attempts=32),
        started_at_unix_ms=1_000,
        deadline_unix_ms=61_000,
    )
    driver = _AutonomousFakeDriver()
    result = AutonomousScheduler(
        authority=authority,
        driver=driver,
        limits=SchedulerLimits(max_steps=64),
        now_unix_ms=lambda: 2_000,
    ).run()
    assert result.snapshot.project.status is ProjectStatus.DONE
    assert result.final_checkpoint_digest == hashlib.sha256(b"final-checkpoint").hexdigest()
    assert result.snapshot.project.final_checkpoint_digest == result.final_checkpoint_digest
    assert result.snapshot.project.finalization_evidence_digest is not None
    assert all(item.status is TaskStatus.DONE for item in result.snapshot.tasks)
    feature = result.snapshot.task("task-000003")
    follow_up = result.snapshot.task("task-000004")
    assert feature.satisfying_descendant_id is not None
    assert follow_up.dependencies == (feature.task_id,)
    assert driver.execution_counts[feature.task_id] == 1
    assert driver.execution_counts[follow_up.task_id] == 1
    repair_tasks = [item for item in result.snapshot.tasks if item.task_type is TaskType.REPAIR]
    assert len(repair_tasks) == 2
    assert all(driver.execution_counts[item.task_id] == 1 for item in repair_tasks)
    kinds = [event.kind for event in result.events]
    assert kinds.count("REPAIR_CREATED") == 2
    assert any(
        event.kind == "TASK_SATISFIED" and event.task_id == feature.task_id
        for event in result.events
    )
    assert kinds[-1] == "PROJECT_DONE"

    from agenticos.orchestration.board import BoardAuthority
    from agenticos.orchestration.journal import TransactionJournal

    recovered = BoardAuthority.recover(TransactionJournal(tmp_path / "journal", "demo-001"))
    after_restart = AutonomousScheduler(
        authority=recovered,
        driver=_AutonomousFakeDriver(),
        limits=SchedulerLimits(max_steps=64),
        now_unix_ms=lambda: 2_000,
    ).run()
    assert after_restart.final_checkpoint_digest == result.final_checkpoint_digest
    assert after_restart.snapshot.project.finalization_evidence_digest == (
        result.snapshot.project.finalization_evidence_digest
    )


def _new_authority(tmp_path, *, deadline: int = 61_000):
    return create_project(
        journal_root=tmp_path / "journal",
        project_id="demo-001",
        goal="Add the requested feature to the fixture application.",
        baseline=baseline(),
        workspace=workspace(),
        limits=RunLimits(max_tasks=16, max_total_attempts=32),
        started_at_unix_ms=1_000,
        deadline_unix_ms=deadline,
    )


def test_scheduler_refuses_a_second_controller_for_the_same_project(tmp_path) -> None:
    authority = _new_authority(tmp_path)
    lock_path = tmp_path / ".demo-001.controller.lock"
    with acquire_repository_lock(lock_path, timeout=0.2):
        with pytest.raises(SchedulerError, match="CONTROLLER_LOCK_UNAVAILABLE"):
            AutonomousScheduler(
                authority=authority,
                driver=_AutonomousFakeDriver(),
                limits=SchedulerLimits(max_steps=64),
                now_unix_ms=lambda: 2_000,
                controller_lock_timeout=0.1,
            ).run()
    assert authority.snapshot.project.status is ProjectStatus.ACTIVE


def test_restart_after_plan_commit_continues_without_duplicate_bootstrap_dispatch(tmp_path) -> None:
    authority = _new_authority(tmp_path)
    driver = _AutonomousFakeDriver()
    paused = AutonomousScheduler(
        authority=authority,
        driver=driver,
        limits=SchedulerLimits(max_steps=64),
        now_unix_ms=lambda: 2_000,
    ).run(stop_after="PLAN_COMPLETED")
    assert paused.snapshot.project.status is ProjectStatus.ACTIVE
    assert driver.research_count == driver.plan_count == 1

    from agenticos.orchestration.board import BoardAuthority
    from agenticos.orchestration.journal import TransactionJournal

    recovered = BoardAuthority.recover(TransactionJournal(tmp_path / "journal", "demo-001"))
    completed = AutonomousScheduler(
        authority=recovered,
        driver=driver,
        limits=SchedulerLimits(max_steps=64),
        now_unix_ms=lambda: 2_000,
    ).run()
    assert completed.snapshot.project.status is ProjectStatus.DONE
    assert driver.research_count == driver.plan_count == 1
    assert all(count == 1 for count in driver.execution_counts.values())


class _RecoveredExecutionDriver(_AutonomousFakeDriver):
    def __init__(self) -> None:
        super().__init__()
        self.reconcile_count = 0

    def reconcile_execution(self, snapshot, task) -> ExecutionStageResult | None:
        self.reconcile_count += 1
        checkpoint = hashlib.sha256(f"checkpoint:{task.task_id}".encode()).hexdigest()
        self.checkpoints[task.task_id] = checkpoint
        return ExecutionStageResult(
            task.task_id,
            task.generation,
            task.attempt_count,
            snapshot.project.controller_epoch,
            task.lease_epoch,
            ExecutionClassification.SUCCESS,
            checkpoint,
            hashlib.sha256(f"recovered:{task.task_id}".encode()).hexdigest(),
            None,
        )

    def run_execution(self, snapshot, task) -> ExecutionStageResult:
        raise AssertionError("reconciled work must not be redispatched")


def test_active_stage_reconciles_existing_execution_without_redispatch(tmp_path) -> None:
    authority = _new_authority(tmp_path)
    bootstrap_driver = _AutonomousFakeDriver()
    for _ in range(3):
        paused = AutonomousScheduler(
            authority=authority,
            driver=bootstrap_driver,
            limits=SchedulerLimits(max_steps=64),
            now_unix_ms=lambda: 2_000,
        ).run(stop_after="TASK_STARTED")
    assert paused.snapshot.task("task-000003").status is TaskStatus.IN_PROGRESS

    reconciled = AutonomousScheduler(
        authority=authority,
        driver=_RecoveredExecutionDriver(),
        limits=SchedulerLimits(max_steps=64),
        now_unix_ms=lambda: 2_000,
    ).run(stop_after="BUILD_COMPLETED")
    assert reconciled.snapshot.task("task-000003").status is TaskStatus.VERIFYING


def test_deadline_reconciles_active_execution_then_leaves_no_active_task(tmp_path) -> None:
    authority = _new_authority(tmp_path, deadline=2_000)
    bootstrap_driver = _AutonomousFakeDriver()
    for _ in range(3):
        paused = AutonomousScheduler(
            authority=authority,
            driver=bootstrap_driver,
            limits=SchedulerLimits(max_steps=64),
            now_unix_ms=lambda: 1_500,
        ).run(stop_after="TASK_STARTED")
    assert paused.snapshot.task("task-000003").status is TaskStatus.IN_PROGRESS

    driver = _RecoveredExecutionDriver()
    terminal = AutonomousScheduler(
        authority=authority,
        driver=driver,
        limits=SchedulerLimits(max_steps=64),
        now_unix_ms=lambda: 2_000,
    ).run()
    assert driver.reconcile_count == 1
    assert terminal.snapshot.project.status is ProjectStatus.FAILED
    assert not any(task.status in AutonomousScheduler._ACTIVE for task in terminal.snapshot.tasks)


class _CheckpointMismatchVerifierDriver(_AutonomousFakeDriver):
    def run_verification(self, snapshot, task) -> VerificationResult:
        result = super().run_verification(snapshot, task)
        return replace(result, checkpoint_digest="f" * 64)


def test_verification_cannot_advance_a_different_workspace_checkpoint(tmp_path) -> None:
    result = AutonomousScheduler(
        authority=_new_authority(tmp_path),
        driver=_CheckpointMismatchVerifierDriver(),
        limits=SchedulerLimits(max_steps=64),
        now_unix_ms=lambda: 2_000,
    ).run()
    assert result.snapshot.project.status is ProjectStatus.FAILED
    assert not any(event.kind.startswith("REVIEW_") for event in result.events)


def test_deadline_and_max_steps_fail_deterministically(tmp_path) -> None:
    deadline = AutonomousScheduler(
        authority=_new_authority(tmp_path / "deadline", deadline=1_500),
        driver=_AutonomousFakeDriver(),
        limits=SchedulerLimits(max_steps=64),
        now_unix_ms=lambda: 1_500,
    ).run()
    assert deadline.snapshot.project.status is ProjectStatus.FAILED
    assert deadline.snapshot.project.terminal_reason.value == "RESOURCE_LIMIT"

    bounded = AutonomousScheduler(
        authority=_new_authority(tmp_path / "steps"),
        driver=_AutonomousFakeDriver(),
        limits=SchedulerLimits(max_steps=1),
        now_unix_ms=lambda: 2_000,
    ).run()
    assert bounded.snapshot.project.status is ProjectStatus.FAILED
    assert bounded.events[-1].message == "Maximum scheduler steps exhausted"


def test_no_ready_nonterminal_board_fails_once_without_spin(tmp_path) -> None:
    authority = _new_authority(tmp_path)
    mutation = authority.transition_task(
        authority.snapshot.revision,
        "bootstrap-research",
        TaskStatus.BLOCKED,
        block_reason=BlockReason.DEPENDENCY_BLOCKED,
        transaction_id="tx-test-block",
    )
    assert mutation.snapshot.task("bootstrap-research").status is TaskStatus.BLOCKED
    result = AutonomousScheduler(
        authority=authority,
        driver=_AutonomousFakeDriver(),
        limits=SchedulerLimits(max_steps=64),
        now_unix_ms=lambda: 2_000,
    ).run()
    assert result.snapshot.project.status is ProjectStatus.FAILED
    assert result.events[-1].message == "No READY task and project nonterminal"
    assert result.steps < 4


class _InfrastructureVerifierDriver(_AutonomousFakeDriver):
    def run_verification(self, snapshot, task) -> VerificationResult:
        return VerificationResult(
            VERIFICATION_RESULT_SCHEMA,
            "demo-verifier",
            "3" * 64,
            task.project_id,
            task.task_id,
            task.generation,
            task.attempt_count,
            snapshot.project.controller_epoch,
            self.checkpoints[task.task_id],
            VerificationClassification.INFRASTRUCTURE_ERROR,
            FailureClassification.TERMINAL_INFRASTRUCTURE_FAILURE,
            VerificationExitClassification.EXITED,
            70,
            hashlib.sha256(b"").hexdigest(),
            0,
            "",
            hashlib.sha256(b"infra").hexdigest(),
            5,
            "infra",
            False,
            False,
            None,
            None,
        )


def test_verifier_infrastructure_error_fails_without_code_repair(tmp_path) -> None:
    result = AutonomousScheduler(
        authority=_new_authority(tmp_path),
        driver=_InfrastructureVerifierDriver(),
        limits=SchedulerLimits(max_steps=64),
        now_unix_ms=lambda: 2_000,
    ).run()
    assert result.snapshot.project.status is ProjectStatus.FAILED
    assert not any(item.task_type is TaskType.REPAIR for item in result.snapshot.tasks)


class _CancelledBuildDriver(_AutonomousFakeDriver):
    def run_execution(self, snapshot, task) -> ExecutionStageResult:
        result = super().run_execution(snapshot, task)
        return replace(
            result,
            classification=ExecutionClassification.CANCELLED,
            checkpoint_digest=None,
        )


def test_cancelled_build_cancels_project_and_never_repairs(tmp_path) -> None:
    result = AutonomousScheduler(
        authority=_new_authority(tmp_path),
        driver=_CancelledBuildDriver(),
        limits=SchedulerLimits(max_steps=64),
        now_unix_ms=lambda: 2_000,
    ).run()
    assert result.snapshot.project.status is ProjectStatus.CANCELLED
    assert not any(item.task_type is TaskType.REPAIR for item in result.snapshot.tasks)


class _MalformedResearchDriver(_AutonomousFakeDriver):
    def run_research(self, snapshot, task):
        return {"status": "DONE", "project_status": "DONE"}


class _RejectedPlanDriver(_AutonomousFakeDriver):
    def run_plan(self, snapshot, task, research_digest: str) -> PlanningStageResult:
        proposal = PlannerProposal(
            PLANNER_SCHEMA,
            (
                ProposedTask("x", "X", "X task.", TaskType.BUILD, ("y",), ("Pass.",), Role.BUILDER, 50),
                ProposedTask("y", "Y", "Y task.", TaskType.BUILD, ("x",), ("Pass.",), Role.BUILDER, 50),
            ),
        )
        digest = hashlib.sha256(canonical_json_bytes(proposal.to_dict())).hexdigest()
        return PlanningStageResult(digest, proposal)


class _FailedBuildDriver(_AutonomousFakeDriver):
    def run_execution(self, snapshot, task) -> ExecutionStageResult:
        result = super().run_execution(snapshot, task)
        return replace(
            result,
            classification=ExecutionClassification.INFRASTRUCTURE_FAILURE,
            checkpoint_digest=None,
        )


class _BuildCrashDriver(_FailedBuildDriver):
    """Synthetic controller observation of a crashed L2 child."""


class _BuildTimeoutDriver(_FailedBuildDriver):
    """Synthetic controller observation of a timed-out L2 child."""


class _StaleBuildDriver(_AutonomousFakeDriver):
    def run_execution(self, snapshot, task) -> ExecutionStageResult:
        return replace(super().run_execution(snapshot, task), attempt=task.attempt_count + 1)


@pytest.mark.parametrize(
    "driver_type",
    [
        _MalformedResearchDriver,
        _RejectedPlanDriver,
        _BuildCrashDriver,
        _BuildTimeoutDriver,
        _StaleBuildDriver,
    ],
)
def test_malformed_rejected_failed_and_stale_stages_fail_closed_without_repair(
    tmp_path, driver_type
) -> None:
    result = AutonomousScheduler(
        authority=_new_authority(tmp_path),
        driver=driver_type(),
        limits=SchedulerLimits(max_steps=64),
        now_unix_ms=lambda: 2_000,
    ).run()
    assert result.snapshot.project.status is ProjectStatus.FAILED
    assert not any(item.task_type is TaskType.REPAIR for item in result.snapshot.tasks)
    assert result.events[-1].kind == "PROJECT_FAILED"


class _RepeatedFingerprintDriver(_AutonomousFakeDriver):
    def run_verification(self, snapshot, task) -> VerificationResult:
        result = super().run_verification(snapshot, task)
        if task.task_type is TaskType.REPAIR and task.generation == 2:
            result = replace(
                result,
                classification=VerificationClassification.FAIL,
                failure_classification=FailureClassification.VERIFICATION_FAILURE,
                exit_code=1,
                failure_fingerprint=hashlib.sha256(b"feature-failure").hexdigest(),
            )
            self.verifications[task.task_id] = result
        return result


def test_repeated_failure_fingerprint_exhausts_lineage_without_new_loop(tmp_path) -> None:
    result = AutonomousScheduler(
        authority=_new_authority(tmp_path),
        driver=_RepeatedFingerprintDriver(),
        limits=SchedulerLimits(max_steps=64),
        now_unix_ms=lambda: 2_000,
    ).run()
    assert result.snapshot.project.status is ProjectStatus.FAILED
    assert len([item for item in result.snapshot.tasks if item.task_type is TaskType.REPAIR]) == 1
    assert result.steps < 64


class _MalformedReviewerDriver(_AutonomousFakeDriver):
    def run_review(self, snapshot, task, verification_result_digest: str) -> ReviewResult:
        return ReviewResult(
            REVIEW_RESULT_SCHEMA,
            task.project_id,
            task.task_id,
            task.generation,
            task.attempt_count,
            snapshot.project.controller_epoch,
            self.checkpoints[task.task_id],
            verification_result_digest,
            ReviewClassification.INFRASTRUCTURE_ERROR,
            FailureClassification.MALFORMED_AGENT_OUTPUT,
            None,
            None,
            None,
            None,
            None,
            None,
        )


def test_malformed_reviewer_output_never_creates_review_repair(tmp_path) -> None:
    result = AutonomousScheduler(
        authority=_new_authority(tmp_path),
        driver=_MalformedReviewerDriver(),
        limits=SchedulerLimits(max_steps=64),
        now_unix_ms=lambda: 2_000,
    ).run()
    assert result.snapshot.project.status is ProjectStatus.FAILED
    assert len([item for item in result.snapshot.tasks if item.task_type is TaskType.REPAIR]) == 1
    assert not any(event.kind == "REVIEW_BLOCKED" for event in result.events)
