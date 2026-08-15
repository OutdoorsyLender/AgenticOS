"""Native WSL/Linux security proof for Slice D read-only execution."""

from __future__ import annotations

from dataclasses import replace
import subprocess
import sys
from pathlib import Path

import pytest

from agenticos.orchestration.board import BoardAuthority, BoardSnapshot
from agenticos.orchestration.execution import (
    ExecutionLedger,
    SyntheticBuildController,
    create_containment_reservation,
)
from agenticos.orchestration.journal import TransactionJournal
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
from agenticos.orchestration.protocol import (
    AGENT_PROTOCOL_SCHEMA,
    AgentCapability,
    AgentTaskRequest,
    ContextItem,
    ContextKind,
    DispatchIdentity,
    ProtocolLimits,
    ResultStatus,
)
from agenticos.orchestration.repair import (
    RepairBudgetPolicy,
    RepairController,
    RepairError,
    SyntheticRepairAdapter,
)
from agenticos.orchestration.review import (
    ReviewClassification,
    ReviewController,
    ReviewerExecutionIdentity,
    SyntheticReviewerAdapter,
)
from agenticos.orchestration.synthetic import (
    SyntheticScenario,
    build_synthetic_workspace_argv,
)
from agenticos.orchestration.verification import (
    FailureClassification,
    VerificationClassification,
    VerificationController,
    VerifierRegistry,
    VerifierSpec,
)
from agenticos.sandbox.containment import CancellationConfig, CgroupProcessRunner
from agenticos.sandbox.isolation import probe_landlock_enforcement
from agenticos.sandbox.m4a_runner import NamespaceLandlockRunner
from agenticos.sandbox.runtime_boundary import M4AProfile, probe_bubblewrap
from agenticos.sandbox.worktree import (
    WorktreeManager,
    WorkspaceReuseDecision,
    create_worktree_reservation,
)
from agenticos.orchestration.workspace import (
    LEASE_IDENTITY_SCHEMA,
    WorkspaceLeaseAdmission,
    WorkspaceLeaseIdentity,
    WorkspaceLeaseLedger,
)


pytestmark = [
    pytest.mark.m4a_linux,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux M4A boundary"),
]

FAST = CancellationConfig(
    sigint_grace=0.5,
    sigterm_grace=0.5,
    empty_verify_timeout=5.0,
    poll_interval=0.05,
)


@pytest.fixture(scope="session")
def slice_d_launcher(tmp_path_factory) -> Path:
    output = tmp_path_factory.mktemp("slice-d-launcher") / "fs_launcher"
    source = Path(__file__).parents[2] / "native" / "fs_launcher" / "fs_launcher.c"
    subprocess.run(
        [
            "cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
            "-Werror", "-O2", str(source), "-o", str(output),
        ],
        check=True,
    )
    return output


@pytest.fixture(scope="session")
def slice_d_host_ok() -> None:
    support = CgroupProcessRunner.probe()
    if not support.supported:
        pytest.skip("transient scopes unavailable: " + "; ".join(support.reasons))
    landlock_ok, reason = probe_landlock_enforcement()
    if not landlock_ok:
        pytest.skip(f"Landlock enforcement unavailable: {reason}")
    bwrap = probe_bubblewrap()
    if not bwrap.supported:
        pytest.fail("required Bubblewrap boundary unavailable: " + "; ".join(bwrap.reasons))


@pytest.fixture
def slice_d_project(tmp_path: Path, slice_d_launcher: Path, slice_d_host_ok):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Slice D Test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "slice-d@agenticos.local"], cwd=repo, check=True)
    (repo / "feature.txt").write_bytes(b"fixed\n")
    subprocess.run(["git", "add", "feature.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "baseline"], cwd=repo, check=True, capture_output=True)
    baseline = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()

    state_root = tmp_path / "state"
    manager = WorktreeManager(state_root)
    reservation = create_worktree_reservation(
        repo_path=repo,
        task_id="project-workspace-d",
        generation=1,
        baseline_commit_sha=baseline,
        nonce="1" * 32,
        policy_digest="2" * 64,
        state_root=state_root,
        allow_temporary_for_test=True,
    )
    state = manager.create(reservation)
    checkpoint_capture = manager.capture_checkpoint(repo, "project-workspace-d", 1)
    assert checkpoint_capture.decision is WorkspaceReuseDecision.REUSABLE
    checkpoint = checkpoint_capture.checkpoint
    assert checkpoint is not None
    workspace = WorkspaceIdentityRef(
        "project-workspace-d", 1, reservation.reservation_digest
    )
    project = ProjectRecord(
        schema=BOARD_SCHEMA,
        project_id="project-d",
        goal="Prove deterministic read-only verification.",
        baseline=BaselineIdentity(reservation.repository.repository_id, baseline),
        workspace=workspace,
        status=ProjectStatus.ACTIVE,
        terminal_reason=None,
        board_revision=1,
        controller_epoch=1,
        lease_epoch=1,
        limits=RunLimits(),
        started_at_unix_ms=1,
        deadline_unix_ms=100_000,
        transition_sequence=1,
        transition_digest="3" * 64,
    )
    task = BoardTask(
        schema=BOARD_SCHEMA,
        task_id="build-d",
        project_id="project-d",
        title="Build fixture",
        description="Verify the controlled project workspace.",
        task_type=TaskType.BUILD,
        priority=50,
        dependencies=(),
        acceptance_criteria=("feature.txt contains the fixed bytes.",),
        preferred_role=Role.BUILDER,
        assigned_role=Role.BUILDER,
        status=TaskStatus.VERIFYING,
        attempt_count=1,
        max_attempts=3,
        creation_sequence=1,
        creator="CONTROLLER",
        parent_task_id=None,
        root_task_id="build-d",
        generation=1,
        workspace=workspace,
        lease_epoch=1,
        block_reason=None,
        terminal_reason=None,
        repair_failure_fingerprint=None,
        satisfying_descendant_id=None,
        verification_result_digest=None,
        review_result_digest=None,
    )
    board = BoardSnapshot.create(project, (task,))
    dispatch = DispatchIdentity(
        project_id="project-d",
        task_id="build-d",
        task_generation=1,
        attempt=1,
        controller_epoch=1,
        lease_epoch=1,
        dispatch_nonce="4" * 32,
        repository_id=reservation.repository.repository_id,
        baseline_commit=baseline,
        workspace_id=workspace.workspace_id,
        workspace_generation=workspace.generation,
        reservation_id=workspace.reservation_id,
        checkpoint_digest=checkpoint.checkpoint_digest,
    )
    task_tmp = tmp_path / "task-tmp"
    home = tmp_path / "home"
    task_tmp.mkdir()
    home.mkdir()
    git_mask = manager.ensure_git_mask(
        reservation.repository.repository_id, workspace.workspace_id, workspace.generation
    )
    yield {
        "repo": repo,
        "manager": manager,
        "state": state,
        "checkpoint": checkpoint,
        "board": board,
        "dispatch": dispatch,
        "task_tmp": task_tmp,
        "home": home,
        "git_mask": git_mask,
        "launcher": slice_d_launcher,
    }


def _spec_for(scenario: str) -> VerifierSpec:
    return VerifierSpec(
        verifier_id="verifier-" + scenario.lower().replace("_", "-"),
        executable="/usr/bin/python3",
        argv=(
            "/usr/bin/python3",
            "/opt/agenticos/worker.py",
            "--scenario",
            scenario,
        ),
        working_directory="/workspace",
        timeout_seconds=1 if scenario == "TIMEOUT" else 10,
        max_stdout_bytes=4096,
        max_stderr_bytes=4096,
        pass_exit_codes=(0,),
        fail_exit_codes=(1,),
        fixture_id="slice-d-" + scenario.lower().replace("_", "-"),
    )


def _stage_runner(evidence, *, profile: M4AProfile, worker: str, label: str):
    task_tmp = evidence["task_tmp"].parent / f"{label}-tmp"
    home = evidence["home"].parent / f"{label}-home"
    task_tmp.mkdir()
    home.mkdir()
    return NamespaceLandlockRunner(
        worker_path=(
            Path(__file__).parents[2]
            / "src" / "agenticos" / "orchestration" / worker
        ),
        workspace=evidence["state"].worktree_path,
        profile=profile,
        launcher_path=evidence["launcher"],
        task_tmp=task_tmp,
        synthetic_home=home,
        git_mask_path=evidence["git_mask"],
        cancellation=FAST,
    )


def _dispatch_for(board, task_id: str, checkpoint, nonce: str) -> DispatchIdentity:
    task = board.task(task_id)
    return DispatchIdentity(
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


def _request_for(board, task_id: str, dispatch: DispatchIdentity) -> AgentTaskRequest:
    task = board.task(task_id)
    limits = board.project.limits
    return AgentTaskRequest(
        schema=AGENT_PROTOCOL_SCHEMA,
        identity=dispatch,
        role=Role.BUILDER,
        provider_id="synthetic-build",
        model_id="deterministic-build-v1",
        workspace_mount="/workspace",
        instructions="Apply only the controller-selected synthetic workspace scenario.",
        acceptance_criteria=task.acceptance_criteria,
        context_manifest=(ContextItem(
            ContextKind.WORKSPACE_MANIFEST,
            "pre-build-checkpoint",
            dispatch.checkpoint_digest,
            64,
        ),),
        capabilities=(
            AgentCapability.READ_CONTEXT,
            AgentCapability.READ_WORKSPACE,
            AgentCapability.WRITE_WORKSPACE,
        ),
        limits=ProtocolLimits(
            max_events=limits.max_events_per_attempt,
            max_event_bytes=limits.max_event_bytes,
            max_output_bytes=limits.max_output_bytes,
            max_context_entries=limits.max_context_entries,
            max_context_bytes=limits.max_context_bytes,
            max_processes=limits.max_processes,
            max_runtime_seconds=limits.max_runtime_seconds,
        ),
    )


def _execute_initial_build(
    evidence,
    *,
    authority: BoardAuthority,
    checkpoint_capture,
    lease_ledger: WorkspaceLeaseLedger,
    scenario: SyntheticScenario,
    label: str,
):
    board = authority.snapshot
    dispatch = _dispatch_for(board, "build-d", checkpoint_capture.checkpoint, "6" * 32)
    request = _request_for(board, "build-d", dispatch)
    lease = WorkspaceLeaseIdentity(
        LEASE_IDENTITY_SCHEMA,
        dispatch.project_id,
        dispatch.task_id,
        dispatch.task_generation,
        dispatch.attempt,
        dispatch.controller_epoch,
        dispatch.lease_epoch,
        board.task("build-d").workspace,
        dispatch.dispatch_nonce,
        dispatch.checkpoint_digest,
    )
    lease_ledger.acquire(
        lease,
        WorkspaceLeaseAdmission.issue(
            board=board, identity=lease, checkpoint_capture=checkpoint_capture
        ),
    )
    runner = _stage_runner(
        evidence, profile=M4AProfile.BUILD, worker="synthetic_worker.py", label=label
    )
    reservation = create_containment_reservation(dispatch)
    outcome = SyntheticBuildController(
        ExecutionLedger(evidence["task_tmp"].parent / f"{label}-execution", dispatch)
    ).execute(
        board=board,
        dispatch=dispatch,
        lease_ledger=lease_ledger,
        pre_checkpoint=checkpoint_capture.checkpoint,
        runner=runner,
        reservation=reservation,
        argv=build_synthetic_workspace_argv(request, scenario),
        workspace_manager=evidence["manager"],
        repo_path=evidence["repo"],
        timeout=10,
        request=request,
    )
    assert outcome.agent_result is not None
    assert outcome.agent_result.status is ResultStatus.SUCCEEDED
    assert outcome.first_checkpoint == outcome.second_checkpoint
    assert runner.backend.scope_evidence(reservation.scope_name).state.value == "ABSENT"
    return dispatch, outcome


def _verify_stage(evidence, board, task_id: str, checkpoint, label: str):
    spec = _spec_for("CHECK_FEATURE")
    runner = _stage_runner(
        evidence, profile=M4AProfile.INSPECT, worker="verifier_worker.py", label=label
    )
    dispatch = _dispatch_for(board, task_id, checkpoint, "7" * 32)
    reservation = create_containment_reservation(dispatch)
    result = VerificationController(VerifierRegistry((spec,))).verify(
        board=board,
        dispatch=dispatch,
        checkpoint=checkpoint,
        verifier_id=spec.verifier_id,
        runner=runner,
        reservation=reservation,
        workspace_manager=evidence["manager"],
        repo_path=evidence["repo"],
    )
    assert runner.backend.scope_evidence(reservation.scope_name).state.value == "ABSENT"
    return dispatch, result


def _review_stage(
    evidence,
    board,
    task_id: str,
    checkpoint,
    verification,
    *,
    scenario: SyntheticScenario,
    builder_dispatch: DispatchIdentity,
    builder_scope: str,
    label: str,
):
    review_dispatch = _dispatch_for(board, task_id, checkpoint, "8" * 32)
    task = board.task(task_id)
    request = ReviewController.build_request(
        board=board,
        dispatch=review_dispatch,
        verification_result=verification,
        checkpoint=checkpoint,
    )
    runner = _stage_runner(
        evidence, profile=M4AProfile.INSPECT, worker="synthetic_worker.py", label=label
    )
    reservation = create_containment_reservation(review_dispatch)
    result = ReviewController().review(
        board=board,
        request=request,
        verification_result=verification,
        checkpoint=checkpoint,
        builder_identity=ReviewerExecutionIdentity(
            "builder-adapter-1",
            "builder-session-" + task_id[-8:],
            builder_dispatch.dispatch_nonce,
            builder_scope,
        ),
        adapter=SyntheticReviewerAdapter(
            "reviewer-adapter-" + task_id[-8:],
            "reviewer-session-" + task_id[-8:],
            scenario,
        ),
        runner=runner,
        reservation=reservation,
        workspace_manager=evidence["manager"],
        repo_path=evidence["repo"],
    )
    assert runner.backend.scope_evidence(reservation.scope_name).state.value == "ABSENT"
    return result


def _authority_for_e2e(evidence, root: Path) -> BoardAuthority:
    task = replace(
        evidence["board"].task("build-d"),
        status=TaskStatus.READY,
        attempt_count=0,
        lease_epoch=0,
    )
    project = replace(
        evidence["board"].project,
        board_revision=0,
        lease_epoch=0,
        transition_sequence=0,
        transition_digest="0" * 64,
    )
    return BoardAuthority.create(
        TransactionJournal(root, project.project_id),
        BoardSnapshot.create(project, (task,)),
        transaction_id="tx-e2e-init",
    )


@pytest.mark.parametrize(
    "scenario",
    [
        "PASS",
        "MUTATE_CREATE",
        "MUTATE_WRITE",
        "MUTATE_RENAME",
        "MUTATE_DELETE",
        "DOT_GIT_ACCESS",
        "HOST_ACCESS",
        "CONTROLLER_ACCESS",
        "CREDENTIAL_ACCESS",
        "OVERSIZED",
    ],
)
def test_real_l1_verifier_is_readonly_bounded_and_leaves_no_scope(
    slice_d_project, scenario: str
) -> None:
    evidence = slice_d_project
    spec = _spec_for(scenario)
    runner = NamespaceLandlockRunner(
        worker_path=Path(__file__).parents[2] / "src" / "agenticos" / "orchestration" / "verifier_worker.py",
        workspace=evidence["state"].worktree_path,
        profile=M4AProfile.INSPECT,
        launcher_path=evidence["launcher"],
        task_tmp=evidence["task_tmp"],
        synthetic_home=evidence["home"],
        git_mask_path=evidence["git_mask"],
        cancellation=FAST,
    )
    reservation = create_containment_reservation(evidence["dispatch"])
    result = VerificationController(VerifierRegistry((spec,))).verify(
        board=evidence["board"],
        dispatch=evidence["dispatch"],
        checkpoint=evidence["checkpoint"],
        verifier_id=spec.verifier_id,
        runner=runner,
        reservation=reservation,
        workspace_manager=evidence["manager"],
        repo_path=evidence["repo"],
    )
    if scenario == "PASS":
        assert result.classification is VerificationClassification.PASS
    else:
        assert result.classification is VerificationClassification.INFRASTRUCTURE_ERROR
        assert result.failure_classification is not FailureClassification.VERIFICATION_FAILURE
    assert result.stdout_byte_count + result.stderr_byte_count <= 8192
    after = evidence["manager"].capture_checkpoint(
        evidence["repo"], "project-workspace-d", 1
    )
    assert after.checkpoint == evidence["checkpoint"]
    scope = runner.backend.scope_evidence(reservation.scope_name)
    assert scope.state.value == "ABSENT"


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        (SyntheticScenario.REVIEWER_PASS, ReviewClassification.PASS),
        (SyntheticScenario.REVIEWER_FAIL, ReviewClassification.BLOCKING),
    ],
)
def test_real_l1_reviewer_is_separate_advisory_and_checkpoint_bound(
    slice_d_project, scenario: SyntheticScenario, expected: ReviewClassification
) -> None:
    evidence = slice_d_project
    verify_spec = _spec_for("PASS")
    verifier_runner = NamespaceLandlockRunner(
        worker_path=Path(__file__).parents[2] / "src" / "agenticos" / "orchestration" / "verifier_worker.py",
        workspace=evidence["state"].worktree_path,
        profile=M4AProfile.INSPECT,
        launcher_path=evidence["launcher"],
        task_tmp=evidence["task_tmp"],
        synthetic_home=evidence["home"],
        git_mask_path=evidence["git_mask"],
        cancellation=FAST,
    )
    verify_reservation = create_containment_reservation(evidence["dispatch"])
    verification = VerificationController(VerifierRegistry((verify_spec,))).verify(
        board=evidence["board"], dispatch=evidence["dispatch"],
        checkpoint=evidence["checkpoint"], verifier_id=verify_spec.verifier_id,
        runner=verifier_runner, reservation=verify_reservation,
        workspace_manager=evidence["manager"], repo_path=evidence["repo"],
    )
    assert verification.classification is VerificationClassification.PASS
    assert verification.process_evidence is not None

    review_board = BoardSnapshot.create(
        evidence["board"].project,
        (replace(evidence["board"].tasks[0], status=TaskStatus.REVIEW),),
    )
    review_dispatch = replace(evidence["dispatch"], dispatch_nonce="5" * 32)
    request = ReviewController.build_request(
        board=review_board,
        dispatch=review_dispatch,
        verification_result=verification,
        checkpoint=evidence["checkpoint"],
    )
    review_tmp = evidence["task_tmp"].parent / "review-tmp"
    review_home = evidence["home"].parent / "review-home"
    review_tmp.mkdir()
    review_home.mkdir()
    reviewer_runner = NamespaceLandlockRunner(
        worker_path=Path(__file__).parents[2] / "src" / "agenticos" / "orchestration" / "synthetic_worker.py",
        workspace=evidence["state"].worktree_path,
        profile=M4AProfile.INSPECT,
        launcher_path=evidence["launcher"],
        task_tmp=review_tmp,
        synthetic_home=review_home,
        git_mask_path=evidence["git_mask"],
        cancellation=FAST,
    )
    review_reservation = create_containment_reservation(review_dispatch)
    result = ReviewController().review(
        board=review_board,
        request=request,
        verification_result=verification,
        checkpoint=evidence["checkpoint"],
        builder_identity=ReviewerExecutionIdentity(
            "builder-adapter-1",
            "builder-session-1",
            evidence["dispatch"].dispatch_nonce,
            verification.process_evidence.containment_unit,
        ),
        adapter=SyntheticReviewerAdapter(
            "reviewer-adapter-1", "reviewer-session-1", scenario
        ),
        runner=reviewer_runner,
        reservation=review_reservation,
        workspace_manager=evidence["manager"],
        repo_path=evidence["repo"],
    )
    assert result.classification is expected
    assert result.reviewer_identity is not None
    assert result.reviewer_identity.adapter_instance_id == "reviewer-adapter-1"
    assert result.reviewer_identity.session_id == "reviewer-session-1"
    assert result.reviewer_identity.dispatch_nonce != evidence["dispatch"].dispatch_nonce
    assert result.reviewer_identity.containment_unit != verification.process_evidence.containment_unit
    assert reviewer_runner.backend.scope_evidence(review_reservation.scope_name).state.value == "ABSENT"


@pytest.mark.parametrize(
    "scenario",
    [
        SyntheticScenario.REVIEWER_MUTATE_CREATE,
        SyntheticScenario.REVIEWER_MUTATE_WRITE,
        SyntheticScenario.REVIEWER_MUTATE_RENAME,
        SyntheticScenario.REVIEWER_MUTATE_DELETE,
        SyntheticScenario.REVIEWER_DOT_GIT_ACCESS,
        SyntheticScenario.REVIEWER_HOST_ACCESS,
        SyntheticScenario.REVIEWER_CONTROLLER_ACCESS,
        SyntheticScenario.REVIEWER_CREDENTIAL_ACCESS,
    ],
)
def test_real_l1_reviewer_attack_is_denied_and_checkpoint_stays_exact(
    slice_d_project, scenario: SyntheticScenario
) -> None:
    evidence = slice_d_project
    _dispatch, verification = _verify_stage(
        evidence,
        evidence["board"],
        "build-d",
        evidence["checkpoint"],
        "review-attack-verify",
    )
    assert verification.classification is VerificationClassification.PASS
    review_board = BoardSnapshot.create(
        evidence["board"].project,
        (replace(evidence["board"].task("build-d"), status=TaskStatus.REVIEW),),
    )
    result = _review_stage(
        evidence,
        review_board,
        "build-d",
        evidence["checkpoint"],
        verification,
        scenario=scenario,
        builder_dispatch=evidence["dispatch"],
        builder_scope="aos-task-builder-original.scope",
        label="review-attack-" + scenario.value.lower(),
    )
    assert result.classification is ReviewClassification.PASS
    after = evidence["manager"].capture_checkpoint(
        evidence["repo"], "project-workspace-d", 1
    )
    assert after.checkpoint == evidence["checkpoint"]


def test_real_build_verify_fail_repair_verify_review_pass_satisfies_parent(
    slice_d_project,
) -> None:
    evidence = slice_d_project
    authority = _authority_for_e2e(
        evidence, evidence["task_tmp"].parent / "flow-one-board"
    )
    authority.transition_task(
        authority.snapshot.revision,
        "build-d",
        TaskStatus.IN_PROGRESS,
        transaction_id="tx-flow-one-build-start",
    )
    initial_capture = evidence["manager"].capture_checkpoint(
        evidence["repo"], "project-workspace-d", 1
    )
    lease_ledger = WorkspaceLeaseLedger(
        evidence["task_tmp"].parent / "flow-one-leases", "project-d"
    )
    build_dispatch, build = _execute_initial_build(
        evidence,
        authority=authority,
        checkpoint_capture=initial_capture,
        lease_ledger=lease_ledger,
        scenario=SyntheticScenario.BROKEN_FEATURE_EDIT,
        label="flow-one-build",
    )
    assert build.first_checkpoint.checkpoint_digest != initial_capture.checkpoint.checkpoint_digest
    authority.transition_task(
        authority.snapshot.revision,
        "build-d",
        TaskStatus.VERIFYING,
        transaction_id="tx-flow-one-build-terminal",
    )
    _verify_dispatch, failed = _verify_stage(
        evidence,
        authority.snapshot,
        "build-d",
        build.first_checkpoint,
        "flow-one-verify-fail",
    )
    assert failed.classification is VerificationClassification.FAIL
    repair_controller = RepairController()
    created = repair_controller.create_for_verification_failure(
        authority=authority,
        parent_task_id="build-d",
        result=failed,
        policy=RepairBudgetPolicy(),
        now_unix_ms=2,
        transaction_id="tx-flow-one-create-repair",
    )
    replay = repair_controller.create_for_verification_failure(
        authority=authority,
        parent_task_id="build-d",
        result=failed,
        policy=RepairBudgetPolicy(),
        now_unix_ms=3,
        transaction_id="tx-flow-one-replay",
    )
    assert created.repair_task_id == replay.repair_task_id
    assert created.created is True and replay.created is False
    assert created.repair_task_id is not None
    repair_id = created.repair_task_id

    authority.transition_task(
        authority.snapshot.revision,
        repair_id,
        TaskStatus.IN_PROGRESS,
        transaction_id="tx-flow-one-repair-start",
    )
    broken_capture = evidence["manager"].capture_checkpoint(
        evidence["repo"], "project-workspace-d", 1
    )
    repair_runner = _stage_runner(
        evidence,
        profile=M4AProfile.BUILD,
        worker="synthetic_worker.py",
        label="flow-one-repair",
    )
    repaired = SyntheticRepairAdapter(SyntheticScenario.REPAIR_FEATURE).execute(
        board=authority.snapshot,
        repair_task_id=repair_id,
        checkpoint_capture=broken_capture,
        lease_ledger=lease_ledger,
        execution_root=evidence["task_tmp"].parent / "flow-one-repair-execution",
        runner=repair_runner,
        workspace_manager=evidence["manager"],
        repo_path=evidence["repo"],
        timeout=10,
    )
    assert repaired.execution.agent_result is not None
    assert repaired.execution.agent_result.status is ResultStatus.SUCCEEDED
    assert repaired.execution.first_checkpoint == repaired.execution.second_checkpoint
    assert repaired.execution.first_checkpoint.checkpoint_digest != broken_capture.checkpoint.checkpoint_digest
    assert repair_runner.backend.scope_evidence(
        repaired.execution.process_result.containment_unit
    ).state.value == "ABSENT"
    with pytest.raises(RepairError, match="INVALID_REPAIR_EXECUTION_RESULT"):
        repair_controller.record_execution_success(
            authority=authority,
            task_id=repair_id,
            result=replace(repaired, terminal_status="CANCELLED"),
            transaction_id="tx-flow-one-late-cancelled",
        )
    assert authority.snapshot.task(repair_id).status is TaskStatus.IN_PROGRESS
    repair_controller.record_execution_success(
        authority=authority,
        task_id=repair_id,
        result=repaired,
        transaction_id="tx-flow-one-repair-terminal",
    )
    _dispatch, passed = _verify_stage(
        evidence,
        authority.snapshot,
        repair_id,
        repaired.execution.first_checkpoint,
        "flow-one-verify-pass",
    )
    assert passed.classification is VerificationClassification.PASS
    repair_controller.record_verification_pass(
        authority=authority,
        task_id=repair_id,
        result=passed,
        transaction_id="tx-flow-one-record-pass",
    )
    review = _review_stage(
        evidence,
        authority.snapshot,
        repair_id,
        repaired.execution.first_checkpoint,
        passed,
        scenario=SyntheticScenario.REVIEWER_PASS,
        builder_dispatch=repaired.dispatch,
        builder_scope=repaired.execution.process_result.containment_unit,
        label="flow-one-review-pass",
    )
    assert review.classification is ReviewClassification.PASS
    repair_controller.satisfy_lineage(
        authority=authority,
        task_id=repair_id,
        result=review,
        transaction_id="tx-flow-one-satisfy",
    )
    parent = authority.snapshot.task("build-d")
    child = authority.snapshot.task(repair_id)
    assert parent.status is child.status is TaskStatus.DONE
    assert parent.satisfying_descendant_id == repair_id
    assert parent.verification_result_digest == failed.result_digest
    assert child.verification_result_digest == passed.result_digest
    assert child.review_result_digest == review.result_digest
    assert build_dispatch.task_id == "build-d"


def test_real_build_review_fail_repair_reverify_rereview_pass_satisfies_parent(
    slice_d_project,
) -> None:
    evidence = slice_d_project
    authority = _authority_for_e2e(
        evidence, evidence["task_tmp"].parent / "flow-two-board"
    )
    authority.transition_task(
        authority.snapshot.revision,
        "build-d",
        TaskStatus.IN_PROGRESS,
        transaction_id="tx-flow-two-build-start",
    )
    initial_capture = evidence["manager"].capture_checkpoint(
        evidence["repo"], "project-workspace-d", 1
    )
    lease_ledger = WorkspaceLeaseLedger(
        evidence["task_tmp"].parent / "flow-two-leases", "project-d"
    )
    build_dispatch, build = _execute_initial_build(
        evidence,
        authority=authority,
        checkpoint_capture=initial_capture,
        lease_ledger=lease_ledger,
        scenario=SyntheticScenario.SUCCESSFUL_EDIT,
        label="flow-two-build",
    )
    authority.transition_task(
        authority.snapshot.revision,
        "build-d",
        TaskStatus.VERIFYING,
        transaction_id="tx-flow-two-build-terminal",
    )
    _dispatch, verified = _verify_stage(
        evidence,
        authority.snapshot,
        "build-d",
        build.first_checkpoint,
        "flow-two-verify-pass",
    )
    assert verified.classification is VerificationClassification.PASS
    repair_controller = RepairController()
    repair_controller.record_verification_pass(
        authority=authority,
        task_id="build-d",
        result=verified,
        transaction_id="tx-flow-two-record-pass",
    )
    blocked = _review_stage(
        evidence,
        authority.snapshot,
        "build-d",
        build.first_checkpoint,
        verified,
        scenario=SyntheticScenario.REVIEWER_FAIL,
        builder_dispatch=build_dispatch,
        builder_scope=build.process_result.containment_unit,
        label="flow-two-review-fail",
    )
    assert blocked.classification is ReviewClassification.BLOCKING
    created = repair_controller.create_for_review_failure(
        authority=authority,
        parent_task_id="build-d",
        result=blocked,
        policy=RepairBudgetPolicy(),
        now_unix_ms=2,
        transaction_id="tx-flow-two-create-repair",
    )
    replay = repair_controller.create_for_review_failure(
        authority=authority,
        parent_task_id="build-d",
        result=blocked,
        policy=RepairBudgetPolicy(),
        now_unix_ms=3,
        transaction_id="tx-flow-two-review-replay",
    )
    assert created.repair_task_id == replay.repair_task_id
    assert created.repair_task_id is not None
    repair_id = created.repair_task_id
    authority.transition_task(
        authority.snapshot.revision,
        repair_id,
        TaskStatus.IN_PROGRESS,
        transaction_id="tx-flow-two-repair-start",
    )
    pre_repair_capture = evidence["manager"].capture_checkpoint(
        evidence["repo"], "project-workspace-d", 1
    )
    repair_runner = _stage_runner(
        evidence,
        profile=M4AProfile.BUILD,
        worker="synthetic_worker.py",
        label="flow-two-repair",
    )
    repaired = SyntheticRepairAdapter(SyntheticScenario.REPAIR_REVIEW).execute(
        board=authority.snapshot,
        repair_task_id=repair_id,
        checkpoint_capture=pre_repair_capture,
        lease_ledger=lease_ledger,
        execution_root=evidence["task_tmp"].parent / "flow-two-repair-execution",
        runner=repair_runner,
        workspace_manager=evidence["manager"],
        repo_path=evidence["repo"],
        timeout=10,
    )
    assert repaired.execution.first_checkpoint.checkpoint_digest != pre_repair_capture.checkpoint.checkpoint_digest
    repair_controller.record_execution_success(
        authority=authority,
        task_id=repair_id,
        result=repaired,
        transaction_id="tx-flow-two-repair-terminal",
    )
    _dispatch, reverified = _verify_stage(
        evidence,
        authority.snapshot,
        repair_id,
        repaired.execution.first_checkpoint,
        "flow-two-reverify-pass",
    )
    assert reverified.classification is VerificationClassification.PASS
    repair_controller.record_verification_pass(
        authority=authority,
        task_id=repair_id,
        result=reverified,
        transaction_id="tx-flow-two-record-reverify",
    )
    rereviewed = _review_stage(
        evidence,
        authority.snapshot,
        repair_id,
        repaired.execution.first_checkpoint,
        reverified,
        scenario=SyntheticScenario.REVIEWER_PASS,
        builder_dispatch=repaired.dispatch,
        builder_scope=repaired.execution.process_result.containment_unit,
        label="flow-two-rereview-pass",
    )
    assert rereviewed.classification is ReviewClassification.PASS
    repair_controller.satisfy_lineage(
        authority=authority,
        task_id=repair_id,
        result=rereviewed,
        transaction_id="tx-flow-two-satisfy",
    )
    parent = authority.snapshot.task("build-d")
    child = authority.snapshot.task(repair_id)
    assert parent.status is child.status is TaskStatus.DONE
    assert parent.satisfying_descendant_id == repair_id
    assert parent.verification_result_digest == verified.result_digest
    assert parent.review_result_digest == blocked.result_digest
    assert child.verification_result_digest == reverified.result_digest
    assert child.review_result_digest == rereviewed.result_digest
