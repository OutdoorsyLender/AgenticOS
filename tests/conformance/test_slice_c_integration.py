"""Real Ubuntu proof for the first autonomous synthetic build slice."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from agenticos.orchestration.board import BoardSnapshot
from agenticos.orchestration.execution import (
    ExecutionError,
    ExecutionLedger,
    SyntheticBuildController,
    create_containment_reservation,
)
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
    DispatchIdentity,
    ProtocolLimits,
    ResultStatus,
)
from agenticos.orchestration.synthetic import (
    SyntheticScenario,
    build_synthetic_workspace_argv,
)
from agenticos.orchestration.workspace import (
    LEASE_IDENTITY_SCHEMA,
    WorkspaceLeaseAdmission,
    WorkspaceLeaseIdentity,
    WorkspaceLeaseLedger,
    WorkspaceLeaseState,
)
from agenticos.sandbox.containment import CancellationConfig, CgroupProcessRunner
from agenticos.sandbox.evidence import EvidenceCollector
from agenticos.sandbox.isolation import probe_landlock_enforcement
from agenticos.sandbox.m4a_runner import NamespaceLandlockRunner
from agenticos.sandbox.runtime_boundary import M4AProfile, probe_bubblewrap
from agenticos.sandbox.worktree import (
    WorkspaceCaptureCompleteness,
    WorkspaceReuseDecision,
    WorktreeManager,
    create_worktree_reservation,
)


pytestmark = [
    pytest.mark.m4a_linux,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux M4A/M5 proof"),
]

FAST = CancellationConfig(0.2, 0.2, 3.0, 0.02)


@pytest.fixture(scope="session")
def slice_c_launcher(tmp_path_factory):
    output = tmp_path_factory.mktemp("slice-c-launcher") / "fs_launcher"
    source = Path(__file__).parents[2] / "native" / "fs_launcher" / "fs_launcher.c"
    subprocess.run(
        ["cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror", "-O2", str(source), "-o", str(output)],
        check=True,
    )
    return output


@pytest.fixture(scope="session")
def slice_c_host_ok():
    support = CgroupProcessRunner.probe()
    if not support.supported:
        pytest.fail("transient scopes unavailable: " + "; ".join(support.reasons))
    landlock_ok, reason = probe_landlock_enforcement()
    if not landlock_ok:
        pytest.fail("Landlock unavailable: " + reason)
    bwrap = probe_bubblewrap()
    if not bwrap.supported:
        pytest.fail("Bubblewrap unavailable: " + "; ".join(bwrap.reasons))


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def _fixture(
    tmp_path: Path,
    launcher: Path,
    scenario: SyntheticScenario,
    *,
    before_execute=None,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "core.autocrlf", "false")
    _git(repo, "config", "user.name", "Slice C Test")
    _git(repo, "config", "user.email", "slice-c@agenticos.local")
    (repo / "slice-c-tracked.txt").write_text("slice-c baseline\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "slice c baseline")
    baseline = _git(repo, "rev-parse", "HEAD")

    state_root = tmp_path / "m5-state"
    manager = WorktreeManager(state_root)
    reservation = create_worktree_reservation(
        repo_path=repo,
        task_id="slice-c-workspace",
        generation=1,
        baseline_commit_sha=baseline,
        nonce="7" * 32,
        policy_digest="8" * 64,
        state_root=state_root,
    )
    lifecycle = manager.create(reservation)
    pre_capture = manager.capture_checkpoint(repo, "slice-c-workspace", 1)
    assert pre_capture.decision is WorkspaceReuseDecision.REUSABLE
    assert pre_capture.checkpoint is not None
    pre = pre_capture.checkpoint
    assert pre.capture_completeness is WorkspaceCaptureCompleteness.COMPLETE

    workspace_ref = WorkspaceIdentityRef(
        workspace_id="slice-c-workspace",
        generation=1,
        reservation_id=pre.reservation_digest,
    )
    dispatch = DispatchIdentity(
        project_id="slice-c-project",
        task_id="build-c",
        task_generation=1,
        attempt=1,
        controller_epoch=1,
        lease_epoch=1,
        dispatch_nonce="1" * 32,
        repository_id=pre.repository_id,
        baseline_commit=baseline,
        workspace_id=workspace_ref.workspace_id,
        workspace_generation=workspace_ref.generation,
        reservation_id=workspace_ref.reservation_id,
        checkpoint_digest=pre.checkpoint_digest,
    )
    request = AgentTaskRequest(
        schema=AGENT_PROTOCOL_SCHEMA,
        identity=dispatch,
        role=Role.BUILDER,
        provider_id="synthetic",
        model_id="deterministic-workspace-v1",
        workspace_mount="/workspace",
        instructions="Execute only the selected deterministic Slice C fixture.",
        acceptance_criteria=("M5 observes the exact terminal workspace state.",),
        context_manifest=(),
        capabilities=(AgentCapability.READ_WORKSPACE, AgentCapability.WRITE_WORKSPACE, AgentCapability.RUN_BOUNDED_COMMANDS),
        limits=ProtocolLimits(16, 16_384, 131_072, 1, 1024, 4, 10),
    )
    project = ProjectRecord(
        BOARD_SCHEMA,
        dispatch.project_id,
        "Run one deterministic synthetic builder.",
        BaselineIdentity(pre.repository_id, baseline),
        workspace_ref,
        ProjectStatus.ACTIVE,
        None,
        1,
        1,
        1,
        RunLimits(max_runtime_seconds=10),
        1,
        100_000,
        1,
        "d" * 64,
    )
    task = BoardTask(
        BOARD_SCHEMA,
        "build-c",
        dispatch.project_id,
        "Synthetic build",
        "Apply one deterministic fixture.",
        TaskType.BUILD,
        50,
        (),
        ("Stable M5 checkpoint exists.",),
        Role.BUILDER,
        Role.BUILDER,
        TaskStatus.IN_PROGRESS,
        1,
        1,
        1,
        "CONTROLLER",
        None,
        "build-c",
        1,
        workspace_ref,
        1,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    board = BoardSnapshot.create(project, (task,))
    lease_identity = WorkspaceLeaseIdentity(
        LEASE_IDENTITY_SCHEMA,
        dispatch.project_id,
        dispatch.task_id,
        1,
        1,
        1,
        1,
        workspace_ref,
        dispatch.dispatch_nonce,
        pre.checkpoint_digest,
    )
    lease_ledger = WorkspaceLeaseLedger(tmp_path / "leases", dispatch.project_id)
    lease_ledger.acquire(
        lease_identity,
        WorkspaceLeaseAdmission.issue(
            board=board,
            identity=lease_identity,
            checkpoint_capture=pre_capture,
        ),
    )
    containment = create_containment_reservation(dispatch)
    task_tmp = tmp_path / "task-tmp"
    synthetic_home = tmp_path / "synthetic-home"
    task_tmp.mkdir()
    synthetic_home.mkdir()
    worker = Path(__file__).parents[2] / "src" / "agenticos" / "orchestration" / "synthetic_worker.py"
    runner = NamespaceLandlockRunner(
        worker_path=worker,
        workspace=lifecycle.worktree_path,
        profile=M4AProfile.BUILD,
        launcher_path=launcher,
        task_tmp=task_tmp,
        synthetic_home=synthetic_home,
        git_mask_path=manager.ensure_git_mask(
            pre.repository_id, "slice-c-workspace", 1
        ),
        cancellation=FAST,
        collector=EvidenceCollector(normalize_root=tmp_path),
    )
    execution_ledger = ExecutionLedger(tmp_path / "execution", dispatch)
    controller = SyntheticBuildController(execution_ledger)
    if before_execute is not None:
        before_execute(
            {
                "containment": containment,
                "dispatch": dispatch,
                "execution_ledger": execution_ledger,
                "lease_ledger": lease_ledger,
                "manager": manager,
                "pre": pre,
                "repo": repo,
                "runner": runner,
                "worktree": lifecycle.worktree_path,
            }
        )
    outcome = controller.execute(
        board=board,
        dispatch=dispatch,
        lease_ledger=lease_ledger,
        pre_checkpoint=pre,
        runner=runner,
        reservation=containment,
        argv=build_synthetic_workspace_argv(request, scenario),
        workspace_manager=manager,
        repo_path=repo,
        timeout=0.35 if scenario is SyntheticScenario.TIMEOUT_AFTER_EDIT else 8.0,
        request=request,
    )
    return outcome, pre, lifecycle.worktree_path, lease_ledger, runner


@pytest.mark.parametrize(
    "scenario",
    [
        SyntheticScenario.SUCCESSFUL_EDIT,
        SyntheticScenario.NO_OP,
        SyntheticScenario.INVALID_PATH_ATTEMPT,
        SyntheticScenario.DOT_GIT_ATTEMPT,
        SyntheticScenario.CRASH_AFTER_EDIT,
        SyntheticScenario.TIMEOUT_AFTER_EDIT,
        SyntheticScenario.CHILD_PROCESS_CASE,
        SyntheticScenario.POST_TERMINAL_MUTATION_ATTEMPT,
    ],
)
def test_real_slice_c_scenario_matrix(
    tmp_path, slice_c_launcher, slice_c_host_ok, scenario: SyntheticScenario
):
    outcome, pre, worktree, lease, runner = _fixture(tmp_path, slice_c_launcher, scenario)

    assert outcome.first_checkpoint == outcome.second_checkpoint
    assert outcome.first_checkpoint.capture_completeness is WorkspaceCaptureCompleteness.COMPLETE
    assert lease.recover().state is WorkspaceLeaseState.RELEASED
    assert outcome.process_result.containment_state == "TERMINATED"
    assert runner.backend.unit_active(outcome.process_result.containment_unit) is False

    if scenario is SyntheticScenario.NO_OP:
        assert outcome.agent_result is not None
        assert outcome.agent_result.status is ResultStatus.NO_OP
        assert outcome.first_checkpoint == pre
    elif scenario in {
        SyntheticScenario.INVALID_PATH_ATTEMPT,
        SyntheticScenario.DOT_GIT_ATTEMPT,
        SyntheticScenario.POST_TERMINAL_MUTATION_ATTEMPT,
    }:
        assert outcome.agent_result is not None
        assert outcome.agent_result.status is ResultStatus.SUCCEEDED
        assert outcome.first_checkpoint == pre
        if scenario is SyntheticScenario.POST_TERMINAL_MUTATION_ATTEMPT:
            assert not (worktree / "slice-c-post-terminal.txt").exists()
    elif scenario is SyntheticScenario.CRASH_AFTER_EDIT:
        assert outcome.process_result.exit_code == 17
        assert outcome.agent_result is None
        assert outcome.first_checkpoint != pre
    elif scenario is SyntheticScenario.TIMEOUT_AFTER_EDIT:
        assert outcome.process_result.timed_out is True
        assert outcome.agent_result is None
        assert outcome.first_checkpoint != pre
    else:
        assert outcome.agent_result is not None
        assert outcome.agent_result.status is ResultStatus.SUCCEEDED
        assert outcome.first_checkpoint != pre

    expected_paths = {
        SyntheticScenario.SUCCESSFUL_EDIT: {"slice-c-created.txt"},
        SyntheticScenario.CHILD_PROCESS_CASE: {"slice-c-child.txt"},
    }
    for relative in expected_paths.get(scenario, set()):
        assert (worktree / relative).is_file()


def test_real_receipt_persistence_failure_never_releases_worker_and_restores_clean_authority(
    tmp_path, slice_c_launcher, slice_c_host_ok
):
    observed: dict[str, object] = {}

    def fail_receipt(context: dict[str, object]) -> None:
        observed.update(context)
        ledger = context["execution_ledger"]

        def fail(*args, **kwargs):
            raise ExecutionError("DURABLE_WRITE_FAILED")

        ledger.record_process_started = fail  # type: ignore[attr-defined]

    with pytest.raises(ExecutionError, match="PROCESS_RECEIPT_PERSISTENCE_FAILED"):
        _fixture(
            tmp_path,
            slice_c_launcher,
            SyntheticScenario.SUCCESSFUL_EDIT,
            before_execute=fail_receipt,
        )

    manager = observed["manager"]
    repo = observed["repo"]
    post = manager.capture_checkpoint(  # type: ignore[attr-defined]
        repo, "slice-c-workspace", 1
    )
    assert post.decision is WorkspaceReuseDecision.REUSABLE
    assert post.checkpoint == observed["pre"]
    worktree = observed["worktree"]
    assert (worktree / "slice-c-tracked.txt").read_bytes() == b"slice-c baseline\n"  # type: ignore[operator]
    assert not (worktree / "slice-c-created.txt").exists()  # type: ignore[operator]
    lease = observed["lease_ledger"]
    assert lease.recover().state is WorkspaceLeaseState.CANCELLED  # type: ignore[attr-defined]
    runner = observed["runner"]
    containment = observed["containment"]
    assert runner.backend.unit_active(containment.scope_name) is False  # type: ignore[attr-defined]
