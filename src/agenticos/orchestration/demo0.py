"""Real deterministic Demo 0 adapter over the earned A-D boundaries."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time

from agenticos.sandbox.containment import CancellationConfig, SystemdScopeBackend
from agenticos.sandbox.m4a_runner import NamespaceLandlockRunner
from agenticos.sandbox.runtime_boundary import M4AProfile
from agenticos.sandbox.worktree import (
    WorkspaceCaptureCompleteness,
    WorkspaceCaptureFailureKind,
    WorkspaceCheckpoint,
    WorkspaceReuseDecision,
    WorkspaceStatusCounts,
    WorktreeManager,
    create_worktree_reservation,
)

from .board import AcceptedBoardMutation, BoardAuthority, BoardSnapshot
from .canonical import canonical_json_bytes, canonical_json_line, load_canonical_json
from .execution import (
    ExecutionLedger,
    ExecutionOutcome,
    ExecutionState,
    SyntheticBuildController,
    create_containment_reservation,
)
from .journal import TransactionJournal, _durable_replace
from .models import (
    BaselineIdentity,
    BoardTask,
    ProjectStatus,
    Role,
    RunLimits,
    TaskStatus,
    TaskType,
    WorkspaceIdentityRef,
)
from .proposals import PlannerProposal
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
from .repair import RepairController, RepairExecutionOutcome, SyntheticRepairAdapter
from .review import (
    ReviewController,
    ReviewResult,
    ReviewerExecutionIdentity,
    SyntheticReviewerAdapter,
)
from .scheduler import (
    AutonomousScheduler,
    ExecutionClassification,
    ExecutionStageResult,
    FinalizationEvidence,
    PlanningStageResult,
    ResearchStageResult,
    SchedulerLimits,
    SchedulerResult,
    SchedulerError,
    create_project,
)
from .synthetic import (
    SyntheticScenario,
    build_synthetic_fixture,
    build_synthetic_workspace_argv,
    run_synthetic_fixture,
)
from .verification import (
    VerificationController,
    VerificationResult,
    VerifierRegistry,
    VerifierSpec,
)
from .workspace import (
    LEASE_IDENTITY_SCHEMA,
    WorkspaceLeaseAdmission,
    WorkspaceLeaseIdentity,
    WorkspaceLeaseLedger,
    WorkspaceLeaseState,
)


DEMO_GOAL = "Add the requested feature to the fixture application."
FAST_CANCELLATION = CancellationConfig(
    sigint_grace=0.5,
    sigterm_grace=0.5,
    empty_verify_timeout=5.0,
    poll_interval=0.05,
)


@dataclass(frozen=True, slots=True)
class _NormalBuildEvidence:
    dispatch: DispatchIdentity
    outcome: ExecutionOutcome


@dataclass(frozen=True, slots=True)
class _RecoveredExecutionEvidence:
    dispatch: DispatchIdentity
    terminal_record_digest: str


class Demo0Runtime:
    """One project-local real M5/M4A stage driver; it never selects work."""

    def __init__(
        self,
        *,
        run_root: Path,
        repo_path: Path,
        state_root: Path,
        manager: WorktreeManager,
        worktree_state: object,
        launcher_path: Path,
        authority: BoardAuthority,
    ) -> None:
        self.run_root = run_root
        self.repo_path = repo_path
        self.state_root = state_root
        self.manager = manager
        self.worktree_state = worktree_state
        self.worktree_path = Path(worktree_state.worktree_path)  # type: ignore[attr-defined]
        self.launcher_path = launcher_path
        self.authority = authority
        self.lease_ledger = WorkspaceLeaseLedger(
            run_root / "leases", authority.snapshot.project.project_id
        )
        self.repair_controller = RepairController()
        self.git_mask = manager.ensure_git_mask(
            authority.snapshot.project.baseline.repository_id,
            authority.snapshot.project.workspace.workspace_id,
            authority.snapshot.project.workspace.generation,
        )
        self._builder_identities: dict[str, ReviewerExecutionIdentity] = {}
        self._verifications: dict[str, VerificationResult] = {}
        self._observed_scopes: list[tuple[object, str]] = []

    @property
    def _repo_root(self) -> Path:
        return Path(__file__).resolve().parents[3]

    @classmethod
    def create(cls, run_root: Path, *, goal: str = DEMO_GOAL) -> "Demo0Runtime":
        run_root = Path(run_root).resolve()
        run_root.mkdir(parents=True, exist_ok=False)
        repo = run_root / "fixture-repo"
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "AgenticOS Demo 0"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "demo0@agenticos.local"], cwd=repo, check=True)
        (repo / "feature.txt").write_bytes(b"fixed\n")
        subprocess.run(["git", "add", "feature.txt"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-m", "Demo 0 baseline"], cwd=repo, check=True, capture_output=True)
        baseline = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, check=True,
            capture_output=True, text=True,
        ).stdout.strip()

        launcher = run_root / "fs_launcher"
        source = Path(__file__).resolve().parents[3] / "native" / "fs_launcher" / "fs_launcher.c"
        subprocess.run(
            [
                "cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
                "-Werror", "-O2", str(source), "-o", str(launcher),
            ],
            check=True,
            capture_output=True,
        )

        state_root = run_root / "m5-state"
        manager = WorktreeManager(state_root)
        reservation = create_worktree_reservation(
            repo_path=repo,
            task_id="demo-project-workspace",
            generation=1,
            baseline_commit_sha=baseline,
            nonce=secrets.token_hex(16),
            policy_digest=hashlib.sha256(b"AgenticOS Demo 0 workspace policy").hexdigest(),
            state_root=state_root,
            allow_temporary_for_test=True,
        )
        worktree_state = manager.create(reservation)
        capture = manager.capture_checkpoint(repo, "demo-project-workspace", 1)
        if capture.decision is not WorkspaceReuseDecision.REUSABLE or capture.checkpoint is None:
            raise RuntimeError("DEMO_WORKSPACE_CHECKPOINT_FAILED")
        now = int(time.time() * 1000)
        authority = create_project(
            journal_root=run_root / "board",
            project_id="demo-001",
            goal=goal,
            baseline=BaselineIdentity(reservation.repository.repository_id, baseline),
            workspace=WorkspaceIdentityRef(
                "demo-project-workspace", 1, reservation.reservation_digest
            ),
            limits=RunLimits(
                max_tasks=16,
                max_total_attempts=32,
                max_repair_depth=4,
                max_events_per_attempt=64,
                max_event_bytes=16_384,
                max_output_bytes=262_144,
                max_context_entries=16,
                max_context_bytes=65_536,
                max_processes=8,
                max_runtime_seconds=30,
            ),
            started_at_unix_ms=now,
            deadline_unix_ms=now + 10 * 60 * 1000,
        )
        return cls(
            run_root=run_root,
            repo_path=repo,
            state_root=state_root,
            manager=manager,
            worktree_state=worktree_state,
            launcher_path=launcher,
            authority=authority,
        )

    @classmethod
    def recover(cls, run_root: Path) -> "Demo0Runtime":
        """Reconstruct the Demo 0 controller solely from durable local state."""
        run_root = Path(run_root).resolve()
        authority = BoardAuthority.recover(
            TransactionJournal(run_root / "board", "demo-001")
        )
        project = authority.snapshot.project
        repo = run_root / "fixture-repo"
        state_root = run_root / "m5-state"
        manager = WorktreeManager(state_root)
        worktree_state = manager.recover(
            repo,
            project.workspace.workspace_id,
            project.workspace.generation,
        )
        return cls(
            run_root=run_root,
            repo_path=repo,
            state_root=state_root,
            manager=manager,
            worktree_state=worktree_state,
            launcher_path=run_root / "fs_launcher",
            authority=authority,
        )

    def _persist_bytes(self, category: str, name: str, raw: bytes) -> Path:
        if type(raw) is not bytes or len(raw) > 262_144:
            raise RuntimeError("DEMO_EVIDENCE_LIMIT")
        root = self.run_root / "evidence" / category
        root.mkdir(parents=True, exist_ok=True)
        target = root / f"{name}.json"
        if target.exists():
            if target.read_bytes() != raw:
                raise RuntimeError("DEMO_EVIDENCE_CONFLICT")
            return target
        temporary = root / f".tmp-{secrets.token_hex(16)}"
        with temporary.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        _durable_replace(temporary, target)
        return target

    def _persist_json(self, category: str, name: str, value: object) -> Path:
        return self._persist_bytes(category, name, canonical_json_line(value))

    def _record_scope(self, backend: object, scope: str) -> None:
        self._observed_scopes.append((backend, scope))
        key = hashlib.sha256(scope.encode("utf-8")).hexdigest()
        self._persist_json("scopes", key, {"scope": scope})

    @staticmethod
    def _checkpoint_from_dict(value: object) -> WorkspaceCheckpoint:
        if not isinstance(value, dict):
            raise RuntimeError("DEMO_CHECKPOINT_EVIDENCE_INVALID")
        expected = set(WorkspaceCheckpoint.__dataclass_fields__)
        if set(value) != expected or not isinstance(value.get("status_counts"), dict):
            raise RuntimeError("DEMO_CHECKPOINT_EVIDENCE_INVALID")
        return WorkspaceCheckpoint(
            **{
                **value,
                "status_counts": WorkspaceStatusCounts(**value["status_counts"]),
                "anomalies": tuple(
                    WorkspaceCaptureFailureKind(item) for item in value["anomalies"]
                ),
                "capture_completeness": WorkspaceCaptureCompleteness(
                    value["capture_completeness"]
                ),
            }
        )

    @staticmethod
    def _dispatch_from_lease(snapshot: BoardSnapshot, lease: WorkspaceLeaseIdentity) -> DispatchIdentity:
        return DispatchIdentity(
            project_id=lease.project_id,
            task_id=lease.task_id,
            task_generation=lease.task_generation,
            attempt=lease.attempt,
            controller_epoch=lease.controller_epoch,
            lease_epoch=lease.lease_epoch,
            dispatch_nonce=lease.dispatch_nonce,
            repository_id=snapshot.project.baseline.repository_id,
            baseline_commit=snapshot.project.baseline.commit_sha,
            workspace_id=lease.workspace.workspace_id,
            workspace_generation=lease.workspace.generation,
            reservation_id=lease.workspace.reservation_id,
            checkpoint_digest=lease.pre_checkpoint_digest,
        )

    def _persist_execution_success(
        self,
        task: BoardTask,
        dispatch: DispatchIdentity,
        checkpoint_digest: str,
        evidence_digest: str,
        terminal_record_digest: str,
    ) -> None:
        self._persist_json(
            "execution",
            task.task_id,
            {
                "schema": "AOSDEMOEXECUTION/1",
                "task_type": task.task_type.value,
                "dispatch": dispatch.to_dict(),
                "checkpoint_digest": checkpoint_digest,
                "evidence_digest": evidence_digest,
                "terminal_record_digest": terminal_record_digest,
            },
        )

    def _capture(self):
        project = self.authority.snapshot.project
        capture = self.manager.capture_checkpoint(
            self.repo_path,
            project.workspace.workspace_id,
            project.workspace.generation,
        )
        if capture.decision is not WorkspaceReuseDecision.REUSABLE or capture.checkpoint is None:
            raise RuntimeError("DEMO_CHECKPOINT_FAILED")
        return capture

    @staticmethod
    def _protocol_limits(snapshot: BoardSnapshot) -> ProtocolLimits:
        limits = snapshot.project.limits
        return ProtocolLimits(
            max_events=limits.max_events_per_attempt,
            max_event_bytes=limits.max_event_bytes,
            max_output_bytes=limits.max_output_bytes,
            max_context_entries=limits.max_context_entries,
            max_context_bytes=limits.max_context_bytes,
            max_processes=limits.max_processes,
            max_runtime_seconds=limits.max_runtime_seconds,
        )

    def _dispatch(self, snapshot: BoardSnapshot, task: BoardTask, checkpoint) -> DispatchIdentity:
        project = snapshot.project
        return DispatchIdentity(
            project_id=project.project_id,
            task_id=task.task_id,
            task_generation=task.generation,
            attempt=task.attempt_count,
            controller_epoch=project.controller_epoch,
            lease_epoch=task.lease_epoch,
            dispatch_nonce=secrets.token_hex(16),
            repository_id=project.baseline.repository_id,
            baseline_commit=project.baseline.commit_sha,
            workspace_id=task.workspace.workspace_id,
            workspace_generation=task.workspace.generation,
            reservation_id=task.workspace.reservation_id,
            checkpoint_digest=checkpoint.checkpoint_digest,
        )

    def _request(
        self,
        snapshot: BoardSnapshot,
        task: BoardTask,
        dispatch: DispatchIdentity,
    ) -> AgentTaskRequest:
        return AgentTaskRequest(
            schema=AGENT_PROTOCOL_SCHEMA,
            identity=dispatch,
            role=task.preferred_role,
            provider_id="synthetic-demo0",
            model_id="deterministic-demo0-v1",
            workspace_mount="/workspace",
            instructions="Execute only the fixed controller-selected synthetic stage.",
            acceptance_criteria=task.acceptance_criteria,
            context_manifest=(ContextItem(
                ContextKind.WORKSPACE_MANIFEST,
                "pre-stage-checkpoint",
                dispatch.checkpoint_digest,
                64,
            ),),
            capabilities=(
                AgentCapability.READ_CONTEXT,
                AgentCapability.READ_WORKSPACE,
                AgentCapability.WRITE_WORKSPACE,
            ),
            limits=self._protocol_limits(snapshot),
        )

    def _nonworkspace_request(
        self,
        snapshot: BoardSnapshot,
        task: BoardTask,
        *,
        context_manifest: tuple[ContextItem, ...],
        capability: AgentCapability,
    ) -> AgentTaskRequest:
        checkpoint = self._capture().checkpoint
        dispatch = self._dispatch(snapshot, task, checkpoint)
        return AgentTaskRequest(
            schema=AGENT_PROTOCOL_SCHEMA,
            identity=dispatch,
            role=task.preferred_role,
            provider_id="synthetic-demo0",
            model_id="deterministic-demo0-v1",
            workspace_mount="/workspace",
            instructions="Return one bounded deterministic proposal; no command authority.",
            acceptance_criteria=task.acceptance_criteria,
            context_manifest=context_manifest,
            capabilities=(
                (AgentCapability.READ_CONTEXT,)
                if capability is AgentCapability.READ_CONTEXT
                else (AgentCapability.READ_CONTEXT, capability)
            ),
            limits=self._protocol_limits(snapshot),
        )

    def run_research(self, snapshot: BoardSnapshot, task: BoardTask) -> ResearchStageResult:
        goal_bytes = snapshot.project.goal.encode("utf-8")
        goal_digest = hashlib.sha256(goal_bytes).hexdigest()
        request = self._nonworkspace_request(
            snapshot,
            task,
            context_manifest=(
                ContextItem(ContextKind.PLAN_INPUT, "owner-goal", goal_digest, len(goal_bytes)),
            ),
            capability=AgentCapability.READ_CONTEXT,
        )
        fixture = build_synthetic_fixture(request, SyntheticScenario.RESEARCHER_SUCCESS)
        outcome = run_synthetic_fixture(request, fixture)
        if not outcome.accepted or outcome.result is None or len(fixture.artifacts) != 1:
            raise RuntimeError("DEMO_RESEARCH_REJECTED")
        content = fixture.artifacts[0][1]
        digest = hashlib.sha256(content).hexdigest()
        self._persist_bytes("research", task.task_id, content)
        return ResearchStageResult(digest, content)

    def run_plan(
        self,
        snapshot: BoardSnapshot,
        task: BoardTask,
        research_digest: str,
    ) -> PlanningStageResult:
        research_content = (self.run_root / "evidence" / "research" / "bootstrap-research.json").read_bytes()
        if hashlib.sha256(research_content).hexdigest() != research_digest:
            raise RuntimeError("DEMO_RESEARCH_EVIDENCE_MISMATCH")
        goal_bytes = snapshot.project.goal.encode("utf-8")
        request = self._nonworkspace_request(
            snapshot,
            task,
            context_manifest=(
                ContextItem(
                    ContextKind.PLAN_INPUT,
                    "owner-goal",
                    hashlib.sha256(goal_bytes).hexdigest(),
                    len(goal_bytes),
                ),
                ContextItem(
                    ContextKind.RESEARCH_NOTE,
                    "bounded-research",
                    research_digest,
                    len(research_content),
                ),
            ),
            capability=AgentCapability.PROPOSE_TASKS,
        )
        fixture = build_synthetic_fixture(request, SyntheticScenario.DEMO_PLANNER_SUCCESS)
        outcome = run_synthetic_fixture(request, fixture)
        if not outcome.accepted or outcome.result is None or len(fixture.artifacts) != 1:
            raise RuntimeError("DEMO_PLAN_REJECTED")
        proposal = PlannerProposal.from_dict(load_canonical_json(fixture.artifacts[0][1]))
        digest = hashlib.sha256(canonical_json_bytes(proposal.to_dict())).hexdigest()
        self._persist_json("planning", task.task_id, proposal.to_dict())
        return PlanningStageResult(digest, proposal)

    def _runner(self, *, profile: M4AProfile, worker: str, label: str):
        stage_root = Path(tempfile.mkdtemp(prefix=f"{label}-", dir=self.run_root / "stages"))
        task_tmp = stage_root / "tmp"
        home = stage_root / "home"
        task_tmp.mkdir()
        home.mkdir()
        return NamespaceLandlockRunner(
            worker_path=self._repo_root / "src" / "agenticos" / "orchestration" / worker,
            workspace=self.worktree_path,
            profile=profile,
            launcher_path=self.launcher_path,
            task_tmp=task_tmp,
            synthetic_home=home,
            git_mask_path=self.git_mask,
            cancellation=FAST_CANCELLATION,
        )

    def _remember_builder(self, task: BoardTask, dispatch: DispatchIdentity, outcome: ExecutionOutcome) -> None:
        scope = outcome.process_result.containment_unit
        self._builder_identities[task.task_id] = ReviewerExecutionIdentity(
            f"builder-adapter-{task.generation}",
            f"builder-session-{task.generation}-{task.creation_sequence}",
            dispatch.dispatch_nonce,
            scope,
        )

    def reconcile_execution(
        self,
        snapshot: BoardSnapshot,
        task: BoardTask,
    ) -> ExecutionStageResult | None:
        """Recover a controller-validated terminal receipt or drain an active dispatch."""
        receipt_path = self.run_root / "evidence" / "execution" / f"{task.task_id}.json"
        if receipt_path.is_file():
            value = load_canonical_json(receipt_path.read_bytes())
            expected = {
                "schema",
                "task_type",
                "dispatch",
                "checkpoint_digest",
                "evidence_digest",
                "terminal_record_digest",
            }
            if not isinstance(value, dict) or set(value) != expected:
                raise SchedulerError("EXECUTION_RECEIPT_INVALID")
            dispatch = DispatchIdentity.from_dict(value["dispatch"])
            ledger = ExecutionLedger(
                self.run_root / "executions" / task.task_id,
                dispatch,
            )
            terminal = ledger.recover()
            lease_record = self.lease_ledger.recover()
            capture = self._capture()
            valid = (
                value["schema"] == "AOSDEMOEXECUTION/1",
                value["task_type"] == task.task_type.value,
                dispatch.task_id == task.task_id,
                dispatch.task_generation == task.generation,
                dispatch.attempt == task.attempt_count,
                dispatch.controller_epoch == snapshot.project.controller_epoch,
                dispatch.lease_epoch == task.lease_epoch == snapshot.project.lease_epoch,
                terminal is not None,
                terminal.state is ExecutionState.TERMINAL_CAPTURED if terminal else False,
                terminal.record_digest == value["terminal_record_digest"] if terminal else False,
                terminal.checkpoint_digest == value["checkpoint_digest"] if terminal else False,
                capture.checkpoint is not None,
                capture.checkpoint.checkpoint_digest == value["checkpoint_digest"] if capture.checkpoint else False,
                lease_record is not None,
                lease_record.identity == terminal.lease if lease_record and terminal else False,
                lease_record.state is WorkspaceLeaseState.RELEASED if lease_record else False,
            )
            if not all(valid):
                raise SchedulerError("EXECUTION_RECEIPT_BINDING_MISMATCH")
            return ExecutionStageResult(
                task.task_id,
                task.generation,
                task.attempt_count,
                snapshot.project.controller_epoch,
                task.lease_epoch,
                ExecutionClassification.SUCCESS,
                value["checkpoint_digest"],
                value["evidence_digest"],
                _RecoveredExecutionEvidence(dispatch, value["terminal_record_digest"]),
            )

        lease_record = self.lease_ledger.recover()
        if lease_record is None or lease_record.identity.task_id != task.task_id:
            return None
        lease = lease_record.identity
        dispatch = self._dispatch_from_lease(snapshot, lease)
        ledger = ExecutionLedger(self.run_root / "executions" / task.task_id, dispatch)
        current = ledger.recover()
        if current is None:
            raise SchedulerError("ACTIVE_LEASE_EXECUTION_MISSING")
        pre_path = self.run_root / "evidence" / "pre-checkpoint" / f"{task.task_id}.json"
        if not pre_path.is_file():
            raise SchedulerError("PRE_EXECUTION_CHECKPOINT_MISSING")
        pre_checkpoint = self._checkpoint_from_dict(
            load_canonical_json(pre_path.read_bytes())
        )
        runner = self._runner(
            profile=M4AProfile.BUILD,
            worker="synthetic_worker.py",
            label=f"recover-{task.creation_sequence}",
        )
        terminal = SyntheticBuildController(ledger).recover(
            backend=runner.backend,
            cancellation=FAST_CANCELLATION,
            lease_ledger=self.lease_ledger,
            workspace_manager=self.manager,
            repo_path=self.repo_path,
            pre_checkpoint=pre_checkpoint,
        )
        self._record_scope(runner.backend, terminal.reservation.scope_name)
        return ExecutionStageResult(
            task.task_id,
            task.generation,
            task.attempt_count,
            snapshot.project.controller_epoch,
            task.lease_epoch,
            (
                ExecutionClassification.CANCELLED
                if terminal.state is ExecutionState.TERMINAL_CAPTURED
                and self.lease_ledger.recover().state is WorkspaceLeaseState.CANCELLED  # type: ignore[union-attr]
                else ExecutionClassification.INFRASTRUCTURE_FAILURE
            ),
            None,
            terminal.record_digest,
            None,
        )

    def run_execution(self, snapshot: BoardSnapshot, task: BoardTask) -> ExecutionStageResult:
        capture = self._capture()
        checkpoint = capture.checkpoint
        self._persist_json("pre-checkpoint", task.task_id, checkpoint.to_dict())
        if task.task_type is TaskType.REPAIR:
            scenario = (
                SyntheticScenario.REPAIR_FEATURE
                if task.generation == 2
                else SyntheticScenario.REPAIR_REVIEW
            )
            runner = self._runner(
                profile=M4AProfile.BUILD,
                worker="synthetic_worker.py",
                label=f"repair-{task.generation}",
            )
            repaired = SyntheticRepairAdapter(scenario).execute(
                board=snapshot,
                repair_task_id=task.task_id,
                checkpoint_capture=capture,
                lease_ledger=self.lease_ledger,
                execution_root=self.run_root / "executions" / task.task_id,
                runner=runner,
                workspace_manager=self.manager,
                repo_path=self.repo_path,
                timeout=15,
            )
            self._record_scope(
                runner.backend,
                repaired.execution.process_result.containment_unit,
            )
            self._remember_builder(task, repaired.dispatch, repaired.execution)
            digest = hashlib.sha256(canonical_json_bytes(
                repaired.execution.terminal_record.to_dict()
            )).hexdigest()
            result = ExecutionStageResult(
                task.task_id,
                task.generation,
                task.attempt_count,
                snapshot.project.controller_epoch,
                task.lease_epoch,
                ExecutionClassification.SUCCESS,
                repaired.execution.first_checkpoint.checkpoint_digest,
                digest,
                repaired,
            )
            self._persist_execution_success(
                task,
                repaired.dispatch,
                result.checkpoint_digest,  # type: ignore[arg-type]
                result.evidence_digest,
                repaired.execution.terminal_record.record_digest,
            )
            return result

        scenario = (
            SyntheticScenario.BROKEN_FEATURE_EDIT
            if task.task_type is TaskType.BUILD
            else SyntheticScenario.FOLLOW_UP_EDIT
        )
        dispatch = self._dispatch(snapshot, task, checkpoint)
        request = self._request(snapshot, task, dispatch)
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
        self.lease_ledger.acquire(
            lease,
            WorkspaceLeaseAdmission.issue(
                board=snapshot, identity=lease, checkpoint_capture=capture
            ),
        )
        runner = self._runner(
            profile=M4AProfile.BUILD,
            worker="synthetic_worker.py",
            label=f"build-{task.creation_sequence}",
        )
        reservation = create_containment_reservation(dispatch)
        outcome = SyntheticBuildController(
            ExecutionLedger(self.run_root / "executions" / task.task_id, dispatch)
        ).execute(
            board=snapshot,
            dispatch=dispatch,
            lease_ledger=self.lease_ledger,
            pre_checkpoint=checkpoint,
            runner=runner,
            reservation=reservation,
            argv=build_synthetic_workspace_argv(request, scenario),
            workspace_manager=self.manager,
            repo_path=self.repo_path,
            timeout=15,
            request=request,
        )
        self._record_scope(runner.backend, outcome.process_result.containment_unit)
        self._remember_builder(task, dispatch, outcome)
        classification = (
            ExecutionClassification.SUCCESS
            if outcome.agent_result is not None
            and outcome.agent_result.status is ResultStatus.SUCCEEDED
            and outcome.terminal_record.state is ExecutionState.TERMINAL_CAPTURED
            else ExecutionClassification.INFRASTRUCTURE_FAILURE
        )
        digest = hashlib.sha256(canonical_json_bytes(outcome.terminal_record.to_dict())).hexdigest()
        result = ExecutionStageResult(
            task.task_id,
            task.generation,
            task.attempt_count,
            snapshot.project.controller_epoch,
            task.lease_epoch,
            classification,
            outcome.first_checkpoint.checkpoint_digest if classification == ExecutionClassification.SUCCESS else None,
            digest,
            _NormalBuildEvidence(dispatch, outcome),
        )
        if classification == ExecutionClassification.SUCCESS:
            self._persist_execution_success(
                task,
                dispatch,
                result.checkpoint_digest,  # type: ignore[arg-type]
                result.evidence_digest,
                outcome.terminal_record.record_digest,
            )
        return result

    def record_execution_success(
        self,
        authority: BoardAuthority,
        task_id: str,
        result: ExecutionStageResult,
        transaction_id: str,
    ) -> None:
        task = authority.snapshot.task(task_id)
        if isinstance(result.payload, _RecoveredExecutionEvidence):
            recovered = self.reconcile_execution(authority.snapshot, task)
            if (
                recovered is None
                or recovered.classification != ExecutionClassification.SUCCESS
                or recovered.task_id != result.task_id
                or recovered.checkpoint_digest != result.checkpoint_digest
                or recovered.evidence_digest != result.evidence_digest
            ):
                raise RuntimeError("DEMO_RECOVERED_EXECUTION_EVIDENCE_INVALID")
            mutation = authority.record_execution_success(
                authority.snapshot.revision,
                task_id,
                checkpoint_digest=result.checkpoint_digest,  # type: ignore[arg-type]
                evidence_digest=result.evidence_digest,
                transaction_id=transaction_id,
            )
            if not isinstance(mutation, AcceptedBoardMutation):
                raise RuntimeError("DEMO_RECOVERED_EXECUTION_ADVANCEMENT_REJECTED")
            return
        if task.task_type is TaskType.REPAIR:
            if not isinstance(result.payload, RepairExecutionOutcome):
                raise RuntimeError("DEMO_REPAIR_EVIDENCE_MISSING")
            self.repair_controller.record_execution_success(
                authority=authority,
                task_id=task_id,
                result=result.payload,
                transaction_id=transaction_id,
            )
            return
        evidence = result.payload
        if not isinstance(evidence, _NormalBuildEvidence):
            raise RuntimeError("DEMO_BUILD_EVIDENCE_MISSING")
        outcome = evidence.outcome
        valid = (
            evidence.dispatch.task_id == task.task_id,
            evidence.dispatch.task_generation == task.generation,
            evidence.dispatch.attempt == task.attempt_count,
            evidence.dispatch.controller_epoch == authority.snapshot.project.controller_epoch,
            evidence.dispatch.lease_epoch == task.lease_epoch,
            outcome.terminal_record.state is ExecutionState.TERMINAL_CAPTURED,
            outcome.first_checkpoint == outcome.second_checkpoint,
            outcome.first_checkpoint.checkpoint_digest == result.checkpoint_digest,
            outcome.agent_result is not None,
            outcome.agent_result.status is ResultStatus.SUCCEEDED if outcome.agent_result else False,
            outcome.protocol_rejection_code is None,
        )
        if not all(valid):
            raise RuntimeError("DEMO_BUILD_EVIDENCE_INVALID")
        mutation = authority.record_execution_success(
            authority.snapshot.revision,
            task_id,
            checkpoint_digest=result.checkpoint_digest,  # type: ignore[arg-type]
            evidence_digest=result.evidence_digest,
            transaction_id=transaction_id,
        )
        if not isinstance(mutation, AcceptedBoardMutation):
            raise RuntimeError("DEMO_BUILD_ADVANCEMENT_REJECTED")

    @staticmethod
    def _verifier_spec() -> VerifierSpec:
        return VerifierSpec(
            verifier_id="demo0-check-feature",
            executable="/usr/bin/python3",
            argv=(
                "/usr/bin/python3",
                "/opt/agenticos/worker.py",
                "--scenario",
                "CHECK_FEATURE",
            ),
            working_directory="/workspace",
            timeout_seconds=10,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
            pass_exit_codes=(0,),
            fail_exit_codes=(1,),
            fixture_id="demo0-feature-policy",
        )

    def run_verification(self, snapshot: BoardSnapshot, task: BoardTask) -> VerificationResult:
        capture = self._capture()
        if (
            task.execution_checkpoint_digest is None
            or capture.checkpoint is None
            or capture.checkpoint.checkpoint_digest != task.execution_checkpoint_digest
        ):
            raise SchedulerError("DEMO_VERIFICATION_CHECKPOINT_MISMATCH")
        evidence_path = (
            self.run_root / "evidence" / "verification" / f"{task.task_id}.json"
        )
        if evidence_path.is_file():
            persisted = VerificationResult.from_dict(
                load_canonical_json(evidence_path.read_bytes())
            )
            if (
                persisted.project_id != task.project_id
                or persisted.task_id != task.task_id
                or persisted.task_generation != task.generation
                or persisted.attempt != task.attempt_count
                or persisted.controller_epoch != snapshot.project.controller_epoch
                or persisted.checkpoint_digest != task.execution_checkpoint_digest
            ):
                raise SchedulerError("DEMO_VERIFICATION_EVIDENCE_MISMATCH")
            self._verifications[task.task_id] = persisted
            return persisted
        dispatch = self._dispatch(snapshot, task, capture.checkpoint)
        spec = self._verifier_spec()
        runner = self._runner(
            profile=M4AProfile.INSPECT,
            worker="verifier_worker.py",
            label=f"verify-{task.generation}-{task.creation_sequence}",
        )
        reservation = create_containment_reservation(dispatch)
        result = VerificationController(VerifierRegistry((spec,))).verify(
            board=snapshot,
            dispatch=dispatch,
            checkpoint=capture.checkpoint,
            verifier_id=spec.verifier_id,
            runner=runner,
            reservation=reservation,
            workspace_manager=self.manager,
            repo_path=self.repo_path,
        )
        self._record_scope(runner.backend, reservation.scope_name)
        self._persist_json("verification", task.task_id, result.to_dict())
        self._verifications[task.task_id] = result
        return result

    def _recover_builder_identity(self, snapshot: BoardSnapshot, task: BoardTask) -> ReviewerExecutionIdentity:
        lease_record = self.lease_ledger.recover()
        if lease_record is None:
            raise RuntimeError("DEMO_BUILDER_LEASE_MISSING")
        lease = lease_record.identity
        if (
            lease.task_id != task.task_id
            or lease.task_generation != task.generation
            or lease.attempt != task.attempt_count
            or lease.controller_epoch != snapshot.project.controller_epoch
            or lease.lease_epoch != task.lease_epoch
            or lease_record.state is not WorkspaceLeaseState.RELEASED
        ):
            raise RuntimeError("DEMO_BUILDER_LEASE_MISMATCH")
        dispatch = DispatchIdentity(
            project_id=lease.project_id,
            task_id=lease.task_id,
            task_generation=lease.task_generation,
            attempt=lease.attempt,
            controller_epoch=lease.controller_epoch,
            lease_epoch=lease.lease_epoch,
            dispatch_nonce=lease.dispatch_nonce,
            repository_id=snapshot.project.baseline.repository_id,
            baseline_commit=snapshot.project.baseline.commit_sha,
            workspace_id=lease.workspace.workspace_id,
            workspace_generation=lease.workspace.generation,
            reservation_id=lease.workspace.reservation_id,
            checkpoint_digest=lease.pre_checkpoint_digest,
        )
        terminal = ExecutionLedger(
            self.run_root / "executions" / task.task_id,
            dispatch,
        ).recover()
        if terminal is None or terminal.state is not ExecutionState.TERMINAL_CAPTURED:
            raise RuntimeError("DEMO_BUILDER_TERMINAL_EVIDENCE_MISSING")
        return ReviewerExecutionIdentity(
            f"builder-adapter-{task.generation}",
            f"builder-session-{task.generation}-{task.creation_sequence}",
            dispatch.dispatch_nonce,
            terminal.reservation.scope_name,
        )

    def run_review(
        self,
        snapshot: BoardSnapshot,
        task: BoardTask,
        verification_result_digest: str,
    ) -> ReviewResult:
        verification = self._verifications.get(task.task_id)
        if verification is None:
            verification_path = (
                self.run_root / "evidence" / "verification" / f"{task.task_id}.json"
            )
            if verification_path.is_file():
                verification = VerificationResult.from_dict(
                    load_canonical_json(verification_path.read_bytes())
                )
                self._verifications[task.task_id] = verification
        if verification is None or verification.result_digest != verification_result_digest:
            raise RuntimeError("DEMO_VERIFICATION_EVIDENCE_MISSING")
        capture = self._capture()
        if (
            task.execution_checkpoint_digest is None
            or capture.checkpoint is None
            or capture.checkpoint.checkpoint_digest != task.execution_checkpoint_digest
        ):
            raise SchedulerError("DEMO_REVIEW_CHECKPOINT_MISMATCH")
        review_path = self.run_root / "evidence" / "review" / f"{task.task_id}.json"
        if review_path.is_file():
            persisted = ReviewResult.from_dict(load_canonical_json(review_path.read_bytes()))
            if (
                persisted.project_id != task.project_id
                or persisted.task_id != task.task_id
                or persisted.task_generation != task.generation
                or persisted.attempt != task.attempt_count
                or persisted.controller_epoch != snapshot.project.controller_epoch
                or persisted.checkpoint_digest != task.execution_checkpoint_digest
                or persisted.verification_result_digest != verification_result_digest
            ):
                raise SchedulerError("DEMO_REVIEW_EVIDENCE_MISMATCH")
            return persisted
        dispatch = self._dispatch(snapshot, task, capture.checkpoint)
        request = ReviewController.build_request(
            board=snapshot,
            dispatch=dispatch,
            verification_result=verification,
            checkpoint=capture.checkpoint,
        )
        scenario = (
            SyntheticScenario.REVIEWER_FAIL
            if task.task_type is TaskType.REPAIR and task.generation == 2
            else SyntheticScenario.REVIEWER_PASS
        )
        runner = self._runner(
            profile=M4AProfile.INSPECT,
            worker="synthetic_worker.py",
            label=f"review-{task.generation}-{task.creation_sequence}",
        )
        reservation = create_containment_reservation(dispatch)
        builder = self._builder_identities.get(task.task_id)
        if builder is None:
            builder = self._recover_builder_identity(snapshot, task)
            self._builder_identities[task.task_id] = builder
        result = ReviewController().review(
            board=snapshot,
            request=request,
            verification_result=verification,
            checkpoint=capture.checkpoint,
            builder_identity=builder,
            adapter=SyntheticReviewerAdapter(
                f"reviewer-adapter-{task.generation}-{task.creation_sequence}",
                f"reviewer-session-{task.generation}-{task.creation_sequence}",
                scenario,
            ),
            runner=runner,
            reservation=reservation,
            workspace_manager=self.manager,
            repo_path=self.repo_path,
        )
        self._record_scope(runner.backend, reservation.scope_name)
        self._persist_json("review", task.task_id, result.to_dict())
        return result

    def finalize_project(self, snapshot: BoardSnapshot) -> FinalizationEvidence:
        first = self._capture()
        second = self._capture()
        checkpoint = first.checkpoint
        stable = checkpoint is not None and checkpoint == second.checkpoint
        lease = self.lease_ledger.recover()
        active = lease is not None and lease.state in {
            WorkspaceLeaseState.ACTIVE,
            WorkspaceLeaseState.EXECUTING,
            WorkspaceLeaseState.CANCELLING,
        }
        try:
            scope_root = self.run_root / "evidence" / "scopes"
            scope_names = tuple(
                load_canonical_json(path.read_bytes())["scope"]
                for path in sorted(scope_root.glob("*.json"))
            ) if scope_root.is_dir() else ()
            backend = SystemdScopeBackend()
            residue_free = all(
                backend.scope_evidence(scope).state.value == "ABSENT"
                for scope in scope_names
            )
        except (OSError, TypeError, ValueError, KeyError):
            residue_free = False
        return FinalizationEvidence(
            stable_checkpoint=stable,
            checkpoint_digest=checkpoint.checkpoint_digest if stable else None,
            active_execution=active,
            residue_free=residue_free,
        )

    def restart_controller(self) -> None:
        """Simulate process loss by rebuilding all controller objects from disk."""
        recovered = type(self).recover(self.run_root)
        self.__dict__.clear()
        self.__dict__.update(recovered.__dict__)

    def run(self, *, stop_after: str | None = None) -> SchedulerResult:
        (self.run_root / "stages").mkdir(exist_ok=True)
        return AutonomousScheduler(
            authority=self.authority,
            driver=self,
            limits=SchedulerLimits(max_steps=64),
            now_unix_ms=lambda: int(time.time() * 1000),
        ).run(stop_after=stop_after)
