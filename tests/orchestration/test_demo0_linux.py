"""Native Linux acceptance for the complete synthetic autonomous loop."""

from __future__ import annotations

import sys
import subprocess
import os
from pathlib import Path

import pytest

from agenticos.orchestration.demo0 import Demo0Runtime
from agenticos.orchestration.models import ProjectStatus, TaskStatus, TaskType
from agenticos.sandbox.containment import CgroupProcessRunner
from agenticos.sandbox.isolation import probe_landlock_enforcement
from agenticos.sandbox.runtime_boundary import probe_bubblewrap


pytestmark = [
    pytest.mark.m4a_linux,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux M4A boundary"),
]


@pytest.fixture(scope="module", autouse=True)
def demo0_host_boundary() -> None:
    support = CgroupProcessRunner.probe()
    if not support.supported:
        pytest.skip("transient scopes unavailable: " + "; ".join(support.reasons))
    landlock_ok, reason = probe_landlock_enforcement()
    if not landlock_ok:
        pytest.skip(f"Landlock enforcement unavailable: {reason}")
    bwrap = probe_bubblewrap()
    if not bwrap.supported:
        pytest.fail("required Bubblewrap boundary unavailable: " + "; ".join(bwrap.reasons))


def test_DEMO_0_SYNTHETIC_AUTONOMOUS_LOOP(tmp_path) -> None:
    runtime = Demo0Runtime.create(
        tmp_path / "demo0",
        goal="Add the requested feature to the fixture application.",
    )
    result = runtime.run()

    assert result.snapshot.project.status is ProjectStatus.DONE
    assert all(item.status is TaskStatus.DONE for item in result.snapshot.tasks)
    assert len([item for item in result.snapshot.tasks if item.task_type is TaskType.REPAIR]) == 2
    feature = result.snapshot.task("task-000003")
    follow_up = result.snapshot.task("task-000004")
    assert feature.satisfying_descendant_id is not None
    assert follow_up.dependencies == (feature.task_id,)
    assert (runtime.worktree_path / "feature.txt").read_bytes() == b"fixed\n"
    assert (runtime.worktree_path / "review-remediation.txt").read_bytes() == b"resolved\n"
    assert (runtime.worktree_path / "follow-up.txt").read_bytes() == b"dependent work complete\n"

    kinds = [event.kind for event in result.events]
    assert kinds.count("REPAIR_CREATED") == 2
    assert kinds.count("VERIFY_FAILED") == 1
    assert kinds.count("REVIEW_BLOCKED") == 1
    assert kinds[-1] == "PROJECT_DONE"
    assert result.final_checkpoint_digest is not None
    assert runtime.finalize_project(result.snapshot).residue_free


def test_demo0_controller_restart_continues_from_authoritative_journal(tmp_path) -> None:
    runtime = Demo0Runtime.create(tmp_path / "recovery")

    researched = runtime.run(stop_after="RESEARCH_COMPLETED")
    assert researched.snapshot.task("bootstrap-research").status is TaskStatus.DONE
    runtime.restart_controller()

    planned = runtime.run(stop_after="PLAN_COMPLETED")
    assert planned.snapshot.project.status is ProjectStatus.ACTIVE
    runtime.restart_controller()

    built = runtime.run(stop_after="BUILD_COMPLETED")
    assert built.snapshot.task("task-000003").status is TaskStatus.VERIFYING
    runtime.restart_controller()

    first_repair = runtime.run(stop_after="REPAIR_CREATED")
    assert len([item for item in first_repair.snapshot.tasks if item.task_type is TaskType.REPAIR]) == 1
    runtime.restart_controller()

    first_repair_built = runtime.run(stop_after="BUILD_COMPLETED")
    repair_one = [item for item in first_repair_built.snapshot.tasks if item.task_type is TaskType.REPAIR][0]
    assert repair_one.status is TaskStatus.VERIFYING
    runtime.restart_controller()

    second_repair = runtime.run(stop_after="REPAIR_CREATED")
    assert len([item for item in second_repair.snapshot.tasks if item.task_type is TaskType.REPAIR]) == 2
    runtime.restart_controller()

    second_repair_built = runtime.run(stop_after="BUILD_COMPLETED")
    assert len([item for item in second_repair_built.snapshot.tasks if item.status is TaskStatus.VERIFYING]) == 1
    runtime.restart_controller()

    repaired = runtime.run(stop_after="REVIEW_PASSED")
    assert repaired.snapshot.task("task-000003").status is TaskStatus.DONE
    runtime.restart_controller()

    dependent_reviewed = runtime.run(stop_after="REVIEW_PASSED")
    assert dependent_reviewed.snapshot.task("task-000004").status is TaskStatus.DONE
    assert dependent_reviewed.snapshot.project.status is ProjectStatus.ACTIVE
    runtime.restart_controller()

    completed = runtime.run()
    assert completed.snapshot.project.status is ProjectStatus.DONE
    assert all(item.attempt_count == 1 for item in completed.snapshot.tasks)
    assert len([item for item in completed.snapshot.tasks if item.task_type is TaskType.REPAIR]) == 2
    assert runtime.finalize_project(completed.snapshot).residue_free


def test_demo0_restart_after_terminal_execution_reuses_receipt_without_redispatch(tmp_path) -> None:
    runtime = Demo0Runtime.create(tmp_path / "receipt-recovery")
    for _ in range(3):
        paused = runtime.run(stop_after="TASK_STARTED")
    task = paused.snapshot.task("task-000003")
    assert task.status is TaskStatus.IN_PROGRESS

    terminal = runtime.run_execution(paused.snapshot, task)
    assert terminal.checkpoint_digest is not None
    execution_root = runtime.run_root / "executions" / task.task_id
    dispatch_roots = tuple(execution_root.glob("execution-*"))
    assert len(dispatch_roots) == 1

    runtime.restart_controller()
    resumed = runtime.run(stop_after="BUILD_COMPLETED")
    assert resumed.snapshot.task(task.task_id).status is TaskStatus.VERIFYING
    assert len(tuple(execution_root.glob("execution-*"))) == 1
    assert runtime.finalize_project(resumed.snapshot).residue_free


def test_demo0_rejects_workspace_change_after_accepted_build_checkpoint(tmp_path) -> None:
    runtime = Demo0Runtime.create(tmp_path / "checkpoint-tamper")
    built = runtime.run(stop_after="BUILD_COMPLETED")
    task = built.snapshot.task("task-000003")
    assert task.execution_checkpoint_digest is not None
    (runtime.worktree_path / "feature.txt").write_bytes(b"tampered-after-build\n")

    runtime.restart_controller()
    rejected = runtime.run()
    assert rejected.snapshot.project.status is ProjectStatus.FAILED
    assert rejected.snapshot.task(task.task_id).status is TaskStatus.FAILED
    assert not (runtime.run_root / "evidence" / "verification" / f"{task.task_id}.json").exists()
    assert not any(event.kind.startswith("REVIEW_") for event in rejected.events)
    assert runtime.finalize_project(rejected.snapshot).residue_free


def test_demo0_reuses_persisted_verification_and_review_after_controller_crash(tmp_path) -> None:
    runtime = Demo0Runtime.create(tmp_path / "readonly-recovery")
    built = runtime.run(stop_after="BUILD_COMPLETED")
    feature = built.snapshot.task("task-000003")
    verification = runtime.run_verification(built.snapshot, feature)
    scope_root = runtime.run_root / "evidence" / "scopes"
    scopes_after_verification = len(tuple(scope_root.glob("*.json")))

    runtime.restart_controller()
    first_repair = runtime.run(stop_after="REPAIR_CREATED")
    assert len([task for task in first_repair.snapshot.tasks if task.task_type is TaskType.REPAIR]) == 1
    assert len(tuple(scope_root.glob("*.json"))) == scopes_after_verification

    repair_built = runtime.run(stop_after="BUILD_COMPLETED")
    repair = next(
        task for task in repair_built.snapshot.tasks
        if task.task_type is TaskType.REPAIR and task.status is TaskStatus.VERIFYING
    )
    review_ready = runtime.run(stop_after="VERIFY_PASSED")
    repair = review_ready.snapshot.task(repair.task_id)
    review = runtime.run_review(
        review_ready.snapshot,
        repair,
        repair.verification_result_digest,
    )
    assert review.classification.value == "BLOCKING"
    scopes_after_review = len(tuple(scope_root.glob("*.json")))

    runtime.restart_controller()
    second_repair = runtime.run(stop_after="REPAIR_CREATED")
    assert len([task for task in second_repair.snapshot.tasks if task.task_type is TaskType.REPAIR]) == 2
    assert len(tuple(scope_root.glob("*.json"))) == scopes_after_review
    assert runtime.finalize_project(second_repair.snapshot).residue_free


def test_demo0_rejects_workspace_change_before_persisted_pass_review_replay(tmp_path) -> None:
    runtime = Demo0Runtime.create(tmp_path / "persisted-pass-tamper")
    repaired = runtime.run(stop_after="REVIEW_PASSED")
    assert repaired.snapshot.task("task-000003").status is TaskStatus.DONE
    dependent_built = runtime.run(stop_after="BUILD_COMPLETED")
    dependent = dependent_built.snapshot.task("task-000004")
    review_ready = runtime.run(stop_after="VERIFY_PASSED")
    dependent = review_ready.snapshot.task(dependent.task_id)
    persisted = runtime.run_review(
        review_ready.snapshot,
        dependent,
        dependent.verification_result_digest,
    )
    assert persisted.classification.value == "PASS"
    (runtime.worktree_path / "follow-up.txt").write_bytes(b"changed-after-review\n")

    runtime.restart_controller()
    rejected = runtime.run()
    assert rejected.snapshot.project.status is ProjectStatus.FAILED
    assert rejected.snapshot.task(dependent.task_id).status is TaskStatus.FAILED
    assert not any(event.kind == "REVIEW_PASSED" for event in rejected.events)
    assert not any(event.kind == "PROJECT_DONE" for event in rejected.events)
    assert runtime.finalize_project(rejected.snapshot).residue_free


def test_demo0_repeated_independent_runs_have_equivalent_logical_outcomes(tmp_path) -> None:
    outcomes = []
    for label in ("repeat-a", "repeat-b"):
        runtime = Demo0Runtime.create(tmp_path / label)
        result = runtime.run()
        outcomes.append((
            tuple(event.kind for event in result.events),
            tuple(
                (task.task_type.value, task.status.value, len(task.dependencies), task.generation)
                for task in result.snapshot.tasks
            ),
            result.snapshot.project.status,
        ))
        assert runtime.finalize_project(result.snapshot).residue_free
    assert outcomes[0] == outcomes[1]


def test_demo0_one_command_cli_repeats_logical_outcome(tmp_path) -> None:
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "agenticos.orchestration.cli",
            "demo0",
            "--run-root",
            str(tmp_path / "cli-run"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
        text=True,
        env={
            **os.environ,
            "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src"),
        },
    )
    assert process.returncode == 0, process.stderr
    assert "Research completed" in process.stdout
    assert process.stdout.count("automatically created") == 2
    assert "REVIEW blocked" in process.stdout
    assert "PROJECT DONE" in process.stdout
    assert "Project status: DONE" in process.stdout
    assert "Final checkpoint:" in process.stdout
