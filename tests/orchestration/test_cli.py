from __future__ import annotations

from dataclasses import replace

from agenticos.orchestration.board import BoardSnapshot
from agenticos.orchestration.cli import render_status
from agenticos.orchestration.models import ProjectStatus, TaskStatus, TerminalReason
from agenticos.orchestration.scheduler import SchedulerEvent, SchedulerResult
from tests.orchestration.test_models import project, task


def test_status_view_is_bounded_and_derived_from_authoritative_snapshot() -> None:
    done_project = replace(
        project(),
        status=ProjectStatus.DONE,
        terminal_reason=TerminalReason.COMPLETED,
        final_checkpoint_digest="c" * 64,
        finalization_evidence_digest="e" * 64,
    )
    done_task = task(
        status=TaskStatus.DONE,
        terminal_reason=TerminalReason.COMPLETED,
    )
    result = SchedulerResult(
        BoardSnapshot.create(done_project, (done_task,)),
        (SchedulerEvent(1, "PROJECT_DONE", None, "PROJECT DONE"),),
        9,
        "a" * 64,
    )
    output = render_status(result)
    assert "Project: project-1" in output
    assert "DONE         1" in output
    assert "Project status: DONE" in output
    assert "Final checkpoint: " + "a" * 64 in output
    assert len(output.encode("utf-8")) < 16_384
