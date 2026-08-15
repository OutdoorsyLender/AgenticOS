"""Minimal presentation-only command for deterministic Demo 0."""

from __future__ import annotations

import argparse
from pathlib import Path
import tempfile

from .demo0 import DEMO_GOAL, Demo0Runtime
from .models import ProjectStatus, TaskStatus
from .scheduler import SchedulerResult

MAX_STATUS_BYTES = 16_384


def render_status(result: SchedulerResult) -> str:
    """Render bounded presentation from the final authoritative snapshot."""
    snapshot = result.snapshot
    counts = {
        status: sum(item.status is status for item in snapshot.tasks)
        for status in TaskStatus
    }
    lines = [f"Project: {snapshot.project.project_id}", ""]
    for status in TaskStatus:
        lines.append(f"{status.value:<12} {counts[status]}")
    lines.extend(
        [
            "",
            f"Project status: {snapshot.project.status.value}",
            f"Board revision: {snapshot.revision}",
            f"Evidence head: {snapshot.project.transition_digest}",
            f"Final checkpoint: {result.final_checkpoint_digest or 'UNAVAILABLE'}",
            f"Scheduler steps: {result.steps}",
        ]
    )
    rendered = "\n".join(lines) + "\n"
    if len(rendered.encode("utf-8")) > MAX_STATUS_BYTES:
        raise RuntimeError("STATUS_OUTPUT_LIMIT_EXCEEDED")
    return rendered


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agenticos-demo")
    subcommands = parser.add_subparsers(dest="command", required=True)
    demo = subcommands.add_parser("demo0", help="run the deterministic synthetic autonomous loop")
    demo.add_argument("--run-root", type=Path)
    demo.add_argument("--goal", default=DEMO_GOAL)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command != "demo0":
        return 2
    run_root = args.run_root
    if run_root is None:
        parent = Path(tempfile.mkdtemp(prefix="agenticos-demo0-"))
        run_root = parent / "run"
    runtime = Demo0Runtime.create(run_root, goal=args.goal)
    result = runtime.run()
    for event in result.events:
        print(event.message)
    print(render_status(result), end="")
    print(f"Run root: {runtime.run_root}")
    return 0 if result.snapshot.project.status is ProjectStatus.DONE else 1


if __name__ == "__main__":
    raise SystemExit(main())
