#!/usr/bin/env python3
"""Standalone deterministic Slice C worker mounted read-only at the M4A ABI."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

MAX_REQUEST_BYTES = 1_048_576
WORKSPACE = Path("/workspace")


def _canonical_line(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _event(identity: dict, sequence: int, kind: str, text: str) -> bytes:
    return _canonical_line(
        {
            "schema": "AOSAGENT/1",
            "identity": identity,
            "sequence": sequence,
            "kind": kind,
            "payload": {"text": text, "evidence_refs": []},
        }
    )


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="\n")


def _scenario_action(scenario: str, workspace: Path) -> tuple[str, str]:
    if scenario == "BROKEN_FEATURE_EDIT":
        _write(workspace / "feature.txt", "broken\n")
        return "SUCCEEDED", "Deterministic broken candidate completed."
    if scenario == "REPAIR_FEATURE":
        _write(workspace / "feature.txt", "fixed\n")
        return "SUCCEEDED", "Deterministic feature repair completed."
    if scenario == "REPAIR_REVIEW":
        _write(workspace / "review-remediation.txt", "resolved\n")
        return "SUCCEEDED", "Deterministic review remediation completed."
    if scenario == "SUCCESSFUL_EDIT":
        _write(workspace / "slice-c-tracked.txt", "slice-c deterministic tracked edit\n")
        _write(workspace / "slice-c-created.txt", "slice-c deterministic untracked file\n")
        return "SUCCEEDED", "Deterministic workspace edit completed."
    if scenario == "FOLLOW_UP_EDIT":
        _write(workspace / "follow-up.txt", "dependent work complete\n")
        return "SUCCEEDED", "Deterministic dependent follow-up completed."
    if scenario == "NO_OP":
        return "NO_OP", "Deterministic no-op completed."
    if scenario == "INVALID_PATH_ATTEMPT":
        try:
            _write(Path("/agenticos-invalid-path"), "must remain contained\n")
        except OSError:
            return "SUCCEEDED", "Invalid path write was denied."
        return "TERMINAL_FAILURE", "Invalid path write unexpectedly succeeded."
    if scenario == "DOT_GIT_ATTEMPT":
        try:
            _write(workspace / ".git" / "config", "must not mutate git authority\n")
        except OSError:
            return "SUCCEEDED", "Git metadata write was denied."
        return "TERMINAL_FAILURE", "Git metadata write unexpectedly succeeded."
    if scenario == "CRASH_AFTER_EDIT":
        _write(workspace / "slice-c-tracked.txt", "slice-c edit before crash\n")
        return "CRASH", "Synthetic crash follows edit."
    if scenario == "TIMEOUT_AFTER_EDIT":
        _write(workspace / "slice-c-tracked.txt", "slice-c edit before timeout\n")
        return "TIMEOUT", "Synthetic timeout follows edit."
    if scenario == "CHILD_PROCESS_CASE":
        target = workspace / "slice-c-child.txt"
        subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; from pathlib import Path; "
                "Path(sys.argv[1]).write_bytes("
                "b'slice-c deterministic child edit\\n')",
                str(target),
            ],
            check=True,
            timeout=5.0,
        )
        return "SUCCEEDED", "Contained child completed deterministic edit."
    if scenario == "POST_TERMINAL_MUTATION_ATTEMPT":
        target = workspace / "slice-c-post-terminal.txt"
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import sys, time; from pathlib import Path; time.sleep(0.05); "
                "Path(sys.argv[1]).write_bytes("
                "b'captured before controller terminal\\n')",
                str(target),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        return "SUCCEEDED", "Terminal claim emitted before contained child attempt."
    return "TERMINAL_FAILURE", "Unknown synthetic scenario."


def _reviewer_attack_denied(scenario: str, workspace: Path) -> bool:
    actions = {
        "REVIEWER_MUTATE_CREATE": lambda: _write(
            workspace / "reviewer-created.txt", "forbidden\n"
        ),
        "REVIEWER_MUTATE_WRITE": lambda: _write(
            workspace / "feature.txt", "forbidden\n"
        ),
        "REVIEWER_MUTATE_RENAME": lambda: (workspace / "feature.txt").rename(
            workspace / "reviewer-renamed.txt"
        ),
        "REVIEWER_MUTATE_DELETE": lambda: (workspace / "feature.txt").unlink(),
        "REVIEWER_DOT_GIT_ACCESS": lambda: (workspace / ".git" / "config").read_bytes(),
        "REVIEWER_HOST_ACCESS": lambda: Path("/agenticos-host-sentinel").read_bytes(),
        "REVIEWER_CONTROLLER_ACCESS": lambda: Path(
            "/controller-state/board.json"
        ).read_bytes(),
        "REVIEWER_CREDENTIAL_ACCESS": lambda: Path(
            "/provider-credentials/sentinel"
        ).read_bytes(),
    }
    action = actions.get(scenario)
    if action is None:
        return True
    try:
        action()
    except (OSError, PermissionError):
        return True
    return False


def run(request: dict, scenario: str, workspace: Path = WORKSPACE) -> int:
    identity = request["identity"]
    events = [_event(identity, 1, "STARTED", "Synthetic Slice C worker started.")]
    if scenario.startswith("REVIEWER_"):
        attack_denied = _reviewer_attack_denied(scenario, workspace)
        proposal = {
            "schema": "AOSREVIEW/1",
            "verdict": "PASS" if scenario == "REVIEWER_PASS" else "BLOCKING",
            "findings": [] if scenario != "REVIEWER_FAIL" else [
                {"code": "SYNTHETIC_FINDING", "message": "Repair the deterministic fixture."}
            ],
            "repair_recommendation": None if scenario != "REVIEWER_FAIL" else "Apply the bounded repair.",
            "evidence_refs": [],
        }
        if scenario != "REVIEWER_FAIL":
            proposal["verdict"] = "PASS"
        events.append(
            _event(
                identity,
                2,
                "PROPOSAL",
                json.dumps(proposal, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")),
            )
        )
        for event in events:
            sys.stdout.buffer.write(event)
        terminal_kind = "SUCCEEDED" if attack_denied else "TERMINAL_FAILURE"
        terminal = _event(identity, 3, terminal_kind, "Synthetic reviewer terminated.")
        events.append(terminal)
        sys.stdout.buffer.write(terminal)
        stream = b"".join(events)
        result = {
            "schema": "AOSAGENT/1",
            "identity": identity,
            "status": terminal_kind,
            "exit_class": "SUCCESS" if terminal_kind == "SUCCEEDED" else "TERMINAL",
            "event_count": len(events),
            "byte_count": len(stream),
            "stream_digest": hashlib.sha256(stream).hexdigest(),
            "evidence_refs": [],
            "workspace_handoff_ref": None,
            "usage": None,
            "retryability": "NOT_RETRYABLE",
        }
        sys.stdout.buffer.write(_canonical_line(result))
        sys.stdout.buffer.flush()
        return 0
    kind, text = _scenario_action(scenario, workspace)
    events.append(_event(identity, 2, "PROGRESS", text))
    for event in events:
        sys.stdout.buffer.write(event)
    sys.stdout.buffer.flush()
    if kind == "CRASH":
        os._exit(17)
    if kind == "TIMEOUT":
        time.sleep(86_400)
        return 19

    terminal = _event(identity, 3, kind, "Synthetic Slice C worker terminated.")
    events.append(terminal)
    sys.stdout.buffer.write(terminal)
    stream = b"".join(events)
    exit_class = {
        "SUCCEEDED": "SUCCESS",
        "NO_OP": "NO_OP",
        "TERMINAL_FAILURE": "TERMINAL",
    }[kind]
    result = {
        "schema": "AOSAGENT/1",
        "identity": identity,
        "status": kind,
        "exit_class": exit_class,
        "event_count": len(events),
        "byte_count": len(stream),
        "stream_digest": hashlib.sha256(stream).hexdigest(),
        "evidence_refs": [],
        "workspace_handoff_ref": None,
        "usage": None,
        "retryability": "NOT_RETRYABLE",
    }
    sys.stdout.buffer.write(_canonical_line(result))
    sys.stdout.buffer.flush()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--request-base64", required=True)
    args = parser.parse_args()
    try:
        raw = base64.b64decode(
            args.request_base64.encode("ascii"), altchars=b"-_", validate=True
        )
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("request exceeds byte bound")
        request = json.loads(raw.decode("utf-8", errors="strict"))
        if type(request) is not dict or request.get("schema") != "AOSAGENT/1":
            raise ValueError("invalid request")
    except (UnicodeError, ValueError, json.JSONDecodeError):
        return 2
    return run(request, args.scenario)


if __name__ == "__main__":
    raise SystemExit(main())
