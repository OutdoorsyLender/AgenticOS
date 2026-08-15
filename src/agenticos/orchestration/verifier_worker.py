#!/usr/bin/env python3
"""Fixed deterministic verifier fixtures for the M4A L1 `/workspace` ABI."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

WORKSPACE = Path("/workspace")


def _denied(action) -> int:
    try:
        action()
    except (OSError, PermissionError):
        sys.stderr.write("read-only policy denied the fixed adversarial action\n")
        return 73
    sys.stderr.write("read-only policy unexpectedly allowed the fixed adversarial action\n")
    return 74


def run(scenario: str, workspace: Path = WORKSPACE) -> int:
    if scenario == "PASS":
        print("deterministic verifier pass")
        return 0
    if scenario == "FAIL":
        sys.stderr.write("deterministic semantic failure\n")
        return 1
    if scenario == "CHECK_FEATURE":
        try:
            content = (workspace / "feature.txt").read_bytes()
        except OSError:
            sys.stderr.write("feature.txt is missing or unreadable\n")
            return 1
        if content == b"fixed\n":
            print("feature fixture satisfies controller policy")
            return 0
        sys.stderr.write("feature fixture does not satisfy controller policy\n")
        return 1
    if scenario == "INFRA_ERROR":
        sys.stderr.write("deterministic verifier infrastructure error\n")
        return 70
    if scenario == "TIMEOUT":
        time.sleep(86_400)
        return 70
    if scenario == "OVERSIZED":
        sys.stdout.write("x" * 2_000_000)
        return 0
    if scenario == "MUTATE_CREATE":
        return _denied(lambda: (workspace / "verifier-created.txt").write_text("forbidden\n"))
    if scenario == "MUTATE_WRITE":
        return _denied(lambda: (workspace / "feature.txt").write_text("forbidden\n"))
    if scenario == "MUTATE_RENAME":
        return _denied(lambda: (workspace / "feature.txt").rename(workspace / "renamed.txt"))
    if scenario == "MUTATE_DELETE":
        return _denied(lambda: (workspace / "feature.txt").unlink())
    if scenario == "DOT_GIT_ACCESS":
        return _denied(lambda: (workspace / ".git" / "config").read_bytes())
    if scenario == "HOST_ACCESS":
        return _denied(lambda: Path("/agenticos-host-sentinel").read_bytes())
    if scenario == "CONTROLLER_ACCESS":
        return _denied(lambda: Path("/controller-state/board.json").read_bytes())
    if scenario == "CREDENTIAL_ACCESS":
        return _denied(lambda: Path("/provider-credentials/sentinel").read_bytes())
    sys.stderr.write("unknown fixed verifier scenario\n")
    return 70


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True)
    args = parser.parse_args()
    return run(args.scenario)


if __name__ == "__main__":
    raise SystemExit(main())
