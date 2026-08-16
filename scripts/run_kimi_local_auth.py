#!/usr/bin/python3
"""Fixed entry point for the conditional one-shot Kimi Level-1 attempt."""

from __future__ import annotations

from pathlib import Path
import sys


REPOSITORY = Path("/home/brand/src/AgenticOS")
EXPECTED_SCRIPT = REPOSITORY / "scripts" / "run_kimi_local_auth.py"
if Path(__file__).resolve() != EXPECTED_SCRIPT:
    print("F1_KIMI_LEVEL1_LOCAL_AUTH_ERROR=SCRIPT_IDENTITY")
    raise SystemExit(2)
sys.path.insert(0, str(REPOSITORY / "src"))

from agenticos.providers.kimi_local_auth_runtime import cli_main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(cli_main())
