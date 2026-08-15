#!/usr/bin/python3
"""Owner-only entry point for the F1 Kimi membership login ceremony."""

from __future__ import annotations

from pathlib import Path
import sys


REPOSITORY = Path("/home/brand/src/AgenticOS")
if Path(__file__).resolve() != REPOSITORY / "scripts" / "run_kimi_owner_login.py":
    raise SystemExit("F1_KIMI_LOGIN_CEREMONY_ERROR=SCRIPT_IDENTITY")
sys.path.insert(0, str(REPOSITORY / "src"))

from agenticos.providers.kimi_login import cli_main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(cli_main())
