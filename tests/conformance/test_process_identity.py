"""Tests for stable process identity (PID + start time + boot id)."""

from __future__ import annotations

import os
import sys

import pytest

from agenticos.sandbox.models import (
    ProcessIdentity,
    parse_stat_start_time,
    read_boot_id,
)
from agenticos.sandbox.runner import UnsafeLocalRunner
from helpers import WORKER_PATH, minimal_env


def test_parse_stat_start_time_simple():
    # field 3 (state) is index 0 after comm; field 22 (starttime) is index 19.
    fields = ["S"] + ["0"] * 18 + ["424242"] + ["9"] * 10
    stat = "1234 (python) " + " ".join(fields) + "\n"
    assert parse_stat_start_time(stat) == 424242


def test_parse_stat_start_time_comm_with_spaces_and_parens():
    fields = ["S"] + ["0"] * 18 + ["777"] + ["9"] * 3
    stat = "4321 (weird ) name) " + " ".join(fields) + "\n"
    assert parse_stat_start_time(stat) == 777


def test_parse_stat_start_time_garbage():
    assert parse_stat_start_time("not a stat line") is None
    assert parse_stat_start_time("") is None


def test_identity_of_current_process():
    identity = ProcessIdentity.from_pid(os.getpid())
    assert identity.pid == os.getpid()
    if sys.platform.startswith("linux"):
        assert identity.start_time_ticks is not None
        assert identity.boot_id is not None
        assert identity.process_group_id is not None
        assert identity.matches_current() is True
    else:
        # No procfs: identity degrades to PID-only, never fabricated.
        assert identity.start_time_ticks is None
        assert identity.boot_id is None


def test_identity_detects_pid_reuse(tmp_path):
    """Same PID, different start time => NOT the same process."""
    proc_dir = tmp_path / "proc"
    (proc_dir / "1234").mkdir(parents=True)
    fields = ["S"] + ["0"] * 18 + ["100"] + ["9"] * 3
    (proc_dir / "1234" / "stat").write_text("1234 (python) " + " ".join(fields))
    identity = ProcessIdentity(pid=1234, start_time_ticks=999, boot_id="boot-x")
    assert identity.matches_current(proc_root=proc_dir) is False
    identity_same = ProcessIdentity(pid=1234, start_time_ticks=100, boot_id=None)
    # boot id unreadable in fixture -> both None -> compares start time only
    assert identity_same.matches_current(proc_root=proc_dir) is True


def test_identity_of_dead_process_does_not_match():
    identity = ProcessIdentity(pid=2**22, start_time_ticks=1, boot_id=None)
    assert identity.matches_current() is False


def test_runner_attaches_identity(tmp_path):
    runner = UnsafeLocalRunner(worker_path=WORKER_PATH)
    result = runner.run(
        [sys.executable, "-c", "print('ok')"], cwd=tmp_path, env=minimal_env()
    )
    assert result.identity is not None
    assert result.identity.pid == result.pid
    if sys.platform.startswith("linux"):
        assert result.identity.start_time_ticks is not None
