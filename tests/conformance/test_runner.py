"""Tests for the runner contract and UnsafeLocalRunner.

UnsafeLocalRunner is NOT a security sandbox; these tests prove only that it
executes and captures processes correctly and reports attacks honestly.
"""

from __future__ import annotations

import inspect
import os
import sys
import time

import pytest

from agenticos.sandbox.models import AttackResult, ConformanceStatus, PolicyExpectation
from agenticos.sandbox.policy import default_policy, evaluate_result, evaluate_run
from agenticos.sandbox.runner import SandboxRunner, UnsafeLocalRunner
from helpers import WORKER_PATH, minimal_env, wait_for


@pytest.fixture
def runner():
    return UnsafeLocalRunner(worker_path=WORKER_PATH)


def test_runner_implements_contract(runner):
    assert isinstance(runner, SandboxRunner)
    assert runner.name == "unsafe-local"


def test_runner_never_uses_shell():
    source = inspect.getsource(UnsafeLocalRunner)
    assert "shell=True" not in source


def test_runner_rejects_missing_worker(tmp_path):
    with pytest.raises(FileNotFoundError):
        UnsafeLocalRunner(worker_path=tmp_path / "nope.py")


def test_stdout_stderr_captured_separately(runner, tmp_path):
    code = "import sys; print('to-stdout'); print('to-stderr', file=sys.stderr)"
    result = runner.run(
        [sys.executable, "-c", code], cwd=tmp_path, env=minimal_env()
    )
    assert result.exit_code == 0
    assert result.signal is None
    assert result.timed_out is False
    assert result.stdout.strip() == "to-stdout"
    assert result.stderr.strip() == "to-stderr"
    assert result.pid > 0
    assert result.started_at and result.finished_at
    assert result.argv[0] == sys.executable  # argv array, never a shell string


def test_explicit_cwd(runner, tmp_path):
    result = runner.run(
        [sys.executable, "-c", "import os; print(os.getcwd())"],
        cwd=tmp_path, env=minimal_env(),
    )
    assert os.path.normcase(result.stdout.strip()) == os.path.normcase(str(tmp_path))


def test_explicit_environment(runner, tmp_path):
    result = runner.run(
        [sys.executable, "-c", "import os; print(os.environ.get('AOS_TEST_VAR', 'MISSING'))"],
        cwd=tmp_path, env=minimal_env(AOS_TEST_VAR="synthetic-value"),
    )
    assert result.stdout.strip() == "synthetic-value"


def test_environment_is_not_inherited(runner, tmp_path, monkeypatch):
    monkeypatch.setenv("AOS_MUST_NOT_LEAK", "real-host-value")
    result = runner.run(
        [sys.executable, "-c", "import os; print(os.environ.get('AOS_MUST_NOT_LEAK', 'absent'))"],
        cwd=tmp_path, env=minimal_env(),  # explicit env without the marker
    )
    assert result.stdout.strip() == "absent"


def test_timeout_kills_process(runner, tmp_path):
    result = runner.run(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        cwd=tmp_path, env=minimal_env(), timeout=0.5,
    )
    assert result.timed_out is True
    assert result.exit_code != 0  # killed, not a clean exit


def test_timeout_kills_whole_tree(runner, tmp_path):
    """A grandchild spawned by a timed-out child must not survive the kill."""
    heartbeat = tmp_path / "tree-heartbeat.txt"
    grandchild = (
        "import time, sys\n"
        "path = sys.argv[1]\n"
        "end = time.time() + 60\n"
        "while time.time() < end:\n"
        "    with open(path, 'w') as f: f.write(str(time.time()))\n"
        "    time.sleep(0.2)\n"
    )
    parent = (
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}, sys.argv[1]])\n"
        "time.sleep(60)\n"
    )
    result = runner.run(
        [sys.executable, "-c", parent, str(heartbeat)],
        cwd=tmp_path, env=minimal_env(), timeout=2.0,
    )
    assert result.timed_out is True
    assert wait_for(heartbeat.exists, timeout=5.0), "grandchild never started"
    last = heartbeat.read_text()
    time.sleep(0.8)
    assert heartbeat.read_text() == last, "grandchild survived the tree kill"


def test_run_scenario_parses_json(runner, layout, fixture_env):
    result = runner.run_scenario(
        "FS-01",
        cwd=layout.assigned_worktree,
        env=fixture_env,
        target=layout.allowed_file,
    )
    assert isinstance(result, AttackResult)
    assert result.scenario_id == "FS-01"
    assert result.attempted is True
    assert result.succeeded is True
    assert result.details["canary"] == layout.canaries["permitted"]
    # The runner attaches the process record for evidence purposes.
    assert result.process is not None
    assert result.process.exit_code == 0
    if os.name != "nt":
        assert result.process.process_group_id is not None


def test_run_scenario_parse_failure_is_runner_error(runner, tmp_path, monkeypatch):
    # Point the runner at a "worker" that emits garbage instead of JSON.
    fake_worker = tmp_path / "fake_worker.py"
    fake_worker.write_text("print('this is not json')\n")
    bad_runner = UnsafeLocalRunner(worker_path=fake_worker)
    result = bad_runner.run_scenario(
        "FS-01", cwd=tmp_path, env=minimal_env(), target=tmp_path
    )
    assert result.error_type == "RunnerError"
    assert result.attempted is False
    assert result.succeeded is False


def test_policy_evaluation_unsafe_baseline(runner, layout, fixture_env):
    """The honesty property: DENY scenarios FAIL under the unsafe runner.

    FS-02 is expected-DENY; the unsandboxed host lets the read succeed, so
    conformance must report FAIL. FS-01 is expected-ALLOW and must PASS.
    """
    policy = default_policy()
    fs01 = runner.run_scenario(
        "FS-01", cwd=layout.assigned_worktree, env=fixture_env,
        target=layout.allowed_file,
    )
    fs02 = runner.run_scenario(
        "FS-02", cwd=layout.assigned_worktree, env=fixture_env,
        target=layout.denied_sibling_file,
    )
    assert evaluate_result(fs01, PolicyExpectation.ALLOW) is ConformanceStatus.PASS
    assert evaluate_result(fs02, PolicyExpectation.DENY) is ConformanceStatus.FAIL

    run = evaluate_run([fs01, fs02], policy, runner_name=runner.name)
    assert run.conformance["FS-01"] == "PASS"
    assert run.conformance["FS-02"] == "FAIL"
    assert run.passed is False
    assert run.status_counts() == {"PASS": 1, "FAIL": 1}


def test_policy_evaluation_future_sandbox_shape():
    """A denied read that FAILS (as a real sandbox would cause) must PASS."""
    denied_and_blocked = AttackResult(
        scenario_id="FS-02",
        attempted=True,
        succeeded=False,
        error_type="PermissionError",
        error_message="[Errno 13] Permission denied",
    )
    assert (
        evaluate_result(denied_and_blocked, PolicyExpectation.DENY)
        is ConformanceStatus.PASS
    )


def test_require_approval_is_unsupported():
    result = AttackResult(scenario_id="X-01", attempted=True, succeeded=True)
    assert (
        evaluate_result(result, PolicyExpectation.REQUIRE_APPROVAL)
        is ConformanceStatus.UNSUPPORTED
    )
