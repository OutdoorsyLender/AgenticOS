"""Integration tests for CgroupProcessRunner against a REAL host.

These run only on Linux with cgroup v2 + systemd user scopes (e.g. Ubuntu
under WSL2 with systemd enabled). They never fake capability: if the probe
fails, every test here skips with the concrete reason.

Run inside WSL Ubuntu:
    cd ~/src/AgenticOS && python3 -m pytest tests/conformance/test_cgroup_integration.py -v
"""

from __future__ import annotations

import sys
import time

import pytest

from agenticos.sandbox.containment import (
    CgroupProcessRunner,
    CancellationConfig,
    ContainmentState,
    EV_CGROUP_EMPTY_VERIFIED,
    EV_CONTAINMENT_CREATED,
    EV_CONTAINMENT_DESTROYED,
    EV_FORCED_KILL_REQUESTED,
    EV_PROCESS_STARTED,
    EV_SIGNAL_SENT,
)
from agenticos.sandbox.evidence import EvidenceCollector
from helpers import (
    WORKER_PATH,
    kill_pid,
    minimal_env,
    pid_alive,
    tcp_fixture_server,
    wait_for,
)

pytestmark = pytest.mark.cgroup_linux

FAST_CANCEL = CancellationConfig(
    sigint_grace=0.5, sigterm_grace=0.5,
    empty_verify_timeout=5.0, poll_interval=0.05,
)


@pytest.fixture(scope="session")
def cgroup_support():
    if not sys.platform.startswith("linux"):
        pytest.skip("requires a Linux host")
    support = CgroupProcessRunner.probe()
    if not support.supported:
        pytest.skip("transient systemd user scopes unavailable: "
                    + "; ".join(support.reasons))
    return support


@pytest.fixture
def crunner(layout, cgroup_support):
    collector = EvidenceCollector(normalize_root=layout.root)
    runner = CgroupProcessRunner(
        WORKER_PATH, collector=collector, cancellation=FAST_CANCEL,
    )
    support = runner.check_support()
    if not support.supported:
        pytest.skip("cgroup containment unsupported: " + "; ".join(support.reasons))
    return runner, collector


def event_kinds(collector):
    return [r.kind for r in collector.records]


def assert_no_aos_units(backend):
    proc = backend._ctl(["list-units", "aos-*", "--all", "--no-legend"])
    assert not proc.stdout.strip(), f"leftover AgenticOS units: {proc.stdout!r}"


# --------------------------------------------------------------------------
# Support / gating
# --------------------------------------------------------------------------

def test_probe_reports_support(cgroup_support):
    assert cgroup_support.supported is True
    assert cgroup_support.reasons


def test_capability_report_on_integration_host(cgroup_support):
    from agenticos.sandbox.capabilities import CapabilityStatus, HostCapabilityDetector

    report = HostCapabilityDetector().detect()
    assert report.status_of("host_platform_linux") is CapabilityStatus.SUPPORTED
    assert report.status_of("cgroup_v2_mounted") is CapabilityStatus.SUPPORTED
    assert report.status_of("cgroup_events_available") is CapabilityStatus.SUPPORTED
    assert report.status_of("systemd_running") is CapabilityStatus.SUPPORTED


# --------------------------------------------------------------------------
# Containment behavior
# --------------------------------------------------------------------------

def test_normal_completion(crunner, layout, fixture_env):
    runner, collector = crunner
    result = runner.run(
        [sys.executable, "-c", "print('contained-ok')"],
        cwd=layout.assigned_worktree, env=fixture_env,
    )
    assert result.exit_code == 0
    assert result.stdout.strip() == "contained-ok"
    assert result.containment_unit and result.containment_unit.startswith("aos-task-")
    assert result.containment_cgroup  # dynamically discovered, not assumed
    assert result.containment_state == ContainmentState.TERMINATED.value
    assert result.identity is not None and result.identity.start_time_ticks is not None
    kinds = event_kinds(collector)
    assert EV_CONTAINMENT_CREATED in kinds
    assert EV_PROCESS_STARTED in kinds
    assert EV_CGROUP_EMPTY_VERIFIED in kinds
    assert EV_CONTAINMENT_DESTROYED in kinds
    assert_no_aos_units(runner.backend)


def test_timeout_escalation_kills_signal_ignoring_tree(crunner, layout, fixture_env):
    """Child ignores SIGINT AND SIGTERM: escalation must reach the forced
    containment kill and the cgroup must end recursively empty."""
    runner, collector = crunner
    code = (
        "import signal, time\n"
        "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "time.sleep(60)\n"
    )
    result = runner.run(
        [sys.executable, "-c", code],
        cwd=layout.assigned_worktree, env=fixture_env, timeout=0.5,
    )
    assert result.timed_out is True
    assert result.containment_state == ContainmentState.TERMINATED.value
    kinds = event_kinds(collector)
    assert EV_SIGNAL_SENT in kinds
    assert EV_FORCED_KILL_REQUESTED in kinds
    assert kinds[-2] in (EV_CGROUP_EMPTY_VERIFIED, EV_CONTAINMENT_DESTROYED)
    assert_no_aos_units(runner.backend)


def test_proc02_grandchild_contained(crunner, layout, fixture_env):
    runner, _ = crunner
    result = runner.run_scenario(
        "PROC-02", cwd=layout.assigned_worktree, env=fixture_env,
    )
    assert result.succeeded is True
    assert result.process.containment_state == ContainmentState.TERMINATED.value


def test_proc01_normal_child_contained(crunner, layout, fixture_env):
    runner, _ = crunner
    result = runner.run_scenario(
        "PROC-01", cwd=layout.assigned_worktree, env=fixture_env,
    )
    assert result.succeeded is True
    assert result.details["child_exit_code"] == 0
    assert not pid_alive(result.details["child_pid"])
    assert result.process.containment_state == ContainmentState.TERMINATED.value


def test_proc04_setsid_child_contained(crunner, layout, fixture_env):
    """A child that calls setsid() (new session) must NOT escape the task
    cgroup: sessions are not the containment boundary, the cgroup is."""
    runner, _ = crunner
    result = runner.run_scenario(
        "PROC-04", cwd=layout.assigned_worktree, env=fixture_env,
    )
    assert result.succeeded is True
    assert result.details["setsid_supported"] is True
    assert result.details["child_outcome"].startswith("setsid-ok")
    assert not pid_alive(result.details["child_pid"])
    assert result.process.containment_state == ContainmentState.TERMINATED.value


def test_proc03_sigterm_child_contained(crunner, layout, fixture_env):
    runner, _ = crunner
    result = runner.run_scenario(
        "PROC-03", cwd=layout.assigned_worktree, env=fixture_env,
    )
    assert result.succeeded is True
    assert result.details["cleaned_up"] is True
    assert result.process.containment_state == ContainmentState.TERMINATED.value


def test_proc05_lingering_child_removed_by_containment(crunner, layout, fixture_env):
    """Baseline comparison: under UnsafeLocalRunner this child survives the
    worker; under the containment runner it stays inside the task cgroup and
    is removed during cancellation."""
    runner, collector = crunner
    heartbeat = layout.task_tmp / "cgroup-hb-05.txt"
    result = runner.run_scenario(
        "PROC-05", cwd=layout.assigned_worktree, env=fixture_env, target=heartbeat,
    )
    assert result.succeeded is True
    child_pid = result.details["child_pid"]
    assert result.process.containment_state == ContainmentState.TERMINATED.value
    assert wait_for(lambda: not pid_alive(child_pid), timeout=5.0), \
        "lingering child escaped containment"
    last = heartbeat.read_text()
    time.sleep(0.6)
    assert heartbeat.read_text() == last
    assert_no_aos_units(runner.backend)


def test_proc06_double_fork_daemon_contained(crunner, layout, fixture_env):
    runner, _ = crunner
    heartbeat = layout.task_tmp / "cgroup-hb-06.txt"
    result = runner.run_scenario(
        "PROC-06", cwd=layout.assigned_worktree, env=fixture_env, target=heartbeat,
    )
    if result.error_type == "Unsupported":
        pytest.skip("os.fork unavailable")
    assert result.succeeded is True
    daemon_pid = result.details["child_pid"]
    assert result.process.containment_state == ContainmentState.TERMINATED.value
    assert wait_for(lambda: not pid_alive(daemon_pid), timeout=5.0), \
        "double-forked daemon escaped containment"


def test_proc07_rapid_spawn_contained(crunner, layout, fixture_env):
    runner, _ = crunner
    result = runner.run_scenario(
        "PROC-07", cwd=layout.assigned_worktree, env=fixture_env,
    )
    assert result.succeeded is True
    assert result.details["all_reaped"] is True
    for pid in result.details["child_pids"]:
        assert not pid_alive(pid)
    assert result.process.containment_state == ContainmentState.TERMINATED.value


def test_proc08_new_process_group_contained(crunner, layout, fixture_env):
    """A child in a DIFFERENT process group must still die with the cgroup."""
    runner, _ = crunner
    heartbeat = layout.task_tmp / "cgroup-hb-08.txt"
    result = runner.run_scenario(
        "PROC-08", cwd=layout.assigned_worktree, env=fixture_env, target=heartbeat,
    )
    if result.error_type == "Unsupported":
        pytest.skip("os.setpgid unavailable")
    assert result.succeeded is True
    child_pid = result.details["child_pid"]
    assert result.process.containment_state == ContainmentState.TERMINATED.value
    assert wait_for(lambda: not pid_alive(child_pid), timeout=5.0), \
        "new-process-group child escaped containment"


def test_fs01_still_runs_contained(crunner, layout, fixture_env):
    """The Milestone 1 corpus is reusable through the containment backend."""
    runner, _ = crunner
    result = runner.run_scenario(
        "FS-01", cwd=layout.assigned_worktree, env=fixture_env,
        target=layout.allowed_file,
    )
    assert result.succeeded is True
    assert result.details["canary"] == layout.canaries["permitted"]
    assert result.process.containment_state == ContainmentState.TERMINATED.value
