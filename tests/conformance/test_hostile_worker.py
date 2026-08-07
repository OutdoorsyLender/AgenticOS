"""Tests for the hostile worker scenarios (run directly, unsandboxed).

Under the unsafe baseline, DENIED actions are expected to SUCCEED — the point
of these tests is that the worker *reports* each attempt accurately and
deterministically, so the same corpus can later measure a real sandbox.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

from helpers import (
    WORKER_PATH,
    kill_pid,
    minimal_env,
    pid_alive,
    run_worker,
    tcp_fixture_server,
    unix_fixture_server,
    wait_for,
)


def test_worker_path_exists():
    assert WORKER_PATH.is_file()


# --------------------------------------------------------------------------
# Filesystem
# --------------------------------------------------------------------------

def test_fs01_allowed_read(layout, fixture_env):
    res = run_worker("FS-01", target=layout.allowed_file, env=fixture_env,
                     cwd=layout.assigned_worktree)
    assert res["scenario_id"] == "FS-01"
    assert res["attempted"] is True
    assert res["succeeded"] is True
    assert res["details"]["canary_found"] is True
    assert res["details"]["canary"] == layout.canaries["permitted"]


def test_fs02_denied_read_reported(layout, fixture_env):
    res = run_worker("FS-02", target=layout.denied_sibling_file, env=fixture_env,
                     cwd=layout.assigned_worktree)
    assert res["attempted"] is True
    # Unsafe host: the denied read succeeds and must be honestly reported.
    assert res["succeeded"] is True
    assert res["details"]["canary"] == layout.canaries["sibling"]


def test_fs03_denied_write_reported(layout, fixture_env):
    target = layout.sibling_worktree / "pwned.txt"
    res = run_worker("FS-03", target=target, env=fixture_env,
                     cwd=layout.assigned_worktree)
    assert res["attempted"] is True
    assert res["succeeded"] is True
    assert "hostile-write" in target.read_text()


def test_fs04_traversal_reported(layout, fixture_env):
    res = run_worker("FS-04", target=layout.denied_sibling_file,
                     base=layout.assigned_worktree, env=fixture_env,
                     cwd=layout.assigned_worktree)
    assert res["attempted"] is True
    assert res["succeeded"] is True
    assert res["details"]["uses_dotdot"] is True
    assert ".." in res["details"]["relative_path"]
    assert res["details"]["canary"] == layout.canaries["sibling"]


def test_fs05_symlink_traversal_reported(layout, fixture_env):
    if not layout.symlink_supported:
        pytest.skip("symlink creation not supported in this environment")
    link = layout.assigned_worktree / "evil-link.txt"
    os.symlink(layout.denied_sibling_file, link)
    res = run_worker("FS-05", target=link, env=fixture_env,
                     cwd=layout.assigned_worktree)
    assert res["attempted"] is True
    assert res["succeeded"] is True
    assert res["details"]["canary"] == layout.canaries["sibling"]


# --------------------------------------------------------------------------
# Environment
# --------------------------------------------------------------------------

def test_env01_harmless_value(layout, fixture_env):
    res = run_worker("ENV-01", env_name=layout.harmless_env_name, env=fixture_env)
    assert res["succeeded"] is True
    assert res["details"]["found"] is True
    assert res["details"]["value"] == fixture_env[layout.harmless_env_name]


def test_env02_secret_probe_reported(layout, fixture_env):
    res = run_worker("ENV-02", env_name=layout.env_secret_name, env=fixture_env)
    assert res["attempted"] is True
    # Unsafe host: the synthetic secret is visible and must be honestly reported.
    assert res["succeeded"] is True
    assert res["details"]["canary"] == layout.canaries["env"]
    assert layout.env_secret_name in res["details"]["suspicious_var_names"]


def test_env02_absent_secret_reports_failure(layout):
    env = minimal_env()  # no synthetic secret present
    res = run_worker("ENV-02", env_name=layout.env_secret_name, env=env)
    assert res["attempted"] is True
    assert res["succeeded"] is False
    assert res["error_type"] == "KeyError"


# --------------------------------------------------------------------------
# Process
# --------------------------------------------------------------------------

def test_proc01_child_captured(layout, fixture_env):
    res = run_worker("PROC-01", env=fixture_env)
    assert res["succeeded"] is True
    assert res["details"]["child_exit_code"] == 0
    assert res["details"]["child_stdout"] == "child-ok"
    assert isinstance(res["details"]["child_pid"], int)
    assert not pid_alive(res["details"]["child_pid"])


def test_proc02_grandchild_captured(layout, fixture_env):
    res = run_worker("PROC-02", env=fixture_env)
    assert res["succeeded"] is True
    assert "grandchild-ok" in res["details"]["child_stdout"]
    assert not pid_alive(res["details"]["child_pid"])


def test_proc03_sigterm_ignoring_child_cleaned_up(layout, fixture_env):
    res = run_worker("PROC-03", env=fixture_env)
    assert res["succeeded"] is True
    details = res["details"]
    assert isinstance(details["sigterm_ignored"], bool)  # platform-dependent value
    assert details["cleaned_up"] is True
    # Nothing may be left running after the scenario returns.
    assert wait_for(lambda: not pid_alive(details["child_pid"]), timeout=5.0)


def test_proc04_setsid_reported(layout, fixture_env):
    res = run_worker("PROC-04", env=fixture_env)
    assert res["succeeded"] is True
    details = res["details"]
    assert details["setsid_supported"] == hasattr(os, "setsid")
    if details["setsid_supported"]:
        assert details["child_outcome"].startswith("setsid-ok") or \
            details["child_outcome"].startswith("setsid-fail")
    else:
        assert details["child_outcome"] == "setsid-unsupported"


def test_proc05_lingering_child_survives_worker_then_killed(layout, fixture_env):
    heartbeat = layout.task_tmp / "heartbeat.txt"
    res = run_worker("PROC-05", target=heartbeat, env=fixture_env)
    assert res["succeeded"] is True
    child_pid = res["details"]["child_pid"]
    try:
        # The worker process has exited, but the child must still be alive
        # and updating its heartbeat file.
        first = heartbeat.read_text()
        assert wait_for(lambda: heartbeat.read_text() != first, timeout=5.0), \
            "lingering child heartbeat did not advance after worker exit"
        assert pid_alive(child_pid)
    finally:
        kill_pid(child_pid)
    # Cleanup must be loud: the child has to die and stay dead.
    assert wait_for(lambda: not pid_alive(child_pid), timeout=5.0), \
        f"lingering child pid={child_pid} survived kill"
    last = heartbeat.read_text()
    time.sleep(0.6)
    assert heartbeat.read_text() == last, "heartbeat still updating after kill"


def test_proc06_double_fork_daemon(layout, fixture_env):
    heartbeat = layout.task_tmp / "daemon-heartbeat.txt"
    res = run_worker("PROC-06", target=heartbeat, env=fixture_env)
    if res["error_type"] == "Unsupported":
        pytest.skip("os.fork not available on this platform")
    assert res["succeeded"] is True
    daemon_pid = res["details"]["child_pid"]
    try:
        first = heartbeat.read_text()
        assert wait_for(lambda: heartbeat.read_text() != first, timeout=5.0), \
            "double-forked daemon heartbeat did not advance"
        assert pid_alive(daemon_pid)
    finally:
        kill_pid(daemon_pid)
    assert wait_for(lambda: not pid_alive(daemon_pid), timeout=5.0), \
        f"daemon pid={daemon_pid} survived kill"
    last = heartbeat.read_text()
    time.sleep(0.6)
    assert heartbeat.read_text() == last, "daemon heartbeat still updating after kill"


def test_proc07_rapid_spawn_bounded_and_reaped(layout, fixture_env):
    res = run_worker("PROC-07", env=fixture_env)
    assert res["succeeded"] is True
    details = res["details"]
    assert details["spawned"] == details["max_children"] == 5
    assert len(details["child_pids"]) == 5
    assert details["all_reaped"] is True
    for pid in details["child_pids"]:
        assert wait_for(lambda p=pid: not pid_alive(p), timeout=5.0), \
            f"rapid-spawn child pid={pid} still alive"


def test_proc08_new_process_group_child(layout, fixture_env):
    heartbeat = layout.task_tmp / "pgroup-heartbeat.txt"
    res = run_worker("PROC-08", target=heartbeat, env=fixture_env)
    if res["error_type"] == "Unsupported":
        pytest.skip("os.setpgid not available on this platform")
    assert res["succeeded"] is True
    details = res["details"]
    child_pid = details["child_pid"]
    # The child really did escape the worker's process group.
    assert details["child_pgid"] == child_pid
    assert details["child_pgid"] != details["worker_pgid"]
    try:
        first = heartbeat.read_text()
        assert wait_for(lambda: heartbeat.read_text() != first, timeout=5.0)
        assert pid_alive(child_pid)
    finally:
        kill_pid(child_pid)
    assert wait_for(lambda: not pid_alive(child_pid), timeout=5.0), \
        f"new-pgroup child pid={child_pid} survived kill"


# --------------------------------------------------------------------------
# Network / sockets (fixture-controlled local endpoints only)
# --------------------------------------------------------------------------

def test_net01_allowed_local_endpoint(layout, fixture_env):
    with tcp_fixture_server() as endpoint:
        res = run_worker("NET-01", target=endpoint, env=fixture_env)
    assert res["succeeded"] is True
    assert res["details"]["connected"] is True
    assert res["details"]["banner"] == "fixture-banner"


def test_net02_denied_local_endpoint_reported(layout, fixture_env):
    with tcp_fixture_server() as endpoint:
        res = run_worker("NET-02", target=endpoint, env=fixture_env)
    # Unsafe host: the "denied" local endpoint is reachable; honesty matters.
    assert res["attempted"] is True
    assert res["succeeded"] is True
    assert res["details"]["connected"] is True


def test_net_connection_refused_reported(layout, fixture_env):
    # A fixture-controlled local port with nothing listening on it.
    with socket_free_port() as endpoint:
        res = run_worker("NET-01", target=endpoint, env=fixture_env)
    assert res["attempted"] is True
    assert res["succeeded"] is False
    assert res["error_type"] in ("ConnectionRefusedError", "TimeoutError", "OSError")


class socket_free_port:
    """Find a free local TCP port and yield it closed (nothing listening)."""

    def __enter__(self):
        import socket as _socket

        with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            self._port = s.getsockname()[1]
        return f"127.0.0.1:{self._port}"

    def __exit__(self, *exc):
        return False


def test_sock01_unix_socket(layout, fixture_env):
    sock_path = layout.sockets_dir / "fixture.sock"
    try:
        server = unix_fixture_server(sock_path)
        endpoint = server.__enter__()
    except OSError as exc:
        pytest.skip(f"Unix sockets not usable here: {exc}")
    try:
        res = run_worker("SOCK-01", target=endpoint, env=fixture_env)
    finally:
        server.__exit__(None, None, None)
    if res["error_type"] == "Unsupported":
        pytest.skip("AF_UNIX not available on this platform")
    assert res["attempted"] is True
    assert res["succeeded"] is True
    assert res["details"]["banner"] == "fixture-unix-banner"


# --------------------------------------------------------------------------
# Writes
# --------------------------------------------------------------------------

def test_write01_inside_assigned_worktree(layout, fixture_env):
    target = layout.assigned_worktree / "output.txt"
    res = run_worker("WRITE-01", target=target, env=fixture_env,
                     cwd=layout.assigned_worktree)
    assert res["succeeded"] is True
    assert "hostile-write" in target.read_text()


def test_write02_outside_assigned_but_inside_root(layout, fixture_env):
    target = layout.sibling_worktree / "escape.txt"
    res = run_worker("WRITE-02", target=target, env=fixture_env,
                     cwd=layout.assigned_worktree)
    assert res["attempted"] is True
    assert res["succeeded"] is True
    assert target.is_file()
    # Still confined to the fixture root even in the "escape" case.
    assert layout.root in target.parents


# --------------------------------------------------------------------------
# JSON contract
# --------------------------------------------------------------------------

def test_worker_stdout_is_single_json_document(layout, fixture_env):
    proc = subprocess.run(
        [sys.executable, str(WORKER_PATH), "--scenario", "FS-01",
         "--target", str(layout.allowed_file)],
        capture_output=True, text=True, env=fixture_env,
        cwd=layout.assigned_worktree, timeout=30.0,
    )
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)  # whole stdout must parse as one JSON value
    for key in ("scenario_id", "attempted", "succeeded", "target",
                "error_type", "error_message", "started_at", "finished_at",
                "details"):
        assert key in doc


def test_unknown_scenario_rejected():
    proc = subprocess.run(
        [sys.executable, str(WORKER_PATH), "--scenario", "NOPE-99"],
        capture_output=True, text=True, env=minimal_env(), timeout=30.0,
    )
    assert proc.returncode != 0
