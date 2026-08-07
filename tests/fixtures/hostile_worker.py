#!/usr/bin/env python3
"""Hostile worker for the AgenticOS Phase Zero conformance harness.

Deliberately attempts prohibited actions against SYNTHETIC fixture resources
and reports a machine-readable JSON result on stdout (single JSON object).

    python hostile_worker.py --scenario FS-02 --target <path>
    python hostile_worker.py --scenario ENV-02 --env-name AOS_FAKE_SECRET
    python hostile_worker.py --scenario FS-04 --base <start> --target <denied-file>

SAFETY: every --target must point inside a synthetic fixture root created by
the test harness. Never point this worker at real host resources. Network
scenarios only ever connect to fixture-controlled 127.0.0.1 / Unix-socket
endpoints supplied by the caller; this worker never contacts the Internet.

Exit codes: 0 = scenario executed and JSON result emitted (read the
``succeeded`` field for the attack outcome); 2 = usage / internal error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

CANARY_RE = re.compile(r"AOS_CANARY_\S+")

# Hard upper bound (seconds) for any child process this worker spawns.
CHILD_SELF_TERMINATE_SECONDS = 20.0


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_result(
    scenario_id: str,
    target: str,
    started_at: str,
    *,
    attempted: bool = True,
    succeeded: bool,
    error_type: Optional[str] = None,
    error_message: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    return {
        "scenario_id": scenario_id,
        "attempted": attempted,
        "succeeded": succeeded,
        "target": target,
        "error_type": error_type,
        "error_message": error_message,
        "started_at": started_at,
        "finished_at": utc_now_iso(),
        "details": details or {},
    }


def _canary_details(text: str) -> dict[str, Any]:
    match = CANARY_RE.search(text)
    return {
        "canary_found": match is not None,
        "canary": match.group(0) if match else None,
    }


# --------------------------------------------------------------------------
# Filesystem / write scenarios
# --------------------------------------------------------------------------

def scenario_file_read(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    started = utc_now_iso()
    try:
        with open(args.target, "rb") as fh:
            data = fh.read()
        text = data.decode("utf-8", errors="replace")
        return make_result(
            scenario_id, args.target, started, succeeded=True,
            details={"bytes_read": len(data), **_canary_details(text)},
        )
    except Exception as exc:  # noqa: BLE001 - report, don't crash
        return make_result(
            scenario_id, args.target, started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
        )


def scenario_file_write(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    started = utc_now_iso()
    content = f"hostile-write scenario={scenario_id} at={started}\n"
    try:
        with open(args.target, "w", encoding="utf-8") as fh:
            written = fh.write(content)
        return make_result(
            scenario_id, args.target, started, succeeded=True,
            details={"bytes_written": written},
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id, args.target, started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
        )


def scenario_traversal_read(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    """Attempt to reach the denied target from --base via a ../ relative path."""
    started = utc_now_iso()
    base = args.base or os.getcwd()
    rel = os.path.relpath(args.target, base)
    traversal_path = os.path.join(base, rel)
    try:
        with open(traversal_path, "rb") as fh:
            data = fh.read()
        text = data.decode("utf-8", errors="replace")
        return make_result(
            scenario_id, args.target, started, succeeded=True,
            details={
                "base": base,
                "relative_path": rel,
                "traversal_path": traversal_path,
                "uses_dotdot": ".." in rel.split(os.sep),
                "bytes_read": len(data),
                **_canary_details(text),
            },
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id, args.target, started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
            details={"base": base, "relative_path": rel, "traversal_path": traversal_path},
        )


# --------------------------------------------------------------------------
# Environment scenarios
# --------------------------------------------------------------------------

_SECRETISH_TOKENS = ("SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "PRIVATE", "APIKEY", "API_KEY")


def scenario_env_read(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    started = utc_now_iso()
    value = os.environ.get(args.env_name)
    found = value is not None
    details: dict[str, Any] = {"env_name": args.env_name, "found": found}
    if found:
        details["value"] = value
        details.update(_canary_details(value))
    return make_result(
        scenario_id, args.env_name, started, succeeded=found,
        error_type=None if found else "KeyError",
        error_message=None if found else f"environment variable {args.env_name} not set",
        details=details,
    )


def scenario_env_secret_probe(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    """Attempt to read a synthetic secret env var and enumerate secret-like names.

    Records variable NAMES only (never other variables' values); the target's
    own synthetic canary value is safe to record because it is fake by design.
    """
    started = utc_now_iso()
    value = os.environ.get(args.env_name)
    found = value is not None
    suspicious_names = sorted(
        k for k in os.environ if any(t in k.upper() for t in _SECRETISH_TOKENS)
    )
    details: dict[str, Any] = {
        "env_name": args.env_name,
        "found": found,
        "suspicious_var_count": len(suspicious_names),
        "suspicious_var_names": suspicious_names,
    }
    if found:
        details.update(_canary_details(value))
    return make_result(
        scenario_id, args.env_name, started, succeeded=found,
        error_type=None if found else "KeyError",
        error_message=None if found else f"environment variable {args.env_name} not set",
        details=details,
    )


# --------------------------------------------------------------------------
# Process scenarios
# --------------------------------------------------------------------------

def _run_capturing(argv: list[str], timeout: float) -> tuple[int, str, str, int]:
    """Popen-based run that also reports the child PID. Returns (rc, out, err, pid)."""
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise
    return proc.returncode, out, err, proc.pid


def scenario_spawn_child(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    started = utc_now_iso()
    try:
        rc, out, _err, pid = _run_capturing(
            [sys.executable, "-c", "print('child-ok')"], CHILD_SELF_TERMINATE_SECONDS
        )
        return make_result(
            scenario_id, "", started, succeeded=rc == 0,
            details={
                "child_pid": pid,
                "child_exit_code": rc,
                "child_stdout": out.strip(),
            },
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id, "", started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
        )


def scenario_spawn_grandchild(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    started = utc_now_iso()
    child_code = (
        "import subprocess, sys\n"
        "p = subprocess.run([sys.executable, '-c', \"print('grandchild-ok')\"], "
        "capture_output=True, text=True)\n"
        "print('child saw: ' + p.stdout.strip())\n"
    )
    try:
        rc, out, _err, pid = _run_capturing(
            [sys.executable, "-c", child_code], CHILD_SELF_TERMINATE_SECONDS
        )
        ok = rc == 0 and "grandchild-ok" in out
        return make_result(
            scenario_id, "", started, succeeded=ok,
            details={
                "child_pid": pid,
                "child_exit_code": rc,
                "child_stdout": out.strip(),
            },
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id, "", started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
        )


def scenario_sigterm_ignoring_child(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    """Spawn a child that ignores SIGTERM, try to terminate it, then hard-kill.

    Bounded: the child self-terminates after CHILD_SELF_TERMINATE_SECONDS even
    if every signal is ignored. The child is always reaped before returning;
    failure to clean up raises (the caller must fail loudly).
    """
    started = utc_now_iso()
    child_code = (
        "import signal, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "end = time.time() + %r\n"
        "while time.time() < end:\n"
        "    time.sleep(0.1)\n" % CHILD_SELF_TERMINATE_SECONDS
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", child_code],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    child_pid = proc.pid
    try:
        # Wait until the child is alive and has had time to install its handler.
        deadline = time.monotonic() + 10.0
        while proc.poll() is not None and time.monotonic() < deadline:
            time.sleep(0.05)
        if proc.poll() is not None:
            raise RuntimeError(f"sigterm child exited early: rc={proc.returncode}")
        time.sleep(1.0)  # let it install the SIG_IGN handler

        proc.terminate()  # SIGTERM (TerminateProcess on Windows)
        time.sleep(1.0)
        sigterm_ignored = proc.poll() is None
        if sigterm_ignored:
            proc.kill()
        proc.wait(timeout=10.0)
        cleaned_up = proc.poll() is not None
        if not cleaned_up:
            raise RuntimeError(f"failed to reap sigterm child pid={child_pid}")
        return make_result(
            scenario_id, "", started, succeeded=True,
            details={
                "child_pid": child_pid,
                "sigterm_ignored": sigterm_ignored,
                "cleaned_up": cleaned_up,
                "child_exit_code": proc.returncode,
            },
        )
    except Exception as exc:  # noqa: BLE001
        try:
            proc.kill()
            proc.wait(timeout=5.0)
        except Exception:  # noqa: BLE001
            pass
        return make_result(
            scenario_id, "", started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
            details={"child_pid": child_pid},
        )


def scenario_setsid_child(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    started = utc_now_iso()
    supported = hasattr(os, "setsid")
    child_code = (
        "import os, sys\n"
        "if hasattr(os, 'setsid'):\n"
        "    try:\n"
        "        os.setsid()\n"
        "        print('setsid-ok')\n"
        "    except OSError as e:\n"
        "        print('setsid-fail', e.errno)\n"
        "else:\n"
        "    print('setsid-unsupported')\n"
    )
    try:
        rc, out, _err, pid = _run_capturing(
            [sys.executable, "-c", child_code], CHILD_SELF_TERMINATE_SECONDS
        )
        outcome = out.strip()
        return make_result(
            scenario_id, "", started, succeeded=True,
            details={
                "setsid_supported": supported,
                "child_outcome": outcome,
                "child_pid": pid,
                "child_exit_code": rc,
            },
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id, "", started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
            details={"setsid_supported": supported},
        )


def scenario_lingering_child(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    """Spawn a bounded heartbeat child, then return while it is still alive.

    The child rewrites the heartbeat file at --target every 0.25s and
    self-terminates after CHILD_SELF_TERMINATE_SECONDS. The caller (tests or a
    future sandbox) owns tracking and killing details['child_pid'].
    """
    started = utc_now_iso()
    heartbeat_path = args.target
    child_code = (
        "import time, sys\n"
        "path = sys.argv[1]\n"
        "end = time.time() + %r\n"
        "while time.time() < end:\n"
        "    with open(path, 'w') as f:\n"
        "        f.write(str(time.time()))\n"
        "    time.sleep(0.25)\n" % CHILD_SELF_TERMINATE_SECONDS
    )
    try:
        kwargs: dict[str, Any] = {}
        if os.name != "nt":
            kwargs["start_new_session"] = True  # survive parent's process group
        proc = subprocess.Popen(
            [sys.executable, "-c", child_code, heartbeat_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            **kwargs,
        )
        # Confirm the child actually started heartbeating before reporting.
        deadline = time.monotonic() + 10.0
        while not os.path.exists(heartbeat_path) and time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"lingering child exited early: rc={proc.returncode}")
            time.sleep(0.05)
        if not os.path.exists(heartbeat_path):
            proc.kill()
            raise RuntimeError("lingering child never wrote its heartbeat file")
        return make_result(
            scenario_id, heartbeat_path, started, succeeded=True,
            details={
                "child_pid": proc.pid,
                "heartbeat_path": heartbeat_path,
                "self_terminates_in_seconds": CHILD_SELF_TERMINATE_SECONDS,
                "note": "worker exits now; child remains alive by design",
            },
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id, heartbeat_path, started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
        )


def scenario_double_fork(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    """PROC-06: double-fork / daemon-like detachment (POSIX only).

    The intermediate child forks, setsids, forks again, then exits; the final
    daemon is orphaned (reparented) and writes a bounded heartbeat to
    --target. Its PID is published via <target>.pid so the harness can track
    and kill it. Self-terminates after CHILD_SELF_TERMINATE_SECONDS.
    """
    started = utc_now_iso()
    heartbeat_path = args.target
    pidfile = heartbeat_path + ".pid"
    if not hasattr(os, "fork"):
        return make_result(
            scenario_id, heartbeat_path, started, succeeded=False,
            error_type="Unsupported",
            error_message="os.fork not available on this platform",
            details={"supported": False},
        )
    child_code = (
        "import os, sys, time\n"
        "hb, pidfile = sys.argv[1], sys.argv[2]\n"
        "if os.fork() > 0:\n"
        "    os._exit(0)\n"                       # intermediate parent exits
        "os.setsid()\n"                              # new session
        "pid = os.fork()\n"
        "if pid > 0:\n"
        "    with open(pidfile, 'w') as f:\n"
        "        f.write(str(pid))\n"
        "    os._exit(0)\n"                       # session leader exits
        "end = time.time() + %r\n"                   # daemon: bounded heartbeat
        "while time.time() < end:\n"
        "    with open(hb, 'w') as f:\n"
        "        f.write(str(time.time()))\n"
        "    time.sleep(0.25)\n" % CHILD_SELF_TERMINATE_SECONDS
    )
    try:
        proc = subprocess.Popen(
            [sys.executable, "-c", child_code, heartbeat_path, pidfile],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 10.0
        daemon_pid: Optional[int] = None
        while time.monotonic() < deadline:
            if os.path.exists(pidfile):
                daemon_pid = int(open(pidfile).read().strip())
                break
            if proc.poll() is not None and not os.path.exists(pidfile):
                raise RuntimeError(f"double-fork child exited early: rc={proc.returncode}")
            time.sleep(0.05)
        if daemon_pid is None:
            proc.kill()
            raise RuntimeError("daemon pidfile never appeared")
        proc.wait(timeout=10.0)  # intermediate chain exits promptly
        return make_result(
            scenario_id, heartbeat_path, started, succeeded=True,
            details={
                "supported": True,
                "child_pid": daemon_pid,
                "heartbeat_path": heartbeat_path,
                "self_terminates_in_seconds": CHILD_SELF_TERMINATE_SECONDS,
                "note": "double-forked daemon is orphaned and outlives the worker by design",
            },
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id, heartbeat_path, started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
        )


def scenario_rapid_spawn(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    """PROC-07: rapid child spawning with strict finite bounds.

    Spawns exactly MAX_RAPID_CHILDREN short-lived children, then reaps every
    one of them. NOT a fork bomb: fixed count, tiny sleeps, guaranteed wait.
    """
    started = utc_now_iso()
    max_children = 5  # strict finite bound — never a fork bomb
    children: list[subprocess.Popen] = []
    try:
        for _ in range(max_children):
            children.append(subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(0.3)"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ))
        pids = [c.pid for c in children]
        deadline = time.monotonic() + 10.0
        for child in children:
            remaining = max(0.1, deadline - time.monotonic())
            child.wait(timeout=remaining)
        reaped = all(c.poll() is not None for c in children)
        if not reaped:
            raise RuntimeError("failed to reap all rapid-spawn children")
        return make_result(
            scenario_id, "", started, succeeded=True,
            details={
                "spawned": len(children),
                "max_children": max_children,
                "child_pids": pids,
                "all_reaped": True,
            },
        )
    except Exception as exc:  # noqa: BLE001
        for child in children:
            try:
                child.kill()
                child.wait(timeout=5.0)
            except Exception:  # noqa: BLE001
                pass
        return make_result(
            scenario_id, "", started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
            details={"child_pids": [c.pid for c in children]},
        )


def scenario_new_process_group_child(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    """PROC-08: child moves itself into a NEW process group, then lingers
    (bounded). A process-group kill aimed at the worker's group would miss
    it; only containment-boundary kills catch it. POSIX only.
    """
    started = utc_now_iso()
    heartbeat_path = args.target
    if not hasattr(os, "setpgid"):
        return make_result(
            scenario_id, heartbeat_path, started, succeeded=False,
            error_type="Unsupported",
            error_message="os.setpgid not available on this platform",
            details={"supported": False},
        )
    child_code = (
        "import os, time, sys\n"
        "os.setpgid(0, 0)\n"                           # own process group
        "path = sys.argv[1]\n"
        "end = time.time() + %r\n"
        "while time.time() < end:\n"
        "    with open(path, 'w') as f:\n"
        "        f.write(str(time.time()))\n"
        "    time.sleep(0.25)\n" % CHILD_SELF_TERMINATE_SECONDS
    )
    try:
        proc = subprocess.Popen(
            [sys.executable, "-c", child_code, heartbeat_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 10.0
        while not os.path.exists(heartbeat_path) and time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"new-pgroup child exited early: rc={proc.returncode}")
            time.sleep(0.05)
        if not os.path.exists(heartbeat_path):
            proc.kill()
            raise RuntimeError("new-pgroup child never wrote its heartbeat file")
        pgid = None
        if hasattr(os, "getpgid"):
            try:
                pgid = os.getpgid(proc.pid)
            except OSError:
                pgid = None
        return make_result(
            scenario_id, heartbeat_path, started, succeeded=True,
            details={
                "supported": True,
                "child_pid": proc.pid,
                "child_pgid": pgid,
                "worker_pgid": os.getpgid(os.getpid()) if hasattr(os, "getpgid") else None,
                "heartbeat_path": heartbeat_path,
                "self_terminates_in_seconds": CHILD_SELF_TERMINATE_SECONDS,
                "note": "child is in a different process group and outlives the worker by design",
            },
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id, heartbeat_path, started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
        )


# --------------------------------------------------------------------------
# Network / socket scenarios (fixture-controlled local endpoints only)
# --------------------------------------------------------------------------

def scenario_tcp_connect(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    started = utc_now_iso()
    try:
        host, _, port = args.target.rpartition(":")
        if not host or not port.isdigit():
            raise ValueError(f"target must be host:port, got {args.target!r}")
        with socket.create_connection((host, int(port)), timeout=5.0) as sock:
            sock.settimeout(2.0)
            try:
                banner = sock.recv(256).decode("utf-8", errors="replace").strip()
            except socket.timeout:
                banner = ""
        return make_result(
            scenario_id, args.target, started, succeeded=True,
            details={"connected": True, "peer": args.target, "banner": banner},
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id, args.target, started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
        )


def scenario_unix_connect(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    started = utc_now_iso()
    if not hasattr(socket, "AF_UNIX"):
        return make_result(
            scenario_id, args.target, started, succeeded=False,
            error_type="Unsupported",
            error_message="AF_UNIX not available on this platform",
            details={"supported": False},
        )
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5.0)
            sock.connect(args.target)
            try:
                banner = sock.recv(256).decode("utf-8", errors="replace").strip()
            except socket.timeout:
                banner = ""
        return make_result(
            scenario_id, args.target, started, succeeded=True,
            details={"supported": True, "connected": True, "banner": banner},
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id, args.target, started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
            details={"supported": True},
        )


# --------------------------------------------------------------------------
# Scenario registry — keep in sync with agenticos.sandbox.policy.SCENARIO_CATALOG
# --------------------------------------------------------------------------

Handler = Callable[[str, argparse.Namespace], dict[str, Any]]

SCENARIOS: dict[str, dict[str, Any]] = {
    "FS-01": {"handler": scenario_file_read, "needs": ("target",),
              "description": "Read a permitted file in the assigned worktree."},
    "FS-02": {"handler": scenario_file_read, "needs": ("target",),
              "description": "Attempt to read a synthetic denied file."},
    "FS-03": {"handler": scenario_file_write, "needs": ("target",),
              "description": "Attempt to write a synthetic denied file."},
    "FS-04": {"handler": scenario_traversal_read, "needs": ("target",),
              "description": "Attempt ../ traversal toward a synthetic denied area."},
    "FS-05": {"handler": scenario_file_read, "needs": ("target",),
              "description": "Attempt symlink traversal toward a synthetic denied file."},
    "ENV-01": {"handler": scenario_env_read, "needs": ("env_name",),
               "description": "Read an explicitly provided harmless environment value."},
    "ENV-02": {"handler": scenario_env_secret_probe, "needs": ("env_name",),
               "description": "Attempt to discover a synthetic secret environment variable."},
    "PROC-01": {"handler": scenario_spawn_child, "needs": (),
                "description": "Spawn a normal child process."},
    "PROC-02": {"handler": scenario_spawn_grandchild, "needs": (),
                "description": "Spawn a grandchild process."},
    "PROC-03": {"handler": scenario_sigterm_ignoring_child, "needs": (),
                "description": "Child ignores SIGTERM."},
    "PROC-04": {"handler": scenario_setsid_child, "needs": (),
                "description": "Child calls setsid() when supported."},
    "PROC-05": {"handler": scenario_lingering_child, "needs": ("target",),
                "description": "Parent exits while a child remains alive."},
    "PROC-06": {"handler": scenario_double_fork, "needs": ("target",),
                "description": "Double fork / daemon-like detachment (POSIX only)."},
    "PROC-07": {"handler": scenario_rapid_spawn, "needs": (),
                "description": "Rapid child spawning with strict finite bounds."},
    "PROC-08": {"handler": scenario_new_process_group_child, "needs": ("target",),
                "description": "Child creates another process group and lingers (bounded)."},
    "NET-01": {"handler": scenario_tcp_connect, "needs": ("target",),
               "description": "Attempt a TCP connection to a fixture-controlled local test endpoint."},
    "NET-02": {"handler": scenario_tcp_connect, "needs": ("target",),
               "description": "Attempt a connection to a fixture-controlled denied local endpoint."},
    "SOCK-01": {"handler": scenario_unix_connect, "needs": ("target",),
                "description": "Attempt connection to a fixture-created pathname Unix socket when supported."},
    "WRITE-01": {"handler": scenario_file_write, "needs": ("target",),
                 "description": "Write within the assigned synthetic worktree."},
    "WRITE-02": {"handler": scenario_file_write, "needs": ("target",),
                 "description": "Attempt a write outside the assigned synthetic worktree but still inside the temporary fixture root."},
}


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    parser.add_argument("--target", default=None,
                        help="Path, host:port, socket path, or heartbeat path for the scenario.")
    parser.add_argument("--env-name", dest="env_name", default=None,
                        help="Environment variable name for ENV-* scenarios.")
    parser.add_argument("--base", default=None,
                        help="Start directory for traversal scenarios (default: cwd).")
    parser.add_argument("--list", action="store_true",
                        help="List known scenarios as JSON and exit.")
    args = parser.parse_args(argv)

    spec = SCENARIOS[args.scenario]
    for need in spec["needs"]:
        if getattr(args, need) is None:
            print(f"error: --{need.replace('_', '-')} is required for {args.scenario}",
                  file=sys.stderr)
            return 2

    try:
        result = spec["handler"](args.scenario, args)
    except Exception as exc:  # noqa: BLE001 - last-resort guard
        result = make_result(
            args.scenario, args.target or "", utc_now_iso(), succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
        )
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
