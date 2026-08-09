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
import resource
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
            details={"errno": getattr(exc, "errno", None)},
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
            details={"errno": getattr(exc, "errno", None)},
        )


def scenario_m4a_runtime_view(
    scenario_id: str, args: argparse.Namespace
) -> dict[str, Any]:
    """Inspect only the fixed synthetic M4A ABI and exercise its write tiers."""
    started = utc_now_iso()
    workspace = os.stat("/workspace", follow_symlinks=False)

    def attempt_write(path: str) -> bool:
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("m4a synthetic write probe\n")
            return True
        except OSError:
            return False

    try:
        with open("/workspace/allowed.txt", encoding="utf-8") as handle:
            workspace_canary_readable = "AOS_CANARY_permitted_" in handle.read()
        locator_visibility: list[bool] = []
        try:
            with open(
                "/workspace/host-locator-probe.txt", encoding="utf-8"
            ) as handle:
                locator_visibility = [
                    os.path.exists(locator.strip())
                    for locator in handle
                    if locator.strip()
                ]
        except FileNotFoundError:
            pass
        return make_result(
            scenario_id,
            "/workspace",
            started,
            succeeded=True,
            details={
                "cwd": os.getcwd(),
                "pwd": os.environ.get("PWD"),
                "workspace_identity": {
                    "device": workspace.st_dev,
                    "inode": workspace.st_ino,
                    "type": workspace.st_mode & 0o170000,
                },
                "fixed_paths": {
                    path: os.path.exists(path)
                    for path in (
                        "/bin", "/dev", "/home", "/lib", "/lib64", "/opt",
                        "/proc", "/run", "/sbin", "/tmp", "/usr", "/workspace",
                    )
                },
                "runtime_python": os.path.realpath(sys.executable),
                "workspace_canary_readable": workspace_canary_readable,
                "workspace_write_succeeded": attempt_write(
                    "/workspace/m4a-write-probe.txt"
                ),
                "private_tmp_write_succeeded": attempt_write(
                    "/tmp/m4a-tmp-probe.txt"
                ),
                "synthetic_home_write_succeeded": attempt_write(
                    "/home/tool/m4a-home-probe.txt"
                ),
                "sibling_visible": os.path.exists("/sibling-worktree"),
                "agenticos_private_visible": os.path.exists("/agenticos-private"),
                "host_fake_home_visible": os.path.exists("/home/tool/.ssh/id_fake"),
                "windows_mount_visible": os.path.exists("/mnt/c"),
                "host_locator_visibility": locator_visibility,
                "environment_names": sorted(os.environ),
            },
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id,
            "/workspace",
            started,
            succeeded=False,
            error_type=type(exc).__name__,
            error_message=str(exc),
        )


def scenario_m4a_security_state(
    scenario_id: str, args: argparse.Namespace
) -> dict[str, Any]:
    """Record final M4A env, capability, nested-userns, and FD state."""
    started = utc_now_iso()
    try:
        # Census before importing ctypes: this Python build loads libffi from
        # a private memfd, which is probe-created rather than inherited.
        open_fds: list[int] = []
        fd_types: dict[str, int] = {}
        fd_targets: dict[str, str] = {}
        for fd in range(256):
            try:
                observed_fd = os.fstat(fd)
            except OSError:
                continue
            open_fds.append(fd)
            fd_types[str(fd)] = observed_fd.st_mode & 0o170000
            try:
                fd_targets[str(fd)] = os.readlink(f"/proc/self/fd/{fd}")
            except OSError as exc:
                fd_targets[str(fd)] = type(exc).__name__

        import ctypes

        class CapHeader(ctypes.Structure):
            _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

        class CapData(ctypes.Structure):
            _fields_ = [
                ("effective", ctypes.c_uint32),
                ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32),
            ]

        libc = ctypes.CDLL(None, use_errno=True)
        header = CapHeader(0x20080522, 0)
        data = (CapData * 2)()
        if libc.capget(ctypes.byref(header), ctypes.byref(data)) != 0:
            raise OSError(ctypes.get_errno(), "capget failed")

        def cap_value(field: str) -> int:
            return int(getattr(data[0], field)) | (
                int(getattr(data[1], field)) << 32
            )

        def prctl_set(operation: int, arg2: int = 0) -> int:
            result = 0
            for capability in range(64):
                ctypes.set_errno(0)
                value = libc.prctl(operation, arg2, capability, 0, 0)
                if value == 1:
                    result |= 1 << capability
                elif value < 0 and ctypes.get_errno() == 22:
                    break
                elif value < 0:
                    raise OSError(ctypes.get_errno(), "prctl capability query failed")
            return result

        capabilities = {
            "CapInh": cap_value("inheritable"),
            "CapPrm": cap_value("permitted"),
            "CapEff": cap_value("effective"),
            "CapBnd": prctl_set(23),  # PR_CAPBSET_READ
            "CapAmb": prctl_set(47, 1),  # PR_CAP_AMBIENT / IS_SET
        }
        no_new_privs = libc.prctl(39, 0, 0, 0, 0)  # PR_GET_NO_NEW_PRIVS
        if no_new_privs < 0:
            raise OSError(ctypes.get_errno(), "PR_GET_NO_NEW_PRIVS failed")

        nested = subprocess.run(
            ["/usr/bin/unshare", "--user", "--map-root-user", "/usr/bin/true"],
            input="",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5.0,
            check=False,
        )
        return make_result(
            scenario_id,
            "self",
            started,
            succeeded=True,
            details={
                "environment": dict(sorted(os.environ.items())),
                "capabilities": {
                    name: f"{value:016x}" for name, value in capabilities.items()
                },
                "capability_source": "capget+prctl",
                "no_new_privs": str(no_new_privs),
                "nested_userns_exit_code": nested.returncode,
                "nested_userns_error_present": bool(nested.stderr.strip()),
                "open_fds": open_fds,
                "fd_types": fd_types,
                "fd_targets": fd_targets,
                "fds_beyond_stdio": [fd for fd in open_fds if fd > 2],
            },
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id,
            "self",
            started,
            succeeded=False,
            error_type=type(exc).__name__,
            error_message=str(exc),
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
            details={
                "base": base,
                "relative_path": rel,
                "traversal_path": traversal_path,
                "errno": getattr(exc, "errno", None),
            },
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


def scenario_symlink_write(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    """FS-06: write THROUGH a symlink (target = symlink pointing at a denied file)."""
    return scenario_file_write(scenario_id, args)


def scenario_rename_across_boundary(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    """FS-07: move a denied file (--target) into the workspace (--base)."""
    started = utc_now_iso()
    dest = os.path.join(args.base, os.path.basename(args.target))
    try:
        os.rename(args.target, dest)
        return make_result(
            scenario_id, args.target, started, succeeded=True,
            details={"source": args.target, "destination": dest},
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id, args.target, started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
            details={"source": args.target, "destination": dest,
                     "errno": getattr(exc, "errno", None)},
        )


def scenario_preopened_fd(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    """FS-08: read a denied resource via an INHERITED pre-opened file
    descriptor (--target = fd number). For contrast, also attempts a path
    open of --base. Path restrictions cannot revoke already-open FDs."""
    started = utc_now_iso()
    details: dict[str, Any] = {}
    if args.base:
        try:
            with open(args.base, "rb") as fh:
                path_data = fh.read()
            details["path_opened"] = True
            details["path_canary_found"] = bool(CANARY_RE.search(
                path_data.decode("utf-8", errors="replace")))
        except Exception as exc:  # noqa: BLE001
            details["path_opened"] = False
            details["path_error"] = type(exc).__name__
    try:
        data = os.read(int(args.target), 65536)
        text = data.decode("utf-8", errors="replace")
        details.update({"fd_read": True, "fd_bytes": len(data)})
        details.update({f"fd_{k}": v for k, v in _canary_details(text).items()})
        return make_result(scenario_id, args.target, started, succeeded=True,
                           details=details)
    except Exception as exc:  # noqa: BLE001
        details["fd_read"] = False
        return make_result(scenario_id, args.target, started, succeeded=False,
                           error_type=type(exc).__name__, error_message=str(exc),
                           details=details)


def scenario_descendant_denied_read(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    """FS-09: a DESCENDANT attempts to read the denied file (--target).
    --base selects the descendant shape: child | grandchild | setsid |
    newpgroup | parentexit | doublefork. The descendant records its observation to a result file in
    the cwd; ``succeeded`` means the descendant actually read the denied
    content (i.e. the restriction was NOT inherited)."""
    started = utc_now_iso()
    mode = (args.base or "child").strip()
    target = args.target
    result_file = os.path.join(os.getcwd(), f"fs09-{mode}-result.json")
    attempt = (
        "import json, os\n"
        "try:\n"
        "    cgroup = open('/proc/self/cgroup').read().strip()\n"
        "except Exception:\n"
        "    cgroup = None\n"
        f"try:\n"
        f"    d = open({target!r}, 'rb').read()\n"
        f"    r = {{'opened': True, 'canary_found': 'AOS_CANARY_' in d.decode('utf-8','replace'), 'pid': os.getpid(), 'cgroup': cgroup}}\n"
        f"except Exception as e:\n"
        f"    r = {{'opened': False, 'error': type(e).__name__, 'errno': getattr(e, 'errno', None), 'pid': os.getpid(), 'cgroup': cgroup}}\n"
        f"open({result_file!r}, 'w').write(json.dumps(r))\n"
    )
    runners = {
        "child": attempt,
        "grandchild": (
            "import subprocess, sys\n"
            f"subprocess.run([sys.executable, '-c', {attempt!r}])\n"
        ),
        "setsid": (
            "import os, subprocess, sys\n"
            "os.setsid()\n"
            f"subprocess.run([sys.executable, '-c', {attempt!r}])\n"
        ),
        "newpgroup": (
            "import os, subprocess, sys\n"
            "os.setpgrp()\n"
            f"subprocess.run([sys.executable, '-c', {attempt!r}])\n"
        ),
        "parentexit": (
            "import os, time\n"
            "if os.fork() > 0:\n"
            "    os._exit(0)\n"
            "time.sleep(0.1)\n"
            f"exec({attempt!r})\n"
        ),
        "doublefork": (
            "import os, subprocess, sys\n"
            "if os.fork() > 0:\n"
            "    os._exit(0)\n"
            "os.setsid()\n"
            "if os.fork() > 0:\n"
            "    os._exit(0)\n"
            f"subprocess.run([sys.executable, '-c', {attempt!r}])\n"
        ),
    }
    if mode not in runners:
        return make_result(scenario_id, target, started, attempted=False,
                           succeeded=False, error_type="ValueError",
                           error_message=f"unknown mode {mode!r}")
    if mode in ("parentexit", "doublefork") and not hasattr(os, "fork"):
        return make_result(scenario_id, target, started, succeeded=False,
                           error_type="Unsupported",
                           error_message="os.fork not available on this platform")
    try:
        if os.path.exists(result_file):
            os.unlink(result_file)
        subprocess.Popen([sys.executable, "-c", runners[mode]],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 15.0
        while not os.path.exists(result_file) and time.monotonic() < deadline:
            time.sleep(0.05)
        if not os.path.exists(result_file):
            raise RuntimeError(f"descendant ({mode}) never wrote its result file")
        with open(result_file) as fh:
            observation = json.load(fh)
        return make_result(
            scenario_id, target, started,
            succeeded=bool(observation.get("opened")),
            error_type=None if observation.get("opened") else observation.get("error"),
            details={"mode": mode, "descendant_opened": bool(observation.get("opened")),
                     "descendant_error": observation.get("error"),
                     "descendant_errno": observation.get("errno"),
                     "descendant_pid": observation.get("pid"),
                     "descendant_cgroup": observation.get("cgroup"),
                     "descendant_canary_found": observation.get("canary_found", False)},
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(scenario_id, target, started, succeeded=False,
                           error_type=type(exc).__name__, error_message=str(exc),
                           details={"mode": mode})


def scenario_enumerate_fds(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    """FS-12: enumerate inherited file descriptors via /proc/self/fd.

    Self-inspection probe: reports which FDs beyond 0/1/2 survived the
    launch boundary. succeeded = enumeration worked; the security signal is
    in details['open_fds']."""
    started = utc_now_iso()
    try:
        entries = os.listdir("/proc/self/fd")
        candidates = sorted(int(e) for e in entries if e.isdigit())
        fds = []
        for fd in candidates:
            try:
                os.fstat(fd)
            except OSError:
                continue
            fds.append(fd)
        return make_result(
            scenario_id, "", started, succeeded=True,
            details={"open_fds": fds, "fds_beyond_stdio": [f for f in fds if f > 2]},
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(scenario_id, "", started, succeeded=False,
                           error_type=type(exc).__name__, error_message=str(exc))


def scenario_boundary_probe(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    """FS-13: characterize what the filesystem boundary does NOT mediate.
    --base selects the probe: stat | chmod | setxattr | socket_connect.
    These document the guarantee edge; they are NOT conformance failures."""
    started = utc_now_iso()
    mode = (args.base or "stat").strip()
    target = args.target
    try:
        if mode == "stat":
            st = os.stat(target)
            detail = {"mode": mode, "size": st.st_size}
        elif mode == "chmod":
            os.chmod(target, 0o600)
            detail = {"mode": mode, "chmod": "0600"}
        elif mode == "setxattr":
            os.setxattr(target, b"user.aos_probe", b"1")
            detail = {"mode": mode, "xattr": "user.aos_probe"}
        elif mode == "socket_connect":
            if not hasattr(socket, "AF_UNIX"):
                return make_result(scenario_id, target, started, succeeded=False,
                                   error_type="Unsupported",
                                   error_message="AF_UNIX unavailable",
                                   details={"mode": mode})
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(5.0)
                s.connect(target)
            detail = {"mode": mode}
        else:
            return make_result(scenario_id, target, started, attempted=False,
                               succeeded=False, error_type="ValueError",
                               error_message=f"unknown probe mode {mode!r}")
        return make_result(scenario_id, target, started, succeeded=True,
                           details=detail)
    except Exception as exc:  # noqa: BLE001
        return make_result(scenario_id, target, started, succeeded=False,
                           error_type=type(exc).__name__, error_message=str(exc),
                           details={"mode": mode, "errno": getattr(exc, "errno", None)})


def scenario_file_truncate(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    """FS-14: exercise both ABI-v3 truncation paths independently."""
    started = utc_now_iso()
    method = (args.base or "truncate").strip()
    try:
        if method == "truncate":
            os.truncate(args.target, 0)
        elif method == "open_trunc":
            fd = os.open(args.target, os.O_RDONLY | os.O_TRUNC)
            os.close(fd)
        else:
            raise ValueError(f"unknown truncation method {method!r}")
        return make_result(
            scenario_id,
            args.target,
            started,
            succeeded=True,
            details={"method": method},
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id,
            args.target,
            started,
            succeeded=False,
            error_type=type(exc).__name__,
            error_message=str(exc),
            details={"method": method, "errno": getattr(exc, "errno", None)},
        )


def scenario_link_or_rename(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    """FS-15: hardlink or rename source target to the destination in --base."""
    started = utc_now_iso()
    try:
        operation, destination = (args.base or "").split(":", 1)
        if operation == "hardlink":
            os.link(args.target, destination)
        elif operation == "rename":
            os.rename(args.target, destination)
        else:
            raise ValueError(f"unknown link/reparent operation {operation!r}")
        return make_result(
            scenario_id,
            args.target,
            started,
            succeeded=True,
            details={"operation": operation, "destination": destination},
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id,
            args.target,
            started,
            succeeded=False,
            error_type=type(exc).__name__,
            error_message=str(exc),
            details={
                "operation": (args.base or "").split(":", 1)[0],
                "errno": getattr(exc, "errno", None),
            },
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


def scenario_udp_exchange(scenario_id: str, args: argparse.Namespace) -> dict[str, Any]:
    """Send only to a fixture-controlled loopback endpoint and await a reply."""
    started = utc_now_iso()
    try:
        host, _, port = args.target.rpartition(":")
        if host != "127.0.0.1" or not port.isdigit():
            raise ValueError("UDP fixture target must be 127.0.0.1:port")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1.0)
            sent = sock.sendto(b"AOS_CANARY_udp_probe", (host, int(port)))
            try:
                response, _ = sock.recvfrom(256)
            except socket.timeout:
                response = b""
        return make_result(
            scenario_id,
            args.target,
            started,
            succeeded=bool(response),
            error_type=None if response else "NoResponse",
            details={"bytes_sent": sent, "response_received": bool(response)},
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id, args.target, started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
            details={"response_received": False},
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
        endpoint = "\0" + args.target[1:] if args.target.startswith("@") else args.target
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5.0)
            sock.connect(endpoint)
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


def scenario_private_unix_socket(
    scenario_id: str, args: argparse.Namespace
) -> dict[str, Any]:
    """Prove socket-node creation remains available only in private /tmp."""
    started = utc_now_iso()
    endpoint = f"/tmp/aos-private-{os.getpid()}.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(endpoint)
        server.listen(1)
        client.settimeout(2.0)
        client.connect(endpoint)
        accepted, _ = server.accept()
        with accepted:
            client.sendall(b"private-socket-ok")
            received = accepted.recv(64)
        return make_result(
            scenario_id, "/tmp", started,
            succeeded=received == b"private-socket-ok",
            details={"private_exchange": received == b"private-socket-ok"},
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id, "/tmp", started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
        )
    finally:
        client.close()
        server.close()
        try:
            os.unlink(endpoint)
        except FileNotFoundError:
            pass


def scenario_connected_fd_send(
    scenario_id: str, args: argparse.Namespace
) -> dict[str, Any]:
    """Attempt a canary write through a deliberately supplied descriptor number."""
    started = utc_now_iso()
    try:
        written = os.write(int(args.target), b"AOS_CANARY_connected_socket")
        return make_result(
            scenario_id, "inherited-fd", started, succeeded=True,
            details={"bytes_written": written},
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id, "inherited-fd", started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
            details={"errno": getattr(exc, "errno", None)},
        )


def scenario_m4b_transport(
    scenario_id: str, args: argparse.Namespace
) -> dict[str, Any]:
    """Use only the fixed worker-facing proxy ABI and record inherited FDs."""
    started = utc_now_iso()
    before = _bounded_live_fd_census()
    try:
        with socket.create_connection(
            ("127.0.0.1", 18080), timeout=args.timeout
        ) as stream:
            stream.sendall(args.canary.encode("ascii"))
            reply = stream.recv(256).decode("ascii")
        return make_result(
            scenario_id,
            "127.0.0.1:18080",
            started,
            succeeded=True,
            details={"reply": reply, "fds_before": before},
        )
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id,
            "127.0.0.1:18080",
            started,
            succeeded=False,
            error_type=type(exc).__name__,
            error_message=str(exc),
            details={"fds_before": before, "errno": getattr(exc, "errno", None)},
        )


def _fd_is_open(fd: int) -> bool:
    try:
        os.fstat(fd)
    except OSError:
        return False
    return True


def _bounded_live_fd_census() -> list[int]:
    try:
        names = os.listdir("/proc/self/fd")
    except PermissionError:
        # Landlock intentionally hides /proc/self/fd. Scan the complete numeric
        # process limit instead, with a fixed maximum, so high inherited FDs
        # cannot escape the proof.
        soft_limit, _hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        if not 0 < soft_limit <= 1 << 20:
            raise RuntimeError("descriptor limit exceeds the census bound")
        return [fd for fd in range(soft_limit) if _fd_is_open(fd)]
    if len(names) > 64:
        raise RuntimeError("live descriptor census exceeded its fixed bound")
    # Directory enumeration itself transiently occupies one descriptor. Retain
    # only numeric descriptors that are still live after the scan.
    return sorted(
        fd
        for name in names
        if name.isdigit()
        for fd in (int(name),)
        if _fd_is_open(fd)
    )


def scenario_m4b_network_view(
    scenario_id: str, args: argparse.Namespace
) -> dict[str, Any]:
    """Inspect only bounded sandbox route, resolver, and FD state."""
    started = utc_now_iso()

    def bounded_read(path: str) -> dict[str, Any]:
        try:
            with open(path, "rb") as handle:
                payload = handle.read(16 * 1024 + 1)
            return {
                "visible": True,
                "bounded": len(payload) <= 16 * 1024,
                "text": payload[: 16 * 1024].decode("utf-8", errors="replace"),
            }
        except OSError as exc:
            return {
                "visible": False,
                "bounded": True,
                "error_type": type(exc).__name__,
                "errno": exc.errno,
            }

    fds = _bounded_live_fd_census()
    return make_result(
        scenario_id,
        "sandbox-network-view",
        started,
        succeeded=True,
        details={
            "fds": fds,
            "ipv4_route": bounded_read("/proc/net/route"),
            "ipv6_route": bounded_read("/proc/net/ipv6_route"),
            "resolv_conf": bounded_read("/etc/resolv.conf"),
        },
    )


def scenario_m4b_descendant_authority(
    scenario_id: str, args: argparse.Namespace
) -> dict[str, Any]:
    """Prove representative hostile descendants inherit only the fixed proxy."""
    started = utc_now_iso()
    shape = args.base
    allowed_shapes = {
        "child", "grandchild", "setsid", "new-pgroup", "parent-exit",
        "double-fork", "rapid-spawn", "signal-ignore",
    }
    if shape not in allowed_shapes:
        raise ValueError("M4B descendant shape is unsupported")
    host, separator, port_text = args.target.rpartition(":")
    if not separator or not host or not port_text.isdigit():
        raise ValueError("M4B direct fixture target must be host:port")
    result_path = f"/tmp/m4b-descendant-authority-{os.getpid()}.json"

    def probe_and_exit() -> None:
        details: dict[str, Any] = {"shape": shape}
        try:
            with socket.create_connection(("127.0.0.1", 18080), timeout=3.0) as stream:
                stream.sendall(f"DESCENDANT_{shape}".encode("ascii"))
                details["proxy_reply"] = stream.recv(256).decode("ascii")
        except Exception as exc:  # noqa: BLE001
            details["proxy_error"] = f"{type(exc).__name__}: {exc}"
        try:
            with socket.create_connection((host, int(port_text)), timeout=0.5):
                details["direct_succeeded"] = True
        except OSError:
            details["direct_succeeded"] = False
        temporary = result_path + f".{os.getpid()}"
        with open(temporary, "w", encoding="ascii") as handle:
            json.dump(details, handle, sort_keys=True)
        os.replace(temporary, result_path)
        os._exit(0)

    def fork_probe(*, setsid=False, setpgrp=False) -> int:
        pid = os.fork()
        if pid == 0:
            if setsid:
                os.setsid()
            if setpgrp:
                os.setpgrp()
            probe_and_exit()
        return pid

    direct_children: list[int] = []
    if shape == "child":
        direct_children.append(fork_probe())
    elif shape == "grandchild":
        first = os.fork()
        if first == 0:
            grandchild = fork_probe()
            os.waitpid(grandchild, 0)
            os._exit(0)
        direct_children.append(first)
    elif shape == "setsid":
        direct_children.append(fork_probe(setsid=True))
    elif shape == "new-pgroup":
        direct_children.append(fork_probe(setpgrp=True))
    elif shape == "parent-exit":
        first = os.fork()
        if first == 0:
            fork_probe()
            os._exit(0)
        direct_children.append(first)
    elif shape == "double-fork":
        first = os.fork()
        if first == 0:
            os.setsid()
            fork_probe()
            os._exit(0)
        direct_children.append(first)
    elif shape == "rapid-spawn":
        for index in range(8):
            pid = os.fork()
            if pid == 0:
                if index == 0:
                    probe_and_exit()
                os._exit(0)
            direct_children.append(pid)
    elif shape == "signal-ignore":
        pid = os.fork()
        if pid == 0:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            probe_and_exit()
        direct_children.append(pid)

    for child in direct_children:
        try:
            os.waitpid(child, 0)
        except ChildProcessError:
            pass
    deadline = time.monotonic() + 5.0
    while not os.path.exists(result_path) and time.monotonic() < deadline:
        time.sleep(0.01)
    try:
        with open(result_path, encoding="ascii") as handle:
            details = json.load(handle)
    except Exception as exc:  # noqa: BLE001
        return make_result(
            scenario_id, args.target, started, succeeded=False,
            error_type=type(exc).__name__, error_message=str(exc),
            details={"shape": shape},
        )
    finally:
        try:
            os.unlink(result_path)
        except FileNotFoundError:
            pass
    succeeded = (
        details.get("proxy_reply") == "DESCENDANT_PROXY_REPLY"
        and details.get("direct_succeeded") is False
    )
    return make_result(
        scenario_id, args.target, started, succeeded=succeeded, details=details,
    )
# --------------------------------------------------------------------------
# Scenario registry — keep in sync with agenticos.sandbox.policy.SCENARIO_CATALOG
# --------------------------------------------------------------------------

Handler = Callable[[str, argparse.Namespace], dict[str, Any]]

SCENARIOS: dict[str, dict[str, Any]] = {
    "M4B-01": {"handler": scenario_m4b_transport, "needs": (),
                "description": "Relay a canary through fixed 127.0.0.1:18080."},
    "M4B-02": {"handler": scenario_m4b_network_view, "needs": (),
                "description": "Inspect bounded isolated route, resolver, and FD state."},
    "M4B-03": {"handler": scenario_m4b_descendant_authority,
                "needs": ("target", "base"),
                "description": "Probe fixed proxy/direct denial from a descendant shape."},
    "FS-16": {"handler": scenario_m4a_runtime_view, "needs": (),
                "description": "Inspect the fixed M4A /workspace and runtime ABI."},
    "PROC-09": {"handler": scenario_m4a_security_state, "needs": (),
                "description": "Inspect final M4A credentials, capabilities, userns, and FDs."},
    "SOCK-04": {"handler": scenario_connected_fd_send, "needs": ("target",),
                "description": "Attempt use of a deliberately inherited connected socket."},
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
    "FS-06": {"handler": scenario_symlink_write, "needs": ("target",),
              "description": "Attempt to WRITE through a symlink toward a synthetic denied file."},
    "FS-07": {"handler": scenario_rename_across_boundary, "needs": ("target", "base"),
              "description": "Attempt to rename/move a denied file into the workspace."},
    "FS-08": {"handler": scenario_preopened_fd, "needs": ("target",),
              "description": "Attempt to read a denied resource via an inherited pre-opened fd."},
    "FS-09": {"handler": scenario_descendant_denied_read, "needs": ("target",),
              "description": "A descendant (child|grandchild|setsid|doublefork via --base) attempts a denied read."},
    "FS-10": {"handler": scenario_file_read, "needs": ("target",),
              "description": "Read an explicitly allowed read-only file."},
    "FS-11": {"handler": scenario_file_write, "needs": ("target",),
              "description": "Attempt to write an explicitly read-only file."},
    "FS-12": {"handler": scenario_enumerate_fds, "needs": (),
              "description": "Enumerate inherited file descriptors (self-inspection)."},
    "FS-13": {"handler": scenario_boundary_probe, "needs": ("target",),
              "description": "Boundary characterization probe (stat|chmod|setxattr|socket_connect via --base)."},
    "FS-14": {"handler": scenario_file_truncate, "needs": ("target",),
              "description": "Attempt truncate() or open(O_TRUNC) selected by --base."},
    "FS-15": {"handler": scenario_link_or_rename, "needs": ("target", "base"),
              "description": "Attempt hardlink or rename to the --base destination."},
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
    "NET-03": {"handler": scenario_udp_exchange, "needs": ("target",),
               "description": "Attempt UDP exchange with a fixture-controlled host endpoint."},
    "SOCK-01": {"handler": scenario_unix_connect, "needs": ("target",),
                "description": "Attempt connection to a fixture-created pathname Unix socket when supported."},
    "SOCK-02": {"handler": scenario_unix_connect, "needs": ("target",),
                "description": "Attempt connection to a fixture-created abstract Unix socket."},
    "SOCK-03": {"handler": scenario_private_unix_socket, "needs": (),
                "description": "Exchange data through a sandbox-private /tmp Unix socket."},
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
    parser.add_argument("--canary", default="AOS_CANARY_m4b_transport",
                        help="Synthetic ASCII canary for the fixed M4B fixture.")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="Bounded timeout for a synthetic network operation.")
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
