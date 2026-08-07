"""Shared helpers for the Phase Zero conformance tests.

Everything here operates only on synthetic fixture resources. No test may
touch real host paths, real credentials, or the network beyond 127.0.0.1
fixture listeners.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

WORKER_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "hostile_worker.py"


def minimal_env(**extra: str) -> dict[str, str]:
    """An explicit, minimal environment for child processes.

    Deliberately does NOT forward the real process environment — only the
    few variables a Python child needs to start on this platform.
    """
    env: dict[str, str] = {}
    if os.environ.get("PATH"):
        env["PATH"] = os.environ["PATH"]
    if os.name == "nt":
        for key in ("SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"):
            if key in os.environ:
                env[key] = os.environ[key]
    else:
        env["HOME"] = os.environ.get("HOME", "/tmp")
    env.update(extra)
    return env


def run_worker(
    scenario: str,
    *,
    target: Optional[str | os.PathLike[str]] = None,
    env_name: Optional[str] = None,
    base: Optional[str | os.PathLike[str]] = None,
    cwd: Optional[str | os.PathLike[str]] = None,
    env: Optional[dict[str, str]] = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Run the hostile worker directly and return its parsed JSON result."""
    argv = [sys.executable, str(WORKER_PATH), "--scenario", scenario]
    if target is not None:
        argv += ["--target", str(target)]
    if env_name is not None:
        argv += ["--env-name", env_name]
    if base is not None:
        argv += ["--base", str(base)]
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd is not None else None,
        env=env if env is not None else minimal_env(),
        timeout=timeout,
    )
    assert proc.returncode == 0, f"worker exited {proc.returncode}: {proc.stderr}"
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert lines, f"worker produced no JSON output; stderr={proc.stderr!r}"
    return json.loads(lines[-1])


def pid_alive(pid: int) -> bool:
    """Cross-platform liveness check for a specific PID."""
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = ctypes.c_ulong(0)
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def kill_pid(pid: int) -> None:
    """Force-kill a specific PID (never a process name)."""
    try:
        if os.name == "nt":
            os.kill(pid, signal.SIGTERM)  # TerminateProcess on Windows
        else:
            os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def wait_for(predicate, timeout: float = 5.0, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


@contextmanager
def tcp_fixture_server(banner: bytes = b"fixture-banner\n") -> Iterator[str]:
    """A 127.0.0.1 TCP listener on an ephemeral port. Yields 'host:port'."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    srv.settimeout(0.25)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                conn.sendall(banner)
            finally:
                conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{port}"
    finally:
        stop.set()
        srv.close()
        thread.join(timeout=5.0)


@contextmanager
def unix_fixture_server(path: Path, banner: bytes = b"fixture-unix-banner\n") -> Iterator[str]:
    """A pathname Unix-socket listener. Yields the socket path.

    Skips-worthy environments (no AF_UNIX, path too long) raise OSError from
    bind; callers should catch and pytest.skip.
    """
    if not hasattr(socket, "AF_UNIX"):
        raise OSError("AF_UNIX not supported on this platform")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    srv.listen(4)
    srv.settimeout(0.25)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                conn.sendall(banner)
            finally:
                conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield str(path)
    finally:
        stop.set()
        srv.close()
        thread.join(timeout=5.0)
        path.unlink(missing_ok=True)
