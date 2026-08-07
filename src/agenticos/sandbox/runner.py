"""Runner contract for the Phase Zero conformance harness.

=====================================================================
WARNING: UnsafeLocalRunner IS NOT A SECURITY SANDBOX.

It executes the hostile worker directly on the host with NO filesystem,
network, process, or environment isolation whatsoever. Denied actions are
EXPECTED to succeed under this runner. It exists only to prove that the
conformance harness itself (fixtures, worker, evidence, policy comparison)
works deterministically. Future real sandbox backends implement the same
:class:`SandboxRunner` interface, and the identical attack corpus is then
re-run against them.
=====================================================================
"""

from __future__ import annotations

import abc
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .models import AttackResult, ProcessIdentity, ProcessResult, utc_now_iso

DEFAULT_TIMEOUT_SECONDS = 30.0


class SandboxRunner(abc.ABC):
    """Interface every sandbox backend (real or synthetic) must implement."""

    name: str
    worker_path: Path

    @abc.abstractmethod
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | os.PathLike[str],
        env: Mapping[str, str],
        timeout: Optional[float] = None,
    ) -> ProcessResult:
        """Execute ``argv`` (never via a shell) and capture the result."""

    def build_scenario_argv(
        self,
        scenario_id: str,
        *,
        target: str | os.PathLike[str] | None = None,
        env_name: Optional[str] = None,
        base: str | os.PathLike[str] | None = None,
    ) -> list[str]:
        argv = [sys.executable, str(self.worker_path), "--scenario", scenario_id]
        if target is not None:
            argv += ["--target", str(target)]
        if env_name is not None:
            argv += ["--env-name", env_name]
        if base is not None:
            argv += ["--base", str(base)]
        return argv

    def run_scenario(
        self,
        scenario_id: str,
        *,
        cwd: str | os.PathLike[str],
        env: Mapping[str, str],
        target: str | os.PathLike[str] | None = None,
        env_name: Optional[str] = None,
        base: str | os.PathLike[str] | None = None,
        timeout: Optional[float] = None,
    ) -> AttackResult:
        """Run one hostile-worker scenario and parse its JSON result."""
        argv = self.build_scenario_argv(
            scenario_id, target=target, env_name=env_name, base=base
        )
        proc = self.run(argv, cwd=cwd, env=env, timeout=timeout)
        result = self._parse_result(scenario_id, proc, target)
        result.process = proc
        return result

    @staticmethod
    def _parse_result(
        scenario_id: str,
        proc: ProcessResult,
        target: str | os.PathLike[str] | None,
    ) -> AttackResult:
        try:
            lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
            payload = json.loads(lines[-1])
            result = AttackResult.from_dict(payload)
            if result.scenario_id != scenario_id:
                raise ValueError(
                    f"scenario mismatch: expected {scenario_id}, got {result.scenario_id}"
                )
            return result
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            return AttackResult(
                scenario_id=scenario_id,
                attempted=False,
                succeeded=False,
                target=str(target) if target is not None else "",
                error_type="RunnerError",
                error_message=(
                    f"could not parse worker JSON: {exc}; "
                    f"exit={proc.exit_code} timed_out={proc.timed_out} "
                    f"stderr={proc.stderr[:500]!r}"
                ),
                started_at=proc.started_at,
                finished_at=proc.finished_at,
            )


class UnsafeLocalRunner(SandboxRunner):
    """Direct, unsandboxed local execution of the hostile worker.

    THIS RUNNER IS NOT A SECURITY SANDBOX. See the module docstring.
    """

    name = "unsafe-local"

    def __init__(
        self,
        worker_path: str | os.PathLike[str],
        default_timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.worker_path = Path(worker_path)
        if not self.worker_path.is_file():
            raise FileNotFoundError(f"hostile worker not found: {self.worker_path}")
        self.default_timeout = float(default_timeout)

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | os.PathLike[str],
        env: Mapping[str, str],
        timeout: Optional[float] = None,
    ) -> ProcessResult:
        argv = [str(a) for a in argv]
        timeout = self.default_timeout if timeout is None else float(timeout)
        started_at = utc_now_iso()
        proc = subprocess.Popen(
            argv,
            cwd=str(cwd),
            env={str(k): str(v) for k, v in env.items()},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,  # hard requirement: argv array only, never a shell
            start_new_session=(os.name != "nt"),  # own process group on POSIX
        )
        # Identity must be captured while the process is alive — after
        # communicate()/reaping, /proc/<pid> is gone on Linux.
        identity = ProcessIdentity.from_pid(proc.pid)
        pgid = identity.process_group_id
        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill_tree(proc)
            stdout, stderr = proc.communicate()
        finished_at = utc_now_iso()
        rc = proc.returncode
        exit_code = rc if rc is not None and rc >= 0 else None
        sig = -rc if rc is not None and rc < 0 else None
        return ProcessResult(
            pid=proc.pid,
            argv=argv,
            exit_code=exit_code,
            signal=sig,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            started_at=started_at,
            finished_at=finished_at,
            process_group_id=pgid,
            identity=identity,
        )

    @staticmethod
    def _kill_tree(proc: subprocess.Popen) -> None:
        """Best-effort kill of the whole process tree rooted at ``proc``."""
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
            )
            try:
                proc.kill()
            except OSError:
                pass
        else:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    proc.kill()
                except OSError:
                    pass
