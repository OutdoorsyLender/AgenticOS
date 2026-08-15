"""EXPERIMENTAL cgroup v2 / systemd-scope process containment runner.

=====================================================================
CgroupProcessRunner IS EXPERIMENTAL AND IS **NOT** A SECURITY SANDBOX.

It proves PROCESS CONTAINMENT ONLY: adversarial process trees (fork,
double-fork, setsid, new process groups, signal-ignoring children,
lingering children) are placed inside a task-owned transient systemd scope
(cgroup v2) and deterministically terminated with a bounded escalation
sequence. It provides NO filesystem, network, credential, Unix-socket, or
Windows-host isolation.
=====================================================================

Architecture:

    AgenticOS
      -> transient task scope (systemd-run --user --scope --collect)
        -> cgroup v2 hierarchy (discovered dynamically, never hard-coded)
          -> hostile worker -> children -> grandchildren

Termination invariant: a contained task is TERMINATED only when the task
cgroup's recursive population state (``cgroup.events`` -> ``populated 0``)
confirms the hierarchy is empty. Root-process exit alone is NEVER enough.
"""

from __future__ import annotations

import errno
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional, Protocol, Sequence

from .capabilities import (
    CapabilityStatus,
    HostCapabilityDetector,
    parse_cgroup_events,
    parse_proc_cgroup,
)
from .evidence import EvidenceCollector
from .models import ProcessIdentity, ProcessResult, utc_now_iso
from .runner import DEFAULT_TIMEOUT_SECONDS, SandboxRunner

# Evidence event kinds emitted by this module.
EV_HOST_CAPABILITY_OBSERVED = "HOST_CAPABILITY_OBSERVED"
EV_CONTAINMENT_CREATED = "CONTAINMENT_CREATED"
EV_PROCESS_STARTED = "PROCESS_STARTED"
EV_SIGNAL_SENT = "SIGNAL_SENT"
EV_FORCED_KILL_REQUESTED = "FORCED_KILL_REQUESTED"
EV_CGROUP_EMPTY_VERIFIED = "CGROUP_EMPTY_VERIFIED"
EV_CONTAINMENT_DESTROYED = "CONTAINMENT_DESTROYED"
EV_CONTAINMENT_FAILURE = "CONTAINMENT_FAILURE"


class ContainmentUnavailableError(RuntimeError):
    """Raised when the host cannot provide the required containment."""


class ContainmentState(str, Enum):
    RUNNING = "RUNNING"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    SIGINT_SENT = "SIGINT_SENT"
    SIGTERM_SENT = "SIGTERM_SENT"
    FORCED_KILL_REQUESTED = "FORCED_KILL_REQUESTED"
    VERIFY_EMPTY = "VERIFY_EMPTY"
    TERMINATED = "TERMINATED"
    FAILED = "FAILED"


class ScopeEvidenceState(str, Enum):
    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class ScopeEvidence:
    state: ScopeEvidenceState
    cgroup_path: Path | None
    detail: str


@dataclass
class CancellationConfig:
    """Bounded escalation timing. Test-friendly defaults; configure for
    production elsewhere — nothing here is a hard-coded production value."""

    sigint_grace: float = 1.0
    sigterm_grace: float = 1.0
    empty_verify_timeout: float = 3.0
    poll_interval: float = 0.05


@dataclass
class ContainmentSupport:
    supported: bool
    reasons: list[str] = field(default_factory=list)
    cgroup_kill_usable: Optional[bool] = None  # None = not verified


# --------------------------------------------------------------------------
# Backend abstraction: the escalation logic is tested against fakes; the real
# backend is a thin systemd/cgroup adapter exercised by gated integration tests.
# --------------------------------------------------------------------------

class ScopeBackend(Protocol):
    def signal_unit(self, unit: str, sig: str) -> None: ...
    def cgroup_kill(self, cgroup_path: Path) -> bool: ...
    def cgroup_populated(self, cgroup_path: Path) -> Optional[bool]: ...
    def unit_active(self, unit: str) -> bool: ...
    def stop_unit(self, unit: str) -> None: ...


def wait_cgroup_empty(
    backend: ScopeBackend,
    cgroup_path: Path,
    timeout: float,
    poll_interval: float = 0.05,
) -> bool:
    """Wait until the cgroup hierarchy is recursively empty (populated 0).

    A vanished cgroup counts as empty: an unpopulated cgroup with --collect
    is garbage-collected by systemd, and a removed hierarchy contains nothing.
    """
    deadline = time.monotonic() + timeout
    while True:
        populated = backend.cgroup_populated(cgroup_path)
        if populated is None or populated is False:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll_interval)


def cancel_contained(
    backend: ScopeBackend,
    unit: str,
    cgroup_path: Path,
    config: CancellationConfig,
    collector: Optional[EvidenceCollector] = None,
) -> tuple[ContainmentState, dict]:
    """Bounded cancellation escalation:

    CANCEL_REQUESTED -> SIGINT -> grace -> SIGTERM -> grace
    -> cgroup.kill (or SIGKILL fallback) -> verify populated 0 -> TERMINATED.

    Signals always target the task's containment unit/cgroup — never global
    process-name searches. Returns (final state, details). FAILED means the
    hierarchy remained populated after the final kill; callers MUST treat
    that as a loud failure.
    """
    details: dict = {"unit": unit, "cgroup_path": str(cgroup_path)}

    def emit(kind: str, **payload) -> None:
        if collector is not None:
            collector.record(kind, payload)

    emit(ContainmentState.CANCEL_REQUESTED.value, unit=unit)

    for sig, grace in (
        ("SIGINT", config.sigint_grace),
        ("SIGTERM", config.sigterm_grace),
    ):
        backend.signal_unit(unit, sig)
        details[f"{sig.lower()}_sent"] = True
        emit(EV_SIGNAL_SENT, unit=unit, signal=sig)
        if wait_cgroup_empty(backend, cgroup_path, grace, config.poll_interval):
            emit(EV_CGROUP_EMPTY_VERIFIED, unit=unit, after=sig)
            details["terminated_by"] = sig
            return ContainmentState.TERMINATED, details

    emit(EV_FORCED_KILL_REQUESTED, unit=unit)
    if backend.cgroup_kill(cgroup_path):
        details["forced_kill_method"] = "cgroup.kill"
    else:
        # Documented testing fallback ONLY when cgroup.kill is unavailable or
        # not permitted: SIGKILL every process in the task unit via systemd.
        # This is NOT equivalent-security; capability reports expose it.
        details["forced_kill_method"] = "systemd SIGKILL (cgroup.kill unavailable)"
        backend.signal_unit(unit, "SIGKILL")
        emit(EV_SIGNAL_SENT, unit=unit, signal="SIGKILL")

    if wait_cgroup_empty(backend, cgroup_path, config.empty_verify_timeout,
                         config.poll_interval):
        emit(EV_CGROUP_EMPTY_VERIFIED, unit=unit, after=details["forced_kill_method"])
        details["terminated_by"] = details["forced_kill_method"]
        return ContainmentState.TERMINATED, details

    emit(EV_CONTAINMENT_FAILURE, unit=unit,
         reason="cgroup hierarchy still populated after final kill")
    details["terminated_by"] = None
    return ContainmentState.FAILED, details


# --------------------------------------------------------------------------
# Real systemd/cgroup v2 backend (thin adapter; Linux only)
# --------------------------------------------------------------------------

class SystemdScopeBackend:
    """Thin adapter over systemctl/systemd-run and cgroup v2 sysfs files.

    All operations are scoped to explicitly named transient user units —
    never global state, never process-name matching.
    """

    def __init__(
        self,
        cgroup_root: str | Path = "/sys/fs/cgroup",
        environ: Optional[Mapping[str, str]] = None,
    ) -> None:
        self.cgroup_root = Path(cgroup_root)
        self.systemctl = shutil.which("systemctl")
        self.systemd_run = shutil.which("systemd-run")
        base = dict(os.environ if environ is None else environ)
        uid = os.getuid() if hasattr(os, "getuid") else None
        runtime_dir = Path(f"/run/user/{uid}") if uid is not None else None
        if runtime_dir is not None and runtime_dir.exists():
            base.setdefault("XDG_RUNTIME_DIR", str(runtime_dir))
            bus = runtime_dir / "bus"
            if bus.exists():
                base.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={bus}")
        self._ctl_env = base

    def _ctl(self, args: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess:
        if self.systemctl is None:
            raise ContainmentUnavailableError("systemctl not found")
        return subprocess.run(
            [self.systemctl, "--user", *args],
            capture_output=True, text=True, env=self._ctl_env, timeout=timeout,
        )

    def control_group(self, unit: str) -> Optional[Path]:
        """Discover the unit's cgroup path dynamically — never assumed."""
        proc = self._ctl(["show", unit, "-p", "ControlGroup", "--value"])
        rel = proc.stdout.strip()
        if proc.returncode != 0 or not rel or rel == "/":
            return None
        return self.cgroup_root / rel.lstrip("/")

    def scope_evidence(self, unit: str) -> ScopeEvidence:
        """Return typed unit evidence; lookup errors are never absence proof."""
        try:
            proc = self._ctl(
                [
                    "show",
                    unit,
                    "-p",
                    "LoadState",
                    "-p",
                    "ActiveState",
                    "-p",
                    "ControlGroup",
                ]
            )
        except (OSError, subprocess.SubprocessError, ContainmentUnavailableError) as exc:
            return ScopeEvidence(
                ScopeEvidenceState.UNKNOWN,
                None,
                f"scope lookup failed: {type(exc).__name__}",
            )
        if proc.returncode != 0:
            return ScopeEvidence(
                ScopeEvidenceState.UNKNOWN,
                None,
                f"scope lookup exit {proc.returncode}",
            )
        properties: dict[str, str] = {}
        for line in proc.stdout.splitlines():
            if "=" not in line:
                continue
            name, value = line.split("=", 1)
            if name in properties:
                return ScopeEvidence(
                    ScopeEvidenceState.UNKNOWN,
                    None,
                    "duplicate scope property",
                )
            properties[name] = value
        if set(properties) != {"LoadState", "ActiveState", "ControlGroup"}:
            return ScopeEvidence(
                ScopeEvidenceState.UNKNOWN,
                None,
                "incomplete scope properties",
            )
        load_state = properties["LoadState"]
        control_group = properties["ControlGroup"]
        if load_state == "not-found" and control_group in {"", "/"}:
            return ScopeEvidence(
                ScopeEvidenceState.ABSENT, None, "unit positively not found"
            )
        if load_state != "not-found" and control_group not in {"", "/"}:
            return ScopeEvidence(
                ScopeEvidenceState.PRESENT,
                self.cgroup_root / control_group.lstrip("/"),
                "unit and control group observed",
            )
        return ScopeEvidence(
            ScopeEvidenceState.UNKNOWN,
            None,
            "contradictory scope properties",
        )

    def signal_unit(self, unit: str, sig: str) -> None:
        self._ctl(["kill", f"--signal={sig}", unit])

    def cgroup_kill(self, cgroup_path: Path) -> bool:
        kill_file = cgroup_path / "cgroup.kill"
        try:
            kill_file.write_text("1")
            return True
        except (OSError, PermissionError):
            return False

    def cgroup_populated(self, cgroup_path: Path) -> Optional[bool]:
        events_path = cgroup_path / "cgroup.events"
        try:
            events = parse_cgroup_events(events_path.read_text())
        except FileNotFoundError:
            return None  # cgroup gone == nothing inside
        except OSError as exc:
            # cgroupfs can report ENODEV when systemd removes the hierarchy
            # during an in-progress read. Accept it only after independently
            # observing that the evidence object is now gone.
            if exc.errno == errno.ENODEV:
                try:
                    events_path.stat()
                except FileNotFoundError:
                    return None
                except OSError:
                    raise
            raise
        if "populated" not in events:
            raise ContainmentUnavailableError(
                f"cgroup.events lacks populated evidence: {cgroup_path}"
            )
        return bool(events["populated"])

    def unit_active(self, unit: str) -> bool:
        proc = self._ctl(["show", unit, "-p", "ActiveState,LoadState", "--value"])
        lines = proc.stdout.split()
        if not lines or "not-found" in lines:
            return False
        return lines[0] in ("active", "activating")

    def stop_unit(self, unit: str) -> None:
        try:
            self._ctl(["stop", unit])
        except Exception:  # noqa: BLE001 - best-effort cleanup
            pass


# --------------------------------------------------------------------------
# The runner
# --------------------------------------------------------------------------

class CgroupProcessRunner(SandboxRunner):
    """EXPERIMENTAL process-containment runner (cgroup v2 via systemd scopes).

    NOT A SECURITY SANDBOX — process containment only. See module docstring.
    """

    name = "cgroup-experimental"

    def __init__(
        self,
        worker_path: str | os.PathLike[str],
        default_timeout: float = DEFAULT_TIMEOUT_SECONDS,
        cancellation: Optional[CancellationConfig] = None,
        collector: Optional[EvidenceCollector] = None,
        backend: Optional[SystemdScopeBackend] = None,
        cgroup_root: str | Path = "/sys/fs/cgroup",
        proc_root: str | Path = "/proc",
    ) -> None:
        self.worker_path = Path(worker_path)
        if not self.worker_path.is_file():
            raise FileNotFoundError(f"hostile worker not found: {self.worker_path}")
        self.default_timeout = float(default_timeout)
        self.cancellation = cancellation or CancellationConfig()
        self.collector = collector
        self.cgroup_root = Path(cgroup_root)
        self.proc_root = Path(proc_root)
        self.backend = backend or SystemdScopeBackend(cgroup_root=self.cgroup_root)
        self._support: Optional[ContainmentSupport] = None

    # -- capability gating --------------------------------------------------

    def check_support(self, refresh: bool = False) -> ContainmentSupport:
        """Read-only support assessment (system capability, not permission)."""
        if self._support is not None and not refresh:
            return self._support
        reasons: list[str] = []
        report = HostCapabilityDetector(cgroup_root=self.cgroup_root).detect()

        def need(name: str, ok_statuses=(CapabilityStatus.SUPPORTED,)) -> bool:
            status = report.status_of(name)
            if status not in ok_statuses:
                reasons.append(f"{name}={status.value}")
                return False
            return True

        need("host_platform_linux")
        need("cgroup_v2_mounted")
        need("cgroup_events_available")
        need("systemd_running")
        need("systemd_available")
        need("systemd_user_bus")
        need("process_groups_available")
        if self.backend.systemd_run is None:
            reasons.append("systemd-run not found on PATH")
        cgroup_kill = report.status_of("cgroup_kill_available")
        self._support = ContainmentSupport(
            supported=not reasons,
            reasons=reasons,
            cgroup_kill_usable=(
                True
                if cgroup_kill is CapabilityStatus.SUPPORTED
                else False
                if cgroup_kill is CapabilityStatus.UNSUPPORTED
                else None
            ),
        )
        return self._support

    @classmethod
    def probe(cls, cgroup_root: str | Path = "/sys/fs/cgroup") -> ContainmentSupport:
        """Permission probe: actually create + destroy a trivial transient
        user scope. This is the ONLY way to distinguish SYSTEM CAPABILITY
        from CURRENT USER PERMISSION. The scope runs `true` and is collected
        automatically; nothing persistent is created."""
        backend = SystemdScopeBackend(cgroup_root=cgroup_root)
        if backend.systemd_run is None:
            return ContainmentSupport(False, ["systemd-run not found on PATH"])
        unit = f"aos-probe-{uuid.uuid4().hex[:12]}"
        true_bin = shutil.which("true") or "/usr/bin/true"
        try:
            proc = subprocess.run(
                [backend.systemd_run, "--user", "--scope", "--quiet", "--collect",
                 f"--unit={unit}", "--", true_bin],
                capture_output=True, text=True, env=backend._ctl_env, timeout=15.0,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            backend.stop_unit(f"{unit}.scope")
            return ContainmentSupport(False, [f"scope probe raised {type(exc).__name__}: {exc}"])
        if proc.returncode != 0:
            return ContainmentSupport(
                False,
                ["transient user scope creation failed: "
                 f"rc={proc.returncode} stderr={proc.stderr.strip()[:200]!r}"],
            )
        if backend.unit_active(f"{unit}.scope"):
            backend.stop_unit(f"{unit}.scope")
            return ContainmentSupport(False, ["probe scope did not self-collect"])
        return ContainmentSupport(True, ["transient user scope created and collected"])

    # -- SandboxRunner API --------------------------------------------------

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | os.PathLike[str],
        env: Mapping[str, str],
        timeout: Optional[float] = None,
    ) -> ProcessResult:
        support = self.check_support()
        if not support.supported:
            raise ContainmentUnavailableError(
                "cgroup process containment unavailable: " + "; ".join(support.reasons)
            )

        argv = [str(a) for a in argv]
        timeout = self.default_timeout if timeout is None else float(timeout)
        unit = f"aos-task-{uuid.uuid4().hex[:12]}"
        # systemd-run names the unit '<unit>.scope'; every systemctl lookup
        # must use the FULL name — a bare name resolves to '<unit>.service'
        # and silently finds nothing.
        scope = f"{unit}.scope"
        full_argv = [
            self.backend.systemd_run, "--user", "--scope", "--quiet", "--collect",
            f"--unit={unit}", "--", *argv,
        ]
        run_env = {str(k): str(v) for k, v in env.items()}
        for key in ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
            if key in self.backend._ctl_env:
                run_env.setdefault(key, self.backend._ctl_env[key])

        started_at = utc_now_iso()
        proc = subprocess.Popen(
            full_argv,
            cwd=str(cwd),
            env=run_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            start_new_session=True,
        )
        identity = ProcessIdentity.from_pid(proc.pid)
        cgroup_path = self._discover_cgroup(scope, proc.pid)
        self._emit(EV_CONTAINMENT_CREATED, unit=scope,
                   cgroup_path=str(cgroup_path) if cgroup_path else None)
        self._emit(EV_PROCESS_STARTED, unit=scope, pid=proc.pid,
                   start_time_ticks=identity.start_time_ticks)

        containment_state = ContainmentState.RUNNING.value
        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            state = self._cancel(scope, cgroup_path, proc)
            containment_state = state.value
            stdout, stderr = proc.communicate()

        # Even after a clean root exit, descendants may linger (PROC-05/06/08).
        # Containment contract: reap anything left inside the task boundary.
        if cgroup_path is not None and not wait_cgroup_empty(
            self.backend, cgroup_path, 0.2, self.cancellation.poll_interval
        ):
            state = self._cancel(scope, cgroup_path, proc)
            containment_state = state.value
        elif cgroup_path is not None:
            containment_state = (
                ContainmentState.TERMINATED.value
                if containment_state == ContainmentState.RUNNING.value
                else containment_state
            )
            self._emit(EV_CGROUP_EMPTY_VERIFIED, unit=scope, after="clean exit")
        else:
            containment_state = ContainmentState.FAILED.value
            self._emit(EV_CONTAINMENT_FAILURE, unit=scope,
                       reason="cgroup path could not be discovered; "
                              "termination invariant cannot be verified")

        self.backend.stop_unit(scope)
        if self.backend.unit_active(scope):
            containment_state = ContainmentState.FAILED.value
            self._emit(EV_CONTAINMENT_FAILURE, unit=scope,
                       reason="unit still active after cleanup")
        else:
            self._emit(EV_CONTAINMENT_DESTROYED, unit=scope)

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
            process_group_id=identity.process_group_id,
            identity=identity,
            containment_unit=scope,
            containment_cgroup=str(cgroup_path) if cgroup_path else None,
            containment_state=containment_state,
        )

    # -- internals ----------------------------------------------------------

    def _cancel(
        self,
        unit: str,
        cgroup_path: Optional[Path],
        proc: subprocess.Popen,
    ) -> ContainmentState:
        if cgroup_path is None:
            # Cannot honor the invariant without the cgroup; last-resort
            # process-group kill, explicitly reported as FAILED containment.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    proc.kill()
                except OSError:
                    pass
            return ContainmentState.FAILED
        state, _details = cancel_contained(
            self.backend, unit, cgroup_path, self.cancellation, self.collector
        )
        return state

    def _discover_cgroup(
        self, scope: str, pid: int, timeout: float = 5.0
    ) -> Optional[Path]:
        """Discover the task cgroup path dynamically — never assumed.

        Primary source is /proc/<pid>/cgroup of the scope process itself:
        it proves actual containment membership and is available the instant
        the process exists, unlike `systemctl show`, which races with
        collection of very short-lived scopes. Falls back to the unit's
        ControlGroup property. Returns None only if neither source confirms
        membership before the deadline (caller treats that as FAILED).
        """
        suffix = "/" + scope
        proc_cgroup = self.proc_root / str(pid) / "cgroup"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                rel = parse_proc_cgroup(proc_cgroup.read_text())
            except OSError:
                rel = None
            if rel and rel.endswith(suffix):
                candidate = self.cgroup_root / rel.lstrip("/")
                if candidate.exists():
                    return candidate
            path = self.backend.control_group(scope)
            if path is not None and path.exists():
                return path
            time.sleep(0.01)
        return None

    def _emit(self, kind: str, **payload) -> None:
        if self.collector is not None:
            self.collector.record(kind, payload)
