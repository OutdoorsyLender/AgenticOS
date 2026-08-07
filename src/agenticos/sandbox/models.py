"""Core typed models for the Phase Zero sandbox conformance harness.

These models describe *synthetic* attack scenarios, their observed outcomes,
and the evidence trail. They are deliberately small so they can evolve, and
they will be reused unchanged when the real AgenticOS sandbox runner exists.
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

TEMP_ROOT_PLACEHOLDER = "<TEMP_ROOT>"


def utc_now_iso() -> str:
    """Current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def new_run_id() -> str:
    return f"run-{uuid.uuid4().hex[:16]}"


def new_event_id() -> str:
    return f"evt-{uuid.uuid4().hex[:16]}"


class ScenarioCategory(str, Enum):
    FILESYSTEM = "filesystem"
    ENVIRONMENT = "environment"
    PROCESS = "process"
    NETWORK = "network"
    SOCKET = "socket"
    WRITE = "write"


class PolicyExpectation(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"  # represented, not implemented in Phase Zero


class ConformanceStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNSUPPORTED = "UNSUPPORTED"
    ERROR = "ERROR"


@dataclass
class AttackScenario:
    """Static description of one hostile probe in the corpus."""

    id: str
    category: str
    description: str
    target_kind: str
    expected_policy: str  # PolicyExpectation value

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_stat_start_time(stat_text: str) -> Optional[int]:
    """Extract the process start time (clock ticks since boot) from
    /proc/<pid>/stat content. Robust against comm values containing spaces
    or parentheses by parsing after the final ')'."""
    try:
        after_comm = stat_text.rsplit(")", 1)[1].split()
        # Fields after comm start at field 3 (state); starttime is field 22,
        # i.e. index 19 of the remainder.
        return int(after_comm[19])
    except (IndexError, ValueError):
        return None


_BOOT_ID_CACHE: dict[str, Optional[str]] = {}


def read_boot_id(proc_root: str | Path = "/proc") -> Optional[str]:
    """The kernel boot id — combined with PID + start time this makes a
    process identity robust against PID reuse within a boot."""
    key = str(proc_root)
    if key not in _BOOT_ID_CACHE:
        try:
            _BOOT_ID_CACHE[key] = (
                (Path(proc_root) / "sys" / "kernel" / "random" / "boot_id")
                .read_text()
                .strip()
            )
        except OSError:
            _BOOT_ID_CACHE[key] = None
    return _BOOT_ID_CACHE[key]


@dataclass
class ProcessIdentity:
    """Durable-ish identity for a process: PID alone is unsafe (PID reuse),
    so combine PID + process start time + kernel boot id where available."""

    pid: int
    process_group_id: Optional[int] = None
    start_time_ticks: Optional[int] = None
    boot_id: Optional[str] = None

    @classmethod
    def from_pid(
        cls, pid: int, proc_root: str | Path = "/proc"
    ) -> "ProcessIdentity":
        start_time: Optional[int] = None
        try:
            start_time = parse_stat_start_time(
                (Path(proc_root) / str(pid) / "stat").read_text()
            )
        except OSError:
            start_time = None
        pgid: Optional[int] = None
        if os.name != "nt":
            try:
                pgid = os.getpgid(pid)
            except OSError:
                pgid = None
        return cls(
            pid=pid,
            process_group_id=pgid,
            start_time_ticks=start_time,
            boot_id=read_boot_id(proc_root),
        )

    def matches_current(self, proc_root: str | Path = "/proc") -> bool:
        """True only if a live process with this PID has the same start time
        and boot id — i.e. it really is the same process, not a reused PID."""
        try:
            current = parse_stat_start_time(
                (Path(proc_root) / str(self.pid) / "stat").read_text()
            )
        except OSError:
            return False
        if self.start_time_ticks is None or current is None:
            return False
        return (
            current == self.start_time_ticks
            and read_boot_id(proc_root) == self.boot_id
        )


@dataclass
class ProcessResult:
    """Captured result of a single child process execution."""

    pid: int
    argv: list[str]
    exit_code: Optional[int]
    signal: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool
    started_at: str
    finished_at: str
    # POSIX process group id; None on Windows (a future Windows backend would
    # record a Job Object identifier instead — keep this platform-typed).
    process_group_id: Optional[int] = None
    # Stable process identity (PID + start time + boot id) where obtainable.
    identity: Optional[ProcessIdentity] = None
    # Containment metadata, set only by containment backends.
    containment_unit: Optional[str] = None
    containment_cgroup: Optional[str] = None
    containment_state: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackResult:
    """Machine-readable outcome of one attempted hostile action.

    ``succeeded`` refers to the *attack action* itself (the read happened, the
    connection opened, the child spawned), not to policy conformance.
    """

    scenario_id: str
    attempted: bool
    succeeded: bool
    target: str = ""
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    started_at: str = ""
    finished_at: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    # Attached by runners after execution; never emitted by the worker itself.
    process: Optional[ProcessResult] = field(default=None, repr=False)

    def to_dict(self, include_process: bool = False) -> dict[str, Any]:
        d: dict[str, Any] = {
            "scenario_id": self.scenario_id,
            "attempted": self.attempted,
            "succeeded": self.succeeded,
            "target": self.target,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "details": self.details,
        }
        if include_process and self.process is not None:
            d["process"] = self.process.to_dict()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackResult":
        known = {
            "scenario_id",
            "attempted",
            "succeeded",
            "target",
            "error_type",
            "error_message",
            "started_at",
            "finished_at",
            "details",
        }
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class EvidenceRecord:
    """One structured evidence event belonging to a conformance run."""

    schema_version: str
    event_id: str
    run_id: str
    scenario_id: Optional[str]
    timestamp: str
    kind: str
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass
class SandboxPolicy:
    """Expected outcome per scenario id."""

    name: str
    version: str
    expectations: dict[str, str]  # scenario id -> PolicyExpectation value

    def expectation_for(self, scenario_id: str) -> PolicyExpectation:
        return PolicyExpectation(self.expectations[scenario_id])

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FixtureLayout:
    """Paths and canaries of one synthetic hostile-test environment.

    Everything lives under ``root`` and nothing outside it may be touched.
    """

    root: Path
    assigned_worktree: Path
    sibling_worktree: Path
    agenticos_private: Path
    fake_home: Path
    task_tmp: Path
    sockets_dir: Path
    allowed_file: Path
    denied_sibling_file: Path
    evidence_secret_file: Path
    fake_state_file: Path
    fake_ssh_key: Path
    fake_credentials_file: Path
    env_secret_name: str
    harmless_env_name: str
    canaries: dict[str, str]
    symlink_supported: bool = False

    def cleanup(self) -> None:
        """Remove the entire fixture root. Raises on failure (loud cleanup)."""
        shutil.rmtree(self.root)

    def normalize(self, value: str) -> str:
        """Replace the absolute fixture root with a stable placeholder."""
        return value.replace(str(self.root), TEMP_ROOT_PLACEHOLDER)


@dataclass
class ConformanceRunResult:
    """Aggregated outcome of running scenarios against a policy."""

    run_id: str
    runner_name: str
    policy_name: str
    policy_version: str
    started_at: str
    finished_at: str
    results: list[AttackResult]
    conformance: dict[str, str]  # scenario id -> ConformanceStatus value

    @property
    def passed(self) -> bool:
        return all(s == ConformanceStatus.PASS.value for s in self.conformance.values())

    def status_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for status in self.conformance.values():
            counts[status] = counts.get(status, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "runner_name": self.runner_name,
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "results": [r.to_dict() for r in self.results],
            "conformance": self.conformance,
            "status_counts": self.status_counts(),
            "passed": self.passed,
        }
