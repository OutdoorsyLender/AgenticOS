"""Core typed models for the Phase Zero sandbox conformance harness.

These models describe *synthetic* attack scenarios, their observed outcomes,
and the evidence trail. They are deliberately small so they can evolve, and
they will be reused unchanged when the real AgenticOS sandbox runner exists.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

TEMP_ROOT_PLACEHOLDER = "<TEMP_ROOT>"
CONTAINMENT_RESERVATION_SCHEMA = "AOSCONTAINMENT/1"
PREPARED_PROCESS_RECEIPT_SCHEMA = "AOSPROCESSSTART/1"
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_UNIT_RE = re.compile(r"aos-task-[a-z0-9][a-z0-9-]{0,116}\Z")
_LOWER_HEX_32_RE = re.compile(r"[0-9a-f]{32}\Z")
_LOWER_HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
_NAMESPACE_NAMES = frozenset({"user", "mnt", "net", "pid", "ipc", "uts"})


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

    def matches_fields(
        self, *, pid: int, start_time_ticks: int, boot_id: str
    ) -> bool:
        """Compare the durable anti-PID-reuse fields exactly."""
        return (
            self.pid == pid
            and self.start_time_ticks == start_time_ticks
            and self.boot_id == boot_id
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "pid": self.pid,
            "process_group_id": self.process_group_id,
            "start_time_ticks": self.start_time_ticks,
            "boot_id": self.boot_id,
        }

    @classmethod
    def from_dict(cls, raw: object) -> "ProcessIdentity":
        if type(raw) is not dict or set(raw) != {
            "pid", "process_group_id", "start_time_ticks", "boot_id"
        }:
            raise ValueError("invalid process identity fields")
        return cls(**raw)


def _require_positive_int(name: str, value: object) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


@dataclass(frozen=True, slots=True)
class ContainmentReservation:
    """Controller-selected exact containment and one-use release authority."""

    schema: str
    project_id: str
    task_id: str
    task_generation: int
    attempt: int
    controller_epoch: int
    lease_epoch: int
    dispatch_nonce: str
    unit_name: str
    release_nonce: str

    def __post_init__(self) -> None:
        if self.schema != CONTAINMENT_RESERVATION_SCHEMA:
            raise ValueError("invalid containment reservation schema")
        for name in ("project_id", "task_id"):
            value = getattr(self, name)
            if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
                raise ValueError(f"invalid {name}")
        for name in (
            "task_generation", "attempt", "controller_epoch", "lease_epoch"
        ):
            _require_positive_int(name, getattr(self, name))
        if _LOWER_HEX_32_RE.fullmatch(self.dispatch_nonce) is None:
            raise ValueError("invalid dispatch nonce")
        if _UNIT_RE.fullmatch(self.unit_name) is None:
            raise ValueError("invalid containment unit")
        if _LOWER_HEX_32_RE.fullmatch(self.release_nonce) is None:
            raise ValueError("invalid release nonce")

    @property
    def scope_name(self) -> str:
        return f"{self.unit_name}.scope"

    def to_dict(self) -> dict[str, object]:
        return {
            name: getattr(self, name)
            for name in self.__dataclass_fields__
        }

    @classmethod
    def from_dict(cls, raw: object) -> "ContainmentReservation":
        if type(raw) is not dict or set(raw) != set(cls.__dataclass_fields__):
            raise ValueError("invalid containment reservation fields")
        return cls(**raw)


@dataclass(frozen=True, slots=True)
class PreparedProcessReceipt:
    """Measured M4A evidence captured while hostile code is still gated."""

    schema: str
    reservation: ContainmentReservation
    process_identity: ProcessIdentity
    cgroup_path: str
    child_cgroup: str
    namespace_ids: tuple[tuple[str, int], ...]
    policy_digest: str
    workspace_destination: str
    workspace_device: int
    workspace_inode: int
    workspace_file_type: int
    executable: str
    argv: tuple[str, ...]
    prepared_at: str

    def __post_init__(self) -> None:
        if self.schema != PREPARED_PROCESS_RECEIPT_SCHEMA:
            raise ValueError("invalid prepared receipt schema")
        if not isinstance(self.reservation, ContainmentReservation):
            raise ValueError("invalid containment reservation")
        identity = self.process_identity
        if not isinstance(identity, ProcessIdentity):
            raise ValueError("invalid process identity")
        _require_positive_int("pid", identity.pid)
        _require_positive_int("process_group_id", identity.process_group_id)
        _require_positive_int("start_time_ticks", identity.start_time_ticks)
        if type(identity.boot_id) is not str or not identity.boot_id:
            raise ValueError("boot id is required")
        expected_suffix = "/" + self.reservation.scope_name
        if (
            type(self.cgroup_path) is not str
            or not self.cgroup_path.startswith("/sys/fs/cgroup/")
            or not self.cgroup_path.endswith(expected_suffix)
        ):
            raise ValueError("receipt cgroup does not match reservation")
        if (
            type(self.child_cgroup) is not str
            or not self.child_cgroup.startswith("/")
            or not self.child_cgroup.endswith(expected_suffix)
        ):
            raise ValueError("child cgroup does not match reservation")
        if type(self.namespace_ids) is not tuple:
            raise ValueError("invalid namespace evidence")
        namespace_names = [item[0] for item in self.namespace_ids]
        if (
            any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not int
                or item[1] < 1
                for item in self.namespace_ids
            )
            or namespace_names != sorted(namespace_names)
            or set(namespace_names) != _NAMESPACE_NAMES
        ):
            raise ValueError("invalid namespace evidence")
        if _LOWER_HEX_64_RE.fullmatch(self.policy_digest) is None:
            raise ValueError("invalid policy digest")
        if self.workspace_destination != "/workspace":
            raise ValueError("invalid workspace destination")
        for name in ("workspace_device", "workspace_inode", "workspace_file_type"):
            _require_positive_int(name, getattr(self, name))
        if (
            type(self.argv) is not tuple
            or not self.argv
            or any(type(item) is not str or not item for item in self.argv)
            or type(self.executable) is not str
            or not self.executable.startswith("/")
            or self.argv[0] != self.executable
        ):
            raise ValueError("invalid prepared executable or argv")
        try:
            datetime.fromisoformat(self.prepared_at)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid prepared timestamp") from exc

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "reservation": self.reservation.to_dict(),
            "process_identity": self.process_identity.to_dict(),
            "cgroup_path": self.cgroup_path,
            "child_cgroup": self.child_cgroup,
            "namespace_ids": [[name, value] for name, value in self.namespace_ids],
            "policy_digest": self.policy_digest,
            "workspace_destination": self.workspace_destination,
            "workspace_device": self.workspace_device,
            "workspace_inode": self.workspace_inode,
            "workspace_file_type": self.workspace_file_type,
            "executable": self.executable,
            "argv": list(self.argv),
            "prepared_at": self.prepared_at,
        }

    @classmethod
    def from_dict(cls, raw: object) -> "PreparedProcessReceipt":
        if type(raw) is not dict or set(raw) != set(cls.__dataclass_fields__):
            raise ValueError("invalid prepared receipt fields")
        return cls(
            **{
                **raw,
                "reservation": ContainmentReservation.from_dict(raw["reservation"]),
                "process_identity": ProcessIdentity.from_dict(raw["process_identity"]),
                "namespace_ids": tuple(
                    tuple(item) for item in raw["namespace_ids"]
                ),
                "argv": tuple(raw["argv"]),
            }
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
    output_limit_exceeded: bool = False
    _stdout_bytes: bytes = field(default=b"", repr=False, compare=False)

    @property
    def stdout_bytes(self) -> bytes:
        """Exact captured bytes for strict protocol validation."""
        return self._stdout_bytes

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("_stdout_bytes", None)
        return value


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
    readonly_dir: Path
    readonly_file: Path
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
