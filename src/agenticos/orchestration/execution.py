"""Durable split-phase process binding and fail-closed restart reconciliation."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Sequence

from agenticos.sandbox.containment import (
    CancellationConfig,
    ContainmentState,
    ScopeEvidence,
    ScopeEvidenceState,
    cancel_contained,
)
from agenticos.sandbox.models import (
    CONTAINMENT_RESERVATION_SCHEMA,
    ContainmentReservation,
    PreparedProcessReceipt,
    ProcessResult,
)
from agenticos.sandbox.worktree import (
    WorkspaceCaptureCompleteness,
    WorkspaceReuseDecision,
    WorktreeValidationError,
    acquire_repository_lock,
)

from .board import BoardSnapshot
from .canonical import CanonicalDataError, canonical_json_bytes, canonical_json_line, load_canonical_json
from .journal import _durable_replace
from .models import ControllerValidationError, TaskStatus, require_digest, require_exact_fields, require_uint
from .protocol import AgentResult, AgentTaskRequest, DispatchIdentity, ResultStatus
from .synthetic import validate_synthetic_process_output
from .workspace import (
    WorkspaceLeaseIdentity,
    WorkspaceLeaseLedger,
    WorkspaceLeaseState,
)

EXECUTION_RECORD_SCHEMA = "AOSEXECUTION/1"
EXECUTION_TAIL_SCHEMA = "AOSEXECUTIONTAIL/1"
ZERO_DIGEST = "0" * 64
DEFAULT_MAX_RECORDS = 64
DEFAULT_MAX_RECORD_BYTES = 256 * 1024
MAX_DETAIL_BYTES = 4096
_RECORD_RE = re.compile(r"(?P<sequence>[0-9]{20})\.execution\.json\Z")


class ExecutionError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail[:MAX_DETAIL_BYTES]
        super().__init__(f"{code}: {self.detail}" if self.detail else code)


class ExecutionState(str, Enum):
    CONTAINMENT_RESERVED = "CONTAINMENT_RESERVED"
    PROCESS_STARTED = "PROCESS_STARTED"
    RELEASED = "RELEASED"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    PROCESS_TERMINATED = "PROCESS_TERMINATED"
    TERMINAL_CAPTURED = "TERMINAL_CAPTURED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    FAILED = "FAILED"


def create_containment_reservation(
    dispatch: DispatchIdentity,
) -> ContainmentReservation:
    """Create controller-owned cryptographically unique pre-spawn authority."""
    if not isinstance(dispatch, DispatchIdentity):
        raise ExecutionError("INVALID_DISPATCH_IDENTITY")
    unit_token = secrets.token_hex(16)
    return ContainmentReservation(
        schema=CONTAINMENT_RESERVATION_SCHEMA,
        project_id=dispatch.project_id,
        task_id=dispatch.task_id,
        task_generation=dispatch.task_generation,
        attempt=dispatch.attempt,
        controller_epoch=dispatch.controller_epoch,
        lease_epoch=dispatch.lease_epoch,
        dispatch_nonce=dispatch.dispatch_nonce,
        unit_name=f"aos-task-slicec-{unit_token}",
        release_nonce=secrets.token_hex(16),
    )


def _record_digest(raw: dict[str, object]) -> str:
    unsigned = {name: value for name, value in raw.items() if name != "record_digest"}
    return hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()


@dataclass(frozen=True, slots=True)
class ExecutionRecord:
    schema: str
    sequence: int
    previous_record_digest: str
    state: ExecutionState
    dispatch: DispatchIdentity
    lease: WorkspaceLeaseIdentity
    reservation: ContainmentReservation
    receipt: PreparedProcessReceipt | None
    detail: str | None
    terminal_status: str | None
    checkpoint_digest: str | None
    record_digest: str

    def __post_init__(self) -> None:
        if self.schema != EXECUTION_RECORD_SCHEMA:
            raise ValueError("invalid execution schema")
        require_uint("sequence", self.sequence, minimum=1)
        require_digest("previous_record_digest", self.previous_record_digest)
        if not isinstance(self.state, ExecutionState):
            raise ValueError("invalid execution state")
        if not isinstance(self.dispatch, DispatchIdentity):
            raise ValueError("invalid dispatch identity")
        if not isinstance(self.lease, WorkspaceLeaseIdentity):
            raise ValueError("invalid lease identity")
        if not isinstance(self.reservation, ContainmentReservation):
            raise ValueError("invalid containment reservation")
        if self.receipt is not None and not isinstance(
            self.receipt, PreparedProcessReceipt
        ):
            raise ValueError("invalid process receipt")
        if self.receipt is not None and self.receipt.reservation != self.reservation:
            raise ValueError("receipt reservation mismatch")
        if self.state in {ExecutionState.PROCESS_STARTED, ExecutionState.RELEASED} and self.receipt is None:
            raise ValueError("measured receipt required")
        if self.detail is not None and (
            type(self.detail) is not str
            or len(self.detail.encode("utf-8")) > MAX_DETAIL_BYTES
        ):
            raise ValueError("invalid execution detail")
        if self.state is ExecutionState.PROCESS_TERMINATED:
            if self.terminal_status not in {"SUCCEEDED", "FAILED", "TIMEOUT", "CANCELLED"}:
                raise ValueError("invalid terminal status")
        elif self.terminal_status is not None:
            raise ValueError("terminal status only belongs to termination")
        if self.state is ExecutionState.TERMINAL_CAPTURED:
            require_digest("checkpoint_digest", self.checkpoint_digest)
        elif self.checkpoint_digest is not None:
            raise ValueError("checkpoint only belongs to terminal capture")
        require_digest("record_digest", self.record_digest)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "sequence": self.sequence,
            "previous_record_digest": self.previous_record_digest,
            "state": self.state.value,
            "dispatch": self.dispatch.to_dict(),
            "lease": self.lease.to_dict(),
            "reservation": self.reservation.to_dict(),
            "receipt": None if self.receipt is None else self.receipt.to_dict(),
            "detail": self.detail,
            "terminal_status": self.terminal_status,
            "checkpoint_digest": self.checkpoint_digest,
            "record_digest": self.record_digest,
        }

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        previous_record_digest: str,
        state: ExecutionState,
        dispatch: DispatchIdentity,
        lease: WorkspaceLeaseIdentity,
        reservation: ContainmentReservation,
        receipt: PreparedProcessReceipt | None,
        detail: str | None = None,
        terminal_status: str | None = None,
        checkpoint_digest: str | None = None,
    ) -> "ExecutionRecord":
        raw: dict[str, object] = {
            "schema": EXECUTION_RECORD_SCHEMA,
            "sequence": sequence,
            "previous_record_digest": previous_record_digest,
            "state": state.value,
            "dispatch": dispatch.to_dict(),
            "lease": lease.to_dict(),
            "reservation": reservation.to_dict(),
            "receipt": None if receipt is None else receipt.to_dict(),
            "detail": detail,
            "terminal_status": terminal_status,
            "checkpoint_digest": checkpoint_digest,
            "record_digest": "",
        }
        raw["record_digest"] = _record_digest(raw)
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: object) -> "ExecutionRecord":
        value = require_exact_fields(raw, set(cls.__dataclass_fields__))
        return cls(
            **{
                **value,
                "state": ExecutionState(value["state"]),
                "dispatch": DispatchIdentity.from_dict(value["dispatch"]),
                "lease": WorkspaceLeaseIdentity.from_dict(value["lease"]),
                "reservation": ContainmentReservation.from_dict(value["reservation"]),
                "receipt": (
                    None
                    if value["receipt"] is None
                    else PreparedProcessReceipt.from_dict(value["receipt"])
                ),
            }
        )


class ExecutionLedger:
    """One immutable hash chain for one exact dispatch; never redispatches."""

    def __init__(
        self,
        root: Path,
        dispatch: DispatchIdentity,
        *,
        max_records: int = DEFAULT_MAX_RECORDS,
        max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
        lock_timeout: float = 30.0,
        write_observer: Callable[[ExecutionState], None] | None = None,
    ) -> None:
        if not isinstance(dispatch, DispatchIdentity):
            raise ExecutionError("INVALID_DISPATCH_IDENTITY")
        if type(max_records) is not int or max_records < 1:
            raise ExecutionError("INVALID_EXECUTION_LIMIT")
        self.dispatch = dispatch
        self.max_records = max_records
        self.max_record_bytes = max_record_bytes
        self.lock_timeout = float(lock_timeout)
        self.write_observer = write_observer
        identity_digest = hashlib.sha256(
            canonical_json_bytes(dispatch.to_dict())
        ).hexdigest()
        leaf = f"execution-{identity_digest}"
        self.root = Path(root) / leaf
        self.lock_path = Path(root) / ".locks" / f"{leaf}.lock"
        self.tail_path = Path(root) / ".tails" / f"{leaf}.tail.json"
        self.root.mkdir(parents=True, exist_ok=True)

    def _locked(self):
        return acquire_repository_lock(self.lock_path, timeout=self.lock_timeout)

    def records(self) -> tuple[ExecutionRecord, ...]:
        try:
            with self._locked():
                return self._records_unlocked()
        except WorktreeValidationError as exc:
            raise ExecutionError("EXECUTION_LOCK_FAILED", str(exc)) from exc

    def recover(self) -> ExecutionRecord | None:
        records = self.records()
        return records[-1] if records else None

    def _records_unlocked(self) -> tuple[ExecutionRecord, ...]:
        try:
            entries = sorted(self.root.iterdir(), key=lambda path: path.name)
        except OSError as exc:
            raise ExecutionError("EXECUTION_DIRECTORY_UNREADABLE") from exc
        if len(entries) > self.max_records:
            raise ExecutionError("EXECUTION_RECORD_LIMIT")
        records: list[ExecutionRecord] = []
        for path in entries:
            match = _RECORD_RE.fullmatch(path.name)
            if match is None or path.is_symlink() or not path.is_file():
                raise ExecutionError("UNKNOWN_EXECUTION_ENTRY", path.name)
            try:
                raw = path.read_bytes()
                if len(raw) > self.max_record_bytes or not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
                    raise ExecutionError("CORRUPT_EXECUTION_RECORD", path.name)
                value = load_canonical_json(raw[:-1], max_bytes=self.max_record_bytes - 1)
                if canonical_json_line(value, max_bytes=self.max_record_bytes) != raw:
                    raise ExecutionError("CORRUPT_EXECUTION_RECORD", path.name)
                record = ExecutionRecord.from_dict(value)
            except (OSError, CanonicalDataError, ControllerValidationError, ValueError, TypeError) as exc:
                raise ExecutionError("CORRUPT_EXECUTION_RECORD", path.name) from exc
            sequence = int(match.group("sequence"))
            if sequence != len(records) + 1 or record.sequence != sequence:
                raise ExecutionError("EXECUTION_SEQUENCE_GAP_OR_ROLLBACK")
            expected_previous = ZERO_DIGEST if not records else records[-1].record_digest
            if record.previous_record_digest != expected_previous:
                raise ExecutionError("EXECUTION_HASH_CHAIN_MISMATCH")
            if record.record_digest != _record_digest(record.to_dict()):
                raise ExecutionError("EXECUTION_RECORD_DIGEST_MISMATCH")
            if record.dispatch != self.dispatch:
                raise ExecutionError("DISPATCH_BINDING_MISMATCH")
            self._require_binding(record.lease, record.reservation, record.receipt)
            self._validate_transition(records[-1] if records else None, record)
            records.append(record)
        self._validate_tail_unlocked(records)
        return tuple(records)

    def _validate_tail_unlocked(self, records: list[ExecutionRecord]) -> None:
        if not self.tail_path.exists():
            if records:
                raise ExecutionError("EXECUTION_TAIL_MISSING")
            return
        try:
            raw = self.tail_path.read_bytes()
            if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
                raise ValueError("noncanonical tail")
            value = load_canonical_json(raw[:-1], max_bytes=4095)
            if canonical_json_line(value, max_bytes=4096) != raw:
                raise ValueError("noncanonical tail")
            value = require_exact_fields(
                value, {"schema", "sequence", "record_digest"}
            )
            require_digest("record_digest", value["record_digest"])
            require_uint("sequence", value["sequence"], minimum=1)
        except (
            OSError,
            CanonicalDataError,
            ControllerValidationError,
            TypeError,
            ValueError,
        ) as exc:
            raise ExecutionError("CORRUPT_EXECUTION_TAIL") from exc
        if value["schema"] != EXECUTION_TAIL_SCHEMA or not records:
            raise ExecutionError("EXECUTION_TAIL_ROLLBACK")
        if (
            value["sequence"] != records[-1].sequence
            or value["record_digest"] != records[-1].record_digest
        ):
            raise ExecutionError("EXECUTION_TAIL_ROLLBACK")

    @staticmethod
    def _validate_transition(
        previous: ExecutionRecord | None, current: ExecutionRecord
    ) -> None:
        if previous is None:
            if current.state is not ExecutionState.CONTAINMENT_RESERVED:
                raise ExecutionError("INVALID_INITIAL_EXECUTION_STATE")
            return
        if (
            current.dispatch != previous.dispatch
            or current.lease != previous.lease
            or current.reservation != previous.reservation
        ):
            raise ExecutionError("EXECUTION_BINDING_CHANGED")
        if previous.receipt is None:
            if current.state is ExecutionState.PROCESS_STARTED:
                if current.receipt is None:
                    raise ExecutionError("PROCESS_RECEIPT_MISSING")
            elif current.receipt is not None:
                raise ExecutionError("UNEXPECTED_PROCESS_RECEIPT")
        elif current.receipt != previous.receipt:
            raise ExecutionError("EXECUTION_BINDING_CHANGED")
        allowed = {
            ExecutionState.CONTAINMENT_RESERVED: {
                ExecutionState.PROCESS_STARTED,
                ExecutionState.CANCEL_REQUESTED,
                ExecutionState.PROCESS_TERMINATED,
                ExecutionState.RECOVERY_REQUIRED,
                ExecutionState.FAILED,
            },
            ExecutionState.PROCESS_STARTED: {
                ExecutionState.RELEASED,
                ExecutionState.CANCEL_REQUESTED,
                ExecutionState.PROCESS_TERMINATED,
                ExecutionState.RECOVERY_REQUIRED,
                ExecutionState.FAILED,
            },
            ExecutionState.RELEASED: {
                ExecutionState.CANCEL_REQUESTED,
                ExecutionState.PROCESS_TERMINATED,
                ExecutionState.RECOVERY_REQUIRED,
                ExecutionState.FAILED,
            },
            ExecutionState.CANCEL_REQUESTED: {
                ExecutionState.PROCESS_TERMINATED,
                ExecutionState.RECOVERY_REQUIRED,
                ExecutionState.FAILED,
            },
            ExecutionState.PROCESS_TERMINATED: {
                ExecutionState.TERMINAL_CAPTURED,
                ExecutionState.RECOVERY_REQUIRED,
                ExecutionState.FAILED,
            },
            ExecutionState.TERMINAL_CAPTURED: set(),
            ExecutionState.RECOVERY_REQUIRED: set(),
            ExecutionState.FAILED: set(),
        }
        if current.state not in allowed[previous.state]:
            raise ExecutionError("INVALID_EXECUTION_TRANSITION")

    def _write_unlocked(self, record: ExecutionRecord) -> ExecutionRecord:
        if record.sequence > self.max_records:
            raise ExecutionError("EXECUTION_RECORD_LIMIT")
        target = self.root / f"{record.sequence:020d}.execution.json"
        raw = canonical_json_line(record.to_dict(), max_bytes=self.max_record_bytes)
        temporary = self.root / f".tmp-{secrets.token_hex(16)}"
        try:
            with temporary.open("xb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            _durable_replace(temporary, target)
            tail_raw = canonical_json_line(
                {
                    "schema": EXECUTION_TAIL_SCHEMA,
                    "sequence": record.sequence,
                    "record_digest": record.record_digest,
                },
                max_bytes=4096,
            )
            self.tail_path.parent.mkdir(parents=True, exist_ok=True)
            tail_temporary = self.tail_path.parent / f".tmp-{secrets.token_hex(16)}"
            with tail_temporary.open("xb") as handle:
                handle.write(tail_raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tail_temporary, self.tail_path)
            if os.name != "nt":
                directory_fd = os.open(
                    self.tail_path.parent, os.O_RDONLY | os.O_DIRECTORY
                )
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except (OSError, CanonicalDataError) as exc:
            raise ExecutionError("DURABLE_WRITE_FAILED", target.name) from exc
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        recovered = self._records_unlocked()[-1]
        if self.write_observer is not None:
            self.write_observer(recovered.state)
        return recovered

    def record_containment_reserved(
        self,
        lease: WorkspaceLeaseIdentity,
        reservation: ContainmentReservation,
    ) -> ExecutionRecord:
        self._require_binding(lease, reservation, None)
        try:
            with self._locked():
                if self._records_unlocked():
                    raise ExecutionError("EXECUTION_ALREADY_RECORDED")
                return self._write_unlocked(
                    ExecutionRecord.create(
                        sequence=1,
                        previous_record_digest=ZERO_DIGEST,
                        state=ExecutionState.CONTAINMENT_RESERVED,
                        dispatch=self.dispatch,
                        lease=lease,
                        reservation=reservation,
                        receipt=None,
                    )
                )
        except WorktreeValidationError as exc:
            raise ExecutionError("EXECUTION_LOCK_FAILED", str(exc)) from exc

    def record_process_started(
        self,
        lease: WorkspaceLeaseIdentity,
        receipt: PreparedProcessReceipt,
        *,
        expected: ExecutionRecord,
    ) -> ExecutionRecord:
        self._require_binding(lease, receipt.reservation, receipt)
        try:
            with self._locked():
                records = self._records_unlocked()
                if not records or records[-1] != expected:
                    raise ExecutionError("STALE_EXECUTION_RECORD")
                if expected.state is not ExecutionState.CONTAINMENT_RESERVED:
                    raise ExecutionError("INVALID_EXECUTION_TRANSITION")
                return self._write_unlocked(
                    ExecutionRecord.create(
                        sequence=expected.sequence + 1,
                        previous_record_digest=expected.record_digest,
                        state=ExecutionState.PROCESS_STARTED,
                        dispatch=self.dispatch,
                        lease=lease,
                        reservation=receipt.reservation,
                        receipt=receipt,
                    )
                )
        except WorktreeValidationError as exc:
            raise ExecutionError("EXECUTION_LOCK_FAILED", str(exc)) from exc

    def _require_binding(
        self,
        lease: WorkspaceLeaseIdentity,
        reservation: ContainmentReservation,
        receipt: PreparedProcessReceipt | None,
    ) -> None:
        dispatch = self.dispatch
        checks = (
            lease.project_id == dispatch.project_id == reservation.project_id,
            lease.task_id == dispatch.task_id == reservation.task_id,
            lease.task_generation
            == dispatch.task_generation
            == reservation.task_generation,
            lease.attempt == dispatch.attempt == reservation.attempt,
            lease.controller_epoch
            == dispatch.controller_epoch
            == reservation.controller_epoch,
            lease.lease_epoch == dispatch.lease_epoch == reservation.lease_epoch,
            lease.dispatch_nonce
            == dispatch.dispatch_nonce
            == reservation.dispatch_nonce,
            lease.pre_checkpoint_digest == dispatch.checkpoint_digest,
            lease.workspace.workspace_id == dispatch.workspace_id,
            lease.workspace.generation == dispatch.workspace_generation,
            lease.workspace.reservation_id == dispatch.reservation_id,
        )
        if not all(checks):
            raise ExecutionError("DISPATCH_BINDING_MISMATCH")
        if receipt is not None and receipt.reservation != reservation:
            raise ExecutionError("DISPATCH_BINDING_MISMATCH")

    def append(
        self,
        state: ExecutionState,
        *,
        expected: ExecutionRecord | None,
        detail: str | None = None,
        terminal_status: str | None = None,
        checkpoint_digest: str | None = None,
    ) -> ExecutionRecord:
        if not isinstance(state, ExecutionState):
            raise ExecutionError("INVALID_EXECUTION_STATE")
        try:
            with self._locked():
                records = self._records_unlocked()
                if not records or expected != records[-1]:
                    raise ExecutionError("STALE_EXECUTION_RECORD")
                current = records[-1]
                if state is ExecutionState.PROCESS_TERMINATED and any(
                    item.state is ExecutionState.CANCEL_REQUESTED for item in records
                ):
                    terminal_status = "CANCELLED"
                candidate = ExecutionRecord.create(
                    sequence=current.sequence + 1,
                    previous_record_digest=current.record_digest,
                    state=state,
                    dispatch=current.dispatch,
                    lease=current.lease,
                    reservation=current.reservation,
                    receipt=current.receipt,
                    detail=detail,
                    terminal_status=terminal_status,
                    checkpoint_digest=checkpoint_digest,
                )
                self._validate_transition(current, candidate)
                return self._write_unlocked(candidate)
        except WorktreeValidationError as exc:
            raise ExecutionError("EXECUTION_LOCK_FAILED", str(exc)) from exc


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    process_result: ProcessResult
    first_checkpoint: object
    second_checkpoint: object
    terminal_record: ExecutionRecord
    agent_result: AgentResult | None = None
    protocol_rejection_code: str | None = None


class SyntheticBuildController:
    """Narrow Slice C executor; this is not a scheduler or provider adapter."""

    def __init__(self, ledger: ExecutionLedger) -> None:
        self.ledger = ledger
        self._active_lock = threading.Lock()
        self._active: tuple[object, WorkspaceLeaseLedger, WorkspaceLeaseIdentity] | None = None

    def request_cancel(self, *, reason: str = "owner cancellation") -> ExecutionRecord:
        """Commit cancellation before recursively signalling the exact live scope."""
        with self._active_lock:
            active = self._active
        if active is None:
            raise ExecutionError("NO_ACTIVE_EXECUTION")
        prepared, lease_ledger, lease = active

        def commit_and_signal() -> ExecutionRecord:
            current = self.ledger.recover()
            if current is None or current.state not in {
                ExecutionState.PROCESS_STARTED,
                ExecutionState.RELEASED,
                ExecutionState.CANCEL_REQUESTED,
            }:
                raise ExecutionError("EXECUTION_NOT_CANCELLABLE")
            if current.state is ExecutionState.CANCEL_REQUESTED:
                cancelled = current
            else:
                cancelled = self.ledger.append(
                    ExecutionState.CANCEL_REQUESTED,
                    expected=current,
                    detail=reason,
                )
            prepared.request_cancel()
            return cancelled

        try:
            _lease_record, execution_record = lease_ledger.cancel_with_callback(
                lease, reason=reason, callback=commit_and_signal
            )
        except BaseException as exc:
            current = self.ledger.recover()
            if current is not None and current.state is ExecutionState.CANCEL_REQUESTED:
                self.ledger.append(
                    ExecutionState.RECOVERY_REQUIRED,
                    expected=current,
                    detail="process cancellation drain failed or is ambiguous",
                )
            raise ExecutionError("PROCESS_CANCELLATION_FAILED") from exc
        return execution_record

    @staticmethod
    def _scope_evidence(backend: object, unit: str) -> ScopeEvidence:
        try:
            evidence = backend.scope_evidence(unit)
        except BaseException as exc:
            return ScopeEvidence(
                ScopeEvidenceState.UNKNOWN,
                None,
                f"scope evidence failed: {type(exc).__name__}",
            )
        if not isinstance(evidence, ScopeEvidence):
            return ScopeEvidence(
                ScopeEvidenceState.UNKNOWN,
                None,
                "backend returned invalid scope evidence",
            )
        return evidence

    def _mark_recovery_required(
        self,
        current: ExecutionRecord,
        lease_ledger: WorkspaceLeaseLedger,
        detail: str,
    ) -> ExecutionRecord:
        recovery = self.ledger.append(
            ExecutionState.RECOVERY_REQUIRED,
            expected=current,
            detail=detail,
        )
        lease = lease_ledger.recover()
        if lease is not None and lease.state in {
            WorkspaceLeaseState.ACTIVE,
            WorkspaceLeaseState.EXECUTING,
            WorkspaceLeaseState.CANCELLING,
        }:
            lease_ledger.require_recovery(current.lease, reason=detail)
        return recovery

    def _reconcile_terminal_lease(
        self,
        terminal: ExecutionRecord,
        lease_ledger: WorkspaceLeaseLedger,
    ) -> ExecutionRecord:
        records = self.ledger.records()
        if len(records) < 2 or records[-1] != terminal:
            raise ExecutionError("TERMINAL_EXECUTION_HISTORY_MISSING")
        terminated = records[-2]
        if terminated.state is not ExecutionState.PROCESS_TERMINATED:
            raise ExecutionError("TERMINAL_EXECUTION_HISTORY_MISSING")
        lease = lease_ledger.recover()
        if lease is None or lease.identity != terminal.lease:
            raise ExecutionError("TERMINAL_LEASE_IDENTITY_MISMATCH")
        expected_state = (
            WorkspaceLeaseState.CANCELLED
            if terminated.terminal_status == "CANCELLED"
            else WorkspaceLeaseState.RELEASED
        )
        if lease.state is expected_state:
            return terminal
        if lease.state in {
            WorkspaceLeaseState.RECOVERY_REQUIRED,
            WorkspaceLeaseState.STALE,
        }:
            raise ExecutionError("TERMINAL_LEASE_RECONCILIATION_BLOCKED")
        if lease.state not in {
            WorkspaceLeaseState.ACTIVE,
            WorkspaceLeaseState.EXECUTING,
            WorkspaceLeaseState.CANCELLING,
        }:
            raise ExecutionError("TERMINAL_LEASE_DISPOSITION_MISMATCH")
        if expected_state is WorkspaceLeaseState.CANCELLED:
            if lease.state is not WorkspaceLeaseState.CANCELLING:
                lease_ledger.begin_cancellation(
                    terminal.lease,
                    reason="reconciling terminal cancelled execution",
                )
            lease_ledger.cancel(
                terminal.lease,
                reason="reconciled terminal cancelled execution",
            )
        else:
            lease_ledger.release(
                terminal.lease,
                reason="reconciled persisted terminal checkpoint",
            )
        return terminal

    @staticmethod
    def _validate_binding(
        board: BoardSnapshot,
        dispatch: DispatchIdentity,
        lease: WorkspaceLeaseIdentity,
        pre_checkpoint: object,
        reservation: object,
    ) -> None:
        try:
            task = board.task(dispatch.task_id)
            project = board.project
            expected_workspace = (
                dispatch.workspace_id,
                dispatch.workspace_generation,
                dispatch.reservation_id,
            )
            actual_workspace = (
                project.workspace.workspace_id,
                project.workspace.generation,
                project.workspace.reservation_id,
            )
            lease_workspace = (
                lease.workspace.workspace_id,
                lease.workspace.generation,
                lease.workspace.reservation_id,
            )
            checks = (
                project.project_id == dispatch.project_id == lease.project_id,
                task.project_id == dispatch.project_id,
                task.task_id == lease.task_id == dispatch.task_id,
                task.status is TaskStatus.IN_PROGRESS,
                task.generation == dispatch.task_generation == lease.task_generation,
                task.attempt_count == dispatch.attempt == lease.attempt,
                project.controller_epoch == dispatch.controller_epoch == lease.controller_epoch,
                project.lease_epoch == task.lease_epoch == dispatch.lease_epoch == lease.lease_epoch,
                project.baseline.repository_id == dispatch.repository_id,
                project.baseline.commit_sha == dispatch.baseline_commit,
                actual_workspace == expected_workspace == lease_workspace,
                dispatch.dispatch_nonce == lease.dispatch_nonce,
                dispatch.checkpoint_digest == lease.pre_checkpoint_digest,
                getattr(pre_checkpoint, "checkpoint_digest") == dispatch.checkpoint_digest,
                getattr(pre_checkpoint, "repository_id") == dispatch.repository_id,
                getattr(pre_checkpoint, "task_id") == dispatch.task_id,
                getattr(pre_checkpoint, "generation") == dispatch.task_generation,
                getattr(pre_checkpoint, "baseline_commit_sha") == dispatch.baseline_commit,
                getattr(pre_checkpoint, "reservation_digest") == dispatch.reservation_id,
                getattr(pre_checkpoint, "capture_completeness")
                is WorkspaceCaptureCompleteness.COMPLETE,
                reservation.project_id == dispatch.project_id,
                reservation.task_id == dispatch.task_id,
                reservation.task_generation == dispatch.task_generation,
                reservation.attempt == dispatch.attempt,
                reservation.controller_epoch == dispatch.controller_epoch,
                reservation.lease_epoch == dispatch.lease_epoch,
                reservation.dispatch_nonce == dispatch.dispatch_nonce,
            )
        except (AttributeError, KeyError, TypeError):
            raise ExecutionError("DISPATCH_BINDING_MISMATCH") from None
        if not all(checks):
            raise ExecutionError("DISPATCH_BINDING_MISMATCH")

    @staticmethod
    def _checkpoint_from_capture(capture: object) -> object:
        if (
            getattr(capture, "decision", None) is not WorkspaceReuseDecision.REUSABLE
            or getattr(capture, "checkpoint", None) is None
            or getattr(capture.checkpoint, "capture_completeness", None)
            is not WorkspaceCaptureCompleteness.COMPLETE
        ):
            raise ExecutionError("TERMINAL_CHECKPOINT_INCOMPLETE")
        return capture.checkpoint

    @staticmethod
    def _capture(
        workspace_manager: object,
        repo_path: Path,
        dispatch: DispatchIdentity,
        receipt: PreparedProcessReceipt | None,
        *,
        expected_device: int | None = None,
        expected_inode: int | None = None,
    ) -> object:
        capture = workspace_manager.capture_checkpoint(
            repo_path, dispatch.task_id, dispatch.task_generation
        )
        checkpoint = SyntheticBuildController._checkpoint_from_capture(capture)
        if receipt is not None:
            expected_device = receipt.workspace_device
            expected_inode = receipt.workspace_inode
        checks = (
            checkpoint.repository_id == dispatch.repository_id,
            checkpoint.task_id == dispatch.task_id,
            checkpoint.generation == dispatch.task_generation,
            checkpoint.baseline_commit_sha == dispatch.baseline_commit,
            checkpoint.reservation_digest == dispatch.reservation_id,
            checkpoint.worktree_device == expected_device,
            checkpoint.worktree_inode == expected_inode,
        )
        if not all(checks):
            raise ExecutionError("TERMINAL_WORKSPACE_IDENTITY_MISMATCH")
        return checkpoint

    def _finish_terminal_capture(
        self,
        *,
        terminated: ExecutionRecord,
        lease_ledger: WorkspaceLeaseLedger,
        workspace_manager: object,
        repo_path: Path,
        pre_checkpoint: object | None = None,
        require_pre_equal: bool = False,
    ) -> tuple[object, object, ExecutionRecord]:
        lease_record = lease_ledger.recover()
        if lease_record is None or lease_record.identity != terminated.lease:
            raise ExecutionError("LEASE_IDENTITY_MISMATCH")
        admission = lease_record.admission
        try:
            first = self._capture(
                workspace_manager,
                repo_path,
                terminated.dispatch,
                terminated.receipt,
                expected_device=admission.worktree_device,
                expected_inode=admission.worktree_inode,
            )
            second = self._capture(
                workspace_manager,
                repo_path,
                terminated.dispatch,
                terminated.receipt,
                expected_device=admission.worktree_device,
                expected_inode=admission.worktree_inode,
            )
        except BaseException:
            self.ledger.append(
                ExecutionState.RECOVERY_REQUIRED,
                expected=terminated,
                detail="terminal workspace capture failed",
            )
            if lease_record.state in {
                WorkspaceLeaseState.ACTIVE,
                WorkspaceLeaseState.EXECUTING,
                WorkspaceLeaseState.CANCELLING,
            }:
                lease_ledger.require_recovery(
                    terminated.lease, reason="terminal workspace capture failed"
                )
            raise
        if first != second:
            self.ledger.append(
                ExecutionState.RECOVERY_REQUIRED,
                expected=terminated,
                detail="terminal workspace checkpoints disagree",
            )
            if lease_record.state in {
                WorkspaceLeaseState.ACTIVE,
                WorkspaceLeaseState.EXECUTING,
                WorkspaceLeaseState.CANCELLING,
            }:
                lease_ledger.require_recovery(
                    terminated.lease, reason="terminal checkpoints disagree"
                )
            raise ExecutionError("UNSTABLE_TERMINAL_CHECKPOINT")
        if require_pre_equal and first != pre_checkpoint:
            self.ledger.append(
                ExecutionState.RECOVERY_REQUIRED,
                expected=terminated,
                detail="workspace changed before release",
            )
            if lease_record.state in {
                WorkspaceLeaseState.ACTIVE,
                WorkspaceLeaseState.EXECUTING,
                WorkspaceLeaseState.CANCELLING,
            }:
                lease_ledger.require_recovery(
                    terminated.lease, reason="workspace changed before release"
                )
            raise ExecutionError("WORKSPACE_CHANGED_BEFORE_DURABLE_RELEASE")
        terminal = self.ledger.append(
            ExecutionState.TERMINAL_CAPTURED,
            expected=terminated,
            checkpoint_digest=getattr(first, "checkpoint_digest"),
        )
        self._reconcile_terminal_lease(terminal, lease_ledger)
        return first, second, terminal

    def execute(
        self,
        *,
        board: BoardSnapshot,
        dispatch: DispatchIdentity,
        lease_ledger: WorkspaceLeaseLedger,
        pre_checkpoint: object,
        runner: object,
        reservation: object,
        argv: Sequence[str],
        workspace_manager: object,
        repo_path: Path,
        timeout: float,
        request: AgentTaskRequest | None = None,
    ) -> ExecutionOutcome:
        lease_record = lease_ledger.require_active(
            WorkspaceLeaseIdentity.from_dict(lease_ledger.recover().identity.to_dict())  # type: ignore[union-attr]
        )
        lease = lease_record.identity
        self._validate_binding(board, dispatch, lease, pre_checkpoint, reservation)
        if request is not None and (
            not isinstance(request, AgentTaskRequest) or request.identity != dispatch
        ):
            raise ExecutionError("DISPATCH_BINDING_MISMATCH")
        reserved = self.ledger.record_containment_reserved(lease, reservation)
        try:
            prepared = runner.prepare(
                argv,
                cwd="/workspace",
                env={},
                reservation=reservation,
            )
        except BaseException as exc:
            self.ledger.append(
                ExecutionState.RECOVERY_REQUIRED,
                expected=reserved,
                detail="sandbox prepare failed after durable containment reservation",
            )
            lease_ledger.require_recovery(
                lease, reason="sandbox prepare failed after containment reservation"
            )
            raise ExecutionError("PROCESS_PREPARE_FAILED") from exc
        receipt = prepared.receipt
        if receipt.reservation != reservation:
            prepared.cancel()
            lease_ledger.require_recovery(lease, reason="prepared receipt reservation mismatch")
            raise ExecutionError("PREPARED_RECEIPT_BINDING_MISMATCH")
        for name in ("worktree_device", "worktree_inode"):
            if hasattr(pre_checkpoint, name):
                receipt_value = getattr(receipt, "workspace_" + name.removeprefix("worktree_"))
                if receipt_value != getattr(pre_checkpoint, name):
                    prepared.cancel()
                    lease_ledger.require_recovery(lease, reason="prepared workspace identity mismatch")
                    raise ExecutionError("PREPARED_RECEIPT_BINDING_MISMATCH")
        try:
            started = self.ledger.record_process_started(
                lease, receipt, expected=reserved
            )
        except BaseException as exc:
            prepared.cancel()
            current = self.ledger.recover()
            if current is None or current.state is not ExecutionState.CONTAINMENT_RESERVED:
                lease_ledger.require_recovery(
                    lease, reason="process receipt rollback state unavailable"
                )
                raise ExecutionError(
                    "PROCESS_RECEIPT_ROLLBACK_EVIDENCE_FAILED"
                ) from exc
            cancelled = self.ledger.append(
                ExecutionState.CANCEL_REQUESTED,
                expected=current,
                detail="receipt persistence failed before release",
            )
            terminated = self.ledger.append(
                ExecutionState.PROCESS_TERMINATED,
                expected=cancelled,
                terminal_status="CANCELLED",
            )
            try:
                self._finish_terminal_capture(
                    terminated=terminated,
                    lease_ledger=lease_ledger,
                    workspace_manager=workspace_manager,
                    repo_path=repo_path,
                    pre_checkpoint=pre_checkpoint,
                    require_pre_equal=True,
                )
            except BaseException as capture_exc:
                if (
                    isinstance(capture_exc, ExecutionError)
                    and capture_exc.code
                    == "WORKSPACE_CHANGED_BEFORE_DURABLE_RELEASE"
                ):
                    raise
                raise ExecutionError(
                    "PROCESS_RECEIPT_ROLLBACK_EVIDENCE_FAILED"
                ) from capture_exc
            raise ExecutionError("PROCESS_RECEIPT_PERSISTENCE_FAILED") from exc
        with self._active_lock:
            self._active = (prepared, lease_ledger, lease)
        try:
            def release_and_record() -> ExecutionRecord:
                prepared.release(receipt, reservation.release_nonce)
                return self.ledger.append(
                    ExecutionState.RELEASED, expected=started
                )

            _executing_lease, released = lease_ledger.authorize_execution(
                lease, release_and_record
            )
        except BaseException as exc:
            cancel_result: ProcessResult | None = None
            if not prepared.terminal:
                cancel_result = prepared.cancel()
            current = self.ledger.recover()
            if current is not None and current.state is ExecutionState.PROCESS_STARTED:
                cancelled = self.ledger.append(
                    ExecutionState.CANCEL_REQUESTED,
                    expected=current,
                    detail="lease revoked before release",
                )
            elif current is not None and current.state is ExecutionState.CANCEL_REQUESTED:
                cancelled = current
            else:
                cancelled = None
            if cancelled is not None:
                terminated = self.ledger.append(
                    ExecutionState.PROCESS_TERMINATED,
                    expected=cancelled,
                    terminal_status="CANCELLED",
                )
            lease_state = lease_ledger.recover()
            if (
                lease_state is not None
                and lease_state.state is WorkspaceLeaseState.CANCELLING
                and cancelled is not None
                and cancel_result is not None
            ):
                first, second, terminal = self._finish_terminal_capture(
                    terminated=terminated,
                    lease_ledger=lease_ledger,
                    workspace_manager=workspace_manager,
                    repo_path=repo_path,
                    pre_checkpoint=pre_checkpoint,
                    require_pre_equal=True,
                )
                with self._active_lock:
                    self._active = None
                return ExecutionOutcome(
                    cancel_result, first, second, terminal, None, None
                )
            if lease_state is not None and lease_state.state in {
                WorkspaceLeaseState.ACTIVE,
                WorkspaceLeaseState.EXECUTING,
                WorkspaceLeaseState.CANCELLING,
            }:
                lease_ledger.require_recovery(
                    lease, reason="release transition failed"
                )
            with self._active_lock:
                self._active = None
            raise ExecutionError("PROCESS_RELEASE_FAILED") from exc
        try:
            wait_record = released

            def record_output_cancellation() -> None:
                nonlocal wait_record
                wait_record = self.ledger.append(
                    ExecutionState.CANCEL_REQUESTED,
                    expected=wait_record,
                    detail="hostile output limit exceeded",
                )

            process_result = prepared.wait(
                timeout=timeout,
                max_output_bytes=(
                    request.limits.max_output_bytes
                    if request is not None
                    else 16 * 1024 * 1024
                ),
                cancellation_observer=record_output_cancellation,
            )
            observed = self.ledger.recover()
            if observed is None or observed.state not in {
                ExecutionState.RELEASED,
                ExecutionState.CANCEL_REQUESTED,
            }:
                raise ExecutionError("EXECUTION_WAIT_STATE_MISMATCH")
            wait_record = observed
        except BaseException as exc:
            with self._active_lock:
                self._active = None
            current = self.ledger.recover()
            if current is None:
                raise ExecutionError("PROCESS_WAIT_FAILED") from exc
            if getattr(prepared, "cleanup_proven", False):
                terminated = self.ledger.append(
                    ExecutionState.PROCESS_TERMINATED,
                    expected=current,
                    terminal_status=(
                        "CANCELLED"
                        if current.state is ExecutionState.CANCEL_REQUESTED
                        else "FAILED"
                    ),
                    detail="process wait failed after proven containment drain",
                )
                self._finish_terminal_capture(
                    terminated=terminated,
                    lease_ledger=lease_ledger,
                    workspace_manager=workspace_manager,
                    repo_path=repo_path,
                    pre_checkpoint=pre_checkpoint,
                )
                raise ExecutionError(
                    "PROCESS_WAIT_FAILED_AFTER_PROVEN_DRAIN"
                ) from exc
            self.ledger.append(
                ExecutionState.RECOVERY_REQUIRED,
                expected=current,
                detail="process wait failed without proven containment drain",
            )
            lease_state = lease_ledger.recover()
            if lease_state is not None and lease_state.state in {
                WorkspaceLeaseState.ACTIVE,
                WorkspaceLeaseState.EXECUTING,
                WorkspaceLeaseState.CANCELLING,
            }:
                lease_ledger.require_recovery(lease, reason="process wait failed")
            raise ExecutionError("PROCESS_WAIT_FAILED") from exc
        with self._active_lock:
            self._active = None
        agent_result: AgentResult | None = None
        protocol_rejection_code: str | None = None
        if request is not None:
            protocol_outcome = validate_synthetic_process_output(
                request, process_result.stdout_bytes
            )
            agent_result = protocol_outcome.result
            protocol_rejection_code = protocol_outcome.rejection_code
        if process_result.output_limit_exceeded:
            terminal_status = "FAILED"
        elif process_result.timed_out:
            terminal_status = "TIMEOUT"
        elif process_result.exit_code != 0:
            terminal_status = "FAILED"
        elif request is not None and agent_result is None:
            terminal_status = "FAILED"
        elif request is not None and agent_result.status not in {
            ResultStatus.SUCCEEDED,
            ResultStatus.NO_OP,
        }:
            terminal_status = "FAILED"
        else:
            terminal_status = "SUCCEEDED"
        terminated = self.ledger.append(
            ExecutionState.PROCESS_TERMINATED,
            expected=wait_record,
            terminal_status=terminal_status,
        )
        first, second, terminal = self._finish_terminal_capture(
            terminated=terminated,
            lease_ledger=lease_ledger,
            workspace_manager=workspace_manager,
            repo_path=repo_path,
        )
        return ExecutionOutcome(
            process_result,
            first,
            second,
            terminal,
            agent_result,
            protocol_rejection_code,
        )

    def recover(
        self,
        *,
        backend: object,
        cancellation: CancellationConfig,
        lease_ledger: WorkspaceLeaseLedger,
        workspace_manager: object,
        repo_path: Path,
        pre_checkpoint: object,
        proc_root: Path = Path("/proc"),
    ) -> ExecutionRecord:
        current = self.ledger.recover()
        if current is None:
            raise ExecutionError("NO_EXECUTION_RECORD")
        if current.state is ExecutionState.TERMINAL_CAPTURED:
            return self._reconcile_terminal_lease(current, lease_ledger)
        if current.state is ExecutionState.RECOVERY_REQUIRED:
            return current
        if current.state is ExecutionState.FAILED:
            raise ExecutionError("UNRECOVERABLE_FAILED_EXECUTION")
        if current.state is ExecutionState.PROCESS_TERMINATED:
            _first, _second, terminal = self._finish_terminal_capture(
                terminated=current,
                lease_ledger=lease_ledger,
                workspace_manager=workspace_manager,
                repo_path=repo_path,
                pre_checkpoint=pre_checkpoint,
                require_pre_equal=current.receipt is None,
            )
            return terminal
        if current.state is ExecutionState.CONTAINMENT_RESERVED:
            scope = self._scope_evidence(
                backend, current.reservation.scope_name
            )
            if scope.state is ScopeEvidenceState.UNKNOWN:
                return self._mark_recovery_required(
                    current,
                    lease_ledger,
                    "reserved containment scope evidence is unknown",
                )
            if scope.state is ScopeEvidenceState.PRESENT:
                if scope.cgroup_path is None:
                    return self._mark_recovery_required(
                        current,
                        lease_ledger,
                        "reserved containment lacks cgroup evidence",
                    )
                cgroup_path = scope.cgroup_path
                if cgroup_path.name != current.reservation.scope_name:
                    return self._mark_recovery_required(
                        current,
                        lease_ledger,
                        "reserved containment identity mismatch on restart",
                    )
                populated = backend.cgroup_populated(cgroup_path)
                if populated is None:
                    return self._mark_recovery_required(
                        current,
                        lease_ledger,
                        "reserved containment population is ambiguous",
                    )
                if populated is True:
                    current = self.ledger.append(
                        ExecutionState.CANCEL_REQUESTED,
                        expected=current,
                        detail="restart before measured receipt",
                    )
                    state, _details = cancel_contained(
                        backend,
                        current.reservation.scope_name,
                        cgroup_path,
                        cancellation,
                    )
                    if state is not ContainmentState.TERMINATED:
                        return self._mark_recovery_required(
                            current,
                            lease_ledger,
                            "reserved containment did not drain",
                        )
                backend.stop_unit(current.reservation.scope_name)
                after_stop = self._scope_evidence(
                    backend, current.reservation.scope_name
                )
                if after_stop.state is not ScopeEvidenceState.ABSENT:
                    return self._mark_recovery_required(
                        current,
                        lease_ledger,
                        "reserved containment absence not proven after drain",
                    )
            if current.state is ExecutionState.CONTAINMENT_RESERVED:
                current = self.ledger.append(
                    ExecutionState.CANCEL_REQUESTED,
                    expected=current,
                    detail="reserved containment proven absent or empty",
                )
            terminated = self.ledger.append(
                ExecutionState.PROCESS_TERMINATED,
                expected=current,
                terminal_status="CANCELLED",
                detail="restart before measured receipt reconciled",
            )
            _first, _second, terminal = self._finish_terminal_capture(
                terminated=terminated,
                lease_ledger=lease_ledger,
                workspace_manager=workspace_manager,
                repo_path=repo_path,
                pre_checkpoint=pre_checkpoint,
                require_pre_equal=True,
            )
            return terminal
        receipt = current.receipt
        if receipt is None:
            raise ExecutionError("PROCESS_RECEIPT_MISSING")
        scope = self._scope_evidence(backend, receipt.reservation.scope_name)
        if scope.state is ScopeEvidenceState.UNKNOWN:
            return self._mark_recovery_required(
                current,
                lease_ledger,
                "measured containment scope evidence is unknown",
            )
        exact_scope = scope.cgroup_path
        identity_matches = receipt.process_identity.matches_current(proc_root)
        try:
            populated = backend.cgroup_populated(Path(receipt.cgroup_path))
        except BaseException:
            return self._mark_recovery_required(
                current,
                lease_ledger,
                "measured cgroup population evidence is unreadable",
            )
        process_dir = proc_root / str(receipt.process_identity.pid)
        process_stat_exists = (process_dir / "stat").exists()
        if process_dir.exists() and not process_stat_exists:
            return self._mark_recovery_required(
                current,
                lease_ledger,
                "process directory exists without complete identity evidence",
            )
        if scope.state is ScopeEvidenceState.ABSENT and populated is True:
            return self._mark_recovery_required(
                current,
                lease_ledger,
                "scope absent but recorded cgroup remains populated",
            )
        if scope.state is ScopeEvidenceState.PRESENT and (
            exact_scope is None
            or Path(exact_scope) != Path(receipt.cgroup_path)
            or populated is None
        ):
            return self._mark_recovery_required(
                current,
                lease_ledger,
                "measured containment identity or population is ambiguous",
            )
        if (
            not process_stat_exists
            and scope.state is ScopeEvidenceState.PRESENT
            and populated is True
        ):
            if current.state is not ExecutionState.CANCEL_REQUESTED:
                current = self.ledger.append(
                    ExecutionState.CANCEL_REQUESTED,
                    expected=current,
                    detail="absent main process left populated exact containment",
                )
            state, _details = cancel_contained(
                backend,
                receipt.reservation.scope_name,
                Path(receipt.cgroup_path),
                cancellation,
            )
            if state is not ContainmentState.TERMINATED:
                return self._mark_recovery_required(
                    current,
                    lease_ledger,
                    "orphan descendants did not drain during restart",
                )
            backend.stop_unit(receipt.reservation.scope_name)
            if self._scope_evidence(
                backend, receipt.reservation.scope_name
            ).state is not ScopeEvidenceState.ABSENT:
                return self._mark_recovery_required(
                    current,
                    lease_ledger,
                    "measured containment absence not proven after drain",
                )
            populated = False
            scope = ScopeEvidence(
                ScopeEvidenceState.ABSENT,
                None,
                "exact populated containment drained and stopped",
            )
            exact_scope = None
        scope_proven_gone_or_empty = (
            scope.state is ScopeEvidenceState.ABSENT and populated in {None, False}
        ) or (
            scope.state is ScopeEvidenceState.PRESENT
            and populated is False
            and exact_scope is not None
            and Path(exact_scope) == Path(receipt.cgroup_path)
        )
        if not process_stat_exists and scope_proven_gone_or_empty:
            terminated = self.ledger.append(
                ExecutionState.PROCESS_TERMINATED,
                expected=current,
                terminal_status=(
                    "CANCELLED"
                    if current.state is ExecutionState.CANCEL_REQUESTED
                    else "FAILED"
                ),
                detail="exact process absent and exact containment empty",
            )
            _first, _second, terminal = self._finish_terminal_capture(
                terminated=terminated,
                lease_ledger=lease_ledger,
                workspace_manager=workspace_manager,
                repo_path=repo_path,
                pre_checkpoint=pre_checkpoint,
            )
            return terminal
        try:
            cgroup_bytes = (
                proc_root / str(receipt.process_identity.pid) / "cgroup"
            ).read_bytes()
            if len(cgroup_bytes) > 4096:
                raise OSError("process cgroup record exceeds bound")
            cgroup_lines = cgroup_bytes.decode("utf-8", errors="strict").splitlines()
            unified = [line[3:] for line in cgroup_lines if line.startswith("0::")]
            process_cgroup_matches = unified == [receipt.child_cgroup]
        except (OSError, UnicodeError):
            process_cgroup_matches = False
        if (
            exact_scope is None
            or Path(exact_scope) != Path(receipt.cgroup_path)
            or not identity_matches
            or not process_cgroup_matches
            or populated is not True
        ):
            recovery = self.ledger.append(
                ExecutionState.RECOVERY_REQUIRED,
                expected=current,
                detail="process identity or containment mismatch on restart",
            )
            lease = lease_ledger.recover()
            if lease is not None and lease.state in {
                WorkspaceLeaseState.ACTIVE,
                WorkspaceLeaseState.EXECUTING,
                WorkspaceLeaseState.CANCELLING,
            }:
                lease_ledger.require_recovery(
                    current.lease,
                    reason="process identity or containment mismatch on restart",
                )
            return recovery
        if current.state is not ExecutionState.CANCEL_REQUESTED:
            current = self.ledger.append(
                ExecutionState.CANCEL_REQUESTED,
                expected=current,
                detail="restart reconciliation cancellation",
            )
        state, _details = cancel_contained(
            backend,
            receipt.reservation.scope_name,
            Path(receipt.cgroup_path),
            cancellation,
        )
        if state is not ContainmentState.TERMINATED:
            recovery = self.ledger.append(
                ExecutionState.RECOVERY_REQUIRED,
                expected=current,
                detail="restart cancellation did not drain containment",
            )
            lease = lease_ledger.recover()
            if lease is not None and lease.state in {
                WorkspaceLeaseState.ACTIVE,
                WorkspaceLeaseState.EXECUTING,
                WorkspaceLeaseState.CANCELLING,
            }:
                lease_ledger.require_recovery(
                    current.lease, reason="restart cancellation did not drain"
                )
            return recovery
        terminated = self.ledger.append(
            ExecutionState.PROCESS_TERMINATED,
            expected=current,
            terminal_status="CANCELLED",
        )
        _first, _second, terminal = self._finish_terminal_capture(
            terminated=terminated,
            lease_ledger=lease_ledger,
            workspace_manager=workspace_manager,
            repo_path=repo_path,
            pre_checkpoint=pre_checkpoint,
        )
        return terminal
