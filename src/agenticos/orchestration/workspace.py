"""Exclusive, durable, fenced project-workspace lease authority."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, TypeVar

from agenticos.sandbox.worktree import (
    WorkspaceCaptureCompleteness,
    WorkspaceReuseDecision,
    WorktreeValidationError,
    acquire_repository_lock,
)

from .canonical import CanonicalDataError, canonical_json_bytes, canonical_json_line, load_canonical_json
from .journal import _durable_replace
from .models import (
    ControllerValidationError,
    TaskStatus,
    WorkspaceIdentityRef,
    require_digest,
    require_exact_fields,
    require_identifier,
    require_uint,
)

LEASE_IDENTITY_SCHEMA = "AOSWORKSPACELEASEIDENTITY/1"
LEASE_RECORD_SCHEMA = "AOSWORKSPACELEASE/1"
LEASE_ADMISSION_SCHEMA = "AOSWORKSPACELEASEADMISSION/1"
LEASE_TAIL_SCHEMA = "AOSWORKSPACELEASETAIL/1"
ZERO_DIGEST = "0" * 64
DEFAULT_MAX_RECORDS = 1024
DEFAULT_MAX_RECORD_BYTES = 64 * 1024
MAX_REASON_BYTES = 1024
_LOWER_HEX_32_RE = re.compile(r"[0-9a-f]{32}\Z")
_SAFE_PATH_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_RECORD_RE = re.compile(r"(?P<sequence>[0-9]{20})\.lease\.json\Z")


class WorkspaceLeaseError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail[:4096]
        super().__init__(f"{code}: {self.detail}" if self.detail else code)


class WorkspaceLeaseState(str, Enum):
    ACTIVE = "ACTIVE"
    EXECUTING = "EXECUTING"
    CANCELLING = "CANCELLING"
    RELEASED = "RELEASED"
    CANCELLED = "CANCELLED"
    STALE = "STALE"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class WorkspaceLeaseAdmission:
    """Controller-issued proof that M5 and Slice B admitted this exact lease."""

    schema: str
    project_id: str
    task_id: str
    task_generation: int
    attempt: int
    controller_epoch: int
    lease_epoch: int
    workspace: WorkspaceIdentityRef
    dispatch_nonce: str
    repository_id: str
    baseline_commit: str
    checkpoint_digest: str
    reservation_digest: str
    worktree_device: int
    worktree_inode: int

    def __post_init__(self) -> None:
        if self.schema != LEASE_ADMISSION_SCHEMA:
            raise ControllerValidationError("INVALID_SCHEMA")
        for name in ("project_id", "task_id", "repository_id"):
            require_identifier(name, getattr(self, name))
        for name in (
            "task_generation",
            "attempt",
            "controller_epoch",
            "lease_epoch",
            "worktree_device",
            "worktree_inode",
        ):
            require_uint(name, getattr(self, name), minimum=1)
        if not isinstance(self.workspace, WorkspaceIdentityRef):
            raise ControllerValidationError("INVALID_WORKSPACE_IDENTITY")
        if (
            type(self.dispatch_nonce) is not str
            or _LOWER_HEX_32_RE.fullmatch(self.dispatch_nonce) is None
        ):
            raise ControllerValidationError("INVALID_DISPATCH_NONCE")
        require_digest("checkpoint_digest", self.checkpoint_digest)
        require_identifier("reservation_digest", self.reservation_digest)
        if (
            type(self.baseline_commit) is not str
            or re.fullmatch(r"[0-9a-f]{40}", self.baseline_commit) is None
        ):
            raise ControllerValidationError("INVALID_BASELINE_COMMIT")

    @classmethod
    def issue(
        cls,
        *,
        board: object,
        identity: "WorkspaceLeaseIdentity",
        checkpoint_capture: object,
    ) -> "WorkspaceLeaseAdmission":
        """Validate live controller, M5, and complete reusable Slice B evidence."""
        try:
            project = board.project
            task = board.task(identity.task_id)
            checkpoint = checkpoint_capture.checkpoint
            valid = (
                checkpoint_capture.decision is WorkspaceReuseDecision.REUSABLE
                and checkpoint is not None
                and checkpoint.capture_completeness
                is WorkspaceCaptureCompleteness.COMPLETE
                and project.project_id == task.project_id == identity.project_id
                and task.task_id == identity.task_id
                and task.status is TaskStatus.IN_PROGRESS
                and task.generation == identity.task_generation
                and task.attempt_count == identity.attempt
                and project.controller_epoch == identity.controller_epoch
                and project.lease_epoch
                == task.lease_epoch
                == identity.lease_epoch
                and project.workspace == task.workspace == identity.workspace
                and project.baseline.repository_id == checkpoint.repository_id
                and project.baseline.commit_sha == checkpoint.baseline_commit_sha
                and checkpoint.task_id == identity.workspace.workspace_id
                and checkpoint.generation == identity.workspace.generation
                and checkpoint.reservation_digest
                == identity.workspace.reservation_id
                and checkpoint.checkpoint_digest
                == identity.pre_checkpoint_digest
            )
        except (AttributeError, KeyError, TypeError):
            valid = False
        if not valid:
            raise WorkspaceLeaseError("LEASE_ADMISSION_EVIDENCE_MISMATCH")
        return cls(
            LEASE_ADMISSION_SCHEMA,
            identity.project_id,
            identity.task_id,
            identity.task_generation,
            identity.attempt,
            identity.controller_epoch,
            identity.lease_epoch,
            identity.workspace,
            identity.dispatch_nonce,
            checkpoint.repository_id,
            checkpoint.baseline_commit_sha,
            checkpoint.checkpoint_digest,
            checkpoint.reservation_digest,
            checkpoint.worktree_device,
            checkpoint.worktree_inode,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            name: (
                self.workspace.to_dict()
                if name == "workspace"
                else getattr(self, name)
            )
            for name in self.__dataclass_fields__
        }

    @classmethod
    def from_dict(cls, raw: object) -> "WorkspaceLeaseAdmission":
        value = require_exact_fields(raw, set(cls.__dataclass_fields__))
        return cls(
            **{
                **value,
                "workspace": WorkspaceIdentityRef.from_dict(value["workspace"]),
            }
        )


@dataclass(frozen=True, slots=True)
class WorkspaceLeaseIdentity:
    schema: str
    project_id: str
    task_id: str
    task_generation: int
    attempt: int
    controller_epoch: int
    lease_epoch: int
    workspace: WorkspaceIdentityRef
    dispatch_nonce: str
    pre_checkpoint_digest: str

    def __post_init__(self) -> None:
        if self.schema != LEASE_IDENTITY_SCHEMA:
            raise ControllerValidationError("INVALID_SCHEMA")
        require_identifier("project_id", self.project_id)
        require_identifier("task_id", self.task_id)
        for name in (
            "task_generation", "attempt", "controller_epoch", "lease_epoch"
        ):
            require_uint(name, getattr(self, name), minimum=1)
        if not isinstance(self.workspace, WorkspaceIdentityRef):
            raise ControllerValidationError("INVALID_WORKSPACE_IDENTITY")
        if type(self.dispatch_nonce) is not str or _LOWER_HEX_32_RE.fullmatch(self.dispatch_nonce) is None:
            raise ControllerValidationError("INVALID_DISPATCH_NONCE")
        require_digest("pre_checkpoint_digest", self.pre_checkpoint_digest)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "project_id": self.project_id,
            "task_id": self.task_id,
            "task_generation": self.task_generation,
            "attempt": self.attempt,
            "controller_epoch": self.controller_epoch,
            "lease_epoch": self.lease_epoch,
            "workspace": self.workspace.to_dict(),
            "dispatch_nonce": self.dispatch_nonce,
            "pre_checkpoint_digest": self.pre_checkpoint_digest,
        }

    @classmethod
    def from_dict(cls, raw: object) -> "WorkspaceLeaseIdentity":
        value = require_exact_fields(raw, set(cls.__dataclass_fields__))
        return cls(
            **{
                **value,
                "workspace": WorkspaceIdentityRef.from_dict(value["workspace"]),
            }
        )


def _digest_record(value: dict[str, object]) -> str:
    unsigned = {name: item for name, item in value.items() if name != "record_digest"}
    return hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()


def _durable_tail_replace(source: Path, target: Path) -> None:
    """Atomically advance the mutable tail anchor after its bytes are fsynced."""
    os.replace(source, target)
    if os.name != "nt":
        directory_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


@dataclass(frozen=True, slots=True)
class WorkspaceLeaseRecord:
    schema: str
    sequence: int
    previous_record_digest: str
    state: WorkspaceLeaseState
    identity: WorkspaceLeaseIdentity
    admission: WorkspaceLeaseAdmission
    reason: str | None
    record_digest: str

    def __post_init__(self) -> None:
        if self.schema != LEASE_RECORD_SCHEMA:
            raise ControllerValidationError("INVALID_SCHEMA")
        require_uint("sequence", self.sequence, minimum=1)
        require_digest("previous_record_digest", self.previous_record_digest)
        if not isinstance(self.state, WorkspaceLeaseState):
            raise ControllerValidationError("INVALID_LEASE_STATE")
        if not isinstance(self.identity, WorkspaceLeaseIdentity):
            raise ControllerValidationError("INVALID_LEASE_IDENTITY")
        if not isinstance(self.admission, WorkspaceLeaseAdmission):
            raise ControllerValidationError("INVALID_LEASE_ADMISSION")
        identity = self.identity
        admission = self.admission
        if not all(
            (
                admission.project_id == identity.project_id,
                admission.task_id == identity.task_id,
                admission.task_generation == identity.task_generation,
                admission.attempt == identity.attempt,
                admission.controller_epoch == identity.controller_epoch,
                admission.lease_epoch == identity.lease_epoch,
                admission.workspace == identity.workspace,
                admission.dispatch_nonce == identity.dispatch_nonce,
                admission.checkpoint_digest == identity.pre_checkpoint_digest,
                admission.reservation_digest == identity.workspace.reservation_id,
            )
        ):
            raise ControllerValidationError("LEASE_ADMISSION_EVIDENCE_MISMATCH")
        if self.state is WorkspaceLeaseState.ACTIVE:
            if self.reason is not None:
                raise ControllerValidationError("INVALID_ACTIVE_REASON")
        elif (
            type(self.reason) is not str
            or not self.reason
            or len(self.reason.encode("utf-8")) > MAX_REASON_BYTES
        ):
            raise ControllerValidationError("INVALID_REASON")
        require_digest("record_digest", self.record_digest)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "sequence": self.sequence,
            "previous_record_digest": self.previous_record_digest,
            "state": self.state.value,
            "identity": self.identity.to_dict(),
            "admission": self.admission.to_dict(),
            "reason": self.reason,
            "record_digest": self.record_digest,
        }

    @classmethod
    def create(
        cls,
        sequence: int,
        previous_record_digest: str,
        state: WorkspaceLeaseState,
        identity: WorkspaceLeaseIdentity,
        admission: WorkspaceLeaseAdmission,
        reason: str | None,
    ) -> "WorkspaceLeaseRecord":
        raw: dict[str, object] = {
            "schema": LEASE_RECORD_SCHEMA,
            "sequence": sequence,
            "previous_record_digest": previous_record_digest,
            "state": state.value,
            "identity": identity.to_dict(),
            "admission": admission.to_dict(),
            "reason": reason,
            "record_digest": "",
        }
        raw["record_digest"] = _digest_record(raw)
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: object) -> "WorkspaceLeaseRecord":
        value = require_exact_fields(raw, set(cls.__dataclass_fields__))
        try:
            state = WorkspaceLeaseState(value["state"])
        except (TypeError, ValueError) as exc:
            raise ControllerValidationError("INVALID_LEASE_STATE") from exc
        return cls(
            **{
                **value,
                "state": state,
                "identity": WorkspaceLeaseIdentity.from_dict(value["identity"]),
                "admission": WorkspaceLeaseAdmission.from_dict(value["admission"]),
            }
        )


class WorkspaceLeaseLedger:
    """Hash-chained immutable records guarded by a kernel-held project lock."""

    def __init__(
        self,
        root: Path,
        project_id: str,
        *,
        max_records: int = DEFAULT_MAX_RECORDS,
        max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
        lock_timeout: float = 30.0,
    ) -> None:
        require_identifier("project_id", project_id)
        if _SAFE_PATH_ID_RE.fullmatch(project_id) is None:
            raise WorkspaceLeaseError("INVALID_PROJECT_PATH_ID")
        if type(max_records) is not int or max_records < 1:
            raise WorkspaceLeaseError("INVALID_LEASE_LIMIT")
        if type(max_record_bytes) is not int or max_record_bytes < 1024:
            raise WorkspaceLeaseError("INVALID_RECORD_LIMIT")
        if type(lock_timeout) not in (int, float) or lock_timeout <= 0:
            raise WorkspaceLeaseError("INVALID_LOCK_TIMEOUT")
        self.root = Path(root)
        self.project_id = project_id
        self.project_root = self.root / project_id
        self.lock_path = self.root / ".locks" / f"{project_id}.lock"
        self.tail_path = self.root / ".tails" / f"{project_id}.tail.json"
        self.max_records = max_records
        self.max_record_bytes = max_record_bytes
        self.lock_timeout = float(lock_timeout)
        self.project_root.mkdir(parents=True, exist_ok=True)

    def _locked(self):
        try:
            return acquire_repository_lock(self.lock_path, timeout=self.lock_timeout)
        except WorktreeValidationError as exc:
            raise WorkspaceLeaseError("LEASE_LOCK_FAILED", str(exc)) from exc

    def recover(self) -> WorkspaceLeaseRecord | None:
        try:
            with self._locked():
                return self._recover_unlocked()
        except WorktreeValidationError as exc:
            raise WorkspaceLeaseError("LEASE_LOCK_FAILED", str(exc)) from exc

    def _recover_unlocked(self) -> WorkspaceLeaseRecord | None:
        try:
            entries = sorted(self.project_root.iterdir(), key=lambda path: path.name)
        except OSError as exc:
            raise WorkspaceLeaseError("LEASE_DIRECTORY_UNREADABLE") from exc
        if len(entries) > self.max_records:
            raise WorkspaceLeaseError("LEASE_RECORD_LIMIT")
        records: list[WorkspaceLeaseRecord] = []
        for path in entries:
            match = _RECORD_RE.fullmatch(path.name)
            if match is None or path.is_symlink() or not path.is_file():
                raise WorkspaceLeaseError("UNKNOWN_LEASE_ENTRY", path.name)
            try:
                raw = path.read_bytes()
                if len(raw) > self.max_record_bytes or not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
                    raise WorkspaceLeaseError("NONCANONICAL_OR_CORRUPT_RECORD", path.name)
                value = load_canonical_json(raw[:-1], max_bytes=self.max_record_bytes - 1)
                if canonical_json_line(value, max_bytes=self.max_record_bytes) != raw:
                    raise WorkspaceLeaseError("NONCANONICAL_OR_CORRUPT_RECORD", path.name)
                record = WorkspaceLeaseRecord.from_dict(value)
            except (OSError, CanonicalDataError, ControllerValidationError, TypeError, ValueError) as exc:
                if isinstance(exc, WorkspaceLeaseError):
                    raise
                raise WorkspaceLeaseError("NONCANONICAL_OR_CORRUPT_RECORD", path.name) from exc
            sequence = int(match.group("sequence"))
            if record.sequence != sequence or sequence != len(records) + 1:
                raise WorkspaceLeaseError("LEASE_SEQUENCE_GAP_OR_ROLLBACK")
            if record.record_digest != _digest_record(record.to_dict()):
                raise WorkspaceLeaseError("LEASE_RECORD_DIGEST_MISMATCH")
            expected_previous = ZERO_DIGEST if not records else records[-1].record_digest
            if record.previous_record_digest != expected_previous:
                raise WorkspaceLeaseError("LEASE_HASH_CHAIN_MISMATCH")
            self._validate_transition(records[-1] if records else None, record)
            records.append(record)
        self._validate_tail_unlocked(records)
        return records[-1] if records else None

    def _validate_tail_unlocked(self, records: list[WorkspaceLeaseRecord]) -> None:
        if not self.tail_path.exists():
            if records:
                raise WorkspaceLeaseError("LEASE_TAIL_MISSING")
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
            raise WorkspaceLeaseError("CORRUPT_LEASE_TAIL") from exc
        if value["schema"] != LEASE_TAIL_SCHEMA or not records:
            raise WorkspaceLeaseError("LEASE_TAIL_ROLLBACK")
        if (
            value["sequence"] != records[-1].sequence
            or value["record_digest"] != records[-1].record_digest
        ):
            raise WorkspaceLeaseError("LEASE_TAIL_ROLLBACK")

    def _validate_transition(
        self,
        previous: WorkspaceLeaseRecord | None,
        current: WorkspaceLeaseRecord,
    ) -> None:
        identity = current.identity
        if identity.project_id != self.project_id:
            raise WorkspaceLeaseError("PROJECT_IDENTITY_MISMATCH")
        if previous is None:
            if current.state is not WorkspaceLeaseState.ACTIVE or identity.lease_epoch != 1:
                raise WorkspaceLeaseError("INVALID_INITIAL_LEASE")
            return
        prior_identity = previous.identity
        if identity.workspace != prior_identity.workspace:
            raise WorkspaceLeaseError("WORKSPACE_IDENTITY_MISMATCH")
        if current.state is not WorkspaceLeaseState.ACTIVE and current.admission != previous.admission:
            raise WorkspaceLeaseError("LEASE_ADMISSION_CHANGED")
        if previous.state is WorkspaceLeaseState.ACTIVE:
            if current.state not in {
                WorkspaceLeaseState.EXECUTING,
                WorkspaceLeaseState.CANCELLING,
                WorkspaceLeaseState.RELEASED,
                WorkspaceLeaseState.STALE,
                WorkspaceLeaseState.RECOVERY_REQUIRED,
            } or identity != prior_identity:
                raise WorkspaceLeaseError("INVALID_ACTIVE_LEASE_TRANSITION")
            return
        if previous.state is WorkspaceLeaseState.EXECUTING:
            if current.state not in {
                WorkspaceLeaseState.CANCELLING,
                WorkspaceLeaseState.RELEASED,
                WorkspaceLeaseState.STALE,
                WorkspaceLeaseState.RECOVERY_REQUIRED,
            } or identity != prior_identity:
                raise WorkspaceLeaseError("INVALID_EXECUTING_LEASE_TRANSITION")
            return
        if previous.state is WorkspaceLeaseState.CANCELLING:
            if current.state not in {
                WorkspaceLeaseState.CANCELLED,
                WorkspaceLeaseState.RECOVERY_REQUIRED,
            } or identity != prior_identity:
                raise WorkspaceLeaseError("INVALID_CANCELLING_LEASE_TRANSITION")
            return
        if previous.state is WorkspaceLeaseState.RECOVERY_REQUIRED:
            raise WorkspaceLeaseError("RECOVERY_REQUIRED")
        if current.state is not WorkspaceLeaseState.ACTIVE:
            raise WorkspaceLeaseError("INVALID_TERMINAL_LEASE_TRANSITION")
        if identity.lease_epoch != prior_identity.lease_epoch + 1:
            raise WorkspaceLeaseError("LEASE_EPOCH_NOT_MONOTONIC")
        if identity.controller_epoch < prior_identity.controller_epoch:
            raise WorkspaceLeaseError("CONTROLLER_EPOCH_ROLLBACK")

    def _write_unlocked(self, record: WorkspaceLeaseRecord) -> WorkspaceLeaseRecord:
        if record.sequence > self.max_records:
            raise WorkspaceLeaseError("LEASE_RECORD_LIMIT")
        target = self.project_root / f"{record.sequence:020d}.lease.json"
        raw = canonical_json_line(record.to_dict(), max_bytes=self.max_record_bytes)
        temporary = self.project_root / f".tmp-{secrets.token_hex(16)}"
        tail_temporary = self.tail_path.parent / f".tmp-{secrets.token_hex(16)}"
        try:
            with temporary.open("xb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            _durable_replace(temporary, target)
            tail_raw = canonical_json_line(
                {
                    "schema": LEASE_TAIL_SCHEMA,
                    "sequence": record.sequence,
                    "record_digest": record.record_digest,
                },
                max_bytes=4096,
            )
            self.tail_path.parent.mkdir(parents=True, exist_ok=True)
            with tail_temporary.open("xb") as handle:
                handle.write(tail_raw)
                handle.flush()
                os.fsync(handle.fileno())
            _durable_tail_replace(tail_temporary, self.tail_path)
        except (OSError, CanonicalDataError) as exc:
            raise WorkspaceLeaseError("DURABLE_LEASE_WRITE_FAILED", target.name) from exc
        finally:
            try:
                temporary.unlink(missing_ok=True)
                tail_temporary.unlink(missing_ok=True)
            except OSError:
                pass
        return self._recover_unlocked()  # type: ignore[return-value]

    def acquire(
        self,
        identity: WorkspaceLeaseIdentity,
        admission: WorkspaceLeaseAdmission,
    ) -> WorkspaceLeaseRecord:
        if not isinstance(identity, WorkspaceLeaseIdentity):
            raise WorkspaceLeaseError("INVALID_LEASE_IDENTITY")
        if not isinstance(admission, WorkspaceLeaseAdmission):
            raise WorkspaceLeaseError("INVALID_LEASE_ADMISSION")
        try:
            WorkspaceLeaseRecord.create(
                1,
                ZERO_DIGEST,
                WorkspaceLeaseState.ACTIVE,
                identity,
                admission,
                None,
            )
        except ControllerValidationError as exc:
            raise WorkspaceLeaseError("LEASE_ADMISSION_EVIDENCE_MISMATCH") from exc
        try:
            with self._locked():
                current = self._recover_unlocked()
                if identity.project_id != self.project_id:
                    raise WorkspaceLeaseError("PROJECT_IDENTITY_MISMATCH")
                if current is not None:
                    if current.state in {
                        WorkspaceLeaseState.ACTIVE,
                        WorkspaceLeaseState.EXECUTING,
                        WorkspaceLeaseState.CANCELLING,
                    }:
                        raise WorkspaceLeaseError("LEASE_ALREADY_ACTIVE")
                    if current.state is WorkspaceLeaseState.RECOVERY_REQUIRED:
                        raise WorkspaceLeaseError("RECOVERY_REQUIRED")
                    if identity.workspace != current.identity.workspace:
                        raise WorkspaceLeaseError("WORKSPACE_IDENTITY_MISMATCH")
                    if identity.controller_epoch < current.identity.controller_epoch:
                        raise WorkspaceLeaseError("CONTROLLER_EPOCH_ROLLBACK")
                    if identity.lease_epoch != current.identity.lease_epoch + 1:
                        raise WorkspaceLeaseError("LEASE_EPOCH_NOT_MONOTONIC")
                elif identity.lease_epoch != 1:
                    raise WorkspaceLeaseError("LEASE_EPOCH_NOT_MONOTONIC")
                return self._write_unlocked(
                    WorkspaceLeaseRecord.create(
                        1 if current is None else current.sequence + 1,
                        ZERO_DIGEST if current is None else current.record_digest,
                        WorkspaceLeaseState.ACTIVE,
                        identity,
                        admission,
                        None,
                    )
                )
        except WorktreeValidationError as exc:
            raise WorkspaceLeaseError("LEASE_LOCK_FAILED", str(exc)) from exc

    def _terminal(
        self,
        identity: WorkspaceLeaseIdentity,
        state: WorkspaceLeaseState,
        reason: str,
    ) -> WorkspaceLeaseRecord:
        if type(reason) is not str or not reason or len(reason.encode("utf-8")) > MAX_REASON_BYTES:
            raise WorkspaceLeaseError("INVALID_REASON")
        try:
            with self._locked():
                current = self._recover_unlocked()
                allowed_states = {
                    WorkspaceLeaseState.ACTIVE,
                    WorkspaceLeaseState.EXECUTING,
                }
                if state is WorkspaceLeaseState.CANCELLED:
                    allowed_states = {WorkspaceLeaseState.CANCELLING}
                elif state is WorkspaceLeaseState.RECOVERY_REQUIRED:
                    allowed_states.add(WorkspaceLeaseState.CANCELLING)
                if current is None or current.state not in allowed_states:
                    raise WorkspaceLeaseError("LEASE_NOT_ACTIVE")
                if identity.lease_epoch != current.identity.lease_epoch:
                    raise WorkspaceLeaseError("LEASE_EPOCH_NOT_MONOTONIC")
                if identity != current.identity:
                    raise WorkspaceLeaseError("LEASE_IDENTITY_MISMATCH")
                return self._write_unlocked(
                    WorkspaceLeaseRecord.create(
                        current.sequence + 1,
                        current.record_digest,
                        state,
                        identity,
                        current.admission,
                        reason,
                    )
                )
        except WorktreeValidationError as exc:
            raise WorkspaceLeaseError("LEASE_LOCK_FAILED", str(exc)) from exc

    def release(self, identity: WorkspaceLeaseIdentity, *, reason: str) -> WorkspaceLeaseRecord:
        return self._terminal(identity, WorkspaceLeaseState.RELEASED, reason)

    def begin_cancellation(
        self, identity: WorkspaceLeaseIdentity, *, reason: str
    ) -> WorkspaceLeaseRecord:
        return self._terminal(identity, WorkspaceLeaseState.CANCELLING, reason)

    def cancel(self, identity: WorkspaceLeaseIdentity, *, reason: str) -> WorkspaceLeaseRecord:
        return self._terminal(identity, WorkspaceLeaseState.CANCELLED, reason)

    def mark_stale(self, identity: WorkspaceLeaseIdentity, *, reason: str) -> WorkspaceLeaseRecord:
        return self._terminal(identity, WorkspaceLeaseState.STALE, reason)

    def require_recovery(self, identity: WorkspaceLeaseIdentity, *, reason: str) -> WorkspaceLeaseRecord:
        return self._terminal(identity, WorkspaceLeaseState.RECOVERY_REQUIRED, reason)

    def require_active(self, identity: WorkspaceLeaseIdentity) -> WorkspaceLeaseRecord:
        current = self.recover()
        if current is None or current.state is not WorkspaceLeaseState.ACTIVE:
            raise WorkspaceLeaseError("LEASE_NOT_ACTIVE")
        if identity.lease_epoch != current.identity.lease_epoch:
            raise WorkspaceLeaseError("LEASE_EPOCH_NOT_MONOTONIC")
        if identity != current.identity:
            raise WorkspaceLeaseError("LEASE_IDENTITY_MISMATCH")
        return current

    def authorize_execution(
        self,
        identity: WorkspaceLeaseIdentity,
        callback: Callable[[], _T],
    ) -> tuple[WorkspaceLeaseRecord, _T]:
        """Serialize durable execution authority and release against cancellation."""
        try:
            with self._locked():
                current = self._recover_unlocked()
                if current is None or current.state is not WorkspaceLeaseState.ACTIVE:
                    raise WorkspaceLeaseError("LEASE_NOT_ACTIVE")
                if current.identity != identity:
                    raise WorkspaceLeaseError("LEASE_IDENTITY_MISMATCH")
                executing = self._write_unlocked(
                    WorkspaceLeaseRecord.create(
                        current.sequence + 1,
                        current.record_digest,
                        WorkspaceLeaseState.EXECUTING,
                        identity,
                        current.admission,
                        "execution release authorized",
                    )
                )
                return executing, callback()
        except WorktreeValidationError as exc:
            raise WorkspaceLeaseError("LEASE_LOCK_FAILED", str(exc)) from exc

    def cancel_with_callback(
        self,
        identity: WorkspaceLeaseIdentity,
        *,
        reason: str,
        callback: Callable[[], _T],
    ) -> tuple[WorkspaceLeaseRecord, _T]:
        """Fence reuse through signalling; terminal capture completes cancellation."""
        if type(reason) is not str or not reason or len(reason.encode("utf-8")) > MAX_REASON_BYTES:
            raise WorkspaceLeaseError("INVALID_REASON")
        try:
            with self._locked():
                current = self._recover_unlocked()
                if current is None or current.state not in {
                    WorkspaceLeaseState.ACTIVE,
                    WorkspaceLeaseState.EXECUTING,
                    WorkspaceLeaseState.CANCELLING,
                }:
                    raise WorkspaceLeaseError("LEASE_NOT_ACTIVE")
                if current.identity != identity:
                    raise WorkspaceLeaseError("LEASE_IDENTITY_MISMATCH")
                if current.state is WorkspaceLeaseState.CANCELLING:
                    cancelling = current
                else:
                    cancelling = self._write_unlocked(
                        WorkspaceLeaseRecord.create(
                            current.sequence + 1,
                            current.record_digest,
                            WorkspaceLeaseState.CANCELLING,
                            identity,
                            current.admission,
                            reason,
                        )
                    )
                try:
                    result = callback()
                except BaseException:
                    self._write_unlocked(
                        WorkspaceLeaseRecord.create(
                            cancelling.sequence + 1,
                            cancelling.record_digest,
                            WorkspaceLeaseState.RECOVERY_REQUIRED,
                            identity,
                            cancelling.admission,
                            "cancellation drain failed or is ambiguous",
                        )
                    )
                    raise
                return cancelling, result
        except WorktreeValidationError as exc:
            raise WorkspaceLeaseError("LEASE_LOCK_FAILED", str(exc)) from exc
