"""Milestone 5 Controlled Git Worktree — Controller-Owned Worktree Lifecycle & Filesystem Authority Substrate.

This module provides trusted, controller-side primitives for:
1. Repository Identity representation & kernel identity binding (SHA-1 / SHA-256 detection).
2. Baseline commit SHA validation (Plumbing-only, repo-object-format strict verification).
3. Task Ref derivation & strict ASCII ref grammar enforcement.
4. Ownership proof modeling, controller storage authentication, and fail-closed ref rules.
5. Controller-owned durable worktree state root outside the authoritative checkout.
6. Real linked Git worktree creation, post-creation verification, transaction tracking,
   concurrency locking, crash recovery classification, and safe preservation/removal.
7. Descriptor-bound filesystem authority (openat2/fstat kernel identity) and identity-guarded ref deletion.

GOVERNING PRINCIPLE: Models reason; AgenticOS guarantees.
AUTHORITY BOUNDARY: The main .git directory is NEVER exposed to hostile workers.

SLICE 2A.1 DISPOSAL & PRESERVATION INVARIANTS:
- CLEAN WORKTREE != DISPOSABLE TASK.
- A task worktree is DISPOSABLE ONLY IF it remains strictly at the original baseline commit.
- Tasks containing task-produced commits beyond baseline are classified COMMITTED_WORK_PRESERVED and CANNOT be deleted.
- Ref deletion uses git update-ref -d <ref> <expected_sha> to prevent ref deletion races.
- Filesystem operations re-verify fstat kernel identity (st_dev/st_ino) before any lifecycle transition.
"""

from __future__ import annotations

import contextlib
import enum
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Optional


OWNERSHIP_SCHEMA_VERSION = "AOSWORKTREE/1"
LIFECYCLE_SCHEMA_VERSION = "AOSLIFECYCLE/1"

_TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_WORKTREE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_LOWER_HEX_40_RE = re.compile(r"^[0-9a-f]{40}\Z")
_LOWER_HEX_64_RE = re.compile(r"^[0-9a-f]{64}\Z")
_LOWER_HEX_32_RE = re.compile(r"^[0-9a-f]{32}\Z")
_MAX_UNSIGNED_64 = (1 << 64) - 1

_ENV_DENY_SUBSTRINGS = (
    "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API_KEY", "APIKEY",
    "PRIVATE_KEY", "AUTH_SOCK",
)
_ENV_DENY_PREFIXES = (
    "AWS_", "AZURE_", "GOOGLE_", "GCLOUD_", "GCP_", "DOCKER_", "GPG_",
    "DBUS_", "GITHUB_", "GH_", "OPENAI_", "ANTHROPIC_", "MOONSHOT_",
    "KIMI_", "SSH_",
)
_ENV_DENY_EXACT = {"XDG_RUNTIME_DIR"}


class WorktreeValidationError(ValueError):
    """Base exception for worktree identity and ref validation errors."""


class InvalidBaselineCommitError(WorktreeValidationError):
    """Raised when baseline SHA is invalid, non-existent, or not a commit object."""


class InvalidRefNameError(WorktreeValidationError):
    """Raised when ref syntax violates rules."""


class TaskRefCollisionError(WorktreeValidationError):
    """Raised when ref exists and ownership cannot be proven."""


class RepositoryIdentityError(WorktreeValidationError):
    """Raised when repository identity verification fails."""


class WorktreeLifecycleStatus(str, enum.Enum):
    """Enumeration of lifecycle status and recovery classifications."""

    RESERVED = "RESERVED"
    STATE_PREPARED = "STATE_PREPARED"
    REF_RESERVED = "REF_RESERVED"
    WORKTREE_CREATED = "WORKTREE_CREATED"
    WORKTREE_VERIFIED = "WORKTREE_VERIFIED"
    READY = "READY"

    # Disposal & Preservation Classifications
    CLEAN_BASELINE_DISPOSABLE = "CLEAN_BASELINE_DISPOSABLE"
    COMMITTED_WORK_PRESERVED = "COMMITTED_WORK_PRESERVED"
    DIRTY_PRESERVED = "DIRTY_PRESERVED"
    PARTIAL_PRESERVED = "PARTIAL_PRESERVED"
    UNKNOWN_PRESERVED = "UNKNOWN_PRESERVED"

    # Recovery / Anomaly Classifications
    PARTIAL_STATE_ONLY = "PARTIAL_STATE_ONLY"
    PARTIAL_REF_ONLY = "PARTIAL_REF_ONLY"
    PARTIAL_WORKTREE = "PARTIAL_WORKTREE"
    OWNERSHIP_MISMATCH = "OWNERSHIP_MISMATCH"
    GIT_METADATA_MISMATCH = "GIT_METADATA_MISMATCH"
    MISSING = "MISSING"


class StatusCategory(str, enum.Enum):
    """Complete semantic categories derived from one porcelain-v1 XY tuple."""

    TRACKED_MODIFIED = "TRACKED_MODIFIED"
    TRACKED_ADDED = "TRACKED_ADDED"
    TRACKED_DELETED = "TRACKED_DELETED"
    TRACKED_TYPE_CHANGED = "TRACKED_TYPE_CHANGED"
    RENAMED = "RENAMED"
    COPIED = "COPIED"
    UNMERGED = "UNMERGED"
    UNTRACKED = "UNTRACKED"
    FILESYSTEM_ANOMALY = "FILESYSTEM_ANOMALY"


class WorkspaceCaptureFailureKind(str, enum.Enum):
    """Typed controller policy inputs for fail-closed workspace capture."""

    GIT_STATUS_FAILURE = "GIT_STATUS_FAILURE"
    MALFORMED_STATUS_STREAM = "MALFORMED_STATUS_STREAM"
    GIT_INDEX_FAILURE = "GIT_INDEX_FAILURE"
    MALFORMED_INDEX_STREAM = "MALFORMED_INDEX_STREAM"
    INVALID_STATUS_PATH = "INVALID_STATUS_PATH"
    GIT_DIFF_FAILURE = "GIT_DIFF_FAILURE"
    REPOSITORY_IDENTITY_MISMATCH = "REPOSITORY_IDENTITY_MISMATCH"
    REF_IDENTITY_MISMATCH = "REF_IDENTITY_MISMATCH"
    FILESYSTEM_IDENTITY_MISMATCH = "FILESYSTEM_IDENTITY_MISMATCH"
    UNREADABLE_UNTRACKED_ENTRY = "UNREADABLE_UNTRACKED_ENTRY"
    UNHASHABLE_UNTRACKED_ENTRY = "UNHASHABLE_UNTRACKED_ENTRY"
    FORBIDDEN_SYMLINK = "FORBIDDEN_SYMLINK"
    FORBIDDEN_NON_REGULAR_ENTRY = "FORBIDDEN_NON_REGULAR_ENTRY"
    FORBIDDEN_GITLINK = "FORBIDDEN_GITLINK"
    UNMERGED_STATUS = "UNMERGED_STATUS"
    EVIDENCE_BOUND_EXCEEDED = "EVIDENCE_BOUND_EXCEEDED"
    INTERNAL_CANONICALIZATION_INCONSISTENCY = "INTERNAL_CANONICALIZATION_INCONSISTENCY"


class WorkspaceCaptureCompleteness(str, enum.Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"


class WorkspaceReuseDecision(str, enum.Enum):
    REUSABLE = "REUSABLE"
    NOT_REUSABLE = "NOT_REUSABLE"
    CAPTURE_FAILED = "CAPTURE_FAILED"


class WorkspaceCaptureError(WorktreeValidationError):
    """Hard capture failure carrying a narrow typed controller reason."""

    def __init__(self, kind: WorkspaceCaptureFailureKind, diagnostic: str = "") -> None:
        self.kind = kind
        self.diagnostic = diagnostic[:16_384]
        super().__init__(
            f"{kind.value}: {self.diagnostic}" if self.diagnostic else kind.value
        )


@dataclass(frozen=True)
class WorkspaceCaptureFailure:
    kind: WorkspaceCaptureFailureKind
    diagnostic: str

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind.value, "diagnostic": self.diagnostic}


@dataclass(frozen=True)
class StatusManifestEntry:
    """One complete, deterministic Git status record and its earned evidence."""

    code: str
    categories: tuple[StatusCategory, ...]
    path: str
    second_path: Optional[str] = None
    anomaly: Optional[WorkspaceCaptureFailureKind] = None
    untracked_file_type: Optional[str] = None
    untracked_byte_count: Optional[int] = None
    untracked_sha256: Optional[str] = None
    untracked_device: Optional[int] = None
    untracked_inode: Optional[int] = None
    untracked_mode: Optional[int] = None
    untracked_mtime_ns: Optional[int] = None
    untracked_ctime_ns: Optional[int] = None

    def to_manifest_dict(self) -> dict[str, Any]:
        return {
            "anomaly": self.anomaly.value if self.anomaly else None,
            "categories": [category.value for category in self.categories],
            "code": self.code,
            "path": self.path,
            "second_path": self.second_path,
            "untracked_byte_count": self.untracked_byte_count,
            "untracked_ctime_ns": self.untracked_ctime_ns,
            "untracked_device": self.untracked_device,
            "untracked_file_type": self.untracked_file_type,
            "untracked_inode": self.untracked_inode,
            "untracked_mode": self.untracked_mode,
            "untracked_mtime_ns": self.untracked_mtime_ns,
            "untracked_sha256": self.untracked_sha256,
        }


@dataclass(frozen=True)
class WorkspaceStatusCounts:
    """Complete counts derived from the same entries as the manifest digest."""

    tracked_modified: int
    tracked_added: int
    tracked_deleted: int
    tracked_type_changed: int
    renamed: int
    copied: int
    unmerged: int
    untracked: int
    filesystem_anomalies: int
    anomalies: int
    total_entries: int

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True)
class WorkspaceCheckpoint:
    """Complete authoritative workspace state identity for later orchestration."""

    schema_version: str
    repository_id: str
    ownership_digest: str
    reservation_digest: str
    task_id: str
    generation: int
    task_ref: str
    baseline_commit_sha: str
    current_head_sha: str
    worktree_device: int
    worktree_inode: int
    status_counts: WorkspaceStatusCounts
    status_manifest_sha256: str
    status_entry_count: int
    diff_byte_count: int
    diff_sha256: str
    anomalies: tuple[WorkspaceCaptureFailureKind, ...]
    capture_completeness: WorkspaceCaptureCompleteness
    authoritative_status_truncated: bool
    authoritative_diff_truncated: bool
    checkpoint_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "anomalies": [anomaly.value for anomaly in self.anomalies],
            "authoritative_diff_truncated": self.authoritative_diff_truncated,
            "authoritative_status_truncated": self.authoritative_status_truncated,
            "baseline_commit_sha": self.baseline_commit_sha,
            "capture_completeness": self.capture_completeness.value,
            "checkpoint_digest": self.checkpoint_digest,
            "current_head_sha": self.current_head_sha,
            "diff_byte_count": self.diff_byte_count,
            "diff_sha256": self.diff_sha256,
            "generation": self.generation,
            "ownership_digest": self.ownership_digest,
            "repository_id": self.repository_id,
            "reservation_digest": self.reservation_digest,
            "schema_version": self.schema_version,
            "status_counts": self.status_counts.to_dict(),
            "status_entry_count": self.status_entry_count,
            "status_manifest_sha256": self.status_manifest_sha256,
            "task_id": self.task_id,
            "task_ref": self.task_ref,
            "worktree_device": self.worktree_device,
            "worktree_inode": self.worktree_inode,
        }


@dataclass(frozen=True)
class WorkspaceCheckpointCaptureResult:
    """Explicit controller decision; callers never infer reuse from fields."""

    decision: WorkspaceReuseDecision
    checkpoint: Optional[WorkspaceCheckpoint]
    failure: Optional[WorkspaceCaptureFailure]
    status_entries: tuple[StatusManifestEntry, ...]
    modified_paths: tuple[str, ...]
    tracked_added_paths: tuple[str, ...]
    added_untracked_paths: tuple[str, ...]
    deleted_paths: tuple[str, ...]
    renamed_paths: tuple[tuple[str, str], ...]
    copied_paths: tuple[tuple[str, str], ...]
    unmerged_paths: tuple[str, ...]
    path_list_truncated: bool
    omitted_path_count: int
    untracked_evidence_content: str
    is_untracked_evidence_truncated: bool
    diff_content: str
    is_diff_truncated: bool
    observed_at: str

    @classmethod
    def capture_failed(
        cls, error: WorkspaceCaptureError, *, observed_at: str
    ) -> WorkspaceCheckpointCaptureResult:
        return cls(
            decision=WorkspaceReuseDecision.CAPTURE_FAILED,
            checkpoint=None,
            failure=WorkspaceCaptureFailure(error.kind, error.diagnostic),
            status_entries=(),
            modified_paths=(),
            tracked_added_paths=(),
            added_untracked_paths=(),
            deleted_paths=(),
            renamed_paths=(),
            copied_paths=(),
            unmerged_paths=(),
            path_list_truncated=False,
            omitted_path_count=0,
            untracked_evidence_content="",
            is_untracked_evidence_truncated=False,
            diff_content="",
            is_diff_truncated=False,
            observed_at=observed_at,
        )


MAX_STATUS_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_STATUS_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_STATUS_ENTRIES = 100_000
MAX_STATUS_PATH_BYTES = 4096
MAX_GIT_DIAGNOSTIC_BYTES = 16_384
MAX_COMPLETE_DIFF_BYTES = 1 << 30
MAX_UNTRACKED_INLINE_TOTAL_BYTES = 1_000_000
MAX_UNTRACKED_FILE_EVIDENCE_BYTES = 64_000
MAX_UNTRACKED_HASH_BYTES = 1 << 30
MAX_AGGREGATE_UNTRACKED_BYTES = 1 << 30
MAX_FILESYSTEM_PATH_BYTES = 64 * 1024 * 1024


@dataclass
class _CaptureBudget:
    deadline: float
    max_aggregate_untracked_bytes: int
    max_filesystem_path_bytes: int
    aggregate_untracked_bytes: int = 0
    filesystem_path_bytes: int = 0

    def remaining_timeout(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED,
                "workspace capture deadline exceeded",
            )
        return remaining

    def account_path(self, path: str) -> None:
        self.filesystem_path_bytes += len(path.encode("utf-8", errors="strict"))
        if self.filesystem_path_bytes > self.max_filesystem_path_bytes:
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED,
                "cumulative filesystem path bytes exceed the capture bound",
            )
        self.remaining_timeout()

    def reserve_untracked_bytes(self, byte_count: int) -> bool:
        if byte_count < 0:
            return False
        if self.aggregate_untracked_bytes + byte_count > self.max_aggregate_untracked_bytes:
            return False
        self.aggregate_untracked_bytes += byte_count
        return True


def _status_categories(code: str) -> tuple[StatusCategory, ...]:
    if code == "??":
        return (StatusCategory.UNTRACKED,)
    if code == "!!":
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.MALFORMED_STATUS_STREAM,
            "ignored status record was not requested by controller policy",
        )
    if code in {"DD", "AU", "UD", "UA", "DU", "AA", "UU"}:
        return (StatusCategory.UNMERGED,)

    categories: set[StatusCategory] = set()
    for marker in code:
        if marker == " ":
            continue
        category = {
            "M": StatusCategory.TRACKED_MODIFIED,
            "A": StatusCategory.TRACKED_ADDED,
            "D": StatusCategory.TRACKED_DELETED,
            "T": StatusCategory.TRACKED_TYPE_CHANGED,
            "R": StatusCategory.RENAMED,
            "C": StatusCategory.COPIED,
        }.get(marker)
        if category is None:
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.MALFORMED_STATUS_STREAM,
                f"unsupported porcelain status code {code!r}",
            )
        categories.add(category)
    if not categories:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.MALFORMED_STATUS_STREAM,
            f"empty porcelain status code {code!r}",
        )
    return tuple(sorted(categories, key=lambda value: value.value))


def _decode_status_path(raw: bytes, *, max_path_bytes: int) -> str:
    if not raw or len(raw) > max_path_bytes:
        kind = (
            WorkspaceCaptureFailureKind.INVALID_STATUS_PATH
            if not raw
            else WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED
        )
        raise WorkspaceCaptureError(kind, "status path is empty or exceeds the byte bound")
    try:
        path = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.INVALID_STATUS_PATH,
            "status path is not strict UTF-8",
        ) from exc
    parts = path.split("/")
    if path.startswith("/") or any(part in {"", ".", ".."} for part in parts):
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.INVALID_STATUS_PATH,
            "status path is not a normalized repository-relative path",
        )
    return path


def _parse_status_stream(
    raw: bytes,
    *,
    max_entries: int,
    max_path_bytes: int,
) -> tuple[StatusManifestEntry, ...]:
    """Strictly parse complete `porcelain=v1 -z` bytes without path quoting."""
    if type(raw) is not bytes:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.MALFORMED_STATUS_STREAM,
            "status output must be bytes",
        )
    if not raw:
        return ()
    if not raw.endswith(b"\0"):
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.MALFORMED_STATUS_STREAM,
            "status output lacks the final NUL delimiter",
        )

    fields = raw[:-1].split(b"\0")
    entries: list[StatusManifestEntry] = []
    observed_primary_paths: set[str] = set()
    observed_tuples: set[tuple[str, str, Optional[str]]] = set()
    index = 0
    while index < len(fields):
        field = fields[index]
        if len(field) < 4 or field[2:3] != b" ":
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.MALFORMED_STATUS_STREAM,
                "status record lacks an exact two-byte XY code and separator",
            )
        try:
            code = field[:2].decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.MALFORMED_STATUS_STREAM,
                "status code is not ASCII",
            ) from exc
        categories = _status_categories(code)
        path = _decode_status_path(field[3:], max_path_bytes=max_path_bytes)
        second_path: Optional[str] = None
        if StatusCategory.RENAMED in categories or StatusCategory.COPIED in categories:
            index += 1
            if index >= len(fields):
                raise WorkspaceCaptureError(
                    WorkspaceCaptureFailureKind.MALFORMED_STATUS_STREAM,
                    "rename/copy record lacks its source path",
                )
            second_path = _decode_status_path(fields[index], max_path_bytes=max_path_bytes)

        status_tuple = (code, path, second_path)
        if (
            path in observed_primary_paths
            or status_tuple in observed_tuples
            or (second_path is not None and second_path == path)
        ):
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.MALFORMED_STATUS_STREAM,
                "duplicate status tuple, duplicate primary path, or self-referential rename/copy",
            )
        observed_primary_paths.add(path)
        observed_tuples.add(status_tuple)
        entries.append(
            StatusManifestEntry(
                code=code,
                categories=categories,
                path=path,
                second_path=second_path,
                anomaly=(
                    WorkspaceCaptureFailureKind.UNMERGED_STATUS
                    if StatusCategory.UNMERGED in categories
                    else None
                ),
            )
        )
        if len(entries) > max_entries:
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED,
                "status entry count exceeds the complete-capture bound",
            )
        index += 1

    return tuple(sorted(entries, key=lambda entry: (entry.path, entry.second_path or "", entry.code)))


def _count_status_categories(entries: tuple[StatusManifestEntry, ...]) -> WorkspaceStatusCounts:
    def count(category: StatusCategory) -> int:
        return sum(category in entry.categories for entry in entries)

    return WorkspaceStatusCounts(
        tracked_modified=count(StatusCategory.TRACKED_MODIFIED),
        tracked_added=count(StatusCategory.TRACKED_ADDED),
        tracked_deleted=count(StatusCategory.TRACKED_DELETED),
        tracked_type_changed=count(StatusCategory.TRACKED_TYPE_CHANGED),
        renamed=count(StatusCategory.RENAMED),
        copied=count(StatusCategory.COPIED),
        unmerged=count(StatusCategory.UNMERGED),
        untracked=count(StatusCategory.UNTRACKED),
        filesystem_anomalies=count(StatusCategory.FILESYSTEM_ANOMALY),
        anomalies=sum(entry.anomaly is not None for entry in entries),
        total_entries=len(entries),
    )


def _canonical_status_manifest(entries: tuple[StatusManifestEntry, ...]) -> str:
    ordered_entries = sorted(entries, key=lambda entry: (entry.path, entry.second_path or "", entry.code))
    payload = {
        "entries": [entry.to_manifest_dict() for entry in ordered_entries],
        "schema_version": "AOSSTATUSMANIFEST/1",
    }
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.INTERNAL_CANONICALIZATION_INCONSISTENCY,
            "status manifest canonical encoding failed",
        ) from exc
    if len(encoded) > MAX_STATUS_MANIFEST_BYTES:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED,
            "status manifest exceeds the canonical byte bound",
        )
    return hashlib.sha256(encoded).hexdigest()


_DESCRIPTOR_RELATIVE_PATHS_SUPPORTED = (
    os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.readlink in os.supports_dir_fd
    and hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
)


def _supports_descriptor_relative_paths() -> bool:
    return _DESCRIPTOR_RELATIVE_PATHS_SUPPORTED


@contextlib.contextmanager
def _open_verified_parent_directory(
    worktree_dir: Path, relative_path: str
) -> Any:
    """Keep every parent directory open and no-follow while inspecting a leaf."""
    full_path = worktree_dir.joinpath(*relative_path.split("/"))
    if not _supports_descriptor_relative_paths():
        yield None, full_path.name, full_path
        return

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    current_fd = os.open(worktree_dir, flags)
    try:
        parts = relative_path.split("/")
        for component in parts[:-1]:
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        yield current_fd, parts[-1], full_path
    finally:
        os.close(current_fd)


def _lstat_at(parent_fd: Optional[int], leaf: str, full_path: Path) -> os.stat_result:
    if parent_fd is None:
        return full_path.lstat()
    return os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)


def _untracked_stable_fields() -> tuple[str, ...]:
    fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")
    # Windows path-stat and descriptor-stat expose incompatible ctime semantics.
    return fields if os.name == "nt" else (*fields, "st_ctime_ns")


def _portable_untracked_ctime_ns(observed: os.stat_result) -> Optional[int]:
    return None if os.name == "nt" else int(observed.st_ctime_ns)


def _scan_unobserved_special_entries(
    worktree_dir: Path,
    entries: tuple[StatusManifestEntry, ...],
    *,
    tracked_paths: frozenset[str],
    gitlink_paths: frozenset[str],
    budget: _CaptureBudget,
    max_entries: int,
    max_path_bytes: int,
) -> tuple[StatusManifestEntry, ...]:
    """Detect unreported special entries without following attacker-replaced directories."""
    observed_paths = {
        path
        for entry in entries
        for path in (entry.path, entry.second_path)
        if path is not None
    }
    anomalies: list[StatusManifestEntry] = []
    visited = 0

    def account_entry(rel_path: str) -> str:
        nonlocal visited
        visited += 1
        if visited > max_entries:
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED,
                "filesystem entry count exceeds the checkpoint audit bound",
            )
        try:
            normalized = _decode_status_path(
                rel_path.encode("utf-8", errors="strict"),
                max_path_bytes=max_path_bytes,
            )
        except UnicodeEncodeError as exc:
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.INVALID_STATUS_PATH,
                "filesystem path is not strict UTF-8",
            ) from exc
        budget.account_path(normalized)
        return normalized

    def record_unreadable(rel_path: str, file_type: str = "UNKNOWN") -> None:
        if rel_path not in observed_paths:
            anomalies.append(
                StatusManifestEntry(
                    code="FS",
                    categories=(StatusCategory.FILESYSTEM_ANOMALY,),
                    path=rel_path,
                    anomaly=WorkspaceCaptureFailureKind.UNREADABLE_UNTRACKED_ENTRY,
                    untracked_file_type=file_type,
                )
            )

    def inspect_child(
        *,
        rel_path: str,
        child_stat: os.stat_result,
        readlink: Any,
        descend: Any,
    ) -> None:
        if rel_path == ".git":
            return
        if stat.S_ISDIR(child_stat.st_mode):
            if rel_path not in gitlink_paths:
                descend()
            return
        if rel_path in observed_paths or stat.S_ISREG(child_stat.st_mode):
            return
        if rel_path in tracked_paths:
            return
        if stat.S_ISLNK(child_stat.st_mode):
            anomaly = WorkspaceCaptureFailureKind.FORBIDDEN_SYMLINK
            file_type = "SYMLINK"
            try:
                target_bytes = os.fsencode(readlink())
                target_size = len(target_bytes)
                target_digest = hashlib.sha256(target_bytes).hexdigest()
            except OSError:
                target_size = None
                target_digest = None
        else:
            anomaly = WorkspaceCaptureFailureKind.FORBIDDEN_NON_REGULAR_ENTRY
            file_type = f"NON_REGULAR:{stat.S_IFMT(child_stat.st_mode):o}"
            target_size = None
            target_digest = None
        anomalies.append(
            StatusManifestEntry(
                code="FS",
                categories=(StatusCategory.FILESYSTEM_ANOMALY,),
                path=rel_path,
                anomaly=anomaly,
                untracked_file_type=file_type,
                untracked_byte_count=target_size,
                untracked_sha256=target_digest,
            )
        )

    def walk_descriptor(directory_fd: int, rel_prefix: str, depth: int) -> None:
        if depth > 128:
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED,
                "filesystem traversal depth exceeds the capture bound",
            )
        try:
            with os.scandir(directory_fd) as children:
                for child in children:
                    rel_path = f"{rel_prefix}/{child.name}" if rel_prefix else child.name
                    normalized = account_entry(rel_path)
                    try:
                        child_stat = os.stat(
                            child.name,
                            dir_fd=directory_fd,
                            follow_symlinks=False,
                        )
                    except OSError:
                        record_unreadable(normalized)
                        continue

                    def descend() -> None:
                        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
                        try:
                            child_fd = os.open(child.name, flags, dir_fd=directory_fd)
                        except OSError:
                            record_unreadable(normalized, "DIRECTORY")
                            return
                        try:
                            opened = os.fstat(child_fd)
                            if (
                                int(opened.st_dev) != int(child_stat.st_dev)
                                or int(opened.st_ino) != int(child_stat.st_ino)
                            ):
                                record_unreadable(normalized, "DIRECTORY")
                                return
                            walk_descriptor(child_fd, normalized, depth + 1)
                        finally:
                            os.close(child_fd)

                    inspect_child(
                        rel_path=normalized,
                        child_stat=child_stat,
                        readlink=lambda: os.readlink(child.name, dir_fd=directory_fd),
                        descend=descend,
                    )
        except WorkspaceCaptureError:
            raise
        except OSError as exc:
            if not rel_prefix:
                raise WorkspaceCaptureError(
                    WorkspaceCaptureFailureKind.UNREADABLE_UNTRACKED_ENTRY,
                    f"worktree directory scan failed: {type(exc).__name__}",
                ) from exc
            record_unreadable(rel_prefix, "DIRECTORY")

    def walk_paths(directory: Path, rel_prefix: str, depth: int) -> None:
        if depth > 128:
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED,
                "filesystem traversal depth exceeds the capture bound",
            )
        try:
            with os.scandir(directory) as children:
                for child in children:
                    full_path = Path(child.path)
                    rel_path = f"{rel_prefix}/{child.name}" if rel_prefix else child.name
                    normalized = account_entry(rel_path)
                    try:
                        child_stat = child.stat(follow_symlinks=False)
                    except OSError:
                        record_unreadable(normalized)
                        continue
                    inspect_child(
                        rel_path=normalized,
                        child_stat=child_stat,
                        readlink=lambda path=full_path: os.readlink(path),
                        descend=lambda path=full_path, prefix=normalized: walk_paths(
                            path, prefix, depth + 1
                        )
                    )
        except WorkspaceCaptureError:
            raise
        except OSError as exc:
            if not rel_prefix:
                raise WorkspaceCaptureError(
                    WorkspaceCaptureFailureKind.UNREADABLE_UNTRACKED_ENTRY,
                    f"worktree directory scan failed: {type(exc).__name__}",
                ) from exc
            record_unreadable(rel_prefix, "DIRECTORY")

    if _supports_descriptor_relative_paths():
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            root_fd = os.open(worktree_dir, flags)
        except OSError as exc:
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.UNREADABLE_UNTRACKED_ENTRY,
                f"worktree directory open failed: {type(exc).__name__}",
            ) from exc
        try:
            walk_descriptor(root_fd, "", 0)
        finally:
            os.close(root_fd)
    else:
        walk_paths(worktree_dir, "", 0)
    if len(entries) + len(anomalies) > max_entries:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED,
            "status plus filesystem anomaly entries exceed the manifest bound",
        )
    return tuple(sorted((*entries, *anomalies), key=lambda entry: (entry.path, entry.second_path or "", entry.code)))


def _sanitize_git_env() -> dict[str, str]:
    """Build a deterministic controller-side environment for Git plumbing commands."""
    kept: dict[str, str] = {
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "SSH_ASKPASS": "",
        "GIT_SSH": "",
        "GIT_SSH_COMMAND": "",
        "HOME": "/nonexistent",
        "XDG_CONFIG_HOME": "/nonexistent",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    return kept


def _run_git_plumbing(
    argv: list[str],
    cwd: Path,
    timeout: float = 10.0,
) -> subprocess.CompletedProcess[str]:
    """Execute a Git plumbing command safely without shell interpretation."""
    if not argv or argv[0] != "git":
        raise ValueError("plumbing command must start with 'git'")
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=_sanitize_git_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WorktreeValidationError(
            f"git plumbing execution failed for {argv[1] if len(argv) > 1 else argv[0]!r}: {type(exc).__name__}"
        ) from exc


@dataclass(frozen=True)
class _GitStreamResult:
    total_bytes: int
    sha256: str
    inline_bytes: bytes


def _run_git_stream_bounded(
    argv: list[str],
    *,
    cwd: Path,
    timeout: float,
    max_complete_bytes: int,
    max_inline_bytes: int,
    failure_kind: WorkspaceCaptureFailureKind,
) -> _GitStreamResult:
    """Drain stdout/stderr concurrently while retaining only explicit bounds."""
    if not argv or argv[0] != "git":
        raise ValueError("streaming Git command must start with 'git'")
    if (
        type(max_complete_bytes) is not int
        or max_complete_bytes < 0
        or type(max_inline_bytes) is not int
        or max_inline_bytes < 0
        or timeout <= 0
    ):
        raise ValueError("Git stream bounds must be non-negative integers and timeout must be positive")
    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_sanitize_git_env(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise WorkspaceCaptureError(
            failure_kind, f"Git command execution failed: {type(exc).__name__}"
        ) from exc

    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    hasher = hashlib.sha256()
    stream_state: dict[str, Any] = {
        "total": 0,
        "bound_exceeded": False,
        "read_error": None,
    }

    def read_stdout() -> None:
        try:
            assert proc.stdout is not None
            while True:
                chunk = proc.stdout.read(65_536)
                if not chunk:
                    break
                hasher.update(chunk)
                stream_state["total"] += len(chunk)
                if len(stdout_buffer) < max_inline_bytes:
                    remaining = max_inline_bytes - len(stdout_buffer)
                    stdout_buffer.extend(chunk[:remaining])
                if stream_state["total"] > max_complete_bytes:
                    stream_state["bound_exceeded"] = True
                    with contextlib.suppress(OSError):
                        proc.kill()
        except BaseException as exc:  # transferred to the controller thread
            stream_state["read_error"] = exc

    def read_stderr() -> None:
        try:
            assert proc.stderr is not None
            while True:
                chunk = proc.stderr.read(4096)
                if not chunk:
                    break
                if len(stderr_buffer) < MAX_GIT_DIAGNOSTIC_BYTES:
                    remaining = MAX_GIT_DIAGNOSTIC_BYTES - len(stderr_buffer)
                    stderr_buffer.extend(chunk[:remaining])
        except BaseException as exc:  # transferred to the controller thread
            stream_state["read_error"] = stream_state["read_error"] or exc

    stdout_thread = threading.Thread(target=read_stdout, daemon=True)
    stderr_thread = threading.Thread(target=read_stderr, daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        with contextlib.suppress(OSError):
            proc.kill()
        proc.wait()
    stdout_thread.join(timeout=1.0)
    stderr_thread.join(timeout=1.0)
    if stdout_thread.is_alive() or stderr_thread.is_alive():
        with contextlib.suppress(OSError):
            proc.kill()
        raise WorkspaceCaptureError(failure_kind, "Git output drain did not terminate")
    if stream_state["read_error"] is not None:
        raise WorkspaceCaptureError(
            failure_kind,
            f"Git output read failed: {type(stream_state['read_error']).__name__}",
        )
    if stream_state["bound_exceeded"]:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED,
            f"Git {argv[1]} output exceeded {max_complete_bytes} bytes",
        )
    diagnostic = stderr_buffer.decode("utf-8", errors="replace")
    if timed_out:
        raise WorkspaceCaptureError(failure_kind, f"Git {argv[1]} timed out: {diagnostic}")
    if proc.returncode != 0:
        raise WorkspaceCaptureError(
            failure_kind,
            f"Git {argv[1]} exited {proc.returncode}: {diagnostic}",
        )
    return _GitStreamResult(
        total_bytes=int(stream_state["total"]),
        sha256=hasher.hexdigest(),
        inline_bytes=bytes(stdout_buffer),
    )


def _run_git_status_bounded(
    cwd: Path,
    *,
    max_status_bytes: int = MAX_STATUS_OUTPUT_BYTES,
    timeout: float = 10.0,
) -> bytes:
    result = _run_git_stream_bounded(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=cwd,
        timeout=timeout,
        max_complete_bytes=max_status_bytes,
        max_inline_bytes=max_status_bytes,
        failure_kind=WorkspaceCaptureFailureKind.GIT_STATUS_FAILURE,
    )
    if result.total_bytes != len(result.inline_bytes):
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.INTERNAL_CANONICALIZATION_INCONSISTENCY,
            "complete status bytes were not retained",
        )
    return result.inline_bytes


@dataclass(frozen=True)
class _IndexManifest:
    tracked_paths: frozenset[str]
    gitlink_paths: frozenset[str]


def _run_git_index_manifest_bounded(
    cwd: Path,
    *,
    object_format: str,
    max_index_bytes: int,
    max_entries: int,
    max_path_bytes: int,
    timeout: float,
) -> _IndexManifest:
    result = _run_git_stream_bounded(
        ["git", "ls-files", "--stage", "-z"],
        cwd=cwd,
        timeout=timeout,
        max_complete_bytes=max_index_bytes,
        max_inline_bytes=max_index_bytes,
        failure_kind=WorkspaceCaptureFailureKind.GIT_INDEX_FAILURE,
    )
    if result.total_bytes != len(result.inline_bytes):
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.INTERNAL_CANONICALIZATION_INCONSISTENCY,
            "complete index bytes were not retained",
        )
    raw = result.inline_bytes
    if raw and not raw.endswith(b"\0"):
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.MALFORMED_INDEX_STREAM,
            "index output lacks the final NUL delimiter",
        )
    tracked_paths: set[str] = set()
    gitlink_paths: set[str] = set()
    records = raw[:-1].split(b"\0") if raw else []
    if len(records) > max_entries:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED,
            "tracked index entry count exceeds the capture bound",
        )
    oid_pattern = _LOWER_HEX_40_RE if object_format == "sha1" else _LOWER_HEX_64_RE
    for record in records:
        try:
            metadata, raw_path = record.split(b"\t", 1)
            raw_mode, raw_oid, raw_stage = metadata.split(b" ")
            mode = raw_mode.decode("ascii", errors="strict")
            oid = raw_oid.decode("ascii", errors="strict")
            stage = int(raw_stage.decode("ascii", errors="strict"), 10)
        except (ValueError, UnicodeDecodeError) as exc:
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.MALFORMED_INDEX_STREAM,
                "index record is malformed",
            ) from exc
        if mode not in {"100644", "100755", "120000", "160000"} or not oid_pattern.fullmatch(oid) or stage not in {0, 1, 2, 3}:
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.MALFORMED_INDEX_STREAM,
                "index record contains an invalid mode, object ID, or stage",
            )
        path = _decode_status_path(raw_path, max_path_bytes=max_path_bytes)
        tracked_paths.add(path)
        if mode == "160000":
            gitlink_paths.add(path)
    return _IndexManifest(
        tracked_paths=frozenset(tracked_paths),
        gitlink_paths=frozenset(gitlink_paths),
    )


def _untracked_evidence_marker(path: str, message: str) -> bytes:
    return (
        f"--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,1 @@\n+ [{message}]\n"
    ).encode("utf-8", errors="replace")


def _capture_untracked_entry(
    worktree_dir: Path,
    entry: StatusManifestEntry,
    *,
    max_inline_file_bytes: int,
    budget: _CaptureBudget,
) -> tuple[StatusManifestEntry, bytes]:
    try:
        with _open_verified_parent_directory(worktree_dir, entry.path) as (
            parent_fd,
            leaf,
            full_path,
        ):
            return _capture_untracked_entry_at(
                parent_fd,
                leaf,
                full_path,
                entry,
                max_inline_file_bytes=max_inline_file_bytes,
                budget=budget,
            )
    except OSError as exc:
        anomaly = WorkspaceCaptureFailureKind.UNREADABLE_UNTRACKED_ENTRY
        return (
            replace(entry, anomaly=anomaly, untracked_file_type="UNKNOWN"),
            _untracked_evidence_marker(entry.path, f"UNREADABLE: {type(exc).__name__}"),
        )


def _capture_untracked_entry_at(
    parent_fd: Optional[int],
    leaf: str,
    full_path: Path,
    entry: StatusManifestEntry,
    *,
    max_inline_file_bytes: int,
    budget: _CaptureBudget,
) -> tuple[StatusManifestEntry, bytes]:
    try:
        initial = _lstat_at(parent_fd, leaf, full_path)
    except OSError as exc:
        anomaly = WorkspaceCaptureFailureKind.UNREADABLE_UNTRACKED_ENTRY
        return (
            replace(entry, anomaly=anomaly, untracked_file_type="UNKNOWN"),
            _untracked_evidence_marker(entry.path, f"UNREADABLE: {type(exc).__name__}"),
        )

    if stat.S_ISLNK(initial.st_mode):
        try:
            target = (
                os.readlink(full_path)
                if parent_fd is None
                else os.readlink(leaf, dir_fd=parent_fd)
            )
            target_bytes = os.fsencode(target)
            target_digest = hashlib.sha256(target_bytes).hexdigest()
            target_size = len(target_bytes)
        except OSError:
            target_digest = None
            target_size = None
        anomaly = WorkspaceCaptureFailureKind.FORBIDDEN_SYMLINK
        return (
            replace(
                entry,
                anomaly=anomaly,
                untracked_file_type="SYMLINK",
                untracked_byte_count=target_size,
                untracked_sha256=target_digest,
                untracked_device=int(initial.st_dev),
                untracked_inode=int(initial.st_ino),
                untracked_mode=int(initial.st_mode),
                untracked_mtime_ns=int(initial.st_mtime_ns),
                untracked_ctime_ns=_portable_untracked_ctime_ns(initial),
            ),
            _untracked_evidence_marker(entry.path, "FORBIDDEN SYMLINK"),
        )

    if not stat.S_ISREG(initial.st_mode):
        anomaly = WorkspaceCaptureFailureKind.FORBIDDEN_NON_REGULAR_ENTRY
        file_type = f"NON_REGULAR:{stat.S_IFMT(initial.st_mode):o}"
        return (
            replace(
                entry,
                anomaly=anomaly,
                untracked_file_type=file_type,
                untracked_device=int(initial.st_dev),
                untracked_inode=int(initial.st_ino),
                untracked_mode=int(initial.st_mode),
                untracked_mtime_ns=int(initial.st_mtime_ns),
                untracked_ctime_ns=_portable_untracked_ctime_ns(initial),
            ),
            _untracked_evidence_marker(entry.path, file_type),
        )

    if int(initial.st_size) > MAX_UNTRACKED_HASH_BYTES:
        anomaly = WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED
        return (
            replace(
                entry,
                anomaly=anomaly,
                untracked_file_type="REGULAR",
                untracked_byte_count=int(initial.st_size),
                untracked_device=int(initial.st_dev),
                untracked_inode=int(initial.st_ino),
                untracked_mode=int(initial.st_mode),
                untracked_mtime_ns=int(initial.st_mtime_ns),
                untracked_ctime_ns=_portable_untracked_ctime_ns(initial),
            ),
            _untracked_evidence_marker(
                entry.path,
                f"UNTRACKED HASH BOUND EXCEEDED: {int(initial.st_size)} BYTES",
            ),
        )

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = (
            os.open(full_path, flags)
            if parent_fd is None
            else os.open(leaf, flags, dir_fd=parent_fd)
        )
    except OSError as exc:
        anomaly = WorkspaceCaptureFailureKind.UNREADABLE_UNTRACKED_ENTRY
        return (
            replace(
                entry,
                anomaly=anomaly,
                untracked_file_type="REGULAR",
                untracked_byte_count=int(initial.st_size),
                untracked_device=int(initial.st_dev),
                untracked_inode=int(initial.st_ino),
                untracked_mode=int(initial.st_mode),
                untracked_mtime_ns=int(initial.st_mtime_ns),
                untracked_ctime_ns=_portable_untracked_ctime_ns(initial),
            ),
            _untracked_evidence_marker(entry.path, f"UNREADABLE: {type(exc).__name__}"),
        )

    hasher = hashlib.sha256()
    inline_prefix = bytearray()
    total = 0
    try:
        opened = os.fstat(fd)
        stable_fields = _untracked_stable_fields()
        if not stat.S_ISREG(opened.st_mode) or any(
            getattr(initial, name) != getattr(opened, name) for name in stable_fields
        ):
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.UNHASHABLE_UNTRACKED_ENTRY,
                "untracked entry identity changed before hashing",
            )
        reserved_size = int(opened.st_size)
        if reserved_size > MAX_UNTRACKED_HASH_BYTES:
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED,
                "untracked descriptor exceeds the per-file hash bound",
            )
        if not budget.reserve_untracked_bytes(reserved_size):
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED,
                "aggregate untracked hash bound exceeded",
            )
        while True:
            budget.remaining_timeout()
            remaining_reserved = reserved_size - total
            chunk = os.read(fd, min(65_536, remaining_reserved + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > reserved_size:
                raise WorkspaceCaptureError(
                    WorkspaceCaptureFailureKind.UNHASHABLE_UNTRACKED_ENTRY,
                    "untracked entry grew beyond its reserved hash budget",
                )
            hasher.update(chunk)
            if len(inline_prefix) <= max_inline_file_bytes:
                remaining = max_inline_file_bytes + 1 - len(inline_prefix)
                inline_prefix.extend(chunk[:remaining])
        final = os.fstat(fd)
        if any(getattr(opened, name) != getattr(final, name) for name in stable_fields):
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.UNHASHABLE_UNTRACKED_ENTRY,
                "untracked entry changed while hashing",
            )
        path_final = _lstat_at(parent_fd, leaf, full_path)
        if any(getattr(final, name) != getattr(path_final, name) for name in stable_fields):
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.UNHASHABLE_UNTRACKED_ENTRY,
                "untracked pathname no longer names the hashed descriptor",
            )
    except WorkspaceCaptureError as exc:
        return (
            replace(
                entry,
                anomaly=exc.kind,
                untracked_file_type="REGULAR",
                untracked_byte_count=int(initial.st_size),
                untracked_device=int(initial.st_dev),
                untracked_inode=int(initial.st_ino),
                untracked_mode=int(initial.st_mode),
                untracked_mtime_ns=int(initial.st_mtime_ns),
                untracked_ctime_ns=_portable_untracked_ctime_ns(initial),
            ),
            _untracked_evidence_marker(entry.path, "UNHASHABLE: IDENTITY CHANGED"),
        )
    except OSError as exc:
        anomaly = WorkspaceCaptureFailureKind.UNHASHABLE_UNTRACKED_ENTRY
        return (
            replace(
                entry,
                anomaly=anomaly,
                untracked_file_type="REGULAR",
                untracked_byte_count=int(initial.st_size),
                untracked_device=int(initial.st_dev),
                untracked_inode=int(initial.st_ino),
                untracked_mode=int(initial.st_mode),
                untracked_mtime_ns=int(initial.st_mtime_ns),
                untracked_ctime_ns=_portable_untracked_ctime_ns(initial),
            ),
            _untracked_evidence_marker(entry.path, f"UNHASHABLE: {type(exc).__name__}"),
        )
    finally:
        os.close(fd)

    digest = hasher.hexdigest()
    captured = replace(
        entry,
        untracked_file_type="REGULAR",
        untracked_byte_count=total,
        untracked_sha256=digest,
        untracked_device=int(final.st_dev),
        untracked_inode=int(final.st_ino),
        untracked_mode=int(final.st_mode),
        untracked_mtime_ns=int(final.st_mtime_ns),
        untracked_ctime_ns=_portable_untracked_ctime_ns(final),
    )
    if total == 0:
        inline = f"--- /dev/null\n+++ b/{entry.path}\n@@ -0,0 +0,0 @@\n".encode("utf-8")
    elif total > max_inline_file_bytes:
        inline = _untracked_evidence_marker(
            entry.path, f"UNTRACKED LARGE FILE: {total} BYTES, SHA256: {digest}"
        )
    elif b"\0" in inline_prefix:
        inline = _untracked_evidence_marker(
            entry.path, f"UNTRACKED BINARY FILE: {total} BYTES, SHA256: {digest}"
        )
    else:
        try:
            text = bytes(inline_prefix).decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            inline = _untracked_evidence_marker(
                entry.path, f"UNTRACKED BINARY FILE: {total} BYTES, SHA256: {digest}"
            )
        else:
            lines = text.splitlines()
            inline = (
                f"--- /dev/null\n+++ b/{entry.path}\n@@ -0,0 +1,{len(lines)} @@\n+"
                + "\n+".join(lines)
                + "\n"
            ).encode("utf-8")
    return captured, inline


def _enrich_untracked_entries(
    worktree_dir: Path,
    entries: tuple[StatusManifestEntry, ...],
    *,
    max_inline_file_bytes: int,
    max_inline_total_bytes: int,
    budget: _CaptureBudget,
) -> tuple[tuple[StatusManifestEntry, ...], str, bool]:
    enriched: list[StatusManifestEntry] = []
    inline = bytearray()
    truncated = False
    for entry in entries:
        if StatusCategory.UNTRACKED not in entry.categories:
            enriched.append(entry)
            continue
        captured, evidence = _capture_untracked_entry(
            worktree_dir,
            entry,
            max_inline_file_bytes=max_inline_file_bytes,
            budget=budget,
        )
        enriched.append(captured)
        remaining = max(0, max_inline_total_bytes - len(inline))
        inline.extend(evidence[:remaining])
        if len(evidence) > remaining:
            truncated = True
    return tuple(enriched), inline.decode("utf-8", errors="replace"), truncated


def _revalidate_untracked_entries(
    worktree_dir: Path,
    entries: tuple[StatusManifestEntry, ...],
    *,
    budget: _CaptureBudget,
) -> None:
    for entry in entries:
        if entry.untracked_file_type != "REGULAR" or entry.untracked_sha256 is None:
            continue
        budget.remaining_timeout()
        try:
            with _open_verified_parent_directory(worktree_dir, entry.path) as (
                parent_fd,
                leaf,
                full_path,
            ):
                current = _lstat_at(parent_fd, leaf, full_path)
        except OSError as exc:
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.UNHASHABLE_UNTRACKED_ENTRY,
                f"hashed untracked path became unreadable: {type(exc).__name__}",
            ) from exc
        expected_by_field = {
            "st_dev": entry.untracked_device,
            "st_ino": entry.untracked_inode,
            "st_mode": entry.untracked_mode,
            "st_size": entry.untracked_byte_count,
            "st_mtime_ns": entry.untracked_mtime_ns,
            "st_ctime_ns": entry.untracked_ctime_ns,
        }
        expected = tuple(expected_by_field[name] for name in _untracked_stable_fields())
        observed = tuple(
            int(getattr(current, name)) for name in _untracked_stable_fields()
        )
        if observed != expected or not stat.S_ISREG(current.st_mode):
            raise WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.UNHASHABLE_UNTRACKED_ENTRY,
                "hashed untracked path changed before checkpoint completion",
            )


def _canonical_checkpoint_digest(payload: dict[str, Any]) -> str:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.INTERNAL_CANONICALIZATION_INCONSISTENCY,
            "checkpoint canonical encoding failed",
        ) from exc
    if len(encoded) > 1_000_000:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.INTERNAL_CANONICALIZATION_INCONSISTENCY,
            "checkpoint canonical representation exceeded its fixed bound",
        )
    return hashlib.sha256(encoded).hexdigest()


def _observe_owned_worktree_identity(
    repo: RepositoryIdentity,
    state: WorktreeLifecycleState,
    worktree_dir: Path,
    *,
    budget: _CaptureBudget,
) -> tuple[int, int, str]:
    """Re-observe kernel and Git identity within the shared capture deadline."""
    if not worktree_dir.is_dir() or worktree_dir.is_symlink():
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.FILESYSTEM_IDENTITY_MISMATCH,
            "worktree path is missing, non-directory, or a symlink",
        )
    try:
        current_device, current_inode = _stat_descriptor_identity(worktree_dir)
    except WorktreeValidationError as exc:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.FILESYSTEM_IDENTITY_MISMATCH,
            str(exc),
        ) from exc
    if (
        state.worktree_device is None
        or state.worktree_inode is None
        or current_device != state.worktree_device
        or current_inode != state.worktree_inode
    ):
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.FILESYSTEM_IDENTITY_MISMATCH,
            "worktree device/inode differs from the controller-owned lifecycle evidence",
        )

    try:
        head_result = _run_git_plumbing(
            ["git", "rev-parse", "HEAD"],
            cwd=worktree_dir,
            timeout=budget.remaining_timeout(),
        )
        ref_result = _run_git_plumbing(
            ["git", "rev-parse", state.task_ref],
            cwd=repo.canonical_root,
            timeout=budget.remaining_timeout(),
        )
        symbolic_ref_result = _run_git_plumbing(
            ["git", "symbolic-ref", "-q", "HEAD"],
            cwd=worktree_dir,
            timeout=budget.remaining_timeout(),
        )
    except WorktreeValidationError as exc:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.REF_IDENTITY_MISMATCH,
            str(exc),
        ) from exc
    if head_result.returncode != 0 or ref_result.returncode != 0 or symbolic_ref_result.returncode != 0:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.REF_IDENTITY_MISMATCH,
            "worktree HEAD, symbolic task branch, or task ref could not be resolved",
        )
    current_head_sha = head_result.stdout.strip().lower()
    current_ref_sha = ref_result.stdout.strip().lower()
    sha_pattern = _LOWER_HEX_40_RE if repo.object_format == "sha1" else _LOWER_HEX_64_RE
    if (
        not sha_pattern.fullmatch(current_head_sha)
        or current_ref_sha != current_head_sha
        or symbolic_ref_result.stdout.strip() != state.task_ref
    ):
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.REF_IDENTITY_MISMATCH,
            "worktree HEAD and controller-owned task ref are not the same exact commit",
        )
    return current_device, current_inode, current_head_sha


def _capture_workspace_checkpoint(
    repo: RepositoryIdentity,
    state: WorktreeLifecycleState,
    *,
    task_id: str,
    generation: int,
    timeout: float,
    max_status_bytes: int,
    max_status_entries: int,
    max_status_path_bytes: int,
    max_paths_per_category: int,
    max_diff_bytes: int,
    max_complete_diff_bytes: int,
    max_untracked_inline_bytes: int,
    max_aggregate_untracked_bytes: int,
    max_filesystem_path_bytes: int,
) -> WorkspaceCheckpointCaptureResult:
    if type(max_paths_per_category) is not int or max_paths_per_category < 0:
        raise ValueError("max_paths_per_category must be a non-negative integer")
    if (
        type(max_aggregate_untracked_bytes) is not int
        or max_aggregate_untracked_bytes < 0
        or type(max_filesystem_path_bytes) is not int
        or max_filesystem_path_bytes < 0
    ):
        raise ValueError("aggregate capture bounds must be non-negative integers")
    budget = _CaptureBudget(
        deadline=time.monotonic() + timeout,
        max_aggregate_untracked_bytes=max_aggregate_untracked_bytes,
        max_filesystem_path_bytes=max_filesystem_path_bytes,
    )
    if state.repository_id != repo.repository_id:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.REPOSITORY_IDENTITY_MISMATCH,
            "lifecycle repository identity does not match the observed repository",
        )
    ownership = state.ownership_record
    if ownership is None or not verify_ownership_record_authenticity(ownership):
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.REPOSITORY_IDENTITY_MISMATCH,
            "trusted M5 ownership evidence is missing or invalid",
        )
    if (
        state.task_id != task_id
        or state.generation != generation
        or ownership.task_id != task_id
        or ownership.generation != generation
        or ownership.repository_id != repo.repository_id
        or ownership.task_ref != state.task_ref
        or ownership.baseline_commit_sha != state.baseline_commit_sha
    ):
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.REPOSITORY_IDENTITY_MISMATCH,
            "task, generation, repository, ref, or baseline ownership identity mismatch",
        )

    worktree_dir = state.worktree_path
    current_device, current_inode, current_head_sha = _observe_owned_worktree_identity(
        repo,
        state,
        worktree_dir,
        budget=budget,
    )

    raw_status = _run_git_status_bounded(
        worktree_dir,
        max_status_bytes=max_status_bytes,
        timeout=budget.remaining_timeout(),
    )
    parsed_entries = _parse_status_stream(
        raw_status,
        max_entries=max_status_entries,
        max_path_bytes=max_status_path_bytes,
    )
    index_manifest = _run_git_index_manifest_bounded(
        worktree_dir,
        object_format=repo.object_format,
        max_index_bytes=max_status_bytes,
        max_entries=max_status_entries,
        max_path_bytes=max_status_path_bytes,
        timeout=budget.remaining_timeout(),
    )
    parsed_entries = tuple(
        replace(entry, anomaly=WorkspaceCaptureFailureKind.FORBIDDEN_GITLINK)
        if entry.path in index_manifest.gitlink_paths
        or (entry.second_path is not None and entry.second_path in index_manifest.gitlink_paths)
        else entry
        for entry in parsed_entries
    )
    represented_paths = {
        path
        for entry in parsed_entries
        for path in (entry.path, entry.second_path)
        if path is not None
    }
    parsed_entries = tuple(
        sorted(
            (
                *parsed_entries,
                *(
                    StatusManifestEntry(
                        code="GL",
                        categories=(StatusCategory.FILESYSTEM_ANOMALY,),
                        path=path,
                        anomaly=WorkspaceCaptureFailureKind.FORBIDDEN_GITLINK,
                        untracked_file_type="GITLINK",
                    )
                    for path in index_manifest.gitlink_paths
                    if path not in represented_paths
                ),
            ),
            key=lambda entry: (entry.path, entry.second_path or "", entry.code),
        )
    )
    parsed_entries = _scan_unobserved_special_entries(
        worktree_dir,
        parsed_entries,
        tracked_paths=index_manifest.tracked_paths,
        gitlink_paths=index_manifest.gitlink_paths,
        budget=budget,
        max_entries=max_status_entries,
        max_path_bytes=max_status_path_bytes,
    )
    entries, untracked_content, untracked_truncated = _enrich_untracked_entries(
        worktree_dir,
        parsed_entries,
        max_inline_file_bytes=MAX_UNTRACKED_FILE_EVIDENCE_BYTES,
        max_inline_total_bytes=max_untracked_inline_bytes,
        budget=budget,
    )
    manifest_digest = _canonical_status_manifest(entries)
    status_counts = _count_status_categories(entries)
    diff_byte_count, diff_sha256, diff_content, is_diff_truncated = _run_git_diff_bounded(
        worktree_dir,
        max_diff_bytes=max_diff_bytes,
        max_complete_bytes=max_complete_diff_bytes,
        timeout=budget.remaining_timeout(),
    )

    repeated_status = _run_git_status_bounded(
        worktree_dir,
        max_status_bytes=max_status_bytes,
        timeout=budget.remaining_timeout(),
    )
    if repeated_status != raw_status:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.INTERNAL_CANONICALIZATION_INCONSISTENCY,
            "workspace status changed during checkpoint capture",
        )
    repeated_diff_count, repeated_diff_sha256, _, _ = _run_git_diff_bounded(
        worktree_dir,
        max_diff_bytes=0,
        max_complete_bytes=max_complete_diff_bytes,
        timeout=budget.remaining_timeout(),
    )
    if (repeated_diff_count, repeated_diff_sha256) != (diff_byte_count, diff_sha256):
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.INTERNAL_CANONICALIZATION_INCONSISTENCY,
            "workspace diff changed during checkpoint capture",
        )
    _revalidate_untracked_entries(worktree_dir, entries, budget=budget)
    final_device, final_inode, final_head_sha = _observe_owned_worktree_identity(
        repo,
        state,
        worktree_dir,
        budget=budget,
    )
    if (
        final_device != current_device
        or final_inode != current_inode
        or final_head_sha != current_head_sha
    ):
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.REF_IDENTITY_MISMATCH,
            "worktree filesystem or commit identity changed during checkpoint capture",
        )

    anomalies = tuple(
        sorted(
            {entry.anomaly for entry in entries if entry.anomaly is not None},
            key=lambda anomaly: anomaly.value,
        )
    )
    incomplete_anomalies = {
        WorkspaceCaptureFailureKind.UNREADABLE_UNTRACKED_ENTRY,
        WorkspaceCaptureFailureKind.UNHASHABLE_UNTRACKED_ENTRY,
        WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED,
    }
    completeness = (
        WorkspaceCaptureCompleteness.INCOMPLETE
        if incomplete_anomalies.intersection(anomalies)
        else WorkspaceCaptureCompleteness.COMPLETE
    )
    checkpoint_payload = {
        "anomalies": [anomaly.value for anomaly in anomalies],
        "authoritative_diff_truncated": False,
        "authoritative_status_truncated": False,
        "baseline_commit_sha": state.baseline_commit_sha,
        "capture_completeness": completeness.value,
        "current_head_sha": current_head_sha,
        "diff_byte_count": diff_byte_count,
        "diff_sha256": diff_sha256,
        "generation": generation,
        "ownership_digest": ownership.ownership_digest,
        "repository_id": repo.repository_id,
        "reservation_digest": ownership.reservation_digest,
        "schema_version": "AOSWORKSPACECHECKPOINT/1",
        "status_counts": status_counts.to_dict(),
        "status_entry_count": len(entries),
        "status_manifest_sha256": manifest_digest,
        "task_id": task_id,
        "task_ref": state.task_ref,
        "worktree_device": current_device,
        "worktree_inode": current_inode,
    }
    checkpoint_digest = _canonical_checkpoint_digest(checkpoint_payload)
    checkpoint = WorkspaceCheckpoint(
        schema_version="AOSWORKSPACECHECKPOINT/1",
        repository_id=repo.repository_id,
        ownership_digest=ownership.ownership_digest,
        reservation_digest=ownership.reservation_digest,
        task_id=task_id,
        generation=generation,
        task_ref=state.task_ref,
        baseline_commit_sha=state.baseline_commit_sha,
        current_head_sha=current_head_sha,
        worktree_device=current_device,
        worktree_inode=current_inode,
        status_counts=status_counts,
        status_manifest_sha256=manifest_digest,
        status_entry_count=len(entries),
        diff_byte_count=diff_byte_count,
        diff_sha256=diff_sha256,
        anomalies=anomalies,
        capture_completeness=completeness,
        authoritative_status_truncated=False,
        authoritative_diff_truncated=False,
        checkpoint_digest=checkpoint_digest,
    )
    presented = entries[:max_paths_per_category]
    omitted_count = len(entries) - len(presented)
    def paths_for(category: StatusCategory) -> tuple[str, ...]:
        return tuple(entry.path for entry in entries if category in entry.categories)[
            :max_paths_per_category
        ]

    decision = (
        WorkspaceReuseDecision.REUSABLE
        if not anomalies and completeness is WorkspaceCaptureCompleteness.COMPLETE
        else WorkspaceReuseDecision.NOT_REUSABLE
    )
    return WorkspaceCheckpointCaptureResult(
        decision=decision,
        checkpoint=checkpoint,
        failure=None,
        status_entries=presented,
        modified_paths=paths_for(StatusCategory.TRACKED_MODIFIED),
        tracked_added_paths=paths_for(StatusCategory.TRACKED_ADDED),
        added_untracked_paths=paths_for(StatusCategory.UNTRACKED),
        deleted_paths=paths_for(StatusCategory.TRACKED_DELETED),
        renamed_paths=tuple(
            (entry.second_path, entry.path)
            for entry in entries
            if StatusCategory.RENAMED in entry.categories and entry.second_path is not None
        )[:max_paths_per_category],
        copied_paths=tuple(
            (entry.second_path, entry.path)
            for entry in entries
            if StatusCategory.COPIED in entry.categories and entry.second_path is not None
        )[:max_paths_per_category],
        unmerged_paths=paths_for(StatusCategory.UNMERGED),
        path_list_truncated=omitted_count > 0,
        omitted_path_count=omitted_count,
        untracked_evidence_content=untracked_content,
        is_untracked_evidence_truncated=untracked_truncated,
        diff_content=diff_content,
        is_diff_truncated=is_diff_truncated,
        observed_at=str(time.time_ns()),
    )


@dataclass(frozen=True)
class RepositoryIdentity:
    """Canonical identity of a controller-owned Git repository."""

    canonical_root: Path
    common_git_dir: Path
    device: Optional[int]
    inode: Optional[int]
    object_format: str
    repository_id: str

    @classmethod
    def from_path(cls, path: str | Path) -> RepositoryIdentity:
        try:
            canonical = Path(path).resolve(strict=True)
        except OSError as exc:
            raise RepositoryIdentityError(f"repository path resolve failed: {type(exc).__name__}") from exc
        if not canonical.is_dir():
            raise RepositoryIdentityError(f"repository root is not a directory: {canonical}")

        git_entry = canonical / ".git"
        if not git_entry.exists():
            raise RepositoryIdentityError(f"repository lacks .git entry: {canonical}")

        res = _run_git_plumbing(["git", "rev-parse", "--git-common-dir"], cwd=canonical)
        if res.returncode != 0 or not res.stdout.strip():
            raise RepositoryIdentityError(f"failed to determine git-common-dir for {canonical}: {res.stderr.strip()}")

        raw_common = Path(res.stdout.strip())
        common_dir = raw_common if raw_common.is_absolute() else (canonical / raw_common).resolve()
        if not common_dir.is_dir():
            raise RepositoryIdentityError(f"git common directory is invalid: {common_dir}")

        res_fmt = _run_git_plumbing(["git", "rev-parse", "--show-object-format"], cwd=canonical)
        object_format = res_fmt.stdout.strip().lower() if res_fmt.returncode == 0 and res_fmt.stdout.strip() else "sha1"
        if object_format not in {"sha1", "sha256"}:
            raise RepositoryIdentityError(f"unsupported repository object format: {object_format!r}")

        device: Optional[int] = None
        inode: Optional[int] = None
        try:
            st = os.stat(canonical)
            device, inode = int(st.st_dev), int(st.st_ino)
        except OSError:
            pass

        repo_payload = f"{canonical.as_posix()}:{common_dir.as_posix()}:{object_format}:{device}:{inode}"
        repo_id = hashlib.sha256(repo_payload.encode("utf-8")).hexdigest()
        return cls(
            canonical_root=canonical,
            common_git_dir=common_dir,
            device=device,
            inode=inode,
            object_format=object_format,
            repository_id=repo_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_root": str(self.canonical_root),
            "common_git_dir": str(self.common_git_dir),
            "device": self.device,
            "inode": self.inode,
            "object_format": self.object_format,
            "repository_id": self.repository_id,
        }


@dataclass(frozen=True)
class WorktreeTaskIdentity:
    """Deterministic, immutable AgenticOS task identity bound to baseline, policy, and object format."""

    task_id: str
    generation: int
    nonce: str
    repository_id: str
    baseline_commit_sha: str
    policy_digest: str
    object_format: str
    identity_digest: str

    @classmethod
    def create(
        cls,
        *,
        task_id: str,
        generation: int,
        nonce: str,
        repository_id: str,
        baseline_commit_sha: str,
        policy_digest: str,
        object_format: str = "sha1",
    ) -> WorktreeTaskIdentity:
        if type(task_id) is not str or not _TASK_ID_RE.fullmatch(task_id):
            raise InvalidRefNameError(
                "task_id must be a bounded ASCII identifier starting with alphanumeric"
            )
        if type(generation) is not int or not (0 <= generation <= _MAX_UNSIGNED_64):
            raise ValueError("generation must be a non-negative integer within unsigned 64-bit range")
        if type(nonce) is not str or not _LOWER_HEX_32_RE.fullmatch(nonce):
            raise ValueError("nonce must be exactly 32 lowercase hexadecimal characters")
        if type(repository_id) is not str or not _LOWER_HEX_64_RE.fullmatch(repository_id):
            raise ValueError("repository_id must be 64 lowercase hexadecimal characters")
        if object_format not in {"sha1", "sha256"}:
            raise ValueError("object_format must be 'sha1' or 'sha256'")
        if object_format == "sha1" and (type(baseline_commit_sha) is not str or not _LOWER_HEX_40_RE.fullmatch(baseline_commit_sha)):
            raise InvalidBaselineCommitError("baseline_commit_sha for sha1 repository must be 40 lowercase hex characters")
        if object_format == "sha256" and (type(baseline_commit_sha) is not str or not _LOWER_HEX_64_RE.fullmatch(baseline_commit_sha)):
            raise InvalidBaselineCommitError("baseline_commit_sha for sha256 repository must be 64 lowercase hex characters")
        if type(policy_digest) is not str or not _LOWER_HEX_64_RE.fullmatch(policy_digest):
            raise ValueError("policy_digest must be 64 lowercase hexadecimal characters")

        payload = {
            "baseline_commit_sha": baseline_commit_sha,
            "generation": generation,
            "nonce": nonce,
            "object_format": object_format,
            "policy_digest": policy_digest,
            "repository_id": repository_id,
            "task_id": task_id,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        identity_digest = hashlib.sha256(encoded).hexdigest()

        return cls(
            task_id=task_id,
            generation=generation,
            nonce=nonce,
            repository_id=repository_id,
            baseline_commit_sha=baseline_commit_sha,
            policy_digest=policy_digest,
            object_format=object_format,
            identity_digest=identity_digest,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TaskRef:
    """Validated, controlled Git ref representation."""

    full_ref: str
    short_ref: str
    branch_name: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class WorktreeReservation:
    """Typed controller reservation for a task worktree execution."""

    repository: RepositoryIdentity
    task_identity: WorktreeTaskIdentity
    task_ref: TaskRef
    worktree_name: str
    proposed_worktree_path: Path
    reservation_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository.to_dict(),
            "task_identity": self.task_identity.to_dict(),
            "task_ref": self.task_ref.to_dict(),
            "worktree_name": self.worktree_name,
            "proposed_worktree_path": str(self.proposed_worktree_path),
            "reservation_digest": self.reservation_digest,
        }


@dataclass(frozen=True)
class WorktreeOwnershipRecord:
    """Typed, serializable ownership proof binding a task ref to a specific WorktreeReservation."""

    schema_version: str
    repository_id: str
    object_format: str
    task_id: str
    generation: int
    nonce: str
    policy_digest: str
    baseline_commit_sha: str
    task_ref: str
    worktree_name: str
    reservation_digest: str
    ownership_digest: str
    is_trusted: bool = False

    @classmethod
    def create(
        cls,
        *,
        repository_id: str,
        object_format: str,
        task_id: str,
        generation: int,
        nonce: str,
        policy_digest: str,
        baseline_commit_sha: str,
        task_ref: str,
        worktree_name: str,
        reservation_digest: str,
        schema_version: str = OWNERSHIP_SCHEMA_VERSION,
        is_trusted: bool = False,
    ) -> WorktreeOwnershipRecord:
        if schema_version != OWNERSHIP_SCHEMA_VERSION:
            raise WorktreeValidationError(
                f"unsupported ownership schema_version {schema_version!r}, expected {OWNERSHIP_SCHEMA_VERSION!r}"
            )
        if object_format not in {"sha1", "sha256"}:
            raise ValueError(f"invalid object_format {object_format!r}")

        payload = {
            "baseline_commit_sha": baseline_commit_sha,
            "generation": generation,
            "nonce": nonce,
            "object_format": object_format,
            "policy_digest": policy_digest,
            "repository_id": repository_id,
            "reservation_digest": reservation_digest,
            "schema_version": schema_version,
            "task_id": task_id,
            "task_ref": task_ref,
            "worktree_name": worktree_name,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ownership_digest = hashlib.sha256(encoded).hexdigest()

        return cls(
            schema_version=schema_version,
            repository_id=repository_id,
            object_format=object_format,
            task_id=task_id,
            generation=generation,
            nonce=nonce,
            policy_digest=policy_digest,
            baseline_commit_sha=baseline_commit_sha,
            task_ref=task_ref,
            worktree_name=worktree_name,
            reservation_digest=reservation_digest,
            ownership_digest=ownership_digest,
            is_trusted=is_trusted,
        )

    @classmethod
    def create_from_reservation(cls, reservation: WorktreeReservation, *, is_trusted: bool = False) -> WorktreeOwnershipRecord:
        return cls.create(
            repository_id=reservation.repository.repository_id,
            object_format=reservation.repository.object_format,
            task_id=reservation.task_identity.task_id,
            generation=reservation.task_identity.generation,
            nonce=reservation.task_identity.nonce,
            policy_digest=reservation.task_identity.policy_digest,
            baseline_commit_sha=reservation.task_identity.baseline_commit_sha,
            task_ref=reservation.task_ref.full_ref,
            worktree_name=reservation.worktree_name,
            reservation_digest=reservation.reservation_digest,
            is_trusted=is_trusted,
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("is_trusted", None)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, is_trusted: bool = False) -> WorktreeOwnershipRecord:
        if not isinstance(data, dict):
            raise WorktreeValidationError("ownership record payload must be a dict")
        known_keys = {
            "schema_version", "repository_id", "object_format", "task_id",
            "generation", "nonce", "policy_digest", "baseline_commit_sha",
            "task_ref", "worktree_name", "reservation_digest", "ownership_digest"
        }
        if not known_keys.issubset(data.keys()):
            raise WorktreeValidationError("ownership record payload missing required keys")

        record = cls.create(
            repository_id=data["repository_id"],
            object_format=data["object_format"],
            task_id=data["task_id"],
            generation=data["generation"],
            nonce=data["nonce"],
            policy_digest=data["policy_digest"],
            baseline_commit_sha=data["baseline_commit_sha"],
            task_ref=data["task_ref"],
            worktree_name=data["worktree_name"],
            reservation_digest=data["reservation_digest"],
            schema_version=data.get("schema_version", OWNERSHIP_SCHEMA_VERSION),
            is_trusted=is_trusted,
        )
        if record.ownership_digest != data.get("ownership_digest"):
            raise WorktreeValidationError("ownership record digest mismatch or corrupted payload")
        return record

    @classmethod
    def from_json(cls, raw: str, *, is_trusted: bool = False) -> WorktreeOwnershipRecord:
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as exc:
            raise WorktreeValidationError(f"invalid ownership record JSON: {type(exc).__name__}") from exc
        return cls.from_dict(data, is_trusted=is_trusted)


@dataclass
class WorktreeLifecycleState:
    """Controller-side lifecycle transaction state."""

    schema_version: str
    status: WorktreeLifecycleStatus
    stage_reached: str
    task_id: str
    generation: int
    repository_id: str
    baseline_commit_sha: str
    task_ref: str
    worktree_path: Path
    worktree_device: Optional[int]
    worktree_inode: Optional[int]
    ownership_record: Optional[WorktreeOwnershipRecord]
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "stage_reached": self.stage_reached,
            "task_id": self.task_id,
            "generation": self.generation,
            "repository_id": self.repository_id,
            "baseline_commit_sha": self.baseline_commit_sha,
            "task_ref": self.task_ref,
            "worktree_path": str(self.worktree_path),
            "worktree_device": self.worktree_device,
            "worktree_inode": self.worktree_inode,
            "ownership_record": self.ownership_record.to_dict() if self.ownership_record else None,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, is_trusted: bool = False) -> WorktreeLifecycleState:
        if not isinstance(data, dict):
            raise WorktreeValidationError("lifecycle payload must be a dict")
        ownership = (
            WorktreeOwnershipRecord.from_dict(data["ownership_record"], is_trusted=is_trusted)
            if data.get("ownership_record")
            else None
        )
        return cls(
            schema_version=data.get("schema_version", LIFECYCLE_SCHEMA_VERSION),
            status=WorktreeLifecycleStatus(data["status"]),
            stage_reached=data["stage_reached"],
            task_id=data["task_id"],
            generation=data["generation"],
            repository_id=data["repository_id"],
            baseline_commit_sha=data["baseline_commit_sha"],
            task_ref=data["task_ref"],
            worktree_path=Path(data["worktree_path"]),
            worktree_device=data.get("worktree_device"),
            worktree_inode=data.get("worktree_inode"),
            ownership_record=ownership,
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )


def verify_ownership_record_authenticity(record: WorktreeOwnershipRecord) -> bool:
    """Verify ownership record integrity and controller storage authentication.

    SECURITY RULE: Record MUST have is_trusted=True (set only by WorktreeManager when loaded
    directly from identity-verified controller storage). Arbitrary parsed JSON is UNTRUSTED.
    """
    if not isinstance(record, WorktreeOwnershipRecord) or not record.is_trusted:
        return False
    if record.schema_version != OWNERSHIP_SCHEMA_VERSION:
        return False

    payload = {
        "baseline_commit_sha": record.baseline_commit_sha,
        "generation": record.generation,
        "nonce": record.nonce,
        "object_format": record.object_format,
        "policy_digest": record.policy_digest,
        "repository_id": record.repository_id,
        "reservation_digest": record.reservation_digest,
        "schema_version": record.schema_version,
        "task_id": record.task_id,
        "task_ref": record.task_ref,
        "worktree_name": record.worktree_name,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected_digest = hashlib.sha256(encoded).hexdigest()
    return record.ownership_digest == expected_digest


def validate_baseline_commit(
    repo_path: str | Path,
    baseline_sha: str,
    expected_object_format: Optional[str] = None,
) -> str:
    """Verify that baseline_sha is a valid, existing commit object matching repo object_format."""
    if type(baseline_sha) is not str:
        raise InvalidBaselineCommitError("baseline commit SHA must be a string")

    clean_sha = baseline_sha.strip().lower()
    canonical_repo = Path(repo_path).resolve(strict=True)

    if expected_object_format is None:
        repo_id = RepositoryIdentity.from_path(canonical_repo)
        object_format = repo_id.object_format
    else:
        object_format = expected_object_format

    if object_format == "sha1":
        if not _LOWER_HEX_40_RE.fullmatch(clean_sha):
            raise InvalidBaselineCommitError(
                f"baseline commit SHA for sha1 repository must be exact 40 lowercase hex characters, got {baseline_sha!r}"
            )
    elif object_format == "sha256":
        if not _LOWER_HEX_64_RE.fullmatch(clean_sha):
            raise InvalidBaselineCommitError(
                f"baseline commit SHA for sha256 repository must be exact 64 lowercase hex characters, got {baseline_sha!r}"
            )
    else:
        raise InvalidBaselineCommitError(f"unsupported repository object format {object_format!r}")

    # 1. Cat-file type check (Plumbing)
    res_type = _run_git_plumbing(["git", "cat-file", "-t", "--", clean_sha], cwd=canonical_repo)
    if res_type.returncode != 0:
        raise InvalidBaselineCommitError(
            f"baseline commit object {clean_sha!r} does not exist in repository {canonical_repo}"
        )
    obj_type = res_type.stdout.strip()
    if obj_type != "commit":
        raise InvalidBaselineCommitError(
            f"object {clean_sha!r} is a {obj_type!r}, expected 'commit'"
        )

    # 2. Rev-parse exact commit verification
    res_parse = _run_git_plumbing(
        ["git", "rev-parse", "--verify", "--quiet", "--end-of-options", f"{clean_sha}^{{commit}}"],
        cwd=canonical_repo,
    )
    if res_parse.returncode != 0 or not res_parse.stdout.strip():
        raise InvalidBaselineCommitError(
            f"baseline commit resolution failed for {clean_sha!r}"
        )

    resolved_sha = res_parse.stdout.strip().lower()
    if resolved_sha != clean_sha:
        raise InvalidBaselineCommitError(
            f"resolved baseline SHA {resolved_sha!r} does not match requested SHA {clean_sha!r}"
        )

    return clean_sha


def validate_task_ref(
    task_id: str,
    generation: int,
    repo_path: Optional[str | Path] = None,
) -> TaskRef:
    """Construct and validate a controlled task ref string derived from trusted identity."""
    if type(task_id) is not str or not task_id:
        raise InvalidRefNameError("task_id must be a non-empty string")

    # 1. Strict ASCII check
    if not task_id.isascii():
        raise InvalidRefNameError("task_id must contain ASCII characters only")

    # 2. Prevent leading hyphen (option injection)
    if task_id.startswith("-"):
        raise InvalidRefNameError("task_id must not start with a hyphen")

    # 3. Match narrow ASCII grammar
    if not _TASK_ID_RE.fullmatch(task_id):
        raise InvalidRefNameError(
            f"task_id {task_id!r} contains invalid characters or structure"
        )

    # 4. Explicit rejection of ref / path hostile elements
    forbidden_substrings = (
        "..", "@", "@{", "//", "\\", ".lock", "~", "^", ":", "?", "*", "[", "\"", "'", " ", "\t", "\n", "\r"
    )
    for sub in forbidden_substrings:
        if sub in task_id:
            raise InvalidRefNameError(f"task_id contains forbidden ref substring {sub!r}")

    if task_id.endswith(".lock") or task_id.startswith(".") or task_id.endswith("."):
        raise InvalidRefNameError("task_id has invalid prefix or suffix")

    # 5. Validate generation bounds
    if type(generation) is not int or not (0 <= generation <= _MAX_UNSIGNED_64):
        raise InvalidRefNameError("generation must be a non-negative integer within 64-bit range")

    branch_name = f"aos/{task_id}/g{generation}"
    full_ref = f"refs/heads/{branch_name}"

    # 6. Git check-ref-format validation if repository path is provided
    if repo_path is not None:
        canonical_repo = Path(repo_path).resolve(strict=True)
        res = _run_git_plumbing(["git", "check-ref-format", "--allow-onelevel", full_ref], cwd=canonical_repo)
        if res.returncode != 0:
            raise InvalidRefNameError(f"Git check-ref-format rejected ref {full_ref!r}")

    return TaskRef(full_ref=full_ref, short_ref=branch_name, branch_name=branch_name)


def check_ref_collision(
    repo_path: str | Path,
    task_ref: TaskRef,
    expected_ownership: Optional[WorktreeOwnershipRecord] = None,
) -> tuple[bool, Optional[str]]:
    """Check if task_ref exists in the repository and verify ownership record match."""
    canonical_repo = Path(repo_path).resolve(strict=True)
    res = _run_git_plumbing(
        ["git", "rev-parse", "--verify", "--quiet", "--end-of-options", task_ref.full_ref],
        cwd=canonical_repo,
    )
    if res.returncode != 0 or not res.stdout.strip():
        return False, None

    existing_sha = res.stdout.strip().lower()

    if expected_ownership is None:
        raise TaskRefCollisionError(
            f"Ref {task_ref.full_ref!r} already exists at {existing_sha!r} and no verified ownership record was provided (FAIL CLOSED)"
        )

    if not verify_ownership_record_authenticity(expected_ownership):
        raise TaskRefCollisionError(
            f"Ownership record for ref {task_ref.full_ref!r} failed controller storage authentication (FAIL CLOSED)"
        )

    if expected_ownership.task_ref != task_ref.full_ref:
        raise TaskRefCollisionError(
            f"Ref {task_ref.full_ref!r} does not match ownership record ref {expected_ownership.task_ref!r}"
        )

    if existing_sha != expected_ownership.baseline_commit_sha:
        raise TaskRefCollisionError(
            f"Ref {task_ref.full_ref!r} exists at SHA {existing_sha!r}, which does not match ownership record baseline {expected_ownership.baseline_commit_sha!r}"
        )

    return True, existing_sha


def _is_same_or_subpath(target: Path, base: Path) -> bool:
    """Non-authoritative early controller-side validation (DEFENSE-IN-DEPTH ONLY)."""
    try:
        t = target.resolve()
        b = base.resolve()
        return t == b or b in t.parents
    except (ValueError, OSError):
        return False


def _stat_descriptor_identity(path: Path) -> tuple[int, int]:
    """Open directory handle and stat kernel identity (st_dev, st_ino)."""
    if not path.exists():
        raise WorktreeValidationError(f"path {path} does not exist for descriptor verification")
    if path.is_symlink():
        raise WorktreeValidationError(f"path {path} is a symlink (REJECTED)")

    try:
        if sys.platform.startswith("linux"):
            fd = os.open(path, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                st = os.fstat(fd)
                return int(st.st_dev), int(st.st_ino)
            finally:
                os.close(fd)
        else:
            st = os.stat(path)
            return int(st.st_dev), int(st.st_ino)
    except OSError as exc:
        raise WorktreeValidationError(f"descriptor stat failed for {path}: {type(exc).__name__}") from exc


def get_development_worktree_root_override() -> Optional[Path]:
    """Retrieve development/test override from environment."""
    val = os.environ.get("AGENTICOS_WORKTREE_ROOT")
    return Path(val).resolve() if val else None


def get_default_worktree_root(
    repo_identity: RepositoryIdentity,
    state_root: str | Path | None = None,
    *,
    allow_temporary_for_test: bool = False,
) -> Path:
    """Determine trusted controller-owned worktree root outside the authoritative repository checkout."""
    if state_root is not None:
        root = Path(state_root).resolve()
    else:
        dev_override = get_development_worktree_root_override()
        if dev_override is not None:
            root = dev_override
        elif allow_temporary_for_test:
            root = Path(tempfile.gettempdir()).resolve() / "agenticos_worktrees"
        else:
            raise WorktreeValidationError(
                "Production worktree reservation requires an explicit durable controller state_root; "
                "temporary directory storage is disallowed"
            )

    canonical_repo = repo_identity.canonical_root
    if _is_same_or_subpath(root, canonical_repo):
        raise WorktreeValidationError(
            f"Worktree state root {root} cannot be equal to or located inside the authoritative repository checkout {canonical_repo}"
        )

    return root / "worktrees" / repo_identity.repository_id


def create_worktree_reservation(
    repo_path: str | Path,
    task_id: str,
    generation: int,
    baseline_commit_sha: str,
    nonce: str,
    policy_digest: str,
    state_root: str | Path | None = None,
    existing_ownership: Optional[WorktreeOwnershipRecord] = None,
    allow_temporary_for_test: bool = False,
) -> WorktreeReservation:
    """Construct a verified, collision-checked WorktreeReservation outside authoritative checkout."""
    repo = RepositoryIdentity.from_path(repo_path)
    validated_baseline = validate_baseline_commit(
        repo.canonical_root, baseline_commit_sha, expected_object_format=repo.object_format
    )

    task_identity = WorktreeTaskIdentity.create(
        task_id=task_id,
        generation=generation,
        nonce=nonce,
        repository_id=repo.repository_id,
        baseline_commit_sha=validated_baseline,
        policy_digest=policy_digest,
        object_format=repo.object_format,
    )

    task_ref = validate_task_ref(task_id, generation, repo_path=repo.canonical_root)
    check_ref_collision(repo.canonical_root, task_ref, expected_ownership=existing_ownership)

    worktree_name = f"{task_id}_g{generation}_{nonce[:8]}"
    if not _WORKTREE_NAME_RE.fullmatch(worktree_name) or ".." in worktree_name or "/" in worktree_name or "\\" in worktree_name:
        raise InvalidRefNameError(f"derived worktree name {worktree_name!r} is invalid")

    target_root = get_default_worktree_root(
        repo, state_root=state_root, allow_temporary_for_test=allow_temporary_for_test
    )
    proposed_path = target_root / task_id / f"g{generation}" / "worktree"

    if _is_same_or_subpath(proposed_path, repo.canonical_root):
        raise WorktreeValidationError(
            f"Proposed worktree path {proposed_path} cannot be inside or equal to the authoritative repository checkout"
        )

    res_payload = {
        "object_format": repo.object_format,
        "proposed_worktree_path": str(proposed_path),
        "repository_id": repo.repository_id,
        "task_identity_digest": task_identity.identity_digest,
        "task_ref": task_ref.full_ref,
        "worktree_name": worktree_name,
    }
    reservation_digest = hashlib.sha256(
        json.dumps(res_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    return WorktreeReservation(
        repository=repo,
        task_identity=task_identity,
        task_ref=task_ref,
        worktree_name=worktree_name,
        proposed_worktree_path=proposed_path,
        reservation_digest=reservation_digest,
    )


# ============================================================================
# CONCURRENCY LOCKING & WORKTREE MANAGER (SLICE 2A.1)
# ============================================================================

@contextlib.contextmanager
def acquire_repository_lock(lock_path: Path, timeout: float = 30.0):
    """Kernel-held cross-process repository lock released automatically on process exit."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    f = open(lock_path, "a+b")
    start = time.monotonic()
    acquired = False
    while time.monotonic() - start < timeout:
        try:
            if sys.platform == "win32":
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
            break
        except OSError:
            time.sleep(0.05)

    if not acquired:
        f.close()
        raise WorktreeValidationError(f"failed to acquire controller repository lock at {lock_path} within {timeout}s")

    try:
        yield f
    finally:
        try:
            if sys.platform == "win32":
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        f.close()


class WorktreeManager:
    """Trusted host-side controller managing Git worktree creation, verification, and preservation."""

    def __init__(self, state_root: str | Path, lock_timeout: float = 30.0):
        self.state_root = Path(state_root).resolve()
        self.lock_timeout = lock_timeout
        if not self.state_root.is_dir():
            self.state_root.mkdir(parents=True, exist_ok=True)

    def _get_repo_state_dir(self, repo_id: str) -> Path:
        return self.state_root / "worktrees" / repo_id

    def _get_task_state_dir(self, repo_id: str, task_id: str, generation: int) -> Path:
        return self._get_repo_state_dir(repo_id) / task_id / f"g{generation}"

    def _get_lock_path(self, repo_id: str) -> Path:
        return self._get_repo_state_dir(repo_id) / "controller.lock"

    def _atomic_write_json(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(f".tmp.{os.getpid()}")
        raw = json.dumps(payload, sort_keys=True, indent=2).encode("utf-8")

        with open(tmp_path, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, path)
        try:
            parent_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except OSError:
            pass

    def _load_trusted_ownership_record(self, task_dir: Path) -> WorktreeOwnershipRecord:
        """Load ownership record directly from identity-verified controller storage directory."""
        if not _is_same_or_subpath(task_dir, self.state_root):
            raise WorktreeValidationError(f"task directory {task_dir} is outside trusted state root {self.state_root}")

        ownership_file = task_dir / "ownership.json"
        if not ownership_file.is_file():
            raise WorktreeValidationError(f"ownership file missing in controller state {ownership_file}")

        raw_json = ownership_file.read_text(encoding="utf-8")
        # Record is trusted because it was loaded directly from controller storage
        return WorktreeOwnershipRecord.from_json(raw_json, is_trusted=True)

    def create(
        self,
        reservation: WorktreeReservation,
        *,
        _inject_failure_at_stage: Optional[str] = None,
    ) -> WorktreeLifecycleState:
        """Create a real linked Git worktree safely from a validated reservation."""
        repo = reservation.repository
        task = reservation.task_identity
        ref = reservation.task_ref

        lock_path = self._get_lock_path(repo.repository_id)
        with acquire_repository_lock(lock_path, timeout=self.lock_timeout):
            # 1. Re-verify baseline commit SHA
            validated_baseline = validate_baseline_commit(
                repo.canonical_root, task.baseline_commit_sha, expected_object_format=repo.object_format
            )

            # 2. Check path & ref collisions
            worktree_dir = reservation.proposed_worktree_path
            task_dir = worktree_dir.parent

            if _is_same_or_subpath(worktree_dir, repo.canonical_root):
                raise WorktreeValidationError("worktree directory cannot be inside or equal to repository checkout")

            if _is_same_or_subpath(task_dir, repo.canonical_root):
                raise WorktreeValidationError("task state directory cannot be inside or equal to repository checkout")

            if worktree_dir.exists() or worktree_dir.is_symlink():
                raise TaskRefCollisionError(f"worktree path {worktree_dir} already exists on disk or is a symlink")

            ownership_file = task_dir / "ownership.json"
            if ownership_file.exists():
                raise TaskRefCollisionError(f"task state directory {task_dir} already contains ownership.json")

            check_ref_collision(repo.canonical_root, ref, expected_ownership=None)

            now_str = str(int(time.time()))
            state = WorktreeLifecycleState(
                schema_version=LIFECYCLE_SCHEMA_VERSION,
                status=WorktreeLifecycleStatus.RESERVED,
                stage_reached="RESERVED",
                task_id=task.task_id,
                generation=task.generation,
                repository_id=repo.repository_id,
                baseline_commit_sha=validated_baseline,
                task_ref=ref.full_ref,
                worktree_path=worktree_dir,
                worktree_device=None,
                worktree_inode=None,
                ownership_record=None,
                created_at=now_str,
                updated_at=now_str,
            )
            self._atomic_write_json(task_dir / "lifecycle.json", state.to_dict())

            if _inject_failure_at_stage == "RESERVED":
                state.status = WorktreeLifecycleStatus.PARTIAL_STATE_ONLY
                self._atomic_write_json(task_dir / "lifecycle.json", state.to_dict())
                raise WorktreeValidationError("injected failure after RESERVED")

            # Stage 2: STATE_PREPARED
            state.stage_reached = "STATE_PREPARED"
            state.status = WorktreeLifecycleStatus.STATE_PREPARED
            task_dir.mkdir(parents=True, exist_ok=True)
            self._atomic_write_json(task_dir / "lifecycle.json", state.to_dict())

            if _inject_failure_at_stage == "STATE_PREPARED":
                state.status = WorktreeLifecycleStatus.PARTIAL_STATE_ONLY
                self._atomic_write_json(task_dir / "lifecycle.json", state.to_dict())
                raise WorktreeValidationError("injected failure after STATE_PREPARED")

            # Stage 3: REF_RESERVED
            res_branch = _run_git_plumbing(
                ["git", "branch", ref.branch_name, validated_baseline],
                cwd=repo.canonical_root,
            )
            if res_branch.returncode != 0:
                raise WorktreeValidationError(f"failed to create task branch {ref.branch_name}: {res_branch.stderr.strip()}")

            state.stage_reached = "REF_RESERVED"
            state.status = WorktreeLifecycleStatus.REF_RESERVED
            self._atomic_write_json(task_dir / "lifecycle.json", state.to_dict())

            if _inject_failure_at_stage == "REF_RESERVED":
                state.status = WorktreeLifecycleStatus.PARTIAL_REF_ONLY
                self._atomic_write_json(task_dir / "lifecycle.json", state.to_dict())
                raise WorktreeValidationError("injected failure after REF_RESERVED")

            # Stage 4: WORKTREE_CREATED
            res_wt = _run_git_plumbing(
                ["git", "worktree", "add", str(worktree_dir), ref.branch_name],
                cwd=repo.canonical_root,
            )
            if res_wt.returncode != 0:
                state.status = WorktreeLifecycleStatus.PARTIAL_REF_ONLY
                self._atomic_write_json(task_dir / "lifecycle.json", state.to_dict())
                raise WorktreeValidationError(f"git worktree add failed: {res_wt.stderr.strip()}")

            state.stage_reached = "WORKTREE_CREATED"
            state.status = WorktreeLifecycleStatus.WORKTREE_CREATED
            self._atomic_write_json(task_dir / "lifecycle.json", state.to_dict())

            if _inject_failure_at_stage == "WORKTREE_CREATED":
                state.status = WorktreeLifecycleStatus.PARTIAL_WORKTREE
                self._atomic_write_json(task_dir / "lifecycle.json", state.to_dict())
                raise WorktreeValidationError("injected failure after WORKTREE_CREATED")

            # Stage 5: WORKTREE_VERIFIED
            self._verify_created_worktree(repo, reservation, worktree_dir)
            st_dev, st_ino = _stat_descriptor_identity(worktree_dir)
            state.worktree_device = st_dev
            state.worktree_inode = st_ino
            state.stage_reached = "WORKTREE_VERIFIED"
            state.status = WorktreeLifecycleStatus.WORKTREE_VERIFIED
            self._atomic_write_json(task_dir / "lifecycle.json", state.to_dict())

            if _inject_failure_at_stage == "WORKTREE_VERIFIED":
                raise WorktreeValidationError("injected failure after WORKTREE_VERIFIED")

            # Stage 6: READY
            ownership = WorktreeOwnershipRecord.create_from_reservation(reservation, is_trusted=True)
            self._atomic_write_json(ownership_file, ownership.to_dict())

            loaded_ownership = self._load_trusted_ownership_record(task_dir)
            if not verify_ownership_record_authenticity(loaded_ownership):
                raise WorktreeValidationError("written ownership record failed verification")

            state.ownership_record = loaded_ownership
            state.stage_reached = "READY"
            state.status = WorktreeLifecycleStatus.CLEAN_BASELINE_DISPOSABLE
            state.updated_at = str(int(time.time()))
            self._atomic_write_json(task_dir / "lifecycle.json", state.to_dict())

            return state

    def _verify_created_worktree(
        self,
        repo: RepositoryIdentity,
        reservation: WorktreeReservation,
        worktree_dir: Path,
    ) -> None:
        """Independently verify created worktree filesystem and Git plumbing metadata."""
        if not worktree_dir.is_dir():
            raise WorktreeValidationError(f"worktree directory does not exist: {worktree_dir}")
        if worktree_dir.is_symlink():
            raise WorktreeValidationError(f"worktree path is a symlink: {worktree_dir}")

        git_file = worktree_dir / ".git"
        if not git_file.is_file():
            raise WorktreeValidationError(f"worktree lacks .git file: {git_file}")

        git_content = git_file.read_text(encoding="utf-8").strip()
        if not git_content.startswith("gitdir:"):
            raise WorktreeValidationError(f"worktree .git file format invalid: {git_content!r}")

        gitdir_raw = Path(git_content.split("gitdir:", 1)[1].strip())
        gitdir = gitdir_raw if gitdir_raw.is_absolute() else (worktree_dir / gitdir_raw).resolve()

        if not _is_same_or_subpath(gitdir, repo.common_git_dir / "worktrees"):
            raise WorktreeValidationError(f"gitdir {gitdir} is not inside repository common git dir worktrees namespace")

        commondir_file = gitdir / "commondir"
        if not commondir_file.is_file():
            raise WorktreeValidationError(f"gitdir lacks commondir file: {commondir_file}")

        raw_cd = commondir_file.read_text(encoding="utf-8").strip()
        commondir = Path(raw_cd) if Path(raw_cd).is_absolute() else (gitdir / raw_cd).resolve()
        if commondir != repo.common_git_dir:
            raise WorktreeValidationError(f"commondir {commondir} does not match repo common git dir {repo.common_git_dir}")

        head_file = gitdir / "HEAD"
        if not head_file.is_file():
            raise WorktreeValidationError("gitdir lacks HEAD file")
        head_content = head_file.read_text(encoding="utf-8").strip()
        if head_content != f"ref: {reservation.task_ref.full_ref}":
            raise WorktreeValidationError(f"worktree HEAD {head_content!r} does not match expected task ref {reservation.task_ref.full_ref!r}")

        res_head = _run_git_plumbing(["git", "rev-parse", "HEAD"], cwd=worktree_dir)
        if res_head.returncode != 0 or res_head.stdout.strip().lower() != reservation.task_identity.baseline_commit_sha:
            raise WorktreeValidationError(f"worktree HEAD rev-parse SHA does not match baseline SHA {reservation.task_identity.baseline_commit_sha}")

        res_ref = _run_git_plumbing(["git", "rev-parse", reservation.task_ref.full_ref], cwd=repo.canonical_root)
        if res_ref.returncode != 0 or res_ref.stdout.strip().lower() != reservation.task_identity.baseline_commit_sha:
            raise WorktreeValidationError(f"task ref rev-parse SHA does not match baseline SHA {reservation.task_identity.baseline_commit_sha}")

    def inspect(self, repo_path: str | Path, task_id: str, generation: int) -> WorktreeLifecycleState:
        """Inspect and classify worktree state strictly from controller-owned records and repository."""
        repo = RepositoryIdentity.from_path(repo_path)
        task_dir = self._get_task_state_dir(repo.repository_id, task_id, generation)
        worktree_dir = task_dir / "worktree"
        lifecycle_file = task_dir / "lifecycle.json"

        if not task_dir.exists():
            return WorktreeLifecycleState(
                schema_version=LIFECYCLE_SCHEMA_VERSION,
                status=WorktreeLifecycleStatus.MISSING,
                stage_reached="NONE",
                task_id=task_id,
                generation=generation,
                repository_id=repo.repository_id,
                baseline_commit_sha="",
                task_ref=f"refs/heads/aos/{task_id}/g{generation}",
                worktree_path=worktree_dir,
                worktree_device=None,
                worktree_inode=None,
                ownership_record=None,
                created_at="0",
                updated_at="0",
            )

        if not lifecycle_file.exists():
            return WorktreeLifecycleState(
                schema_version=LIFECYCLE_SCHEMA_VERSION,
                status=WorktreeLifecycleStatus.PARTIAL_STATE_ONLY,
                stage_reached="STATE_UNTRACKED",
                task_id=task_id,
                generation=generation,
                repository_id=repo.repository_id,
                baseline_commit_sha="",
                task_ref=f"refs/heads/aos/{task_id}/g{generation}",
                worktree_path=worktree_dir,
                worktree_device=None,
                worktree_inode=None,
                ownership_record=None,
                created_at="0",
                updated_at="0",
            )

        with open(lifecycle_file, "r", encoding="utf-8") as f:
            state_data = json.load(f)
        state = WorktreeLifecycleState.from_dict(state_data, is_trusted=False)

        try:
            owner = self._load_trusted_ownership_record(task_dir)
            if verify_ownership_record_authenticity(owner):
                state.ownership_record = owner
            else:
                state.status = WorktreeLifecycleStatus.OWNERSHIP_MISMATCH
                return state
        except WorktreeValidationError:
            state.status = WorktreeLifecycleStatus.OWNERSHIP_MISMATCH
            return state

        if not worktree_dir.exists() or worktree_dir.is_symlink():
            if state.status in {WorktreeLifecycleStatus.READY, WorktreeLifecycleStatus.CLEAN_BASELINE_DISPOSABLE}:
                state.status = WorktreeLifecycleStatus.PARTIAL_REF_ONLY
            return state

        # Check task branch current SHA vs baseline SHA
        res_ref = _run_git_plumbing(["git", "rev-parse", state.task_ref], cwd=repo.canonical_root)
        if res_ref.returncode != 0:
            state.status = WorktreeLifecycleStatus.PARTIAL_WORKTREE
            return state
        current_ref_sha = res_ref.stdout.strip().lower()

        # Check worktree HEAD current SHA
        res_wt_head = _run_git_plumbing(["git", "rev-parse", "HEAD"], cwd=worktree_dir)
        if res_wt_head.returncode != 0:
            state.status = WorktreeLifecycleStatus.GIT_METADATA_MISMATCH
            return state
        current_wt_sha = res_wt_head.stdout.strip().lower()

        # Check git status inside worktree
        res_status = _run_git_plumbing(["git", "status", "--porcelain"], cwd=worktree_dir)
        is_clean = (res_status.returncode == 0 and not res_status.stdout.strip())

        if not is_clean:
            state.status = WorktreeLifecycleStatus.DIRTY_PRESERVED
            return state

        # Working tree is clean. Now check if task branch produced commits beyond baseline!
        baseline_sha = state.baseline_commit_sha.lower()
        if current_ref_sha != baseline_sha or current_wt_sha != baseline_sha:
            # CLEAN WORKTREE != DISPOSABLE TASK! Task produced commits beyond baseline.
            state.status = WorktreeLifecycleStatus.COMMITTED_WORK_PRESERVED
            return state

        # Working tree is clean AND branch is at baseline SHA -> DISPOSABLE
        state.status = WorktreeLifecycleStatus.CLEAN_BASELINE_DISPOSABLE
        return state

    def recover(self, repo_path: str | Path, task_id: str, generation: int) -> WorktreeLifecycleState:
        """Run crash recovery inspection for a task worktree."""
        repo = RepositoryIdentity.from_path(repo_path)
        lock_path = self._get_lock_path(repo.repository_id)
        with acquire_repository_lock(lock_path, timeout=self.lock_timeout):
            return self.inspect(repo_path, task_id, generation)

    def preserve(self, repo_path: str | Path, task_id: str, generation: int) -> WorktreeLifecycleState:
        """Explicitly preserve task worktree state."""
        state = self.inspect(repo_path, task_id, generation)
        if state.status not in {WorktreeLifecycleStatus.MISSING, WorktreeLifecycleStatus.CLEAN_BASELINE_DISPOSABLE}:
            state.status = WorktreeLifecycleStatus.DIRTY_PRESERVED
        return state

    def remove_if_safe(self, repo_path: str | Path, task_id: str, generation: int) -> bool:
        """Safely remove a clean, baseline-only owned worktree and its task ref.

        REFUSES DELETION and preserves work if:
        - Worktree contains uncommitted/dirty/untracked changes (DIRTY_PRESERVED).
        - Task branch contains commits beyond baseline (COMMITTED_WORK_PRESERVED).
        - Ownership record is missing, invalid, or unverified.
        - Worktree kernel identity (st_dev/st_ino) changed unexpectedly.
        - Ref deletion race is detected (git update-ref -d fails).
        """
        repo = RepositoryIdentity.from_path(repo_path)
        lock_path = self._get_lock_path(repo.repository_id)

        with acquire_repository_lock(lock_path, timeout=self.lock_timeout):
            state = self.inspect(repo_path, task_id, generation)
            if state.status == WorktreeLifecycleStatus.MISSING:
                return True

            if state.status == WorktreeLifecycleStatus.COMMITTED_WORK_PRESERVED:
                raise WorktreeValidationError(
                    f"Task branch for {task_id} g{generation} contains committed work beyond baseline and CANNOT be deleted (COMMITTED_WORK_PRESERVED)"
                )

            if state.status == WorktreeLifecycleStatus.DIRTY_PRESERVED:
                raise WorktreeValidationError(
                    f"Worktree for task {task_id} g{generation} contains uncommitted changes and CANNOT be deleted (DIRTY_PRESERVED)"
                )

            if state.status != WorktreeLifecycleStatus.CLEAN_BASELINE_DISPOSABLE or not state.ownership_record:
                raise WorktreeValidationError(
                    f"Worktree state for task {task_id} g{generation} is status={state.status.value} (NOT DISPOSABLE, PRESERVED)"
                )

            task_dir = self._get_task_state_dir(repo.repository_id, task_id, generation)
            worktree_dir = task_dir / "worktree"
            ref_name = state.task_ref

            # 1. Re-verify descriptor kernel identity (st_dev/st_ino) before destructive action
            if worktree_dir.exists():
                cur_dev, cur_ino = _stat_descriptor_identity(worktree_dir)
                if state.worktree_device is not None and (cur_dev != state.worktree_device or cur_ino != state.worktree_inode):
                    raise WorktreeValidationError(
                        f"Worktree filesystem identity changed! Expected ({state.worktree_device}, {state.worktree_inode}), observed ({cur_dev}, {cur_ino}) (PRESERVED)"
                    )

                # 2. Re-verify git status porcelain is empty
                res_st = _run_git_plumbing(["git", "status", "--porcelain"], cwd=worktree_dir)
                if res_st.returncode != 0 or res_st.stdout.strip():
                    raise WorktreeValidationError("Worktree contains modified/untracked files (PRESERVED)")

                # 3. Prune worktree using git worktree remove
                res_rm = _run_git_plumbing(["git", "worktree", "remove", str(worktree_dir)], cwd=repo.canonical_root)
                if res_rm.returncode != 0:
                    shutil.rmtree(worktree_dir, ignore_errors=True)
                    _run_git_plumbing(["git", "worktree", "prune"], cwd=repo.canonical_root)

            # 4. Identity-bound ref deletion with race guard: git update-ref -d <ref> <expected_sha>
            expected_baseline = state.baseline_commit_sha
            res_del_ref = _run_git_plumbing(
                ["git", "update-ref", "-d", ref_name, expected_baseline],
                cwd=repo.canonical_root,
            )
            if res_del_ref.returncode != 0:
                raise WorktreeValidationError(
                    f"git update-ref -d failed for {ref_name} expecting {expected_baseline}: ref race or mismatch detected (PRESERVED)"
                )

            # 5. Remove task state directory
            shutil.rmtree(task_dir, ignore_errors=True)
            return True

    def ensure_git_mask(self, repo_id: str, task_id: str, generation: int) -> Path:
        """Create controller-owned inert Git mask file for sandbox /workspace/.git binding."""
        task_dir = self._get_task_state_dir(repo_id, task_id, generation)
        task_dir.mkdir(parents=True, exist_ok=True)
        mask_file = task_dir / "git_mask"
        if not mask_file.exists():
            payload = b"# AgenticOS Git metadata masked for sandbox\n"
            tmp_file = mask_file.with_suffix(f".tmp.{os.getpid()}")
            with open(tmp_file, "wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_file, mask_file)
            try:
                os.chmod(mask_file, 0o400)
            except OSError:
                pass
        return mask_file

    def verify_worktree_for_sandbox(
        self, repo_path: str | Path, task_id: str, generation: int
    ) -> tuple[Path, Path, WorktreeLifecycleState]:
        """Verify task worktree identity and status before mounting into sandbox.

        Re-verifies:
        1. Repository identity
        2. Trusted ownership record authenticity
        3. Descriptor kernel identity (st_dev/st_ino)
        4. Lifecycle status (READY or valid active status)
        5. Task ref existence and SHA

        Returns (worktree_path, git_mask_path, lifecycle_state).
        Raises WorktreeValidationError if any check fails (FAIL CLOSED).
        """
        repo = RepositoryIdentity.from_path(repo_path)
        lock_path = self._get_lock_path(repo.repository_id)
        with acquire_repository_lock(lock_path, timeout=self.lock_timeout):
            state = self.inspect(repo_path, task_id, generation)
            if state.status not in {
                WorktreeLifecycleStatus.READY,
                WorktreeLifecycleStatus.CLEAN_BASELINE_DISPOSABLE,
                WorktreeLifecycleStatus.COMMITTED_WORK_PRESERVED,
                WorktreeLifecycleStatus.DIRTY_PRESERVED,
            }:
                raise WorktreeValidationError(
                    f"Worktree status {state.status.value} is not ready or valid for sandbox mount (FAIL CLOSED)"
                )
            if not state.ownership_record or not verify_ownership_record_authenticity(state.ownership_record):
                raise WorktreeValidationError("Ownership record failed verification (FAIL CLOSED)")

            worktree_dir = state.worktree_path
            if not worktree_dir.is_dir() or worktree_dir.is_symlink():
                raise WorktreeValidationError(f"Worktree path {worktree_dir} is invalid or a symlink")

            cur_dev, cur_ino = _stat_descriptor_identity(worktree_dir)
            if state.worktree_device is not None and (cur_dev != state.worktree_device or cur_ino != state.worktree_inode):
                raise WorktreeValidationError(
                    f"Worktree filesystem identity changed! Expected ({state.worktree_device}, {state.worktree_inode}), observed ({cur_dev}, {cur_ino})"
                )

            res_ref = _run_git_plumbing(["git", "rev-parse", state.task_ref], cwd=repo.canonical_root)
            if res_ref.returncode != 0:
                raise WorktreeValidationError(f"Task ref {state.task_ref} missing in repository")

            mask_file = self.ensure_git_mask(repo.repository_id, task_id, generation)
            return worktree_dir, mask_file, state

    def capture_checkpoint(
        self,
        repo_path: str | Path,
        task_id: str,
        generation: int,
        *,
        max_diff_bytes: int = 1_000_000,
        max_paths_per_category: int = 1000,
        max_status_bytes: int = MAX_STATUS_OUTPUT_BYTES,
        max_status_entries: int = MAX_STATUS_ENTRIES,
        max_status_path_bytes: int = MAX_STATUS_PATH_BYTES,
        max_complete_diff_bytes: int = MAX_COMPLETE_DIFF_BYTES,
        max_untracked_inline_bytes: int = MAX_UNTRACKED_INLINE_TOTAL_BYTES,
        max_aggregate_untracked_bytes: int = MAX_AGGREGATE_UNTRACKED_BYTES,
        max_filesystem_path_bytes: int = MAX_FILESYSTEM_PATH_BYTES,
    ) -> WorkspaceCheckpointCaptureResult:
        """Measure one complete M5 state and return an explicit reuse decision."""
        observed_at = str(time.time_ns())
        try:
            repo = RepositoryIdentity.from_path(repo_path)
        except WorktreeValidationError as exc:
            error = WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.REPOSITORY_IDENTITY_MISMATCH, str(exc)
            )
            return WorkspaceCheckpointCaptureResult.capture_failed(error, observed_at=observed_at)

        lock_path = self._get_lock_path(repo.repository_id)
        try:
            with acquire_repository_lock(lock_path, timeout=self.lock_timeout):
                state = self.inspect(repo_path, task_id, generation)
                return _capture_workspace_checkpoint(
                    repo,
                    state,
                    task_id=task_id,
                    generation=generation,
                    timeout=self.lock_timeout,
                    max_status_bytes=max_status_bytes,
                    max_status_entries=max_status_entries,
                    max_status_path_bytes=max_status_path_bytes,
                    max_paths_per_category=max_paths_per_category,
                    max_diff_bytes=max_diff_bytes,
                    max_complete_diff_bytes=max_complete_diff_bytes,
                    max_untracked_inline_bytes=max_untracked_inline_bytes,
                    max_aggregate_untracked_bytes=max_aggregate_untracked_bytes,
                    max_filesystem_path_bytes=max_filesystem_path_bytes,
                )
        except WorkspaceCaptureError as exc:
            return WorkspaceCheckpointCaptureResult.capture_failed(exc, observed_at=observed_at)
        except WorktreeValidationError as exc:
            error = WorkspaceCaptureError(
                WorkspaceCaptureFailureKind.REPOSITORY_IDENTITY_MISMATCH, str(exc)
            )
            return WorkspaceCheckpointCaptureResult.capture_failed(error, observed_at=observed_at)

    def capture_result(
        self,
        repo_path: str | Path,
        task_id: str,
        generation: int,
        *,
        worker_exit_code: Optional[int] = None,
        worker_signal: Optional[int] = None,
        worker_timed_out: bool = False,
        max_diff_bytes: int = 1_000_000,
        max_paths_per_category: int = 1000,
        max_status_bytes: int = MAX_STATUS_OUTPUT_BYTES,
        max_status_entries: int = MAX_STATUS_ENTRIES,
        max_status_path_bytes: int = MAX_STATUS_PATH_BYTES,
        max_complete_diff_bytes: int = MAX_COMPLETE_DIFF_BYTES,
        max_untracked_inline_bytes: int = MAX_UNTRACKED_INLINE_TOTAL_BYTES,
        max_aggregate_untracked_bytes: int = MAX_AGGREGATE_UNTRACKED_BYTES,
        max_filesystem_path_bytes: int = MAX_FILESYSTEM_PATH_BYTES,
    ) -> TaskWorktreeResult:
        """Capture post-worker result from trusted Git & filesystem inspection of task worktree."""
        repo = RepositoryIdentity.from_path(repo_path)
        lock_path = self._get_lock_path(repo.repository_id)
        with acquire_repository_lock(lock_path, timeout=self.lock_timeout):
            state = self.inspect(repo_path, task_id, generation)
            worktree_dir = state.worktree_path

            if not worktree_dir.is_dir():
                raise WorktreeValidationError(f"Worktree path {worktree_dir} missing for result capture")

            capture = _capture_workspace_checkpoint(
                repo,
                state,
                task_id=task_id,
                generation=generation,
                timeout=self.lock_timeout,
                max_status_bytes=max_status_bytes,
                max_status_entries=max_status_entries,
                max_status_path_bytes=max_status_path_bytes,
                max_paths_per_category=max_paths_per_category,
                max_diff_bytes=max_diff_bytes,
                max_complete_diff_bytes=max_complete_diff_bytes,
                max_untracked_inline_bytes=max_untracked_inline_bytes,
                max_aggregate_untracked_bytes=max_aggregate_untracked_bytes,
                max_filesystem_path_bytes=max_filesystem_path_bytes,
            )
            checkpoint = capture.checkpoint
            if checkpoint is None:
                raise WorkspaceCaptureError(
                    WorkspaceCaptureFailureKind.INTERNAL_CANONICALIZATION_INCONSISTENCY,
                    "successful capture did not produce a checkpoint",
                )
            current_head_sha = checkpoint.current_head_sha

            is_clean = (
                checkpoint.status_counts.total_entries == 0
                and current_head_sha == state.baseline_commit_sha.lower()
            )

            if is_clean:
                preservation = WorktreeLifecycleStatus.CLEAN_BASELINE_DISPOSABLE.value
            elif current_head_sha != state.baseline_commit_sha.lower():
                preservation = WorktreeLifecycleStatus.COMMITTED_WORK_PRESERVED.value
            else:
                preservation = WorktreeLifecycleStatus.DIRTY_PRESERVED.value

            result = TaskWorktreeResult(
                repository_id=repo.repository_id,
                task_id=task_id,
                generation=generation,
                task_ref=state.task_ref,
                baseline_commit_sha=state.baseline_commit_sha,
                current_head_sha=current_head_sha,
                worktree_path=worktree_dir,
                worktree_device=checkpoint.worktree_device,
                worktree_inode=checkpoint.worktree_inode,
                worker_exit_code=worker_exit_code,
                worker_signal=worker_signal,
                worker_timed_out=worker_timed_out,
                lifecycle_status=WorktreeLifecycleStatus(preservation),
                is_clean=is_clean,
                modified_paths=capture.modified_paths,
                tracked_added_paths=capture.tracked_added_paths,
                added_untracked_paths=capture.added_untracked_paths,
                deleted_paths=capture.deleted_paths,
                renamed_paths=capture.renamed_paths,
                copied_paths=capture.copied_paths,
                unmerged_paths=capture.unmerged_paths,
                status_entries=capture.status_entries,
                status_counts=checkpoint.status_counts,
                status_manifest_sha256=checkpoint.status_manifest_sha256,
                status_entry_count=checkpoint.status_entry_count,
                path_list_truncated=capture.path_list_truncated,
                omitted_path_count=capture.omitted_path_count,
                diff_sha256=checkpoint.diff_sha256,
                diff_byte_count=checkpoint.diff_byte_count,
                diff_content=capture.diff_content,
                is_diff_truncated=capture.is_diff_truncated,
                untracked_evidence_content=capture.untracked_evidence_content,
                is_untracked_evidence_truncated=capture.is_untracked_evidence_truncated,
                workspace_checkpoint=checkpoint,
                checkpoint_digest=checkpoint.checkpoint_digest,
                capture_completeness=checkpoint.capture_completeness,
                reusability_decision=capture.decision,
                preservation_classification=preservation,
            )

            task_dir = self._get_task_state_dir(repo.repository_id, task_id, generation)
            state.status = WorktreeLifecycleStatus(preservation)
            state.stage_reached = "RESULT_CAPTURED"
            state.updated_at = str(int(time.time()))
            self._atomic_write_json(task_dir / "lifecycle.json", state.to_dict())
            self._atomic_write_json(task_dir / "result.json", result.to_dict())

            return result


def _run_git_diff_bounded(
    cwd: Path,
    max_diff_bytes: int = 1_000_000,
    max_complete_bytes: int = MAX_COMPLETE_DIFF_BYTES,
    timeout: float = 10.0,
) -> tuple[int, str, str, bool]:
    """Execute git diff HEAD with bounded streaming memory consumption.

    Returns (diff_byte_count, diff_sha256, diff_inline_content, is_diff_truncated).
    """
    if type(max_diff_bytes) is not int or max_diff_bytes < 0:
        raise ValueError("max_diff_bytes must be a non-negative integer")
    result = _run_git_stream_bounded(
        [
            "git",
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "HEAD",
            "--",
        ],
        cwd=cwd,
        timeout=timeout,
        max_complete_bytes=max_complete_bytes,
        max_inline_bytes=max_diff_bytes,
        failure_kind=WorkspaceCaptureFailureKind.GIT_DIFF_FAILURE,
    )
    is_truncated = result.total_bytes > max_diff_bytes
    diff_text = result.inline_bytes.decode("utf-8", errors="replace")
    if is_truncated:
        diff_text += f"\n... [TRUNCATED {result.total_bytes - max_diff_bytes} BYTES]"
    return result.total_bytes, result.sha256, diff_text, is_truncated


@dataclass(frozen=True)
class TaskWorktreeResult:
    """Typed controller result captured from trusted Git & filesystem inspection after worker execution."""

    repository_id: str
    task_id: str
    generation: int
    task_ref: str
    baseline_commit_sha: str
    current_head_sha: str
    worktree_path: Path
    worktree_device: Optional[int]
    worktree_inode: Optional[int]
    worker_exit_code: Optional[int]
    worker_signal: Optional[int]
    worker_timed_out: bool
    lifecycle_status: WorktreeLifecycleStatus
    is_clean: bool
    modified_paths: tuple[str, ...]
    tracked_added_paths: tuple[str, ...]
    added_untracked_paths: tuple[str, ...]
    deleted_paths: tuple[str, ...]
    renamed_paths: tuple[tuple[str, str], ...]
    copied_paths: tuple[tuple[str, str], ...]
    unmerged_paths: tuple[str, ...]
    status_entries: tuple[StatusManifestEntry, ...]
    status_counts: WorkspaceStatusCounts
    status_manifest_sha256: str
    status_entry_count: int
    path_list_truncated: bool
    omitted_path_count: int
    diff_sha256: str
    diff_byte_count: int
    diff_content: str
    is_diff_truncated: bool
    untracked_evidence_content: str
    is_untracked_evidence_truncated: bool
    workspace_checkpoint: WorkspaceCheckpoint
    checkpoint_digest: str
    capture_completeness: WorkspaceCaptureCompleteness
    reusability_decision: WorkspaceReuseDecision
    preservation_classification: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository_id": self.repository_id,
            "task_id": self.task_id,
            "generation": self.generation,
            "task_ref": self.task_ref,
            "baseline_commit_sha": self.baseline_commit_sha,
            "current_head_sha": self.current_head_sha,
            "worktree_path": str(self.worktree_path),
            "worktree_device": self.worktree_device,
            "worktree_inode": self.worktree_inode,
            "worker_exit_code": self.worker_exit_code,
            "worker_signal": self.worker_signal,
            "worker_timed_out": self.worker_timed_out,
            "lifecycle_status": self.lifecycle_status.value,
            "is_clean": self.is_clean,
            "modified_paths": list(self.modified_paths),
            "tracked_added_paths": list(self.tracked_added_paths),
            "added_untracked_paths": list(self.added_untracked_paths),
            "deleted_paths": list(self.deleted_paths),
            "renamed_paths": [list(pair) for pair in self.renamed_paths],
            "copied_paths": [list(pair) for pair in self.copied_paths],
            "unmerged_paths": list(self.unmerged_paths),
            "status_entries": [entry.to_manifest_dict() for entry in self.status_entries],
            "status_counts": self.status_counts.to_dict(),
            "status_manifest_sha256": self.status_manifest_sha256,
            "status_entry_count": self.status_entry_count,
            "path_list_truncated": self.path_list_truncated,
            "omitted_path_count": self.omitted_path_count,
            "diff_sha256": self.diff_sha256,
            "diff_byte_count": self.diff_byte_count,
            "diff_content": self.diff_content,
            "is_diff_truncated": self.is_diff_truncated,
            "untracked_evidence_content": self.untracked_evidence_content,
            "is_untracked_evidence_truncated": self.is_untracked_evidence_truncated,
            "workspace_checkpoint": self.workspace_checkpoint.to_dict(),
            "checkpoint_digest": self.checkpoint_digest,
            "capture_completeness": self.capture_completeness.value,
            "reusability_decision": self.reusability_decision.value,
            "preservation_classification": self.preservation_classification,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)
