"""Milestone 5 Controlled Git Worktree — Controller-Owned Worktree Lifecycle Substrate.

This module provides trusted, controller-side primitives for:
1. Repository Identity representation & kernel identity binding (SHA-1 / SHA-256 detection).
2. Baseline commit SHA validation (Plumbing-only, repo-object-format strict verification).
3. Task Ref derivation & strict ASCII ref grammar enforcement.
4. Ownership proof modeling, controller storage authentication, and fail-closed ref rules.
5. Controller-owned durable worktree state root outside the authoritative checkout.
6. Real linked Git worktree creation, post-creation verification, transaction tracking,
   concurrency locking, crash recovery classification, and safe preservation/removal.

GOVERNING PRINCIPLE: Models reason; AgenticOS guarantees.
AUTHORITY BOUNDARY: The main .git directory is NEVER exposed to hostile workers.

SLICE 2A SCOPE & BOUNDARIES:
- Controller-only lifecycle management.
- Host-side Git worktree creation and identity verification.
- No hostile worker launched.
- Main .git directory is NEVER mounted into Bubblewrap/worker.
- No worker Git view / commands exposed in this slice.
"""

from __future__ import annotations

import contextlib
import enum
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
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

    # Recovery / Anomaly Classifications
    PARTIAL_STATE_ONLY = "PARTIAL_STATE_ONLY"
    PARTIAL_REF_ONLY = "PARTIAL_REF_ONLY"
    PARTIAL_WORKTREE = "PARTIAL_WORKTREE"
    DIRTY_PRESERVED = "DIRTY_PRESERVED"
    OWNERSHIP_MISMATCH = "OWNERSHIP_MISMATCH"
    GIT_METADATA_MISMATCH = "GIT_METADATA_MISMATCH"
    UNKNOWN_PRESERVED = "UNKNOWN_PRESERVED"
    MISSING = "MISSING"
    CLEAN_DISPOSABLE = "CLEAN_DISPOSABLE"


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
        )

    @classmethod
    def create_from_reservation(cls, reservation: WorktreeReservation) -> WorktreeOwnershipRecord:
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
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorktreeOwnershipRecord:
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
        )
        if record.ownership_digest != data.get("ownership_digest"):
            raise WorktreeValidationError("ownership record digest mismatch or corrupted payload")
        return record

    @classmethod
    def from_json(cls, raw: str) -> WorktreeOwnershipRecord:
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as exc:
            raise WorktreeValidationError(f"invalid ownership record JSON: {type(exc).__name__}") from exc
        return cls.from_dict(data)


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
    def from_dict(cls, data: dict[str, Any]) -> WorktreeLifecycleState:
        if not isinstance(data, dict):
            raise WorktreeValidationError("lifecycle payload must be a dict")
        ownership = (
            WorktreeOwnershipRecord.from_dict(data["ownership_record"])
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


def verify_ownership_record_authenticity(
    record: WorktreeOwnershipRecord,
    *,
    in_controller_storage: bool,
) -> bool:
    """Verify ownership record integrity and controller storage authentication."""
    if not in_controller_storage:
        return False
    if not isinstance(record, WorktreeOwnershipRecord):
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
    *,
    in_controller_storage: bool = True,
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

    if not verify_ownership_record_authenticity(expected_ownership, in_controller_storage=in_controller_storage):
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
# CONCURRENCY LOCKING & WORKTREE MANAGER (SLICE 2A)
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

            if worktree_dir.exists():
                raise TaskRefCollisionError(f"worktree path {worktree_dir} already exists on disk")

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
            st_wt = os.stat(worktree_dir)
            state.worktree_device = int(st_wt.st_dev)
            state.worktree_inode = int(st_wt.st_ino)
            state.stage_reached = "WORKTREE_VERIFIED"
            state.status = WorktreeLifecycleStatus.WORKTREE_VERIFIED
            self._atomic_write_json(task_dir / "lifecycle.json", state.to_dict())

            if _inject_failure_at_stage == "WORKTREE_VERIFIED":
                raise WorktreeValidationError("injected failure after WORKTREE_VERIFIED")

            # Stage 6: READY
            ownership = WorktreeOwnershipRecord.create_from_reservation(reservation)
            self._atomic_write_json(ownership_file, ownership.to_dict())

            # Re-read and verify written ownership record
            with open(ownership_file, "r", encoding="utf-8") as f:
                loaded_ownership = WorktreeOwnershipRecord.from_json(f.read())
            if not verify_ownership_record_authenticity(loaded_ownership, in_controller_storage=True):
                raise WorktreeValidationError("written ownership record failed verification")

            state.ownership_record = loaded_ownership
            state.stage_reached = "READY"
            state.status = WorktreeLifecycleStatus.READY
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
        ownership_file = task_dir / "ownership.json"

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
        state = WorktreeLifecycleState.from_dict(state_data)

        if ownership_file.exists():
            with open(ownership_file, "r", encoding="utf-8") as f:
                raw_owner = f.read()
            try:
                owner = WorktreeOwnershipRecord.from_json(raw_owner)
                if verify_ownership_record_authenticity(owner, in_controller_storage=True):
                    state.ownership_record = owner
                else:
                    state.status = WorktreeLifecycleStatus.OWNERSHIP_MISMATCH
                    return state
            except WorktreeValidationError:
                state.status = WorktreeLifecycleStatus.OWNERSHIP_MISMATCH
                return state

        if not worktree_dir.exists():
            if state.status == WorktreeLifecycleStatus.READY:
                state.status = WorktreeLifecycleStatus.PARTIAL_REF_ONLY
            return state

        # Check git status inside worktree
        res_status = _run_git_plumbing(["git", "status", "--porcelain"], cwd=worktree_dir)
        if res_status.returncode == 0 and res_status.stdout.strip():
            state.status = WorktreeLifecycleStatus.DIRTY_PRESERVED
            return state

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
        if state.status not in {WorktreeLifecycleStatus.MISSING, WorktreeLifecycleStatus.CLEAN_DISPOSABLE}:
            state.status = WorktreeLifecycleStatus.DIRTY_PRESERVED
        return state

    def remove_if_safe(self, repo_path: str | Path, task_id: str, generation: int) -> bool:
        """Safely remove a clean, verified worktree and its task ref.

        REFUSES DELETION and preserves work if:
        - Worktree contains uncommitted/dirty/untracked changes.
        - Ownership record is missing or invalid.
        - Worktree filesystem/Git identity checks fail.
        """
        repo = RepositoryIdentity.from_path(repo_path)
        lock_path = self._get_lock_path(repo.repository_id)

        with acquire_repository_lock(lock_path, timeout=self.lock_timeout):
            state = self.inspect(repo_path, task_id, generation)
            if state.status == WorktreeLifecycleStatus.MISSING:
                return True

            if state.status == WorktreeLifecycleStatus.DIRTY_PRESERVED:
                raise WorktreeValidationError(
                    f"Worktree for task {task_id} g{generation} contains uncommitted changes and CANNOT be deleted (PRESERVED)"
                )

            if state.status != WorktreeLifecycleStatus.READY or not state.ownership_record:
                raise WorktreeValidationError(
                    f"Worktree state for task {task_id} g{generation} is not READY or lacks verified ownership (PRESERVED)"
                )

            task_dir = self._get_task_state_dir(repo.repository_id, task_id, generation)
            worktree_dir = task_dir / "worktree"
            ref_name = state.task_ref

            # 1. Verify git status porcelain is empty
            if worktree_dir.exists():
                res_st = _run_git_plumbing(["git", "status", "--porcelain"], cwd=worktree_dir)
                if res_st.returncode != 0 or res_st.stdout.strip():
                    raise WorktreeValidationError("Worktree contains modified/untracked files (PRESERVED)")

                # 2. Prune worktree using git worktree remove
                res_rm = _run_git_plumbing(["git", "worktree", "remove", str(worktree_dir)], cwd=repo.canonical_root)
                if res_rm.returncode != 0:
                    # Fallback to directory deletion if git worktree remove fails but dir is clean
                    shutil.rmtree(worktree_dir, ignore_errors=True)
                    _run_git_plumbing(["git", "worktree", "prune"], cwd=repo.canonical_root)

            # 3. Delete task branch
            _run_git_plumbing(["git", "branch", "-D", ref_name.replace("refs/heads/", "")], cwd=repo.canonical_root)

            # 4. Remove task state directory
            shutil.rmtree(task_dir, ignore_errors=True)
            return True
