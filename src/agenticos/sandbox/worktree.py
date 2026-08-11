"""Milestone 5 Controlled Git Worktree — Task Identity & Ref Validation Substrate.

This module provides trusted, controller-side primitives for:
1. Repository Identity representation & kernel identity binding (SHA-1 / SHA-256 detection).
2. Baseline commit SHA validation (Plumbing-only, repo-object-format strict verification).
3. Task Ref derivation & strict ASCII ref grammar enforcement.
4. Ownership proof modeling, controller storage authentication, and fail-closed ref rules.
5. Controller-owned durable worktree state root outside the authoritative checkout.

GOVERNING PRINCIPLE: Models reason; AgenticOS guarantees.
AUTHORITY BOUNDARY: The main .git directory is NEVER exposed to hostile workers.

SLICE 2 HARD CONSTRAINTS & FILESYSTEM AUTHORITY CONTRACT:
1. Pathname String Semantics:
   - String pathname comparisons (_is_same_or_subpath) are non-authoritative defense-in-depth ONLY.
   - Textual normalization does NOT establish filesystem object identity.
   - Real Slice 2 worktree creation/destruction on Linux MUST operate on descriptor handles:
     a. Open trusted state_root directory (O_DIRECTORY | O_CLOEXEC | O_PATH).
     b. Verify directory kernel identity (fstat st_dev / st_ino).
     c. Resolve paths using openat2 with RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS.
     d. Record & re-verify st_dev / st_ino before any destructive lifecycle action.
2. Durable State Root:
   - Production worktrees MUST use an explicit durable controller state_root outside the checkout.
   - Defaulting to OS temporary storage (/tmp) in production is disallowed (controller crash != loss of work).
   - Ambient process environment (AGENTICOS_WORKTREE_ROOT) is NOT trusted authority for production.
3. Ownership Authenticity:
   - SHA-256 ownership_digest proves integrity and equality, NOT authentic provenance.
   - Ownership records are authoritative ONLY when stored in controller-owned state (in_controller_storage=True).
   - Worker-controlled .git metadata is NEVER used as an ownership record.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional


OWNERSHIP_SCHEMA_VERSION = "AOSWORKTREE/1"

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


def _sanitize_git_env() -> dict[str, str]:
    """Build a sanitized environment for controller-side Git subprocesses."""
    kept: dict[str, str] = {
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    for key, value in os.environ.items():
        upper = key.upper()
        if (
            upper in _ENV_DENY_EXACT
            or any(upper.startswith(p) for p in _ENV_DENY_PREFIXES)
            or any(s in upper for s in _ENV_DENY_SUBSTRINGS)
        ):
            continue
        if key not in kept:
            kept[key] = value
    return kept


def _run_git_plumbing(
    argv: list[str],
    cwd: Path,
    timeout: float = 5.0,
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


def verify_ownership_record_authenticity(
    record: WorktreeOwnershipRecord,
    *,
    in_controller_storage: bool,
) -> bool:
    """Verify ownership record integrity and controller storage authentication.

    SECURITY RULE: SHA-256 ownership_digest proves integrity and identity equality,
    NOT authentic provenance. Anyone can recompute a SHA-256 digest over tampered JSON.
    Ownership records are authoritative ONLY when retrieved from trusted, controller-owned
    storage (in_controller_storage=True) that hostile workers cannot write or modify.
    """
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
    """Check if task_ref exists in the repository and verify ownership record match.

    Returns (exists, commit_sha).
    Raises TaskRefCollisionError if the ref exists and ownership cannot be proven (FAIL CLOSED).
    """
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
    """Non-authoritative early controller-side validation (DEFENSE-IN-DEPTH ONLY).

    NOTE: Pathname string comparison DOES NOT establish filesystem object identity.
    Real Slice 2 authority enforcement MUST use descriptor handles (openat2),
    kernel identity (st_dev/st_ino), and RESOLVE_BENEATH semantics.
    """
    try:
        t = target.resolve()
        b = base.resolve()
        return t == b or b in t.parents
    except (ValueError, OSError):
        return False


def get_development_worktree_root_override() -> Optional[Path]:
    """Retrieve development/test override from environment.

    NOTE: Ambient environment variables are NOT trusted authority roots for production tasks.
    Top-level controller configuration MUST explicitly validate and bind state_root.
    """
    val = os.environ.get("AGENTICOS_WORKTREE_ROOT")
    return Path(val).resolve() if val else None


def get_default_worktree_root(
    repo_identity: RepositoryIdentity,
    state_root: str | Path | None = None,
    *,
    allow_temporary_for_test: bool = False,
) -> Path:
    """Determine trusted controller-owned worktree root outside the authoritative repository checkout.

    PRODUCTION REQUIREMENT: Production worktree state MUST use an explicit durable controller state_root.
    Silently defaulting to temporary OS storage (/tmp) in production is disallowed to ensure
    uncommitted model work survives controller restart/crash.
    """
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

    return root / repo_identity.repository_id


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
    proposed_path = target_root / task_identity.identity_digest[:16] / worktree_name

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
