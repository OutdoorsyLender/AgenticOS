"""Milestone 5 Controlled Git Worktree — Task Identity & Ref Validation Substrate.

This module provides trusted, controller-side primitives for:
1. Repository Identity representation & kernel identity binding.
2. Baseline commit SHA validation (Plumbing-only, commit-object verification).
3. Task Ref derivation & strict ASCII ref grammar enforcement.
4. Collision verification and fail-closed ref ownership rules.
5. Deterministic WorktreeTaskIdentity and WorktreeReservation models.

GOVERNING PRINCIPLE: Models reason; AgenticOS guarantees.
AUTHORITY BOUNDARY: The main .git directory is NEVER exposed to hostile workers.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional


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
    """Build a sanitized environment for controller-side Git subprocesses.

    Prevents ambient credential leaks or proxy hijacking during plumbing execution.
    """
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

        device: Optional[int] = None
        inode: Optional[int] = None
        try:
            st = os.stat(canonical)
            device, inode = int(st.st_dev), int(st.st_ino)
        except OSError:
            pass

        repo_payload = f"{canonical.as_posix()}:{common_dir.as_posix()}:{device}:{inode}"
        repo_id = hashlib.sha256(repo_payload.encode("utf-8")).hexdigest()
        return cls(
            canonical_root=canonical,
            common_git_dir=common_dir,
            device=device,
            inode=inode,
            repository_id=repo_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_root": str(self.canonical_root),
            "common_git_dir": str(self.common_git_dir),
            "device": self.device,
            "inode": self.inode,
            "repository_id": self.repository_id,
        }


@dataclass(frozen=True)
class WorktreeTaskIdentity:
    """Deterministic, immutable AgenticOS task identity bound to baseline and policy."""

    task_id: str
    generation: int
    nonce: str
    repository_id: str
    baseline_commit_sha: str
    policy_digest: str
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
        if type(baseline_commit_sha) is not str or not (
            _LOWER_HEX_40_RE.fullmatch(baseline_commit_sha) or _LOWER_HEX_64_RE.fullmatch(baseline_commit_sha)
        ):
            raise InvalidBaselineCommitError("baseline_commit_sha must be full lowercase hexadecimal object ID")
        if type(policy_digest) is not str or not _LOWER_HEX_64_RE.fullmatch(policy_digest):
            raise ValueError("policy_digest must be 64 lowercase hexadecimal characters")

        payload = {
            "baseline_commit_sha": baseline_commit_sha,
            "generation": generation,
            "nonce": nonce,
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


def validate_baseline_commit(repo_path: str | Path, baseline_sha: str) -> str:
    """Verify that baseline_sha is a valid, existing commit object in the repository."""
    if type(baseline_sha) is not str:
        raise InvalidBaselineCommitError("baseline commit SHA must be a string")

    clean_sha = baseline_sha.strip().lower()
    if not (_LOWER_HEX_40_RE.fullmatch(clean_sha) or _LOWER_HEX_64_RE.fullmatch(clean_sha)):
        raise InvalidBaselineCommitError(
            f"baseline commit SHA must be exact 40-char or 64-char lowercase hex, got {baseline_sha!r}"
        )

    canonical_repo = Path(repo_path).resolve(strict=True)

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
    expected_identity: Optional[WorktreeTaskIdentity] = None,
) -> tuple[bool, Optional[str]]:
    """Check if task_ref exists in the repository and verify ownership.

    Returns (exists, commit_sha).
    Raises TaskRefCollisionError if the ref exists and ownership cannot be proven.
    """
    canonical_repo = Path(repo_path).resolve(strict=True)
    res = _run_git_plumbing(
        ["git", "rev-parse", "--verify", "--quiet", "--end-of-options", task_ref.full_ref],
        cwd=canonical_repo,
    )
    if res.returncode != 0 or not res.stdout.strip():
        return False, None

    existing_sha = res.stdout.strip().lower()

    if expected_identity is None:
        raise TaskRefCollisionError(
            f"Ref {task_ref.full_ref!r} already exists at {existing_sha!r} and ownership cannot be verified"
        )

    if existing_sha != expected_identity.baseline_commit_sha:
        raise TaskRefCollisionError(
            f"Ref {task_ref.full_ref!r} exists at SHA {existing_sha!r}, which does not match expected baseline {expected_identity.baseline_commit_sha!r}"
        )

    return True, existing_sha


def create_worktree_reservation(
    repo_path: str | Path,
    task_id: str,
    generation: int,
    baseline_commit_sha: str,
    nonce: str,
    policy_digest: str,
    worktree_root: Optional[str | Path] = None,
) -> WorktreeReservation:
    """Construct a verified, collision-checked WorktreeReservation."""
    repo = RepositoryIdentity.from_path(repo_path)
    validated_baseline = validate_baseline_commit(repo.canonical_root, baseline_commit_sha)

    task_identity = WorktreeTaskIdentity.create(
        task_id=task_id,
        generation=generation,
        nonce=nonce,
        repository_id=repo.repository_id,
        baseline_commit_sha=validated_baseline,
        policy_digest=policy_digest,
    )

    task_ref = validate_task_ref(task_id, generation, repo_path=repo.canonical_root)
    check_ref_collision(repo.canonical_root, task_ref, expected_identity=task_identity)

    worktree_name = f"{task_id}_g{generation}_{nonce[:8]}"
    if not _WORKTREE_NAME_RE.fullmatch(worktree_name) or ".." in worktree_name or "/" in worktree_name or "\\" in worktree_name:
        raise InvalidRefNameError(f"derived worktree name {worktree_name!r} is invalid")

    root_path = Path(worktree_root).resolve() if worktree_root else repo.canonical_root / ".agenticos_worktrees"
    proposed_path = root_path / worktree_name

    res_payload = {
        "repository_id": repo.repository_id,
        "task_identity_digest": task_identity.identity_digest,
        "task_ref": task_ref.full_ref,
        "worktree_name": worktree_name,
        "proposed_worktree_path": str(proposed_path),
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
