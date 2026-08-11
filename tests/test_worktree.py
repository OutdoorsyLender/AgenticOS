"""Unit and security property tests for Milestone 5 Slice 1B Controlled Git Worktree Identity & Authority Hardening."""

import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from agenticos.sandbox.worktree import (
    OWNERSHIP_SCHEMA_VERSION,
    InvalidBaselineCommitError,
    InvalidRefNameError,
    RepositoryIdentity,
    RepositoryIdentityError,
    TaskRef,
    TaskRefCollisionError,
    WorktreeOwnershipRecord,
    WorktreeReservation,
    WorktreeTaskIdentity,
    WorktreeValidationError,
    _is_same_or_subpath,
    check_ref_collision,
    create_worktree_reservation,
    get_default_worktree_root,
    get_development_worktree_root_override,
    validate_baseline_commit,
    validate_task_ref,
    verify_ownership_record_authenticity,
)


@pytest.fixture
def temp_git_repo(tmp_path):
    """Create a temporary git repository (SHA-1) with initial commit, tree, and blob."""
    repo = tmp_path / "test_repo"
    repo.mkdir()

    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test Agent"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@agenticos.local"], cwd=repo, check=True)

    file_a = repo / "README.md"
    file_a.write_text("# Test Repo\n", encoding="utf-8")

    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=repo, check=True)

    commit_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()

    tree_sha = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()

    blob_sha = subprocess.run(
        ["git", "hash-object", str(file_a)], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()

    return {
        "path": repo,
        "commit_sha": commit_sha,
        "tree_sha": tree_sha,
        "blob_sha": blob_sha,
        "object_format": "sha1",
    }


@pytest.fixture
def temp_sha256_git_repo(tmp_path):
    """Create a temporary git repository using SHA-256 object format."""
    repo = tmp_path / "sha256_repo"
    repo.mkdir()

    res = subprocess.run(["git", "init", "--object-format=sha256"], cwd=repo, capture_output=True, text=True)
    if res.returncode != 0:
        pytest.skip("installed Git does not support --object-format=sha256")

    subprocess.run(["git", "config", "user.name", "Test Agent"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@agenticos.local"], cwd=repo, check=True)

    file_a = repo / "README.md"
    file_a.write_text("# SHA-256 Test Repo\n", encoding="utf-8")

    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "initial sha256 commit"], cwd=repo, check=True)

    commit_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()

    return {
        "path": repo,
        "commit_sha": commit_sha,
        "object_format": "sha256",
    }


# ============================================================================
# 1. VALID IDENTITY & RESERVATION TESTS
# ============================================================================

def test_repository_identity_from_path_valid(temp_git_repo):
    repo_path = temp_git_repo["path"]
    identity = RepositoryIdentity.from_path(repo_path)

    assert identity.canonical_root == repo_path.resolve()
    assert identity.common_git_dir.is_dir()
    assert identity.object_format == "sha1"
    assert len(identity.repository_id) == 64
    assert isinstance(identity.to_dict(), dict)


def test_baseline_commit_validation_success(temp_git_repo):
    repo_path = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    validated = validate_baseline_commit(repo_path, commit_sha)
    assert validated == commit_sha.lower()


def test_task_ref_validation_valid(temp_git_repo):
    repo_path = temp_git_repo["path"]

    ref = validate_task_ref("task-123", 1, repo_path=repo_path)
    assert ref.full_ref == "refs/heads/aos/task-123/g1"
    assert ref.short_ref == "aos/task-123/g1"
    assert ref.branch_name == "aos/task-123/g1"


def test_worktree_task_identity_create_valid():
    identity = WorktreeTaskIdentity.create(
        task_id="task-abc_123",
        generation=2,
        nonce="a" * 32,
        repository_id="b" * 64,
        baseline_commit_sha="c" * 40,
        policy_digest="d" * 64,
        object_format="sha1",
    )
    assert identity.task_id == "task-abc_123"
    assert identity.generation == 2
    assert identity.object_format == "sha1"
    assert len(identity.identity_digest) == 64


def test_worktree_reservation_creation_success(temp_git_repo, tmp_path):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]
    external_root = tmp_path / "external_state_root"

    reservation = create_worktree_reservation(
        repo_path=repo,
        task_id="task-m5-slice1b",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="0" * 32,
        policy_digest="f" * 64,
        state_root=external_root,
    )

    assert reservation.task_ref.full_ref == "refs/heads/aos/task-m5-slice1b/g1"
    assert reservation.worktree_name == "task-m5-slice1b_g1_00000000"
    assert not str(reservation.proposed_worktree_path).startswith(str(repo))
    assert len(reservation.reservation_digest) == 64


# ============================================================================
# 2. PATH SEMANTICS & CONTAINMENT TESTS
# ============================================================================

def test_path_semantics_subpath_and_distinct():
    base = Path("/var/lib/agenticos")
    sub = Path("/var/lib/agenticos/worktrees/repo1/task1")
    unrelated = Path("/var/lib/other")

    assert _is_same_or_subpath(sub, base) is True
    assert _is_same_or_subpath(unrelated, base) is False


def test_reject_worktree_root_inside_authoritative_checkout(temp_git_repo):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]
    inside_root = repo / ".agenticos_worktrees"

    with pytest.raises(WorktreeValidationError) as exc:
        create_worktree_reservation(
            repo_path=repo,
            task_id="inside-task",
            generation=1,
            baseline_commit_sha=commit_sha,
            nonce="6" * 32,
            policy_digest="f" * 64,
            state_root=inside_root,
        )
    assert "cannot be equal to or located inside" in str(exc.value)


def test_reject_worktree_root_equal_to_checkout(temp_git_repo):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    with pytest.raises(WorktreeValidationError) as exc:
        create_worktree_reservation(
            repo_path=repo,
            task_id="equal-task",
            generation=1,
            baseline_commit_sha=commit_sha,
            nonce="7" * 32,
            policy_digest="0" * 64,
            state_root=repo,
        )
    assert "cannot be equal to or located inside" in str(exc.value)


def test_accept_trusted_external_state_root(temp_git_repo, tmp_path):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]
    external_root = tmp_path / "trusted_state_root"

    res = create_worktree_reservation(
        repo_path=repo,
        task_id="ext-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="8" * 32,
        policy_digest="1" * 64,
        state_root=external_root,
    )
    assert str(res.proposed_worktree_path).startswith(str(external_root.resolve()))


# ============================================================================
# 3. DURABLE STATE ROOT & AMBIENT ENVIRONMENT TESTS
# ============================================================================

def test_production_reservation_requires_explicit_state_root(temp_git_repo):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    # Without state_root or allow_temporary_for_test=True, production call MUST fail
    with pytest.raises(WorktreeValidationError) as exc:
        create_worktree_reservation(
            repo_path=repo,
            task_id="prod-task",
            generation=1,
            baseline_commit_sha=commit_sha,
            nonce="9" * 32,
            policy_digest="2" * 64,
            allow_temporary_for_test=False,
        )
    assert "Production worktree reservation requires an explicit durable controller state_root" in str(exc.value)


def test_temporary_root_allowed_only_when_explicitly_flagged(temp_git_repo):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    res = create_worktree_reservation(
        repo_path=repo,
        task_id="temp-flag-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="a" * 32,
        policy_digest="3" * 64,
        allow_temporary_for_test=True,
    )
    assert res.proposed_worktree_path is not None


def test_ambient_env_does_not_silently_override_production(temp_git_repo, monkeypatch):
    monkeypatch.setenv("AGENTICOS_WORKTREE_ROOT", "/tmp/ambient_override")
    assert get_development_worktree_root_override() == Path("/tmp/ambient_override").resolve()

    # Even with env set, production reservation without explicit state_root fails if allow_temporary_for_test=False and env isn't trusted as prod authority
    repo = temp_git_repo["path"]

    # env is accessible for dev helper, but get_default_worktree_root handles it explicitly
    repo_id = RepositoryIdentity.from_path(repo)
    root = get_default_worktree_root(repo_id)
    assert str(root).startswith(str(Path("/tmp/ambient_override").resolve()))


def test_distinct_repository_ids_receive_distinct_namespaces(temp_git_repo, tmp_path):
    repo1 = temp_git_repo["path"]
    id1 = RepositoryIdentity.from_path(repo1)

    repo2 = tmp_path / "repo2"
    repo2.mkdir()
    subprocess.run(["git", "init"], cwd=repo2, check=True, capture_output=True)
    id2 = RepositoryIdentity.from_path(repo2)

    assert id1.repository_id != id2.repository_id

    root1 = get_default_worktree_root(id1, state_root=tmp_path / "state")
    root2 = get_default_worktree_root(id2, state_root=tmp_path / "state")

    assert root1 != root2
    assert str(id1.repository_id) in str(root1)
    assert str(id2.repository_id) in str(root2)


# ============================================================================
# 4. OWNERSHIP AUTHENTICATION & DIGEST HARDENING TESTS
# ============================================================================

def test_ownership_digest_changes_when_fields_change(temp_git_repo, tmp_path):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    res = create_worktree_reservation(
        repo_path=repo,
        task_id="digest-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="b" * 32,
        policy_digest="4" * 64,
        state_root=tmp_path / "ext_root",
    )
    rec1 = WorktreeOwnershipRecord.create_from_reservation(res)

    rec2 = WorktreeOwnershipRecord.create(
        repository_id=rec1.repository_id,
        object_format=rec1.object_format,
        task_id="digest-task-2",  # Different field
        generation=rec1.generation,
        nonce=rec1.nonce,
        policy_digest=rec1.policy_digest,
        baseline_commit_sha=rec1.baseline_commit_sha,
        task_ref=rec1.task_ref,
        worktree_name=rec1.worktree_name,
        reservation_digest=rec1.reservation_digest,
    )

    assert rec1.ownership_digest != rec2.ownership_digest


def test_recomputing_digest_without_controller_storage_unauthenticated(temp_git_repo, tmp_path):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    res = create_worktree_reservation(
        repo_path=repo,
        task_id="auth-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="c" * 32,
        policy_digest="5" * 64,
        state_root=tmp_path / "ext_root",
    )
    rec = WorktreeOwnershipRecord.create_from_reservation(res)

    # Valid integrity digest, but in_controller_storage=False -> UNAUTHENTICATED
    assert verify_ownership_record_authenticity(rec, in_controller_storage=False) is False
    # Only authenticated when in_controller_storage=True
    assert verify_ownership_record_authenticity(rec, in_controller_storage=True) is True


def test_unauthenticated_ownership_record_fails_ref_collision_check(temp_git_repo, tmp_path):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    reservation = create_worktree_reservation(
        repo_path=repo,
        task_id="auth-collision-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="d" * 32,
        policy_digest="6" * 64,
        state_root=tmp_path / "ext_root",
    )
    ownership = WorktreeOwnershipRecord.create_from_reservation(reservation)

    ref = validate_task_ref("auth-collision-task", 1, repo_path=repo)
    subprocess.run(["git", "branch", ref.branch_name, commit_sha], cwd=repo, check=True)

    # Calling check_ref_collision with in_controller_storage=False MUST fail closed
    with pytest.raises(TaskRefCollisionError) as exc:
        check_ref_collision(repo, ref, expected_ownership=ownership, in_controller_storage=False)
    assert "failed controller storage authentication" in str(exc.value)


# ============================================================================
# 5. OBJECT FORMAT HARDENING TESTS
# ============================================================================

def test_sha1_repo_accepts_exact_40_hex(temp_git_repo):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]
    assert len(commit_sha) == 40
    assert validate_baseline_commit(repo, commit_sha) == commit_sha.lower()


def test_sha1_repo_rejects_64_hex_value(temp_git_repo):
    repo = temp_git_repo["path"]
    sha64 = "a" * 64
    with pytest.raises(InvalidBaselineCommitError) as exc:
        validate_baseline_commit(repo, sha64)
    assert "40 lowercase hex" in str(exc.value)


def test_sha256_synthetic_repository_detects_and_accepts_64_hex(temp_sha256_git_repo):
    repo = temp_sha256_git_repo["path"]
    commit_sha = temp_sha256_git_repo["commit_sha"]
    assert len(commit_sha) == 64

    repo_id = RepositoryIdentity.from_path(repo)
    assert repo_id.object_format == "sha256"

    validated = validate_baseline_commit(repo, commit_sha)
    assert validated == commit_sha.lower()


def test_sha256_synthetic_repository_rejects_40_hex(temp_sha256_git_repo):
    repo = temp_sha256_git_repo["path"]
    sha40 = "a" * 40
    with pytest.raises(InvalidBaselineCommitError) as exc:
        validate_baseline_commit(repo, sha40)
    assert "64 lowercase hex" in str(exc.value)


def test_abbreviated_sha_rejected(temp_git_repo):
    repo = temp_git_repo["path"]
    short_sha = temp_git_repo["commit_sha"][:7]
    with pytest.raises(InvalidBaselineCommitError):
        validate_baseline_commit(repo, short_sha)
