"""Unit and security property tests for Milestone 5 Slice 1 Controlled Git Worktree Identity."""

import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from agenticos.sandbox.worktree import (
    InvalidBaselineCommitError,
    InvalidRefNameError,
    RepositoryIdentity,
    RepositoryIdentityError,
    TaskRef,
    TaskRefCollisionError,
    WorktreeReservation,
    WorktreeTaskIdentity,
    WorktreeValidationError,
    check_ref_collision,
    create_worktree_reservation,
    validate_baseline_commit,
    validate_task_ref,
)


@pytest.fixture
def temp_git_repo(tmp_path):
    """Create a temporary git repository with initial commit, tree, and blob."""
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

    # Get tree sha
    tree_sha = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()

    # Get blob sha
    blob_sha = subprocess.run(
        ["git", "hash-object", str(file_a)], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()

    return {
        "path": repo,
        "commit_sha": commit_sha,
        "tree_sha": tree_sha,
        "blob_sha": blob_sha,
    }


# ============================================================================
# 1. VALID IDENTITY & RESERVATION TESTS
# ============================================================================

def test_repository_identity_from_path_valid(temp_git_repo):
    repo_path = temp_git_repo["path"]
    identity = RepositoryIdentity.from_path(repo_path)

    assert identity.canonical_root == repo_path.resolve()
    assert identity.common_git_dir.is_dir()
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
    )
    assert identity.task_id == "task-abc_123"
    assert identity.generation == 2
    assert len(identity.identity_digest) == 64


def test_distinct_generations_produce_distinct_identities():
    id1 = WorktreeTaskIdentity.create(
        task_id="task-1",
        generation=1,
        nonce="a" * 32,
        repository_id="b" * 64,
        baseline_commit_sha="c" * 40,
        policy_digest="d" * 64,
    )
    id2 = WorktreeTaskIdentity.create(
        task_id="task-1",
        generation=2,
        nonce="a" * 32,
        repository_id="b" * 64,
        baseline_commit_sha="c" * 40,
        policy_digest="d" * 64,
    )
    assert id1.identity_digest != id2.identity_digest


def test_distinct_tasks_produce_distinct_refs():
    ref1 = validate_task_ref("task-1", 1)
    ref2 = validate_task_ref("task-2", 1)
    assert ref1.full_ref != ref2.full_ref


def test_same_identity_produces_same_digest():
    id1 = WorktreeTaskIdentity.create(
        task_id="task-1",
        generation=1,
        nonce="a" * 32,
        repository_id="b" * 64,
        baseline_commit_sha="c" * 40,
        policy_digest="d" * 64,
    )
    id2 = WorktreeTaskIdentity.create(
        task_id="task-1",
        generation=1,
        nonce="a" * 32,
        repository_id="b" * 64,
        baseline_commit_sha="c" * 40,
        policy_digest="d" * 64,
    )
    assert id1.identity_digest == id2.identity_digest


def test_worktree_reservation_creation_success(temp_git_repo):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    reservation = create_worktree_reservation(
        repo_path=repo,
        task_id="task-m5-slice1",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="0" * 32,
        policy_digest="f" * 64,
    )

    assert reservation.task_ref.full_ref == "refs/heads/aos/task-m5-slice1/g1"
    assert reservation.worktree_name == "task-m5-slice1_g1_00000000"
    assert len(reservation.reservation_digest) == 64


# ============================================================================
# 2. INVALID / HOSTILE TASK ID & REF INPUTS
# ============================================================================

@pytest.mark.parametrize(
    "invalid_task_id",
    [
        "",
        "..",
        ".",
        "/",
        "//",
        "/task",
        "task/",
        "task\\1",
        "task@{1}",
        "task.lock",
        "task.lock/bar",
        "task\x001",
        "task\x011",
        "task\x1f1",
        "task\x7f1",
        "task\n1",
        "task\r1",
        "task\t1",
        "task 1",
        "task:1",
        "task~1",
        "task^1",
        "task?1",
        "task*1",
        "task[1]",
        "-task",
        "--exec",
        "tаsk",  # Cyrillic 'а' homoglyph
        "../../../etc/passwd",
        "refs/heads/main",
        "task; rm -rf /",
        "task $(whoami)",
        "a" * 65,  # Exceeds 64 chars
    ],
)
def test_invalid_task_ids_rejected(invalid_task_id):
    with pytest.raises(InvalidRefNameError):
        validate_task_ref(invalid_task_id, 1)


@pytest.mark.parametrize("invalid_generation", [-1, -100, 18446744073709551616])
def test_invalid_generations_rejected(invalid_generation):
    with pytest.raises(InvalidRefNameError):
        validate_task_ref("task-1", invalid_generation)


# ============================================================================
# 3. BASELINE COMMIT VALIDATION TESTS
# ============================================================================

def test_baseline_nonexistent_sha_rejected(temp_git_repo):
    repo = temp_git_repo["path"]
    fake_sha = "0" * 40
    with pytest.raises(InvalidBaselineCommitError):
        validate_baseline_commit(repo, fake_sha)


def test_baseline_blob_object_rejected(temp_git_repo):
    repo = temp_git_repo["path"]
    blob_sha = temp_git_repo["blob_sha"]
    with pytest.raises(InvalidBaselineCommitError) as exc_info:
        validate_baseline_commit(repo, blob_sha)
    assert "blob" in str(exc_info.value)


def test_baseline_tree_object_rejected(temp_git_repo):
    repo = temp_git_repo["path"]
    tree_sha = temp_git_repo["tree_sha"]
    with pytest.raises(InvalidBaselineCommitError) as exc_info:
        validate_baseline_commit(repo, tree_sha)
    assert "tree" in str(exc_info.value)


@pytest.mark.parametrize(
    "invalid_sha",
    [
        "e468269",                             # Short SHA
        "main",                                # Branch name
        "HEAD",                                # HEAD ref
        "g468269965866407614c3d5e98e15167176c56de", # Non-hex char 'g'
        "a" * 39,                              # 39 chars
        "a" * 41,                              # 41 chars
    ],
)
def test_baseline_invalid_sha_syntax_rejected(temp_git_repo, invalid_sha):
    repo = temp_git_repo["path"]
    with pytest.raises(InvalidBaselineCommitError):
        validate_baseline_commit(repo, invalid_sha)


# ============================================================================
# 4. COLLISION VALIDATION TESTS
# ============================================================================

def test_ref_collision_without_expected_identity_fails_closed(temp_git_repo):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    # Create a ref manually
    ref = validate_task_ref("collision-task", 1, repo_path=repo)
    subprocess.run(["git", "branch", ref.branch_name, commit_sha], cwd=repo, check=True)

    with pytest.raises(TaskRefCollisionError):
        check_ref_collision(repo, ref, expected_identity=None)


def test_ref_collision_with_different_baseline_sha_fails_closed(temp_git_repo):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    ref = validate_task_ref("collision-task-2", 1, repo_path=repo)
    subprocess.run(["git", "branch", ref.branch_name, commit_sha], cwd=repo, check=True)

    different_identity = WorktreeTaskIdentity.create(
        task_id="collision-task-2",
        generation=1,
        nonce="1" * 32,
        repository_id="a" * 64,
        baseline_commit_sha="f" * 40,
        policy_digest="b" * 64,
    )

    with pytest.raises(TaskRefCollisionError):
        check_ref_collision(repo, ref, expected_identity=different_identity)


def test_ref_collision_with_matching_baseline_sha_succeeds(temp_git_repo):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    ref = validate_task_ref("collision-task-3", 1, repo_path=repo)
    subprocess.run(["git", "branch", ref.branch_name, commit_sha], cwd=repo, check=True)

    matching_identity = WorktreeTaskIdentity.create(
        task_id="collision-task-3",
        generation=1,
        nonce="1" * 32,
        repository_id="a" * 64,
        baseline_commit_sha=commit_sha,
        policy_digest="b" * 64,
    )

    exists, observed_sha = check_ref_collision(repo, ref, expected_identity=matching_identity)
    assert exists is True
    assert observed_sha == commit_sha.lower()


# ============================================================================
# 5. REPOSITORY IDENTITY ERROR TESTS
# ============================================================================

def test_repository_identity_nonexistent_path_fails():
    with pytest.raises(RepositoryIdentityError):
        RepositoryIdentity.from_path(Path("/nonexistent/path/for/repo"))


def test_repository_identity_non_git_dir_fails(tmp_path):
    non_git = tmp_path / "not_git"
    non_git.mkdir()
    with pytest.raises(RepositoryIdentityError):
        RepositoryIdentity.from_path(non_git)
