"""Unit and security property tests for Milestone 5 Slice 1A Controlled Git Worktree Identity Hardening."""

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
    check_ref_collision,
    create_worktree_reservation,
    get_default_worktree_root,
    validate_baseline_commit,
    validate_task_ref,
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
        task_id="task-m5-slice1a",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="0" * 32,
        policy_digest="f" * 64,
        worktree_root=external_root,
    )

    assert reservation.task_ref.full_ref == "refs/heads/aos/task-m5-slice1a/g1"
    assert reservation.worktree_name == "task-m5-slice1a_g1_00000000"
    assert not str(reservation.proposed_worktree_path).startswith(str(repo))
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


# ============================================================================
# 3. OBJECT FORMAT HARDENING TESTS
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


def test_malformed_sha_rejected(temp_git_repo):
    repo = temp_git_repo["path"]
    malformed = "g" + temp_git_repo["commit_sha"][1:]
    with pytest.raises(InvalidBaselineCommitError):
        validate_baseline_commit(repo, malformed)


# ============================================================================
# 4. OWNERSHIP HARDENING & REF COLLISION TESTS
# ============================================================================

def test_unrelated_existing_ref_same_baseline_rejected_without_ownership(temp_git_repo, tmp_path):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    ref = validate_task_ref("collision-task-1a", 1, repo_path=repo)
    subprocess.run(["git", "branch", ref.branch_name, commit_sha], cwd=repo, check=True)

    # Ref exists at baseline commit SHA, but NO ownership record provided -> FAIL CLOSED
    with pytest.raises(TaskRefCollisionError) as exc:
        check_ref_collision(repo, ref, expected_ownership=None)
    assert "no verified ownership record" in str(exc.value)


def test_unrelated_existing_ref_different_baseline_rejected(temp_git_repo, tmp_path):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    reservation = create_worktree_reservation(
        repo_path=repo,
        task_id="collision-task-1b",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="1" * 32,
        policy_digest="a" * 64,
        worktree_root=tmp_path / "ext_root",
    )
    ownership = WorktreeOwnershipRecord.create_from_reservation(reservation)

    ref = validate_task_ref("collision-task-1b", 1, repo_path=repo)
    subprocess.run(["git", "branch", ref.branch_name, commit_sha], cwd=repo, check=True)

    # Modify ownership record baseline to a different SHA
    diff_ownership = WorktreeOwnershipRecord.create(
        repository_id=ownership.repository_id,
        object_format=ownership.object_format,
        task_id=ownership.task_id,
        generation=ownership.generation,
        nonce=ownership.nonce,
        policy_digest=ownership.policy_digest,
        baseline_commit_sha="f" * 40,
        task_ref=ownership.task_ref,
        worktree_name=ownership.worktree_name,
        reservation_digest=ownership.reservation_digest,
    )

    with pytest.raises(TaskRefCollisionError) as exc:
        check_ref_collision(repo, ref, expected_ownership=diff_ownership)
    assert "does not match ownership record baseline" in str(exc.value)


def test_same_task_id_different_generation_rejected(temp_git_repo, tmp_path):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    res2 = create_worktree_reservation(
        repo_path=repo,
        task_id="gen-task",
        generation=2,
        baseline_commit_sha=commit_sha,
        nonce="2" * 32,
        policy_digest="b" * 64,
        worktree_root=tmp_path / "ext_root",
    )
    ownership2 = WorktreeOwnershipRecord.create_from_reservation(res2)

    # Ref for gen 1 exists
    ref1 = validate_task_ref("gen-task", 1, repo_path=repo)
    subprocess.run(["git", "branch", ref1.branch_name, commit_sha], cwd=repo, check=True)

    # Checking ref1 against ownership2 (different gen / ref) -> FAIL CLOSED
    with pytest.raises(TaskRefCollisionError):
        check_ref_collision(repo, ref1, expected_ownership=ownership2)


def test_exact_matching_reservation_ownership_succeeds(temp_git_repo, tmp_path):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    reservation = create_worktree_reservation(
        repo_path=repo,
        task_id="matching-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="3" * 32,
        policy_digest="c" * 64,
        worktree_root=tmp_path / "ext_root",
    )
    ownership = WorktreeOwnershipRecord.create_from_reservation(reservation)

    ref = validate_task_ref("matching-task", 1, repo_path=repo)
    subprocess.run(["git", "branch", ref.branch_name, commit_sha], cwd=repo, check=True)

    exists, observed_sha = check_ref_collision(repo, ref, expected_ownership=ownership)
    assert exists is True
    assert observed_sha == commit_sha.lower()


def test_ownership_record_serialization_roundtrip(temp_git_repo, tmp_path):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    reservation = create_worktree_reservation(
        repo_path=repo,
        task_id="serde-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="4" * 32,
        policy_digest="d" * 64,
        worktree_root=tmp_path / "ext_root",
    )
    ownership = WorktreeOwnershipRecord.create_from_reservation(reservation)

    json_str = ownership.to_json()
    reconstructed = WorktreeOwnershipRecord.from_json(json_str)

    assert reconstructed == ownership
    assert reconstructed.ownership_digest == ownership.ownership_digest


def test_malformed_ownership_record_rejected():
    with pytest.raises(WorktreeValidationError):
        WorktreeOwnershipRecord.from_json("{invalid_json: true")

    with pytest.raises(WorktreeValidationError):
        WorktreeOwnershipRecord.from_dict({"schema_version": "AOSWORKTREE/1"})


def test_unknown_ownership_schema_version_rejected(temp_git_repo, tmp_path):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    res = create_worktree_reservation(
        repo_path=repo,
        task_id="schema-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="5" * 32,
        policy_digest="e" * 64,
        worktree_root=tmp_path / "ext_root",
    )
    with pytest.raises(WorktreeValidationError):
        WorktreeOwnershipRecord.create(
            repository_id=res.repository.repository_id,
            object_format=res.repository.object_format,
            task_id=res.task_identity.task_id,
            generation=res.task_identity.generation,
            nonce=res.task_identity.nonce,
            policy_digest=res.task_identity.policy_digest,
            baseline_commit_sha=res.task_identity.baseline_commit_sha,
            task_ref=res.task_ref.full_ref,
            worktree_name=res.worktree_name,
            reservation_digest=res.reservation_digest,
            schema_version="AOSWORKTREE/999",
        )


# ============================================================================
# 5. WORKTREE ROOT LOCATION HARDENING TESTS
# ============================================================================

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
            worktree_root=inside_root,
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
            worktree_root=repo,
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
        worktree_root=external_root,
    )
    assert str(res.proposed_worktree_path).startswith(str(external_root.resolve()))


def test_distinct_repository_ids_receive_distinct_namespaces(temp_git_repo, tmp_path):
    repo1 = temp_git_repo["path"]
    id1 = RepositoryIdentity.from_path(repo1)

    repo2 = tmp_path / "repo2"
    repo2.mkdir()
    subprocess.run(["git", "init"], cwd=repo2, check=True, capture_output=True)
    id2 = RepositoryIdentity.from_path(repo2)

    assert id1.repository_id != id2.repository_id

    root1 = get_default_worktree_root(id1, custom_root=tmp_path / "state")
    root2 = get_default_worktree_root(id2, custom_root=tmp_path / "state")

    assert root1 != root2
    assert str(id1.repository_id) in str(root1)
    assert str(id2.repository_id) in str(root2)
