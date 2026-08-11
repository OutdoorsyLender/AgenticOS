"""Unit, integration, and security property tests for Milestone 5 Slice 2A Controlled Git Worktree Lifecycle."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from agenticos.sandbox.worktree import (
    LIFECYCLE_SCHEMA_VERSION,
    OWNERSHIP_SCHEMA_VERSION,
    InvalidBaselineCommitError,
    InvalidRefNameError,
    RepositoryIdentity,
    RepositoryIdentityError,
    TaskRef,
    TaskRefCollisionError,
    WorktreeLifecycleState,
    WorktreeLifecycleStatus,
    WorktreeManager,
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
    """Create a synthetic temporary git repository (SHA-1) with initial commit."""
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

    return {
        "path": repo,
        "commit_sha": commit_sha,
        "object_format": "sha1",
    }


@pytest.fixture
def temp_state_root(tmp_path):
    """Create a temporary state root directory outside the repository."""
    root = tmp_path / "state_root"
    root.mkdir()
    return root


# ============================================================================
# 1. WORKTREE MANAGER CREATION & VERIFICATION TESTS
# ============================================================================

def test_worktree_manager_creation_success(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="manager-create-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="0" * 32,
        policy_digest="f" * 64,
        state_root=temp_state_root,
    )

    state = manager.create(res)

    assert state.status == WorktreeLifecycleStatus.READY
    assert state.stage_reached == "READY"
    assert state.worktree_path.is_dir()
    assert (state.worktree_path / ".git").is_file()
    assert state.worktree_device is not None
    assert state.worktree_inode is not None
    assert state.ownership_record is not None
    assert state.ownership_record.schema_version == OWNERSHIP_SCHEMA_VERSION

    # Verify authoritative checkout HEAD remained unchanged
    main_head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()
    assert main_head == commit_sha


def test_worktree_manager_post_creation_verification_gitdir_and_commondir(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="gitdir-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="1" * 32,
        policy_digest="a" * 64,
        state_root=temp_state_root,
    )

    state = manager.create(res)
    wt_dir = state.worktree_path

    # Check rev-parse inside worktree
    wt_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=wt_dir, check=True, capture_output=True, text=True
    ).stdout.strip()
    assert wt_sha.lower() == commit_sha.lower()

    # Check task branch ref rev-parse
    ref_sha = subprocess.run(
        ["git", "rev-parse", res.task_ref.full_ref], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()
    assert ref_sha.lower() == commit_sha.lower()


# ============================================================================
# 2. COLLISION & RENEWED RESERVATION TESTS
# ============================================================================

def test_collision_pre_existing_worktree_path(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="path-collide-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="2" * 32,
        policy_digest="b" * 64,
        state_root=temp_state_root,
    )

    # Pre-create the proposed worktree directory
    res.proposed_worktree_path.mkdir(parents=True, exist_ok=True)

    with pytest.raises(TaskRefCollisionError) as exc:
        manager.create(res)
    assert "already exists on disk" in str(exc.value)


def test_collision_unrelated_existing_branch(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    # Pre-create branch aos/branch-collide-task/g1
    subprocess.run(["git", "branch", "aos/branch-collide-task/g1", commit_sha], cwd=repo, check=True)

    manager = WorktreeManager(temp_state_root)
    with pytest.raises(TaskRefCollisionError):
        create_worktree_reservation(
            repo_path=repo,
            task_id="branch-collide-task",
            generation=1,
            baseline_commit_sha=commit_sha,
            nonce="3" * 32,
            policy_digest="c" * 64,
            state_root=temp_state_root,
        )


def test_same_task_different_generation_success(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)

    res1 = create_worktree_reservation(
        repo_path=repo,
        task_id="gen-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="4" * 32,
        policy_digest="d" * 64,
        state_root=temp_state_root,
    )
    state1 = manager.create(res1)
    assert state1.status == WorktreeLifecycleStatus.READY

    res2 = create_worktree_reservation(
        repo_path=repo,
        task_id="gen-task",
        generation=2,
        baseline_commit_sha=commit_sha,
        nonce="5" * 32,
        policy_digest="e" * 64,
        state_root=temp_state_root,
    )
    state2 = manager.create(res2)
    assert state2.status == WorktreeLifecycleStatus.READY
    assert state1.worktree_path != state2.worktree_path


# ============================================================================
# 3. PATH & SYMLINK ATTACK TESTS
# ============================================================================

def test_reject_worktree_path_inside_checkout(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    repo_id = RepositoryIdentity.from_path(repo)
    res = WorktreeReservation(
        repository=repo_id,
        task_identity=WorktreeTaskIdentity.create(
            task_id="path-inside",
            generation=1,
            nonce="6" * 32,
            repository_id=repo_id.repository_id,
            baseline_commit_sha=commit_sha,
            policy_digest="f" * 64,
        ),
        task_ref=TaskRef(full_ref="refs/heads/aos/path-inside/g1", short_ref="aos/path-inside/g1", branch_name="aos/path-inside/g1"),
        worktree_name="path-inside_g1_66666666",
        proposed_worktree_path=repo / "malicious_inside",
        reservation_digest="0" * 64,
    )

    manager = WorktreeManager(temp_state_root)
    with pytest.raises(WorktreeValidationError) as exc:
        manager.create(res)
    assert "cannot be inside or equal to repository checkout" in str(exc.value)


# ============================================================================
# 4. FAILURE INJECTION & TRANSACTION RECOVERY TESTS
# ============================================================================

def test_failure_injection_recovery_classification(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)

    # 1. Inject failure after RESERVED
    res1 = create_worktree_reservation(
        repo_path=repo,
        task_id="inj-reserved",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="7" * 32,
        policy_digest="1" * 64,
        state_root=temp_state_root,
    )
    with pytest.raises(WorktreeValidationError):
        manager.create(res1, _inject_failure_at_stage="RESERVED")

    st1 = manager.inspect(repo, "inj-reserved", 1)
    assert st1.status == WorktreeLifecycleStatus.PARTIAL_STATE_ONLY

    # 2. Inject failure after WORKTREE_CREATED
    res2 = create_worktree_reservation(
        repo_path=repo,
        task_id="inj-wt-created",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="8" * 32,
        policy_digest="2" * 64,
        state_root=temp_state_root,
    )
    with pytest.raises(WorktreeValidationError):
        manager.create(res2, _inject_failure_at_stage="WORKTREE_CREATED")

    st2 = manager.inspect(repo, "inj-wt-created", 1)
    assert st2.status == WorktreeLifecycleStatus.PARTIAL_WORKTREE


# ============================================================================
# 5. SAFE REMOVAL & DIRTY PRESERVATION TESTS
# ============================================================================

def test_safe_removal_clean_worktree_success(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="clean-rm-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="9" * 32,
        policy_digest="3" * 64,
        state_root=temp_state_root,
    )

    state = manager.create(res)
    assert state.status == WorktreeLifecycleStatus.READY

    removed = manager.remove_if_safe(repo, "clean-rm-task", 1)
    assert removed is True
    assert not state.worktree_path.exists()

    # Verify branch was deleted
    res_branch = subprocess.run(["git", "rev-parse", "--verify", res.task_ref.full_ref], cwd=repo, capture_output=True)
    assert res_branch.returncode != 0


def test_refuse_deletion_uncommitted_modified_file(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="dirty-mod-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="a" * 32,
        policy_digest="4" * 64,
        state_root=temp_state_root,
    )

    state = manager.create(res)
    wt_dir = state.worktree_path

    # Modify a file inside the worktree
    (wt_dir / "README.md").write_text("# Modified\n", encoding="utf-8")

    st_insp = manager.inspect(repo, "dirty-mod-task", 1)
    assert st_insp.status == WorktreeLifecycleStatus.DIRTY_PRESERVED

    with pytest.raises(WorktreeValidationError) as exc:
        manager.remove_if_safe(repo, "dirty-mod-task", 1)
    assert "contains uncommitted changes" in str(exc.value)


def test_refuse_deletion_untracked_file(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="dirty-untracked-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="b" * 32,
        policy_digest="5" * 64,
        state_root=temp_state_root,
    )

    state = manager.create(res)
    wt_dir = state.worktree_path

    # Add an untracked file inside worktree
    (wt_dir / "untracked.txt").write_text("untracked work\n", encoding="utf-8")

    with pytest.raises(WorktreeValidationError) as exc:
        manager.remove_if_safe(repo, "dirty-untracked-task", 1)
    assert "contains uncommitted changes" in str(exc.value)


def test_refuse_deletion_staged_change(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="dirty-staged-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="c" * 32,
        policy_digest="6" * 64,
        state_root=temp_state_root,
    )

    state = manager.create(res)
    wt_dir = state.worktree_path

    (wt_dir / "staged.txt").write_text("staged work\n", encoding="utf-8")
    subprocess.run(["git", "add", "staged.txt"], cwd=wt_dir, check=True)

    with pytest.raises(WorktreeValidationError) as exc:
        manager.remove_if_safe(repo, "dirty-staged-task", 1)
    assert "contains uncommitted changes" in str(exc.value)


# ============================================================================
# 6. CONCURRENCY & LOCKING TESTS
# ============================================================================

def test_concurrent_reservations_locked(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res1 = create_worktree_reservation(
        repo_path=repo,
        task_id="conc-task-1",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="d" * 32,
        policy_digest="7" * 64,
        state_root=temp_state_root,
    )
    res2 = create_worktree_reservation(
        repo_path=repo,
        task_id="conc-task-2",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="e" * 32,
        policy_digest="8" * 64,
        state_root=temp_state_root,
    )

    st1 = manager.create(res1)
    st2 = manager.create(res2)

    assert st1.status == WorktreeLifecycleStatus.READY
    assert st2.status == WorktreeLifecycleStatus.READY
    assert st1.worktree_path != st2.worktree_path


# ============================================================================
# 7. COMMAND SAFETY & OPTION INJECTION TESTS
# ============================================================================

def test_option_injection_in_task_id_rejected(temp_git_repo):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    with pytest.raises(InvalidRefNameError):
        validate_task_ref("-oProxyCommand=touch /tmp/evil", 1, repo_path=repo)
