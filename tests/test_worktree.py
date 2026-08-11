"""Unit, integration, and security property tests for Milestone 5 Slice 2A.1 Controlled Git Worktree Preservation & Authority Closure."""

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
    subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=repo, check=True)
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
# 1. COMMITTED WORK PRESERVED TESTS (CLEAN WORKTREE != DISPOSABLE TASK)
# ============================================================================

def test_clean_tree_at_baseline_is_disposable(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="clean-baseline-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="0" * 32,
        policy_digest="f" * 64,
        state_root=temp_state_root,
    )
    manager.create(res)

    st = manager.inspect(repo, "clean-baseline-task", 1)
    assert st.status == WorktreeLifecycleStatus.CLEAN_BASELINE_DISPOSABLE


def test_clean_tree_with_one_task_commit_preserved(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="one-commit-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="1" * 32,
        policy_digest="a" * 64,
        state_root=temp_state_root,
    )
    state = manager.create(res)
    wt_dir = state.worktree_path

    # Model commits valuable work inside the worktree
    (wt_dir / "new_feature.py").write_text("print('valuable feature')\n", encoding="utf-8")
    subprocess.run(["git", "add", "new_feature.py"], cwd=wt_dir, check=True)
    subprocess.run(["git", "commit", "-m", "add feature"], cwd=wt_dir, check=True)

    # Working tree is clean!
    res_st = subprocess.run(["git", "status", "--porcelain"], cwd=wt_dir, capture_output=True, text=True)
    assert res_st.stdout.strip() == ""

    # BUT task branch has commits beyond baseline -> COMMITTED_WORK_PRESERVED!
    st_insp = manager.inspect(repo, "one-commit-task", 1)
    assert st_insp.status == WorktreeLifecycleStatus.COMMITTED_WORK_PRESERVED

    # Deletion MUST be refused!
    with pytest.raises(WorktreeValidationError) as exc:
        manager.remove_if_safe(repo, "one-commit-task", 1)
    assert "contains committed work beyond baseline" in str(exc.value)

    # Task branch survives in repository!
    res_branch = subprocess.run(["git", "rev-parse", "--verify", res.task_ref.full_ref], cwd=repo, capture_output=True)
    assert res_branch.returncode == 0


def test_clean_tree_with_multiple_task_commits_preserved(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="multi-commit-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="2" * 32,
        policy_digest="b" * 64,
        state_root=temp_state_root,
    )
    state = manager.create(res)
    wt_dir = state.worktree_path

    # Commit 1
    (wt_dir / "f1.py").write_text("v1\n", encoding="utf-8")
    subprocess.run(["git", "add", "f1.py"], cwd=wt_dir, check=True)
    subprocess.run(["git", "commit", "-m", "commit 1"], cwd=wt_dir, check=True)

    # Commit 2
    (wt_dir / "f2.py").write_text("v2\n", encoding="utf-8")
    subprocess.run(["git", "add", "f2.py"], cwd=wt_dir, check=True)
    subprocess.run(["git", "commit", "-m", "commit 2"], cwd=wt_dir, check=True)

    st_insp = manager.inspect(repo, "multi-commit-task", 1)
    assert st_insp.status == WorktreeLifecycleStatus.COMMITTED_WORK_PRESERVED

    with pytest.raises(WorktreeValidationError):
        manager.remove_if_safe(repo, "multi-commit-task", 1)


# ============================================================================
# 2. REF RACE PROTECTION TESTS
# ============================================================================

def test_ref_race_deletion_prevents_destroying_changed_ref(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="ref-race-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="3" * 32,
        policy_digest="c" * 64,
        state_root=temp_state_root,
    )
    manager.create(res)

    # Race condition: Task branch is updated externally to point to a new commit SHA right before deletion
    dummy_file = repo / "dummy.txt"
    dummy_file.write_text("dummy\n")
    subprocess.run(["git", "add", "dummy.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "external commit"], cwd=repo, check=True)
    new_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()

    # Update ref_name to new_sha directly in git
    subprocess.run(["git", "update-ref", res.task_ref.full_ref, new_sha], cwd=repo, check=True)

    # Attempting deletion MUST fail because ref moved!
    with pytest.raises(WorktreeValidationError):
        manager.remove_if_safe(repo, "ref-race-task", 1)

    # Verify ref survives intact at new_sha
    ref_curr = subprocess.run(["git", "rev-parse", res.task_ref.full_ref], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
    assert ref_curr == new_sha


# ============================================================================
# 3. FILESYSTEM DESCRIPTOR & SYMLINK ADVERSARIAL TESTS
# ============================================================================

def test_symlink_worktree_path_rejected(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="sym-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="4" * 32,
        policy_digest="d" * 64,
        state_root=temp_state_root,
    )

    # Pre-create proposed worktree path as a symlink
    target_dir = temp_state_root / "sym_target"
    target_dir.mkdir()
    try:
        res.proposed_worktree_path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target_dir, res.proposed_worktree_path)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform/user privilege")

    with pytest.raises(TaskRefCollisionError) as exc:
        manager.create(res)
    assert "symlink" in str(exc.value).lower() or "already exists" in str(exc.value).lower()


def test_worktree_inode_changed_refuses_deletion(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="inode-change-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="5" * 32,
        policy_digest="e" * 64,
        state_root=temp_state_root,
    )

    state = manager.create(res)

    # Tamper with recorded inode in state to simulate swap race
    state.worktree_inode = (state.worktree_inode or 0) + 999999
    task_dir = temp_state_root / "worktrees" / state.repository_id / "inode-change-task" / "g1"
    manager._atomic_write_json(task_dir / "lifecycle.json", state.to_dict())

    with pytest.raises(WorktreeValidationError) as exc:
        manager.remove_if_safe(repo, "inode-change-task", 1)
    assert "identity changed" in str(exc.value) or "NOT DISPOSABLE" in str(exc.value)


# ============================================================================
# 4. OWNERSHIP RECORD AUTHENTICATION & TRUSTED API TESTS
# ============================================================================

def test_forged_ownership_record_untrusted_by_default(temp_git_repo):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    repo_id = RepositoryIdentity.from_path(repo)
    res = WorktreeReservation(
        repository=repo_id,
        task_identity=WorktreeTaskIdentity.create(
            task_id="forged-task",
            generation=1,
            nonce="6" * 32,
            repository_id=repo_id.repository_id,
            baseline_commit_sha=commit_sha,
            policy_digest="f" * 64,
        ),
        task_ref=TaskRef(full_ref="refs/heads/aos/forged-task/g1", short_ref="aos/forged-task/g1", branch_name="aos/forged-task/g1"),
        worktree_name="forged-task_g1_66666666",
        proposed_worktree_path=Path("/tmp/forged"),
        reservation_digest="0" * 64,
    )

    # Ownership record created outside WorktreeManager has is_trusted=False
    parsed_record = WorktreeOwnershipRecord.create_from_reservation(res)
    assert parsed_record.is_trusted is False
    assert verify_ownership_record_authenticity(parsed_record) is False


def test_manager_loaded_ownership_record_is_trusted(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="trusted-load-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="7" * 32,
        policy_digest="0" * 64,
        state_root=temp_state_root,
    )
    state = manager.create(res)

    assert state.ownership_record is not None
    assert state.ownership_record.is_trusted is True
    assert verify_ownership_record_authenticity(state.ownership_record) is True


# ============================================================================
# 5. SAFE CLEAN DISPOSAL TESTS
# ============================================================================

def test_safe_clean_disposal(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)

    # Create unrelated task
    res_unrelated = create_worktree_reservation(
        repo_path=repo,
        task_id="unrelated-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="8" * 32,
        policy_digest="1" * 64,
        state_root=temp_state_root,
    )
    st_unrelated = manager.create(res_unrelated)

    # Create disposable target task
    res_target = create_worktree_reservation(
        repo_path=repo,
        task_id="disposable-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="9" * 32,
        policy_digest="2" * 64,
        state_root=temp_state_root,
    )
    st_target = manager.create(res_target)

    # Remove target task
    removed = manager.remove_if_safe(repo, "disposable-task", 1)
    assert removed is True
    assert not st_target.worktree_path.exists()

    # Unrelated task, branch, worktree, and main repo HEAD survive intact!
    assert st_unrelated.worktree_path.is_dir()
    res_unrelated_branch = subprocess.run(["git", "rev-parse", res_unrelated.task_ref.full_ref], cwd=repo, capture_output=True)
    assert res_unrelated_branch.returncode == 0

    main_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()
    assert main_head == commit_sha
