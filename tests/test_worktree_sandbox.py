"""Unit, integration, and security property tests for Milestone 5 Slice 3A Gitless Worktree Sandbox Integration."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from agenticos.sandbox.models import ProcessResult
from agenticos.sandbox.runtime_boundary import (
    AuthorizedMount,
    AuthorizedSource,
    FileIdentity,
    M4AProfile,
    MountRole,
    RuntimeBoundaryPlan,
    build_bwrap_argv,
    build_runtime_plan,
    _validate_extra_worker_env,
    FORBIDDEN_GIT_ENV_NAMES,
)
from agenticos.sandbox.worktree import (
    LIFECYCLE_SCHEMA_VERSION,
    OWNERSHIP_SCHEMA_VERSION,
    InvalidBaselineCommitError,
    InvalidRefNameError,
    RepositoryIdentity,
    TaskRef,
    TaskRefCollisionError,
    TaskWorktreeResult,
    WorktreeLifecycleState,
    WorktreeLifecycleStatus,
    WorktreeManager,
    WorktreeOwnershipRecord,
    WorktreeReservation,
    WorktreeTaskIdentity,
    WorktreeValidationError,
    create_worktree_reservation,
    verify_ownership_record_authenticity,
)

sys.path.insert(0, str(Path(__file__).resolve().parent / "conformance"))
try:
    from helpers import WORKER_PATH
except ImportError:
    WORKER_PATH = Path(__file__).resolve().parent / "fixtures" / "hostile_worker.py"


@pytest.fixture(scope="session")
def m4a_launcher(tmp_path_factory):
    if not sys.platform.startswith("linux"):
        pytest.skip("requires Linux")
    output = tmp_path_factory.mktemp("m4a-launcher") / "fs_launcher"
    source = WORKER_PATH.parents[2] / "native" / "fs_launcher" / "fs_launcher.c"
    subprocess.run(
        [
            "cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
            "-Werror", "-O2", str(source), "-o", str(output),
        ],
        check=True,
    )
    return output


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
    file_b = repo / "main.py"
    file_b.write_text("print('hello world')\n", encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=repo, check=True)
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
# 1. RUNTIME BOUNDARY & GIT MASK UNIT TESTS
# ============================================================================

def test_git_mask_in_mount_role_and_runtime_plan():
    assert MountRole.GIT_MASK.value == "git_mask"

    dummy_id = FileIdentity(device=1, inode=2, file_type=0o40000)
    dummy_file_id = FileIdentity(device=1, inode=3, file_type=0o100000)

    workspace_src = AuthorizedSource(Path("/workspace"), 10, dummy_id)
    usr_src = AuthorizedSource(Path("/usr"), 11, dummy_id)
    launcher_src = AuthorizedSource(Path("/launcher"), 12, dummy_file_id)
    worker_src = AuthorizedSource(Path("/worker"), 13, dummy_file_id)
    tmp_src = AuthorizedSource(Path("/tmp"), 14, dummy_id)
    home_src = AuthorizedSource(Path("/home"), 15, dummy_id)
    git_mask_src = AuthorizedSource(Path("/state/git_mask"), 16, dummy_file_id)

    plan = build_runtime_plan(
        profile=M4AProfile.BUILD,
        workspace=workspace_src,
        runtime_usr=usr_src,
        launcher=launcher_src,
        worker=worker_src,
        task_tmp=tmp_src,
        synthetic_home=home_src,
        git_mask=git_mask_src,
    )

    mask_mount = plan.mount_for("/workspace/.git")
    assert mask_mount.role == MountRole.GIT_MASK
    assert mask_mount.bind_option == "--ro-bind-fd"
    assert mask_mount.landlock_mode == "r"


def test_forbidden_git_environment_variables_rejected():
    for var_name in FORBIDDEN_GIT_ENV_NAMES:
        with pytest.raises(ValueError) as exc:
            _validate_extra_worker_env(((var_name, "/tmp/host_git"),))
        assert "forbids Git authority environment variable" in str(exc.value)

    with pytest.raises(ValueError):
        _validate_extra_worker_env((("GIT_DIR", "/host/git"),))
    with pytest.raises(ValueError):
        _validate_extra_worker_env((("GIT_WORK_TREE", "/workspace"),))
    with pytest.raises(ValueError):
        _validate_extra_worker_env((("GIT_COMMON_DIR", "/host/common"),))


def test_bwrap_argv_includes_git_mask_mount():
    dummy_id = FileIdentity(device=1, inode=2, file_type=0o40000)
    dummy_file_id = FileIdentity(device=1, inode=3, file_type=0o100000)

    workspace_src = AuthorizedSource(Path("/workspace"), 10, dummy_id)
    usr_src = AuthorizedSource(Path("/usr"), 11, dummy_id)
    launcher_src = AuthorizedSource(Path("/launcher"), 12, dummy_file_id)
    worker_src = AuthorizedSource(Path("/worker"), 13, dummy_file_id)
    tmp_src = AuthorizedSource(Path("/tmp"), 14, dummy_id)
    home_src = AuthorizedSource(Path("/home"), 15, dummy_id)
    git_mask_src = AuthorizedSource(Path("/state/git_mask"), 16, dummy_file_id)

    plan = build_runtime_plan(
        profile=M4AProfile.BUILD,
        workspace=workspace_src,
        runtime_usr=usr_src,
        launcher=launcher_src,
        worker=worker_src,
        task_tmp=tmp_src,
        synthetic_home=home_src,
        git_mask=git_mask_src,
    )

    argv = build_bwrap_argv(
        plan,
        namespace_gate_fd=5,
        json_status_fd=6,
        launcher_status_fd=7,
        executable=Path("/usr/bin/bwrap"),
    )

    # Verify order: /workspace is bound first, then /workspace/.git is ro-bound over it
    ws_idx = argv.index("/workspace")
    git_idx = argv.index("/workspace/.git")
    assert ws_idx < git_idx
    assert argv[git_idx - 2] == "--ro-bind-fd"
    assert argv[git_idx - 1] == "16"


# ============================================================================
# 2. WORKTREE MANAGER SANDBOX VERIFICATION & RESULT CAPTURE TESTS
# ============================================================================

def test_verify_worktree_for_sandbox_and_ensure_git_mask(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="sandbox-prep-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="0" * 32,
        policy_digest="a" * 64,
        state_root=temp_state_root,
    )
    manager.create(res)

    worktree_dir, mask_file, state = manager.verify_worktree_for_sandbox(repo, "sandbox-prep-task", 1)
    assert worktree_dir.is_dir()
    assert mask_file.is_file()
    assert mask_file.parent.name == "g1"
    assert "# AgenticOS Git metadata masked for sandbox" in mask_file.read_text(encoding="utf-8")


def test_result_capture_clean_baseline_worktree(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="clean-result-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="1" * 32,
        policy_digest="b" * 64,
        state_root=temp_state_root,
    )
    manager.create(res)

    res_obj = manager.capture_result(repo, "clean-result-task", 1, worker_exit_code=0)
    assert res_obj.is_clean is True
    assert res_obj.preservation_classification == WorktreeLifecycleStatus.CLEAN_BASELINE_DISPOSABLE.value
    assert len(res_obj.modified_paths) == 0
    assert len(res_obj.added_untracked_paths) == 0
    assert len(res_obj.deleted_paths) == 0
    assert res_obj.is_diff_truncated is False


def test_result_capture_source_edits(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="source-edits-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="2" * 32,
        policy_digest="c" * 64,
        state_root=temp_state_root,
    )
    state = manager.create(res)
    wt_dir = state.worktree_path

    # Perform edits: modify README.md, add new_script.py, delete main.py
    (wt_dir / "README.md").write_text("# Updated Title\nNew line\n", encoding="utf-8")
    (wt_dir / "new_script.py").write_text("print('new script')\n", encoding="utf-8")
    (wt_dir / "main.py").unlink()

    res_obj = manager.capture_result(repo, "source-edits-task", 1, worker_exit_code=0)

    assert res_obj.is_clean is False
    assert res_obj.preservation_classification == WorktreeLifecycleStatus.DIRTY_PRESERVED.value
    assert "README.md" in res_obj.modified_paths
    assert "new_script.py" in res_obj.added_untracked_paths
    assert "main.py" in res_obj.deleted_paths
    assert res_obj.diff_byte_count > 0
    assert len(res_obj.diff_sha256) == 64
    assert res_obj.is_diff_truncated is False


def test_result_capture_committed_work(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="committed-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="3" * 32,
        policy_digest="d" * 64,
        state_root=temp_state_root,
    )
    state = manager.create(res)
    wt_dir = state.worktree_path

    (wt_dir / "feature.py").write_text("code\n", encoding="utf-8")
    subprocess.run(["git", "add", "feature.py"], cwd=wt_dir, check=True)
    subprocess.run(["git", "commit", "-m", "add feature"], cwd=wt_dir, check=True)

    res_obj = manager.capture_result(repo, "committed-task", 1, worker_exit_code=0)

    assert res_obj.is_clean is False
    assert res_obj.preservation_classification == WorktreeLifecycleStatus.COMMITTED_WORK_PRESERVED.value
    assert res_obj.current_head_sha != commit_sha.lower()


def test_result_capture_diff_truncation(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="large-diff-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="4" * 32,
        policy_digest="e" * 64,
        state_root=temp_state_root,
    )
    state = manager.create(res)
    wt_dir = state.worktree_path

    # Generate a tracked Git diff larger than 100 bytes. Untracked evidence has
    # its own bounded presentation and does not alter the complete Git diff hash.
    (wt_dir / "README.md").write_text("X" * 1000 + "\n", encoding="utf-8")

    res_obj = manager.capture_result(repo, "large-diff-task", 1, worker_exit_code=0, max_diff_bytes=100)

    assert res_obj.is_diff_truncated is True
    assert "[TRUNCATED" in res_obj.diff_content
    assert res_obj.diff_byte_count > 1000
    assert len(res_obj.diff_sha256) == 64


# ============================================================================
# 3. LINUX LIVE SANDBOX & ADVERSARIAL INTEGRATION TESTS
# ============================================================================

@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="M4A Bubblewrap Linux sandbox integration")
def test_live_worktree_sandbox_git_mask_denies_git_status(temp_git_repo, temp_state_root, m4a_launcher):
    from agenticos.sandbox.m4a_runner import NamespaceLandlockRunner

    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="live-mask-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="5" * 32,
        policy_digest="f" * 64,
        state_root=temp_state_root,
    )
    manager.create(res)
    worktree_dir, mask_file, state = manager.verify_worktree_for_sandbox(repo, "live-mask-task", 1)

    tmp_dir = temp_state_root / "tmp"
    home_dir = temp_state_root / "home"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    home_dir.mkdir(parents=True, exist_ok=True)

    runner = NamespaceLandlockRunner(
        worker_path=WORKER_PATH,
        workspace=worktree_dir,
        profile=M4AProfile.BUILD,
        launcher_path=m4a_launcher,
        task_tmp=tmp_dir,
        synthetic_home=home_dir,
        git_mask_path=mask_file,
    )

    proc_res = runner.run(["/usr/bin/git", "status"], cwd="/workspace", env={})
    assert proc_res.exit_code != 0
    assert "not a git repository" in proc_res.stderr.lower() or "invalid gitfile format" in proc_res.stderr.lower()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="M4A Bubblewrap Linux sandbox integration")
def test_live_worktree_sandbox_source_operations(temp_git_repo, temp_state_root, m4a_launcher):
    from agenticos.sandbox.m4a_runner import NamespaceLandlockRunner

    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="live-ops-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="6" * 32,
        policy_digest="0" * 64,
        state_root=temp_state_root,
    )
    manager.create(res)
    worktree_dir, mask_file, state = manager.verify_worktree_for_sandbox(repo, "live-ops-task", 1)

    tmp_dir = temp_state_root / "tmp"
    home_dir = temp_state_root / "home"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    home_dir.mkdir(parents=True, exist_ok=True)

    runner = NamespaceLandlockRunner(
        worker_path=WORKER_PATH,
        workspace=worktree_dir,
        profile=M4AProfile.BUILD,
        launcher_path=m4a_launcher,
        task_tmp=tmp_dir,
        synthetic_home=home_dir,
        git_mask_path=mask_file,
    )

    # Worker script executing source filesystem operations inside /workspace
    script = (
        "import os, pathlib; "
        "ws = pathlib.Path('/workspace'); "
        "(ws / 'README.md').write_text('# Modified in Sandbox\\n'); "
        "(ws / 'created.py').write_text('print(123)\\n'); "
        "(ws / 'main.py').unlink() if (ws / 'main.py').exists() else None; "
        "os.rename(str(ws / 'created.py'), str(ws / 'renamed.py'))"
    )

    proc_res = runner.run(["/usr/bin/python3", "-c", script], cwd="/workspace", env={})
    assert proc_res.exit_code == 0

    # Controller captures result after worker exit
    res_obj = manager.capture_result(repo, "live-ops-task", 1, worker_exit_code=0)
    assert res_obj.is_clean is False
    assert "README.md" in res_obj.modified_paths
    assert "renamed.py" in res_obj.added_untracked_paths
    assert "main.py" in res_obj.deleted_paths


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="M4A Bubblewrap Linux sandbox integration")
def test_live_worktree_sandbox_git_mask_tamper_denied(temp_git_repo, temp_state_root, m4a_launcher):
    from agenticos.sandbox.m4a_runner import NamespaceLandlockRunner

    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="live-tamper-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="7" * 32,
        policy_digest="1" * 64,
        state_root=temp_state_root,
    )
    manager.create(res)
    worktree_dir, mask_file, state = manager.verify_worktree_for_sandbox(repo, "live-tamper-task", 1)

    tmp_dir = temp_state_root / "tmp"
    home_dir = temp_state_root / "home"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    home_dir.mkdir(parents=True, exist_ok=True)

    runner = NamespaceLandlockRunner(
        worker_path=WORKER_PATH,
        workspace=worktree_dir,
        profile=M4AProfile.BUILD,
        launcher_path=m4a_launcher,
        task_tmp=tmp_dir,
        synthetic_home=home_dir,
        git_mask_path=mask_file,
    )

    tamper_script = "exec(\"import os\\np = '/workspace/.git'\\nfor op in [lambda: os.unlink(p), lambda: open(p, 'w').write('x'), lambda: os.rename(p, '/workspace/.git.bak')]:\\n    try:\\n        op()\\n        print('SUCCESS')\\n    except OSError as e:\\n        print('DENIED:', type(e).__name__)\")"

    proc_res = runner.run(["/usr/bin/python3", "-c", tamper_script], cwd="/workspace", env={})
    assert "SUCCESS" not in proc_res.stdout
    assert "DENIED" in proc_res.stdout

    # Verify host worktree .git is untouched
    host_git_file = worktree_dir / ".git"
    assert host_git_file.is_file()
    assert host_git_file.read_text(encoding="utf-8").startswith("gitdir:")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="M4A Bubblewrap Linux sandbox integration")
def test_live_worktree_sandbox_multi_task_isolation(temp_git_repo, temp_state_root, m4a_launcher):
    from agenticos.sandbox.m4a_runner import NamespaceLandlockRunner

    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)

    # Task A
    res_a = create_worktree_reservation(
        repo_path=repo,
        task_id="task-a",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="8" * 32,
        policy_digest="2" * 64,
        state_root=temp_state_root,
    )
    st_a = manager.create(res_a)
    wt_a, mask_a, _ = manager.verify_worktree_for_sandbox(repo, "task-a", 1)

    # Task B
    res_b = create_worktree_reservation(
        repo_path=repo,
        task_id="task-b",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="9" * 32,
        policy_digest="3" * 64,
        state_root=temp_state_root,
    )
    st_b = manager.create(res_b)
    wt_b, mask_b, _ = manager.verify_worktree_for_sandbox(repo, "task-b", 1)

    tmp_a = temp_state_root / "tmp_a"
    home_a = temp_state_root / "home_a"
    tmp_a.mkdir(parents=True, exist_ok=True)
    home_a.mkdir(parents=True, exist_ok=True)

    runner_a = NamespaceLandlockRunner(
        worker_path=WORKER_PATH,
        workspace=wt_a,
        profile=M4AProfile.BUILD,
        launcher_path=m4a_launcher,
        task_tmp=tmp_a,
        synthetic_home=home_a,
        git_mask_path=mask_a,
    )

    probe_script = (
        f"exec(\"import os, pathlib\\npath_b = pathlib.Path('{wt_b}')\\ntry:\\n    path_b.read_text()\\n    print('READ_B_SUCCESS')\\nexcept OSError:\\n    print('READ_B_DENIED')\\n(pathlib.Path('/workspace') / 'file_a.txt').write_text('task a file\\\\n')\")"
    )

    proc_res_a = runner_a.run(["/usr/bin/python3", "-c", probe_script], cwd="/workspace", env={})
    assert "READ_B_SUCCESS" not in proc_res_a.stdout
    assert "READ_B_DENIED" in proc_res_a.stdout

    # Verify Task A edits appear ONLY in Task A worktree
    assert (wt_a / "file_a.txt").is_file()
    assert not (wt_b / "file_a.txt").exists()


# ============================================================================
# 4. SLICE 3A.1 REMEDIATION & VERIFICATION TESTS
# ============================================================================

def test_git_ssl_cainfo_allowed_and_authority_vars_rejected():
    # GIT_SSL_CAINFO is permitted for M4B-3 network CA configuration
    _validate_extra_worker_env((("GIT_SSL_CAINFO", "/opt/agenticos/network-ca.pem"),))

    # All Git repository authority variables are strictly forbidden
    for var in FORBIDDEN_GIT_ENV_NAMES:
        with pytest.raises(ValueError) as exc:
            _validate_extra_worker_env(((var, "/tmp/attack_path"),))
        assert "forbids Git authority environment variable" in str(exc.value)


def test_result_capture_rename_parsing(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="rename-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="a" * 32,
        policy_digest="a" * 64,
        state_root=temp_state_root,
    )
    state = manager.create(res)
    wt_dir = state.worktree_path

    # Perform rename: main.py -> app.py
    subprocess.run(["git", "mv", "main.py", "app.py"], cwd=wt_dir, check=True)
    # Untracked file
    (wt_dir / "untracked.py").write_text("print('untracked')\n", encoding="utf-8")
    # Modified file
    (wt_dir / "README.md").write_text("# Renamed Repo\n", encoding="utf-8")

    res_obj = manager.capture_result(repo, "rename-task", 1, worker_exit_code=0)

    assert res_obj.is_clean is False
    assert ("main.py", "app.py") in res_obj.renamed_paths
    assert "README.md" in res_obj.modified_paths
    assert "untracked.py" in res_obj.added_untracked_paths
    assert "app.py" not in res_obj.added_untracked_paths


def test_result_capture_rename_with_spaces(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="rename-space-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="b" * 32,
        policy_digest="b" * 64,
        state_root=temp_state_root,
    )
    state = manager.create(res)
    wt_dir = state.worktree_path

    subprocess.run(["git", "mv", "main.py", "my main script.py"], cwd=wt_dir, check=True)

    res_obj = manager.capture_result(repo, "rename-space-task", 1, worker_exit_code=0)

    assert ("main.py", "my main script.py") in res_obj.renamed_paths


def test_untracked_file_evidence_bounds(temp_git_repo, temp_state_root):
    repo = temp_git_repo["path"]
    commit_sha = temp_git_repo["commit_sha"]

    manager = WorktreeManager(temp_state_root)
    res = create_worktree_reservation(
        repo_path=repo,
        task_id="untracked-bounds-task",
        generation=1,
        baseline_commit_sha=commit_sha,
        nonce="c" * 32,
        policy_digest="c" * 64,
        state_root=temp_state_root,
    )
    state = manager.create(res)
    wt_dir = state.worktree_path

    # Small text file
    (wt_dir / "small.txt").write_text("hello\n", encoding="utf-8")
    # Empty file
    (wt_dir / "empty.txt").write_text("", encoding="utf-8")
    # Large file (> 64 KiB)
    large_data = b"X" * (70 * 1024)
    (wt_dir / "large.bin").write_bytes(large_data)
    # Binary file with NUL bytes
    binary_data = b"hello\x00world\x00123"
    (wt_dir / "binary.dat").write_bytes(binary_data)
    # Symlink
    if hasattr(os, "symlink"):
        try:
            os.symlink("small.txt", str(wt_dir / "symlink.txt"))
        except OSError:
            pass

    res_obj = manager.capture_result(repo, "untracked-bounds-task", 1, worker_exit_code=0)

    assert "small.txt" in res_obj.added_untracked_paths
    assert "empty.txt" in res_obj.added_untracked_paths
    assert "large.bin" in res_obj.added_untracked_paths
    assert "binary.dat" in res_obj.added_untracked_paths

    assert "[UNTRACKED LARGE FILE:" in res_obj.untracked_evidence_content
    assert "[UNTRACKED BINARY FILE:" in res_obj.untracked_evidence_content
    assert len(res_obj.diff_sha256) == 64
    # Ensure source worktree files remain untouched and intact
    assert (wt_dir / "large.bin").read_bytes() == large_data
    assert (wt_dir / "binary.dat").read_bytes() == binary_data
