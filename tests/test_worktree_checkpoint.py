"""Slice B complete M5 workspace checkpoint tests."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import agenticos.sandbox.worktree as worktree_module

from agenticos.sandbox.worktree import (
    StatusCategory,
    WorkspaceCaptureCompleteness,
    WorkspaceCaptureError,
    WorkspaceCaptureFailureKind,
    WorkspaceReuseDecision,
    WorktreeManager,
    _canonical_status_manifest,
    _canonical_checkpoint_digest,
    _count_status_categories,
    _parse_status_stream,
    _run_git_diff_bounded,
    _run_git_status_bounded,
    create_worktree_reservation,
)


@pytest.fixture
def checkpoint_repo(tmp_path: Path) -> dict[str, object]:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Checkpoint Test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "checkpoint@agenticos.local"], cwd=repo, check=True)
    (repo / "README.md").write_text("baseline\n", encoding="utf-8")
    (repo / "delete.txt").write_text("delete me\n", encoding="utf-8")
    (repo / "rename.txt").write_text("rename me\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "baseline"], cwd=repo, check=True, capture_output=True)
    baseline = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()
    return {"path": repo, "baseline": baseline}


@pytest.fixture
def checkpoint_workspace(
    checkpoint_repo: dict[str, object], tmp_path: Path
) -> tuple[WorktreeManager, Path, Path, str]:
    repo = checkpoint_repo["path"]
    baseline = checkpoint_repo["baseline"]
    assert isinstance(repo, Path)
    assert isinstance(baseline, str)
    state_root = tmp_path / "state"
    state_root.mkdir()
    manager = WorktreeManager(state_root)
    reservation = create_worktree_reservation(
        repo_path=repo,
        task_id="checkpoint-task",
        generation=7,
        baseline_commit_sha=baseline,
        nonce="7" * 32,
        policy_digest="b" * 64,
        state_root=state_root,
    )
    state = manager.create(reservation)
    return manager, repo, state.worktree_path, baseline


def test_complete_status_manifest_is_order_independent_and_counts_each_category() -> None:
    raw_a = (
        b" M tracked.txt\0"
        b"A  staged.txt\0"
        b" D deleted.txt\0"
        b"R  renamed.txt\0old.txt\0"
        b"?? nested/new file.txt\0"
        b"UU conflicted.txt\0"
    )
    raw_b = (
        b"UU conflicted.txt\0"
        b"?? nested/new file.txt\0"
        b"R  renamed.txt\0old.txt\0"
        b" D deleted.txt\0"
        b"A  staged.txt\0"
        b" M tracked.txt\0"
    )

    entries_a = _parse_status_stream(raw_a, max_entries=100, max_path_bytes=4096)
    entries_b = _parse_status_stream(raw_b, max_entries=100, max_path_bytes=4096)

    assert entries_a == entries_b
    assert _canonical_status_manifest(entries_a) == _canonical_status_manifest(entries_b)
    assert _canonical_status_manifest(entries_a) == _canonical_status_manifest(tuple(reversed(entries_a)))
    assert len(_canonical_status_manifest(entries_a)) == 64
    counts = _count_status_categories(entries_a)
    assert counts.tracked_modified == 1
    assert counts.tracked_added == 1
    assert counts.tracked_deleted == 1
    assert counts.renamed == 1
    assert counts.copied == 0
    assert counts.unmerged == 1
    assert counts.untracked == 1
    assert counts.total_entries == 6
    rename = next(entry for entry in entries_a if StatusCategory.RENAMED in entry.categories)
    assert rename.path == "renamed.txt"
    assert rename.second_path == "old.txt"


@pytest.mark.parametrize(
    ("raw", "kind"),
    [
        (b" M incomplete.txt", WorkspaceCaptureFailureKind.MALFORMED_STATUS_STREAM),
        (b"M short-code.txt\0", WorkspaceCaptureFailureKind.MALFORMED_STATUS_STREAM),
        (b"ZZ unsupported.txt\0", WorkspaceCaptureFailureKind.MALFORMED_STATUS_STREAM),
        (b"U  invalid-unmerged.txt\0", WorkspaceCaptureFailureKind.MALFORMED_STATUS_STREAM),
        (b"R  destination.txt\0", WorkspaceCaptureFailureKind.MALFORMED_STATUS_STREAM),
        (b"?? bad-utf8-\xff\0", WorkspaceCaptureFailureKind.INVALID_STATUS_PATH),
        (b"?? duplicate.txt\0?? duplicate.txt\0", WorkspaceCaptureFailureKind.MALFORMED_STATUS_STREAM),
        (b"?? ../escape.txt\0", WorkspaceCaptureFailureKind.INVALID_STATUS_PATH),
    ],
)
def test_status_parser_fails_closed_on_malformed_or_ambiguous_streams(
    raw: bytes, kind: WorkspaceCaptureFailureKind
) -> None:
    with pytest.raises(WorkspaceCaptureError) as exc_info:
        _parse_status_stream(raw, max_entries=100, max_path_bytes=4096)

    assert exc_info.value.kind is kind


def test_status_parser_enforces_complete_entry_and_path_bounds() -> None:
    with pytest.raises(WorkspaceCaptureError) as entries_exc:
        _parse_status_stream(b"?? a\0?? b\0", max_entries=1, max_path_bytes=4096)
    assert entries_exc.value.kind is WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED

    with pytest.raises(WorkspaceCaptureError) as path_exc:
        _parse_status_stream(b"?? abcde\0", max_entries=10, max_path_bytes=4)
    assert path_exc.value.kind is WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED


def test_checkpoint_observes_all_nested_untracked_files_and_separates_presentation(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str]
) -> None:
    manager, repo, worktree, _ = checkpoint_workspace
    nested = worktree / "untracked" / "deep" / "inside"
    nested.mkdir(parents=True)
    (nested / "alpha.txt").write_text("alpha\n", encoding="utf-8")
    (nested / "beta file.txt").write_text("beta\n", encoding="utf-8")
    (worktree / "untracked" / "gamma.bin").write_bytes(b"g" * 200_000)

    bounded = manager.capture_checkpoint(
        repo, "checkpoint-task", 7, max_paths_per_category=1
    )
    complete = manager.capture_checkpoint(
        repo, "checkpoint-task", 7, max_paths_per_category=10
    )

    assert bounded.decision is WorkspaceReuseDecision.REUSABLE
    assert bounded.failure is None
    assert bounded.checkpoint is not None
    assert bounded.checkpoint.capture_completeness is WorkspaceCaptureCompleteness.COMPLETE
    assert bounded.checkpoint.status_counts.untracked == 3
    assert bounded.checkpoint.status_counts.total_entries == 3
    assert bounded.checkpoint.status_manifest_sha256 == complete.checkpoint.status_manifest_sha256
    assert bounded.checkpoint.checkpoint_digest == complete.checkpoint.checkpoint_digest
    assert bounded.path_list_truncated is True
    assert bounded.omitted_path_count == 2
    assert len(bounded.status_entries) == 1
    assert complete.path_list_truncated is False
    assert complete.omitted_path_count == 0
    assert {entry.path for entry in complete.status_entries} == {
        "untracked/deep/inside/alpha.txt",
        "untracked/deep/inside/beta file.txt",
        "untracked/gamma.bin",
    }
    gamma = next(entry for entry in complete.status_entries if entry.path == "untracked/gamma.bin")
    assert gamma.untracked_byte_count == 200_000
    assert gamma.untracked_sha256 == hashlib.sha256(b"g" * 200_000).hexdigest()


def test_complete_counts_and_checkpoint_digest_track_status_diff_and_untracked_content(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str]
) -> None:
    manager, repo, worktree, _ = checkpoint_workspace
    (worktree / "README.md").write_text("modified\n", encoding="utf-8")
    (worktree / "staged.txt").write_text("staged\n", encoding="utf-8")
    subprocess.run(["git", "add", "staged.txt"], cwd=worktree, check=True)
    (worktree / "delete.txt").unlink()
    subprocess.run(["git", "mv", "rename.txt", "renamed file.txt"], cwd=worktree, check=True)
    (worktree / "untracked.txt").write_text("one\n", encoding="utf-8")

    first = manager.capture_checkpoint(repo, "checkpoint-task", 7)
    second = manager.capture_checkpoint(repo, "checkpoint-task", 7)

    assert first.decision is WorkspaceReuseDecision.REUSABLE
    assert first.checkpoint is not None
    assert second.checkpoint is not None
    assert first.checkpoint.checkpoint_digest == second.checkpoint.checkpoint_digest
    counts = first.checkpoint.status_counts
    assert counts.tracked_modified == 1
    assert counts.tracked_added == 1
    assert counts.tracked_deleted == 1
    assert counts.renamed == 1
    assert counts.untracked == 1
    assert counts.total_entries == 5
    assert first.checkpoint.diff_byte_count > 0
    assert len(first.checkpoint.diff_sha256) == 64

    (worktree / "untracked.txt").write_text("two\n", encoding="utf-8")
    changed = manager.capture_checkpoint(repo, "checkpoint-task", 7)
    assert changed.checkpoint is not None
    assert changed.checkpoint.status_manifest_sha256 != first.checkpoint.status_manifest_sha256
    assert changed.checkpoint.checkpoint_digest != first.checkpoint.checkpoint_digest


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native Linux symlink semantics")
def test_forbidden_untracked_symlink_is_explicit_and_not_reusable(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str]
) -> None:
    manager, repo, worktree, _ = checkpoint_workspace
    (worktree / "target.txt").write_text("target\n", encoding="utf-8")
    os.symlink("target.txt", worktree / "link.txt")

    capture = manager.capture_checkpoint(repo, "checkpoint-task", 7)

    assert capture.decision is WorkspaceReuseDecision.NOT_REUSABLE
    assert capture.failure is None
    assert capture.checkpoint is not None
    assert capture.checkpoint.capture_completeness is WorkspaceCaptureCompleteness.COMPLETE
    assert WorkspaceCaptureFailureKind.FORBIDDEN_SYMLINK in capture.checkpoint.anomalies
    symlink_entry = next(entry for entry in capture.status_entries if entry.path == "link.txt")
    assert symlink_entry.anomaly is WorkspaceCaptureFailureKind.FORBIDDEN_SYMLINK
    assert symlink_entry.untracked_file_type == "SYMLINK"


def test_m5_result_capture_exposes_checkpoint_and_keeps_git_diff_identity_complete(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str]
) -> None:
    manager, repo, worktree, _ = checkpoint_workspace
    (worktree / "README.md").write_text("tracked change\n", encoding="utf-8")
    (worktree / "untracked.txt").write_text("untracked change\n", encoding="utf-8")
    expected_diff = subprocess.run(
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
        cwd=worktree,
        check=True,
        capture_output=True,
    ).stdout

    result = manager.capture_result(repo, "checkpoint-task", 7, worker_exit_code=0)

    assert result.reusability_decision is WorkspaceReuseDecision.REUSABLE
    assert result.capture_completeness is WorkspaceCaptureCompleteness.COMPLETE
    assert result.checkpoint_digest == result.workspace_checkpoint.checkpoint_digest
    serialized_checkpoint = result.workspace_checkpoint.to_dict()
    serialized_digest = serialized_checkpoint.pop("checkpoint_digest")
    assert serialized_digest == _canonical_checkpoint_digest(serialized_checkpoint)
    assert result.status_manifest_sha256 == result.workspace_checkpoint.status_manifest_sha256
    assert result.status_counts.tracked_modified == 1
    assert result.status_counts.untracked == 1
    assert result.diff_byte_count == len(expected_diff)
    assert result.diff_sha256 == hashlib.sha256(expected_diff).hexdigest()
    assert "UNTRACKED" not in result.diff_content
    assert "untracked change" in result.untracked_evidence_content


def test_copy_and_type_change_codes_remain_distinct_in_complete_counts() -> None:
    entries = _parse_status_stream(
        b"C  copied.txt\0source.txt\0 T type-changed.txt\0",
        max_entries=10,
        max_path_bytes=4096,
    )
    counts = _count_status_categories(entries)
    assert counts.copied == 1
    assert counts.renamed == 0
    assert counts.tracked_type_changed == 1


def test_valid_rename_recreated_source_and_shared_copy_source_are_not_ambiguous() -> None:
    entries = _parse_status_stream(
        b"R  renamed.txt\0source.txt\0"
        b"?? source.txt\0"
        b"C  copy-one.txt\0shared.txt\0"
        b"C  copy-two.txt\0shared.txt\0",
        max_entries=10,
        max_path_bytes=4096,
    )

    assert len(entries) == 4
    assert _count_status_categories(entries).renamed == 1
    assert _count_status_categories(entries).copied == 2
    assert _count_status_categories(entries).untracked == 1


def test_unmerged_status_is_typed_complete_evidence_but_never_reusable(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, repo, _, _ = checkpoint_workspace
    monkeypatch.setattr(
        worktree_module,
        "_run_git_status_bounded",
        lambda *args, **kwargs: b"UU conflict.txt\0",
    )

    capture = manager.capture_checkpoint(repo, "checkpoint-task", 7)

    assert capture.decision is WorkspaceReuseDecision.NOT_REUSABLE
    assert capture.checkpoint is not None
    assert capture.checkpoint.capture_completeness is WorkspaceCaptureCompleteness.COMPLETE
    assert capture.checkpoint.status_counts.unmerged == 1
    assert WorkspaceCaptureFailureKind.UNMERGED_STATUS in capture.checkpoint.anomalies


def test_status_and_diff_child_process_failures_are_typed_and_not_clean(tmp_path: Path) -> None:
    not_a_repo = tmp_path / "not-a-repo"
    not_a_repo.mkdir()
    with pytest.raises(WorkspaceCaptureError) as status_exc:
        _run_git_status_bounded(not_a_repo)
    assert status_exc.value.kind is WorkspaceCaptureFailureKind.GIT_STATUS_FAILURE

    with pytest.raises(WorkspaceCaptureError) as diff_exc:
        _run_git_diff_bounded(not_a_repo)
    assert diff_exc.value.kind is WorkspaceCaptureFailureKind.GIT_DIFF_FAILURE


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native executable textconv fixture")
def test_diff_identity_ignores_textconv_and_covers_complete_binary_patch(tmp_path: Path) -> None:
    repo = tmp_path / "diff-repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Diff Test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "diff@agenticos.local"], cwd=repo, check=True)
    (repo / ".gitattributes").write_text("*.dat diff=constant\n", encoding="utf-8")
    (repo / "binary.dat").write_bytes(b"\x00baseline\xff")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "baseline"], cwd=repo, check=True, capture_output=True)
    textconv = tmp_path / "constant-textconv"
    textconv.write_text("#!/bin/sh\nprintf 'CONSTANT\\n'\n", encoding="utf-8")
    textconv.chmod(0o755)
    subprocess.run(
        ["git", "config", "diff.constant.textconv", str(textconv)], cwd=repo, check=True
    )
    (repo / "binary.dat").write_bytes(b"\x00changed-content\xfe")
    expected = subprocess.run(
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
        cwd=repo,
        check=True,
        capture_output=True,
    ).stdout

    byte_count, digest, _, _ = _run_git_diff_bounded(repo)

    assert b"GIT binary patch" in expected
    assert byte_count == len(expected)
    assert digest == hashlib.sha256(expected).hexdigest()


def test_public_capture_returns_typed_failed_result_for_status_and_diff_faults(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, repo, _, _ = checkpoint_workspace

    def fail_status(*args: object, **kwargs: object) -> bytes:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.GIT_STATUS_FAILURE, "synthetic status failure"
        )

    monkeypatch.setattr(worktree_module, "_run_git_status_bounded", fail_status)
    status_capture = manager.capture_checkpoint(repo, "checkpoint-task", 7)
    assert status_capture.decision is WorkspaceReuseDecision.CAPTURE_FAILED
    assert status_capture.checkpoint is None
    assert status_capture.failure is not None
    assert status_capture.failure.kind is WorkspaceCaptureFailureKind.GIT_STATUS_FAILURE

    monkeypatch.undo()

    def fail_diff(*args: object, **kwargs: object) -> tuple[int, str, str, bool]:
        raise WorkspaceCaptureError(
            WorkspaceCaptureFailureKind.GIT_DIFF_FAILURE, "synthetic diff failure"
        )

    monkeypatch.setattr(worktree_module, "_run_git_diff_bounded", fail_diff)
    diff_capture = manager.capture_checkpoint(repo, "checkpoint-task", 7)
    assert diff_capture.decision is WorkspaceReuseDecision.CAPTURE_FAILED
    assert diff_capture.checkpoint is None
    assert diff_capture.failure is not None
    assert diff_capture.failure.kind is WorkspaceCaptureFailureKind.GIT_DIFF_FAILURE


def test_public_capture_maps_repository_plumbing_execution_failure_to_typed_result(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, repo, _, _ = checkpoint_workspace

    def fail_identity(cls: type[object], path: object) -> object:
        raise worktree_module.WorktreeValidationError("synthetic repository Git timeout")

    monkeypatch.setattr(
        worktree_module.RepositoryIdentity,
        "from_path",
        classmethod(fail_identity),
    )

    capture = manager.capture_checkpoint(repo, "checkpoint-task", 7)

    assert capture.decision is WorkspaceReuseDecision.CAPTURE_FAILED
    assert capture.failure is not None
    assert capture.failure.kind is WorkspaceCaptureFailureKind.REPOSITORY_IDENTITY_MISMATCH


def test_public_capture_rejects_malformed_or_bounded_status_without_partial_checkpoint(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, repo, _, _ = checkpoint_workspace
    monkeypatch.setattr(
        worktree_module,
        "_run_git_status_bounded",
        lambda *args, **kwargs: b"?? truncated.txt",
    )
    malformed = manager.capture_checkpoint(repo, "checkpoint-task", 7)
    assert malformed.decision is WorkspaceReuseDecision.CAPTURE_FAILED
    assert malformed.failure is not None
    assert malformed.failure.kind is WorkspaceCaptureFailureKind.MALFORMED_STATUS_STREAM

    monkeypatch.undo()
    worktree = checkpoint_workspace[2]
    for index in range(5):
        (worktree / f"bounded-{index}.txt").write_text(str(index), encoding="utf-8")
    bounded = manager.capture_checkpoint(repo, "checkpoint-task", 7, max_status_entries=2)
    assert bounded.decision is WorkspaceReuseDecision.CAPTURE_FAILED
    assert bounded.failure is not None
    assert bounded.failure.kind is WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED


def test_inline_diff_and_untracked_bounds_do_not_change_authoritative_checkpoint(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str]
) -> None:
    manager, repo, worktree, _ = checkpoint_workspace
    (worktree / "README.md").write_text("diff\n" * 5000, encoding="utf-8")
    (worktree / "untracked.txt").write_text("untracked\n" * 5000, encoding="utf-8")

    tiny = manager.capture_checkpoint(
        repo,
        "checkpoint-task",
        7,
        max_diff_bytes=32,
        max_untracked_inline_bytes=32,
    )
    roomy = manager.capture_checkpoint(
        repo,
        "checkpoint-task",
        7,
        max_diff_bytes=1_000_000,
        max_untracked_inline_bytes=1_000_000,
    )

    assert tiny.checkpoint is not None
    assert roomy.checkpoint is not None
    assert tiny.is_diff_truncated is True
    assert tiny.is_untracked_evidence_truncated is True
    assert tiny.checkpoint.diff_sha256 == roomy.checkpoint.diff_sha256
    assert tiny.checkpoint.diff_byte_count == roomy.checkpoint.diff_byte_count
    assert tiny.checkpoint.status_manifest_sha256 == roomy.checkpoint.status_manifest_sha256
    assert tiny.checkpoint.checkpoint_digest == roomy.checkpoint.checkpoint_digest


def test_unreadable_and_unhashable_untracked_entries_are_incomplete_and_not_reusable(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, repo, worktree, _ = checkpoint_workspace
    target = worktree / "fault.txt"
    target.write_text("fault\n", encoding="utf-8")
    real_open = os.open

    def unreadable_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if Path(path) == target or (
            Path(path).name == target.name and kwargs.get("dir_fd") is not None
        ):
            raise PermissionError("synthetic unreadable file")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(worktree_module.os, "open", unreadable_open)
    unreadable = manager.capture_checkpoint(repo, "checkpoint-task", 7)
    assert unreadable.decision is WorkspaceReuseDecision.NOT_REUSABLE
    assert unreadable.checkpoint is not None
    assert unreadable.checkpoint.capture_completeness is WorkspaceCaptureCompleteness.INCOMPLETE
    assert WorkspaceCaptureFailureKind.UNREADABLE_UNTRACKED_ENTRY in unreadable.checkpoint.anomalies

    monkeypatch.undo()
    real_open = os.open
    real_read = os.read
    target_fds: set[int] = set()

    def tracked_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        fd = real_open(path, flags, *args, **kwargs)
        if Path(path) == target or (
            Path(path).name == target.name and kwargs.get("dir_fd") is not None
        ):
            target_fds.add(fd)
        return fd

    def unhashable_read(fd: int, size: int) -> bytes:
        if fd in target_fds:
            target_fds.remove(fd)
            raise OSError("synthetic hash read failure")
        return real_read(fd, size)

    monkeypatch.setattr(worktree_module.os, "open", tracked_open)
    monkeypatch.setattr(worktree_module.os, "read", unhashable_read)
    unhashable = manager.capture_checkpoint(repo, "checkpoint-task", 7)
    assert unhashable.decision is WorkspaceReuseDecision.NOT_REUSABLE
    assert unhashable.checkpoint is not None
    assert unhashable.checkpoint.capture_completeness is WorkspaceCaptureCompleteness.INCOMPLETE
    assert WorkspaceCaptureFailureKind.UNHASHABLE_UNTRACKED_ENTRY in unhashable.checkpoint.anomalies


def test_untracked_hash_bound_fails_closed_without_silent_partial_digest(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, repo, worktree, _ = checkpoint_workspace
    (worktree / "bounded-hash.bin").write_bytes(b"12345")
    monkeypatch.setattr(worktree_module, "MAX_UNTRACKED_HASH_BYTES", 4, raising=False)

    capture = manager.capture_checkpoint(repo, "checkpoint-task", 7)

    assert capture.decision is WorkspaceReuseDecision.NOT_REUSABLE
    assert capture.checkpoint is not None
    assert capture.checkpoint.capture_completeness is WorkspaceCaptureCompleteness.INCOMPLETE
    assert WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED in capture.checkpoint.anomalies
    entry = next(item for item in capture.status_entries if item.path == "bounded-hash.bin")
    assert entry.untracked_byte_count == 5
    assert entry.untracked_sha256 is None


def test_aggregate_untracked_and_cumulative_path_budgets_fail_closed(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str]
) -> None:
    manager, repo, worktree, _ = checkpoint_workspace
    (worktree / "a.bin").write_bytes(b"123")
    (worktree / "b.bin").write_bytes(b"456")

    aggregate = manager.capture_checkpoint(
        repo,
        "checkpoint-task",
        7,
        max_aggregate_untracked_bytes=5,
    )
    assert aggregate.decision is WorkspaceReuseDecision.NOT_REUSABLE
    assert aggregate.checkpoint is not None
    assert aggregate.checkpoint.capture_completeness is WorkspaceCaptureCompleteness.INCOMPLETE
    assert WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED in aggregate.checkpoint.anomalies

    path_bound = manager.capture_checkpoint(
        repo,
        "checkpoint-task",
        7,
        max_filesystem_path_bytes=1,
    )
    assert path_bound.decision is WorkspaceReuseDecision.CAPTURE_FAILED
    assert path_bound.failure is not None
    assert path_bound.failure.kind is WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native Linux openat semantics")
def test_untracked_growth_cannot_bypass_per_file_or_aggregate_hash_bounds(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, repo, worktree, _ = checkpoint_workspace
    target = worktree / "growing.bin"
    target.write_bytes(b"1234")
    real_open = os.open
    grew_before_open = False

    def grow_before_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal grew_before_open
        if path == target.name and kwargs.get("dir_fd") is not None and not grew_before_open:
            grew_before_open = True
            with target.open("ab") as stream:
                stream.write(b"56789")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(worktree_module.os, "open", grow_before_open)
    before_open = manager.capture_checkpoint(
        repo,
        "checkpoint-task",
        7,
        max_aggregate_untracked_bytes=4,
    )
    assert before_open.decision is WorkspaceReuseDecision.NOT_REUSABLE
    assert before_open.checkpoint is not None
    assert WorkspaceCaptureFailureKind.UNHASHABLE_UNTRACKED_ENTRY in before_open.checkpoint.anomalies

    monkeypatch.undo()
    target.write_bytes(b"1234")
    real_open = os.open
    real_read = os.read
    target_fds: set[int] = set()
    observed_target_bytes = 0

    def track_target(path: object, flags: int, *args: object, **kwargs: object) -> int:
        fd = real_open(path, flags, *args, **kwargs)
        if path == target.name and kwargs.get("dir_fd") is not None:
            target_fds.add(fd)
        return fd

    def grow_during_read(fd: int, size: int) -> bytes:
        nonlocal observed_target_bytes
        is_target = fd in target_fds
        if is_target:
            target_fds.remove(fd)
            with target.open("ab") as stream:
                stream.write(b"x" * 100)
        chunk = real_read(fd, size)
        if is_target:
            observed_target_bytes += len(chunk)
        return chunk

    monkeypatch.setattr(worktree_module.os, "open", track_target)
    monkeypatch.setattr(worktree_module.os, "read", grow_during_read)
    during_read = manager.capture_checkpoint(
        repo,
        "checkpoint-task",
        7,
        max_aggregate_untracked_bytes=4,
    )
    assert during_read.decision is WorkspaceReuseDecision.NOT_REUSABLE
    assert during_read.checkpoint is not None
    assert WorkspaceCaptureFailureKind.UNHASHABLE_UNTRACKED_ENTRY in during_read.checkpoint.anomalies
    assert observed_target_bytes <= 5


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native Linux dirfd semantics")
def test_failed_stat_entries_still_consume_path_and_deadline_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    for name in ("a", "b", "c"):
        (worktree / name).write_text(name, encoding="utf-8")
    real_stat = os.stat

    def fail_leaf_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if kwargs.get("dir_fd") is not None:
            raise PermissionError("synthetic stat failure")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(worktree_module.os, "stat", fail_leaf_stat)
    with pytest.raises(WorkspaceCaptureError) as exc:
        worktree_module._scan_unobserved_special_entries(
            worktree,
            (),
            tracked_paths=frozenset(),
            gitlink_paths=frozenset(),
            budget=worktree_module._CaptureBudget(
                deadline=time.monotonic() + 10,
                max_aggregate_untracked_bytes=1_000_000,
                max_filesystem_path_bytes=1,
            ),
            max_entries=100,
            max_path_bytes=4096,
        )
    assert exc.value.kind is WorkspaceCaptureFailureKind.EVIDENCE_BOUND_EXCEEDED


def test_capture_revalidates_status_untracked_path_and_ref_after_measurement(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, repo, worktree, _ = checkpoint_workspace
    target = worktree / "observed.txt"
    target.write_text("initial\n", encoding="utf-8")
    real_enrich = worktree_module._enrich_untracked_entries

    def replace_after_hash(*args: object, **kwargs: object) -> object:
        result = real_enrich(*args, **kwargs)
        target.unlink()
        target.write_text("replacement\n", encoding="utf-8")
        return result

    monkeypatch.setattr(worktree_module, "_enrich_untracked_entries", replace_after_hash)
    replaced = manager.capture_checkpoint(repo, "checkpoint-task", 7)
    assert replaced.decision is WorkspaceReuseDecision.CAPTURE_FAILED
    assert replaced.failure is not None
    assert replaced.failure.kind is WorkspaceCaptureFailureKind.UNHASHABLE_UNTRACKED_ENTRY

    monkeypatch.undo()
    real_status = worktree_module._run_git_status_bounded
    status_calls = 0

    def add_after_first_status(*args: object, **kwargs: object) -> bytes:
        nonlocal status_calls
        status_calls += 1
        raw = real_status(*args, **kwargs)
        if status_calls == 1:
            (worktree / "late.txt").write_text("late\n", encoding="utf-8")
        return raw

    monkeypatch.setattr(worktree_module, "_run_git_status_bounded", add_after_first_status)
    status_race = manager.capture_checkpoint(repo, "checkpoint-task", 7)
    assert status_race.decision is WorkspaceReuseDecision.CAPTURE_FAILED
    assert status_race.failure is not None
    assert status_race.failure.kind is WorkspaceCaptureFailureKind.INTERNAL_CANONICALIZATION_INCONSISTENCY

    monkeypatch.undo()
    (worktree / "late.txt").unlink(missing_ok=True)
    real_diff = worktree_module._run_git_diff_bounded
    diff_calls = 0

    def detach_after_first_diff(*args: object, **kwargs: object) -> tuple[int, str, str, bool]:
        nonlocal diff_calls
        diff_calls += 1
        result = real_diff(*args, **kwargs)
        if diff_calls == 1:
            subprocess.run(["git", "checkout", "--detach"], cwd=worktree, check=True, capture_output=True)
        return result

    monkeypatch.setattr(worktree_module, "_run_git_diff_bounded", detach_after_first_diff)
    ref_race = manager.capture_checkpoint(repo, "checkpoint-task", 7)
    assert ref_race.decision is WorkspaceReuseDecision.CAPTURE_FAILED
    assert ref_race.failure is not None
    assert ref_race.failure.kind is WorkspaceCaptureFailureKind.REF_IDENTITY_MISMATCH


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native Linux openat semantics")
def test_special_entry_scan_never_follows_directory_replaced_by_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = tmp_path / "worktree"
    nested = worktree / "nested"
    outside = tmp_path / "outside"
    nested.mkdir(parents=True)
    outside.mkdir()
    (nested / "inside.txt").write_text("inside\n", encoding="utf-8")
    (outside / "outside-secret").write_text("secret\n", encoding="utf-8")
    real_open = os.open
    replaced = False

    def replace_directory_before_open(
        path: object, flags: int, *args: object, **kwargs: object
    ) -> int:
        nonlocal replaced
        if path == "nested" and kwargs.get("dir_fd") is not None and not replaced:
            replaced = True
            nested.rename(worktree / "quarantined")
            nested.symlink_to(outside, target_is_directory=True)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(worktree_module.os, "open", replace_directory_before_open)
    entries = worktree_module._scan_unobserved_special_entries(
        worktree,
        (),
        tracked_paths=frozenset(),
        gitlink_paths=frozenset(),
        budget=worktree_module._CaptureBudget(
            deadline=time.monotonic() + 10,
            max_aggregate_untracked_bytes=1_000_000,
            max_filesystem_path_bytes=1_000_000,
        ),
        max_entries=100,
        max_path_bytes=4096,
    )

    assert replaced is True
    assert any(
        entry.path == "nested"
        and entry.anomaly is WorkspaceCaptureFailureKind.UNREADABLE_UNTRACKED_ENTRY
        for entry in entries
    )
    assert all("outside-secret" not in entry.path for entry in entries)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native Linux FIFO semantics")
def test_non_regular_untracked_entry_is_explicit_and_not_reusable(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str]
) -> None:
    manager, repo, worktree, _ = checkpoint_workspace
    os.mkfifo(worktree / "named-pipe")

    capture = manager.capture_checkpoint(repo, "checkpoint-task", 7)

    assert capture.decision is WorkspaceReuseDecision.NOT_REUSABLE
    assert capture.checkpoint is not None
    assert WorkspaceCaptureFailureKind.FORBIDDEN_NON_REGULAR_ENTRY in capture.checkpoint.anomalies


def test_device_inode_and_ref_mismatch_fail_before_checkpoint_reuse(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, repo, worktree, _ = checkpoint_workspace
    real_identity = worktree_module._stat_descriptor_identity

    def wrong_identity(path: Path) -> tuple[int, int]:
        device, inode = real_identity(path)
        if Path(path) == worktree:
            return device, inode + 1
        return device, inode

    monkeypatch.setattr(worktree_module, "_stat_descriptor_identity", wrong_identity)
    mismatch = manager.capture_checkpoint(repo, "checkpoint-task", 7)
    assert mismatch.decision is WorkspaceReuseDecision.CAPTURE_FAILED
    assert mismatch.failure is not None
    assert mismatch.failure.kind is WorkspaceCaptureFailureKind.FILESYSTEM_IDENTITY_MISMATCH

    monkeypatch.undo()
    subprocess.run(["git", "checkout", "--detach"], cwd=worktree, check=True, capture_output=True)
    ref_mismatch = manager.capture_checkpoint(repo, "checkpoint-task", 7)
    assert ref_mismatch.decision is WorkspaceReuseDecision.CAPTURE_FAILED
    assert ref_mismatch.failure is not None
    assert ref_mismatch.failure.kind is WorkspaceCaptureFailureKind.REF_IDENTITY_MISMATCH


def test_status_filename_and_valid_task_ref_commit_changes_checkpoint_identity(
    checkpoint_workspace: tuple[WorktreeManager, Path, Path, str]
) -> None:
    manager, repo, worktree, _ = checkpoint_workspace
    clean = manager.capture_checkpoint(repo, "checkpoint-task", 7)
    assert clean.checkpoint is not None

    first_path = worktree / "first name.txt"
    first_path.write_text("content\n", encoding="utf-8")
    first = manager.capture_checkpoint(repo, "checkpoint-task", 7)
    assert first.checkpoint is not None
    first_path.rename(worktree / "second name.txt")
    renamed = manager.capture_checkpoint(repo, "checkpoint-task", 7)
    assert renamed.checkpoint is not None
    assert first.checkpoint.status_manifest_sha256 != renamed.checkpoint.status_manifest_sha256
    assert first.checkpoint.checkpoint_digest != renamed.checkpoint.checkpoint_digest

    subprocess.run(["git", "add", "second name.txt"], cwd=worktree, check=True)
    subprocess.run(
        ["git", "commit", "-m", "controller test commit"],
        cwd=worktree,
        check=True,
        capture_output=True,
    )
    committed = manager.capture_checkpoint(repo, "checkpoint-task", 7)
    assert committed.decision is WorkspaceReuseDecision.REUSABLE
    assert committed.checkpoint is not None
    assert committed.checkpoint.current_head_sha != clean.checkpoint.current_head_sha
    assert committed.checkpoint.checkpoint_digest != clean.checkpoint.checkpoint_digest


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native Linux tracked symlink semantics")
def test_unchanged_tracked_symlink_is_not_misclassified_as_untracked_anomaly(
    checkpoint_repo: dict[str, object], tmp_path: Path
) -> None:
    repo = checkpoint_repo["path"]
    assert isinstance(repo, Path)
    (repo / "target.txt").write_text("target\n", encoding="utf-8")
    os.symlink("target.txt", repo / "tracked-link")
    subprocess.run(["git", "add", "target.txt", "tracked-link"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "tracked symlink"], cwd=repo, check=True, capture_output=True)
    baseline = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()
    state_root = tmp_path / "symlink-state"
    state_root.mkdir()
    manager = WorktreeManager(state_root)
    reservation = create_worktree_reservation(
        repo_path=repo,
        task_id="tracked-symlink",
        generation=1,
        baseline_commit_sha=baseline,
        nonce="1" * 32,
        policy_digest="a" * 64,
        state_root=state_root,
    )
    manager.create(reservation)

    capture = manager.capture_checkpoint(repo, "tracked-symlink", 1)

    assert capture.decision is WorkspaceReuseDecision.REUSABLE
    assert capture.checkpoint is not None
    assert capture.checkpoint.status_counts.filesystem_anomalies == 0


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="native local submodule fixture")
def test_any_gitlink_is_explicit_and_never_reusable_even_when_status_ignores_it(
    checkpoint_repo: dict[str, object], tmp_path: Path
) -> None:
    repo = checkpoint_repo["path"]
    assert isinstance(repo, Path)
    submodule_repo = tmp_path / "submodule-source"
    submodule_repo.mkdir()
    subprocess.run(["git", "init"], cwd=submodule_repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Submodule Test"], cwd=submodule_repo, check=True)
    subprocess.run(["git", "config", "user.email", "submodule@agenticos.local"], cwd=submodule_repo, check=True)
    (submodule_repo / "sub.txt").write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=submodule_repo, check=True)
    subprocess.run(["git", "commit", "-m", "submodule baseline"], cwd=submodule_repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "protocol.file.allow=always", "submodule", "add", str(submodule_repo), "module"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "commit", "-am", "add submodule"], cwd=repo, check=True, capture_output=True)
    baseline = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()
    state_root = tmp_path / "gitlink-state"
    state_root.mkdir()
    manager = WorktreeManager(state_root)
    reservation = create_worktree_reservation(
        repo_path=repo,
        task_id="dirty-gitlink",
        generation=1,
        baseline_commit_sha=baseline,
        nonce="2" * 32,
        policy_digest="b" * 64,
        state_root=state_root,
    )
    state = manager.create(reservation)
    subprocess.run(
        ["git", "-c", "protocol.file.allow=always", "submodule", "update", "--init"],
        cwd=state.worktree_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "submodule.module.ignore", "all"],
        cwd=state.worktree_path,
        check=True,
    )

    clean_capture = manager.capture_checkpoint(repo, "dirty-gitlink", 1)
    assert clean_capture.decision is WorkspaceReuseDecision.NOT_REUSABLE
    assert clean_capture.checkpoint is not None
    assert WorkspaceCaptureFailureKind.FORBIDDEN_GITLINK in clean_capture.checkpoint.anomalies

    (state.worktree_path / "module" / "sub.txt").write_text("dirty\n", encoding="utf-8")

    capture = manager.capture_checkpoint(repo, "dirty-gitlink", 1)

    assert capture.decision is WorkspaceReuseDecision.NOT_REUSABLE
    assert capture.checkpoint is not None
    assert WorkspaceCaptureFailureKind.FORBIDDEN_GITLINK in capture.checkpoint.anomalies
