"""Tests for the synthetic fixture builder itself."""

from __future__ import annotations

import pytest

from agenticos.sandbox.fixtures import (
    ENV_SECRET_NAME,
    HARMLESS_ENV_NAME,
    FixtureBuilder,
    synthetic_env,
)


def test_layout_paths_created(layout):
    for path in (
        layout.assigned_worktree,
        layout.sibling_worktree,
        layout.agenticos_private,
        layout.fake_home,
        layout.task_tmp,
        layout.sockets_dir,
    ):
        assert path.is_dir(), f"missing fixture directory: {path}"
    for path in (
        layout.allowed_file,
        layout.denied_sibling_file,
        layout.evidence_secret_file,
        layout.fake_state_file,
        layout.fake_ssh_key,
        layout.fake_credentials_file,
    ):
        assert path.is_file(), f"missing fixture file: {path}"


def test_everything_lives_under_root(layout):
    paths = [
        layout.assigned_worktree,
        layout.sibling_worktree,
        layout.agenticos_private,
        layout.fake_home,
        layout.task_tmp,
        layout.sockets_dir,
        layout.allowed_file,
        layout.denied_sibling_file,
        layout.evidence_secret_file,
        layout.fake_state_file,
        layout.fake_ssh_key,
        layout.fake_credentials_file,
    ]
    for path in paths:
        assert layout.root in path.parents or path == layout.root, (
            f"fixture path escapes root: {path}"
        )


def test_canaries_unique_and_planted(layout):
    values = list(layout.canaries.values())
    assert len(set(values)) == len(values), "canaries are not unique"
    for value in values:
        assert value.startswith("AOS_CANARY_")
    assert layout.canaries["permitted"] in layout.allowed_file.read_text()
    assert layout.canaries["sibling"] in layout.denied_sibling_file.read_text()
    assert layout.canaries["state"] in layout.evidence_secret_file.read_text()
    assert layout.canaries["state"].encode() in layout.fake_state_file.read_bytes()
    assert layout.canaries["credential"] in layout.fake_ssh_key.read_text()
    assert layout.canaries["credential"] in layout.fake_credentials_file.read_text()


def test_canaries_randomized_per_run(tmp_path):
    a = FixtureBuilder(root=tmp_path / "a").build()
    b = FixtureBuilder(root=tmp_path / "b").build()
    try:
        assert a.canaries != b.canaries
    finally:
        a.cleanup()
        b.cleanup()


def test_synthetic_env(layout):
    env = synthetic_env(layout)
    assert env[ENV_SECRET_NAME] == layout.canaries["env"]
    assert env[HARMLESS_ENV_NAME]
    assert layout.env_secret_name == ENV_SECRET_NAME


def test_cleanup_removes_root(tmp_path):
    builder = FixtureBuilder(root=tmp_path / "doomed")
    lay = builder.build()
    assert lay.root.exists()
    lay.cleanup()
    assert not lay.root.exists()


def test_cleanup_failure_is_loud(tmp_path):
    builder = FixtureBuilder(root=tmp_path / "broken")
    lay = builder.build()
    lay.cleanup()
    with pytest.raises(FileNotFoundError):
        lay.cleanup()  # already gone -> must raise, not silently pass


def test_context_manager(tmp_path):
    with FixtureBuilder(root=tmp_path / "ctx") as lay:
        root = lay.root
        assert root.exists()
    assert not root.exists()
