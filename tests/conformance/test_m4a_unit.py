"""Unit tests for the Milestone 4A runtime boundary."""

from __future__ import annotations

import importlib
import importlib.util
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


MODULE = "agenticos.sandbox.runtime_boundary"


def _runtime_boundary():
    return importlib.import_module(MODULE)


def test_runtime_boundary_module_exists():
    assert importlib.util.find_spec(MODULE) is not None


def test_runtime_boundary_module_imports_for_fail_closed_platform_checks():
    assert _runtime_boundary().__name__ == MODULE


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux openat2")
def test_secure_open_source_returns_authoritative_fd_and_identity(tmp_path):
    boundary = _runtime_boundary()
    source = tmp_path / "source"
    source.mkdir()

    opened = boundary.secure_open_source(source, expected_type=stat.S_IFDIR)
    try:
        observed = os.fstat(opened.fd)
        assert opened.locator == source.resolve()
        assert opened.identity == boundary.FileIdentity(
            device=observed.st_dev,
            inode=observed.st_ino,
            file_type=stat.S_IFMT(observed.st_mode),
        )
    finally:
        os.close(opened.fd)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux openat2")
def test_secure_open_source_rejects_wrong_object_type(tmp_path):
    boundary = _runtime_boundary()
    source = tmp_path / "source.txt"
    source.write_text("synthetic")

    with pytest.raises(boundary.RuntimeBoundaryUnavailable, match="wrong type"):
        boundary.secure_open_source(source, expected_type=stat.S_IFDIR)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux openat2")
def test_secure_open_source_authorizes_canonical_symlink_target(tmp_path):
    boundary = _runtime_boundary()
    source = tmp_path / "source"
    source.mkdir()
    locator = tmp_path / "locator"
    locator.symlink_to(source, target_is_directory=True)

    opened = boundary.secure_open_source(locator, expected_type=stat.S_IFDIR)
    try:
        assert opened.locator == source.resolve()
        assert opened.identity.inode == source.stat().st_ino
    finally:
        os.close(opened.fd)


def test_bubblewrap_probe_rejects_setuid_metadata(monkeypatch, tmp_path):
    boundary = _runtime_boundary()
    executable = tmp_path / "bwrap"
    executable.write_bytes(b"synthetic-bwrap")

    monkeypatch.setattr(
        boundary,
        "_stat_executable",
        lambda _path: SimpleNamespace(
            st_uid=0,
            st_gid=0,
            st_mode=stat.S_IFREG | stat.S_ISUID | 0o755,
        ),
    )
    monkeypatch.setattr(boundary, "_read_file_capabilities", lambda _path: "")
    result = boundary.probe_bubblewrap(executable, run_behavior_probe=False)

    assert result.supported is False
    assert any("setuid" in reason for reason in result.reasons)


def test_bubblewrap_probe_rejects_file_capabilities(monkeypatch, tmp_path):
    boundary = _runtime_boundary()
    executable = tmp_path / "bwrap"
    executable.write_bytes(b"synthetic-bwrap")
    executable.chmod(0o755)

    monkeypatch.setattr(
        boundary,
        "_read_file_capabilities",
        lambda _path: f"{executable} cap_sys_admin=ep",
    )
    result = boundary.probe_bubblewrap(executable, run_behavior_probe=False)

    assert result.supported is False
    assert any("file capabilities" in reason for reason in result.reasons)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux Bubblewrap")
def test_recorded_bubblewrap_installation_is_unprivileged():
    boundary = _runtime_boundary()
    result = boundary.probe_bubblewrap(Path("/usr/bin/bwrap"))

    assert result.supported is True, result.reasons
    assert result.version == "bubblewrap 0.11.1"
    assert result.sha256 == (
        "8e19e40e7d5f7a7e8b488c7926feb040"
        "eab6ed10c58fa360e266d2f70670e92b"
    )
    assert result.setuid is False
    assert result.setgid is False
    assert result.file_capabilities == ""
    assert result.unprivileged_user_namespace is True
