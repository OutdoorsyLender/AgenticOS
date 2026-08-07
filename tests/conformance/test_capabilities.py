"""Unit tests for the read-only host capability detector.

Detection/parsing logic is tested against synthetic fixture trees; nothing
here requires (or fakes) real Linux capabilities on the current host.
"""

from __future__ import annotations

import hashlib
import json
import sys

import pytest

from agenticos.sandbox.capabilities import (
    CapabilityStatus,
    HostCapabilityDetector,
    parse_cgroup_events,
    parse_mounts,
    parse_wsl_version,
)

WSL2_PROC_VERSION = (
    "Linux version 5.15.90.1-microsoft-standard-WSL2 (builder@host) "
    "(gcc (GCC) 11.2.0) #1 SMP Tue Jan 1 00:00:00 UTC 2024\n"
)
PLAIN_LINUX_PROC_VERSION = (
    "Linux version 6.1.0--amd64 (builder@host) (gcc (GCC) 12.2.0) "
    "#1 SMP PREEMPT Tue Jan 1 00:00:00 UTC 2024\n"
)


def make_linux_fixture_tree(tmp_path, *, wsl=True, cgroup_v2=True, cgroup_kill=True):
    """A synthetic /proc + /sys/fs/cgroup tree for the detector."""
    proc = tmp_path / "proc"
    cg = tmp_path / "sys" / "fs" / "cgroup"
    (proc / "1").mkdir(parents=True)
    (proc / "self").mkdir(parents=True)
    (proc / "sys" / "user").mkdir(parents=True)
    cg.mkdir(parents=True)

    (proc / "version").write_text(
        WSL2_PROC_VERSION if wsl else PLAIN_LINUX_PROC_VERSION
    )
    (proc / "1" / "comm").write_text("systemd\n")
    (proc / "self" / "stat").write_text("1 (init) S 0 1 1 0 -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 42 1000 1\n")
    (proc / "sys" / "user" / "max_user_namespaces").write_text("15000\n")
    if cgroup_v2:
        (proc / "self" / "mounts").write_text(
            "tmpfs /run tmpfs rw 0 0\n"
            "cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime 0 0\n"
        )
        (cg / "cgroup.controllers").write_text("cpuset cpu io memory pids\n")
        (cg / "cgroup.events").write_text("populated 1\nfrozen 0\n")
        if cgroup_kill:
            (cg / "cgroup.kill").write_text("")
    else:
        (proc / "self" / "mounts").write_text(
            "cgroup /sys/fs/cgroup/cpu cgroup rw,cpu 0 0\n"
        )
    return proc, cg


# --------------------------------------------------------------------------
# Pure parsers
# --------------------------------------------------------------------------

def test_parse_wsl_version():
    assert parse_wsl_version(WSL2_PROC_VERSION) == "WSL2"
    assert parse_wsl_version(PLAIN_LINUX_PROC_VERSION) is None
    assert parse_wsl_version("Linux version 4.4.0-19041-Microsoft\n") == "WSL1-or-unknown"


def test_parse_mounts():
    entries = parse_mounts("cgroup2 /sys/fs/cgroup cgroup2 rw 0 0\ntmpfs /run tmpfs rw 0 0\n")
    assert ("cgroup2", "/sys/fs/cgroup", "cgroup2") in entries
    assert len(entries) == 2


def test_parse_cgroup_events():
    assert parse_cgroup_events("populated 0\nfrozen 0\n") == {"populated": 0, "frozen": 0}
    assert parse_cgroup_events("populated 1\nfrozen 0\n")["populated"] == 1
    assert parse_cgroup_events("garbage line\n") == {}


# --------------------------------------------------------------------------
# Detector against synthetic trees
# --------------------------------------------------------------------------

def test_wsl2_cgroup_v2_detection(tmp_path):
    proc, cg = make_linux_fixture_tree(tmp_path, wsl=True, cgroup_v2=True)
    report = HostCapabilityDetector(proc_root=proc, cgroup_root=cg, environ={}).detect()
    assert report.status_of("wsl_detected") is CapabilityStatus.SUPPORTED
    assert report.status_of("wsl_version") is CapabilityStatus.SUPPORTED
    assert report.capabilities["wsl_version"].evidence == "environment=WSL2"
    assert report.status_of("systemd_running") is CapabilityStatus.SUPPORTED
    assert report.status_of("cgroup_v2_mounted") is CapabilityStatus.SUPPORTED
    assert report.status_of("cgroup_kill_available") is CapabilityStatus.SUPPORTED
    assert report.status_of("cgroup_events_available") is CapabilityStatus.SUPPORTED
    assert report.status_of("user_namespaces_observed") is CapabilityStatus.SUPPORTED
    assert report.status_of("procfs_available") is CapabilityStatus.SUPPORTED


def test_plain_linux_cgroup_v1_detection(tmp_path):
    proc, cg = make_linux_fixture_tree(tmp_path, wsl=False, cgroup_v2=False)
    report = HostCapabilityDetector(proc_root=proc, cgroup_root=cg, environ={}).detect()
    assert report.status_of("wsl_detected") is CapabilityStatus.UNSUPPORTED
    assert report.status_of("cgroup_v2_mounted") is CapabilityStatus.UNSUPPORTED
    assert report.status_of("cgroup_kill_available") is CapabilityStatus.UNSUPPORTED
    assert report.status_of("cgroup_events_available") is CapabilityStatus.UNSUPPORTED


def test_cgroup_kill_absent_reported(tmp_path):
    proc, cg = make_linux_fixture_tree(tmp_path, cgroup_v2=True, cgroup_kill=False)
    report = HostCapabilityDetector(proc_root=proc, cgroup_root=cg, environ={}).detect()
    assert report.status_of("cgroup_v2_mounted") is CapabilityStatus.SUPPORTED
    assert report.status_of("cgroup_kill_available") is CapabilityStatus.UNSUPPORTED
    assert "missing" in report.capabilities["cgroup_kill_available"].evidence


def test_scope_creation_is_not_assumed_from_systemd(tmp_path):
    """System capability must not be confused with current-user permission."""
    proc, cg = make_linux_fixture_tree(tmp_path)
    report = HostCapabilityDetector(proc_root=proc, cgroup_root=cg, environ={}).detect()
    assert report.status_of("systemd_running") is CapabilityStatus.SUPPORTED
    assert report.status_of("systemd_scope_creation") is CapabilityStatus.UNVERIFIED


def test_detector_is_read_only(tmp_path):
    proc, cg = make_linux_fixture_tree(tmp_path)

    def tree_digest() -> str:
        h = hashlib.sha256()
        for path in sorted(tmp_path.rglob("*")):
            h.update(str(path).encode())
            if path.is_file():
                h.update(path.read_bytes())
        return h.hexdigest()

    before = tree_digest()
    HostCapabilityDetector(proc_root=proc, cgroup_root=cg, environ={}).detect()
    assert tree_digest() == before, "detector modified the inspected tree"


def test_report_serialization(tmp_path):
    proc, cg = make_linux_fixture_tree(tmp_path)
    report = HostCapabilityDetector(proc_root=proc, cgroup_root=cg, environ={}).detect()
    doc = json.loads(json.dumps(report.to_dict()))
    assert doc["schema_version"] == "0.1.0"
    assert "collected_at" in doc
    assert doc["capabilities"]["cgroup_v2_mounted"]["status"] == "SUPPORTED"
    assert doc["capabilities"]["cgroup_v2_mounted"]["evidence"]


def test_unknown_capability_is_unverified(tmp_path):
    proc, cg = make_linux_fixture_tree(tmp_path)
    report = HostCapabilityDetector(proc_root=proc, cgroup_root=cg, environ={}).detect()
    assert report.status_of("no_such_capability") is CapabilityStatus.UNVERIFIED


# --------------------------------------------------------------------------
# Current-host behavior (must never crash, never fake success)
# --------------------------------------------------------------------------

def test_current_host_detection_runs_and_serializes():
    report = HostCapabilityDetector().detect()
    doc = report.to_dict()
    json.dumps(doc)
    if sys.platform.startswith("linux"):
        assert report.status_of("host_platform_linux") is CapabilityStatus.SUPPORTED
        assert report.status_of("procfs_available") is CapabilityStatus.SUPPORTED
    else:
        # Non-Linux host: containment-relevant capabilities must NOT be faked.
        assert report.status_of("host_platform_linux") is CapabilityStatus.UNSUPPORTED
        assert report.status_of("cgroup_v2_mounted") is not CapabilityStatus.SUPPORTED
        assert report.status_of("repo_on_linux_filesystem") is CapabilityStatus.UNSUPPORTED
        assert report.status_of("landlock_abi") is CapabilityStatus.UNVERIFIED


def test_repo_location_on_windows_host_reported():
    report = HostCapabilityDetector().detect()
    cap = report.capabilities["repo_on_linux_filesystem"]
    if not sys.platform.startswith("linux"):
        assert cap.status == CapabilityStatus.UNSUPPORTED.value
        assert "WSL" in cap.evidence or "not Linux" in cap.evidence
