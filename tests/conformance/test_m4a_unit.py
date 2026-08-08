"""Unit tests for the Milestone 4A runtime boundary."""

from __future__ import annotations

import importlib
import importlib.util
import json
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


def _authorized_source(boundary, tmp_path, name, fd, file_type=stat.S_IFDIR):
    return boundary.AuthorizedSource(
        locator=tmp_path / "host" / name,
        fd=fd,
        identity=boundary.FileIdentity(
            device=100 + fd,
            inode=200 + fd,
            file_type=file_type,
        ),
    )


def _runtime_sources(boundary, tmp_path):
    return {
        "workspace": _authorized_source(boundary, tmp_path, "worktree", 10),
        "runtime_usr": _authorized_source(boundary, tmp_path, "usr", 11),
        "launcher": _authorized_source(
            boundary, tmp_path, "fs_launcher", 12, stat.S_IFREG
        ),
        "worker": _authorized_source(
            boundary, tmp_path, "hostile_worker.py", 13, stat.S_IFREG
        ),
        "task_tmp": _authorized_source(boundary, tmp_path, "task-tmp", 14),
        "synthetic_home": _authorized_source(boundary, tmp_path, "home", 15),
    }


@pytest.mark.parametrize(
    ("profile_name", "bind_option", "landlock_mode"),
    [
        ("INSPECT", "--ro-bind-fd", "r"),
        ("BUILD", "--bind-fd", "w"),
    ],
)
def test_workspace_is_fixed_and_profiled(
    tmp_path, profile_name, bind_option, landlock_mode
):
    boundary = _runtime_boundary()
    plan = boundary.build_runtime_plan(
        profile=getattr(boundary.M4AProfile, profile_name),
        **_runtime_sources(boundary, tmp_path),
    )

    workspace = plan.mount_for("/workspace")
    assert workspace.bind_option == bind_option
    assert workspace.landlock_mode == landlock_mode
    assert workspace.role is boundary.MountRole.WORKSPACE
    assert plan.cwd == "/workspace"


def test_worker_environment_is_exact_and_ignores_controller_values():
    boundary = _runtime_boundary()
    expected = {
        "HOME": "/home/tool",
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TMPDIR": "/tmp",
        "PWD": "/workspace",
    }

    assert boundary.build_worker_env(
        {
            "OPENAI_API_KEY": "AOS_CANARY_openai",
            "SSH_AUTH_SOCK": "/synthetic/ssh.sock",
            "PATH": "/host/bin",
        }
    ) == expected


def test_runtime_plan_grants_socket_creation_only_to_private_tmp(tmp_path):
    boundary = _runtime_boundary()
    plan = boundary.build_runtime_plan(
        profile=boundary.M4AProfile.BUILD,
        **_runtime_sources(boundary, tmp_path),
    )

    socket_roots = [mount.destination for mount in plan.mounts if mount.allow_socket]
    assert socket_roots == ["/tmp"]
    assert plan.mount_for("/home/tool").allow_socket is False
    assert plan.mount_for("/workspace").allow_socket is False


def test_runtime_policy_digests_are_deterministic_and_hide_host_locators(tmp_path):
    boundary = _runtime_boundary()
    sources = _runtime_sources(boundary, tmp_path)
    first = boundary.build_runtime_plan(
        profile=boundary.M4AProfile.BUILD, **sources
    )
    second = boundary.build_runtime_plan(
        profile=boundary.M4AProfile.BUILD, **sources
    )

    assert first.filesystem_view_digest == second.filesystem_view_digest
    assert first.environment_policy_digest == second.environment_policy_digest
    assert first.combined_policy_digest == second.combined_policy_digest
    serialized = json.dumps(first.digest_payload, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert "worktree" not in serialized


def test_bwrap_argv_uses_only_fixed_destinations_and_explicit_namespaces(tmp_path):
    boundary = _runtime_boundary()
    plan = boundary.build_runtime_plan(
        profile=boundary.M4AProfile.BUILD,
        **_runtime_sources(boundary, tmp_path),
    )

    argv = boundary.build_bwrap_argv(
        plan,
        namespace_gate_fd=20,
        json_status_fd=21,
        launcher_status_fd=22,
    )

    assert "--unshare-all" not in argv
    assert "--unshare-cgroup" not in argv
    for flag in (
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--disable-userns",
        "--new-session",
        "--die-with-parent",
        "--clearenv",
    ):
        assert flag in argv
    for forbidden in (str(source.locator) for source in _runtime_sources(boundary, tmp_path).values()):
        assert forbidden not in argv
    assert argv[-1] == "/opt/agenticos/fs_launcher"
    assert argv[argv.index("--chdir") + 1] == "/workspace"
    assert argv[argv.index("--block-fd") + 1] == "20"
    assert argv[argv.index("--json-status-fd") + 1] == "21"
    status_index = argv.index("AOS_STATUS_FD")
    assert argv[status_index + 1] == "22"


def _valid_bwrap_setup(boundary, child_pid=42, **extra):
    payload = {
        "child-pid": child_pid,
        "mnt-namespace": 102,
        "net-namespace": 103,
        "pid-namespace": 104,
        "ipc-namespace": 105,
        "uts-namespace": 106,
    }
    payload.update(extra)
    return payload


def test_status_parser_tolerates_unknown_fields_and_future_objects():
    boundary = _runtime_boundary()
    parsed = boundary.parse_bwrap_documents(
        [
            {"future-event": "bounded"},
            _valid_bwrap_setup(boundary, extra_namespace=999),
            {"another-future-event": {"version": 2}},
        ]
    )

    assert parsed.child_pid == 42
    assert parsed.reported_namespaces == {
        "mnt": 102,
        "net": 103,
        "pid": 104,
        "ipc": 105,
        "uts": 106,
    }


def test_status_parser_rejects_contradictory_setup_records():
    boundary = _runtime_boundary()
    with pytest.raises(boundary.NamespaceEvidenceError, match="contradictory"):
        boundary.parse_bwrap_documents(
            [
                _valid_bwrap_setup(boundary, child_pid=42),
                _valid_bwrap_setup(boundary, child_pid=43),
            ]
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.pop("net-namespace"),
        lambda payload: payload.update({"child-pid": "42"}),
        lambda payload: payload.update({"mnt-namespace": -1}),
    ],
)
def test_status_parser_rejects_missing_or_invalid_required_fields(mutation):
    boundary = _runtime_boundary()
    payload = _valid_bwrap_setup(boundary)
    mutation(payload)

    with pytest.raises(boundary.NamespaceEvidenceError):
        boundary.parse_bwrap_documents([payload])


def test_status_parser_rejects_missing_setup_object():
    boundary = _runtime_boundary()
    with pytest.raises(boundary.NamespaceEvidenceError, match="missing"):
        boundary.parse_bwrap_documents([{"exit-code": 0}, {"future": True}])


def test_namespace_verifier_requires_proc_identities_and_exact_cgroup():
    boundary = _runtime_boundary()
    controller = boundary.NamespaceSnapshot(
        pid=10,
        identities={name: index for index, name in enumerate(boundary.NAMESPACE_NAMES, 1)},
        cgroup="/controller.scope",
        uid_map="0 0 4294967295\n",
    )
    child = boundary.NamespaceSnapshot(
        pid=42,
        identities={
            "user": 101,
            "mnt": 102,
            "net": 103,
            "pid": 104,
            "ipc": 105,
            "uts": 106,
        },
        cgroup="/user.slice/aos-task.scope",
        uid_map="0 1000 1\n",
    )
    status = boundary.parse_bwrap_documents([_valid_bwrap_setup(boundary)])

    evidence = boundary.verify_namespace_evidence(
        status,
        controller=controller,
        child=child,
        expected_cgroup="/user.slice/aos-task.scope",
        expected_host_uid=1000,
    )

    assert evidence.verified is True
    assert evidence.child == child


@pytest.mark.parametrize("mismatch", ["net", "cgroup", "uid_map", "child_pid"])
def test_namespace_verifier_rejects_each_authority_mismatch(mismatch):
    boundary = _runtime_boundary()
    controller = boundary.NamespaceSnapshot(
        pid=10,
        identities={name: index for index, name in enumerate(boundary.NAMESPACE_NAMES, 1)},
        cgroup="/controller.scope",
        uid_map="0 0 4294967295\n",
    )
    child_ids = {
        "user": 101,
        "mnt": 102,
        "net": 103,
        "pid": 104,
        "ipc": 105,
        "uts": 106,
    }
    child = boundary.NamespaceSnapshot(
        pid=43 if mismatch == "child_pid" else 42,
        identities=child_ids | ({"net": 999} if mismatch == "net" else {}),
        cgroup="/wrong.scope" if mismatch == "cgroup" else "/user.slice/aos-task.scope",
        uid_map="0 0 1\n" if mismatch == "uid_map" else "0 1000 1\n",
    )
    status = boundary.parse_bwrap_documents([_valid_bwrap_setup(boundary)])

    with pytest.raises(boundary.NamespaceEvidenceError):
        boundary.verify_namespace_evidence(
            status,
            controller=controller,
            child=child,
            expected_cgroup="/user.slice/aos-task.scope",
            expected_host_uid=1000,
        )


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux pipe polling")
def test_bounded_status_reader_finds_setup_after_unknown_object():
    boundary = _runtime_boundary()
    read_fd, write_fd = os.pipe()
    try:
        payload = (
            json.dumps({"future-event": "x"})
            + "\n"
            + json.dumps(_valid_bwrap_setup(boundary))
            + "\n"
        ).encode()
        os.write(write_fd, payload)
        os.close(write_fd)
        write_fd = -1

        parsed = boundary.read_bwrap_setup_status(read_fd, timeout=1.0)
        assert parsed.child_pid == 42
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux pipe polling")
def test_bounded_status_reader_rejects_oversized_record():
    boundary = _runtime_boundary()
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, b'{"future":"' + b"x" * 5000 + b'"}\n')
        os.close(write_fd)
        write_fd = -1

        with pytest.raises(boundary.NamespaceEvidenceError, match="bounded"):
            boundary.read_bwrap_setup_status(
                read_fd, timeout=1.0, max_line_bytes=1024
            )
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux procfs")
def test_namespace_snapshot_reads_all_required_host_proc_fields():
    boundary = _runtime_boundary()
    snapshot = boundary.read_namespace_snapshot(os.getpid())

    assert snapshot.pid == os.getpid()
    assert set(snapshot.identities) == set(boundary.NAMESPACE_NAMES)
    assert all(identity > 0 for identity in snapshot.identities.values())
    assert snapshot.cgroup.startswith("/")
    assert snapshot.uid_map.strip()
