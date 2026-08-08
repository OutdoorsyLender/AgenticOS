"""Real-host integration tests for the Milestone 3B native boundary."""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import time

import pytest

from agenticos.sandbox.containment import (
    CancellationConfig,
    CgroupProcessRunner,
    ContainmentState,
    ContainmentUnavailableError,
    EV_CGROUP_EMPTY_VERIFIED,
    EV_FORCED_KILL_REQUESTED,
)
from agenticos.sandbox.evidence import EvidenceCollector
from agenticos.sandbox.isolation import FilesystemPolicy, probe_landlock_enforcement
from agenticos.sandbox.launcher import (
    EV_CONTAINMENT_VERIFIED,
    EV_EXEC_ATTEMPTED,
    EV_EXEC_FAILED,
    EV_FD_SANITIZED,
    EV_NO_NEW_PRIVS,
    EV_POLICY_APPLIED,
    EV_POLICY_FAILED,
    EV_POLICY_PREPARED,
    NativeLandlockRunner,
)
from helpers import WORKER_PATH

pytestmark = pytest.mark.fs_isolation_linux

FAST = CancellationConfig(
    sigint_grace=0.5,
    sigterm_grace=0.5,
    empty_verify_timeout=5.0,
    poll_interval=0.05,
)


@pytest.fixture(scope="session")
def native_launcher(tmp_path_factory):
    if not sys.platform.startswith("linux"):
        pytest.skip("requires Linux")
    repo_root = WORKER_PATH.parents[2]
    source = repo_root / "native" / "fs_launcher" / "fs_launcher.c"
    output = tmp_path_factory.mktemp("native-launcher") / "fs_launcher"
    subprocess.run(
        [
            "cc",
            "-std=c11",
            "-D_GNU_SOURCE",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O2",
            str(source),
            "-o",
            str(output),
        ],
        check=True,
    )
    return output


@pytest.fixture(scope="session")
def native_host_ok():
    support = CgroupProcessRunner.probe()
    if not support.supported:
        pytest.skip("transient scopes unavailable: " + "; ".join(support.reasons))
    enforcement, reason = probe_landlock_enforcement()
    if not enforcement:
        pytest.skip(f"Landlock enforcement unavailable: {reason}")


@pytest.fixture
def native_runner(layout, native_launcher, native_host_ok):
    policy = FilesystemPolicy.for_layout(layout, WORKER_PATH)
    return NativeLandlockRunner(
        WORKER_PATH,
        policy,
        launcher_path=native_launcher,
        cancellation=FAST,
        collector=EvidenceCollector(normalize_root=layout.root),
    )


def test_controller_rejects_mismatched_policy_digest_acknowledgement(
    native_runner, layout, fixture_env, monkeypatch
):
    marker = layout.assigned_worktree / "bad-ack-worker-ran"
    monkeypatch.setenv("AOS_LAUNCHER_FAULT_INJECT", "bad_policy_digest_ack")
    with pytest.raises(ContainmentUnavailableError, match="policy acknowledgement"):
        native_runner.run(
            [
                sys.executable,
                "-c",
                f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')",
            ],
            cwd=layout.assigned_worktree,
            env=fixture_env,
        )
    assert not marker.exists()
    assert native_runner.last_launch_outcome["failed_stage"] == "protocol"
    assert native_runner.last_launch_outcome["policy_applied"] is False
    kinds = [record.kind for record in native_runner.collector.records]
    assert EV_POLICY_APPLIED not in kinds
    assert EV_POLICY_FAILED in kinds
    units = native_runner.backend._ctl(
        ["list-units", "aos-*", "--all", "--no-legend"]
    )
    assert not units.stdout.strip()


def test_post_exec_release_controller_failure_uses_verified_cgroup_drain(
    native_runner, layout, fixture_env, monkeypatch
):
    marker = layout.assigned_worktree / "post-release-child.pid"
    child_code = (
        "import signal,time;"
        "signal.signal(signal.SIGINT, signal.SIG_IGN);"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
        "time.sleep(60)"
    )
    worker_code = (
        "import pathlib,signal,subprocess,sys,time;"
        "signal.signal(signal.SIGINT, signal.SIG_IGN);"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
        f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]);"
        f"pathlib.Path({str(marker)!r}).write_text(str(p.pid));"
        "time.sleep(60)"
    )
    def fail_after_exec_release(fd, budget, max_bytes=256):
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.02)
        raise RuntimeError("injected controller failure after exec release")

    monkeypatch.setattr(
        native_runner, "_read_post_release_status", fail_after_exec_release
    )
    with pytest.raises(RuntimeError, match="after exec release"):
        native_runner.run(
            [sys.executable, "-c", worker_code],
            cwd=layout.assigned_worktree,
            env=fixture_env,
        )
    assert marker.exists(), "failure injection did not reach hostile exec"
    child_pid = int(marker.read_text())
    assert not os.path.exists(f"/proc/{child_pid}")
    kinds = [record.kind for record in native_runner.collector.records]
    assert EV_CGROUP_EMPTY_VERIFIED in kinds
    assert EV_EXEC_ATTEMPTED not in kinds
    units = native_runner.backend._ctl(
        ["list-units", "aos-*", "--all", "--no-legend"]
    )
    assert not units.stdout.strip()


def test_policy_applied_evidence_records_enforcement_metadata(
    native_runner, layout, fixture_env
):
    result = native_runner.run_scenario(
        "FS-01",
        cwd=layout.assigned_worktree,
        env=fixture_env,
        target=layout.allowed_file,
    )
    assert result.succeeded is True
    applied = [
        record
        for record in native_runner.collector.records
        if record.kind == EV_POLICY_APPLIED
    ]
    assert len(applied) == 1
    payload = applied[0].payload
    assert payload["backend"] == "landlock"
    assert payload["abi"] == 3
    assert payload["handled_access_fs"] == 0x7FFF
    assert len(payload["policy_digest"]) == 64
    assert payload["no_new_privs"] is True
    assert payload["restrict_self"] is True
    assert "roots" not in payload


def test_cgroup_gate_precedes_fd_sanitation_and_landlock_activation(
    native_runner, layout, fixture_env
):
    result = native_runner.run_scenario(
        "FS-01",
        cwd=layout.assigned_worktree,
        env=fixture_env,
        target=layout.allowed_file,
    )
    assert result.succeeded is True
    kinds = [record.kind for record in native_runner.collector.records]
    ordered = [
        EV_CONTAINMENT_VERIFIED,
        EV_FD_SANITIZED,
        EV_POLICY_PREPARED,
        EV_NO_NEW_PRIVS,
        EV_POLICY_APPLIED,
        EV_EXEC_ATTEMPTED,
    ]
    assert [kinds.index(kind) for kind in ordered] == sorted(
        kinds.index(kind) for kind in ordered
    )


def test_support_gate_rejects_required_abi_above_observed_host(
    layout, native_launcher, native_host_ok
):
    runner = NativeLandlockRunner(
        WORKER_PATH,
        FilesystemPolicy.for_layout(layout, WORKER_PATH),
        launcher_path=native_launcher,
        min_abi=4,
        cancellation=FAST,
    )
    support = runner.check_support()
    assert support.supported is False
    assert any("landlock_abi=3" in reason for reason in support.reasons)
    assert any("required=4" in reason for reason in support.reasons)


def test_conflicting_overlapping_policy_fails_before_task_launcher(
    layout, fixture_env, native_launcher, native_host_ok
):
    marker = layout.assigned_worktree / "invalid-policy-worker-ran"
    policy = FilesystemPolicy(
        workspace=layout.assigned_worktree,
        readonly_paths=[layout.assigned_worktree / "nested-readonly"],
    )
    policy.readonly_paths[0].mkdir()
    runner = NativeLandlockRunner(
        WORKER_PATH,
        policy,
        launcher_path=native_launcher,
        cancellation=FAST,
    )
    with pytest.raises(ValueError, match="overlapping policy roots"):
        runner.run(
            [
                sys.executable,
                "-c",
                f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')",
            ],
            cwd=layout.assigned_worktree,
            env=fixture_env,
        )
    assert not marker.exists()
    units = runner.backend._ctl(
        ["list-units", "aos-*", "--all", "--no-legend"]
    )
    assert not units.stdout.strip()


def test_production_launcher_drops_deliberately_inherited_outside_fd(
    native_runner, layout, fixture_env
):
    outside_fd = os.open(layout.denied_sibling_file, os.O_RDONLY)
    try:
        process = native_runner.run(
            native_runner.build_scenario_argv("FS-12"),
            cwd=layout.assigned_worktree,
            env=fixture_env,
            _leak_fds=(outside_fd,),
        )
    finally:
        os.close(outside_fd)
    payload = json.loads(process.stdout.strip().splitlines()[-1])
    assert payload["succeeded"] is True
    assert payload["details"]["open_fds"] == [0, 1, 2]
    assert payload["details"]["fds_beyond_stdio"] == []


@pytest.mark.parametrize("method", ["truncate", "open_trunc"])
def test_native_landlock_denies_each_outside_truncation_path(
    native_runner, layout, fixture_env, method
):
    before = layout.denied_sibling_file.read_bytes()
    result = native_runner.run_scenario(
        "FS-14",
        cwd=layout.assigned_worktree,
        env=fixture_env,
        target=layout.denied_sibling_file,
        base=method,
    )
    assert result.succeeded is False
    assert result.error_type == "PermissionError"
    assert result.details["errno"] == 13
    assert layout.denied_sibling_file.read_bytes() == before


def test_native_landlock_allows_rename_within_workspace(
    native_runner, layout, fixture_env
):
    source = layout.assigned_worktree / "rename-source.txt"
    destination = layout.assigned_worktree / "rename-destination.txt"
    source.write_text("rename-control")
    result = native_runner.run_scenario(
        "FS-15",
        cwd=layout.assigned_worktree,
        env=fixture_env,
        target=source,
        base=f"rename:{destination}",
    )
    assert result.succeeded is True
    assert not source.exists()
    assert destination.read_text() == "rename-control"


@pytest.mark.parametrize(
    ("operation", "source_name", "error_type", "error_number"),
    [
        ("hardlink", "outside", "OSError", 18),
        ("rename", "readonly", "PermissionError", 13),
    ],
)
def test_native_landlock_denies_cross_hierarchy_link_or_reparent(
    native_runner,
    layout,
    fixture_env,
    operation,
    source_name,
    error_type,
    error_number,
):
    source = (
        layout.denied_sibling_file
        if source_name == "outside"
        else layout.readonly_file
    )
    destination = layout.assigned_worktree / f"escaped-{operation}.txt"
    result = native_runner.run_scenario(
        "FS-15",
        cwd=layout.assigned_worktree,
        env=fixture_env,
        target=source,
        base=f"{operation}:{destination}",
    )
    assert result.succeeded is False
    assert result.error_type == error_type
    assert result.details["errno"] == error_number
    assert source.exists()
    assert not destination.exists()


@pytest.mark.parametrize(
    ("scenario", "target_kind"),
    [("FS-02", "read"), ("FS-03", "write"), ("FS-04", "traversal")],
)
def test_native_landlock_core_outside_denials_report_eacces(
    native_runner, layout, fixture_env, scenario, target_kind
):
    target = (
        layout.sibling_worktree / "new-outside-file.txt"
        if target_kind == "write"
        else layout.denied_sibling_file
    )
    result = native_runner.run_scenario(
        scenario,
        cwd=layout.assigned_worktree,
        env=fixture_env,
        target=target,
        base=layout.assigned_worktree,
    )
    assert result.succeeded is False
    assert result.error_type == "PermissionError"
    assert result.details["errno"] == 13
    if target_kind == "write":
        assert not target.exists()


def test_native_landlock_allows_workspace_and_readonly_operations(
    native_runner, layout, fixture_env
):
    allowed_read = native_runner.run_scenario(
        "FS-01",
        cwd=layout.assigned_worktree,
        env=fixture_env,
        target=layout.allowed_file,
    )
    assert allowed_read.succeeded is True, {
        "outcome": native_runner.last_launch_outcome,
        "stderr": allowed_read.process.stderr,
    }
    allowed_write_target = layout.assigned_worktree / "allowed-output.txt"
    allowed_write = native_runner.run_scenario(
        "WRITE-01",
        cwd=layout.assigned_worktree,
        env=fixture_env,
        target=allowed_write_target,
    )
    readonly_read = native_runner.run_scenario(
        "FS-10",
        cwd=layout.assigned_worktree,
        env=fixture_env,
        target=layout.readonly_file,
    )
    assert allowed_write.succeeded is True
    assert allowed_write_target.is_file()
    assert readonly_read.succeeded is True


def test_native_landlock_denies_symlink_read_and_write_escape(
    native_runner, layout, fixture_env
):
    if not layout.symlink_supported:
        pytest.skip("symlinks unavailable")
    link = layout.assigned_worktree / "outside-link"
    os.symlink(layout.denied_sibling_file, link)
    for scenario in ("FS-05", "FS-06"):
        result = native_runner.run_scenario(
            scenario,
            cwd=layout.assigned_worktree,
            env=fixture_env,
            target=link,
        )
        assert result.succeeded is False
        assert result.error_type == "PermissionError"
        assert result.details["errno"] == 13


def test_native_landlock_denies_readonly_write_and_outside_reparent(
    native_runner, layout, fixture_env
):
    readonly_before = layout.readonly_file.read_bytes()
    readonly_write = native_runner.run_scenario(
        "FS-11",
        cwd=layout.assigned_worktree,
        env=fixture_env,
        target=layout.readonly_file,
    )
    reparent = native_runner.run_scenario(
        "FS-07",
        cwd=layout.assigned_worktree,
        env=fixture_env,
        target=layout.denied_sibling_file,
        base=layout.assigned_worktree,
    )
    assert readonly_write.succeeded is False
    assert readonly_write.error_type == "PermissionError"
    assert readonly_write.details["errno"] == 13
    assert layout.readonly_file.read_bytes() == readonly_before
    assert reparent.succeeded is False
    assert reparent.error_type == "PermissionError"
    assert reparent.details["errno"] == 13
    assert layout.denied_sibling_file.exists()


@pytest.mark.parametrize(
    "mode",
    ["child", "grandchild", "setsid", "newpgroup", "parentexit", "doublefork"],
)
def test_native_landlock_descendants_keep_filesystem_and_cgroup_boundaries(
    native_runner, layout, fixture_env, mode
):
    result = native_runner.run_scenario(
        "FS-09",
        cwd=layout.assigned_worktree,
        env=fixture_env,
        target=layout.denied_sibling_file,
        base=mode,
    )
    assert result.succeeded is False
    assert result.details["descendant_opened"] is False
    assert result.details["descendant_error"] == "PermissionError"
    assert result.details["descendant_errno"] == 13
    assert result.process.containment_state == ContainmentState.TERMINATED.value
    assert result.process.containment_unit
    assert result.process.containment_cgroup
    cgroup_relative = result.process.containment_cgroup.removeprefix(
        "/sys/fs/cgroup"
    )
    assert cgroup_relative in result.details["descendant_cgroup"]
    assert not os.path.exists(f"/proc/{result.details['descendant_pid']}")
    kinds = [record.kind for record in native_runner.collector.records]
    assert EV_CGROUP_EMPTY_VERIFIED in kinds


@pytest.mark.parametrize(
    ("fault", "stage"),
    [
        ("fail_ruleset", "ruleset"),
        ("fail_rule", "rule"),
        ("fail_nnp", "nnp"),
        ("fail_restrict", "restrict"),
    ],
)
def test_native_launcher_setup_faults_fail_closed_without_worker_exec(
    native_runner, layout, fixture_env, monkeypatch, fault, stage
):
    marker = layout.assigned_worktree / f"worker-executed-{fault}"
    monkeypatch.setenv("AOS_LAUNCHER_FAULT_INJECT", fault)
    process = native_runner.run(
        [
            sys.executable,
            "-c",
            f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')",
        ],
        cwd=layout.assigned_worktree,
        env=fixture_env,
    )
    assert not marker.exists()
    assert process.exit_code == 2
    assert process.containment_state == ContainmentState.TERMINATED.value
    assert native_runner.last_launch_outcome["failed_stage"] == stage
    assert native_runner.last_launch_outcome["policy_applied"] is False
    assert "A" not in native_runner.last_launch_outcome["progress"]


def test_skipped_no_new_privs_never_emits_false_nnp_evidence(
    native_runner, layout, fixture_env, monkeypatch
):
    marker = layout.assigned_worktree / "worker-executed-skip-nnp"
    monkeypatch.setenv("AOS_LAUNCHER_FAULT_INJECT", "skip_nnp")
    process = native_runner.run(
        [
            sys.executable,
            "-c",
            f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')",
        ],
        cwd=layout.assigned_worktree,
        env=fixture_env,
    )
    assert not marker.exists()
    assert process.exit_code == 2
    outcome = native_runner.last_launch_outcome
    assert outcome["failed_stage"] == "restrict"
    assert "N" not in outcome["progress"]
    assert "A" not in outcome["progress"]


def test_exec_failure_remains_distinct_from_successful_policy_barrier(
    native_runner, layout, fixture_env
):
    process = native_runner.run(
        ["/usr/bin/agenticos-definitely-missing"],
        cwd=layout.assigned_worktree,
        env=fixture_env,
    )
    outcome = native_runner.last_launch_outcome
    assert process.exit_code == 127
    assert process.containment_state == ContainmentState.TERMINATED.value
    assert outcome["failed_stage"] == "exec"
    assert outcome["exec_errno"] == 2
    assert outcome["policy_applied"] is True
    assert outcome["exec_succeeded"] is False
    kinds = [record.kind for record in native_runner.collector.records]
    assert EV_POLICY_APPLIED in kinds
    assert EV_EXEC_FAILED in kinds
    assert EV_POLICY_FAILED not in kinds


def test_stalled_pre_policy_setup_is_bounded_and_never_executes_worker(
    layout, fixture_env, native_launcher, native_host_ok, monkeypatch
):
    marker = layout.assigned_worktree / "stalled-setup-worker-ran"
    runner = NativeLandlockRunner(
        WORKER_PATH,
        FilesystemPolicy.for_layout(layout, WORKER_PATH),
        launcher_path=native_launcher,
        setup_timeout=0.4,
        cancellation=FAST,
    )
    monkeypatch.setenv("AOS_LAUNCHER_FAULT_INJECT", "sleep_after_gate:60")
    started = time.monotonic()
    with pytest.raises(ContainmentUnavailableError, match="policy barrier"):
        runner.run(
            [
                sys.executable,
                "-c",
                f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')",
            ],
            cwd=layout.assigned_worktree,
            env=fixture_env,
        )
    assert time.monotonic() - started < 3.0
    assert not marker.exists()
    units = runner.backend._ctl(["list-units", "aos-*", "--all", "--no-legend"])
    assert not units.stdout.strip()


@pytest.mark.parametrize("operation", ["stat", "chmod", "setxattr"])
def test_abi_v3_metadata_operations_are_boundary_characterization(
    native_runner, layout, fixture_env, operation
):
    target = layout.denied_sibling_file
    original_mode = stat.S_IMODE(target.stat().st_mode)
    try:
        result = native_runner.run_scenario(
            "FS-13",
            cwd=layout.assigned_worktree,
            env=fixture_env,
            target=target,
            base=operation,
        )
        assert result.succeeded is True
        assert result.details["mode"] == operation
    finally:
        os.chmod(target, original_mode)
        try:
            os.removexattr(target, b"user.aos_probe")
        except OSError:
            pass


def test_abi_v3_does_not_claim_existing_pathname_unix_socket_isolation(
    native_runner, layout, fixture_env
):
    socket_path = layout.sockets_dir / "outside.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(socket_path))
        server.listen(1)
        result = native_runner.run_scenario(
            "FS-13",
            cwd=layout.assigned_worktree,
            env=fixture_env,
            target=socket_path,
            base="socket_connect",
        )
        assert result.succeeded is True
        assert result.details["mode"] == "socket_connect"
    finally:
        server.close()
        socket_path.unlink(missing_ok=True)


def test_native_worker_cancellation_reaches_forced_kill_and_recursive_empty(
    native_runner, layout, fixture_env
):
    process = native_runner.run(
        [
            sys.executable,
            "-c",
            "import signal,time; "
            "signal.signal(signal.SIGINT, signal.SIG_IGN); "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "time.sleep(60)",
        ],
        cwd=layout.assigned_worktree,
        env=fixture_env,
        timeout=0.5,
    )
    assert process.timed_out is True
    assert process.containment_state == ContainmentState.TERMINATED.value
    kinds = [record.kind for record in native_runner.collector.records]
    assert EV_FORCED_KILL_REQUESTED in kinds
    assert EV_CGROUP_EMPTY_VERIFIED in kinds
    units = native_runner.backend._ctl(
        ["list-units", "aos-*", "--all", "--no-legend"]
    )
    assert not units.stdout.strip()
