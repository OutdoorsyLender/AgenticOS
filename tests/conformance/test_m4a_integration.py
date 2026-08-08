"""Real-host integration tests for the Milestone 4A composed boundary."""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

from agenticos.sandbox.containment import (
    CancellationConfig,
    CgroupProcessRunner,
    ContainmentState,
    ContainmentUnavailableError,
)
from agenticos.sandbox.evidence import EvidenceCollector
from agenticos.sandbox.isolation import probe_landlock_enforcement
from agenticos.sandbox.runtime_boundary import (
    AuthorizedSource,
    M4AProfile,
    probe_bubblewrap,
    secure_open_source,
    build_worker_env,
)
from helpers import WORKER_PATH


pytestmark = [
    pytest.mark.m4a_linux,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux M4A boundary"),
]

FAST = CancellationConfig(
    sigint_grace=0.5,
    sigterm_grace=0.5,
    empty_verify_timeout=5.0,
    poll_interval=0.05,
)


@pytest.fixture(scope="session")
def m4a_launcher(tmp_path_factory):
    if not sys.platform.startswith("linux"):
        pytest.skip("requires Linux")
    import subprocess

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


@pytest.fixture(scope="session")
def m4a_host_ok():
    support = CgroupProcessRunner.probe()
    if not support.supported:
        pytest.skip("transient scopes unavailable: " + "; ".join(support.reasons))
    landlock_ok, reason = probe_landlock_enforcement()
    if not landlock_ok:
        pytest.skip(f"Landlock enforcement unavailable: {reason}")
    bwrap = probe_bubblewrap()
    if not bwrap.supported:
        pytest.fail("required Bubblewrap boundary unavailable: " + "; ".join(bwrap.reasons))


@pytest.fixture
def m4a_runner(layout, m4a_launcher, m4a_host_ok):
    from agenticos.sandbox.m4a_runner import NamespaceLandlockRunner

    synthetic_home = layout.root / "m4a-home"
    synthetic_home.mkdir()
    return NamespaceLandlockRunner(
        worker_path=WORKER_PATH,
        workspace=layout.assigned_worktree,
        profile=M4AProfile.BUILD,
        launcher_path=m4a_launcher,
        task_tmp=layout.task_tmp,
        synthetic_home=synthetic_home,
        cancellation=FAST,
        collector=EvidenceCollector(normalize_root=layout.root),
    )


def _runtime_runner(layout, m4a_launcher, profile):
    from agenticos.sandbox.m4a_runner import NamespaceLandlockRunner

    synthetic_home = layout.root / f"m4a-home-{profile.value}"
    synthetic_home.mkdir()
    return NamespaceLandlockRunner(
        worker_path=WORKER_PATH,
        workspace=layout.assigned_worktree,
        profile=profile,
        launcher_path=m4a_launcher,
        task_tmp=layout.task_tmp,
        synthetic_home=synthetic_home,
        cancellation=FAST,
        collector=EvidenceCollector(normalize_root=layout.root),
    )


def _run_worker(runner, *worker_args):
    process = runner.run(
        ["/usr/bin/python3", "/opt/agenticos/worker.py", *worker_args],
        cwd="/workspace",
        env={"AOS_HOST_ONLY": "AOS_CANARY_must_not_cross"},
    )
    assert process.exit_code == 0, process.stderr
    return process, json.loads(process.stdout)


def test_block_fd_ordering_and_normal_exit(m4a_runner, layout):
    marker = layout.task_tmp / "worker-entry-marker"
    process = m4a_runner.run(
        [
            "/usr/bin/python3",
            "-c",
            "from pathlib import Path; "
            "Path('/tmp/worker-entry-marker').write_text('ran'); "
            "print('m4a-ok')",
        ],
        cwd="/workspace",
        env={"OPENAI_API_KEY": "AOS_CANARY_openai"},
        _marker_path=marker,
    )

    assert process.exit_code == 0
    assert process.stdout.strip() == "m4a-ok"
    assert marker.read_text() == "ran"
    assert m4a_runner.last_ordering_observations == {
        "namespace_status_before_release": True,
        "namespace_verified_before_release": True,
        "launcher_entered_before_namespace_release": False,
        "worker_entered_before_namespace_release": False,
        "launcher_entered_after_namespace_release": True,
        "worker_entered_before_exec_release": False,
    }
    kinds = [record.kind for record in m4a_runner.collector.records]
    required_order = [
        "CONTAINMENT_VERIFIED",
        "NAMESPACE_BOUNDARY_VERIFIED",
        "TRUSTED_LAUNCHER_ENTERED",
        "FD_SET_SANITIZED",
        "SANDBOX_IDENTITIES_VERIFIED",
        "FILESYSTEM_POLICY_PREPARED",
        "NO_NEW_PRIVS_SET",
        "FILESYSTEM_POLICY_APPLIED",
        "WORKER_EXEC_ATTEMPTED",
        "CGROUP_EMPTY_VERIFIED",
    ]
    assert [kind for kind in kinds if kind in required_order] == required_order
    evidence = m4a_runner.last_namespace_evidence
    assert evidence is not None and evidence.verified is True
    assert process.containment_cgroup is not None
    assert process.containment_cgroup.endswith(evidence.child.cgroup)
    terminal = [
        record
        for record in m4a_runner.collector.records
        if record.kind == "RUNTIME_BOUNDARY_VERIFIED"
    ]
    assert len(terminal) == 1
    payload = terminal[0].payload
    assert payload["workspace_destination"] == "/workspace"
    assert payload["worker_cwd"] == "/workspace"
    assert payload["network_policy"] == "DENY"
    assert payload["containment_state"] == "TERMINATED"
    assert payload["landlock_abi"] == 3
    assert payload["namespace_identities"] == evidence.child.identities
    assert len(payload["filesystem_view_digest"]) == 64
    assert len(payload["environment_policy_digest"]) == 64
    assert len(payload["combined_policy_digest"]) == 64
    serialized = json.dumps(payload, sort_keys=True)
    assert str(layout.root) not in serialized
    assert str(layout.assigned_worktree) not in serialized
    assert "OPENAI_API_KEY" not in serialized


def test_large_authenticated_request_is_streamed_after_namespace_release(
    m4a_runner,
):
    large_arguments = ["x" * 4000 for _ in range(60)]
    process = m4a_runner.run(
        ["/usr/bin/python3", "-c", "print('large-request-ok')", *large_arguments],
        cwd="/workspace",
        env={},
    )

    assert process.exit_code == 0, process.stderr
    assert process.stdout.strip() == "large-request-ok"
    _assert_no_task_units(m4a_runner)


def test_controller_exception_after_hostile_exec_recursively_cleans_scope(
    m4a_runner, layout, monkeypatch
):
    marker = layout.task_tmp / "post-exec-controller-fault"
    original_communicate = m4a_runner._communicate_process
    calls = 0

    def fail_once(proc, timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            deadline = time.monotonic() + 3.0
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert marker.exists(), "worker did not enter before injected controller fault"
            raise RuntimeError("injected post-exec controller failure")
        return original_communicate(proc, timeout)

    monkeypatch.setattr(m4a_runner, "_communicate_process", fail_once)
    with pytest.raises(RuntimeError, match="post-exec controller failure"):
        m4a_runner.run(
            [
                "/usr/bin/python3",
                "-c",
                "from pathlib import Path; import time; "
                "Path('/tmp/post-exec-controller-fault').touch(); time.sleep(60)",
            ],
            cwd="/workspace",
            env={},
        )
    assert marker.exists()
    _assert_no_task_units(m4a_runner)


def test_unreadable_cgroup_evidence_is_not_treated_as_empty(
    m4a_runner, monkeypatch
):
    original_populated = m4a_runner.backend.cgroup_populated
    calls = 0

    def fail_once(cgroup_path):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise PermissionError("injected unreadable cgroup.events")
        return original_populated(cgroup_path)

    monkeypatch.setattr(m4a_runner.backend, "cgroup_populated", fail_once)
    with pytest.raises(PermissionError, match="unreadable cgroup.events"):
        m4a_runner.run(
            ["/usr/bin/python3", "-c", "print('worker-finished')"],
            cwd="/workspace",
            env={},
        )
    _assert_no_task_units(m4a_runner)


@pytest.mark.parametrize(
    ("profile", "write_allowed"),
    [(M4AProfile.INSPECT, False), (M4AProfile.BUILD, True)],
)
def test_workspace_identity_runtime_view_and_profiled_write(
    layout, m4a_launcher, m4a_host_ok, profile, write_allowed
):
    (layout.assigned_worktree / "host-locator-probe.txt").write_text(
        "\n".join(
            str(path)
            for path in (
                layout.assigned_worktree,
                layout.sibling_worktree,
                layout.agenticos_private,
                layout.fake_home,
            )
        )
    )
    runner = _runtime_runner(layout, m4a_launcher, profile)
    process, result = _run_worker(runner, "--scenario", "FS-16")

    assert result["succeeded"] is True, result
    details = result["details"]
    observed = details["workspace_identity"]
    authorized = layout.assigned_worktree.stat()
    assert (observed["device"], observed["inode"]) == (
        authorized.st_dev,
        authorized.st_ino,
    )
    assert details["cwd"] == "/workspace"
    assert details["pwd"] == "/workspace"
    assert details["fixed_paths"] == {
        path: True
        for path in (
            "/bin", "/dev", "/home", "/lib", "/lib64", "/opt", "/proc",
            "/run", "/sbin", "/tmp", "/usr", "/workspace",
        )
    }
    assert details["runtime_python"].startswith("/usr/bin/python3")
    assert details["workspace_canary_readable"] is True
    assert details["workspace_write_succeeded"] is write_allowed
    assert details["private_tmp_write_succeeded"] is True
    assert details["synthetic_home_write_succeeded"] is True
    assert details["sibling_visible"] is False
    assert details["agenticos_private_visible"] is False
    assert details["host_fake_home_visible"] is False
    assert details["windows_mount_visible"] is False
    assert details["host_locator_visibility"] == [False, False, False, False]
    assert "AOS_HOST_ONLY" not in details["environment_names"]
    assert str(layout.assigned_worktree) not in process.stdout


def test_substituted_workspace_source_is_rejected_before_hostile_exec(
    m4a_runner, layout, monkeypatch
):
    original_open = m4a_runner._open_runtime_sources
    marker = layout.task_tmp / "substituted-source-worker-ran"

    def substitute_source():
        sources = list(original_open())
        wrong = secure_open_source(layout.sibling_worktree, expected_type=stat.S_IFDIR)
        os.close(sources[0].fd)
        sources[0] = AuthorizedSource(
            sources[0].locator, wrong.fd, sources[0].identity
        )
        return tuple(sources)

    monkeypatch.setattr(m4a_runner, "_open_runtime_sources", substitute_source)
    with pytest.raises(ContainmentUnavailableError):
        m4a_runner.run(
            [
                "/usr/bin/python3", "-c",
                "from pathlib import Path; Path('/tmp/substituted-source-worker-ran').touch()",
            ],
            cwd="/workspace",
            env={},
            _marker_path=marker,
        )
    assert not marker.exists()


def test_workspace_replacement_after_authorization_mounts_opened_identity_safely(
    m4a_runner, layout, monkeypatch
):
    original_open = m4a_runner._open_runtime_sources
    authorized_object = layout.root / "authorized-object-after-rename"

    def replace_locator_after_open():
        sources = original_open()
        layout.assigned_worktree.rename(authorized_object)
        layout.assigned_worktree.mkdir()
        (layout.assigned_worktree / "allowed.txt").write_text("replacement")
        return sources

    monkeypatch.setattr(
        m4a_runner, "_open_runtime_sources", replace_locator_after_open
    )
    try:
        process = m4a_runner.run(
            [
                "/usr/bin/python3", "-c",
                "import os; print(os.stat('/workspace').st_ino); "
                "print(open('/workspace/allowed.txt').read().splitlines()[0])",
            ],
            cwd="/workspace",
            env={},
        )
        lines = process.stdout.splitlines()
        assert process.exit_code == 0
        assert int(lines[0]) == authorized_object.stat().st_ino
        assert lines[1] == "permitted worktree file"
    finally:
        if layout.assigned_worktree.exists():
            for child in layout.assigned_worktree.iterdir():
                child.unlink()
            layout.assigned_worktree.rmdir()
        if authorized_object.exists():
            authorized_object.rename(layout.assigned_worktree)


def test_changed_workspace_destination_is_rejected_before_hostile_exec(
    m4a_runner, layout, monkeypatch
):
    import agenticos.sandbox.m4a_runner as runner_module

    original_build = runner_module.build_bwrap_argv
    marker = layout.task_tmp / "changed-destination-worker-ran"

    def change_destination(plan, **kwargs):
        argv = original_build(plan, **kwargs)
        workspace_fd = str(plan.mount_for("/workspace").source.fd)
        for index, item in enumerate(argv):
            if item in ("--bind-fd", "--ro-bind-fd") and argv[index + 1] == workspace_fd:
                argv[index + 2] = "/unexpected-workspace"
                break
        return argv

    monkeypatch.setattr(runner_module, "build_bwrap_argv", change_destination)
    with pytest.raises(ContainmentUnavailableError):
        m4a_runner.run(
            [
                "/usr/bin/python3", "-c",
                "from pathlib import Path; Path('/tmp/changed-destination-worker-ran').touch()",
            ],
            cwd="/workspace",
            env={},
            _marker_path=marker,
        )
    assert not marker.exists()


def test_wrong_workspace_object_type_is_rejected_before_hostile_exec(
    m4a_runner, layout, monkeypatch
):
    original_open = m4a_runner._open_runtime_sources
    marker = layout.task_tmp / "wrong-type-worker-ran"
    wrong_file = layout.root / "wrong-workspace-object"
    wrong_file.write_text("not a directory")

    def substitute_wrong_type():
        sources = list(original_open())
        wrong = secure_open_source(wrong_file, expected_type=stat.S_IFREG)
        os.close(sources[0].fd)
        sources[0] = AuthorizedSource(
            sources[0].locator, wrong.fd, sources[0].identity
        )
        return tuple(sources)

    monkeypatch.setattr(m4a_runner, "_open_runtime_sources", substitute_wrong_type)
    with pytest.raises(ContainmentUnavailableError):
        m4a_runner.run(
            [
                "/usr/bin/python3", "-c",
                "from pathlib import Path; Path('/tmp/wrong-type-worker-ran').touch()",
            ],
            cwd="/workspace",
            env={},
            _marker_path=marker,
        )
    assert not marker.exists()


def test_credentials_capabilities_nested_userns_and_fds_are_closed(
    m4a_runner, layout
):
    fake_credentials = {
        "OPENAI_API_KEY": "AOS_CANARY_openai",
        "ANTHROPIC_API_KEY": "AOS_CANARY_anthropic",
        "AWS_ACCESS_KEY_ID": "AOS_CANARY_cloud",
        "SSH_AUTH_SOCK": str(layout.sockets_dir / "host-agent.sock"),
        "XDG_RUNTIME_DIR": str(layout.sockets_dir),
        "AOS_PROVIDER_CONFIG": str(layout.fake_credentials_file),
        "GIT_ASKPASS": str(layout.root / "host-askpass"),
    }
    outside_fd = os.open(layout.denied_sibling_file, os.O_RDONLY)
    controller_socket, leaked_socket = socket.socketpair()
    try:
        process = m4a_runner.run(
            [
                "/usr/bin/python3", "/opt/agenticos/worker.py",
                "--scenario", "PROC-09",
            ],
            cwd="/workspace",
            env=fake_credentials,
            _leak_fds=(outside_fd, leaked_socket.fileno()),
        )
    finally:
        os.close(outside_fd)
        controller_socket.close()
        leaked_socket.close()

    assert process.exit_code == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["succeeded"] is True, result
    details = result["details"]
    assert details["environment"] == build_worker_env()
    assert not set(fake_credentials).intersection(details["environment"])
    assert details["capabilities"] == {
        "CapInh": "0000000000000000",
        "CapPrm": "0000000000000000",
        "CapEff": "0000000000000000",
        "CapBnd": "0000000000000000",
        "CapAmb": "0000000000000000",
    }
    assert details["no_new_privs"] == "1"
    assert details["nested_userns_exit_code"] != 0
    assert details["open_fds"] == [0, 1, 2], details["fd_targets"]
    assert details["fds_beyond_stdio"] == []


def test_host_tcp_endpoint_is_unreachable_and_observes_no_connection(m4a_runner):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(0.2)
        target = f"127.0.0.1:{server.getsockname()[1]}"
        _, result = _run_worker(
            m4a_runner, "--scenario", "NET-02", "--target", target
        )
        assert result["succeeded"] is False
        with pytest.raises(TimeoutError):
            server.accept()
    finally:
        server.close()


def test_host_udp_endpoint_receives_no_datagram_or_response(m4a_runner):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server.bind(("127.0.0.1", 0))
        server.settimeout(0.2)
        target = f"127.0.0.1:{server.getsockname()[1]}"
        _, result = _run_worker(
            m4a_runner, "--scenario", "NET-03", "--target", target
        )
        assert result["succeeded"] is False
        assert result["details"]["response_received"] is False
        with pytest.raises(TimeoutError):
            server.recvfrom(256)
    finally:
        server.close()


def test_host_pathname_and_abstract_unix_sockets_are_unreachable(
    m4a_runner, layout
):
    abstract_name = "aos-host-" + uuid.uuid4().hex
    pathname = str(layout.sockets_dir / "host.sock")
    endpoints = [(pathname, pathname), ("\0" + abstract_name, "@" + abstract_name)]
    for bind_target, worker_target in endpoints:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(bind_target)
            server.listen(1)
            server.settimeout(0.2)
            scenario = "SOCK-02" if worker_target.startswith("@") else "SOCK-01"
            _, result = _run_worker(
                m4a_runner, "--scenario", scenario, "--target", worker_target
            )
            assert result["succeeded"] is False
            with pytest.raises(TimeoutError):
                server.accept()
        finally:
            server.close()
            if not bind_target.startswith("\0"):
                Path(bind_target).unlink(missing_ok=True)


def test_sandbox_private_tmp_unix_socket_works(m4a_runner):
    _, result = _run_worker(m4a_runner, "--scenario", "SOCK-03")
    assert result["succeeded"] is True, result
    assert result["details"]["private_exchange"] is True


def test_connected_socket_negative_control_and_production_sanitation(
    m4a_runner
):
    control, inherited = socket.socketpair()
    control.settimeout(2.0)
    try:
        canary = b"AOS_CANARY_namespace_only_connected_socket"
        completed = subprocess.run(
            [
                "/usr/bin/unshare", "--user", "--map-root-user", "--net",
                "--fork", sys.executable, "-c",
                "import os,sys; os.write(int(sys.argv[1]), " + repr(canary) + ")",
                str(inherited.fileno()),
            ],
            pass_fds=(inherited.fileno(),),
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert control.recv(256) == canary
    finally:
        control.close()
        inherited.close()

    controller_peer, leaked_peer = socket.socketpair()
    controller_peer.settimeout(0.2)
    try:
        process = m4a_runner.run(
            [
                "/usr/bin/python3", "/opt/agenticos/worker.py",
                "--scenario", "SOCK-04", "--target", str(leaked_peer.fileno()),
            ],
            cwd="/workspace",
            env={},
            _leak_fds=(leaked_peer.fileno(),),
        )
        assert process.exit_code == 0, process.stderr
        result = json.loads(process.stdout)
        assert result["succeeded"] is False
        assert result["details"]["errno"] == 9
        with pytest.raises(TimeoutError):
            controller_peer.recv(256)
    finally:
        controller_peer.close()
        leaked_peer.close()


def _assert_no_task_units(runner):
    units = runner.backend._ctl(["list-units", "aos-*", "--all", "--no-legend"])
    assert not units.stdout.strip()


@pytest.mark.parametrize(
    ("scenario", "target"),
    [
        ("PROC-01", None),
        ("PROC-02", None),
        ("PROC-03", None),
        ("PROC-04", None),
        ("PROC-05", "/tmp/m4a-lingering-heartbeat"),
        ("PROC-06", "/tmp/m4a-double-fork-heartbeat"),
        ("PROC-07", None),
        ("PROC-08", "/tmp/m4a-new-pgroup-heartbeat"),
    ],
)
def test_descendant_shapes_inherit_boundary_and_finish_with_empty_cgroup(
    m4a_runner, scenario, target
):
    args = ["--scenario", scenario]
    if target is not None:
        args += ["--target", target]
    process, result = _run_worker(m4a_runner, *args)
    assert result["succeeded"] is True, result
    assert process.containment_state == ContainmentState.TERMINATED.value
    _assert_no_task_units(m4a_runner)


def test_timeout_cancels_signal_ignoring_worker_and_drains_scope(m4a_runner):
    process = m4a_runner.run(
        [
            "/usr/bin/python3", "-c",
            "import signal,time; "
            "signal.signal(signal.SIGINT, signal.SIG_IGN); "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
        ],
        cwd="/workspace",
        env={},
        timeout=0.3,
    )
    assert process.timed_out is True
    assert process.containment_state == ContainmentState.TERMINATED.value
    _assert_no_task_units(m4a_runner)


def test_namespace_evidence_failure_never_releases_hostile_exec_and_cleans_up(
    m4a_runner, layout, monkeypatch
):
    import agenticos.sandbox.m4a_runner as runner_module

    marker = layout.task_tmp / "namespace-fault-worker-ran"

    def reject_namespace(*args, **kwargs):
        raise runner_module.NamespaceEvidenceError("injected namespace mismatch")

    monkeypatch.setattr(runner_module, "verify_namespace_evidence", reject_namespace)
    with pytest.raises(ContainmentUnavailableError, match="namespace mismatch"):
        m4a_runner.run(
            [
                "/usr/bin/python3", "-c",
                "from pathlib import Path; Path('/tmp/namespace-fault-worker-ran').touch()",
            ],
            cwd="/workspace",
            env={},
            _marker_path=marker,
        )
    assert not marker.exists()
    _assert_no_task_units(m4a_runner)


def test_post_namespace_landlock_failure_never_executes_worker_and_cleans_up(
    m4a_runner, layout, monkeypatch
):
    import agenticos.sandbox.m4a_runner as runner_module

    original_build = runner_module.build_bwrap_argv
    marker = layout.task_tmp / "landlock-fault-worker-ran"

    def inject_fault(plan, **kwargs):
        argv = original_build(plan, **kwargs)
        command_index = argv.index("--")
        argv[command_index:command_index] = [
            "--setenv", "AOS_LAUNCHER_FAULT_INJECT", "fail_ruleset"
        ]
        return argv

    monkeypatch.setattr(runner_module, "build_bwrap_argv", inject_fault)
    with pytest.raises(ContainmentUnavailableError):
        m4a_runner.run(
            [
                "/usr/bin/python3", "-c",
                "from pathlib import Path; Path('/tmp/landlock-fault-worker-ran').touch()",
            ],
            cwd="/workspace",
            env={},
            _marker_path=marker,
        )
    assert not marker.exists()
    assert m4a_runner.last_launch_outcome["failed_stage"] == "ruleset"
    _assert_no_task_units(m4a_runner)


def test_controller_exception_before_exec_release_cleans_up_without_worker(
    m4a_runner, layout, monkeypatch
):
    import agenticos.sandbox.m4a_runner as runner_module

    marker = layout.task_tmp / "controller-fault-worker-ran"

    def fail_parse(*args, **kwargs):
        raise RuntimeError("injected controller parse failure")

    monkeypatch.setattr(runner_module, "parse_launcher_status", fail_parse)
    with pytest.raises(RuntimeError, match="controller parse failure"):
        m4a_runner.run(
            [
                "/usr/bin/python3", "-c",
                "from pathlib import Path; Path('/tmp/controller-fault-worker-ran').touch()",
            ],
            cwd="/workspace",
            env={},
            _marker_path=marker,
        )
    assert not marker.exists()
    _assert_no_task_units(m4a_runner)


def test_missing_workspace_source_fails_before_process_creation(
    m4a_runner, layout
):
    moved = layout.root / "workspace-temporarily-missing"
    layout.assigned_worktree.rename(moved)
    try:
        with pytest.raises(Exception, match="source|No such file|resolve"):
            m4a_runner.run(
                ["/usr/bin/true"], cwd="/workspace", env={}
            )
        _assert_no_task_units(m4a_runner)
    finally:
        moved.rename(layout.assigned_worktree)


def test_failed_worker_exec_after_authenticated_policy_is_fail_closed(
    m4a_runner
):
    with pytest.raises(ContainmentUnavailableError, match="launcher failed at exec"):
        m4a_runner.run(
            ["/usr/bin/agenticos-definitely-missing"],
            cwd="/workspace",
            env={},
        )
    assert m4a_runner.last_launch_outcome["failed_stage"] == "exec"
    assert m4a_runner.last_launch_outcome["policy_applied"] is True
    assert m4a_runner.last_launch_outcome["exec_succeeded"] is False
    _assert_no_task_units(m4a_runner)
