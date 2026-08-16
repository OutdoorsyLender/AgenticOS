from __future__ import annotations

import errno
import mmap
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import textwrap
import threading
import time
import types

import pytest

from agenticos.providers.kimi_local_auth_freezer import FreezerError, WorkloadCgroup
from agenticos.providers import kimi_local_auth_runtime as runtime
from tests.providers.test_kimi_local_auth_freezer import (
    AUTHENTICATE_SUCCESS,
    INITIALIZE_SUCCESS,
)


_NATIVE_CHILD = "AOS_KIMI_FREEZER_NATIVE_CHILD"
_UNIT = "aos-kimi-level1-local-auth"


def _inside_delegated_service(node_id: str) -> None:
    repository = Path(__file__).resolve().parents[2]
    uid = os.getuid()
    service_cgroup = (
        f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/"
        f"app.slice/{_UNIT}.service"
    )
    command = [
        "/usr/bin/systemd-run",
        "--user",
        f"--unit={_UNIT}",
        "--service-type=exec",
        "--wait",
        "--collect",
        "--pipe",
        "--quiet",
        f"--working-directory={repository}",
        "--property=Delegate=yes",
        "--property=KillMode=control-group",
        "--property=SendSIGKILL=yes",
        "--property=TimeoutStopSec=5s",
        "--property=Restart=no",
        "--property=TasksMax=21",
        "--property=MemoryMax=1G",
        "--property=ProtectControlGroups=yes",
        f"--property=BindPaths={service_cgroup}",
        "/usr/bin/env",
        f"{_NATIVE_CHILD}=1",
        sys.executable,
        "-m",
        "pytest",
        "-q",
        node_id,
    ]
    completed = subprocess.run(
        command,
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.skipif(os.name != "posix", reason="native Linux cgroup-v2 required")
def test_freezer_native_a_b_c_direct_topology_freeze_thaw_and_frozen_kill() -> None:
    if os.environ.get(_NATIVE_CHILD) != "1":
        _inside_delegated_service(
            "tests/providers/test_kimi_local_auth_freezer_linux.py::"
            "test_freezer_native_a_b_c_direct_topology_freeze_thaw_and_frozen_kill"
        )
        return

    workload = WorkloadCgroup.create()
    process = workload.spawn(
        [
            sys.executable,
            "-c",
            textwrap.dedent(
                """
                import os
                import threading
                import time

                inner = os.fork()
                if inner == 0:
                    provider = os.fork()
                    if provider == 0:
                        thread = threading.Thread(
                            target=lambda: time.sleep(60),
                            daemon=False,
                        )
                        thread.start()
                        thread.join()
                        os._exit(0)
                    os.waitpid(provider, 0)
                    os._exit(0)
                os.waitpid(inner, 0)
                """
            ),
        ],
        pass_fds=(),
    )
    deadline = time.monotonic() + 5.0
    try:
        while True:
            raw_processes = workload._read_ids(workload._controls["procs"])
            raw_threads = workload._read_ids(workload._controls["threads"])
            if process.poll() is not None:
                pytest.fail(f"direct child exited early: {process.returncode}")
            if len(raw_processes) == 3 and len(raw_threads) == 4:
                snapshot = workload.checkpoint()
                break
            if time.monotonic() >= deadline:
                pytest.fail(
                    f"full topology not observed: {raw_processes}/{raw_threads}"
                )
            time.sleep(0.005)
        assert process.pid in snapshot.process_ids
        assert os.getpid() not in snapshot.thread_ids

        workload.request_freeze()
        assert workload.await_events(populated=True, frozen=True, deadline=deadline).frozen
        assert workload.checkpoint(expected=snapshot) == snapshot

        workload.request_thaw()
        thawed = workload.await_events(populated=True, frozen=False, deadline=deadline)
        assert thawed.populated is True
        assert workload.checkpoint(expected=snapshot) == snapshot

        workload.request_freeze()
        workload.await_events(populated=True, frozen=True, deadline=deadline)
        workload.kill_and_drain(process, deadline=deadline)
        assert workload.await_events(populated=False, frozen=None, deadline=deadline).populated is False
    finally:
        workload.close(process=process, deadline=time.monotonic() + 5.0)

    assert process.poll() is not None


@pytest.mark.skipif(os.name != "posix", reason="native Linux cgroup-v2 required")
def test_freezer_native_b_counter_stops_only_at_frozen_1_and_resumes_after_thaw() -> None:
    if os.environ.get(_NATIVE_CHILD) != "1":
        _inside_delegated_service(
            "tests/providers/test_kimi_local_auth_freezer_linux.py::"
            "test_freezer_native_b_counter_stops_only_at_frozen_1_and_resumes_after_thaw"
        )
        return

    counter_fd = os.memfd_create("aos-freezer-counter", os.MFD_CLOEXEC)
    os.ftruncate(counter_fd, 8)
    counter = mmap.mmap(counter_fd, 8, flags=mmap.MAP_SHARED)
    workload = WorkloadCgroup.create()
    process = workload.spawn(
        [
            sys.executable,
            "-c",
            textwrap.dedent(
                f"""
                import mmap
                import struct
                import time
                shared = mmap.mmap({counter_fd}, 8, flags=mmap.MAP_SHARED)
                value = 0
                while True:
                    value += 1
                    struct.pack_into('Q', shared, 0, value)
                    time.sleep(0.001)
                """
            ),
        ],
        pass_fds=(counter_fd,),
    )
    deadline = time.monotonic() + 5.0
    try:
        while struct.unpack_from("Q", counter)[0] < 10:
            if time.monotonic() >= deadline:
                pytest.fail("synthetic workload counter did not start")
            time.sleep(0.002)
        workload.request_freeze()
        workload.await_events(populated=True, frozen=True, deadline=deadline)
        frozen_value = struct.unpack_from("Q", counter)[0]
        time.sleep(0.05)
        assert struct.unpack_from("Q", counter)[0] == frozen_value
        workload.request_thaw()
        workload.await_events(populated=True, frozen=False, deadline=deadline)
        while struct.unpack_from("Q", counter)[0] == frozen_value:
            if time.monotonic() >= deadline:
                pytest.fail("synthetic workload counter did not resume")
            time.sleep(0.002)
        workload.kill_and_drain(process, deadline=deadline)
    finally:
        workload.close(process=process, deadline=deadline)
        counter.close()
        os.close(counter_fd)


@pytest.mark.skipif(os.name != "posix", reason="native Linux cgroup-v2 required")
def test_freezer_native_b_fork_racing_freeze_revokes_stale_membership() -> None:
    if os.environ.get(_NATIVE_CHILD) != "1":
        _inside_delegated_service(
            "tests/providers/test_kimi_local_auth_freezer_linux.py::"
            "test_freezer_native_b_fork_racing_freeze_revokes_stale_membership"
        )
        return

    trigger_read, trigger_write = os.pipe2(os.O_CLOEXEC)
    workload = WorkloadCgroup.create()
    process = workload.spawn(
        [
            sys.executable,
            "-c",
            textwrap.dedent(
                f"""
                import os
                import time
                os.write(1, b'R')
                if os.read({trigger_read}, 1) != b'F':
                    os._exit(90)
                for _index in range(8):
                    child = os.fork()
                    if child == 0:
                        time.sleep(30)
                        os._exit(0)
                time.sleep(30)
                """
            ),
        ],
        pass_fds=(trigger_read,),
    )
    os.close(trigger_read)
    deadline = time.monotonic() + 5.0
    try:
        assert process.stdout.read(1) == b"R"
        baseline = workload.checkpoint()
        os.write(trigger_write, b"F")
        os.sched_yield()
        workload.request_freeze()
        workload.await_events(populated=True, frozen=True, deadline=deadline)
        frozen = workload.checkpoint()
        assert len(frozen.process_ids) > len(baseline.process_ids)
        with pytest.raises(FreezerError) as rejected:
            workload.checkpoint(expected=baseline)
        assert rejected.value.code == "LOCAL_AUTH_CGROUP_MEMBERSHIP"
        workload.kill_and_drain(process, deadline=deadline)
    finally:
        os.close(trigger_write)
        workload.close(process=process, deadline=deadline)


@pytest.mark.parametrize("failed_role", ["inner", "provider"])
@pytest.mark.skipif(os.name != "posix", reason="native Linux pidfd required")
def test_freezer_native_c_expected_role_death_while_frozen_is_terminal(
    failed_role: str,
) -> None:
    if os.environ.get(_NATIVE_CHILD) != "1":
        _inside_delegated_service(
            "tests/providers/test_kimi_local_auth_freezer_linux.py::"
            f"test_freezer_native_c_expected_role_death_while_frozen_is_terminal[{failed_role}]"
        )
        return

    workload = WorkloadCgroup.create()
    process = workload.spawn(
        [
            sys.executable,
            "-c",
            textwrap.dedent(
                """
                import os
                import time
                inner = os.fork()
                if inner == 0:
                    provider = os.fork()
                    if provider == 0:
                        time.sleep(30)
                        os._exit(0)
                    os.write(1, f'{os.getpid()} {provider}\\n'.encode('ascii'))
                    os.waitpid(provider, 0)
                    os._exit(0)
                os.waitpid(inner, 0)
                """
            ),
        ],
        pass_fds=(),
    )
    inner_pid, provider_pid = (
        int(value) for value in process.stdout.readline().decode("ascii").split()
    )
    deadline = time.monotonic() + 5.0
    roles = None
    try:
        while True:
            snapshot = workload.checkpoint()
            if len(snapshot.process_ids) == 3:
                break
            if time.monotonic() >= deadline:
                pytest.fail("synthetic role topology did not stabilize")
            time.sleep(0.005)
        pidfds = tuple(os.pidfd_open(pid, 0) for pid in snapshot.process_ids)
        roles = runtime.LocalAuthRoles(
            records=tuple(
                runtime._read_live_process_record(pid) for pid in snapshot.process_ids
            ),
            pidfds=pidfds,
            outer_pid=process.pid,
            inner_pid=inner_pid,
            provider_pid=provider_pid,
        )
        workload.request_freeze()
        workload.await_events(populated=True, frozen=True, deadline=deadline)
        os.kill(inner_pid if failed_role == "inner" else provider_pid, signal.SIGKILL)
        while runtime._pidfds_are_live(roles.pidfds):
            if time.monotonic() >= deadline:
                pytest.fail("killed frozen role pidfd never became readable")
            time.sleep(0.002)
        with pytest.raises(runtime.KimiLocalAuthRuntimeError) as rejected:
            runtime._validate_local_auth_topology(
                workload,
                process,
                snapshot,
                [sys.executable],
                roles,
                provider_executable=Path(sys.executable),
            )
        assert rejected.value.code == "LOCAL_AUTH_CGROUP_TOPOLOGY"
    finally:
        if roles is not None:
            roles.close()
        workload.close(process=process, deadline=deadline)


@pytest.mark.skipif(os.name != "posix", reason="native Linux cgroup-v2 required")
def test_freezer_native_c_mode_drift_is_terminal_and_never_resurrected() -> None:
    if os.environ.get(_NATIVE_CHILD) != "1":
        _inside_delegated_service(
            "tests/providers/test_kimi_local_auth_freezer_linux.py::"
            "test_freezer_native_c_mode_drift_is_terminal_and_never_resurrected"
        )
        return

    workload = WorkloadCgroup.create()
    workload_path = Path(
        "/sys/fs/cgroup" + workload.controller.unit_relative + "/workload"
    )
    workload_path.chmod(0o755)
    with pytest.raises(FreezerError) as rejected:
        workload.checkpoint()
    assert rejected.value.code == "LOCAL_AUTH_CGROUP_IDENTITY"
    with pytest.raises(FreezerError) as cleanup_rejected:
        workload.close(process=None, deadline=time.monotonic() + 1.0)
    assert cleanup_rejected.value.code == "LOCAL_AUTH_CGROUP_IDENTITY"


@pytest.mark.skipif(os.name != "posix", reason="native Linux signal ABI required")
def test_freezer_native_a_clone_child_restores_signal_defaults_and_mask(
    tmp_path: Path,
) -> None:
    if os.environ.get(_NATIVE_CHILD) != "1":
        _inside_delegated_service(
            "tests/providers/test_kimi_local_auth_freezer_linux.py::"
            "test_freezer_native_a_clone_child_restores_signal_defaults_and_mask"
        )
        return

    source = tmp_path / "signal_probe.c"
    executable = tmp_path / "signal_probe"
    source.write_text(
        textwrap.dedent(
            """
            #define _GNU_SOURCE
            #include <signal.h>
            #include <unistd.h>
            int main(void) {
                sigset_t mask;
                struct sigaction action;
                if (sigprocmask(SIG_SETMASK, 0, &mask) != 0) return 90;
                for (int value = 1; value < NSIG; value++) {
                    if (sigismember(&mask, value) == 1) return 91;
                }
                if (sigaction(SIGPIPE, 0, &action) != 0 || action.sa_handler != SIG_DFL) return 92;
            #ifdef SIGXFZ
                if (sigaction(SIGXFZ, 0, &action) != 0 || action.sa_handler != SIG_DFL) return 93;
            #endif
            #ifdef SIGXFSZ
                if (sigaction(SIGXFSZ, 0, &action) != 0 || action.sa_handler != SIG_DFL) return 94;
            #endif
                if (write(1, "R", 1) != 1) return 95;
                for (;;) pause();
            }
            """
        ),
        encoding="ascii",
    )
    subprocess.run(
        ["/usr/bin/cc", "-std=c11", "-Wall", "-Werror", str(source), "-o", str(executable)],
        check=True,
        timeout=10,
    )
    workload = WorkloadCgroup.create()
    process = workload.spawn([str(executable)], pass_fds=())
    deadline = time.monotonic() + 5.0
    try:
        assert process.stdout.read(1) == b"R", process.poll()
        snapshot = workload.checkpoint()
        assert snapshot.process_ids == (process.pid,)
        workload.request_freeze()
        workload.await_events(populated=True, frozen=True, deadline=deadline)
        workload.kill_and_drain(process, deadline=deadline)
    finally:
        workload.close(process=process, deadline=deadline)


@pytest.mark.skipif(os.name != "posix", reason="native Linux cgroup-v2 required")
def test_freezer_native_a_controller_thread_unit_entry_and_sibling_block() -> None:
    if os.environ.get(_NATIVE_CHILD) != "1":
        _inside_delegated_service(
            "tests/providers/test_kimi_local_auth_freezer_linux.py::"
            "test_freezer_native_a_controller_thread_unit_entry_and_sibling_block"
        )
        return

    blocker = threading.Event()
    thread = threading.Thread(target=blocker.wait)
    workload = WorkloadCgroup.create()
    thread.start()
    try:
        with pytest.raises(FreezerError) as rejected:
            workload.checkpoint()
        assert rejected.value.code == "LOCAL_AUTH_CONTROLLER_THREAD"
    finally:
        blocker.set()
        thread.join(timeout=2)
        workload.close(process=None, deadline=time.monotonic() + 2.0)

    workload = WorkloadCgroup.create()
    os.mkdir("sibling", mode=0o700, dir_fd=workload.unit_fd)
    try:
        with pytest.raises(FreezerError) as rejected:
            workload.checkpoint()
        assert rejected.value.code == "LOCAL_AUTH_CGROUP_TOPOLOGY"
    finally:
        os.rmdir("sibling", dir_fd=workload.unit_fd)
        workload.close(process=None, deadline=time.monotonic() + 2.0)

    workload = WorkloadCgroup.create()
    sibling = os.fork()
    if sibling == 0:
        time.sleep(30)
        os._exit(0)
    try:
        with pytest.raises(FreezerError) as rejected:
            workload.checkpoint()
        assert rejected.value.code == "LOCAL_AUTH_CGROUP_MEMBERSHIP"
    finally:
        os.kill(sibling, signal.SIGKILL)
        os.waitpid(sibling, 0)
        workload.close(process=None, deadline=time.monotonic() + 2.0)


@pytest.mark.skipif(os.name != "posix", reason="native Linux cgroup-v2 required")
def test_freezer_native_e_delegation_cannot_create_outside_service_boundary() -> None:
    if os.environ.get(_NATIVE_CHILD) != "1":
        _inside_delegated_service(
            "tests/providers/test_kimi_local_auth_freezer_linux.py::"
            "test_freezer_native_e_delegation_cannot_create_outside_service_boundary"
        )
        return

    workload = WorkloadCgroup.create()
    uid = os.getuid()
    root = Path("/sys/fs/cgroup")
    outside_parents = (
        root,
        root / "user.slice",
        root / "user.slice" / f"user-{uid}.slice",
        root / "user.slice" / f"user-{uid}.slice" / f"user@{uid}.service",
        root / "user.slice" / f"user-{uid}.slice" / f"user@{uid}.service" / "app.slice",
        root / "system.slice",
    )
    try:
        assert workload.checkpoint() == runtime.WorkloadSnapshot((), ())
        for index, parent in enumerate(outside_parents):
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            name = f"aos-kimi-authority-probe-{os.getpid()}-{index}"
            try:
                try:
                    os.mkdir(name, mode=0o700, dir_fd=descriptor)
                except OSError as rejected:
                    assert rejected.errno in {
                        errno.EACCES,
                        errno.EPERM,
                        errno.EROFS,
                    }
                else:
                    os.rmdir(name, dir_fd=descriptor)
                    pytest.fail(f"delegated controller created cgroup outside service: {parent}")
            finally:
                try:
                    os.rmdir(name, dir_fd=descriptor)
                except OSError:
                    pass
                os.close(descriptor)
        alias_probe = f"aos-kimi-proc-root-probe-{os.getpid()}"
        for process_root in Path("/proc").iterdir():
            if not process_root.name.isdecimal() or int(process_root.name) == os.getpid():
                continue
            alias_parent = (
                process_root
                / "root/sys/fs/cgroup/user.slice"
                / f"user-{uid}.slice"
                / f"user@{uid}.service"
            )
            try:
                descriptor = os.open(
                    alias_parent,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                )
            except OSError as rejected:
                assert rejected.errno in {
                    errno.EACCES,
                    errno.ENOENT,
                    errno.EPERM,
                }
                continue
            try:
                try:
                    os.mkdir(alias_probe, mode=0o700, dir_fd=descriptor)
                except OSError as rejected:
                    assert rejected.errno in {
                        errno.EACCES,
                        errno.EPERM,
                        errno.EROFS,
                    }
                else:
                    os.rmdir(alias_probe, dir_fd=descriptor)
                    pytest.fail(
                        f"controller escaped cgroup mount through {process_root}/root"
                    )
            finally:
                try:
                    os.rmdir(alias_probe, dir_fd=descriptor)
                except OSError:
                    pass
                os.close(descriptor)
        assert workload.checkpoint() == runtime.WorkloadSnapshot((), ())
    finally:
        workload.close(process=None, deadline=time.monotonic() + 2.0)


@pytest.mark.skipif(os.name != "posix", reason="native Linux cgroup-v2 required")
def test_freezer_native_a_workload_entry_and_escape_block_before_capture() -> None:
    if os.environ.get(_NATIVE_CHILD) != "1":
        _inside_delegated_service(
            "tests/providers/test_kimi_local_auth_freezer_linux.py::"
            "test_freezer_native_a_workload_entry_and_escape_block_before_capture"
        )
        return

    workload = WorkloadCgroup.create()
    entrant = os.fork()
    if entrant == 0:
        time.sleep(30)
        os._exit(0)
    workload_path = Path(
        "/sys/fs/cgroup" + workload.controller.unit_relative + "/workload"
    )
    (workload_path / "cgroup.procs").write_text(f"{entrant}\n", encoding="ascii")
    try:
        with pytest.raises(FreezerError) as rejected:
            workload.checkpoint(expected=runtime.WorkloadSnapshot((), ()))
        assert rejected.value.code == "LOCAL_AUTH_CGROUP_MEMBERSHIP"
    finally:
        workload._cleanup_bound(process=None, deadline=time.monotonic() + 2.0)
        os.waitpid(entrant, 0)
        workload.close(process=None, deadline=time.monotonic() + 2.0)

    workload = WorkloadCgroup.create()
    process = workload.spawn([sys.executable, "-c", "import time; time.sleep(30)"], pass_fds=())
    deadline = time.monotonic() + 5.0
    snapshot = workload.checkpoint()
    unit_path = Path("/sys/fs/cgroup" + workload.controller.unit_relative)
    (unit_path / "cgroup.procs").write_text(f"{process.pid}\n", encoding="ascii")
    try:
        with pytest.raises(FreezerError) as rejected:
            workload.checkpoint(expected=snapshot)
        assert rejected.value.code == "LOCAL_AUTH_CGROUP_MEMBERSHIP"
    finally:
        os.kill(process.pid, signal.SIGKILL)
        process.wait(timeout=2)
        workload.close(process=process, deadline=deadline)


@pytest.mark.skipif(os.name != "posix", reason="native Linux cgroup-v2 required")
def test_freezer_native_b_eof_sensitive_runner_stays_live_through_capture_and_thaw(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.environ.get(_NATIVE_CHILD) != "1":
        _inside_delegated_service(
            "tests/providers/test_kimi_local_auth_freezer_linux.py::"
            "test_freezer_native_b_eof_sensitive_runner_stays_live_through_capture_and_thaw"
        )
        return

    fixture_root = tmp_path / "synthetic-fixtures"
    fixture_root.mkdir(mode=0o700)
    for name in ("agent.md", "config.toml", "kimi-code.json"):
        (fixture_root / name).write_text(f"synthetic-{name}\n", encoding="ascii")
    expected_environment = runtime.build_kimi_environment()
    fixture = textwrap.dedent(
        f"""
        import os
        import sys
        import threading

        initialize = {INITIALIZE_SUCCESS!r}
        authenticate = {AUTHENTICATE_SUCCESS!r}
        if dict(os.environ) != {expected_environment!r}:
            os._exit(80)
        stop = threading.Event()
        worker = threading.Thread(target=stop.wait)
        worker.start()
        if not sys.stdin.buffer.readline():
            os._exit(81)
        sys.stdout.buffer.write(initialize)
        sys.stdout.buffer.flush()
        if not sys.stdin.buffer.readline():
            os._exit(82)
        sys.stdout.buffer.write(authenticate)
        sys.stdout.buffer.flush()
        if sys.stdin.buffer.read() != b'':
            os._exit(83)
        stop.set()
        worker.join()
        """
    )
    common = [
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/lib", "/lib",
        "--ro-bind", "/lib64", "/lib64",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
    ]
    launch = [
        "/usr/bin/bwrap",
        *common,
        "--dir", "/workspace",
        "--dir", "/home",
        "--dir", "/home/aos",
        "--dir", "/home/aos/kimi",
        "--dir", "/home/aos/kimi/agents",
        "--dir", "/home/aos/kimi/credentials",
        "--ro-bind", str(fixture_root / "agent.md"), "/home/aos/kimi/agents/agent.md",
        "--ro-bind", str(fixture_root / "config.toml"), "/home/aos/kimi/config.toml",
        "--ro-bind", str(fixture_root / "kimi-code.json"), "/home/aos/kimi/credentials/kimi-code.json",
        "--clearenv",
    ]
    for name, value in expected_environment.items():
        launch.extend(("--setenv", name, value))
    launch.extend(("--chdir", "/workspace", "--", sys.executable, "-c", fixture))
    synthetic_credential = fixture_root / "credential-leaf.json"
    synthetic_credential.write_text("synthetic-known-credential\n", encoding="ascii")
    descriptor = os.open(synthetic_credential, os.O_PATH | os.O_CLOEXEC)
    credential_source = launch.index(str(fixture_root / "kimi-code.json"))
    launch[credential_source - 1 : credential_source + 1] = [
        "--ro-bind-fd",
        str(descriptor),
    ]
    credential_info = os.fstat(descriptor)
    credential = runtime.CredentialLeafHandle(
        descriptor,
        credential_info.st_dev,
        credential_info.st_ino,
        credential_info.st_uid,
        credential_info.st_mode & 0o777,
        credential_info.st_nlink,
    )
    spec = runtime.KimiLocalAuthSpec(
        executable=Path(sys.executable),
        bundle=tmp_path / "bundle",
        namespace_launcher=tmp_path / "launcher",
        state_root=tmp_path / "state",
        evidence_root=tmp_path / "evidence",
    )
    monkeypatch.setattr(
        runtime,
        "build_local_auth_bwrap_argv",
        lambda observed_spec, observed_credential: launch
        if observed_spec is spec and observed_credential is credential
        else pytest.fail("synthetic runner changed launch inputs"),
    )

    def topology(_workload, process, snapshot, _argv, roles):
        try:
            return runtime._validate_local_auth_topology(
                _workload,
                process,
                snapshot,
                _argv,
                roles,
                provider_executable=Path(sys.executable),
            )
        except runtime.KimiLocalAuthRuntimeError as exc:
            records = tuple(
                runtime._read_live_process_record(pid)
                for pid in snapshot.process_ids
            )
            raise AssertionError((exc.code, snapshot, process.pid, records)) from exc

    outcome = runtime.run_local_auth(
        spec,
        credential,
        topology_validator=topology,
        timeout_seconds=5.0,
    )

    assert outcome.protocol.qualification.value == "COMPLETE", outcome
    assert outcome.protocol.credential_state.value == "LOADABLE"
    assert outcome.reason_code == "ACP_LOCAL_AUTH_SUCCESS"
    assert outcome.census.cleanup_complete is True


@pytest.mark.parametrize(
    ("script", "reason_code"),
    [
        ("import sys; sys.stdin.buffer.read(); sys.stdout.write('late')", "LOCAL_AUTH_LATE_OUTPUT"),
        ("import sys; sys.stdin.buffer.read(); raise SystemExit(42)", "LOCAL_AUTH_PROCESS_CRASH"),
        (
            "import os, signal, sys; sys.stdin.buffer.read(); os.kill(os.getpid(), signal.SIGSYS)",
            "LOCAL_AUTH_NETWORK_POLICY_VIOLATION",
        ),
    ],
)
def test_freezer_native_d_post_eof_drain_rejects_late_output_and_fatal_exit(
    script: str,
    reason_code: str,
) -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    process.stdin.close()
    try:
        with pytest.raises(runtime._LocalAuthRunFailure) as rejected:
            runtime._validate_post_eof_drain(
                process,
                process.stdout,
                process.stderr,
                deadline=time.monotonic() + 5.0,
                monotonic=time.monotonic,
            )
        assert rejected.value.code == reason_code
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


@pytest.mark.skipif(os.name != "posix", reason="native Linux cgroup-v2 required")
def test_freezer_native_c_freeze_timeout_reserves_cleanup_and_removes_cgroup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.environ.get(_NATIVE_CHILD) != "1":
        _inside_delegated_service(
            "tests/providers/test_kimi_local_auth_freezer_linux.py::"
            "test_freezer_native_c_freeze_timeout_reserves_cleanup_and_removes_cgroup"
        )
        return

    synthetic_credential = tmp_path / "synthetic-credential.json"
    synthetic_credential.write_text("known-synthetic\n", encoding="ascii")
    descriptor = os.open(synthetic_credential, os.O_PATH | os.O_CLOEXEC)
    info = os.fstat(descriptor)
    credential = runtime.CredentialLeafHandle(
        descriptor,
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode & 0o777,
        info.st_nlink,
    )
    spec = runtime.KimiLocalAuthSpec(
        executable=Path(sys.executable),
        bundle=tmp_path / "bundle",
        namespace_launcher=tmp_path / "launcher",
        state_root=tmp_path / "state",
        evidence_root=tmp_path / "evidence",
    )
    fixture = textwrap.dedent(
        f"""
        import sys, time
        if not sys.stdin.buffer.readline(): raise SystemExit(81)
        sys.stdout.buffer.write({INITIALIZE_SUCCESS!r}); sys.stdout.buffer.flush()
        if not sys.stdin.buffer.readline(): raise SystemExit(82)
        sys.stdout.buffer.write({AUTHENTICATE_SUCCESS!r}); sys.stdout.buffer.flush()
        time.sleep(30)
        """
    )
    argv = [sys.executable, "-c", fixture]
    monkeypatch.setattr(runtime, "build_local_auth_bwrap_argv", lambda *_args: argv)
    workload = WorkloadCgroup.create()
    unit_path = Path("/sys/fs/cgroup" + workload.controller.unit_relative)
    workload.request_freeze = types.MethodType(lambda _self: None, workload)

    outcome = runtime.run_local_auth(
        spec,
        credential,
        workload_factory=lambda: workload,
        topology_validator=lambda _w, process, _s, _a, roles: roles
        or runtime.LocalAuthRoles((), (), process.pid, process.pid, process.pid),
        timeout_seconds=2.0,
    )

    assert outcome.protocol.qualification.value == "BLOCKED"
    assert outcome.reason_code == "LOCAL_AUTH_FREEZE_TIMEOUT"
    assert outcome.census.cleanup_complete is True
    assert (unit_path / "workload").exists() is False


@pytest.mark.skipif(os.name != "posix", reason="native Linux systemd required")
def test_freezer_native_f_controller_death_while_frozen_is_collected() -> None:
    repository = Path(__file__).resolve().parents[2]
    uid = os.getuid()
    service_cgroup = (
        f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/"
        f"app.slice/{_UNIT}.service"
    )
    controller = textwrap.dedent(
        f"""
        import sys
        import time
        sys.path.insert(0, {str(repository / 'src')!r})
        from agenticos.providers.kimi_local_auth_freezer import WorkloadCgroup

        workload = WorkloadCgroup.create()
        process = workload.spawn(
            [sys.executable, '-c', 'import time; time.sleep(60)'],
            pass_fds=(),
        )
        deadline = time.monotonic() + 5
        workload.await_events(populated=True, frozen=False, deadline=deadline)
        workload.request_freeze()
        workload.await_events(populated=True, frozen=True, deadline=deadline)
        time.sleep(60)
        """
    )
    command = [
        "/usr/bin/systemd-run", "--user", f"--unit={_UNIT}",
        "--service-type=exec", "--collect", "--quiet",
        f"--working-directory={repository}",
        "--property=Delegate=yes", "--property=KillMode=control-group",
        "--property=SendSIGKILL=yes", "--property=TimeoutStopSec=5s",
        "--property=Restart=no", "--property=TasksMax=21",
        "--property=MemoryMax=1G",
        "--property=ProtectControlGroups=yes",
        f"--property=BindPaths={service_cgroup}",
        sys.executable, "-c", controller,
    ]
    subprocess.run(command, check=True, timeout=5)
    cgroup = Path(
        f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/"
        f"app.slice/{_UNIT}.service"
    )
    deadline = time.monotonic() + 5
    while True:
        events = cgroup / "workload" / "cgroup.events"
        if events.exists() and events.read_text(encoding="ascii") == "populated 1\nfrozen 1\n":
            break
        if time.monotonic() >= deadline:
            pytest.fail("controller-crash fixture did not reach frozen state")
        time.sleep(0.01)
    main_pid = int(
        subprocess.check_output(
            ["systemctl", "--user", "show", f"{_UNIT}.service", "-p", "MainPID", "--value"],
            text=True,
        ).strip()
    )
    member_pids = tuple(
        int(value)
        for value in (cgroup / "workload" / "cgroup.procs").read_text(encoding="ascii").split()
    )
    subprocess.run(
        ["systemctl", "--user", "kill", "--kill-whom=main", f"--signal={signal.SIGKILL}", f"{_UNIT}.service"],
        check=True,
        timeout=5,
    )
    while cgroup.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert cgroup.exists() is False
    for process_id in (main_pid, *member_pids):
        with pytest.raises(ProcessLookupError):
            os.kill(process_id, 0)
