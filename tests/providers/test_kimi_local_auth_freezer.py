from __future__ import annotations

import io
import json
import os
from pathlib import Path
import fcntl
import signal
import subprocess
import sys
import types

import pytest

from agenticos.providers import kimi_local_auth_freezer as freezer
from agenticos.providers.kimi_local_auth import (
    ACPProtocolState,
    KimiLocalAuthError,
    KimiLocalAuthSession,
)
from agenticos.providers.kimi_local_auth_freezer import (
    ControllerIdentity,
    Clone3Process,
    CaptureAuthority,
    CaptureState,
    CgroupEvents,
    FreezerError,
    WorkloadSnapshot,
    bind_controller_identity,
    parse_delegated_service_membership,
    revalidate_controller_identity,
    validate_running_systemd_service,
)
from agenticos.providers import kimi_local_auth_runtime as runtime
from agenticos.providers.kimi_local_auth_runtime import local_auth_systemd_command


INITIALIZE_SUCCESS = (
    json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": 1,
                "agentCapabilities": {
                    "loadSession": True,
                    "promptCapabilities": {
                        "image": True,
                        "audio": False,
                        "embeddedContext": True,
                    },
                    "sessionCapabilities": {
                        "list": {}, "resume": {}, "close": {}, "delete": {},
                        "fork": {}, "additionalDirectories": {},
                    },
                    "mcpCapabilities": {"http": True, "sse": True},
                    "auth": {"logout": {}},
                },
                "authMethods": [
                    {
                        "id": "login",
                        "type": "terminal",
                        "name": "Login with Kimi account",
                        "description": "Open the device-code login flow in a terminal.",
                        "args": ["--login"],
                        "env": {"KIMI_CODE_HOME": "/home/aos/kimi"},
                        "_meta": {
                            "terminal-auth": {
                                "type": "terminal",
                                "label": "Login with Kimi account",
                                "command": "/opt/agenticos/kimi/bin/kimi",
                                "args": ["login"],
                                "env": {"KIMI_CODE_HOME": "/home/aos/kimi"},
                            }
                        },
                    }
                ],
                "agentInfo": {"name": "Kimi Code CLI", "version": "0.36.1"},
            },
        },
        separators=(",", ":"),
    ).encode("ascii")
    + b"\n"
)
AUTHENTICATE_SUCCESS = b'{"jsonrpc":"2.0","id":2,"result":null}\n'


def test_freezer_f01_terminal_response_disables_every_protocol_write_surface() -> None:
    session = KimiLocalAuthSession()
    stdin = io.BytesIO()

    stdin.write(session.initialize_request())
    session.accept(INITIALIZE_SUCCESS)
    stdin.write(session.authenticate_request())
    session.accept(AUTHENTICATE_SUCCESS)

    assert session.protocol_state is ACPProtocolState.TERMINAL_RESPONSE_ACCEPTED
    assert stdin.closed is False
    accepted_bytes = stdin.getvalue()
    for encoder in (session.initialize_request, session.authenticate_request):
        with pytest.raises(KimiLocalAuthError) as rejected:
            encoder()
        assert rejected.value.code == "ACP_PROTOCOL_TERMINAL"
    assert stdin.getvalue() == accepted_bytes

    session.close()
    assert session.protocol_state is ACPProtocolState.CLOSED
    with pytest.raises(KimiLocalAuthError) as repeated:
        session.close()
    assert repeated.value.code == "ACP_PROTOCOL_CLOSED"


def test_freezer_f02_capture_authority_is_monotonic_and_consumes_once() -> None:
    calls: list[str] = []
    authority = CaptureAuthority(lambda: calls.append("capture") or (b"one",))

    assert authority.state is CaptureState.NOT_YET_GRANTED
    authority.grant()
    assert authority.state is CaptureState.GRANTED
    assert authority.consume() == (b"one",)
    assert authority.state is CaptureState.CONSUMED
    assert calls == ["capture"]

    for operation in (authority.grant, authority.consume, lambda: authority.revoke("late")):
        with pytest.raises(FreezerError) as rejected:
            operation()
        assert rejected.value.code == "LOCAL_AUTH_CAPTURE_STATE"
    assert calls == ["capture"]


@pytest.mark.parametrize("failure_point", ["protocol", "process", "timeout", "freezer", "membership", "census", "evidence", "cleanup"])
def test_freezer_f03_every_preconsumption_failure_revokes_without_capture_io(
    failure_point: str,
) -> None:
    calls: list[str] = []
    authority = CaptureAuthority(lambda: calls.append("capture") or ())
    if failure_point in {"census", "evidence", "cleanup"}:
        authority.grant()

    authority.revoke(f"LOCAL_AUTH_{failure_point.upper()}_FAILED")

    assert authority.state is CaptureState.REVOKED
    assert authority.reason_code == f"LOCAL_AUTH_{failure_point.upper()}_FAILED"
    for operation in (authority.grant, authority.consume, lambda: authority.revoke("second")):
        with pytest.raises(FreezerError):
            operation()
    assert calls == []


def test_freezer_e01_live_role_binding_never_reads_proc_cmdline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_read_bytes = Path.read_bytes
    original_read_text = Path.read_text
    original_readlink = os.readlink

    def reject_raw_process_memory(path: Path) -> bytes:
        if path.name == "cmdline":
            pytest.fail("controller read process-controlled argv memory")
        return original_read_bytes(path)

    def reject_proc_stat(path: Path, *args, **kwargs) -> str:
        if path.name == "stat" and "/proc/" in str(path):
            pytest.fail("controller read process-controlled comm memory")
        return original_read_text(path, *args, **kwargs)

    def reject_exe_readlink(path: str | bytes | os.PathLike[str] | os.PathLike[bytes]):
        if Path(path).name == "exe":
            pytest.fail("controller ingested provider-selected exe link text")
        return original_readlink(path)

    monkeypatch.setattr(Path, "read_bytes", reject_raw_process_memory)
    monkeypatch.setattr(Path, "read_text", reject_proc_stat)
    monkeypatch.setattr(os, "readlink", reject_exe_readlink)
    record = runtime._read_live_process_record(os.getpid())
    assert record.process_id == os.getpid()


def test_freezer_e02_census_derives_environment_from_trusted_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = Path.read_bytes

    def reject_raw_process_memory(path: Path) -> bytes:
        if path.name == "environ":
            pytest.fail("controller read process-controlled environment memory")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", reject_raw_process_memory)
    monkeypatch.setattr(runtime, "_read_fd_classes", lambda _pid, _process: ("pipe",))
    monkeypatch.setattr(runtime, "_count_inet_rows", lambda _pid: 0)
    monkeypatch.setattr(runtime, "_count_session_artifacts", lambda _pid: 0)
    process_id = os.getpid()
    roles = runtime.LocalAuthRoles((), (), process_id, process_id, process_id)
    census = runtime._sample_local_auth_census(
        object(),
        object(),
        ["/trusted/bwrap"],
        WorkloadSnapshot((process_id,), (process_id,)),
        roles,
    )
    assert census.environment_names == tuple(sorted(runtime.build_kimi_environment()))


def test_freezer_e03_fd_census_compares_pipe_identities_without_readlink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import os, time; os.write(1, b'R'); time.sleep(30)",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    original_readlink = os.readlink

    def reject_fd_link_text(path):
        if "/fd/" in str(path):
            pytest.fail("controller ingested provider-selected fd link text")
        return original_readlink(path)

    monkeypatch.setattr(os, "readlink", reject_fd_link_text)
    try:
        assert process.stdout is not None
        assert process.stdout.read(1) == b"R"
        assert runtime._read_fd_classes(process.pid, process) == ("pipe",)
    finally:
        process.kill()
        process.wait(timeout=5)


def test_freezer_e04_fd_census_fails_on_fourth_entry_without_materializing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []

    class Entry:
        def __init__(self, name: str) -> None:
            self.name = name

    class Scan:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            for name in ("0", "1", "2", "3"):
                observed.append(name)
                yield Entry(name)
            pytest.fail("fd census consumed beyond its exact three-entry cap")

    monkeypatch.setattr(runtime.os, "scandir", lambda _root: Scan())
    with pytest.raises(runtime.KimiLocalAuthRuntimeError) as rejected:
        runtime._read_fd_classes(99999, object())
    assert rejected.value.code == "LOCAL_AUTH_CENSUS_FD"
    assert observed == ["0", "1", "2", "3"]


@pytest.mark.parametrize(
    "payload",
    [
        b"populated 1\nfrozen 1\nextra 0\n",
        b"populated 1\npopulated 1\nfrozen 1\n",
        b"frozen 1\n",
        b"populated yes\nfrozen 1\n",
        b"populated 1\nfrozen 2\n",
        b"populated 1\rfrozen 1\n",
    ],
)
def test_freezer_b01_cgroup_events_parser_is_strict_and_total(payload: bytes) -> None:
    with pytest.raises(FreezerError) as rejected:
        CgroupEvents.parse(payload)
    assert rejected.value.code == "LOCAL_AUTH_CGROUP_EVENTS_INVALID"


def test_freezer_b02_cgroup_events_requires_boolean_populated_and_frozen() -> None:
    assert CgroupEvents.parse(b"populated 1\nfrozen 0\n") == CgroupEvents(
        populated=True,
        frozen=False,
    )
    assert CgroupEvents.parse(b"populated 1\nfrozen 1\n") == CgroupEvents(
        populated=True,
        frozen=True,
    )


@pytest.mark.parametrize(
    "payload",
    [
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/aos-kimi-level1-local-auth.scope\n",
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/other.service\n",
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/extra.slice/aos-kimi-level1-local-auth.service\n",
        "0::/user.slice/aos-kimi-level1-local-auth.service\n0::/duplicate\n",
        "1:name=/wrong\n",
        "0::/user.slice/../aos-kimi-level1-local-auth.service\n",
    ],
)
def test_freezer_a01_only_exact_transient_service_membership_is_admitted(
    payload: str,
) -> None:
    with pytest.raises(FreezerError) as rejected:
        parse_delegated_service_membership(payload)
    assert rejected.value.code == "LOCAL_AUTH_SERVICE_REQUIRED"


def test_freezer_a02_controller_binds_one_process_pidfd_and_one_stable_tid() -> None:
    events: list[tuple[str, int | None]] = []

    identity = bind_controller_identity(
        process_id=4242,
        task_enumerator=lambda: events.append(("tasks", None)) or (4242,),
        cgroup_reader=lambda: events.append(("cgroup", None))
        or "0::/user.slice/user-1000.slice/user@1000.service/app.slice/aos-kimi-level1-local-auth.service\n",
        pidfd_opener=lambda pid, flags: events.append(("pidfd", pid)) or 19,
        start_time_reader=lambda pid: events.append(("start", pid)) or 9001,
    )

    assert identity == ControllerIdentity(
        process_id=4242,
        pidfd=19,
        start_time=9001,
        unit_relative="/user.slice/user-1000.slice/user@1000.service/app.slice/aos-kimi-level1-local-auth.service",
    )
    assert events == [
        ("tasks", None),
        ("tasks", None),
        ("cgroup", None),
        ("pidfd", 4242),
        ("start", 4242),
    ]

    events.clear()
    revalidate_controller_identity(
        identity,
        task_enumerator=lambda: events.append(("tasks", None)) or (4242,),
        cgroup_reader=lambda: events.append(("cgroup", None))
        or f"0::{identity.unit_relative}\n",
        start_time_reader=lambda pid: events.append(("start", pid)) or 9001,
    )
    assert events == [
        ("tasks", None),
        ("tasks", None),
        ("cgroup", None),
        ("start", 4242),
    ]


@pytest.mark.parametrize("tasks", [(4242, 4243), (4243,), (4242, 4242), ()])
def test_freezer_a03_controller_thread_injection_or_churn_blocks(
    tasks: tuple[int, ...],
) -> None:
    snapshots = iter(((4242,), tasks))
    with pytest.raises(FreezerError) as rejected:
        bind_controller_identity(
            process_id=4242,
            task_enumerator=lambda: next(snapshots),
            cgroup_reader=lambda: "0::/user.slice/user-1000.slice/user@1000.service/app.slice/aos-kimi-level1-local-auth.service\n",
            pidfd_opener=lambda _pid, _flags: pytest.fail("pidfd opened after bad task census"),
            start_time_reader=lambda _pid: pytest.fail("start time read after bad task census"),
        )
    assert rejected.value.code == "LOCAL_AUTH_CONTROLLER_THREAD"


def test_freezer_a08_start_metadata_failure_closes_controller_pidfd() -> None:
    pidfd = os.open("/dev/null", os.O_RDONLY)
    with pytest.raises(FreezerError) as rejected:
        bind_controller_identity(
            process_id=4242,
            task_enumerator=lambda: (4242,),
            cgroup_reader=lambda: (
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/"
                "aos-kimi-level1-local-auth.service\n"
            ),
            pidfd_opener=lambda _pid, _flags: pidfd,
            start_time_reader=lambda _pid: (_ for _ in ()).throw(
                OSError("metadata failure")
            ),
        )
    assert rejected.value.code == "LOCAL_AUTH_CONTROLLER_IDENTITY"
    with pytest.raises(OSError):
        fcntl.fcntl(pidfd, fcntl.F_GETFD)


def test_freezer_a04_service_vector_is_delegated_pipe_service_not_scope() -> None:
    candidate = "1" * 40
    command = local_auth_systemd_command(candidate)

    assert command[:6] == [
        "/usr/bin/systemd-run",
        "--user",
        "--service-type=exec",
        "--wait",
        "--collect",
        "--pipe",
    ]
    assert "--quiet" in command
    assert "--unit=aos-kimi-level1-local-auth" in command
    assert "--property=Delegate=yes" in command
    assert "--property=KillMode=control-group" in command
    assert "--property=SendSIGKILL=yes" in command
    assert "--property=TimeoutStopSec=5s" in command
    assert "--property=Restart=no" in command
    assert "--property=TasksMax=21" in command
    assert "--property=MemoryMax=1G" in command
    assert "--property=ProtectControlGroups=yes" in command
    assert any(item.startswith("--property=BindPaths=/sys/fs/cgroup/") for item in command)
    assert "--scope" not in command
    assert not any(item in command for item in ("sh", "bash", "tee"))
    assert command[-2:] == ["--expected-commit", candidate]


def test_freezer_a06_running_service_properties_bind_exact_mainpid_and_cleanup() -> None:
    process_id = 4242
    relative = (
        "/user.slice/user-1000.slice/user@1000.service/app.slice/"
        "aos-kimi-level1-local-auth.service"
    )
    payload = "\n".join(
        (
            "Type=exec",
            "Restart=no",
            "TimeoutStopUSec=5s",
            f"MainPID={process_id}",
            f"ControlGroup={relative}",
            "Delegate=yes",
            "MemoryMax=1073741824",
            "TasksMax=21",
            "KillMode=control-group",
            "SendSIGKILL=yes",
            "ProtectControlGroups=yes",
            (
                "BindPaths=/sys/fs/cgroup"
                f"{relative}:/sys/fs/cgroup{relative}:rbind"
            ),
            "",
        )
    )
    commands: list[list[str]] = []

    def runner(command: list[str], **kwargs):
        commands.append(command)
        assert kwargs == {
            "check": False,
            "capture_output": True,
            "text": True,
            "timeout": 2.0,
        }
        return subprocess.CompletedProcess(command, 0, payload, "")

    validate_running_systemd_service(
        process_id,
        relative,
        runner=runner,
    )
    assert commands[0][:4] == [
        "/usr/bin/systemctl",
        "--user",
        "show",
        "aos-kimi-level1-local-auth.service",
    ]

    weakened = payload.replace("KillMode=control-group", "KillMode=process")
    with pytest.raises(FreezerError) as rejected:
        validate_running_systemd_service(
            process_id,
            relative,
            runner=lambda command, **_kwargs: subprocess.CompletedProcess(
                command, 0, weakened, ""
            ),
        )
    assert rejected.value.code == "LOCAL_AUTH_SERVICE_PROPERTIES"


def test_freezer_a05_process_handle_failure_closes_every_parent_pipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_descriptors: list[int] = []
    child_descriptors: list[int] = []
    for _ in range(3):
        child, parent = os.pipe()
        child_descriptors.append(child)
        parent_descriptors.append(parent)
    for descriptor in child_descriptors:
        os.close(descriptor)
    monkeypatch.setattr(
        os,
        "pidfd_open",
        lambda _pid, _flags: (_ for _ in ()).throw(OSError("pidfd failure")),
    )

    with pytest.raises(FreezerError) as rejected:
        Clone3Process(987654, *parent_descriptors)

    assert rejected.value.code == "LOCAL_AUTH_PROCESS_IDENTITY"
    for descriptor in parent_descriptors:
        with pytest.raises(OSError):
            fcntl.fcntl(descriptor, fcntl.F_GETFD)


@pytest.mark.parametrize("failed_call", [1, 2, 3])
def test_freezer_a07_pipe_setup_failure_closes_every_allocated_descriptor(
    monkeypatch: pytest.MonkeyPatch,
    failed_call: int,
) -> None:
    workload = object.__new__(runtime.WorkloadCgroup)
    workload.checkpoint = types.MethodType(
        lambda _self: WorkloadSnapshot((), ()),
        workload,
    )
    original_pipe2 = os.pipe2
    allocated: list[int] = []
    calls = 0

    def failing_pipe2(flags: int) -> tuple[int, int]:
        nonlocal calls
        calls += 1
        if calls == failed_call:
            raise OSError("injected pipe failure")
        pair = original_pipe2(flags)
        allocated.extend(pair)
        return pair

    monkeypatch.setattr(os, "pipe2", failing_pipe2)
    with pytest.raises(FreezerError) as rejected:
        workload.spawn(["/synthetic"], pass_fds=())
    assert rejected.value.code == "LOCAL_AUTH_PIPE_SETUP"
    for descriptor in allocated:
        with pytest.raises(OSError):
            fcntl.fcntl(descriptor, fcntl.F_GETFD)


def test_freezer_a09_clone_syscall_setup_exception_closes_all_six_pipe_ends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workload = object.__new__(runtime.WorkloadCgroup)
    workload.workload_fd = os.open("/dev/null", os.O_RDONLY)
    workload.checkpoint = types.MethodType(
        lambda _self: WorkloadSnapshot((), ()),
        workload,
    )
    original_pipe2 = os.pipe2
    allocated: list[int] = []

    def recording_pipe2(flags: int) -> tuple[int, int]:
        pair = original_pipe2(flags)
        allocated.extend(pair)
        return pair

    monkeypatch.setattr(os, "pipe2", recording_pipe2)
    monkeypatch.setattr(
        freezer.ctypes,
        "CDLL",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("syscall setup")),
    )
    with pytest.raises(FreezerError) as rejected:
        workload.spawn(["/synthetic"], pass_fds=())
    assert rejected.value.code == "LOCAL_AUTH_CLONE3_UNAVAILABLE"
    assert len(allocated) == 6
    for descriptor in allocated:
        with pytest.raises(OSError):
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
    os.close(workload.workload_fd)


def test_freezer_c02_identity_loss_uses_bound_cleanup_without_removing_new_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workload = object.__new__(runtime.WorkloadCgroup)
    workload._removed = False
    workload._controls = {}
    workload._unit_controls = {}
    workload._outer_pid = None
    workload.unit_fd = os.open("/dev/null", os.O_RDONLY)
    workload.workload_fd = os.open("/dev/null", os.O_RDONLY)
    controller_pidfd = os.open("/dev/null", os.O_RDONLY)
    workload.controller = ControllerIdentity(
        process_id=os.getpid(),
        pidfd=controller_pidfd,
        start_time=1,
        unit_relative="/user.slice/user-1000.slice/user@1000.service/app.slice/aos-kimi-level1-local-auth.service",
    )
    cleanup_calls: list[str] = []
    removals: list[str] = []

    def identity_lost(_self) -> None:
        raise FreezerError("LOCAL_AUTH_CGROUP_IDENTITY")

    def bound_cleanup(_self, *, process, deadline) -> None:
        del process, deadline
        cleanup_calls.append("bound-kill-drain")

    workload._validate_identity = types.MethodType(identity_lost, workload)
    workload._cleanup_bound = types.MethodType(bound_cleanup, workload)
    monkeypatch.setattr(
        os,
        "rmdir",
        lambda name, *, dir_fd: removals.append(f"{dir_fd}:{name}"),
    )

    with pytest.raises(FreezerError) as rejected:
        workload.close(process=None, deadline=1.0)

    assert rejected.value.code == "LOCAL_AUTH_CGROUP_IDENTITY"
    assert cleanup_calls == ["bound-kill-drain"]
    assert removals == []


def _creation_controller() -> ControllerIdentity:
    return ControllerIdentity(
        process_id=os.getpid(),
        pidfd=os.open("/dev/null", os.O_RDONLY),
        start_time=1,
        unit_relative="/user.slice/user-1000.slice/user@1000.service/app.slice/aos-kimi-level1-local-auth.service",
    )


def test_freezer_c03_create_open_failure_removes_only_the_created_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller = _creation_controller()
    unit_fd = os.open("/dev/null", os.O_RDONLY)
    identity = types.SimpleNamespace(st_dev=71, st_ino=72)
    removals: list[str] = []
    original_open = os.open
    original_stat = os.stat
    monkeypatch.setattr(freezer, "bind_controller_identity", lambda: controller)
    monkeypatch.setattr(freezer, "_read_self_cgroup", lambda: f"0::{controller.unit_relative}\n")
    monkeypatch.setattr(freezer, "validate_running_systemd_service", lambda *_args: None)
    monkeypatch.setattr(runtime.WorkloadCgroup, "_open_unit", lambda _relative: unit_fd)
    monkeypatch.setattr(runtime.WorkloadCgroup, "_require_cgroup2", lambda _fd: None)
    monkeypatch.setattr(runtime.WorkloadCgroup, "_child_cgroups", lambda _fd: ())
    monkeypatch.setattr(runtime.WorkloadCgroup, "_UNIT_CONTROLS", {})
    monkeypatch.setattr(
        runtime.WorkloadCgroup,
        "_validate_unit_limits",
        lambda _fd, *, require_controller_only: None,
    )
    monkeypatch.setattr(os, "mkdir", lambda _name, *, mode, dir_fd: None)
    monkeypatch.setattr(
        os,
        "stat",
        lambda name, *args, **kwargs: identity
        if name == "workload" and kwargs.get("dir_fd") == unit_fd
        else original_stat(name, *args, **kwargs),
    )
    monkeypatch.setattr(
        os,
        "open",
        lambda name, flags, *args, **kwargs: (_ for _ in ()).throw(OSError("open failed"))
        if name == "workload" and kwargs.get("dir_fd") == unit_fd
        else original_open(name, flags, *args, **kwargs),
    )
    monkeypatch.setattr(
        os,
        "rmdir",
        lambda name, *, dir_fd: removals.append(f"{dir_fd}:{name}"),
    )

    with pytest.raises(OSError, match="open failed"):
        runtime.WorkloadCgroup.create()

    assert removals == [f"{unit_fd}:workload"]


def test_freezer_c04_create_validation_failure_never_removes_replacement_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller = _creation_controller()
    unit_fd = os.open("/dev/null", os.O_RDONLY)
    workload_fd = os.open("/dev/null", os.O_RDONLY)
    opened = os.fstat(workload_fd)
    original_open = os.open
    original_stat = os.stat
    identities = iter(
        (
            types.SimpleNamespace(st_dev=opened.st_dev, st_ino=opened.st_ino),
            types.SimpleNamespace(st_dev=opened.st_dev, st_ino=opened.st_ino + 1),
        )
    )
    removals: list[str] = []
    monkeypatch.setattr(freezer, "bind_controller_identity", lambda: controller)
    monkeypatch.setattr(freezer, "_read_self_cgroup", lambda: f"0::{controller.unit_relative}\n")
    monkeypatch.setattr(freezer, "validate_running_systemd_service", lambda *_args: None)
    monkeypatch.setattr(runtime.WorkloadCgroup, "_open_unit", lambda _relative: unit_fd)
    monkeypatch.setattr(runtime.WorkloadCgroup, "_require_cgroup2", lambda _fd: None)
    monkeypatch.setattr(runtime.WorkloadCgroup, "_child_cgroups", lambda _fd: ())
    monkeypatch.setattr(runtime.WorkloadCgroup, "_UNIT_CONTROLS", {})
    monkeypatch.setattr(
        runtime.WorkloadCgroup,
        "_validate_unit_limits",
        lambda _fd, *, require_controller_only: None,
    )
    monkeypatch.setattr(runtime.WorkloadCgroup, "_mount_id", lambda _fd: 91)
    monkeypatch.setattr(os, "mkdir", lambda _name, *, mode, dir_fd: None)
    monkeypatch.setattr(
        os,
        "stat",
        lambda name, *args, **kwargs: next(identities)
        if name == "workload" and kwargs.get("dir_fd") == unit_fd
        else original_stat(name, *args, **kwargs),
    )
    monkeypatch.setattr(
        os,
        "open",
        lambda name, flags, *args, **kwargs: workload_fd
        if name == "workload" and kwargs.get("dir_fd") == unit_fd
        else original_open(name, flags, *args, **kwargs),
    )
    monkeypatch.setattr(
        os,
        "rmdir",
        lambda name, *, dir_fd: removals.append(f"{dir_fd}:{name}"),
    )

    with pytest.raises(FreezerError) as rejected:
        runtime.WorkloadCgroup.create()

    assert rejected.value.code == "LOCAL_AUTH_CGROUP_IDENTITY"
    assert removals == []


def test_freezer_c05_unit_open_failure_closes_bound_controller_pidfd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller = _creation_controller()
    monkeypatch.setattr(
        freezer,
        "_read_self_cgroup",
        lambda: f"0::{controller.unit_relative}\n",
    )
    monkeypatch.setattr(freezer, "validate_running_systemd_service", lambda *_args: None)
    monkeypatch.setattr(freezer, "bind_controller_identity", lambda: controller)
    monkeypatch.setattr(
        freezer.WorkloadCgroup,
        "_open_unit",
        lambda _relative: (_ for _ in ()).throw(OSError("unit traversal failed")),
    )

    with pytest.raises(OSError, match="unit traversal failed"):
        freezer.WorkloadCgroup.create()
    with pytest.raises(OSError):
        fcntl.fcntl(controller.pidfd, fcntl.F_GETFD)


class _RecordingInput:
    def __init__(self, events: list[str] | None = None, on_write=None) -> None:
        self.writes: list[bytes] = []
        self.closed = False
        self.sealed = False
        self.events = events
        self.on_write = on_write

    def write(self, payload: bytes) -> int:
        assert self.closed is False
        if self.sealed:
            raise FreezerError("LOCAL_AUTH_PROTOCOL_STATE")
        self.writes.append(payload)
        if self.on_write is not None:
            self.on_write(len(self.writes))
        return len(payload)

    def flush(self) -> None:
        assert self.closed is False
        if self.sealed:
            raise FreezerError("LOCAL_AUTH_PROTOCOL_STATE")

    def seal(self) -> None:
        assert self.closed is False
        assert self.sealed is False
        self.sealed = True
        if self.events is not None:
            self.events.append("terminal-response-accepted")

    def close(self) -> None:
        if not self.closed and self.events is not None:
            self.events.append("stdin-eof")
        self.closed = True


class _StaticStream:
    def __init__(self, payload: bytes) -> None:
        reader, writer = os.pipe()
        os.write(writer, payload)
        os.close(writer)
        self._file = os.fdopen(reader, "rb", buffering=0)

    def fileno(self) -> int:
        return self._file.fileno()

    def close(self) -> None:
        self._file.close()


class _PushStream:
    def __init__(self, payload: bytes = b"") -> None:
        reader, self._writer = os.pipe()
        if payload:
            os.write(self._writer, payload)
        self._file = os.fdopen(reader, "rb", buffering=0)

    def push(self, payload: bytes) -> None:
        os.write(self._writer, payload)

    def fileno(self) -> int:
        return self._file.fileno()

    def close(self) -> None:
        self._file.close()
        os.close(self._writer)


class _FreezerProcess:
    def __init__(
        self,
        events: list[str] | None = None,
        *,
        premature_auth: bool = False,
    ) -> None:
        self.pid = 5001
        initial = INITIALIZE_SUCCESS + (AUTHENTICATE_SUCCESS if premature_auth else b"")
        self.stdout = _PushStream(initial)
        self.stdin = _RecordingInput(
            events,
            None
            if premature_auth
            else lambda count: self.stdout.push(AUTHENTICATE_SUCCESS)
            if count == 2
            else None,
        )
        self.stderr = _StaticStream(b"")
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.returncode = 0
        return 0


def test_freezer_f04_consumed_capture_alias_is_sealed_before_lifecycle_drain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FreezerProcess()
    capture = runtime._LocalAuthCapture(process.stdout, process.stderr)
    capture.seal()
    monkeypatch.setattr(
        runtime.select,
        "select",
        lambda *_args, **_kwargs: pytest.fail("select after capture consumption"),
    )
    monkeypatch.setattr(
        runtime.os,
        "read",
        lambda *_args, **_kwargs: pytest.fail("read after capture consumption"),
    )
    for operation in (
        lambda: capture.drain_available(10.0, lambda: 0.0),
        lambda: capture.finish(10.0, lambda: 0.0),
        lambda: capture.next_frame(process, 10.0, lambda: 0.0),
    ):
        with pytest.raises(runtime._LocalAuthRunFailure) as rejected:
            operation()
        assert rejected.value.code == "LOCAL_AUTH_CAPTURE_CONSUMED"
    process.stdin.close()
    process.stdout.close()
    process.stderr.close()


class _FakeWorkload:
    def __init__(
        self,
        process: _FreezerProcess,
        events: list[str],
        *,
        fail_at: str | None = None,
        failure_code: str | None = None,
    ) -> None:
        self.process = process
        self.events = events
        self.fail_at = fail_at
        self.failure_code = failure_code
        self.snapshot = WorkloadSnapshot((5001, 5002, 5003), (5001, 5002, 5003, 5004))
        self.checkpoints = 0
        self.capture_calls = 0

    def spawn(self, argv: list[str], *, pass_fds: tuple[int, ...]) -> _FreezerProcess:
        assert argv == ["/usr/bin/synthetic-freezer-provider"]
        assert len(pass_fds) == 1
        self.events.append("spawn")
        return self.process

    def checkpoint(self, *, expected: WorkloadSnapshot | None = None) -> WorkloadSnapshot:
        self.checkpoints += 1
        label = {1: "pre-freeze", 2: "post-freeze", 3: "post-thaw"}[self.checkpoints]
        self.events.append(label)
        if self.fail_at == label:
            raise FreezerError(
                self.failure_code
                or f"LOCAL_AUTH_{label.upper().replace('-', '_')}_FAILED"
            )
        if expected is not None:
            assert expected == self.snapshot
        return self.snapshot

    def request_freeze(self) -> None:
        assert self.process.stdin.closed is False
        assert self.process.stdin.sealed is True
        assert len(self.process.stdin.writes) == 2
        with pytest.raises(FreezerError):
            self.process.stdin.write(b"post-terminal-bomb")
        with pytest.raises(FreezerError):
            self.process.stdin.flush()
        self.events.append("freeze-request")
        if self.fail_at == "freeze-request":
            raise FreezerError(self.failure_code or "LOCAL_AUTH_FREEZE_REQUEST_FAILED")

    def await_events(
        self,
        *,
        populated: bool,
        frozen: bool | None,
        deadline: float,
        monotonic=runtime.time.monotonic,
    ) -> CgroupEvents:
        del deadline, monotonic
        label = "frozen-1" if frozen is True else "frozen-0" if frozen is False else "populated-0"
        if frozen is True:
            self.events.append("populated-1")
        self.events.append(label)
        if self.fail_at == label:
            raise FreezerError(
                self.failure_code
                or f"LOCAL_AUTH_{label.upper().replace('-', '_')}_FAILED"
            )
        return CgroupEvents(populated=populated, frozen=bool(frozen))

    def request_thaw(self) -> None:
        assert self.process.stdin.closed is False
        assert len(self.process.stdin.writes) == 2
        assert self.capture_calls == 1
        self.events.append("thaw-request")
        if self.fail_at == "thaw-request":
            raise FreezerError(self.failure_code or "LOCAL_AUTH_THAW_REQUEST_FAILED")

    def close(self, *, process: _FreezerProcess | None, deadline: float) -> None:
        del deadline
        assert process is self.process
        assert self.process.stdin.closed is True
        if self.process.returncode is None:
            self.process.returncode = -signal.SIGKILL
        self.events.append("bounded-drain")
        self.process.stdout.close()
        self.process.stderr.close()


def _freezer_runner_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    descriptor, writer = os.pipe()
    os.close(writer)
    credential = runtime.CredentialLeafHandle(descriptor, 1, 2, os.getuid(), 0o600, 1)
    spec = runtime.KimiLocalAuthSpec(
        executable=tmp_path / "runtime",
        bundle=tmp_path / "bundle",
        namespace_launcher=tmp_path / "launcher",
        state_root=tmp_path / "state",
        evidence_root=tmp_path / "evidence",
    )
    monkeypatch.setattr(
        runtime,
        "build_local_auth_bwrap_argv",
        lambda observed_spec, observed_credential: ["/usr/bin/synthetic-freezer-provider"]
        if observed_spec is spec and observed_credential is credential
        else pytest.fail("runner substituted launch inputs"),
    )
    return spec, credential


def _valid_freezer_census() -> runtime.LocalAuthCensus:
    return runtime.LocalAuthCensus(
        process_count=3,
        descendant_count=2,
        environment_names=tuple(sorted(runtime.build_kimi_environment())),
        fd_classes=("pipe",),
        network_namespace="net:[4242]",
        external_endpoint_count=0,
        session_artifact_count=0,
        cleanup_complete=False,
    )


def test_freezer_b03_runner_orders_terminal_freeze_capture_thaw_eof_and_drain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, credential = _freezer_runner_inputs(tmp_path, monkeypatch)
    events: list[str] = []
    process = _FreezerProcess(events)
    workload = _FakeWorkload(process, events)
    original_capture = runtime._LocalAuthCapture

    class RecordingCapture(original_capture):
        def drain_available(self, deadline: float, monotonic):
            workload.capture_calls += 1
            events.append("one-capture")
            return super().drain_available(deadline, monotonic)

    monkeypatch.setattr(runtime, "_LocalAuthCapture", RecordingCapture)
    outcome = runtime.run_local_auth(
        spec,
        credential,
        workload_factory=lambda: workload,
        census_sampler=lambda _workload, _process, _argv, _snapshot, _roles: events.append("census") or _valid_freezer_census(),
        topology_validator=lambda _workload, _process, _snapshot, _argv, roles: events.append("live-roles") or roles or runtime.LocalAuthRoles((), (), 5001, 5002, 5003),
        timeout_seconds=0.5,
    )

    assert outcome.protocol.qualification.value == "COMPLETE"
    assert outcome.reason_code == "ACP_LOCAL_AUTH_SUCCESS"
    assert events == [
        "spawn",
        "terminal-response-accepted",
        "pre-freeze", "live-roles",
        "freeze-request", "populated-1", "frozen-1",
        "post-freeze", "live-roles",
        "one-capture", "census",
        "thaw-request", "frozen-0",
        "post-thaw", "live-roles",
        "stdin-eof",
        "bounded-drain",
    ]
    assert len(process.stdin.writes) == 2
    assert process.stdin.closed is True
    assert outcome.census.cleanup_complete is True


def test_freezer_b04_preauthenticate_terminal_response_is_rejected_before_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, credential = _freezer_runner_inputs(tmp_path, monkeypatch)
    events: list[str] = []
    process = _FreezerProcess(events, premature_auth=True)
    workload = _FakeWorkload(process, events)

    outcome = runtime.run_local_auth(
        spec,
        credential,
        workload_factory=lambda: workload,
        census_sampler=lambda *_args: pytest.fail("census after pre-auth response"),
        topology_validator=lambda *_args: pytest.fail("topology after pre-auth response"),
        timeout_seconds=0.5,
    )

    assert outcome.protocol.qualification.value == "BLOCKED"
    assert outcome.reason_code == "LOCAL_AUTH_PROTOCOL_ORDER"
    assert len(process.stdin.writes) == 1
    assert "freeze-request" not in events
    assert events[-1] == "bounded-drain"


@pytest.mark.parametrize(
    ("fail_at", "failure_code", "expected_captures"),
    [
        ("pre-freeze", "LOCAL_AUTH_CGROUP_IDENTITY", 0),
        ("freeze-request", "LOCAL_AUTH_FREEZE_REQUEST_FAILED", 0),
        ("frozen-1", "LOCAL_AUTH_FREEZE_TIMEOUT", 0),
        ("post-freeze", "LOCAL_AUTH_FORK_DURING_FREEZE", 0),
        ("post-freeze", "LOCAL_AUTH_WORKLOAD_ESCAPE", 0),
        ("post-freeze", "LOCAL_AUTH_UNEXPECTED_CHILD_CGROUP", 0),
        ("thaw-request", "LOCAL_AUTH_THAW_REQUEST_FAILED", 1),
        ("frozen-0", "LOCAL_AUTH_THAW_FAILED", 1),
        ("post-thaw", "LOCAL_AUTH_PROVIDER_CRASH", 1),
    ],
)
def test_freezer_c01_failures_revoke_or_consume_once_and_always_drain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_at: str,
    failure_code: str,
    expected_captures: int,
) -> None:
    spec, credential = _freezer_runner_inputs(tmp_path, monkeypatch)
    events: list[str] = []
    process = _FreezerProcess()
    workload = _FakeWorkload(
        process,
        events,
        fail_at=fail_at,
        failure_code=failure_code,
    )
    original_capture = runtime._LocalAuthCapture
    original_authority = runtime.CaptureAuthority
    captures: list[runtime._LocalAuthCapture] = []
    authorities: list[CaptureAuthority] = []
    sessions: list[KimiLocalAuthSession] = []

    class RecordingCapture(original_capture):
        def __init__(self, stdout, stderr):
            super().__init__(stdout, stderr)
            captures.append(self)

        def drain_available(self, deadline: float, monotonic):
            workload.capture_calls += 1
            return super().drain_available(deadline, monotonic)

    class RecordingAuthority(original_authority):
        def __init__(self, capture):
            super().__init__(capture)
            authorities.append(self)

    class RecordingSession(KimiLocalAuthSession):
        def __init__(self):
            super().__init__()
            sessions.append(self)

    monkeypatch.setattr(runtime, "_LocalAuthCapture", RecordingCapture)
    monkeypatch.setattr(runtime, "CaptureAuthority", RecordingAuthority)
    monkeypatch.setattr(runtime, "KimiLocalAuthSession", RecordingSession)
    outcome = runtime.run_local_auth(
        spec,
        credential,
        workload_factory=lambda: workload,
        census_sampler=lambda _workload, _process, _argv, _snapshot, _roles: _valid_freezer_census(),
        topology_validator=lambda _workload, _process, _snapshot, _argv, roles: roles or runtime.LocalAuthRoles((), (), 5001, 5002, 5003),
        timeout_seconds=0.5,
    )

    assert outcome.protocol.qualification.value == "BLOCKED"
    assert outcome.reason_code == failure_code
    assert workload.capture_calls == expected_captures
    assert events[-1] == "bounded-drain"
    assert process.stdin.closed is True
    assert len(process.stdin.writes) == 2
    assert len(authorities) == 1
    assert len(sessions) == 1
    assert sessions[0].protocol_state is ACPProtocolState.CLOSED
    assert authorities[0].state is (
        CaptureState.REVOKED if expected_captures == 0 else CaptureState.CONSUMED
    )
    assert len(captures) == 1
    if expected_captures == 0:
        assert captures[0]._error_code is not None
        assert captures[0]._stdout_buffer == bytearray()
        assert tuple(captures[0]._frames) == ()


def test_freezer_c06_factory_failure_after_entry_never_claims_cleanup_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, credential = _freezer_runner_inputs(tmp_path, monkeypatch)

    def partial_create_failure():
        raise FreezerError("LOCAL_AUTH_CGROUP_REMOVE_FAILED")

    outcome = runtime.run_local_auth(
        spec,
        credential,
        workload_factory=partial_create_failure,
        timeout_seconds=0.5,
    )

    assert outcome.protocol.qualification.value == "BLOCKED"
    assert outcome.reason_code == "LOCAL_AUTH_CGROUP_REMOVE_FAILED"
    assert outcome.census.cleanup_complete is False


def test_freezer_c07_expired_deadline_blocks_before_factory_spawn_or_protocol(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, credential = _freezer_runner_inputs(tmp_path, monkeypatch)
    times = iter((0.0, 1.0))
    outcome = runtime.run_local_auth(
        spec,
        credential,
        workload_factory=lambda: pytest.fail("factory entered after deadline"),
        monotonic=lambda: next(times),
        timeout_seconds=0.5,
    )
    assert outcome.protocol.qualification.value == "BLOCKED"
    assert outcome.reason_code == "LOCAL_AUTH_TIMEOUT"
    assert outcome.census.cleanup_complete is True


@pytest.mark.parametrize("failure", ["credential", "artifact"])
def test_freezer_c08_prelaunch_recheck_blocks_drift_before_clone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    spec, credential = _freezer_runner_inputs(tmp_path, monkeypatch)
    argv = ["/usr/bin/synthetic-freezer-provider"]
    calls = 0

    def rechecking_builder(_spec, _credential):
        nonlocal calls
        calls += 1
        if calls == 1:
            return argv
        if failure == "credential":
            raise runtime.KimiLocalAuthRuntimeError("CREDENTIAL_HANDLE_INVALID")
        return ["/substituted/bwrap"]

    monkeypatch.setattr(runtime, "build_local_auth_bwrap_argv", rechecking_builder)

    class EmptyWorkload:
        def spawn(self, *_args, **_kwargs):
            pytest.fail("clone reached after prelaunch drift")

        def close(self, *, process, deadline):
            assert process is None
            assert deadline > 0

    outcome = runtime.run_local_auth(
        spec,
        credential,
        workload_factory=EmptyWorkload,
        timeout_seconds=0.5,
    )
    assert calls == 2
    assert outcome.protocol.qualification.value == "BLOCKED"
    assert outcome.reason_code == (
        "CREDENTIAL_HANDLE_INVALID"
        if failure == "credential"
        else "LOCAL_AUTH_ARTIFACT_SUBSTITUTION"
    )
