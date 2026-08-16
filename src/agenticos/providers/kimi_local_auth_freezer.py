"""Controller-excluding cgroup-v2 freezer authority for Kimi Level 1."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path
import signal
import stat
import subprocess
import time
from typing import Callable

try:
    import fcntl
except ModuleNotFoundError:  # pragma: no cover - exercised by Windows regressions
    fcntl = None  # type: ignore[assignment]


class FreezerError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CaptureState(str, Enum):
    NOT_YET_GRANTED = "NOT_YET_GRANTED"
    GRANTED = "GRANTED"
    CONSUMED = "CONSUMED"
    REVOKED = "REVOKED"


class CaptureAuthority:
    def __init__(self, capture: Callable[[], tuple[bytes, ...]]) -> None:
        if not callable(capture):
            raise FreezerError("LOCAL_AUTH_CAPTURE_ARGUMENT")
        self.state = CaptureState.NOT_YET_GRANTED
        self.reason_code: str | None = None
        self._capture = capture

    def grant(self) -> None:
        if self.state is not CaptureState.NOT_YET_GRANTED:
            raise FreezerError("LOCAL_AUTH_CAPTURE_STATE")
        self.state = CaptureState.GRANTED

    def consume(self) -> tuple[bytes, ...]:
        if self.state is not CaptureState.GRANTED:
            raise FreezerError("LOCAL_AUTH_CAPTURE_STATE")
        try:
            captured = self._capture()
        except BaseException:
            self.state = CaptureState.REVOKED
            self.reason_code = "LOCAL_AUTH_CAPTURE_FAILED"
            raise
        if type(captured) is not tuple or any(type(item) is not bytes for item in captured):
            self.state = CaptureState.REVOKED
            self.reason_code = "LOCAL_AUTH_CAPTURE_FAILED"
            raise FreezerError(self.reason_code)
        self.state = CaptureState.CONSUMED
        self._capture = self._unavailable
        return captured

    def revoke(self, reason_code: str) -> None:
        if (
            self.state not in {CaptureState.NOT_YET_GRANTED, CaptureState.GRANTED}
            or type(reason_code) is not str
            or not reason_code
        ):
            raise FreezerError("LOCAL_AUTH_CAPTURE_STATE")
        self.state = CaptureState.REVOKED
        self.reason_code = reason_code
        self._capture = self._unavailable

    @staticmethod
    def _unavailable() -> tuple[bytes, ...]:
        raise FreezerError("LOCAL_AUTH_CAPTURE_STATE")


@dataclass(frozen=True, slots=True)
class CgroupEvents:
    populated: bool
    frozen: bool

    @classmethod
    def parse(cls, payload: bytes) -> "CgroupEvents":
        try:
            text = payload.decode("ascii", errors="strict")
        except (AttributeError, UnicodeError) as exc:
            raise FreezerError("LOCAL_AUTH_CGROUP_EVENTS_INVALID") from exc
        if not text.endswith("\n") or "\r" in text:
            raise FreezerError("LOCAL_AUTH_CGROUP_EVENTS_INVALID")
        values: dict[str, bool] = {}
        for line in text.splitlines():
            parts = line.split(" ")
            if (
                len(parts) != 2
                or parts[0] not in {"populated", "frozen"}
                or parts[0] in values
                or parts[1] not in {"0", "1"}
            ):
                raise FreezerError("LOCAL_AUTH_CGROUP_EVENTS_INVALID")
            values[parts[0]] = parts[1] == "1"
        if set(values) != {"populated", "frozen"}:
            raise FreezerError("LOCAL_AUTH_CGROUP_EVENTS_INVALID")
        return cls(populated=values["populated"], frozen=values["frozen"])


_SERVICE_SUFFIX = "/aos-kimi-level1-local-auth.service"


@dataclass(frozen=True, slots=True)
class ControllerIdentity:
    process_id: int
    pidfd: int
    start_time: int
    unit_relative: str


def parse_delegated_service_membership(payload: str) -> str:
    if type(payload) is not str:
        raise FreezerError("LOCAL_AUTH_SERVICE_REQUIRED")
    lines = payload.splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        raise FreezerError("LOCAL_AUTH_SERVICE_REQUIRED")
    relative = lines[0][3:]
    parts = Path(relative).parts
    uid_reader = getattr(os, "getuid", None)
    uid = uid_reader() if uid_reader is not None else None
    expected_relative = (
        f"/user.slice/user-{uid}.slice/user@{uid}.service/"
        "app.slice/aos-kimi-level1-local-auth.service"
        if uid is not None
        else ""
    )
    if (
        not relative.startswith("/")
        or not relative.endswith(_SERVICE_SUFFIX)
        or ".." in parts
        or "." in parts
        or not expected_relative
        or relative != expected_relative
    ):
        raise FreezerError("LOCAL_AUTH_SERVICE_REQUIRED")
    return relative


_SYSTEMD_PROPERTIES = (
    "Delegate",
    "KillMode",
    "SendSIGKILL",
    "TimeoutStopUSec",
    "Restart",
    "Type",
    "ControlGroup",
    "MainPID",
    "TasksMax",
    "MemoryMax",
    "ProtectControlGroups",
    "BindPaths",
)


def validate_running_systemd_service(
    process_id: int,
    unit_relative: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    command = [
        "/usr/bin/systemctl",
        "--user",
        "show",
        "aos-kimi-level1-local-auth.service",
        *(f"--property={name}" for name in _SYSTEMD_PROPERTIES),
    ]
    try:
        completed = runner(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=2.0,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FreezerError("LOCAL_AUTH_SERVICE_PROPERTIES") from exc
    if (
        type(completed) is not subprocess.CompletedProcess
        or completed.returncode != 0
        or completed.stderr != ""
        or not completed.stdout.endswith("\n")
    ):
        raise FreezerError("LOCAL_AUTH_SERVICE_PROPERTIES")
    observed: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        name, separator, value = line.partition("=")
        if separator != "=" or name not in _SYSTEMD_PROPERTIES or name in observed:
            raise FreezerError("LOCAL_AUTH_SERVICE_PROPERTIES")
        observed[name] = value
    expected = {
        "Delegate": "yes",
        "KillMode": "control-group",
        "SendSIGKILL": "yes",
        "TimeoutStopUSec": "5s",
        "Restart": "no",
        "Type": "exec",
        "ControlGroup": unit_relative,
        "MainPID": str(process_id),
        "TasksMax": "21",
        "MemoryMax": "1073741824",
        "ProtectControlGroups": "yes",
        "BindPaths": (
            f"/sys/fs/cgroup{unit_relative}:"
            f"/sys/fs/cgroup{unit_relative}:rbind"
        ),
    }
    if observed != expected:
        raise FreezerError("LOCAL_AUTH_SERVICE_PROPERTIES")


def _stable_controller_tasks(
    process_id: int,
    task_enumerator: Callable[[], tuple[int, ...]],
) -> None:
    before = task_enumerator()
    after = task_enumerator()
    if (
        type(before) is not tuple
        or type(after) is not tuple
        or before != (process_id,)
        or after != before
    ):
        raise FreezerError("LOCAL_AUTH_CONTROLLER_THREAD")


def _read_self_tasks() -> tuple[int, ...]:
    try:
        names = tuple(path.name for path in Path("/proc/self/task").iterdir())
    except OSError as exc:
        raise FreezerError("LOCAL_AUTH_CONTROLLER_THREAD") from exc
    if not names or any(not name.isdecimal() or name.startswith("0") for name in names):
        raise FreezerError("LOCAL_AUTH_CONTROLLER_THREAD")
    values = tuple(sorted(int(name) for name in names))
    if len(values) != len(set(values)):
        raise FreezerError("LOCAL_AUTH_CONTROLLER_THREAD")
    return values


def _read_self_cgroup() -> str:
    try:
        return Path("/proc/self/cgroup").read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise FreezerError("LOCAL_AUTH_SERVICE_REQUIRED") from exc


def _read_process_start_time(process_id: int) -> int:
    try:
        payload = (Path("/proc") / str(process_id) / "stat").read_text(encoding="ascii")
        fields = payload.rsplit(")", 1)[1].strip().split()
        start_time = fields[19]
    except (OSError, UnicodeError, IndexError) as exc:
        raise FreezerError("LOCAL_AUTH_CONTROLLER_IDENTITY") from exc
    if not start_time.isdecimal():
        raise FreezerError("LOCAL_AUTH_CONTROLLER_IDENTITY")
    return int(start_time)


def _open_pidfd(process_id: int, flags: int) -> int:
    opener = getattr(os, "pidfd_open", None)
    if opener is None:
        raise OSError("pidfd_open unavailable")
    return opener(process_id, flags)


def bind_controller_identity(
    *,
    process_id: int | None = None,
    task_enumerator: Callable[[], tuple[int, ...]] = _read_self_tasks,
    cgroup_reader: Callable[[], str] = _read_self_cgroup,
    pidfd_opener: Callable[[int, int], int] = _open_pidfd,
    start_time_reader: Callable[[int], int] = _read_process_start_time,
) -> ControllerIdentity:
    selected_pid = os.getpid() if process_id is None else process_id
    if type(selected_pid) is not int or selected_pid <= 0:
        raise FreezerError("LOCAL_AUTH_CONTROLLER_IDENTITY")
    _stable_controller_tasks(selected_pid, task_enumerator)
    unit_relative = parse_delegated_service_membership(cgroup_reader())
    pidfd = -1
    try:
        pidfd = pidfd_opener(selected_pid, 0)
        start_time = start_time_reader(selected_pid)
    except OSError as exc:
        if type(pidfd) is int and pidfd >= 0:
            os.close(pidfd)
        raise FreezerError("LOCAL_AUTH_CONTROLLER_IDENTITY") from exc
    if type(pidfd) is not int or pidfd < 0 or type(start_time) is not int or start_time <= 0:
        if type(pidfd) is int and pidfd >= 0:
            os.close(pidfd)
        raise FreezerError("LOCAL_AUTH_CONTROLLER_IDENTITY")
    return ControllerIdentity(selected_pid, pidfd, start_time, unit_relative)


def revalidate_controller_identity(
    identity: ControllerIdentity,
    *,
    task_enumerator: Callable[[], tuple[int, ...]] = _read_self_tasks,
    cgroup_reader: Callable[[], str] = _read_self_cgroup,
    start_time_reader: Callable[[int], int] = _read_process_start_time,
) -> None:
    if type(identity) is not ControllerIdentity:
        raise FreezerError("LOCAL_AUTH_CONTROLLER_IDENTITY")
    _stable_controller_tasks(identity.process_id, task_enumerator)
    if (
        parse_delegated_service_membership(cgroup_reader()) != identity.unit_relative
        or start_time_reader(identity.process_id) != identity.start_time
    ):
        raise FreezerError("LOCAL_AUTH_CONTROLLER_IDENTITY")


@dataclass(frozen=True, slots=True)
class WorkloadSnapshot:
    process_ids: tuple[int, ...]
    thread_ids: tuple[int, ...]


class _CloneArgs(ctypes.Structure):
    _fields_ = (
        ("flags", ctypes.c_uint64),
        ("pidfd", ctypes.c_uint64),
        ("child_tid", ctypes.c_uint64),
        ("parent_tid", ctypes.c_uint64),
        ("exit_signal", ctypes.c_uint64),
        ("stack", ctypes.c_uint64),
        ("stack_size", ctypes.c_uint64),
        ("tls", ctypes.c_uint64),
        ("set_tid", ctypes.c_uint64),
        ("set_tid_size", ctypes.c_uint64),
        ("cgroup", ctypes.c_uint64),
    )


class Clone3Process:
    """Small Popen-compatible handle for one direct-placement child."""

    def __init__(
        self,
        process_id: int,
        stdin_fd: int,
        stdout_fd: int,
        stderr_fd: int,
    ) -> None:
        self.pid = process_id
        self.pidfd = -1
        streams: list[object] = []
        try:
            self.pidfd = os.pidfd_open(process_id, 0)
            stdin_stream = os.fdopen(stdin_fd, "wb", buffering=0)
            streams.append(stdin_stream)
            self.stdin = SealedProtocolInput(stdin_stream)
            self.stdout = os.fdopen(stdout_fd, "rb", buffering=0)
            streams.append(self.stdout)
            self.stderr = os.fdopen(stderr_fd, "rb", buffering=0)
            streams.append(self.stderr)
        except (OSError, ValueError) as exc:
            for stream in streams:
                try:
                    stream.close()  # type: ignore[attr-defined]
                except OSError:
                    pass
            for descriptor in (stdin_fd, stdout_fd, stderr_fd, self.pidfd):
                if descriptor < 0:
                    continue
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise FreezerError("LOCAL_AUTH_PROCESS_IDENTITY") from exc
        self.returncode: int | None = None

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        try:
            waited, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            raise FreezerError("LOCAL_AUTH_PROCESS_IDENTITY") from None
        if waited == 0:
            return None
        self.returncode = os.waitstatus_to_exitcode(status)
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + timeout
        while self.poll() is None:
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired((self.pid,), timeout)
            time.sleep(0.005)
        assert self.returncode is not None
        return self.returncode

    def close(self) -> None:
        for stream in (self.stdin, self.stdout, self.stderr):
            try:
                stream.close()
            except OSError:
                pass
        try:
            os.close(self.pidfd)
        except OSError:
            pass


class SealedProtocolInput:
    """A pipe writer that becomes permanently close-only at ACP terminality."""

    def __init__(self, stream: object) -> None:
        self._stream = stream
        self._sealed = False

    @property
    def closed(self) -> bool:
        return bool(getattr(self._stream, "closed"))

    def fileno(self) -> int:
        return getattr(self._stream, "fileno")()

    def write(self, payload: bytes) -> int:
        if self._sealed:
            raise FreezerError("LOCAL_AUTH_PROTOCOL_STATE")
        return getattr(self._stream, "write")(payload)

    def flush(self) -> None:
        if self._sealed:
            raise FreezerError("LOCAL_AUTH_PROTOCOL_STATE")
        getattr(self._stream, "flush")()

    def seal(self) -> None:
        if self._sealed:
            raise FreezerError("LOCAL_AUTH_PROTOCOL_STATE")
        self._sealed = True

    def close(self) -> None:
        getattr(self._stream, "close")()


class WorkloadCgroup:
    """Identity-bound sole workload child beneath one delegated user service."""

    _CGROUP2_MAGIC = 0x63677270
    _SYS_CLONE3 = 435
    _CLONE_INTO_CGROUP = 0x200000000
    _WORKLOAD_NAME = "workload"
    _CONTROLS = {
        "freeze": ("cgroup.freeze", os.O_WRONLY),
        "events": ("cgroup.events", os.O_RDONLY),
        "procs": ("cgroup.procs", os.O_RDONLY),
        "threads": ("cgroup.threads", os.O_RDONLY),
        "kill": ("cgroup.kill", os.O_WRONLY),
        "type": ("cgroup.type", os.O_RDONLY),
    }
    _UNIT_CONTROLS = {
        "procs": "cgroup.procs",
        "threads": "cgroup.threads",
    }

    def __init__(
        self,
        controller: ControllerIdentity,
        unit_fd: int,
        workload_fd: int,
        controls: dict[str, int],
        directory_identity: tuple[int, int, int],
        control_identities: dict[str, tuple[int, int]],
        unit_controls: dict[str, int],
        unit_control_identities: dict[str, tuple[int, int]],
    ) -> None:
        self.controller = controller
        self.unit_fd = unit_fd
        self.workload_fd = workload_fd
        self._controls = controls
        self._directory_identity = directory_identity
        self._control_identities = control_identities
        self._unit_controls = unit_controls
        self._unit_control_identities = unit_control_identities
        self._removed = False
        self._outer_pid: int | None = None

    @classmethod
    def create(cls) -> "WorkloadCgroup":
        unit_relative = parse_delegated_service_membership(_read_self_cgroup())
        validate_running_systemd_service(os.getpid(), unit_relative)
        controller = bind_controller_identity()
        try:
            unit_fd = cls._open_unit(controller.unit_relative)
        except BaseException:
            os.close(controller.pidfd)
            raise
        created_identity: tuple[int, int] | None = None
        workload_fd: int | None = None
        unit_controls: dict[str, int] = {}
        try:
            cls._require_cgroup2(unit_fd)
            cls._validate_unit_limits(unit_fd, require_controller_only=True)
            if cls._child_cgroups(unit_fd):
                raise FreezerError("LOCAL_AUTH_SERVICE_NOT_EMPTY")
            for key, name in cls._UNIT_CONTROLS.items():
                unit_controls[key] = os.open(
                    name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=unit_fd,
                )
            os.mkdir(cls._WORKLOAD_NAME, mode=0o700, dir_fd=unit_fd)
            created = os.stat(
                cls._WORKLOAD_NAME,
                dir_fd=unit_fd,
                follow_symlinks=False,
            )
            created_identity = (created.st_dev, created.st_ino)
            workload_fd = os.open(
                cls._WORKLOAD_NAME,
                os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=unit_fd,
            )
            opened = os.fstat(workload_fd)
            if (opened.st_dev, opened.st_ino) != created_identity:
                raise FreezerError("LOCAL_AUTH_CGROUP_IDENTITY")
        except BaseException:
            if workload_fd is not None:
                os.close(workload_fd)
            for descriptor in unit_controls.values():
                os.close(descriptor)
            if created_identity is not None:
                cls._remove_created_name(unit_fd, created_identity)
            os.close(unit_fd)
            os.close(controller.pidfd)
            raise
        assert workload_fd is not None
        controls: dict[str, int] = {}
        try:
            cls._require_cgroup2(workload_fd)
            info = os.fstat(workload_fd)
            mount_id = cls._mount_id(workload_fd)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or cls._read_named(workload_fd, "cgroup.type") != b"domain\n"
            ):
                raise FreezerError("LOCAL_AUTH_CGROUP_IDENTITY")
            for key, (name, flags) in cls._CONTROLS.items():
                controls[key] = os.open(
                    name,
                    flags | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=workload_fd,
                )
            instance = cls(
                controller,
                unit_fd,
                workload_fd,
                controls,
                (mount_id, info.st_dev, info.st_ino),
                {
                    key: (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
                    for key, fd in controls.items()
                },
                unit_controls,
                {
                    key: (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
                    for key, fd in unit_controls.items()
                },
            )
            if instance._events() != CgroupEvents(False, False):
                raise FreezerError("LOCAL_AUTH_CGROUP_NOT_EMPTY")
            if instance.checkpoint() != WorkloadSnapshot((), ()):
                raise FreezerError("LOCAL_AUTH_CGROUP_NOT_EMPTY")
            return instance
        except BaseException:
            for descriptor in controls.values():
                os.close(descriptor)
            for descriptor in unit_controls.values():
                os.close(descriptor)
            os.close(workload_fd)
            assert created_identity is not None
            cls._remove_created_name(unit_fd, created_identity)
            os.close(unit_fd)
            os.close(controller.pidfd)
            raise

    @classmethod
    def _remove_created_name(
        cls,
        unit_fd: int,
        created_identity: tuple[int, int],
    ) -> None:
        """Best-effort removal that never targets a same-name replacement."""
        try:
            anchored = os.stat(
                cls._WORKLOAD_NAME,
                dir_fd=unit_fd,
                follow_symlinks=False,
            )
            if (anchored.st_dev, anchored.st_ino) != created_identity:
                return
            os.rmdir(cls._WORKLOAD_NAME, dir_fd=unit_fd)
        except OSError:
            pass

    @staticmethod
    def _open_unit(relative: str) -> int:
        descriptor = os.open(
            "/sys/fs/cgroup",
            os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            for component in Path(relative).parts[1:]:
                next_descriptor = os.open(
                    component,
                    os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = next_descriptor
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @classmethod
    def _require_cgroup2(cls, descriptor: int) -> None:
        storage = (ctypes.c_byte * 256)()
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.fstatfs(descriptor, ctypes.byref(storage)) != 0:
            error = ctypes.get_errno()
            raise FreezerError("LOCAL_AUTH_CGROUP_FILESYSTEM") from OSError(
                error, os.strerror(error)
            )
        filesystem_type = ctypes.cast(storage, ctypes.POINTER(ctypes.c_long))[0]
        if filesystem_type != cls._CGROUP2_MAGIC:
            raise FreezerError("LOCAL_AUTH_CGROUP_FILESYSTEM")

    @staticmethod
    def _mount_id(descriptor: int) -> int:
        try:
            text = Path(f"/proc/self/fdinfo/{descriptor}").read_text(encoding="ascii")
        except (OSError, UnicodeError) as exc:
            raise FreezerError("LOCAL_AUTH_CGROUP_IDENTITY") from exc
        values = [line.removeprefix("mnt_id:\t") for line in text.splitlines() if line.startswith("mnt_id:\t")]
        if len(values) != 1 or not values[0].isdecimal():
            raise FreezerError("LOCAL_AUTH_CGROUP_IDENTITY")
        return int(values[0])

    @staticmethod
    def _read_named(directory_fd: int, name: str) -> bytes:
        descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
        try:
            return os.read(descriptor, 4096)
        finally:
            os.close(descriptor)

    @staticmethod
    def _child_cgroups(directory_fd: int) -> tuple[str, ...]:
        scan_fd = -1
        try:
            scan_fd = os.open(
                ".",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            names = os.listdir(scan_fd)
            children = tuple(
                sorted(
                    name
                    for name in names
                    if stat.S_ISDIR(
                        os.stat(
                            name,
                            dir_fd=directory_fd,
                            follow_symlinks=False,
                        ).st_mode
                    )
                )
            )
        except OSError as exc:
            raise FreezerError("LOCAL_AUTH_CGROUP_TOPOLOGY") from exc
        finally:
            if scan_fd >= 0:
                os.close(scan_fd)
        return children

    @classmethod
    def _validate_unit_limits(cls, unit_fd: int, *, require_controller_only: bool) -> None:
        maximum = cls._read_named(unit_fd, "pids.max")
        current = cls._read_named(unit_fd, "pids.current")
        events = cls._read_named(unit_fd, "pids.events")
        memory = cls._read_named(unit_fd, "memory.max")
        if maximum != b"21\n" or memory != b"1073741824\n":
            raise FreezerError("LOCAL_AUTH_SERVICE_LIMITS")
        if require_controller_only and current != b"1\n":
            raise FreezerError("LOCAL_AUTH_SERVICE_NOT_EMPTY")
        if events != b"max 0\n":
            raise FreezerError("LOCAL_AUTH_SERVICE_EXHAUSTED")

    @staticmethod
    def _read_ids(descriptor: int) -> tuple[int, ...]:
        try:
            text = os.pread(descriptor, 1_048_576, 0).decode("ascii", errors="strict")
        except (OSError, UnicodeError) as exc:
            raise FreezerError("LOCAL_AUTH_CGROUP_MEMBERSHIP") from exc
        lines = text.splitlines()
        if any(not line.isdecimal() or line.startswith("0") for line in lines):
            raise FreezerError("LOCAL_AUTH_CGROUP_MEMBERSHIP")
        values = tuple(sorted(int(line) for line in lines))
        if len(values) != len(set(values)):
            raise FreezerError("LOCAL_AUTH_CGROUP_MEMBERSHIP")
        return values

    def _events(self) -> CgroupEvents:
        try:
            payload = os.pread(self._controls["events"], 4096, 0)
        except OSError as exc:
            raise FreezerError("LOCAL_AUTH_CGROUP_EVENTS_INVALID") from exc
        return CgroupEvents.parse(payload)

    def _validate_identity(self) -> None:
        if self._removed:
            raise FreezerError("LOCAL_AUTH_CGROUP_IDENTITY")
        try:
            revalidate_controller_identity(self.controller)
            info = os.fstat(self.workload_fd)
            anchored = os.stat(
                self._WORKLOAD_NAME,
                dir_fd=self.unit_fd,
                follow_symlinks=False,
            )
        except (FreezerError, OSError) as exc:
            if isinstance(exc, FreezerError):
                raise
            raise FreezerError("LOCAL_AUTH_CGROUP_IDENTITY") from exc
        if (
            self._directory_identity != (self._mount_id(self.workload_fd), info.st_dev, info.st_ino)
            or (anchored.st_dev, anchored.st_ino) != (info.st_dev, info.st_ino)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise FreezerError("LOCAL_AUTH_CGROUP_IDENTITY")
        try:
            for key, (name, _flags) in self._CONTROLS.items():
                opened = os.fstat(self._controls[key])
                named = os.stat(
                    name,
                    dir_fd=self.workload_fd,
                    follow_symlinks=False,
                )
                if (
                    self._control_identities[key] != (opened.st_dev, opened.st_ino)
                    or (named.st_dev, named.st_ino)
                    != (opened.st_dev, opened.st_ino)
                ):
                    raise FreezerError("LOCAL_AUTH_CGROUP_IDENTITY")
            for key, name in self._UNIT_CONTROLS.items():
                opened = os.fstat(self._unit_controls[key])
                named = os.stat(name, dir_fd=self.unit_fd, follow_symlinks=False)
                if (
                    self._unit_control_identities[key] != (opened.st_dev, opened.st_ino)
                    or (named.st_dev, named.st_ino)
                    != (opened.st_dev, opened.st_ino)
                ):
                    raise FreezerError("LOCAL_AUTH_CGROUP_IDENTITY")
        except OSError as exc:
            raise FreezerError("LOCAL_AUTH_CGROUP_IDENTITY") from exc
        try:
            if os.pread(self._controls["type"], 4096, 0) != b"domain\n":
                raise FreezerError("LOCAL_AUTH_CGROUP_IDENTITY")
        except OSError as exc:
            raise FreezerError("LOCAL_AUTH_CGROUP_IDENTITY") from exc
        try:
            scan_fd = os.open(
                ".",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self.workload_fd,
            )
            scan_info = os.fstat(scan_fd)
            if (scan_info.st_dev, scan_info.st_ino) != (info.st_dev, info.st_ino):
                raise FreezerError("LOCAL_AUTH_CGROUP_IDENTITY")
            names = os.listdir(scan_fd)
            child_names = [
                name
                for name in names
                if stat.S_ISDIR(os.stat(name, dir_fd=self.workload_fd, follow_symlinks=False).st_mode)
            ]
        except OSError as exc:
            raise FreezerError("LOCAL_AUTH_CGROUP_TOPOLOGY") from exc
        finally:
            if "scan_fd" in locals():
                os.close(scan_fd)
        if child_names:
            raise FreezerError("LOCAL_AUTH_CGROUP_TOPOLOGY")
        if self._child_cgroups(self.unit_fd) != (self._WORKLOAD_NAME,):
            raise FreezerError("LOCAL_AUTH_CGROUP_TOPOLOGY")
        unit_procs_before = self._read_ids(self._unit_controls["procs"])
        unit_threads_before = self._read_ids(self._unit_controls["threads"])
        unit_procs_after = self._read_ids(self._unit_controls["procs"])
        unit_threads_after = self._read_ids(self._unit_controls["threads"])
        controller_only = (self.controller.process_id,)
        if (
            unit_procs_before != controller_only
            or unit_threads_before != controller_only
            or unit_procs_after != unit_procs_before
            or unit_threads_after != unit_threads_before
        ):
            raise FreezerError("LOCAL_AUTH_CGROUP_MEMBERSHIP")
        self._validate_unit_limits(self.unit_fd, require_controller_only=False)

    def _validate_recursive_task_count(self, expected: int) -> None:
        current = self._read_named(self.unit_fd, "pids.current")
        if not current.endswith(b"\n") or not current[:-1].isdigit():
            raise FreezerError("LOCAL_AUTH_SERVICE_LIMITS")
        if int(current) != expected:
            raise FreezerError("LOCAL_AUTH_CGROUP_MEMBERSHIP")

    @staticmethod
    def _proc_tasks(process_id: int) -> tuple[int, ...]:
        try:
            names = tuple(path.name for path in (Path("/proc") / str(process_id) / "task").iterdir())
        except OSError as exc:
            raise FreezerError("LOCAL_AUTH_CGROUP_MEMBERSHIP") from exc
        if not names or any(not name.isdecimal() or name.startswith("0") for name in names):
            raise FreezerError("LOCAL_AUTH_CGROUP_MEMBERSHIP")
        return tuple(sorted(int(name) for name in names))

    def checkpoint(self, *, expected: WorkloadSnapshot | None = None) -> WorkloadSnapshot:
        self._validate_identity()
        process_before = self._read_ids(self._controls["procs"])
        thread_before = self._read_ids(self._controls["threads"])
        task_union = tuple(sorted(task for pid in process_before for task in self._proc_tasks(pid)))
        process_after = self._read_ids(self._controls["procs"])
        thread_after = self._read_ids(self._controls["threads"])
        self._validate_identity()
        if process_before != process_after or thread_before != thread_after:
            raise FreezerError("LOCAL_AUTH_CGROUP_MEMBERSHIP")
        if task_union != thread_before or self.controller.process_id in thread_before:
            raise FreezerError("LOCAL_AUTH_CGROUP_MEMBERSHIP")
        self._validate_recursive_task_count(1 + len(thread_after))
        snapshot = WorkloadSnapshot(process_before, thread_before)
        if expected is not None and snapshot != expected:
            raise FreezerError("LOCAL_AUTH_CGROUP_MEMBERSHIP")
        return snapshot

    def spawn(self, argv: list[str], *, pass_fds: tuple[int, ...]) -> Clone3Process:
        if (
            type(argv) is not list
            or not argv
            or any(type(item) is not str or not item for item in argv)
            or type(pass_fds) is not tuple
            or any(type(fd) is not int or fd < 0 for fd in pass_fds)
        ):
            raise FreezerError("LOCAL_AUTH_CLONE3_ARGUMENT")
        if fcntl is None:
            raise FreezerError("LOCAL_AUTH_CLONE3_UNAVAILABLE")
        if self.checkpoint() != WorkloadSnapshot((), ()):
            raise FreezerError("LOCAL_AUTH_CGROUP_NOT_EMPTY")
        allocated: list[int] = []
        try:
            stdin_read, stdin_write = os.pipe2(os.O_CLOEXEC)
            allocated.extend((stdin_read, stdin_write))
            stdout_read, stdout_write = os.pipe2(os.O_CLOEXEC)
            allocated.extend((stdout_read, stdout_write))
            stderr_read, stderr_write = os.pipe2(os.O_CLOEXEC)
            allocated.extend((stderr_read, stderr_write))
        except OSError as exc:
            for descriptor in allocated:
                os.close(descriptor)
            raise FreezerError("LOCAL_AUTH_PIPE_SETUP") from exc
        child_ends = (stdin_read, stdout_write, stderr_write)
        parent_ends = (stdin_write, stdout_read, stderr_read)
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            args = _CloneArgs(
                flags=self._CLONE_INTO_CGROUP,
                exit_signal=signal.SIGCHLD,
                cgroup=self.workload_fd,
            )
            result = libc.syscall(
                self._SYS_CLONE3,
                ctypes.byref(args),
                ctypes.sizeof(args),
            )
        except BaseException as exc:
            for descriptor in allocated:
                os.close(descriptor)
            raise FreezerError("LOCAL_AUTH_CLONE3_UNAVAILABLE") from exc
        if result == -1:
            error = ctypes.get_errno()
            for descriptor in (*child_ends, *parent_ends):
                os.close(descriptor)
            raise FreezerError("LOCAL_AUTH_CLONE3_UNAVAILABLE") from OSError(
                error, os.strerror(error)
            )
        if result == 0:
            try:
                for name in ("SIGPIPE", "SIGXFZ", "SIGXFSZ"):
                    selected = getattr(signal, name, None)
                    if selected is not None:
                        signal.signal(selected, signal.SIG_DFL)
                signal.pthread_sigmask(signal.SIG_SETMASK, set())
                for descriptor in parent_ends:
                    os.close(descriptor)
                for source, target in zip(child_ends, (0, 1, 2), strict=True):
                    os.dup2(source, target)
                for descriptor in pass_fds:
                    flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
                    fcntl.fcntl(descriptor, fcntl.F_SETFD, flags & ~fcntl.FD_CLOEXEC)
                keep = {0, 1, 2, *pass_fds}
                for name in os.listdir("/proc/self/fd"):
                    if name.isdecimal() and int(name) not in keep:
                        try:
                            os.close(int(name))
                        except OSError:
                            pass
                os.execve(argv[0], argv, {})
            except BaseException:
                os._exit(127)
        for descriptor in child_ends:
            os.close(descriptor)
        self._outer_pid = int(result)
        process: Clone3Process | None = None
        try:
            process = Clone3Process(self._outer_pid, *parent_ends)
            revalidate_controller_identity(self.controller)
        except BaseException:
            if process is not None:
                process.close()
            raise
        return process

    def _write_control(self, key: str, payload: bytes) -> None:
        self._validate_identity()
        descriptor = self._controls[key]
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            written = os.write(descriptor, payload)
        except OSError as exc:
            raise FreezerError("LOCAL_AUTH_CGROUP_CONTROL") from exc
        if written != len(payload):
            raise FreezerError("LOCAL_AUTH_CGROUP_CONTROL")

    def request_freeze(self) -> None:
        self._write_control("freeze", b"1\n")

    def request_thaw(self) -> None:
        self._write_control("freeze", b"0\n")

    def await_events(
        self,
        *,
        populated: bool,
        frozen: bool | None,
        deadline: float,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> CgroupEvents:
        while True:
            self._validate_identity()
            events = self._events()
            if events.populated is populated and (frozen is None or events.frozen is frozen):
                return events
            if monotonic() >= deadline:
                raise FreezerError("LOCAL_AUTH_FREEZE_TIMEOUT")
            time.sleep(0.005)

    def kill_and_drain(self, process: Clone3Process, *, deadline: float) -> None:
        self._validate_identity()
        self._cleanup_bound(process=process, deadline=deadline)

    def _bound_events(self) -> CgroupEvents:
        descriptor = self._controls["events"]
        opened = os.fstat(descriptor)
        if self._control_identities["events"] != (opened.st_dev, opened.st_ino):
            raise FreezerError("LOCAL_AUTH_CGROUP_IDENTITY")
        try:
            payload = os.pread(descriptor, 4096, 0)
        except OSError as exc:
            raise FreezerError("LOCAL_AUTH_CGROUP_EVENTS_INVALID") from exc
        return CgroupEvents.parse(payload)

    def _write_bound_control(self, key: str, payload: bytes) -> None:
        descriptor = self._controls[key]
        opened = os.fstat(descriptor)
        if self._control_identities[key] != (opened.st_dev, opened.st_ino):
            raise FreezerError("LOCAL_AUTH_CGROUP_IDENTITY")
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            written = os.write(descriptor, payload)
        except OSError as exc:
            raise FreezerError("LOCAL_AUTH_CGROUP_KILL_FAILED") from exc
        if written != len(payload):
            raise FreezerError("LOCAL_AUTH_CGROUP_KILL_FAILED")

    def _cleanup_bound(
        self,
        *,
        process: Clone3Process | None,
        deadline: float,
    ) -> None:
        """Kill and reap through the originally opened cgroup objects only."""
        events = self._bound_events()
        if events.populated:
            self._write_bound_control("kill", b"1\n")
            while self._bound_events().populated:
                if time.monotonic() >= deadline:
                    raise FreezerError("LOCAL_AUTH_CGROUP_KILL_FAILED")
                time.sleep(0.005)
        if process is not None:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise FreezerError("LOCAL_AUTH_CGROUP_KILL_FAILED") from exc
            self._outer_pid = None
        self._reap_outer(deadline)

    def _reap_outer(self, deadline: float) -> None:
        if self._outer_pid is None:
            return
        while True:
            try:
                waited, _status = os.waitpid(self._outer_pid, os.WNOHANG)
            except ChildProcessError:
                self._outer_pid = None
                return
            if waited == self._outer_pid:
                self._outer_pid = None
                return
            if time.monotonic() >= deadline:
                raise FreezerError("LOCAL_AUTH_CGROUP_KILL_FAILED")
            time.sleep(0.005)

    def close(self, *, process: Clone3Process | None, deadline: float) -> None:
        if self._removed:
            return
        failure: BaseException | None = None
        identity_valid = False
        try:
            self._validate_identity()
            identity_valid = True
        except BaseException as exc:
            failure = exc
        try:
            self._cleanup_bound(process=process, deadline=deadline)
        except BaseException as exc:
            failure = failure or exc
            identity_valid = False
        if identity_valid:
            try:
                self._validate_identity()
                self._validate_recursive_task_count(1)
            except BaseException as exc:
                failure = failure or exc
                identity_valid = False
        if process is not None:
            process.close()
        for descriptor in self._controls.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        for descriptor in self._unit_controls.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.close(self.workload_fd)
            if identity_valid and failure is None:
                try:
                    os.rmdir(self._WORKLOAD_NAME, dir_fd=self.unit_fd)
                except OSError as exc:
                    failure = FreezerError("LOCAL_AUTH_CGROUP_REMOVE_FAILED")
                    failure.__cause__ = exc
        finally:
            os.close(self.unit_fd)
            os.close(self.controller.pidfd)
            self._removed = True
        if failure is not None:
            raise failure
