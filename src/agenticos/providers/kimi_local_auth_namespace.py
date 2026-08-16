"""Read-only credential mount guard and exact Kimi ACP launcher."""

from __future__ import annotations

import errno
import fcntl
import os
import platform
import re
import resource
import stat
import sys
from pathlib import Path
from typing import Callable, Final, Mapping, NoReturn


KIMI_EXECUTABLE: Final = "/opt/agenticos/kimi/bin/kimi"
SANDBOX_CREDENTIAL_LEAF: Final = Path(
    "/home/aos/kimi/credentials/kimi-code.json"
)
_DECIMAL_METADATA: Final = re.compile(r"[0-9]+\Z")
_EXACT_ENVIRONMENT: Final = {
    "HOME": "/home/aos",
    "KIMI_CODE_HOME": "/home/aos/kimi",
    "KIMI_CODE_NO_AUTO_UPDATE": "1",
    "KIMI_DISABLE_CRON": "1",
    "KIMI_DISABLE_TELEMETRY": "1",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/opt/agenticos/kimi/bin:/usr/bin",
    "PWD": "/workspace",
    "TMPDIR": "/tmp",
}

_BPF_LD_W_ABS: Final = 0x20
_BPF_JMP_JEQ_K: Final = 0x15
_BPF_RET_K: Final = 0x06
_AUDIT_ARCH_X86_64: Final = 0xC000003E
_X86_64_NR_SOCKET: Final = 41
_SECCOMP_RET_KILL_PROCESS: Final = 0x80000000
_SECCOMP_RET_TRAP: Final = 0x00030000
_SECCOMP_RET_ALLOW: Final = 0x7FFF0000
_PR_SET_NO_NEW_PRIVS: Final = 38
_PR_SET_SECCOMP: Final = 22
_SECCOMP_MODE_FILTER: Final = 2


class NamespaceLauncherError(RuntimeError):
    pass


def _no_inet_filter_instructions() -> tuple[tuple[int, int, int, int], ...]:
    """Return the literal x86-64 classic-BPF policy installed below."""

    return (
        # seccomp_data.arch; x86-64 skips the kill instruction.
        (_BPF_LD_W_ABS, 0, 0, 4),
        (_BPF_JMP_JEQ_K, 1, 0, _AUDIT_ARCH_X86_64),
        (_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        # seccomp_data.nr; every syscall other than socket jumps to ALLOW.
        (_BPF_LD_W_ABS, 0, 0, 0),
        (_BPF_JMP_JEQ_K, 0, 3, _X86_64_NR_SOCKET),
        # seccomp_data.args[0]; AF_INET and AF_INET6 jump to TRAP.
        (_BPF_LD_W_ABS, 0, 0, 16),
        (_BPF_JMP_JEQ_K, 2, 0, 2),
        (_BPF_JMP_JEQ_K, 1, 0, 10),
        (_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW),
        (_BPF_RET_K, 0, 0, _SECCOMP_RET_TRAP),
    )


def assert_mount_identity(
    expected_device: int,
    expected_inode: int,
    *,
    leaf: Path = SANDBOX_CREDENTIAL_LEAF,
) -> None:
    """Require the exact validated credential object at the one sandbox leaf."""

    if (
        type(expected_device) is not int
        or expected_device < 0
        or type(expected_inode) is not int
        or expected_inode <= 0
        or not isinstance(leaf, Path)
        or not leaf.is_absolute()
    ):
        raise NamespaceLauncherError("CREDENTIAL_MOUNT_ARGUMENT")
    try:
        info = leaf.lstat()
    except OSError as exc:
        raise NamespaceLauncherError("CREDENTIAL_MOUNT_IDENTITY") from exc
    if (
        leaf.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or (info.st_dev, info.st_ino) != (expected_device, expected_inode)
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise NamespaceLauncherError("CREDENTIAL_MOUNT_IDENTITY")


def assert_no_inherited_descriptors() -> None:
    """Probe every descriptor above stderr through the soft RLIMIT_NOFILE cap."""

    soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if (
        type(soft_limit) is not int
        or soft_limit == resource.RLIM_INFINITY
        or soft_limit < 3
    ):
        raise NamespaceLauncherError("DESCRIPTOR_LIMIT_INVALID")
    for descriptor in range(3, soft_limit):
        try:
            fcntl.fcntl(descriptor, fcntl.F_GETFD)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise NamespaceLauncherError("DESCRIPTOR_PROBE_FAILED") from exc
        raise NamespaceLauncherError("INHERITED_DESCRIPTOR")


def install_no_inet_seccomp() -> None:
    """Trap IPv4/IPv6 socket creation while allowing all other syscalls."""

    import ctypes

    class SockFilter(ctypes.Structure):
        _fields_ = (
            ("code", ctypes.c_ushort),
            ("jt", ctypes.c_ubyte),
            ("jf", ctypes.c_ubyte),
            ("k", ctypes.c_uint32),
        )

    class SockFprog(ctypes.Structure):
        _fields_ = (
            ("length", ctypes.c_ushort),
            ("filters", ctypes.POINTER(SockFilter)),
        )

    if platform.machine() != "x86_64":
        raise NamespaceLauncherError("SECCOMP_ARCH_UNSUPPORTED")
    rows = _no_inet_filter_instructions()
    filters = (SockFilter * len(rows))(*(SockFilter(*row) for row in rows))
    program = SockFprog(len(rows), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = (
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    prctl.restype = ctypes.c_int
    if prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise NamespaceLauncherError("NO_NEW_PRIVS_FAILED") from OSError(
            error, os.strerror(error)
        )
    program_address = ctypes.cast(ctypes.pointer(program), ctypes.c_void_p).value
    if program_address is None or prctl(
        _PR_SET_SECCOMP,
        _SECCOMP_MODE_FILTER,
        program_address,
        0,
        0,
    ) != 0:
        error = ctypes.get_errno()
        raise NamespaceLauncherError("SECCOMP_INSTALL_FAILED") from OSError(
            error, os.strerror(error)
        )


def exec_official_acp(
    environment: Mapping[str, str],
    *,
    execve: Callable[[str, list[str], dict[str, str]], NoReturn] = os.execve,
) -> NoReturn:
    """Execute the only command and environment this launcher represents."""

    if dict(environment) != _EXACT_ENVIRONMENT:
        raise NamespaceLauncherError("ACP_ENVIRONMENT_DRIFT")
    execve(KIMI_EXECUTABLE, [KIMI_EXECUTABLE, "acp"], dict(environment))
    raise NamespaceLauncherError("ACP_EXEC_RETURNED")


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if (
        len(arguments) != 2
        or any(_DECIMAL_METADATA.fullmatch(argument) is None for argument in arguments)
    ):
        raise NamespaceLauncherError("CREDENTIAL_MOUNT_ARGUMENT")
    expected_device, expected_inode = (int(argument) for argument in arguments)
    assert_mount_identity(expected_device, expected_inode)
    assert_no_inherited_descriptors()
    install_no_inet_seccomp()
    exec_official_acp(dict(os.environ))


if __name__ == "__main__":
    raise SystemExit(main())
