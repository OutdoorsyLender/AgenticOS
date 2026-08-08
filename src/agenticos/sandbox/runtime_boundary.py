"""Milestone 4A namespace and minimal-runtime boundary primitives.

This module is Linux-only security infrastructure.  It never falls back to
pathname authorization or a weaker isolation backend.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional


EXPECTED_BWRAP_PATH = Path("/usr/bin/bwrap")
EXPECTED_BWRAP_VERSION = "bubblewrap 0.11.1"
EXPECTED_BWRAP_SHA256 = (
    "8e19e40e7d5f7a7e8b488c7926feb040"
    "eab6ed10c58fa360e266d2f70670e92b"
)

SYS_OPENAT2_X86_64 = 437
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
RESOLVE_FLAGS = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS
O_PATH = getattr(os, "O_PATH", 0o10000000)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0o2000000)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0o400000)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0o200000)
O_PATH_FLAGS = O_PATH | O_CLOEXEC | O_NOFOLLOW


class RuntimeBoundaryUnavailable(RuntimeError):
    """Raised when M4A cannot establish its exact runtime boundary."""


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    file_type: int

    @classmethod
    def from_stat(cls, observed: os.stat_result) -> "FileIdentity":
        return cls(
            device=int(observed.st_dev),
            inode=int(observed.st_ino),
            file_type=stat.S_IFMT(observed.st_mode),
        )


@dataclass(frozen=True)
class AuthorizedSource:
    locator: Path
    fd: int
    identity: FileIdentity


@dataclass(frozen=True)
class BubblewrapCapability:
    path: Path
    supported: bool
    reasons: tuple[str, ...]
    version: Optional[str]
    sha256: Optional[str]
    uid: Optional[int]
    gid: Optional[int]
    mode: Optional[int]
    setuid: bool
    setgid: bool
    file_capabilities: Optional[str]
    unprivileged_user_namespace: bool
    nested_user_namespace_denied: bool


class M4AProfile(str, Enum):
    INSPECT = "L1_INSPECT"
    BUILD = "L2_BUILD"


class MountRole(str, Enum):
    WORKSPACE = "workspace"
    RUNTIME = "runtime"
    LAUNCHER = "launcher"
    WORKER = "worker"
    TASK_TMP = "task_tmp"
    SYNTHETIC_HOME = "synthetic_home"


@dataclass(frozen=True)
class AuthorizedMount:
    source: AuthorizedSource
    destination: str
    role: MountRole
    bind_option: str
    landlock_mode: str
    allow_socket: bool = False


@dataclass(frozen=True)
class RuntimeBoundaryPlan:
    profile: M4AProfile
    mounts: tuple[AuthorizedMount, ...]
    cwd: str
    worker_environment: tuple[tuple[str, str], ...]
    namespace_flags: tuple[str, ...]
    network_policy: str
    filesystem_view_digest: str
    environment_policy_digest: str
    combined_policy_digest: str
    digest_payload: dict

    def mount_for(self, destination: str) -> AuthorizedMount:
        matches = [mount for mount in self.mounts if mount.destination == destination]
        if len(matches) != 1:
            raise RuntimeBoundaryUnavailable(
                f"runtime destination is not unique: {destination!r}"
            )
        return matches[0]


WORKER_ENVIRONMENT = (
    ("HOME", "/home/tool"),
    ("PATH", "/usr/bin:/bin"),
    ("LANG", "C.UTF-8"),
    ("LC_ALL", "C.UTF-8"),
    ("TMPDIR", "/tmp"),
    ("PWD", "/workspace"),
)

EXPLICIT_NAMESPACE_FLAGS = (
    "--unshare-user",
    "--unshare-pid",
    "--unshare-net",
    "--unshare-ipc",
    "--unshare-uts",
    "--disable-userns",
    "--new-session",
    "--die-with-parent",
)


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


def _require_linux_x86_64() -> None:
    machine = platform.machine().lower()
    if not sys.platform.startswith("linux") or machine not in {"x86_64", "amd64"}:
        raise RuntimeBoundaryUnavailable(
            f"M4A openat2 is supported only on recorded Linux x86_64, got "
            f"platform={sys.platform!r} machine={machine!r}"
        )


def _openat2_from_root(
    canonical: Path,
    *,
    flags: int = O_PATH_FLAGS,
    resolve: int = RESOLVE_FLAGS,
    retries: int = 3,
) -> int:
    _require_linux_x86_64()
    if not canonical.is_absolute():
        raise RuntimeBoundaryUnavailable("authorized source must be absolute")
    relative = os.fsencode(str(canonical)).lstrip(b"/") or b"."
    libc = ctypes.CDLL(None, use_errno=True)
    how = _OpenHow(flags=flags, mode=0, resolve=resolve)
    root_fd = os.open("/", O_PATH | O_DIRECTORY | O_CLOEXEC)
    try:
        for _attempt in range(retries):
            result = int(
                libc.syscall(
                    SYS_OPENAT2_X86_64,
                    root_fd,
                    ctypes.c_char_p(relative),
                    ctypes.byref(how),
                    ctypes.sizeof(how),
                )
            )
            if result >= 0:
                return result
            error_number = ctypes.get_errno()
            if error_number == errno.EAGAIN:
                continue
            raise RuntimeBoundaryUnavailable(
                f"openat2 authorization failed: errno={error_number}"
            )
    finally:
        os.close(root_fd)
    raise RuntimeBoundaryUnavailable("openat2 authorization remained unstable")


def secure_open_source(locator: Path, *, expected_type: int) -> AuthorizedSource:
    """Open a canonical source by kernel identity with no weaker fallback."""
    try:
        canonical = Path(locator).resolve(strict=True)
    except OSError as exc:
        raise RuntimeBoundaryUnavailable(
            f"authorized source locator failed: {type(exc).__name__}"
        ) from exc
    fd = _openat2_from_root(canonical)
    try:
        identity = FileIdentity.from_stat(os.fstat(fd))
        if identity.file_type != expected_type:
            raise RuntimeBoundaryUnavailable(
                "authorized source has wrong type: "
                f"expected={expected_type:#x} observed={identity.file_type:#x}"
            )
        return AuthorizedSource(canonical, fd, identity)
    except BaseException:
        os.close(fd)
        raise


def _read_file_capabilities(path: Path) -> Optional[str]:
    getcap = shutil.which("getcap")
    if getcap is None:
        return None
    try:
        completed = subprocess.run(
            [getcap, str(path)],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _stat_executable(path: Path) -> os.stat_result:
    return os.stat(path, follow_symlinks=False)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _probe_unprivileged_bwrap(path: Path) -> tuple[bool, bool, str]:
    names = ("user", "mnt", "net", "pid", "ipc", "uts")
    host = {name: os.readlink(f"/proc/self/ns/{name}") for name in names}
    inner_code = (
        "import json,os,subprocess;"
        "names=('user','mnt','net','pid','ipc','uts');"
        "ns={n:os.readlink('/proc/self/ns/'+n) for n in names};"
        "p=subprocess.run(['/usr/bin/unshare','--user','/usr/bin/true'],"
        "capture_output=True,text=True);"
        "print(json.dumps({'ns':ns,'nested_rc':p.returncode}))"
    )
    command = [
        str(path),
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--disable-userns",
        "--new-session",
        "--die-with-parent",
        "--clearenv",
        "--tmpfs",
        "/",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/sbin",
        "/sbin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--setenv",
        "PATH",
        "/usr/bin",
        "--",
        "/usr/bin/python3",
        "-c",
        inner_code,
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, False, f"behavior probe raised {type(exc).__name__}"
    if completed.returncode != 0:
        return False, False, (
            f"behavior probe rc={completed.returncode}: "
            f"{completed.stderr.strip()[:160]}"
        )
    try:
        payload = json.loads(completed.stdout)
        namespace_ok = all(payload["ns"][name] != host[name] for name in names)
        nested_denied = int(payload["nested_rc"]) != 0
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return False, False, f"behavior probe evidence invalid: {type(exc).__name__}"
    return namespace_ok, nested_denied, ""


def probe_bubblewrap(
    path: Path = EXPECTED_BWRAP_PATH,
    *,
    run_behavior_probe: bool = True,
) -> BubblewrapCapability:
    """Verify the exact non-privileged Bubblewrap backend; never install it."""
    executable = Path(path)
    reasons: list[str] = []
    version: Optional[str] = None
    sha256: Optional[str] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    mode: Optional[int] = None
    setuid = False
    setgid = False
    file_capabilities = _read_file_capabilities(executable)
    unprivileged_user_namespace = False
    nested_user_namespace_denied = False

    try:
        observed = _stat_executable(executable)
        uid, gid, mode = int(observed.st_uid), int(observed.st_gid), stat.S_IMODE(observed.st_mode)
        setuid = bool(observed.st_mode & stat.S_ISUID)
        setgid = bool(observed.st_mode & stat.S_ISGID)
        if not stat.S_ISREG(observed.st_mode):
            reasons.append("Bubblewrap executable is not a regular file")
        if uid != 0 or gid != 0:
            reasons.append(f"unexpected Bubblewrap owner uid={uid} gid={gid}")
        if mode != 0o755:
            reasons.append(f"unexpected Bubblewrap mode {mode:#o}")
        if setuid:
            reasons.append("Bubblewrap setuid bit is present")
        if setgid:
            reasons.append("Bubblewrap setgid bit is present")
        sha256 = _sha256_file(executable)
    except OSError as exc:
        reasons.append(f"Bubblewrap executable unavailable: {type(exc).__name__}")

    if file_capabilities is None:
        reasons.append("Bubblewrap file capabilities could not be verified")
    elif file_capabilities:
        reasons.append("unexpected Bubblewrap file capabilities are present")

    if run_behavior_probe and not reasons:
        try:
            completed = subprocess.run(
                [str(executable), "--version"],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            lines = completed.stdout.splitlines()
            if completed.returncode != 0 or len(lines) != 1:
                reasons.append("Bubblewrap version probe failed")
            else:
                version = lines[0].strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            reasons.append(f"Bubblewrap version probe raised {type(exc).__name__}")
        if version != EXPECTED_BWRAP_VERSION:
            reasons.append(f"unexpected Bubblewrap version {version!r}")
        if sha256 != EXPECTED_BWRAP_SHA256:
            reasons.append(f"unexpected Bubblewrap SHA-256 {sha256!r}")
        if not reasons:
            (
                unprivileged_user_namespace,
                nested_user_namespace_denied,
                behavior_reason,
            ) = _probe_unprivileged_bwrap(executable)
            if behavior_reason:
                reasons.append(behavior_reason)
            if not unprivileged_user_namespace:
                reasons.append("required unprivileged namespace separation failed")
            if not nested_user_namespace_denied:
                reasons.append("nested user namespace creation was not denied")

    return BubblewrapCapability(
        path=executable,
        supported=not reasons,
        reasons=tuple(reasons),
        version=version,
        sha256=sha256,
        uid=uid,
        gid=gid,
        mode=mode,
        setuid=setuid,
        setgid=setgid,
        file_capabilities=file_capabilities,
        unprivileged_user_namespace=unprivileged_user_namespace,
        nested_user_namespace_denied=nested_user_namespace_denied,
    )


def build_worker_env(_controller_env: Optional[Mapping[str, str]] = None) -> dict[str, str]:
    """Return the complete worker environment; ambient input is never merged."""
    return dict(WORKER_ENVIRONMENT)


def _canonical_digest(payload: object) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_runtime_plan(
    *,
    profile: M4AProfile,
    workspace: AuthorizedSource,
    runtime_usr: AuthorizedSource,
    launcher: AuthorizedSource,
    worker: AuthorizedSource,
    task_tmp: AuthorizedSource,
    synthetic_home: AuthorizedSource,
) -> RuntimeBoundaryPlan:
    """Build the fixed M4A source-to-synthetic-destination policy."""
    if not isinstance(profile, M4AProfile):
        raise ValueError(f"invalid M4A profile: {profile!r}")
    workspace_bind = "--ro-bind-fd" if profile is M4AProfile.INSPECT else "--bind-fd"
    workspace_mode = "r" if profile is M4AProfile.INSPECT else "w"
    mounts = (
        AuthorizedMount(
            workspace,
            "/workspace",
            MountRole.WORKSPACE,
            workspace_bind,
            workspace_mode,
        ),
        AuthorizedMount(
            runtime_usr,
            "/usr",
            MountRole.RUNTIME,
            "--ro-bind-fd",
            "x",
        ),
        AuthorizedMount(
            launcher,
            "/opt/agenticos/fs_launcher",
            MountRole.LAUNCHER,
            "--ro-bind-fd",
            "x",
        ),
        AuthorizedMount(
            worker,
            "/opt/agenticos/worker.py",
            MountRole.WORKER,
            "--ro-bind-fd",
            "r",
        ),
        AuthorizedMount(
            task_tmp,
            "/tmp",
            MountRole.TASK_TMP,
            "--bind-fd",
            "ws",
            allow_socket=True,
        ),
        AuthorizedMount(
            synthetic_home,
            "/home/tool",
            MountRole.SYNTHETIC_HOME,
            "--bind-fd",
            "w",
        ),
    )
    destinations = [mount.destination for mount in mounts]
    if len(destinations) != len(set(destinations)):
        raise RuntimeBoundaryUnavailable("duplicate fixed runtime destination")
    fs_payload = {
        "mounts": [
            {
                "destination": mount.destination,
                "role": mount.role.value,
                "bind": mount.bind_option,
                "landlock": mount.landlock_mode,
                "allow_socket": mount.allow_socket,
                "identity": {
                    "device": mount.source.identity.device,
                    "inode": mount.source.identity.inode,
                    "file_type": mount.source.identity.file_type,
                },
            }
            for mount in mounts
        ],
        "symlinks": {
            "/bin": "usr/bin",
            "/sbin": "usr/sbin",
            "/lib": "usr/lib",
            "/lib64": "usr/lib64",
        },
        "cwd": "/workspace",
        "proc": "new",
        "dev": "synthetic",
        "run": "empty",
    }
    environment = dict(WORKER_ENVIRONMENT)
    environment_digest = _canonical_digest(environment)
    fs_digest = _canonical_digest(fs_payload)
    combined_payload = {
        "profile": profile.value,
        "filesystem_view_digest": fs_digest,
        "environment_policy_digest": environment_digest,
        "namespace_flags": list(EXPLICIT_NAMESPACE_FLAGS),
        "network_policy": "DENY",
    }
    combined_digest = _canonical_digest(combined_payload)
    digest_payload = {
        "filesystem": fs_payload,
        "environment": environment,
        "combined": combined_payload,
    }
    return RuntimeBoundaryPlan(
        profile=profile,
        mounts=mounts,
        cwd="/workspace",
        worker_environment=WORKER_ENVIRONMENT,
        namespace_flags=EXPLICIT_NAMESPACE_FLAGS,
        network_policy="DENY",
        filesystem_view_digest=fs_digest,
        environment_policy_digest=environment_digest,
        combined_policy_digest=combined_digest,
        digest_payload=digest_payload,
    )


def _append_directory(argv: list[str], destination: str) -> None:
    if destination in {"/usr", "/workspace", "/tmp", "/home/tool"}:
        argv.extend(("--dir", destination))


def build_bwrap_argv(
    plan: RuntimeBoundaryPlan,
    *,
    namespace_gate_fd: int,
    json_status_fd: int,
    launcher_status_fd: int,
    executable: Path = EXPECTED_BWRAP_PATH,
) -> list[str]:
    """Build a shell-free Bubblewrap command from fixed policy records."""
    setup_fds = (namespace_gate_fd, json_status_fd, launcher_status_fd)
    if len(set(setup_fds)) != len(setup_fds) or any(fd < 5 for fd in setup_fds):
        raise ValueError("setup descriptors must be unique and at least 5")
    argv = [str(executable), *plan.namespace_flags, "--clearenv", "--tmpfs", "/"]
    argv.extend(("--dir", "/opt", "--dir", "/opt/agenticos"))
    argv.extend(("--dir", "/home", "--dir", "/run"))
    for mount in plan.mounts:
        _append_directory(argv, mount.destination)
        argv.extend(
            (
                mount.bind_option,
                str(mount.source.fd),
                mount.destination,
            )
        )
    for target, destination in (
        ("usr/bin", "/bin"),
        ("usr/sbin", "/sbin"),
        ("usr/lib", "/lib"),
        ("usr/lib64", "/lib64"),
    ):
        argv.extend(("--symlink", target, destination))
    argv.extend(
        (
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--chdir",
            plan.cwd,
            "--setenv",
            "AOS_STATUS_FD",
            str(launcher_status_fd),
            "--block-fd",
            str(namespace_gate_fd),
            "--json-status-fd",
            str(json_status_fd),
            "--",
            "/opt/agenticos/fs_launcher",
        )
    )
    return argv
