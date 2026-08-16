"""Metadata-only credential and controller-evidence boundary for Kimi Level 1."""

from __future__ import annotations

import argparse
import array
import json
import os
import re
import select
import signal
import stat
import subprocess
import sys
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Final

try:
    import fcntl
    import termios
except ModuleNotFoundError:  # pragma: no cover - exercised by Windows regressions
    fcntl = None  # type: ignore[assignment]
    termios = None  # type: ignore[assignment]

from agenticos.providers.kimi_local_auth import (
    ACPProtocolState,
    KimiLocalAuthError,
    KimiLocalAuthSession,
    LocalAuthProtocolOutcome,
    LocalCredentialState,
    QualificationState,
)
from agenticos.providers.kimi_local_auth_freezer import (
    CaptureAuthority,
    CaptureState,
    FreezerError,
    WorkloadCgroup,
    WorkloadSnapshot,
    parse_delegated_service_membership,
    validate_running_systemd_service,
)
from agenticos.providers.kimi_login import (
    KimiLoginError,
    validate_repository_identity,
)
from agenticos.providers.kimi_policy import (
    PINNED_EXECUTABLE_SHA256,
    KimiPolicyError,
    build_kimi_environment,
    sha256_file,
    validate_future_credential_directory,
)
import agenticos.providers.kimi_runtime as kimi_runtime


REAL_PROVIDER_STATE_ROOT: Final = Path(
    "/home/brand/.local/share/agenticos/provider-state/kimi-code/0.36.1"
)
REAL_EVIDENCE_ROOT: Final = Path(
    "/home/brand/.local/share/agenticos/controller-evidence/kimi-code/0.36.1/level1-local-auth"
)
SANDBOX_WORKSPACE_ROOT: Final = Path("/workspace")
REPO_ROOT: Final = Path("/home/brand/src/AgenticOS")
_CANONICAL_LOCAL_AUTH_EXECUTABLE: Final = Path(
    "/home/brand/.local/share/agenticos/provider-qualification/"
    "kimi-code/0.36.1/runtime/bin/kimi"
)
_CANONICAL_LOCAL_AUTH_BUNDLE: Final = (
    REPO_ROOT / "qualification" / "kimi-code" / "0.36.1"
)
SANDBOX_LOCAL_AUTH_LAUNCHER: Final = (
    "/opt/agenticos/kimi/local_auth_namespace.py"
)
SANDBOX_CREDENTIAL_ROOT: Final = "/home/aos/kimi/credentials"
SANDBOX_CREDENTIAL_LEAF: Final = (
    "/home/aos/kimi/credentials/kimi-code.json"
)
_CANONICAL_LOCAL_AUTH_LAUNCHER: Final = Path(__file__).with_name(
    "kimi_local_auth_namespace.py"
)
_PINNED_LOCAL_AUTH_LAUNCHER_SHA256: Final = (
    "861c5fecbf9599e158000fb732c661e51c9592c20be55e0eef458d1d663e60db"
)
LOCAL_AUTH_SCRIPT: Final = REPO_ROOT / "scripts" / "run_kimi_local_auth.py"
PRE_REAL_GATE: Final = (
    REPO_ROOT
    / "docs"
    / "phase-zero"
    / "first-autonomous-build-slice-f1-kimi-local-auth-pre-real.md"
)

QUALIFIED_LOCAL_AUTH_TASKS_MAX: Final = 21
LOCAL_AUTH_MEMORY_MAX_BYTES: Final = 1_073_741_824
LOCAL_AUTH_TIMEOUT_SECONDS: Final = 30.0
LOCAL_AUTH_MAX_FRAMES: Final = 4
LOCAL_AUTH_MAX_FRAME_BYTES: Final = 65_536
LOCAL_AUTH_MAX_STDERR_BYTES: Final = 65_536
LOCAL_AUTH_CLEANUP_GRACE_SECONDS: Final = 2.0
_LOCAL_AUTH_SERVICE_SUFFIX: Final = "/aos-kimi-level1-local-auth.service"
_NETWORK_NAMESPACE: Final = re.compile(r"net:\[[0-9]+\]\Z")

_ATTEMPT_FILE: Final = "attempt.json"
_RESULT_FILE: Final = "result.json"
_COMMIT_ID: Final = re.compile(r"[0-9a-f]{40}\Z")
_PROTOCOL_COMBINATIONS: Final = frozenset(
    {
        (
            QualificationState.COMPLETE,
            LocalCredentialState.LOADABLE,
            "ACP_LOCAL_AUTH_SUCCESS",
        ),
        (
            QualificationState.BLOCKED,
            LocalCredentialState.REJECTED,
            "ACP_LOCAL_AUTH_REJECTED",
        ),
        (
            QualificationState.BLOCKED,
            LocalCredentialState.BLOCKED,
            "ACP_LOCAL_AUTH_BLOCKED",
        ),
    }
)
_PERSISTED_REASON_CODES: Final = frozenset(
    {
        "ACP_ERROR_RESPONSE",
        "ACP_LOCAL_AUTH_BLOCKED",
        "ACP_LOCAL_AUTH_REJECTED",
        "ACP_LOCAL_AUTH_SUCCESS",
        "AUTHENTICATE_ORDER",
        "AUTH_METHOD_SHAPE",
        "CAPABILITIES_SHAPE",
        "CREDENTIAL_HANDLE_INVALID",
        "DUPLICATE_JSON_KEY",
        "DUPLICATE_TERMINAL",
        "FRAME_TOO_LARGE",
        "INCOMPLETE_TRANSCRIPT",
        "INITIALIZE_ORDER",
        "INITIALIZE_SHAPE",
        "INVALID_FRAME_TYPE",
        "INVALID_UTF8",
        "LOCAL_AUTH_ARTIFACT_SUBSTITUTION",
        "LOCAL_AUTH_CAPTURE_READER_FAILED",
        "LOCAL_AUTH_CAPTURE_FAILED",
        "LOCAL_AUTH_CAPTURE_REVOKED",
        "LOCAL_AUTH_CENSUS_ARGV",
        "LOCAL_AUTH_CENSUS_EXECUTABLE",
        "LOCAL_AUTH_CENSUS_FAILED",
        "LOCAL_AUTH_CENSUS_FD",
        "LOCAL_AUTH_CENSUS_POLICY",
        "LOCAL_AUTH_CLEANUP_FAILED",
        "LOCAL_AUTH_CGROUP_CONTROL",
        "LOCAL_AUTH_CGROUP_EVENTS_INVALID",
        "LOCAL_AUTH_CGROUP_FILESYSTEM",
        "LOCAL_AUTH_CGROUP_IDENTITY",
        "LOCAL_AUTH_CGROUP_KILL_FAILED",
        "LOCAL_AUTH_CGROUP_MEMBERSHIP",
        "LOCAL_AUTH_CGROUP_NOT_EMPTY",
        "LOCAL_AUTH_CGROUP_REMOVE_FAILED",
        "LOCAL_AUTH_CGROUP_TOPOLOGY",
        "LOCAL_AUTH_CLONE3_UNAVAILABLE",
        "LOCAL_AUTH_CONTROLLER_IDENTITY",
        "LOCAL_AUTH_CONTROLLER_THREAD",
        "LOCAL_AUTH_FREEZE_REQUEST_FAILED",
        "LOCAL_AUTH_FREEZE_TIMEOUT",
        "LOCAL_AUTH_LAUNCHER_IDENTITY",
        "LOCAL_AUTH_LAUNCHER_SUBSTITUTION",
        "LOCAL_AUTH_LATE_OUTPUT",
        "LOCAL_AUTH_NETWORK_POLICY_VIOLATION",
        "LOCAL_AUTH_PIN_RECHECK_FAILED",
        "LOCAL_AUTH_PIPE_SETUP",
        "LOCAL_AUTH_PROCESS_CRASH",
        "LOCAL_AUTH_PROCESS_IDENTITY",
        "LOCAL_AUTH_PROCESS_IO",
        "LOCAL_AUTH_PROTOCOL_ORDER",
        "LOCAL_AUTH_PROTOCOL_STATE",
        "LOCAL_AUTH_RUNTIME_ARGUMENT",
        "LOCAL_AUTH_SERVICE_EXHAUSTED",
        "LOCAL_AUTH_SERVICE_INVALID",
        "LOCAL_AUTH_SERVICE_LIMITS",
        "LOCAL_AUTH_SERVICE_NOT_EMPTY",
        "LOCAL_AUTH_SERVICE_PROPERTIES",
        "LOCAL_AUTH_SERVICE_REQUIRED",
        "LOCAL_AUTH_STDERR_LIMIT",
        "LOCAL_AUTH_STDOUT_CLOSED",
        "LOCAL_AUTH_STDOUT_FRAME_COUNT",
        "LOCAL_AUTH_STDOUT_FRAME_LIMIT",
        "LOCAL_AUTH_TIMEOUT",
        "MALFORMED_JSON",
        "MALFORMED_JSON_RPC",
        "MALFORMED_RESPONSE",
        "TRUNCATED_FRAME",
        "UNEXPECTED_CALLBACK",
        "UNEXPECTED_RESPONSE",
        "UNEXPECTED_RESPONSE_ID",
        "WRONG_ACP_VERSION",
        "WRONG_AGENT_IDENTITY",
    }
)
_COUNT_FIELDS: Final = frozenset(
    {
        "process_count",
        "descendant_count",
        "environment_name_count",
        "fd_class_count",
        "external_endpoint_count",
        "session_artifact_count",
    }
)
_BOOLEAN_FIELDS: Final = frozenset({"cleanup_complete"})


class KimiLocalAuthRuntimeError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class LocalAuthCensus:
    process_count: int
    descendant_count: int
    environment_names: tuple[str, ...]
    fd_classes: tuple[str, ...]
    network_namespace: str
    external_endpoint_count: int
    session_artifact_count: int
    cleanup_complete: bool


@dataclass(frozen=True, slots=True)
class LocalAuthRunOutcome:
    protocol: LocalAuthProtocolOutcome
    census: LocalAuthCensus
    reason_code: str


@dataclass(frozen=True, slots=True)
class KimiLocalAuthSpec:
    executable: Path
    bundle: Path
    namespace_launcher: Path
    state_root: Path
    evidence_root: Path

    def __post_init__(self) -> None:
        paths = (
            self.executable,
            self.bundle,
            self.namespace_launcher,
            self.state_root,
            self.evidence_root,
        )
        if any(not isinstance(path, Path) or not path.is_absolute() for path in paths):
            raise KimiLocalAuthRuntimeError("LOCAL_AUTH_RUNTIME_PATH")


@dataclass(slots=True)
class CredentialLeafHandle:
    descriptor: int
    device: int
    inode: int
    uid: int
    mode: int
    link_count: int
    _closed: bool = field(default=False, init=False, repr=False)

    def close(self) -> None:
        if self._closed:
            return
        os.close(self.descriptor)
        self._closed = True


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _overlaps(left: Path, right: Path) -> bool:
    return _is_within(left, right) or _is_within(right, left)


def _resolve_existing(path: Path, code: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise KimiLocalAuthRuntimeError(code)
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise KimiLocalAuthRuntimeError(code) from exc


def _reject_credential_crossover(resolved: Path) -> None:
    if resolved == REAL_PROVIDER_STATE_ROOT:
        return
    if (
        _overlaps(resolved, REAL_PROVIDER_STATE_ROOT)
        or _overlaps(resolved, REAL_EVIDENCE_ROOT)
        or _overlaps(resolved, SANDBOX_WORKSPACE_ROOT)
    ):
        raise KimiLocalAuthRuntimeError("SYNTHETIC_REAL_CROSSOVER")


def _reject_evidence_crossover(resolved: Path) -> None:
    if resolved == REAL_EVIDENCE_ROOT:
        return
    if (
        _overlaps(resolved, REAL_PROVIDER_STATE_ROOT)
        or _overlaps(resolved, REAL_EVIDENCE_ROOT)
        or _overlaps(resolved, SANDBOX_WORKSPACE_ROOT)
    ):
        raise KimiLocalAuthRuntimeError("SYNTHETIC_REAL_CROSSOVER")


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _validate_private_owned_ancestry(
    path: Path,
    *,
    expected_uid: int,
    code: str,
) -> None:
    current = path
    while True:
        try:
            info = current.lstat()
        except OSError as exc:
            raise KimiLocalAuthRuntimeError(code) from exc
        if info.st_uid != expected_uid:
            return
        if (
            current.is_symlink()
            or not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise KimiLocalAuthRuntimeError(code)
        parent = current.parent
        if parent == current:
            return
        current = parent


def open_validated_credential_leaf(
    state_root: Path,
    *,
    trusted_state_root: Path,
    expected_uid: int,
) -> CredentialLeafHandle:
    """Open only an unreadable Linux metadata descriptor for the fixed leaf."""

    if type(expected_uid) is not int or expected_uid < 0:
        raise KimiLocalAuthRuntimeError("CREDENTIAL_DIRECTORY_ARGUMENT")
    resolved_state = _resolve_existing(state_root, "CREDENTIAL_DIRECTORY_PATH")
    resolved_trusted = _resolve_existing(
        trusted_state_root, "CREDENTIAL_DIRECTORY_PATH"
    )
    _reject_credential_crossover(resolved_state)
    _reject_credential_crossover(resolved_trusted)

    credential_root = state_root / "credentials"
    leaf = credential_root / "kimi-code.json"
    try:
        before_validation = leaf.lstat()
    except OSError:
        before_validation = None
    try:
        validate_future_credential_directory(
            credential_root,
            trusted_state_root=trusted_state_root,
            expected_uid=expected_uid,
        )
    except KimiPolicyError as exc:
        raise KimiLocalAuthRuntimeError(exc.code) from exc
    _validate_private_owned_ancestry(
        trusted_state_root,
        expected_uid=expected_uid,
        code="CREDENTIAL_DIRECTORY_MODE",
    )
    try:
        after_validation = leaf.lstat()
    except OSError as exc:
        code = (
            "CREDENTIAL_ENTRY_TYPE"
            if before_validation is None
            else "CREDENTIAL_INODE_CHANGED"
        )
        raise KimiLocalAuthRuntimeError(code) from exc
    if before_validation is None or not _same_inode(
        before_validation, after_validation
    ):
        raise KimiLocalAuthRuntimeError("CREDENTIAL_INODE_CHANGED")

    o_path = getattr(os, "O_PATH", None)
    if type(o_path) is not int:
        raise KimiLocalAuthRuntimeError("O_PATH_UNAVAILABLE")
    flags = o_path | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(leaf, flags)
    except OSError as exc:
        raise KimiLocalAuthRuntimeError("CREDENTIAL_OPEN_FAILED") from exc
    try:
        opened = os.fstat(descriptor)
        lexical = leaf.lstat()
        if not (
            _same_inode(before_validation, opened)
            and _same_inode(opened, lexical)
        ):
            raise KimiLocalAuthRuntimeError("CREDENTIAL_INODE_CHANGED")
        if not stat.S_ISREG(opened.st_mode):
            raise KimiLocalAuthRuntimeError("CREDENTIAL_ENTRY_TYPE")
        if opened.st_uid != expected_uid:
            raise KimiLocalAuthRuntimeError("CREDENTIAL_FILE_OWNER")
        if stat.S_IMODE(opened.st_mode) != 0o600:
            raise KimiLocalAuthRuntimeError("CREDENTIAL_FILE_MODE")
        if opened.st_nlink != 1:
            raise KimiLocalAuthRuntimeError("CREDENTIAL_FILE_LINK_COUNT")
    except BaseException:
        os.close(descriptor)
        raise
    return CredentialLeafHandle(
        descriptor=descriptor,
        device=opened.st_dev,
        inode=opened.st_ino,
        uid=opened.st_uid,
        mode=stat.S_IMODE(opened.st_mode),
        link_count=opened.st_nlink,
    )


def _assert_launchable_credential(credential: CredentialLeafHandle) -> None:
    if (
        not isinstance(credential, CredentialLeafHandle)
        or credential._closed
        or credential.descriptor < 3
        or credential.device < 0
        or credential.inode <= 0
        or credential.uid < 0
        or credential.mode != 0o600
        or credential.link_count != 1
    ):
        raise KimiLocalAuthRuntimeError("CREDENTIAL_HANDLE_INVALID")
    try:
        info = os.fstat(credential.descriptor)
        descriptor_flags = fcntl.fcntl(credential.descriptor, fcntl.F_GETFD)
        status_flags = fcntl.fcntl(credential.descriptor, fcntl.F_GETFL)
    except OSError as exc:
        raise KimiLocalAuthRuntimeError("CREDENTIAL_HANDLE_INVALID") from exc
    o_path = getattr(os, "O_PATH", None)
    if (
        type(o_path) is not int
        or status_flags & o_path != o_path
        or descriptor_flags & fcntl.FD_CLOEXEC != fcntl.FD_CLOEXEC
        or not stat.S_ISREG(info.st_mode)
        or (info.st_dev, info.st_ino) != (credential.device, credential.inode)
        or info.st_uid != credential.uid
        or stat.S_IMODE(info.st_mode) != credential.mode
        or info.st_nlink != credential.link_count
    ):
        raise KimiLocalAuthRuntimeError("CREDENTIAL_HANDLE_INVALID")


def _launcher_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _verify_canonical_launcher(path: Path) -> None:
    if path != _CANONICAL_LOCAL_AUTH_LAUNCHER:
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_LAUNCHER_SUBSTITUTION")
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_LAUNCHER_IDENTITY") from exc
    if (
        resolved != path
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != 0o644
        or before.st_nlink != 1
    ):
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_LAUNCHER_IDENTITY")
    try:
        digest = sha256_file(path)
        after = path.lstat()
    except OSError as exc:
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_LAUNCHER_IDENTITY") from exc
    if (
        digest != _PINNED_LOCAL_AUTH_LAUNCHER_SHA256
        or _launcher_identity(before) != _launcher_identity(after)
    ):
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_LAUNCHER_IDENTITY")


def _verify_local_auth_launch_artifacts(
    spec: KimiLocalAuthSpec,
) -> kimi_runtime.KimiRuntimeSpec:
    try:
        verified = kimi_runtime.build_runtime_spec(spec.executable, spec.bundle)
    except kimi_runtime.KimiRuntimeError as exc:
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_PIN_RECHECK_FAILED") from exc
    if (
        verified.executable != _CANONICAL_LOCAL_AUTH_EXECUTABLE
        or verified.bundle != _CANONICAL_LOCAL_AUTH_BUNDLE
    ):
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_ARTIFACT_SUBSTITUTION")
    _verify_canonical_launcher(spec.namespace_launcher)
    return verified


def build_local_auth_bwrap_argv(
    spec: KimiLocalAuthSpec,
    credential: CredentialLeafHandle,
) -> list[str]:
    """Build the route-less namespace around exactly one credential leaf."""

    if not isinstance(spec, KimiLocalAuthSpec):
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_RUNTIME_ARGUMENT")
    verified = _verify_local_auth_launch_artifacts(spec)
    _assert_launchable_credential(credential)
    argv = [
        str(kimi_runtime.BWRAP),
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--hostname",
        "agenticos-kimi-local-auth",
        "--clearenv",
        "--tmpfs",
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/lib",
        "/lib",
        "--ro-bind",
        "/lib64",
        "/lib64",
        "--dir",
        "/opt",
        "--dir",
        "/opt/agenticos",
        "--dir",
        "/opt/agenticos/kimi",
        "--dir",
        "/opt/agenticos/kimi/bin",
        "--ro-bind",
        str(verified.executable),
        kimi_runtime.SANDBOX_EXECUTABLE,
        "--ro-bind",
        str(spec.namespace_launcher),
        SANDBOX_LOCAL_AUTH_LAUNCHER,
        "--dir",
        "/home",
        "--dir",
        "/home/aos",
        "--tmpfs",
        "/home/aos/kimi",
        "--ro-bind",
        str(verified.bundle / "config.toml"),
        "/home/aos/kimi/config.toml",
        "--ro-bind",
        str(verified.bundle / "agents"),
        "/home/aos/kimi/agents",
        "--tmpfs",
        SANDBOX_CREDENTIAL_ROOT,
        "--dir",
        SANDBOX_CREDENTIAL_ROOT,
        "--ro-bind-fd",
        str(credential.descriptor),
        SANDBOX_CREDENTIAL_LEAF,
        "--remount-ro",
        SANDBOX_CREDENTIAL_ROOT,
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/workspace",
        "--chdir",
        "/workspace",
    ]
    for name, value in build_kimi_environment().items():
        argv.extend(("--setenv", name, value))
    argv.extend(
        (
            "--",
            "/usr/bin/python3",
            SANDBOX_LOCAL_AUTH_LAUNCHER,
            str(credential.device),
            str(credential.inode),
        )
    )
    return argv


def default_local_auth_spec() -> KimiLocalAuthSpec:
    return KimiLocalAuthSpec(
        executable=_CANONICAL_LOCAL_AUTH_EXECUTABLE,
        bundle=_CANONICAL_LOCAL_AUTH_BUNDLE,
        namespace_launcher=(
            REPO_ROOT
            / "src"
            / "agenticos"
            / "providers"
            / "kimi_local_auth_namespace.py"
        ),
        state_root=REAL_PROVIDER_STATE_ROOT,
        evidence_root=REAL_EVIDENCE_ROOT,
    )


def validate_local_auth_service(
    cgroup_text: str,
    *,
    cgroup_root: Path = Path("/sys/fs/cgroup"),
) -> None:
    """Admit only the fresh, exact finite delegated Level-1 service."""

    try:
        relative = parse_delegated_service_membership(cgroup_text)
    except FreezerError as exc:
        raise KimiLocalAuthRuntimeError(exc.code) from exc
    parts = Path(relative).parts
    if (
        not relative.startswith("/")
        or not relative.endswith(_LOCAL_AUTH_SERVICE_SUFFIX)
        or ".." in parts
        or not isinstance(cgroup_root, Path)
        or not cgroup_root.is_absolute()
    ):
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_SERVICE_REQUIRED")
    service_root = cgroup_root.joinpath(*parts[1:])
    try:
        maximum = (service_root / "pids.max").read_text(encoding="ascii").strip()
        current = (service_root / "pids.current").read_text(encoding="ascii").strip()
        events = (service_root / "pids.events").read_text(encoding="ascii").strip()
        memory = (service_root / "memory.max").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_SERVICE_INVALID") from exc
    if not maximum.isdecimal() or int(maximum) != QUALIFIED_LOCAL_AUTH_TASKS_MAX:
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_SERVICE_LIMITS")
    if not current.isdecimal():
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_SERVICE_INVALID")
    if int(current) != 1:
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_SERVICE_NOT_EMPTY")
    event_parts = events.split()
    if (
        len(event_parts) != 2
        or event_parts[0] != "max"
        or not event_parts[1].isdecimal()
    ):
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_SERVICE_INVALID")
    if int(event_parts[1]) != 0:
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_SERVICE_EXHAUSTED")
    if not memory.isdecimal() or int(memory) != LOCAL_AUTH_MEMORY_MAX_BYTES:
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_SERVICE_LIMITS")
    if cgroup_root == Path("/sys/fs/cgroup"):
        try:
            validate_running_systemd_service(os.getpid(), relative)
        except FreezerError as exc:
            raise KimiLocalAuthRuntimeError(exc.code) from exc


def local_auth_systemd_command(candidate_commit: str) -> list[str]:
    """Return the only admitted owner vector for the conditional real attempt."""

    if type(candidate_commit) is not str or _COMMIT_ID.fullmatch(candidate_commit) is None:
        raise KimiLocalAuthRuntimeError("CLI_ARGUMENT")
    uid_reader = getattr(os, "getuid", None)
    uid = uid_reader() if uid_reader is not None else 1000
    service_cgroup = (
        f"/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service/"
        "app.slice/aos-kimi-level1-local-auth.service"
    )
    return [
        "/usr/bin/systemd-run",
        "--user",
        "--service-type=exec",
        "--wait",
        "--collect",
        "--pipe",
        "--quiet",
        "--unit=aos-kimi-level1-local-auth",
        "--property=Delegate=yes",
        "--property=KillMode=control-group",
        "--property=SendSIGKILL=yes",
        "--property=TimeoutStopSec=5s",
        "--property=Restart=no",
        f"--property=TasksMax={QUALIFIED_LOCAL_AUTH_TASKS_MAX}",
        "--property=MemoryMax=1G",
        "--property=ProtectControlGroups=yes",
        f"--property=BindPaths={service_cgroup}",
        "/usr/bin/python3",
        str(LOCAL_AUTH_SCRIPT),
        "--expected-commit",
        candidate_commit,
    ]


def _validate_local_auth_script() -> None:
    try:
        lexical = LOCAL_AUTH_SCRIPT.lstat()
        resolved = LOCAL_AUTH_SCRIPT.resolve(strict=True)
        invoked = Path(sys.argv[0]).resolve(strict=True)
    except OSError as exc:
        raise KimiLocalAuthRuntimeError("SCRIPT_IDENTITY") from exc
    if (
        resolved != LOCAL_AUTH_SCRIPT
        or invoked != LOCAL_AUTH_SCRIPT
        or LOCAL_AUTH_SCRIPT.is_symlink()
        or not stat.S_ISREG(lexical.st_mode)
        or lexical.st_uid != os.getuid()
        or stat.S_IMODE(lexical.st_mode) not in (0o644, 0o755)
        or lexical.st_nlink != 1
    ):
        raise KimiLocalAuthRuntimeError("SCRIPT_IDENTITY")


def _read_self_cgroup() -> str:
    try:
        return Path("/proc/self/cgroup").read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_SERVICE_INVALID") from exc


def validate_local_auth_spec(
    spec: KimiLocalAuthSpec,
    *,
    expected_uid: int,
) -> None:
    """Recheck the immutable runtime and the two fixed external roots."""

    if (
        not isinstance(spec, KimiLocalAuthSpec)
        or type(expected_uid) is not int
        or expected_uid < 0
        or spec != default_local_auth_spec()
    ):
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_RUNTIME_ARGUMENT")
    _verify_local_auth_launch_artifacts(spec)
    state = _resolve_existing(spec.state_root, "CREDENTIAL_DIRECTORY_PATH")
    evidence = _resolve_existing(spec.evidence_root, "EVIDENCE_ROOT_PATH")
    if state != REAL_PROVIDER_STATE_ROOT or evidence != REAL_EVIDENCE_ROOT:
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_RUNTIME_PATH")
    evidence_fd = _open_validated_evidence_root(spec.evidence_root, expected_uid)
    os.close(evidence_fd)


def validate_pre_real_gate(repo_root: Path, candidate_commit: str) -> None:
    """Require the fixed Task-7 GO checkpoint before marker or credential open."""

    if (
        repo_root != REPO_ROOT
        or type(candidate_commit) is not str
        or _COMMIT_ID.fullmatch(candidate_commit) is None
        or PRE_REAL_GATE.parent != repo_root / "docs" / "phase-zero"
    ):
        raise KimiLocalAuthRuntimeError("PRE_REAL_GATE_BLOCKED")
    try:
        payload = PRE_REAL_GATE.read_bytes()
        text = payload.decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise KimiLocalAuthRuntimeError("PRE_REAL_GATE_BLOCKED") from exc
    if len(payload) > 65_536:
        raise KimiLocalAuthRuntimeError("PRE_REAL_GATE_BLOCKED")
    required = (
        "F1_KIMI_LEVEL1_PRE_REAL_GATE=GO",
        "UNRESOLVED_CRITICAL=0",
        "UNRESOLVED_IMPORTANT=0",
        "REAL_ATTEMPT_COUNT=0",
        "REAL_LOGIN_EXECUTED=NO",
        "REAL_PROMPT_EXECUTED=NO",
        "REAL_INFERENCE_EXECUTED=NO",
    )
    lines = text.splitlines()
    if any(lines.count(line) != 1 for line in required):
        raise KimiLocalAuthRuntimeError("PRE_REAL_GATE_BLOCKED")


def _validate_candidate(candidate_commit: str, expected_uid: int) -> None:
    if (
        type(candidate_commit) is not str
        or _COMMIT_ID.fullmatch(candidate_commit) is None
        or type(expected_uid) is not int
        or expected_uid < 0
    ):
        raise KimiLocalAuthRuntimeError("EVIDENCE_ARGUMENT")


def _open_validated_evidence_root(evidence_root: Path, expected_uid: int) -> int:
    resolved = _resolve_existing(evidence_root, "EVIDENCE_ROOT_PATH")
    _reject_evidence_crossover(resolved)
    try:
        lexical = evidence_root.lstat()
    except OSError as exc:
        raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_PATH") from exc
    if evidence_root.is_symlink() or not stat.S_ISDIR(lexical.st_mode):
        raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_TYPE")
    if lexical.st_uid != expected_uid:
        raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_OWNER")
    if stat.S_IMODE(lexical.st_mode) != 0o700:
        raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_MODE")
    _validate_private_owned_ancestry(
        evidence_root,
        expected_uid=expected_uid,
        code="EVIDENCE_ROOT_MODE",
    )

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(evidence_root, flags)
    except OSError as exc:
        raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_OPEN") from exc
    try:
        opened = os.fstat(descriptor)
        if not _same_inode(lexical, opened):
            raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_CHANGED")
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != expected_uid
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_CHANGED")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def _persist_exclusive(
    directory_fd: int,
    name: str,
    payload: bytes,
    *,
    exists_code: str,
    failure_code: str,
    expected_uid: int,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    except FileExistsError as exc:
        raise KimiLocalAuthRuntimeError(exists_code) from exc
    except OSError as exc:
        raise KimiLocalAuthRuntimeError(failure_code) from exc
    try:
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != expected_uid
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
        ):
            raise KimiLocalAuthRuntimeError(failure_code)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written < 1:
                raise KimiLocalAuthRuntimeError(failure_code)
            remaining = remaining[written:]
        os.fsync(descriptor)
    except KimiLocalAuthRuntimeError:
        raise
    except OSError as exc:
        raise KimiLocalAuthRuntimeError(failure_code) from exc
    finally:
        os.close(descriptor)
    try:
        os.fsync(directory_fd)
    except OSError as exc:
        raise KimiLocalAuthRuntimeError(failure_code) from exc


def _claim_payload(candidate_commit: str) -> dict[str, object]:
    return {
        "schema": "AOS_KIMI_LEVEL1_ATTEMPT/1",
        "attempt": 1,
        "candidate_commit": candidate_commit,
        "pinned_executable_sha256": PINNED_EXECUTABLE_SHA256,
        "lifecycle": "CLAIMED_BEFORE_LAUNCH",
    }


def claim_real_attempt(
    evidence_root: Path,
    *,
    candidate_commit: str,
    expected_uid: int,
) -> None:
    _validate_candidate(candidate_commit, expected_uid)
    directory_fd = _open_validated_evidence_root(evidence_root, expected_uid)
    try:
        try:
            entries = set(os.listdir(directory_fd))
        except OSError as exc:
            raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_UNREADABLE") from exc
        if _ATTEMPT_FILE in entries:
            raise KimiLocalAuthRuntimeError("ATTEMPT_ALREADY_CLAIMED")
        if entries:
            raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_ENTRIES")
        _persist_exclusive(
            directory_fd,
            _ATTEMPT_FILE,
            _canonical_json(_claim_payload(candidate_commit)),
            exists_code="ATTEMPT_ALREADY_CLAIMED",
            failure_code="ATTEMPT_EVIDENCE_WRITE_FAILED",
            expected_uid=expected_uid,
        )
    finally:
        os.close(directory_fd)


def _validate_protocol(protocol: LocalAuthProtocolOutcome) -> None:
    if (
        type(protocol) is not LocalAuthProtocolOutcome
        or type(protocol.qualification) is not QualificationState
        or type(protocol.credential_state) is not LocalCredentialState
        or protocol.auth_state != "LOCAL_ONLY"
        or protocol.level2_status
        != "BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT"
        or type(protocol.reason_code) is not str
    ):
        raise KimiLocalAuthRuntimeError("RESULT_PROTOCOL_FIELDS")
    if (
        protocol.qualification,
        protocol.credential_state,
        protocol.reason_code,
    ) not in _PROTOCOL_COMBINATIONS:
        raise KimiLocalAuthRuntimeError("RESULT_PROTOCOL_COMBINATION")


def _validated_census(census_counts: Mapping[str, int | bool]) -> dict[str, int | bool]:
    if not isinstance(census_counts, Mapping):
        raise KimiLocalAuthRuntimeError("RESULT_CENSUS_FIELDS")
    if not set(census_counts).issubset(_COUNT_FIELDS | _BOOLEAN_FIELDS):
        raise KimiLocalAuthRuntimeError("RESULT_CENSUS_FIELDS")
    result: dict[str, int | bool] = {}
    for name, value in census_counts.items():
        if name in _COUNT_FIELDS:
            if type(value) is not int or value < 0:
                raise KimiLocalAuthRuntimeError("RESULT_CENSUS_FIELDS")
        elif type(value) is not bool:
            raise KimiLocalAuthRuntimeError("RESULT_CENSUS_FIELDS")
        result[name] = value
    return result


def _validated_result_reason(
    protocol: LocalAuthProtocolOutcome,
    reason_code: str,
) -> str:
    if type(reason_code) is not str or reason_code not in _PERSISTED_REASON_CODES:
        raise KimiLocalAuthRuntimeError("RESULT_REASON_CODE")
    if protocol.credential_state is LocalCredentialState.LOADABLE:
        expected = "ACP_LOCAL_AUTH_SUCCESS"
    elif protocol.credential_state is LocalCredentialState.REJECTED:
        expected = "ACP_LOCAL_AUTH_REJECTED"
    else:
        expected = None
    if expected is not None and reason_code != expected:
        raise KimiLocalAuthRuntimeError("RESULT_REASON_CODE")
    if expected is None and reason_code in {
        "ACP_LOCAL_AUTH_SUCCESS",
        "ACP_LOCAL_AUTH_REJECTED",
    }:
        raise KimiLocalAuthRuntimeError("RESULT_REASON_CODE")
    return reason_code


def _read_exact_claim(
    directory_fd: int,
    *,
    candidate_commit: str,
    expected_uid: int,
) -> None:
    expected = _canonical_json(_claim_payload(candidate_commit))
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(_ATTEMPT_FILE, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise KimiLocalAuthRuntimeError("ATTEMPT_MARKER_INVALID") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != expected_uid
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size != len(expected)
        ):
            raise KimiLocalAuthRuntimeError("ATTEMPT_MARKER_INVALID")
        observed = bytearray()
        while len(observed) <= len(expected):
            chunk = os.read(descriptor, len(expected) + 1 - len(observed))
            if not chunk:
                break
            observed.extend(chunk)
        if bytes(observed) != expected:
            raise KimiLocalAuthRuntimeError("ATTEMPT_MARKER_INVALID")
    except KimiLocalAuthRuntimeError:
        raise
    except OSError as exc:
        raise KimiLocalAuthRuntimeError("ATTEMPT_MARKER_INVALID") from exc
    finally:
        os.close(descriptor)


def persist_typed_result(
    evidence_root: Path,
    protocol: LocalAuthProtocolOutcome,
    census_counts: Mapping[str, int | bool],
    *,
    reason_code: str | None = None,
    candidate_commit: str,
    expected_uid: int,
) -> None:
    _validate_candidate(candidate_commit, expected_uid)
    _validate_protocol(protocol)
    persisted_reason = _validated_result_reason(
        protocol,
        protocol.reason_code if reason_code is None else reason_code,
    )
    census = _validated_census(census_counts)
    directory_fd = _open_validated_evidence_root(evidence_root, expected_uid)
    try:
        try:
            entries = set(os.listdir(directory_fd))
        except OSError as exc:
            raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_UNREADABLE") from exc
        if _RESULT_FILE in entries:
            raise KimiLocalAuthRuntimeError("RESULT_ALREADY_PERSISTED")
        if entries != {_ATTEMPT_FILE}:
            raise KimiLocalAuthRuntimeError("ATTEMPT_MARKER_INVALID")
        _read_exact_claim(
            directory_fd,
            candidate_commit=candidate_commit,
            expected_uid=expected_uid,
        )
        result = {
            "F1_KIMI_LEVEL1_LOCAL_AUTH_QUALIFICATION": protocol.qualification.value,
            "F1_KIMI_LOCAL_CREDENTIAL_STATE": protocol.credential_state.value,
            "F1_KIMI_AUTH_STATE": protocol.auth_state,
            "F1_KIMI_LEVEL2_NON_INFERENCE_STATUS": protocol.level2_status,
            "reason_code": persisted_reason,
            "census_counts": census,
        }
        _persist_exclusive(
            directory_fd,
            _RESULT_FILE,
            _canonical_json(result),
            exists_code="RESULT_ALREADY_PERSISTED",
            failure_code="RESULT_EVIDENCE_WRITE_FAILED",
            expected_uid=expected_uid,
        )
    finally:
        os.close(directory_fd)


class _LocalAuthRunFailure(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _blocked_protocol() -> LocalAuthProtocolOutcome:
    return LocalAuthProtocolOutcome(
        qualification=QualificationState.BLOCKED,
        credential_state=LocalCredentialState.BLOCKED,
        reason_code="ACP_LOCAL_AUTH_BLOCKED",
    )


def _empty_census(*, cleanup_complete: bool) -> LocalAuthCensus:
    return LocalAuthCensus(
        process_count=0,
        descendant_count=0,
        environment_names=(),
        fd_classes=(),
        network_namespace="UNKNOWN",
        external_endpoint_count=0,
        session_artifact_count=0,
        cleanup_complete=cleanup_complete,
    )


def _process_exit_code(process: object) -> str:
    returncode = getattr(process, "poll")()
    if returncode == -signal.SIGSYS:
        return "LOCAL_AUTH_NETWORK_POLICY_VIOLATION"
    return "LOCAL_AUTH_PROCESS_CRASH"


def _read_fd_classes(pid: int, process: object) -> tuple[str, ...]:
    root = Path("/proc") / str(pid) / "fd"
    try:
        names: set[str] = set()
        with os.scandir(root) as entries:
            for entry in entries:
                names.add(entry.name)
                if len(names) > 3:
                    raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CENSUS_FD")
        if names != {"0", "1", "2"}:
            raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CENSUS_FD")
        expected_streams = {
            "0": getattr(process, "stdin"),
            "1": getattr(process, "stdout"),
            "2": getattr(process, "stderr"),
        }
        for name, stream in expected_streams.items():
            expected = os.fstat(getattr(stream, "fileno")())
            observed = os.stat(root / name, follow_symlinks=True)
            if (
                not stat.S_ISFIFO(expected.st_mode)
                or not stat.S_ISFIFO(observed.st_mode)
                or (observed.st_dev, observed.st_ino)
                != (expected.st_dev, expected.st_ino)
            ):
                raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CENSUS_FD")
    except KimiLocalAuthRuntimeError:
        raise
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CENSUS_FAILED") from exc
    return ("pipe",)


def _count_inet_rows(pid: int) -> int:
    total = 0
    for name in ("tcp", "tcp6", "udp", "udp6"):
        try:
            rows = (Path("/proc") / str(pid) / "net" / name).read_text(
                encoding="ascii"
            ).splitlines()
        except (OSError, UnicodeError) as exc:
            raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CENSUS_FAILED") from exc
        total += max(0, len(rows) - 1)
    return total


_LOCAL_AUTH_ARTIFACT_ENTRY_LIMIT: Final = 64


def _count_sandbox_artifacts(
    sandbox_root: Path,
    *,
    deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> int:
    if not isinstance(sandbox_root, Path) or not sandbox_root.is_absolute():
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CENSUS_FAILED")
    selected_deadline = monotonic() + 0.25 if deadline is None else deadline

    def directory_names(path: Path) -> set[str]:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
            raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CENSUS_FAILED")
        names: set[str] = set()
        with os.scandir(path) as entries:
            for entry in entries:
                if monotonic() >= selected_deadline:
                    raise KimiLocalAuthRuntimeError("LOCAL_AUTH_TIMEOUT")
                if (
                    len(names) >= _LOCAL_AUTH_ARTIFACT_ENTRY_LIMIT
                    or entry.name in names
                ):
                    raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CENSUS_FAILED")
                names.add(entry.name)
        return names

    def require_regular(path: Path) -> None:
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CENSUS_FAILED")

    try:
        workspace = sandbox_root / "workspace"
        aos_home = sandbox_root / "home" / "aos"
        kimi_home = aos_home / "kimi"
        temporary = sandbox_root / "tmp"
        workspace_names = directory_names(workspace)
        temporary_names = directory_names(temporary)
        aos_home_names = directory_names(aos_home)
        kimi_names = directory_names(kimi_home)
        expected_kimi_names = {"agents", "config.toml", "credentials"}
        if not expected_kimi_names.issubset(kimi_names):
            raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CENSUS_FAILED")
        agents = kimi_home / "agents"
        credentials = kimi_home / "credentials"
        agent_names = directory_names(agents)
        if "agent.md" not in agent_names:
            raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CENSUS_FAILED")
        require_regular(agents / "agent.md")
        credential_names = directory_names(credentials)
        require_regular(kimi_home / "config.toml")
        if "kimi-code.json" not in credential_names:
            raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CENSUS_FAILED")
        require_regular(credentials / "kimi-code.json")
    except OSError as exc:
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CENSUS_FAILED") from exc
    return (
        len(workspace_names)
        + len(temporary_names)
        + len(aos_home_names - {"kimi"})
        + len(kimi_names - expected_kimi_names)
        + len(agent_names - {"agent.md"})
        + len(credential_names - {"kimi-code.json"})
    )


def _count_session_artifacts(pid: int) -> int:
    root = Path("/proc") / str(pid) / "root"
    return _count_sandbox_artifacts(root)


def _sample_local_auth_census(
    workload: object,
    process: object,
    argv: list[str],
    snapshot: WorkloadSnapshot,
    roles: "LocalAuthRoles",
    *,
    deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> LocalAuthCensus:
    """Reduce the identity-bound provider state to content-free census facts."""

    del workload, argv
    pid = roles.provider_pid
    proc_root = Path("/proc") / str(pid)
    try:
        namespace = os.readlink(proc_root / "ns" / "net")
    except OSError as exc:
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CENSUS_FAILED") from exc
    return LocalAuthCensus(
        process_count=len(snapshot.process_ids),
        descendant_count=len(snapshot.process_ids) - 1,
        # The child starts with an empty exec environment and the validated
        # launch/exec guards install this exact map.  Reading proc environ
        # would ingest provider-controlled, potentially credential-derived
        # memory into the controller.
        environment_names=tuple(sorted(build_kimi_environment())),
        fd_classes=_read_fd_classes(pid, process),
        network_namespace=namespace,
        external_endpoint_count=_count_inet_rows(pid),
        session_artifact_count=(
            _count_sandbox_artifacts(
                Path("/proc") / str(pid) / "root",
                deadline=deadline,
                monotonic=monotonic,
            )
            if deadline is not None
            else _count_session_artifacts(pid)
        ),
        cleanup_complete=False,
    )


def _validate_live_census(census: LocalAuthCensus) -> None:
    expected_environment = tuple(sorted(build_kimi_environment()))
    if (
        type(census) is not LocalAuthCensus
        or type(census.process_count) is not int
        or census.process_count != 1
        or type(census.descendant_count) is not int
        or census.descendant_count != 0
        or census.environment_names != expected_environment
        or census.fd_classes != ("pipe",)
        or _NETWORK_NAMESPACE.fullmatch(census.network_namespace) is None
        or type(census.external_endpoint_count) is not int
        or census.external_endpoint_count != 0
        or type(census.session_artifact_count) is not int
        or census.session_artifact_count != 0
        or type(census.cleanup_complete) is not bool
        or census.cleanup_complete
    ):
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CENSUS_POLICY")


def _close_stream(stream: object | None) -> None:
    if stream is None:
        return
    try:
        getattr(stream, "close")()
    except (OSError, ValueError):
        pass


class _LocalAuthCapture:
    """Controller-thread-only nonblocking stdout/stderr reduction."""

    def __init__(self, stdout: object, stderr: object) -> None:
        try:
            stdout_fd = getattr(stdout, "fileno")()
            stderr_fd = getattr(stderr, "fileno")()
            if (
                type(stdout_fd) is not int
                or type(stderr_fd) is not int
                or stdout_fd < 0
                or stderr_fd < 0
                or stdout_fd == stderr_fd
            ):
                raise ValueError
            os.set_blocking(stdout_fd, False)
            os.set_blocking(stderr_fd, False)
        except (AttributeError, OSError, TypeError, ValueError) as exc:
            raise _LocalAuthRunFailure("LOCAL_AUTH_PIPE_SETUP") from exc
        self._stdout_fd = stdout_fd
        self._stderr_fd = stderr_fd
        self._stdout_buffer = bytearray()
        self._frames: deque[bytes] = deque()
        self._frame_count = 0
        self._stderr_bytes = 0
        self._stdout_eof = False
        self._stderr_eof = False
        self._error_code: str | None = None

    def _latch_failure(self, code: str) -> _LocalAuthRunFailure:
        if self._error_code is None:
            self._error_code = code
        self._stdout_buffer.clear()
        self._frames.clear()
        return _LocalAuthRunFailure(self._error_code)

    def revoke(self, code: str) -> None:
        self._latch_failure(code)

    def seal(self) -> None:
        self._latch_failure("LOCAL_AUTH_CAPTURE_CONSUMED")

    def _consume_stdout(self, chunk: bytes) -> None:
        if self._error_code is not None:
            return
        self._stdout_buffer.extend(chunk)
        while True:
            newline = self._stdout_buffer.find(b"\n")
            if newline < 0:
                break
            frame_length = newline + 1
            if frame_length > LOCAL_AUTH_MAX_FRAME_BYTES:
                self._latch_failure("LOCAL_AUTH_STDOUT_FRAME_LIMIT")
                return
            frame = bytes(self._stdout_buffer[:frame_length])
            del self._stdout_buffer[:frame_length]
            self._frame_count += 1
            if self._frame_count > LOCAL_AUTH_MAX_FRAMES:
                self._latch_failure("LOCAL_AUTH_STDOUT_FRAME_COUNT")
                return
            self._frames.append(frame)
        if len(self._stdout_buffer) > LOCAL_AUTH_MAX_FRAME_BYTES:
            self._latch_failure("LOCAL_AUTH_STDOUT_FRAME_LIMIT")

    def require_stdout_quiet(self) -> None:
        self._raise_error()
        if self._frames or self._stdout_buffer or self._stdout_eof:
            raise self._latch_failure("LOCAL_AUTH_PROTOCOL_ORDER")
        try:
            readable, _writable, exceptional = select.select(
                [self._stdout_fd],
                [],
                [self._stdout_fd],
                0.0,
            )
        except (OSError, ValueError) as exc:
            raise self._latch_failure(
                "LOCAL_AUTH_CAPTURE_READER_FAILED"
            ) from exc
        if readable or exceptional:
            raise self._latch_failure("LOCAL_AUTH_PROTOCOL_ORDER")

    def _read_ready(
        self,
        timeout_seconds: float,
        deadline: float,
        monotonic: Callable[[], float],
    ) -> bool:
        self._raise_error()
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise self._latch_failure("LOCAL_AUTH_TIMEOUT")
        descriptors = []
        if not self._stdout_eof:
            descriptors.append(self._stdout_fd)
        if not self._stderr_eof:
            descriptors.append(self._stderr_fd)
        if not descriptors:
            return False
        try:
            readable, _writable, _exceptional = select.select(
                descriptors,
                [],
                [],
                min(max(0.0, timeout_seconds), remaining),
            )
        except (OSError, ValueError) as exc:
            raise self._latch_failure(
                "LOCAL_AUTH_CAPTURE_READER_FAILED"
            ) from exc
        self._raise_error()
        if monotonic() >= deadline:
            raise self._latch_failure("LOCAL_AUTH_TIMEOUT")
        if not readable:
            return False
        progressed = False
        for descriptor in readable:
            self._raise_error()
            if descriptor not in descriptors or monotonic() >= deadline:
                code = (
                    "LOCAL_AUTH_CAPTURE_READER_FAILED"
                    if descriptor not in descriptors
                    else "LOCAL_AUTH_TIMEOUT"
                )
                raise self._latch_failure(code)
            try:
                chunk = os.read(descriptor, 8_192)
            except BlockingIOError:
                if monotonic() >= deadline:
                    raise self._latch_failure("LOCAL_AUTH_TIMEOUT")
                continue
            except OSError as exc:
                raise self._latch_failure(
                    "LOCAL_AUTH_CAPTURE_READER_FAILED"
                ) from exc
            if monotonic() >= deadline:
                raise self._latch_failure("LOCAL_AUTH_TIMEOUT")
            progressed = True
            if descriptor == self._stdout_fd:
                if chunk:
                    self._consume_stdout(chunk)
                else:
                    self._stdout_eof = True
            elif chunk:
                self._stderr_bytes += len(chunk)
                if self._stderr_bytes > LOCAL_AUTH_MAX_STDERR_BYTES:
                    self._latch_failure("LOCAL_AUTH_STDERR_LIMIT")
            else:
                self._stderr_eof = True
            self._raise_error()
        return progressed

    def _raise_error(self) -> None:
        if self._error_code is not None:
            raise self._latch_failure(self._error_code)

    def next_frame(
        self,
        process: object,
        deadline: float,
        monotonic: Callable[[], float],
    ) -> bytes:
        while True:
            self._raise_error()
            if monotonic() >= deadline:
                raise self._latch_failure("LOCAL_AUTH_TIMEOUT")
            if self._frames:
                return self._frames.popleft()
            if self._stdout_eof:
                if self._stdout_buffer:
                    raise self._latch_failure("LOCAL_AUTH_STDOUT_FRAME_LIMIT")
                if getattr(process, "poll")() is not None:
                    raise _LocalAuthRunFailure(_process_exit_code(process))
                raise _LocalAuthRunFailure("LOCAL_AUTH_STDOUT_CLOSED")
            if getattr(process, "poll")() is not None:
                raise _LocalAuthRunFailure(_process_exit_code(process))
            remaining = deadline - monotonic()
            if remaining <= 0 or not self._read_ready(
                remaining,
                deadline,
                monotonic,
            ):
                raise self._latch_failure("LOCAL_AUTH_TIMEOUT")

    def drain_available(
        self,
        deadline: float,
        monotonic: Callable[[], float],
    ) -> tuple[bytes, ...]:
        while self._read_ready(0.0, deadline, monotonic):
            pass
        self._raise_error()
        if self._stdout_buffer:
            raise self._latch_failure("LOCAL_AUTH_STDOUT_FRAME_LIMIT")
        frames = tuple(self._frames)
        self._frames.clear()
        return frames

    def finish(
        self,
        deadline: float,
        monotonic: Callable[[], float],
    ) -> tuple[bool, tuple[bytes, ...]]:
        while not self._stdout_eof or not self._stderr_eof:
            if monotonic() >= deadline:
                raise self._latch_failure("LOCAL_AUTH_TIMEOUT")
            try:
                if self._read_ready(0.0, deadline, monotonic):
                    continue
            except _LocalAuthRunFailure as exc:
                if exc.code == "LOCAL_AUTH_TIMEOUT":
                    return False, ()
                raise
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise self._latch_failure("LOCAL_AUTH_TIMEOUT")
            try:
                if not self._read_ready(remaining, deadline, monotonic):
                    return False, ()
            except _LocalAuthRunFailure as exc:
                if exc.code == "LOCAL_AUTH_TIMEOUT":
                    return False, ()
                raise
        self._raise_error()
        if self._stdout_buffer:
            raise self._latch_failure("LOCAL_AUTH_STDOUT_FRAME_LIMIT")
        frames = tuple(self._frames)
        self._frames.clear()
        return True, frames


def _validate_post_eof_drain(
    process: object,
    stdout: object,
    stderr: object,
    *,
    deadline: float,
    monotonic: Callable[[], float],
) -> None:
    if fcntl is None or termios is None:
        raise _LocalAuthRunFailure("LOCAL_AUTH_PROCESS_IO")
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise _LocalAuthRunFailure("LOCAL_AUTH_TIMEOUT")
    try:
        returncode = getattr(process, "wait")(timeout=remaining)
    except subprocess.TimeoutExpired as exc:
        raise _LocalAuthRunFailure("LOCAL_AUTH_TIMEOUT") from exc
    if returncode != 0:
        raise _LocalAuthRunFailure(_process_exit_code(process))
    for stream in (stdout, stderr):
        pending = array.array("i", [0])
        try:
            fcntl.ioctl(getattr(stream, "fileno")(), termios.FIONREAD, pending, True)
        except (AttributeError, OSError, TypeError, ValueError) as exc:
            raise _LocalAuthRunFailure("LOCAL_AUTH_PROCESS_IO") from exc
        if pending[0] != 0:
            raise _LocalAuthRunFailure("LOCAL_AUTH_LATE_OUTPUT")


def _validate_freezer_census(
    census: LocalAuthCensus,
    snapshot: WorkloadSnapshot,
) -> None:
    if (
        type(census) is not LocalAuthCensus
        or census.process_count != len(snapshot.process_ids)
        or census.process_count < 3
        or census.descendant_count != census.process_count - 1
        or census.environment_names != tuple(sorted(build_kimi_environment()))
        or census.fd_classes != ("pipe",)
        or _NETWORK_NAMESPACE.fullmatch(census.network_namespace) is None
        or census.external_endpoint_count != 0
        or census.session_artifact_count != 0
        or census.cleanup_complete is not False
    ):
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CENSUS_POLICY")


@dataclass(frozen=True, slots=True)
class _LiveProcessRecord:
    process_id: int
    executable_identity: tuple[int, int]
    child_ids: tuple[int, ...]


@dataclass(slots=True)
class LocalAuthRoles:
    records: tuple[_LiveProcessRecord, ...]
    pidfds: tuple[int, ...]
    outer_pid: int
    inner_pid: int
    provider_pid: int

    def close(self) -> None:
        for descriptor in self.pidfds:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_live_process_record(process_id: int) -> _LiveProcessRecord:
    root = Path("/proc") / str(process_id)
    executable_fd = -1
    try:
        executable_fd = os.open(root / "exe", os.O_PATH | os.O_CLOEXEC)
        executable = os.fstat(executable_fd)
        if not stat.S_ISREG(executable.st_mode):
            raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CGROUP_TOPOLOGY")
        task_names = tuple(path.name for path in (root / "task").iterdir())
        if (
            not task_names
            or any(not name.isdecimal() or name.startswith("0") for name in task_names)
            or len(task_names) != len(set(task_names))
        ):
            raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CGROUP_TOPOLOGY")
        children: list[int] = []
        for task_name in task_names:
            descriptor = os.open(
                root / "task" / task_name / "children",
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                payload = os.read(descriptor, 1_048_577)
            finally:
                os.close(descriptor)
            if len(payload) > 1_048_576:
                raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CGROUP_TOPOLOGY")
            values = payload.decode("ascii", errors="strict").split()
            if any(not value.isdecimal() or value.startswith("0") for value in values):
                raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CGROUP_TOPOLOGY")
            children.extend(int(value) for value in values)
    except KimiLocalAuthRuntimeError:
        raise
    except (OSError, UnicodeError) as exc:
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CGROUP_TOPOLOGY") from exc
    finally:
        if executable_fd >= 0:
            os.close(executable_fd)
    if len(children) != len(set(children)):
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CGROUP_TOPOLOGY")
    return _LiveProcessRecord(
        process_id,
        (executable.st_dev, executable.st_ino),
        tuple(sorted(children)),
    )


def _pidfds_are_live(pidfds: tuple[int, ...]) -> bool:
    for descriptor in pidfds:
        readable, _writable, exceptional = select.select([descriptor], [], [descriptor], 0.0)
        if readable or exceptional:
            return False
    return True


def _is_descendant(
    process_id: int,
    ancestor_id: int,
    parents: Mapping[int, int],
) -> bool:
    seen: set[int] = set()
    current = process_id
    while current in parents and current not in seen:
        seen.add(current)
        current = parents[current]
        if current == ancestor_id:
            return True
    return False


def _validate_local_auth_topology(
    workload: WorkloadCgroup,
    process: object,
    snapshot: WorkloadSnapshot,
    argv: list[str],
    expected: LocalAuthRoles | None,
    *,
    provider_executable: Path = _CANONICAL_LOCAL_AUTH_EXECUTABLE,
) -> LocalAuthRoles:
    del workload
    pid = getattr(process, "pid", None)
    if (
        type(snapshot) is not WorkloadSnapshot
        or type(pid) is not int
        or pid not in snapshot.process_ids
        or len(snapshot.process_ids) < 3
        or len(snapshot.thread_ids) < len(snapshot.process_ids)
    ):
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CGROUP_TOPOLOGY")
    if expected is not None:
        if not _pidfds_are_live(expected.pidfds):
            raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CGROUP_TOPOLOGY")
        records = tuple(_read_live_process_record(item) for item in snapshot.process_ids)
        if records != expected.records or not _pidfds_are_live(expected.pidfds):
            raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CGROUP_TOPOLOGY")
        return expected

    pidfds: list[int] = []
    try:
        pidfds = [os.pidfd_open(process_id, 0) for process_id in snapshot.process_ids]
        bound_pidfds = tuple(pidfds)
        if not _pidfds_are_live(bound_pidfds):
            raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CGROUP_TOPOLOGY")
        records = tuple(_read_live_process_record(item) for item in snapshot.process_ids)
        if not _pidfds_are_live(bound_pidfds):
            raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CGROUP_TOPOLOGY")
    except BaseException:
        for descriptor in pidfds:
            os.close(descriptor)
        raise

    by_pid = {record.process_id: record for record in records}
    parents: dict[int, int] = {}
    for record in records:
        for child_id in record.child_ids:
            if child_id not in by_pid or child_id in parents:
                for descriptor in pidfds:
                    os.close(descriptor)
                raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CGROUP_TOPOLOGY")
            parents[child_id] = record.process_id
    del argv
    try:
        bwrap_info = os.stat(kimi_runtime.BWRAP, follow_symlinks=True)
        provider_info = os.stat(
            provider_executable,
            follow_symlinks=True,
        )
    except OSError as exc:
        for descriptor in pidfds:
            os.close(descriptor)
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CGROUP_TOPOLOGY") from exc
    bwrap_identity = (bwrap_info.st_dev, bwrap_info.st_ino)
    provider_identity = (provider_info.st_dev, provider_info.st_ino)
    outer = by_pid[pid]
    inner_candidates = [
        record
        for record in records
        if record.process_id != pid
        and record.executable_identity == bwrap_identity
        and _is_descendant(record.process_id, pid, parents)
    ]
    provider_candidates = [
        record
        for record in records
        if record.executable_identity == provider_identity
    ]
    if (
        outer.executable_identity != bwrap_identity
        or len(inner_candidates) != 1
        or len(provider_candidates) != 1
    ):
        for descriptor in pidfds:
            os.close(descriptor)
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CGROUP_TOPOLOGY")
    inner = inner_candidates[0]
    provider = provider_candidates[0]
    if not _is_descendant(provider.process_id, inner.process_id, parents):
        for descriptor in pidfds:
            os.close(descriptor)
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CGROUP_TOPOLOGY")
    role_ids = {outer.process_id, inner.process_id, provider.process_id}
    if any(
        record.process_id not in role_ids
        and not _is_descendant(record.process_id, provider.process_id, parents)
        for record in records
    ):
        for descriptor in pidfds:
            os.close(descriptor)
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_CGROUP_TOPOLOGY")
    return LocalAuthRoles(
        records=records,
        pidfds=bound_pidfds,
        outer_pid=outer.process_id,
        inner_pid=inner.process_id,
        provider_pid=provider.process_id,
    )


def run_local_auth(
    spec: KimiLocalAuthSpec,
    credential: CredentialLeafHandle,
    *,
    workload_factory: Callable[[], object] = WorkloadCgroup.create,
    census_sampler: Callable[[object, object, list[str], WorkloadSnapshot, LocalAuthRoles], LocalAuthCensus] | None = None,
    topology_validator: Callable[[object, object, WorkloadSnapshot, list[str], LocalAuthRoles | None], LocalAuthRoles] = _validate_local_auth_topology,
    monotonic: Callable[[], float] = time.monotonic,
    timeout_seconds: float = LOCAL_AUTH_TIMEOUT_SECONDS,
) -> LocalAuthRunOutcome:
    """Run the one terminal ACP exchange through the cgroup-freezer transaction."""

    if (
        not isinstance(spec, KimiLocalAuthSpec)
        or not isinstance(credential, CredentialLeafHandle)
        or not callable(workload_factory)
        or (census_sampler is not None and not callable(census_sampler))
        or not callable(topology_validator)
        or not callable(monotonic)
        or type(timeout_seconds) not in (int, float)
        or not 0.01 <= float(timeout_seconds) <= LOCAL_AUTH_TIMEOUT_SECONDS
    ):
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_RUN_ARGUMENT")
    cleanup_deadline = monotonic() + float(timeout_seconds)
    cleanup_reserve = min(
        LOCAL_AUTH_CLEANUP_GRACE_SECONDS,
        float(timeout_seconds) / 4.0,
    )
    deadline = cleanup_deadline - cleanup_reserve
    session = KimiLocalAuthSession()
    workload: object | None = None
    process: object | None = None
    capture: _LocalAuthCapture | None = None
    def consume_capture() -> tuple[bytes, ...]:
        if capture is None:
            raise FreezerError("LOCAL_AUTH_CAPTURE_FAILED")
        return capture.drain_available(deadline, monotonic)

    authority = CaptureAuthority(consume_capture)
    census: LocalAuthCensus | None = None
    accepted_protocol: LocalAuthProtocolOutcome | None = None
    roles: LocalAuthRoles | None = None
    first_reason: str | None = None
    cleanup_complete = False
    workload_factory_entered = False

    try:
        argv = build_local_auth_bwrap_argv(spec, credential)
    except KimiLocalAuthRuntimeError as exc:
        authority.revoke(exc.code)
        credential.close()
        session.close()
        return LocalAuthRunOutcome(
            protocol=_blocked_protocol(),
            census=_empty_census(cleanup_complete=True),
            reason_code=exc.code,
        )

    def require_time() -> None:
        if monotonic() >= deadline:
            raise _LocalAuthRunFailure("LOCAL_AUTH_TIMEOUT")

    try:
        require_time()
        workload_factory_entered = True
        workload = workload_factory()
        require_time()
        launch_recheck = build_local_auth_bwrap_argv(spec, credential)
        if launch_recheck != argv:
            raise _LocalAuthRunFailure("LOCAL_AUTH_ARTIFACT_SUBSTITUTION")
        require_time()
        process = getattr(workload, "spawn")(
            launch_recheck,
            pass_fds=(credential.descriptor,),
        )
        credential.close()
        stdin = getattr(process, "stdin", None)
        stdout = getattr(process, "stdout", None)
        stderr = getattr(process, "stderr", None)
        if stdin is None or stdout is None or stderr is None:
            raise _LocalAuthRunFailure("LOCAL_AUTH_PIPE_SETUP")
        capture = _LocalAuthCapture(stdout, stderr)
        if getattr(process, "poll")() is not None:
            raise _LocalAuthRunFailure(_process_exit_code(process))
        require_time()
        getattr(stdin, "write")(session.initialize_request())
        require_time()
        getattr(stdin, "flush")()
        session.accept(capture.next_frame(process, deadline, monotonic))
        capture.require_stdout_quiet()
        require_time()
        getattr(stdin, "write")(session.authenticate_request())
        require_time()
        getattr(stdin, "flush")()
        session.accept(capture.next_frame(process, deadline, monotonic))
        if session.protocol_state is not ACPProtocolState.TERMINAL_RESPONSE_ACCEPTED:
            raise _LocalAuthRunFailure("LOCAL_AUTH_PROTOCOL_STATE")
        seal_input = getattr(stdin, "seal", None)
        if not callable(seal_input):
            raise _LocalAuthRunFailure("LOCAL_AUTH_PROTOCOL_STATE")
        seal_input()
        accepted_protocol = session.finish()
        require_time()
        baseline = getattr(workload, "checkpoint")()
        roles = topology_validator(workload, process, baseline, argv, None)
        if getattr(process, "poll")() is not None:
            raise _LocalAuthRunFailure(_process_exit_code(process))
        require_time()
        getattr(workload, "request_freeze")()
        getattr(workload, "await_events")(
            populated=True,
            frozen=True,
            deadline=deadline,
            monotonic=monotonic,
        )
        frozen = getattr(workload, "checkpoint")(expected=baseline)
        topology_validator(workload, process, frozen, argv, roles)
        if getattr(process, "poll")() is not None:
            raise _LocalAuthRunFailure(_process_exit_code(process))
        require_time()
        authority.grant()
        require_time()
        captured_frames = authority.consume()
        capture.seal()
        for frame in captured_frames:
            session.accept(frame)
        require_time()
        census = (
            _sample_local_auth_census(
                workload,
                process,
                argv,
                frozen,
                roles,
                deadline=deadline,
                monotonic=monotonic,
            )
            if census_sampler is None
            else census_sampler(workload, process, argv, frozen, roles)
        )
        _validate_freezer_census(census, frozen)
        require_time()
        getattr(workload, "request_thaw")()
        getattr(workload, "await_events")(
            populated=True,
            frozen=False,
            deadline=deadline,
            monotonic=monotonic,
        )
        thawed = getattr(workload, "checkpoint")(expected=baseline)
        topology_validator(workload, process, thawed, argv, roles)
        if getattr(process, "poll")() is not None:
            raise _LocalAuthRunFailure(_process_exit_code(process))
        _close_stream(stdin)
        session.close()
        _validate_post_eof_drain(
            process,
            stdout,
            stderr,
            deadline=deadline,
            monotonic=monotonic,
        )
    except (KimiLocalAuthError, KimiLocalAuthRuntimeError, FreezerError, _LocalAuthRunFailure) as exc:
        first_reason = exc.code
    except (BrokenPipeError, OSError, ValueError, TypeError, AttributeError):
        first_reason = "LOCAL_AUTH_PROCESS_IO"
    finally:
        if authority.state in {
            CaptureState.NOT_YET_GRANTED,
            CaptureState.GRANTED,
        }:
            try:
                if capture is not None:
                    capture.revoke(first_reason or "LOCAL_AUTH_CAPTURE_REVOKED")
                authority.revoke(first_reason or "LOCAL_AUTH_CAPTURE_REVOKED")
            except FreezerError:
                pass
        if process is None:
            credential.close()
        else:
            _close_stream(getattr(process, "stdin", None))
        if session.protocol_state is not ACPProtocolState.CLOSED:
            session.close()
        if workload is not None:
            try:
                getattr(workload, "close")(
                    process=process,
                    deadline=cleanup_deadline,
                )
            except BaseException:
                if first_reason is None:
                    first_reason = "LOCAL_AUTH_CLEANUP_FAILED"
                cleanup_complete = False
            else:
                cleanup_complete = True
        elif process is None and not workload_factory_entered:
            cleanup_complete = True
        if process is not None:
            _close_stream(getattr(process, "stdout", None))
            _close_stream(getattr(process, "stderr", None))
        if roles is not None:
            roles.close()

    if census is None:
        census = _empty_census(cleanup_complete=cleanup_complete)
    else:
        census = replace(census, cleanup_complete=cleanup_complete)
    if not cleanup_complete and first_reason is None:
        first_reason = "LOCAL_AUTH_CLEANUP_FAILED"
    if first_reason is None and accepted_protocol is not None:
        protocol = accepted_protocol
        reason_code = protocol.reason_code
    else:
        protocol = _blocked_protocol()
        reason_code = first_reason or "LOCAL_AUTH_PROCESS_CRASH"
    return LocalAuthRunOutcome(protocol=protocol, census=census, reason_code=reason_code)


def _persisted_census(census: LocalAuthCensus) -> dict[str, int | bool]:
    return {
        "process_count": census.process_count,
        "descendant_count": census.descendant_count,
        "environment_name_count": len(census.environment_names),
        "fd_class_count": len(census.fd_classes),
        "external_endpoint_count": census.external_endpoint_count,
        "session_artifact_count": census.session_artifact_count,
        "cleanup_complete": census.cleanup_complete,
    }


class _FailClosedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise KimiLocalAuthRuntimeError("CLI_ARGUMENT")


def cli_main(
    argv: list[str] | None = None,
    *,
    output: Callable[[str], object] = print,
) -> int:
    """Fail-closed fixed entry point; output contains typed fields only."""

    parser = _FailClosedArgumentParser(add_help=False)
    parser.add_argument("--expected-commit", required=True)
    credential: CredentialLeafHandle | None = None
    try:
        arguments = parser.parse_args(argv)
        if _COMMIT_ID.fullmatch(arguments.expected_commit) is None:
            raise KimiLocalAuthRuntimeError("CLI_ARGUMENT")
        _validate_local_auth_script()
        validate_local_auth_service(_read_self_cgroup())
        validate_repository_identity(REPO_ROOT, arguments.expected_commit)
        spec = default_local_auth_spec()
        expected_uid = os.getuid()
        validate_local_auth_spec(spec, expected_uid=expected_uid)
        validate_pre_real_gate(REPO_ROOT, arguments.expected_commit)
        credential = open_validated_credential_leaf(
            spec.state_root,
            trusted_state_root=spec.state_root,
            expected_uid=expected_uid,
        )
        claim_real_attempt(
            spec.evidence_root,
            candidate_commit=arguments.expected_commit,
            expected_uid=expected_uid,
        )
        outcome = run_local_auth(spec, credential)
        if type(outcome) is not LocalAuthRunOutcome:
            raise KimiLocalAuthRuntimeError("LOCAL_AUTH_RUN_OUTCOME")
        try:
            validate_local_auth_service(_read_self_cgroup())
        except KimiLocalAuthRuntimeError as exc:
            outcome = LocalAuthRunOutcome(
                protocol=_blocked_protocol(),
                census=replace(outcome.census, cleanup_complete=False),
                reason_code=exc.code,
            )
        persist_typed_result(
            spec.evidence_root,
            outcome.protocol,
            _persisted_census(outcome.census),
            reason_code=outcome.reason_code,
            candidate_commit=arguments.expected_commit,
            expected_uid=expected_uid,
        )
        output(
            "F1_KIMI_LEVEL1_LOCAL_AUTH_QUALIFICATION="
            f"{outcome.protocol.qualification.value}"
        )
        output(
            "F1_KIMI_LOCAL_CREDENTIAL_STATE="
            f"{outcome.protocol.credential_state.value}"
        )
        output(f"F1_KIMI_AUTH_STATE={outcome.protocol.auth_state}")
        output(
            "F1_KIMI_LEVEL2_NON_INFERENCE_STATUS="
            f"{outcome.protocol.level2_status}"
        )
        output(f"F1_KIMI_LEVEL1_LOCAL_AUTH_REASON={outcome.reason_code}")
        return (
            0
            if outcome.protocol.qualification is QualificationState.COMPLETE
            and outcome.protocol.credential_state is LocalCredentialState.LOADABLE
            else 2
        )
    except (KimiLocalAuthRuntimeError, KimiLoginError) as exc:
        output(f"F1_KIMI_LEVEL1_LOCAL_AUTH_ERROR={exc.code}")
        return 2
    except (OSError, UnicodeError):
        output("F1_KIMI_LEVEL1_LOCAL_AUTH_ERROR=LOCAL_VALIDATION_FAILED")
        return 2
    except Exception:
        output("F1_KIMI_LEVEL1_LOCAL_AUTH_ERROR=LOCAL_AUTH_UNEXPECTED")
        return 2
    finally:
        if credential is not None:
            credential.close()
