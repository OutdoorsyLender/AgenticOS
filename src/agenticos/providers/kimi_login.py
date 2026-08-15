"""Owner-only, login-only containment for the pinned Kimi 0.36.1 client.

The provider TLS leg stays opaque.  This module admits only the plaintext
HTTP CONNECT authority and the plaintext TLS ClientHello metadata needed to
prove an exact ``auth.kimi.com:443`` connection.  It never terminates provider
TLS and never parses OAuth HTTP traffic.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import argparse
import array
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import subprocess
import threading
import time
from typing import Callable, Final

from agenticos.sandbox.network_clienthello import ClientHelloGate, GateDecision
from agenticos.sandbox.network_https import NormalizationError, normalize_https_authority

from .kimi_policy import (
    KimiPolicyError,
    build_kimi_environment,
    sha256_file,
    validate_future_credential_directory,
    validate_qualification_bundle,
    verify_pinned_runtime,
    verify_reported_version,
)
from .kimi_runtime import (
    BWRAP,
    BWRAP_SHA256,
    SANDBOX_EXECUTABLE,
    KimiRuntimeError,
    build_runtime_spec,
    run_passive_kimi,
)
from .kimi_login_namespace import HANDOFF_MARKER


AUTH_HOST: Final = "auth.kimi.com"
AUTH_PORT: Final = 443
AUTH_PROXY: Final = "http://127.0.0.1:18080"
SANDBOX_LOGIN_LAUNCHER: Final = "/opt/agenticos/kimi/login_namespace.py"
SANDBOX_CREDENTIAL_ROOT: Final = "/home/aos/kimi/credentials"
MAX_CONNECT_HEAD_BYTES: Final = 16_384
MAX_CONNECT_HEADERS: Final = 32
MAX_TLS_RECORD_BYTES: Final = 16_384
MAX_RELAY_BYTES: Final = 16 * 1024 * 1024
RELAY_TIMEOUT_SECONDS: Final = 900.0
STAGE_TIMEOUT_SECONDS: Final = 5.0
CONNECT_OK: Final = b"HTTP/1.1 200 Connection Established\r\n\r\n"
CONNECT_DENIED: Final = (
    b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
)
_HELLO_RETRY_REQUEST_RANDOM: Final = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)
_COMMIT_RE: Final = re.compile(r"[0-9a-f]{40}\Z")
REPO_ROOT: Final = Path("/home/brand/src/AgenticOS")
OWNER_SCRIPT: Final = REPO_ROOT / "scripts" / "run_kimi_owner_login.py"
STATE_ANCHOR: Final = Path("/home/brand/.local/share/agenticos")


class KimiLoginError(RuntimeError):
    """A stable fail-closed owner-login rejection."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class CredentialRootState(str, Enum):
    EMPTY = "EMPTY"
    PRESENT = "PRESENT"


class AuthRelayResult(str, Enum):
    COMPLETED = "COMPLETED"
    DENIED = "DENIED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class AuthRelayObservation:
    result: AuthRelayResult
    hostname: str | None
    destination_class: str
    client_to_origin_bytes: int
    origin_to_client_bytes: int
    reason_code: str


@dataclass(frozen=True, slots=True)
class KimiLoginSpec:
    executable: Path
    bundle: Path
    state_root: Path
    namespace_launcher: Path

    @property
    def credential_root(self) -> Path:
        return self.state_root / "credentials"


def _validate_no_symlink_ancestry(path: Path) -> None:
    if not path.is_absolute():
        raise KimiLoginError("CREDENTIAL_ROOT_PATH")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            info = current.lstat()
        except OSError as exc:
            raise KimiLoginError("CREDENTIAL_ROOT_PATH", str(current)) from exc
        if stat.S_ISLNK(info.st_mode):
            raise KimiLoginError("CREDENTIAL_ROOT_SYMLINK_ANCESTRY", str(current))


def provision_empty_credential_root(
    state_root: Path, *, expected_uid: int
) -> CredentialRootState:
    """Create the approved state root once; never create a fake credential."""

    if not isinstance(state_root, Path) or not state_root.is_absolute():
        raise KimiLoginError("CREDENTIAL_ROOT_PATH")
    if type(expected_uid) is not int or expected_uid < 0:
        raise KimiLoginError("CREDENTIAL_ROOT_ARGUMENT")
    if state_root.exists() or state_root.is_symlink():
        raise KimiLoginError("CREDENTIAL_ROOT_ALREADY_EXISTS")
    previous_umask = os.umask(0o077)
    try:
        os.mkdir(state_root, mode=0o700)
        try:
            os.mkdir(state_root / "credentials", mode=0o700)
        except BaseException:
            os.rmdir(state_root)
            raise
    finally:
        os.umask(previous_umask)
    return validate_credential_root(state_root, expected_uid=expected_uid)


def _validate_private_directory(path: Path, *, expected_uid: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise KimiLoginError("CREDENTIAL_PARENT_PATH", str(path)) from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) != 0o700
        or path.resolve(strict=True) != path
    ):
        raise KimiLoginError("CREDENTIAL_PARENT_IDENTITY", str(path))


def provision_default_credential_root(
    *,
    anchor: Path = STATE_ANCHOR,
    expected_uid: int,
) -> Path:
    """Create the fixed private provider-state chain and empty credential leaf."""

    if not isinstance(anchor, Path) or not anchor.is_absolute():
        raise KimiLoginError("CREDENTIAL_PARENT_PATH")
    _validate_no_symlink_ancestry(anchor)
    anchor_info = anchor.lstat()
    if (
        not stat.S_ISDIR(anchor_info.st_mode)
        or anchor_info.st_uid != expected_uid
        or stat.S_IMODE(anchor_info.st_mode) & 0o022
    ):
        raise KimiLoginError("CREDENTIAL_PARENT_IDENTITY", str(anchor))
    provider_state = anchor / "provider-state"
    kimi_state = provider_state / "kimi-code"
    state_root = kimi_state / "0.36.1"
    if state_root.exists() or state_root.is_symlink():
        raise KimiLoginError("CREDENTIAL_ROOT_ALREADY_EXISTS")
    created: list[Path] = []
    previous_umask = os.umask(0o077)
    try:
        for parent in (provider_state, kimi_state):
            if parent.exists() or parent.is_symlink():
                _validate_private_directory(parent, expected_uid=expected_uid)
            else:
                os.mkdir(parent, mode=0o700)
                created.append(parent)
                _validate_private_directory(parent, expected_uid=expected_uid)
        provision_empty_credential_root(state_root, expected_uid=expected_uid)
    except BaseException:
        for path in reversed(created):
            try:
                os.rmdir(path)
            except OSError:
                pass
        raise
    finally:
        os.umask(previous_umask)
    return state_root


def validate_credential_parent_chain(
    state_root: Path,
    *,
    anchor: Path = STATE_ANCHOR,
    expected_uid: int,
) -> None:
    """Revalidate the fixed owner-controlled parents of the credential root."""

    expected_state_root = anchor / "provider-state" / "kimi-code" / "0.36.1"
    if state_root != expected_state_root:
        raise KimiLoginError("CREDENTIAL_PARENT_PATH", str(state_root))
    _validate_no_symlink_ancestry(state_root)
    try:
        anchor_info = anchor.lstat()
    except OSError as exc:
        raise KimiLoginError("CREDENTIAL_PARENT_PATH", str(anchor)) from exc
    if (
        not stat.S_ISDIR(anchor_info.st_mode)
        or anchor_info.st_uid != expected_uid
        or stat.S_IMODE(anchor_info.st_mode) & 0o022
    ):
        raise KimiLoginError("CREDENTIAL_PARENT_IDENTITY", str(anchor))
    for parent in (anchor / "provider-state", anchor / "provider-state" / "kimi-code"):
        _validate_private_directory(parent, expected_uid=expected_uid)


def validate_credential_root(
    state_root: Path, *, expected_uid: int
) -> CredentialRootState:
    """Validate content-free ancestry, identity, modes, names, and link counts."""

    if not isinstance(state_root, Path) or not state_root.is_absolute():
        raise KimiLoginError("CREDENTIAL_ROOT_PATH")
    _validate_no_symlink_ancestry(state_root)
    try:
        state_info = state_root.lstat()
    except OSError as exc:
        raise KimiLoginError("CREDENTIAL_ROOT_PATH") from exc
    if not stat.S_ISDIR(state_info.st_mode):
        raise KimiLoginError("CREDENTIAL_ROOT_TYPE")
    if stat.S_IMODE(state_info.st_mode) != 0o700:
        raise KimiLoginError("CREDENTIAL_ROOT_MODE")
    if state_info.st_uid != expected_uid:
        raise KimiLoginError("CREDENTIAL_ROOT_OWNER")
    try:
        state_entries = sorted(path.name for path in state_root.iterdir())
    except OSError as exc:
        raise KimiLoginError("CREDENTIAL_ROOT_UNREADABLE") from exc
    if state_entries != ["credentials"]:
        raise KimiLoginError("CREDENTIAL_ROOT_ENTRIES")
    credential_root = state_root / "credentials"
    try:
        validate_future_credential_directory(
            credential_root,
            trusted_state_root=state_root,
            allow_transient=False,
            expected_uid=expected_uid,
        )
    except KimiPolicyError as exc:
        raise KimiLoginError(exc.code) from exc
    return (
        CredentialRootState.PRESENT
        if (credential_root / "kimi-code.json").exists()
        else CredentialRootState.EMPTY
    )


def open_validated_credential_root(state_root: Path, *, expected_uid: int) -> int:
    """Open the validated directory once so Bubblewrap binds its kernel identity."""

    validate_credential_root(state_root, expected_uid=expected_uid)
    credential_root = state_root / "credentials"
    flags = (
        getattr(os, "O_PATH", os.O_RDONLY)
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
    )
    try:
        descriptor = os.open(credential_root, flags)
        opened = os.fstat(descriptor)
        lexical = credential_root.lstat()
    except OSError as exc:
        raise KimiLoginError("CREDENTIAL_DIRECTORY_OPEN") from exc
    if (
        opened.st_dev != lexical.st_dev
        or opened.st_ino != lexical.st_ino
        or opened.st_uid != expected_uid
        or not stat.S_ISDIR(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != 0o700
    ):
        os.close(descriptor)
        raise KimiLoginError("CREDENTIAL_DIRECTORY_IDENTITY")
    return descriptor


def validate_interactive_terminal(
    isatty: Callable[[int], bool] = os.isatty,
) -> None:
    """Require direct owner-visible stdin, stdout, and stderr terminals."""

    if not callable(isatty) or any(not isatty(fd) for fd in (0, 1, 2)):
        raise KimiLoginError("INTERACTIVE_TERMINAL_REQUIRED")


def validate_scope_membership(cgroup_text: str) -> None:
    """Require the exact owner-login scope before any persistent mount."""

    expected = "/aos-kimi-owner-login.scope"
    if type(cgroup_text) is not str:
        raise KimiLoginError("LOGIN_SCOPE_REQUIRED")
    lines = [line for line in cgroup_text.splitlines() if line]
    if len(lines) != 1 or not lines[0].startswith("0::") or not lines[0][3:].endswith(expected):
        raise KimiLoginError("LOGIN_SCOPE_REQUIRED")


def _run_repository_git(repo_root: Path, *arguments: str) -> str:
    environment = {
        "HOME": "/nonexistent",
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }
    try:
        completed = subprocess.run(
            ["/usr/bin/git", "-C", str(repo_root), *arguments],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            env=environment,
            timeout=10,
        )
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        raise KimiLoginError("LOGIN_REPOSITORY_IDENTITY") from exc
    return completed.stdout.strip()


def validate_repository_identity(repo_root: Path, expected_commit: str) -> None:
    """Bind the owner command to one clean published ``main`` checkout."""

    if (
        not isinstance(repo_root, Path)
        or not repo_root.is_absolute()
        or repo_root.is_symlink()
        or not repo_root.is_dir()
        or type(expected_commit) is not str
        or _COMMIT_RE.fullmatch(expected_commit) is None
    ):
        raise KimiLoginError("LOGIN_REPOSITORY_IDENTITY")
    head = _run_repository_git(repo_root, "rev-parse", "HEAD")
    origin = _run_repository_git(repo_root, "rev-parse", "origin/main")
    branch = _run_repository_git(repo_root, "branch", "--show-current")
    if head != expected_commit or origin != expected_commit or branch != "main":
        raise KimiLoginError("LOGIN_REPOSITORY_IDENTITY")
    if _run_repository_git(repo_root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise KimiLoginError("LOGIN_REPOSITORY_DIRTY")


def owner_systemd_command(expected_commit: str) -> list[str]:
    """Return the one owner command vector; no shell or capture layer exists."""

    if type(expected_commit) is not str or _COMMIT_RE.fullmatch(expected_commit) is None:
        raise KimiLoginError("LOGIN_REPOSITORY_IDENTITY")
    return [
        "/usr/bin/systemd-run",
        "--user",
        "--scope",
        "--collect",
        "--quiet",
        "--unit=aos-kimi-owner-login",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=5s",
        "--property=TasksMax=16",
        "--property=MemoryMax=1G",
        "/usr/bin/python3",
        str(OWNER_SCRIPT),
        "--expected-commit",
        expected_commit,
    ]


def terminate_and_drain_process(
    process: subprocess.Popen[bytes], *, grace_seconds: float = 2.0
) -> None:
    """Terminate the isolated process group and prove the group disappeared."""

    if not isinstance(process, subprocess.Popen) or not 0.1 <= grace_seconds <= 10:
        raise KimiLoginError("PROCESS_DRAIN_ARGUMENT")

    def group_exists() -> bool:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError as exc:
            raise KimiLoginError("PROCESS_DRAIN_UNCERTAIN") from exc
        return True

    def wait_for_group(deadline: float) -> bool:
        while group_exists():
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.02)
        return True

    if group_exists():
        os.killpg(process.pid, signal.SIGTERM)
    if process.poll() is None:
        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            pass
    if wait_for_group(time.monotonic() + grace_seconds):
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    if process.poll() is None:
        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired as exc:
            raise KimiLoginError("PROCESS_DRAIN_FAILED") from exc
    if not wait_for_group(time.monotonic() + grace_seconds):
        raise KimiLoginError("PROCESS_DRAIN_FAILED")


def validate_login_spec(spec: KimiLoginSpec, *, expected_uid: int) -> None:
    """Recheck every immutable or metadata-only login prerequisite."""

    if not isinstance(spec, KimiLoginSpec):
        raise KimiLoginError("LOGIN_RUNTIME_ARGUMENT")
    for path in (spec.executable, spec.bundle, spec.state_root, spec.namespace_launcher):
        if not path.is_absolute():
            raise KimiLoginError("LOGIN_RUNTIME_PATH")
    try:
        artifact = validate_qualification_bundle(spec.bundle)
        verify_pinned_runtime(spec.executable, artifact, expected_uid=expected_uid)
        if BWRAP.is_symlink() or not BWRAP.is_file() or sha256_file(BWRAP) != BWRAP_SHA256:
            raise KimiLoginError("BWRAP_IDENTITY_DRIFT")
        runtime = build_runtime_spec(spec.executable, spec.bundle)
        observed = run_passive_kimi(runtime, ("--version",), timeout_seconds=15)
        if observed.returncode != 0 or observed.stderr:
            raise KimiLoginError("RUNTIME_VERSION_PROBE_FAILED")
        verify_reported_version(observed.stdout.decode("utf-8"))
    except (KimiPolicyError, KimiRuntimeError, UnicodeError) as exc:
        code = (
            exc.code
            if isinstance(exc, (KimiPolicyError, KimiRuntimeError))
            else "WRONG_REPORTED_VERSION"
        )
        raise KimiLoginError("PIN_RECHECK_FAILED", code) from exc
    if spec.state_root == STATE_ANCHOR / "provider-state" / "kimi-code" / "0.36.1":
        validate_credential_parent_chain(
            spec.state_root,
            anchor=STATE_ANCHOR,
            expected_uid=expected_uid,
        )
    validate_credential_root(spec.state_root, expected_uid=expected_uid)
    try:
        launcher_info = spec.namespace_launcher.lstat()
    except OSError as exc:
        raise KimiLoginError("LOGIN_LAUNCHER_IDENTITY") from exc
    if (
        spec.namespace_launcher.is_symlink()
        or not stat.S_ISREG(launcher_info.st_mode)
        or launcher_info.st_uid != expected_uid
        or stat.S_IMODE(launcher_info.st_mode) & 0o022
    ):
        raise KimiLoginError("LOGIN_LAUNCHER_IDENTITY")


def receive_listener_fd(channel: socket.socket) -> socket.socket:
    """Receive and validate exactly one loopback listener object."""

    if not isinstance(channel, socket.socket):
        raise KimiLoginError("LISTENER_HANDOFF_INVALID")
    payload, ancillary, flags, _ = channel.recvmsg(
        len(HANDOFF_MARKER), socket.CMSG_SPACE(array.array("i").itemsize)
    )
    received: list[int] = []
    for level, kind, data in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            for fd in received:
                os.close(fd)
            raise KimiLoginError("LISTENER_HANDOFF_INVALID")
        rights = array.array("i")
        rights.frombytes(data[: len(data) - (len(data) % rights.itemsize)])
        received.extend(rights.tolist())
    if (
        payload != HANDOFF_MARKER
        or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
        or len(received) != 1
    ):
        for fd in received:
            os.close(fd)
        raise KimiLoginError("LISTENER_HANDOFF_INVALID")
    listener = socket.socket(fileno=received[0])
    try:
        if (
            listener.family != socket.AF_INET
            or listener.type & 0xF != socket.SOCK_STREAM
            or listener.getsockname() != ("127.0.0.1", 18080)
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
        ):
            raise KimiLoginError("LISTENER_HANDOFF_INVALID")
    except BaseException:
        listener.close()
        raise
    return listener


_TCHAR = frozenset(
    b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)


def authorize_connect_head(head: bytes) -> str:
    """Admit one exact CONNECT authority without retaining header contents."""

    if type(head) is not bytes or not head.endswith(b"\r\n\r\n"):
        raise KimiLoginError("CONNECT_HEAD_MALFORMED")
    if len(head) > MAX_CONNECT_HEAD_BYTES:
        raise KimiLoginError("CONNECT_HEAD_OVERSIZED")
    lines = head[:-4].split(b"\r\n")
    if not lines or len(lines) - 1 > MAX_CONNECT_HEADERS:
        raise KimiLoginError("CONNECT_HEAD_MALFORMED")
    parts = lines[0].split(b" ")
    if len(parts) != 3 or parts[0] != b"CONNECT" or parts[2] != b"HTTP/1.1":
        raise KimiLoginError("CONNECT_HEAD_MALFORMED")
    try:
        hostname = normalize_https_authority(parts[1])
    except NormalizationError as exc:
        raise KimiLoginError("CONNECT_AUTHORITY_INVALID", exc.code.value) from exc
    if hostname != AUTH_HOST:
        raise KimiLoginError("CONNECT_HOST_DENIED", hostname)
    for line in lines[1:]:
        if not line or line[:1] in (b" ", b"\t") or b":" not in line:
            raise KimiLoginError("CONNECT_HEADER_MALFORMED")
        name, value = line.split(b":", 1)
        if not name or any(byte not in _TCHAR for byte in name):
            raise KimiLoginError("CONNECT_HEADER_MALFORMED")
        value = value[1:] if value.startswith(b" ") else value
        if any(byte < 0x20 or byte > 0x7E for byte in value):
            raise KimiLoginError("CONNECT_HEADER_MALFORMED")
        if name.lower() in {b"authorization", b"cookie", b"proxy-authorization"}:
            raise KimiLoginError("CONNECT_SECRET_HEADER_FORBIDDEN")
    return hostname


def _client_hello_wire_payload_size(payload: bytes) -> int:
    pos = 0
    total = 0
    while pos < len(payload):
        if len(payload) - pos < 5:
            raise KimiLoginError("TLS_CLIENT_HELLO_REJECTED", "truncated record")
        record_length = int.from_bytes(payload[pos + 3 : pos + 5], "big")
        if not 0 < record_length <= MAX_TLS_RECORD_BYTES:
            raise KimiLoginError("TLS_CLIENT_HELLO_REJECTED", "record bound")
        end = pos + 5 + record_length
        if end > len(payload):
            raise KimiLoginError("TLS_CLIENT_HELLO_REJECTED", "truncated record")
        total += record_length
        pos = end
    return total


def validate_client_hello_bytes(payload: bytes) -> str:
    """Apply the qualified ClientHello/ECH gate and exact SNI decision."""

    if type(payload) is not bytes or not payload:
        raise KimiLoginError("TLS_CLIENT_HELLO_REJECTED")
    gate = ClientHelloGate()
    decision = gate.feed(payload)
    if decision is not GateDecision.ACCEPT or gate.metadata is None:
        raise KimiLoginError("TLS_CLIENT_HELLO_REJECTED", gate.rejection_reason)
    if gate.metadata.sni is None:
        raise KimiLoginError("TLS_CLIENT_HELLO_REJECTED", "missing SNI")
    try:
        observed = gate.metadata.sni.decode("ascii")
    except UnicodeDecodeError as exc:
        raise KimiLoginError("TLS_SNI_DENIED", "non-ASCII SNI") from exc
    if observed != AUTH_HOST:
        raise KimiLoginError("TLS_SNI_DENIED", observed)
    if _client_hello_wire_payload_size(payload) != 4 + gate.metadata.declared_length:
        raise KimiLoginError("SECOND_CLIENT_HELLO", "trailing initial handshake")
    return observed


def _tls_handshake_payload(payload: bytes, *, label: str) -> bytes:
    pos = 0
    handshake = bytearray()
    while pos < len(payload):
        if len(payload) - pos < 5:
            raise KimiLoginError(f"{label}_REJECTED", "truncated record")
        record_version = int.from_bytes(payload[pos + 1 : pos + 3], "big")
        if payload[pos] != 22 or not 0x0301 <= record_version <= 0x0303:
            raise KimiLoginError(f"{label}_REJECTED", "unexpected record")
        size = int.from_bytes(payload[pos + 3 : pos + 5], "big")
        if not 0 < size <= MAX_TLS_RECORD_BYTES:
            raise KimiLoginError(f"{label}_REJECTED", "record bound")
        end = pos + 5 + size
        if end > len(payload):
            raise KimiLoginError(f"{label}_REJECTED", "truncated record")
        handshake.extend(payload[pos + 5 : end])
        pos = end
    return bytes(handshake)


def validate_tls13_server_hello(payload: bytes) -> bytes:
    """Require a direct TLS 1.3 ServerHello; HRR/TLS 1.2 cannot proceed opaquely."""

    if type(payload) is not bytes or not payload:
        raise KimiLoginError("TLS_SERVER_HELLO_REJECTED")
    handshake = _tls_handshake_payload(payload, label="TLS_SERVER_HELLO")
    if len(handshake) < 4 or handshake[0] != 2:
        raise KimiLoginError("TLS_SERVER_HELLO_REJECTED", "not ServerHello")
    declared = int.from_bytes(handshake[1:4], "big")
    if declared != len(handshake) - 4:
        raise KimiLoginError("TLS_SERVER_HELLO_REJECTED", "length mismatch")
    body = handshake[4:]
    if len(body) < 2 + 32 + 1 + 2 + 1 + 2:
        raise KimiLoginError("TLS_SERVER_HELLO_REJECTED", "truncated body")
    pos = 0
    if body[pos : pos + 2] != b"\x03\x03":
        raise KimiLoginError("TLS_SERVER_HELLO_REJECTED", "legacy version")
    pos += 2
    random = body[pos : pos + 32]
    pos += 32
    if random == _HELLO_RETRY_REQUEST_RANDOM:
        raise KimiLoginError("SECOND_CLIENT_HELLO", "HelloRetryRequest denied")
    session_size = body[pos]
    pos += 1
    if pos + session_size + 5 > len(body):
        raise KimiLoginError("TLS_SERVER_HELLO_REJECTED", "session id")
    pos += session_size
    pos += 2  # cipher suite
    if body[pos] != 0:
        raise KimiLoginError("TLS_SERVER_HELLO_REJECTED", "compression")
    pos += 1
    extension_size = int.from_bytes(body[pos : pos + 2], "big")
    pos += 2
    if pos + extension_size != len(body):
        raise KimiLoginError("TLS_SERVER_HELLO_REJECTED", "extensions length")
    end = pos + extension_size
    selected_version: bytes | None = None
    seen: set[int] = set()
    while pos < end:
        if end - pos < 4:
            raise KimiLoginError("TLS_SERVER_HELLO_REJECTED", "extension header")
        extension_id = int.from_bytes(body[pos : pos + 2], "big")
        size = int.from_bytes(body[pos + 2 : pos + 4], "big")
        pos += 4
        if extension_id in seen or pos + size > end:
            raise KimiLoginError("TLS_SERVER_HELLO_REJECTED", "extension shape")
        seen.add(extension_id)
        value = body[pos : pos + size]
        pos += size
        if extension_id == 43:
            if size != 2:
                raise KimiLoginError("TLS_SERVER_HELLO_REJECTED", "supported version")
            selected_version = value
    if selected_version != b"\x03\x04":
        raise KimiLoginError("TLS_VERSION_DENIED", "TLS 1.3 required")
    return payload


class OpaqueClientTlsGuard:
    """Reject any plaintext handshake record after the admitted ClientHello."""

    def __init__(self) -> None:
        self._pending = bytearray()

    def accept(self, payload: bytes) -> bytes:
        if type(payload) is not bytes:
            raise KimiLoginError("TLS_RECORD_MALFORMED")
        self._pending.extend(payload)
        pos = 0
        admitted = bytearray()
        while len(self._pending) - pos >= 5:
            content_type = self._pending[pos]
            record_length = int.from_bytes(self._pending[pos + 3 : pos + 5], "big")
            if not 0 < record_length <= MAX_TLS_RECORD_BYTES:
                raise KimiLoginError("TLS_RECORD_MALFORMED")
            end = pos + 5 + record_length
            if end > len(self._pending):
                break
            record_payload = self._pending[pos + 5 : end]
            record_version = int.from_bytes(self._pending[pos + 1 : pos + 3], "big")
            if content_type == 22:
                if record_payload and record_payload[0] == 1:
                    raise KimiLoginError("SECOND_CLIENT_HELLO")
                raise KimiLoginError("POST_INITIAL_PLAINTEXT_HANDSHAKE")
            if content_type not in (20, 21, 23) or record_version != 0x0303:
                raise KimiLoginError("TLS_RECORD_MALFORMED")
            admitted.extend(self._pending[pos:end])
            pos = end
        if pos:
            del self._pending[:pos]
        return bytes(admitted)

    def finish(self) -> None:
        if self._pending:
            raise KimiLoginError("TLS_RECORD_TRUNCATED")


def _recv_exact(stream: socket.socket, size: int, *, deadline: float) -> bytes:
    data = bytearray()
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise KimiLoginError("NETWORK_STAGE_TIMEOUT")
        stream.settimeout(min(0.25, remaining))
        try:
            chunk = stream.recv(size - len(data))
        except socket.timeout:
            continue
        except OSError as exc:
            raise KimiLoginError("NETWORK_SOCKET_ERROR") from exc
        if not chunk:
            raise KimiLoginError("NETWORK_UNEXPECTED_EOF")
        data.extend(chunk)
    return bytes(data)


def _read_connect_head(stream: socket.socket) -> bytes:
    head = bytearray()
    deadline = time.monotonic() + STAGE_TIMEOUT_SECONDS
    while not head.endswith(b"\r\n\r\n"):
        if len(head) >= MAX_CONNECT_HEAD_BYTES:
            raise KimiLoginError("CONNECT_HEAD_OVERSIZED")
        head.extend(_recv_exact(stream, 1, deadline=deadline))
    return bytes(head)


def _read_tls_handshake(stream: socket.socket, *, expected_type: int) -> bytes:
    raw = bytearray()
    handshake_size: int | None = None
    payload_size = 0
    deadline = time.monotonic() + STAGE_TIMEOUT_SECONDS
    for _ in range(64):
        header = _recv_exact(stream, 5, deadline=deadline)
        if header[0] != 22:
            raise KimiLoginError("TLS_HANDSHAKE_REJECTED", "unexpected record")
        size = int.from_bytes(header[3:5], "big")
        if not 0 < size <= MAX_TLS_RECORD_BYTES:
            raise KimiLoginError("TLS_HANDSHAKE_REJECTED", "record bound")
        record = _recv_exact(stream, size, deadline=deadline)
        raw.extend(header)
        raw.extend(record)
        payload_size += size
        if handshake_size is None and payload_size >= 4:
            handshake = _tls_handshake_payload(bytes(raw), label="TLS_HANDSHAKE")
            if handshake[0] != expected_type:
                raise KimiLoginError("TLS_HANDSHAKE_REJECTED", "wrong message type")
            handshake_size = 4 + int.from_bytes(handshake[1:4], "big")
        if handshake_size is not None and payload_size >= handshake_size:
            if payload_size != handshake_size:
                raise KimiLoginError("SECOND_CLIENT_HELLO", "coalesced handshake denied")
            return bytes(raw)
    raise KimiLoginError("TLS_HANDSHAKE_REJECTED", "record count")


def _default_origin_socket() -> socket.socket:
    from agenticos.sandbox.network_origin import connect_validated_sockaddr
    from agenticos.sandbox.network_resolution import ResolutionCode, resolve_all_once

    resolved = resolve_all_once(AUTH_HOST)
    if resolved.code is not ResolutionCode.RESOLVED:
        raise KimiLoginError("AUTH_DNS_DENIED", resolved.code.value)
    connected = connect_validated_sockaddr(resolved.addresses)
    if not connected.connected or connected.sock is None:
        raise KimiLoginError("AUTH_ORIGIN_CONNECT_DENIED", connected.code.value)
    return connected.sock


def _relay_opaque(
    worker: socket.socket,
    origin: socket.socket,
) -> tuple[int, int]:
    selector = selectors.DefaultSelector()
    selector.register(worker, selectors.EVENT_READ, (worker, origin, "client"))
    selector.register(origin, selectors.EVENT_READ, (origin, worker, "origin"))
    guard = OpaqueClientTlsGuard()
    client_bytes = 0
    origin_bytes = 0
    deadline = time.monotonic() + RELAY_TIMEOUT_SECONDS
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise KimiLoginError("AUTH_RELAY_TIMEOUT")
            events = selector.select(timeout=0.25)
            for key, _ in events:
                source, destination, direction = key.data
                try:
                    chunk = source.recv(16_384)
                except OSError as exc:
                    raise KimiLoginError("AUTH_RELAY_SOCKET_ERROR") from exc
                if not chunk:
                    selector.unregister(source)
                    if direction == "client":
                        guard.finish()
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                if direction == "client":
                    admitted = guard.accept(chunk)
                    client_bytes += len(admitted)
                else:
                    admitted = chunk
                    origin_bytes += len(admitted)
                if client_bytes + origin_bytes > MAX_RELAY_BYTES:
                    raise KimiLoginError("AUTH_RELAY_BYTE_LIMIT")
                if admitted:
                    destination.sendall(admitted)
    finally:
        selector.close()
    return client_bytes, origin_bytes


def handle_opaque_auth_connection(
    worker: socket.socket,
    *,
    origin_socket_factory: Callable[[], socket.socket] = _default_origin_socket,
) -> AuthRelayObservation:
    """Gate and relay one TLS connection without inspecting encrypted OAuth bytes."""

    hostname: str | None = None
    origin: socket.socket | None = None
    client_bytes = 0
    origin_bytes = 0
    try:
        try:
            hostname = authorize_connect_head(_read_connect_head(worker))
        except KimiLoginError as exc:
            if exc.code == "CONNECT_HOST_DENIED" and exc.detail:
                hostname = exc.detail
            try:
                worker.sendall(CONNECT_DENIED)
            except OSError:
                pass
            return AuthRelayObservation(
                AuthRelayResult.DENIED,
                hostname,
                "UNKNOWN",
                0,
                0,
                exc.code,
            )
        worker.sendall(CONNECT_OK)
        client_hello = _read_tls_handshake(worker, expected_type=1)
        validate_client_hello_bytes(client_hello)
        origin = origin_socket_factory()
        origin.sendall(client_hello)
        client_bytes += len(client_hello)
        server_hello = _read_tls_handshake(origin, expected_type=2)
        validate_tls13_server_hello(server_hello)
        worker.sendall(server_hello)
        origin_bytes += len(server_hello)
        extra_client, extra_origin = _relay_opaque(worker, origin)
        client_bytes += extra_client
        origin_bytes += extra_origin
        return AuthRelayObservation(
            AuthRelayResult.COMPLETED,
            hostname,
            "AUTH",
            client_bytes,
            origin_bytes,
            "COMPLETED",
        )
    except KimiLoginError as exc:
        if exc.code == "TLS_SNI_DENIED" and exc.detail:
            hostname = exc.detail
        return AuthRelayObservation(
            AuthRelayResult.FAILED,
            hostname,
            "AUTH" if hostname == AUTH_HOST else "UNKNOWN",
            client_bytes,
            origin_bytes,
            exc.code,
        )
    except OSError:
        return AuthRelayObservation(
            AuthRelayResult.FAILED,
            hostname,
            "AUTH" if hostname == AUTH_HOST else "UNKNOWN",
            client_bytes,
            origin_bytes,
            "NETWORK_SOCKET_ERROR",
        )
    finally:
        try:
            worker.close()
        except OSError:
            pass
        if origin is not None:
            try:
                origin.close()
            except OSError:
                pass


class KimiAuthRelay:
    """A bounded accept loop over a listener created inside the client netns."""

    def __init__(
        self,
        listener: socket.socket,
        *,
        origin_socket_factory: Callable[[], socket.socket] = _default_origin_socket,
        connection_limit: int = 32,
    ) -> None:
        if not isinstance(listener, socket.socket) or not 1 <= connection_limit <= 64:
            raise KimiLoginError("AUTH_RELAY_ARGUMENT")
        self._listener = listener
        self._origin_socket_factory = origin_socket_factory
        self._connection_limit = connection_limit
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._connections: set[socket.socket] = set()
        self._workers: set[threading.Thread] = set()
        self._lock = threading.Lock()
        self.observations: list[AuthRelayObservation] = []

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def active_connection_count(self) -> int:
        with self._lock:
            return len(self._connections)

    @property
    def fatal_observation(self) -> AuthRelayObservation | None:
        with self._lock:
            return next(
                (
                    observation
                    for observation in self.observations
                    if observation.result is not AuthRelayResult.COMPLETED
                ),
                None,
            )

    def start(self) -> None:
        if self._thread is not None:
            raise KimiLoginError("AUTH_RELAY_ALREADY_STARTED")
        self._listener.settimeout(0.25)
        self._thread = threading.Thread(
            target=self._serve,
            name="aos-kimi-auth-relay",
            daemon=True,
        )
        self._thread.start()

    def _serve_connection(self, connection: socket.socket) -> None:
        try:
            observation = handle_opaque_auth_connection(
                connection, origin_socket_factory=self._origin_socket_factory
            )
            with self._lock:
                self.observations.append(observation)
        finally:
            with self._lock:
                self._connections.discard(connection)
                self._workers.discard(threading.current_thread())

    def _serve(self) -> None:
        accepted = 0
        try:
            while not self._stop.is_set() and accepted < self._connection_limit:
                try:
                    connection, _ = self._listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                if self._stop.is_set():
                    connection.close()
                    return
                accepted += 1
                with self._lock:
                    if self._connections:
                        connection.close()
                        self.observations.append(
                            AuthRelayObservation(
                                AuthRelayResult.DENIED,
                                None,
                                "UNKNOWN",
                                0,
                                0,
                                "CONCURRENT_CONNECTION_DENIED",
                            )
                        )
                        continue
                    self._connections.add(connection)
                    worker = threading.Thread(
                        target=self._serve_connection,
                        args=(connection,),
                        name=f"aos-kimi-auth-connection-{accepted}",
                        daemon=True,
                    )
                    self._workers.add(worker)
                worker.start()
        finally:
            try:
                self._listener.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2)
        with self._lock:
            connections = tuple(self._connections)
            workers = tuple(self._workers)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass
        for worker in workers:
            worker.join(timeout=2)
        with self._lock:
            remaining_workers = tuple(self._workers)
            remaining_connections = tuple(self._connections)
        if (
            self.running
            or any(worker.is_alive() for worker in workers)
            or remaining_workers
            or remaining_connections
        ):
            raise KimiLoginError("AUTH_RELAY_DRAIN_FAILED")


def build_login_environment() -> dict[str, str]:
    environment = build_kimi_environment()
    environment["https_proxy"] = AUTH_PROXY
    return environment


def build_login_bwrap_argv(
    spec: KimiLoginSpec, *, handoff_fd: int, credential_fd: int
) -> list[str]:
    """Build the login-only namespace; the launcher execs exactly ``kimi login``."""

    if (
        not isinstance(spec, KimiLoginSpec)
        or type(handoff_fd) is not int
        or handoff_fd < 3
        or type(credential_fd) is not int
        or credential_fd < 3
        or credential_fd == handoff_fd
    ):
        raise KimiLoginError("LOGIN_RUNTIME_ARGUMENT")
    argv = [
        str(BWRAP),
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
        "agenticos-kimi-login",
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
        str(spec.executable),
        SANDBOX_EXECUTABLE,
        "--ro-bind",
        str(spec.namespace_launcher),
        SANDBOX_LOGIN_LAUNCHER,
        "--dir",
        "/home",
        "--dir",
        "/home/aos",
        "--tmpfs",
        "/home/aos/kimi",
        "--ro-bind",
        str(spec.bundle / "config.toml"),
        "/home/aos/kimi/config.toml",
        "--ro-bind",
        str(spec.bundle / "agents"),
        "/home/aos/kimi/agents",
        "--bind-fd",
        str(credential_fd),
        SANDBOX_CREDENTIAL_ROOT,
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/workspace",
        "--chdir",
        "/workspace",
    ]
    for name, value in build_login_environment().items():
        argv.extend(("--setenv", name, value))
    argv.extend(("--", "/usr/bin/python3", SANDBOX_LOGIN_LAUNCHER, str(handoff_fd)))
    return argv


def default_login_spec() -> KimiLoginSpec:
    return KimiLoginSpec(
        executable=Path(
            "/home/brand/.local/share/agenticos/provider-qualification/"
            "kimi-code/0.36.1/runtime/bin/kimi"
        ),
        bundle=REPO_ROOT / "qualification" / "kimi-code" / "0.36.1",
        state_root=Path(
            "/home/brand/.local/share/agenticos/provider-state/kimi-code/0.36.1"
        ),
        namespace_launcher=(
            REPO_ROOT / "src" / "agenticos" / "providers" / "kimi_login_namespace.py"
        ),
    )


def cleanup_login_runtime(relay: object, process: subprocess.Popen[bytes]) -> None:
    """Drain the credential-bearing process even when relay cleanup fails."""

    try:
        stop = getattr(relay, "stop")
        stop()
    finally:
        terminate_and_drain_process(process)


def run_owner_login(spec: KimiLoginSpec) -> tuple[AuthRelayObservation, ...]:
    """Run the official login with direct terminal I/O and no transcript capture."""

    parent_channel, child_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    process: subprocess.Popen[bytes] | None = None
    relay: KimiAuthRelay | None = None
    credential_fd = open_validated_credential_root(spec.state_root, expected_uid=os.getuid())
    try:
        argv = build_login_bwrap_argv(
            spec,
            handoff_fd=child_channel.fileno(),
            credential_fd=credential_fd,
        )
        process = subprocess.Popen(
            argv,
            stdin=None,
            stdout=None,
            stderr=None,
            env={},
            close_fds=True,
            pass_fds=(child_channel.fileno(), credential_fd),
            start_new_session=True,
        )
        child_channel.close()
        parent_channel.settimeout(10)
        try:
            listener = receive_listener_fd(parent_channel)
        except (OSError, socket.timeout) as exc:
            raise KimiLoginError("LISTENER_HANDOFF_FAILED") from exc
        relay = KimiAuthRelay(listener)
        relay.start()
        while process.poll() is None:
            fatal = relay.fatal_observation
            if fatal is not None:
                if fatal.hostname not in (None, AUTH_HOST):
                    raise KimiLoginError("UNAUTHORIZED_HOSTNAME", fatal.hostname)
                raise KimiLoginError("AUTH_RELAY_FAILED", fatal.reason_code)
            time.sleep(0.1)
        returncode = process.returncode
    except KeyboardInterrupt as exc:
        raise KimiLoginError("OWNER_LOGIN_CANCELLED") from exc
    finally:
        try:
            os.close(credential_fd)
        except OSError:
            pass
        try:
            child_channel.close()
        except OSError:
            pass
        try:
            parent_channel.close()
        except OSError:
            pass
        if relay is not None and process is not None:
            cleanup_login_runtime(relay, process)
        elif process is not None:
            terminate_and_drain_process(process)
    assert relay is not None
    observations = tuple(relay.observations)
    if returncode != 0:
        raise KimiLoginError("LOGIN_COMMAND_FAILED")
    if not observations or any(
        observation.result is not AuthRelayResult.COMPLETED
        or observation.hostname != AUTH_HOST
        or observation.destination_class != "AUTH"
        for observation in observations
    ):
        raise KimiLoginError("AUTH_RELAY_INCOMPLETE")
    validate_credential_root(spec.state_root, expected_uid=os.getuid())
    return observations


def cli_main(
    argv: list[str] | None = None,
    *,
    isatty: Callable[[int], bool] = os.isatty,
    output: Callable[[str], object] = print,
) -> int:
    """Owner-facing entry point.  Errors expose codes/hostnames, never OAuth data."""

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--expected-commit", required=True)
    try:
        arguments = parser.parse_args(argv)
        validate_interactive_terminal(isatty)
        validate_scope_membership(Path("/proc/self/cgroup").read_text(encoding="ascii"))
        validate_repository_identity(REPO_ROOT, arguments.expected_commit)
        spec = default_login_spec()
        validate_login_spec(spec, expected_uid=os.getuid())
        output("F1_KIMI_LOGIN_CEREMONY=STARTING")
        run_owner_login(spec)
        output("OWNER_LOGIN_COMMAND_FINISHED=YES")
        return 0
    except KimiLoginError as exc:
        if exc.code == "UNAUTHORIZED_HOSTNAME" and exc.detail:
            output(f"F1_KIMI_LOGIN_BLOCKED_HOSTNAME={exc.detail}")
        output(f"F1_KIMI_LOGIN_CEREMONY_ERROR={exc.code}")
        return 2
    except (OSError, UnicodeError):
        output("F1_KIMI_LOGIN_CEREMONY_ERROR=LOCAL_VALIDATION_FAILED")
        return 2


__all__ = [
    "AUTH_HOST",
    "AUTH_PORT",
    "AuthRelayResult",
    "CredentialRootState",
    "KimiLoginError",
    "KimiAuthRelay",
    "KimiLoginSpec",
    "OpaqueClientTlsGuard",
    "authorize_connect_head",
    "build_login_bwrap_argv",
    "build_login_environment",
    "cli_main",
    "cleanup_login_runtime",
    "default_login_spec",
    "handle_opaque_auth_connection",
    "open_validated_credential_root",
    "owner_systemd_command",
    "receive_listener_fd",
    "run_owner_login",
    "terminate_and_drain_process",
    "provision_empty_credential_root",
    "provision_default_credential_root",
    "validate_client_hello_bytes",
    "validate_credential_parent_chain",
    "validate_credential_root",
    "validate_interactive_terminal",
    "validate_login_spec",
    "validate_repository_identity",
    "validate_scope_membership",
    "validate_tls13_server_hello",
]
