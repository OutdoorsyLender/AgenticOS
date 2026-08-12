"""Out-of-process provider authentication daemon.

Runs in a separate OS process with least authority.
Manages refresh token and subscription access tokens in a private root.
Listens on a local socket endpoint for task-bound capability requests from the controller.
"""

from __future__ import annotations

import argparse
import array
import ctypes
import errno
import hashlib
import json
import os
import queue
import re
import secrets
import socket
import stat
import struct
import sys
import threading
import time
from collections.abc import Mapping
from typing import Any, Dict


IPC_PROTOCOL_VERSION = "AOSAUTH/1"
IPC_MAX_REQUEST_BYTES = 16_384
IPC_MAX_RESPONSE_BYTES = 16_384
IPC_REQUEST_TIMEOUT_SECONDS = 2.0
IPC_RESPONSE_TIMEOUT_SECONDS = 2.0
IPC_MAX_MESSAGES_PER_HELPER = 4_096
IPC_MAX_REPLAY_ENTRIES = 4_096
IPC_MAX_ATTEMPT_CONTEXTS = 4_096
IPC_MAX_CAPABILITIES_PER_ATTEMPT = 8
_TASK_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_HEX_32_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
_HOST_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")

_PR_GET_DUMPABLE = 3
_PR_SET_DUMPABLE = 4
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39
_UINT_MAX = (1 << 32) - 1
_LANDLOCK_HANDLED_ACCESS_FS = 0x7FFF
_LANDLOCK_ALLOWED_AUTH_ACCESS = (
    (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5) | (1 << 8) | (1 << 13) | (1 << 14)
)
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_BENEATH = 0x08


class AuthProtocolError(RuntimeError):
    """Fixed-code protocol failure that never retains rejected input."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _validate_capability_context(request: Mapping[str, Any]) -> tuple[Any, ...]:
    if not _TASK_ID_PATTERN.fullmatch(request["task_id"]):
        raise AuthProtocolError("CAPABILITY_BINDING_INVALID")
    if not _HEX_32_PATTERN.fullmatch(request["request_nonce"]):
        raise AuthProtocolError("CAPABILITY_BINDING_INVALID")
    if not _HEX_32_PATTERN.fullmatch(request["launch_nonce"]):
        raise AuthProtocolError("CAPABILITY_BINDING_INVALID")
    if not 1 <= request["generation"] <= (1 << 64) - 1:
        raise AuthProtocolError("CAPABILITY_BINDING_INVALID")
    if not 1 <= request["attempt_id"] <= (1 << 64) - 1:
        raise AuthProtocolError("CAPABILITY_BINDING_INVALID")
    if request["provider_id"] != "chatgpt_subscription":
        raise AuthProtocolError("CAPABILITY_BINDING_INVALID")
    if request["upstream_scheme"] not in ("http", "https"):
        raise AuthProtocolError("CAPABILITY_BINDING_INVALID")
    if not _HOST_PATTERN.fullmatch(request["upstream_host"]):
        raise AuthProtocolError("CAPABILITY_BINDING_INVALID")
    if not 1 <= request["upstream_port"] <= 65_535:
        raise AuthProtocolError("CAPABILITY_BINDING_INVALID")
    if request["provider_purpose"] != "responses_sse":
        raise AuthProtocolError("CAPABILITY_BINDING_INVALID")
    return tuple(
        request[name]
        for name in (
            "task_id", "generation", "attempt_id", "launch_nonce", "provider_id",
            "upstream_scheme", "upstream_host", "upstream_port", "provider_purpose",
        )
    )


class _OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
        ("reserved", ctypes.c_uint32),
    ]


def _syscall(number: int, *arguments: Any) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(number, *arguments)
    if result == -1:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return int(result)


def _openat2(directory_fd: int, path: str, *, flags: int) -> int:
    how = _OpenHow(
        flags=flags,
        mode=0,
        resolve=_RESOLVE_BENEATH | _RESOLVE_NO_SYMLINKS | _RESOLVE_NO_MAGICLINKS,
    )
    return _syscall(437, directory_fd, path.encode(), ctypes.byref(how), ctypes.sizeof(how))


def _openat2_auth_root(path: str, expected_device: int, expected_inode: int) -> int:
    root_fd = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        auth_root_fd = _openat2(
            root_fd,
            path.lstrip("/"),
            flags=os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC,
        )
    finally:
        os.close(root_fd)
    metadata = os.fstat(auth_root_fd)
    if (metadata.st_dev, metadata.st_ino) != (expected_device, expected_inode):
        os.close(auth_root_fd)
        raise AuthProtocolError("AUTH_ROOT_IDENTITY")
    return auth_root_fd


def _apply_auth_landlock(auth_root_fd: int) -> int:
    abi = _syscall(444, 0, 0, 1)
    if abi < 3:
        raise AuthProtocolError("LANDLOCK_ABI")
    ruleset_attr = _LandlockRulesetAttr(_LANDLOCK_HANDLED_ACCESS_FS)
    ruleset_fd = _syscall(444, ctypes.byref(ruleset_attr), ctypes.sizeof(ruleset_attr), 0)
    try:
        path_attr = _LandlockPathBeneathAttr(
            _LANDLOCK_ALLOWED_AUTH_ACCESS, auth_root_fd, 0
        )
        _syscall(445, ruleset_fd, 1, ctypes.byref(path_attr), 0)
        _syscall(446, ruleset_fd, 0)
    finally:
        os.close(ruleset_fd)
    return abi


def _openat2_auth_json(auth_root_fd: int) -> int:
    auth_fd = _openat2(auth_root_fd, "auth.json", flags=os.O_RDONLY | os.O_CLOEXEC)
    metadata = os.fstat(auth_fd)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & ~0o600
        or metadata.st_nlink != 1
    ):
        os.close(auth_fd)
        raise AuthProtocolError("AUTH_FILE_IDENTITY")
    return auth_fd


def _strict_json_loads(
    payload: bytes,
    *,
    required_fields: frozenset[str],
    optional_fields: frozenset[str],
    field_types: Mapping[str, type | tuple[type, ...]],
) -> dict[str, Any]:
    """Decode one bounded UTF-8 JSON object under an exact field schema."""
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not payload:
        raise AuthProtocolError("IPC_EMPTY")
    if len(payload) > IPC_MAX_REQUEST_BYTES:
        raise AuthProtocolError("IPC_OVERSIZED")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise AuthProtocolError("IPC_BAD_ENCODING") from None

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AuthProtocolError("IPC_DUPLICATE_FIELD")
            result[key] = value
        return result

    try:
        decoded = json.loads(text, object_pairs_hook=reject_duplicates)
    except AuthProtocolError:
        raise
    except (json.JSONDecodeError, ValueError, RecursionError):
        raise AuthProtocolError("IPC_BAD_JSON") from None
    if not isinstance(decoded, dict):
        raise AuthProtocolError("IPC_NOT_OBJECT")
    actual_fields = frozenset(decoded)
    if required_fields - actual_fields:
        raise AuthProtocolError("IPC_MISSING_FIELD")
    if actual_fields - required_fields - optional_fields:
        raise AuthProtocolError("IPC_UNKNOWN_FIELD")
    for name, expected_type in field_types.items():
        if name in decoded and type(decoded[name]) not in (
            expected_type if isinstance(expected_type, tuple) else (expected_type,)
        ):
            raise AuthProtocolError("IPC_FIELD_TYPE")
    if decoded.get("protocol_version") != IPC_PROTOCOL_VERSION:
        raise AuthProtocolError("IPC_VERSION")
    return decoded


def _encode_packet(payload: Mapping[str, Any]) -> bytes:
    """Encode one deterministic bounded protocol response packet."""
    try:
        encoded = json.dumps(
            dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise AuthProtocolError("IPC_BAD_RESPONSE") from None
    if len(encoded) > IPC_MAX_RESPONSE_BYTES:
        raise AuthProtocolError("IPC_RESPONSE_OVERSIZED")
    return encoded


def _sanitize_linux_fds(allowed_fds: frozenset[int]) -> None:
    """Close every currently open descriptor outside an explicit allowlist."""
    if not sys.platform.startswith("linux"):
        return
    for fd in _linux_open_fds():
        if fd in allowed_fds:
            continue
        try:
            os.close(fd)
        except OSError:
            pass


def _linux_open_fds() -> frozenset[int]:
    """Return a stable bounded snapshot without retaining the procfs scan FD."""
    try:
        candidates = [int(name) for name in os.listdir("/proc/self/fd")]
    except (FileNotFoundError, NotADirectoryError, PermissionError, ValueError):
        candidates = list(range(0, 4_096))
    result: set[int] = set()
    for fd in candidates:
        try:
            os.fstat(fd)
        except OSError:
            pass
        else:
            result.add(fd)
    return frozenset(result)


def _linux_open_fds_fcntl() -> tuple[int, ...]:
    """Prove the exact live FD set with bounded proc-independent kernel probes."""
    import fcntl
    import resource

    soft_limit, _hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft_limit == resource.RLIM_INFINITY:
        raise AuthProtocolError("HARDEN_NOFILE_UNBOUNDED")
    result: list[int] = []
    for fd in range(int(soft_limit)):
        try:
            fcntl.fcntl(fd, fcntl.F_GETFD)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            result.append(fd)
    return tuple(result)


def _recv_linux_packet(
    sock: socket.socket,
    *,
    expected_pid: int,
    expected_uid: int,
    expected_gid: int,
    allowed_fds: frozenset[int],
) -> bytes:
    """Receive one seqpacket and authenticate its current kernel sender."""
    if not sys.platform.startswith("linux"):
        raise RuntimeError("Linux credential transport is unavailable")
    sock.settimeout(IPC_REQUEST_TIMEOUT_SECONDS)
    credential_size = struct.calcsize("3i")
    integer_size = array.array("i").itemsize
    ancillary_size = socket.CMSG_SPACE(credential_size) + socket.CMSG_SPACE(
        253 * integer_size
    )
    try:
        payload, ancillary, flags, _address = sock.recvmsg(
            IPC_MAX_REQUEST_BYTES + 1, ancillary_size
        )
    except (TimeoutError, socket.timeout):
        raise AuthProtocolError("IPC_TIMEOUT") from None

    credentials: list[tuple[int, int, int]] = []
    received_fds: list[int] = []
    sanitize_required = bool(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
    try:
        unexpected_ancillary = False
        malformed_ancillary = False
        rights_record_seen = False
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                if len(data) != credential_size:
                    malformed_ancillary = True
                else:
                    credentials.append(struct.unpack("3i", data))
            elif level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                rights_record_seen = True
                sanitize_required = True
                if len(data) % integer_size:
                    malformed_ancillary = True
                rights = array.array("i")
                rights.frombytes(data[: len(data) - (len(data) % integer_size)])
                received_fds.extend(rights.tolist())
            else:
                unexpected_ancillary = True
                sanitize_required = True

        if flags & socket.MSG_CTRUNC:
            raise AuthProtocolError("IPC_CTRUNC")
        if flags & socket.MSG_TRUNC:
            raise AuthProtocolError("IPC_TRUNC")
        if malformed_ancillary:
            sanitize_required = True
            raise AuthProtocolError("IPC_ANCILLARY_INVALID")
        if rights_record_seen:
            raise AuthProtocolError("IPC_ANCILLARY_RIGHTS")
        if unexpected_ancillary:
            sanitize_required = True
            raise AuthProtocolError("IPC_ANCILLARY_INVALID")
        if len(credentials) != 1:
            sanitize_required = True
            raise AuthProtocolError("IPC_CREDENTIAL_COUNT")
        if credentials[0] != (expected_pid, expected_uid, expected_gid):
            raise AuthProtocolError("IPC_PEER_CREDENTIALS")
        if not payload:
            raise AuthProtocolError("IPC_EMPTY")
        if len(payload) > IPC_MAX_REQUEST_BYTES:
            raise AuthProtocolError("IPC_OVERSIZED")
        return payload
    finally:
        for fd in received_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        if sanitize_required:
            _sanitize_linux_fds(allowed_fds)
            if _linux_open_fds() != allowed_fds:
                raise AuthProtocolError("IPC_FD_SANITIZE")


def _send_linux_packet(sock: socket.socket, payload: bytes) -> None:
    """Send exactly one bounded seqpacket."""
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not payload:
        raise AuthProtocolError("IPC_EMPTY")
    if len(payload) > IPC_MAX_RESPONSE_BYTES:
        raise AuthProtocolError("IPC_RESPONSE_OVERSIZED")
    sock.settimeout(IPC_RESPONSE_TIMEOUT_SECONDS)
    try:
        sent = sock.sendmsg([payload])
    except (TimeoutError, socket.timeout):
        raise AuthProtocolError("IPC_TIMEOUT") from None
    if sent != len(payload):
        raise AuthProtocolError("IPC_SHORT_SEND")


def _recv_exact(sock: socket.socket, length: int, *, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AuthProtocolError("IPC_TIMEOUT")
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(length - len(result))
        except (TimeoutError, socket.timeout):
            raise AuthProtocolError("IPC_TIMEOUT") from None
        if not chunk:
            raise AuthProtocolError("IPC_EARLY_EOF")
        result.extend(chunk)
    return bytes(result)


def _recv_stream_packet(sock: socket.socket) -> bytes:
    """Receive one bounded four-byte-length-prefixed stream packet."""
    deadline = time.monotonic() + IPC_REQUEST_TIMEOUT_SECONDS
    length = struct.unpack("!I", _recv_exact(sock, 4, deadline=deadline))[0]
    if length == 0:
        raise AuthProtocolError("IPC_EMPTY")
    if length > IPC_MAX_REQUEST_BYTES:
        raise AuthProtocolError("IPC_OVERSIZED")
    return _recv_exact(sock, length, deadline=deadline)


def _send_stream_packet(sock: socket.socket, payload: bytes) -> None:
    """Send one bounded four-byte-length-prefixed stream packet."""
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not payload:
        raise AuthProtocolError("IPC_EMPTY")
    if len(payload) > IPC_MAX_RESPONSE_BYTES:
        raise AuthProtocolError("IPC_RESPONSE_OVERSIZED")
    sock.settimeout(IPC_RESPONSE_TIMEOUT_SECONDS)
    try:
        sock.sendall(struct.pack("!I", len(payload)) + payload)
    except (TimeoutError, socket.timeout):
        raise AuthProtocolError("IPC_TIMEOUT") from None


def _read_windows_bootstrap(stream: Any) -> bytes:
    """Consume exactly one bounded 32-byte bootstrap frame from inherited stdin."""
    frame = stream.read(33)
    if len(frame) < 32:
        raise AuthProtocolError("IPC_BOOTSTRAP_EOF")
    if len(frame) > 32:
        raise AuthProtocolError("IPC_BOOTSTRAP_OVERSIZED")
    return frame


def _read_windows_bootstrap_with_deadline(stream: Any) -> bytes:
    result_queue: queue.Queue[bytes | BaseException] = queue.Queue(maxsize=1)

    def read_once() -> None:
        try:
            result_queue.put_nowait(_read_windows_bootstrap(stream))
        except BaseException as exc:  # startup must fail closed on every read defect
            result_queue.put_nowait(exc)

    reader = threading.Thread(target=read_once, daemon=True)
    reader.start()
    try:
        result = result_queue.get(timeout=IPC_REQUEST_TIMEOUT_SECONDS)
    except queue.Empty:
        raise AuthProtocolError("IPC_BOOTSTRAP_TIMEOUT") from None
    if isinstance(result, BaseException):
        raise result
    return result


_REQUEST_FIELD_TYPES: dict[str, type | tuple[type, ...]] = {
    "protocol_version": str,
    "action": str,
    "bootstrap_nonce": str,
    "auth_file": str,
    "controller_pid": int,
    "controller_uid": int,
    "controller_gid": int,
    "auth_root_device": int,
    "auth_root_inode": int,
    "request_nonce": str,
    "task_id": str,
    "generation": int,
    "attempt_id": int,
    "launch_nonce": str,
    "provider_id": str,
    "upstream_scheme": str,
    "upstream_host": str,
    "upstream_port": int,
    "provider_purpose": str,
    "new_access_token": str,
    "expires_in": int,
}

_REQUEST_FIELDS: dict[str, frozenset[str]] = {
    "BOOTSTRAP": frozenset({"protocol_version", "action", "bootstrap_nonce"}),
    "STARTUP": frozenset(
        {
            "protocol_version",
            "action",
            "auth_file",
            "controller_pid",
            "controller_uid",
            "controller_gid",
            "auth_root_device",
            "auth_root_inode",
        }
    ),
    "PING": frozenset({"protocol_version", "action"}),
    "GET_IDENTITY": frozenset({"protocol_version", "action"}),
    "GET_TASK_PROVIDER_CAPABILITY": frozenset(
        {
            "protocol_version",
            "action",
            "request_nonce",
            "task_id",
            "generation",
            "attempt_id",
            "launch_nonce",
            "provider_id",
            "upstream_scheme",
            "upstream_host",
            "upstream_port",
            "provider_purpose",
        }
    ),
    "CANCEL_ATTEMPT": frozenset(
        {
            "protocol_version",
            "action",
            "task_id",
            "generation",
            "attempt_id",
            "launch_nonce",
            "provider_id",
            "upstream_scheme",
            "upstream_host",
            "upstream_port",
            "provider_purpose",
        }
    ),
    "TRIGGER_REFRESH_FAILURE": frozenset({"protocol_version", "action"}),
    "SHUTDOWN": frozenset({"protocol_version", "action"}),
}


def _decode_request_packet(payload: bytes) -> dict[str, Any]:
    union_fields = frozenset(_REQUEST_FIELD_TYPES)
    envelope = _strict_json_loads(
        payload,
        required_fields=frozenset({"protocol_version", "action"}),
        optional_fields=union_fields - {"protocol_version", "action"},
        field_types=_REQUEST_FIELD_TYPES,
    )
    required = _REQUEST_FIELDS.get(envelope["action"])
    if required is None:
        raise AuthProtocolError("IPC_UNKNOWN_OPERATION")
    return _strict_json_loads(
        payload,
        required_fields=required,
        optional_fields=frozenset(),
        field_types={name: _REQUEST_FIELD_TYPES[name] for name in required},
    )


_RESPONSE_FIELD_TYPES: dict[str, type | tuple[type, ...]] = {
    "protocol_version": str,
    "status": str,
    "error": str,
    "identity": dict,
    "request_nonce": str,
    "task_id": str,
    "generation": int,
    "attempt_id": int,
    "launch_nonce": str,
    "provider_id": str,
    "upstream_scheme": str,
    "upstream_host": str,
    "upstream_port": int,
    "provider_purpose": str,
    "helper_epoch": str,
    "access_token": str,
    "account_id": (str, type(None)),
    "issued_at": int,
    "expires_at": int,
    "capability_nonce": str,
    "capability_sequence": int,
}


def _decode_response_packet(payload: bytes) -> dict[str, Any]:
    response = _strict_json_loads(
        payload,
        required_fields=frozenset({"protocol_version", "status"}),
        optional_fields=frozenset(_RESPONSE_FIELD_TYPES) - {"protocol_version", "status"},
        field_types=_RESPONSE_FIELD_TYPES,
    )
    status = response["status"]
    if status == "ERROR":
        exact_fields = frozenset({"protocol_version", "status", "error"})
    elif status == "READY":
        exact_fields = frozenset({"protocol_version", "status", "identity"})
    elif status in ("PONG",):
        exact_fields = frozenset({"protocol_version", "status"})
    elif status == "OK" and "access_token" in response:
        exact_fields = frozenset(
            {
                "protocol_version", "status", "request_nonce", "task_id",
                "generation", "attempt_id", "launch_nonce", "provider_id",
                "upstream_scheme", "upstream_host", "upstream_port",
                "provider_purpose", "helper_epoch", "access_token",
                "issued_at", "expires_at", "capability_nonce", "capability_sequence",
            }
        )
        if "account_id" in response:
            exact_fields |= {"account_id"}
    elif status == "OK" and "identity" in response:
        exact_fields = frozenset({"protocol_version", "status", "identity"})
    elif status == "OK":
        exact_fields = frozenset({"protocol_version", "status"})
    else:
        raise AuthProtocolError("IPC_RESPONSE_STATUS")
    if frozenset(response) != exact_fields:
        raise AuthProtocolError("IPC_RESPONSE_SCHEMA")
    return response


def _encode_response(response: Mapping[str, Any]) -> bytes:
    return _encode_packet({"protocol_version": IPC_PROTOCOL_VERSION, **response})


def _file_identity(path: str) -> tuple[str, int, int, str]:
    """Hash one no-follow regular file and bind the digest to its kernel identity."""
    absolute = os.path.abspath(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(absolute, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise AuthProtocolError("IDENTITY_NOT_REGULAR")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        return absolute, metadata.st_dev, metadata.st_ino, digest.hexdigest()
    finally:
        os.close(fd)


def _linux_prctl(option: int, argument: int = 0) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(option, argument, 0, 0, 0)
    if result == -1:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return int(result)


def _linux_close_range(first: int, last: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    close_range = getattr(libc, "close_range", None)
    if close_range is None:
        raise AuthProtocolError("HARDEN_CLOSE_RANGE")
    if close_range(first, last, 0) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _bind_standard_fds_to_null() -> None:
    null_fd = os.open(os.devnull, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
    try:
        for target in (0, 1, 2):
            if null_fd != target:
                os.dup2(null_fd, target, inheritable=False)
    finally:
        if null_fd > 2:
            os.close(null_fd)


def _standard_fds_are_null() -> bool:
    null_metadata = os.stat(os.devnull)
    return all(
        stat.S_ISCHR(metadata.st_mode)
        and (metadata.st_dev, metadata.st_ino)
        == (null_metadata.st_dev, null_metadata.st_ino)
        for metadata in (os.fstat(0), os.fstat(1), os.fstat(2))
    )


def _fd_is_null(fd: int) -> bool:
    null_metadata = os.stat(os.devnull)
    metadata = os.fstat(fd)
    return (metadata.st_dev, metadata.st_ino) == (
        null_metadata.st_dev,
        null_metadata.st_ino,
    )


def _normalize_linux_ipc_and_harden(
    ipc_fd: int,
    *,
    test_fault: str | None,
    test_inherited_fds: tuple[int, ...],
) -> tuple[socket.socket, dict[str, Any]]:
    """Establish the exact pre-READY Linux process state."""
    import resource

    if test_fault == "core":
        raise AuthProtocolError("HARDEN_CORE")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    core_soft, core_hard = resource.getrlimit(resource.RLIMIT_CORE)
    if (core_soft, core_hard) != (0, 0):
        raise AuthProtocolError("HARDEN_CORE")

    if test_fault == "dumpable":
        raise AuthProtocolError("HARDEN_DUMPABLE")
    _linux_prctl(_PR_SET_DUMPABLE, 0)
    if _linux_prctl(_PR_GET_DUMPABLE) != 0:
        raise AuthProtocolError("HARDEN_DUMPABLE")

    _bind_standard_fds_to_null()
    if not _standard_fds_are_null():
        raise AuthProtocolError("HARDEN_STANDARD_FDS")
    if ipc_fd != 3:
        os.dup2(ipc_fd, 3, inheritable=False)
        os.close(ipc_fd)
    else:
        os.set_inheritable(3, False)
    ipc_socket = socket.socket(fileno=3)
    if test_fault == "fd_sanitize":
        raise AuthProtocolError("HARDEN_FD_SANITIZE")
    _linux_close_range(4, _UINT_MAX)
    open_fds = _linux_open_fds_fcntl()
    if open_fds != (0, 1, 2, 3):
        raise AuthProtocolError("HARDEN_FD_CENSUS")
    closed_inherited_fds: list[int] = []
    for inherited_fd in test_inherited_fds:
        try:
            os.fstat(inherited_fd)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
            closed_inherited_fds.append(inherited_fd)
            continue
        raise AuthProtocolError("HARDEN_INHERITED_FD")
    return ipc_socket, {
        "open_fds": open_fds,
        "core_soft_limit": core_soft,
        "core_hard_limit": core_hard,
        "dumpable": 0,
        "standard_fds_null": True,
        "closed_inherited_fds": tuple(closed_inherited_fds),
    }


def _count_open_fds() -> int:
    """Count open file descriptors for the current process."""
    if hasattr(os, "procfs") or os.path.exists("/proc/self/fd"):
        try:
            return len(os.listdir("/proc/self/fd"))
        except Exception:
            pass
    # Basic fallback approximation
    return 3


class AuthHelperDaemon:
    """Out-of-process daemon managing synthetic provider authentication state."""

    def __init__(
        self,
        auth_file: str,
        parent_pid: int,
        *,
        startup_identity: Mapping[str, Any],
        auth_data: Mapping[str, Any] | None = None,
    ) -> None:
        self.auth_file = os.path.abspath(auth_file)
        self.parent_pid = parent_pid
        self.started_at_monotonic_ns = time.monotonic_ns()
        self.helper_epoch = secrets.token_hex(16)
        self.request_nonces: set[str] = set()
        self.attempt_contexts: dict[tuple[Any, ...], tuple[int, bool]] = {}
        self._startup_identity = dict(startup_identity)

        if auth_data is None:
            if not os.path.exists(self.auth_file):
                raise FileNotFoundError("Auth file not found")
            with open(self.auth_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = dict(auth_data)

        self._validate_schema(data)
        tokens = data.get("tokens", {})
        self._auth_mode: str = data.get("auth_mode", "chatgpt")
        self._access_token: str = tokens.get("access_token", "")
        self._refresh_token: str = tokens.get("refresh_token", "")
        self._account_id: str | None = tokens.get("account_id")
        self._expires_at: int = tokens.get("expires_at", int(time.time()) + 3600)
        self._refresh_fail_trigger: bool = False

    def _validate_schema(self, data: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            raise ValueError("Auth data must be a dictionary")
        if "tokens" not in data or not isinstance(data["tokens"], dict):
            raise ValueError("Auth data missing required 'tokens' dictionary")
        tokens = data["tokens"]
        if "access_token" not in tokens or not isinstance(tokens["access_token"], str):
            raise ValueError("Auth tokens missing required 'access_token' string")

    @property
    def is_expired(self) -> bool:
        return time.time() >= self._expires_at

    def trigger_refresh_failure(self) -> None:
        """Trigger simulated refresh rejection for failure mode testing."""
        self._refresh_fail_trigger = True

    def get_identity_dict(self, ipc_endpoint: str) -> Dict[str, Any]:
        executable_identity = self._startup_identity.get("executable_identity")
        entrypoint_identity = self._startup_identity.get("entrypoint_identity")
        if executable_identity is None:
            executable_identity = _file_identity(sys.executable)
        if entrypoint_identity is None:
            entrypoint_identity = _file_identity(__file__)
        executable, executable_device, executable_inode, executable_digest = executable_identity
        entrypoint, entrypoint_device, entrypoint_inode, entrypoint_digest = entrypoint_identity
        return {
            "pid": os.getpid(),
            "uid": os.getuid() if hasattr(os, "getuid") else 0,
            "gid": os.getgid() if hasattr(os, "getgid") else 0,
            "controller_uid": self._startup_identity["controller_uid"],
            "controller_gid": self._startup_identity["controller_gid"],
            "executable": executable,
            "executable_device": executable_device,
            "executable_inode": executable_inode,
            "executable_digest": executable_digest,
            "entrypoint": entrypoint,
            "entrypoint_device": entrypoint_device,
            "entrypoint_inode": entrypoint_inode,
            "entrypoint_digest": entrypoint_digest,
            "cwd": os.getcwd(),
            "env_keys": sorted(list(os.environ.keys())),
            "import_paths": list(sys.path),
            "open_fds": list(self._startup_identity["open_fds"]),
            "standard_fds_null": self._startup_identity.get(
                "standard_fds_null", False
            ),
            "windows_stdin_bootstrap_closed": self._startup_identity.get(
                "windows_stdin_bootstrap_closed", False
            ),
            "closed_inherited_fds": list(
                self._startup_identity.get("closed_inherited_fds", ())
            ),
            "filesystem_probe_results": list(
                self._startup_identity.get("filesystem_probe_results", ())
            ),
            "ipc_endpoint": ipc_endpoint,
            "ipc_type": self._startup_identity["ipc_type"],
            "ipc_peer_auth": self._startup_identity["ipc_peer_auth"],
            "helper_epoch": self.helper_epoch,
            "protocol_version": IPC_PROTOCOL_VERSION,
            "core_soft_limit": self._startup_identity["core_soft_limit"],
            "core_hard_limit": self._startup_identity["core_hard_limit"],
            "dumpable": self._startup_identity["dumpable"],
            "no_new_privs": self._startup_identity["no_new_privs"],
            "landlock_abi": self._startup_identity.get("landlock_abi"),
            "landlock_handled_access_fs": self._startup_identity.get(
                "landlock_handled_access_fs"
            ),
            "auth_root_device": self._startup_identity.get("auth_root_device"),
            "auth_root_inode": self._startup_identity.get("auth_root_inode"),
            "parent_pid": self.parent_pid,
            "started_at_monotonic_ns": self.started_at_monotonic_ns,
        }

    def process_request(self, request: Dict[str, Any], ipc_endpoint: str) -> Dict[str, Any]:
        action = request.get("action")
        if action == "PING":
            return {"status": "PONG"}
        if action == "GET_IDENTITY":
            return {"status": "OK", "identity": self.get_identity_dict(ipc_endpoint)}

        if action == "GET_TASK_PROVIDER_CAPABILITY":
            task_id = request.get("task_id")
            generation = request.get("generation")
            attempt_id = request.get("attempt_id")
            launch_nonce = request.get("launch_nonce")
            provider_id = request.get("provider_id", "chatgpt_subscription")
            request_nonce = request.get("request_nonce")
            upstream_scheme = request.get("upstream_scheme")
            upstream_host = request.get("upstream_host")
            upstream_port = request.get("upstream_port")
            provider_purpose = request.get("provider_purpose")

            try:
                context_key = _validate_capability_context(request)
            except AuthProtocolError as exc:
                return {"status": "ERROR", "error": exc.code}
            previous_sequence, cancelled = self.attempt_contexts.get(context_key, (0, False))
            if cancelled:
                return {"status": "ERROR", "error": "TASK_CAPABILITY_CANCELLED"}
            if request_nonce in self.request_nonces:
                return {"status": "ERROR", "error": "REPLAYED_CAPABILITY_REQUEST"}
            if len(self.request_nonces) >= IPC_MAX_REPLAY_ENTRIES:
                return {"status": "ERROR", "error": "REPLAY_CACHE_EXHAUSTED"}
            if context_key not in self.attempt_contexts:
                if len(self.attempt_contexts) >= IPC_MAX_ATTEMPT_CONTEXTS:
                    return {"status": "ERROR", "error": "ATTEMPT_CONTEXT_EXHAUSTED"}
            if previous_sequence >= IPC_MAX_CAPABILITIES_PER_ATTEMPT:
                return {"status": "ERROR", "error": "CAPABILITY_ISSUANCE_LIMIT"}
            capability_sequence = previous_sequence + 1

            # Check simulated refresh trigger failure
            if self._refresh_fail_trigger:
                self._refresh_fail_trigger = False
                return {"status": "ERROR", "error": "PROVIDER_AUTH_UNAVAILABLE"}

            # Perform synthetic token refresh if expired
            if self.is_expired:
                if not self._refresh_token:
                    return {"status": "ERROR", "error": "PROVIDER_AUTH_UNAVAILABLE"}
                # Synthetic token refresh out-of-process
                self._access_token = f"CANARY_ACCESS_TOKEN_REFRESHED_{int(time.time())}"
                self._expires_at = int(time.time()) + 3600

            self.request_nonces.add(request_nonce)
            self.attempt_contexts[context_key] = (capability_sequence, False)

            issued_at = int(time.time())
            cap_nonce = secrets.token_hex(16)
            return {
                "status": "OK",
                "request_nonce": request_nonce,
                "task_id": task_id,
                "generation": generation,
                "attempt_id": attempt_id,
                "launch_nonce": launch_nonce,
                "provider_id": provider_id,
                "upstream_scheme": upstream_scheme,
                "upstream_host": upstream_host,
                "upstream_port": upstream_port,
                "provider_purpose": provider_purpose,
                "helper_epoch": self.helper_epoch,
                "access_token": self._access_token,
                "account_id": self._account_id,
                "issued_at": issued_at,
                "expires_at": min(self._expires_at, issued_at + 300),
                "capability_nonce": cap_nonce,
                "capability_sequence": capability_sequence,
            }

        if action == "CANCEL_ATTEMPT":
            try:
                context_key = _validate_capability_context(
                    {**request, "request_nonce": "0" * 32}
                )
            except AuthProtocolError as exc:
                return {"status": "ERROR", "error": exc.code}
            if context_key not in self.attempt_contexts:
                if len(self.attempt_contexts) >= IPC_MAX_ATTEMPT_CONTEXTS:
                    return {"status": "ERROR", "error": "ATTEMPT_CONTEXT_EXHAUSTED"}
                sequence = 0
            else:
                sequence = self.attempt_contexts[context_key][0]
            self.attempt_contexts[context_key] = (sequence, True)
            return {"status": "OK"}

        if action == "TRIGGER_REFRESH_FAILURE":
            self.trigger_refresh_failure()
            return {"status": "OK"}

        if action == "SHUTDOWN":
            return {"status": "OK"}

        return {"status": "ERROR", "error": "IPC_UNKNOWN_OPERATION"}


def _run_authenticated_session(
    daemon: AuthHelperDaemon,
    sock: socket.socket,
    endpoint_str: str,
    *,
    linux_parent_credentials: tuple[int, int, int] | None,
) -> None:
    if linux_parent_credentials is None:
        recv_packet = lambda: _recv_stream_packet(sock)
        send_packet = lambda packet: _send_stream_packet(sock, packet)
    else:
        parent_pid, parent_uid, parent_gid = linux_parent_credentials
        allowed_fds = frozenset({0, 1, 2, sock.fileno()})
        recv_packet = lambda: _recv_linux_packet(
            sock,
            expected_pid=parent_pid,
            expected_uid=parent_uid,
            expected_gid=parent_gid,
            allowed_fds=allowed_fds,
        )
        send_packet = lambda packet: _send_linux_packet(sock, packet)

    for message_number in range(1, IPC_MAX_MESSAGES_PER_HELPER + 2):
        try:
            packet = recv_packet()
            if message_number > IPC_MAX_MESSAGES_PER_HELPER:
                send_packet(
                    _encode_response(
                        {"status": "ERROR", "error": "IPC_MESSAGE_LIMIT"}
                    )
                )
                return
            request = _decode_request_packet(packet)
            response = daemon.process_request(request, endpoint_str)
        except AuthProtocolError as exc:
            send_packet(_encode_response({"status": "ERROR", "error": exc.code}))
            continue
        send_packet(_encode_response(response))
        if request["action"] == "SHUTDOWN":
            return


def _validate_startup(
    startup: Mapping[str, Any],
    *,
    parent_pid: int,
    controller_uid: int,
    controller_gid: int,
) -> str:
    if startup["action"] != "STARTUP":
        raise AuthProtocolError("STARTUP_ACTION")
    if (
        startup["controller_pid"],
        startup["controller_uid"],
        startup["controller_gid"],
    ) != (parent_pid, controller_uid, controller_gid):
        raise AuthProtocolError("STARTUP_IDENTITY")
    return startup["auth_file"]


def run_linux_daemon(
    parent_pid: int,
    ipc_fd: int,
    *,
    test_fault: str | None,
    test_inherited_fds: tuple[int, ...],
    test_denied_probe_paths: tuple[str, ...],
    test_allowed_probe_name: str | None,
) -> None:
    """Run one inherited Linux seqpacket endpoint with no listener or path."""
    ipc_socket, startup_identity = _normalize_linux_ipc_and_harden(
        ipc_fd,
        test_fault=test_fault,
        test_inherited_fds=test_inherited_fds,
    )
    startup_identity["executable_identity"] = _file_identity(sys.executable)
    startup_identity["entrypoint_identity"] = _file_identity(__file__)
    ipc_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    endpoint_str = f"fd://{ipc_socket.fileno()}"
    try:
        peer_pid, peer_uid, peer_gid = struct.unpack(
            "3i",
            ipc_socket.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            ),
        )
        if (peer_pid, peer_uid, peer_gid) != (
            parent_pid,
            os.getuid(),
            os.getgid(),
        ):
            raise AuthProtocolError("IPC_CREATION_PEER")
        startup = _decode_request_packet(
            _recv_linux_packet(
                ipc_socket,
                expected_pid=parent_pid,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
                allowed_fds=frozenset({0, 1, 2, 3}),
            )
        )
        auth_file = _validate_startup(
            startup,
            parent_pid=parent_pid,
            controller_uid=os.getuid(),
            controller_gid=os.getgid(),
        )
        if test_fault == "no_new_privs":
            raise AuthProtocolError("HARDEN_NO_NEW_PRIVS")
        _linux_prctl(_PR_SET_NO_NEW_PRIVS, 1)
        no_new_privs = _linux_prctl(_PR_GET_NO_NEW_PRIVS)
        if no_new_privs != 1:
            raise AuthProtocolError("HARDEN_NO_NEW_PRIVS")
        startup_identity.update(
            {
                "controller_uid": os.getuid(),
                "controller_gid": os.getgid(),
                "ipc_type": "AF_UNIX/SOCK_SEQPACKET",
                "ipc_peer_auth": "SO_PASSCRED/SCM_CREDENTIALS",
                "no_new_privs": no_new_privs,
            }
        )
        if test_fault == "openat2":
            raise AuthProtocolError("OPENAT2")
        root_device = startup["auth_root_device"]
        root_inode = startup["auth_root_inode"]
        if test_fault == "auth_root_identity":
            root_inode += 1
        auth_root_fd = _openat2_auth_root(auth_file.rsplit("/", 1)[0], root_device, root_inode)
        try:
            if test_fault == "landlock_abi":
                raise AuthProtocolError("LANDLOCK_ABI")
            if test_fault == "landlock_create":
                raise AuthProtocolError("LANDLOCK_CREATE")
            if test_fault == "landlock_add":
                raise AuthProtocolError("LANDLOCK_ADD")
            if test_fault == "landlock_restrict":
                raise AuthProtocolError("LANDLOCK_RESTRICT")
            landlock_abi = _apply_auth_landlock(auth_root_fd)
            probe_results: list[tuple[str, str, str]] = []
            for index, probe_path in enumerate(test_denied_probe_paths):
                try:
                    probe_fd = os.open(probe_path, os.O_RDONLY | os.O_CLOEXEC)
                except OSError as exc:
                    probe_results.append(
                        (f"probe-{index}", "KERNEL_DENIED", errno.errorcode.get(exc.errno, "UNKNOWN"))
                    )
                else:
                    os.close(probe_fd)
                    raise AuthProtocolError("LANDLOCK_PROBE_ALLOWED")
            if test_allowed_probe_name is not None:
                if "/" in test_allowed_probe_name or test_allowed_probe_name in ("", ".", ".."):
                    raise AuthProtocolError("LANDLOCK_ALLOWED_PROBE_NAME")
                allowed_fd = _openat2(
                    auth_root_fd,
                    test_allowed_probe_name,
                    flags=os.O_RDONLY | os.O_CLOEXEC,
                )
                try:
                    if os.read(allowed_fd, 8) != b"allowed\n":
                        raise AuthProtocolError("LANDLOCK_ALLOWED_PROBE_CONTENT")
                finally:
                    os.close(allowed_fd)
            if test_fault == "auth_open":
                raise AuthProtocolError("AUTH_OPEN")
            auth_fd = _openat2_auth_json(auth_root_fd)
            try:
                with os.fdopen(os.dup(auth_fd), "r", encoding="utf-8") as auth_stream:
                    if test_fault == "auth_json":
                        raise AuthProtocolError("AUTH_JSON")
                    auth_data = json.load(auth_stream)
            finally:
                os.close(auth_fd)
        finally:
            os.close(auth_root_fd)
        startup_identity.update(
            {
                "landlock_abi": landlock_abi,
                "landlock_handled_access_fs": _LANDLOCK_HANDLED_ACCESS_FS,
                "auth_root_device": root_device,
                "auth_root_inode": root_inode,
                "filesystem_probe_results": tuple(probe_results),
            }
        )
        if _linux_open_fds_fcntl() != (0, 1, 2, 3):
            raise AuthProtocolError("LANDLOCK_READY_FD_CENSUS")
        daemon = AuthHelperDaemon(
            auth_file,
            parent_pid,
            startup_identity=startup_identity,
            auth_data=auth_data,
        )
        _send_linux_packet(
            ipc_socket,
            _encode_response(
                {"status": "READY", "identity": daemon.get_identity_dict(endpoint_str)}
            ),
        )
        _run_authenticated_session(
            daemon,
            ipc_socket,
            endpoint_str,
            linux_parent_credentials=(parent_pid, os.getuid(), os.getgid()),
        )
    finally:
        ipc_socket.close()


def _replace_stdin_with_null() -> None:
    try:
        sys.stdin.close()
    except Exception:
        pass
    null_fd = os.open(os.devnull, os.O_RDONLY)
    try:
        if null_fd != 0:
            os.dup2(null_fd, 0)
    finally:
        if null_fd != 0:
            os.close(null_fd)
    if not _fd_is_null(0):
        raise AuthProtocolError("IPC_BOOTSTRAP_CLOSE")


def run_windows_daemon(parent_pid: int) -> None:
    """Run the bounded one-connection Windows functional fallback."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(IPC_REQUEST_TIMEOUT_SECONDS)
    bootstrap_nonce = _read_windows_bootstrap_with_deadline(sys.stdin.buffer)
    _replace_stdin_with_null()
    endpoint_str = f"tcp://127.0.0.1:{listener.getsockname()[1]}"
    print(f"AUTH_HELPER_READY:{endpoint_str}", flush=True)
    try:
        connection, _address = listener.accept()
    except (TimeoutError, socket.timeout):
        raise AuthProtocolError("IPC_BOOTSTRAP_TIMEOUT") from None
    finally:
        listener.close()

    with connection:
        bootstrap = _decode_request_packet(_recv_stream_packet(connection))
        if bootstrap["action"] != "BOOTSTRAP" or not secrets.compare_digest(
            bootstrap["bootstrap_nonce"], bootstrap_nonce.hex()
        ):
            raise AuthProtocolError("IPC_BOOTSTRAP_AUTH")
        bootstrap_nonce = b""
        startup = _decode_request_packet(_recv_stream_packet(connection))
        auth_file = _validate_startup(
            startup,
            parent_pid=parent_pid,
            controller_uid=0,
            controller_gid=0,
        )
        daemon = AuthHelperDaemon(
            auth_file,
            parent_pid,
            startup_identity={
                "controller_uid": 0,
                "controller_gid": 0,
                "open_fds": tuple(),
                "ipc_type": "AF_INET/SOCK_STREAM",
                "ipc_peer_auth": "BOOTSTRAP_NONCE_ONLY_WINDOWS_FUNCTIONAL",
                "core_soft_limit": None,
                "core_hard_limit": None,
                "dumpable": None,
                "no_new_privs": None,
                "standard_fds_null": False,
                "windows_stdin_bootstrap_closed": True,
                "closed_inherited_fds": tuple(),
                "filesystem_probe_results": tuple(),
            },
        )
        _send_stream_packet(
            connection,
            _encode_response(
                {"status": "READY", "identity": daemon.get_identity_dict(endpoint_str)}
            ),
        )
        _run_authenticated_session(
            daemon,
            connection,
            endpoint_str,
            linux_parent_credentials=None,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="AgenticOS Out-of-Process Auth Helper Daemon")
    parser.add_argument("--parent-pid", type=int, required=True, help="Parent controller PID")
    parser.add_argument("--ipc-fd", type=int, help="Inherited Linux seqpacket descriptor")
    parser.add_argument(
        "--windows-loopback",
        action="store_true",
        help="Use the bounded Windows functional fallback",
    )
    parser.add_argument("--test-startup-fault", choices=("core", "dumpable", "fd_sanitize", "no_new_privs", "openat2", "auth_root_identity", "landlock_abi", "landlock_create", "landlock_add", "landlock_restrict", "auth_open", "auth_json"))
    parser.add_argument("--test-inherited-fds", default="")
    parser.add_argument("--test-denied-probe", action="append", default=[])
    parser.add_argument("--test-allowed-probe")
    args = parser.parse_args()
    if sys.platform.startswith("linux"):
        if args.ipc_fd is None or args.windows_loopback:
            parser.error("Linux requires exactly one inherited --ipc-fd")
        inherited_fds = tuple(
            int(value) for value in args.test_inherited_fds.split(",") if value
        )
        run_linux_daemon(
            args.parent_pid,
            args.ipc_fd,
            test_fault=args.test_startup_fault,
            test_inherited_fds=inherited_fds,
            test_denied_probe_paths=tuple(args.test_denied_probe),
            test_allowed_probe_name=args.test_allowed_probe,
        )
    elif os.name == "nt":
        if args.ipc_fd is not None or not args.windows_loopback:
            parser.error("Windows requires --windows-loopback")
        if args.test_startup_fault or args.test_inherited_fds:
            parser.error("test hardening controls are Linux-only")
        run_windows_daemon(args.parent_pid)
    else:
        parser.error("unsupported auth-helper platform")


if __name__ == "__main__":
    main()
