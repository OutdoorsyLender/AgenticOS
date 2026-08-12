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

_PR_GET_DUMPABLE = 3
_PR_SET_DUMPABLE = 4
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39
_UINT_MAX = (1 << 32) - 1


class AuthProtocolError(RuntimeError):
    """Fixed-code protocol failure that never retains rejected input."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


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
    "CANCEL_TASK": frozenset({"protocol_version", "action", "task_id"}),
    "TRIGGER_REFRESH_FAILURE": frozenset({"protocol_version", "action"}),
    "REFRESH_TOKENS": frozenset(
        {"protocol_version", "action", "new_access_token", "expires_in"}
    ),
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
        raise AuthProtocolError("IPC_ACTION")
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
    return _strict_json_loads(
        payload,
        required_fields=frozenset({"protocol_version", "status"}),
        optional_fields=frozenset(_RESPONSE_FIELD_TYPES) - {"protocol_version", "status"},
        field_types=_RESPONSE_FIELD_TYPES,
    )


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
    ) -> None:
        self.auth_file = os.path.abspath(auth_file)
        self.parent_pid = parent_pid
        self.started_at_monotonic_ns = time.monotonic_ns()
        self.helper_epoch = secrets.token_hex(16)
        self.revoked_tasks: set[str] = set()
        self.issued_nonces: set[str] = set()
        self._startup_identity = dict(startup_identity)

        if not os.path.exists(self.auth_file):
            raise FileNotFoundError(f"Auth file not found: {self.auth_file}")

        with open(self.auth_file, "r", encoding="utf-8") as f:
            data = json.load(f)

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
        executable, executable_device, executable_inode, executable_digest = (
            _file_identity(sys.executable)
        )
        entrypoint, entrypoint_device, entrypoint_inode, entrypoint_digest = (
            _file_identity(__file__)
        )
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
            "ipc_endpoint": ipc_endpoint,
            "ipc_type": self._startup_identity["ipc_type"],
            "ipc_peer_auth": self._startup_identity["ipc_peer_auth"],
            "helper_epoch": self.helper_epoch,
            "protocol_version": IPC_PROTOCOL_VERSION,
            "core_soft_limit": self._startup_identity["core_soft_limit"],
            "core_hard_limit": self._startup_identity["core_hard_limit"],
            "dumpable": self._startup_identity["dumpable"],
            "no_new_privs": self._startup_identity["no_new_privs"],
            "landlock_abi": None,
            "landlock_handled_access_fs": None,
            "auth_root_device": None,
            "auth_root_inode": None,
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

            if not task_id or not isinstance(task_id, str):
                return {"status": "ERROR", "error": "Invalid task_id"}
            if type(generation) is not int or generation <= 0:
                return {"status": "ERROR", "error": "Invalid generation"}
            if type(attempt_id) is not int or attempt_id <= 0:
                return {"status": "ERROR", "error": "Invalid attempt_id"}
            if not launch_nonce or not isinstance(launch_nonce, str):
                return {"status": "ERROR", "error": "Invalid launch_nonce"}

            # Check revocation
            if task_id in self.revoked_tasks:
                return {"status": "ERROR", "error": "TASK_CAPABILITY_CANCELLED"}

            # Check replay prevention on capability nonce
            cap_key = f"{task_id}:{generation}:{attempt_id}:{launch_nonce}"
            if cap_key in self.issued_nonces:
                return {"status": "ERROR", "error": "REPLAYED_CAPABILITY_REQUEST"}
            self.issued_nonces.add(cap_key)

            # Check simulated refresh trigger failure
            if self._refresh_fail_trigger:
                return {"status": "ERROR", "error": "PROVIDER_AUTH_UNAVAILABLE"}

            # Perform synthetic token refresh if expired
            if self.is_expired:
                if not self._refresh_token:
                    return {"status": "ERROR", "error": "PROVIDER_AUTH_UNAVAILABLE"}
                # Synthetic token refresh out-of-process
                self._access_token = f"CANARY_ACCESS_TOKEN_REFRESHED_{int(time.time())}"
                self._expires_at = int(time.time()) + 3600

            issued_at = int(time.time())
            cap_nonce = hashlib.sha256(f"{cap_key}:{time.time()}".encode("ascii")).hexdigest()[:32]
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
                "capability_sequence": 1,
            }

        if action == "CANCEL_TASK":
            task_id = request.get("task_id")
            if task_id and isinstance(task_id, str):
                self.revoked_tasks.add(task_id)
            return {"status": "OK"}

        if action == "TRIGGER_REFRESH_FAILURE":
            self.trigger_refresh_failure()
            return {"status": "OK"}

        if action == "REFRESH_TOKENS":
            new_access = request.get("new_access_token")
            if not new_access or not isinstance(new_access, str):
                return {"status": "ERROR", "error": "Invalid new_access_token"}
            self._access_token = new_access
            self._expires_at = int(time.time()) + request.get("expires_in", 3600)
            return {"status": "OK"}

        if action == "SHUTDOWN":
            return {"status": "OK"}

        return {"status": "ERROR", "error": "IPC_ACTION"}


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
) -> None:
    """Run one inherited Linux seqpacket endpoint with no listener or path."""
    ipc_socket, startup_identity = _normalize_linux_ipc_and_harden(
        ipc_fd,
        test_fault=test_fault,
        test_inherited_fds=test_inherited_fds,
    )
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
        daemon = AuthHelperDaemon(
            auth_file,
            parent_pid,
            startup_identity=startup_identity,
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
    parser.add_argument("--test-startup-fault", choices=("core", "dumpable", "fd_sanitize", "no_new_privs"))
    parser.add_argument("--test-inherited-fds", default="")
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
