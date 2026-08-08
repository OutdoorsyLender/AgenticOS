"""Linux kernel identity primitives for M4B network capabilities."""

from __future__ import annotations

import array
from collections.abc import Callable
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
import re
import select
import socket
import stat
import struct
import sys
import threading
import time
from typing import Any

from .network_models import (
    ListenerEvidence,
    TransportMode,
    TransportPolicy,
    canonical_policy_bytes,
)


_ADOPTION_VERSION = "AOSLISTENER/1"
_MAX_POLICY_BYTES = 4096
_MAX_ADOPTION_FRAME = 2048
_ADOPTION_EOF_TIMEOUT_SECONDS = 0.25
_MAX_UNSIGNED_64 = (1 << 64) - 1
_TASK_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_LOWER_HEX_32_RE = re.compile(r"[0-9a-f]{32}\Z")
_LOWER_HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
_SO_NETNS_COOKIE = getattr(socket, "SO_NETNS_COOKIE", 71)
_SO_DOMAIN = getattr(socket, "SO_DOMAIN", 39)
_SO_REUSEPORT = getattr(socket, "SO_REUSEPORT", 15)
_POLL_READ_CLOSED = getattr(select, "POLLRDHUP", 0x2000)
_CREDENTIAL_BYTES = struct.calcsize("=3i")
_RIGHTS_BYTES = array.array("i").itemsize
_ACTIVE_CHANNEL_CLAIMS_LOCK = threading.Lock()
_ACTIVE_CHANNEL_CLAIMS: dict[tuple[int, int, int, str], int] = {}
_REQUIRED_POLICY_SEALS = (
    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
)
_POLICY_FIELDS = {
    "version",
    "task_id",
    "task_generation",
    "launch_nonce",
    "mode",
    "proxy_host",
    "proxy_port",
    "activated_at_monotonic_ns",
    "expires_at_monotonic_ns",
    "connection_limit",
    "byte_limit",
}
_FRAME_FIELDS = {
    "version",
    "task_id",
    "task_generation",
    "launch_nonce",
    "policy_digest",
    "evidence",
}
_EVIDENCE_FIELDS = {
    "family",
    "socket_type",
    "address",
    "port",
    "device",
    "inode",
    "file_type",
    "netns_cookie",
    "accepting",
}


class NetworkIdentityError(RuntimeError):
    """A network capability failed closed identity validation."""


@dataclass(frozen=True)
class VerifiedSealedPolicy:
    """A policy reconstructed from an immutable kernel object."""

    policy: TransportPolicy
    digest: str
    device: int
    inode: int
    size: int
    seals: int


def _require_positive_u64(name: str, value: object) -> None:
    if type(value) is not int or not 0 < value <= _MAX_UNSIGNED_64:
        raise NetworkIdentityError(f"{name} must be a positive unsigned 64-bit integer")


def _require_task_context(
    task_id: object, generation: object, nonce: object, digest: object
) -> None:
    if type(task_id) is not str or not _TASK_ID_RE.fullmatch(task_id):
        raise NetworkIdentityError("task_id must be a bounded ASCII identifier")
    _require_positive_u64("task_generation", generation)
    if type(nonce) is not str or not _LOWER_HEX_32_RE.fullmatch(nonce):
        raise NetworkIdentityError("launch_nonce must be lowercase hexadecimal")
    if type(digest) is not str or not _LOWER_HEX_64_RE.fullmatch(digest):
        raise NetworkIdentityError("policy_digest must be lowercase hexadecimal")


def _require_exact_fields(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise NetworkIdentityError(f"{label} has missing or unknown fields")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NetworkIdentityError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise NetworkIdentityError(f"non-finite JSON number is forbidden: {value}")


def _decode_json(payload: bytes, *, maximum: int, label: str) -> dict[str, Any]:
    if type(payload) is not bytes or not 0 < len(payload) <= maximum:
        raise NetworkIdentityError(f"{label} is empty or oversized")
    try:
        text = payload.decode("ascii")
        decoded = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except NetworkIdentityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise NetworkIdentityError(f"{label} is not strict ASCII JSON") from exc
    if type(decoded) is not dict:
        raise NetworkIdentityError(f"{label} must be a JSON object")
    return decoded


def _duplicate_cloexec(fd: int) -> int:
    if type(fd) is not int or fd < 0:
        raise NetworkIdentityError("file descriptor must be a non-negative integer")
    duplicate: int | None = None
    completed = False
    try:
        duplicate = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
        if not fcntl.fcntl(duplicate, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
            raise NetworkIdentityError("duplicated descriptor is not close-on-exec")
        completed = True
        return duplicate
    except NetworkIdentityError:
        raise
    except OSError as exc:
        raise NetworkIdentityError("could not securely duplicate descriptor") from exc
    finally:
        if duplicate is not None and not completed:
            try:
                os.close(duplicate)
            except OSError:
                pass


def _require_cloexec_fd(fd: int, label: str) -> None:
    if type(fd) is not int or fd < 0:
        raise NetworkIdentityError(f"{label} must be a non-negative descriptor")
    try:
        if not fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
            raise NetworkIdentityError(f"{label} must be close-on-exec")
    except NetworkIdentityError:
        raise
    except OSError as exc:
        raise NetworkIdentityError(f"could not inspect {label}") from exc


def _write_exact(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise NetworkIdentityError("short write to sealed policy object")
        offset += written


def create_sealed_policy_fd(policy: TransportPolicy) -> int:
    """Create an owned CLOEXEC memfd containing one fully sealed policy."""
    fd: int | None = None
    completed = False
    try:
        payload = canonical_policy_bytes(policy)
        if not 0 < len(payload) <= _MAX_POLICY_BYTES:
            raise NetworkIdentityError("canonical policy payload is empty or oversized")
        flags = os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
        fd = os.memfd_create("aos-network-policy", flags)
        _write_exact(fd, payload)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, _REQUIRED_POLICY_SEALS)
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        if seals & _REQUIRED_POLICY_SEALS != _REQUIRED_POLICY_SEALS:
            raise NetworkIdentityError("policy object did not acquire every required seal")
        os.lseek(fd, 0, os.SEEK_SET)
        completed = True
        return fd
    except NetworkIdentityError:
        raise
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise NetworkIdentityError("could not create sealed policy object") from exc
    finally:
        if fd is not None and not completed:
            try:
                os.close(fd)
            except OSError:
                pass


def _transport_policy_from_bytes(payload: bytes) -> TransportPolicy:
    decoded = _require_exact_fields(
        _decode_json(payload, maximum=_MAX_POLICY_BYTES, label="sealed policy"),
        _POLICY_FIELDS,
        "sealed policy",
    )
    try:
        if type(decoded["mode"]) is not str:
            raise ValueError("mode must be a string")
        policy = TransportPolicy(
            version=decoded["version"],
            task_id=decoded["task_id"],
            task_generation=decoded["task_generation"],
            launch_nonce=decoded["launch_nonce"],
            mode=TransportMode(decoded["mode"]),
            proxy_host=decoded["proxy_host"],
            proxy_port=decoded["proxy_port"],
            activated_at_monotonic_ns=decoded["activated_at_monotonic_ns"],
            expires_at_monotonic_ns=decoded["expires_at_monotonic_ns"],
            connection_limit=decoded["connection_limit"],
            byte_limit=decoded["byte_limit"],
        )
    except (TypeError, ValueError) as exc:
        raise NetworkIdentityError("sealed policy fields are invalid") from exc
    if canonical_policy_bytes(policy) != payload:
        raise NetworkIdentityError("sealed policy encoding is not canonical")
    return policy


def read_sealed_policy_fd(fd: int) -> VerifiedSealedPolicy:
    """Securely duplicate, re-verify, and reconstruct a fully sealed policy."""
    duplicate: int | None = None
    try:
        duplicate = _duplicate_cloexec(fd)
        before = os.fstat(duplicate)
        if not stat.S_ISREG(before.st_mode):
            raise NetworkIdentityError("policy descriptor is not a regular memfd-like object")
        if before.st_dev <= 0 or before.st_ino <= 0:
            raise NetworkIdentityError("policy object lacks positive kernel identity")
        if not 0 < before.st_size <= _MAX_POLICY_BYTES:
            raise NetworkIdentityError("sealed policy size is empty or oversized")
        seals_before = fcntl.fcntl(duplicate, fcntl.F_GET_SEALS)
        if seals_before & _REQUIRED_POLICY_SEALS != _REQUIRED_POLICY_SEALS:
            raise NetworkIdentityError("policy object is not fully sealed")

        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(duplicate, before.st_size - offset, offset)
            if not chunk:
                raise NetworkIdentityError("sealed policy read ended early")
            chunks.append(chunk)
            offset += len(chunk)
        if os.pread(duplicate, 1, before.st_size):
            raise NetworkIdentityError("sealed policy exceeded its verified size")
        payload = b"".join(chunks)
        if len(payload) != before.st_size:
            raise NetworkIdentityError("sealed policy read length changed")

        after = os.fstat(duplicate)
        seals_after = fcntl.fcntl(duplicate, fcntl.F_GET_SEALS)
        if seals_after & _REQUIRED_POLICY_SEALS != _REQUIRED_POLICY_SEALS:
            raise NetworkIdentityError("policy seals changed during verification")
        if (
            after.st_dev,
            after.st_ino,
            stat.S_IFMT(after.st_mode),
            after.st_size,
        ) != (
            before.st_dev,
            before.st_ino,
            stat.S_IFMT(before.st_mode),
            before.st_size,
        ):
            raise NetworkIdentityError("policy kernel identity changed during verification")

        policy = _transport_policy_from_bytes(payload)
        return VerifiedSealedPolicy(
            policy=policy,
            digest=hashlib.sha256(payload).hexdigest(),
            device=after.st_dev,
            inode=after.st_ino,
            size=after.st_size,
            seals=seals_after,
        )
    except NetworkIdentityError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise NetworkIdentityError("sealed policy verification failed") from exc
    finally:
        if duplicate is not None:
            os.close(duplicate)


def listener_evidence(fd: int) -> ListenerEvidence:
    """Independently observe the exact fixed M4B listener kernel object."""
    _require_cloexec_fd(fd, "listener source descriptor")
    duplicate = _duplicate_cloexec(fd)
    observed: socket.socket | None = None
    try:
        observed = socket.socket(fileno=duplicate)
        duplicate = -1
        status = os.fstat(observed.fileno())
        file_type = stat.S_IFMT(status.st_mode)
        socket_type = observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        accepting = bool(observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN))
        reuse_address = observed.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
        reuse_port = observed.getsockopt(socket.SOL_SOCKET, _SO_REUSEPORT)
        address = observed.getsockname()
        cookie_bytes = observed.getsockopt(socket.SOL_SOCKET, _SO_NETNS_COOKIE, 8)
        if type(cookie_bytes) is not bytes or len(cookie_bytes) != 8:
            raise NetworkIdentityError("SO_NETNS_COOKIE returned an invalid value")
        netns_cookie = struct.unpack("=Q", cookie_bytes)[0]
        if (
            observed.family != socket.AF_INET
            or socket_type != socket.SOCK_STREAM
            or type(address) is not tuple
            or len(address) < 2
            or address[0] != "127.0.0.1"
            or address[1] != 18080
            or file_type != stat.S_IFSOCK
            or status.st_dev <= 0
            or status.st_ino <= 0
            or not accepting
            or reuse_address != 0
            or reuse_port != 0
            or netns_cookie <= 0
        ):
            raise NetworkIdentityError("descriptor is not the exact fixed M4B listener")
        return ListenerEvidence(
            family=int(socket.AF_INET),
            socket_type=socket_type & 0xF,
            address=address[0],
            port=address[1],
            device=status.st_dev,
            inode=status.st_ino,
            file_type=file_type,
            netns_cookie=netns_cookie,
            accepting=accepting,
        )
    except NetworkIdentityError:
        raise
    except (OSError, TypeError, ValueError, struct.error) as exc:
        raise NetworkIdentityError("listener kernel identity could not be established") from exc
    finally:
        if observed is not None:
            observed.close()
        elif duplicate >= 0:
            os.close(duplicate)


def _require_listener_contract(evidence: object) -> ListenerEvidence:
    if type(evidence) is not ListenerEvidence:
        raise NetworkIdentityError("evidence must be exact ListenerEvidence")
    if (
        evidence.family != socket.AF_INET
        or evidence.socket_type != socket.SOCK_STREAM
        or evidence.address != "127.0.0.1"
        or evidence.port != 18080
        or evidence.file_type != stat.S_IFSOCK
        or not evidence.accepting
    ):
        raise NetworkIdentityError("adoption frame does not describe the fixed listener")
    return evidence


@dataclass(frozen=True)
class ListenerAdoptionFrame:
    """Canonical one-shot listener handoff control frame."""

    version: str
    task_id: str
    task_generation: int
    launch_nonce: str
    policy_digest: str
    evidence: ListenerEvidence

    def __post_init__(self) -> None:
        if type(self.version) is not str or self.version != _ADOPTION_VERSION:
            raise NetworkIdentityError(f"version must be {_ADOPTION_VERSION}")
        _require_task_context(
            self.task_id,
            self.task_generation,
            self.launch_nonce,
            self.policy_digest,
        )
        _require_listener_contract(self.evidence)

    def to_bytes(self) -> bytes:
        payload = {
            "version": self.version,
            "task_id": self.task_id,
            "task_generation": self.task_generation,
            "launch_nonce": self.launch_nonce,
            "policy_digest": self.policy_digest,
            "evidence": {
                "family": self.evidence.family,
                "socket_type": self.evidence.socket_type,
                "address": self.evidence.address,
                "port": self.evidence.port,
                "device": self.evidence.device,
                "inode": self.evidence.inode,
                "file_type": self.evidence.file_type,
                "netns_cookie": self.evidence.netns_cookie,
                "accepting": self.evidence.accepting,
            },
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
        if not 0 < len(encoded) <= _MAX_ADOPTION_FRAME:
            raise NetworkIdentityError("listener adoption frame is empty or oversized")
        return encoded

    @classmethod
    def from_bytes(cls, payload: bytes) -> ListenerAdoptionFrame:
        decoded = _require_exact_fields(
            _decode_json(payload, maximum=_MAX_ADOPTION_FRAME, label="listener adoption frame"),
            _FRAME_FIELDS,
            "listener adoption frame",
        )
        evidence_data = _require_exact_fields(
            decoded["evidence"], _EVIDENCE_FIELDS, "listener evidence"
        )
        try:
            evidence = ListenerEvidence(**evidence_data)
            frame = cls(
                version=decoded["version"],
                task_id=decoded["task_id"],
                task_generation=decoded["task_generation"],
                launch_nonce=decoded["launch_nonce"],
                policy_digest=decoded["policy_digest"],
                evidence=evidence,
            )
        except NetworkIdentityError:
            raise
        except (TypeError, ValueError) as exc:
            raise NetworkIdentityError("listener adoption fields are invalid") from exc
        if frame.to_bytes() != payload:
            raise NetworkIdentityError("listener adoption frame is not canonical")
        return frame


@dataclass(frozen=True)
class AdoptedListener:
    """Owned received listener descriptor and its authenticated identity."""

    fd: int
    frame: ListenerAdoptionFrame
    evidence: ListenerEvidence

    def __post_init__(self) -> None:
        if type(self.fd) is not int or self.fd < 0:
            raise NetworkIdentityError("adopted listener fd is invalid")
        if type(self.frame) is not ListenerAdoptionFrame:
            raise NetworkIdentityError("adopted listener frame is invalid")
        if type(self.evidence) is not ListenerEvidence:
            raise NetworkIdentityError("adopted listener evidence is invalid")


def _attempt_cleanup(*actions: Callable[[], None]) -> BaseException | None:
    first_error: BaseException | None = None
    for action in actions:
        try:
            action()
        except BaseException as exc:
            if first_error is None:
                first_error = exc
    return first_error


def _remove_active_channel_claim(
    key: tuple[int, int, int, str], anchor_fd: int
) -> None:
    with _ACTIVE_CHANNEL_CLAIMS_LOCK:
        if _ACTIVE_CHANNEL_CLAIMS.get(key) == anchor_fd:
            del _ACTIVE_CHANNEL_CLAIMS[key]


@dataclass
class _PinnedChannel:
    socket: socket.socket
    device: int
    inode: int
    file_type: int
    closed: bool = False

    @property
    def identity(self) -> tuple[int, int, int]:
        return (self.device, self.inode, self.file_type)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.socket.close()


@dataclass
class _ChannelClaim:
    key: tuple[int, int, int, str]
    anchor_fd: int
    released: bool = False

    def release(self) -> None:
        if self.released:
            return
        self.released = True
        cleanup_error = _attempt_cleanup(
            lambda: _remove_active_channel_claim(self.key, self.anchor_fd),
            lambda: os.close(self.anchor_fd),
        )
        if cleanup_error is not None:
            raise cleanup_error


def _channel_stat_identity(status: os.stat_result) -> tuple[int, int, int]:
    return (status.st_dev, status.st_ino, stat.S_IFMT(status.st_mode))


def _require_seqpacket_channel(channel: socket.socket) -> None:
    try:
        if not isinstance(channel, socket.socket):
            raise NetworkIdentityError("adoption channel must be a socket")
        channel_domain = channel.getsockopt(socket.SOL_SOCKET, _SO_DOMAIN)
        channel_type = channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        channel_stat = os.fstat(channel.fileno())
        channel.getpeername()
        if (
            channel.family != socket.AF_UNIX
            or channel_domain != socket.AF_UNIX
            or channel_type != socket.SOCK_SEQPACKET
            or stat.S_IFMT(channel_stat.st_mode) != stat.S_IFSOCK
            or channel_stat.st_dev <= 0
            or channel_stat.st_ino <= 0
            or not fcntl.fcntl(channel.fileno(), fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        ):
            raise NetworkIdentityError("adoption channel must be exact AF_UNIX SOCK_SEQPACKET")
    except NetworkIdentityError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise NetworkIdentityError("adoption channel identity could not be established") from exc


def _pin_channel(channel: socket.socket) -> _PinnedChannel:
    if not isinstance(channel, socket.socket):
        raise NetworkIdentityError("adoption channel must be a socket")
    caller_fd = channel.fileno()
    _require_cloexec_fd(caller_fd, "adoption channel descriptor")
    duplicate: int | None = None
    pinned_socket: socket.socket | None = None
    completed = False
    try:
        before = os.fstat(caller_fd)
        duplicate = _duplicate_cloexec(caller_fd)
        caller_after_duplicate = os.fstat(caller_fd)
        duplicate_before_validation = os.fstat(duplicate)
        identity = _channel_stat_identity(before)
        if (
            _channel_stat_identity(caller_after_duplicate) != identity
            or _channel_stat_identity(duplicate_before_validation) != identity
        ):
            raise NetworkIdentityError("adoption channel changed while being pinned")
        pinned_socket = socket.socket(fileno=duplicate)
        duplicate = None
        _require_seqpacket_channel(pinned_socket)
        pinned_after_validation = os.fstat(pinned_socket.fileno())
        if _channel_stat_identity(pinned_after_validation) != identity:
            raise NetworkIdentityError("pinned adoption channel identity changed")
        result = _PinnedChannel(
            socket=pinned_socket,
            device=identity[0],
            inode=identity[1],
            file_type=identity[2],
        )
        completed = True
        return result
    except NetworkIdentityError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise NetworkIdentityError("adoption channel could not be securely pinned") from exc
    finally:
        cleanup_actions: list[Callable[[], None]] = []
        if duplicate is not None:
            cleanup_actions.append(lambda: os.close(duplicate))
        if pinned_socket is not None and not completed:
            cleanup_actions.append(pinned_socket.close)
        cleanup_error = _attempt_cleanup(*cleanup_actions)
        if sys.exception() is None and cleanup_error is not None:
            raise NetworkIdentityError("adoption channel pin cleanup failed") from cleanup_error


def _build_channel_claim(
    key: tuple[int, int, int, str], anchor_fd: int
) -> _ChannelClaim:
    return _ChannelClaim(key=key, anchor_fd=anchor_fd)


def _claim_channel(pinned: _PinnedChannel, direction: str) -> _ChannelClaim:
    anchor_fd = _duplicate_cloexec(pinned.socket.fileno())
    key = (*pinned.identity, direction)
    inserted = False
    try:
        if _channel_stat_identity(os.fstat(anchor_fd)) != pinned.identity:
            raise NetworkIdentityError("channel claim anchor changed identity")
        with _ACTIVE_CHANNEL_CLAIMS_LOCK:
            if key in _ACTIVE_CHANNEL_CLAIMS:
                raise NetworkIdentityError(f"channel {direction} side is already claimed")
            inserted = True
            _ACTIVE_CHANNEL_CLAIMS[key] = anchor_fd
        return _build_channel_claim(key, anchor_fd)
    except BaseException:
        cleanup_actions: list[Callable[[], None]] = []
        if inserted:
            cleanup_actions.append(lambda: _remove_active_channel_claim(key, anchor_fd))
        cleanup_actions.append(lambda: os.close(anchor_fd))
        _attempt_cleanup(*cleanup_actions)
        raise


def send_listener_fd(
    channel: socket.socket, fd: int, frame: ListenerAdoptionFrame
) -> None:
    """Atomically send exactly one authenticated listener FD, then seal writes."""
    if type(frame) is not ListenerAdoptionFrame:
        raise NetworkIdentityError("listener frame has the wrong type")
    _require_cloexec_fd(fd, "listener source descriptor")
    pinned_fd = _duplicate_cloexec(fd)
    pinned_channel: _PinnedChannel | None = None
    claim: _ChannelClaim | None = None
    write_side_closed = False
    try:
        if listener_evidence(pinned_fd) != frame.evidence:
            raise NetworkIdentityError("listener descriptor does not match its adoption frame")
        pinned_channel = _pin_channel(channel)
        claim = _claim_channel(pinned_channel, "send")
        payload = frame.to_bytes()
        rights = array.array("i", [pinned_fd]).tobytes()
        sent = pinned_channel.socket.sendmsg(
            [payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]
        )
        if sent != len(payload):
            raise NetworkIdentityError("listener adoption frame was not sent atomically")
        pinned_channel.socket.shutdown(socket.SHUT_WR)
        write_side_closed = True
    except NetworkIdentityError:
        raise
    except OSError as exc:
        raise NetworkIdentityError("listener adoption send failed") from exc
    finally:
        primary_error = sys.exception()
        cleanup_actions: list[Callable[[], None]] = []
        if claim is not None and not write_side_closed and pinned_channel is not None:
            cleanup_actions.append(
                lambda: pinned_channel.socket.shutdown(socket.SHUT_WR)
            )
        if claim is not None:
            cleanup_actions.append(claim.release)
        if pinned_channel is not None:
            cleanup_actions.append(pinned_channel.close)
        cleanup_actions.append(lambda: os.close(pinned_fd))
        cleanup_error = _attempt_cleanup(*cleanup_actions)
        if primary_error is None and cleanup_error is not None:
            raise NetworkIdentityError("listener adoption send cleanup failed") from cleanup_error


def _rights_fds(ancillary: list[tuple[int, int, bytes]]) -> list[int]:
    received: list[int] = []
    itemsize = array.array("i").itemsize
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            complete = len(data) - (len(data) % itemsize)
            if complete:
                values = array.array("i")
                values.frombytes(data[:complete])
                received.extend(values)
    return received


def _close_all(fds: list[int]) -> BaseException | None:
    owned_fds = set(fds)
    fds.clear()
    return _attempt_cleanup(*(lambda fd=fd: os.close(fd) for fd in owned_fds))


def _set_passcred(channel: socket.socket, value: int) -> None:
    channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, value)
    if channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != value:
        raise NetworkIdentityError("SO_PASSCRED state could not be established")


def _shutdown_and_drain_read_side(channel: socket.socket, *, strict: bool) -> None:
    previous_passcred: int | None = None
    try:
        previous_passcred = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED)
        _set_passcred(channel, 1)
        channel.shutdown(socket.SHUT_RD)
        ancillary_size = socket.CMSG_SPACE(_RIGHTS_BYTES) + socket.CMSG_SPACE(
            _CREDENTIAL_BYTES
        )
        while True:
            payload, ancillary, flags, _address = channel.recvmsg(
                _MAX_ADOPTION_FRAME + 1,
                ancillary_size,
                socket.MSG_CMSG_CLOEXEC | socket.MSG_DONTWAIT,
            )
            close_error = _close_all(_rights_fds(ancillary))
            if strict and close_error is not None:
                raise NetworkIdentityError(
                    "could not close a queued adoption descriptor"
                ) from close_error
            if not payload and not ancillary and not flags & socket.MSG_EOR:
                break
    except BlockingIOError:
        pass
    except (NetworkIdentityError, OSError) as exc:
        if strict:
            raise NetworkIdentityError("could not enforce one-shot adoption reads") from exc
    finally:
        if previous_passcred is not None:
            restore_error = _attempt_cleanup(
                lambda: _set_passcred(channel, previous_passcred)
            )
            if strict and sys.exception() is None and restore_error is not None:
                raise NetworkIdentityError(
                    "could not restore adoption channel record marking"
                ) from restore_error


def _require_clean_write_eof(channel: socket.socket) -> None:
    poller = select.poll()
    poller.register(
        channel.fileno(),
        select.POLLIN
        | select.POLLHUP
        | _POLL_READ_CLOSED
        | select.POLLERR
        | select.POLLNVAL,
    )
    deadline = time.monotonic() + _ADOPTION_EOF_TIMEOUT_SECONDS
    ancillary_size = socket.CMSG_SPACE(_RIGHTS_BYTES) + socket.CMSG_SPACE(
        _CREDENTIAL_BYTES
    )
    previous_passcred = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED)
    passcred_changed = False
    try:
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        passcred_changed = True
        if channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1:
            raise NetworkIdentityError("SO_PASSCRED state could not be established")
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NetworkIdentityError("listener adoption write EOF timed out")
            events = poller.poll(max(1, int(remaining * 1000)))
            if not events:
                raise NetworkIdentityError("listener adoption write EOF timed out")
            event_mask = 0
            for _fd, observed_mask in events:
                event_mask |= observed_mask
            if event_mask & (select.POLLERR | select.POLLNVAL):
                raise NetworkIdentityError(
                    "listener adoption channel reported a poll error"
                )
            try:
                payload, ancillary, flags, _address = channel.recvmsg(
                    _MAX_ADOPTION_FRAME + 1,
                    ancillary_size,
                    socket.MSG_CMSG_CLOEXEC | socket.MSG_DONTWAIT,
                )
            except BlockingIOError:
                continue
            close_error = _close_all(_rights_fds(ancillary))
            if close_error is not None:
                raise NetworkIdentityError(
                    "could not close an extra adoption descriptor"
                ) from close_error
            terminal = bool(event_mask & (_POLL_READ_CLOSED | select.POLLHUP))
            if payload or ancillary or flags & socket.MSG_EOR or not terminal:
                raise NetworkIdentityError(
                    "listener adoption contained an extra record before EOF"
                )
            return
    finally:
        if passcred_changed:
            restore_error = _attempt_cleanup(
                lambda: _set_passcred(channel, previous_passcred)
            )
            if sys.exception() is None and restore_error is not None:
                raise NetworkIdentityError(
                    "could not restore adoption channel record marking"
                ) from restore_error


def recv_listener_fd(
    channel: socket.socket,
    *,
    expected_task_id: str,
    expected_generation: int,
    expected_nonce: str,
    expected_policy_digest: str,
) -> AdoptedListener:
    """Receive and authenticate exactly one listener FD, then seal reads."""
    _require_task_context(
        expected_task_id,
        expected_generation,
        expected_nonce,
        expected_policy_digest,
    )
    pinned_channel: _PinnedChannel | None = None
    claim: _ChannelClaim | None = None
    received_fds: list[int] = []
    read_side_closed = False
    adopted: AdoptedListener | None = None
    try:
        pinned_channel = _pin_channel(channel)
        claim = _claim_channel(pinned_channel, "receive")
        payload, ancillary, flags, _address = pinned_channel.socket.recvmsg(
            _MAX_ADOPTION_FRAME + 1,
            socket.CMSG_SPACE(_RIGHTS_BYTES),
            socket.MSG_CMSG_CLOEXEC,
        )
        received_fds = _rights_fds(ancillary)
        if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise NetworkIdentityError("listener adoption message was truncated")
        if not payload or len(payload) > _MAX_ADOPTION_FRAME:
            raise NetworkIdentityError("listener adoption frame is empty or oversized")
        if len(ancillary) != 1:
            raise NetworkIdentityError("listener adoption has unknown ancillary records")
        level, kind, data = ancillary[0]
        if (
            level != socket.SOL_SOCKET
            or kind != socket.SCM_RIGHTS
            or len(data) != _RIGHTS_BYTES
            or len(received_fds) != 1
        ):
            raise NetworkIdentityError("listener adoption must carry exactly one descriptor")
        received_fd = received_fds[0]
        if not fcntl.fcntl(received_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
            raise NetworkIdentityError("received listener descriptor is not close-on-exec")

        frame = ListenerAdoptionFrame.from_bytes(payload)
        if (
            frame.task_id != expected_task_id
            or frame.task_generation != expected_generation
            or frame.launch_nonce != expected_nonce
            or frame.policy_digest != expected_policy_digest
        ):
            raise NetworkIdentityError("listener adoption context did not authenticate")
        evidence = listener_evidence(received_fd)
        if evidence != frame.evidence:
            raise NetworkIdentityError("received listener does not match its adoption frame")
        _require_clean_write_eof(pinned_channel.socket)
        _shutdown_and_drain_read_side(pinned_channel.socket, strict=True)
        read_side_closed = True
        adopted = AdoptedListener(fd=received_fd, frame=frame, evidence=evidence)
    except NetworkIdentityError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise NetworkIdentityError("listener adoption receive failed") from exc
    finally:
        primary_error = sys.exception()
        cleanup_actions: list[Callable[[], None]] = []
        if claim is not None and not read_side_closed and pinned_channel is not None:
            cleanup_actions.append(
                lambda: _shutdown_and_drain_read_side(
                    pinned_channel.socket, strict=False
                )
            )
        if claim is not None:
            cleanup_actions.append(claim.release)
        if pinned_channel is not None:
            cleanup_actions.append(pinned_channel.close)
        cleanup_error = _attempt_cleanup(*cleanup_actions)
        received_close_error: BaseException | None = None
        if primary_error is not None or cleanup_error is not None or adopted is None:
            received_close_error = _close_all(received_fds)
        if primary_error is None:
            finalization_error = cleanup_error or received_close_error
            if finalization_error is not None:
                raise NetworkIdentityError(
                    "listener adoption receive cleanup failed"
                ) from finalization_error
    if adopted is None:
        raise NetworkIdentityError("listener adoption did not produce a listener")
    received_fds.clear()
    return adopted


__all__ = [
    "AdoptedListener",
    "ListenerAdoptionFrame",
    "NetworkIdentityError",
    "VerifiedSealedPolicy",
    "create_sealed_policy_fd",
    "listener_evidence",
    "read_sealed_policy_fd",
    "recv_listener_fd",
    "send_listener_fd",
]
