"""Least-authority M4B-1 broker core.

The production entry point consumes only a bounded argv contract and fixed
inherited descriptors.  It does not consult ambient configuration or create an
upstream connection.  M4B-1 can relay bytes only through an already-connected
synthetic fixture descriptor.
"""

from __future__ import annotations

import array
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import socket
import stat
import struct
import sys
import time
from typing import Any, NoReturn

from .network_identity import (
    NetworkIdentityError,
    VerifiedSealedPolicy,
    listener_evidence,
    read_sealed_policy_fd,
    recv_listener_fd,
)
from .network_models import (
    BrokerProcessEvidence,
    BrokerReadyEvidence,
    ListenerEvidence,
    TransportMode,
    TransportPolicy,
)


BROKER_CONTRACT_VERSION = "AOSBROKER/1"
READY_VERSION = "AOSBROKERREADY/1"
READY_EVENT = "NETWORK_BROKER_READY"
CONTROL_REVOKE = b"AOSBROKERCTL/1 REVOKE\n"

BROKER_POLICY_FD = 30
BROKER_HANDOFF_FD = 31
BROKER_STATUS_FD = 32
BROKER_CONTROL_FD = 33
BROKER_FIXTURE_FD = 34

BROKER_ROOT = "/opt/agenticos/python"
RUNTIME_PATH = "/usr"
BROKER_CODE_PATH = (
    "/opt/agenticos/python/agenticos/sandbox/network_broker.py"
)
IDENTITY_CODE_PATH = (
    "/opt/agenticos/python/agenticos/sandbox/network_identity.py"
)
MODELS_CODE_PATH = (
    "/opt/agenticos/python/agenticos/sandbox/network_models.py"
)
INTERPRETER_PATH = "/usr/bin/python3"

BROKER_ENVIRONMENT = (
    ("HOME", "/home/broker"),
    ("PATH", "/usr/bin:/bin"),
    ("LANG", "C.UTF-8"),
    ("LC_ALL", "C.UTF-8"),
    ("TMPDIR", "/tmp"),
    ("PWD", BROKER_ROOT),
    ("PYTHONDONTWRITEBYTECODE", "1"),
)

MAX_CONTRACT_ITEMS = 64
MAX_CONTRACT_ITEM_BYTES = 256
MAX_READY_BYTES = 8192
MAX_CONTROL_BYTES = 64
RELAY_CHUNK_BYTES = 16 * 1024
RELAY_BUFFER_BYTES = 32 * 1024
SELECTOR_SLICE_SECONDS = 0.1
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39
_SO_DOMAIN = getattr(socket, "SO_DOMAIN", 39)
_MAX_UNSIGNED_64 = (1 << 64) - 1
_HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
_BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_NAMESPACE_RE = re.compile(r"[a-z]+:\[([1-9][0-9]*)\]\Z")
_STATUS_CAP_FIELDS = {
    "CapInh": "cap_inheritable",
    "CapPrm": "cap_permitted",
    "CapEff": "cap_effective",
    "CapBnd": "cap_bounding",
    "CapAmb": "cap_ambient",
}
_NAMESPACE_NAMES = ("ipc", "mnt", "net", "pid", "user", "uts")


class BrokerBoundaryError(RuntimeError):
    """The broker could not prove its fixed least-authority boundary."""


class TransportTermination(str, Enum):
    COMPLETED = "COMPLETED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    CONTROL_EOF = "CONTROL_EOF"
    MALFORMED_CONTROL = "MALFORMED_CONTROL"
    BYTE_LIMIT = "BYTE_LIMIT"
    CONNECTION_LIMIT = "CONNECTION_LIMIT"
    PEER_ERROR = "PEER_ERROR"


def _positive_u64(name: str, value: object) -> int:
    if type(value) is not int or not 0 < value <= _MAX_UNSIGNED_64:
        raise BrokerBoundaryError(
            f"{name} must be a positive unsigned 64-bit integer"
        )
    return value


def _nonnegative_u64(name: str, value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_UNSIGNED_64:
        raise BrokerBoundaryError(
            f"{name} must be a non-negative unsigned 64-bit integer"
        )
    return value


def _lower_hex_digest(name: str, value: object) -> str:
    if type(value) is not str or not _HEX_64_RE.fullmatch(value):
        raise BrokerBoundaryError(f"{name} must be lowercase SHA-256 hexadecimal")
    return value


@dataclass(frozen=True)
class ObservedFileIdentity:
    device: int
    inode: int
    file_type: int

    def __post_init__(self) -> None:
        _positive_u64("identity device", self.device)
        _positive_u64("identity inode", self.inode)
        _positive_u64("identity file type", self.file_type)

    @classmethod
    def from_stat(cls, observed: os.stat_result) -> ObservedFileIdentity:
        return cls(
            device=int(observed.st_dev),
            inode=int(observed.st_ino),
            file_type=stat.S_IFMT(observed.st_mode),
        )


@dataclass(frozen=True)
class _SocketDescriptorSnapshot:
    domain: int
    socket_type: int
    accepting: int
    local_name: object
    peer_name: object | None
    peer_errno: int | None


@dataclass(frozen=True)
class _DescriptorSnapshot:
    fd: int
    device: int
    inode: int
    file_type: int
    rdevice: int
    descriptor_flags: int
    status_flags: int
    socket: _SocketDescriptorSnapshot | None

    @property
    def kernel_identity(self) -> tuple[int, int, int, int]:
        return (self.device, self.inode, self.file_type, self.rdevice)


@dataclass(frozen=True)
class ProcStatusEvidence:
    cap_inheritable: int
    cap_permitted: int
    cap_effective: int
    cap_bounding: int
    cap_ambient: int
    no_new_privs: int

    def __post_init__(self) -> None:
        for name in (
            "cap_inheritable",
            "cap_permitted",
            "cap_effective",
            "cap_bounding",
            "cap_ambient",
        ):
            _nonnegative_u64(name, getattr(self, name))
        if type(self.no_new_privs) is not int or self.no_new_privs not in (0, 1):
            raise BrokerBoundaryError("NoNewPrivs must be exactly zero or one")


@dataclass(frozen=True)
class EnvironmentEvidence:
    names: tuple[str, ...]
    digest: str

    def __post_init__(self) -> None:
        if (
            type(self.names) is not tuple
            or any(type(name) is not str for name in self.names)
            or len(self.names) != len(set(self.names))
        ):
            raise BrokerBoundaryError("environment names must be a unique tuple")
        _lower_hex_digest("environment digest", self.digest)


@dataclass(frozen=True)
class SealedPolicyEvidence:
    device: int
    inode: int
    size: int
    seals: int

    def __post_init__(self) -> None:
        _positive_u64("sealed policy device", self.device)
        _positive_u64("sealed policy inode", self.inode)
        _positive_u64("sealed policy size", self.size)
        _positive_u64("sealed policy seals", self.seals)


@dataclass(frozen=True)
class BrokerBoundaryEvidence:
    proc_status: ProcStatusEvidence
    environment: EnvironmentEvidence
    filesystem_digest: str
    fd_numbers: tuple[int, ...]
    cgroup: str
    namespaces: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        if type(self.proc_status) is not ProcStatusEvidence:
            raise BrokerBoundaryError("proc status evidence has the wrong type")
        if type(self.environment) is not EnvironmentEvidence:
            raise BrokerBoundaryError("environment evidence has the wrong type")
        _lower_hex_digest("filesystem digest", self.filesystem_digest)
        if (
            type(self.fd_numbers) is not tuple
            or any(type(fd) is not int or fd < 0 for fd in self.fd_numbers)
            or tuple(sorted(self.fd_numbers)) != self.fd_numbers
            or len(set(self.fd_numbers)) != len(self.fd_numbers)
        ):
            raise BrokerBoundaryError(
                "descriptor evidence must be a sorted unique tuple"
            )
        if (
            type(self.cgroup) is not str
            or not self.cgroup.startswith("/")
            or "\n" in self.cgroup
            or len(self.cgroup.encode("utf-8")) > 4096
        ):
            raise BrokerBoundaryError("cgroup evidence is invalid")
        if (
            type(self.namespaces) is not tuple
            or tuple(name for name, _inode in self.namespaces)
            != _NAMESPACE_NAMES
        ):
            raise BrokerBoundaryError("namespace evidence is incomplete or unordered")
        for name, inode in self.namespaces:
            if type(name) is not str:
                raise BrokerBoundaryError("namespace name has the wrong type")
            _positive_u64(f"{name} namespace inode", inode)


@dataclass(frozen=True)
class BrokerContract:
    version: str
    policy_fd: int
    handoff_fd: int
    status_fd: int
    control_fd: int
    fixture_fd: int | None
    runtime_identity: ObservedFileIdentity
    broker_code_identity: ObservedFileIdentity
    identity_code_identity: ObservedFileIdentity
    models_code_identity: ObservedFileIdentity

    def __post_init__(self) -> None:
        if type(self.version) is not str or self.version != BROKER_CONTRACT_VERSION:
            raise BrokerBoundaryError(
                f"broker contract version must be {BROKER_CONTRACT_VERSION}"
            )
        expected = (
            ("policy_fd", self.policy_fd, BROKER_POLICY_FD),
            ("handoff_fd", self.handoff_fd, BROKER_HANDOFF_FD),
            ("status_fd", self.status_fd, BROKER_STATUS_FD),
            ("control_fd", self.control_fd, BROKER_CONTROL_FD),
        )
        for name, value, fixed in expected:
            if type(value) is not int or value != fixed:
                raise BrokerBoundaryError(f"{name} must be fixed descriptor {fixed}")
        if self.fixture_fd is not None and (
            type(self.fixture_fd) is not int or self.fixture_fd != BROKER_FIXTURE_FD
        ):
            raise BrokerBoundaryError(
                f"fixture_fd must be absent or fixed descriptor {BROKER_FIXTURE_FD}"
            )
        if len(set(self.capability_fds)) != len(self.capability_fds):
            raise BrokerBoundaryError("broker capability descriptor roles collide")
        identities = (
            self.runtime_identity,
            self.broker_code_identity,
            self.identity_code_identity,
            self.models_code_identity,
        )
        if any(type(identity) is not ObservedFileIdentity for identity in identities):
            raise BrokerBoundaryError("broker source identity has the wrong type")
        if len(
            {
                (identity.device, identity.inode, identity.file_type)
                for identity in identities
            }
        ) != len(identities):
            raise BrokerBoundaryError("broker source identities collide")

    @property
    def capability_fds(self) -> tuple[int, ...]:
        values = (
            self.policy_fd,
            self.handoff_fd,
            self.status_fd,
            self.control_fd,
        )
        return values if self.fixture_fd is None else (*values, self.fixture_fd)

    def to_argv(self) -> tuple[str, ...]:
        result = [
            self.version,
            "policy_fd",
            str(self.policy_fd),
            "handoff_fd",
            str(self.handoff_fd),
            "status_fd",
            str(self.status_fd),
            "control_fd",
            str(self.control_fd),
            "fixture_fd",
            "none" if self.fixture_fd is None else str(self.fixture_fd),
        ]
        for role, identity in (
            ("runtime_identity", self.runtime_identity),
            ("broker_code_identity", self.broker_code_identity),
            ("identity_code_identity", self.identity_code_identity),
            ("models_code_identity", self.models_code_identity),
        ):
            result.extend(
                (
                    role,
                    str(identity.device),
                    str(identity.inode),
                    str(identity.file_type),
                )
            )
        result.append("END")
        return tuple(result)

    @classmethod
    def from_argv(cls, argv: Sequence[str]) -> BrokerContract:
        if type(argv) not in (tuple, list):
            raise BrokerBoundaryError("broker argv must be an exact sequence")
        values = list(argv)
        if (
            not 1 <= len(values) <= MAX_CONTRACT_ITEMS
            or any(
                type(item) is not str
                or not 0 < len(item.encode("utf-8")) <= MAX_CONTRACT_ITEM_BYTES
                or "\x00" in item
                or "\n" in item
                or "\r" in item
                for item in values
            )
        ):
            raise BrokerBoundaryError("broker argv is empty, oversized, or malformed")
        cursor = 0

        def take(expected: str) -> None:
            nonlocal cursor
            if cursor >= len(values) or values[cursor] != expected:
                raise BrokerBoundaryError(f"expected broker contract token {expected!r}")
            cursor += 1

        def decimal(name: str) -> int:
            nonlocal cursor
            if cursor >= len(values):
                raise BrokerBoundaryError(f"{name} value is missing")
            text = values[cursor]
            cursor += 1
            if not re.fullmatch(r"[1-9][0-9]*", text):
                raise BrokerBoundaryError(f"{name} is not canonical decimal")
            value = int(text)
            return _positive_u64(name, value)

        take(BROKER_CONTRACT_VERSION)
        take("policy_fd")
        policy_fd = decimal("policy_fd")
        take("handoff_fd")
        handoff_fd = decimal("handoff_fd")
        take("status_fd")
        status_fd = decimal("status_fd")
        take("control_fd")
        control_fd = decimal("control_fd")
        take("fixture_fd")
        if cursor >= len(values):
            raise BrokerBoundaryError("fixture_fd value is missing")
        fixture_text = values[cursor]
        cursor += 1
        fixture_fd = None if fixture_text == "none" else _canonical_decimal(
            "fixture_fd", fixture_text
        )

        def identity(role: str) -> ObservedFileIdentity:
            take(role)
            return ObservedFileIdentity(
                decimal(f"{role} device"),
                decimal(f"{role} inode"),
                decimal(f"{role} file_type"),
            )

        runtime_identity = identity("runtime_identity")
        broker_code_identity = identity("broker_code_identity")
        identity_code_identity = identity("identity_code_identity")
        models_code_identity = identity("models_code_identity")
        take("END")
        if cursor != len(values):
            raise BrokerBoundaryError("broker contract has trailing arguments")
        return cls(
            version=BROKER_CONTRACT_VERSION,
            policy_fd=policy_fd,
            handoff_fd=handoff_fd,
            status_fd=status_fd,
            control_fd=control_fd,
            fixture_fd=fixture_fd,
            runtime_identity=runtime_identity,
            broker_code_identity=broker_code_identity,
            identity_code_identity=identity_code_identity,
            models_code_identity=models_code_identity,
        )


def _canonical_decimal(name: str, text: object) -> int:
    if type(text) is not str or not re.fullmatch(r"[1-9][0-9]*", text):
        raise BrokerBoundaryError(f"{name} is not canonical decimal")
    return _positive_u64(name, int(text))


def _identity_dict(identity: ObservedFileIdentity) -> dict[str, int]:
    return {
        "device": identity.device,
        "file_type": identity.file_type,
        "inode": identity.inode,
    }


def _identity_from_dict(value: object, label: str) -> ObservedFileIdentity:
    decoded = _exact_dict(value, {"device", "inode", "file_type"}, label)
    try:
        return ObservedFileIdentity(
            device=decoded["device"],
            inode=decoded["inode"],
            file_type=decoded["file_type"],
        )
    except (TypeError, ValueError, BrokerBoundaryError) as exc:
        raise BrokerBoundaryError(f"{label} fields are invalid") from exc


def _listener_dict(evidence: ListenerEvidence) -> dict[str, object]:
    return {
        "accepting": evidence.accepting,
        "address": evidence.address,
        "device": evidence.device,
        "family": evidence.family,
        "file_type": evidence.file_type,
        "inode": evidence.inode,
        "netns_cookie": evidence.netns_cookie,
        "port": evidence.port,
        "socket_type": evidence.socket_type,
    }


def _listener_from_dict(value: object) -> ListenerEvidence:
    decoded = _exact_dict(
        value,
        {
            "family",
            "socket_type",
            "address",
            "port",
            "device",
            "inode",
            "file_type",
            "netns_cookie",
            "accepting",
        },
        "listener evidence",
    )
    try:
        return ListenerEvidence(**decoded)
    except (TypeError, ValueError) as exc:
        raise BrokerBoundaryError("listener evidence fields are invalid") from exc


def _process_dict(process: BrokerProcessEvidence) -> dict[str, object]:
    return {
        "boot_id": process.boot_id,
        "pid": process.pid,
        "start_time_ticks": process.start_time_ticks,
    }


def _process_from_dict(value: object) -> BrokerProcessEvidence:
    decoded = _exact_dict(
        value, {"pid", "start_time_ticks", "boot_id"}, "process evidence"
    )
    try:
        return BrokerProcessEvidence(**decoded)
    except (TypeError, ValueError) as exc:
        raise BrokerBoundaryError("process evidence fields are invalid") from exc


def _ready_dict(ready: BrokerReadyEvidence) -> dict[str, object]:
    return {
        "broker_boot_id": ready.broker_boot_id,
        "broker_pid": ready.broker_pid,
        "broker_start_time_ticks": ready.broker_start_time_ticks,
        "launch_nonce": ready.launch_nonce,
        "policy_digest": ready.policy_digest,
        "ready_at_monotonic_ns": ready.ready_at_monotonic_ns,
        "task_generation": ready.task_generation,
        "task_id": ready.task_id,
    }


def _ready_from_dict(value: object) -> BrokerReadyEvidence:
    decoded = _exact_dict(
        value,
        {
            "task_id",
            "task_generation",
            "launch_nonce",
            "policy_digest",
            "broker_pid",
            "broker_start_time_ticks",
            "broker_boot_id",
            "ready_at_monotonic_ns",
        },
        "ready evidence",
    )
    try:
        return BrokerReadyEvidence(**decoded)
    except (TypeError, ValueError) as exc:
        raise BrokerBoundaryError("ready evidence fields are invalid") from exc


@dataclass(frozen=True)
class NetworkBrokerReadyRecord:
    version: str
    event: str
    ready: BrokerReadyEvidence
    process: BrokerProcessEvidence
    listener: ListenerEvidence
    sealed_policy: SealedPolicyEvidence
    runtime_identity: ObservedFileIdentity
    broker_code_identity: ObservedFileIdentity
    identity_code_identity: ObservedFileIdentity
    models_code_identity: ObservedFileIdentity
    interpreter_identity: ObservedFileIdentity
    boundary: BrokerBoundaryEvidence

    def __post_init__(self) -> None:
        if type(self.version) is not str or self.version != READY_VERSION:
            raise BrokerBoundaryError(f"ready version must be {READY_VERSION}")
        if type(self.event) is not str or self.event != READY_EVENT:
            raise BrokerBoundaryError(f"ready event must be {READY_EVENT}")
        if type(self.ready) is not BrokerReadyEvidence:
            raise BrokerBoundaryError("ready evidence has the wrong type")
        if type(self.process) is not BrokerProcessEvidence:
            raise BrokerBoundaryError("process evidence has the wrong type")
        if type(self.listener) is not ListenerEvidence:
            raise BrokerBoundaryError("listener evidence has the wrong type")
        if (
            self.listener.family != int(socket.AF_INET)
            or self.listener.socket_type != int(socket.SOCK_STREAM)
            or self.listener.address != "127.0.0.1"
            or self.listener.port != 18080
            or self.listener.file_type != stat.S_IFSOCK
            or not self.listener.accepting
        ):
            raise BrokerBoundaryError("ready listener evidence is not fixed")
        if type(self.sealed_policy) is not SealedPolicyEvidence:
            raise BrokerBoundaryError("sealed policy evidence has the wrong type")
        for identity in (
            self.runtime_identity,
            self.broker_code_identity,
            self.identity_code_identity,
            self.models_code_identity,
            self.interpreter_identity,
        ):
            if type(identity) is not ObservedFileIdentity:
                raise BrokerBoundaryError("ready identity evidence has the wrong type")
        if type(self.boundary) is not BrokerBoundaryEvidence:
            raise BrokerBoundaryError("boundary evidence has the wrong type")
        if (
            self.ready.broker_pid != self.process.pid
            or self.ready.broker_start_time_ticks != self.process.start_time_ticks
            or self.ready.broker_boot_id != self.process.boot_id
        ):
            raise BrokerBoundaryError("ready and process identities do not match")

    def to_bytes(self) -> bytes:
        payload = {
            "boundary": {
                "cgroup": self.boundary.cgroup,
                "environment": {
                    "digest": self.boundary.environment.digest,
                    "names": list(self.boundary.environment.names),
                },
                "fd_numbers": list(self.boundary.fd_numbers),
                "filesystem_digest": self.boundary.filesystem_digest,
                "namespaces": {
                    name: inode for name, inode in self.boundary.namespaces
                },
                "proc_status": {
                    "cap_ambient": self.boundary.proc_status.cap_ambient,
                    "cap_bounding": self.boundary.proc_status.cap_bounding,
                    "cap_effective": self.boundary.proc_status.cap_effective,
                    "cap_inheritable": self.boundary.proc_status.cap_inheritable,
                    "cap_permitted": self.boundary.proc_status.cap_permitted,
                    "no_new_privs": self.boundary.proc_status.no_new_privs,
                },
            },
            "broker_code_identity": _identity_dict(self.broker_code_identity),
            "event": self.event,
            "identity_code_identity": _identity_dict(self.identity_code_identity),
            "interpreter_identity": _identity_dict(self.interpreter_identity),
            "listener": _listener_dict(self.listener),
            "models_code_identity": _identity_dict(self.models_code_identity),
            "process": _process_dict(self.process),
            "ready": _ready_dict(self.ready),
            "runtime_identity": _identity_dict(self.runtime_identity),
            "sealed_policy": {
                "device": self.sealed_policy.device,
                "inode": self.sealed_policy.inode,
                "seals": self.sealed_policy.seals,
                "size": self.sealed_policy.size,
            },
            "version": self.version,
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        if not 0 < len(encoded) <= MAX_READY_BYTES:
            raise BrokerBoundaryError("ready record is empty or oversized")
        return encoded

    @classmethod
    def from_bytes(cls, payload: bytes) -> NetworkBrokerReadyRecord:
        decoded = _decode_json(payload, MAX_READY_BYTES, "ready record")
        decoded = _exact_dict(
            decoded,
            {
                "version",
                "event",
                "ready",
                "process",
                "listener",
                "sealed_policy",
                "runtime_identity",
                "broker_code_identity",
                "identity_code_identity",
                "models_code_identity",
                "interpreter_identity",
                "boundary",
            },
            "ready record",
        )
        sealed_data = _exact_dict(
            decoded["sealed_policy"],
            {"device", "inode", "size", "seals"},
            "sealed policy evidence",
        )
        boundary_data = _exact_dict(
            decoded["boundary"],
            {
                "proc_status",
                "environment",
                "filesystem_digest",
                "fd_numbers",
                "cgroup",
                "namespaces",
            },
            "boundary evidence",
        )
        proc_data = _exact_dict(
            boundary_data["proc_status"],
            {
                "cap_inheritable",
                "cap_permitted",
                "cap_effective",
                "cap_bounding",
                "cap_ambient",
                "no_new_privs",
            },
            "proc status evidence",
        )
        environment_data = _exact_dict(
            boundary_data["environment"],
            {"names", "digest"},
            "environment evidence",
        )
        namespace_data = _exact_dict(
            boundary_data["namespaces"],
            set(_NAMESPACE_NAMES),
            "namespace evidence",
        )
        try:
            record = cls(
                version=decoded["version"],
                event=decoded["event"],
                ready=_ready_from_dict(decoded["ready"]),
                process=_process_from_dict(decoded["process"]),
                listener=_listener_from_dict(decoded["listener"]),
                sealed_policy=SealedPolicyEvidence(**sealed_data),
                runtime_identity=_identity_from_dict(
                    decoded["runtime_identity"], "runtime identity"
                ),
                broker_code_identity=_identity_from_dict(
                    decoded["broker_code_identity"], "broker code identity"
                ),
                identity_code_identity=_identity_from_dict(
                    decoded["identity_code_identity"], "identity code identity"
                ),
                models_code_identity=_identity_from_dict(
                    decoded["models_code_identity"], "models code identity"
                ),
                interpreter_identity=_identity_from_dict(
                    decoded["interpreter_identity"], "interpreter identity"
                ),
                boundary=BrokerBoundaryEvidence(
                    proc_status=ProcStatusEvidence(**proc_data),
                    environment=EnvironmentEvidence(
                        names=_string_tuple(
                            environment_data["names"], "environment names"
                        ),
                        digest=environment_data["digest"],
                    ),
                    filesystem_digest=boundary_data["filesystem_digest"],
                    fd_numbers=_integer_tuple(
                        boundary_data["fd_numbers"], "descriptor evidence"
                    ),
                    cgroup=boundary_data["cgroup"],
                    namespaces=tuple(
                        (name, namespace_data[name]) for name in _NAMESPACE_NAMES
                    ),
                ),
            )
        except BrokerBoundaryError:
            raise
        except (TypeError, ValueError) as exc:
            raise BrokerBoundaryError("ready record fields are invalid") from exc
        if record.to_bytes() != payload:
            raise BrokerBoundaryError("ready record encoding is not canonical")
        return record


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise BrokerBoundaryError(f"{label} must be a string array")
    return tuple(value)


def _integer_tuple(value: object, label: str) -> tuple[int, ...]:
    if type(value) is not list or any(type(item) is not int for item in value):
        raise BrokerBoundaryError(f"{label} must be an integer array")
    return tuple(value)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BrokerBoundaryError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise BrokerBoundaryError(f"non-finite JSON constant is forbidden: {value}")


def _decode_json(payload: bytes, maximum: int, label: str) -> dict[str, Any]:
    if type(payload) is not bytes or not 0 < len(payload) <= maximum:
        raise BrokerBoundaryError(f"{label} is empty or oversized")
    try:
        decoded = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except BrokerBoundaryError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise BrokerBoundaryError(f"{label} is not strict ASCII JSON") from exc
    if type(decoded) is not dict:
        raise BrokerBoundaryError(f"{label} must be a JSON object")
    return decoded


def _exact_dict(
    value: object, expected_fields: set[str], label: str
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected_fields:
        raise BrokerBoundaryError(f"{label} has missing or unknown fields")
    return value


def parse_proc_status(payload: str) -> ProcStatusEvidence:
    """Strictly parse the Linux capability and no-new-privileges fields."""
    if type(payload) is not str or len(payload.encode("utf-8")) > 1024 * 1024:
        raise BrokerBoundaryError("/proc status text is invalid or oversized")
    found: dict[str, int] = {}
    required = {*_STATUS_CAP_FIELDS, "NoNewPrivs"}
    for raw_line in payload.splitlines():
        if ":" not in raw_line:
            continue
        name, raw_value = raw_line.split(":", 1)
        if name not in required:
            continue
        if name in found:
            raise BrokerBoundaryError(f"duplicate /proc status field {name}")
        value = raw_value.strip()
        if name in _STATUS_CAP_FIELDS:
            if not re.fullmatch(r"[0-9a-f]{16}", value):
                raise BrokerBoundaryError(
                    f"/proc status capability field {name} is noncanonical"
                )
            found[name] = int(value, 16)
        else:
            if value not in {"0", "1"}:
                raise BrokerBoundaryError("NoNewPrivs is noncanonical")
            found[name] = int(value)
    if set(found) != required:
        raise BrokerBoundaryError("/proc status is missing required security fields")
    return ProcStatusEvidence(
        cap_inheritable=found["CapInh"],
        cap_permitted=found["CapPrm"],
        cap_effective=found["CapEff"],
        cap_bounding=found["CapBnd"],
        cap_ambient=found["CapAmb"],
        no_new_privs=found["NoNewPrivs"],
    )


def require_minimal_proc_status(evidence: ProcStatusEvidence) -> None:
    if type(evidence) is not ProcStatusEvidence:
        raise BrokerBoundaryError("proc status evidence has the wrong type")
    if any(
        (
            evidence.cap_inheritable,
            evidence.cap_permitted,
            evidence.cap_effective,
            evidence.cap_bounding,
            evidence.cap_ambient,
        )
    ):
        raise BrokerBoundaryError("broker Linux capability sets are not all zero")
    if evidence.no_new_privs != 1:
        raise BrokerBoundaryError("broker NoNewPrivs is not one")


def _require_zero_capabilities(evidence: ProcStatusEvidence) -> None:
    if any(
        (
            evidence.cap_inheritable,
            evidence.cap_permitted,
            evidence.cap_effective,
            evidence.cap_bounding,
            evidence.cap_ambient,
        )
    ):
        raise BrokerBoundaryError("broker Linux capability sets are not all zero")


def _read_proc_status(proc_root: Path = Path("/proc")) -> ProcStatusEvidence:
    try:
        payload = (proc_root / "self" / "status").read_text(
            encoding="ascii", errors="strict"
        )
    except (OSError, UnicodeError) as exc:
        raise BrokerBoundaryError("broker /proc/self/status is unavailable") from exc
    return parse_proc_status(payload)


def _snapshot_socket_descriptor(fd: int) -> _SocketDescriptorSnapshot:
    duplicate = _duplicate_cloexec(fd)
    observed: socket.socket | None = None
    try:
        observed = socket.socket(fileno=duplicate)
        duplicate = -1
        domain = observed.getsockopt(socket.SOL_SOCKET, _SO_DOMAIN)
        socket_type = observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        accepting = observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        local_name = observed.getsockname()
        try:
            peer_name: object | None = observed.getpeername()
            peer_errno: int | None = None
        except OSError as exc:
            peer_name = None
            peer_errno = exc.errno
        return _SocketDescriptorSnapshot(
            domain=domain,
            socket_type=socket_type,
            accepting=accepting,
            local_name=local_name,
            peer_name=peer_name,
            peer_errno=peer_errno,
        )
    except OSError as exc:
        raise BrokerBoundaryError(
            f"fixed descriptor {fd} socket evidence is unavailable"
        ) from exc
    finally:
        try:
            if observed is not None:
                observed.close()
            elif duplicate >= 0:
                os.close(duplicate)
        except OSError as exc:
            raise BrokerBoundaryError(
                f"fixed descriptor {fd} snapshot cleanup failed"
            ) from exc


def _snapshot_descriptor(fd: int) -> _DescriptorSnapshot:
    try:
        descriptor_flags = fcntl.fcntl(fd, fcntl.F_GETFD)
        status_flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        observed = os.fstat(fd)
    except OSError as exc:
        raise BrokerBoundaryError(
            f"fixed descriptor {fd} is unavailable"
        ) from exc
    file_type = stat.S_IFMT(observed.st_mode)
    return _DescriptorSnapshot(
        fd=fd,
        device=int(observed.st_dev),
        inode=int(observed.st_ino),
        file_type=file_type,
        rdevice=int(observed.st_rdev),
        descriptor_flags=descriptor_flags,
        status_flags=status_flags,
        socket=(
            _snapshot_socket_descriptor(fd)
            if file_type == stat.S_IFSOCK
            else None
        ),
    )


def _snapshot_fixed_descriptors(
    expected_fd_numbers: tuple[int, ...],
) -> tuple[_DescriptorSnapshot, ...]:
    return tuple(_snapshot_descriptor(fd) for fd in expected_fd_numbers)


def _require_unchanged_fixed_descriptors(
    expected: tuple[_DescriptorSnapshot, ...],
) -> None:
    try:
        observed = _snapshot_fixed_descriptors(tuple(item.fd for item in expected))
    except BrokerBoundaryError as exc:
        raise BrokerBoundaryError(
            "fixed descriptor disappeared during trusted import"
        ) from exc
    if observed != expected:
        raise BrokerBoundaryError(
            "fixed descriptor identity or flags changed during trusted import"
        )


def _establish_no_new_privs(
    expected_fd_numbers: tuple[int, ...],
    runtime_identity: ObservedFileIdentity,
) -> ProcStatusEvidence:
    if (
        type(expected_fd_numbers) is not tuple
        or tuple(sorted(expected_fd_numbers)) != expected_fd_numbers
        or len(set(expected_fd_numbers)) != len(expected_fd_numbers)
        or any(type(fd) is not int or fd < 0 for fd in expected_fd_numbers)
    ):
        raise BrokerBoundaryError("pre-import descriptor evidence is invalid")
    if type(runtime_identity) is not ObservedFileIdentity:
        raise BrokerBoundaryError("runtime identity has the wrong type")
    if _observe_fd_numbers() != expected_fd_numbers:
        raise BrokerBoundaryError("descriptor set changed before trusted import")

    fixed_snapshots = _snapshot_fixed_descriptors(expected_fd_numbers)
    before = _read_proc_status()
    _require_zero_capabilities(before)

    runtime_ctypes: Any = None
    import_error: BaseException | None = None
    try:
        import ctypes as runtime_ctypes
    except BaseException as exc:
        import_error = exc

    after_import = _observe_fd_numbers()
    expected_set = set(expected_fd_numbers)
    import_fds = tuple(fd for fd in after_import if fd not in expected_set)
    import_snapshots: dict[int, _DescriptorSnapshot] = {}
    operation_error: BaseException | None = None
    try:
        fixed_identities = {item.kernel_identity for item in fixed_snapshots}
        import_identities: set[tuple[int, int, int, int]] = set()
        rejected_status_flags = (
            getattr(os, "O_APPEND", 0)
            | getattr(os, "O_ASYNC", 0)
            | getattr(os, "O_DIRECT", 0)
            | getattr(os, "O_DSYNC", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_PATH", 0)
            | getattr(os, "O_SYNC", 0)
        )
        for fd in import_fds:
            snapshot = _snapshot_descriptor(fd)
            import_snapshots[fd] = snapshot
        if not expected_set.issubset(after_import):
            raise BrokerBoundaryError(
                "trusted import changed a fixed descriptor number"
            )
        _require_unchanged_fixed_descriptors(fixed_snapshots)
        for fd in import_fds:
            snapshot = import_snapshots[fd]
            if snapshot.descriptor_flags != fcntl.FD_CLOEXEC:
                raise BrokerBoundaryError(
                    "trusted import descriptor is not exact CLOEXEC"
                )
            if (
                snapshot.file_type != stat.S_IFREG
                or snapshot.device != runtime_identity.device
                or snapshot.status_flags & os.O_ACCMODE != os.O_RDONLY
                or snapshot.status_flags & rejected_status_flags
                or snapshot.socket is not None
            ):
                raise BrokerBoundaryError(
                    "trusted import descriptor is not a read-only runtime object"
                )
            if (
                snapshot.kernel_identity in fixed_identities
                or snapshot.kernel_identity in import_identities
            ):
                raise BrokerBoundaryError(
                    "trusted import descriptor aliases another descriptor object"
                )
            import_identities.add(snapshot.kernel_identity)
        if import_error is not None:
            raise BrokerBoundaryError("trusted ctypes import failed") from import_error

        libc = runtime_ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [
            runtime_ctypes.c_int,
            runtime_ctypes.c_ulong,
            runtime_ctypes.c_ulong,
            runtime_ctypes.c_ulong,
            runtime_ctypes.c_ulong,
        ]
        libc.prctl.restype = runtime_ctypes.c_int
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            error_number = runtime_ctypes.get_errno()
            raise BrokerBoundaryError(
                f"PR_SET_NO_NEW_PRIVS failed with errno={error_number}"
            )
        observed_nnp = libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
        if observed_nnp != 1:
            raise BrokerBoundaryError("PR_GET_NO_NEW_PRIVS did not return one")
        _require_unchanged_fixed_descriptors(fixed_snapshots)
    except BaseException as exc:
        operation_error = exc

    close_error: BaseException | None = None
    for fd in import_fds:
        try:
            snapshot = import_snapshots.get(fd)
            if snapshot is None or _snapshot_descriptor(fd) != snapshot:
                raise BrokerBoundaryError(
                    "trusted import descriptor changed before cleanup"
                )
            os.close(fd)
        except BaseException as exc:
            if close_error is None:
                close_error = exc
    if close_error is not None:
        raise BrokerBoundaryError(
            "trusted import descriptor cleanup failed"
        ) from close_error
    if operation_error is not None:
        raise operation_error
    if _observe_fd_numbers() != expected_fd_numbers:
        raise BrokerBoundaryError(
            "trusted import descriptor cleanup did not restore the fixed set"
        )
    _require_unchanged_fixed_descriptors(fixed_snapshots)

    after = _read_proc_status()
    require_minimal_proc_status(after)
    return after


def validate_broker_environment(
    environment: Mapping[str, str],
) -> EnvironmentEvidence:
    if not isinstance(environment, Mapping):
        raise BrokerBoundaryError("broker environment has the wrong type")
    observed: dict[str, str] = {}
    for key, value in environment.items():
        if type(key) is not str or type(value) is not str:
            raise BrokerBoundaryError("broker environment primitives are invalid")
        observed[key] = value
    expected = dict(BROKER_ENVIRONMENT)
    if observed != expected:
        raise BrokerBoundaryError("broker environment is not the exact fixed mapping")
    encoded = json.dumps(
        expected, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return EnvironmentEvidence(
        names=tuple(expected),
        digest=hashlib.sha256(encoded).hexdigest(),
    )


def _require_cloexec(fd: int, label: str) -> None:
    if type(fd) is not int or fd < 0:
        raise BrokerBoundaryError(f"{label} descriptor is invalid")
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    except OSError as exc:
        raise BrokerBoundaryError(f"{label} descriptor is unavailable") from exc
    if not flags & fcntl.FD_CLOEXEC:
        raise BrokerBoundaryError(f"{label} descriptor is not close-on-exec")


def restore_contract_cloexec(contract: BrokerContract) -> None:
    """Immediately restore CLOEXEC after the launcher intentionally passed FDs."""
    if type(contract) is not BrokerContract:
        raise BrokerBoundaryError("broker contract has the wrong type")
    for fd in contract.capability_fds:
        try:
            flags = fcntl.fcntl(fd, fcntl.F_GETFD)
            fcntl.fcntl(fd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
        except OSError as exc:
            raise BrokerBoundaryError(
                "broker capability CLOEXEC restoration failed"
            ) from exc
        _require_cloexec(fd, "broker capability")


def _duplicate_cloexec(fd: int) -> int:
    try:
        duplicate = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
    except OSError as exc:
        raise BrokerBoundaryError("descriptor duplication failed") from exc
    try:
        _require_cloexec(duplicate, "duplicated")
        return duplicate
    except BaseException:
        os.close(duplicate)
        raise


def _validate_connected_unix_socket(fd: int, socket_type: int, label: str) -> None:
    _require_cloexec(fd, label)
    duplicate = _duplicate_cloexec(fd)
    observed: socket.socket | None = None
    try:
        status = os.fstat(duplicate)
        if not stat.S_ISSOCK(status.st_mode):
            raise BrokerBoundaryError(f"{label} is not a socket")
        observed = socket.socket(fileno=duplicate)
        duplicate = -1
        domain = observed.getsockopt(socket.SOL_SOCKET, _SO_DOMAIN)
        kind = observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) & 0xF
        accepting = observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        if domain != socket.AF_UNIX or kind != socket_type or accepting != 0:
            raise BrokerBoundaryError(f"{label} has the wrong socket contract")
        observed.getpeername()
    except BrokerBoundaryError:
        raise
    except OSError as exc:
        raise BrokerBoundaryError(f"{label} is not an exact connected socket") from exc
    finally:
        if observed is not None:
            observed.close()
        elif duplicate >= 0:
            os.close(duplicate)


def validate_fixture_fd(fd: int) -> None:
    _validate_connected_unix_socket(fd, socket.SOCK_STREAM, "fixture")


def _require_distinct_fd_identities(fds: Sequence[int]) -> None:
    if type(fds) not in (tuple, list) or any(
        type(fd) is not int or fd < 0 for fd in fds
    ):
        raise BrokerBoundaryError("descriptor identity input is invalid")
    identities = []
    try:
        for fd in fds:
            observed = os.fstat(fd)
            identities.append(
                (
                    int(observed.st_dev),
                    int(observed.st_ino),
                    stat.S_IFMT(observed.st_mode),
                )
            )
    except OSError as exc:
        raise BrokerBoundaryError("descriptor identity is unavailable") from exc
    if len(identities) != len(set(identities)):
        raise BrokerBoundaryError("descriptor roles alias one kernel object")


def _validate_status_control_handoff(contract: BrokerContract) -> None:
    _require_distinct_fd_identities(contract.capability_fds)
    _validate_connected_unix_socket(
        contract.handoff_fd, socket.SOCK_SEQPACKET, "listener handoff"
    )
    _validate_connected_unix_socket(
        contract.status_fd, socket.SOCK_SEQPACKET, "broker status"
    )
    _validate_connected_unix_socket(
        contract.control_fd, socket.SOCK_SEQPACKET, "broker control"
    )
    if contract.fixture_fd is not None:
        validate_fixture_fd(contract.fixture_fd)


def _observe_fd_numbers() -> tuple[int, ...]:
    scan_fd = -1
    names: list[str] = []
    try:
        try:
            scan_fd = os.open(
                "/proc/self/fd",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            names = os.listdir(scan_fd)
        except OSError as exc:
            raise BrokerBoundaryError(
                "broker descriptor set is unobservable"
            ) from exc
    finally:
        if scan_fd >= 0:
            os.close(scan_fd)
    try:
        candidates = sorted(int(name) for name in names)
    except ValueError as exc:
        raise BrokerBoundaryError(
            "broker descriptor set is malformed"
        ) from exc
    observed = []
    for fd in candidates:
        try:
            fcntl.fcntl(fd, fcntl.F_GETFD)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise BrokerBoundaryError(
                "broker descriptor set changed during observation"
            ) from exc
        observed.append(fd)
    return tuple(observed)


def validate_fixed_fd_set(
    contract: BrokerContract, observed: tuple[int, ...] | None = None
) -> tuple[int, ...]:
    if type(contract) is not BrokerContract:
        raise BrokerBoundaryError("broker contract has the wrong type")
    numbers = _observe_fd_numbers() if observed is None else observed
    if (
        type(numbers) is not tuple
        or any(type(fd) is not int or fd < 0 for fd in numbers)
    ):
        raise BrokerBoundaryError("observed descriptor evidence is invalid")
    expected = tuple(sorted((0, 1, 2, *contract.capability_fds)))
    if numbers != expected:
        raise BrokerBoundaryError("broker inherited an unexpected descriptor set")
    return numbers


def _observe_identity(path: str, expected_type: int) -> ObservedFileIdentity:
    try:
        observed = os.stat(path, follow_symlinks=True)
    except OSError as exc:
        raise BrokerBoundaryError(f"required broker object {path} is unavailable") from exc
    identity = ObservedFileIdentity.from_stat(observed)
    if identity.file_type != expected_type:
        raise BrokerBoundaryError(f"required broker object {path} has wrong type")
    return identity


def _verify_loaded_module_origins(contract: BrokerContract) -> None:
    expected_modules = (
        (
            "agenticos.sandbox.network_models",
            MODELS_CODE_PATH,
            contract.models_code_identity,
        ),
        (
            "agenticos.sandbox.network_identity",
            IDENTITY_CODE_PATH,
            contract.identity_code_identity,
        ),
        (
            "agenticos.sandbox.network_broker",
            BROKER_CODE_PATH,
            contract.broker_code_identity,
        ),
    )
    for name, path, authorized in expected_modules:
        module = sys.modules.get(name)
        specification = getattr(module, "__spec__", None)
        if (
            type(module) is not type(sys)
            or getattr(module, "__file__", None) != path
            or specification is None
            or getattr(specification, "origin", None) != path
        ):
            raise BrokerBoundaryError(
                f"loaded broker module origin is not exact: {name}"
            )
        observed = _observe_identity(path, stat.S_IFREG)
        if observed != authorized:
            raise BrokerBoundaryError(
                f"loaded broker module identity does not match authority: {name}"
            )


def _readlink_exact(path: str, expected: str) -> None:
    try:
        observed = os.readlink(path)
    except OSError as exc:
        raise BrokerBoundaryError(f"required broker symlink {path} is unavailable") from exc
    if observed != expected:
        raise BrokerBoundaryError(f"required broker symlink {path} changed")


def _listdir_exact(path: str, expected: tuple[str, ...]) -> None:
    try:
        observed = tuple(sorted(os.listdir(path)))
    except OSError as exc:
        raise BrokerBoundaryError(f"required broker directory {path} is unavailable") from exc
    if observed != tuple(sorted(expected)):
        raise BrokerBoundaryError(f"broker directory {path} has unexpected entries")


@dataclass(frozen=True)
class _FilesystemObservation:
    digest: str
    runtime_identity: ObservedFileIdentity
    broker_code_identity: ObservedFileIdentity
    identity_code_identity: ObservedFileIdentity
    models_code_identity: ObservedFileIdentity
    interpreter_identity: ObservedFileIdentity


def _observe_filesystem(contract: BrokerContract) -> _FilesystemObservation:
    try:
        cwd = os.getcwd()
    except OSError as exc:
        raise BrokerBoundaryError("broker cwd is unobservable") from exc
    if cwd != BROKER_ROOT:
        raise BrokerBoundaryError("broker cwd is not the fixed synthetic root")
    _listdir_exact(
        "/",
        (
            "bin",
            "dev",
            "home",
            "lib",
            "lib64",
            "opt",
            "proc",
            "run",
            "sbin",
            "tmp",
            "usr",
        ),
    )
    _listdir_exact("/home", ("broker",))
    _listdir_exact("/home/broker", ())
    _listdir_exact("/run", ())
    _listdir_exact("/tmp", ())
    _listdir_exact("/opt", ("agenticos",))
    _listdir_exact("/opt/agenticos", ("python",))
    _listdir_exact(BROKER_ROOT, ("agenticos",))
    _listdir_exact(f"{BROKER_ROOT}/agenticos", ("sandbox",))
    _listdir_exact(
        f"{BROKER_ROOT}/agenticos/sandbox",
        ("network_broker.py", "network_identity.py", "network_models.py"),
    )
    for forbidden in (
        "/workspace",
        "/etc",
        "/root",
        "/var",
        "/run/user",
        "/opt/agenticos/network-ca.pem",
    ):
        if os.path.lexists(forbidden):
            raise BrokerBoundaryError(
                f"forbidden broker filesystem object is visible: {forbidden}"
            )
    for path, target in (
        ("/bin", "usr/bin"),
        ("/sbin", "usr/sbin"),
        ("/lib", "usr/lib"),
        ("/lib64", "usr/lib64"),
    ):
        _readlink_exact(path, target)
    runtime_identity = _observe_identity(RUNTIME_PATH, stat.S_IFDIR)
    broker_code_identity = _observe_identity(BROKER_CODE_PATH, stat.S_IFREG)
    identity_code_identity = _observe_identity(IDENTITY_CODE_PATH, stat.S_IFREG)
    models_code_identity = _observe_identity(MODELS_CODE_PATH, stat.S_IFREG)
    interpreter_identity = _observe_identity(INTERPRETER_PATH, stat.S_IFREG)
    executable_identity = _observe_identity("/proc/self/exe", stat.S_IFREG)
    if interpreter_identity != executable_identity:
        raise BrokerBoundaryError("broker interpreter identity is not exact")
    expected = (
        (runtime_identity, contract.runtime_identity, "runtime"),
        (broker_code_identity, contract.broker_code_identity, "broker code"),
        (identity_code_identity, contract.identity_code_identity, "identity code"),
        (models_code_identity, contract.models_code_identity, "models code"),
    )
    for observed, authorized, label in expected:
        if observed != authorized:
            raise BrokerBoundaryError(f"{label} identity does not match authority")
    payload = {
        "cwd": cwd,
        "empty": ["/home/broker", "/run", "/tmp"],
        "identities": {
            "broker_code": _identity_dict(broker_code_identity),
            "identity_code": _identity_dict(identity_code_identity),
            "models_code": _identity_dict(models_code_identity),
            "runtime": _identity_dict(runtime_identity),
        },
        "root_entries": [
            "bin",
            "dev",
            "home",
            "lib",
            "lib64",
            "opt",
            "proc",
            "run",
            "sbin",
            "tmp",
            "usr",
        ],
        "symlinks": {
            "/bin": "usr/bin",
            "/lib": "usr/lib",
            "/lib64": "usr/lib64",
            "/sbin": "usr/sbin",
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )
    return _FilesystemObservation(
        digest=hashlib.sha256(encoded).hexdigest(),
        runtime_identity=runtime_identity,
        broker_code_identity=broker_code_identity,
        identity_code_identity=identity_code_identity,
        models_code_identity=models_code_identity,
        interpreter_identity=interpreter_identity,
    )


def _read_process_evidence() -> BrokerProcessEvidence:
    pid = os.getpid()
    try:
        stat_text = Path("/proc/self/stat").read_text(encoding="ascii")
        after_comm = stat_text.rsplit(")", 1)[1].split()
        start_time = int(after_comm[19])
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii"
        ).strip()
    except (OSError, UnicodeError, IndexError, ValueError) as exc:
        raise BrokerBoundaryError("broker process identity is unavailable") from exc
    if not _BOOT_ID_RE.fullmatch(boot_id):
        raise BrokerBoundaryError("broker boot identity is noncanonical")
    try:
        return BrokerProcessEvidence(
            pid=pid,
            start_time_ticks=start_time,
            boot_id=boot_id,
        )
    except ValueError as exc:
        raise BrokerBoundaryError("broker process identity is invalid") from exc


def _read_cgroup() -> str:
    try:
        payload = Path("/proc/self/cgroup").read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise BrokerBoundaryError("broker cgroup evidence is unavailable") from exc
    matches = []
    for line in payload.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0" and parts[1] == "":
            matches.append(parts[2])
    if (
        len(matches) != 1
        or not matches[0].startswith("/")
        or len(matches[0].encode("ascii")) > 4096
    ):
        raise BrokerBoundaryError("broker cgroup evidence is not exact cgroup v2")
    return matches[0]


def _read_namespaces() -> tuple[tuple[str, int], ...]:
    result = []
    for name in _NAMESPACE_NAMES:
        try:
            value = os.readlink(f"/proc/self/ns/{name}")
        except OSError as exc:
            raise BrokerBoundaryError(
                f"broker {name} namespace is unavailable"
            ) from exc
        match = _NAMESPACE_RE.fullmatch(value)
        if match is None:
            raise BrokerBoundaryError(f"broker {name} namespace is malformed")
        result.append((name, int(match.group(1))))
    return tuple(result)


@dataclass(frozen=True)
class _BoundaryObservation:
    evidence: BrokerBoundaryEvidence
    process: BrokerProcessEvidence
    filesystem: _FilesystemObservation


def assert_minimal_process_boundary(
    contract: BrokerContract, policy: TransportPolicy
) -> _BoundaryObservation:
    """Independently prove the production broker boundary before readiness."""
    if type(contract) is not BrokerContract:
        raise BrokerBoundaryError("broker contract has the wrong type")
    _validate_policy_contract(policy, contract)
    fd_numbers = validate_fixed_fd_set(contract)
    _verify_loaded_module_origins(contract)
    _validate_status_control_handoff(contract)
    environment = validate_broker_environment(os.environ)
    proc_status = _establish_no_new_privs(fd_numbers, contract.runtime_identity)
    validate_fixed_fd_set(contract)
    filesystem = _observe_filesystem(contract)
    process = _read_process_evidence()
    evidence = BrokerBoundaryEvidence(
        proc_status=proc_status,
        environment=environment,
        filesystem_digest=filesystem.digest,
        fd_numbers=fd_numbers,
        cgroup=_read_cgroup(),
        namespaces=_read_namespaces(),
    )
    return _BoundaryObservation(
        evidence=evidence,
        process=process,
        filesystem=filesystem,
    )


def _validate_policy_contract(
    policy: TransportPolicy,
    contract: BrokerContract,
    *,
    now_ns: int | None = None,
) -> int:
    if type(policy) is not TransportPolicy:
        raise BrokerBoundaryError("sealed policy has the wrong exact type")
    if type(contract) is not BrokerContract:
        raise BrokerBoundaryError("broker contract has the wrong exact type")
    now = time.monotonic_ns() if now_ns is None else now_ns
    if type(now) is not int or now <= 0:
        raise BrokerBoundaryError("monotonic observation is invalid")
    if now < policy.activated_at_monotonic_ns:
        raise BrokerBoundaryError("sealed policy is not active yet")
    if now >= policy.expires_at_monotonic_ns:
        raise BrokerBoundaryError("sealed policy expired before readiness")
    if policy.mode is TransportMode.DENY and contract.fixture_fd is not None:
        raise BrokerBoundaryError("DENY policy must not receive a fixture")
    if (
        policy.mode is TransportMode.SYNTHETIC_FIXTURE_FD
        and contract.fixture_fd != BROKER_FIXTURE_FD
    ):
        raise BrokerBoundaryError("synthetic policy requires the fixed fixture")
    return now


def emit_network_broker_ready(
    status_fd: int, record: NetworkBrokerReadyRecord
) -> None:
    if type(record) is not NetworkBrokerReadyRecord:
        raise BrokerBoundaryError("ready record has the wrong type")
    _validate_connected_unix_socket(
        status_fd, socket.SOCK_SEQPACKET, "broker status"
    )
    payload = record.to_bytes()
    duplicate = _duplicate_cloexec(status_fd)
    channel: socket.socket | None = None
    try:
        channel = socket.socket(fileno=duplicate)
        duplicate = -1
        sent = channel.send(payload)
        if sent != len(payload):
            raise BrokerBoundaryError("ready record was not sent atomically")
        channel.shutdown(socket.SHUT_WR)
    except BrokerBoundaryError:
        raise
    except OSError as exc:
        raise BrokerBoundaryError("ready record send failed") from exc
    finally:
        if channel is not None:
            channel.close()
        elif duplicate >= 0:
            os.close(duplicate)


def _read_control(channel: socket.socket) -> TransportTermination | None:
    try:
        payload, ancillary, flags, _address = channel.recvmsg(
            MAX_CONTROL_BYTES + 1,
            socket.CMSG_SPACE(array_itemsize()),
            socket.MSG_DONTWAIT | socket.MSG_CMSG_CLOEXEC,
        )
    except BlockingIOError:
        return None
    except OSError:
        return TransportTermination.PEER_ERROR
    received_fds: set[int] = set()
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            complete = len(data) - (len(data) % array.array("i").itemsize)
            if complete:
                values = array.array("i")
                values.frombytes(data[:complete])
                received_fds.update(values)
    for received_fd in received_fds:
        try:
            os.close(received_fd)
        except OSError:
            pass
    if ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        return TransportTermination.MALFORMED_CONTROL
    if payload == b"":
        return TransportTermination.CONTROL_EOF
    if payload == CONTROL_REVOKE:
        return TransportTermination.REVOKED
    return TransportTermination.MALFORMED_CONTROL


def array_itemsize() -> int:
    # One native int is enough space to detect and reject any SCM_RIGHTS record.
    return struct.calcsize("i")


def _abort_socket(channel: socket.socket | None) -> None:
    if channel is None:
        return
    try:
        channel.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_LINGER,
            struct.pack("ii", 1, 0),
        )
    except OSError:
        pass
    try:
        channel.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        channel.close()
    except OSError:
        pass


def _close_socket(channel: socket.socket | None) -> None:
    if channel is None:
        return
    try:
        channel.close()
    except OSError:
        pass


def _wrap_owned_socket(fd: int, label: str) -> socket.socket:
    if type(fd) is not int or fd < 0:
        raise BrokerBoundaryError(f"{label} descriptor is invalid")
    try:
        return socket.socket(fileno=fd)
    except OSError as exc:
        raise BrokerBoundaryError(f"{label} descriptor cannot be owned") from exc


def _relay_loop(
    policy: TransportPolicy,
    listener: socket.socket,
    fixture: socket.socket,
    control: socket.socket,
) -> TransportTermination:
    worker: socket.socket | None = None
    selector = selectors.DefaultSelector()
    total_bytes = 0
    limit_reached = False
    read_open: dict[socket.socket, bool] = {}
    buffers: dict[socket.socket, bytearray] = {}
    try:
        listener.setblocking(False)
        fixture.setblocking(False)
        control.setblocking(False)
        selector.register(listener, selectors.EVENT_READ, "listener")
        selector.register(control, selectors.EVENT_READ, "control")

        while True:
            now = time.monotonic_ns()
            if now >= policy.expires_at_monotonic_ns:
                buffers.clear()
                return TransportTermination.EXPIRED
            timeout = min(
                SELECTOR_SLICE_SECONDS,
                (policy.expires_at_monotonic_ns - now) / 1_000_000_000,
            )
            events = selector.select(timeout)
            if time.monotonic_ns() >= policy.expires_at_monotonic_ns:
                buffers.clear()
                return TransportTermination.EXPIRED
            if not events:
                continue
            for key, _mask in events:
                if key.data != "control":
                    continue
                outcome = _read_control(control)
                if outcome is not None:
                    buffers.clear()
                    return outcome
            for key, mask in events:
                if key.data == "control":
                    continue
                if key.data == "listener":
                    try:
                        accepted, _address = listener.accept()
                    except BlockingIOError:
                        continue
                    except OSError:
                        return TransportTermination.PEER_ERROR
                    if worker is not None or policy.connection_limit < 1:
                        _abort_socket(accepted)
                        return TransportTermination.CONNECTION_LIMIT
                    worker = accepted
                    worker.setblocking(False)
                    read_open = {worker: True, fixture: True}
                    buffers = {worker: bytearray(), fixture: bytearray()}
                    selector.register(worker, selectors.EVENT_READ, "endpoint")
                    selector.register(fixture, selectors.EVENT_READ, "endpoint")
                    continue

                endpoint = key.fileobj
                if type(endpoint) is not socket.socket:
                    return TransportTermination.PEER_ERROR
                if worker is None:
                    return TransportTermination.PEER_ERROR
                other = fixture if endpoint is worker else worker
                if mask & selectors.EVENT_READ and read_open.get(endpoint, False):
                    remaining = policy.byte_limit - total_bytes
                    if remaining <= 0:
                        limit_reached = True
                    elif len(buffers[other]) < RELAY_BUFFER_BYTES:
                        available_buffer = (
                            RELAY_BUFFER_BYTES - len(buffers[other])
                        )
                        try:
                            chunk = endpoint.recv(
                                min(
                                    RELAY_CHUNK_BYTES,
                                    remaining,
                                    available_buffer,
                                )
                            )
                        except BlockingIOError:
                            chunk = None
                        except OSError:
                            return TransportTermination.PEER_ERROR
                        if chunk == b"":
                            read_open[endpoint] = False
                        elif chunk:
                            buffers[other].extend(chunk)
                            total_bytes += len(chunk)
                            if total_bytes >= policy.byte_limit:
                                limit_reached = True
                if mask & selectors.EVENT_WRITE and buffers[endpoint]:
                    try:
                        sent = endpoint.send(buffers[endpoint])
                    except BlockingIOError:
                        sent = 0
                    except OSError:
                        return TransportTermination.PEER_ERROR
                    if sent < 0 or sent > len(buffers[endpoint]):
                        return TransportTermination.PEER_ERROR
                    del buffers[endpoint][:sent]

            if worker is None:
                continue
            for endpoint in (worker, fixture):
                try:
                    selector.unregister(endpoint)
                except (KeyError, ValueError):
                    pass
                other = fixture if endpoint is worker else worker
                event_mask = 0
                if (
                    read_open.get(endpoint, False)
                    and not limit_reached
                    and len(buffers[other]) < RELAY_BUFFER_BYTES
                ):
                    event_mask |= selectors.EVENT_READ
                if buffers[endpoint]:
                    event_mask |= selectors.EVENT_WRITE
                if event_mask:
                    selector.register(endpoint, event_mask, "endpoint")
                elif not read_open.get(other, False) and not buffers[endpoint]:
                    try:
                        endpoint.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
            if limit_reached and not any(buffers.values()):
                return TransportTermination.BYTE_LIMIT
            if not any(read_open.values()) and not any(buffers.values()):
                return TransportTermination.COMPLETED
    finally:
        selector.close()
        _abort_socket(worker)


def _deny_loop(
    policy: TransportPolicy, control: socket.socket
) -> TransportTermination:
    selector = selectors.DefaultSelector()
    try:
        control.setblocking(False)
        selector.register(control, selectors.EVENT_READ)
        while True:
            now = time.monotonic_ns()
            if now >= policy.expires_at_monotonic_ns:
                return TransportTermination.EXPIRED
            timeout = min(
                SELECTOR_SLICE_SECONDS,
                (policy.expires_at_monotonic_ns - now) / 1_000_000_000,
            )
            if selector.select(timeout):
                outcome = _read_control(control)
                if outcome is not None:
                    return outcome
    finally:
        selector.close()


def serve_transport(
    policy: TransportPolicy,
    *,
    listener_fd: int,
    fixture_fd: int | None,
    control_fd: int,
) -> TransportTermination:
    """Own and close the supplied capabilities while serving one bounded relay."""
    listener: socket.socket | None = None
    fixture: socket.socket | None = None
    control: socket.socket | None = None
    raw_values = (listener_fd, control_fd, fixture_fd)
    owned_raw = {
        fd for fd in raw_values if type(fd) is int and fd >= 0
    }
    try:
        if type(policy) is not TransportPolicy:
            raise BrokerBoundaryError("transport policy has the wrong type")
        now = time.monotonic_ns()
        if now < policy.activated_at_monotonic_ns:
            raise BrokerBoundaryError("transport policy is not active")
        if now >= policy.expires_at_monotonic_ns:
            return TransportTermination.EXPIRED
        fds = (listener_fd, control_fd) if fixture_fd is None else (
            listener_fd,
            control_fd,
            fixture_fd,
        )
        if (
            any(type(fd) is not int or fd < 0 for fd in fds)
            or len(set(fds)) != len(fds)
        ):
            raise BrokerBoundaryError("transport descriptor roles collide")
        listener_evidence(listener_fd)
        _validate_connected_unix_socket(
            control_fd, socket.SOCK_SEQPACKET, "broker control"
        )
        if policy.mode is TransportMode.DENY:
            if fixture_fd is not None:
                raise BrokerBoundaryError("DENY transport received a fixture")
        elif policy.mode is TransportMode.SYNTHETIC_FIXTURE_FD:
            if fixture_fd is None:
                raise BrokerBoundaryError("synthetic transport lacks a fixture")
            validate_fixture_fd(fixture_fd)
        else:
            raise BrokerBoundaryError("transport mode is unsupported")

        listener = _wrap_owned_socket(listener_fd, "listener")
        owned_raw.discard(listener_fd)
        control = _wrap_owned_socket(control_fd, "control")
        owned_raw.discard(control_fd)
        if fixture_fd is not None:
            fixture = _wrap_owned_socket(fixture_fd, "fixture")
            owned_raw.discard(fixture_fd)
        if policy.mode is TransportMode.DENY:
            return _deny_loop(policy, control)
        if fixture is None:
            raise BrokerBoundaryError("synthetic fixture ownership failed")
        return _relay_loop(policy, listener, fixture, control)
    finally:
        _close_socket(listener)
        _abort_socket(fixture)
        _abort_socket(control)
        _close_owned(owned_raw)


def _build_ready_record(
    sealed: VerifiedSealedPolicy,
    adopted_listener: ListenerEvidence,
    observation: _BoundaryObservation,
    ready_at_ns: int,
) -> NetworkBrokerReadyRecord:
    policy = sealed.policy
    ready = BrokerReadyEvidence(
        task_id=policy.task_id,
        task_generation=policy.task_generation,
        launch_nonce=policy.launch_nonce,
        policy_digest=sealed.digest,
        broker_pid=observation.process.pid,
        broker_start_time_ticks=observation.process.start_time_ticks,
        broker_boot_id=observation.process.boot_id,
        ready_at_monotonic_ns=ready_at_ns,
    )
    filesystem = observation.filesystem
    return NetworkBrokerReadyRecord(
        version=READY_VERSION,
        event=READY_EVENT,
        ready=ready,
        process=observation.process,
        listener=adopted_listener,
        sealed_policy=SealedPolicyEvidence(
            device=sealed.device,
            inode=sealed.inode,
            size=sealed.size,
            seals=sealed.seals,
        ),
        runtime_identity=filesystem.runtime_identity,
        broker_code_identity=filesystem.broker_code_identity,
        identity_code_identity=filesystem.identity_code_identity,
        models_code_identity=filesystem.models_code_identity,
        interpreter_identity=filesystem.interpreter_identity,
        boundary=observation.evidence,
    )


def _close_owned(fds: set[int]) -> None:
    for fd in tuple(fds):
        try:
            os.close(fd)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                pass
        finally:
            fds.discard(fd)


def broker_main(contract: BrokerContract) -> NoReturn:
    """Verify, adopt once, announce once, and serve until fail-closed teardown."""
    if type(contract) is not BrokerContract:
        raise BrokerBoundaryError("broker contract has the wrong type")
    owned = set(contract.capability_fds)
    adopted_fd: int | None = None
    try:
        restore_contract_cloexec(contract)
        try:
            sealed = read_sealed_policy_fd(contract.policy_fd)
        except NetworkIdentityError as exc:
            raise BrokerBoundaryError("sealed policy verification failed") from exc
        _validate_policy_contract(sealed.policy, contract)
        observation = assert_minimal_process_boundary(contract, sealed.policy)

        handoff = _wrap_owned_socket(contract.handoff_fd, "listener handoff")
        owned.discard(contract.handoff_fd)
        try:
            try:
                adopted = recv_listener_fd(
                    handoff,
                    expected_task_id=sealed.policy.task_id,
                    expected_generation=sealed.policy.task_generation,
                    expected_nonce=sealed.policy.launch_nonce,
                    expected_policy_digest=sealed.digest,
                )
            except NetworkIdentityError as exc:
                raise BrokerBoundaryError("listener adoption failed") from exc
        finally:
            _abort_socket(handoff)
        adopted_fd = adopted.fd

        ready_at_ns = time.monotonic_ns()
        if ready_at_ns >= sealed.policy.expires_at_monotonic_ns:
            raise BrokerBoundaryError("sealed policy expired before readiness")
        record = _build_ready_record(
            sealed, adopted.evidence, observation, ready_at_ns
        )
        emit_network_broker_ready(contract.status_fd, record)
        os.close(contract.status_fd)
        owned.discard(contract.status_fd)
        os.close(contract.policy_fd)
        owned.discard(contract.policy_fd)

        control_fd = contract.control_fd
        fixture_fd = contract.fixture_fd
        owned.discard(control_fd)
        if fixture_fd is not None:
            owned.discard(fixture_fd)
        relay_listener_fd = adopted_fd
        adopted_fd = None
        termination = serve_transport(
            sealed.policy,
            listener_fd=relay_listener_fd,
            fixture_fd=fixture_fd,
            control_fd=control_fd,
        )
        if termination in {
            TransportTermination.COMPLETED,
            TransportTermination.REVOKED,
            TransportTermination.EXPIRED,
        }:
            raise SystemExit(0)
        raise SystemExit(111)
    finally:
        if adopted_fd is not None:
            try:
                os.close(adopted_fd)
            except OSError:
                pass
        _close_owned(owned)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    try:
        contract = BrokerContract.from_argv(arguments)
        broker_main(contract)
    except SystemExit as exc:
        return int(exc.code) if type(exc.code) is int else 111
    except BaseException:
        return 111
    return 111


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "BROKER_CODE_PATH",
    "BROKER_CONTRACT_VERSION",
    "BROKER_CONTROL_FD",
    "BROKER_ENVIRONMENT",
    "BROKER_FIXTURE_FD",
    "BROKER_HANDOFF_FD",
    "BROKER_POLICY_FD",
    "BROKER_ROOT",
    "BROKER_STATUS_FD",
    "BrokerBoundaryError",
    "BrokerBoundaryEvidence",
    "BrokerContract",
    "EnvironmentEvidence",
    "MAX_READY_BYTES",
    "NetworkBrokerReadyRecord",
    "ObservedFileIdentity",
    "ProcStatusEvidence",
    "SealedPolicyEvidence",
    "TransportTermination",
    "assert_minimal_process_boundary",
    "broker_main",
    "emit_network_broker_ready",
    "main",
    "parse_proc_status",
    "require_minimal_proc_status",
    "restore_contract_cloexec",
    "serve_transport",
    "validate_broker_environment",
    "validate_fixture_fd",
    "validate_fixed_fd_set",
]
