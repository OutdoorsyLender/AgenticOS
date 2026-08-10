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
import threading
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
    policy_digest as transport_policy_digest,
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

# M4B-2 HTTPS flavor: sealed task material descriptors (broker contract roles).
BROKER_HTTPS_POLICY_FD = 36
BROKER_HTTPS_CA_CERT_FD = 37
BROKER_HTTPS_LEAF_CERT_FD = 38
BROKER_HTTPS_LEAF_KEY_FD = 39
BROKER_HTTPS_BINDING_FD = 43

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

# M4B-2 HTTPS flavor: additional broker-mounted code objects and the gated
# h11 vendor directory.  The fixed order below is the canonical module role
# order used by the contract, the bootstrap, and the boundary proof.
M4A_MODELS_CODE_PATH = "/opt/agenticos/python/agenticos/sandbox/models.py"
CAPABILITIES_CODE_PATH = (
    "/opt/agenticos/python/agenticos/sandbox/capabilities.py"
)
SPECIAL_ADDRESSES_CODE_PATH = (
    "/opt/agenticos/python/agenticos/sandbox/special_addresses.py"
)
RESOLUTION_CODE_PATH = (
    "/opt/agenticos/python/agenticos/sandbox/network_resolution.py"
)
HTTP_CODE_PATH = "/opt/agenticos/python/agenticos/sandbox/network_http.py"
HTTPS_CODE_PATH = "/opt/agenticos/python/agenticos/sandbox/network_https.py"
CLIENTHELLO_CODE_PATH = (
    "/opt/agenticos/python/agenticos/sandbox/network_clienthello.py"
)
HOSTQUAL_CODE_PATH = (
    "/opt/agenticos/python/agenticos/sandbox/host_qualification.py"
)
TLS_CODE_PATH = "/opt/agenticos/python/agenticos/sandbox/network_tls.py"
ORIGIN_CODE_PATH = "/opt/agenticos/python/agenticos/sandbox/network_origin.py"
CERT_HELPER_CODE_PATH = (
    "/opt/agenticos/python/agenticos/sandbox/cert_helper.py"
)
VENDOR_PATH = "/opt/agenticos/vendor"
VENDOR_ENTRIES = ("h11", "h11-0.16.0.dist-info")

BROKER_HTTPS_MODULE_ROLES = (
    ("m4a_models_code", "agenticos.sandbox.models", M4A_MODELS_CODE_PATH),
    ("capabilities_code", "agenticos.sandbox.capabilities", CAPABILITIES_CODE_PATH),
    (
        "special_addresses_code",
        "agenticos.sandbox.special_addresses",
        SPECIAL_ADDRESSES_CODE_PATH,
    ),
    ("resolution_code", "agenticos.sandbox.network_resolution", RESOLUTION_CODE_PATH),
    ("http_code", "agenticos.sandbox.network_http", HTTP_CODE_PATH),
    ("https_code", "agenticos.sandbox.network_https", HTTPS_CODE_PATH),
    ("clienthello_code", "agenticos.sandbox.network_clienthello", CLIENTHELLO_CODE_PATH),
    ("hostqual_code", "agenticos.sandbox.host_qualification", HOSTQUAL_CODE_PATH),
    ("tls_code", "agenticos.sandbox.network_tls", TLS_CODE_PATH),
    ("origin_code", "agenticos.sandbox.network_origin", ORIGIN_CODE_PATH),
    ("cert_helper_code", "agenticos.sandbox.cert_helper", CERT_HELPER_CODE_PATH),
)

BROKER_HTTPS_SANDBOX_ENTRIES = tuple(
    sorted(
        (
            "capabilities.py",
            "cert_helper.py",
            "host_qualification.py",
            "models.py",
            "network_broker.py",
            "network_clienthello.py",
            "network_http.py",
            "network_https.py",
            "network_identity.py",
            "network_models.py",
            "network_origin.py",
            "network_resolution.py",
            "network_tls.py",
            "special_addresses.py",
        )
    )
)

BROKER_ENVIRONMENT = (
    ("HOME", "/home/broker"),
    ("PATH", "/usr/bin:/bin"),
    ("LANG", "C.UTF-8"),
    ("LC_ALL", "C.UTF-8"),
    ("TMPDIR", "/tmp"),
    ("PWD", BROKER_ROOT),
    ("PYTHONDONTWRITEBYTECODE", "1"),
)

MAX_CONTRACT_ITEMS = 128
MAX_CONTRACT_ITEM_BYTES = 256
MAX_READY_BYTES = 8192
MAX_TRANSPORT_OBSERVATION_BYTES = 4096
MAX_CONTROL_BYTES = 64
RELAY_CHUNK_BYTES = 16 * 1024
RELAY_BUFFER_BYTES = 32 * 1024
SELECTOR_SLICE_SECONDS = 0.1
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39
_SO_DOMAIN = getattr(socket, "SO_DOMAIN", 39)
_MAX_UNSIGNED_64 = (1 << 64) - 1
_HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
_HEX_32_RE = re.compile(r"[0-9a-f]{32}\Z")
_TASK_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
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
    DENY_NO_RELAY = "DENY_NO_RELAY"
    COMPLETED = "COMPLETED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    CONTROL_EOF = "CONTROL_EOF"
    MALFORMED_CONTROL = "MALFORMED_CONTROL"
    BYTE_LIMIT = "BYTE_LIMIT"
    CONNECTION_LIMIT = "CONNECTION_LIMIT"
    PEER_ERROR = "PEER_ERROR"


@dataclass(frozen=True)
class NetworkTransportObservation:
    """Canonical broker-owned terminal relay accounting."""

    version: str
    event: str
    task_id: str
    task_generation: int
    launch_nonce: str
    policy_digest: str
    observed_at_monotonic_ns: int
    connection_count: int
    accounted_bytes: int
    worker_to_fixture_bytes: int
    fixture_to_worker_bytes: int
    total_bytes: int
    discarded_unsent_bytes: int
    terminal_reason: TransportTermination

    def __post_init__(self) -> None:
        if self.version != "AOSTRANSPORT/1":
            raise BrokerBoundaryError("transport observation version is invalid")
        if self.event != "NETWORK_TRANSPORT_TERMINATED":
            raise BrokerBoundaryError("transport observation event is invalid")
        if type(self.task_id) is not str or not _TASK_ID_RE.fullmatch(self.task_id):
            raise BrokerBoundaryError("transport observation task ID is invalid")
        _positive_u64("transport observation generation", self.task_generation)
        if type(self.launch_nonce) is not str or not _HEX_32_RE.fullmatch(
            self.launch_nonce
        ):
            raise BrokerBoundaryError("transport observation nonce is invalid")
        if type(self.policy_digest) is not str or not _HEX_64_RE.fullmatch(
            self.policy_digest
        ):
            raise BrokerBoundaryError("transport observation policy digest is invalid")
        if type(self.terminal_reason) is not TransportTermination:
            raise BrokerBoundaryError("transport observation reason is invalid")
        _positive_u64(
            "transport observation monotonic timestamp",
            self.observed_at_monotonic_ns,
        )
        for name, value in (
            ("connection count", self.connection_count),
            ("accounted bytes", self.accounted_bytes),
            ("worker-to-fixture bytes", self.worker_to_fixture_bytes),
            ("fixture-to-worker bytes", self.fixture_to_worker_bytes),
            ("total bytes", self.total_bytes),
            ("discarded unsent bytes", self.discarded_unsent_bytes),
        ):
            _nonnegative_u64(f"transport observation {name}", value)
        if self.connection_count > 1:
            raise BrokerBoundaryError("transport observation exceeds one connection")
        if self.total_bytes != (
            self.worker_to_fixture_bytes + self.fixture_to_worker_bytes
        ):
            raise BrokerBoundaryError("transport observation byte total is inconsistent")
        if self.accounted_bytes != self.total_bytes + self.discarded_unsent_bytes:
            raise BrokerBoundaryError("transport observation accounting is inconsistent")
        if self.terminal_reason is TransportTermination.DENY_NO_RELAY and any(
            (
                self.connection_count,
                self.accounted_bytes,
                self.worker_to_fixture_bytes,
                self.fixture_to_worker_bytes,
                self.total_bytes,
                self.discarded_unsent_bytes,
            )
        ):
            raise BrokerBoundaryError("DENY observation must contain zero relay totals")

    def to_bytes(self) -> bytes:
        payload = {
            "accounted_bytes": self.accounted_bytes,
            "connection_count": self.connection_count,
            "discarded_unsent_bytes": self.discarded_unsent_bytes,
            "event": self.event,
            "fixture_to_worker_bytes": self.fixture_to_worker_bytes,
            "launch_nonce": self.launch_nonce,
            "observed_at_monotonic_ns": self.observed_at_monotonic_ns,
            "policy_digest": self.policy_digest,
            "task_generation": self.task_generation,
            "task_id": self.task_id,
            "terminal_reason": self.terminal_reason.value,
            "total_bytes": self.total_bytes,
            "version": self.version,
            "worker_to_fixture_bytes": self.worker_to_fixture_bytes,
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        if len(encoded) > MAX_TRANSPORT_OBSERVATION_BYTES:
            raise BrokerBoundaryError("transport observation is oversized")
        return encoded

    @classmethod
    def from_bytes(cls, payload: bytes) -> NetworkTransportObservation:
        decoded = _exact_dict(
            _decode_json(
                payload,
                MAX_TRANSPORT_OBSERVATION_BYTES,
                "transport observation",
            ),
            {
                "connection_count",
                "accounted_bytes",
                "discarded_unsent_bytes",
                "event",
                "fixture_to_worker_bytes",
                "launch_nonce",
                "observed_at_monotonic_ns",
                "policy_digest",
                "task_generation",
                "task_id",
                "terminal_reason",
                "total_bytes",
                "version",
                "worker_to_fixture_bytes",
            },
            "transport observation",
        )
        try:
            record = cls(
                version=decoded["version"],
                event=decoded["event"],
                task_id=decoded["task_id"],
                task_generation=decoded["task_generation"],
                launch_nonce=decoded["launch_nonce"],
                policy_digest=decoded["policy_digest"],
                observed_at_monotonic_ns=decoded["observed_at_monotonic_ns"],
                connection_count=decoded["connection_count"],
                accounted_bytes=decoded["accounted_bytes"],
                worker_to_fixture_bytes=decoded["worker_to_fixture_bytes"],
                fixture_to_worker_bytes=decoded["fixture_to_worker_bytes"],
                total_bytes=decoded["total_bytes"],
                discarded_unsent_bytes=decoded["discarded_unsent_bytes"],
                terminal_reason=TransportTermination(decoded["terminal_reason"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise BrokerBoundaryError("transport observation fields are invalid") from exc
        if record.to_bytes() != payload:
            raise BrokerBoundaryError("transport observation encoding is not canonical")
        return record


def _transport_observation(
    policy: TransportPolicy,
    *,
    connection_count: int,
    accounted_bytes: int,
    worker_to_fixture_bytes: int,
    fixture_to_worker_bytes: int,
    terminal_reason: TransportTermination,
    observed_at_monotonic_ns: int | None = None,
) -> NetworkTransportObservation:
    observed_at = (
        time.monotonic_ns()
        if observed_at_monotonic_ns is None
        else observed_at_monotonic_ns
    )
    if observed_at < policy.activated_at_monotonic_ns:
        raise BrokerBoundaryError("transport observation precedes policy activation")
    if terminal_reason is TransportTermination.EXPIRED:
        if observed_at < policy.expires_at_monotonic_ns:
            raise BrokerBoundaryError("expiry observation precedes policy expiry")
    elif observed_at >= policy.expires_at_monotonic_ns:
        raise BrokerBoundaryError("non-expiry observation is not before policy expiry")
    forwarded = worker_to_fixture_bytes + fixture_to_worker_bytes
    if not 0 <= forwarded <= accounted_bytes <= policy.byte_limit:
        raise BrokerBoundaryError("transport byte accounting exceeds policy authority")
    if not 0 <= connection_count <= policy.connection_limit:
        raise BrokerBoundaryError("transport connection accounting exceeds policy authority")
    return NetworkTransportObservation(
        version="AOSTRANSPORT/1",
        event="NETWORK_TRANSPORT_TERMINATED",
        task_id=policy.task_id,
        task_generation=policy.task_generation,
        launch_nonce=policy.launch_nonce,
        policy_digest=transport_policy_digest(policy),
        observed_at_monotonic_ns=observed_at,
        connection_count=connection_count,
        accounted_bytes=accounted_bytes,
        worker_to_fixture_bytes=worker_to_fixture_bytes,
        fixture_to_worker_bytes=fixture_to_worker_bytes,
        total_bytes=worker_to_fixture_bytes + fixture_to_worker_bytes,
        discarded_unsent_bytes=(
            accounted_bytes - worker_to_fixture_bytes - fixture_to_worker_bytes
        ),
        terminal_reason=terminal_reason,
    )


def build_deny_transport_observation(
    policy: TransportPolicy, *, policy_digest: str
) -> NetworkTransportObservation:
    if type(policy) is not TransportPolicy or policy.mode is not TransportMode.DENY:
        raise BrokerBoundaryError("DENY observation requires a DENY policy")
    if policy_digest != transport_policy_digest(policy):
        raise BrokerBoundaryError("DENY observation policy digest is invalid")
    return _transport_observation(
        policy,
        connection_count=0,
        accounted_bytes=0,
        worker_to_fixture_bytes=0,
        fixture_to_worker_bytes=0,
        terminal_reason=TransportTermination.DENY_NO_RELAY,
    )


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
class HttpsMaterialContract:
    """Fixed M4B-2 sealed-material descriptor roles and code identities.

    Additive broker-contract section for the HTTPS flavor.  The five
    material descriptors are verified and CLOSED before readiness; they are
    never part of the broker's post-readiness descriptor census.
    """

    network_policy_fd: int
    ca_cert_fd: int
    leaf_cert_fd: int
    leaf_key_fd: int
    binding_fd: int
    m4a_models_code_identity: ObservedFileIdentity
    capabilities_code_identity: ObservedFileIdentity
    special_addresses_code_identity: ObservedFileIdentity
    resolution_code_identity: ObservedFileIdentity
    http_code_identity: ObservedFileIdentity
    https_code_identity: ObservedFileIdentity
    clienthello_code_identity: ObservedFileIdentity
    hostqual_code_identity: ObservedFileIdentity
    tls_code_identity: ObservedFileIdentity
    origin_code_identity: ObservedFileIdentity
    cert_helper_code_identity: ObservedFileIdentity
    vendor_identity: ObservedFileIdentity

    def __post_init__(self) -> None:
        expected = (
            ("network_policy_fd", self.network_policy_fd, BROKER_HTTPS_POLICY_FD),
            ("ca_cert_fd", self.ca_cert_fd, BROKER_HTTPS_CA_CERT_FD),
            ("leaf_cert_fd", self.leaf_cert_fd, BROKER_HTTPS_LEAF_CERT_FD),
            ("leaf_key_fd", self.leaf_key_fd, BROKER_HTTPS_LEAF_KEY_FD),
            ("binding_fd", self.binding_fd, BROKER_HTTPS_BINDING_FD),
        )
        for name, value, fixed in expected:
            if type(value) is not int or value != fixed:
                raise BrokerBoundaryError(f"{name} must be fixed descriptor {fixed}")
        if len(set(self.material_fds)) != len(self.material_fds):
            raise BrokerBoundaryError("https material descriptor roles collide")
        identities = self.code_identities
        if any(type(identity) is not ObservedFileIdentity for identity in identities):
            raise BrokerBoundaryError("https code identity has the wrong type")
        if self.vendor_identity.file_type != stat.S_IFDIR:
            raise BrokerBoundaryError("https vendor identity must be a directory")
        if any(
            identity.file_type != stat.S_IFREG for identity in identities[:-1]
        ):
            raise BrokerBoundaryError("https code identities must be regular files")
        if (
            len(
                {
                    (identity.device, identity.inode, identity.file_type)
                    for identity in identities
                }
            )
            != len(identities)
        ):
            raise BrokerBoundaryError("https code identities collide")

    @property
    def material_fds(self) -> tuple[int, ...]:
        return (
            self.network_policy_fd,
            self.ca_cert_fd,
            self.leaf_cert_fd,
            self.leaf_key_fd,
            self.binding_fd,
        )

    @property
    def code_identities(self) -> tuple[ObservedFileIdentity, ...]:
        return (
            self.m4a_models_code_identity,
            self.capabilities_code_identity,
            self.special_addresses_code_identity,
            self.resolution_code_identity,
            self.http_code_identity,
            self.https_code_identity,
            self.clienthello_code_identity,
            self.hostqual_code_identity,
            self.tls_code_identity,
            self.origin_code_identity,
            self.cert_helper_code_identity,
            self.vendor_identity,
        )

    def to_argv(self) -> tuple[str, ...]:
        result = [
            "https_material",
            "network_policy_fd",
            str(self.network_policy_fd),
            "ca_cert_fd",
            str(self.ca_cert_fd),
            "leaf_cert_fd",
            str(self.leaf_cert_fd),
            "leaf_key_fd",
            str(self.leaf_key_fd),
            "binding_fd",
            str(self.binding_fd),
        ]
        for role, identity in zip(
            (*(role for role, _module, _path in BROKER_HTTPS_MODULE_ROLES), "vendor"),
            self.code_identities,
        ):
            result.extend(
                (
                    f"{role}_identity",
                    str(identity.device),
                    str(identity.inode),
                    str(identity.file_type),
                )
            )
        return tuple(result)


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
    https: HttpsMaterialContract | None = None

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
        if self.https is not None and type(self.https) is not HttpsMaterialContract:
            raise BrokerBoundaryError("https material contract has the wrong type")
        if len(set(self.entry_fds)) != len(self.entry_fds):
            raise BrokerBoundaryError("broker capability descriptor roles collide")
        identities = (
            self.runtime_identity,
            self.broker_code_identity,
            self.identity_code_identity,
            self.models_code_identity,
        )
        if any(type(identity) is not ObservedFileIdentity for identity in identities):
            raise BrokerBoundaryError("broker source identity has the wrong type")
        all_identities = (
            (*identities, *self.https.code_identities)
            if self.https is not None
            else identities
        )
        if len(
            {
                (identity.device, identity.inode, identity.file_type)
                for identity in all_identities
            }
        ) != len(all_identities):
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

    @property
    def material_fds(self) -> tuple[int, ...]:
        """Sealed HTTPS material descriptors, closed before readiness."""
        return () if self.https is None else self.https.material_fds

    @property
    def entry_fds(self) -> tuple[int, ...]:
        """Every fixed descriptor the broker inherits at process entry."""
        return (*self.capability_fds, *self.material_fds)

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
        if self.https is not None:
            result.extend(self.https.to_argv())
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
        https: HttpsMaterialContract | None = None
        if cursor < len(values) and values[cursor] == "https_material":
            cursor += 1

            def material_fd(name: str) -> int:
                take(name)
                return decimal(name)

            network_policy_fd = material_fd("network_policy_fd")
            ca_cert_fd = material_fd("ca_cert_fd")
            leaf_cert_fd = material_fd("leaf_cert_fd")
            leaf_key_fd = material_fd("leaf_key_fd")
            binding_fd = material_fd("binding_fd")
            https_identities = tuple(
                identity(f"{role}_identity")
                for role, _module, _path in BROKER_HTTPS_MODULE_ROLES
            )
            vendor_identity = identity("vendor_identity")
            https = HttpsMaterialContract(
                network_policy_fd=network_policy_fd,
                ca_cert_fd=ca_cert_fd,
                leaf_cert_fd=leaf_cert_fd,
                leaf_key_fd=leaf_key_fd,
                binding_fd=binding_fd,
                m4a_models_code_identity=https_identities[0],
                capabilities_code_identity=https_identities[1],
                special_addresses_code_identity=https_identities[2],
                resolution_code_identity=https_identities[3],
                http_code_identity=https_identities[4],
                https_code_identity=https_identities[5],
                clienthello_code_identity=https_identities[6],
                hostqual_code_identity=https_identities[7],
                tls_code_identity=https_identities[8],
                origin_code_identity=https_identities[9],
                cert_helper_code_identity=https_identities[10],
                vendor_identity=vendor_identity,
            )
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
            https=https,
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
    for fd in contract.entry_fds:
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
    expected_modules = [
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
    ]
    if contract.https is not None:
        expected_modules.extend(
            (module, path, identity)
            for (_role, module, path), identity in zip(
                BROKER_HTTPS_MODULE_ROLES, contract.https.code_identities[:-1]
            )
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
    if contract.https is None:
        _listdir_exact("/opt/agenticos", ("python",))
        _listdir_exact(BROKER_ROOT, ("agenticos",))
        _listdir_exact(f"{BROKER_ROOT}/agenticos", ("sandbox",))
        _listdir_exact(
            f"{BROKER_ROOT}/agenticos/sandbox",
            ("network_broker.py", "network_identity.py", "network_models.py"),
        )
    else:
        _listdir_exact("/opt/agenticos", ("python", "vendor"))
        _listdir_exact(VENDOR_PATH, VENDOR_ENTRIES)
        _listdir_exact(BROKER_ROOT, ("agenticos",))
        _listdir_exact(f"{BROKER_ROOT}/agenticos", ("sandbox",))
        _listdir_exact(
            f"{BROKER_ROOT}/agenticos/sandbox",
            BROKER_HTTPS_SANDBOX_ENTRIES,
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
    https_identities: tuple[tuple[str, ObservedFileIdentity], ...] = ()
    if contract.https is not None:
        observed_https = []
        for (role, _module, path), authorized in zip(
            BROKER_HTTPS_MODULE_ROLES, contract.https.code_identities[:-1]
        ):
            observed = _observe_identity(path, stat.S_IFREG)
            if observed != authorized:
                raise BrokerBoundaryError(
                    f"{role} identity does not match authority"
                )
            observed_https.append((f"{role}_identity", observed))
        vendor_identity = _observe_identity(VENDOR_PATH, stat.S_IFDIR)
        if vendor_identity != contract.https.vendor_identity:
            raise BrokerBoundaryError("vendor identity does not match authority")
        observed_https.append(("vendor_identity", vendor_identity))
        https_identities = tuple(observed_https)
    identity_payload = {
        "broker_code": _identity_dict(broker_code_identity),
        "identity_code": _identity_dict(identity_code_identity),
        "models_code": _identity_dict(models_code_identity),
        "runtime": _identity_dict(runtime_identity),
    }
    for name, observed in https_identities:
        identity_payload[name] = _identity_dict(observed)
    payload = {
        "cwd": cwd,
        "empty": ["/home/broker", "/run", "/tmp"],
        "identities": identity_payload,
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
    if contract.https is not None:
        payload["vendor_entries"] = list(VENDOR_ENTRIES)
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


def emit_transport_observation(
    control_fd: int, record: NetworkTransportObservation
) -> None:
    """Send the sole terminal observation on the control capability."""
    if type(record) is not NetworkTransportObservation:
        raise BrokerBoundaryError("transport observation has the wrong type")
    _validate_connected_unix_socket(
        control_fd, socket.SOCK_SEQPACKET, "broker control"
    )
    payload = record.to_bytes()
    duplicate = _duplicate_cloexec(control_fd)
    channel: socket.socket | None = None
    try:
        channel = socket.socket(fileno=duplicate)
        duplicate = -1
        sent = channel.send(payload, socket.MSG_NOSIGNAL)
        if sent != len(payload):
            raise BrokerBoundaryError("transport observation send was short")
        channel.shutdown(socket.SHUT_WR)
    except BrokerBoundaryError:
        raise
    except OSError as exc:
        raise BrokerBoundaryError("transport observation send failed") from exc
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
) -> NetworkTransportObservation:
    worker: socket.socket | None = None
    selector = selectors.DefaultSelector()
    total_bytes = 0
    worker_to_fixture_bytes = 0
    fixture_to_worker_bytes = 0
    limit_reached = False
    read_open: dict[socket.socket, bool] = {}
    write_open: dict[socket.socket, bool] = {}
    buffers: dict[socket.socket, bytearray] = {}
    connection_used = False

    def finish(reason: TransportTermination) -> NetworkTransportObservation:
        if total_bytes > policy.byte_limit:
            raise BrokerBoundaryError("relay accounting exceeded the policy byte limit")
        observed_at = time.monotonic_ns()
        if observed_at >= policy.expires_at_monotonic_ns:
            reason = TransportTermination.EXPIRED
        return _transport_observation(
            policy,
            connection_count=int(connection_used),
            accounted_bytes=total_bytes,
            worker_to_fixture_bytes=worker_to_fixture_bytes,
            fixture_to_worker_bytes=fixture_to_worker_bytes,
            terminal_reason=reason,
            observed_at_monotonic_ns=observed_at,
        )

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
                return finish(TransportTermination.EXPIRED)
            timeout = min(
                SELECTOR_SLICE_SECONDS,
                (policy.expires_at_monotonic_ns - now) / 1_000_000_000,
            )
            events = selector.select(timeout)
            if time.monotonic_ns() >= policy.expires_at_monotonic_ns:
                buffers.clear()
                return finish(TransportTermination.EXPIRED)
            if not events:
                continue
            for key, _mask in events:
                if key.data != "control":
                    continue
                outcome = _read_control(control)
                if outcome is not None:
                    buffers.clear()
                    return finish(outcome)
            for key, mask in events:
                if key.data == "control":
                    continue
                if key.data == "listener":
                    try:
                        accepted, _address = listener.accept()
                    except BlockingIOError:
                        continue
                    except OSError:
                        return finish(TransportTermination.PEER_ERROR)
                    if connection_used or worker is not None or policy.connection_limit < 1:
                        _abort_socket(accepted)
                        return finish(TransportTermination.CONNECTION_LIMIT)
                    connection_used = True
                    worker = accepted
                    worker.setblocking(False)
                    read_open = {worker: True, fixture: True}
                    write_open = {worker: True, fixture: True}
                    buffers = {worker: bytearray(), fixture: bytearray()}
                    selector.register(worker, selectors.EVENT_READ, "endpoint")
                    selector.register(fixture, selectors.EVENT_READ, "endpoint")
                    continue

                endpoint = key.fileobj
                if type(endpoint) is not socket.socket:
                    return finish(TransportTermination.PEER_ERROR)
                if worker is None:
                    return finish(TransportTermination.PEER_ERROR)
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
                            return finish(TransportTermination.PEER_ERROR)
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
                        return finish(TransportTermination.PEER_ERROR)
                    if sent < 0 or sent > len(buffers[endpoint]):
                        return finish(TransportTermination.PEER_ERROR)
                    if endpoint is fixture:
                        worker_to_fixture_bytes += sent
                    else:
                        fixture_to_worker_bytes += sent
                    del buffers[endpoint][:sent]

            if worker is None:
                continue
            for endpoint in (worker, fixture):
                try:
                    selector.unregister(endpoint)
                except (KeyError, ValueError):
                    pass
                other = fixture if endpoint is worker else worker
                if (
                    not read_open.get(other, False)
                    and not buffers[endpoint]
                    and write_open.get(endpoint, False)
                ):
                    try:
                        endpoint.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    write_open[endpoint] = False
                event_mask = 0
                if (
                    read_open.get(endpoint, False)
                    and not limit_reached
                    and len(buffers[other]) < RELAY_BUFFER_BYTES
                ):
                    event_mask |= selectors.EVENT_READ
                if buffers[endpoint] and write_open.get(endpoint, False):
                    event_mask |= selectors.EVENT_WRITE
                if event_mask:
                    selector.register(endpoint, event_mask, "endpoint")
            if limit_reached and not any(buffers.values()):
                return finish(TransportTermination.BYTE_LIMIT)
            if not any(read_open.values()) and not any(buffers.values()):
                for endpoint in (worker, fixture):
                    try:
                        selector.unregister(endpoint)
                    except (KeyError, ValueError):
                        pass
                _abort_socket(worker)
                worker = None
                _abort_socket(fixture)
                read_open.clear()
                write_open.clear()
                buffers.clear()
                return finish(TransportTermination.COMPLETED)
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
) -> TransportTermination | NetworkTransportObservation:
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
        # A broker-held duplicate may still need to emit the immutable terminal
        # observation.  Closing this owned alias must not shutdown the shared
        # socket description and destroy that opposite-direction capability.
        _close_socket(control)
        _close_owned(owned_raw)


# -- M4B-2 HTTPS serve path (slice 9b) ------------------------------------------
#
# Evidence design choice: the HTTPS flavor runs under a DENY transport policy,
# and the M4B-1 AOSTRANSPORT/1 observation cannot express per-connection HTTPS
# truth (its connection_count is capped at one and its DENY semantics require
# zero totals), so extending it would weaken a format M4B-1 authenticates.
# Instead the broker emits PARALLEL HTTPS evidence records on the same
# authenticated control channel under their own version tag: zero or more
# HTTPS_CONNECTION_TERMINATED records (one per accepted connection, emitted
# EAGERLY in completion order) followed — whenever the serve loop ends while
# the worker still lives (revoke-while-alive, expiry, control EOF, limit) —
# by exactly one aggregate HTTPS_TRANSPORT_TERMINATED record and the
# write-side shutdown.  M4B-1 record formats, readers, and
# DENY/SYNTHETIC_FIXTURE_FD semantics are byte-compatibly untouched.
#
# Platform constraint (broker death semantics, unchanged from M4B-1): the
# broker is parented to the supervisor, which execs the worker chain; when
# the worker exits, the broker is reaped with it.  Records buffered on the
# seqpacket control channel remain readable by the controller afterwards
# (the same mechanism M4B-1's upfront DENY observation relies on).  A clean
# worker exit therefore yields the eager per-connection records plus channel
# EOF WITHOUT a terminal record; the runner authenticates the records and
# synthesizes the aggregate itself (its own liveness gates prove the broker
# died only at or after worker exit — a mid-run broker death fails the pump
# closed).  Mid-run expiry exits the broker with an EXPIRED terminal and,
# exactly as in M4B-1, fails the run closed at the broker-liveness gate.
#
# Concurrency posture: the main selector thread owns the listener and the
# control channel; each accepted connection is served on its own bounded
# worker thread.  Simultaneous ClientHello gates are bounded by
# BoundedGateGuard; per-connection worker-TLS termination is serialized on one
# mutex because the SNI policy installs on the shared task-leaf context;
# post-handshake relay runs concurrently per connection.  Aggregate byte and
# connection authority is enforced across all threads by one locked
# accountant.  Accepted connections are bounded by the grant connection limit;
# exceeding it terminates the broker (CONNECTION_LIMIT), mirroring M4B-1.

HTTPS_EVIDENCE_VERSION = "AOSHTTPEV/1"
HTTPS_CONNECTION_EVENT = "HTTPS_CONNECTION_TERMINATED"
HTTPS_TERMINAL_EVENT = "HTTPS_TRANSPORT_TERMINATED"
MAX_HTTPS_EVIDENCE_BYTES = 4096
MAX_HTTPS_CONTROL_BYTES = 16384
CONTROL_HTTPS_FIXTURE = b"AOSBROKERCTL/1 HTTPS-FIXTURE\n"
HTTPS_FIXTURE_VERSION = "AOSHTTPSFIX/1"
HTTPS_FIXTURE_MAX_PEM_BYTES = 8192
HTTPS_FIXTURE_MAX_ADDRESSES = 8
CONNECT_HEAD_MAX_BYTES = 16384
CONNECT_MAX_HEADER_LINES = 32
CONNECT_STAGE_TIMEOUT_SECONDS = 5.0
HTTPS_STAGE_SLICE_SECONDS = 0.25
HTTPS_CHANNEL_WRITE_TIMEOUT_SECONDS = 10.0
HTTPS_THREAD_JOIN_GRACE_SECONDS = 8.0
HTTPS_CONNECT_RESPONSE_OK = b"HTTP/1.1 200 Connection Established\r\n\r\n"
HTTPS_CONNECT_RESPONSE_DENIED = (
    b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
)
_HTTPS_HOST_EVIDENCE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}\Z")
_HTTPS_TCHAR = frozenset(
    b"!#$%&'*+-.^_`|~0123456789"
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)


class HttpsConnectionStage(str, Enum):
    """The furthest trust stage one worker connection reached."""

    CONNECT = "connect"
    AUTHORIZATION = "authorization"
    GATE = "clienthello_gate"
    WORKER_TLS = "worker_tls"
    HTTP = "http_prevalidation"
    RESOLUTION = "resolution"
    ORIGIN_CONNECT = "origin_connect"
    ORIGIN_TLS = "origin_tls"
    REQUEST_FORWARD = "request_forward"
    RESPONSE_RELAY = "response_relay"


class HttpsConnectionTermination(str, Enum):
    """Per-connection terminal verdict of the HTTPS serve path."""

    COMPLETED = "completed"
    DENIED = "denied"
    REVOKED = "revoked"
    EXPIRED = "expired"
    BYTE_LIMIT = "byte_limit"
    PEER_ERROR = "peer_error"


def _https_evidence_text(name: str, value: object, maximum: int = 160) -> str:
    if type(value) is not str or not 0 < len(value) <= maximum:
        raise BrokerBoundaryError(f"https evidence {name} is invalid")
    if any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
        raise BrokerBoundaryError(f"https evidence {name} is not printable ASCII")
    return value


def _https_optional_hostname(value: object, label: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not _HTTPS_HOST_EVIDENCE_RE.fullmatch(value):
        raise BrokerBoundaryError(f"https evidence {label} is invalid")
    return value


def _sanitize_gate_reason(reason: object) -> str:
    """Bound a gate rejection reason to safe printable ASCII for evidence."""
    if type(reason) is not str:
        return "rejected"
    cleaned = "".join(
        char if 0x20 <= ord(char) <= 0x7E and char not in "\"\\" else "_"
        for char in reason
    )
    return cleaned[:160] or "rejected"


def _evidence_hostname(value: object) -> str | None:
    """Map an observed (possibly hostile) hostname onto the evidence grammar."""
    if value is None:
        return None
    if type(value) is str and _HTTPS_HOST_EVIDENCE_RE.fullmatch(value):
        return value
    return "<non-canonical>"


@dataclass(frozen=True)
class HttpsConnectionRecord:
    """Canonical broker-owned per-connection HTTPS evidence (AOSHTTPEV/1)."""

    version: str
    event: str
    task_id: str
    task_generation: int
    launch_nonce: str
    policy_digest: str
    network_policy_digest: str
    address_policy_version: str
    connection_index: int
    stage_reached: HttpsConnectionStage
    terminal_reason: HttpsConnectionTermination
    detail: str
    approved_hostname: str
    connect_authority: str | None
    worker_sni: str | None
    http_host: str | None
    origin_tls_name: str | None
    identity_chain: str
    worker_tls_version: str | None
    worker_alpn: str | None
    origin_tls_version: str | None
    origin_alpn: str | None
    origin_peer_address: str | None
    origin_peer_port: int
    synthetic_origin: bool
    requests_completed: int
    accounted_bytes: int
    worker_to_origin_bytes: int
    origin_to_worker_bytes: int
    total_bytes: int
    discarded_unsent_bytes: int
    observed_at_monotonic_ns: int

    def __post_init__(self) -> None:
        if self.version != HTTPS_EVIDENCE_VERSION:
            raise BrokerBoundaryError("https connection record version is invalid")
        if self.event != HTTPS_CONNECTION_EVENT:
            raise BrokerBoundaryError("https connection record event is invalid")
        if type(self.task_id) is not str or not _TASK_ID_RE.fullmatch(self.task_id):
            raise BrokerBoundaryError("https connection record task ID is invalid")
        _positive_u64("https connection record generation", self.task_generation)
        if type(self.launch_nonce) is not str or not _HEX_32_RE.fullmatch(
            self.launch_nonce
        ):
            raise BrokerBoundaryError("https connection record nonce is invalid")
        for label, digest in (
            ("policy digest", self.policy_digest),
            ("network policy digest", self.network_policy_digest),
        ):
            if type(digest) is not str or not _HEX_64_RE.fullmatch(digest):
                raise BrokerBoundaryError(
                    f"https connection record {label} is invalid"
                )
        _https_evidence_text(
            "address policy version", self.address_policy_version, 128
        )
        _positive_u64("https connection index", self.connection_index)
        if type(self.stage_reached) is not HttpsConnectionStage:
            raise BrokerBoundaryError("https connection record stage is invalid")
        if type(self.terminal_reason) is not HttpsConnectionTermination:
            raise BrokerBoundaryError("https connection record reason is invalid")
        _https_evidence_text("detail", self.detail)
        _https_optional_hostname(self.approved_hostname, "approved hostname")
        for label, value in (
            ("CONNECT authority", self.connect_authority),
            ("worker SNI", self.worker_sni),
            ("HTTP host", self.http_host),
            ("origin TLS name", self.origin_tls_name),
        ):
            _https_optional_hostname(value, label)
        _https_evidence_text("identity chain", self.identity_chain, 64)
        for label, value in (
            ("worker TLS version", self.worker_tls_version),
            ("worker ALPN", self.worker_alpn),
            ("origin TLS version", self.origin_tls_version),
            ("origin ALPN", self.origin_alpn),
            ("origin peer address", self.origin_peer_address),
        ):
            if value is not None:
                _https_evidence_text(label, value, 64)
        if type(self.origin_peer_port) is not int or not 0 <= (
            self.origin_peer_port
        ) <= 65535:
            raise BrokerBoundaryError("https connection record peer port is invalid")
        if type(self.synthetic_origin) is not bool:
            raise BrokerBoundaryError("https connection record synthetic flag is invalid")
        _nonnegative_u64("https requests completed", self.requests_completed)
        for name, value in (
            ("accounted bytes", self.accounted_bytes),
            ("worker-to-origin bytes", self.worker_to_origin_bytes),
            ("origin-to-worker bytes", self.origin_to_worker_bytes),
            ("total bytes", self.total_bytes),
            ("discarded unsent bytes", self.discarded_unsent_bytes),
        ):
            _nonnegative_u64(f"https connection record {name}", value)
        if self.total_bytes != (
            self.worker_to_origin_bytes + self.origin_to_worker_bytes
        ):
            raise BrokerBoundaryError("https connection byte total is inconsistent")
        if self.accounted_bytes != self.total_bytes + self.discarded_unsent_bytes:
            raise BrokerBoundaryError("https connection accounting is inconsistent")
        _positive_u64(
            "https connection record monotonic timestamp",
            self.observed_at_monotonic_ns,
        )

    def to_bytes(self) -> bytes:
        payload = {
            "accounted_bytes": self.accounted_bytes,
            "address_policy_version": self.address_policy_version,
            "approved_hostname": self.approved_hostname,
            "connect_authority": self.connect_authority,
            "connection_index": self.connection_index,
            "detail": self.detail,
            "discarded_unsent_bytes": self.discarded_unsent_bytes,
            "event": self.event,
            "http_host": self.http_host,
            "identity_chain": self.identity_chain,
            "launch_nonce": self.launch_nonce,
            "network_policy_digest": self.network_policy_digest,
            "observed_at_monotonic_ns": self.observed_at_monotonic_ns,
            "origin_alpn": self.origin_alpn,
            "origin_peer_address": self.origin_peer_address,
            "origin_peer_port": self.origin_peer_port,
            "origin_tls_name": self.origin_tls_name,
            "origin_tls_version": self.origin_tls_version,
            "origin_to_worker_bytes": self.origin_to_worker_bytes,
            "policy_digest": self.policy_digest,
            "requests_completed": self.requests_completed,
            "stage_reached": self.stage_reached.value,
            "synthetic_origin": self.synthetic_origin,
            "task_generation": self.task_generation,
            "task_id": self.task_id,
            "terminal_reason": self.terminal_reason.value,
            "total_bytes": self.total_bytes,
            "version": self.version,
            "worker_alpn": self.worker_alpn,
            "worker_sni": self.worker_sni,
            "worker_tls_version": self.worker_tls_version,
            "worker_to_origin_bytes": self.worker_to_origin_bytes,
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        if len(encoded) > MAX_HTTPS_EVIDENCE_BYTES:
            raise BrokerBoundaryError("https connection record is oversized")
        return encoded

    @classmethod
    def from_bytes(cls, payload: bytes) -> HttpsConnectionRecord:
        decoded = _exact_dict(
            _decode_json(payload, MAX_HTTPS_EVIDENCE_BYTES, "https connection record"),
            {
                "accounted_bytes",
                "address_policy_version",
                "approved_hostname",
                "connect_authority",
                "connection_index",
                "detail",
                "discarded_unsent_bytes",
                "event",
                "http_host",
                "identity_chain",
                "launch_nonce",
                "network_policy_digest",
                "observed_at_monotonic_ns",
                "origin_alpn",
                "origin_peer_address",
                "origin_peer_port",
                "origin_tls_name",
                "origin_tls_version",
                "origin_to_worker_bytes",
                "policy_digest",
                "requests_completed",
                "stage_reached",
                "synthetic_origin",
                "task_generation",
                "task_id",
                "terminal_reason",
                "total_bytes",
                "version",
                "worker_alpn",
                "worker_sni",
                "worker_tls_version",
                "worker_to_origin_bytes",
            },
            "https connection record",
        )
        try:
            record = cls(
                version=decoded["version"],
                event=decoded["event"],
                task_id=decoded["task_id"],
                task_generation=decoded["task_generation"],
                launch_nonce=decoded["launch_nonce"],
                policy_digest=decoded["policy_digest"],
                network_policy_digest=decoded["network_policy_digest"],
                address_policy_version=decoded["address_policy_version"],
                connection_index=decoded["connection_index"],
                stage_reached=HttpsConnectionStage(decoded["stage_reached"]),
                terminal_reason=HttpsConnectionTermination(
                    decoded["terminal_reason"]
                ),
                detail=decoded["detail"],
                approved_hostname=decoded["approved_hostname"],
                connect_authority=decoded["connect_authority"],
                worker_sni=decoded["worker_sni"],
                http_host=decoded["http_host"],
                origin_tls_name=decoded["origin_tls_name"],
                identity_chain=decoded["identity_chain"],
                worker_tls_version=decoded["worker_tls_version"],
                worker_alpn=decoded["worker_alpn"],
                origin_tls_version=decoded["origin_tls_version"],
                origin_alpn=decoded["origin_alpn"],
                origin_peer_address=decoded["origin_peer_address"],
                origin_peer_port=decoded["origin_peer_port"],
                synthetic_origin=decoded["synthetic_origin"],
                requests_completed=decoded["requests_completed"],
                accounted_bytes=decoded["accounted_bytes"],
                worker_to_origin_bytes=decoded["worker_to_origin_bytes"],
                origin_to_worker_bytes=decoded["origin_to_worker_bytes"],
                total_bytes=decoded["total_bytes"],
                discarded_unsent_bytes=decoded["discarded_unsent_bytes"],
                observed_at_monotonic_ns=decoded["observed_at_monotonic_ns"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise BrokerBoundaryError(
                "https connection record fields are invalid"
            ) from exc
        if record.to_bytes() != payload:
            raise BrokerBoundaryError(
                "https connection record encoding is not canonical"
            )
        return record


@dataclass(frozen=True)
class HttpsTransportTerminal:
    """Canonical aggregate terminal HTTPS evidence (AOSHTTPEV/1)."""

    version: str
    event: str
    task_id: str
    task_generation: int
    launch_nonce: str
    policy_digest: str
    network_policy_digest: str
    observed_at_monotonic_ns: int
    connection_count: int
    accounted_bytes: int
    worker_to_origin_bytes: int
    origin_to_worker_bytes: int
    total_bytes: int
    discarded_unsent_bytes: int
    terminal_reason: TransportTermination
    synthetic_origin: bool

    def __post_init__(self) -> None:
        if self.version != HTTPS_EVIDENCE_VERSION:
            raise BrokerBoundaryError("https terminal record version is invalid")
        if self.event != HTTPS_TERMINAL_EVENT:
            raise BrokerBoundaryError("https terminal record event is invalid")
        if type(self.task_id) is not str or not _TASK_ID_RE.fullmatch(self.task_id):
            raise BrokerBoundaryError("https terminal record task ID is invalid")
        _positive_u64("https terminal record generation", self.task_generation)
        if type(self.launch_nonce) is not str or not _HEX_32_RE.fullmatch(
            self.launch_nonce
        ):
            raise BrokerBoundaryError("https terminal record nonce is invalid")
        for label, digest in (
            ("policy digest", self.policy_digest),
            ("network policy digest", self.network_policy_digest),
        ):
            if type(digest) is not str or not _HEX_64_RE.fullmatch(digest):
                raise BrokerBoundaryError(f"https terminal record {label} is invalid")
        _positive_u64(
            "https terminal record monotonic timestamp",
            self.observed_at_monotonic_ns,
        )
        for name, value in (
            ("connection count", self.connection_count),
            ("accounted bytes", self.accounted_bytes),
            ("worker-to-origin bytes", self.worker_to_origin_bytes),
            ("origin-to-worker bytes", self.origin_to_worker_bytes),
            ("total bytes", self.total_bytes),
            ("discarded unsent bytes", self.discarded_unsent_bytes),
        ):
            _nonnegative_u64(f"https terminal record {name}", value)
        if self.total_bytes != (
            self.worker_to_origin_bytes + self.origin_to_worker_bytes
        ):
            raise BrokerBoundaryError("https terminal byte total is inconsistent")
        if self.accounted_bytes != self.total_bytes + self.discarded_unsent_bytes:
            raise BrokerBoundaryError("https terminal accounting is inconsistent")
        if type(self.terminal_reason) is not TransportTermination:
            raise BrokerBoundaryError("https terminal record reason is invalid")
        if self.terminal_reason in {
            TransportTermination.DENY_NO_RELAY,
            TransportTermination.COMPLETED,
        }:
            raise BrokerBoundaryError(
                "https terminal record reason is not an HTTPS serve outcome"
            )
        if type(self.synthetic_origin) is not bool:
            raise BrokerBoundaryError("https terminal record synthetic flag is invalid")

    @property
    def worker_to_fixture_bytes(self) -> int:
        """M4B-1-shaped alias: the normalized runner evidence is flavor-blind."""
        return self.worker_to_origin_bytes

    @property
    def fixture_to_worker_bytes(self) -> int:
        """M4B-1-shaped alias: the normalized runner evidence is flavor-blind."""
        return self.origin_to_worker_bytes

    def to_bytes(self) -> bytes:
        payload = {
            "accounted_bytes": self.accounted_bytes,
            "connection_count": self.connection_count,
            "discarded_unsent_bytes": self.discarded_unsent_bytes,
            "event": self.event,
            "launch_nonce": self.launch_nonce,
            "network_policy_digest": self.network_policy_digest,
            "observed_at_monotonic_ns": self.observed_at_monotonic_ns,
            "origin_to_worker_bytes": self.origin_to_worker_bytes,
            "policy_digest": self.policy_digest,
            "synthetic_origin": self.synthetic_origin,
            "task_generation": self.task_generation,
            "task_id": self.task_id,
            "terminal_reason": self.terminal_reason.value,
            "total_bytes": self.total_bytes,
            "version": self.version,
            "worker_to_origin_bytes": self.worker_to_origin_bytes,
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        if len(encoded) > MAX_HTTPS_EVIDENCE_BYTES:
            raise BrokerBoundaryError("https terminal record is oversized")
        return encoded

    @classmethod
    def from_bytes(cls, payload: bytes) -> HttpsTransportTerminal:
        decoded = _exact_dict(
            _decode_json(payload, MAX_HTTPS_EVIDENCE_BYTES, "https terminal record"),
            {
                "accounted_bytes",
                "connection_count",
                "discarded_unsent_bytes",
                "event",
                "launch_nonce",
                "network_policy_digest",
                "observed_at_monotonic_ns",
                "origin_to_worker_bytes",
                "policy_digest",
                "synthetic_origin",
                "task_generation",
                "task_id",
                "terminal_reason",
                "total_bytes",
                "version",
                "worker_to_origin_bytes",
            },
            "https terminal record",
        )
        try:
            record = cls(
                version=decoded["version"],
                event=decoded["event"],
                task_id=decoded["task_id"],
                task_generation=decoded["task_generation"],
                launch_nonce=decoded["launch_nonce"],
                policy_digest=decoded["policy_digest"],
                network_policy_digest=decoded["network_policy_digest"],
                observed_at_monotonic_ns=decoded["observed_at_monotonic_ns"],
                connection_count=decoded["connection_count"],
                accounted_bytes=decoded["accounted_bytes"],
                worker_to_origin_bytes=decoded["worker_to_origin_bytes"],
                origin_to_worker_bytes=decoded["origin_to_worker_bytes"],
                total_bytes=decoded["total_bytes"],
                discarded_unsent_bytes=decoded["discarded_unsent_bytes"],
                terminal_reason=TransportTermination(decoded["terminal_reason"]),
                synthetic_origin=decoded["synthetic_origin"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise BrokerBoundaryError(
                "https terminal record fields are invalid"
            ) from exc
        if record.to_bytes() != payload:
            raise BrokerBoundaryError(
                "https terminal record encoding is not canonical"
            )
        return record


def _emit_https_packet(control_fd: int, payload: bytes, *, final: bool) -> None:
    """Send one HTTPS evidence packet; only the final one closes the channel."""
    if len(payload) > MAX_HTTPS_EVIDENCE_BYTES:
        raise BrokerBoundaryError("https evidence packet is oversized")
    _validate_connected_unix_socket(
        control_fd, socket.SOCK_SEQPACKET, "broker control"
    )
    duplicate = _duplicate_cloexec(control_fd)
    channel: socket.socket | None = None
    try:
        channel = socket.socket(fileno=duplicate)
        duplicate = -1
        sent = channel.send(payload, socket.MSG_NOSIGNAL)
        if sent != len(payload):
            raise BrokerBoundaryError("https evidence send was short")
        if final:
            channel.shutdown(socket.SHUT_WR)
    except BrokerBoundaryError:
        raise
    except OSError as exc:
        raise BrokerBoundaryError("https evidence send failed") from exc
    finally:
        if channel is not None:
            channel.close()
        elif duplicate >= 0:
            os.close(duplicate)


class _HttpsFixtureState:
    """One conformance-only synthetic origin armed over the control channel.

    The fixture is selected ONLY by the controller (never by policy or worker
    input): exactly one already-connected socket plus its explicit trust roots
    and declared numeric resolution arrive as one authenticated control
    message before the first connection.  It supplies exactly ONE origin
    connection per launch; every record produced under it is marked
    ``synthetic_origin=True`` (non-production).
    """

    def __init__(
        self, fd: int, ca_certs_pem: str, addresses: tuple[str, ...]
    ) -> None:
        self.fd = fd
        self.ca_certs_pem = ca_certs_pem
        self.addresses = addresses
        self.spent = False


class _HttpsByteAccountant:
    """Aggregate, lock-protected byte authority across all connections."""

    def __init__(self, byte_limit: int) -> None:
        self._limit = byte_limit
        self._lock = threading.Lock()
        self.accounted = 0
        self.worker_to_origin = 0
        self.origin_to_worker = 0

    @property
    def limit(self) -> int:
        return self._limit

    def read_budget(self) -> int:
        with self._lock:
            return self._limit - self.accounted

    def commit_read(self, count: int) -> None:
        with self._lock:
            self.accounted += count
            if self.accounted > self._limit:
                raise BrokerBoundaryError("https byte accounting exceeded its limit")

    def commit_worker_to_origin(self, count: int) -> None:
        with self._lock:
            self.worker_to_origin += count

    def commit_origin_to_worker(self, count: int) -> None:
        with self._lock:
            self.origin_to_worker += count

    def snapshot(self) -> tuple[int, int, int]:
        with self._lock:
            return self.accounted, self.worker_to_origin, self.origin_to_worker


class _HttpsConnectionRuntime:
    """Live abort handles for one in-flight connection (teardown plumbing)."""

    def __init__(self, worker_sock: socket.socket) -> None:
        self._lock = threading.Lock()
        self._worker_sock: socket.socket | None = worker_sock
        self._channel: Any = None
        self._origin_sock: socket.socket | None = None

    def set_channel(self, channel: Any) -> None:
        with self._lock:
            self._channel = channel

    def set_origin(self, origin_sock: socket.socket | None) -> None:
        with self._lock:
            self._origin_sock = origin_sock

    def abort(self) -> None:
        with self._lock:
            worker_sock, channel, origin_sock = (
                self._worker_sock,
                self._channel,
                self._origin_sock,
            )
        if channel is not None:
            try:
                channel.close()
            except Exception:
                pass
        _abort_socket(origin_sock)
        _abort_socket(worker_sock)


class _HttpsServeState:
    """Shared broker-owned state for one HTTPS serve run."""

    def __init__(
        self,
        policy: TransportPolicy,
        https_state: _HttpsMaterialState,
        control_fd: int,
    ) -> None:
        from .network_clienthello import BoundedGateGuard

        self.policy = policy
        self.https_state = https_state
        self.network_policy = https_state.network_policy
        # Zero grants is the deny-all posture: no approved hostname exists,
        # authority comes from the transport policy alone, and every CONNECT
        # is denied by authorize_grant before any trust stage is reached.
        self.grant = (
            self.network_policy.grants[0] if self.network_policy.grants else None
        )
        self.approved_hostname = (
            self.grant.hostname if self.grant is not None else None
        )
        self.control_fd = control_fd
        self.connection_limit = (
            min(policy.connection_limit, self.grant.connection_limit)
            if self.grant is not None
            else policy.connection_limit
        )
        self.accountant = _HttpsByteAccountant(
            min(policy.byte_limit, self.grant.byte_limit)
            if self.grant is not None
            else policy.byte_limit
        )
        self.guard = BoundedGateGuard()
        self.tls_configure_lock = threading.Lock()
        self.emit_lock = threading.Lock()
        self.abort = threading.Event()
        self.fixture: _HttpsFixtureState | None = None
        self.connections_accepted = 0
        self.records_emitted = 0
        self.byte_limit_reached = False
        self.runtimes: list[_HttpsConnectionRuntime] = []
        self.threads: list[threading.Thread] = []
        self.thread_errors: list[BaseException] = []

    def expired(self) -> bool:
        return time.monotonic_ns() >= self.policy.expires_at_monotonic_ns

    def emit_record(self, record: HttpsConnectionRecord) -> None:
        with self.emit_lock:
            _emit_https_packet(self.control_fd, record.to_bytes(), final=False)
            self.records_emitted += 1

    def abort_connections(self) -> None:
        self.abort.set()
        for runtime in tuple(self.runtimes):
            runtime.abort()


def _parse_https_fixture(payload: bytes, fd: int) -> _HttpsFixtureState:
    """Validate the controller-sent conformance fixture control message."""
    import ipaddress

    decoded = _exact_dict(
        _decode_json(payload, MAX_HTTPS_CONTROL_BYTES, "https fixture"),
        {"version", "ca_certs_pem", "addresses"},
        "https fixture",
    )
    if decoded["version"] != HTTPS_FIXTURE_VERSION:
        raise BrokerBoundaryError("https fixture version is invalid")
    pem = decoded["ca_certs_pem"]
    if (
        type(pem) is not str
        or not pem
        or not pem.isascii()
        or len(pem.encode("ascii")) > HTTPS_FIXTURE_MAX_PEM_BYTES
    ):
        raise BrokerBoundaryError("https fixture trust roots are invalid")
    raw_addresses = decoded["addresses"]
    if (
        type(raw_addresses) is not list
        or not 1 <= len(raw_addresses) <= HTTPS_FIXTURE_MAX_ADDRESSES
    ):
        raise BrokerBoundaryError("https fixture address set is invalid")
    addresses: list[str] = []
    for entry in raw_addresses:
        if type(entry) is not str:
            raise BrokerBoundaryError("https fixture address is invalid")
        try:
            parsed = ipaddress.ip_address(entry)
        except ValueError as exc:
            raise BrokerBoundaryError("https fixture address is invalid") from exc
        if str(parsed) != entry:
            raise BrokerBoundaryError("https fixture address is not canonical")
        addresses.append(entry)
    if type(fd) is not int or fd < 0:
        raise BrokerBoundaryError("https fixture descriptor is invalid")
    try:
        os.fstat(fd)
    except OSError as exc:
        raise BrokerBoundaryError("https fixture descriptor is not open") from exc
    return _HttpsFixtureState(fd, pem, tuple(addresses))


def _read_https_control(
    channel: socket.socket, serve: _HttpsServeState
) -> TransportTermination | None:
    """HTTPS-flavor control read: REVOKE/EOF plus the conformance fixture.

    M4B-1's ``_read_control`` is deliberately untouched; the fixture verb is
    recognized only here, on the HTTPS serve loop, and is accepted at most
    once and only before the first accepted connection.
    """
    try:
        payload, ancillary, flags, _address = channel.recvmsg(
            MAX_HTTPS_CONTROL_BYTES + 1,
            socket.CMSG_SPACE(array_itemsize() * 2),
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

    def close_received() -> None:
        for received_fd in received_fds:
            try:
                os.close(received_fd)
            except OSError:
                pass
        received_fds.clear()

    if payload.startswith(CONTROL_HTTPS_FIXTURE):
        if (
            len(received_fds) != 1
            or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or serve.fixture is not None
            or serve.connections_accepted
        ):
            close_received()
            return TransportTermination.MALFORMED_CONTROL
        fixture_fd = received_fds.pop()
        try:
            serve.fixture = _parse_https_fixture(
                payload[len(CONTROL_HTTPS_FIXTURE):], fixture_fd
            )
        except BrokerBoundaryError:
            try:
                os.close(fixture_fd)
            except OSError:
                pass
            return TransportTermination.MALFORMED_CONTROL
        return None
    close_received()
    if ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        return TransportTermination.MALFORMED_CONTROL
    if payload == b"":
        return TransportTermination.CONTROL_EOF
    if payload == CONTROL_REVOKE:
        return TransportTermination.REVOKED
    return TransportTermination.MALFORMED_CONTROL


def _read_connect_head(
    serve: _HttpsServeState, worker: socket.socket
) -> tuple[bytes | None, str]:
    """Bounded byte-at-a-time CONNECT head read (no over-read into TLS)."""
    head = bytearray()
    deadline = time.monotonic() + CONNECT_STAGE_TIMEOUT_SECONDS
    worker.settimeout(HTTPS_STAGE_SLICE_SECONDS)
    while b"\r\n\r\n" not in head:
        if serve.expired():
            return None, "expired"
        if serve.abort.is_set():
            return None, "aborted"
        if len(head) >= CONNECT_HEAD_MAX_BYTES:
            return None, "head_bound_exceeded"
        if time.monotonic() >= deadline:
            return None, "timeout"
        try:
            chunk = worker.recv(1)
        except socket.timeout:
            continue
        except OSError:
            return None, "socket_error"
        if chunk == b"":
            return None, "eof"
        head += chunk
    return bytes(head), "ok"


def _parse_connect_authority(head: bytes) -> tuple[str | None, str]:
    """Strict raw-byte CONNECT-authority parse; the only CONNECT on the wire."""
    from .network_https import NormalizationError, normalize_https_authority

    lines = head[:-4].split(b"\r\n")
    request_line = lines[0]
    parts = request_line.split(b" ")
    if len(parts) != 3 or any(part == b"" for part in parts):
        return None, "request_line_malformed"
    method, authority, version = parts
    if method != b"CONNECT":
        return None, "method_not_connect"
    if version != b"HTTP/1.1":
        return None, "version_rejected"
    try:
        hostname = normalize_https_authority(authority)
    except NormalizationError as exc:
        return None, f"authority_{exc.code.value}"
    if len(lines) - 1 > CONNECT_MAX_HEADER_LINES:
        return None, "too_many_headers"
    for line in lines[1:]:
        if not line:
            return None, "header_malformed"
        if line[0] in (0x20, 0x09):
            return None, "obs_fold_rejected"
        colon = line.find(b":")
        if colon == -1:
            return None, "header_malformed"
        name = line[:colon]
        if not name or any(byte not in _HTTPS_TCHAR for byte in name):
            return None, "header_name_invalid"
        rest = line[colon + 1:]
        if rest.startswith(b" "):
            rest = rest[1:]
        if (
            any(byte < 0x20 or byte > 0x7E for byte in rest)
            or rest.startswith(b" ")
            or rest.endswith(b" ")
        ):
            return None, "header_value_invalid"
    return hostname, "ok"


def _best_effort_plain_send(worker: socket.socket, payload: bytes) -> bool:
    try:
        worker.settimeout(HTTPS_STAGE_SLICE_SECONDS)
        worker.sendall(payload)
    except OSError:
        return False
    return True


class _OriginLeg:
    """One established origin leg plus its evidence fields."""

    def __init__(
        self,
        *,
        sock: socket.socket,
        tls_version: str,
        alpn: str,
        peer_address: str,
        peer_port: int,
        address_policy_version: str,
        synthetic: bool,
    ) -> None:
        self.sock = sock
        self.tls_version = tls_version
        self.alpn = alpn
        self.peer_address = peer_address
        self.peer_port = peer_port
        self.address_policy_version = address_policy_version
        self.synthetic = synthetic


def _establish_fixture_origin(
    serve: _HttpsServeState,
    runtime: _HttpsConnectionRuntime,
) -> tuple[_OriginLeg | None, HttpsConnectionStage, str]:
    """Synthetic origin: validated declared set + TLS over the armed socket."""
    import ipaddress

    from .network_origin import OriginTrustRoots, open_origin_tls
    from .network_resolution import ResolvedAddress
    from .special_addresses import (
        ADDRESS_POLICY_VERSION,
        AddressDecision,
        validate_address,
    )

    fixture = serve.fixture
    if fixture is None:
        return None, HttpsConnectionStage.ORIGIN_CONNECT, "origin_fixture_absent"
    if fixture.spent:
        return None, HttpsConnectionStage.ORIGIN_CONNECT, "origin_fixture_spent"
    resolved: list[ResolvedAddress] = []
    prohibited = 0
    for text in fixture.addresses:
        address = ipaddress.ip_address(text)
        verdict = validate_address(address)
        if verdict.decision is AddressDecision.ALLOWED:
            family = (
                socket.AF_INET
                if isinstance(address, ipaddress.IPv4Address)
                else socket.AF_INET6
            )
            resolved.append(
                ResolvedAddress(
                    address=address, family=family, port=443, verdict=verdict
                )
            )
        else:
            prohibited += 1
    if prohibited or not resolved:
        return None, HttpsConnectionStage.RESOLUTION, "origin_prohibited_address"
    fixture.spent = True
    sock = _wrap_owned_socket(os.dup(fixture.fd), "https fixture origin")
    runtime.set_origin(sock)
    outcome = open_origin_tls(
        sock,
        serve.approved_hostname,
        trust_roots=OriginTrustRoots(fixture.ca_certs_pem),
    )
    if not outcome.established:
        return (
            None,
            HttpsConnectionStage.ORIGIN_TLS,
            f"origin_{outcome.code.value}",
        )
    assert outcome.channel is not None
    runtime.set_origin(outcome.channel.tls_socket)
    peer = resolved[0]
    return (
        _OriginLeg(
            sock=outcome.channel.tls_socket,
            tls_version=outcome.channel.tls_version,
            alpn=outcome.channel.alpn_protocol,
            peer_address=str(peer.address),
            peer_port=peer.port,
            address_policy_version=ADDRESS_POLICY_VERSION,
            synthetic=True,
        ),
        HttpsConnectionStage.ORIGIN_TLS,
        "ok",
    )


def _establish_origin(
    serve: _HttpsServeState,
    runtime: _HttpsConnectionRuntime,
) -> tuple[_OriginLeg | None, HttpsConnectionStage, str]:
    """Resolve once, connect numeric, authenticate origin TLS (or fixture)."""
    from .network_origin import OriginHTTPSCode, open_origin_https
    from .network_resolution import resolve_all_once

    if serve.fixture is not None:
        return _establish_fixture_origin(serve, runtime)
    resolution = resolve_all_once(serve.approved_hostname)
    outcome = open_origin_https(resolution, serve.grant)
    if not outcome.established:
        stage = {
            OriginHTTPSCode.RESOLUTION_DENIED: HttpsConnectionStage.RESOLUTION,
            OriginHTTPSCode.HOSTNAME_MISMATCH: HttpsConnectionStage.RESOLUTION,
            OriginHTTPSCode.INVALID_ADDRESS_SET: HttpsConnectionStage.RESOLUTION,
            OriginHTTPSCode.CONNECT_FAILED: HttpsConnectionStage.ORIGIN_CONNECT,
        }.get(outcome.code, HttpsConnectionStage.ORIGIN_TLS)
        return None, stage, f"origin_{outcome.code.value}"
    assert outcome.channel is not None
    runtime.set_origin(outcome.channel.tls_socket)
    return (
        _OriginLeg(
            sock=outcome.channel.tls_socket,
            tls_version=outcome.channel.tls_version,
            alpn=outcome.channel.alpn_protocol,
            peer_address=outcome.channel.peer_address,
            peer_port=outcome.channel.peer_port,
            address_policy_version=resolution.policy_version,
            synthetic=False,
        ),
        HttpsConnectionStage.ORIGIN_TLS,
        "ok",
    )


def _relay_origin_response(
    serve: _HttpsServeState,
    runtime: _HttpsConnectionRuntime,
    channel: Any,
    origin: _OriginLeg,
    counters: dict[str, int],
) -> tuple[str, str]:
    """Bounded verbatim origin->worker relay; h11 CLIENT is framing-only.

    The origin response is relayed byte-exact (nothing stripped, nothing
    logged); the h11 client machine is used ONLY to delimit the response
    (EndOfMessage) so the persistent connection can cycle.  A response h11
    cannot frame fails the connection closed.
    """
    import h11

    from .network_tls import ChannelError

    framer = h11.Connection(h11.CLIENT)
    sock = origin.sock
    while True:
        if serve.expired():
            return "expired", "expired"
        if serve.abort.is_set():
            return "revoked", "aborted"
        budget = serve.accountant.read_budget()
        if budget <= 0:
            return "byte_limit", "byte_limit"
        sock.settimeout(HTTPS_STAGE_SLICE_SECONDS)
        try:
            chunk = sock.recv(min(RELAY_CHUNK_BYTES, budget))
        except socket.timeout:
            continue
        except OSError:
            if serve.expired():
                return "expired", "expired"
            if serve.abort.is_set():
                return "revoked", "aborted"
            return "peer_error", "origin_read_failed"
        serve.accountant.commit_read(len(chunk))
        counters["read_from_origin"] += len(chunk)
        try:
            framer.receive_data(chunk)
        except h11.LocalProtocolError:
            return "peer_error", "response_unframeable"
        completed = False
        try:
            while True:
                event = framer.next_event()
                if event is h11.NEED_DATA or event is h11.PAUSED:
                    break
                if isinstance(event, h11.EndOfMessage):
                    completed = True
                    break
        except h11.LocalProtocolError:
            return "peer_error", "response_unframeable"
        if chunk:
            try:
                channel.write(
                    chunk, timeout=HTTPS_CHANNEL_WRITE_TIMEOUT_SECONDS
                )
            except ChannelError:
                if serve.expired():
                    return "expired", "expired"
                if serve.abort.is_set():
                    return "revoked", "aborted"
                return "peer_error", "worker_write_failed"
            serve.accountant.commit_origin_to_worker(len(chunk))
            counters["origin_to_worker"] += len(chunk)
        if completed:
            # An EOF-delimited response completes here; the origin leg is
            # spent afterwards and the NEXT request ends the connection.
            return ("done_eof" if chunk == b"" else "done"), "ok"
        if chunk == b"":
            # EOF before the framer could delimit the response: fail closed.
            return "peer_error", "origin_truncated_response"


def _serve_https_connection(
    serve: _HttpsServeState,
    runtime: _HttpsConnectionRuntime,
    connection_index: int,
) -> None:
    """Serve one accepted worker connection through the full trust pipeline."""
    from . import network_clienthello as nch
    from . import network_tls as ntls
    from .network_http import RequestComplete, RequestHead, StrictHttpParser
    from .network_https import (
        NormalizationError,
        authorize_grant,
        normalize_https_authority,
        verify_identity_chain,
    )

    worker = runtime._worker_sock
    assert worker is not None
    stage = HttpsConnectionStage.CONNECT
    connect_authority: str | None = None
    worker_sni_raw: str | None = None
    http_host: str | None = None
    origin_tls_name: str | None = None
    worker_tls_version: str | None = None
    worker_alpn: str | None = None
    origin_tls_version: str | None = None
    origin_alpn: str | None = None
    origin_peer_address: str | None = None
    origin_peer_port = 0
    address_policy_version = ""
    # The synthetic marking follows the ARMED fixture (non-production mode
    # for the whole launch), not merely connections that reached the origin.
    synthetic = serve.fixture is not None
    requests_completed = 0
    counters = {
        "read_from_worker": 0,
        "read_from_origin": 0,
        "worker_to_origin": 0,
        "origin_to_worker": 0,
    }
    termination = HttpsConnectionTermination.DENIED
    detail = "denied"

    def finish() -> None:
        from .special_addresses import ADDRESS_POLICY_VERSION

        total = counters["worker_to_origin"] + counters["origin_to_worker"]
        accounted = counters["read_from_worker"] + counters["read_from_origin"]
        if serve.grant is None:
            # Deny-all posture: no grant exists to verify an identity chain
            # against; every connection was denied before any trust stage.
            identity = "no_grant"
        else:
            chain = verify_identity_chain(
                serve.grant,
                connect_authority=connect_authority,
                worker_sni=worker_sni_raw,
                http_host=http_host,
                origin_tls_name=origin_tls_name,
                evidence_name=serve.approved_hostname,
            )
            identity = chain.code.value
            if not chain.verified and chain.stage is not None:
                identity = f"{chain.code.value}:{chain.stage.value}"
        record = HttpsConnectionRecord(
            version=HTTPS_EVIDENCE_VERSION,
            event=HTTPS_CONNECTION_EVENT,
            task_id=serve.policy.task_id,
            task_generation=serve.policy.task_generation,
            launch_nonce=serve.policy.launch_nonce,
            policy_digest=transport_policy_digest(serve.policy),
            network_policy_digest=serve.https_state.network_policy_digest,
            address_policy_version=address_policy_version or ADDRESS_POLICY_VERSION,
            connection_index=connection_index,
            stage_reached=stage,
            terminal_reason=termination,
            detail=detail,
            approved_hostname=serve.approved_hostname,
            connect_authority=_evidence_hostname(connect_authority),
            worker_sni=_evidence_hostname(worker_sni_raw),
            http_host=_evidence_hostname(http_host),
            origin_tls_name=_evidence_hostname(origin_tls_name),
            identity_chain=identity,
            worker_tls_version=worker_tls_version,
            worker_alpn=worker_alpn,
            origin_tls_version=origin_tls_version,
            origin_alpn=origin_alpn,
            origin_peer_address=origin_peer_address,
            origin_peer_port=origin_peer_port,
            synthetic_origin=synthetic,
            requests_completed=requests_completed,
            accounted_bytes=accounted,
            worker_to_origin_bytes=counters["worker_to_origin"],
            origin_to_worker_bytes=counters["origin_to_worker"],
            total_bytes=total,
            discarded_unsent_bytes=accounted - total,
            observed_at_monotonic_ns=time.monotonic_ns(),
        )
        try:
            serve.emit_record(record)
        except BrokerBoundaryError as exc:
            serve.thread_errors.append(exc)
        runtime.abort()

    try:
        head, read_code = _read_connect_head(serve, worker)
        if head is None:
            if read_code == "aborted":
                termination = HttpsConnectionTermination.REVOKED
            elif read_code == "expired":
                termination = HttpsConnectionTermination.EXPIRED
            detail = f"connect_{read_code}"
            return
        authority, parse_code = _parse_connect_authority(head)
        if authority is None:
            detail = f"connect_{parse_code}"
            return
        connect_authority = authority

        stage = HttpsConnectionStage.AUTHORIZATION
        authorization = authorize_grant(
            serve.network_policy,
            authority,
            at_monotonic_ns=time.monotonic_ns(),
        )
        if not authorization.authorized:
            detail = f"authorization_{authorization.code.value}"
            _best_effort_plain_send(worker, HTTPS_CONNECT_RESPONSE_DENIED)
            return
        # The 200 response is sent ONLY after policy permits the TLS attempt.
        if not _best_effort_plain_send(worker, HTTPS_CONNECT_RESPONSE_OK):
            termination = HttpsConnectionTermination.PEER_ERROR
            detail = "connect_response_failed"
            return

        stage = HttpsConnectionStage.GATE
        gate = nch.run_gate_on_socket(worker, guard=serve.guard)
        if not gate.accepted:
            if serve.expired():
                termination = HttpsConnectionTermination.EXPIRED
                detail = "gate_expired"
            elif serve.abort.is_set():
                termination = HttpsConnectionTermination.REVOKED
                detail = "gate_aborted"
            else:
                detail = f"gate_{_sanitize_gate_reason(gate.reason)}"
            return

        stage = HttpsConnectionStage.WORKER_TLS
        # The per-connection SNI policy installs on the shared task-leaf
        # context, so configuration + handshake are serialized broker-wide.
        with serve.tls_configure_lock:
            prepared = ntls.configure_worker_server_context(
                serve.https_state.server_context, serve.approved_hostname
            )
            outcome = ntls.terminate_worker_tls(worker, gate, prepared)
        worker_sni_raw = outcome.sni_seen[0] if outcome.sni_seen else None
        worker_tls_version = outcome.tls_version
        worker_alpn = outcome.alpn_selected
        if not outcome.established:
            if serve.expired():
                termination = HttpsConnectionTermination.EXPIRED
                detail = "worker_tls_expired"
            elif serve.abort.is_set():
                termination = HttpsConnectionTermination.REVOKED
                detail = "worker_tls_aborted"
            else:
                detail = f"worker_tls_{outcome.code.value}"
            return
        channel = outcome.channel
        assert channel is not None
        runtime.set_channel(channel)

        stage = HttpsConnectionStage.HTTP
        parser = StrictHttpParser(serve.grant.purpose.http_policy())
        origin: _OriginLeg | None = None
        origin_eof = False
        http_done = False
        while not http_done:
            if serve.expired():
                termination, detail = (
                    HttpsConnectionTermination.EXPIRED,
                    "expired",
                )
                break
            if serve.abort.is_set():
                termination, detail = (
                    HttpsConnectionTermination.REVOKED,
                    "aborted",
                )
                break
            budget = serve.accountant.read_budget()
            if budget <= 0:
                termination, detail = (
                    HttpsConnectionTermination.BYTE_LIMIT,
                    "byte_limit",
                )
                serve.byte_limit_reached = True
                break
            try:
                data = channel.read(
                    min(RELAY_CHUNK_BYTES, budget),
                    timeout=HTTPS_STAGE_SLICE_SECONDS,
                )
            except ntls.ChannelTimeoutError:
                continue
            except ntls.ChannelError:
                if serve.expired():
                    termination, detail = (
                        HttpsConnectionTermination.EXPIRED,
                        "expired",
                    )
                elif serve.abort.is_set():
                    termination, detail = (
                        HttpsConnectionTermination.REVOKED,
                        "aborted",
                    )
                else:
                    termination, detail = (
                        HttpsConnectionTermination.PEER_ERROR,
                        "channel_error",
                    )
                break
            if data == b"":
                termination, detail = (
                    HttpsConnectionTermination.COMPLETED,
                    "worker_closed",
                )
                break
            serve.accountant.commit_read(len(data))
            counters["read_from_worker"] += len(data)
            feed = parser.feed(data)
            completed_wires = list(parser.pop_completed_wire())
            denial: str | None = None
            denial_stage: HttpsConnectionStage | None = None
            for event in feed.events:
                if denial is not None:
                    break
                if isinstance(event, RequestHead):
                    try:
                        head_host = normalize_https_authority(event.host)
                    except NormalizationError:
                        denial = "http_host_rejected"
                        break
                    if http_host is None:
                        http_host = head_host
                    if head_host != serve.approved_hostname:
                        denial = "http_host_mismatch"
                        break
                    reauthorization = authorize_grant(
                        serve.network_policy,
                        head_host,
                        at_monotonic_ns=time.monotonic_ns(),
                    )
                    if not reauthorization.authorized:
                        denial = f"reauthorization_{reauthorization.code.value}"
                        break
                elif isinstance(event, RequestComplete):
                    if not completed_wires:
                        denial = "http_internal_wire_accounting"
                        break
                    wire = completed_wires.pop(0)
                    if origin is None:
                        leg, leg_stage, leg_detail = _establish_origin(
                            serve, runtime
                        )
                        if leg is None:
                            denial = leg_detail
                            denial_stage = leg_stage
                            break
                        origin = leg
                        origin_tls_name = serve.approved_hostname
                        origin_tls_version = leg.tls_version
                        origin_alpn = leg.alpn
                        origin_peer_address = leg.peer_address
                        origin_peer_port = leg.peer_port
                        address_policy_version = leg.address_policy_version
                    if origin_eof:
                        termination = HttpsConnectionTermination.COMPLETED
                        detail = "origin_closed"
                        http_done = True
                        break
                    stage = HttpsConnectionStage.REQUEST_FORWARD
                    try:
                        origin.sock.settimeout(HTTPS_STAGE_SLICE_SECONDS)
                        origin.sock.sendall(wire)
                    except OSError:
                        if serve.expired():
                            termination = HttpsConnectionTermination.EXPIRED
                            detail = "expired"
                        elif serve.abort.is_set():
                            termination = HttpsConnectionTermination.REVOKED
                            detail = "aborted"
                        else:
                            termination = HttpsConnectionTermination.PEER_ERROR
                            detail = "origin_write_failed"
                        http_done = True
                        break
                    serve.accountant.commit_worker_to_origin(len(wire))
                    counters["worker_to_origin"] += len(wire)
                    requests_completed += 1
                    stage = HttpsConnectionStage.RESPONSE_RELAY
                    relay_status, relay_detail = _relay_origin_response(
                        serve, runtime, channel, origin, counters
                    )
                    stage = HttpsConnectionStage.HTTP
                    if relay_status == "done":
                        continue
                    if relay_status == "done_eof":
                        origin_eof = True
                        continue
                    if relay_status == "peer_error" and relay_detail == (
                        "origin_truncated_response"
                    ):
                        termination = HttpsConnectionTermination.PEER_ERROR
                        detail = relay_detail
                        http_done = True
                        break
                    if relay_status == "revoked":
                        termination = HttpsConnectionTermination.REVOKED
                    elif relay_status == "expired":
                        termination = HttpsConnectionTermination.EXPIRED
                    elif relay_status == "byte_limit":
                        termination = HttpsConnectionTermination.BYTE_LIMIT
                        serve.byte_limit_reached = True
                    else:
                        termination = HttpsConnectionTermination.PEER_ERROR
                    detail = relay_detail
                    http_done = True
                    break
            if http_done:
                break
            if denial is not None:
                if denial_stage is not None:
                    stage = denial_stage
                detail = denial
                termination = HttpsConnectionTermination.DENIED
                break
            if feed.rejection is not None:
                detail = f"http_{feed.rejection.code.value}"
                termination = HttpsConnectionTermination.DENIED
                break
    except BaseException as exc:  # noqa: BLE001 — fail closed per connection
        termination = HttpsConnectionTermination.PEER_ERROR
        detail = f"internal_{type(exc).__name__}"
    finally:
        finish()


def _build_https_terminal(
    serve: _HttpsServeState, reason: TransportTermination
) -> HttpsTransportTerminal:
    observed_at = time.monotonic_ns()
    if observed_at >= serve.policy.expires_at_monotonic_ns:
        reason = TransportTermination.EXPIRED
    accounted, worker_to_origin, origin_to_worker = serve.accountant.snapshot()
    total = worker_to_origin + origin_to_worker
    if accounted < total or accounted > serve.accountant.limit:
        raise BrokerBoundaryError("https serve accounting exceeded its authority")
    if serve.records_emitted > serve.connection_limit:
        raise BrokerBoundaryError("https serve exceeded its connection authority")
    return HttpsTransportTerminal(
        version=HTTPS_EVIDENCE_VERSION,
        event=HTTPS_TERMINAL_EVENT,
        task_id=serve.policy.task_id,
        task_generation=serve.policy.task_generation,
        launch_nonce=serve.policy.launch_nonce,
        policy_digest=transport_policy_digest(serve.policy),
        network_policy_digest=serve.https_state.network_policy_digest,
        observed_at_monotonic_ns=observed_at,
        connection_count=serve.records_emitted,
        accounted_bytes=accounted,
        worker_to_origin_bytes=worker_to_origin,
        origin_to_worker_bytes=origin_to_worker,
        total_bytes=total,
        discarded_unsent_bytes=accounted - total,
        terminal_reason=reason,
        synthetic_origin=serve.fixture is not None,
    )


def _serve_https(
    policy: TransportPolicy,
    https_state: _HttpsMaterialState,
    listener: socket.socket,
    control: socket.socket,
) -> HttpsTransportTerminal:
    """Bounded accept loop: listener + control on the main selector thread."""
    serve = _HttpsServeState(policy, https_state, control.fileno())
    selector = selectors.DefaultSelector()
    reason: TransportTermination | None = None
    try:
        listener.setblocking(False)
        control.setblocking(False)
        selector.register(listener, selectors.EVENT_READ, "listener")
        selector.register(control, selectors.EVENT_READ, "control")
        while True:
            now = time.monotonic_ns()
            if now >= policy.expires_at_monotonic_ns:
                reason = TransportTermination.EXPIRED
                break
            timeout = min(
                SELECTOR_SLICE_SECONDS,
                (policy.expires_at_monotonic_ns - now) / 1_000_000_000,
            )
            events = selector.select(timeout)
            if time.monotonic_ns() >= policy.expires_at_monotonic_ns:
                reason = TransportTermination.EXPIRED
                break
            for key, _mask in events:
                if key.data != "control":
                    continue
                outcome = _read_https_control(control, serve)
                if outcome is not None:
                    reason = outcome
                    break
            if reason is not None:
                break
            for key, _mask in events:
                if key.data != "listener":
                    continue
                try:
                    accepted, _address = listener.accept()
                except BlockingIOError:
                    continue
                except OSError:
                    reason = TransportTermination.PEER_ERROR
                    break
                if serve.connections_accepted >= serve.connection_limit:
                    _abort_socket(accepted)
                    reason = TransportTermination.CONNECTION_LIMIT
                    break
                serve.connections_accepted += 1
                runtime = _HttpsConnectionRuntime(accepted)
                serve.runtimes.append(runtime)
                thread = threading.Thread(
                    target=_serve_https_connection,
                    args=(serve, runtime, serve.connections_accepted),
                    name=f"m4b2-https-conn-{serve.connections_accepted}",
                    daemon=True,
                )
                serve.threads.append(thread)
                thread.start()
            if reason is not None:
                break
            if serve.byte_limit_reached:
                reason = TransportTermination.BYTE_LIMIT
                break
        serve.abort_connections()
        for thread in serve.threads:
            thread.join(timeout=HTTPS_THREAD_JOIN_GRACE_SECONDS)
        if serve.thread_errors:
            raise serve.thread_errors[0]
        if reason is None:
            reason = TransportTermination.PEER_ERROR
        return _build_https_terminal(serve, reason)
    finally:
        selector.close()
        serve.abort.set()
        for runtime in tuple(serve.runtimes):
            runtime.abort()


def serve_https_transport(
    policy: TransportPolicy,
    https_state: _HttpsMaterialState,
    *,
    listener_fd: int,
    control_fd: int,
) -> HttpsTransportTerminal:
    """Own and close the supplied capabilities while serving gated HTTPS."""
    listener: socket.socket | None = None
    control: socket.socket | None = None
    owned_raw = {
        fd for fd in (listener_fd, control_fd) if type(fd) is int and fd >= 0
    }
    try:
        if type(policy) is not TransportPolicy:
            raise BrokerBoundaryError("transport policy has the wrong type")
        if type(https_state) is not _HttpsMaterialState:
            raise BrokerBoundaryError("https material state has the wrong type")
        if policy.mode is not TransportMode.DENY:
            raise BrokerBoundaryError("https serve requires a DENY transport policy")
        if len(https_state.network_policy.grants) > 1:
            raise BrokerBoundaryError("https serve permits at most one grant")
        now = time.monotonic_ns()
        if now < policy.activated_at_monotonic_ns:
            raise BrokerBoundaryError("transport policy is not active")
        if now >= policy.expires_at_monotonic_ns:
            return _build_https_terminal_expired(policy, https_state)
        fds = (listener_fd, control_fd)
        if (
            any(type(fd) is not int or fd < 0 for fd in fds)
            or len(set(fds)) != len(fds)
        ):
            raise BrokerBoundaryError("https transport descriptor roles collide")
        listener_evidence(listener_fd)
        _validate_connected_unix_socket(
            control_fd, socket.SOCK_SEQPACKET, "broker control"
        )
        listener = _wrap_owned_socket(listener_fd, "listener")
        owned_raw.discard(listener_fd)
        control = _wrap_owned_socket(control_fd, "control")
        owned_raw.discard(control_fd)
        return _serve_https(policy, https_state, listener, control)
    finally:
        _close_socket(listener)
        # Closing this owned alias must not shutdown the shared socket
        # description; a broker-held duplicate emits the terminal record.
        _close_socket(control)
        _close_owned(owned_raw)


def _build_https_terminal_expired(
    policy: TransportPolicy, https_state: _HttpsMaterialState
) -> HttpsTransportTerminal:
    return HttpsTransportTerminal(
        version=HTTPS_EVIDENCE_VERSION,
        event=HTTPS_TERMINAL_EVENT,
        task_id=policy.task_id,
        task_generation=policy.task_generation,
        launch_nonce=policy.launch_nonce,
        policy_digest=transport_policy_digest(policy),
        network_policy_digest=https_state.network_policy_digest,
        observed_at_monotonic_ns=time.monotonic_ns(),
        connection_count=0,
        accounted_bytes=0,
        worker_to_origin_bytes=0,
        origin_to_worker_bytes=0,
        total_bytes=0,
        discarded_unsent_bytes=0,
        terminal_reason=TransportTermination.EXPIRED,
        synthetic_origin=False,
    )


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


@dataclass(frozen=True)
class _HttpsMaterialState:
    """Verified M4B-2 material held by the broker after source-fd closure."""

    network_policy: Any
    network_policy_digest: str
    binding: Any
    server_context: Any
    network_policy_seals: int = 0
    material_seals_verified: bool = False
    leaf_self_audit_passed: bool = False


def _run_https_startup_probe(https_state: _HttpsMaterialState) -> None:
    """Fail-closed security startup probe for the HTTPS-flavor broker.

    Runs AFTER sealed-material adoption and BEFORE the ready record is
    emitted.  Any failure raises :class:`BrokerBoundaryError`, so the broker
    exits non-zero WITHOUT readiness and the controller's liveness/ordering
    gates fail the launch closed before hostile exec.

    Legs (all TLS posture lives in :mod:`agenticos.sandbox.network_tls`;
    this module keeps its no-ssl-import boundary):

    1. ClientHello gate self-test, OpenSSL identity, OP_NO_RENEGOTIATION
       settable, host behavior probes, and libssl ECH-machinery absence —
       delegated to ``network_tls.run_tls_startup_self_test`` (never
       duplicated here).  The expected OpenSSL identity is the value SEALED
       into the NetworkPolicy by the controller from the host qualification
       manifest it gated on — an authenticated channel, not an argv string.
    2. Worker context posture — delegated to
       ``network_tls.run_worker_context_startup_probe``: the adopted context
       hardens (fresh exact-hostname SNI policy, TLS>=1.2),
       OP_NO_RENEGOTIATION is in its effective options, and its ALPN
       behavior is exactly http/1.1 (a real handshake offering http/1.1
       selects it; an h2-only offer selects nothing).
    3. Adoption proofs held in the material state: the leaf loading
       self-audit ran, every material source passed the functional
       sealed-memfd check, and the recorded network-policy seals are complete.
    """
    from . import network_tls as ntls

    if type(https_state) is not _HttpsMaterialState:
        raise BrokerBoundaryError("https startup probe requires adopted material")
    network_policy = https_state.network_policy
    if https_state.binding is None:
        raise BrokerBoundaryError("https startup probe requires a verified binding")
    try:
        ntls.run_tls_startup_self_test(
            recorded_openssl_version=network_policy.openssl_runtime_identity
        )
        ntls.run_worker_context_startup_probe(
            https_state.server_context, https_state.binding.hostname
        )
    except ntls.StartupSelfTestError as exc:
        raise BrokerBoundaryError("https startup probe self-test failed") from exc

    if not https_state.leaf_self_audit_passed:
        raise BrokerBoundaryError("leaf loading self-audit did not run at adoption")
    if not https_state.material_seals_verified:
        raise BrokerBoundaryError(
            "material sealed-memfd functional check did not run at adoption"
        )
    required = (
        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    )
    if https_state.network_policy_seals & required != required:
        raise BrokerBoundaryError(
            "recorded network policy seals are incomplete at probe time"
        )


def _adopt_https_material(
    contract: BrokerContract, sealed: VerifiedSealedPolicy
) -> _HttpsMaterialState:
    """Verify sealed HTTPS material, load the leaf context, close every source.

    Fail closed anywhere: a stale or mismatched sealed NetworkPolicy, a
    binding that disagrees with the transport authority, or a leaf that does
    not authenticate under the sealed task CA means no readiness record is
    ever emitted.  Before closure every material source descriptor must also
    pass the FUNCTIONAL sealed-memfd check (verify_memfd_sealed: all four
    immutable seals present and writes denied).  On success every material
    source descriptor is closed and PROVEN closed (EBADF), so the
    post-readiness descriptor census contains no certificate, key, or
    policy source.
    """
    if type(contract) is not BrokerContract or contract.https is None:
        raise BrokerBoundaryError("https material adoption requires the https contract")
    if type(sealed) is not VerifiedSealedPolicy:
        raise BrokerBoundaryError("sealed transport policy has the wrong type")
    from .cert_helper import (
        CertHelperError,
        load_leaf_ssl_context,
        verify_task_material,
    )
    from .network_https import (
        NetworkPolicySealError,
        read_sealed_network_policy_fd,
    )

    https = contract.https
    _require_distinct_fd_identities((*contract.capability_fds, *https.material_fds))
    try:
        net_sealed = read_sealed_network_policy_fd(https.network_policy_fd)
    except NetworkPolicySealError as exc:
        raise BrokerBoundaryError(
            "sealed network policy verification failed"
        ) from exc
    network_policy = net_sealed.policy
    policy = sealed.policy
    if (
        network_policy.task_id != policy.task_id
        or network_policy.task_generation != policy.task_generation
        or network_policy.launch_nonce != policy.launch_nonce
    ):
        raise BrokerBoundaryError(
            "network policy task context does not match transport authority"
        )
    if len(network_policy.grants) > 1:
        raise BrokerBoundaryError(
            "https flavor permits at most one network grant"
        )
    # Zero grants is the deny-all posture: adoption still authenticates the
    # sealed material (the binding's own committed hostname is adopted), the
    # broker becomes ready, and every CONNECT is denied by authorize_grant.
    hostname = (
        network_policy.grants[0].hostname if network_policy.grants else None
    )
    try:
        verified = verify_task_material(
            ca_cert_fd=https.ca_cert_fd,
            leaf_cert_fd=https.leaf_cert_fd,
            leaf_key_fd=https.leaf_key_fd,
            binding_fd=https.binding_fd,
            task_id=policy.task_id,
            task_generation=policy.task_generation,
            launch_nonce=policy.launch_nonce,
            hostname=hostname,
            policy_digest=sealed.digest,
        )
    except CertHelperError as exc:
        raise BrokerBoundaryError(
            "task certificate material did not authenticate"
        ) from exc
    if verified.binding.ca_cert_sha256 != network_policy.task_ca_certificate_digest:
        raise BrokerBoundaryError(
            "network policy does not commit the sealed task CA"
        )
    try:
        context = load_leaf_ssl_context(
            ca_cert_fd=https.ca_cert_fd,
            leaf_cert_fd=https.leaf_cert_fd,
            leaf_key_fd=https.leaf_key_fd,
            binding_fd=https.binding_fd,
            task_id=policy.task_id,
            task_generation=policy.task_generation,
            launch_nonce=policy.launch_nonce,
            hostname=hostname,
            policy_digest=sealed.digest,
        )
    except CertHelperError as exc:
        raise BrokerBoundaryError("leaf TLS context could not be loaded") from exc
    # Functional sealed-memfd check on every adopted source descriptor
    # BEFORE closure: all four immutable seals present AND writes denied
    # (the structural seal-bit verification already ran inside
    # read_sealed_network_policy_fd / verify_task_material; this proves the
    # kernel actually enforces them on these objects).
    from .host_qualification import HostQualificationError, verify_memfd_sealed

    for fd in https.material_fds:
        try:
            verify_memfd_sealed(fd)
        except HostQualificationError as exc:
            raise BrokerBoundaryError(
                "https material object failed the functional seal check"
            ) from exc
    for fd in https.material_fds:
        os.close(fd)
    for fd in https.material_fds:
        try:
            fcntl.fcntl(fd, fcntl.F_GETFD)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                continue
            raise BrokerBoundaryError(
                "https material descriptor closure could not be proven"
            ) from exc
        raise BrokerBoundaryError("https material descriptor survived closure")
    return _HttpsMaterialState(
        network_policy=network_policy,
        network_policy_digest=net_sealed.digest,
        binding=verified.binding,
        server_context=context,
        network_policy_seals=net_sealed.seals,
        material_seals_verified=True,
        leaf_self_audit_passed=True,
    )


def broker_main(contract: BrokerContract) -> NoReturn:
    """Verify, adopt once, announce once, and serve until fail-closed teardown."""
    if type(contract) is not BrokerContract:
        raise BrokerBoundaryError("broker contract has the wrong type")
    owned = set(contract.entry_fds)
    adopted_fd: int | None = None
    https_state: _HttpsMaterialState | None = None
    try:
        restore_contract_cloexec(contract)
        try:
            sealed = read_sealed_policy_fd(contract.policy_fd)
        except NetworkIdentityError as exc:
            raise BrokerBoundaryError("sealed policy verification failed") from exc
        if contract.https is not None:
            https_state = _adopt_https_material(contract, sealed)
            for fd in contract.https.material_fds:
                owned.discard(fd)
            # Fail-closed security startup probe: after adoption, before any
            # readiness signal.  A failure here raises BrokerBoundaryError,
            # so no ready record is ever emitted and the controller fails
            # the launch closed before hostile exec.
            _run_https_startup_probe(https_state)
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
        if sealed.policy.mode is TransportMode.DENY:
            if https_state is not None:
                terminal_control_fd = _duplicate_cloexec(control_fd)
                try:
                    terminal = serve_https_transport(
                        sealed.policy,
                        https_state,
                        listener_fd=relay_listener_fd,
                        control_fd=control_fd,
                    )
                    if type(terminal) is not HttpsTransportTerminal:
                        raise BrokerBoundaryError(
                            "https transport did not return terminal evidence"
                        )
                    _emit_https_packet(
                        terminal_control_fd, terminal.to_bytes(), final=True
                    )
                    termination = terminal.terminal_reason
                finally:
                    if terminal_control_fd >= 0:
                        os.close(terminal_control_fd)
            else:
                emit_transport_observation(
                    control_fd,
                    build_deny_transport_observation(
                        sealed.policy, policy_digest=sealed.digest
                    ),
                )
                termination = serve_transport(
                    sealed.policy,
                    listener_fd=relay_listener_fd,
                    fixture_fd=fixture_fd,
                    control_fd=control_fd,
                )
        else:
            terminal_control_fd = _duplicate_cloexec(control_fd)
            try:
                observation = serve_transport(
                    sealed.policy,
                    listener_fd=relay_listener_fd,
                    fixture_fd=fixture_fd,
                    control_fd=control_fd,
                )
                if type(observation) is not NetworkTransportObservation:
                    raise BrokerBoundaryError(
                        "synthetic transport did not return terminal accounting"
                    )
                emit_transport_observation(terminal_control_fd, observation)
                if observation.terminal_reason is TransportTermination.COMPLETED:
                    terminal_channel = socket.socket(fileno=terminal_control_fd)
                    terminal_control_fd = -1
                    try:
                        termination = _deny_loop(sealed.policy, terminal_channel)
                    finally:
                        terminal_channel.close()
                else:
                    termination = observation.terminal_reason
            finally:
                if terminal_control_fd >= 0:
                    os.close(terminal_control_fd)
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
    "BROKER_HTTPS_BINDING_FD",
    "BROKER_HTTPS_CA_CERT_FD",
    "BROKER_HTTPS_LEAF_CERT_FD",
    "BROKER_HTTPS_LEAF_KEY_FD",
    "BROKER_HTTPS_MODULE_ROLES",
    "BROKER_HTTPS_POLICY_FD",
    "BROKER_HTTPS_SANDBOX_ENTRIES",
    "BROKER_POLICY_FD",
    "BROKER_ROOT",
    "BROKER_STATUS_FD",
    "BrokerBoundaryError",
    "BrokerBoundaryEvidence",
    "BrokerContract",
    "CONTROL_HTTPS_FIXTURE",
    "EnvironmentEvidence",
    "HTTPS_CONNECTION_EVENT",
    "HTTPS_EVIDENCE_VERSION",
    "HTTPS_FIXTURE_VERSION",
    "HTTPS_TERMINAL_EVENT",
    "HttpsConnectionRecord",
    "HttpsConnectionStage",
    "HttpsConnectionTermination",
    "HttpsMaterialContract",
    "HttpsTransportTerminal",
    "MAX_HTTPS_EVIDENCE_BYTES",
    "MAX_READY_BYTES",
    "MAX_TRANSPORT_OBSERVATION_BYTES",
    "NetworkBrokerReadyRecord",
    "NetworkTransportObservation",
    "ObservedFileIdentity",
    "ProcStatusEvidence",
    "SealedPolicyEvidence",
    "TransportTermination",
    "VENDOR_ENTRIES",
    "VENDOR_PATH",
    "assert_minimal_process_boundary",
    "broker_main",
    "build_deny_transport_observation",
    "emit_network_broker_ready",
    "emit_transport_observation",
    "main",
    "parse_proc_status",
    "require_minimal_proc_status",
    "restore_contract_cloexec",
    "serve_https_transport",
    "serve_transport",
    "validate_broker_environment",
    "validate_fixture_fd",
    "validate_fixed_fd_set",
]
