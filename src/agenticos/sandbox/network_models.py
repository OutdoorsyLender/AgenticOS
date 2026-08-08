"""Immutable M4B network transport capability and lifecycle evidence types."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from enum import Enum


_VERSION = "AOSNET/1"
_PROXY_HOST = "127.0.0.1"
_PROXY_PORT = 18080
_MAX_TASK_ID_LENGTH = 128
_MAX_UNSIGNED_64 = (1 << 64) - 1
_TASK_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_LOWER_HEX_32_RE = re.compile(r"[0-9a-f]{32}\Z")
_LOWER_HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
_BOOT_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


class TransportMode(str, Enum):
    """The only network modes recognized by the M4B transport contract."""

    DENY = "DENY"
    SYNTHETIC_FIXTURE_FD = "SYNTHETIC_FIXTURE_FD"


def _require_positive_int(name: str, value: object) -> None:
    if type(value) is not int or not 0 < value <= _MAX_UNSIGNED_64:
        raise ValueError(f"{name} must be a positive unsigned 64-bit integer")


def _require_task_id(value: object) -> None:
    if not isinstance(value, str) or not _TASK_ID_RE.fullmatch(value):
        raise ValueError("task_id must be a bounded ASCII identifier")


def _require_nonce(value: object) -> None:
    if not isinstance(value, str) or not _LOWER_HEX_32_RE.fullmatch(value):
        raise ValueError("launch_nonce must be exactly 32 lowercase hexadecimal characters")


def _require_boot_id(value: object, name: str) -> None:
    if type(value) is not str or not _BOOT_ID_RE.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase Linux boot ID")


@dataclass(frozen=True)
class TransportPolicy:
    """A bounded capability to use the fixed synthetic fixture proxy only."""

    version: str
    task_id: str
    task_generation: int
    launch_nonce: str
    mode: TransportMode
    proxy_host: str
    proxy_port: int
    activated_at_monotonic_ns: int
    expires_at_monotonic_ns: int
    connection_limit: int
    byte_limit: int

    def __post_init__(self) -> None:
        if self.version != _VERSION:
            raise ValueError(f"version must be {_VERSION}")
        _require_task_id(self.task_id)
        _require_positive_int("task_generation", self.task_generation)
        _require_nonce(self.launch_nonce)
        if type(self.mode) is not TransportMode:
            raise ValueError("mode must be a TransportMode")
        if (
            type(self.proxy_host) is not str
            or type(self.proxy_port) is not int
            or self.proxy_host != _PROXY_HOST
            or self.proxy_port != _PROXY_PORT
        ):
            raise ValueError("proxy listener must be exactly 127.0.0.1:18080")
        _require_positive_int("activated_at_monotonic_ns", self.activated_at_monotonic_ns)
        _require_positive_int("expires_at_monotonic_ns", self.expires_at_monotonic_ns)
        if self.expires_at_monotonic_ns <= self.activated_at_monotonic_ns:
            raise ValueError("expires_at_monotonic_ns must be after activation")
        _require_positive_int("connection_limit", self.connection_limit)
        _require_positive_int("byte_limit", self.byte_limit)


@dataclass(frozen=True)
class ListenerEvidence:
    """A bounded snapshot of an observed listening socket."""

    family: int
    socket_type: int
    address: str
    port: int
    device: int
    inode: int
    file_type: int
    netns_cookie: int
    accepting: bool

    def __post_init__(self) -> None:
        _require_positive_int("family", self.family)
        _require_positive_int("socket_type", self.socket_type)
        if not isinstance(self.address, str) or len(self.address) > 45:
            raise ValueError("address must be a bounded IP address")
        try:
            ipaddress.ip_address(self.address)
        except ValueError as exc:
            raise ValueError("address must be an IP address") from exc
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("port must be in the range 1..65535")
        _require_positive_int("device", self.device)
        _require_positive_int("inode", self.inode)
        _require_positive_int("file_type", self.file_type)
        _require_positive_int("netns_cookie", self.netns_cookie)
        if type(self.accepting) is not bool:
            raise ValueError("accepting must be a bool")


@dataclass(frozen=True)
class BrokerProcessEvidence:
    """Stable broker process identity for a later authenticated lifecycle."""

    pid: int
    start_time_ticks: int
    boot_id: str

    def __post_init__(self) -> None:
        _require_positive_int("pid", self.pid)
        _require_positive_int("start_time_ticks", self.start_time_ticks)
        _require_boot_id(self.boot_id, "boot_id")


@dataclass(frozen=True)
class BrokerReadyEvidence:
    """Explicit broker-ready proof bound to one transport capability."""

    task_id: str
    task_generation: int
    launch_nonce: str
    policy_digest: str
    broker_pid: int
    broker_start_time_ticks: int
    broker_boot_id: str
    ready_at_monotonic_ns: int

    def __post_init__(self) -> None:
        _require_task_id(self.task_id)
        _require_positive_int("task_generation", self.task_generation)
        _require_nonce(self.launch_nonce)
        if not isinstance(self.policy_digest, str) or not _LOWER_HEX_64_RE.fullmatch(
            self.policy_digest
        ):
            raise ValueError("policy_digest must be exactly 64 lowercase hexadecimal characters")
        _require_positive_int("broker_pid", self.broker_pid)
        _require_positive_int("broker_start_time_ticks", self.broker_start_time_ticks)
        _require_boot_id(self.broker_boot_id, "broker_boot_id")
        _require_positive_int("ready_at_monotonic_ns", self.ready_at_monotonic_ns)


def canonical_policy_bytes(policy: TransportPolicy) -> bytes:
    """Return the deterministic, locator-free serialization of ``policy``."""
    if type(policy) is not TransportPolicy:
        raise TypeError("policy must be a TransportPolicy")
    payload = {
        "version": policy.version,
        "task_id": policy.task_id,
        "task_generation": policy.task_generation,
        "launch_nonce": policy.launch_nonce,
        "mode": policy.mode.value,
        "proxy_host": policy.proxy_host,
        "proxy_port": policy.proxy_port,
        "activated_at_monotonic_ns": policy.activated_at_monotonic_ns,
        "expires_at_monotonic_ns": policy.expires_at_monotonic_ns,
        "connection_limit": policy.connection_limit,
        "byte_limit": policy.byte_limit,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")


def policy_digest(policy: TransportPolicy) -> str:
    """Return the lowercase SHA-256 digest for every transport policy field."""
    return hashlib.sha256(canonical_policy_bytes(policy)).hexdigest()


__all__ = [
    "BrokerProcessEvidence",
    "BrokerReadyEvidence",
    "ListenerEvidence",
    "TransportMode",
    "TransportPolicy",
    "canonical_policy_bytes",
    "policy_digest",
]
