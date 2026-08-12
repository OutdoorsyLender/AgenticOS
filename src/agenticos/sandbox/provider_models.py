"""Immutable task-scoped provider broker policy, capability, evidence, and authority types."""

from __future__ import annotations

import abc
import hashlib
import ipaddress
import json
import re
import time
from dataclasses import dataclass
from enum import Enum

_VERSION = "AOSPROV/1"
_MAX_UNSIGNED_64 = (1 << 64) - 1
_TASK_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_LOWER_HEX_32_RE = re.compile(r"[0-9a-f]{32}\Z")
_LOWER_HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
_BOOT_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


class NetworkAuthority(str, Enum):
    """Network authority classifications for AgenticOS policy scoping."""

    NONE = "NONE"
    CONNECTED_BUILD = "CONNECTED_BUILD"
    PROVIDER_CONTROL = "PROVIDER_CONTROL"


class ProviderFailureClass(str, Enum):
    """Typed structural failure categories for provider broker operations."""

    PROVIDER_BROKER_UNAVAILABLE = "PROVIDER_BROKER_UNAVAILABLE"
    PROVIDER_POLICY_REJECTED = "PROVIDER_POLICY_REJECTED"
    PROVIDER_CLIENT_PROTOCOL_ERROR = "PROVIDER_CLIENT_PROTOCOL_ERROR"
    PROVIDER_AUTH_UNAVAILABLE = "PROVIDER_AUTH_UNAVAILABLE"
    PROVIDER_UPSTREAM_CONNECT_ERROR = "PROVIDER_UPSTREAM_CONNECT_ERROR"
    PROVIDER_UPSTREAM_PROTOCOL_ERROR = "PROVIDER_UPSTREAM_PROTOCOL_ERROR"
    PROVIDER_UPSTREAM_STATUS_ERROR = "PROVIDER_UPSTREAM_STATUS_ERROR"
    PROVIDER_RESPONSE_TOO_LARGE = "PROVIDER_RESPONSE_TOO_LARGE"
    PROVIDER_EVENT_TOO_LARGE = "PROVIDER_EVENT_TOO_LARGE"
    PROVIDER_IDLE_TIMEOUT = "PROVIDER_IDLE_TIMEOUT"
    PROVIDER_TOTAL_TIMEOUT = "PROVIDER_TOTAL_TIMEOUT"
    PROVIDER_CANCELLED = "PROVIDER_CANCELLED"


class ProviderAuthBindingError(RuntimeError):
    """Stable secret-free failure raised when a capability is not current for a policy."""


@dataclass(frozen=True)
class ProviderAuthBinding:
    """Complete immutable authority binding for a short-lived provider capability."""

    task_id: str
    generation: int
    attempt_id: int
    launch_nonce: str
    provider_id: str
    upstream_scheme: str
    upstream_host: str
    upstream_port: int
    provider_purpose: str
    helper_epoch: str
    request_nonce: str
    capability_nonce: str
    capability_sequence: int
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        _require_task_id(self.task_id)
        _require_positive_int("generation", self.generation)
        _require_positive_int("attempt_id", self.attempt_id)
        _require_nonce(self.launch_nonce)
        if not isinstance(self.provider_id, str) or not self.provider_id:
            raise ValueError("provider_id must be a non-empty string")
        if self.upstream_scheme not in ("http", "https"):
            raise ValueError("upstream_scheme must be 'http' or 'https'")
        if not isinstance(self.upstream_host, str) or not self.upstream_host:
            raise ValueError("upstream_host must be a non-empty string")
        if type(self.upstream_port) is not int or not 1 <= self.upstream_port <= 65535:
            raise ValueError("upstream_port must be in range 1..65535")
        if not isinstance(self.provider_purpose, str) or not self.provider_purpose:
            raise ValueError("provider_purpose must be a non-empty string")
        for name, value in (
            ("helper_epoch", self.helper_epoch),
            ("request_nonce", self.request_nonce),
            ("capability_nonce", self.capability_nonce),
        ):
            if not isinstance(value, str) or not _LOWER_HEX_32_RE.fullmatch(value):
                raise ValueError(f"{name} must be exactly 32 lowercase hexadecimal characters")
        _require_positive_int("capability_sequence", self.capability_sequence)
        _require_positive_int("issued_at", self.issued_at)
        _require_positive_int("expires_at", self.expires_at)
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")


@dataclass(frozen=True, slots=True, repr=False)
class SecretValue:
    """Wrapper for secret material that prevents accidental printing or stringification."""

    _value: str

    def __post_init__(self) -> None:
        if not isinstance(self._value, str):
            raise TypeError("SecretValue requires a string value")

    def __repr__(self) -> str:
        return "SecretValue(REDACTED)"

    def __str__(self) -> str:
        return "[REDACTED]"

    def reveal_secret(self) -> str:
        """Explicitly reveal the underlying secret string for authorized transport logic."""
        return self._value


class ProviderAuthCapability(abc.ABC):
    """Abstract interface for controller-supplied provider authentication."""

    @abc.abstractmethod
    def get_auth_header(self, task_id: str, generation: int) -> SecretValue:
        """Return the authorization header value wrapped in a SecretValue."""
        raise NotImplementedError

    def get_extra_headers(self, task_id: str, generation: int) -> dict[str, SecretValue]:
        """Return any extra authorization headers (e.g. ChatGPT-Account-ID) to inject."""
        return {}

    def validate_for_policy(
        self, policy: ProviderBrokerPolicy, now: int | float | None = None
    ) -> None:
        """Validate this capability at its broker consumption point."""
        if not isinstance(policy, ProviderBrokerPolicy):
            raise TypeError("policy must be a ProviderBrokerPolicy instance")


class SyntheticBearerAuth(ProviderAuthCapability):
    """Deterministic synthetic test authorization provider for Slice 1 qualification."""

    def __init__(self, canary_token: str) -> None:
        if not isinstance(canary_token, str) or not canary_token.strip():
            raise ValueError("canary_token must be a non-empty string")
        self._canary_token = canary_token

    def get_auth_header(self, task_id: str, generation: int) -> SecretValue:
        return SecretValue(f"Bearer {self._canary_token}")


@dataclass(frozen=True, slots=True, init=False, repr=False)
class SubscriptionAuthCapability(ProviderAuthCapability):
    """Auth capability supporting bearer access token and optional ChatGPT account ID."""

    _access_token: SecretValue
    _account_id: SecretValue | None
    binding: ProviderAuthBinding

    def __init__(
        self,
        access_token: str,
        account_id: str | None = None,
        *,
        binding: ProviderAuthBinding,
    ) -> None:
        if not isinstance(access_token, str) or not access_token.strip():
            raise ValueError("access_token must be a non-empty string")
        if account_id is not None and (not isinstance(account_id, str) or not account_id.strip()):
            raise ValueError("account_id must be a non-empty string or None")
        if not isinstance(binding, ProviderAuthBinding):
            raise TypeError("binding must be a ProviderAuthBinding instance")
        object.__setattr__(self, "_access_token", SecretValue(access_token))
        object.__setattr__(self, "_account_id", SecretValue(account_id) if account_id is not None else None)
        object.__setattr__(self, "binding", binding)

    def get_auth_header(self, task_id: str, generation: int) -> SecretValue:
        return SecretValue(f"Bearer {self._access_token.reveal_secret()}")

    def get_extra_headers(self, task_id: str, generation: int) -> dict[str, SecretValue]:
        headers: dict[str, SecretValue] = {}
        if self._account_id is not None:
            headers["ChatGPT-Account-ID"] = SecretValue(self._account_id.reveal_secret())
        return headers

    def validate_for_policy(
        self, policy: ProviderBrokerPolicy, now: int | float | None = None
    ) -> None:
        ProviderAuthCapability.validate_for_policy(self, policy, now)
        binding = self.binding
        expected = (
            (binding.task_id, policy.task_id),
            (binding.generation, policy.generation),
            (binding.attempt_id, policy.attempt_id),
            (binding.launch_nonce, policy.launch_nonce),
            (binding.provider_id, policy.upstream_provider_id),
            (binding.upstream_scheme, policy.upstream_scheme),
            (binding.upstream_host, policy.upstream_host),
            (binding.upstream_port, policy.upstream_port),
            (binding.provider_purpose, "responses_sse"),
        )
        current_time = time.time() if now is None else now
        if type(current_time) not in (int, float):
            raise TypeError("now must be an int, float, or None")
        if any(actual != required for actual, required in expected) or current_time >= binding.expires_at:
            raise ProviderAuthBindingError("PROVIDER_AUTH_BINDING_REJECTED")


def _require_positive_int(name: str, value: object) -> None:
    if type(value) is not int or not 0 < value <= _MAX_UNSIGNED_64:
        raise ValueError(f"{name} must be a positive unsigned 64-bit integer")


def _require_non_negative_int(name: str, value: object) -> None:
    if type(value) is not int or not 0 <= value <= _MAX_UNSIGNED_64:
        raise ValueError(f"{name} must be a non-negative unsigned 64-bit integer")


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
class ProviderBrokerPolicy:
    """Task-scoped policy governing provider broker capabilities and operational limits."""

    version: str
    task_id: str
    generation: int
    attempt_id: int
    launch_nonce: str
    upstream_provider_id: str
    upstream_scheme: str
    upstream_host: str
    upstream_port: int
    allowed_paths: tuple[str, ...]
    protocol_type: str
    max_request_bytes: int
    max_response_bytes: int
    max_event_bytes: int
    max_header_count: int
    max_header_bytes: int
    max_connections: int
    retry_budget: int
    idle_timeout_seconds: float
    total_lifetime_seconds: float

    def __post_init__(self) -> None:
        if self.version != _VERSION:
            raise ValueError(f"version must be {_VERSION}")
        _require_task_id(self.task_id)
        _require_positive_int("generation", self.generation)
        _require_positive_int("attempt_id", self.attempt_id)
        _require_nonce(self.launch_nonce)
        if not isinstance(self.upstream_provider_id, str) or not self.upstream_provider_id:
            raise ValueError("upstream_provider_id must be a non-empty string")
        if self.upstream_scheme not in ("http", "https"):
            raise ValueError("upstream_scheme must be 'http' or 'https'")
        if not isinstance(self.upstream_host, str) or not self.upstream_host:
            raise ValueError("upstream_host must be a non-empty string")
        if type(self.upstream_port) is not int or not 1 <= self.upstream_port <= 65535:
            raise ValueError("upstream_port must be in range 1..65535")
        if not isinstance(self.allowed_paths, tuple) or not self.allowed_paths:
            raise ValueError("allowed_paths must be a non-empty tuple of path strings")
        for path in self.allowed_paths:
            if not isinstance(path, str) or not path.startswith("/"):
                raise ValueError("each path in allowed_paths must be a string starting with '/'")
        if self.protocol_type != "HTTP_SSE":
            raise ValueError("protocol_type must be 'HTTP_SSE'")
        _require_positive_int("max_request_bytes", self.max_request_bytes)
        _require_positive_int("max_response_bytes", self.max_response_bytes)
        _require_positive_int("max_event_bytes", self.max_event_bytes)
        _require_positive_int("max_header_count", self.max_header_count)
        _require_positive_int("max_header_bytes", self.max_header_bytes)
        _require_positive_int("max_connections", self.max_connections)
        _require_non_negative_int("retry_budget", self.retry_budget)
        if type(self.idle_timeout_seconds) not in (int, float) or self.idle_timeout_seconds <= 0:
            raise ValueError("idle_timeout_seconds must be a positive number")
        if type(self.total_lifetime_seconds) not in (int, float) or self.total_lifetime_seconds <= 0:
            raise ValueError("total_lifetime_seconds must be a positive number")


@dataclass(frozen=True)
class ProviderGrant:
    """Proof of an active provider capability assigned to a specific task attempt."""

    task_id: str
    generation: int
    attempt_id: int
    launch_nonce: str
    policy_digest: str
    listener_address: str
    listener_port: int

    def __post_init__(self) -> None:
        _require_task_id(self.task_id)
        _require_positive_int("generation", self.generation)
        _require_positive_int("attempt_id", self.attempt_id)
        _require_nonce(self.launch_nonce)
        if not isinstance(self.policy_digest, str) or not _LOWER_HEX_64_RE.fullmatch(self.policy_digest):
            raise ValueError("policy_digest must be 64 lowercase hex characters")
        if not isinstance(self.listener_address, str):
            raise ValueError("listener_address must be a string")
        try:
            ipaddress.ip_address(self.listener_address)
        except ValueError as exc:
            raise ValueError("listener_address must be a valid IP address") from exc
        if type(self.listener_port) is not int or not 1 <= self.listener_port <= 65535:
            raise ValueError("listener_port must be in range 1..65535")


@dataclass(frozen=True)
class ProviderBrokerIdentity:
    """Host process identity snapshot for the running provider broker."""

    broker_id: str
    pid: int
    start_time_ticks: int
    boot_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.broker_id, str) or not self.broker_id:
            raise ValueError("broker_id must be a non-empty string")
        _require_positive_int("pid", self.pid)
        _require_positive_int("start_time_ticks", self.start_time_ticks)
        _require_boot_id(self.boot_id, "boot_id")


@dataclass(frozen=True)
class AuthHelperProcessIdentity:
    """Host process identity snapshot for the out-of-process auth helper process."""

    pid: int
    executable: str
    executable_digest: str
    cwd: str
    env_keys: tuple[str, ...]
    open_fd_count: int
    ipc_endpoint: str
    parent_pid: int
    started_at_monotonic_ns: int

    def __post_init__(self) -> None:
        _require_positive_int("pid", self.pid)
        if not isinstance(self.executable, str) or not self.executable:
            raise ValueError("executable must be a non-empty string")
        if not isinstance(self.executable_digest, str) or not _LOWER_HEX_64_RE.fullmatch(self.executable_digest):
            raise ValueError("executable_digest must be 64 lowercase hex characters")
        if not isinstance(self.cwd, str) or not self.cwd:
            raise ValueError("cwd must be a non-empty string")
        if not isinstance(self.ipc_endpoint, str) or not self.ipc_endpoint:
            raise ValueError("ipc_endpoint must be a non-empty string")
        _require_positive_int("parent_pid", self.parent_pid)
        _require_positive_int("started_at_monotonic_ns", self.started_at_monotonic_ns)
        _require_non_negative_int("open_fd_count", self.open_fd_count)



@dataclass(frozen=True)
class ProviderBrokerEvidence:
    """Immutable evidence record summarizing provider broker execution for a task attempt."""

    task_id: str
    generation: int
    attempt_id: int
    policy_digest: str
    broker_identity: ProviderBrokerIdentity
    upstream_identity: str
    protocol: str
    client_connection_count: int
    request_byte_count: int
    response_byte_count: int
    response_event_count: int
    upstream_status: int | None
    started_at_monotonic_ns: int
    ended_at_monotonic_ns: int
    terminal_failure_class: ProviderFailureClass | None
    cancellation_state: bool
    canary_exposure_status: str

    def __post_init__(self) -> None:
        _require_task_id(self.task_id)
        _require_positive_int("generation", self.generation)
        _require_positive_int("attempt_id", self.attempt_id)
        if not isinstance(self.policy_digest, str) or not _LOWER_HEX_64_RE.fullmatch(self.policy_digest):
            raise ValueError("policy_digest must be 64 lowercase hex characters")
        if not isinstance(self.broker_identity, ProviderBrokerIdentity):
            raise ValueError("broker_identity must be a ProviderBrokerIdentity instance")
        if not isinstance(self.upstream_identity, str) or not self.upstream_identity:
            raise ValueError("upstream_identity must be a non-empty string")
        if not isinstance(self.protocol, str) or not self.protocol:
            raise ValueError("protocol must be a non-empty string")
        _require_non_negative_int("client_connection_count", self.client_connection_count)
        _require_non_negative_int("request_byte_count", self.request_byte_count)
        _require_non_negative_int("response_byte_count", self.response_byte_count)
        _require_non_negative_int("response_event_count", self.response_event_count)
        if self.upstream_status is not None:
            if type(self.upstream_status) is not int or not 100 <= self.upstream_status <= 599:
                raise ValueError("upstream_status must be a valid HTTP status code or None")
        _require_positive_int("started_at_monotonic_ns", self.started_at_monotonic_ns)
        _require_positive_int("ended_at_monotonic_ns", self.ended_at_monotonic_ns)
        if self.ended_at_monotonic_ns < self.started_at_monotonic_ns:
            raise ValueError("ended_at_monotonic_ns cannot be before started_at_monotonic_ns")
        if self.terminal_failure_class is not None and not isinstance(self.terminal_failure_class, ProviderFailureClass):
            raise ValueError("terminal_failure_class must be a ProviderFailureClass or None")
        if type(self.cancellation_state) is not bool:
            raise ValueError("cancellation_state must be a bool")
        if not isinstance(self.canary_exposure_status, str) or not self.canary_exposure_status:
            raise ValueError("canary_exposure_status must be a non-empty string")


def canonical_provider_policy_bytes(policy: ProviderBrokerPolicy) -> bytes:
    """Return the deterministic ASCII JSON serialization of a ProviderBrokerPolicy."""
    if not isinstance(policy, ProviderBrokerPolicy):
        raise TypeError("policy must be a ProviderBrokerPolicy instance")
    payload = {
        "allowed_paths": list(policy.allowed_paths),
        "attempt_id": policy.attempt_id,
        "generation": policy.generation,
        "idle_timeout_seconds": policy.idle_timeout_seconds,
        "launch_nonce": policy.launch_nonce,
        "max_connections": policy.max_connections,
        "max_event_bytes": policy.max_event_bytes,
        "max_header_bytes": policy.max_header_bytes,
        "max_header_count": policy.max_header_count,
        "max_request_bytes": policy.max_request_bytes,
        "max_response_bytes": policy.max_response_bytes,
        "protocol_type": policy.protocol_type,
        "retry_budget": policy.retry_budget,
        "task_id": policy.task_id,
        "total_lifetime_seconds": policy.total_lifetime_seconds,
        "upstream_host": policy.upstream_host,
        "upstream_port": policy.upstream_port,
        "upstream_provider_id": policy.upstream_provider_id,
        "upstream_scheme": policy.upstream_scheme,
        "version": policy.version,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")


def provider_policy_digest(policy: ProviderBrokerPolicy) -> str:
    """Return the SHA-256 digest of canonical_provider_policy_bytes."""
    return hashlib.sha256(canonical_provider_policy_bytes(policy)).hexdigest()


__all__ = [
    "AuthHelperProcessIdentity",
    "NetworkAuthority",
    "ProviderAuthCapability",
    "ProviderAuthBinding",
    "ProviderAuthBindingError",
    "ProviderBrokerEvidence",
    "ProviderBrokerIdentity",
    "ProviderBrokerPolicy",
    "ProviderFailureClass",
    "ProviderGrant",
    "SecretValue",
    "SubscriptionAuthCapability",
    "SyntheticBearerAuth",
    "canonical_provider_policy_bytes",
    "provider_policy_digest",
]
