"""Strict provider-neutral AgenticOS request, event, and result ABI."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, ClassVar

from .canonical import CanonicalDataError, canonical_json_line, load_canonical_json
from .models import (
    MAX_CRITERIA,
    MAX_CRITERION_BYTES,
    Role,
    require_digest,
    require_enum,
    require_exact_fields,
    require_identifier,
    require_text,
    require_uint,
)

AGENT_PROTOCOL_SCHEMA = "AOSAGENT/1"
MAX_INSTRUCTION_BYTES = 32_768
MAX_EVENT_TEXT_BYTES = 8_192
MAX_RESULT_REFS = 64
_NONCE_RE = re.compile(r"[0-9a-f]{32}\Z")
_SHA40_RE = re.compile(r"[0-9a-f]{40}\Z")


class ProtocolRejection(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


def _guard(code: str, function, *args):
    try:
        return function(*args)
    except (ValueError, TypeError) as exc:
        if isinstance(exc, ProtocolRejection):
            raise
        inner = getattr(exc, "code", "INVALID_VALUE")
        raise ProtocolRejection(code if code else inner, str(inner)) from exc


def _exact(raw: object, names: set[str]) -> dict[str, Any]:
    try:
        return require_exact_fields(raw, names)
    except ValueError as exc:
        raise ProtocolRejection(getattr(exc, "code", "INVALID_OBJECT")) from exc


class AgentCapability(str, Enum):
    READ_CONTEXT = "READ_CONTEXT"
    PROPOSE_TASKS = "PROPOSE_TASKS"
    PROPOSE_REVIEW = "PROPOSE_REVIEW"
    READ_WORKSPACE = "READ_WORKSPACE"
    WRITE_WORKSPACE = "WRITE_WORKSPACE"
    RUN_BOUNDED_COMMANDS = "RUN_BOUNDED_COMMANDS"


class ContextKind(str, Enum):
    RESEARCH_NOTE = "RESEARCH_NOTE"
    PLAN_INPUT = "PLAN_INPUT"
    ARCHITECTURE_NOTE = "ARCHITECTURE_NOTE"
    VERIFICATION_FINDING = "VERIFICATION_FINDING"
    REVIEW_FINDING = "REVIEW_FINDING"
    WORKSPACE_MANIFEST = "WORKSPACE_MANIFEST"


class EventKind(str, Enum):
    STARTED = "STARTED"
    PROGRESS = "PROGRESS"
    PROPOSAL = "PROPOSAL"
    SUCCEEDED = "SUCCEEDED"
    NO_OP = "NO_OP"
    RETRYABLE_FAILURE = "RETRYABLE_FAILURE"
    TERMINAL_FAILURE = "TERMINAL_FAILURE"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


TERMINAL_EVENT_KINDS = frozenset({
    EventKind.SUCCEEDED, EventKind.NO_OP, EventKind.RETRYABLE_FAILURE,
    EventKind.TERMINAL_FAILURE, EventKind.BLOCKED, EventKind.CANCELLED,
})


class ResultStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    NO_OP = "NO_OP"
    RETRYABLE_FAILURE = "RETRYABLE_FAILURE"
    TERMINAL_FAILURE = "TERMINAL_FAILURE"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


class AgentExitClass(str, Enum):
    SUCCESS = "SUCCESS"
    NO_OP = "NO_OP"
    RETRYABLE = "RETRYABLE"
    TERMINAL = "TERMINAL"
    MALFORMED = "MALFORMED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"


class Retryability(str, Enum):
    RETRYABLE = "RETRYABLE"
    NOT_RETRYABLE = "NOT_RETRYABLE"
    CONTROLLER_POLICY_REQUIRED = "CONTROLLER_POLICY_REQUIRED"


@dataclass(frozen=True, slots=True)
class DispatchIdentity:
    project_id: str
    task_id: str
    task_generation: int
    attempt: int
    controller_epoch: int
    lease_epoch: int
    dispatch_nonce: str
    repository_id: str
    baseline_commit: str
    workspace_id: str
    workspace_generation: int
    reservation_id: str
    checkpoint_digest: str

    def __post_init__(self) -> None:
        try:
            for name in ("project_id", "task_id", "repository_id", "workspace_id", "reservation_id"):
                require_identifier(name, getattr(self, name))
            for name, minimum in (("task_generation", 1), ("attempt", 1), ("controller_epoch", 1), ("lease_epoch", 0), ("workspace_generation", 1)):
                require_uint(name, getattr(self, name), minimum=minimum)
            if type(self.dispatch_nonce) is not str or not _NONCE_RE.fullmatch(self.dispatch_nonce):
                raise ProtocolRejection("INVALID_DISPATCH_NONCE")
            if type(self.baseline_commit) is not str or not _SHA40_RE.fullmatch(self.baseline_commit):
                raise ProtocolRejection("INVALID_BASELINE_COMMIT")
            require_digest("checkpoint_digest", self.checkpoint_digest)
        except ValueError as exc:
            if isinstance(exc, ProtocolRejection):
                raise
            raise ProtocolRejection(getattr(exc, "code", "INVALID_IDENTITY")) from exc

    def to_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: object) -> DispatchIdentity:
        return cls(**_exact(raw, set(cls.__dataclass_fields__)))


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    kind: str
    evidence_id: str
    digest: str
    byte_size: int

    def __post_init__(self) -> None:
        try:
            require_identifier("kind", self.kind)
            require_identifier("evidence_id", self.evidence_id)
            require_digest("digest", self.digest)
            require_uint("byte_size", self.byte_size, maximum=16_777_216)
        except ValueError as exc:
            raise ProtocolRejection(getattr(exc, "code", "INVALID_EVIDENCE_REF")) from exc

    def to_dict(self) -> dict[str, object]:
        return {"kind": self.kind, "evidence_id": self.evidence_id, "digest": self.digest, "byte_size": self.byte_size}

    @classmethod
    def from_dict(cls, raw: object) -> EvidenceRef:
        return cls(**_exact(raw, {"kind", "evidence_id", "digest", "byte_size"}))


@dataclass(frozen=True, slots=True)
class ContextItem:
    kind: ContextKind
    item_id: str
    digest: str
    byte_size: int

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ContextKind):
            raise ProtocolRejection("INVALID_ENUM", "context.kind")
        try:
            require_identifier("item_id", self.item_id)
            require_digest("digest", self.digest)
            require_uint("byte_size", self.byte_size, maximum=16_777_216)
        except ValueError as exc:
            raise ProtocolRejection(getattr(exc, "code", "INVALID_CONTEXT_ITEM")) from exc

    def to_dict(self) -> dict[str, object]:
        return {"kind": self.kind.value, "item_id": self.item_id, "digest": self.digest, "byte_size": self.byte_size}

    @classmethod
    def from_dict(cls, raw: object) -> ContextItem:
        value = _exact(raw, {"kind", "item_id", "digest", "byte_size"})
        try:
            kind = require_enum(ContextKind, "kind", value["kind"])
        except ValueError as exc:
            raise ProtocolRejection("INVALID_ENUM") from exc
        return cls(kind=kind, item_id=value["item_id"], digest=value["digest"], byte_size=value["byte_size"])


@dataclass(frozen=True, slots=True)
class ProtocolLimits:
    max_events: int = 256
    max_event_bytes: int = 65_536
    max_output_bytes: int = 1_048_576
    max_context_entries: int = 64
    max_context_bytes: int = 262_144
    max_processes: int = 32
    max_runtime_seconds: int = 3_600

    _MAXIMA: ClassVar[dict[str, int]] = {
        "max_events": 4096,
        "max_event_bytes": 1_048_576,
        "max_output_bytes": 16_777_216,
        "max_context_entries": 1024,
        "max_context_bytes": 16_777_216,
        "max_processes": 256,
        "max_runtime_seconds": 86_400,
    }

    def __post_init__(self) -> None:
        try:
            for name, maximum in self._MAXIMA.items():
                require_uint(name, getattr(self, name), minimum=1, maximum=maximum)
        except ValueError as exc:
            raise ProtocolRejection(getattr(exc, "code", "INVALID_LIMIT")) from exc

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self._MAXIMA}

    @classmethod
    def from_dict(cls, raw: object) -> ProtocolLimits:
        return cls(**_exact(raw, set(cls._MAXIMA)))


@dataclass(frozen=True, slots=True)
class AgentTaskRequest:
    schema: str
    identity: DispatchIdentity
    role: Role
    provider_id: str
    model_id: str
    workspace_mount: str
    instructions: str
    acceptance_criteria: tuple[str, ...]
    context_manifest: tuple[ContextItem, ...]
    capabilities: tuple[AgentCapability, ...]
    limits: ProtocolLimits

    def __post_init__(self) -> None:
        if self.schema != AGENT_PROTOCOL_SCHEMA:
            raise ProtocolRejection("INVALID_SCHEMA")
        if not isinstance(self.identity, DispatchIdentity) or not isinstance(self.role, Role):
            raise ProtocolRejection("INVALID_ENUM_OR_IDENTITY")
        try:
            require_identifier("provider_id", self.provider_id)
            require_identifier("model_id", self.model_id)
            require_text("instructions", self.instructions, MAX_INSTRUCTION_BYTES)
        except ValueError as exc:
            code = "INSTRUCTION_LIMIT_EXCEEDED" if getattr(exc, "code", "") == "TEXT_LIMIT_EXCEEDED" else getattr(exc, "code", "INVALID_REQUEST")
            raise ProtocolRejection(code) from exc
        if self.workspace_mount != "/workspace":
            raise ProtocolRejection("INVALID_WORKSPACE_ABI")
        if type(self.acceptance_criteria) is not tuple or not 1 <= len(self.acceptance_criteria) <= MAX_CRITERIA:
            raise ProtocolRejection("ACCEPTANCE_CRITERIA_LIMIT")
        for criterion in self.acceptance_criteria:
            try:
                require_text("criterion", criterion, MAX_CRITERION_BYTES)
            except ValueError as exc:
                raise ProtocolRejection("ACCEPTANCE_CRITERIA_LIMIT") from exc
        if not isinstance(self.limits, ProtocolLimits):
            raise ProtocolRejection("INVALID_LIMITS")
        if type(self.context_manifest) is not tuple or len(self.context_manifest) > self.limits.max_context_entries:
            raise ProtocolRejection("CONTEXT_ENTRY_LIMIT_EXCEEDED")
        if any(not isinstance(item, ContextItem) for item in self.context_manifest):
            raise ProtocolRejection("INVALID_CONTEXT_ITEM")
        if sum(item.byte_size for item in self.context_manifest) > self.limits.max_context_bytes:
            raise ProtocolRejection("CONTEXT_BYTE_LIMIT_EXCEEDED")
        item_ids = [item.item_id for item in self.context_manifest]
        if len(item_ids) != len(set(item_ids)):
            raise ProtocolRejection("DUPLICATE_CONTEXT_ITEM")
        if type(self.capabilities) is not tuple or len(self.capabilities) > 16 or len(set(self.capabilities)) != len(self.capabilities):
            raise ProtocolRejection("INVALID_CAPABILITIES")
        if any(not isinstance(item, AgentCapability) for item in self.capabilities):
            raise ProtocolRejection("INVALID_ENUM", "capability")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema, "identity": self.identity.to_dict(), "role": self.role.value,
            "provider_id": self.provider_id, "model_id": self.model_id,
            "workspace_mount": self.workspace_mount, "instructions": self.instructions,
            "acceptance_criteria": list(self.acceptance_criteria),
            "context_manifest": [item.to_dict() for item in self.context_manifest],
            "capabilities": [item.value for item in self.capabilities], "limits": self.limits.to_dict(),
        }

    @classmethod
    def from_dict(cls, raw: object) -> AgentTaskRequest:
        value = _exact(raw, set(cls.__dataclass_fields__))
        try:
            role = require_enum(Role, "role", value["role"])
            capabilities = tuple(require_enum(AgentCapability, "capability", item) for item in value["capabilities"])
        except (ValueError, TypeError) as exc:
            raise ProtocolRejection("INVALID_ENUM") from exc
        try:
            return cls(
                **{**value, "identity": DispatchIdentity.from_dict(value["identity"]), "role": role,
                   "acceptance_criteria": tuple(value["acceptance_criteria"]),
                   "context_manifest": tuple(ContextItem.from_dict(item) for item in value["context_manifest"]),
                   "capabilities": capabilities, "limits": ProtocolLimits.from_dict(value["limits"])}
            )
        except TypeError as exc:
            raise ProtocolRejection("INVALID_REQUEST_SHAPE") from exc


@dataclass(frozen=True, slots=True)
class AgentEventPayload:
    text: str
    evidence_refs: tuple[EvidenceRef, ...]

    def __post_init__(self) -> None:
        try:
            require_text("event.text", self.text, MAX_EVENT_TEXT_BYTES, allow_empty=True)
        except ValueError as exc:
            raise ProtocolRejection("EVENT_PAYLOAD_LIMIT_EXCEEDED") from exc
        if type(self.evidence_refs) is not tuple or len(self.evidence_refs) > 16 or any(not isinstance(item, EvidenceRef) for item in self.evidence_refs):
            raise ProtocolRejection("EVENT_EVIDENCE_LIMIT_EXCEEDED")

    def to_dict(self) -> dict[str, object]:
        return {"text": self.text, "evidence_refs": [item.to_dict() for item in self.evidence_refs]}

    @classmethod
    def from_dict(cls, raw: object) -> AgentEventPayload:
        value = _exact(raw, {"text", "evidence_refs"})
        if type(value["evidence_refs"]) is not list:
            raise ProtocolRejection("INVALID_EVENT_PAYLOAD")
        return cls(text=value["text"], evidence_refs=tuple(EvidenceRef.from_dict(item) for item in value["evidence_refs"]))


@dataclass(frozen=True, slots=True)
class AgentEvent:
    schema: str
    identity: DispatchIdentity
    sequence: int
    kind: EventKind
    payload: AgentEventPayload

    def __post_init__(self) -> None:
        if self.schema != AGENT_PROTOCOL_SCHEMA:
            raise ProtocolRejection("INVALID_SCHEMA")
        if not isinstance(self.identity, DispatchIdentity) or not isinstance(self.kind, EventKind) or not isinstance(self.payload, AgentEventPayload):
            raise ProtocolRejection("INVALID_EVENT")
        try:
            require_uint("sequence", self.sequence, minimum=1)
        except ValueError as exc:
            raise ProtocolRejection("INVALID_EVENT_SEQUENCE") from exc

    def to_dict(self) -> dict[str, object]:
        return {"schema": self.schema, "identity": self.identity.to_dict(), "sequence": self.sequence, "kind": self.kind.value, "payload": self.payload.to_dict()}

    @classmethod
    def from_dict(cls, raw: object) -> AgentEvent:
        value = _exact(raw, {"schema", "identity", "sequence", "kind", "payload"})
        try:
            kind = require_enum(EventKind, "kind", value["kind"])
        except ValueError as exc:
            raise ProtocolRejection("INVALID_ENUM") from exc
        return cls(schema=value["schema"], identity=DispatchIdentity.from_dict(value["identity"]), sequence=value["sequence"], kind=kind, payload=AgentEventPayload.from_dict(value["payload"]))


@dataclass(frozen=True, slots=True)
class UsageRecord:
    input_units: int
    output_units: int

    def __post_init__(self) -> None:
        try:
            require_uint("input_units", self.input_units, maximum=MAX_UNSIGNED_UNITS)
            require_uint("output_units", self.output_units, maximum=MAX_UNSIGNED_UNITS)
        except ValueError as exc:
            raise ProtocolRejection("INVALID_USAGE") from exc

    def to_dict(self) -> dict[str, int]:
        return {"input_units": self.input_units, "output_units": self.output_units}

    @classmethod
    def from_dict(cls, raw: object) -> UsageRecord:
        return cls(**_exact(raw, {"input_units", "output_units"}))


MAX_UNSIGNED_UNITS = 1_000_000_000


@dataclass(frozen=True, slots=True)
class AgentResult:
    schema: str
    identity: DispatchIdentity
    status: ResultStatus
    exit_class: AgentExitClass
    event_count: int
    byte_count: int
    stream_digest: str
    evidence_refs: tuple[EvidenceRef, ...]
    workspace_handoff_ref: EvidenceRef | None
    usage: UsageRecord | None
    retryability: Retryability

    def __post_init__(self) -> None:
        if self.schema != AGENT_PROTOCOL_SCHEMA or not isinstance(self.identity, DispatchIdentity):
            raise ProtocolRejection("INVALID_RESULT")
        if not isinstance(self.status, ResultStatus) or not isinstance(self.exit_class, AgentExitClass) or not isinstance(self.retryability, Retryability):
            raise ProtocolRejection("INVALID_ENUM")
        try:
            require_uint("event_count", self.event_count, minimum=1, maximum=4096)
            require_uint("byte_count", self.byte_count, minimum=1, maximum=16_777_216)
            require_digest("stream_digest", self.stream_digest)
        except ValueError as exc:
            raise ProtocolRejection(getattr(exc, "code", "INVALID_RESULT_METRICS")) from exc
        if type(self.evidence_refs) is not tuple or len(self.evidence_refs) > MAX_RESULT_REFS or any(not isinstance(item, EvidenceRef) for item in self.evidence_refs):
            raise ProtocolRejection("RESULT_EVIDENCE_LIMIT")
        if self.workspace_handoff_ref is not None and not isinstance(self.workspace_handoff_ref, EvidenceRef):
            raise ProtocolRejection("INVALID_WORKSPACE_HANDOFF_REF")
        if self.usage is not None and not isinstance(self.usage, UsageRecord):
            raise ProtocolRejection("INVALID_USAGE")
        allowed = {
            ResultStatus.SUCCEEDED: ({AgentExitClass.SUCCESS}, {Retryability.NOT_RETRYABLE}),
            ResultStatus.NO_OP: ({AgentExitClass.NO_OP}, {Retryability.NOT_RETRYABLE}),
            ResultStatus.RETRYABLE_FAILURE: ({AgentExitClass.RETRYABLE, AgentExitClass.TIMEOUT}, {Retryability.RETRYABLE}),
            ResultStatus.TERMINAL_FAILURE: ({AgentExitClass.TERMINAL, AgentExitClass.MALFORMED, AgentExitClass.TIMEOUT}, {Retryability.NOT_RETRYABLE}),
            ResultStatus.BLOCKED: ({AgentExitClass.TERMINAL}, {Retryability.CONTROLLER_POLICY_REQUIRED, Retryability.NOT_RETRYABLE}),
            ResultStatus.CANCELLED: ({AgentExitClass.CANCELLED}, {Retryability.NOT_RETRYABLE}),
        }
        exit_classes, retry_values = allowed[self.status]
        if self.exit_class not in exit_classes or self.retryability not in retry_values:
            raise ProtocolRejection("RESULT_CLASSIFICATION_CONFLICT")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema, "identity": self.identity.to_dict(), "status": self.status.value,
            "exit_class": self.exit_class.value, "event_count": self.event_count,
            "byte_count": self.byte_count, "stream_digest": self.stream_digest,
            "evidence_refs": [item.to_dict() for item in self.evidence_refs],
            "workspace_handoff_ref": self.workspace_handoff_ref.to_dict() if self.workspace_handoff_ref else None,
            "usage": self.usage.to_dict() if self.usage else None, "retryability": self.retryability.value,
        }

    @classmethod
    def from_dict(cls, raw: object) -> AgentResult:
        value = _exact(raw, set(cls.__dataclass_fields__))
        try:
            status = require_enum(ResultStatus, "status", value["status"])
            exit_class = require_enum(AgentExitClass, "exit_class", value["exit_class"])
            retryability = require_enum(Retryability, "retryability", value["retryability"])
        except ValueError as exc:
            raise ProtocolRejection("INVALID_ENUM") from exc
        return cls(
            **{**value, "identity": DispatchIdentity.from_dict(value["identity"]), "status": status,
               "exit_class": exit_class, "evidence_refs": tuple(EvidenceRef.from_dict(item) for item in value["evidence_refs"]),
               "workspace_handoff_ref": None if value["workspace_handoff_ref"] is None else EvidenceRef.from_dict(value["workspace_handoff_ref"]),
               "usage": None if value["usage"] is None else UsageRecord.from_dict(value["usage"]), "retryability": retryability}
        )


_RESULT_FOR_EVENT = {
    EventKind.SUCCEEDED: ResultStatus.SUCCEEDED,
    EventKind.NO_OP: ResultStatus.NO_OP,
    EventKind.RETRYABLE_FAILURE: ResultStatus.RETRYABLE_FAILURE,
    EventKind.TERMINAL_FAILURE: ResultStatus.TERMINAL_FAILURE,
    EventKind.BLOCKED: ResultStatus.BLOCKED,
    EventKind.CANCELLED: ResultStatus.CANCELLED,
}


class AgentStreamValidator:
    """Incrementally validates bounded event frames before trusting their contents."""

    def __init__(self, request: AgentTaskRequest) -> None:
        if not isinstance(request, AgentTaskRequest):
            raise TypeError("request must be AgentTaskRequest")
        self.request = request
        self._next_sequence = 1
        self._event_count = 0
        self._byte_count = 0
        self._digest = hashlib.sha256()
        self._terminal_kind: EventKind | None = None
        self._result_accepted = False

    @property
    def byte_count(self) -> int:
        return self._byte_count

    @property
    def stream_digest(self) -> str:
        return self._digest.hexdigest()

    def accept(self, raw: bytes) -> AgentEvent:
        if type(raw) is not bytes or len(raw) > self.request.limits.max_event_bytes:
            raise ProtocolRejection("EVENT_BYTE_LIMIT_EXCEEDED")
        if self._event_count >= self.request.limits.max_events:
            raise ProtocolRejection("EVENT_COUNT_LIMIT_EXCEEDED")
        if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
            raise ProtocolRejection("MALFORMED_EVENT")
        try:
            value = load_canonical_json(raw[:-1], max_bytes=self.request.limits.max_event_bytes - 1)
            if canonical_json_line(value, max_bytes=self.request.limits.max_event_bytes) != raw:
                raise ProtocolRejection("NONCANONICAL_EVENT")
            item = AgentEvent.from_dict(value)
        except (CanonicalDataError, ProtocolRejection) as exc:
            if isinstance(exc, ProtocolRejection) and exc.code not in {"NONCANONICAL_EVENT"}:
                raise
            raise ProtocolRejection("MALFORMED_EVENT") from exc
        if self._terminal_kind is not None:
            raise ProtocolRejection("EVENT_AFTER_TERMINAL")
        if item.identity != self.request.identity:
            raise ProtocolRejection("DISPATCH_IDENTITY_MISMATCH")
        if item.sequence != self._next_sequence:
            raise ProtocolRejection("EVENT_SEQUENCE_MISMATCH")
        if self._byte_count + len(raw) > self.request.limits.max_output_bytes:
            raise ProtocolRejection("OUTPUT_BYTE_LIMIT_EXCEEDED")
        self._event_count += 1
        self._next_sequence += 1
        self._byte_count += len(raw)
        self._digest.update(raw)
        if item.kind in TERMINAL_EVENT_KINDS:
            self._terminal_kind = item.kind
        return item

    def finish(self) -> EventKind:
        if self._terminal_kind is None:
            raise ProtocolRejection("INCOMPLETE_EVENT_STREAM")
        return self._terminal_kind

    def accept_result(self, result: AgentResult) -> AgentResult:
        if not isinstance(result, AgentResult):
            raise ProtocolRejection("INVALID_RESULT")
        if result.identity != self.request.identity:
            raise ProtocolRejection("DISPATCH_IDENTITY_MISMATCH")
        if self._result_accepted:
            raise ProtocolRejection("DUPLICATE_RESULT")
        if self._byte_count + len(canonical_json_line(result.to_dict())) > self.request.limits.max_output_bytes:
            raise ProtocolRejection("RESULT_BYTE_LIMIT_EXCEEDED")
        terminal = self.finish()
        if result.status is not _RESULT_FOR_EVENT[terminal]:
            raise ProtocolRejection("RESULT_TERMINAL_CONFLICT")
        if result.event_count != self._event_count or result.byte_count != self._byte_count or result.stream_digest != self.stream_digest:
            raise ProtocolRejection("RESULT_STREAM_BINDING_MISMATCH")
        self._result_accepted = True
        return result
