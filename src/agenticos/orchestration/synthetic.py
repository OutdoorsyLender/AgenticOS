"""Deterministic non-workspace fixtures for the exact provider-neutral ABI."""

from __future__ import annotations

import hashlib
import base64
from dataclasses import dataclass, replace
from enum import Enum

from .canonical import CanonicalDataError, canonical_json_line, load_canonical_json
from .proposals import (
    PLANNER_SCHEMA,
    REVIEW_SCHEMA,
    PlannerProposal,
    ProposedTask,
    ReviewFinding,
    ReviewerProposal,
    ReviewVerdict,
)
from .protocol import (
    AGENT_PROTOCOL_SCHEMA,
    AgentEvent,
    AgentEventPayload,
    AgentExitClass,
    AgentResult,
    AgentStreamValidator,
    AgentTaskRequest,
    EventKind,
    EvidenceRef,
    ProtocolRejection,
    ResultStatus,
    Retryability,
)
from .models import Role, TaskType


class SyntheticScenario(str, Enum):
    RESEARCHER_SUCCESS = "RESEARCHER_SUCCESS"
    PLANNER_SUCCESS = "PLANNER_SUCCESS"
    REVIEWER_PASS = "REVIEWER_PASS"
    REVIEWER_FAIL = "REVIEWER_FAIL"
    REVIEWER_MUTATE_CREATE = "REVIEWER_MUTATE_CREATE"
    REVIEWER_MUTATE_WRITE = "REVIEWER_MUTATE_WRITE"
    REVIEWER_MUTATE_RENAME = "REVIEWER_MUTATE_RENAME"
    REVIEWER_MUTATE_DELETE = "REVIEWER_MUTATE_DELETE"
    REVIEWER_DOT_GIT_ACCESS = "REVIEWER_DOT_GIT_ACCESS"
    REVIEWER_HOST_ACCESS = "REVIEWER_HOST_ACCESS"
    REVIEWER_CONTROLLER_ACCESS = "REVIEWER_CONTROLLER_ACCESS"
    REVIEWER_CREDENTIAL_ACCESS = "REVIEWER_CREDENTIAL_ACCESS"
    NO_OP = "NO_OP"
    RETRYABLE_FAILURE = "RETRYABLE_FAILURE"
    TERMINAL_FAILURE = "TERMINAL_FAILURE"
    MALFORMED_EVENT = "MALFORMED_EVENT"
    UNKNOWN_EVENT_KIND = "UNKNOWN_EVENT_KIND"
    OUT_OF_ORDER = "OUT_OF_ORDER"
    DUPLICATE_TERMINAL = "DUPLICATE_TERMINAL"
    CONFLICTING_TERMINAL = "CONFLICTING_TERMINAL"
    OVERSIZED_PAYLOAD = "OVERSIZED_PAYLOAD"
    WRONG_TASK = "WRONG_TASK"
    WRONG_GENERATION = "WRONG_GENERATION"
    WRONG_NONCE = "WRONG_NONCE"
    STALE_ATTEMPT = "STALE_ATTEMPT"
    INCOMPLETE_STREAM = "INCOMPLETE_STREAM"
    SUCCESSFUL_EDIT = "SUCCESSFUL_EDIT"
    BROKEN_FEATURE_EDIT = "BROKEN_FEATURE_EDIT"
    REPAIR_FEATURE = "REPAIR_FEATURE"
    REPAIR_REVIEW = "REPAIR_REVIEW"
    INVALID_PATH_ATTEMPT = "INVALID_PATH_ATTEMPT"
    DOT_GIT_ATTEMPT = "DOT_GIT_ATTEMPT"
    CRASH_AFTER_EDIT = "CRASH_AFTER_EDIT"
    TIMEOUT_AFTER_EDIT = "TIMEOUT_AFTER_EDIT"
    CHILD_PROCESS_CASE = "CHILD_PROCESS_CASE"
    POST_TERMINAL_MUTATION_ATTEMPT = "POST_TERMINAL_MUTATION_ATTEMPT"


@dataclass(frozen=True, slots=True)
class SyntheticFixture:
    scenario: SyntheticScenario
    events: tuple[bytes, ...]
    result: AgentResult | None
    artifacts: tuple[tuple[str, bytes], ...] = ()
    provider_calls: int = 0
    process_spawns: int = 0
    workspace_accesses: int = 0
    network_accesses: int = 0


@dataclass(frozen=True, slots=True)
class SyntheticOutcome:
    accepted: bool
    rejection_code: str | None
    result: AgentResult | None


WORKSPACE_SCENARIOS = frozenset(
    {
        SyntheticScenario.REVIEWER_PASS,
        SyntheticScenario.REVIEWER_FAIL,
        SyntheticScenario.REVIEWER_MUTATE_CREATE,
        SyntheticScenario.REVIEWER_MUTATE_WRITE,
        SyntheticScenario.REVIEWER_MUTATE_RENAME,
        SyntheticScenario.REVIEWER_MUTATE_DELETE,
        SyntheticScenario.REVIEWER_DOT_GIT_ACCESS,
        SyntheticScenario.REVIEWER_HOST_ACCESS,
        SyntheticScenario.REVIEWER_CONTROLLER_ACCESS,
        SyntheticScenario.REVIEWER_CREDENTIAL_ACCESS,
        SyntheticScenario.SUCCESSFUL_EDIT,
        SyntheticScenario.BROKEN_FEATURE_EDIT,
        SyntheticScenario.REPAIR_FEATURE,
        SyntheticScenario.REPAIR_REVIEW,
        SyntheticScenario.NO_OP,
        SyntheticScenario.INVALID_PATH_ATTEMPT,
        SyntheticScenario.DOT_GIT_ATTEMPT,
        SyntheticScenario.CRASH_AFTER_EDIT,
        SyntheticScenario.TIMEOUT_AFTER_EDIT,
        SyntheticScenario.CHILD_PROCESS_CASE,
        SyntheticScenario.POST_TERMINAL_MUTATION_ATTEMPT,
    }
)


def build_synthetic_workspace_argv(
    request: AgentTaskRequest, scenario: SyntheticScenario
) -> list[str]:
    """Build the fixed in-sandbox argv without exposing a host locator."""
    if not isinstance(request, AgentTaskRequest) or scenario not in WORKSPACE_SCENARIOS:
        raise ValueError("strict Slice C request and scenario are required")
    encoded = base64.urlsafe_b64encode(canonical_json_line(request.to_dict())[:-1]).decode("ascii")
    return [
        "/usr/bin/python3",
        "/opt/agenticos/worker.py",
        "--scenario",
        scenario.value,
        "--request-base64",
        encoded,
    ]


def validate_synthetic_process_output(
    request: AgentTaskRequest, raw: bytes
) -> SyntheticOutcome:
    """Validate exact worker bytes; decoded replacement text is never authority."""
    if not isinstance(request, AgentTaskRequest) or type(raw) is not bytes:
        raise TypeError("strict request and raw bytes are required")
    validator = AgentStreamValidator(request)
    try:
        lines = raw.splitlines(keepends=True)
        if len(lines) < 2 or any(not line.endswith(b"\n") for line in lines):
            raise ProtocolRejection("MISSING_RESULT")
        for line in lines[:-1]:
            validator.accept(line)
        result_raw = lines[-1]
        value = load_canonical_json(
            result_raw[:-1], max_bytes=request.limits.max_output_bytes
        )
        if canonical_json_line(value, max_bytes=request.limits.max_output_bytes) != result_raw:
            raise ProtocolRejection("NONCANONICAL_RESULT")
        result = AgentResult.from_dict(value)
        return SyntheticOutcome(True, None, validator.accept_result(result))
    except (CanonicalDataError, ProtocolRejection, TypeError, ValueError) as exc:
        code = exc.code if isinstance(exc, ProtocolRejection) else "MALFORMED_RESULT"
        return SyntheticOutcome(False, code, None)


def _event(request: AgentTaskRequest, sequence: int, kind: EventKind, text: str = "", refs: tuple[EvidenceRef, ...] = ()) -> AgentEvent:
    return AgentEvent(
        schema=AGENT_PROTOCOL_SCHEMA,
        identity=request.identity,
        sequence=sequence,
        kind=kind,
        payload=AgentEventPayload(text=text, evidence_refs=refs),
    )


def _artifact(kind: str, artifact_id: str, content: bytes) -> EvidenceRef:
    return EvidenceRef(kind, artifact_id, hashlib.sha256(content).hexdigest(), len(content))


def _result(request: AgentTaskRequest, events: tuple[bytes, ...], terminal: EventKind, refs: tuple[EvidenceRef, ...]) -> AgentResult:
    status = ResultStatus(terminal.value)
    exit_class = {
        EventKind.SUCCEEDED: AgentExitClass.SUCCESS,
        EventKind.NO_OP: AgentExitClass.NO_OP,
        EventKind.RETRYABLE_FAILURE: AgentExitClass.RETRYABLE,
        EventKind.TERMINAL_FAILURE: AgentExitClass.TERMINAL,
        EventKind.BLOCKED: AgentExitClass.TERMINAL,
        EventKind.CANCELLED: AgentExitClass.CANCELLED,
    }[terminal]
    retryability = Retryability.RETRYABLE if terminal is EventKind.RETRYABLE_FAILURE else Retryability.NOT_RETRYABLE
    stream = b"".join(events)
    return AgentResult(
        schema=AGENT_PROTOCOL_SCHEMA,
        identity=request.identity,
        status=status,
        exit_class=exit_class,
        event_count=len(events),
        byte_count=len(stream),
        stream_digest=hashlib.sha256(stream).hexdigest(),
        evidence_refs=refs,
        workspace_handoff_ref=None,
        usage=None,
        retryability=retryability,
    )


def _normal_fixture(request: AgentTaskRequest, scenario: SyntheticScenario) -> SyntheticFixture:
    artifacts: tuple[tuple[str, bytes], ...] = ()
    refs: tuple[EvidenceRef, ...] = ()
    middle_kind = EventKind.PROGRESS
    middle_text = "Deterministic bounded progress."
    terminal = EventKind.SUCCEEDED
    if scenario is SyntheticScenario.RESEARCHER_SUCCESS:
        content = canonical_json_line({"schema": "AOSNOTE/1", "note": "Bounded deterministic research."})
        artifacts = (("research-note-1", content),)
    elif scenario is SyntheticScenario.PLANNER_SUCCESS:
        plan = PlannerProposal(
            schema=PLANNER_SCHEMA,
            tasks=(ProposedTask("build", "Build fixture", "Implement bounded fixture.", TaskType.BUILD, (), ("Focused test passes.",), Role.BUILDER, 50),),
        )
        content = canonical_json_line(plan.to_dict())
        artifacts = (("planner-proposal-1", content),)
        middle_kind = EventKind.PROPOSAL
        middle_text = "Planner proposal artifact emitted."
    elif scenario in {SyntheticScenario.REVIEWER_PASS, SyntheticScenario.REVIEWER_FAIL}:
        if scenario is SyntheticScenario.REVIEWER_PASS:
            review = ReviewerProposal(REVIEW_SCHEMA, ReviewVerdict.PASS, (), None, ())
        else:
            review = ReviewerProposal(REVIEW_SCHEMA, ReviewVerdict.BLOCKING, (ReviewFinding("SYNTHETIC_FINDING", "Repair the deterministic fixture."),), "Apply the bounded repair.", ())
        content = canonical_json_line(review.to_dict())
        artifacts = (("review-proposal-1", content),)
        middle_kind = EventKind.PROPOSAL
        middle_text = content[:-1].decode("utf-8")
    elif scenario is SyntheticScenario.NO_OP:
        terminal = EventKind.NO_OP
    elif scenario is SyntheticScenario.RETRYABLE_FAILURE:
        terminal = EventKind.RETRYABLE_FAILURE
    elif scenario is SyntheticScenario.TERMINAL_FAILURE:
        terminal = EventKind.TERMINAL_FAILURE
    if artifacts:
        refs = tuple(_artifact("proposal" if middle_kind is EventKind.PROPOSAL else "note", name, content) for name, content in artifacts)
    events = (
        canonical_json_line(_event(request, 1, EventKind.STARTED, "Synthetic fixture started.").to_dict()),
        canonical_json_line(_event(request, 2, middle_kind, middle_text, refs).to_dict()),
        canonical_json_line(_event(request, 3, terminal, "Synthetic fixture terminated.", refs).to_dict()),
    )
    return SyntheticFixture(scenario, events, _result(request, events, terminal, refs), artifacts)


def build_synthetic_fixture(request: AgentTaskRequest, scenario: SyntheticScenario) -> SyntheticFixture:
    if not isinstance(request, AgentTaskRequest) or not isinstance(scenario, SyntheticScenario):
        raise TypeError("strict request and scenario values are required")
    normal = {
        SyntheticScenario.RESEARCHER_SUCCESS, SyntheticScenario.PLANNER_SUCCESS,
        SyntheticScenario.REVIEWER_PASS, SyntheticScenario.REVIEWER_FAIL,
        SyntheticScenario.NO_OP, SyntheticScenario.RETRYABLE_FAILURE,
        SyntheticScenario.TERMINAL_FAILURE,
    }
    if scenario in normal:
        return _normal_fixture(request, scenario)
    started = _event(request, 1, EventKind.STARTED, "Synthetic fixture started.")
    success = _event(request, 1, EventKind.SUCCEEDED, "terminal")
    if scenario is SyntheticScenario.MALFORMED_EVENT:
        events = (b'{"schema":\n',)
    elif scenario is SyntheticScenario.UNKNOWN_EVENT_KIND:
        raw = started.to_dict()
        raw["kind"] = "UNKNOWN_KIND"
        events = (canonical_json_line(raw),)
    elif scenario is SyntheticScenario.OUT_OF_ORDER:
        events = (canonical_json_line(replace(started, sequence=2).to_dict()),)
    elif scenario is SyntheticScenario.DUPLICATE_TERMINAL:
        events = (canonical_json_line(success.to_dict()), canonical_json_line(replace(success, sequence=2).to_dict()))
    elif scenario is SyntheticScenario.CONFLICTING_TERMINAL:
        events = (canonical_json_line(success.to_dict()), canonical_json_line(_event(request, 2, EventKind.TERMINAL_FAILURE).to_dict()))
    elif scenario is SyntheticScenario.OVERSIZED_PAYLOAD:
        raw = started.to_dict()
        raw["payload"]["text"] = "x" * request.limits.max_event_bytes  # type: ignore[index]
        events = (canonical_json_line(raw, max_bytes=request.limits.max_event_bytes * 2),)
    elif scenario in {SyntheticScenario.WRONG_TASK, SyntheticScenario.WRONG_GENERATION, SyntheticScenario.WRONG_NONCE, SyntheticScenario.STALE_ATTEMPT}:
        changes = {
            SyntheticScenario.WRONG_TASK: {"task_id": "other-task"},
            SyntheticScenario.WRONG_GENERATION: {"task_generation": request.identity.task_generation + 1},
            SyntheticScenario.WRONG_NONCE: {"dispatch_nonce": "9" * 32},
            SyntheticScenario.STALE_ATTEMPT: {"attempt": request.identity.attempt + 1},
        }[scenario]
        events = (canonical_json_line(replace(started, identity=replace(request.identity, **changes)).to_dict()),)
    else:
        events = (canonical_json_line(started.to_dict()),)
    return SyntheticFixture(scenario, events, None)


def run_synthetic_fixture(request: AgentTaskRequest, fixture: SyntheticFixture) -> SyntheticOutcome:
    validator = AgentStreamValidator(request)
    try:
        for raw in fixture.events:
            validator.accept(raw)
        validator.finish()
        if fixture.result is None:
            raise ProtocolRejection("MISSING_RESULT")
        accepted = validator.accept_result(fixture.result)
        return SyntheticOutcome(True, None, accepted)
    except ProtocolRejection as exc:
        return SyntheticOutcome(False, exc.code, None)
