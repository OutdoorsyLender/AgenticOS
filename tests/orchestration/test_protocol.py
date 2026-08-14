from __future__ import annotations

from dataclasses import replace

import pytest

from agenticos.orchestration.canonical import canonical_json_bytes, canonical_json_line
from agenticos.orchestration.models import Role
from agenticos.orchestration.protocol import (
    AGENT_PROTOCOL_SCHEMA,
    AgentCapability,
    AgentEvent,
    AgentEventPayload,
    AgentExitClass,
    AgentResult,
    AgentStreamValidator,
    AgentTaskRequest,
    ContextItem,
    ContextKind,
    DispatchIdentity,
    EventKind,
    EvidenceRef,
    ProtocolLimits,
    ProtocolRejection,
    ResultStatus,
    Retryability,
)


def identity(**changes: object) -> DispatchIdentity:
    values: dict[str, object] = {
        "project_id": "project-1",
        "task_id": "task-1",
        "task_generation": 1,
        "attempt": 1,
        "controller_epoch": 1,
        "lease_epoch": 0,
        "dispatch_nonce": "a" * 32,
        "repository_id": "repo-1",
        "baseline_commit": "b" * 40,
        "workspace_id": "workspace-1",
        "workspace_generation": 1,
        "reservation_id": "reservation-1",
        "checkpoint_digest": "c" * 64,
    }
    values.update(changes)
    return DispatchIdentity(**values)  # type: ignore[arg-type]


def request(**changes: object) -> AgentTaskRequest:
    values: dict[str, object] = {
        "schema": AGENT_PROTOCOL_SCHEMA,
        "identity": identity(),
        "role": Role.RESEARCHER,
        "provider_id": "synthetic",
        "model_id": "deterministic-v1",
        "workspace_mount": "/workspace",
        "instructions": "Summarize the bounded task context.",
        "acceptance_criteria": ("Return one bounded note.",),
        "context_manifest": (
            ContextItem(ContextKind.RESEARCH_NOTE, "context-1", "d" * 64, 12),
        ),
        "capabilities": (AgentCapability.READ_CONTEXT,),
        "limits": ProtocolLimits(),
    }
    values.update(changes)
    return AgentTaskRequest(**values)  # type: ignore[arg-type]


def event(sequence: int, kind: EventKind, **identity_changes: object) -> AgentEvent:
    return AgentEvent(
        schema=AGENT_PROTOCOL_SCHEMA,
        identity=identity(**identity_changes),
        sequence=sequence,
        kind=kind,
        payload=AgentEventPayload(text="bounded", evidence_refs=()),
    )


def result() -> AgentResult:
    return AgentResult(
        schema=AGENT_PROTOCOL_SCHEMA,
        identity=identity(),
        status=ResultStatus.SUCCEEDED,
        exit_class=AgentExitClass.SUCCESS,
        event_count=2,
        byte_count=1,
        stream_digest="e" * 64,
        evidence_refs=(EvidenceRef("note", "note-1", "f" * 64, 10),),
        workspace_handoff_ref=None,
        usage=None,
        retryability=Retryability.NOT_RETRYABLE,
    )


def test_valid_request_event_and_result_round_trip_strictly() -> None:
    assert AgentTaskRequest.from_dict(request().to_dict()) == request()
    assert AgentEvent.from_dict(event(1, EventKind.STARTED).to_dict()) == event(1, EventKind.STARTED)
    assert AgentResult.from_dict(result().to_dict()) == result()


def test_unknown_fields_invalid_kind_and_oversize_are_rejected() -> None:
    raw = event(1, EventKind.STARTED).to_dict()
    raw["board_status"] = "DONE"
    with pytest.raises(ProtocolRejection, match="UNKNOWN_FIELDS"):
        AgentEvent.from_dict(raw)
    raw = event(1, EventKind.STARTED).to_dict()
    raw["kind"] = "MODEL_DECIDES_DONE"
    with pytest.raises(ProtocolRejection, match="INVALID_ENUM"):
        AgentEvent.from_dict(raw)
    with pytest.raises(ProtocolRejection, match="INSTRUCTION_LIMIT_EXCEEDED"):
        request(instructions="x" * 32_769)


def test_context_and_result_claims_are_bounded_and_have_no_authority_fields() -> None:
    with pytest.raises(ProtocolRejection, match="CONTEXT_BYTE_LIMIT_EXCEEDED"):
        request(context_manifest=(ContextItem(ContextKind.RESEARCH_NOTE, "context-1", "d" * 64, 300_000),))
    raw = result().to_dict()
    assert not ({"board_status", "command", "git_ref", "credential", "accepted"} & set(raw))
    raw["accepted"] = True
    with pytest.raises(ProtocolRejection, match="UNKNOWN_FIELDS"):
        AgentResult.from_dict(raw)
    duplicate_context = request().context_manifest[0]
    with pytest.raises(ProtocolRejection, match="DUPLICATE_CONTEXT_ITEM"):
        request(context_manifest=(duplicate_context, duplicate_context))


@pytest.mark.parametrize(
    "events,code",
    [
        ((event(2, EventKind.STARTED),), "EVENT_SEQUENCE_MISMATCH"),
        ((event(1, EventKind.STARTED), event(1, EventKind.SUCCEEDED)), "EVENT_SEQUENCE_MISMATCH"),
        ((event(1, EventKind.SUCCEEDED), event(2, EventKind.SUCCEEDED)), "EVENT_AFTER_TERMINAL"),
        ((event(1, EventKind.STARTED),), "INCOMPLETE_EVENT_STREAM"),
        ((event(1, EventKind.STARTED, task_id="other"),), "DISPATCH_IDENTITY_MISMATCH"),
        ((event(1, EventKind.STARTED, task_generation=2),), "DISPATCH_IDENTITY_MISMATCH"),
        ((event(1, EventKind.STARTED, dispatch_nonce="9" * 32),), "DISPATCH_IDENTITY_MISMATCH"),
        ((event(1, EventKind.STARTED, attempt=2),), "DISPATCH_IDENTITY_MISMATCH"),
    ],
)
def test_stream_rejects_stale_spoofed_or_ambiguous_events(events, code: str) -> None:
    validator = AgentStreamValidator(request())
    with pytest.raises(ProtocolRejection, match=code):
        for item in events:
            validator.accept(canonical_json_line(item.to_dict()))
        validator.finish()


def test_stream_enforces_aggregate_event_count_and_payload_bytes() -> None:
    limited = request(limits=replace(ProtocolLimits(), max_events=1, max_event_bytes=256))
    validator = AgentStreamValidator(limited)
    with pytest.raises(ProtocolRejection, match="EVENT_BYTE_LIMIT_EXCEEDED"):
        validator.accept(canonical_json_line(event(1, EventKind.PROGRESS).to_dict()))


def test_stream_enforces_aggregate_output_bytes_before_accepting_event() -> None:
    limited = request(limits=replace(ProtocolLimits(), max_output_bytes=800))
    validator = AgentStreamValidator(limited)
    validator.accept(canonical_json_line(event(1, EventKind.STARTED).to_dict()))
    with pytest.raises(ProtocolRejection, match="OUTPUT_BYTE_LIMIT_EXCEEDED"):
        validator.accept(canonical_json_line(event(2, EventKind.SUCCEEDED).to_dict()))


def test_result_identity_is_checked_and_can_only_be_accepted_once() -> None:
    validator = AgentStreamValidator(request())
    validator.accept(canonical_json_line(event(1, EventKind.STARTED).to_dict()))
    validator.accept(canonical_json_line(event(2, EventKind.SUCCEEDED).to_dict()))
    validator.finish()
    accepted = validator.accept_result(replace(result(), event_count=2, byte_count=validator.byte_count, stream_digest=validator.stream_digest))
    assert accepted.status is ResultStatus.SUCCEEDED
    with pytest.raises(ProtocolRejection, match="DUPLICATE_RESULT"):
        validator.accept_result(accepted)
    wrong = replace(result(), identity=identity(dispatch_nonce="9" * 32))
    fresh = AgentStreamValidator(request())
    with pytest.raises(ProtocolRejection, match="DISPATCH_IDENTITY_MISMATCH"):
        fresh.accept_result(wrong)


def test_result_size_and_status_classification_are_controller_checked() -> None:
    limited = request(limits=replace(ProtocolLimits(), max_output_bytes=700))
    validator = AgentStreamValidator(limited)
    validator.accept(canonical_json_line(event(1, EventKind.SUCCEEDED).to_dict()))
    oversized = replace(
        result(),
        event_count=1,
        byte_count=validator.byte_count,
        stream_digest=validator.stream_digest,
        evidence_refs=tuple(EvidenceRef("note", f"note-{i}", "f" * 64, 1) for i in range(8)),
    )
    with pytest.raises(ProtocolRejection, match="RESULT_BYTE_LIMIT_EXCEEDED"):
        validator.accept_result(oversized)
    with pytest.raises(ProtocolRejection, match="RESULT_CLASSIFICATION_CONFLICT"):
        replace(result(), exit_class=AgentExitClass.TERMINAL)


def test_duplicate_json_keys_are_rejected_before_event_construction() -> None:
    validator = AgentStreamValidator(request())
    with pytest.raises(ProtocolRejection, match="MALFORMED_EVENT"):
        validator.accept(b'{"schema":"AOSAGENT/1","schema":"AOSAGENT/1"}\n')
