"""Tests for the F1 Kimi Planner qualification protocol types (slice 1)."""

from __future__ import annotations

import hashlib
import inspect

import pytest

from agenticos.orchestration.canonical import canonical_json_bytes
from agenticos.providers import kimi_planner_types as kpt
from agenticos.providers.kimi_planner_types import (
    ACCOUNTING_BOUNDS,
    ATTEMPT_SCHEMA,
    HISTORICAL_F1_KIMI_LEVEL1_REAL_ATTEMPT_COUNT,
    HISTORICAL_F1_KIMI_LEVEL1_REASON,
    HISTORICAL_F1_KIMI_LEVEL1_RESULT,
    OPAQUE_TLS_HTTP_COUNT_MARKER,
    RESULT_FIELD_PROVENANCE,
    RESULT_SCHEMA,
    REAL_ATTEMPT_COUNT,
    AccountingBound,
    AttemptRecord,
    AuthRefreshState,
    CompilePreviewRequest,
    EvidenceProvenance,
    KimiPlannerTypeError,
    PlannerEgressMachine,
    PlannerEgressState,
    PlannerFailureCode,
    ResultRecord,
    kimi_planner_prompt,
    kimi_planner_prompt_canonical_bytes,
    kimi_planner_prompt_sha256,
    validate_bounded_count,
)


_HEX64 = "ab" * 32
_HEX64_B = "cd" * 32
_HEX40 = "ef" * 20


def _attempt_dict(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "schema": ATTEMPT_SCHEMA,
        "planner_attempt_number": 1,
        "implementation_commit": _HEX40,
        "authorization_digest": _HEX64,
        "kimi_version": "0.36.1",
        "kimi_source_commit": "13d86f8b7bb2443a3b8222e7d94deb0a66429f8e",
        "kimi_executable_sha256": _HEX64,
        "kimi_namespace_launcher_sha256": _HEX64_B,
        "config_digest": _HEX64,
        "profile_digest": _HEX64,
        "mediator_policy_digest": _HEX64,
        "prompt_digest": _HEX64,
        "historical_level1_result": HISTORICAL_F1_KIMI_LEVEL1_RESULT,
        "historical_reason": HISTORICAL_F1_KIMI_LEVEL1_REASON,
        "historical_real_attempt_count": HISTORICAL_F1_KIMI_LEVEL1_REAL_ATTEMPT_COUNT,
        "claim_timestamp": "2026-08-17T00:00:00Z",
    }
    data.update(overrides)
    return data


def _result_dict(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "schema": RESULT_SCHEMA,
        "qualification_state": "BLOCKED",
        "primary_failure_code": None,
        "local_credential_recognized": True,
        "credential_refresh_state": "NOT_REQUIRED",
        "acp_real_prompt_count": 1,
        "planner_proposal_count": 1,
        "aosplan_validated": True,
        "model_allowance_claim_count": 1,
        "model_tunnel_admission_count": 1,
        "auth_tunnel_admission_count": 1,
        "model_http_request_count": OPAQUE_TLS_HTTP_COUNT_MARKER,
        "auth_http_request_count": OPAQUE_TLS_HTTP_COUNT_MARKER,
        "sdk_retry_configuration": 0,
        "loop_attempt_limit": 1,
        "loop_step_limit": 1,
        "model_host": "api.kimi.com",
        "auth_host": "auth.kimi.com",
        "model_base_url": "https://api.kimi.com/coding/v1",
        "wire_model": "kimi-for-coding",
        "oauth_storage_path": "oauth/kimi-code",
        "tls_transport_policy": "END_TO_END_ORIGIN_TLS",
        "server_auth_accepted_inferred_from_successful_model_turn": True,
        "prompt_byte_count": 512,
        "prompt_sha256": _HEX64,
        "output_byte_count": 128,
        "output_sha256": _HEX64_B,
        "acp_terminal_state": "SESSION_CLOSED",
        "network_terminal_state": "CLOSED",
        "cleanup_completed": True,
        "residue_count": 0,
    }
    data.update(overrides)
    return data


def _model_once() -> PlannerEgressMachine:
    machine = PlannerEgressMachine()
    machine = machine.begin_auth_window().machine
    machine = machine.request_model_tunnel().machine
    return machine.complete_auth_drain(AuthRefreshState.NOT_REQUIRED).machine


def test_initial_state() -> None:
    machine = PlannerEgressMachine()
    assert machine.state is PlannerEgressState.START
    assert machine.active_auth_tunnels == 0
    assert machine.auth_tunnel_admission_count == 0
    assert machine.model_allowance_claimed is False
    assert machine.model_tunnel_admission_count == 0
    assert machine.auth_admission_revoked is False
    assert machine.acp_real_prompt_count == 0
    assert machine.planner_proposal_count == 0
    assert machine.terminal_failure_code is None


@pytest.mark.parametrize("refresh_state", ["NOT_REQUIRED", "COMPLETED_AND_PERSISTED"])
def test_happy_path_full_sequence(refresh_state: str) -> None:
    machine = PlannerEgressMachine()

    result = machine.begin_auth_window()
    assert result.accepted and result.failure_code is None
    machine = result.machine
    assert machine.state is PlannerEgressState.AUTH_WINDOW

    result = machine.admit_auth_tunnel()
    assert result.accepted
    machine = result.machine
    assert machine.active_auth_tunnels == 1
    assert machine.auth_tunnel_admission_count == 1

    result = machine.auth_tunnel_closed()
    assert result.accepted
    machine = result.machine
    assert machine.active_auth_tunnels == 0

    result = machine.request_model_tunnel()
    assert result.accepted
    machine = result.machine
    assert machine.state is PlannerEgressState.AUTH_DRAINING
    assert machine.model_allowance_claimed is True
    assert machine.auth_admission_revoked is True

    result = machine.complete_auth_drain(refresh_state)
    assert result.accepted
    machine = result.machine
    assert machine.state is PlannerEgressState.MODEL_ONCE
    assert machine.model_tunnel_admission_count == 1

    result = machine.admit_prompt()
    assert result.accepted
    machine = result.machine
    assert machine.acp_real_prompt_count == 1

    result = machine.accept_proposal()
    assert result.accepted
    machine = result.machine
    assert machine.planner_proposal_count == 1

    result = machine.model_tunnel_terminated()
    assert result.accepted
    machine = result.machine
    assert machine.state is PlannerEgressState.CLOSED
    assert machine.terminal_failure_code is None


def test_happy_path_drain_interrupts_active_auth_tunnel() -> None:
    machine = PlannerEgressMachine().begin_auth_window().machine
    machine = machine.admit_auth_tunnel().machine
    machine = machine.request_model_tunnel().machine
    assert machine.state is PlannerEgressState.AUTH_DRAINING
    assert machine.active_auth_tunnels == 1
    result = machine.auth_tunnel_closed()
    assert result.accepted
    result = result.machine.complete_auth_drain(AuthRefreshState.COMPLETED_AND_PERSISTED)
    assert result.accepted
    assert result.machine.state is PlannerEgressState.MODEL_ONCE


@pytest.mark.parametrize(
    "event_name",
    [
        "admit_auth_tunnel",
        "auth_tunnel_closed",
        "request_model_tunnel",
        "complete_auth_drain",
        "admit_prompt",
        "accept_proposal",
        "model_tunnel_terminated",
    ],
)
def test_invalid_events_from_start_fail_closed(event_name: str) -> None:
    machine = PlannerEgressMachine()
    event = getattr(machine, event_name)
    result = (
        event(AuthRefreshState.NOT_REQUIRED)
        if event_name == "complete_auth_drain"
        else event()
    )
    assert not result.accepted
    assert result.machine.state is PlannerEgressState.CLOSED
    assert result.machine.terminal_failure_code is not None
    assert result.failure_code is not None


def test_invalid_events_from_each_state_fail_closed() -> None:
    window = PlannerEgressMachine().begin_auth_window().machine
    draining = window.request_model_tunnel().machine
    model_once = draining.complete_auth_drain(AuthRefreshState.NOT_REQUIRED).machine

    # From AUTH_WINDOW.
    assert not window.begin_auth_window().accepted
    assert not window.complete_auth_drain(AuthRefreshState.NOT_REQUIRED).accepted
    assert not window.admit_prompt().accepted
    assert not window.accept_proposal().accepted
    assert not window.model_tunnel_terminated().accepted
    assert not window.auth_tunnel_closed().accepted  # no active tunnel

    # From AUTH_DRAINING.
    assert not draining.begin_auth_window().accepted
    assert not draining.admit_auth_tunnel().accepted
    assert not draining.admit_prompt().accepted
    assert not draining.accept_proposal().accepted
    assert not draining.model_tunnel_terminated().accepted

    # From MODEL_ONCE.
    assert not model_once.begin_auth_window().accepted
    assert not model_once.admit_auth_tunnel().accepted
    assert not model_once.auth_tunnel_closed().accepted
    assert not model_once.complete_auth_drain(AuthRefreshState.NOT_REQUIRED).accepted

    for outcome in (
        window.begin_auth_window(),
        draining.admit_auth_tunnel(),
        model_once.complete_auth_drain(AuthRefreshState.NOT_REQUIRED),
    ):
        assert outcome.machine.state is PlannerEgressState.CLOSED
        assert outcome.failure_code is not None


def test_auth_cannot_reopen_after_revocation() -> None:
    draining = (
        PlannerEgressMachine().begin_auth_window().machine.request_model_tunnel().machine
    )
    model_once = draining.complete_auth_drain(AuthRefreshState.NOT_REQUIRED).machine
    closed = model_once.model_tunnel_terminated().machine
    for machine in (draining, model_once, closed):
        result = machine.admit_auth_tunnel()
        assert not result.accepted
        assert result.failure_code is PlannerFailureCode.AUTH_EGRESS_POLICY_FAILED or (
            machine.state is PlannerEgressState.CLOSED
        )
        assert result.machine.auth_admission_revoked is True


def test_model_allowance_claimable_only_once() -> None:
    draining = (
        PlannerEgressMachine().begin_auth_window().machine.request_model_tunnel().machine
    )
    result = draining.request_model_tunnel()
    assert not result.accepted
    assert result.failure_code is PlannerFailureCode.MODEL_TUNNEL_ALREADY_CONSUMED
    assert result.machine.state is PlannerEgressState.CLOSED
    assert result.machine.model_allowance_claimed is True
    assert result.machine.auth_admission_revoked is True
    assert result.machine.model_tunnel_admission_count == 0


def test_failure_after_claim_leaves_allowance_consumed() -> None:
    draining = (
        PlannerEgressMachine().begin_auth_window().machine.request_model_tunnel().machine
    )
    result = draining.fail(PlannerFailureCode.TLS_OR_TUNNEL_FAILED)
    assert result.accepted
    machine = result.machine
    assert machine.state is PlannerEgressState.CLOSED
    assert machine.model_allowance_claimed is True
    assert machine.auth_admission_revoked is True
    assert machine.model_tunnel_admission_count == 0
    assert machine.terminal_failure_code is PlannerFailureCode.TLS_OR_TUNNEL_FAILED
    # A later model request in CLOSED regains nothing.
    again = machine.request_model_tunnel()
    assert not again.accepted
    assert again.machine is machine


def test_drain_failure_keeps_allowance_spent() -> None:
    draining = (
        PlannerEgressMachine().begin_auth_window().machine.request_model_tunnel().machine
    )
    result = draining.complete_auth_drain(AuthRefreshState.FAILED)
    assert not result.accepted
    assert result.failure_code is PlannerFailureCode.AUTH_REFRESH_FAILED
    machine = result.machine
    assert machine.state is PlannerEgressState.CLOSED
    assert machine.model_allowance_claimed is True
    assert machine.auth_admission_revoked is True
    assert machine.model_tunnel_admission_count == 0


def test_model_admission_requires_empty_auth_registry() -> None:
    machine = PlannerEgressMachine().begin_auth_window().machine
    machine = machine.admit_auth_tunnel().machine
    draining = machine.request_model_tunnel().machine
    result = draining.complete_auth_drain(AuthRefreshState.NOT_REQUIRED)
    assert not result.accepted
    assert result.failure_code is PlannerFailureCode.AUTH_EGRESS_POLICY_FAILED
    assert result.machine.state is PlannerEgressState.CLOSED
    assert result.machine.model_allowance_claimed is True
    assert result.machine.model_tunnel_admission_count == 0


@pytest.mark.parametrize("refresh_state", ["IN_PROGRESS", "FAILED", "INTERRUPTED", "AMBIGUOUS"])
def test_model_admission_denied_for_blocking_refresh_states(refresh_state: str) -> None:
    draining = (
        PlannerEgressMachine().begin_auth_window().machine.request_model_tunnel().machine
    )
    result = draining.complete_auth_drain(refresh_state)
    assert not result.accepted
    assert result.failure_code is PlannerFailureCode.AUTH_REFRESH_FAILED
    assert result.machine.state is PlannerEgressState.CLOSED
    assert result.machine.model_allowance_claimed is True
    assert result.machine.model_tunnel_admission_count == 0


def test_drain_rejects_unrecognized_refresh_state() -> None:
    draining = (
        PlannerEgressMachine().begin_auth_window().machine.request_model_tunnel().machine
    )
    for bogus in ("SAVED", "", None, 7):
        result = draining.complete_auth_drain(bogus)  # type: ignore[arg-type]
        assert not result.accepted
        assert result.failure_code is PlannerFailureCode.AUTH_REFRESH_FAILED
        assert result.machine.state is PlannerEgressState.CLOSED


def test_second_model_admission_rejects() -> None:
    model_once = _model_once()
    result = model_once.request_model_tunnel()
    assert not result.accepted
    assert result.failure_code is PlannerFailureCode.MODEL_TUNNEL_ALREADY_CONSUMED
    assert result.machine.state is PlannerEgressState.CLOSED
    assert result.machine.model_tunnel_admission_count == 1


def test_second_prompt_rejects() -> None:
    model_once = _model_once().admit_prompt().machine
    result = model_once.admit_prompt()
    assert not result.accepted
    assert result.failure_code is PlannerFailureCode.ACP_PROTOCOL_FAILED
    assert result.machine.state is PlannerEgressState.CLOSED
    assert result.machine.acp_real_prompt_count == 1


def test_second_proposal_rejects() -> None:
    machine = _model_once().admit_prompt().machine.accept_proposal().machine
    result = machine.accept_proposal()
    assert not result.accepted
    assert result.failure_code is PlannerFailureCode.ACP_PROTOCOL_FAILED
    assert result.machine.state is PlannerEgressState.CLOSED
    assert result.machine.planner_proposal_count == 1


def test_proposal_requires_prompt() -> None:
    result = _model_once().accept_proposal()
    assert not result.accepted
    assert result.machine.state is PlannerEgressState.CLOSED


def test_prompt_requires_model_tunnel() -> None:
    window = PlannerEgressMachine().begin_auth_window().machine
    result = window.admit_prompt()
    assert not result.accepted
    assert result.machine.state is PlannerEgressState.CLOSED


def test_auth_tunnel_lifetime_bound_three() -> None:
    machine = PlannerEgressMachine().begin_auth_window().machine
    for expected_count in (1, 2, 3):
        result = machine.admit_auth_tunnel()
        assert result.accepted
        machine = result.machine
        assert machine.auth_tunnel_admission_count == expected_count
        machine = machine.auth_tunnel_closed().machine
    result = machine.admit_auth_tunnel()
    assert not result.accepted
    assert result.failure_code is PlannerFailureCode.AUTH_EGRESS_POLICY_FAILED
    assert result.machine.state is PlannerEgressState.CLOSED
    assert result.machine.auth_tunnel_admission_count == 3


def test_second_concurrent_auth_tunnel_rejects() -> None:
    machine = PlannerEgressMachine().begin_auth_window().machine.admit_auth_tunnel().machine
    result = machine.admit_auth_tunnel()
    assert not result.accepted
    assert result.machine.state is PlannerEgressState.CLOSED


def test_closed_regains_no_authority() -> None:
    machine = _model_once().model_tunnel_terminated().machine
    snapshot = machine
    events = (
        machine.begin_auth_window,
        machine.admit_auth_tunnel,
        machine.auth_tunnel_closed,
        machine.request_model_tunnel,
        machine.admit_prompt,
        machine.accept_proposal,
        machine.model_tunnel_terminated,
        machine.fail,
    )
    for event in events:
        result = (
            event(PlannerFailureCode.TIMEOUT)
            if event == machine.fail
            else event()
        )
        assert not result.accepted
        assert result.machine is snapshot
        assert result.machine.state is PlannerEgressState.CLOSED


def test_failed_machine_absorbs_events() -> None:
    machine = PlannerEgressMachine().fail(PlannerFailureCode.TIMEOUT).machine
    assert machine.terminal_failure_code is PlannerFailureCode.TIMEOUT
    for event in (machine.begin_auth_window, machine.admit_auth_tunnel, machine.admit_prompt):
        result = event()
        assert not result.accepted
        assert result.machine is machine
        assert result.failure_code is PlannerFailureCode.TIMEOUT


def test_machine_constructor_rejects_inconsistent_state() -> None:
    with pytest.raises(KimiPlannerTypeError):
        PlannerEgressMachine(state="START")  # type: ignore[arg-type]
    with pytest.raises(KimiPlannerTypeError):
        PlannerEgressMachine(active_auth_tunnels=2)
    with pytest.raises(KimiPlannerTypeError):
        PlannerEgressMachine(auth_tunnel_admission_count=4)
    with pytest.raises(KimiPlannerTypeError):
        PlannerEgressMachine(model_tunnel_admission_count=1)  # no allowance claim
    with pytest.raises(KimiPlannerTypeError):
        PlannerEgressMachine(planner_proposal_count=1)  # no prompt
    with pytest.raises(KimiPlannerTypeError):
        PlannerEgressMachine(active_auth_tunnels=True)  # bool is not a count
    with pytest.raises(KimiPlannerTypeError):
        PlannerEgressMachine(
            state=PlannerEgressState.CLOSED,
            active_auth_tunnels=1,
            auth_tunnel_admission_count=1,
        )


def test_result_schema_rejects_numeric_http_counts() -> None:
    for field in ("model_http_request_count", "auth_http_request_count"):
        for bad in (0, 1, 21, 42, 63, 126, True):
            with pytest.raises(KimiPlannerTypeError):
                ResultRecord.from_dict(_result_dict(**{field: bad}))
        data = _result_dict(**{field: OPAQUE_TLS_HTTP_COUNT_MARKER})
        assert ResultRecord.from_dict(data).to_dict() == data


def test_provenance_enum_rejects_unsupported_values() -> None:
    with pytest.raises(ValueError):
        EvidenceProvenance("DIRECT_TLS_OBSERVATION")
    with pytest.raises(ValueError):
        AuthRefreshState("SAVED")
    with pytest.raises(ValueError):
        PlannerEgressState("MODEL_SPENT")
    with pytest.raises(KimiPlannerTypeError):
        ResultRecord.from_dict(_result_dict(credential_refresh_state="SAVED"))
    with pytest.raises(KimiPlannerTypeError):
        ResultRecord.from_dict(_result_dict(network_terminal_state="MODEL_SPENT"))
    with pytest.raises(KimiPlannerTypeError):
        ResultRecord.from_dict(_result_dict(primary_failure_code="HTTP_401"))


def test_failure_taxonomy_has_exact_fifteen_codes_no_http_status() -> None:
    names = {member.name for member in PlannerFailureCode}
    assert names == {
        "LOCAL_AUTH_REJECTED",
        "AUTH_REFRESH_FAILED",
        "AUTH_EGRESS_POLICY_FAILED",
        "MODEL_EGRESS_POLICY_FAILED",
        "MODEL_TUNNEL_ALREADY_CONSUMED",
        "TLS_OR_TUNNEL_FAILED",
        "SNI_MISMATCH",
        "DNS_POLICY_FAILED",
        "ACP_PROTOCOL_FAILED",
        "PROVIDER_INFERENCE_FAILED",
        "MODEL_OUTPUT_INVALID",
        "AOSPLAN_INVALID",
        "TIMEOUT",
        "CLEANUP_FAILED",
        "EVIDENCE_FAILED",
    }
    forbidden_fragments = ("HTTP", "401", "403", "429", "5XX", "STATUS")
    for name in names:
        for fragment in forbidden_fragments:
            assert fragment not in name


def test_historical_immutability_constants() -> None:
    assert HISTORICAL_F1_KIMI_LEVEL1_RESULT == "BLOCKED"
    assert HISTORICAL_F1_KIMI_LEVEL1_REASON == "AUTH_METHOD_SHAPE"
    assert HISTORICAL_F1_KIMI_LEVEL1_REAL_ATTEMPT_COUNT == 1
    assert REAL_ATTEMPT_COUNT == 1


def test_historical_attempt_count_must_equal_one() -> None:
    assert AttemptRecord.from_dict(_attempt_dict()).historical_real_attempt_count == 1
    for bad in (0, 2, -1, True, "1"):
        with pytest.raises(KimiPlannerTypeError):
            AttemptRecord.from_dict(_attempt_dict(historical_real_attempt_count=bad))
    with pytest.raises(KimiPlannerTypeError):
        AttemptRecord.from_dict(_attempt_dict(historical_level1_result="QUALIFIED"))
    with pytest.raises(KimiPlannerTypeError):
        AttemptRecord.from_dict(_attempt_dict(historical_reason="OTHER"))


def test_serialization_determinism_and_round_trip() -> None:
    first = ResultRecord.from_dict(_result_dict())
    second = ResultRecord.from_dict(_result_dict())
    assert first == second
    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.canonical_bytes() == canonical_json_bytes(_result_dict())
    assert ResultRecord.from_dict(first.to_dict()) == first

    attempt = AttemptRecord.from_dict(_attempt_dict())
    assert attempt.canonical_bytes() == canonical_json_bytes(_attempt_dict())
    assert AttemptRecord.from_dict(attempt.to_dict()) == attempt

    assert kimi_planner_prompt_canonical_bytes() == kimi_planner_prompt_canonical_bytes()
    assert kimi_planner_prompt_sha256() == kimi_planner_prompt_sha256()
    assert (
        kimi_planner_prompt_sha256()
        == hashlib.sha256(kimi_planner_prompt_canonical_bytes()).hexdigest()
    )


def test_schema_field_strictness() -> None:
    for build, record in (
        (_result_dict, ResultRecord),
        (_attempt_dict, AttemptRecord),
    ):
        base = build()
        with pytest.raises(KimiPlannerTypeError):
            record.from_dict({**base, "unexpected_field": 1})
        for key in base:
            incomplete = {k: v for k, v in base.items() if k != key}
            with pytest.raises(KimiPlannerTypeError):
                record.from_dict(incomplete)
        with pytest.raises(KimiPlannerTypeError):
            record.from_dict("not-a-dict")
        wrong_schema = dict(base)
        wrong_schema["schema"] = "AOS_OTHER/1"
        with pytest.raises(KimiPlannerTypeError):
            record.from_dict(wrong_schema)


def test_booleans_rejected_for_integer_counters() -> None:
    for field in (
        "acp_real_prompt_count",
        "planner_proposal_count",
        "model_allowance_claim_count",
        "model_tunnel_admission_count",
        "auth_tunnel_admission_count",
        "sdk_retry_configuration",
        "prompt_byte_count",
        "residue_count",
    ):
        for bad in (True, False):
            with pytest.raises(KimiPlannerTypeError):
                ResultRecord.from_dict(_result_dict(**{field: bad}))
    with pytest.raises(KimiPlannerTypeError):
        AttemptRecord.from_dict(_attempt_dict(planner_attempt_number=True))
    with pytest.raises(KimiPlannerTypeError):
        validate_bounded_count(True, name="x", bound=1)


def test_negative_counts_rejected() -> None:
    for field in (
        "acp_real_prompt_count",
        "model_allowance_claim_count",
        "auth_tunnel_admission_count",
        "sdk_retry_configuration",
        "prompt_byte_count",
        "output_byte_count",
        "residue_count",
    ):
        with pytest.raises(KimiPlannerTypeError):
            ResultRecord.from_dict(_result_dict(**{field: -1}))
    with pytest.raises(KimiPlannerTypeError):
        AttemptRecord.from_dict(_attempt_dict(planner_attempt_number=-1))
    with pytest.raises(KimiPlannerTypeError):
        validate_bounded_count(-1, name="x", bound=3)


def test_over_bound_values_rejected() -> None:
    with pytest.raises(KimiPlannerTypeError):
        ResultRecord.from_dict(_result_dict(auth_tunnel_admission_count=4))
    with pytest.raises(KimiPlannerTypeError):
        ResultRecord.from_dict(_result_dict(acp_real_prompt_count=2))
    with pytest.raises(KimiPlannerTypeError):
        ResultRecord.from_dict(_result_dict(planner_proposal_count=2))
    with pytest.raises(KimiPlannerTypeError):
        ResultRecord.from_dict(_result_dict(model_allowance_claim_count=2))
    with pytest.raises(KimiPlannerTypeError):
        ResultRecord.from_dict(_result_dict(model_tunnel_admission_count=2))
    with pytest.raises(KimiPlannerTypeError):
        ResultRecord.from_dict(_result_dict(sdk_retry_configuration=1))
    with pytest.raises(KimiPlannerTypeError):
        ResultRecord.from_dict(_result_dict(loop_attempt_limit=2))
    with pytest.raises(KimiPlannerTypeError):
        validate_bounded_count(4, name="auth", bound=3)
    with pytest.raises(KimiPlannerTypeError):
        validate_bounded_count("1", name="auth", bound=3)  # type: ignore[arg-type]


def test_literal_and_enum_field_strictness() -> None:
    with pytest.raises(KimiPlannerTypeError):
        ResultRecord.from_dict(_result_dict(tls_transport_policy="TLS_TERMINATING_MEDIATOR"))
    with pytest.raises(KimiPlannerTypeError):
        ResultRecord.from_dict(_result_dict(local_credential_recognized=1))
    with pytest.raises(KimiPlannerTypeError):
        ResultRecord.from_dict(_result_dict(aosplan_validated="yes"))
    with pytest.raises(KimiPlannerTypeError):
        ResultRecord.from_dict(_result_dict(prompt_sha256="zz"))
    with pytest.raises(KimiPlannerTypeError):
        AttemptRecord.from_dict(_attempt_dict(kimi_executable_sha256="short"))
    # No TLS-version, HTTP-status, or direct server-auth fields exist.
    assert not any(
        "tls_version" in field or "http_status" in field or field == "server_auth_accepted"
        for field in RESULT_FIELD_PROVENANCE
    )


def test_prompt_is_canonical_small_and_exact() -> None:
    expected = {
        "schema": "AOS_KIMI_PLANNER_PROMPT/1",
        "owner_goal": "Propose one documentation task that records a synthetic controller invariant.",
        "research_evidence": [
            "Synthetic qualification input. No repository access is required."
        ],
        "context_manifest": [
            {
                "path": "synthetic/invariant.txt",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "size": 0,
            }
        ],
        "acceptance_criteria": [
            "The proposed task states that the controller, not the model, assigns authoritative task identifiers."
        ],
    }
    assert kimi_planner_prompt() == expected
    canonical = kimi_planner_prompt_canonical_bytes()
    assert canonical == canonical_json_bytes(expected)
    assert len(canonical) < 4096
    # The accessor returns a fresh copy; mutation cannot corrupt the constant.
    mutated = kimi_planner_prompt()
    mutated["owner_goal"] = "tampered"
    assert kimi_planner_prompt() == expected


def test_accounting_bounds_match_design() -> None:
    assert ACCOUNTING_BOUNDS["ACP_REAL_PROMPT_COUNT"].enforced_bound == 1
    assert ACCOUNTING_BOUNDS["MODEL_ALLOWANCE_CLAIM_COUNT"].enforced_bound == 1
    assert ACCOUNTING_BOUNDS["MODEL_TUNNEL_ADMISSION_COUNT"].enforced_bound == 1
    assert ACCOUNTING_BOUNDS["AUTH_TUNNEL_ADMISSION_COUNT"].enforced_bound == 3
    assert ACCOUNTING_BOUNDS["PLANNER_PROPOSAL_COUNT"].enforced_bound == 1
    assert ACCOUNTING_BOUNDS["SDK_RETRY_CONFIGURATION"].enforced_bound == 0
    assert ACCOUNTING_BOUNDS["LOOP_ATTEMPT_COUNT"].enforced_bound == 1
    assert ACCOUNTING_BOUNDS["LOOP_STEP_COUNT"].enforced_bound == 1
    model_http = ACCOUNTING_BOUNDS["MODEL_HTTP_REQUEST_COUNT"]
    assert model_http.enforced_bound is None
    assert model_http.source_only_bound == 42
    assert model_http.composed_target == 21
    auth_http = ACCOUNTING_BOUNDS["AUTH_HTTP_REQUEST_COUNT"]
    assert auth_http.source_only_bound == 126
    assert auth_http.composed_target == 63
    oauth = ACCOUNTING_BOUNDS["OAUTH_TOP_LEVEL_FETCH_CALL_BOUND"]
    assert oauth.source_only_bound == 6
    assert oauth.composed_target == 3
    # Composed targets are conditional, never earned facts.
    for name in ("MODEL_HTTP_REQUEST_COUNT", "AUTH_HTTP_REQUEST_COUNT", "OAUTH_TOP_LEVEL_FETCH_CALL_BOUND"):
        assert (
            ACCOUNTING_BOUNDS[name].composed_target_status
            == "PENDING_SYNTHETIC_PROOF_AND_OWNER_RISK_ACCEPTANCE"
        )
    with pytest.raises(KimiPlannerTypeError):
        AccountingBound("X", True, EvidenceProvenance.DIRECT_CONTROLLER_ENFORCEMENT)


def test_provenance_map_covers_exact_result_fields() -> None:
    assert set(RESULT_FIELD_PROVENANCE) | {"schema"} == set(_result_dict())
    for provenances in RESULT_FIELD_PROVENANCE.values():
        for provenance in provenances:
            assert type(provenance) is EvidenceProvenance


def test_compile_preview_boundary_is_typed_only() -> None:
    request = CompilePreviewRequest(
        proposal_canonical_bytes=b"{}",
        board_snapshot_canonical_bytes=b"{}",
        policy_digest=_HEX64,
    )
    assert request.policy_digest == _HEX64
    with pytest.raises(KimiPlannerTypeError):
        CompilePreviewRequest(
            proposal_canonical_bytes="{}",  # type: ignore[arg-type]
            board_snapshot_canonical_bytes=b"{}",
            policy_digest=_HEX64,
        )
    result = kpt.CompilePreviewResult(accepted=True, preview_canonical_bytes=b"{}")
    assert result.accepted
    with pytest.raises(KimiPlannerTypeError):
        kpt.CompilePreviewResult(accepted=True, failure_code=PlannerFailureCode.TIMEOUT)


def test_module_never_imports_mutating_compiler() -> None:
    source = inspect.getsource(kpt)
    assert "compile_planner_proposal" not in [
        name for name in dir(kpt) if not name.startswith("__")
    ]
    import_lines = [
        line for line in source.splitlines() if line.startswith(("import ", "from "))
    ]
    assert not any("proposals" in line for line in import_lines)
    assert not any("compile_planner_proposal" in line for line in import_lines)


def test_module_has_no_forbidden_capabilities() -> None:
    source = inspect.getsource(kpt)
    import_lines = [
        line for line in source.splitlines() if line.startswith(("import ", "from "))
    ]
    for forbidden in (
        "socket",
        "subprocess",
        "urllib",
        "requests",
        "httpx",
        "random",
        "time",
        "datetime",
        "uuid",
        "kimi_policy",
        "proposals",
    ):
        assert not any(forbidden in line for line in import_lines)
    assert not hasattr(kpt, "os")


def test_result_record_constructor_requires_typed_enums() -> None:
    kwargs = {key: value for key, value in _result_dict().items() if key != "schema"}
    # Raw strings for enum-typed fields must fail closed at construction.
    with pytest.raises(KimiPlannerTypeError):
        ResultRecord(**kwargs)
    kwargs["credential_refresh_state"] = AuthRefreshState.NOT_REQUIRED
    with pytest.raises(KimiPlannerTypeError):
        ResultRecord(**kwargs)
    kwargs["network_terminal_state"] = PlannerEgressState.CLOSED
    record = ResultRecord(**kwargs)
    assert record.to_dict()["network_terminal_state"] == "CLOSED"
    assert record.to_dict()["credential_refresh_state"] == "NOT_REQUIRED"


def test_qualification_state_is_closed_literal_set() -> None:
    for good in ("COMPLETE", "BLOCKED"):
        record = ResultRecord.from_dict(_result_dict(qualification_state=good))
        assert record.qualification_state == good
    for bad in ("QUALIFIED", "TOTALLY_MADE_UP", "", 1, None):
        with pytest.raises(KimiPlannerTypeError):
            ResultRecord.from_dict(_result_dict(qualification_state=bad))


def test_machine_constructor_rejects_unreachable_states() -> None:
    with pytest.raises(KimiPlannerTypeError):
        PlannerEgressMachine(state=PlannerEgressState.AUTH_DRAINING)
    with pytest.raises(KimiPlannerTypeError):
        PlannerEgressMachine(
            state=PlannerEgressState.MODEL_ONCE,
            model_allowance_claimed=True,
        )
    with pytest.raises(KimiPlannerTypeError):
        PlannerEgressMachine(
            state=PlannerEgressState.AUTH_DRAINING,
            auth_admission_revoked=True,
        )
    # A consistent hand-built MODEL_ONCE remains constructible.
    machine = PlannerEgressMachine(
        state=PlannerEgressState.MODEL_ONCE,
        model_allowance_claimed=True,
        model_tunnel_admission_count=1,
        auth_admission_revoked=True,
    )
    assert machine.state is PlannerEgressState.MODEL_ONCE
