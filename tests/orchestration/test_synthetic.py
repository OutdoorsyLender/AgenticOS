from __future__ import annotations

import pytest

from agenticos.orchestration.synthetic import (
    SyntheticScenario,
    build_synthetic_fixture,
    run_synthetic_fixture,
)
from tests.orchestration.test_protocol import request


@pytest.mark.parametrize(
    "scenario",
    [
        SyntheticScenario.RESEARCHER_SUCCESS,
        SyntheticScenario.PLANNER_SUCCESS,
        SyntheticScenario.REVIEWER_PASS,
        SyntheticScenario.REVIEWER_FAIL,
        SyntheticScenario.NO_OP,
        SyntheticScenario.RETRYABLE_FAILURE,
        SyntheticScenario.TERMINAL_FAILURE,
    ],
)
def test_success_and_failure_fixtures_are_byte_deterministic(scenario: SyntheticScenario) -> None:
    first = build_synthetic_fixture(request(), scenario)
    second = build_synthetic_fixture(request(), scenario)
    assert first == second
    outcome = run_synthetic_fixture(request(), first)
    assert outcome.accepted
    assert outcome.rejection_code is None
    assert all(not path.startswith(("/", "C:\\")) for path, _ in first.artifacts)


@pytest.mark.parametrize(
    "scenario,code",
    [
        (SyntheticScenario.MALFORMED_EVENT, "MALFORMED_EVENT"),
        (SyntheticScenario.UNKNOWN_EVENT_KIND, "INVALID_ENUM"),
        (SyntheticScenario.OUT_OF_ORDER, "EVENT_SEQUENCE_MISMATCH"),
        (SyntheticScenario.DUPLICATE_TERMINAL, "EVENT_AFTER_TERMINAL"),
        (SyntheticScenario.CONFLICTING_TERMINAL, "EVENT_AFTER_TERMINAL"),
        (SyntheticScenario.OVERSIZED_PAYLOAD, "EVENT_BYTE_LIMIT_EXCEEDED"),
        (SyntheticScenario.WRONG_TASK, "DISPATCH_IDENTITY_MISMATCH"),
        (SyntheticScenario.WRONG_GENERATION, "DISPATCH_IDENTITY_MISMATCH"),
        (SyntheticScenario.WRONG_NONCE, "DISPATCH_IDENTITY_MISMATCH"),
        (SyntheticScenario.STALE_ATTEMPT, "DISPATCH_IDENTITY_MISMATCH"),
        (SyntheticScenario.INCOMPLETE_STREAM, "INCOMPLETE_EVENT_STREAM"),
    ],
)
def test_adversarial_fixtures_become_typed_controller_failures(
    scenario: SyntheticScenario, code: str
) -> None:
    fixture = build_synthetic_fixture(request(), scenario)
    outcome = run_synthetic_fixture(request(), fixture)
    assert not outcome.accepted
    assert outcome.rejection_code == code
    assert outcome.result is None


def test_synthetic_fixtures_are_non_workspace_and_provider_neutral() -> None:
    fixture = build_synthetic_fixture(request(), SyntheticScenario.PLANNER_SUCCESS)
    assert fixture.provider_calls == 0
    assert fixture.process_spawns == 0
    assert fixture.workspace_accesses == 0
    assert fixture.network_accesses == 0
    assert fixture.artifacts
