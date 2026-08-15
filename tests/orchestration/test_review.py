"""Independent read-only reviewer and advisory proposal contracts."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from agenticos.orchestration.canonical import canonical_json_line
from agenticos.orchestration.models import Role, TaskStatus
from agenticos.orchestration.protocol import AgentCapability
from agenticos.orchestration.proposals import REVIEW_SCHEMA, ReviewFinding, ReviewerProposal, ReviewVerdict
from agenticos.orchestration.review import (
    REVIEW_RESULT_SCHEMA,
    ReviewClassification,
    ReviewContext,
    ReviewController,
    ReviewError,
    ReviewResult,
    ReviewerExecutionIdentity,
    SyntheticReviewerAdapter,
    review_failure_fingerprint,
    validate_reviewer_proposal,
)
from agenticos.orchestration.synthetic import SyntheticScenario, build_synthetic_fixture
from agenticos.orchestration.verification import (
    FailureClassification,
    VerificationClassification,
    VerificationExitClassification,
)
from agenticos.sandbox.containment import ContainmentState
from agenticos.sandbox.runtime_boundary import M4AProfile
from tests.orchestration.test_execution import (
    FakeCheckpoint,
    FakeWorkspaceManager,
    _board,
    _capture,
    _dispatch,
    _process_result,
    _receipt,
    _reservation,
)
from tests.orchestration.test_verification import _result as _verification_result


def _review_request():
    return ReviewController.build_request(
        board=_board(status=TaskStatus.REVIEW),
        dispatch=replace(_dispatch(), dispatch_nonce="5" * 32),
        verification_result=_verification_pass(),
        checkpoint=FakeCheckpoint("a" * 64),
    )


def _verification_pass():
    return _verification_result(
        project_id="project-c",
        task_id="build-c",
        task_generation=2,
        attempt=1,
        controller_epoch=4,
        checkpoint_digest="a" * 64,
        classification=VerificationClassification.PASS,
    )


def _builder_identity() -> ReviewerExecutionIdentity:
    return ReviewerExecutionIdentity(
        adapter_instance_id="builder-adapter-1",
        session_id="builder-session-1",
        dispatch_nonce="1" * 32,
        containment_unit="aos-task-builder.scope",
    )


def _review_stream(request, scenario):
    fixture = build_synthetic_fixture(request, scenario)
    assert fixture.result is not None
    return b"".join(fixture.events) + canonical_json_line(fixture.result.to_dict())


class _PreparedReview:
    def __init__(
        self, process, request, scenario=SyntheticScenario.REVIEWER_PASS,
        on_wait=None,
    ) -> None:
        adapter = SyntheticReviewerAdapter(
            "reviewer-adapter-1", "reviewer-session-1", scenario
        )
        self.receipt = replace(
            _receipt(),
            reservation=replace(_reservation(), dispatch_nonce="5" * 32),
            executable=adapter.argv(request)[0],
            argv=tuple(adapter.argv(request)),
        )
        self.process = process
        self.terminal = False
        self.cancelled = False
        self.on_wait = on_wait

    def release(self, receipt, nonce):
        assert receipt == self.receipt
        assert nonce == self.receipt.reservation.release_nonce

    def wait(self, timeout=None, **_kwargs):
        if self.on_wait is not None:
            self.on_wait()
        self.terminal = True
        return self.process

    def cancel(self):
        self.cancelled = True
        self.terminal = True
        return self.process

    def request_cancel(self):
        self.cancelled = True


class _ReviewRunner:
    profile = M4AProfile.INSPECT

    def __init__(self, prepared) -> None:
        self.prepared = prepared
        self.calls = 0

    def prepare(self, argv, **kwargs):
        self.calls += 1
        assert tuple(argv) == self.prepared.receipt.argv
        return self.prepared


def _run_review(scenario: SyntheticScenario):
    request = _review_request()
    raw = _review_stream(request, scenario)
    process = replace(
        _process_result(),
        stdout=raw.decode("utf-8"),
        _stdout_bytes=raw,
        containment_unit=replace(_reservation(), dispatch_nonce="5" * 32).scope_name,
        containment_state=ContainmentState.TERMINATED.value,
    )
    prepared = _PreparedReview(process, request, scenario)
    process = replace(process, containment_cgroup=prepared.receipt.cgroup_path)
    prepared.process = process
    checkpoint = FakeCheckpoint("a" * 64)
    adapter = SyntheticReviewerAdapter(
        "reviewer-adapter-1", "reviewer-session-1", scenario
    )
    result = ReviewController().review(
        board=_board(status=TaskStatus.REVIEW),
        request=request,
        verification_result=_verification_pass(),
        checkpoint=checkpoint,
        builder_identity=_builder_identity(),
        adapter=adapter,
        runner=_ReviewRunner(prepared),
        reservation=replace(_reservation(), dispatch_nonce="5" * 32),
        workspace_manager=FakeWorkspaceManager([_capture(checkpoint), _capture(checkpoint)]),
        repo_path=Path("/repo"),
    )
    return result


def test_review_context_is_bounded_and_digest_bound() -> None:
    context = ReviewContext(
        task_description="Implement the bounded fixture.",
        acceptance_criteria=("Verifier passes.",),
        checkpoint_digest="a" * 64,
        verification_result_digest="b" * 64,
    )
    assert ReviewContext.from_dict(context.to_dict()) == context
    assert len(context.context_digest) == 64
    with pytest.raises(ReviewError):
        replace(context, task_description="x" * 4097)


def test_review_request_is_fully_controller_constructed_and_cannot_expand_authority() -> None:
    request = _review_request()
    assert request == ReviewController.build_request(
        board=_board(status=TaskStatus.REVIEW),
        dispatch=request.identity,
        verification_result=_verification_pass(),
        checkpoint=FakeCheckpoint("a" * 64),
    )
    expanded = replace(
        request,
        capabilities=request.capabilities + (AgentCapability.WRITE_WORKSPACE,),
    )
    runner = _ReviewRunner(_PreparedReview(_process_result(), request))
    with pytest.raises(ReviewError, match="INVALID_REVIEW_CONTEXT"):
        ReviewController().review(
            board=_board(status=TaskStatus.REVIEW), request=expanded,
            verification_result=_verification_pass(),
            checkpoint=FakeCheckpoint("a" * 64),
            builder_identity=_builder_identity(),
            adapter=SyntheticReviewerAdapter(
                "reviewer-adapter-1", "reviewer-session-1",
                SyntheticScenario.REVIEWER_PASS,
            ),
            runner=runner,
            reservation=replace(_reservation(), dispatch_nonce="5" * 32),
            workspace_manager=FakeWorkspaceManager([]),
            repo_path=Path("/repo"),
        )
    assert runner.calls == 0


def test_pass_and_blocking_review_are_typed_and_checkpoint_bound() -> None:
    passed = _run_review(SyntheticScenario.REVIEWER_PASS)
    blocked = _run_review(SyntheticScenario.REVIEWER_FAIL)
    assert passed.classification is ReviewClassification.PASS
    assert passed.failure_classification is None
    assert blocked.classification is ReviewClassification.BLOCKING
    assert blocked.failure_classification is FailureClassification.REVIEW_BLOCKING_FINDING
    assert blocked.failure_fingerprint is not None
    assert passed.reviewer_identity.adapter_instance_id == "reviewer-adapter-1"
    assert passed.reviewer_identity != _builder_identity()


def test_review_failure_fingerprint_normalizes_validated_finding_set() -> None:
    proposal = ReviewerProposal(
        REVIEW_SCHEMA,
        ReviewVerdict.BLOCKING,
        (
            ReviewFinding("B_FINDING", "Second bounded finding."),
            ReviewFinding("A_FINDING", "First bounded finding."),
        ),
        "Apply the bounded repair.",
        (),
    )
    reversed_proposal = replace(proposal, findings=tuple(reversed(proposal.findings)))
    first = review_failure_fingerprint("a" * 64, proposal)
    assert first == review_failure_fingerprint("a" * 64, reversed_proposal)
    assert first != review_failure_fingerprint("b" * 64, proposal)


@pytest.mark.parametrize(
    "field",
    ["task_id", "board_revision", "command", "provider_id", "mark_done"],
)
def test_reviewer_authority_claims_and_unknown_fields_are_rejected(field: str) -> None:
    raw = ReviewerProposal(REVIEW_SCHEMA, ReviewVerdict.PASS, (), None, ()).to_dict()
    raw[field] = "model-claim"
    with pytest.raises(ReviewError, match="MALFORMED_AGENT_OUTPUT"):
        validate_reviewer_proposal(raw)


@pytest.mark.parametrize(
    "identity_change",
    [
        {"adapter_instance_id": "reviewer-adapter-1"},
        {"session_id": "reviewer-session-1"},
        {"dispatch_nonce": "5" * 32},
        {"containment_unit": "aos-task-project-c-build-c-2-1-1.scope"},
    ],
)
def test_reviewer_cannot_reuse_builder_execution_identity(identity_change) -> None:
    request = _review_request()
    raw = _review_stream(request, SyntheticScenario.REVIEWER_PASS)
    process = replace(_process_result(), stdout=raw.decode(), _stdout_bytes=raw)
    prepared = _PreparedReview(process, request)
    runner = _ReviewRunner(prepared)
    checkpoint = FakeCheckpoint("a" * 64)
    builder = replace(_builder_identity(), **identity_change)
    with pytest.raises(ReviewError, match="REVIEWER_INDEPENDENCE_VIOLATION"):
        ReviewController().review(
            board=_board(status=TaskStatus.REVIEW), request=request,
            verification_result=_verification_pass(), checkpoint=checkpoint,
            builder_identity=builder,
            adapter=SyntheticReviewerAdapter(
                "reviewer-adapter-1", "reviewer-session-1", SyntheticScenario.REVIEWER_PASS
            ),
            runner=runner,
            reservation=replace(_reservation(), dispatch_nonce="5" * 32),
            workspace_manager=FakeWorkspaceManager([]), repo_path=Path("/repo"),
        )
    assert runner.calls == 0


def test_review_pass_cannot_override_failed_verification_or_changed_checkpoint() -> None:
    request = _review_request()
    checkpoint = FakeCheckpoint("a" * 64)
    adapter = SyntheticReviewerAdapter(
        "reviewer-adapter-1", "reviewer-session-1", SyntheticScenario.REVIEWER_PASS
    )
    runner = _ReviewRunner(_PreparedReview(_process_result(), request))
    for verification, changed, code in (
        (
            replace(
                _verification_pass(),
                classification=VerificationClassification.INFRASTRUCTURE_ERROR,
                failure_classification=FailureClassification.TIMEOUT,
                exit_code=None,
                exit_classification=VerificationExitClassification.TIMEOUT,
                timed_out=True,
                process_evidence=None,
            ),
            checkpoint,
            "VERIFICATION_NOT_PASS",
        ),
        (_verification_pass(), FakeCheckpoint("f" * 64), "CHECKPOINT_MISMATCH"),
    ):
        with pytest.raises((ReviewError, ValueError), match=code):
            ReviewController().review(
                board=_board(status=TaskStatus.REVIEW), request=request,
                verification_result=verification, checkpoint=changed,
                builder_identity=_builder_identity(), adapter=adapter, runner=runner,
                reservation=replace(_reservation(), dispatch_nonce="5" * 32),
                workspace_manager=FakeWorkspaceManager([]), repo_path=Path("/repo"),
            )


def test_review_result_is_strict_and_round_trips() -> None:
    result = _run_review(SyntheticScenario.REVIEWER_PASS)
    assert result.schema == REVIEW_RESULT_SCHEMA
    assert ReviewResult.from_dict(result.to_dict()) == result
    assert len(result.result_digest) == 64


@pytest.mark.parametrize("mode", ["malformed", "duplicate_terminal", "duplicate_result"])
def test_malformed_or_duplicate_reviewer_output_is_infrastructure_only(mode: str) -> None:
    request = _review_request()
    raw = _review_stream(request, SyntheticScenario.REVIEWER_PASS)
    lines = raw.splitlines(keepends=True)
    if mode == "malformed":
        raw = b'{"schema":\n'
    elif mode == "duplicate_terminal":
        raw = b"".join(lines[:-1] + [lines[-2], lines[-1]])
    else:
        raw = raw + lines[-1]
    process = replace(
        _process_result(), stdout=raw.decode("utf-8"), _stdout_bytes=raw,
        containment_state=ContainmentState.TERMINATED.value,
    )
    prepared = _PreparedReview(process, request)
    prepared.process = replace(
        process, containment_unit=prepared.receipt.reservation.scope_name,
        containment_cgroup=prepared.receipt.cgroup_path,
    )
    checkpoint = FakeCheckpoint("a" * 64)
    result = ReviewController().review(
        board=_board(status=TaskStatus.REVIEW), request=request,
        verification_result=_verification_pass(), checkpoint=checkpoint,
        builder_identity=_builder_identity(),
        adapter=SyntheticReviewerAdapter(
            "reviewer-adapter-1", "reviewer-session-1",
            SyntheticScenario.REVIEWER_PASS,
        ),
        runner=_ReviewRunner(prepared),
        reservation=replace(_reservation(), dispatch_nonce="5" * 32),
        workspace_manager=FakeWorkspaceManager(
            [_capture(checkpoint), _capture(checkpoint)]
        ),
        repo_path=Path("/repo"),
    )
    assert result.classification is ReviewClassification.INFRASTRUCTURE_ERROR
    assert result.failure_classification is FailureClassification.MALFORMED_AGENT_OUTPUT


def test_reviewer_output_limit_and_workspace_mutation_fail_closed() -> None:
    request = _review_request()
    raw = _review_stream(request, SyntheticScenario.REVIEWER_PASS)
    checkpoint = FakeCheckpoint("a" * 64)
    for process, captures, expected in (
        (
            replace(
                _process_result(), stdout=raw.decode(), _stdout_bytes=raw,
                output_limit_exceeded=True,
                containment_state=ContainmentState.TERMINATED.value,
            ),
            [_capture(checkpoint), _capture(checkpoint)],
            FailureClassification.TERMINAL_INFRASTRUCTURE_FAILURE,
        ),
        (
            replace(
                _process_result(), stdout=raw.decode(), _stdout_bytes=raw,
                containment_state=ContainmentState.TERMINATED.value,
            ),
            [_capture(FakeCheckpoint("f" * 64)), _capture(FakeCheckpoint("f" * 64))],
            FailureClassification.WORKSPACE_MUTATION_DURING_READONLY_STAGE,
        ),
    ):
        prepared = _PreparedReview(process, request)
        prepared.process = replace(
            process, containment_unit=prepared.receipt.reservation.scope_name,
            containment_cgroup=prepared.receipt.cgroup_path,
        )
        result = ReviewController().review(
            board=_board(status=TaskStatus.REVIEW), request=request,
            verification_result=_verification_pass(), checkpoint=checkpoint,
            builder_identity=_builder_identity(),
            adapter=SyntheticReviewerAdapter(
                "reviewer-adapter-1", "reviewer-session-1",
                SyntheticScenario.REVIEWER_PASS,
            ),
            runner=_ReviewRunner(prepared),
            reservation=replace(_reservation(), dispatch_nonce="5" * 32),
            workspace_manager=FakeWorkspaceManager(captures),
            repo_path=Path("/repo"),
        )
        assert result.classification is ReviewClassification.INFRASTRUCTURE_ERROR
        assert result.failure_classification is expected


def test_terminal_reviewer_result_cannot_smuggle_a_pass_proposal() -> None:
    request = _review_request()
    lines = _review_stream(request, SyntheticScenario.REVIEWER_PASS).splitlines(
        keepends=True
    )
    events = [json.loads(line) for line in lines[:-1]]
    events[-1]["kind"] = "TERMINAL_FAILURE"
    event_lines = [canonical_json_line(event) for event in events]
    result_raw = json.loads(lines[-1])
    result_raw["status"] = "TERMINAL_FAILURE"
    result_raw["exit_class"] = "TERMINAL"
    stream = b"".join(event_lines)
    result_raw["byte_count"] = len(stream)
    result_raw["stream_digest"] = hashlib.sha256(stream).hexdigest()
    raw = stream + canonical_json_line(result_raw)
    process = replace(
        _process_result(), stdout=raw.decode(), _stdout_bytes=raw,
        containment_state=ContainmentState.TERMINATED.value,
    )
    prepared = _PreparedReview(process, request)
    prepared.process = replace(
        process, containment_unit=prepared.receipt.reservation.scope_name,
        containment_cgroup=prepared.receipt.cgroup_path,
    )
    checkpoint = FakeCheckpoint("a" * 64)
    result = ReviewController().review(
        board=_board(status=TaskStatus.REVIEW), request=request,
        verification_result=_verification_pass(), checkpoint=checkpoint,
        builder_identity=_builder_identity(),
        adapter=SyntheticReviewerAdapter(
            "reviewer-adapter-1", "reviewer-session-1",
            SyntheticScenario.REVIEWER_PASS,
        ),
        runner=_ReviewRunner(prepared),
        reservation=replace(_reservation(), dispatch_nonce="5" * 32),
        workspace_manager=FakeWorkspaceManager(
            [_capture(checkpoint), _capture(checkpoint)]
        ),
        repo_path=Path("/repo"),
    )
    assert result.classification is ReviewClassification.INFRASTRUCTURE_ERROR
    assert result.failure_classification is FailureClassification.TERMINAL_INFRASTRUCTURE_FAILURE


def test_reviewer_cancellation_wins_over_late_structural_pass() -> None:
    request = _review_request()
    raw = _review_stream(request, SyntheticScenario.REVIEWER_PASS)
    process = replace(
        _process_result(), stdout=raw.decode(), _stdout_bytes=raw,
        containment_state=ContainmentState.TERMINATED.value,
    )
    controller = ReviewController()
    prepared = _PreparedReview(process, request, on_wait=controller.request_cancel)
    prepared.process = replace(
        process, containment_unit=prepared.receipt.reservation.scope_name,
        containment_cgroup=prepared.receipt.cgroup_path,
    )
    checkpoint = FakeCheckpoint("a" * 64)
    result = controller.review(
        board=_board(status=TaskStatus.REVIEW), request=request,
        verification_result=_verification_pass(), checkpoint=checkpoint,
        builder_identity=_builder_identity(),
        adapter=SyntheticReviewerAdapter(
            "reviewer-adapter-1", "reviewer-session-1",
            SyntheticScenario.REVIEWER_PASS,
        ),
        runner=_ReviewRunner(prepared),
        reservation=replace(_reservation(), dispatch_nonce="5" * 32),
        workspace_manager=FakeWorkspaceManager(
            [_capture(checkpoint), _capture(checkpoint)]
        ),
        repo_path=Path("/repo"),
    )
    assert result.classification is ReviewClassification.INFRASTRUCTURE_ERROR
    assert result.failure_classification is FailureClassification.CANCELLED
    assert prepared.cancelled is True
