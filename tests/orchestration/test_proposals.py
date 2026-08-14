from __future__ import annotations

import pytest

from agenticos.orchestration.board import BoardAuthority, BoardSnapshot
from agenticos.orchestration.journal import TransactionJournal
from agenticos.orchestration.models import Role, TaskStatus, TaskType
from agenticos.orchestration.proposals import (
    PLANNER_SCHEMA,
    REVIEW_SCHEMA,
    PlannerProposal,
    ProposalCompilationError,
    ProposedTask,
    ReviewFinding,
    ReviewerProposal,
    ReviewVerdict,
    compile_planner_proposal,
)
from agenticos.orchestration.protocol import EvidenceRef
from tests.orchestration.test_models import project


def proposed(local_id: str, dependencies: tuple[str, ...] = ()) -> ProposedTask:
    return ProposedTask(
        local_id=local_id,
        title=f"Task {local_id}",
        description="Bounded proposed work.",
        task_type=TaskType.BUILD,
        dependencies=dependencies,
        acceptance_criteria=("Controller verification passes.",),
        preferred_role=Role.BUILDER,
        priority=50,
    )


def proposal(*tasks: ProposedTask) -> PlannerProposal:
    return PlannerProposal(schema=PLANNER_SCHEMA, tasks=tasks)


def test_valid_multi_task_dag_compiles_atomically_with_controller_ids(tmp_path) -> None:
    authority = BoardAuthority.create(TransactionJournal(tmp_path, "project-1"), BoardSnapshot.create(project(), ()), transaction_id="tx-init")
    result = compile_planner_proposal(
        authority,
        expected_revision=0,
        proposal=proposal(proposed("local-a"), proposed("local-b", ("local-a",))),
        transaction_id="tx-plan",
    )
    assert result.accepted
    assert [item.task_id for item in authority.snapshot.tasks] == ["task-000001", "task-000002"]
    assert authority.snapshot.task("task-000002").dependencies == ("task-000001",)
    assert all(item.status is TaskStatus.BACKLOG for item in authority.snapshot.tasks)
    assert authority.snapshot.revision == 1
    assert all(item.acceptance_criteria == ("Controller-registered verification policy must pass.",) for item in authority.snapshot.tasks)


@pytest.mark.parametrize(
    "bad,code",
    [
        (proposal(proposed("x"), proposed("x")), "DUPLICATE_PROPOSAL_ID"),
        (proposal(proposed("x", ("missing",))), "MISSING_PROPOSAL_DEPENDENCY"),
        (proposal(proposed("x", ("x",))), "SELF_PROPOSAL_DEPENDENCY"),
        (proposal(proposed("x", ("y",)), proposed("y", ("x",))), "PROPOSAL_DEPENDENCY_CYCLE"),
    ],
)
def test_invalid_whole_dag_is_rejected_without_partial_application(tmp_path, bad, code: str) -> None:
    authority = BoardAuthority.create(TransactionJournal(tmp_path, "project-1"), BoardSnapshot.create(project(), ()), transaction_id="tx-init")
    with pytest.raises(ProposalCompilationError, match=code):
        compile_planner_proposal(authority, expected_revision=0, proposal=bad, transaction_id="tx-plan")
    assert authority.snapshot.tasks == ()
    assert authority.snapshot.revision == 0


def test_controller_policy_rejects_bootstrap_types_and_role_mismatch(tmp_path) -> None:
    authority = BoardAuthority.create(TransactionJournal(tmp_path, "project-1"), BoardSnapshot.create(project(), ()), transaction_id="tx-init")
    bootstrap = proposed("research")
    bootstrap = ProposedTask(
        bootstrap.local_id, bootstrap.title, bootstrap.description, TaskType.RESEARCH,
        bootstrap.dependencies, bootstrap.acceptance_criteria, Role.RESEARCHER, bootstrap.priority,
    )
    with pytest.raises(ProposalCompilationError, match="TASK_TYPE_NOT_ALLOWED"):
        compile_planner_proposal(authority, expected_revision=0, proposal=proposal(bootstrap), transaction_id="tx-bootstrap")
    mismatch = ProposedTask(
        "build", "Build", "Bounded build.", TaskType.BUILD, (), ("Model says pass.",), Role.REVIEWER, 50,
    )
    with pytest.raises(ProposalCompilationError, match="ROLE_POLICY_MISMATCH"):
        compile_planner_proposal(authority, expected_revision=0, proposal=proposal(mismatch), transaction_id="tx-role")


def test_over_limit_plan_is_rejected_before_compilation() -> None:
    with pytest.raises(ProposalCompilationError, match="PROPOSAL_TASK_LIMIT"):
        proposal(*(proposed(f"t-{i}") for i in range(129)))


def test_proposal_parser_rejects_unknown_fields_and_invalid_enum() -> None:
    raw = proposal(proposed("x")).to_dict()
    raw["tasks"][0]["status"] = "DONE"  # type: ignore[index]
    with pytest.raises(ProposalCompilationError, match="UNKNOWN_FIELDS"):
        PlannerProposal.from_dict(raw)
    raw = proposal(proposed("x")).to_dict()
    raw["tasks"][0]["preferred_role"] = "OWNER"  # type: ignore[index]
    with pytest.raises(ProposalCompilationError, match="INVALID_ENUM"):
        PlannerProposal.from_dict(raw)


def test_reviewer_pass_and_bounded_blocking_finding_are_advisory_only() -> None:
    passed = ReviewerProposal(
        schema=REVIEW_SCHEMA,
        verdict=ReviewVerdict.PASS,
        findings=(),
        repair_recommendation=None,
        evidence_refs=(),
    )
    blocked = ReviewerProposal(
        schema=REVIEW_SCHEMA,
        verdict=ReviewVerdict.BLOCKING,
        findings=(ReviewFinding("REVIEW_TEST_FAILURE", "A deterministic test failed."),),
        repair_recommendation="Repair only the failing behavior.",
        evidence_refs=(EvidenceRef("review", "review-1", "a" * 64, 12),),
    )
    assert ReviewerProposal.from_dict(passed.to_dict()) == passed
    assert ReviewerProposal.from_dict(blocked.to_dict()) == blocked
    assert not hasattr(blocked, "apply")
    assert not ({"board_revision", "project_status", "task_status"} & set(blocked.to_dict()))


def test_reviewer_cannot_smuggle_authoritative_state_or_unbounded_findings() -> None:
    raw = ReviewerProposal(
        schema=REVIEW_SCHEMA,
        verdict=ReviewVerdict.PASS,
        findings=(),
        repair_recommendation=None,
        evidence_refs=(),
    ).to_dict()
    raw["task_status"] = "DONE"
    with pytest.raises(ProposalCompilationError, match="UNKNOWN_FIELDS"):
        ReviewerProposal.from_dict(raw)
    with pytest.raises(ProposalCompilationError, match="REVIEW_FINDING_LIMIT"):
        ReviewerProposal(
            schema=REVIEW_SCHEMA,
            verdict=ReviewVerdict.BLOCKING,
            findings=tuple(ReviewFinding(f"FINDING_{i}", "bounded") for i in range(33)),
            repair_recommendation=None,
            evidence_refs=(),
        )
