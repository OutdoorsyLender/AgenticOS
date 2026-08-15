"""Atomic idempotent repair creation and root-lineage budget contracts."""

from __future__ import annotations

from dataclasses import replace

import pytest

from agenticos.orchestration.board import BoardAuthority, BoardSnapshot
from agenticos.orchestration.journal import TransactionJournal
from agenticos.orchestration.models import RunLimits, TaskStatus, TerminalReason
from agenticos.orchestration.repair import (
    RepairBudgetPolicy,
    RepairController,
    RepairError,
)
from agenticos.orchestration.review import ReviewClassification
from agenticos.orchestration.synthetic import SyntheticScenario
from agenticos.orchestration.verification import (
    FailureClassification,
    VerificationClassification,
    verification_failure_fingerprint,
)
from tests.orchestration.test_execution import _board
from tests.orchestration.test_review import _run_review
from tests.orchestration.test_verification import _result as _verification_result


def _authority(
    tmp_path, *, status=TaskStatus.VERIFYING, dependent=False, limits=None
):
    journal = TransactionJournal(tmp_path, "project-c")
    source = _board(status=status)
    if limits is not None:
        source = BoardSnapshot.create(replace(source.project, limits=limits), source.tasks)
    if status is TaskStatus.REVIEW:
        verification = _verification_result(
            project_id="project-c", task_id="build-c", task_generation=2,
            attempt=1, controller_epoch=4, checkpoint_digest="a" * 64,
            classification=VerificationClassification.PASS,
        )
        source = BoardSnapshot.create(
            source.project,
            (replace(source.tasks[0], verification_result_digest=verification.result_digest),),
        )
    tasks = source.tasks
    if dependent:
        tasks += (replace(
            source.tasks[0],
            task_id="dependent-c",
            title="Dependent task",
            dependencies=("build-c",),
            status=TaskStatus.BACKLOG,
            attempt_count=0,
            creation_sequence=2,
            parent_task_id=None,
            root_task_id="dependent-c",
            generation=1,
            repair_failure_fingerprint=None,
            satisfying_descendant_id=None,
            verification_result_digest=None,
            review_result_digest=None,
        ),)
    initial = BoardSnapshot.create(
        replace(
            source.project,
            board_revision=0,
            transition_sequence=0,
            transition_digest="0" * 64,
        ),
        tasks,
    )
    authority = BoardAuthority.create(
        journal, initial, transaction_id="tx-init"
    )
    return authority, journal


def _verification_failure():
    fingerprint = verification_failure_fingerprint(
        verifier_id="demo-fixture-v1",
        verifier_spec_digest=_verification_result().verifier_spec_digest,
        checkpoint_digest="a" * 64,
        exit_code=1,
        stdout_sha256="d" * 64,
        stderr_sha256="e" * 64,
    )
    base = _verification_result(
        project_id="project-c",
        task_id="build-c",
        task_generation=2,
        attempt=1,
        controller_epoch=4,
        checkpoint_digest="a" * 64,
        classification=VerificationClassification.FAIL,
        failure_classification=FailureClassification.VERIFICATION_FAILURE,
        exit_code=1,
        failure_fingerprint=fingerprint,
    )
    return base


def _verification_failure_for_task(
    task, *, controller_epoch=4, checkpoint_digest="b" * 64,
    stdout_sha256="d" * 64, stderr_sha256="e" * 64,
):
    spec_digest = _verification_result().verifier_spec_digest
    fingerprint = verification_failure_fingerprint(
        verifier_id="demo-fixture-v1",
        verifier_spec_digest=spec_digest,
        checkpoint_digest=checkpoint_digest,
        exit_code=1,
        stdout_sha256=stdout_sha256,
        stderr_sha256=stderr_sha256,
    )
    return _verification_result(
        project_id=task.project_id,
        task_id=task.task_id,
        task_generation=task.generation,
        attempt=task.attempt_count,
        controller_epoch=controller_epoch,
        checkpoint_digest=checkpoint_digest,
        classification=VerificationClassification.FAIL,
        failure_classification=FailureClassification.VERIFICATION_FAILURE,
        exit_code=1,
        stdout_sha256=stdout_sha256,
        stderr_sha256=stderr_sha256,
        failure_fingerprint=fingerprint,
    )


def _first_repair_in_verifying(authority):
    first = RepairController().create_for_verification_failure(
        authority=authority, parent_task_id="build-c", result=_verification_failure(),
        policy=RepairBudgetPolicy(), now_unix_ms=2, transaction_id="tx-first-repair",
    )
    assert first.repair_task_id is not None
    authority.transition_task(
        authority.snapshot.revision, first.repair_task_id, TaskStatus.IN_PROGRESS,
        transaction_id="tx-first-start",
    )
    authority.transition_task(
        authority.snapshot.revision, first.repair_task_id, TaskStatus.VERIFYING,
        transaction_id="tx-first-verify",
    )
    return first.repair_task_id


def test_verification_failure_creates_one_atomic_controller_owned_repair(tmp_path) -> None:
    authority, journal = _authority(tmp_path)
    failure = _verification_failure()
    outcome = RepairController().create_for_verification_failure(
        authority=authority,
        parent_task_id="build-c",
        result=failure,
        policy=RepairBudgetPolicy(),
        now_unix_ms=2,
        transaction_id="tx-repair",
    )

    assert outcome.created is True
    assert outcome.repair_task_id is not None
    parent = authority.snapshot.task("build-c")
    child = authority.snapshot.task(outcome.repair_task_id)
    assert parent.status is TaskStatus.WAITING_REPAIR
    assert parent.verification_result_digest == failure.result_digest
    assert child.parent_task_id == parent.task_id
    assert child.root_task_id == parent.root_task_id
    assert child.repair_failure_fingerprint == failure.failure_fingerprint
    assert child.dependencies == parent.dependencies
    assert child.status is TaskStatus.READY
    assert child.task_id.startswith("repair-")
    assert journal.recover().snapshot == authority.snapshot


def test_review_failure_creates_one_distinct_repair_and_keeps_verification_evidence(tmp_path) -> None:
    authority, _journal = _authority(tmp_path, status=TaskStatus.REVIEW)
    review = _run_review(SyntheticScenario.REVIEWER_FAIL)
    assert review.classification is ReviewClassification.BLOCKING

    outcome = RepairController().create_for_review_failure(
        authority=authority,
        parent_task_id="build-c",
        result=review,
        policy=RepairBudgetPolicy(),
        now_unix_ms=2,
        transaction_id="tx-review-repair",
    )

    parent = authority.snapshot.task("build-c")
    assert outcome.created is True
    assert parent.status is TaskStatus.WAITING_REPAIR
    assert parent.review_result_digest == review.result_digest
    assert parent.verification_result_digest == review.verification_result_digest


def test_replay_and_restart_return_same_authoritative_child_without_new_transaction(tmp_path) -> None:
    authority, journal = _authority(tmp_path)
    failure = _verification_failure()
    controller = RepairController()
    first = controller.create_for_verification_failure(
        authority=authority, parent_task_id="build-c", result=failure,
        policy=RepairBudgetPolicy(), now_unix_ms=2, transaction_id="tx-repair",
    )
    revision = authority.snapshot.revision
    replay = controller.create_for_verification_failure(
        authority=authority, parent_task_id="build-c", result=failure,
        policy=RepairBudgetPolicy(), now_unix_ms=3, transaction_id="tx-replay",
    )
    recovered = BoardAuthority.recover(journal)
    restarted = controller.create_for_verification_failure(
        authority=recovered, parent_task_id="build-c", result=failure,
        policy=RepairBudgetPolicy(), now_unix_ms=4, transaction_id="tx-restart",
    )

    assert first.repair_task_id == replay.repair_task_id == restarted.repair_task_id
    assert replay.created is restarted.created is False
    assert authority.snapshot.revision == recovered.snapshot.revision == revision
    assert len(authority.snapshot.tasks) == 2


def test_infrastructure_or_malformed_failure_never_creates_code_repair(tmp_path) -> None:
    authority, _journal = _authority(tmp_path)
    infrastructure = _verification_result(
        project_id="project-c", task_id="build-c", task_generation=2,
        attempt=1, controller_epoch=4, checkpoint_digest="a" * 64,
        classification=VerificationClassification.INFRASTRUCTURE_ERROR,
        failure_classification=FailureClassification.CONTAINMENT_FAILURE,
        exit_code=None, process_evidence=None,
    )
    before = authority.snapshot
    with pytest.raises(RepairError, match="INELIGIBLE_REPAIR_FAILURE"):
        RepairController().create_for_verification_failure(
            authority=authority, parent_task_id="build-c", result=infrastructure,
            policy=RepairBudgetPolicy(), now_unix_ms=2, transaction_id="tx-no-repair",
        )
    assert authority.snapshot == before


@pytest.mark.parametrize(
    "policy",
    [
        RepairBudgetPolicy(max_repair_tasks=0),
        RepairBudgetPolicy(max_distinct_fingerprints=0),
        RepairBudgetPolicy(max_consecutive_failures=0),
    ],
)
def test_budget_exhaustion_terminalizes_deterministically_without_owner_block(
    tmp_path, policy
) -> None:
    authority, _journal = _authority(tmp_path)
    outcome = RepairController().create_for_verification_failure(
        authority=authority, parent_task_id="build-c", result=_verification_failure(),
        policy=policy, now_unix_ms=2, transaction_id="tx-budget",
    )
    parent = authority.snapshot.task("build-c")
    assert outcome.created is False
    assert outcome.failure_classification is FailureClassification.REPAIR_BUDGET_EXHAUSTED
    assert parent.status is TaskStatus.FAILED
    assert parent.terminal_reason is TerminalReason.RESOURCE_LIMIT


def test_deadline_and_root_total_attempt_budget_do_not_reset_for_child(tmp_path) -> None:
    authority, _journal = _authority(tmp_path)
    expired = RepairController().create_for_verification_failure(
        authority=authority, parent_task_id="build-c", result=_verification_failure(),
        policy=RepairBudgetPolicy(), now_unix_ms=100_000,
        transaction_id="tx-deadline",
    )
    assert expired.failure_classification is FailureClassification.REPAIR_BUDGET_EXHAUSTED
    assert expired.budget_usage.total_attempts == 1
    assert authority.snapshot.project.status.value == "ACTIVE"


def test_successful_repair_recursively_satisfies_parent_without_erasing_history(
    tmp_path,
) -> None:
    authority, journal = _authority(tmp_path, dependent=True)
    failure = _verification_failure()
    created = RepairController().create_for_verification_failure(
        authority=authority, parent_task_id="build-c", result=failure,
        policy=RepairBudgetPolicy(), now_unix_ms=2, transaction_id="tx-repair",
    )
    assert created.repair_task_id is not None
    child_id = created.repair_task_id
    assert authority.snapshot.task("dependent-c").status is TaskStatus.BACKLOG

    authority.transition_task(
        authority.snapshot.revision, child_id, TaskStatus.IN_PROGRESS,
        transaction_id="tx-start-repair",
    )
    authority.transition_task(
        authority.snapshot.revision, child_id, TaskStatus.VERIFYING,
        transaction_id="tx-verify-repair",
    )
    child = authority.snapshot.task(child_id)
    verification = _verification_result(
        project_id=child.project_id,
        task_id=child.task_id,
        task_generation=child.generation,
        attempt=child.attempt_count,
        controller_epoch=authority.snapshot.project.controller_epoch,
        checkpoint_digest="b" * 64,
        classification=VerificationClassification.PASS,
    )
    controller = RepairController()
    assert controller.record_verification_pass(
        authority=authority, task_id=child_id, result=verification,
        transaction_id="tx-verification-pass",
    ) is True
    assert controller.record_verification_pass(
        authority=authority, task_id=child_id, result=verification,
        transaction_id="tx-verification-replay",
    ) is False

    review = replace(
        _run_review(SyntheticScenario.REVIEWER_PASS),
        task_id=child.task_id,
        task_generation=child.generation,
        attempt=child.attempt_count,
        checkpoint_digest=verification.checkpoint_digest,
        verification_result_digest=verification.result_digest,
    )
    satisfied = controller.satisfy_lineage(
        authority=authority, task_id=child_id, result=review,
        transaction_id="tx-satisfy",
    )
    assert satisfied.applied is True
    assert controller.satisfy_lineage(
        authority=authority, task_id=child_id, result=review,
        transaction_id="tx-satisfy-replay",
    ).applied is False

    child = authority.snapshot.task(child_id)
    parent = authority.snapshot.task("build-c")
    assert child.status is parent.status is TaskStatus.DONE
    assert parent.satisfying_descendant_id == child_id
    assert parent.verification_result_digest == failure.result_digest
    assert child.verification_result_digest == verification.result_digest
    assert child.review_result_digest == review.result_digest
    assert authority.snapshot.task("dependent-c").status is TaskStatus.BACKLOG
    authority.derive_ready(
        authority.snapshot.revision, transaction_id="tx-dependent-ready"
    )
    assert authority.snapshot.task("dependent-c").status is TaskStatus.READY
    assert journal.recover().snapshot == authority.snapshot


def test_repair_of_repair_is_allowed_with_separate_lineage_not_dependency_edge(
    tmp_path,
) -> None:
    authority, _journal = _authority(tmp_path)
    first_id = _first_repair_in_verifying(authority)
    first = authority.snapshot.task(first_id)
    second = RepairController().create_for_verification_failure(
        authority=authority,
        parent_task_id=first_id,
        result=_verification_failure_for_task(first, stderr_sha256="f" * 64),
        policy=RepairBudgetPolicy(),
        now_unix_ms=3,
        transaction_id="tx-second-repair",
    )
    assert second.created is True
    assert second.repair_task_id is not None
    grandchild = authority.snapshot.task(second.repair_task_id)
    assert grandchild.parent_task_id == first_id
    assert grandchild.root_task_id == "build-c"
    assert grandchild.dependencies == authority.snapshot.task("build-c").dependencies
    assert first_id not in grandchild.dependencies
    assert authority.snapshot.task("build-c").status is TaskStatus.WAITING_REPAIR
    assert authority.snapshot.task(first_id).status is TaskStatus.WAITING_REPAIR


@pytest.mark.parametrize(
    ("limits", "policy", "distinct"),
    [
        (RunLimits(max_total_attempts=1), RepairBudgetPolicy(), False),
        (RunLimits(max_tasks=1), RepairBudgetPolicy(), False),
        (RunLimits(max_repair_depth=1), RepairBudgetPolicy(), True),
        (RunLimits(), RepairBudgetPolicy(max_repair_tasks=1), True),
        (RunLimits(), RepairBudgetPolicy(max_distinct_fingerprints=1), True),
        (RunLimits(), RepairBudgetPolicy(max_consecutive_failures=1), True),
    ],
)
def test_root_lineage_limits_do_not_reset_on_child_creation(
    tmp_path, limits, policy, distinct
) -> None:
    authority, _journal = _authority(tmp_path, limits=limits)
    if limits.max_total_attempts == 1 or limits.max_tasks == 1:
        outcome = RepairController().create_for_verification_failure(
            authority=authority, parent_task_id="build-c",
            result=_verification_failure(), policy=policy, now_unix_ms=2,
            transaction_id="tx-root-limit",
        )
        assert outcome.failure_classification is FailureClassification.REPAIR_BUDGET_EXHAUSTED
        assert len(authority.snapshot.tasks) == 1
        return
    first_id = _first_repair_in_verifying(authority)
    first = authority.snapshot.task(first_id)
    outcome = RepairController().create_for_verification_failure(
        authority=authority,
        parent_task_id=first_id,
        result=_verification_failure_for_task(
            first, stderr_sha256=("f" if distinct else "e") * 64
        ),
        policy=policy,
        now_unix_ms=3,
        transaction_id="tx-lineage-limit",
    )
    assert outcome.failure_classification is FailureClassification.REPAIR_BUDGET_EXHAUSTED
    assert authority.snapshot.task(first_id).status is TaskStatus.FAILED
    assert authority.snapshot.task("build-c").status is TaskStatus.FAILED
    assert len(authority.snapshot.tasks) == 2


def test_repeated_identical_fingerprint_and_stale_result_never_branch_lineage(
    tmp_path,
) -> None:
    authority, _journal = _authority(tmp_path)
    first_id = _first_repair_in_verifying(authority)
    first = authority.snapshot.task(first_id)
    repeated = replace(
        _verification_failure(),
        task_id=first.task_id,
        task_generation=first.generation,
        attempt=first.attempt_count,
    )
    exhausted = RepairController().create_for_verification_failure(
        authority=authority, parent_task_id=first_id, result=repeated,
        policy=RepairBudgetPolicy(), now_unix_ms=3,
        transaction_id="tx-repeat-fingerprint",
    )
    assert exhausted.failure_classification is FailureClassification.REPAIR_BUDGET_EXHAUSTED
    assert authority.snapshot.task("build-c").status is TaskStatus.FAILED
    assert len(authority.snapshot.tasks) == 2

    other_authority, _other_journal = _authority(tmp_path / "stale")
    stale_child = _first_repair_in_verifying(other_authority)
    with pytest.raises(RepairError, match="STALE_IDENTITY"):
        RepairController().create_for_verification_failure(
            authority=other_authority,
            parent_task_id=stale_child,
            result=_verification_failure(),
            policy=RepairBudgetPolicy(),
            now_unix_ms=3,
            transaction_id="tx-stale-result",
        )
    assert len(other_authority.snapshot.tasks) == 2
