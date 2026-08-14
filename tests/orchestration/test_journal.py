from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from agenticos.orchestration.board import BoardSnapshot
from agenticos.orchestration.journal import (
    JournalError,
    TransactionJournal,
)
from tests.orchestration.test_models import project, task


def snapshot(revision: int, *, title: str = "Implement records") -> BoardSnapshot:
    return BoardSnapshot.create(
        replace(project(), board_revision=revision),
        (task(title=title),),
    )


def test_clean_replay_and_restart_recover_exact_committed_state(tmp_path: Path) -> None:
    journal = TransactionJournal(tmp_path, "project-1")
    first = snapshot(0)
    second = snapshot(1, title="Implement durable records")
    initialized = journal.initialize(first, transaction_id="tx-0001")
    committed = journal.commit(initialized.snapshot, second, transaction_id="tx-0002")

    recovered = TransactionJournal(tmp_path, "project-1").recover()
    assert recovered.snapshot == committed.snapshot
    assert recovered.committed_transactions == 2
    assert recovered.dangling_prepares == ()
    assert recovered.snapshot.project.transition_sequence == 2
    assert recovered.snapshot.project.transition_digest != "0" * 64
    assert (tmp_path / "board.json").read_bytes().endswith(b"\n")


def test_crash_after_prepare_never_makes_partial_transaction_authoritative(tmp_path: Path) -> None:
    journal = TransactionJournal(tmp_path, "project-1")
    first = snapshot(0)
    initialized = journal.initialize(first, transaction_id="tx-0001")
    with pytest.raises(JournalError, match="SIMULATED_CRASH_AFTER_PREPARE"):
        journal.commit(initialized.snapshot, snapshot(1), transaction_id="tx-0002", fail_after_prepare=True)

    recovered = TransactionJournal(tmp_path, "project-1").recover()
    assert recovered.snapshot == initialized.snapshot
    assert recovered.committed_transactions == 1
    assert recovered.dangling_prepares == ("tx-0002",)
    with pytest.raises(JournalError, match="UNRESOLVED_DANGLING_PREPARE"):
        journal.commit(initialized.snapshot, snapshot(1), transaction_id="tx-0003")
    completed = journal.complete_prepared("tx-0002")
    assert completed.snapshot.project.board_revision == 1
    assert completed.dangling_prepares == ()


def test_committed_chain_repairs_missing_or_truncated_derived_snapshot(tmp_path: Path) -> None:
    journal = TransactionJournal(tmp_path, "project-1")
    initialized = journal.initialize(snapshot(0), transaction_id="tx-0001")
    derived = tmp_path / "board.json"
    derived.write_bytes(b'{"truncated"')
    recovered = journal.recover()
    assert recovered.snapshot == initialized.snapshot
    assert journal.read_derived_snapshot_for_test() == recovered


def test_crash_after_commit_before_derived_snapshot_recovers_committed_state(tmp_path: Path) -> None:
    journal = TransactionJournal(tmp_path, "project-1")
    first = snapshot(0)
    initialized = journal.initialize(first, transaction_id="tx-0001")
    with pytest.raises(JournalError, match="SIMULATED_CRASH_AFTER_COMMIT"):
        journal.commit(
            initialized.snapshot,
            snapshot(1),
            transaction_id="tx-0002",
            fail_after_commit=True,
        )
    recovered = journal.recover()
    assert recovered.snapshot.project.board_revision == 1
    assert journal.read_derived_snapshot_for_test() == recovered


def test_atomic_temporary_tail_is_ignored_but_named_truncation_fails(tmp_path: Path) -> None:
    journal = TransactionJournal(tmp_path, "project-1")
    initialized = journal.initialize(snapshot(0), transaction_id="tx-0001")
    (tmp_path / ".tmp-interrupted").write_bytes(b'{"truncated"')
    assert journal.recover().snapshot == initialized.snapshot
    prepare = next(tmp_path.glob("*.prepare.json"))
    prepare.write_bytes(prepare.read_bytes()[:20])
    with pytest.raises(JournalError, match="TRUNCATED_OR_NONCANONICAL_RECORD"):
        journal.recover()


@pytest.mark.parametrize("mutation,code", [
    ("payload", "PAYLOAD_DIGEST_MISMATCH"),
    ("chain", "HASH_CHAIN_MISMATCH"),
    ("sequence", "SEQUENCE_FILENAME_MISMATCH"),
])
def test_corruption_hash_mismatch_and_sequence_rollback_fail_closed(
    tmp_path: Path, mutation: str, code: str
) -> None:
    journal = TransactionJournal(tmp_path, "project-1")
    initialized = journal.initialize(snapshot(0), transaction_id="tx-0001")
    journal.commit(initialized.snapshot, snapshot(1), transaction_id="tx-0002")
    target = sorted(tmp_path.glob("*.commit.json"))[-1]
    raw = journal.read_record_for_test(target)
    if mutation == "payload":
        raw["payload_digest"] = "f" * 64
    elif mutation == "chain":
        raw["previous_commit_digest"] = "e" * 64
    else:
        raw["transaction_sequence"] = 1
    journal.write_record_for_test(target, raw)
    with pytest.raises(JournalError, match=code):
        journal.recover()


def test_duplicate_transaction_and_revision_gap_fail_closed(tmp_path: Path) -> None:
    journal = TransactionJournal(tmp_path, "project-1")
    first = snapshot(0)
    initialized = journal.initialize(first, transaction_id="tx-0001")
    with pytest.raises(JournalError, match="DUPLICATE_TRANSACTION"):
        journal.commit(initialized.snapshot, snapshot(1), transaction_id="tx-0001")
    with pytest.raises(JournalError, match="REVISION_NOT_CONTIGUOUS"):
        journal.commit(initialized.snapshot, snapshot(2), transaction_id="tx-0002")


def test_malformed_unknown_fields_and_record_limit_fail_closed(tmp_path: Path) -> None:
    journal = TransactionJournal(tmp_path, "project-1", max_transactions=1)
    first = snapshot(0)
    initialized = journal.initialize(first, transaction_id="tx-0001")
    with pytest.raises(JournalError, match="JOURNAL_TRANSACTION_LIMIT"):
        journal.commit(initialized.snapshot, snapshot(1), transaction_id="tx-0002")
    target = next(tmp_path.glob("*.commit.json"))
    raw = journal.read_record_for_test(target)
    raw["authority"] = "MODEL"
    journal.write_record_for_test(target, raw)
    with pytest.raises(JournalError, match="INVALID_RECORD_FIELDS"):
        journal.recover()
