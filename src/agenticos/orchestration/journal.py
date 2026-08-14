"""Crash-consistent bounded single-project transaction journal."""

from __future__ import annotations

import ctypes
import hashlib
import os
import re
import secrets
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .board import BoardSnapshot
from .canonical import CanonicalDataError, canonical_json_bytes, canonical_json_line, load_canonical_json
from .models import ControllerValidationError, require_identifier

JOURNAL_SCHEMA = "AOSBOARDTX/1"
DERIVED_SCHEMA = "AOSBOARDSNAPSHOT/1"
ZERO_DIGEST = "0" * 64
DEFAULT_MAX_RECORD_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_TRANSACTIONS = 1024
_FILE_RE = re.compile(r"(?P<seq>[0-9]{20})-(?P<tx>[A-Za-z0-9][A-Za-z0-9._-]{0,127})\.(?P<phase>prepare|commit)\.json\Z")
_RECORD_FIELDS = {
    "schema", "state", "project_id", "transaction_id", "controller_epoch",
    "transaction_sequence", "previous_revision", "new_revision",
    "previous_event_sequence", "new_event_sequence", "previous_commit_digest",
    "payload", "payload_digest", "prepare_digest", "record_digest",
}


class JournalError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True, slots=True)
class RecoveryResult:
    snapshot: BoardSnapshot
    committed_transactions: int
    head_digest: str
    dangling_prepares: tuple[str, ...]


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _record_digest(record: dict[str, object]) -> str:
    unsigned = {key: value for key, value in record.items() if key != "record_digest"}
    return _sha256(canonical_json_bytes(unsigned))


def _bind_transition_metadata(
    previous: BoardSnapshot | None,
    candidate: BoardSnapshot,
    sequence: int,
) -> BoardSnapshot:
    previous_digest = ZERO_DIGEST if previous is None else previous.project.transition_digest
    normalized_project = replace(
        candidate.project,
        transition_sequence=sequence,
        transition_digest=ZERO_DIGEST,
    )
    normalized = BoardSnapshot.create(normalized_project, candidate.tasks)
    transition_digest = _sha256(
        canonical_json_bytes(
            {
                "schema": "AOSTRANSITION/1",
                "previous_transition_digest": previous_digest,
                "transition_sequence": sequence,
                "board": normalized.to_dict(),
            }
        )
    )
    return BoardSnapshot.create(
        replace(normalized_project, transition_digest=transition_digest),
        candidate.tasks,
    )


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _durable_replace(source: Path, target: Path) -> None:
    if os.name == "nt":
        move_write_through = 0x8
        succeeded = ctypes.windll.kernel32.MoveFileExW(  # type: ignore[attr-defined]
            str(source), str(target), move_write_through
        )
        if not succeeded:
            error = ctypes.get_last_error()
            raise OSError(error, "MoveFileExW failed")
    else:
        # link() is the portable same-filesystem no-replace primitive. It makes
        # the fully fsynced temporary inode authoritative without permitting a
        # concurrent writer to overwrite an immutable record name.
        os.link(source, target)
        os.unlink(source)
        _fsync_directory(target.parent)


def _durable_replace_mutable(source: Path, target: Path) -> None:
    if os.name == "nt":
        move_replace_existing = 0x1
        move_write_through = 0x8
        succeeded = ctypes.windll.kernel32.MoveFileExW(  # type: ignore[attr-defined]
            str(source), str(target), move_replace_existing | move_write_through
        )
        if not succeeded:
            error = ctypes.get_last_error()
            raise OSError(error, "MoveFileExW failed")
    else:
        os.replace(source, target)
        _fsync_directory(target.parent)


class TransactionJournal:
    """Immutable PREPARE/COMMIT records; only committed chains are authoritative."""

    def __init__(
        self,
        root: Path,
        project_id: str,
        *,
        max_transactions: int = DEFAULT_MAX_TRANSACTIONS,
        max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
    ) -> None:
        require_identifier("project_id", project_id)
        if type(max_transactions) is not int or max_transactions < 1:
            raise JournalError("INVALID_JOURNAL_LIMIT")
        if type(max_record_bytes) is not int or max_record_bytes < 1024:
            raise JournalError("INVALID_RECORD_LIMIT")
        self.root = Path(root)
        self.project_id = project_id
        self.max_transactions = max_transactions
        self.max_record_bytes = max_record_bytes
        self.root.mkdir(parents=True, exist_ok=True)

    def initialize(
        self,
        snapshot: BoardSnapshot,
        *,
        transaction_id: str,
        fail_after_prepare: bool = False,
        fail_after_commit: bool = False,
    ) -> RecoveryResult:
        if any(self.root.glob("*.commit.json")) or any(self.root.glob("*.prepare.json")):
            raise JournalError("JOURNAL_ALREADY_INITIALIZED")
        if snapshot.revision != 0:
            raise JournalError("INITIAL_REVISION_MUST_BE_ZERO")
        return self._write_transaction(None, snapshot, transaction_id, fail_after_prepare, fail_after_commit)

    def commit(
        self,
        previous: BoardSnapshot,
        new: BoardSnapshot,
        *,
        transaction_id: str,
        fail_after_prepare: bool = False,
        fail_after_commit: bool = False,
    ) -> RecoveryResult:
        recovered = self.recover()
        if recovered.dangling_prepares:
            raise JournalError("UNRESOLVED_DANGLING_PREPARE")
        if recovered.snapshot != previous:
            raise JournalError("STALE_AUTHORITATIVE_SNAPSHOT")
        if recovered.committed_transactions >= self.max_transactions:
            raise JournalError("JOURNAL_TRANSACTION_LIMIT")
        if new.revision != previous.revision + 1:
            raise JournalError("REVISION_NOT_CONTIGUOUS")
        return self._write_transaction(previous, new, transaction_id, fail_after_prepare, fail_after_commit)

    def _write_transaction(
        self,
        previous: BoardSnapshot | None,
        new: BoardSnapshot,
        transaction_id: str,
        fail_after_prepare: bool,
        fail_after_commit: bool,
    ) -> RecoveryResult:
        self._require_transaction_id(transaction_id)
        existing = self._records_by_phase()
        if any(record["transaction_id"] == transaction_id for record in existing.values()):
            raise JournalError("DUPLICATE_TRANSACTION")
        committed = [record for (_, phase), record in existing.items() if phase == "COMMIT"]
        sequence = len(committed) + 1
        previous_revision = -1 if previous is None else previous.revision
        if new.revision != previous_revision + 1:
            raise JournalError("REVISION_NOT_CONTIGUOUS")
        if previous is not None and previous.project.transition_sequence != sequence - 1:
            raise JournalError("TRANSITION_SEQUENCE_ROLLBACK")
        new = _bind_transition_metadata(previous, new, sequence)
        prior_digest = ZERO_DIGEST if not committed else str(sorted(committed, key=lambda item: item["transaction_sequence"])[-1]["record_digest"])
        payload = new.to_dict()
        payload_digest = _sha256(canonical_json_bytes(payload))
        common: dict[str, object] = {
            "schema": JOURNAL_SCHEMA,
            "project_id": self.project_id,
            "transaction_id": transaction_id,
            "controller_epoch": new.project.controller_epoch,
            "transaction_sequence": sequence,
            "previous_revision": previous_revision,
            "new_revision": new.revision,
            "previous_event_sequence": sequence - 1,
            "new_event_sequence": sequence,
            "previous_commit_digest": prior_digest,
            "payload": payload,
            "payload_digest": payload_digest,
        }
        prepare = {**common, "state": "PREPARE", "prepare_digest": None, "record_digest": ""}
        prepare["record_digest"] = _record_digest(prepare)
        prepare_path = self._path(sequence, transaction_id, "prepare")
        self._write_immutable(prepare_path, prepare)
        if fail_after_prepare:
            raise JournalError("SIMULATED_CRASH_AFTER_PREPARE")
        commit = {
            **common,
            "state": "COMMIT",
            "prepare_digest": prepare["record_digest"],
            "record_digest": "",
        }
        commit["record_digest"] = _record_digest(commit)
        self._write_immutable(self._path(sequence, transaction_id, "commit"), commit)
        if fail_after_commit:
            raise JournalError("SIMULATED_CRASH_AFTER_COMMIT")
        return self.recover()

    def complete_prepared(self, transaction_id: str) -> RecoveryResult:
        """Explicitly finish one verified dangling PREPARE; recovery alone never does."""
        self._require_transaction_id(transaction_id)
        recovered = self.recover()
        if recovered.dangling_prepares != (transaction_id,):
            raise JournalError("PREPARED_TRANSACTION_NOT_CURRENT")
        records = self._records_by_phase()
        sequence = recovered.committed_transactions + 1
        prepare = records[(sequence, "PREPARE")]
        commit = {
            **prepare,
            "state": "COMMIT",
            "prepare_digest": prepare["record_digest"],
            "record_digest": "",
        }
        commit["record_digest"] = _record_digest(commit)
        self._write_immutable(self._path(sequence, transaction_id, "commit"), commit)
        return self.recover()

    def recover(self) -> RecoveryResult:
        records = self._records_by_phase()
        if not records:
            raise JournalError("EMPTY_JOURNAL")
        commits = {seq: record for (seq, phase), record in records.items() if phase == "COMMIT"}
        prepares = {seq: record for (seq, phase), record in records.items() if phase == "PREPARE"}
        if not commits:
            raise JournalError("NO_COMMITTED_TRANSACTION")
        expected_sequences = set(range(1, len(commits) + 1))
        if set(commits) != expected_sequences:
            raise JournalError("SEQUENCE_GAP_OR_ROLLBACK")
        if len(commits) > self.max_transactions:
            raise JournalError("JOURNAL_TRANSACTION_LIMIT")
        seen_transactions: set[str] = set()
        prior_digest = ZERO_DIGEST
        prior_revision = -1
        snapshot: BoardSnapshot | None = None
        previous_snapshot: BoardSnapshot | None = None
        for sequence in sorted(commits):
            commit = commits[sequence]
            prepare = prepares.get(sequence)
            if prepare is None:
                raise JournalError("COMMIT_WITHOUT_PREPARE")
            transaction_id = str(commit["transaction_id"])
            if transaction_id in seen_transactions:
                raise JournalError("DUPLICATE_TRANSACTION")
            seen_transactions.add(transaction_id)
            if prepare["transaction_id"] != transaction_id:
                raise JournalError("PREPARE_COMMIT_MISMATCH")
            if commit["previous_commit_digest"] != prior_digest or prepare["previous_commit_digest"] != prior_digest:
                raise JournalError("HASH_CHAIN_MISMATCH")
            self._validate_semantics(commit, sequence, "COMMIT")
            self._validate_semantics(prepare, sequence, "PREPARE")
            if commit["prepare_digest"] != prepare["record_digest"]:
                raise JournalError("PREPARE_DIGEST_MISMATCH")
            if any(commit[key] != prepare[key] for key in _RECORD_FIELDS - {"state", "prepare_digest", "record_digest"}):
                raise JournalError("PREPARE_COMMIT_MISMATCH")
            if commit["previous_revision"] != prior_revision or commit["new_revision"] != prior_revision + 1:
                raise JournalError("REVISION_ROLLBACK_OR_GAP")
            try:
                snapshot = BoardSnapshot.from_dict(commit["payload"])
            except (ControllerValidationError, TypeError, ValueError) as exc:
                raise JournalError("INVALID_BOARD_PAYLOAD") from exc
            if snapshot.revision != commit["new_revision"]:
                raise JournalError("PAYLOAD_REVISION_MISMATCH")
            if snapshot.project.transition_sequence != sequence:
                raise JournalError("TRANSITION_SEQUENCE_ROLLBACK")
            expected_transition = _bind_transition_metadata(
                previous_snapshot,
                snapshot,
                sequence,
            ).project.transition_digest
            if snapshot.project.transition_digest != expected_transition:
                raise JournalError("TRANSITION_DIGEST_MISMATCH")
            prior_revision = snapshot.revision
            prior_digest = str(commit["record_digest"])
            previous_snapshot = snapshot
        dangling = []
        for sequence, prepare in prepares.items():
            if sequence in commits:
                continue
            if sequence != len(commits) + 1:
                raise JournalError("DANGLING_PREPARE_SEQUENCE")
            self._validate_semantics(prepare, sequence, "PREPARE")
            if prepare["previous_commit_digest"] != prior_digest or prepare["previous_revision"] != prior_revision:
                raise JournalError("HASH_CHAIN_MISMATCH")
            txid = str(prepare["transaction_id"])
            if txid in seen_transactions:
                raise JournalError("DUPLICATE_TRANSACTION")
            dangling.append(txid)
        assert snapshot is not None
        result = RecoveryResult(snapshot, len(commits), prior_digest, tuple(sorted(dangling)))
        self._reconcile_derived_snapshot(result)
        return result

    def _records_by_phase(self) -> dict[tuple[int, str], dict[str, Any]]:
        records: dict[tuple[int, str], dict[str, Any]] = {}
        entries = sorted(self.root.iterdir())
        if len(entries) > self.max_transactions * 2 + 2:
            raise JournalError("JOURNAL_ENTRY_LIMIT")
        for path in entries:
            if path.name.startswith(".tmp-"):
                continue
            if path.name == "board.json":
                continue
            match = _FILE_RE.fullmatch(path.name)
            if match is None:
                raise JournalError("UNKNOWN_JOURNAL_ENTRY", path.name)
            sequence = int(match.group("seq"))
            phase = match.group("phase").upper()
            try:
                raw = path.read_bytes()
            except OSError as exc:
                raise JournalError("UNREADABLE_RECORD", path.name) from exc
            if len(raw) > self.max_record_bytes:
                raise JournalError("RECORD_BYTE_LIMIT")
            if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
                raise JournalError("TRUNCATED_OR_NONCANONICAL_RECORD", path.name)
            try:
                value = load_canonical_json(raw[:-1], max_bytes=self.max_record_bytes - 1)
                if canonical_json_line(value, max_bytes=self.max_record_bytes) != raw:
                    raise JournalError("TRUNCATED_OR_NONCANONICAL_RECORD", path.name)
            except CanonicalDataError as exc:
                raise JournalError("TRUNCATED_OR_NONCANONICAL_RECORD", path.name) from exc
            if type(value) is not dict or set(value) != _RECORD_FIELDS:
                raise JournalError("INVALID_RECORD_FIELDS", path.name)
            if value["transaction_sequence"] != sequence or value["transaction_id"] != match.group("tx") or value["state"] != phase:
                raise JournalError("SEQUENCE_FILENAME_MISMATCH", path.name)
            key = (sequence, phase)
            if key in records:
                raise JournalError("DUPLICATE_RECORD")
            records[key] = value
        return records

    def _validate_semantics(self, record: dict[str, Any], sequence: int, phase: str) -> None:
        if record["schema"] != JOURNAL_SCHEMA or record["project_id"] != self.project_id:
            raise JournalError("INVALID_RECORD_IDENTITY")
        if record["state"] != phase or record["transaction_sequence"] != sequence:
            raise JournalError("SEQUENCE_FILENAME_MISMATCH")
        if type(record["controller_epoch"]) is not int or record["controller_epoch"] < 1:
            raise JournalError("INVALID_CONTROLLER_EPOCH")
        if record["previous_event_sequence"] != sequence - 1 or record["new_event_sequence"] != sequence:
            raise JournalError("EVENT_SEQUENCE_ROLLBACK")
        calculated_payload = _sha256(canonical_json_bytes(record["payload"]))
        if record["payload_digest"] != calculated_payload:
            raise JournalError("PAYLOAD_DIGEST_MISMATCH")
        if type(record["previous_commit_digest"]) is not str or len(record["previous_commit_digest"]) != 64:
            raise JournalError("HASH_CHAIN_MISMATCH")
        if phase == "PREPARE" and record["prepare_digest"] is not None:
            raise JournalError("INVALID_PREPARE_DIGEST")
        if record["record_digest"] != _record_digest(record):
            raise JournalError("RECORD_DIGEST_MISMATCH")

    def _path(self, sequence: int, transaction_id: str, phase: str) -> Path:
        return self.root / f"{sequence:020d}-{transaction_id}.{phase}.json"

    @staticmethod
    def _require_transaction_id(value: str) -> None:
        require_identifier("transaction_id", value)
        if ":" in value:
            raise JournalError("INVALID_TRANSACTION_ID")

    def _write_immutable(self, target: Path, value: dict[str, object]) -> None:
        if target.exists():
            raise JournalError("IMMUTABLE_RECORD_EXISTS")
        raw = canonical_json_line(value, max_bytes=self.max_record_bytes)
        temporary = self.root / f".tmp-{secrets.token_hex(16)}"
        try:
            with temporary.open("xb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            _durable_replace(temporary, target)
        except OSError as exc:
            raise JournalError("DURABLE_WRITE_FAILED", target.name) from exc
        finally:
            if temporary.exists():
                temporary.unlink()

    def _derived_value(self, result: RecoveryResult) -> dict[str, object]:
        return {
            "schema": DERIVED_SCHEMA,
            "project_id": self.project_id,
            "committed_transactions": result.committed_transactions,
            "head_digest": result.head_digest,
            "board": result.snapshot.to_dict(),
        }

    def _reconcile_derived_snapshot(self, result: RecoveryResult) -> None:
        target = self.root / "board.json"
        expected = canonical_json_line(self._derived_value(result), max_bytes=self.max_record_bytes)
        if target.is_symlink() or (target.exists() and not target.is_file()):
            raise JournalError("DERIVED_SNAPSHOT_PATH_INVALID")
        try:
            if target.exists() and target.read_bytes() == expected:
                return
        except OSError as exc:
            raise JournalError("UNREADABLE_DERIVED_SNAPSHOT") from exc
        temporary = self.root / f".tmp-{secrets.token_hex(16)}"
        try:
            with temporary.open("xb") as handle:
                handle.write(expected)
                handle.flush()
                os.fsync(handle.fileno())
            _durable_replace_mutable(temporary, target)
        except OSError as exc:
            raise JournalError("DERIVED_SNAPSHOT_WRITE_FAILED") from exc
        finally:
            if temporary.exists():
                temporary.unlink()

    def read_record_for_test(self, path: Path) -> dict[str, Any]:
        value = load_canonical_json(path.read_bytes()[:-1])
        assert type(value) is dict
        return value

    def write_record_for_test(self, path: Path, value: dict[str, Any]) -> None:
        path.write_bytes(canonical_json_line(value, max_bytes=self.max_record_bytes))

    def read_derived_snapshot_for_test(self) -> RecoveryResult:
        target = self.root / "board.json"
        value = load_canonical_json(target.read_bytes()[:-1], max_bytes=self.max_record_bytes)
        if type(value) is not dict or set(value) != {"schema", "project_id", "committed_transactions", "head_digest", "board"}:
            raise JournalError("INVALID_DERIVED_SNAPSHOT")
        return RecoveryResult(
            BoardSnapshot.from_dict(value["board"]),
            value["committed_transactions"],
            value["head_digest"],
            (),
        )
