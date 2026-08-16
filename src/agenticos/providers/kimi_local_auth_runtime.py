"""Metadata-only credential and controller-evidence boundary for Kimi Level 1."""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from agenticos.providers.kimi_local_auth import (
    LocalAuthProtocolOutcome,
    LocalCredentialState,
    QualificationState,
)
from agenticos.providers.kimi_policy import (
    PINNED_EXECUTABLE_SHA256,
    KimiPolicyError,
    validate_future_credential_directory,
)


REAL_PROVIDER_STATE_ROOT: Final = Path(
    "/home/brand/.local/share/agenticos/provider-state/kimi-code/0.36.1"
)
REAL_EVIDENCE_ROOT: Final = Path(
    "/home/brand/.local/share/agenticos/controller-evidence/kimi-code/0.36.1/level1-local-auth"
)
SANDBOX_WORKSPACE_ROOT: Final = Path("/workspace")

_ATTEMPT_FILE: Final = "attempt.json"
_RESULT_FILE: Final = "result.json"
_COMMIT_ID: Final = re.compile(r"[0-9a-f]{40}\Z")
_REASON_CODE: Final = re.compile(r"[A-Z][A-Z0-9_]*\Z")
_COUNT_FIELDS: Final = frozenset(
    {
        "process_count",
        "descendant_count",
        "environment_name_count",
        "fd_class_count",
        "external_endpoint_count",
        "session_artifact_count",
    }
)
_BOOLEAN_FIELDS: Final = frozenset({"cleanup_complete"})


class KimiLocalAuthRuntimeError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(slots=True)
class CredentialLeafHandle:
    descriptor: int
    device: int
    inode: int
    uid: int
    mode: int
    link_count: int
    _closed: bool = field(default=False, init=False, repr=False)

    def close(self) -> None:
        if self._closed:
            return
        os.close(self.descriptor)
        self._closed = True


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _resolve_existing(path: Path, code: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise KimiLocalAuthRuntimeError(code)
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise KimiLocalAuthRuntimeError(code) from exc


def _reject_credential_crossover(resolved: Path) -> None:
    if resolved == REAL_PROVIDER_STATE_ROOT:
        return
    if (
        _is_within(resolved, REAL_PROVIDER_STATE_ROOT)
        or _is_within(resolved, REAL_EVIDENCE_ROOT)
        or _is_within(resolved, SANDBOX_WORKSPACE_ROOT)
    ):
        raise KimiLocalAuthRuntimeError("SYNTHETIC_REAL_CROSSOVER")


def _reject_evidence_crossover(resolved: Path) -> None:
    if resolved == REAL_EVIDENCE_ROOT:
        return
    if (
        _is_within(resolved, REAL_PROVIDER_STATE_ROOT)
        or _is_within(resolved, REAL_EVIDENCE_ROOT)
        or _is_within(resolved, SANDBOX_WORKSPACE_ROOT)
    ):
        raise KimiLocalAuthRuntimeError("SYNTHETIC_REAL_CROSSOVER")


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _validate_private_owned_ancestry(
    path: Path,
    *,
    expected_uid: int,
    code: str,
) -> None:
    current = path
    while True:
        try:
            info = current.lstat()
        except OSError as exc:
            raise KimiLocalAuthRuntimeError(code) from exc
        if info.st_uid != expected_uid:
            return
        if (
            current.is_symlink()
            or not stat.S_ISDIR(info.st_mode)
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise KimiLocalAuthRuntimeError(code)
        parent = current.parent
        if parent == current:
            return
        current = parent


def open_validated_credential_leaf(
    state_root: Path,
    *,
    trusted_state_root: Path,
    expected_uid: int,
) -> CredentialLeafHandle:
    """Open only an unreadable Linux metadata descriptor for the fixed leaf."""

    if type(expected_uid) is not int or expected_uid < 0:
        raise KimiLocalAuthRuntimeError("CREDENTIAL_DIRECTORY_ARGUMENT")
    resolved_state = _resolve_existing(state_root, "CREDENTIAL_DIRECTORY_PATH")
    resolved_trusted = _resolve_existing(
        trusted_state_root, "CREDENTIAL_DIRECTORY_PATH"
    )
    _reject_credential_crossover(resolved_state)
    _reject_credential_crossover(resolved_trusted)

    credential_root = state_root / "credentials"
    leaf = credential_root / "kimi-code.json"
    try:
        before_validation = leaf.lstat()
    except OSError:
        before_validation = None
    try:
        validate_future_credential_directory(
            credential_root,
            trusted_state_root=trusted_state_root,
            expected_uid=expected_uid,
        )
    except KimiPolicyError as exc:
        raise KimiLocalAuthRuntimeError(exc.code) from exc
    _validate_private_owned_ancestry(
        trusted_state_root,
        expected_uid=expected_uid,
        code="CREDENTIAL_DIRECTORY_MODE",
    )
    try:
        after_validation = leaf.lstat()
    except OSError as exc:
        code = (
            "CREDENTIAL_ENTRY_TYPE"
            if before_validation is None
            else "CREDENTIAL_INODE_CHANGED"
        )
        raise KimiLocalAuthRuntimeError(code) from exc
    if before_validation is None or not _same_inode(
        before_validation, after_validation
    ):
        raise KimiLocalAuthRuntimeError("CREDENTIAL_INODE_CHANGED")

    o_path = getattr(os, "O_PATH", None)
    if type(o_path) is not int:
        raise KimiLocalAuthRuntimeError("O_PATH_UNAVAILABLE")
    flags = o_path | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(leaf, flags)
    except OSError as exc:
        raise KimiLocalAuthRuntimeError("CREDENTIAL_OPEN_FAILED") from exc
    try:
        opened = os.fstat(descriptor)
        lexical = leaf.lstat()
        if not (
            _same_inode(before_validation, opened)
            and _same_inode(opened, lexical)
        ):
            raise KimiLocalAuthRuntimeError("CREDENTIAL_INODE_CHANGED")
        if not stat.S_ISREG(opened.st_mode):
            raise KimiLocalAuthRuntimeError("CREDENTIAL_ENTRY_TYPE")
        if opened.st_uid != expected_uid:
            raise KimiLocalAuthRuntimeError("CREDENTIAL_FILE_OWNER")
        if stat.S_IMODE(opened.st_mode) != 0o600:
            raise KimiLocalAuthRuntimeError("CREDENTIAL_FILE_MODE")
        if opened.st_nlink != 1:
            raise KimiLocalAuthRuntimeError("CREDENTIAL_FILE_LINK_COUNT")
    except BaseException:
        os.close(descriptor)
        raise
    return CredentialLeafHandle(
        descriptor=descriptor,
        device=opened.st_dev,
        inode=opened.st_ino,
        uid=opened.st_uid,
        mode=stat.S_IMODE(opened.st_mode),
        link_count=opened.st_nlink,
    )


def _validate_candidate(candidate_commit: str, expected_uid: int) -> None:
    if (
        type(candidate_commit) is not str
        or _COMMIT_ID.fullmatch(candidate_commit) is None
        or type(expected_uid) is not int
        or expected_uid < 0
    ):
        raise KimiLocalAuthRuntimeError("EVIDENCE_ARGUMENT")


def _open_validated_evidence_root(evidence_root: Path, expected_uid: int) -> int:
    resolved = _resolve_existing(evidence_root, "EVIDENCE_ROOT_PATH")
    _reject_evidence_crossover(resolved)
    try:
        lexical = evidence_root.lstat()
    except OSError as exc:
        raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_PATH") from exc
    if evidence_root.is_symlink() or not stat.S_ISDIR(lexical.st_mode):
        raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_TYPE")
    if lexical.st_uid != expected_uid:
        raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_OWNER")
    if stat.S_IMODE(lexical.st_mode) != 0o700:
        raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_MODE")
    _validate_private_owned_ancestry(
        evidence_root,
        expected_uid=expected_uid,
        code="EVIDENCE_ROOT_MODE",
    )

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(evidence_root, flags)
    except OSError as exc:
        raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_OPEN") from exc
    try:
        opened = os.fstat(descriptor)
        if not _same_inode(lexical, opened):
            raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_CHANGED")
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != expected_uid
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_CHANGED")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def _persist_exclusive(
    directory_fd: int,
    name: str,
    payload: bytes,
    *,
    exists_code: str,
    failure_code: str,
    expected_uid: int,
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    except FileExistsError as exc:
        raise KimiLocalAuthRuntimeError(exists_code) from exc
    except OSError as exc:
        raise KimiLocalAuthRuntimeError(failure_code) from exc
    try:
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != expected_uid
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
        ):
            raise KimiLocalAuthRuntimeError(failure_code)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written < 1:
                raise KimiLocalAuthRuntimeError(failure_code)
            remaining = remaining[written:]
        os.fsync(descriptor)
    except KimiLocalAuthRuntimeError:
        raise
    except OSError as exc:
        raise KimiLocalAuthRuntimeError(failure_code) from exc
    finally:
        os.close(descriptor)
    try:
        os.fsync(directory_fd)
    except OSError as exc:
        raise KimiLocalAuthRuntimeError(failure_code) from exc


def _claim_payload(candidate_commit: str) -> dict[str, object]:
    return {
        "schema": "AOS_KIMI_LEVEL1_ATTEMPT/1",
        "attempt": 1,
        "candidate_commit": candidate_commit,
        "pinned_executable_sha256": PINNED_EXECUTABLE_SHA256,
        "lifecycle": "CLAIMED_BEFORE_LAUNCH",
    }


def claim_real_attempt(
    evidence_root: Path,
    *,
    candidate_commit: str,
    expected_uid: int,
) -> None:
    _validate_candidate(candidate_commit, expected_uid)
    directory_fd = _open_validated_evidence_root(evidence_root, expected_uid)
    try:
        try:
            entries = set(os.listdir(directory_fd))
        except OSError as exc:
            raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_UNREADABLE") from exc
        if _ATTEMPT_FILE in entries:
            raise KimiLocalAuthRuntimeError("ATTEMPT_ALREADY_CLAIMED")
        if entries:
            raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_ENTRIES")
        _persist_exclusive(
            directory_fd,
            _ATTEMPT_FILE,
            _canonical_json(_claim_payload(candidate_commit)),
            exists_code="ATTEMPT_ALREADY_CLAIMED",
            failure_code="ATTEMPT_EVIDENCE_WRITE_FAILED",
            expected_uid=expected_uid,
        )
    finally:
        os.close(directory_fd)


def _validate_protocol(protocol: LocalAuthProtocolOutcome) -> None:
    if (
        type(protocol) is not LocalAuthProtocolOutcome
        or type(protocol.qualification) is not QualificationState
        or type(protocol.credential_state) is not LocalCredentialState
        or protocol.auth_state != "LOCAL_ONLY"
        or protocol.level2_status
        != "BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT"
        or type(protocol.reason_code) is not str
        or _REASON_CODE.fullmatch(protocol.reason_code) is None
    ):
        raise KimiLocalAuthRuntimeError("RESULT_PROTOCOL_FIELDS")
    expected_reason = {
        LocalCredentialState.LOADABLE: "ACP_LOCAL_AUTH_SUCCESS",
        LocalCredentialState.REJECTED: "ACP_LOCAL_AUTH_REJECTED",
    }.get(protocol.credential_state)
    if expected_reason is not None and protocol.reason_code != expected_reason:
        raise KimiLocalAuthRuntimeError("RESULT_REASON_CONTRADICTION")
    if (
        protocol.credential_state is LocalCredentialState.BLOCKED
        and protocol.reason_code
        in {"ACP_LOCAL_AUTH_SUCCESS", "ACP_LOCAL_AUTH_REJECTED"}
    ):
        raise KimiLocalAuthRuntimeError("RESULT_REASON_CONTRADICTION")


def _validated_census(census_counts: Mapping[str, int | bool]) -> dict[str, int | bool]:
    if not isinstance(census_counts, Mapping):
        raise KimiLocalAuthRuntimeError("RESULT_CENSUS_FIELDS")
    if not set(census_counts).issubset(_COUNT_FIELDS | _BOOLEAN_FIELDS):
        raise KimiLocalAuthRuntimeError("RESULT_CENSUS_FIELDS")
    result: dict[str, int | bool] = {}
    for name, value in census_counts.items():
        if name in _COUNT_FIELDS:
            if type(value) is not int or value < 0:
                raise KimiLocalAuthRuntimeError("RESULT_CENSUS_FIELDS")
        elif type(value) is not bool:
            raise KimiLocalAuthRuntimeError("RESULT_CENSUS_FIELDS")
        result[name] = value
    return result


def _read_exact_claim(
    directory_fd: int,
    *,
    candidate_commit: str,
    expected_uid: int,
) -> None:
    expected = _canonical_json(_claim_payload(candidate_commit))
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(_ATTEMPT_FILE, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise KimiLocalAuthRuntimeError("ATTEMPT_MARKER_INVALID") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != expected_uid
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
        ):
            raise KimiLocalAuthRuntimeError("ATTEMPT_MARKER_INVALID")
        observed = os.read(descriptor, len(expected) + 1)
        if observed != expected:
            raise KimiLocalAuthRuntimeError("ATTEMPT_MARKER_INVALID")
    except KimiLocalAuthRuntimeError:
        raise
    except OSError as exc:
        raise KimiLocalAuthRuntimeError("ATTEMPT_MARKER_INVALID") from exc
    finally:
        os.close(descriptor)


def persist_typed_result(
    evidence_root: Path,
    protocol: LocalAuthProtocolOutcome,
    census_counts: Mapping[str, int | bool],
    *,
    candidate_commit: str,
    expected_uid: int,
) -> None:
    _validate_candidate(candidate_commit, expected_uid)
    _validate_protocol(protocol)
    census = _validated_census(census_counts)
    directory_fd = _open_validated_evidence_root(evidence_root, expected_uid)
    try:
        try:
            entries = set(os.listdir(directory_fd))
        except OSError as exc:
            raise KimiLocalAuthRuntimeError("EVIDENCE_ROOT_UNREADABLE") from exc
        if _RESULT_FILE in entries:
            raise KimiLocalAuthRuntimeError("RESULT_ALREADY_PERSISTED")
        if entries != {_ATTEMPT_FILE}:
            raise KimiLocalAuthRuntimeError("ATTEMPT_MARKER_INVALID")
        _read_exact_claim(
            directory_fd,
            candidate_commit=candidate_commit,
            expected_uid=expected_uid,
        )
        result = {
            "schema": "AOS_KIMI_LEVEL1_RESULT/1",
            "candidate_commit": candidate_commit,
            "pinned_executable_sha256": PINNED_EXECUTABLE_SHA256,
            "F1_KIMI_LEVEL1_LOCAL_AUTH_QUALIFICATION": protocol.qualification.value,
            "F1_KIMI_LOCAL_CREDENTIAL_STATE": protocol.credential_state.value,
            "F1_KIMI_AUTH_STATE": protocol.auth_state,
            "F1_KIMI_LEVEL2_NON_INFERENCE_STATUS": protocol.level2_status,
            "reason_code": protocol.reason_code,
            "census_counts": census,
        }
        _persist_exclusive(
            directory_fd,
            _RESULT_FILE,
            _canonical_json(result),
            exists_code="RESULT_ALREADY_PERSISTED",
            failure_code="RESULT_EVIDENCE_WRITE_FAILED",
            expected_uid=expected_uid,
        )
    finally:
        os.close(directory_fd)
