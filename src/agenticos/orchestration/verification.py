"""Controller-owned deterministic verification values and execution policy."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath

from .canonical import canonical_json_bytes
from .models import (
    ControllerValidationError,
    require_digest,
    require_enum,
    require_exact_fields,
    require_identifier,
    require_text,
    require_uint,
    TaskStatus,
)
from .board import BoardSnapshot
from .protocol import DispatchIdentity
from agenticos.sandbox.containment import ContainmentState
from agenticos.sandbox.models import ContainmentReservation, PreparedProcessReceipt, ProcessResult
from agenticos.sandbox.runtime_boundary import M4AProfile
from agenticos.sandbox.worktree import WorkspaceCaptureCompleteness, WorkspaceReuseDecision

VERIFICATION_RESULT_SCHEMA = "AOSVERIFICATIONRESULT/1"
MAX_ARG_BYTES = 4096
MAX_ARGV_BYTES = 32_768
MAX_INLINE_OUTPUT_BYTES = 4096
MAX_CAPTURE_BYTES = 16_777_216
_FORBIDDEN_EXECUTABLES = frozenset(
    {"sh", "bash", "dash", "zsh", "ksh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"}
)
_FORBIDDEN_INTERPRETER_ARGUMENTS = frozenset(
    {"-c", "/c", "--command", "-command", "-encodedcommand"}
)


class VerificationError(ValueError):
    """Stable fail-closed rejection for Slice D verification authority."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail[:4096]
        super().__init__(f"{code}: {self.detail}" if self.detail else code)


def _convert(exc: Exception, fallback: str = "INVALID_VERIFICATION_VALUE") -> VerificationError:
    return VerificationError(getattr(exc, "code", fallback), getattr(exc, "detail", ""))


class FailureClassification(str, Enum):
    VERIFICATION_FAILURE = "VERIFICATION_FAILURE"
    REVIEW_BLOCKING_FINDING = "REVIEW_BLOCKING_FINDING"
    RETRYABLE_INFRASTRUCTURE_FAILURE = "RETRYABLE_INFRASTRUCTURE_FAILURE"
    TERMINAL_INFRASTRUCTURE_FAILURE = "TERMINAL_INFRASTRUCTURE_FAILURE"
    MALFORMED_AGENT_OUTPUT = "MALFORMED_AGENT_OUTPUT"
    STALE_IDENTITY = "STALE_IDENTITY"
    CHECKPOINT_MISMATCH = "CHECKPOINT_MISMATCH"
    WORKSPACE_MUTATION_DURING_READONLY_STAGE = "WORKSPACE_MUTATION_DURING_READONLY_STAGE"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    CONTAINMENT_FAILURE = "CONTAINMENT_FAILURE"
    REPAIR_BUDGET_EXHAUSTED = "REPAIR_BUDGET_EXHAUSTED"


class VerificationClassification(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INFRASTRUCTURE_ERROR = "INFRASTRUCTURE_ERROR"


class VerificationExitClassification(str, Enum):
    EXITED = "EXITED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    OUTPUT_LIMIT = "OUTPUT_LIMIT"
    CONTAINMENT_FAILURE = "CONTAINMENT_FAILURE"


def _exact_tuple_of_exit_codes(name: str, value: object) -> tuple[int, ...]:
    if type(value) is not tuple or not value:
        raise VerificationError("INVALID_EXIT_CODE_POLICY", name)
    if any(type(item) is not int or not 0 <= item <= 255 for item in value):
        raise VerificationError("INVALID_EXIT_CODE_POLICY", name)
    if tuple(sorted(set(value))) != value:
        raise VerificationError("INVALID_EXIT_CODE_POLICY", name)
    return value


@dataclass(frozen=True, slots=True)
class VerifierSpec:
    verifier_id: str
    executable: str
    argv: tuple[str, ...]
    working_directory: str
    timeout_seconds: int
    max_stdout_bytes: int
    max_stderr_bytes: int
    pass_exit_codes: tuple[int, ...]
    fail_exit_codes: tuple[int, ...]
    fixture_id: str | None = None

    def __post_init__(self) -> None:
        try:
            require_identifier("verifier_id", self.verifier_id)
            if self.fixture_id is not None:
                require_identifier("fixture_id", self.fixture_id)
            require_uint("timeout_seconds", self.timeout_seconds, minimum=1, maximum=3600)
            require_uint("max_stdout_bytes", self.max_stdout_bytes, minimum=1, maximum=MAX_CAPTURE_BYTES)
            require_uint("max_stderr_bytes", self.max_stderr_bytes, minimum=1, maximum=MAX_CAPTURE_BYTES)
        except ControllerValidationError as exc:
            raise _convert(exc) from exc
        if (
            type(self.executable) is not str
            or not self.executable.startswith("/")
            or PurePosixPath(self.executable).name in _FORBIDDEN_EXECUTABLES
            or "\x00" in self.executable
        ):
            raise VerificationError("INVALID_VERIFIER_EXECUTABLE")
        if type(self.argv) is not tuple or not self.argv or self.argv[0] != self.executable:
            raise VerificationError("INVALID_VERIFIER_ARGV")
        encoded_total = 0
        for item in self.argv:
            if type(item) is not str or not item or "\x00" in item:
                raise VerificationError("INVALID_VERIFIER_ARGV")
            item_bytes = len(item.encode("utf-8"))
            if item_bytes > MAX_ARG_BYTES:
                raise VerificationError("VERIFIER_ARGV_LIMIT")
            encoded_total += item_bytes
            if item.lower() in _FORBIDDEN_INTERPRETER_ARGUMENTS:
                raise VerificationError("COMMAND_INTERPOLATION_FORBIDDEN")
        if encoded_total > MAX_ARGV_BYTES:
            raise VerificationError("VERIFIER_ARGV_LIMIT")
        if self.working_directory != "/workspace":
            raise VerificationError("INVALID_VERIFIER_WORKING_DIRECTORY")
        passed = _exact_tuple_of_exit_codes("pass_exit_codes", self.pass_exit_codes)
        failed = _exact_tuple_of_exit_codes("fail_exit_codes", self.fail_exit_codes)
        if set(passed) & set(failed):
            raise VerificationError("AMBIGUOUS_EXIT_CODE_POLICY")

    @property
    def spec_digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_dict())).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "verifier_id": self.verifier_id,
            "executable": self.executable,
            "argv": list(self.argv),
            "working_directory": self.working_directory,
            "timeout_seconds": self.timeout_seconds,
            "max_stdout_bytes": self.max_stdout_bytes,
            "max_stderr_bytes": self.max_stderr_bytes,
            "pass_exit_codes": list(self.pass_exit_codes),
            "fail_exit_codes": list(self.fail_exit_codes),
            "fixture_id": self.fixture_id,
        }

    @classmethod
    def from_dict(cls, raw: object) -> "VerifierSpec":
        try:
            value = require_exact_fields(raw, set(cls.__dataclass_fields__))
        except ControllerValidationError as exc:
            raise _convert(exc) from exc
        if any(type(value[name]) is not list for name in ("argv", "pass_exit_codes", "fail_exit_codes")):
            raise VerificationError("INVALID_VERIFIER_SPEC_SHAPE")
        return cls(
            **{
                **value,
                "argv": tuple(value["argv"]),
                "pass_exit_codes": tuple(value["pass_exit_codes"]),
                "fail_exit_codes": tuple(value["fail_exit_codes"]),
            }
        )


class VerifierRegistry:
    """Immutable controller registry; callers may select only by registered ID."""

    def __init__(self, specs: tuple[VerifierSpec, ...]) -> None:
        if type(specs) is not tuple or any(not isinstance(item, VerifierSpec) for item in specs):
            raise VerificationError("INVALID_VERIFIER_REGISTRY")
        by_id = {item.verifier_id: item for item in specs}
        if len(by_id) != len(specs):
            raise VerificationError("DUPLICATE_VERIFIER_ID")
        self._specs = by_id

    def resolve(self, verifier_id: str, *, spec_digest: str | None = None) -> VerifierSpec:
        spec = self._specs.get(verifier_id)
        if spec is None:
            raise VerificationError("UNKNOWN_VERIFIER")
        if spec_digest is not None and spec.spec_digest != spec_digest:
            raise VerificationError("VERIFIER_SPEC_MISMATCH")
        return spec


@dataclass(frozen=True, slots=True)
class ReadonlyProcessEvidence:
    containment_unit: str
    cgroup_path: str
    pid: int
    process_group_id: int
    start_time_ticks: int
    boot_id: str
    policy_digest: str
    namespace_digest: str
    workspace_device: int
    workspace_inode: int

    def __post_init__(self) -> None:
        try:
            require_text("containment_unit", self.containment_unit, 256)
            require_text("cgroup_path", self.cgroup_path, 1024)
            require_text("boot_id", self.boot_id, 128)
            for name in (
                "pid", "process_group_id", "start_time_ticks", "workspace_device", "workspace_inode"
            ):
                require_uint(name, getattr(self, name), minimum=1)
            require_digest("policy_digest", self.policy_digest)
            require_digest("namespace_digest", self.namespace_digest)
        except ControllerValidationError as exc:
            raise _convert(exc) from exc
        if not self.containment_unit.endswith(".scope") or not self.cgroup_path.startswith("/sys/fs/cgroup/"):
            raise VerificationError("INVALID_CONTAINMENT_EVIDENCE")

    def to_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: object) -> "ReadonlyProcessEvidence":
        try:
            return cls(**require_exact_fields(raw, set(cls.__dataclass_fields__)))
        except ControllerValidationError as exc:
            raise _convert(exc) from exc


def verification_failure_fingerprint(
    *,
    verifier_id: str,
    verifier_spec_digest: str,
    checkpoint_digest: str,
    exit_code: int,
    stdout_sha256: str,
    stderr_sha256: str,
) -> str:
    try:
        require_identifier("verifier_id", verifier_id)
        for name, value in (
            ("verifier_spec_digest", verifier_spec_digest),
            ("checkpoint_digest", checkpoint_digest),
            ("stdout_sha256", stdout_sha256),
            ("stderr_sha256", stderr_sha256),
        ):
            require_digest(name, value)
        require_uint("exit_code", exit_code, maximum=255)
    except ControllerValidationError as exc:
        raise _convert(exc) from exc
    payload = {
        "checkpoint_digest": checkpoint_digest,
        "exit_code": exit_code,
        "stderr_sha256": stderr_sha256,
        "stdout_sha256": stdout_sha256,
        "verifier_id": verifier_id,
        "verifier_spec_digest": verifier_spec_digest,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


@dataclass(frozen=True, slots=True)
class VerificationResult:
    schema: str
    verifier_id: str
    verifier_spec_digest: str
    project_id: str
    task_id: str
    task_generation: int
    attempt: int
    controller_epoch: int
    checkpoint_digest: str
    classification: VerificationClassification
    failure_classification: FailureClassification | None
    exit_classification: VerificationExitClassification
    exit_code: int | None
    stdout_sha256: str
    stdout_byte_count: int
    stdout_inline: str
    stderr_sha256: str
    stderr_byte_count: int
    stderr_inline: str
    timed_out: bool
    cancelled: bool
    process_evidence: ReadonlyProcessEvidence | None
    failure_fingerprint: str | None

    def __post_init__(self) -> None:
        if self.schema != VERIFICATION_RESULT_SCHEMA:
            raise VerificationError("INVALID_SCHEMA")
        try:
            for name in ("verifier_id", "project_id", "task_id"):
                require_identifier(name, getattr(self, name))
            for name in ("verifier_spec_digest", "checkpoint_digest", "stdout_sha256", "stderr_sha256"):
                require_digest(name, getattr(self, name))
            require_digest("failure_fingerprint", self.failure_fingerprint, allow_none=True)
            for name in ("task_generation", "attempt", "controller_epoch"):
                require_uint(name, getattr(self, name), minimum=1)
            for name in ("stdout_byte_count", "stderr_byte_count"):
                require_uint(name, getattr(self, name), maximum=MAX_CAPTURE_BYTES)
            require_text("stdout_inline", self.stdout_inline, MAX_INLINE_OUTPUT_BYTES, allow_empty=True)
            require_text("stderr_inline", self.stderr_inline, MAX_INLINE_OUTPUT_BYTES, allow_empty=True)
        except ControllerValidationError as exc:
            raise _convert(exc) from exc
        if not isinstance(self.classification, VerificationClassification):
            raise VerificationError("INVALID_ENUM", "classification")
        if self.failure_classification is not None and not isinstance(self.failure_classification, FailureClassification):
            raise VerificationError("INVALID_ENUM", "failure_classification")
        if not isinstance(self.exit_classification, VerificationExitClassification):
            raise VerificationError("INVALID_ENUM", "exit_classification")
        if type(self.timed_out) is not bool or type(self.cancelled) is not bool:
            raise VerificationError("INVALID_BOOLEAN")
        if self.exit_code is not None and (type(self.exit_code) is not int or not 0 <= self.exit_code <= 255):
            raise VerificationError("INVALID_EXIT_CODE")
        if self.process_evidence is not None and not isinstance(self.process_evidence, ReadonlyProcessEvidence):
            raise VerificationError("INVALID_PROCESS_EVIDENCE")
        for text, count in (
            (self.stdout_inline, self.stdout_byte_count),
            (self.stderr_inline, self.stderr_byte_count),
        ):
            if (count == 0) != (text == "") or (
                "\ufffd" not in text
                and len(text.encode("utf-8")) != min(count, MAX_INLINE_OUTPUT_BYTES)
            ):
                raise VerificationError("INVALID_INLINE_OUTPUT_EVIDENCE")
        if self.timed_out != (self.exit_classification is VerificationExitClassification.TIMEOUT):
            raise VerificationError("INCONSISTENT_TIMEOUT")
        if self.cancelled != (self.exit_classification is VerificationExitClassification.CANCELLED):
            raise VerificationError("INCONSISTENT_CANCELLATION")
        if (self.timed_out or self.cancelled) and self.exit_code is not None:
            raise VerificationError("INCONSISTENT_EXIT_CODE")
        if self.classification is VerificationClassification.PASS:
            if (
                self.failure_classification is not None
                or self.failure_fingerprint is not None
                or self.exit_classification is not VerificationExitClassification.EXITED
                or self.exit_code is None
                or self.process_evidence is None
            ):
                raise VerificationError("INVALID_PASS_RESULT")
        elif self.classification is VerificationClassification.FAIL:
            if (
                self.failure_classification is not FailureClassification.VERIFICATION_FAILURE
                or self.failure_fingerprint is None
                or self.exit_classification is not VerificationExitClassification.EXITED
                or self.exit_code is None
                or self.process_evidence is None
            ):
                raise VerificationError("INVALID_SEMANTIC_FAILURE")
        elif (
            self.failure_classification is None
            or self.failure_classification is FailureClassification.VERIFICATION_FAILURE
            or self.failure_fingerprint is not None
        ):
            raise VerificationError("INVALID_INFRASTRUCTURE_FAILURE")

    @property
    def result_digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_dict())).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "verifier_id": self.verifier_id,
            "verifier_spec_digest": self.verifier_spec_digest,
            "project_id": self.project_id,
            "task_id": self.task_id,
            "task_generation": self.task_generation,
            "attempt": self.attempt,
            "controller_epoch": self.controller_epoch,
            "checkpoint_digest": self.checkpoint_digest,
            "classification": self.classification.value,
            "failure_classification": self.failure_classification.value if self.failure_classification else None,
            "exit_classification": self.exit_classification.value,
            "exit_code": self.exit_code,
            "stdout_sha256": self.stdout_sha256,
            "stdout_byte_count": self.stdout_byte_count,
            "stdout_inline": self.stdout_inline,
            "stderr_sha256": self.stderr_sha256,
            "stderr_byte_count": self.stderr_byte_count,
            "stderr_inline": self.stderr_inline,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "process_evidence": self.process_evidence.to_dict() if self.process_evidence else None,
            "failure_fingerprint": self.failure_fingerprint,
        }

    @classmethod
    def from_dict(cls, raw: object) -> "VerificationResult":
        try:
            value = require_exact_fields(raw, set(cls.__dataclass_fields__))
            classification = require_enum(VerificationClassification, "classification", value["classification"])
            failure = None if value["failure_classification"] is None else require_enum(
                FailureClassification, "failure_classification", value["failure_classification"]
            )
            exit_classification = require_enum(
                VerificationExitClassification, "exit_classification", value["exit_classification"]
            )
        except ControllerValidationError as exc:
            raise _convert(exc) from exc
        return cls(
            **{
                **value,
                "classification": classification,
                "failure_classification": failure,
                "exit_classification": exit_classification,
                "process_evidence": None if value["process_evidence"] is None else ReadonlyProcessEvidence.from_dict(value["process_evidence"]),
            }
        )


class VerificationController:
    """One explicitly invoked verifier stage; it performs no task selection."""

    def __init__(self, registry: VerifierRegistry) -> None:
        if not isinstance(registry, VerifierRegistry):
            raise VerificationError("INVALID_VERIFIER_REGISTRY")
        self.registry = registry
        self._cancel_requested = threading.Event()
        self._active_lock = threading.Lock()
        self._active: object | None = None

    def request_cancel(self) -> None:
        self._cancel_requested.set()
        with self._active_lock:
            active = self._active
        if active is not None:
            active.request_cancel()  # type: ignore[attr-defined]

    @staticmethod
    def _validate_binding(
        board: BoardSnapshot,
        dispatch: DispatchIdentity,
        checkpoint: object,
        reservation: ContainmentReservation,
    ) -> None:
        try:
            task = board.task(dispatch.task_id)
            project = board.project
            stale_checks = (
                project.project_id == dispatch.project_id,
                task.project_id == dispatch.project_id,
                task.status is TaskStatus.VERIFYING,
                task.generation == dispatch.task_generation,
                task.attempt_count == dispatch.attempt,
                project.controller_epoch == dispatch.controller_epoch,
                project.lease_epoch == task.lease_epoch == dispatch.lease_epoch,
                project.baseline.repository_id == dispatch.repository_id,
                project.baseline.commit_sha == dispatch.baseline_commit,
                project.workspace.workspace_id == task.workspace.workspace_id == dispatch.workspace_id,
                project.workspace.generation == task.workspace.generation == dispatch.workspace_generation,
                project.workspace.reservation_id == task.workspace.reservation_id == dispatch.reservation_id,
                reservation.project_id == dispatch.project_id,
                reservation.task_id == dispatch.task_id,
                reservation.task_generation == dispatch.task_generation,
                reservation.attempt == dispatch.attempt,
                reservation.controller_epoch == dispatch.controller_epoch,
                reservation.lease_epoch == dispatch.lease_epoch,
                reservation.dispatch_nonce == dispatch.dispatch_nonce,
            )
        except (AttributeError, KeyError, TypeError):
            raise VerificationError("STALE_IDENTITY") from None
        if not all(stale_checks):
            raise VerificationError("STALE_IDENTITY")
        try:
            checkpoint_checks = (
                checkpoint.checkpoint_digest == dispatch.checkpoint_digest,
                checkpoint.repository_id == dispatch.repository_id,
                checkpoint.task_id == dispatch.workspace_id,
                checkpoint.generation == dispatch.workspace_generation,
                checkpoint.baseline_commit_sha == dispatch.baseline_commit,
                checkpoint.reservation_digest == dispatch.reservation_id,
                checkpoint.capture_completeness is WorkspaceCaptureCompleteness.COMPLETE,
            )
        except (AttributeError, TypeError):
            raise VerificationError("CHECKPOINT_MISMATCH") from None
        if not all(checkpoint_checks):
            raise VerificationError("CHECKPOINT_MISMATCH")

    @staticmethod
    def _process_evidence(receipt: PreparedProcessReceipt) -> ReadonlyProcessEvidence:
        namespace_digest = hashlib.sha256(
            canonical_json_bytes(dict(receipt.namespace_ids))
        ).hexdigest()
        identity = receipt.process_identity
        return ReadonlyProcessEvidence(
            containment_unit=receipt.reservation.scope_name,
            cgroup_path=receipt.cgroup_path,
            pid=identity.pid,
            process_group_id=identity.process_group_id,  # type: ignore[arg-type]
            start_time_ticks=identity.start_time_ticks,  # type: ignore[arg-type]
            boot_id=identity.boot_id,  # type: ignore[arg-type]
            policy_digest=receipt.policy_digest,
            namespace_digest=namespace_digest,
            workspace_device=receipt.workspace_device,
            workspace_inode=receipt.workspace_inode,
        )

    @staticmethod
    def _bytes(process: ProcessResult) -> tuple[bytes, bytes]:
        stdout = process.stdout_bytes
        if not stdout and process.stdout:
            stdout = process.stdout.encode("utf-8")
        return stdout, process.stderr.encode("utf-8")

    @staticmethod
    def _inline(raw: bytes) -> str:
        bounded = raw[:MAX_INLINE_OUTPUT_BYTES]
        text = bounded.decode("utf-8", errors="replace")
        while len(text.encode("utf-8")) > MAX_INLINE_OUTPUT_BYTES:
            text = text[:-1]
        return text

    @staticmethod
    def _captured_checkpoint(capture: object) -> object:
        if (
            getattr(capture, "decision", None) is not WorkspaceReuseDecision.REUSABLE
            or getattr(capture, "checkpoint", None) is None
            or capture.checkpoint.capture_completeness is not WorkspaceCaptureCompleteness.COMPLETE
        ):
            raise VerificationError("CHECKPOINT_MISMATCH")
        return capture.checkpoint

    def _workspace_unchanged(
        self,
        *,
        workspace_manager: object,
        repo_path: Path,
        dispatch: DispatchIdentity,
        checkpoint: object,
    ) -> bool:
        try:
            first = self._captured_checkpoint(
                workspace_manager.capture_checkpoint(
                    repo_path, dispatch.workspace_id, dispatch.workspace_generation
                )
            )
            second = self._captured_checkpoint(
                workspace_manager.capture_checkpoint(
                    repo_path, dispatch.workspace_id, dispatch.workspace_generation
                )
            )
        except BaseException:
            return False
        return first == second == checkpoint

    def _result(
        self,
        *,
        spec: VerifierSpec,
        dispatch: DispatchIdentity,
        classification: VerificationClassification,
        failure: FailureClassification | None,
        exit_classification: VerificationExitClassification,
        exit_code: int | None,
        stdout: bytes = b"",
        stderr: bytes = b"",
        evidence: ReadonlyProcessEvidence | None = None,
        fingerprint: str | None = None,
    ) -> VerificationResult:
        return VerificationResult(
            schema=VERIFICATION_RESULT_SCHEMA,
            verifier_id=spec.verifier_id,
            verifier_spec_digest=spec.spec_digest,
            project_id=dispatch.project_id,
            task_id=dispatch.task_id,
            task_generation=dispatch.task_generation,
            attempt=dispatch.attempt,
            controller_epoch=dispatch.controller_epoch,
            checkpoint_digest=dispatch.checkpoint_digest,
            classification=classification,
            failure_classification=failure,
            exit_classification=exit_classification,
            exit_code=exit_code,
            stdout_sha256=hashlib.sha256(stdout).hexdigest(),
            stdout_byte_count=len(stdout),
            stdout_inline=self._inline(stdout),
            stderr_sha256=hashlib.sha256(stderr).hexdigest(),
            stderr_byte_count=len(stderr),
            stderr_inline=self._inline(stderr),
            timed_out=exit_classification is VerificationExitClassification.TIMEOUT,
            cancelled=exit_classification is VerificationExitClassification.CANCELLED,
            process_evidence=evidence,
            failure_fingerprint=fingerprint,
        )

    def verify(
        self,
        *,
        board: BoardSnapshot,
        dispatch: DispatchIdentity,
        checkpoint: object,
        verifier_id: str,
        runner: object,
        reservation: ContainmentReservation,
        workspace_manager: object,
        repo_path: Path,
    ) -> VerificationResult:
        spec = self.registry.resolve(verifier_id)
        if getattr(runner, "profile", None) is not M4AProfile.INSPECT:
            raise VerificationError("READONLY_PROFILE_REQUIRED")
        self._validate_binding(board, dispatch, checkpoint, reservation)
        self._cancel_requested.clear()
        try:
            prepared = runner.prepare(
                spec.argv,
                cwd=spec.working_directory,
                env={},
                reservation=reservation,
            )
        except BaseException:
            return self._result(
                spec=spec,
                dispatch=dispatch,
                classification=VerificationClassification.INFRASTRUCTURE_ERROR,
                failure=FailureClassification.CONTAINMENT_FAILURE,
                exit_classification=VerificationExitClassification.CONTAINMENT_FAILURE,
                exit_code=None,
            )
        receipt = getattr(prepared, "receipt", None)
        evidence: ReadonlyProcessEvidence | None = None
        receipt_valid = isinstance(receipt, PreparedProcessReceipt)
        if receipt_valid:
            try:
                evidence = self._process_evidence(receipt)
                receipt_valid = (
                    receipt.reservation == reservation
                    and receipt.executable == spec.executable
                    and receipt.argv == spec.argv
                    and receipt.workspace_device == checkpoint.worktree_device
                    and receipt.workspace_inode == checkpoint.worktree_inode
                )
            except (AttributeError, TypeError, VerificationError):
                receipt_valid = False
        if not receipt_valid:
            try:
                prepared.cancel()
            except BaseException:
                pass
            unchanged = self._workspace_unchanged(
                workspace_manager=workspace_manager,
                repo_path=repo_path,
                dispatch=dispatch,
                checkpoint=checkpoint,
            )
            return self._result(
                spec=spec,
                dispatch=dispatch,
                classification=VerificationClassification.INFRASTRUCTURE_ERROR,
                failure=(
                    FailureClassification.CONTAINMENT_FAILURE
                    if unchanged
                    else FailureClassification.WORKSPACE_MUTATION_DURING_READONLY_STAGE
                ),
                exit_classification=VerificationExitClassification.CONTAINMENT_FAILURE,
                exit_code=None,
                evidence=evidence,
            )
        with self._active_lock:
            self._active = prepared
        try:
            prepared.release(receipt, reservation.release_nonce)
            process = prepared.wait(
                timeout=spec.timeout_seconds,
                max_output_bytes=spec.max_stdout_bytes + spec.max_stderr_bytes,
            )
        except BaseException:
            try:
                if not getattr(prepared, "terminal", False):
                    prepared.cancel()
            except BaseException:
                pass
            process = None
        finally:
            with self._active_lock:
                self._active = None
        unchanged = self._workspace_unchanged(
            workspace_manager=workspace_manager,
            repo_path=repo_path,
            dispatch=dispatch,
            checkpoint=checkpoint,
        )
        if process is None:
            return self._result(
                spec=spec,
                dispatch=dispatch,
                classification=VerificationClassification.INFRASTRUCTURE_ERROR,
                failure=FailureClassification.CONTAINMENT_FAILURE,
                exit_classification=VerificationExitClassification.CONTAINMENT_FAILURE,
                exit_code=None,
                evidence=evidence,
            )
        stdout, stderr = self._bytes(process)
        if not unchanged:
            return self._result(
                spec=spec, dispatch=dispatch,
                classification=VerificationClassification.INFRASTRUCTURE_ERROR,
                failure=FailureClassification.WORKSPACE_MUTATION_DURING_READONLY_STAGE,
                exit_classification=VerificationExitClassification.EXITED,
                exit_code=process.exit_code, stdout=stdout, stderr=stderr, evidence=evidence,
            )
        containment_ok = (
            process.containment_unit == reservation.scope_name
            and process.containment_cgroup == receipt.cgroup_path
            and process.containment_state == ContainmentState.TERMINATED.value
        )
        if not containment_ok:
            return self._result(
                spec=spec, dispatch=dispatch,
                classification=VerificationClassification.INFRASTRUCTURE_ERROR,
                failure=FailureClassification.CONTAINMENT_FAILURE,
                exit_classification=VerificationExitClassification.CONTAINMENT_FAILURE,
                exit_code=process.exit_code, stdout=stdout, stderr=stderr, evidence=evidence,
            )
        if self._cancel_requested.is_set():
            return self._result(
                spec=spec, dispatch=dispatch,
                classification=VerificationClassification.INFRASTRUCTURE_ERROR,
                failure=FailureClassification.CANCELLED,
                exit_classification=VerificationExitClassification.CANCELLED,
                exit_code=None, stdout=stdout, stderr=stderr, evidence=evidence,
            )
        if process.timed_out:
            return self._result(
                spec=spec, dispatch=dispatch,
                classification=VerificationClassification.INFRASTRUCTURE_ERROR,
                failure=FailureClassification.TIMEOUT,
                exit_classification=VerificationExitClassification.TIMEOUT,
                exit_code=None, stdout=stdout, stderr=stderr, evidence=evidence,
            )
        if (
            process.output_limit_exceeded
            or len(stdout) > spec.max_stdout_bytes
            or len(stderr) > spec.max_stderr_bytes
        ):
            return self._result(
                spec=spec, dispatch=dispatch,
                classification=VerificationClassification.INFRASTRUCTURE_ERROR,
                failure=FailureClassification.TERMINAL_INFRASTRUCTURE_FAILURE,
                exit_classification=VerificationExitClassification.OUTPUT_LIMIT,
                exit_code=process.exit_code, stdout=stdout, stderr=stderr, evidence=evidence,
            )
        if process.exit_code in spec.pass_exit_codes:
            return self._result(
                spec=spec, dispatch=dispatch,
                classification=VerificationClassification.PASS,
                failure=None,
                exit_classification=VerificationExitClassification.EXITED,
                exit_code=process.exit_code, stdout=stdout, stderr=stderr, evidence=evidence,
            )
        if process.exit_code in spec.fail_exit_codes:
            fingerprint = verification_failure_fingerprint(
                verifier_id=spec.verifier_id,
                verifier_spec_digest=spec.spec_digest,
                checkpoint_digest=dispatch.checkpoint_digest,
                exit_code=process.exit_code,
                stdout_sha256=hashlib.sha256(stdout).hexdigest(),
                stderr_sha256=hashlib.sha256(stderr).hexdigest(),
            )
            return self._result(
                spec=spec, dispatch=dispatch,
                classification=VerificationClassification.FAIL,
                failure=FailureClassification.VERIFICATION_FAILURE,
                exit_classification=VerificationExitClassification.EXITED,
                exit_code=process.exit_code, stdout=stdout, stderr=stderr,
                evidence=evidence, fingerprint=fingerprint,
            )
        return self._result(
            spec=spec, dispatch=dispatch,
            classification=VerificationClassification.INFRASTRUCTURE_ERROR,
            failure=FailureClassification.TERMINAL_INFRASTRUCTURE_FAILURE,
            exit_classification=VerificationExitClassification.EXITED,
            exit_code=process.exit_code, stdout=stdout, stderr=stderr, evidence=evidence,
        )
