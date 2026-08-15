"""Independent read-only review execution and advisory proposal validation."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from agenticos.sandbox.containment import ContainmentState
from agenticos.sandbox.models import ContainmentReservation, PreparedProcessReceipt
from agenticos.sandbox.runtime_boundary import M4AProfile
from agenticos.sandbox.worktree import WorkspaceCaptureCompleteness, WorkspaceReuseDecision

from .board import BoardSnapshot
from .canonical import CanonicalDataError, canonical_json_bytes, load_canonical_json
from .models import (
    ControllerValidationError,
    Role,
    TaskStatus,
    require_digest,
    require_enum,
    require_exact_fields,
    require_identifier,
    require_text,
    require_uint,
)
from .proposals import ProposalCompilationError, ReviewerProposal, ReviewVerdict
from .protocol import (
    AGENT_PROTOCOL_SCHEMA,
    AgentCapability,
    AgentResult,
    AgentStreamValidator,
    AgentTaskRequest,
    ContextItem,
    ContextKind,
    EventKind,
    ProtocolLimits,
    ProtocolRejection,
    ResultStatus,
)
from .synthetic import SyntheticScenario, build_synthetic_workspace_argv
from .verification import (
    FailureClassification,
    ReadonlyProcessEvidence,
    VerificationClassification,
    VerificationResult,
)

REVIEW_RESULT_SCHEMA = "AOSREVIEWRESULT/1"
MAX_REVIEW_DESCRIPTION_BYTES = 4096


class ReviewError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail[:4096]
        super().__init__(f"{code}: {self.detail}" if self.detail else code)


def _convert(exc: Exception, fallback: str = "MALFORMED_AGENT_OUTPUT") -> ReviewError:
    return ReviewError(getattr(exc, "code", fallback), getattr(exc, "detail", ""))


class ReviewClassification(str, Enum):
    PASS = "PASS"
    BLOCKING = "BLOCKING"
    INFRASTRUCTURE_ERROR = "INFRASTRUCTURE_ERROR"


@dataclass(frozen=True, slots=True)
class ReviewContext:
    task_description: str
    acceptance_criteria: tuple[str, ...]
    checkpoint_digest: str
    verification_result_digest: str

    def __post_init__(self) -> None:
        try:
            require_text("task_description", self.task_description, MAX_REVIEW_DESCRIPTION_BYTES)
            if type(self.acceptance_criteria) is not tuple or not 1 <= len(self.acceptance_criteria) <= 32:
                raise ReviewError("REVIEW_CONTEXT_LIMIT")
            for item in self.acceptance_criteria:
                require_text("acceptance_criterion", item, 1024)
            require_digest("checkpoint_digest", self.checkpoint_digest)
            require_digest("verification_result_digest", self.verification_result_digest)
        except ControllerValidationError as exc:
            raise _convert(exc, "INVALID_REVIEW_CONTEXT") from exc

    @property
    def context_digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_dict())).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "task_description": self.task_description,
            "acceptance_criteria": list(self.acceptance_criteria),
            "checkpoint_digest": self.checkpoint_digest,
            "verification_result_digest": self.verification_result_digest,
        }

    @classmethod
    def from_dict(cls, raw: object) -> "ReviewContext":
        try:
            value = require_exact_fields(raw, set(cls.__dataclass_fields__))
        except ControllerValidationError as exc:
            raise _convert(exc, "INVALID_REVIEW_CONTEXT") from exc
        if type(value["acceptance_criteria"]) is not list:
            raise ReviewError("INVALID_REVIEW_CONTEXT")
        return cls(**{**value, "acceptance_criteria": tuple(value["acceptance_criteria"])})


@dataclass(frozen=True, slots=True)
class ReviewerExecutionIdentity:
    adapter_instance_id: str
    session_id: str
    dispatch_nonce: str
    containment_unit: str

    def __post_init__(self) -> None:
        try:
            require_identifier("adapter_instance_id", self.adapter_instance_id)
            require_identifier("session_id", self.session_id)
            require_identifier("dispatch_nonce", self.dispatch_nonce)
            require_text("containment_unit", self.containment_unit, 256)
        except ControllerValidationError as exc:
            raise _convert(exc, "INVALID_REVIEWER_IDENTITY") from exc
        if len(self.dispatch_nonce) != 32 or any(char not in "0123456789abcdef" for char in self.dispatch_nonce):
            raise ReviewError("INVALID_REVIEWER_IDENTITY")
        if not self.containment_unit.endswith(".scope"):
            raise ReviewError("INVALID_REVIEWER_IDENTITY")

    def to_dict(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, raw: object) -> "ReviewerExecutionIdentity":
        try:
            return cls(**require_exact_fields(raw, set(cls.__dataclass_fields__)))
        except ControllerValidationError as exc:
            raise _convert(exc, "INVALID_REVIEWER_IDENTITY") from exc


class SyntheticReviewerAdapter:
    """Fixed deterministic adapter instance; it owns no board authority."""

    def __init__(
        self,
        adapter_instance_id: str,
        session_id: str,
        scenario: SyntheticScenario,
    ) -> None:
        if scenario not in {
            item for item in SyntheticScenario if item.value.startswith("REVIEWER_")
        }:
            raise ReviewError("INVALID_REVIEWER_SCENARIO")
        self.adapter_instance_id = adapter_instance_id
        self.session_id = session_id
        self.scenario = scenario
        ReviewerExecutionIdentity(
            adapter_instance_id, session_id, "0" * 32, "aos-task-validation.scope"
        )

    def argv(self, request: AgentTaskRequest) -> list[str]:
        return build_synthetic_workspace_argv(request, self.scenario)


def validate_reviewer_proposal(raw: object) -> ReviewerProposal:
    try:
        return ReviewerProposal.from_dict(raw)
    except (ProposalCompilationError, ControllerValidationError, TypeError, ValueError) as exc:
        raise ReviewError("MALFORMED_AGENT_OUTPUT", getattr(exc, "code", "")) from exc


def review_failure_fingerprint(checkpoint_digest: str, proposal: ReviewerProposal) -> str:
    try:
        require_digest("checkpoint_digest", checkpoint_digest)
    except ControllerValidationError as exc:
        raise _convert(exc) from exc
    if not isinstance(proposal, ReviewerProposal) or proposal.verdict is not ReviewVerdict.BLOCKING:
        raise ReviewError("INVALID_BLOCKING_PROPOSAL")
    normalized = {
        "checkpoint_digest": checkpoint_digest,
        "findings": sorted(
            (finding.to_dict() for finding in proposal.findings),
            key=lambda item: (item["code"], item["message"]),
        ),
        "repair_recommendation": proposal.repair_recommendation,
    }
    return hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()


@dataclass(frozen=True, slots=True)
class ReviewResult:
    schema: str
    project_id: str
    task_id: str
    task_generation: int
    attempt: int
    controller_epoch: int
    checkpoint_digest: str
    verification_result_digest: str
    classification: ReviewClassification
    failure_classification: FailureClassification | None
    reviewer_identity: ReviewerExecutionIdentity | None
    proposal: ReviewerProposal | None
    proposal_digest: str | None
    agent_result_digest: str | None
    process_evidence: ReadonlyProcessEvidence | None
    failure_fingerprint: str | None

    def __post_init__(self) -> None:
        if self.schema != REVIEW_RESULT_SCHEMA:
            raise ReviewError("INVALID_SCHEMA")
        try:
            for name in ("project_id", "task_id"):
                require_identifier(name, getattr(self, name))
            for name in ("task_generation", "attempt", "controller_epoch"):
                require_uint(name, getattr(self, name), minimum=1)
            for name in (
                "checkpoint_digest", "verification_result_digest", "proposal_digest",
                "agent_result_digest", "failure_fingerprint",
            ):
                require_digest(name, getattr(self, name), allow_none=name not in {"checkpoint_digest", "verification_result_digest"})
        except ControllerValidationError as exc:
            raise _convert(exc, "INVALID_REVIEW_RESULT") from exc
        if not isinstance(self.classification, ReviewClassification):
            raise ReviewError("INVALID_REVIEW_RESULT")
        if self.failure_classification is not None and not isinstance(self.failure_classification, FailureClassification):
            raise ReviewError("INVALID_REVIEW_RESULT")
        if self.classification is ReviewClassification.PASS:
            if (
                self.failure_classification is not None
                or self.failure_fingerprint is not None
                or self.proposal is None
                or self.proposal.verdict is not ReviewVerdict.PASS
                or self.reviewer_identity is None
                or self.process_evidence is None
            ):
                raise ReviewError("INVALID_REVIEW_PASS")
        elif self.classification is ReviewClassification.BLOCKING:
            if (
                self.failure_classification is not FailureClassification.REVIEW_BLOCKING_FINDING
                or self.failure_fingerprint is None
                or self.proposal is None
                or self.proposal.verdict is not ReviewVerdict.BLOCKING
                or self.reviewer_identity is None
                or self.process_evidence is None
            ):
                raise ReviewError("INVALID_BLOCKING_REVIEW")
        elif self.failure_classification in {None, FailureClassification.REVIEW_BLOCKING_FINDING} or self.failure_fingerprint is not None:
            raise ReviewError("INVALID_REVIEW_INFRASTRUCTURE_FAILURE")
        if self.proposal is None:
            if self.proposal_digest is not None:
                raise ReviewError("INVALID_PROPOSAL_DIGEST")
        elif self.proposal_digest != hashlib.sha256(canonical_json_bytes(self.proposal.to_dict())).hexdigest():
            raise ReviewError("INVALID_PROPOSAL_DIGEST")

    @property
    def result_digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_dict())).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "project_id": self.project_id,
            "task_id": self.task_id,
            "task_generation": self.task_generation,
            "attempt": self.attempt,
            "controller_epoch": self.controller_epoch,
            "checkpoint_digest": self.checkpoint_digest,
            "verification_result_digest": self.verification_result_digest,
            "classification": self.classification.value,
            "failure_classification": self.failure_classification.value if self.failure_classification else None,
            "reviewer_identity": self.reviewer_identity.to_dict() if self.reviewer_identity else None,
            "proposal": self.proposal.to_dict() if self.proposal else None,
            "proposal_digest": self.proposal_digest,
            "agent_result_digest": self.agent_result_digest,
            "process_evidence": self.process_evidence.to_dict() if self.process_evidence else None,
            "failure_fingerprint": self.failure_fingerprint,
        }

    @classmethod
    def from_dict(cls, raw: object) -> "ReviewResult":
        try:
            value = require_exact_fields(raw, set(cls.__dataclass_fields__))
            classification = require_enum(ReviewClassification, "classification", value["classification"])
            failure = None if value["failure_classification"] is None else require_enum(
                FailureClassification, "failure_classification", value["failure_classification"]
            )
        except ControllerValidationError as exc:
            raise _convert(exc, "INVALID_REVIEW_RESULT") from exc
        return cls(
            **{
                **value,
                "classification": classification,
                "failure_classification": failure,
                "reviewer_identity": None if value["reviewer_identity"] is None else ReviewerExecutionIdentity.from_dict(value["reviewer_identity"]),
                "proposal": None if value["proposal"] is None else validate_reviewer_proposal(value["proposal"]),
                "process_evidence": None if value["process_evidence"] is None else ReadonlyProcessEvidence.from_dict(value["process_evidence"]),
            }
        )


def _parse_review_output(request: AgentTaskRequest, raw: bytes) -> tuple[AgentResult, ReviewerProposal]:
    validator = AgentStreamValidator(request)
    proposal_texts: list[str] = []
    try:
        lines = raw.splitlines(keepends=True)
        if len(lines) < 2 or any(not line.endswith(b"\n") for line in lines):
            raise ProtocolRejection("MISSING_RESULT")
        for line in lines[:-1]:
            event = validator.accept(line)
            if event.kind is EventKind.PROPOSAL:
                proposal_texts.append(event.payload.text)
        value = load_canonical_json(lines[-1][:-1], max_bytes=request.limits.max_output_bytes)
        result = validator.accept_result(AgentResult.from_dict(value))
        if len(proposal_texts) != 1:
            raise ProtocolRejection("INVALID_REVIEW_PROPOSAL_COUNT")
        proposal_raw = load_canonical_json(
            proposal_texts[0].encode("utf-8"), max_bytes=request.limits.max_event_bytes
        )
        return result, validate_reviewer_proposal(proposal_raw)
    except (CanonicalDataError, ProtocolRejection, ProposalCompilationError, UnicodeError, ValueError) as exc:
        raise ReviewError("MALFORMED_AGENT_OUTPUT", getattr(exc, "code", "")) from exc


class ReviewController:
    """One explicit review stage; advisory output never applies board state."""

    def __init__(self) -> None:
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
    def build_request(
        *,
        board: BoardSnapshot,
        dispatch,
        verification_result: VerificationResult,
        checkpoint: object,
    ) -> AgentTaskRequest:
        """Construct the complete bounded reviewer request from controller state."""
        try:
            task = board.task(dispatch.task_id)
            context = ReviewContext(
                task.description,
                task.acceptance_criteria,
                checkpoint.checkpoint_digest,
                verification_result.result_digest,
            )
            limits = board.project.limits
            context_size = len(canonical_json_bytes(context.to_dict()))
            verification_size = len(
                canonical_json_bytes(verification_result.to_dict())
            )
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise ReviewError("INVALID_REVIEW_CONTEXT") from exc
        return AgentTaskRequest(
            schema=AGENT_PROTOCOL_SCHEMA,
            identity=dispatch,
            role=Role.REVIEWER,
            provider_id="synthetic-reviewer",
            model_id="deterministic-review-v1",
            workspace_mount="/workspace",
            instructions=(
                "Review only the controller-owned bounded context and read-only "
                "workspace. Return one advisory review proposal."
            ),
            acceptance_criteria=task.acceptance_criteria,
            context_manifest=(
                ContextItem(
                    ContextKind.REVIEW_FINDING,
                    "review-context",
                    context.context_digest,
                    context_size,
                ),
                ContextItem(
                    ContextKind.VERIFICATION_FINDING,
                    "verification-result",
                    verification_result.result_digest,
                    verification_size,
                ),
                ContextItem(
                    ContextKind.WORKSPACE_MANIFEST,
                    "workspace-checkpoint",
                    checkpoint.checkpoint_digest,
                    64,
                ),
            ),
            capabilities=(
                AgentCapability.READ_CONTEXT,
                AgentCapability.READ_WORKSPACE,
                AgentCapability.PROPOSE_REVIEW,
            ),
            limits=ProtocolLimits(
                max_events=limits.max_events_per_attempt,
                max_event_bytes=limits.max_event_bytes,
                max_output_bytes=limits.max_output_bytes,
                max_context_entries=limits.max_context_entries,
                max_context_bytes=limits.max_context_bytes,
                max_processes=limits.max_processes,
                max_runtime_seconds=limits.max_runtime_seconds,
            ),
        )

    @staticmethod
    def _validate_prelaunch(
        *,
        board: BoardSnapshot,
        request: AgentTaskRequest,
        verification_result: VerificationResult,
        checkpoint: object,
        builder_identity: ReviewerExecutionIdentity,
        adapter: SyntheticReviewerAdapter,
        reservation: ContainmentReservation,
    ) -> None:
        if request.role is not Role.REVIEWER:
            raise ReviewError("STALE_IDENTITY")
        identity = request.identity
        try:
            task = board.task(identity.task_id)
            valid = (
                board.project.project_id == identity.project_id,
                task.status is TaskStatus.REVIEW,
                task.generation == identity.task_generation,
                task.attempt_count == identity.attempt,
                board.project.controller_epoch == identity.controller_epoch,
                board.project.lease_epoch == task.lease_epoch == identity.lease_epoch,
                checkpoint.checkpoint_digest == identity.checkpoint_digest,
                checkpoint.task_id == identity.workspace_id,
                checkpoint.generation == identity.workspace_generation,
                checkpoint.reservation_digest == identity.reservation_id,
                verification_result.classification is VerificationClassification.PASS,
                verification_result.project_id == identity.project_id,
                verification_result.task_id == identity.task_id,
                verification_result.task_generation == identity.task_generation,
                verification_result.attempt == identity.attempt,
                verification_result.controller_epoch == identity.controller_epoch,
                verification_result.checkpoint_digest == identity.checkpoint_digest,
                reservation.project_id == identity.project_id,
                reservation.task_id == identity.task_id,
                reservation.task_generation == identity.task_generation,
                reservation.attempt == identity.attempt,
                reservation.controller_epoch == identity.controller_epoch,
                reservation.lease_epoch == identity.lease_epoch,
                reservation.dispatch_nonce == identity.dispatch_nonce,
            )
        except (AttributeError, KeyError, TypeError):
            raise ReviewError("STALE_IDENTITY") from None
        if verification_result.classification is not VerificationClassification.PASS:
            raise ReviewError("VERIFICATION_NOT_PASS")
        if checkpoint.checkpoint_digest != verification_result.checkpoint_digest:
            raise ReviewError("CHECKPOINT_MISMATCH")
        if not all(valid):
            if checkpoint.checkpoint_digest != identity.checkpoint_digest:
                raise ReviewError("CHECKPOINT_MISMATCH")
            raise ReviewError("STALE_IDENTITY")
        expected_request = ReviewController.build_request(
            board=board,
            dispatch=identity,
            verification_result=verification_result,
            checkpoint=checkpoint,
        )
        if request != expected_request:
            raise ReviewError("INVALID_REVIEW_CONTEXT")
        if (
            adapter.adapter_instance_id == builder_identity.adapter_instance_id
            or adapter.session_id == builder_identity.session_id
            or identity.dispatch_nonce == builder_identity.dispatch_nonce
            or reservation.scope_name == builder_identity.containment_unit
        ):
            raise ReviewError("REVIEWER_INDEPENDENCE_VIOLATION")

    @staticmethod
    def _workspace_unchanged(workspace_manager, repo_path, identity, checkpoint) -> bool:
        try:
            captures = [
                workspace_manager.capture_checkpoint(
                    repo_path, identity.workspace_id, identity.workspace_generation
                )
                for _ in range(2)
            ]
            values = [capture.checkpoint for capture in captures]
            return all(
                capture.decision is WorkspaceReuseDecision.REUSABLE
                and value is not None
                and value.capture_completeness is WorkspaceCaptureCompleteness.COMPLETE
                for capture, value in zip(captures, values)
            ) and values[0] == values[1] == checkpoint
        except BaseException:
            return False

    @staticmethod
    def _process_evidence(receipt: PreparedProcessReceipt) -> ReadonlyProcessEvidence:
        identity = receipt.process_identity
        return ReadonlyProcessEvidence(
            containment_unit=receipt.reservation.scope_name,
            cgroup_path=receipt.cgroup_path,
            pid=identity.pid,
            process_group_id=identity.process_group_id,  # type: ignore[arg-type]
            start_time_ticks=identity.start_time_ticks,  # type: ignore[arg-type]
            boot_id=identity.boot_id,  # type: ignore[arg-type]
            policy_digest=receipt.policy_digest,
            namespace_digest=hashlib.sha256(canonical_json_bytes(dict(receipt.namespace_ids))).hexdigest(),
            workspace_device=receipt.workspace_device,
            workspace_inode=receipt.workspace_inode,
        )

    @staticmethod
    def _result(
        *, request, verification_result, classification, failure,
        reviewer_identity=None, proposal=None, agent_result=None,
        process_evidence=None, fingerprint=None,
    ) -> ReviewResult:
        proposal_digest = None if proposal is None else hashlib.sha256(
            canonical_json_bytes(proposal.to_dict())
        ).hexdigest()
        agent_digest = None if agent_result is None else hashlib.sha256(
            canonical_json_bytes(agent_result.to_dict())
        ).hexdigest()
        return ReviewResult(
            REVIEW_RESULT_SCHEMA,
            request.identity.project_id,
            request.identity.task_id,
            request.identity.task_generation,
            request.identity.attempt,
            request.identity.controller_epoch,
            request.identity.checkpoint_digest,
            verification_result.result_digest,
            classification,
            failure,
            reviewer_identity,
            proposal,
            proposal_digest,
            agent_digest,
            process_evidence,
            fingerprint,
        )

    def review(
        self,
        *,
        board: BoardSnapshot,
        request: AgentTaskRequest,
        verification_result: VerificationResult,
        checkpoint: object,
        builder_identity: ReviewerExecutionIdentity,
        adapter: SyntheticReviewerAdapter,
        runner: object,
        reservation: ContainmentReservation,
        workspace_manager: object,
        repo_path: Path,
    ) -> ReviewResult:
        if getattr(runner, "profile", None) is not M4AProfile.INSPECT:
            raise ReviewError("READONLY_PROFILE_REQUIRED")
        self._cancel_requested.clear()
        self._validate_prelaunch(
            board=board, request=request, verification_result=verification_result,
            checkpoint=checkpoint, builder_identity=builder_identity,
            adapter=adapter, reservation=reservation,
        )
        argv = adapter.argv(request)
        try:
            prepared = runner.prepare(argv, cwd="/workspace", env={}, reservation=reservation)
        except BaseException:
            return self._result(
                request=request, verification_result=verification_result,
                classification=ReviewClassification.INFRASTRUCTURE_ERROR,
                failure=FailureClassification.CONTAINMENT_FAILURE,
            )
        receipt = getattr(prepared, "receipt", None)
        valid_receipt = isinstance(receipt, PreparedProcessReceipt) and (
            receipt.reservation == reservation
            and receipt.executable == argv[0]
            and receipt.argv == tuple(argv)
            and receipt.workspace_device == checkpoint.worktree_device
            and receipt.workspace_inode == checkpoint.worktree_inode
        )
        if not valid_receipt:
            try:
                prepared.cancel()
            except BaseException:
                pass
            return self._result(
                request=request, verification_result=verification_result,
                classification=ReviewClassification.INFRASTRUCTURE_ERROR,
                failure=FailureClassification.CONTAINMENT_FAILURE,
            )
        evidence = self._process_evidence(receipt)
        reviewer_identity = ReviewerExecutionIdentity(
            adapter.adapter_instance_id,
            adapter.session_id,
            request.identity.dispatch_nonce,
            receipt.reservation.scope_name,
        )
        with self._active_lock:
            self._active = prepared
        try:
            prepared.release(receipt, reservation.release_nonce)
            process = prepared.wait(
                timeout=request.limits.max_runtime_seconds,
                max_output_bytes=request.limits.max_output_bytes,
            )
        except BaseException:
            try:
                if not getattr(prepared, "terminal", False):
                    prepared.cancel()
            except BaseException:
                pass
            return self._result(
                request=request, verification_result=verification_result,
                classification=ReviewClassification.INFRASTRUCTURE_ERROR,
                failure=FailureClassification.CONTAINMENT_FAILURE,
                reviewer_identity=reviewer_identity, process_evidence=evidence,
            )
        finally:
            with self._active_lock:
                self._active = None
        unchanged = self._workspace_unchanged(
            workspace_manager, repo_path, request.identity, checkpoint
        )
        if not unchanged:
            return self._result(
                request=request, verification_result=verification_result,
                classification=ReviewClassification.INFRASTRUCTURE_ERROR,
                failure=FailureClassification.WORKSPACE_MUTATION_DURING_READONLY_STAGE,
                reviewer_identity=reviewer_identity, process_evidence=evidence,
            )
        if self._cancel_requested.is_set():
            return self._result(
                request=request,
                verification_result=verification_result,
                classification=ReviewClassification.INFRASTRUCTURE_ERROR,
                failure=FailureClassification.CANCELLED,
                reviewer_identity=reviewer_identity,
                process_evidence=evidence,
            )
        if (
            process.timed_out
            or process.output_limit_exceeded
            or process.exit_code != 0
            or process.containment_unit != reservation.scope_name
            or process.containment_cgroup != receipt.cgroup_path
            or process.containment_state != ContainmentState.TERMINATED.value
        ):
            failure = (
                FailureClassification.TIMEOUT
                if process.timed_out
                else FailureClassification.TERMINAL_INFRASTRUCTURE_FAILURE
            )
            return self._result(
                request=request, verification_result=verification_result,
                classification=ReviewClassification.INFRASTRUCTURE_ERROR,
                failure=failure, reviewer_identity=reviewer_identity,
                process_evidence=evidence,
            )
        try:
            agent_result, proposal = _parse_review_output(request, process.stdout_bytes)
        except ReviewError:
            return self._result(
                request=request, verification_result=verification_result,
                classification=ReviewClassification.INFRASTRUCTURE_ERROR,
                failure=FailureClassification.MALFORMED_AGENT_OUTPUT,
                reviewer_identity=reviewer_identity, process_evidence=evidence,
            )
        if agent_result.status is not ResultStatus.SUCCEEDED:
            return self._result(
                request=request,
                verification_result=verification_result,
                classification=ReviewClassification.INFRASTRUCTURE_ERROR,
                failure=FailureClassification.TERMINAL_INFRASTRUCTURE_FAILURE,
                reviewer_identity=reviewer_identity,
                agent_result=agent_result,
                process_evidence=evidence,
            )
        if proposal.verdict is ReviewVerdict.PASS:
            return self._result(
                request=request, verification_result=verification_result,
                classification=ReviewClassification.PASS, failure=None,
                reviewer_identity=reviewer_identity, proposal=proposal,
                agent_result=agent_result, process_evidence=evidence,
            )
        fingerprint = review_failure_fingerprint(
            request.identity.checkpoint_digest, proposal
        )
        return self._result(
            request=request, verification_result=verification_result,
            classification=ReviewClassification.BLOCKING,
            failure=FailureClassification.REVIEW_BLOCKING_FINDING,
            reviewer_identity=reviewer_identity, proposal=proposal,
            agent_result=agent_result, process_evidence=evidence,
            fingerprint=fingerprint,
        )
