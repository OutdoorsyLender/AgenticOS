"""Protocol types and state machine core for the F1 Kimi Planner qualification.

Slice 1 of the reviewed design
``docs/superpowers/specs/2026-08-16-f1-kimi-combined-planner-qualification-design.md``.
This module is pure, deterministic, standard-library-only, credential-free, and
network-free: no sockets, no subprocess, no I/O, no clocks, no randomness, and
no mutable module-level state. It never imports or invokes the mutating
``compile_planner_proposal``; the pure compile-preview interface is a typed
boundary deferred to a later slice.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from enum import Enum
from types import MappingProxyType
from typing import Final

from agenticos.orchestration.canonical import canonical_json_bytes


class KimiPlannerTypeError(ValueError):
    """One stable rejection code for planner-qualification type drift."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


class PlannerEgressState(str, Enum):
    """Normative network egress state machine states."""

    START = "START"
    AUTH_WINDOW = "AUTH_WINDOW"
    AUTH_DRAINING = "AUTH_DRAINING"
    MODEL_ONCE = "MODEL_ONCE"
    CLOSED = "CLOSED"


class AuthRefreshState(str, Enum):
    """Content-blind credential refresh attestation states."""

    NOT_REQUIRED = "NOT_REQUIRED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED_AND_PERSISTED = "COMPLETED_AND_PERSISTED"
    FAILED = "FAILED"
    INTERRUPTED = "INTERRUPTED"
    AMBIGUOUS = "AMBIGUOUS"


class PlannerFailureCode(str, Enum):
    """Failure classification taxonomy: exactly these 15 codes.

    No HTTP-status-derived class may ever be added: the live opaque mediator
    cannot classify encrypted HTTP status, and no code may parse free-form
    error text to recover status authority.
    """

    LOCAL_AUTH_REJECTED = "LOCAL_AUTH_REJECTED"
    AUTH_REFRESH_FAILED = "AUTH_REFRESH_FAILED"
    AUTH_EGRESS_POLICY_FAILED = "AUTH_EGRESS_POLICY_FAILED"
    MODEL_EGRESS_POLICY_FAILED = "MODEL_EGRESS_POLICY_FAILED"
    MODEL_TUNNEL_ALREADY_CONSUMED = "MODEL_TUNNEL_ALREADY_CONSUMED"
    TLS_OR_TUNNEL_FAILED = "TLS_OR_TUNNEL_FAILED"
    SNI_MISMATCH = "SNI_MISMATCH"
    DNS_POLICY_FAILED = "DNS_POLICY_FAILED"
    ACP_PROTOCOL_FAILED = "ACP_PROTOCOL_FAILED"
    PROVIDER_INFERENCE_FAILED = "PROVIDER_INFERENCE_FAILED"
    MODEL_OUTPUT_INVALID = "MODEL_OUTPUT_INVALID"
    AOSPLAN_INVALID = "AOSPLAN_INVALID"
    TIMEOUT = "TIMEOUT"
    CLEANUP_FAILED = "CLEANUP_FAILED"
    EVIDENCE_FAILED = "EVIDENCE_FAILED"


class EvidenceProvenance(str, Enum):
    """Evidence provenance values, including the two enforcement provenances
    and the literal opaque-TLS non-observation marker."""

    DIRECT_CONTROLLER_OBSERVATION = "DIRECT_CONTROLLER_OBSERVATION"
    DIRECT_MEDIATOR_OBSERVATION = "DIRECT_MEDIATOR_OBSERVATION"
    DIRECT_ACP_OBSERVATION = "DIRECT_ACP_OBSERVATION"
    SOURCE_BOUND_CONFIGURATION = "SOURCE_BOUND_CONFIGURATION"
    SYNTHETIC_QUALIFICATION_ONLY = "SYNTHETIC_QUALIFICATION_ONLY"
    INFERRED_FROM_SUCCESSFUL_PLANNER_RESULT = "INFERRED_FROM_SUCCESSFUL_PLANNER_RESULT"
    DIRECT_CONTROLLER_ENFORCEMENT = "DIRECT_CONTROLLER_ENFORCEMENT"
    DIRECT_MEDIATOR_ENFORCEMENT = "DIRECT_MEDIATOR_ENFORCEMENT"
    NOT_DIRECTLY_OBSERVABLE_UNDER_OPAQUE_TLS = "NOT_DIRECTLY_OBSERVABLE_UNDER_OPAQUE_TLS"


# Literal serialized value for the two HTTP request count fields. Any numeric
# value for these fields must be rejected: same-origin HTTP request
# multiplication is never a live observation under opaque end-to-end TLS.
OPAQUE_TLS_HTTP_COUNT_MARKER: Final = "NOT_DIRECTLY_OBSERVABLE_UNDER_OPAQUE_TLS"

TLS_TRANSPORT_POLICY_LITERAL: Final = "END_TO_END_ORIGIN_TLS"

COMPOSED_TARGET_STATUS: Final = "PENDING_SYNTHETIC_PROOF_AND_OWNER_RISK_ACCEPTANCE"

AUTH_HOST: Final = "auth.kimi.com"
MODEL_HOST: Final = "api.kimi.com"
EGRESS_PORT: Final = 443

# Historical immutability: the Level-1 qualification result can never change.
HISTORICAL_F1_KIMI_LEVEL1_RESULT: Final = "BLOCKED"
HISTORICAL_F1_KIMI_LEVEL1_REASON: Final = "AUTH_METHOD_SHAPE"
HISTORICAL_F1_KIMI_LEVEL1_REAL_ATTEMPT_COUNT: Final = 1
REAL_ATTEMPT_COUNT: Final = 1

ATTEMPT_SCHEMA: Final = "AOS_KIMI_PLANNER_QUALIFICATION_ATTEMPT/1"
RESULT_SCHEMA: Final = "AOS_KIMI_PLANNER_QUALIFICATION_RESULT/1"
PROMPT_SCHEMA: Final = "AOS_KIMI_PLANNER_PROMPT/1"

PROMPT_MAX_CANONICAL_BYTES: Final = 4 * 1024

MAX_AUTH_TUNNEL_ADMISSIONS: Final = 3
MAX_MODEL_ALLOWANCE_CLAIMS: Final = 1
MAX_MODEL_TUNNEL_ADMISSIONS: Final = 1
MAX_ACP_REAL_PROMPTS: Final = 1
MAX_PLANNER_PROPOSALS: Final = 1
MAX_ACTIVE_AUTH_TUNNELS: Final = 1


@dataclass(frozen=True, slots=True)
class AccountingBound:
    """One normative accounting metric with its provenance.

    ``enforced_bound`` is the live fail-closed bound, or ``None`` when the
    metric is a source-only bound that is never a live numeric observation.
    ``composed_target`` is a conditional target only; while
    ``composed_target_status`` is ``PENDING_SYNTHETIC_PROOF_AND_OWNER_RISK_ACCEPTANCE``
    the target is unearned and must never be represented as a fact.
    """

    name: str
    enforced_bound: int | None
    provenance: EvidenceProvenance
    source_only_bound: int | None = None
    composed_target: int | None = None
    composed_target_status: str | None = None

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name:
            raise KimiPlannerTypeError("INVALID_BOUND_NAME")
        if type(self.provenance) is not EvidenceProvenance:
            raise KimiPlannerTypeError("INVALID_BOUND_PROVENANCE", self.name)
        for value in (self.enforced_bound, self.source_only_bound, self.composed_target):
            if value is not None and (type(value) is not int or value < 0):
                raise KimiPlannerTypeError("INVALID_BOUND_VALUE", self.name)


ACCOUNTING_BOUNDS: Final = MappingProxyType(
    {
        bound.name: bound
        for bound in (
            AccountingBound(
                "ACP_REAL_PROMPT_COUNT",
                1,
                EvidenceProvenance.DIRECT_CONTROLLER_ENFORCEMENT,
            ),
            AccountingBound(
                "MODEL_ALLOWANCE_CLAIM_COUNT",
                1,
                EvidenceProvenance.DIRECT_MEDIATOR_ENFORCEMENT,
            ),
            AccountingBound(
                "MODEL_TUNNEL_ADMISSION_COUNT",
                1,
                EvidenceProvenance.DIRECT_MEDIATOR_ENFORCEMENT,
            ),
            AccountingBound(
                "AUTH_TUNNEL_ADMISSION_COUNT",
                3,
                EvidenceProvenance.DIRECT_MEDIATOR_ENFORCEMENT,
            ),
            AccountingBound(
                "MODEL_HTTP_REQUEST_COUNT",
                None,
                EvidenceProvenance.SOURCE_BOUND_CONFIGURATION,
                source_only_bound=42,
                composed_target=21,
                composed_target_status=COMPOSED_TARGET_STATUS,
            ),
            AccountingBound(
                "AUTH_HTTP_REQUEST_COUNT",
                None,
                EvidenceProvenance.SOURCE_BOUND_CONFIGURATION,
                source_only_bound=126,
                composed_target=63,
                composed_target_status=COMPOSED_TARGET_STATUS,
            ),
            AccountingBound(
                "PLANNER_PROPOSAL_COUNT",
                1,
                EvidenceProvenance.DIRECT_CONTROLLER_ENFORCEMENT,
            ),
            AccountingBound(
                "SDK_RETRY_CONFIGURATION",
                0,
                EvidenceProvenance.SOURCE_BOUND_CONFIGURATION,
            ),
            AccountingBound(
                "OAUTH_TOP_LEVEL_FETCH_CALL_BOUND",
                None,
                EvidenceProvenance.SOURCE_BOUND_CONFIGURATION,
                source_only_bound=6,
                composed_target=3,
                composed_target_status=COMPOSED_TARGET_STATUS,
            ),
            AccountingBound(
                "LOOP_ATTEMPT_COUNT",
                1,
                EvidenceProvenance.DIRECT_CONTROLLER_OBSERVATION,
            ),
            AccountingBound(
                "LOOP_STEP_COUNT",
                1,
                EvidenceProvenance.DIRECT_CONTROLLER_OBSERVATION,
            ),
        )
    }
)


def validate_bounded_count(value: object, *, name: str, bound: int) -> int:
    """Strictly validate one bounded counter.

    ``bool`` is rejected explicitly (it is an ``int`` subclass), as are
    negative values, non-``int`` types, and values over ``bound``.
    """

    if type(value) is not int:
        raise KimiPlannerTypeError("INVALID_COUNT_TYPE", name)
    if value < 0:
        raise KimiPlannerTypeError("NEGATIVE_COUNT", name)
    if value > bound:
        raise KimiPlannerTypeError("COUNT_OVER_BOUND", name)
    return value


def _require_str(value: object, name: str) -> str:
    if type(value) is not str or not value:
        raise KimiPlannerTypeError("INVALID_STRING_FIELD", name)
    return value


def _require_bool(value: object, name: str) -> bool:
    if type(value) is not bool:
        raise KimiPlannerTypeError("INVALID_BOOL_FIELD", name)
    return value


def _require_hex(value: object, name: str, length: int) -> str:
    text = _require_str(value, name)
    if len(text) != length or any(char not in "0123456789abcdef" for char in text):
        raise KimiPlannerTypeError("INVALID_HEX_FIELD", name)
    return text


def _require_enum(enum_type: type[Enum], value: object, name: str) -> Enum:
    if type(value) is enum_type:
        return value
    if type(value) is str:
        try:
            return enum_type(value)
        except ValueError as exc:
            raise KimiPlannerTypeError("UNSUPPORTED_ENUM_VALUE", name) from exc
    raise KimiPlannerTypeError("INVALID_ENUM_FIELD", name)


def _require_fields(raw: object, expected: set[str], name: str) -> dict[str, object]:
    if type(raw) is not dict or any(type(key) is not str for key in raw):
        raise KimiPlannerTypeError("INVALID_RECORD", name)
    keys = set(raw)
    if keys - expected:
        raise KimiPlannerTypeError("UNKNOWN_FIELD", name)
    if expected - keys:
        raise KimiPlannerTypeError("MISSING_FIELD", name)
    return raw


def kimi_planner_prompt() -> dict[str, object]:
    """Return the canonical qualification prompt as a fresh object.

    The prompt is frozen exactly as defined in the design: public, synthetic,
    and never sent anywhere by this slice. It is constructed inside this
    accessor so no mutable module-level prompt state exists.
    """

    return {
        "schema": PROMPT_SCHEMA,
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


def kimi_planner_prompt_canonical_bytes() -> bytes:
    """Return the deterministic canonical serialization of the prompt."""

    return canonical_json_bytes(
        kimi_planner_prompt(), max_bytes=PROMPT_MAX_CANONICAL_BYTES - 1
    )


def kimi_planner_prompt_sha256() -> str:
    """Return the SHA-256 digest of the canonical prompt bytes."""

    return hashlib.sha256(kimi_planner_prompt_canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class TransitionResult:
    """Outcome of one egress state machine event.

    ``machine`` is the resulting machine (unchanged when an event is rejected
    in ``CLOSED``; fail-closed to ``CLOSED`` on any invalid event).
    """

    accepted: bool
    machine: PlannerEgressMachine
    failure_code: PlannerFailureCode | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            raise KimiPlannerTypeError("INVALID_TRANSITION_RESULT")
        if type(self.machine) is not PlannerEgressMachine:
            raise KimiPlannerTypeError("INVALID_TRANSITION_RESULT")
        if self.failure_code is not None and type(self.failure_code) is not PlannerFailureCode:
            raise KimiPlannerTypeError("INVALID_TRANSITION_RESULT")
        if type(self.detail) is not str:
            raise KimiPlannerTypeError("INVALID_TRANSITION_RESULT")


@dataclass(frozen=True, slots=True)
class PlannerEgressMachine:
    """Pure, deterministic egress-authority state machine.

    Every event method returns a :class:`TransitionResult`; the machine itself
    is never mutated. Any invalid or impossible transition fails closed: the
    event is denied and the resulting machine is terminally ``CLOSED`` with a
    typed failure code. No transition ever restores consumed authority.
    """

    state: PlannerEgressState = PlannerEgressState.START
    active_auth_tunnels: int = 0
    auth_tunnel_admission_count: int = 0
    model_allowance_claimed: bool = False
    model_tunnel_admission_count: int = 0
    auth_admission_revoked: bool = False
    acp_real_prompt_count: int = 0
    planner_proposal_count: int = 0
    terminal_failure_code: PlannerFailureCode | None = None

    def __post_init__(self) -> None:
        if type(self.state) is not PlannerEgressState:
            raise KimiPlannerTypeError("INVALID_MACHINE_STATE")
        validate_bounded_count(
            self.active_auth_tunnels,
            name="active_auth_tunnels",
            bound=MAX_ACTIVE_AUTH_TUNNELS,
        )
        validate_bounded_count(
            self.auth_tunnel_admission_count,
            name="auth_tunnel_admission_count",
            bound=MAX_AUTH_TUNNEL_ADMISSIONS,
        )
        validate_bounded_count(
            self.model_tunnel_admission_count,
            name="model_tunnel_admission_count",
            bound=MAX_MODEL_TUNNEL_ADMISSIONS,
        )
        validate_bounded_count(
            self.acp_real_prompt_count,
            name="acp_real_prompt_count",
            bound=MAX_ACP_REAL_PROMPTS,
        )
        validate_bounded_count(
            self.planner_proposal_count,
            name="planner_proposal_count",
            bound=MAX_PLANNER_PROPOSALS,
        )
        for name in ("model_allowance_claimed", "auth_admission_revoked"):
            if type(getattr(self, name)) is not bool:
                raise KimiPlannerTypeError("INVALID_MACHINE_FLAG", name)
        if self.terminal_failure_code is not None and (
            type(self.terminal_failure_code) is not PlannerFailureCode
        ):
            raise KimiPlannerTypeError("INVALID_TERMINAL_FAILURE_CODE")
        if self.auth_tunnel_admission_count < self.active_auth_tunnels:
            raise KimiPlannerTypeError("INCONSISTENT_MACHINE")
        if self.model_tunnel_admission_count == 1 and not self.model_allowance_claimed:
            raise KimiPlannerTypeError("INCONSISTENT_MACHINE")
        if self.state in (
            PlannerEgressState.AUTH_DRAINING,
            PlannerEgressState.MODEL_ONCE,
        ) and not self.model_allowance_claimed:
            raise KimiPlannerTypeError("INCONSISTENT_MACHINE")
        if (
            self.state is PlannerEgressState.MODEL_ONCE
            and self.model_tunnel_admission_count != 1
        ):
            raise KimiPlannerTypeError("INCONSISTENT_MACHINE")
        if self.planner_proposal_count == 1 and self.acp_real_prompt_count == 0:
            raise KimiPlannerTypeError("INCONSISTENT_MACHINE")
        if self.active_auth_tunnels and self.state not in (
            PlannerEgressState.AUTH_WINDOW,
            PlannerEgressState.AUTH_DRAINING,
        ):
            raise KimiPlannerTypeError("INCONSISTENT_MACHINE")
        if self.state is PlannerEgressState.CLOSED and self.active_auth_tunnels:
            raise KimiPlannerTypeError("INCONSISTENT_MACHINE")

    def _closed(self, code: PlannerFailureCode, detail: str) -> TransitionResult:
        if self.state is PlannerEgressState.CLOSED:
            return TransitionResult(
                accepted=False,
                machine=self,
                failure_code=self.terminal_failure_code,
                detail=f"CLOSED absorbs event; no authority restored: {detail}",
            )
        machine = replace(
            self,
            state=PlannerEgressState.CLOSED,
            active_auth_tunnels=0,
            auth_admission_revoked=True,
            terminal_failure_code=code,
        )
        return TransitionResult(accepted=False, machine=machine, failure_code=code, detail=detail)

    def _accepted(self, **changes: object) -> TransitionResult:
        return TransitionResult(accepted=True, machine=replace(self, **changes))

    def begin_auth_window(self) -> TransitionResult:
        """Open the auth window; only valid from ``START``."""

        if self.state is not PlannerEgressState.START:
            return self._closed(
                PlannerFailureCode.AUTH_EGRESS_POLICY_FAILED,
                "begin_auth_window is only valid from START",
            )
        return self._accepted(state=PlannerEgressState.AUTH_WINDOW)

    def admit_auth_tunnel(self) -> TransitionResult:
        """Admit one ``auth.kimi.com:443`` tunnel inside the auth window."""

        if self.state is not PlannerEgressState.AUTH_WINDOW or self.auth_admission_revoked:
            return self._closed(
                PlannerFailureCode.AUTH_EGRESS_POLICY_FAILED,
                "auth admission is not open",
            )
        if self.active_auth_tunnels >= MAX_ACTIVE_AUTH_TUNNELS:
            return self._closed(
                PlannerFailureCode.AUTH_EGRESS_POLICY_FAILED,
                "an auth tunnel is already active",
            )
        if self.auth_tunnel_admission_count >= MAX_AUTH_TUNNEL_ADMISSIONS:
            return self._closed(
                PlannerFailureCode.AUTH_EGRESS_POLICY_FAILED,
                "AUTH_TUNNEL_ADMISSION_COUNT bound exceeded",
            )
        return self._accepted(
            active_auth_tunnels=1,
            auth_tunnel_admission_count=self.auth_tunnel_admission_count + 1,
        )

    def auth_tunnel_closed(self) -> TransitionResult:
        """Record the end of the active auth tunnel (including drain interrupt)."""

        if self.state not in (
            PlannerEgressState.AUTH_WINDOW,
            PlannerEgressState.AUTH_DRAINING,
        ) or self.active_auth_tunnels != 1:
            return self._closed(
                PlannerFailureCode.AUTH_EGRESS_POLICY_FAILED,
                "no active auth tunnel to close",
            )
        return self._accepted(active_auth_tunnels=0)

    def request_model_tunnel(self) -> TransitionResult:
        """Handle the first model CONNECT: atomically claim the sole model
        allowance exactly once, permanently revoke auth admission, and enter
        ``AUTH_DRAINING``. The claim is spent even if a later step fails."""

        if self.state is PlannerEgressState.CLOSED:
            return self._closed(
                PlannerFailureCode.MODEL_EGRESS_POLICY_FAILED,
                "egress is permanently closed",
            )
        if self.model_allowance_claimed:
            return self._closed(
                PlannerFailureCode.MODEL_TUNNEL_ALREADY_CONSUMED,
                "the sole model allowance was already claimed",
            )
        if self.state is not PlannerEgressState.AUTH_WINDOW:
            return self._closed(
                PlannerFailureCode.MODEL_EGRESS_POLICY_FAILED,
                "model CONNECT is only valid from AUTH_WINDOW",
            )
        return self._accepted(
            state=PlannerEgressState.AUTH_DRAINING,
            model_allowance_claimed=True,
            auth_admission_revoked=True,
        )

    def complete_auth_drain(self, auth_refresh_state: AuthRefreshState | str) -> TransitionResult:
        """Complete the atomic model transition after auth drain.

        Prerequisites: the active-auth registry is empty and the content-blind
        refresh attestation is ``NOT_REQUIRED`` or ``COMPLETED_AND_PERSISTED``.
        On any failure the allowance stays spent, auth stays revoked, the model
        tunnel is never admitted, and the machine fails closed to ``CLOSED``.
        """

        try:
            refresh = _require_enum(AuthRefreshState, auth_refresh_state, "auth_refresh_state")
        except KimiPlannerTypeError:
            return self._closed(
                PlannerFailureCode.AUTH_REFRESH_FAILED,
                "unrecognized auth refresh state",
            )
        if self.state is not PlannerEgressState.AUTH_DRAINING:
            return self._closed(
                PlannerFailureCode.MODEL_EGRESS_POLICY_FAILED,
                "drain completion is only valid from AUTH_DRAINING",
            )
        if self.active_auth_tunnels != 0:
            return self._closed(
                PlannerFailureCode.AUTH_EGRESS_POLICY_FAILED,
                "active-auth registry is not empty",
            )
        if refresh not in (
            AuthRefreshState.NOT_REQUIRED,
            AuthRefreshState.COMPLETED_AND_PERSISTED,
        ):
            return self._closed(
                PlannerFailureCode.AUTH_REFRESH_FAILED,
                f"refresh state {refresh.value} blocks model admission",
            )
        return self._accepted(
            state=PlannerEgressState.MODEL_ONCE,
            model_tunnel_admission_count=1,
        )

    def admit_prompt(self) -> TransitionResult:
        """Admit the single real ACP prompt; requires the admitted model tunnel."""

        if self.state is not PlannerEgressState.MODEL_ONCE:
            return self._closed(
                PlannerFailureCode.ACP_PROTOCOL_FAILED,
                "prompt admission requires MODEL_ONCE",
            )
        if self.acp_real_prompt_count >= MAX_ACP_REAL_PROMPTS:
            return self._closed(
                PlannerFailureCode.ACP_PROTOCOL_FAILED,
                "ACP_REAL_PROMPT_COUNT bound exceeded",
            )
        return self._accepted(acp_real_prompt_count=1)

    def accept_proposal(self) -> TransitionResult:
        """Accept the single bounded planner proposal; requires an admitted prompt."""

        if self.state is not PlannerEgressState.MODEL_ONCE or self.acp_real_prompt_count != 1:
            return self._closed(
                PlannerFailureCode.ACP_PROTOCOL_FAILED,
                "proposal acceptance requires an admitted prompt in MODEL_ONCE",
            )
        if self.planner_proposal_count >= MAX_PLANNER_PROPOSALS:
            return self._closed(
                PlannerFailureCode.ACP_PROTOCOL_FAILED,
                "PLANNER_PROPOSAL_COUNT bound exceeded",
            )
        return self._accepted(planner_proposal_count=1)

    def model_tunnel_terminated(self) -> TransitionResult:
        """Any termination of the model tunnel transitions to ``CLOSED``."""

        if self.state is not PlannerEgressState.MODEL_ONCE:
            return self._closed(
                PlannerFailureCode.MODEL_EGRESS_POLICY_FAILED,
                "no admitted model tunnel to terminate",
            )
        machine = replace(self, state=PlannerEgressState.CLOSED)
        return TransitionResult(accepted=True, machine=machine, detail="model tunnel terminated")

    def fail(self, code: PlannerFailureCode | str) -> TransitionResult:
        """Explicitly fail closed with a typed failure code from any open state."""

        try:
            failure = _require_enum(PlannerFailureCode, code, "code")
        except KimiPlannerTypeError:
            return self._closed(
                PlannerFailureCode.EVIDENCE_FAILED,
                "unrecognized failure code",
            )
        if self.state is PlannerEgressState.CLOSED:
            return self._closed(failure, "already closed")
        machine = replace(
            self,
            state=PlannerEgressState.CLOSED,
            active_auth_tunnels=0,
            auth_admission_revoked=True,
            terminal_failure_code=failure,
        )
        return TransitionResult(
            accepted=True, machine=machine, failure_code=failure, detail="explicit fail closed"
        )


_ATTEMPT_FIELDS: Final = {
    "schema",
    "planner_attempt_number",
    "implementation_commit",
    "authorization_digest",
    "kimi_version",
    "kimi_source_commit",
    "kimi_executable_sha256",
    "kimi_namespace_launcher_sha256",
    "config_digest",
    "profile_digest",
    "mediator_policy_digest",
    "prompt_digest",
    "historical_level1_result",
    "historical_reason",
    "historical_real_attempt_count",
    "claim_timestamp",
}


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    """Immutable ``AOS_KIMI_PLANNER_QUALIFICATION_ATTEMPT/1`` record."""

    planner_attempt_number: int
    implementation_commit: str
    authorization_digest: str
    kimi_version: str
    kimi_source_commit: str
    kimi_executable_sha256: str
    kimi_namespace_launcher_sha256: str
    config_digest: str
    profile_digest: str
    mediator_policy_digest: str
    prompt_digest: str
    historical_level1_result: str
    historical_reason: str
    historical_real_attempt_count: int
    claim_timestamp: str

    def __post_init__(self) -> None:
        if type(self.planner_attempt_number) is not int or self.planner_attempt_number < 0:
            raise KimiPlannerTypeError("INVALID_COUNT_TYPE", "planner_attempt_number")
        _require_hex(self.implementation_commit, "implementation_commit", 40)
        _require_hex(self.authorization_digest, "authorization_digest", 64)
        _require_str(self.kimi_version, "kimi_version")
        _require_hex(self.kimi_source_commit, "kimi_source_commit", 40)
        _require_hex(self.kimi_executable_sha256, "kimi_executable_sha256", 64)
        _require_hex(
            self.kimi_namespace_launcher_sha256, "kimi_namespace_launcher_sha256", 64
        )
        for name in ("config_digest", "profile_digest", "mediator_policy_digest", "prompt_digest"):
            _require_hex(getattr(self, name), name, 64)
        if self.historical_level1_result != HISTORICAL_F1_KIMI_LEVEL1_RESULT:
            raise KimiPlannerTypeError("HISTORICAL_RESULT_DRIFT")
        if self.historical_reason != HISTORICAL_F1_KIMI_LEVEL1_REASON:
            raise KimiPlannerTypeError("HISTORICAL_REASON_DRIFT")
        if (
            type(self.historical_real_attempt_count) is not int
            or self.historical_real_attempt_count != HISTORICAL_F1_KIMI_LEVEL1_REAL_ATTEMPT_COUNT
        ):
            raise KimiPlannerTypeError("HISTORICAL_COUNT_DRIFT")
        _require_str(self.claim_timestamp, "claim_timestamp")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": ATTEMPT_SCHEMA,
            "planner_attempt_number": self.planner_attempt_number,
            "implementation_commit": self.implementation_commit,
            "authorization_digest": self.authorization_digest,
            "kimi_version": self.kimi_version,
            "kimi_source_commit": self.kimi_source_commit,
            "kimi_executable_sha256": self.kimi_executable_sha256,
            "kimi_namespace_launcher_sha256": self.kimi_namespace_launcher_sha256,
            "config_digest": self.config_digest,
            "profile_digest": self.profile_digest,
            "mediator_policy_digest": self.mediator_policy_digest,
            "prompt_digest": self.prompt_digest,
            "historical_level1_result": self.historical_level1_result,
            "historical_reason": self.historical_reason,
            "historical_real_attempt_count": self.historical_real_attempt_count,
            "claim_timestamp": self.claim_timestamp,
        }

    @classmethod
    def from_dict(cls, raw: object) -> AttemptRecord:
        data = _require_fields(raw, _ATTEMPT_FIELDS, "attempt")
        if data["schema"] != ATTEMPT_SCHEMA:
            raise KimiPlannerTypeError("WRONG_SCHEMA", "attempt")
        return cls(
            planner_attempt_number=data["planner_attempt_number"],
            implementation_commit=data["implementation_commit"],
            authorization_digest=data["authorization_digest"],
            kimi_version=data["kimi_version"],
            kimi_source_commit=data["kimi_source_commit"],
            kimi_executable_sha256=data["kimi_executable_sha256"],
            kimi_namespace_launcher_sha256=data["kimi_namespace_launcher_sha256"],
            config_digest=data["config_digest"],
            profile_digest=data["profile_digest"],
            mediator_policy_digest=data["mediator_policy_digest"],
            prompt_digest=data["prompt_digest"],
            historical_level1_result=data["historical_level1_result"],
            historical_reason=data["historical_reason"],
            historical_real_attempt_count=data["historical_real_attempt_count"],
            claim_timestamp=data["claim_timestamp"],
        )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


RESULT_FIELD_PROVENANCE: Final = MappingProxyType(
    {
        "qualification_state": (EvidenceProvenance.DIRECT_CONTROLLER_OBSERVATION,),
        "primary_failure_code": (EvidenceProvenance.DIRECT_CONTROLLER_OBSERVATION,),
        "local_credential_recognized": (EvidenceProvenance.DIRECT_ACP_OBSERVATION,),
        "credential_refresh_state": (
            EvidenceProvenance.DIRECT_CONTROLLER_OBSERVATION,
            EvidenceProvenance.DIRECT_MEDIATOR_OBSERVATION,
            EvidenceProvenance.SOURCE_BOUND_CONFIGURATION,
        ),
        "acp_real_prompt_count": (EvidenceProvenance.DIRECT_CONTROLLER_OBSERVATION,),
        "planner_proposal_count": (EvidenceProvenance.DIRECT_CONTROLLER_OBSERVATION,),
        "aosplan_validated": (EvidenceProvenance.DIRECT_CONTROLLER_OBSERVATION,),
        "model_allowance_claim_count": (EvidenceProvenance.DIRECT_MEDIATOR_OBSERVATION,),
        "model_tunnel_admission_count": (EvidenceProvenance.DIRECT_MEDIATOR_OBSERVATION,),
        "auth_tunnel_admission_count": (EvidenceProvenance.DIRECT_MEDIATOR_OBSERVATION,),
        "model_http_request_count": (EvidenceProvenance.SOURCE_BOUND_CONFIGURATION,),
        "auth_http_request_count": (EvidenceProvenance.SOURCE_BOUND_CONFIGURATION,),
        "sdk_retry_configuration": (EvidenceProvenance.SOURCE_BOUND_CONFIGURATION,),
        "loop_attempt_limit": (EvidenceProvenance.SOURCE_BOUND_CONFIGURATION,),
        "loop_step_limit": (EvidenceProvenance.SOURCE_BOUND_CONFIGURATION,),
        "model_host": (EvidenceProvenance.SOURCE_BOUND_CONFIGURATION,),
        "auth_host": (EvidenceProvenance.SOURCE_BOUND_CONFIGURATION,),
        "model_base_url": (EvidenceProvenance.SOURCE_BOUND_CONFIGURATION,),
        "wire_model": (EvidenceProvenance.SOURCE_BOUND_CONFIGURATION,),
        "oauth_storage_path": (EvidenceProvenance.SOURCE_BOUND_CONFIGURATION,),
        "tls_transport_policy": (
            EvidenceProvenance.SOURCE_BOUND_CONFIGURATION,
            EvidenceProvenance.DIRECT_MEDIATOR_OBSERVATION,
        ),
        "server_auth_accepted_inferred_from_successful_model_turn": (
            EvidenceProvenance.INFERRED_FROM_SUCCESSFUL_PLANNER_RESULT,
        ),
        "prompt_byte_count": (EvidenceProvenance.DIRECT_CONTROLLER_OBSERVATION,),
        "prompt_sha256": (EvidenceProvenance.DIRECT_CONTROLLER_OBSERVATION,),
        "output_byte_count": (EvidenceProvenance.DIRECT_CONTROLLER_OBSERVATION,),
        "output_sha256": (EvidenceProvenance.DIRECT_CONTROLLER_OBSERVATION,),
        "acp_terminal_state": (EvidenceProvenance.DIRECT_ACP_OBSERVATION,),
        "network_terminal_state": (EvidenceProvenance.DIRECT_MEDIATOR_OBSERVATION,),
        "cleanup_completed": (EvidenceProvenance.DIRECT_CONTROLLER_OBSERVATION,),
        "residue_count": (EvidenceProvenance.DIRECT_CONTROLLER_OBSERVATION,),
    }
)

_RESULT_FIELDS: Final = set(RESULT_FIELD_PROVENANCE) | {"schema"}


@dataclass(frozen=True, slots=True)
class ResultRecord:
    """Immutable ``AOS_KIMI_PLANNER_QUALIFICATION_RESULT/1`` record.

    Per-field provenance is fixed by :data:`RESULT_FIELD_PROVENANCE`. The two
    HTTP request count fields serialize only as the literal
    ``NOT_DIRECTLY_OBSERVABLE_UNDER_OPAQUE_TLS``; numeric values are rejected.
    No TLS-version, HTTP-status, or direct server-auth fields exist.
    """

    qualification_state: str
    primary_failure_code: PlannerFailureCode | None
    local_credential_recognized: bool
    credential_refresh_state: AuthRefreshState
    acp_real_prompt_count: int
    planner_proposal_count: int
    aosplan_validated: bool
    model_allowance_claim_count: int
    model_tunnel_admission_count: int
    auth_tunnel_admission_count: int
    model_http_request_count: str
    auth_http_request_count: str
    sdk_retry_configuration: int
    loop_attempt_limit: int
    loop_step_limit: int
    model_host: str
    auth_host: str
    model_base_url: str
    wire_model: str
    oauth_storage_path: str
    tls_transport_policy: str
    server_auth_accepted_inferred_from_successful_model_turn: bool
    prompt_byte_count: int
    prompt_sha256: str
    output_byte_count: int
    output_sha256: str
    acp_terminal_state: str
    network_terminal_state: PlannerEgressState
    cleanup_completed: bool
    residue_count: int

    def __post_init__(self) -> None:
        if (
            type(self.qualification_state) is not str
            or self.qualification_state not in ("COMPLETE", "BLOCKED")
        ):
            raise KimiPlannerTypeError("INVALID_QUALIFICATION_STATE")
        if self.primary_failure_code is not None and (
            type(self.primary_failure_code) is not PlannerFailureCode
        ):
            raise KimiPlannerTypeError("INVALID_ENUM_FIELD", "primary_failure_code")
        _require_bool(self.local_credential_recognized, "local_credential_recognized")
        if type(self.credential_refresh_state) is not AuthRefreshState:
            raise KimiPlannerTypeError("INVALID_ENUM_FIELD", "credential_refresh_state")
        validate_bounded_count(
            self.acp_real_prompt_count, name="acp_real_prompt_count", bound=MAX_ACP_REAL_PROMPTS
        )
        validate_bounded_count(
            self.planner_proposal_count,
            name="planner_proposal_count",
            bound=MAX_PLANNER_PROPOSALS,
        )
        _require_bool(self.aosplan_validated, "aosplan_validated")
        validate_bounded_count(
            self.model_allowance_claim_count,
            name="model_allowance_claim_count",
            bound=MAX_MODEL_ALLOWANCE_CLAIMS,
        )
        validate_bounded_count(
            self.model_tunnel_admission_count,
            name="model_tunnel_admission_count",
            bound=MAX_MODEL_TUNNEL_ADMISSIONS,
        )
        validate_bounded_count(
            self.auth_tunnel_admission_count,
            name="auth_tunnel_admission_count",
            bound=MAX_AUTH_TUNNEL_ADMISSIONS,
        )
        for name in ("model_http_request_count", "auth_http_request_count"):
            if getattr(self, name) != OPAQUE_TLS_HTTP_COUNT_MARKER:
                raise KimiPlannerTypeError("HTTP_COUNT_NOT_OPAQUE_MARKER", name)
        validate_bounded_count(
            self.sdk_retry_configuration, name="sdk_retry_configuration", bound=0
        )
        validate_bounded_count(self.loop_attempt_limit, name="loop_attempt_limit", bound=1)
        validate_bounded_count(self.loop_step_limit, name="loop_step_limit", bound=1)
        for name in ("model_host", "auth_host", "model_base_url", "wire_model", "oauth_storage_path"):
            _require_str(getattr(self, name), name)
        if self.tls_transport_policy != TLS_TRANSPORT_POLICY_LITERAL:
            raise KimiPlannerTypeError("TLS_POLICY_DRIFT")
        _require_bool(
            self.server_auth_accepted_inferred_from_successful_model_turn,
            "server_auth_accepted_inferred_from_successful_model_turn",
        )
        validate_bounded_count(self.prompt_byte_count, name="prompt_byte_count", bound=2**31)
        _require_hex(self.prompt_sha256, "prompt_sha256", 64)
        validate_bounded_count(self.output_byte_count, name="output_byte_count", bound=2**31)
        _require_hex(self.output_sha256, "output_sha256", 64)
        _require_str(self.acp_terminal_state, "acp_terminal_state")
        if type(self.network_terminal_state) is not PlannerEgressState:
            raise KimiPlannerTypeError("INVALID_ENUM_FIELD", "network_terminal_state")
        _require_bool(self.cleanup_completed, "cleanup_completed")
        validate_bounded_count(self.residue_count, name="residue_count", bound=2**31)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": RESULT_SCHEMA,
            "qualification_state": self.qualification_state,
            "primary_failure_code": (
                None if self.primary_failure_code is None else self.primary_failure_code.value
            ),
            "local_credential_recognized": self.local_credential_recognized,
            "credential_refresh_state": self.credential_refresh_state.value,
            "acp_real_prompt_count": self.acp_real_prompt_count,
            "planner_proposal_count": self.planner_proposal_count,
            "aosplan_validated": self.aosplan_validated,
            "model_allowance_claim_count": self.model_allowance_claim_count,
            "model_tunnel_admission_count": self.model_tunnel_admission_count,
            "auth_tunnel_admission_count": self.auth_tunnel_admission_count,
            "model_http_request_count": self.model_http_request_count,
            "auth_http_request_count": self.auth_http_request_count,
            "sdk_retry_configuration": self.sdk_retry_configuration,
            "loop_attempt_limit": self.loop_attempt_limit,
            "loop_step_limit": self.loop_step_limit,
            "model_host": self.model_host,
            "auth_host": self.auth_host,
            "model_base_url": self.model_base_url,
            "wire_model": self.wire_model,
            "oauth_storage_path": self.oauth_storage_path,
            "tls_transport_policy": self.tls_transport_policy,
            "server_auth_accepted_inferred_from_successful_model_turn": (
                self.server_auth_accepted_inferred_from_successful_model_turn
            ),
            "prompt_byte_count": self.prompt_byte_count,
            "prompt_sha256": self.prompt_sha256,
            "output_byte_count": self.output_byte_count,
            "output_sha256": self.output_sha256,
            "acp_terminal_state": self.acp_terminal_state,
            "network_terminal_state": self.network_terminal_state.value,
            "cleanup_completed": self.cleanup_completed,
            "residue_count": self.residue_count,
        }

    @classmethod
    def from_dict(cls, raw: object) -> ResultRecord:
        data = _require_fields(raw, _RESULT_FIELDS, "result")
        if data["schema"] != RESULT_SCHEMA:
            raise KimiPlannerTypeError("WRONG_SCHEMA", "result")
        failure = data["primary_failure_code"]
        return cls(
            qualification_state=data["qualification_state"],
            primary_failure_code=(
                None
                if failure is None
                else _require_enum(PlannerFailureCode, failure, "primary_failure_code")
            ),
            local_credential_recognized=data["local_credential_recognized"],
            credential_refresh_state=_require_enum(
                AuthRefreshState, data["credential_refresh_state"], "credential_refresh_state"
            ),
            acp_real_prompt_count=data["acp_real_prompt_count"],
            planner_proposal_count=data["planner_proposal_count"],
            aosplan_validated=data["aosplan_validated"],
            model_allowance_claim_count=data["model_allowance_claim_count"],
            model_tunnel_admission_count=data["model_tunnel_admission_count"],
            auth_tunnel_admission_count=data["auth_tunnel_admission_count"],
            model_http_request_count=data["model_http_request_count"],
            auth_http_request_count=data["auth_http_request_count"],
            sdk_retry_configuration=data["sdk_retry_configuration"],
            loop_attempt_limit=data["loop_attempt_limit"],
            loop_step_limit=data["loop_step_limit"],
            model_host=data["model_host"],
            auth_host=data["auth_host"],
            model_base_url=data["model_base_url"],
            wire_model=data["wire_model"],
            oauth_storage_path=data["oauth_storage_path"],
            tls_transport_policy=data["tls_transport_policy"],
            server_auth_accepted_inferred_from_successful_model_turn=data[
                "server_auth_accepted_inferred_from_successful_model_turn"
            ],
            prompt_byte_count=data["prompt_byte_count"],
            prompt_sha256=data["prompt_sha256"],
            output_byte_count=data["output_byte_count"],
            output_sha256=data["output_sha256"],
            acp_terminal_state=data["acp_terminal_state"],
            network_terminal_state=_require_enum(
                PlannerEgressState, data["network_terminal_state"], "network_terminal_state"
            ),
            cleanup_completed=data["cleanup_completed"],
            residue_count=data["residue_count"],
        )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


@dataclass(frozen=True, slots=True)
class CompilePreviewRequest:
    """Typed input boundary for the future pure, non-mutating compile-preview.

    Implementation is deferred to a later slice. The mutating
    ``compile_planner_proposal`` in ``agenticos.orchestration.proposals``
    mutates board state through ``add_tasks`` and stage completion, has no
    dry-run mode, and must never be used by qualification code.
    """

    proposal_canonical_bytes: bytes
    board_snapshot_canonical_bytes: bytes
    policy_digest: str

    def __post_init__(self) -> None:
        for name in ("proposal_canonical_bytes", "board_snapshot_canonical_bytes"):
            if type(getattr(self, name)) is not bytes:
                raise KimiPlannerTypeError("INVALID_PREVIEW_REQUEST", name)
        _require_hex(self.policy_digest, "policy_digest", 64)


@dataclass(frozen=True, slots=True)
class CompilePreviewResult:
    """Typed output boundary for the future pure, non-mutating compile-preview.

    Implementation is deferred to a later slice; no implementation exists in
    this module and none may call the mutating board compiler.
    """

    accepted: bool
    failure_code: PlannerFailureCode | None = None
    detail: str = ""
    preview_canonical_bytes: bytes | None = None

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            raise KimiPlannerTypeError("INVALID_PREVIEW_RESULT")
        if self.failure_code is not None and type(self.failure_code) is not PlannerFailureCode:
            raise KimiPlannerTypeError("INVALID_PREVIEW_RESULT")
        if type(self.detail) is not str:
            raise KimiPlannerTypeError("INVALID_PREVIEW_RESULT")
        if self.preview_canonical_bytes is not None and (
            type(self.preview_canonical_bytes) is not bytes
        ):
            raise KimiPlannerTypeError("INVALID_PREVIEW_RESULT")
        if self.accepted and self.failure_code is not None:
            raise KimiPlannerTypeError("INVALID_PREVIEW_RESULT")
