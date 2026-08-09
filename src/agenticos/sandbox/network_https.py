"""M4B-2 immutable HTTPS grant policy: hostname grammar and identity chain.

This module owns the ONE hostname canonicalization function for the M4B-2
authenticated-HTTPS path.  Exactly one canonical approved hostname flows
through every stage of a task's network authority:

    sealed task grant -> CONNECT authority -> worker TLS SNI ->
    HTTP Host authority -> origin TLS SNI -> origin certificate hostname ->
    evidence

Authorization at every comparison boundary is canonical BYTE EQUALITY.  No
layer may independently "helpfully normalize" a mismatch into acceptance:
``canonicalize_hostname`` is the single normalization point, applied exactly
once per input at a defined boundary (grant construction for the approved
hostname; ``normalize_https_authority`` for CONNECT authority and Host
header bytes).  Every later comparison sees only canonical lowercase ASCII
and compares bytes.

Hostname grammar — narrow ASCII profile (NO IDNA in the MVP):

* pure ASCII only; non-ASCII bytes/str reject (never IDNA-converted)
* LDH labels: ``[a-z0-9-]``, 1..63 octets, no leading/trailing hyphen
* total name length 1..253 octets; no leading dot, trailing dot, or empty
  label (``example.com.`` is a DIFFERENT, rejected form at authorization —
  a resolver may append the root dot for the DNS query later, but that is
  not a second identity)
* ``xn--`` labels reject outright (punycode is never converted)
* IP literals and inet_aton-compatible legacy numerics reject: any label
  that is all digits (covers ``127.0.0.1``, ``127.1``, ``1.2.3``,
  ``0177.0.0.1``, ``2130706433``, and all-digit final labels such as
  ``example.123``) and any ``0x``-prefixed hex label (covers
  ``0x7f.1``, ``0xffffffff``) — anything libc could resolve numerically
  without ordinary DNS is not a hostname here
* IPv6 in every form (bare, bracketed, zone IDs) rejects: the colon,
  bracket, and percent bytes are outside the label grammar, and an
  authority with more than one colon rejects before that
* authorities: no userinfo (``@``), no percent-encoding (``%``), no
  whitespace/control bytes, at most one port separator, port must be
  exactly 443 (``:443`` is equivalent to omitted; everything else rejects),
  empty authority rejects

Fail-closed contract: grammar violations raise the typed
:class:`NormalizationError` (carrying a machine-readable code) at the
single canonicalization boundary; authorization and identity-chain
verification return typed outcomes and never raise across the module
boundary.

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum

from .network_http import HttpPolicy

_POLICY_VERSION = "AOSHTTPS/1"
_HTTPS_PORT = 443
_MAX_GRANTS = 64
_MAX_UNSIGNED_64 = (1 << 64) - 1
_MAX_HOSTNAME_OCTETS = 253
_MAX_LABEL_OCTETS = 63
_MAX_APPROVAL_TEXT = 256
_TASK_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_LOWER_HEX_32_RE = re.compile(r"[0-9a-f]{32}\Z")
_LOWER_HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
_LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\Z")
_ALL_DIGITS_RE = re.compile(r"[0-9]+\Z")
_HEX_LABEL_RE = re.compile(r"0x[0-9a-f]+\Z")


class HostnameRejectionCode(str, Enum):
    """Machine-readable reason a hostname failed the grammar."""

    NON_ASCII = "non_ascii"
    EMPTY_NAME = "empty_name"
    NAME_TOO_LONG = "name_too_long"
    EMPTY_LABEL = "empty_label"
    LABEL_TOO_LONG = "label_too_long"
    LABEL_SYNTAX = "label_syntax"
    PUNYCODE_LABEL = "punycode_label"
    NUMERIC_LABEL = "numeric_label"


class AuthorityRejectionCode(str, Enum):
    """Machine-readable reason an authority string failed the grammar."""

    NON_ASCII = "non_ascii"
    EMPTY_AUTHORITY = "empty_authority"
    USERINFO = "userinfo"
    PERCENT_ENCODING = "percent_encoding"
    AMBIGUOUS_COLONS = "ambiguous_colons"
    PORT_SYNTAX = "port_syntax"
    PORT_NOT_443 = "port_not_443"
    HOSTNAME_REJECTED = "hostname_rejected"


class NormalizationError(ValueError):
    """Typed fail-closed grammar rejection at the canonicalization boundary."""

    __slots__ = ("code", "detail")

    def __init__(
        self,
        code: HostnameRejectionCode | AuthorityRejectionCode,
        detail: str,
    ) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def canonicalize_hostname(raw: bytes | str) -> str:
    """Return the ONE canonical lowercase ASCII form of ``raw``.

    This is the single normalization point for the entire M4B-2 HTTPS path.
    Any grammar violation raises :class:`NormalizationError` — the function
    fails closed and never converts IDNA, strips a trailing dot, or repairs
    a numeric/legacy form.  The returned str is the only form authorization
    ever compares, by byte equality.
    """
    if isinstance(raw, (bytes, bytearray, memoryview)):
        try:
            text = bytes(raw).decode("ascii")
        except UnicodeDecodeError as exc:
            raise NormalizationError(
                HostnameRejectionCode.NON_ASCII,
                "hostname must be pure ASCII (no IDNA in this profile)",
            ) from exc
    elif type(raw) is str:
        text = raw
        if not text.isascii():
            raise NormalizationError(
                HostnameRejectionCode.NON_ASCII,
                "hostname must be pure ASCII (no IDNA in this profile)",
            )
    else:
        raise NormalizationError(
            HostnameRejectionCode.NON_ASCII,
            f"hostname must be bytes or str, got {type(raw).__name__}",
        )
    lowered = text.lower()
    if not lowered:
        raise NormalizationError(HostnameRejectionCode.EMPTY_NAME, "hostname is empty")
    if len(lowered.encode("ascii")) > _MAX_HOSTNAME_OCTETS:
        raise NormalizationError(
            HostnameRejectionCode.NAME_TOO_LONG,
            f"hostname exceeds {_MAX_HOSTNAME_OCTETS} octets",
        )
    labels = lowered.split(".")
    for label in labels:
        if not label:
            raise NormalizationError(
                HostnameRejectionCode.EMPTY_LABEL,
                "leading dot, trailing dot, or empty label is rejected",
            )
        if len(label.encode("ascii")) > _MAX_LABEL_OCTETS:
            raise NormalizationError(
                HostnameRejectionCode.LABEL_TOO_LONG,
                f"label exceeds {_MAX_LABEL_OCTETS} octets",
            )
        if not _LABEL_RE.fullmatch(label):
            raise NormalizationError(
                HostnameRejectionCode.LABEL_SYNTAX,
                "label must be LDH: [a-z0-9-], no leading/trailing hyphen",
            )
        if label.startswith("xn--"):
            raise NormalizationError(
                HostnameRejectionCode.PUNYCODE_LABEL,
                "punycode (xn--) labels are rejected, never IDNA-converted",
            )
        if _ALL_DIGITS_RE.fullmatch(label) or _HEX_LABEL_RE.fullmatch(label):
            raise NormalizationError(
                HostnameRejectionCode.NUMERIC_LABEL,
                "all-digit or 0x-hex labels are rejected "
                "(IP literals and inet_aton legacy numerics are not hostnames)",
            )
    return lowered


def normalize_https_authority(authority: bytes) -> str:
    """Parse a CONNECT authority or Host header value into canonical form.

    Grammar: ``host[:port]`` where an explicit port must be exactly 443
    (``:443`` is equivalent to omitted).  Userinfo, percent-encoding,
    whitespace/control bytes, multiple colons (any IPv6 form), and every
    hostname grammar violation reject.  The hostname part passes through
    :func:`canonicalize_hostname` — the ONE normalization point.
    """
    if not isinstance(authority, (bytes, bytearray, memoryview)):
        raise NormalizationError(
            AuthorityRejectionCode.NON_ASCII,
            f"authority must be bytes, got {type(authority).__name__}",
        )
    try:
        text = bytes(authority).decode("ascii")
    except UnicodeDecodeError as exc:
        raise NormalizationError(
            AuthorityRejectionCode.NON_ASCII,
            "authority must be pure ASCII",
        ) from exc
    if not text:
        raise NormalizationError(
            AuthorityRejectionCode.EMPTY_AUTHORITY, "authority is empty"
        )
    if "@" in text:
        raise NormalizationError(
            AuthorityRejectionCode.USERINFO, "userinfo is rejected"
        )
    if "%" in text:
        raise NormalizationError(
            AuthorityRejectionCode.PERCENT_ENCODING,
            "percent-encoding is rejected",
        )
    if text.count(":") > 1:
        raise NormalizationError(
            AuthorityRejectionCode.AMBIGUOUS_COLONS,
            "more than one colon (any IPv6 or multi-port form) is rejected",
        )
    host = text
    if ":" in text:
        host, _, port_text = text.partition(":")
        if not port_text or not port_text.isdigit():
            raise NormalizationError(
                AuthorityRejectionCode.PORT_SYNTAX,
                "port must be non-empty canonical decimal",
            )
        if port_text != "443":
            raise NormalizationError(
                AuthorityRejectionCode.PORT_NOT_443,
                f"only port {_HTTPS_PORT} (or omitted) is admitted; "
                "non-canonical forms such as 0443 reject too",
            )
    try:
        return canonicalize_hostname(host)
    except NormalizationError as exc:
        raise NormalizationError(
            AuthorityRejectionCode.HOSTNAME_REJECTED,
            f"authority hostname rejected: {exc.detail}",
        ) from exc


class GrantPurpose(str, Enum):
    """Purpose-specific method grants, wired to network_http.HttpPolicy."""

    GENERAL_DOWNLOAD = "general_download"
    GIT_SMART_FETCH = "git_smart_fetch"

    def http_policy(self) -> HttpPolicy:
        """Return the method/body policy this purpose authorizes."""
        if self is GrantPurpose.GENERAL_DOWNLOAD:
            return HttpPolicy.general_download()
        return HttpPolicy.git_smart_fetch()


def _require_task_id(value: object) -> None:
    if not isinstance(value, str) or not _TASK_ID_RE.fullmatch(value):
        raise ValueError("task_id must be a bounded ASCII identifier")


def _require_nonce(value: object) -> None:
    if not isinstance(value, str) or not _LOWER_HEX_32_RE.fullmatch(value):
        raise ValueError("launch_nonce must be exactly 32 lowercase hexadecimal characters")


def _require_positive_u64(name: str, value: object) -> None:
    if type(value) is not int or not 0 < value <= _MAX_UNSIGNED_64:
        raise ValueError(f"{name} must be a positive unsigned 64-bit integer")


def _require_approval_text(name: str, value: object) -> None:
    if (
        type(value) is not str
        or not 0 < len(value) <= _MAX_APPROVAL_TEXT
        or not value.isascii()
        or any(ord(c) < 0x20 or ord(c) > 0x7E for c in value)
    ):
        raise ValueError(f"{name} must be bounded visible ASCII")


@dataclass(frozen=True)
class NetworkGrant:
    """One immutable exact-hostname HTTPS grant inside a NetworkPolicy.

    ``hostname`` must already be the canonical form: it is validated AND
    lowercased exactly once, by the caller through
    :func:`canonicalize_hostname`, before construction; construction
    re-verifies the value equals its own canonical form, so an uppercase or
    otherwise uncanonicalized value is refused here rather than silently
    repaired.  ``port`` is fixed at 443.  Monotonic time controls
    activation/expiry; wall time is evidence only (mirrors TransportPolicy).
    """

    grant_id: str
    hostname: str
    purpose: GrantPurpose
    approval_source: str
    approval_reference: str
    granted_at_wall_ns: int
    expires_at_wall_ns: int
    activated_at_monotonic_ns: int
    expires_at_monotonic_ns: int
    connection_limit: int
    byte_limit: int
    port: int = _HTTPS_PORT

    def __post_init__(self) -> None:
        if type(self.grant_id) is not str or not _TASK_ID_RE.fullmatch(self.grant_id):
            raise ValueError("grant_id must be a bounded ASCII identifier")
        if type(self.hostname) is not str:
            raise ValueError("hostname must be a str in canonical form")
        canonical = canonicalize_hostname(self.hostname)
        if self.hostname != canonical:
            raise ValueError(
                "hostname must be the canonical form; pass it through "
                "canonicalize_hostname exactly once before construction"
            )
        if type(self.port) is not int or self.port != _HTTPS_PORT:
            raise ValueError(f"port is fixed at {_HTTPS_PORT}")
        if type(self.purpose) is not GrantPurpose:
            raise ValueError("purpose must be a GrantPurpose")
        _require_approval_text("approval_source", self.approval_source)
        _require_approval_text("approval_reference", self.approval_reference)
        _require_positive_u64("granted_at_wall_ns", self.granted_at_wall_ns)
        _require_positive_u64("expires_at_wall_ns", self.expires_at_wall_ns)
        if self.expires_at_wall_ns <= self.granted_at_wall_ns:
            raise ValueError("expires_at_wall_ns must be after granted_at_wall_ns")
        _require_positive_u64("activated_at_monotonic_ns", self.activated_at_monotonic_ns)
        _require_positive_u64("expires_at_monotonic_ns", self.expires_at_monotonic_ns)
        if self.expires_at_monotonic_ns <= self.activated_at_monotonic_ns:
            raise ValueError("expires_at_monotonic_ns must be after activation")
        _require_positive_u64("connection_limit", self.connection_limit)
        _require_positive_u64("byte_limit", self.byte_limit)

    def is_active(self, at_monotonic_ns: int) -> bool:
        """Monotonic-clock activity window; wall time is evidence only."""
        return self.activated_at_monotonic_ns <= at_monotonic_ns < self.expires_at_monotonic_ns

    def _canonical_fields(self) -> dict:
        return {
            "grant_id": self.grant_id,
            "hostname": self.hostname,
            "port": self.port,
            "scheme": "https",
            "transport": "tcp",
            "application": "http/1.1",
            "allowed_methods": sorted(self.purpose.http_policy().allowed_methods),
            "purpose": self.purpose.value,
            "approval_source": self.approval_source,
            "approval_reference": self.approval_reference,
            "granted_at_wall_ns": self.granted_at_wall_ns,
            "expires_at_wall_ns": self.expires_at_wall_ns,
            "activated_at_monotonic_ns": self.activated_at_monotonic_ns,
            "expires_at_monotonic_ns": self.expires_at_monotonic_ns,
            "connection_limit": self.connection_limit,
            "byte_limit": self.byte_limit,
        }


@dataclass(frozen=True)
class NetworkPolicy:
    """The immutable M4B-2 HTTPS grant-set, canonicalized and digested
    before process creation.

    ``task_ca_certificate_digest`` is the SHA-256 of the exact per-task CA
    certificate from the cert_helper binding (``CertBinding.ca_cert_sha256``),
    so the policy commits to the exact CA.  Grants serialize sorted by
    (hostname, grant_id), so the digest is independent of input order.
    """

    version: str
    task_id: str
    task_generation: int
    launch_nonce: str
    task_ca_certificate_digest: str
    grants: tuple

    def __post_init__(self) -> None:
        if self.version != _POLICY_VERSION:
            raise ValueError(f"version must be {_POLICY_VERSION}")
        _require_task_id(self.task_id)
        _require_positive_u64("task_generation", self.task_generation)
        _require_nonce(self.launch_nonce)
        if type(self.task_ca_certificate_digest) is not str or not _LOWER_HEX_64_RE.fullmatch(
            self.task_ca_certificate_digest
        ):
            raise ValueError(
                "task_ca_certificate_digest must be exactly 64 lowercase "
                "hexadecimal characters"
            )
        grants = tuple(self.grants)
        if len(grants) > _MAX_GRANTS:
            raise ValueError(f"more than {_MAX_GRANTS} grants is not buildable policy")
        for grant in grants:
            if type(grant) is not NetworkGrant:
                raise ValueError("grants must be NetworkGrant instances")
        grant_ids = [g.grant_id for g in grants]
        if len(set(grant_ids)) != len(grant_ids):
            raise ValueError("duplicate grant_id is not buildable policy")
        object.__setattr__(self, "grants", grants)


def canonical_network_policy_bytes(policy: NetworkPolicy) -> bytes:
    """Return the deterministic, locator-free serialization of ``policy``."""
    if type(policy) is not NetworkPolicy:
        raise TypeError("policy must be a NetworkPolicy")
    payload = {
        "version": policy.version,
        "task_id": policy.task_id,
        "task_generation": policy.task_generation,
        "launch_nonce": policy.launch_nonce,
        "task_ca_certificate_digest": policy.task_ca_certificate_digest,
        "grants": [
            grant._canonical_fields()
            for grant in sorted(policy.grants, key=lambda g: (g.hostname, g.grant_id))
        ],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")


def network_policy_digest(policy: NetworkPolicy) -> str:
    """Return the lowercase SHA-256 digest for every network policy field."""
    return hashlib.sha256(canonical_network_policy_bytes(policy)).hexdigest()


class AuthorizationCode(str, Enum):
    """Typed verdict of one grant authorization decision."""

    AUTHORIZED = "authorized"
    HOSTNAME_NOT_CANONICAL = "hostname_not_canonical"
    NO_MATCH = "no_match"
    NO_ACTIVE_GRANT = "no_active_grant"
    AMBIGUOUS_GRANTS = "ambiguous_grants"


@dataclass(frozen=True)
class GrantAuthorization:
    """Typed outcome of ``authorize_grant``; never a bare exception."""

    code: AuthorizationCode
    detail: str
    grant: NetworkGrant | None = None

    @property
    def authorized(self) -> bool:
        return self.code is AuthorizationCode.AUTHORIZED

    def __post_init__(self) -> None:
        if type(self.code) is not AuthorizationCode:
            raise ValueError("code must be an AuthorizationCode")
        if self.authorized and self.grant is None:
            raise ValueError("an authorized outcome must carry the grant")
        if not self.authorized and self.grant is not None:
            raise ValueError("a denied outcome carries no grant")


def authorize_grant(
    policy: NetworkPolicy,
    hostname: str,
    *,
    at_monotonic_ns: int,
) -> GrantAuthorization:
    """Authorize ``hostname`` against ``policy`` by canonical byte equality.

    ``hostname`` must ALREADY be canonical (the caller applied
    :func:`canonicalize_hostname` at exactly one boundary); an uncanonical
    value is a typed denial, never a silent normalization.  Exactly one
    ACTIVE grant must match; zero matches, zero active matches, and
    multiple active matches all fail closed.
    """
    if type(policy) is not NetworkPolicy:
        raise TypeError("policy must be a NetworkPolicy")
    if type(at_monotonic_ns) is not int or at_monotonic_ns < 0:
        raise TypeError("at_monotonic_ns must be a non-negative int")
    if type(hostname) is not str:
        return GrantAuthorization(
            AuthorizationCode.HOSTNAME_NOT_CANONICAL,
            f"hostname must be a canonical str, got {type(hostname).__name__}",
        )
    try:
        canonical = canonicalize_hostname(hostname)
    except NormalizationError as exc:
        return GrantAuthorization(
            AuthorizationCode.HOSTNAME_NOT_CANONICAL,
            f"hostname rejected by the grammar: {exc.detail}",
        )
    if hostname != canonical:
        return GrantAuthorization(
            AuthorizationCode.HOSTNAME_NOT_CANONICAL,
            "hostname is not in canonical form; authorization compares "
            "canonical bytes only and never normalizes at this boundary",
        )
    matches = [g for g in policy.grants if g.hostname == hostname]
    if not matches:
        return GrantAuthorization(
            AuthorizationCode.NO_MATCH,
            f"no grant names {hostname!r} exactly",
        )
    active = [g for g in matches if g.is_active(at_monotonic_ns)]
    if not active:
        return GrantAuthorization(
            AuthorizationCode.NO_ACTIVE_GRANT,
            f"no ACTIVE grant for {hostname!r} at {at_monotonic_ns}",
        )
    if len(active) > 1:
        return GrantAuthorization(
            AuthorizationCode.AMBIGUOUS_GRANTS,
            f"multiple active grants name {hostname!r}; fail closed",
        )
    return GrantAuthorization(
        AuthorizationCode.AUTHORIZED,
        f"exact active grant {active[0].grant_id!r}",
        active[0],
    )


class IdentityStage(str, Enum):
    """The stages one canonical hostname must flow through unchanged."""

    CONNECT_AUTHORITY = "connect_authority"
    WORKER_SNI = "worker_sni"
    HTTP_HOST = "http_host"
    ORIGIN_TLS_NAME = "origin_tls_name"
    EVIDENCE_NAME = "evidence_name"


class IdentityChainCode(str, Enum):
    """Typed verdict of the identity-chain verification."""

    VERIFIED = "verified"
    STAGE_ABSENT = "stage_absent"
    IDENTITY_DIVERGENCE = "identity_divergence"


@dataclass(frozen=True)
class IdentityChainOutcome:
    """Typed outcome of ``verify_identity_chain``; never a bare exception."""

    code: IdentityChainCode
    stage: IdentityStage | None
    detail: str

    @property
    def verified(self) -> bool:
        return self.code is IdentityChainCode.VERIFIED

    def __post_init__(self) -> None:
        if type(self.code) is not IdentityChainCode:
            raise ValueError("code must be an IdentityChainCode")
        if self.verified and self.stage is not None:
            raise ValueError("a verified outcome names no stage")
        if not self.verified and type(self.stage) is not IdentityStage:
            raise ValueError("a failed outcome must name the divergent stage")


def verify_identity_chain(
    grant: NetworkGrant,
    *,
    connect_authority: str | None,
    worker_sni: str | None,
    http_host: str | None,
    origin_tls_name: str | None,
    evidence_name: str | None,
) -> IdentityChainOutcome:
    """Require every stage to be canonical byte-equal to the grant hostname.

    This function NEVER normalizes: each stage value must already be the
    canonical form produced at its own single boundary (CONNECT authority
    and Host header via :func:`normalize_https_authority`; SNI and the
    origin TLS name compared lowercase by network_tls / the origin
    verifier; the grant hostname via :func:`canonicalize_hostname`).  A
    stage carrying any other byte form — different case, trailing dot,
    suffix/prefix variation — is a typed divergence naming that stage.
    """
    if type(grant) is not NetworkGrant:
        raise TypeError("grant must be a NetworkGrant")
    approved = grant.hostname
    stages = (
        (IdentityStage.CONNECT_AUTHORITY, connect_authority),
        (IdentityStage.WORKER_SNI, worker_sni),
        (IdentityStage.HTTP_HOST, http_host),
        (IdentityStage.ORIGIN_TLS_NAME, origin_tls_name),
        (IdentityStage.EVIDENCE_NAME, evidence_name),
    )
    for stage, value in stages:
        if value is None:
            return IdentityChainOutcome(
                IdentityChainCode.STAGE_ABSENT,
                stage,
                f"{stage.value} carries no identity; fail closed",
            )
        if type(value) is not str or value != approved:
            return IdentityChainOutcome(
                IdentityChainCode.IDENTITY_DIVERGENCE,
                stage,
                f"{stage.value} identity {value!r} != approved hostname "
                f"{approved!r} (canonical byte equality)",
            )
    return IdentityChainOutcome(
        IdentityChainCode.VERIFIED,
        None,
        f"all stages byte-equal to approved hostname {approved!r}",
    )


__all__ = [
    "AuthorityRejectionCode",
    "AuthorizationCode",
    "GrantAuthorization",
    "GrantPurpose",
    "HostnameRejectionCode",
    "IdentityChainCode",
    "IdentityChainOutcome",
    "IdentityStage",
    "NetworkGrant",
    "NetworkPolicy",
    "NormalizationError",
    "authorize_grant",
    "canonical_network_policy_bytes",
    "canonicalize_hostname",
    "network_policy_digest",
    "normalize_https_authority",
    "verify_identity_chain",
]
