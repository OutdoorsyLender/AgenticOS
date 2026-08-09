"""Corpus D — hostname/authority confusion matrix for M4B-2 Slice 6.

Covers :mod:`agenticos.sandbox.network_https`: the ONE hostname
canonicalization function, CONNECT/Host authority parsing, the immutable
NetworkGrant/NetworkPolicy digest binding, exact-one-active-grant
authorization, and the cross-stage identity chain.

Systematic confusion matrix: for every stage of the identity chain (grant,
CONNECT authority, worker SNI, HTTP Host, origin TLS name, evidence name),
every identity unequal to the approved hostname must fail — by grammar
rejection at the single canonicalization boundary, by typed denial at
authorization, or by a typed identity divergence naming the stage.  Pure
unit tests: no Linux-only resources, no network, no sleeps.
"""

from __future__ import annotations

import pytest

from agenticos.sandbox.network_https import (
    AuthorityRejectionCode,
    AuthorizationCode,
    GrantPurpose,
    HostnameRejectionCode,
    IdentityChainCode,
    IdentityStage,
    NetworkGrant,
    NetworkPolicy,
    NormalizationError,
    authorize_grant,
    canonical_network_policy_bytes,
    canonicalize_hostname,
    network_policy_digest,
    normalize_https_authority,
    verify_identity_chain,
)

APPROVED = "example.com"
NONCE = "a" * 32
CA_DIGEST = "b" * 64
TASK_ID = "task-0001"

# monotonic window in which the standard grant is active
T0 = 1_000_000_000
T1 = 2_000_000_000
W0 = 1_700_000_000_000_000_000
W1 = 1_800_000_000_000_000_000


def _grant(hostname: str = APPROVED, grant_id: str = "grant-1", **kw) -> NetworkGrant:
    fields = dict(
        grant_id=grant_id,
        hostname=hostname,
        purpose=GrantPurpose.GENERAL_DOWNLOAD,
        approval_source="test-approval-authority",
        approval_reference="approval-ref-0001",
        granted_at_wall_ns=W0,
        expires_at_wall_ns=W1,
        activated_at_monotonic_ns=T0,
        expires_at_monotonic_ns=T1,
        connection_limit=8,
        byte_limit=1 << 20,
    )
    fields.update(kw)
    return NetworkGrant(**fields)


def _policy(grants=(_grant(),), **kw) -> NetworkPolicy:
    fields = dict(
        version="AOSHTTPS/1",
        task_id=TASK_ID,
        task_generation=1,
        launch_nonce=NONCE,
        task_ca_certificate_digest=CA_DIGEST,
        grants=tuple(grants),
    )
    fields.update(kw)
    return NetworkPolicy(**fields)


def _chain(grant, **overrides):
    stages = dict(
        connect_authority=grant.hostname,
        worker_sni=grant.hostname,
        http_host=grant.hostname,
        origin_tls_name=grant.hostname,
        evidence_name=grant.hostname,
    )
    stages.update(overrides)
    return verify_identity_chain(grant, **stages)


# ---------------------------------------------------------------------------
# canonicalize_hostname: valid positives
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "example.com"),
        (b"example.com", "example.com"),
        ("deep.sub.example.com", "deep.sub.example.com"),
        ("EXAMPLE.com", "example.com"),      # case folds at THIS boundary only
        (b"Example.COM", "example.com"),
        ("a-b.c-d.example.com", "a-b.c-d.example.com"),
        ("a.example.com", "a.example.com"),
        ("x" * 63 + ".example.com", "x" * 63 + ".example.com"),
    ],
)
def test_canonicalize_hostname_accepts(raw, expected):
    assert canonicalize_hostname(raw) == expected


# ---------------------------------------------------------------------------
# canonicalize_hostname: rejection grammar matrix
# ---------------------------------------------------------------------------


REJECT_HOSTNAMES = [
    # IP literals and inet_aton-compatible legacy numerics
    ("ip-literal-v4", "127.0.0.1", HostnameRejectionCode.NUMERIC_LABEL),
    ("legacy-decimal", "2130706433", HostnameRejectionCode.NUMERIC_LABEL),
    ("legacy-hex-label", "0x7f.1", HostnameRejectionCode.NUMERIC_LABEL),
    ("legacy-short-v4", "127.1", HostnameRejectionCode.NUMERIC_LABEL),
    ("legacy-octal", "0177.0.0.1", HostnameRejectionCode.NUMERIC_LABEL),
    ("legacy-hex-whole", "0xffffffff", HostnameRejectionCode.NUMERIC_LABEL),
    ("legacy-three-part", "1.2.3", HostnameRejectionCode.NUMERIC_LABEL),
    ("all-digit-final-label", "example.123", HostnameRejectionCode.NUMERIC_LABEL),
    ("all-digit-leading-label", "123.example.com", HostnameRejectionCode.NUMERIC_LABEL),
    # IPv6 in any form (colon/bracket/zone-id bytes are outside LDH)
    ("ipv6-bare", "::1", HostnameRejectionCode.LABEL_SYNTAX),
    ("ipv6-bracketed", "[::1]", HostnameRejectionCode.LABEL_SYNTAX),
    ("ipv6-zone-id", "fe80::1%eth0", HostnameRejectionCode.LABEL_SYNTAX),
    # punycode rejects outright; no IDNA conversion
    ("punycode-label", "xn--exmple-cua.com", HostnameRejectionCode.PUNYCODE_LABEL),
    ("punycode-uppercase", "XN--exmple-cua.com", HostnameRejectionCode.PUNYCODE_LABEL),
    # dot forms
    ("trailing-dot", "example.com.", HostnameRejectionCode.EMPTY_LABEL),
    ("leading-dot", ".example.com", HostnameRejectionCode.EMPTY_LABEL),
    ("double-dot", "example..com", HostnameRejectionCode.EMPTY_LABEL),
    ("bare-dot", ".", HostnameRejectionCode.EMPTY_LABEL),
    # LDH syntax
    ("leading-hyphen", "-example.com", HostnameRejectionCode.LABEL_SYNTAX),
    ("trailing-hyphen", "example-.com", HostnameRejectionCode.LABEL_SYNTAX),
    ("label-too-long", "x" * 64 + ".example.com", HostnameRejectionCode.LABEL_TOO_LONG),
    ("name-too-long", ("x" * 63 + ".") * 4 + "example.com", HostnameRejectionCode.NAME_TOO_LONG),
    ("whitespace-inside", "exa mple.com", HostnameRejectionCode.LABEL_SYNTAX),
    ("tab-inside", "exa\tmple.com", HostnameRejectionCode.LABEL_SYNTAX),
    ("control-char", "exa\x01mple.com", HostnameRejectionCode.LABEL_SYNTAX),
    ("underscore", "exa_mple.com", HostnameRejectionCode.LABEL_SYNTAX),
    ("wildcard", "*.example.com", HostnameRejectionCode.LABEL_SYNTAX),
    ("empty", "", HostnameRejectionCode.EMPTY_NAME),
    ("non-ascii-str", "exämple.com", HostnameRejectionCode.NON_ASCII),
    ("non-ascii-bytes", b"ex\xc3\xa4mple.com", HostnameRejectionCode.NON_ASCII),
    ("obs-text-byte", b"example.\x80com", HostnameRejectionCode.NON_ASCII),
]


@pytest.mark.parametrize("raw,code", [r[1:] for r in REJECT_HOSTNAMES],
                         ids=[r[0] for r in REJECT_HOSTNAMES])
def test_canonicalize_hostname_rejects(raw, code):
    with pytest.raises(NormalizationError) as excinfo:
        canonicalize_hostname(raw)
    assert excinfo.value.code is code


def test_canonicalize_hostname_rejects_non_bytes_str():
    with pytest.raises(NormalizationError):
        canonicalize_hostname(123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# normalize_https_authority: CONNECT authority / Host header grammar
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        (b"example.com", "example.com"),
        (b"example.com:443", "example.com"),   # :443 ≡ omitted
        (b"EXAMPLE.com:443", "example.com"),
        (b"deep.sub.example.com", "deep.sub.example.com"),
    ],
)
def test_normalize_authority_accepts(raw, expected):
    assert normalize_https_authority(raw) == expected


REJECT_AUTHORITIES = [
    ("wrong-port", b"example.com:8443", AuthorityRejectionCode.PORT_NOT_443),
    ("port-80", b"example.com:80", AuthorityRejectionCode.PORT_NOT_443),
    ("port-zero", b"example.com:0", AuthorityRejectionCode.PORT_NOT_443),
    ("non-canonical-port", b"example.com:0443", AuthorityRejectionCode.PORT_NOT_443),
    ("empty-port", b"example.com:", AuthorityRejectionCode.PORT_SYNTAX),
    ("non-numeric-port", b"example.com:https", AuthorityRejectionCode.PORT_SYNTAX),
    ("multiple-ports", b"example.com:443:443", AuthorityRejectionCode.AMBIGUOUS_COLONS),
    ("ipv6-bracketed", b"[::1]:443", AuthorityRejectionCode.AMBIGUOUS_COLONS),
    ("ipv6-bare", b"::1", AuthorityRejectionCode.AMBIGUOUS_COLONS),
    ("userinfo", b"user@example.com", AuthorityRejectionCode.USERINFO),
    ("userinfo-with-password", b"user:pw@example.com:443", AuthorityRejectionCode.USERINFO),
    ("percent-encoded", b"%65xample.com", AuthorityRejectionCode.PERCENT_ENCODING),
    ("percent-encoded-delimiter", b"example.com%3a443", AuthorityRejectionCode.PERCENT_ENCODING),
    ("empty-authority", b"", AuthorityRejectionCode.EMPTY_AUTHORITY),
    ("non-ascii", b"ex\xc3\xa4mple.com", AuthorityRejectionCode.NON_ASCII),
    ("whitespace", b"example.com :443", AuthorityRejectionCode.HOSTNAME_REJECTED),
    ("ip-literal", b"127.0.0.1:443", AuthorityRejectionCode.HOSTNAME_REJECTED),
    ("legacy-decimal", b"2130706433", AuthorityRejectionCode.HOSTNAME_REJECTED),
    ("trailing-dot", b"example.com.:443", AuthorityRejectionCode.HOSTNAME_REJECTED),
    ("punycode", b"xn--exmple-cua.com:443", AuthorityRejectionCode.HOSTNAME_REJECTED),
]


@pytest.mark.parametrize("raw,code", [r[1:] for r in REJECT_AUTHORITIES],
                         ids=[r[0] for r in REJECT_AUTHORITIES])
def test_normalize_authority_rejects(raw, code):
    with pytest.raises(NormalizationError) as excinfo:
        normalize_https_authority(raw)
    assert excinfo.value.code is code


# ---------------------------------------------------------------------------
# NetworkGrant construction: the grant stage fails closed on any non-canonical
# or otherwise invalid identity
# ---------------------------------------------------------------------------


GRANT_REJECT_HOSTNAMES = [r[:2] for r in REJECT_HOSTNAMES] + [
    ("uppercase-uncanonicalized", "EXAMPLE.com"),
    ("mixed-case-uncanonicalized", "Example.Com"),
]


@pytest.mark.parametrize("hostname", [r[1] for r in GRANT_REJECT_HOSTNAMES],
                         ids=[r[0] for r in GRANT_REJECT_HOSTNAMES])
def test_grant_construction_rejects_bad_hostname(hostname):
    with pytest.raises((ValueError, NormalizationError)):
        _grant(hostname=hostname)


def test_grant_construction_rejects_non_443_port():
    with pytest.raises(ValueError):
        _grant(port=8443)


def test_grant_construction_rejects_bad_lifetimes():
    with pytest.raises(ValueError):
        _grant(expires_at_monotonic_ns=T0)          # expiry <= activation
    with pytest.raises(ValueError):
        _grant(expires_at_wall_ns=W0)               # wall expiry <= grant
    with pytest.raises(ValueError):
        _grant(connection_limit=0)
    with pytest.raises(ValueError):
        _grant(byte_limit=-1)


def test_grant_purpose_method_hooks():
    assert _grant(purpose=GrantPurpose.GENERAL_DOWNLOAD).purpose.http_policy().allowed_methods == frozenset({"GET", "HEAD"})
    assert _grant(purpose=GrantPurpose.GIT_SMART_FETCH).purpose.http_policy().allowed_methods == frozenset({"GET", "HEAD", "POST"})


# ---------------------------------------------------------------------------
# NetworkPolicy canonical bytes + digest binding
# ---------------------------------------------------------------------------


def test_policy_digest_is_stable():
    assert network_policy_digest(_policy()) == network_policy_digest(_policy())
    assert canonical_network_policy_bytes(_policy()) == canonical_network_policy_bytes(_policy())


def test_policy_digest_changes_with_hostname():
    assert network_policy_digest(_policy()) != network_policy_digest(
        _policy(grants=(_grant(hostname="other.example.com"),))
    )


def test_policy_digest_changes_with_ca_digest():
    assert network_policy_digest(_policy()) != network_policy_digest(
        _policy(task_ca_certificate_digest="c" * 64)
    )


def test_policy_digest_is_grant_order_independent():
    g1 = _grant(grant_id="grant-1")
    g2 = _grant(grant_id="grant-2", hostname="deep.sub.example.com")
    assert network_policy_digest(_policy(grants=(g1, g2))) == network_policy_digest(
        _policy(grants=(g2, g1))
    )


def test_policy_digest_is_compact_sorted_ascii_json():
    payload = canonical_network_policy_bytes(_policy())
    assert b" " not in payload
    assert payload.isascii()
    assert b'"task_ca_certificate_digest":"' + CA_DIGEST.encode() + b'"' in payload


def test_policy_rejects_duplicate_grant_id():
    with pytest.raises(ValueError):
        _policy(grants=(_grant(grant_id="dup"), _grant(grant_id="dup", hostname="deep.sub.example.com")))


def test_policy_commits_to_exact_fields():
    policy = _policy()
    for field, value in [
        ("task_id", "task-9999"),
        ("task_generation", 2),
        ("launch_nonce", "d" * 32),
    ]:
        assert network_policy_digest(policy) != network_policy_digest(
            _policy(**{field: value})
        )


# ---------------------------------------------------------------------------
# authorize_grant: exact-one-active-grant, byte equality, fail closed
# ---------------------------------------------------------------------------


def test_authorize_grant_exact_match():
    policy = _policy()
    outcome = authorize_grant(policy, APPROVED, at_monotonic_ns=T0)
    assert outcome.authorized
    assert outcome.code is AuthorizationCode.AUTHORIZED
    assert outcome.grant is policy.grants[0]


def test_authorize_grant_zero_match_denied():
    outcome = authorize_grant(_policy(), "other.example.com", at_monotonic_ns=T0)
    assert not outcome.authorized
    assert outcome.code is AuthorizationCode.NO_MATCH
    assert outcome.grant is None


def test_authorize_grant_multi_match_denied():
    policy = _policy(grants=(_grant(grant_id="g1"), _grant(grant_id="g2")))
    outcome = authorize_grant(policy, APPROVED, at_monotonic_ns=T0)
    assert not outcome.authorized
    assert outcome.code is AuthorizationCode.AMBIGUOUS_GRANTS


def test_authorize_grant_expired_denied():
    outcome = authorize_grant(_policy(), APPROVED, at_monotonic_ns=T1)
    assert not outcome.authorized
    assert outcome.code is AuthorizationCode.NO_ACTIVE_GRANT


def test_authorize_grant_not_yet_active_denied():
    outcome = authorize_grant(_policy(), APPROVED, at_monotonic_ns=T0 - 1)
    assert not outcome.authorized
    assert outcome.code is AuthorizationCode.NO_ACTIVE_GRANT


def test_authorize_grant_one_expired_one_active_is_unambiguous():
    expired = _grant(grant_id="g-old", activated_at_monotonic_ns=T0 - 10,
                     expires_at_monotonic_ns=T0)
    outcome = authorize_grant(
        _policy(grants=(expired, _grant(grant_id="g-new"))),
        APPROVED,
        at_monotonic_ns=T0,
    )
    assert outcome.authorized
    assert outcome.grant.grant_id == "g-new"


# every non-canonical byte form is a typed denial at authorization — this
# boundary NEVER normalizes a mismatch into acceptance
@pytest.mark.parametrize(
    "hostname",
    [
        "EXAMPLE.com",          # case difference, uncanonicalized
        "example.com.",         # trailing dot
        ".example.com",         # leading dot
        "example..com",         # double dot
        "badexample.com",       # suffix variation
        "example.com.evil.test",
        "www.example.com",      # prefix variation
        "example.com:443",      # authority form, not a bare hostname
        "127.0.0.1",
        "xn--exmple-cua.com",
        "example.123",
        "2130706433",
    ],
)
def test_authorize_grant_rejects_every_unequal_identity(hostname):
    outcome = authorize_grant(_policy(), hostname, at_monotonic_ns=T0)
    assert not outcome.authorized
    assert outcome.code in (
        AuthorizationCode.HOSTNAME_NOT_CANONICAL,
        AuthorizationCode.NO_MATCH,
    )


# ---------------------------------------------------------------------------
# verify_identity_chain: per-stage confusion matrix
# ---------------------------------------------------------------------------


def test_identity_chain_verified():
    outcome = _chain(_grant())
    assert outcome.verified
    assert outcome.code is IdentityChainCode.VERIFIED
    assert outcome.stage is None


ALL_STAGES = [
    "connect_authority",
    "worker_sni",
    "http_host",
    "origin_tls_name",
    "evidence_name",
]

# identities unequal to the grant that must fail at EVERY stage
DIVERGENT_IDENTITIES = [
    ("case-difference", "EXAMPLE.com"),
    ("trailing-dot", "example.com."),
    ("leading-dot", ".example.com"),
    ("double-dot", "example..com"),
    ("suffix-variation", "badexample.com"),
    ("suffix-attack", "example.com.evil.test"),
    ("prefix-variation", "www.example.com"),
    ("authority-with-port", "example.com:443"),
    ("wrong-port", "example.com:8443"),
    ("ip-literal", "127.0.0.1"),
    ("ipv6-literal", "[::1]"),
    ("punycode", "xn--exmple-cua.com"),
    ("all-digit-final-label", "example.123"),
    ("legacy-decimal", "2130706433"),
    ("userinfo", "user@example.com"),
    ("percent-encoded", "%65xample.com"),
    ("empty", ""),
]


@pytest.mark.parametrize("stage", ALL_STAGES)
@pytest.mark.parametrize("identity", [d[1] for d in DIVERGENT_IDENTITIES],
                         ids=[d[0] for d in DIVERGENT_IDENTITIES])
def test_identity_chain_every_unequal_identity_fails_at_every_stage(stage, identity):
    outcome = _chain(_grant(), **{stage: identity})
    assert not outcome.verified
    assert outcome.code is IdentityChainCode.IDENTITY_DIVERGENCE
    assert outcome.stage is IdentityStage(stage)


@pytest.mark.parametrize("stage", ALL_STAGES)
def test_identity_chain_absent_stage_fails_closed(stage):
    outcome = _chain(_grant(), **{stage: None})
    assert not outcome.verified
    assert outcome.code is IdentityChainCode.STAGE_ABSENT
    assert outcome.stage.value == stage


def test_identity_chain_names_first_divergent_stage():
    outcome = _chain(_grant(), worker_sni="evil.example.test",
                     http_host="also-evil.example.test")
    assert outcome.stage is IdentityStage.WORKER_SNI


def test_identity_chain_rejects_non_grant():
    with pytest.raises(TypeError):
        verify_identity_chain(
            "example.com",  # type: ignore[arg-type]
            connect_authority="example.com",
            worker_sni="example.com",
            http_host="example.com",
            origin_tls_name="example.com",
            evidence_name="example.com",
        )


# ---------------------------------------------------------------------------
# ONE normalization point proof: a stage carrying raw uppercase bytes fails
# the chain; the SAME bytes pass only after canonicalize_hostname — there is
# exactly one defined normalization point per input, and it is this function.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("stage", ALL_STAGES)
def test_raw_uppercase_stage_fails_until_canonicalized(stage):
    raw = "EXAMPLE.com"
    assert _chain(_grant(), **{stage: raw}).code is IdentityChainCode.IDENTITY_DIVERGENCE
    canonical = canonicalize_hostname(raw)
    assert canonical == APPROVED
    assert _chain(_grant(), **{stage: canonical}).verified


@pytest.mark.parametrize("stage", ["connect_authority", "http_host"])
def test_raw_authority_bytes_pass_only_through_normalize_authority(stage):
    raw = b"EXAMPLE.com:443"
    # the raw wire bytes are not the canonical identity
    assert _chain(_grant(), **{stage: raw.decode()}).code is IdentityChainCode.IDENTITY_DIVERGENCE
    normalized = normalize_https_authority(raw)
    assert _chain(_grant(), **{stage: normalized}).verified


def test_grant_construction_is_the_grant_stage_normalization_point():
    # an uncanonicalized grant hostname is refused at construction; the same
    # name is buildable only after the ONE canonicalization
    with pytest.raises(ValueError):
        _grant(hostname="EXAMPLE.com")
    grant = _grant(hostname=canonicalize_hostname("EXAMPLE.com"))
    assert grant.hostname == APPROVED
    assert _chain(grant).verified


# ---------------------------------------------------------------------------
# end-to-end flow: grant -> CONNECT authority -> chain -> authorization
# ---------------------------------------------------------------------------


def test_one_hostname_flows_through_every_stage():
    grant = _grant()
    policy = _policy(grants=(grant,))
    # CONNECT authority arrives as wire bytes; normalized ONCE here
    connect = normalize_https_authority(b"example.com:443")
    host = normalize_https_authority(b"example.com")
    outcome = _chain(grant, connect_authority=connect, http_host=host)
    assert outcome.verified
    auth = authorize_grant(policy, connect, at_monotonic_ns=T0)
    assert auth.authorized
    assert auth.grant is grant
    # the authorized grant's method policy is the purpose hook
    assert grant.purpose.http_policy().allowed_methods == frozenset({"GET", "HEAD"})
