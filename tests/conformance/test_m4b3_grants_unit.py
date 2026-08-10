"""M4B-3 Slice 1 adversarial corpus: bounded exact-host grant sets + Connected Build.

Covers the generalized grant-set machinery: ``validate_grant_set``
cardinality and duplicate-hostname bounds, multi-grant authorization
(per-grant activity windows, no suffix/wildcard authority), 4-grant
serialization/digest determinism, broker adoption/serve grant-set bounds,
in-process broker serve flows across a 2-grant policy (ungranted CONNECT,
cross-grant SNI/Host divergence, expired grant vs active peer, per-grant
connection limit), controller-side grant-spec validation and minting, and
the Connected Build worker-environment profile.

The pure network_https / runtime_boundary sections run on any platform.
Broker, cert, and runner sections require Linux sealed memfds; they import
their modules lazily under the ``linux_only`` marker so this file imports
cleanly everywhere.  Conventions mirror test_m4b_hostname_unit.py and
test_m4b_https_unit.py (whose serve/adoption helpers are reused).
"""

from __future__ import annotations

import importlib
import os
import shutil
import socket
import ssl
import stat
import sys
import threading
import time

import pytest

from agenticos.sandbox.network_https import (
    CONNECTED_BUILD_MAX_GRANTS,
    AuthorizationCode,
    GrantPurpose,
    NetworkGrant,
    NetworkPolicy,
    NormalizationError,
    authorize_grant,
    canonical_network_policy_bytes,
    canonicalize_hostname,
    network_policy_digest,
    normalize_https_authority,
    validate_grant_set,
)
from agenticos.sandbox.network_models import TransportMode, TransportPolicy


linux_only = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="requires Linux sealed memfds / broker runtime",
)

HOST_A = "alpha.example.com"
HOST_B = "beta.example.com"
HOST_UNGRANTED = "gamma.example.com"
SERVE_HOSTS = (HOST_A, HOST_B)

NONCE = "ab" * 16
CA_DIGEST = "cd" * 32
OPENSSL_IDENTITY = "OpenSSL 3.5.5 27 Jan 2026"
TASK_ID = "task-m4b3-grants"

# monotonic/wall windows in which the standard grant is active
T0 = 1_000_000_000
T1 = 2_000_000_000
W0 = 1_700_000_000_000_000_000
W1 = 1_800_000_000_000_000_000


def _grant(hostname: str, grant_id: str, **kw) -> NetworkGrant:
    fields = dict(
        grant_id=grant_id,
        hostname=hostname,
        purpose=GrantPurpose.GENERAL_DOWNLOAD,
        approval_source="m4b3-unit-approval",
        approval_reference="approval-ref-m4b3",
        granted_at_wall_ns=W0,
        expires_at_wall_ns=W1,
        activated_at_monotonic_ns=T0,
        expires_at_monotonic_ns=T1,
        connection_limit=8,
        byte_limit=1 << 20,
    )
    fields.update(kw)
    return NetworkGrant(**fields)


def _policy(grants, **kw) -> NetworkPolicy:
    fields = dict(
        version="AOSHTTPS/1",
        task_id=TASK_ID,
        task_generation=1,
        launch_nonce=NONCE,
        task_ca_certificate_digest=CA_DIGEST,
        openssl_runtime_identity=OPENSSL_IDENTITY,
        grants=tuple(grants),
    )
    fields.update(kw)
    return NetworkPolicy(**fields)


def _two_grants(**kw) -> tuple[NetworkGrant, NetworkGrant]:
    return (_grant(HOST_A, "g-alpha", **kw), _grant(HOST_B, "g-beta", **kw))


def _four_grants() -> tuple[NetworkGrant, ...]:
    return tuple(
        _grant(f"host{index}.example.com", f"g-{index:02d}") for index in range(4)
    )


def _broker():
    from agenticos.sandbox import network_broker as broker

    return broker


def _cert_helper():
    from agenticos.sandbox import cert_helper

    return cert_helper


def _runner():
    from agenticos.sandbox import m4b_runner

    return m4b_runner


def _runtime_boundary():
    return importlib.import_module("agenticos.sandbox.runtime_boundary")


# ---------------------------------------------------------------------------
# validate_grant_set: cardinality and duplicate bounds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("count", [0, 1, CONNECTED_BUILD_MAX_GRANTS])
def test_validate_grant_set_accepts_zero_one_and_four(count):
    grants = tuple(
        _grant(f"host{index}.example.com", f"g-{index}") for index in range(count)
    )
    validate_grant_set(grants)


def test_validate_grant_set_rejects_five_grants():
    grants = tuple(
        _grant(f"host{index}.example.com", f"g-{index}") for index in range(5)
    )
    with pytest.raises(ValueError, match="Connected Build bound"):
        validate_grant_set(grants)


def test_validate_grant_set_rejects_duplicate_hostname_distinct_purposes():
    first = _grant(HOST_A, "g-1", purpose=GrantPurpose.GENERAL_DOWNLOAD)
    second = _grant(
        HOST_A,
        "g-2",
        purpose=GrantPurpose.GIT_SMART_FETCH,
        approval_reference="different-ref",
    )
    with pytest.raises(ValueError, match="duplicate grant hostname"):
        validate_grant_set((first, second))


def test_validate_grant_set_rejects_non_grant_entries():
    with pytest.raises(ValueError, match="NetworkGrant"):
        validate_grant_set((_grant(HOST_A, "g-1"), "not-a-grant"))


def test_authorize_time_ambiguity_is_precluded_by_construction():
    """Two same-hostname grants would be AMBIGUOUS_GRANTS at authorize time;
    the set validator rejects the shape before any launch or adoption, so the
    ambiguous policy is unbuildable through the validated path."""
    first = _grant(HOST_A, "g-1")
    second = _grant(HOST_A, "g-2")
    policy = _policy((first, second))
    outcome = authorize_grant(policy, HOST_A, at_monotonic_ns=T0)
    assert outcome.code is AuthorizationCode.AMBIGUOUS_GRANTS
    with pytest.raises(ValueError, match="duplicate grant hostname"):
        validate_grant_set(policy.grants)


# ---------------------------------------------------------------------------
# Wildcard / suffix / numeric authority in the multi-grant context
# ---------------------------------------------------------------------------


def test_wildcard_grant_is_unbuildable():
    """No wildcard can ever occupy a grant slot: the single normalization
    point rejects the form, so a NetworkPolicy CANNOT contain one."""
    with pytest.raises(NormalizationError):
        canonicalize_hostname("*.example.com")
    with pytest.raises(ValueError):
        _grant("*.example.com", "g-wild")


def test_suffix_of_granted_hostname_is_not_authorized():
    policy = _policy((_grant("example.com", "g-root"), _grant("example.org", "g-org")))
    outcome = authorize_grant(policy, "sub.example.com", at_monotonic_ns=T0)
    assert outcome.code is AuthorizationCode.NO_MATCH
    granted = authorize_grant(policy, "example.com", at_monotonic_ns=T0)
    assert granted.authorized


def test_trailing_dot_authority_never_matches_grant():
    policy = _policy(_two_grants())
    with pytest.raises(NormalizationError):
        normalize_https_authority(b"alpha.example.com.")
    with pytest.raises(NormalizationError):
        normalize_https_authority(b"alpha.example.com.:443")
    outcome = authorize_grant(policy, HOST_A, at_monotonic_ns=T0)
    assert outcome.authorized


def test_case_folds_only_at_the_authority_boundary():
    """A grant must be built from the canonical form (uppercase rejects); a
    case-variant AUTHORITY canonicalizes at its own boundary and then
    matches the canonical grant by byte equality."""
    with pytest.raises(ValueError, match="canonical"):
        _grant("ALPHA.example.com", "g-case")
    policy = _policy(_two_grants())
    authority = normalize_https_authority(b"ALPHA.EXAMPLE.COM:443")
    assert authority == HOST_A
    outcome = authorize_grant(policy, authority, at_monotonic_ns=T0)
    assert outcome.authorized
    assert outcome.grant.hostname == HOST_A


@pytest.mark.parametrize(
    "numeric",
    ["127.0.0.1", "127.1", "1.2.3", "0177.0.0.1", "2130706433", "0x7f.1"],
)
def test_numeric_forms_are_unbuildable_grants(numeric):
    """IP literals and inet_aton legacy numerics are not hostnames: no grant
    slot can ever name one, so the grant set cannot smuggle a numeric
    authority past the DNS/SSRF posture."""
    with pytest.raises(NormalizationError):
        canonicalize_hostname(numeric)
    with pytest.raises(ValueError):
        _grant(numeric, "g-numeric")


# ---------------------------------------------------------------------------
# Per-grant activity windows
# ---------------------------------------------------------------------------


def test_expired_grant_denied_while_peer_grant_active():
    expired = _grant(
        HOST_A,
        "g-alpha",
        activated_at_monotonic_ns=T0,
        expires_at_monotonic_ns=T0 + 1,
    )
    active = _grant(HOST_B, "g-beta")
    policy = _policy((expired, active))
    outcome_a = authorize_grant(policy, HOST_A, at_monotonic_ns=T0 + 2)
    assert outcome_a.code is AuthorizationCode.NO_ACTIVE_GRANT
    outcome_b = authorize_grant(policy, HOST_B, at_monotonic_ns=T0 + 2)
    assert outcome_b.authorized
    assert outcome_b.grant.grant_id == "g-beta"


# ---------------------------------------------------------------------------
# Serialization / digest determinism for the bounded grant set
# ---------------------------------------------------------------------------


def test_four_grant_policy_digest_independent_of_input_order():
    grants = _four_grants()
    base = _policy(grants)
    reversed_policy = _policy(tuple(reversed(grants)))
    rotated = _policy(grants[2:] + grants[:2])
    assert canonical_network_policy_bytes(base) == canonical_network_policy_bytes(
        reversed_policy
    )
    assert canonical_network_policy_bytes(base) == canonical_network_policy_bytes(
        rotated
    )
    assert network_policy_digest(base) == network_policy_digest(reversed_policy)
    assert network_policy_digest(base) == network_policy_digest(rotated)


def test_minted_style_grant_ids_are_distinct_and_accepted():
    ids = tuple(f"g{NONCE[:12]}x{index:02d}" for index in range(2))
    assert len(set(ids)) == 2
    policy = _policy((_grant(HOST_A, ids[0]), _grant(HOST_B, ids[1])))
    assert tuple(grant.grant_id for grant in policy.grants) == ids


@linux_only
def test_four_grant_sealed_round_trip_under_cap():
    from agenticos.sandbox.network_https import (
        create_sealed_network_policy_fd,
        read_sealed_network_policy_fd,
    )

    policy = _policy(_four_grants())
    fd = create_sealed_network_policy_fd(policy)
    try:
        assert os.fstat(fd).st_size <= 16384
        verified = read_sealed_network_policy_fd(fd)
    finally:
        os.close(fd)
    assert verified.policy == policy
    assert verified.digest == network_policy_digest(policy)


# ---------------------------------------------------------------------------
# Broker adoption / serve grant-set bounds (Linux)
# ---------------------------------------------------------------------------


def _deny_transport_policy(**changes):
    now = time.monotonic_ns()
    values = {
        "version": "AOSNET/1",
        "task_id": TASK_ID,
        "task_generation": 1,
        "launch_nonce": NONCE,
        "mode": TransportMode.DENY,
        "proxy_host": "127.0.0.1",
        "proxy_port": 18080,
        "activated_at_monotonic_ns": now - 1_000_000_000,
        "expires_at_monotonic_ns": now + 60_000_000_000,
        "connection_limit": 8,
        "byte_limit": 1 << 20,
    }
    values.update(changes)
    return TransportPolicy(**values)


@linux_only
def test_broker_serve_rejects_five_grant_policy():
    broker = _broker()
    policy = _deny_transport_policy()
    five = tuple(
        _grant(f"host{index}.example.com", f"g-{index}") for index in range(5)
    )
    network_policy = _policy(five)
    https_state = broker._HttpsMaterialState(
        network_policy=network_policy,
        network_policy_digest=network_policy_digest(network_policy),
        binding=None,
        server_context=None,
    )
    with pytest.raises(broker.BrokerBoundaryError, match="grant set"):
        broker.serve_https_transport(policy, https_state, listener_fd=-1, control_fd=-1)


@linux_only
def test_broker_adoption_rejects_five_grant_policy(tmp_path):
    broker = _broker()
    from agenticos.sandbox.network_identity import read_sealed_policy_fd
    from test_m4b_https_unit import (
        _adoption_fixture,
        _cleanup_installed,
        _grant as _adoption_grant,
        _transport_policy as _adoption_policy,
    )

    policy = _adoption_policy()
    five = tuple(
        _adoption_grant(f"host{index}.example.com", policy, grant_id=f"g-{index}")
        for index in range(5)
    )
    _p, _m, _np, contract, installed = _adoption_fixture(
        tmp_path, policy=policy, network_policy_changes={"grants": five}
    )
    try:
        sealed = read_sealed_policy_fd(30)
        with pytest.raises(broker.BrokerBoundaryError, match="grant set"):
            broker._adopt_https_material(contract, sealed)
    finally:
        _cleanup_installed(installed)


@linux_only
def test_serve_state_zero_grant_posture_preserved():
    broker = _broker()
    policy = _deny_transport_policy()
    network_policy = _policy(())
    https_state = broker._HttpsMaterialState(
        network_policy=network_policy,
        network_policy_digest=network_policy_digest(network_policy),
        binding=None,
        server_context=None,
    )
    serve = broker._HttpsServeState(policy, https_state, -1)
    # The deny-all posture is unchanged: no grant exists, authority comes
    # from the transport policy alone.
    assert serve.sole_grant is None
    assert serve.grant_accounting == {}
    assert serve.connection_limit == policy.connection_limit
    assert serve.accountant.limit == policy.byte_limit


@linux_only
def test_serve_state_two_grants_builds_per_grant_accounting():
    broker = _broker()
    policy = _deny_transport_policy()
    network_policy = _policy(_two_grants())
    https_state = broker._HttpsMaterialState(
        network_policy=network_policy,
        network_policy_digest=network_policy_digest(network_policy),
        binding=None,
        server_context=None,
    )
    serve = broker._HttpsServeState(policy, https_state, -1)
    # Several grants: no sole-grant evidence fallback; per-grant accounting
    # keyed by canonical hostname, bounded by the grant-set size.
    assert serve.sole_grant is None
    assert set(serve.grant_accounting) == {HOST_A, HOST_B}
    assert len(serve.grant_accounting) <= CONNECTED_BUILD_MAX_GRANTS


# ---------------------------------------------------------------------------
# In-process broker serve flows across a 2-grant policy (Linux)
# ---------------------------------------------------------------------------


def _serve_network_policy(policy, grants):
    return NetworkPolicy(
        version="AOSHTTPS/1",
        task_id=policy.task_id,
        task_generation=policy.task_generation,
        launch_nonce=policy.launch_nonce,
        task_ca_certificate_digest=CA_DIGEST,
        openssl_runtime_identity=ssl.OPENSSL_VERSION,
        grants=grants,
    )


def _serve_grant(hostname, policy, grant_id, **changes):
    values = {
        "grant_id": grant_id,
        "hostname": hostname,
        "purpose": GrantPurpose.GENERAL_DOWNLOAD,
        "approval_source": "m4b3-unit",
        "approval_reference": "serve-1",
        "granted_at_wall_ns": time.time_ns(),
        "expires_at_wall_ns": time.time_ns() + 3_600_000_000_000,
        "activated_at_monotonic_ns": policy.activated_at_monotonic_ns,
        "expires_at_monotonic_ns": policy.expires_at_monotonic_ns,
        "connection_limit": policy.connection_limit,
        "byte_limit": policy.byte_limit,
    }
    values.update(changes)
    return NetworkGrant(**values)


@pytest.fixture(scope="module")
def two_host_leaf():
    """One genuine multi-SAN helper leaf (alpha+beta) shared read-only."""
    cert_helper = _cert_helper()
    material = cert_helper.generate_task_material(
        task_id=TASK_ID,
        task_generation=1,
        launch_nonce=NONCE,
        hostnames=SERVE_HOSTS,
        policy_digest="ab" * 32,
    )
    try:
        context = cert_helper.load_leaf_ssl_context(
            ca_cert_fd=material.ca_cert_fd,
            leaf_cert_fd=material.leaf_cert_fd,
            leaf_key_fd=material.leaf_key_fd,
            binding_fd=material.binding_fd,
            task_id=TASK_ID,
            task_generation=1,
            launch_nonce=NONCE,
            hostnames=SERVE_HOSTS,
            policy_digest="ab" * 32,
        )
        ca_pem = os.pread(
            material.ca_cert_fd, os.fstat(material.ca_cert_fd).st_size, 0
        ).decode("ascii")
        yield {"context": context, "ca_pem": ca_pem}
    finally:
        material.close()


class _ServeHarness:
    """One in-process 2-grant serve state plus its evidence channel."""

    def __init__(self, policy, network_policy, context):
        broker = _broker()
        https_state = broker._HttpsMaterialState(
            network_policy=network_policy,
            network_policy_digest=network_policy_digest(network_policy),
            binding=None,
            server_context=context,
        )
        self.control_broker, self.control_peer = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET
        )
        self.serve = broker._HttpsServeState(
            policy, https_state, self.control_broker.fileno()
        )
        self.origins = []

    def arm_origin(self, origin, pems, addresses=("93.184.216.34",)):
        broker = _broker()
        self.origins.append(origin)
        fixture = broker._HttpsFixtureState(
            origin.fd, pems["ca"].decode("ascii"), tuple(addresses)
        )
        # Mirrors the broker's ARM verb: the first origin is active, the
        # rest queue and rotate in, in arming order, as each is spent.
        if self.serve.fixture is None:
            self.serve.fixture = fixture
        else:
            self.serve.fixture_queue.append(fixture)

    def read_record(self):
        broker = _broker()
        self.control_peer.settimeout(5.0)
        payload = self.control_peer.recv(broker.MAX_HTTPS_EVIDENCE_BYTES + 1)
        return broker.HttpsConnectionRecord.from_bytes(payload)

    def close(self):
        for origin in self.origins:
            origin.close()
        for origin in self.origins:
            origin.join()
        self.control_peer.close()
        self.control_broker.close()


def _harness(policy, grants, leaf):
    network_policy = _serve_network_policy(policy, grants)
    return _ServeHarness(policy, network_policy, leaf["context"])


def _drive_connection(harness, leaf, index, *, authority, expect, sni=None,
                      request=None, timeout=10.0):
    """Run one in-process worker connection; return (record, response)."""
    broker = _broker()
    from test_m4b_https_unit import (
        _close_tls,
        _read_worker_response,
        _worker_connect,
        _worker_tls,
    )

    worker_broker, worker_client = socket.socketpair()
    runtime = broker._HttpsConnectionRuntime(worker_broker)
    harness.serve.runtimes.append(runtime)
    thread = threading.Thread(
        target=broker._serve_https_connection,
        args=(harness.serve, runtime, index),
        daemon=True,
    )
    thread.start()
    tls = None
    response = None
    try:
        reply = _worker_connect(worker_client, authority)
        if expect == "connect_denied":
            assert reply.startswith(b"HTTP/1.1 403"), reply
        else:
            assert reply.startswith(b"HTTP/1.1 200"), reply
            host = authority.split(":")[0]
            if expect == "tls_fail":
                with pytest.raises(ssl.SSLError):
                    _worker_tls(
                        worker_client,
                        leaf["ca_pem"],
                        sni=sni or host,
                        timeout=timeout,
                    )
            else:
                tls = _worker_tls(
                    worker_client, leaf["ca_pem"], sni=sni or host, timeout=timeout
                )
                if request is not None:
                    tls.sendall(request)
                    response = _read_worker_response(tls)
    finally:
        if tls is not None:
            _close_tls(tls)
        try:
            worker_client.close()
        except OSError:
            pass
    thread.join(15.0)
    assert not thread.is_alive(), "serve connection thread stuck"
    record = harness.read_record()
    return record, response


@linux_only
def test_serve_two_grants_ungranted_connect_denied(two_host_leaf):
    policy = _deny_transport_policy()
    harness = _harness(policy, _two_grants_serving(policy), two_host_leaf)
    try:
        record, _response = _drive_connection(
            harness, two_host_leaf, 1, authority=HOST_UNGRANTED,
            expect="connect_denied",
        )
        assert record.stage_reached.value == "authorization"
        assert record.terminal_reason.value == "denied"
        assert record.detail == "authorization_no_match"
        # Several grants and no per-connection selection: the deny-all
        # identity posture is the honest evidence shape.
        assert record.identity_chain == "no_grant"
        assert record.approved_hostname is None
        assert not harness.serve.thread_errors
    finally:
        harness.close()


def _two_grants_serving(policy, **per_host):
    return (
        _serve_grant(HOST_A, policy, "g-alpha", **per_host.get(HOST_A, {})),
        _serve_grant(HOST_B, policy, "g-beta", **per_host.get(HOST_B, {})),
    )


@linux_only
def test_serve_cross_grant_sni_mismatch_denied(two_host_leaf):
    """Both hosts are granted, yet mixing them across stages fails closed:
    CONNECT for A with SNI for B is a divergence against A's grant."""
    policy = _deny_transport_policy()
    harness = _harness(policy, _two_grants_serving(policy), two_host_leaf)
    try:
        record_a, _ = _drive_connection(
            harness, two_host_leaf, 1, authority=HOST_A, sni=HOST_B,
            expect="tls_fail",
        )
        assert record_a.approved_hostname == HOST_A
        assert record_a.worker_sni == HOST_B
        assert record_a.detail == "worker_tls_sni_mismatch"
        assert record_a.identity_chain == "identity_divergence:worker_sni"
        record_b, _ = _drive_connection(
            harness, two_host_leaf, 2, authority=HOST_B, sni=HOST_A,
            expect="tls_fail",
        )
        assert record_b.approved_hostname == HOST_B
        assert record_b.worker_sni == HOST_A
        assert record_b.detail == "worker_tls_sni_mismatch"
        assert record_b.identity_chain == "identity_divergence:worker_sni"
        assert not harness.serve.thread_errors
    finally:
        harness.close()


@linux_only
def test_serve_cross_grant_http_host_mismatch_denied(two_host_leaf):
    """CONNECT + SNI for A but an HTTP Host naming B (also granted) still
    fails closed against A's grant at the HTTP stage."""
    policy = _deny_transport_policy()
    harness = _harness(policy, _two_grants_serving(policy), two_host_leaf)
    try:
        request = f"GET / HTTP/1.1\r\nHost: {HOST_B}\r\n\r\n".encode("ascii")
        record, response = _drive_connection(
            harness, two_host_leaf, 1, authority=HOST_A, expect="tls",
            request=request,
        )
        assert response is None  # denial forwards nothing; broker closes
        assert record.approved_hostname == HOST_A
        assert record.http_host == HOST_B
        assert record.detail == "http_host_mismatch"
        assert record.terminal_reason.value == "denied"
        assert record.identity_chain == "identity_divergence:http_host"
        assert not harness.serve.thread_errors
    finally:
        harness.close()


@linux_only
def test_serve_expired_grant_denied_while_active_peer_serves(
    tmp_path, two_host_leaf
):
    from test_m4b_https_unit import _ScriptedOrigin, _ok_responder, _origin_pems

    policy = _deny_transport_policy()
    expired_a = _serve_grant(
        HOST_A,
        policy,
        "g-alpha",
        activated_at_monotonic_ns=policy.activated_at_monotonic_ns,
        expires_at_monotonic_ns=policy.activated_at_monotonic_ns + 1,
    )
    active_b = _serve_grant(HOST_B, policy, "g-beta")
    harness = _harness(policy, (expired_a, active_b), two_host_leaf)
    try:
        record_a, _ = _drive_connection(
            harness, two_host_leaf, 1, authority=HOST_A, expect="connect_denied",
        )
        assert record_a.detail == "authorization_no_active_grant"
        assert record_a.approved_hostname is None
        pems = _origin_pems(HOST_B)
        origin = _ScriptedOrigin(
            tmp_path, pems, _ok_responder(body=b"m4b3-beta-body")
        )
        harness.arm_origin(origin, pems)
        record_b, response = _drive_connection(
            harness,
            two_host_leaf,
            2,
            authority=HOST_B,
            expect="tls",
            request=f"GET / HTTP/1.1\r\nHost: {HOST_B}\r\n\r\n".encode("ascii"),
        )
        assert response is not None and b"m4b3-beta-body" in response
        assert record_b.approved_hostname == HOST_B
        assert record_b.identity_chain == "verified"
        assert record_b.terminal_reason.value == "completed"
        assert record_b.requests_completed == 1
        assert origin.requests == [
            f"GET / HTTP/1.1\r\nHost: {HOST_B}\r\n\r\n".encode("ascii")
        ]
        assert origin.errors == []
        assert not harness.serve.thread_errors
    finally:
        harness.close()


@linux_only
def test_serve_per_grant_connection_limit_denies_only_that_grant(
    tmp_path, two_host_leaf
):
    """Grant A is limited to ONE connection; the policy aggregate allows
    many.  The second A connection is denied per-grant while B still serves."""
    from test_m4b_https_unit import _ScriptedOrigin, _ok_responder, _origin_pems

    policy = _deny_transport_policy()
    grants = _two_grants_serving(policy, **{HOST_A: {"connection_limit": 1}})
    harness = _harness(policy, grants, two_host_leaf)
    try:
        pems_a = _origin_pems(HOST_A)
        origin_a_dir = tmp_path / "a"
        origin_a_dir.mkdir()
        origin_a = _ScriptedOrigin(
            origin_a_dir, pems_a, _ok_responder(body=b"m4b3-alpha-body")
        )
        harness.arm_origin(origin_a, pems_a)
        record_a1, response = _drive_connection(
            harness,
            two_host_leaf,
            1,
            authority=HOST_A,
            expect="tls",
            request=f"GET / HTTP/1.1\r\nHost: {HOST_A}\r\n\r\n".encode("ascii"),
        )
        assert response is not None and b"m4b3-alpha-body" in response
        assert record_a1.approved_hostname == HOST_A
        assert record_a1.identity_chain == "verified"
        record_a2, _ = _drive_connection(
            harness, two_host_leaf, 2, authority=HOST_A, expect="connect_denied",
        )
        assert record_a2.detail == "grant_connection_limit"
        assert record_a2.terminal_reason.value == "denied"
        assert record_a2.stage_reached.value == "authorization"
        pems_b = _origin_pems(HOST_B)
        origin_b_dir = tmp_path / "b"
        origin_b_dir.mkdir()
        origin_b = _ScriptedOrigin(
            origin_b_dir, pems_b, _ok_responder(body=b"m4b3-beta-body")
        )
        # The queued second origin rotates in for B's connection.
        harness.serve.fixture_queue.append(
            _broker()._HttpsFixtureState(
                origin_b.fd,
                pems_b["ca"].decode("ascii"),
                ("93.184.216.34",),
            )
        )
        harness.origins.append(origin_b)
        record_b, response_b = _drive_connection(
            harness,
            two_host_leaf,
            3,
            authority=HOST_B,
            expect="tls",
            request=f"GET / HTTP/1.1\r\nHost: {HOST_B}\r\n\r\n".encode("ascii"),
        )
        assert response_b is not None and b"m4b3-beta-body" in response_b
        assert record_b.approved_hostname == HOST_B
        assert record_b.identity_chain == "verified"
        # The policy-aggregate limit was never tripped.
        assert not harness.serve.byte_limit_reached
        assert not harness.serve.thread_errors
    finally:
        harness.close()


# ---------------------------------------------------------------------------
# Per-grant byte-limit machinery (Linux, in-process serve)
# ---------------------------------------------------------------------------


def _expected_response(body):
    """Byte-exact response produced by _ok_responder(keepalive=False)."""
    return (
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\nConnection: close\r\n\r\n" + body
    )


@linux_only
def test_serve_grant_byte_limit_worker_to_origin_leg(tmp_path, two_host_leaf):
    """The worker->origin leg is reachable: the GIT_SMART_FETCH grant admits
    POST bodies, and a body exceeding the grant's own byte limit terminates
    the connection at the HTTP stage BEFORE any origin round trip."""
    from test_m4b_https_unit import _ScriptedOrigin, _ok_responder, _origin_pems

    body = b"x" * 32
    request = (
        f"POST /git-upload-pack HTTP/1.1\r\nHost: {HOST_B}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("ascii") + body
    policy = _deny_transport_policy()
    grants = (
        _serve_grant(HOST_A, policy, "g-alpha"),
        _serve_grant(
            HOST_B,
            policy,
            "g-beta",
            purpose=GrantPurpose.GIT_SMART_FETCH,
            byte_limit=48,
        ),
    )
    harness = _harness(policy, grants, two_host_leaf)
    try:
        pems = _origin_pems(HOST_B)
        origin = _ScriptedOrigin(tmp_path, pems, _ok_responder(body=b"unused"))
        harness.arm_origin(origin, pems)
        record, response = _drive_connection(
            harness, two_host_leaf, 1, authority=HOST_B, expect="tls",
            request=request,
        )
        assert response is None  # denial forwards nothing; broker closes
        assert record.approved_hostname == HOST_B
        assert record.stage_reached.value == "http_prevalidation"
        assert record.terminal_reason.value == "byte_limit"
        assert record.detail == "grant_byte_limit"
        assert record.requests_completed == 0
        # The grant's accounted bytes are a HARD bound even at termination.
        assert harness.serve.grant_accounting[HOST_B].accounted <= 48
        assert not harness.serve.byte_limit_reached
        origin.close()  # unblock the never-used origin's handshake wait
        origin.join()
        assert origin.requests == []
        assert not harness.serve.thread_errors
    finally:
        harness.close()


@linux_only
def test_serve_grant_byte_limit_origin_to_worker_leg(tmp_path, two_host_leaf):
    """A response larger than the grant's byte limit terminates the relay
    with grant_byte_limit; the OTHER grant then completes a full verified
    session and the policy-aggregate posture is never tripped."""
    from test_m4b_https_unit import _ScriptedOrigin, _ok_responder, _origin_pems

    body_a = b"m4b3-alpha-response-payload"
    request_a = f"GET / HTTP/1.1\r\nHost: {HOST_A}\r\n\r\n".encode("ascii")
    tight = len(request_a) + len(_expected_response(body_a)) - 8
    policy = _deny_transport_policy()
    grants = _two_grants_serving(policy, **{HOST_A: {"byte_limit": tight}})
    harness = _harness(policy, grants, two_host_leaf)
    try:
        pems_a = _origin_pems(HOST_A)
        origin_a = _ScriptedOrigin(
            tmp_path, pems_a, _ok_responder(body=body_a, keepalive=False)
        )
        harness.arm_origin(origin_a, pems_a)
        record_a, response_a = _drive_connection(
            harness, two_host_leaf, 1, authority=HOST_A, expect="tls",
            request=request_a,
        )
        assert response_a is None or _expected_response(body_a) not in response_a
        assert record_a.approved_hostname == HOST_A
        assert record_a.terminal_reason.value == "byte_limit"
        assert record_a.detail == "grant_byte_limit"
        assert record_a.stage_reached.value == "http_prevalidation"
        assert harness.serve.grant_accounting[HOST_A].accounted <= tight
        # The policy-aggregate posture stands: B still serves fully.
        assert not harness.serve.byte_limit_reached
        pems_b = _origin_pems(HOST_B)
        origin_b_dir = tmp_path / "b"
        origin_b_dir.mkdir()
        origin_b = _ScriptedOrigin(
            origin_b_dir, pems_b, _ok_responder(body=b"m4b3-beta-body")
        )
        harness.arm_origin(origin_b, pems_b)
        record_b, response_b = _drive_connection(
            harness,
            two_host_leaf,
            2,
            authority=HOST_B,
            expect="tls",
            request=f"GET / HTTP/1.1\r\nHost: {HOST_B}\r\n\r\n".encode("ascii"),
        )
        assert response_b is not None and b"m4b3-beta-body" in response_b
        assert record_b.approved_hostname == HOST_B
        assert record_b.identity_chain == "verified"
        assert not harness.serve.thread_errors
    finally:
        harness.close()


@linux_only
@pytest.mark.parametrize("delta", [0, -1])
def test_serve_grant_byte_limit_exact_boundary(tmp_path, two_host_leaf, delta):
    """Off-by-one: byte_limit == exact request+response size succeeds;
    one byte less fails the relay with grant_byte_limit."""
    from test_m4b_https_unit import _ScriptedOrigin, _ok_responder, _origin_pems

    body = b"m4b3-boundary-body"
    request = f"GET / HTTP/1.1\r\nHost: {HOST_A}\r\n\r\n".encode("ascii")
    response_expected = _expected_response(body)
    exact = len(request) + len(response_expected)
    policy = _deny_transport_policy()
    grants = (
        _serve_grant(HOST_A, policy, "g-alpha", byte_limit=exact + delta),
        _serve_grant(HOST_B, policy, "g-beta"),
    )
    harness = _harness(policy, grants, two_host_leaf)
    try:
        pems = _origin_pems(HOST_A)
        origin = _ScriptedOrigin(
            tmp_path, pems, _ok_responder(body=body, keepalive=False)
        )
        harness.arm_origin(origin, pems)
        record, response = _drive_connection(
            harness, two_host_leaf, 1, authority=HOST_A, expect="tls",
            request=request,
        )
        if delta == 0:
            assert response is not None and body in response
            assert record.identity_chain == "verified"
            assert record.requests_completed == 1
            assert (
                harness.serve.grant_accounting[HOST_A].accounted == exact
            )
        else:
            assert record.terminal_reason.value == "byte_limit"
            assert record.detail == "grant_byte_limit"
            # The request forwards completely; the RELAY leg exhausts.
            assert record.requests_completed == 1
            assert (
                harness.serve.grant_accounting[HOST_A].accounted <= exact - 1
            )
        assert not harness.serve.byte_limit_reached
        assert not harness.serve.thread_errors
    finally:
        harness.close()


def _drive_two_concurrent(harness, leaf, authority, request):
    """Drive two simultaneous same-grant connections; return their records."""
    broker = _broker()
    from test_m4b_https_unit import (
        _close_tls,
        _read_worker_response,
        _worker_connect,
        _worker_tls,
    )

    workers = []
    threads = []
    for index in (1, 2):
        worker_broker, worker_client = socket.socketpair()
        runtime = broker._HttpsConnectionRuntime(worker_broker)
        harness.serve.runtimes.append(runtime)
        thread = threading.Thread(
            target=broker._serve_https_connection,
            args=(harness.serve, runtime, index),
            daemon=True,
        )
        thread.start()
        threads.append(thread)
        workers.append(worker_client)
    replies = [_worker_connect(client, authority) for client in workers]
    assert all(reply.startswith(b"HTTP/1.1 200") for reply in replies), replies
    tls_clients = [
        _worker_tls(client, leaf["ca_pem"], sni=authority) for client in workers
    ]
    for tls in tls_clients:
        tls.sendall(request)
    responses = [_read_worker_response(tls) for tls in tls_clients]
    for tls in tls_clients:
        _close_tls(tls)
    for client in workers:
        try:
            client.close()
        except OSError:
            pass
    for thread in threads:
        thread.join(15.0)
        assert not thread.is_alive(), "concurrent serve thread stuck"
    return [harness.read_record(), harness.read_record()], responses


@linux_only
def test_serve_concurrent_same_grant_byte_limit_is_hard_bound(
    tmp_path, two_host_leaf
):
    """Two simultaneous connections to ONE grant with a byte_limit fitting
    exactly one session: at most one completes, at least one fails loud with
    grant_byte_limit, and the grant's accounted bytes NEVER exceed its
    limit — the pre-reservation race (both observing the same budget) cannot
    silently debit the shared aggregate."""
    from test_m4b_https_unit import _ScriptedOrigin, _ok_responder, _origin_pems

    body = b"m4b3-race-body"
    request = f"GET / HTTP/1.1\r\nHost: {HOST_A}\r\n\r\n".encode("ascii")
    exact = len(request) + len(_expected_response(body))
    policy = _deny_transport_policy()
    grants = (
        _serve_grant(HOST_A, policy, "g-alpha", byte_limit=exact),
        _serve_grant(HOST_B, policy, "g-beta"),
    )
    harness = _harness(policy, grants, two_host_leaf)
    try:
        for slot in ("a1", "a2"):
            pems = _origin_pems(HOST_A)
            origin_dir = tmp_path / slot
            origin_dir.mkdir()
            origin = _ScriptedOrigin(
                origin_dir, pems, _ok_responder(body=body, keepalive=False)
            )
            harness.arm_origin(origin, pems)
        records, responses = _drive_two_concurrent(
            harness, two_host_leaf, HOST_A, request
        )
        assert harness.serve.grant_accounting[HOST_A].accounted <= exact
        completed = [
            record for record in records if record.terminal_reason.value == "completed"
        ]
        limited = [
            record
            for record in records
            if record.detail == "grant_byte_limit"
        ]
        assert len(completed) <= 1
        assert len(limited) >= 1, records
        full = [r for r in responses if r is not None and body in r]
        assert len(full) <= 1
        assert not harness.serve.byte_limit_reached
        assert not harness.serve.thread_errors
    finally:
        harness.close()


FOUR_HOSTS = (HOST_A, HOST_B, "charlie.example.com", "delta.example.com")


@pytest.fixture(scope="module")
def four_host_leaf():
    """One genuine 4-SAN helper leaf shared read-only."""
    cert_helper = _cert_helper()
    material = cert_helper.generate_task_material(
        task_id=TASK_ID,
        task_generation=1,
        launch_nonce=NONCE,
        hostnames=FOUR_HOSTS,
        policy_digest="ab" * 32,
    )
    try:
        context = cert_helper.load_leaf_ssl_context(
            ca_cert_fd=material.ca_cert_fd,
            leaf_cert_fd=material.leaf_cert_fd,
            leaf_key_fd=material.leaf_key_fd,
            binding_fd=material.binding_fd,
            task_id=TASK_ID,
            task_generation=1,
            launch_nonce=NONCE,
            hostnames=FOUR_HOSTS,
            policy_digest="ab" * 32,
        )
        ca_pem = os.pread(
            material.ca_cert_fd, os.fstat(material.ca_cert_fd).st_size, 0
        ).decode("ascii")
        yield {"context": context, "ca_pem": ca_pem}
    finally:
        material.close()


@linux_only
def test_serve_four_grant_flow_rotates_fixture_queue(tmp_path, four_host_leaf):
    """The full Connected Build cardinality: four granted hostnames, four
    armed synthetic origins consumed in arming order through the fixture
    queue, and four independently verified evidence records."""
    from test_m4b_https_unit import _ScriptedOrigin, _ok_responder, _origin_pems

    policy = _deny_transport_policy()
    grants = tuple(
        _serve_grant(host, policy, f"g-{index:02d}")
        for index, host in enumerate(FOUR_HOSTS)
    )
    harness = _harness(policy, grants, four_host_leaf)
    try:
        assert len(harness.serve.grant_accounting) == 4
        assert harness.serve.sole_grant is None
        for index, host in enumerate(FOUR_HOSTS):
            pems = _origin_pems(host)
            origin_dir = tmp_path / f"origin-{index}"
            origin_dir.mkdir()
            origin = _ScriptedOrigin(
                origin_dir,
                pems,
                _ok_responder(body=f"m4b3-body-{index}".encode("ascii")),
            )
            harness.arm_origin(origin, pems)
        assert len(harness.serve.fixture_queue) == 3
        for index, host in enumerate(FOUR_HOSTS):
            record, response = _drive_connection(
                harness,
                four_host_leaf,
                index + 1,
                authority=host,
                expect="tls",
                request=f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii"),
            )
            assert response is not None
            assert f"m4b3-body-{index}".encode("ascii") in response
            assert record.approved_hostname == host
            assert record.identity_chain == "verified"
            assert record.terminal_reason.value == "completed"
            assert record.requests_completed == 1
        for index, host in enumerate(FOUR_HOSTS):
            assert harness.origins[index].requests == [
                f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii")
            ]
            assert harness.origins[index].errors == []
        assert not harness.serve.thread_errors
    finally:
        harness.close()


# ---------------------------------------------------------------------------
# Controller-side grant-spec validation (Linux: m4b_runner import)
# ---------------------------------------------------------------------------


def _spec(hostname, **changes):
    runner = _runner()
    values = {
        "hostname": hostname,
        "purpose": GrantPurpose.GENERAL_DOWNLOAD,
        "approval_source": "m4b3-unit",
        "approval_reference": "ref-1",
    }
    values.update(changes)
    return runner.HostGrantSpec(**values)


def _validate(**kwargs):
    runner = _runner()
    defaults = {
        "approved_hostname": None,
        "grant_purpose": None,
        "approval_source": None,
        "approval_reference": None,
        "approved_grants": None,
    }
    defaults.update(kwargs)
    return runner.HttpsCapabilityTransportRunner._validate_grant_specs(**defaults)


def _single_form(**changes):
    values = {
        "approved_hostname": HOST_A,
        "grant_purpose": GrantPurpose.GENERAL_DOWNLOAD,
        "approval_source": "m4b3-unit",
        "approval_reference": "ref-1",
    }
    values.update(changes)
    return values


@linux_only
def test_runner_single_host_form_still_works():
    specs = _validate(**_single_form())
    assert len(specs) == 1
    assert specs[0].hostname == HOST_A
    assert specs[0].purpose is GrantPurpose.GENERAL_DOWNLOAD


@linux_only
def test_runner_grant_forms_are_mutually_exclusive():
    runner = _runner()
    with pytest.raises(
        runner.CapabilityTransportError, match="mutually exclusive"
    ):
        _validate(**_single_form(approved_grants=(_spec(HOST_B),)))


@linux_only
@pytest.mark.parametrize(
    "missing",
    ["approved_hostname", "grant_purpose", "approval_source", "approval_reference"],
)
def test_runner_single_form_requires_complete_set(missing):
    runner = _runner()
    with pytest.raises(runner.CapabilityTransportError, match="single-host"):
        _validate(**_single_form(**{missing: None}))


@linux_only
def test_runner_approved_grants_rejects_empty_tuple():
    runner = _runner()
    with pytest.raises(runner.CapabilityTransportError, match="1.."):
        _validate(approved_grants=())


@linux_only
def test_runner_approved_grants_rejects_five():
    runner = _runner()
    grants = tuple(_spec(f"host{index}.example.com") for index in range(5))
    with pytest.raises(runner.CapabilityTransportError, match="1.."):
        _validate(approved_grants=grants)


@linux_only
def test_runner_approved_grants_accepts_four():
    grants = tuple(_spec(f"host{index}.example.com") for index in range(4))
    specs = _validate(approved_grants=grants)
    assert len(specs) == CONNECTED_BUILD_MAX_GRANTS


@linux_only
def test_runner_approved_grants_rejects_non_spec_entries():
    runner = _runner()
    with pytest.raises(runner.CapabilityTransportError, match="HostGrantSpec"):
        _validate(approved_grants=(_spec(HOST_A), "not-a-spec"))


@linux_only
def test_runner_spec_rejects_invalid_purpose_type():
    runner = _runner()
    with pytest.raises(runner.CapabilityTransportError, match="GrantPurpose"):
        _validate(approved_grants=(_spec(HOST_A, purpose="general_download"),))


@linux_only
@pytest.mark.parametrize("field", ["approval_source", "approval_reference"])
def test_runner_spec_rejects_non_string_approval(field):
    runner = _runner()
    with pytest.raises(runner.CapabilityTransportError, match="approval"):
        _validate(approved_grants=(_spec(HOST_A, **{field: None}),))


@linux_only
@pytest.mark.parametrize(
    "limits",
    [
        {"connection_limit": 0},
        {"connection_limit": -1},
        {"connection_limit": "8"},
        {"byte_limit": 0},
        {"byte_limit": -5},
        {"byte_limit": 1.5},
    ],
)
def test_runner_spec_rejects_invalid_limits(limits):
    runner = _runner()
    with pytest.raises(runner.CapabilityTransportError, match="limit"):
        _validate(approved_grants=(_spec(HOST_A, **limits),))


@linux_only
def test_runner_duplicate_hostname_rejected_even_with_distinct_purposes():
    runner = _runner()
    grants = (
        _spec(HOST_A, purpose=GrantPurpose.GENERAL_DOWNLOAD),
        _spec(
            HOST_A,
            purpose=GrantPurpose.GIT_SMART_FETCH,
            approval_reference="other-ref",
        ),
    )
    with pytest.raises(runner.CapabilityTransportError, match="duplicate"):
        _validate(approved_grants=grants)


@linux_only
def test_runner_spec_hostname_is_canonicalized():
    specs = _validate(approved_grants=(_spec("ALPHA.EXAMPLE.COM"),))
    assert specs[0].hostname == HOST_A


@linux_only
def test_grant_minting_mints_distinct_ids_and_policy_defaults(tmp_path):
    """The real minting path (no launch): two HostGrantSpecs produce two
    NetworkGrants with deterministic distinct ids; omitted limits default to
    the TransportPolicy limits and an explicit per-grant limit is kept."""
    runner = _runner()
    host_state = tmp_path / "host-state"
    runner.qualify_host_for_https(host_state)
    policy = _deny_transport_policy(connection_limit=6, byte_limit=123456)
    instance = object.__new__(runner.HttpsCapabilityTransportRunner)
    instance._transport_policy = policy
    instance._host_state_dir = host_state
    instance._helper_timeout = 15.0
    instance._grant_wall_lifetime_ns = 12 * 3600 * 1_000_000_000
    instance._grant_specs = (
        _spec(HOST_A),
        _spec(HOST_B, purpose=GrantPurpose.GIT_SMART_FETCH, connection_limit=2),
    )
    prepared = instance._assemble_https_material()
    try:
        grants = prepared.network_policy.grants
        assert len(grants) == 2
        expected_ids = (
            f"g{policy.launch_nonce[:12]}x00",
            f"g{policy.launch_nonce[:12]}x01",
        )
        assert tuple(grant.grant_id for grant in grants) == expected_ids
        first, second = grants
        assert first.hostname == HOST_A
        assert first.connection_limit == policy.connection_limit
        assert first.byte_limit == policy.byte_limit
        assert second.hostname == HOST_B
        assert second.purpose is GrantPurpose.GIT_SMART_FETCH
        assert second.connection_limit == 2
        assert second.byte_limit == policy.byte_limit
        # The sealed material commits exactly the sorted granted hostname set.
        assert prepared.material.binding.hostnames == SERVE_HOSTS
        assert prepared.network_policy.task_ca_certificate_digest == (
            prepared.material.binding.ca_cert_sha256
        )
    finally:
        os.close(prepared.sealed_network_policy_fd)
        prepared.material.close()
        shutil.rmtree(prepared.worker_ca_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Connected Build worker-environment profile
# ---------------------------------------------------------------------------


def _runtime_sources(boundary, tmp_path):
    def source(name, fd, file_type):
        return boundary.AuthorizedSource(
            locator=tmp_path / "host" / name,
            fd=fd,
            identity=boundary.FileIdentity(
                device=100 + fd, inode=200 + fd, file_type=file_type
            ),
        )

    return {
        "workspace": source("worktree", 10, stat.S_IFDIR),
        "runtime_usr": source("usr", 11, stat.S_IFDIR),
        "launcher": source("fs_launcher", 12, stat.S_IFREG),
        "worker": source("hostile_worker.py", 13, stat.S_IFREG),
        "task_tmp": source("task-tmp", 14, stat.S_IFDIR),
        "synthetic_home": source("home", 15, stat.S_IFDIR),
    }


@linux_only
def test_connected_build_worker_extra_env_exact_contents():
    runner = _runner()
    assert runner.CONNECTED_BUILD_WORKER_EXTRA_ENV == (
        ("https_proxy", "http://127.0.0.1:18080"),
        ("SSL_CERT_FILE", "/opt/agenticos/network-ca.pem"),
        ("CURL_CA_BUNDLE", "/opt/agenticos/network-ca.pem"),
        ("GIT_SSL_CAINFO", "/opt/agenticos/network-ca.pem"),
        ("REQUESTS_CA_BUNDLE", "/opt/agenticos/network-ca.pem"),
    )
    # Deliberately lowercase-only proxy variable; nothing else proxy-shaped
    # exists in the profile.
    names = {name for name, _value in runner.CONNECTED_BUILD_WORKER_EXTRA_ENV}
    assert "HTTPS_PROXY" not in names
    assert "HTTP_PROXY" not in names
    assert "ALL_PROXY" not in names
    assert "no_proxy" not in names


def test_extra_worker_env_appends_and_changes_digests(tmp_path):
    boundary = _runtime_boundary()
    sources = _runtime_sources(boundary, tmp_path)
    base = boundary.build_runtime_plan(
        profile=boundary.M4AProfile.BUILD, **sources
    )
    base_again = boundary.build_runtime_plan(
        profile=boundary.M4AProfile.BUILD, **sources
    )
    # The None posture stays byte-identical to today's base plan.
    assert base.worker_environment == boundary.WORKER_ENVIRONMENT
    assert base.environment_policy_digest == base_again.environment_policy_digest
    assert base.combined_policy_digest == base_again.combined_policy_digest
    assert base.digest_payload["environment"] == dict(boundary.WORKER_ENVIRONMENT)
    extra = (
        ("https_proxy", "http://127.0.0.1:18080"),
        ("SSL_CERT_FILE", "/opt/agenticos/network-ca.pem"),
    )
    extended = boundary.build_runtime_plan(
        profile=boundary.M4AProfile.BUILD,
        extra_worker_env=extra,
        **sources,
    )
    assert extended.worker_environment == boundary.WORKER_ENVIRONMENT + extra
    assert extended.digest_payload["environment"] == dict(
        boundary.WORKER_ENVIRONMENT + extra
    )
    assert extended.environment_policy_digest != base.environment_policy_digest
    assert extended.combined_policy_digest != base.combined_policy_digest
    # The filesystem view is untouched by the environment extension.
    assert extended.filesystem_view_digest == base.filesystem_view_digest


@pytest.mark.parametrize(
    "extra",
    [
        (("PATH", "/evil"),),                       # base-name collision
        (("PWD", "/evil"),),                        # base-name collision
        (("X_NEW", "1"), ("X_NEW", "2")),           # duplicate names
        (("1BAD", "x"),),                           # leading digit
        (("with-dash", "x"),),                      # non-identifier
        (("WITH SPACE", "x"),),                     # non-identifier
        (("", "x"),),                               # empty name
        (("X_OK", "a\x00b"),),                      # NUL
        (("X_OK", "a\rb"),),                        # CR
        (("X_OK", "a\nb"),),                        # LF
        (("X_OK", "a\x01b"),),                      # control byte
        (("X_OK", "café"),),                        # non-ASCII
        (("X_OK", "x" * 513),),                     # oversized value
        tuple((f"X_{index}", "v") for index in range(17)),  # too many entries
        (("X_ONLY",),),                             # not a pair
        (["X", "y"],),                              # non-tuple entry
    ],
)
def test_validate_extra_worker_env_rejection_matrix(extra):
    boundary = _runtime_boundary()
    with pytest.raises(ValueError):
        boundary._validate_extra_worker_env(extra)


def test_validate_extra_worker_env_rejects_non_tuple_input():
    boundary = _runtime_boundary()
    with pytest.raises(ValueError):
        boundary._validate_extra_worker_env([("X_OK", "v")])


def test_validate_extra_worker_env_accepts_empty_and_valid():
    boundary = _runtime_boundary()
    boundary._validate_extra_worker_env(())
    boundary._validate_extra_worker_env(
        (("https_proxy", "http://127.0.0.1:18080"), ("_ok_2", ""))
    )


def test_validate_extra_worker_env_name_length_bound():
    boundary = _runtime_boundary()
    boundary._validate_extra_worker_env((("X" * 128, "v"),))
    with pytest.raises(ValueError):
        boundary._validate_extra_worker_env((("X" * 129, "v"),))
