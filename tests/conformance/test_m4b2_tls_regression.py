"""M4B-2 adversarial-review regression tests for the worker TLS boundary.

Covers four findings against :mod:`agenticos.sandbox.network_tls`:

* TLS F-1 (MEDIUM): the ESTABLISHED path never asserted that the SNI
  authorization callback actually fired — a stack change that completed the
  handshake without the policy callback would silently skip hostname
  authorization.  Establishment now fails closed unless
  ``policy.firing_count == 1``, and the startup probe's ``_alpn_probe_leg``
  asserts the same invariant after each probe handshake.
* TLS F-2 (LOW): ``_drive_handshake`` restored the socket timeout only when
  the previous timeout was not ``None``, leaving a previously blocking
  socket at the 0.25s poll slice.  The exact previous timeout — including
  blocking mode — is now restored before returning.
* TLS F-3 (LOW): the GATE_NOT_ACCEPTED / CONTEXT_POLICY_VIOLATION early
  returns leaked the worker socket, contradicting the function's docstring;
  those denial paths now close it like every other denial path.
* Hostname F2 (LOW): ``_require_canonical_hostname`` was a parallel hostname
  grammar that could diverge from the canonical one; it now reuses
  :func:`agenticos.sandbox.network_https.canonicalize_hostname` and requires
  the approved value to equal its own canonical form.

Self-contained: mirrors the harness style of
``tests/conformance/test_m4b_tls_unit.py`` but imports nothing from the
conformance conftest/helpers.  Real TLS handshakes over AF_UNIX
socketpairs; no internet.
"""

from __future__ import annotations

import sys

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("M4B-2 worker TLS termination tests require Linux", allow_module_level=True)

import socket
import ssl
import threading

import chgen
from agenticos.sandbox import cert_helper as ch
from agenticos.sandbox import network_clienthello as nch
from agenticos.sandbox import network_tls as ntl

pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnraisableExceptionWarning"
)

APPROVED = "approved.example.test"
APPROVED_BYTES = APPROVED.encode("ascii")

TASK_CONTEXT = {
    "task_id": "task-tls-regression",
    "task_generation": 4,
    "launch_nonce": "cd" * 16,
    "hostnames": (APPROVED,),
    "policy_digest": "ab" * 32,
}

GATE_TIMEOUT = 5.0
HANDSHAKE_TIMEOUT = 10.0

_LEAVE = object()  # sentinel: do not touch the socket timeout before termination


@pytest.fixture(scope="module")
def leaf_context():
    """One genuine cert_helper leaf context (EC P-256) shared read-only."""
    material = ch.generate_task_material(**TASK_CONTEXT)
    try:
        context = ch.load_leaf_ssl_context(
            ca_cert_fd=material.ca_cert_fd,
            leaf_cert_fd=material.leaf_cert_fd,
            leaf_key_fd=material.leaf_key_fd,
            binding_fd=material.binding_fd,
            **TASK_CONTEXT,
        )
    finally:
        material.close()
    return context


def _prepare(leaf_context, approved=APPROVED):
    return ntl.configure_worker_server_context(leaf_context, approved)


def _accepted_gate_outcome(hello: bytes) -> nch.GateOutcome:
    gate = nch.ClientHelloGate()
    assert gate.feed(hello) is nch.GateDecision.ACCEPT
    return nch.GateOutcome(gate.decision, "", gate.accepted_bytes, gate.metadata)


# ---------------------------------------------------------------------------
# Harness: production gate -> production termination, real TLS client
# ---------------------------------------------------------------------------

def _serve(prepared, server_sock, results, *, pre_termination_timeout=_LEAVE):
    """Broker side: production gate -> production termination.

    ``pre_termination_timeout`` sets an explicit socket timeout between the
    gate and termination so the termination stage's timeout-restore behavior
    is measured against a known prior mode (isolated from the gate stage).
    Records the post-termination socket state before any harness cleanup.
    """
    try:
        gate = nch.run_gate_on_socket(server_sock, timeout=GATE_TIMEOUT)
        results["gate"] = gate
        if pre_termination_timeout is not _LEAVE:
            server_sock.settimeout(pre_termination_timeout)
        outcome = ntl.terminate_worker_tls(
            server_sock, gate, prepared, timeout=HANDSHAKE_TIMEOUT
        )
        results["outcome"] = outcome
        results["post_fileno"] = server_sock.fileno()
        results["post_timeout"] = (
            server_sock.gettimeout() if server_sock.fileno() != -1 else None
        )
        if outcome.established:
            outcome.channel.close()
    finally:
        try:
            server_sock.close()
        except OSError:
            pass


def _run_real_client(leaf_context, *, doctor=None, pre_termination_timeout=_LEAVE):
    """Real Python TLS client (SNI approved, ALPN http/1.1) over a socketpair.

    ``doctor`` mutates the prepared context/policy before serving, simulating
    a stack that deviates from the SNI-authorization contract.
    """
    prepared = _prepare(leaf_context)
    if doctor is not None:
        doctor(prepared)
    srv, cli = socket.socketpair()
    results: dict = {}
    server = threading.Thread(
        target=_serve,
        args=(prepared, srv, results),
        kwargs={"pre_termination_timeout": pre_termination_timeout},
        daemon=True,
    )
    server.start()
    client: dict = {}
    try:
        cli.settimeout(20.0)
        cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cctx.check_hostname = False
        cctx.verify_mode = ssl.CERT_NONE
        cctx.set_alpn_protocols(["http/1.1"])
        try:
            css = cctx.wrap_socket(cli, server_hostname=APPROVED)
        except (ssl.SSLError, OSError) as exc:
            client["error"] = f"{type(exc).__name__}: {exc}"
            cli.close()
        else:
            client["version"] = css.version()
            client["alpn"] = css.selected_alpn_protocol()
            try:
                css.close()
            except OSError:
                pass
    finally:
        server.join(timeout=40)
    assert not server.is_alive(), "server thread stuck"
    return prepared, client, results


# ---------------------------------------------------------------------------
# TLS F-1: ESTABLISHED must require exactly one SNI authorization firing
# ---------------------------------------------------------------------------

def test_establishment_fails_closed_when_sni_callback_never_fires(leaf_context):
    """A handshake that completes with the authorization callback uninstalled
    must NOT establish: hostname authorization would be silently skipped."""

    def doctor(prepared):
        prepared.context.sni_callback = None

    _prepared, client, results = _run_real_client(leaf_context, doctor=doctor)
    # The bare stack happily completes the handshake without the callback...
    assert "error" not in client
    assert client["alpn"] == "http/1.1"
    # ...so establishment must fail closed on the missing authorization.
    outcome = results["outcome"]
    assert not outcome.established
    assert outcome.code is ntl.TerminationCode.SNI_AUTHORIZATION_MISSING
    assert outcome.sni_firing_count == 0
    assert outcome.channel is None
    assert results["post_fileno"] == -1  # denied: socket closed


def test_establishment_fails_closed_when_sni_fires_more_than_once(leaf_context):
    """More than one recorded authorization decision at establishment is just
    as much a contract violation as zero — fail closed identically."""

    def doctor(prepared):
        original = prepared.policy.callback

        def callback(sslobj, server_name, ctx):
            original(sslobj, server_name, ctx)
            # Simulate a stack that fired the authorization callback twice
            # without the policy's own second-firing abort engaging.
            prepared.policy.firing_count += 1

        prepared.context.sni_callback = callback

    _prepared, client, results = _run_real_client(leaf_context, doctor=doctor)
    assert "error" not in client
    outcome = results["outcome"]
    assert not outcome.established
    assert outcome.code is ntl.TerminationCode.SNI_AUTHORIZATION_MISSING
    assert outcome.sni_firing_count == 2
    assert outcome.channel is None
    assert results["post_fileno"] == -1


def test_establishment_with_exactly_one_firing_still_works(leaf_context):
    """Control: the undoctored path establishes with firing_count == 1."""
    _prepared, client, results = _run_real_client(leaf_context)
    assert "error" not in client
    outcome = results["outcome"]
    assert outcome.established
    assert outcome.sni_firing_count == 1
    assert outcome.sni_seen == (APPROVED,)


def test_alpn_probe_leg_fails_closed_when_callback_never_fires(leaf_context):
    """The startup probe's MemoryBIO handshake asserts the same invariant."""
    prepared = _prepare(leaf_context)
    prepared.context.sni_callback = None
    with pytest.raises(ntl.StartupSelfTestError):
        ntl._alpn_probe_leg(prepared, ["http/1.1"], APPROVED)


def test_alpn_probe_leg_with_live_policy_passes(leaf_context):
    """Control: the undoctored probe leg selects http/1.1 as before."""
    prepared = _prepare(leaf_context)
    assert ntl._alpn_probe_leg(prepared, ["http/1.1"], APPROVED) == "http/1.1"


# ---------------------------------------------------------------------------
# TLS F-2: termination restores the socket's exact previous timeout
# ---------------------------------------------------------------------------

def test_termination_restores_prior_blocking_mode(leaf_context):
    """A previously blocking socket must be blocking again afterwards
    (the restore guard used to skip the None case, leaking the 0.25s slice)."""
    _prepared, client, results = _run_real_client(
        leaf_context, pre_termination_timeout=None
    )
    assert "error" not in client
    assert results["outcome"].established
    assert results["post_timeout"] is None


def test_termination_restores_prior_timeout(leaf_context):
    """Control: a previously timed-out socket keeps its exact timeout."""
    _prepared, client, results = _run_real_client(
        leaf_context, pre_termination_timeout=7.5
    )
    assert "error" not in client
    assert results["outcome"].established
    assert results["post_timeout"] == 7.5


# ---------------------------------------------------------------------------
# TLS F-3: denial early returns close the worker socket
# ---------------------------------------------------------------------------

def test_gate_not_accepted_denial_closes_socket(leaf_context):
    prepared = _prepare(leaf_context)
    rejected = nch.GateOutcome(nch.GateDecision.REJECT, "ECH extension 0xfe0d present")
    srv, cli = socket.socketpair()
    try:
        outcome = ntl.terminate_worker_tls(srv, rejected, prepared)
        assert outcome.code is ntl.TerminationCode.GATE_NOT_ACCEPTED
        assert outcome.channel is None
        assert srv.fileno() == -1, "denial leaked the worker socket"
    finally:
        cli.close()
        try:
            srv.close()
        except OSError:
            pass


def test_context_policy_violation_denial_closes_socket(leaf_context):
    prepared = _prepare(leaf_context)
    prepared.context.options &= ~ssl.OP_NO_RENEGOTIATION
    accepted = _accepted_gate_outcome(chgen.make_client_hello(APPROVED_BYTES))
    srv, cli = socket.socketpair()
    try:
        outcome = ntl.terminate_worker_tls(srv, accepted, prepared)
        assert outcome.code is ntl.TerminationCode.CONTEXT_POLICY_VIOLATION
        assert outcome.channel is None
        assert srv.fileno() == -1, "denial leaked the worker socket"
    finally:
        cli.close()
        try:
            srv.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Hostname F2: approved hostname uses the ONE canonical grammar
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "name",
    [
        "Example.COM",              # raw uppercase: != its canonical form
        "APPROVED.Example.Test",    # case variant of the approved name
        "evil_example.com",         # underscore: outside the LDH grammar
        "xn--nxasmq6b.example",     # punycode label: never IDNA-converted
        "1234",                     # all-digit: legacy numeric form
        "127.0.0.1",                # IPv4 literal
        "example.123",              # all-digit final label
        "0x7f.1",                   # hex label: inet_aton-compatible
        "*.example.test",           # wildcard
        "example.test.",            # trailing dot
    ],
    ids=[
        "raw_uppercase",
        "case_variant",
        "underscore",
        "punycode",
        "all_digit",
        "ipv4_literal",
        "digit_final_label",
        "hex_label",
        "wildcard",
        "trailing_dot",
    ],
)
def test_approved_hostname_rejects_raw_noncanonical_forms(name):
    with pytest.raises(ValueError):
        ntl.configure_worker_server_context(
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), name
        )


def test_approved_hostname_rejects_non_str_and_empty():
    for bad in (None, b"approved.example.test", "", 42):
        with pytest.raises(ValueError):
            ntl.configure_worker_server_context(
                ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), bad
            )


def test_approved_hostname_accepts_canonical_form():
    prepared = ntl.configure_worker_server_context(
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), APPROVED
    )
    assert prepared.approved_hostname == APPROVED
