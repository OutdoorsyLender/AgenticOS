"""Conformance Corpus B for the M4B-2 worker-facing TLS termination.

Exercises the PRODUCTION termination primitive
(``agenticos.sandbox.network_tls``) behind the PRODUCTION ClientHello gate
with real TLS clients (TLS 1.3 and forced TLS 1.2), synthetic wire fixtures
(case-variant SNI, ECH, forced-HRR second ClientHello), and a compiled C
renegotiation probe.  All fixtures are local: AF_UNIX socketpair or
127.0.0.1 loopback.  No internet.

Fixture choice (documented per slice handoff): the server leaf context
comes from the Slice 3 certificate helper (``cert_helper``), whose leaf is
EC P-256.  That leaf works for every real-client case here — TLS 1.3
cipher suites are certificate-agnostic and TLS 1.2 ECDHE-ECDSA intersects
the default OpenSSL 3.5 client cipher list — so no RSA fixture is needed.
(The TLS 1.2 ECDHE-RSA limitation recorded in Slice 3 concerns the
synthetic corpus templates of Corpus A, which offer only 0xC02F/0xC030;
no synthetic fixture in THIS file completes crypto against cipher
templates — the case-variant/ECH/HRR fixtures are denied before or at the
second ClientHello, where only signature algorithms matter, and the chgen
sigalg list includes 0x0403 ecdsa_secp256r1_sha256.)

The SNI policy abort mechanism is the measured one from the spike (x28c):
the policy raises inside ``sni_callback``; CPython reports that through
``sys.unraisablehook`` ("exception ignored in ssl servername callback")
and fails the handshake with CALLBACK_FAILED.  Filter the resulting
pytest unraisable warning for this module — it is the mechanism, not a
defect.
"""

from __future__ import annotations

import sys

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("M4B-2 worker TLS termination tests require Linux", allow_module_level=True)

from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import threading
import time

import chgen
from agenticos.sandbox import cert_helper as ch
from agenticos.sandbox import network_clienthello as nch
from agenticos.sandbox import network_tls as ntl

pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnraisableExceptionWarning"
)

APPROVED = "approved.example.test"
APPROVED_BYTES = APPROVED.encode("ascii")

REPO_ROOT = Path(__file__).resolve().parents[2]
RENEG_SOURCE = REPO_ROOT / "tests" / "fixtures" / "reneg_client.c"

TASK_CONTEXT = {
    "task_id": "task-tls-termination",
    "task_generation": 4,
    "launch_nonce": "cd" * 16,
    "hostnames": (APPROVED,),
    "policy_digest": "ab" * 32,
}

GATE_TIMEOUT = 5.0
HANDSHAKE_TIMEOUT = 10.0


@pytest.fixture(scope="module")
def leaf_context():
    """One genuine cert_helper leaf context (EC P-256) shared read-only.

    ``configure_worker_server_context`` re-hardens it per test with a fresh
    SNI policy; tests run sequentially, so per-test re-preparation resets
    the firing counters deterministically.
    """
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


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

def _serve(prepared, server_sock, results, *, echo_reads=0):
    """Broker side: production gate -> production termination -> optional echo."""
    try:
        gate = nch.run_gate_on_socket(server_sock, timeout=GATE_TIMEOUT)
        results["gate"] = gate
        outcome = ntl.terminate_worker_tls(
            server_sock, gate, prepared, timeout=HANDSHAKE_TIMEOUT
        )
        results["outcome"] = outcome
        if outcome.established and echo_reads:
            channel = outcome.channel
            try:
                for _ in range(echo_reads):
                    data = channel.read(65536, timeout=8.0)
                    if not data:
                        break
                    channel.write(data, timeout=8.0)
            except ntl.ChannelError as exc:
                results["channel_error"] = str(exc)
            finally:
                channel.close()
    finally:
        try:
            server_sock.close()
        except OSError:
            pass


def _run_real_client(
    leaf_context,
    *,
    sni=APPROVED,
    alpn=("http/1.1",),
    max_version=None,
    payloads=(),
):
    """Real Python TLS client through gate+termination over a socketpair."""
    prepared = _prepare(leaf_context)
    srv, cli = socket.socketpair()
    results: dict = {}
    server = threading.Thread(
        target=_serve,
        args=(prepared, srv, results),
        kwargs={"echo_reads": len(payloads)},
        daemon=True,
    )
    server.start()
    client: dict = {}
    try:
        cli.settimeout(20.0)
        cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cctx.check_hostname = False
        cctx.verify_mode = ssl.CERT_NONE
        if alpn:
            cctx.set_alpn_protocols(list(alpn))
        if max_version is not None:
            cctx.maximum_version = max_version
        try:
            css = cctx.wrap_socket(cli, server_hostname=sni)
        except (ssl.SSLError, OSError) as exc:
            client["error"] = f"{type(exc).__name__}: {exc}"
            cli.close()
        else:
            client["version"] = css.version()
            client["alpn"] = css.selected_alpn_protocol()
            client["replies"] = []
            try:
                for payload in payloads:
                    css.sendall(payload)
                    client["replies"].append(css.recv(65536))
            except (ssl.SSLError, OSError) as exc:
                client["exchange_error"] = f"{type(exc).__name__}: {exc}"
            finally:
                try:
                    css.close()
                except OSError:
                    pass
    finally:
        server.join(timeout=40)
    assert not server.is_alive(), "server thread stuck"
    return client, results


def _run_synthetic(prepared, flights, *, read_window=0.7):
    """Synthetic wire fixture: send raw flights, drain between and after.

    Returns (received_per_drain, results).  ``received_per_drain[i]`` is
    whatever the server emitted after flight ``i`` (plus a final drain).
    """
    srv, cli = socket.socketpair()
    results: dict = {}
    server = threading.Thread(target=_serve, args=(prepared, srv, results), daemon=True)
    server.start()
    received: list[bytes] = []
    cli.settimeout(0.05)

    def drain(window):
        end = time.monotonic() + window
        buf = b""
        while time.monotonic() < end:
            try:
                chunk = cli.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return buf, True
            if chunk == b"":
                return buf, True
            buf += chunk
        return buf, False

    closed = False
    for flight in flights:
        if closed:
            break
        try:
            cli.sendall(flight)
        except OSError:
            closed = True
            break
        buf, closed = drain(read_window)
        received.append(buf)
    if not closed:
        # Denial paths flush an alert and close; drain until then.
        buf, _closed = drain(8.0)
        received.append(buf)
    try:
        cli.close()
    except OSError:
        pass
    server.join(timeout=40)
    assert not server.is_alive(), "server thread stuck"
    return received, results


def _accepted_gate_outcome(hello: bytes) -> nch.GateOutcome:
    gate = nch.ClientHelloGate()
    assert gate.feed(hello) is nch.GateDecision.ACCEPT
    return nch.GateOutcome(gate.decision, "", gate.accepted_bytes, gate.metadata)


# ---------------------------------------------------------------------------
# Establishment
# ---------------------------------------------------------------------------

def test_tls13_approved_sni_establishes_and_echoes(leaf_context):
    payload = b"GET / HTTP/1.1\r\nHost: approved.example.test\r\n\r\n"
    client, results = _run_real_client(leaf_context, payloads=(payload,))
    assert "error" not in client
    assert client["version"] == "TLSv1.3"
    assert client["alpn"] == "http/1.1"
    assert client["replies"] == [payload]

    gate = results["gate"]
    assert gate.decision is nch.GateDecision.ACCEPT
    outcome = results["outcome"]
    assert outcome.established
    assert outcome.tls_version == "TLSv1.3"
    assert outcome.alpn_selected == "http/1.1"
    assert outcome.sni_firing_count == 1
    assert outcome.sni_seen == (APPROVED,)


def test_tls12_approved_sni_establishes(leaf_context):
    client, results = _run_real_client(
        leaf_context, max_version=ssl.TLSVersion.TLSv1_2, payloads=(b"ping",)
    )
    assert "error" not in client
    assert client["version"] == "TLSv1.2"
    assert client["replies"] == [b"ping"]
    outcome = results["outcome"]
    assert outcome.established
    assert outcome.tls_version == "TLSv1.2"
    assert outcome.sni_firing_count == 1


def test_channel_session_reuse_multiple_messages(leaf_context):
    payloads = (b"first-message", b"second-message", b"third-message")
    client, results = _run_real_client(leaf_context, payloads=payloads)
    assert "error" not in client
    assert "exchange_error" not in client
    assert tuple(client["replies"]) == payloads
    assert results["outcome"].established


# ---------------------------------------------------------------------------
# SNI authorization (every firing is a fresh decision)
# ---------------------------------------------------------------------------

def test_wrong_sni_denied(leaf_context):
    client, results = _run_real_client(leaf_context, sni="evil.example.test")
    assert "error" in client  # client observes the handshake failure
    gate = results["gate"]
    assert gate.decision is nch.GateDecision.ACCEPT  # gate accepts; SNI is not its job
    outcome = results["outcome"]
    assert outcome.code is ntl.TerminationCode.SNI_MISMATCH
    assert outcome.sni_firing_count == 1
    assert outcome.sni_seen == ("evil.example.test",)
    assert outcome.channel is None


def test_absent_sni_denied_fail_closed(leaf_context):
    client, results = _run_real_client(leaf_context, sni=None)
    assert "error" in client
    outcome = results["outcome"]
    assert outcome.code is ntl.TerminationCode.SNI_ABSENT
    assert outcome.sni_firing_count == 1
    assert outcome.sni_seen == (None,)


def test_case_variant_sni_denied(leaf_context):
    """APPROVED.Example.Test on the wire != approved lowercase canonical form."""
    hello = chgen.make_client_hello(b"APPROVED.Example.Test")
    prepared = _prepare(leaf_context)
    _received, results = _run_synthetic(prepared, [hello])
    gate = results["gate"]
    assert gate.decision is nch.GateDecision.ACCEPT
    outcome = results["outcome"]
    assert outcome.code is ntl.TerminationCode.SNI_MISMATCH
    assert outcome.sni_seen == ("APPROVED.Example.Test",)


def test_hostname_validation_rejects_noncanonical():
    with pytest.raises(ValueError):
        ntl.configure_worker_server_context(
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), "APPROVED.Example.Test"
        )
    with pytest.raises(ValueError):
        ntl.configure_worker_server_context(
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), "*.example.test"
        )


# ---------------------------------------------------------------------------
# Second ClientHello: HRR abort (ECH-in-CH2 structurally unreachable)
# ---------------------------------------------------------------------------

def _hrr_ch1() -> bytes:
    """CH1 forcing a HelloRetryRequest: supported_groups prefers x25519 but
    the only key_share is secp256r1 (the spike's forced-HRR method)."""
    return chgen.make_client_hello(
        APPROVED_BYTES, supported_groups=[0x001D, 0x0018], key_share_group=0x0018
    )


@pytest.mark.parametrize(
    "ch2",
    [
        chgen.make_client_hello(APPROVED_BYTES),            # same SNI, no ECH
        chgen.make_client_hello(APPROVED_BYTES, ech=True),  # ECH only in CH2
        chgen.make_client_hello(b"evil.example.test"),      # swapped SNI
    ],
    ids=["same_sni", "ech_in_ch2", "swapped_sni"],
)
def test_second_client_hello_aborts_regardless_of_ch2(leaf_context, ch2):
    prepared = _prepare(leaf_context)
    received, results = _run_synthetic(prepared, [_hrr_ch1(), ch2])

    gate = results["gate"]
    assert gate.decision is nch.GateDecision.ACCEPT  # gate inspected CH1 only

    outcome = results["outcome"]
    assert outcome.code is ntl.TerminationCode.SECOND_CLIENT_HELLO
    assert outcome.sni_firing_count == 2  # exactly two authorization decisions
    assert outcome.channel is None

    # The HRR flight (plaintext handshake records) followed CH1...
    assert received[0].startswith(b"\x16")
    # ...but NO server flight follows CH2: at most a plaintext alert (21)
    # or nothing.  ECH-in-CH2 never reaches a trusting component.
    post_ch2 = received[1] if len(received) > 1 else b""
    if len(received) > 2:
        post_ch2 += received[2]
    assert post_ch2 == b"" or post_ch2[0] == 21


# ---------------------------------------------------------------------------
# ALPN enforcement (mandatory post-handshake check — spike E3)
# ---------------------------------------------------------------------------

def test_h2_only_alpn_client_denied_post_handshake(leaf_context):
    client, results = _run_real_client(leaf_context, alpn=("h2",))
    # The stack completes the handshake with selected ALPN None (E3)...
    assert "error" not in client
    assert client["alpn"] is None
    # ...and establishment is DENIED at the post-handshake check.
    outcome = results["outcome"]
    assert outcome.code is ntl.TerminationCode.ALPN_REJECTED
    assert outcome.alpn_selected is None
    assert outcome.sni_firing_count == 1


def test_no_alpn_client_denied(leaf_context):
    client, results = _run_real_client(leaf_context, alpn=None)
    assert "error" not in client
    assert client["alpn"] is None
    outcome = results["outcome"]
    assert outcome.code is ntl.TerminationCode.ALPN_REJECTED
    assert outcome.alpn_selected is None


def test_http11_alpn_accepted(leaf_context):
    client, results = _run_real_client(leaf_context, alpn=("h2", "http/1.1"))
    assert "error" not in client
    assert client["alpn"] == "http/1.1"
    assert results["outcome"].established


# ---------------------------------------------------------------------------
# Gate interaction: ECH denied before TLS; non-ACCEPT fails closed
# ---------------------------------------------------------------------------

def test_ech_client_hello_denied_with_zero_sni_firings(leaf_context):
    prepared = _prepare(leaf_context)
    ech_hello = chgen.make_client_hello(APPROVED_BYTES, ech=True)
    _received, results = _run_synthetic(prepared, [ech_hello])
    gate = results["gate"]
    assert gate.decision is nch.GateDecision.REJECT
    assert "0xfe0d" in gate.reason
    outcome = results["outcome"]
    assert outcome.code is ntl.TerminationCode.GATE_NOT_ACCEPTED
    # The decision preceded any TLS object: the SNI policy never fired.
    assert outcome.sni_firing_count == 0
    assert prepared.policy.firing_count == 0


def test_rejected_gate_outcome_fails_closed_without_tls(leaf_context):
    prepared = _prepare(leaf_context)
    rejected = nch.GateOutcome(nch.GateDecision.REJECT, "ECH extension 0xfe0d present")
    srv, cli = socket.socketpair()
    try:
        outcome = ntl.terminate_worker_tls(srv, rejected, prepared)
    finally:
        cli.close()
        try:
            srv.close()
        except OSError:
            pass
    assert outcome.code is ntl.TerminationCode.GATE_NOT_ACCEPTED
    assert outcome.sni_firing_count == 0


# ---------------------------------------------------------------------------
# OP_NO_RENEGOTIATION
# ---------------------------------------------------------------------------

def test_op_no_renegotiation_set_and_verified_on_context(leaf_context):
    prepared = _prepare(leaf_context)
    assert prepared.context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert prepared.context.options & ssl.OP_NO_RENEGOTIATION


def test_termination_fails_closed_if_no_renegotiation_flag_missing(leaf_context):
    prepared = _prepare(leaf_context)
    prepared.context.options &= ~ssl.OP_NO_RENEGOTIATION
    accepted = _accepted_gate_outcome(chgen.make_client_hello(APPROVED_BYTES))
    srv, cli = socket.socketpair()
    try:
        outcome = ntl.terminate_worker_tls(srv, accepted, prepared)
    finally:
        cli.close()
        try:
            srv.close()
        except OSError:
            pass
    assert outcome.code is ntl.TerminationCode.CONTEXT_POLICY_VIOLATION


@pytest.fixture(scope="session")
def reneg_client(tmp_path_factory):
    """The C renegotiation probe, compiled at test time (mirrors Slice 1's
    session-scoped native-helper builds).  Skips cleanly without cc."""
    cc = shutil.which("cc")
    if cc is None:
        pytest.skip("cc not available; renegotiation probe cannot be built")
    output = tmp_path_factory.mktemp("reneg-probe") / "reneg_client"
    subprocess.run(
        [
            cc, "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror",
            "-O2", str(RENEG_SOURCE), "-o", str(output),
            "-l:libssl.so.3", "-l:libcrypto.so.3",
        ],
        check=True,
        capture_output=True,
    )
    return output


def test_tls12_renegotiation_refused(leaf_context, reneg_client):
    """A real TLS 1.2 SSL_renegotiate client is refused (spike E4, ported)."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    results: dict = {}

    def server():
        try:
            conn, _ = listener.accept()
            gate = nch.run_gate_on_socket(conn, timeout=HANDSHAKE_TIMEOUT)
            results["gate"] = gate
            prepared = _prepare(leaf_context)
            outcome = ntl.terminate_worker_tls(
                conn, gate, prepared, timeout=HANDSHAKE_TIMEOUT
            )
            results["outcome"] = outcome
            if outcome.established:
                try:
                    outcome.channel.read(4096, timeout=HANDSHAKE_TIMEOUT)
                    results["post"] = "read returned without error"
                except ntl.ChannelError as exc:
                    results["post"] = f"ChannelError: {exc}"
                finally:
                    outcome.channel.close()
        finally:
            listener.close()

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    proc = subprocess.run(
        [str(reneg_client), str(port)], capture_output=True, text=True, timeout=30
    )
    thread.join(timeout=30)
    assert not thread.is_alive(), "server thread stuck"

    assert "RENEGOTIATION_REFUSED" in proc.stdout, proc.stdout
    assert "no renegotiation" in proc.stdout, proc.stdout
    outcome = results["outcome"]
    assert outcome.established  # the initial handshake + ALPN policy passed
    assert outcome.tls_version == "TLSv1.2"
    # The server observes the failure on the established channel; no
    # plaintext is ever read after the renegotiation attempt.
    assert results["post"].startswith("ChannelError"), results["post"]


# ---------------------------------------------------------------------------
# Startup self-test primitives
# ---------------------------------------------------------------------------

def test_startup_self_test_passes_on_the_recorded_host():
    report = ntl.run_tls_startup_self_test()
    assert report["gate_self_test"] == "pass"
    assert report["openssl_version"] == ssl.OPENSSL_VERSION
    assert report["op_no_renegotiation"] == "pass"
    assert report["ech_machinery"] == "absent"


def test_startup_self_test_fails_closed_on_unmeasured_openssl():
    with pytest.raises(ntl.StartupSelfTestError):
        ntl.run_tls_startup_self_test(recorded_openssl_version="OpenSSL 0.0.0 bogus")


def test_startup_self_test_fixtures_drive_the_real_gate():
    # The self-test's synthetic ECH ClientHello must trip the production
    # gate's ECH branch, and the clean one must replay byte-verbatim.
    ech = ntl._self_test_client_hello(b"approved.example.test", ech=True)
    gate = nch.ClientHelloGate()
    assert gate.feed(ech) is nch.GateDecision.REJECT
    assert "0xfe0d" in gate.rejection_reason
    clean = ntl._self_test_client_hello(b"approved.example.test", ech=False)
    clean_gate = nch.ClientHelloGate()
    assert clean_gate.feed(clean) is nch.GateDecision.ACCEPT
    assert clean_gate.accepted_bytes == clean
    assert clean_gate.metadata.sni == b"approved.example.test"
