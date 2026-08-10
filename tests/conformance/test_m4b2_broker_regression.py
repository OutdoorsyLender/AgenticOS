"""Adversarial-review regression tests for the M4B-2 HTTPS broker core.

Each test pins one security finding fixed in
``src/agenticos/sandbox/network_broker.py``:

* HTTP-2 (forward-before-reject): a feed that ends in a typed rejection
  must forward NOTHING to the origin and must not run an origin round
  trip — the rejection check precedes all event processing.
* HTTP-3 (HEAD response framing): the origin-response relay seeds its
  h11 CLIENT framer with the request method, so compliant HEAD/204/304
  responses (Content-Length but no body) frame EndOfMessage and the
  keep-alive cycle stays boundary-exact; a silent origin is terminated
  by a bounded idle deadline instead of spinning until grant expiry.
* Hostname F1 (evidence sentinel): hostile observed hostnames map onto
  a grammar-valid ``non-canonical-<digest>`` sentinel, and connection
  record construction sits inside the fail-closed guard so a
  construction failure can never kill the connection thread silently.
* Origin F1 (expectation-sourced evidence): the evidence
  ``origin_tls_name`` is the origin channel's OBSERVED verified
  hostname, not the approved expectation.

The in-process serve harness (real TLS on both legs over socketpairs)
is imported from test_m4b_https_unit.py; conventions mirror it.
"""

from __future__ import annotations

import sys

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("M4B-2 broker regression tests require Linux", allow_module_level=True)

# The SNI policy aborts hostile handshakes by RAISING inside the ssl
# servername callback; CPython reports that through sys.unraisablehook
# ("exception ignored in ssl servername callback").  It is the abort
# mechanism itself, not a defect (mirrors test_m4b_tls_unit.py).
pytestmark = pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnraisableExceptionWarning"
)

import socket
import ssl
import time

from agenticos.sandbox import network_broker as broker
from agenticos.sandbox import network_origin as origin_module

from test_m4b_https_unit import (
    SERVE_HOSTNAME,
    _close_tls,
    _established_tls_worker,
    _finish_serve_run,
    _read_worker_response,
    _start_serve_connection,
    _worker_connect,
    _worker_tls,
    serve_leaf_material,  # noqa: F401  (imported fixture)
)


def _get_request(path="/"):
    return f"GET {path} HTTP/1.1\r\nHost: {SERVE_HOSTNAME}\r\n\r\n".encode("ascii")


class _WorkerReader:
    """Buffering worker-side reader that splits responses at exact
    boundaries even when the relay coalesces them into one TLS flight."""

    def __init__(self, tls, timeout=8.0):
        self.tls = tls
        self.timeout = timeout
        self.buf = b""

    def _fill(self):
        self.tls.settimeout(self.timeout)
        chunk = self.tls.recv(4096)
        if not chunk:
            raise EOFError("worker leg closed mid-response")
        self.buf += chunk

    def read_head(self):
        while b"\r\n\r\n" not in self.buf:
            self._fill()
        head, _, self.buf = self.buf.partition(b"\r\n\r\n")
        return head + b"\r\n\r\n"

    def read_body(self, count):
        while len(self.buf) < count:
            self._fill()
        body, self.buf = self.buf[:count], self.buf[count:]
        return body


# -- HTTP-2: rejection short-circuits before any forwarding ---------------------


def test_rejected_feed_forwards_nothing_to_origin(tmp_path, serve_leaf_material):
    """A complete request plus rejected trailing bytes in ONE read: the
    rejection short-circuits before event processing, so the completed
    wire is never forwarded and no origin round trip runs."""
    run = _start_serve_connection(tmp_path, serve_leaf_material)
    tls = _established_tls_worker(run, serve_leaf_material)
    valid = _get_request()
    # A header name with an embedded SP is a typed rejection
    # (header_name_invalid); both requests arrive in one TLS flight.
    garbage = (
        f"GET /two HTTP/1.1\r\nHost: {SERVE_HOSTNAME}\r\n"
        "Bad Header: x\r\n\r\n"
    ).encode("ascii")
    tls.sendall(valid + garbage)
    # The denial tears the tunnel down without answering anything.
    assert _read_worker_response(tls) is None
    _close_tls(tls)
    record = _finish_serve_run(run)
    assert run.origin.requests == [], "a rejected feed reached the origin"
    assert record.requests_completed == 0
    assert record.worker_to_origin_bytes == 0
    assert record.origin_to_worker_bytes == 0
    assert record.detail == "http_header_name_invalid"
    assert record.terminal_reason is broker.HttpsConnectionTermination.DENIED


# -- HTTP-3: HEAD/bodiless response framing + bounded silent origin --------------


def _head_responder(tls, _request, _index):
    """Compliant HEAD response: 200 + Content-Length but NO body, keep-alive."""
    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
    return True


def test_head_response_frames_and_completes_promptly(tmp_path, serve_leaf_material):
    run = _start_serve_connection(
        tmp_path,
        serve_leaf_material,
        origin_responder=_head_responder,
        lifetime_ns=5_000_000_000,
    )
    tls = _established_tls_worker(run, serve_leaf_material)
    request = f"HEAD / HTTP/1.1\r\nHost: {SERVE_HOSTNAME}\r\n\r\n".encode("ascii")
    started = time.monotonic()
    tls.sendall(request)
    reader = _WorkerReader(tls)
    head = reader.read_head()
    assert head == b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
    _close_tls(tls)
    record = _finish_serve_run(run)
    # The bodiless response frames EndOfMessage immediately; the
    # connection ends when the worker closes, long before the 5s grant
    # lifetime an unframeable response would spin away.
    assert time.monotonic() - started < 4.0
    assert run.origin.requests == [request]
    assert record.requests_completed == 1
    assert record.terminal_reason is broker.HttpsConnectionTermination.COMPLETED
    assert record.detail == "worker_closed"


def _head_then_body_responder(tls, _request, index):
    if index == 0:
        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
    else:
        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
    return True


def test_bodiless_response_keeps_keepalive_boundaries_exact(
    tmp_path, serve_leaf_material
):
    """A no-body response followed by a pipelined second response: both
    frame at their correct boundaries on the persistent connection."""
    run = _start_serve_connection(
        tmp_path,
        serve_leaf_material,
        origin_responder=_head_then_body_responder,
        origin_request_count=2,
        lifetime_ns=5_000_000_000,
    )
    tls = _established_tls_worker(run, serve_leaf_material)
    head_request = f"HEAD /one HTTP/1.1\r\nHost: {SERVE_HOSTNAME}\r\n\r\n".encode(
        "ascii"
    )
    get_request = _get_request("/two")
    tls.sendall(head_request + get_request)
    reader = _WorkerReader(tls)
    first = reader.read_head()
    assert first == b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
    second = reader.read_head() + reader.read_body(5)
    assert second == b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    _close_tls(tls)
    record = _finish_serve_run(run)
    assert run.origin.requests == [head_request, get_request]
    assert record.requests_completed == 2
    assert record.terminal_reason is broker.HttpsConnectionTermination.COMPLETED
    expected_origin_bytes = len(first) + len(second)
    assert record.origin_to_worker_bytes == expected_origin_bytes


def _silent_responder(tls, _request, _index):
    """Accept the request, then never answer; wake when the leg is torn down."""
    try:
        tls.recv(4096)
    except (ssl.SSLError, OSError):
        pass
    return False


def test_silent_origin_relay_terminates_within_idle_bound(
    tmp_path, serve_leaf_material, monkeypatch
):
    monkeypatch.setattr(broker, "HTTPS_RESPONSE_IDLE_TIMEOUT_SECONDS", 1.0)
    run = _start_serve_connection(
        tmp_path,
        serve_leaf_material,
        origin_responder=_silent_responder,
        lifetime_ns=6_000_000_000,
    )
    tls = _established_tls_worker(run, serve_leaf_material)
    started = time.monotonic()
    tls.sendall(_get_request())
    # The fail-closed idle bound tears the tunnel down promptly.
    assert _read_worker_response(tls) is None
    _close_tls(tls)
    record = _finish_serve_run(run)
    assert time.monotonic() - started < 20.0, "relay spun instead of failing closed"
    assert record.terminal_reason is broker.HttpsConnectionTermination.PEER_ERROR
    assert record.detail == "origin_response_timeout"


# -- Hostname F1: grammar-valid sentinel + guarded record construction -----------


def test_evidence_hostname_sentinel_is_grammar_valid():
    hostile_values = (
        "evil_example.com",
        "bad\x01name",
        "a" * 300,
        "-leading-dash.example.com",
        "trailing-dot-.example.com",
        "<non-canonical>",
        42,
        b"bytes-not-str",
    )
    for hostile in hostile_values:
        sentinel = broker._evidence_hostname(hostile)
        assert sentinel is not None
        assert broker._HTTPS_HOST_EVIDENCE_RE.fullmatch(sentinel), (
            f"sentinel for {hostile!r} violates the record grammar"
        )
    # Canonical values pass through byte-exact; None stays absent.
    assert broker._evidence_hostname(SERVE_HOSTNAME) == SERVE_HOSTNAME
    assert broker._evidence_hostname(None) is None
    # Distinct hostile observations stay distinguishable in evidence.
    assert broker._evidence_hostname("evil_a.example.com") != (
        broker._evidence_hostname("evil_b.example.com")
    )


def test_hostile_sni_emits_valid_denial_record(tmp_path, serve_leaf_material):
    """SNI outside the record grammar: the connection is denied AND a
    valid evidence record carrying the grammar-valid sentinel is
    emitted (pre-fix the sentinel itself broke the record grammar, the
    connection thread died, and the run's evidence was lost)."""
    run = _start_serve_connection(tmp_path, serve_leaf_material)
    reply = _worker_connect(run.worker_client)
    assert reply.startswith(b"HTTP/1.1 200")
    with pytest.raises((ssl.SSLError, OSError, ValueError)):
        _worker_tls(
            run.worker_client,
            serve_leaf_material["ca_pem"],
            sni="evil_example.com",
        )
    record = _finish_serve_run(run)
    assert record.terminal_reason is broker.HttpsConnectionTermination.DENIED
    assert record.detail == "worker_tls_sni_mismatch"
    assert record.worker_sni is not None
    assert broker._HTTPS_HOST_EVIDENCE_RE.fullmatch(record.worker_sni)
    assert record.worker_sni.startswith("non-canonical-")
    assert record.identity_chain == "identity_divergence:worker_sni"


def test_record_construction_failure_fails_closed_without_thread_death(
    tmp_path, serve_leaf_material, monkeypatch
):
    """Force a record-construction failure: it must surface in
    serve.thread_errors (never kill the thread silently) and the
    connection runtime must still be aborted."""
    monkeypatch.setattr(
        broker, "_evidence_hostname", lambda value: "<grammar-breaking>"
    )
    run = _start_serve_connection(tmp_path, serve_leaf_material)
    tls = _established_tls_worker(run, serve_leaf_material)
    # Half-close: the broker sees EOF and runs the connection teardown —
    # including the (sabotaged) record construction — while we keep our
    # end of the leg open to observe the abort.  (_close_tls would close
    # the fd shared with run.worker_client, leaving nothing to observe.)
    tls.shutdown(socket.SHUT_WR)
    run.thread.join(15.0)
    assert not run.thread.is_alive(), "serve connection thread stuck"
    assert run.serve.thread_errors, "construction failure vanished silently"
    # runtime.abort() ran despite the construction failure: the broker
    # half of the worker leg is closed (EOF) rather than leaked open.
    # Drain first: abort best-effort flushes pending ciphertext before
    # the close.
    tls.settimeout(5.0)
    while tls.recv(4096):
        pass
    # Drained to EOF (the peer's close_notify is consumed): a plain close
    # is all that remains — unwrap would raise ValueError.
    try:
        tls.close()
    except OSError:
        pass
    # No valid record could be constructed, so none was emitted.
    run.control_peer.settimeout(0.5)
    with pytest.raises(TimeoutError):
        run.control_peer.recv(broker.MAX_HTTPS_EVIDENCE_BYTES + 1)
    if run.origin is not None:
        run.origin.close()
        run.origin.join()
    run.control_peer.close()
    run.control_broker.close()
    try:
        run.worker_client.close()
    except OSError:
        pass  # fd already closed via tls


# -- Origin F1: origin_tls_name evidence is channel-observed ---------------------


def test_origin_tls_name_evidence_is_channel_observed(
    tmp_path, serve_leaf_material, monkeypatch
):
    """The evidence origin_tls_name comes from the origin channel's
    OBSERVED verified hostname.  A channel reporting a divergent
    observed name must surface as identity_divergence:origin_tls_name,
    not vanish behind the approved expectation."""
    real_open_origin_tls = origin_module.open_origin_tls

    def divergent_observed_open(sock, hostname, **kwargs):
        outcome = real_open_origin_tls(sock, hostname, **kwargs)
        if not outcome.established:
            return outcome
        channel = outcome.channel
        observed = origin_module.OriginChannel(
            tls_socket=channel.tls_socket,
            tls_version=channel.tls_version,
            verified_hostname="divergent.example.com",
            peer_cert_san_dns=channel.peer_cert_san_dns,
            alpn_protocol=channel.alpn_protocol,
            peer_address=channel.peer_address,
            peer_port=channel.peer_port,
        )
        return origin_module.OriginTLSOutcome(
            code=outcome.code, reason=outcome.reason, channel=observed
        )

    monkeypatch.setattr(origin_module, "open_origin_tls", divergent_observed_open)
    run = _start_serve_connection(tmp_path, serve_leaf_material)
    tls = _established_tls_worker(run, serve_leaf_material)
    tls.sendall(_get_request())
    response = _read_worker_response(tls)
    assert response is not None and response.endswith(b"hello")
    _close_tls(tls)
    record = _finish_serve_run(run)
    assert record.origin_tls_name == "divergent.example.com"
    assert record.identity_chain == "identity_divergence:origin_tls_name"
    assert record.terminal_reason is broker.HttpsConnectionTermination.COMPLETED
