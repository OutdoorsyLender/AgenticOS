"""Socket driver + verbatim replay into Python ssl for the ECH gate spike.

SPIKE CODE — not production. Standard-library only.

Flow under test (the proposed M4B-2 worker-facing path):

    worker bytes -> ClientHelloGate -> [accept] -> verbatim replay into
    ssl.MemoryBIO-driven SSLObject (server side) -> sni_callback policy ->
    ALPN check -> plaintext stream

The replay writes the gate-accepted bytes unchanged into the inbound
MemoryBIO, so OpenSSL parses exactly the bytes the gate parsed.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field

from ech_gate import (
    ClientHelloGate,
    Decision,
    GATE_TIMEOUT_SECONDS,
    MAX_READ_CALLS,
)


@dataclass
class GateRun:
    decision: str                 # "accept" | "reject"
    reason: str = ""
    accepted_bytes: bytes = b""
    metadata: dict = field(default_factory=dict)
    read_calls: int = 0
    elapsed: float = 0.0


def run_gate_on_socket(
    sock: socket.socket,
    *,
    timeout: float = GATE_TIMEOUT_SECONDS,
    max_read_calls: int = MAX_READ_CALLS,
) -> GateRun:
    """Drive the gate over a blocking socket with explicit bounds."""
    gate = ClientHelloGate()
    deadline = time.monotonic() + timeout
    reads = 0
    sock.settimeout(min(0.25, timeout))
    while True:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            chunk = None
        except OSError as exc:
            return GateRun("reject", f"socket error: {exc}", read_calls=reads)
        if chunk is not None:
            reads += 1
            if chunk == b"":
                return GateRun("reject", "EOF before ClientHello complete",
                               read_calls=reads)
            try:
                decision = gate.feed(chunk)
            except Exception as exc:  # feed-after-decision is a bug; fail closed
                return GateRun("reject", f"gate internal error: {exc}",
                               read_calls=reads)
            if decision is Decision.ACCEPT:
                return GateRun("accept", "", gate.accepted_bytes,
                               dict(gate.metadata), reads,
                               time.monotonic() - (deadline - timeout))
            if decision is Decision.REJECT:
                return GateRun("reject", gate.reason, read_calls=reads)
        if reads >= max_read_calls:
            return GateRun("reject", "read-call bound exceeded", read_calls=reads)
        if time.monotonic() >= deadline:
            return GateRun("reject", "gate timeout", read_calls=reads)


class SniPolicyError(Exception):
    pass


@dataclass
class HandshakeResult:
    outcome: str                  # "completed" | "ch_accepted" | "failed"
    error: str = ""
    sni_seen: list[str | None] = field(default_factory=list)
    sni_callback_fires: int = 0
    alpn: str | None = None
    tls_version: str | None = None
    server_flight_prefix: bytes = b""   # first bytes OpenSSL emitted


def make_server_context(
    certfile: str,
    keyfile: str,
    *,
    approved_hostname: str = "approved.example.test",
    sni_fires: list | None = None,
    abort_on_second_sni_fire: bool = False,
    max_version: ssl.TLSVersion | None = None,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if max_version is not None:
        ctx.maximum_version = max_version
    ctx.options |= ssl.OP_NO_RENEGOTIATION
    ctx.set_alpn_protocols(["http/1.1"])
    ctx.load_cert_chain(certfile, keyfile)

    fires = sni_fires if sni_fires is not None else []

    def _sni_cb(sslobj: ssl.SSLObject, server_name: str | None,
                _ctx: ssl.SSLContext) -> None:
        fires.append(server_name)
        if abort_on_second_sni_fire and len(fires) > 1:
            raise SniPolicyError("second ClientHello (HRR/renegotiation) refused")
        if server_name != approved_hostname:
            raise SniPolicyError(f"SNI {server_name!r} != approved hostname")

    ctx.sni_callback = _sni_cb
    ctx._spike_fires = fires  # type: ignore[attr-defined]
    return ctx


def drive_handshake(
    sock: socket.socket,
    ctx: ssl.SSLContext,
    initial_bytes: bytes,
    *,
    timeout: float = GATE_TIMEOUT_SECONDS,
    max_bytes: int = 1 << 20,
) -> HandshakeResult:
    """Replay gate-accepted bytes verbatim into OpenSSL via MemoryBIO and
    drive the server-side handshake. `ch_accepted` means OpenSSL consumed
    the ClientHello and emitted its server flight (it is now waiting for
    the client's next flight) — the fixture need not complete the crypto.
    """
    inbio = ssl.MemoryBIO()
    outbio = ssl.MemoryBIO()
    sslobj = ctx.wrap_bio(inbio, outbio, server_side=True)
    fires: list = ctx._spike_fires  # type: ignore[attr-defined]
    result = HandshakeResult("failed")
    inbio.write(initial_bytes)
    deadline = time.monotonic() + timeout
    sock.settimeout(min(0.25, timeout))
    total = 0
    flight_emitted = False
    try:
        while True:
            try:
                sslobj.do_handshake()
            except ssl.SSLWantReadError:
                flight = b""
                while True:
                    chunk = outbio.read()
                    if not chunk:
                        break
                    flight += chunk
                if flight:
                    sock.sendall(flight)
                    flight_emitted = True
                    if not result.server_flight_prefix:
                        result.server_flight_prefix = flight[:64]
                # A server flight means OpenSSL consumed the ClientHello
                # and answered it: the CH was accepted at TLS level.
                if flight_emitted and result.outcome != "completed":
                    result.outcome = "ch_accepted"
                if time.monotonic() >= deadline:
                    result.error = ("awaiting client flight (timeout)"
                                    if flight_emitted else "handshake timeout")
                    break
                try:
                    data = sock.recv(65536)
                except socket.timeout:
                    continue
                except OSError as exc:
                    result.error = f"socket error: {exc}"
                    break
                if data == b"":
                    result.error = ("EOF awaiting client flight"
                                    if flight_emitted else "EOF mid-handshake")
                    break
                total += len(data)
                if total > max_bytes:
                    result.error = "handshake byte bound exceeded"
                    break
                inbio.write(data)
                continue
            else:
                result.outcome = "completed"
                result.alpn = sslobj.selected_alpn_protocol()
                result.tls_version = sslobj.version()
                break
    except (ssl.SSLError, SniPolicyError, OSError) as exc:
        if result.outcome != "completed":
            result.outcome = "failed"
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        result.sni_seen = list(fires)
        result.sni_callback_fires = len(fires)
    return result
