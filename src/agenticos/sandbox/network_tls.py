"""Worker-facing TLS termination behind the M4B-2 ClientHello gate.

This module is the second enforcement stage of the M4B-2 worker-facing TLS
path.  :mod:`agenticos.sandbox.network_clienthello` gates the exact worker
bytes before any SNI trust; this module replays the gate-accepted bytes
VERBATIM into a server-side ``ssl.MemoryBIO``/``SSLObject`` and enforces the
hostname and ALPN policy that OpenSSL alone does not:

* exact-hostname SNI authorization on EVERY ``sni_callback`` firing.  The
  spike measured that Python's ``sni_callback`` fires again for a post-HRR
  second ClientHello and that bare OpenSSL does NOT enforce CH1==CH2 SNI
  equality (``spikes/m4b2-ech-gate/results.md``, x28b).  Therefore every
  firing is a fresh authorization decision, and ANY second firing — even
  with the correct hostname — aborts the handshake (x28c: CALLBACK_FAILED,
  no server flight follows CH2).  This makes ECH-in-CH2 structurally
  unreachable.
* SNI absent -> fail closed (the gate accepts missing SNI; it is not the
  gate's job).
* post-handshake ALPN enforcement.  The spike measured (E3) that an
  h2-only client completes the handshake with selected ALPN ``None``, so
  ``selected_alpn_protocol() == "http/1.1"`` is a MANDATORY post-handshake
  check, not a configuration assumption.
* ``OP_NO_RENEGOTIATION`` set on the context AND verified present in the
  context options (measured effective in the spike, E4).

Fail-closed contract: anything other than an ACCEPTED gate outcome with
verbatim replay bytes is denied before any TLS object exists; every worker-
or transport-controlled failure path returns a typed
:class:`TerminationOutcome`; bare exceptions never cross the boundary.
On denial the connection is terminated (best-effort alert delivery, then
close).  On establishment, ownership of the socket passes to the returned
:class:`EstablishedTlsChannel`.

The ``BoundedGateGuard`` permit lifecycle is the caller's concern (the gate
phase has already completed when this module is invoked).

Standard library only: this module runs inside the broker boundary.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from enum import Enum
import socket
import ssl
import struct
import time

from . import host_qualification
from . import network_clienthello as nch

WORKER_ALPN_PROTOCOL = "http/1.1"       # the only protocol the broker serves
WORKER_ALPN_PROTOCOLS = (WORKER_ALPN_PROTOCOL,)

HANDSHAKE_TIMEOUT_SECONDS = 10.0        # wall-clock bound for the TLS handshake
MAX_HANDSHAKE_BYTES = 1 << 20           # post-gate handshake ciphertext bound
CHANNEL_IO_TIMEOUT_SECONDS = 30.0       # default per-operation channel bound
POLL_SLICE_SECONDS = 0.25               # recv slice; deadline re-checked per slice
RECV_CHUNK_BYTES = 65536

# Recorded on the approved, reviewed M4B-2 host (Ubuntu 26.04 WSL2, Python
# 3.14.4).  Any other value is a different, unmeasured stack: fail closed.
RECORDED_OPENSSL_VERSION = "OpenSSL 3.5.5 27 Jan 2026"


class TerminationCode(str, Enum):
    """Terminal verdict of one worker TLS termination attempt."""

    ESTABLISHED = "established"
    GATE_NOT_ACCEPTED = "gate_not_accepted"
    CONTEXT_POLICY_VIOLATION = "context_policy_violation"
    SNI_ABSENT = "sni_absent"
    SNI_MISMATCH = "sni_mismatch"
    SECOND_CLIENT_HELLO = "second_client_hello"
    ALPN_REJECTED = "alpn_rejected"
    HANDSHAKE_FAILED = "handshake_failed"
    HANDSHAKE_TIMEOUT = "handshake_timeout"
    HANDSHAKE_BYTE_BOUND = "handshake_byte_bound"
    SOCKET_ERROR = "socket_error"


class SniPolicyAbort(Exception):
    """Internal abort signal raised inside ``sni_callback``.

    CPython surfaces a servername-callback exception from ``do_handshake``
    (or converts it to a generic ``ssl.SSLError``); either way the handshake
    dies with CALLBACK_FAILED, which is the measured abort mechanism.  The
    policy records its own structured code before raising so the structured
    denial reason never depends on the exception flavor that surfaces.
    """


class WorkerTlsConfigurationError(Exception):
    """Context hardening failed; the caller must fail closed."""


def _require_canonical_hostname(value: object) -> str:
    """Require the approved hostname in canonical lowercase ASCII form.

    The SNI authorization comparison is an exact string match against this
    canonical form — no wildcard, suffix, or case ambiguity — so the
    approved value itself must be unambiguous at configuration time.
    """
    if type(value) is not str or not value:
        raise ValueError("approved hostname must be a non-empty str")
    if not value.isascii():
        raise ValueError("approved hostname must be pure ASCII")
    if value != value.lower():
        raise ValueError("approved hostname must be canonical lowercase ASCII")
    if "*" in value or value.startswith(".") or value.endswith(".") or ".." in value:
        raise ValueError("approved hostname must be an exact DNS name")
    return value


class ExactHostnameSniPolicy:
    """Per-context SNI authorization state installed as ``sni_callback``.

    EVERY firing is a fresh authorization decision (bare OpenSSL does not
    enforce CH1==CH2 SNI equality — spike x28b).  The first firing must
    carry the byte-exact approved hostname in canonical lowercase ASCII
    form; ``None`` fails closed; ANY second firing aborts the handshake
    regardless of value (spike x28c), which makes ECH-in-CH2 structurally
    unreachable.  ``firing_count`` is tracked explicitly so callers and
    tests can assert the exact number of authorization decisions made.
    """

    def __init__(self, approved_hostname: str) -> None:
        self.approved_hostname = _require_canonical_hostname(approved_hostname)
        self.firing_count = 0
        self.seen: list[str | None] = []
        self.abort_code: TerminationCode | None = None
        self.abort_reason = ""

    def _abort(self, code: TerminationCode, reason: str) -> None:
        self.abort_code = code
        self.abort_reason = reason
        raise SniPolicyAbort(reason)

    def callback(
        self,
        _sslobj: ssl.SSLObject,
        server_name: str | None,
        _ctx: ssl.SSLContext,
    ) -> None:
        self.firing_count += 1
        self.seen.append(server_name)
        if self.firing_count > 1:
            self._abort(
                TerminationCode.SECOND_CLIENT_HELLO,
                f"second ClientHello (HRR/renegotiation) refused; "
                f"SNI {server_name!r} never authorized",
            )
        if server_name is None:
            self._abort(
                TerminationCode.SNI_ABSENT,
                "ClientHello carried no SNI; hostname authorization fails closed",
            )
        if server_name != self.approved_hostname:
            self._abort(
                TerminationCode.SNI_MISMATCH,
                f"SNI {server_name!r} != approved hostname "
                f"{self.approved_hostname!r}",
            )


@dataclass(frozen=True)
class PreparedWorkerTlsContext:
    """A hardened server context plus its exact-hostname SNI policy.

    A prepared context serves task-scoped terminations; the SNI policy
    object tracks firings, so a broker that terminates several connections
    on one context must re-prepare (re-install a fresh policy) per
    connection, exactly as the task-scoped leaf is per-task.
    """

    context: ssl.SSLContext
    approved_hostname: str
    policy: ExactHostnameSniPolicy


def configure_worker_server_context(
    context: ssl.SSLContext,
    approved_hostname: str,
) -> PreparedWorkerTlsContext:
    """Harden a leaf server context for worker-facing termination.

    Sets minimum TLS 1.2, ALPN ``["http/1.1"]``, ``OP_NO_RENEGOTIATION``
    (verified present in the resulting options), and installs a fresh
    exact-hostname SNI policy.  Any failure raises
    :class:`WorkerTlsConfigurationError` — the caller must fail closed.
    """
    if not isinstance(context, ssl.SSLContext):
        raise ValueError("context must be an ssl.SSLContext")
    hostname = _require_canonical_hostname(approved_hostname)
    if not hasattr(ssl, "OP_NO_RENEGOTIATION"):
        raise WorkerTlsConfigurationError("ssl.OP_NO_RENEGOTIATION is not exposed")
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(list(WORKER_ALPN_PROTOCOLS))
    context.options |= ssl.OP_NO_RENEGOTIATION
    if not (context.options & ssl.OP_NO_RENEGOTIATION):
        raise WorkerTlsConfigurationError(
            "OP_NO_RENEGOTIATION not present in context options after set"
        )
    policy = ExactHostnameSniPolicy(hostname)
    context.sni_callback = policy.callback
    return PreparedWorkerTlsContext(context, hostname, policy)


class ChannelError(Exception):
    """A channel I/O failure after establishment (TLS or transport)."""


class ChannelTimeoutError(ChannelError):
    """A channel operation exceeded its wall-clock bound."""


def _drain_outbio(outbio: ssl.MemoryBIO) -> bytes:
    parts: list[bytes] = []
    while True:
        chunk = outbio.read()
        if not chunk:
            break
        parts.append(chunk)
    return b"".join(parts)


class EstablishedTlsChannel:
    """An established worker TLS session: SSLObject plus its socket shuttle.

    Reads and writes shuttle ciphertext between the MemoryBIO pair and the
    real socket, bounded per operation by a wall-clock deadline.  The
    channel never exposes the raw socket for application use.
    """

    def __init__(
        self,
        sslobj: ssl.SSLObject,
        inbio: ssl.MemoryBIO,
        outbio: ssl.MemoryBIO,
        sock: socket.socket,
    ) -> None:
        self._sslobj = sslobj
        self._inbio = inbio
        self._outbio = outbio
        self._sock = sock
        self._closed = False

    @property
    def tls_version(self) -> str | None:
        return self._sslobj.version()

    @property
    def alpn(self) -> str | None:
        return self._sslobj.selected_alpn_protocol()

    def _flush(self) -> None:
        flight = _drain_outbio(self._outbio)
        if flight:
            try:
                self._sock.sendall(flight)
            except OSError as exc:
                raise ChannelError(f"socket error: {exc}") from exc

    def read(self, max_bytes: int, *, timeout: float = CHANNEL_IO_TIMEOUT_SECONDS) -> bytes:
        """Read up to ``max_bytes`` of application data.

        Returns ``b""`` on a clean close_notify.  Raises
        :class:`ChannelTimeoutError` on deadline, :class:`ChannelError` on
        TLS or transport failure (including EOF without close_notify).
        """
        if type(max_bytes) is not int or max_bytes < 1:
            raise ValueError("max_bytes must be a positive integer")
        deadline = time.monotonic() + timeout
        self._sock.settimeout(min(POLL_SLICE_SECONDS, timeout))
        while True:
            try:
                return self._sslobj.read(max_bytes)
            except ssl.SSLWantReadError:
                self._flush()
                if time.monotonic() >= deadline:
                    raise ChannelTimeoutError("channel read timeout")
                try:
                    data = self._sock.recv(RECV_CHUNK_BYTES)
                except socket.timeout:
                    continue
                except OSError as exc:
                    raise ChannelError(f"socket error: {exc}") from exc
                if data == b"":
                    # EOF without close_notify: let OpenSSL say so.
                    try:
                        return self._sslobj.read(max_bytes)
                    except ssl.SSLError as exc:
                        raise ChannelError(f"unexpected EOF: {exc}") from exc
                self._inbio.write(data)
            except ssl.SSLError as exc:
                raise ChannelError(f"TLS error: {exc}") from exc

    def write(self, data: bytes, *, timeout: float = CHANNEL_IO_TIMEOUT_SECONDS) -> None:
        """Write application data; returns only when all of it is queued."""
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("data must be bytes-like")
        deadline = time.monotonic() + timeout
        self._sock.settimeout(min(POLL_SLICE_SECONDS, timeout))
        while True:
            try:
                self._sslobj.write(bytes(data))
            except ssl.SSLWantReadError:
                self._flush()
                if time.monotonic() >= deadline:
                    raise ChannelTimeoutError("channel write timeout")
                try:
                    incoming = self._sock.recv(RECV_CHUNK_BYTES)
                except socket.timeout:
                    continue
                except OSError as exc:
                    raise ChannelError(f"socket error: {exc}") from exc
                if incoming == b"":
                    raise ChannelError("EOF during channel write")
                self._inbio.write(incoming)
            except ssl.SSLError as exc:
                raise ChannelError(f"TLS error: {exc}") from exc
            else:
                self._flush()
                return

    def close(self) -> None:
        """Flush pending ciphertext (best-effort) and close the socket."""
        if self._closed:
            return
        self._closed = True
        try:
            self._flush()
        except ChannelError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass


@dataclass(frozen=True)
class TerminationOutcome:
    """Typed result of one worker TLS termination; never a bare exception."""

    code: TerminationCode
    reason: str = ""
    channel: EstablishedTlsChannel | None = None
    sni_firing_count: int = 0
    sni_seen: tuple[str | None, ...] = ()
    tls_version: str | None = None
    alpn_selected: str | None = None

    @property
    def established(self) -> bool:
        return self.code is TerminationCode.ESTABLISHED

    def __post_init__(self) -> None:
        if type(self.code) is not TerminationCode:
            raise ValueError("code must be a TerminationCode")
        if self.established and self.channel is None:
            raise ValueError("an established outcome must carry a channel")
        if not self.established and self.channel is not None:
            raise ValueError("a denied outcome carries no channel")


def _deny(
    prepared: PreparedWorkerTlsContext,
    code: TerminationCode,
    reason: str,
) -> TerminationOutcome:
    return TerminationOutcome(
        code,
        reason,
        None,
        prepared.policy.firing_count,
        tuple(prepared.policy.seen),
    )


def terminate_worker_tls(
    sock: socket.socket,
    gate_outcome: nch.GateOutcome,
    prepared: PreparedWorkerTlsContext,
    *,
    timeout: float = HANDSHAKE_TIMEOUT_SECONDS,
    max_handshake_bytes: int = MAX_HANDSHAKE_BYTES,
) -> TerminationOutcome:
    """Terminate worker TLS behind a completed ClientHello gate.

    Replays the gate's accepted bytes VERBATIM into a server-side
    ``SSLObject`` and drives a bounded handshake, shuttling bytes between
    the BIO pair and the real socket (the gate's trailing coalesced bytes
    ride the replay and are consumed by OpenSSL exactly as the gate saw
    them).  On establishment the post-handshake ALPN check is MANDATORY.
    On denial the connection is terminated and the socket closed.
    """
    if not isinstance(sock, socket.socket):
        raise ValueError("sock must be a socket.socket")
    if not isinstance(gate_outcome, nch.GateOutcome):
        raise ValueError("gate_outcome must be a GateOutcome")
    if not isinstance(prepared, PreparedWorkerTlsContext):
        raise ValueError("prepared must be a PreparedWorkerTlsContext")
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or timeout <= 0
    ):
        raise ValueError("timeout must be a positive number of seconds")
    if type(max_handshake_bytes) is not int or max_handshake_bytes < 1:
        raise ValueError("max_handshake_bytes must be a positive integer")

    context = prepared.context
    policy = prepared.policy

    if not gate_outcome.accepted or not gate_outcome.accepted_bytes:
        return _deny(
            prepared,
            TerminationCode.GATE_NOT_ACCEPTED,
            f"gate did not accept; no TLS trust established ({gate_outcome.reason})",
        )
    if not (context.options & ssl.OP_NO_RENEGOTIATION):
        return _deny(
            prepared,
            TerminationCode.CONTEXT_POLICY_VIOLATION,
            "OP_NO_RENEGOTIATION not present on the worker server context",
        )

    inbio = ssl.MemoryBIO()
    outbio = ssl.MemoryBIO()
    try:
        sslobj = context.wrap_bio(inbio, outbio, server_side=True)
    except (ssl.SSLError, ValueError) as exc:
        return _deny(prepared, TerminationCode.HANDSHAKE_FAILED, f"wrap_bio: {exc}")
    inbio.write(gate_outcome.accepted_bytes)  # verbatim replay, trailing bytes included

    failure: TerminationOutcome | None = None
    try:
        failure = _drive_handshake(sock, sslobj, inbio, outbio, prepared,
                                   timeout=timeout, max_bytes=max_handshake_bytes)
    except SniPolicyAbort:
        failure = _deny(
            prepared,
            policy.abort_code or TerminationCode.HANDSHAKE_FAILED,
            policy.abort_reason or "SNI policy abort",
        )
    except ssl.SSLError as exc:
        # A policy abort may surface as a generic SSLError; the policy's own
        # structured decision always wins over the exception flavor.
        if policy.abort_code is not None:
            failure = _deny(prepared, policy.abort_code, policy.abort_reason)
        else:
            failure = _deny(
                prepared, TerminationCode.HANDSHAKE_FAILED,
                f"TLS handshake failed: {exc}",
            )
    except OSError as exc:
        failure = _deny(prepared, TerminationCode.SOCKET_ERROR, f"socket error: {exc}")

    if failure is not None:
        _flush_and_close(sock, outbio)
        return failure

    alpn = sslobj.selected_alpn_protocol()
    if alpn != WORKER_ALPN_PROTOCOL:
        # Spike E3: h2-only and no-ALPN clients complete the handshake with
        # selected ALPN None — the post-handshake check is the enforcement.
        failure = _deny(
            prepared,
            TerminationCode.ALPN_REJECTED,
            f"selected ALPN {alpn!r} != {WORKER_ALPN_PROTOCOL!r}",
        )
        _flush_and_close(sock, outbio)
        return TerminationOutcome(
            failure.code,
            failure.reason,
            None,
            failure.sni_firing_count,
            failure.sni_seen,
            sslobj.version(),
            alpn,
        )

    channel = EstablishedTlsChannel(sslobj, inbio, outbio, sock)
    return TerminationOutcome(
        TerminationCode.ESTABLISHED,
        "",
        channel,
        policy.firing_count,
        tuple(policy.seen),
        sslobj.version(),
        alpn,
    )


def _drive_handshake(
    sock: socket.socket,
    sslobj: ssl.SSLObject,
    inbio: ssl.MemoryBIO,
    outbio: ssl.MemoryBIO,
    prepared: PreparedWorkerTlsContext,
    *,
    timeout: float,
    max_bytes: int,
) -> TerminationOutcome | None:
    """Bounded handshake drive; ``None`` on success, typed denial otherwise."""
    deadline = time.monotonic() + timeout
    previous_timeout: float | None = None
    received = 0
    try:
        previous_timeout = sock.gettimeout()
        sock.settimeout(min(POLL_SLICE_SECONDS, timeout))
    except OSError as exc:
        return _deny(prepared, TerminationCode.SOCKET_ERROR, f"socket error: {exc}")
    try:
        while True:
            try:
                sslobj.do_handshake()
            except ssl.SSLWantReadError:
                flight = _drain_outbio(outbio)
                if flight:
                    try:
                        sock.sendall(flight)
                    except OSError as exc:
                        return _deny(prepared, TerminationCode.SOCKET_ERROR,
                                     f"socket error: {exc}")
                if time.monotonic() >= deadline:
                    return _deny(prepared, TerminationCode.HANDSHAKE_TIMEOUT,
                                 "handshake timeout")
                try:
                    data = sock.recv(RECV_CHUNK_BYTES)
                except socket.timeout:
                    continue
                if data == b"":
                    return _deny(prepared, TerminationCode.HANDSHAKE_FAILED,
                                 "EOF mid-handshake")
                received += len(data)
                if received > max_bytes:
                    return _deny(prepared, TerminationCode.HANDSHAKE_BYTE_BOUND,
                                 "handshake byte bound exceeded")
                inbio.write(data)
            else:
                return None
    finally:
        if previous_timeout is not None:
            try:
                sock.settimeout(previous_timeout)
            except OSError:
                pass


def _flush_and_close(sock: socket.socket, outbio: ssl.MemoryBIO) -> None:
    """Best-effort alert delivery, then terminate the connection."""
    try:
        flight = _drain_outbio(outbio)
        if flight:
            sock.sendall(flight)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


# -- fail-closed startup self-test (Slice 9 startup probe primitives) ---------


class StartupSelfTestError(Exception):
    """A startup self-test invariant failed; the broker must not go ready."""


def _self_test_client_hello(hostname: bytes, *, ech: bool) -> bytes:
    """Minimal synthetic ClientHello for the gate self-test leg.

    Well-formed per the gate's parser: TLS1.3-style cipher list, exact SNI
    extension, optional 0xfe0d.  Used only to prove the enforcement path is
    live at startup — never parsed by OpenSSL.
    """
    body = struct.pack(">H", 0x0303) + bytes(32)  # legacy_version + random
    body += b"\x00"                                # session_id length 0
    suites = struct.pack(">HH", 0x1301, 0x1302)
    body += struct.pack(">H", len(suites)) + suites
    body += b"\x01\x00"                            # one null compression
    name_entry = b"\x00" + struct.pack(">H", len(hostname)) + hostname
    sni_payload = struct.pack(">H", len(name_entry)) + name_entry
    extensions = [(nch.EXT_SERVER_NAME, sni_payload)]
    if ech:
        extensions.append((nch.EXT_ECH, b"\x00"))
    ext_block = b"".join(
        struct.pack(">HH", ext_id, len(payload)) + payload
        for ext_id, payload in extensions
    )
    body += struct.pack(">H", len(ext_block)) + ext_block
    message = bytes([nch.HT_CLIENT_HELLO]) + len(body).to_bytes(3, "big") + body
    return (
        bytes([nch.CT_HANDSHAKE])
        + struct.pack(">HH", 0x0301, len(message))
        + message
    )


def run_tls_startup_self_test(
    *,
    recorded_openssl_version: str = RECORDED_OPENSSL_VERSION,
) -> dict:
    """Fail-closed startup self-test for the worker TLS boundary.

    Legs (any failure raises :class:`StartupSelfTestError`):

    1. Gate self-test: a synthetic ECH-bearing ClientHello must reject
       (because of 0xfe0d), a synthetic clean ClientHello must accept, and
       the replay bytes must be byte-verbatim — proves the enforcement code
       path is live in THIS process.
    2. OpenSSL identity: ``ssl.OPENSSL_VERSION`` must equal the recorded,
       reviewed value; any other stack is unmeasured.
    3. ``OP_NO_RENEGOTIATION`` must be exposed and verifiably settable.
    4. Host-qualification behavior probes (MemoryBIO/SSLObject, ALPN) plus
       absence of ECH acceptance machinery symbols in the loaded libssl —
       reused from :mod:`agenticos.sandbox.host_qualification`.
    """
    ech_hello = _self_test_client_hello(b"approved.example.test", ech=True)
    gate = nch.ClientHelloGate()
    if gate.feed(ech_hello) is not nch.GateDecision.REJECT:
        raise StartupSelfTestError("gate accepted an ECH-bearing ClientHello")
    if "0xfe0d" not in gate.rejection_reason:
        raise StartupSelfTestError(
            f"gate rejected ECH for the wrong reason: {gate.rejection_reason}"
        )
    clean_hello = _self_test_client_hello(b"approved.example.test", ech=False)
    clean_gate = nch.ClientHelloGate()
    if clean_gate.feed(clean_hello) is not nch.GateDecision.ACCEPT:
        raise StartupSelfTestError(
            f"gate rejected a clean ClientHello: {clean_gate.rejection_reason}"
        )
    if clean_gate.accepted_bytes != clean_hello:
        raise StartupSelfTestError("gate replay is not byte-verbatim")

    if ssl.OPENSSL_VERSION != recorded_openssl_version:
        raise StartupSelfTestError(
            f"unmeasured OpenSSL: {ssl.OPENSSL_VERSION!r} "
            f"(recorded {recorded_openssl_version!r})"
        )

    if not hasattr(ssl, "OP_NO_RENEGOTIATION"):
        raise StartupSelfTestError("ssl.OP_NO_RENEGOTIATION is not exposed")
    probe_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    probe_context.options |= ssl.OP_NO_RENEGOTIATION
    if not (probe_context.options & ssl.OP_NO_RENEGOTIATION):
        raise StartupSelfTestError(
            "OP_NO_RENEGOTIATION not present in context options after set"
        )

    try:
        behavior = host_qualification._probe_python_ssl_behavior()
        libraries = host_qualification._loaded_tls_libraries()
    except host_qualification.HostQualificationError as exc:
        raise StartupSelfTestError(f"host qualification probe failed: {exc}") from exc
    library = ctypes.CDLL(str(libraries["libssl"]))
    present = [
        symbol
        for symbol in host_qualification.ECH_MACHINERY_SYMBOLS
        if hasattr(library, symbol)
    ]
    if present:
        raise StartupSelfTestError(
            f"loaded libssl exports ECH acceptance machinery: {present}"
        )

    return {
        "gate_self_test": "pass",
        "openssl_version": ssl.OPENSSL_VERSION,
        "op_no_renegotiation": "pass",
        "python_ssl_behavior": behavior,
        "ech_machinery": "absent",
    }
