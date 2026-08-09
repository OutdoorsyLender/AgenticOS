"""Bounded pre-TLS ClientHello gate for the M4B-2 worker-facing TLS path.

The broker terminates worker TLS itself, but the host OpenSSL cannot
enumerate unrecognized ClientHello extensions: extension 0xfe0d
(encrypted_client_hello) is invisible to its client-hello API (measured in
the M4B-2 ECH spike, ``spikes/m4b2-ech-gate/results.md``).  This module is
the enforcement point.  A bounded pure-Python gate inspects the EXACT
worker bytes on the accepted broker connection, reassembles precisely the
first handshake message (which must be a structurally valid ClientHello),
enumerates extension IDs, and rejects any ClientHello carrying 0xfe0d
BEFORE any SNI trust decision.  On acceptance it returns the exact
original bytes — including any coalesced trailing bytes — for verbatim
replay into ``ssl.MemoryBIO``/``SSLObject``.  The gate never rewrites,
normalizes, or reinterprets the byte stream.

Fail-closed contract: any malformed length, EOF, timeout, wrong content
type, or bound violation rejects the connection.  Rejecting input that
OpenSSL might have accepted costs compatibility only; the gate must never
ACCEPT a byte stream whose first ClientHello — as OpenSSL will parse it —
contains 0xfe0d.  Every gate/OpenSSL divergence measured in the spike's
50-case adversarial corpus is in that safe (gate-stricter) direction, and
the corpus is a permanent regression suite under ``tests/conformance``.

Bounds (measured compatible clients are >=10x inside every axis):

* TLS record payload <= 16384 (RFC 8446 section 5.1 max plaintext fragment)
* record-layer version 0x0301-0x0303 only (SSLv3/SSLv2 formats rejected)
* accumulated ClientHello handshake bytes <= 16384
* record count <= 64; extension count <= 256
* transport read calls <= 4096; wall-clock gate deadline <= 5 seconds
* zero-length handshake records, duplicate extensions, and any first
  handshake message other than ClientHello are rejected

Because one gate can hold a worker connection for up to the wall-clock
deadline, :class:`BoundedGateGuard` caps the number of simultaneously
in-progress gates; acquisition failure must fail the connection closed.

Standard library only: this module runs inside the broker boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import socket
import threading
import time

CT_HANDSHAKE = 22
HT_CLIENT_HELLO = 1
EXT_SERVER_NAME = 0x0000
EXT_ECH = 0xFE0D

MAX_RECORD_PAYLOAD = 16384        # RFC 8446 section 5.1 max plaintext fragment
MIN_RECORD_VERSION = 0x0301       # TLS 1.0 floor; SSLv3/SSLv2 rejected
MAX_RECORD_VERSION = 0x0303
MAX_CLIENT_HELLO_BYTES = 16384    # handshake message cap (one max record's worth)
MAX_RECORDS = 64                  # record-layer fragmentation bound
MAX_EXTENSIONS = 256              # extension-count bound
MAX_READ_CALLS = 4096             # transport read-syscall bound; the byte and
                                  # wall-clock bounds do the real work — a CH is
                                  # capped at ~16.6 KB on the wire, so 4096 reads
                                  # still forces >= ~4 bytes/read on average
GATE_TIMEOUT_SECONDS = 5.0        # wall-clock bound for the whole gate phase
RECV_CHUNK_BYTES = 65536          # one recv can never unbound accepted_bytes
POLL_SLICE_SECONDS = 0.25         # recv timeout slice; deadline re-checked per slice

DEFAULT_MAX_IN_FLIGHT_GATES = 8   # small broker-level concurrency bound


class GateDecision(str, Enum):
    """Terminal gate verdict; ``None`` from ``feed`` means more bytes needed."""

    ACCEPT = "accept"
    REJECT = "reject"


class _GateReject(Exception):
    """Internal reject signal; converted into a typed fail-closed outcome."""


class _Cursor:
    """Bounds-checked cursor over a bytes-like buffer."""

    __slots__ = ("buf", "pos", "end")

    def __init__(self, buf: bytes, start: int = 0, end: int | None = None):
        self.buf = buf
        self.pos = start
        self.end = len(buf) if end is None else end

    def take(self, n: int, what: str) -> bytes:
        if n < 0 or self.pos + n > self.end:
            raise _GateReject(f"truncated {what}")
        out = self.buf[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self, what: str) -> int:
        return self.take(1, what)[0]

    def u16(self, what: str) -> int:
        return int.from_bytes(self.take(2, what), "big")

    def exhausted(self) -> bool:
        return self.pos == self.end


@dataclass(frozen=True)
class ClientHelloMetadata:
    """Observations from an accepted ClientHello, for evidence/differential."""

    legacy_version: int
    sni: bytes | None
    extension_ids: tuple[int, ...]
    record_count: int
    declared_length: int


class ClientHelloGate:
    """Incremental ClientHello parser.  Feed transport bytes; poll decision.

    On ACCEPT, ``accepted_bytes`` holds every byte fed so far, unchanged
    (complete CH records plus any coalesced trailing bytes), and
    ``metadata`` holds the observed SNI (or None) and extension-ID list.
    On REJECT, ``rejection_reason`` carries the fail-closed cause.
    """

    def __init__(self) -> None:
        self._records_buf = bytearray()   # raw record bytes pending parse
        self._raw_log = bytearray()       # every byte ever fed (verbatim replay)
        self._hs = bytearray()            # reassembled handshake-layer bytes
        self._record_count = 0
        self._decision: GateDecision | None = None
        self.rejection_reason = ""
        self.accepted_bytes: bytes = b""
        self.metadata: ClientHelloMetadata | None = None

    @property
    def decision(self) -> GateDecision | None:
        return self._decision

    def feed(self, data: bytes) -> GateDecision | None:
        """Feed raw transport bytes.  Returns the decision once reached."""
        if self._decision is not None:
            raise _GateReject("feed after decision")
        self._raw_log += data
        self._records_buf += data
        try:
            self._process_records()
        except _GateReject as exc:
            self._decision = GateDecision.REJECT
            self.rejection_reason = str(exc)
        return self._decision

    # -- record layer ------------------------------------------------------

    def _process_records(self) -> None:
        buf = self._records_buf
        consumed = 0
        while True:
            if self._ch_complete():
                self._finish_accept()
                return
            available = len(buf) - consumed
            if available < 5:
                break  # need more header bytes
            content_type = buf[consumed]
            record_version = int.from_bytes(buf[consumed + 1 : consumed + 3], "big")
            record_len = int.from_bytes(buf[consumed + 3 : consumed + 5], "big")
            if content_type != CT_HANDSHAKE:
                raise _GateReject(f"non-handshake record content type {content_type}")
            if not (MIN_RECORD_VERSION <= record_version <= MAX_RECORD_VERSION):
                raise _GateReject(f"unsupported record version 0x{record_version:04x}")
            if record_len == 0:
                raise _GateReject("zero-length handshake record")
            if record_len > MAX_RECORD_PAYLOAD:
                raise _GateReject(f"oversized record payload {record_len}")
            if available - 5 < record_len:
                break  # need more payload bytes
            self._record_count += 1
            if self._record_count > MAX_RECORDS:
                raise _GateReject("record count bound exceeded")
            payload = buf[consumed + 5 : consumed + 5 + record_len]
            self._hs += payload
            if len(self._hs) > MAX_CLIENT_HELLO_BYTES + 4:
                raise _GateReject("client hello byte bound exceeded")
            consumed += 5 + record_len
        if consumed:
            del self._records_buf[:consumed]

    def _ch_complete(self) -> bool:
        hs = self._hs
        if len(hs) < 4:
            return False
        if hs[0] != HT_CLIENT_HELLO:
            raise _GateReject(f"first handshake message type {hs[0]} != ClientHello")
        declared = int.from_bytes(hs[1:4], "big")
        if declared > MAX_CLIENT_HELLO_BYTES:
            raise _GateReject(f"declared ClientHello length {declared} exceeds bound")
        return len(hs) >= 4 + declared

    # -- handshake layer ---------------------------------------------------

    def _finish_accept(self) -> None:
        hs = self._hs
        declared = int.from_bytes(hs[1:4], "big")
        ch = _Cursor(bytes(hs), 4, 4 + declared)

        legacy_version = ch.u16("legacy_version")
        ch.take(32, "random")
        sid_len = ch.u8("session_id length")
        ch.take(sid_len, "session_id")
        cs_len = ch.u16("cipher_suites length")
        if cs_len == 0 or cs_len % 2:
            raise _GateReject("malformed cipher_suites length")
        ch.take(cs_len, "cipher_suites")
        comp_len = ch.u8("compression_methods length")
        if comp_len == 0:
            raise _GateReject("malformed compression_methods length")
        ch.take(comp_len, "compression_methods")

        ext_ids: list[int] = []
        sni: bytes | None = None
        if not ch.exhausted():
            ext_total = ch.u16("extensions length")
            ext_end = ch.pos + ext_total
            if ext_end != ch.end:
                raise _GateReject("extensions block length mismatch")
            seen: set[int] = set()
            while ch.pos < ext_end:
                ext_id = ch.u16("extension id")
                ext_len = ch.u16("extension length")
                payload = ch.take(ext_len, "extension payload")
                if ext_id in seen:
                    raise _GateReject(f"duplicate extension 0x{ext_id:04x}")
                seen.add(ext_id)
                if len(ext_ids) >= MAX_EXTENSIONS:
                    raise _GateReject("extension count bound exceeded")
                ext_ids.append(ext_id)
                if ext_id == EXT_ECH:
                    raise _GateReject("ECH extension 0xfe0d present")
                if ext_id == EXT_SERVER_NAME:
                    sni = self._parse_sni(payload)
            if not ch.exhausted():
                raise _GateReject("trailing bytes in ClientHello")

        # Everything fed so far — the complete CH records plus any
        # coalesced trailing bytes — is replayed verbatim downstream.
        self.accepted_bytes = bytes(self._raw_log)
        self.metadata = ClientHelloMetadata(
            legacy_version=legacy_version,
            sni=sni,
            extension_ids=tuple(ext_ids),
            record_count=self._record_count,
            declared_length=declared,
        )
        self._decision = GateDecision.ACCEPT

    @staticmethod
    def _parse_sni(payload: bytes) -> bytes | None:
        cur = _Cursor(payload)
        total = cur.u16("server_name_list length")
        if total != len(payload) - 2:
            raise _GateReject("server_name_list length mismatch")
        if total == 0:
            return None
        name_type = cur.u8("server_name type")
        name_len = cur.u16("server_name length")
        name = cur.take(name_len, "server_name")
        if name_type != 0 or name_len == 0:
            raise _GateReject("unsupported server_name entry")
        if not cur.exhausted():
            raise _GateReject("multiple server_name entries")
        return name


class GatePermit:
    """Admission token for one in-progress gate.  Release is idempotent."""

    __slots__ = ("_guard", "_released")

    def __init__(self, guard: BoundedGateGuard) -> None:
        self._guard = guard
        self._released = False

    def release(self) -> None:
        with self._guard._lock:
            if not self._released:
                self._released = True
                self._guard._in_flight -= 1

    def __enter__(self) -> GatePermit:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()


class BoundedGateGuard:
    """Broker-level bound on simultaneously in-progress ClientHello gates.

    One gate can hold a worker connection open for up to
    ``GATE_TIMEOUT_SECONDS``; without a concurrency bound many simultaneous
    gated connections would multiply that window (spike handoff item).
    Acquisition is non-blocking: when the bound is exhausted the caller
    MUST fail the connection closed, which :func:`run_gate_on_socket` does.
    The bound is fixed at construction; the default is deliberately small.
    """

    def __init__(self, max_in_flight: int = DEFAULT_MAX_IN_FLIGHT_GATES) -> None:
        if type(max_in_flight) is not int or max_in_flight < 1:
            raise ValueError("max_in_flight must be a positive integer")
        self._max_in_flight = max_in_flight
        self._in_flight = 0
        self._lock = threading.Lock()

    @property
    def max_in_flight(self) -> int:
        return self._max_in_flight

    @property
    def in_flight(self) -> int:
        with self._lock:
            return self._in_flight

    def try_acquire(self) -> GatePermit | None:
        """Take an admission slot, or return None when the bound is full."""
        with self._lock:
            if self._in_flight >= self._max_in_flight:
                return None
            self._in_flight += 1
        return GatePermit(self)


@dataclass(frozen=True)
class GateOutcome:
    """Typed result of one gated connection; never a bare exception."""

    decision: GateDecision
    reason: str = ""
    accepted_bytes: bytes = b""
    metadata: ClientHelloMetadata | None = None
    read_calls: int = 0
    elapsed_seconds: float = 0.0

    @property
    def accepted(self) -> bool:
        return self.decision is GateDecision.ACCEPT

    def __post_init__(self) -> None:
        if type(self.decision) is not GateDecision:
            raise ValueError("decision must be a GateDecision")
        if self.accepted and not self.accepted_bytes:
            raise ValueError("an accepted gate outcome must carry replay bytes")
        if not self.accepted and self.accepted_bytes:
            raise ValueError("a rejected gate outcome carries no replay bytes")


def run_gate_on_socket(
    sock: socket.socket,
    *,
    timeout: float = GATE_TIMEOUT_SECONDS,
    max_read_calls: int = MAX_READ_CALLS,
    guard: BoundedGateGuard | None = None,
) -> GateOutcome:
    """Drive the ClientHello gate over a blocking socket with explicit bounds.

    Returns a typed :class:`GateOutcome`; worker-controlled input and
    transport failures never raise.  When ``guard`` is given, one admission
    slot is held for the whole gate phase and an exhausted guard fails the
    connection closed without consuming a single worker byte.  The socket's
    previous timeout is restored before returning.
    """
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("timeout must be a positive number of seconds")
    if type(max_read_calls) is not int or max_read_calls < 1:
        raise ValueError("max_read_calls must be a positive integer")

    started = time.monotonic()
    deadline = started + timeout

    def reject(reason: str, reads: int) -> GateOutcome:
        return GateOutcome(
            GateDecision.REJECT,
            reason,
            read_calls=reads,
            elapsed_seconds=time.monotonic() - started,
        )

    permit: GatePermit | None = None
    if guard is not None:
        permit = guard.try_acquire()
        if permit is None:
            return reject("gate concurrency bound exceeded", 0)

    previous_timeout: float | None = None
    try:
        try:
            previous_timeout = sock.gettimeout()
            sock.settimeout(min(POLL_SLICE_SECONDS, timeout))
        except OSError as exc:
            return reject(f"socket error: {exc}", 0)

        gate = ClientHelloGate()
        reads = 0
        while True:
            try:
                chunk = sock.recv(RECV_CHUNK_BYTES)
            except socket.timeout:
                chunk = None
            except OSError as exc:
                return reject(f"socket error: {exc}", reads)
            if chunk is not None:
                reads += 1
                if chunk == b"":
                    return reject("EOF before ClientHello complete", reads)
                try:
                    decision = gate.feed(chunk)
                except Exception as exc:  # feed-after-decision is a bug; fail closed
                    return reject(f"gate internal error: {type(exc).__name__}: {exc}", reads)
                if decision is GateDecision.ACCEPT:
                    return GateOutcome(
                        GateDecision.ACCEPT,
                        "",
                        gate.accepted_bytes,
                        gate.metadata,
                        reads,
                        time.monotonic() - started,
                    )
                if decision is GateDecision.REJECT:
                    return reject(gate.rejection_reason, reads)
            if reads >= max_read_calls:
                return reject("read-call bound exceeded", reads)
            if time.monotonic() >= deadline:
                return reject("gate timeout", reads)
    finally:
        if permit is not None:
            permit.release()
        if previous_timeout is not None:
            try:
                sock.settimeout(previous_timeout)
            except OSError:
                pass
