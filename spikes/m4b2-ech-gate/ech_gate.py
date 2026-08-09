"""Bounded TLS ClientHello ECH gate — Candidate B spike.

SPIKE CODE — not production. Standard-library only.

Contract:
  * Read bounded TLS records from a worker-controlled byte stream.
  * Reassemble exactly the first handshake message and require it to be a
    structurally valid ClientHello.
  * Reject if extension 0xfe0d (encrypted_client_hello) is present.
  * On acceptance, return the EXACT original bytes (including any coalesced
    trailing bytes) for verbatim replay into the real TLS stack.
  * Never rewrites, normalizes, or reinterprets the byte stream.

Fail-closed: any deviation from the expected structure rejects the
connection. Rejecting input that OpenSSL might have accepted is safe
(compatibility cost only); the gate must never ACCEPT a byte stream whose
first ClientHello — as OpenSSL will parse it — contains 0xfe0d.
"""

from __future__ import annotations

import enum

CT_HANDSHAKE = 22
HT_CLIENT_HELLO = 1
EXT_ECH = 0xFE0D

# Explicit bounds (spike values, justified in results.md):
MAX_RECORD_PAYLOAD = 16384        # RFC 8446 §5.1 max plaintext fragment
MAX_RECORD_VERSION = 0x0303       # record-layer legacy version floor/ceiling
MIN_RECORD_VERSION = 0x0301       # TLS 1.0 floor; SSLv3/SSLv2 rejected
MAX_CLIENT_HELLO_BYTES = 16384    # handshake message cap (one max record's worth)
MAX_RECORDS = 64                  # record-layer fragmentation bound
MAX_EXTENSIONS = 256              # extension-count bound (2-byte length block caps ~16k)
MAX_READ_CALLS = 4096             # transport read-syscall bound; the byte and
                                  # wall-clock bounds do the real work — a CH is
                                  # capped at ~16.6 KB on the wire, so 4096 reads
                                  # still forces >= ~4 bytes/read on average
GATE_TIMEOUT_SECONDS = 5.0        # wall-clock bound for the whole gate phase


class Decision(enum.Enum):
    ACCEPT = "accept"
    REJECT = "reject"
    NEED_MORE = "need_more"


class GateReject(Exception):
    """Raised internally; converted to a REJECT decision. Carries a reason."""


class _Cursor:
    """Bounds-checked cursor over a bytes-like buffer."""

    __slots__ = ("buf", "pos", "end")

    def __init__(self, buf: bytes, start: int = 0, end: int | None = None):
        self.buf = buf
        self.pos = start
        self.end = len(buf) if end is None else end

    def take(self, n: int, what: str) -> bytes:
        if n < 0 or self.pos + n > self.end:
            raise GateReject(f"truncated {what}")
        out = self.buf[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self, what: str) -> int:
        return self.take(1, what)[0]

    def u16(self, what: str) -> int:
        return int.from_bytes(self.take(2, what), "big")

    def u24(self, what: str) -> int:
        return int.from_bytes(self.take(3, what), "big")

    def exhausted(self) -> bool:
        return self.pos == self.end


class ClientHelloGate:
    """Incremental parser. Feed transport bytes; poll for a decision.

    On ACCEPT, `accepted_bytes` holds every byte fed so far, unchanged,
    and `metadata` holds the observed SNI (or None), offered TLS1.3 flag,
    and extension-id list for evidence/differential comparison.
    """

    def __init__(self) -> None:
        self._records_buf = bytearray()   # raw record bytes pending parse
        self._raw_log = bytearray()       # every byte ever fed (verbatim replay)
        self._hs = bytearray()            # reassembled handshake-layer bytes
        self._record_count = 0
        self._decision: Decision | None = None
        self.reason = ""
        self.accepted_bytes: bytes = b""
        self.metadata: dict = {}

    # -- public API ------------------------------------------------------

    @property
    def decision(self) -> Decision | None:
        return self._decision

    def feed(self, data: bytes) -> Decision | None:
        """Feed raw transport bytes. Returns the decision once reached."""
        if self._decision is not None:
            raise GateReject("feed after decision")
        self._raw_log += data
        self._records_buf += data
        try:
            self._process_records()
        except GateReject as exc:
            self._decision = Decision.REJECT
            self.reason = str(exc)
        return self._decision

    # -- record layer ----------------------------------------------------

    def _process_records(self) -> None:
        buf = self._records_buf
        consumed = 0
        while True:
            if self._ch_complete():
                self._finish_accept(consumed)
                return
            available = len(buf) - consumed
            if available < 5:
                break  # need more header bytes
            content_type = buf[consumed]
            record_version = int.from_bytes(buf[consumed + 1 : consumed + 3], "big")
            record_len = int.from_bytes(buf[consumed + 3 : consumed + 5], "big")
            if content_type != CT_HANDSHAKE:
                raise GateReject(f"non-handshake record content type {content_type}")
            if not (MIN_RECORD_VERSION <= record_version <= MAX_RECORD_VERSION):
                raise GateReject(f"unsupported record version 0x{record_version:04x}")
            if record_len == 0:
                raise GateReject("zero-length handshake record")
            if record_len > MAX_RECORD_PAYLOAD:
                raise GateReject(f"oversized record payload {record_len}")
            if available - 5 < record_len:
                break  # need more payload bytes
            self._record_count += 1
            if self._record_count > MAX_RECORDS:
                raise GateReject("record count bound exceeded")
            payload = buf[consumed + 5 : consumed + 5 + record_len]
            self._hs += payload
            if len(self._hs) > MAX_CLIENT_HELLO_BYTES + 4:
                raise GateReject("client hello byte bound exceeded")
            consumed += 5 + record_len
        if consumed:
            del self._records_buf[:consumed]

    def _ch_complete(self) -> bool:
        hs = self._hs
        if len(hs) < 4:
            return False
        if hs[0] != HT_CLIENT_HELLO:
            raise GateReject(f"first handshake message type {hs[0]} != ClientHello")
        declared = int.from_bytes(hs[1:4], "big")
        if declared > MAX_CLIENT_HELLO_BYTES:
            raise GateReject(f"declared ClientHello length {declared} exceeds bound")
        return len(hs) >= 4 + declared

    # -- handshake layer -------------------------------------------------

    def _finish_accept(self, consumed_records: int) -> None:
        hs = self._hs
        declared = int.from_bytes(hs[1:4], "big")
        ch = _Cursor(bytes(hs), 4, 4 + declared)

        legacy_version = ch.u16("legacy_version")
        ch.take(32, "random")
        sid_len = ch.u8("session_id length")
        ch.take(sid_len, "session_id")
        cs_len = ch.u16("cipher_suites length")
        if cs_len == 0 or cs_len % 2:
            raise GateReject("malformed cipher_suites length")
        ch.take(cs_len, "cipher_suites")
        comp_len = ch.u8("compression_methods length")
        if comp_len == 0:
            raise GateReject("malformed compression_methods length")
        ch.take(comp_len, "compression_methods")

        ext_ids: list[int] = []
        sni: bytes | None = None
        if not ch.exhausted():
            ext_total = ch.u16("extensions length")
            ext_end = ch.pos + ext_total
            if ext_end != ch.end:
                raise GateReject("extensions block length mismatch")
            seen: set[int] = set()
            while ch.pos < ext_end:
                ext_id = ch.u16("extension id")
                ext_len = ch.u16("extension length")
                payload = ch.take(ext_len, "extension payload")
                if ext_id in seen:
                    raise GateReject(f"duplicate extension 0x{ext_id:04x}")
                seen.add(ext_id)
                if len(ext_ids) >= MAX_EXTENSIONS:
                    raise GateReject("extension count bound exceeded")
                ext_ids.append(ext_id)
                if ext_id == EXT_ECH:
                    raise GateReject("ECH extension 0xfe0d present")
                if ext_id == 0x0000:
                    sni = self._parse_sni(payload)
            if not ch.exhausted():
                raise GateReject("trailing bytes in ClientHello")

        # Everything fed so far — the complete CH records plus any
        # coalesced trailing bytes — is replayed verbatim downstream.
        self.accepted_bytes = bytes(self._raw_log)
        self.metadata = {
            "legacy_version": legacy_version,
            "sni": sni,
            "extension_ids": ext_ids,
            "record_count": self._record_count,
            "declared_len": declared,
        }
        self._decision = Decision.ACCEPT

    @staticmethod
    def _parse_sni(payload: bytes) -> bytes | None:
        cur = _Cursor(payload)
        total = cur.u16("server_name_list length")
        if total != len(payload) - 2:
            raise GateReject("server_name_list length mismatch")
        if total == 0:
            return None
        name_type = cur.u8("server_name type")
        name_len = cur.u16("server_name length")
        name = cur.take(name_len, "server_name")
        if name_type != 0 or name_len == 0:
            raise GateReject("unsupported server_name entry")
        if not cur.exhausted():
            raise GateReject("multiple server_name entries")
        return name
