"""Conformance Corpus A for the M4B-2 production ClientHello gate.

The 50-case adversarial corpus recorded by the M4B-2 ECH spike
(``spikes/m4b2-ech-gate/results.json``) is promoted to run against the
PRODUCTION gate (``agenticos.sandbox.network_clienthello``) with the same
expected gate decisions, rejection reasons, extension observations, SNI
observations, and OpenSSL outcomes.  Six further cases close gaps found
while promoting: the spike's three ``p_*`` cases were dead code (an early
``return`` in its ``build_cases`` meant they never executed), the
zero-length-record case never actually reached the zero-length branch
(the injected record landed mid-record, i.e. inside the first record's
declared payload), and the record-count bound had no exact-boundary case.

Every case runs twice:

* parser level — bytes fed straight to ``ClientHelloGate.feed`` (chunked
  exactly as the socket fixture would deliver them), pinning the pure
  parser contract including the verbatim-replay property;
* socket level — bytes driven over a real socket through the production
  bounded driver ``run_gate_on_socket`` and, for gate-accept cases,
  replayed verbatim into a real ``ssl.MemoryBIO`` server-side ``SSLObject``
  under the spike's approved-hostname SNI policy.

Differential check (spike T1, made permanent): for every gate-accept case
the OpenSSL observation must match the gate's — same SNI, same sni_callback
firing list, same accept/fail outcome class.  Any UNSAFE parser
differential (OpenSSL acting on an SNI the gate did not observe, or an SNI
mismatch) fails the suite; that is a stop condition, not a ship.  Bare
Python ``ssl`` cannot enumerate ClientHello extension IDs, so the
wire-order extension-set differential remains spike-only (it needs the
native probe); what is pinned here is every observation Python ssl exposes.

All fixtures are synthetic and local (AF_UNIX socketpair).  The server
certificate is an RSA-2048 self-signed fixture generated with the host
``openssl`` CLI, exactly as the spike generated it: the recorded corpus
template offers only ECDHE-RSA TLS 1.2 cipher suites (0xC02F/0xC030), so
an RSA leaf is required to reproduce the recorded TLS 1.2 OpenSSL
outcomes.  Requires Linux for AF_UNIX ``socket.socketpair`` semantics.
"""

from __future__ import annotations

import sys

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("M4B-2 ClientHello gate corpus requires Linux", allow_module_level=True)

import os
from dataclasses import dataclass, field
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import threading
import time

import chgen
from agenticos.sandbox import network_clienthello as nch

APPROVED = "approved.example.test"
APPROVED_BYTES = APPROVED.encode()

# Extension-ID lists recorded by the spike for the standard templates.
EXTS_TLS12 = (0, 10, 11, 13, 16, 43)
EXTS_TLS13 = (0, 10, 11, 13, 16, 43, 45, 51)


@pytest.fixture(scope="module")
def server_context(tmp_path_factory):
    """An RSA self-signed server context, mirroring the spike's fixture."""
    work = tmp_path_factory.mktemp("clienthello-tls")
    cert = work / "cert.pem"
    key = work / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "2",
         "-subj", f"/CN={APPROVED}",
         "-addext", f"subjectAltName=DNS:{APPROVED}"],
        check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_RENEGOTIATION
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(str(cert), str(key))
    return context


class SniPolicyError(Exception):
    """Raised by the exact-hostname SNI policy callback to abort TLS."""


@dataclass
class HandshakeResult:
    outcome: str = "failed"     # "completed" | "ch_accepted" | "failed"
    error: str = ""
    sni_seen: list = field(default_factory=list)


def drive_handshake(
    sock: socket.socket,
    ctx: ssl.SSLContext,
    initial_bytes: bytes,
    fires: list,
    *,
    timeout: float = 10.0,
) -> HandshakeResult:
    """Replay gate-accepted bytes verbatim into OpenSSL via MemoryBIO and
    drive the server-side handshake.  ``ch_accepted`` means OpenSSL consumed
    the ClientHello and emitted its server flight; the fixture need not
    complete the crypto.  Mirrors the spike driver, including the rule that
    a TLS-layer exception after CH acceptance still classifies "failed".
    """
    inbio = ssl.MemoryBIO()
    outbio = ssl.MemoryBIO()
    sslobj = ctx.wrap_bio(inbio, outbio, server_side=True)
    result = HandshakeResult()
    inbio.write(initial_bytes)
    deadline = time.monotonic() + timeout
    sock.settimeout(0.25)
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
                    result.outcome = "ch_accepted"
                if time.monotonic() >= deadline:
                    result.error = "handshake timeout"
                    break
                try:
                    data = sock.recv(65536)
                except socket.timeout:
                    continue
                except OSError as exc:
                    result.error = f"socket error: {exc}"
                    break
                if data == b"":
                    result.error = "EOF from fixture"
                    break
                inbio.write(data)
                continue
            else:
                result.outcome = "completed"
                break
    except (ssl.SSLError, SniPolicyError, OSError) as exc:
        if result.outcome != "completed":
            result.outcome = "failed"
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        result.sni_seen = list(fires)
    return result


# ---------------------------------------------------------------------------
# Case definitions — the 50 recorded spike cases plus six promotion additions
# ---------------------------------------------------------------------------

@dataclass
class Case:
    name: str
    category: str
    flights: list[bytes]
    chunk_sizes: list[int] | None = None
    drip: bool = False
    hold_open: bool = False          # keep the stream open until gate timeout
    refuse_second_ch: bool = False   # policy: abort on 2nd sni_callback firing
    gate_timeout: float = 5.0
    read_window: float = 0.4
    parser_decides: bool = True      # False: parser stays undecided (timeout/EOF)
    expect_gate: str = "accept"
    expect_reason: str = ""
    expect_exts: tuple[int, ...] | None = None
    expect_sni: str | None = None
    expect_openssl: str | None = None   # "ch_accepted" | "failed" on accept
    expect_fires: tuple = ()


def _split_sizes(total: int, n: int) -> list[int]:
    """n positive fragment sizes summing to total (zero-size would reject)."""
    assert total >= n
    base, rem = divmod(total, n)
    return [base + (1 if i < rem else 0) for i in range(n)]


def build_cases() -> list[Case]:
    cases: list[Case] = []
    ap = APPROVED_BYTES

    def add(name, category, flights, **kw):
        cases.append(Case(name, category, flights, **kw))

    def accept(name, category, flights, exts, sni, openssl, fires, **kw):
        add(name, category, flights, expect_exts=exts, expect_sni=sni,
            expect_openssl=openssl, expect_fires=fires, **kw)

    def reject(name, category, flights, reason, **kw):
        add(name, category, flights, expect_gate="reject", expect_reason=reason,
            **kw)

    # ---- SUCCESS ------------------------------------------------------
    accept("s01_tls12_no_ech", "success",
           [chgen.make_client_hello(ap, tls13=False)],
           EXTS_TLS12, APPROVED, "ch_accepted", (APPROVED,))
    accept("s02_tls13_no_ech", "success",
           [chgen.make_client_hello(ap, tls13=True)],
           EXTS_TLS13, APPROVED, "ch_accepted", (APPROVED,))
    ch = chgen.make_client_hello(ap)
    body_len = len(ch) - 5
    frag = chgen.fragment_handshake_into_records(ch[5:], [3, 7, body_len - 10])
    accept("s03_record_fragmented", "success", [frag],
           EXTS_TLS13, APPROVED, "ch_accepted", (APPROVED,))
    small = chgen.make_client_hello(ap, tls13=False, session_id=b"",
                                    alpn=[b"http/1.1"])
    accept("s04_drip_feed", "success", [small],
           EXTS_TLS12, APPROVED, "ch_accepted", (APPROVED,),
           drip=True, read_window=0.6)
    frag2 = chgen.fragment_handshake_into_records(
        ch[5:], [body_len // 2, body_len - body_len // 2])
    accept("s05a_coalesced_records", "success", [frag2],
           EXTS_TLS13, APPROVED, "ch_accepted", (APPROVED,))
    accept("s05b_coalesced_ch_plus_ccs", "success",
           [ch + chgen.build_record(chgen.CT_CHANGE_CIPHER_SPEC, b"\x01",
                                    record_version=0x0303)],
           EXTS_TLS13, APPROVED, "ch_accepted", (APPROVED,))
    accept("s06_unknown_ext", "success",
           [chgen.make_client_hello(ap, extra_extensions=[(0xCAFE, b"\x01\x02")])],
           EXTS_TLS13 + (0xCAFE,), APPROVED, "ch_accepted", (APPROVED,))
    accept("s07_grease_exts", "success",
           [chgen.make_client_hello(ap, grease=True)],
           (0x0A0A,) + EXTS_TLS13 + (0x1A1A,), APPROVED, "ch_accepted", (APPROVED,))

    # ---- ECH DENIAL ----------------------------------------------------
    reject("e08_ech_valid", "ech",
           [chgen.make_client_hello(ap, ech=True)],
           "ECH extension 0xfe0d present")
    reject("e09_ech_zero_len", "ech",
           [chgen.make_client_hello(ap, ech=True, ech_payload=b"")],
           "ECH extension 0xfe0d present")
    reject("e10_ech_arbitrary", "ech",
           [chgen.make_client_hello(ap, ech=True, ech_payload=b"\xff" * 64)],
           "ECH extension 0xfe0d present")
    reject("e11_ech_duplicate", "ech",
           [chgen.make_client_hello(
               ap, extra_extensions=[(chgen.EXT_ECH, b"\x00"), (chgen.EXT_ECH, b"\x00")])],
           "ECH extension 0xfe0d present")
    reject("e12_ech_approved_outer", "ech",
           [chgen.make_client_hello(ap, ech=True)],
           "ECH extension 0xfe0d present")
    reject("e13_ech_unapproved_outer", "ech",
           [chgen.make_client_hello(b"evil.example.test", ech=True)],
           "ECH extension 0xfe0d present")
    ch_ech = chgen.make_client_hello(ap, ech=True)
    raw = ch_ech[5:]
    idx = raw.find(struct.pack(">H", chgen.EXT_ECH))
    assert idx > 0
    frag = chgen.fragment_handshake_into_records(raw, [idx + 1, len(raw) - idx - 1])
    reject("e14_ech_ext_split_records", "ech", [frag],
           "ECH extension 0xfe0d present")
    reject("e15_ech_split_writes", "ech", [ch_ech],
           "ECH extension 0xfe0d present",
           chunk_sizes=[idx + 5 + 1])  # split mid-ECH-extension at transport level
    reject("e16_ech_tls12", "ech",
           [chgen.make_client_hello(ap, tls13=False, ech=True)],
           "ECH extension 0xfe0d present")
    reject("e17_ech_no_sni", "ech",
           [chgen.make_client_hello(None, ech=True)],
           "ECH extension 0xfe0d present")

    # ---- MALFORMED ------------------------------------------------------
    bad_len_rec = chgen.build_record(chgen.CT_HANDSHAKE, ch[5:],
                                     length_override=len(ch))  # lie: +5
    reject("m16_bad_record_length", "malformed", [bad_len_rec],
           "gate timeout", gate_timeout=0.7, hold_open=True, parser_decides=False)
    hs = chgen.build_handshake_message(1, ch[9:], length_override=20000)
    reject("m17_bad_handshake_length", "malformed",
           [chgen.build_record(chgen.CT_HANDSHAKE, hs)],
           "declared ClientHello length 20000 exceeds bound")
    reject("m18_truncated_ch", "malformed", [ch[: len(ch) // 2]],
           "gate timeout", gate_timeout=0.7, hold_open=True, parser_decides=False)
    exts_bad = chgen.build_client_hello_body(
        extensions=[(0xCAFE, b"\x01")], extensions_len_override=600)
    msg = chgen.build_handshake_message(1, exts_bad)
    reject("m19_bad_extensions_len", "malformed",
           [chgen.build_record(chgen.CT_HANDSHAKE, msg)],
           "extensions block length mismatch")
    good = chgen.build_client_hello_body(extensions=[(0xCAFE, b"\x01\x02")])
    ext_off = good.rfind(b"\xca\xfe")
    tampered = bytearray(good)
    tampered[ext_off + 2 : ext_off + 4] = struct.pack(">H", 500)
    reject("m20_ext_overrun", "malformed",
           [chgen.build_record(chgen.CT_HANDSHAKE,
                               chgen.build_handshake_message(1, bytes(tampered)))],
           "truncated extension payload")
    many = chgen.fragment_handshake_into_records(
        ch[5:], [1] * (nch.MAX_RECORDS + 1) + [len(ch) - 5 - (nch.MAX_RECORDS + 1)])
    reject("m21_excessive_records", "malformed", [many],
           "record count bound exceeded")
    big_body = chgen.build_client_hello_body(
        extensions=[(0xCAFE, b"\x00" * 16380)])
    big_msg = chgen.build_handshake_message(1, big_body)
    reject("m22_excessive_bytes", "malformed",
           [chgen.build_record(chgen.CT_HANDSHAKE, big_msg[:16384]),
            chgen.build_record(chgen.CT_HANDSHAKE, big_msg[16384:])],
           "declared ClientHello length 16433 exceeds bound")
    reject("m23_timeout_mid_ch", "malformed", [ch[:20]],
           "gate timeout", gate_timeout=0.7, hold_open=True, parser_decides=False)
    reject("m24_eof_mid_ch", "malformed", [ch[: len(ch) // 2]],
           "EOF before ClientHello complete", parser_decides=False)
    reject("m25_wrong_content_type", "malformed",
           [chgen.build_record(chgen.CT_APPLICATION_DATA, b"\x16\x03\x01junk")],
           "non-handshake record content type 23")
    reject("m26_random_bytes", "malformed", [b"\xde\xad\xbe\xef" * 64],
           "non-handshake record content type 222")

    # ---- STATE / MULTI-HELLO -------------------------------------------
    accept("x27_second_ch_coalesced", "state", [ch + ch],
           EXTS_TLS13, APPROVED, "failed", (APPROVED,))
    ch1_hrr = chgen.make_client_hello(
        ap, supported_groups=[0x001D, 0x0018], key_share_group=0x0018)
    ch2_hrr_ech = chgen.make_client_hello(ap, ech=True)  # CH2 with ECH
    accept("x28_hrr_then_ch2_ech", "state", [ch1_hrr, ch2_hrr_ech],
           EXTS_TLS13, APPROVED, "ch_accepted", (APPROVED, APPROVED),
           read_window=0.7)
    accept("x28c_hrr_refused", "state", [ch1_hrr, ch2_hrr_ech],
           EXTS_TLS13, APPROVED, "failed", (APPROVED, APPROVED),
           refuse_second_ch=True, read_window=0.7)
    ch2_hrr_diff_sni = chgen.make_client_hello(b"evil.example.test")
    accept("x28b_hrr_ch2_different_sni", "state", [ch1_hrr, ch2_hrr_diff_sni],
           EXTS_TLS13, APPROVED, "failed", (APPROVED, "evil.example.test"),
           read_window=0.7)
    other_msg = chgen.build_record(
        chgen.CT_HANDSHAKE,
        chgen.build_handshake_message(20, b"\x00" * 12))  # Finished first
    reject("x29_unexpected_first_msg", "state", [other_msg],
           "first handshake message type 20 != ClientHello")
    accept("x30_garbage_after_ch", "state",
           [ch + b"\x17\x03\x03\x00\x05junk!"],
           EXTS_TLS13, APPROVED, "failed", (APPROVED,))

    # ---- GATE-BRANCH / BOUNDARY COVERAGE --------------------------------
    noext_body = chgen.build_client_hello_body(include_extensions_block=False,
                                               cipher_suites=[0xC02F])
    noext = chgen.build_record(
        chgen.CT_HANDSHAKE, chgen.build_handshake_message(1, noext_body))
    accept("g01_no_extensions_block", "policy", [noext],
           (), None, "failed", (None,))
    ch_ech2 = chgen.make_client_hello(ap, ech=True)
    two_in_one = chgen.build_record(chgen.CT_HANDSHAKE, ch[5:] + ch_ech2[5:])
    accept("g02_two_msgs_one_record", "state", [two_in_one],
           EXTS_TLS13, APPROVED, "failed", ())
    accept("g03_tls12_second_flight_ch_ech", "state",
           [chgen.make_client_hello(ap, tls13=False),
            chgen.make_client_hello(ap, tls13=False, ech=True)],
           EXTS_TLS12, APPROVED, "failed", (APPROVED,), read_window=0.7)
    reject("g04a_ech_ext_256th", "ech",
           [chgen.make_client_hello(
               ap, extra_extensions=[(0xCA00 + i, b"") for i in range(247)]
               + [(chgen.EXT_ECH, b"")])],
           "ECH extension 0xfe0d present")
    reject("g04b_ech_ext_257th", "ech-boundary",
           [chgen.make_client_hello(
               ap, extra_extensions=[(0xCA00 + i, b"") for i in range(248)]
               + [(chgen.EXT_ECH, b"")])],
           "extension count bound exceeded")
    sid_lie = chgen.build_client_hello_body(
        session_id=b"abcd", session_id_len_override=250,
        extensions=[(chgen.EXT_ECH, b"")])
    reject("g05a_session_id_lie_ech", "ech-boundary",
           [chgen.build_record(chgen.CT_HANDSHAKE,
                               chgen.build_handshake_message(1, sid_lie))],
           "truncated session_id")
    comp_lie = chgen.build_client_hello_body(
        compression_len_override=200, extensions=[(chgen.EXT_ECH, b"")])
    reject("g05b_compression_lie_ech", "ech-boundary",
           [chgen.build_record(chgen.CT_HANDSHAKE,
                               chgen.build_handshake_message(1, comp_lie))],
           "truncated compression_methods")
    zl = ch[:20] + chgen.build_record(chgen.CT_HANDSHAKE, b"") + ch[20:]
    reject("g06_zero_len_record_mid", "malformed", [zl],
           "malformed cipher_suites length")
    reject("g07_ccs_before_ch", "malformed",
           [chgen.build_record(chgen.CT_CHANGE_CIPHER_SPEC, b"\x01",
                               record_version=0x0303) + ch],
           "non-handshake record content type 20")
    reject("g08a_record_version_0304", "malformed",
           [chgen.build_record(chgen.CT_HANDSHAKE, ch[5:], record_version=0x0304)],
           "unsupported record version 0x0304")
    mixed = chgen.build_record(chgen.CT_HANDSHAKE, ch[5:60],
                               record_version=0x0301) + \
        chgen.build_record(chgen.CT_HANDSHAKE, ch[60:], record_version=0x0303)
    accept("g08b_mixed_record_versions", "success", [mixed],
           EXTS_TLS13, APPROVED, "ch_accepted", (APPROVED,))
    base_len = len(chgen.build_client_hello_body(extensions=[]))
    pad = 16384 - base_len - 4  # 4 = extension header of the padding ext
    exact_body = chgen.build_client_hello_body(
        extensions=[(0xCAFE, b"\x00" * pad)])
    assert len(exact_body) == 16384, len(exact_body)
    exact_msg = chgen.build_handshake_message(1, exact_body)
    exact_wire = chgen.fragment_handshake_into_records(
        exact_msg, [16384, len(exact_msg) - 16384])
    accept("g09a_declared_16384", "success", [exact_wire],
           (0xCAFE,), None, "failed", (None,))
    big_body2 = chgen.build_client_hello_body(
        extensions=[(0xCAFE, b"\x00" * (pad + 1))])
    reject("g09b_declared_16385", "malformed",
           [chgen.build_record(chgen.CT_HANDSHAKE,
                               chgen.build_handshake_message(1, big_body2))],
           "oversized record payload 16389")
    empty_ext = chgen.build_client_hello_body(extensions=[])
    accept("g10_empty_ext_vector", "policy",
           [chgen.build_record(chgen.CT_HANDSHAKE,
                               chgen.build_handshake_message(1, empty_ext))],
           (), None, "failed", (None,))
    reject("g11_dup_unknown_ext", "policy",
           [chgen.make_client_hello(
               ap, extra_extensions=[(0xCAFE, b"\x01"), (0xCAFE, b"\x02")])],
           "duplicate extension 0xcafe")

    # ---- PROMOTION ADDITIONS ---------------------------------------------
    # The spike's p_* cases sat after an early ``return`` and never ran.
    accept("p_missing_sni", "policy", [chgen.make_client_hello(None)],
           EXTS_TLS13[1:], None, "failed", (None,))
    reject("p_sslv2_style", "policy", [chgen.make_sslv2_client_hello()],
           "non-handshake record content type 128")
    reject("p_record_version_0300", "policy",
           [chgen.build_record(chgen.CT_HANDSHAKE, ch[5:], record_version=0x0300)],
           "unsupported record version 0x0300")
    # A genuine zero-length record at a record boundary (the spike's g06
    # injects it mid-record, where it is indistinguishable from payload
    # corruption; the fail-closed outcome held but the branch was unhit).
    msg12 = chgen.make_client_hello(ap, tls13=False)[5:]
    zl_boundary = (
        chgen.build_record(chgen.CT_HANDSHAKE, msg12[:10])
        + chgen.build_record(chgen.CT_HANDSHAKE, b"")
        + chgen.build_record(chgen.CT_HANDSHAKE, msg12[10:])
    )
    reject("g06b_zero_len_record_boundary", "malformed", [zl_boundary],
           "zero-length handshake record")
    # Record-count exact boundary: 64 records accepted, 65 rejected.
    accept("g12a_record_count_64", "boundary",
           [chgen.fragment_handshake_into_records(msg12, _split_sizes(len(msg12), 64))],
           EXTS_TLS12, APPROVED, "ch_accepted", (APPROVED,))
    reject("g12b_record_count_65", "boundary",
           [chgen.fragment_handshake_into_records(msg12, _split_sizes(len(msg12), 65))],
           "record count bound exceeded")
    return cases


CASES = build_cases()
CASE_IDS = [c.name for c in CASES]


# ---------------------------------------------------------------------------
# Fixture plumbing
# ---------------------------------------------------------------------------

def run_fixture(peer: socket.socket, case: Case) -> None:
    """Worker-side raw fixture: write flights (chunked/dripped as the case
    demands), draining whatever the server emits in between and after."""
    peer.settimeout(0.05)

    def drain(cap: float) -> None:
        end = time.monotonic() + cap
        while time.monotonic() < end:
            try:
                chunk = peer.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            if chunk == b"":  # server closed; it is done
                return

    for flight in case.flights:
        try:
            if case.drip:
                for pos in range(len(flight)):
                    peer.sendall(flight[pos : pos + 1])
                    time.sleep(0.002)
            elif case.chunk_sizes:
                pos = 0
                for size in case.chunk_sizes:
                    peer.sendall(flight[pos : pos + size])
                    pos += size
                    time.sleep(0.01)
                if pos < len(flight):
                    peer.sendall(flight[pos:])
            else:
                peer.sendall(flight)
        except OSError:
            return  # server closed early (fail-closed rejection)
        drain(case.read_window)
    if case.hold_open:
        # Timeout cases: the server must still be reading when its gate
        # deadline expires; it closes after rejecting, ending this drain.
        drain(case.gate_timeout + 1.5)
    else:
        # Half-close so the server's TLS drive observes a prompt EOF.
        try:
            peer.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        drain(3.0)


@dataclass
class SocketRun:
    gate: nch.GateOutcome | None = None
    handshake: HandshakeResult | None = None
    error: str = ""


def run_case_over_socket(case: Case, ctx: ssl.SSLContext) -> SocketRun:
    """Drive one case through the PRODUCTION gate and, on acceptance, the
    verbatim replay into OpenSSL — the spike's T1 pipeline."""
    srv_sock, cli_sock = socket.socketpair()
    fires: list = []

    def _sni_cb(sslobj: ssl.SSLObject, server_name: str | None,
                _ctx: ssl.SSLContext) -> None:
        fires.append(server_name)
        if case.refuse_second_ch and len(fires) > 1:
            raise SniPolicyError("second ClientHello (HRR/renegotiation) refused")
        if server_name != APPROVED:
            raise SniPolicyError(f"SNI {server_name!r} != approved hostname")

    ctx.sni_callback = _sni_cb
    run = SocketRun()

    def server() -> None:
        try:
            outcome = nch.run_gate_on_socket(srv_sock, timeout=case.gate_timeout)
            run.gate = outcome
            if outcome.accepted:
                run.handshake = drive_handshake(
                    srv_sock, ctx, outcome.accepted_bytes, fires,
                    timeout=case.gate_timeout + 5.0)
        except Exception as exc:  # noqa: BLE001 — surfaced as an assertion below
            run.error = f"{type(exc).__name__}: {exc}"
        finally:
            try:
                srv_sock.close()
            except OSError:
                pass

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    try:
        run_fixture(cli_sock, case)
    finally:
        cli_sock.close()
    thread.join(timeout=case.gate_timeout + 15.0)
    assert not thread.is_alive(), f"server thread stuck for {case.name}"
    return run


# ---------------------------------------------------------------------------
# Corpus A — socket-level, through the production bounded driver
# ---------------------------------------------------------------------------

# The SNI policy callback deliberately raises inside OpenSSL's servername
# callback to abort policy-violating handshakes; CPython surfaces that as an
# "exception ignored in ssl servername callback" unraisable warning.  It is
# the measured abort mechanism, not a defect — filter it for this test only.
@pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnraisableExceptionWarning")
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_corpus_socket_driver(case, server_context):
    run = run_case_over_socket(case, server_context)
    assert run.error == "", f"harness error: {run.error}"
    gate = run.gate
    assert gate is not None, "driver produced no outcome"

    # Same gate decision and fail-closed reason as the recorded spike run.
    assert gate.decision is nch.GateDecision(case.expect_gate), (
        f"gate decision {gate.decision} != {case.expect_gate} ({gate.reason})")
    assert gate.reason == case.expect_reason

    if case.category == "ech":
        # ECH must be rejected because of 0xfe0d, before any SNI trust.
        assert "0xfe0d" in gate.reason
    if case.category in ("ech", "ech-boundary"):
        assert run.handshake is None, "TLS phase reached despite ECH"
        assert gate.accepted_bytes == b""

    if gate.decision is nch.GateDecision.REJECT:
        assert run.handshake is None, "SNI trust phase reached after rejection"
        return

    # Verbatim replay: the bytes handed to OpenSSL are EXACTLY the worker
    # bytes the gate consumed (the whole first flight for every accept
    # case — trailing coalesced bytes included).
    assert gate.accepted_bytes == case.flights[0]

    # Same gate observations as the recorded spike run.
    metadata = gate.metadata
    assert metadata is not None
    assert list(metadata.extension_ids) == list(case.expect_exts)
    observed_sni = metadata.sni.decode("ascii") if metadata.sni else None
    assert observed_sni == case.expect_sni

    # OpenSSL differential: same outcome class, same SNI firings.
    hs = run.handshake
    assert hs is not None
    assert hs.outcome == case.expect_openssl, (
        f"openssl outcome {hs.outcome} != {case.expect_openssl} ({hs.error})")
    assert list(hs.sni_seen) == list(case.expect_fires)

    # STOP CONDITION: any SNI the TLS stack acts on must be exactly the SNI
    # the gate observed.  A mismatch here is an unsafe parser differential.
    if hs.sni_seen and metadata.sni is not None:
        assert hs.sni_seen[0] == observed_sni, (
            f"PARSER DIFFERENTIAL: gate SNI {observed_sni!r} vs "
            f"OpenSSL SNI {hs.sni_seen[0]!r}")


# ---------------------------------------------------------------------------
# Corpus A — parser level, pure ClientHelloGate.feed contract
# ---------------------------------------------------------------------------

def _parser_chunks(case: Case) -> list[bytes]:
    """Reproduce the socket fixture's delivery as feed() chunks."""
    stream = case.flights[0]  # every decision is reached within flight 1
    if case.drip:
        return [stream[pos : pos + 1] for pos in range(len(stream))]
    if case.chunk_sizes:
        chunks = []
        pos = 0
        for size in case.chunk_sizes:
            chunks.append(stream[pos : pos + size])
            pos += size
        if pos < len(stream):
            chunks.append(stream[pos:])
        return chunks
    return [stream]


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_corpus_parser_level(case):
    gate = nch.ClientHelloGate()
    decision = None
    for chunk in _parser_chunks(case):
        decision = gate.feed(chunk)
        if decision is not None:
            break

    if not case.parser_decides:
        # Truncated/lying inputs leave the parser undecided; only the
        # bounded driver's EOF/timeout leg can fail them closed.
        assert decision is None
        return

    assert decision is nch.GateDecision(case.expect_gate)
    if decision is nch.GateDecision.ACCEPT:
        assert gate.accepted_bytes == case.flights[0]  # verbatim replay
        assert list(gate.metadata.extension_ids) == list(case.expect_exts)
        sni = gate.metadata.sni
        assert (sni.decode("ascii") if sni else None) == case.expect_sni
    else:
        assert gate.rejection_reason == case.expect_reason


# ---------------------------------------------------------------------------
# BoundedGateGuard — broker-level gate concurrency bound
# ---------------------------------------------------------------------------

class TestBoundedGateGuard:
    def test_cap_is_enforced(self):
        guard = nch.BoundedGateGuard(2)
        first = guard.try_acquire()
        second = guard.try_acquire()
        assert first is not None and second is not None
        assert guard.in_flight == 2
        assert guard.try_acquire() is None
        assert guard.in_flight == 2

    def test_release_permits_new_gates(self):
        guard = nch.BoundedGateGuard(1)
        permit = guard.try_acquire()
        assert permit is not None
        assert guard.try_acquire() is None
        permit.release()
        assert guard.in_flight == 0
        assert guard.try_acquire() is not None

    def test_release_is_idempotent(self):
        guard = nch.BoundedGateGuard(2)
        first = guard.try_acquire()
        second = guard.try_acquire()
        assert first is not None and second is not None
        first.release()
        first.release()  # must not drop below the true in-flight count
        assert guard.in_flight == 1

    def test_permit_is_a_context_manager(self):
        guard = nch.BoundedGateGuard(1)
        with guard.try_acquire():
            assert guard.in_flight == 1
        assert guard.in_flight == 0

    def test_small_default_and_construction_validation(self):
        assert nch.BoundedGateGuard().max_in_flight == nch.DEFAULT_MAX_IN_FLIGHT_GATES
        assert nch.DEFAULT_MAX_IN_FLIGHT_GATES <= 16  # deliberately small
        for bad in (0, -1, 1.5, "8", True):
            with pytest.raises(ValueError):
                nch.BoundedGateGuard(bad)

    def test_concurrent_acquirers_never_exceed_cap(self):
        guard = nch.BoundedGateGuard(3)
        violations = []

        def worker():
            for _ in range(200):
                permit = guard.try_acquire()
                if permit is None:
                    continue
                if guard.in_flight > 3:
                    violations.append(guard.in_flight)
                permit.release()

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert violations == []
        assert guard.in_flight == 0

    def test_driver_fails_closed_when_guard_is_exhausted(self):
        guard = nch.BoundedGateGuard(1)
        held = guard.try_acquire()
        assert held is not None
        srv, cli = socket.socketpair()
        try:
            cli.sendall(chgen.make_client_hello(APPROVED_BYTES))
            outcome = nch.run_gate_on_socket(srv, timeout=1.0, guard=guard)
            assert outcome.decision is nch.GateDecision.REJECT
            assert outcome.reason == "gate concurrency bound exceeded"
            assert outcome.read_calls == 0
            # Fail-closed without consuming a single worker byte.
            srv.settimeout(1.0)
            assert srv.recv(65536).startswith(b"\x16\x03\x01")
        finally:
            held.release()
            srv.close()
            cli.close()

    def test_driver_acquires_and_releases_permit(self):
        guard = nch.BoundedGateGuard(1)
        srv, cli = socket.socketpair()
        try:
            cli.sendall(chgen.make_client_hello(APPROVED_BYTES))
            outcome = nch.run_gate_on_socket(srv, timeout=2.0, guard=guard)
            assert outcome.decision is nch.GateDecision.ACCEPT
            assert guard.in_flight == 0  # released after the gate phase
            # A follow-up gate may proceed immediately.
            outcome2 = nch.run_gate_on_socket(srv, timeout=0.3, guard=guard)
            assert outcome2.reason == "gate timeout"
            assert guard.in_flight == 0
        finally:
            srv.close()
            cli.close()


# ---------------------------------------------------------------------------
# GateOutcome / driver hygiene
# ---------------------------------------------------------------------------

def test_outcome_invariants_are_enforced():
    with pytest.raises(ValueError):
        nch.GateOutcome(nch.GateDecision.ACCEPT)  # accept without replay bytes
    with pytest.raises(ValueError):
        nch.GateOutcome(nch.GateDecision.REJECT, "x", accepted_bytes=b"y")
    with pytest.raises(ValueError):
        nch.GateOutcome("accept")  # type must be GateDecision


def test_driver_parameter_validation():
    srv, cli = socket.socketpair()
    try:
        with pytest.raises(ValueError):
            nch.run_gate_on_socket(srv, timeout=0)
        with pytest.raises(ValueError):
            nch.run_gate_on_socket(srv, max_read_calls=0)
    finally:
        srv.close()
        cli.close()


def test_driver_restores_socket_timeout():
    srv, cli = socket.socketpair()
    try:
        srv.settimeout(7.5)
        cli.sendall(b"\xde\xad\xbe\xef" * 4)  # instant reject
        outcome = nch.run_gate_on_socket(srv)
        assert outcome.decision is nch.GateDecision.REJECT
        assert srv.gettimeout() == 7.5
    finally:
        srv.close()
        cli.close()


def test_driver_restores_prior_blocking_mode():
    """A previously blocking socket must be blocking again afterwards
    (the restore guard used to skip the None case, leaking the 0.25s poll
    slice onto the caller's socket)."""
    srv, cli = socket.socketpair()
    try:
        srv.settimeout(None)
        cli.sendall(b"\xde\xad\xbe\xef" * 4)  # instant reject
        outcome = nch.run_gate_on_socket(srv)
        assert outcome.decision is nch.GateDecision.REJECT
        assert srv.gettimeout() is None
    finally:
        srv.close()
        cli.close()


def test_feed_after_decision_fails_closed_at_driver_level():
    gate = nch.ClientHelloGate()
    wire = chgen.make_client_hello(APPROVED_BYTES)
    assert gate.feed(wire) is nch.GateDecision.ACCEPT
    with pytest.raises(Exception):
        gate.feed(b"\x16\x03\x01\x00\x00")


def test_gate_module_import_is_stdlib_only():
    src_root = Path(nch.__file__).resolve().parents[2]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(src_root)
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import agenticos.sandbox.network_clienthello;"
            "assert 'cryptography' not in sys.modules",
        ],
        env=env,
        capture_output=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
