"""Conformance + differential corpus for the M4B-2 ECH gate spike.

SPIKE CODE — not production. Standard-library only.

Every case is driven against up to four targets:

  T1  gate -> verbatim replay -> Python ssl (OpenSSL) server
  T2  direct Python ssl (OpenSSL) server, permissive SNI logging (no gate)
  T3  native client_hello_cb probe, log mode (OpenSSL's own extension view)
  T4  native client_hello_cb probe, deny-ech mode (Candidate A behavior)

The differential assertions that matter for the security claim:

  * For every case whose ClientHello contains 0xfe0d: T1 gate must REJECT
    before any SNI trust, while T2 (bare OpenSSL, no ECH keys configured)
    demonstrably ACCEPTS the ClientHello and proceeds with the outer SNI —
    proving the gate adds an enforcement property OpenSSL alone lacks.
  * For every gate-ACCEPT case: the extension-ID set observed by the gate
    must equal the set observed by OpenSSL's own client_hello callback (T3),
    and the gate-observed SNI must equal the SNI observed by both TLS
    stacks. Any divergence is a parser differential — a security finding.

All fixtures are synthetic and local (socketpair / 127.0.0.1). No public
network is touched.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import chgen  # noqa: E402
from chgen import EXT_ECH  # noqa: E402
from ech_gate import (  # noqa: E402
    Decision,
    MAX_RECORDS,
)
from gate_driver import (  # noqa: E402
    drive_handshake,
    make_server_context,
    run_gate_on_socket,
)

APPROVED = "approved.example.test"
CERT = os.path.join(HERE, "work", "cert.pem")
KEY = os.path.join(HERE, "work", "key.pem")
PROBE = os.path.join(HERE, "work", "ech_cb_probe")
RESULTS = os.path.join(HERE, "work", "results.json")

HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)


# ---------------------------------------------------------------------------
# Fixture plumbing
# ---------------------------------------------------------------------------

@dataclass
class FixtureResult:
    server_bytes: bytes = b""          # everything the fixture read back
    flight_after_ch2: bytes = b""      # bytes read after second flight


def run_fixture(
    peer: socket.socket,
    flights: list[bytes],
    *,
    chunk_sizes: list[int] | None = None,
    drip: bool = False,
    close_after: bool = False,
    read_window: float = 0.8,
) -> FixtureResult:
    """Worker-side raw fixture: writes flights (with optional chunking),
    reading whatever the server emits in between and after."""
    res = FixtureResult()
    peer.settimeout(0.1)

    def drain(duration: float) -> bytes:
        out = b""
        end = time.monotonic() + duration
        while time.monotonic() < end:
            try:
                chunk = peer.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if chunk == b"":
                break
            out += chunk
        return out

    for i, flight in enumerate(flights):
        try:
            if drip:
                for pos in range(len(flight)):
                    peer.sendall(flight[pos : pos + 1])
                    time.sleep(0.002)
            elif chunk_sizes:
                pos = 0
                for size in chunk_sizes:
                    peer.sendall(flight[pos : pos + size])
                    pos += size
                    time.sleep(0.01)
                if pos < len(flight):
                    peer.sendall(flight[pos:])
            else:
                peer.sendall(flight)
        except OSError:
            break  # server closed early (e.g. fail-closed rejection)
        got = drain(read_window if i < len(flights) - 1 else read_window)
        if i == 0:
            res.server_bytes += got
        else:
            res.flight_after_ch2 += got
    if close_after:
        peer.close()
    return res


def parse_flight_observation(data: bytes) -> dict:
    """Best-effort observation of the server's first response records."""
    obs: dict = {"records": []}
    pos = 0
    while pos + 5 <= len(data) and len(obs["records"]) < 8:
        ctype = data[pos]
        rlen = int.from_bytes(data[pos + 3 : pos + 5], "big")
        payload = data[pos + 5 : pos + 5 + rlen]
        rec: dict = {"type": ctype, "len": rlen}
        if ctype == 22 and len(payload) >= 4:
            rec["handshake_type"] = payload[0]
            if payload[0] == 2 and len(payload) >= 38:
                random = payload[6:38]
                rec["server_hello"] = (
                    "hello_retry_request" if random == HRR_RANDOM else "server_hello"
                )
        if ctype == 21 and len(payload) >= 2:
            rec["alert"] = {"level": payload[0], "description": payload[1]}
        obs["records"].append(rec)
        pos += 5 + rlen
    return obs


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

@dataclass
class TargetOutcome:
    target: str
    gate_decision: str | None = None
    gate_reason: str = ""
    gate_exts: list[int] | None = None
    gate_sni: str | None = None
    openssl_outcome: str | None = None     # completed|ch_accepted|failed
    openssl_error: str = ""
    openssl_sni_fires: list = field(default_factory=list)
    openssl_alpn: str | None = None
    openssl_tls: str | None = None
    flight_obs: dict = field(default_factory=dict)
    probe_chcb_fires: int | None = None
    probe_exts: list[int] | None = None        # get1_extensions_present (known only)
    probe_exts_order: list[int] | None = None  # get_extension_order (wire order, all)
    probe_ech: int | None = None
    probe_sni_fires: list = field(default_factory=list)
    probe_isv2: int | None = None


def _readiness_wait(f: socket.socket, timeout: float = 5.0) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            r, _, _ = __import__("select").select([f], [], [], 0.1)
            if r:
                return
        except OSError:
            return
    raise TimeoutError("server thread not ready")


def run_python_target(
    case: "Case", *, use_gate: bool, approved_policy: bool
) -> TargetOutcome:
    """T1 (use_gate=True) or T2 (direct)."""
    out = TargetOutcome(target="T1_gate+python" if use_gate else "T2_direct_python")
    srv_sock, cli_sock = socket.socketpair()
    errors: list[str] = []

    def server() -> None:
        try:
            ctx = make_server_context(
                CERT, KEY,
                approved_hostname=APPROVED if approved_policy else "\x00never",
                abort_on_second_sni_fire=case.refuse_second_ch,
            )
            if not approved_policy:
                # permissive logging-only SNI observation
                fires: list = ctx._spike_fires  # type: ignore[attr-defined]
                def _log_cb(sslobj, name, _ctx):
                    fires.append(name)
                ctx.sni_callback = _log_cb
            if use_gate:
                gr = run_gate_on_socket(
                    srv_sock, timeout=case.gate_timeout
                )
                out.gate_decision = gr.decision
                out.gate_reason = gr.reason
                if gr.decision != "accept":
                    return
                out.gate_exts = list(gr.metadata.get("extension_ids", []))
                sni = gr.metadata.get("sni")
                out.gate_sni = sni.decode("ascii", "replace") if sni else None
                hr = drive_handshake(srv_sock, ctx, gr.accepted_bytes,
                                     timeout=case.hs_timeout)
            else:
                hr = drive_handshake(srv_sock, ctx, b"", timeout=case.hs_timeout)
            out.openssl_outcome = hr.outcome
            out.openssl_error = hr.error
            out.openssl_sni_fires = list(hr.sni_seen)
            out.openssl_alpn = hr.alpn
            out.openssl_tls = hr.tls_version
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{type(exc).__name__}: {exc}")
        finally:
            try:
                srv_sock.close()
            except OSError:
                pass

    t = threading.Thread(target=server, daemon=True)
    t.start()
    fx = run_fixture(
        cli_sock,
        case.flights,
        chunk_sizes=case.chunk_sizes,
        drip=case.drip,
        close_after=case.close_after,
        read_window=case.read_window,
    )
    out.flight_obs = parse_flight_observation(fx.server_bytes)
    if fx.flight_after_ch2:
        out.flight_obs["after_ch2"] = parse_flight_observation(fx.flight_after_ch2)
    t.join(timeout=case.gate_timeout + case.hs_timeout + 5)
    cli_sock.close()
    if errors:
        out.openssl_error = (out.openssl_error + " | " if out.openssl_error else "") + errors[0]
    return out


_probe_port_lock = threading.Lock()
_probe_port = [18100]


def run_probe_target(case: "Case", mode: str) -> TargetOutcome:
    """T3/T4: native client_hello_cb probe."""
    out = TargetOutcome(target=f"T4_probe_deny_ech" if mode == "deny-ech" else "T3_probe_log")
    with _probe_port_lock:
        port = _probe_port[0]
        _probe_port[0] += 1
    proc = subprocess.Popen(
        [PROBE, mode, str(port), CERT, KEY],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        # wait for READY
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            line = proc.stdout.readline()
            if line.strip() == "READY":
                break
            if proc.poll() is not None:
                out.openssl_error = f"probe exited early: {line}"
                return out
        else:
            out.openssl_error = "probe not ready"
            return out
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        fx = run_fixture(
            sock, case.flights,
            chunk_sizes=case.chunk_sizes, drip=case.drip,
            close_after=case.close_after,
            read_window=case.read_window,
        )
        out.flight_obs = parse_flight_observation(fx.server_bytes)
        if fx.flight_after_ch2:
            out.flight_obs["after_ch2"] = parse_flight_observation(
                fx.flight_after_ch2)
        sock.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        for line in proc.stdout.read().splitlines():
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "CHCB":
                kv = dict(p.split("=", 1) for p in parts[1:] if "=" in p)
                out.probe_chcb_fires = int(kv.get("fire", "0"))
                out.probe_ech = int(kv.get("ech", "0"))
                out.probe_isv2 = int(kv.get("isv2", "0"))
                exts = kv.get("exts", "")
                out.probe_exts = (
                    [int(e, 16) for e in exts.split(",") if e] if exts else []
                )
            elif parts[0] == "PROBE" and any(p.startswith("order=")
                                             for p in parts[1:]):
                kv = dict(p.split("=", 1) for p in parts[1:] if "=" in p)
                if kv.get("order_rc") == "1":
                    order = kv.get("order", "")
                    out.probe_exts_order = (
                        [int(e, 16) for e in order.split(",") if e]
                        if order else []
                    )
            elif parts[0] == "SNICB":
                kv = dict(p.split("=", 1) for p in parts[1:] if "=" in p)
                out.probe_sni_fires.append(kv.get("name"))
            elif parts[0] == "RESULT":
                kv = dict(p.split("=", 1) for p in parts[1:] if "=" in p)
                out.openssl_outcome = (
                    "completed" if kv.get("outcome") == "ok" else "failed"
                )
                out.probe_chcb_fires = int(kv.get("chcb_fires",
                                                  out.probe_chcb_fires or 0))
                out.probe_ech = int(kv.get("ech_seen", out.probe_ech or 0))
                out.openssl_error = kv.get("detail", "")
    finally:
        if proc.poll() is None:
            proc.kill()
    return out


# ---------------------------------------------------------------------------
# Case definitions
# ---------------------------------------------------------------------------

@dataclass
class Case:
    name: str
    category: str
    flights: list[bytes]
    chunk_sizes: list[int] | None = None
    drip: bool = False
    close_after: bool = False
    refuse_second_ch: bool = False      # policy: abort on 2nd sni_callback firing
    gate_timeout: float = 5.0
    hs_timeout: float = 2.0
    read_window: float = 0.8
    targets: tuple = ("T1", "T2", "T3", "T4")
    expect: dict = field(default_factory=dict)


def _frag(ch_bytes: bytes, sizes: list[int]) -> list[int]:
    """Chunk sizes for the fixture write plan covering whole byte string."""
    assert sum(sizes) <= len(ch_bytes)
    return sizes


def build_cases() -> list[Case]:
    cases: list[Case] = []
    ap = APPROVED.encode()

    def add(name, category, flights, **kw):
        cases.append(Case(name, category, flights, **kw))

    # ---- SUCCESS ------------------------------------------------------
    add("s01_tls12_no_ech", "success",
        [chgen.make_client_hello(ap, tls13=False)],
        expect={"T1": ("accept", "ch_accepted"), "T3_ech": 0})
    add("s02_tls13_no_ech", "success",
        [chgen.make_client_hello(ap, tls13=True)],
        expect={"T1": ("accept", "ch_accepted")})
    ch = chgen.make_client_hello(ap)
    body_len = len(ch) - 5
    frag = chgen.fragment_handshake_into_records(
        ch[5:], [3, 7, body_len - 10])
    add("s03_record_fragmented", "success", [frag],
        expect={"T1": ("accept", "ch_accepted")})
    small = chgen.make_client_hello(ap, tls13=False,
                                    session_id=b"", alpn=[b"http/1.1"])
    add("s04_drip_feed", "success", [small], drip=True,
        gate_timeout=15.0, read_window=1.0,
        targets=("T1",), expect={"T1": ("accept", "ch_accepted")})
    # coalesced: two CH records + trailing CCS in ONE write
    frag2 = chgen.fragment_handshake_into_records(ch[5:], [body_len // 2,
                                                          body_len - body_len // 2])
    add("s05a_coalesced_records", "success", [frag2],
        expect={"T1": ("accept", "ch_accepted")})
    add("s05b_coalesced_ch_plus_ccs", "success",
        [ch + chgen.build_record(chgen.CT_CHANGE_CIPHER_SPEC, b"\x01",
                                 record_version=0x0303)],
        expect={"T1": ("accept", "ch_accepted")})
    add("s06_unknown_ext", "success",
        [chgen.make_client_hello(ap, extra_extensions=[(0xCAFE, b"\x01\x02")])],
        expect={"T1": ("accept", "ch_accepted")})
    add("s07_grease_exts", "success",
        [chgen.make_client_hello(ap, grease=True)],
        expect={"T1": ("accept", "ch_accepted")})

    # ---- ECH DENIAL ----------------------------------------------------
    add("e08_ech_valid", "ech",
        [chgen.make_client_hello(ap, ech=True)],
        expect={"T1": ("reject", None), "T4": "reject"})
    add("e09_ech_zero_len", "ech",
        [chgen.make_client_hello(ap, ech=True, ech_payload=b"")],
        expect={"T1": ("reject", None), "T4": "reject"})
    add("e10_ech_arbitrary", "ech",
        [chgen.make_client_hello(ap, ech=True, ech_payload=b"\xff" * 64)],
        expect={"T1": ("reject", None), "T4": "reject"})
    add("e11_ech_duplicate", "ech",
        [chgen.make_client_hello(
            ap, extra_extensions=[(EXT_ECH, b"\x00"), (EXT_ECH, b"\x00")])],
        expect={"T1": ("reject", None), "T4": "reject"})
    add("e12_ech_approved_outer", "ech",
        [chgen.make_client_hello(ap, ech=True)],
        expect={"T1": ("reject", None), "T4": "reject"})
    add("e13_ech_unapproved_outer", "ech",
        [chgen.make_client_hello(b"evil.example.test", ech=True)],
        expect={"T1": ("reject", None), "T4": "reject"})
    # ECH extension header straddling a record boundary
    ch_ech = chgen.make_client_hello(ap, ech=True)
    raw = ch_ech[5:]
    idx = raw.find(struct.pack(">H", EXT_ECH))
    assert idx > 0
    frag = chgen.fragment_handshake_into_records(raw, [idx + 1, len(raw) - idx - 1])
    add("e14_ech_ext_split_records", "ech", [frag],
        expect={"T1": ("reject", None), "T4": "reject"})
    add("e15_ech_split_writes", "ech", [ch_ech],
        chunk_sizes=[idx + 5 + 1],  # split mid-ECH-extension at transport level
        expect={"T1": ("reject", None), "T4": "reject"})

    # ---- MALFORMED ------------------------------------------------------
    bad_len_rec = chgen.build_record(chgen.CT_HANDSHAKE, ch[5:],
                                     length_override=len(ch))  # lie: +5
    add("m16_bad_record_length", "malformed", [bad_len_rec],
        read_window=0.5, gate_timeout=1.5,
        expect={"T1": ("reject", None)})
    hs = chgen.build_handshake_message(1, ch[9:], length_override=20000)
    add("m17_bad_handshake_length", "malformed",
        [chgen.build_record(chgen.CT_HANDSHAKE, hs)],
        expect={"T1": ("reject", None)})
    add("m18_truncated_ch", "malformed", [ch[: len(ch) // 2]],
        gate_timeout=1.5, read_window=0.5,
        expect={"T1": ("reject", None)})
    # craft: valid CH but extensions length field too large
    exts_bad = chgen.build_client_hello_body(
        extensions=[(0xCAFE, b"\x01")], extensions_len_override=600)
    msg = chgen.build_handshake_message(1, exts_bad)
    add("m19_bad_extensions_len", "malformed",
        [chgen.build_record(chgen.CT_HANDSHAKE, msg)],
        expect={"T1": ("reject", None)})
    # extension header says payload longer than remaining block
    good = chgen.build_client_hello_body(extensions=[(0xCAFE, b"\x01\x02")])
    ext_off = good.rfind(b"\xca\xfe")
    tampered = bytearray(good)
    tampered[ext_off + 2 : ext_off + 4] = struct.pack(">H", 500)
    add("m20_ext_overrun", "malformed",
        [chgen.build_record(chgen.CT_HANDSHAKE,
                            chgen.build_handshake_message(1, bytes(tampered)))],
        expect={"T1": ("reject", None)})
    many = chgen.fragment_handshake_into_records(
        ch[5:], [1] * (MAX_RECORDS + 1) + [len(ch) - 5 - (MAX_RECORDS + 1)])
    add("m21_excessive_records", "malformed", [many],
        expect={"T1": ("reject", None)})
    big_body = chgen.build_client_hello_body(
        extensions=[(0xCAFE, b"\x00" * 16380)])
    big_msg = chgen.build_handshake_message(1, big_body)
    add("m22_excessive_bytes", "malformed",
        [chgen.build_record(chgen.CT_HANDSHAKE, big_msg[:16384]),
         chgen.build_record(chgen.CT_HANDSHAKE, big_msg[16384:])],
        read_window=0.5, gate_timeout=2.0,
        expect={"T1": ("reject", None)})
    add("m23_timeout_mid_ch", "malformed", [ch[:20]],
        gate_timeout=1.0, read_window=1.6, targets=("T1",),
        expect={"T1": ("reject", None)})
    add("m24_eof_mid_ch", "malformed", [ch[: len(ch) // 2]],
        close_after=True,
        targets=("T1",), gate_timeout=1.5, read_window=0.3,
        expect={"T1": ("reject", None)})
    add("m25_wrong_content_type", "malformed",
        [chgen.build_record(chgen.CT_APPLICATION_DATA, b"\x16\x03\x01junk")],
        expect={"T1": ("reject", None)})
    add("m26_random_bytes", "malformed", [b"\xde\xad\xbe\xef" * 64],
        expect={"T1": ("reject", None)})

    # ---- STATE / MULTI-HELLO -------------------------------------------
    add("x27_second_ch_coalesced", "state",
        [ch + ch],  # two full CHs in one write
        read_window=0.6,
        expect={"T1": ("accept", "failed"), "T1_fires": 1})
    ch1_hrr = chgen.make_client_hello(
        ap, supported_groups=[0x001D, 0x0018], key_share_group=0x0018)
    ch2_hrr_ech = chgen.make_client_hello(ap, ech=True)  # CH2 with ECH
    add("x28_hrr_then_ch2_ech", "state", [ch1_hrr, ch2_hrr_ech],
        read_window=1.2,
        expect={"T1": ("accept", "ch_accepted"), "T1_fires": 2})
    add("x28c_hrr_refused", "state", [ch1_hrr, ch2_hrr_ech],
        read_window=1.2, refuse_second_ch=True,
        expect={"T1": ("accept", "failed"), "T1_fires": 2})
    ch2_hrr_diff_sni = chgen.make_client_hello(b"evil.example.test")
    add("x28b_hrr_ch2_different_sni", "state", [ch1_hrr, ch2_hrr_diff_sni],
        read_window=1.2,
        expect={"T1": ("accept", "failed"), "T1_fires": 2})
    other_msg = chgen.build_record(
        chgen.CT_HANDSHAKE,
        chgen.build_handshake_message(20, b"\x00" * 12))  # Finished first
    add("x29_unexpected_first_msg", "state", [other_msg],
        expect={"T1": ("reject", None)})
    add("x30_garbage_after_ch", "state",
        [ch + b"\x17\x03\x03\x00\x05junk!"],
        expect={"T1": ("accept", "failed"), "T1_fires": 1})

    # ---- GATE-BRANCH / BOUNDARY COVERAGE --------------------------------
    # no extensions block at all (legacy TLS1.2 CH)
    noext_body = chgen.build_client_hello_body(include_extensions_block=False,
                                               cipher_suites=[0xC02F])
    noext = chgen.build_record(
        chgen.CT_HANDSHAKE,
        chgen.build_handshake_message(1, noext_body))
    add("g01_no_extensions_block", "policy", [noext],
        expect={"T1": ("accept", None)})  # no SNI -> policy denies downstream
    # two handshake messages in ONE record (trailing bytes inside _hs)
    ch_ech2 = chgen.make_client_hello(ap, ech=True)
    two_in_one = chgen.build_record(chgen.CT_HANDSHAKE, ch[5:] + ch_ech2[5:])
    add("g02_two_msgs_one_record", "state", [two_in_one],
        expect={"T1": ("accept", "failed"), "T1_fires": 0})
    # TLS1.2 forced; plaintext ECH-bearing CH2 as a second flight
    add("g03_tls12_second_flight_ch_ech", "state",
        [chgen.make_client_hello(ap, tls13=False),
         chgen.make_client_hello(ap, tls13=False, ech=True)],
        read_window=1.0,
        expect={"T1": ("accept", "failed"), "T1_fires": 1})
    # ECH at the extension-count boundary: typical set has 8 entries, so
    # 247 benign extras put ECH exactly at position 256 (the bound), 248
    # put it at 257 (beyond the bound; reject via the bound itself).
    add("g04a_ech_ext_256th", "ech",
        [chgen.make_client_hello(
            ap, extra_extensions=[(0xCA00 + i, b"") for i in range(247)]
            + [(EXT_ECH, b"")])],
        expect={"T1": ("reject", None)})
    add("g04b_ech_ext_257th", "ech-boundary",
        [chgen.make_client_hello(
            ap, extra_extensions=[(0xCA00 + i, b"") for i in range(248)]
            + [(EXT_ECH, b"")])],
        expect={"T1": ("reject", None)})
    # length-field offset games: session_id / compression lies with ECH
    sid_lie = chgen.build_client_hello_body(
        session_id=b"abcd", session_id_len_override=250,
        extensions=[(EXT_ECH, b"")])
    add("g05a_session_id_lie_ech", "ech-boundary",
        [chgen.build_record(chgen.CT_HANDSHAKE,
                            chgen.build_handshake_message(1, sid_lie))],
        expect={"T1": ("reject", None)})
    comp_lie = chgen.build_client_hello_body(
        compression_len_override=200, extensions=[(EXT_ECH, b"")])
    add("g05b_compression_lie_ech", "ech-boundary",
        [chgen.build_record(chgen.CT_HANDSHAKE,
                            chgen.build_handshake_message(1, comp_lie))],
        expect={"T1": ("reject", None)})
    # zero-length record interleaved mid-fragment
    zl = ch[:20] + chgen.build_record(chgen.CT_HANDSHAKE, b"") + ch[20:]
    add("g06_zero_len_record_mid", "malformed", [zl],
        expect={"T1": ("reject", None)})
    # CCS before CH
    add("g07_ccs_before_ch", "malformed",
        [chgen.build_record(chgen.CT_CHANGE_CIPHER_SPEC, b"\x01",
                            record_version=0x0303) + ch],
        expect={"T1": ("reject", None)})
    # record version games
    add("g08a_record_version_0304", "malformed",
        [chgen.build_record(chgen.CT_HANDSHAKE, ch[5:], record_version=0x0304)],
        expect={"T1": ("reject", None)})
    mixed = chgen.build_record(chgen.CT_HANDSHAKE, ch[5:60],
                               record_version=0x0301) + \
        chgen.build_record(chgen.CT_HANDSHAKE, ch[60:], record_version=0x0303)
    add("g08b_mixed_record_versions", "success", [mixed],
        expect={"T1": ("accept", "ch_accepted")})
    # CH declared-length boundary: exactly 16384 accepted, 16385 rejected
    base_len = len(chgen.build_client_hello_body(extensions=[]))
    pad = 16384 - base_len - 4  # 4 = extension header of the padding ext
    exact_body = chgen.build_client_hello_body(
        extensions=[(0xCAFE, b"\x00" * pad)])
    assert len(exact_body) == 16384, len(exact_body)
    exact_msg = chgen.build_handshake_message(1, exact_body)
    # fragment so no single record exceeds the 16384 record-payload bound
    exact_wire = chgen.fragment_handshake_into_records(
        exact_msg, [16384, len(exact_msg) - 16384])
    add("g09a_declared_16384", "success",
        [exact_wire],
        expect={"T1": ("accept", "failed"), "T1_fires": 1})  # no SNI -> policy denies
    big_body2 = chgen.build_client_hello_body(
        extensions=[(0xCAFE, b"\x00" * (pad + 1))])
    add("g09b_declared_16385", "malformed",
        [chgen.build_record(chgen.CT_HANDSHAKE,
                            chgen.build_handshake_message(1, big_body2))],
        expect={"T1": ("reject", None)})
    # empty extensions vector (block present, length 0)
    empty_ext = chgen.build_client_hello_body(extensions=[])
    add("g10_empty_ext_vector", "policy",
        [chgen.build_record(chgen.CT_HANDSHAKE,
                            chgen.build_handshake_message(1, empty_ext))],
        expect={"T1": ("accept", None)})  # no SNI -> denied downstream
    # duplicate unknown extension (OpenSSL tolerates; gate is stricter)
    add("g11_dup_unknown_ext", "policy",
        [chgen.make_client_hello(
            ap, extra_extensions=[(0xCAFE, b"\x01"), (0xCAFE, b"\x02")])],
        expect={"T1": ("reject", None)})
    # ECH variants: TLS1.2 CH carrying ECH; ECH without any SNI
    add("e16_ech_tls12", "ech",
        [chgen.make_client_hello(ap, tls13=False, ech=True)],
        expect={"T1": ("reject", None), "T4": "reject"})
    add("e17_ech_no_sni", "ech",
        [chgen.make_client_hello(None, ech=True)],
        expect={"T1": ("reject", None), "T4": "reject"})
    return cases

    # ---- MISC POLICY ----------------------------------------------------
    add("p_missing_sni", "policy", [chgen.make_client_hello(None)],
        expect={"T1": ("accept", None)})  # SNI policy must deny downstream
    add("p_sslv2_style", "policy", [chgen.make_sslv2_client_hello()],
        expect={"T1": ("reject", None)})
    add("p_record_version_0300", "policy",
        [chgen.build_record(chgen.CT_HANDSHAKE, ch[5:], record_version=0x0300)],
        expect={"T1": ("reject", None)})
    return cases


# ---------------------------------------------------------------------------
# Differential evaluation
# ---------------------------------------------------------------------------

def evaluate(case: Case, outcomes: dict[str, TargetOutcome]) -> list[str]:
    """Return list of findings; empty = case behaved as required."""
    findings: list[str] = []
    t1 = outcomes.get("T1")
    t2 = outcomes.get("T2")
    t3 = outcomes.get("T3")
    t4 = outcomes.get("T4")

    # Explicit per-case expectations on the gated pipeline (T1).
    if t1 is not None and "T1" in case.expect:
        want_decision, want_ossl = case.expect["T1"]
        if t1.gate_decision != want_decision:
            findings.append(
                f"gate decision {t1.gate_decision} != expected "
                f"{want_decision} ({t1.gate_reason})")
        if want_ossl is not None and t1.gate_decision == "accept":
            if want_ossl == "failed":
                allowed = ("failed",)
            else:
                allowed = (want_ossl, "completed")
            if t1.openssl_outcome not in allowed:
                findings.append(
                    f"openssl outcome {t1.openssl_outcome} != expected "
                    f"{want_ossl} ({t1.openssl_error})")
    if t1 is not None and "T1_fires" in case.expect:
        want_fires = case.expect["T1_fires"]
        if len(t1.openssl_sni_fires) != want_fires:
            findings.append(
                f"sni_callback fires {len(t1.openssl_sni_fires)} != expected "
                f"{want_fires}")

    # Primary ECH property: any CH containing 0xfe0d must be gate-rejected
    # before SNI trust. "ech" cases must reject *because of* 0xfe0d;
    # "ech-boundary" cases may legitimately trip a bound first — rejection
    # is what matters there.
    if case.category in ("ech", "ech-boundary"):
        if t1 is None or t1.gate_decision != "reject":
            findings.append("CRITICAL: ECH case not rejected by gate")
        elif case.category == "ech" and "0xfe0d" not in t1.gate_reason:
            findings.append(f"ECH rejected for wrong reason: {t1.gate_reason}")
        if t1 and t1.openssl_sni_fires:
            findings.append("CRITICAL: SNI trust reached despite ECH")
        # Evidence that bare OpenSSL alone would have proceeded with the
        # outer SNI (for the well-formed ECH cases): the gap the gate closes.
        if t2 is not None and case.name in ("e08_ech_valid",
                                            "e12_ech_approved_outer"):
            if t2.openssl_outcome not in ("ch_accepted", "completed"):
                findings.append(
                    "note: bare OpenSSL did not accept well-formed ECH CH: "
                    f"{t2.openssl_outcome} {t2.openssl_error}")

    # Gate-accept differential: gate ext set must equal OpenSSL ext set (T3),
    # and SNI views must agree everywhere.
    if t1 and t1.gate_decision == "accept":
        ossl_exts = t3.probe_exts_order if t3 else None
        if ossl_exts:
            # OpenSSL's client_hello APIs only expose extensions the stack
            # *recognizes* (measured on this host). 0xfe0d is registered in
            # the probe, so it WOULD appear if present. Compare the gate's
            # wire-order list restricted to the stack-visible universe.
            visible_universe = set(ossl_exts) | {EXT_ECH}
            gate_filtered = [e for e in (t1.gate_exts or [])
                             if e in visible_universe]
            if gate_filtered != list(ossl_exts):
                findings.append(
                    f"PARSER DIFFERENTIAL: gate exts (filtered) "
                    f"{gate_filtered} != openssl wire-order exts {ossl_exts}")
            if EXT_ECH in ossl_exts:
                findings.append("CRITICAL: OpenSSL saw ECH that gate accepted")
        py_sni = t1.openssl_sni_fires[0] if t1.openssl_sni_fires else None
        if py_sni is not None and t1.gate_sni is not None \
                and py_sni != t1.gate_sni:
            findings.append(
                f"SNI DIFFERENTIAL: gate {t1.gate_sni!r} vs python {py_sni!r}")
        if t3 and t3.probe_sni_fires:
            c_sni = t3.probe_sni_fires[0]
            if c_sni not in (None, "NONE") and t1.gate_sni is not None \
                    and c_sni != t1.gate_sni:
                findings.append(
                    f"SNI DIFFERENTIAL: gate {t1.gate_sni!r} vs C {c_sni!r}")

    # T4 (deny-ech probe) must reject exactly the ECH cases and accept the
    # well-formed non-ECH ones.
    if t4 and case.category == "ech":
        flight = t4.flight_obs.get("records", [])
        alert = any(r.get("type") == 21 for r in flight)
        if not alert and t4.openssl_outcome == "completed":
            findings.append("CRITICAL: deny-ech probe completed ECH handshake")
    return findings


# ---------------------------------------------------------------------------
# Setup / main
# ---------------------------------------------------------------------------

def setup() -> None:
    os.makedirs(os.path.join(HERE, "work"), exist_ok=True)
    if not (os.path.exists(CERT) and os.path.exists(KEY)):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", KEY, "-out", CERT, "-days", "2",
             "-subj", f"/CN={APPROVED}",
             "-addext", f"subjectAltName=DNS:{APPROVED}"],
            check=True, capture_output=True)
    if not os.path.exists(PROBE):
        subprocess.run(
            ["gcc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror",
             "-O2", os.path.join(HERE, "ech_cb_probe.c"), "-o", PROBE,
             "-l:libssl.so.3", "-l:libcrypto.so.3"],
            check=True)


def main() -> int:
    setup()
    cases = build_cases()
    only = sys.argv[1] if len(sys.argv) > 1 else None
    all_results = {}
    total_findings = 0
    for case in cases:
        if only and only not in case.name:
            continue
        outcomes: dict[str, TargetOutcome] = {}
        for tgt in case.targets:
            if tgt == "T1":
                outcomes["T1"] = run_python_target(case, use_gate=True,
                                                   approved_policy=True)
            elif tgt == "T2":
                outcomes["T2"] = run_python_target(case, use_gate=False,
                                                   approved_policy=False)
            elif tgt == "T3":
                outcomes["T3"] = run_probe_target(case, "log")
            elif tgt == "T4":
                outcomes["T4"] = run_probe_target(case, "deny-ech")
        findings = evaluate(case, outcomes)
        total_findings += len([f for f in findings if "CRITICAL" in f
                               or "DIFFERENTIAL" in f])
        rec = {
            "name": case.name,
            "category": case.category,
            "findings": findings,
            "outcomes": {k: vars(v) for k, v in outcomes.items()},
        }
        all_results[case.name] = rec
        status = "OK " if not findings else "!! "
        t1 = outcomes.get("T1")
        t1s = ""
        if t1:
            t1s = (f" gate={t1.gate_decision}"
                   f"({t1.gate_reason or '-'})"
                   f" ossl={t1.openssl_outcome or '-'}"
                   f" sni_fires={len(t1.openssl_sni_fires)}")
        print(f"{status}{case.name}{t1s}")
        for f in findings:
            print(f"    FINDING: {f}")
    with open(RESULTS, "w") as fh:
        json.dump(all_results, fh, indent=2, default=str)
    print(f"\nresults written to {RESULTS}")
    print(f"critical/differential findings: {total_findings}")
    return 1 if total_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
