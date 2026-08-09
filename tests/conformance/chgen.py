"""Synthetic TLS ClientHello generator for the M4B-2 ClientHello gate corpus.

Promoted from the M4B-2 ECH spike (spikes/m4b2-ech-gate/chgen.py) so the
conformance corpus never imports from spikes/.  Standard-library only.
Builds raw TLS bytes so conformance tests can present arbitrary (including
hostile/malformed) ClientHello messages to the production gate and to a
real OpenSSL server.

The generator never normalizes on output: what you specify is what goes on
the wire, including deliberate length violations when requested.
"""

from __future__ import annotations

import os
import struct

# TLS record content types
CT_CHANGE_CIPHER_SPEC = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPLICATION_DATA = 23

# Handshake message types
HT_CLIENT_HELLO = 1
HT_SERVER_HELLO = 2

# Extension IDs
EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_PRE_SHARED_KEY = 0x0029
EXT_EARLY_DATA = 0x002A
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_PSK_KEY_EXCHANGE_MODES = 0x002D
EXT_KEY_SHARE = 0x0033
EXT_ECH = 0xFE0D
EXT_ECH_OUTER_EXTENSIONS = 0xFD00  # reserved; used for confusion tests

TLS10 = 0x0301
TLS11 = 0x0302
TLS12 = 0x0303
TLS13 = 0x0304


def grease_values():
    """All 16 GREASE values (RFC 8701)."""
    return [0x0A0A + 0x1010 * i for i in range(16)]


def ext_server_name(hostname: bytes | None) -> bytes:
    if hostname is None:
        return b""
    entry = b"\x00" + struct.pack(">H", len(hostname)) + hostname
    return struct.pack(">H", len(entry)) + entry


def ext_supported_versions(versions: list[int]) -> bytes:
    body = b"".join(struct.pack(">H", v) for v in versions)
    return bytes([len(body)]) + body


def ext_supported_groups(groups: list[int]) -> bytes:
    body = b"".join(struct.pack(">H", g) for g in groups)
    return struct.pack(">H", len(body)) + body


def ext_signature_algorithms(algs: list[int]) -> bytes:
    body = b"".join(struct.pack(">H", a) for a in algs)
    return struct.pack(">H", len(body)) + body


def ext_alpn(protocols: list[bytes]) -> bytes:
    body = b"".join(bytes([len(p)]) + p for p in protocols)
    return struct.pack(">H", len(body)) + body


def ext_key_share(shares: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(
        struct.pack(">HH", group, len(key)) + key for group, key in shares
    )
    return struct.pack(">H", len(body)) + body


def ext_psk_kx_modes(modes: list[int]) -> bytes:
    body = bytes(modes)
    return bytes([len(body)]) + body


def build_extension(ext_id: int, payload: bytes) -> bytes:
    return struct.pack(">HH", ext_id, len(payload)) + payload


def build_client_hello_body(
    *,
    legacy_version: int = TLS12,
    random_bytes: bytes | None = None,
    session_id: bytes = b"",
    cipher_suites: list[int] | None = None,
    compression_methods: bytes = b"\x00",
    extensions: list[tuple[int, bytes]] | None = None,
    include_extensions_block: bool = True,
    # Malformation hooks (default = well-formed):
    extensions_len_override: int | None = None,
    cipher_suites_len_override: int | None = None,
    session_id_len_override: int | None = None,
    compression_len_override: int | None = None,
) -> bytes:
    """Build a ClientHello handshake body (everything after the 4-byte
    handshake header)."""
    if random_bytes is None:
        random_bytes = bytes(32)
    if cipher_suites is None:
        cipher_suites = [0x1301, 0x1302, 0xC02F, 0xC030]

    cs = b"".join(struct.pack(">H", c) for c in cipher_suites)
    cs_len = (
        len(cs) if cipher_suites_len_override is None else cipher_suites_len_override
    )
    sid_len = (
        len(session_id) if session_id_len_override is None
        else session_id_len_override
    )
    comp_len = (
        len(compression_methods) if compression_len_override is None
        else compression_len_override
    )
    head = b"".join(
        [
            struct.pack(">H", legacy_version),
            random_bytes,
            bytes([sid_len]),
            session_id,
            struct.pack(">H", cs_len),
            cs,
            bytes([comp_len]),
            compression_methods,
        ]
    )
    if not include_extensions_block:
        return head
    ext_block = b"".join(build_extension(i, p) for i, p in (extensions or []))
    ext_len = (
        len(ext_block) if extensions_len_override is None else extensions_len_override
    )
    return head + struct.pack(">H", ext_len) + ext_block


def build_handshake_message(
    msg_type: int, body: bytes, *, length_override: int | None = None
) -> bytes:
    n = len(body) if length_override is None else length_override
    return bytes([msg_type]) + n.to_bytes(3, "big") + body


def build_record(
    content_type: int,
    payload: bytes,
    *,
    record_version: int = TLS10,
    length_override: int | None = None,
) -> bytes:
    n = len(payload) if length_override is None else length_override
    return bytes([content_type]) + struct.pack(">HH", record_version, n) + payload


def fragment_handshake_into_records(
    handshake_msg: bytes,
    fragment_sizes: list[int],
    *,
    record_version: int = TLS10,
    content_type: int = CT_HANDSHAKE,
) -> bytes:
    """Split one handshake message across records of the given sizes.
    Sizes must sum to exactly len(handshake_msg)."""
    assert sum(fragment_sizes) == len(handshake_msg), (
        sum(fragment_sizes),
        len(handshake_msg),
    )
    out = b""
    off = 0
    for size in fragment_sizes:
        out += build_record(
            content_type, handshake_msg[off : off + size], record_version=record_version
        )
        off += size
    return out


# ---------------------------------------------------------------------------
# Standard well-formed ClientHello templates
# ---------------------------------------------------------------------------

def typical_extensions(
    hostname: bytes | None,
    *,
    tls13: bool = True,
    alpn: list[bytes] | None = None,
    key_share_group: int = 0x001D,  # x25519
    key_share_bytes: bytes | None = None,
    supported_groups: list[int] | None = None,
) -> list[tuple[int, bytes]]:
    """A plausible modern-browser-style extension set (no ECH)."""
    if alpn is None:
        alpn = [b"http/1.1"]
    if key_share_bytes is None:
        key_share_bytes = os.urandom(32)
    if supported_groups is None:
        supported_groups = [0x001D, 0x0017, 0x0018]  # x25519, secp256r1, secp384r1
    exts: list[tuple[int, bytes]] = []
    if hostname is not None:
        exts.append((EXT_SERVER_NAME, ext_server_name(hostname)))
    exts.append((EXT_SUPPORTED_GROUPS, ext_supported_groups(supported_groups)))
    exts.append((EXT_EC_POINT_FORMATS, b"\x01\x00"))  # uncompressed
    exts.append(
        (
            EXT_SIGNATURE_ALGORITHMS,
            ext_signature_algorithms([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501]),
        )
    )
    exts.append((EXT_ALPN, ext_alpn(alpn)))
    if tls13:
        exts.append((EXT_SUPPORTED_VERSIONS, ext_supported_versions([TLS13, TLS12])))
        exts.append((EXT_PSK_KEY_EXCHANGE_MODES, ext_psk_kx_modes([1])))
        exts.append((EXT_KEY_SHARE, ext_key_share([(key_share_group, key_share_bytes)])))
    else:
        exts.append((EXT_SUPPORTED_VERSIONS, ext_supported_versions([TLS12])))
    return exts


def synthetically_valid_ech_payload(inner_sni: bytes = b"evil.example.test") -> bytes:
    """A syntactically plausible ECH extension payload (ECHClientHello
    'outer' variant).  Contents are not a real ECH encryption; they are
    structurally well-formed per the draft -13-ish layout so parsers that
    look only at structure accept it."""
    # type(1)=outer(0), cipher_suite(4), config_id(1), enc_len(2), enc(0),
    # payload_len(2), payload(...)
    inner = b"AOS-SPIKE-INNER:" + inner_sni
    return b"\x00" + b"\x13\x01\x00\x2f" + b"\x00" + b"\x00\x00" + struct.pack(
        ">H", len(inner)
    ) + inner


def make_client_hello(
    hostname: bytes | None,
    *,
    tls13: bool = True,
    extra_extensions: list[tuple[int, bytes]] | None = None,
    ech: bool = False,
    ech_payload: bytes | None = None,
    grease: bool = False,
    record_version: int = TLS10,
    fragment_sizes: list[int] | None = None,
    session_id: bytes = b"",
    alpn: list[bytes] | None = None,
    key_share_group: int = 0x001D,
    supported_groups: list[int] | None = None,
) -> bytes:
    """Complete wire bytes for one ClientHello flight (record(s) included)."""
    exts = typical_extensions(
        hostname,
        tls13=tls13,
        alpn=alpn,
        key_share_group=key_share_group,
        supported_groups=supported_groups,
    )
    if grease:
        g = grease_values()
        exts.insert(0, (g[0], b""))
        exts.append((g[1], b"\x00"))
    if ech:
        exts.append(
            (EXT_ECH, ech_payload if ech_payload is not None else synthetically_valid_ech_payload())
        )
    if extra_extensions:
        exts.extend(extra_extensions)
    body = build_client_hello_body(
        legacy_version=TLS12, session_id=session_id, extensions=exts
    )
    msg = build_handshake_message(HT_CLIENT_HELLO, body)
    if fragment_sizes is None:
        return build_record(CT_HANDSHAKE, msg, record_version=record_version)
    return fragment_handshake_into_records(
        msg, fragment_sizes, record_version=record_version
    )


def make_sslv2_client_hello(
    cipher_suites: list[int] | None = None,
) -> bytes:
    """SSLv2-compatible ClientHello (2-byte header, no extensions possible).

    0x80 | total_len(15 bits), msg_type=1, version(2), cipher_len(2),
    session_id_len(2)=0, challenge_len(2)=16, ciphers, challenge.
    """
    if cipher_suites is None:
        cipher_suites = [0xC02F, 0xC030, 0x009C]
    cs = b"".join(c.to_bytes(3, "big") for c in cipher_suites)
    challenge = os.urandom(16)
    body = (
        b"\x01"
        + struct.pack(">H", TLS12)
        + struct.pack(">H", len(cs))
        + struct.pack(">H", 0)
        + struct.pack(">H", len(challenge))
        + cs
        + challenge
    )
    total = len(body)
    return bytes([0x80 | (total >> 8), total & 0xFF]) + body
