"""Conformance tests for the M4B-2 authenticated origin connection (Slice 8).

Exercises the PRODUCTION composition
``agenticos.sandbox.network_origin.open_origin_https`` and its two stages
(``connect_validated_sockaddr`` numeric connect, ``open_origin_tls``
authenticated origin TLS) entirely against LOCAL fixtures: plain TCP and
real TLS listeners on 127.0.0.1, plus one unroutable TEST-NET-1 address
(RFC 5737, never answers) for the connect-timeout bound.  No internet.

Trust roots are ALWAYS injected per connection (the Slice 2 task CA, a
second independent task CA, or in-process custom CAs for the validity
matrix): no test touches the system trust store, /etc/ssl, or SSL_* /
OPENSSL_* environment variables.  A dedicated test monkeypatches the
system-default loading entry points to fail loudly, proving the injection
path is the only trust source used.

The injected resolution sets are synthetic ``ResolutionOutcome`` values
carrying real ``ResolvedAddress`` entries pointed at the local listeners'
numeric addresses and ports — exactly the "synthetic result sets prove the
exact numeric sockaddr passed to the connector" capability the design doc
mandates (production port 443 and the special-address policy are enforced
upstream, by Slice 7 validation).
"""

from __future__ import annotations

import sys

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("M4B-2 origin connection tests require Linux", allow_module_level=True)

import datetime
import inspect
import ipaddress
import os
import socket
import ssl
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from agenticos.sandbox import cert_helper as ch
from agenticos.sandbox import network_origin as origin
from agenticos.sandbox.network_https import GrantPurpose, NetworkGrant
from agenticos.sandbox.network_resolution import (
    RESOLUTION_POLICY_VERSION,
    ResolutionCode,
    ResolutionOutcome,
    ResolvedAddress,
)
from agenticos.sandbox.special_addresses import AddressDecision, AddressVerdict

APPROVED = "approved.example.test"
OTHER = "other.example.test"

TASK_CONTEXT_A = {
    "task_id": "task-origin-a",
    "task_generation": 5,
    "launch_nonce": "a0" * 16,
    "hostnames": (APPROVED,),
    "policy_digest": "aa" * 32,
}
TASK_CONTEXT_B = {
    "task_id": "task-origin-b",
    "task_generation": 6,
    "launch_nonce": "b0" * 16,
    "hostnames": (OTHER,),
    "policy_digest": "bb" * 32,
}

# RFC 5737 TEST-NET-1: guaranteed unroutable, answers never arrive.
BLACKHOLE_IP = "192.0.2.1"

T0, T1 = 1_000_000_000, 2_000_000_000
W0, W1 = 1_700_000_000_000_000_000, 1_800_000_000_000_000_000

_SERVER_JOIN_TIMEOUT = 20.0


# ---------------------------------------------------------------------------
# Fixtures: certificate material and builders
# ---------------------------------------------------------------------------


def _read_fd_payload(fd):
    return os.pread(fd, os.fstat(fd).st_size, 0)


@pytest.fixture(scope="module")
def pems_a():
    """Slice 2 helper material for the approved hostname (real TLS chain)."""
    material = ch.generate_task_material(**TASK_CONTEXT_A)
    try:
        yield {
            "ca": _read_fd_payload(material.ca_cert_fd),
            "leaf": _read_fd_payload(material.leaf_cert_fd),
            "key": _read_fd_payload(material.leaf_key_fd),
        }
    finally:
        material.close()


@pytest.fixture(scope="module")
def pems_b():
    """A second, fully independent task material (other hostname, other CA)."""
    material = ch.generate_task_material(**TASK_CONTEXT_B)
    try:
        yield {
            "ca": _read_fd_payload(material.ca_cert_fd),
            "leaf": _read_fd_payload(material.leaf_cert_fd),
            "key": _read_fd_payload(material.leaf_key_fd),
        }
    finally:
        material.close()


def _custom_material(not_before, not_after, hostname=APPROVED):
    """In-process CA + leaf with a caller-chosen leaf validity window.

    Mirrors the Slice 2 helper's certificate profile (EC P-256, exact-hostname
    critical SAN, SERVER_AUTH EKU, CA path_length 0) so only the validity
    window differs from the happy path.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "origin-test custom CA")]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(seconds=300))
        .not_valid_after(now + datetime.timedelta(hours=24))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "origin-test custom leaf")]
    )
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                       critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return {
        "ca": ca_cert.public_bytes(serialization.Encoding.PEM),
        "leaf": leaf_cert.public_bytes(serialization.Encoding.PEM),
        "key": leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    }


@pytest.fixture(scope="module")
def pems_expired():
    now = datetime.datetime.now(datetime.timezone.utc)
    return _custom_material(
        now - datetime.timedelta(hours=2), now - datetime.timedelta(hours=1)
    )


@pytest.fixture(scope="module")
def pems_not_yet_valid():
    now = datetime.datetime.now(datetime.timezone.utc)
    return _custom_material(
        now + datetime.timedelta(hours=1), now + datetime.timedelta(hours=2)
    )


def _server_context(tmp_path, pems, *, alpn=("http/1.1",), min_version=None,
                    max_version=None):
    cert_path = tmp_path / "leaf.pem"
    key_path = tmp_path / "leaf-key.pem"
    cert_path.write_bytes(pems["leaf"])
    key_path.write_bytes(pems["key"])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    context.minimum_version = min_version or ssl.TLSVersion.TLSv1_2
    if max_version is not None:
        context.maximum_version = max_version
    if alpn is not None:
        context.set_alpn_protocols(list(alpn))
    return context


# ---------------------------------------------------------------------------
# Harness: local listeners
# ---------------------------------------------------------------------------


class _OriginServer:
    """A local TLS origin on 127.0.0.1 serving ``connections`` handshakes."""

    def __init__(self, server_context, *, connections=1):
        self._context = server_context
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        self.port = self._listener.getsockname()[1]
        self.errors = []
        self.handshakes = []
        self._thread = threading.Thread(
            target=self._run, args=(connections,), daemon=True
        )
        self._thread.start()

    def _run(self, connections):
        try:
            for _ in range(connections):
                conn, _ = self._listener.accept()
                try:
                    tls = self._context.wrap_socket(conn, server_side=True)
                    self.handshakes.append(
                        {
                            "version": tls.version(),
                            "alpn": tls.selected_alpn_protocol(),
                            "sni_peer": tls.getpeercert() is not None,
                        }
                    )
                    tls.settimeout(5.0)
                    try:
                        tls.recv(4096)
                    except OSError:
                        pass
                    tls.close()
                except (ssl.SSLError, OSError) as exc:
                    self.errors.append(exc)
                    try:
                        conn.close()
                    except OSError:
                        pass
        except OSError as exc:
            self.errors.append(exc)
        finally:
            self._listener.close()

    def join(self, timeout=_SERVER_JOIN_TIMEOUT):
        self._thread.join(timeout)


def _plain_listener():
    """A plain (non-TLS) TCP listener that accepts and discards one conn."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    accepted = []

    def run():
        try:
            conn, _ = listener.accept()
            accepted.append(True)
            conn.close()
        except OSError:
            pass
        finally:
            listener.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return port, thread, accepted


def _closed_port():
    """A 127.0.0.1 port that is guaranteed to refuse connections."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


# ---------------------------------------------------------------------------
# Synthetic resolution sets and grants
# ---------------------------------------------------------------------------


def _verdict(ip_text):
    return AddressVerdict(
        decision=AddressDecision.ALLOWED,
        address=str(ip_text),
        entry=None,
        reason="synthetic conformance fixture (test-only connector path)",
        embedded_ipv4=None,
        embedded_decision=None,
        embedded_entry=None,
    )


def _resolved(*endpoints, hostname=APPROVED):
    addresses = tuple(
        ResolvedAddress(
            address=ipaddress.ip_address(ip_text),
            family=socket.AF_INET6 if ":" in ip_text else socket.AF_INET,
            port=port,
            verdict=_verdict(ip_text),
        )
        for ip_text, port in endpoints
    )
    return ResolutionOutcome(
        code=ResolutionCode.RESOLVED,
        hostname=hostname,
        query_name=hostname + ".",
        addresses=addresses,
        reason="synthetic injected resolution set for conformance",
        policy_version=RESOLUTION_POLICY_VERSION,
    )


def _denied_resolution(code=ResolutionCode.RESOLVER_ERROR, hostname=APPROVED):
    return ResolutionOutcome(
        code=code,
        hostname=hostname,
        query_name=hostname + ".",
        addresses=(),
        reason="injected denied resolution for conformance",
        policy_version=RESOLUTION_POLICY_VERSION,
        resolver_error="gaierror errno=-2: injected",
    )


def _grant(hostname=APPROVED, grant_id="grant-origin-1"):
    return NetworkGrant(
        grant_id=grant_id,
        hostname=hostname,
        purpose=GrantPurpose.GENERAL_DOWNLOAD,
        approval_source="test-approval-authority",
        approval_reference="approval-ref-0001",
        granted_at_wall_ns=W0,
        expires_at_wall_ns=W1,
        activated_at_monotonic_ns=T0,
        expires_at_monotonic_ns=T1,
        connection_limit=8,
        byte_limit=1 << 20,
    )


def _trust(pems):
    return origin.OriginTrustRoots(ca_certs_pem=pems["ca"].decode("ascii"))


# ---------------------------------------------------------------------------
# Numeric connect: structure and bounds
# ---------------------------------------------------------------------------


def test_connect_signature_has_no_hostname_parameter():
    sig = inspect.signature(origin.connect_validated_sockaddr)
    assert set(sig.parameters) == {"addresses", "connect_timeout", "max_attempts"}
    assert "hostname" not in sig.parameters


@pytest.mark.parametrize(
    "bad",
    [
        "example.com",                      # bare hostname string
        ("example.com",),                   # hostname-looking entry
        ("192.0.2.1",),                     # numeric-looking STRING entry
        (("127.0.0.1", 443),),              # (host, port) tuple entry
        (b"example.com",),                  # bytes entry
        (),                                 # empty set
    ],
)
def test_connect_rejects_non_validated_address_types(bad):
    """A hostname-looking input cannot be connected: type enforcement."""
    outcome = origin.connect_validated_sockaddr(bad, connect_timeout=0.2)
    assert outcome.code is origin.ConnectCode.INVALID_ADDRESS_SET
    assert not outcome.connected
    assert outcome.attempts == 0
    assert outcome.sock is None


def test_connect_invalid_timeout_and_bound_rejected():
    resolution = _resolved(("127.0.0.1", _closed_port()))
    for kwargs in ({"connect_timeout": 0}, {"connect_timeout": -1.0},
                   {"connect_timeout": "1"}, {"max_attempts": 0},
                   {"max_attempts": 1.5}):
        outcome = origin.connect_validated_sockaddr(
            resolution.addresses, **kwargs
        )
        assert outcome.code is origin.ConnectCode.INVALID_ADDRESS_SET


def test_connect_local_listener_succeeds():
    port, thread, accepted = _plain_listener()
    outcome = origin.connect_validated_sockaddr(
        _resolved(("127.0.0.1", port)).addresses
    )
    assert outcome.code is origin.ConnectCode.CONNECTED
    assert outcome.connected
    assert outcome.attempts == 1
    assert outcome.peer is not None
    assert outcome.peer.port == port
    assert str(outcome.peer.address) == "127.0.0.1"
    assert outcome.sock is not None
    assert outcome.sock.getpeername()[0] == "127.0.0.1"
    outcome.sock.close()
    thread.join(_SERVER_JOIN_TIMEOUT)
    assert accepted == [True]


def test_connect_closed_port_fails_bounded():
    port = _closed_port()
    started = time.monotonic()
    outcome = origin.connect_validated_sockaddr(
        _resolved(("127.0.0.1", port)).addresses, connect_timeout=5.0
    )
    elapsed = time.monotonic() - started
    assert outcome.code is origin.ConnectCode.CONNECT_FAILED
    assert not outcome.connected
    assert outcome.attempts == 1
    assert len(outcome.errors) == 1
    # Refusal is prompt; the 5 s timeout is only an upper bound.
    assert elapsed < 5.0


def test_connect_timeout_enforced_against_blackhole():
    started = time.monotonic()
    outcome = origin.connect_validated_sockaddr(
        _resolved((BLACKHOLE_IP, 443)).addresses, connect_timeout=0.2
    )
    elapsed = time.monotonic() - started
    assert outcome.code is origin.ConnectCode.CONNECT_FAILED
    assert outcome.attempts == 1
    # The injected 0.2 s bound is what stopped the attempt.
    assert 0.2 <= elapsed < 5.0


def test_multiaddress_first_refuses_second_accepts():
    refusing = _closed_port()
    port, thread, accepted = _plain_listener()
    resolution = _resolved(("127.0.0.1", refusing), ("127.0.0.1", port))
    outcome = origin.connect_validated_sockaddr(resolution.addresses)
    assert outcome.connected
    assert outcome.attempts == 2
    assert outcome.peer is not None
    assert outcome.peer.port == port
    assert len(outcome.errors) == 1
    assert outcome.errors[0][0] == f"127.0.0.1:{refusing}"
    outcome.sock.close()
    thread.join(_SERVER_JOIN_TIMEOUT)
    assert accepted == [True]


def test_multiaddress_all_refuse_fails_closed():
    ports = [_closed_port() for _ in range(3)]
    resolution = _resolved(*(("127.0.0.1", p) for p in ports))
    outcome = origin.connect_validated_sockaddr(
        resolution.addresses, connect_timeout=2.0
    )
    assert outcome.code is origin.ConnectCode.CONNECT_FAILED
    assert outcome.attempts == 3
    assert len(outcome.errors) == 3
    assert outcome.sock is None


def test_attempt_bound_respected():
    ports = [_closed_port() for _ in range(3)]
    resolution = _resolved(*(("127.0.0.1", p) for p in ports))
    outcome = origin.connect_validated_sockaddr(
        resolution.addresses, connect_timeout=2.0, max_attempts=2
    )
    assert outcome.code is origin.ConnectCode.CONNECT_FAILED
    # Exactly two attempts although three addresses were validated.
    assert outcome.attempts == 2
    assert len(outcome.errors) == 2
    assert outcome.errors[-1][0] == f"127.0.0.1:{ports[1]}"


# ---------------------------------------------------------------------------
# Origin TLS happy path and evidence
# ---------------------------------------------------------------------------


def test_origin_tls_happy_path_establishes_with_evidence(tmp_path, pems_a):
    server = _OriginServer(_server_context(tmp_path, pems_a))
    try:
        outcome = origin.open_origin_https(
            _resolved(("127.0.0.1", server.port)),
            _grant(),
            trust_roots=_trust(pems_a),
        )
        assert outcome.code is origin.OriginHTTPSCode.ESTABLISHED
        assert outcome.established
        channel = outcome.channel
        assert channel is not None
        assert channel.tls_version in ("TLSv1.2", "TLSv1.3")
        assert channel.alpn_protocol == "http/1.1"
        assert channel.verified_hostname == APPROVED
        assert APPROVED in channel.peer_cert_san_dns
        assert channel.peer_address == "127.0.0.1"
        assert channel.peer_port == server.port
        assert outcome.resolution_code is ResolutionCode.RESOLVED
        assert outcome.connect_attempts == 1
        assert outcome.policy_version.startswith("AOSORIGIN/1+")
        channel.close()
    finally:
        server.join()
    assert not server.errors
    assert len(server.handshakes) == 1
    assert server.handshakes[0]["alpn"] == "http/1.1"


def test_origin_tls_forced_tls12_accepted(tmp_path, pems_a):
    context = _server_context(
        tmp_path, pems_a, max_version=ssl.TLSVersion.TLSv1_2
    )
    server = _OriginServer(context)
    try:
        outcome = origin.open_origin_https(
            _resolved(("127.0.0.1", server.port)),
            _grant(),
            trust_roots=_trust(pems_a),
        )
        assert outcome.established
        assert outcome.channel is not None
        assert outcome.channel.tls_version == "TLSv1.2"
        outcome.channel.close()
    finally:
        server.join()
    assert not server.errors


def test_no_resolution_between_validation_and_connection(
    tmp_path, pems_a, monkeypatch
):
    """getaddrinfo can never fire on the connect path (structural proof)."""
    server = _OriginServer(_server_context(tmp_path, pems_a))

    def _explode(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("getaddrinfo called on the origin connect path")

    monkeypatch.setattr(socket, "getaddrinfo", _explode)
    try:
        outcome = origin.open_origin_https(
            _resolved(("127.0.0.1", server.port)),
            _grant(),
            trust_roots=_trust(pems_a),
        )
        assert outcome.established
        assert outcome.channel is not None
        outcome.channel.close()
    finally:
        server.join()


# ---------------------------------------------------------------------------
# Origin TLS failure matrix -> typed stage codes
# ---------------------------------------------------------------------------


def test_wrong_hostname_certificate_denied(tmp_path, pems_b):
    """Leaf for other.example.test vs approved approved.example.test."""
    server = _OriginServer(_server_context(tmp_path, pems_b))
    try:
        outcome = origin.open_origin_https(
            _resolved(("127.0.0.1", server.port)),
            _grant(),
            trust_roots=_trust(pems_b),
        )
        assert outcome.code is origin.OriginHTTPSCode.VERIFICATION_FAILED
        assert outcome.channel is None
    finally:
        server.join()


def test_expired_certificate_denied(tmp_path, pems_expired):
    server = _OriginServer(_server_context(tmp_path, pems_expired))
    try:
        outcome = origin.open_origin_https(
            _resolved(("127.0.0.1", server.port)),
            _grant(),
            trust_roots=_trust(pems_expired),
        )
        assert outcome.code is origin.OriginHTTPSCode.VERIFICATION_FAILED
    finally:
        server.join()


def test_not_yet_valid_certificate_denied(tmp_path, pems_not_yet_valid):
    server = _OriginServer(_server_context(tmp_path, pems_not_yet_valid))
    try:
        outcome = origin.open_origin_https(
            _resolved(("127.0.0.1", server.port)),
            _grant(),
            trust_roots=_trust(pems_not_yet_valid),
        )
        assert outcome.code is origin.OriginHTTPSCode.VERIFICATION_FAILED
    finally:
        server.join()


def test_untrusted_ca_denied(tmp_path, pems_a, pems_b):
    server = _OriginServer(_server_context(tmp_path, pems_a))
    try:
        outcome = origin.open_origin_https(
            _resolved(("127.0.0.1", server.port)),
            _grant(),
            trust_roots=_trust(pems_b),
        )
        assert outcome.code is origin.OriginHTTPSCode.VERIFICATION_FAILED
    finally:
        server.join()


def test_h2_only_origin_denied_alpn_failed(tmp_path, pems_a):
    server = _OriginServer(_server_context(tmp_path, pems_a, alpn=("h2",)))
    try:
        outcome = origin.open_origin_https(
            _resolved(("127.0.0.1", server.port)),
            _grant(),
            trust_roots=_trust(pems_a),
        )
        assert outcome.code is origin.OriginHTTPSCode.ALPN_FAILED
        assert outcome.channel is None
    finally:
        server.join()


def test_no_alpn_origin_denied_alpn_failed(tmp_path, pems_a):
    server = _OriginServer(_server_context(tmp_path, pems_a, alpn=None))
    try:
        outcome = origin.open_origin_https(
            _resolved(("127.0.0.1", server.port)),
            _grant(),
            trust_roots=_trust(pems_a),
        )
        assert outcome.code is origin.OriginHTTPSCode.ALPN_FAILED
    finally:
        server.join()


@pytest.mark.filterwarnings("ignore:ssl.TLSVersion.*is deprecated:DeprecationWarning")
def test_tls11_only_origin_denied(tmp_path, pems_a):
    context = _server_context(
        tmp_path,
        pems_a,
        min_version=ssl.TLSVersion.TLSv1,
        max_version=ssl.TLSVersion.TLSv1_1,
    )
    server = _OriginServer(context)
    try:
        outcome = origin.open_origin_https(
            _resolved(("127.0.0.1", server.port)),
            _grant(),
            trust_roots=_trust(pems_a),
        )
        # Version negotiation fails before any certificate is evaluated.
        assert outcome.code is origin.OriginHTTPSCode.TLS_FAILED
    finally:
        server.join()


def test_composition_resolution_denied_stage():
    outcome = origin.open_origin_https(
        _denied_resolution(), _grant(), trust_roots=None
    )
    assert outcome.code is origin.OriginHTTPSCode.RESOLUTION_DENIED
    assert outcome.resolution_code is ResolutionCode.RESOLVER_ERROR


def test_composition_hostname_mismatch_stage():
    outcome = origin.open_origin_https(
        _resolved(("127.0.0.1", 443), hostname=OTHER),
        _grant(),
        trust_roots=None,
    )
    assert outcome.code is origin.OriginHTTPSCode.HOSTNAME_MISMATCH


def test_composition_connect_failed_stage():
    outcome = origin.open_origin_https(
        _resolved(("127.0.0.1", _closed_port())),
        _grant(),
        trust_roots=None,
        connect_timeout=2.0,
    )
    assert outcome.code is origin.OriginHTTPSCode.CONNECT_FAILED
    assert outcome.connect_attempts == 1


def test_composition_invalid_address_set_stage():
    resolution = _resolved(("127.0.0.1", 443))
    forged = ResolutionOutcome(
        code=ResolutionCode.RESOLVED,
        hostname=APPROVED,
        query_name=APPROVED + ".",
        addresses=("example.com",),  # type: ignore[arg-type]
        reason="forged non-ResolvedAddress entries",
        policy_version=RESOLUTION_POLICY_VERSION,
    )
    outcome = origin.open_origin_https(forged, _grant(), trust_roots=None)
    assert outcome.code is origin.OriginHTTPSCode.INVALID_ADDRESS_SET
    assert resolution.code is ResolutionCode.RESOLVED


def test_failure_stage_codes_are_distinguishable():
    """Every failure matrix entry maps to a distinct, expected stage code.

    The matrix tests above each assert their exact code; here the stage set
    itself is pinned so a future change cannot collapse two stages into one
    code without failing this test.
    """
    expected = {
        origin.OriginHTTPSCode.RESOLUTION_DENIED,
        origin.OriginHTTPSCode.HOSTNAME_MISMATCH,
        origin.OriginHTTPSCode.CONNECT_FAILED,
        origin.OriginHTTPSCode.VERIFICATION_FAILED,
        origin.OriginHTTPSCode.ALPN_FAILED,
        origin.OriginHTTPSCode.TLS_FAILED,
    }
    assert len(expected) == 6  # all six stages are distinguishable


# ---------------------------------------------------------------------------
# Trust-root isolation and no system-trust mutation
# ---------------------------------------------------------------------------


def test_trust_roots_do_not_leak_between_connections(tmp_path, pems_a, pems_b):
    """Policy B's roots are not trusted by policy A's connection and vice
    versa: each connection builds a FRESH context from its injected roots."""
    context = _server_context(tmp_path, pems_a)
    server = _OriginServer(context, connections=2)
    try:
        # Connection 1: trust roots name CA B only -> server A's chain fails.
        denied = origin.open_origin_https(
            _resolved(("127.0.0.1", server.port)),
            _grant(),
            trust_roots=_trust(pems_b),
        )
        assert denied.code is origin.OriginHTTPSCode.VERIFICATION_FAILED
        # Connection 2: trust roots name CA A only -> succeeds.  If trust
        # persisted across connections, connection 2 would see CA B state.
        established = origin.open_origin_https(
            _resolved(("127.0.0.1", server.port)),
            _grant(),
            trust_roots=_trust(pems_a),
        )
        assert established.established
        assert established.channel is not None
        established.channel.close()
    finally:
        server.join()


def test_injected_trust_path_never_touches_system_trust(
    tmp_path, pems_a, monkeypatch
):
    """The injection path is the only trust source: system-default loading
    entry points and SSL_* environment are never involved."""
    env_before = {
        key: value
        for key, value in os.environ.items()
        if key.startswith("SSL_") or key.startswith("OPENSSL_")
    }

    def _no_default_context(*args, **kwargs):  # pragma: no cover
        raise AssertionError("system default CA store was consulted")

    def _no_default_certs(self, *args, **kwargs):  # pragma: no cover
        raise AssertionError("load_default_certs was called")

    monkeypatch.setattr(ssl, "create_default_context", _no_default_context)
    monkeypatch.setattr(
        ssl.SSLContext, "load_default_certs", _no_default_certs
    )
    server = _OriginServer(_server_context(tmp_path, pems_a))
    try:
        outcome = origin.open_origin_https(
            _resolved(("127.0.0.1", server.port)),
            _grant(),
            trust_roots=_trust(pems_a),
        )
        assert outcome.established
        assert outcome.channel is not None
        outcome.channel.close()
    finally:
        server.join()
    env_after = {
        key: value
        for key, value in os.environ.items()
        if key.startswith("SSL_") or key.startswith("OPENSSL_")
    }
    assert env_before == env_after
    # The test itself never wrote to the system trust store location.
    assert not os.environ.get("SSL_CERT_FILE")
    assert not os.environ.get("SSL_CERT_DIR")
