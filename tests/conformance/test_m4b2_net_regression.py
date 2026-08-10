"""Adversarial-review regression corpus for the M4B-2 network slices.

One test per fixed finding, each written against the PRE-fix behavior and
confirmed to fail before the production change landed:

* DNS-SSRF-01: ``network_resolution._validate_entry` accepted IPv6
  zone-id host strings (``fe80::1%eth0`` / ``fe80::1%25eth0``); any host
  string containing ``%`` is now denied as malformed.
* DNS-SSRF-02 / Origin F3: ``network_origin._validate_address_set``
  never inspected the entry verdict; an address set carrying a
  non-ALLOWED verdict is now a fail-closed INVALID_ADDRESS_SET before any
  socket is created.
* Origin F2: ``build_origin_ssl_context`` did not set
  ``ssl.OP_NO_RENEGOTIATION`` on the origin client context; it is now set
  and verified present, and a TLS 1.2 server double that sends a
  HelloRequest after the handshake is refused on the wire.
* FD sweep off-by-one (fd-leak F-1 / CERT-02): the HTTPS bootstrap
  ``os.closerange`` high bounds are EXCLUSIVE, so fds 29, 35, and 42
  survived the sweep and the top sweep stopped short of the validated
  pass-fd maximum; the sweep now covers exactly the non-admitted
  descriptor space up to ``MAX_SUPERVISOR_FD``.

All fixtures are local: injected resolver callables, synthetic verdict
objects, a 127.0.0.1 TLS 1.2 server double compiled at test time, and a
sacrificial-fd child process (``os.closerange`` is destructive, so the
sweep is exercised only in a throwaway subprocess).  No internet.
"""

from __future__ import annotations

import sys

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip(
        "M4B-2 network regression tests require Linux",
        allow_module_level=True,
    )

import ipaddress
import os
import re
import shutil
import socket
import ssl
import subprocess

from agenticos.sandbox import cert_helper as ch
from agenticos.sandbox import network_boundary as boundary
from agenticos.sandbox import network_origin as origin
from agenticos.sandbox.network_resolution import (
    ResolutionCode,
    resolve_all_once,
)
from agenticos.sandbox.network_resolution import ResolvedAddress
from agenticos.sandbox.special_addresses import AddressDecision, AddressVerdict

HOSTNAME = "example.com"
APPROVED = "approved.example.test"

# Public addresses that pass the frozen special-address policy.
PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)
)))
RENEG_SERVER_SOURCE = os.path.join(
    REPO_ROOT, "tests", "fixtures", "reneg_server.c"
)

TASK_CONTEXT = {
    "task_id": "task-net-regression",
    "task_generation": 7,
    "launch_nonce": "ee" * 16,
    "hostname": APPROVED,
    "policy_digest": "cc" * 32,
}

# The fixed entry descriptor set the HTTPS bootstrap sweep must NOT close
# (broker contract roles 30-33, sealed material roles 36-39, and the
# binding role 43); everything else from fd 3 upward is swept.
SWEEP_ADMITTED_FDS = (30, 31, 32, 33, 36, 37, 38, 39, 43)
SWEEP_SACRIFICIAL_FDS = (29, 35, 42)


# ---------------------------------------------------------------------------
# DNS-SSRF-01: IPv6 zone-id host strings are denied
# ---------------------------------------------------------------------------


def _a(host, port=443):
    return (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (host, port),
    )


def _aaaa(host, port=443, flowinfo=0, scope_id=0):
    return (
        socket.AF_INET6,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (host, port, flowinfo, scope_id),
    )


def _resolver_returning(results):
    def fake(*args, **kwargs):
        return results

    return fake


def test_zone_id_host_strings_are_denied():
    """A host string with '%' (IPv6 zone-id) fails closed as malformed."""
    for host in (
        "fe80::1%eth0",
        "fe80::1%25eth0",
        f"{PUBLIC_V6}%eth0",
    ):
        outcome = resolve_all_once(
            HOSTNAME, getaddrinfo_fn=_resolver_returning([_aaaa(host)])
        )
        assert outcome.code is ResolutionCode.MALFORMED_RESULT, host
        assert outcome.addresses == ()


def test_zone_id_in_mixed_set_denies_whole_resolution():
    outcome = resolve_all_once(
        HOSTNAME,
        getaddrinfo_fn=_resolver_returning(
            [_a(PUBLIC_V4), _aaaa("fe80::1%eth0")]
        ),
    )
    assert outcome.code is ResolutionCode.MALFORMED_RESULT
    assert outcome.addresses == ()


def test_zone_id_rejection_does_not_affect_normal_hosts():
    outcome = resolve_all_once(
        HOSTNAME,
        getaddrinfo_fn=_resolver_returning([_a(PUBLIC_V4), _aaaa(PUBLIC_V6)]),
    )
    assert outcome.code is ResolutionCode.RESOLVED
    assert len(outcome.addresses) == 2


# ---------------------------------------------------------------------------
# DNS-SSRF-02 / Origin F3: non-ALLOWED verdicts rejected from the address set
# ---------------------------------------------------------------------------


def _verdict(decision, ip_text):
    return AddressVerdict(
        decision=decision,
        address=str(ip_text),
        entry=None,
        reason="synthetic regression fixture (test-only connector path)",
        embedded_ipv4=None,
        embedded_decision=None,
        embedded_entry=None,
    )


def _resolved_entry(ip_text, port, decision=AddressDecision.ALLOWED):
    return ResolvedAddress(
        address=ipaddress.ip_address(ip_text),
        family=socket.AF_INET6 if ":" in ip_text else socket.AF_INET,
        port=port,
        verdict=_verdict(decision, ip_text),
    )


def _closed_port():
    """A 127.0.0.1 port that is guaranteed to refuse connections."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def test_prohibited_verdict_entry_is_rejected_before_any_socket():
    """A non-ALLOWED verdict fails closed: INVALID_ADDRESS_SET, 0 attempts."""
    entry = _resolved_entry(
        "127.0.0.1", _closed_port(), AddressDecision.PROHIBITED
    )
    outcome = origin.connect_validated_sockaddr(
        (entry,), connect_timeout=1.0, max_attempts=1
    )
    assert outcome.code is origin.ConnectCode.INVALID_ADDRESS_SET
    assert outcome.attempts == 0
    assert outcome.errors == ()


def test_prohibited_verdict_in_mixed_set_is_rejected_before_any_socket():
    outcome = origin.connect_validated_sockaddr(
        (
            _resolved_entry("127.0.0.1", _closed_port()),
            _resolved_entry(
                "127.0.0.1", _closed_port(), AddressDecision.PROHIBITED
            ),
        ),
        connect_timeout=1.0,
        max_attempts=2,
    )
    assert outcome.code is origin.ConnectCode.INVALID_ADDRESS_SET
    assert outcome.attempts == 0


def test_allowed_verdict_set_still_passes_structural_validation():
    """The added verdict check must not deny a well-formed ALLOWED set."""
    outcome = origin.connect_validated_sockaddr(
        (_resolved_entry("127.0.0.1", _closed_port()),),
        connect_timeout=1.0,
        max_attempts=1,
    )
    assert outcome.code is origin.ConnectCode.CONNECT_FAILED
    assert outcome.attempts == 1


# ---------------------------------------------------------------------------
# Origin F2: OP_NO_RENEGOTIATION on the origin client context
# ---------------------------------------------------------------------------


def _read_fd_payload(fd):
    return os.pread(fd, os.fstat(fd).st_size, 0)


@pytest.fixture(scope="module")
def origin_pems():
    """Slice 2 helper material for the approved hostname (real TLS chain)."""
    material = ch.generate_task_material(**TASK_CONTEXT)
    try:
        yield {
            "ca": _read_fd_payload(material.ca_cert_fd),
            "leaf": _read_fd_payload(material.leaf_cert_fd),
            "key": _read_fd_payload(material.leaf_key_fd),
        }
    finally:
        material.close()


def test_origin_ssl_context_sets_and_verifies_op_no_renegotiation(origin_pems):
    """Both trust-root paths produce a context with renegotiation off."""
    injected = origin.build_origin_ssl_context(
        origin.OriginTrustRoots(
            ca_certs_pem=origin_pems["ca"].decode("ascii")
        )
    )
    system_default = origin.build_origin_ssl_context()
    for context in (injected, system_default):
        assert context.options & ssl.OP_NO_RENEGOTIATION
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname
        assert context.minimum_version == ssl.TLSVersion.TLSv1_2


@pytest.fixture(scope="session")
def reneg_server(tmp_path_factory):
    """The C HelloRequest server double, compiled at test time (mirrors the
    worker-leg reneg_client fixture).  Skips cleanly without cc."""
    cc = shutil.which("cc")
    if cc is None:
        pytest.skip("cc not available; renegotiation probe cannot be built")
    output = tmp_path_factory.mktemp("reneg-server-probe") / "reneg_server"
    subprocess.run(
        [
            cc, "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror",
            "-O2", RENEG_SERVER_SOURCE, "-o", str(output),
            "-l:libssl.so.3", "-l:libcrypto.so.3",
        ],
        check=True,
        capture_output=True,
    )
    return output


def test_origin_tls12_server_hello_request_is_refused(
    tmp_path, origin_pems, reneg_server
):
    """A TLS 1.2 server-initiated HelloRequest fails the origin channel.

    Inverted mirror of the worker-leg probe: here the code under test is
    the TLS CLIENT.  The server double completes the handshake (ALPN
    http/1.1) and then sends a HelloRequest; an OP_NO_RENEGOTIATION
    client answers with a no_renegotiation alert and the second handshake
    never completes.
    """
    cert_path = tmp_path / "leaf.pem"
    key_path = tmp_path / "leaf-key.pem"
    cert_path.write_bytes(origin_pems["leaf"])
    key_path.write_bytes(origin_pems["key"])
    proc = subprocess.Popen(
        [str(reneg_server), str(cert_path), str(key_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    client_failure = None
    transcript = ""
    try:
        banner = proc.stdout.readline()
        assert banner.startswith("PORT "), banner
        transcript += banner
        port = int(banner.split()[1])
        sock = socket.create_connection(("127.0.0.1", port), timeout=10.0)
        outcome = origin.open_origin_tls(
            sock,
            APPROVED,
            trust_roots=origin.OriginTrustRoots(
                ca_certs_pem=origin_pems["ca"].decode("ascii")
            ),
            handshake_timeout=5.0,
        )
        assert outcome.established, outcome.reason
        channel = outcome.channel
        assert channel.tls_version == "TLSv1.2"
        try:
            data = channel.tls_socket.recv(4096)
            if not data:
                client_failure = "connection closed by peer"
        except (ssl.SSLError, OSError) as exc:
            client_failure = f"{type(exc).__name__}: {exc}"
        finally:
            channel.close()
        transcript += proc.communicate(timeout=30)[0]
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()

    # The renegotiation never completed: the server double observed the
    # refusal (the no_renegotiation alert) and the client channel broke
    # instead of silently renegotiating.
    assert "RENEGOTIATION_REFUSED" in transcript, transcript
    assert "RENEGOTIATION_COMPLETED" not in transcript, transcript
    assert client_failure is not None, (
        "origin channel survived a server-initiated HelloRequest"
    )
    assert "no renegotiation" in (
        transcript + str(client_failure)
    ).lower()


# ---------------------------------------------------------------------------
# FD sweep off-by-one (fd-leak F-1 / CERT-02)
# ---------------------------------------------------------------------------


def _sweep_ranges():
    """The (low, high) closerange pairs in the HTTPS bootstrap string."""
    return [
        (int(low), int(high))
        for low, high in re.findall(
            r"os\.closerange\((\d+),(\d+)\)",
            boundary.BROKER_BOOTSTRAP_HTTPS,
        )
    ]


def test_bootstrap_fd_sweep_bounds_are_exact():
    """closerange high bounds are EXCLUSIVE: the sweep must cover every fd
    from 3 up to the validated pass-fd maximum except the admitted roles."""
    assert _sweep_ranges() == [
        (3, 30),  # closes 3-29 (was (3, 29): fd 29 leaked)
        (34, 36),  # closes 34-35 (was (34, 35): fd 35 leaked)
        (40, 43),  # closes 40-42 (was (40, 42): fd 42 leaked)
        # Was 2**30 - 1, short of the validated pass-fd maximum
        # MAX_SUPERVISOR_FD ((1<<31)-1).  The high bound is a C int, so
        # (1<<31) itself overflows; (1<<31)-1 is complete anyway because
        # the kernel never allocates an fd that high (RLIMIT_NOFILE is
        # capped by fs.nr_open < (1<<31)-1).
        (44, boundary.MAX_SUPERVISOR_FD),
    ]


_SWEEP_CHILD = """
import fcntl
import os
import sys


def is_open(fd):
    try:
        fcntl.fcntl(fd, fcntl.F_GETFD)
        return True
    except OSError:
        return False


targets = [int(x) for x in sys.argv[1].split(",")]
admitted = [int(x) for x in sys.argv[2].split(",")]
donor = os.open("/dev/null", os.O_RDONLY)
# Land a sacrificial open descriptor on every checked fd number, no matter
# which descriptors the interpreter itself holds.
for fd in targets + admitted:
    os.dup2(donor, fd)
exec(sys.argv[3])
leaked = [fd for fd in targets if is_open(fd)]
wrongly_closed = [fd for fd in admitted if not is_open(fd)]
if leaked or wrongly_closed:
    print(f"SWEEP_DEFECT leaked={leaked} wrongly_closed={wrongly_closed}")
    sys.exit(1)
print("SWEEP_OK")
"""


def test_bootstrap_fd_sweep_closes_sacrificial_fds_in_child():
    """Run the EXACT bootstrap sweep in a throwaway child (closerange is
    destructive) with sacrificial fds planted at 29/35/42: they must be
    swept while every admitted role descriptor survives."""
    sweep = "".join(
        match.group(0)
        for match in re.finditer(
            r"os\.closerange\(\d+,\d+\);",
            boundary.BROKER_BOOTSTRAP_HTTPS,
        )
    )
    assert sweep, "no closerange statements found in the HTTPS bootstrap"
    proc = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            _SWEEP_CHILD,
            ",".join(str(fd) for fd in SWEEP_SACRIFICIAL_FDS),
            ",".join(str(fd) for fd in SWEEP_ADMITTED_FDS),
            sweep,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, (
        f"sweep child failed: {proc.stdout.strip()} {proc.stderr.strip()}"
    )
    assert "SWEEP_OK" in proc.stdout
