"""Real-host integration proof for M4B-3 Slice 1 Connected Build grant sets.

Full launches through the authenticated M4B-1 broker boundary carrying a
multi-grant sealed NetworkPolicy and a multi-SAN sealed task leaf.  The
worker drives a SEQUENCE of broker sessions (scenario M4B3-01) against a
bounded set of pre-armed conformance synthetic origins (one per granted
hostname, armed in order through the private FixtureFdConnector path).
Covers: two-grant full path with per-grant evidence, per-grant method
policy, cross-grant SNI divergence, ungranted redirect target re-entering
authorization, the deterministic Connected Build environment profile,
per-grant connection limits, and ALPN h2-offer fallback.  Conventions
mirror test_m4b_https_integration.py.
"""

from __future__ import annotations

import sys

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("M4B-3 real-host proof requires Linux", allow_module_level=True)

import datetime
import fcntl
import json
import os
from pathlib import Path
import socket
import ssl
import threading
import time
import uuid

from agenticos.sandbox import m4b_runner as runner_module
from agenticos.sandbox.evidence import EvidenceCollector
from agenticos.sandbox.network_https import GrantPurpose
from agenticos.sandbox.network_models import TransportMode, TransportPolicy
from agenticos.sandbox.runtime_boundary import M4AProfile, WORKER_ENVIRONMENT

from helpers import WORKER_PATH
from test_m4b_integration import (
    FAST,
    _assert_no_m4b_residue,
    _fixed_native_fd_window,
    _same_uid_opaque_fd_baseline,
)
from test_m4b_https_integration import (
    _origin_read_request,
    _worker_argv,
    m4b2_host_state,
    m4b2_native_helpers,
    m4b2_vendor,
)
from test_m4b_origin_unit import _custom_material, _server_context


pytestmark = pytest.mark.m4b_linux

REPO_ROOT = Path(__file__).resolve().parents[2]
HOST_A = "alpha.example.com"
HOST_B = "beta.example.com"
HOST_UNGRANTED = "ungranted.example"


class _ScriptedOriginServer:
    """A scripted test TLS origin with a responder hook (fixture socketpair).

    Mirrors _SyntheticOriginServer from test_m4b_https_integration.py but
    lets each test script the exact response bytes (e.g. a 302 redirect).
    """

    def __init__(self, cert_dir, *, hostname, respond, request_count=1):
        cert_dir.mkdir(parents=True, exist_ok=True)
        now = datetime.datetime.now(datetime.timezone.utc)
        self.pems = _custom_material(
            now - datetime.timedelta(minutes=2),
            now + datetime.timedelta(hours=1),
            hostname=hostname,
        )
        self.requests = []
        self.errors = []
        broker_end, server_end = socket.socketpair()
        # Pin both ends above the fixed native FD window: the launch chain
        # vacates low descriptors and the origin thread runs across it.
        for index, sock in enumerate((broker_end, server_end)):
            pinned = fcntl.fcntl(sock.fileno(), fcntl.F_DUPFD_CLOEXEC, 300 + index)
            sock.close()
            if index == 0:
                broker_end = socket.socket(fileno=pinned)
            else:
                server_end = socket.socket(fileno=pinned)
        self.broker_sock = broker_end
        self._context = _server_context(cert_dir, self.pems)
        self._thread = threading.Thread(
            target=self._run,
            args=(server_end, respond, request_count),
            daemon=True,
        )
        self._thread.start()

    def _run(self, sock, respond, request_count):
        try:
            tls = self._context.wrap_socket(sock, server_side=True)
            tls.settimeout(25.0)
            for index in range(request_count):
                request = _origin_read_request(tls)
                self.requests.append(request)
                if not respond(tls, request, index):
                    break
            tls.close()
        except (ssl.SSLError, OSError) as exc:
            self.errors.append(f"{type(exc).__name__}: {exc}")
        except RuntimeError as exc:
            self.errors.append(str(exc))
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def join(self, timeout=8.0):
        self._thread.join(timeout)
        assert not self._thread.is_alive(), "scripted origin thread stuck"

    def close(self):
        try:
            self.broker_sock.close()
        except OSError:
            pass


def _ok_responder(body, *, keepalive=False):
    """Fixed 200 response; Connection: close so the session ends cleanly."""

    def respond(tls, _request, _index):
        connection = b"" if keepalive else b"Connection: close\r\n"
        tls.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(body)).encode("ascii")
            + b"\r\n" + connection + b"\r\n" + body
        )
        return True

    return respond


def _redirect_responder(location):
    """A 302 the broker must relay byte-exact and NEVER follow."""

    def respond(tls, _request, _index):
        tls.sendall(
            b"HTTP/1.1 302 Found\r\nLocation: " + location
            + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        return True

    return respond


def _spec(hostname, purpose, **changes):
    values = {
        "hostname": hostname,
        "purpose": purpose,
        "approval_source": "m4b3-integration",
        "approval_reference": "slice-m4b3-s1",
    }
    values.update(changes)
    return runner_module.HostGrantSpec(**values)


def _two_grant_specs(**per_host):
    return (
        _spec(HOST_A, GrantPurpose.GENERAL_DOWNLOAD, **per_host.get(HOST_A, {})),
        _spec(HOST_B, GrantPurpose.GIT_SMART_FETCH, **per_host.get(HOST_B, {})),
    )


@pytest.fixture
def m4b3_runner_factory(layout, m4b2_native_helpers, m4b2_host_state, m4b2_vendor):
    launcher, supervisor = m4b2_native_helpers
    counter = 0

    def make(
        *,
        grant_specs,
        connected_build_profile=False,
        fixture_origins=(),
        fixture_addresses=("93.184.216.34",),
        lifetime=30.0,
        connection_limit=8,
        byte_limit=256 * 1024,
        transport_policy=None,
        host_state_dir=None,
    ):
        nonlocal counter
        counter += 1
        now = time.monotonic_ns()
        synthetic_home = layout.root / f"m4b3-home-{counter}"
        synthetic_home.mkdir()
        policy = transport_policy or TransportPolicy(
            version="AOSNET/1",
            task_id=f"m4b3-real-{counter}-{uuid.uuid4().hex[:8]}",
            task_generation=counter,
            launch_nonce=uuid.uuid4().hex,
            mode=TransportMode.DENY,
            proxy_host="127.0.0.1",
            proxy_port=18080,
            activated_at_monotonic_ns=now - 1_000_000_000,
            expires_at_monotonic_ns=now + int(lifetime * 1_000_000_000),
            connection_limit=connection_limit,
            byte_limit=byte_limit,
        )
        connectors = None
        if fixture_origins:
            built = []
            for origin in fixture_origins:
                # Pin the synthetic origin socket above the fixed native FD
                # window before the launch vacates low descriptors.
                pinned = fcntl.fcntl(
                    origin.broker_sock.fileno(), fcntl.F_DUPFD_CLOEXEC, 300
                )
                origin.broker_sock.close()
                origin.broker_sock = socket.socket(fileno=pinned)
                built.append(
                    runner_module.FixtureFdConnector(
                        origin.broker_sock,
                        ca_certs_pem=origin.pems["ca"].decode("ascii"),
                        addresses=fixture_addresses,
                    )
                )
            connectors = tuple(built)
        runner = runner_module.HttpsCapabilityTransportRunner(
            WORKER_PATH,
            workspace=layout.assigned_worktree,
            profile=M4AProfile.BUILD,
            launcher_path=launcher,
            task_tmp=layout.task_tmp,
            synthetic_home=synthetic_home,
            transport_policy=policy,
            supervisor_path=supervisor,
            cancellation=FAST,
            collector=EvidenceCollector(normalize_root=layout.root),
            setup_timeout=5.0,
            approved_grants=grant_specs,
            connected_build_profile=connected_build_profile,
            host_state_dir=host_state_dir or m4b2_host_state,
            broker_vendor_dir=m4b2_vendor,
            _fixture_connector=connectors,
        )
        live_run = runner.run

        def run_with_fixed_fd_window(*args, **kwargs):
            if not hasattr(runner, "_opaque_fd_baseline"):
                runner._opaque_fd_baseline = _same_uid_opaque_fd_baseline()
            with _fixed_native_fd_window():
                return live_run(*args, **kwargs)

        runner.run = run_with_fixed_fd_window
        return runner

    return make


def _m4b3_worker_options(options):
    return _worker_argv(
        "--scenario",
        "M4B3-01",
        "--target",
        "connected-build",
        "--canary",
        json.dumps(options, separators=(",", ":")),
    )


def _run_m4b3_worker(runner, options):
    process = runner.run(_m4b3_worker_options(options), cwd="/workspace", env={})
    assert process.exit_code == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["succeeded"] is True, result
    return result["details"]


def _records(runner, count):
    records = runner.last_https_connection_records
    assert records is not None and len(records) == count, records
    return records


# ---------------------------------------------------------------------------
# Two-grant launch: full path per grant, per-grant evidence
# ---------------------------------------------------------------------------


def test_m4b3_two_grant_launch_full_path(m4b3_runner_factory, tmp_path):
    origin_a = _ScriptedOriginServer(
        tmp_path / "origin-a",
        hostname=HOST_A,
        respond=_ok_responder(b"m4b3-artifact-bytes"),
    )
    origin_b = _ScriptedOriginServer(
        tmp_path / "origin-b",
        hostname=HOST_B,
        respond=_ok_responder(b"m4b3-git-info-refs"),
    )
    runner = m4b3_runner_factory(
        grant_specs=_two_grant_specs(),
        fixture_origins=(origin_a, origin_b),
    )
    details = _run_m4b3_worker(
        runner,
        {
            "sessions": [
                {
                    "authority": f"{HOST_A}:443",
                    "requests": [{"method": "GET", "path": "/artifact"}],
                },
                {
                    "authority": f"{HOST_B}:443",
                    "requests": [
                        {"method": "GET", "path": "/info/refs?service=git-upload-pack"}
                    ],
                },
            ]
        },
    )
    sessions = details["sessions"]
    assert len(sessions) == 2
    for session, host, body in (
        (sessions[0], HOST_A, b"m4b3-artifact-bytes"),
        (sessions[1], HOST_B, b"m4b3-git-info-refs"),
    ):
        assert session["succeeded"] is True, session
        inner = session["details"]
        assert inner["connect_reply"].startswith("HTTP/1.1 200")
        assert inner["tls_version"] == "TLSv1.3"
        assert inner["alpn"] == "http/1.1"
        response = inner["responses"][0]
        assert response["status"] == 200
        assert bytes.fromhex(response["body_hex"]) == body

    origin_a.join()
    origin_b.join()
    assert origin_a.requests == [
        f"GET /artifact HTTP/1.1\r\nHost: {HOST_A}\r\n\r\n".encode("ascii")
    ]
    assert origin_b.requests == [
        f"GET /info/refs?service=git-upload-pack HTTP/1.1\r\n"
        f"Host: {HOST_B}\r\n\r\n".encode("ascii")
    ]
    assert origin_a.errors == []
    assert origin_b.errors == []

    terminal = runner.last_https_terminal
    assert terminal is not None
    assert terminal.synthetic_origin is True
    record_a, record_b = _records(runner, 2)
    assert record_a.approved_hostname == HOST_A
    assert record_a.identity_chain == "verified"
    assert record_a.connect_authority == HOST_A
    assert record_a.worker_sni == HOST_A
    assert record_a.http_host == HOST_A
    assert record_a.origin_tls_name == HOST_A
    assert record_a.synthetic_origin is True
    assert record_a.terminal_reason.value == "completed"
    assert record_a.requests_completed == 1
    assert record_b.approved_hostname == HOST_B
    assert record_b.identity_chain == "verified"
    assert record_b.connect_authority == HOST_B
    assert record_b.worker_sni == HOST_B
    assert record_b.http_host == HOST_B
    assert record_b.origin_tls_name == HOST_B
    assert record_b.synthetic_origin is True
    assert record_b.terminal_reason.value == "completed"
    assert record_b.requests_completed == 1
    assert terminal.connection_count == 2
    origin_a.close()
    origin_b.close()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# Per-grant method policy
# ---------------------------------------------------------------------------


def test_m4b3_method_policy_is_per_grant(m4b3_runner_factory, tmp_path):
    """POST is denied on the GENERAL_DOWNLOAD grant but crosses the parser on
    the GIT_SMART_FETCH grant — method authority follows the connection's
    grant, not the policy as a whole."""
    origin_b = _ScriptedOriginServer(
        tmp_path / "origin-b",
        hostname=HOST_B,
        respond=_ok_responder(b"m4b3-git-post-ack"),
    )
    runner = m4b3_runner_factory(
        grant_specs=_two_grant_specs(),
        fixture_origins=(origin_b,),
    )
    details = _run_m4b3_worker(
        runner,
        {
            "sessions": [
                {
                    "authority": f"{HOST_A}:443",
                    "requests": [
                        {"method": "POST", "path": "/upload", "body": "x"}
                    ],
                },
                {
                    "authority": f"{HOST_B}:443",
                    "requests": [
                        {
                            "method": "POST",
                            "path": "/git-upload-pack",
                            "body": "m4b3-git-request-body",
                        }
                    ],
                },
            ]
        },
    )
    session_a, session_b = details["sessions"]
    # The typed parser rejection closes the connection: no response frames.
    assert session_a["succeeded"] is False
    assert "error" in session_a["details"]["responses"][0]
    assert session_b["succeeded"] is True, session_b
    assert session_b["details"]["responses"][0]["status"] == 200

    origin_b.join()
    assert origin_b.requests == [
        b"POST /git-upload-pack HTTP/1.1\r\nHost: " + HOST_B.encode("ascii")
        + b"\r\nContent-Length: 21\r\n\r\nm4b3-git-request-body"
    ]
    assert origin_b.errors == []

    record_a, record_b = _records(runner, 2)
    assert record_a.approved_hostname == HOST_A
    assert record_a.detail == "http_method_not_allowed"
    assert record_a.terminal_reason.value == "denied"
    assert record_a.stage_reached.value == "http_prevalidation"
    assert record_a.requests_completed == 0
    assert record_b.approved_hostname == HOST_B
    assert record_b.identity_chain == "verified"
    assert record_b.requests_completed == 1
    origin_b.close()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# Cross-grant identity divergence
# ---------------------------------------------------------------------------


def test_m4b3_cross_grant_sni_mismatch_denied(m4b3_runner_factory, tmp_path):
    """CONNECT for B with SNI for A: both granted, yet the per-connection
    SNI policy authorizes only the connection's own grant."""
    origin = _ScriptedOriginServer(
        tmp_path / "origin",
        hostname=HOST_B,
        respond=_ok_responder(b"unused"),
    )
    runner = m4b3_runner_factory(
        grant_specs=_two_grant_specs(),
        fixture_origins=(origin,),
    )
    details = _run_m4b3_worker(
        runner,
        {
            "sessions": [
                {"authority": f"{HOST_B}:443", "sni": HOST_A},
            ]
        },
    )
    session = details["sessions"][0]
    assert session["succeeded"] is False
    assert session["details"]["connect_reply"].startswith("HTTP/1.1 200")
    assert session["error_type"] == "SSLError"

    origin.close()
    origin.join()
    assert origin.requests == []
    (record,) = _records(runner, 1)
    assert record.approved_hostname == HOST_B
    assert record.worker_sni == HOST_A
    assert record.detail == "worker_tls_sni_mismatch"
    assert record.terminal_reason.value == "denied"
    assert record.stage_reached.value == "worker_tls"
    assert record.identity_chain == "identity_divergence:worker_sni"
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# Ungranted redirect target re-enters authorization
# ---------------------------------------------------------------------------


def test_m4b3_ungranted_redirect_target_denied(m4b3_runner_factory, tmp_path):
    """The broker relays a 302 byte-exact and never follows it; when the
    worker re-CONNECTs to the redirect target it re-enters authorization
    and is denied because the target names no grant."""
    origin = _ScriptedOriginServer(
        tmp_path / "origin",
        hostname=HOST_A,
        respond=_redirect_responder(b"https://ungranted.example/x"),
    )
    runner = m4b3_runner_factory(
        grant_specs=_two_grant_specs(),
        fixture_origins=(origin,),
    )
    details = _run_m4b3_worker(
        runner,
        {
            "sessions": [
                {
                    "authority": f"{HOST_A}:443",
                    "requests": [{"method": "GET", "path": "/old"}],
                },
                {"authority": f"{HOST_UNGRANTED}:443"},
            ]
        },
    )
    session_a, session_b = details["sessions"]
    assert session_a["succeeded"] is True, session_a
    response = session_a["details"]["responses"][0]
    assert response["status"] == 302
    assert response["headers"]["location"] == "https://ungranted.example/x"
    assert session_b["succeeded"] is False
    assert session_b["error_type"] == "ConnectDenied"
    assert session_b["details"]["connect_reply"].startswith("HTTP/1.1 403")

    origin.join()
    assert origin.requests == [
        f"GET /old HTTP/1.1\r\nHost: {HOST_A}\r\n\r\n".encode("ascii")
    ]
    record_a, record_b = _records(runner, 2)
    assert record_a.approved_hostname == HOST_A
    assert record_a.identity_chain == "verified"
    assert record_a.terminal_reason.value == "completed"
    assert record_b.stage_reached.value == "authorization"
    assert record_b.detail == "authorization_no_match"
    assert record_b.terminal_reason.value == "denied"
    assert record_b.approved_hostname is None
    assert record_b.identity_chain == "no_grant"
    origin.close()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# Connected Build deterministic worker environment
# ---------------------------------------------------------------------------


def test_m4b3_connected_build_env_census(m4b3_runner_factory, tmp_path):
    origin = _ScriptedOriginServer(
        tmp_path / "origin",
        hostname=HOST_A,
        respond=_ok_responder(b"m4b3-profile-body"),
    )
    runner = m4b3_runner_factory(
        grant_specs=_two_grant_specs(),
        connected_build_profile=True,
        fixture_origins=(origin,),
    )
    details = _run_m4b3_worker(
        runner,
        {
            "env_census": True,
            "sessions": [
                {
                    "authority": f"{HOST_A}:443",
                    "requests": [{"method": "GET", "path": "/"}],
                }
            ],
        },
    )
    expected = dict(WORKER_ENVIRONMENT) | dict(
        runner_module.CONNECTED_BUILD_WORKER_EXTRA_ENV
    )
    assert details["environment"] == expected
    # Ambient proxy/verification-bypass variables are absent by construction.
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "all_proxy",
        "no_proxy",
        "NO_PROXY",
        "GIT_SSL_NO_VERIFY",
    ):
        assert name not in details["environment"]
    assert details["environment"]["https_proxy"] == "http://127.0.0.1:18080"
    assert details["environment"]["SSL_CERT_FILE"] == (
        "/opt/agenticos/network-ca.pem"
    )
    # The profiled environment still brokers the granted session.
    session = details["sessions"][0]
    assert session["succeeded"] is True, session
    (record,) = _records(runner, 1)
    assert record.identity_chain == "verified"
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# Per-grant connection limit
# ---------------------------------------------------------------------------


def test_m4b3_per_grant_connection_limit(m4b3_runner_factory, tmp_path):
    origin_a = _ScriptedOriginServer(
        tmp_path / "origin-a",
        hostname=HOST_A,
        respond=_ok_responder(b"m4b3-alpha-body"),
    )
    origin_b = _ScriptedOriginServer(
        tmp_path / "origin-b",
        hostname=HOST_B,
        respond=_ok_responder(b"m4b3-beta-body"),
    )
    runner = m4b3_runner_factory(
        grant_specs=_two_grant_specs(**{HOST_A: {"connection_limit": 1}}),
        fixture_origins=(origin_a, origin_b),
    )
    details = _run_m4b3_worker(
        runner,
        {
            "sessions": [
                {
                    "authority": f"{HOST_A}:443",
                    "requests": [{"method": "GET", "path": "/"}],
                },
                {"authority": f"{HOST_A}:443"},
                {
                    "authority": f"{HOST_B}:443",
                    "requests": [{"method": "GET", "path": "/"}],
                },
            ]
        },
    )
    session_a1, session_a2, session_b = details["sessions"]
    assert session_a1["succeeded"] is True, session_a1
    assert session_a2["succeeded"] is False
    assert session_a2["error_type"] == "ConnectDenied"
    assert session_a2["details"]["connect_reply"].startswith("HTTP/1.1 403")
    assert session_b["succeeded"] is True, session_b

    record_a1, record_a2, record_b = _records(runner, 3)
    assert record_a1.approved_hostname == HOST_A
    assert record_a1.identity_chain == "verified"
    assert record_a2.stage_reached.value == "authorization"
    assert record_a2.detail == "grant_connection_limit"
    assert record_a2.terminal_reason.value == "denied"
    assert record_b.approved_hostname == HOST_B
    assert record_b.identity_chain == "verified"
    origin_a.close()
    origin_b.close()
    origin_a.join()
    origin_b.join()
    _assert_no_m4b_residue(runner)


# ---------------------------------------------------------------------------
# ALPN fallback: h2 offer still lands on http/1.1
# ---------------------------------------------------------------------------


def test_m4b3_alpn_h2_offer_falls_back_to_http11(m4b3_runner_factory, tmp_path):
    """A git/curl-style ALPN offer ["h2", "http/1.1"] must negotiate
    http/1.1 — the broker's worker context offers exactly that protocol."""
    origin = _ScriptedOriginServer(
        tmp_path / "origin",
        hostname=HOST_A,
        respond=_ok_responder(b"m4b3-alpn-body"),
    )
    runner = m4b3_runner_factory(
        grant_specs=_two_grant_specs(),
        fixture_origins=(origin,),
    )
    details = _run_m4b3_worker(
        runner,
        {
            "sessions": [
                {
                    "authority": f"{HOST_A}:443",
                    "alpn": ["h2", "http/1.1"],
                    "requests": [{"method": "GET", "path": "/"}],
                }
            ]
        },
    )
    session = details["sessions"][0]
    assert session["succeeded"] is True, session
    assert session["details"]["alpn"] == "http/1.1"
    assert session["details"]["responses"][0]["status"] == 200
    (record,) = _records(runner, 1)
    assert record.worker_alpn == "http/1.1"
    assert record.origin_alpn == "http/1.1"
    assert record.identity_chain == "verified"
    origin.close()
    origin.join()
    _assert_no_m4b_residue(runner)
