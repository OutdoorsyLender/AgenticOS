"""Integration and adversarial security test suite for AgenticOS task-scoped provider broker."""

import http.server
import os
import socket
import socketserver
import threading
import time
import urllib.request
import pytest
from typing import Generator, Tuple

from agenticos.sandbox.provider_broker import TaskProviderBroker
from agenticos.sandbox.provider_models import (
    ProviderBrokerPolicy,
    ProviderFailureClass,
    SecretValue,
    SyntheticBearerAuth,
    provider_policy_digest,
)

CANARY_TOKEN = "CANARY_SYNTHETIC_BEARER_TOKEN_SECRET_987654321"


class FakeUpstreamHandler(http.server.BaseHTTPRequestHandler):
    """Fake upstream provider server validating headers and emitting Responses SSE stream."""

    received_authorization: str | None = None
    received_host: str | None = None
    received_path: str | None = None
    received_body: bytes | None = None

    def log_message(self, format: str, *args: object) -> None:
        # Suppress standard HTTP logging in test runs
        pass

    def do_POST(self) -> None:
        FakeUpstreamHandler.received_authorization = self.headers.get("Authorization")
        FakeUpstreamHandler.received_host = self.headers.get("Host")
        FakeUpstreamHandler.received_path = self.path

        length = int(self.headers.get("Content-Length", "0"))
        if length > 0:
            FakeUpstreamHandler.received_body = self.rfile.read(length)

        if self.path == "/v1/responses":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Upstream-Internal-ID", "secret-backend-123")  # Should be stripped
            self.end_headers()

            # Emit standard Responses SSE stream sequence
            sse_data = (
                b"event: response.created\r\ndata: {\"id\":\"resp_123\",\"status\":\"in_progress\"}\r\n\r\n"
                b"event: response.text.delta\r\ndata: {\"delta\":\"Hello from synthetic upstream\"}\r\n\r\n"
                b"event: response.completed\r\ndata: {\"status\":\"completed\"}\r\n\r\n"
            )
            self.wfile.write(sse_data)
            self.wfile.flush()
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://attacker.example/leak")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture
def fake_upstream() -> Generator[Tuple[str, int], None, None]:
    """Fixture running a local loopback fake upstream HTTP/SSE server."""
    FakeUpstreamHandler.received_authorization = None
    FakeUpstreamHandler.received_host = None
    FakeUpstreamHandler.received_path = None
    FakeUpstreamHandler.received_body = None

    server = socketserver.TCPServer(("127.0.0.1", 0), FakeUpstreamHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield host, port

    server.shutdown()
    server.server_close()


def _make_policy(upstream_port: int, **kwargs) -> ProviderBrokerPolicy:
    defaults = {
        "version": "AOSPROV/1",
        "task_id": "integration-task-1",
        "generation": 1,
        "attempt_id": 1,
        "launch_nonce": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "upstream_provider_id": "synthetic_openai",
        "upstream_scheme": "http",
        "upstream_host": "127.0.0.1",
        "upstream_port": upstream_port,
        "allowed_paths": ("/v1/responses", "/backend-api/codex/responses"),
        "protocol_type": "HTTP_SSE",
        "max_request_bytes": 10 * 1024 * 1024,
        "max_response_bytes": 50 * 1024 * 1024,
        "max_event_bytes": 1 * 1024 * 1024,
        "max_header_count": 32,
        "max_header_bytes": 8192,
        "max_connections": 1,
        "retry_budget": 0,
        "idle_timeout_seconds": 5.0,
        "total_lifetime_seconds": 10.0,
    }
    defaults.update(kwargs)
    return ProviderBrokerPolicy(**defaults)


def test_end_to_end_provider_broker_flow(fake_upstream: Tuple[str, int]) -> None:
    up_host, up_port = fake_upstream
    policy = _make_policy(up_port)
    auth = SyntheticBearerAuth(CANARY_TOKEN)

    broker = TaskProviderBroker(policy, auth)
    grant = broker.start()

    try:
        req_url = f"http://{grant.listener_address}:{grant.listener_port}/v1/responses"
        req_body = b'{"model":"synthetic-model","prompt":"hello"}'
        headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            "User-Agent": "codex_exec/0.120.0",
            "X-Codex-Turn-Metadata": '{"turn_id":"1"}',
        }

        req = urllib.request.Request(req_url, data=req_body, headers=headers, method="POST")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            content_type = resp.headers.get("Content-Type")
            assert "text/event-stream" in content_type
            assert resp.headers.get("X-Upstream-Internal-ID") is None  # Stripped!

            body = resp.read().decode("utf-8")
            assert "response.created" in body
            assert "Hello from synthetic upstream" in body
            assert "response.completed" in body

        # Verify upstream received authorization injection
        assert FakeUpstreamHandler.received_authorization == f"Bearer {CANARY_TOKEN}"
        assert FakeUpstreamHandler.received_host == f"127.0.0.1:{up_port}"
        assert FakeUpstreamHandler.received_path == "/v1/responses"

        # Verify evidence
        evidence = broker.get_evidence()
        assert evidence.request_byte_count > 0
        assert evidence.response_byte_count > 0
        assert evidence.response_event_count == 3
        assert evidence.upstream_status == 200
        assert evidence.terminal_failure_class is None
        assert evidence.cancellation_state is False
        assert evidence.canary_exposure_status == "CLEAN_NO_EXPOSURE"

    finally:
        broker.stop()


def test_secret_canary_isolation(fake_upstream: Tuple[str, int]) -> None:
    up_host, up_port = fake_upstream
    policy = _make_policy(up_port)
    auth = SyntheticBearerAuth(CANARY_TOKEN)

    broker = TaskProviderBroker(policy, auth)
    grant = broker.start()

    try:
        req_url = f"http://{grant.listener_address}:{grant.listener_port}/v1/responses"
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
        req = urllib.request.Request(req_url, data=b'{"prompt":"test"}', headers=headers, method="POST")

        with urllib.request.urlopen(req) as resp:
            resp_body = resp.read().decode("utf-8")

        evidence = broker.get_evidence()

        # Secret canary assertion: check all surfaces for canary string
        assert CANARY_TOKEN not in resp_body
        assert CANARY_TOKEN not in repr(evidence)
        assert CANARY_TOKEN not in str(evidence)
        assert CANARY_TOKEN not in repr(broker.policy)
        assert CANARY_TOKEN not in repr(broker.grant)
        assert CANARY_TOKEN not in repr(broker.identity)

    finally:
        broker.stop()


def test_adversarial_client_supplied_authorization(fake_upstream: Tuple[str, int]) -> None:
    up_host, up_port = fake_upstream
    policy = _make_policy(up_port)
    auth = SyntheticBearerAuth(CANARY_TOKEN)

    broker = TaskProviderBroker(policy, auth)
    grant = broker.start()

    try:
        req_url = f"http://{grant.listener_address}:{grant.listener_port}/v1/responses"
        # Client maliciously supplies Authorization header
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer ATTACKER_FORGED_TOKEN",
        }
        req = urllib.request.Request(req_url, data=b'{}', headers=headers, method="POST")

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)

        assert exc_info.value.code == 400
        # Upstream must NOT be contacted
        assert FakeUpstreamHandler.received_authorization is None

        evidence = broker.get_evidence()
        assert evidence.terminal_failure_class == ProviderFailureClass.PROVIDER_POLICY_REJECTED

    finally:
        broker.stop()


def test_adversarial_client_supplied_cookie(fake_upstream: Tuple[str, int]) -> None:
    up_host, up_port = fake_upstream
    policy = _make_policy(up_port)
    auth = SyntheticBearerAuth(CANARY_TOKEN)

    broker = TaskProviderBroker(policy, auth)
    grant = broker.start()

    try:
        req_url = f"http://{grant.listener_address}:{grant.listener_port}/v1/responses"
        headers = {"Content-Type": "application/json", "Cookie": "session=attacker_session_123"}
        req = urllib.request.Request(req_url, data=b'{}', headers=headers, method="POST")

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)

        assert exc_info.value.code == 400
        evidence = broker.get_evidence()
        assert evidence.terminal_failure_class == ProviderFailureClass.PROVIDER_POLICY_REJECTED

    finally:
        broker.stop()


def test_adversarial_destination_override_attempt(fake_upstream: Tuple[str, int]) -> None:
    up_host, up_port = fake_upstream
    policy = _make_policy(up_port)
    auth = SyntheticBearerAuth(CANARY_TOKEN)

    broker = TaskProviderBroker(policy, auth)
    grant = broker.start()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((grant.listener_address, grant.listener_port))

        # Client attempts absolute-form proxy request to external destination
        raw_req = b"POST http://attacker.example.com/v1/responses HTTP/1.1\r\nHost: attacker.example.com\r\nContent-Length: 0\r\n\r\n"
        sock.sendall(raw_req)

        resp = sock.recv(4096).decode("ascii", errors="replace")
        sock.close()

        assert "400 Bad Request" in resp or "400 Absolute Proxy URLs Disallowed" in resp
        assert FakeUpstreamHandler.received_authorization is None

        evidence = broker.get_evidence()
        assert evidence.terminal_failure_class == ProviderFailureClass.PROVIDER_POLICY_REJECTED

    finally:
        broker.stop()


def test_adversarial_unsupported_http_methods(fake_upstream: Tuple[str, int]) -> None:
    up_host, up_port = fake_upstream
    policy = _make_policy(up_port)
    auth = SyntheticBearerAuth(CANARY_TOKEN)

    broker = TaskProviderBroker(policy, auth)
    grant = broker.start()

    try:
        for method in ("GET", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE"):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((grant.listener_address, grant.listener_port))

            raw_req = f"{method} /v1/responses HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n".encode("utf-8")
            sock.sendall(raw_req)

            resp = sock.recv(4096).decode("ascii", errors="replace")
            sock.close()

            assert "405" in resp or "400" in resp

    finally:
        broker.stop()


def test_adversarial_websocket_upgrade_rejection(fake_upstream: Tuple[str, int]) -> None:
    up_host, up_port = fake_upstream
    policy = _make_policy(up_port)
    auth = SyntheticBearerAuth(CANARY_TOKEN)

    broker = TaskProviderBroker(policy, auth)
    grant = broker.start()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((grant.listener_address, grant.listener_port))

        raw_req = b"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: 0\r\n\r\n"
        sock.sendall(raw_req)

        resp = sock.recv(4096).decode("ascii", errors="replace")
        sock.close()

        assert "400 Bad Request" in resp or "WebSocket Upgrade Disallowed" in resp

    finally:
        broker.stop()


def test_adversarial_upstream_redirect_rejection(fake_upstream: Tuple[str, int]) -> None:
    up_host, up_port = fake_upstream
    policy = _make_policy(up_port, allowed_paths=("/v1/responses", "/redirect"))
    auth = SyntheticBearerAuth(CANARY_TOKEN)

    broker = TaskProviderBroker(policy, auth)
    grant = broker.start()

    try:
        req_url = f"http://{grant.listener_address}:{grant.listener_port}/redirect"
        req = urllib.request.Request(req_url, data=b'{}', method="POST")

        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)

        assert exc_info.value.code == 502
        evidence = broker.get_evidence()
        assert evidence.terminal_failure_class == ProviderFailureClass.PROVIDER_UPSTREAM_PROTOCOL_ERROR

    finally:
        broker.stop()


def test_cross_task_capability_isolation(fake_upstream: Tuple[str, int]) -> None:
    up_host, up_port = fake_upstream

    policy_a = _make_policy(up_port, task_id="task-A", launch_nonce="a" * 32)
    policy_b = _make_policy(up_port, task_id="task-B", launch_nonce="b" * 32)

    broker_a = TaskProviderBroker(policy_a, SyntheticBearerAuth("CANARY_A"))
    broker_b = TaskProviderBroker(policy_b, SyntheticBearerAuth("CANARY_B"))

    grant_a = broker_a.start()
    grant_b = broker_b.start()

    try:
        assert grant_a.listener_port != grant_b.listener_port
        assert grant_a.policy_digest != grant_b.policy_digest

        # Task A client reaches Task A broker successfully
        req_a = urllib.request.Request(
            f"http://{grant_a.listener_address}:{grant_a.listener_port}/v1/responses",
            data=b'{}',
            method="POST",
        )
        with urllib.request.urlopen(req_a) as resp_a:
            assert resp_a.status == 200

        # Revoke broker A
        broker_a.stop()

        # Task A client trying to reuse revoked broker A fails
        with pytest.raises(OSError):
            urllib.request.urlopen(req_a, timeout=1.0)

    finally:
        broker_a.stop()
        broker_b.stop()


def test_cancellation_drill(fake_upstream: Tuple[str, int]) -> None:
    up_host, up_port = fake_upstream
    policy = _make_policy(up_port)
    auth = SyntheticBearerAuth(CANARY_TOKEN)

    broker = TaskProviderBroker(policy, auth)
    grant = broker.start()

    # Cancel broker while running
    broker.stop()

    evidence = broker.get_evidence()
    assert evidence.cancellation_state is True
    assert evidence.terminal_failure_class == ProviderFailureClass.PROVIDER_CANCELLED


def test_broker_filesystem_negative_proof() -> None:
    policy = _make_policy(9000)
    auth = SyntheticBearerAuth(CANARY_TOKEN)
    broker = TaskProviderBroker(policy, auth)

    # Broker instance carries NO /workspace, NO git repo, NO file handles to sensitive files
    assert not hasattr(broker, "workspace")
    assert not hasattr(broker, "git")
    assert not hasattr(broker, "repo")

    evidence = broker.get_evidence()
    evidence_repr = repr(evidence)

    # Ensure no file path leak in evidence
    assert "/workspace" not in evidence_repr
    assert ".git" not in evidence_repr
