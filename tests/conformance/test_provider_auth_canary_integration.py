"""Integration and canary security test suite for ChatGPT subscription authentication flow."""

import http.server
import os
import socketserver
import sys
import threading
import urllib.request
import pytest
from typing import Generator, Tuple

from agenticos.sandbox.controller_auth_helper import ControllerAuthHelper
from agenticos.sandbox.provider_broker import TaskProviderBroker
from agenticos.sandbox.provider_models import ProviderBrokerPolicy, ProviderFailureClass

CANARY_REFRESH = "CANARY_REFRESH_TOKEN_SECRET_77777"
CANARY_ACCESS = "CANARY_ACCESS_TOKEN_SECRET_99999"
CANARY_ACCT = "CANARY_ACCT_ID_SECRET_88888"
CANARY_COOKIE = "CANARY_COOKIE_SECRET_66666"


class FakeChatGPTUpstreamHandler(http.server.BaseHTTPRequestHandler):
    """Fake ChatGPT upstream endpoint verifying bearer access token and account ID headers."""

    received_authorization: str | None = None
    received_account_id: str | None = None
    received_path: str | None = None

    def log_message(self, format: str, *args: object) -> None:
        pass

    def do_POST(self) -> None:
        FakeChatGPTUpstreamHandler.received_authorization = self.headers.get("Authorization")
        FakeChatGPTUpstreamHandler.received_account_id = self.headers.get("ChatGPT-Account-ID")
        FakeChatGPTUpstreamHandler.received_path = self.path

        if self.path == "/backend-api/codex/responses":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()

            sse_data = (
                b"event: response.created\r\ndata: {\"id\":\"resp_chatgpt_123\"}\r\n\r\n"
                b"event: response.completed\r\ndata: {\"status\":\"completed\"}\r\n\r\n"
            )
            self.wfile.write(sse_data)
            self.wfile.flush()
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture
def fake_chatgpt_upstream() -> Generator[Tuple[str, int], None, None]:
    FakeChatGPTUpstreamHandler.received_authorization = None
    FakeChatGPTUpstreamHandler.received_account_id = None
    FakeChatGPTUpstreamHandler.received_path = None

    server = socketserver.TCPServer(("127.0.0.1", 0), FakeChatGPTUpstreamHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield host, port

    server.shutdown()
    server.server_close()


def _make_policy(upstream_port: int) -> ProviderBrokerPolicy:
    return ProviderBrokerPolicy(
        version="AOSPROV/1",
        task_id="chatgpt-auth-task-1",
        generation=1,
        attempt_id=1,
        launch_nonce="a1b2c3d4e5f60718293a4b5c6d7e8f90",
        upstream_provider_id="chatgpt_subscription",
        upstream_scheme="http",
        upstream_host="127.0.0.1",
        upstream_port=upstream_port,
        allowed_paths=("/backend-api/codex/responses",),
        protocol_type="HTTP_SSE",
        max_request_bytes=10 * 1024 * 1024,
        max_response_bytes=50 * 1024 * 1024,
        max_event_bytes=1 * 1024 * 1024,
        max_header_count=32,
        max_header_bytes=8192,
        max_connections=1,
        retry_budget=0,
        idle_timeout_seconds=5.0,
        total_lifetime_seconds=10.0,
    )


def test_chatgpt_subscription_auth_injection_flow(fake_chatgpt_upstream: Tuple[str, int]) -> None:
    up_host, up_port = fake_chatgpt_upstream
    policy = _make_policy(up_port)

    # Controller Auth Helper holding synthetic tokens out-of-process
    auth_data = {
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": CANARY_ACCESS,
            "refresh_token": CANARY_REFRESH,
            "account_id": CANARY_ACCT,
        },
    }

    with ControllerAuthHelper(auth_data) as auth_helper:
        auth_cap = auth_helper.get_auth_capability(
            policy.task_id,
            policy.generation,
            policy.attempt_id,
            policy.launch_nonce,
        )

        broker = TaskProviderBroker(policy, auth_cap)
        grant = broker.start()

        try:
            req_url = f"http://{grant.listener_address}:{grant.listener_port}/backend-api/codex/responses"
            headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}

            req = urllib.request.Request(req_url, data=b'{"prompt":"test"}', headers=headers, method="POST")
            with urllib.request.urlopen(req) as resp:
                assert resp.status == 200
                resp_body = resp.read().decode("utf-8")

            # Verify upstream received access token and account ID
            assert FakeChatGPTUpstreamHandler.received_authorization == f"Bearer {CANARY_ACCESS}"
            assert FakeChatGPTUpstreamHandler.received_account_id == CANARY_ACCT
            assert FakeChatGPTUpstreamHandler.received_path == "/backend-api/codex/responses"

            # Expanded Canary Isolation Assertions
            for canary in (CANARY_REFRESH, CANARY_ACCESS, CANARY_ACCT, CANARY_COOKIE):
                assert canary not in resp_body
                assert canary not in repr(broker.get_evidence())
                assert canary not in repr(broker.grant)
                assert canary not in repr(broker.identity)

            # Explicit invariant: refresh secret visible count outside auth helper process domain
            refresh_secret_visible_outside_auth_helper = 0
            for surface in (
                " ".join(sys.argv),
                str(dict(os.environ)),
                resp_body,
                repr(broker.get_evidence()),
                repr(broker.grant),
                repr(broker.identity),
                repr(auth_helper.process_identity),
            ):
                if CANARY_REFRESH in surface:
                    refresh_secret_visible_outside_auth_helper += 1

            assert refresh_secret_visible_outside_auth_helper == 0

        finally:
            broker.stop()
