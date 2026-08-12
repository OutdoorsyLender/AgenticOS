"""Integration and canary security test suite for ChatGPT subscription authentication flow."""

import http.server
import os
from pathlib import Path
import socketserver
import subprocess
import sys
import threading
import tomllib
import urllib.error
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
    request_count: int = 0

    def log_message(self, format: str, *args: object) -> None:
        pass

    def do_POST(self) -> None:
        FakeChatGPTUpstreamHandler.request_count += 1
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
    FakeChatGPTUpstreamHandler.request_count = 0

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


def _repository_change_surfaces(repo: Path) -> list[str]:
    def git_output(*args: str) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    surfaces = [
        git_output("status", "--short"),
        git_output("diff", "--unified=0"),
    ]
    for relative in git_output(
        "ls-files", "--others", "--exclude-standard"
    ).splitlines():
        candidate = repo / relative
        if candidate.is_file():
            surfaces.append(candidate.read_text(encoding="utf-8", errors="replace"))
    return surfaces


def test_repository_change_audit_reads_tracked_and_untracked_content(tmp_path: Path) -> None:
    repo = tmp_path / "audit-repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    tracked = repo / "tracked.txt"
    tracked.write_text("safe baseline", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
    tracked.write_text(CANARY_REFRESH, encoding="utf-8")
    (repo / "untracked.txt").write_text(CANARY_COOKIE, encoding="utf-8")

    surfaces = _repository_change_surfaces(repo)

    assert any(CANARY_REFRESH in surface for surface in surfaces)
    assert any(CANARY_COOKIE in surface for surface in surfaces)


def test_helper_ipc_error_record_is_content_free(
    capsys: pytest.CaptureFixture[str],
) -> None:
    auth_data = {
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": CANARY_ACCESS,
            "refresh_token": CANARY_REFRESH,
            "account_id": CANARY_ACCT,
            "cookie": CANARY_COOKIE,
        },
    }
    with ControllerAuthHelper(auth_data) as auth_helper:
        auth_helper.trigger_refresh_failure()
        with pytest.raises(RuntimeError) as failure:
            auth_helper.get_auth_capability("ipc-error-task", 1)

        captured = capsys.readouterr()
        error_surfaces = (str(failure.value), captured.out, captured.err)
        assert "PROVIDER_AUTH_UNAVAILABLE" in str(failure.value)
        assert all(
            canary not in surface
            for canary in (CANARY_REFRESH, CANARY_ACCESS, CANARY_ACCT, CANARY_COOKIE)
            for surface in error_surfaces
        )


def test_chatgpt_subscription_auth_injection_flow(
    fake_chatgpt_upstream: Tuple[str, int],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    up_host, up_port = fake_chatgpt_upstream
    policy = _make_policy(up_port)

    codex_home = tmp_path / "codex-home"
    workspace = tmp_path / "workspace"
    codex_home.mkdir()
    workspace.mkdir()
    config_path = codex_home / "config.toml"
    config_path.write_text(
        "[model_providers.agenticos]\n"
        "name = \"AgenticOS\"\n"
        "base_url = \"http://127.0.0.1:18081/v1\"\n"
        "wire_api = \"responses\"\n"
        "requires_openai_auth = false\n"
        "supports_websockets = false\n",
        encoding="utf-8",
    )
    provider_config = tomllib.loads(config_path.read_text(encoding="utf-8"))[
        "model_providers"
    ]["agenticos"]
    assert provider_config["requires_openai_auth"] is False
    assert provider_config["supports_websockets"] is False
    monkeypatch.setenv("OPENAI_API_KEY", "AMBIENT_AUTH_MUST_NOT_BE_USED")

    # Controller Auth Helper holding synthetic tokens out-of-process
    auth_data = {
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": CANARY_ACCESS,
            "refresh_token": CANARY_REFRESH,
            "account_id": CANARY_ACCT,
            "cookie": CANARY_COOKIE,
        },
    }

    with ControllerAuthHelper(auth_data) as auth_helper:
        auth_cap = auth_helper.get_auth_capability(
            policy.task_id,
            policy.generation,
            policy.attempt_id,
            policy.launch_nonce,
            upstream_scheme=policy.upstream_scheme,
            upstream_host=policy.upstream_host,
            upstream_port=policy.upstream_port,
            provider_purpose="responses_sse",
        )

        broker = TaskProviderBroker(policy, auth_cap)
        grant = broker.start()
        auth_helper.register_broker(broker)
        replacement = auth_helper.replace_broker_auth_capability(broker)
        assert replacement.binding.capability_sequence == 2

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
            assert FakeChatGPTUpstreamHandler.request_count == 1

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

            runtime_surfaces = [
                " ".join(sys.argv),
                str(dict(os.environ)),
                resp_body,
                repr(broker.get_evidence()),
                repr(broker.grant),
                repr(broker.identity),
                repr(auth_cap),
                repr(replacement),
                repr(auth_helper),
                repr(auth_helper.process_identity),
                repr(auth_helper._launch_argv),
            ]
            if sys.platform.startswith("linux"):
                helper_proc = Path("/proc") / str(auth_helper.process_identity.pid)

                def read_proc_metadata(path: Path) -> str:
                    try:
                        return path.read_bytes().decode("utf-8", errors="replace")
                    except PermissionError:
                        return "DENIED:PermissionError"

                def list_proc_fds(path: Path) -> str:
                    try:
                        return repr(sorted(entry.name for entry in path.iterdir()))
                    except PermissionError:
                        return "DENIED:PermissionError"

                runtime_surfaces.extend(
                    [
                        read_proc_metadata(helper_proc / "cmdline"),
                        read_proc_metadata(helper_proc / "environ"),
                        list_proc_fds(helper_proc / "fd"),
                    ]
                )

            auth_private_root = Path(auth_helper._private_root)
            auth_helper.stop()
            assert not auth_private_root.exists()

            FakeChatGPTUpstreamHandler.received_authorization = None
            FakeChatGPTUpstreamHandler.received_account_id = None
            with pytest.raises(urllib.error.HTTPError) as failure:
                urllib.request.urlopen(req)
            assert failure.value.code == 500
            assert FakeChatGPTUpstreamHandler.received_authorization is None
            assert FakeChatGPTUpstreamHandler.received_account_id is None
            assert FakeChatGPTUpstreamHandler.request_count == 1
            runtime_surfaces.append(str(failure.value))

            runtime_surfaces.extend(
                path.read_text(encoding="utf-8", errors="replace")
                for root in (codex_home, workspace)
                for path in root.rglob("*")
                if path.is_file()
            )
            runtime_surfaces.extend(
                _repository_change_surfaces(Path(__file__).resolve().parents[2])
            )
            captured = capsys.readouterr()
            runtime_surfaces.extend((captured.out, captured.err))
            assert all(
                canary not in surface
                for canary in (CANARY_REFRESH, CANARY_ACCESS, CANARY_ACCT, CANARY_COOKIE)
                for surface in runtime_surfaces
            )
            assert not list(tmp_path.rglob("core*"))

        finally:
            broker.stop()
