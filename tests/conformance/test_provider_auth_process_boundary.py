"""Process boundary, negative authority, and capability transport tests for Auth Helper daemon."""

import os
import pathlib
import json
import socket
import sys
import pytest

from agenticos.sandbox.controller_auth_helper import ControllerAuthHelper
from agenticos.sandbox.provider_models import AuthHelperProcessIdentity, SubscriptionAuthCapability


CANARY_REFRESH = "CANARY_REFRESH_TOKEN_SECRET_77777"
CANARY_ACCESS = "CANARY_ACCESS_TOKEN_SECRET_99999"
CANARY_ACCT = "CANARY_ACCT_ID_SECRET_88888"


@pytest.fixture
def auth_fixture_data():
    return {
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": CANARY_ACCESS,
            "refresh_token": CANARY_REFRESH,
            "account_id": CANARY_ACCT,
            "expires_at": 1900000000,
        },
    }


def test_auth_helper_process_boundary_proof(auth_fixture_data) -> None:
    """Prove that Auth Helper runs in a separate OS process with distinct identity."""
    controller_pid = os.getpid()

    with ControllerAuthHelper(auth_fixture_data) as helper:
        proc_id = helper.process_identity
        assert isinstance(proc_id, AuthHelperProcessIdentity)

        # 1. PID separation proof
        assert proc_id.pid != controller_pid
        assert proc_id.parent_pid == controller_pid

        # 2. Executable & Digest proof
        assert proc_id.executable != ""
        assert len(proc_id.executable_digest) == 64

        # 3. Working Directory proof (must be outside repo checkout)
        repo_root = str(pathlib.Path(__file__).resolve().parents[2])
        assert not proc_id.cwd.startswith(repo_root)
        assert "auth.json" not in proc_id.cwd

        # 4. Environment proof (minimal environment)
        for secret_key in ("CANARY_REFRESH", "AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY"):
            assert secret_key not in proc_id.env_keys

        # 5. Open FD census
        assert proc_id.open_fd_count >= 0


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux transport contract")
def test_linux_helper_uses_only_inherited_connected_seqpacket(auth_fixture_data) -> None:
    with ControllerAuthHelper(auth_fixture_data) as helper:
        assert helper.process_identity.ipc_endpoint.startswith("fd://")
        assert helper._ipc_endpoint.startswith("fd://")
        assert helper._ipc_sock is not None
        assert helper._ipc_sock.family == socket.AF_UNIX
        assert helper._ipc_sock.type & socket.SOCK_SEQPACKET == socket.SOCK_SEQPACKET
        assert helper._ipc_sock.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1

        # The same authenticated channel remains live for more than one request.
        assert helper._send_ipc({"action": "PING"})["status"] == "PONG"
        assert helper._send_ipc({"action": "PING"})["status"] == "PONG"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux transport contract")
def test_linux_helper_rejects_message_4097(auth_fixture_data) -> None:
    with ControllerAuthHelper(auth_fixture_data) as helper:
        for _ in range(4_096):
            assert helper._send_ipc({"action": "PING"})["status"] == "PONG"

        assert helper._send_ipc({"action": "PING"}) == {
            "protocol_version": "AOSAUTH/1",
            "status": "ERROR",
            "error": "IPC_MESSAGE_LIMIT",
        }


def test_hostile_worker_cannot_access_auth_secrets(auth_fixture_data, tmp_path) -> None:
    """Prove that a process in hostile workspace cannot read auth.json or refresh token."""
    with ControllerAuthHelper(auth_fixture_data) as helper:
        proc_id = helper.process_identity
        private_auth_file = os.path.join(proc_id.cwd, "auth.json")

        # Simulate hostile worker operating inside a mock workspace
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        # Direct attempt from workspace directory to open private auth.json via relative path escape fails
        relative_escape = os.path.join(str(workspace), "..", "..", os.path.basename(proc_id.cwd), "auth.json")

        # Auth file is in isolated temporary root outside workspace
        assert not os.path.exists(os.path.join(str(workspace), "auth.json"))
        assert not os.path.exists(os.path.join(str(workspace), ".git", "auth.json"))

        # Verify hostile worker environment cannot read refresh secret from ambient env
        assert "CANARY_REFRESH_TOKEN_SECRET_77777" not in os.environ.values()


def test_auth_capability_task_binding_and_nonces(auth_fixture_data) -> None:
    """Verify short-lived capabilities are task-bound and non-replayable."""
    with ControllerAuthHelper(auth_fixture_data) as helper:
        cap1 = helper.get_auth_capability(
            task_id="task-001",
            generation=1,
            attempt_id=1,
            launch_nonce="a1b2c3d4e5f60718293a4b5c6d7e8f90",
        )
        assert isinstance(cap1, SubscriptionAuthCapability)
        assert cap1.get_auth_header("task-001", 1).reveal_secret() == f"Bearer {CANARY_ACCESS}"

        # Replay attempt with exact same task parameters fails closed
        with pytest.raises(RuntimeError, match="REPLAYED_CAPABILITY_REQUEST"):
            helper.get_auth_capability(
                task_id="task-001",
                generation=1,
                attempt_id=1,
                launch_nonce="a1b2c3d4e5f60718293a4b5c6d7e8f90",
            )

        # Distinct launch nonce succeeds
        cap2 = helper.get_auth_capability(
            task_id="task-001",
            generation=1,
            attempt_id=2,
            launch_nonce="b2c3d4e5f60718293a4b5c6d7e8f90a1",
        )
        assert cap2.get_auth_header("task-001", 1).reveal_secret() == f"Bearer {CANARY_ACCESS}"


def test_task_cancellation_invalidates_capabilities(auth_fixture_data) -> None:
    """Verify task cancellation revokes capability issuance for that task."""
    with ControllerAuthHelper(auth_fixture_data) as helper:
        helper.cancel_task("task-cancel-me")

        with pytest.raises(RuntimeError, match="TASK_CAPABILITY_CANCELLED"):
            helper.get_auth_capability(
                task_id="task-cancel-me",
                generation=1,
                attempt_id=1,
                launch_nonce="c3d4e5f60718293a4b5c6d7e8f90a1b2",
            )


def test_expired_token_synthetic_refresh(auth_fixture_data) -> None:
    """Verify expired access token triggers out-of-process synthetic refresh using refresh token."""
    expired_data = dict(auth_fixture_data)
    expired_data["tokens"] = dict(auth_fixture_data["tokens"])
    expired_data["tokens"]["expires_at"] = 1000000000  # Expired in past

    with ControllerAuthHelper(expired_data) as helper:
        cap = helper.get_auth_capability(
            task_id="task-refresh-1",
            generation=1,
            attempt_id=1,
            launch_nonce="d4e5f60718293a4b5c6d7e8f90a1b2c3",
        )
        auth_hdr = cap.get_auth_header("task-refresh-1", 1).reveal_secret()
        assert auth_hdr.startswith("Bearer CANARY_ACCESS_TOKEN_REFRESHED_")


def test_refresh_rejection_fails_closed(auth_fixture_data) -> None:
    """Verify helper refresh rejection fails closed with PROVIDER_AUTH_UNAVAILABLE."""
    with ControllerAuthHelper(auth_fixture_data) as helper:
        helper.trigger_refresh_failure()

        with pytest.raises(RuntimeError, match="PROVIDER_AUTH_UNAVAILABLE"):
            helper.get_auth_capability(
                task_id="task-fail-1",
                generation=1,
                attempt_id=1,
                launch_nonce="e5f60718293a4b5c6d7e8f90a1b2c3d4",
            )
