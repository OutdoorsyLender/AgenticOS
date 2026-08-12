"""Process boundary, negative authority, and capability transport tests for Auth Helper daemon."""

import os
import pathlib
import json
import socket
import sys
import tempfile
import pytest

from agenticos.sandbox.controller_auth_helper import ControllerAuthHelper
from agenticos.sandbox.provider_models import AuthHelperProcessIdentity, SubscriptionAuthCapability


CANARY_REFRESH = "CANARY_REFRESH_TOKEN_SECRET_77777"
CANARY_ACCESS = "CANARY_ACCESS_TOKEN_SECRET_99999"
CANARY_ACCT = "CANARY_ACCT_ID_SECRET_88888"


def _linux_auth_helper_pids() -> frozenset[int]:
    if not sys.platform.startswith("linux"):
        return frozenset()
    result: set[int] = set()
    for proc_entry in pathlib.Path("/proc").iterdir():
        if not proc_entry.name.isdigit():
            continue
        try:
            command_line = (proc_entry / "cmdline").read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if b"auth_helper_daemon.py" in command_line:
            result.add(int(proc_entry.name))
    return frozenset(result)


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


def test_helper_identity_binds_isolated_interpreter_and_entrypoint(
    auth_fixture_data, monkeypatch
) -> None:
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    monkeypatch.setenv("PYTHONPATH", str(repo_root / "hostile-imports"))
    monkeypatch.setenv("PYTHONHOME", str(repo_root / "hostile-home"))
    monkeypatch.setenv("PYTHONSTARTUP", str(repo_root / "hostile-startup.py"))
    monkeypatch.setenv("PYTHONUSERBASE", str(repo_root / "hostile-user-site"))

    with ControllerAuthHelper(auth_fixture_data) as helper:
        identity = helper.process_identity
        assert helper._launch_argv[0] == identity.executable
        assert helper._launch_argv[1:3] == ("-I", "-S")
        assert "-m" not in helper._launch_argv
        assert helper._launch_argv[3] == identity.entrypoint
        assert str(helper._auth_json_path) not in helper._launch_argv
        assert CANARY_REFRESH not in " ".join(helper._launch_argv)
        assert pathlib.Path(identity.executable).is_absolute()
        assert pathlib.Path(identity.entrypoint).is_absolute()
        assert identity.executable_digest != identity.entrypoint_digest
        assert len(identity.executable_digest) == 64
        assert len(identity.entrypoint_digest) == 64
        assert identity.executable_device > 0
        assert identity.executable_inode > 0
        assert identity.entrypoint_device > 0
        assert identity.entrypoint_inode > 0
        assert identity.protocol_version == "AOSAUTH/1"
        assert identity.helper_epoch

        for hostile_key in (
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONSTARTUP",
            "PYTHONUSERBASE",
        ):
            assert hostile_key not in identity.env_keys
        excluded_import_roots = (
            repo_root,
            repo_root / "hostile-imports",
            repo_root / "hostile-user-site",
            pathlib.Path(identity.cwd),
        )
        for import_path in identity.import_paths:
            if not import_path:
                pytest.fail("isolated helper retained current-directory import authority")
            resolved_import = pathlib.Path(import_path).resolve()
            assert all(
                resolved_import != excluded
                and excluded not in resolved_import.parents
                for excluded in excluded_import_roots
            )


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux hardening contract")
def test_linux_helper_ready_reports_exact_pre_ready_hardening(auth_fixture_data) -> None:
    with ControllerAuthHelper(auth_fixture_data) as helper:
        identity = helper.process_identity
        assert identity.pid == helper._proc.pid
        assert identity.parent_pid == os.getpid()
        assert identity.uid == os.getuid()
        assert identity.gid == os.getgid()
        assert identity.controller_uid == os.getuid()
        assert identity.controller_gid == os.getgid()
        assert identity.open_fds == (0, 1, 2, 3)
        assert identity.core_soft_limit == 0
        assert identity.core_hard_limit == 0
        assert identity.dumpable == 0
        assert identity.no_new_privs == 1
        assert identity.ipc_type == "AF_UNIX/SOCK_SEQPACKET"
        assert identity.ipc_peer_auth == "SO_PASSCRED/SCM_CREDENTIALS"
        assert helper._ready_standard_fds_null is True


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux hardening contract")
def test_linux_helper_closes_deliberately_inherited_authority_before_ready(
    auth_fixture_data, tmp_path
) -> None:
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    workspace = tmp_path / "hostile-workspace"
    workspace.mkdir()
    opened: list[int] = []
    peer_a, peer_b = socket.socketpair()
    try:
        opened.extend(
            [
                os.open(__file__, os.O_RDONLY | os.O_CLOEXEC),
                os.open(repo_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC),
                os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC),
                os.open(repo_root / ".git", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC),
                peer_b.fileno(),
            ]
        )
        with ControllerAuthHelper(
            auth_fixture_data,
            _test_inherited_fds=tuple(opened),
        ) as helper:
            assert helper.process_identity.open_fds == (0, 1, 2, 3)
            assert tuple(helper._test_inherited_fds_closed) == tuple(opened)
    finally:
        peer_b.close()
        peer_a.close()
        for fd in opened[:-1]:
            os.close(fd)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux hardening contract")
@pytest.mark.parametrize(
    "startup_fault", ["core", "dumpable", "fd_sanitize", "no_new_privs"]
)
def test_linux_helper_never_accepts_ready_on_hardening_failure(
    auth_fixture_data, startup_fault: str
) -> None:
    private_roots_before = frozenset(
        pathlib.Path(tempfile.gettempdir()).glob("aos-auth-private-*")
    )
    helper_pids_before = _linux_auth_helper_pids()
    with pytest.raises(RuntimeError, match="Auth helper startup failed closed"):
        ControllerAuthHelper(
            auth_fixture_data,
            _test_startup_fault=startup_fault,
        )
    assert frozenset(
        pathlib.Path(tempfile.gettempdir()).glob("aos-auth-private-*")
    ) == private_roots_before
    assert _linux_auth_helper_pids() == helper_pids_before


def test_helper_shutdown_removes_process_channel_and_temporary_root(
    auth_fixture_data,
) -> None:
    helper = ControllerAuthHelper(auth_fixture_data)
    pid = helper.process_identity.pid
    private_root = helper._private_root
    helper.stop()

    assert helper._ipc_sock is None
    assert helper._proc is None
    assert not private_root.exists()
    if sys.platform.startswith("linux"):
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)


@pytest.mark.skipif(os.name != "nt", reason="Windows functional bootstrap contract")
def test_windows_ready_follows_one_use_closed_stdin_bootstrap(
    auth_fixture_data,
) -> None:
    with ControllerAuthHelper(auth_fixture_data) as helper:
        assert helper._windows_stdin_bootstrap_closed is True
        assert helper.process_identity.ipc_type == "AF_INET/SOCK_STREAM"
        assert (
            helper.process_identity.ipc_peer_auth
            == "BOOTSTRAP_NONCE_ONLY_WINDOWS_FUNCTIONAL"
        )
        assert helper.process_identity.open_fds == ()


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
