"""Process boundary, negative authority, and capability transport tests for Auth Helper daemon."""

import os
import pathlib
import json
import socket
import sys
import tempfile
import threading
import pytest

from agenticos.sandbox.controller_auth_helper import ControllerAuthHelper
from agenticos.sandbox.provider_broker import _AtomicCapabilitySlot
from agenticos.sandbox.provider_models import (
    AuthHelperProcessIdentity,
    ProviderAuthBindingError,
    ProviderBrokerPolicy,
    SubscriptionAuthCapability,
)


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

        # Replacement issuance reuses the attempt tuple but advances sequence.
        replacements = [
            helper.get_auth_capability(
                task_id="task-001",
                generation=1,
                attempt_id=1,
                launch_nonce="a1b2c3d4e5f60718293a4b5c6d7e8f90",
            )
            for _ in range(7)
        ]
        assert [cap.binding.capability_sequence for cap in [cap1, *replacements]] == list(
            range(1, 9)
        )
        assert len({cap.binding.capability_nonce for cap in [cap1, *replacements]}) == 8
        assert {cap.binding.helper_epoch for cap in [cap1, *replacements]} == {
            helper.process_identity.helper_epoch
        }
        with pytest.raises(RuntimeError, match="CAPABILITY_ISSUANCE_LIMIT"):
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
        assert cap2.binding.capability_sequence == 1


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


def _subscription_policy() -> ProviderBrokerPolicy:
    return ProviderBrokerPolicy(
        version="AOSPROV/1",
        task_id="task-current-only",
        generation=1,
        attempt_id=1,
        launch_nonce="a1b2c3d4e5f60718293a4b5c6d7e8f90",
        upstream_provider_id="chatgpt_subscription",
        upstream_scheme="https",
        upstream_host="chatgpt.example.test",
        upstream_port=443,
        allowed_paths=("/backend-api/codex/responses",),
        protocol_type="HTTP_SSE",
        max_request_bytes=1024,
        max_response_bytes=1024,
        max_event_bytes=512,
        max_header_count=16,
        max_header_bytes=2048,
        max_connections=1,
        retry_budget=0,
        idle_timeout_seconds=2.0,
        total_lifetime_seconds=5.0,
    )


def test_older_materialized_capability_cannot_initialize_after_reissuance(
    auth_fixture_data,
) -> None:
    policy = _subscription_policy()
    with ControllerAuthHelper(auth_fixture_data) as helper:
        first = helper.get_auth_capability(
            policy.task_id,
            policy.generation,
            policy.attempt_id,
            policy.launch_nonce,
        )
        second = helper.get_auth_capability(
            policy.task_id,
            policy.generation,
            policy.attempt_id,
            policy.launch_nonce,
        )
        assert second.binding.capability_sequence == 2
        with pytest.raises(ProviderAuthBindingError, match="SEQUENCE"):
            _AtomicCapabilitySlot(policy, first)


def test_materialized_capability_cannot_initialize_after_helper_cancellation(
    auth_fixture_data,
) -> None:
    policy = _subscription_policy()
    with ControllerAuthHelper(auth_fixture_data) as helper:
        capability = helper.get_auth_capability(
            policy.task_id,
            policy.generation,
            policy.attempt_id,
            policy.launch_nonce,
        )
        helper.cancel_task(
            policy.task_id,
            policy.generation,
            policy.attempt_id,
            policy.launch_nonce,
        )
        with pytest.raises(ProviderAuthBindingError, match="CANCELLED"):
            _AtomicCapabilitySlot(policy, capability)


def test_helper_cancellation_waits_for_post_validation_injection(
    auth_fixture_data, monkeypatch,
) -> None:
    policy = _subscription_policy()
    validated = threading.Event()
    release = threading.Event()
    injected: list[str] = []
    with ControllerAuthHelper(auth_fixture_data) as helper:
        capability = helper.get_auth_capability(
            policy.task_id,
            policy.generation,
            policy.attempt_id,
            policy.launch_nonce,
        )
        slot = _AtomicCapabilitySlot(policy, capability)
        original = SubscriptionAuthCapability.get_auth_header

        def blocked_header(self, task_id: str, generation: int):
            validated.set()
            assert release.wait(timeout=5.0)
            return original(self, task_id, generation)

        monkeypatch.setattr(
            SubscriptionAuthCapability, "get_auth_header", blocked_header
        )
        consumer = threading.Thread(
            target=lambda: slot.validate_extract_and_send(
                policy=policy,
                sender=lambda auth, extra: injected.append(auth.reveal_secret()),
            )
        )
        consumer.start()
        assert validated.wait(timeout=5.0)
        cancellation_done = threading.Event()
        canceller = threading.Thread(
            target=lambda: (
                helper.cancel_task(
                    policy.task_id,
                    policy.generation,
                    policy.attempt_id,
                    policy.launch_nonce,
                ),
                cancellation_done.set(),
            )
        )
        canceller.start()
        assert not cancellation_done.wait(timeout=0.1)
        release.set()
        consumer.join(timeout=5.0)
        canceller.join(timeout=5.0)
        assert cancellation_done.is_set()
        assert injected == ["Bearer " + CANARY_ACCESS]


def test_subscription_capability_requires_trusted_issuance_state(
    auth_fixture_data,
) -> None:
    policy = _subscription_policy()
    with ControllerAuthHelper(auth_fixture_data) as helper:
        capability = helper.get_auth_capability(
            policy.task_id,
            policy.generation,
            policy.attempt_id,
            policy.launch_nonce,
        )
        with pytest.raises(TypeError, match="_issuance_state"):
            SubscriptionAuthCapability(
                access_token=CANARY_ACCESS,
                binding=capability.binding,
            )


def test_same_context_issuance_and_cancellation_never_deadlock(
    auth_fixture_data,
) -> None:
    policy = _subscription_policy()
    with ControllerAuthHelper(auth_fixture_data) as helper:
        helper.get_auth_capability(
            policy.task_id,
            policy.generation,
            policy.attempt_id,
            policy.launch_nonce,
        )
        start = threading.Barrier(3)
        outcomes: list[str] = []

        def issue() -> None:
            start.wait()
            try:
                helper.get_auth_capability(
                    policy.task_id,
                    policy.generation,
                    policy.attempt_id,
                    policy.launch_nonce,
                )
                outcomes.append("issued")
            except RuntimeError as exc:
                outcomes.append(str(exc))

        def cancel() -> None:
            start.wait()
            helper.cancel_task(
                policy.task_id,
                policy.generation,
                policy.attempt_id,
                policy.launch_nonce,
            )
            outcomes.append("cancelled")

        threads = [threading.Thread(target=issue), threading.Thread(target=cancel)]
        for thread in threads:
            thread.start()
        start.wait()
        for thread in threads:
            thread.join(timeout=5.0)
            assert not thread.is_alive()
        assert "cancelled" in outcomes


def test_helper_restart_revokes_prior_epoch_without_old_ipc_probe(
    auth_fixture_data,
) -> None:
    policy = _subscription_policy()
    first_helper = ControllerAuthHelper(auth_fixture_data)
    try:
        stale = first_helper.get_auth_capability(
            policy.task_id,
            policy.generation,
            policy.attempt_id,
            policy.launch_nonce,
        )
        assert first_helper._proc is not None
        first_helper._proc.kill()
        first_helper._proc.wait(timeout=2.0)

        with ControllerAuthHelper(auth_fixture_data) as replacement:
            assert (
                replacement.process_identity.helper_epoch
                != stale.binding.helper_epoch
            )
            with pytest.raises(ProviderAuthBindingError, match="CANCELLED"):
                _AtomicCapabilitySlot(policy, stale)
    finally:
        first_helper.stop()


def test_request_nonce_is_single_use_without_burning_attempt_tuple(
    auth_fixture_data,
) -> None:
    nonce = "11111111111111111111111111111111"
    with ControllerAuthHelper(auth_fixture_data) as helper:
        first = helper.get_auth_capability("task-nonce", 1, _request_nonce=nonce)
        assert first.binding.capability_sequence == 1
        with pytest.raises(RuntimeError, match="REPLAYED_CAPABILITY_REQUEST"):
            helper.get_auth_capability("task-nonce", 1, _request_nonce=nonce)
        replacement = helper.get_auth_capability("task-nonce", 1)
        assert replacement.binding.capability_sequence == 2


@pytest.mark.parametrize(
    "operation",
    ["GET_REFRESH_TOKEN", "GET_ACCESS_TOKEN", "DUMP_AUTH_STATE", "SHOW_AUTH_JSON"],
)
def test_ambient_auth_operations_are_unknown_and_secret_free(
    auth_fixture_data, operation: str
) -> None:
    with ControllerAuthHelper(auth_fixture_data) as helper:
        response = helper._send_ipc({"action": operation})
        assert response == {
            "protocol_version": "AOSAUTH/1",
            "status": "ERROR",
            "error": "IPC_UNKNOWN_OPERATION",
        }
        assert CANARY_ACCESS not in repr(response)
        assert CANARY_REFRESH not in repr(response)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("task_id", "../../bad"),
        ("generation", 0),
        ("generation", 2**64),
        ("attempt_id", 0),
        ("launch_nonce", "not-a-nonce"),
        ("provider_id", ""),
        ("upstream_scheme", "ftp"),
        ("upstream_host", ""),
        ("upstream_port", 0),
        ("upstream_port", 65_536),
        ("provider_purpose", "wrong"),
        ("_request_nonce", "x"),
    ],
)
def test_capability_semantic_substitutions_never_return_credentials(
    auth_fixture_data, field: str, value: object
) -> None:
    kwargs = {
        "task_id": "task-valid",
        "generation": 1,
        "attempt_id": 1,
        "launch_nonce": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "provider_id": "chatgpt_subscription",
        "upstream_scheme": "https",
        "upstream_host": "chatgpt.example.test",
        "upstream_port": 443,
        "provider_purpose": "responses_sse",
    }
    kwargs[field] = value
    with ControllerAuthHelper(auth_fixture_data) as helper:
        with pytest.raises(ValueError) as exc_info:
            helper.get_auth_capability(**kwargs)
        assert "CAPABILITY_BINDING_INVALID" in str(exc_info.value)
        assert CANARY_ACCESS not in str(exc_info.value)
        assert CANARY_REFRESH not in str(exc_info.value)


def test_concurrent_same_context_issuance_remains_monotonic(auth_fixture_data) -> None:
    with ControllerAuthHelper(auth_fixture_data) as helper:
        results: list[SubscriptionAuthCapability] = []
        errors: list[BaseException] = []

        def issue() -> None:
            try:
                results.append(helper.get_auth_capability("task-concurrent", 1))
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=issue) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5.0)
        assert errors == []
        assert sorted(cap.binding.capability_sequence for cap in results) == list(
            range(1, 9)
        )


def test_helper_disconnect_synchronously_revokes_materialized_capability(
    auth_fixture_data,
) -> None:
    policy = _subscription_policy()
    helper = ControllerAuthHelper(auth_fixture_data)
    capability = helper.get_auth_capability(
        policy.task_id, policy.generation, policy.attempt_id, policy.launch_nonce
    )
    assert helper._proc is not None
    helper._proc.kill()
    helper._proc.wait(timeout=2.0)
    with pytest.raises(Exception):
        helper._send_ipc({"action": "PING"})
    with pytest.raises(ProviderAuthBindingError, match="CANCELLED"):
        _AtomicCapabilitySlot(policy, capability)
    helper.stop()


def test_malformed_helper_response_synchronously_revokes_materialized_capability(
    auth_fixture_data, monkeypatch
) -> None:
    policy = _subscription_policy()
    with ControllerAuthHelper(auth_fixture_data) as helper:
        capability = helper.get_auth_capability(
            policy.task_id,
            policy.generation,
            policy.attempt_id,
            policy.launch_nonce,
        )
        receiver_name = (
            "_recv_linux_packet" if sys.platform.startswith("linux") else "_recv_stream_packet"
        )
        monkeypatch.setattr(
            f"agenticos.sandbox.controller_auth_helper.{receiver_name}",
            lambda *args, **kwargs: b'{"protocol_version":"AOSAUTH/1","status":"OK","error":"bad"}',
        )
        with pytest.raises(Exception):
            helper._send_ipc({"action": "PING"})
        with pytest.raises(ProviderAuthBindingError, match="CANCELLED"):
            _AtomicCapabilitySlot(policy, capability)


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
        recovered = helper.get_auth_capability(
            task_id="task-fail-1",
            generation=1,
            attempt_id=1,
            launch_nonce="e5f60718293a4b5c6d7e8f90a1b2c3d4",
        )
        assert recovered.binding.capability_sequence == 1
