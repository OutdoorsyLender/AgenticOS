"""Unit test suite for out-of-process controller auth helper and subscription auth capability."""

from dataclasses import replace
import array
import errno
import io
import json
import os
import socket
import struct
import sys
import threading
import time

import pytest

if sys.platform.startswith("linux"):
    import fcntl
else:  # pragma: no cover - Linux-only test helper
    fcntl = None  # type: ignore[assignment]

from agenticos.sandbox.auth_helper_daemon import (
    IPC_MAX_REQUEST_BYTES,
    IPC_MAX_RESPONSE_BYTES,
    IPC_PROTOCOL_VERSION,
    AuthProtocolError,
    _encode_packet,
    _read_windows_bootstrap,
    _recv_linux_packet,
    _recv_stream_packet,
    _send_linux_packet,
    _send_stream_packet,
    _strict_json_loads,
)
from agenticos.sandbox.controller_auth_helper import ControllerAuthHelper
from agenticos.sandbox.provider_models import (
    ProviderAuthBinding,
    ProviderAuthBindingError,
    ProviderBrokerPolicy,
    SecretValue,
    SubscriptionAuthCapability,
)


_CODEC_REQUIRED = frozenset({"protocol_version", "action"})
_CODEC_TYPES = {"protocol_version": str, "action": str}


def _decode_test_packet(payload: bytes) -> dict[str, object]:
    return _strict_json_loads(
        payload,
        required_fields=_CODEC_REQUIRED,
        optional_fields=frozenset(),
        field_types=_CODEC_TYPES,
    )


def test_ipc_codec_accepts_only_the_exact_bounded_schema() -> None:
    assert IPC_PROTOCOL_VERSION == "AOSAUTH/1"
    assert IPC_MAX_REQUEST_BYTES == 16_384
    assert IPC_MAX_RESPONSE_BYTES == 16_384
    assert _decode_test_packet(
        b'{"action":"PING","protocol_version":"AOSAUTH/1"}'
    ) == {"action": "PING", "protocol_version": "AOSAUTH/1"}
    assert _encode_packet(
        {"status": "PONG", "protocol_version": IPC_PROTOCOL_VERSION}
    ) == b'{"protocol_version":"AOSAUTH/1","status":"PONG"}'


@pytest.mark.parametrize(
    ("payload", "error_code"),
    [
        (b"", "IPC_EMPTY"),
        (b"x" * 16_385, "IPC_OVERSIZED"),
        (b"\xff", "IPC_BAD_ENCODING"),
        (b"{", "IPC_BAD_JSON"),
        (b"[]", "IPC_NOT_OBJECT"),
        (
            b'{"action":"PING","action":"SHUTDOWN","protocol_version":"AOSAUTH/1"}',
            "IPC_DUPLICATE_FIELD",
        ),
        (b'{"protocol_version":"AOSAUTH/1"}', "IPC_MISSING_FIELD"),
        (
            b'{"action":"PING","extra":1,"protocol_version":"AOSAUTH/1"}',
            "IPC_UNKNOWN_FIELD",
        ),
        (b'{"action":7,"protocol_version":"AOSAUTH/1"}', "IPC_FIELD_TYPE"),
        (b'{"action":"PING","protocol_version":"AOSAUTH/2"}', "IPC_VERSION"),
    ],
)
def test_ipc_codec_rejects_malformed_input_without_echo(
    payload: bytes, error_code: str
) -> None:
    with pytest.raises(AuthProtocolError) as exc_info:
        _decode_test_packet(payload)

    assert str(exc_info.value) == error_code
    assert repr(payload[:64]) not in str(exc_info.value)


def test_ipc_codec_rejects_oversized_encoded_response() -> None:
    with pytest.raises(AuthProtocolError, match="^IPC_RESPONSE_OVERSIZED$"):
        _encode_packet({"status": "X" * 16_385})


def _open_linux_fds() -> frozenset[int]:
    assert fcntl is not None
    result: set[int] = set()
    for candidate in range(0, 4_096):
        try:
            fcntl.fcntl(candidate, fcntl.F_GETFD)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            result.add(candidate)
    return frozenset(result)


class _SyntheticRecvmsgSocket:
    def __init__(
        self,
        payload: bytes,
        ancillary: list[tuple[int, int, bytes]],
        flags: int,
    ) -> None:
        self.payload = payload
        self.ancillary = ancillary
        self.flags = flags

    def settimeout(self, timeout: float) -> None:
        assert timeout == 2.0

    def recvmsg(
        self, data_size: int, ancillary_size: int
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, None]:
        assert data_size == IPC_MAX_REQUEST_BYTES + 1
        assert ancillary_size > 0
        return self.payload, self.ancillary, self.flags, None


class _TimeoutRecvmsgSocket:
    def settimeout(self, timeout: float) -> None:
        assert timeout == 2.0

    def recvmsg(self, data_size: int, ancillary_size: int) -> None:
        raise socket.timeout


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux kernel IPC contract")
def test_linux_seqpacket_accepts_one_current_sender_credential_record() -> None:
    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        allowed_fds = _open_linux_fds()
        _send_linux_packet(sender, b"kernel-authenticated-packet")

        assert _recv_linux_packet(
            receiver,
            expected_pid=os.getpid(),
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
            allowed_fds=allowed_fds,
        ) == b"kernel-authenticated-packet"
    finally:
        receiver.close()
        sender.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux kernel IPC contract")
def test_linux_seqpacket_binds_current_sender_pid_after_fork() -> None:
    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    child_pid = os.fork()
    if child_pid == 0:
        try:
            receiver.close()
            _send_linux_packet(sender, b"child-packet")
        finally:
            os._exit(0)

    try:
        sender.close()
        with pytest.raises(AuthProtocolError, match="^IPC_PEER_CREDENTIALS$"):
            _recv_linux_packet(
                receiver,
                expected_pid=os.getpid(),
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
                allowed_fds=_open_linux_fds(),
            )
    finally:
        receiver.close()
        os.waitpid(child_pid, 0)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux kernel IPC contract")
@pytest.mark.parametrize("flag_name", ["MSG_TRUNC", "MSG_CTRUNC"])
def test_linux_recvmsg_rejects_truncated_data_or_ancillary(flag_name: str) -> None:
    credentials = struct.pack("3i", os.getpid(), os.getuid(), os.getgid())
    fake = _SyntheticRecvmsgSocket(
        b"packet",
        [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, credentials)],
        getattr(socket, flag_name),
    )

    with pytest.raises(AuthProtocolError, match=f"^IPC_{flag_name[4:]}$"):
        _recv_linux_packet(
            fake,  # type: ignore[arg-type]
            expected_pid=os.getpid(),
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
            allowed_fds=_open_linux_fds(),
        )


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux kernel IPC contract")
@pytest.mark.parametrize("credential_count", [0, 2])
def test_linux_recvmsg_requires_exactly_one_scm_credentials(
    credential_count: int,
) -> None:
    credentials = struct.pack("3i", os.getpid(), os.getuid(), os.getgid())
    fake = _SyntheticRecvmsgSocket(
        b"packet",
        [
            (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, credentials)
            for _ in range(credential_count)
        ],
        0,
    )

    with pytest.raises(AuthProtocolError, match="^IPC_CREDENTIAL_COUNT$"):
        _recv_linux_packet(
            fake,  # type: ignore[arg-type]
            expected_pid=os.getpid(),
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
            allowed_fds=_open_linux_fds(),
        )


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux kernel IPC contract")
def test_linux_recvmsg_rejects_malformed_or_unknown_ancillary() -> None:
    credentials = struct.pack("3i", os.getpid(), os.getuid(), os.getgid())
    allowed_fds = _open_linux_fds()
    for ancillary in (
        [
            (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, credentials),
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, b"bad"),
        ],
        [
            (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, credentials),
            (999, 999, b""),
        ],
    ):
        fake = _SyntheticRecvmsgSocket(b"packet", ancillary, 0)
        with pytest.raises(AuthProtocolError, match="^IPC_ANCILLARY_INVALID$"):
            _recv_linux_packet(
                fake,  # type: ignore[arg-type]
                expected_pid=os.getpid(),
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
                allowed_fds=allowed_fds,
            )
        assert _open_linux_fds() == allowed_fds


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux kernel IPC contract")
def test_linux_recvmsg_timeout_is_stable_and_bounded() -> None:
    with pytest.raises(AuthProtocolError, match="^IPC_TIMEOUT$"):
        _recv_linux_packet(
            _TimeoutRecvmsgSocket(),  # type: ignore[arg-type]
            expected_pid=os.getpid(),
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
            allowed_fds=_open_linux_fds(),
        )


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux kernel IPC contract")
@pytest.mark.parametrize("rights_count", [1, 3])
def test_linux_recvmsg_rejects_scm_rights_without_fd_leak(rights_count: int) -> None:
    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    pipes = [os.pipe() for _ in range(rights_count)]
    try:
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        before = _open_linux_fds()
        expected_received_fds: list[int] = []
        candidate = 0
        while len(expected_received_fds) < rights_count:
            if candidate not in before:
                expected_received_fds.append(candidate)
            candidate += 1
        rights = array.array("i", [read_fd for read_fd, _write_fd in pipes])
        sender.sendmsg(
            [b"rights-attack"],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())],
        )

        with pytest.raises(AuthProtocolError, match="^IPC_ANCILLARY_RIGHTS$"):
            _recv_linux_packet(
                receiver,
                expected_pid=os.getpid(),
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
                allowed_fds=before,
            )

        assert _open_linux_fds() == before
        for received_fd in expected_received_fds:
            with pytest.raises(OSError) as exc_info:
                os.fstat(received_fd)
            assert exc_info.value.errno == errno.EBADF
        for read_fd, write_fd in pipes:
            os.write(write_fd, b"x")
            assert os.read(read_fd, 1) == b"x"
    finally:
        for read_fd, write_fd in pipes:
            os.close(read_fd)
            os.close(write_fd)
        receiver.close()
        sender.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux kernel IPC contract")
def test_linux_recvmsg_rejects_empty_and_oversized_packets() -> None:
    for payload, error_code in ((b"", "IPC_EMPTY"), (b"x" * 16_385, "IPC_OVERSIZED")):
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            allowed_fds = _open_linux_fds()
            sender.sendmsg([payload])
            with pytest.raises(AuthProtocolError, match=f"^{error_code}$"):
                _recv_linux_packet(
                    receiver,
                    expected_pid=os.getpid(),
                    expected_uid=os.getuid(),
                    expected_gid=os.getgid(),
                    allowed_fds=allowed_fds,
                )
        finally:
            receiver.close()
            sender.close()


def test_stream_packet_transport_is_length_prefixed_and_bounded() -> None:
    receiver, sender = socket.socketpair()
    try:
        _send_stream_packet(sender, b"bounded-stream-packet")
        assert _recv_stream_packet(receiver) == b"bounded-stream-packet"

        sender.sendall(struct.pack("!I", IPC_MAX_REQUEST_BYTES + 1))
        with pytest.raises(AuthProtocolError, match="^IPC_OVERSIZED$"):
            _recv_stream_packet(receiver)
    finally:
        receiver.close()
        sender.close()


def test_stream_packet_receive_enforces_one_absolute_frame_deadline() -> None:
    receiver, sender = socket.socketpair()
    encoded = struct.pack("!I", 3) + b"abc"

    def drip_frame() -> None:
        try:
            for byte in encoded:
                sender.sendall(bytes([byte]))
                time.sleep(0.6)
        except OSError:
            pass

    dripper = threading.Thread(target=drip_frame, daemon=True)
    dripper.start()
    started_at = time.monotonic()
    try:
        with pytest.raises(AuthProtocolError, match="^IPC_TIMEOUT$"):
            _recv_stream_packet(receiver)
        assert time.monotonic() - started_at < 2.5
    finally:
        receiver.close()
        sender.close()
        dripper.join(timeout=1.0)


@pytest.mark.parametrize(
    ("bootstrap", "error_code"),
    [
        (b"n" * 31, "IPC_BOOTSTRAP_EOF"),
        (b"n" * 33, "IPC_BOOTSTRAP_OVERSIZED"),
    ],
)
def test_windows_bootstrap_frame_rejects_wrong_exact_length(
    bootstrap: bytes, error_code: str
) -> None:
    with pytest.raises(AuthProtocolError, match=f"^{error_code}$"):
        _read_windows_bootstrap(io.BytesIO(bootstrap))


def test_windows_bootstrap_frame_is_consumed_once_at_32_bytes() -> None:
    stream = io.BytesIO(b"n" * 32)

    assert _read_windows_bootstrap(stream) == b"n" * 32
    assert stream.read() == b""


def _bound_policy() -> ProviderBrokerPolicy:
    return ProviderBrokerPolicy(
        version="AOSPROV/1",
        task_id="task-1",
        generation=1,
        attempt_id=2,
        launch_nonce="a1b2c3d4e5f60718293a4b5c6d7e8f90",
        upstream_provider_id="chatgpt_subscription",
        upstream_scheme="https",
        upstream_host="chatgpt.example.test",
        upstream_port=443,
        allowed_paths=("/backend-api/codex/responses",),
        protocol_type="HTTP_SSE",
        max_request_bytes=16_384,
        max_response_bytes=16_384,
        max_event_bytes=8_192,
        max_header_count=32,
        max_header_bytes=8_192,
        max_connections=1,
        retry_budget=0,
        idle_timeout_seconds=2.0,
        total_lifetime_seconds=300.0,
    )


def _bound_capability() -> tuple[ProviderBrokerPolicy, SubscriptionAuthCapability]:
    policy = _bound_policy()
    binding = ProviderAuthBinding(
        task_id=policy.task_id,
        generation=policy.generation,
        attempt_id=policy.attempt_id,
        launch_nonce=policy.launch_nonce,
        provider_id=policy.upstream_provider_id,
        upstream_scheme=policy.upstream_scheme,
        upstream_host=policy.upstream_host,
        upstream_port=policy.upstream_port,
        provider_purpose="responses_sse",
        helper_epoch="0123456789abcdef0123456789abcdef",
        request_nonce="11111111111111111111111111111111",
        capability_nonce="22222222222222222222222222222222",
        capability_sequence=1,
        issued_at=1_800_000_000,
        expires_at=1_800_000_300,
    )
    return policy, SubscriptionAuthCapability(
        access_token="SYNTHETIC_ACCESS_123",
        account_id="acct_synthetic_456",
        binding=binding,
    )


def test_subscription_capability_accepts_complete_exact_binding() -> None:
    policy, capability = _bound_capability()

    capability.validate_for_policy(policy, now=1_800_000_001)


@pytest.mark.parametrize(
    ("field", "wrong_value"),
    [
        ("task_id", "task-other"),
        ("generation", 2),
        ("attempt_id", 3),
        ("launch_nonce", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        ("provider_id", "other_provider"),
        ("upstream_scheme", "http"),
        ("upstream_host", "other.example.test"),
        ("upstream_port", 8443),
        ("provider_purpose", "other_purpose"),
    ],
)
def test_subscription_capability_rejects_each_wrong_binding_field(
    field: str, wrong_value: object
) -> None:
    policy, capability = _bound_capability()
    wrong_binding = replace(capability.binding, **{field: wrong_value})
    wrong_capability = SubscriptionAuthCapability(
        access_token="SYNTHETIC_ACCESS_123",
        account_id="acct_synthetic_456",
        binding=wrong_binding,
    )

    with pytest.raises(ProviderAuthBindingError) as exc_info:
        wrong_capability.validate_for_policy(policy, now=1_800_000_001)

    assert str(exc_info.value) == "PROVIDER_AUTH_BINDING_REJECTED"
    assert "SYNTHETIC_ACCESS_123" not in str(exc_info.value)
    assert "acct_synthetic_456" not in str(exc_info.value)


def test_subscription_capability_rejects_at_expiration_boundary() -> None:
    policy, capability = _bound_capability()

    with pytest.raises(ProviderAuthBindingError, match="^PROVIDER_AUTH_BINDING_REJECTED$"):
        capability.validate_for_policy(policy, now=1_800_000_300)


def test_subscription_auth_capability_headers() -> None:
    policy, auth = _bound_capability()
    header = auth.get_auth_header(policy.task_id, policy.generation)
    assert isinstance(header, SecretValue)
    assert header.reveal_secret() == "Bearer SYNTHETIC_ACCESS_123"

    extra = auth.get_extra_headers(policy.task_id, policy.generation)
    assert "ChatGPT-Account-ID" in extra
    acct_sec = extra["ChatGPT-Account-ID"]
    assert isinstance(acct_sec, SecretValue)
    assert acct_sec.reveal_secret() == "acct_synthetic_456"

    # Redaction checks
    assert repr(header) == "SecretValue(REDACTED)"
    assert str(header) == "[REDACTED]"
    assert repr(acct_sec) == "SecretValue(REDACTED)"
    assert str(acct_sec) == "[REDACTED]"


def test_subscription_capability_nested_secret_state_is_immutable() -> None:
    policy, capability = _bound_capability()

    with pytest.raises((AttributeError, TypeError)):
        capability._access_token._value = "SYNTHETIC_REPLACEMENT"  # type: ignore[misc]
    assert capability.get_auth_header(policy.task_id, policy.generation).reveal_secret() == (
        "Bearer SYNTHETIC_ACCESS_123"
    )

    assert capability._account_id is not None
    with pytest.raises((AttributeError, TypeError)):
        capability._account_id._value = "acct_replacement"  # type: ignore[misc]
    assert capability.get_extra_headers(policy.task_id, policy.generation)[
        "ChatGPT-Account-ID"
    ].reveal_secret() == "acct_synthetic_456"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux READY evidence")
@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("env_keys", ["PATH"]),
        ("import_paths", ["/usr/lib/python"]),
        ("open_fds", [0, 1, 2, 3]),
        ("open_fds", (0, 1, 2, "3")),
        ("helper_epoch", "not-32-hex"),
        ("core_soft_limit", -1),
        ("core_hard_limit", "0"),
        ("dumpable", 2),
        ("no_new_privs", 2),
        ("landlock_abi", -1),
        ("auth_root_device", -1),
        ("auth_root_inode", 0),
    ],
)
def test_auth_helper_identity_rejects_mutable_or_malformed_evidence(
    field: str, invalid_value: object
) -> None:
    auth_data = {
        "auth_mode": "chatgpt",
        "tokens": {"access_token": "SYNTHETIC_ACCESS", "expires_at": 1_900_000_000},
    }
    with ControllerAuthHelper(auth_data) as helper:
        with pytest.raises(ValueError):
            replace(helper.process_identity, **{field: invalid_value})


def test_controller_auth_helper_dict_init() -> None:
    auth_data = {
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": "SYNTHETIC_ACCESS_ABC",
            "refresh_token": "SYNTHETIC_REFRESH_DEF",
            "account_id": "acct_test_789",
            "expires_at": 1900000000,
        },
    }
    with ControllerAuthHelper(auth_data) as helper:
        assert helper.auth_mode == "chatgpt"
        assert helper.account_id == "acct_test_789"
        assert helper.is_expired is False

        # Process identity checks
        proc_id = helper.process_identity
        assert proc_id.pid != 0
        assert proc_id.executable_digest != ""
        assert "auth.json" not in proc_id.cwd

        cap = helper.get_auth_capability(
            "task-99",
            1,
            launch_nonce="a1b2c3d4e5f60718293a4b5c6d7e8f90",
            upstream_scheme="https",
            upstream_host="chatgpt.example.test",
            upstream_port=443,
            provider_purpose="responses_sse",
        )
        assert isinstance(cap, SubscriptionAuthCapability)
        assert cap.binding.task_id == "task-99"
        assert cap.binding.generation == 1
        assert cap.binding.attempt_id == 1
        assert cap.binding.launch_nonce == "a1b2c3d4e5f60718293a4b5c6d7e8f90"
        assert cap.binding.provider_id == "chatgpt_subscription"
        assert cap.binding.upstream_scheme == "https"
        assert cap.binding.upstream_host == "chatgpt.example.test"
        assert cap.binding.upstream_port == 443
        assert cap.binding.provider_purpose == "responses_sse"
        assert cap.binding.capability_sequence == 1
        assert cap.binding.expires_at <= cap.binding.issued_at + 300
        assert cap.get_auth_header("task-99", 1).reveal_secret() == "Bearer SYNTHETIC_ACCESS_ABC"
        assert cap.get_extra_headers("task-99", 1)["ChatGPT-Account-ID"].reveal_secret() == "acct_test_789"

        # Test token refresh and new capability request with distinct nonce
        helper.refresh_access_token("SYNTHETIC_ACCESS_NEW_XYZ")
        new_cap = helper.get_auth_capability(
            "task-99",
            2,
            launch_nonce="c9d8e7f6a5b403211234567890abcdef",
            upstream_scheme="https",
            upstream_host="chatgpt.example.test",
            upstream_port=443,
            provider_purpose="responses_sse",
        )
        assert new_cap.get_auth_header("task-99", 2).reveal_secret() == "Bearer SYNTHETIC_ACCESS_NEW_XYZ"


def test_controller_auth_helper_file_init(tmp_path) -> None:
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(
        json.dumps(
            {
                "auth_mode": "chatgpt",
                "tokens": {
                    "access_token": "FILE_ACCESS_TOKEN_111",
                    "refresh_token": "FILE_REFRESH_TOKEN_222",
                },
            }
        ),
        encoding="utf-8",
    )

    with ControllerAuthHelper(str(auth_file)) as helper:
        assert helper.auth_mode == "chatgpt"
        assert helper.account_id is None

        cap = helper.get_auth_capability(
            "task-1",
            1,
            launch_nonce="f1e2d3c4b5a60718293a4b5c6d7e8f90",
            upstream_scheme="https",
            upstream_host="chatgpt.example.test",
            upstream_port=443,
            provider_purpose="responses_sse",
        )
        assert cap.get_auth_header("task-1", 1).reveal_secret() == "Bearer FILE_ACCESS_TOKEN_111"
        assert cap.get_extra_headers("task-1", 1) == {}


def test_controller_auth_helper_invalid_schema() -> None:
    with pytest.raises(ValueError, match="missing required 'tokens'"):
        ControllerAuthHelper({"auth_mode": "chatgpt"})

    with pytest.raises(ValueError, match="missing required 'access_token'"):
        ControllerAuthHelper({"auth_mode": "chatgpt", "tokens": {}})
