"""Unit test suite for AgenticOS task-scoped provider broker policies and envelope parsing."""

from dataclasses import replace
import socket
import threading

import pytest

from agenticos.sandbox.provider_broker import (
    TaskProviderBroker,
    _AtomicCapabilitySlot,
    _CLIENT_ALLOWED_HEADERS,
    _CLIENT_FORBIDDEN_HEADERS,
    _RESPONSE_ALLOWED_HEADERS,
)
from agenticos.sandbox.provider_models import (
    NetworkAuthority,
    ProviderAuthCapability,
    ProviderAuthBinding,
    ProviderAuthBindingError,
    ProviderBrokerEvidence,
    ProviderBrokerIdentity,
    ProviderBrokerPolicy,
    ProviderFailureClass,
    ProviderGrant,
    SecretValue,
    SubscriptionAuthCapability,
    SyntheticBearerAuth,
    canonical_provider_policy_bytes,
    provider_policy_digest,
)


def _make_valid_policy(**kwargs) -> ProviderBrokerPolicy:
    defaults = {
        "version": "AOSPROV/1",
        "task_id": "test-task-1",
        "generation": 1,
        "attempt_id": 1,
        "launch_nonce": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "upstream_provider_id": "synthetic_openai",
        "upstream_scheme": "http",
        "upstream_host": "127.0.0.1",
        "upstream_port": 9000,
        "allowed_paths": ("/v1/responses", "/backend-api/codex/responses"),
        "protocol_type": "HTTP_SSE",
        "max_request_bytes": 10 * 1024 * 1024,
        "max_response_bytes": 50 * 1024 * 1024,
        "max_event_bytes": 1 * 1024 * 1024,
        "max_header_count": 32,
        "max_header_bytes": 8192,
        "max_connections": 1,
        "retry_budget": 0,
        "idle_timeout_seconds": 30.0,
        "total_lifetime_seconds": 300.0,
    }
    defaults.update(kwargs)
    return ProviderBrokerPolicy(**defaults)


def _make_subscription_capability(
    policy: ProviderBrokerPolicy,
    *,
    sequence: int = 1,
    access_token: str = "SYNTHETIC_ACCESS_1",
    helper_epoch: str = "0123456789abcdef0123456789abcdef",
) -> SubscriptionAuthCapability:
    digit = str(sequence % 10)
    return SubscriptionAuthCapability(
        access_token=access_token,
        account_id="acct_synthetic",
        binding=ProviderAuthBinding(
            task_id=policy.task_id,
            generation=policy.generation,
            attempt_id=policy.attempt_id,
            launch_nonce=policy.launch_nonce,
            provider_id=policy.upstream_provider_id,
            upstream_scheme=policy.upstream_scheme,
            upstream_host=policy.upstream_host,
            upstream_port=policy.upstream_port,
            provider_purpose="responses_sse",
            helper_epoch=helper_epoch,
            request_nonce=digit * 32,
            capability_nonce=(str((sequence + 1) % 10)) * 32,
            capability_sequence=sequence,
            issued_at=1_800_000_000,
            expires_at=4_000_000_000,
        ),
    )


def _inject_once(slot: _AtomicCapabilitySlot, policy: ProviderBrokerPolicy) -> list[str]:
    observed: list[str] = []

    def sender(auth: SecretValue, extra: dict[str, SecretValue]) -> None:
        observed.append(auth.reveal_secret())

    slot.validate_extract_and_send(policy=policy, sender=sender)
    return observed


def _start_recording_upstream(
    connection_count: int,
) -> tuple[int, list[str], threading.Thread]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(connection_count)
    listener.settimeout(2.0)
    port = listener.getsockname()[1]
    observed: list[str] = []

    def serve() -> None:
        try:
            for _ in range(connection_count):
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(2.0)
                    request = bytearray()
                    while b"\r\n\r\n" not in request:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        request.extend(chunk)
                    for line in bytes(request).split(b"\r\n"):
                        if line.lower().startswith(b"authorization:"):
                            observed.append(line.split(b":", 1)[1].strip().decode("ascii"))
                    if request:
                        conn.sendall(
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: text/event-stream\r\n"
                            b"Connection: close\r\n\r\n"
                            b"event: done\ndata: {}\n\n"
                        )
        finally:
            listener.close()

    thread = threading.Thread(target=serve, name="fake-provider-upstream")
    thread.start()
    return port, observed, thread


def _send_broker_request(broker: TaskProviderBroker) -> bytes:
    grant = broker.grant
    with socket.create_connection(
        (grant.listener_address, grant.listener_port), timeout=2.0
    ) as client:
        client.settimeout(2.0)
        client.sendall(
            b"POST /v1/responses HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        response = bytearray()
        while True:
            chunk = client.recv(4096)
            if not chunk:
                return bytes(response)
            response.extend(chunk)


def test_subscription_binding_is_rejected_before_broker_start() -> None:
    policy = _make_valid_policy()
    valid = _make_subscription_capability(policy)
    wrong = SubscriptionAuthCapability(
        access_token="SYNTHETIC_ACCESS_1",
        binding=replace(valid.binding, task_id="other-task"),
    )

    with pytest.raises(ProviderAuthBindingError, match="^PROVIDER_AUTH_BINDING_REJECTED$"):
        TaskProviderBroker(policy, wrong)


def test_capability_replacement_waits_for_validation_and_old_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _make_valid_policy()
    old = _make_subscription_capability(policy, access_token="SYNTHETIC_OLD")
    new = _make_subscription_capability(policy, sequence=2, access_token="SYNTHETIC_NEW")
    slot = _AtomicCapabilitySlot(policy, old)
    validation_entered = threading.Event()
    allow_validation = threading.Event()
    replacement_started = threading.Event()
    replacement_done = threading.Event()
    observed: list[str] = []
    original_validate = SubscriptionAuthCapability.validate_for_policy

    def blocking_validate(self, checked_policy, now=None):
        if self is old and threading.current_thread().name == "old-injection":
            validation_entered.set()
            assert allow_validation.wait(2.0)
        return original_validate(self, checked_policy, now)

    monkeypatch.setattr(SubscriptionAuthCapability, "validate_for_policy", blocking_validate)

    injection = threading.Thread(
        name="old-injection",
        target=lambda: slot.validate_extract_and_send(
            policy=policy,
            sender=lambda auth, extra: observed.append(auth.reveal_secret()),
        ),
    )

    def replace_capability() -> None:
        replacement_started.set()
        slot.replace(new, policy=policy, expected_sequence=1)
        replacement_done.set()

    replacement = threading.Thread(target=replace_capability)
    injection.start()
    assert validation_entered.wait(2.0)
    replacement.start()
    assert replacement_started.wait(2.0)
    assert not replacement_done.wait(0.05)
    allow_validation.set()
    injection.join(2.0)
    replacement.join(2.0)

    assert not injection.is_alive()
    assert not replacement.is_alive()
    assert observed == ["Bearer SYNTHETIC_OLD"]
    assert _inject_once(slot, policy) == ["Bearer SYNTHETIC_NEW"]


def test_live_broker_replacement_during_validation_linearizes_real_upstream_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upstream_port, observed, upstream_thread = _start_recording_upstream(2)
    policy = _make_valid_policy(upstream_port=upstream_port, idle_timeout_seconds=2.0)
    old = _make_subscription_capability(policy, access_token="SYNTHETIC_OLD")
    new = _make_subscription_capability(policy, sequence=2, access_token="SYNTHETIC_NEW")
    broker = TaskProviderBroker(policy, old)
    validation_barrier = threading.Barrier(2)
    allow_validation = threading.Event()
    replacement_started = threading.Event()
    replacement_done = threading.Event()
    original_validate = SubscriptionAuthCapability.validate_for_policy

    def blocking_validate(self, checked_policy, now=None):
        if self is old and threading.current_thread().name.startswith("ProvBroker-"):
            validation_barrier.wait(timeout=2.0)
            assert allow_validation.wait(2.0)
        return original_validate(self, checked_policy, now)

    monkeypatch.setattr(SubscriptionAuthCapability, "validate_for_policy", blocking_validate)
    broker.start()
    first_response: list[bytes] = []
    first_client = threading.Thread(target=lambda: first_response.append(_send_broker_request(broker)))

    def replace_live_capability() -> None:
        replacement_started.set()
        broker.replace_auth_capability(new, expected_sequence=1)
        replacement_done.set()

    replacement = threading.Thread(target=replace_live_capability)
    try:
        first_client.start()
        validation_barrier.wait(timeout=2.0)
        replacement.start()
        assert replacement_started.wait(2.0)
        assert not replacement_done.wait(0.05)
        allow_validation.set()
        first_client.join(2.0)
        replacement.join(2.0)
        assert not first_client.is_alive()
        assert not replacement.is_alive()
        assert first_response and first_response[0].startswith(b"HTTP/1.1 200")

        second_response = _send_broker_request(broker)
        assert second_response.startswith(b"HTTP/1.1 200")
    finally:
        broker.stop()
        upstream_thread.join(2.0)

    assert not upstream_thread.is_alive()
    assert observed == ["Bearer SYNTHETIC_OLD", "Bearer SYNTHETIC_NEW"]


def test_capability_cancellation_waits_for_validation_and_prevents_later_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _make_valid_policy()
    old = _make_subscription_capability(policy, access_token="SYNTHETIC_OLD")
    slot = _AtomicCapabilitySlot(policy, old)
    validation_entered = threading.Event()
    allow_validation = threading.Event()
    cancellation_done = threading.Event()
    observed: list[str] = []
    original_validate = SubscriptionAuthCapability.validate_for_policy

    def blocking_validate(self, checked_policy, now=None):
        if self is old and threading.current_thread().name == "old-injection":
            validation_entered.set()
            assert allow_validation.wait(2.0)
        return original_validate(self, checked_policy, now)

    monkeypatch.setattr(SubscriptionAuthCapability, "validate_for_policy", blocking_validate)
    injection = threading.Thread(
        name="old-injection",
        target=lambda: slot.validate_extract_and_send(
            policy=policy,
            sender=lambda auth, extra: observed.append(auth.reveal_secret()),
        ),
    )
    cancellation = threading.Thread(target=lambda: (slot.cancel(), cancellation_done.set()))
    injection.start()
    assert validation_entered.wait(2.0)
    cancellation.start()
    assert not cancellation_done.wait(0.05)
    allow_validation.set()
    injection.join(2.0)
    cancellation.join(2.0)

    assert observed == ["Bearer SYNTHETIC_OLD"]
    with pytest.raises(ProviderAuthBindingError, match="^PROVIDER_AUTH_CANCELLED$"):
        _inject_once(slot, policy)


def test_live_broker_cancellation_during_validation_prevents_later_upstream_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upstream_port, observed, upstream_thread = _start_recording_upstream(2)
    policy = _make_valid_policy(upstream_port=upstream_port, idle_timeout_seconds=2.0)
    old = _make_subscription_capability(policy, access_token="SYNTHETIC_OLD")
    broker = TaskProviderBroker(policy, old)
    validation_barrier = threading.Barrier(2)
    allow_validation = threading.Event()
    cancellation_done = threading.Event()
    original_validate = SubscriptionAuthCapability.validate_for_policy

    def blocking_validate(self, checked_policy, now=None):
        if self is old and threading.current_thread().name.startswith("ProvBroker-"):
            validation_barrier.wait(timeout=2.0)
            assert allow_validation.wait(2.0)
        return original_validate(self, checked_policy, now)

    monkeypatch.setattr(SubscriptionAuthCapability, "validate_for_policy", blocking_validate)
    broker.start()
    first_response: list[bytes] = []
    first_client = threading.Thread(target=lambda: first_response.append(_send_broker_request(broker)))
    cancellation = threading.Thread(
        target=lambda: (broker.cancel_auth_capability(), cancellation_done.set())
    )
    try:
        first_client.start()
        validation_barrier.wait(timeout=2.0)
        cancellation.start()
        assert not cancellation_done.wait(0.05)
        allow_validation.set()
        first_client.join(2.0)
        cancellation.join(2.0)
        assert not first_client.is_alive()
        assert not cancellation.is_alive()
        assert first_response and first_response[0].startswith(b"HTTP/1.1 200")

        second_response = _send_broker_request(broker)
        assert second_response.startswith(b"HTTP/1.1 500 Auth Unavailable")
    finally:
        broker.stop()
        upstream_thread.join(2.0)

    assert not upstream_thread.is_alive()
    assert observed == ["Bearer SYNTHETIC_OLD"]


def test_capability_replacement_immediately_before_injection_is_linearized() -> None:
    policy = _make_valid_policy()
    old = _make_subscription_capability(policy, access_token="SYNTHETIC_OLD")
    new = _make_subscription_capability(policy, sequence=2, access_token="SYNTHETIC_NEW")
    slot = _AtomicCapabilitySlot(policy, old)
    sender_entered = threading.Event()
    allow_sender = threading.Event()
    replacement_done = threading.Event()
    observed: list[str] = []

    def blocked_sender(auth: SecretValue, extra: dict[str, SecretValue]) -> None:
        sender_entered.set()
        assert allow_sender.wait(2.0)
        observed.append(auth.reveal_secret())

    injection = threading.Thread(
        target=lambda: slot.validate_extract_and_send(policy=policy, sender=blocked_sender)
    )
    replacement = threading.Thread(
        target=lambda: (
            slot.replace(new, policy=policy, expected_sequence=1),
            replacement_done.set(),
        )
    )
    injection.start()
    assert sender_entered.wait(2.0)
    replacement.start()
    assert not replacement_done.wait(0.05)
    allow_sender.set()
    injection.join(2.0)
    replacement.join(2.0)

    assert observed == ["Bearer SYNTHETIC_OLD"]
    assert _inject_once(slot, policy) == ["Bearer SYNTHETIC_NEW"]


def test_concurrent_capability_replacements_have_one_compare_and_swap_winner() -> None:
    policy = _make_valid_policy()
    slot = _AtomicCapabilitySlot(policy, _make_subscription_capability(policy))
    candidates = (
        _make_subscription_capability(policy, sequence=2, access_token="SYNTHETIC_NEW_A"),
        _make_subscription_capability(policy, sequence=2, access_token="SYNTHETIC_NEW_B"),
    )
    start = threading.Barrier(3)
    outcomes: list[str] = []
    outcomes_lock = threading.Lock()

    def replace_candidate(candidate: SubscriptionAuthCapability) -> None:
        start.wait()
        try:
            slot.replace(candidate, policy=policy, expected_sequence=1)
            result = "accepted"
        except ProviderAuthBindingError:
            result = "rejected"
        with outcomes_lock:
            outcomes.append(result)

    threads = [threading.Thread(target=replace_candidate, args=(candidate,)) for candidate in candidates]
    for thread in threads:
        thread.start()
    start.wait()
    for thread in threads:
        thread.join(2.0)

    assert sorted(outcomes) == ["accepted", "rejected"]
    assert _inject_once(slot, policy)[0] in {
        "Bearer SYNTHETIC_NEW_A",
        "Bearer SYNTHETIC_NEW_B",
    }


def test_stale_sequence_and_helper_epoch_reuse_fail_after_replacement() -> None:
    policy = _make_valid_policy()
    slot = _AtomicCapabilitySlot(policy, _make_subscription_capability(policy))
    slot.replace(
        _make_subscription_capability(policy, sequence=2, access_token="SYNTHETIC_NEW"),
        policy=policy,
        expected_sequence=1,
    )

    with pytest.raises(ProviderAuthBindingError, match="^PROVIDER_AUTH_SEQUENCE_REJECTED$"):
        slot.replace(
            _make_subscription_capability(policy, sequence=3, access_token="SYNTHETIC_STALE"),
            policy=policy,
            expected_sequence=1,
        )
    with pytest.raises(ProviderAuthBindingError, match="^PROVIDER_AUTH_EPOCH_REJECTED$"):
        slot.replace(
            _make_subscription_capability(
                policy,
                sequence=3,
                access_token="SYNTHETIC_OLD_EPOCH",
                helper_epoch="abcdef0123456789abcdef0123456789",
            ),
            policy=policy,
            expected_sequence=2,
        )


def test_secret_value_redaction() -> None:
    secret = SecretValue("SUPER_SECRET_CANARY_VALUE_123")
    assert repr(secret) == "SecretValue(REDACTED)"
    assert str(secret) == "[REDACTED]"
    assert f"{secret}" == "[REDACTED]"
    assert secret.reveal_secret() == "SUPER_SECRET_CANARY_VALUE_123"

    with pytest.raises(TypeError):
        SecretValue(12345)  # type: ignore


def test_synthetic_bearer_auth() -> None:
    auth = SyntheticBearerAuth("CANARY_BEARER_999")
    val = auth.get_auth_header("task-123", 1)
    assert isinstance(val, SecretValue)
    assert repr(val) == "SecretValue(REDACTED)"
    assert str(val) == "[REDACTED]"
    assert val.reveal_secret() == "Bearer CANARY_BEARER_999"

    with pytest.raises(ValueError):
        SyntheticBearerAuth("")


def test_provider_broker_policy_validation() -> None:
    policy = _make_valid_policy()
    assert policy.task_id == "test-task-1"
    assert policy.generation == 1
    assert policy.attempt_id == 1
    assert policy.upstream_scheme == "http"

    # Test version check
    with pytest.raises(ValueError, match="version must be"):
        _make_valid_policy(version="INVALID/1")

    # Test task_id check
    with pytest.raises(ValueError, match="task_id"):
        _make_valid_policy(task_id="bad task name!")

    # Test generation check
    with pytest.raises(ValueError, match="generation"):
        _make_valid_policy(generation=0)

    # Test launch_nonce check
    with pytest.raises(ValueError, match="launch_nonce"):
        _make_valid_policy(launch_nonce="short_nonce")

    # Test upstream_scheme check
    with pytest.raises(ValueError, match="upstream_scheme"):
        _make_valid_policy(upstream_scheme="ftp")

    # Test upstream_port check
    with pytest.raises(ValueError, match="upstream_port"):
        _make_valid_policy(upstream_port=70000)

    # Test allowed_paths check
    with pytest.raises(ValueError, match="allowed_paths"):
        _make_valid_policy(allowed_paths=("invalid_path_without_slash",))

    # Test protocol_type check
    with pytest.raises(ValueError, match="protocol_type"):
        _make_valid_policy(protocol_type="WEBSOCKET")


def test_provider_policy_digest_determinism() -> None:
    policy1 = _make_valid_policy()
    policy2 = _make_valid_policy()
    assert canonical_provider_policy_bytes(policy1) == canonical_provider_policy_bytes(policy2)
    digest1 = provider_policy_digest(policy1)
    digest2 = provider_policy_digest(policy2)
    assert len(digest1) == 64
    assert digest1 == digest2


def test_provider_grant_validation() -> None:
    policy = _make_valid_policy()
    p_digest = provider_policy_digest(policy)
    grant = ProviderGrant(
        task_id=policy.task_id,
        generation=policy.generation,
        attempt_id=policy.attempt_id,
        launch_nonce=policy.launch_nonce,
        policy_digest=p_digest,
        listener_address="127.0.0.1",
        listener_port=9001,
    )
    assert grant.listener_address == "127.0.0.1"
    assert grant.listener_port == 9001

    with pytest.raises(ValueError, match="policy_digest"):
        ProviderGrant(
            task_id=policy.task_id,
            generation=policy.generation,
            attempt_id=policy.attempt_id,
            launch_nonce=policy.launch_nonce,
            policy_digest="invalid_digest",
            listener_address="127.0.0.1",
            listener_port=9001,
        )


def test_provider_broker_evidence_validation() -> None:
    policy = _make_valid_policy()
    p_digest = provider_policy_digest(policy)
    identity = ProviderBrokerIdentity(
        broker_id="provbroker-test",
        pid=1234,
        start_time_ticks=1000,
        boot_id="00000000-0000-0000-0000-000000000000",
    )
    evidence = ProviderBrokerEvidence(
        task_id=policy.task_id,
        generation=policy.generation,
        attempt_id=policy.attempt_id,
        policy_digest=p_digest,
        broker_identity=identity,
        upstream_identity="http://127.0.0.1:9000",
        protocol="HTTP_SSE",
        client_connection_count=1,
        request_byte_count=500,
        response_byte_count=2000,
        response_event_count=5,
        upstream_status=200,
        started_at_monotonic_ns=100,
        ended_at_monotonic_ns=200,
        terminal_failure_class=None,
        cancellation_state=False,
        canary_exposure_status="CLEAN_NO_EXPOSURE",
    )
    assert evidence.upstream_status == 200
    assert evidence.canary_exposure_status == "CLEAN_NO_EXPOSURE"

    with pytest.raises(ValueError, match="ended_at_monotonic_ns"):
        ProviderBrokerEvidence(
            task_id=policy.task_id,
            generation=policy.generation,
            attempt_id=policy.attempt_id,
            policy_digest=p_digest,
            broker_identity=identity,
            upstream_identity="http://127.0.0.1:9000",
            protocol="HTTP_SSE",
            client_connection_count=1,
            request_byte_count=500,
            response_byte_count=2000,
            response_event_count=5,
            upstream_status=200,
            started_at_monotonic_ns=200,
            ended_at_monotonic_ns=100,
            terminal_failure_class=None,
            cancellation_state=False,
            canary_exposure_status="CLEAN_NO_EXPOSURE",
        )


def test_header_allowlist_definitions() -> None:
    assert "authorization" in _CLIENT_FORBIDDEN_HEADERS
    assert "cookie" in _CLIENT_FORBIDDEN_HEADERS
    assert "proxy-authorization" in _CLIENT_FORBIDDEN_HEADERS
    assert "x-api-key" in _CLIENT_FORBIDDEN_HEADERS
    assert "host" in _CLIENT_ALLOWED_HEADERS
    assert "content-type" in _CLIENT_ALLOWED_HEADERS
    assert "content-type" in _RESPONSE_ALLOWED_HEADERS
    assert "cache-control" in _RESPONSE_ALLOWED_HEADERS
    assert "set-cookie" not in _RESPONSE_ALLOWED_HEADERS


def test_network_authority_enum() -> None:
    assert NetworkAuthority.NONE.value == "NONE"
    assert NetworkAuthority.CONNECTED_BUILD.value == "CONNECTED_BUILD"
    assert NetworkAuthority.PROVIDER_CONTROL.value == "PROVIDER_CONTROL"


def test_provider_failure_class_coverage() -> None:
    expected_failures = {
        "PROVIDER_BROKER_UNAVAILABLE",
        "PROVIDER_POLICY_REJECTED",
        "PROVIDER_CLIENT_PROTOCOL_ERROR",
        "PROVIDER_AUTH_UNAVAILABLE",
        "PROVIDER_UPSTREAM_CONNECT_ERROR",
        "PROVIDER_UPSTREAM_PROTOCOL_ERROR",
        "PROVIDER_UPSTREAM_STATUS_ERROR",
        "PROVIDER_RESPONSE_TOO_LARGE",
        "PROVIDER_EVENT_TOO_LARGE",
        "PROVIDER_IDLE_TIMEOUT",
        "PROVIDER_TOTAL_TIMEOUT",
        "PROVIDER_CANCELLED",
    }
    actual = {f.value for f in ProviderFailureClass}
    assert actual == expected_failures
