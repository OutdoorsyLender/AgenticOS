"""Unit test suite for AgenticOS task-scoped provider broker policies and envelope parsing."""

import pytest

from agenticos.sandbox.provider_broker import _CLIENT_ALLOWED_HEADERS, _CLIENT_FORBIDDEN_HEADERS, _RESPONSE_ALLOWED_HEADERS
from agenticos.sandbox.provider_models import (
    NetworkAuthority,
    ProviderAuthCapability,
    ProviderBrokerEvidence,
    ProviderBrokerIdentity,
    ProviderBrokerPolicy,
    ProviderFailureClass,
    ProviderGrant,
    SecretValue,
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
