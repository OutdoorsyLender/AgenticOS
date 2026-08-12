"""Unit test suite for out-of-process controller auth helper and subscription auth capability."""

from dataclasses import replace
import json
import pytest

from agenticos.sandbox.controller_auth_helper import ControllerAuthHelper
from agenticos.sandbox.provider_models import (
    ProviderAuthBinding,
    ProviderAuthBindingError,
    ProviderBrokerPolicy,
    SecretValue,
    SubscriptionAuthCapability,
)


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
