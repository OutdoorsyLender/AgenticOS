"""Unit test suite for out-of-process controller auth helper and subscription auth capability."""

import json
import pytest

from agenticos.sandbox.controller_auth_helper import ControllerAuthHelper
from agenticos.sandbox.provider_models import SecretValue, SubscriptionAuthCapability


def test_subscription_auth_capability_headers() -> None:
    auth = SubscriptionAuthCapability(access_token="SYNTHETIC_ACCESS_123", account_id="acct_synthetic_456")
    header = auth.get_auth_header("task-1", 1)
    assert isinstance(header, SecretValue)
    assert header.reveal_secret() == "Bearer SYNTHETIC_ACCESS_123"

    extra = auth.get_extra_headers("task-1", 1)
    assert "ChatGPT-Account-ID" in extra
    acct_sec = extra["ChatGPT-Account-ID"]
    assert isinstance(acct_sec, SecretValue)
    assert acct_sec.reveal_secret() == "acct_synthetic_456"

    # Redaction checks
    assert repr(header) == "SecretValue(REDACTED)"
    assert str(header) == "[REDACTED]"
    assert repr(acct_sec) == "SecretValue(REDACTED)"
    assert str(acct_sec) == "[REDACTED]"


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

        cap = helper.get_auth_capability("task-99", 1, launch_nonce="a1b2c3d4e5f60718293a4b5c6d7e8f90")
        assert isinstance(cap, SubscriptionAuthCapability)
        assert cap.get_auth_header("task-99", 1).reveal_secret() == "Bearer SYNTHETIC_ACCESS_ABC"
        assert cap.get_extra_headers("task-99", 1)["ChatGPT-Account-ID"].reveal_secret() == "acct_test_789"

        # Test token refresh and new capability request with distinct nonce
        helper.refresh_access_token("SYNTHETIC_ACCESS_NEW_XYZ")
        new_cap = helper.get_auth_capability("task-99", 2, launch_nonce="c9d8e7f6a5b403211234567890abcdef")
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

        cap = helper.get_auth_capability("task-1", 1, launch_nonce="f1e2d3c4b5a60718293a4b5c6d7e8f90")
        assert cap.get_auth_header("task-1", 1).reveal_secret() == "Bearer FILE_ACCESS_TOKEN_111"
        assert cap.get_extra_headers("task-1", 1) == {}


def test_controller_auth_helper_invalid_schema() -> None:
    with pytest.raises(ValueError, match="missing required 'tokens'"):
        ControllerAuthHelper({"auth_mode": "chatgpt"})

    with pytest.raises(ValueError, match="missing required 'access_token'"):
        ControllerAuthHelper({"auth_mode": "chatgpt", "tokens": {}})
