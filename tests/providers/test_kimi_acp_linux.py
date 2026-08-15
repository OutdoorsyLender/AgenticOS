from __future__ import annotations

import os
from pathlib import Path

import pytest

from agenticos.providers.kimi_policy import validate_qualification_bundle, verify_pinned_runtime
from agenticos.providers.kimi_runtime import build_runtime_spec, run_synthetic_acp_fixture


RUNTIME = Path("/home/brand/.local/share/agenticos/provider-qualification/kimi-code/0.36.1/runtime/bin/kimi")
ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "qualification" / "kimi-code" / "0.36.1"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "kimi_loopback_fixture.py"


@pytest.mark.skipif(not RUNTIME.exists() or os.name != "posix", reason="pinned WSL runtime required")
def test_real_kimi_acp_plan_is_tool_free_checkout_free_and_loopback_only() -> None:
    artifact = validate_qualification_bundle(BUNDLE)
    verify_pinned_runtime(RUNTIME, artifact, expected_uid=os.getuid())
    report = run_synthetic_acp_fixture(build_runtime_spec(RUNTIME, BUNDLE), FIXTURE, "plan", timeout_seconds=45)
    assert report["schema"] == "AOS_KIMI_FIXTURE/1"
    assert report["ok"] is True, report
    assert report["agent_info"] == {"name": "Kimi Code CLI", "version": "0.36.1"}
    assert report["protocol_version"] == 1
    assert report["auth_method_ids"] == ["login"]
    assert report["auth_terminal_args"] == ["--login"]
    assert report["provider_request_count"] == 1
    assert report["provider_tools"] == []
    assert report["profile_prompt_seen"] is True
    assert report["plan_schema"] == "AOSPLAN/1"
    assert report["workspace_entries"] == []
    assert report["checkout_visible"] is False
    assert report["default_route_present"] is False
    assert report["non_loopback_socket_seen"] is False
    assert report["credential_canary_leaked"] is False
    assert report["credential_canary_count"] == 2
    assert report["api_key_name_seen"] is False
    assert report["unexpected_callback_methods"] == []
    assert report["tool_update_kinds"] == []
    assert report["kimi_children"] == []
    assert report["continuous_census_samples"] > 0
    assert report["hostile_window_samples"] > 0
    assert report["monitor_error"] is None
    assert report["monitor_stopped"] is True
    assert report["max_descendant_count"] == 1
    assert report["provider_process_count"] == 1
    assert report["provider_process_argv"] == ["kimi-code"]
    assert report["provider_executable"] == "/opt/agenticos/kimi/bin/kimi"
    assert report["provider_parent"] == "python3:kimi_loopback_fixture.py"
    assert report["child_environment_names"] == [
        "HOME", "KIMI_CODE_HOME", "KIMI_CODE_NO_AUTO_UPDATE", "KIMI_DISABLE_CRON",
        "KIMI_DISABLE_TELEMETRY", "LANG", "LC_ALL", "PATH", "PWD", "TMPDIR",
    ]
    assert report["child_fd_classes"] == ["pipe", "pipe", "pipe"]
    credential_state = {
        path: kind
        for path, kind in report["created_state_classifications"].items()
        if kind == "FUTURE_CREDENTIAL_STATE"
    }
    assert len(credential_state) == 1
    assert next(iter(credential_state)).startswith("credentials/kimi-code-env-")
    assert report["host_authority_fd_seen"] is False
    assert report["hostile_window_samples"] > 0
    assert report["monitor_error"] is None
    assert report["monitor_stopped"] is True
    assert report["synthetic_secret_fd_inherited"] is False
    assert report["non_loopback_socket_seen"] is False
    assert "UNKNOWN" not in report["created_state_classifications"].values()


@pytest.mark.skipif(not RUNTIME.exists() or os.name != "posix", reason="pinned WSL runtime required")
def test_real_kimi_cancel_notification_wins_before_a_delayed_provider_response() -> None:
    report = run_synthetic_acp_fixture(
        build_runtime_spec(RUNTIME, BUNDLE), FIXTURE, "cancel", timeout_seconds=45
    )
    assert report["ok"] is True, report
    assert report["cancel_stop_reason"] == "cancelled"
    assert report["provider_request_count"] == 1
    assert report["credential_canary_leaked"] is False
    assert report["shell_marker_exists"] is False
    assert report["kimi_children"] == []
    assert report["max_descendant_count"] == 1
    assert report["host_authority_fd_seen"] is False
    assert report["hostile_window_samples"] > 0
    assert report["monitor_error"] is None
    assert report["monitor_stopped"] is True


@pytest.mark.skipif(not RUNTIME.exists() or os.name != "posix", reason="pinned WSL runtime required")
def test_real_kimi_malformed_provider_stream_fails_closed_without_execution() -> None:
    report = run_synthetic_acp_fixture(
        build_runtime_spec(RUNTIME, BUNDLE), FIXTURE, "malformed-stream", timeout_seconds=45
    )
    # Pinned 0.36.1 does not terminally answer malformed upstream SSE.  The
    # controller's bounded fixture timeout kills it and admits no proposal.
    assert report == {
        "schema": "AOS_KIMI_FIXTURE/1",
        "ok": False,
        "error": "ACP_TIMEOUT",
        "detail": "3",
    }


@pytest.mark.skipif(not RUNTIME.exists() or os.name != "posix", reason="pinned WSL runtime required")
def test_real_kimi_process_crash_mid_turn_admits_no_proposal_or_residue() -> None:
    report = run_synthetic_acp_fixture(
        build_runtime_spec(RUNTIME, BUNDLE), FIXTURE, "process-crash", timeout_seconds=45
    )
    assert report["ok"] is True, report
    assert report["process_crash_rejected"] is True
    assert report["process_returncode"] < 0
    assert report["provider_process_alive_after_cleanup"] is False
    assert report["plan_schema"] is None
    assert report["kimi_children"] == []
    assert report["max_descendant_count"] == 1
    assert report["shell_marker_exists"] is False
    assert report["credential_canary_leaked"] is False
    assert report["host_authority_fd_seen"] is False
    assert report["hostile_window_samples"] > 0
    assert report["monitor_error"] is None
    assert report["monitor_stopped"] is True


@pytest.mark.skipif(not RUNTIME.exists() or os.name != "posix", reason="pinned WSL runtime required")
def test_real_kimi_profile_does_not_offer_or_execute_a_malicious_shell_tool_call() -> None:
    report = run_synthetic_acp_fixture(build_runtime_spec(RUNTIME, BUNDLE), FIXTURE, "tool-attempt", timeout_seconds=45)
    assert report["ok"] is True, report
    assert report["provider_tools"] == []
    assert report["shell_marker_exists"] is False
    assert report["kimi_children"] == []
    assert report["credential_canary_leaked"] is False
    assert report["tool_attempt_structurally_rejected"] is True
    assert report["attempted_tool_names"] == [
        "Bash", "CommandExecution", "ReadFile", "WriteFile", "Glob", "ListDirectory",
        "ReadBinary", "Subagent", "MCP", "Plugin", "Skill", "Hook", "BackgroundTask",
    ]
    assert report["tool_update_kinds"]
    assert report["synthetic_secret_fd_inherited"] is False
    assert report["filesystem_read_canary_leaked"] is False
    assert report["filesystem_write_marker_exists"] is False
    assert report["continuous_census_samples"] > 0
    assert report["max_descendant_count"] == 1
    assert report["hostile_window_samples"] > 0
    assert report["monitor_error"] is None
    assert report["monitor_stopped"] is True
