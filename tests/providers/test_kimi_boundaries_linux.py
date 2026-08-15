from __future__ import annotations

import os
from pathlib import Path

import pytest

from agenticos.providers.kimi_runtime import build_runtime_spec, run_synthetic_acp_fixture


RUNTIME = Path(
    "/home/brand/.local/share/agenticos/provider-qualification/"
    "kimi-code/0.36.1/runtime/bin/kimi"
)
ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "qualification" / "kimi-code" / "0.36.1"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "kimi_loopback_fixture.py"


@pytest.mark.skipif(not RUNTIME.exists() or os.name != "posix", reason="pinned WSL runtime required")
def test_native_kimi_boundary_census_is_closed_and_unknown_state_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in {
        "KIMI_API_KEY": "AOS_AMBIENT_API_KEY_CANARY",
        "SSH_AUTH_SOCK": "/tmp/aos-ambient-agent-canary",
        "GIT_ASKPASS": "/tmp/aos-ambient-git-canary",
        "HTTPS_PROXY": "http://aos-ambient-proxy-canary",
        "CODEX_HOME": "/tmp/aos-controller-state-canary",
    }.items():
        monkeypatch.setenv(name, value)

    report = run_synthetic_acp_fixture(
        build_runtime_spec(RUNTIME, BUNDLE), FIXTURE, "plan", timeout_seconds=45
    )
    assert report["ok"] is True, report
    assert report["net_namespace"] != os.readlink("/proc/self/ns/net")
    assert report["pid_namespace"] != os.readlink("/proc/self/ns/pid")
    assert report["default_route_present"] is False
    assert report["non_loopback_socket_seen"] is False
    assert {
        endpoint["local_class"] for endpoint in report["socket_census"]
    } <= {"loopback", "unspecified"}
    assert {
        endpoint["remote_class"] for endpoint in report["socket_census"]
    } <= {"loopback", "unspecified"}
    assert report["child_fd_classes"] == ["pipe", "pipe", "pipe"]
    assert set(report["child_open_fd_classes"].values()) <= {
        "pipe", "socket", "anon_inode", "dev_null", "kimi_state", "pinned_runtime"
    }
    assert report["synthetic_secret_fd_inherited"] is False
    assert report["host_authority_fd_seen"] is False
    assert report["api_key_name_seen"] is False
    assert report["checkout_visible"] is False
    assert report["workspace_entries"] == []
    assert report["credential_canary_leaked"] is False
    assert report["kimi_children"] == []
    assert report["continuous_census_samples"] > 0
    assert report["hostile_window_samples"] > 0
    assert report["monitor_error"] is None
    assert report["monitor_stopped"] is True
    assert report["max_descendant_count"] == 1
    assert report["provider_process_count"] == 1
    assert set(report["namespace_ids"]) == {
        "user", "pid", "mnt", "net", "ipc", "uts", "cgroup"
    }
    assert report["cgroup_membership"]
    classifications = set(report["created_state_classifications"].values())
    assert classifications == {
        "IMMUTABLE_RUNTIME",
        "MUTABLE_NONSECRET_STATE",
        "FUTURE_CREDENTIAL_STATE",
        "LOG",
        "CACHE",
    }
