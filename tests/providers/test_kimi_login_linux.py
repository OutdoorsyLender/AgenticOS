"""Native WSL qualification for the owner-login containment boundary."""

from __future__ import annotations

import json
import itertools
import os
from pathlib import Path
import socket
import subprocess
import time

import pytest

from agenticos.providers.kimi_login import (
    AuthRelayResult,
    KimiAuthRelay,
    KimiLoginSpec,
    build_login_bwrap_argv,
    default_login_spec,
    open_validated_credential_root,
    provision_empty_credential_root,
    receive_listener_fd,
    validate_login_spec,
)


RUNTIME = Path(
    "/home/brand/.local/share/agenticos/provider-qualification/"
    "kimi-code/0.36.1/runtime/bin/kimi"
)
TASK_BUDGET_FIXTURE = (
    Path(__file__).parent / "fixtures" / "kimi_task_budget_fixture.py"
).resolve()
POST_AUTH_FIXTURE = (
    Path(__file__).parent / "fixtures" / "kimi_post_auth_fixture.py"
).resolve()
POST_AUTH_NAMESPACE_FIXTURE = POST_AUTH_FIXTURE.with_name(
    "kimi_post_auth_namespace_fixture.py"
)
_UNIT_SEQUENCE = itertools.count(1)


pytestmark = pytest.mark.skipif(
    os.name != "posix" or not RUNTIME.exists(), reason="pinned native WSL runtime required"
)


def test_real_pinned_login_spec_revalidates_without_running_login(tmp_path: Path) -> None:
    """The real executable/config/profile pass while the credential leaf remains empty."""

    spec = default_login_spec()
    state_root = tmp_path / "state"
    provision_empty_credential_root(state_root, expected_uid=os.getuid())
    validate_login_spec(
        KimiLoginSpec(spec.executable, spec.bundle, state_root, spec.namespace_launcher),
        expected_uid=os.getuid(),
    )
    assert list((state_root / "credentials").iterdir()) == []


def test_real_bwrap_netns_handoff_denies_api_without_kimi_or_oauth(tmp_path: Path) -> None:
    """The actual namespace listener reaches only the opaque relay's denied API branch."""

    executable = tmp_path / "unused-kimi"
    executable.write_bytes(b"synthetic executable never invoked")
    executable.chmod(0o555)
    bundle = tmp_path / "bundle"
    (bundle / "agents").mkdir(parents=True)
    (bundle / "config.toml").write_text("synthetic\n", encoding="utf-8")
    (bundle / "agents" / "agent.md").write_text("synthetic\n", encoding="utf-8")
    state_root = tmp_path / "state"
    provision_empty_credential_root(state_root, expected_uid=os.getuid())
    fixture = (
        Path(__file__).parent / "fixtures" / "kimi_login_namespace_fixture.py"
    ).resolve()
    spec = KimiLoginSpec(executable, bundle, state_root, fixture)
    parent, child = socket.socketpair()
    credential_fd = open_validated_credential_root(state_root, expected_uid=os.getuid())
    process = subprocess.Popen(
        build_login_bwrap_argv(
            spec, handoff_fd=child.fileno(), credential_fd=credential_fd
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={},
        close_fds=True,
        pass_fds=(child.fileno(), credential_fd),
        start_new_session=True,
    )
    os.close(credential_fd)
    child.close()
    relay = None
    try:
        parent.settimeout(5)
        listener = receive_listener_fd(parent)
        relay = KimiAuthRelay(listener)
        relay.start()
        stdout, stderr = process.communicate(timeout=10)
    finally:
        parent.close()
        if relay is not None:
            relay.stop()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
    assert process.returncode == 0
    assert stderr == b""
    report = json.loads(stdout)
    assert report["schema"] == "AOS_KIMI_LOGIN_NAMESPACE_FIXTURE/1"
    assert report["api_denied"] is True
    assert report["net_namespace"] != os.readlink("/proc/self/ns/net")
    assert relay is not None
    assert len(relay.observations) == 1
    assert relay.observations[0].result is AuthRelayResult.DENIED
    assert relay.observations[0].hostname == "api.kimi.com"
    assert list((state_root / "credentials").iterdir()) == []


def _run_task_budget_fixture(mode: str, tasks_max: int) -> dict[str, object]:
    assert TASK_BUDGET_FIXTURE.is_file(), "native task-budget fixture is missing"
    unit = (
        "aos-kimi-owner-login"
        if mode == "preflight"
        else f"aos-kimi-budget-test-{os.getpid()}-{next(_UNIT_SEQUENCE)}"
    )
    completed = subprocess.run(
        [
            "/usr/bin/systemd-run",
            "--user",
            "--scope",
            "--collect",
            "--quiet",
            f"--unit={unit}",
            "--property=KillMode=control-group",
            "--property=TimeoutStopSec=5s",
            f"--property=TasksMax={tasks_max}",
            "--property=MemoryMax=1G",
            "/usr/bin/python3",
            str(TASK_BUDGET_FIXTURE),
            f"--mode={mode}",
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=30,
    )
    lines = [line for line in completed.stdout.splitlines() if line]
    assert len(lines) == 1
    assert completed.stderr == ""
    report = json.loads(lines[0])
    deadline = time.monotonic() + 3
    unit_state = ""
    while time.monotonic() < deadline:
        observed = subprocess.run(
            [
                "/usr/bin/systemctl",
                "--user",
                "show",
                f"{unit}.scope",
                "--property=LoadState",
                "--property=ControlGroup",
                "--no-pager",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=2,
        )
        unit_state = observed.stdout
        if "LoadState=not-found" in unit_state and "ControlGroup=\n" in unit_state:
            break
        time.sleep(0.05)
    assert "LoadState=not-found" in unit_state
    assert "ControlGroup=\n" in unit_state
    return report


def test_tasksmax_16_preflight_and_pinned_topology_fail_without_provider_network() -> None:
    """The old ceiling must fail before launch and at the measured resolver boundary."""

    preflight = _run_task_budget_fixture("preflight", 16)
    assert preflight["result"] == "LOGIN_TASK_BUDGET_INSUFFICIENT"
    assert preflight["provider_launch_attempted"] is False
    assert preflight["external_network_attempted"] is False

    topology = _run_task_budget_fixture("topology", 16)
    assert topology["resolver_worker_start"] == "FAILED"
    assert topology["resolver_worker_error"] == "can't start new thread"
    assert topology["relay_reason"] == "TASK_BUDGET_EXHAUSTED"
    assert topology["before_resolver_worker"]["pids_current"] == 16
    assert topology["before_resolver_worker"]["pids_max"] == 16
    assert topology["before_resolver_worker"]["process_count"] == 4
    assert topology["before_resolver_worker"]["thread_count"] == 16
    assert topology["process_peak"] == 4
    assert topology["expected_active_relay_connections"] == 1
    assert topology["after_resolver_worker"]["pids_events_max"] == 1
    assert topology["external_network_attempted"] is False
    assert topology["credential_state"] == "EMPTY"
    assert topology["after_cleanup"]["pids_current"] == 1


def test_tasksmax_21_has_measured_headroom_and_completes_synthetic_tls() -> None:
    """The 17+4 bound must admit the resolver and a complete opaque TLS fixture."""

    preflight = _run_task_budget_fixture("preflight", 21)
    assert preflight["result"] == "PASSED"
    assert preflight["provider_launch_attempted"] is False
    assert preflight["external_network_attempted"] is False

    topology = _run_task_budget_fixture("topology", 21)
    assert topology["resolver_worker_start"] == "SUCCEEDED"
    assert topology["resolver_outcome"] == "resolved"
    assert topology["before_resolver_worker"]["thread_count"] == 16
    assert topology["peak_tasks"] == 17
    assert topology["process_peak"] == 4
    assert topology["expected_active_relay_connections"] == 1
    assert topology["qualified_tasks_max"] == 21
    assert topology["headroom"] == 4
    assert topology["pids_events_max"] == 0
    assert topology["external_network_attempted"] is False
    assert topology["credential_state"] == "EMPTY"

    tls = _run_task_budget_fixture("tls", 21)
    assert tls["relay_result"] == "COMPLETED"
    assert tls["hostname"] == "auth.kimi.com"
    assert tls["resolver_outcome"] == "resolved"
    assert tls["peak_tasks"] < 21
    assert tls["pids_events_max"] == 0
    assert tls["external_network_attempted"] is False
    assert tls["after_cleanup"]["pids_current"] == 1


def test_tasksmax_21_remains_a_hard_ceiling_for_task_explosion() -> None:
    """Unexpected task creation must hit pids.max and still drain completely."""

    report = _run_task_budget_fixture("explosion", 21)
    assert report["task_creation_denied"] is True
    assert report["task_start_error"] == "can't start new thread"
    assert report["peak_tasks"] == 21
    assert report["pids_events_max"] >= 1
    assert report["after_cleanup"]["pids_current"] == 1


def test_synthetic_post_auth_device_flow_completes_and_drains() -> None:
    """The full fake flow must write only synthetic state and leave zero residue."""

    assert POST_AUTH_FIXTURE.is_file(), "synthetic post-auth fixture is missing"
    sources = (
        POST_AUTH_FIXTURE.read_text(encoding="utf-8"),
        POST_AUTH_NAMESPACE_FIXTURE.read_text(encoding="utf-8"),
    )
    assert all(
        "/home/brand/.local/share/agenticos/provider-state" not in source
        for source in sources
    )
    unit = f"aos-kimi-post-auth-test-{os.getpid()}-{next(_UNIT_SEQUENCE)}"
    completed = subprocess.run(
        [
            "/usr/bin/systemd-run",
            "--user",
            "--scope",
            "--collect",
            "--quiet",
            f"--unit={unit}",
            "--property=KillMode=control-group",
            "--property=TimeoutStopSec=5s",
            "--property=TasksMax=21",
            "--property=MemoryMax=1G",
            "/usr/bin/python3",
            str(POST_AUTH_FIXTURE),
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=30,
    )
    report = json.loads(completed.stdout)
    assert completed.stderr == ""
    assert report == {
        "after_cleanup_tasks": 1,
        "cleanup_result": "COMPLETED",
        "credential_state": "PRESENT",
        "device_authorization": "COMPLETED",
        "external_network_attempted": False,
        "owner_approval_transition": "COMPLETED",
        "pending_poll_count": 2,
        "primary_login_result": "COMPLETED",
        "process_returncode": 0,
        "real_credential_root_referenced": False,
        "relay_active_connections": 0,
        "relay_result": "COMPLETED",
        "schema": "AOS_KIMI_POST_AUTH_FIXTURE/1",
        "synthetic_atomic_credential_write": "COMPLETED",
        "synthetic_token_response": "COMPLETED",
        "top_level_error": None,
    }
    deadline = time.monotonic() + 3
    unit_state = ""
    while time.monotonic() < deadline:
        observed = subprocess.run(
            [
                "/usr/bin/systemctl",
                "--user",
                "show",
                f"{unit}.scope",
                "--property=LoadState",
                "--property=ControlGroup",
                "--no-pager",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=2,
        )
        unit_state = observed.stdout
        if "LoadState=not-found" in unit_state and "ControlGroup=\n" in unit_state:
            break
        time.sleep(0.05)
    assert "LoadState=not-found" in unit_state
    assert "ControlGroup=\n" in unit_state
