"""Composed M4A reverse-boundary proof for the auth domain."""

from __future__ import annotations

import sys

import pytest

from agenticos.sandbox.controller_auth_helper import ControllerAuthHelper
from agenticos.sandbox.models import ConformanceStatus, PolicyExpectation
from agenticos.sandbox.policy import evaluate_result
from test_m4a_integration import m4a_host_ok, m4a_launcher, m4a_runner  # noqa: F401


pytestmark = [
    pytest.mark.m4a_linux,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux Level A claim"),
]


CANARIES = (
    "AOS_CANARY_AUTH_REFRESH_2C1",
    "AOS_CANARY_AUTH_ACCESS_2C1",
    "AOS_CANARY_AUTH_ACCOUNT_2C1",
)


def test_m4a_hostile_workspace_cannot_reach_auth_domain(
    m4a_runner, layout,
) -> None:
    controller_state = layout.root / "controller-auth-state"
    controller_state.write_text("AOS_CANARY_CONTROLLER_STATE_2C1", encoding="ascii")
    auth_data = {
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": CANARIES[1],
            "refresh_token": CANARIES[0],
            "account_id": CANARIES[2],
            "expires_at": 1_900_000_000,
        },
    }
    with ControllerAuthHelper(auth_data) as helper:
        attack = m4a_runner.run_scenario(
            "AUTH-01",
            cwd="/workspace",
            env={},
            auth_root=helper._private_root,
            auth_file=helper._auth_json_path,
            controller_state=controller_state,
            helper_pid=helper.process_identity.pid,
        )
        process = attack.process
        assert process is not None
        assert process.exit_code == 0, process.stderr
        result = attack.to_dict()
        assert result["scenario_id"] == "AUTH-01"
        assert result["succeeded"] is False
        assert evaluate_result(attack, PolicyExpectation.DENY) is ConformanceStatus.PASS
        assert result["details"]["open_fds"] == [0, 1, 2]
        assert result["details"]["socket_fds"] == []
        assert result["details"]["auth_environment_names"] == []
        assert result["details"]["auth_environment_authority_present"] is False
        assert all(
            not operation["succeeded"]
            and operation["errno_name"] in ("ENOENT", "EACCES", "EPERM", "EXDEV")
            for operation in result["details"]["operations"]
        )
        combined = process.stdout + process.stderr + repr(m4a_runner.collector.records)
        assert all(canary not in combined for canary in CANARIES)
        workspace_contents = "".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in layout.assigned_worktree.rglob("*")
            if path.is_file()
        )
        assert all(canary not in workspace_contents for canary in CANARIES)

    assert m4a_runner.last_launch_outcome is not None
    assert any(
        record.kind == "CGROUP_EMPTY_VERIFIED"
        for record in m4a_runner.collector.records
    )
