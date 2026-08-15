"""Provider-neutral out-of-process synthetic workspace worker tests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from agenticos.orchestration.models import Role
from agenticos.orchestration.protocol import (
    AGENT_PROTOCOL_SCHEMA,
    AgentCapability,
    AgentTaskRequest,
    DispatchIdentity,
    ProtocolLimits,
    ResultStatus,
)
from agenticos.orchestration.synthetic import (
    SyntheticScenario,
    build_synthetic_workspace_argv,
    validate_synthetic_process_output,
)
from agenticos.orchestration import synthetic_worker


def _request() -> AgentTaskRequest:
    return AgentTaskRequest(
        schema=AGENT_PROTOCOL_SCHEMA,
        identity=DispatchIdentity(
            project_id="project-c",
            task_id="build-c",
            task_generation=2,
            attempt=1,
            controller_epoch=4,
            lease_epoch=1,
            dispatch_nonce="1" * 32,
            repository_id="repo-c",
            baseline_commit="b" * 40,
            workspace_id="workspace-c",
            workspace_generation=2,
            reservation_id="reservation-c",
            checkpoint_digest="a" * 64,
        ),
        role=Role.BUILDER,
        provider_id="synthetic",
        model_id="deterministic-workspace-v1",
        workspace_mount="/workspace",
        instructions="Apply only the selected deterministic Slice C scenario.",
        acceptance_criteria=("Controller checkpoint captures the exact mutation.",),
        context_manifest=(),
        capabilities=(
            AgentCapability.READ_WORKSPACE,
            AgentCapability.WRITE_WORKSPACE,
            AgentCapability.RUN_BOUNDED_COMMANDS,
        ),
        limits=ProtocolLimits(
            max_events=16,
            max_event_bytes=16_384,
            max_output_bytes=131_072,
            max_context_entries=1,
            max_context_bytes=1024,
            max_processes=4,
            max_runtime_seconds=10,
        ),
    )


def _run_worker(scenario: SyntheticScenario) -> subprocess.CompletedProcess[bytes]:
    argv = build_synthetic_workspace_argv(_request(), scenario)
    script = Path(synthetic_worker.__file__)
    return subprocess.run(
        [sys.executable, str(script), *argv[2:]],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5.0,
        check=False,
    )


def test_workspace_argv_is_fixed_bounded_and_has_no_host_locator() -> None:
    argv = build_synthetic_workspace_argv(_request(), SyntheticScenario.SUCCESSFUL_EDIT)
    assert argv[:2] == ["/usr/bin/python3", "/opt/agenticos/worker.py"]
    assert argv[2:4] == ["--scenario", "SUCCESSFUL_EDIT"]
    assert all("repo-c" not in item and "workspace-c" not in item for item in argv)
    assert sum(len(item.encode("utf-8")) for item in argv) < 64 * 1024


def test_no_op_worker_emits_exact_bound_agent_abi() -> None:
    process = _run_worker(SyntheticScenario.NO_OP)
    assert process.returncode == 0, process.stderr.decode()

    outcome = validate_synthetic_process_output(_request(), process.stdout)

    assert outcome.accepted is True
    assert outcome.result is not None
    assert outcome.result.status is ResultStatus.NO_OP
    assert outcome.result.identity == _request().identity


def test_worker_successfully_mutates_only_deterministic_fixture_paths(tmp_path) -> None:
    tracked = tmp_path / "slice-c-tracked.txt"
    tracked.write_text("baseline\n", encoding="utf-8")

    kind, _ = synthetic_worker._scenario_action("SUCCESSFUL_EDIT", tmp_path)

    assert kind == "SUCCEEDED"
    assert tracked.read_bytes() == b"slice-c deterministic tracked edit\n"
    assert (tmp_path / "slice-c-created.txt").read_bytes() == (
        b"slice-c deterministic untracked file\n"
    )
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "slice-c-created.txt",
        "slice-c-tracked.txt",
    ]


def test_child_process_case_is_bounded_and_deterministic(tmp_path) -> None:
    kind, _ = synthetic_worker._scenario_action("CHILD_PROCESS_CASE", tmp_path)
    assert kind == "SUCCEEDED"
    assert (tmp_path / "slice-c-child.txt").read_bytes() == (
        b"slice-c deterministic child edit\n"
    )


def test_noncanonical_or_incomplete_worker_bytes_fail_closed() -> None:
    for raw in (
        b'{"schema":\n',
        b'{"kind":"STARTED"}\n',
        b'{"payload":"\xff"}\n',
    ):
        outcome = validate_synthetic_process_output(_request(), raw)
        assert outcome.accepted is False
        assert outcome.result is None


def test_required_slice_c_scenarios_are_exact() -> None:
    required = {
        "SUCCESSFUL_EDIT",
        "NO_OP",
        "INVALID_PATH_ATTEMPT",
        "DOT_GIT_ATTEMPT",
        "CRASH_AFTER_EDIT",
        "TIMEOUT_AFTER_EDIT",
        "CHILD_PROCESS_CASE",
        "POST_TERMINAL_MUTATION_ATTEMPT",
    }
    assert required <= {item.value for item in SyntheticScenario}


def test_follow_up_edit_is_a_real_bounded_workspace_mutation(tmp_path) -> None:
    kind, _ = synthetic_worker._scenario_action("FOLLOW_UP_EDIT", tmp_path)
    assert kind == "SUCCEEDED"
    assert (tmp_path / "follow-up.txt").read_bytes() == b"dependent work complete\n"
