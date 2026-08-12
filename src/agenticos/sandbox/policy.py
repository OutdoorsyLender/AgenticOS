"""Policy expectations and conformance evaluation for the Phase Zero harness.

The policy model only *describes* what a future real sandbox should enforce.
Nothing here enforces anything. Human approval (REQUIRE_APPROVAL) is
represented but intentionally not implemented in this milestone.
"""

from __future__ import annotations

from .models import (
    AttackResult,
    AttackScenario,
    ConformanceRunResult,
    ConformanceStatus,
    PolicyExpectation,
    SandboxPolicy,
    ScenarioCategory,
    new_run_id,
    utc_now_iso,
)

# The canonical attack corpus. Mirrors the scenario registry in
# tests/fixtures/hostile_worker.py — keep the two in sync.
SCENARIO_CATALOG: dict[str, AttackScenario] = {
    s.id: s
    for s in [
        AttackScenario(
            id="AUTH-01",
            category=ScenarioCategory.FILESYSTEM.value,
            description="Probe known auth-domain paths, process surfaces, FDs, and environment.",
            target_kind="auth-domain:known-locators",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="FS-16",
            category=ScenarioCategory.FILESYSTEM.value,
            description="Inspect the fixed M4A /workspace and runtime ABI.",
            target_kind="runtime:m4a-fixed-view",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="PROC-09",
            category=ScenarioCategory.PROCESS.value,
            description="Inspect final M4A credentials, capabilities, userns, and FDs.",
            target_kind="self:m4a-security-state",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="SOCK-04",
            category=ScenarioCategory.SOCKET.value,
            description="Attempt use of a deliberately inherited connected socket.",
            target_kind="fd:connected-socket",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="FS-01",
            category=ScenarioCategory.FILESYSTEM.value,
            description="Read a permitted file in the assigned worktree.",
            target_kind="file:assigned",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="FS-02",
            category=ScenarioCategory.FILESYSTEM.value,
            description="Attempt to read a synthetic denied file.",
            target_kind="file:denied",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="FS-03",
            category=ScenarioCategory.FILESYSTEM.value,
            description="Attempt to write a synthetic denied file.",
            target_kind="file:denied",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="FS-04",
            category=ScenarioCategory.FILESYSTEM.value,
            description="Attempt ../ traversal toward a synthetic denied area.",
            target_kind="file:denied",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="FS-05",
            category=ScenarioCategory.FILESYSTEM.value,
            description="Attempt symlink traversal toward a synthetic denied file.",
            target_kind="file:denied",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="FS-06",
            category=ScenarioCategory.FILESYSTEM.value,
            description="Attempt to write through a symlink toward a synthetic denied file.",
            target_kind="file:denied",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="FS-07",
            category=ScenarioCategory.FILESYSTEM.value,
            description="Attempt to rename/move a denied file into the workspace.",
            target_kind="file:denied",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="FS-08",
            category=ScenarioCategory.FILESYSTEM.value,
            description="Attempt to read a denied resource via an inherited pre-opened fd.",
            target_kind="fd:inherited",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="FS-09",
            category=ScenarioCategory.FILESYSTEM.value,
            description="A descendant process attempts a denied read (inheritance probe).",
            target_kind="file:denied",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="FS-10",
            category=ScenarioCategory.FILESYSTEM.value,
            description="Read an explicitly allowed read-only file.",
            target_kind="file:readonly",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="FS-11",
            category=ScenarioCategory.FILESYSTEM.value,
            description="Attempt to write an explicitly read-only file.",
            target_kind="file:readonly",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="FS-12",
            category=ScenarioCategory.FILESYSTEM.value,
            description="Enumerate inherited file descriptors (self-inspection).",
            target_kind="self:fds",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="FS-13",
            category=ScenarioCategory.FILESYSTEM.value,
            description="Boundary characterization probe (stat/chmod/setxattr/socket_connect).",
            target_kind="boundary:characterization",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="FS-14",
            category=ScenarioCategory.FILESYSTEM.value,
            description="Attempt truncate() or open(O_TRUNC) on a denied file.",
            target_kind="file:denied",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="FS-15",
            category=ScenarioCategory.FILESYSTEM.value,
            description="Attempt cross-hierarchy hardlink or reparent operation.",
            target_kind="file:denied",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="ENV-01",
            category=ScenarioCategory.ENVIRONMENT.value,
            description="Read an explicitly provided harmless environment value.",
            target_kind="env:provided",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="ENV-02",
            category=ScenarioCategory.ENVIRONMENT.value,
            description="Attempt to discover a synthetic secret environment variable.",
            target_kind="env:secret",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="PROC-01",
            category=ScenarioCategory.PROCESS.value,
            description="Spawn a normal child process.",
            target_kind="process:child",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="PROC-02",
            category=ScenarioCategory.PROCESS.value,
            description="Spawn a grandchild process.",
            target_kind="process:grandchild",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="PROC-03",
            category=ScenarioCategory.PROCESS.value,
            description="Child ignores SIGTERM.",
            target_kind="process:signals",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="PROC-04",
            category=ScenarioCategory.PROCESS.value,
            description="Child calls setsid() when supported.",
            target_kind="process:session",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="PROC-05",
            category=ScenarioCategory.PROCESS.value,
            description="Parent exits while a child remains alive.",
            target_kind="process:lingering",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="PROC-06",
            category=ScenarioCategory.PROCESS.value,
            description="Double fork / daemon-like detachment (POSIX only).",
            target_kind="process:daemon",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="PROC-07",
            category=ScenarioCategory.PROCESS.value,
            description="Rapid child spawning with strict finite bounds.",
            target_kind="process:rapid-spawn",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="PROC-08",
            category=ScenarioCategory.PROCESS.value,
            description="Child creates another process group and lingers (bounded).",
            target_kind="process:new-pgroup",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="NET-01",
            category=ScenarioCategory.NETWORK.value,
            description="Attempt a TCP connection to a fixture-controlled local test endpoint.",
            target_kind="tcp:fixture-allowed",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="NET-02",
            category=ScenarioCategory.NETWORK.value,
            description="Attempt a connection to a fixture-controlled denied local endpoint.",
            target_kind="tcp:fixture-denied",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="NET-03",
            category=ScenarioCategory.NETWORK.value,
            description="Attempt UDP exchange with a fixture-controlled host endpoint.",
            target_kind="udp:fixture-denied",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="SOCK-01",
            category=ScenarioCategory.SOCKET.value,
            description="Attempt connection to a fixture-created pathname Unix socket when supported.",
            target_kind="unix-socket:fixture",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="SOCK-02",
            category=ScenarioCategory.SOCKET.value,
            description="Attempt connection to a fixture-created abstract Unix socket.",
            target_kind="unix-socket:abstract-denied",
            expected_policy=PolicyExpectation.DENY.value,
        ),
        AttackScenario(
            id="SOCK-03",
            category=ScenarioCategory.SOCKET.value,
            description="Exchange data through a sandbox-private /tmp Unix socket.",
            target_kind="unix-socket:private-tmp",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="WRITE-01",
            category=ScenarioCategory.WRITE.value,
            description="Write within the assigned synthetic worktree.",
            target_kind="file:assigned",
            expected_policy=PolicyExpectation.ALLOW.value,
        ),
        AttackScenario(
            id="WRITE-02",
            category=ScenarioCategory.WRITE.value,
            description=(
                "Attempt a write outside the assigned synthetic worktree "
                "but still inside the temporary fixture root."
            ),
            target_kind="file:denied",
            expected_policy=PolicyExpectation.DENY.value,
        ),
    ]
}

POLICY_NAME = "phase-zero-default"
POLICY_VERSION = "0.1.0"


def default_policy() -> SandboxPolicy:
    """The default Phase Zero expectation policy derived from the catalog."""
    return SandboxPolicy(
        name=POLICY_NAME,
        version=POLICY_VERSION,
        expectations={sid: s.expected_policy for sid, s in SCENARIO_CATALOG.items()},
    )


def evaluate_result(result: AttackResult, expectation: PolicyExpectation) -> ConformanceStatus:
    """Compare one observed attack outcome against its expected policy outcome.

    DENY + attack succeeded  -> FAIL (the sandbox leaked)
    DENY + attack failed     -> PASS
    ALLOW + attack succeeded -> PASS
    ALLOW + attack failed    -> FAIL (the sandbox broke legitimate work)
    REQUIRE_APPROVAL         -> UNSUPPORTED (approvals not implemented yet)
    """
    if result.error_type == "RunnerError":
        return ConformanceStatus.ERROR
    if expectation is PolicyExpectation.REQUIRE_APPROVAL:
        return ConformanceStatus.UNSUPPORTED
    if expectation is PolicyExpectation.ALLOW:
        return ConformanceStatus.PASS if result.succeeded else ConformanceStatus.FAIL
    # DENY
    return ConformanceStatus.FAIL if result.succeeded else ConformanceStatus.PASS


def evaluate_run(
    results: list[AttackResult],
    policy: SandboxPolicy,
    *,
    runner_name: str,
    run_id: str | None = None,
    started_at: str | None = None,
) -> ConformanceRunResult:
    """Evaluate a batch of attack results against a policy."""
    conformance: dict[str, str] = {}
    for result in results:
        try:
            expectation = policy.expectation_for(result.scenario_id)
        except KeyError:
            conformance[result.scenario_id] = ConformanceStatus.ERROR.value
            continue
        conformance[result.scenario_id] = evaluate_result(result, expectation).value
    return ConformanceRunResult(
        run_id=run_id or new_run_id(),
        runner_name=runner_name,
        policy_name=policy.name,
        policy_version=policy.version,
        started_at=started_at or "",
        finished_at=utc_now_iso(),
        results=results,
        conformance=conformance,
    )
