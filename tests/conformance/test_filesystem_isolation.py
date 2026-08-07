"""Filesystem isolation experiments (Milestone 3A) — REAL host only.

Proves which layer supplies which guarantee:

    UnsafeLocalRunner        -> denied FS access SUCCEEDS (no isolation)
    CgroupProcessRunner      -> denied FS access SUCCEEDS (process containment
                                is NOT filesystem isolation)
    LandlockIsolatedRunner   -> denied FS access FAILS with EACCES
    BwrapIsolatedRunner      -> denied FS access FAILS (ENOENT/EACCES)

All denied targets are synthetic fixture canaries. Nothing touches real host
secrets. Gated behind real capability probes — never faked.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from agenticos.sandbox.containment import (
    CgroupProcessRunner,
    CancellationConfig,
    ContainmentState,
)
from agenticos.sandbox.evidence import EvidenceCollector
from agenticos.sandbox.isolation import (
    POLICY_ENV_VAR,
    SHIM_PATH,
    BwrapIsolatedRunner,
    FilesystemPolicy,
    LandlockIsolatedRunner,
    probe_landlock_enforcement,
    probe_unprivileged_namespaces,
)
from agenticos.sandbox.models import PolicyExpectation
from agenticos.sandbox.policy import default_policy, evaluate_result
from agenticos.sandbox.runner import UnsafeLocalRunner
from helpers import WORKER_PATH, minimal_env

pytestmark = pytest.mark.fs_isolation_linux

FAST = CancellationConfig(
    sigint_grace=0.5, sigterm_grace=0.5,
    empty_verify_timeout=5.0, poll_interval=0.05,
)


@pytest.fixture(scope="session")
def scope_ok():
    if not sys.platform.startswith("linux"):
        pytest.skip("requires a Linux host")
    support = CgroupProcessRunner.probe()
    if not support.supported:
        pytest.skip("transient scopes unavailable: " + "; ".join(support.reasons))
    return support


@pytest.fixture(scope="session")
def landlock_ok():
    if not sys.platform.startswith("linux"):
        pytest.skip("requires a Linux host")
    ok, reason = probe_landlock_enforcement()
    if not ok:
        pytest.skip(f"Landlock enforcement unusable: {reason}")
    return reason


@pytest.fixture(scope="session")
def bwrap_ok(scope_ok):
    import shutil

    if shutil.which("bwrap") is None:
        pytest.skip("bwrap not installed")
    ok, reason = probe_unprivileged_namespaces()
    if not ok:
        pytest.skip(f"unprivileged namespaces unusable: {reason}")
    return reason


@pytest.fixture
def fs_policy(layout):
    return FilesystemPolicy.for_layout(layout, WORKER_PATH)


@pytest.fixture
def unsafe(layout):
    return UnsafeLocalRunner(WORKER_PATH)


@pytest.fixture
def cg_runner(layout, scope_ok):
    return CgroupProcessRunner(WORKER_PATH, cancellation=FAST)


@pytest.fixture
def ll_runner(layout, scope_ok, landlock_ok, fs_policy):
    return LandlockIsolatedRunner(
        WORKER_PATH, fs_policy,
        cancellation=FAST,
        collector=EvidenceCollector(normalize_root=layout.root),
    )


@pytest.fixture
def bw_runner(layout, scope_ok, bwrap_ok, fs_policy):
    return BwrapIsolatedRunner(WORKER_PATH, fs_policy, cancellation=FAST)


def denied_path(layout):
    return layout.denied_sibling_file


# --------------------------------------------------------------------------
# Control group: the guarantee does NOT come from the process layer
# --------------------------------------------------------------------------

def test_baseline_unsafe_runner_allows_denied_reads(unsafe, layout, fixture_env):
    res = unsafe.run_scenario("FS-02", cwd=layout.assigned_worktree,
                              env=fixture_env, target=denied_path(layout))
    assert res.succeeded is True  # no isolation at all


def test_baseline_cgroup_runner_still_allows_denied_fs(cg_runner, layout, fixture_env):
    """Milestone 2 process containment intentionally does NOT restrict the
    filesystem — denied access must still succeed here."""
    for scenario in ("FS-02", "FS-04"):
        res = cg_runner.run_scenario(
            scenario, cwd=layout.assigned_worktree, env=fixture_env,
            target=denied_path(layout), base=layout.assigned_worktree,
        )
        assert res.succeeded is True, f"{scenario} unexpectedly denied"
        assert res.process.containment_state == ContainmentState.TERMINATED.value


# --------------------------------------------------------------------------
# Landlock: allowed operations keep working
# --------------------------------------------------------------------------

def test_landlock_allowed_operations(ll_runner, layout, fixture_env):
    assert ll_runner.run_scenario(
        "FS-01", cwd=layout.assigned_worktree, env=fixture_env,
        target=layout.allowed_file).succeeded is True
    assert ll_runner.run_scenario(
        "WRITE-01", cwd=layout.assigned_worktree, env=fixture_env,
        target=layout.assigned_worktree / "out.txt").succeeded is True
    ro = ll_runner.run_scenario(
        "FS-10", cwd=layout.assigned_worktree, env=fixture_env,
        target=layout.readonly_file)
    assert ro.succeeded is True
    assert ro.details["canary"] == layout.canaries["readonly"]


# --------------------------------------------------------------------------
# Landlock: denied operations are denied
# --------------------------------------------------------------------------

def test_landlock_denied_read_write_traversal(ll_runner, layout, fixture_env):
    read = ll_runner.run_scenario(
        "FS-02", cwd=layout.assigned_worktree, env=fixture_env,
        target=denied_path(layout))
    assert read.succeeded is False
    assert read.error_type == "PermissionError"

    write = ll_runner.run_scenario(
        "FS-03", cwd=layout.assigned_worktree, env=fixture_env,
        target=layout.sibling_worktree / "pwned.txt")
    assert write.succeeded is False
    assert write.error_type == "PermissionError"

    traversal = ll_runner.run_scenario(
        "FS-04", cwd=layout.assigned_worktree, env=fixture_env,
        target=denied_path(layout), base=layout.assigned_worktree)
    assert traversal.succeeded is False
    assert traversal.error_type == "PermissionError"


def test_landlock_symlink_escape_denied(ll_runner, layout, fixture_env):
    if not layout.symlink_supported:
        pytest.skip("symlink creation unsupported")
    link = layout.assigned_worktree / "evil-link.txt"
    os.symlink(denied_path(layout), link)
    read = ll_runner.run_scenario(
        "FS-05", cwd=layout.assigned_worktree, env=fixture_env, target=link)
    assert read.succeeded is False
    assert read.error_type == "PermissionError"
    write = ll_runner.run_scenario(
        "FS-06", cwd=layout.assigned_worktree, env=fixture_env, target=link)
    assert write.succeeded is False
    assert write.error_type == "PermissionError"


def test_landlock_rename_across_boundary_denied(ll_runner, layout, fixture_env):
    res = ll_runner.run_scenario(
        "FS-07", cwd=layout.assigned_worktree, env=fixture_env,
        target=denied_path(layout), base=layout.assigned_worktree)
    assert res.succeeded is False
    assert res.error_type == "PermissionError"
    assert denied_path(layout).is_file(), "denied file must not have moved"


def test_landlock_readonly_write_denied(ll_runner, layout, fixture_env):
    res = ll_runner.run_scenario(
        "FS-11", cwd=layout.assigned_worktree, env=fixture_env,
        target=layout.readonly_file)
    assert res.succeeded is False
    assert res.error_type == "PermissionError"
    assert layout.canaries["readonly"] in layout.readonly_file.read_text()


@pytest.mark.parametrize("mode", ["child", "grandchild", "setsid", "doublefork"])
def test_landlock_descendant_inheritance(ll_runner, layout, fixture_env, mode):
    """Restrictions must survive fork/exec, new sessions, and double fork."""
    res = ll_runner.run_scenario(
        "FS-09", cwd=layout.assigned_worktree, env=fixture_env,
        target=denied_path(layout), base=mode)
    assert res.succeeded is False, f"descendant ({mode}) read the denied file"
    assert res.details["descendant_opened"] is False
    assert res.details["descendant_error"] == "PermissionError"


def test_landlock_composition_keeps_process_containment(ll_runner, layout, fixture_env):
    """Filesystem denial AND process lifecycle containment simultaneously."""
    res = ll_runner.run_scenario(
        "FS-09", cwd=layout.assigned_worktree, env=fixture_env,
        target=denied_path(layout), base="doublefork")
    assert res.succeeded is False
    assert res.process.containment_state == ContainmentState.TERMINATED.value
    assert res.process.containment_unit


def test_landlock_preopened_fd_limitation(layout, landlock_ok, fs_policy):
    """Landlock does NOT revoke already-open file descriptors. The denied
    PATH is EACCES while the inherited FD remains readable — this is why
    AgenticOS must never pass sensitive FDs into a restricted worker."""
    fd = os.open(denied_path(layout), os.O_RDONLY)
    try:
        env = minimal_env()
        env[POLICY_ENV_VAR] = fs_policy.to_env_value()
        proc = subprocess.run(
            [sys.executable, str(SHIM_PATH), "--",
             sys.executable, str(WORKER_PATH), "--scenario", "FS-08",
             "--target", str(fd), "--base", str(denied_path(layout))],
            capture_output=True, text=True, pass_fds=(fd,),
            cwd=layout.assigned_worktree, env=env, timeout=30.0,
        )
        assert proc.returncode == 0, proc.stderr
        import json

        res = json.loads(proc.stdout.strip().splitlines()[-1])
        assert res["details"]["path_opened"] is False          # path: denied
        assert res["details"]["path_error"] == "PermissionError"
        assert res["details"]["fd_read"] is True               # fd: NOT revoked
        assert res["details"]["fd_canary_found"] is True
    finally:
        os.close(fd)


def test_landlock_conformance_against_default_policy(ll_runner, layout, fixture_env):
    """The same corpus + same policy now flips DENY scenarios to PASS."""
    policy = default_policy()
    for scenario, expectation in (("FS-01", PolicyExpectation.ALLOW),
                                  ("FS-02", PolicyExpectation.DENY)):
        res = ll_runner.run_scenario(
            scenario, cwd=layout.assigned_worktree, env=fixture_env,
            target=layout.allowed_file if scenario == "FS-01" else denied_path(layout))
        status = evaluate_result(res, expectation)
        assert status.value == "PASS", f"{scenario}: {status}"


# --------------------------------------------------------------------------
# Bubblewrap / mount-namespace experiment
# --------------------------------------------------------------------------

def test_bwrap_allowed_and_denied(bw_runner, layout, fixture_env):
    allowed = bw_runner.run_scenario(
        "FS-01", cwd=layout.assigned_worktree, env=fixture_env,
        target=layout.allowed_file)
    assert allowed.succeeded is True

    denied = bw_runner.run_scenario(
        "FS-02", cwd=layout.assigned_worktree, env=fixture_env,
        target=denied_path(layout))
    assert denied.succeeded is False
    # Under a mount-namespace view the denied path simply does not exist.
    assert denied.error_type in ("FileNotFoundError", "PermissionError")


def test_bwrap_traversal_and_descendant_denied(bw_runner, layout, fixture_env):
    traversal = bw_runner.run_scenario(
        "FS-04", cwd=layout.assigned_worktree, env=fixture_env,
        target=denied_path(layout), base=layout.assigned_worktree)
    assert traversal.succeeded is False

    child = bw_runner.run_scenario(
        "FS-09", cwd=layout.assigned_worktree, env=fixture_env,
        target=denied_path(layout), base="child")
    assert child.succeeded is False
    assert child.details["descendant_opened"] is False
    assert child.process.containment_state == ContainmentState.TERMINATED.value
