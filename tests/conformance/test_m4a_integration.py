"""Real-host integration tests for the Milestone 4A composed boundary."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from agenticos.sandbox.containment import CancellationConfig, CgroupProcessRunner
from agenticos.sandbox.evidence import EvidenceCollector
from agenticos.sandbox.isolation import probe_landlock_enforcement
from agenticos.sandbox.runtime_boundary import M4AProfile, probe_bubblewrap
from helpers import WORKER_PATH


pytestmark = [
    pytest.mark.m4a_linux,
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux M4A boundary"),
]

FAST = CancellationConfig(
    sigint_grace=0.5,
    sigterm_grace=0.5,
    empty_verify_timeout=5.0,
    poll_interval=0.05,
)


@pytest.fixture(scope="session")
def m4a_launcher(tmp_path_factory):
    if not sys.platform.startswith("linux"):
        pytest.skip("requires Linux")
    import subprocess

    output = tmp_path_factory.mktemp("m4a-launcher") / "fs_launcher"
    source = WORKER_PATH.parents[2] / "native" / "fs_launcher" / "fs_launcher.c"
    subprocess.run(
        [
            "cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
            "-Werror", "-O2", str(source), "-o", str(output),
        ],
        check=True,
    )
    return output


@pytest.fixture(scope="session")
def m4a_host_ok():
    support = CgroupProcessRunner.probe()
    if not support.supported:
        pytest.skip("transient scopes unavailable: " + "; ".join(support.reasons))
    landlock_ok, reason = probe_landlock_enforcement()
    if not landlock_ok:
        pytest.skip(f"Landlock enforcement unavailable: {reason}")
    bwrap = probe_bubblewrap()
    if not bwrap.supported:
        pytest.fail("required Bubblewrap boundary unavailable: " + "; ".join(bwrap.reasons))


@pytest.fixture
def m4a_runner(layout, m4a_launcher, m4a_host_ok):
    from agenticos.sandbox.m4a_runner import NamespaceLandlockRunner

    synthetic_home = layout.root / "m4a-home"
    synthetic_home.mkdir()
    return NamespaceLandlockRunner(
        worker_path=WORKER_PATH,
        workspace=layout.assigned_worktree,
        profile=M4AProfile.BUILD,
        launcher_path=m4a_launcher,
        task_tmp=layout.task_tmp,
        synthetic_home=synthetic_home,
        cancellation=FAST,
        collector=EvidenceCollector(normalize_root=layout.root),
    )


def test_block_fd_ordering_and_normal_exit(m4a_runner, layout):
    marker = layout.task_tmp / "worker-entry-marker"
    process = m4a_runner.run(
        [
            "/usr/bin/python3",
            "-c",
            "from pathlib import Path; "
            "Path('/tmp/worker-entry-marker').write_text('ran'); "
            "print('m4a-ok')",
        ],
        cwd="/workspace",
        env={"OPENAI_API_KEY": "AOS_CANARY_openai"},
        _marker_path=marker,
    )

    assert process.exit_code == 0
    assert process.stdout.strip() == "m4a-ok"
    assert marker.read_text() == "ran"
    assert m4a_runner.last_ordering_observations == {
        "namespace_status_before_release": True,
        "namespace_verified_before_release": True,
        "launcher_entered_before_namespace_release": False,
        "worker_entered_before_namespace_release": False,
        "launcher_entered_after_namespace_release": True,
        "worker_entered_before_exec_release": False,
    }
    kinds = [record.kind for record in m4a_runner.collector.records]
    required_order = [
        "CONTAINMENT_VERIFIED",
        "NAMESPACE_BOUNDARY_VERIFIED",
        "TRUSTED_LAUNCHER_ENTERED",
        "FD_SET_SANITIZED",
        "SANDBOX_IDENTITIES_VERIFIED",
        "FILESYSTEM_POLICY_PREPARED",
        "NO_NEW_PRIVS_SET",
        "FILESYSTEM_POLICY_APPLIED",
        "WORKER_EXEC_ATTEMPTED",
        "CGROUP_EMPTY_VERIFIED",
    ]
    assert [kind for kind in kinds if kind in required_order] == required_order
    evidence = m4a_runner.last_namespace_evidence
    assert evidence is not None and evidence.verified is True
    assert process.containment_cgroup is not None
    assert process.containment_cgroup.endswith(evidence.child.cgroup)
