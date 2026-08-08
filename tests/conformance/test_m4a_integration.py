"""Real-host integration tests for the Milestone 4A composed boundary."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from agenticos.sandbox.containment import (
    CancellationConfig,
    CgroupProcessRunner,
    ContainmentUnavailableError,
)
from agenticos.sandbox.evidence import EvidenceCollector
from agenticos.sandbox.isolation import probe_landlock_enforcement
from agenticos.sandbox.runtime_boundary import (
    AuthorizedSource,
    M4AProfile,
    probe_bubblewrap,
    secure_open_source,
)
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


def _runtime_runner(layout, m4a_launcher, profile):
    from agenticos.sandbox.m4a_runner import NamespaceLandlockRunner

    synthetic_home = layout.root / f"m4a-home-{profile.value}"
    synthetic_home.mkdir()
    return NamespaceLandlockRunner(
        worker_path=WORKER_PATH,
        workspace=layout.assigned_worktree,
        profile=profile,
        launcher_path=m4a_launcher,
        task_tmp=layout.task_tmp,
        synthetic_home=synthetic_home,
        cancellation=FAST,
        collector=EvidenceCollector(normalize_root=layout.root),
    )


def _run_worker(runner, *worker_args):
    process = runner.run(
        ["/usr/bin/python3", "/opt/agenticos/worker.py", *worker_args],
        cwd="/workspace",
        env={"AOS_HOST_ONLY": "AOS_CANARY_must_not_cross"},
    )
    assert process.exit_code == 0, process.stderr
    return process, json.loads(process.stdout)


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


@pytest.mark.parametrize(
    ("profile", "write_allowed"),
    [(M4AProfile.INSPECT, False), (M4AProfile.BUILD, True)],
)
def test_workspace_identity_runtime_view_and_profiled_write(
    layout, m4a_launcher, m4a_host_ok, profile, write_allowed
):
    (layout.assigned_worktree / "host-locator-probe.txt").write_text(
        "\n".join(
            str(path)
            for path in (
                layout.assigned_worktree,
                layout.sibling_worktree,
                layout.agenticos_private,
                layout.fake_home,
            )
        )
    )
    runner = _runtime_runner(layout, m4a_launcher, profile)
    process, result = _run_worker(runner, "--scenario", "M4A-01")

    assert result["succeeded"] is True, result
    details = result["details"]
    observed = details["workspace_identity"]
    authorized = layout.assigned_worktree.stat()
    assert (observed["device"], observed["inode"]) == (
        authorized.st_dev,
        authorized.st_ino,
    )
    assert details["cwd"] == "/workspace"
    assert details["pwd"] == "/workspace"
    assert details["fixed_paths"] == {
        path: True
        for path in (
            "/bin", "/dev", "/home", "/lib", "/lib64", "/opt", "/proc",
            "/run", "/sbin", "/tmp", "/usr", "/workspace",
        )
    }
    assert details["runtime_python"].startswith("/usr/bin/python3")
    assert details["workspace_canary_readable"] is True
    assert details["workspace_write_succeeded"] is write_allowed
    assert details["private_tmp_write_succeeded"] is True
    assert details["synthetic_home_write_succeeded"] is True
    assert details["sibling_visible"] is False
    assert details["agenticos_private_visible"] is False
    assert details["host_fake_home_visible"] is False
    assert details["windows_mount_visible"] is False
    assert details["host_locator_visibility"] == [False, False, False, False]
    assert "AOS_HOST_ONLY" not in details["environment_names"]
    assert str(layout.assigned_worktree) not in process.stdout


def test_substituted_workspace_source_is_rejected_before_hostile_exec(
    m4a_runner, layout, monkeypatch
):
    original_open = m4a_runner._open_runtime_sources
    marker = layout.task_tmp / "substituted-source-worker-ran"

    def substitute_source():
        sources = list(original_open())
        wrong = secure_open_source(layout.sibling_worktree, expected_type=stat.S_IFDIR)
        os.close(sources[0].fd)
        sources[0] = AuthorizedSource(
            sources[0].locator, wrong.fd, sources[0].identity
        )
        return tuple(sources)

    monkeypatch.setattr(m4a_runner, "_open_runtime_sources", substitute_source)
    with pytest.raises(ContainmentUnavailableError):
        m4a_runner.run(
            [
                "/usr/bin/python3", "-c",
                "from pathlib import Path; Path('/tmp/substituted-source-worker-ran').touch()",
            ],
            cwd="/workspace",
            env={},
            _marker_path=marker,
        )
    assert not marker.exists()


def test_workspace_replacement_after_authorization_mounts_opened_identity_safely(
    m4a_runner, layout, monkeypatch
):
    original_open = m4a_runner._open_runtime_sources
    authorized_object = layout.root / "authorized-object-after-rename"

    def replace_locator_after_open():
        sources = original_open()
        layout.assigned_worktree.rename(authorized_object)
        layout.assigned_worktree.mkdir()
        (layout.assigned_worktree / "allowed.txt").write_text("replacement")
        return sources

    monkeypatch.setattr(
        m4a_runner, "_open_runtime_sources", replace_locator_after_open
    )
    try:
        process = m4a_runner.run(
            [
                "/usr/bin/python3", "-c",
                "import os; print(os.stat('/workspace').st_ino); "
                "print(open('/workspace/allowed.txt').read().splitlines()[0])",
            ],
            cwd="/workspace",
            env={},
        )
        lines = process.stdout.splitlines()
        assert process.exit_code == 0
        assert int(lines[0]) == authorized_object.stat().st_ino
        assert lines[1] == "permitted worktree file"
    finally:
        if layout.assigned_worktree.exists():
            for child in layout.assigned_worktree.iterdir():
                child.unlink()
            layout.assigned_worktree.rmdir()
        if authorized_object.exists():
            authorized_object.rename(layout.assigned_worktree)


def test_changed_workspace_destination_is_rejected_before_hostile_exec(
    m4a_runner, layout, monkeypatch
):
    import agenticos.sandbox.m4a_runner as runner_module

    original_build = runner_module.build_bwrap_argv
    marker = layout.task_tmp / "changed-destination-worker-ran"

    def change_destination(plan, **kwargs):
        argv = original_build(plan, **kwargs)
        workspace_fd = str(plan.mount_for("/workspace").source.fd)
        for index, item in enumerate(argv):
            if item in ("--bind-fd", "--ro-bind-fd") and argv[index + 1] == workspace_fd:
                argv[index + 2] = "/unexpected-workspace"
                break
        return argv

    monkeypatch.setattr(runner_module, "build_bwrap_argv", change_destination)
    with pytest.raises(ContainmentUnavailableError):
        m4a_runner.run(
            [
                "/usr/bin/python3", "-c",
                "from pathlib import Path; Path('/tmp/changed-destination-worker-ran').touch()",
            ],
            cwd="/workspace",
            env={},
            _marker_path=marker,
        )
    assert not marker.exists()


def test_wrong_workspace_object_type_is_rejected_before_hostile_exec(
    m4a_runner, layout, monkeypatch
):
    original_open = m4a_runner._open_runtime_sources
    marker = layout.task_tmp / "wrong-type-worker-ran"
    wrong_file = layout.root / "wrong-workspace-object"
    wrong_file.write_text("not a directory")

    def substitute_wrong_type():
        sources = list(original_open())
        wrong = secure_open_source(wrong_file, expected_type=stat.S_IFREG)
        os.close(sources[0].fd)
        sources[0] = AuthorizedSource(
            sources[0].locator, wrong.fd, sources[0].identity
        )
        return tuple(sources)

    monkeypatch.setattr(m4a_runner, "_open_runtime_sources", substitute_wrong_type)
    with pytest.raises(ContainmentUnavailableError):
        m4a_runner.run(
            [
                "/usr/bin/python3", "-c",
                "from pathlib import Path; Path('/tmp/wrong-type-worker-ran').touch()",
            ],
            cwd="/workspace",
            env={},
            _marker_path=marker,
        )
    assert not marker.exists()
