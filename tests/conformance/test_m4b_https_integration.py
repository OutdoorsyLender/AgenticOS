"""Real-host integration proof for the M4B-2 slice-9a HTTPS material plumbing.

Full launches through the authenticated M4B-1 broker boundary carrying the
sealed NetworkPolicy and sealed task certificate material.  Slice 9a proves
material + policy plumbing only: the broker verifies, loads, and CLOSES the
material before readiness, then runs the unchanged DENY loop (dispatch is
slice 9b).  Conventions mirror test_m4b_integration.py.
"""

from __future__ import annotations

import sys

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("M4B-2 HTTPS real-host proof requires Linux", allow_module_level=True)

import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from agenticos.sandbox import host_qualification as hq
from agenticos.sandbox import m4b_runner as runner_module
from agenticos.sandbox.cert_helper import generate_task_material
from agenticos.sandbox.evidence import EvidenceCollector
from agenticos.sandbox.network_https import (
    GrantPurpose,
    NetworkGrant,
    NetworkPolicy,
    create_sealed_network_policy_fd,
)
from agenticos.sandbox.network_models import TransportMode, TransportPolicy, policy_digest
from agenticos.sandbox.runtime_boundary import M4AProfile

from helpers import WORKER_PATH, pid_alive
from test_m4b_integration import (
    FAST,
    _assert_no_m4b_residue,
    _fixed_native_fd_window,
    _same_uid_opaque_fd_baseline,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
APPROVED_HOSTNAME = "cdn.example.com"


@pytest.fixture(scope="session")
def m4b2_native_helpers(tmp_path_factory):
    output = tmp_path_factory.mktemp("m4b2-native")
    launcher = output / "fs_launcher"
    supervisor = output / "task_supervisor"
    subprocess.run(
        [
            "cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
            "-Werror", "-O2",
            str(REPO_ROOT / "native/fs_launcher/fs_launcher.c"),
            "-o", str(launcher),
        ],
        check=True,
    )
    subprocess.run(
        [
            "cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
            "-Werror", "-O2",
            str(REPO_ROOT / "native/task_supervisor/task_supervisor.c"),
            "-o", str(supervisor),
        ],
        check=True,
    )
    return launcher, supervisor


@pytest.fixture(scope="session")
def m4b2_host_state(tmp_path_factory):
    """A recorded host qualification manifest for the session's host."""
    state = tmp_path_factory.mktemp("m4b2-host-state")
    runner_module.qualify_host_for_https(state)
    return state


@pytest.fixture(scope="session")
def m4b2_vendor():
    """The offline-installed, exact h11 broker vendor directory."""
    return runner_module.ensure_broker_vendor()


@pytest.fixture
def m4b2_runner_factory(layout, m4b2_native_helpers, m4b2_host_state, m4b2_vendor):
    launcher, supervisor = m4b2_native_helpers
    counter = 0

    def make(
        *,
        hostname=APPROVED_HOSTNAME,
        lifetime=30.0,
        transport_policy=None,
        host_state_dir=None,
    ):
        nonlocal counter
        counter += 1
        now = time.monotonic_ns()
        synthetic_home = layout.root / f"m4b2-home-{counter}"
        synthetic_home.mkdir()
        policy = transport_policy or TransportPolicy(
            version="AOSNET/1",
            task_id=f"m4b2-real-{counter}-{uuid.uuid4().hex[:8]}",
            task_generation=counter,
            launch_nonce=uuid.uuid4().hex,
            mode=TransportMode.DENY,
            proxy_host="127.0.0.1",
            proxy_port=18080,
            activated_at_monotonic_ns=now - 1_000_000_000,
            expires_at_monotonic_ns=now + int(lifetime * 1_000_000_000),
            connection_limit=1,
            byte_limit=64 * 1024,
        )
        runner = runner_module.HttpsCapabilityTransportRunner(
            WORKER_PATH,
            workspace=layout.assigned_worktree,
            profile=M4AProfile.BUILD,
            launcher_path=launcher,
            task_tmp=layout.task_tmp,
            synthetic_home=synthetic_home,
            transport_policy=policy,
            supervisor_path=supervisor,
            cancellation=FAST,
            collector=EvidenceCollector(normalize_root=layout.root),
            setup_timeout=5.0,
            approved_hostname=hostname,
            grant_purpose=GrantPurpose.GENERAL_DOWNLOAD,
            approval_source="m4b2-integration",
            approval_reference="slice-9a",
            host_state_dir=host_state_dir or m4b2_host_state,
            broker_vendor_dir=m4b2_vendor,
        )
        live_run = runner.run

        def run_with_fixed_fd_window(*args, **kwargs):
            if not hasattr(runner, "_opaque_fd_baseline"):
                runner._opaque_fd_baseline = _same_uid_opaque_fd_baseline()
            with _fixed_native_fd_window():
                return live_run(*args, **kwargs)

        runner.run = run_with_fixed_fd_window
        return runner

    return make


def _worker_argv(*args):
    return ["/usr/bin/python3", "/opt/agenticos/worker.py", *args]


def test_https_launch_reaches_readiness_and_helper_exited(m4b2_runner_factory):
    runner = m4b2_runner_factory()
    process = runner.run(["/usr/bin/true"], cwd="/workspace", env={})
    assert process.exit_code == 0, process.stderr

    # The cert helper is SHORT-LIVED: generate_task_material returns only
    # after the helper exited, and material assembly completes before the
    # broker launch chain even starts (therefore before any hostile exec).
    helper_pid = runner.last_https_helper_pid
    assert helper_pid is not None
    assert not pid_alive(helper_pid), "certificate helper survived the launch"
    broker = runner.last_broker_process
    assert broker is not None and broker.pid != helper_pid

    network_policy = runner.last_https_network_policy
    assert network_policy is not None
    assert len(network_policy.grants) == 1
    assert network_policy.grants[0].hostname == APPROVED_HOSTNAME
    observation = runner.last_transport_observation
    assert observation is not None
    assert observation.terminal_reason.value == "DENY_NO_RELAY"
    _assert_no_m4b_residue(runner)


def test_broker_post_readiness_fd_census_has_no_secret_fds(
    m4b2_runner_factory, monkeypatch
):
    runner = m4b2_runner_factory()
    census = {}
    original_emit = runner._emit

    def observe(event, **payload):
        if event == "NETWORK_BROKER_READY":
            broker_pid = runner.last_broker_process.pid
            observed = {}
            for entry in Path(f"/proc/{broker_pid}/fd").iterdir():
                try:
                    observed[int(entry.name)] = os.readlink(entry)
                except OSError:
                    observed[int(entry.name)] = "<gone>"
            census["broker"] = observed
        return original_emit(event, **payload)

    monkeypatch.setattr(runner, "_emit", observe)
    process = runner.run(["/usr/bin/true"], cwd="/workspace", env={})
    assert process.exit_code == 0, process.stderr
    assert "broker" in census, "broker readiness transition was not observed"
    observed = census["broker"]
    # No cert/key/policy/binding source descriptor may survive past readiness.
    for secret_fd in (36, 37, 38, 39, 43):
        assert secret_fd not in observed, (
            f"sealed material descriptor {secret_fd} survived readiness"
        )
    for fd, target in observed.items():
        assert "memfd" not in target, (fd, target)
        assert "aos-" not in target, (fd, target)
        assert fd <= 34, f"unexpected high descriptor {fd} -> {target}"
    _assert_no_m4b_residue(runner)


def test_worker_sees_only_ca_cert_read_only_at_fixed_path(m4b2_runner_factory):
    runner = m4b2_runner_factory()
    process = runner.run(
        _worker_argv(
            "--scenario", "FS-01", "--target", "/opt/agenticos/network-ca.pem"
        ),
        cwd="/workspace",
        env={},
    )
    assert process.exit_code == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["succeeded"] is True, result
    # The mount is exactly the sealed CA certificate (never the leaf key):
    # its byte length must equal the sealed CA memfd payload size recorded
    # by the controller at assembly time (a key-for-cert swap changes it).
    observed_size = result["details"]["bytes_read"]
    assert observed_size == runner.last_https_ca_cert_size
    assert runner.last_https_network_policy is not None

    writer = m4b2_runner_factory()
    write_process = writer.run(
        _worker_argv(
            "--scenario", "FS-03", "--target", "/opt/agenticos/network-ca.pem"
        ),
        cwd="/workspace",
        env={},
    )
    assert write_process.exit_code == 0, write_process.stderr
    write_result = json.loads(write_process.stdout)
    assert write_result["succeeded"] is False, write_result
    assert write_result["details"]["errno"] in (13, 30), write_result
    _assert_no_m4b_residue(writer)


def test_worker_fd_census_has_no_secret_fds(m4b2_runner_factory):
    runner = m4b2_runner_factory()
    process = runner.run(
        _worker_argv("--scenario", "M4B-01", "--timeout", "2"),
        cwd="/workspace",
        env={},
    )
    assert process.exit_code == 0, process.stderr
    result = json.loads(process.stdout)
    # DENY mode refuses the relay; the census was taken before the attempt.
    assert result["details"]["fds_before"] == [0, 1, 2], result
    _assert_no_m4b_residue(runner)


def test_tampered_network_policy_hostname_fails_closed_before_exec(
    m4b2_runner_factory,
):
    runner = m4b2_runner_factory()
    policy = runner.transport_policy
    material = generate_task_material(
        task_id=policy.task_id,
        task_generation=policy.task_generation,
        launch_nonce=policy.launch_nonce,
        hostname=APPROVED_HOSTNAME,
        policy_digest=policy_digest(policy),
    )
    sealed_fd = None
    try:
        # The SEALED NetworkPolicy bytes name a hostname the cert binding
        # does NOT, while the controller-visible policy object stays
        # consistent — so controller-side assembly checks pass and the
        # broker's independent sealed-byte verification is what must fail
        # closed before readiness (and therefore before hostile exec).
        now_wall = time.time_ns()

        def _grant_for(hostname):
            return NetworkGrant(
                grant_id="g-tampered",
                hostname=hostname,
                purpose=GrantPurpose.GENERAL_DOWNLOAD,
                approval_source="m4b2-integration",
                approval_reference="slice-9a",
                granted_at_wall_ns=now_wall,
                expires_at_wall_ns=now_wall + 3_600_000_000_000,
                activated_at_monotonic_ns=policy.activated_at_monotonic_ns,
                expires_at_monotonic_ns=policy.expires_at_monotonic_ns,
                connection_limit=1,
                byte_limit=64 * 1024,
            )

        def _policy_for(hostname):
            return NetworkPolicy(
                version="AOSHTTPS/1",
                task_id=policy.task_id,
                task_generation=policy.task_generation,
                launch_nonce=policy.launch_nonce,
                task_ca_certificate_digest=material.binding.ca_cert_sha256,
                grants=(_grant_for(hostname),),
            )

        sealed_fd = create_sealed_network_policy_fd(
            _policy_for("evil.example.com")
        )
        worker_ca_dir, worker_ca_path = runner_module._stage_worker_ca_pem(material)
        # The material was built OUTSIDE the fixed-fd window; pin every
        # descriptor above the window's range before the launch vacates them.
        import fcntl as _fcntl

        for _name in ("ca_cert_fd", "leaf_cert_fd", "leaf_key_fd", "binding_fd"):
            _fd = getattr(material, _name)
            _pinned = _fcntl.fcntl(_fd, _fcntl.F_DUPFD_CLOEXEC, 300)
            os.close(_fd)
            setattr(material, _name, _pinned)
        _pinned_policy = _fcntl.fcntl(sealed_fd, _fcntl.F_DUPFD_CLOEXEC, 300)
        os.close(sealed_fd)
        sealed_fd = _pinned_policy
        prepared = runner_module._PreparedHttpsMaterial(
            network_policy=_policy_for(APPROVED_HOSTNAME),
            sealed_network_policy_fd=sealed_fd,
            material=material,
            worker_ca_path=worker_ca_path,
            worker_ca_dir=worker_ca_dir,
        )
        sealed_fd = None
        try:
            with pytest.raises(runner_module.CapabilityTransportError):
                runner.run(
                    ["/usr/bin/true"],
                    cwd="/workspace",
                    env={},
                    _prepared_material=prepared,
                )
        finally:
            import shutil

            shutil.rmtree(worker_ca_dir, ignore_errors=True)
    finally:
        if sealed_fd is not None:
            os.close(sealed_fd)
        material.close()
    # The broker failed closed BEFORE readiness, so the final exec gate was
    # never released: no hostile exec happened.
    outcome = runner.last_launch_outcome
    assert outcome is not None and outcome["exec_succeeded"] is False, outcome
    _assert_no_m4b_residue(runner)


def test_host_manifest_mismatch_fails_closed_before_helper(
    m4b2_runner_factory, tmp_path
):
    bad_state = tmp_path / "bad-host-state"
    record = runner_module.qualify_host_for_https(bad_state)
    document = json.loads(record.read_bytes())
    components = document["manifest"]["components"]
    first = next(iter(sorted(components)))
    components[first]["tampered"] = True
    document["manifest_digest"] = hq.manifest_digest(document["manifest"])
    record.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")))

    runner = m4b2_runner_factory(host_state_dir=bad_state)
    with pytest.raises(hq.HostQualificationMismatchError):
        runner.run(["/usr/bin/true"], cwd="/workspace", env={})
    # The host gate runs before the cert helper is even spawned.
    assert runner.last_https_helper_pid is None


def test_absent_host_manifest_fails_closed(m4b2_runner_factory, tmp_path):
    runner = m4b2_runner_factory(host_state_dir=tmp_path / "no-record")
    with pytest.raises(hq.HostQualificationError, match="absent"):
        runner.run(["/usr/bin/true"], cwd="/workspace", env={})
    assert runner.last_https_helper_pid is None
