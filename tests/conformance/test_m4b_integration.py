"""Real-host integration proof for M4B listener capability transport."""

from __future__ import annotations

import dataclasses
import contextlib
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid

import pytest

from agenticos.sandbox.network_identity import (
    recv_listener_fd,
)
from agenticos.sandbox.containment import CancellationConfig, ContainmentState
from agenticos.sandbox.evidence import EvidenceCollector
from agenticos.sandbox.models import ProcessIdentity
from agenticos.sandbox.network_models import TransportMode, TransportPolicy
from agenticos.sandbox.runtime_boundary import M4AProfile

from helpers import WORKER_PATH


REPO_ROOT = Path(__file__).resolve().parents[2]
FAST = CancellationConfig(
    sigint_grace=0.3,
    sigterm_grace=0.3,
    empty_verify_timeout=5.0,
    poll_interval=0.05,
)


def _process_identity_key(pid):
    identity = ProcessIdentity.from_pid(pid)
    if identity.start_time_ticks is None or identity.boot_id is None:
        return None
    return (identity.pid, identity.start_time_ticks, identity.boot_id)


def _same_uid_opaque_fd_baseline():
    """Record stable pre-task same-UID processes hidden by ptrace policy."""
    controller_uid = os.getuid()
    opaque = set()
    entries = list(Path("/proc").iterdir())
    assert len(entries) < 1 << 16
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != controller_uid:
                continue
            descriptors = list((entry / "fd").iterdir())
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            key = _process_identity_key(int(entry.name))
            if key is not None:
                opaque.add(key)
            continue
        for descriptor in descriptors:
            if not descriptor.name.isdigit():
                continue
            opened = None
            try:
                opened = os.open(descriptor, os.O_PATH | os.O_CLOEXEC)
                os.fstat(opened)
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError:
                key = _process_identity_key(int(entry.name))
                if key is not None:
                    opaque.add(key)
                break
            finally:
                if opened is not None:
                    os.close(opened)
    return frozenset(opaque)


_FIXED_NATIVE_FDS = (
    5, 6, 7, 8,
    *range(20, 36),
    40, 41, 42,
    *range(50, 56),
)


@contextlib.contextmanager
def _fixed_native_fd_window():
    """Save, vacate, and exactly restore ambient test-harness low FDs."""
    saved = []
    try:
        for fd in _FIXED_NATIVE_FDS:
            try:
                os.fstat(fd)
            except OSError:
                continue
            duplicate = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 300)
            saved.append((fd, duplicate))
            os.close(fd)
        yield
    finally:
        for fd, duplicate in saved:
            os.dup2(duplicate, fd, inheritable=False)
            os.close(duplicate)
CHILD_PROGRAM = r"""
import dataclasses
import json
import os
import socket
import subprocess
import sys

sys.path.insert(0, sys.argv[1])
from agenticos.sandbox.network_identity import (
    ListenerAdoptionFrame,
    listener_evidence,
    send_listener_fd,
)

channel_fd = int(sys.argv[2])
os.set_inheritable(channel_fd, False)
channel = socket.socket(fileno=channel_fd)
subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
listener.bind(("127.0.0.1", 18080))
listener.listen(4)
evidence = listener_evidence(listener.fileno())
frame = ListenerAdoptionFrame(
    version="AOSLISTENER/1",
    task_id="integration-task",
    task_generation=9,
    launch_nonce="12" * 16,
    policy_digest="34" * 32,
    evidence=evidence,
)
send_listener_fd(channel, listener.fileno(), frame)
print(json.dumps(dataclasses.asdict(evidence), sort_keys=True), flush=True)
client = socket.create_connection(("127.0.0.1", 18080), timeout=5)
client.sendall(b"child-namespace-probe")
reply = client.recv(64)
if reply != b"adopted-listener-reply":
    raise SystemExit(f"unexpected reply: {reply!r}")
client.close()
listener.close()
channel.close()
"""


def _start_namespace_child(*, popen=subprocess.Popen):
    parent_channel = None
    child_channel = None
    try:
        parent_channel, child_channel = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
        )
        proc = popen(
            [
                "unshare",
                "-Urn",
                sys.executable,
                "-c",
                CHILD_PROGRAM,
                str(REPO_ROOT / "src"),
                str(child_channel.fileno()),
            ],
            pass_fds=(child_channel.fileno(),),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except BaseException:
        if child_channel is not None:
            child_channel.close()
        if parent_channel is not None:
            parent_channel.close()
        raise
    child_channel.close()
    return parent_channel, proc


def test_listener_identity_popen_failure_closes_both_channel_endpoints():
    before = {int(name) for name in os.listdir("/proc/self/fd")}

    def fail_popen(*_args, **_kwargs):
        raise OSError("injected Popen failure")

    with pytest.raises(OSError, match="injected Popen failure"):
        _start_namespace_child(popen=fail_popen)
    assert {int(name) for name in os.listdir("/proc/self/fd")} == before


def test_listener_identity_survives_real_cross_netns_adoption_and_remains_operational():
    parent_channel, proc = _start_namespace_child()
    adopted = None
    accepted = None
    host_socket = None
    try:
        adopted = recv_listener_fd(
            parent_channel,
            expected_task_id="integration-task",
            expected_generation=9,
            expected_nonce="12" * 16,
            expected_policy_digest="34" * 32,
        )
        assert proc.stdout is not None
        child_line = proc.stdout.readline()
        child_evidence = json.loads(child_line)

        adopted_stat = os.fstat(adopted.fd)
        assert adopted.evidence == adopted.frame.evidence
        assert child_evidence == dataclasses.asdict(adopted.evidence)
        assert adopted.evidence.device == adopted_stat.st_dev
        assert adopted.evidence.inode == adopted_stat.st_ino
        assert adopted.evidence.file_type == (adopted_stat.st_mode & 0o170000)

        adopted_socket = socket.socket(fileno=os.dup(adopted.fd))
        try:
            adopted_socket.settimeout(5)
            accepted, _address = adopted_socket.accept()
            assert accepted.recv(64) == b"child-namespace-probe"
            accepted.sendall(b"adopted-listener-reply")
        finally:
            adopted_socket.close()

        host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        cookie_option = getattr(socket, "SO_NETNS_COOKIE", 71)
        host_cookie = struct.unpack(
            "=Q", host_socket.getsockopt(socket.SOL_SOCKET, cookie_option, 8)
        )[0]
        assert host_cookie > 0
        assert host_cookie != adopted.evidence.netns_cookie

        stdout_tail, stderr = proc.communicate(timeout=10)
        assert proc.returncode == 0, f"child stdout={stdout_tail!r} stderr={stderr!r}"
    finally:
        if accepted is not None:
            accepted.close()
        if host_socket is not None:
            host_socket.close()
        if adopted is not None:
            os.close(adopted.fd)
        parent_channel.close()
        if proc.poll() is None:
            proc.kill()
        proc.communicate(timeout=10)


@pytest.fixture(scope="session")
def m4b_native_helpers(tmp_path_factory):
    output = tmp_path_factory.mktemp("m4b-native")
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


@pytest.fixture
def m4b_runner_factory(layout, m4b_native_helpers):
    from agenticos.sandbox.m4b_runner import CapabilityTransportRunner

    launcher, supervisor = m4b_native_helpers
    counter = 0

    def make(
        mode=TransportMode.SYNTHETIC_FIXTURE_FD,
        *,
        lifetime=30.0,
        transport_policy=None,
    ):
        nonlocal counter
        counter += 1
        now = time.monotonic_ns()
        synthetic_home = layout.root / f"m4b-home-{counter}"
        synthetic_home.mkdir()
        policy = transport_policy or TransportPolicy(
                version="AOSNET/1",
                task_id=f"m4b-real-{counter}-{uuid.uuid4().hex[:8]}",
                task_generation=counter,
                launch_nonce=uuid.uuid4().hex,
                mode=mode,
                proxy_host="127.0.0.1",
                proxy_port=18080,
                activated_at_monotonic_ns=now - 1_000_000_000,
                expires_at_monotonic_ns=now + int(lifetime * 1_000_000_000),
                connection_limit=1,
                byte_limit=64 * 1024,
            )
        runner = CapabilityTransportRunner(
            worker_path=WORKER_PATH,
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
        )
        live_run = runner.run

        def run_with_fixed_fd_window(*args, **kwargs):
            if not hasattr(runner, "_opaque_fd_baseline"):
                runner._opaque_fd_baseline = _same_uid_opaque_fd_baseline()
            duplicated_fixture = None
            fixture_fd = kwargs.get("_synthetic_fixture_fd")
            if fixture_fd in _FIXED_NATIVE_FDS:
                duplicated_fixture = fcntl.fcntl(
                    fixture_fd, fcntl.F_DUPFD_CLOEXEC, 400
                )
                kwargs["_synthetic_fixture_fd"] = duplicated_fixture
            try:
                with _fixed_native_fd_window():
                    return live_run(*args, **kwargs)
            finally:
                if duplicated_fixture is not None:
                    os.close(duplicated_fixture)

        runner.run = run_with_fixed_fd_window
        return runner

    return make


def _worker_argv(*args):
    return ["/usr/bin/python3", "/opt/agenticos/worker.py", *args]


def _assert_no_m4b_residue(runner):
    units = runner.backend._ctl(["list-units", "aos-*", "--all", "--no-legend"])
    assert not units.stdout.strip()
    namespace = runner.last_namespace_evidence
    listener = runner.last_listener_evidence
    if namespace is None or listener is None:
        return
    worker_netns = namespace.child.identities["net"]
    host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        host_cookie = struct.unpack(
            "=Q",
            host_socket.getsockopt(
                socket.SOL_SOCKET, getattr(socket, "SO_NETNS_COOKIE", 71), 8
            ),
        )[0]
    finally:
        host_socket.close()
    assert listener.netns_cookie != host_cookie
    assert worker_netns != namespace.controller.identities["net"]
    proc_entries = list(Path("/proc").iterdir())
    assert len(proc_entries) < 1 << 16, "process census exceeded its bound"
    controller_uid = os.getuid()
    total_descriptors = 0
    for entry in proc_entries:
        if not entry.name.isdigit():
            continue
        try:
            process_status = entry.stat()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if process_status.st_uid != controller_uid:
            continue
        try:
            assert os.readlink(entry / "ns/net") != f"net:[{worker_netns}]"
        except PermissionError:
            # Same-UID non-dumpable processes on the recorded host can hide
            # namespace symlinks while still exposing their FD table. Exact
            # listener-object evidence below remains mandatory.
            pass
        except (FileNotFoundError, ProcessLookupError):
            continue
        try:
            descriptor_entries = list((entry / "fd").iterdir())
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            key = _process_identity_key(int(entry.name))
            assert key is not None and key in runner._opaque_fd_baseline, (
                "new or changed same-UID process descriptor ambiguity appeared "
                f"at {entry.name}"
            )
            continue
        assert len(descriptor_entries) < 1 << 16, (
            f"same-UID process {entry.name} descriptor census exceeded its bound"
        )
        for descriptor in descriptor_entries:
            if not descriptor.name.isdigit():
                continue
            total_descriptors += 1
            assert total_descriptors < 1 << 20, (
                "same-UID descriptor census exceeded its total bound"
            )
            opened = None
            try:
                opened = os.open(
                    descriptor, os.O_PATH | os.O_CLOEXEC
                )
                observed = os.fstat(opened)
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError as exc:
                key = _process_identity_key(int(entry.name))
                assert key is not None and key in runner._opaque_fd_baseline, (
                    "new or changed same-UID descriptor ambiguity appeared "
                    f"at {entry.name}/{descriptor.name}"
                )
                break
            finally:
                if opened is not None:
                    os.close(opened)
            assert (observed.st_dev, observed.st_ino) != (
                listener.device,
                listener.inode,
            ), "exact listener kernel object remains referenced by same UID"


def _relay_policy(*, lifetime=5.0):
    now = time.monotonic_ns()
    return TransportPolicy(
        version="AOSNET/1",
        task_id=f"relay-{uuid.uuid4().hex[:8]}",
        task_generation=1,
        launch_nonce=uuid.uuid4().hex,
        mode=TransportMode.SYNTHETIC_FIXTURE_FD,
        proxy_host="127.0.0.1",
        proxy_port=18080,
        activated_at_monotonic_ns=now - 1_000_000,
        expires_at_monotonic_ns=now + int(lifetime * 1_000_000_000),
        connection_limit=1,
        byte_limit=64 * 1024,
    )


def _queued_relay(policy, *, worker_count=1, worker_payload=b"", half_close=False):
    from agenticos.sandbox.network_broker import serve_transport

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 18080))
    listener.listen(4)
    fixture_peer, fixture_broker = socket.socketpair()
    control_peer, control_broker = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET
    )
    workers = [
        socket.create_connection(("127.0.0.1", 18080), timeout=2.0)
        for _ in range(worker_count)
    ]
    if worker_payload:
        workers[0].sendall(worker_payload)
    if half_close:
        workers[0].shutdown(socket.SHUT_WR)
    result = []

    def serve():
        result.append(
            serve_transport(
                policy,
                listener_fd=os.dup(listener.fileno()),
                fixture_fd=os.dup(fixture_broker.fileno()),
                control_fd=os.dup(control_broker.fileno()),
            )
        )

    return (
        listener, fixture_peer, fixture_broker, control_peer, control_broker,
        workers, result, serve,
    )


def _close_relay(resources):
    for value in resources:
        if isinstance(value, socket.socket):
            value.close()
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, socket.socket):
                    item.close()


def _assert_no_fixture_bytes(channel):
    channel.settimeout(0.2)
    try:
        payload = channel.recv(256)
    except TimeoutError:
        return
    assert payload == b""


def test_active_full_duplex_relay_revoke_blocks_post_terminal_canary():
    from agenticos.sandbox.network_broker import CONTROL_REVOKE, TransportTermination

    resources = _queued_relay(_relay_policy())
    listener, fixture, _fixture_broker, control, _control_broker, workers, result, serve = resources
    thread = threading.Thread(target=serve)
    thread.start()
    try:
        workers[0].sendall(b"PRE_REVOKE_WORKER")
        fixture.settimeout(2.0)
        assert fixture.recv(256) == b"PRE_REVOKE_WORKER"
        fixture.sendall(b"PRE_REVOKE_FIXTURE")
        workers[0].settimeout(2.0)
        assert workers[0].recv(256) == b"PRE_REVOKE_FIXTURE"
        control.sendall(CONTROL_REVOKE)
        thread.join(timeout=3.0)
        assert len(result) == 1
        assert result[0].terminal_reason is TransportTermination.REVOKED
        assert result[0].worker_to_fixture_bytes == len(b"PRE_REVOKE_WORKER")
        assert result[0].fixture_to_worker_bytes == len(b"PRE_REVOKE_FIXTURE")
        try:
            workers[0].sendall(b"POST_REVOKE_CANARY")
        except OSError:
            pass
        _assert_no_fixture_bytes(fixture)
    finally:
        _close_relay(resources[:-2])


def test_active_full_duplex_absolute_expiry_blocks_post_terminal_canary():
    from agenticos.sandbox.network_broker import TransportTermination

    resources = _queued_relay(_relay_policy(lifetime=0.3))
    _listener, fixture, _fixture_broker, _control, _control_broker, workers, result, serve = resources
    thread = threading.Thread(target=serve)
    thread.start()
    try:
        workers[0].sendall(b"PRE_EXPIRY_WORKER")
        fixture.settimeout(2.0)
        assert fixture.recv(256) == b"PRE_EXPIRY_WORKER"
        fixture.sendall(b"PRE_EXPIRY_FIXTURE")
        workers[0].settimeout(2.0)
        assert workers[0].recv(256) == b"PRE_EXPIRY_FIXTURE"
        thread.join(timeout=3.0)
        assert len(result) == 1
        assert result[0].terminal_reason is TransportTermination.EXPIRED
        assert result[0].observed_at_monotonic_ns > 0
        try:
            workers[0].sendall(b"POST_EXPIRY_CANARY")
        except OSError:
            pass
        _assert_no_fixture_bytes(fixture)
    finally:
        _close_relay(resources[:-2])


def test_revoke_cancels_open_half_closed_connection_without_fixture_bytes():
    from agenticos.sandbox.network_broker import CONTROL_REVOKE, TransportTermination

    resources = _queued_relay(_relay_policy())
    _listener, fixture, _fixture_broker, control, _control_broker, workers, result, serve = resources
    thread = threading.Thread(target=serve)
    thread.start()
    workers[0].sendall(b"PRE_TERMINAL")
    fixture.settimeout(2.0)
    assert fixture.recv(256) == b"PRE_TERMINAL"
    workers[0].shutdown(socket.SHUT_WR)
    control.sendall(CONTROL_REVOKE)
    thread.join(timeout=3.0)
    try:
        assert len(result) == 1
        assert result[0].terminal_reason is TransportTermination.REVOKED
        assert result[0].worker_to_fixture_bytes == len(b"PRE_TERMINAL")
        _assert_no_fixture_bytes(fixture)
        workers[0].settimeout(0.2)
        assert workers[0].recv(1) == b""
    finally:
        _close_relay(resources[:-2])


def test_expiry_cancels_active_half_closed_connection_without_late_bytes():
    from agenticos.sandbox.network_broker import TransportTermination

    resources = _queued_relay(_relay_policy(lifetime=0.4))
    _listener, fixture, _fixture_broker, _control, _control_broker, workers, result, serve = resources
    thread = threading.Thread(target=serve)
    thread.start()
    try:
        workers[0].sendall(b"PRE_EXPIRY_HALF_CLOSE")
        workers[0].shutdown(socket.SHUT_WR)
        fixture.settimeout(2.0)
        received = bytearray()
        while True:
            chunk = fixture.recv(256)
            if not chunk:
                break
            received.extend(chunk)
        assert bytes(received) == b"PRE_EXPIRY_HALF_CLOSE"
        thread.join(timeout=3.0)
        assert len(result) == 1
        assert result[0].terminal_reason is TransportTermination.EXPIRED
        assert result[0].worker_to_fixture_bytes == len(b"PRE_EXPIRY_HALF_CLOSE")
        try:
            fixture.sendall(b"POST_EXPIRY_HALF_CLOSE_CANARY")
        except OSError:
            pass
        workers[0].settimeout(0.2)
        try:
            assert workers[0].recv(256) == b""
        except ConnectionResetError:
            pass
    finally:
        _close_relay(resources[:-2])


def test_worker_fin_is_forwarded_before_eof_dependent_fixture_response():
    from agenticos.sandbox.network_broker import CONTROL_REVOKE, TransportTermination

    resources = _queued_relay(_relay_policy())
    _listener, fixture, _fixture_broker, control, _control_broker, workers, result, serve = resources
    thread = threading.Thread(target=serve)
    thread.start()
    try:
        workers[0].sendall(b"REQUEST_THEN_FIN")
        workers[0].shutdown(socket.SHUT_WR)
        fixture.settimeout(2.0)
        received = bytearray()
        while True:
            chunk = fixture.recv(256)
            if not chunk:
                break
            received.extend(chunk)
        assert bytes(received) == b"REQUEST_THEN_FIN"
        fixture.sendall(b"EOF_DEPENDENT_RESPONSE")
        fixture.shutdown(socket.SHUT_WR)
        workers[0].settimeout(2.0)
        response = bytearray()
        while True:
            chunk = workers[0].recv(256)
            if not chunk:
                break
            response.extend(chunk)
        assert bytes(response) == b"EOF_DEPENDENT_RESPONSE"
        control.sendall(CONTROL_REVOKE)
        thread.join(timeout=3.0)
        assert len(result) == 1
        assert result[0].terminal_reason is TransportTermination.COMPLETED
        assert result[0].worker_to_fixture_bytes == len(b"REQUEST_THEN_FIN")
        assert result[0].fixture_to_worker_bytes == len(b"EOF_DEPENDENT_RESPONSE")
    finally:
        _close_relay(resources[:-2])


def test_second_queued_connection_terminates_one_connection_capability():
    from agenticos.sandbox.network_broker import TransportTermination

    resources = _queued_relay(_relay_policy(), worker_count=2)
    _listener, fixture, _fixture_broker, _control, _control_broker, _workers, result, serve = resources
    thread = threading.Thread(target=serve)
    thread.start()
    thread.join(timeout=3.0)
    try:
        assert len(result) == 1
        assert result[0].terminal_reason is TransportTermination.CONNECTION_LIMIT
        assert result[0].connection_count == 1
        _assert_no_fixture_bytes(fixture)
    finally:
        _close_relay(resources[:-2])


def _run_with_fixture(runner, worker_args, *, response=b"fixture-reply"):
    low_fixture, low_broker_end = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_STREAM
    )
    fixture_fd = fcntl.fcntl(low_fixture.fileno(), fcntl.F_DUPFD_CLOEXEC, 400)
    broker_fd = fcntl.fcntl(low_broker_end.fileno(), fcntl.F_DUPFD_CLOEXEC, 400)
    low_fixture.close()
    low_broker_end.close()
    fixture = socket.socket(fileno=fixture_fd)
    broker_end = socket.socket(fileno=broker_fd)
    observed = []

    def fixture_server():
        try:
            request = fixture.recv(4096)
            observed.append(request)
            if request:
                fixture.sendall(response)
                fixture.shutdown(socket.SHUT_WR)
        finally:
            fixture.close()

    thread = threading.Thread(target=fixture_server, daemon=True)
    thread.start()
    try:
        result = runner.run(
            worker_args,
            cwd="/workspace",
            env={},
            _synthetic_fixture_fd=broker_end.fileno(),
        )
    finally:
        broker_end.close()
        thread.join(timeout=5.0)
    assert not thread.is_alive()
    return result, observed


def test_real_host_fixed_proxy_relay_and_exact_worker_boundary(m4b_runner_factory):
    runner = m4b_runner_factory()
    process, observed = _run_with_fixture(
        runner,
        _worker_argv("--scenario", "M4B-01", "--canary", "M4B_REAL_CANARY"),
    )
    assert process.exit_code == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["succeeded"] is True, result
    assert result["details"] == {
        "reply": "fixture-reply",
        "fds_before": [0, 1, 2],
    }
    assert observed == [b"M4B_REAL_CANARY"]
    broker = runner.last_broker_process
    namespace = runner.last_namespace_evidence
    assert broker.cgroup == namespace.child.cgroup
    assert broker.netns == namespace.controller.identities["net"]
    assert namespace.child.identities["net"] != broker.netns
    assert runner.last_listener_evidence.port == 18080
    assert runner.last_listener_evidence.netns_cookie > 0
    transport = runner.last_transport_observation
    assert transport.connection_count == 1
    assert transport.worker_to_fixture_bytes == len(b"M4B_REAL_CANARY")
    assert transport.fixture_to_worker_bytes == len(b"fixture-reply")
    assert transport.total_bytes == len(b"M4B_REAL_CANARYfixture-reply")
    assert transport.terminal_reason.value == "COMPLETED"
    mapping = runner.last_broker_identity_mapping
    assert mapping["readiness_namespace_pid"] == 2
    assert mapping["supervisor_broker_outer_pid"] != mapping["bwrap_setup_child_pid"]
    assert mapping["resolved_host_broker_pid"] != mapping["readiness_namespace_pid"]
    assert mapping["resolved_parent_pid"] == mapping["bwrap_setup_child_pid"]
    assert process.containment_state == ContainmentState.TERMINATED.value
    _assert_no_m4b_residue(runner)


def test_residue_scan_rejects_exact_listener_object_held_by_same_uid(
    m4b_runner_factory
):
    runner = m4b_runner_factory(TransportMode.DENY)
    process = runner.run(["/usr/bin/true"], cwd="/workspace", env={})
    assert process.exit_code == 0
    held, peer = socket.socketpair()
    try:
        status = os.fstat(held.fileno())
        runner.last_listener_evidence = dataclasses.replace(
            runner.last_listener_evidence,
            device=status.st_dev,
            inode=status.st_ino,
            file_type=status.st_mode & 0o170000,
        )
        with pytest.raises(AssertionError, match="exact listener"):
            _assert_no_m4b_residue(runner)
    finally:
        held.close()
        peer.close()


def test_transport_authority_claim_is_atomic_one_shot(m4b_runner_factory):
    import agenticos.sandbox.m4b_runner as runner_module

    first = m4b_runner_factory(TransportMode.DENY)
    second = m4b_runner_factory(transport_policy=first.transport_policy)
    barrier = threading.Barrier(2)
    outcomes = []

    def claim_runner(runner):
        barrier.wait()
        try:
            runner._claim_transport_authority()
        except runner_module.CapabilityTransportError:
            outcomes.append("rejected")
        else:
            outcomes.append("claimed")

    threads = [
        threading.Thread(target=lambda runner=runner: claim_runner(runner))
        for runner in (first, second)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=3.0)
    assert outcomes.count("claimed") == 1
    assert outcomes.count("rejected") == 1


def test_successful_generation_cannot_be_replayed(m4b_runner_factory):
    import agenticos.sandbox.m4b_runner as runner_module

    runner = m4b_runner_factory()
    process, _observed = _run_with_fixture(
        runner, _worker_argv("--scenario", "M4B-01")
    )
    assert process.exit_code == 0
    replay = m4b_runner_factory(transport_policy=runner.transport_policy)
    left, right = socket.socketpair()
    try:
        with pytest.raises(runner_module.CapabilityTransportError, match="consumed"):
            replay.run(
                _worker_argv("--scenario", "M4B-01"),
                cwd="/workspace", env={},
                _synthetic_fixture_fd=right.fileno(),
            )
    finally:
        left.close()
        right.close()
    _assert_no_m4b_residue(runner)


def test_failed_launch_generation_cannot_restart(
    m4b_runner_factory, monkeypatch
):
    import agenticos.sandbox.m4b_runner as runner_module

    runner = m4b_runner_factory(TransportMode.DENY)
    calls = 0

    def fail_prepare(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise RuntimeError("injected preparation failure")

    monkeypatch.setattr(runner, "_prepare_live_launch", fail_prepare)
    with pytest.raises(RuntimeError, match="preparation"):
        runner.run(["/usr/bin/true"], cwd="/workspace", env={})
    replay = m4b_runner_factory(transport_policy=runner.transport_policy)
    with pytest.raises(runner_module.CapabilityTransportError, match="consumed"):
        replay.run(["/usr/bin/true"], cwd="/workspace", env={})
    assert calls == 1


@pytest.mark.parametrize(
    "pause_event", ["NETWORK_BROKER_READY", "FILESYSTEM_POLICY_APPLIED"]
)
def test_policy_expiry_before_c_or_x_withholds_hostile_exec_and_cleans(
    m4b_runner_factory, layout, monkeypatch, pause_event
):
    import agenticos.sandbox.m4b_runner as runner_module

    runner = m4b_runner_factory(TransportMode.DENY, lifetime=2.0)
    marker = layout.task_tmp / f"expired-{pause_event}"
    original_emit = runner._emit

    def cross_expiry(event, **payload):
        original_emit(event, **payload)
        if event == pause_event:
            remaining = (
                runner.transport_policy.expires_at_monotonic_ns
                - time.monotonic_ns()
            ) / 1_000_000_000
            if remaining > 0:
                time.sleep(remaining + 0.05)

    monkeypatch.setattr(runner, "_emit", cross_expiry)
    with pytest.raises(runner_module.CapabilityTransportError, match="expired"):
        runner.run(
            [
                "/usr/bin/python3", "-c",
                f"from pathlib import Path; Path('/tmp/{marker.name}').touch()",
            ],
            cwd="/workspace", env={}, _marker_path=marker,
        )
    assert not marker.exists()
    _assert_no_m4b_residue(runner)


def test_confirmed_post_exec_broker_death_cancels_live_hostile_worker(
    m4b_runner_factory, layout, monkeypatch
):
    import agenticos.sandbox.m4b_runner as runner_module

    runner = m4b_runner_factory(TransportMode.DENY)
    marker = layout.task_tmp / "confirmed-after-exec"
    original_emit = runner._emit

    def kill_after_confirmed_exec(event, **payload):
        original_emit(event, **payload)
        if event != "WORKER_EXEC_ATTEMPTED":
            return
        deadline = time.monotonic() + 3.0
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert marker.exists()
        os.kill(runner.last_broker_process.pid, signal.SIGKILL)

    monkeypatch.setattr(runner, "_emit", kill_after_confirmed_exec)
    with pytest.raises(runner_module.CapabilityTransportError, match="not live"):
        runner.run(
            [
                "/usr/bin/python3", "-c",
                "from pathlib import Path; import time; "
                "Path('/tmp/confirmed-after-exec').touch(); time.sleep(30)",
            ],
            cwd="/workspace", env={}, _marker_path=marker,
        )
    assert marker.exists()
    _assert_no_m4b_residue(runner)


def test_fixture_capability_is_pinned_before_caller_fd_reuse(m4b_runner_factory):
    from agenticos.sandbox.network_broker import validate_fixture_fd

    runner = m4b_runner_factory()
    low_peer, low_source = socket.socketpair()
    peer_fd = fcntl.fcntl(low_peer.fileno(), fcntl.F_DUPFD_CLOEXEC, 500)
    source_fd = fcntl.fcntl(low_source.fileno(), fcntl.F_DUPFD_CLOEXEC, 500)
    low_peer.close()
    low_source.close()
    peer = socket.socket(fileno=peer_fd)
    pinned = runner._pin_synthetic_fixture(source_fd)
    os.close(source_fd)
    replacement_r, replacement_w = os.pipe()
    try:
        os.dup2(replacement_r, source_fd, inheritable=False)
        validate_fixture_fd(pinned)
        peer.sendall(b"PINNED_CAPABILITY")
        observed = socket.socket(fileno=os.dup(pinned))
        try:
            assert observed.recv(256) == b"PINNED_CAPABILITY"
        finally:
            observed.close()
    finally:
        peer.close()
        os.close(pinned)
        os.close(source_fd)
        os.close(replacement_r)
        os.close(replacement_w)


def test_timeout_cancels_active_open_half_closed_relay(
    m4b_runner_factory
):
    runner = m4b_runner_factory()
    low_fixture, low_broker = socket.socketpair()
    fixture_fd = fcntl.fcntl(low_fixture.fileno(), fcntl.F_DUPFD_CLOEXEC, 500)
    broker_fd = fcntl.fcntl(low_broker.fileno(), fcntl.F_DUPFD_CLOEXEC, 500)
    low_fixture.close()
    low_broker.close()
    fixture = socket.socket(fileno=fixture_fd)
    broker = socket.socket(fileno=broker_fd)
    half_closed = threading.Event()
    release = threading.Event()

    def hold_fixture_open():
        fixture.settimeout(3.0)
        request = bytearray()
        while True:
            chunk = fixture.recv(256)
            if not chunk:
                break
            request.extend(chunk)
        assert bytes(request) == b"HALF_CLOSE_TIMEOUT"
        half_closed.set()
        release.wait(5.0)

    thread = threading.Thread(target=hold_fixture_open)
    thread.start()
    try:
        process = runner.run(
            [
                "/usr/bin/python3", "-c",
                "import socket,time; s=socket.create_connection(('127.0.0.1',18080)); "
                "s.sendall(b'HALF_CLOSE_TIMEOUT'); s.shutdown(socket.SHUT_WR); "
                "time.sleep(30)",
            ],
            cwd="/workspace", env={}, timeout=0.5,
            _synthetic_fixture_fd=broker.fileno(),
        )
        assert half_closed.wait(2.0)
        assert process.timed_out is True
        assert process.containment_state == ContainmentState.TERMINATED.value
        observation = runner.last_transport_observation
        assert observation.terminal_reason.value == "REVOKED"
        assert observation.connection_count == 1
        assert observation.worker_to_fixture_bytes == len(b"HALF_CLOSE_TIMEOUT")
        assert observation.total_bytes <= observation.accounted_bytes
    finally:
        release.set()
        broker.close()
        thread.join(timeout=5.0)
        fixture.close()
    assert not thread.is_alive()
    _assert_no_m4b_residue(runner)


def test_timeout_missing_terminal_record_starts_cancel_within_one_shared_grace(
    m4b_runner_factory, monkeypatch
):
    import agenticos.sandbox.m4b_runner as runner_module

    runner = m4b_runner_factory(TransportMode.DENY)
    budgets = []
    cancel_started = []
    terminal_grace_started = []
    original_cancel = runner._cancel

    def unresponsive_revoke(_fd, *, budget):
        terminal_grace_started.append(time.monotonic())
        budgets.append(budget)
        time.sleep(min(0.7, budget))

    def missing_observation(_fd, *, expected_policy, expected_policy_digest, budget):
        del expected_policy, expected_policy_digest
        budgets.append(budget)
        time.sleep(budget)
        raise runner_module.CapabilityTransportError(
            "injected missing terminal observation"
        )

    def observe_cancel(*args, **kwargs):
        cancel_started.append(time.monotonic())
        return original_cancel(*args, **kwargs)

    monkeypatch.setattr(runner_module, "_revoke_broker_control", unresponsive_revoke)
    monkeypatch.setattr(
        runner_module,
        "_read_authenticated_transport_observation",
        missing_observation,
    )
    monkeypatch.setattr(runner, "_cancel", observe_cancel)
    with pytest.raises(
        runner_module.CapabilityTransportError,
        match="injected missing terminal observation",
    ):
        runner.run(
            ["/usr/bin/python3", "-c", "import time; time.sleep(30)"],
            cwd="/workspace",
            env={},
            timeout=0.1,
        )

    assert len(budgets) == 2
    assert budgets[0] <= 1.0
    assert budgets[1] <= 0.35
    assert len(cancel_started) >= 1
    assert len(terminal_grace_started) == 1
    assert cancel_started[0] - terminal_grace_started[0] < 1.05
    _assert_no_m4b_residue(runner)


@pytest.mark.parametrize(
    "shape",
    [
        "child", "grandchild", "setsid", "new-pgroup", "parent-exit",
        "double-fork", "rapid-spawn", "signal-ignore",
    ],
)
def test_descendant_shapes_have_only_fixed_proxy_not_direct_network(
    m4b_runner_factory, shape
):
    host_address = socket.gethostbyname(socket.gethostname())
    direct = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    direct.bind((host_address, 0))
    direct.listen(1)
    direct.settimeout(0.2)
    try:
        runner = m4b_runner_factory()
        process, observed = _run_with_fixture(
            runner,
            _worker_argv(
                "--scenario", "M4B-03", "--base", shape,
                "--target", f"{host_address}:{direct.getsockname()[1]}",
            ),
            response=b"DESCENDANT_PROXY_REPLY",
        )
        assert process.exit_code == 0, process.stderr
        result = json.loads(process.stdout)
        assert result["succeeded"] is True, result
        assert result["details"] == {
            "shape": shape,
            "proxy_reply": "DESCENDANT_PROXY_REPLY",
            "direct_succeeded": False,
        }
        assert observed == [f"DESCENDANT_{shape}".encode("ascii")]
        with pytest.raises(TimeoutError):
            direct.accept()
        _assert_no_m4b_residue(runner)
    finally:
        direct.close()


@pytest.mark.parametrize(
    "fault",
    [
        "socket_type", "address", "port", "cookie", "policy", "pid",
        "cgroup", "generation", "nonce",
    ],
)
def test_live_substituted_readiness_identity_is_rejected_before_exec(
    m4b_runner_factory, monkeypatch, fault
):
    import agenticos.sandbox.m4b_runner as runner_module

    runner = m4b_runner_factory()
    original = runner_module._read_ready_packet

    def substitute(fd, *, budget):
        payload = original(fd, budget=budget)
        document = json.loads(payload)
        if fault == "policy":
            document["ready"]["policy_digest"] = "0" * 64
        elif fault == "pid":
            document["process"]["pid"] += 1
            document["ready"]["broker_pid"] += 1
        elif fault == "cgroup":
            document["boundary"]["cgroup"] = "/wrong.scope"
        elif fault == "generation":
            document["ready"]["task_generation"] += 1
        elif fault == "nonce":
            document["ready"]["launch_nonce"] = "0" * 32
        else:
            field, value = {
                "socket_type": ("socket_type", socket.SOCK_DGRAM),
                "address": ("address", "127.0.0.2"),
                "port": ("port", 18081),
                "cookie": (
                    "netns_cookie", document["listener"]["netns_cookie"] + 1,
                ),
            }[fault]
            document["listener"][field] = value
        return json.dumps(
            document, sort_keys=True, separators=(",", ":")
        ).encode("ascii")

    monkeypatch.setattr(runner_module, "_read_ready_packet", substitute)
    left, right = socket.socketpair()
    try:
        with pytest.raises(runner_module.CapabilityTransportError):
            runner.run(
                _worker_argv("--scenario", "M4B-01"),
                cwd="/workspace", env={},
                _synthetic_fixture_fd=right.fileno(),
            )
    finally:
        left.close()
        right.close()
    _assert_no_m4b_residue(runner)


@pytest.mark.parametrize(
    "kill_event",
    ["BROKER_PROCESS_VERIFIED", "NETWORK_BROKER_READY", "WORKER_EXEC_ATTEMPTED"],
)
def test_broker_death_at_lifecycle_boundary_cancels_task(
    m4b_runner_factory, monkeypatch, kill_event
):
    import agenticos.sandbox.m4b_runner as runner_module

    runner = m4b_runner_factory(TransportMode.DENY)
    original_emit = runner._emit

    def kill_on_event(event, **payload):
        original_emit(event, **payload)
        if event == kill_event:
            os.kill(runner.last_broker_process.pid, signal.SIGKILL)

    monkeypatch.setattr(runner, "_emit", kill_on_event)
    started = time.monotonic()
    with pytest.raises((runner_module.CapabilityTransportError, OSError)):
        runner.run(
            ["/usr/bin/python3", "-c", "import time; time.sleep(30)"],
            cwd="/workspace", env={}, timeout=10.0,
        )
    assert time.monotonic() - started < 8.0
    _assert_no_m4b_residue(runner)


def test_broker_death_after_close_before_final_exec_is_rejected(
    m4b_runner_factory, monkeypatch
):
    import agenticos.sandbox.m4b_runner as runner_module

    runner = m4b_runner_factory(TransportMode.DENY)
    original_write = runner._write_all

    def kill_after_close(fd, payload, *, budget):
        original_write(fd, payload, budget=budget)
        if payload == b"C":
            os.kill(runner.last_broker_process.pid, signal.SIGKILL)

    monkeypatch.setattr(runner, "_write_all", kill_after_close)
    with pytest.raises(runner_module.CapabilityTransportError):
        runner.run(
            ["/usr/bin/python3", "-c", "print('must-not-run')"],
            cwd="/workspace", env={},
        )
    _assert_no_m4b_residue(runner)


@pytest.mark.parametrize(
    ("gate_name", "gate_payload", "gate_occurrence"),
    [
        ("namespace", b"G", 1),
        ("launcher_setup", b"G", 2),
        ("network_close", b"C", 1),
        ("final_exec", b"X", 1),
    ],
)
def test_controller_exception_at_each_release_gate_recursively_cleans(
    m4b_runner_factory, monkeypatch, gate_name, gate_payload, gate_occurrence
):
    runner = m4b_runner_factory(TransportMode.DENY)
    original_write = runner._write_all
    matching_writes = 0

    def fail_gate(fd, payload, *, budget):
        nonlocal matching_writes
        if payload == gate_payload:
            matching_writes += 1
        if payload == gate_payload and matching_writes == gate_occurrence:
            raise RuntimeError(f"injected {gate_name} gate failure")
        return original_write(fd, payload, budget=budget)

    monkeypatch.setattr(runner, "_write_all", fail_gate)
    with pytest.raises(RuntimeError, match=f"{gate_name} gate"):
        runner.run(
            ["/usr/bin/python3", "-c", "import time; time.sleep(30)"],
            cwd="/workspace", env={},
        )
    _assert_no_m4b_residue(runner)


def test_isolated_worker_has_no_default_routes_resolver_or_extra_fds(
    m4b_runner_factory
):
    runner = m4b_runner_factory(TransportMode.DENY)
    process = runner.run(
        _worker_argv("--scenario", "M4B-02"),
        cwd="/workspace", env={},
    )
    assert process.exit_code == 0, process.stderr
    details = json.loads(process.stdout)["details"]
    assert details["fds"] == [0, 1, 2]
    assert "00000000" not in details["ipv4_route"].get("text", "")
    assert details["resolv_conf"]["visible"] is False
    _assert_no_m4b_residue(runner)


def test_direct_host_and_wsl_lan_fixture_targets_receive_no_connection(
    m4b_runner_factory
):
    candidates = ["127.0.0.1"]
    host_address = socket.gethostbyname(socket.gethostname())
    if host_address != "127.0.0.1":
        candidates.append(host_address)
    for address in candidates:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((address, 0))
        server.listen(1)
        server.settimeout(0.2)
        try:
            runner = m4b_runner_factory(TransportMode.DENY)
            process = runner.run(
                _worker_argv(
                    "--scenario", "NET-02", "--target",
                    f"{address}:{server.getsockname()[1]}",
                ),
                cwd="/workspace", env={},
            )
            assert process.exit_code == 0, process.stderr
            assert json.loads(process.stdout)["succeeded"] is False
            with pytest.raises(TimeoutError):
                server.accept()
            _assert_no_m4b_residue(runner)
        finally:
            server.close()


def test_direct_host_udp_fixtures_receive_no_datagram(m4b_runner_factory):
    candidates = ["127.0.0.1"]
    host_address = socket.gethostbyname(socket.gethostname())
    if host_address != "127.0.0.1":
        candidates.append(host_address)
    for address in candidates:
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind((address, 0))
        server.settimeout(0.2)
        try:
            runner = m4b_runner_factory(TransportMode.DENY)
            process = runner.run(
                _worker_argv(
                    "--scenario", "NET-03", "--target",
                    f"{address}:{server.getsockname()[1]}",
                ),
                cwd="/workspace", env={},
            )
            assert process.exit_code == 0, process.stderr
            assert json.loads(process.stdout)["succeeded"] is False
            with pytest.raises(TimeoutError):
                server.recvfrom(256)
            _assert_no_m4b_residue(runner)
        finally:
            server.close()


def _recorded_wsl_gateway():
    lines = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
    gateways = []
    for line in lines:
        fields = line.split()
        if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 2:
            gateways.append(socket.inet_ntoa(struct.pack("<I", int(fields[2], 16))))
    assert len(gateways) == 1
    return gateways[0]


@pytest.mark.parametrize("scenario", ["NET-02", "NET-03"])
def test_windows_gateway_and_nonlocal_lan_targets_are_unreachable(
    m4b_runner_factory, scenario
):
    topology_targets = {
        "windows_gateway": _recorded_wsl_gateway(),
        "nonlocal_lan_fixture": "192.0.2.1",
    }
    for label, address in topology_targets.items():
        runner = m4b_runner_factory(TransportMode.DENY)
        process = runner.run(
            _worker_argv(
                "--scenario", scenario, "--target", f"{address}:18081"
            ),
            cwd="/workspace", env={},
        )
        assert process.exit_code == 0, f"{label}: {process.stderr}"
        result = json.loads(process.stdout)
        assert result["succeeded"] is False, (label, result)
        _assert_no_m4b_residue(runner)


@pytest.mark.parametrize(
    ("scenario", "target"),
    [
        ("PROC-01", None), ("PROC-02", None), ("PROC-03", None),
        ("PROC-04", None), ("PROC-05", "/tmp/m4b-lingering"),
        ("PROC-06", "/tmp/m4b-double-fork"), ("PROC-07", None),
        ("PROC-08", "/tmp/m4b-new-pgroup"),
    ],
)
def test_m4b_descendant_shapes_end_with_recursive_empty_scope(
    m4b_runner_factory, scenario, target
):
    runner = m4b_runner_factory(TransportMode.DENY)
    args = ["--scenario", scenario]
    if target is not None:
        args += ["--target", target]
    process = runner.run(_worker_argv(*args), cwd="/workspace", env={})
    assert process.exit_code == 0, process.stderr
    assert json.loads(process.stdout)["succeeded"] is True
    assert process.containment_state == ContainmentState.TERMINATED.value
    _assert_no_m4b_residue(runner)


def test_m4a_workspace_credentials_and_direct_network_invariants_remain(
    m4b_runner_factory
):
    for args in (
        ("--scenario", "FS-16"),
        ("--scenario", "PROC-09"),
        ("--scenario", "NET-02", "--target", "127.0.0.1:9"),
        ("--scenario", "SOCK-01", "--target", "/tmp/not-host.sock"),
    ):
        runner = m4b_runner_factory(TransportMode.DENY)
        process = runner.run(_worker_argv(*args), cwd="/workspace", env={})
        assert process.exit_code == 0, process.stderr
        result = json.loads(process.stdout)
        if args[1] == "FS-16":
            assert result["details"]["cwd"] == "/workspace"
            assert result["details"]["sibling_visible"] is False
        elif args[1] == "PROC-09":
            assert result["details"]["fds_beyond_stdio"] == []
            assert set(result["details"]["capabilities"].values()) == {
                "0000000000000000"
            }
        else:
            assert result["succeeded"] is False
        _assert_no_m4b_residue(runner)
