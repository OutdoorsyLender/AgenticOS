"""Real-host integration proof for the M4B-2 HTTPS broker serve path.

Full launches through the authenticated M4B-1 broker boundary carrying the
sealed NetworkPolicy and sealed task certificate material.  Slice 9b serves
the gated HTTPS pipeline in the broker: strict CONNECT authority -> grant
authorization -> bounded ClientHello gate -> per-connection worker TLS
termination -> strict HTTP/1.1 prevalidation -> validated resolution ->
numeric connect -> authenticated origin TLS -> bounded verbatim relay.  The
origin side is the conformance FixtureFdConnector: an already-connected
synthetic origin (socketpair to a test TLS server) selected ONLY by the
private runner API and committed to evidence as non-production synthetic.
Conventions mirror test_m4b_integration.py.
"""

from __future__ import annotations

import sys

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("M4B-2 HTTPS real-host proof requires Linux", allow_module_level=True)

import array
import datetime
import fcntl
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time
import uuid

from agenticos.sandbox import host_qualification as hq
from agenticos.sandbox import m4b_runner as runner_module
from agenticos.sandbox import network_broker as broker_module
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

import chgen
from helpers import WORKER_PATH, pid_alive
from test_m4b_integration import (
    FAST,
    _assert_no_m4b_residue,
    _fixed_native_fd_window,
    _same_uid_opaque_fd_baseline,
)
from test_m4b_origin_unit import _custom_material, _server_context


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
        purpose=GrantPurpose.GENERAL_DOWNLOAD,
        fixture_origin=None,
        fixture_addresses=("93.184.216.34",),
        connection_limit=1,
        byte_limit=64 * 1024,
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
            connection_limit=connection_limit,
            byte_limit=byte_limit,
        )
        connector = None
        if fixture_origin is not None:
            # Pin the synthetic origin socket above the fixed native FD
            # window before the launch vacates low descriptors.
            pinned = fcntl.fcntl(
                fixture_origin.broker_sock.fileno(), fcntl.F_DUPFD_CLOEXEC, 300
            )
            fixture_origin.broker_sock.close()
            fixture_origin.broker_sock = socket.socket(fileno=pinned)
            connector = runner_module.FixtureFdConnector(
                fixture_origin.broker_sock,
                ca_certs_pem=fixture_origin.pems["ca"].decode("ascii"),
                addresses=fixture_addresses,
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
            grant_purpose=purpose,
            approval_source="m4b2-integration",
            approval_reference="slice-9b",
            host_state_dir=host_state_dir or m4b2_host_state,
            broker_vendor_dir=m4b2_vendor,
            _fixture_connector=connector,
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
    # Slice 9b: the broker serves the HTTPS pipeline; with no worker
    # connection the clean worker exit reaps the broker and the runner
    # synthesizes the aggregate from the (empty) record set.
    assert observation.terminal_reason.value == "REVOKED"
    assert runner.last_https_terminal is observation
    assert runner.last_https_terminal_source == "synthesized_at_worker_exit"
    assert runner.last_https_connection_records == ()
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
        hostnames=(APPROVED_HOSTNAME,),
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
                openssl_runtime_identity=ssl.OPENSSL_VERSION,
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


# ============================================================================
# Slice 9b: real-launch HTTPS serve path through the FixtureFdConnector
# ============================================================================


def _origin_read_request(tls):
    """Read one request head plus any Content-Length body (test origin side)."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = tls.recv(4096)
        if not chunk:
            return data
        data += chunk
        if len(data) > 65536:
            raise RuntimeError("origin request head exceeded test bound")
    head, _, rest = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(rest) < length:
        chunk = tls.recv(4096)
        if not chunk:
            break
        rest += chunk
    return head + b"\r\n\r\n" + rest


class _SyntheticOriginServer:
    """A scripted test TLS origin on one end of the fixture socketpair."""

    def __init__(
        self,
        cert_dir,
        *,
        hostname=APPROVED_HOSTNAME,
        body=b"agenticos-m4b2-origin-body",
        delay=0.0,
        request_count=1,
    ):
        cert_dir.mkdir(parents=True, exist_ok=True)
        now = datetime.datetime.now(datetime.timezone.utc)
        self.pems = _custom_material(
            now - datetime.timedelta(minutes=2),
            now + datetime.timedelta(hours=1),
            hostname=hostname,
        )
        self.requests = []
        self.errors = []
        self.body = body
        broker_end, server_end = socket.socketpair()
        # Pin both ends above the fixed native FD window: the launch chain
        # vacates low descriptors and the origin thread runs across it.
        for index, sock in enumerate((broker_end, server_end)):
            pinned = fcntl.fcntl(sock.fileno(), fcntl.F_DUPFD_CLOEXEC, 300 + index)
            sock.close()
            if index == 0:
                broker_end = socket.socket(fileno=pinned)
            else:
                server_end = socket.socket(fileno=pinned)
        self.broker_sock = broker_end
        self._context = _server_context(cert_dir, self.pems)
        self._thread = threading.Thread(
            target=self._run,
            args=(server_end, delay, request_count),
            daemon=True,
        )
        self._thread.start()

    def _run(self, sock, delay, request_count):
        try:
            tls = self._context.wrap_socket(sock, server_side=True)
            tls.settimeout(25.0)
            for _ in range(request_count):
                request = _origin_read_request(tls)
                self.requests.append(request)
                if delay:
                    time.sleep(delay)
                tls.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: "
                    + str(len(self.body)).encode("ascii")
                    + b"\r\nConnection: close\r\n\r\n" + self.body
                )
            tls.close()
        except (ssl.SSLError, OSError) as exc:
            self.errors.append(f"{type(exc).__name__}: {exc}")
        except RuntimeError as exc:
            self.errors.append(str(exc))
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def expected_response(self):
        return (
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(self.body)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n" + self.body
        )

    def join(self, timeout=8.0):
        self._thread.join(timeout)
        assert not self._thread.is_alive(), "synthetic origin thread stuck"

    def close(self):
        try:
            self.broker_sock.close()
        except OSError:
            pass


def _https_worker_options(target, options):
    return _worker_argv(
        "--scenario",
        "M4B2-01",
        "--target",
        target,
        "--canary",
        json.dumps(options, separators=(",", ":")),
    )


def _sole_connection_record(runner):
    records = runner.last_https_connection_records
    assert records is not None and len(records) == 1, records
    return records[0]


def test_https_full_path_worker_receives_exact_origin_bytes(
    m4b2_runner_factory, tmp_path
):
    origin = _SyntheticOriginServer(tmp_path / "origin")
    runner = m4b2_runner_factory(fixture_origin=origin)
    process = runner.run(
        _https_worker_options(f"{APPROVED_HOSTNAME}:443", {}),
        cwd="/workspace",
        env={},
    )
    assert process.exit_code == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["succeeded"] is True, result
    details = result["details"]
    assert details["connect_reply"].startswith("HTTP/1.1 200")
    assert details["tls_version"] == "TLSv1.3"
    assert details["alpn"] == "http/1.1"
    response = details["responses"][0]
    assert response["status"] == 200
    assert bytes.fromhex(response["body_hex"]) == origin.body

    expected_request = (
        f"GET / HTTP/1.1\r\nHost: {APPROVED_HOSTNAME}\r\n\r\n"
    ).encode("ascii")
    origin.join()
    assert origin.requests == [expected_request]
    assert origin.errors == []
    expected_response = origin.expected_response()

    terminal = runner.last_https_terminal
    assert terminal is not None
    assert terminal.terminal_reason.value == "REVOKED"
    assert terminal.synthetic_origin is True
    # Clean worker exit reaps the broker: the aggregate is synthesized from
    # the authenticated per-connection records (see network_broker.py).
    assert runner.last_https_terminal_source == "synthesized_at_worker_exit"
    record = _sole_connection_record(runner)
    # The whole identity chain is bound to the approved hostname.
    assert record.identity_chain == "verified"
    assert record.connect_authority == APPROVED_HOSTNAME
    assert record.worker_sni == APPROVED_HOSTNAME
    assert record.http_host == APPROVED_HOSTNAME
    assert record.origin_tls_name == APPROVED_HOSTNAME
    assert record.worker_tls_version == "TLSv1.3"
    assert record.origin_tls_version == "TLSv1.3"
    assert record.worker_alpn == "http/1.1"
    assert record.origin_alpn == "http/1.1"
    assert record.origin_peer_address == "93.184.216.34"
    assert record.origin_peer_port == 443
    assert record.synthetic_origin is True
    assert record.terminal_reason.value == "completed"
    assert record.requests_completed == 1
    # Byte accounting invariants, exact both directions.
    assert record.worker_to_origin_bytes == len(expected_request)
    assert record.origin_to_worker_bytes == len(expected_response)
    assert record.total_bytes == len(expected_request) + len(expected_response)
    assert record.accounted_bytes == (
        record.total_bytes + record.discarded_unsent_bytes
    )
    assert terminal.connection_count == 1
    assert terminal.accounted_bytes == record.accounted_bytes
    assert terminal.worker_to_origin_bytes == record.worker_to_origin_bytes
    assert terminal.origin_to_worker_bytes == record.origin_to_worker_bytes
    origin.close()
    _assert_no_m4b_residue(runner)


def test_https_ech_clienthello_denied(m4b2_runner_factory, tmp_path):
    origin = _SyntheticOriginServer(tmp_path / "origin")
    runner = m4b2_runner_factory(fixture_origin=origin)
    hello = chgen.make_client_hello(APPROVED_HOSTNAME.encode("ascii"), ech=True)
    process = runner.run(
        _https_worker_options(
            f"{APPROVED_HOSTNAME}:443", {"raw_tls_hex": hello.hex()}
        ),
        cwd="/workspace",
        env={},
    )
    assert process.exit_code == 0, process.stderr
    result = json.loads(process.stdout)
    details = result["details"]
    # The CONNECT is authorized (200), then the ECH-bearing ClientHello is
    # rejected at the gate: no TLS trust is ever established.
    assert details["connect_reply"].startswith("HTTP/1.1 200")
    assert details["raw_received_length"] == 0
    origin.close()
    origin.join()
    assert origin.requests == []
    record = _sole_connection_record(runner)
    assert record.stage_reached.value == "clienthello_gate"
    assert record.terminal_reason.value == "denied"
    assert "0xfe0d" in record.detail
    assert record.worker_sni is None
    assert record.worker_tls_version is None
    _assert_no_m4b_residue(runner)


def test_https_wrong_sni_denied(m4b2_runner_factory, tmp_path):
    origin = _SyntheticOriginServer(tmp_path / "origin")
    runner = m4b2_runner_factory(fixture_origin=origin)
    process = runner.run(
        _https_worker_options(
            f"{APPROVED_HOSTNAME}:443", {"sni": "evil.example.com"}
        ),
        cwd="/workspace",
        env={},
    )
    assert process.exit_code == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["succeeded"] is False, result
    origin.close()
    origin.join()
    assert origin.requests == []
    record = _sole_connection_record(runner)
    assert record.stage_reached.value == "worker_tls"
    assert record.detail == "worker_tls_sni_mismatch"
    assert record.worker_sni == "evil.example.com"
    assert record.identity_chain == "identity_divergence:worker_sni"
    _assert_no_m4b_residue(runner)


def test_https_host_grant_mismatch_denied(m4b2_runner_factory, tmp_path):
    origin = _SyntheticOriginServer(tmp_path / "origin")
    runner = m4b2_runner_factory(fixture_origin=origin)
    options = {"requests": [{"method": "GET", "path": "/", "host": "evil.example.com"}]}
    process = runner.run(
        _https_worker_options(f"{APPROVED_HOSTNAME}:443", options),
        cwd="/workspace",
        env={},
    )
    assert process.exit_code == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["succeeded"] is False, result
    assert "error" in result["details"]["responses"][0]
    origin.close()
    origin.join()
    assert origin.requests == [], "a divergent Host reached the origin"
    record = _sole_connection_record(runner)
    assert record.stage_reached.value == "http_prevalidation"
    assert record.detail == "http_host_mismatch"
    assert record.identity_chain == "identity_divergence:http_host"
    assert record.requests_completed == 0
    _assert_no_m4b_residue(runner)


def test_https_te_cl_smuggling_denied(m4b2_runner_factory, tmp_path):
    origin = _SyntheticOriginServer(tmp_path / "origin")
    runner = m4b2_runner_factory(fixture_origin=origin)
    options = {
        "requests": [
            {
                "method": "GET",
                "path": "/",
                "body": "abcd",
                "extra_headers": [["Transfer-Encoding", "chunked"]],
            }
        ]
    }
    process = runner.run(
        _https_worker_options(f"{APPROVED_HOSTNAME}:443", options),
        cwd="/workspace",
        env={},
    )
    assert process.exit_code == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["succeeded"] is False, result
    origin.close()
    origin.join()
    assert origin.requests == []
    record = _sole_connection_record(runner)
    assert record.stage_reached.value == "http_prevalidation"
    assert record.detail == "http_te_with_content_length"
    _assert_no_m4b_residue(runner)


def test_https_post_allowed_for_git_smart_fetch(m4b2_runner_factory, tmp_path):
    origin = _SyntheticOriginServer(tmp_path / "origin")
    runner = m4b2_runner_factory(
        fixture_origin=origin, purpose=GrantPurpose.GIT_SMART_FETCH
    )
    options = {
        "requests": [
            {"method": "POST", "path": "/git-upload-pack", "body": "0000"}
        ]
    }
    process = runner.run(
        _https_worker_options(f"{APPROVED_HOSTNAME}:443", options),
        cwd="/workspace",
        env={},
    )
    assert process.exit_code == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["succeeded"] is True, result
    expected_request = (
        f"POST /git-upload-pack HTTP/1.1\r\nHost: {APPROVED_HOSTNAME}\r\n"
        "Content-Length: 4\r\n\r\n0000"
    ).encode("ascii")
    origin.join()
    assert origin.requests == [expected_request]
    record = _sole_connection_record(runner)
    assert record.requests_completed == 1
    assert record.worker_to_origin_bytes == len(expected_request)
    assert record.terminal_reason.value == "completed"
    origin.close()
    _assert_no_m4b_residue(runner)


def test_https_post_denied_for_general_download(m4b2_runner_factory, tmp_path):
    origin = _SyntheticOriginServer(tmp_path / "origin")
    runner = m4b2_runner_factory(fixture_origin=origin)
    options = {
        "requests": [
            {"method": "POST", "path": "/git-upload-pack", "body": "0000"}
        ]
    }
    process = runner.run(
        _https_worker_options(f"{APPROVED_HOSTNAME}:443", options),
        cwd="/workspace",
        env={},
    )
    assert process.exit_code == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["succeeded"] is False, result
    origin.close()
    origin.join()
    assert origin.requests == []
    record = _sole_connection_record(runner)
    assert record.stage_reached.value == "http_prevalidation"
    assert record.detail == "http_method_not_allowed"
    _assert_no_m4b_residue(runner)


def test_https_origin_wrong_hostname_cert_fails_closed(
    m4b2_runner_factory, tmp_path
):
    origin = _SyntheticOriginServer(
        tmp_path / "origin", hostname="evil.example.com"
    )
    runner = m4b2_runner_factory(fixture_origin=origin)
    process = runner.run(
        _https_worker_options(f"{APPROVED_HOSTNAME}:443", {}),
        cwd="/workspace",
        env={},
    )
    assert process.exit_code == 0, process.stderr
    result = json.loads(process.stdout)
    # The origin TLS verification fails closed: no origin bytes reach the
    # worker even though the test CA is trusted for the fixture.
    assert result["succeeded"] is False, result
    response = result["details"]["responses"][0]
    assert "error" in response and response.get("status") is None
    origin.close()
    origin.join()
    assert origin.requests == []
    record = _sole_connection_record(runner)
    assert record.stage_reached.value == "origin_tls"
    assert record.detail == "origin_verification_failed"
    assert record.origin_to_worker_bytes == 0
    _assert_no_m4b_residue(runner)


def test_https_prohibited_fixture_address_denied_before_connect(
    m4b2_runner_factory, tmp_path
):
    origin = _SyntheticOriginServer(tmp_path / "origin")
    runner = m4b2_runner_factory(
        fixture_origin=origin, fixture_addresses=("127.0.0.1",)
    )
    process = runner.run(
        _https_worker_options(f"{APPROVED_HOSTNAME}:443", {}),
        cwd="/workspace",
        env={},
    )
    assert process.exit_code == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["succeeded"] is False, result
    origin.close()
    origin.join()
    # The prohibited loopback resolution is denied before the fixture socket
    # is ever used: no TLS handshake reaches the synthetic origin.
    assert origin.requests == []
    record = _sole_connection_record(runner)
    assert record.stage_reached.value == "resolution"
    assert record.detail == "origin_prohibited_address"
    assert record.origin_tls_version is None
    assert record.worker_to_origin_bytes == 0
    _assert_no_m4b_residue(runner)


def test_https_revoke_mid_connection_tears_down(m4b2_runner_factory, tmp_path):
    origin = _SyntheticOriginServer(tmp_path / "origin", delay=10.0)
    runner = m4b2_runner_factory(fixture_origin=origin)
    process = runner.run(
        _https_worker_options(f"{APPROVED_HOSTNAME}:443", {}),
        cwd="/workspace",
        env={},
        timeout=3.0,
    )
    assert process.timed_out is True, process
    terminal = runner.last_https_terminal
    assert terminal is not None
    assert terminal.terminal_reason.value == "REVOKED"
    assert terminal.synthetic_origin is True
    # The revoke was processed while the worker lived: a real broker terminal.
    assert runner.last_https_terminal_source == "broker"
    record = _sole_connection_record(runner)
    assert record.terminal_reason.value == "revoked"
    origin.close()
    _assert_no_m4b_residue(runner)


def test_https_expiry_tears_down_connections(m4b2_runner_factory, tmp_path):
    origin = _SyntheticOriginServer(tmp_path / "origin", delay=10.0)
    runner = m4b2_runner_factory(fixture_origin=origin, lifetime=6.0)
    # Mid-run policy expiry exits the broker with an EXPIRED terminal; the
    # worker stays alive past it (post_sleep), so the pump's broker-liveness
    # gate deterministically fails the run closed — exactly how M4B-1 treats
    # a mid-run broker death.  Connection-level expiry accounting (closed
    # connections, discarded buffered bytes) is proven in the unit suite
    # (test_serve_expiry_*).
    with pytest.raises(runner_module.CapabilityTransportError):
        runner.run(
            _https_worker_options(
                f"{APPROVED_HOSTNAME}:443", {"post_sleep": 8.0}
            ),
            cwd="/workspace",
            env={},
        )
    origin.close()
    _assert_no_m4b_residue(runner)


# -- Slice 9c: startup probe gating readiness -----------------------------------------


def test_startup_probe_passes_in_real_launch(m4b2_runner_factory):
    runner = m4b2_runner_factory()
    process = runner.run(["/usr/bin/true"], cwd="/workspace", env={})
    assert process.exit_code == 0, process.stderr
    # Readiness was achieved, which now PROVES the broker's fail-closed
    # startup probe passed: the sealed NetworkPolicy carried the host
    # manifest's OpenSSL identity and the broker verified it against its
    # own runtime before emitting its ready record.
    assert (
        runner.last_https_network_policy.openssl_runtime_identity
        == ssl.OPENSSL_VERSION
    )
    _assert_no_m4b_residue(runner)


def test_tampered_openssl_identity_fails_closed_before_exec(
    m4b2_runner_factory,
):
    runner = m4b2_runner_factory()
    policy = runner.transport_policy
    material = generate_task_material(
        task_id=policy.task_id,
        task_generation=policy.task_generation,
        launch_nonce=policy.launch_nonce,
        hostnames=(APPROVED_HOSTNAME,),
        policy_digest=policy_digest(policy),
    )
    sealed_fd = None
    try:
        # The SEALED NetworkPolicy commits a well-formed but WRONG expected
        # OpenSSL identity.  Controller-side assembly checks (task context,
        # grant, CA commit) all pass; the broker's startup probe — comparing
        # the sealed expectation against its OWN ssl.OPENSSL_VERSION — is
        # what must fail closed before readiness (and before hostile exec).
        now_wall = time.time_ns()
        tampered_policy = NetworkPolicy(
            version="AOSHTTPS/1",
            task_id=policy.task_id,
            task_generation=policy.task_generation,
            launch_nonce=policy.launch_nonce,
            task_ca_certificate_digest=material.binding.ca_cert_sha256,
            openssl_runtime_identity="OpenSSL 9.9.9 tampered",
            grants=(
                NetworkGrant(
                    grant_id="g-tampered",
                    hostname=APPROVED_HOSTNAME,
                    purpose=GrantPurpose.GENERAL_DOWNLOAD,
                    approval_source="m4b2-integration",
                    approval_reference="slice-9c",
                    granted_at_wall_ns=now_wall,
                    expires_at_wall_ns=now_wall + 3_600_000_000_000,
                    activated_at_monotonic_ns=policy.activated_at_monotonic_ns,
                    expires_at_monotonic_ns=policy.expires_at_monotonic_ns,
                    connection_limit=1,
                    byte_limit=64 * 1024,
                ),
            ),
        )
        sealed_fd = create_sealed_network_policy_fd(tampered_policy)
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
            network_policy=tampered_policy,
            sealed_network_policy_fd=sealed_fd,
            material=material,
            worker_ca_path=worker_ca_path,
            worker_ca_dir=worker_ca_dir,
        )
        sealed_fd = None
        try:
            with pytest.raises(
                runner_module.CapabilityTransportError
            ) as excinfo:
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
    # The launch died AT the readiness gate: the broker's startup probe
    # rejected the sealed OpenSSL identity and exited without a ready record,
    # so the readiness channel closed before any record arrived.
    assert "readiness" in str(excinfo.value), excinfo.value
    # The probe failure denied readiness, so the final exec gate was never
    # released: no hostile exec happened.
    outcome = runner.last_launch_outcome
    assert outcome is not None and outcome["exec_succeeded"] is False, outcome
    _assert_no_m4b_residue(runner)
