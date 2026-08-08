"""Unit-level contracts for the Milestone 3B native Landlock boundary."""

from __future__ import annotations

import fcntl
import os
import re
import select
import socket
import subprocess
import sys
import time
from pathlib import Path

import agenticos.sandbox.launcher as launcher_module
import pytest
from agenticos.sandbox.launcher import (
    DEFAULT_LAUNCHER_PATH,
    NetworkLaunchRecord,
    build_launch_request,
    parse_launcher_status,
    prepare_launch_request,
    sanitize_env,
)
from agenticos.sandbox.network_identity import recv_listener_fd
from agenticos.sandbox.isolation import FilesystemPolicy
from agenticos.sandbox.fixtures import FixtureBuilder
from agenticos.sandbox.models import PolicyExpectation
from agenticos.sandbox.policy import default_policy


REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = [
    pytest.mark.fs_isolation_linux,
    pytest.mark.skipif(
        not sys.platform.startswith("linux"),
        reason="native launcher contracts require Linux",
    ),
]


def test_default_launcher_path_targets_repository_native_directory():
    expected = REPO_ROOT / "native" / "fs_launcher" / "fs_launcher"
    assert DEFAULT_LAUNCHER_PATH == expected


def test_status_parser_authenticates_policy_acknowledgement_metadata():
    outcome = parse_launcher_status(
        b"R:request-nonce\nS\nP\nN\nA:3:7fff:policy-digest\n",
        expected_nonce="request-nonce",
        expected_policy_digest="policy-digest",
    )
    assert outcome["failed_stage"] is None
    assert outcome["policy_applied"] is True
    assert outcome["abi"] == 3
    assert outcome["handled_access_fs"] == 0x7FFF
    assert outcome["policy_digest"] == "policy-digest"
    assert outcome["exec_succeeded"] is False


def test_status_parser_rejects_nonce_or_policy_digest_mismatch():
    outcome = parse_launcher_status(
        b"R:wrong-nonce\nS\nP\nN\nA:3:7fff:wrong-digest\n",
        expected_nonce="request-nonce",
        expected_policy_digest="policy-digest",
    )
    assert outcome["failed_stage"] == "protocol"
    assert outcome["policy_applied"] is False
    assert outcome["exec_succeeded"] is False


@pytest.mark.parametrize(
    "status",
    [
        b"R:request-nonce\nS\nP\nA:3:7fff:policy-digest\n",
        b"R:request-nonce\nS\nN\nP\nA:3:7fff:policy-digest\n",
        b"R:request-nonce\nS\nP\nN\nN\nA:3:7fff:policy-digest\n",
        b"R:request-nonce\nS\nP\nN\nA:2:7fff:policy-digest\n",
        b"R:request-nonce\nS\nP\nN\nA:3:3fff:policy-digest\n",
    ],
)
def test_status_parser_rejects_incomplete_or_weakened_policy_evidence(status):
    outcome = parse_launcher_status(
        status,
        expected_nonce="request-nonce",
        expected_policy_digest="policy-digest",
    )
    assert outcome["failed_stage"] == "protocol"
    assert outcome["policy_applied"] is False


def test_status_parser_preserves_setup_failure_before_policy_ack():
    outcome = parse_launcher_status(
        b"R:request-nonce\nS\nF:rule:22\n",
        expected_nonce="request-nonce",
        expected_policy_digest="policy-digest",
    )
    assert outcome["failed_stage"] == "rule"
    assert outcome["errno"] == 22
    assert outcome["policy_applied"] is False


def test_prepared_request_binds_wire_nonce_and_policy_digest(tmp_path):
    prepared = launcher_module.prepare_launch_request(
        ["/usr/bin/true"],
        {},
        str(tmp_path),
        [("/usr", "x"), (str(tmp_path), "w")],
        nonce="fixed-nonce",
    )
    assert prepared.nonce == "fixed-nonce"
    assert len(prepared.policy_digest) == 64
    assert f"nonce 11 fixed-nonce\n".encode() in prepared.wire
    assert (
        f"policy_digest 64 {prepared.policy_digest}\n".encode()
        in prepared.wire
    )


def test_layout_policy_grants_only_explicit_standard_device_nodes(tmp_path):
    with FixtureBuilder(tmp_path / "fixture") as layout:
        policy = FilesystemPolicy.for_layout(
            layout, REPO_ROOT / "tests" / "fixtures" / "hostile_worker.py"
        )
    roots = dict(policy.to_launcher_roots())
    assert "/dev" not in roots
    assert roots["/dev/null"] == "w"
    assert roots["/dev/zero"] == "w"
    assert roots["/dev/random"] == "r"
    assert roots["/dev/urandom"] == "r"


def test_launcher_policy_rejects_writable_ancestor_of_readonly_root(tmp_path):
    workspace = tmp_path / "workspace"
    readonly = workspace / "readonly"
    readonly.mkdir(parents=True)
    policy = FilesystemPolicy(workspace=workspace, readonly_paths=[readonly])
    with pytest.raises(ValueError, match="overlapping policy roots"):
        policy.to_launcher_roots()


def test_launcher_policy_rejects_conflicting_modes_for_same_object(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    policy = FilesystemPolicy(workspace=workspace, readonly_paths=[workspace])
    with pytest.raises(ValueError, match="conflicting modes"):
        policy.to_launcher_roots()


def test_launcher_policy_allows_readonly_ancestor_with_writable_exception(tmp_path):
    parent = tmp_path / "parent"
    writable = parent / "writable"
    writable.mkdir(parents=True)
    policy = FilesystemPolicy(
        workspace=writable,
        readonly_paths=[parent],
    )
    assert policy.to_launcher_roots()


def test_default_policy_denies_new_truncation_and_reparent_attacks():
    policy = default_policy()
    assert policy.expectation_for("FS-14") == PolicyExpectation.DENY.value
    assert policy.expectation_for("FS-15") == PolicyExpectation.DENY.value


def test_worker_environment_drops_ambient_credential_and_control_variables():
    kept, dropped = sanitize_env(
        {
            "PATH": "/usr/bin",
            "AOS_HARMLESS": "fixture",
            "SSH_AUTH_SOCK": "/synthetic/agent.sock",
            "AWS_ACCESS_KEY_ID": "synthetic",
            "OPENAI_API_KEY": "synthetic",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/synthetic/bus",
            "XDG_RUNTIME_DIR": "/synthetic/run",
        }
    )
    assert kept == {"PATH": "/usr/bin", "AOS_HARMLESS": "fixture"}
    assert dropped == [
        "AWS_ACCESS_KEY_ID",
        "DBUS_SESSION_BUS_ADDRESS",
        "OPENAI_API_KEY",
        "SSH_AUTH_SOCK",
        "XDG_RUNTIME_DIR",
    ]


def test_native_launcher_compiles_warning_clean_with_installed_uapi(tmp_path):
    source = REPO_ROOT / "native" / "fs_launcher" / "fs_launcher.c"
    output = tmp_path / "fs_launcher"
    result = subprocess.run(
        [
            "cc",
            "-std=c11",
            "-D_GNU_SOURCE",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O2",
            str(source),
            "-o",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert output.is_file()


def _compile_launcher(output: Path) -> None:
    source = REPO_ROOT / "native" / "fs_launcher" / "fs_launcher.c"
    subprocess.run(
        [
            "cc",
            "-std=c11",
            "-D_GNU_SOURCE",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O2",
            str(source),
            "-o",
            str(output),
        ],
        check=True,
    )


def _read_exact_with_timeout(fd: int, size: int, timeout: float) -> bytes:
    data = b""
    deadline = time.monotonic() + timeout
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        readable, _, _ = select.select([fd], [], [], remaining)
        if not readable:
            break
        chunk = os.read(fd, size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _read_line_with_timeout(fd: int, timeout: float, cap: int = 4096) -> bytes:
    data = b""
    deadline = time.monotonic() + timeout
    while len(data) < cap:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        readable, _, _ = select.select([fd], [], [], remaining)
        if not readable:
            break
        chunk = os.read(fd, 1)
        if not chunk:
            break
        data += chunk
        if chunk == b"\n":
            break
    return data


def _read_status_terminal(fd: int, timeout: float = 3.0) -> bytes:
    data = b""
    deadline = time.monotonic() + timeout
    while len(data) < 8192:
        if any(
            line.startswith((b"A:", b"F:", b"E:"))
            for line in data.splitlines()
        ):
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        readable, _, _ = select.select([fd], [], [], remaining)
        if not readable:
            break
        chunk = os.read(fd, 1024)
        if not chunk:
            break
        data += chunk
    return data


def _drain_fd(fd: int) -> bytes:
    data = b""
    while True:
        chunk = os.read(fd, 4096)
        if not chunk:
            return data
        data += chunk


@pytest.fixture(scope="module")
def m4b_native_launcher(tmp_path_factory):
    launcher = tmp_path_factory.mktemp("m4b-native-launcher") / "fs_launcher"
    _compile_launcher(launcher)
    return launcher


def _v3_request(
    *,
    status_fd: int,
    handoff_fd: int,
    cwd: Path,
    argv: list[str] | None = None,
    include_proc: bool = False,
):
    cwd_status = os.stat(cwd)
    usr_status = os.stat("/usr")
    root_records = [
        ("/usr", usr_status.st_dev, usr_status.st_ino, "x"),
        (str(cwd), cwd_status.st_dev, cwd_status.st_ino, "w"),
    ]
    if include_proc:
        proc_status = os.stat("/proc")
        root_records.append(
            ("/proc", proc_status.st_dev, proc_status.st_ino, "r")
        )
    record = NetworkLaunchRecord(
        task_id="task-7",
        task_generation=3,
        launch_nonce="ab" * 16,
        network_policy_digest="c" * 64,
        handoff_fd=handoff_fd,
        proxy_host="127.0.0.1",
        proxy_port=18080,
    )
    prepared = prepare_launch_request(
        argv or ["/usr/bin/true"],
        {"PATH": "/usr/bin"},
        str(cwd),
        [],
        protocol_version=3,
        cwd_record=(str(cwd), cwd_status.st_dev, cwd_status.st_ino),
        root_records=root_records,
        policy_digest_override="d" * 64,
        status_fd=status_fd,
        network_record=record,
    )
    return record, prepared


def _spawn_v3(
    launcher: Path,
    prepared,
    status_w: int,
    handoff_fd: int,
):
    return subprocess.Popen(
        [str(launcher)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"AOS_STATUS_FD": "1"},
        pass_fds=(status_w, handoff_fd),
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-network",
        "duplicate-network",
        "unknown-record",
        "overlong-network",
        "truncated-network",
        "extra-network-field",
        "bad-task-id",
        "nonce-mismatch",
        "uppercase-digest",
        "wrong-host",
        "wrong-port",
        "generation-overflow",
        "handoff-overflow",
        "leading-generation",
        "leading-handoff",
        "leading-status",
        "nul-network-suffix",
        "nul-status-suffix",
        "nul-argv-suffix",
        "descriptor-collision",
        "descriptor-collision-before-error",
    ],
)
def test_protocol_v3_native_parser_rejects_malformed_network_record(
    m4b_native_launcher, tmp_path, mutation
):
    status_r, status_w = os.pipe()
    sender, receiver = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
    )
    proc = None
    try:
        record, prepared = _v3_request(
            status_fd=status_w,
            handoff_fd=sender.fileno(),
            cwd=tmp_path,
        )
        network_line = next(
            line for line in prepared.wire.splitlines(keepends=True)
            if line.startswith(b"network ")
        )
        if mutation == "missing-network":
            wire = prepared.wire.replace(network_line, b"", 1)
        elif mutation == "duplicate-network":
            wire = prepared.wire.replace(network_line, network_line * 2, 1)
        elif mutation == "unknown-record":
            wire = prepared.wire.replace(network_line, network_line + b"unknown 1\n", 1)
        elif mutation == "overlong-network":
            wire = prepared.wire.replace(network_line, b"network " + b"x" * 5000 + b"\n", 1)
        elif mutation == "truncated-network":
            wire = prepared.wire.replace(network_line, b"network task-7 3 ab\n", 1)
        elif mutation == "extra-network-field":
            wire = prepared.wire.replace(
                network_line, network_line.rstrip(b"\n") + b" extra\n", 1
            )
        elif mutation == "bad-task-id":
            tokens = network_line.split()
            tokens[1] = b"-task"
            wire = prepared.wire.replace(network_line, b" ".join(tokens) + b"\n", 1)
        elif mutation == "nonce-mismatch":
            tokens = network_line.split()
            tokens[3] = b"cd" * 16
            wire = prepared.wire.replace(network_line, b" ".join(tokens) + b"\n", 1)
        elif mutation == "uppercase-digest":
            tokens = network_line.split()
            tokens[4] = tokens[4].upper()
            wire = prepared.wire.replace(network_line, b" ".join(tokens) + b"\n", 1)
        elif mutation == "wrong-host":
            tokens = network_line.split()
            tokens[6] = b"0.0.0.0"
            wire = prepared.wire.replace(network_line, b" ".join(tokens) + b"\n", 1)
        elif mutation == "wrong-port":
            tokens = network_line.split()
            tokens[7] = b"18081"
            wire = prepared.wire.replace(network_line, b" ".join(tokens) + b"\n", 1)
        elif mutation == "generation-overflow":
            tokens = network_line.split()
            tokens[2] = str(1 << 64).encode("ascii")
            wire = prepared.wire.replace(network_line, b" ".join(tokens) + b"\n", 1)
        elif mutation == "handoff-overflow":
            tokens = network_line.split()
            tokens[5] = str(1 << 31).encode("ascii")
            wire = prepared.wire.replace(network_line, b" ".join(tokens) + b"\n", 1)
        elif mutation == "leading-generation":
            tokens = network_line.split()
            tokens[2] = b"03"
            wire = prepared.wire.replace(network_line, b" ".join(tokens) + b"\n", 1)
        elif mutation == "leading-handoff":
            tokens = network_line.split()
            tokens[5] = b"0" + tokens[5]
            wire = prepared.wire.replace(network_line, b" ".join(tokens) + b"\n", 1)
        elif mutation == "leading-status":
            wire = prepared.wire.replace(
                f"status_fd {status_w}\n".encode("ascii"),
                f"status_fd 0{status_w}\n".encode("ascii"),
                1,
            )
        elif mutation == "nul-network-suffix":
            wire = prepared.wire.replace(
                network_line, network_line.rstrip(b"\n") + b"\x00extra\n", 1
            )
        elif mutation == "nul-status-suffix":
            wire = prepared.wire.replace(
                f"status_fd {status_w}\n".encode("ascii"),
                f"status_fd {status_w}".encode("ascii") + b"\x00junk\n",
                1,
            )
        elif mutation == "nul-argv-suffix":
            wire = prepared.wire.replace(
                b"13 /usr/bin/true\n", b"13 /usr/bin/true\x00junk\n", 1
            )
        elif mutation == "descriptor-collision":
            wire = prepared.wire.replace(
                f"status_fd {status_w}\n".encode("ascii"),
                f"status_fd {record.handoff_fd}\n".encode("ascii"),
                1,
            )
        else:
            wire = prepared.wire.replace(
                f"status_fd {status_w}\n".encode("ascii"),
                f"status_fd {record.handoff_fd}\n".encode("ascii"),
                1,
            ).replace(network_line, network_line + b"unknown 1\n", 1)
        proc = _spawn_v3(
            m4b_native_launcher, prepared, status_w, sender.fileno()
        )
        os.close(status_w)
        status_w = -1
        sender.close()
        stdout, _stderr = proc.communicate(input=wire, timeout=5.0)
        status = _drain_fd(status_r)

        assert stdout == b""
        if mutation in (
            "descriptor-collision",
            "descriptor-collision-before-error",
            "leading-status",
            "nul-status-suffix",
        ):
            assert status == b""
            receiver.settimeout(1.0)
            assert receiver.recv(4096) == b""
        else:
            assert status.startswith(b"F:parse:")
        assert proc.returncode == 2
    finally:
        if status_w >= 0:
            os.close(status_w)
        os.close(status_r)
        sender.close()
        receiver.close()
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)


def test_protocol_v3_native_parser_missing_status_fd_never_uses_ambient_fd(
    m4b_native_launcher, tmp_path
):
    status_r, status_w = os.pipe()
    sender, receiver = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
    )
    proc = None
    try:
        _record, prepared = _v3_request(
            status_fd=status_w,
            handoff_fd=sender.fileno(),
            cwd=tmp_path,
        )
        wire = prepared.wire.replace(
            f"status_fd {status_w}\n".encode("ascii"), b"", 1
        )
        proc = _spawn_v3(
            m4b_native_launcher, prepared, status_w, sender.fileno()
        )
        os.close(status_w)
        status_w = -1
        sender.close()
        stdout, _stderr = proc.communicate(input=wire, timeout=5.0)
        status = _drain_fd(status_r)

        assert stdout == b""
        assert status == b""
        assert proc.returncode == 2
    finally:
        if status_w >= 0:
            os.close(status_w)
        os.close(status_r)
        sender.close()
        receiver.close()
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)


def test_protocol_legacy_unknown_header_still_reports_on_ambient_status_fd(
    m4b_native_launcher,
):
    status_r, status_w = os.pipe()
    proc = subprocess.Popen(
        [str(m4b_native_launcher)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"AOS_STATUS_FD": str(status_w)},
        pass_fds=(status_w,),
    )
    os.close(status_w)
    try:
        stdout, _stderr = proc.communicate(input=b"AOSLAUNCH/9\n", timeout=5.0)
        assert stdout == b""
        assert _drain_fd(status_r) == b"F:parse:71\n"
        assert proc.returncode == 2
    finally:
        os.close(status_r)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)


@pytest.mark.parametrize("protocol_version", [1, 2])
def test_protocol_v1_v2_native_parser_rejects_network_record(
    m4b_native_launcher, protocol_version
):
    if protocol_version == 1:
        prepared = prepare_launch_request(
            ["/usr/bin/true"], {}, "/tmp", [], nonce="legacy-network"
        )
    else:
        tmp_status = os.stat("/tmp")
        prepared = prepare_launch_request(
            ["/usr/bin/true"],
            {},
            "/tmp",
            [],
            nonce="legacy-network",
            protocol_version=2,
            cwd_record=("/tmp", tmp_status.st_dev, tmp_status.st_ino),
            root_records=[],
        )
    header, remainder = prepared.wire.split(b"\n", 1)
    injected = (
        header
        + b"\nnetwork task-7 3 "
        + b"ab" * 16
        + b" "
        + b"c" * 64
        + b" 35 127.0.0.1 18080\n"
        + remainder
    )
    status_r, status_w = os.pipe()
    proc = subprocess.Popen(
        [str(m4b_native_launcher)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"AOS_STATUS_FD": str(status_w)},
        pass_fds=(status_w,),
    )
    os.close(status_w)
    try:
        stdout, _stderr = proc.communicate(input=injected, timeout=5.0)
        assert stdout == b""
        assert _drain_fd(status_r).startswith(b"F:parse:")
        assert proc.returncode == 2
    finally:
        os.close(status_r)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)


def test_listener_handoff_native_frame_is_canonical_and_c_gate_precedes_sanitation(
    m4b_native_launcher, tmp_path
):
    marker = tmp_path / "worker-fds"
    worker = (
        "import os;"
        "names=os.listdir('/proc/self/fd');"
        "fds=sorted(int(n) for n in names "
        "if n.isdigit() and os.path.exists('/proc/self/fd/'+n));"
        f"open({str(marker)!r},'w').write(','.join(map(str,fds)))"
    )
    status_r, status_w = os.pipe()
    sender, receiver = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
    )
    proc = None
    adopted = None
    try:
        record, prepared = _v3_request(
            status_fd=status_w,
            handoff_fd=sender.fileno(),
            cwd=tmp_path,
            argv=["/usr/bin/python3", "-c", worker],
            include_proc=True,
        )
        proc = _spawn_v3(
            m4b_native_launcher, prepared, status_w, sender.fileno()
        )
        child_handoff_fd = sender.fileno()
        os.close(status_w)
        status_w = -1
        sender.close()
        assert proc.stdin is not None
        proc.stdin.write(prepared.wire)
        proc.stdin.flush()

        ready = _read_line_with_timeout(status_r, 2.0)
        assert ready == b"R:" + b"ab" * 16 + b"\n"
        fdinfo = Path(f"/proc/{proc.pid}/fdinfo/{child_handoff_fd}").read_text()
        flags = next(line for line in fdinfo.splitlines() if line.startswith("flags:"))
        assert int(flags.split()[1], 8) & os.O_CLOEXEC

        proc.stdin.write(b"G")
        proc.stdin.flush()
        adopted = recv_listener_fd(
            receiver,
            expected_task_id=record.task_id,
            expected_generation=record.task_generation,
            expected_nonce=record.launch_nonce,
            expected_policy_digest=record.network_policy_digest,
        )
        listener_status = _read_line_with_timeout(status_r, 2.0)
        assert listener_status.startswith(b"L:" + b"c" * 64 + b":{")
        partial = parse_launcher_status(
            ready + listener_status,
            expected_nonce=record.launch_nonce,
            expected_policy_digest="d" * 64,
            expected_network_record=record,
            protocol_version=3,
        )
        assert partial["failed_stage"] is None
        assert partial["listener_frame"].to_bytes() == adopted.frame.to_bytes()
        assert partial["listener_evidence"] == adopted.evidence
        assert adopted.evidence.netns_cookie > 0
        assert not marker.exists()
        adopted_stat = os.fstat(adopted.fd)
        listener_identity = (adopted_stat.st_dev, adopted_stat.st_ino)
        child_identities = set()
        for name in os.listdir(f"/proc/{proc.pid}/fd"):
            try:
                observed = os.stat(f"/proc/{proc.pid}/fd/{name}")
            except FileNotFoundError:
                continue
            child_identities.add((observed.st_dev, observed.st_ino))
        assert listener_identity not in child_identities
        assert Path(f"/proc/{proc.pid}/fd/{child_handoff_fd}").exists()
        readable, _, _ = select.select([status_r], [], [], 0.2)
        assert readable == []
        assert proc.poll() is None

        proc.stdin.write(b"C")
        proc.stdin.flush()
        after_c = _read_status_terminal(status_r)
        assert after_c.splitlines()[:5] == [
            b"S",
            b"I",
            b"P",
            b"N",
            b"A:3:7fff:" + b"d" * 64,
        ]
        transcript = ready + listener_status + after_c
        parsed = parse_launcher_status(
            transcript,
            expected_nonce=record.launch_nonce,
            expected_policy_digest="d" * 64,
            expected_network_record=record,
            protocol_version=3,
        )
        assert parsed["failed_stage"] is None
        assert parsed["progress"] == ["R", "L", "S", "I", "P", "N", "A"]
        assert not marker.exists()

        proc.stdin.write(b"X")
        proc.stdin.close()
        proc.stdin = None
        returncode = proc.wait(timeout=5.0)
        stderr = proc.stderr.read() if proc.stderr is not None else b""
        assert returncode == 0, stderr.decode(errors="replace")
        assert marker.read_text() == "0,1,2"
    finally:
        if adopted is not None:
            os.close(adopted.fd)
        if status_w >= 0:
            os.close(status_w)
        os.close(status_r)
        sender.close()
        receiver.close()
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)


@pytest.mark.parametrize(
    ("kind", "stage"),
    [
        ("regular", b"handoff_stat"),
        ("stream", b"handoff_type"),
        ("unconnected", b"handoff_peer"),
    ],
)
def test_listener_handoff_native_rejects_bad_kernel_endpoint(
    m4b_native_launcher, tmp_path, kind, stage
):
    status_r, status_w = os.pipe()
    peer = None
    if kind == "regular":
        endpoint = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
    elif kind == "stream":
        endpoint, peer = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC
        )
    else:
        endpoint = socket.socket(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
        )
    endpoint_fd = endpoint if type(endpoint) is int else endpoint.fileno()
    proc = None
    try:
        _record, prepared = _v3_request(
            status_fd=status_w,
            handoff_fd=endpoint_fd,
            cwd=tmp_path,
        )
        proc = _spawn_v3(m4b_native_launcher, prepared, status_w, endpoint_fd)
        os.close(status_w)
        status_w = -1
        if type(endpoint) is int:
            os.close(endpoint)
        else:
            endpoint.close()
        stdout, _stderr = proc.communicate(input=prepared.wire, timeout=5.0)
        status = _drain_fd(status_r)

        assert stdout == b""
        assert b"F:" + stage + b":" in status
        assert proc.returncode == 2
    finally:
        if status_w >= 0:
            os.close(status_w)
        os.close(status_r)
        if type(endpoint) is int:
            try:
                os.close(endpoint)
            except OSError:
                pass
        else:
            endpoint.close()
        if peer is not None:
            peer.close()
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)


def test_listener_handoff_native_bind_collision_fails_before_export(
    m4b_native_launcher, tmp_path
):
    collision = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    collision.bind(("127.0.0.1", 18080))
    collision.listen(1)
    status_r, status_w = os.pipe()
    sender, receiver = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
    )
    proc = None
    try:
        _record, prepared = _v3_request(
            status_fd=status_w,
            handoff_fd=sender.fileno(),
            cwd=tmp_path,
        )
        proc = _spawn_v3(
            m4b_native_launcher, prepared, status_w, sender.fileno()
        )
        os.close(status_w)
        status_w = -1
        sender.close()
        assert proc.stdin is not None
        proc.stdin.write(prepared.wire)
        proc.stdin.flush()
        assert _read_line_with_timeout(status_r, 2.0) == b"R:" + b"ab" * 16 + b"\n"
        proc.stdin.write(b"G")
        proc.stdin.close()
        proc.stdin = None
        status = _read_status_terminal(status_r)
        assert b"F:listener_bind:" in status
        assert proc.wait(timeout=5.0) == 2
    finally:
        collision.close()
        if status_w >= 0:
            os.close(status_w)
        os.close(status_r)
        sender.close()
        receiver.close()
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)


def test_listener_handoff_native_closed_receiver_fails_send_without_sanitation(
    m4b_native_launcher, tmp_path
):
    status_r, status_w = os.pipe()
    sender, receiver = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
    )
    proc = None
    try:
        _record, prepared = _v3_request(
            status_fd=status_w,
            handoff_fd=sender.fileno(),
            cwd=tmp_path,
        )
        proc = _spawn_v3(
            m4b_native_launcher, prepared, status_w, sender.fileno()
        )
        os.close(status_w)
        status_w = -1
        sender.close()
        assert proc.stdin is not None
        proc.stdin.write(prepared.wire)
        proc.stdin.flush()
        assert _read_line_with_timeout(status_r, 2.0) == b"R:" + b"ab" * 16 + b"\n"
        receiver.close()
        proc.stdin.write(b"G")
        proc.stdin.close()
        proc.stdin = None
        status = _read_status_terminal(status_r)
        assert b"F:handoff_sendmsg:" in status
        assert b"\nS\n" not in status
        assert proc.wait(timeout=5.0) == 2
    finally:
        if status_w >= 0:
            os.close(status_w)
        os.close(status_r)
        sender.close()
        receiver.close()
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)


def test_listener_handoff_native_rejects_wrong_g_without_export(
    m4b_native_launcher, tmp_path
):
    status_r, status_w = os.pipe()
    sender, receiver = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
    )
    proc = None
    try:
        _record, prepared = _v3_request(
            status_fd=status_w,
            handoff_fd=sender.fileno(),
            cwd=tmp_path,
        )
        proc = _spawn_v3(
            m4b_native_launcher, prepared, status_w, sender.fileno()
        )
        os.close(status_w)
        status_w = -1
        sender.close()
        assert proc.stdin is not None
        proc.stdin.write(prepared.wire)
        proc.stdin.flush()
        assert _read_line_with_timeout(status_r, 2.0) == b"R:" + b"ab" * 16 + b"\n"
        proc.stdin.write(b"Q")
        proc.stdin.close()
        proc.stdin = None
        status = _read_status_terminal(status_r)
        assert b"F:gate:" in status
        assert b"\nL:" not in status
        assert proc.wait(timeout=5.0) == 2
    finally:
        if status_w >= 0:
            os.close(status_w)
        os.close(status_r)
        sender.close()
        receiver.close()
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)


def test_listener_handoff_native_rejects_wrong_c_before_sanitation(
    m4b_native_launcher, tmp_path
):
    status_r, status_w = os.pipe()
    sender, receiver = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
    )
    proc = None
    adopted = None
    try:
        record, prepared = _v3_request(
            status_fd=status_w,
            handoff_fd=sender.fileno(),
            cwd=tmp_path,
        )
        proc = _spawn_v3(
            m4b_native_launcher, prepared, status_w, sender.fileno()
        )
        os.close(status_w)
        status_w = -1
        sender.close()
        assert proc.stdin is not None
        proc.stdin.write(prepared.wire)
        proc.stdin.flush()
        assert _read_line_with_timeout(status_r, 2.0) == b"R:" + b"ab" * 16 + b"\n"
        proc.stdin.write(b"G")
        proc.stdin.flush()
        adopted = recv_listener_fd(
            receiver,
            expected_task_id=record.task_id,
            expected_generation=record.task_generation,
            expected_nonce=record.launch_nonce,
            expected_policy_digest=record.network_policy_digest,
        )
        assert _read_line_with_timeout(status_r, 2.0).startswith(b"L:")
        proc.stdin.write(b"Q")
        proc.stdin.close()
        proc.stdin = None
        status = _read_status_terminal(status_r)
        assert b"F:listener_gate:" in status
        assert b"\nS\n" not in status
        assert proc.wait(timeout=5.0) == 2
    finally:
        if adopted is not None:
            os.close(adopted.fd)
        if status_w >= 0:
            os.close(status_w)
        os.close(status_r)
        sender.close()
        receiver.close()
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)


@pytest.mark.parametrize("protocol_version", [1, 2])
def test_protocol_v1_v2_native_order_and_listener_absence_remain_exact(
    m4b_native_launcher, protocol_version
):
    nonce = f"legacy-v{protocol_version}"
    if protocol_version == 1:
        prepared = launcher_module.prepare_launch_request(
            ["/usr/bin/true"], {}, "/tmp", [("/usr", "x"), ("/tmp", "w")],
            nonce=nonce,
        )
    else:
        tmp_status = os.stat("/tmp")
        usr_status = os.stat("/usr")
        prepared = launcher_module.prepare_launch_request(
            ["/usr/bin/true"],
            {},
            "/tmp",
            [],
            nonce=nonce,
            protocol_version=2,
            cwd_record=("/tmp", tmp_status.st_dev, tmp_status.st_ino),
            root_records=[
                ("/usr", usr_status.st_dev, usr_status.st_ino, "x"),
                ("/tmp", tmp_status.st_dev, tmp_status.st_ino, "w"),
            ],
            policy_digest_override="d" * 64,
        )
    status_r, status_w = os.pipe()
    proc = subprocess.Popen(
        [str(m4b_native_launcher)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"AOS_STATUS_FD": str(status_w)},
        pass_fds=(status_w,),
    )
    os.close(status_w)
    try:
        assert proc.stdin is not None
        proc.stdin.write(prepared.wire)
        proc.stdin.flush()
        ready = _read_line_with_timeout(status_r, 2.0)
        assert ready == f"R:{nonce}\n".encode("ascii")
        proc.stdin.write(b"G")
        proc.stdin.flush()
        status = _read_status_terminal(status_r)
        expected = [b"S", b"P", b"N"] if protocol_version == 1 else [b"S", b"I", b"P", b"N"]
        assert status.splitlines()[:-1] == expected
        assert status.splitlines()[-1].startswith(b"A:3:7fff:")
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        try:
            probe.bind(("127.0.0.1", 18080))
        finally:
            probe.close()
        proc.stdin.write(b"X")
        proc.stdin.close()
        proc.stdin = None
        assert proc.wait(timeout=5.0) == 0
    finally:
        os.close(status_r)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)


def test_status_channel_closes_on_exec_while_worker_is_alive(tmp_path):
    launcher = tmp_path / "fs_launcher"
    _compile_launcher(launcher)
    status_r, status_w = os.pipe()
    env = {"AOS_STATUS_FD": str(status_w)}
    request = build_launch_request(
        ["/usr/bin/sleep", "3"],
        {},
        "/tmp",
        [("/usr", "x"), ("/tmp", "w")],
        nonce="test-nonce",
    )
    proc = subprocess.Popen(
        [str(launcher)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        pass_fds=(status_w,),
    )
    os.close(status_w)
    try:
        assert proc.stdin is not None
        proc.stdin.write(request)
        proc.stdin.flush()
        assert _read_exact_with_timeout(status_r, 13, 2.0) == b"R:test-nonce\n"
        proc.stdin.write(b"G")
        proc.stdin.flush()
        progress = _read_exact_with_timeout(status_r, 80, 2.0)
        lines = progress.splitlines()
        assert lines[:3] == [b"S", b"P", b"N"]
        assert re.fullmatch(rb"A:3:7fff:[0-9a-f]{64}", lines[3])
        proc.stdin.write(b"X")
        proc.stdin.close()
        assert proc.poll() is None
        readable, _, _ = select.select([status_r], [], [], 0.5)
        assert readable, "status FD survived execve instead of producing EOF"
        assert os.read(status_r, 1) == b""
        assert proc.poll() is None
    finally:
        os.close(status_r)
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5.0)


def test_policy_root_object_swap_fails_closed_before_worker_exec(tmp_path):
    launcher = tmp_path / "fs_launcher"
    _compile_launcher(launcher)
    intended = tmp_path / "policy-root"
    replacement = tmp_path / "replacement"
    displaced = tmp_path / "displaced-intended"
    intended.mkdir()
    replacement.mkdir()
    marker = intended / "worker-ran"
    request = build_launch_request(
        ["/usr/bin/python3", "-c", "open('worker-ran', 'w').write('ran')"],
        {"PATH": "/usr/bin"},
        str(intended),
        [("/usr", "x"), (str(intended), "w")],
    )
    status_r, status_w = os.pipe()
    proc = subprocess.Popen(
        [str(launcher)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"AOS_STATUS_FD": str(status_w)},
        pass_fds=(status_w,),
    )
    os.close(status_w)
    try:
        assert proc.stdin is not None
        proc.stdin.write(request)
        proc.stdin.flush()
        assert _read_exact_with_timeout(status_r, 1, 2.0) == b"R"
        intended.rename(displaced)
        replacement.rename(intended)
        proc.stdin.write(b"G")
        proc.stdin.close()
        status = b""
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            readable, _, _ = select.select([status_r], [], [], 0.2)
            if not readable:
                continue
            chunk = os.read(status_r, 256)
            if not chunk:
                break
            status += chunk
        proc.wait(timeout=5.0)
        assert b"F:resolve_identity:" in status
        assert not marker.exists(), "worker executed against a swapped policy root"
    finally:
        os.close(status_r)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)


def test_duplicate_protocol_field_fails_before_worker_exec(tmp_path):
    launcher = tmp_path / "fs_launcher"
    _compile_launcher(launcher)
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    marker = workdir / "worker-ran"
    request = build_launch_request(
        ["/usr/bin/python3", "-c", "open('worker-ran', 'w').write('ran')"],
        {"PATH": "/usr/bin"},
        str(workdir),
        [("/usr", "x"), (str(workdir), "w")],
        nonce="original-nonce",
    )
    request = request.replace(
        b"min_abi 3\n", b"nonce 15 duplicate-nonce\nmin_abi 3\n", 1
    )
    status_r, status_w = os.pipe()
    proc = subprocess.Popen(
        [str(launcher)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"AOS_STATUS_FD": str(status_w)},
        pass_fds=(status_w,),
    )
    os.close(status_w)
    try:
        assert proc.stdin is not None
        proc.stdin.write(request)
        proc.stdin.flush()
        first = _read_exact_with_timeout(status_r, 1, 2.0)
        if first == b"R":
            proc.stdin.write(b"G")
        proc.stdin.close()
        status = first
        while True:
            readable, _, _ = select.select([status_r], [], [], 2.0)
            if not readable:
                break
            chunk = os.read(status_r, 256)
            if not chunk:
                break
            status += chunk
        proc.wait(timeout=5.0)
        assert b"F:parse:71\n" in status
        assert not marker.exists()
    finally:
        os.close(status_r)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)


def test_oversized_numeric_protocol_token_fails_closed(tmp_path):
    launcher = tmp_path / "fs_launcher"
    _compile_launcher(launcher)
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    marker = workdir / "worker-ran"
    request = build_launch_request(
        ["/usr/bin/python3", "-c", "open('worker-ran', 'w').write('ran')"],
        {"PATH": "/usr/bin"},
        str(workdir),
        [("/usr", "x"), (str(workdir), "w")],
    ).replace(
        b"min_abi 3\n",
        b"min_abi 999999999999999999999999999999999999999999\n",
        1,
    )
    status_r, status_w = os.pipe()
    proc = subprocess.Popen(
        [str(launcher)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"AOS_STATUS_FD": str(status_w)},
        pass_fds=(status_w,),
    )
    os.close(status_w)
    try:
        stdout, _stderr = proc.communicate(input=request, timeout=5.0)
        assert stdout == b""
        status = os.read(status_r, 256)
        assert b"F:parse:71\n" in status
        assert proc.returncode == 2
        assert not marker.exists()
    finally:
        os.close(status_r)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)


@pytest.mark.parametrize("iteration", range(5))
def test_openat2_concurrent_swap_opens_intended_inode_or_fails_closed(
    tmp_path, iteration
):
    launcher = tmp_path / "fs_launcher"
    _compile_launcher(launcher)
    case = tmp_path / f"case-{iteration}"
    case.mkdir()
    intended = case / "policy-root"
    replacement = case / "replacement"
    intended.mkdir()
    replacement.mkdir()
    (intended / "identity.txt").write_text("intended")
    (replacement / "identity.txt").write_text("replacement")
    request = build_launch_request(
        [
            "/usr/bin/python3",
            "-c",
            "print(open('identity.txt').read(), flush=True)",
        ],
        {"PATH": "/usr/bin"},
        str(intended),
        [("/usr", "x"), (str(intended), "w")],
    )
    status_r, status_w = os.pipe()
    proc = subprocess.Popen(
        [str(launcher)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"AOS_STATUS_FD": str(status_w)},
        pass_fds=(status_w,),
    )
    os.close(status_w)
    swapper = None
    try:
        assert proc.stdin is not None
        proc.stdin.write(request)
        proc.stdin.flush()
        first = _read_exact_with_timeout(status_r, 1, 2.0)
        assert first == b"R"
        swap_code = (
            "import os,sys\n"
            "a,b=sys.argv[1:3]\n"
            "tmp=a+'.swap'\n"
            "while True:\n"
            " try:\n"
            "  os.rename(a,tmp); os.rename(b,a); os.rename(tmp,b)\n"
            " except FileNotFoundError:\n"
            "  pass\n"
        )
        swapper = subprocess.Popen(
            [sys.executable, "-c", swap_code, str(intended), str(replacement)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        proc.stdin.write(b"G")
        proc.stdin.flush()
        status = first
        while True:
            readable, _, _ = select.select([status_r], [], [], 3.0)
            if not readable:
                break
            chunk = os.read(status_r, 256)
            if not chunk:
                break
            status += chunk
            if b"\nA:3:7fff:" in status:
                proc.stdin.write(b"X")
                proc.stdin.close()
                proc.stdin = None
                break
            if b"\nF:" in status:
                proc.stdin.close()
                proc.stdin = None
                break
        stdout, _stderr = proc.communicate(timeout=5.0)
        if b"A:3:7fff:" in status:
            assert stdout.strip() == b"intended"
        else:
            assert b"F:resolve:" in status or b"F:resolve_identity:" in status
            assert b"replacement" not in stdout
    finally:
        os.close(status_r)
        if swapper is not None and swapper.poll() is None:
            swapper.kill()
            swapper.wait(timeout=5.0)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5.0)
