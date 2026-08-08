"""Unit-level contracts for the Milestone 3B native Landlock boundary."""

from __future__ import annotations

import os
import re
import select
import subprocess
import sys
import time
from pathlib import Path

import agenticos.sandbox.launcher as launcher_module
import pytest
from agenticos.sandbox.launcher import (
    DEFAULT_LAUNCHER_PATH,
    build_launch_request,
    parse_launcher_status,
    sanitize_env,
)
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
