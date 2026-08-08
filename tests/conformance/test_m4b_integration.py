"""Real-host integration proof for M4B listener capability transport."""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys

import pytest

from agenticos.sandbox.network_identity import (
    recv_listener_fd,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
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
