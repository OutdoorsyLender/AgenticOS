#!/usr/bin/python3
"""Full local-only Kimi post-auth device-flow qualification fixture."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


REPOSITORY = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPOSITORY / "src"))

from agenticos.providers.kimi_login import (  # noqa: E402
    AuthRelayResult,
    KimiAuthRelay,
    KimiLoginSpec,
    PrimaryLoginResult,
    build_login_bwrap_argv,
    cleanup_login_runtime,
    finalize_login_outcome,
    open_validated_credential_root,
    provision_empty_credential_root,
    receive_listener_fd,
    validate_credential_root,
)


PINNED_KIMI = Path(
    "/home/brand/.local/share/agenticos/provider-qualification/"
    "kimi-code/0.36.1/runtime/bin/kimi"
)
NAMESPACE_FIXTURE = Path(__file__).with_name("kimi_post_auth_namespace_fixture.py")


def _cgroup_tasks() -> int:
    line = Path("/proc/self/cgroup").read_text(encoding="ascii").strip()
    if not line.startswith("0::/"):
        raise RuntimeError("unexpected cgroup shape")
    root = Path("/sys/fs/cgroup") / line[3:].lstrip("/")
    return int((root / "pids.current").read_text(encoding="ascii").strip())


def _tls_record(content_type: int, payload: bytes) -> bytes:
    return bytes((content_type, 3, 3)) + len(payload).to_bytes(2, "big") + payload


def _server_hello() -> bytes:
    extensions = b"\x00\x2b\x00\x02\x03\x04"
    body = (
        b"\x03\x03"
        + b"S" * 32
        + b"\x00"
        + b"\x13\x01"
        + b"\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    return _tls_record(22, b"\x02" + len(body).to_bytes(3, "big") + body)


def _recv_exact(stream: socket.socket, size: int) -> bytes:
    received = bytearray()
    while len(received) < size:
        chunk = stream.recv(size - len(received))
        if not chunk:
            raise RuntimeError("synthetic peer closed early")
        received.extend(chunk)
    return bytes(received)


def _recv_record(stream: socket.socket) -> bytes:
    head = _recv_exact(stream, 5)
    return head + _recv_exact(stream, int.from_bytes(head[3:5], "big"))


def main() -> int:
    report: dict[str, object] = {
        "schema": "AOS_KIMI_POST_AUTH_FIXTURE/1",
        "external_network_attempted": False,
        "real_credential_root_referenced": False,
        "device_authorization": "INCOMPLETE",
        "pending_poll_count": 0,
        "owner_approval_transition": "INCOMPLETE",
        "synthetic_token_response": "INCOMPLETE",
        "synthetic_atomic_credential_write": "INCOMPLETE",
    }
    with tempfile.TemporaryDirectory(prefix="aos-kimi-post-auth-") as temporary:
        state_root = Path(temporary) / "state"
        provision_empty_credential_root(state_root, expected_uid=os.getuid())
        spec = KimiLoginSpec(
            PINNED_KIMI,
            REPOSITORY / "qualification" / "kimi-code" / "0.36.1",
            state_root,
            NAMESPACE_FIXTURE,
        )
        parent, child = socket.socketpair()
        credential_fd = open_validated_credential_root(
            state_root, expected_uid=os.getuid()
        )
        process = subprocess.Popen(
            build_login_bwrap_argv(
                spec, handoff_fd=child.fileno(), credential_fd=credential_fd
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={},
            close_fds=True,
            pass_fds=(child.fileno(), credential_fd),
            start_new_session=True,
        )
        os.close(credential_fd)
        child.close()
        parent.settimeout(5)
        listener = receive_listener_fd(parent)
        parent.close()
        origin_peer_box: list[socket.socket] = []

        def synthetic_origin() -> socket.socket:
            origin, peer = socket.socketpair()
            origin_peer_box.append(peer)
            return origin

        relay = KimiAuthRelay(listener, origin_socket_factory=synthetic_origin)
        relay.start()
        deadline = time.monotonic() + 5
        while not origin_peer_box and time.monotonic() < deadline:
            time.sleep(0.01)
        if not origin_peer_box:
            raise RuntimeError("synthetic origin was not opened")
        origin_peer = origin_peer_box[0]
        origin_peer.settimeout(5)
        _recv_record(origin_peer)
        origin_peer.sendall(_server_hello())

        requests = (
            ("device", b"synthetic-device-response"),
            ("pending", b"synthetic-authorization-pending"),
            ("pending", b"synthetic-authorization-pending"),
            ("complete", b"synthetic-token-response"),
        )
        for phase, payload in requests:
            if _recv_record(origin_peer)[0] != 23:
                raise RuntimeError("unexpected synthetic TLS record")
            if phase == "device":
                report["device_authorization"] = "COMPLETED"
            elif phase == "pending":
                report["pending_poll_count"] = int(report["pending_poll_count"]) + 1
            else:
                report["owner_approval_transition"] = "COMPLETED"
                report["synthetic_token_response"] = "COMPLETED"
            origin_peer.sendall(_tls_record(23, payload))
        origin_peer.shutdown(socket.SHUT_WR)
        while origin_peer.recv(4096):
            pass
        origin_peer.close()
        process.wait(timeout=5)
        cleanup = cleanup_login_runtime(relay, process)
        credential_state = validate_credential_root(
            state_root, expected_uid=os.getuid()
        )
        outcome = finalize_login_outcome(
            primary_login_result=(
                PrimaryLoginResult.COMPLETED
                if process.returncode == 0
                else PrimaryLoginResult.LOGIN_COMMAND_FAILED
            ),
            primary_reason_code=(
                "COMPLETED" if process.returncode == 0 else "LOGIN_COMMAND_FAILED"
            ),
            observations=tuple(relay.observations),
            cleanup=cleanup,
            credential_structure_result=credential_state,
        )
        report.update(
            process_returncode=process.returncode,
            primary_login_result=outcome.primary_login_result.value,
            relay_result=outcome.relay_result.value,
            cleanup_result=outcome.cleanup_result.value,
            credential_state=credential_state.value,
            relay_active_connections=relay.active_connection_count,
            top_level_error=outcome.top_level_error,
            synthetic_atomic_credential_write=(
                "COMPLETED" if credential_state.value == "PRESENT" else "INCOMPLETE"
            ),
            after_cleanup_tasks=_cgroup_tasks(),
        )
        if len(relay.observations) != 1:
            raise RuntimeError("unexpected relay observation count")
        if relay.observations[0].result is not AuthRelayResult.COMPLETED:
            raise RuntimeError("synthetic relay did not complete")
    print(json.dumps(report, sort_keys=True, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
