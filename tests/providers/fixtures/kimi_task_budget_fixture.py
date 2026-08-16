#!/usr/bin/python3
"""Content-free native cgroup fixtures for the Kimi login task budget."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import pty
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Callable


REPOSITORY = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPOSITORY / "src"))

from agenticos.providers.kimi_login import (  # noqa: E402
    AUTH_HOST,
    KimiAuthRelay,
    KimiLoginError,
    KimiLoginSpec,
    QUALIFIED_LOGIN_TASKS_MAX,
    build_login_bwrap_argv,
    cleanup_login_runtime,
    open_validated_credential_root,
    provision_empty_credential_root,
    receive_listener_fd,
    terminate_and_drain_process,
    validate_credential_root,
    validate_login_task_budget,
)
from agenticos.sandbox.network_resolution import resolve_all_once  # noqa: E402


PINNED_KIMI = Path(
    "/home/brand/.local/share/agenticos/provider-qualification/"
    "kimi-code/0.36.1/runtime/bin/kimi"
)
CHGEN_PATH = REPOSITORY / "tests" / "conformance" / "chgen.py"
CHGEN_SPEC = importlib.util.spec_from_file_location("aos_task_budget_chgen", CHGEN_PATH)
assert CHGEN_SPEC is not None and CHGEN_SPEC.loader is not None
chgen = importlib.util.module_from_spec(CHGEN_SPEC)
CHGEN_SPEC.loader.exec_module(chgen)


def _cgroup_path() -> tuple[str, Path]:
    lines = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        raise RuntimeError("unexpected cgroup shape")
    relative = lines[0][3:]
    return relative, Path("/sys/fs/cgroup") / relative.lstrip("/")


def _counter(root: Path, name: str) -> int | str:
    value = (root / name).read_text(encoding="ascii").strip()
    return int(value) if value.isdecimal() else value


def _events_max(root: Path) -> int:
    fields = (root / "pids.events").read_text(encoding="ascii").split()
    if len(fields) != 2 or fields[0] != "max" or not fields[1].isdecimal():
        raise RuntimeError("unexpected pids.events shape")
    return int(fields[1])


def _snapshot(*, topology: bool = False) -> dict[str, object]:
    relative, root = _cgroup_path()
    result: dict[str, object] = {
        "pids_current": _counter(root, "pids.current"),
        "pids_max": _counter(root, "pids.max"),
        "pids_peak": _counter(root, "pids.peak"),
        "pids_events_max": _events_max(root),
    }
    if not topology:
        return result
    process_count = 0
    thread_count = 0
    components: dict[str, int] = {}
    for process_root in Path("/proc").iterdir():
        if not process_root.name.isdigit():
            continue
        try:
            membership = (process_root / "cgroup").read_text(
                encoding="ascii"
            ).splitlines()
            if membership != [f"0::{relative}"]:
                continue
            name = (process_root / "comm").read_text(encoding="utf-8").strip()
            threads = sum(1 for _ in (process_root / "task").iterdir())
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        process_count += 1
        thread_count += threads
        components[name] = components.get(name, 0) + threads
    result.update(
        process_count=process_count,
        thread_count=thread_count,
        threads_by_component=dict(sorted(components.items())),
    )
    return result


def _synthetic_getaddrinfo(
    *_args: object, **_kwargs: object
) -> list[tuple[object, ...]]:
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("93.184.216.34", 443),
        )
    ]


def _preflight() -> dict[str, object]:
    cgroup_text = Path("/proc/self/cgroup").read_text(encoding="ascii")
    try:
        validate_login_task_budget(cgroup_text)
    except KimiLoginError as exc:
        result = exc.code
    else:
        result = "PASSED"
    return {
        "schema": "AOS_KIMI_TASK_BUDGET_FIXTURE/1",
        "mode": "preflight",
        "result": result,
        "provider_launch_attempted": False,
        "external_network_attempted": False,
        "after_cleanup": _snapshot(),
    }


def _topology() -> dict[str, object]:
    evidence: dict[str, object] = {
        "schema": "AOS_KIMI_TASK_BUDGET_FIXTURE/1",
        "mode": "topology",
        "external_network_attempted": False,
        "qualified_tasks_max": QUALIFIED_LOGIN_TASKS_MAX,
        "expected_active_relay_connections": 1,
    }

    def synthetic_origin() -> socket.socket:
        evidence["before_resolver_worker"] = _snapshot(topology=True)
        try:
            outcome = resolve_all_once(
                AUTH_HOST,
                getaddrinfo_fn=_synthetic_getaddrinfo,
                deadline_seconds=1.0,
            )
        except RuntimeError as exc:
            evidence["resolver_worker_start"] = "FAILED"
            evidence["resolver_worker_error"] = str(exc)
            evidence["after_resolver_worker"] = _snapshot(topology=True)
            if str(exc) == "can't start new thread":
                raise KimiLoginError("TASK_BUDGET_EXHAUSTED") from exc
            raise
        evidence["resolver_worker_start"] = "SUCCEEDED"
        evidence["resolver_outcome"] = outcome.code.value
        evidence["after_resolver_worker"] = _snapshot(topology=True)
        raise KimiLoginError("SYNTHETIC_STOP_BEFORE_ORIGIN_CONNECT")

    with tempfile.TemporaryDirectory(prefix="aos-kimi-budget-") as temporary:
        state_root = Path(temporary) / "state"
        provision_empty_credential_root(state_root, expected_uid=os.getuid())
        spec = KimiLoginSpec(
            executable=PINNED_KIMI,
            bundle=REPOSITORY / "qualification" / "kimi-code" / "0.36.1",
            state_root=state_root,
            namespace_launcher=(
                REPOSITORY
                / "src"
                / "agenticos"
                / "providers"
                / "kimi_login_namespace.py"
            ),
        )
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        credential_fd = open_validated_credential_root(
            state_root, expected_uid=os.getuid()
        )
        master_fd, slave_fd = pty.openpty()
        process: subprocess.Popen[bytes] | None = None
        relay: KimiAuthRelay | None = None
        try:
            process = subprocess.Popen(
                build_login_bwrap_argv(
                    spec,
                    handoff_fd=child.fileno(),
                    credential_fd=credential_fd,
                ),
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                env={},
                close_fds=True,
                pass_fds=(child.fileno(), credential_fd),
                start_new_session=True,
            )
            os.close(credential_fd)
            credential_fd = -1
            os.close(slave_fd)
            slave_fd = -1
            child.close()
            parent.settimeout(10)
            listener = receive_listener_fd(parent)
            relay = KimiAuthRelay(listener, origin_socket_factory=synthetic_origin)
            relay.start()
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if relay.fatal_observation is not None or process.poll() is not None:
                    break
                time.sleep(0.05)
            observation = relay.fatal_observation
            evidence["relay_reason"] = (
                observation.reason_code if observation is not None else "NO_OBSERVATION"
            )
        finally:
            if credential_fd >= 0:
                os.close(credential_fd)
            if slave_fd >= 0:
                os.close(slave_fd)
            os.close(master_fd)
            child.close()
            parent.close()
            if process is not None and relay is not None:
                cleanup_login_runtime(relay, process)
            elif process is not None:
                terminate_and_drain_process(process)
        evidence["credential_state"] = validate_credential_root(
            state_root, expected_uid=os.getuid()
        ).value
    final = _snapshot()
    evidence["after_cleanup"] = final
    evidence["peak_tasks"] = final["pids_peak"]
    evidence["pids_events_max"] = final["pids_events_max"]
    before_resolver = evidence.get("before_resolver_worker")
    if isinstance(before_resolver, dict):
        evidence["process_peak"] = before_resolver["process_count"]
    if isinstance(evidence["peak_tasks"], int):
        evidence["headroom"] = QUALIFIED_LOGIN_TASKS_MAX - evidence["peak_tasks"]
    return evidence


def _tls_record(content_type: int, payload: bytes) -> bytes:
    return bytes([content_type, 3, 3]) + len(payload).to_bytes(2, "big") + payload


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
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return _tls_record(22, handshake)


def _recv_exact(stream: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise RuntimeError("synthetic peer closed early")
        data.extend(chunk)
    return bytes(data)


def _tls() -> dict[str, object]:
    evidence: dict[str, object] = {
        "schema": "AOS_KIMI_TASK_BUDGET_FIXTURE/1",
        "mode": "tls",
        "external_network_attempted": False,
    }
    origin_ready = threading.Event()
    origin_peer_box: list[socket.socket] = []

    def synthetic_origin() -> socket.socket:
        outcome = resolve_all_once(
            AUTH_HOST,
            getaddrinfo_fn=_synthetic_getaddrinfo,
            deadline_seconds=1.0,
        )
        evidence["resolver_outcome"] = outcome.code.value
        origin, peer = socket.socketpair()
        origin_peer_box.append(peer)
        origin_ready.set()
        return origin

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    relay = KimiAuthRelay(listener, origin_socket_factory=synthetic_origin)
    client: socket.socket | None = None
    origin_peer: socket.socket | None = None
    try:
        relay.start()
        client = socket.create_connection(listener.getsockname(), timeout=2)
        client.sendall(
            b"CONNECT auth.kimi.com:443 HTTP/1.1\r\n"
            b"Host: auth.kimi.com:443\r\n\r\n"
        )
        response = client.recv(128)
        if response != b"HTTP/1.1 200 Connection Established\r\n\r\n":
            raise RuntimeError("synthetic CONNECT was not admitted")
        hello = chgen.make_client_hello(b"auth.kimi.com", tls13=True)
        client.sendall(hello)
        if not origin_ready.wait(timeout=3):
            raise RuntimeError("synthetic origin was not created")
        origin_peer = origin_peer_box[0]
        if _recv_exact(origin_peer, len(hello)) != hello:
            raise RuntimeError("ClientHello was not relayed exactly")
        server_hello = _server_hello()
        origin_peer.sendall(server_hello)
        if _recv_exact(client, len(server_hello)) != server_hello:
            raise RuntimeError("ServerHello was not relayed exactly")
        request = _tls_record(23, b"synthetic-opaque-request")
        response_record = _tls_record(23, b"synthetic-opaque-response")
        client.sendall(request)
        if _recv_exact(origin_peer, len(request)) != request:
            raise RuntimeError("opaque client record changed")
        origin_peer.sendall(response_record)
        if _recv_exact(client, len(response_record)) != response_record:
            raise RuntimeError("opaque origin record changed")
        client.shutdown(socket.SHUT_WR)
        origin_peer.shutdown(socket.SHUT_WR)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not relay.observations:
            time.sleep(0.01)
        if len(relay.observations) != 1:
            raise RuntimeError("synthetic relay did not finish")
        observation = relay.observations[0]
        evidence["relay_result"] = observation.result.value
        evidence["hostname"] = observation.hostname
    finally:
        if client is not None:
            client.close()
        if origin_peer is not None:
            origin_peer.close()
        relay.stop()
    final = _snapshot()
    evidence["after_cleanup"] = final
    evidence["peak_tasks"] = final["pids_peak"]
    evidence["pids_events_max"] = final["pids_events_max"]
    return evidence


def _explosion() -> dict[str, object]:
    release = threading.Event()
    threads: list[threading.Thread] = []
    denied = False
    error = ""
    try:
        while True:
            worker = threading.Thread(target=release.wait, daemon=True)
            try:
                worker.start()
            except RuntimeError as exc:
                denied = True
                error = str(exc)
                break
            threads.append(worker)
    finally:
        at_denial = _snapshot()
        release.set()
        for worker in threads:
            worker.join(timeout=2)
    final = _snapshot()
    return {
        "schema": "AOS_KIMI_TASK_BUDGET_FIXTURE/1",
        "mode": "explosion",
        "external_network_attempted": False,
        "task_creation_denied": denied,
        "task_start_error": error,
        "peak_tasks": final["pids_peak"],
        "pids_events_max": final["pids_events_max"],
        "at_denial": at_denial,
        "after_cleanup": final,
    }


MODES: dict[str, Callable[[], dict[str, object]]] = {
    "preflight": _preflight,
    "topology": _topology,
    "tls": _tls,
    "explosion": _explosion,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=tuple(MODES), required=True)
    arguments = parser.parse_args()
    report = MODES[arguments.mode]()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
