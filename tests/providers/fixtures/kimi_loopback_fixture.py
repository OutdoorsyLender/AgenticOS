"""Credential-free same-namespace ACP/OpenAI fixture for Kimi 0.36.1.

Runs only inside the network-denied qualification Bubblewrap domain.  The
synthetic OAuth canary is deliberately never emitted in the report.
"""

from __future__ import annotations

import http.server
import hashlib
import json
import os
import pathlib
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Any


SCENARIOS = {"plan", "tool-attempt", "cancel", "malformed-stream", "process-crash"}
CANARY = "AOS_SYNTHETIC_OAUTH_CANARY_F1_36_1_DO_NOT_PUBLISH"
REFRESH_CANARY = "AOS_SYNTHETIC_REFRESH_CANARY_F1_36_1_DO_NOT_PUBLISH"
CREDENTIAL_CANARIES = (CANARY, REFRESH_CANARY)
KIMI_HOME = pathlib.Path("/home/aos/kimi")
KIMI = "/opt/agenticos/kimi/bin/kimi"
WORKSPACE = pathlib.Path("/workspace")
PLAN = {
    "schema": "AOSPLAN/1",
    "tasks": [
        {
            "local_id": "local-1",
            "title": "Bounded build",
            "description": "Implement only the controller-selected change.",
            "task_type": "BUILD",
            "dependencies": [],
            "acceptance_criteria": ["Provider suggestion only."],
            "preferred_role": "BUILDER",
            "priority": 50,
        }
    ],
}
FORBIDDEN_TOOL_ATTEMPTS = (
    "Bash",
    "CommandExecution",
    "ReadFile",
    "WriteFile",
    "Glob",
    "ListDirectory",
    "ReadBinary",
    "Subagent",
    "MCP",
    "Plugin",
    "Skill",
    "Hook",
    "BackgroundTask",
)


def fail(code: str, detail: str = "") -> None:
    leak = any(canary in detail for canary in CREDENTIAL_CANARIES)
    for canary in CREDENTIAL_CANARIES:
        detail = detail.replace(canary, "<synthetic-credential-canary-redacted>")
    report = {
        "schema": "AOS_KIMI_FIXTURE/1",
        "ok": False,
        "error": "CREDENTIAL_CANARY_LEAK" if leak else code,
        "detail": detail[:20_000],
    }
    sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    raise SystemExit(2)


def write_synthetic_home(port: int) -> None:
    (KIMI_HOME / "credentials").mkdir(parents=True, mode=0o700, exist_ok=True)
    base_url = f"http://127.0.0.1:{port}/v1"
    scope_input = json.dumps(
        {"oauthHost": "https://auth.kimi.com", "baseUrl": base_url},
        separators=(",", ":"),
    )
    scope_digest = hashlib.sha256(scope_input.encode()).hexdigest()[:16]
    oauth_storage_name = f"kimi-code-env-{scope_digest}"
    oauth_key = f"oauth/{oauth_storage_name}"
    config = f'''default_model = "kimi-code/kimi-for-coding"
default_permission_mode = "manual"
default_plan_mode = true
merge_all_available_skills = false
builtin_product_skills = false
telemetry = false

[background]
max_running_tasks = 1
keep_alive_on_exit = false

[tools]
enabled = ["AgenticOSPlannerNoToolSentinel"]

[providers."managed:kimi-code"]
type = "kimi"
base_url = "{base_url}"
api_key = ""

[providers."managed:kimi-code".oauth]
storage = "file"
key = "{oauth_key}"

[models."kimi-code/kimi-for-coding"]
provider = "managed:kimi-code"
model = "kimi-for-coding"
max_context_size = 262144
capabilities = ["thinking", "always_thinking"]
'''
    (KIMI_HOME / "config.toml").write_text(config, encoding="utf-8")
    token = {
        "access_token": CANARY,
        "refresh_token": REFRESH_CANARY,
        "expires_at": 4102444800,
        "scope": "synthetic-local-qualification",
        "token_type": "Bearer",
        "expires_in": 3600,
    }
    credential = KIMI_HOME / "credentials" / f"{oauth_storage_name}.json"
    credential.write_text(json.dumps(token, separators=(",", ":")) + "\n", encoding="utf-8")
    credential.chmod(0o600)


class Capture:
    def __init__(self, scenario: str) -> None:
        self.scenario = scenario
        self.requests: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.cancel_request_started = threading.Event()
        self.release_cancel_response = threading.Event()
        self.crash_request_started = threading.Event()
        self.release_crash_response = threading.Event()


def make_handler(capture: Capture) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "AgenticOSLoopback/1"

        def log_message(self, format: str, *args: object) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("content-length", "0"))
            if length > 1_048_576:
                self.send_error(413)
                return
            body = self.rfile.read(length)
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = None
            record = {
                "path": self.path,
                "header_names": sorted(name.lower() for name in self.headers),
                "auth_ok": self.headers.get("authorization") == f"Bearer {CANARY}",
                "body": parsed,
                "body_text": body.decode("utf-8", "replace"),
            }
            with capture.lock:
                capture.requests.append(record)
                index = len(capture.requests)
            self.send_response(200)
            self.send_header("content-type", "text/event-stream; charset=utf-8")
            self.send_header("cache-control", "no-cache")
            self.end_headers()
            if capture.scenario == "cancel":
                capture.cancel_request_started.set()
                capture.release_cancel_response.wait(15)
                return
            if capture.scenario == "process-crash":
                capture.crash_request_started.set()
                capture.release_crash_response.wait(15)
                return
            if capture.scenario == "malformed-stream":
                self.wfile.write(b"data: {malformed-json\n\ndata: [DONE]\n\n")
                self.wfile.flush()
                return
            if capture.scenario == "tool-attempt" and index == 1:
                tool_calls = []
                for tool_index, name in enumerate(FORBIDDEN_TOOL_ATTEMPTS):
                    arguments_by_name = {
                        "Bash": {"command": "touch /tmp/aos-shell-marker"},
                        "ReadFile": {"path": "/tmp/aos-fs-read-canary"},
                        "WriteFile": {"path": "/tmp/aos-fs-write-marker", "content": "forbidden"},
                        "Glob": {"pattern": "/tmp/*"},
                        "ListDirectory": {"path": "/tmp"},
                        "ReadBinary": {"path": "/tmp/aos-fs-read-canary"},
                    }
                    arguments = arguments_by_name.get(name, {"authority": name})
                    tool_calls.append(
                        {
                            "index": tool_index,
                            "id": f"call_{tool_index}",
                            "function": {
                                "name": name,
                                "arguments": json.dumps(arguments, separators=(",", ":")),
                            },
                        }
                    )
                chunks = [
                    {
                        "id": "chatcmpl-tool-attempt",
                        "object": "chat.completion.chunk",
                        "created": 1,
                        "model": "kimi-for-coding",
                        "choices": [{
                            "index": 0,
                            "delta": {"tool_calls": tool_calls},
                            "finish_reason": None,
                        }],
                    },
                    {
                        "id": "chatcmpl-tool-attempt",
                        "object": "chat.completion.chunk",
                        "created": 1,
                        "model": "kimi-for-coding",
                        "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
                    },
                ]
            else:
                text = json.dumps(PLAN, separators=(",", ":"))
                chunks = [
                    {
                        "id": "chatcmpl-plan",
                        "object": "chat.completion.chunk",
                        "created": 1,
                        "model": "kimi-for-coding",
                        "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}],
                    },
                    {
                        "id": "chatcmpl-plan",
                        "object": "chat.completion.chunk",
                        "created": 1,
                        "model": "kimi-for-coding",
                        "choices": [{
                            "index": 0,
                            "delta": {},
                            "finish_reason": "stop",
                            "usage": {"prompt_tokens": 20, "completion_tokens": 20, "total_tokens": 40, "cached_tokens": 0},
                        }],
                    },
                ]
            for chunk in chunks:
                self.wfile.write(("data: " + json.dumps(chunk, separators=(",", ":")) + "\n\n").encode())
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()

    return Handler


def send(proc: subprocess.Popen[bytes], method: str, params: dict[str, Any], request_id: int | None = None) -> None:
    message: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params}
    if request_id is not None:
        message["id"] = request_id
    assert proc.stdin is not None
    proc.stdin.write((json.dumps(message, separators=(",", ":")) + "\n").encode())
    proc.stdin.flush()


def read_until(proc: subprocess.Popen[bytes], request_id: int, transcript: list[dict[str, Any]], timeout: float = 20.0) -> dict[str, Any]:
    assert proc.stdout is not None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], min(0.25, deadline - time.monotonic()))
        if not ready:
            if proc.poll() is not None:
                fail("ACP_PROCESS_EXITED", str(proc.returncode))
            continue
        line = proc.stdout.readline()
        if not line:
            fail("ACP_STDOUT_CLOSED")
        if len(line) > 65_536:
            fail("ACP_FRAME_TOO_LARGE")
        try:
            message = json.loads(line)
        except Exception as exc:
            fail("ACP_MALFORMED_JSON", str(exc))
        transcript.append(message)
        if message.get("id") == request_id and ("result" in message or "error" in message):
            return message
        if "method" in message and "id" in message:
            fail("UNEXPECTED_REVERSE_CALLBACK", str(message.get("method")))
    fail("ACP_TIMEOUT", str(request_id))
    raise AssertionError


def descendants(pid: int) -> list[int]:
    found: list[int] = []
    pending = [pid]
    while pending:
        current = pending.pop()
        path = pathlib.Path(f"/proc/{current}/task/{current}/children")
        try:
            children = [int(value) for value in path.read_text().split()]
        except OSError:
            children = []
        found.extend(children)
        pending.extend(children)
    return found


def proc_observation(proc: subprocess.Popen[bytes]) -> dict[str, Any]:
    pids = descendants(os.getpid())
    kimi_pids: list[int] = []
    other_children: list[dict[str, Any]] = []
    target_pid = proc.pid
    target_argv: list[str] = []
    for pid in pids:
        try:
            argv = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        rendered = [pathlib.Path(part.decode("utf-8", "replace")).name if index == 0 else part.decode("utf-8", "replace") for index, part in enumerate(argv) if part]
        if pid == target_pid or (rendered and rendered[0] == "kimi"):
            kimi_pids.append(pid)
            if pid == target_pid:
                target_argv = rendered
        elif pid != os.getpid():
            other_children.append({"pid": pid, "argv": rendered})
    try:
        env_names = sorted(
            item.split(b"=", 1)[0].decode("ascii")
            for item in pathlib.Path(f"/proc/{target_pid}/environ").read_bytes().split(b"\0")
            if item
        )
    except OSError:
        env_names = []
    fd_classes: list[str] = []
    for number in (0, 1, 2):
        try:
            target = os.readlink(f"/proc/{target_pid}/fd/{number}")
        except OSError:
            target = "missing"
        fd_classes.append("pipe" if target.startswith("pipe:") else target.split(":", 1)[0])
    open_fds: dict[str, str] = {}
    host_authority_fd_seen = False
    try:
        fd_paths = sorted(
            pathlib.Path(f"/proc/{target_pid}/fd").iterdir(),
            key=lambda item: int(item.name),
        )
    except OSError:
        fd_paths = []
    for fd_path in fd_paths:
        try:
            target = os.readlink(fd_path)
        except OSError:
            continue
        if target.startswith("pipe:"):
            kind = "pipe"
        elif target.startswith("socket:"):
            kind = "socket"
        elif target.startswith("anon_inode:"):
            kind = "anon_inode"
        elif target.startswith("/home/aos/kimi/"):
            kind = "kimi_state"
        elif target.startswith("/opt/agenticos/kimi/"):
            kind = "pinned_runtime"
        elif target == "/dev/null":
            kind = "dev_null"
        else:
            kind = "other"
        open_fds[fd_path.name] = kind
        host_authority_fd_seen = host_authority_fd_seen or any(
            fragment in target
            for fragment in ("/mnt/c/", "/home/brand/src/", "/controller", "/.git/")
        )
    try:
        executable = os.readlink(f"/proc/{target_pid}/exe")
    except OSError:
        executable = "missing"
    namespace_ids: dict[str, str] = {}
    for name in ("user", "pid", "mnt", "net", "ipc", "uts", "cgroup"):
        try:
            namespace_ids[name] = os.readlink(f"/proc/{target_pid}/ns/{name}")
        except OSError:
            namespace_ids[name] = "missing"
    try:
        cgroup = pathlib.Path(f"/proc/{target_pid}/cgroup").read_text().splitlines()
    except OSError:
        cgroup = []
    return {
        "all_descendants": pids,
        "kimi_pids": kimi_pids,
        "other_children": other_children,
        "env_names": env_names,
        "fd_classes": fd_classes,
        "open_fd_classes": open_fds,
        "host_authority_fd_seen": host_authority_fd_seen,
        "target_argv": target_argv,
        "target_executable": executable,
        "namespace_ids": namespace_ids,
        "net_namespace": namespace_ids["net"],
        "pid_namespace": namespace_ids["pid"],
        "cgroup": cgroup,
        "process_group": _safe_process_group(target_pid),
    }


def _safe_process_group(pid: int) -> int | str:
    try:
        return os.getpgid(pid)
    except OSError:
        return "missing"


class ProcessMonitor:
    """Continuously union process/FD observations across the hostile window."""

    def __init__(self, proc: subprocess.Popen[bytes]) -> None:
        self.proc = proc
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.samples = 0
        self.max_descendants = 0
        self.other_children: dict[int, dict[str, Any]] = {}
        self.fd_classes: set[str] = set()
        self.host_authority_fd_seen = False
        self.socket_endpoints: dict[str, dict[str, str]] = {}
        self.non_loopback_socket_seen = False
        self.error: str | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        while not self.stop_event.is_set() and self.proc.poll() is None:
            try:
                sample = proc_observation(self.proc)
                sockets = socket_census()
            except Exception as exc:
                with self.lock:
                    self.error = type(exc).__name__
                self.stop_event.set()
                return
            with self.lock:
                self.samples += 1
                self.max_descendants = max(self.max_descendants, len(sample["all_descendants"]))
                for item in sample["other_children"]:
                    self.other_children[item["pid"]] = item
                self.fd_classes.update(sample["open_fd_classes"].values())
                self.host_authority_fd_seen = (
                    self.host_authority_fd_seen or sample["host_authority_fd_seen"]
                )
                for endpoint in sockets["endpoints"]:
                    self.socket_endpoints[json.dumps(endpoint, sort_keys=True)] = endpoint
                self.non_loopback_socket_seen = (
                    self.non_loopback_socket_seen or sockets["non_loopback"]
                )
            self.stop_event.wait(0.002)

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2)

    def sample_count(self) -> int:
        with self.lock:
            return self.samples

    def wait_for_sample_after(self, count: int, timeout: float = 1.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                if self.error is not None:
                    return False
                if self.samples > count:
                    return True
            time.sleep(0.001)
        return False

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "samples": self.samples,
                "max_descendants": self.max_descendants,
                "other_children": list(self.other_children.values()),
                "fd_classes": sorted(self.fd_classes),
                "host_authority_fd_seen": self.host_authority_fd_seen,
                "socket_endpoints": list(self.socket_endpoints.values()),
                "non_loopback_socket_seen": self.non_loopback_socket_seen,
                "monitor_error": self.error,
                "monitor_stopped": not self.thread.is_alive(),
            }


def _decode_proc_address(encoded: str, *, ipv6: bool) -> str:
    if ipv6:
        raw = bytes.fromhex(encoded)
        raw = b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4))
        return socket.inet_ntop(socket.AF_INET6, raw)
    return socket.inet_ntoa(struct.pack("<I", int(encoded, 16)))


def socket_census() -> dict[str, Any]:
    endpoints: list[dict[str, str]] = []
    non_loopback = False
    for relative, ipv6 in (
        ("tcp", False), ("tcp6", True), ("udp", False), ("udp6", True)
    ):
        try:
            lines = pathlib.Path("/proc/net", relative).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 4:
                continue
            local_hex, local_port = fields[1].split(":")
            remote_hex, remote_port = fields[2].split(":")
            local = _decode_proc_address(local_hex, ipv6=ipv6)
            remote = _decode_proc_address(remote_hex, ipv6=ipv6)
            endpoints.append(
                {
                    "family": relative,
                    "local_class": "loopback" if socket.inet_pton(socket.AF_INET6 if ipv6 else socket.AF_INET, local) and (local == "::1" or local.startswith("127.")) else "unspecified" if local in {"0.0.0.0", "::"} else "non_loopback",
                    "local_port": str(int(local_port, 16)),
                    "remote_class": "loopback" if remote == "::1" or remote.startswith("127.") else "unspecified" if remote in {"0.0.0.0", "::"} else "non_loopback",
                    "remote_port": str(int(remote_port, 16)),
                    "state": fields[3],
                }
            )
            non_loopback = non_loopback or any(
                address not in {"0.0.0.0", "::"}
                and not address.startswith("127.")
                and address != "::1"
                for address in (local, remote)
            )
    return {"endpoints": endpoints, "non_loopback": non_loopback}


def classify_state() -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(KIMI_HOME.rglob("*")):
        if not path.is_file():
            continue
        relative = str(path.relative_to(KIMI_HOME))
        if relative == "config.toml" or relative == "agents/agent.md":
            kind = "IMMUTABLE_RUNTIME"
        elif relative.startswith("credentials/kimi-code-env-") and relative.endswith(".json"):
            kind = "FUTURE_CREDENTIAL_STATE"
        elif "cache" in relative.lower():
            kind = "CACHE"
        elif "log" in relative.lower():
            kind = "LOG"
        elif relative in {"migrations-effort.json", "session_index.jsonl", "workspaces.json"}:
            kind = "MUTABLE_NONSECRET_STATE"
        elif relative.startswith("sessions/") and relative.endswith(("/wire.jsonl", "/state.json")):
            kind = "MUTABLE_NONSECRET_STATE"
        else:
            kind = "UNKNOWN"
        result[relative] = kind
    return result


def canary_outside_credential(transcript: list[dict[str, Any]], stderr: bytes, capture: Capture) -> bool:
    values = [json.dumps(transcript, sort_keys=True), stderr.decode("utf-8", "replace")]
    with capture.lock:
        values.extend(str(item.get("body_text", "")) for item in capture.requests)
    for path in KIMI_HOME.rglob("*"):
        if not path.is_file() or (path.parent == KIMI_HOME / "credentials" and path.name.startswith("kimi-code-env-")):
            continue
        try:
            values.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
    return any(canary in value for canary in CREDENTIAL_CANARIES for value in values)


def main() -> None:
    scenario = sys.argv[1] if len(sys.argv) == 2 else ""
    if scenario not in SCENARIOS:
        fail("BAD_SCENARIO")
    capture = Capture(scenario)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(capture))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    write_synthetic_home(server.server_address[1])
    fd_canary_path = pathlib.Path("/tmp/aos-controller-secret-fd-canary")
    fd_canary_path.write_text("AOS_SYNTHETIC_SECRET_FD_CANARY", encoding="utf-8")
    fd_canary = fd_canary_path.open("rb")
    try:
        proc = subprocess.Popen(
            [KIMI, "acp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(os.environ),
            close_fds=True,
            pass_fds=(),
            start_new_session=True,
        )
    finally:
        fd_canary.close()
    pathlib.Path("/tmp/aos-fs-read-canary").write_text(
        "AOS_SYNTHETIC_FILESYSTEM_READ_CANARY", encoding="utf-8"
    )
    monitor = ProcessMonitor(proc)
    monitor.start()
    monitor_before_prompt = 0
    monitor_after_hostile = 0
    transcript: list[dict[str, Any]] = []
    stderr = b""
    try:
        send(proc, "initialize", {"protocolVersion": 1, "clientCapabilities": {}}, 1)
        initialized = read_until(proc, 1, transcript)
        if "error" in initialized:
            fail("INITIALIZE_ERROR", str(initialized["error"]))
        result = initialized["result"]
        # The pinned ACP host initializes provider/OAuth catalogs
        # asynchronously after initialize. Its own lifecycle tests poll this
        # readiness gate before session/new; a bounded wait avoids racing it.
        time.sleep(1.5)
        send(proc, "session/new", {"cwd": "/workspace", "mcpServers": []}, 2)
        created = read_until(proc, 2, transcript)
        if "error" in created:
            fail("NEW_SESSION_ERROR", str(created["error"]).replace(CANARY, "<redacted>"))
        session_id = created["result"]["sessionId"]
        process = proc_observation(proc)
        bounded = json.dumps({
            "owner_goal": "Plan one bounded controller-selected change.",
            "research_evidence": ["Synthetic fixture only."],
            "manifest": [{"item_id": "context-1", "digest": "d" * 64, "byte_size": 12}],
            "acceptance": ["Return one AOSPLAN/1 proposal."],
        }, separators=(",", ":"))
        monitor_before_prompt = monitor.sample_count()
        send(proc, "session/prompt", {"sessionId": session_id, "prompt": [{"type": "text", "text": bounded}]}, 3)
        if scenario == "cancel":
            if not capture.cancel_request_started.wait(5):
                fail("CANCEL_REQUEST_NOT_STARTED")
            if not monitor.wait_for_sample_after(monitor_before_prompt):
                fail("MONITOR_HOSTILE_WINDOW_GAP")
            send(proc, "session/cancel", {"sessionId": session_id})
        if scenario == "process-crash":
            if not capture.crash_request_started.wait(5):
                fail("CRASH_REQUEST_NOT_STARTED")
            if not monitor.wait_for_sample_after(monitor_before_prompt):
                fail("MONITOR_HOSTILE_WINDOW_GAP")
            proc.kill()
            proc.wait(timeout=5)
            capture.release_crash_response.set()
            prompted = {"error": {"code": "SYNTHETIC_PROCESS_CRASH"}}
        else:
            prompted = read_until(
                proc,
                3,
                transcript,
                timeout={"cancel": 10, "malformed-stream": 5}.get(scenario, 20),
            )
        if scenario == "cancel":
            capture.release_cancel_response.set()
        monitor_after_hostile = monitor.sample_count()
        if monitor_after_hostile <= monitor_before_prompt:
            fail("MONITOR_HOSTILE_WINDOW_GAP")
        if scenario == "plan" and "error" in prompted:
            fail("PROMPT_ERROR", str(prompted["error"]))
        if scenario == "tool-attempt" and len(capture.requests) == 1:
            # A profile with no registered tools may reject the malicious tool
            # before a second model call.  Either failure or a bounded retry is
            # acceptable; execution is never acceptable.
            pass
        time.sleep(0.2)
    finally:
        capture.release_cancel_response.set()
        capture.release_crash_response.set()
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait(timeout=5)
        if proc.stderr is not None:
            stderr = proc.stderr.read(262_145)
        monitor.stop()
        server.shutdown(); server.server_close(); thread.join(timeout=2)

    with capture.lock:
        requests = list(capture.requests)
    first_body = requests[0]["body"] if requests and isinstance(requests[0]["body"], dict) else {}
    messages = first_body.get("messages", []) if isinstance(first_body, dict) else []
    system_text = "\n".join(str(item.get("content", "")) for item in messages if isinstance(item, dict) and item.get("role") == "system")
    provider_tools = first_body.get("tools", []) if isinstance(first_body, dict) else []
    update_kinds = [
        message.get("params", {}).get("update", {}).get("sessionUpdate")
        for message in transcript
        if message.get("method") == "session/update"
    ]
    message_text = "".join(
        str(message.get("params", {}).get("update", {}).get("content", {}).get("text", ""))
        for message in transcript
        if message.get("method") == "session/update"
        and message.get("params", {}).get("update", {}).get("sessionUpdate") == "agent_message_chunk"
    )
    plan_schema = None
    try:
        plan_schema = json.loads(message_text).get("schema")
    except Exception:
        pass
    default_route = any(
        line.split()[1] == "00000000"
        for line in pathlib.Path("/proc/net/route").read_text().splitlines()[1:]
        if len(line.split()) > 1
    )
    unexpected_methods = sorted({
        str(message["method"])
        for message in transcript
        if "method" in message and message["method"] != "session/update"
    })
    forbidden_updates = [kind for kind in update_kinds if kind in {"tool_call", "tool_call_update"}]
    continuous = monitor.snapshot()
    if continuous["monitor_error"] is not None or not continuous["monitor_stopped"]:
        fail("MONITOR_FAILED", str(continuous["monitor_error"]))
    filesystem_canary_leaked = any(
        "AOS_SYNTHETIC_FILESYSTEM_READ_CANARY" in value
        for value in (
            json.dumps(transcript, sort_keys=True),
            stderr.decode("utf-8", "replace"),
            *(str(item.get("body_text", "")) for item in requests),
        )
    )
    report = {
        "schema": "AOS_KIMI_FIXTURE/1",
        "ok": bool(requests) and all(item["auth_ok"] for item in requests),
        "agent_info": result.get("agentInfo"),
        "protocol_version": result.get("protocolVersion"),
        "auth_method_ids": [item.get("id") for item in result.get("authMethods", [])],
        "auth_terminal_args": result.get("authMethods", [{}])[0].get("args"),
        "provider_request_count": len(requests),
        "provider_paths": [item["path"] for item in requests],
        "provider_header_names": requests[0]["header_names"] if requests else [],
        "provider_tools": provider_tools,
        "profile_prompt_seen": "AgenticOS F1 Planner" in system_text,
        "plan_schema": plan_schema,
        "workspace_entries": sorted(path.name for path in WORKSPACE.iterdir()),
        "checkout_visible": pathlib.Path("/workspace/.git").exists() or pathlib.Path("/.git").exists(),
        "default_route_present": default_route,
        "non_loopback_socket_seen": continuous["non_loopback_socket_seen"],
        "socket_census": continuous["socket_endpoints"],
        "credential_canary_leaked": canary_outside_credential(transcript, stderr, capture),
        "credential_canary_count": len(CREDENTIAL_CANARIES),
        "api_key_name_seen": any("API_KEY" in name for name in process["env_names"]),
        "unexpected_callback_methods": unexpected_methods,
        "tool_update_kinds": forbidden_updates,
        "kimi_children": continuous["other_children"],
        "continuous_census_samples": continuous["samples"],
        "hostile_window_samples": monitor_after_hostile - monitor_before_prompt,
        "monitor_error": continuous["monitor_error"],
        "monitor_stopped": continuous["monitor_stopped"],
        "max_descendant_count": continuous["max_descendants"],
        "continuous_fd_classes": continuous["fd_classes"],
        "child_environment_names": process["env_names"],
        "child_fd_classes": process["fd_classes"],
        "child_open_fd_classes": process["open_fd_classes"],
        "host_authority_fd_seen": continuous["host_authority_fd_seen"],
        "synthetic_secret_fd_inherited": any(
            kind == "other" for kind in process["open_fd_classes"].values()
        ),
        "net_namespace": process["net_namespace"],
        "pid_namespace": process["pid_namespace"],
        "namespace_ids": process["namespace_ids"],
        "cgroup_membership": process["cgroup"],
        "provider_process_count": len(process["kimi_pids"]),
        "provider_process_argv": process["target_argv"],
        "provider_executable": process["target_executable"],
        "provider_parent": "python3:kimi_loopback_fixture.py",
        "process_group": process["process_group"],
        "created_state_classifications": classify_state(),
        "shell_marker_exists": pathlib.Path("/tmp/aos-shell-marker").exists(),
        "attempted_tool_names": list(FORBIDDEN_TOOL_ATTEMPTS) if scenario == "tool-attempt" else [],
        "tool_attempt_structurally_rejected": scenario != "tool-attempt" or (
            not pathlib.Path("/tmp/aos-shell-marker").exists()
            and not pathlib.Path("/tmp/aos-fs-write-marker").exists()
            and not filesystem_canary_leaked
            and provider_tools == []
            and not continuous["other_children"]
            and bool(forbidden_updates)
        ),
        "filesystem_read_canary_leaked": filesystem_canary_leaked,
        "filesystem_write_marker_exists": pathlib.Path("/tmp/aos-fs-write-marker").exists(),
        "cancel_stop_reason": prompted.get("result", {}).get("stopReason") if scenario == "cancel" else None,
        "malformed_stream_rejected": scenario != "malformed-stream" or (
            "error" in prompted or plan_schema != "AOSPLAN/1"
        ),
        "process_crash_rejected": scenario != "process-crash" or (
            proc.returncode is not None and plan_schema is None and not continuous["other_children"]
        ),
        "process_returncode": proc.returncode,
        "provider_process_alive_after_cleanup": proc.poll() is None,
        "stderr_nonempty": bool(stderr),
    }
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if any(canary in encoded for canary in CREDENTIAL_CANARIES):
        fail("REPORT_CANARY_LEAK")
    sys.stdout.write(encoded + "\n")


if __name__ == "__main__":
    main()
