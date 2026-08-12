"""Out-of-process provider authentication daemon.

Runs in a separate OS process with least authority.
Manages refresh token and subscription access tokens in a private root.
Listens on a local socket endpoint for task-bound capability requests from the controller.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import signal
import socket
import sys
import time
from typing import Any, Dict, Optional, Tuple


def _get_executable_digest() -> str:
    """Return SHA-256 hex digest of the current Python executable."""
    try:
        with open(sys.executable, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        # Fallback digest if binary cannot be read directly
        return hashlib.sha256(sys.executable.encode("utf-8")).hexdigest()


def _count_open_fds() -> int:
    """Count open file descriptors for the current process."""
    if hasattr(os, "procfs") or os.path.exists("/proc/self/fd"):
        try:
            return len(os.listdir("/proc/self/fd"))
        except Exception:
            pass
    # Basic fallback approximation
    return 3


class AuthHelperDaemon:
    """Out-of-process daemon managing synthetic provider authentication state."""

    def __init__(self, auth_file: str, parent_pid: int) -> None:
        self.auth_file = os.path.abspath(auth_file)
        self.parent_pid = parent_pid
        self.started_at_monotonic_ns = time.monotonic_ns()
        self.helper_epoch = secrets.token_hex(16)
        self.revoked_tasks: set[str] = set()
        self.issued_nonces: set[str] = set()

        if not os.path.exists(self.auth_file):
            raise FileNotFoundError(f"Auth file not found: {self.auth_file}")

        with open(self.auth_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        self._validate_schema(data)
        tokens = data.get("tokens", {})
        self._auth_mode: str = data.get("auth_mode", "chatgpt")
        self._access_token: str = tokens.get("access_token", "")
        self._refresh_token: str = tokens.get("refresh_token", "")
        self._account_id: str | None = tokens.get("account_id")
        self._expires_at: int = tokens.get("expires_at", int(time.time()) + 3600)
        self._refresh_fail_trigger: bool = False

    def _validate_schema(self, data: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            raise ValueError("Auth data must be a dictionary")
        if "tokens" not in data or not isinstance(data["tokens"], dict):
            raise ValueError("Auth data missing required 'tokens' dictionary")
        tokens = data["tokens"]
        if "access_token" not in tokens or not isinstance(tokens["access_token"], str):
            raise ValueError("Auth tokens missing required 'access_token' string")

    @property
    def is_expired(self) -> bool:
        return time.time() >= self._expires_at

    def trigger_refresh_failure(self) -> None:
        """Trigger simulated refresh rejection for failure mode testing."""
        self._refresh_fail_trigger = True

    def get_identity_dict(self, ipc_endpoint: str) -> Dict[str, Any]:
        return {
            "pid": os.getpid(),
            "executable": sys.executable,
            "executable_digest": _get_executable_digest(),
            "cwd": os.getcwd(),
            "env_keys": sorted(list(os.environ.keys())),
            "open_fd_count": _count_open_fds(),
            "ipc_endpoint": ipc_endpoint,
            "parent_pid": self.parent_pid,
            "started_at_monotonic_ns": self.started_at_monotonic_ns,
        }

    def process_request(self, request: Dict[str, Any], ipc_endpoint: str) -> Dict[str, Any]:
        action = request.get("action")
        if action == "PING":
            return {"status": "PONG"}
        if action == "GET_IDENTITY":
            return {"status": "OK", "identity": self.get_identity_dict(ipc_endpoint)}

        if action == "GET_TASK_PROVIDER_CAPABILITY":
            task_id = request.get("task_id")
            generation = request.get("generation")
            attempt_id = request.get("attempt_id")
            launch_nonce = request.get("launch_nonce")
            provider_id = request.get("provider_id", "chatgpt_subscription")
            request_nonce = request.get("request_nonce")
            upstream_scheme = request.get("upstream_scheme")
            upstream_host = request.get("upstream_host")
            upstream_port = request.get("upstream_port")
            provider_purpose = request.get("provider_purpose")

            if not task_id or not isinstance(task_id, str):
                return {"status": "ERROR", "error": "Invalid task_id"}
            if type(generation) is not int or generation <= 0:
                return {"status": "ERROR", "error": "Invalid generation"}
            if type(attempt_id) is not int or attempt_id <= 0:
                return {"status": "ERROR", "error": "Invalid attempt_id"}
            if not launch_nonce or not isinstance(launch_nonce, str):
                return {"status": "ERROR", "error": "Invalid launch_nonce"}

            # Check revocation
            if task_id in self.revoked_tasks:
                return {"status": "ERROR", "error": "TASK_CAPABILITY_CANCELLED"}

            # Check replay prevention on capability nonce
            cap_key = f"{task_id}:{generation}:{attempt_id}:{launch_nonce}"
            if cap_key in self.issued_nonces:
                return {"status": "ERROR", "error": "REPLAYED_CAPABILITY_REQUEST"}
            self.issued_nonces.add(cap_key)

            # Check simulated refresh trigger failure
            if self._refresh_fail_trigger:
                return {"status": "ERROR", "error": "PROVIDER_AUTH_UNAVAILABLE"}

            # Perform synthetic token refresh if expired
            if self.is_expired:
                if not self._refresh_token:
                    return {"status": "ERROR", "error": "PROVIDER_AUTH_UNAVAILABLE"}
                # Synthetic token refresh out-of-process
                self._access_token = f"CANARY_ACCESS_TOKEN_REFRESHED_{int(time.time())}"
                self._expires_at = int(time.time()) + 3600

            issued_at = int(time.time())
            cap_nonce = hashlib.sha256(f"{cap_key}:{time.time()}".encode("ascii")).hexdigest()[:32]
            return {
                "status": "OK",
                "request_nonce": request_nonce,
                "task_id": task_id,
                "generation": generation,
                "attempt_id": attempt_id,
                "launch_nonce": launch_nonce,
                "provider_id": provider_id,
                "upstream_scheme": upstream_scheme,
                "upstream_host": upstream_host,
                "upstream_port": upstream_port,
                "provider_purpose": provider_purpose,
                "helper_epoch": self.helper_epoch,
                "access_token": self._access_token,
                "account_id": self._account_id,
                "issued_at": issued_at,
                "expires_at": min(self._expires_at, issued_at + 300),
                "capability_nonce": cap_nonce,
                "capability_sequence": 1,
            }

        if action == "CANCEL_TASK":
            task_id = request.get("task_id")
            if task_id and isinstance(task_id, str):
                self.revoked_tasks.add(task_id)
            return {"status": "OK"}

        if action == "TRIGGER_REFRESH_FAILURE":
            self.trigger_refresh_failure()
            return {"status": "OK"}

        if action == "REFRESH_TOKENS":
            new_access = request.get("new_access_token")
            if not new_access or not isinstance(new_access, str):
                return {"status": "ERROR", "error": "Invalid new_access_token"}
            self._access_token = new_access
            self._expires_at = int(time.time()) + request.get("expires_in", 3600)
            return {"status": "OK"}

        return {"status": "ERROR", "error": f"Unknown action: {action}"}


def run_daemon_server(auth_file: str, parent_pid: int, socket_path_or_port: str) -> None:
    """Run socket server for AuthHelperDaemon."""
    daemon = AuthHelperDaemon(auth_file, parent_pid)

    if socket_path_or_port.isdigit():
        port = int(socket_path_or_port)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", port))
        endpoint_str = f"tcp://127.0.0.1:{server.getsockname()[1]}"
    else:
        # AF_UNIX socket path
        if os.path.exists(socket_path_or_port):
            os.remove(socket_path_or_port)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(socket_path_or_port)
        endpoint_str = f"unix://{socket_path_or_port}"

    server.listen(5)
    print(f"AUTH_HELPER_READY:{endpoint_str}", flush=True)

    while True:
        try:
            conn, _ = server.accept()
        except KeyboardInterrupt:
            break
        except Exception:
            break

        with conn:
            try:
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if b"\n" in chunk:
                        break

                if not data:
                    continue

                line = data.decode("utf-8").strip()
                if not line:
                    continue

                request = json.loads(line)
                response = daemon.process_request(request, endpoint_str)
                conn.sendall(json.dumps(response).encode("utf-8") + b"\n")

                if request.get("action") == "SHUTDOWN":
                    break
            except Exception as exc:
                err_resp = {"status": "ERROR", "error": str(exc)}
                try:
                    conn.sendall(json.dumps(err_resp).encode("utf-8") + b"\n")
                except Exception:
                    pass

    server.close()
    if not socket_path_or_port.isdigit() and os.path.exists(socket_path_or_port):
        try:
            os.remove(socket_path_or_port)
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="AgenticOS Out-of-Process Auth Helper Daemon")
    parser.add_argument("--auth-file", required=True, help="Path to auth.json file")
    parser.add_argument("--socket-endpoint", required=True, help="Socket path or port number")
    parser.add_argument("--parent-pid", type=int, required=True, help="Parent controller PID")
    args = parser.parse_args()

    run_daemon_server(args.auth_file, args.parent_pid, args.socket_endpoint)


if __name__ == "__main__":
    main()
