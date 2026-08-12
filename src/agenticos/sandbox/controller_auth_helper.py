"""Controller-side manager for out-of-process provider authentication daemon.

Launches and manages a dedicated AuthHelperDaemon process with least OS authority.
Ensures refresh token authority is strictly process-separated from controller and provider broker.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .provider_models import (
    AuthHelperProcessIdentity,
    ProviderAuthCapability,
    ProviderAuthBinding,
    SecretValue,
    SubscriptionAuthCapability,
)


class ControllerAuthHelper:
    """Manages synthetic provider authentication state out-of-process in a dedicated daemon."""

    def __init__(self, auth_json_path_or_dict: str | Dict[str, Any], private_dir: Optional[str] = None) -> None:
        if private_dir is None:
            self._temp_dir: Optional[str] = tempfile.mkdtemp(prefix="aos-auth-private-")
            self._private_root = Path(self._temp_dir)
        else:
            self._temp_dir = None
            self._private_root = Path(private_dir)
            self._private_root.mkdir(parents=True, exist_ok=True)

        self._auth_json_path = self._private_root / "auth.json"

        if isinstance(auth_json_path_or_dict, str):
            if not os.path.exists(auth_json_path_or_dict):
                raise FileNotFoundError(f"Auth file not found: {auth_json_path_or_dict}")
            with open(auth_json_path_or_dict, "r", encoding="utf-8") as f:
                data = json.load(f)
        elif isinstance(auth_json_path_or_dict, dict):
            data = auth_json_path_or_dict
        else:
            raise TypeError("auth_json_path_or_dict must be a file path string or a dict")

        self._validate_schema(data)
        tokens = data.get("tokens", {})
        self._auth_mode: str = data.get("auth_mode", "chatgpt")
        self._account_id: str | None = tokens.get("account_id")

        # Write private auth file in non-repository root
        with open(self._auth_json_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        self._proc: Optional[subprocess.Popen[str]] = None
        self._ipc_endpoint: Optional[str] = None
        self._process_identity: Optional[AuthHelperProcessIdentity] = None

        self._start_daemon()

    def _validate_schema(self, data: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            raise ValueError("Auth data must be a dictionary")
        if "tokens" not in data or not isinstance(data["tokens"], dict):
            raise ValueError("Auth data missing required 'tokens' dictionary")
        tokens = data["tokens"]
        if "access_token" not in tokens or not isinstance(tokens["access_token"], str):
            raise ValueError("Auth tokens missing required 'access_token' string")

    def _start_daemon(self) -> None:
        """Launch AuthHelperDaemon in a separate OS process with minimal env and non-repo cwd."""
        daemon_module = "agenticos.sandbox.auth_helper_daemon"

        # Explicit minimal environment for auth helper process
        minimal_env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": os.environ.get("PYTHONPATH", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        }
        # Clean out any ambient secret variables from daemon environment
        for k in list(minimal_env.keys()):
            if not minimal_env[k]:
                del minimal_env[k]

        # Port 0 for dynamic loopback socket binding
        argv = [
            sys.executable,
            "-m",
            daemon_module,
            "--auth-file",
            str(self._auth_json_path),
            "--socket-endpoint",
            "0",
            "--parent-pid",
            str(os.getpid()),
        ]

        self._proc = subprocess.Popen(
            argv,
            cwd=str(self._private_root),
            env=minimal_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            close_fds=True,
        )

        # Wait for daemon readiness signal
        assert self._proc.stdout is not None
        ready_line = self._proc.stdout.readline().strip()
        if not ready_line.startswith("AUTH_HELPER_READY:"):
            stderr_msg = self._proc.stderr.read() if self._proc.stderr else ""
            self.stop()
            raise RuntimeError(f"Auth helper daemon failed to start: {ready_line} {stderr_msg}")

        self._ipc_endpoint = ready_line.split(":", 1)[1]

        # Request identity snapshot over IPC
        id_resp = self._send_ipc({"action": "GET_IDENTITY"})
        if id_resp.get("status") != "OK" or "identity" not in id_resp:
            self.stop()
            raise RuntimeError(f"Auth helper daemon identity handshake failed: {id_resp}")

        raw_id = id_resp["identity"]
        self._process_identity = AuthHelperProcessIdentity(
            pid=raw_id["pid"],
            executable=raw_id["executable"],
            executable_digest=raw_id["executable_digest"],
            cwd=raw_id["cwd"],
            env_keys=tuple(raw_id["env_keys"]),
            open_fd_count=raw_id["open_fd_count"],
            ipc_endpoint=raw_id["ipc_endpoint"],
            parent_pid=raw_id["parent_pid"],
            started_at_monotonic_ns=raw_id["started_at_monotonic_ns"],
        )

    def _send_ipc(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send line-delimited JSON IPC request to auth helper daemon."""
        if not self._ipc_endpoint:
            raise RuntimeError("Auth helper daemon endpoint not available")

        if self._ipc_endpoint.startswith("tcp://"):
            host, port_str = self._ipc_endpoint[6:].split(":", 1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, int(port_str)))
        elif self._ipc_endpoint.startswith("unix://"):
            path = self._ipc_endpoint[7:]
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(path)
        else:
            raise RuntimeError(f"Unsupported IPC endpoint format: {self._ipc_endpoint}")

        with sock:
            sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in chunk:
                    break
            line = data.decode("utf-8").strip()
            if not line:
                raise RuntimeError("Empty response from auth helper daemon")
            return json.loads(line)

    @property
    def auth_mode(self) -> str:
        return self._auth_mode

    @property
    def account_id(self) -> str | None:
        return self._account_id

    @property
    def process_identity(self) -> AuthHelperProcessIdentity:
        if self._process_identity is None:
            raise RuntimeError("Auth helper process identity not available")
        return self._process_identity

    @property
    def is_expired(self) -> bool:
        resp = self._send_ipc({"action": "PING"})
        return resp.get("status") != "PONG"

    def get_auth_capability(
        self,
        task_id: str,
        generation: int,
        attempt_id: int = 1,
        launch_nonce: str = "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        provider_id: str = "chatgpt_subscription",
        *,
        upstream_scheme: str = "https",
        upstream_host: str = "chatgpt.example.test",
        upstream_port: int = 443,
        provider_purpose: str = "responses_sse",
    ) -> ProviderAuthCapability:
        """Return a short-lived task-bound SubscriptionAuthCapability over IPC."""
        request_nonce = secrets.token_hex(16)
        req = {
            "action": "GET_TASK_PROVIDER_CAPABILITY",
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
        }
        resp = self._send_ipc(req)
        if resp.get("status") != "OK":
            err = resp.get("error", "UNKNOWN_ERROR")
            if err in ("TASK_CAPABILITY_CANCELLED", "PROVIDER_AUTH_UNAVAILABLE", "REPLAYED_CAPABILITY_REQUEST"):
                raise RuntimeError(f"Auth capability request denied: {err}")
            raise ValueError(f"Auth capability request failed: {err}")

        expected_response = {
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
        }
        if any(resp.get(name) != value for name, value in expected_response.items()):
            raise ValueError("Auth capability response binding mismatch")
        binding = ProviderAuthBinding(
            task_id=resp["task_id"],
            generation=resp["generation"],
            attempt_id=resp["attempt_id"],
            launch_nonce=resp["launch_nonce"],
            provider_id=resp["provider_id"],
            upstream_scheme=resp["upstream_scheme"],
            upstream_host=resp["upstream_host"],
            upstream_port=resp["upstream_port"],
            provider_purpose=resp["provider_purpose"],
            helper_epoch=resp["helper_epoch"],
            request_nonce=resp["request_nonce"],
            capability_nonce=resp["capability_nonce"],
            capability_sequence=resp["capability_sequence"],
            issued_at=resp["issued_at"],
            expires_at=resp["expires_at"],
        )
        return SubscriptionAuthCapability(
            access_token=resp["access_token"],
            account_id=resp.get("account_id"),
            binding=binding,
        )

    def cancel_task(self, task_id: str) -> None:
        """Revoke capabilities for a task in the auth helper process."""
        self._send_ipc({"action": "CANCEL_TASK", "task_id": task_id})

    def trigger_refresh_failure(self) -> None:
        """Trigger simulated refresh rejection in daemon for failure testing."""
        self._send_ipc({"action": "TRIGGER_REFRESH_FAILURE"})

    def refresh_access_token(self, new_access_token: str, new_expires_in: int = 3600) -> None:
        """Update synthetic access token out-of-process when refreshed."""
        resp = self._send_ipc({
            "action": "REFRESH_TOKENS",
            "new_access_token": new_access_token,
            "expires_in": new_expires_in,
        })
        if resp.get("status") != "OK":
            raise ValueError(f"Token refresh update failed: {resp.get('error')}")

    def stop(self) -> None:
        """Stop auth helper daemon process and clean up private temp state."""
        if self._ipc_endpoint:
            try:
                self._send_ipc({"action": "SHUTDOWN"})
            except Exception:
                pass
            self._ipc_endpoint = None

        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2.0)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

        if self._temp_dir and os.path.exists(self._temp_dir):
            try:
                shutil.rmtree(self._temp_dir, ignore_errors=True)
            except Exception:
                pass

    def __enter__(self) -> "ControllerAuthHelper":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()

    def __repr__(self) -> str:
        pid = self._process_identity.pid if self._process_identity else None
        return f"ControllerAuthHelper(mode={self._auth_mode!r}, daemon_pid={pid})"


__all__ = [
    "ControllerAuthHelper",
]
