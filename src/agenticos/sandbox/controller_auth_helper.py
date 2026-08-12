"""Controller-side manager for out-of-process provider authentication daemon.

Launches and manages a dedicated AuthHelperDaemon process with least OS authority.
The trusted controller retains the documented same-UID authority residual; the
hostile Codex workspace and provider broker receive no refresh-secret authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from . import auth_helper_daemon as _auth_helper_daemon
from .auth_helper_daemon import (
    IPC_PROTOCOL_VERSION,
    _decode_response_packet,
    _encode_packet,
    _linux_open_fds,
    _recv_linux_packet,
    _recv_stream_packet,
    _send_linux_packet,
    _send_stream_packet,
)

from .provider_models import (
    AuthHelperProcessIdentity,
    ProviderAuthCapability,
    ProviderAuthBinding,
    SubscriptionAuthCapability,
)


def _trusted_file_identity(path: Path) -> tuple[str, int, int, str]:
    absolute = str(path.resolve(strict=True))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(absolute, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("Trusted helper implementation is not a regular file")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        return absolute, metadata.st_dev, metadata.st_ino, digest.hexdigest()
    finally:
        os.close(fd)


def _open_or_create_auth_root(path: Path) -> int | None:
    """Resolve every root component without symlinks and return the exact directory FD."""
    if os.name == "nt":
        if path.exists() or path.is_symlink():
            metadata = path.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise RuntimeError("auth root must be a real directory")
        else:
            path.mkdir(parents=True, mode=0o700)
        return None
    absolute = path.absolute()
    components = absolute.parts[1:]
    if not components:
        raise RuntimeError("auth root cannot be filesystem root")
    current_fd = os.open(
        os.path.sep,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        for index, component in enumerate(components):
            flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except FileNotFoundError:
                os.mkdir(component, mode=0o700, dir_fd=current_fd)
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except OSError as exc:
                raise RuntimeError("auth root path must contain only real directories") from exc
            os.close(current_fd)
            current_fd = next_fd
            if index == len(components) - 1:
                os.fchmod(current_fd, 0o700)
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


class ControllerAuthHelper:
    """Manages synthetic provider authentication state out-of-process in a dedicated daemon."""

    def __init__(
        self,
        auth_json_path_or_dict: str | Dict[str, Any],
        private_dir: Optional[str] = None,
        *,
        _test_inherited_fds: tuple[int, ...] = (),
        _test_startup_fault: str | None = None,
        _test_denied_probe_paths: tuple[str, ...] = (),
        _test_auth_root_mutator: Callable[[Path], None] | None = None,
        _test_allowed_probe_name: str | None = None,
        _test_expose_process_probe: bool = False,
    ) -> None:
        if private_dir is None:
            self._temp_dir: Optional[str] = tempfile.mkdtemp(prefix="aos-auth-private-")
            self._private_root = Path(self._temp_dir)
        else:
            self._temp_dir = None
            self._private_root = Path(private_dir)
        auth_root_fd = _open_or_create_auth_root(self._private_root)
        auth_created = False
        try:
            root_metadata = (
                os.fstat(auth_root_fd)
                if auth_root_fd is not None
                else self._private_root.stat(follow_symlinks=False)
            )
            self._auth_root_identity = (root_metadata.st_dev, root_metadata.st_ino)
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
            self._auth_mode = data.get("auth_mode", "chatgpt")
            self._account_id = tokens.get("account_id")

            auth_fd = os.open(
                "auth.json" if auth_root_fd is not None else self._auth_json_path,
                os.O_CREAT
                | os.O_EXCL
                | os.O_WRONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                **({"dir_fd": auth_root_fd} if auth_root_fd is not None else {}),
            )
            auth_created = True
            with os.fdopen(auth_fd, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            if auth_created:
                try:
                    if auth_root_fd is not None:
                        os.unlink("auth.json", dir_fd=auth_root_fd)
                    else:
                        os.unlink(self._auth_json_path)
                except FileNotFoundError:
                    pass
            if self._temp_dir and os.path.exists(self._temp_dir):
                shutil.rmtree(self._temp_dir, ignore_errors=True)
            raise
        finally:
            if auth_root_fd is not None:
                os.close(auth_root_fd)

        self._proc: Optional[subprocess.Popen[Any]] = None
        self._ipc_sock: Optional[socket.socket] = None
        self._ipc_endpoint: Optional[str] = None
        self._process_identity: Optional[AuthHelperProcessIdentity] = None
        self._ipc_lock = threading.RLock()
        self._launch_argv: tuple[str, ...] = ()
        self._test_inherited_fds = _test_inherited_fds
        self._test_inherited_fds_closed: tuple[int, ...] = ()
        self._test_startup_fault = _test_startup_fault
        self._test_denied_probe_paths = _test_denied_probe_paths
        self._test_allowed_probe_name = _test_allowed_probe_name
        self._filesystem_probe_results: tuple[tuple[str, str, str], ...] = ()
        self._test_process_probe_address: int | None = None
        self._test_expose_process_probe = _test_expose_process_probe
        self._attempt_sequences: dict[tuple[Any, ...], int] = {}
        self._registered_brokers: list[Any] = []
        if _test_auth_root_mutator is not None:
            _test_auth_root_mutator(self._private_root)
        self._ready_standard_fds_null = False
        self._windows_stdin_bootstrap_closed = False

        try:
            self._start_daemon()
        except Exception as exc:
            self._abort_startup()
            raise RuntimeError("Auth helper startup failed closed") from exc

    def _validate_schema(self, data: Dict[str, Any]) -> None:
        if not isinstance(data, dict):
            raise ValueError("Auth data must be a dictionary")
        if data.get("auth_mode", "chatgpt") != "chatgpt":
            raise ValueError("Auth mode must be chatgpt")
        if "tokens" not in data or not isinstance(data["tokens"], dict):
            raise ValueError("Auth data missing required 'tokens' dictionary")
        tokens = data["tokens"]
        if "access_token" not in tokens or not isinstance(tokens["access_token"], str):
            raise ValueError("Auth tokens missing required 'access_token' string")

    def _start_daemon(self) -> None:
        """Launch AuthHelperDaemon in a separate OS process with minimal env and non-repo cwd."""
        interpreter_identity = _trusted_file_identity(Path(sys.executable))
        entrypoint_file = getattr(_auth_helper_daemon, "__file__", None)
        if not entrypoint_file:
            raise RuntimeError("Auth helper entrypoint identity unavailable")
        entrypoint_identity = _trusted_file_identity(Path(entrypoint_file))
        argv = [
            interpreter_identity[0],
            "-I",
            "-S",
            entrypoint_identity[0],
            "--parent-pid",
            str(os.getpid()),
        ]
        minimal_env: dict[str, str]
        if sys.platform.startswith("linux"):
            minimal_env = {}
        else:
            minimal_env = {
                key: os.environ[key]
                for key in ("SYSTEMROOT", "WINDIR")
                if os.environ.get(key)
            }
        if sys.platform.startswith("linux"):
            parent_socket, child_socket = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET
            )
            parent_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            child_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            creation_peer = struct.unpack(
                "3i",
                parent_socket.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                ),
            )
            if creation_peer != (os.getpid(), os.getuid(), os.getgid()):
                parent_socket.close()
                child_socket.close()
                raise RuntimeError("Auth helper socketpair creation peer mismatch")
            argv.extend(["--ipc-fd", str(child_socket.fileno())])
            if self._test_startup_fault:
                argv.extend(["--test-startup-fault", self._test_startup_fault])
            if self._test_inherited_fds:
                argv.extend(
                    [
                        "--test-inherited-fds",
                        ",".join(str(fd) for fd in self._test_inherited_fds),
                    ]
                )
            for probe_path in self._test_denied_probe_paths:
                argv.extend(["--test-denied-probe", probe_path])
            if self._test_allowed_probe_name is not None:
                argv.extend(["--test-allowed-probe", self._test_allowed_probe_name])
            if self._test_expose_process_probe:
                argv.append("--test-expose-process-probe")
            pass_fds = (child_socket.fileno(), *self._test_inherited_fds)
            self._launch_argv = tuple(argv)
            try:
                self._proc = subprocess.Popen(
                    argv,
                    cwd=str(self._private_root),
                    env=minimal_env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    pass_fds=pass_fds,
                )
            finally:
                child_socket.close()
            self._ipc_sock = parent_socket
            self._ipc_endpoint = f"fd://{parent_socket.fileno()}"
            assert self._proc is not None
            _send_linux_packet(parent_socket, self._startup_packet())
            ready_packet = _recv_linux_packet(
                parent_socket,
                expected_pid=self._proc.pid,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
                allowed_fds=self._current_controller_fds(),
            )
        elif os.name == "nt":
            bootstrap_nonce = secrets.token_bytes(32)
            argv.append("--windows-loopback")
            self._launch_argv = tuple(argv)
            self._proc = subprocess.Popen(
                argv,
                cwd=str(self._private_root),
                env=minimal_env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                text=False,
            )
            assert self._proc.stdin is not None
            self._proc.stdin.write(bootstrap_nonce)
            self._proc.stdin.flush()
            self._proc.stdin.close()
            assert self._proc.stdout is not None
            ready_line = self._proc.stdout.readline(129)
            self._proc.stdout.close()
            prefix = b"AUTH_HELPER_READY:"
            if (
                not ready_line.endswith(b"\n")
                or len(ready_line) > 128
                or not ready_line.startswith(prefix)
            ):
                self.stop()
                raise RuntimeError("Auth helper daemon failed bounded startup")
            endpoint = ready_line[len(prefix) : -1].decode("ascii", errors="strict")
            if not endpoint.startswith("tcp://127.0.0.1:"):
                self.stop()
                raise RuntimeError("Auth helper daemon returned invalid endpoint")
            port = int(endpoint.rsplit(":", 1)[1])
            ipc_socket = socket.create_connection(
                ("127.0.0.1", port), timeout=2.0
            )
            self._ipc_sock = ipc_socket
            self._ipc_endpoint = endpoint
            _send_stream_packet(
                ipc_socket,
                _encode_packet(
                    {
                        "protocol_version": IPC_PROTOCOL_VERSION,
                        "action": "BOOTSTRAP",
                        "bootstrap_nonce": bootstrap_nonce.hex(),
                    }
                ),
            )
            bootstrap_nonce = b""
            _send_stream_packet(ipc_socket, self._startup_packet())
            ready_packet = _recv_stream_packet(ipc_socket)
        else:
            raise RuntimeError("Unsupported auth helper platform")

        ready = _decode_response_packet(ready_packet)
        if ready.get("status") != "READY" or "identity" not in ready:
            self.stop()
            raise RuntimeError("Auth helper daemon identity handshake failed")
        raw_id = ready["identity"]
        self._process_identity = AuthHelperProcessIdentity(
            pid=raw_id["pid"],
            parent_pid=raw_id["parent_pid"],
            uid=raw_id["uid"],
            gid=raw_id["gid"],
            controller_uid=raw_id["controller_uid"],
            controller_gid=raw_id["controller_gid"],
            executable=raw_id["executable"],
            executable_device=raw_id["executable_device"],
            executable_inode=raw_id["executable_inode"],
            executable_digest=raw_id["executable_digest"],
            entrypoint=raw_id["entrypoint"],
            entrypoint_device=raw_id["entrypoint_device"],
            entrypoint_inode=raw_id["entrypoint_inode"],
            entrypoint_digest=raw_id["entrypoint_digest"],
            cwd=raw_id["cwd"],
            env_keys=tuple(raw_id["env_keys"]),
            import_paths=tuple(raw_id["import_paths"]),
            open_fds=tuple(raw_id["open_fds"]),
            ipc_endpoint=raw_id["ipc_endpoint"],
            ipc_type=raw_id["ipc_type"],
            ipc_peer_auth=raw_id["ipc_peer_auth"],
            helper_epoch=raw_id["helper_epoch"],
            protocol_version=raw_id["protocol_version"],
            core_soft_limit=raw_id["core_soft_limit"],
            core_hard_limit=raw_id["core_hard_limit"],
            dumpable=raw_id["dumpable"],
            no_new_privs=raw_id["no_new_privs"],
            landlock_abi=raw_id["landlock_abi"],
            landlock_handled_access_fs=raw_id["landlock_handled_access_fs"],
            auth_root_device=raw_id["auth_root_device"],
            auth_root_inode=raw_id["auth_root_inode"],
            started_at_monotonic_ns=raw_id["started_at_monotonic_ns"],
        )
        self._ready_standard_fds_null = bool(raw_id["standard_fds_null"])
        self._windows_stdin_bootstrap_closed = bool(
            raw_id["windows_stdin_bootstrap_closed"]
        )
        self._filesystem_probe_results = tuple(
            tuple(result) for result in raw_id["filesystem_probe_results"]
        )
        self._test_process_probe_address = raw_id["test_process_probe_address"]
        self._validate_ready_identity(
            self._process_identity,
            interpreter_identity=interpreter_identity,
            entrypoint_identity=entrypoint_identity,
        )
        self._test_inherited_fds_closed = tuple(raw_id["closed_inherited_fds"])

    def _startup_packet(self) -> bytes:
        controller_uid = os.getuid() if hasattr(os, "getuid") else 0
        controller_gid = os.getgid() if hasattr(os, "getgid") else 0
        return _encode_packet(
            {
                "protocol_version": IPC_PROTOCOL_VERSION,
                "action": "STARTUP",
                "auth_file": str(self._auth_json_path),
                "controller_pid": os.getpid(),
                "controller_uid": controller_uid,
                "controller_gid": controller_gid,
                "auth_root_device": self._auth_root_identity[0],
                "auth_root_inode": self._auth_root_identity[1],
            }
        )

    def _validate_ready_identity(
        self,
        identity: AuthHelperProcessIdentity,
        *,
        interpreter_identity: tuple[str, int, int, str],
        entrypoint_identity: tuple[str, int, int, str],
    ) -> None:
        assert self._proc is not None
        controller_uid = os.getuid() if hasattr(os, "getuid") else 0
        controller_gid = os.getgid() if hasattr(os, "getgid") else 0
        if (
            identity.pid != self._proc.pid
            or identity.parent_pid != os.getpid()
            or identity.controller_uid != controller_uid
            or identity.controller_gid != controller_gid
            or identity.protocol_version != IPC_PROTOCOL_VERSION
            or (
                identity.executable,
                identity.executable_device,
                identity.executable_inode,
                identity.executable_digest,
            )
            != interpreter_identity
            or (
                identity.entrypoint,
                identity.entrypoint_device,
                identity.entrypoint_inode,
                identity.entrypoint_digest,
            )
            != entrypoint_identity
        ):
            raise RuntimeError("Auth helper READY identity mismatch")
        if sys.platform.startswith("linux") and (
            identity.uid != controller_uid
            or identity.gid != controller_gid
            or identity.open_fds != (0, 1, 2, 3)
            or identity.core_soft_limit != 0
            or identity.core_hard_limit != 0
            or identity.dumpable != 0
            or identity.no_new_privs != 1
            or identity.ipc_type != "AF_UNIX/SOCK_SEQPACKET"
            or identity.ipc_peer_auth != "SO_PASSCRED/SCM_CREDENTIALS"
            or not self._ready_standard_fds_null
            or identity.landlock_abi is None
            or identity.landlock_abi < 3
            or identity.landlock_handled_access_fs != 0x7FFF
            or (identity.auth_root_device, identity.auth_root_inode)
            != self._auth_root_identity
        ):
            raise RuntimeError("Auth helper READY hardening mismatch")
        if os.name == "nt" and (
            not self._windows_stdin_bootstrap_closed
            or identity.ipc_type != "AF_INET/SOCK_STREAM"
            or identity.ipc_peer_auth
            != "BOOTSTRAP_NONCE_ONLY_WINDOWS_FUNCTIONAL"
        ):
            raise RuntimeError("Auth helper Windows bootstrap evidence mismatch")

    def _current_controller_fds(self) -> frozenset[int]:
        if not sys.platform.startswith("linux"):
            return frozenset()
        return _linux_open_fds()

    def _send_ipc(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Exchange one strict bounded request on the persistent authenticated channel."""
        if not self._ipc_endpoint or self._ipc_sock is None:
            raise RuntimeError("Auth helper daemon endpoint not available")
        request = _encode_packet(
            {"protocol_version": IPC_PROTOCOL_VERSION, **payload}
        )
        try:
            with self._ipc_lock:
                if sys.platform.startswith("linux"):
                    _send_linux_packet(self._ipc_sock, request)
                    assert self._proc is not None
                    response = _recv_linux_packet(
                        self._ipc_sock,
                        expected_pid=self._proc.pid,
                        expected_uid=os.getuid(),
                        expected_gid=os.getgid(),
                        allowed_fds=self._current_controller_fds(),
                    )
                else:
                    _send_stream_packet(self._ipc_sock, request)
                    response = _recv_stream_packet(self._ipc_sock)
                decoded = _decode_response_packet(response)
        except Exception:
            self._revoke_registered_brokers()
            raise
        return decoded

    def _revoke_registered_brokers(self) -> None:
        for broker in tuple(self._registered_brokers):
            try:
                broker.cancel_auth_capability()
            except Exception:
                pass

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
        _request_nonce: str | None = None,
    ) -> ProviderAuthCapability:
        """Return a short-lived task-bound SubscriptionAuthCapability over IPC."""
        with self._ipc_lock:
            return self._get_auth_capability_locked(
                task_id, generation, attempt_id, launch_nonce, provider_id,
                upstream_scheme=upstream_scheme,
                upstream_host=upstream_host,
                upstream_port=upstream_port,
                provider_purpose=provider_purpose,
                request_nonce=_request_nonce or secrets.token_hex(16),
            )

    def _get_auth_capability_locked(
        self,
        task_id: str,
        generation: int,
        attempt_id: int,
        launch_nonce: str,
        provider_id: str,
        *,
        upstream_scheme: str,
        upstream_host: str,
        upstream_port: int,
        provider_purpose: str,
        request_nonce: str,
    ) -> ProviderAuthCapability:
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
            if err in (
                "TASK_CAPABILITY_CANCELLED",
                "PROVIDER_AUTH_UNAVAILABLE",
                "REPLAYED_CAPABILITY_REQUEST",
                "CAPABILITY_ISSUANCE_LIMIT",
                "REPLAY_CACHE_EXHAUSTED",
                "ATTEMPT_CONTEXT_EXHAUSTED",
            ):
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
        context_key = (
            task_id, generation, attempt_id, launch_nonce, provider_id,
            upstream_scheme, upstream_host, upstream_port, provider_purpose,
        )
        expected_sequence = self._attempt_sequences.get(context_key, 0) + 1
        now = int(time.time())
        if (
            self._process_identity is None
            or resp.get("helper_epoch") != self._process_identity.helper_epoch
            or resp.get("capability_sequence") != expected_sequence
            or type(resp.get("issued_at")) is not int
            or type(resp.get("expires_at")) is not int
            or not resp["issued_at"] <= now + 1
            or not resp["issued_at"] < resp["expires_at"] <= resp["issued_at"] + 300
            or type(resp.get("capability_nonce")) is not str
            or not re.fullmatch(r"[0-9a-f]{32}", resp["capability_nonce"])
        ):
            raise ValueError("Auth capability response issuance mismatch")
        self._attempt_sequences[context_key] = expected_sequence
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

    def cancel_task(
        self,
        task_id: str,
        generation: int = 1,
        attempt_id: int = 1,
        launch_nonce: str = "c3d4e5f60718293a4b5c6d7e8f90a1b2",
        provider_id: str = "chatgpt_subscription",
        *,
        upstream_scheme: str = "https",
        upstream_host: str = "chatgpt.example.test",
        upstream_port: int = 443,
        provider_purpose: str = "responses_sse",
    ) -> None:
        """Revoke one exact attempt context in the auth helper process."""
        response = self._send_ipc(
            {
                "action": "CANCEL_ATTEMPT",
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
        )
        if response.get("status") != "OK":
            raise RuntimeError(
                f"Auth capability cancellation denied: {response.get('error', 'UNKNOWN_ERROR')}"
            )

    def register_broker(self, broker: Any) -> None:
        """Register a live broker whose slot is bound to this helper epoch."""
        if broker not in self._registered_brokers:
            self._registered_brokers.append(broker)

    def replace_broker_auth_capability(self, broker: Any) -> ProviderAuthCapability:
        """Issue and atomically install the next capability for a live broker."""
        with self._ipc_lock:
            self.register_broker(broker)
            policy = broker.policy
            context_key = (
                policy.task_id, policy.generation, policy.attempt_id,
                policy.launch_nonce, policy.upstream_provider_id,
                policy.upstream_scheme, policy.upstream_host,
                policy.upstream_port, "responses_sse",
            )
            expected_sequence = self._attempt_sequences.get(context_key, 0)
            candidate = self.get_auth_capability(
                policy.task_id,
                policy.generation,
                policy.attempt_id,
                policy.launch_nonce,
                policy.upstream_provider_id,
                upstream_scheme=policy.upstream_scheme,
                upstream_host=policy.upstream_host,
                upstream_port=policy.upstream_port,
                provider_purpose="responses_sse",
            )
            broker.replace_auth_capability(
                candidate,
                expected_sequence=expected_sequence,
            )
            return candidate

    def cancel_broker_auth_capability(self, broker: Any) -> None:
        """Cancel the exact helper context before atomically revoking the broker."""
        policy = broker.policy
        self.cancel_task(
            policy.task_id,
            policy.generation,
            policy.attempt_id,
            policy.launch_nonce,
            policy.upstream_provider_id,
            upstream_scheme=policy.upstream_scheme,
            upstream_host=policy.upstream_host,
            upstream_port=policy.upstream_port,
            provider_purpose="responses_sse",
        )
        broker.cancel_auth_capability()

    def trigger_refresh_failure(self) -> None:
        """Trigger simulated refresh rejection in daemon for failure testing."""
        self._send_ipc({"action": "TRIGGER_REFRESH_FAILURE"})

    def _abort_startup(self) -> None:
        """Close partial startup authority without attempting protocol shutdown."""
        self._ipc_endpoint = None
        if self._ipc_sock is not None:
            try:
                self._ipc_sock.close()
            except Exception:
                pass
            self._ipc_sock = None
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2.0)
            except Exception:
                try:
                    self._proc.kill()
                    self._proc.wait(timeout=2.0)
                except Exception:
                    pass
            self._proc = None
        if self._temp_dir and os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)

    def stop(self) -> None:
        """Stop auth helper daemon process and clean up private temp state."""
        self._revoke_registered_brokers()
        self._registered_brokers.clear()
        if self._ipc_endpoint:
            try:
                self._send_ipc({"action": "SHUTDOWN"})
            except Exception:
                pass
            self._ipc_endpoint = None

        if self._ipc_sock is not None:
            try:
                self._ipc_sock.close()
            except Exception:
                pass
            self._ipc_sock = None

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
