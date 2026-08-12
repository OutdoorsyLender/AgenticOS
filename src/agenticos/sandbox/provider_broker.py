"""Task-scoped provider proxy broker implementing strict HTTP/SSE request and response boundaries."""

from __future__ import annotations

import os
import socket
import select
import time
import uuid
import threading
from typing import Callable, Tuple

from .provider_models import (
    NetworkAuthority,
    ProviderAuthCapability,
    ProviderAuthBindingError,
    ProviderBrokerEvidence,
    ProviderBrokerIdentity,
    ProviderBrokerPolicy,
    ProviderFailureClass,
    ProviderGrant,
    SecretValue,
    SubscriptionAuthCapability,
    provider_policy_digest,
)

_CLIENT_ALLOWED_HEADERS = {
    "host",
    "accept",
    "content-type",
    "user-agent",
    "originator",
    "session_id",
    "x-client-request-id",
    "x-codex-window-id",
    "x-codex-turn-metadata",
    "content-length",
}


class _AtomicCapabilitySlot:
    """Linearize capability validation, injection, replacement, and cancellation."""

    def __init__(
        self, policy: ProviderBrokerPolicy, capability: ProviderAuthCapability
    ) -> None:
        if not isinstance(policy, ProviderBrokerPolicy):
            raise TypeError("policy must be a ProviderBrokerPolicy instance")
        if not isinstance(capability, ProviderAuthCapability):
            raise TypeError("capability must be a ProviderAuthCapability instance")
        capability.validate_for_policy(policy)
        self._lock = threading.RLock()
        self._capability: ProviderAuthCapability | None = capability
        self._active = True
        if isinstance(capability, SubscriptionAuthCapability):
            self._sequence: int | None = capability.binding.capability_sequence
            self._helper_epoch: str | None = capability.binding.helper_epoch
        else:
            self._sequence = None
            self._helper_epoch = None

    def replace(
        self,
        candidate: ProviderAuthCapability,
        *,
        policy: ProviderBrokerPolicy,
        expected_sequence: int,
    ) -> None:
        """Atomically replace the current subscription capability by sequence CAS."""
        if not isinstance(candidate, ProviderAuthCapability):
            raise TypeError("candidate must be a ProviderAuthCapability instance")
        with self._lock:
            if not self._active or self._capability is None:
                raise ProviderAuthBindingError("PROVIDER_AUTH_CANCELLED")
            if not isinstance(candidate, SubscriptionAuthCapability):
                raise ProviderAuthBindingError("PROVIDER_AUTH_REPLACEMENT_REJECTED")
            if self._sequence is None or expected_sequence != self._sequence:
                raise ProviderAuthBindingError("PROVIDER_AUTH_SEQUENCE_REJECTED")
            candidate.validate_for_policy(policy)
            binding = candidate.binding
            if binding.helper_epoch != self._helper_epoch:
                raise ProviderAuthBindingError("PROVIDER_AUTH_EPOCH_REJECTED")
            if binding.capability_sequence != self._sequence + 1:
                raise ProviderAuthBindingError("PROVIDER_AUTH_SEQUENCE_REJECTED")
            self._capability = candidate
            self._sequence = binding.capability_sequence

    def cancel(self) -> None:
        """Atomically revoke the slot and clear its credential reference."""
        with self._lock:
            self._active = False
            self._capability = None

    def validate_extract_and_send(
        self,
        *,
        policy: ProviderBrokerPolicy,
        sender: Callable[[SecretValue, dict[str, SecretValue]], None],
    ) -> None:
        """Validate and inject while holding the slot's single synchronization boundary."""
        with self._lock:
            if not self._active or self._capability is None:
                raise ProviderAuthBindingError("PROVIDER_AUTH_CANCELLED")
            capability = self._capability
            capability.validate_for_policy(policy)
            if isinstance(capability, SubscriptionAuthCapability):
                binding = capability.binding
                if binding.helper_epoch != self._helper_epoch:
                    raise ProviderAuthBindingError("PROVIDER_AUTH_EPOCH_REJECTED")
                if binding.capability_sequence != self._sequence:
                    raise ProviderAuthBindingError("PROVIDER_AUTH_SEQUENCE_REJECTED")
            auth_value = capability.get_auth_header(policy.task_id, policy.generation)
            extra_headers = capability.get_extra_headers(policy.task_id, policy.generation)
            sender(auth_value, extra_headers)

_CLIENT_FORBIDDEN_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "x-openai-api-key",
    "x-auth-token",
    "sec-websocket-key",
    "sec-websocket-version",
}

_RESPONSE_ALLOWED_HEADERS = {
    "content-type",
    "cache-control",
}


def _get_boot_id() -> str:
    """Return Linux boot ID or a deterministic fallback UUID if unavailable."""
    try:
        if os.path.exists("/proc/sys/kernel/random/boot_id"):
            with open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii") as f:
                val = f.read().strip()
                if len(val) == 36 and val.count("-") == 4:
                    return val
    except Exception:
        pass
    # Fallback to a fixed deterministic boot ID format for Windows/fixtures
    return "00000000-0000-0000-0000-000000000000"


class TaskProviderBroker:
    """Task-scoped provider proxy broker server enforcing strict security boundaries."""

    def __init__(
        self,
        policy: ProviderBrokerPolicy,
        auth_capability: ProviderAuthCapability,
        *,
        bind_address: str = "127.0.0.1",
    ) -> None:
        if not isinstance(policy, ProviderBrokerPolicy):
            raise TypeError("policy must be a ProviderBrokerPolicy instance")
        if not isinstance(auth_capability, ProviderAuthCapability):
            raise TypeError("auth_capability must be a ProviderAuthCapability instance")

        self._policy = policy
        self._auth_slot = _AtomicCapabilitySlot(policy, auth_capability)
        self._bind_address = bind_address
        self._policy_digest = provider_policy_digest(policy)

        self._broker_id = f"provbroker-{uuid.uuid4().hex[:16]}"
        self._identity = ProviderBrokerIdentity(
            broker_id=self._broker_id,
            pid=os.getpid(),
            start_time_ticks=1000,
            boot_id=_get_boot_id(),
        )

        self._server_socket: socket.socket | None = None
        self._listener_port: int = 0
        self._server_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

        self._started_at_ns: int = 0
        self._ended_at_ns: int = 0
        self._client_connection_count: int = 0
        self._request_byte_count: int = 0
        self._response_byte_count: int = 0
        self._response_event_count: int = 0
        self._upstream_status: int | None = None
        self._terminal_failure_class: ProviderFailureClass | None = None
        self._cancellation_state: bool = False
        self._active_client_sock: socket.socket | None = None
        self._active_upstream_sock: socket.socket | None = None
        self._lock = threading.Lock()

    @property
    def identity(self) -> ProviderBrokerIdentity:
        return self._identity

    @property
    def policy(self) -> ProviderBrokerPolicy:
        return self._policy

    @property
    def policy_digest(self) -> str:
        return self._policy_digest

    @property
    def grant(self) -> ProviderGrant:
        if self._listener_port == 0:
            raise RuntimeError("Broker is not started")
        return ProviderGrant(
            task_id=self._policy.task_id,
            generation=self._policy.generation,
            attempt_id=self._policy.attempt_id,
            launch_nonce=self._policy.launch_nonce,
            policy_digest=self._policy_digest,
            listener_address=self._bind_address,
            listener_port=self._listener_port,
        )

    def start(self) -> ProviderGrant:
        """Start the task-scoped loopback listener socket and server thread."""
        with self._lock:
            if self._server_socket is not None:
                raise RuntimeError("Broker is already running")

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self._bind_address, 0))
            sock.listen(self._policy.max_connections)
            sock.settimeout(0.5)

            self._server_socket = sock
            self._listener_port = sock.getsockname()[1]
            self._started_at_ns = time.monotonic_ns()

            self._server_thread = threading.Thread(
                target=self._run_server, name=f"ProvBroker-{self._policy.task_id}", daemon=True
            )
            self._server_thread.start()

            return self.grant

    def replace_auth_capability(
        self,
        candidate: ProviderAuthCapability,
        *,
        expected_sequence: int,
    ) -> None:
        """Atomically install the next capability for this broker policy."""
        self._auth_slot.replace(
            candidate,
            policy=self._policy,
            expected_sequence=expected_sequence,
        )

    def cancel_auth_capability(self) -> None:
        """Atomically revoke the broker's current provider credential."""
        self._auth_slot.cancel()

    def stop(self) -> None:
        """Revoke capability, close active connections, and terminate broker thread."""
        self._auth_slot.cancel()
        with self._lock:
            self._cancellation_state = True
            if self._terminal_failure_class is None:
                self._terminal_failure_class = ProviderFailureClass.PROVIDER_CANCELLED
            self._stop_event.set()

            if self._active_client_sock is not None:
                try:
                    self._active_client_sock.close()
                except Exception:
                    pass
            if self._active_upstream_sock is not None:
                try:
                    self._active_upstream_sock.close()
                except Exception:
                    pass
            if self._server_socket is not None:
                try:
                    self._server_socket.close()
                except Exception:
                    pass

        if self._server_thread is not None and self._server_thread.is_alive():
            self._server_thread.join(timeout=2.0)

        if self._ended_at_ns == 0:
            self._ended_at_ns = time.monotonic_ns()

    def get_evidence(self) -> ProviderBrokerEvidence:
        """Return the immutable ProviderBrokerEvidence snapshot for this run."""
        ended = self._ended_at_ns if self._ended_at_ns > 0 else time.monotonic_ns()
        started = self._started_at_ns if self._started_at_ns > 0 else ended
        if ended < started:
            ended = started

        return ProviderBrokerEvidence(
            task_id=self._policy.task_id,
            generation=self._policy.generation,
            attempt_id=self._policy.attempt_id,
            policy_digest=self._policy_digest,
            broker_identity=self._identity,
            upstream_identity=f"{self._policy.upstream_scheme}://{self._policy.upstream_host}:{self._policy.upstream_port}",
            protocol=self._policy.protocol_type,
            client_connection_count=self._client_connection_count,
            request_byte_count=self._request_byte_count,
            response_byte_count=self._response_byte_count,
            response_event_count=self._response_event_count,
            upstream_status=self._upstream_status,
            started_at_monotonic_ns=started,
            ended_at_monotonic_ns=ended,
            terminal_failure_class=self._terminal_failure_class,
            cancellation_state=self._cancellation_state,
            canary_exposure_status="CLEAN_NO_EXPOSURE",
        )

    def _run_server(self) -> None:
        """Server main loop accepting task-local client connections."""
        while not self._stop_event.is_set():
            try:
                if self._server_socket is None:
                    break
                client_sock, addr = self._server_socket.accept()
            except (socket.timeout, BlockingIOError):
                continue
            except OSError:
                break

            with self._lock:
                self._client_connection_count += 1
                if self._active_client_sock is not None:
                    # Enforce concurrent connection limit fail-closed
                    self._send_error_and_close(
                        client_sock, 429, "Too Many Connections", ProviderFailureClass.PROVIDER_POLICY_REJECTED
                    )
                    continue
                self._active_client_sock = client_sock

            try:
                self._handle_client_connection(client_sock)
            except Exception as exc:
                with self._lock:
                    if self._terminal_failure_class is None:
                        self._terminal_failure_class = ProviderFailureClass.PROVIDER_CLIENT_PROTOCOL_ERROR
            finally:
                with self._lock:
                    self._active_client_sock = None
                try:
                    client_sock.close()
                except Exception:
                    pass

        if self._ended_at_ns == 0:
            self._ended_at_ns = time.monotonic_ns()

    def _send_error_and_close(
        self, sock: socket.socket, status_code: int, status_text: str, failure_class: ProviderFailureClass
    ) -> None:
        """Send a standard HTTP error response to the client socket and record failure."""
        with self._lock:
            if self._terminal_failure_class is None:
                self._terminal_failure_class = failure_class
        try:
            resp = f"HTTP/1.1 {status_code} {status_text}\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: {len(status_text)}\r\n\r\n{status_text}".encode("utf-8")
            sock.sendall(resp)
        except Exception:
            pass

    def _handle_client_connection(self, client_sock: socket.socket) -> None:
        """Validate request envelope, forward to upstream with synthetic auth, and relay response."""
        client_sock.settimeout(self._policy.idle_timeout_seconds)

        # 1. Read HTTP request line and headers
        headers_raw, rest_body = self._read_headers(client_sock)
        if headers_raw is None:
            return

        lines = headers_raw.decode("ascii", errors="replace").split("\r\n")
        if not lines or not lines[0]:
            self._send_error_and_close(client_sock, 400, "Bad Request", ProviderFailureClass.PROVIDER_CLIENT_PROTOCOL_ERROR)
            return

        request_line = lines[0].strip().split(" ")
        if len(request_line) != 3:
            self._send_error_and_close(client_sock, 400, "Bad Request", ProviderFailureClass.PROVIDER_CLIENT_PROTOCOL_ERROR)
            return

        method, req_path, http_version = request_line[0], request_line[1], request_line[2]

        # Validate HTTP Method
        if method.upper() != "POST":
            self._send_error_and_close(
                client_sock, 405, "Method Not Allowed", ProviderFailureClass.PROVIDER_POLICY_REJECTED
            )
            return

        # Validate Path
        if req_path.startswith("http://") or req_path.startswith("https://"):
            # Reject absolute-form proxy URLs (destination injection attempt)
            self._send_error_and_close(
                client_sock, 400, "Absolute Proxy URLs Disallowed", ProviderFailureClass.PROVIDER_POLICY_REJECTED
            )
            return

        if req_path not in self._policy.allowed_paths:
            self._send_error_and_close(
                client_sock, 404, "Path Not Allowed", ProviderFailureClass.PROVIDER_POLICY_REJECTED
            )
            return

        # Parse client headers
        parsed_headers: list[Tuple[str, str]] = []
        header_count = 0
        content_length: int | None = None
        is_chunked = False
        has_upgrade = False

        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                self._send_error_and_close(client_sock, 400, "Malformed Header", ProviderFailureClass.PROVIDER_CLIENT_PROTOCOL_ERROR)
                return
            header_count += 1
            if header_count > self._policy.max_header_count:
                self._send_error_and_close(
                    client_sock, 400, "Header Count Exceeded", ProviderFailureClass.PROVIDER_POLICY_REJECTED
                )
                return

            name, value = line.split(":", 1)
            name_lower = name.strip().lower()
            val_strip = value.strip()

            # Fail closed on forbidden / credential headers supplied by client
            if name_lower in _CLIENT_FORBIDDEN_HEADERS:
                self._send_error_and_close(
                    client_sock, 400, "Credential Header Disallowed", ProviderFailureClass.PROVIDER_POLICY_REJECTED
                )
                return

            if name_lower == "upgrade":
                has_upgrade = True

            if name_lower == "transfer-encoding" and "chunked" in val_strip.lower():
                is_chunked = True

            if name_lower == "content-length":
                try:
                    content_length = int(val_strip)
                except ValueError:
                    self._send_error_and_close(client_sock, 400, "Invalid Content-Length", ProviderFailureClass.PROVIDER_CLIENT_PROTOCOL_ERROR)
                    return

            if name_lower in _CLIENT_ALLOWED_HEADERS and name_lower not in ("host", "content-length"):
                parsed_headers.append((name.strip(), val_strip))

        if has_upgrade:
            self._send_error_and_close(
                client_sock, 400, "WebSocket Upgrade Disallowed", ProviderFailureClass.PROVIDER_POLICY_REJECTED
            )
            return

        if is_chunked and content_length is not None:
            self._send_error_and_close(
                client_sock, 400, "Conflicting Transfer Framing", ProviderFailureClass.PROVIDER_CLIENT_PROTOCOL_ERROR
            )
            return

        if content_length is None and not is_chunked:
            content_length = 0

        if content_length is not None and content_length > self._policy.max_request_bytes:
            self._send_error_and_close(
                client_sock, 413, "Payload Too Large", ProviderFailureClass.PROVIDER_CLIENT_PROTOCOL_ERROR
            )
            return

        # Read body
        body_bytes = bytearray(rest_body)
        if content_length is not None:
            needed = content_length - len(body_bytes)
            while needed > 0:
                chunk = client_sock.recv(min(needed, 65536))
                if not chunk:
                    self._send_error_and_close(client_sock, 400, "Premature EOF in Request Body", ProviderFailureClass.PROVIDER_CLIENT_PROTOCOL_ERROR)
                    return
                body_bytes.extend(chunk)
                needed -= len(chunk)

        with self._lock:
            self._request_byte_count += len(headers_raw) + len(body_bytes)

        # 2. Connect to locked upstream destination without credential authority.
        try:
            upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream_sock.settimeout(self._policy.idle_timeout_seconds)
            upstream_sock.connect((self._policy.upstream_host, self._policy.upstream_port))
            with self._lock:
                self._active_upstream_sock = upstream_sock
        except Exception as exc:
            self._send_error_and_close(
                client_sock, 502, "Upstream Connect Error", ProviderFailureClass.PROVIDER_UPSTREAM_CONNECT_ERROR
            )
            return

        # 3. Validate, extract, and inject under the capability slot lock.
        try:
            def inject_and_send(
                auth_value: SecretValue,
                extra_headers: dict[str, SecretValue],
            ) -> None:
                req_lines = [f"POST {req_path} HTTP/1.1"]
                req_lines.append(
                    f"Host: {self._policy.upstream_host}:{self._policy.upstream_port}"
                )
                req_lines.append(f"Authorization: {auth_value.reveal_secret()}")
                for header_name, header_secret in extra_headers.items():
                    req_lines.append(f"{header_name}: {header_secret.reveal_secret()}")
                req_lines.append(f"Content-Length: {len(body_bytes)}")
                req_lines.append("Connection: close")
                for name, value in parsed_headers:
                    req_lines.append(f"{name}: {value}")
                upstream_request = (
                    "\r\n".join(req_lines).encode("utf-8")
                    + b"\r\n\r\n"
                    + bytes(body_bytes)
                )
                upstream_sock.sendall(upstream_request)

            self._auth_slot.validate_extract_and_send(
                policy=self._policy,
                sender=inject_and_send,
            )
        except ProviderAuthBindingError:
            with self._lock:
                self._active_upstream_sock = None
            try:
                upstream_sock.close()
            except Exception:
                pass
            self._send_error_and_close(
                client_sock,
                500,
                "Auth Unavailable",
                ProviderFailureClass.PROVIDER_AUTH_UNAVAILABLE,
            )
            return
        except Exception:
            with self._lock:
                self._active_upstream_sock = None
            try:
                upstream_sock.close()
            except Exception:
                pass
            self._send_error_and_close(
                client_sock, 502, "Upstream Send Error", ProviderFailureClass.PROVIDER_UPSTREAM_CONNECT_ERROR
            )
            return

        # 4. Read upstream response
        try:
            resp_headers_raw, resp_rest = self._read_headers(upstream_sock)
            if resp_headers_raw is None:
                self._send_error_and_close(
                    client_sock, 502, "Upstream Protocol Error", ProviderFailureClass.PROVIDER_UPSTREAM_PROTOCOL_ERROR
                )
                return

            resp_lines = resp_headers_raw.decode("ascii", errors="replace").split("\r\n")
            status_line = resp_lines[0].strip().split(" ")
            if len(status_line) < 2:
                self._send_error_and_close(
                    client_sock, 502, "Upstream Protocol Error", ProviderFailureClass.PROVIDER_UPSTREAM_PROTOCOL_ERROR
                )
                return

            upstream_status = int(status_line[1])
            with self._lock:
                self._upstream_status = upstream_status

            # Fail closed on upstream redirect (3xx)
            if 300 <= upstream_status <= 399:
                self._send_error_and_close(
                    client_sock, 502, "Upstream Redirect Disallowed", ProviderFailureClass.PROVIDER_UPSTREAM_PROTOCOL_ERROR
                )
                return

            # Parse and filter response headers
            forward_headers: list[Tuple[str, str]] = []
            for hline in resp_lines[1:]:
                if not hline or ":" not in hline:
                    continue
                hname, hval = hline.split(":", 1)
                hname_clean = hname.strip()
                if hname_clean.lower() in _RESPONSE_ALLOWED_HEADERS:
                    forward_headers.append((hname_clean, hval.strip()))

            # Send client response header
            resp_header_lines = [f"HTTP/1.1 {upstream_status} OK"]
            for hname, hval in forward_headers:
                resp_header_lines.append(f"{hname}: {hval}")
            resp_header_lines.append("Connection: close")
            client_resp_headers = "\r\n".join(resp_header_lines).encode("utf-8") + b"\r\n\r\n"
            client_sock.sendall(client_resp_headers)

            # Relay SSE body stream with byte and event bounds
            total_resp_bytes = len(resp_rest)
            client_sock.sendall(resp_rest)

            sse_buffer = bytearray(resp_rest)
            event_count = 0
            start_time = time.monotonic()

            def process_sse_buffer(buf: bytearray) -> Tuple[bytearray, int]:
                count = 0
                while b"\n\n" in buf or b"\r\n\r\n" in buf:
                    sep = b"\n\n" if b"\n\n" in buf else b"\r\n\r\n"
                    part, sep_found, remainder = buf.partition(sep)
                    if len(part) > self._policy.max_event_bytes:
                        with self._lock:
                            self._terminal_failure_class = ProviderFailureClass.PROVIDER_EVENT_TOO_LARGE
                        break
                    count += 1
                    buf = bytearray(remainder)
                return buf, count

            sse_buffer, added_events = process_sse_buffer(sse_buffer)
            event_count += added_events

            while True:
                if time.monotonic() - start_time > self._policy.total_lifetime_seconds:
                    with self._lock:
                        self._terminal_failure_class = ProviderFailureClass.PROVIDER_TOTAL_TIMEOUT
                    break

                try:
                    chunk = upstream_sock.recv(65536)
                except socket.timeout:
                    with self._lock:
                        self._terminal_failure_class = ProviderFailureClass.PROVIDER_IDLE_TIMEOUT
                    break
                except OSError:
                    break

                if not chunk:
                    break

                total_resp_bytes += len(chunk)
                if total_resp_bytes > self._policy.max_response_bytes:
                    with self._lock:
                        self._terminal_failure_class = ProviderFailureClass.PROVIDER_RESPONSE_TOO_LARGE
                    break

                client_sock.sendall(chunk)
                sse_buffer.extend(chunk)
                sse_buffer, added_events = process_sse_buffer(sse_buffer)
                event_count += added_events

            with self._lock:
                self._response_byte_count += total_resp_bytes
                self._response_event_count += event_count

        finally:
            with self._lock:
                self._active_upstream_sock = None
            try:
                upstream_sock.close()
            except Exception:
                pass

    def _read_headers(self, sock: socket.socket) -> Tuple[bytes | None, bytes]:
        """Read socket until HTTP double CRLF header delimiter."""
        buf = bytearray()
        start_time = time.monotonic()
        while b"\r\n\r\n" not in buf:
            if time.monotonic() - start_time > self._policy.idle_timeout_seconds:
                return None, b""
            if len(buf) > self._policy.max_header_bytes:
                return None, b""
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    return None, b""
                buf.extend(chunk)
            except (socket.timeout, OSError):
                return None, b""

        header_part, _, body_part = buf.partition(b"\r\n\r\n")
        return bytes(header_part), bytes(body_part)


__all__ = [
    "TaskProviderBroker",
]
