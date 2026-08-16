#!/usr/bin/python3
"""Hermetic netns client for the synthetic Kimi post-auth fixture."""

from __future__ import annotations

import array
import os
from pathlib import Path
import socket
import struct
import sys


LISTENER_MARKER = b"AOS_KIMI_AUTH_LISTENER/1\n"
CREDENTIAL_ROOT = Path("/home/aos/kimi/credentials")


def _extension(identifier: int, payload: bytes) -> bytes:
    return struct.pack(">HH", identifier, len(payload)) + payload


def _client_hello() -> bytes:
    hostname = b"auth.kimi.com"
    server_name = b"\x00" + struct.pack(">H", len(hostname)) + hostname
    extensions = b"".join(
        (
            _extension(0, struct.pack(">H", len(server_name)) + server_name),
            _extension(10, b"\x00\x02\x00\x1d"),
            _extension(11, b"\x01\x00"),
            _extension(13, b"\x00\x02\x04\x03"),
            _extension(16, b"\x00\x09\x08http/1.1"),
            _extension(43, b"\x04\x03\x04\x03\x03"),
            _extension(45, b"\x01\x01"),
            _extension(51, b"\x00\x24\x00\x1d\x00\x20" + b"K" * 32),
        )
    )
    body = (
        b"\x03\x03"
        + b"C" * 32
        + b"\x00"
        + b"\x00\x08\x13\x01\x13\x02\xc0\x2f\xc0\x30"
        + b"\x01\x00"
        + struct.pack(">H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return _tls_record(22, handshake)


def _tls_record(content_type: int, payload: bytes) -> bytes:
    return bytes((content_type, 3, 3)) + len(payload).to_bytes(2, "big") + payload


def _recv_exact(stream: socket.socket, size: int) -> bytes:
    received = bytearray()
    while len(received) < size:
        chunk = stream.recv(size - len(received))
        if not chunk:
            raise RuntimeError("synthetic relay closed early")
        received.extend(chunk)
    return bytes(received)


def _recv_record(stream: socket.socket) -> bytes:
    head = _recv_exact(stream, 5)
    return head + _recv_exact(stream, int.from_bytes(head[3:5], "big"))


def _send_listener(channel: socket.socket, listener: socket.socket) -> None:
    rights = array.array("i", [listener.fileno()])
    sent = channel.sendmsg(
        [LISTENER_MARKER],
        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())],
    )
    if sent != len(LISTENER_MARKER):
        raise RuntimeError("listener handoff was incomplete")


def _write_synthetic_credential() -> None:
    target = CREDENTIAL_ROOT / "kimi-code.json"
    temporary = CREDENTIAL_ROOT / f"kimi-code.json.tmp.{os.getpid()}.abcdef12"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.write(descriptor, b'{"synthetic_fixture":true}\n')
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, target)


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].isdigit():
        return 2
    channel = socket.socket(fileno=int(sys.argv[1]))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 18080))
        listener.listen(1)
        _send_listener(channel, listener)
    finally:
        listener.close()
        channel.close()

    proxy = socket.create_connection(("127.0.0.1", 18080), timeout=5)
    proxy.settimeout(5)
    try:
        proxy.sendall(
            b"CONNECT auth.kimi.com:443 HTTP/1.1\r\n"
            b"Host: auth.kimi.com:443\r\n\r\n"
        )
        if _recv_exact(proxy, 39) != b"HTTP/1.1 200 Connection Established\r\n\r\n":
            return 3
        proxy.sendall(_client_hello())
        if _recv_record(proxy)[0] != 22:
            return 4
        for request in (
            b"synthetic-device-authorization",
            b"synthetic-poll-pending-1",
            b"synthetic-poll-pending-2",
            b"synthetic-poll-complete",
        ):
            proxy.sendall(_tls_record(23, request))
            if _recv_record(proxy)[0] != 23:
                return 5
        _write_synthetic_credential()
        proxy.shutdown(socket.SHUT_WR)
        while proxy.recv(4096):
            pass
    finally:
        proxy.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
