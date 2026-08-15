"""Synthetic netns client for the owner-login listener handoff test."""

from __future__ import annotations

import array
import json
import os
import socket
import sys


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].isdigit():
        return 2
    channel = socket.socket(fileno=int(sys.argv[1]))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 18080))
        listener.listen(1)
        rights = array.array("i", [listener.fileno()])
        marker = b"AOS_KIMI_AUTH_LISTENER/1\n"
        if channel.sendmsg(
            [marker], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())]
        ) != len(marker):
            return 3
    finally:
        listener.close()
        channel.close()
    probe = socket.create_connection(("127.0.0.1", 18080), timeout=3)
    try:
        probe.sendall(
            b"CONNECT api.kimi.com:443 HTTP/1.1\r\n"
            b"Host: api.kimi.com:443\r\n\r\n"
        )
        response = probe.recv(128)
    finally:
        probe.close()
    print(
        json.dumps(
            {
                "schema": "AOS_KIMI_LOGIN_NAMESPACE_FIXTURE/1",
                "api_denied": response.startswith(b"HTTP/1.1 403"),
                "net_namespace": os.readlink("/proc/self/ns/net"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )
    return 0 if response.startswith(b"HTTP/1.1 403") else 4


if __name__ == "__main__":
    raise SystemExit(main())
