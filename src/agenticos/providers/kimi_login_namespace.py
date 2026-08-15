"""Minimal in-netns listener handoff followed by exact ``kimi login`` exec."""

from __future__ import annotations

import array
import os
import socket
import sys
from typing import Callable, Final, Mapping, NoReturn


HANDOFF_MARKER: Final = b"AOS_KIMI_AUTH_LISTENER/1\n"
LISTENER_HOST: Final = "127.0.0.1"
LISTENER_PORT: Final = 18080
KIMI_EXECUTABLE: Final = "/opt/agenticos/kimi/bin/kimi"
_EXACT_ENVIRONMENT: Final = {
    "HOME": "/home/aos",
    "KIMI_CODE_HOME": "/home/aos/kimi",
    "KIMI_CODE_NO_AUTO_UPDATE": "1",
    "KIMI_DISABLE_CRON": "1",
    "KIMI_DISABLE_TELEMETRY": "1",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/opt/agenticos/kimi/bin:/usr/bin",
    "PWD": "/workspace",
    "TMPDIR": "/tmp",
    "https_proxy": "http://127.0.0.1:18080",
}


class NamespaceLauncherError(RuntimeError):
    pass


def send_listener_fd(channel: socket.socket, listener: socket.socket) -> None:
    """Transfer exactly one accepting loopback listener to the outer relay."""

    if not isinstance(channel, socket.socket) or not isinstance(listener, socket.socket):
        raise NamespaceLauncherError("socket arguments required")
    if listener.family != socket.AF_INET or listener.type & 0xF != socket.SOCK_STREAM:
        raise NamespaceLauncherError("listener type rejected")
    if listener.getsockname() != (LISTENER_HOST, LISTENER_PORT):
        raise NamespaceLauncherError("listener address rejected")
    if listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1:
        raise NamespaceLauncherError("listener is not accepting")
    rights = array.array("i", [listener.fileno()])
    sent = channel.sendmsg(
        [HANDOFF_MARKER],
        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())],
    )
    if sent != len(HANDOFF_MARKER):
        raise NamespaceLauncherError("listener handoff truncated")


def exec_official_login(
    environment: Mapping[str, str],
    *,
    execve: Callable[[str, list[str], dict[str, str]], NoReturn] = os.execve,
) -> NoReturn:
    """Execute the only command this launcher can represent."""

    if dict(environment) != _EXACT_ENVIRONMENT:
        raise NamespaceLauncherError("login environment drift")
    execve(KIMI_EXECUTABLE, ["kimi-code", "login"], dict(environment))
    raise NamespaceLauncherError("execve returned")


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1 or not arguments[0].isdigit():
        raise NamespaceLauncherError("one handoff descriptor is required")
    handoff_fd = int(arguments[0])
    if handoff_fd < 3 or any(not os.isatty(fd) for fd in (0, 1, 2)):
        raise NamespaceLauncherError("interactive terminal and handoff required")
    channel = socket.socket(fileno=handoff_fd)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((LISTENER_HOST, LISTENER_PORT))
        listener.listen(4)
        send_listener_fd(channel, listener)
    finally:
        listener.close()
        channel.close()
    exec_official_login(dict(os.environ))


if __name__ == "__main__":
    raise SystemExit(main())
