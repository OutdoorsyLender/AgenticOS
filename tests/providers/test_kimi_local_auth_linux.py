"""Native Linux boundary tests for Kimi Level-1 local authentication."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import ctypes
import errno
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import textwrap

import pytest

try:
    import fcntl
except ModuleNotFoundError:  # pragma: no cover - Windows collection guard
    fcntl = None  # type: ignore[assignment]

import agenticos.providers.kimi_local_auth_runtime as local_auth_runtime
from agenticos.providers.kimi_local_auth_namespace import (
    NamespaceLauncherError,
    _no_inet_filter_instructions,
    assert_mount_identity,
    exec_official_acp,
)
from agenticos.providers.kimi_local_auth_runtime import (
    CredentialLeafHandle,
    KimiLocalAuthSpec,
    KimiLocalAuthRuntimeError,
    build_local_auth_bwrap_argv,
    open_validated_credential_leaf,
)


ROOT = Path(__file__).resolve().parents[2]
BWRAP = Path("/usr/bin/bwrap")
PINNED_RUNTIME = Path(
    "/home/brand/.local/share/agenticos/provider-qualification/"
    "kimi-code/0.36.1/runtime/bin/kimi"
)
QUALIFIED_BUNDLE = ROOT / "qualification" / "kimi-code" / "0.36.1"
LAUNCHER = ROOT / "src" / "agenticos" / "providers" / "kimi_local_auth_namespace.py"
SANDBOX_LAUNCHER = "/opt/agenticos/kimi/local_auth_namespace.py"
SYNTHETIC_CREDENTIAL_BYTES = b'{"access_token":"synthetic-kernel-canary"}\n'


pytestmark = pytest.mark.skipif(
    os.name != "posix" or not BWRAP.exists(),
    reason="native Linux Bubblewrap required",
)


@pytest.fixture(autouse=True)
def _admit_checked_out_qualified_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_auth_runtime,
        "_CANONICAL_LOCAL_AUTH_BUNDLE",
        QUALIFIED_BUNDLE,
    )


def _spec(tmp_path: Path) -> KimiLocalAuthSpec:
    state_root = tmp_path / "state"
    credential_root = state_root / "credentials"
    credential_root.mkdir(parents=True, mode=0o700)
    state_root.chmod(0o700)
    credential_root.chmod(0o700)
    leaf = credential_root / "kimi-code.json"
    leaf.write_bytes(SYNTHETIC_CREDENTIAL_BYTES)
    leaf.chmod(0o600)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir(mode=0o700)
    return KimiLocalAuthSpec(
        executable=PINNED_RUNTIME,
        bundle=QUALIFIED_BUNDLE,
        namespace_launcher=LAUNCHER,
        state_root=state_root.resolve(),
        evidence_root=evidence_root.resolve(),
    )


@contextmanager
def _local_auth_vector(
    tmp_path: Path,
) -> Iterator[tuple[KimiLocalAuthSpec, CredentialLeafHandle, list[str]]]:
    spec = _spec(tmp_path)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        descriptor_flags = fcntl.fcntl(credential.descriptor, fcntl.F_GETFD)
        assert descriptor_flags & fcntl.FD_CLOEXEC == fcntl.FD_CLOEXEC
        yield spec, credential, build_local_auth_bwrap_argv(spec, credential)
    finally:
        credential.close()


def _replace_command(argv: list[str], script: str) -> list[str]:
    separator = argv.index("--")
    return [*argv[:separator], "--", "/usr/bin/python3", "-c", script]


def _load_launcher_script(
    body: str,
    *,
    launcher: str = SANDBOX_LAUNCHER,
) -> str:
    loader = textwrap.dedent(
        f"""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "aos_local_auth_namespace", {launcher!r}
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        """
    )
    return loader + textwrap.dedent(body)


def test_native_mount_is_exact_inode_read_only_and_consumes_credential_fd(
    tmp_path: Path,
) -> None:
    with _local_auth_vector(tmp_path) as (spec, credential, argv):
        host_leaf = spec.state_root / "credentials" / "kimi-code.json"
        host_info = host_leaf.lstat()
        script = _load_launcher_script(
            f"""
            import json
            import os
            import socket
            module.assert_mount_identity({host_info.st_dev}, {host_info.st_ino})
            module.assert_no_inherited_descriptors()
            sibling_errno = None
            try:
                with open('/home/aos/kimi/credentials/sibling', 'xb'):
                    pass
            except OSError as exc:
                sibling_errno = exc.errno
            leaf = os.lstat('/home/aos/kimi/credentials/kimi-code.json')
            route_lines = open('/proc/net/route', encoding='ascii').read().splitlines()[1:]
            tcp_rows = open('/proc/net/tcp', encoding='ascii').read().splitlines()[1:]
            tcp6_rows = open('/proc/net/tcp6', encoding='ascii').read().splitlines()[1:]
            udp_rows = open('/proc/net/udp', encoding='ascii').read().splitlines()[1:]
            udp6_rows = open('/proc/net/udp6', encoding='ascii').read().splitlines()[1:]
            module.install_no_inet_seccomp()
            status = {{
                line.split(':', 1)[0]: line.split(':', 1)[1].strip()
                for line in open('/proc/self/status', encoding='ascii')
                if line.startswith(('NoNewPrivs:', 'Seccomp:'))
            }}
            unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            unix_socket.close()
            print(json.dumps({{
                'device': leaf.st_dev,
                'inode': leaf.st_ino,
                'entries': os.listdir('/home/aos/kimi/credentials'),
                'sibling_errno': sibling_errno,
                'environment': dict(os.environ),
                'proxy_names': sorted(
                    name for name in os.environ if 'proxy' in name.casefold()
                ),
                'etc_exists': os.path.exists('/etc'),
                'resolver_exists': os.path.exists('/etc/resolv.conf'),
                'hosts_exists': os.path.exists('/etc/hosts'),
                'host_home_exists': os.path.exists('/home/brand'),
                'windows_mount_exists': os.path.exists('/mnt/c'),
                'workspace_entries': os.listdir('/workspace'),
                'default_route_present': any(
                    line.split()[1] == '00000000' for line in route_lines if line.split()
                ),
                'tcp_rows': tcp_rows,
                'tcp6_rows': tcp6_rows,
                'udp_rows': udp_rows,
                'udp6_rows': udp6_rows,
                'no_new_privs': status['NoNewPrivs'],
                'seccomp_mode': status['Seccomp'],
                'unix_socket_allowed': True,
            }}, sort_keys=True))
            """
        )
        completed = subprocess.run(
            _replace_command(argv, script),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env={},
            close_fds=True,
            pass_fds=(credential.descriptor,),
            check=False,
            timeout=15,
        )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert completed.stderr == b""
    report = json.loads(completed.stdout)
    assert (report["device"], report["inode"]) == (
        host_info.st_dev,
        host_info.st_ino,
    )
    assert report["entries"] == ["kimi-code.json"]
    assert report["sibling_errno"] == errno.EROFS
    assert report["environment"] == {
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
    }
    assert report["proxy_names"] == []
    assert report["etc_exists"] is False
    assert report["resolver_exists"] is False
    assert report["hosts_exists"] is False
    assert report["host_home_exists"] is False
    assert report["windows_mount_exists"] is False
    assert report["workspace_entries"] == []
    assert report["default_route_present"] is False
    assert report["tcp_rows"] == []
    assert report["tcp6_rows"] == []
    assert report["udp_rows"] == []
    assert report["udp6_rows"] == []
    assert report["no_new_privs"] == "1"
    assert report["seccomp_mode"] == "2"
    assert report["unix_socket_allowed"] is True


def test_mount_guard_rejects_wrong_inode_mode_and_link_count(tmp_path: Path) -> None:
    leaf = tmp_path / "kimi-code.json"
    leaf.write_bytes(SYNTHETIC_CREDENTIAL_BYTES)
    leaf.chmod(0o600)
    info = leaf.lstat()
    assert_mount_identity(info.st_dev, info.st_ino, leaf=leaf)

    with pytest.raises(NamespaceLauncherError, match="CREDENTIAL_MOUNT_IDENTITY"):
        assert_mount_identity(info.st_dev, info.st_ino + 1, leaf=leaf)

    leaf.chmod(0o640)
    with pytest.raises(NamespaceLauncherError, match="CREDENTIAL_MOUNT_IDENTITY"):
        assert_mount_identity(info.st_dev, info.st_ino, leaf=leaf)

    leaf.chmod(0o600)
    os.link(leaf, tmp_path / "credential-hardlink")
    with pytest.raises(NamespaceLauncherError, match="CREDENTIAL_MOUNT_IDENTITY"):
        assert_mount_identity(info.st_dev, info.st_ino, leaf=leaf)


def test_bwrap_builder_rejects_descriptor_without_cloexec(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        flags = fcntl.fcntl(credential.descriptor, fcntl.F_GETFD)
        fcntl.fcntl(
            credential.descriptor,
            fcntl.F_SETFD,
            flags & ~fcntl.FD_CLOEXEC,
        )
        with pytest.raises(KimiLocalAuthRuntimeError, match="CREDENTIAL_HANDLE_INVALID"):
            build_local_auth_bwrap_argv(spec, credential)
    finally:
        credential.close()


def test_descriptor_guard_rejects_a_real_inherited_descriptor() -> None:
    inherited, peer = os.pipe()
    try:
        script = _load_launcher_script(
            "module.assert_no_inherited_descriptors()",
            launcher=str(LAUNCHER),
        )
        completed = subprocess.run(
            [sys.executable, "-c", script],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env={},
            close_fds=True,
            pass_fds=(inherited,),
            check=False,
            timeout=10,
        )
    finally:
        os.close(inherited)
        os.close(peer)
    assert completed.returncode != 0
    assert b"INHERITED_DESCRIPTOR" in completed.stderr


def test_seccomp_filter_has_literal_x86_64_kill_and_checked_jump_targets() -> None:
    instructions = _no_inet_filter_instructions()
    assert instructions == (
        (0x20, 0, 0, 4),
        (0x15, 1, 0, 0xC000003E),
        (0x06, 0, 0, 0x80000000),
        (0x20, 0, 0, 0),
        (0x15, 0, 3, 41),
        (0x20, 0, 0, 16),
        (0x15, 2, 0, 2),
        (0x15, 1, 0, 10),
        (0x06, 0, 0, 0x7FFF0000),
        (0x06, 0, 0, 0x00030000),
    )
    assert 1 + 1 + instructions[1][1] == 3
    assert 1 + 1 + instructions[1][2] == 2
    assert 4 + 1 + instructions[4][2] == 8
    assert 6 + 1 + instructions[6][1] == 9
    assert 7 + 1 + instructions[7][1] == 9


@pytest.mark.parametrize("family", [socket.AF_INET, socket.AF_INET6])
def test_seccomp_traps_real_inet_socket_syscalls_with_sigsys(family: int) -> None:
    script = (
        "from agenticos.providers.kimi_local_auth_namespace import "
        "install_no_inet_seccomp; import socket; "
        f"install_no_inet_seccomp(); socket.socket({family}, socket.SOCK_STREAM)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env={"PYTHONPATH": str(ROOT / "src"), "LANG": "C.UTF-8"},
        close_fds=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == -signal.SIGSYS
    assert completed.stdout == b""
    assert completed.stderr == b""


def test_exec_guard_allows_only_exact_official_acp_vector_and_environment() -> None:
    environment = {
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
    }
    observed: list[tuple[str, list[str], dict[str, str]]] = []

    def stop_exec(path: str, argv: list[str], env: dict[str, str]) -> None:
        observed.append((path, argv, env))
        raise RuntimeError("synthetic exec stop")

    with pytest.raises(RuntimeError, match="synthetic exec stop"):
        exec_official_acp(environment, execve=stop_exec)
    assert observed == [
        (
            "/opt/agenticos/kimi/bin/kimi",
            ["kimi-code", "acp"],
            environment,
        )
    ]

    with pytest.raises(NamespaceLauncherError, match="ACP_ENVIRONMENT_DRIFT"):
        exec_official_acp(
            {**environment, "HTTPS_PROXY": "http://ambient-proxy.invalid"},
            execve=stop_exec,
        )
