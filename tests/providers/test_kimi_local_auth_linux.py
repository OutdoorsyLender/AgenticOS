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
import tempfile
import textwrap
import time

import pytest

try:
    import fcntl
except ModuleNotFoundError:  # pragma: no cover - Windows collection guard
    fcntl = None  # type: ignore[assignment]

if os.name != "posix":  # pragma: no cover - Windows collection guard
    pytest.skip("native Linux Bubblewrap required", allow_module_level=True)

import agenticos.providers.kimi_local_auth_runtime as local_auth_runtime
from agenticos.providers.kimi_acp import (
    decode_acp_line,
    validate_kimi_initialize_result,
)
from agenticos.providers.kimi_local_auth import KimiLocalAuthSession
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
from agenticos.providers.kimi_policy import (
    PINNED_EXECUTABLE_SHA256,
    sha256_file,
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
REMEDIATED_LAUNCHER_SHA256 = (
    "800dbc83e1d1dc7efd127151d257025b4160ae92dfc23d13ed175f09778d15dc"
)
EXACT_ENVIRONMENT = {
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
EXPECTED_AGENT_CAPABILITIES = {
    "loadSession": True,
    "promptCapabilities": {
        "image": True,
        "audio": False,
        "embeddedContext": True,
    },
    "sessionCapabilities": {
        "list": {},
        "resume": {},
        "close": {},
        "delete": {},
        "fork": {},
        "additionalDirectories": {},
    },
    "mcpCapabilities": {"http": True, "sse": True},
    "auth": {"logout": {}},
}
EXPECTED_AUTH_METHODS = [
    {
        "id": "login",
        "type": "terminal",
        "name": "Login with Kimi account",
        "description": "Open the device-code login flow in a terminal.",
        "args": ["--login"],
        "env": {"KIMI_CODE_HOME": "/home/aos/kimi"},
        "_meta": {
            "terminal-auth": {
                "type": "terminal",
                "label": "Login with Kimi account",
                "command": "/opt/agenticos/kimi/bin/kimi",
                "args": ["login"],
                "env": {"KIMI_CODE_HOME": "/home/aos/kimi"},
            }
        },
    }
]


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


def _expected_production_bwrap_argv(
    spec: KimiLocalAuthSpec,
    credential: CredentialLeafHandle,
) -> list[str]:
    argv = [
        "/usr/bin/bwrap",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--hostname",
        "agenticos-kimi-local-auth",
        "--clearenv",
        "--tmpfs",
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/lib",
        "/lib",
        "--ro-bind",
        "/lib64",
        "/lib64",
        "--dir",
        "/opt",
        "--dir",
        "/opt/agenticos",
        "--dir",
        "/opt/agenticos/kimi",
        "--dir",
        "/opt/agenticos/kimi/bin",
        "--ro-bind",
        str(spec.executable),
        "/opt/agenticos/kimi/bin/kimi",
        "--ro-bind",
        str(spec.namespace_launcher),
        SANDBOX_LAUNCHER,
        "--dir",
        "/home",
        "--dir",
        "/home/aos",
        "--tmpfs",
        "/home/aos/kimi",
        "--ro-bind",
        str(spec.bundle / "config.toml"),
        "/home/aos/kimi/config.toml",
        "--ro-bind",
        str(spec.bundle / "agents"),
        "/home/aos/kimi/agents",
        "--tmpfs",
        "/home/aos/kimi/credentials",
        "--dir",
        "/home/aos/kimi/credentials",
        "--ro-bind-fd",
        str(credential.descriptor),
        "/home/aos/kimi/credentials/kimi-code.json",
        "--remount-ro",
        "/home/aos/kimi/credentials",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/workspace",
        "--chdir",
        "/workspace",
    ]
    for name, value in EXACT_ENVIRONMENT.items():
        argv.extend(("--setenv", name, value))
    argv.extend(
        (
            "--",
            "/usr/bin/python3",
            SANDBOX_LAUNCHER,
            str(credential.device),
            str(credential.inode),
        )
    )
    return argv


def _read_single_frame(stream: object, timeout: float) -> bytes:
    descriptor = stream.fileno()  # type: ignore[attr-defined]
    deadline = time.monotonic() + timeout
    payload = bytearray()
    while b"\n" not in payload:
        remaining = deadline - time.monotonic()
        assert remaining > 0, "initialize response timed out"
        readable, _, _ = select.select([descriptor], [], [], remaining)
        assert readable, "initialize response timed out"
        chunk = os.read(descriptor, 65_537 - len(payload))
        assert chunk, "stdout closed before initialize response"
        payload.extend(chunk)
        assert len(payload) <= 65_536, "initialize response exceeded frame limit"
    assert payload.count(b"\n") == 1, "multiple frames arrived for one request"
    assert payload.endswith(b"\n"), "bytes followed the initialize frame"
    return bytes(payload)


def _process_tree(root_pid: int) -> set[int]:
    pending = [root_pid]
    observed: set[int] = set()
    while pending:
        pid = pending.pop()
        if pid in observed:
            continue
        observed.add(pid)
        try:
            children = Path(
                f"/proc/{pid}/task/{pid}/children"
            ).read_text(encoding="ascii")
        except OSError:
            continue
        pending.extend(int(value) for value in children.split())
        assert len(observed) + len(pending) <= 8
    return observed


def _kernel_status(pid: int) -> dict[str, str]:
    admitted = {"NoNewPrivs", "Seccomp"}
    result: dict[str, str] = {}
    with Path(f"/proc/{pid}/status").open(encoding="ascii") as stream:
        for line in stream:
            name, separator, value = line.partition(":")
            if separator and name in admitted:
                result[name] = value.strip()
    return result


def _network_rows(pid: int, name: str) -> list[str]:
    lines = Path(f"/proc/{pid}/net/{name}").read_text(
        encoding="ascii"
    ).splitlines()
    return lines[1:]


def _workload_cgroups() -> set[Path]:
    root = Path(
        f"/sys/fs/cgroup/user.slice/user-{os.getuid()}.slice/"
        f"user@{os.getuid()}.service/app.slice"
    )
    return set(root.glob("**/workload")) if root.is_dir() else set()


def test_exact_pinned_binary_production_initialize_matches_strict_auth_contract(
    tmp_path: Path,
) -> None:
    """Production binary proof; protocol fixtures cannot satisfy this test."""

    real_state = Path(
        "/home/brand/.local/share/agenticos/provider-state/kimi-code/0.36.1"
    )
    real_evidence = Path(
        "/home/brand/.local/share/agenticos/controller-evidence/"
        "kimi-code/0.36.1/level1-local-auth"
    )
    cgroups_before = _workload_cgroups()
    temporary_path: Path | None = None

    with tempfile.TemporaryDirectory(
        prefix="aos-kimi-shape-",
        dir=tmp_path,
    ) as temporary:
        temporary_path = Path(temporary).resolve()
        assert not temporary_path.is_relative_to(real_state)
        assert not real_state.is_relative_to(temporary_path)
        assert not temporary_path.is_relative_to(real_evidence)
        assert not real_evidence.is_relative_to(temporary_path)

        spec = _spec(temporary_path)
        synthetic_leaf = spec.state_root / "credentials" / "kimi-code.json"
        synthetic_leaf.write_bytes(b"")
        synthetic_leaf.chmod(0o600)
        assert synthetic_leaf.stat().st_size == 0

        credential = open_validated_credential_leaf(
            spec.state_root,
            trusted_state_root=spec.state_root,
            expected_uid=os.getuid(),
        )
        process: subprocess.Popen[bytes] | None = None
        pidfds: dict[int, int] = {}
        try:
            argv = build_local_auth_bwrap_argv(spec, credential)
            assert argv == _expected_production_bwrap_argv(spec, credential)

            session = KimiLocalAuthSession()
            requests = [session.initialize_request()]
            assert [decode_acp_line(request)["method"] for request in requests] == [
                "initialize"
            ]

            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={},
                close_fds=True,
                pass_fds=(credential.descriptor,),
                bufsize=0,
            )
            assert process.stdin is not None
            assert process.stdout is not None
            assert process.stderr is not None
            process.stdin.write(requests[0])
            process.stdin.flush()

            frame = _read_single_frame(process.stdout, 10.0)
            response = decode_acp_line(frame)
            assert set(response) == {"jsonrpc", "id", "result"}
            assert response["jsonrpc"] == "2.0"
            assert response["id"] == 1
            result = response["result"]
            assert isinstance(result, dict)
            assert result["protocolVersion"] == 1
            assert result["agentInfo"] == {
                "name": "Kimi Code CLI",
                "version": "0.36.1",
            }
            assert result["agentCapabilities"] == EXPECTED_AGENT_CAPABILITIES
            assert result["authMethods"] == EXPECTED_AUTH_METHODS
            session.accept(frame)
            assert validate_kimi_initialize_result(result) == result

            assert sha256_file(PINNED_RUNTIME) == PINNED_EXECUTABLE_SHA256
            assert sha256_file(LAUNCHER) == REMEDIATED_LAUNCHER_SHA256
            assert len(requests) == 1
            assert process.poll() is None
            readable, _, _ = select.select([process.stdout], [], [], 0.2)
            assert readable == []

            deadline = time.monotonic() + 5.0
            seccomp_pids: list[int] = []
            observed_pids: set[int] = set()
            while time.monotonic() < deadline:
                observed_pids = _process_tree(process.pid)
                seccomp_pids = []
                for pid in observed_pids:
                    try:
                        status = _kernel_status(pid)
                    except OSError:
                        continue
                    if status == {"NoNewPrivs": "1", "Seccomp": "2"}:
                        seccomp_pids.append(pid)
                if seccomp_pids:
                    break
                time.sleep(0.02)
            assert len(seccomp_pids) == 1
            provider_pid = seccomp_pids[0]
            assert os.readlink(f"/proc/{provider_pid}/ns/net") != os.readlink(
                "/proc/self/ns/net"
            )
            routes = _network_rows(provider_pid, "route")
            assert not any(
                len(row.split()) > 1 and row.split()[1] == "00000000"
                for row in routes
            )
            for table in ("tcp", "tcp6", "udp", "udp6"):
                assert _network_rows(provider_pid, table) == []

            for pid in observed_pids:
                try:
                    pidfds[pid] = os.pidfd_open(pid)
                except ProcessLookupError:
                    pass
            assert process.pid in pidfds

            process.stdin.close()
            process.stdin = None
            assert process.wait(timeout=10) == 0
            assert process.stdout.read() == b""
            assert process.stderr.read() == b""
            for descriptor in pidfds.values():
                readable, _, _ = select.select([descriptor], [], [], 0)
                assert readable == [descriptor]

            assert list(spec.evidence_root.iterdir()) == []
            assert sorted(
                path.relative_to(spec.state_root).as_posix()
                for path in spec.state_root.rglob("*")
            ) == ["credentials", "credentials/kimi-code.json"]
            assert synthetic_leaf.read_bytes() == b""
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            for descriptor in pidfds.values():
                os.close(descriptor)
            credential.close()

    assert temporary_path is not None
    assert not temporary_path.exists()
    assert _workload_cgroups() == cgroups_before


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
            ["/opt/agenticos/kimi/bin/kimi", "acp"],
            environment,
        )
    ]

    with pytest.raises(NamespaceLauncherError, match="ACP_ENVIRONMENT_DRIFT"):
        exec_official_acp(
            {**environment, "HTTPS_PROXY": "http://ambient-proxy.invalid"},
            execve=stop_exec,
        )
