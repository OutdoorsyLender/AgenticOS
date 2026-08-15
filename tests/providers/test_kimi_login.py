"""Fail-closed policy tests for the owner-run Kimi login ceremony."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import socket
import stat
import subprocess
import threading
import time

import pytest

if os.name != "posix":
    pytest.skip("Kimi owner-login security boundary is Linux-only", allow_module_level=True)

from agenticos.providers.kimi_login import (
    AUTH_HOST,
    AUTH_PORT,
    CredentialRootState,
    AuthRelayResult,
    KimiLoginError,
    KimiAuthRelay,
    KimiLoginSpec,
    OpaqueClientTlsGuard,
    authorize_connect_head,
    build_login_environment,
    build_login_bwrap_argv,
    cleanup_login_runtime,
    cli_main,
    default_login_spec,
    owner_systemd_command,
    handle_opaque_auth_connection,
    open_validated_credential_root,
    provision_default_credential_root,
    receive_listener_fd,
    terminate_and_drain_process,
    validate_repository_identity,
    validate_login_spec,
    validate_scope_membership,
    validate_tls13_server_hello,
    provision_empty_credential_root,
    validate_client_hello_bytes,
    validate_credential_parent_chain,
    validate_credential_root,
    validate_interactive_terminal,
)
from agenticos.providers.kimi_login_namespace import (
    exec_official_login,
    send_listener_fd,
)


_CHGEN_PATH = Path(__file__).parents[1] / "conformance" / "chgen.py"
_CHGEN_SPEC = importlib.util.spec_from_file_location("aos_test_chgen", _CHGEN_PATH)
assert _CHGEN_SPEC is not None and _CHGEN_SPEC.loader is not None
chgen = importlib.util.module_from_spec(_CHGEN_SPEC)
_CHGEN_SPEC.loader.exec_module(chgen)


_HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)


def _tls_record(content_type: int, payload: bytes) -> bytes:
    return bytes([content_type, 3, 3]) + len(payload).to_bytes(2, "big") + payload


def _server_hello(*, tls13: bool = True, hello_retry: bool = False) -> bytes:
    random = _HRR_RANDOM if hello_retry else b"S" * 32
    extensions = b"\x00\x2b\x00\x02\x03\x04" if tls13 else b""
    body = (
        b"\x03\x03"
        + random
        + b"\x00"
        + (b"\x13\x01" if tls13 else b"\xc0\x2f")
        + b"\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return _tls_record(22, handshake)


def _connect_head(authority: str) -> bytes:
    return (
        f"CONNECT {authority} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "Proxy-Connection: Keep-Alive\r\n\r\n"
    ).encode("ascii")


@pytest.mark.parametrize(
    ("authority", "expected_code"),
    [
        ("api.kimi.com:443", "CONNECT_HOST_DENIED"),
        ("code.kimi.com:443", "CONNECT_HOST_DENIED"),
        ("redirect.example:443", "CONNECT_HOST_DENIED"),
        ("203.0.113.8:443", "CONNECT_AUTHORITY_INVALID"),
        ("auth.kimi.com:444", "CONNECT_AUTHORITY_INVALID"),
    ],
)
def test_only_exact_auth_kimi_connect_authority_is_admitted(
    authority: str, expected_code: str
) -> None:
    """Changing the exact CONNECT authority must fail before TLS bytes flow."""

    with pytest.raises(KimiLoginError) as rejected:
        authorize_connect_head(_connect_head(authority))
    assert rejected.value.code == expected_code

    assert authorize_connect_head(_connect_head("auth.kimi.com:443")) == AUTH_HOST
    assert AUTH_PORT == 443


@pytest.mark.parametrize(
    ("hostname", "ech", "expected_code"),
    [
        (b"api.kimi.com", False, "TLS_SNI_DENIED"),
        (b"code.kimi.com", False, "TLS_SNI_DENIED"),
        (b"redirect.example", False, "TLS_SNI_DENIED"),
        (None, False, "TLS_CLIENT_HELLO_REJECTED"),
        (b"auth.kimi.com", True, "TLS_CLIENT_HELLO_REJECTED"),
    ],
)
def test_clienthello_requires_visible_exact_auth_kimi_sni(
    hostname: bytes | None, ech: bool, expected_code: str
) -> None:
    """Missing, hidden, alternate, or malformed SNI must never reach origin."""

    hello = chgen.make_client_hello(hostname, tls13=True, ech=ech)
    with pytest.raises(KimiLoginError) as rejected:
        validate_client_hello_bytes(hello)
    assert rejected.value.code == expected_code

    accepted = validate_client_hello_bytes(
        chgen.make_client_hello(b"auth.kimi.com", tls13=True)
    )
    assert accepted == AUTH_HOST


def test_post_initial_tls_guard_rejects_every_plaintext_second_clienthello() -> None:
    """A second ClientHello must close the opaque connection, never change SNI."""

    guard = OpaqueClientTlsGuard()
    second = chgen.make_client_hello(b"auth.kimi.com", tls13=True)
    with pytest.raises(KimiLoginError) as rejected:
        guard.accept(second)
    assert rejected.value.code == "SECOND_CLIENT_HELLO"


def test_opaque_relay_requires_tls13_and_rejects_hello_retry_request() -> None:
    """TLS 1.2 or HRR would make a later ClientHello unverifiable, so both block."""

    accepted = _server_hello()
    assert validate_tls13_server_hello(accepted) == accepted
    with pytest.raises(KimiLoginError) as tls12:
        validate_tls13_server_hello(_server_hello(tls13=False))
    assert tls12.value.code == "TLS_VERSION_DENIED"
    with pytest.raises(KimiLoginError) as hrr:
        validate_tls13_server_hello(_server_hello(hello_retry=True))
    assert hrr.value.code == "SECOND_CLIENT_HELLO"


def test_opaque_auth_relay_forwards_encrypted_records_without_http_inspection() -> None:
    """The admitted connection must relay bytes unchanged after metadata gates."""

    worker, worker_peer = socket.socketpair()
    origin, origin_peer = socket.socketpair()
    outcome: list[object] = []

    def serve() -> None:
        outcome.append(
            handle_opaque_auth_connection(worker, origin_socket_factory=lambda: origin)
        )

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    worker_peer.sendall(_connect_head("auth.kimi.com:443"))
    assert worker_peer.recv(128) == b"HTTP/1.1 200 Connection Established\r\n\r\n"
    hello = chgen.make_client_hello(b"auth.kimi.com", tls13=True)
    worker_peer.sendall(hello)
    assert origin_peer.recv(len(hello)) == hello
    server_hello = _server_hello()
    origin_peer.sendall(server_hello)
    assert worker_peer.recv(len(server_hello)) == server_hello
    encrypted_request = _tls_record(23, b"opaque-request-ciphertext")
    encrypted_response = _tls_record(23, b"opaque-response-ciphertext")
    worker_peer.sendall(encrypted_request)
    assert origin_peer.recv(len(encrypted_request)) == encrypted_request
    origin_peer.sendall(encrypted_response)
    assert worker_peer.recv(len(encrypted_response)) == encrypted_response
    worker_peer.shutdown(socket.SHUT_WR)
    origin_peer.shutdown(socket.SHUT_WR)
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert len(outcome) == 1
    observation = outcome[0]
    assert observation.result is AuthRelayResult.COMPLETED
    assert observation.hostname == "auth.kimi.com"
    assert observation.destination_class == "AUTH"
    assert set(observation.__dataclass_fields__) == {
        "result",
        "hostname",
        "destination_class",
        "client_to_origin_bytes",
        "origin_to_client_bytes",
        "reason_code",
    }
    worker_peer.close()
    origin_peer.close()


def test_wrong_sni_is_reported_as_unknown_hostname_without_origin_connection() -> None:
    """A CONNECT/SNI disagreement must report only the observed alternate hostname."""

    worker, peer = socket.socketpair()
    observations: list[object] = []
    thread = threading.Thread(
        target=lambda: observations.append(handle_opaque_auth_connection(worker)),
        daemon=True,
    )
    thread.start()
    peer.sendall(_connect_head("auth.kimi.com:443"))
    assert peer.recv(128).startswith(b"HTTP/1.1 200")
    peer.sendall(chgen.make_client_hello(b"api.kimi.com", tls13=True))
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert observations[0].result is AuthRelayResult.FAILED
    assert observations[0].hostname == "api.kimi.com"
    assert observations[0].destination_class == "UNKNOWN"
    assert observations[0].reason_code == "TLS_SNI_DENIED"
    peer.close()


def test_relay_denies_alternate_redirect_followup_before_origin_connection() -> None:
    """An encrypted redirect can only cause a new CONNECT, which is gated anew."""

    worker, peer = socket.socketpair()
    observation: list[object] = []
    thread = threading.Thread(
        target=lambda: observation.append(handle_opaque_auth_connection(worker)),
        daemon=True,
    )
    thread.start()
    peer.sendall(_connect_head("redirect.example:443"))
    assert peer.recv(128).startswith(b"HTTP/1.1 403")
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert observation[0].result is AuthRelayResult.DENIED
    assert observation[0].hostname == "redirect.example"
    assert observation[0].destination_class == "UNKNOWN"
    peer.close()


def test_relay_stop_closes_active_connection_and_drains_threads() -> None:
    """Cancellation must close accepted sockets and leave no broker thread alive."""

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    relay = KimiAuthRelay(listener)
    relay.start()
    peer = socket.create_connection(listener.getsockname(), timeout=1)
    peer.sendall(b"CONNECT auth.kimi.com:443 HTTP/1.1\r\n")
    deadline = time.monotonic() + 2
    while relay.active_connection_count == 0 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert relay.active_connection_count == 1
    relay.stop()
    assert relay.active_connection_count == 0
    assert relay.running is False
    peer.close()


@pytest.mark.parametrize(
    "record",
    [
        b"\x00\x03\x03\x00\x01x",
        b"\x17\x03\x01\x00\x01x",
    ],
)
def test_post_handshake_guard_rejects_invalid_content_type_or_version(record: bytes) -> None:
    """Opaque does not mean unframed: invalid TLS record metadata must fail closed."""

    with pytest.raises(KimiLoginError) as rejected:
        OpaqueClientTlsGuard().accept(record)
    assert rejected.value.code == "TLS_RECORD_MALFORMED"


def test_connection_limit_closes_listener_instead_of_leaving_unserved_backlog() -> None:
    """Exhausting connection authority must make the proxy unreachable immediately."""

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    address = listener.getsockname()
    listener.listen(1)
    relay = KimiAuthRelay(listener, connection_limit=1)
    relay.start()
    peer = socket.create_connection(address, timeout=1)
    peer.sendall(_connect_head("api.kimi.com:443"))
    assert peer.recv(128).startswith(b"HTTP/1.1 403")
    peer.close()
    deadline = time.monotonic() + 2
    while relay.running and time.monotonic() < deadline:
        time.sleep(0.01)
    assert relay.running is False
    with pytest.raises(OSError):
        socket.create_connection(address, timeout=0.2)
    relay.stop()


def test_empty_credential_root_is_provisioned_once_with_exact_modes(tmp_path: Path) -> None:
    """Provisioning must create only the approved empty 0700 credential leaf."""

    state_root = tmp_path / "provider-state"
    result = provision_empty_credential_root(state_root, expected_uid=os.getuid())
    assert result is CredentialRootState.EMPTY
    assert sorted(path.name for path in state_root.iterdir()) == ["credentials"]
    credentials = state_root / "credentials"
    assert stat.S_IMODE(state_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(credentials.stat().st_mode) == 0o700
    assert list(credentials.iterdir()) == []
    assert (
        validate_credential_root(state_root, expected_uid=os.getuid())
        is CredentialRootState.EMPTY
    )

    with pytest.raises(KimiLoginError) as rejected:
        provision_empty_credential_root(state_root, expected_uid=os.getuid())
    assert rejected.value.code == "CREDENTIAL_ROOT_ALREADY_EXISTS"


def test_default_provisioner_creates_private_missing_parent_chain_once(tmp_path: Path) -> None:
    """The real missing parent shape must become only private approved directories."""

    anchor = tmp_path / "agenticos"
    anchor.mkdir(mode=0o755)
    state_root = provision_default_credential_root(
        anchor=anchor, expected_uid=os.getuid()
    )
    assert state_root == anchor / "provider-state" / "kimi-code" / "0.36.1"
    for path in (
        anchor / "provider-state",
        anchor / "provider-state" / "kimi-code",
        state_root,
        state_root / "credentials",
    ):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
        assert path.stat().st_uid == os.getuid()
        assert not path.is_symlink()
    assert list((state_root / "credentials").iterdir()) == []
    with pytest.raises(KimiLoginError) as repeated:
        provision_default_credential_root(anchor=anchor, expected_uid=os.getuid())
    assert repeated.value.code == "CREDENTIAL_ROOT_ALREADY_EXISTS"


def test_default_credential_parent_chain_modes_are_revalidated(tmp_path: Path) -> None:
    """Wrapper validation must reject mode drift in every controlled parent."""

    anchor = tmp_path / "agenticos"
    anchor.mkdir(mode=0o755)
    state_root = provision_default_credential_root(
        anchor=anchor, expected_uid=os.getuid()
    )
    assert (
        validate_credential_parent_chain(
            state_root, anchor=anchor, expected_uid=os.getuid()
        )
        is None
    )

    provider_state = anchor / "provider-state"
    provider_state.chmod(0o755)
    with pytest.raises(KimiLoginError) as parent_mode:
        validate_credential_parent_chain(
            state_root, anchor=anchor, expected_uid=os.getuid()
        )
    assert parent_mode.value.code == "CREDENTIAL_PARENT_IDENTITY"

    provider_state.chmod(0o700)
    anchor.chmod(0o777)
    with pytest.raises(KimiLoginError) as anchor_mode:
        validate_credential_parent_chain(
            state_root, anchor=anchor, expected_uid=os.getuid()
        )
    assert anchor_mode.value.code == "CREDENTIAL_PARENT_IDENTITY"


@pytest.mark.parametrize("breakage", ["wrong-mode", "unknown-entry", "symlink-leaf"])
def test_credential_root_validation_fails_closed(tmp_path: Path, breakage: str) -> None:
    """A mode, ancestry, or entry mutation must block before the login process."""

    state_root = tmp_path / "state"
    provision_empty_credential_root(state_root, expected_uid=os.getuid())
    credentials = state_root / "credentials"
    if breakage == "wrong-mode":
        credentials.chmod(0o755)
    elif breakage == "unknown-entry":
        (credentials / "unexpected").write_bytes(b"synthetic")
        (credentials / "unexpected").chmod(0o600)
    else:
        credentials.rmdir()
        credentials.symlink_to(tmp_path, target_is_directory=True)

    with pytest.raises(KimiLoginError):
        validate_credential_root(state_root, expected_uid=os.getuid())


def test_terminal_requirement_needs_all_three_real_terminal_descriptors() -> None:
    """Redirecting any terminal stream must block before owner authorization output."""

    assert validate_interactive_terminal(lambda fd: fd in (0, 1, 2)) is None
    for missing in (0, 1, 2):
        with pytest.raises(KimiLoginError) as rejected:
            validate_interactive_terminal(lambda fd, missing=missing: fd != missing)
        assert rejected.value.code == "INTERACTIVE_TERMINAL_REQUIRED"


def test_login_environment_adds_only_fixed_proxy_to_passive_allowlist() -> None:
    """Adding an API key, alternate proxy, or model endpoint variable must fail review."""

    environment = build_login_environment()
    assert environment == {
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
    assert not any(
        "KEY" in name
        or name.lower() in {"http_proxy", "all_proxy", "no_proxy"}
        for name in environment
    )


def test_scope_membership_requires_exact_owner_login_scope() -> None:
    """Launching outside the dedicated systemd scope must block before credentials mount."""

    assert validate_scope_membership("0::/user.slice/aos-kimi-owner-login.scope\n") is None
    for observed in (
        "0::/user.slice/session-1.scope\n",
        "0::/user.slice/aos-kimi-owner-login-evil.scope\n",
        "",
    ):
        with pytest.raises(KimiLoginError) as rejected:
            validate_scope_membership(observed)
        assert rejected.value.code == "LOGIN_SCOPE_REQUIRED"


def test_listener_handoff_transfers_only_exact_loopback_proxy_socket() -> None:
    """The host broker must receive the listener object, not general netns authority."""

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 18080))
    listener.listen(1)
    parent, child = socket.socketpair()
    send_listener_fd(child, listener)
    received = receive_listener_fd(parent)
    assert received.getsockname() == ("127.0.0.1", 18080)
    assert received.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
    received.close()
    listener.close()
    parent.close()
    child.close()


def test_namespace_launcher_exec_vector_is_exact_official_login() -> None:
    """A prompt, model flag, provider override, or shell must never enter argv."""

    observed: list[tuple[str, list[str], dict[str, str]]] = []
    environment = build_login_environment()
    with pytest.raises(RuntimeError, match="synthetic exec stop"):
        exec_official_login(
            environment,
            execve=lambda path, argv, env: (
                observed.append((path, argv, env)),
                (_ for _ in ()).throw(RuntimeError("synthetic exec stop")),
            )[1],
        )
    assert observed == [
        (
            "/opt/agenticos/kimi/bin/kimi",
            ["kimi-code", "login"],
            environment,
        )
    ]


def test_login_spec_rejects_wrong_runtime_before_namespace_creation(tmp_path: Path) -> None:
    """Substituting an executable must fail at the hash pin, before any login process."""

    repo = Path(__file__).parents[2]
    bundle = repo / "qualification" / "kimi-code" / "0.36.1"
    executable = tmp_path / "kimi"
    executable.write_bytes(b"wrong runtime")
    executable.chmod(0o555)
    state_root = tmp_path / "state"
    provision_empty_credential_root(state_root, expected_uid=os.getuid())
    launcher = repo / "src" / "agenticos" / "providers" / "kimi_login_namespace.py"
    spec = KimiLoginSpec(executable, bundle, state_root, launcher)
    with pytest.raises(KimiLoginError) as rejected:
        validate_login_spec(spec, expected_uid=os.getuid())
    assert rejected.value.code == "PIN_RECHECK_FAILED"


def test_runtime_probe_error_is_collapsed_to_safe_pin_recheck_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Low-level runtime diagnostics must not escape into owner-facing evidence."""

    from agenticos.providers import kimi_login
    from agenticos.providers.kimi_runtime import KimiRuntimeError

    repo = Path(__file__).parents[2]
    state_root = tmp_path / "state"
    provision_empty_credential_root(state_root, expected_uid=os.getuid())
    spec = KimiLoginSpec(
        Path(
            "/home/brand/.local/share/agenticos/provider-qualification/"
            "kimi-code/0.36.1/runtime/bin/kimi"
        ),
        repo / "qualification" / "kimi-code" / "0.36.1",
        state_root,
        repo / "src" / "agenticos" / "providers" / "kimi_login_namespace.py",
    )
    monkeypatch.setattr(
        kimi_login,
        "run_passive_kimi",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KimiRuntimeError("SYNTHETIC_DETAIL")),
    )
    with pytest.raises(KimiLoginError) as rejected:
        validate_login_spec(spec, expected_uid=os.getuid())
    assert rejected.value.code == "PIN_RECHECK_FAILED"


def test_owner_command_is_exact_systemd_scope_without_shell_or_capture() -> None:
    """The returned command must have no shell, tee, transcript, prompt, or model flag."""

    commit = "a" * 40
    command = owner_systemd_command(commit)
    assert command == [
        "/usr/bin/systemd-run",
        "--user",
        "--scope",
        "--collect",
        "--quiet",
        "--unit=aos-kimi-owner-login",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=5s",
        "--property=TasksMax=16",
        "--property=MemoryMax=1G",
        "/usr/bin/python3",
        "/home/brand/src/AgenticOS/scripts/run_kimi_owner_login.py",
        "--expected-commit",
        commit,
    ]
    assert "tee" not in command
    assert "script" not in command
    assert "--prompt" not in command
    assert "-p" not in command
    assert all("api.kimi.com" not in token for token in command)


def test_default_login_spec_names_only_qualified_external_and_bundle_paths() -> None:
    """Ambient HOME, PATH, or a second checkout must not redirect the ceremony."""

    spec = default_login_spec()
    assert spec.executable == Path(
        "/home/brand/.local/share/agenticos/provider-qualification/"
        "kimi-code/0.36.1/runtime/bin/kimi"
    )
    assert spec.bundle == Path("/home/brand/src/AgenticOS/qualification/kimi-code/0.36.1")
    assert spec.state_root == Path(
        "/home/brand/.local/share/agenticos/provider-state/kimi-code/0.36.1"
    )
    assert spec.namespace_launcher == Path(
        "/home/brand/src/AgenticOS/src/agenticos/providers/kimi_login_namespace.py"
    )


def test_cli_nonterminal_fails_before_repository_or_login_execution() -> None:
    """A captured/redirected wrapper invocation must emit only one safe error code."""

    output: list[str] = []
    result = cli_main(
        ["--expected-commit", "a" * 40],
        isatty=lambda _fd: False,
        output=output.append,
    )
    assert result == 2
    assert output == ["F1_KIMI_LOGIN_CEREMONY_ERROR=INTERACTIVE_TERMINAL_REQUIRED"]


def _git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        capture_output=True,
        text=True,
        env={
            "HOME": str(repo / ".home"),
            "PATH": os.environ["PATH"],
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1",
        },
    )
    return completed.stdout.strip()


def test_repository_binding_requires_clean_main_at_exact_expected_commit(tmp_path: Path) -> None:
    """A modified wrapper or moved HEAD must block before entering the login scope."""

    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.name", "Synthetic Test")
    _git(repo, "config", "user.email", "synthetic@example.invalid")
    (repo / "tracked").write_text("one\n", encoding="utf-8")
    _git(repo, "add", "tracked")
    _git(repo, "commit", "-m", "synthetic baseline")
    commit = _git(repo, "rev-parse", "HEAD")
    _git(repo, "update-ref", "refs/remotes/origin/main", commit)
    assert validate_repository_identity(repo, commit) is None

    (repo / "tracked").write_text("drift\n", encoding="utf-8")
    with pytest.raises(KimiLoginError) as dirty:
        validate_repository_identity(repo, commit)
    assert dirty.value.code == "LOGIN_REPOSITORY_DIRTY"
    (repo / "tracked").write_text("one\n", encoding="utf-8")
    with pytest.raises(KimiLoginError) as wrong:
        validate_repository_identity(repo, "b" * 40)
    assert wrong.value.code == "LOGIN_REPOSITORY_IDENTITY"


@pytest.mark.skipif(os.name != "posix", reason="process-group drain is Linux-only")
def test_cancellation_recursively_drains_synthetic_process_group() -> None:
    """Cancellation must kill a synthetic descendant, not only its direct parent."""

    process = subprocess.Popen(
        [
            "/usr/bin/python3",
            "-c",
            "import subprocess,time; "
            "subprocess.Popen(['/usr/bin/python3','-c',"
            "'import time; time.sleep(60)']); time.sleep(60)",
        ],
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    try:
        time.sleep(0.2)
        terminate_and_drain_process(process)
        assert process.poll() is not None
        with pytest.raises(ProcessLookupError):
            os.killpg(process.pid, 0)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)


@pytest.mark.skipif(os.name != "posix", reason="process-group drain is Linux-only")
def test_drain_kills_residual_descendant_after_direct_parent_exits() -> None:
    """A successful direct wait must not hide a surviving background descendant."""

    process = subprocess.Popen(
        [
            "/usr/bin/python3",
            "-c",
            "import subprocess; subprocess.Popen(['/usr/bin/python3','-c',"
            "'import time; time.sleep(60)'])",
        ],
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    process.wait(timeout=2)
    terminate_and_drain_process(process)
    with pytest.raises(ProcessLookupError):
        os.killpg(process.pid, 0)


def test_cleanup_drains_process_even_when_relay_cleanup_reports_failure() -> None:
    """A broker cleanup error must never skip credential-bearing process drain."""

    class BrokenRelay:
        def stop(self) -> None:
            raise KimiLoginError("SYNTHETIC_RELAY_STOP_FAILURE")

    process = subprocess.Popen(
        ["/usr/bin/python3", "-c", "import time; time.sleep(60)"],
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    with pytest.raises(KimiLoginError) as rejected:
        cleanup_login_runtime(BrokenRelay(), process)
    assert rejected.value.code == "SYNTHETIC_RELAY_STOP_FAILURE"
    assert process.poll() is not None
    with pytest.raises(ProcessLookupError):
        os.killpg(process.pid, 0)


def test_login_sandbox_runs_only_official_login_and_mounts_no_checkout(tmp_path: Path) -> None:
    """Changing the child command or exposing the checkout must be structurally impossible."""

    executable = tmp_path / "kimi"
    executable.write_bytes(b"synthetic executable")
    executable.chmod(0o555)
    bundle = tmp_path / "bundle"
    (bundle / "agents").mkdir(parents=True)
    for relative in ("config.toml", "agents/agent.md"):
        path = bundle / relative
        path.write_text("synthetic", encoding="utf-8")
    state_root = tmp_path / "state"
    provision_empty_credential_root(state_root, expected_uid=os.getuid())
    launcher = tmp_path / "launcher.py"
    launcher.write_text("# synthetic", encoding="utf-8")
    spec = KimiLoginSpec(
        executable=executable.resolve(),
        bundle=bundle.resolve(),
        state_root=state_root.resolve(),
        namespace_launcher=launcher.resolve(),
    )

    credential_fd = open_validated_credential_root(state_root, expected_uid=os.getuid())
    try:
        argv = build_login_bwrap_argv(spec, handoff_fd=9, credential_fd=credential_fd)
    finally:
        os.close(credential_fd)
    assert argv[-3:] == ["/usr/bin/python3", "/opt/agenticos/kimi/login_namespace.py", "9"]
    assert ["--", "/opt/agenticos/kimi/bin/kimi", "login"] not in [
        argv[index : index + 3] for index in range(len(argv) - 2)
    ]
    assert "--unshare-net" in argv
    assert "--unshare-pid" in argv
    assert "--unshare-cgroup" in argv
    assert "--bind-fd" in argv
    assert str(credential_fd) in argv
    assert str(state_root / "credentials") not in argv
    assert "/home/aos/kimi/credentials" in argv
    assert str(Path.cwd()) not in argv
    assert "/workspace" in argv
