from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
import errno
import fcntl
import io
import json
import os
import shutil
import stat
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time

import pytest

import agenticos.providers.kimi_runtime as kimi_runtime
import agenticos.providers.kimi_local_auth_runtime as local_auth_runtime
from agenticos.providers.kimi_local_auth import (
    KimiLocalAuthError,
    KimiLocalAuthSession,
    LocalAuthProtocolOutcome,
    LocalCredentialState,
    QualificationState,
)
from agenticos.providers.kimi_local_auth_runtime import (
    KimiLocalAuthSpec,
    KimiLocalAuthRuntimeError,
    build_local_auth_bwrap_argv,
    claim_real_attempt,
    default_local_auth_spec,
    open_validated_credential_leaf,
    persist_typed_result,
)


def _line(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


INITIALIZE_SUCCESS = _line(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": 1,
            "agentCapabilities": {
                "loadSession": True,
                "promptCapabilities": {"image": True, "audio": False, "embeddedContext": True},
                "sessionCapabilities": {
                    "list": {}, "resume": {}, "close": {}, "delete": {}, "fork": {},
                    "additionalDirectories": {},
                },
                "mcpCapabilities": {"http": True, "sse": True},
                "auth": {"logout": {}},
            },
            "authMethods": [
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
            ],
            "agentInfo": {"name": "Kimi Code CLI", "version": "0.36.1"},
        },
    }
)

CANDIDATE_COMMIT = "1111111111111111111111111111111111111111"
OTHER_CANDIDATE_COMMIT = "2222222222222222222222222222222222222222"
SYNTHETIC_CREDENTIAL_BYTES = b'{"access_token":"synthetic-test-canary"}\n'
EXPECTED_ATTEMPT_BYTES = (
    b'{"attempt":1,"candidate_commit":"1111111111111111111111111111111111111111",'
    b'"lifecycle":"CLAIMED_BEFORE_LAUNCH","pinned_executable_sha256":'
    b'"78c07b255e0bdc8dfe90d0cbd3204a3d862957394a08ca99c6e31144732451c7",'
    b'"schema":"AOS_KIMI_LEVEL1_ATTEMPT/1"}\n'
)
ROOT = Path(__file__).resolve().parents[2]
PINNED_RUNTIME = Path(
    "/home/brand/.local/share/agenticos/provider-qualification/"
    "kimi-code/0.36.1/runtime/bin/kimi"
)
QUALIFIED_BUNDLE = ROOT / "qualification" / "kimi-code" / "0.36.1"
CANONICAL_LOCAL_AUTH_LAUNCHER = (
    ROOT / "src" / "agenticos" / "providers" / "kimi_local_auth_namespace.py"
)
PINNED_LOCAL_AUTH_LAUNCHER_SHA256 = (
    "861c5fecbf9599e158000fb732c661e51c9592c20be55e0eef458d1d663e60db"
)
_BWRAP_OPTION_OPERAND_ROLES = {
    "--unshare-user": (),
    "--unshare-pid": (),
    "--unshare-net": (),
    "--unshare-ipc": (),
    "--unshare-uts": (),
    "--unshare-cgroup": (),
    "--disable-userns": (),
    "--die-with-parent": (),
    "--new-session": (),
    "--clearenv": (),
    "--hostname": ("other",),
    "--chdir": ("other",),
    "--setenv": ("other", "other"),
    "--proc": ("destination",),
    "--dev": ("destination",),
    "--ro-bind": ("source", "destination"),
    "--dir": ("destination",),
    "--ro-bind-fd": ("descriptor", "destination"),
    "--remount-ro": ("destination",),
    "--tmpfs": ("destination",),
}


def make_structurally_valid_synthetic_state(state_root: Path) -> Path:
    credential_root = state_root / "credentials"
    credential_root.mkdir(parents=True, mode=0o700)
    state_root.chmod(0o700)
    credential_root.chmod(0o700)
    leaf = credential_root / "kimi-code.json"
    leaf.write_bytes(SYNTHETIC_CREDENTIAL_BYTES)
    leaf.chmod(0o600)
    return state_root


def make_private_evidence_root(evidence_root: Path) -> Path:
    evidence_root.mkdir(parents=True, mode=0o700)
    evidence_root.chmod(0o700)
    return evidence_root


def _parse_bwrap_mount_operands(argv: list[str]) -> list[tuple[str, str, str]]:
    operands: list[tuple[str, str, str]] = []
    index = 1
    while index < len(argv) and argv[index] != "--":
        option = argv[index]
        roles = _BWRAP_OPTION_OPERAND_ROLES.get(option)
        assert roles is not None, f"unclassified Bubblewrap option: {option}"
        arity = len(roles)
        values = argv[index + 1 : index + 1 + arity]
        assert len(values) == arity, f"truncated Bubblewrap option: {option}"
        operands.extend(
            (option, role, value)
            for role, value in zip(roles, values, strict=True)
            if role != "other"
        )
        index += arity + 1
    assert index < len(argv) and argv[index] == "--", (
        "missing Bubblewrap command separator"
    )
    return operands


def _normalized_mount_path(value: str | Path) -> Path:
    path = Path(os.path.normpath(str(value)))
    assert path.is_absolute(), f"mount path is not absolute: {value}"
    return path


def _path_is_at_or_below(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _assert_no_checkout_mount_exposure(
    mount_operands: list[tuple[str, str, str]],
    checkout_root: Path,
    approved_sources: set[Path],
) -> None:
    normalized_root = _normalized_mount_path(checkout_root)
    normalized_approved_sources = {
        _normalized_mount_path(source) for source in approved_sources
    }
    mount_sources = [
        _normalized_mount_path(value)
        for _option, role, value in mount_operands
        if role == "source"
    ]
    mount_destinations = [
        _normalized_mount_path(value)
        for _option, role, value in mount_operands
        if role == "destination"
    ]

    for source in mount_sources:
        if _path_is_at_or_below(source, normalized_root):
            assert source in normalized_approved_sources, (
                f"unapproved checkout mount source: {source}"
            )
        else:
            assert not _path_is_at_or_below(normalized_root, source), (
                f"checkout exposed through ancestor mount source: {source}"
            )
    for destination in mount_destinations:
        assert not _path_is_at_or_below(destination, normalized_root), (
            f"checkout destination: {destination}"
        )


def isolate_real_roots(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path, Path]:
    real_provider = tmp_path / "reserved-real-provider"
    real_evidence = tmp_path / "reserved-real-evidence"
    workspace = tmp_path / "reserved-workspace"
    monkeypatch.setattr(local_auth_runtime, "REAL_PROVIDER_STATE_ROOT", real_provider)
    monkeypatch.setattr(local_auth_runtime, "REAL_EVIDENCE_ROOT", real_evidence)
    monkeypatch.setattr(local_auth_runtime, "SANDBOX_WORKSPACE_ROOT", workspace)
    return real_provider, real_evidence, workspace


def _initialized_session() -> KimiLocalAuthSession:
    session = KimiLocalAuthSession()
    session.initialize_request()
    session.accept(INITIALIZE_SUCCESS)
    return session


def test_la_p01_exact_two_request_surface_and_no_level2_promotion() -> None:
    session = KimiLocalAuthSession()
    assert json.loads(session.initialize_request()) == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": 1, "clientCapabilities": {}},
    }
    session.accept(INITIALIZE_SUCCESS)
    assert json.loads(session.authenticate_request()) == {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "authenticate",
        "params": {"methodId": "login"},
    }
    session.accept(_line({"jsonrpc": "2.0", "id": 2, "result": None}))
    outcome = session.finish()
    assert outcome.qualification is QualificationState.COMPLETE
    assert outcome.credential_state is LocalCredentialState.LOADABLE
    assert outcome.auth_state == "LOCAL_ONLY"
    assert outcome.level2_status == "BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT"
    assert outcome.reason_code == "ACP_LOCAL_AUTH_SUCCESS"


def test_la_p02_rejects_empty_initialize_result() -> None:
    session = KimiLocalAuthSession()
    session.initialize_request()
    with pytest.raises(KimiLocalAuthError, match="INITIALIZE_SHAPE"):
        session.accept(_line({"jsonrpc": "2.0", "id": 1, "result": {}}))


def test_la_p03_accepts_empty_authenticate_result_as_loadable() -> None:
    session = _initialized_session()
    session.authenticate_request()
    session.accept(_line({"jsonrpc": "2.0", "id": 2, "result": {}}))
    assert session.finish().credential_state is LocalCredentialState.LOADABLE


def test_la_p04_maps_only_exact_login_rejection_to_rejected() -> None:
    session = _initialized_session()
    session.authenticate_request()
    session.accept(_line({"jsonrpc": "2.0", "id": 2, "error": {"code": -32000, "message": "declined"}}))
    outcome = session.finish()
    assert outcome.qualification is QualificationState.BLOCKED
    assert outcome.credential_state is LocalCredentialState.REJECTED
    assert outcome.level2_status == "BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT"


def test_la_p05_rejects_nonexact_authentication_error() -> None:
    session = _initialized_session()
    session.authenticate_request()
    with pytest.raises(KimiLocalAuthError, match="ACP_ERROR_RESPONSE"):
        session.accept(_line({"jsonrpc": "2.0", "id": 2, "error": {"code": -32001, "message": "unknown"}}))


def test_la_p06_rejects_wrong_response_id() -> None:
    session = KimiLocalAuthSession()
    session.initialize_request()
    with pytest.raises(KimiLocalAuthError, match="UNEXPECTED_RESPONSE_ID"):
        session.accept(_line({"jsonrpc": "2.0", "id": 2, "result": {}}))


def test_la_p07_rejects_duplicate_terminal_response() -> None:
    session = _initialized_session()
    session.authenticate_request()
    session.accept(_line({"jsonrpc": "2.0", "id": 2, "result": None}))
    with pytest.raises(KimiLocalAuthError, match="DUPLICATE_TERMINAL"):
        session.accept(_line({"jsonrpc": "2.0", "id": 2, "result": None}))


def test_la_p08_rejects_callbacks() -> None:
    session = KimiLocalAuthSession()
    session.initialize_request()
    with pytest.raises(KimiLocalAuthError, match="UNEXPECTED_CALLBACK"):
        session.accept(_line({"jsonrpc": "2.0", "method": "session/update", "params": {}}))


@pytest.mark.parametrize(
    "frame, code",
    [
        (b"not-json\n", "MALFORMED_JSON"),
        (b"x" * 65_537 + b"\n", "FRAME_TOO_LARGE"),
    ],
)
def test_la_p09_rejects_malformed_and_oversized_frames(frame: bytes, code: str) -> None:
    session = KimiLocalAuthSession()
    with pytest.raises(KimiLocalAuthError, match=code):
        session.accept(frame)


def test_la_p10_initialize_only_transcript_is_incomplete() -> None:
    session = _initialized_session()
    with pytest.raises(KimiLocalAuthError, match="INCOMPLETE_TRANSCRIPT"):
        session.finish()


def test_la_c10_validated_credential_leaf_is_opath_not_read_authority(
    tmp_path: Path,
) -> None:
    state_root = make_structurally_valid_synthetic_state(tmp_path / "state")
    leaf = state_root / "credentials" / "kimi-code.json"
    before = leaf.read_bytes()

    handle = open_validated_credential_leaf(
        state_root,
        trusted_state_root=state_root,
        expected_uid=os.getuid(),
    )
    descriptor = handle.descriptor
    try:
        descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
        assert descriptor_flags & fcntl.FD_CLOEXEC == fcntl.FD_CLOEXEC
        with pytest.raises(OSError) as rejected:
            os.read(descriptor, 1)
        assert rejected.value.errno == errno.EBADF
        leaf_info = leaf.lstat()
        assert (handle.device, handle.inode) == (leaf_info.st_dev, leaf_info.st_ino)
        assert handle.uid == os.getuid()
        assert handle.mode == 0o600
        assert handle.link_count == 1
        assert not hasattr(handle, "path")
        assert not hasattr(handle, "size")
        assert "kimi-code.json" not in repr(handle)
    finally:
        handle.close()

    with pytest.raises(OSError) as closed:
        os.fstat(descriptor)
    assert closed.value.errno == errno.EBADF
    handle.close()
    assert leaf.read_bytes() == before == SYNTHETIC_CREDENTIAL_BYTES


def _local_auth_spec(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> KimiLocalAuthSpec:
    monkeypatch.setattr(
        local_auth_runtime,
        "_CANONICAL_LOCAL_AUTH_BUNDLE",
        QUALIFIED_BUNDLE,
    )
    state_root = make_structurally_valid_synthetic_state(tmp_path / "state")
    evidence_root = make_private_evidence_root(tmp_path / "evidence")
    return KimiLocalAuthSpec(
        executable=PINNED_RUNTIME,
        bundle=QUALIFIED_BUNDLE,
        namespace_launcher=CANONICAL_LOCAL_AUTH_LAUNCHER,
        state_root=state_root.resolve(),
        evidence_root=evidence_root.resolve(),
    )


def test_la_c12_bwrap_mounts_exactly_one_credential_leaf_by_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    leaf = spec.state_root / "credentials" / "kimi-code.json"
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        argv = build_local_auth_bwrap_argv(spec, credential)
    finally:
        credential.close()

    mount_index = argv.index("--ro-bind-fd")
    assert argv.count("--ro-bind-fd") == 1
    assert argv[mount_index : mount_index + 3] == [
        "--ro-bind-fd",
        str(credential.descriptor),
        "/home/aos/kimi/credentials/kimi-code.json",
    ]
    assert "--bind-fd" not in argv
    assert str(leaf) not in argv
    assert str(spec.state_root) not in argv
    assert str(spec.evidence_root) not in argv


def test_la_c13_credential_parent_is_created_then_remounted_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        argv = build_local_auth_bwrap_argv(spec, credential)
    finally:
        credential.close()

    parent = "/home/aos/kimi/credentials"
    create_index = next(
        index
        for index in range(len(argv) - 1)
        if argv[index : index + 2] == ["--dir", parent]
    )
    mount_index = argv.index("--ro-bind-fd")
    remount_index = next(
        index
        for index in range(len(argv) - 1)
        if argv[index : index + 2] == ["--remount-ro", parent]
    )
    assert create_index < mount_index < remount_index
    assert argv[remount_index : remount_index + 2] == ["--remount-ro", parent]
    assert "--bind" not in argv


def test_la_n01_namespace_is_route_less_without_host_network_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        argv = build_local_auth_bwrap_argv(spec, credential)
    finally:
        credential.close()

    for flag in (
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
    ):
        assert flag in argv
    assert ["--tmpfs", "/workspace"] in [
        argv[index : index + 2] for index in range(len(argv) - 1)
    ]
    assert ["--chdir", "/workspace"] in [
        argv[index : index + 2] for index in range(len(argv) - 1)
    ]
    assert "/run" not in argv
    assert "/var" not in argv
    mount_operands = _parse_bwrap_mount_operands(argv)
    _assert_no_checkout_mount_exposure(
        mount_operands,
        ROOT,
        {
            spec.namespace_launcher,
            spec.bundle / "config.toml",
            spec.bundle / "agents",
        },
    )
    absolute_argv_paths = [
        _normalized_mount_path(value) for value in argv if value.startswith("/")
    ]
    assert all(".git" not in value for value in argv)
    assert not any(
        _path_is_at_or_below(path, Path("/etc")) for path in absolute_argv_paths
    )
    assert all("resolv.conf" not in value for value in argv)
    assert all("/mnt/c" not in value for value in argv)
    assert all("socket" not in value.casefold() for value in argv)
    assert all("relay" not in value.casefold() for value in argv)


def test_la_n01_exact_canonical_launcher_source_is_not_broad_checkout_exposure() -> None:
    checkout_root = Path("/home/brand/src/AgenticOS")
    launcher = checkout_root / (
        "src/agenticos/providers/kimi_local_auth_namespace.py"
    )
    argv = [
        "/usr/bin/bwrap",
        "--ro-bind",
        str(launcher),
        "/opt/agenticos/local-auth/kimi_local_auth_namespace.py",
        "--",
        "/usr/bin/python3",
        "/opt/agenticos/local-auth/kimi_local_auth_namespace.py",
        "1",
        "2",
    ]

    assert str(checkout_root) in "\n".join(argv)
    _assert_no_checkout_mount_exposure(
        _parse_bwrap_mount_operands(argv),
        checkout_root,
        {launcher},
    )

    forbidden_mounts = (
        (str(checkout_root), "/workspace/checkout", "unapproved checkout mount source"),
        (str(checkout_root / "src"), "/workspace/src", "unapproved checkout mount source"),
        (
            str(checkout_root.parent),
            "/workspace/src-parent",
            "checkout exposed through ancestor mount source",
        ),
        ("/usr", str(checkout_root / "sandbox-destination"), "checkout destination"),
    )
    for source, destination, reason in forbidden_mounts:
        forbidden_argv = [
            "/usr/bin/bwrap",
            "--ro-bind",
            source,
            destination,
            "--",
            "/usr/bin/true",
        ]
        with pytest.raises(AssertionError, match=reason):
            _assert_no_checkout_mount_exposure(
                _parse_bwrap_mount_operands(forbidden_argv),
                checkout_root,
                {launcher},
            )


def test_la_n02_argv_environment_is_exact_and_has_no_proxy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://ambient-proxy.invalid")
    monkeypatch.setenv("ALL_PROXY", "socks5://ambient-proxy.invalid")
    monkeypatch.setenv("KIMI_API_KEY", "ambient-secret")
    spec = _local_auth_spec(tmp_path, monkeypatch)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        argv = build_local_auth_bwrap_argv(spec, credential)
    finally:
        credential.close()

    environment = {
        argv[index + 1]: argv[index + 2]
        for index, item in enumerate(argv)
        if item == "--setenv"
    }
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
    }
    assert not any("proxy" in name.casefold() for name in environment)
    assert "ambient" not in repr(argv)


def test_la_n03_argv_launcher_receives_only_device_and_inode_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        argv = build_local_auth_bwrap_argv(spec, credential)
    finally:
        credential.close()

    separator = argv.index("--")
    assert argv[separator:] == [
        "--",
        "/usr/bin/python3",
        "/opt/agenticos/kimi/local_auth_namespace.py",
        str(credential.device),
        str(credential.inode),
    ]


def test_la_n04_default_argv_spec_names_fixed_qualified_and_external_roots() -> None:
    spec = default_local_auth_spec()
    assert spec == KimiLocalAuthSpec(
        executable=Path(
            "/home/brand/.local/share/agenticos/provider-qualification/"
            "kimi-code/0.36.1/runtime/bin/kimi"
        ),
        bundle=Path(
            "/home/brand/src/AgenticOS/qualification/kimi-code/0.36.1"
        ),
        namespace_launcher=Path(
            "/home/brand/src/AgenticOS/src/agenticos/providers/"
            "kimi_local_auth_namespace.py"
        ),
        state_root=Path(
            "/home/brand/.local/share/agenticos/provider-state/kimi-code/0.36.1"
        ),
        evidence_root=Path(
            "/home/brand/.local/share/agenticos/controller-evidence/"
            "kimi-code/0.36.1/level1-local-auth"
        ),
    )


def test_la_c14_launch_vector_directly_revalidates_qualified_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        argv = build_local_auth_bwrap_argv(spec, credential)
    finally:
        credential.close()
    assert str(kimi_runtime.BWRAP) == argv[0]
    assert str(PINNED_RUNTIME) in argv
    assert str(QUALIFIED_BUNDLE / "config.toml") in argv
    assert str(QUALIFIED_BUNDLE / "agents") in argv
    assert str(CANONICAL_LOCAL_AUTH_LAUNCHER) in argv


@pytest.mark.parametrize(
    ("relative", "expected", "replacement"),
    [
        ("artifact.json", '"version": "0.36.1"', '"version": "0.36.2"'),
        ("config.toml", "default_plan_mode = true", "default_plan_mode = false"),
        ("agents/agent.md", "tools: []", "tools: [AgenticOSPlannerNoToolSentinel]"),
        (
            "data-root-policy.json",
            '"workspace_authority": "NONE"',
            '"workspace_authority": "READ_WRITE"',
        ),
    ],
)
def test_la_c14_pin_revalidation_rejects_every_qualified_bundle_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    expected: str,
    replacement: str,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    drifted_bundle = tmp_path / "drifted-qualification"
    shutil.copytree(QUALIFIED_BUNDLE, drifted_bundle)
    target = drifted_bundle / relative
    source = target.read_text(encoding="utf-8")
    assert expected in source
    target.write_text(source.replace(expected, replacement, 1), encoding="utf-8")
    monkeypatch.setattr(
        local_auth_runtime,
        "_CANONICAL_LOCAL_AUTH_BUNDLE",
        drifted_bundle,
    )
    drifted = replace(spec, bundle=drifted_bundle)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        with pytest.raises(
            KimiLocalAuthRuntimeError, match="LOCAL_AUTH_PIN_RECHECK_FAILED"
        ):
            build_local_auth_bwrap_argv(drifted, credential)
    finally:
        credential.close()


def test_la_c14_pin_revalidation_runs_for_every_vector_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    mutable_bundle = tmp_path / "mutable-qualification"
    shutil.copytree(QUALIFIED_BUNDLE, mutable_bundle)
    monkeypatch.setattr(
        local_auth_runtime,
        "_CANONICAL_LOCAL_AUTH_BUNDLE",
        mutable_bundle,
    )
    candidate = replace(spec, bundle=mutable_bundle)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        build_local_auth_bwrap_argv(candidate, credential)
        config = mutable_bundle / "config.toml"
        source = config.read_text(encoding="utf-8")
        assert "default_plan_mode = true" in source
        config.write_text(
            source.replace("default_plan_mode = true", "default_plan_mode = false", 1),
            encoding="utf-8",
        )
        with pytest.raises(
            KimiLocalAuthRuntimeError, match="LOCAL_AUTH_PIN_RECHECK_FAILED"
        ):
            build_local_auth_bwrap_argv(candidate, credential)
    finally:
        credential.close()


@pytest.mark.parametrize("substitution", ["file", "symlink"])
def test_la_c14_pin_revalidation_rejects_executable_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    substitution: str,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    executable = tmp_path / "substituted-kimi"
    if substitution == "symlink":
        executable.symlink_to(PINNED_RUNTIME)
    else:
        executable.write_bytes(b"synthetic executable never invoked")
        executable.chmod(0o555)
    candidate = replace(spec, executable=executable)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        with pytest.raises(
            KimiLocalAuthRuntimeError, match="LOCAL_AUTH_PIN_RECHECK_FAILED"
        ):
            build_local_auth_bwrap_argv(candidate, credential)
    finally:
        credential.close()


def test_la_c14_pin_revalidation_rejects_bundle_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    bundle_link = tmp_path / "qualification-link"
    bundle_link.symlink_to(QUALIFIED_BUNDLE, target_is_directory=True)
    candidate = replace(spec, bundle=bundle_link)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        with pytest.raises(
            KimiLocalAuthRuntimeError, match="LOCAL_AUTH_PIN_RECHECK_FAILED"
        ):
            build_local_auth_bwrap_argv(candidate, credential)
    finally:
        credential.close()


def test_la_c14_pin_revalidation_rejects_bwrap_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    drifted_bwrap = tmp_path / "bwrap"
    drifted_bwrap.write_bytes(b"synthetic bwrap never invoked")
    drifted_bwrap.chmod(0o755)
    monkeypatch.setattr(kimi_runtime, "BWRAP", drifted_bwrap)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        with pytest.raises(
            KimiLocalAuthRuntimeError, match="LOCAL_AUTH_PIN_RECHECK_FAILED"
        ):
            build_local_auth_bwrap_argv(spec, credential)
    finally:
        credential.close()


def test_la_c14_byte_valid_copied_executable_is_not_canonical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    executable_copy = tmp_path / "kimi-copy"
    shutil.copyfile(PINNED_RUNTIME, executable_copy)
    executable_copy.chmod(0o555)
    passively_verified = kimi_runtime.build_runtime_spec(
        executable_copy,
        spec.bundle,
    )
    assert passively_verified.executable == executable_copy
    candidate = replace(spec, executable=executable_copy)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        with pytest.raises(
            KimiLocalAuthRuntimeError,
            match="LOCAL_AUTH_ARTIFACT_SUBSTITUTION",
        ):
            build_local_auth_bwrap_argv(candidate, credential)
    finally:
        credential.close()


def test_la_c14_byte_valid_copied_bundle_is_not_canonical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    bundle_copy = tmp_path / "qualification-copy"
    shutil.copytree(QUALIFIED_BUNDLE, bundle_copy)
    passively_verified = kimi_runtime.build_runtime_spec(
        spec.executable,
        bundle_copy,
    )
    assert passively_verified.bundle == bundle_copy
    candidate = replace(spec, bundle=bundle_copy)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        with pytest.raises(
            KimiLocalAuthRuntimeError,
            match="LOCAL_AUTH_ARTIFACT_SUBSTITUTION",
        ):
            build_local_auth_bwrap_argv(candidate, credential)
    finally:
        credential.close()


def test_la_c14_vector_consumes_passive_verifier_returned_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    verified_bundle = tmp_path / "verifier-returned-qualification"
    shutil.copytree(QUALIFIED_BUNDLE, verified_bundle)
    verified = kimi_runtime.KimiRuntimeSpec(
        executable=PINNED_RUNTIME,
        bundle=verified_bundle,
    )
    monkeypatch.setattr(
        local_auth_runtime,
        "_CANONICAL_LOCAL_AUTH_BUNDLE",
        verified_bundle,
    )
    def return_verified_runtime(
        executable: Path,
        bundle: Path,
    ) -> kimi_runtime.KimiRuntimeSpec:
        assert executable == PINNED_RUNTIME
        assert bundle == QUALIFIED_BUNDLE
        return verified

    monkeypatch.setattr(
        kimi_runtime,
        "build_runtime_spec",
        return_verified_runtime,
    )
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        argv = build_local_auth_bwrap_argv(spec, credential)
    finally:
        credential.close()
    assert str(verified_bundle / "config.toml") in argv
    assert str(verified_bundle / "agents") in argv
    assert str(QUALIFIED_BUNDLE / "config.toml") not in argv
    assert str(QUALIFIED_BUNDLE / "agents") not in argv


@pytest.mark.parametrize("substitution", ["file", "symlink"])
def test_la_c14_launcher_path_substitution_is_forbidden(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    substitution: str,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    launcher = tmp_path / "substituted-launcher.py"
    if substitution == "symlink":
        launcher.symlink_to(CANONICAL_LOCAL_AUTH_LAUNCHER)
    else:
        shutil.copyfile(CANONICAL_LOCAL_AUTH_LAUNCHER, launcher)
        launcher.chmod(0o644)
    candidate = replace(spec, namespace_launcher=launcher)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        with pytest.raises(
            KimiLocalAuthRuntimeError, match="LOCAL_AUTH_LAUNCHER_SUBSTITUTION"
        ):
            build_local_auth_bwrap_argv(candidate, credential)
    finally:
        credential.close()


def test_la_c14_canonical_launcher_symlink_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    target = tmp_path / "launcher-target.py"
    shutil.copyfile(CANONICAL_LOCAL_AUTH_LAUNCHER, target)
    target.chmod(0o644)
    launcher = tmp_path / "canonical-launcher.py"
    launcher.symlink_to(target)
    monkeypatch.setattr(
        local_auth_runtime,
        "_CANONICAL_LOCAL_AUTH_LAUNCHER",
        launcher,
    )
    candidate = replace(spec, namespace_launcher=launcher)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        with pytest.raises(
            KimiLocalAuthRuntimeError,
            match="LOCAL_AUTH_LAUNCHER_IDENTITY",
        ):
            build_local_auth_bwrap_argv(candidate, credential)
    finally:
        credential.close()


def test_la_c14_canonical_launcher_must_use_normalized_lexical_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    launcher = tmp_path / "canonical-launcher.py"
    shutil.copyfile(CANONICAL_LOCAL_AUTH_LAUNCHER, launcher)
    launcher.chmod(0o644)
    unused_directory = tmp_path / "unused"
    unused_directory.mkdir()
    nonnormalized = unused_directory / ".." / launcher.name
    monkeypatch.setattr(
        local_auth_runtime,
        "_CANONICAL_LOCAL_AUTH_LAUNCHER",
        nonnormalized,
    )
    candidate = replace(spec, namespace_launcher=nonnormalized)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        with pytest.raises(
            KimiLocalAuthRuntimeError,
            match="LOCAL_AUTH_LAUNCHER_IDENTITY",
        ):
            build_local_auth_bwrap_argv(candidate, credential)
    finally:
        credential.close()


def test_la_c14_canonical_launcher_hard_link_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    launcher = tmp_path / "canonical-launcher.py"
    shutil.copyfile(CANONICAL_LOCAL_AUTH_LAUNCHER, launcher)
    launcher.chmod(0o644)
    os.link(launcher, tmp_path / "launcher-hard-link.py")
    assert launcher.lstat().st_nlink == 2
    monkeypatch.setattr(
        local_auth_runtime,
        "_CANONICAL_LOCAL_AUTH_LAUNCHER",
        launcher,
    )
    candidate = replace(spec, namespace_launcher=launcher)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        with pytest.raises(
            KimiLocalAuthRuntimeError,
            match="LOCAL_AUTH_LAUNCHER_IDENTITY",
        ):
            build_local_auth_bwrap_argv(candidate, credential)
    finally:
        credential.close()


def test_la_c14_canonical_launcher_nonregular_type_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    launcher = tmp_path / "canonical-launcher.py"
    os.mkfifo(launcher, mode=0o644)
    assert stat.S_ISFIFO(launcher.lstat().st_mode)
    monkeypatch.setattr(
        local_auth_runtime,
        "_CANONICAL_LOCAL_AUTH_LAUNCHER",
        launcher,
    )
    def return_pinned_digest(path: Path) -> str:
        assert path == launcher
        return PINNED_LOCAL_AUTH_LAUNCHER_SHA256

    monkeypatch.setattr(
        local_auth_runtime,
        "sha256_file",
        return_pinned_digest,
    )
    candidate = replace(spec, namespace_launcher=launcher)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        with pytest.raises(
            KimiLocalAuthRuntimeError,
            match="LOCAL_AUTH_LAUNCHER_IDENTITY",
        ):
            build_local_auth_bwrap_argv(candidate, credential)
    finally:
        credential.close()


def test_la_c14_canonical_launcher_identity_must_remain_stable_while_hashed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    launcher = tmp_path / "canonical-launcher.py"
    shutil.copyfile(CANONICAL_LOCAL_AUTH_LAUNCHER, launcher)
    launcher.chmod(0o644)
    monkeypatch.setattr(
        local_auth_runtime,
        "_CANONICAL_LOCAL_AUTH_LAUNCHER",
        launcher,
    )
    real_sha256_file = local_auth_runtime.sha256_file

    def change_identity_after_hash(path: Path) -> str:
        digest = real_sha256_file(path)
        info = path.stat()
        os.utime(
            path,
            ns=(info.st_atime_ns, info.st_mtime_ns + 1),
        )
        return digest

    monkeypatch.setattr(
        local_auth_runtime,
        "sha256_file",
        change_identity_after_hash,
    )
    candidate = replace(spec, namespace_launcher=launcher)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        with pytest.raises(
            KimiLocalAuthRuntimeError,
            match="LOCAL_AUTH_LAUNCHER_IDENTITY",
        ):
            build_local_auth_bwrap_argv(candidate, credential)
    finally:
        credential.close()


@pytest.mark.parametrize("drift", ["content", "mode"])
def test_la_c14_canonical_launcher_identity_drift_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    spec = _local_auth_spec(tmp_path, monkeypatch)
    launcher = tmp_path / "canonical-launcher.py"
    shutil.copyfile(CANONICAL_LOCAL_AUTH_LAUNCHER, launcher)
    launcher.chmod(0o644)
    if drift == "content":
        launcher.write_bytes(launcher.read_bytes() + b"# identity drift\n")
    else:
        launcher.chmod(0o664)
    monkeypatch.setattr(
        local_auth_runtime,
        "_CANONICAL_LOCAL_AUTH_LAUNCHER",
        launcher,
        raising=False,
    )
    candidate = replace(spec, namespace_launcher=launcher)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    try:
        with pytest.raises(
            KimiLocalAuthRuntimeError, match="LOCAL_AUTH_LAUNCHER_IDENTITY"
        ):
            build_local_auth_bwrap_argv(candidate, credential)
    finally:
        credential.close()


@pytest.mark.parametrize(
    ("scenario", "expected_code"),
    [
        ("wrong-name", "CREDENTIAL_ENTRY_NAME"),
        ("unknown-sibling", "CREDENTIAL_ENTRY_NAME"),
        ("temp-sibling", "CREDENTIAL_TRANSIENT_PRESENT"),
        ("symlink", "CREDENTIAL_ENTRY_TYPE"),
        ("directory", "CREDENTIAL_ENTRY_TYPE"),
        ("fifo", "CREDENTIAL_ENTRY_TYPE"),
        ("mode", "CREDENTIAL_FILE_MODE"),
        ("uid", "CREDENTIAL_DIRECTORY_OWNER"),
        ("link-count", "CREDENTIAL_FILE_LINK_COUNT"),
    ],
)
def test_la_c06_through_c09_invalid_credential_metadata_blocks_before_open(
    tmp_path: Path,
    scenario: str,
    expected_code: str,
) -> None:
    state_root = make_structurally_valid_synthetic_state(tmp_path / "state")
    credential_root = state_root / "credentials"
    leaf = credential_root / "kimi-code.json"
    expected_uid = os.getuid()

    if scenario == "wrong-name":
        leaf.rename(credential_root / "unexpected.json")
    elif scenario == "unknown-sibling":
        sibling = credential_root / "other.json"
        sibling.write_bytes(b"synthetic sibling")
        sibling.chmod(0o600)
    elif scenario == "temp-sibling":
        sibling = credential_root / "kimi-code.json.tmp.1.deadbeef"
        sibling.write_bytes(b"synthetic transient")
        sibling.chmod(0o600)
    elif scenario == "symlink":
        target = tmp_path / "synthetic-target"
        target.write_bytes(b"synthetic target")
        leaf.unlink()
        leaf.symlink_to(target)
    elif scenario == "directory":
        leaf.unlink()
        leaf.mkdir()
    elif scenario == "fifo":
        leaf.unlink()
        os.mkfifo(leaf, mode=0o600)
    elif scenario == "mode":
        leaf.chmod(0o640)
    elif scenario == "uid":
        expected_uid += 1
    elif scenario == "link-count":
        os.link(leaf, tmp_path / "credential-hardlink")
    else:  # pragma: no cover - parametrization is closed above
        raise AssertionError(scenario)

    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        open_validated_credential_leaf(
            state_root,
            trusted_state_root=state_root,
            expected_uid=expected_uid,
        )
    assert rejected.value.code == expected_code


def test_la_c07_symlinked_credential_ancestry_blocks(tmp_path: Path) -> None:
    state_root = make_structurally_valid_synthetic_state(tmp_path / "real-state")
    alias = tmp_path / "state-alias"
    alias.symlink_to(state_root, target_is_directory=True)

    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        open_validated_credential_leaf(
            alias,
            trusted_state_root=alias,
            expected_uid=os.getuid(),
        )
    assert rejected.value.code == "CREDENTIAL_DIRECTORY_PATH"


def test_la_c09_group_writable_owned_credential_ancestry_blocks(
    tmp_path: Path,
) -> None:
    state_root = make_structurally_valid_synthetic_state(tmp_path / "state")
    state_root.chmod(0o770)

    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        open_validated_credential_leaf(
            state_root,
            trusted_state_root=state_root,
            expected_uid=os.getuid(),
        )
    assert rejected.value.code == "CREDENTIAL_DIRECTORY_MODE"


def test_la_c11_credential_path_replacement_after_open_blocks_and_closes_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = make_structurally_valid_synthetic_state(tmp_path / "state")
    leaf = state_root / "credentials" / "kimi-code.json"
    real_open = os.open
    opened_descriptors: list[int] = []

    def swap_after_open(path: os.PathLike[str] | str, flags: int, mode: int = 0o777) -> int:
        descriptor = real_open(path, flags, mode)
        if Path(path) == leaf:
            opened_descriptors.append(descriptor)
            leaf.rename(tmp_path / "opened-original")
            leaf.write_bytes(b"replacement synthetic credential\n")
            leaf.chmod(0o600)
        return descriptor

    monkeypatch.setattr(local_auth_runtime.os, "open", swap_after_open)

    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        open_validated_credential_leaf(
            state_root,
            trusted_state_root=state_root,
            expected_uid=os.getuid(),
        )
    assert rejected.value.code == "CREDENTIAL_INODE_CHANGED"
    assert len(opened_descriptors) == 1
    with pytest.raises(OSError) as closed:
        os.fstat(opened_descriptors[0])
    assert closed.value.errno == errno.EBADF


def test_la_e04_real_credential_root_is_allowed_but_crossovers_block(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_provider, real_evidence, workspace = isolate_real_roots(monkeypatch, tmp_path)
    make_private_evidence_root(real_evidence)
    make_private_evidence_root(workspace)

    exact_real_state = make_structurally_valid_synthetic_state(real_provider)
    handle = open_validated_credential_leaf(
        exact_real_state,
        trusted_state_root=exact_real_state,
        expected_uid=os.getuid(),
    )
    handle.close()

    crossover_roots = [
        make_structurally_valid_synthetic_state(real_provider / "nested"),
        make_structurally_valid_synthetic_state(real_evidence / "state"),
        make_structurally_valid_synthetic_state(workspace / "state"),
    ]
    for state_root in crossover_roots:
        with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
            open_validated_credential_leaf(
                state_root,
                trusted_state_root=state_root,
                expected_uid=os.getuid(),
            )
        assert rejected.value.code == "SYNTHETIC_REAL_CROSSOVER"


@pytest.mark.parametrize(
    "overlapped_boundary",
    ["real-provider", "real-evidence", "workspace"],
)
def test_la_e04_credential_root_ancestor_overlap_blocks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overlapped_boundary: str,
) -> None:
    state_root = make_structurally_valid_synthetic_state(tmp_path / "state")
    boundaries = {
        "real-provider": tmp_path / "reserved-real-provider",
        "real-evidence": tmp_path / "reserved-real-evidence",
        "workspace": tmp_path / "reserved-workspace",
    }
    boundaries[overlapped_boundary] = state_root / "reserved-descendant"
    monkeypatch.setattr(
        local_auth_runtime, "REAL_PROVIDER_STATE_ROOT", boundaries["real-provider"]
    )
    monkeypatch.setattr(
        local_auth_runtime, "REAL_EVIDENCE_ROOT", boundaries["real-evidence"]
    )
    monkeypatch.setattr(
        local_auth_runtime, "SANDBOX_WORKSPACE_ROOT", boundaries["workspace"]
    )

    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        open_validated_credential_leaf(
            state_root,
            trusted_state_root=state_root,
            expected_uid=os.getuid(),
        )
    assert rejected.value.code == "SYNTHETIC_REAL_CROSSOVER"


def test_la_e01_claim_marker_is_canonical_private_and_immutable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolate_real_roots(monkeypatch, tmp_path)
    evidence_root = make_private_evidence_root(tmp_path / "evidence")

    claim_real_attempt(
        evidence_root,
        candidate_commit=CANDIDATE_COMMIT,
        expected_uid=os.getuid(),
    )

    marker = evidence_root / "attempt.json"
    assert marker.read_bytes() == EXPECTED_ATTEMPT_BYTES
    marker_info = marker.lstat()
    assert stat.S_ISREG(marker_info.st_mode)
    assert stat.S_IMODE(marker_info.st_mode) == 0o600
    assert marker_info.st_uid == os.getuid()
    assert marker_info.st_nlink == 1

    with pytest.raises(KimiLocalAuthRuntimeError) as second:
        claim_real_attempt(
            evidence_root,
            candidate_commit=CANDIDATE_COMMIT,
            expected_uid=os.getuid(),
        )
    assert second.value.code == "ATTEMPT_ALREADY_CLAIMED"
    assert marker.read_bytes().endswith(b'"schema":"AOS_KIMI_LEVEL1_ATTEMPT/1"}\n')


def test_la_e01_group_writable_owned_evidence_ancestry_blocks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolate_real_roots(monkeypatch, tmp_path)
    unsafe_parent = tmp_path / "unsafe-parent"
    evidence_root = make_private_evidence_root(unsafe_parent / "evidence")
    unsafe_parent.chmod(0o770)

    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        claim_real_attempt(
            evidence_root,
            candidate_commit=CANDIDATE_COMMIT,
            expected_uid=os.getuid(),
        )
    assert rejected.value.code == "EVIDENCE_ROOT_MODE"
    assert not (evidence_root / "attempt.json").exists()


@pytest.mark.parametrize("existing_kind", ["symlink", "malformed"])
def test_la_e01_existing_symlink_or_malformed_marker_blocks_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing_kind: str,
) -> None:
    isolate_real_roots(monkeypatch, tmp_path)
    evidence_root = make_private_evidence_root(tmp_path / "evidence")
    marker = evidence_root / "attempt.json"
    if existing_kind == "symlink":
        target = tmp_path / "outside-marker"
        target.write_bytes(b"outside")
        marker.symlink_to(target)
    else:
        marker.write_bytes(b"{malformed")
        marker.chmod(0o600)

    before = marker.lstat()
    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        claim_real_attempt(
            evidence_root,
            candidate_commit=CANDIDATE_COMMIT,
            expected_uid=os.getuid(),
        )
    assert rejected.value.code == "ATTEMPT_ALREADY_CLAIMED"
    after = marker.lstat()
    assert (after.st_dev, after.st_ino, after.st_size) == (
        before.st_dev,
        before.st_ino,
        before.st_size,
    )


@pytest.mark.parametrize(
    "marker_fault",
    ["symlink", "malformed", "wrong-mode", "hard-link", "candidate-mismatch"],
)
def test_la_e01_persist_rejects_every_invalid_claim_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    marker_fault: str,
) -> None:
    isolate_real_roots(monkeypatch, tmp_path)
    evidence_root = make_private_evidence_root(tmp_path / "evidence")
    marker = evidence_root / "attempt.json"
    marker_bytes = EXPECTED_ATTEMPT_BYTES
    if marker_fault == "candidate-mismatch":
        marker_bytes = marker_bytes.replace(
            CANDIDATE_COMMIT.encode("ascii"),
            OTHER_CANDIDATE_COMMIT.encode("ascii"),
        )
    if marker_fault == "symlink":
        target = tmp_path / "outside-marker"
        target.write_bytes(marker_bytes)
        target.chmod(0o600)
        marker.symlink_to(target)
    else:
        marker.write_bytes(
            b"{malformed" if marker_fault == "malformed" else marker_bytes
        )
        marker.chmod(0o640 if marker_fault == "wrong-mode" else 0o600)
        if marker_fault == "hard-link":
            os.link(marker, tmp_path / "attempt-hard-link")
    protocol = LocalAuthProtocolOutcome(
        qualification=QualificationState.COMPLETE,
        credential_state=LocalCredentialState.LOADABLE,
    )

    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        persist_typed_result(
            evidence_root,
            protocol,
            {"process_count": 1, "cleanup_complete": True},
            candidate_commit=CANDIDATE_COMMIT,
            expected_uid=os.getuid(),
        )
    assert rejected.value.code == "ATTEMPT_MARKER_INVALID"
    assert not (evidence_root / "result.json").exists()


def test_la_e01_persist_accumulates_permitted_short_claim_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolate_real_roots(monkeypatch, tmp_path)
    evidence_root = make_private_evidence_root(tmp_path / "evidence")
    claim_real_attempt(
        evidence_root,
        candidate_commit=CANDIDATE_COMMIT,
        expected_uid=os.getuid(),
    )
    real_read = os.read

    def short_read(descriptor: int, count: int) -> bytes:
        return real_read(descriptor, min(count, 7))

    monkeypatch.setattr(local_auth_runtime.os, "read", short_read)
    protocol = LocalAuthProtocolOutcome(
        qualification=QualificationState.COMPLETE,
        credential_state=LocalCredentialState.LOADABLE,
    )

    persist_typed_result(
        evidence_root,
        protocol,
        {"process_count": 1, "cleanup_complete": True},
        candidate_commit=CANDIDATE_COMMIT,
        expected_uid=os.getuid(),
    )
    assert (evidence_root / "result.json").is_file()


def test_la_e01_persist_rejects_trailing_claim_bytes_after_an_exact_prefix_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolate_real_roots(monkeypatch, tmp_path)
    evidence_root = make_private_evidence_root(tmp_path / "evidence")
    marker = evidence_root / "attempt.json"
    marker.write_bytes(EXPECTED_ATTEMPT_BYTES + b"TRAILING")
    marker.chmod(0o600)
    real_read = os.read

    def exact_prefix_read(descriptor: int, count: int) -> bytes:
        return real_read(descriptor, min(count, len(EXPECTED_ATTEMPT_BYTES)))

    monkeypatch.setattr(local_auth_runtime.os, "read", exact_prefix_read)
    protocol = LocalAuthProtocolOutcome(
        qualification=QualificationState.COMPLETE,
        credential_state=LocalCredentialState.LOADABLE,
    )

    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        persist_typed_result(
            evidence_root,
            protocol,
            {"process_count": 1, "cleanup_complete": True},
            candidate_commit=CANDIDATE_COMMIT,
            expected_uid=os.getuid(),
        )
    assert rejected.value.code == "ATTEMPT_MARKER_INVALID"
    assert not (evidence_root / "result.json").exists()


def test_la_e03_typed_evidence_contains_only_literal_allowlisted_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolate_real_roots(monkeypatch, tmp_path)
    evidence_root = make_private_evidence_root(tmp_path / "evidence")
    claim_real_attempt(
        evidence_root,
        candidate_commit=CANDIDATE_COMMIT,
        expected_uid=os.getuid(),
    )
    protocol = LocalAuthProtocolOutcome(
        qualification=QualificationState.COMPLETE,
        credential_state=LocalCredentialState.LOADABLE,
    )

    persist_typed_result(
        evidence_root,
        protocol,
        {
            "process_count": 1,
            "descendant_count": 0,
            "external_endpoint_count": 0,
            "session_artifact_count": 0,
            "cleanup_complete": True,
        },
        candidate_commit=CANDIDATE_COMMIT,
        expected_uid=os.getuid(),
    )

    result_path = evidence_root / "result.json"
    assert json.loads(result_path.read_bytes()) == {
        "F1_KIMI_LEVEL1_LOCAL_AUTH_QUALIFICATION": "COMPLETE",
        "F1_KIMI_LOCAL_CREDENTIAL_STATE": "LOADABLE",
        "F1_KIMI_AUTH_STATE": "LOCAL_ONLY",
        "F1_KIMI_LEVEL2_NON_INFERENCE_STATUS": (
            "BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT"
        ),
        "reason_code": "ACP_LOCAL_AUTH_SUCCESS",
        "census_counts": {
            "process_count": 1,
            "descendant_count": 0,
            "external_endpoint_count": 0,
            "session_artifact_count": 0,
            "cleanup_complete": True,
        },
    }
    result_info = result_path.lstat()
    assert stat.S_IMODE(result_info.st_mode) == 0o600
    assert result_info.st_uid == os.getuid()
    assert result_info.st_nlink == 1
    assert SYNTHETIC_CREDENTIAL_BYTES not in result_path.read_bytes()

    with pytest.raises(KimiLocalAuthRuntimeError) as second:
        persist_typed_result(
            evidence_root,
            protocol,
            {"process_count": 1, "cleanup_complete": True},
            candidate_commit=CANDIDATE_COMMIT,
            expected_uid=os.getuid(),
        )
    assert second.value.code == "RESULT_ALREADY_PERSISTED"


@pytest.mark.parametrize(
    "census_counts",
    [
        {"credential_size": 40},
        {"credential_path": 1},
        {"unknown_count": 0},
        {"process_count": -1},
        {"process_count": True},
        {"cleanup_complete": 1},
    ],
)
def test_la_e03_typed_evidence_rejects_nonallowlisted_or_untyped_census(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    census_counts: dict[str, int | bool],
) -> None:
    isolate_real_roots(monkeypatch, tmp_path)
    evidence_root = make_private_evidence_root(tmp_path / "evidence")
    claim_real_attempt(
        evidence_root,
        candidate_commit=CANDIDATE_COMMIT,
        expected_uid=os.getuid(),
    )
    protocol = LocalAuthProtocolOutcome(
        qualification=QualificationState.COMPLETE,
        credential_state=LocalCredentialState.LOADABLE,
    )

    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        persist_typed_result(
            evidence_root,
            protocol,
            census_counts,
            candidate_commit=CANDIDATE_COMMIT,
            expected_uid=os.getuid(),
        )
    assert rejected.value.code == "RESULT_CENSUS_FIELDS"
    assert not (evidence_root / "result.json").exists()


def test_la_e03_rejected_typed_evidence_has_a_rejection_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolate_real_roots(monkeypatch, tmp_path)
    evidence_root = make_private_evidence_root(tmp_path / "evidence")
    claim_real_attempt(
        evidence_root,
        candidate_commit=CANDIDATE_COMMIT,
        expected_uid=os.getuid(),
    )
    session = _initialized_session()
    session.authenticate_request()
    session.accept(
        _line(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "error": {"code": -32000, "message": "synthetic rejection"},
            }
        )
    )

    persist_typed_result(
        evidence_root,
        session.finish(),
        {"process_count": 1, "cleanup_complete": True},
        candidate_commit=CANDIDATE_COMMIT,
        expected_uid=os.getuid(),
    )
    persisted = json.loads((evidence_root / "result.json").read_bytes())
    assert persisted["F1_KIMI_LEVEL1_LOCAL_AUTH_QUALIFICATION"] == "BLOCKED"
    assert persisted["F1_KIMI_LOCAL_CREDENTIAL_STATE"] == "REJECTED"
    assert persisted["reason_code"] == "ACP_LOCAL_AUTH_REJECTED"


@pytest.mark.parametrize(
    ("qualification", "credential_state", "reason_code"),
    [
        (
            QualificationState.BLOCKED,
            LocalCredentialState.LOADABLE,
            "ACP_LOCAL_AUTH_SUCCESS",
        ),
        (
            QualificationState.COMPLETE,
            LocalCredentialState.REJECTED,
            "ACP_LOCAL_AUTH_REJECTED",
        ),
        (
            QualificationState.COMPLETE,
            LocalCredentialState.BLOCKED,
            "ACP_LOCAL_AUTH_BLOCKED",
        ),
        (
            QualificationState.BLOCKED,
            LocalCredentialState.BLOCKED,
            "ARBITRARY_BLOCKED_REASON",
        ),
        (
            QualificationState.COMPLETE,
            LocalCredentialState.LOADABLE,
            "ACP_LOCAL_AUTH_REJECTED",
        ),
        (
            QualificationState.COMPLETE,
            LocalCredentialState.REJECTED,
            "ACP_LOCAL_AUTH_SUCCESS",
        ),
    ],
)
def test_la_e03_typed_evidence_rejects_every_nonmatrix_protocol_combination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    qualification: QualificationState,
    credential_state: LocalCredentialState,
    reason_code: str,
) -> None:
    isolate_real_roots(monkeypatch, tmp_path)
    evidence_root = make_private_evidence_root(tmp_path / "evidence")
    claim_real_attempt(
        evidence_root,
        candidate_commit=CANDIDATE_COMMIT,
        expected_uid=os.getuid(),
    )
    protocol = LocalAuthProtocolOutcome(
        qualification=qualification,
        credential_state=credential_state,
        reason_code=reason_code,
    )

    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        persist_typed_result(
            evidence_root,
            protocol,
            {"process_count": 1, "cleanup_complete": True},
            candidate_commit=CANDIDATE_COMMIT,
            expected_uid=os.getuid(),
        )
    assert rejected.value.code == "RESULT_PROTOCOL_COMBINATION"
    assert not (evidence_root / "result.json").exists()


def test_la_e03_typed_evidence_accepts_only_the_finite_blocked_combination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolate_real_roots(monkeypatch, tmp_path)
    evidence_root = make_private_evidence_root(tmp_path / "evidence")
    claim_real_attempt(
        evidence_root,
        candidate_commit=CANDIDATE_COMMIT,
        expected_uid=os.getuid(),
    )
    protocol = LocalAuthProtocolOutcome(
        qualification=QualificationState.BLOCKED,
        credential_state=LocalCredentialState.BLOCKED,
        reason_code="ACP_LOCAL_AUTH_BLOCKED",
    )

    persist_typed_result(
        evidence_root,
        protocol,
        {"process_count": 0, "cleanup_complete": True},
        candidate_commit=CANDIDATE_COMMIT,
        expected_uid=os.getuid(),
    )
    persisted = json.loads((evidence_root / "result.json").read_bytes())
    assert persisted["F1_KIMI_LEVEL1_LOCAL_AUTH_QUALIFICATION"] == "BLOCKED"
    assert persisted["F1_KIMI_LOCAL_CREDENTIAL_STATE"] == "BLOCKED"
    assert persisted["reason_code"] == "ACP_LOCAL_AUTH_BLOCKED"


@pytest.mark.parametrize(
    "reason_code",
    [
        "LOCAL_AUTH_TIMEOUT",
        "LOCAL_AUTH_PROCESS_CRASH",
        "LOCAL_AUTH_NETWORK_POLICY_VIOLATION",
        "LOCAL_AUTH_CENSUS_POLICY",
        "LOCAL_AUTH_CLEANUP_FAILED",
    ],
)
def test_la_e03_persists_exact_stable_runner_reason_without_raw_detail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reason_code: str,
) -> None:
    isolate_real_roots(monkeypatch, tmp_path)
    evidence_root = make_private_evidence_root(tmp_path / "evidence")
    claim_real_attempt(
        evidence_root,
        candidate_commit=CANDIDATE_COMMIT,
        expected_uid=os.getuid(),
    )

    persist_typed_result(
        evidence_root,
        LocalAuthProtocolOutcome(
            qualification=QualificationState.BLOCKED,
            credential_state=LocalCredentialState.BLOCKED,
            reason_code="ACP_LOCAL_AUTH_BLOCKED",
        ),
        {"process_count": 1, "cleanup_complete": True},
        reason_code=reason_code,
        candidate_commit=CANDIDATE_COMMIT,
        expected_uid=os.getuid(),
    )

    persisted = json.loads((evidence_root / "result.json").read_bytes())
    assert persisted["reason_code"] == reason_code
    assert set(persisted) == {
        "F1_KIMI_LEVEL1_LOCAL_AUTH_QUALIFICATION",
        "F1_KIMI_LOCAL_CREDENTIAL_STATE",
        "F1_KIMI_AUTH_STATE",
        "F1_KIMI_LEVEL2_NON_INFERENCE_STATUS",
        "reason_code",
        "census_counts",
    }


def test_la_e03_rejects_nonallowlisted_runner_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    isolate_real_roots(monkeypatch, tmp_path)
    evidence_root = make_private_evidence_root(tmp_path / "evidence")
    claim_real_attempt(
        evidence_root,
        candidate_commit=CANDIDATE_COMMIT,
        expected_uid=os.getuid(),
    )

    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        persist_typed_result(
            evidence_root,
            LocalAuthProtocolOutcome(
                qualification=QualificationState.BLOCKED,
                credential_state=LocalCredentialState.BLOCKED,
                reason_code="ACP_LOCAL_AUTH_BLOCKED",
            ),
            {"process_count": 1, "cleanup_complete": True},
            reason_code="RAW detail /home/aos/kimi/credentials/kimi-code.json",
            candidate_commit=CANDIDATE_COMMIT,
            expected_uid=os.getuid(),
        )
    assert rejected.value.code == "RESULT_REASON_CODE"
    assert not (evidence_root / "result.json").exists()


def test_la_e02_e04_evidence_root_crossovers_block_without_touching_real_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_provider, real_evidence, workspace = isolate_real_roots(monkeypatch, tmp_path)
    make_private_evidence_root(real_provider)
    make_private_evidence_root(real_evidence)
    make_private_evidence_root(workspace)

    claim_real_attempt(
        real_evidence,
        candidate_commit=CANDIDATE_COMMIT,
        expected_uid=os.getuid(),
    )
    assert (real_evidence / "attempt.json").is_file()

    crossover_roots = [
        real_provider,
        make_private_evidence_root(real_provider / "nested-evidence"),
        make_private_evidence_root(real_evidence / "nested-evidence"),
        workspace,
        make_private_evidence_root(workspace / "nested-evidence"),
    ]
    provider_alias = tmp_path / "provider-alias"
    provider_alias.symlink_to(real_provider, target_is_directory=True)
    crossover_roots.append(provider_alias)

    for evidence_root in crossover_roots:
        with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
            claim_real_attempt(
                evidence_root,
                candidate_commit=CANDIDATE_COMMIT,
                expected_uid=os.getuid(),
            )
        assert rejected.value.code == "SYNTHETIC_REAL_CROSSOVER"


@pytest.mark.parametrize(
    "overlapped_boundary",
    ["real-provider", "real-evidence", "workspace"],
)
def test_la_e04_evidence_root_ancestor_overlap_blocks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overlapped_boundary: str,
) -> None:
    evidence_root = make_private_evidence_root(tmp_path / "evidence")
    boundaries = {
        "real-provider": tmp_path / "reserved-real-provider",
        "real-evidence": tmp_path / "reserved-real-evidence",
        "workspace": tmp_path / "reserved-workspace",
    }
    boundaries[overlapped_boundary] = evidence_root / "reserved-descendant"
    monkeypatch.setattr(
        local_auth_runtime, "REAL_PROVIDER_STATE_ROOT", boundaries["real-provider"]
    )
    monkeypatch.setattr(
        local_auth_runtime, "REAL_EVIDENCE_ROOT", boundaries["real-evidence"]
    )
    monkeypatch.setattr(
        local_auth_runtime, "SANDBOX_WORKSPACE_ROOT", boundaries["workspace"]
    )

    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        claim_real_attempt(
            evidence_root,
            candidate_commit=CANDIDATE_COMMIT,
            expected_uid=os.getuid(),
        )
    assert rejected.value.code == "SYNTHETIC_REAL_CROSSOVER"
    assert not (evidence_root / "attempt.json").exists()


AUTHENTICATE_SUCCESS = _line(
    {"jsonrpc": "2.0", "id": 2, "result": None}
)
AUTHENTICATE_REJECTION = _line(
    {
        "jsonrpc": "2.0",
        "id": 2,
        "error": {"code": -32000, "message": "synthetic rejection"},
    }
)
EXPECTED_INITIALIZE_REQUEST = (
    b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":'
    b'{"protocolVersion":1,"clientCapabilities":{}}}\n'
)
EXPECTED_AUTHENTICATE_REQUEST = (
    b'{"jsonrpc":"2.0","id":2,"method":"authenticate",'
    b'"params":{"methodId":"login"}}\n'
)


class _RecordingInput:
    def __init__(self) -> None:
        self.writes: list[bytes] = []
        self.flush_count = 0
        self.closed = False

    def write(self, value: bytes) -> int:
        assert not self.closed
        self.writes.append(value)
        return len(value)

    def flush(self) -> None:
        assert not self.closed
        self.flush_count += 1

    def close(self) -> None:
        self.closed = True


class _StaticCaptureStream:
    def __init__(self, payload: bytes) -> None:
        self._stream = tempfile.TemporaryFile()
        self._stream.write(payload)
        self._stream.flush()
        self._stream.seek(0)

    def fileno(self) -> int:
        return self._stream.fileno()

    def close(self) -> None:
        self._stream.close()

    @property
    def closed(self) -> bool:
        return self._stream.closed


class _ScriptedProcess:
    def __init__(
        self,
        stdout: object,
        *,
        stderr: object | None = None,
        returncode: int | None = None,
        retain_capture_source: bool = False,
    ) -> None:
        self.pid = 4242
        self.stdin = _RecordingInput()
        self.stdout = (
            _StaticCaptureStream(stdout.getvalue())
            if isinstance(stdout, io.BytesIO)
            else stdout
        )
        stderr = io.BytesIO() if stderr is None else stderr
        self.stderr = (
            _StaticCaptureStream(stderr.getvalue())
            if isinstance(stderr, io.BytesIO)
            else stderr
        )
        self.returncode = returncode
        self.retain_capture_source = retain_capture_source
        self.frozen = False
        self.controller_signals: list[int] = []

    def poll(self) -> int | None:
        return self.returncode


class _LinesThenBlock:
    def __init__(self, lines: bytes) -> None:
        read_descriptor, self._write_descriptor = os.pipe()
        self._reader = os.fdopen(read_descriptor, "rb", buffering=0)
        os.write(self._write_descriptor, lines)

    def fileno(self) -> int:
        return self._reader.fileno()

    def close(self) -> None:
        self._reader.close()

    def release(self) -> None:
        if self._write_descriptor >= 0:
            os.close(self._write_descriptor)
            self._write_descriptor = -1


def _valid_runner_census(*, descendant_count: int = 0):
    return local_auth_runtime.LocalAuthCensus(
        process_count=1 + descendant_count,
        descendant_count=descendant_count,
        environment_names=(
            "HOME",
            "KIMI_CODE_HOME",
            "KIMI_CODE_NO_AUTO_UPDATE",
            "KIMI_DISABLE_CRON",
            "KIMI_DISABLE_TELEMETRY",
            "LANG",
            "LC_ALL",
            "PATH",
            "PWD",
            "TMPDIR",
        ),
        fd_classes=("pipe",),
        network_namespace="net:[4242]",
        external_endpoint_count=0,
        session_artifact_count=0,
        cleanup_complete=False,
    )


def _runner_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[KimiLocalAuthSpec, object]:
    isolate_real_roots(monkeypatch, tmp_path)
    spec = _local_auth_spec(tmp_path, monkeypatch)
    credential = open_validated_credential_leaf(
        spec.state_root,
        trusted_state_root=spec.state_root,
        expected_uid=os.getuid(),
    )
    monkeypatch.setattr(
        local_auth_runtime,
        "build_local_auth_bwrap_argv",
        lambda observed_spec, observed_credential: [
            "/usr/bin/bwrap",
            "--unshare-net",
            "--",
            "/usr/bin/python3",
            "/opt/agenticos/kimi/local_auth_namespace.py",
            str(observed_credential.device),
            str(observed_credential.inode),
        ]
        if observed_spec is spec
        else pytest.fail("runner changed the fixed spec"),
    )
    return spec, credential


def _run_scripted_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    process: _ScriptedProcess,
    *,
    census: object | None = None,
    census_effect: Callable[[_ScriptedProcess, list[str]], object] | None = None,
    drain_effect: Callable[[_ScriptedProcess], None] | None = None,
    drain_is_controller: bool = False,
    drain_error: bool = False,
    freeze_pending_reason: str | None = None,
    drain_pending_reason: str | None = None,
    monotonic: Callable[[], float] | None = None,
    timeout_seconds: float = 0.5,
):
    spec, credential = _runner_inputs(tmp_path, monkeypatch)
    launches: list[tuple[list[str], dict[str, object]]] = []
    drains: list[int] = []

    def process_factory(argv: list[str], **kwargs: object) -> _ScriptedProcess:
        launches.append((argv, kwargs))
        return process

    def freeze(
        observed: object,
        _deadline: float,
        _monotonic: Callable[[], float],
    ) -> local_auth_runtime.LocalAuthFreezeProvenance:
        assert observed is process
        process.frozen = True
        return local_auth_runtime.LocalAuthFreezeProvenance(
            leader_pid=process.pid,
            process_group_id=process.pid,
            member_pids=(process.pid,),
            controller_stop_sent=True,
            all_members_stopped=True,
            pending_signals_clear=freeze_pending_reason is None,
            pending_reason_code=freeze_pending_reason,
        )

    def drain(
        observed: object,
        frozen: local_auth_runtime.LocalAuthFreezeProvenance | None,
    ) -> local_auth_runtime.LocalAuthDrainProvenance:
        assert observed is process
        drains.append(process.pid)
        frozen_state_observed = (
            frozen is not None and process.frozen and process.returncode is None
        )
        if drain_error:
            raise RuntimeError("synthetic content-free drain failure")
        if drain_effect is not None:
            drain_effect(process)
        elif process.returncode is None:
            process.returncode = -signal.SIGKILL
            process.controller_signals.append(signal.SIGKILL)
        if drain_effect is not None and drain_is_controller:
            assert process.returncode in (-signal.SIGTERM, -signal.SIGKILL)
            process.controller_signals.append(-process.returncode)
        if not process.retain_capture_source:
            release = getattr(process.stdout, "release", None)
            if callable(release):
                release()
        controller_signal = (
            process.controller_signals[-1] if process.controller_signals else None
        )
        return local_auth_runtime.LocalAuthDrainProvenance(
            frozen=frozen,
            frozen_state_observed=frozen_state_observed,
            pending_signals_clear_before_kill=(
                frozen_state_observed and drain_pending_reason is None
            ),
            pending_reason_code=(
                drain_pending_reason
                if frozen_state_observed
                else "LOCAL_AUTH_PROCESS_CRASH"
            ),
            controller_signal=controller_signal,
            controller_signal_sent=controller_signal is not None,
            group_disappeared=process.returncode is not None,
            final_returncode=process.returncode,
        )

    runner_kwargs: dict[str, object] = {}
    if monotonic is not None:
        runner_kwargs["monotonic"] = monotonic
    outcome = local_auth_runtime.run_local_auth(
        spec,
        credential,
        process_factory=process_factory,
        census_sampler=lambda observed, argv: census_effect(process, argv)
        if census_effect is not None
        else (_valid_runner_census() if census is None else census),
        freeze_process=freeze,
        drain_process=drain,
        timeout_seconds=timeout_seconds,
        **runner_kwargs,
    )
    return outcome, credential, launches, drains


@pytest.mark.parametrize(
    ("terminal", "credential_state", "reason_code"),
    [
        (
            AUTHENTICATE_SUCCESS,
            LocalCredentialState.LOADABLE,
            "ACP_LOCAL_AUTH_SUCCESS",
        ),
        (
            AUTHENTICATE_REJECTION,
            LocalCredentialState.REJECTED,
            "ACP_LOCAL_AUTH_REJECTED",
        ),
    ],
)
def test_la_r01_runner_sends_only_initialize_then_authenticate_and_drains_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal: bytes,
    credential_state: LocalCredentialState,
    reason_code: str,
) -> None:
    process = _ScriptedProcess(io.BytesIO(INITIALIZE_SUCCESS + terminal))
    outcome, credential, launches, drains = _run_scripted_process(
        tmp_path, monkeypatch, process
    )

    assert outcome.protocol.credential_state is credential_state
    assert outcome.protocol.auth_state == "LOCAL_ONLY"
    assert outcome.protocol.level2_status == (
        "BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT"
    )
    assert outcome.reason_code == reason_code
    assert outcome.census.cleanup_complete is True
    assert process.stdin.writes == [
        EXPECTED_INITIALIZE_REQUEST,
        EXPECTED_AUTHENTICATE_REQUEST,
    ]
    assert process.stdin.flush_count == 2
    assert process.stdin.closed is True
    assert drains == [process.pid]
    assert process.frozen is True
    assert process.controller_signals == [signal.SIGKILL]
    assert credential._closed is True
    assert len(launches) == 1
    _argv, kwargs = launches[0]
    assert kwargs == {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": {},
        "close_fds": True,
        "pass_fds": (credential.descriptor,),
        "start_new_session": True,
    }


def test_la_r02_runner_pin_recheck_failure_closes_without_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, credential = _runner_inputs(tmp_path, monkeypatch)

    def fail_builder(_spec: object, _credential: object) -> list[str]:
        raise KimiLocalAuthRuntimeError("LOCAL_AUTH_PIN_RECHECK_FAILED")

    monkeypatch.setattr(
        local_auth_runtime,
        "build_local_auth_bwrap_argv",
        fail_builder,
    )
    outcome = local_auth_runtime.run_local_auth(
        spec,
        credential,
        process_factory=lambda *_args, **_kwargs: pytest.fail(
            "pin failure launched a process"
        ),
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.protocol.credential_state is LocalCredentialState.BLOCKED
    assert outcome.reason_code == "LOCAL_AUTH_PIN_RECHECK_FAILED"
    assert outcome.census.cleanup_complete is True
    assert credential._closed is True


@pytest.mark.parametrize(
    ("stdout", "returncode", "expected_reason"),
    [
        (
            _line({"jsonrpc": "2.0", "id": 99, "result": {}}),
            None,
            "UNEXPECTED_RESPONSE_ID",
        ),
        (b"", 7, "LOCAL_AUTH_PROCESS_CRASH"),
        (b"", -signal.SIGSYS, "LOCAL_AUTH_NETWORK_POLICY_VIOLATION"),
        (
            b"x" * 65_537 + b"\n",
            None,
            "LOCAL_AUTH_STDOUT_FRAME_LIMIT",
        ),
        (
            INITIALIZE_SUCCESS
            + AUTHENTICATE_SUCCESS
            + _line({"jsonrpc": "2.0", "method": "session/update", "params": {}}),
            None,
            "UNEXPECTED_CALLBACK",
        ),
    ],
)
def test_la_r02_r03_runner_blocks_wrong_crash_sigsys_overflow_and_callback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stdout: bytes,
    returncode: int | None,
    expected_reason: str,
) -> None:
    process = _ScriptedProcess(io.BytesIO(stdout), returncode=returncode)
    outcome, credential, launches, drains = _run_scripted_process(
        tmp_path, monkeypatch, process
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.protocol.credential_state is LocalCredentialState.BLOCKED
    assert outcome.protocol.auth_state == "LOCAL_ONLY"
    assert outcome.reason_code == expected_reason
    assert outcome.census.cleanup_complete is True
    assert credential._closed is True
    assert len(launches) == 1
    assert drains == [process.pid]


def test_la_r03_runner_blocks_bounded_stderr_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS),
        stderr=io.BytesIO(b"e" * 65_537),
    )
    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path, monkeypatch, process
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.reason_code == "LOCAL_AUTH_STDERR_LIMIT"
    assert drains == [process.pid]


def test_la_r03_runner_drains_stderr_before_closing_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS),
        stderr=io.BytesIO(b"e" * 65_537),
    )
    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path, monkeypatch, process
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.reason_code == "LOCAL_AUTH_STDERR_LIMIT"
    assert outcome.census.cleanup_complete is True
    assert drains == [process.pid]


def test_la_r01_runner_uses_one_nonresetting_timeout_and_drains(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    delayed = _LinesThenBlock(INITIALIZE_SUCCESS)
    process = _ScriptedProcess(delayed)
    try:
        outcome, credential, launches, drains = _run_scripted_process(
            tmp_path,
            monkeypatch,
            process,
            timeout_seconds=0.02,
        )
    finally:
        delayed.release()

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.reason_code == "LOCAL_AUTH_TIMEOUT"
    assert outcome.census.cleanup_complete is True
    assert credential._closed is True
    assert len(launches) == 1
    assert drains == [process.pid]
    assert process.stdin.writes == [
        EXPECTED_INITIALIZE_REQUEST,
        EXPECTED_AUTHENTICATE_REQUEST,
    ]


def test_la_r03_stuck_reader_blocks_even_after_valid_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blocked = _LinesThenBlock(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    process = _ScriptedProcess(blocked, retain_capture_source=True)
    threads_before = set(threading.enumerate())
    surviving_capture_threads: list[threading.Thread] = []
    started = time.monotonic()
    try:
        outcome, _credential, _launches, drains = _run_scripted_process(
            tmp_path,
            monkeypatch,
            process,
            timeout_seconds=0.05,
        )
        surviving_capture_threads = [
            thread
            for thread in threading.enumerate()
            if thread not in threads_before and thread.is_alive()
        ]
    finally:
        blocked.release()
        for thread in surviving_capture_threads:
            thread.join(timeout=1)
    elapsed = time.monotonic() - started

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.reason_code == "LOCAL_AUTH_CAPTURE_READER_STUCK"
    assert outcome.census.cleanup_complete is False
    assert drains == [process.pid]
    assert surviving_capture_threads == []
    assert elapsed < 0.5


def test_la_r03_sustained_readable_stdout_stops_at_first_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    )
    stdout_fd = process.stdout.fileno()
    original_read = os.read
    clock = [0.0]
    select_calls = [0]
    stdout_reads = [0]

    def always_readable(
        descriptors: list[int],
        _writable: list[int],
        _exceptional: list[int],
        _timeout: float,
    ) -> tuple[list[int], list[int], list[int]]:
        select_calls[0] += 1
        clock[0] += 0.001
        if select_calls[0] > 20:
            raise OSError("synthetic select budget exhausted")
        return list(descriptors), [], []

    def sustained_read(descriptor: int, size: int) -> bytes:
        if descriptor != stdout_fd:
            return original_read(descriptor, size)
        stdout_reads[0] += 1
        if stdout_reads[0] == 1:
            return original_read(descriptor, size)
        return b"x" * 8_192

    monkeypatch.setattr(local_auth_runtime.select, "select", always_readable)
    monkeypatch.setattr(local_auth_runtime.os, "read", sustained_read)

    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path,
        monkeypatch,
        process,
        monotonic=lambda: clock[0],
        timeout_seconds=0.05,
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.reason_code == "LOCAL_AUTH_STDOUT_FRAME_LIMIT"
    assert drains == [process.pid]
    assert stdout_reads == [10]
    assert select_calls == [10]
    assert process.stdout.closed is True
    assert process.stderr.closed is True


def test_la_r03_repeated_eagain_makes_bounded_no_progress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    )
    stdout_fd = process.stdout.fileno()
    original_read = os.read
    clock = [0.0]
    select_calls = [0]
    stdout_reads = [0]

    def spuriously_readable(
        descriptors: list[int],
        _writable: list[int],
        _exceptional: list[int],
        _timeout: float,
    ) -> tuple[list[int], list[int], list[int]]:
        select_calls[0] += 1
        clock[0] += 0.001
        if select_calls[0] > 12:
            raise OSError("synthetic EAGAIN spin budget exhausted")
        return list(descriptors), [], []

    def eagain_after_terminal(descriptor: int, size: int) -> bytes:
        if descriptor != stdout_fd:
            return original_read(descriptor, size)
        stdout_reads[0] += 1
        if stdout_reads[0] == 1:
            return original_read(descriptor, size)
        raise BlockingIOError(errno.EAGAIN, "synthetic no progress")

    monkeypatch.setattr(local_auth_runtime.select, "select", spuriously_readable)
    monkeypatch.setattr(local_auth_runtime.os, "read", eagain_after_terminal)

    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path,
        monkeypatch,
        process,
        monotonic=lambda: clock[0],
        timeout_seconds=0.05,
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.reason_code == "LOCAL_AUTH_CAPTURE_READER_STUCK"
    assert outcome.census.cleanup_complete is False
    assert drains == [process.pid]
    assert stdout_reads[0] <= 4
    assert select_calls[0] <= 4
    assert process.stdout.closed is True
    assert process.stderr.closed is True


def test_la_r03_capture_discards_retained_bytes_at_first_limit() -> None:
    stdout = _StaticCaptureStream(b"")
    stderr = _StaticCaptureStream(b"")
    capture = local_auth_runtime._LocalAuthCapture(stdout, stderr)
    try:
        capture._consume_stdout(b"x" * (65_536 + 1))
        with pytest.raises(local_auth_runtime._LocalAuthRunFailure) as rejected:
            capture._raise_error()
        assert rejected.value.code == "LOCAL_AUTH_STDOUT_FRAME_LIMIT"
        assert capture._stdout_buffer == bytearray()
        assert tuple(capture._frames) == ()

        capture._consume_stdout(b"must-not-be-retained")
        assert capture._stdout_buffer == bytearray()
        assert tuple(capture._frames) == ()
    finally:
        stdout.close()
        stderr.close()


def test_la_r03_capture_preserves_exact_frame_and_count_bounds() -> None:
    stdout = _StaticCaptureStream(b"")
    stderr = _StaticCaptureStream(b"")
    capture = local_auth_runtime._LocalAuthCapture(stdout, stderr)
    try:
        capture._consume_stdout((b"x" * 65_535) + b"\n")
        capture._raise_error()
        assert tuple(map(len, capture._frames)) == (65_536,)

        capture._frames.clear()
        capture._frame_count = 0
        capture._consume_stdout(b"{}\n" * 4)
        capture._raise_error()
        assert tuple(capture._frames) == (b"{}\n",) * 4

        capture._consume_stdout(b"{}\n")
        with pytest.raises(local_auth_runtime._LocalAuthRunFailure) as rejected:
            capture._raise_error()
        assert rejected.value.code == "LOCAL_AUTH_STDOUT_FRAME_COUNT"
        assert capture._stdout_buffer == bytearray()
        assert tuple(capture._frames) == ()
    finally:
        stdout.close()
        stderr.close()


def test_la_r03_select_error_is_typed_and_drains_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    )

    def fail_select(*_args: object) -> tuple[list[int], list[int], list[int]]:
        raise OSError("synthetic select failure")

    monkeypatch.setattr(local_auth_runtime.select, "select", fail_select)
    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path,
        monkeypatch,
        process,
    )

    assert outcome.reason_code == "LOCAL_AUTH_CAPTURE_READER_FAILED"
    assert drains == [process.pid]
    assert process.stdout.closed is True
    assert process.stderr.closed is True


@pytest.mark.parametrize("fault_stream", ["stdout", "stderr"])
def test_la_r03_stream_read_error_is_typed_and_drains_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_stream: str,
) -> None:
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    )
    fault_fd = getattr(process, fault_stream).fileno()
    original_read = os.read

    def fail_one_stream(descriptor: int, size: int) -> bytes:
        if descriptor == fault_fd:
            raise OSError("synthetic stream read failure")
        return original_read(descriptor, size)

    monkeypatch.setattr(local_auth_runtime.os, "read", fail_one_stream)
    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path,
        monkeypatch,
        process,
    )

    assert outcome.reason_code == "LOCAL_AUTH_CAPTURE_READER_FAILED"
    assert drains == [process.pid]
    assert process.stdout.closed is True
    assert process.stderr.closed is True


def test_la_r05_r07_descendant_or_cleanup_uncertainty_cannot_succeed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    )
    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path,
        monkeypatch,
        process,
        census=_valid_runner_census(descendant_count=1),
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.reason_code == "LOCAL_AUTH_CENSUS_POLICY"
    assert outcome.census.descendant_count == 1
    assert outcome.census.cleanup_complete is True
    assert drains == [process.pid]


def test_la_r07_drain_uncertainty_blocks_valid_authentication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    )
    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path,
        monkeypatch,
        process,
        drain_error=True,
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.protocol.credential_state is LocalCredentialState.BLOCKED
    assert outcome.reason_code == "LOCAL_AUTH_CLEANUP_FAILED"
    assert outcome.census.cleanup_complete is False
    assert drains == [process.pid]


@pytest.mark.parametrize(
    ("late_returncode", "expected_reason"),
    [
        (-signal.SIGSYS, "LOCAL_AUTH_NETWORK_POLICY_VIOLATION"),
        (-signal.SIGTERM, "LOCAL_AUTH_PROCESS_CRASH"),
        (9, "LOCAL_AUTH_PROCESS_CRASH"),
    ],
)
def test_la_r07_late_exit_during_census_cannot_retain_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    late_returncode: int,
    expected_reason: str,
) -> None:
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    )

    def census_effect(
        observed: _ScriptedProcess,
        _argv: list[str],
    ) -> local_auth_runtime.LocalAuthCensus:
        observed.returncode = late_returncode
        return _valid_runner_census()

    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path,
        monkeypatch,
        process,
        census_effect=census_effect,
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.reason_code == expected_reason
    assert drains == [process.pid]


@pytest.mark.parametrize(
    ("late_returncode", "expected_reason"),
    [
        (-signal.SIGSYS, "LOCAL_AUTH_NETWORK_POLICY_VIOLATION"),
        (-signal.SIGTERM, "LOCAL_AUTH_PROCESS_CRASH"),
        (-signal.SIGKILL, "LOCAL_AUTH_PROCESS_CRASH"),
        (9, "LOCAL_AUTH_PROCESS_CRASH"),
    ],
)
def test_la_r07_independent_signal_during_drain_cannot_retain_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    late_returncode: int,
    expected_reason: str,
) -> None:
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    )
    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path,
        monkeypatch,
        process,
        drain_effect=lambda observed: setattr(
            observed,
            "returncode",
            late_returncode,
        ),
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.reason_code == expected_reason
    assert drains == [process.pid]


def test_la_r07_only_typed_controller_sigkill_action_can_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller_signal = signal.SIGKILL
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    )
    frozen_at_census: list[bool] = []

    def census_effect(
        observed: _ScriptedProcess,
        _argv: list[str],
    ) -> local_auth_runtime.LocalAuthCensus:
        frozen_at_census.append(observed.frozen)
        return _valid_runner_census()

    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path,
        monkeypatch,
        process,
        census_effect=census_effect,
        drain_effect=lambda observed: setattr(
            observed,
            "returncode",
            -controller_signal,
        ),
        drain_is_controller=True,
    )

    assert outcome.protocol.qualification is QualificationState.COMPLETE
    assert outcome.reason_code == "ACP_LOCAL_AUTH_SUCCESS"
    assert outcome.census.cleanup_complete is True
    assert process.frozen is True
    assert frozen_at_census == [True]
    assert process.controller_signals == [controller_signal]
    assert drains == [process.pid]


def test_la_r07_injected_controller_sigterm_cannot_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    )
    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path,
        monkeypatch,
        process,
        drain_effect=lambda observed: setattr(
            observed,
            "returncode",
            -signal.SIGTERM,
        ),
        drain_is_controller=True,
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.reason_code == "LOCAL_AUTH_PROCESS_CRASH"
    assert outcome.census.cleanup_complete is True
    assert process.controller_signals == [signal.SIGTERM]
    assert drains == [process.pid]


@pytest.mark.parametrize(
    ("status", "expected_clear", "expected_reason"),
    [
        (
            "Name:\tpython3\nSigPnd:\t0000000000000000\n"
            "ShdPnd:\t0000000000000000\n",
            True,
            None,
        ),
        (
            "Name:\tpython3\nSigPnd:\t0000000000000000\n"
            f"ShdPnd:\t{1 << (signal.SIGTERM - 1):016x}\n",
            False,
            "LOCAL_AUTH_PROCESS_CRASH",
        ),
        (
            f"SigPnd:\t{1 << (signal.SIGSYS - 1):016x}\n"
            "ShdPnd:\t0000000000000000\n",
            False,
            "LOCAL_AUTH_NETWORK_POLICY_VIOLATION",
        ),
    ],
)
def test_la_r07_pending_signal_status_reduces_to_typed_provenance(
    status: str,
    expected_clear: bool,
    expected_reason: str | None,
) -> None:
    observed = local_auth_runtime._parse_pending_signal_status(status)

    assert observed == (expected_clear, expected_reason)


@pytest.mark.parametrize(
    "status",
    [
        "SigPnd:\t0000000000000000\n",
        "ShdPnd:\t0000000000000000\n",
        (
            "SigPnd:\t0000000000000000\n"
            "SigPnd:\t0000000000000000\n"
            "ShdPnd:\t0000000000000000\n"
        ),
        "SigPnd:\tgarbage\nShdPnd:\t0000000000000000\n",
        "SigPnd:\t00000000000000000\nShdPnd:\t0000000000000000\n",
    ],
)
def test_la_r07_pending_signal_status_is_strict_and_fail_closed(
    status: str,
) -> None:
    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        local_auth_runtime._parse_pending_signal_status(status)
    assert rejected.value.code == "LOCAL_AUTH_FREEZE_FAILED"


@pytest.mark.parametrize(
    "pending_reason",
    [
        "LOCAL_AUTH_PROCESS_CRASH",
        "LOCAL_AUTH_NETWORK_POLICY_VIOLATION",
    ],
)
def test_la_r07_pre_census_pending_signal_blocks_with_typed_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pending_reason: str,
) -> None:
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    )
    census_calls: list[int] = []

    def forbidden_census(
        observed: _ScriptedProcess,
        _argv: list[str],
    ) -> local_auth_runtime.LocalAuthCensus:
        census_calls.append(observed.pid)
        return _valid_runner_census()

    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path,
        monkeypatch,
        process,
        census_effect=forbidden_census,
        freeze_pending_reason=pending_reason,
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.reason_code == pending_reason
    assert census_calls == []
    assert drains == [process.pid]


@pytest.mark.parametrize(
    "pending_reason",
    [
        "LOCAL_AUTH_PROCESS_CRASH",
        "LOCAL_AUTH_NETWORK_POLICY_VIOLATION",
    ],
)
def test_la_r07_pre_kill_pending_signal_blocks_with_typed_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pending_reason: str,
) -> None:
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    )
    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path,
        monkeypatch,
        process,
        drain_pending_reason=pending_reason,
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.reason_code == pending_reason
    assert outcome.census.cleanup_complete is True
    assert process.controller_signals == [signal.SIGKILL]
    assert drains == [process.pid]


def test_la_r07_drain_must_return_final_termination_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    )
    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path,
        monkeypatch,
        process,
        drain_effect=lambda _observed: None,
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.reason_code == "LOCAL_AUTH_CLEANUP_FAILED"
    assert outcome.census.cleanup_complete is False
    assert drains == [process.pid]


def test_la_r01_slow_census_cannot_complete_after_absolute_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    )

    def census_effect(
        _observed: _ScriptedProcess,
        _argv: list[str],
    ) -> local_auth_runtime.LocalAuthCensus:
        clock[0] = 0.6
        return _valid_runner_census()

    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path,
        monkeypatch,
        process,
        census_effect=census_effect,
        monotonic=lambda: clock[0],
        timeout_seconds=0.5,
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.reason_code == "LOCAL_AUTH_TIMEOUT"
    assert outcome.census.cleanup_complete is True
    assert drains == [process.pid]


def test_la_r01_slow_cleanup_cannot_complete_after_absolute_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [0.0]
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    )

    def slow_drain(observed: _ScriptedProcess) -> None:
        clock[0] = 0.6
        observed.returncode = -signal.SIGKILL

    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path,
        monkeypatch,
        process,
        drain_effect=slow_drain,
        drain_is_controller=True,
        monotonic=lambda: clock[0],
        timeout_seconds=0.5,
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.reason_code == "LOCAL_AUTH_TIMEOUT"
    assert outcome.census.cleanup_complete is True
    assert drains == [process.pid]


@pytest.mark.parametrize(
    "census",
    [
        replace(
            _valid_runner_census(),
            environment_names=(*_valid_runner_census().environment_names, "TOKEN"),
        ),
        replace(_valid_runner_census(), fd_classes=("pipe", "socket")),
        replace(_valid_runner_census(), network_namespace="host-net"),
        replace(_valid_runner_census(), external_endpoint_count=1),
        replace(_valid_runner_census(), session_artifact_count=1),
    ],
)
def test_la_r05_r06_every_census_policy_violation_blocks_without_raw_detail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    census: object,
) -> None:
    process = _ScriptedProcess(
        io.BytesIO(INITIALIZE_SUCCESS + AUTHENTICATE_SUCCESS)
    )
    outcome, _credential, _launches, drains = _run_scripted_process(
        tmp_path,
        monkeypatch,
        process,
        census=census,
    )

    assert outcome.protocol.qualification is QualificationState.BLOCKED
    assert outcome.protocol.credential_state is LocalCredentialState.BLOCKED
    assert outcome.reason_code == "LOCAL_AUTH_CENSUS_POLICY"
    assert "TOKEN" not in outcome.reason_code
    assert drains == [process.pid]


def test_la_r06_content_free_artifact_census_covers_workspace_home_and_tmp(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox-root"
    (sandbox / "workspace").mkdir(parents=True)
    (sandbox / "tmp").mkdir()
    kimi_home = sandbox / "home" / "aos" / "kimi"
    (kimi_home / "agents").mkdir(parents=True)
    (kimi_home / "credentials").mkdir()
    (kimi_home / "config.toml").write_text("synthetic config\n", encoding="utf-8")
    (kimi_home / "agents" / "agent.md").write_text(
        "synthetic agent\n", encoding="utf-8"
    )
    (kimi_home / "credentials" / "kimi-code.json").write_text(
        "synthetic credential never read by production\n",
        encoding="utf-8",
    )

    assert local_auth_runtime._count_sandbox_artifacts(sandbox) == 0
    (sandbox / "workspace" / "unexpected-state").write_text(
        "synthetic workspace canary\n", encoding="utf-8"
    )
    (kimi_home / "cache.db").write_text("synthetic cache\n", encoding="utf-8")
    (sandbox / "tmp" / "state.bin").write_text(
        "synthetic temp canary\n", encoding="utf-8"
    )
    assert local_auth_runtime._count_sandbox_artifacts(sandbox) == 3


@pytest.mark.parametrize("unexpected_kind", ["file", "directory", "symlink"])
def test_la_r06_artifact_census_counts_every_unexpected_agents_entry(
    tmp_path: Path,
    unexpected_kind: str,
) -> None:
    sandbox = tmp_path / "sandbox-root"
    (sandbox / "workspace").mkdir(parents=True)
    (sandbox / "tmp").mkdir()
    kimi_home = sandbox / "home" / "aos" / "kimi"
    agents = kimi_home / "agents"
    agents.mkdir(parents=True)
    (kimi_home / "credentials").mkdir()
    (kimi_home / "config.toml").write_text("synthetic config\n", encoding="utf-8")
    (agents / "agent.md").write_text("synthetic agent\n", encoding="utf-8")
    (kimi_home / "credentials" / "kimi-code.json").write_text(
        "synthetic credential never read by production\n",
        encoding="utf-8",
    )
    unexpected = agents / "state.bin"
    if unexpected_kind == "file":
        unexpected.write_text("synthetic state\n", encoding="utf-8")
    elif unexpected_kind == "directory":
        unexpected.mkdir()
    else:
        unexpected.symlink_to(agents / "agent.md")

    assert local_auth_runtime._count_sandbox_artifacts(sandbox) == 1


@pytest.mark.parametrize("agent_fault", ["missing", "directory", "symlink"])
def test_la_r06_artifact_census_requires_regular_nonsymlink_agent_file(
    tmp_path: Path,
    agent_fault: str,
) -> None:
    sandbox = tmp_path / "sandbox-root"
    (sandbox / "workspace").mkdir(parents=True)
    (sandbox / "tmp").mkdir()
    kimi_home = sandbox / "home" / "aos" / "kimi"
    agents = kimi_home / "agents"
    agents.mkdir(parents=True)
    (kimi_home / "credentials").mkdir()
    (kimi_home / "config.toml").write_text("synthetic config\n", encoding="utf-8")
    (kimi_home / "credentials" / "kimi-code.json").write_text(
        "synthetic credential never read by production\n",
        encoding="utf-8",
    )
    agent = agents / "agent.md"
    if agent_fault == "directory":
        agent.mkdir()
    elif agent_fault == "symlink":
        agent.symlink_to(kimi_home / "config.toml")

    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        local_auth_runtime._count_sandbox_artifacts(sandbox)
    assert rejected.value.code == "LOCAL_AUTH_CENSUS_FAILED"


@pytest.mark.parametrize(
    "relative",
    [Path("workspace"), Path("tmp"), Path("home/aos/kimi")],
)
def test_la_r06_artifact_census_fails_closed_on_missing_sandbox_root(
    tmp_path: Path,
    relative: Path,
) -> None:
    sandbox = tmp_path / "sandbox-root"
    (sandbox / "workspace").mkdir(parents=True)
    (sandbox / "tmp").mkdir()
    (sandbox / "home" / "aos" / "kimi").mkdir(parents=True)
    shutil.rmtree(sandbox / relative)

    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        local_auth_runtime._count_sandbox_artifacts(sandbox)
    assert rejected.value.code == "LOCAL_AUTH_CENSUS_FAILED"


@pytest.mark.parametrize(
    "relative",
    [
        Path("home/aos/kimi/config.toml"),
        Path("home/aos/kimi/agents"),
        Path("home/aos/kimi/credentials/kimi-code.json"),
    ],
)
def test_la_r06_artifact_census_requires_every_fixed_source_backed_input(
    tmp_path: Path,
    relative: Path,
) -> None:
    sandbox = tmp_path / "sandbox-root"
    (sandbox / "workspace").mkdir(parents=True)
    (sandbox / "tmp").mkdir()
    kimi_home = sandbox / "home" / "aos" / "kimi"
    (kimi_home / "agents").mkdir(parents=True)
    (kimi_home / "credentials").mkdir()
    (kimi_home / "config.toml").write_text("synthetic config\n", encoding="utf-8")
    (kimi_home / "credentials" / "kimi-code.json").write_text(
        "synthetic credential never read by production\n",
        encoding="utf-8",
    )
    target = sandbox / relative
    if target.is_dir():
        target.rmdir()
    else:
        target.unlink()

    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        local_auth_runtime._count_sandbox_artifacts(sandbox)
    assert rejected.value.code == "LOCAL_AUTH_CENSUS_FAILED"


def _write_scope_files(
    root: Path,
    *,
    maximum: str = "21",
    current: str = "1",
    events: str = "max 0",
    memory: str = "1073741824",
) -> str:
    relative = "/user.slice/aos-kimi-level1-local-auth.scope"
    scope = root / relative.removeprefix("/")
    scope.mkdir(parents=True)
    (scope / "pids.max").write_text(maximum + "\n", encoding="ascii")
    (scope / "pids.current").write_text(current + "\n", encoding="ascii")
    (scope / "pids.events").write_text(events + "\n", encoding="ascii")
    (scope / "memory.max").write_text(memory + "\n", encoding="ascii")
    return f"0::{relative}\n"


def test_la_r05_scope_admits_only_exact_finite_fresh_budget(tmp_path: Path) -> None:
    cgroup_text = _write_scope_files(tmp_path)
    assert (
        local_auth_runtime.validate_local_auth_scope(
            cgroup_text,
            cgroup_root=tmp_path,
        )
        is None
    )


@pytest.mark.parametrize(
    ("field", "value", "expected_code"),
    [
        ("maximum", "max", "LOCAL_AUTH_SCOPE_TASKS_MAX"),
        ("maximum", "20", "LOCAL_AUTH_SCOPE_TASKS_MAX"),
        ("maximum", "22", "LOCAL_AUTH_SCOPE_TASKS_MAX"),
        ("current", "2", "LOCAL_AUTH_SCOPE_NOT_EMPTY"),
        ("events", "max 1", "LOCAL_AUTH_SCOPE_EXHAUSTED"),
        ("memory", "1073741823", "LOCAL_AUTH_SCOPE_MEMORY_MAX"),
        ("memory", "max", "LOCAL_AUTH_SCOPE_MEMORY_MAX"),
    ],
)
def test_la_r05_scope_rejects_every_budget_drift(
    tmp_path: Path,
    field: str,
    value: str,
    expected_code: str,
) -> None:
    values = {
        "maximum": "21",
        "current": "1",
        "events": "max 0",
        "memory": "1073741824",
    }
    values[field] = value
    cgroup_text = _write_scope_files(tmp_path, **values)

    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        local_auth_runtime.validate_local_auth_scope(
            cgroup_text,
            cgroup_root=tmp_path,
        )
    assert rejected.value.code == expected_code


@pytest.mark.parametrize(
    "cgroup_text",
    [
        "",
        "0::/user.slice/aos-kimi-owner-login.scope\n",
        "0::/user.slice/aos-kimi-level1-local-auth.scope/child\n",
        "0::/user.slice/../aos-kimi-level1-local-auth.scope\n",
        "0::/first/aos-kimi-level1-local-auth.scope\n0::/second\n",
    ],
)
def test_la_r05_scope_rejects_wrong_or_ambiguous_membership(
    tmp_path: Path,
    cgroup_text: str,
) -> None:
    with pytest.raises(KimiLocalAuthRuntimeError) as rejected:
        local_auth_runtime.validate_local_auth_scope(
            cgroup_text,
            cgroup_root=tmp_path,
        )
    assert rejected.value.code == "LOCAL_AUTH_SCOPE_REQUIRED"


def test_la_r05_systemd_vector_is_fixed_and_has_no_shell_or_redirect() -> None:
    command = local_auth_runtime.local_auth_systemd_command(CANDIDATE_COMMIT)
    assert command == [
        "/usr/bin/systemd-run",
        "--user",
        "--scope",
        "--collect",
        "--quiet",
        "--unit=aos-kimi-level1-local-auth",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=5s",
        "--property=TasksMax=21",
        "--property=MemoryMax=1G",
        "/usr/bin/python3",
        "/home/brand/src/AgenticOS/scripts/run_kimi_local_auth.py",
        "--expected-commit",
        CANDIDATE_COMMIT,
    ]
    assert not any(
        item in command
        for item in ("sh", "bash", "tee", ">", "--retry", "--network")
    )


def _install_cli_happy_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[list[str], object]:
    calls: list[str] = []
    spec = KimiLocalAuthSpec(
        executable=Path("/qualified/kimi"),
        bundle=Path("/qualified/bundle"),
        namespace_launcher=Path("/qualified/launcher.py"),
        state_root=Path("/real/state"),
        evidence_root=Path("/real/evidence"),
    )

    class Credential:
        descriptor = 9
        _closed = False

        def close(self) -> None:
            self._closed = True

    credential = Credential()
    outcome = local_auth_runtime.LocalAuthRunOutcome(
        protocol=LocalAuthProtocolOutcome(
            qualification=QualificationState.COMPLETE,
            credential_state=LocalCredentialState.LOADABLE,
        ),
        census=replace(_valid_runner_census(), cleanup_complete=True),
        reason_code="ACP_LOCAL_AUTH_SUCCESS",
    )

    monkeypatch.setattr(
        local_auth_runtime,
        "_validate_local_auth_script",
        lambda: calls.append("script"),
    )
    monkeypatch.setattr(
        local_auth_runtime,
        "_read_self_cgroup",
        lambda: "0::/user.slice/aos-kimi-level1-local-auth.scope\n",
    )
    monkeypatch.setattr(
        local_auth_runtime,
        "validate_local_auth_scope",
        lambda _text: calls.append("scope"),
    )
    monkeypatch.setattr(
        local_auth_runtime,
        "validate_repository_identity",
        lambda _root, _commit: calls.append("repository"),
    )
    monkeypatch.setattr(
        local_auth_runtime,
        "default_local_auth_spec",
        lambda: calls.append("spec_factory") or spec,
    )
    monkeypatch.setattr(
        local_auth_runtime,
        "validate_local_auth_spec",
        lambda _spec, **_kwargs: calls.append("runtime"),
    )
    monkeypatch.setattr(
        local_auth_runtime,
        "validate_pre_real_gate",
        lambda _root, _commit: calls.append("gate"),
    )
    monkeypatch.setattr(
        local_auth_runtime,
        "open_validated_credential_leaf",
        lambda *_args, **_kwargs: calls.append("credential") or credential,
    )
    monkeypatch.setattr(
        local_auth_runtime,
        "claim_real_attempt",
        lambda *_args, **_kwargs: calls.append("marker"),
    )
    monkeypatch.setattr(
        local_auth_runtime,
        "run_local_auth",
        lambda *_args, **_kwargs: calls.append("runner") or outcome,
    )
    monkeypatch.setattr(
        local_auth_runtime,
        "persist_typed_result",
        lambda *_args, **_kwargs: calls.append("persist"),
    )
    return calls, credential


def test_la_r04_cli_orders_all_gates_before_marker_and_one_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls, credential = _install_cli_happy_path(monkeypatch, tmp_path)
    output: list[str] = []
    assert (
        local_auth_runtime.cli_main(
            ["--expected-commit", CANDIDATE_COMMIT],
            output=output.append,
        )
        == 0
    )
    assert calls == [
        "script",
        "scope",
        "repository",
        "spec_factory",
        "runtime",
        "gate",
        "credential",
        "marker",
        "runner",
        "scope",
        "persist",
    ]
    assert credential._closed is True
    assert output == [
        "F1_KIMI_LEVEL1_LOCAL_AUTH_QUALIFICATION=COMPLETE",
        "F1_KIMI_LOCAL_CREDENTIAL_STATE=LOADABLE",
        "F1_KIMI_AUTH_STATE=LOCAL_ONLY",
        (
            "F1_KIMI_LEVEL2_NON_INFERENCE_STATUS="
            "BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT"
        ),
        "F1_KIMI_LEVEL1_LOCAL_AUTH_REASON=ACP_LOCAL_AUTH_SUCCESS",
    ]


@pytest.mark.parametrize(
    "reason_code",
    [
        "LOCAL_AUTH_TIMEOUT",
        "LOCAL_AUTH_PROCESS_CRASH",
        "LOCAL_AUTH_NETWORK_POLICY_VIOLATION",
        "LOCAL_AUTH_CENSUS_POLICY",
        "LOCAL_AUTH_CLEANUP_FAILED",
    ],
)
def test_la_r04_cli_printed_and_persisted_runner_reasons_agree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reason_code: str,
) -> None:
    calls, credential = _install_cli_happy_path(monkeypatch, tmp_path)
    monkeypatch.setattr(
        local_auth_runtime,
        "run_local_auth",
        lambda *_args, **_kwargs: local_auth_runtime.LocalAuthRunOutcome(
            protocol=LocalAuthProtocolOutcome(
                qualification=QualificationState.BLOCKED,
                credential_state=LocalCredentialState.BLOCKED,
                reason_code="ACP_LOCAL_AUTH_BLOCKED",
            ),
            census=replace(_valid_runner_census(), cleanup_complete=True),
            reason_code=reason_code,
        ),
    )
    persisted_reasons: list[str] = []

    def persist(
        _root: Path,
        _protocol: LocalAuthProtocolOutcome,
        _census: dict[str, int | bool],
        *,
        reason_code: str,
        **_kwargs: object,
    ) -> None:
        calls.append("persist-reason")
        persisted_reasons.append(reason_code)

    monkeypatch.setattr(local_auth_runtime, "persist_typed_result", persist)
    output: list[str] = []

    assert (
        local_auth_runtime.cli_main(
            ["--expected-commit", CANDIDATE_COMMIT],
            output=output.append,
        )
        == 2
    )
    assert credential._closed is True
    assert persisted_reasons == [reason_code]
    assert output[-1] == f"F1_KIMI_LEVEL1_LOCAL_AUTH_REASON={reason_code}"


@pytest.mark.parametrize("failing_gate", ["scope", "repository", "runtime", "gate"])
def test_la_r04_cli_gate_failure_bombs_before_credential_marker_or_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failing_gate: str,
) -> None:
    calls, _credential = _install_cli_happy_path(monkeypatch, tmp_path)
    names = {
        "scope": "validate_local_auth_scope",
        "repository": "validate_repository_identity",
        "runtime": "validate_local_auth_spec",
        "gate": "validate_pre_real_gate",
    }

    def fail(*_args: object, **_kwargs: object) -> None:
        calls.append(f"{failing_gate}-failed")
        raise KimiLocalAuthRuntimeError(f"{failing_gate.upper()}_BLOCKED")

    monkeypatch.setattr(local_auth_runtime, names[failing_gate], fail)
    output: list[str] = []
    assert (
        local_auth_runtime.cli_main(
            ["--expected-commit", CANDIDATE_COMMIT],
            output=output.append,
        )
        == 2
    )
    assert "credential" not in calls
    assert "marker" not in calls
    assert "runner" not in calls
    assert output == [
        f"F1_KIMI_LEVEL1_LOCAL_AUTH_ERROR={failing_gate.upper()}_BLOCKED"
    ]


def test_la_r04_cli_evidence_failure_is_typed_and_never_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls, credential = _install_cli_happy_path(monkeypatch, tmp_path)

    def fail_persist(*_args: object, **_kwargs: object) -> None:
        calls.append("persist-failed")
        raise KimiLocalAuthRuntimeError("RESULT_EVIDENCE_WRITE_FAILED")

    monkeypatch.setattr(local_auth_runtime, "persist_typed_result", fail_persist)
    output: list[str] = []
    assert (
        local_auth_runtime.cli_main(
            ["--expected-commit", CANDIDATE_COMMIT],
            output=output.append,
        )
        == 2
    )
    assert calls.count("marker") == 1
    assert calls.count("runner") == 1
    assert calls.count("persist-failed") == 1
    assert credential._closed is True
    assert output == [
        "F1_KIMI_LEVEL1_LOCAL_AUTH_ERROR=RESULT_EVIDENCE_WRITE_FAILED"
    ]


def test_la_r07_post_run_scope_drift_persists_blocked_cleanup_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls, credential = _install_cli_happy_path(monkeypatch, tmp_path)
    scope_checks = 0
    persisted: list[tuple[LocalAuthProtocolOutcome, dict[str, int | bool]]] = []

    def scope_check(_text: str) -> None:
        nonlocal scope_checks
        scope_checks += 1
        calls.append(f"scope-{scope_checks}")
        if scope_checks == 2:
            raise KimiLocalAuthRuntimeError("LOCAL_AUTH_SCOPE_EXHAUSTED")

    def persist(
        _root: Path,
        protocol: LocalAuthProtocolOutcome,
        census: dict[str, int | bool],
        **_kwargs: object,
    ) -> None:
        calls.append("persist-blocked")
        persisted.append((protocol, census))

    monkeypatch.setattr(local_auth_runtime, "validate_local_auth_scope", scope_check)
    monkeypatch.setattr(local_auth_runtime, "persist_typed_result", persist)
    output: list[str] = []

    assert (
        local_auth_runtime.cli_main(
            ["--expected-commit", CANDIDATE_COMMIT],
            output=output.append,
        )
        == 2
    )
    assert scope_checks == 2
    assert calls.count("marker") == 1
    assert calls.count("runner") == 1
    assert calls.count("persist-blocked") == 1
    assert credential._closed is True
    protocol, census = persisted[0]
    assert protocol.qualification is QualificationState.BLOCKED
    assert protocol.credential_state is LocalCredentialState.BLOCKED
    assert protocol.reason_code == "ACP_LOCAL_AUTH_BLOCKED"
    assert census["cleanup_complete"] is False
    assert output == [
        "F1_KIMI_LEVEL1_LOCAL_AUTH_QUALIFICATION=BLOCKED",
        "F1_KIMI_LOCAL_CREDENTIAL_STATE=BLOCKED",
        "F1_KIMI_AUTH_STATE=LOCAL_ONLY",
        (
            "F1_KIMI_LEVEL2_NON_INFERENCE_STATUS="
            "BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT"
        ),
        "F1_KIMI_LEVEL1_LOCAL_AUTH_REASON=LOCAL_AUTH_SCOPE_EXHAUSTED",
    ]


def test_la_r04_cli_rejects_every_command_or_path_selector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_auth_runtime,
        "_validate_local_auth_script",
        lambda: pytest.fail("invalid arguments reached the script gate"),
    )
    output: list[str] = []
    assert (
        local_auth_runtime.cli_main(
            [
                "--expected-commit",
                CANDIDATE_COMMIT,
                "--command",
                "session/new",
            ],
            output=output.append,
        )
        == 2
    )
    assert output == ["F1_KIMI_LEVEL1_LOCAL_AUTH_ERROR=CLI_ARGUMENT"]
