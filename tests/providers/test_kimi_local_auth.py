from __future__ import annotations

from dataclasses import replace
import errno
import fcntl
import json
import os
import shutil
import stat
from pathlib import Path

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
    assert outcome.qualification is QualificationState.COMPLETE
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
    assert "/etc" not in argv
    assert "/run" not in argv
    assert "/var" not in argv
    joined = "\n".join(argv)
    for forbidden in (
        "resolv.conf",
        "/mnt/c",
        "/home/brand/src/AgenticOS",
        ".git",
        "socket",
        "relay",
    ):
        assert forbidden not in joined


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
            QualificationState.BLOCKED,
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
