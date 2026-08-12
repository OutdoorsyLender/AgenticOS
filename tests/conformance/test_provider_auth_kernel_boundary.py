"""Linux kernel confinement proofs for the unprivileged auth helper."""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import stat
import sys
import tempfile

import pytest

from agenticos.sandbox.controller_auth_helper import ControllerAuthHelper


pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Linux Level A kernel claim"
)


def _auth_data() -> dict[str, object]:
    return {
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": "SYNTHETIC_KERNEL_ACCESS",
            "refresh_token": "SYNTHETIC_KERNEL_REFRESH",
            "expires_at": 1_900_000_000,
        },
    }


def test_auth_root_and_file_are_owner_only_and_identity_bound(tmp_path: Path) -> None:
    auth_root = tmp_path / "auth-private"
    with ControllerAuthHelper(_auth_data(), private_dir=str(auth_root)) as helper:
        root_metadata = auth_root.stat()
        auth_metadata = (auth_root / "auth.json").stat()
        identity = helper.process_identity
        assert stat.S_IMODE(root_metadata.st_mode) == 0o700
        assert stat.S_IMODE(auth_metadata.st_mode) == 0o600
        assert auth_metadata.st_nlink == 1
        assert (identity.auth_root_device, identity.auth_root_inode) == (
            root_metadata.st_dev,
            root_metadata.st_ino,
        )


@pytest.mark.parametrize(
    "startup_fault",
    [
        "openat2",
        "auth_root_identity",
        "landlock_abi",
        "landlock_create",
        "landlock_add",
        "landlock_restrict",
        "auth_open",
        "auth_json",
    ],
)
def test_auth_root_and_landlock_faults_fail_before_ready(
    startup_fault: str,
) -> None:
    with pytest.raises(RuntimeError, match="Auth helper startup failed closed"):
        ControllerAuthHelper(_auth_data(), _test_startup_fault=startup_fault)


def test_auth_root_symlink_and_non_directory_are_rejected(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    symlink = tmp_path / "auth-link"
    symlink.symlink_to(actual, target_is_directory=True)
    with pytest.raises(RuntimeError, match="auth root"):
        ControllerAuthHelper(_auth_data(), private_dir=str(symlink))

    regular = tmp_path / "not-a-directory"
    regular.write_text("x", encoding="ascii")
    with pytest.raises(RuntimeError, match="auth root"):
        ControllerAuthHelper(_auth_data(), private_dir=str(regular))

    symlink_parent = tmp_path / "parent-link"
    symlink_parent.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(RuntimeError, match="auth root"):
        ControllerAuthHelper(
            _auth_data(), private_dir=str(symlink_parent / "through-link")
        )
    assert not (tmp_path / "through-link" / "auth.json").exists()


def test_auth_root_path_replacement_race_fails_closed(tmp_path: Path) -> None:
    auth_root = tmp_path / "auth-private"

    def replace_after_identity(original: Path) -> None:
        moved = original.with_name("recorded-object")
        original.rename(moved)
        original.mkdir(mode=0o700)
        (original / "auth.json").write_text(
            '{"auth_mode":"chatgpt","tokens":{"access_token":"SUBSTITUTED"}}',
            encoding="utf-8",
        )
        os.chmod(original / "auth.json", 0o600)

    with pytest.raises(RuntimeError, match="Auth helper startup failed closed"):
        ControllerAuthHelper(
            _auth_data(),
            private_dir=str(auth_root),
            _test_auth_root_mutator=replace_after_identity,
        )


def test_landlock_ready_evidence_and_post_policy_runtime(tmp_path: Path) -> None:
    denied = tmp_path / "denied.txt"
    denied.write_text("outside", encoding="ascii")
    auth_root = tmp_path / "auth-private"
    auth_root.mkdir(mode=0o700)
    (auth_root / "allowed.txt").write_text("allowed\n", encoding="ascii")
    with ControllerAuthHelper(
        _auth_data(),
        private_dir=str(auth_root),
        _test_denied_probe_paths=(str(denied), "/proc/self/status"),
        _test_allowed_probe_name="allowed.txt",
    ) as helper:
        identity = helper.process_identity
        assert identity.landlock_abi is not None and identity.landlock_abi >= 3
        assert identity.landlock_handled_access_fs == 0x7FFF
        assert helper._filesystem_probe_results == (
            ("probe-0", "KERNEL_DENIED", "EACCES"),
            ("probe-1", "KERNEL_DENIED", "EACCES"),
        )
        assert helper._send_ipc({"action": "PING"})["status"] == "PONG"
        cap = helper.get_auth_capability("task-landlock", 1)
        assert cap.binding.helper_epoch == identity.helper_epoch


@pytest.mark.parametrize(
    ("field", "forged_value"),
    [
        ("landlock_abi", None),
        ("landlock_abi", 2),
        ("landlock_handled_access_fs", 0),
        ("auth_root_device", 0),
        ("auth_root_inode", 1),
    ],
)
def test_controller_rejects_missing_or_forged_landlock_ready_evidence(
    field: str, forged_value: object
) -> None:
    with ControllerAuthHelper(_auth_data()) as helper:
        identity = helper.process_identity
        forged = replace(identity, **{field: forged_value})
        interpreter_identity = (
            identity.executable,
            identity.executable_device,
            identity.executable_inode,
            identity.executable_digest,
        )
        entrypoint_identity = (
            identity.entrypoint,
            identity.entrypoint_device,
            identity.entrypoint_inode,
            identity.entrypoint_digest,
        )
        with pytest.raises(RuntimeError, match="READY hardening mismatch"):
            helper._validate_ready_identity(
                forged,
                interpreter_identity=interpreter_identity,
                entrypoint_identity=entrypoint_identity,
            )


def test_pre_spawn_provisioning_failure_leaves_no_fd_root_or_partial_secret(
    tmp_path: Path,
) -> None:
    import fcntl

    def open_fds() -> frozenset[int]:
        result: set[int] = set()
        for fd in range(256):
            try:
                fcntl.fcntl(fd, fcntl.F_GETFD)
            except OSError:
                continue
            result.add(fd)
        return frozenset(result)

    before_fds = open_fds()
    before_roots = frozenset(
        Path(tempfile.gettempdir()).glob("aos-auth-private-*")
    )
    with pytest.raises(ValueError, match="missing required 'tokens'"):
        ControllerAuthHelper({"auth_mode": "chatgpt"})
    assert open_fds() == before_fds
    assert frozenset(
        Path(tempfile.gettempdir()).glob("aos-auth-private-*")
    ) == before_roots

    external_root = tmp_path / "external-auth"
    unserializable = {
        "auth_mode": "chatgpt",
        "tokens": {"access_token": "SYNTHETIC_PARTIAL", "bad": object()},
    }
    with pytest.raises(TypeError):
        ControllerAuthHelper(unserializable, private_dir=str(external_root))
    assert open_fds() == before_fds
    assert external_root.is_dir()
    assert not (external_root / "auth.json").exists()
