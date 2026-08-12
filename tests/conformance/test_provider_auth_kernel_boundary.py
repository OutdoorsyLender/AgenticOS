"""Linux kernel confinement proofs for the unprivileged auth helper."""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
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


def _storage_contract(tmp_path: Path) -> tuple[str, ...]:
    hostile_root = tmp_path / "declared-hostile-root"
    hostile_root.mkdir(exist_ok=True)
    return (str(hostile_root),)


def test_auth_root_and_file_are_owner_only_and_identity_bound(tmp_path: Path) -> None:
    auth_root = tmp_path / "auth-private"
    with ControllerAuthHelper(
        _auth_data(),
        private_dir=str(auth_root),
        forbidden_storage_roots=_storage_contract(tmp_path),
    ) as helper:
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
        ControllerAuthHelper(
            _auth_data(), private_dir=str(symlink),
            forbidden_storage_roots=_storage_contract(tmp_path),
        )

    regular = tmp_path / "not-a-directory"
    regular.write_text("x", encoding="ascii")
    with pytest.raises(RuntimeError, match="auth root"):
        ControllerAuthHelper(
            _auth_data(), private_dir=str(regular),
            forbidden_storage_roots=_storage_contract(tmp_path),
        )

    symlink_parent = tmp_path / "parent-link"
    symlink_parent.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(RuntimeError, match="auth root"):
        ControllerAuthHelper(
            _auth_data(), private_dir=str(symlink_parent / "through-link"),
            forbidden_storage_roots=_storage_contract(tmp_path),
        )
    assert not (tmp_path / "through-link" / "auth.json").exists()


def test_auth_storage_cannot_overlap_a_repository_or_worktree(tmp_path: Path) -> None:
    repository = tmp_path / "hostile-worktree"
    repository.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)

    with pytest.raises(RuntimeError, match="repository or worktree"):
        ControllerAuthHelper(
            _auth_data(), private_dir=str(repository / "auth-private"),
            forbidden_storage_roots=(str(repository),),
        )

    source = repository / "persistent-auth.json"
    source.write_text(json.dumps(_auth_data()), encoding="utf-8")
    os.chmod(source, 0o600)
    with pytest.raises(RuntimeError, match="repository or worktree"):
        ControllerAuthHelper(str(source), forbidden_storage_roots=(str(repository),))

    nongit_workspace = tmp_path / "nongit-hostile-workspace"
    nongit_workspace.mkdir()
    with pytest.raises(RuntimeError, match="hostile root"):
        ControllerAuthHelper(
            _auth_data(),
            private_dir=str(nongit_workspace / "auth-private"),
            forbidden_storage_roots=(str(nongit_workspace),),
        )


def test_persistent_auth_source_rejects_symlink_and_broad_mode(tmp_path: Path) -> None:
    source = tmp_path / "persistent-auth.json"
    source.write_text(json.dumps(_auth_data()), encoding="utf-8")
    os.chmod(source, 0o644)
    with pytest.raises(RuntimeError, match="owner-only regular file"):
        ControllerAuthHelper(
            str(source), forbidden_storage_roots=_storage_contract(tmp_path)
        )

    os.chmod(source, 0o600)
    link = tmp_path / "auth-link.json"
    link.symlink_to(source)
    with pytest.raises(RuntimeError, match="owner-only regular file"):
        ControllerAuthHelper(
            str(link), forbidden_storage_roots=_storage_contract(tmp_path)
        )


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
            forbidden_storage_roots=_storage_contract(tmp_path),
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
        forbidden_storage_roots=_storage_contract(tmp_path),
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
        ControllerAuthHelper(
            unserializable,
            private_dir=str(external_root),
            forbidden_storage_roots=_storage_contract(tmp_path),
        )
    assert open_fds() == before_fds
    assert external_root.is_dir()
    assert not (external_root / "auth.json").exists()


def test_real_helper_denies_existing_repo_workspace_home_and_traversal(
    tmp_path: Path,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    sentinel = workspace / "sentinel.txt"
    sentinel.write_text("denied", encoding="ascii")
    controller_state = tmp_path / "controller-state.txt"
    controller_state.write_text("denied", encoding="ascii")
    build_output = tmp_path / "build-output.txt"
    build_output.write_text("denied", encoding="ascii")
    probes = (
        str(repo_root / "pyproject.toml"),
        str(repo_root / ".git" / "HEAD"),
        str(sentinel),
        str(controller_state),
        str(build_output),
        str(Path.home()),
        "/proc/self/status",
        str(workspace / ".." / "controller-state.txt"),
    )
    with ControllerAuthHelper(_auth_data(), _test_denied_probe_paths=probes) as helper:
        assert len(helper._filesystem_probe_results) == len(probes)
        assert all(
            outcome == "KERNEL_DENIED" and errno_name in ("EACCES", "EPERM", "EXDEV")
            for _label, outcome, errno_name in helper._filesystem_probe_results
        )


def test_real_helper_denies_auth_root_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("denied", encoding="ascii")
    auth_root = tmp_path / "auth-private"
    auth_root.mkdir(mode=0o700)
    (auth_root / "escape").symlink_to(outside)
    with ControllerAuthHelper(
        _auth_data(),
        private_dir=str(auth_root),
        forbidden_storage_roots=_storage_contract(tmp_path),
        _test_denied_probe_paths=(str(auth_root / "escape"),),
    ) as helper:
        assert helper._filesystem_probe_results == (
            ("probe-0", "KERNEL_DENIED", "EACCES"),
        )


def test_inherited_repo_workspace_and_socket_fds_are_ebadf_before_ready(
    tmp_path: Path,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    peer_a, peer_b = socket.socketpair()
    inherited = (
        os.open(repo_root / "pyproject.toml", os.O_RDONLY | os.O_CLOEXEC),
        os.open(repo_root / ".git", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC),
        os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC),
        peer_b.fileno(),
    )
    try:
        with ControllerAuthHelper(
            _auth_data(), _test_inherited_fds=inherited
        ) as helper:
            assert helper.process_identity.open_fds == (0, 1, 2, 3)
            assert helper._test_inherited_fds_closed == inherited
    finally:
        for fd in inherited[:-1]:
            os.close(fd)
        peer_b.close()
        peer_a.close()


def test_same_uid_process_surfaces_are_denied_by_dumpability(tmp_path: Path) -> None:
    child_probe = r'''
import ctypes, errno, json, os, sys
pid, address = int(sys.argv[1]), int(sys.argv[2])
result = {}
for surface in ("environ", "mem", "root", "cwd"):
    try:
        fd = os.open(f"/proc/{pid}/{surface}", os.O_RDONLY)
    except OSError as exc:
        result[surface] = errno.errorcode.get(exc.errno, str(exc.errno))
    else:
        os.close(fd); result[surface] = "ALLOWED"
try:
    os.listdir(f"/proc/{pid}/fd")
except OSError as exc:
    result["fd"] = errno.errorcode.get(exc.errno, str(exc.errno))
else:
    result["fd"] = "ALLOWED"
libc = ctypes.CDLL(None, use_errno=True)
ctypes.set_errno(0)
result["ptrace_result"] = libc.ptrace(16, pid, 0, 0)
result["ptrace_errno"] = errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
class IOVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]
local = ctypes.create_string_buffer(5)
local_iovec = IOVec(ctypes.addressof(local), 5)
remote_iovec = IOVec(address, 5)
ctypes.set_errno(0)
result["vm_result"] = libc.process_vm_readv(
    pid, ctypes.byref(local_iovec), 1, ctypes.byref(remote_iovec), 1, 0
)
result["vm_errno"] = errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
print(json.dumps(result, sort_keys=True))
'''

    with ControllerAuthHelper(
        _auth_data(), _test_expose_process_probe=True
    ) as helper:
        pid = helper.process_identity.pid
        assert helper._test_process_probe_address is not None
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                child_probe,
                str(pid),
                str(helper._test_process_probe_address),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        evidence = json.loads(completed.stdout)
        for surface in ("environ", "mem", "root", "cwd", "fd"):
            assert evidence[surface] in ("EPERM", "EACCES")
        assert evidence["ptrace_result"] == -1
        assert evidence["ptrace_errno"] in ("EPERM", "EACCES")
        assert evidence["vm_result"] == -1
        assert evidence["vm_errno"] in ("EPERM", "EACCES")


@pytest.mark.parametrize("defect", ["broad_mode", "hardlink"])
def test_controller_supplied_auth_file_defects_are_rejected_before_ready(
    tmp_path: Path, defect: str
) -> None:
    auth_root = tmp_path / "auth-private"

    def damage_auth_file(root: Path) -> None:
        auth_file = root / "auth.json"
        if defect == "broad_mode":
            auth_file.chmod(0o644)
        else:
            os.link(auth_file, root / "auth-hardlink.json")

    with pytest.raises(RuntimeError, match="Auth helper startup failed closed"):
        ControllerAuthHelper(
            _auth_data(),
            private_dir=str(auth_root),
            forbidden_storage_roots=_storage_contract(tmp_path),
            _test_auth_root_mutator=damage_auth_file,
        )


def test_non_chatgpt_auth_mode_is_rejected_before_ready() -> None:
    with pytest.raises(ValueError, match="Auth mode must be chatgpt"):
        ControllerAuthHelper(
            {"auth_mode": "api_key", "tokens": {"access_token": "SYNTHETIC"}}
        )
