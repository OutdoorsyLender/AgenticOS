"""Minimal Bubblewrap runtime for passive Kimi 0.36.1 qualification."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Final, Mapping

from .kimi_policy import (
    KimiPolicyError,
    build_kimi_environment,
    sha256_file,
    validate_qualification_bundle,
    verify_pinned_runtime,
)


BWRAP: Final = Path("/usr/bin/bwrap")
BWRAP_VERSION: Final = "bubblewrap 0.11.1"
BWRAP_SHA256: Final = "8e19e40e7d5f7a7e8b488c7926feb040eab6ed10c58fa360e266d2f70670e92b"
SANDBOX_EXECUTABLE: Final = "/opt/agenticos/kimi/bin/kimi"
SAFE_COMMANDS: Final = frozenset(
    {
        ("--version",),
        ("--help",),
        ("acp",),
        ("acp", "--help"),
    }
)
SAFE_FIXTURE_SCENARIOS: Final = frozenset(
    {"plan", "tool-attempt", "cancel", "malformed-stream", "process-crash"}
)
MAX_CAPTURE_BYTES: Final = 65_536


class KimiRuntimeError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True, slots=True)
class KimiRuntimeSpec:
    executable: Path
    bundle: Path
    environment: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType(build_kimi_environment())
    )

    def __post_init__(self) -> None:
        if not self.executable.is_absolute() or not self.bundle.is_absolute():
            raise KimiRuntimeError("BUNDLE_PATH")
        if self.executable.is_symlink():
            raise KimiRuntimeError("RUNTIME_EXECUTABLE_SYMLINK")
        if not self.executable.is_file():
            raise KimiRuntimeError("RUNTIME_EXECUTABLE_MISSING")
        if self.bundle.is_symlink() or not self.bundle.is_dir():
            raise KimiRuntimeError("BUNDLE_PATH")
        if dict(self.environment) != build_kimi_environment():
            raise KimiRuntimeError("ENVIRONMENT_DRIFT")

    def bwrap_argv(self, command: tuple[str, ...]) -> list[str]:
        if type(command) is not tuple or command not in SAFE_COMMANDS:
            raise KimiRuntimeError("COMMAND_NOT_QUALIFICATION_SAFE")
        argv = [
            str(BWRAP),
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
            "agenticos-kimi",
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
            str(self.executable),
            SANDBOX_EXECUTABLE,
            "--dir",
            "/home",
            "--dir",
            "/home/aos",
            "--tmpfs",
            "/home/aos/kimi",
            "--ro-bind",
            str(self.bundle / "config.toml"),
            "/home/aos/kimi/config.toml",
            "--ro-bind",
            str(self.bundle / "agents"),
            "/home/aos/kimi/agents",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/workspace",
            "--chdir",
            "/workspace",
        ]
        for name, value in self.environment.items():
            argv.extend(("--setenv", name, value))
        argv.extend(("--", SANDBOX_EXECUTABLE, *command))
        return argv

    def synthetic_fixture_argv(self, fixture_script: Path, scenario: str) -> list[str]:
        if scenario not in SAFE_FIXTURE_SCENARIOS:
            raise KimiRuntimeError("FIXTURE_SCENARIO")
        if not fixture_script.is_absolute() or fixture_script.is_symlink() or not fixture_script.is_file():
            raise KimiRuntimeError("FIXTURE_PATH")
        argv = self.bwrap_argv(("acp",))
        config_source = str(self.bundle / "config.toml")
        try:
            source_index = argv.index(config_source)
        except ValueError as exc:
            raise KimiRuntimeError("RUNTIME_LAYOUT") from exc
        if source_index < 1 or argv[source_index - 1] != "--ro-bind":
            raise KimiRuntimeError("RUNTIME_LAYOUT")
        del argv[source_index - 1 : source_index + 2]
        separator = len(argv) - 3
        if argv[separator] != "--":
            raise KimiRuntimeError("RUNTIME_LAYOUT")
        fixture_target = "/opt/agenticos/qualification/kimi_loopback_fixture.py"
        argv[separator:separator] = [
            "--dir",
            "/opt/agenticos/qualification",
            "--ro-bind",
            str(fixture_script),
            fixture_target,
        ]
        separator += 5
        argv[separator:] = ["--", "/usr/bin/python3", fixture_target, scenario]
        return argv


@dataclass(frozen=True, slots=True)
class KimiRuntimeObservation:
    returncode: int
    stdout: bytes
    stderr: bytes
    network_denied: bool
    workspace_mount: str
    inherited_fd_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _BoundedCompleted:
    returncode: int
    stdout: bytes
    stderr: bytes


def _run_bounded(
    argv: list[str],
    *,
    timeout_seconds: int,
    stdout_limit: int,
    stderr_limit: int,
    overflow_code: str,
) -> _BoundedCompleted:
    """Capture both pipes concurrently and kill the scope at the first excess byte."""

    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={},
        close_fds=True,
        pass_fds=(),
        start_new_session=True,
    )
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = threading.Event()

    def kill_scope() -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                process.kill()
            except ProcessLookupError:
                pass

    def reader(name: str, stream: object, limit: int) -> None:
        target = buffers[name]
        read = getattr(stream, "read")
        while True:
            chunk = read(8_192)
            if not chunk:
                return
            remaining = limit + 1 - len(target)
            if remaining > 0:
                target.extend(chunk[:remaining])
            if len(target) > limit or len(chunk) > remaining:
                overflow.set()
                kill_scope()
                return

    def close_pipes() -> None:
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()

    def bounded_drain_after_kill() -> None:
        kill_scope()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired as exc:
            close_pipes()
            raise KimiRuntimeError("PROCESS_DRAIN_TIMEOUT") from exc

    assert process.stdout is not None and process.stderr is not None
    readers = (
        threading.Thread(target=reader, args=("stdout", process.stdout, stdout_limit), daemon=True),
        threading.Thread(target=reader, args=("stderr", process.stderr, stderr_limit), daemon=True),
    )
    for thread in readers:
        thread.start()
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        bounded_drain_after_kill()
        for thread in readers:
            thread.join(timeout=2)
        close_pipes()
        raise
    for thread in readers:
        thread.join(timeout=2)
    if any(thread.is_alive() for thread in readers):
        bounded_drain_after_kill()
        close_pipes()
        for thread in readers:
            thread.join(timeout=2)
        raise KimiRuntimeError("CAPTURE_READER_STUCK")
    close_pipes()
    if overflow.is_set():
        raise KimiRuntimeError(overflow_code)
    return _BoundedCompleted(
        returncode=returncode,
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
    )


def build_runtime_spec(executable: Path, bundle: Path) -> KimiRuntimeSpec:
    if not executable.is_absolute() or not bundle.is_absolute():
        raise KimiRuntimeError("BUNDLE_PATH")
    if executable.is_symlink():
        raise KimiRuntimeError("RUNTIME_EXECUTABLE_SYMLINK")
    spec = KimiRuntimeSpec(executable=executable, bundle=bundle)
    _verify_spec_identity(spec)
    return spec


def _verify_spec_identity(spec: KimiRuntimeSpec) -> None:
    try:
        if BWRAP.is_symlink() or not BWRAP.is_file() or sha256_file(BWRAP) != BWRAP_SHA256:
            raise KimiRuntimeError("BWRAP_IDENTITY_DRIFT")
        artifact = validate_qualification_bundle(spec.bundle)
        verify_pinned_runtime(spec.executable, artifact, expected_uid=os.getuid())
    except KimiPolicyError as exc:
        raise KimiRuntimeError("PIN_RECHECK_FAILED", exc.code) from exc


def run_passive_kimi(
    spec: KimiRuntimeSpec,
    command: tuple[str, ...],
    *,
    timeout_seconds: int = 15,
) -> KimiRuntimeObservation:
    if not isinstance(spec, KimiRuntimeSpec):
        raise TypeError("spec must be KimiRuntimeSpec")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60:
        raise KimiRuntimeError("INVALID_TIMEOUT")
    _verify_spec_identity(spec)
    argv = spec.bwrap_argv(command)
    try:
        completed = _run_bounded(
            argv,
            timeout_seconds=timeout_seconds,
            stdout_limit=MAX_CAPTURE_BYTES,
            stderr_limit=MAX_CAPTURE_BYTES,
            overflow_code="RUNTIME_OUTPUT_LIMIT",
        )
    except subprocess.TimeoutExpired as exc:
        raise KimiRuntimeError("RUNTIME_TIMEOUT") from exc
    if len(completed.stdout) > MAX_CAPTURE_BYTES or len(completed.stderr) > MAX_CAPTURE_BYTES:
        raise KimiRuntimeError("RUNTIME_OUTPUT_LIMIT")
    return KimiRuntimeObservation(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        network_denied=True,
        workspace_mount="/workspace",
        inherited_fd_names=("stdin", "stdout", "stderr"),
    )


def run_synthetic_acp_fixture(
    spec: KimiRuntimeSpec,
    fixture_script: Path,
    scenario: str,
    *,
    timeout_seconds: int = 45,
) -> dict[str, object]:
    if not isinstance(spec, KimiRuntimeSpec):
        raise TypeError("spec must be KimiRuntimeSpec")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60:
        raise KimiRuntimeError("INVALID_TIMEOUT")
    _verify_spec_identity(spec)
    argv = spec.synthetic_fixture_argv(fixture_script, scenario)
    try:
        completed = _run_bounded(
            argv,
            timeout_seconds=timeout_seconds,
            stdout_limit=1_048_576,
            stderr_limit=262_144,
            overflow_code="FIXTURE_OUTPUT_LIMIT",
        )
    except subprocess.TimeoutExpired as exc:
        raise KimiRuntimeError("FIXTURE_TIMEOUT") from exc
    if len(completed.stdout) > 1_048_576 or len(completed.stderr) > 262_144:
        raise KimiRuntimeError("FIXTURE_OUTPUT_LIMIT")
    lines = completed.stdout.splitlines()
    if len(lines) != 1:
        raise KimiRuntimeError(
            "FIXTURE_REPORT_SHAPE",
            f"exit={completed.returncode} stderr={completed.stderr[:1000]!r}",
        )
    try:
        report = json.loads(lines[0])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KimiRuntimeError("FIXTURE_REPORT_JSON") from exc
    if type(report) is not dict or report.get("schema") != "AOS_KIMI_FIXTURE/1":
        raise KimiRuntimeError("FIXTURE_REPORT_SCHEMA")
    if completed.returncode not in (0, 2):
        raise KimiRuntimeError("FIXTURE_PROCESS_EXIT", str(completed.returncode))
    return report
