"""EXPERIMENTAL filesystem isolation layer (Phase Zero, Milestone 3A).

=====================================================================
NOT A COMPLETE SANDBOX. These runners compose a filesystem restriction
UNDER the proven cgroup process-containment lifecycle:

    AgenticOS -> CgroupProcessRunner (task scope, cancellation, populated 0)
                   -> filesystem restriction (Landlock | bubblewrap)
                     -> hostile worker -> descendants

Process containment is NOT filesystem isolation; this module adds the
second layer as an experiment. Nothing here restricts network, sockets,
environment secrets, or pre-opened file descriptors.

NOTE (Milestone 3B): the production launch boundary lives in
agenticos.sandbox.launcher (NativeLandlockRunner + native fs_launcher).
The runners in this module remain as the EXPERIMENTAL 3A reference/test
oracle and are never selected as a production fallback.
=====================================================================

Policy model (deliberately minimal):

    workspace + writable_paths : read/write
    readonly_paths             : read only
    runtime_paths              : read only (incl. execute) — interpreter etc.
    everything else            : denied where the mechanism can enforce it
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .containment import (
    CgroupProcessRunner,
    ContainmentSupport,
    ContainmentUnavailableError,
)
from .models import FixtureLayout, ProcessResult

SHIM_PATH = Path(__file__).with_name("landlock_shim.py")
POLICY_ENV_VAR = "AOS_LANDLOCK_POLICY"

EV_FILESYSTEM_POLICY_CREATED = "FILESYSTEM_POLICY_CREATED"
EV_FILESYSTEM_POLICY_FAILURE = "FILESYSTEM_POLICY_FAILURE"


@dataclass
class FilesystemPolicy:
    """Minimal workspace-boundary policy. Paths must exist at apply time."""

    workspace: Path
    writable_paths: list[Path] = field(default_factory=list)
    readonly_paths: list[Path] = field(default_factory=list)
    runtime_paths: list[Path] = field(default_factory=list)
    # MAKE_FIFO / MAKE_SOCK are only granted to writable roots when the
    # policy explicitly requires them. MAKE_CHAR / MAKE_BLOCK: never.
    allow_fifo_nodes: bool = False
    allow_socket_nodes: bool = False

    def rules(self) -> list[dict[str, str]]:
        rules = [{"path": str(self.workspace), "access": "rw"}]
        rules += [{"path": str(p), "access": "rw"} for p in self.writable_paths]
        rules += [{"path": str(p), "access": "ro"} for p in self.readonly_paths]
        rules += [{"path": str(p), "access": "ro"} for p in self.runtime_paths]
        return rules

    def to_launcher_roots(self) -> list[tuple[str, str]]:
        """Canonicalized (path, mode) records for the native launcher.

        Modes: r=ro, x=rx, w=rw (+f/s flags). Paths are realpath-resolved by
        the controller; the launcher independently requires symlink-free
        resolution (RESOLVE_NO_SYMLINKS) and fails closed on mismatch.
        """
        flags = ("f" if self.allow_fifo_nodes else "") + (
            "s" if self.allow_socket_nodes else "")
        roots: list[tuple[str, str]] = []

        def add(path: Path, mode: str) -> None:
            canon = os.path.realpath(path)
            for existing_path, existing_mode in roots:
                if existing_path == canon and existing_mode != mode:
                    raise ValueError(
                        "conflicting modes for canonical policy root "
                        f"{canon!r}: {existing_mode!r} and {mode!r}"
                    )
            record = (canon, mode)
            if record not in roots:
                roots.append(record)

        def granted_rights(mode: str) -> set[str]:
            rights = {"read_file", "read_dir"}
            if mode[0] == "x":
                rights.add("execute")
            elif mode[0] == "w":
                rights.update({
                    "write_file", "truncate", "remove_file", "remove_dir",
                    "make_reg", "make_dir", "make_sym", "refer",
                })
            if "f" in mode:
                rights.add("make_fifo")
            if "s" in mode:
                rights.add("make_sock")
            return rights

        add(self.workspace, "w" + flags)
        for p in self.writable_paths:
            add(p, "w" + flags)
        for p in self.readonly_paths:
            add(p, "r")
        for p in self.runtime_paths:
            add(p, "x")

        # Landlock path-beneath rules in one layer union their grants.  An
        # ancestor may therefore be narrower than a descendant exception,
        # but it must never grant a right that the descendant mode omits.
        for ancestor_path, ancestor_mode in roots:
            ancestor = Path(ancestor_path)
            for descendant_path, descendant_mode in roots:
                descendant = Path(descendant_path)
                if ancestor == descendant or not descendant.is_relative_to(ancestor):
                    continue
                if not granted_rights(ancestor_mode) <= granted_rights(descendant_mode):
                    raise ValueError(
                        "overlapping policy roots would widen descendant "
                        f"rights: {ancestor_path!r} ({ancestor_mode}) contains "
                        f"{descendant_path!r} ({descendant_mode})"
                    )
        return roots

    def to_env_value(self) -> str:
        return base64.b64encode(json.dumps({"rules": self.rules()}).encode()).decode()

    @classmethod
    def for_layout(cls, layout: FixtureLayout, worker_path: Path) -> "FilesystemPolicy":
        """Policy for a hostile-worker run inside a fixture layout.

        workspace = assigned worktree (rw); task-tmp (rw); readonly fixture
        (ro); runtime = interpreter/venv/repo paths needed to execute Python
        and the worker (ro). Everything else — sibling worktree, private
        state, fake home, the rest of the host — is denied by omission.
        """
        runtime = [
            Path(sys.executable).resolve(),
            Path(worker_path).resolve().parent.parent.parent,  # repo root (worker + package)
        ]
        for prefix in ("/usr", "/lib", "/lib64", "/etc", "/proc"):
            p = Path(prefix)
            if p.exists():
                runtime.append(p)
        # venv (if the interpreter lives in one)
        for parent in Path(sys.executable).resolve().parents:
            if (parent / "pyvenv.cfg").exists():
                runtime.append(parent)
                break
        # Keep the device grant intentionally narrow. ABI v3 cannot mediate
        # device ioctls, so ordinary workers get only the standard nodes they
        # commonly need rather than authority over the full /dev hierarchy.
        writable = [layout.task_tmp]
        readonly = [layout.readonly_dir]
        for device in (Path("/dev/null"), Path("/dev/zero")):
            if device.exists():
                writable.append(device)
        for device in (Path("/dev/random"), Path("/dev/urandom")):
            if device.exists():
                readonly.append(device)
        return cls(
            workspace=layout.assigned_worktree,
            writable_paths=writable,
            readonly_paths=readonly,
            runtime_paths=runtime,
        )


def probe_landlock_enforcement() -> tuple[bool, str]:
    """Bounded REAL probe: child process applies a deny-all Landlock ruleset
    and attempts to read a synthetic temp file. SUPPORTED only if EACCES is
    actually observed. Creates and removes one temp dir; nothing else."""
    probe_code = (
        "import ctypes, os, sys, pathlib\n"
        "target = sys.argv[1]\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        "class A(ctypes.Structure):\n"
        "    _fields_ = [('h', ctypes.c_uint64)]\n"
        "a = A((1 << 15) - 1)\n"
        "fd = libc.syscall(444, ctypes.byref(a), ctypes.sizeof(a), 0)\n"
        "assert fd >= 0, ('create_ruleset', ctypes.get_errno())\n"
        "assert libc.prctl(38, 1, 0, 0, 0) == 0\n"
        "assert libc.syscall(446, fd, 0) == 0, ('restrict_self', ctypes.get_errno())\n"
        "try:\n"
        "    pathlib.Path(target).read_text()\n"
        "    print('ALLOWED')\n"
        "except PermissionError:\n"
        "    print('DENIED')\n"
    )
    tmp = Path(tempfile.mkdtemp(prefix="aos-ll-probe-"))
    try:
        canary = tmp / "probe-canary.txt"
        canary.write_text("AOS_CANARY_probe")
        proc = subprocess.run(
            [sys.executable, "-c", probe_code, str(canary)],
            capture_output=True, text=True, timeout=20.0,
        )
        out = proc.stdout.strip()
        if proc.returncode == 0 and out == "DENIED":
            return True, "deny-all ruleset produced EACCES on a synthetic file"
        if "Operation not permitted" in proc.stderr or proc.returncode != 0:
            return False, f"probe failed: rc={proc.returncode} {proc.stderr.strip()[:160]!r}"
        return False, f"probe observed {out!r} instead of DENIED"
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, f"probe raised {type(exc).__name__}: {exc}"
    finally:
        import shutil as _shutil

        _shutil.rmtree(tmp, ignore_errors=True)


def probe_unprivileged_namespaces() -> tuple[bool, str]:
    """Bounded REAL probe: unprivileged user+mount namespace creation."""
    unshare = shutil.which("unshare")
    if unshare is None:
        return False, "unshare not found on PATH"
    try:
        proc = subprocess.run(
            [unshare, "--user", "--map-root-user", "--mount", "true"],
            capture_output=True, text=True, timeout=15.0,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, f"probe raised {type(exc).__name__}: {exc}"
    if proc.returncode == 0:
        return True, "unshare --user --map-root-user --mount succeeded"
    return False, f"unshare failed: {proc.stderr.strip()[:160]!r}"


class LandlockIsolatedRunner(CgroupProcessRunner):
    """EXPERIMENTAL: cgroup process containment + Landlock filesystem rules.

    NOT A COMPLETE SANDBOX — see module docstring. Landlock is applied by a
    fail-closed shim inside the task scope, before the worker starts, and is
    inherited by every descendant across fork/exec/setsid/double-fork.
    Pre-opened file descriptors are NOT revoked by Landlock (documented
    limitation: never hand sensitive FDs to a worker).

    Milestone 3B: retained as the experimental reference / test oracle.
    The production boundary is agenticos.sandbox.launcher.NativeLandlockRunner.
    """

    name = "landlock-experimental"

    def __init__(
        self,
        worker_path: str | os.PathLike[str],
        fs_policy: FilesystemPolicy,
        **kwargs,
    ) -> None:
        super().__init__(worker_path, **kwargs)
        self.fs_policy = fs_policy
        if not SHIM_PATH.is_file():
            raise FileNotFoundError(f"landlock shim not found: {SHIM_PATH}")

    def check_support(self, refresh: bool = False) -> ContainmentSupport:
        support = super().check_support(refresh=refresh)
        if support.supported:
            ok, reason = probe_landlock_enforcement()
            if not ok:
                support.supported = False
                support.reasons.append(f"landlock_enforcement={reason}")
        return support

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | os.PathLike[str],
        env: Mapping[str, str],
        timeout: Optional[float] = None,
    ) -> ProcessResult:
        wrapped = [sys.executable, str(SHIM_PATH), "--", *[str(a) for a in argv]]
        run_env = dict(env)
        run_env[POLICY_ENV_VAR] = self.fs_policy.to_env_value()
        self._emit(EV_FILESYSTEM_POLICY_CREATED,
                   mechanism="landlock",
                   rule_count=len(self.fs_policy.rules()))
        result = super().run(wrapped, cwd=cwd, env=run_env, timeout=timeout)
        if result.exit_code == 2 and '"shim": "landlock"' in result.stdout:
            self._emit(EV_FILESYSTEM_POLICY_FAILURE, mechanism="landlock",
                       detail=result.stdout.strip()[:200])
        return result


class BwrapIsolatedRunner(CgroupProcessRunner):
    """EXPERIMENTAL: cgroup process containment + bubblewrap mount view.

    NOT A COMPLETE SANDBOX. Builds a scratch root (--tmpfs /) containing
    only the policy's paths; everything else simply does not exist inside
    (denials surface as ENOENT rather than EACCES). Requires unprivileged
    user+mount namespaces; bwrap binary must already be installed.
    """

    name = "bwrap-experimental"

    def __init__(
        self,
        worker_path: str | os.PathLike[str],
        fs_policy: FilesystemPolicy,
        **kwargs,
    ) -> None:
        super().__init__(worker_path, **kwargs)
        self.fs_policy = fs_policy
        self.bwrap = shutil.which("bwrap")
        if self.bwrap is None:
            raise ContainmentUnavailableError("bwrap not found on PATH")

    def check_support(self, refresh: bool = False) -> ContainmentSupport:
        support = super().check_support(refresh=refresh)
        if support.supported:
            ok, reason = probe_unprivileged_namespaces()
            if not ok:
                support.supported = False
                support.reasons.append(f"unprivileged_namespaces={reason}")
        return support

    def _bwrap_argv(self, argv: Sequence[str]) -> list[str]:
        args = [self.bwrap, "--tmpfs", "/", "--dev", "/dev"]
        emitted: set[str] = set()

        def add(flag: str, path: Path) -> None:
            # /dev and /proc are handled by bwrap itself (--dev /dev);
            # binding host device nodes would WIDEN access, not narrow it.
            if path in {
                Path("/dev"),
                Path("/dev/null"),
                Path("/dev/zero"),
                Path("/dev/random"),
                Path("/dev/urandom"),
                Path("/proc"),
            }:
                return
            key = f"{flag}:{path}"
            if key in emitted:
                return
            emitted.add(key)
            args.extend([flag, str(path), str(path)])

        add("--bind", self.fs_policy.workspace)
        for p in self.fs_policy.writable_paths:
            add("--bind", p)
        for p in self.fs_policy.readonly_paths:
            add("--ro-bind", p)
        for p in self.fs_policy.runtime_paths:
            add("--ro-bind", p)
        args.append("--")
        args.extend(str(a) for a in argv)
        return args

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | os.PathLike[str],
        env: Mapping[str, str],
        timeout: Optional[float] = None,
    ) -> ProcessResult:
        wrapped = self._bwrap_argv(argv)
        self._emit(EV_FILESYSTEM_POLICY_CREATED,
                   mechanism="bubblewrap",
                   rule_count=len(self.fs_policy.rules()))
        return super().run(wrapped, cwd=cwd, env=env, timeout=timeout)
