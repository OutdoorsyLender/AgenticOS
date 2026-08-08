"""Production Landlock launch boundary (Phase Zero, Milestone 3B).

=====================================================================
NOT A COMPLETE SANDBOX. NativeLandlockRunner composes, in order:

    CgroupProcessRunner lifecycle (task scope, cancellation, populated 0)
      -> native fs_launcher (trusted, single-threaded C, direct UAPI)
        -> launch gate (controller verifies containment BEFORE release)
          -> FD hygiene (close_range; worker inherits only 0/1/2)
            -> trusted openat2 policy roots
              -> PR_SET_NO_NEW_PRIVS -> landlock_restrict_self (ABI >= 3)
                -> authenticated policy acknowledgement
                  -> controller exec-release gate
                    -> execve(hostile worker)

The experimental Python shim (landlock_shim.py / LandlockIsolatedRunner)
remains as the Milestone 3A behavioral reference and test oracle. It is
NOT selected as a production fallback — if the native boundary cannot be
established, the task does not run.
=====================================================================
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import select
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .capabilities import probe_landlock_abi
from .containment import (
    CgroupProcessRunner,
    ContainmentState,
    ContainmentSupport,
    ContainmentUnavailableError,
    EV_CGROUP_EMPTY_VERIFIED,
    wait_cgroup_empty,
)
from .isolation import (
    FilesystemPolicy,
    probe_landlock_enforcement,
)
from .models import AttackResult, ProcessIdentity, ProcessResult, utc_now_iso

DEFAULT_LAUNCHER_PATH = (
    Path(__file__).resolve().parents[3] / "native" / "fs_launcher" / "fs_launcher"
)

# Evidence events (launcher-originated where noted).
EV_CAPABILITY_OBSERVED = "FILESYSTEM_CAPABILITY_OBSERVED"
EV_LAUNCHER_STARTED = "TRUSTED_LAUNCHER_STARTED"
EV_CONTAINMENT_VERIFIED = "CONTAINMENT_VERIFIED"
EV_FD_SANITIZED = "FD_SET_SANITIZED"
EV_POLICY_PREPARED = "FILESYSTEM_POLICY_PREPARED"
EV_NO_NEW_PRIVS = "NO_NEW_PRIVS_SET"
EV_POLICY_APPLIED = "FILESYSTEM_POLICY_APPLIED"
EV_EXEC_ATTEMPTED = "WORKER_EXEC_ATTEMPTED"
EV_EXEC_FAILED = "WORKER_EXEC_FAILED"
EV_POLICY_FAILED = "FILESYSTEM_POLICY_FAILED"
EV_TASK_EXITED = "FILESYSTEM_TASK_EXITED"

PROTOCOL_VERSION = "AOSLAUNCH/1"
PROTOCOL_VERSION_M4A = "AOSLAUNCH/2"
MAX_ITEMS = 64
MAX_ITEM_LEN = 4096
ABI_V3_HANDLED_ACCESS_FS = 0x7FFF

# Ambient-credential accident prevention — NOT credential isolation.
_ENV_DENY_SUBSTRINGS = (
    "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API_KEY", "APIKEY",
    "PRIVATE_KEY", "AUTH_SOCK",
)
_ENV_DENY_PREFIXES = (
    "AWS_", "AZURE_", "GOOGLE_", "GCLOUD_", "GCP_", "DOCKER_", "GPG_",
    "DBUS_", "GITHUB_", "GH_", "OPENAI_", "ANTHROPIC_", "MOONSHOT_",
    "KIMI_", "SSH_",
)
_ENV_DENY_EXACT = {"XDG_RUNTIME_DIR"}


@dataclass(frozen=True)
class PreparedLaunchRequest:
    wire: bytes
    nonce: str
    policy_digest: str


def sanitize_env(env: Mapping[str, str]) -> tuple[dict[str, str], list[str]]:
    """Split an explicit env into (kept, dropped_names).

    Prevents accidental ambient inheritance of credential-shaped variables.
    This is NOT the future credential broker: credential_isolation remains
    NOT_CLAIMED. Dropped names (never values) may be recorded as evidence.
    """
    kept: dict[str, str] = {}
    dropped: list[str] = []
    for key, value in env.items():
        upper = key.upper()
        if (
            upper in _ENV_DENY_EXACT
            or any(upper.startswith(p) for p in _ENV_DENY_PREFIXES)
            or any(s in upper for s in _ENV_DENY_SUBSTRINGS)
        ):
            dropped.append(key)
            continue
        kept[key] = value
    return kept, sorted(dropped)


def _lv(value: str) -> bytes:
    """Length-prefixed protocol value; bounded; rejects newlines."""
    raw = value.encode()
    if b"\n" in raw:
        raise ValueError("protocol value must not contain a newline")
    if len(raw) > MAX_ITEM_LEN:
        raise ValueError(f"protocol value exceeds {MAX_ITEM_LEN} bytes")
    return str(len(raw)).encode() + b" " + raw + b"\n"


def prepare_launch_request(
    argv: Sequence[str],
    env: Mapping[str, str],
    cwd: str,
    roots: Sequence[tuple[str, str]],
    *,
    min_abi: int = 3,
    nonce: Optional[str] = None,
    protocol_version: int = 1,
    cwd_record: Optional[tuple[str, int, int]] = None,
    root_records: Optional[Sequence[tuple[str, int, int, str]]] = None,
    policy_digest_override: Optional[str] = None,
) -> PreparedLaunchRequest:
    """Serialize a launch request for the native fs_launcher protocol.

    ``roots`` is a sequence of (path, mode) with mode in {"r", "x", "w",
    "wf", "ws", "wfs"}. All inputs are bounded; violations raise ValueError
    (the controller fails before ever starting the launcher).
    """
    argv = [str(a) for a in argv]
    if not 1 <= len(argv) <= MAX_ITEMS:
        raise ValueError("argv count out of bounds")
    if len(env) > MAX_ITEMS or len(roots) > MAX_ITEMS:
        raise ValueError("env/roots count out of bounds")
    if protocol_version not in (1, 2):
        raise ValueError(f"unsupported launch protocol version {protocol_version}")
    for mode in (m for _, m in roots):
        if mode[0] not in "rxw" or any(f not in "fs" for f in mode[1:]):
            raise ValueError(f"invalid root mode {mode!r}")
    def identity(path: str) -> tuple[str, int, int]:
        canonical = os.path.realpath(path)
        stat_result = os.stat(canonical)
        return canonical, int(stat_result.st_dev), int(stat_result.st_ino)

    nonce_value = nonce or secrets.token_hex(16)
    if protocol_version == 1:
        if cwd_record is not None or root_records is not None:
            raise ValueError("pre-authorized identity records require protocol v2")
        cwd_path, cwd_dev, cwd_ino = identity(str(cwd))
        resolved_root_records = [
            (*identity(str(path)), mode) for path, mode in roots
        ]
    else:
        if cwd_record is None or root_records is None:
            raise ValueError("protocol v2 requires pre-authorized identity records")
        cwd_path, cwd_dev, cwd_ino = cwd_record
        if cwd_path != str(cwd):
            raise ValueError("protocol v2 cwd record does not match cwd")
        resolved_root_records = list(root_records)
        for path, dev, ino, mode in resolved_root_records:
            if not path.startswith("/") or dev < 0 or ino <= 0:
                raise ValueError("invalid protocol v2 root identity record")
            if mode[0] not in "rxw" or any(f not in "fs" for f in mode[1:]):
                raise ValueError(f"invalid root mode {mode!r}")
    digest_payload = {
        "cwd": {"path": cwd_path, "dev": cwd_dev, "ino": cwd_ino},
        "roots": [
            {"path": path, "dev": dev, "ino": ino, "mode": mode}
            for path, dev, ino, mode in resolved_root_records
        ],
    }
    computed_digest = hashlib.sha256(
        json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if policy_digest_override is not None:
        if (
            len(policy_digest_override) != 64
            or any(c not in "0123456789abcdef" for c in policy_digest_override)
        ):
            raise ValueError("policy digest override must be lowercase SHA-256 hex")
        digest = policy_digest_override
    else:
        digest = computed_digest

    version_tag = PROTOCOL_VERSION if protocol_version == 1 else PROTOCOL_VERSION_M4A
    out = [version_tag.encode() + b"\n"]
    out.append(b"nonce " + _lv(nonce_value))
    out.append(b"policy_digest " + _lv(digest))
    out.append(f"min_abi {int(min_abi)}\n".encode())
    out.append(f"argv {len(argv)}\n".encode())
    out += [_lv(a) for a in argv]
    out.append(f"env {len(env)}\n".encode())
    out += [_lv(f"{k}={v}") for k, v in env.items()]
    out.append(f"cwd {cwd_dev} {cwd_ino} ".encode() + _lv(cwd_path))
    out.append(f"roots {len(resolved_root_records)}\n".encode())
    out += [
        f"{mode} {dev} {ino} ".encode() + _lv(path)
        for path, dev, ino, mode in resolved_root_records
    ]
    out.append(b"END\n")
    return PreparedLaunchRequest(
        wire=b"".join(out), nonce=nonce_value, policy_digest=digest
    )


def build_launch_request(
    argv: Sequence[str],
    env: Mapping[str, str],
    cwd: str,
    roots: Sequence[tuple[str, str]],
    *,
    min_abi: int = 3,
    nonce: Optional[str] = None,
) -> bytes:
    """Compatibility wrapper returning only the bounded protocol bytes."""
    return prepare_launch_request(
        argv, env, cwd, roots, min_abi=min_abi, nonce=nonce
    ).wire


def parse_launcher_status(
    data: bytes,
    *,
    expected_nonce: Optional[str] = None,
    expected_policy_digest: Optional[str] = None,
    expected_min_abi: int = 3,
    expected_handled_access_fs: int = ABI_V3_HANDLED_ACCESS_FS,
    protocol_version: int = 1,
) -> dict:
    """Parse and authenticate the line-oriented launcher status stream."""
    outcome: dict = {
        "progress": [],
        "failed_stage": None,
        "exec_errno": None,
        "exec_succeeded": False,
        "policy_applied": False,
        "nonce": None,
        "abi": None,
        "handled_access_fs": None,
        "policy_digest": None,
        "identity_verified": False,
    }
    for raw_line in data.splitlines():
        line = raw_line.decode(errors="replace")
        try:
            if line.startswith("R:"):
                outcome["progress"].append("R")
                outcome["nonce"] = line[2:]
            elif line in ("S", "I", "P", "N"):
                outcome["progress"].append(line)
            elif line.startswith("A:"):
                _tag, abi, mask, digest = line.split(":", 3)
                outcome["progress"].append("A")
                outcome["abi"] = int(abi)
                outcome["handled_access_fs"] = int(mask, 16)
                outcome["policy_digest"] = digest
            elif line.startswith("F:"):
                _tag, stage, error_number = line.split(":", 2)
                outcome["failed_stage"] = stage
                outcome["errno"] = int(error_number)
            elif line.startswith("E:"):
                _tag, error_number = line.split(":", 1)
                outcome["failed_stage"] = "exec"
                outcome["exec_errno"] = int(error_number)
            else:
                raise ValueError("unknown status record")
        except (TypeError, ValueError):
            outcome["failed_stage"] = "protocol"
            break

    if expected_nonce is not None and outcome["nonce"] != expected_nonce:
        outcome["failed_stage"] = "protocol"
    if (
        expected_policy_digest is not None
        and "A" in outcome["progress"]
        and outcome["policy_digest"] != expected_policy_digest
    ):
        outcome["failed_stage"] = "protocol"
    expected_progress = (
        ["R", "S", "P", "N", "A"]
        if protocol_version == 1
        else ["R", "S", "I", "P", "N", "A"]
    )
    if protocol_version not in (1, 2):
        outcome["failed_stage"] = "protocol"
    if "A" in outcome["progress"] and (
        outcome["progress"] != expected_progress
        or outcome["abi"] is None
        or outcome["abi"] < expected_min_abi
        or outcome["handled_access_fs"] != expected_handled_access_fs
    ):
        outcome["failed_stage"] = "protocol"
    outcome["policy_applied"] = (
        "A" in outcome["progress"]
        and outcome["failed_stage"] in (None, "exec")
        and outcome["abi"] is not None
        and outcome["handled_access_fs"] is not None
    )
    outcome["identity_verified"] = (
        protocol_version == 2
        and "I" in outcome["progress"]
        and outcome["failed_stage"] in (None, "exec")
    )
    # Parsing A proves the restriction, not exec: the native launcher still
    # waits for the controller's second gate.  The runner sets this only
    # after release plus positive status-FD EOF.
    outcome["exec_succeeded"] = False
    return outcome


class NativeLandlockRunner(CgroupProcessRunner):
    """Production Landlock launch boundary under cgroup containment.

    NOT A COMPLETE SANDBOX — see module docstring. Fails closed: if the
    native launcher, the ABI requirement, trusted path resolution, or any
    setup stage fails, the hostile worker never executes. There is NO
    fallback to the experimental Python shim or to unsandboxed execution.
    """

    name = "landlock-native"

    def __init__(
        self,
        worker_path: str | os.PathLike[str],
        fs_policy: FilesystemPolicy,
        launcher_path: str | os.PathLike[str] | None = None,
        min_abi: int = 3,
        setup_timeout: float = 10.0,
        **kwargs,
    ) -> None:
        super().__init__(worker_path, **kwargs)
        self.fs_policy = fs_policy
        self.launcher_path = Path(launcher_path) if launcher_path else DEFAULT_LAUNCHER_PATH
        self.min_abi = int(min_abi)
        self.setup_timeout = float(setup_timeout)
        if self.setup_timeout <= 0:
            raise ValueError("setup_timeout must be positive")
        self.last_launch_outcome: Optional[dict] = None
        self.last_dropped_env: list[str] = []

    def check_support(self, refresh: bool = False) -> ContainmentSupport:
        support = super().check_support(refresh=refresh)
        if not self.launcher_path.is_file():
            support.supported = False
            support.reasons.append(f"native launcher missing: {self.launcher_path}")
        else:
            capability = probe_landlock_abi()
            self._emit(
                EV_CAPABILITY_OBSERVED,
                backend=self.name,
                status=capability.status,
                landlock_abi=capability.abi,
                min_abi_required=self.min_abi,
                errno=capability.errno,
            )
            if capability.status != "SUPPORTED":
                support.supported = False
                support.reasons.append(
                    f"landlock_abi={capability.status.lower()}: {capability.reason}"
                )
            elif capability.abi is None or capability.abi < self.min_abi:
                support.supported = False
                support.reasons.append(
                    f"landlock_abi={capability.abi} required={self.min_abi}"
                )
        if support.supported:
            ok, reason = probe_landlock_enforcement()
            if not ok:
                support.supported = False
                support.reasons.append(f"landlock_enforcement={reason}")
            else:
                self._emit(EV_CAPABILITY_OBSERVED, backend=self.name,
                           landlock_enforcement="SUPPORTED")
        return support

    # -- SandboxRunner API --------------------------------------------------

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | os.PathLike[str],
        env: Mapping[str, str],
        timeout: Optional[float] = None,
        _leak_fds: Sequence[int] = (),
    ) -> ProcessResult:
        """Run ``argv`` behind the full production launch boundary.

        ``_leak_fds`` is a TEST-ONLY hook that deliberately inherits extra
        parent FDs into the launcher, proving they never reach the worker.
        """
        support = self.check_support()
        if not support.supported:
            raise ContainmentUnavailableError(
                "native landlock launch unavailable: " + "; ".join(support.reasons)
            )

        argv = [str(a) for a in argv]
        timeout = self.default_timeout if timeout is None else float(timeout)
        roots = self.fs_policy.to_launcher_roots()
        worker_env, dropped = sanitize_env(env)
        self.last_dropped_env = dropped
        prepared = prepare_launch_request(
            argv, worker_env, str(cwd), roots, min_abi=self.min_abi
        )

        unit = f"aos-task-{uuid.uuid4().hex[:12]}"
        scope = f"{unit}.scope"
        status_r, status_w = os.pipe()
        os.set_inheritable(status_w, True)
        scope_env = dict(self.backend._ctl_env)
        scope_env["AOS_STATUS_FD"] = str(status_w)
        fault = os.environ.get("AOS_LAUNCHER_FAULT_INJECT")
        if fault:  # test-only fault path, opt-in from the controller env
            scope_env["AOS_LAUNCHER_FAULT_INJECT"] = fault

        started_at = utc_now_iso()
        proc = subprocess.Popen(
            [self.backend.systemd_run, "--user", "--scope", "--quiet",
             "--collect", f"--unit={unit}", "--", str(self.launcher_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd),
            env=scope_env,
            shell=False,
            start_new_session=True,
            pass_fds=(status_w, *_leak_fds),
        )
        os.close(status_w)
        identity = ProcessIdentity.from_pid(proc.pid)
        self._emit(EV_LAUNCHER_STARTED, unit=scope, pid=proc.pid,
                   launcher=str(self.launcher_path))

        outcome: dict = {"progress": [], "failed_stage": "gate",
                         "exec_errno": None, "exec_succeeded": False}
        cgroup_path = None
        progress_emitted = False
        try:
            proc.stdin.write(prepared.wire)
            proc.stdin.flush()
            first = self._read_status(
                status_r, budget=self.setup_timeout, max_bytes=1
            )
            if first != b"R":
                raise ContainmentUnavailableError(
                    "launcher did not reach the launch gate")
            cgroup_path = self._discover_cgroup(scope, proc.pid)
            if cgroup_path is None:
                raise ContainmentUnavailableError(
                    "containment cgroup could not be verified; refusing to release")
            self._emit(EV_CONTAINMENT_VERIFIED, unit=scope,
                       cgroup_path=str(cgroup_path))
            proc.stdin.write(b"G")
            proc.stdin.flush()

            rest = self._read_status(status_r, budget=self.setup_timeout)
            status_transcript = b"R" + rest
            outcome = parse_launcher_status(
                status_transcript,
                expected_nonce=prepared.nonce,
                expected_policy_digest=prepared.policy_digest,
                expected_min_abi=self.min_abi,
            )
            # A proves policy application, not that exec has been released
            # or observed.  Terminal evidence requires status-FD EOF/E below.
            outcome["exec_succeeded"] = False
            self.last_launch_outcome = outcome
            if outcome["failed_stage"] == "protocol":
                raise ContainmentUnavailableError(
                    "invalid filesystem policy acknowledgement; refusing exec"
                )
            if outcome["policy_applied"]:
                # Second gate: hostile exec is released only after the
                # controller authenticates the complete policy evidence.
                self._emit_launch_events(
                    scope, outcome, emit_terminal=False
                )
                progress_emitted = True
                proc.stdin.write(b"X")
                proc.stdin.flush()
                proc.stdin.close()
                trailing, status_eof = self._read_post_release_status(
                    status_r, budget=self.setup_timeout
                )
                if not status_eof:
                    raise ContainmentUnavailableError(
                        "launcher status channel did not close after exec release"
                    )
                outcome = parse_launcher_status(
                    status_transcript + trailing,
                    expected_nonce=prepared.nonce,
                    expected_policy_digest=prepared.policy_digest,
                    expected_min_abi=self.min_abi,
                )
                self.last_launch_outcome = outcome
                if outcome["failed_stage"] == "protocol":
                    raise ContainmentUnavailableError(
                        "invalid post-release launcher status"
                    )
                outcome["exec_succeeded"] = outcome["failed_stage"] is None
            else:
                proc.stdin.close()
                if outcome["failed_stage"] is None:
                    raise ContainmentUnavailableError(
                        "launcher did not complete the filesystem policy barrier"
                    )
        except BaseException as launch_error:
            # Every exception after cgroup discovery uses the same verified
            # recursive drain as ordinary cancellation.  Killing only the
            # systemd-run wrapper can strand already-execed descendants.
            self.last_launch_outcome = outcome
            if outcome.get("progress"):
                self._emit_launch_events(
                    scope,
                    outcome,
                    emit_progress=not progress_emitted,
                    emit_terminal=not progress_emitted,
                )
            os.close(status_r)
            if not proc.stdin.closed:
                proc.stdin.close()
            cleanup_problems = []
            try:
                cleanup_state = self._cancel(scope, cgroup_path, proc)
                if cleanup_state is not ContainmentState.TERMINATED:
                    cleanup_problems.append(
                        f"containment state={cleanup_state.value}"
                    )
            except BaseException as cleanup_error:
                cleanup_problems.append(
                    f"cgroup drain raised {type(cleanup_error).__name__}: "
                    f"{cleanup_error}"
                )
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                cleanup_problems.append("scope wrapper did not exit")
            self.backend.stop_unit(scope)
            if self.backend.unit_active(scope):
                cleanup_problems.append("transient scope remains active")
            if cleanup_problems:
                raise ContainmentUnavailableError(
                    "launch failed and containment cleanup was not proven: "
                    + "; ".join(cleanup_problems)
                ) from launch_error
            raise
        finally:
            if not proc.stdin.closed:
                proc.stdin.close()
        os.close(status_r)
        self.last_launch_outcome = outcome
        self._emit_launch_events(
            scope, outcome, emit_progress=not progress_emitted
        )

        timed_out = False
        containment_state = ContainmentState.RUNNING.value
        try:
            out_b, err_b = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            state = self._cancel(scope, cgroup_path, proc)
            containment_state = state.value
            out_b, err_b = proc.communicate()

        if cgroup_path is not None and not wait_cgroup_empty(
            self.backend, cgroup_path, 0.2, self.cancellation.poll_interval
        ):
            state = self._cancel(scope, cgroup_path, proc)
            containment_state = state.value
        elif cgroup_path is not None:
            if containment_state == ContainmentState.RUNNING.value:
                containment_state = ContainmentState.TERMINATED.value
            self._emit(
                EV_CGROUP_EMPTY_VERIFIED,
                unit=scope,
                after="clean exit",
            )
        else:
            containment_state = ContainmentState.FAILED.value

        self.backend.stop_unit(scope)
        if self.backend.unit_active(scope):
            containment_state = ContainmentState.FAILED.value
        self._emit(EV_TASK_EXITED, unit=scope,
                   containment_state=containment_state)

        finished_at = utc_now_iso()
        rc = proc.returncode
        return ProcessResult(
            pid=proc.pid,
            argv=argv,
            exit_code=rc if rc is not None and rc >= 0 else None,
            signal=-rc if rc is not None and rc < 0 else None,
            stdout=(out_b or b"").decode(errors="replace"),
            stderr=(err_b or b"").decode(errors="replace"),
            timed_out=timed_out,
            started_at=started_at,
            finished_at=finished_at,
            process_group_id=identity.process_group_id,
            identity=identity,
            containment_unit=scope,
            containment_cgroup=str(cgroup_path) if cgroup_path else None,
            containment_state=containment_state,
        )

    def run_scenario(self, scenario_id: str, **kwargs) -> AttackResult:
        """Like the base implementation, but pre-exec launcher failures are
        reported as PolicyFailure/ExecFailure — never as a worker result."""
        result = super().run_scenario(scenario_id, **kwargs)
        outcome = self.last_launch_outcome or {}
        stage = outcome.get("failed_stage")
        if result.error_type == "RunnerError" and stage:
            if stage == "exec":
                result.error_type = "ExecFailure"
                result.error_message = (
                    f"execve failed after policy applied, "
                    f"errno={outcome.get('exec_errno')}")
            else:
                result.error_type = "PolicyFailure"
                result.error_message = f"launcher failed closed at stage {stage!r}"
        return result

    # -- internals ----------------------------------------------------------

    @staticmethod
    def _read_status(fd: int, budget: float, max_bytes: int = 256) -> bytes:
        """Read launcher status bytes until EOF (exec closed the fd) or a
        complete A:/F:/E: line, with a hard time budget."""
        data = b""
        deadline = time.monotonic() + budget
        while len(data) < max_bytes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select([fd], [], [], min(remaining, 0.2))
            if not ready:
                continue
            chunk = os.read(fd, 1)
            if not chunk:
                break
            data += chunk
            if chunk == b"\n":
                last_line = data.rstrip(b"\n").rsplit(b"\n", 1)[-1]
                if last_line.startswith((b"A:", b"F:", b"E:")):
                    break
        return data

    @staticmethod
    def _read_post_release_status(
        fd: int, budget: float, max_bytes: int = 256
    ) -> tuple[bytes, bool]:
        """Read the status channel through EOF after exec release.

        CLOEXEC EOF is the positive exec-attempt observation.  Returning
        ``eof=False`` distinguishes a bounded timeout/oversized stream from
        successful exec, so terminal evidence cannot be inferred from `A`.
        """
        data = b""
        deadline = time.monotonic() + budget
        while len(data) < max_bytes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return data, False
            ready, _, _ = select.select([fd], [], [], min(remaining, 0.2))
            if not ready:
                continue
            chunk = os.read(fd, min(64, max_bytes - len(data)))
            if not chunk:
                return data, True
            data += chunk
        return data, False

    def _emit_launch_events(
        self,
        scope: str,
        outcome: dict,
        *,
        emit_progress: bool = True,
        emit_terminal: bool = True,
    ) -> None:
        letter_events = {
            "S": EV_FD_SANITIZED,
            "P": EV_POLICY_PREPARED,
            "N": EV_NO_NEW_PRIVS,
            "A": EV_POLICY_APPLIED,
        }
        if emit_progress:
            for letter in outcome.get("progress", []):
                if letter == "A" and not outcome.get("policy_applied"):
                    # An A line is evidence only after its nonce/digest/ABI
                    # fields have been authenticated by the parser.
                    continue
                if letter in letter_events:
                    payload = {"unit": scope}
                    if letter == "A":
                        payload.update(
                            backend="landlock",
                            abi=outcome.get("abi"),
                            handled_access_fs=outcome.get("handled_access_fs"),
                            policy_digest=outcome.get("policy_digest"),
                            no_new_privs="N" in outcome.get("progress", []),
                            restrict_self=True,
                        )
                    self._emit(letter_events[letter], **payload)
        if not emit_terminal:
            return
        stage = outcome.get("failed_stage")
        if stage == "exec":
            self._emit(EV_EXEC_FAILED, unit=scope,
                       errno=outcome.get("exec_errno"))
        elif stage:
            self._emit(EV_POLICY_FAILED, unit=scope, stage=stage,
                       errno=outcome.get("errno"))
        elif outcome.get("exec_succeeded"):
            self._emit(EV_EXEC_ATTEMPTED, unit=scope)
