"""Composed Milestone 4A Bubblewrap, Landlock, and cgroup runner."""

from __future__ import annotations

import os
import select
import selectors
import subprocess
import time
import uuid
from pathlib import Path
from typing import Mapping, Optional, Sequence

try:
    import fcntl
except ImportError:  # Windows imports the runner only to verify fail-closed behavior.
    fcntl = None  # type: ignore[assignment]

from .containment import (
    CgroupProcessRunner,
    ContainmentState,
    ContainmentSupport,
    ContainmentUnavailableError,
    EV_CGROUP_EMPTY_VERIFIED,
    wait_cgroup_empty,
)
from .isolation import probe_landlock_enforcement
from .launcher import (
    EV_CONTAINMENT_VERIFIED,
    EV_EXEC_ATTEMPTED,
    EV_FD_SANITIZED,
    EV_NO_NEW_PRIVS,
    EV_POLICY_APPLIED,
    EV_POLICY_PREPARED,
    EV_TASK_EXITED,
    NativeLandlockRunner,
    parse_launcher_status,
    prepare_launch_request,
)
from .models import (
    CONTAINMENT_RESERVATION_SCHEMA,
    PREPARED_PROCESS_RECEIPT_SCHEMA,
    ContainmentReservation,
    PreparedProcessReceipt,
    ProcessIdentity,
    ProcessResult,
    utc_now_iso,
)
from .runtime_boundary import (
    AuthorizedSource,
    M4AProfile,
    NamespaceEvidence,
    NamespaceEvidenceError,
    RuntimeBoundaryUnavailable,
    build_bwrap_argv,
    build_runtime_plan,
    exact_cgroup_relative,
    probe_bubblewrap,
    open_verified_bwrap,
    read_bwrap_setup_status,
    read_namespace_snapshot,
    secure_open_source,
    verify_namespace_evidence,
)


EV_NAMESPACE_CAPABILITY = "NAMESPACE_CAPABILITY_OBSERVED"
EV_NAMESPACE_VERIFIED = "NAMESPACE_BOUNDARY_VERIFIED"
EV_LAUNCHER_ENTERED = "TRUSTED_LAUNCHER_ENTERED"
EV_IDENTITIES_VERIFIED = "SANDBOX_IDENTITIES_VERIFIED"
EV_RUNTIME_FAILURE = "RUNTIME_BOUNDARY_FAILED"
EV_RUNTIME_VERIFIED = "RUNTIME_BOUNDARY_VERIFIED"


class PreparedM4AExecution:
    """Single-owner M4A process held after policy proof and before worker exec."""

    def __init__(
        self,
        *,
        runner: "NamespaceLandlockRunner",
        proc: subprocess.Popen,
        worker_argv: list[str],
        started_at: str,
        process_identity: ProcessIdentity,
        scope: str,
        cgroup_path: Path,
        control_fd: int,
        native_status_fd: int,
        json_status_fd: int,
        launch_request: object,
        launch_transcript: bytes,
        launch_outcome: dict,
        plan: object,
        workspace_mount: object,
        namespace_evidence: NamespaceEvidence,
        receipt: PreparedProcessReceipt,
        marker_instrumented: bool,
    ) -> None:
        self._runner = runner
        self._proc = proc
        self._worker_argv = worker_argv
        self._started_at = started_at
        self._process_identity = process_identity
        self._scope = scope
        self._cgroup_path = cgroup_path
        self._control_fd = control_fd
        self._native_status_fd = native_status_fd
        self._json_status_fd = json_status_fd
        self._launch_request = launch_request
        self._launch_transcript = launch_transcript
        self._launch_outcome = launch_outcome
        self._plan = plan
        self._workspace_mount = workspace_mount
        self._namespace_evidence = namespace_evidence
        self.receipt = receipt
        self._marker_instrumented = marker_instrumented
        self._released = False
        self._terminal = False
        self._cancellation_requested = False
        self._cleanup_proven = False
        self._result: Optional[ProcessResult] = None

    @property
    def terminal(self) -> bool:
        return self._terminal

    @property
    def released(self) -> bool:
        return self._released

    @property
    def cleanup_proven(self) -> bool:
        return self._cleanup_proven

    def __enter__(self) -> "PreparedM4AExecution":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if not self._terminal:
            self.cancel()

    def _close_status_fds(self) -> None:
        for name in ("_native_status_fd", "_json_status_fd"):
            fd = getattr(self, name)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, name, -1)

    def _close_native_status_fd(self) -> None:
        if self._native_status_fd >= 0:
            try:
                os.close(self._native_status_fd)
            except OSError:
                pass
            self._native_status_fd = -1

    def _cleanup_after_error(self, cause: BaseException) -> None:
        self._cleanup_proven = False
        try:
            self._runner._cleanup_failed_process(
                self._scope, self._cgroup_path, self._proc, cause
            )
            self._cleanup_proven = True
        finally:
            self._close_status_fds()
            self._terminal = True

    def release(
        self,
        expected_receipt: PreparedProcessReceipt,
        release_nonce: str,
    ) -> None:
        if self._terminal or self._released:
            raise ContainmentUnavailableError("prepared execution already released or terminal")
        if expected_receipt != self.receipt:
            raise ContainmentUnavailableError("prepared receipt mismatch")
        if release_nonce != self.receipt.reservation.release_nonce:
            raise ContainmentUnavailableError("prepared release nonce mismatch")
        try:
            self._runner._write_all(
                self._control_fd, b"X", budget=self._runner.setup_timeout
            )
            assert self._proc.stdin is not None
            self._proc.stdin.close()
            trailing, status_eof = NativeLandlockRunner._read_post_release_status(
                self._native_status_fd, budget=self._runner.setup_timeout
            )
            if not status_eof:
                raise ContainmentUnavailableError(
                    "native status channel did not close on worker exec"
                )
            prepared = self._launch_request
            outcome = parse_launcher_status(
                self._launch_transcript + trailing,
                expected_nonce=prepared.nonce,
                expected_policy_digest=prepared.policy_digest,
                expected_min_abi=3,
                protocol_version=2,
            )
            self._launch_outcome = outcome
            self._runner.last_launch_outcome = outcome
            if outcome.get("failed_stage") is not None:
                raise ContainmentUnavailableError(
                    f"M4A launcher failed at {outcome['failed_stage']}"
                )
            outcome["exec_succeeded"] = True
            self._runner._emit(EV_EXEC_ATTEMPTED, unit=self._scope)
            self._released = True
            # Bubblewrap may continue writing lifecycle JSON until process exit.
            # Keep that read end open so the contained process cannot receive
            # SIGPIPE merely because the native launch channel reached EOF.
            self._close_native_status_fd()
        except BaseException as exc:
            self._runner.last_launch_outcome = self._launch_outcome
            self._runner._emit(
                EV_RUNTIME_FAILURE,
                unit=self._scope,
                stage="exec_release",
                error_type=type(exc).__name__,
            )
            self._cleanup_after_error(exc)
            raise

    def _complete(
        self,
        out_b: bytes,
        err_b: bytes,
        *,
        timed_out: bool,
        containment_state: str,
        output_limit_exceeded: bool = False,
    ) -> ProcessResult:
        if not wait_cgroup_empty(
            self._runner.backend,
            self._cgroup_path,
            0.2,
            self._runner.cancellation.poll_interval,
        ):
            containment_state = self._runner._cancel(
                self._scope, self._cgroup_path, self._proc
            ).value
        else:
            if containment_state == ContainmentState.RUNNING.value:
                containment_state = ContainmentState.TERMINATED.value
            self._runner._emit(
                EV_CGROUP_EMPTY_VERIFIED, unit=self._scope, after="clean exit"
            )
        self._runner.backend.stop_unit(self._scope)
        if self._runner.backend.unit_active(self._scope):
            containment_state = ContainmentState.FAILED.value
        if containment_state != ContainmentState.TERMINATED.value:
            raise ContainmentUnavailableError(
                "M4A task cleanup did not reach proven TERMINATED state"
            )

        plan = self._plan
        workspace_mount = self._workspace_mount
        evidence = self._namespace_evidence
        outcome = self._launch_outcome
        self._runner._emit(
            EV_RUNTIME_VERIFIED,
            profile=plan.profile.value,
            workspace_destination="/workspace",
            workspace_identity={
                "device": workspace_mount.source.identity.device,
                "inode": workspace_mount.source.identity.inode,
                "file_type": workspace_mount.source.identity.file_type,
            },
            worker_cwd=plan.cwd,
            environment_names=[name for name, _ in plan.worker_environment],
            filesystem_view_digest=plan.filesystem_view_digest,
            environment_policy_digest=plan.environment_policy_digest,
            combined_policy_digest=plan.combined_policy_digest,
            network_policy=plan.network_policy,
            namespace_identities=dict(evidence.child.identities),
            child_cgroup=evidence.child.cgroup,
            gate_ordering=dict(self._runner.last_ordering_observations),
            worker_marker_instrumented=self._marker_instrumented,
            landlock_abi=outcome.get("abi"),
            handled_access_fs=outcome.get("handled_access_fs"),
            identity_verified=outcome.get("identity_verified"),
            policy_applied=outcome.get("policy_applied"),
            exec_succeeded=outcome.get("exec_succeeded"),
            containment_state=containment_state,
            output_limit_exceeded=output_limit_exceeded,
            cleanup="recursive_cgroup_empty",
        )
        self._runner._emit(
            EV_TASK_EXITED, unit=self._scope, containment_state=containment_state
        )
        result = self._runner._assemble_process_result(
            proc=self._proc,
            worker_argv=self._worker_argv,
            out_b=out_b,
            err_b=err_b,
            timed_out=timed_out,
            started_at=self._started_at,
            finished_at=utc_now_iso(),
            identity=self._process_identity,
            scope=self._scope,
            cgroup_path=self._cgroup_path,
            containment_state=containment_state,
            output_limit_exceeded=output_limit_exceeded,
        )
        self._result = result
        self._terminal = True
        self._close_status_fds()
        return result

    def wait(
        self,
        timeout: Optional[float] = None,
        *,
        max_output_bytes: int = 16 * 1024 * 1024,
        cancellation_observer=None,
    ) -> ProcessResult:
        if self._terminal:
            if self._result is None:
                raise ContainmentUnavailableError("prepared execution is terminal")
            return self._result
        if not self._released:
            raise ContainmentUnavailableError("prepared execution has not been released")
        timeout = self._runner.default_timeout if timeout is None else float(timeout)
        timed_out = False
        output_limit_exceeded = False
        containment_state = ContainmentState.RUNNING.value
        try:
            try:
                out_b, err_b, output_limit_exceeded = (
                    self._runner._communicate_process_bounded(
                        self._proc, timeout, max_output_bytes
                    )
                )
                if output_limit_exceeded:
                    if cancellation_observer is not None:
                        cancellation_observer()
                    cancellation_state = self._runner._cancel(
                        self._scope, self._cgroup_path, self._proc
                    )
                    if cancellation_state is not ContainmentState.TERMINATED:
                        raise ContainmentUnavailableError(
                            "output-limited M4A task cleanup was not proven"
                        )
                    containment_state = cancellation_state.value
                    self._runner._communicate_process(
                        self._proc, self._runner.setup_timeout
                    )
            except subprocess.TimeoutExpired:
                timed_out = True
                cancellation_state = self._runner._cancel(
                    self._scope, self._cgroup_path, self._proc
                )
                if cancellation_state is not ContainmentState.TERMINATED:
                    raise ContainmentUnavailableError(
                        "timed-out M4A task cleanup was not proven"
                    )
                containment_state = cancellation_state.value
                out_b, err_b = self._runner._communicate_process(
                    self._proc, self._runner.setup_timeout
                )
            return self._complete(
                out_b,
                err_b,
                timed_out=timed_out,
                containment_state=containment_state,
                output_limit_exceeded=output_limit_exceeded,
            )
        except BaseException as exc:
            self._runner._emit(
                EV_RUNTIME_FAILURE,
                unit=self._scope,
                stage="host_lifecycle",
                error_type=type(exc).__name__,
            )
            self._cleanup_after_error(exc)
            raise

    def cancel(self) -> ProcessResult:
        if self._terminal:
            if self._result is None:
                raise ContainmentUnavailableError("prepared execution is terminal")
            return self._result
        try:
            if self._proc.stdin is not None and not self._proc.stdin.closed:
                self._proc.stdin.close()
            state = self._runner._cancel(
                self._scope, self._cgroup_path, self._proc
            )
            if state is not ContainmentState.TERMINATED:
                raise ContainmentUnavailableError(
                    "cancelled M4A task cleanup was not proven"
                )
            out_b, err_b = self._runner._communicate_process(
                self._proc, self._runner.setup_timeout
            )
            return self._complete(
                out_b,
                err_b,
                timed_out=False,
                containment_state=state.value,
            )
        except BaseException as exc:
            self._cleanup_after_error(exc)
            raise

    def request_cancel(self) -> None:
        """Recursively signal/drain now; the owning wait path performs final reap."""
        if self._terminal or self._cancellation_requested:
            return
        if self._proc.stdin is not None and not self._proc.stdin.closed:
            self._proc.stdin.close()
        state = self._runner._cancel(
            self._scope, self._cgroup_path, self._proc
        )
        if state is not ContainmentState.TERMINATED:
            raise ContainmentUnavailableError(
                "requested M4A cancellation did not drain containment"
            )
        self._cancellation_requested = True


class NamespaceLandlockRunner(CgroupProcessRunner):
    """Production M4A composition; unavailable until every gate is proven."""

    name = "bubblewrap-landlock-native"

    def build_scenario_argv(self, scenario_id: str, **kwargs) -> list[str]:
        """Build the canonical worker argv using the stable in-namespace ABI."""
        argv = super().build_scenario_argv(scenario_id, **kwargs)
        argv[:2] = ["/usr/bin/python3", "/opt/agenticos/worker.py"]
        return argv

    def __init__(
        self,
        worker_path: str | os.PathLike[str],
        *,
        workspace: str | os.PathLike[str],
        profile: M4AProfile,
        launcher_path: str | os.PathLike[str],
        task_tmp: str | os.PathLike[str],
        synthetic_home: str | os.PathLike[str],
        git_mask_path: Optional[str | os.PathLike[str]] = None,
        setup_timeout: float = 10.0,
        **kwargs,
    ) -> None:
        super().__init__(worker_path, **kwargs)
        self.workspace = Path(workspace)
        self.profile = profile
        self.launcher_path = Path(launcher_path)
        self.task_tmp = Path(task_tmp)
        self.synthetic_home = Path(synthetic_home)
        self.git_mask_path = Path(git_mask_path) if git_mask_path else None
        self.setup_timeout = float(setup_timeout)
        if self.setup_timeout <= 0:
            raise ValueError("setup_timeout must be positive")
        self.last_ordering_observations: dict[str, Optional[bool]] = {}
        self.last_namespace_evidence: Optional[NamespaceEvidence] = None
        self.last_launch_outcome: Optional[dict] = None
        self._bwrap_capability = None

    def check_support(self, refresh: bool = False) -> ContainmentSupport:
        support = super().check_support(refresh=refresh)
        if not self.launcher_path.is_file():
            support.supported = False
            support.reasons.append(f"native launcher missing: {self.launcher_path}")
        if support.supported:
            bwrap = probe_bubblewrap()
            self._bwrap_capability = bwrap
            self._emit(
                EV_NAMESPACE_CAPABILITY,
                backend="bubblewrap",
                path=str(bwrap.path),
                version=bwrap.version,
                sha256=bwrap.sha256,
                mode=bwrap.mode,
                uid=bwrap.uid,
                gid=bwrap.gid,
                setuid=bwrap.setuid,
                setgid=bwrap.setgid,
                file_capabilities=bool(bwrap.file_capabilities),
                device=bwrap.device,
                inode=bwrap.inode,
                unprivileged_user_namespace=bwrap.unprivileged_user_namespace,
                nested_user_namespace_denied=bwrap.nested_user_namespace_denied,
            )
            if not bwrap.supported:
                support.supported = False
                support.reasons.extend(bwrap.reasons)
        if support.supported:
            landlock_ok, reason = probe_landlock_enforcement()
            if not landlock_ok:
                support.supported = False
                support.reasons.append(f"landlock_enforcement={reason}")
        return support

    @staticmethod
    def _move_fd(fd: int, minimum: int) -> int:
        if fcntl is None:
            os.close(fd)
            raise RuntimeBoundaryUnavailable("M4A descriptor setup requires Linux fcntl")
        try:
            moved = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, minimum)
        except BaseException:
            os.close(fd)
            raise
        os.close(fd)
        os.set_inheritable(moved, True)
        return moved

    @classmethod
    def _open_high_source(
        cls,
        path: Path,
        *,
        expected_type: int,
        minimum: int,
    ) -> AuthorizedSource:
        opened = secure_open_source(path, expected_type=expected_type)
        moved = cls._move_fd(opened.fd, minimum)
        return AuthorizedSource(opened.locator, moved, opened.identity)

    def _open_runtime_sources(self) -> tuple[AuthorizedSource, ...]:
        import stat

        specs: list[tuple[Path, int]] = [
            (self.workspace, stat.S_IFDIR),
            (Path("/usr"), stat.S_IFDIR),
            (self.launcher_path, stat.S_IFREG),
            (self.worker_path, stat.S_IFREG),
            (self.task_tmp, stat.S_IFDIR),
            (self.synthetic_home, stat.S_IFDIR),
        ]
        if self.git_mask_path is not None:
            specs.append((self.git_mask_path, stat.S_IFREG))

        opened: list[AuthorizedSource] = []
        try:
            for index, (path, expected_type) in enumerate(specs):
                opened.append(
                    self._open_high_source(
                        path,
                        expected_type=expected_type,
                        minimum=10 + index,
                    )
                )
            return tuple(opened)
        except BaseException:
            for source in opened:
                os.close(source.fd)
            raise

    @classmethod
    def _pipe_with_moved_end(
        cls, *, move_read: bool, minimum: int
    ) -> tuple[int, int]:
        """Create one pipe and move only the child-owned end above a floor."""
        read_fd, write_fd = os.pipe()
        try:
            if move_read:
                return cls._move_fd(read_fd, minimum), write_fd
            return read_fd, cls._move_fd(write_fd, minimum)
        except BaseException:
            for fd in (read_fd, write_fd):
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise

    @staticmethod
    def _close_source_fds(sources: Sequence[AuthorizedSource]) -> None:
        for source in sources:
            try:
                os.close(source.fd)
            except OSError:
                pass

    @staticmethod
    def _assemble_process_result(
        *,
        proc: subprocess.Popen,
        worker_argv: list[str],
        out_b: bytes,
        err_b: bytes,
        timed_out: bool,
        started_at: str,
        finished_at: str,
        identity: Optional[ProcessIdentity],
        scope: str,
        cgroup_path: Optional[Path],
        containment_state: str,
        output_limit_exceeded: bool = False,
    ) -> ProcessResult:
        rc = proc.returncode
        return ProcessResult(
            pid=proc.pid,
            argv=worker_argv,
            exit_code=rc if rc is not None and rc >= 0 else None,
            signal=-rc if rc is not None and rc < 0 else None,
            stdout=(out_b or b"").decode(errors="replace"),
            stderr=(err_b or b"").decode(errors="replace"),
            timed_out=timed_out,
            started_at=started_at,
            finished_at=finished_at,
            process_group_id=identity.process_group_id if identity else None,
            identity=identity,
            containment_unit=scope,
            containment_cgroup=str(cgroup_path) if cgroup_path else None,
            containment_state=containment_state,
            output_limit_exceeded=output_limit_exceeded,
            _stdout_bytes=out_b or b"",
        )

    @staticmethod
    def _cgroup_relative(cgroup_root: Path, cgroup_path: Path) -> str:
        try:
            return exact_cgroup_relative(cgroup_root, cgroup_path)
        except RuntimeBoundaryUnavailable as exc:
            raise ContainmentUnavailableError(str(exc)) from exc

    @staticmethod
    def _marker_absent(marker: Optional[Path]) -> Optional[bool]:
        return None if marker is None else not marker.exists()

    @staticmethod
    def _communicate_process(
        proc: subprocess.Popen, timeout: Optional[float]
    ) -> tuple[bytes, bytes]:
        return proc.communicate(timeout=timeout)

    @staticmethod
    def _communicate_process_bounded(
        proc: subprocess.Popen,
        timeout: Optional[float],
        max_output_bytes: int,
    ) -> tuple[bytes, bytes, bool]:
        """Drain both hostile streams incrementally under one aggregate bound."""
        if type(max_output_bytes) is not int or max_output_bytes < 1:
            raise ValueError("max_output_bytes must be positive")
        deadline = None if timeout is None else time.monotonic() + timeout
        captured = {"stdout": bytearray(), "stderr": bytearray()}
        selector = selectors.DefaultSelector()
        streams = (("stdout", proc.stdout), ("stderr", proc.stderr))
        for name, stream in streams:
            if stream is not None:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
        overflow = False
        try:
            while selector.get_map():
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise subprocess.TimeoutExpired(
                        proc.args,
                        timeout,
                        output=bytes(captured["stdout"]),
                        stderr=bytes(captured["stderr"]),
                    )
                events = selector.select(remaining)
                if not events:
                    continue
                for key, _mask in events:
                    try:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total = len(captured["stdout"]) + len(captured["stderr"])
                    available = max_output_bytes - total
                    captured[key.data].extend(chunk[:available])
                    if len(chunk) > available:
                        overflow = True
                        return (
                            bytes(captured["stdout"]),
                            bytes(captured["stderr"]),
                            True,
                        )
            proc.wait(timeout=0)
            return bytes(captured["stdout"]), bytes(captured["stderr"]), overflow
        finally:
            selector.close()
            for _name, stream in streams:
                if stream is not None and not stream.closed:
                    try:
                        os.set_blocking(stream.fileno(), True)
                    except OSError:
                        pass

    @staticmethod
    def _write_all(fd: int, payload: bytes, *, budget: float) -> None:
        """Write one bounded control payload without blocking past its deadline."""
        deadline = time.monotonic() + budget
        offset = 0
        original_blocking = os.get_blocking(fd)
        os.set_blocking(fd, False)
        try:
            while offset < len(payload):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ContainmentUnavailableError(
                        "timed out streaming trusted launcher request"
                    )
                _, writable, _ = select.select([], [fd], [], min(remaining, 0.2))
                if not writable:
                    continue
                try:
                    written = os.write(fd, payload[offset:])
                except BlockingIOError:
                    continue
                if written <= 0:
                    raise ContainmentUnavailableError(
                        "trusted launcher request channel closed"
                    )
                offset += written
        finally:
            os.set_blocking(fd, original_blocking)

    def _cleanup_failed_process(
        self,
        scope: str,
        cgroup_path: Optional[Path],
        proc: subprocess.Popen,
        cause: BaseException,
    ) -> None:
        if proc.stdin is not None and not proc.stdin.closed:
            proc.stdin.close()
        cleanup_state = ContainmentState.FAILED
        try:
            cleanup_state = self._cancel(scope, cgroup_path, proc)
        except BaseException:  # Preserve cleanup progress even if evidence I/O fails.
            cleanup_state = ContainmentState.FAILED
        finally:
            self.backend.stop_unit(scope)
        try:
            self._communicate_process(proc, 5.0)
        except (subprocess.TimeoutExpired, ValueError, OSError):
            cleanup_state = ContainmentState.FAILED
            try:
                proc.kill()
            except OSError:
                pass
        try:
            if self.backend.unit_active(scope):
                cleanup_state = ContainmentState.FAILED
        except BaseException:
            cleanup_state = ContainmentState.FAILED
        if cleanup_state is not ContainmentState.TERMINATED:
            raise ContainmentUnavailableError(
                "M4A failure cleanup was not proven"
            ) from cause

    def _emit_v2_progress(self, scope: str, outcome: dict) -> None:
        events = {
            "S": EV_FD_SANITIZED,
            "I": EV_IDENTITIES_VERIFIED,
            "P": EV_POLICY_PREPARED,
            "N": EV_NO_NEW_PRIVS,
        }
        for letter in outcome.get("progress", []):
            if letter in events:
                self._emit(events[letter], unit=scope)
        if outcome.get("policy_applied"):
            self._emit(
                EV_POLICY_APPLIED,
                unit=scope,
                backend="landlock",
                abi=outcome.get("abi"),
                handled_access_fs=outcome.get("handled_access_fs"),
                policy_digest=outcome.get("policy_digest"),
                namespace_backend="bubblewrap",
                network_policy="DENY",
            )

    def prepare(
        self,
        argv: Sequence[str],
        *,
        cwd: str | os.PathLike[str],
        env: Mapping[str, str],
        reservation: ContainmentReservation,
        _leak_fds: Sequence[int] = (),
        _marker_path: Optional[Path] = None,
    ) -> PreparedM4AExecution:
        if str(cwd) != "/workspace":
            raise ValueError("M4A worker cwd must be the stable /workspace ABI")
        if not isinstance(reservation, ContainmentReservation):
            raise TypeError("reservation must be a ContainmentReservation")
        support = self.check_support()
        if not support.supported:
            raise ContainmentUnavailableError(
                "M4A runtime boundary unavailable: " + "; ".join(support.reasons)
            )
        if self._bwrap_capability is None:
            raise ContainmentUnavailableError("Bubblewrap capability evidence is missing")
        worker_argv = [str(item) for item in argv]
        bwrap_fd = -1
        sources: tuple[AuthorizedSource, ...] = ()
        namespace_gate_r0 = namespace_gate_r = namespace_gate_w = -1
        json_status_r = json_status_w0 = json_status_w = -1
        native_status_r = native_status_w0 = native_status_w = -1
        try:
            bwrap_fd = self._move_fd(
                open_verified_bwrap(self._bwrap_capability), 20
            )
            sources = self._open_runtime_sources()
            workspace = sources[0]
            runtime_usr = sources[1]
            launcher = sources[2]
            worker = sources[3]
            task_tmp = sources[4]
            synthetic_home = sources[5]
            git_mask = sources[6] if len(sources) > 6 else None
            plan = build_runtime_plan(
                profile=self.profile,
                workspace=workspace,
                runtime_usr=runtime_usr,
                launcher=launcher,
                worker=worker,
                task_tmp=task_tmp,
                synthetic_home=synthetic_home,
                git_mask=git_mask,
            )
            workspace_mount = plan.mount_for("/workspace")
            authorized_root_records = [
                (
                    mount.destination,
                    mount.source.identity.device,
                    mount.source.identity.inode,
                    mount.landlock_mode,
                )
                for mount in plan.mounts
            ]
            namespace_gate_r, namespace_gate_w = self._pipe_with_moved_end(
                move_read=True, minimum=32
            )
            json_status_r, json_status_w = self._pipe_with_moved_end(
                move_read=False, minimum=33
            )
            native_status_r, native_status_w = self._pipe_with_moved_end(
                move_read=False, minimum=34
            )
            bwrap_argv = build_bwrap_argv(
                plan,
                namespace_gate_fd=namespace_gate_r,
                json_status_fd=json_status_w,
                launcher_status_fd=native_status_w,
                executable=Path(f"/proc/self/fd/{bwrap_fd}"),
            )
        except BaseException:
            self._close_source_fds(sources)
            for fd in {
                bwrap_fd,
                namespace_gate_r0,
                namespace_gate_r,
                namespace_gate_w,
                json_status_r,
                json_status_w0,
                json_status_w,
                native_status_r,
                native_status_w0,
                native_status_w,
            }:
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            raise
        unit = reservation.unit_name
        scope = reservation.scope_name
        pass_fds = tuple(
            [bwrap_fd, *[source.fd for source in sources]]
            + [namespace_gate_r, json_status_w, native_status_w]
            + list(_leak_fds)
        )
        started_at = utc_now_iso()
        proc: Optional[subprocess.Popen] = None
        cgroup_path: Optional[Path] = None
        identity: Optional[ProcessIdentity] = None
        child_ends = (namespace_gate_r, json_status_w, native_status_w)
        self.last_ordering_observations = {}
        self.last_namespace_evidence = None
        outcome: dict = {
            "progress": [],
            "failed_stage": "namespace",
            "policy_applied": False,
            "exec_succeeded": False,
        }
        handle_ready = False
        try:
            command = [
                self.backend.systemd_run,
                "--user",
                "--scope",
                "--quiet",
                "--collect",
                f"--unit={unit}",
                "--",
                *bwrap_argv,
            ]
            proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd="/",
                env=dict(self.backend._ctl_env),
                shell=False,
                start_new_session=True,
                pass_fds=pass_fds,
            )
            identity = ProcessIdentity.from_pid(proc.pid)
            for fd in child_ends:
                os.close(fd)
            child_ends = ()
            self._close_source_fds(sources)
            sources = ()
            os.close(bwrap_fd)
            bwrap_fd = -1

            setup_status = read_bwrap_setup_status(
                json_status_r,
                timeout=self.setup_timeout,
            )
            self.last_ordering_observations["namespace_status_before_release"] = True
            cgroup_path = self._discover_cgroup(scope, proc.pid)
            if cgroup_path is None:
                raise ContainmentUnavailableError(
                    "containment cgroup could not be verified before namespace release"
                )
            expected_cgroup = self._cgroup_relative(self.cgroup_root, cgroup_path)
            controller_snapshot = read_namespace_snapshot(os.getpid())
            child_snapshot = read_namespace_snapshot(setup_status.child_pid)
            evidence = verify_namespace_evidence(
                setup_status,
                controller=controller_snapshot,
                child=child_snapshot,
                expected_cgroup=expected_cgroup,
                expected_host_uid=os.getuid(),
            )
            self.last_namespace_evidence = evidence
            self.last_ordering_observations["namespace_verified_before_release"] = True

            prepared = prepare_launch_request(
                worker_argv,
                dict(plan.worker_environment),
                "/workspace",
                [],
                min_abi=3,
                protocol_version=2,
                cwd_record=(
                    "/workspace",
                    workspace_mount.source.identity.device,
                    workspace_mount.source.identity.inode,
                ),
                root_records=[
                    *authorized_root_records,
                    ("/dev/null", 0, 0, "w"),
                ],
                policy_digest_override=plan.combined_policy_digest,
            )
            self._emit(EV_CONTAINMENT_VERIFIED, unit=scope, cgroup_path=str(cgroup_path))
            self._emit(
                EV_NAMESPACE_VERIFIED,
                unit=scope,
                child_pid=evidence.child.pid,
                namespace_ids=dict(evidence.child.identities),
                filesystem_view_digest=plan.filesystem_view_digest,
                environment_policy_digest=plan.environment_policy_digest,
                combined_policy_digest=plan.combined_policy_digest,
                network_policy=plan.network_policy,
            )
            launcher_ready, _, _ = select.select([native_status_r], [], [], 0)
            launcher_absent = not launcher_ready
            worker_absent = self._marker_absent(_marker_path)
            self.last_ordering_observations[
                "launcher_entered_before_namespace_release"
            ] = not launcher_absent
            self.last_ordering_observations[
                "worker_entered_before_namespace_release"
            ] = None if worker_absent is None else not worker_absent
            if not launcher_absent or worker_absent is False:
                raise ContainmentUnavailableError(
                    "launcher or worker entered before namespace gate release"
                )
            os.write(namespace_gate_w, b"G")
            os.close(namespace_gate_w)
            namespace_gate_w = -1

            assert proc.stdin is not None
            control_fd = proc.stdin.fileno()
            self._write_all(control_fd, prepared.wire, budget=self.setup_timeout)

            first = NativeLandlockRunner._read_status(
                native_status_r, budget=self.setup_timeout, max_bytes=1
            )
            if first != b"R":
                raise ContainmentUnavailableError(
                    "native launcher did not enter after namespace release"
                )
            self.last_ordering_observations[
                "launcher_entered_after_namespace_release"
            ] = True
            self._emit(EV_LAUNCHER_ENTERED, unit=scope)
            self._write_all(control_fd, b"G", budget=self.setup_timeout)
            rest = NativeLandlockRunner._read_status(
                native_status_r, budget=self.setup_timeout
            )
            transcript = b"R" + rest
            outcome = parse_launcher_status(
                transcript,
                expected_nonce=prepared.nonce,
                expected_policy_digest=prepared.policy_digest,
                expected_min_abi=3,
                protocol_version=2,
            )
            self.last_launch_outcome = outcome
            if not outcome.get("policy_applied") or not outcome.get("identity_verified"):
                raise ContainmentUnavailableError(
                    "invalid M4A filesystem policy acknowledgement: "
                    f"stage={outcome.get('failed_stage')} "
                    f"error={outcome.get('failure')}"
                )
            self._emit_v2_progress(scope, outcome)
            worker_absent = self._marker_absent(_marker_path)
            self.last_ordering_observations[
                "worker_entered_before_exec_release"
            ] = None if worker_absent is None else not worker_absent
            if worker_absent is False:
                raise ContainmentUnavailableError(
                    "worker entered before authenticated exec release"
                )
            worker_identity = ProcessIdentity.from_pid(evidence.child.pid)
            receipt = PreparedProcessReceipt(
                schema=PREPARED_PROCESS_RECEIPT_SCHEMA,
                reservation=reservation,
                process_identity=worker_identity,
                cgroup_path=str(cgroup_path),
                child_cgroup=evidence.child.cgroup,
                namespace_ids=tuple(sorted(evidence.child.identities.items())),
                policy_digest=prepared.policy_digest,
                workspace_destination="/workspace",
                workspace_device=workspace_mount.source.identity.device,
                workspace_inode=workspace_mount.source.identity.inode,
                workspace_file_type=workspace_mount.source.identity.file_type,
                executable=worker_argv[0],
                argv=tuple(worker_argv),
                prepared_at=utc_now_iso(),
            )
            handle = PreparedM4AExecution(
                runner=self,
                proc=proc,
                worker_argv=worker_argv,
                started_at=started_at,
                process_identity=identity,
                scope=scope,
                cgroup_path=cgroup_path,
                control_fd=control_fd,
                native_status_fd=native_status_r,
                json_status_fd=json_status_r,
                launch_request=prepared,
                launch_transcript=transcript,
                launch_outcome=outcome,
                plan=plan,
                workspace_mount=workspace_mount,
                namespace_evidence=evidence,
                receipt=receipt,
                marker_instrumented=_marker_path is not None,
            )
            handle_ready = True
            return handle
        except BaseException as launch_error:
            self.last_launch_outcome = outcome
            self._emit(
                EV_RUNTIME_FAILURE,
                unit=scope,
                stage=outcome.get("failed_stage", "namespace"),
                error_type=type(launch_error).__name__,
            )
            if proc is not None:
                self._cleanup_failed_process(scope, cgroup_path, proc, launch_error)
            if isinstance(
                launch_error, (NamespaceEvidenceError, RuntimeBoundaryUnavailable)
            ):
                raise ContainmentUnavailableError(
                    f"M4A launch evidence failed: {launch_error}"
                ) from launch_error
            raise
        finally:
            for fd in child_ends:
                try:
                    os.close(fd)
                except OSError:
                    pass
            self._close_source_fds(sources)
            if bwrap_fd >= 0:
                try:
                    os.close(bwrap_fd)
                except OSError:
                    pass
            if namespace_gate_w >= 0:
                os.close(namespace_gate_w)

            if not handle_ready:
                for fd in (native_status_r, json_status_r):
                    try:
                        os.close(fd)
                    except OSError:
                        pass

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | os.PathLike[str],
        env: Mapping[str, str],
        timeout: Optional[float] = None,
        _leak_fds: Sequence[int] = (),
        _marker_path: Optional[Path] = None,
    ) -> ProcessResult:
        """Compatibility one-shot composed from the split-phase contract."""
        token = uuid.uuid4().hex
        reservation = ContainmentReservation(
            schema=CONTAINMENT_RESERVATION_SCHEMA,
            project_id="one-shot",
            task_id="one-shot",
            task_generation=1,
            attempt=1,
            controller_epoch=1,
            lease_epoch=1,
            dispatch_nonce=token,
            unit_name=f"aos-task-{token[:24]}",
            release_nonce=uuid.uuid4().hex,
        )
        prepared = self.prepare(
            argv,
            cwd=cwd,
            env=env,
            reservation=reservation,
            _leak_fds=_leak_fds,
            _marker_path=_marker_path,
        )
        try:
            prepared.release(prepared.receipt, reservation.release_nonce)
            return prepared.wait(timeout=timeout)
        except BaseException:
            if not prepared.terminal:
                prepared.cancel()
            raise
