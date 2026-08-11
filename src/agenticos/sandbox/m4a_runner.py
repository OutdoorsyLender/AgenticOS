"""Composed Milestone 4A Bubblewrap, Landlock, and cgroup runner."""

from __future__ import annotations

import os
import select
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
from .models import ProcessIdentity, ProcessResult, utc_now_iso
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


class NamespaceLandlockRunner(CgroupProcessRunner):
    """Production M4A composition; unavailable until every gate is proven."""

    name = "bubblewrap-landlock-native"

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
        if str(cwd) != "/workspace":
            raise ValueError("M4A worker cwd must be the stable /workspace ABI")
        support = self.check_support()
        if not support.supported:
            raise ContainmentUnavailableError(
                "M4A runtime boundary unavailable: " + "; ".join(support.reasons)
            )
        timeout = self.default_timeout if timeout is None else float(timeout)
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
        unit = f"aos-task-{uuid.uuid4().hex[:12]}"
        scope = f"{unit}.scope"
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
        launch_ready = False
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
            self._write_all(control_fd, b"X", budget=self.setup_timeout)
            proc.stdin.close()
            trailing, status_eof = NativeLandlockRunner._read_post_release_status(
                native_status_r, budget=self.setup_timeout
            )
            if not status_eof:
                raise ContainmentUnavailableError(
                    "native status channel did not close on worker exec"
                )
            outcome = parse_launcher_status(
                transcript + trailing,
                expected_nonce=prepared.nonce,
                expected_policy_digest=prepared.policy_digest,
                expected_min_abi=3,
                protocol_version=2,
            )
            if outcome.get("failed_stage") is not None:
                raise ContainmentUnavailableError(
                    f"M4A launcher failed at {outcome['failed_stage']}"
                )
            outcome["exec_succeeded"] = True
            self.last_launch_outcome = outcome
            self._emit(EV_EXEC_ATTEMPTED, unit=scope)
            launch_ready = True
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

            if not launch_ready:
                for fd in (native_status_r, json_status_r):
                    try:
                        os.close(fd)
                    except OSError:
                        pass

        assert proc is not None
        try:
            os.close(native_status_r)
            native_status_r = -1
            timed_out = False
            containment_state = ContainmentState.RUNNING.value
            try:
                out_b, err_b = self._communicate_process(proc, timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                cancellation_state = self._cancel(scope, cgroup_path, proc)
                if cancellation_state is not ContainmentState.TERMINATED:
                    raise ContainmentUnavailableError(
                        "timed-out M4A task cleanup was not proven"
                    )
                containment_state = cancellation_state.value
                out_b, err_b = self._communicate_process(proc, self.setup_timeout)

            if cgroup_path is not None and not wait_cgroup_empty(
                self.backend,
                cgroup_path,
                0.2,
                self.cancellation.poll_interval,
            ):
                containment_state = self._cancel(scope, cgroup_path, proc).value
            elif cgroup_path is not None:
                if containment_state == ContainmentState.RUNNING.value:
                    containment_state = ContainmentState.TERMINATED.value
                self._emit(EV_CGROUP_EMPTY_VERIFIED, unit=scope, after="clean exit")
            else:
                containment_state = ContainmentState.FAILED.value
            self.backend.stop_unit(scope)
            if self.backend.unit_active(scope):
                containment_state = ContainmentState.FAILED.value
            if containment_state != ContainmentState.TERMINATED.value:
                raise ContainmentUnavailableError(
                    "M4A task cleanup did not reach proven TERMINATED state"
                )
            self._emit(
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
                gate_ordering=dict(self.last_ordering_observations),
                worker_marker_instrumented=_marker_path is not None,
                landlock_abi=outcome.get("abi"),
                handled_access_fs=outcome.get("handled_access_fs"),
                identity_verified=outcome.get("identity_verified"),
                policy_applied=outcome.get("policy_applied"),
                exec_succeeded=outcome.get("exec_succeeded"),
                containment_state=containment_state,
                cleanup="recursive_cgroup_empty",
            )
            self._emit(EV_TASK_EXITED, unit=scope, containment_state=containment_state)

            finished_at = utc_now_iso()
            return self._assemble_process_result(
                proc=proc,
                worker_argv=worker_argv,
                out_b=out_b,
                err_b=err_b,
                timed_out=timed_out,
                started_at=started_at,
                finished_at=finished_at,
                identity=identity,
                scope=scope,
                cgroup_path=cgroup_path,
                containment_state=containment_state,
            )
        except BaseException as runtime_error:
            self._emit(
                EV_RUNTIME_FAILURE,
                unit=scope,
                stage="host_lifecycle",
                error_type=type(runtime_error).__name__,
            )
            self._cleanup_failed_process(scope, cgroup_path, proc, runtime_error)
            raise
        finally:
            for fd in (native_status_r, json_status_r):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
