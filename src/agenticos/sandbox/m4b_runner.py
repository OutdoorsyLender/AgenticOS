"""Authenticated M4B-1 pre-exec readiness coordination.

The pure coordinator in this module consumes only fixed, typed observations
collected by the live runner.  It has no process-discovery or descriptor-I/O
authority of its own, which keeps the four release writes deterministic and
unit-testable.
"""

from __future__ import annotations

from collections.abc import Callable
import array
from dataclasses import dataclass
import hashlib
import json
import re
import stat
import os
import select
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Mapping, Optional, Sequence

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore[assignment]

from .containment import (
    ContainmentState,
    ContainmentUnavailableError,
    EV_CGROUP_EMPTY_VERIFIED,
    wait_cgroup_empty,
)
from .launcher import (
    NativeLandlockRunner,
    NetworkLaunchRecord,
    PreparedLaunchRequest,
    parse_launcher_status,
    prepare_launch_request,
)
from .m4a_runner import NamespaceLandlockRunner
from .capabilities import parse_proc_cgroup
from .models import ProcessIdentity, ProcessResult, utc_now_iso
from .network_boundary import (
    BROKER_CODE_FD,
    BROKER_IDENTITY_CODE_FD,
    BROKER_JSON_STATUS_FD,
    BROKER_MODELS_CODE_FD,
    BROKER_RUNTIME_USR_FD,
    SUPERVISOR_BWRAP_FD,
    SUPERVISOR_EXECUTABLE_FD,
    SUPERVISOR_STATUS_FD,
    BrokerBwrapSetupStatus,
    NetworkBoundaryPlan,
    build_network_boundary_plan,
    read_broker_bwrap_setup_status,
)
from .network_broker import (
    BROKER_ENVIRONMENT,
    BROKER_ROOT,
    BROKER_CONTROL_FD,
    BROKER_FIXTURE_FD,
    BROKER_HANDOFF_FD,
    BROKER_POLICY_FD,
    BROKER_STATUS_FD,
    CONTROL_REVOKE,
    EnvironmentEvidence,
    INTERPRETER_PATH,
    MAX_READY_BYTES,
    NetworkBrokerReadyRecord,
    ObservedFileIdentity,
    ProcStatusEvidence,
    SealedPolicyEvidence,
    validate_broker_environment,
    validate_fixture_fd,
)
from .network_identity import (
    VerifiedSealedPolicy,
    create_sealed_policy_fd,
    read_sealed_policy_fd,
)
from .network_models import (
    TransportMode,
    TransportPolicy,
    canonical_policy_bytes,
    policy_digest,
)
from .runtime_boundary import (
    AuthorizedSource,
    FileIdentity,
    NamespaceEvidence,
    NamespaceEvidenceError,
    RuntimeBoundaryPlan,
    RuntimeBoundaryUnavailable,
    build_bwrap_argv,
    build_runtime_plan,
    open_verified_bwrap,
    read_bwrap_setup_status,
    read_namespace_snapshot,
    secure_open_source,
    verify_namespace_evidence,
)


EV_CONTAINMENT_VERIFIED = "CONTAINMENT_VERIFIED"
EV_NAMESPACE_VERIFIED = "NAMESPACE_BOUNDARY_VERIFIED"
EV_BROKER_PROCESS_VERIFIED = "BROKER_PROCESS_VERIFIED"
EV_LAUNCHER_ENTERED = "TRUSTED_LAUNCHER_ENTERED"
EV_LISTENER_EXPORTED = "NETWORK_LISTENER_EXPORTED"
EV_BROKER_READY = "NETWORK_BROKER_READY"
EV_FD_SANITIZED = "FD_SET_SANITIZED"
EV_IDENTITIES_VERIFIED = "SANDBOX_IDENTITIES_VERIFIED"
EV_POLICY_PREPARED = "FILESYSTEM_POLICY_PREPARED"
EV_NO_NEW_PRIVS = "NO_NEW_PRIVS_SET"
EV_POLICY_APPLIED = "FILESYSTEM_POLICY_APPLIED"
EV_WORKER_EXEC_ATTEMPTED = "WORKER_EXEC_ATTEMPTED"

_MAX_SUPERVISOR_STATUS_BYTES = 128
_SUPERVISOR_PID_RE = re.compile(
    rb"AOSSUP/1 BROKER_PID ([1-9][0-9]*)\n\Z"
)
_MAX_PID = (1 << 31) - 1
_BOOT_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_NETNS_RE = re.compile(r"net:\[([1-9][0-9]*)\]\Z")

_WORKER_HANDOFF_FD = 35
_WORKER_NAMESPACE_GATE_FD = 40
_WORKER_JSON_STATUS_FD = 41
_WORKER_LAUNCHER_STATUS_FD = 42
_WORKER_SOURCE_MINIMUM = 50
_CONTROLLER_FD_MINIMUM = 100
_MAX_CAPTURE_BYTES = 64 * 1024 * 1024
_POLL_READ_CLOSED = getattr(select, "POLLRDHUP", 0x2000)
_MAX_CONSUMED_TRANSPORT_AUTHORITIES = 1 << 16
_CONSUMED_TRANSPORT_AUTHORITIES: set[tuple[str, int, str, str]] = set()
_TRANSPORT_AUTHORITY_REGISTRY_LOCK = threading.Lock()


class CapabilityTransportError(RuntimeError):
    """Typed launch evidence did not authorize the next release gate."""


class _OwnedDescriptors:
    """Idempotent ownership ledger for fail-closed launch cleanup."""

    def __init__(self) -> None:
        self._fds: set[int] = set()

    def add(self, *fds: int) -> None:
        for fd in fds:
            if type(fd) is not int or fd < 0:
                raise ValueError("owned descriptor must be nonnegative")
            self._fds.add(fd)

    def release(self, fd: int) -> None:
        self._fds.discard(fd)

    def close(self) -> None:
        while self._fds:
            fd = self._fds.pop()
            try:
                os.close(fd)
            except OSError:
                pass


@dataclass(frozen=True)
class _ExpectedBrokerBoundary:
    """Controller-derived evidence required before the close gate."""

    runtime_identity: ObservedFileIdentity
    broker_code_identity: ObservedFileIdentity
    identity_code_identity: ObservedFileIdentity
    models_code_identity: ObservedFileIdentity
    interpreter_identity: ObservedFileIdentity
    sealed_policy: SealedPolicyEvidence
    verified_policy: VerifiedSealedPolicy
    proc_status: ProcStatusEvidence
    fd_numbers: tuple[int, ...]
    environment: EnvironmentEvidence
    filesystem_digest: str


def _filesystem_identity(identity: ObservedFileIdentity) -> dict[str, int]:
    return {
        "device": identity.device,
        "inode": identity.inode,
        "file_type": identity.file_type,
    }


def _expected_broker_filesystem_digest(
    *,
    runtime_identity: ObservedFileIdentity,
    broker_code_identity: ObservedFileIdentity,
    identity_code_identity: ObservedFileIdentity,
    models_code_identity: ObservedFileIdentity,
) -> str:
    payload = {
        "cwd": BROKER_ROOT,
        "empty": ["/home/broker", "/run", "/tmp"],
        "identities": {
            "broker_code": _filesystem_identity(broker_code_identity),
            "identity_code": _filesystem_identity(identity_code_identity),
            "models_code": _filesystem_identity(models_code_identity),
            "runtime": _filesystem_identity(runtime_identity),
        },
        "root_entries": [
            "bin",
            "dev",
            "home",
            "lib",
            "lib64",
            "opt",
            "proc",
            "run",
            "sbin",
            "tmp",
            "usr",
        ],
        "symlinks": {
            "/bin": "usr/bin",
            "/lib": "usr/lib",
            "/lib64": "usr/lib64",
            "/sbin": "usr/sbin",
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class _PreparedLiveLaunch:
    owned: _OwnedDescriptors
    sources: tuple[AuthorizedSource, ...]
    runtime_plan: RuntimeBoundaryPlan
    network_plan: NetworkBoundaryPlan
    prepared_request: PreparedLaunchRequest
    supervisor_argv: tuple[str, ...]
    pass_fds: tuple[int, ...]
    child_fds: tuple[int, ...]
    namespace_gate_w: int
    worker_json_status_r: int
    launcher_status_r: int
    broker_json_status_r: int
    supervisor_status_r: int
    broker_ready_r: int
    broker_control_w: int
    expected_bwrap_identity: FileIdentity
    expected_supervisor_identity: FileIdentity
    expected_interpreter_identity: FileIdentity
    expected_broker_boundary: _ExpectedBrokerBoundary


class _LiveAuthority:
    """Private mutable evidence carrier populated only by the live runner."""


class CapabilityTransportRunner(NamespaceLandlockRunner):
    """M4B-1 runner that adds one authenticated broker capability boundary."""

    name = "bubblewrap-landlock-capability-transport"

    def __init__(
        self,
        worker_path,
        *,
        workspace,
        profile,
        launcher_path,
        task_tmp,
        synthetic_home,
        transport_policy: TransportPolicy,
        supervisor_path,
        setup_timeout: float = 10.0,
        **kwargs,
    ) -> None:
        if type(transport_policy) is not TransportPolicy:
            raise TypeError("transport_policy must be exact TransportPolicy")
        super().__init__(
            worker_path,
            workspace=workspace,
            profile=profile,
            launcher_path=launcher_path,
            task_tmp=task_tmp,
            synthetic_home=synthetic_home,
            setup_timeout=setup_timeout,
            **kwargs,
        )
        self.transport_policy = transport_policy
        self.supervisor_path = Path(supervisor_path)

    def _claim_transport_authority(self) -> None:
        """Consume exact policy authority once per controller-process lifetime.

        This registry deliberately never evicts: when its fixed bound is full,
        the controller fails closed. A controller restart is a new trust-domain
        lifetime, so the outer AgenticOS task authority must continue issuing
        globally fresh task generations/nonces across controller processes.
        """
        policy = self.transport_policy
        if type(policy) is not TransportPolicy:
            raise CapabilityTransportError(
                "transport launch authority has the wrong exact type"
            )
        key = (
            policy.task_id,
            policy.task_generation,
            policy.launch_nonce,
            policy_digest(policy),
        )
        with _TRANSPORT_AUTHORITY_REGISTRY_LOCK:
            if key in _CONSUMED_TRANSPORT_AUTHORITIES:
                raise CapabilityTransportError(
                    "transport launch authority is already consumed"
                )
            if (
                len(_CONSUMED_TRANSPORT_AUTHORITIES)
                >= _MAX_CONSUMED_TRANSPORT_AUTHORITIES
            ):
                raise CapabilityTransportError(
                    "transport authority registry reached its fail-closed bound"
                )
            _CONSUMED_TRANSPORT_AUTHORITIES.add(key)

    def _pin_synthetic_fixture(self, fd: int | None) -> int | None:
        if self.transport_policy.mode is TransportMode.DENY:
            if fd is not None:
                raise CapabilityTransportError(
                    "deny transport cannot receive a synthetic fixture"
                )
            return None
        if self.transport_policy.mode is not TransportMode.SYNTHETIC_FIXTURE_FD:
            raise CapabilityTransportError("transport policy mode is unsupported")
        if type(fd) is not int or fd < 0 or fcntl is None:
            raise CapabilityTransportError(
                "synthetic transport requires one test-only fixture descriptor"
            )
        try:
            pinned = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 400)
        except OSError as exc:
            raise CapabilityTransportError(
                "synthetic fixture capability cannot be pinned"
            ) from exc
        try:
            validate_fixture_fd(pinned)
        except BaseException:
            os.close(pinned)
            raise
        return pinned

    def check_support(self, refresh: bool = False):
        support = super().check_support(refresh=refresh)
        if not self.supervisor_path.is_file():
            support.supported = False
            support.reasons.append(
                f"native task supervisor missing: {self.supervisor_path}"
            )
        return support

    def _open_worker_sources_m4b(self) -> tuple[AuthorizedSource, ...]:
        specs = (
            (self.workspace, stat.S_IFDIR),
            (Path("/usr"), stat.S_IFDIR),
            (self.launcher_path, stat.S_IFREG),
            (self.worker_path, stat.S_IFREG),
            (self.task_tmp, stat.S_IFDIR),
            (self.synthetic_home, stat.S_IFDIR),
        )
        opened: list[AuthorizedSource] = []
        try:
            for index, (path, expected_type) in enumerate(specs):
                opened.append(
                    self._open_high_source(
                        path,
                        expected_type=expected_type,
                        minimum=_WORKER_SOURCE_MINIMUM + index,
                    )
                )
            return tuple(opened)
        except BaseException:
            self._close_source_fds(opened)
            raise

    def _prepare_live_launch(
        self,
        worker_argv: list[str],
        *,
        synthetic_fixture_fd: int | None = None,
    ) -> _PreparedLiveLaunch:
        if self.transport_policy.mode is TransportMode.DENY:
            if synthetic_fixture_fd is not None:
                raise CapabilityTransportError(
                    "deny transport cannot receive a synthetic fixture"
                )
        elif self.transport_policy.mode is TransportMode.SYNTHETIC_FIXTURE_FD:
            if type(synthetic_fixture_fd) is not int or synthetic_fixture_fd < 0:
                raise CapabilityTransportError(
                    "synthetic transport requires one test-only fixture descriptor"
                )
            validate_fixture_fd(synthetic_fixture_fd)
        else:
            raise CapabilityTransportError(
                "transport policy mode is unsupported"
            )
        owned = _OwnedDescriptors()
        sources: list[AuthorizedSource] = []

        def exact_pipe(*, child_reads: bool, target: int) -> tuple[int, int]:
            read_fd, write_fd = os.pipe()
            try:
                if child_reads:
                    controller = self._move_fd(write_fd, _CONTROLLER_FD_MINIMUM)
                    os.set_inheritable(controller, False)
                    child = _move_exact_fd(read_fd, target)
                    owned.add(controller, child)
                    return child, controller
                controller = self._move_fd(read_fd, _CONTROLLER_FD_MINIMUM)
                os.set_inheritable(controller, False)
                child = _move_exact_fd(write_fd, target)
                owned.add(controller, child)
                return controller, child
            except BaseException:
                for fd in (read_fd, write_fd):
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                raise

        def exact_socketpair(
            first_target: int, second_target: Optional[int]
        ) -> tuple[int, int]:
            first_socket, second_socket = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
            )
            first_raw = first_socket.detach()
            second_raw = second_socket.detach()
            try:
                first = _move_exact_fd(first_raw, first_target)
                if second_target is None:
                    second = self._move_fd(
                        second_raw, _CONTROLLER_FD_MINIMUM
                    )
                    os.set_inheritable(second, False)
                else:
                    second = _move_exact_fd(second_raw, second_target)
                owned.add(first, second)
                return first, second
            except BaseException:
                for fd in (first_raw, second_raw):
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                raise

        try:
            bwrap_fd = _move_exact_fd(
                open_verified_bwrap(self._bwrap_capability),
                SUPERVISOR_BWRAP_FD,
            )
            owned.add(bwrap_fd)
            expected_bwrap_identity = FileIdentity.from_stat(os.fstat(bwrap_fd))

            supervisor = _open_exact_source(
                self.supervisor_path,
                stat.S_IFREG,
                SUPERVISOR_EXECUTABLE_FD,
            )
            broker_runtime = _open_exact_source(
                Path("/usr"), stat.S_IFDIR, BROKER_RUNTIME_USR_FD
            )
            broker_code = _open_exact_source(
                Path(__file__).with_name("network_broker.py"),
                stat.S_IFREG,
                BROKER_CODE_FD,
            )
            identity_code = _open_exact_source(
                Path(__file__).with_name("network_identity.py"),
                stat.S_IFREG,
                BROKER_IDENTITY_CODE_FD,
            )
            models_code = _open_exact_source(
                Path(__file__).with_name("network_models.py"),
                stat.S_IFREG,
                BROKER_MODELS_CODE_FD,
            )
            network_sources = (
                supervisor,
                broker_runtime,
                broker_code,
                identity_code,
                models_code,
            )
            sources.extend(network_sources)
            owned.add(*(source.fd for source in network_sources))

            interpreter = secure_open_source(
                Path(INTERPRETER_PATH), expected_type=stat.S_IFREG
            )
            expected_interpreter_identity = interpreter.identity
            os.close(interpreter.fd)

            worker_sources = self._open_worker_sources_m4b()
            sources.extend(worker_sources)
            owned.add(*(source.fd for source in worker_sources))
            (
                workspace,
                runtime_usr,
                launcher,
                worker,
                task_tmp,
                synthetic_home,
            ) = worker_sources
            runtime_plan = build_runtime_plan(
                profile=self.profile,
                workspace=workspace,
                runtime_usr=runtime_usr,
                launcher=launcher,
                worker=worker,
                task_tmp=task_tmp,
                synthetic_home=synthetic_home,
            )

            policy_fd = _move_exact_fd(
                create_sealed_policy_fd(self.transport_policy), BROKER_POLICY_FD
            )
            owned.add(policy_fd)
            if synthetic_fixture_fd is not None:
                fixture_duplicate = os.dup(synthetic_fixture_fd)
                try:
                    fixture_capability = _move_exact_fd(
                        fixture_duplicate, BROKER_FIXTURE_FD
                    )
                except BaseException:
                    try:
                        os.close(fixture_duplicate)
                    except OSError:
                        pass
                    raise
                owned.add(fixture_capability)
            verified_policy = read_sealed_policy_fd(policy_fd)
            if (
                verified_policy.policy != self.transport_policy
                or verified_policy.digest != policy_digest(self.transport_policy)
            ):
                _reject("sealed transport policy does not match controller authority")
            _broker_handoff, worker_handoff = exact_socketpair(
                BROKER_HANDOFF_FD, _WORKER_HANDOFF_FD
            )
            _broker_ready, broker_ready_r = exact_socketpair(
                BROKER_STATUS_FD, None
            )
            _broker_control, broker_control_w = exact_socketpair(
                BROKER_CONTROL_FD, None
            )
            broker_json_status_r, _broker_json_status_w = exact_pipe(
                child_reads=False, target=BROKER_JSON_STATUS_FD
            )
            supervisor_status_r, _supervisor_status_w = exact_pipe(
                child_reads=False, target=SUPERVISOR_STATUS_FD
            )
            _namespace_gate_r, namespace_gate_w = exact_pipe(
                child_reads=True, target=_WORKER_NAMESPACE_GATE_FD
            )
            worker_json_status_r, _worker_json_status_w = exact_pipe(
                child_reads=False, target=_WORKER_JSON_STATUS_FD
            )
            launcher_status_r, _launcher_status_w = exact_pipe(
                child_reads=False, target=_WORKER_LAUNCHER_STATUS_FD
            )

            network_plan = build_network_boundary_plan(
                transport_policy=self.transport_policy,
                runtime_usr=broker_runtime,
                broker_code=broker_code,
                identity_code=identity_code,
                models_code=models_code,
                supervisor=supervisor,
            )
            contract = network_plan.broker_contract
            interpreter_observed = ObservedFileIdentity(
                expected_interpreter_identity.device,
                expected_interpreter_identity.inode,
                expected_interpreter_identity.file_type,
            )
            sealed_policy = SealedPolicyEvidence(
                device=verified_policy.device,
                inode=verified_policy.inode,
                size=verified_policy.size,
                seals=verified_policy.seals,
            )
            expected_broker_boundary = _ExpectedBrokerBoundary(
                runtime_identity=contract.runtime_identity,
                broker_code_identity=contract.broker_code_identity,
                identity_code_identity=contract.identity_code_identity,
                models_code_identity=contract.models_code_identity,
                interpreter_identity=interpreter_observed,
                sealed_policy=sealed_policy,
                verified_policy=verified_policy,
                proc_status=ProcStatusEvidence(0, 0, 0, 0, 0, 1),
                fd_numbers=(0, 1, 2, *contract.capability_fds),
                environment=validate_broker_environment(dict(BROKER_ENVIRONMENT)),
                filesystem_digest=_expected_broker_filesystem_digest(
                    runtime_identity=contract.runtime_identity,
                    broker_code_identity=contract.broker_code_identity,
                    identity_code_identity=contract.identity_code_identity,
                    models_code_identity=contract.models_code_identity,
                ),
            )
            worker_bwrap = build_bwrap_argv(
                runtime_plan,
                namespace_gate_fd=_WORKER_NAMESPACE_GATE_FD,
                json_status_fd=_WORKER_JSON_STATUS_FD,
                launcher_status_fd=_WORKER_LAUNCHER_STATUS_FD,
                executable=Path("bwrap"),
            )
            worker_pass_fds = tuple(
                sorted(
                    (
                        *(source.fd for source in worker_sources),
                        _WORKER_HANDOFF_FD,
                        _WORKER_NAMESPACE_GATE_FD,
                        _WORKER_JSON_STATUS_FD,
                        _WORKER_LAUNCHER_STATUS_FD,
                    )
                )
            )
            supervisor_argv = network_plan.supervisor_contract.argv_for(
                worker_bwrap, worker_pass_fds=worker_pass_fds
            )
            workspace_mount = runtime_plan.mount_for("/workspace")
            authorized_roots = [
                (
                    mount.destination,
                    mount.source.identity.device,
                    mount.source.identity.inode,
                    mount.landlock_mode,
                )
                for mount in runtime_plan.mounts
            ]
            network_record = NetworkLaunchRecord(
                task_id=self.transport_policy.task_id,
                task_generation=self.transport_policy.task_generation,
                launch_nonce=self.transport_policy.launch_nonce,
                network_policy_digest=network_plan.transport_policy_digest,
                handoff_fd=_WORKER_HANDOFF_FD,
                proxy_host=self.transport_policy.proxy_host,
                proxy_port=self.transport_policy.proxy_port,
            )
            prepared_request = prepare_launch_request(
                worker_argv,
                dict(runtime_plan.worker_environment),
                "/workspace",
                [],
                min_abi=3,
                protocol_version=3,
                status_fd=_WORKER_LAUNCHER_STATUS_FD,
                network_record=network_record,
                cwd_record=(
                    "/workspace",
                    workspace_mount.source.identity.device,
                    workspace_mount.source.identity.inode,
                ),
                root_records=[*authorized_roots, ("/dev/null", 0, 0, "w")],
                policy_digest_override=runtime_plan.combined_policy_digest,
            )
            child_fds = tuple(
                sorted(
                    {
                        SUPERVISOR_BWRAP_FD,
                        SUPERVISOR_STATUS_FD,
                        SUPERVISOR_EXECUTABLE_FD,
                        *network_plan.supervisor_contract.broker_pass_fds,
                        *worker_pass_fds,
                    }
                )
            )
            return _PreparedLiveLaunch(
                owned=owned,
                sources=tuple(sources),
                runtime_plan=runtime_plan,
                network_plan=network_plan,
                prepared_request=prepared_request,
                supervisor_argv=supervisor_argv,
                pass_fds=child_fds,
                child_fds=child_fds,
                namespace_gate_w=namespace_gate_w,
                worker_json_status_r=worker_json_status_r,
                launcher_status_r=launcher_status_r,
                broker_json_status_r=broker_json_status_r,
                supervisor_status_r=supervisor_status_r,
                broker_ready_r=broker_ready_r,
                broker_control_w=broker_control_w,
                expected_bwrap_identity=expected_bwrap_identity,
                expected_supervisor_identity=supervisor.identity,
                expected_interpreter_identity=expected_interpreter_identity,
                expected_broker_boundary=expected_broker_boundary,
            )
        except BaseException:
            owned.close()
            raise

    def _cleanup_live_launch_failure(
        self,
        owned: _OwnedDescriptors,
        scope: str,
        cgroup_path: Optional[Path],
        proc: Optional[subprocess.Popen],
        cause: BaseException,
    ) -> None:
        """Close every release/capability FD before recursive scope cleanup."""
        owned.close()
        if proc is not None:
            self._cleanup_failed_process(scope, cgroup_path, proc, cause)

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | os.PathLike[str],
        env: Mapping[str, str],
        timeout: Optional[float] = None,
        _leak_fds: Sequence[int] = (),
        _marker_path: Optional[Path] = None,
        _synthetic_fixture_fd: int | None = None,
    ) -> ProcessResult:
        """Launch one protocol-v3 worker only after authenticated readiness."""
        if str(cwd) != "/workspace":
            raise ValueError("M4B worker cwd must be the stable /workspace ABI")
        if _leak_fds:
            raise ValueError("M4B does not permit additional inherited descriptors")
        self._claim_transport_authority()
        pinned_fixture = self._pin_synthetic_fixture(_synthetic_fixture_fd)
        try:
            support = self.check_support()
            if not support.supported:
                raise ContainmentUnavailableError(
                    "M4B capability transport unavailable: "
                    + "; ".join(support.reasons)
                )
            if self._bwrap_capability is None:
                raise ContainmentUnavailableError(
                    "Bubblewrap capability evidence is missing"
                )
            worker_argv = [str(item) for item in argv]
            timeout = self.default_timeout if timeout is None else float(timeout)
            prepared = self._prepare_live_launch(
                worker_argv, synthetic_fixture_fd=pinned_fixture
            )
        finally:
            if pinned_fixture is not None:
                os.close(pinned_fixture)
        owned = prepared.owned
        unit = f"aos-task-{uuid.uuid4().hex[:12]}"
        scope = f"{unit}.scope"
        started_at = utc_now_iso()
        proc: Optional[subprocess.Popen] = None
        identity: Optional[ProcessIdentity] = None
        cgroup_path: Optional[Path] = None
        launch_ready = False
        outcome: dict = {
            "progress": [],
            "failed_stage": "containment",
            "policy_applied": False,
            "exec_succeeded": False,
        }
        transcript = bytearray()
        authority = _LiveAuthority()
        self.last_ordering_observations = {}
        self.last_namespace_evidence = None
        self.last_broker_process = None
        self.last_listener_evidence = None
        self.last_broker_identity_mapping = None
        self.last_launch_outcome = outcome

        try:
            command = [
                self.backend.systemd_run,
                "--user",
                "--scope",
                "--quiet",
                "--collect",
                f"--unit={unit}",
                "--",
                f"/proc/self/fd/{SUPERVISOR_EXECUTABLE_FD}",
                *prepared.supervisor_argv[1:],
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
                pass_fds=prepared.pass_fds,
            )
            identity = ProcessIdentity.from_pid(proc.pid)

            for fd in prepared.child_fds:
                owned.release(fd)
                try:
                    os.close(fd)
                except OSError:
                    pass

            broker_setup = read_broker_bwrap_setup_status(
                prepared.broker_json_status_r, timeout=self.setup_timeout
            )
            worker_setup = read_bwrap_setup_status(
                prepared.worker_json_status_r, timeout=self.setup_timeout
            )
            supervisor_status = _read_to_eof(
                prepared.supervisor_status_r,
                budget=self.setup_timeout,
                maximum=_MAX_SUPERVISOR_STATUS_BYTES,
            )
            broker_outer_pid = _parse_supervisor_broker_pid(supervisor_status)

            cgroup_path = self._discover_cgroup(scope, proc.pid)
            if cgroup_path is None:
                raise ContainmentUnavailableError(
                    "containment cgroup could not be verified before release"
                )
            expected_cgroup = self._cgroup_relative(
                self.cgroup_root, cgroup_path
            )
            controller_snapshot = read_namespace_snapshot(os.getpid())
            worker_snapshot = read_namespace_snapshot(worker_setup.child_pid)
            worker_namespace = verify_namespace_evidence(
                worker_setup,
                controller=controller_snapshot,
                child=worker_snapshot,
                expected_cgroup=expected_cgroup,
                expected_host_uid=os.getuid(),
            )
            worker_outer = _read_observed_process(proc.pid)
            broker_outer = _read_observed_process(broker_outer_pid)
            self.last_broker_process = broker_outer
            ready_early, _, _ = select.select(
                [prepared.broker_ready_r], [], [], 0
            )

            network_record = NetworkLaunchRecord(
                task_id=self.transport_policy.task_id,
                task_generation=self.transport_policy.task_generation,
                launch_nonce=self.transport_policy.launch_nonce,
                network_policy_digest=prepared.network_plan.transport_policy_digest,
                handoff_fd=_WORKER_HANDOFF_FD,
                proxy_host=self.transport_policy.proxy_host,
                proxy_port=self.transport_policy.proxy_port,
            )
            authority.expected_cgroup = expected_cgroup
            authority.host_netns = controller_snapshot.identities["net"]
            authority.expected_bwrap_identity = prepared.expected_bwrap_identity
            authority.expected_supervisor_identity = (
                prepared.expected_supervisor_identity
            )
            authority.expected_broker_code_identity = (
                prepared.network_plan.broker_contract.broker_code_identity
            )
            authority.expected_broker_interpreter_identity = (
                prepared.expected_interpreter_identity
            )
            authority.expected_broker_boundary = (
                prepared.expected_broker_boundary
            )
            authority.supervisor_exec_contract_verified = (
                command[6] == "--"
                and command[7]
                == f"/proc/self/fd/{SUPERVISOR_EXECUTABLE_FD}"
                and prepared.supervisor_argv[0] == "task_supervisor"
            )
            authority.supervisor_process_identity = identity
            authority.transport_policy = self.transport_policy
            authority.worker_outer = worker_outer
            authority.supervisor_status_stream = supervisor_status
            authority.broker_outer = broker_outer
            authority.worker_namespace = worker_namespace
            authority.broker_setup = broker_setup
            authority.launcher_network_record = network_record
            authority.expected_filesystem_policy_digest = (
                prepared.runtime_plan.combined_policy_digest
            )
            authority.ready_before_namespace_release = bool(ready_early)

            assert proc.stdin is not None
            control_fd = proc.stdin.fileno()

            def controller_write(gate: str, payload: bytes) -> None:
                if gate in {"network_close_gate", "final_exec_gate"}:
                    authority.observed_at_monotonic_ns = time.monotonic_ns()
                    _require_active_transport_policy(authority)
                    _require_live_broker_identity(authority, gate)
                if gate == "namespace_gate":
                    self._write_all(
                        prepared.namespace_gate_w,
                        payload,
                        budget=self.setup_timeout,
                    )
                    owned.release(prepared.namespace_gate_w)
                    os.close(prepared.namespace_gate_w)
                    self._write_all(
                        control_fd,
                        prepared.prepared_request.wire,
                        budget=self.setup_timeout,
                    )
                    return
                self._write_all(control_fd, payload, budget=self.setup_timeout)
                if gate == "final_exec_gate":
                    proc.stdin.close()

            def transition(event: str) -> None:
                self._emit(event, unit=scope)

            def authenticate_entry() -> None:
                line = _read_line(
                    prepared.launcher_status_r,
                    budget=self.setup_timeout,
                    maximum=128,
                )
                transcript.extend(line)
                authority.launcher_entry_status = bytes(line)
                authority.launcher_status_before_ready = bytes(transcript)
                _parse_launcher_prefix(authority)
                _require_launcher_entry_quiescent(prepared.launcher_status_r)

            def authenticate_listener() -> dict:
                line = _read_line(
                    prepared.launcher_status_r,
                    budget=self.setup_timeout,
                    maximum=4096,
                )
                transcript.extend(line)
                authority.launcher_status_before_ready = bytes(transcript)
                return _parse_listener_prefix(authority)

            def authenticate_readiness(
                listener_outcome: dict,
            ) -> NetworkBrokerReadyRecord:
                payload = _read_ready_packet(
                    prepared.broker_ready_r, budget=self.setup_timeout
                )
                try:
                    ready_record = NetworkBrokerReadyRecord.from_bytes(payload)
                except BaseException as exc:
                    raise CapabilityTransportError(
                        "broker readiness record is invalid"
                    ) from exc
                authority.broker_ready_payloads = (payload,)
                self.last_listener_evidence = ready_record.listener
                authority.observed_at_monotonic_ns = time.monotonic_ns()
                authority.broker_recheck = _resolve_ready_broker_process(
                    cgroup_path,
                    ready_record,
                    expected_cgroup=expected_cgroup,
                    host_netns=authority.host_netns,
                    expected_interpreter=prepared.expected_interpreter_identity,
                    setup_pid=authority.broker_setup.child_pid,
                    expected_bwrap=prepared.expected_bwrap_identity,
                )
                self.last_broker_process = authority.broker_recheck
                self.last_broker_identity_mapping = {
                    "supervisor_broker_outer_pid": authority.broker_outer.pid,
                    "bwrap_setup_child_pid": authority.broker_setup.child_pid,
                    "readiness_namespace_pid": ready_record.process.pid,
                    "resolved_host_broker_pid": authority.broker_recheck.pid,
                    "resolved_parent_pid": authority.broker_setup.child_pid,
                    "start_time_ticks": authority.broker_recheck.start_time_ticks,
                    "boot_id": authority.broker_recheck.boot_id,
                }
                authority.readiness_preserved = True
                _require_active_transport_policy(authority)
                return _require_ready(authority, listener_outcome)

            def authenticate_post_close() -> dict:
                while True:
                    line = _read_line(
                        prepared.launcher_status_r,
                        budget=self.setup_timeout,
                        maximum=4096,
                    )
                    transcript.extend(line)
                    parsed = parse_launcher_status(
                        bytes(transcript),
                        expected_nonce=network_record.launch_nonce,
                        expected_policy_digest=(
                            prepared.runtime_plan.combined_policy_digest
                        ),
                        expected_network_record=network_record,
                        protocol_version=3,
                    )
                    if parsed.get("failed_stage") is not None:
                        raise CapabilityTransportError(
                            "launcher failed before filesystem policy release"
                        )
                    if parsed.get("progress") == [
                        "R", "L", "S", "I", "P", "N", "A"
                    ]:
                        break
                authority.launcher_status_after_close = bytes(transcript)
                return _parse_post_close_launcher(authority)

            operations = _CoordinatorOperations(
                verify_containment=lambda: _require_live_containment(authority),
                verify_worker_namespace=lambda: _require_worker_namespace(
                    authority
                ),
                verify_broker_process=lambda: _require_broker_outer(authority),
                authenticate_launcher_entry=authenticate_entry,
                authenticate_listener=authenticate_listener,
                authenticate_readiness=authenticate_readiness,
                authenticate_post_close=authenticate_post_close,
                verify_worker_marker_absent=lambda: (
                    self._marker_absent(_marker_path) is not False
                ),
                transition=transition,
                controller_write=controller_write,
            )
            coordinated = _coordinate_operations(operations)
            outcome = coordinated.launcher_outcome
            trailing, status_eof = NativeLandlockRunner._read_post_release_status(
                prepared.launcher_status_r, budget=self.setup_timeout
            )
            if not status_eof:
                raise CapabilityTransportError(
                    "launcher status channel did not close on worker exec"
                )
            outcome = parse_launcher_status(
                bytes(transcript) + trailing,
                expected_nonce=network_record.launch_nonce,
                expected_policy_digest=prepared.runtime_plan.combined_policy_digest,
                expected_network_record=network_record,
                protocol_version=3,
            )
            if outcome.get("failed_stage") is not None:
                raise CapabilityTransportError(
                    "launcher reported a terminal protocol-v3 failure"
                )
            outcome["exec_succeeded"] = True
            self.last_namespace_evidence = worker_namespace
            self.last_launch_outcome = outcome
            launch_ready = True
        except BaseException as launch_error:
            self.last_launch_outcome = outcome
            self._cleanup_live_launch_failure(
                owned, scope, cgroup_path, proc, launch_error
            )
            if isinstance(
                launch_error,
                (NamespaceEvidenceError, RuntimeBoundaryUnavailable),
            ):
                raise ContainmentUnavailableError(
                    f"M4B launch evidence failed: {launch_error}"
                ) from launch_error
            raise

        assert proc is not None
        try:
            timed_out = False
            containment_state = ContainmentState.RUNNING.value
            try:
                first_out, first_err = _pump_process_output_until_exit(
                    proc,
                    timeout=timeout,
                    verify_broker=lambda: _require_live_broker_identity(
                        authority, "hostile execution"
                    ),
                )
            except subprocess.TimeoutExpired as timeout_error:
                timed_out = True
                cancellation_state = self._cancel(scope, cgroup_path, proc)
                if cancellation_state is not ContainmentState.TERMINATED:
                    raise ContainmentUnavailableError(
                        "timed-out M4B task cleanup was not proven"
                    )
                containment_state = cancellation_state.value
                trailing_out, trailing_err = self._communicate_process(
                    proc, self.setup_timeout
                )
                out_b, err_b = _combine_captured_output(
                    timeout_error.output or b"",
                    timeout_error.stderr or b"",
                    trailing_out,
                    trailing_err,
                )
            else:
                broker_live = True
                try:
                    _require_live_broker_identity(authority, "worker exit cleanup")
                except CapabilityTransportError:
                    # The authenticated hostile worker has exited. The scope
                    # supervisor may synchronously reap its broker sibling;
                    # recursive-empty proof below remains mandatory.
                    broker_live = False
                if broker_live:
                    try:
                        _revoke_broker_control(
                            prepared.broker_control_w, budget=self.setup_timeout
                        )
                    except (BrokenPipeError, ConnectionResetError):
                        _require_broker_gone(authority)
                owned.release(prepared.broker_control_w)
                os.close(prepared.broker_control_w)
                trailing_out, trailing_err = self._communicate_process(
                    proc, self.setup_timeout
                )
                out_b, err_b = _combine_captured_output(
                    first_out, first_err, trailing_out, trailing_err
                )
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
                    "M4B task cleanup did not reach proven TERMINATED state"
                )
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
            self._cleanup_failed_process(scope, cgroup_path, proc, runtime_error)
            raise
        finally:
            if launch_ready:
                owned.close()


@dataclass(frozen=True)
class _ObservedProcess:
    pid: int
    start_time_ticks: int
    boot_id: str
    executable_identity: FileIdentity
    cgroup: str
    netns: int


@dataclass(frozen=True)
class _CoordinatorInputs:
    expected_cgroup: str
    host_netns: int
    expected_bwrap_identity: FileIdentity
    expected_supervisor_identity: FileIdentity
    expected_broker_code_identity: ObservedFileIdentity
    expected_broker_interpreter_identity: FileIdentity
    expected_broker_boundary: _ExpectedBrokerBoundary
    transport_policy: TransportPolicy
    observed_at_monotonic_ns: int
    supervisor_initial: _ObservedProcess
    worker_outer: _ObservedProcess
    supervisor_status_stream: bytes
    broker_outer: _ObservedProcess
    worker_namespace: NamespaceEvidence
    broker_setup: BrokerBwrapSetupStatus
    launcher_network_record: NetworkLaunchRecord
    launcher_entry_status: bytes
    launcher_status_before_ready: bytes
    broker_ready_payloads: tuple[bytes, ...]
    broker_recheck: _ObservedProcess
    launcher_status_after_close: bytes
    expected_filesystem_policy_digest: str
    readiness_preserved: bool
    ready_before_namespace_release: bool
    worker_marker_absent: bool


@dataclass(frozen=True)
class _CoordinatorResult:
    ready: NetworkBrokerReadyRecord
    launcher_outcome: dict


@dataclass(frozen=True)
class _CoordinatorOperations:
    """Fixed operations whose live implementation owns all observations."""

    verify_containment: Callable[[], None]
    verify_worker_namespace: Callable[[], None]
    verify_broker_process: Callable[[], None]
    authenticate_launcher_entry: Callable[[], None]
    authenticate_listener: Callable[[], dict]
    authenticate_readiness: Callable[[dict], NetworkBrokerReadyRecord]
    authenticate_post_close: Callable[[], dict]
    verify_worker_marker_absent: Callable[[], bool]
    transition: Callable[[str], None]
    controller_write: Callable[[str, bytes], None]


def _reject(message: str) -> None:
    raise CapabilityTransportError(message)


def _parse_supervisor_broker_pid(payload: bytes) -> int:
    if (
        type(payload) is not bytes
        or not 0 < len(payload) <= _MAX_SUPERVISOR_STATUS_BYTES
    ):
        _reject("supervisor status is missing or oversized")
    match = _SUPERVISOR_PID_RE.fullmatch(payload)
    if match is None:
        _reject("supervisor status is noncanonical, duplicate, or truncated")
    broker_pid = int(match.group(1))
    if broker_pid > _MAX_PID:
        _reject("supervisor broker PID is out of range")
    return broker_pid


def _read_bounded_proc_file(path: Path, maximum: int) -> bytes:
    try:
        with path.open("rb", buffering=0) as stream:
            payload = stream.read(maximum + 1)
    except OSError as exc:
        raise CapabilityTransportError(
            f"process evidence is unavailable: {path.name}"
        ) from exc
    if len(payload) > maximum:
        _reject(f"process evidence is oversized: {path.name}")
    return payload


def _process_start_time(payload: bytes) -> int:
    try:
        text = payload.decode("ascii")
        after_comm = text.rsplit(")", 1)[1].split()
        value = int(after_comm[19])
    except (UnicodeDecodeError, IndexError, ValueError) as exc:
        raise CapabilityTransportError("process stat evidence is malformed") from exc
    if value <= 0:
        _reject("process start time is invalid")
    return value


def _read_observed_process(
    pid: int, *, proc_root: Path = Path("/proc")
) -> _ObservedProcess:
    """Capture one stable controller-owned host process observation."""
    if (
        not sys.platform.startswith("linux")
        or type(pid) is not int
        or not 0 < pid <= _MAX_PID
    ):
        _reject("live process observation requires a Linux PID")
    root = Path(proc_root)
    process_root = root / str(pid)
    start_before = _process_start_time(
        _read_bounded_proc_file(process_root / "stat", 8192)
    )
    try:
        executable = FileIdentity.from_stat(os.stat(process_root / "exe"))
        netns_link = os.readlink(process_root / "ns" / "net")
    except OSError as exc:
        raise CapabilityTransportError(
            "process executable or network namespace is unavailable"
        ) from exc
    netns_match = _NETNS_RE.fullmatch(netns_link)
    if netns_match is None:
        _reject("process network namespace evidence is malformed")
    try:
        cgroup_text = _read_bounded_proc_file(
            process_root / "cgroup", 4096
        ).decode("ascii")
        boot_id = _read_bounded_proc_file(
            root / "sys" / "kernel" / "random" / "boot_id", 64
        ).decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise CapabilityTransportError("process text evidence is malformed") from exc
    cgroup = parse_proc_cgroup(cgroup_text)
    if cgroup is None or not cgroup.startswith("/"):
        _reject("process cgroup-v2 evidence is missing")
    if _BOOT_ID_RE.fullmatch(boot_id) is None:
        _reject("process boot identity is noncanonical")
    start_after = _process_start_time(
        _read_bounded_proc_file(process_root / "stat", 8192)
    )
    if start_before != start_after:
        _reject("process identity changed during observation")
    return _ObservedProcess(
        pid=pid,
        start_time_ticks=start_after,
        boot_id=boot_id,
        executable_identity=executable,
        cgroup=cgroup,
        netns=int(netns_match.group(1)),
    )


def _resolve_ready_broker_process(
    cgroup_path: Path,
    ready: NetworkBrokerReadyRecord,
    *,
    expected_cgroup: str,
    host_netns: int,
    expected_interpreter: FileIdentity,
    setup_pid: int,
    expected_bwrap: FileIdentity,
) -> _ObservedProcess:
    """Map namespace-local readiness to one exact host-visible cgroup member."""
    try:
        payload = (cgroup_path / "cgroup.procs").read_bytes()
    except OSError as exc:
        raise CapabilityTransportError(
            "broker cgroup membership is unavailable"
        ) from exc
    if not payload or len(payload) > 64 * 1024 or not payload.endswith(b"\n"):
        _reject("broker cgroup membership is empty, oversized, or truncated")
    lines = payload.splitlines()
    if len(lines) > 1024 or any(
        re.fullmatch(rb"[1-9][0-9]*", line) is None for line in lines
    ):
        _reject("broker cgroup membership is noncanonical or unbounded")
    setup = _read_observed_process(setup_pid)
    if (
        setup.executable_identity != expected_bwrap
        or setup.cgroup != expected_cgroup
        or setup.netns != host_netns
    ):
        _reject("broker Bubblewrap setup child boundary changed")
    candidates = []
    for line in lines:
        candidate_pid = int(line)
        try:
            stat_path = Path("/proc") / str(candidate_pid) / "stat"
            status_path = Path("/proc") / str(candidate_pid) / "status"
            stat_before = _read_bounded_proc_file(stat_path, 8192)
            status_before = _read_bounded_proc_file(status_path, 64 * 1024)
            after_comm = stat_before.decode("ascii").rsplit(")", 1)[1].split()
            parent_pid = int(after_comm[1])
            nspid_lines = [
                line for line in status_before.splitlines()
                if line.startswith(b"NSpid:")
            ]
            if len(nspid_lines) != 1:
                continue
            nspids = nspid_lines[0].split()[1:]
            if not nspids or any(
                re.fullmatch(rb"[1-9][0-9]*", value) is None
                for value in nspids
            ):
                continue
            observed = _read_observed_process(candidate_pid)
            stat_after = _read_bounded_proc_file(stat_path, 8192)
            status_after = _read_bounded_proc_file(status_path, 64 * 1024)
        except CapabilityTransportError:
            continue
        except (UnicodeDecodeError, IndexError, ValueError):
            continue
        if (
            stat_before == stat_after
            and status_before == status_after
            and parent_pid == setup.pid
            and int(nspids[-1]) == ready.process.pid
            and observed.start_time_ticks == ready.process.start_time_ticks
            and observed.boot_id == ready.process.boot_id
            and observed.executable_identity == expected_interpreter
            and observed.cgroup == expected_cgroup
            and observed.netns == host_netns
        ):
            candidates.append(observed)
    if len(candidates) != 1:
        _reject("readiness did not resolve to one exact host broker identity")
    if _read_observed_process(setup_pid) != setup:
        _reject("broker Bubblewrap setup child changed during resolution")
    return candidates[0]


def _move_exact_fd(fd: int, target: int) -> int:
    """Move an owned FD to one vacant fixed role without overwriting authority."""
    if fcntl is None:
        try:
            os.close(fd)
        finally:
            _reject("fixed descriptor setup requires Linux fcntl")
    if fd == target:
        os.set_inheritable(fd, True)
        return fd
    try:
        moved = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, target)
    except BaseException:
        os.close(fd)
        raise
    os.close(fd)
    if moved != target:
        os.close(moved)
        _reject(f"fixed descriptor role {target} is already occupied")
    os.set_inheritable(moved, True)
    return moved


def _open_exact_source(path: Path, expected_type: int, target: int) -> AuthorizedSource:
    source = secure_open_source(path, expected_type=expected_type)
    moved = _move_exact_fd(source.fd, target)
    return AuthorizedSource(source.locator, moved, source.identity)


def _read_line(fd: int, *, budget: float, maximum: int) -> bytes:
    deadline = time.monotonic() + budget
    result = bytearray()
    while time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        ready, _, _ = select.select([fd], [], [], min(0.1, remaining))
        if not ready:
            continue
        chunk = os.read(fd, 1)
        if not chunk:
            _reject("authenticated status channel closed before a complete record")
        result.extend(chunk)
        if len(result) > maximum:
            _reject("authenticated status record exceeded its bound")
        if chunk == b"\n":
            return bytes(result)
    _reject("authenticated status record timed out")


def _require_launcher_entry_quiescent(fd: int) -> None:
    """Reject queued progress or channel closure before the setup release."""
    if type(fd) is not int or fd < 0:
        _reject("launcher status descriptor is invalid")
    poller = select.poll()
    poller.register(
        fd,
        select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL,
    )
    if poller.poll(0):
        _reject("launcher status is queued or closed before setup release")


def _read_to_eof(fd: int, *, budget: float, maximum: int) -> bytes:
    deadline = time.monotonic() + budget
    result = bytearray()
    while time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        ready, _, _ = select.select([fd], [], [], min(0.1, remaining))
        if not ready:
            continue
        chunk = os.read(fd, min(4096, maximum + 1 - len(result)))
        if not chunk:
            return bytes(result)
        result.extend(chunk)
        if len(result) > maximum:
            _reject("authenticated status stream exceeded its bound")
    _reject("authenticated status stream did not close before deadline")


def _read_ready_packet(fd: int, *, budget: float) -> bytes:
    deadline = time.monotonic() + budget
    channel = socket.socket(fileno=os.dup(fd))
    try:
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            ready, _, _ = select.select(
                [channel], [], [], min(0.1, remaining)
            )
            if not ready:
                continue
            payload, ancillary, flags, _address = channel.recvmsg(
                MAX_READY_BYTES,
                socket.CMSG_SPACE(array.array("i").itemsize * 8),
                socket.MSG_CMSG_CLOEXEC,
            )
            _close_received_rights(ancillary)
            if not payload:
                _reject("broker readiness channel closed before readiness")
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                _reject(
                    "broker readiness record exceeded its bound or ancillary data was truncated"
                )
            allowed_record_flags = socket.MSG_CMSG_CLOEXEC | socket.MSG_EOR
            if flags & ~allowed_record_flags:
                _reject("broker readiness record carried unexpected flags")
            if ancillary:
                _reject("broker readiness carried unauthorized ancillary data")
            _require_exact_ready_eof(channel, deadline=deadline)
            return payload
        _reject("broker readiness record timed out")
    finally:
        channel.close()


def _set_passcred(channel: socket.socket, value: int) -> None:
    channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, value)
    if channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != value:
        _reject("readiness SO_PASSCRED state could not be established")


def _require_exact_ready_eof(
    channel: socket.socket, *, deadline: float
) -> None:
    poller = select.poll()
    poller.register(
        channel.fileno(),
        select.POLLIN
        | select.POLLHUP
        | _POLL_READ_CLOSED
        | select.POLLERR
        | select.POLLNVAL,
    )
    width = array.array("i").itemsize
    ancillary_size = socket.CMSG_SPACE(width * 8) + socket.CMSG_SPACE(width * 3)
    previous_passcred = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED)
    changed = False
    try:
        changed = True
        _set_passcred(channel, 1)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _reject("broker readiness channel did not close after one record")
            events = poller.poll(max(1, int(remaining * 1000)))
            if not events:
                _reject("broker readiness channel did not close after one record")
            event_mask = 0
            for _fd, observed_mask in events:
                event_mask |= observed_mask
            if event_mask & (select.POLLERR | select.POLLNVAL):
                _reject("broker readiness channel reported a poll error")
            try:
                trailing, ancillary, flags, _address = channel.recvmsg(
                    MAX_READY_BYTES,
                    ancillary_size,
                    socket.MSG_CMSG_CLOEXEC | socket.MSG_DONTWAIT,
                )
            except BlockingIOError:
                continue
            _close_received_rights(ancillary)
            terminal = bool(event_mask & (_POLL_READ_CLOSED | select.POLLHUP))
            unexpected_flags = flags & ~socket.MSG_CMSG_CLOEXEC
            if trailing or ancillary or unexpected_flags or not terminal:
                _reject(
                    "broker readiness contained a duplicate, extra, or zero record before EOF"
                )
            return
    finally:
        if changed:
            restore_error: Optional[BaseException] = None
            try:
                _set_passcred(channel, previous_passcred)
            except BaseException as exc:
                restore_error = exc
            if restore_error is not None and sys.exception() is None:
                raise CapabilityTransportError(
                    "readiness SO_PASSCRED state could not be restored"
                ) from restore_error


def _close_received_rights(
    ancillary: list[tuple[int, int, bytes]],
) -> None:
    width = array.array("i").itemsize
    for level, kind, payload in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            continue
        received = array.array("i")
        received.frombytes(payload[: len(payload) - (len(payload) % width)])
        for received_fd in received:
            try:
                os.close(received_fd)
            except OSError:
                pass


def _revoke_broker_control(fd: int, *, budget: float) -> None:
    deadline = time.monotonic() + budget
    channel = socket.socket(fileno=os.dup(fd))
    try:
        channel.setblocking(False)
        while time.monotonic() < deadline:
            _readable, writable, _exceptional = select.select(
                [], [channel], [], min(0.1, max(0.0, deadline - time.monotonic()))
            )
            if not writable:
                continue
            try:
                sent = channel.send(CONTROL_REVOKE, socket.MSG_NOSIGNAL)
            except BlockingIOError:
                continue
            if sent != len(CONTROL_REVOKE):
                _reject("broker control revoke write was short")
            channel.shutdown(socket.SHUT_WR)
            return
        _reject("broker control revoke timed out")
    finally:
        channel.close()


def _pump_process_output_until_exit(
    proc: subprocess.Popen,
    *,
    timeout: float,
    verify_broker: Callable[[], None] | None = None,
) -> tuple[bytes, bytes]:
    """Drain bounded output while waiting only for the worker outer process."""
    if proc.stdout is None or proc.stderr is None:
        _reject("worker output pipes are unavailable")
    if type(timeout) not in (int, float) or isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("worker output timeout must be positive")
    streams = {
        proc.stdout.fileno(): bytearray(),
        proc.stderr.fileno(): bytearray(),
    }
    active = set(streams)
    deadline = time.monotonic() + float(timeout)
    for fd in streams:
        os.set_blocking(fd, False)
    try:
        while proc.poll() is None:
            if verify_broker is not None:
                verify_broker()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(
                    proc.args,
                    timeout,
                    output=bytes(streams[proc.stdout.fileno()]),
                    stderr=bytes(streams[proc.stderr.fileno()]),
                )
            ready, _, _ = select.select(
                list(active), [], [], min(0.05, remaining)
            )
            for fd in ready:
                try:
                    chunk = os.read(fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    active.discard(fd)
                    continue
                streams[fd].extend(chunk)
                if sum(len(value) for value in streams.values()) > _MAX_CAPTURE_BYTES:
                    _reject("worker output exceeded its bounded capture")
        return (
            bytes(streams[proc.stdout.fileno()]),
            bytes(streams[proc.stderr.fileno()]),
        )
    finally:
        for fd in streams:
            try:
                os.set_blocking(fd, True)
            except OSError:
                pass


def _combine_captured_output(
    first_out: bytes,
    first_err: bytes,
    trailing_out: bytes,
    trailing_err: bytes,
) -> tuple[bytes, bytes]:
    values = (first_out, first_err, trailing_out, trailing_err)
    if any(type(value) is not bytes for value in values):
        _reject("worker output capture has the wrong exact type")
    if sum(len(value) for value in values) > _MAX_CAPTURE_BYTES:
        _reject("worker output exceeded its bounded capture")
    return first_out + trailing_out, first_err + trailing_err


def _require_process_shape(observed: _ObservedProcess, label: str) -> None:
    if type(observed) is not _ObservedProcess:
        _reject(f"{label} process observation has the wrong type")
    if (
        type(observed.pid) is not int
        or observed.pid <= 0
        or type(observed.start_time_ticks) is not int
        or observed.start_time_ticks <= 0
        or type(observed.boot_id) is not str
        or not observed.boot_id
        or type(observed.executable_identity) is not FileIdentity
        or type(observed.cgroup) is not str
        or not observed.cgroup.startswith("/")
        or type(observed.netns) is not int
        or observed.netns <= 0
    ):
        _reject(f"{label} process observation is invalid")


def _require_live_broker_identity(authority: _LiveAuthority, stage: str) -> None:
    """Re-observe the exact authenticated host broker at a release boundary."""
    expected = getattr(authority, "broker_recheck", None)
    if type(expected) is not _ObservedProcess:
        expected = getattr(authority, "broker_outer", None)
    _require_process_shape(expected, "authorized broker")
    try:
        observed = _read_observed_process(expected.pid)
    except CapabilityTransportError as exc:
        raise CapabilityTransportError(
            f"authenticated broker is not live at {stage}"
        ) from exc
    if observed != expected:
        _reject(f"authenticated broker identity changed at {stage}")


def _require_broker_gone(authority: _LiveAuthority) -> None:
    expected = getattr(authority, "broker_recheck", None)
    _require_process_shape(expected, "authorized broker")
    try:
        observed = _read_observed_process(expected.pid)
    except CapabilityTransportError:
        return
    if observed == expected:
        _reject("authenticated broker remained live after revoke channel failure")


def _require_live_containment(authority: _LiveAuthority) -> None:
    """Prove the race-free supervisor-FD contract and stable worker outer."""
    worker = authority.worker_outer
    _require_process_shape(worker, "worker outer")
    supervisor = authority.supervisor_process_identity
    if (
        type(authority.expected_supervisor_identity) is not FileIdentity
        or authority.supervisor_exec_contract_verified is not True
    ):
        _reject("authorized supervisor descriptor exec contract is missing")
    if (
        type(supervisor) is not ProcessIdentity
        or type(supervisor.pid) is not int
        or not 0 < supervisor.pid <= _MAX_PID
        or type(supervisor.start_time_ticks) is not int
        or supervisor.start_time_ticks <= 0
        or type(supervisor.boot_id) is not str
        or _BOOT_ID_RE.fullmatch(supervisor.boot_id) is None
    ):
        _reject("captured supervisor process identity is invalid")
    if (
        worker.pid != supervisor.pid
        or worker.start_time_ticks != supervisor.start_time_ticks
        or worker.boot_id != supervisor.boot_id
    ):
        _reject("worker outer is not the stable supervisor process after exec")
    if worker.executable_identity != authority.expected_bwrap_identity:
        _reject("worker outer Bubblewrap executable identity changed")
    if worker.cgroup != authority.expected_cgroup:
        _reject("worker outer is outside the exact task cgroup")
    if worker.netns != authority.host_netns:
        _reject("worker outer left the host network namespace")


def _require_exact_process_transition(inputs: _CoordinatorInputs) -> None:
    initial = inputs.supervisor_initial
    worker = inputs.worker_outer
    _require_process_shape(initial, "initial supervisor")
    _require_process_shape(worker, "worker outer")
    if initial.executable_identity != inputs.expected_supervisor_identity:
        _reject("initial supervisor executable identity changed")
    if (
        initial.pid != worker.pid
        or initial.start_time_ticks != worker.start_time_ticks
        or initial.boot_id != worker.boot_id
    ):
        _reject("worker outer is not the stable supervisor process after exec")
    if worker.executable_identity != inputs.expected_bwrap_identity:
        _reject("worker outer Bubblewrap executable identity changed")
    if (
        initial.cgroup != inputs.expected_cgroup
        or worker.cgroup != inputs.expected_cgroup
    ):
        _reject("supervisor or worker outer cgroup is not exact")
    if initial.netns != inputs.host_netns or worker.netns != inputs.host_netns:
        _reject("supervisor or worker outer left the host network namespace")


def _require_worker_namespace(inputs: _CoordinatorInputs) -> None:
    evidence = inputs.worker_namespace
    if type(evidence) is not NamespaceEvidence or evidence.verified is not True:
        _reject("worker namespace evidence is not verified")
    if (
        evidence.child.pid != evidence.status.child_pid
        or evidence.child.cgroup != inputs.expected_cgroup
        or evidence.child.identities.get("net") == inputs.host_netns
    ):
        _reject("worker namespace evidence is not the exact task boundary")


def _require_broker_outer(inputs: _CoordinatorInputs) -> None:
    broker_pid = _parse_supervisor_broker_pid(inputs.supervisor_status_stream)
    broker = inputs.broker_outer
    _require_process_shape(broker, "broker outer")
    if broker.pid != broker_pid or broker.pid == inputs.worker_outer.pid:
        _reject("supervisor broker PID does not match the observed process")
    if broker.executable_identity != inputs.expected_bwrap_identity:
        _reject("broker outer Bubblewrap executable identity changed")
    if broker.cgroup != inputs.expected_cgroup:
        _reject("broker outer is outside the exact task cgroup")
    if broker.netns != inputs.host_netns:
        _reject("broker outer is not in the host network namespace")
    if inputs.ready_before_namespace_release is not False:
        _reject("broker readiness arrived before prerequisite release")


def _parse_launcher_prefix(inputs: _CoordinatorInputs) -> dict:
    payload = inputs.launcher_entry_status
    if type(payload) is not bytes or not payload.endswith(b"\n"):
        _reject("launcher entry status is malformed")
    lines = payload.splitlines(keepends=True)
    if len(lines) != 1:
        _reject("launcher entry status is duplicate or early")
    entered = parse_launcher_status(
        payload,
        expected_nonce=inputs.launcher_network_record.launch_nonce,
        expected_network_record=inputs.launcher_network_record,
        protocol_version=3,
    )
    if (
        entered.get("failed_stage") is not None
        or entered.get("progress") != ["R"]
        or entered.get("listener_exported") is not False
    ):
        _reject("trusted launcher entry is not authenticated")
    return entered


def _parse_listener_prefix(inputs: _CoordinatorInputs) -> dict:
    parsed = parse_launcher_status(
        inputs.launcher_status_before_ready,
        expected_nonce=inputs.launcher_network_record.launch_nonce,
        expected_network_record=inputs.launcher_network_record,
        protocol_version=3,
    )
    if (
        parsed.get("failed_stage") is not None
        or parsed.get("progress") != ["R", "L"]
        or parsed.get("listener_exported") is not True
    ):
        _reject("listener export is missing, unauthenticated, or out of order")
    return parsed


def _require_active_transport_policy(inputs: _CoordinatorInputs) -> None:
    policy = inputs.transport_policy
    launch = inputs.launcher_network_record
    if type(policy) is not TransportPolicy:
        _reject("transport policy has the wrong exact type")
    if (
        policy.task_id != launch.task_id
        or policy.task_generation != launch.task_generation
        or policy.launch_nonce != launch.launch_nonce
        or policy.proxy_host != launch.proxy_host
        or policy.proxy_port != launch.proxy_port
        or policy_digest(policy) != launch.network_policy_digest
    ):
        _reject("transport policy does not match launch authority")
    if not (
        policy.activated_at_monotonic_ns
        <= inputs.observed_at_monotonic_ns
        < policy.expires_at_monotonic_ns
    ):
        if inputs.observed_at_monotonic_ns >= policy.expires_at_monotonic_ns:
            _reject("transport policy expired before authorization release")
        _reject("transport policy is not active at authorization release")


def _require_expected_broker_boundary(
    inputs: _CoordinatorInputs,
) -> _ExpectedBrokerBoundary:
    expected = inputs.expected_broker_boundary
    if type(expected) is not _ExpectedBrokerBoundary:
        _reject("expected broker boundary has the wrong exact type")
    identities = (
        expected.runtime_identity,
        expected.broker_code_identity,
        expected.identity_code_identity,
        expected.models_code_identity,
        expected.interpreter_identity,
    )
    if any(type(identity) is not ObservedFileIdentity for identity in identities):
        _reject("expected broker identity evidence has the wrong exact type")
    if (
        expected.broker_code_identity != inputs.expected_broker_code_identity
        or (
            expected.interpreter_identity.device,
            expected.interpreter_identity.inode,
            expected.interpreter_identity.file_type,
        )
        != (
            inputs.expected_broker_interpreter_identity.device,
            inputs.expected_broker_interpreter_identity.inode,
            inputs.expected_broker_interpreter_identity.file_type,
        )
    ):
        _reject("expected broker identities disagree with launch authority")
    if (
        type(expected.sealed_policy) is not SealedPolicyEvidence
        or type(expected.verified_policy) is not VerifiedSealedPolicy
        or type(expected.proc_status) is not ProcStatusEvidence
        or type(expected.environment) is not EnvironmentEvidence
    ):
        _reject("expected broker boundary evidence has the wrong exact type")
    verified = expected.verified_policy
    policy = inputs.transport_policy
    if (
        verified.policy != policy
        or verified.digest != policy_digest(policy)
        or verified.size != len(canonical_policy_bytes(policy))
        or (
            verified.device,
            verified.inode,
            verified.size,
            verified.seals,
        )
        != (
            expected.sealed_policy.device,
            expected.sealed_policy.inode,
            expected.sealed_policy.size,
            expected.sealed_policy.seals,
        )
    ):
        _reject("verified sealed policy disagrees with launch authority")
    if fcntl is None:
        _reject("sealed policy validation requires Linux fcntl")
    required_seals = (
        fcntl.F_SEAL_WRITE
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_SEAL
    )
    if verified.seals & required_seals != required_seals:
        _reject("verified transport policy is not fully sealed")
    if expected.proc_status != ProcStatusEvidence(0, 0, 0, 0, 0, 1):
        _reject("expected broker process status is not least privilege")
    expected_fds = (
        0,
        1,
        2,
        BROKER_POLICY_FD,
        BROKER_HANDOFF_FD,
        BROKER_STATUS_FD,
        BROKER_CONTROL_FD,
    )
    if policy.mode is TransportMode.SYNTHETIC_FIXTURE_FD:
        expected_fds = (*expected_fds, BROKER_FIXTURE_FD)
    if expected.fd_numbers != expected_fds:
        _reject("expected broker descriptor set is not the exact contract")
    if expected.environment != validate_broker_environment(dict(BROKER_ENVIRONMENT)):
        _reject("expected broker environment is not the exact fixed mapping")
    filesystem_digest = _expected_broker_filesystem_digest(
        runtime_identity=expected.runtime_identity,
        broker_code_identity=expected.broker_code_identity,
        identity_code_identity=expected.identity_code_identity,
        models_code_identity=expected.models_code_identity,
    )
    if expected.filesystem_digest != filesystem_digest:
        _reject("expected broker filesystem digest is inconsistent")
    return expected


def _require_ready(
    inputs: _CoordinatorInputs,
    listener_outcome: dict,
) -> NetworkBrokerReadyRecord:
    payloads = inputs.broker_ready_payloads
    if (
        type(payloads) is not tuple
        or len(payloads) != 1
        or type(payloads[0]) is not bytes
        or not 0 < len(payloads[0]) <= MAX_READY_BYTES
    ):
        _reject("broker readiness record is missing, duplicate, or oversized")
    try:
        record = NetworkBrokerReadyRecord.from_bytes(payloads[0])
    except BaseException as exc:
        raise CapabilityTransportError("broker readiness record is invalid") from exc
    expected_boundary = _require_expected_broker_boundary(inputs)
    launch = inputs.launcher_network_record
    if (
        record.ready.task_id != launch.task_id
        or record.ready.task_generation != launch.task_generation
        or record.ready.launch_nonce != launch.launch_nonce
        or record.ready.policy_digest != launch.network_policy_digest
    ):
        _reject("broker readiness task capability does not match launch authority")
    if record.listener != listener_outcome.get("listener_evidence"):
        _reject("broker and launcher listener evidence do not match")
    if (
        record.runtime_identity != expected_boundary.runtime_identity
        or record.broker_code_identity != expected_boundary.broker_code_identity
        or record.identity_code_identity != expected_boundary.identity_code_identity
        or record.models_code_identity != expected_boundary.models_code_identity
        or record.interpreter_identity != expected_boundary.interpreter_identity
    ):
        _reject("broker source identity does not match launch authority")
    if record.sealed_policy != expected_boundary.sealed_policy:
        _reject("broker sealed policy evidence does not match launch authority")
    if (
        record.boundary.proc_status != expected_boundary.proc_status
        or record.boundary.fd_numbers != expected_boundary.fd_numbers
        or record.boundary.environment != expected_boundary.environment
        or record.boundary.filesystem_digest
        != expected_boundary.filesystem_digest
    ):
        _reject("broker readiness boundary does not match launch authority")
    expected_interpreter = inputs.expected_broker_interpreter_identity
    if type(inputs.broker_setup) is not BrokerBwrapSetupStatus:
        _reject("broker Bubblewrap setup evidence has the wrong type")
    ready_namespaces = dict(record.boundary.namespaces)
    if (
        record.boundary.cgroup != inputs.expected_cgroup
        or ready_namespaces.get("net") != inputs.host_netns
        or inputs.worker_namespace.child.identities.get("net")
        == ready_namespaces.get("net")
    ):
        _reject("broker readiness namespace or cgroup evidence is wrong")
    for name, inode in inputs.broker_setup.reported_namespaces:
        if ready_namespaces.get(name) != inode:
            _reject("broker Bubblewrap and readiness namespaces disagree")

    recheck = inputs.broker_recheck
    _require_process_shape(recheck, "broker readiness recheck")
    if (
        recheck.start_time_ticks != record.process.start_time_ticks
        or recheck.boot_id != record.process.boot_id
        or recheck.cgroup != inputs.expected_cgroup
        or recheck.netns != inputs.host_netns
        or recheck.executable_identity != expected_interpreter
    ):
        _reject("broker process identity or boundary changed before close gate")
    if inputs.readiness_preserved is not True:
        _reject("broker readiness was lost before network close")
    return record


def _parse_post_close_launcher(inputs: _CoordinatorInputs) -> dict:
    parsed = parse_launcher_status(
        inputs.launcher_status_after_close,
        expected_nonce=inputs.launcher_network_record.launch_nonce,
        expected_policy_digest=inputs.expected_filesystem_policy_digest,
        expected_network_record=inputs.launcher_network_record,
        protocol_version=3,
    )
    if (
        parsed.get("failed_stage") is not None
        or parsed.get("progress") != ["R", "L", "S", "I", "P", "N", "A"]
        or parsed.get("listener_exported") is not True
        or parsed.get("identity_verified") is not True
        or parsed.get("policy_applied") is not True
    ):
        _reject("post-close launcher evidence is incomplete or unauthenticated")
    return parsed


def _coordinate_capability_transport(
    inputs: _CoordinatorInputs,
    *,
    transition: Callable[[str], None],
    controller_write: Callable[[str, bytes], None],
) -> _CoordinatorResult:
    """Exercise the fixed coordinator against already captured test evidence."""
    if type(inputs) is not _CoordinatorInputs:
        _reject("coordinator inputs have the wrong exact type")
    if not callable(transition) or not callable(controller_write):
        _reject("coordinator operations must be callable")
    if (
        type(inputs.expected_cgroup) is not str
        or not inputs.expected_cgroup.startswith("/")
        or type(inputs.host_netns) is not int
        or inputs.host_netns <= 0
        or type(inputs.expected_bwrap_identity) is not FileIdentity
        or type(inputs.expected_supervisor_identity) is not FileIdentity
        or type(inputs.expected_broker_code_identity) is not ObservedFileIdentity
        or type(inputs.expected_broker_interpreter_identity) is not FileIdentity
        or type(inputs.expected_broker_boundary) is not _ExpectedBrokerBoundary
        or type(inputs.observed_at_monotonic_ns) is not int
        or inputs.observed_at_monotonic_ns <= 0
    ):
        _reject("coordinator authority is invalid")

    def authenticate_readiness(listener_outcome: dict) -> NetworkBrokerReadyRecord:
        _require_active_transport_policy(inputs)
        return _require_ready(inputs, listener_outcome)

    return _coordinate_operations(
        _CoordinatorOperations(
            verify_containment=lambda: _require_exact_process_transition(inputs),
            verify_worker_namespace=lambda: _require_worker_namespace(inputs),
            verify_broker_process=lambda: _require_broker_outer(inputs),
            authenticate_launcher_entry=lambda: _parse_launcher_prefix(inputs),
            authenticate_listener=lambda: _parse_listener_prefix(inputs),
            authenticate_readiness=authenticate_readiness,
            authenticate_post_close=lambda: _parse_post_close_launcher(inputs),
            verify_worker_marker_absent=lambda: inputs.worker_marker_absent is True,
            transition=transition,
            controller_write=controller_write,
        )
    )


def _coordinate_operations(
    operations: _CoordinatorOperations,
) -> _CoordinatorResult:
    """Run the only release order, observing each prerequisite just in time."""
    if type(operations) is not _CoordinatorOperations:
        _reject("coordinator operations have the wrong exact type")
    for operation in (
        operations.verify_containment,
        operations.verify_worker_namespace,
        operations.verify_broker_process,
        operations.authenticate_launcher_entry,
        operations.authenticate_listener,
        operations.authenticate_readiness,
        operations.authenticate_post_close,
        operations.verify_worker_marker_absent,
        operations.transition,
        operations.controller_write,
    ):
        if not callable(operation):
            _reject("coordinator operation is not callable")

    operations.verify_containment()
    operations.transition(EV_CONTAINMENT_VERIFIED)
    operations.verify_worker_namespace()
    operations.transition(EV_NAMESPACE_VERIFIED)
    operations.verify_broker_process()
    operations.transition(EV_BROKER_PROCESS_VERIFIED)
    operations.controller_write("namespace_gate", b"G")

    operations.authenticate_launcher_entry()
    operations.transition(EV_LAUNCHER_ENTERED)
    operations.controller_write("launcher_setup_gate", b"G")
    listener_outcome = operations.authenticate_listener()
    operations.transition(EV_LISTENER_EXPORTED)

    ready = operations.authenticate_readiness(listener_outcome)
    operations.transition(EV_BROKER_READY)
    operations.controller_write("network_close_gate", b"C")

    outcome = operations.authenticate_post_close()
    operations.transition(EV_FD_SANITIZED)
    operations.transition(EV_IDENTITIES_VERIFIED)
    operations.transition(EV_POLICY_PREPARED)
    operations.transition(EV_NO_NEW_PRIVS)
    operations.transition(EV_POLICY_APPLIED)
    if operations.verify_worker_marker_absent() is not True:
        _reject("worker executed before authenticated final release")
    operations.controller_write("final_exec_gate", b"X")
    operations.transition(EV_WORKER_EXEC_ATTEMPTED)
    return _CoordinatorResult(ready=ready, launcher_outcome=outcome)


__all__ = ["CapabilityTransportError", "CapabilityTransportRunner"]
