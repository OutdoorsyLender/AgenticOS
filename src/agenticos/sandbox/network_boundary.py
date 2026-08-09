"""Deterministic least-authority Bubblewrap plan for the M4B-1 broker."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import json
from pathlib import Path
import os
import select
import stat
import time
from typing import Any

from .network_broker import (
    BROKER_CODE_PATH,
    BROKER_CONTRACT_VERSION,
    BROKER_CONTROL_FD,
    BROKER_ENVIRONMENT,
    BROKER_FIXTURE_FD,
    BROKER_HANDOFF_FD,
    BROKER_POLICY_FD,
    BROKER_ROOT,
    BROKER_STATUS_FD,
    IDENTITY_CODE_PATH,
    INTERPRETER_PATH,
    MODELS_CODE_PATH,
    RUNTIME_PATH,
    BrokerContract,
    ObservedFileIdentity,
)
from .network_models import TransportMode, TransportPolicy, policy_digest
from .runtime_boundary import AuthorizedSource, FileIdentity


SUPERVISOR_CONTRACT_VERSION = "AOSSUP/1"
SUPERVISOR_BWRAP_FD = 5
SUPERVISOR_STATUS_FD = 6
SUPERVISOR_EXECUTABLE_FD = 7
BROKER_JSON_STATUS_FD = 8
BROKER_RUNTIME_USR_FD = 20
BROKER_CODE_FD = 21
BROKER_IDENTITY_CODE_FD = 22
BROKER_MODELS_CODE_FD = 23

MAX_SUPERVISOR_ARGV_ITEMS = 128
MAX_SUPERVISOR_ITEM_BYTES = 4096
MAX_SUPERVISOR_PASS_FDS = 128
MAX_SUPERVISOR_FD = (1 << 31) - 1

BROKER_REQUIRED_PASS_FDS = (
    BROKER_JSON_STATUS_FD,
    BROKER_RUNTIME_USR_FD,
    BROKER_CODE_FD,
    BROKER_IDENTITY_CODE_FD,
    BROKER_MODELS_CODE_FD,
    BROKER_POLICY_FD,
    BROKER_HANDOFF_FD,
    BROKER_STATUS_FD,
    BROKER_CONTROL_FD,
)

BROKER_STDLIB_PATHS = (
    "/usr/lib/python3.14",
    "/usr/lib/python3.14/lib-dynload",
)
BROKER_BOOTSTRAP = (
    "import sys,types,importlib.util,importlib.machinery;"
    "sys.dont_write_bytecode=True;"
    "sys.path[:]=["
    "'/usr/lib/python3.14',"
    "'/usr/lib/python3.14/lib-dynload'"
    "];"
    "_a=types.ModuleType('agenticos');"
    "_a.__path__=['/opt/agenticos/python/agenticos'];"
    "_a.__package__='agenticos';"
    "_a.__spec__=importlib.machinery.ModuleSpec('agenticos',None,is_package=True);"
    "_a.__spec__.submodule_search_locations=_a.__path__;"
    "sys.modules['agenticos']=_a;"
    "_s=types.ModuleType('agenticos.sandbox');"
    "_s.__path__=['/opt/agenticos/python/agenticos/sandbox'];"
    "_s.__package__='agenticos.sandbox';"
    "_s.__spec__=importlib.machinery.ModuleSpec('agenticos.sandbox',None,is_package=True);"
    "_s.__spec__.submodule_search_locations=_s.__path__;"
    "sys.modules['agenticos.sandbox']=_s;"
    "_p='/opt/agenticos/python/agenticos/sandbox/network_models.py';"
    "_q=importlib.util.spec_from_file_location('agenticos.sandbox.network_models',_p);"
    "_m=importlib.util.module_from_spec(_q);"
    "sys.modules[_q.name]=_m;"
    "_q.loader.exec_module(_m);"
    "_p='/opt/agenticos/python/agenticos/sandbox/network_identity.py';"
    "_q=importlib.util.spec_from_file_location('agenticos.sandbox.network_identity',_p);"
    "_i=importlib.util.module_from_spec(_q);"
    "sys.modules[_q.name]=_i;"
    "_q.loader.exec_module(_i);"
    "_p='/opt/agenticos/python/agenticos/sandbox/network_broker.py';"
    "_q=importlib.util.spec_from_file_location('agenticos.sandbox.network_broker',_p);"
    "_b=importlib.util.module_from_spec(_q);"
    "sys.modules[_q.name]=_b;"
    "_q.loader.exec_module(_b);"
    "raise SystemExit(_b.main())"
)

BROKER_NAMESPACE_FLAGS = (
    "--unshare-user",
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts",
    "--disable-userns",
    "--new-session",
    "--die-with-parent",
)

BROKER_SYNTHETIC_DIRECTORIES = (
    "/opt",
    "/opt/agenticos",
    BROKER_ROOT,
    f"{BROKER_ROOT}/agenticos",
    f"{BROKER_ROOT}/agenticos/sandbox",
    "/home",
    "/home/broker",
    "/run",
    "/tmp",
)

BROKER_SYMLINKS = (
    ("usr/bin", "/bin"),
    ("usr/sbin", "/sbin"),
    ("usr/lib", "/lib"),
    ("usr/lib64", "/lib64"),
)

BROKER_REPORTED_NAMESPACE_KEYS = {
    "ipc": "ipc-namespace",
    "mnt": "mnt-namespace",
    "pid": "pid-namespace",
    "uts": "uts-namespace",
}


class NetworkBoundaryError(RuntimeError):
    """A fixed broker boundary or status record failed validation."""


@dataclass(frozen=True)
class BrokerBwrapSetupStatus:
    child_pid: int
    reported_namespaces: tuple[tuple[str, int], ...]

    def __post_init__(self) -> None:
        if type(self.child_pid) is not int or self.child_pid <= 0:
            raise NetworkBoundaryError("broker Bubblewrap child PID is invalid")
        if (
            type(self.reported_namespaces) is not tuple
            or tuple(name for name, _inode in self.reported_namespaces)
            != tuple(BROKER_REPORTED_NAMESPACE_KEYS)
        ):
            raise NetworkBoundaryError(
                "broker Bubblewrap namespace evidence is incomplete"
            )
        for name, inode in self.reported_namespaces:
            if type(name) is not str or type(inode) is not int or inode <= 0:
                raise NetworkBoundaryError(
                    "broker Bubblewrap namespace evidence is invalid"
                )


class BrokerMountRole(str, Enum):
    RUNTIME = "runtime"
    BROKER_CODE = "broker_code"
    IDENTITY_CODE = "identity_code"
    MODELS_CODE = "models_code"


@dataclass(frozen=True)
class SupervisorSource:
    source: AuthorizedSource
    role: str = "supervisor"

    def __post_init__(self) -> None:
        if type(self.source) is not AuthorizedSource:
            raise TypeError("supervisor source must be exact AuthorizedSource")
        if self.role != "supervisor":
            raise ValueError("supervisor source role is not fixed")


@dataclass(frozen=True)
class BrokerMount:
    source: AuthorizedSource
    destination: str
    role: BrokerMountRole
    bind_option: str = "--ro-bind-fd"

    def __post_init__(self) -> None:
        if type(self.source) is not AuthorizedSource:
            raise TypeError("broker mount source must be exact AuthorizedSource")
        if type(self.destination) is not str or not self.destination.startswith("/"):
            raise ValueError("broker mount destination must be absolute")
        if type(self.role) is not BrokerMountRole:
            raise TypeError("broker mount role must be exact BrokerMountRole")
        if self.bind_option != "--ro-bind-fd":
            raise ValueError("broker mounts must be read-only descriptor binds")


def _validate_exec_vector(name: str, values: Sequence[str]) -> tuple[str, ...]:
    if type(values) not in (tuple, list):
        raise ValueError(f"{name} argv must be an exact sequence")
    result = tuple(values)
    if (
        not 1 <= len(result) <= MAX_SUPERVISOR_ARGV_ITEMS
        or result[0] != "bwrap"
        or any(
            type(item) is not str
            or not 0 < len(item.encode("utf-8")) <= MAX_SUPERVISOR_ITEM_BYTES
            or "\x00" in item
            or "\n" in item
            or "\r" in item
            for item in result
        )
    ):
        raise ValueError(f"{name} argv must be a bounded bwrap vector")
    return result


def _validate_pass_fds(
    name: str,
    values: Sequence[int],
    *,
    allow_empty: bool,
) -> tuple[int, ...]:
    if type(values) not in (tuple, list):
        raise ValueError(f"{name} pass FDs must be an exact sequence")
    result = tuple(values)
    if (
        (not allow_empty and not result)
        or len(result) > MAX_SUPERVISOR_PASS_FDS
        or any(
            type(fd) is not int
            or not SUPERVISOR_EXECUTABLE_FD < fd <= MAX_SUPERVISOR_FD
            for fd in result
        )
        or tuple(sorted(result)) != result
        or len(set(result)) != len(result)
    ):
        raise ValueError(
            f"{name} pass FDs must be bounded sorted unique descriptors"
        )
    return result


@dataclass(frozen=True)
class SupervisorContract:
    version: str
    bwrap_fd: int
    status_fd: int
    broker_pass_fds: tuple[int, ...]
    broker_argv: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.version != SUPERVISOR_CONTRACT_VERSION:
            raise ValueError(
                f"supervisor version must be {SUPERVISOR_CONTRACT_VERSION}"
            )
        if type(self.bwrap_fd) is not int or self.bwrap_fd != SUPERVISOR_BWRAP_FD:
            raise ValueError(
                f"supervisor bwrap fd must be {SUPERVISOR_BWRAP_FD}"
            )
        if type(self.status_fd) is not int or self.status_fd != SUPERVISOR_STATUS_FD:
            raise ValueError(
                f"supervisor status fd must be {SUPERVISOR_STATUS_FD}"
            )
        if self.bwrap_fd == self.status_fd:
            raise ValueError("supervisor descriptor roles collide")
        broker_pass = _validate_pass_fds(
            "broker", self.broker_pass_fds, allow_empty=False
        )
        if broker_pass not in (
            BROKER_REQUIRED_PASS_FDS,
            (*BROKER_REQUIRED_PASS_FDS, BROKER_FIXTURE_FD),
        ):
            raise ValueError("broker pass FDs are not the exact fixed role set")
        object.__setattr__(self, "broker_pass_fds", broker_pass)
        object.__setattr__(
            self,
            "broker_argv",
            _validate_exec_vector("broker", self.broker_argv),
        )

    def with_broker_argv(
        self, broker_argv: Sequence[str]
    ) -> SupervisorContract:
        return replace(
            self,
            broker_argv=_validate_exec_vector("broker", broker_argv),
        )

    def argument_tokens_for(
        self,
        worker_argv: Sequence[str],
        *,
        worker_pass_fds: Sequence[int] = (),
    ) -> tuple[str, ...]:
        worker = _validate_exec_vector("worker", worker_argv)
        worker_pass = _validate_pass_fds(
            "worker", worker_pass_fds, allow_empty=True
        )
        if set(worker_pass).intersection(self.broker_pass_fds):
            raise ValueError("broker and worker pass FD roles overlap")
        return (
            self.version,
            "bwrap_fd",
            str(self.bwrap_fd),
            "status_fd",
            str(self.status_fd),
            "broker_passc",
            str(len(self.broker_pass_fds)),
            "broker_pass",
            *(str(fd) for fd in self.broker_pass_fds),
            "worker_passc",
            str(len(worker_pass)),
            "worker_pass",
            *(str(fd) for fd in worker_pass),
            "broker_argc",
            str(len(self.broker_argv)),
            "broker",
            *self.broker_argv,
            "worker_argc",
            str(len(worker)),
            "worker",
            *worker,
            "END",
        )

    def argv_for(
        self,
        worker_argv: Sequence[str],
        *,
        worker_pass_fds: Sequence[int] = (),
    ) -> tuple[str, ...]:
        return (
            "task_supervisor",
            *self.argument_tokens_for(
                worker_argv,
                worker_pass_fds=worker_pass_fds,
            ),
        )


@dataclass(frozen=True)
class NetworkBoundaryPlan:
    transport_policy: TransportPolicy
    mounts: tuple[BrokerMount, ...]
    synthetic_directories: tuple[str, ...]
    symlinks: tuple[tuple[str, str], ...]
    broker_environment: tuple[tuple[str, str], ...]
    broker_contract: BrokerContract
    broker_json_status_fd: int
    broker_bwrap_argv: tuple[str, ...]
    supervisor_contract: SupervisorContract
    supervisor_source: SupervisorSource
    transport_policy_digest: str
    canonical_boundary_policy: bytes
    boundary_policy_digest: str

    def __post_init__(self) -> None:
        if type(self.transport_policy) is not TransportPolicy:
            raise TypeError("transport policy must be exact TransportPolicy")
        if type(self.mounts) is not tuple or any(
            type(mount) is not BrokerMount for mount in self.mounts
        ):
            raise TypeError("broker mounts must be an explicit frozen tuple")
        destinations = tuple(mount.destination for mount in self.mounts)
        if len(destinations) != len(set(destinations)):
            raise ValueError("broker plan has a duplicate destination")
        if self.broker_environment != BROKER_ENVIRONMENT:
            raise ValueError("broker plan environment is not exact")
        if type(self.broker_contract) is not BrokerContract:
            raise TypeError("broker contract has the wrong type")
        if self.broker_json_status_fd != BROKER_JSON_STATUS_FD:
            raise ValueError("broker JSON status descriptor is not fixed")
        if type(self.supervisor_contract) is not SupervisorContract:
            raise TypeError("supervisor contract has the wrong type")
        if type(self.supervisor_source) is not SupervisorSource:
            raise TypeError("supervisor source has the wrong type")
        if self.supervisor_contract.broker_argv != self.broker_bwrap_argv:
            raise ValueError("supervisor broker argv does not match boundary plan")
        if (
            type(self.canonical_boundary_policy) is not bytes
            or hashlib.sha256(self.canonical_boundary_policy).hexdigest()
            != self.boundary_policy_digest
        ):
            raise ValueError("broker boundary digest does not match canonical policy")


def _require_source(
    name: str,
    source: AuthorizedSource,
    *,
    fixed_fd: int,
    expected_type: int,
) -> None:
    if type(source) is not AuthorizedSource:
        raise TypeError(f"{name} must be exact AuthorizedSource")
    if not isinstance(source.locator, Path) or not source.locator.is_absolute():
        raise ValueError(f"{name} locator must be absolute")
    locator_text = str(source.locator)
    if "\x00" in locator_text or "\n" in locator_text or "\r" in locator_text:
        raise ValueError(f"{name} locator is malformed")
    if type(source.fd) is not int or source.fd != fixed_fd:
        raise ValueError(f"{name} must use fixed descriptor {fixed_fd}")
    if type(source.identity) is not FileIdentity:
        raise TypeError(f"{name} identity must be exact FileIdentity")
    for field_name in ("device", "inode", "file_type"):
        value = getattr(source.identity, field_name)
        if type(value) is not int or value <= 0:
            raise ValueError(
                f"{name} identity {field_name} must be a positive integer"
            )
    if source.identity.file_type != expected_type:
        label = "directory" if expected_type == stat.S_IFDIR else "regular file"
        raise ValueError(f"{name} must authorize a {label}")


def _observed(identity: FileIdentity) -> ObservedFileIdentity:
    return ObservedFileIdentity(
        device=identity.device,
        inode=identity.inode,
        file_type=identity.file_type,
    )


def _build_bwrap_argv(
    mounts: tuple[BrokerMount, ...],
    contract: BrokerContract,
) -> tuple[str, ...]:
    argv: list[str] = ["bwrap", *BROKER_NAMESPACE_FLAGS, "--clearenv"]
    argv.extend(("--cap-drop", "ALL", "--tmpfs", "/"))
    for directory in BROKER_SYNTHETIC_DIRECTORIES:
        argv.extend(("--dir", directory))
    argv.extend(("--dir", "/usr", "--dev", "/dev"))
    for mount in mounts:
        argv.extend(
            (
                mount.bind_option,
                str(mount.source.fd),
                mount.destination,
            )
        )
    for target, destination in BROKER_SYMLINKS:
        argv.extend(("--symlink", target, destination))
    argv.extend(
        (
            "--proc",
            "/proc",
            "--chdir",
            BROKER_ROOT,
            "--json-status-fd",
            str(BROKER_JSON_STATUS_FD),
        )
    )
    for name, value in BROKER_ENVIRONMENT:
        argv.extend(("--setenv", name, value))
    argv.extend(
        (
            "--",
            INTERPRETER_PATH,
            "-I",
            "-S",
            "-B",
            "-c",
            BROKER_BOOTSTRAP,
            *contract.to_argv(),
        )
    )
    return tuple(argv)


def _canonical_boundary_bytes(
    *,
    policy: TransportPolicy,
    mounts: tuple[BrokerMount, ...],
    supervisor: AuthorizedSource,
    supervisor_contract: SupervisorContract,
    contract: BrokerContract,
    bwrap_argv: tuple[str, ...],
) -> bytes:
    payload = {
        "broker": {
            "argv": list(bwrap_argv),
            "environment": [
                {"name": name, "value": value}
                for name, value in BROKER_ENVIRONMENT
            ],
            "mounts": [
                {
                    "bind": mount.bind_option,
                    "destination": mount.destination,
                    "identity": {
                        "device": mount.source.identity.device,
                        "file_type": mount.source.identity.file_type,
                        "inode": mount.source.identity.inode,
                    },
                    "role": mount.role.value,
                }
                for mount in mounts
            ],
            "namespace_flags": list(BROKER_NAMESPACE_FLAGS),
            "synthetic_directories": list(BROKER_SYNTHETIC_DIRECTORIES),
            "symlinks": [
                {"destination": destination, "target": target}
                for target, destination in BROKER_SYMLINKS
            ],
        },
        "contract": list(contract.to_argv()),
        "supervisor": {
            "bwrap_fd": SUPERVISOR_BWRAP_FD,
            "broker_pass_fds": list(supervisor_contract.broker_pass_fds),
            "identity": {
                "device": supervisor.identity.device,
                "file_type": supervisor.identity.file_type,
                "inode": supervisor.identity.inode,
            },
            "status_fd": SUPERVISOR_STATUS_FD,
            "version": SUPERVISOR_CONTRACT_VERSION,
        },
        "transport_policy_digest": policy_digest(policy),
        "version": "AOSNETBOUNDARY/1",
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )


def _positive_status_integer(document: dict[str, Any], key: str) -> int:
    value = document.get(key)
    if type(value) is not int or value <= 0:
        raise NetworkBoundaryError(
            f"broker Bubblewrap status field {key!r} must be positive"
        )
    return value


def parse_broker_bwrap_documents(
    documents: Sequence[object],
) -> BrokerBwrapSetupStatus:
    """Parse the host-network broker setup record without inventing net evidence."""
    if type(documents) not in (tuple, list):
        raise NetworkBoundaryError(
            "broker Bubblewrap documents must be an exact sequence"
        )
    setup: BrokerBwrapSetupStatus | None = None
    setup_keys = {
        "child-pid",
        "net-namespace",
        *BROKER_REPORTED_NAMESPACE_KEYS.values(),
    }
    for document in documents:
        if type(document) is not dict:
            raise NetworkBoundaryError(
                "broker Bubblewrap status object must be a mapping"
            )
        if not setup_keys.intersection(document):
            continue
        if "net-namespace" in document:
            raise NetworkBoundaryError(
                "broker Bubblewrap unexpectedly unshared the network namespace"
            )
        candidate = BrokerBwrapSetupStatus(
            child_pid=_positive_status_integer(document, "child-pid"),
            reported_namespaces=tuple(
                (name, _positive_status_integer(document, key))
                for name, key in BROKER_REPORTED_NAMESPACE_KEYS.items()
            ),
        )
        if setup is not None:
            raise NetworkBoundaryError(
                "broker Bubblewrap setup record is duplicate or contradictory"
            )
        setup = candidate
    if setup is None:
        raise NetworkBoundaryError("broker Bubblewrap setup record is missing")
    return setup


def _reject_status_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NetworkBoundaryError(
                f"duplicate broker Bubblewrap JSON field: {key}"
            )
        result[key] = value
    return result


def _reject_status_constant(value: str) -> Any:
    raise NetworkBoundaryError(
        f"non-finite broker Bubblewrap value: {value}"
    )


def read_broker_bwrap_setup_status(
    fd: int,
    *,
    timeout: float,
    max_line_bytes: int = 4096,
    max_total_bytes: int = 16384,
    max_objects: int = 16,
) -> BrokerBwrapSetupStatus:
    """Read a bounded broker Bubblewrap JSON stream through its fixed pipe."""
    if type(fd) is not int or fd < 0:
        raise NetworkBoundaryError("broker Bubblewrap status fd is invalid")
    if type(timeout) not in (int, float) or isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("broker Bubblewrap status timeout must be positive")
    deadline = time.monotonic() + float(timeout)
    settle_deadline: float | None = None
    line = bytearray()
    total = 0
    documents: list[object] = []
    setup_keys = {
        "child-pid",
        "net-namespace",
        *BROKER_REPORTED_NAMESPACE_KEYS.values(),
    }
    while time.monotonic() < deadline:
        now = time.monotonic()
        if settle_deadline is not None and now >= settle_deadline:
            return parse_broker_bwrap_documents(documents)
        wait_until = deadline if settle_deadline is None else min(
            deadline, settle_deadline
        )
        ready, _, _ = select.select([fd], [], [], min(0.1, wait_until - now))
        if not ready:
            continue
        try:
            chunk = os.read(fd, 1)
        except OSError as exc:
            raise NetworkBoundaryError(
                "broker Bubblewrap status read failed"
            ) from exc
        if not chunk:
            break
        total += 1
        if total > max_total_bytes:
            raise NetworkBoundaryError(
                "broker Bubblewrap status exceeded bounded total"
            )
        if chunk != b"\n":
            line.extend(chunk)
            if len(line) > max_line_bytes:
                raise NetworkBoundaryError(
                    "broker Bubblewrap status exceeded bounded line"
                )
            continue
        if not line:
            raise NetworkBoundaryError(
                "broker Bubblewrap emitted an empty JSON record"
            )
        try:
            document = json.loads(
                line.decode("ascii"),
                object_pairs_hook=_reject_status_pairs,
                parse_constant=_reject_status_constant,
            )
        except NetworkBoundaryError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise NetworkBoundaryError(
                "broker Bubblewrap emitted malformed JSON"
            ) from exc
        line.clear()
        documents.append(document)
        if len(documents) > max_objects:
            raise NetworkBoundaryError(
                "broker Bubblewrap status exceeded bounded objects"
            )
        if type(document) is dict and setup_keys.intersection(document):
            settle_deadline = time.monotonic() + min(0.05, float(timeout))
    if line:
        raise NetworkBoundaryError(
            "broker Bubblewrap status ended with truncated JSON"
        )
    if documents:
        return parse_broker_bwrap_documents(documents)
    raise NetworkBoundaryError(
        "broker Bubblewrap setup status missing before deadline"
    )


def build_network_boundary_plan(
    *,
    transport_policy: TransportPolicy,
    runtime_usr: AuthorizedSource,
    broker_code: AuthorizedSource,
    identity_code: AuthorizedSource,
    models_code: AuthorizedSource,
    supervisor: AuthorizedSource,
) -> NetworkBoundaryPlan:
    """Build the only supported M4B-1 broker mount/argv/FD policy."""
    if type(transport_policy) is not TransportPolicy:
        raise TypeError("transport_policy must be exact TransportPolicy")
    _require_source(
        "runtime_usr",
        runtime_usr,
        fixed_fd=BROKER_RUNTIME_USR_FD,
        expected_type=stat.S_IFDIR,
    )
    _require_source(
        "broker_code",
        broker_code,
        fixed_fd=BROKER_CODE_FD,
        expected_type=stat.S_IFREG,
    )
    _require_source(
        "identity_code",
        identity_code,
        fixed_fd=BROKER_IDENTITY_CODE_FD,
        expected_type=stat.S_IFREG,
    )
    _require_source(
        "models_code",
        models_code,
        fixed_fd=BROKER_MODELS_CODE_FD,
        expected_type=stat.S_IFREG,
    )
    _require_source(
        "supervisor",
        supervisor,
        fixed_fd=SUPERVISOR_EXECUTABLE_FD,
        expected_type=stat.S_IFREG,
    )
    sources = (runtime_usr, broker_code, identity_code, models_code, supervisor)
    if len({source.fd for source in sources}) != len(sources):
        raise ValueError("broker source descriptor collision")
    identities = {
        (
            source.identity.device,
            source.identity.inode,
            source.identity.file_type,
        )
        for source in sources
    }
    if len(identities) != len(sources):
        raise ValueError("broker source identity collision")
    if len({source.locator for source in sources}) != len(sources):
        raise ValueError("broker source locator collision")
    every_fixed_fd = (
        SUPERVISOR_BWRAP_FD,
        SUPERVISOR_STATUS_FD,
        SUPERVISOR_EXECUTABLE_FD,
        BROKER_JSON_STATUS_FD,
        BROKER_RUNTIME_USR_FD,
        BROKER_CODE_FD,
        BROKER_IDENTITY_CODE_FD,
        BROKER_MODELS_CODE_FD,
        BROKER_POLICY_FD,
        BROKER_HANDOFF_FD,
        BROKER_STATUS_FD,
        BROKER_CONTROL_FD,
        BROKER_FIXTURE_FD,
    )
    if len(every_fixed_fd) != len(set(every_fixed_fd)):
        raise ValueError("fixed broker and supervisor descriptor roles collide")

    fixture_fd = (
        BROKER_FIXTURE_FD
        if transport_policy.mode is TransportMode.SYNTHETIC_FIXTURE_FD
        else None
    )
    contract = BrokerContract(
        version=BROKER_CONTRACT_VERSION,
        policy_fd=BROKER_POLICY_FD,
        handoff_fd=BROKER_HANDOFF_FD,
        status_fd=BROKER_STATUS_FD,
        control_fd=BROKER_CONTROL_FD,
        fixture_fd=fixture_fd,
        runtime_identity=_observed(runtime_usr.identity),
        broker_code_identity=_observed(broker_code.identity),
        identity_code_identity=_observed(identity_code.identity),
        models_code_identity=_observed(models_code.identity),
    )
    mounts = (
        BrokerMount(runtime_usr, RUNTIME_PATH, BrokerMountRole.RUNTIME),
        BrokerMount(broker_code, BROKER_CODE_PATH, BrokerMountRole.BROKER_CODE),
        BrokerMount(
            identity_code, IDENTITY_CODE_PATH, BrokerMountRole.IDENTITY_CODE
        ),
        BrokerMount(models_code, MODELS_CODE_PATH, BrokerMountRole.MODELS_CODE),
    )
    destinations = tuple(mount.destination for mount in mounts)
    if len(destinations) != len(set(destinations)):
        raise ValueError("broker mount destination collision")
    bwrap_argv = _build_bwrap_argv(mounts, contract)
    supervisor_contract = SupervisorContract(
        version=SUPERVISOR_CONTRACT_VERSION,
        bwrap_fd=SUPERVISOR_BWRAP_FD,
        status_fd=SUPERVISOR_STATUS_FD,
        broker_pass_fds=(
            BROKER_REQUIRED_PASS_FDS
            if fixture_fd is None
            else (*BROKER_REQUIRED_PASS_FDS, BROKER_FIXTURE_FD)
        ),
        broker_argv=bwrap_argv,
    )
    canonical = _canonical_boundary_bytes(
        policy=transport_policy,
        mounts=mounts,
        supervisor=supervisor,
        supervisor_contract=supervisor_contract,
        contract=contract,
        bwrap_argv=bwrap_argv,
    )
    return NetworkBoundaryPlan(
        transport_policy=transport_policy,
        mounts=mounts,
        synthetic_directories=BROKER_SYNTHETIC_DIRECTORIES,
        symlinks=BROKER_SYMLINKS,
        broker_environment=BROKER_ENVIRONMENT,
        broker_contract=contract,
        broker_json_status_fd=BROKER_JSON_STATUS_FD,
        broker_bwrap_argv=bwrap_argv,
        supervisor_contract=supervisor_contract,
        supervisor_source=SupervisorSource(supervisor),
        transport_policy_digest=policy_digest(transport_policy),
        canonical_boundary_policy=canonical,
        boundary_policy_digest=hashlib.sha256(canonical).hexdigest(),
    )


__all__ = [
    "AuthorizedSource",
    "BROKER_BOOTSTRAP",
    "BROKER_CODE_FD",
    "BROKER_ENVIRONMENT",
    "BROKER_IDENTITY_CODE_FD",
    "BROKER_JSON_STATUS_FD",
    "BROKER_MODELS_CODE_FD",
    "BROKER_RUNTIME_USR_FD",
    "BrokerBwrapSetupStatus",
    "BrokerMount",
    "BrokerMountRole",
    "FileIdentity",
    "NetworkBoundaryPlan",
    "NetworkBoundaryError",
    "SUPERVISOR_BWRAP_FD",
    "SUPERVISOR_CONTRACT_VERSION",
    "SUPERVISOR_EXECUTABLE_FD",
    "SUPERVISOR_STATUS_FD",
    "SupervisorContract",
    "SupervisorSource",
    "build_network_boundary_plan",
    "parse_broker_bwrap_documents",
    "read_broker_bwrap_setup_status",
]
