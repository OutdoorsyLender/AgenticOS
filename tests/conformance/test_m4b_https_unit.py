"""Unit tests for the M4B-2 slice-9a HTTPS material/policy plumbing.

Covers the extended broker FD contract, the sealed NetworkPolicy memfd
transport, the boundary plan's HTTPS flavor (mounts, bootstrap module list,
supervisor pass vector), the broker's material adoption (binding mismatch
matrix, fail-closed tamper cases, descriptor-closure proof), the native
supervisor's HTTPS pass vector, and the host-manifest record/gate workflow.
Linux-only: sealed memfds and fixed descriptors require it.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import time
import uuid

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("M4B-2 HTTPS plumbing requires Linux sealed memfds", allow_module_level=True)

from agenticos.sandbox import host_qualification as hq
from agenticos.sandbox import m4b_runner as runner_module
from agenticos.sandbox import network_broker as broker
from agenticos.sandbox import network_boundary as boundary
from agenticos.sandbox.cert_helper import (
    CertHelperError,
    generate_task_material,
    verify_task_material,
)
from agenticos.sandbox.network_https import (
    GrantPurpose,
    NetworkGrant,
    NetworkPolicy,
    NetworkPolicySealError,
    canonical_network_policy_bytes,
    create_sealed_network_policy_fd,
    network_policy_digest,
    read_sealed_network_policy_fd,
)
from agenticos.sandbox.network_identity import (
    create_sealed_policy_fd,
    read_sealed_policy_fd,
)
from agenticos.sandbox.network_models import (
    TransportMode,
    TransportPolicy,
    canonical_policy_bytes,
    policy_digest,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


# -- shared builders --------------------------------------------------------------


def _transport_policy(**changes):
    now = time.monotonic_ns()
    values = {
        "version": "AOSNET/1",
        "task_id": "task-https-unit",
        "task_generation": 7,
        "launch_nonce": "cd" * 16,
        "mode": TransportMode.DENY,
        "proxy_host": "127.0.0.1",
        "proxy_port": 18080,
        "activated_at_monotonic_ns": now - 1_000_000_000,
        "expires_at_monotonic_ns": now + 60_000_000_000,
        "connection_limit": 1,
        "byte_limit": 65536,
    }
    values.update(changes)
    return TransportPolicy(**values)


def _grant(hostname, policy, **changes):
    values = {
        "grant_id": "g-unit-1",
        "hostname": hostname,
        "purpose": GrantPurpose.GENERAL_DOWNLOAD,
        "approval_source": "unit-test",
        "approval_reference": "ref-1",
        "granted_at_wall_ns": time.time_ns(),
        "expires_at_wall_ns": time.time_ns() + 3_600_000_000_000,
        "activated_at_monotonic_ns": policy.activated_at_monotonic_ns,
        "expires_at_monotonic_ns": policy.expires_at_monotonic_ns,
        "connection_limit": 1,
        "byte_limit": 65536,
    }
    values.update(changes)
    return NetworkGrant(**values)


def _network_policy(policy, hostname, ca_digest, **changes):
    values = {
        "version": "AOSHTTPS/1",
        "task_id": policy.task_id,
        "task_generation": policy.task_generation,
        "launch_nonce": policy.launch_nonce,
        "task_ca_certificate_digest": ca_digest,
        "grants": (_grant(hostname, policy),),
    }
    values.update(changes)
    return NetworkPolicy(**values)


def _identity(device, inode, file_type=stat.S_IFREG):
    return broker.ObservedFileIdentity(
        device=device, inode=inode, file_type=file_type
    )


def _https_material_contract():
    return broker.HttpsMaterialContract(
        network_policy_fd=36,
        ca_cert_fd=37,
        leaf_cert_fd=38,
        leaf_key_fd=39,
        binding_fd=43,
        m4a_models_code_identity=_identity(200, 1),
        capabilities_code_identity=_identity(201, 2),
        special_addresses_code_identity=_identity(202, 3),
        resolution_code_identity=_identity(203, 4),
        http_code_identity=_identity(204, 5),
        https_code_identity=_identity(205, 6),
        clienthello_code_identity=_identity(206, 7),
        hostqual_code_identity=_identity(207, 8),
        tls_code_identity=_identity(208, 9),
        origin_code_identity=_identity(209, 10),
        cert_helper_code_identity=_identity(210, 11),
        vendor_identity=_identity(211, 12, stat.S_IFDIR),
    )


def _broker_contract(https=None):
    return broker.BrokerContract(
        version="AOSBROKER/1",
        policy_fd=30,
        handoff_fd=31,
        status_fd=32,
        control_fd=33,
        fixture_fd=None,
        runtime_identity=_identity(100, 1, stat.S_IFDIR),
        broker_code_identity=_identity(101, 2),
        identity_code_identity=_identity(102, 3),
        models_code_identity=_identity(103, 4),
        https=https,
    )


def _fixed_source(*, locator, fd, device, inode, file_type=stat.S_IFREG):
    return boundary.AuthorizedSource(
        locator=Path(locator),
        fd=fd,
        identity=boundary.FileIdentity(
            device=device, inode=inode, file_type=file_type
        ),
    )


def _boundary_sources():
    return {
        "runtime_usr": _fixed_source(
            locator="/trusted/runtime/usr", fd=20, device=101, inode=201,
            file_type=stat.S_IFDIR,
        ),
        "broker_code": _fixed_source(
            locator="/trusted/code/network_broker.py", fd=21, device=102, inode=202
        ),
        "identity_code": _fixed_source(
            locator="/trusted/code/network_identity.py", fd=22, device=103, inode=203
        ),
        "models_code": _fixed_source(
            locator="/trusted/code/network_models.py", fd=23, device=104, inode=204
        ),
        "supervisor": _fixed_source(
            locator="/trusted/native/task_supervisor", fd=7, device=105, inode=205
        ),
    }


def _https_sources():
    names = (
        ("m4a_models_code", "models.py", 9),
        ("capabilities_code", "capabilities.py", 10),
        ("special_addresses_code", "special_addresses.py", 11),
        ("resolution_code", "network_resolution.py", 12),
        ("http_code", "network_http.py", 13),
        ("https_code", "network_https.py", 14),
        ("clienthello_code", "network_clienthello.py", 15),
        ("hostqual_code", "host_qualification.py", 16),
        ("tls_code", "network_tls.py", 17),
        ("origin_code", "network_origin.py", 18),
        ("cert_helper_code", "cert_helper.py", 19),
    )
    values = {
        role: _fixed_source(
            locator=f"/trusted/code/{filename}",
            fd=fd,
            device=300 + index,
            inode=400 + index,
        )
        for index, (role, filename, fd) in enumerate(names)
    }
    values["vendor"] = _fixed_source(
        locator="/trusted/vendor",
        fd=24,
        device=399,
        inode=499,
        file_type=stat.S_IFDIR,
    )
    return boundary.HttpsBrokerSources(**values)


def _move_fd(fd, target):
    if fd == target:
        return target
    os.dup2(fd, target, inheritable=True)
    os.close(fd)
    return target


def _fd_closed(fd):
    try:
        fcntl.fcntl(fd, fcntl.F_GETFD)
    except OSError as exc:
        return exc.errno == errno.EBADF
    return False


# -- broker contract argv shape -----------------------------------------------------


def test_https_material_contract_pins_fixed_fds_and_round_trips():
    https = _https_material_contract()
    assert https.material_fds == (36, 37, 38, 39, 43)
    contract = _broker_contract(https)
    assert contract.capability_fds == (30, 31, 32, 33)
    assert contract.entry_fds == (30, 31, 32, 33, 36, 37, 38, 39, 43)
    argv = contract.to_argv()
    assert argv[-1] == "END"
    assert len(argv) <= broker.MAX_CONTRACT_ITEMS
    assert all(0 < len(item.encode()) <= broker.MAX_CONTRACT_ITEM_BYTES for item in argv)
    assert broker.BrokerContract.from_argv(argv) == contract


def test_m4b1_contract_argv_is_byte_identical_without_https_section():
    contract = _broker_contract()
    argv = contract.to_argv()
    assert argv == (
        "AOSBROKER/1",
        "policy_fd", "30",
        "handoff_fd", "31",
        "status_fd", "32",
        "control_fd", "33",
        "fixture_fd", "none",
        "runtime_identity", "100", "1", str(stat.S_IFDIR),
        "broker_code_identity", "101", "2", str(stat.S_IFREG),
        "identity_code_identity", "102", "3", str(stat.S_IFREG),
        "models_code_identity", "103", "4", str(stat.S_IFREG),
        "END",
    )
    assert "https_material" not in argv
    assert contract.material_fds == ()
    assert broker.BrokerContract.from_argv(argv) == contract


@pytest.mark.parametrize(
    "field,value",
    [
        ("network_policy_fd", 35),
        ("ca_cert_fd", 36),
        ("leaf_cert_fd", 37),
        ("leaf_key_fd", 38),
        ("binding_fd", 42),
        ("binding_fd", 44),
    ],
)
def test_https_material_contract_rejects_nonfixed_descriptors(field, value):
    values = {
        "network_policy_fd": 36,
        "ca_cert_fd": 37,
        "leaf_cert_fd": 38,
        "leaf_key_fd": 39,
        "binding_fd": 43,
    }
    values[field] = value
    identities = {
        name: _identity(200 + index, index + 1)
        for index, name in enumerate(
            (
                "m4a_models_code_identity",
                "capabilities_code_identity",
                "special_addresses_code_identity",
                "resolution_code_identity",
                "http_code_identity",
                "https_code_identity",
                "clienthello_code_identity",
                "hostqual_code_identity",
                "tls_code_identity",
                "origin_code_identity",
                "cert_helper_code_identity",
            )
        )
    }
    identities["vendor_identity"] = _identity(300, 99, stat.S_IFDIR)
    with pytest.raises(broker.BrokerBoundaryError):
        broker.HttpsMaterialContract(**values, **identities)


def test_https_material_contract_rejects_identity_collisions():
    colliding = _identity(200, 1)
    identities = {
        name: colliding if index < 2 else _identity(200 + index, index + 1)
        for index, name in enumerate(
            (
                "m4a_models_code_identity",
                "capabilities_code_identity",
                "special_addresses_code_identity",
                "resolution_code_identity",
                "http_code_identity",
                "https_code_identity",
                "clienthello_code_identity",
                "hostqual_code_identity",
                "tls_code_identity",
                "origin_code_identity",
                "cert_helper_code_identity",
            )
        )
    }
    identities["vendor_identity"] = _identity(300, 99, stat.S_IFDIR)
    with pytest.raises(broker.BrokerBoundaryError):
        broker.HttpsMaterialContract(
            network_policy_fd=36,
            ca_cert_fd=37,
            leaf_cert_fd=38,
            leaf_key_fd=39,
            binding_fd=43,
            **identities,
        )


def test_broker_contract_rejects_https_section_in_m4b1_position():
    contract = _broker_contract()
    argv = list(contract.to_argv())
    argv.insert(-1, "https_material")
    with pytest.raises(broker.BrokerBoundaryError):
        broker.BrokerContract.from_argv(argv)


# -- sealed NetworkPolicy memfd ----------------------------------------------------


def test_sealed_network_policy_round_trip_and_digest():
    policy = _transport_policy()
    network_policy = _network_policy(policy, "cdn.example.com", "ab" * 32)
    fd = create_sealed_network_policy_fd(network_policy)
    try:
        verified = read_sealed_network_policy_fd(fd)
    finally:
        os.close(fd)
    assert verified.policy == network_policy
    assert verified.digest == network_policy_digest(network_policy)
    assert verified.size == len(canonical_network_policy_bytes(network_policy))


def test_sealed_network_policy_rejects_unsealed_object():
    policy = _transport_policy()
    network_policy = _network_policy(policy, "cdn.example.com", "ab" * 32)
    payload = canonical_network_policy_bytes(network_policy)
    fd = os.memfd_create("unsealed", os.MFD_CLOEXEC)
    try:
        os.write(fd, payload)
        with pytest.raises(NetworkPolicySealError):
            read_sealed_network_policy_fd(fd)
    finally:
        os.close(fd)


def test_sealed_network_policy_rejects_truncated_and_noncanonical_payloads():
    policy = _transport_policy()
    network_policy = _network_policy(policy, "cdn.example.com", "ab" * 32)
    payload = canonical_network_policy_bytes(network_policy)
    for mutated in (payload[:-1], payload + b" "):
        fd = os.memfd_create("mutated", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            os.write(fd, mutated)
            seals = (
                fcntl.F_SEAL_WRITE
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_SEAL
            )
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            with pytest.raises(NetworkPolicySealError):
                read_sealed_network_policy_fd(fd)
        finally:
            os.close(fd)


# -- boundary plan HTTPS flavor -----------------------------------------------------


def test_https_boundary_plan_mounts_pass_fds_and_bootstrap():
    plan = boundary.build_network_boundary_plan(
        transport_policy=_transport_policy(),
        **_boundary_sources(),
        https=_https_sources(),
    )
    assert plan.supervisor_contract.broker_pass_fds == boundary.BROKER_HTTPS_PASS_FDS
    assert boundary.BROKER_HTTPS_PASS_FDS == (
        8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        30, 31, 32, 33, 36, 37, 38, 39, 43,
    )
    argv = plan.broker_bwrap_argv
    assert boundary.BROKER_BOOTSTRAP_HTTPS in argv
    assert "https_material" in argv
    destinations = tuple(mount.destination for mount in plan.mounts)
    assert "/opt/agenticos/vendor" in destinations
    for role, _module, path in broker.BROKER_HTTPS_MODULE_ROLES:
        assert path in destinations
    assert "cryptography" not in boundary.BROKER_BOOTSTRAP_HTTPS
    assert broker.VENDOR_PATH in boundary.BROKER_BOOTSTRAP_HTTPS
    assert plan.broker_contract.https is not None
    assert broker.BrokerContract.from_argv(
        plan.broker_contract.to_argv()
    ) == plan.broker_contract


def test_https_bootstrap_module_list_is_exact_dependency_order():
    assert boundary.BROKER_HTTPS_BOOTSTRAP_MODULES == (
        "models",
        "network_models",
        "capabilities",
        "special_addresses",
        "network_resolution",
        "network_http",
        "network_https",
        "network_clienthello",
        "host_qualification",
        "network_tls",
        "network_origin",
        "network_identity",
        "cert_helper",
        "network_broker",
    )
    bootstrap = boundary.BROKER_BOOTSTRAP_HTTPS
    for module in boundary.BROKER_HTTPS_BOOTSTRAP_MODULES[:-1]:
        assert f"'{module}'" in bootstrap
    assert bootstrap.endswith(
        "importlib.import_module('agenticos.sandbox.network_broker').main())"
    )
    assert len(bootstrap.encode()) <= boundary.MAX_SUPERVISOR_ITEM_BYTES


def test_m4b1_boundary_plan_is_unchanged_by_https_flavor():
    deny = boundary.build_network_boundary_plan(
        transport_policy=_transport_policy(), **_boundary_sources()
    )
    assert deny.broker_contract.https is None
    assert deny.supervisor_contract.broker_pass_fds == (
        8, 20, 21, 22, 23, 30, 31, 32, 33
    )
    assert boundary.BROKER_BOOTSTRAP in deny.broker_bwrap_argv
    assert "https_material" not in deny.broker_bwrap_argv
    fixture = boundary.build_network_boundary_plan(
        transport_policy=_transport_policy(mode=TransportMode.SYNTHETIC_FIXTURE_FD),
        **_boundary_sources(),
    )
    assert fixture.supervisor_contract.broker_pass_fds == (
        8, 20, 21, 22, 23, 30, 31, 32, 33, 34
    )


def test_https_boundary_plan_rejects_non_deny_transport():
    with pytest.raises(ValueError, match="DENY"):
        boundary.build_network_boundary_plan(
            transport_policy=_transport_policy(
                mode=TransportMode.SYNTHETIC_FIXTURE_FD
            ),
            **_boundary_sources(),
            https=_https_sources(),
        )


def test_https_sources_reject_wrong_fixed_fd():
    values = _https_sources()
    broken = {
        **{
            role: getattr(values, role)
            for role in (
                "m4a_models_code",
                "capabilities_code",
                "special_addresses_code",
                "resolution_code",
                "http_code",
                "https_code",
                "clienthello_code",
                "hostqual_code",
                "tls_code",
                "origin_code",
                "cert_helper_code",
                "vendor",
            )
        }
    }
    broken["tls_code"] = _fixed_source(
        locator="/trusted/code/network_tls.py", fd=25, device=317, inode=417
    )
    with pytest.raises(ValueError, match="fixed descriptor"):
        boundary.HttpsBrokerSources(**broken)


# -- broker material adoption --------------------------------------------------------


def _adoption_fixture(tmp_path, *, policy=None, hostname="cdn.example.com",
                      network_policy_changes=None):
    """Install real sealed material at the fixed descriptor roles."""
    policy = policy or _transport_policy()
    material = generate_task_material(
        task_id=policy.task_id,
        task_generation=policy.task_generation,
        launch_nonce=policy.launch_nonce,
        hostname=hostname,
        policy_digest=policy_digest(policy),
    )
    changes = dict(network_policy_changes or {})
    network_policy = _network_policy(
        policy, changes.pop("hostname", hostname),
        changes.pop("ca_digest", material.binding.ca_cert_sha256),
        **changes,
    )
    network_policy_fd = create_sealed_network_policy_fd(network_policy)
    installed = []
    try:
        installed.append(_move_fd(create_sealed_policy_fd(policy), 30))
        for target in (31, 32, 33):
            pair = socket.socketpair()
            keep, drop = pair[0].detach(), pair[1].detach()
            os.close(drop)
            installed.append(_move_fd(keep, target))
        installed.append(_move_fd(network_policy_fd, 36))
        installed.append(_move_fd(material.ca_cert_fd, 37))
        installed.append(_move_fd(material.leaf_cert_fd, 38))
        installed.append(_move_fd(material.leaf_key_fd, 39))
        installed.append(_move_fd(material.binding_fd, 43))
    except BaseException:
        for fd in installed:
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    contract = _broker_contract(_https_material_contract())
    return policy, material, network_policy, contract, installed


def _cleanup_installed(installed):
    for fd in installed:
        try:
            os.close(fd)
        except OSError:
            pass


def test_broker_adopts_https_material_and_proves_source_closure(tmp_path):
    policy, material, network_policy, contract, installed = _adoption_fixture(tmp_path)
    try:
        sealed = read_sealed_policy_fd(30)
        state = broker._adopt_https_material(contract, sealed)
        assert state.network_policy == network_policy
        assert state.network_policy_digest == network_policy_digest(network_policy)
        assert state.binding == material.binding
        assert state.server_context is not None
        for fd in (36, 37, 38, 39, 43):
            assert _fd_closed(fd), f"material descriptor {fd} survived closure"
    finally:
        _cleanup_installed(installed)


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param("task_id", id="wrong-task"),
        pytest.param("task_generation", id="wrong-generation"),
        pytest.param("launch_nonce", id="wrong-nonce"),
        pytest.param("hostname", id="wrong-hostname"),
        pytest.param("ca_digest", id="wrong-ca-commit"),
    ],
)
def test_broker_adoption_fails_closed_on_binding_mismatch(tmp_path, tamper):
    policy = _transport_policy()
    if tamper in {"task_id", "task_generation", "launch_nonce"}:
        # Material bound to a DIFFERENT task context than the transport policy.
        other = {
            "task_id": "task-https-other",
            "task_generation": policy.task_generation + 1,
            "launch_nonce": "ef" * 16,
        }
        material_policy = _transport_policy(**{tamper: other[tamper]})
        _policy, material, network_policy, contract, installed = _adoption_fixture(
            tmp_path, policy=material_policy
        )
        try:
            sealed = read_sealed_policy_fd(30)
            try:
                broker._adopt_https_material(
                    contract,
                    broker.VerifiedSealedPolicy(
                        policy=policy,
                        digest=policy_digest(policy),
                        device=sealed.device,
                        inode=sealed.inode,
                        size=sealed.size,
                        seals=sealed.seals,
                    ),
                )
                raise AssertionError("adoption must fail closed")
            except broker.BrokerBoundaryError:
                pass
        finally:
            _cleanup_installed(installed)
        return
    changes = (
        {"hostname": "evil.example.com"}
        if tamper == "hostname"
        else {"ca_digest": "00" * 32}
    )
    _policy, material, network_policy, contract, installed = _adoption_fixture(
        tmp_path, network_policy_changes=changes
    )
    try:
        sealed = read_sealed_policy_fd(30)
        with pytest.raises(broker.BrokerBoundaryError):
            broker._adopt_https_material(contract, sealed)
    finally:
        _cleanup_installed(installed)


def test_broker_adoption_rejects_unsealed_material(tmp_path):
    policy = _transport_policy()
    _policy, material, network_policy, contract, installed = _adoption_fixture(tmp_path)
    try:
        # Replace the sealed leaf key with an unsealed impostor object.
        os.close(39)
        impostor = os.memfd_create("impostor", os.MFD_CLOEXEC)
        os.write(impostor, b"not-a-key")
        _move_fd(impostor, 39)
        sealed = read_sealed_policy_fd(30)
        with pytest.raises(broker.BrokerBoundaryError):
            broker._adopt_https_material(contract, sealed)
    finally:
        _cleanup_installed(installed)


def test_verify_task_material_context_matrix(tmp_path):
    policy = _transport_policy()
    material = generate_task_material(
        task_id=policy.task_id,
        task_generation=policy.task_generation,
        launch_nonce=policy.launch_nonce,
        hostname="cdn.example.com",
        policy_digest=policy_digest(policy),
    )
    try:
        base = {
            "ca_cert_fd": material.ca_cert_fd,
            "leaf_cert_fd": material.leaf_cert_fd,
            "leaf_key_fd": material.leaf_key_fd,
            "binding_fd": material.binding_fd,
            "task_id": policy.task_id,
            "task_generation": policy.task_generation,
            "launch_nonce": policy.launch_nonce,
            "hostname": "cdn.example.com",
            "policy_digest": policy_digest(policy),
        }
        verified = verify_task_material(**base)
        assert verified.binding == material.binding
        for field, bad in (
            ("task_id", "task-other"),
            ("task_generation", policy.task_generation + 1),
            ("launch_nonce", "ef" * 16),
            ("hostname", "other.example.com"),
            ("policy_digest", "00" * 32),
        ):
            with pytest.raises(CertHelperError):
                verify_task_material(**{**base, field: bad})
    finally:
        material.close()


# -- native supervisor HTTPS pass vector ----------------------------------------------


@pytest.fixture(scope="module")
def supervisor_binary(tmp_path_factory):
    output = tmp_path_factory.mktemp("m4b2-supervisor")
    binary = output / "task_supervisor"
    subprocess.run(
        [
            "cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra",
            "-Werror", "-O2",
            str(REPO_ROOT / "native/task_supervisor/task_supervisor.c"),
            "-o", str(binary),
        ],
        check=True,
    )
    return binary


def _supervisor_argv(pass_fds):
    return [
        "AOSSUP/1",
        "bwrap_fd", "5",
        "status_fd", "6",
        "broker_passc", str(len(pass_fds)),
        "broker_pass", *(str(fd) for fd in pass_fds),
        "worker_passc", "0",
        "worker_pass",
        "broker_argc", "1",
        "broker", "bwrap",
        "worker_argc", "1",
        "worker", "bwrap",
        "END",
    ]


def _run_supervisor_contract(binary, pass_fds):
    """Probe contract parsing: an accepted vector fails LATER (fd validation)."""
    completed = subprocess.run(
        [str(binary), *_supervisor_argv(pass_fds)],
        capture_output=True,
        timeout=10,
    )
    return completed


def test_supervisor_accepts_https_pass_vector_but_rejects_mutations(supervisor_binary):
    https = list(boundary.BROKER_HTTPS_PASS_FDS)
    accepted = _run_supervisor_contract(supervisor_binary, https)
    # Accepted by the contract parser; fails only LATER at descriptor
    # validation (the probe passes no real descriptors).
    assert b"contract" not in accepted.stderr

    for mutation in (
        https[:-1],
        [*https, 45],
        [9 if fd == 8 else fd for fd in https],
        sorted(https, reverse=True),
        [44 if fd == 24 else fd for fd in https],
    ):
        rejected = _run_supervisor_contract(supervisor_binary, mutation)
        assert b"contract" in rejected.stderr, mutation


# -- host manifest record and gate -----------------------------------------------------


def test_host_manifest_record_round_trip_and_gate(tmp_path):
    record = runner_module.qualify_host_for_https(tmp_path)
    assert record == tmp_path / runner_module.HOST_MANIFEST_FILENAME
    runner_module.verify_https_host(tmp_path)


def test_host_manifest_gate_fails_closed_when_absent(tmp_path):
    with pytest.raises(hq.HostQualificationError, match="absent"):
        runner_module.verify_https_host(tmp_path)


def test_host_manifest_gate_fails_closed_on_tamper(tmp_path):
    record = runner_module.qualify_host_for_https(tmp_path)
    document = json.loads(record.read_bytes())
    components = document["manifest"]["components"]
    first = next(iter(sorted(components)))
    components[first]["tampered"] = True
    record.write_text(json.dumps(document))
    with pytest.raises(hq.HostQualificationError):
        runner_module.verify_https_host(tmp_path)


def test_host_manifest_gate_fails_closed_on_digest_substitution(tmp_path):
    record = runner_module.qualify_host_for_https(tmp_path)
    document = json.loads(record.read_bytes())
    components = document["manifest"]["components"]
    first = next(iter(sorted(components)))
    components[first]["tampered"] = True
    # Recompute the digest honestly over tampered content: verification must
    # still fail because the LIVE host does not match the record.
    document["manifest_digest"] = hq.manifest_digest(document["manifest"])
    record.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":"))
    )
    with pytest.raises(hq.HostQualificationMismatchError):
        runner_module.verify_https_host(tmp_path)


# -- vendor directory ------------------------------------------------------------------


def test_broker_vendor_directory_is_exact_offline_h11():
    vendor = runner_module.ensure_broker_vendor()
    assert tuple(sorted(p.name for p in vendor.iterdir())) == broker.VENDOR_ENTRIES
    assert (vendor / "h11" / "__init__.py").is_file()
    metadata = vendor / "h11-0.16.0.dist-info" / "METADATA"
    assert "Version: 0.16.0" in metadata.read_text().splitlines()


def test_https_runner_requires_deny_policy(tmp_path):
    from helpers import WORKER_PATH

    policy = _transport_policy(mode=TransportMode.SYNTHETIC_FIXTURE_FD)
    with pytest.raises(runner_module.CapabilityTransportError, match="DENY"):
        runner_module.HttpsCapabilityTransportRunner(
            WORKER_PATH,
            workspace=tmp_path,
            profile=None,
            launcher_path=tmp_path / "launcher",
            task_tmp=tmp_path,
            synthetic_home=tmp_path,
            transport_policy=policy,
            supervisor_path=tmp_path / "supervisor",
            approved_hostname="cdn.example.com",
            grant_purpose=GrantPurpose.GENERAL_DOWNLOAD,
            approval_source="unit-test",
            approval_reference="ref-1",
            host_state_dir=tmp_path,
        )


# ============================================================================
# Slice 9b: HTTPS serve path state machine (in-process doubles)
# ============================================================================
#
# The broker's per-connection pipeline is exercised synchronously over
# socketpairs with real TLS on both legs: the worker leg uses a real
# OpenSSL client trusting only the task CA, the origin leg uses the
# conformance fixture (an already-connected socketpair to a scripted test
# TLS server) exactly as the FixtureFdConnector arms it over the control
# channel.  Patterns mirror test_m4b_unit.py (_run_relay_thread) and
# test_m4b_tls_unit.py (real/synthetic TLS clients).

import array
import datetime
import ssl
import threading
import types

from agenticos.sandbox import cert_helper as cert_helper_module
from agenticos.sandbox import network_tls as tls_module
from agenticos.sandbox import network_clienthello as clienthello_module

import chgen
from test_m4b_origin_unit import _custom_material, _server_context


SERVE_HOSTNAME = "cdn.example.com"
OTHER_HOSTNAME = "other.example.com"
SERVE_TASK = {
    "task_id": "task-https-serve",
    "task_generation": 9,
    "launch_nonce": "cd" * 16,
    "hostname": SERVE_HOSTNAME,
    "policy_digest": "ab" * 32,
}


@pytest.fixture(scope="module")
def serve_leaf_material():
    material = cert_helper_module.generate_task_material(**SERVE_TASK)
    try:
        yield {
            "context": cert_helper_module.load_leaf_ssl_context(
                ca_cert_fd=material.ca_cert_fd,
                leaf_cert_fd=material.leaf_cert_fd,
                leaf_key_fd=material.leaf_key_fd,
                binding_fd=material.binding_fd,
                **SERVE_TASK,
            ),
            "ca_pem": os.pread(
                material.ca_cert_fd, os.fstat(material.ca_cert_fd).st_size, 0
            ).decode("ascii"),
        }
    finally:
        material.close()


def _serve_policy(*, connection_limit=4, byte_limit=1 << 20, lifetime_ns=None):
    now = time.monotonic_ns()
    return TransportPolicy(
        version="AOSNET/1",
        task_id=SERVE_TASK["task_id"],
        task_generation=SERVE_TASK["task_generation"],
        launch_nonce=SERVE_TASK["launch_nonce"],
        mode=TransportMode.DENY,
        proxy_host="127.0.0.1",
        proxy_port=18080,
        activated_at_monotonic_ns=now - 1_000_000_000,
        expires_at_monotonic_ns=(
            now + (30_000_000_000 if lifetime_ns is None else lifetime_ns)
        ),
        connection_limit=connection_limit,
        byte_limit=byte_limit,
    )


def _serve_network_policy(
    policy, *, purpose=GrantPurpose.GENERAL_DOWNLOAD, hostname=SERVE_HOSTNAME
):
    now_wall = time.time_ns()
    grant = NetworkGrant(
        grant_id="g-serve-1",
        hostname=hostname,
        purpose=purpose,
        approval_source="unit-test",
        approval_reference="serve-1",
        granted_at_wall_ns=now_wall,
        expires_at_wall_ns=now_wall + 3_600_000_000_000,
        activated_at_monotonic_ns=policy.activated_at_monotonic_ns,
        expires_at_monotonic_ns=policy.expires_at_monotonic_ns,
        connection_limit=policy.connection_limit,
        byte_limit=policy.byte_limit,
    )
    return NetworkPolicy(
        version="AOSHTTPS/1",
        task_id=policy.task_id,
        task_generation=policy.task_generation,
        launch_nonce=policy.launch_nonce,
        task_ca_certificate_digest="ab" * 32,
        grants=(grant,),
    )


def _serve_https_state(network_policy, server_context):
    return broker._HttpsMaterialState(
        network_policy=network_policy,
        network_policy_digest=network_policy_digest(network_policy),
        binding=None,
        server_context=server_context,
    )


def _origin_pems(hostname=SERVE_HOSTNAME):
    now = datetime.datetime.now(datetime.timezone.utc)
    return _custom_material(
        now - datetime.timedelta(minutes=2),
        now + datetime.timedelta(hours=1),
        hostname=hostname,
    )


def _origin_read_request(tls):
    """Read one request head plus any Content-Length body from the origin leg."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = tls.recv(4096)
        if not chunk:
            return data
        data += chunk
        if len(data) > 65536:
            raise RuntimeError("origin request head exceeded test bound")
    head, _, rest = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(rest) < length:
        chunk = tls.recv(4096)
        if not chunk:
            break
        rest += chunk
    return head + b"\r\n\r\n" + rest


class _ScriptedOrigin:
    """A scripted test TLS server on one end of the fixture socketpair."""

    def __init__(self, tmp_path, pems, responder, *, request_count=1):
        self._broker_end, server_end = socket.socketpair()
        self.fd = self._broker_end.fileno()
        self.requests = []
        self.errors = []
        self._context = _server_context(tmp_path, pems)
        self._thread = threading.Thread(
            target=self._run,
            args=(server_end, responder, request_count),
            daemon=True,
        )
        self._thread.start()

    def _run(self, sock, responder, request_count):
        try:
            tls = self._context.wrap_socket(sock, server_side=True)
            tls.settimeout(20.0)
            for index in range(request_count):
                request = _origin_read_request(tls)
                self.requests.append(request)
                if not responder(tls, request, index):
                    break
            tls.close()
        except (ssl.SSLError, OSError) as exc:
            self.errors.append(f"{type(exc).__name__}: {exc}")
        except RuntimeError as exc:
            self.errors.append(str(exc))
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def join(self, timeout=8.0):
        self._thread.join(timeout)
        assert not self._thread.is_alive(), "scripted origin thread stuck"

    def close(self):
        try:
            self._broker_end.close()
        except OSError:
            pass


def _ok_responder(body=b"hello", *, status=b"200 OK", keepalive=True):
    def respond(tls, _request, _index):
        connection = b"" if keepalive else b"Connection: close\r\n"
        tls.sendall(
            b"HTTP/1.1 " + status + b"\r\nContent-Length: "
            + str(len(body)).encode("ascii") + b"\r\n" + connection
            + b"\r\n" + body
        )
        return True

    return respond


def _slow_responder(delay=10.0):
    def respond(tls, _request, _index):
        time.sleep(delay)
        return True

    return respond


class _ServeRun:
    def __init__(self, serve, control_peer, origin, thread):
        self.serve = serve
        self.control_peer = control_peer
        self.origin = origin
        self.thread = thread

    def read_record(self):
        self.control_peer.settimeout(5.0)
        payload = self.control_peer.recv(broker.MAX_HTTPS_EVIDENCE_BYTES + 1)
        return broker.HttpsConnectionRecord.from_bytes(payload)


def _start_serve_connection(
    tmp_path,
    serve_leaf_material,
    *,
    purpose=GrantPurpose.GENERAL_DOWNLOAD,
    connection_limit=4,
    byte_limit=1 << 20,
    lifetime_ns=None,
    origin=True,
    origin_pems=None,
    origin_responder=None,
    origin_request_count=1,
    fixture_addresses=("93.184.216.34",),
):
    """Wire one in-process connection through _serve_https_connection."""
    policy = _serve_policy(
        connection_limit=connection_limit,
        byte_limit=byte_limit,
        lifetime_ns=lifetime_ns,
    )
    network_policy = _serve_network_policy(policy, purpose=purpose)
    https_state = _serve_https_state(
        network_policy, serve_leaf_material["context"]
    )
    control_broker, control_peer = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET
    )
    serve = broker._HttpsServeState(policy, https_state, control_broker.fileno())
    origin_server = None
    if origin:
        pems = origin_pems or _origin_pems()
        origin_server = _ScriptedOrigin(
            tmp_path,
            pems,
            origin_responder or _ok_responder(),
            request_count=origin_request_count,
        )
        serve.fixture = broker._HttpsFixtureState(
            origin_server.fd,
            pems["ca"].decode("ascii"),
            tuple(fixture_addresses),
        )
    worker_broker, worker_client = socket.socketpair()
    runtime = broker._HttpsConnectionRuntime(worker_broker)
    serve.runtimes.append(runtime)
    thread = threading.Thread(
        target=broker._serve_https_connection,
        args=(serve, runtime, 1),
        daemon=True,
    )
    run = _ServeRun(serve, control_peer, origin_server, thread)
    run.control_broker = control_broker
    run.worker_client = worker_client
    run.policy = policy
    run.network_policy = network_policy
    thread.start()
    return run


def _close_tls(tls):
    try:
        tls.settimeout(1.0)
    except OSError:
        pass
    try:
        tls.unwrap()
    except (ssl.SSLError, OSError):
        pass
    try:
        tls.close()
    except OSError:
        pass


def _finish_serve_run(run, *, origin_join=True):
    run.thread.join(15.0)
    assert not run.thread.is_alive(), "serve connection thread stuck"
    assert not run.serve.thread_errors, (
        f"serve thread emitted errors: {run.serve.thread_errors}"
    )
    if run.origin is not None:
        # Unblock a never-used scripted origin (its handshake wait ends).
        run.origin.close()
        if origin_join:
            run.origin.join()
    record = run.read_record()
    run.control_peer.close()
    run.control_broker.close()
    try:
        run.worker_client.close()
    except OSError:
        pass
    return record


def _worker_connect(sock, authority=SERVE_HOSTNAME, *, raw_head=None, timeout=5.0):
    head = raw_head
    if head is None:
        head = f"CONNECT {authority} HTTP/1.1\r\n\r\n".encode("ascii")
    sock.settimeout(timeout)
    sock.sendall(head)
    reply = b""
    while b"\r\n\r\n" not in reply:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        reply += chunk
    return reply


def _worker_tls(sock, ca_pem, *, sni=SERVE_HOSTNAME, alpn=("http/1.1",), timeout=10.0):
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(cadata=ca_pem)
    client_context.verify_mode = ssl.CERT_REQUIRED
    client_context.check_hostname = True
    client_context.set_alpn_protocols(list(alpn))
    tls = client_context.wrap_socket(sock, server_hostname=sni)
    tls.settimeout(timeout)
    return tls


def _read_worker_response(tls, timeout=8.0):
    """Read one Content-Length-delimited response; None on EOF/error."""
    tls.settimeout(timeout)
    head = b""
    try:
        while b"\r\n\r\n" not in head:
            chunk = tls.recv(4096)
            if not chunk:
                return None
            head += chunk
    except (ssl.SSLError, OSError):
        return None
    raw, _, body = head.partition(b"\r\n\r\n")
    length = 0
    for line in raw.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    try:
        while len(body) < length:
            chunk = tls.recv(4096)
            if not chunk:
                break
            body += chunk
    except (ssl.SSLError, OSError):
        return None
    return raw + b"\r\n\r\n" + body


# -- evidence record codecs ----------------------------------------------------


def _connection_record_kwargs(**changes):
    values = {
        "version": broker.HTTPS_EVIDENCE_VERSION,
        "event": broker.HTTPS_CONNECTION_EVENT,
        "task_id": "task-https-serve",
        "task_generation": 9,
        "launch_nonce": "cd" * 16,
        "policy_digest": "ab" * 32,
        "network_policy_digest": "cd" * 32,
        "address_policy_version": "AOSADDR/1+test",
        "connection_index": 1,
        "stage_reached": broker.HttpsConnectionStage.RESPONSE_RELAY,
        "terminal_reason": broker.HttpsConnectionTermination.COMPLETED,
        "detail": "worker_closed",
        "approved_hostname": SERVE_HOSTNAME,
        "connect_authority": SERVE_HOSTNAME,
        "worker_sni": SERVE_HOSTNAME,
        "http_host": SERVE_HOSTNAME,
        "origin_tls_name": SERVE_HOSTNAME,
        "identity_chain": "verified",
        "worker_tls_version": "TLSv1.3",
        "worker_alpn": "http/1.1",
        "origin_tls_version": "TLSv1.3",
        "origin_alpn": "http/1.1",
        "origin_peer_address": "93.184.216.34",
        "origin_peer_port": 443,
        "synthetic_origin": True,
        "requests_completed": 1,
        "accounted_bytes": 84,
        "worker_to_origin_bytes": 41,
        "origin_to_worker_bytes": 43,
        "total_bytes": 84,
        "discarded_unsent_bytes": 0,
        "observed_at_monotonic_ns": time.monotonic_ns(),
    }
    values.update(changes)
    return values


def test_https_connection_record_round_trip_and_canonicality():
    record = broker.HttpsConnectionRecord(**_connection_record_kwargs())
    payload = record.to_bytes()
    assert broker.HttpsConnectionRecord.from_bytes(payload) == record
    with pytest.raises(broker.BrokerBoundaryError):
        broker.HttpsConnectionRecord.from_bytes(payload + b" ")
    with pytest.raises(broker.BrokerBoundaryError):
        broker.HttpsConnectionRecord.from_bytes(payload[:-1])


@pytest.mark.parametrize(
    "changes",
    [
        {"total_bytes": 85},  # total != w2o + o2w
        {"accounted_bytes": 83},  # accounted != total + discarded
        {"connection_index": 0},
        {"worker_sni": "evil\x01host"},
        {"synthetic_origin": "yes"},
        {"origin_peer_port": 65536},
    ],
)
def test_https_connection_record_rejects_invalid_invariants(changes):
    with pytest.raises(broker.BrokerBoundaryError):
        broker.HttpsConnectionRecord(**_connection_record_kwargs(**changes))


def test_https_terminal_record_round_trip_and_aliases():
    terminal = broker.HttpsTransportTerminal(
        version=broker.HTTPS_EVIDENCE_VERSION,
        event=broker.HTTPS_TERMINAL_EVENT,
        task_id="task-https-serve",
        task_generation=9,
        launch_nonce="cd" * 16,
        policy_digest="ab" * 32,
        network_policy_digest="cd" * 32,
        observed_at_monotonic_ns=time.monotonic_ns(),
        connection_count=2,
        accounted_bytes=100,
        worker_to_origin_bytes=60,
        origin_to_worker_bytes=40,
        total_bytes=100,
        discarded_unsent_bytes=0,
        terminal_reason=broker.TransportTermination.REVOKED,
        synthetic_origin=True,
    )
    payload = terminal.to_bytes()
    assert broker.HttpsTransportTerminal.from_bytes(payload) == terminal
    assert terminal.worker_to_fixture_bytes == 60
    assert terminal.fixture_to_worker_bytes == 40
    with pytest.raises(broker.BrokerBoundaryError):
        broker.HttpsConnectionRecord.from_bytes(payload)


@pytest.mark.parametrize("reason", [
    broker.TransportTermination.DENY_NO_RELAY,
    broker.TransportTermination.COMPLETED,
])
def test_https_terminal_rejects_non_https_outcomes(reason):
    with pytest.raises(broker.BrokerBoundaryError):
        broker.HttpsTransportTerminal(
            version=broker.HTTPS_EVIDENCE_VERSION,
            event=broker.HTTPS_TERMINAL_EVENT,
            task_id="task-https-serve",
            task_generation=9,
            launch_nonce="cd" * 16,
            policy_digest="ab" * 32,
            network_policy_digest="cd" * 32,
            observed_at_monotonic_ns=time.monotonic_ns(),
            connection_count=0,
            accounted_bytes=0,
            worker_to_origin_bytes=0,
            origin_to_worker_bytes=0,
            total_bytes=0,
            discarded_unsent_bytes=0,
            terminal_reason=reason,
            synthetic_origin=False,
        )


# -- CONNECT stage --------------------------------------------------------------


@pytest.mark.parametrize(
    "head,code",
    [
        (b"CONNECT cdn.example.com:444 HTTP/1.1\r\n\r\n",
         "connect_authority_port_not_443"),
        (b"CONNECT cdn.example.com:0443 HTTP/1.1\r\n\r\n",
         "connect_authority_port_not_443"),
        (b"CONNECT https://cdn.example.com:443 HTTP/1.1\r\n\r\n",
         "connect_authority_ambiguous_colons"),
        (b"CONNECT user@cdn.example.com:443 HTTP/1.1\r\n\r\n",
         "connect_authority_userinfo"),
        (b"GET cdn.example.com:443 HTTP/1.1\r\n\r\n",
         "connect_method_not_connect"),
        (b"CONNECT cdn.example.com:443 HTTP/1.0\r\n\r\n",
         "connect_version_rejected"),
        (b"CONNECT  cdn.example.com:443 HTTP/1.1\r\n\r\n",
         "connect_request_line_malformed"),
        (b"CONNECT cdn.example.com:443 HTTP/1.1\r\nGET / HTTP/1.1\r\n\r\n",
         "connect_header_malformed"),
        (b"CONNECT cdn.example.com:443 HTTP/1.1\r\n Folded: x\r\n\r\n",
         "connect_obs_fold_rejected"),
        (b"CONNECT cdn.example.com:443 HTTP/1.1\r\nBad Header: x\r\n\r\n",
         "connect_header_name_invalid"),
    ],
)
def test_serve_connect_parse_strictness(tmp_path, serve_leaf_material, head, code):
    run = _start_serve_connection(tmp_path, serve_leaf_material)
    reply = _worker_connect(run.worker_client, raw_head=head)
    assert b"200" not in reply
    record = _finish_serve_run(run)
    assert record.stage_reached is broker.HttpsConnectionStage.CONNECT
    assert record.terminal_reason is broker.HttpsConnectionTermination.DENIED
    assert record.detail == code
    assert record.accounted_bytes == 0
    assert run.serve.guard.in_flight == 0


def test_serve_authorization_denied_before_200(tmp_path, serve_leaf_material):
    run = _start_serve_connection(tmp_path, serve_leaf_material)
    reply = _worker_connect(run.worker_client, authority=OTHER_HOSTNAME)
    assert reply.startswith(b"HTTP/1.1 403")
    record = _finish_serve_run(run)
    assert record.stage_reached is broker.HttpsConnectionStage.AUTHORIZATION
    assert record.terminal_reason is broker.HttpsConnectionTermination.DENIED
    assert record.detail == "authorization_no_match"
    assert record.connect_authority == OTHER_HOSTNAME
    assert record.identity_chain == "identity_divergence:connect_authority"
    assert run.serve.guard.in_flight == 0


def test_serve_no_gate_before_connect_authorized(
    tmp_path, serve_leaf_material, monkeypatch
):
    gate_calls = []
    configure_calls = []
    real_gate = clienthello_module.run_gate_on_socket
    monkeypatch.setattr(
        clienthello_module,
        "run_gate_on_socket",
        lambda *a, **k: gate_calls.append(1) or real_gate(*a, **k),
    )
    monkeypatch.setattr(
        tls_module,
        "configure_worker_server_context",
        lambda *a, **k: configure_calls.append(1),
    )
    run = _start_serve_connection(tmp_path, serve_leaf_material)
    # A TLS record header on the wire where a CONNECT request line belongs.
    reply = _worker_connect(
        run.worker_client, raw_head=b"\x16\x03\x01\x02\x00\r\n\r\n"
    )
    assert b"200" not in reply
    record = _finish_serve_run(run)
    assert record.stage_reached is broker.HttpsConnectionStage.CONNECT
    assert record.detail == "connect_request_line_malformed"
    assert gate_calls == []
    assert configure_calls == []
    assert run.serve.guard.in_flight == 0


# -- gate and worker-TLS stages ---------------------------------------------------


def test_serve_ech_denied_after_valid_connect_zero_sni_firings(
    tmp_path, serve_leaf_material, monkeypatch
):
    configure_calls = []
    real_configure = tls_module.configure_worker_server_context
    monkeypatch.setattr(
        tls_module,
        "configure_worker_server_context",
        lambda *a, **k: configure_calls.append(1) or real_configure(*a, **k),
    )
    run = _start_serve_connection(tmp_path, serve_leaf_material)
    reply = _worker_connect(run.worker_client)
    assert reply.startswith(b"HTTP/1.1 200")
    hello = chgen.make_client_hello(SERVE_HOSTNAME.encode("ascii"), ech=True)
    run.worker_client.sendall(hello)
    # The denial closes the connection without any TLS trust established.
    run.worker_client.settimeout(5.0)
    drained = b""
    try:
        while True:
            chunk = run.worker_client.recv(65536)
            if not chunk:
                break
            drained += chunk
    except OSError:
        pass
    record = _finish_serve_run(run)
    assert record.stage_reached is broker.HttpsConnectionStage.GATE
    assert record.terminal_reason is broker.HttpsConnectionTermination.DENIED
    assert "0xfe0d" in record.detail
    assert configure_calls == [], "worker TLS configuration ran before gate accept"
    assert record.worker_tls_version is None
    assert record.worker_sni is None


def test_serve_wrong_sni_denied(tmp_path, serve_leaf_material):
    run = _start_serve_connection(tmp_path, serve_leaf_material)
    reply = _worker_connect(run.worker_client)
    assert reply.startswith(b"HTTP/1.1 200")
    with pytest.raises((ssl.SSLError, OSError)):
        _worker_tls(run.worker_client, serve_leaf_material["ca_pem"],
                    sni=OTHER_HOSTNAME)
    record = _finish_serve_run(run)
    assert record.stage_reached is broker.HttpsConnectionStage.WORKER_TLS
    assert record.detail == "worker_tls_sni_mismatch"
    assert record.worker_sni == OTHER_HOSTNAME
    assert record.identity_chain == "identity_divergence:worker_sni"
    assert record.terminal_reason is broker.HttpsConnectionTermination.DENIED


def _hrr_ch1(hostname):
    return chgen.make_client_hello(
        hostname, supported_groups=[0x001D, 0x0018], key_share_group=0x0018
    )


def test_serve_second_client_hello_aborts(tmp_path, serve_leaf_material):
    run = _start_serve_connection(tmp_path, serve_leaf_material)
    reply = _worker_connect(run.worker_client)
    assert reply.startswith(b"HTTP/1.1 200")
    sock = run.worker_client
    sock.settimeout(5.0)
    sock.sendall(_hrr_ch1(SERVE_HOSTNAME.encode("ascii")))
    # Drain the HelloRetryRequest flight.
    try:
        sock.recv(65536)
    except OSError:
        pass
    sock.sendall(chgen.make_client_hello(SERVE_HOSTNAME.encode("ascii")))
    drained = b""
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            drained += chunk
    except OSError:
        pass
    record = _finish_serve_run(run)
    assert record.stage_reached is broker.HttpsConnectionStage.WORKER_TLS
    assert record.detail == "worker_tls_second_client_hello"
    assert record.terminal_reason is broker.HttpsConnectionTermination.DENIED


def test_serve_alpn_h2_only_denied(tmp_path, serve_leaf_material):
    run = _start_serve_connection(tmp_path, serve_leaf_material)
    reply = _worker_connect(run.worker_client)
    assert reply.startswith(b"HTTP/1.1 200")
    # h2-only client: the handshake completes with no usable ALPN.
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(cadata=serve_leaf_material["ca_pem"])
    client_context.verify_mode = ssl.CERT_REQUIRED
    client_context.check_hostname = True
    client_context.set_alpn_protocols(["h2"])
    try:
        client_context.wrap_socket(run.worker_client, server_hostname=SERVE_HOSTNAME)
    except (ssl.SSLError, OSError):
        pass
    record = _finish_serve_run(run)
    assert record.stage_reached is broker.HttpsConnectionStage.WORKER_TLS
    assert record.detail == "worker_tls_alpn_rejected"
    assert record.worker_tls_version is not None


# -- HTTP prevalidation and identity chain -----------------------------------------


def _established_tls_worker(run, serve_leaf_material):
    reply = _worker_connect(run.worker_client)
    assert reply.startswith(b"HTTP/1.1 200")
    return _worker_tls(run.worker_client, serve_leaf_material["ca_pem"])


def test_serve_full_path_origin_and_evidence(tmp_path, serve_leaf_material):
    run = _start_serve_connection(tmp_path, serve_leaf_material)
    tls = _established_tls_worker(run, serve_leaf_material)
    request = f"GET /resource HTTP/1.1\r\nHost: {SERVE_HOSTNAME}\r\n\r\n".encode("ascii")
    tls.sendall(request)
    response = _read_worker_response(tls)
    assert response is not None
    assert response.startswith(b"HTTP/1.1 200 OK")
    assert response.endswith(b"hello")
    _close_tls(tls)
    record = _finish_serve_run(run)
    assert run.origin.requests == [request]
    assert record.terminal_reason is broker.HttpsConnectionTermination.COMPLETED
    assert record.stage_reached is broker.HttpsConnectionStage.HTTP
    assert record.identity_chain == "verified"
    assert record.connect_authority == SERVE_HOSTNAME
    assert record.worker_sni == SERVE_HOSTNAME
    assert record.http_host == SERVE_HOSTNAME
    assert record.origin_tls_name == SERVE_HOSTNAME
    assert record.worker_tls_version == "TLSv1.3"
    assert record.origin_tls_version == "TLSv1.3"
    assert record.worker_alpn == "http/1.1"
    assert record.origin_alpn == "http/1.1"
    assert record.origin_peer_address == "93.184.216.34"
    assert record.origin_peer_port == 443
    assert record.synthetic_origin is True
    assert record.requests_completed == 1
    assert record.worker_to_origin_bytes == len(request)
    assert record.origin_to_worker_bytes == len(response)
    assert record.total_bytes == len(request) + len(response)
    assert record.accounted_bytes == record.total_bytes + (
        record.discarded_unsent_bytes
    )


def test_serve_host_mismatch_denied_before_origin(tmp_path, serve_leaf_material):
    run = _start_serve_connection(tmp_path, serve_leaf_material)
    tls = _established_tls_worker(run, serve_leaf_material)
    tls.sendall(
        f"GET / HTTP/1.1\r\nHost: {OTHER_HOSTNAME}\r\n\r\n".encode("ascii")
    )
    # The denial tears the tunnel down without a response.
    assert _read_worker_response(tls) is None
    _close_tls(tls)
    record = _finish_serve_run(run)
    assert run.origin.requests == [], "a divergent Host reached the origin"
    assert record.stage_reached is broker.HttpsConnectionStage.HTTP
    assert record.detail == "http_host_mismatch"
    assert record.http_host == OTHER_HOSTNAME
    assert record.identity_chain == "identity_divergence:http_host"
    assert record.terminal_reason is broker.HttpsConnectionTermination.DENIED
    assert record.requests_completed == 0


def test_serve_post_denied_for_general_download(tmp_path, serve_leaf_material):
    run = _start_serve_connection(tmp_path, serve_leaf_material)
    tls = _established_tls_worker(run, serve_leaf_material)
    tls.sendall(
        f"POST /git-upload-pack HTTP/1.1\r\nHost: {SERVE_HOSTNAME}\r\n"
        "Content-Length: 4\r\n\r\n".encode("ascii") + b"body"
    )
    assert _read_worker_response(tls) is None
    _close_tls(tls)
    record = _finish_serve_run(run)
    assert run.origin.requests == []
    assert record.detail == "http_method_not_allowed"
    assert record.terminal_reason is broker.HttpsConnectionTermination.DENIED


def test_serve_post_allowed_for_git_smart_fetch(tmp_path, serve_leaf_material):
    run = _start_serve_connection(
        tmp_path, serve_leaf_material, purpose=GrantPurpose.GIT_SMART_FETCH
    )
    tls = _established_tls_worker(run, serve_leaf_material)
    request = (
        f"POST /git-upload-pack HTTP/1.1\r\nHost: {SERVE_HOSTNAME}\r\n"
        "Content-Length: 4\r\n\r\n".encode("ascii") + b"body"
    )
    tls.sendall(request)
    response = _read_worker_response(tls)
    assert response is not None and response.endswith(b"hello")
    _close_tls(tls)
    record = _finish_serve_run(run)
    assert run.origin.requests == [request]
    assert record.requests_completed == 1
    assert record.worker_to_origin_bytes == len(request)
    assert record.terminal_reason is broker.HttpsConnectionTermination.COMPLETED


def test_serve_pipelined_second_host_denied(tmp_path, serve_leaf_material):
    run = _start_serve_connection(
        tmp_path, serve_leaf_material, origin_request_count=1
    )
    tls = _established_tls_worker(run, serve_leaf_material)
    first = f"GET /one HTTP/1.1\r\nHost: {SERVE_HOSTNAME}\r\n\r\n".encode("ascii")
    second = f"GET /two HTTP/1.1\r\nHost: {OTHER_HOSTNAME}\r\n\r\n".encode("ascii")
    tls.sendall(first + second)
    response = _read_worker_response(tls)
    assert response is not None and response.endswith(b"hello")
    # The second, divergent request is never answered nor forwarded.
    assert _read_worker_response(tls) is None
    _close_tls(tls)
    record = _finish_serve_run(run)
    assert run.origin.requests == [first]
    assert record.requests_completed == 1
    assert record.detail == "http_host_mismatch"
    assert record.terminal_reason is broker.HttpsConnectionTermination.DENIED
    assert record.worker_to_origin_bytes == len(first)


def test_serve_te_cl_smuggling_denied_pre_forwarding(tmp_path, serve_leaf_material):
    run = _start_serve_connection(tmp_path, serve_leaf_material)
    tls = _established_tls_worker(run, serve_leaf_material)
    tls.sendall(
        f"GET / HTTP/1.1\r\nHost: {SERVE_HOSTNAME}\r\n"
        "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
        "0\r\n\r\n".encode("ascii")
    )
    assert _read_worker_response(tls) is None
    _close_tls(tls)
    record = _finish_serve_run(run)
    assert run.origin.requests == []
    assert record.detail == "http_te_with_content_length"
    assert record.terminal_reason is broker.HttpsConnectionTermination.DENIED


# -- limits, expiry, revocation -----------------------------------------------------


def test_serve_byte_limit_enforced_mid_relay(tmp_path, serve_leaf_material):
    request = f"GET / HTTP/1.1\r\nHost: {SERVE_HOSTNAME}\r\n\r\n".encode("ascii")
    full_response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    byte_limit = len(request) + 9
    run = _start_serve_connection(
        tmp_path, serve_leaf_material, byte_limit=byte_limit
    )
    tls = _established_tls_worker(run, serve_leaf_material)
    tls.sendall(request)
    partial = b""
    try:
        while True:
            chunk = tls.recv(4096)
            if not chunk:
                break
            partial += chunk
    except (ssl.SSLError, OSError):
        pass
    _close_tls(tls)
    record = _finish_serve_run(run)
    assert record.terminal_reason is broker.HttpsConnectionTermination.BYTE_LIMIT
    assert record.accounted_bytes == byte_limit
    assert record.worker_to_origin_bytes == len(request)
    assert record.origin_to_worker_bytes == len(partial)
    assert len(partial) < len(full_response)


def test_serve_expiry_mid_relay_discards_buffered_bytes(
    tmp_path, serve_leaf_material
):
    run = _start_serve_connection(
        tmp_path,
        serve_leaf_material,
        lifetime_ns=1_500_000_000,
    )
    tls = _established_tls_worker(run, serve_leaf_material)
    request = f"GET / HTTP/1.1\r\nHost: {SERVE_HOSTNAME}\r\n\r\n".encode("ascii")
    tls.sendall(request)
    assert _read_worker_response(tls) is not None
    # A partial second request is read but never completed or forwarded;
    # expiry must account it as discarded, never as forwarded bytes.
    partial = b"GET /partial HTTP/1.1"
    tls.sendall(partial)
    time.sleep(2.0)
    _close_tls(tls)
    record = _finish_serve_run(run)
    assert record.terminal_reason is broker.HttpsConnectionTermination.EXPIRED
    assert record.discarded_unsent_bytes == len(partial)
    assert record.accounted_bytes == record.total_bytes + len(partial)
    assert record.worker_to_origin_bytes == len(request)
    assert run.origin.requests == [request]


def _dup_cloexec_fd(fd):
    import fcntl as _fcntl

    return _fcntl.fcntl(fd, _fcntl.F_DUPFD_CLOEXEC, 100)


def _start_serve_transport_thread(
    tmp_path,
    serve_leaf_material,
    *,
    connection_limit=1,
    byte_limit=1 << 20,
    lifetime_ns=None,
    origin_responder=None,
    origin_request_count=1,
    fixture_addresses=("93.184.216.34",),
):
    """Run serve_https_transport on a real listener with the fixture armed
    through the authenticated control message (the runner's delivery path)."""
    policy = _serve_policy(
        connection_limit=connection_limit,
        byte_limit=byte_limit,
        lifetime_ns=lifetime_ns,
    )
    network_policy = _serve_network_policy(policy)
    https_state = _serve_https_state(
        network_policy, serve_leaf_material["context"]
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # The broker's listener contract forbids SO_REUSEADDR; retry briefly to
    # ride out a previous test's TIME_WAIT on the fixed port instead.
    bind_deadline = time.monotonic() + 10.0
    while True:
        try:
            listener.bind(("127.0.0.1", 18080))
            break
        except OSError:
            if time.monotonic() >= bind_deadline:
                raise
            time.sleep(0.1)
    listener.listen(4)
    control_broker, control_peer = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET
    )
    pems = _origin_pems()
    origin_server = _ScriptedOrigin(
        tmp_path,
        pems,
        origin_responder or _ok_responder(),
        request_count=origin_request_count,
    )
    owned = (
        _dup_cloexec_fd(listener.fileno()),
        _dup_cloexec_fd(control_broker.fileno()),
    )
    outcomes = []

    def run():
        try:
            outcomes.append(
                broker.serve_https_transport(
                    policy, https_state,
                    listener_fd=owned[0], control_fd=owned[1],
                )
            )
        except BaseException as exc:  # noqa: BLE001
            outcomes.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    payload = broker.CONTROL_HTTPS_FIXTURE + json.dumps(
        {
            "version": broker.HTTPS_FIXTURE_VERSION,
            "ca_certs_pem": pems["ca"].decode("ascii"),
            "addresses": list(fixture_addresses),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    control_peer.sendmsg(
        [payload],
        [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
          array.array("i", [origin_server.fd]))],
    )
    return types.SimpleNamespace(
        thread=thread,
        outcomes=outcomes,
        listener=listener,
        control_broker=control_broker,
        control_peer=control_peer,
        origin=origin_server,
        owned=owned,
        policy=policy,
    )


def _cleanup_serve_transport(serve):
    serve.origin.close()
    serve.listener.close()
    serve.control_broker.close()
    serve.control_peer.close()
    for fd in serve.owned:
        try:
            os.close(fd)
        except OSError:
            pass


def _tcp_worker():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    sock.connect(("127.0.0.1", 18080))
    return sock


def _read_evidence_packets(control_peer, count):
    packets = []
    control_peer.settimeout(10.0)
    for _ in range(count):
        packets.append(control_peer.recv(broker.MAX_HTTPS_EVIDENCE_BYTES + 1))
    return packets


def _join_serve_transport(serve):
    serve.thread.join(15.0)
    assert not serve.thread.is_alive()
    assert len(serve.outcomes) == 1
    terminal = serve.outcomes[0]
    assert type(terminal) is broker.HttpsTransportTerminal, terminal
    return terminal


def test_serve_revoke_mid_connection_tears_down(tmp_path, serve_leaf_material):
    serve = _start_serve_transport_thread(
        tmp_path, serve_leaf_material, origin_responder=_slow_responder(10.0)
    )
    try:
        worker = _tcp_worker()
        reply = _worker_connect(worker)
        assert reply.startswith(b"HTTP/1.1 200")
        tls = _worker_tls(worker, serve_leaf_material["ca_pem"])
        tls.sendall(
            f"GET / HTTP/1.1\r\nHost: {SERVE_HOSTNAME}\r\n\r\n".encode("ascii")
        )
        serve.control_peer.send(broker.CONTROL_REVOKE)
        packets = _read_evidence_packets(serve.control_peer, 1)
        terminal = _join_serve_transport(serve)
        assert terminal.terminal_reason is broker.TransportTermination.REVOKED
        assert terminal.connection_count == 1
        record = broker.HttpsConnectionRecord.from_bytes(packets[0])
        assert record.terminal_reason is broker.HttpsConnectionTermination.REVOKED
        assert terminal.synthetic_origin is True
        try:
            tail = tls.recv(4096)
            assert tail == b""
        except (ssl.SSLError, OSError):
            pass
    finally:
        _cleanup_serve_transport(serve)


def test_serve_expiry_closes_listener_and_connections(
    tmp_path, serve_leaf_material
):
    serve = _start_serve_transport_thread(
        tmp_path,
        serve_leaf_material,
        lifetime_ns=2_000_000_000,
        origin_responder=_slow_responder(10.0),
    )
    try:
        worker = _tcp_worker()
        reply = _worker_connect(worker)
        assert reply.startswith(b"HTTP/1.1 200")
        tls = _worker_tls(worker, serve_leaf_material["ca_pem"])
        tls.sendall(
            f"GET / HTTP/1.1\r\nHost: {SERVE_HOSTNAME}\r\n\r\n".encode("ascii")
        )
        packets = _read_evidence_packets(serve.control_peer, 1)
        terminal = _join_serve_transport(serve)
        assert terminal.terminal_reason is broker.TransportTermination.EXPIRED
        assert terminal.observed_at_monotonic_ns >= (
            serve.policy.expires_at_monotonic_ns
        )
        record = broker.HttpsConnectionRecord.from_bytes(packets[0])
        assert record.terminal_reason is broker.HttpsConnectionTermination.EXPIRED
        assert terminal.accounted_bytes == (
            terminal.total_bytes + terminal.discarded_unsent_bytes
        )
    finally:
        _cleanup_serve_transport(serve)


def test_serve_connection_limit_terminates(tmp_path, serve_leaf_material):
    serve = _start_serve_transport_thread(
        tmp_path, serve_leaf_material, connection_limit=1
    )
    try:
        first = _tcp_worker()
        second = _tcp_worker()
        second.settimeout(5.0)
        # The over-limit connection is aborted and the broker terminates.
        try:
            assert second.recv(64) == b""
        except OSError:
            pass
        packets = _read_evidence_packets(serve.control_peer, 1)
        terminal = _join_serve_transport(serve)
        assert (
            terminal.terminal_reason
            is broker.TransportTermination.CONNECTION_LIMIT
        )
        assert terminal.connection_count == 1
        first.close()
    finally:
        _cleanup_serve_transport(serve)


# -- fixture control-message validation ----------------------------------------------


def _fixture_control_serve(tmp_path, serve_leaf_material):
    policy = _serve_policy()
    network_policy = _serve_network_policy(policy)
    https_state = _serve_https_state(
        network_policy, serve_leaf_material["context"]
    )
    control_broker, control_peer = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET
    )
    serve = broker._HttpsServeState(policy, https_state, control_broker.fileno())
    return serve, control_broker, control_peer


def _send_fixture_message(control_peer, payload, fds=()):
    ancillary = []
    if fds:
        ancillary = [
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", list(fds)))
        ]
    control_peer.sendmsg([payload], ancillary)


def test_https_fixture_control_message_arming_and_validation(
    tmp_path, serve_leaf_material
):
    serve, control_broker, control_peer = _fixture_control_serve(
        tmp_path, serve_leaf_material
    )
    pems = _origin_pems()
    good_fd, keep = socket.socketpair()
    payload = broker.CONTROL_HTTPS_FIXTURE + json.dumps(
        {
            "version": broker.HTTPS_FIXTURE_VERSION,
            "ca_certs_pem": pems["ca"].decode("ascii"),
            "addresses": ["93.184.216.34"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    # A fixture message without its descriptor is malformed.
    _send_fixture_message(control_peer, payload)
    assert broker._read_https_control(control_broker, serve) is (
        broker.TransportTermination.MALFORMED_CONTROL
    )
    # A valid message arms the fixture exactly once.
    _send_fixture_message(control_peer, payload, fds=(good_fd.fileno(),))
    assert broker._read_https_control(control_broker, serve) is None
    assert serve.fixture is not None
    assert serve.fixture.addresses == ("93.184.216.34",)
    # A second fixture message is malformed.
    _send_fixture_message(control_peer, payload, fds=(good_fd.fileno(),))
    assert broker._read_https_control(control_broker, serve) is (
        broker.TransportTermination.MALFORMED_CONTROL
    )
    # REVOKE remains intact on the extended control reader.
    control_peer.send(broker.CONTROL_REVOKE)
    assert broker._read_https_control(control_broker, serve) is (
        broker.TransportTermination.REVOKED
    )
    serve.fixture = None
    keep.close()
    good_fd.close()
    control_broker.close()
    control_peer.close()


@pytest.mark.parametrize(
    "document",
    [
        {"version": "AOSHTTPSFIX/2", "ca_certs_pem": "x",
         "addresses": ["93.184.216.34"]},
        {"version": "AOSHTTPSFIX/1", "ca_certs_pem": "",
         "addresses": ["93.184.216.34"]},
        {"version": "AOSHTTPSFIX/1", "ca_certs_pem": "x", "addresses": []},
        {"version": "AOSHTTPSFIX/1", "ca_certs_pem": "x",
         "addresses": ["999.1.1.1"]},
        {"version": "AOSHTTPSFIX/1", "ca_certs_pem": "x",
         "addresses": ["93.184.216.34"], "extra": 1},
    ],
)
def test_https_fixture_payload_rejected(tmp_path, serve_leaf_material, document):
    serve, control_broker, control_peer = _fixture_control_serve(
        tmp_path, serve_leaf_material
    )
    good_fd, keep = socket.socketpair()
    payload = broker.CONTROL_HTTPS_FIXTURE + json.dumps(
        document, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    _send_fixture_message(control_peer, payload, fds=(good_fd.fileno(),))
    assert broker._read_https_control(control_broker, serve) is (
        broker.TransportTermination.MALFORMED_CONTROL
    )
    assert serve.fixture is None
    keep.close()
    good_fd.close()
    control_broker.close()
    control_peer.close()


# -- runner-side HTTPS evidence reader -----------------------------------------------


def test_https_evidence_reader_authenticates_records(tmp_path):
    policy = _serve_policy(connection_limit=4)
    network_policy = _serve_network_policy(policy)
    control_broker, control_peer = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET
    )
    record = broker.HttpsConnectionRecord(
        **_connection_record_kwargs(
            policy_digest=policy_digest(policy),
            network_policy_digest=network_policy_digest(network_policy),
        )
    )
    terminal = broker.HttpsTransportTerminal(
        version=broker.HTTPS_EVIDENCE_VERSION,
        event=broker.HTTPS_TERMINAL_EVENT,
        task_id=policy.task_id,
        task_generation=policy.task_generation,
        launch_nonce=policy.launch_nonce,
        policy_digest=policy_digest(policy),
        network_policy_digest=network_policy_digest(network_policy),
        observed_at_monotonic_ns=time.monotonic_ns(),
        connection_count=1,
        accounted_bytes=84,
        worker_to_origin_bytes=41,
        origin_to_worker_bytes=43,
        total_bytes=84,
        discarded_unsent_bytes=0,
        terminal_reason=broker.TransportTermination.REVOKED,
        synthetic_origin=True,
    )
    broker._emit_https_packet(control_broker.fileno(), record.to_bytes(), final=False)
    broker._emit_https_packet(control_broker.fileno(), terminal.to_bytes(), final=True)
    read_terminal, records, broker_emitted = (
        runner_module._read_authenticated_https_transport_records(
            control_peer.fileno(),
            expected_policy=policy,
            expected_network_policy_digest=network_policy_digest(network_policy),
            expect_synthetic=True,
            budget=5.0,
        )
    )
    assert read_terminal == terminal
    assert records == (record,)
    assert broker_emitted is True
    control_broker.close()
    control_peer.close()


def test_https_evidence_reader_synthesizes_after_worker_exit_reap(tmp_path):
    """Clean worker exit reaps the broker: records + EOF, no terminal packet."""
    policy = _serve_policy(connection_limit=4)
    network_policy = _serve_network_policy(policy)
    control_broker, control_peer = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET
    )
    record = broker.HttpsConnectionRecord(
        **_connection_record_kwargs(
            policy_digest=policy_digest(policy),
            network_policy_digest=network_policy_digest(network_policy),
            synthetic_origin=False,
        )
    )
    # The eager record lands while the worker lives; the broker is then
    # reaped (close without any terminal packet or shutdown).
    broker._emit_https_packet(control_broker.fileno(), record.to_bytes(), final=False)
    control_broker.close()
    read_terminal, records, broker_emitted = (
        runner_module._read_authenticated_https_transport_records(
            control_peer.fileno(),
            expected_policy=policy,
            expected_network_policy_digest=network_policy_digest(network_policy),
            expect_synthetic=False,
            budget=5.0,
        )
    )
    assert broker_emitted is False
    assert records == (record,)
    assert read_terminal.terminal_reason is broker.TransportTermination.REVOKED
    assert read_terminal.connection_count == 1
    assert read_terminal.accounted_bytes == record.accounted_bytes
    assert read_terminal.total_bytes == record.total_bytes
    assert read_terminal.discarded_unsent_bytes == (
        record.discarded_unsent_bytes
    )
    assert read_terminal.synthetic_origin is False
    control_peer.close()


def test_https_evidence_reader_rejects_wrong_authority(tmp_path):
    policy = _serve_policy(connection_limit=4)
    network_policy = _serve_network_policy(policy)
    control_broker, control_peer = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET
    )
    terminal = broker.HttpsTransportTerminal(
        version=broker.HTTPS_EVIDENCE_VERSION,
        event=broker.HTTPS_TERMINAL_EVENT,
        task_id=policy.task_id,
        task_generation=policy.task_generation,
        launch_nonce=policy.launch_nonce,
        policy_digest=policy_digest(policy),
        network_policy_digest="00" * 32,  # not the sealed network policy
        observed_at_monotonic_ns=time.monotonic_ns(),
        connection_count=0,
        accounted_bytes=0,
        worker_to_origin_bytes=0,
        origin_to_worker_bytes=0,
        total_bytes=0,
        discarded_unsent_bytes=0,
        terminal_reason=broker.TransportTermination.REVOKED,
        synthetic_origin=False,
    )
    broker._emit_https_packet(control_broker.fileno(), terminal.to_bytes(), final=True)
    with pytest.raises(runner_module.CapabilityTransportError):
        runner_module._read_authenticated_https_transport_records(
            control_peer.fileno(),
            expected_policy=policy,
            expected_network_policy_digest=network_policy_digest(network_policy),
            expect_synthetic=False,
            budget=5.0,
        )
    control_broker.close()
    control_peer.close()


def test_https_evidence_reader_rejects_record_after_terminal(tmp_path):
    policy = _serve_policy(connection_limit=4)
    network_policy = _serve_network_policy(policy)
    control_broker, control_peer = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET
    )
    kwargs = _connection_record_kwargs(
        policy_digest=policy_digest(policy),
        network_policy_digest=network_policy_digest(network_policy),
    )
    terminal = broker.HttpsTransportTerminal(
        version=broker.HTTPS_EVIDENCE_VERSION,
        event=broker.HTTPS_TERMINAL_EVENT,
        task_id=policy.task_id,
        task_generation=policy.task_generation,
        launch_nonce=policy.launch_nonce,
        policy_digest=policy_digest(policy),
        network_policy_digest=network_policy_digest(network_policy),
        observed_at_monotonic_ns=time.monotonic_ns(),
        connection_count=0,
        accounted_bytes=0,
        worker_to_origin_bytes=0,
        origin_to_worker_bytes=0,
        total_bytes=0,
        discarded_unsent_bytes=0,
        terminal_reason=broker.TransportTermination.REVOKED,
        synthetic_origin=True,
    )
    broker._emit_https_packet(control_broker.fileno(), terminal.to_bytes(), final=False)
    broker._emit_https_packet(
        control_broker.fileno(),
        broker.HttpsConnectionRecord(**kwargs).to_bytes(),
        final=True,
    )
    with pytest.raises(runner_module.CapabilityTransportError):
        runner_module._read_authenticated_https_transport_records(
            control_peer.fileno(),
            expected_policy=policy,
            expected_network_policy_digest=network_policy_digest(network_policy),
            expect_synthetic=True,
            budget=5.0,
        )
    control_broker.close()
    control_peer.close()
