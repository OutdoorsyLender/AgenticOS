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
