"""Unit tests for the M4B network capability transport contract."""

from __future__ import annotations

import array
import contextlib
import dataclasses
import errno
import fcntl
import hashlib
import importlib
import importlib.util
import json
import os
import select
import socket
import stat
import tempfile
import threading

import pytest


MODULE = "agenticos.sandbox.network_models"
IDENTITY_MODULE = "agenticos.sandbox.network_identity"


def _network_models():
    """Load the public contract, producing a test failure until it exists."""
    try:
        return importlib.import_module(MODULE)
    except ModuleNotFoundError as exc:
        pytest.fail(f"M4B transport contract is missing: {exc}")


def _network_identity():
    """Load the identity boundary, producing RED until Task 2 exists."""
    try:
        return importlib.import_module(IDENTITY_MODULE)
    except ModuleNotFoundError as exc:
        pytest.fail(f"M4B network identity boundary is missing: {exc}")


def _valid_policy(models):
    return models.TransportPolicy(
        version="AOSNET/1",
        task_id="task-7",
        task_generation=3,
        launch_nonce="ab" * 16,
        mode=models.TransportMode.SYNTHETIC_FIXTURE_FD,
        proxy_host="127.0.0.1",
        proxy_port=18080,
        activated_at_monotonic_ns=100,
        expires_at_monotonic_ns=200,
        connection_limit=4,
        byte_limit=8192,
    )


def _valid_listener(models):
    return models.ListenerEvidence(
        family=2,
        socket_type=1,
        address="127.0.0.1",
        port=18080,
        device=10,
        inode=20,
        file_type=49152,
        netns_cookie=30,
        accepting=True,
    )


def _valid_process(models):
    return models.BrokerProcessEvidence(
        pid=1234,
        start_time_ticks=5678,
        boot_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    )


def _valid_ready(models):
    return models.BrokerReadyEvidence(
        task_id="task-7",
        task_generation=3,
        launch_nonce="ab" * 16,
        policy_digest="c" * 64,
        broker_pid=1234,
        broker_start_time_ticks=5678,
        broker_boot_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        ready_at_monotonic_ns=150,
    )


@contextlib.contextmanager
def _fixed_listener():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    try:
        listener.bind(("127.0.0.1", 18080))
        listener.listen(4)
        yield listener
    finally:
        listener.close()


def _valid_adoption_frame(identity, models, listener):
    return identity.ListenerAdoptionFrame(
        version="AOSLISTENER/1",
        task_id="task-7",
        task_generation=3,
        launch_nonce="ab" * 16,
        policy_digest="c" * 64,
        evidence=identity.listener_evidence(listener.fileno()),
    )


def _sealed_payload_fd(payload: bytes, seals: int) -> int:
    fd = os.memfd_create(
        "aos-network-policy-test", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    )
    try:
        assert os.write(fd, payload) == len(payload)
        if seals:
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _send_raw(channel, payload: bytes, fds=()):
    ancillary = []
    if fds:
        ancillary.append(
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds).tobytes())
        )
    return channel.sendmsg([payload], ancillary)


def _open_fd_numbers() -> set[int]:
    return {int(name) for name in os.listdir("/proc/self/fd")}


def test_network_models_module_exists():
    assert importlib.util.find_spec(MODULE) is not None


def test_policy_canonicalization_is_sorted_compact_and_binds_every_field():
    models = _network_models()
    policy = _valid_policy(models)

    expected = (
        b'{"activated_at_monotonic_ns":100,"byte_limit":8192,'
        b'"connection_limit":4,"expires_at_monotonic_ns":200,'
        b'"launch_nonce":"abababababababababababababababab",'
        b'"mode":"SYNTHETIC_FIXTURE_FD","proxy_host":"127.0.0.1",'
        b'"proxy_port":18080,"task_generation":3,"task_id":"task-7",'
        b'"version":"AOSNET/1"}'
    )

    canonical = models.canonical_policy_bytes(policy)
    assert canonical == expected
    assert canonical == models.canonical_policy_bytes(_valid_policy(models))
    assert b"/home/agent" not in canonical
    assert b'"proxy_port":18080,' in canonical
    assert all(not field.endswith("_fd") for field in json.loads(canonical))
    assert models.policy_digest(policy) == hashlib.sha256(expected).hexdigest()
    assert models.policy_digest(policy).isascii()
    assert len(models.policy_digest(policy)) == 64
    assert models.policy_digest(policy) == models.policy_digest(policy).lower()


@pytest.mark.parametrize(
    "replacement",
    [
        {"task_id": "task-8"},
        {"task_generation": 4},
        {"launch_nonce": "cd" * 16},
        {"mode": "DENY"},
        {"activated_at_monotonic_ns": 101},
        {"expires_at_monotonic_ns": 201},
        {"connection_limit": 5},
        {"byte_limit": 8193},
    ],
)
def test_policy_digest_changes_when_each_mutable_field_changes(replacement):
    models = _network_models()
    policy = _valid_policy(models)
    if "mode" in replacement:
        replacement = {**replacement, "mode": models.TransportMode(replacement["mode"])}
    changed = dataclasses.replace(policy, **replacement)

    assert models.policy_digest(changed) != models.policy_digest(policy)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", "AOSNET/2"),
        ("task_id", ""),
        ("task_id", "x" * 129),
        ("task_generation", 0),
        ("task_generation", True),
        ("launch_nonce", "AB" * 16),
        ("launch_nonce", "ab" * 15),
        ("mode", "ALLOW"),
        ("proxy_host", "0.0.0.0"),
        ("proxy_host", "::1"),
        ("proxy_port", 443),
        ("activated_at_monotonic_ns", 0),
        ("expires_at_monotonic_ns", 100),
        ("connection_limit", 0),
        ("byte_limit", -1),
    ],
)
def test_transport_policy_rejects_invalid_or_unbounded_values(field, value):
    models = _network_models()
    values = dataclasses.asdict(_valid_policy(models))
    values["mode"] = models.TransportMode(values["mode"])
    values[field] = value

    with pytest.raises((TypeError, ValueError)):
        models.TransportPolicy(**values)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("proxy_host", b"127.0.0.1"),
        ("proxy_port", 18080.0),
        ("proxy_port", True),
        ("task_generation", 3.0),
        ("task_generation", True),
        ("activated_at_monotonic_ns", 100.0),
        ("activated_at_monotonic_ns", True),
        ("expires_at_monotonic_ns", 200.0),
        ("expires_at_monotonic_ns", True),
        ("connection_limit", 4.0),
        ("connection_limit", True),
        ("byte_limit", 8192.0),
        ("byte_limit", True),
    ],
)
def test_transport_policy_rejects_type_confusable_primitives(field, value):
    models = _network_models()
    values = dataclasses.asdict(_valid_policy(models))
    values["mode"] = models.TransportMode(values["mode"])
    values[field] = value

    with pytest.raises((TypeError, ValueError)):
        models.TransportPolicy(**values)


def test_transport_policy_rejects_unknown_fields_and_does_not_accept_listener_variants():
    models = _network_models()
    values = dataclasses.asdict(_valid_policy(models))
    values["mode"] = models.TransportMode(values["mode"])
    values["host_locator"] = "/host/private/proxy.sock"

    with pytest.raises(TypeError):
        models.TransportPolicy(**values)


def test_transport_mode_has_exactly_the_two_contract_members():
    models = _network_models()

    assert list(models.TransportMode) == [
        models.TransportMode.DENY,
        models.TransportMode.SYNTHETIC_FIXTURE_FD,
    ]
    assert models.TransportMode.DENY.value == "DENY"
    assert models.TransportMode.SYNTHETIC_FIXTURE_FD.value == "SYNTHETIC_FIXTURE_FD"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("family", 0),
        ("family", True),
        ("family", 2.0),
        ("family", (1 << 64)),
        ("socket_type", 0),
        ("socket_type", True),
        ("socket_type", 1.0),
        ("socket_type", (1 << 64)),
        ("address", "localhost"),
        ("address", "x" * 46),
        ("address", True),
        ("port", 0),
        ("port", 65536),
        ("port", True),
        ("port", 18080.0),
        ("device", 0),
        ("device", True),
        ("device", 10.0),
        ("device", (1 << 64)),
        ("inode", 0),
        ("inode", True),
        ("inode", 20.0),
        ("inode", (1 << 64)),
        ("file_type", 0),
        ("file_type", True),
        ("file_type", 49152.0),
        ("file_type", (1 << 64)),
        ("netns_cookie", 0),
        ("netns_cookie", True),
        ("netns_cookie", 30.0),
        ("netns_cookie", (1 << 64)),
        ("accepting", 1),
        ("accepting", "true"),
    ],
)
def test_listener_evidence_rejects_invalid_field_boundaries_and_types(field, value):
    models = _network_models()

    with pytest.raises((TypeError, ValueError)):
        dataclasses.replace(_valid_listener(models), **{field: value})


def test_transport_contract_dataclasses_are_frozen_and_have_only_public_fields():
    models = _network_models()
    policy = _valid_policy(models)
    listener = _valid_listener(models)

    assert [field.name for field in dataclasses.fields(models.TransportPolicy)] == [
        "version",
        "task_id",
        "task_generation",
        "launch_nonce",
        "mode",
        "proxy_host",
        "proxy_port",
        "activated_at_monotonic_ns",
        "expires_at_monotonic_ns",
        "connection_limit",
        "byte_limit",
    ]
    assert [field.name for field in dataclasses.fields(models.ListenerEvidence)] == [
        "family",
        "socket_type",
        "address",
        "port",
        "device",
        "inode",
        "file_type",
        "netns_cookie",
        "accepting",
    ]
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.byte_limit = 1
    with pytest.raises(dataclasses.FrozenInstanceError):
        listener.accepting = False


@pytest.mark.parametrize(
    "boot_id",
    [
        "\x1f" + "a" * 35,
        "\x7f" + "a" * 35,
        "\u0085" + "a" * 35,
        "😀" * 128,
        "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
        "a" * 36,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaaa",
    ],
)
def test_broker_evidence_rejects_noncanonical_boot_ids(boot_id):
    models = _network_models()

    with pytest.raises((TypeError, ValueError)):
        dataclasses.replace(_valid_process(models), boot_id=boot_id)
    with pytest.raises((TypeError, ValueError)):
        dataclasses.replace(_valid_ready(models), broker_boot_id=boot_id)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("pid", 0),
        ("pid", True),
        ("pid", 1234.0),
        ("pid", (1 << 64)),
        ("start_time_ticks", 0),
        ("start_time_ticks", True),
        ("start_time_ticks", 5678.0),
        ("start_time_ticks", (1 << 64)),
    ],
)
def test_broker_process_evidence_rejects_invalid_field_boundaries_and_types(field, value):
    models = _network_models()

    with pytest.raises((TypeError, ValueError)):
        dataclasses.replace(_valid_process(models), **{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("task_id", ""),
        ("task_id", "x" * 129),
        ("task_id", True),
        ("task_generation", 0),
        ("task_generation", True),
        ("task_generation", 3.0),
        ("launch_nonce", "AB" * 16),
        ("launch_nonce", "ab" * 15),
        ("policy_digest", "C" * 64),
        ("policy_digest", "c" * 63),
        ("broker_pid", 0),
        ("broker_pid", True),
        ("broker_pid", 1234.0),
        ("broker_start_time_ticks", 0),
        ("broker_start_time_ticks", True),
        ("broker_start_time_ticks", 5678.0),
        ("ready_at_monotonic_ns", 0),
        ("ready_at_monotonic_ns", True),
        ("ready_at_monotonic_ns", 150.0),
    ],
)
def test_broker_ready_evidence_rejects_invalid_field_boundaries_and_types(field, value):
    models = _network_models()

    with pytest.raises((TypeError, ValueError)):
        dataclasses.replace(_valid_ready(models), **{field: value})


def test_lifecycle_evidence_is_frozen_and_contains_only_explicit_fields():
    models = _network_models()
    process = _valid_process(models)
    ready = _valid_ready(models)

    assert [field.name for field in dataclasses.fields(models.BrokerProcessEvidence)] == [
        "pid",
        "start_time_ticks",
        "boot_id",
    ]
    assert [field.name for field in dataclasses.fields(models.BrokerReadyEvidence)] == [
        "task_id",
        "task_generation",
        "launch_nonce",
        "policy_digest",
        "broker_pid",
        "broker_start_time_ticks",
        "broker_boot_id",
        "ready_at_monotonic_ns",
    ]
    with pytest.raises(dataclasses.FrozenInstanceError):
        process.pid = 1
    with pytest.raises(dataclasses.FrozenInstanceError):
        ready.ready_at_monotonic_ns = 1


def test_sandbox_package_exports_m4b_transport_contract():
    import agenticos.sandbox as sandbox

    models = _network_models()
    for name in (
        "TransportMode",
        "TransportPolicy",
        "ListenerEvidence",
        "BrokerProcessEvidence",
        "BrokerReadyEvidence",
        "canonical_policy_bytes",
        "policy_digest",
    ):
        assert getattr(sandbox, name) is getattr(models, name)


def test_policy_memfd_is_fully_sealed_round_trips_and_rejects_writes():
    identity = _network_identity()
    models = _network_models()
    policy = _valid_policy(models)

    fd = identity.create_sealed_policy_fd(policy)
    try:
        required = (
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL
        )
        assert fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) & required == required
        assert os.lseek(fd, 0, os.SEEK_CUR) == 0
        with pytest.raises(OSError):
            os.write(fd, b"x")
        with pytest.raises(OSError):
            os.pwrite(fd, b"x", 0)

        verified = identity.read_sealed_policy_fd(fd)
        assert verified.policy == policy
        assert verified.digest == models.policy_digest(policy)
        assert verified.size == len(models.canonical_policy_bytes(policy))
        assert verified.seals & required == required
        assert verified.device > 0
        assert verified.inode > 0
        with pytest.raises(dataclasses.FrozenInstanceError):
            verified.digest = "0" * 64
    finally:
        os.close(fd)


@pytest.mark.parametrize(
    "seals",
    [
        0,
        fcntl.F_SEAL_WRITE,
        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK,
    ],
)
def test_read_sealed_policy_rejects_missing_or_partial_seals(seals):
    identity = _network_identity()
    models = _network_models()
    fd = _sealed_payload_fd(models.canonical_policy_bytes(_valid_policy(models)), seals)
    try:
        with pytest.raises(identity.NetworkIdentityError):
            identity.read_sealed_policy_fd(fd)
    finally:
        os.close(fd)


def test_read_sealed_policy_rejects_mutable_ordinary_fd_substitution():
    identity = _network_identity()
    models = _network_models()
    with tempfile.TemporaryFile() as ordinary:
        ordinary.write(models.canonical_policy_bytes(_valid_policy(models)))
        ordinary.flush()
        ordinary.seek(0)

        with pytest.raises(identity.NetworkIdentityError):
            identity.read_sealed_policy_fd(ordinary.fileno())


@pytest.mark.parametrize(
    "payload_factory",
    [
        lambda canonical: b"{" + canonical[1:-1] + b',"task_id":"task-8"}',
        lambda canonical: canonical[:-1] + b',"unknown":1}',
        lambda canonical: canonical.replace(b'"task_id":"task-7",', b""),
        lambda canonical: canonical.replace(b'"task_generation":3', b'"task_generation":true'),
        lambda canonical: b"{" + canonical[1:-1] + b",}",
        lambda canonical: b" " + canonical,
        lambda canonical: canonical + b"\n",
        lambda canonical: canonical.replace(b"task-7", b"task-\\u0037"),
    ],
    ids=[
        "duplicate-key",
        "unknown-field",
        "missing-field",
        "wrong-type",
        "malformed-json",
        "leading-space",
        "trailing-data",
        "noncanonical-escape",
    ],
)
def test_read_sealed_policy_rejects_malformed_or_noncanonical_json(payload_factory):
    identity = _network_identity()
    models = _network_models()
    canonical = models.canonical_policy_bytes(_valid_policy(models))
    required = (
        fcntl.F_SEAL_WRITE
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_SEAL
    )
    fd = _sealed_payload_fd(payload_factory(canonical), required)
    try:
        with pytest.raises(identity.NetworkIdentityError):
            identity.read_sealed_policy_fd(fd)
    finally:
        os.close(fd)


def test_read_sealed_policy_rejects_oversized_payload():
    identity = _network_identity()
    required = (
        fcntl.F_SEAL_WRITE
        | fcntl.F_SEAL_GROW
        | fcntl.F_SEAL_SHRINK
        | fcntl.F_SEAL_SEAL
    )
    fd = _sealed_payload_fd(b"x" * 65_537, required)
    try:
        with pytest.raises(identity.NetworkIdentityError):
            identity.read_sealed_policy_fd(fd)
    finally:
        os.close(fd)


def test_listener_evidence_records_exact_listening_socket_kernel_identity():
    identity = _network_identity()
    with _fixed_listener() as listener:
        evidence = identity.listener_evidence(listener.fileno())
        observed = os.fstat(listener.fileno())

        assert evidence.family == socket.AF_INET
        assert evidence.socket_type == socket.SOCK_STREAM
        assert evidence.address == "127.0.0.1"
        assert evidence.port == 18080
        assert evidence.device == observed.st_dev
        assert evidence.inode == observed.st_ino
        assert evidence.file_type == stat.S_IFSOCK
        assert evidence.netns_cookie > 0
        assert evidence.accepting is True


def test_listener_evidence_uses_a_cloexec_duplicate_without_consuming_the_fd():
    identity = _network_identity()
    with _fixed_listener() as listener:
        before = os.fstat(listener.fileno())
        identity.listener_evidence(listener.fileno())
        after = os.fstat(listener.fileno())

        assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
        assert fcntl.fcntl(listener.fileno(), fcntl.F_GETFD) & fcntl.FD_CLOEXEC


def test_listener_evidence_rejects_wrong_family_type_address_port_state_and_file_type():
    identity = _network_identity()
    with contextlib.ExitStack() as stack:
        unix_listener = stack.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
        unix_listener.bind("\0aos-m4b-listener-test")
        unix_listener.listen(1)
        with pytest.raises(identity.NetworkIdentityError):
            identity.listener_evidence(unix_listener.fileno())

        datagram = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        datagram.bind(("127.0.0.1", 18080))
        with pytest.raises(identity.NetworkIdentityError):
            identity.listener_evidence(datagram.fileno())

        any_address = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        any_address.bind(("0.0.0.0", 18080))
        any_address.listen(1)
        with pytest.raises(identity.NetworkIdentityError):
            identity.listener_evidence(any_address.fileno())
        any_address.close()

        wrong_port = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        wrong_port.bind(("127.0.0.1", 0))
        wrong_port.listen(1)
        with pytest.raises(identity.NetworkIdentityError):
            identity.listener_evidence(wrong_port.fileno())

        not_listening = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        not_listening.bind(("127.0.0.1", 18080))
        with pytest.raises(identity.NetworkIdentityError):
            identity.listener_evidence(not_listening.fileno())

        ordinary = stack.enter_context(tempfile.TemporaryFile())
        with pytest.raises(identity.NetworkIdentityError):
            identity.listener_evidence(ordinary.fileno())


def test_listener_adoption_frame_is_frozen_bounded_and_canonical():
    identity = _network_identity()
    models = _network_models()
    with _fixed_listener() as listener:
        frame = _valid_adoption_frame(identity, models, listener)
        payload = frame.to_bytes()

        assert payload == json.dumps(
            {
                "evidence": dataclasses.asdict(frame.evidence),
                "launch_nonce": "ab" * 16,
                "policy_digest": "c" * 64,
                "task_generation": 3,
                "task_id": "task-7",
                "version": "AOSLISTENER/1",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        assert identity.ListenerAdoptionFrame.from_bytes(payload) == frame
        assert len(payload) < 2048
        with pytest.raises(dataclasses.FrozenInstanceError):
            frame.policy_digest = "d" * 64


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", "AOSLISTENER/2"),
        ("task_id", "bad\ncontrol"),
        ("task_id", "\u00e9" * 128),
        ("task_generation", True),
        ("task_generation", 0),
        ("launch_nonce", "AB" * 16),
        ("policy_digest", "C" * 64),
    ],
)
def test_listener_adoption_frame_rejects_invalid_identity_fields(field, value):
    identity = _network_identity()
    models = _network_models()
    with _fixed_listener() as listener:
        frame = _valid_adoption_frame(identity, models, listener)
        with pytest.raises((TypeError, ValueError, identity.NetworkIdentityError)):
            dataclasses.replace(frame, **{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("family", int(socket.AF_INET6)),
        ("socket_type", int(socket.SOCK_DGRAM)),
        ("address", "0.0.0.0"),
        ("port", 18081),
        ("file_type", stat.S_IFREG),
        ("accepting", False),
    ],
)
def test_listener_adoption_frame_rejects_invalid_listener_contract(field, value):
    identity = _network_identity()
    models = _network_models()
    with _fixed_listener() as listener:
        frame = _valid_adoption_frame(identity, models, listener)
        evidence = dataclasses.replace(frame.evidence, **{field: value})
        with pytest.raises((TypeError, ValueError, identity.NetworkIdentityError)):
            dataclasses.replace(frame, evidence=evidence)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda payload: b"{" + payload[1:-1] + b',"task_id":"task-8"}',
        lambda payload: payload[:-1] + b',"unknown":1}',
        lambda payload: payload.replace(b'"task_id":"task-7",', b""),
        lambda payload: payload.replace(b'"task_generation":3', b'"task_generation":"3"'),
        lambda payload: b" " + payload,
        lambda payload: payload + b"\n",
        lambda payload: payload[:40],
        lambda payload: b"x" * 4096,
    ],
    ids=[
        "duplicate",
        "unknown",
        "missing",
        "wrong-type",
        "noncanonical",
        "trailing",
        "truncated",
        "oversized",
    ],
)
def test_listener_adoption_frame_rejects_malformed_noncanonical_or_oversized_bytes(mutator):
    identity = _network_identity()
    models = _network_models()
    with _fixed_listener() as listener:
        payload = _valid_adoption_frame(identity, models, listener).to_bytes()
        with pytest.raises(identity.NetworkIdentityError):
            identity.ListenerAdoptionFrame.from_bytes(mutator(payload))


def test_listener_fd_positive_one_fd_roundtrip_is_cloexec_and_one_shot():
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
    )
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            identity.send_listener_fd(sender, listener.fileno(), frame)
            adopted = identity.recv_listener_fd(
                receiver,
                expected_task_id="task-7",
                expected_generation=3,
                expected_nonce="ab" * 16,
                expected_policy_digest="c" * 64,
            )
            try:
                assert adopted.frame == frame
                assert adopted.evidence == frame.evidence
                assert fcntl.fcntl(adopted.fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
                assert os.fstat(adopted.fd).st_ino == os.fstat(listener.fileno()).st_ino
                with pytest.raises(identity.NetworkIdentityError):
                    identity.recv_listener_fd(
                        receiver,
                        expected_task_id="task-7",
                        expected_generation=3,
                        expected_nonce="ab" * 16,
                        expected_policy_digest="c" * 64,
                    )
                with pytest.raises(identity.NetworkIdentityError):
                    identity.send_listener_fd(sender, listener.fileno(), frame)
            finally:
                os.close(adopted.fd)
    finally:
        sender.close()
        receiver.close()


@pytest.mark.parametrize("fd_count", [0, 2])
def test_listener_receive_rejects_zero_or_two_scm_rights_fds_without_leaking(fd_count):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            fds = [listener.fileno()] * fd_count
            _send_raw(sender, frame.to_bytes(), fds)
            before = _open_fd_numbers()
            with pytest.raises(identity.NetworkIdentityError):
                identity.recv_listener_fd(
                    receiver,
                    expected_task_id="task-7",
                    expected_generation=3,
                    expected_nonce="ab" * 16,
                    expected_policy_digest="c" * 64,
                )
            assert _open_fd_numbers() == before
    finally:
        sender.close()
        receiver.close()


def test_listener_receive_rejects_unknown_ancillary_record_without_leaking_fd():
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            _send_raw(sender, frame.to_bytes(), [listener.fileno()])
            before = _open_fd_numbers()
            with pytest.raises(identity.NetworkIdentityError):
                identity.recv_listener_fd(
                    receiver,
                    expected_task_id="task-7",
                    expected_generation=3,
                    expected_nonce="ab" * 16,
                    expected_policy_digest="c" * 64,
                )
            assert _open_fd_numbers() == before
    finally:
        sender.close()
        receiver.close()


@pytest.mark.parametrize("payload_kind", ["truncated", "oversized", "malformed"])
def test_listener_receive_rejects_invalid_control_frame_and_closes_received_fd(payload_kind):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        with _fixed_listener() as listener:
            payload = _valid_adoption_frame(identity, models, listener).to_bytes()
            if payload_kind == "truncated":
                payload = payload[:20]
            elif payload_kind == "oversized":
                payload = b"x" * 8192
            else:
                payload = b"{not-json}"
            _send_raw(sender, payload, [listener.fileno()])
            before = _open_fd_numbers()
            with pytest.raises(identity.NetworkIdentityError):
                identity.recv_listener_fd(
                    receiver,
                    expected_task_id="task-7",
                    expected_generation=3,
                    expected_nonce="ab" * 16,
                    expected_policy_digest="c" * 64,
                )
            assert _open_fd_numbers() == before
    finally:
        sender.close()
        receiver.close()


@pytest.mark.parametrize(
    "replacement",
    [
        {"expected_task_id": "task-8"},
        {"expected_generation": 4},
        {"expected_nonce": "cd" * 16},
        {"expected_policy_digest": "d" * 64},
    ],
)
def test_listener_receive_rejects_wrong_authenticated_context_and_closes_fd(replacement):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    expected = {
        "expected_task_id": "task-7",
        "expected_generation": 3,
        "expected_nonce": "ab" * 16,
        "expected_policy_digest": "c" * 64,
    }
    expected.update(replacement)
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            _send_raw(sender, frame.to_bytes(), [listener.fileno()])
            before = _open_fd_numbers()
            with pytest.raises(identity.NetworkIdentityError):
                identity.recv_listener_fd(receiver, **expected)
            assert _open_fd_numbers() == before
    finally:
        sender.close()
        receiver.close()


@pytest.mark.parametrize("identity_field", ["device", "inode", "netns_cookie"])
def test_listener_receive_rejects_frame_vs_fd_identity_substitution(identity_field):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            altered = dataclasses.replace(
                frame,
                evidence=dataclasses.replace(
                    frame.evidence,
                    **{identity_field: getattr(frame.evidence, identity_field) + 1},
                ),
            )
            _send_raw(sender, altered.to_bytes(), [listener.fileno()])
            before = _open_fd_numbers()
            with pytest.raises(identity.NetworkIdentityError):
                identity.recv_listener_fd(
                    receiver,
                    expected_task_id="task-7",
                    expected_generation=3,
                    expected_nonce="ab" * 16,
                    expected_policy_digest="c" * 64,
                )
            assert _open_fd_numbers() == before
    finally:
        sender.close()
        receiver.close()


def test_listener_send_rejects_frame_vs_fd_substitution():
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            altered = dataclasses.replace(
                frame,
                evidence=dataclasses.replace(frame.evidence, inode=frame.evidence.inode + 1),
            )
            with pytest.raises(identity.NetworkIdentityError):
                identity.send_listener_fd(sender, listener.fileno(), altered)
    finally:
        sender.close()
        receiver.close()


def test_listener_send_and_receive_require_exact_unix_seqpacket_channel():
    identity = _network_identity()
    models = _network_models()
    stream_sender, stream_receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            with pytest.raises(identity.NetworkIdentityError):
                identity.send_listener_fd(stream_sender, listener.fileno(), frame)
            with pytest.raises(identity.NetworkIdentityError):
                identity.recv_listener_fd(
                    stream_receiver,
                    expected_task_id="task-7",
                    expected_generation=3,
                    expected_nonce="ab" * 16,
                    expected_policy_digest="c" * 64,
                )
    finally:
        stream_sender.close()
        stream_receiver.close()


def test_listener_adoption_frame_rejects_protocol_version_type_confusable():
    identity = _network_identity()
    models = _network_models()

    class VersionConfusable:
        def __eq__(self, _other):
            return True

    with _fixed_listener() as listener:
        frame = _valid_adoption_frame(identity, models, listener)
        with pytest.raises(identity.NetworkIdentityError):
            dataclasses.replace(frame, version=VersionConfusable())


def test_rejected_listener_packet_consumes_one_shot_read_side_and_closes_queued_fds():
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            _send_raw(sender, b"{malformed}", [listener.fileno()])
            _send_raw(sender, frame.to_bytes(), [listener.fileno()])
            before = _open_fd_numbers()
            for _attempt in range(2):
                with pytest.raises(identity.NetworkIdentityError):
                    identity.recv_listener_fd(
                        receiver,
                        expected_task_id="task-7",
                        expected_generation=3,
                        expected_nonce="ab" * 16,
                        expected_policy_digest="c" * 64,
                    )
            assert _open_fd_numbers() == before
    finally:
        sender.close()
        receiver.close()


def test_listener_send_pins_the_validated_object_across_fd_number_reuse(monkeypatch):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    reached_serialization = threading.Event()
    resume_serialization = threading.Event()
    original_to_bytes = identity.ListenerAdoptionFrame.to_bytes
    first_call = True

    def pause_once(frame):
        nonlocal first_call
        if first_call:
            first_call = False
            reached_serialization.set()
            assert resume_serialization.wait(5)
        return original_to_bytes(frame)

    monkeypatch.setattr(identity.ListenerAdoptionFrame, "to_bytes", pause_once)
    adopted = None
    try:
        with _fixed_listener() as listener, tempfile.TemporaryFile() as replacement:
            frame = _valid_adoption_frame(identity, models, listener)
            original_inode = frame.evidence.inode
            outcomes = []
            worker = threading.Thread(
                target=lambda: outcomes.append(
                    identity.send_listener_fd(sender, listener.fileno(), frame)
                )
            )
            worker.start()
            assert reached_serialization.wait(5)
            os.dup2(replacement.fileno(), listener.fileno(), inheritable=False)
            resume_serialization.set()
            worker.join(5)
            assert not worker.is_alive()
            assert outcomes == [None]
            monkeypatch.setattr(identity.ListenerAdoptionFrame, "to_bytes", original_to_bytes)

            adopted = identity.recv_listener_fd(
                receiver,
                expected_task_id="task-7",
                expected_generation=3,
                expected_nonce="ab" * 16,
                expected_policy_digest="c" * 64,
            )
            assert adopted.evidence.inode == original_inode
    finally:
        resume_serialization.set()
        if adopted is not None:
            os.close(adopted.fd)
        sender.close()
        receiver.close()


def test_listener_receive_rejects_two_valid_records_before_clean_eof_without_leaking():
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    adopted = None
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            _send_raw(sender, frame.to_bytes(), [listener.fileno()])
            _send_raw(sender, frame.to_bytes(), [listener.fileno()])
            sender.shutdown(socket.SHUT_WR)
            before = _open_fd_numbers()
            with pytest.raises(identity.NetworkIdentityError):
                adopted = identity.recv_listener_fd(
                    receiver,
                    expected_task_id="task-7",
                    expected_generation=3,
                    expected_nonce="ab" * 16,
                    expected_policy_digest="c" * 64,
                )
            assert _open_fd_numbers() == before
    finally:
        if adopted is not None:
            os.close(adopted.fd)
        sender.close()
        receiver.close()


def test_listener_receive_requires_clean_eof_with_bounded_wait():
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    adopted = None
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            _send_raw(sender, frame.to_bytes(), [listener.fileno()])
            before = _open_fd_numbers()
            with pytest.raises(identity.NetworkIdentityError):
                adopted = identity.recv_listener_fd(
                    receiver,
                    expected_task_id="task-7",
                    expected_generation=3,
                    expected_nonce="ab" * 16,
                    expected_policy_digest="c" * 64,
                )
            assert _open_fd_numbers() == before
    finally:
        if adopted is not None:
            os.close(adopted.fd)
        sender.close()
        receiver.close()


def test_concurrent_listener_senders_cannot_both_succeed_on_one_channel(monkeypatch):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    paused = threading.Event()
    release = threading.Event()
    original_to_bytes = identity.ListenerAdoptionFrame.to_bytes
    first_call = True

    def pause_first(frame):
        nonlocal first_call
        if first_call:
            first_call = False
            paused.set()
            assert release.wait(5)
        return original_to_bytes(frame)

    monkeypatch.setattr(identity.ListenerAdoptionFrame, "to_bytes", pause_first)
    adopted = None
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            outcomes = []
            outcomes_lock = threading.Lock()

            def attempt_send():
                try:
                    identity.send_listener_fd(sender, listener.fileno(), frame)
                except identity.NetworkIdentityError:
                    outcome = "rejected"
                else:
                    outcome = "success"
                with outcomes_lock:
                    outcomes.append(outcome)

            first = threading.Thread(target=attempt_send)
            second = threading.Thread(target=attempt_send)
            first.start()
            assert paused.wait(5)
            second.start()
            second.join(0.5)
            second_rejected_before_release = not second.is_alive()
            release.set()
            first.join(5)
            second.join(5)
            assert not first.is_alive() and not second.is_alive()
            assert second_rejected_before_release is True
            assert sorted(outcomes) == ["rejected", "success"]

            adopted = identity.recv_listener_fd(
                receiver,
                expected_task_id="task-7",
                expected_generation=3,
                expected_nonce="ab" * 16,
                expected_policy_digest="c" * 64,
            )
    finally:
        release.set()
        if adopted is not None:
            os.close(adopted.fd)
        sender.close()
        receiver.close()


def test_listener_channels_reject_unconnected_listening_wrong_domain_and_inheritable():
    identity = _network_identity()
    unconnected = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    listening = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    wrong_domain = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    inheritable, inheritable_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        listening.bind(f"\0aos-m4b-channel-{os.getpid()}")
        listening.listen(1)
        os.set_inheritable(inheritable.fileno(), True)
        for channel in (unconnected, listening, wrong_domain, inheritable):
            with pytest.raises(identity.NetworkIdentityError):
                identity._require_seqpacket_channel(channel)
    finally:
        unconnected.close()
        listening.close()
        wrong_domain.close()
        inheritable.close()
        inheritable_peer.close()


@pytest.mark.parametrize("invalid_source", ["inheritable", "reuseaddr", "reuseport"])
def test_listener_evidence_rejects_inheritable_or_reusable_source(invalid_source):
    identity = _network_identity()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    try:
        if invalid_source == "reuseaddr":
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        elif invalid_source == "reuseport":
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        listener.bind(("127.0.0.1", 18080))
        listener.listen(1)
        if invalid_source == "inheritable":
            os.set_inheritable(listener.fileno(), True)

        with pytest.raises(identity.NetworkIdentityError):
            identity.listener_evidence(listener.fileno())
    finally:
        listener.close()


def test_listener_receive_constructor_failure_closes_received_fd(monkeypatch):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            identity.send_listener_fd(sender, listener.fileno(), frame)
            before = _open_fd_numbers()

            def fail_construction(**_kwargs):
                raise RuntimeError("injected adopted-listener construction failure")

            monkeypatch.setattr(identity, "AdoptedListener", fail_construction)
            with pytest.raises(RuntimeError, match="injected adopted-listener"):
                identity.recv_listener_fd(
                    receiver,
                    expected_task_id="task-7",
                    expected_generation=3,
                    expected_nonce="ab" * 16,
                    expected_policy_digest="c" * 64,
                )
            assert _open_fd_numbers() == before
    finally:
        sender.close()
        receiver.close()


@pytest.mark.parametrize("shutdown_after_zero", [False, True])
def test_listener_receive_rejects_queued_zero_length_record_as_not_eof(
    shutdown_after_zero,
):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    adopted = None
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            _send_raw(sender, frame.to_bytes(), [listener.fileno()])
            assert sender.send(b"") == 0
            if shutdown_after_zero:
                sender.shutdown(socket.SHUT_WR)
            before = _open_fd_numbers()
            with pytest.raises(identity.NetworkIdentityError):
                adopted = identity.recv_listener_fd(
                    receiver,
                    expected_task_id="task-7",
                    expected_generation=3,
                    expected_nonce="ab" * 16,
                    expected_policy_digest="c" * 64,
                )
            assert _open_fd_numbers() == before
    finally:
        if adopted is not None:
            os.close(adopted.fd)
        sender.close()
        receiver.close()


def test_listener_send_uses_pinned_channel_across_caller_fd_reuse(monkeypatch):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    substitute_sender, substitute_receiver = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET
    )
    validated = threading.Event()
    resume = threading.Event()
    original_validator = identity._require_seqpacket_channel
    pause_once = True

    def pause_after_validation(channel):
        nonlocal pause_once
        original_validator(channel)
        if pause_once:
            pause_once = False
            validated.set()
            assert resume.wait(5)

    monkeypatch.setattr(identity, "_require_seqpacket_channel", pause_after_validation)
    adopted = None
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            outcomes = []

            def send():
                try:
                    identity.send_listener_fd(sender, listener.fileno(), frame)
                except BaseException as exc:
                    outcomes.append(exc)
                else:
                    outcomes.append(None)

            worker = threading.Thread(target=send)
            worker.start()
            assert validated.wait(5)
            os.dup2(substitute_sender.fileno(), sender.fileno(), inheritable=False)
            resume.set()
            worker.join(5)
            assert not worker.is_alive()
            assert outcomes == [None]

            adopted = identity.recv_listener_fd(
                receiver,
                expected_task_id="task-7",
                expected_generation=3,
                expected_nonce="ab" * 16,
                expected_policy_digest="c" * 64,
            )
            assert adopted.evidence == frame.evidence
    finally:
        resume.set()
        if adopted is not None:
            os.close(adopted.fd)
        sender.close()
        receiver.close()
        substitute_sender.close()
        substitute_receiver.close()


def test_listener_receive_uses_pinned_channel_across_caller_fd_reuse(monkeypatch):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    substitute_sender, substitute_receiver = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET
    )
    validated = threading.Event()
    resume = threading.Event()
    original_validator = identity._require_seqpacket_channel
    pause_once = True

    def pause_after_validation(channel):
        nonlocal pause_once
        original_validator(channel)
        if pause_once:
            pause_once = False
            validated.set()
            assert resume.wait(5)

    monkeypatch.setattr(identity, "_require_seqpacket_channel", pause_after_validation)
    outcomes = []
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            _send_raw(sender, frame.to_bytes(), [listener.fileno()])
            sender.shutdown(socket.SHUT_WR)

            def receive():
                try:
                    result = identity.recv_listener_fd(
                        receiver,
                        expected_task_id="task-7",
                        expected_generation=3,
                        expected_nonce="ab" * 16,
                        expected_policy_digest="c" * 64,
                    )
                except BaseException as exc:
                    outcomes.append(exc)
                else:
                    outcomes.append(result)

            worker = threading.Thread(target=receive)
            worker.start()
            assert validated.wait(5)
            os.dup2(substitute_receiver.fileno(), receiver.fileno(), inheritable=False)
            resume.set()
            _send_raw(substitute_sender, b"{malformed}")
            substitute_sender.shutdown(socket.SHUT_WR)
            worker.join(5)
            assert not worker.is_alive()
            assert len(outcomes) == 1
            assert isinstance(outcomes[0], identity.AdoptedListener)
            assert outcomes[0].evidence == frame.evidence
    finally:
        resume.set()
        for outcome in outcomes:
            if hasattr(outcome, "fd"):
                os.close(outcome.fd)
        sender.close()
        receiver.close()
        substitute_sender.close()
        substitute_receiver.close()


def test_distinct_listener_channel_progress_is_not_blocked_by_stalled_channel(
    monkeypatch,
):
    identity = _network_identity()
    models = _network_models()
    sender_a, receiver_a = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    sender_b, receiver_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    stalled_inode = os.fstat(sender_a.fileno()).st_ino
    stalled = threading.Event()
    release = threading.Event()
    original_validator = identity._require_seqpacket_channel

    def stall_one_channel(channel):
        original_validator(channel)
        if os.fstat(channel.fileno()).st_ino == stalled_inode:
            stalled.set()
            assert release.wait(5)

    monkeypatch.setattr(identity, "_require_seqpacket_channel", stall_one_channel)
    outcomes = {}
    outcome_lock = threading.Lock()
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)

            def send(label, channel):
                try:
                    identity.send_listener_fd(channel, listener.fileno(), frame)
                except BaseException as exc:
                    outcome = exc
                else:
                    outcome = None
                with outcome_lock:
                    outcomes[label] = outcome

            first = threading.Thread(target=send, args=("a", sender_a))
            second = threading.Thread(target=send, args=("b", sender_b))
            first.start()
            assert stalled.wait(5)
            second.start()
            second.join(0.5)
            independent_progress = not second.is_alive()
            release.set()
            first.join(5)
            second.join(5)
            assert independent_progress is True
            assert outcomes == {"a": None, "b": None}
    finally:
        release.set()
        sender_a.close()
        receiver_a.close()
        sender_b.close()
        receiver_b.close()


def test_listener_send_alias_is_claimed_before_frame_serialization(monkeypatch):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    alias = socket.socket(fileno=os.dup(sender.fileno()))
    paused = threading.Event()
    release = threading.Event()
    original_to_bytes = identity.ListenerAdoptionFrame.to_bytes
    first_call = True

    def pause_first(frame):
        nonlocal first_call
        if first_call:
            first_call = False
            paused.set()
            assert release.wait(5)
        return original_to_bytes(frame)

    monkeypatch.setattr(identity.ListenerAdoptionFrame, "to_bytes", pause_first)
    outcomes = {}
    adopted = None
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)

            def send(label, channel):
                try:
                    identity.send_listener_fd(channel, listener.fileno(), frame)
                except identity.NetworkIdentityError:
                    outcome = "rejected"
                else:
                    outcome = "success"
                outcomes[label] = outcome

            first = threading.Thread(target=send, args=("first", sender))
            second = threading.Thread(target=send, args=("alias", alias))
            first.start()
            assert paused.wait(5)
            second.start()
            second.join(0.5)
            assert not second.is_alive()
            assert outcomes.get("alias") == "rejected"
            release.set()
            first.join(5)
            assert outcomes == {"alias": "rejected", "first": "success"}
            monkeypatch.setattr(identity.ListenerAdoptionFrame, "to_bytes", original_to_bytes)
            adopted = identity.recv_listener_fd(
                receiver,
                expected_task_id="task-7",
                expected_generation=3,
                expected_nonce="ab" * 16,
                expected_policy_digest="c" * 64,
            )
    finally:
        release.set()
        if adopted is not None:
            os.close(adopted.fd)
        sender.close()
        alias.close()
        receiver.close()


def _run_two_coordinated_receivers(identity, receiver, monkeypatch):
    original_eof = identity._require_clean_write_eof
    first_at_eof = threading.Event()
    second_at_eof = threading.Event()
    release_first = threading.Event()
    calls = 0
    calls_lock = threading.Lock()

    def pause_first_eof(channel):
        nonlocal calls
        with calls_lock:
            calls += 1
            call_number = calls
        if call_number == 1:
            first_at_eof.set()
            assert release_first.wait(5)
        else:
            second_at_eof.set()
        return original_eof(channel)

    monkeypatch.setattr(identity, "_require_clean_write_eof", pause_first_eof)
    outcomes = []
    outcome_lock = threading.Lock()

    def receive():
        try:
            result = identity.recv_listener_fd(
                receiver,
                expected_task_id="task-7",
                expected_generation=3,
                expected_nonce="ab" * 16,
                expected_policy_digest="c" * 64,
            )
        except identity.NetworkIdentityError:
            result = "rejected"
        with outcome_lock:
            outcomes.append(result)

    first = threading.Thread(target=receive)
    second = threading.Thread(target=receive)
    first.start()
    assert first_at_eof.wait(5)
    second.start()
    second_reached_eof = second_at_eof.wait(0.25)
    release_first.set()
    first.join(5)
    second.join(5)
    assert not first.is_alive() and not second.is_alive()
    return outcomes, second_reached_eof


def test_listener_two_records_two_receivers_reject_duplicate_without_leaking(monkeypatch):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            _send_raw(sender, frame.to_bytes(), [listener.fileno()])
            _send_raw(sender, frame.to_bytes(), [listener.fileno()])
            sender.shutdown(socket.SHUT_WR)
            before = _open_fd_numbers()
            outcomes, second_reached_eof = _run_two_coordinated_receivers(
                identity, receiver, monkeypatch
            )
            try:
                assert second_reached_eof is False
                assert outcomes == ["rejected", "rejected"]
                assert _open_fd_numbers() == before
            finally:
                for outcome in outcomes:
                    if hasattr(outcome, "fd"):
                        os.close(outcome.fd)
    finally:
        sender.close()
        receiver.close()


def test_listener_one_record_two_receivers_yields_one_success_without_interference(
    monkeypatch,
):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            identity.send_listener_fd(sender, listener.fileno(), frame)
            outcomes, second_reached_eof = _run_two_coordinated_receivers(
                identity, receiver, monkeypatch
            )
            try:
                adopted = [outcome for outcome in outcomes if hasattr(outcome, "fd")]
                assert second_reached_eof is False
                assert len(adopted) == 1
                assert outcomes.count("rejected") == 1
            finally:
                for outcome in outcomes:
                    if hasattr(outcome, "fd"):
                        os.close(outcome.fd)
    finally:
        sender.close()
        receiver.close()


@pytest.mark.parametrize(
    "event_mask",
    [select.POLLERR | select.POLLHUP, select.POLLNVAL | select.POLLRDHUP],
)
def test_listener_receive_rejects_poll_error_even_with_terminal_mask(
    monkeypatch, event_mask
):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    adopted = None

    class ErrorTerminalPoll:
        def __init__(self):
            self.fd = None

        def register(self, fd, _events):
            self.fd = fd

        def poll(self, _timeout):
            return [(self.fd, event_mask)]

    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            identity.send_listener_fd(sender, listener.fileno(), frame)
            before = _open_fd_numbers()
            monkeypatch.setattr(identity.select, "poll", ErrorTerminalPoll)
            try:
                with pytest.raises(identity.NetworkIdentityError):
                    adopted = identity.recv_listener_fd(
                        receiver,
                        expected_task_id="task-7",
                        expected_generation=3,
                        expected_nonce="ab" * 16,
                        expected_policy_digest="c" * 64,
                    )
            finally:
                if adopted is not None:
                    os.close(adopted.fd)
            assert _open_fd_numbers() == before
    finally:
        sender.close()
        receiver.close()


def test_channel_claim_rolls_back_registry_after_post_insert_failure(monkeypatch):
    identity = _network_identity()
    baseline = _open_fd_numbers()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    pinned = identity._pin_channel(sender)
    claim = None

    def fail_claim_construction(*_args, **_kwargs):
        raise RuntimeError("injected post-insert claim construction failure")

    monkeypatch.setattr(
        identity, "_build_channel_claim", fail_claim_construction, raising=False
    )
    try:
        with pytest.raises(RuntimeError, match="post-insert claim construction"):
            claim = identity._claim_channel(pinned, "send")
        assert (*pinned.identity, "send") not in identity._ACTIVE_CHANNEL_CLAIMS
    finally:
        if claim is not None:
            claim.release()
        pinned.socket.close()
        sender.close()
        receiver.close()
    assert _open_fd_numbers() == baseline


def test_clean_eof_restores_passcred_after_establishment_verification_failure():
    identity = _network_identity()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)

    class VerificationFailingSocket:
        def __init__(self, wrapped):
            self.wrapped = wrapped
            self.passcred_reads = 0

        def fileno(self):
            return self.wrapped.fileno()

        def getsockopt(self, level, option):
            if level == socket.SOL_SOCKET and option == socket.SO_PASSCRED:
                self.passcred_reads += 1
                if self.passcred_reads == 2:
                    return 0
            return self.wrapped.getsockopt(level, option)

        def setsockopt(self, level, option, value):
            return self.wrapped.setsockopt(level, option, value)

        def recvmsg(self, *args):
            return self.wrapped.recvmsg(*args)

    wrapped = VerificationFailingSocket(receiver)
    try:
        assert receiver.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 0
        with pytest.raises(identity.NetworkIdentityError):
            identity._require_clean_write_eof(wrapped)
        assert receiver.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 0
    finally:
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 0)
        sender.close()
        receiver.close()


def _close_injected_fd_leaks(baseline):
    leaked = set()
    for fd in _open_fd_numbers() - baseline:
        try:
            os.close(fd)
        except OSError as exc:
            if exc.errno != errno.EBADF:
                raise
        else:
            leaked.add(fd)
    return leaked


def test_listener_send_cleanup_attempts_later_resources_after_claim_release_failure(
    monkeypatch,
):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    original_release = identity._ChannelClaim.release

    def release_then_fail(claim):
        original_release(claim)
        raise OSError(errno.EIO, "injected claim release failure")

    monkeypatch.setattr(identity._ChannelClaim, "release", release_then_fail)
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            baseline = _open_fd_numbers()
            failure_type = None
            try:
                identity.send_listener_fd(sender, listener.fileno(), frame)
            except BaseException as exc:
                failure_type = type(exc)
                exc.__traceback__ = None
            leaked = _close_injected_fd_leaks(baseline)
            assert leaked == set()
            assert failure_type is identity.NetworkIdentityError
            assert identity._ACTIVE_CHANNEL_CLAIMS == {}
    finally:
        sender.close()
        receiver.close()


def test_listener_receive_cleanup_failure_closes_listener_and_later_resources(
    monkeypatch,
):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            identity.send_listener_fd(sender, listener.fileno(), frame)
            original_release = identity._ChannelClaim.release

            def release_then_fail(claim):
                original_release(claim)
                raise OSError(errno.EIO, "injected receive claim release failure")

            monkeypatch.setattr(identity._ChannelClaim, "release", release_then_fail)
            baseline = _open_fd_numbers()
            failure_type = None
            try:
                identity.recv_listener_fd(
                    receiver,
                    expected_task_id="task-7",
                    expected_generation=3,
                    expected_nonce="ab" * 16,
                    expected_policy_digest="c" * 64,
                )
            except BaseException as exc:
                failure_type = type(exc)
                exc.__traceback__ = None
            leaked = _close_injected_fd_leaks(baseline)
            assert leaked == set()
            assert failure_type is identity.NetworkIdentityError
            assert identity._ACTIVE_CHANNEL_CLAIMS == {}
    finally:
        sender.close()
        receiver.close()


def test_listener_receive_pinned_close_failure_closes_received_listener(monkeypatch):
    identity = _network_identity()
    models = _network_models()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        with _fixed_listener() as listener:
            frame = _valid_adoption_frame(identity, models, listener)
            identity.send_listener_fd(sender, listener.fileno(), frame)
            original_close = getattr(identity._PinnedChannel, "close", None)

            def close_then_fail(pinned):
                if original_close is None:
                    pinned.socket.close()
                else:
                    original_close(pinned)
                raise OSError(errno.EIO, "injected pinned channel close failure")

            monkeypatch.setattr(
                identity._PinnedChannel, "close", close_then_fail, raising=False
            )
            baseline = _open_fd_numbers()
            adopted = None
            failure_type = None
            try:
                adopted = identity.recv_listener_fd(
                    receiver,
                    expected_task_id="task-7",
                    expected_generation=3,
                    expected_nonce="ab" * 16,
                    expected_policy_digest="c" * 64,
                )
            except BaseException as exc:
                failure_type = type(exc)
                exc.__traceback__ = None
            finally:
                if adopted is not None:
                    os.close(adopted.fd)
            assert _open_fd_numbers() == baseline
            assert failure_type is identity.NetworkIdentityError
            assert identity._ACTIVE_CHANNEL_CLAIMS == {}
    finally:
        sender.close()
        receiver.close()


def test_channel_claim_release_does_not_retry_close_after_eintr(monkeypatch):
    identity = _network_identity()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    pinned = identity._pin_channel(sender)
    claim = identity._claim_channel(pinned, "send")
    anchor_fd = claim.anchor_fd
    original_os_close = os.close
    close_calls = 0

    def interrupt_anchor_close(fd):
        nonlocal close_calls
        if fd == anchor_fd:
            close_calls += 1
            raise InterruptedError(errno.EINTR, "injected interrupted close")
        return original_os_close(fd)

    monkeypatch.setattr(identity.os, "close", interrupt_anchor_close)
    try:
        with pytest.raises(InterruptedError):
            claim.release()
        claim.release()
        assert close_calls == 1
        assert claim.key not in identity._ACTIVE_CHANNEL_CLAIMS
    finally:
        monkeypatch.undo()
        try:
            original_os_close(anchor_fd)
        except OSError:
            pass
        pinned.socket.close()
        sender.close()
        receiver.close()
