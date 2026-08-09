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
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

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


def _valid_network_launch_record(launcher):
    return launcher.NetworkLaunchRecord(
        task_id="task-7",
        task_generation=3,
        launch_nonce="ab" * 16,
        network_policy_digest="c" * 64,
        handoff_fd=35,
        proxy_host="127.0.0.1",
        proxy_port=18080,
    )


def test_protocol_v3_launch_request_has_exact_bounded_wire_and_frozen_record():
    launcher = importlib.import_module("agenticos.sandbox.launcher")
    record = _valid_network_launch_record(launcher)

    prepared = launcher.prepare_launch_request(
        ["/usr/bin/true"],
        {"PWD": "/workspace"},
        "/workspace",
        [],
        protocol_version=3,
        cwd_record=("/workspace", 11, 22),
        root_records=[
            ("/workspace", 11, 22, "w"),
            ("/usr", 33, 44, "x"),
        ],
        policy_digest_override="d" * 64,
        status_fd=34,
        network_record=record,
    )

    expected = (
        b"AOSLAUNCH/3\n"
        b"status_fd 34\n"
        b"network task-7 3 abababababababababababababababab "
        + b"c" * 64
        + b" 35 127.0.0.1 18080\n"
        b"nonce 32 abababababababababababababababab\n"
        b"policy_digest 64 "
        + b"d" * 64
        + b"\n"
        b"min_abi 3\n"
        b"argv 1\n"
        b"13 /usr/bin/true\n"
        b"env 1\n"
        b"14 PWD=/workspace\n"
        b"cwd 11 22 10 /workspace\n"
        b"roots 2\n"
        b"w 11 22 10 /workspace\n"
        b"x 33 44 4 /usr\n"
        b"END\n"
    )
    assert prepared.wire == expected
    assert prepared.nonce == "ab" * 16
    assert prepared.policy_digest == "d" * 64
    assert [field.name for field in dataclasses.fields(record)] == [
        "task_id",
        "task_generation",
        "launch_nonce",
        "network_policy_digest",
        "handoff_fd",
        "proxy_host",
        "proxy_port",
    ]
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.handoff_fd = 36


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("task_id", "-task"),
        ("task_id", "task\n8"),
        ("task_id", "task\r8"),
        ("task_id", "task\x008"),
        ("task_id", "t\u00e9st"),
        ("task_id", "t" * 129),
        ("task_generation", 0),
        ("task_generation", True),
        ("task_generation", 3.0),
        ("task_generation", 1 << 64),
        ("launch_nonce", "AB" * 16),
        ("launch_nonce", "a" * 31),
        ("launch_nonce", "a" * 31 + "\n"),
        ("network_policy_digest", "C" * 64),
        ("network_policy_digest", "c" * 63),
        ("network_policy_digest", "c" * 63 + "\x00"),
        ("handoff_fd", 4),
        ("handoff_fd", True),
        ("handoff_fd", 35.0),
        ("handoff_fd", 1 << 31),
        ("proxy_host", "0.0.0.0"),
        ("proxy_host", "127.0.0.1\n"),
        ("proxy_host", "127.0.0.1\x00"),
        ("proxy_port", 18081),
        ("proxy_port", True),
        ("proxy_port", 18080.0),
    ],
)
def test_protocol_v3_network_launch_record_rejects_malformed_fields(field, value):
    launcher = importlib.import_module("agenticos.sandbox.launcher")
    record = _valid_network_launch_record(launcher)

    with pytest.raises((TypeError, ValueError)):
        dataclasses.replace(record, **{field: value})


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"network_record": None}, "network record"),
        ({"status_fd": None}, "status fd"),
        ({"status_fd": 2}, "status fd"),
        ({"status_fd": True}, "status fd"),
        ({"status_fd": 34.0}, "status fd"),
        ({"status_fd": 1 << 31}, "status fd"),
        ({"status_fd": 35}, "distinct"),
        ({"nonce": "cd" * 16}, "nonce"),
    ],
)
def test_protocol_v3_launch_request_rejects_missing_or_inconsistent_fields(
    updates, message
):
    launcher = importlib.import_module("agenticos.sandbox.launcher")
    arguments = {
        "protocol_version": 3,
        "cwd_record": ("/workspace", 11, 22),
        "root_records": [],
        "policy_digest_override": "d" * 64,
        "status_fd": 34,
        "network_record": _valid_network_launch_record(launcher),
    }
    arguments.update(updates)

    with pytest.raises(ValueError, match=message):
        launcher.prepare_launch_request(
            ["/usr/bin/true"], {}, "/workspace", [], **arguments
        )


@pytest.mark.parametrize(
    "nul_location", ["argv", "env-key", "env-value", "cwd", "root"]
)
def test_protocol_v3_launch_request_rejects_nul_in_nested_values(nul_location):
    launcher = importlib.import_module("agenticos.sandbox.launcher")
    argv = ["/usr/bin/true"]
    env = {"PWD": "/workspace"}
    cwd = "/workspace"
    roots = []
    cwd_record = (cwd, 11, 22)
    root_records = []
    if nul_location == "argv":
        argv = ["/usr/bin/tr\x00ue"]
    elif nul_location == "env-key":
        env = {"P\x00WD": "/workspace"}
    elif nul_location == "env-value":
        env = {"PWD": "/work\x00space"}
    elif nul_location == "cwd":
        cwd = "/work\x00space"
        cwd_record = (cwd, 11, 22)
    else:
        roots = [("/work\x00space", "w")]
        root_records = [("/work\x00space", 11, 22, "w")]

    with pytest.raises(ValueError, match="NUL"):
        launcher.prepare_launch_request(
            argv,
            env,
            cwd,
            roots,
            protocol_version=3,
            cwd_record=cwd_record,
            root_records=root_records,
            policy_digest_override="d" * 64,
            status_fd=34,
            network_record=_valid_network_launch_record(launcher),
        )


@pytest.mark.parametrize("protocol_version", [1, 2])
@pytest.mark.parametrize("field", ["network_record", "status_fd"])
def test_protocol_v1_v2_reject_v3_network_launch_fields(protocol_version, field):
    launcher = importlib.import_module("agenticos.sandbox.launcher")
    kwargs = {"protocol_version": protocol_version}
    if protocol_version == 2:
        kwargs.update(
            cwd_record=("/workspace", 11, 22),
            root_records=[],
        )
    kwargs[field] = (
        _valid_network_launch_record(launcher) if field == "network_record" else 34
    )

    with pytest.raises(ValueError, match="protocol v3"):
        launcher.prepare_launch_request(
            ["/usr/bin/true"], {}, "/workspace", [], **kwargs
        )


@pytest.mark.parametrize("protocol_version", [True, 1.0, 0, 4])
def test_protocol_launch_request_rejects_wrong_version_type_or_value(protocol_version):
    launcher = importlib.import_module("agenticos.sandbox.launcher")
    with pytest.raises(ValueError, match="protocol version"):
        launcher.prepare_launch_request(
            ["/usr/bin/true"],
            {},
            "/workspace",
            [],
            protocol_version=protocol_version,
        )


def test_protocol_v3_status_authenticates_canonical_listener_frame_and_order():
    launcher = importlib.import_module("agenticos.sandbox.launcher")
    identity = _network_identity()
    record = _valid_network_launch_record(launcher)
    with _fixed_listener() as listener:
        frame = identity.ListenerAdoptionFrame(
            version="AOSLISTENER/1",
            task_id=record.task_id,
            task_generation=record.task_generation,
            launch_nonce=record.launch_nonce,
            policy_digest=record.network_policy_digest,
            evidence=identity.listener_evidence(listener.fileno()),
        )
        transcript = (
            b"R:" + record.launch_nonce.encode("ascii") + b"\n"
            b"L:" + record.network_policy_digest.encode("ascii") + b":"
            + frame.to_bytes()
            + b"\nS\nI\nP\nN\nA:3:7fff:"
            + b"d" * 64
            + b"\n"
        )

        parsed = launcher.parse_launcher_status(
            transcript,
            expected_nonce=record.launch_nonce,
            expected_policy_digest="d" * 64,
            expected_network_record=record,
            protocol_version=3,
        )

    assert parsed["failed_stage"] is None
    assert parsed["progress"] == ["R", "L", "S", "I", "P", "N", "A"]
    assert parsed["listener_exported"] is True
    assert parsed["network_policy_digest"] == "c" * 64
    assert parsed["listener_frame"] == frame
    assert parsed["listener_evidence"] == frame.evidence
    assert parsed["identity_verified"] is True
    assert parsed["policy_applied"] is True


@pytest.mark.parametrize("mutation", ["missing", "wrong-prefix", "wrong-frame"])
def test_protocol_v3_status_rejects_missing_or_unauthenticated_listener(mutation):
    launcher = importlib.import_module("agenticos.sandbox.launcher")
    identity = _network_identity()
    record = _valid_network_launch_record(launcher)
    with _fixed_listener() as listener:
        frame = identity.ListenerAdoptionFrame(
            version="AOSLISTENER/1",
            task_id=record.task_id,
            task_generation=record.task_generation,
            launch_nonce=record.launch_nonce,
            policy_digest=record.network_policy_digest,
            evidence=identity.listener_evidence(listener.fileno()),
        )
        if mutation == "missing":
            listener_line = b""
        elif mutation == "wrong-prefix":
            listener_line = b"L:" + b"e" * 64 + b":" + frame.to_bytes() + b"\n"
        else:
            malformed = frame.to_bytes().replace(
                b'"task_id":"task-7"', b'"task_id":"task-8"'
            )
            listener_line = b"L:" + b"c" * 64 + b":" + malformed + b"\n"
        transcript = (
            b"R:" + b"ab" * 16 + b"\n" + listener_line
            + b"S\nI\nP\nN\nA:3:7fff:" + b"d" * 64 + b"\n"
        )

        parsed = launcher.parse_launcher_status(
            transcript,
            expected_nonce=record.launch_nonce,
            expected_policy_digest="d" * 64,
            expected_network_record=record,
            protocol_version=3,
        )

    assert parsed["failed_stage"] == "protocol"
    assert parsed["policy_applied"] is False


@pytest.mark.parametrize("expected_nonce", [None, "cd" * 16])
def test_protocol_v3_status_binds_ready_nonce_to_network_record(expected_nonce):
    launcher = importlib.import_module("agenticos.sandbox.launcher")
    identity = _network_identity()
    record = _valid_network_launch_record(launcher)
    with _fixed_listener() as listener:
        frame = identity.ListenerAdoptionFrame(
            version="AOSLISTENER/1",
            task_id=record.task_id,
            task_generation=record.task_generation,
            launch_nonce=record.launch_nonce,
            policy_digest=record.network_policy_digest,
            evidence=identity.listener_evidence(listener.fileno()),
        )
        parsed = launcher.parse_launcher_status(
            b"R:" + b"cd" * 16 + b"\nL:" + b"c" * 64 + b":"
            + frame.to_bytes() + b"\n",
            expected_nonce=expected_nonce,
            expected_network_record=record,
            protocol_version=3,
        )

    assert parsed["failed_stage"] == "protocol"
    assert parsed["listener_exported"] is False


@pytest.mark.parametrize(
    "progress_tags",
    [
        ("L", "R"),
        ("R", "S", "L"),
        ("R", "R"),
        ("R", "L", "S", "S"),
        ("R", "L", "S", "I", "I"),
        ("R", "L", "S", "I", "P", "P"),
        ("R", "L", "S", "I", "P", "N", "N"),
        ("R", "L", "S", "I", "P", "N", "A", "A"),
    ],
)
def test_protocol_v3_status_rejects_nonprefix_partial_progress(progress_tags):
    launcher = importlib.import_module("agenticos.sandbox.launcher")
    identity = _network_identity()
    record = _valid_network_launch_record(launcher)
    with _fixed_listener() as listener:
        frame = identity.ListenerAdoptionFrame(
            version="AOSLISTENER/1",
            task_id=record.task_id,
            task_generation=record.task_generation,
            launch_nonce=record.launch_nonce,
            policy_digest=record.network_policy_digest,
            evidence=identity.listener_evidence(listener.fileno()),
        )
        records = {
            "R": b"R:" + record.launch_nonce.encode("ascii") + b"\n",
            "L": b"L:" + record.network_policy_digest.encode("ascii")
            + b":" + frame.to_bytes() + b"\n",
            "S": b"S\n",
            "I": b"I\n",
            "P": b"P\n",
            "N": b"N\n",
            "A": b"A:3:7fff:" + b"d" * 64 + b"\n",
        }
        parsed = launcher.parse_launcher_status(
            b"".join(records[tag] for tag in progress_tags),
            expected_network_record=record,
            expected_policy_digest="d" * 64,
            protocol_version=3,
        )

    assert parsed["failed_stage"] == "protocol"
    assert parsed["listener_exported"] is False
    assert parsed["policy_applied"] is False


@pytest.mark.parametrize(
    "status_tags",
    [
        ("E", "R", "L", "S", "I", "P", "N", "A"),
        ("R", "L", "E", "S", "I", "P", "N", "A"),
        ("R", "L", "S", "I", "P", "N", "A", "E", "E"),
        ("R", "L", "S", "I", "P", "N", "A", "E", "F"),
        ("R", "L", "F", "F"),
        ("R", "L", "F", "E"),
    ],
)
def test_protocol_v3_status_rejects_impossible_terminal_records(status_tags):
    launcher = importlib.import_module("agenticos.sandbox.launcher")
    identity = _network_identity()
    record = _valid_network_launch_record(launcher)
    with _fixed_listener() as listener:
        frame = identity.ListenerAdoptionFrame(
            version="AOSLISTENER/1",
            task_id=record.task_id,
            task_generation=record.task_generation,
            launch_nonce=record.launch_nonce,
            policy_digest=record.network_policy_digest,
            evidence=identity.listener_evidence(listener.fileno()),
        )
        records = {
            "R": b"R:" + record.launch_nonce.encode("ascii") + b"\n",
            "L": b"L:" + record.network_policy_digest.encode("ascii")
            + b":" + frame.to_bytes() + b"\n",
            "S": b"S\n",
            "I": b"I\n",
            "P": b"P\n",
            "N": b"N\n",
            "A": b"A:3:7fff:" + b"d" * 64 + b"\n",
            "E": b"E:5\n",
            "F": b"F:gate:13\n",
        }
        parsed = launcher.parse_launcher_status(
            b"".join(records[tag] for tag in status_tags),
            expected_network_record=record,
            expected_policy_digest="d" * 64,
            protocol_version=3,
        )

    assert parsed["failed_stage"] == "protocol"
    assert parsed["listener_exported"] is False
    assert parsed["policy_applied"] is False


def test_protocol_v1_v2_status_bytes_and_progress_remain_exact(tmp_path):
    launcher = importlib.import_module("agenticos.sandbox.launcher")
    observed = os.stat(tmp_path)
    v1 = launcher.prepare_launch_request(
        ["/usr/bin/true"], {}, str(tmp_path), [], nonce="legacy-nonce"
    )
    expected_v1_digest = hashlib.sha256(
        json.dumps(
            {
                "cwd": {
                    "path": str(tmp_path),
                    "dev": observed.st_dev,
                    "ino": observed.st_ino,
                },
                "roots": [],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    assert v1.policy_digest == expected_v1_digest
    expected_v1 = (
        b"AOSLAUNCH/1\nnonce 12 legacy-nonce\npolicy_digest 64 "
        + expected_v1_digest.encode("ascii")
        + b"\nmin_abi 3\nargv 1\n13 /usr/bin/true\nenv 0\n"
        + f"cwd {observed.st_dev} {observed.st_ino} ".encode("ascii")
        + f"{len(str(tmp_path).encode())} {tmp_path}\n".encode()
        + b"roots 0\nEND\n"
    )
    assert v1.wire == expected_v1

    v2 = launcher.prepare_launch_request(
        ["/usr/bin/true"],
        {},
        "/workspace",
        [],
        nonce="legacy-nonce",
        protocol_version=2,
        cwd_record=("/workspace", 11, 22),
        root_records=[],
        policy_digest_override="d" * 64,
    )
    assert v2.wire == (
        b"AOSLAUNCH/2\nnonce 12 legacy-nonce\npolicy_digest 64 "
        + b"d" * 64
        + b"\nmin_abi 3\nargv 1\n13 /usr/bin/true\nenv 0\n"
        b"cwd 11 22 10 /workspace\nroots 0\nEND\n"
    )
    parsed = launcher.parse_launcher_status(
        b"R:legacy-nonce\nS\nI\nP\nN\nA:3:7fff:" + b"d" * 64 + b"\n",
        expected_nonce="legacy-nonce",
        expected_policy_digest="d" * 64,
        protocol_version=2,
    )
    assert parsed["failed_stage"] is None
    assert parsed["progress"] == ["R", "S", "I", "P", "N", "A"]


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


# Task 4: authoritative same-scope supervisor and least-authority broker.

BOUNDARY_MODULE = "agenticos.sandbox.network_boundary"
BROKER_MODULE = "agenticos.sandbox.network_broker"


def _network_boundary():
    try:
        return importlib.import_module(BOUNDARY_MODULE)
    except ModuleNotFoundError as exc:
        pytest.fail(f"M4B broker boundary is missing: {exc}")


def _network_broker():
    try:
        return importlib.import_module(BROKER_MODULE)
    except ModuleNotFoundError as exc:
        pytest.fail(f"M4B broker core is missing: {exc}")


def _boundary_policy(models, *, mode=None, **changes):
    now = time.monotonic_ns()
    values = {
        "version": "AOSNET/1",
        "task_id": "task-boundary",
        "task_generation": 9,
        "launch_nonce": "cd" * 16,
        "mode": mode or models.TransportMode.SYNTHETIC_FIXTURE_FD,
        "proxy_host": "127.0.0.1",
        "proxy_port": 18080,
        "activated_at_monotonic_ns": now - 1_000_000_000,
        "expires_at_monotonic_ns": now + 10_000_000_000,
        "connection_limit": 1,
        "byte_limit": 4096,
    }
    values.update(changes)
    return models.TransportPolicy(**values)


def _fixed_source(boundary, *, locator, fd, device, inode, file_type):
    return boundary.AuthorizedSource(
        locator=Path(locator),
        fd=fd,
        identity=boundary.FileIdentity(
            device=device,
            inode=inode,
            file_type=file_type,
        ),
    )


def _boundary_sources(boundary):
    return {
        "runtime_usr": _fixed_source(
            boundary,
            locator="/trusted/runtime/usr",
            fd=boundary.BROKER_RUNTIME_USR_FD,
            device=101,
            inode=201,
            file_type=stat.S_IFDIR,
        ),
        "broker_code": _fixed_source(
            boundary,
            locator="/trusted/code/network_broker.py",
            fd=boundary.BROKER_CODE_FD,
            device=102,
            inode=202,
            file_type=stat.S_IFREG,
        ),
        "identity_code": _fixed_source(
            boundary,
            locator="/trusted/code/network_identity.py",
            fd=boundary.BROKER_IDENTITY_CODE_FD,
            device=103,
            inode=203,
            file_type=stat.S_IFREG,
        ),
        "models_code": _fixed_source(
            boundary,
            locator="/trusted/code/network_models.py",
            fd=boundary.BROKER_MODELS_CODE_FD,
            device=104,
            inode=204,
            file_type=stat.S_IFREG,
        ),
        "supervisor": _fixed_source(
            boundary,
            locator="/trusted/native/task_supervisor",
            fd=boundary.SUPERVISOR_EXECUTABLE_FD,
            device=105,
            inode=205,
            file_type=stat.S_IFREG,
        ),
    }


def _boundary_plan(*, mode=None):
    boundary = _network_boundary()
    models = _network_models()
    return boundary, boundary.build_network_boundary_plan(
        transport_policy=_boundary_policy(models, mode=mode),
        **_boundary_sources(boundary),
    )


def _adjacent_pairs(values):
    return set(zip(values, values[1:]))


def test_broker_boundary_plan_has_exact_environment_mounts_and_host_network():
    boundary, plan = _boundary_plan()

    assert plan.broker_environment == (
        ("HOME", "/home/broker"),
        ("PATH", "/usr/bin:/bin"),
        ("LANG", "C.UTF-8"),
        ("LC_ALL", "C.UTF-8"),
        ("TMPDIR", "/tmp"),
        ("PWD", "/opt/agenticos/python"),
        ("PYTHONDONTWRITEBYTECODE", "1"),
    )
    argv = plan.broker_bwrap_argv
    assert argv[0] == "bwrap"
    assert "--unshare-net" not in argv
    assert "--unshare-cgroup" not in argv
    assert "--unshare-all" not in argv
    for flag in (
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--disable-userns",
        "--new-session",
        "--die-with-parent",
        "--clearenv",
    ):
        assert flag in argv
    assert ("--cap-drop", "ALL") in _adjacent_pairs(argv)
    assert ("--tmpfs", "/") in _adjacent_pairs(argv)
    assert ("--proc", "/proc") in _adjacent_pairs(argv)
    assert ("--dev", "/dev") in _adjacent_pairs(argv)
    assert ("--chdir", "/opt/agenticos/python") in _adjacent_pairs(argv)

    expected_destinations = (
        "/usr",
        "/opt/agenticos/python/agenticos/sandbox/network_broker.py",
        "/opt/agenticos/python/agenticos/sandbox/network_identity.py",
        "/opt/agenticos/python/agenticos/sandbox/network_models.py",
    )
    assert tuple(mount.destination for mount in plan.mounts) == expected_destinations
    assert all(mount.bind_option == "--ro-bind-fd" for mount in plan.mounts)
    assert tuple(plan.synthetic_directories) == (
        "/opt",
        "/opt/agenticos",
        "/opt/agenticos/python",
        "/opt/agenticos/python/agenticos",
        "/opt/agenticos/python/agenticos/sandbox",
        "/home",
        "/home/broker",
        "/run",
        "/tmp",
    )
    for forbidden in (
        "/workspace",
        "/etc/resolv.conf",
        "/etc/ssl",
        "/run/user",
        "/home/brand",
        "PYTHONPATH",
        "HTTP_PROXY",
        "HTTPS_PROXY",
    ):
        assert all(forbidden not in item for item in argv)
    for source in _boundary_sources(boundary).values():
        assert str(source.locator) not in argv


def test_broker_boundary_command_uses_only_fixed_isolated_bootstrap():
    boundary, plan = _boundary_plan()
    argv = plan.broker_bwrap_argv
    separator = argv.index("--")

    assert argv[separator + 1 : separator + 6] == (
        "/usr/bin/python3",
        "-I",
        "-S",
        "-B",
        "-c",
    )
    assert argv[separator + 6] == boundary.BROKER_BOOTSTRAP
    assert "/opt/agenticos/python" in boundary.BROKER_BOOTSTRAP
    assert "PYTHONPATH" not in boundary.BROKER_BOOTSTRAP
    assert "site" not in boundary.BROKER_BOOTSTRAP
    assert argv[separator + 7] == "AOSBROKER/1"
    assert boundary.BROKER_JSON_STATUS_FD == 8
    assert ("--json-status-fd", "8") in _adjacent_pairs(argv)
    assert "--close-fd" not in argv
    for mount in plan.mounts:
        assert (
            "--ro-bind-fd",
            str(mount.source.fd),
            mount.destination,
        ) in set(zip(argv, argv[1:], argv[2:]))


@pytest.mark.m4b_linux
def test_broker_bootstrap_ignores_competing_regular_package(tmp_path):
    boundary = _network_boundary()
    repo_sandbox = Path(__file__).parents[2] / "src/agenticos/sandbox"
    exact_root = tmp_path / "exact"
    exact_sandbox = exact_root / "agenticos/sandbox"
    exact_sandbox.mkdir(parents=True)
    for name in ("network_broker.py", "network_identity.py", "network_models.py"):
        (exact_sandbox / name).write_bytes((repo_sandbox / name).read_bytes())

    marker = tmp_path / "competing-package-ran"
    competing = tmp_path / "competing"
    competing_sandbox = competing / "agenticos/sandbox"
    competing_sandbox.mkdir(parents=True)
    (competing / "agenticos/__init__.py").write_text("", encoding="utf-8")
    (competing_sandbox / "__init__.py").write_text("", encoding="utf-8")
    (competing_sandbox / "network_broker.py").write_text(
        "from pathlib import Path\n"
        f"def main():\n    Path({str(marker)!r}).write_text('ran')\n    return 0\n",
        encoding="utf-8",
    )
    bootstrap = boundary.BROKER_BOOTSTRAP.replace(
        "/opt/agenticos/python", str(exact_root)
    ).replace(
        "sys.path[:]=[",
        f"sys.path[:]=[{str(competing)!r},",
        1,
    )

    completed = subprocess.run(
        ["/usr/bin/python3", "-I", "-S", "-B", "-c", bootstrap],
        env=dict(_network_broker().BROKER_ENVIRONMENT),
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 111
    assert not marker.exists()


def test_broker_boundary_digest_is_deterministic_and_binds_policy_and_identities():
    boundary, first = _boundary_plan()
    _boundary, second = _boundary_plan()
    # Replace the time-varying policy with one shared instance for the determinism proof.
    models = _network_models()
    policy = _boundary_policy(models)
    sources = _boundary_sources(boundary)
    first = boundary.build_network_boundary_plan(transport_policy=policy, **sources)
    second = boundary.build_network_boundary_plan(transport_policy=policy, **sources)

    assert first.transport_policy_digest == models.policy_digest(policy)
    assert first.boundary_policy_digest == second.boundary_policy_digest
    changed = dict(sources)
    changed["broker_code"] = dataclasses.replace(
        changed["broker_code"],
        identity=dataclasses.replace(changed["broker_code"].identity, inode=999),
    )
    third = boundary.build_network_boundary_plan(
        transport_policy=policy,
        **changed,
    )
    assert third.boundary_policy_digest != first.boundary_policy_digest
    assert b"/trusted/" not in first.canonical_boundary_policy


@pytest.mark.parametrize(
    ("source_name", "mutation", "message"),
    [
        ("runtime_usr", lambda b, s: dataclasses.replace(s, fd=999), "fixed descriptor"),
        (
            "broker_code",
            lambda b, s: dataclasses.replace(
                s, identity=dataclasses.replace(s.identity, file_type=stat.S_IFDIR)
            ),
            "regular file",
        ),
        (
            "identity_code",
            lambda b, s: dataclasses.replace(s, locator=Path("relative.py")),
            "absolute",
        ),
        (
            "models_code",
            lambda b, s: dataclasses.replace(
                s, identity=dataclasses.replace(s.identity, inode=True)
            ),
            "positive integer",
        ),
    ],
)
def test_broker_boundary_rejects_wrong_source_fd_type_locator_or_primitive(
    source_name, mutation, message
):
    boundary = _network_boundary()
    models = _network_models()
    sources = _boundary_sources(boundary)
    sources[source_name] = mutation(boundary, sources[source_name])

    with pytest.raises((TypeError, ValueError), match=message):
        boundary.build_network_boundary_plan(
            transport_policy=_boundary_policy(models),
            **sources,
        )


def test_broker_boundary_rejects_source_identity_collision():
    boundary = _network_boundary()
    models = _network_models()
    sources = _boundary_sources(boundary)
    sources["models_code"] = dataclasses.replace(
        sources["models_code"],
        identity=sources["identity_code"].identity,
    )

    with pytest.raises(ValueError, match="identity collision"):
        boundary.build_network_boundary_plan(
            transport_policy=_boundary_policy(models),
            **sources,
        )


def test_supervisor_contract_is_exact_versioned_and_count_bounded():
    _boundary, plan = _boundary_plan()
    worker = ("bwrap", "--clearenv", "--", "/usr/bin/true")

    argv = plan.supervisor_contract.argv_for(worker)

    assert argv == (
        "task_supervisor",
        "AOSSUP/1",
        "bwrap_fd",
        "5",
        "status_fd",
        "6",
        "broker_passc",
        str(len(plan.supervisor_contract.broker_pass_fds)),
        "broker_pass",
        *(str(fd) for fd in plan.supervisor_contract.broker_pass_fds),
        "worker_passc",
        "0",
        "worker_pass",
        "broker_argc",
        str(len(plan.broker_bwrap_argv)),
        "broker",
        *plan.broker_bwrap_argv,
        "worker_argc",
        "4",
        "worker",
        *worker,
        "END",
    )
    assert plan.supervisor_source.role == "supervisor"
    assert plan.supervisor_source.source.fd == 7
    assert plan.supervisor_contract.broker_pass_fds == (
        8,
        20,
        21,
        22,
        23,
        30,
        31,
        32,
        33,
        34,
    )
    with pytest.raises(ValueError, match="worker argv"):
        plan.supervisor_contract.argv_for(())
    with pytest.raises(ValueError, match="bounded"):
        plan.supervisor_contract.argv_for(("bwrap", "x" * 4097))
    with pytest.raises(ValueError, match="overlap"):
        plan.supervisor_contract.argv_for(
            worker,
            worker_pass_fds=(8,),
        )
    with pytest.raises(ValueError, match="sorted unique"):
        plan.supervisor_contract.argv_for(
            worker,
            worker_pass_fds=(40, 40),
        )
    with pytest.raises(ValueError, match="sorted unique"):
        plan.supervisor_contract.argv_for(
            worker,
            worker_pass_fds=(5,),
        )


def test_broker_contract_round_trips_fixed_argv_and_restores_only_fixed_roles():
    broker = _network_broker()
    _boundary, plan = _boundary_plan()
    contract = plan.broker_contract

    assert broker.BrokerContract.from_argv(contract.to_argv()) == contract
    assert contract.capability_fds == (30, 31, 32, 33, 34)
    assert len(set(contract.capability_fds)) == len(contract.capability_fds)
    deny_boundary, deny_plan = _boundary_plan(
        mode=_network_models().TransportMode.DENY
    )
    assert deny_boundary is not None
    assert deny_plan.broker_contract.fixture_fd is None
    assert deny_plan.broker_contract.capability_fds == (30, 31, 32, 33)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda argv: ["AOSBROKER/2", *argv[1:]],
        lambda argv: [*argv, "trailing"],
        lambda argv: [*argv[:2], "+30", *argv[3:]],
        lambda argv: [*argv[:2], "030", *argv[3:]],
        lambda argv: [*argv[:2], "31", *argv[3:]],
        lambda argv: [*argv[:4], "30", *argv[5:]],
        lambda argv: [*argv[:6], "not-a-number", *argv[7:]],
    ],
)
def test_broker_contract_rejects_malformed_noncanonical_or_colliding_argv(mutation):
    broker = _network_broker()
    _boundary, plan = _boundary_plan()
    malformed = mutation(list(plan.broker_contract.to_argv()))

    with pytest.raises(broker.BrokerBoundaryError):
        broker.BrokerContract.from_argv(malformed)


def _zero_proc_status(*, no_new_privs=1, cap_eff="0000000000000000"):
    return (
        "Name:\tpython3\n"
        "CapInh:\t0000000000000000\n"
        "CapPrm:\t0000000000000000\n"
        f"CapEff:\t{cap_eff}\n"
        "CapBnd:\t0000000000000000\n"
        "CapAmb:\t0000000000000000\n"
        f"NoNewPrivs:\t{no_new_privs}\n"
    )


def test_broker_proc_status_requires_all_zero_capability_sets_and_nnp():
    broker = _network_broker()

    evidence = broker.parse_proc_status(_zero_proc_status())

    assert evidence == broker.ProcStatusEvidence(
        cap_inheritable=0,
        cap_permitted=0,
        cap_effective=0,
        cap_bounding=0,
        cap_ambient=0,
        no_new_privs=1,
    )
    broker.require_minimal_proc_status(evidence)


@pytest.mark.parametrize(
    "payload",
    [
        _zero_proc_status(no_new_privs=0),
        _zero_proc_status(cap_eff="0000000000000001"),
        _zero_proc_status().replace("CapAmb:\t0000000000000000\n", ""),
        _zero_proc_status() + "CapEff:\t0000000000000000\n",
        _zero_proc_status().replace("0000000000000000", "0", 1),
    ],
)
def test_broker_proc_status_rejects_missing_duplicate_noncanonical_or_privileged(payload):
    broker = _network_broker()

    with pytest.raises(broker.BrokerBoundaryError):
        evidence = broker.parse_proc_status(payload)
        broker.require_minimal_proc_status(evidence)


def test_broker_environment_is_exact_and_rejects_ambient_credentials():
    broker = _network_broker()
    expected = dict(broker.BROKER_ENVIRONMENT)

    evidence = broker.validate_broker_environment(expected)

    assert evidence.names == tuple(expected)
    assert evidence.digest == hashlib.sha256(
        json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    for name in (
        "OPENAI_API_KEY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "AWS_SECRET_ACCESS_KEY",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "SSH_AUTH_SOCK",
        "PYTHONPATH",
    ):
        with pytest.raises(broker.BrokerBoundaryError, match="environment"):
            broker.validate_broker_environment({**expected, name: "canary"})


def test_broker_fd_observation_excludes_its_own_closed_proc_directory_fd():
    broker = _network_broker()

    observed = broker._observe_fd_numbers()

    for fd in observed:
        fcntl.fcntl(fd, fcntl.F_GETFD)


@pytest.mark.m4b_linux
def test_broker_prctl_runtime_import_leaves_no_loader_descriptor():
    broker = _network_broker()
    repo_src = Path(__file__).parents[2] / "src"
    package_root = repo_src / "agenticos"
    sandbox_root = package_root / "sandbox"
    script = (
        "import json,os,sys,types;"
        "agenticos=types.ModuleType('agenticos');"
        f"agenticos.__path__=[{str(package_root)!r}];"
        "sys.modules['agenticos']=agenticos;"
        "sandbox=types.ModuleType('agenticos.sandbox');"
        f"sandbox.__path__=[{str(sandbox_root)!r}];"
        "sys.modules['agenticos.sandbox']=sandbox;"
        "from agenticos.sandbox import network_broker as broker;"
        "before=broker._observe_fd_numbers();"
        "ctypes_before='ctypes' in sys.modules;"
        "runtime=broker.ObservedFileIdentity.from_stat(os.stat('/usr'));"
        "status=broker._establish_no_new_privs(before,runtime);"
        "after=broker._observe_fd_numbers();"
        "print(json.dumps({'before':before,'after':after,"
        "'ctypes_before':ctypes_before,'nnp':status.no_new_privs},"
        "sort_keys=True,separators=(',',':')))"
    )

    completed = subprocess.run(
        [
            "/usr/bin/bwrap",
            "--unshare-user",
            "--disable-userns",
            "--cap-drop",
            "ALL",
            "--ro-bind",
            "/",
            "/",
            "--",
            broker.INTERPRETER_PATH,
            "-I",
            "-S",
            "-B",
            "-c",
            script,
        ],
        cwd=Path(__file__).parents[2],
        env=dict(broker.BROKER_ENVIRONMENT),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "after": [0, 1, 2],
        "before": [0, 1, 2],
        "ctypes_before": False,
        "nnp": 1,
    }


@pytest.mark.m4b_linux
def test_broker_prctl_rejects_fixed_fd_close_and_numeric_reuse():
    broker = _network_broker()
    repo_src = Path(__file__).parents[2] / "src"
    package_root = repo_src / "agenticos"
    sandbox_root = package_root / "sandbox"
    script = f"""
import builtins
import json
import os
import sys
import types

agenticos = types.ModuleType("agenticos")
agenticos.__path__ = [{str(package_root)!r}]
sys.modules["agenticos"] = agenticos
sandbox = types.ModuleType("agenticos.sandbox")
sandbox.__path__ = [{str(sandbox_root)!r}]
sys.modules["agenticos.sandbox"] = sandbox
from agenticos.sandbox import network_broker as broker

source = os.open("/usr/bin/python3", os.O_RDONLY | os.O_CLOEXEC)
os.dup2(source, 40, inheritable=False)
if source != 40:
    os.close(source)
before = broker._observe_fd_numbers()
original_import = builtins.__import__

def replacing_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "ctypes":
        replacement = os.open("/usr/bin/true", os.O_RDONLY | os.O_CLOEXEC)
        os.close(40)
        os.dup2(replacement, 40, inheritable=False)
        if replacement != 40:
            os.close(replacement)
    return original_import(name, globals, locals, fromlist, level)

builtins.__import__ = replacing_import
runtime = broker.ObservedFileIdentity.from_stat(os.stat("/usr"))
try:
    broker._establish_no_new_privs(before, runtime)
except broker.BrokerBoundaryError as exc:
    print(json.dumps({{"accepted": False, "error": str(exc),
                      "after": broker._observe_fd_numbers()}}, sort_keys=True))
else:
    print(json.dumps({{"accepted": True,
                      "after": broker._observe_fd_numbers()}}, sort_keys=True))
"""
    completed = subprocess.run(
        [
            "/usr/bin/bwrap",
            "--unshare-user",
            "--disable-userns",
            "--cap-drop",
            "ALL",
            "--ro-bind",
            "/",
            "/",
            "--",
            broker.INTERPRETER_PATH,
            "-I",
            "-S",
            "-B",
            "-c",
            script,
        ],
        cwd=Path(__file__).parents[2],
        env=dict(broker.BROKER_ENVIRONMENT),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["accepted"] is False
    assert "fixed descriptor" in result["error"]
    assert result["after"] == [0, 1, 2, 40]


def _ready_record(broker):
    models = _network_models()
    return broker.NetworkBrokerReadyRecord(
        version="AOSBROKERREADY/1",
        event="NETWORK_BROKER_READY",
        ready=models.BrokerReadyEvidence(
            task_id="task-boundary",
            task_generation=9,
            launch_nonce="cd" * 16,
            policy_digest="a" * 64,
            broker_pid=123,
            broker_start_time_ticks=456,
            broker_boot_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            ready_at_monotonic_ns=789,
        ),
        process=models.BrokerProcessEvidence(
            pid=123,
            start_time_ticks=456,
            boot_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        ),
        listener=models.ListenerEvidence(
            family=int(socket.AF_INET),
            socket_type=int(socket.SOCK_STREAM),
            address="127.0.0.1",
            port=18080,
            device=10,
            inode=20,
            file_type=stat.S_IFSOCK,
            netns_cookie=30,
            accepting=True,
        ),
        sealed_policy=broker.SealedPolicyEvidence(
            device=40,
            inode=50,
            size=60,
            seals=70,
        ),
        runtime_identity=broker.ObservedFileIdentity(101, 201, stat.S_IFDIR),
        broker_code_identity=broker.ObservedFileIdentity(102, 202, stat.S_IFREG),
        identity_code_identity=broker.ObservedFileIdentity(103, 203, stat.S_IFREG),
        models_code_identity=broker.ObservedFileIdentity(104, 204, stat.S_IFREG),
        interpreter_identity=broker.ObservedFileIdentity(105, 205, stat.S_IFREG),
        boundary=broker.BrokerBoundaryEvidence(
            proc_status=broker.ProcStatusEvidence(0, 0, 0, 0, 0, 1),
            environment=broker.EnvironmentEvidence(
                names=tuple(dict(broker.BROKER_ENVIRONMENT)),
                digest="b" * 64,
            ),
            filesystem_digest="c" * 64,
            fd_numbers=(0, 1, 2, 30, 31, 32, 33, 34),
            cgroup="/user.slice/task.scope",
            namespaces=(
                ("ipc", 11),
                ("mnt", 12),
                ("net", 13),
                ("pid", 14),
                ("user", 15),
                ("uts", 16),
            ),
        ),
    )


def test_broker_ready_record_is_canonical_bounded_and_one_shot():
    broker = _network_broker()
    record = _ready_record(broker)
    payload = record.to_bytes()

    assert len(payload) <= broker.MAX_READY_BYTES
    assert payload == json.dumps(
        json.loads(payload),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    assert broker.NetworkBrokerReadyRecord.from_bytes(payload) == record

    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        broker.emit_network_broker_ready(sender.fileno(), record)
        assert receiver.recv(broker.MAX_READY_BYTES + 1) == payload
        assert receiver.recv(1) == b""
    finally:
        sender.close()
        receiver.close()


def test_broker_ready_record_rejects_nonfixed_listener_or_process_mismatch():
    broker = _network_broker()
    record = _ready_record(broker)

    with pytest.raises(broker.BrokerBoundaryError, match="listener"):
        dataclasses.replace(
            record,
            listener=dataclasses.replace(record.listener, address="127.0.0.2"),
        )
    with pytest.raises(broker.BrokerBoundaryError, match="identities"):
        dataclasses.replace(
            record,
            process=dataclasses.replace(record.process, pid=999),
        )


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"{malformed}",
        b'{"event":"NETWORK_BROKER_READY"}',
        b'{"event":"NETWORK_BROKER_READY","event":"NETWORK_BROKER_READY"}',
        b"x" * 16384,
    ],
)
def test_broker_ready_parser_rejects_malformed_duplicate_or_oversized(payload):
    broker = _network_broker()
    with pytest.raises(broker.BrokerBoundaryError):
        broker.NetworkBrokerReadyRecord.from_bytes(payload)


def _relay_policy(*, mode=None, lifetime_ns=5_000_000_000, byte_limit=4096):
    models = _network_models()
    now = time.monotonic_ns()
    return _boundary_policy(
        models,
        mode=mode or models.TransportMode.SYNTHETIC_FIXTURE_FD,
        activated_at_monotonic_ns=now - 1_000_000,
        expires_at_monotonic_ns=now + lifetime_ns,
        byte_limit=byte_limit,
        connection_limit=1,
    )


def _dup_cloexec(fd):
    return fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 100)


def _run_relay_thread(broker, policy, listener, fixture, control):
    owned = (
        _dup_cloexec(listener.fileno()),
        None if fixture is None else _dup_cloexec(fixture.fileno()),
        _dup_cloexec(control.fileno()),
    )
    outcomes = []

    def run():
        try:
            outcomes.append(
                broker.serve_transport(
                    policy,
                    listener_fd=owned[0],
                    fixture_fd=owned[1],
                    control_fd=owned[2],
                )
            )
        except BaseException as exc:
            outcomes.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    return thread, outcomes, owned


class _ScriptedRelaySelector:
    def __init__(self, broker, steps):
        self._broker = broker
        self._steps = list(steps)
        self._keys = {}

    def register(self, fileobj, events, data=None):
        if fileobj in self._keys:
            raise KeyError(fileobj)
        key = self._broker.selectors.SelectorKey(
            fileobj, fileobj.fileno(), events, data
        )
        self._keys[fileobj] = key
        return key

    def unregister(self, fileobj):
        try:
            return self._keys.pop(fileobj)
        except KeyError:
            raise KeyError(fileobj) from None

    def key(self, fileobj):
        return self._keys[fileobj]

    def select(self, _timeout=None):
        if not self._steps:
            return []
        return self._steps.pop(0)(self)

    def close(self):
        self._keys.clear()


def test_broker_revoke_preempts_simultaneous_endpoint_io(monkeypatch):
    broker = _network_broker()
    fixture_broker, fixture_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    control_broker, control_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    payload = b"must-remain-after-revoke"
    with _fixed_listener() as listener:
        scripted = _ScriptedRelaySelector(
            broker,
            [
                lambda selected: [
                    (selected.key(listener), broker.selectors.EVENT_READ)
                ],
                lambda selected: [
                    (selected.key(fixture_broker), broker.selectors.EVENT_READ),
                    (selected.key(control_broker), broker.selectors.EVENT_READ),
                ],
            ],
        )
        monkeypatch.setattr(
            broker.selectors, "DefaultSelector", lambda: scripted
        )
        try:
            client.connect(("127.0.0.1", 18080))
            fixture_peer.sendall(payload)
            control_peer.send(broker.CONTROL_REVOKE)

            outcome = broker._relay_loop(
                _relay_policy(), listener, fixture_broker, control_broker
            )

            assert outcome is broker.TransportTermination.REVOKED
            assert fixture_broker.recv(len(payload)) == payload
        finally:
            client.close()
            fixture_broker.close()
            fixture_peer.close()
            control_broker.close()
            control_peer.close()


def test_broker_expiry_crossed_during_select_preempts_endpoint_io(monkeypatch):
    broker = _network_broker()
    fixture_broker, fixture_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    control_broker, control_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    payload = b"must-remain-after-expiry"
    policy = _relay_policy()
    clock = {"now": policy.expires_at_monotonic_ns - 1}

    def expire_then_report_fixture(selected):
        clock["now"] = policy.expires_at_monotonic_ns
        return [(selected.key(fixture_broker), broker.selectors.EVENT_READ)]

    with _fixed_listener() as listener:
        scripted = _ScriptedRelaySelector(
            broker,
            [
                lambda selected: [
                    (selected.key(listener), broker.selectors.EVENT_READ)
                ],
                expire_then_report_fixture,
            ],
        )
        monkeypatch.setattr(
            broker.selectors, "DefaultSelector", lambda: scripted
        )
        monkeypatch.setattr(broker.time, "monotonic_ns", lambda: clock["now"])
        try:
            client.connect(("127.0.0.1", 18080))
            fixture_peer.sendall(payload)

            outcome = broker._relay_loop(
                policy, listener, fixture_broker, control_broker
            )

            assert outcome is broker.TransportTermination.EXPIRED
            assert fixture_broker.recv(len(payload)) == payload
        finally:
            client.close()
            fixture_broker.close()
            fixture_peer.close()
            control_broker.close()
            control_peer.close()


def test_broker_relay_never_reads_beyond_exact_buffer_capacity(monkeypatch):
    broker = _network_broker()
    fixture_broker, fixture_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    control_broker, control_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    payload = b"0123456789abcdefghijklmnopqrstuv"
    assert len(payload) == 32
    with _fixed_listener() as listener:
        scripted = _ScriptedRelaySelector(
            broker,
            [
                lambda selected: [
                    (selected.key(listener), broker.selectors.EVENT_READ)
                ],
                lambda selected: [
                    (selected.key(fixture_broker), broker.selectors.EVENT_READ)
                ],
                lambda selected: [
                    (selected.key(fixture_broker), broker.selectors.EVENT_READ)
                ],
                lambda selected: [
                    (selected.key(control_broker), broker.selectors.EVENT_READ)
                ],
            ],
        )
        monkeypatch.setattr(
            broker.selectors, "DefaultSelector", lambda: scripted
        )
        monkeypatch.setattr(broker, "RELAY_BUFFER_BYTES", 20)
        monkeypatch.setattr(broker, "RELAY_CHUNK_BYTES", 16)
        try:
            client.connect(("127.0.0.1", 18080))
            fixture_peer.sendall(payload)
            control_peer.send(broker.CONTROL_REVOKE)

            outcome = broker._relay_loop(
                _relay_policy(byte_limit=128),
                listener,
                fixture_broker,
                control_broker,
            )

            assert outcome is broker.TransportTermination.REVOKED
            assert fixture_broker.recv(len(payload)) == payload[20:]
        finally:
            client.close()
            fixture_broker.close()
            fixture_peer.close()
            control_broker.close()
            control_peer.close()


def test_broker_synthetic_fixture_relays_only_inherited_socket_and_revokes_cleanly():
    broker = _network_broker()
    fixture_broker, fixture_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    control_broker, control_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with _fixed_listener() as listener:
        thread, outcomes, owned = _run_relay_thread(
            broker,
            _relay_policy(),
            listener,
            fixture_broker,
            control_broker,
        )
        try:
            client.settimeout(2)
            fixture_peer.settimeout(2)
            client.connect(("127.0.0.1", 18080))
            client.sendall(b"from-worker")
            assert fixture_peer.recv(64) == b"from-worker"
            fixture_peer.sendall(b"from-fixture")
            assert client.recv(64) == b"from-fixture"
            control_peer.send(b"AOSBROKERCTL/1 REVOKE\n")
            thread.join(3)
            assert not thread.is_alive()
            assert outcomes == [broker.TransportTermination.REVOKED]
            for fd in owned:
                if fd is not None:
                    with pytest.raises(OSError) as closed:
                        fcntl.fcntl(fd, fcntl.F_GETFD)
                    assert closed.value.errno == errno.EBADF
        finally:
            client.close()
            fixture_broker.close()
            fixture_peer.close()
            control_broker.close()
            control_peer.close()


def test_broker_deny_mode_never_accepts_listener():
    broker = _network_broker()
    models = _network_models()
    control_broker, control_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with _fixed_listener() as listener:
        policy = _relay_policy(
            mode=models.TransportMode.DENY,
            lifetime_ns=150_000_000,
        )
        thread, outcomes, _owned = _run_relay_thread(
            broker, policy, listener, None, control_broker
        )
        try:
            client.connect(("127.0.0.1", 18080))
            thread.join(2)
            assert not thread.is_alive()
            assert outcomes == [broker.TransportTermination.EXPIRED]
            listener.setblocking(False)
            accepted, _address = listener.accept()
            broker._abort_socket(accepted)
        finally:
            client.close()
            control_broker.close()
            control_peer.close()


@pytest.mark.parametrize(
    ("control_payload", "expected"),
    [
        (b"", "CONTROL_EOF"),
        (b"malformed", "MALFORMED_CONTROL"),
        (b"AOSBROKERCTL/1 REVOKE\n", "REVOKED"),
    ],
)
def test_broker_control_eof_revoke_or_malformed_terminates_fail_closed(
    control_payload, expected
):
    broker = _network_broker()
    models = _network_models()
    control_broker, control_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with _fixed_listener() as listener:
        thread, outcomes, _owned = _run_relay_thread(
            broker,
            _relay_policy(mode=models.TransportMode.DENY),
            listener,
            None,
            control_broker,
        )
        try:
            if control_payload:
                control_peer.send(control_payload)
            else:
                control_peer.shutdown(socket.SHUT_WR)
            thread.join(2)
            assert not thread.is_alive()
            assert outcomes == [getattr(broker.TransportTermination, expected)]
        finally:
            control_broker.close()
            control_peer.close()


def test_broker_malformed_control_closes_received_ancillary_descriptors():
    broker = _network_broker()
    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    try:
        baseline = _open_fd_numbers()
        sender.sendmsg(
            [b"malformed"],
            [
                (
                    socket.SOL_SOCKET,
                    socket.SCM_RIGHTS,
                    array.array("i", [read_fd]).tobytes(),
                )
            ],
        )
        assert broker._read_control(receiver) is broker.TransportTermination.MALFORMED_CONTROL
        assert _open_fd_numbers() == baseline
    finally:
        os.close(read_fd)
        os.close(write_fd)
        receiver.close()
        sender.close()


def test_broker_byte_limit_fails_closed():
    broker = _network_broker()
    fixture_broker, fixture_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    control_broker, control_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with _fixed_listener() as listener:
        thread, outcomes, _owned = _run_relay_thread(
            broker,
            _relay_policy(byte_limit=4),
            listener,
            fixture_broker,
            control_broker,
        )
        try:
            first.connect(("127.0.0.1", 18080))
            first.sendall(b"12345")
            thread.join(2)
            assert not thread.is_alive()
            assert outcomes == [broker.TransportTermination.BYTE_LIMIT]
            fixture_peer.settimeout(1)
            assert len(fixture_peer.recv(64)) <= 4
        finally:
            first.close()
            fixture_broker.close()
            fixture_peer.close()
            control_broker.close()
            control_peer.close()


def test_broker_extra_connection_fails_closed():
    broker = _network_broker()
    fixture_broker, fixture_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    control_broker, control_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    second = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with _fixed_listener() as listener:
        thread, outcomes, _owned = _run_relay_thread(
            broker,
            _relay_policy(),
            listener,
            fixture_broker,
            control_broker,
        )
        try:
            fixture_peer.settimeout(2)
            first.connect(("127.0.0.1", 18080))
            first.sendall(b"first")
            assert fixture_peer.recv(16) == b"first"
            second.connect(("127.0.0.1", 18080))
            thread.join(2)
            assert not thread.is_alive()
            assert outcomes == [broker.TransportTermination.CONNECTION_LIMIT]
        finally:
            first.close()
            second.close()
            fixture_broker.close()
            fixture_peer.close()
            control_broker.close()
            control_peer.close()


def test_broker_fixture_rejects_wrong_fd_type_or_unconnected_socket():
    broker = _network_broker()
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    unconnected = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    try:
        with pytest.raises(broker.BrokerBoundaryError):
            broker.validate_fixture_fd(read_fd)
        with pytest.raises(broker.BrokerBoundaryError):
            broker.validate_fixture_fd(unconnected.fileno())
    finally:
        os.close(read_fd)
        os.close(write_fd)
        unconnected.close()


def test_broker_transport_validation_failure_closes_every_owned_descriptor():
    broker = _network_broker()
    control_broker, control_peer = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET
    )
    bad_fixture_r, bad_fixture_w = os.pipe2(os.O_CLOEXEC)
    with _fixed_listener() as listener:
        owned = (
            _dup_cloexec(listener.fileno()),
            _dup_cloexec(bad_fixture_r),
            _dup_cloexec(control_broker.fileno()),
        )
        try:
            with pytest.raises(broker.BrokerBoundaryError):
                broker.serve_transport(
                    _relay_policy(),
                    listener_fd=owned[0],
                    fixture_fd=owned[1],
                    control_fd=owned[2],
                )
            for fd in owned:
                with pytest.raises(OSError) as closed:
                    fcntl.fcntl(fd, fcntl.F_GETFD)
                assert closed.value.errno == errno.EBADF
        finally:
            for fd in owned:
                try:
                    os.close(fd)
                except OSError:
                    pass
            os.close(bad_fixture_r)
            os.close(bad_fixture_w)
            control_broker.close()
            control_peer.close()


def test_broker_rejects_distinct_fd_numbers_that_alias_one_kernel_object():
    broker = _network_broker()
    first, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    alias_fd = fcntl.fcntl(first.fileno(), fcntl.F_DUPFD_CLOEXEC, 100)
    try:
        with pytest.raises(broker.BrokerBoundaryError, match="alias"):
            broker._require_distinct_fd_identities((first.fileno(), alias_fd))
    finally:
        os.close(alias_fd)
        first.close()
        peer.close()


def test_broker_source_has_no_outbound_resolution_or_protocol_surface():
    module = _network_broker()
    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = __import__("ast").parse(source)
    forbidden_calls = {
        "connect",
        "connect_ex",
        "create_connection",
        "getaddrinfo",
        "gethostbyname",
    }
    observed_calls = {
        node.func.attr
        for node in __import__("ast").walk(tree)
        if isinstance(node, __import__("ast").Call)
        and isinstance(node.func, __import__("ast").Attribute)
    }
    assert forbidden_calls.isdisjoint(observed_calls)
    for forbidden_import in ("ssl", "http", "urllib"):
        assert not any(
            (
                isinstance(node, __import__("ast").Import)
                and any(alias.name == forbidden_import for alias in node.names)
            )
            or (
                isinstance(node, __import__("ast").ImportFrom)
                and node.module == forbidden_import
            )
            for node in __import__("ast").walk(tree)
        )


@pytest.fixture(scope="module")
def task_supervisor_binary(tmp_path_factory):
    source = (
        Path(__file__).parents[2]
        / "native"
        / "task_supervisor"
        / "task_supervisor.c"
    )
    output = tmp_path_factory.mktemp("task-supervisor") / "task_supervisor"
    subprocess.run(
        [
            "cc",
            "-std=c11",
            "-D_GNU_SOURCE",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O2",
            str(source),
            "-o",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return output


def _run_native_supervisor(
    binary,
    contract_argv,
    *,
    status_is_pipe=True,
    pass_fd_numbers=(),
    aliased_pass_pair=None,
    aliased_pass_kind=None,
):
    bwrap_fd = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
    pass_sources = {}
    for target in pass_fd_numbers:
        raw = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        try:
            pass_sources[target] = fcntl.fcntl(
                raw, fcntl.F_DUPFD_CLOEXEC, 128
            )
        finally:
            os.close(raw)
    if aliased_pass_pair is not None:
        source_target, alias_target = aliased_pass_pair
        if (
            source_target not in pass_sources
            or alias_target not in pass_sources
            or source_target == alias_target
            or aliased_pass_kind not in {"pipe", "socket"}
        ):
            raise ValueError("invalid aliased pass-descriptor fixture")
        os.close(pass_sources.pop(source_target))
        os.close(pass_sources.pop(alias_target))
        if aliased_pass_kind == "socket":
            source, peer = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC
            )
            source_fd = source.fileno()
            close_sources = (source, peer)
        else:
            source_fd, peer_fd = os.pipe2(os.O_CLOEXEC)
            close_sources = (source_fd, peer_fd)
        try:
            pass_sources[source_target] = fcntl.fcntl(
                source_fd, fcntl.F_DUPFD_CLOEXEC, 128
            )
            pass_sources[alias_target] = fcntl.fcntl(
                source_fd, fcntl.F_DUPFD_CLOEXEC, 128
            )
        finally:
            for owned_source in close_sources:
                if type(owned_source) is socket.socket:
                    owned_source.close()
                else:
                    os.close(owned_source)
    status_r = status_w = -1
    if status_is_pipe:
        status_r, status_w = os.pipe2(os.O_CLOEXEC)
    else:
        status_w = os.open("/dev/null", os.O_WRONLY | os.O_CLOEXEC)
    output_r, output_w = os.pipe2(os.O_CLOEXEC)
    pid = os.fork()
    if pid == 0:
        try:
            if status_r >= 0:
                os.close(status_r)
            os.close(output_r)
            os.dup2(bwrap_fd, 5, inheritable=True)
            os.dup2(status_w, 6, inheritable=True)
            os.dup2(output_w, 1, inheritable=True)
            os.dup2(output_w, 2, inheritable=True)
            for target, source in pass_sources.items():
                os.dup2(source, target, inheritable=True)
            keep = {0, 1, 2, 5, 6, *pass_fd_numbers}
            for fd in (bwrap_fd, status_w, output_w, *pass_sources.values()):
                if fd not in keep:
                    os.close(fd)
            os.execve(
                str(binary),
                [str(binary), *contract_argv],
                {"PATH": "/definitely/not/used"},
            )
        except BaseException:
            os._exit(127)
    os.close(bwrap_fd)
    for fd in pass_sources.values():
        os.close(fd)
    os.close(status_w)
    os.close(output_w)
    _, wait_status = os.waitpid(pid, 0)
    status_bytes = b""
    if status_r >= 0:
        status_bytes = os.read(status_r, 4096)
        os.close(status_r)
    chunks = []
    while True:
        ready, _, _ = select.select([output_r], [], [], 1)
        if not ready:
            break
        chunk = os.read(output_r, 4096)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(output_r)
    return pid, wait_status, status_bytes, b"".join(chunks)


@pytest.mark.m4b_linux
def test_supervisor_partitions_broker_and_worker_capability_descriptors(
    task_supervisor_binary,
):
    _boundary, plan = _boundary_plan()
    program = (
        "import json,os,sys,time;"
        "fds=[fd for fd in range(3,64) "
        "if os.path.exists('/proc/self/fd/'+str(fd))];"
        "print(json.dumps({'label':sys.argv[1],'fds':fds}),flush=True);"
        "time.sleep(0.1)"
    )
    broker_argv = ("bwrap", "-c", program, "broker")
    worker_argv = ("bwrap", "-c", program, "worker")
    broker_pass = plan.supervisor_contract.broker_pass_fds
    worker_pass = (40,)
    contract = plan.supervisor_contract.with_broker_argv(broker_argv)
    tokens = contract.argument_tokens_for(
        worker_argv,
        worker_pass_fds=worker_pass,
    )

    _pid, wait_status, status_bytes, output = _run_native_supervisor(
        task_supervisor_binary,
        tokens,
        pass_fd_numbers=(*broker_pass, *worker_pass),
    )

    assert os.waitstatus_to_exitcode(wait_status) == 0
    assert status_bytes.startswith(b"AOSSUP/1 BROKER_PID ")
    records = {
        record["label"]: record
        for record in (
            json.loads(line) for line in output.splitlines() if line.startswith(b"{")
        )
    }
    assert records["broker"]["fds"] == list(broker_pass)
    assert records["worker"]["fds"] == list(worker_pass)


@pytest.mark.m4b_linux
@pytest.mark.parametrize("alias_kind", ["socket", "pipe"])
def test_supervisor_rejects_cross_branch_open_file_description_aliases(
    task_supervisor_binary,
    alias_kind,
):
    boundary, plan = _boundary_plan()
    broker_argv = ("bwrap", "-c", "raise SystemExit(97)")
    worker_argv = ("bwrap", "-c", "raise SystemExit(98)")
    worker_pass = (40,)
    contract = plan.supervisor_contract.with_broker_argv(broker_argv)
    tokens = contract.argument_tokens_for(
        worker_argv,
        worker_pass_fds=worker_pass,
    )

    _pid, wait_status, status_bytes, output = _run_native_supervisor(
        task_supervisor_binary,
        tokens,
        pass_fd_numbers=(*contract.broker_pass_fds, *worker_pass),
        aliased_pass_pair=(boundary.BROKER_CONTROL_FD, worker_pass[0]),
        aliased_pass_kind=alias_kind,
    )

    assert os.waitstatus_to_exitcode(wait_status) == 66
    assert status_bytes == b""
    assert output == b"AOSSUP/1 ERROR pass_fds 22\n"


@pytest.mark.m4b_linux
def test_supervisor_execveat_reports_one_broker_pid_and_preserves_same_cgroup(
    task_supervisor_binary,
):
    _boundary, plan = _boundary_plan()
    program = (
        "import json,os,sys,time;"
        "print(json.dumps({'label':sys.argv[1],'pid':os.getpid(),"
        "'cgroup':open('/proc/self/cgroup').read(),"
        "'argv':sys.argv[1:],'env':sorted(os.environ)}),flush=True);"
        "time.sleep(float(sys.argv[2]))"
    )
    broker_argv = ("bwrap", "-c", program, "broker", "0.15")
    worker_argv = ("bwrap", "-c", program, "worker", "0.25")
    contract = plan.supervisor_contract.with_broker_argv(broker_argv)
    full = contract.argv_for(worker_argv)

    root_pid, wait_status, status_bytes, output = _run_native_supervisor(
        task_supervisor_binary,
        full[1:],
        pass_fd_numbers=plan.supervisor_contract.broker_pass_fds,
    )

    assert os.waitstatus_to_exitcode(wait_status) == 0
    status_line = status_bytes.decode("ascii").strip().split()
    assert status_line[:2] == ["AOSSUP/1", "BROKER_PID"]
    broker_pid = int(status_line[2])
    records = [json.loads(line) for line in output.splitlines() if line.startswith(b"{")]
    assert {record["label"] for record in records} == {"broker", "worker"}
    by_label = {record["label"]: record for record in records}
    assert by_label["broker"]["pid"] == broker_pid
    assert by_label["worker"]["pid"] == root_pid
    assert by_label["broker"]["cgroup"] == by_label["worker"]["cgroup"]
    assert by_label["broker"]["argv"] == ["broker", "0.15"]
    assert by_label["worker"]["argv"] == ["worker", "0.25"]
    assert by_label["broker"]["env"] == ["LANG", "LC_ALL"]
    assert by_label["worker"]["env"] == ["LANG", "LC_ALL"]
    deadline = time.monotonic() + 2
    while Path(f"/proc/{broker_pid}").exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not Path(f"/proc/{broker_pid}").exists()


@pytest.mark.m4b_linux
def test_supervisor_accepts_the_minimal_one_item_bounded_vectors(
    task_supervisor_binary,
):
    _boundary, plan = _boundary_plan()
    contract = plan.supervisor_contract.with_broker_argv(("bwrap",))
    full = contract.argv_for(("bwrap",))

    _pid, wait_status, status_bytes, _output = _run_native_supervisor(
        task_supervisor_binary,
        full[1:],
        pass_fd_numbers=plan.supervisor_contract.broker_pass_fds,
    )

    assert os.waitstatus_to_exitcode(wait_status) == 0
    assert status_bytes.startswith(b"AOSSUP/1 BROKER_PID ")


@pytest.mark.m4b_linux
@pytest.mark.parametrize(
    "tokens",
    [
        (),
        ("AOSSUP/2",),
        ("AOSSUP/1", "bwrap_fd", "+5"),
        ("AOSSUP/1", "bwrap_fd", "05"),
        ("AOSSUP/1", "unknown", "5"),
    ],
)
def test_supervisor_rejects_malformed_contract_without_shell_or_path_lookup(
    task_supervisor_binary, tokens
):
    completed = subprocess.run(
        [str(task_supervisor_binary), *tokens],
        env={"PATH": "/definitely/not/used"},
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert completed.returncode != 0


@pytest.mark.m4b_linux
@pytest.mark.parametrize(
    ("worker_values", "broker_first"),
    [
        (("8",), "8"),
        (("40", "40"), "8"),
        (("5",), "8"),
        (("6",), "8"),
        ((str(1 << 31),), "8"),
        ((), "9"),
    ],
)
def test_supervisor_native_contract_rejects_overlapping_duplicate_reserved_or_unknown_pass_fds(
    task_supervisor_binary,
    worker_values,
    broker_first,
):
    _boundary, plan = _boundary_plan()
    broker_values = [str(fd) for fd in plan.supervisor_contract.broker_pass_fds]
    broker_values[0] = broker_first
    tokens = (
        "AOSSUP/1",
        "bwrap_fd",
        "5",
        "status_fd",
        "6",
        "broker_passc",
        str(len(broker_values)),
        "broker_pass",
        *broker_values,
        "worker_passc",
        str(len(worker_values)),
        "worker_pass",
        *worker_values,
        "broker_argc",
        "1",
        "broker",
        "bwrap",
        "worker_argc",
        "1",
        "worker",
        "bwrap",
        "END",
    )

    completed = subprocess.run(
        [str(task_supervisor_binary), *tokens],
        capture_output=True,
        timeout=5,
        check=False,
    )

    assert completed.returncode == 64
    assert completed.stderr == b"AOSSUP/1 ERROR contract 22\n"


@pytest.mark.m4b_linux
def test_supervisor_rejects_wrong_status_descriptor_type_before_fork(
    task_supervisor_binary,
):
    _boundary, plan = _boundary_plan()
    contract = plan.supervisor_contract.with_broker_argv(
        ("bwrap", "-c", "raise SystemExit(99)")
    )
    full = contract.argv_for(("bwrap", "-c", "raise SystemExit(98)"))

    _pid, wait_status, status_bytes, output = _run_native_supervisor(
        task_supervisor_binary,
        full[1:],
        status_is_pipe=False,
        pass_fd_numbers=plan.supervisor_contract.broker_pass_fds,
    )

    assert os.waitstatus_to_exitcode(wait_status) != 0
    assert status_bytes == b""
    assert output == b"AOSSUP/1 ERROR descriptors 9\n"


@pytest.mark.m4b_linux
def test_broker_boundary_real_bwrap_bootstrap_emits_strict_readiness(
    task_supervisor_binary,
):
    boundary = _network_boundary()
    broker = _network_broker()
    identity = _network_identity()
    models = _network_models()
    repo_root = Path(__file__).parents[2]
    policy = _boundary_policy(
        models,
        mode=models.TransportMode.DENY,
        expires_at_monotonic_ns=time.monotonic_ns() + 30_000_000_000,
    )

    opened = []

    def source(path, fixed_fd, expected_type):
        flags = os.O_PATH | os.O_CLOEXEC
        if expected_type == stat.S_IFDIR:
            flags |= os.O_DIRECTORY
        fd = os.open(path, flags)
        opened.append(fd)
        observed = os.fstat(fd)
        return boundary.AuthorizedSource(
            locator=Path(path).resolve(),
            fd=fixed_fd,
            identity=boundary.FileIdentity.from_stat(observed),
        )

    sources = {
        "runtime_usr": source("/usr", boundary.BROKER_RUNTIME_USR_FD, stat.S_IFDIR),
        "broker_code": source(
            repo_root / "src/agenticos/sandbox/network_broker.py",
            boundary.BROKER_CODE_FD,
            stat.S_IFREG,
        ),
        "identity_code": source(
            repo_root / "src/agenticos/sandbox/network_identity.py",
            boundary.BROKER_IDENTITY_CODE_FD,
            stat.S_IFREG,
        ),
        "models_code": source(
            repo_root / "src/agenticos/sandbox/network_models.py",
            boundary.BROKER_MODELS_CODE_FD,
            stat.S_IFREG,
        ),
        "supervisor": source(
            task_supervisor_binary,
            boundary.SUPERVISOR_EXECUTABLE_FD,
            stat.S_IFREG,
        ),
    }
    plan = boundary.build_network_boundary_plan(
        transport_policy=policy,
        **sources,
    )
    policy_fd = identity.create_sealed_policy_fd(policy)
    handoff_sender, handoff_broker = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
    )
    status_broker, status_receiver = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
    )
    control_broker, control_sender = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC
    )
    json_r, json_w = os.pipe2(os.O_CLOEXEC)
    bwrap_fd = os.open("/usr/bin/bwrap", os.O_RDONLY | os.O_CLOEXEC)
    with _fixed_listener() as listener:
        frame = identity.ListenerAdoptionFrame(
            version="AOSLISTENER/1",
            task_id=policy.task_id,
            task_generation=policy.task_generation,
            launch_nonce=policy.launch_nonce,
            policy_digest=models.policy_digest(policy),
            evidence=identity.listener_evidence(listener.fileno()),
        )
        identity.send_listener_fd(handoff_sender, listener.fileno(), frame)

        child_sources = {
            boundary.BROKER_JSON_STATUS_FD: json_w,
            boundary.BROKER_RUNTIME_USR_FD: opened[0],
            boundary.BROKER_CODE_FD: opened[1],
            boundary.BROKER_IDENTITY_CODE_FD: opened[2],
            boundary.BROKER_MODELS_CODE_FD: opened[3],
            broker.BROKER_POLICY_FD: policy_fd,
            broker.BROKER_HANDOFF_FD: handoff_broker.fileno(),
            broker.BROKER_STATUS_FD: status_broker.fileno(),
            broker.BROKER_CONTROL_FD: control_broker.fileno(),
        }
        high_sources = {
            target: fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 100)
            for target, fd in child_sources.items()
        }
        high_bwrap = fcntl.fcntl(bwrap_fd, fcntl.F_DUPFD_CLOEXEC, 100)
        child_pid = os.fork()
        if child_pid == 0:
            try:
                os.dup2(high_bwrap, 19, inheritable=False)
                for target, high_fd in high_sources.items():
                    os.dup2(high_fd, target, inheritable=True)
                keep = {0, 1, 2, 19, *child_sources}
                for name in os.listdir("/proc/self/fd"):
                    fd = int(name)
                    if fd not in keep:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                argv = list(plan.broker_bwrap_argv)
                argv[0] = "/proc/self/fd/19"
                os.execve(argv[0], argv, {})
            except BaseException:
                os._exit(127)

        for fd in (*high_sources.values(), high_bwrap):
            os.close(fd)
        os.close(json_w)
        status_broker.close()
        control_broker.close()
        handoff_broker.close()
        status_receiver.settimeout(10)
        try:
            setup = boundary.read_broker_bwrap_setup_status(json_r, timeout=10)
            payload = status_receiver.recv(broker.MAX_READY_BYTES + 1)
            record = broker.NetworkBrokerReadyRecord.from_bytes(payload)
            assert setup.child_pid > 0
            assert "net" not in dict(setup.reported_namespaces)
            assert record.ready.task_id == policy.task_id
            assert record.ready.policy_digest == models.policy_digest(policy)
            assert record.listener == frame.evidence
            assert record.boundary.proc_status == broker.ProcStatusEvidence(
                0, 0, 0, 0, 0, 1
            )
            assert record.boundary.fd_numbers == (0, 1, 2, 30, 31, 32, 33)
            assert record.runtime_identity == plan.broker_contract.runtime_identity
            assert (
                record.broker_code_identity
                == plan.broker_contract.broker_code_identity
            )
            assert status_receiver.recv(1) == b""
            control_sender.send(b"AOSBROKERCTL/1 REVOKE\n")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                waited, wait_status = os.waitpid(child_pid, os.WNOHANG)
                if waited == child_pid:
                    assert os.waitstatus_to_exitcode(wait_status) == 0
                    break
                time.sleep(0.01)
            else:
                os.kill(child_pid, 9)
                os.waitpid(child_pid, 0)
                pytest.fail("real broker boundary did not terminate after revocation")
        finally:
            try:
                waited, _status = os.waitpid(child_pid, os.WNOHANG)
            except ChildProcessError:
                waited = child_pid
            if waited == 0:
                os.kill(child_pid, 9)
                os.waitpid(child_pid, 0)
            try:
                os.close(json_r)
            except OSError:
                pass
            status_receiver.close()
            control_sender.close()
            handoff_sender.close()
            for fd in (policy_fd, bwrap_fd, *opened):
                try:
                    os.close(fd)
                except OSError:
                    pass
