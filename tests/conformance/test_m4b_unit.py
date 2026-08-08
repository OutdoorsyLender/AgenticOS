"""Unit tests for the M4B network capability transport contract."""

from __future__ import annotations

import dataclasses
import hashlib
import importlib
import importlib.util
import json

import pytest


MODULE = "agenticos.sandbox.network_models"


def _network_models():
    """Load the public contract, producing a test failure until it exists."""
    try:
        return importlib.import_module(MODULE)
    except ModuleNotFoundError as exc:
        pytest.fail(f"M4B transport contract is missing: {exc}")


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
