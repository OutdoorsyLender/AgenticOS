"""Adversarial-review regression tests for the M4B-2 HTTPS evidence reader.

Each test pins one fail-closed branch of
``m4b_runner._read_authenticated_https_transport_records``:

* Evidence F1 (untested fail-closed branches): non-contiguous connection
  indexes, aggregate-vs-per-record accounting disagreement, evidence
  exceeding connection/byte authority, premature EXPIRED terminal and
  post-expiry terminal, per-record and terminal synthetic-marking
  mismatch, MSG_TRUNC/oversized packets, unauthorized ancillary metadata,
  pre-activation timestamps, and EOF timeout — every one must reject
  closed with a typed CapabilityTransportError.
* Evidence F2 (address-policy binding): a connection record whose
  ``address_policy_version`` is not the frozen ADDRESS_POLICY_VERSION is
  evidence from a policy this run never authorized; the reader rejects
  it before any accounting runs.

The harness speaks the real wire protocol (AOSHTTPEV/1 records over an
AF_UNIX SOCK_SEQPACKET control channel) using the production record
types, so a rejection assertion can only pass if the reader itself
fails closed.
"""

from __future__ import annotations

import array
import socket
import sys
import time

import pytest

if not sys.platform.startswith("linux"):
    pytest.skip("M4B-2 evidence reader regression tests require Linux",
                allow_module_level=True)

from agenticos.sandbox import m4b_runner as runner
from agenticos.sandbox import network_broker as broker
from agenticos.sandbox.network_models import (
    TransportMode,
    TransportPolicy,
    policy_digest,
)
from agenticos.sandbox.special_addresses import ADDRESS_POLICY_VERSION

_NETWORK_POLICY_DIGEST = "cd" * 32
_LAUNCH_NONCE = "ab" * 16


def _policy(**overrides):
    now = time.monotonic_ns()
    fields = {
        "version": "AOSNET/1",
        "task_id": "task-evidence-regression",
        "task_generation": 1,
        "launch_nonce": _LAUNCH_NONCE,
        "mode": TransportMode.SYNTHETIC_FIXTURE_FD,
        "proxy_host": "127.0.0.1",
        "proxy_port": 18080,
        "activated_at_monotonic_ns": now,
        "expires_at_monotonic_ns": now + 30_000_000_000,
        "connection_limit": 4,
        "byte_limit": 1_000_000,
    }
    fields.update(overrides)
    return TransportPolicy(**fields)


def _connection_record(policy, *, index=1, observed=None, synthetic=False,
                       w2o=4, o2w=6, discarded=2, requests=1, **overrides):
    """A valid per-connection record; keyword overrides break ONE thing."""
    fields = {
        "version": broker.HTTPS_EVIDENCE_VERSION,
        "event": broker.HTTPS_CONNECTION_EVENT,
        "task_id": policy.task_id,
        "task_generation": policy.task_generation,
        "launch_nonce": policy.launch_nonce,
        "policy_digest": policy_digest(policy),
        "network_policy_digest": _NETWORK_POLICY_DIGEST,
        "address_policy_version": ADDRESS_POLICY_VERSION,
        "connection_index": index,
        "stage_reached": broker.HttpsConnectionStage.HTTP,
        "terminal_reason": broker.HttpsConnectionTermination.COMPLETED,
        "detail": "worker_closed",
        "approved_hostname": "cdn.example.com",
        "connect_authority": "cdn.example.com",
        "worker_sni": "cdn.example.com",
        "http_host": "cdn.example.com",
        "origin_tls_name": "cdn.example.com",
        "identity_chain": "verified",
        "worker_tls_version": "TLSv1.3",
        "worker_alpn": "http/1.1",
        "origin_tls_version": "TLSv1.3",
        "origin_alpn": "http/1.1",
        "origin_peer_address": "93.184.216.34",
        "origin_peer_port": 443,
        "synthetic_origin": synthetic,
        "requests_completed": requests,
        "accounted_bytes": w2o + o2w + discarded,
        "worker_to_origin_bytes": w2o,
        "origin_to_worker_bytes": o2w,
        "total_bytes": w2o + o2w,
        "discarded_unsent_bytes": discarded,
        "observed_at_monotonic_ns": (
            observed if observed is not None else time.monotonic_ns()
        ),
    }
    fields.update(overrides)
    return broker.HttpsConnectionRecord(**fields)


def _terminal(policy, records, *, observed=None, synthetic=False,
              reason=broker.TransportTermination.REVOKED, **overrides):
    """The aggregate terminal consistent with ``records`` (unless broken)."""
    fields = {
        "version": broker.HTTPS_EVIDENCE_VERSION,
        "event": broker.HTTPS_TERMINAL_EVENT,
        "task_id": policy.task_id,
        "task_generation": policy.task_generation,
        "launch_nonce": policy.launch_nonce,
        "policy_digest": policy_digest(policy),
        "network_policy_digest": _NETWORK_POLICY_DIGEST,
        "observed_at_monotonic_ns": (
            observed if observed is not None else time.monotonic_ns()
        ),
        "connection_count": len(records),
        "accounted_bytes": sum(r.accounted_bytes for r in records),
        "worker_to_origin_bytes": sum(
            r.worker_to_origin_bytes for r in records
        ),
        "origin_to_worker_bytes": sum(
            r.origin_to_worker_bytes for r in records
        ),
        "total_bytes": sum(r.total_bytes for r in records),
        "discarded_unsent_bytes": sum(
            r.discarded_unsent_bytes for r in records
        ),
        "terminal_reason": reason,
        "synthetic_origin": synthetic,
    }
    fields.update(overrides)
    return broker.HttpsTransportTerminal(**fields)


def _read(policy, packets, *, budget=3.0, expect_synthetic=False):
    """Run the production reader against a seqpacket channel carrying
    ``packets`` (bytes), then EOF.  Returns the reader's return value."""
    writer, reader = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET
    )
    try:
        for packet in packets:
            writer.send(packet)
        writer.shutdown(socket.SHUT_WR)
        return runner._read_authenticated_https_transport_records(
            reader.fileno(),
            expected_policy=policy,
            expected_network_policy_digest=_NETWORK_POLICY_DIGEST,
            expect_synthetic=expect_synthetic,
            budget=budget,
        )
    finally:
        writer.close()
        reader.close()


def _read_raw(policy, send, *, budget=3.0):
    """Like _read but with full control over the sendmsg call."""
    writer, reader = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET
    )
    try:
        send(writer)
        writer.shutdown(socket.SHUT_WR)
        return runner._read_authenticated_https_transport_records(
            reader.fileno(),
            expected_policy=policy,
            expected_network_policy_digest=_NETWORK_POLICY_DIGEST,
            expect_synthetic=False,
            budget=budget,
        )
    finally:
        writer.close()
        reader.close()


# -- Positive controls: the harness is the real protocol -----------------------


def test_valid_records_and_terminal_are_accepted():
    policy = _policy()
    records = [
        _connection_record(policy, index=1),
        _connection_record(policy, index=2, w2o=1, o2w=1, discarded=0),
    ]
    terminal = _terminal(policy, records)
    result, read_records, broker_emitted = _read(
        policy, [r.to_bytes() for r in records] + [terminal.to_bytes()]
    )
    assert result == terminal
    assert read_records == tuple(records)
    assert broker_emitted is True


def test_eof_without_terminal_synthesizes_aggregate():
    policy = _policy()
    record = _connection_record(policy, index=1)
    terminal, records, broker_emitted = _read(policy, [record.to_bytes()])
    assert broker_emitted is False
    assert records == (record,)
    assert terminal.connection_count == 1
    assert terminal.accounted_bytes == record.accounted_bytes
    assert terminal.terminal_reason is broker.TransportTermination.REVOKED


# -- Evidence F2: address-policy version binding --------------------------------


def test_connection_record_with_foreign_address_policy_version_rejected():
    policy = _policy()
    record = _connection_record(
        policy, index=1, address_policy_version="AOSADDR/0+bogus"
    )
    with pytest.raises(
        runner.CapabilityTransportError,
        match="address policy version is unrecognized",
    ):
        _read(policy, [record.to_bytes()])


# -- Evidence F1: per-branch fail-closed rejections ------------------------------


def test_noncontiguous_connection_indexes_rejected():
    policy = _policy()
    records = [
        _connection_record(policy, index=1),
        _connection_record(policy, index=3),  # gap: index 2 never arrived
    ]
    terminal = _terminal(policy, records)
    with pytest.raises(
        runner.CapabilityTransportError,
        match="connection indexes are not the exact accepted set",
    ):
        _read(policy, [r.to_bytes() for r in records] + [terminal.to_bytes()])


def test_duplicate_connection_index_rejected():
    policy = _policy()
    records = [
        _connection_record(policy, index=1),
        _connection_record(policy, index=1),
    ]
    terminal = _terminal(policy, records)
    with pytest.raises(
        runner.CapabilityTransportError,
        match="connection indexes are not the exact accepted set",
    ):
        _read(policy, [r.to_bytes() for r in records] + [terminal.to_bytes()])


@pytest.mark.parametrize(
    "expect,broken",
    [
        ("terminal connection count disagrees", {"connection_count": 2}),
        (
            "terminal accounted_bytes disagrees",
            {"accounted_bytes": 13, "discarded_unsent_bytes": 3},
        ),
        # Each break keeps the terminal INTERNALLY consistent (total =
        # w2o + o2w, accounted = total + discarded) so exactly one named
        # field disagrees with the per-record sums.
        (
            "terminal worker_to_origin_bytes disagrees",
            {"worker_to_origin_bytes": 5, "total_bytes": 11,
             "discarded_unsent_bytes": 1},
        ),
        (
            "terminal origin_to_worker_bytes disagrees",
            {"origin_to_worker_bytes": 7, "total_bytes": 11,
             "discarded_unsent_bytes": 1},
        ),
    ],
)
def test_terminal_accounting_disagreement_rejected(expect, broken):
    """The aggregate terminal must equal the exact sum of the per-record
    evidence; any disagreement fails closed."""
    policy = _policy()
    record = _connection_record(policy, index=1)
    terminal = _terminal(policy, [record], **broken)
    with pytest.raises(runner.CapabilityTransportError, match=expect):
        _read(policy, [record.to_bytes(), terminal.to_bytes()])


def test_records_exceeding_connection_authority_rejected():
    policy = _policy(connection_limit=1)
    records = [
        _connection_record(policy, index=1),
        _connection_record(policy, index=2),
    ]
    with pytest.raises(
        runner.CapabilityTransportError,
        match="evidence exceeds connection authority",
    ):
        _read(policy, [r.to_bytes() for r in records])


def test_terminal_exceeding_byte_authority_rejected():
    policy = _policy(byte_limit=5)
    record = _connection_record(policy, index=1)  # accounted_bytes = 12
    terminal = _terminal(policy, [record])
    with pytest.raises(
        runner.CapabilityTransportError,
        match="terminal evidence exceeds policy authority",
    ):
        _read(policy, [record.to_bytes(), terminal.to_bytes()])


def test_premature_expired_terminal_rejected():
    """An EXPIRED terminal observed BEFORE the policy expired is forged."""
    policy = _policy()
    record = _connection_record(policy, index=1)
    terminal = _terminal(
        policy,
        [record],
        reason=broker.TransportTermination.EXPIRED,
        observed=policy.expires_at_monotonic_ns - 1,
    )
    with pytest.raises(
        runner.CapabilityTransportError, match="expiry evidence is premature"
    ):
        _read(policy, [record.to_bytes(), terminal.to_bytes()])


def test_post_expiry_terminal_rejected():
    """A non-EXPIRED terminal observed AT/AFTER expiry is forged."""
    policy = _policy()
    record = _connection_record(policy, index=1)
    terminal = _terminal(
        policy,
        [record],
        observed=policy.expires_at_monotonic_ns + 1,
    )
    with pytest.raises(
        runner.CapabilityTransportError,
        match="terminal evidence is after policy expiry",
    ):
        _read(policy, [record.to_bytes(), terminal.to_bytes()])


def test_connection_synthetic_marking_mismatch_rejected():
    policy = _policy()
    record = _connection_record(policy, index=1, synthetic=True)
    with pytest.raises(
        runner.CapabilityTransportError,
        match="connection synthetic marking disagrees",
    ):
        _read(policy, [record.to_bytes()])  # launch expects real origins


def test_terminal_synthetic_marking_mismatch_rejected():
    policy = _policy()
    record = _connection_record(policy, index=1)
    terminal = _terminal(policy, [record], synthetic=True)
    with pytest.raises(
        runner.CapabilityTransportError,
        match="terminal synthetic marking disagrees",
    ):
        _read(policy, [record.to_bytes(), terminal.to_bytes()])


def test_oversized_packet_msg_trunc_rejected():
    policy = _policy()
    oversized = b" " * (broker.MAX_HTTPS_EVIDENCE_BYTES + 2)
    with pytest.raises(
        runner.CapabilityTransportError, match="exceeded its bound"
    ):
        _read(policy, [oversized])


def test_ancillary_metadata_rejected():
    """A record smuggling an SCM_RIGHTS descriptor is unauthorized
    metadata, whatever the record payload says."""
    policy = _policy()
    record = _connection_record(policy, index=1)
    payload = record.to_bytes()
    donor = socket.socket()  # held open so the fd stays valid for sendmsg
    try:
        rights = array.array("i", [donor.fileno()])

        def send(writer):
            writer.sendmsg(
                [payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]
            )

        with pytest.raises(
            runner.CapabilityTransportError, match="unauthorized metadata"
        ):
            _read_raw(policy, send)
    finally:
        donor.close()


def test_pre_activation_timestamp_rejected():
    policy = _policy()
    record = _connection_record(
        policy, index=1, observed=policy.activated_at_monotonic_ns - 1
    )
    with pytest.raises(
        runner.CapabilityTransportError, match="precedes policy activation"
    ):
        _read(policy, [record.to_bytes()])


def test_eof_timeout_rejected():
    """A channel that stays silent until the budget expires fails closed."""
    policy = _policy()
    writer, reader = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET
    )
    try:
        started = time.monotonic()
        with pytest.raises(
            runner.CapabilityTransportError, match="timed out"
        ):
            runner._read_authenticated_https_transport_records(
                reader.fileno(),
                expected_policy=policy,
                expected_network_policy_digest=_NETWORK_POLICY_DIGEST,
                expect_synthetic=False,
                budget=0.3,
            )
        assert time.monotonic() - started < 3.0
    finally:
        writer.close()
        reader.close()


def test_evidence_after_terminal_rejected():
    policy = _policy()
    record = _connection_record(policy, index=1)
    terminal = _terminal(policy, [record])
    with pytest.raises(
        runner.CapabilityTransportError,
        match="arrived after the terminal record",
    ):
        _read(
            policy,
            [record.to_bytes(), terminal.to_bytes(), record.to_bytes()],
        )
