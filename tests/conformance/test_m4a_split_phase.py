"""Contract tests for controller-selected split-phase M4A execution."""

from __future__ import annotations

from dataclasses import replace

import pytest

from agenticos.sandbox.models import (
    CONTAINMENT_RESERVATION_SCHEMA,
    PREPARED_PROCESS_RECEIPT_SCHEMA,
    ContainmentReservation,
    PreparedProcessReceipt,
    ProcessIdentity,
)


def _reservation() -> ContainmentReservation:
    return ContainmentReservation(
        schema=CONTAINMENT_RESERVATION_SCHEMA,
        project_id="project-c",
        task_id="build-c",
        task_generation=3,
        attempt=2,
        controller_epoch=7,
        lease_epoch=11,
        dispatch_nonce="1" * 32,
        unit_name="aos-task-project-c-build-c-3-2-11",
        release_nonce="2" * 32,
    )


def _receipt() -> PreparedProcessReceipt:
    return PreparedProcessReceipt(
        schema=PREPARED_PROCESS_RECEIPT_SCHEMA,
        reservation=_reservation(),
        process_identity=ProcessIdentity(
            pid=1234,
            process_group_id=1234,
            start_time_ticks=987654,
            boot_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        ),
        cgroup_path="/sys/fs/cgroup/user.slice/aos-task-project-c-build-c-3-2-11.scope",
        child_cgroup="/user.slice/aos-task-project-c-build-c-3-2-11.scope",
        namespace_ids=(("ipc", 101), ("mnt", 102), ("net", 103), ("pid", 104), ("user", 105), ("uts", 106)),
        policy_digest="a" * 64,
        workspace_destination="/workspace",
        workspace_device=41,
        workspace_inode=42,
        workspace_file_type=0o040000,
        executable="/usr/bin/python3",
        argv=("/usr/bin/python3", "/opt/agenticos/worker.py", "--scenario", "SUCCESSFUL_EDIT"),
        prepared_at="2026-08-14T12:00:00+00:00",
    )


def test_containment_reservation_is_exact_and_round_trips() -> None:
    reservation = _reservation()

    assert reservation.scope_name == reservation.unit_name + ".scope"
    assert ContainmentReservation.from_dict(reservation.to_dict()) == reservation


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("unit_name", "bad.scope"),
        ("unit_name", "aos-task-UPPER"),
        ("release_nonce", "2" * 31),
        ("dispatch_nonce", "not-hex"),
        ("lease_epoch", 0),
        ("attempt", 0),
    ],
)
def test_containment_reservation_rejects_ambiguous_or_unfenced_identity(
    field: str, value: object
) -> None:
    with pytest.raises(ValueError):
        replace(_reservation(), **{field: value})


def test_prepared_process_receipt_round_trips_all_earned_evidence() -> None:
    receipt = _receipt()

    assert PreparedProcessReceipt.from_dict(receipt.to_dict()) == receipt
    assert receipt.process_identity.matches_fields(
        pid=1234,
        start_time_ticks=987654,
        boot_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )
    assert dict(receipt.namespace_ids)["mnt"] == 102
    assert receipt.executable == receipt.argv[0]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cgroup_path", "/wrong/aos-task.scope"),
        ("child_cgroup", "/wrong.scope"),
        ("namespace_ids", (("mnt", 1), ("mnt", 2))),
        ("policy_digest", "b" * 63),
        ("workspace_destination", "/host/worktree"),
        ("executable", "/bin/sh"),
        ("argv", ()),
    ],
)
def test_prepared_process_receipt_rejects_mismatched_or_incomplete_evidence(
    field: str, value: object
) -> None:
    with pytest.raises(ValueError):
        replace(_receipt(), **{field: value})


def test_prepared_receipt_requires_pid_start_ticks_boot_id_and_process_group() -> None:
    for identity in (
        ProcessIdentity(pid=1234, process_group_id=1234, start_time_ticks=None, boot_id="boot"),
        ProcessIdentity(pid=1234, process_group_id=None, start_time_ticks=1, boot_id="boot"),
        ProcessIdentity(pid=1234, process_group_id=1234, start_time_ticks=1, boot_id=None),
    ):
        with pytest.raises(ValueError):
            replace(_receipt(), process_identity=identity)
