# M4B-3 Slice 5 — Connected Build: lifecycle matrix

Status: closed against the lifecycle/cancellation matrix of the M4B-3
milestone task specification (session-governing prompt; the matrix is
reproduced in full below so this document is self-contained), 2026-08-10.
New proof corpus:
`tests/conformance/test_m4b3_lifecycle_integration.py` (6 tests,
`m4b_linux`, all passing). This document is the per-cell proof map the
final report needs; it deliberately CITES grant-agnostic coverage instead
of duplicating it.

## Matrix

| Lifecycle cell | Status | Proof |
| --- | --- | --- |
| Task cancellation mid-curl-download | PRE-EXISTING [^curl-partial] | `test_fetch_worker_cancellation_mid_download_no_artifact` (Slice 3) |
| Task cancellation mid-git-clone (POST + pack stream) | NEW | `test_cancel_mid_git_clone_no_partial_clone` |
| Task cancellation mid-pip-download | NEW | `test_cancel_mid_pip_download_no_partial_artifact` |
| Broker REVOKE mid-connection (control channel) | PRE-EXISTING (mechanism, grant-agnostic) | `test_https_revoke_mid_connection_tears_down` (M4B-2); ecosystem transfer + REVOKED terminal evidence pinned by the two NEW cancellation tests above (runner cancellation IS the control-channel revoke) |
| Grant/policy expiry mid-acquisition | PRE-EXISTING (grant-agnostic — no per-ecosystem duplicate needed) | `test_https_expiry_tears_down_connections` (M4B-2), `test_fetch_policy_expiry_mid_download_fails` (Slice 3), unit `test_serve_expiry_*` |
| Broker death mid-run cancels task | PRE-EXISTING | `test_confirmed_post_exec_broker_death_cancels_live_hostile_worker`, `test_broker_death_at_lifecycle_boundary_cancels_task` (M4B-1) |
| No partial trusted artifact on any kill path | NEW (ecosystem-level) | both NEW cancellation tests (no checked-out clone, no completed/full-size wheel) + Slice 3 fetch suite (no rename on any failure) |
| Post-teardown authority non-reuse | NEW | `test_post_teardown_authority_hygiene`: broker process reaped (listener dead with the netns), `/tmp/aos-m4b2-ca-*` staging dirs removed, zero `aos-task` memfds in the controller, zero `aos-*` units |
| Unit/process/fd residue after every flow | PRE-EXISTING + NEW | `_assert_no_m4b_residue` in every integration test (Slices 0-5); worker fd censuses (Slices 3-4); pip cache confinement (Slice 4) |
| Cache/temp residue sweep | PRE-EXISTING + NEW | pip cache confinement test (Slice 4 worker census + host-side worktree diff); NEW: authority-hygiene test covers CA staging dirs and sealed memfds |
| Authority after expiry/revoke is non-reusable | PRE-EXISTING | post-terminal canary blocked in M4B-1 relay tests (`test_active_full_duplex_relay_revoke_blocks_post_terminal_canary`, `..._absolute_expiry_...`); broker teardown above |

## Cancellation-mechanics note

The runner's task cancellation and the broker revoke are the SAME
mechanism: cancellation writes `CONTROL_REVOKE` into the broker control
channel; the serve loop terminates with `terminal_reason=REVOKED` and
aborts in-flight connections. Slice 5 therefore proves the revoke cell
through the two ecosystem cancellation tests rather than a third
duplicated variant: each asserts `timed_out is True`, a broker-sourced
REVOKED terminal, per-connection `revoked` records, a reaped broker, and
no partial trusted output.

## Authority-hygiene closure (new assertions)

- Broker process: `pid_alive(broker.pid) is False` after teardown.
- Task CA staging: no `/tmp/aos-m4b2-ca-*` directory survives any run
  (the runner removes `material.worker_ca_dir` on both success and
  failure teardown paths).
- Sealed material: no `aos-task-*` memfd symlink survives in
  `/proc/self/fd` of the controller.
- Scope/units: zero `aos-*` systemd units after every test
  (`_assert_no_m4b_residue`, unchanged).

[^curl-partial]: The curl cancellation test pins `exit_code != 0` plus
residue; the no-partial-trusted-artifact property for the curl path is
pinned explicitly by its sibling
`test_fetch_policy_expiry_mid_download_fails` (partial staged, digest
gate rejects, no rename, no residue).
