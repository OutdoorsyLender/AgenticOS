# F1 Kimi Level-1 Task-4 Freezer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Replace the superseded SIGSTOP/process-group Task-4 runner with the approved controller-excluding cgroup-v2 freezer implementation, qualify it synthetically and natively, and publish the exact tested pre-real-attempt commit.

**Architecture:** A single-threaded controller runs as the MainPID of a transient delegated user service and creates one identity-bound `workload` child cgroup. It uses one ordinary controller pidfd and `clone3(CLONE_INTO_CGROUP)` to place the outer supervisor directly in that cgroup; every workload descendant inherits membership. After the terminal authenticate response permanently disables ACP writes, the controller proves `populated 1` and `frozen 1`, revalidates live identity/topology, consumes exactly one capture, thaws to `frozen 0`, and only then closes stdin and drains. Every pre-consumption failure revokes capture; bounded cleanup uses `cgroup.kill` without adding credential, memory-inspection, or network authority.

**Tech Stack:** Python 3.12, Linux pidfd/clone3/cgroup-v2 syscalls, systemd 259 user services, Bubblewrap 0.11.1, pytest.

**Spec:** `docs/superpowers/specs/2026-08-15-f1-kimi-level1-local-auth-qualification-design.md` at `dd5b6a08609cd1db6f3ac2aa7075d3215ee0e05e`

## Global Constraints

- `TASK4_RESUME_AUTHORIZED=YES`; `REAL_LEVEL1_ATTEMPT_AUTHORIZED=NO`.
- Do not access, mount, hash, read, or launch against the real credential; do not claim the one-shot marker.
- `EXTERNAL_NETWORK_AUTHORITY=NONE`; no Kimi contact, login, model inference, or F2 work.
- One controller process leader, one ordinary pidfd, and exactly one controller TID from immediately before direct placement through workload drain and cgroup removal.
- One fixed workload child cgroup; no migrate-after-fork fallback and no child cgroups.
- No ptrace, `process_vm_readv`, `/proc/<pid>/mem`, debugger, or core-dump authority.
- No SIGSTOP/SIGCONT capture quiescence or fallback.
- All timeouts share one non-resetting monotonic deadline.

## Preserved five-commit reconciliation

| Commit | KEEP | REWORK | DROP |
| --- | --- | --- | --- |
| `13e93c2` | Fixed CLI, typed evidence/census, artifact rechecks, launch ordering, finite ACP parsing | scope to service, `Popen` to direct clone3, stdin/capture sequencing, cleanup | process-group ownership as security boundary |
| `a9fd046` | fail-closed Level-1 result, reason allowlist, artifact census, deadline and late-exit checks | lifecycle checks around cgroup identity/topology | signal attribution as proof of clean termination |
| `2271ee4` | nonblocking bounded pipe capture, buffer scrubbing, race-oriented census | explicit ACP and capture state machines | process-group drain and reader-thread compatibility |
| `663a4c6` | first-failure latch, no-I/O-after-failure instrumentation, bounded cleanup intent | capture transitions to `NOT_YET_GRANTED/GRANTED/CONSUMED/REVOKED` | SIGSTOP freeze provenance and SIGCHLD/pending-signal inference |
| `3eca6bf` | stable double-snapshot method and topology-churn rejection | controller task, cgroup process/thread, pidfd, and live-role snapshots | task pending-signal census and `tgkill` attribution tests |

## Qualified exact-host prerequisites

- WSL kernel `6.6.87.2-microsoft-standard-WSL2`, systemd `259`, Bubblewrap `0.11.1`.
- Live transient service properties: `Delegate=yes`, `KillMode=control-group`, `SendSIGKILL=yes`, `TimeoutStopUSec=5s`, `Restart=no`, `TasksMax=21`, `MemoryMax=1073741824`, `ProtectControlGroups=yes`, and one exact service-cgroup `BindPaths=` mount.
- Direct clone3 placement, inherited outer/inner/provider/thread membership, strict freeze/thaw events, frozen-task `cgroup.kill`, and controller-crash systemd cleanup were observed in disjoint synthetic probes with zero residue.

---

### Task 1: Monotonic protocol and capture authority

**Files:**
- Modify: `src/agenticos/providers/kimi_local_auth.py`
- Modify: `src/agenticos/providers/kimi_local_auth_runtime.py`
- Modify: `tests/providers/test_kimi_local_auth.py`

**Interfaces:**
- Produces `ACPProtocolState(ACTIVE, TERMINAL_RESPONSE_ACCEPTED, CLOSED)` and `CaptureState(NOT_YET_GRANTED, GRANTED, CONSUMED, REVOKED)`.
- Produces a single-threaded capture object whose `revoke()` scrubs buffers and permanently forbids `select`, `read`, `write`, `finish`, and retry.

- [x] **Step 1: Write failing transition and bomb-instrumentation tests**

Cover every admitted state edge, every invalid/repeated edge, terminal response disabling the encoder before freezer work, inert-open stdin, one capture only, and every pre-consumption failure reaching `REVOKED`.

- [x] **Step 2: Run RED**

Run: `python3 -m pytest -q tests/providers/test_kimi_local_auth.py -k 'protocol_state or capture_state or post_terminal or revocation'`

Expected: missing states/transitions or observable forbidden I/O.

- [x] **Step 3: Implement minimal monotonic state objects and single-threaded nonblocking capture**

The only successful sequence is:

```text
ACTIVE -> TERMINAL_RESPONSE_ACCEPTED
NOT_YET_GRANTED -> GRANTED -> CONSUMED
thaw confirmed -> CLOSED
```

Every earlier failure performs `capture.revoke(first_reason)` before cleanup; protocol close is lifecycle-only and cannot invoke capture.

- [x] **Step 4: Run GREEN**

Run the RED selector plus the complete portable local-auth file.

### Task 2: Identity-bound delegated workload cgroup and direct placement

**Files:**
- Modify: `src/agenticos/providers/kimi_local_auth_runtime.py`
- Modify: `tests/providers/test_kimi_local_auth.py`
- Modify: `tests/providers/test_kimi_local_auth_linux.py`

**Interfaces:**
- Produces immutable `WorkloadCgroupIdentity`, `ControllerIdentity`, strict `CgroupEvents`, and anchored control descriptors.
- Produces `clone3_into_cgroup()` with no migration fallback.
- Produces stable controller/cgroup membership snapshots and live-role pidfd identities.

- [x] **Step 1: Write failing fake-file identity, topology, controller-thread, pidfd, and clone3 tests**

Cover mount/device/inode/path replacement, control replacement, dying cgroup, child cgroup, duplicate/churning PID/TID sets, controller entry, workload escape/entry, injected controller thread, and any attempted migrate-after-fork fallback.

- [x] **Step 2: Run RED**

Run: `python3 -m pytest -q tests/providers/test_kimi_local_auth.py tests/providers/test_kimi_local_auth_linux.py -k 'workload_cgroup or controller_identity or clone3 or membership or topology'`

- [x] **Step 3: Implement anchored creation and validation**

Open the fixed child with `O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`; pre-open `cgroup.freeze`, `cgroup.events`, `cgroup.procs`, `cgroup.threads`, and `cgroup.kill`; bind directory plus mount/device/inode identity; bind the controller leader with exactly one ordinary pidfd; and require the stable controller task set to equal `(getpid(),)` at every checkpoint.

- [x] **Step 4: Implement direct child placement**

Call x86-64 `clone3` with only `CLONE_INTO_CGROUP` plus `SIGCHLD`, close every cgroup/controller descriptor in the child, and exec the fixed Bubblewrap vector. `ENOSYS`, `EINVAL`, `EOPNOTSUPP`, `EPERM`, or any ambiguity returns a typed blocked result; never write a PID to `cgroup.procs`.

- [x] **Step 5: Run GREEN and native placement tests**

Prove the outer process is born in the workload cgroup and every inner supervisor/provider process/thread/descendant inherits it while the controller remains outside.

### Task 3: Asynchronous freezer transaction and exact ordering

**Files:**
- Modify: `src/agenticos/providers/kimi_local_auth_runtime.py`
- Modify: `tests/providers/test_kimi_local_auth.py`
- Modify: `tests/providers/test_kimi_local_auth_linux.py`

**Interfaces:**
- Produces strict total `cgroup.events` parsing, `request_freeze()`, `await_frozen()`, `request_thaw()`, `await_thawed()`, and post-transition revalidation.

- [x] **Step 1: Write failing A-F matrix tests for freeze/capture/thaw/EOF order**

Assert the trace:

```text
terminal authenticate response -> writes disabled -> stdin open
-> freeze request -> populated 1 -> frozen 1 -> live-role revalidation
-> one capture -> thaw -> frozen 0 -> stdin EOF -> bounded drain -> zero residue
```

Add EOF-sensitive provider, fork-during-freeze, freeze timeout, supervisor/provider crash, identity replacement, workload escape/entry, thaw failure, cgroup.kill while frozen, and revocation-bomb cases.

- [x] **Step 2: Run RED**

Run: `python3 -m pytest -q tests/providers/test_kimi_local_auth.py tests/providers/test_kimi_local_auth_linux.py -k 'freez or thaw or eof or fork_during or identity_replacement or escape or revocation'`

- [x] **Step 3: Implement one-deadline transaction**

Write exact `1\n`, poll the pre-opened events FD until strict `populated 1` and `frozen 1`, then revalidate identity/membership/topology/controller exclusion before granting capture. After one capture, write exact `0\n`, require strict `frozen 0`, revalidate live roles, and only then close stdin. On thaw failure, do not continue the provider; keep capture consumed and kill/drain.

- [x] **Step 4: Run GREEN and prove SIGSTOP/SIGCONT absence**

The implementation and tests must contain no capture-quiescence signal fallback; fatal signals remain cleanup-only.

### Task 4: Bounded cgroup cleanup, service command, and controller-crash proof

**Files:**
- Modify: `src/agenticos/providers/kimi_local_auth_runtime.py`
- Modify: `scripts/run_kimi_local_auth.py`
- Modify: `tests/providers/test_kimi_local_auth.py`
- Modify: `tests/providers/test_kimi_local_auth_linux.py`

**Interfaces:**
- `local_auth_systemd_command()` creates a transient delegated service, not a scope.
- Failure cleanup writes exact `1\n` to identity-bound `cgroup.kill`, proves recursive `populated 0`, removes the same empty cgroup, and closes all controller descriptors.

- [x] **Step 1: Write failing service-vector, kill/drain, controller-death, and residue tests**

Require direct `--pipe` transport, `Delegate=yes`, `KillMode=control-group`, `SendSIGKILL=yes`, `TimeoutStopSec=5s`, `Restart=no`, `TasksMax=21`, and `MemoryMax=1G`. Prove controller death while frozen is bounded by systemd and leaves no process, unit, cgroup, socket, listener, or frozen orphan.

- [x] **Step 2: Run RED**

Run the portable service-vector selector and native controller-crash selector.

- [x] **Step 3: Implement cleanup and CLI integration**

Preserve the existing fail-closed pre-real gates and typed evidence. No cleanup callback may write ACP or access capture after revocation/consumption.

- [x] **Step 4: Run GREEN**

Run both complete local-auth files and the exact native host-qualification selectors.

### Task 5: Full qualification, adversarial review, and exact publication

**Files:**
- Modify implementation/tests only for a finding first reproduced by a failing test.
- Modify: `docs/phase-zero/first-autonomous-build-slice-f1-kimi-local-auth-pre-real.md`

- [x] **Step 1: Run the complete amended A-F synthetic/native matrix**

Run both local-auth test files without selection and record exact counts/results.

- [x] **Step 2: Run all focused Kimi, orchestration, conformance, and worktree regressions**

Use the command list in the original plan Task 7, plus the new native freezer/controller-crash suite.

- [ ] **Step 3: Run full native WSL verification**

Run `python3 -m pytest -q`, `python3 -m compileall -q src tests scripts`, Ruff/format/type checks configured by the repository, `git diff --check`, and the secret-pattern scan. Run a final credential-blind process/unit/cgroup/socket/listener/frozen-orphan census.

- [x] **Step 4: Dispatch fresh adversarial review**

Review every gate listed by the approved specification. Resolve every Critical and Important finding through RED/GREEN; rerun affected focused and full gates.

- [ ] **Step 5: Inspect and commit the exact tested candidate**

Confirm no SIGSTOP/SIGCONT quiescence, ptrace/process-memory surface, readable credential authority, real marker access, or network authority. Commit the final plan, implementation, tests, and pre-real evidence together.

- [ ] **Step 6: Publish and synchronize under the preservation contract**

Publish the exact tested WSL SHA through the approved exact-SHA path, independently verify GitHub `refs/heads/main`, fast-forward both canonical clones, and prove clean `0/0`, zero stashes, unexplained files, provider processes, units/scopes, workload cgroups, sockets/listeners, and frozen orphans.

- [ ] **Step 7: Hard stop**

Return `REAL_LEVEL1_ATTEMPT_AUTHORIZED=NO`; do not claim the marker, mount the real credential, authenticate, contact Kimi, infer, or begin F2.
