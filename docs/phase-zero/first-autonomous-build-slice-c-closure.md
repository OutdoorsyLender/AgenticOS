# First Autonomous Build Slice C Closure

Status: complete and independently reviewed on 2026-08-14.

## Authorization and scope

This checkpoint implements only the approved First Autonomous Build Slice C:

- controller-selected containment identity before process creation;
- split-phase M4A prepare, measured receipt, durable commit, release, wait,
  cancellation, and drain;
- one exclusive fenced mutable project-workspace lease;
- durable execution binding and bounded restart reconciliation;
- deterministic out-of-process L2 synthetic workspace mutation through the
  real M5/M4A envelope; and
- terminal M5 identity validation plus two equal complete Slice B captures.

It performs no verifier or reviewer execution, repair scheduling, autonomous
scheduling, real provider integration, subscription authentication, network or
provider egress, Codex admission, deployment, UI, or generated-project
publication.

The implementation began from the verified common Windows, WSL, origin, and
live GitHub baseline:

```text
cc6a1b8efb7c14b7df43c60d7b84136be62a970b
```

## Controller-selected containment and split release

`ContainmentReservation` binds project, task, generation, attempt, controller
epoch, lease epoch, dispatch nonce, a cryptographically unique exact systemd
scope, and a separate cryptographic release nonce. The controller creates and
durably records this reservation before `prepare()` may spawn anything.

`NamespaceLandlockRunner.prepare()` creates that exact scope, establishes the
existing namespace, Landlock, environment, file-descriptor, process, and
network-denial boundaries, then stops at the authenticated pre-exec gate. Its
strict `PreparedProcessReceipt` binds the reservation to measured PID,
process-group, start ticks, boot ID, cgroup, namespace identities, launch-policy
digest, workspace device/inode/type and `/workspace` destination, executable,
and argv. The controller writes the exact receipt as `PROCESS_STARTED` before
calling `release(receipt, release_nonce)`. Forged, stale, mismatched, or repeated
release fails closed. The legacy one-shot `run()` remains a composition of
prepare, release, and wait.

If receipt persistence fails, the prepared process is cancelled and recursively
drained without release. The controller then revalidates the workspace, takes
two complete captures, and requires equality with the pre-launch checkpoint.
Any mutation before durable release is `RECOVERY_REQUIRED` evidence, never a
retry or success.

## Workspace lease and execution durability

The per-project `WorkspaceLeaseLedger` uses a cross-process project lock,
canonical append-only hash-chained records, fsync/no-replace publication, and a
separate durable mutable tail anchor. Acquisition requires typed live board,
M5 ownership/reservation, and complete explicitly reusable Slice B evidence.
The identity binds project/task/generation/attempt, controller and monotonically
increasing lease epochs, workspace identity, dispatch nonce, and pre-checkpoint.

`ACTIVE`, `EXECUTING`, and `CANCELLING` are non-reusable. Cancellation remains
`CANCELLING` across signalling, recursive drain, M5 identity validation, and
both terminal captures. Only after `TERMINAL_CAPTURED` may it become
`CANCELLED`; drain/callback ambiguity becomes `RECOVERY_REQUIRED`. This closes
lease reuse and ABA windows while preserving explicit terminal `RELEASED`,
`CANCELLED`, `STALE`, and `RECOVERY_REQUIRED` outcomes.

The execution ledger independently persists a canonical hash chain and durable
tail anchor for `CONTAINMENT_RESERVED`, `PROCESS_STARTED`, `RELEASED`,
`CANCEL_REQUESTED`, `PROCESS_TERMINATED`, `TERMINAL_CAPTURED`, and
`RECOVERY_REQUIRED`. Cancellation intent dominates late success. Process-wait
failure terminalizes only when M4A positively proves cleanup; otherwise both
ledgers remain recovery-fenced.

## Synthetic mutation and terminal evidence

The standalone worker consumes the exact provider-neutral Slice A request ABI,
runs out of process under real M4A L2 with `/workspace` as its only mutable
workspace ABI, and emits bounded canonical events plus one result. Covered
deterministic scenarios are:

- `SUCCESSFUL_EDIT` and `NO_OP`;
- `INVALID_PATH_ATTEMPT` and `DOT_GIT_ATTEMPT`;
- `CRASH_AFTER_EDIT` and `TIMEOUT_AFTER_EDIT`;
- `CHILD_PROCESS_CASE`; and
- `POST_TERMINAL_MUTATION_ATTEMPT`.

The worker receives no host repository path, main `.git`, controller or M5
state path, provider/subscription credential, ambient Git authority, or network
authority. Exact stdout bytes are incrementally bounded before buffering and
then validated against the Agent ABI; worker claims never establish workspace
authority.

Structural terminalization requires measured process termination, recursive
containment drain, exact scope absence/emptiness, revalidation of worktree
device/inode/ref/baseline identity, and two immediate complete reusable M5
captures with identical checkpoint objects. No-op proves pre equals post;
successful edit proves a stable changed post-checkpoint without claiming
semantic correctness.

## Restart recovery

Recovery never redispatches. It addresses the controller-selected exact scope
and measured PID/process-group/start-ticks/boot-ID/cgroup identity. Typed scope
evidence distinguishes `PRESENT`, positively `ABSENT`, and `UNKNOWN`; command
errors, incomplete properties, contradictions, PID reuse, wrong cgroup, or
unreadable population remain fail closed. A missing main PID with descendants
in the exact populated scope is recursively drained and stopped before double
capture. A persisted terminal execution reconciles an unfinished lease
disposition without recapturing or dispatching.

## Verification and independent review

Final focused Ubuntu WSL/Linux result, including real M4A and Slice C
integration:

```text
286 passed
```

Final focused Windows platform-neutral result on the exact candidate:

```text
225 passed, 19 skipped
```

Final full Ubuntu WSL/Linux result:

```text
2383 passed, 2 skipped
```

One preceding full run found a same-run orphaned M4B temporary CA directory.
After proving it contained only the generated CA file, was owned by the test
user, and had no owning process, that exact temporary artifact was removed.
The initiating M4B lifecycle test passed alone and the fresh full run above
passed without residue.

Final full Windows result in a dedicated Git-backed candidate clone:

```text
1096 passed, 254 skipped
```

An initial full Windows attempt used a file-only candidate directory and one
unrelated provider-auth canary correctly failed because `.git` was absent. The
Git-backed candidate rerun above supplies the repository evidence that test
requires.

Independent adversarial review drove iterative closure of pre-release receipt
ordering, durable containment reservation, lease/release/cancellation races,
bounded output, ledger rollback, typed scope evidence, terminal lease crash
reconciliation, failed/ambiguous wait cleanup, and exact orphan-descendant
recovery. Its final frozen-snapshot verdict was:

```text
SLICE_C_ADVERSARIAL_REVIEW=GO
UNRESOLVED_CRITICAL=0
UNRESOLVED_IMPORTANT=0
```

## Deliberately deferred

The following remain later-slice work:

- Slice D: verifier/reviewer execution and repair-lineage operation;
- Slice E: scheduler and Demo 0 acceptance;
- Slices F1/F2: separately authorized official subscription-backed adapters;
- G2: synthetic owner-blocked behavior qualification; and
- G1: real autonomous DONE acceptance.

No Slice D work begins from this checkpoint. The only next implementation gate
is:

```text
AUTHORIZE_FIRST_AUTONOMOUS_BUILD_SLICE_D=YES
```
