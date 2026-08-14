# First Autonomous Build Slice A Closure

Status: complete and independently reviewed on 2026-08-14.

## Authorization and scope

This checkpoint implements only the approved First Autonomous Build Slice A:

- authoritative project, task, board, reason, identity, and limit records;
- total project/task transition staging plus journal-backed board authority;
- deterministic dependency-DAG validation distinct from repair lineage;
- a bounded crash-consistent single-project PREPARE/COMMIT journal;
- the provider-neutral request/event/result ABI;
- strict planner/reviewer proposal values and controller compilation policy;
- deterministic non-workspace synthetic fixtures; and
- strict board/protocol schemas and focused tests.

It performs no hostile workspace mutation, M5 execution or checkpoint work,
M4A launch work, scheduler operation, verifier/reviewer execution, provider
installation or selection, authentication, subscription login, credential
access, network request, Codex admission, Gate B operation, deployment, or
generated-project publication.

## Authority implementation

`BoardTransitionEngine` is a staging-only pure state machine. It defines a
total transition result for every project and task state: either a typed
accepted candidate or a deterministic typed rejection. It does not publish
durable authority.

`BoardAuthority` owns the published snapshot. It stages an operation in a
fresh engine, commits the complete candidate through `TransactionJournal`, and
only then replaces its in-memory snapshot with the journal-recovered snapshot.
A durability failure leaves the previously committed snapshot authoritative.

Task dependency edges control readiness. Repair parent/root fields are checked
as a separate lineage relation and do not participate in dependency-cycle
analysis. READY derivation is deterministic and applies in one board revision.

Project `OWNER_BLOCKED` is terminal for autonomous transitions. Project and
task DONE, FAILED, CANCELLED, and blocked reasons are state-consistent; in
particular a FAILED project cannot encode completion, cancellation, or an owner
decision.

## Journal and recovery

The journal uses canonical UTF-8 JSON with sorted keys, compact separators,
integer-only numeric authority, enum strings, and exactly one trailing newline
per stored record. Duplicate JSON keys, non-integer numbers, invalid UTF-8,
excessive depth/bytes, unknown typed fields, and noncanonical stored forms fail
closed.

Each transaction has immutable, atomically published PREPARE and COMMIT files.
Files are flushed before publication; Linux directory metadata is flushed, and
Windows uses write-through rename. Publication is no-replace, preventing a
concurrent writer from overwriting an immutable record name. Records bind the
project, transaction/controller identity, monotonic transaction/event/revision
numbers, prior COMMIT digest, canonical payload digest, PREPARE digest, and
record digest.

The authoritative project record carries a transition sequence and a chained
transition digest. Recovery recalculates and verifies both. A canonical
`board.json` is a derived snapshot keyed to the committed head; recovery repairs
a missing or truncated derived file from the immutable authoritative chain.

A valid dangling PREPARE is reported but is never authoritative and blocks new
transactions. The controller may explicitly complete only that exact verified
PREPARE. Named truncation, malformed records, gaps, rollback, duplicate
transactions, hash mismatch, unreadable state, or ambiguous corruption fail
closed.

## Provider-neutral protocol and proposal boundary

Every request, event, and result binds the complete dispatch identity:
project/task, task generation, attempt, controller/lease epochs, dispatch nonce,
repository/baseline, opaque workspace/reservation identity, and checkpoint
digest. Requests contain only bounded instructions, criteria, typed context
references, enumerated capabilities, `/workspace`, and explicit limits.

Event frames are canonical and validated incrementally before acceptance. The
validator enforces per-frame size, total event count, aggregate output bytes,
strict sequence, exact dispatch identity, one terminal event, a complete stream,
result/terminal agreement, exact stream count/bytes/digest, bounded combined
stream/result bytes, and single result acceptance.

Results contain structural claims and evidence references only. They expose no
board state, acceptance, command, retry, Git, path, provider credential, or
controller mutation authority.

Planner proposals are separate from `BoardTask`. Whole-DAG validation happens
before any board operation. The controller assigns task IDs and creation
sequence. `PlannerCompilationPolicy` excludes bootstrap RESEARCH/PLAN and
controller-only REPAIR creation, fixes task-to-role policy, bounds priority, and
supplies controller-owned acceptance criteria. Reviewer proposals remain
bounded advisory values with no apply or transition operation.

## Synthetic qualification

The deterministic fixture corpus covers researcher/planner success, reviewer
pass/fail, no-op, retryable and terminal failure, malformed and unknown events,
sequence rollback, duplicate/conflicting terminal events, oversized payload,
wrong task/generation/nonce/attempt, and incomplete streams. Fixtures use the
real typed protocol but perform zero provider calls, process spawns, workspace
accesses, or network accesses.

## Verification and independent review

Final focused Windows result:

```text
90 passed
```

Final full Windows regression result:

```text
991 passed, 234 skipped
```

The independent adversarial review initially found one Critical and four
Important issues: disconnected in-memory/durable authority, unbound transition
metadata, unresolved dangling PREPARE, insufficient controller planner policy,
and missing aggregate stream accounting. Those were corrected and retested.
The second pass found one remaining Important FAILED-reason ambiguity, which was
closed in runtime validation, transition tests, and JSON Schema conditions.

Final review verdict:

```text
SLICE_A_ADVERSARIAL_REVIEW=GO
UNRESOLVED_CRITICAL=0
UNRESOLVED_IMPORTANT=0
```

## Deliberately deferred

The following remain later-slice work:

- Slice B: complete M5 workspace checkpoint capture and anomaly hardening;
- Slice C: fenced split-phase M4A execution and workspace leases;
- Slice D: verifier/reviewer execution and repair lineage operation;
- Slice E: scheduler and Demo 0 acceptance;
- Slices F1/F2: separately authorized official subscription-backed adapters;
- G2: synthetic owner-blocked behavior qualification; and
- G1: real autonomous DONE acceptance.

No Slice B work begins from this checkpoint. The only next implementation gate
is:

```text
AUTHORIZE_FIRST_AUTONOMOUS_BUILD_SLICE_B=YES
```
