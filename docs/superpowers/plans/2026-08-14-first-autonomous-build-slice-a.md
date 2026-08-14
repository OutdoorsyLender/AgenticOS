# First Autonomous Build Slice A Implementation Plan

> Scope: implement and publish only the controller-authority core authorized on
> 2026-08-14. Slice B and every runtime, workspace, scheduler, and real-provider
> concern remain out of scope.

## Boundaries

`SLICE_A_BLOCKER` work is limited to authoritative records, total transition
rules, deterministic dependency validation, a crash-consistent bounded journal,
the provider-neutral protocol, proposal compilation, non-workspace synthetic
fixtures, schemas, tests, and the narrow closure record.

`LATER_SLICE` items deliberately excluded are M5 capture/checkpoint changes,
M4A execution or containment changes, workspace leases or mutation, verifier or
reviewer execution, repair execution, scheduler behavior, provider adapters,
authentication, network access, Codex admission, and deployment.

The Windows clone is the only writer for this platform-neutral slice. The WSL
clone is a native regression and synchronization target and receives the exact
published commit only through `origin/main`.

## A1 — Models and bounded values

**Files:**

- Add `src/agenticos/orchestration/models.py`.
- Add `tests/orchestration/test_models.py`.

**Test first:**

- Prove valid immutable project/task records and all required enum values.
- Reject invalid identifiers, enums, text/list bounds, attempt overflow,
  inconsistent lineage, and unauthorized terminal/block reasons.
- Prove dependency and repair-lineage edges remain separate fields.

**Implementation:**

- Define frozen `ProjectRecord`, `BoardTask`, `RunLimits`, and opaque baseline
  and workspace identity references.
- Define narrow controller enums and shared bounded validation helpers.
- Provide strict canonical-dictionary conversion without accepting model strings
  as controller decisions.

## A2 — Board authority and total transitions

**Files:**

- Add `src/agenticos/orchestration/board.py`.
- Add `tests/orchestration/test_board.py`.

**Test first:**

- Cover every task and project source state, accepted and rejected transitions,
  duplicate transitions, stale revisions, duplicate IDs, missing/self/cyclic
  dependencies, and deterministic READY derivation.
- Prove rejected operations return a stable typed rejection and do not mutate
  the immutable board.

**Implementation:**

- Make transition tables complete over every enum member.
- Put ID, creation sequence, dependency, status, attempts, priority,
  assignment, criteria, lineage, and revision updates behind `BoardAuthority`.
- Validate the dependency DAG independently of repair lineage.

## A3 — Canonical journal and deterministic recovery

**Files:**

- Add `src/agenticos/orchestration/canonical.py`.
- Add `src/agenticos/orchestration/journal.py`.
- Add `tests/orchestration/test_canonical.py`.
- Add `tests/orchestration/test_journal.py`.

**Test first:**

- Prove UTF-8, sorted keys, compact separators, integer-only numeric authority,
  enum strings, one trailing newline for stored records, duplicate-key
  rejection, unknown-field rejection at typed boundaries, and byte caps.
- Simulate failures after PREPARE persistence and during atomic temporary-file
  writes. A dangling valid PREPARE is non-authoritative; malformed named
  records, truncation, digest mismatch, rollback, gaps, and duplicates fail
  closed.
- Prove recovery reconstructs the exact last committed immutable snapshot.

**Implementation:**

- Use canonical JSON records, SHA-256 chain binding, immutable PREPARE/COMMIT
  files, atomic same-directory rename, file fsync, and parent-directory fsync.
- Bound record count and bytes. Treat the transaction chain as authoritative;
  do not add a database or event service.

## A4 — Provider-neutral protocol

**Files:**

- Add `src/agenticos/orchestration/protocol.py`.
- Add `tests/orchestration/test_protocol.py`.

**Test first:**

- Round-trip one valid request, event stream, and result.
- Reject unknown/duplicate/malformed fields, over-limit material, identity,
  generation, attempt, epoch or nonce mismatch, event rollback, extra events
  after terminal, duplicate/conflicting terminal events, and incomplete streams.
- Prove results carry claims and evidence references but no board-state,
  command, Git, credential, or acceptance authority.

**Implementation:**

- Model the exact dispatch identity once and bind it into request, events, and
  result.
- Use enumerated roles, capabilities, event/result classifications, typed
  context/evidence items, and explicit aggregate limits.
- Validate event framing incrementally through a stateful bounded stream
  validator before accepting an event.

## A5 — Planner and reviewer proposals

**Files:**

- Add `src/agenticos/orchestration/proposals.py`.
- Add `tests/orchestration/test_proposals.py`.

**Test first:**

- Compile a valid multi-task proposal atomically with controller IDs and
  creation sequences.
- Reject the complete proposal for duplicate local IDs, missing/self/cyclic
  dependencies, invalid roles/types/priorities, and count or text bounds.
- Prove reviewer pass/finding/repair recommendations are bounded advisory
  values and expose no authoritative mutation operation.

**Implementation:**

- Keep proposal types distinct from `BoardTask`.
- Resolve proposal-local dependency names only after whole-input validation,
  then ask `BoardAuthority` to admit the complete authoritative task set in one
  board revision.

## A6 — Synthetic fixtures and schemas

**Files:**

- Add `src/agenticos/orchestration/synthetic.py`.
- Add `src/agenticos/orchestration/__init__.py`.
- Add `schemas/orchestration-board.schema.json`.
- Add `schemas/agent-protocol.schema.json`.
- Add `tests/orchestration/test_synthetic.py`.
- Add `tests/orchestration/test_schemas.py`.

**Test first:**

- Run deterministic researcher, planner, reviewer pass/fail, no-op,
  retryable-failure, and terminal-failure fixtures twice and compare bytes.
- Exercise malformed, unknown-kind, out-of-order, duplicate/conflicting
  terminal, oversized, wrong identity/generation/nonce, stale attempt, and
  incomplete streams through the real protocol validator and require typed
  controller failures.
- Validate emitted canonical objects against the committed schemas.

**Implementation:**

- Fixtures return only canonical protocol bytes/objects and never touch a
  workspace, spawn a process, access the network, or import provider auth.

## Verification, review, and publication

1. Run focused `tests/orchestration` tests and schema validation.
2. Run the full Windows regression suite.
3. Run platform-neutral orchestration tests in native Ubuntu WSL against an
   exact temporary candidate commit/worktree if needed; do not edit in WSL.
4. Request an independent adversarial code review focused on authority leaks,
   partial DAG application, transition totality, journal ambiguity, replay,
   stale/duplicate stream acceptance, bounds, deterministic serialization,
   graph confusion, and scope expansion.
5. Resolve every Critical and Important finding and rerun affected and full
   tests.
6. Add the narrow Slice A closure record, inspect the complete diff, and run
   `git diff --check`.
7. Commit and push the exact tested Windows commit to `main`, verify live
   `refs/heads/main`, fast-forward WSL from GitHub, and prove both clones clean,
   stash-free, 0/0 divergent, and SHA-identical.
8. Hard stop. Slice B requires separate owner authorization.
