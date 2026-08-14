# First Autonomous Build Slice B Implementation Plan

> Scope: implement and publish only the complete M5 workspace-checkpoint
> hardening authorized on 2026-08-14. Slice C and every execution, lease,
> scheduler, repair, provider, authentication, and Codex concern remain out of
> scope.

## Boundaries

`SLICE_B_BLOCKER` work is limited to complete binary-safe Git status capture,
canonical status manifests and counts, bounded presentation metadata,
descriptor-oriented untracked-file evidence, complete Git diff identity, a
deterministic typed workspace checkpoint, explicit controller-owned reuse
decisions, focused fault injection, regressions, and the narrow closure record.

`LATER_SLICE` items deliberately excluded are M4A split-phase execution,
workspace leases, verifier or reviewer execution, repair execution, scheduler
behavior, provider adapters, authentication, network access, Codex admission,
UI, deployment, databases, generalized evidence storage, and concurrent
mutation.

Ubuntu WSL is the sole authoring clone for this Linux-sensitive M5 slice. The
Windows clone is the regression and synchronization target and receives the
exact published commit only through `origin/main`.

## B1 - Typed complete status capture

**Files:**

- Modify `src/agenticos/sandbox/worktree.py`.
- Add `tests/test_worktree_checkpoint.py`.

**Test first:**

- Prove clean, modified, added, deleted, renamed, copied when representable,
  unmerged, deeply nested untracked, multiple untracked-directory contents,
  legal spaces, deterministic ordering, duplicate/conflict rejection, strict
  NUL framing, UTF-8/path bounds, command failure, output bounds, complete
  counts, and repeatable manifest digests.
- Prove `git status --porcelain=v1 -z --untracked-files=all` is the exact
  controller-owned observation and no empty bounded list can imply clean.

**Implementation:**

- Stream and bound raw status/stdout and diagnostic stderr without shell
  interpretation; reject nonzero exit, timeout, malformed or incomplete NUL
  frames, invalid UTF-8/path values, unsupported codes, duplicate/conflicting
  tuples, byte/cardinality/path bounds, and canonicalization inconsistency.
- Represent every complete tuple with exact XY code, deterministic category
  membership, path, rename/copy source path, and typed anomaly/evidence fields.
- Canonicalize compact sorted-key JSON directly to strict UTF-8 bytes with no
  newline and hash the complete sorted manifest with SHA-256.

## B2 - Untracked evidence and bounded presentation

**Files:**

- Modify `src/agenticos/sandbox/worktree.py`.
- Modify `tests/test_worktree_sandbox.py` only where the hardened typed fields
  replace ambiguous legacy inline evidence semantics.
- Modify `tests/test_worktree_checkpoint.py`.

**Test first:**

- Prove regular and large-file streaming hashes, content/name changes,
  descriptor identity checks, unreadable/hash failures, symlink rejection,
  directories and non-regular entries, aggregate inline bounds, under/over
  presentation limits, exact omitted counts, and manifest identity independent
  of presentation bounds.

**Implementation:**

- Use `lstat`, no-follow descriptor open where supported, `fstat` identity and
  type checks, streaming SHA-256, and before/after descriptor metadata checks.
- Put content size/hash or a typed anomaly into each untracked manifest entry;
  never silently omit an observed entry.
- Keep legacy category lists and inline untracked evidence bounded, but expose
  explicit truncation/omission fields independent of complete counts and the
  complete manifest digest.

## B3 - Complete diff and canonical checkpoint identity

**Files:**

- Modify `src/agenticos/sandbox/worktree.py`.
- Modify `tests/test_worktree_checkpoint.py`.

**Test first:**

- Prove clean/modified/large diff behavior, complete byte count and SHA-256,
  bounded inline presentation independent of the digest, nonzero/timeout
  failures, identical immediate captures, and digest changes for status,
  filename, untracked content, diff, baseline/ref, and device/inode changes.

**Implementation:**

- Harden the existing streaming `git diff HEAD` path so nonzero exit and
  timeout are typed hard failures and bounded stderr is diagnostic only.
- Build one canonical checkpoint without timestamps or host paths, binding the
  existing M5 repository/ownership/reservation/task/ref/baseline/current-head/
  device/inode identity, complete counts and manifest digest, complete diff
  size/digest, anomalies, and authoritative completeness.
- Expose `REUSABLE`, `NOT_REUSABLE`, and `CAPTURE_FAILED` as a typed
  controller-owned result. Presentation truncation alone remains reusable;
  incomplete/ambiguous/forbidden evidence never does.

## B4 - Integration, regression, review, and publication

1. Run focused checkpoint and existing M5 tests on Ubuntu WSL and Windows;
   retain native Linux-only symlink/file-type coverage in WSL.
2. Run relevant M4A/M5 regressions and the complete suite on both required
   platforms as applicable.
3. Request an independent adversarial review focused on collapsed untracked
   directories, rename/copy framing, NUL/path ambiguity, duplicate tuples,
   presentation masking, command failures, symlink/non-regular bypass, TOCTOU,
   omitted checkpoint authority, nondeterminism, identity confusion, memory
   amplification, and M5 preservation regressions.
4. Resolve every Critical and Important finding and rerun affected and full
   tests.
5. Add only the narrow Slice B closure record, inspect the complete diff, and
   run `git diff --check`.
6. Commit and attempt direct publication of the exact tested WSL `main`
   commit. If WSL push times out, stop edits and use the approved exact-commit
   bundle fallback through Windows without changing the SHA.
7. Verify live GitHub `refs/heads/main`, fast-forward the other clone from
   GitHub, and prove both clones clean, stash-free, 0/0 divergent,
   unpushed-count zero, unexplained-untracked-count zero, and SHA-identical.
8. Hard stop. Slice C requires separate owner authorization.
