# First Autonomous Build Slice D Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove controller-owned BUILD-to-verification/review failure, idempotent repair, real M4A/M5 repair execution, and recursive task satisfaction without introducing an autonomous scheduler.

**Architecture:** Keep the Slice A board and agent ABI authoritative, reuse Slice B checkpoints as immutable content identities, and reuse Slice C split-phase M4A execution for all workspace mutation. Add narrow `verification.py`, `review.py`, and `repair.py` controller modules; deterministic verification and synthetic review run out of process under M4A L1, while repair runs through the existing Slice C L2 controller. Board mutations for failure-to-repair and descendant satisfaction are single durable transactions.

**Tech Stack:** Python 3.12+ standard library, pytest, native Ubuntu WSL systemd/cgroup v2, Bubblewrap, Landlock, Git-backed M5 worktrees.

**Spec:** `docs/superpowers/specs/2026-08-14-first-autonomous-build-design.md`

## Global Constraints

- Implement Slice D only; no scheduler loop, provider adapter, login, networking, UI, deployment, concurrent mutators, or Codex admission.
- Verification commands are controller-registered exact executable/argv values; reject shells, interpolation, and agent-supplied commands.
- Verification and review use M4A `L1_INSPECT`; repair uses the real Slice C `L2_BUILD` path.
- Every read-only result binds project, board task, generation, attempt, controller epoch, checkpoint digest, dispatch identity, containment evidence, and verifier/reviewer identity.
- Verification/review workspace mutation is an infrastructure/security failure and never creates code repair work.
- Eligible semantic verification or validated blocking review failure creates exactly one repair child per root-lineage fingerprint.
- Cancellation and stale identities dominate late success; original failure evidence remains on satisfied parents.
- Root-lineage limits do not reset on child creation.
- WSL is the authoring/security-proof clone; Windows is regression and final synchronization only.
- One final Slice D commit is published only after tests, adversarial review, diff inspection, and closure evidence are complete.

---

### Task 1: Decouple board-task dispatch from M5 project-workspace ownership

**Files:**
- Modify: `src/agenticos/orchestration/workspace.py`
- Modify: `src/agenticos/orchestration/execution.py`
- Test: `tests/orchestration/test_workspace_lease.py`
- Test: `tests/orchestration/test_execution.py`

**Interfaces:**
- Consumes: `WorkspaceIdentityRef(workspace_id, generation, reservation_id)` and `WorkspaceCheckpoint.task_id/generation`.
- Produces: Slice C lease admission/capture checks that bind checkpoint ownership to `identity.workspace.workspace_id/generation`, while board/dispatch checks remain bound to `identity.task_id/task_generation`.

- [ ] Write focused tests where a REPAIR board task has a distinct task ID/generation but shares the original project `WorkspaceIdentityRef`; name the break as accidental re-coupling of task identity to workspace ownership.
- [ ] Run the two focused tests and verify `LEASE_ADMISSION_EVIDENCE_MISMATCH` / `TERMINAL_WORKSPACE_IDENTITY_MISMATCH` under the old behavior.
- [ ] Change only checkpoint ownership comparisons and checkpoint capture arguments to use the explicit workspace identity.
- [ ] Run `python3 -m pytest tests/orchestration/test_workspace_lease.py tests/orchestration/test_execution.py -q` and keep all Slice C tests green.

### Task 2: Controller-owned verifier types, registry, and deterministic fingerprints

**Files:**
- Create: `src/agenticos/orchestration/verification.py`
- Create: `src/agenticos/orchestration/verifier_worker.py`
- Modify: `src/agenticos/orchestration/__init__.py`
- Test: `tests/orchestration/test_verification.py`

**Interfaces:**
- Produces: `FailureClassification`, `VerificationClassification`, `VerifierSpec`, `VerifierRegistry`, `VerificationResult`, `VerificationController.verify(...)`, and `verification_failure_fingerprint(...)`.
- `VerifierSpec` binds exact executable, exact argv, `/workspace`, timeout, stdout/stderr bounds, accepted pass/fail exit codes, and optional fixture identity; `spec_id` is the canonical SHA-256 identity.

- [ ] Write tests proving exact spec round-trip/identity, registry-only selection, rejection of `sh`, `bash`, `-c`, empty/non-absolute argv, unknown fields, model-supplied argv, and unstable/unbounded fingerprint inputs.
- [ ] Run those tests and verify they fail because the new types do not exist.
- [ ] Implement strict immutable types, canonical digesting, bounded normalized semantic-failure evidence, and the complete typed failure enum required by Slice D.
- [ ] Implement the deterministic verifier worker scenarios for pass, semantic fail, infrastructure exit, timeout, oversized output, and read-only attack attempts using only fixed scenario argv.
- [ ] Run `python3 -m pytest tests/orchestration/test_verification.py -q` and verify the type/registry/fingerprint cases pass.

### Task 3: M4A L1 verifier execution and checkpoint immutability

**Files:**
- Modify: `src/agenticos/orchestration/verification.py`
- Test: `tests/orchestration/test_verification.py`
- Test: `tests/orchestration/test_slice_d_linux.py`

**Interfaces:**
- Consumes: live `BoardSnapshot`, exact stable Slice B checkpoint, `NamespaceLandlockRunner(profile=M4AProfile.INSPECT)`, controller-created `ContainmentReservation`, `WorktreeManager`, and registered `VerifierSpec`.
- Produces: typed `VerificationResult` with exact bindings, exit classification/code, bounded stdout/stderr digests and byte counts, timeout/cancel state, prepared-process containment evidence, PASS/FAIL/INFRASTRUCTURE_ERROR, and optional deterministic failure fingerprint.

- [ ] Write fake-runner tests for stale generation/attempt/controller epoch, wrong checkpoint/spec, pass/fail/timeout/infrastructure exits, output bounds, cancellation beating late PASS, malformed containment evidence, and post-run checkpoint disagreement.
- [ ] Run each new unit test before implementation and confirm the expected missing/incorrect behavior.
- [ ] Implement split-phase L1 prepare/release/wait, strict receipt/spec binding, bounded evidence hashing, two post-stage captures, and equality with the input checkpoint.
- [ ] Add real WSL tests proving L1 workspace create/write/rename/delete denial plus `.git`, host, controller-state, and credential-sentinel denial, with unchanged complete checkpoints and zero residual scopes.
- [ ] Run `python3 -m pytest tests/orchestration/test_verification.py tests/orchestration/test_slice_d_linux.py -q` on WSL.

### Task 4: Independent synthetic reviewer and typed advisory validation

**Files:**
- Create: `src/agenticos/orchestration/review.py`
- Modify: `src/agenticos/orchestration/synthetic.py`
- Modify: `src/agenticos/orchestration/synthetic_worker.py`
- Modify: `src/agenticos/orchestration/__init__.py`
- Test: `tests/orchestration/test_review.py`
- Test: `tests/orchestration/test_slice_d_linux.py`

**Interfaces:**
- Produces: `ReviewerExecutionIdentity`, `ReviewContext`, `ReviewClassification`, `ReviewResult`, `SyntheticReviewerAdapter`, `ReviewController.review(...)`, and `review_failure_fingerprint(...)`.
- Consumes and validates the existing `AgentTaskRequest`/`AgentEvent`/`AgentResult` ABI and existing `ReviewerProposal` advisory type.

- [ ] Write tests for PASS and blocking proposals, malformed/unknown/oversized output, stale identity, wrong checkpoint, duplicate terminal/result, verification-not-PASS, arbitrary command/provider/task-ID/board-revision claims, and reused builder dispatch/session/adapter/containment identity.
- [ ] Run the tests and verify expected failures before implementation.
- [ ] Extend the standalone synthetic worker with fixed read-only reviewer PASS/BLOCKING/adversarial scenarios that emit canonical ABI events/results and one bounded proposal payload.
- [ ] Implement controller-built bounded context, exact ABI validation, proposal schema validation, independence checks, and PASS gating on the exact successful verification/checkpoint.
- [ ] Reuse the L1 read-only executor and prove separate adapter instance, dispatch nonce, process/cgroup, and immutable checkpoint on native WSL.
- [ ] Run `python3 -m pytest tests/orchestration/test_review.py tests/orchestration/test_slice_d_linux.py -q`.

### Task 5: Atomic idempotent repair creation and root-lineage budgets

**Files:**
- Modify: `src/agenticos/orchestration/board.py`
- Create: `src/agenticos/orchestration/repair.py`
- Modify: `src/agenticos/orchestration/__init__.py`
- Test: `tests/orchestration/test_board.py`
- Test: `tests/orchestration/test_repair.py`
- Test: `tests/orchestration/test_journal.py`

**Interfaces:**
- Produces: `RepairBudgetPolicy`, `RepairBudgetUsage`, `RepairCreationOutcome`, `RepairController.create_for_verification_failure(...)`, and `RepairController.create_for_review_failure(...)`.
- Board engine/authority gains narrowly typed atomic operations for result recording, parent `WAITING_REPAIR` + child addition, budget terminalization, and result-digest-preserving satisfaction.

- [ ] Write tests proving one verification repair, one review repair, deterministic controller task IDs, inherited satisfied dependencies, separate lineage edges, atomic journal recovery, and no dependency cycle.
- [ ] Add replay/restart tests: same failure before/after creation, duplicate verifier/reviewer result, stale repair result, and repeated identical fingerprint all yield one child.
- [ ] Add budget tests for total attempts, repair depth, repair task count, total task cap, distinct fingerprints, repeated fingerprint count, consecutive failures, deadline, and no reset through repair-of-repair.
- [ ] Run tests and verify they fail against the pre-Slice-D board APIs.
- [ ] Implement the minimal typed board operations and repair policy; only semantic verification failure and validated blocking review may create children. Infrastructure, malformed, stale, mutation, timeout, cancelled, containment, and checkpoint failures terminalize/retry by typed policy without repair.
- [ ] Map exhausted repair budget deterministically to task `FAILED`/`RESOURCE_LIMIT`, never `OWNER_BLOCKED`.
- [ ] Run `python3 -m pytest tests/orchestration/test_board.py tests/orchestration/test_journal.py tests/orchestration/test_repair.py -q`.

### Task 6: Real Slice C repair execution and recursive satisfaction

**Files:**
- Modify: `src/agenticos/orchestration/repair.py`
- Modify: `src/agenticos/orchestration/synthetic.py`
- Modify: `src/agenticos/orchestration/synthetic_worker.py`
- Test: `tests/orchestration/test_repair.py`
- Test: `tests/orchestration/test_slice_d_linux.py`

**Interfaces:**
- Produces: `SyntheticRepairAdapter.execute(...)` that constructs the child request/lease/reservation and delegates mutation to `SyntheticBuildController.execute(...)`; `RepairController.satisfy_lineage(...)` atomically marks the successful repair and waiting ancestors DONE with `satisfying_descendant_id` while retaining historical result digests.

- [ ] Write unit tests that a repair must acquire the fenced workspace lease, bind the current stable checkpoint, use L2, require recursive drain/two stable post-checkpoints, and reject stale/cancelled/duplicate completion.
- [ ] Write recursive-satisfaction tests for repair-of-repair, retained failure history, and dependent tasks remaining BACKLOG until the root is effectively satisfied.
- [ ] Run tests and verify the missing execution/satisfaction APIs fail.
- [ ] Add fixed synthetic repair scenarios that change the verifier/reviewer fixture through `/workspace` only and run them via Slice C.
- [ ] Implement the narrow repair adapter and atomic recursive satisfaction; do not select another task or loop.
- [ ] Run `python3 -m pytest tests/orchestration/test_repair.py tests/orchestration/test_slice_d_linux.py -q`.

### Task 7: Required end-to-end flows, adversarial matrix, and regressions

**Files:**
- Modify: `tests/orchestration/test_slice_d_linux.py`
- Modify: `tests/orchestration/test_verification.py`
- Modify: `tests/orchestration/test_review.py`
- Modify: `tests/orchestration/test_repair.py`

**Interfaces:**
- Produces two explicitly staged (non-scheduler) native WSL demonstrations: Build→VerifyFail→Repair→VerifyPass→ReviewPass and Build→VerifyPass→ReviewFail→Repair→VerifyPass→ReviewPass.

- [ ] Build a temporary Git repository and real M5 project worktree fixture, then use the real M4A L2 Slice C builder/repair and L1 verifier/reviewer controllers.
- [ ] Prove verification-failure flow creates exactly one repair child and recursively satisfies the parent only after repair verification and independent review pass.
- [ ] Prove review-failure flow creates exactly one review repair and follows the same reverify/rereview/satisfaction gates.
- [ ] Exercise replay, checkpoint change between verify/review, cancellation races, output amplification, and all read-only attack fixtures; assert no residual scopes after each flow.
- [ ] Run focused WSL: `python3 -m pytest tests/orchestration tests/conformance/test_m4a_integration.py tests/conformance/test_m4a_split_phase.py tests/test_worktree.py tests/test_worktree_checkpoint.py tests/test_worktree_sandbox.py -q`.
- [ ] Run focused Windows platform-neutral tests from an exact Git-backed candidate checkout; Linux enforcement cases must skip, not be simulated.
- [ ] Run full WSL and Windows regressions with `python -m pytest -q` and record exact counts.

### Task 8: Adversarial review, closure, publication, and synchronization

**Files:**
- Create: `docs/phase-zero/first-autonomous-build-slice-d-closure.md`
- Modify only findings-driven Slice D files if Critical or Important review issues are confirmed.

**Interfaces:**
- Produces: final Slice D evidence checkpoint and exact published commit; deliberately produces no Slice E code.

- [ ] Review the frozen diff for command injection, reviewer authority, PASS replay, read-only mutation, self-review, duplicate repairs, lineage cycles, root-budget reset, infinite repetition, stale identity, cancellation races, infra-to-repair confusion, premature satisfaction/readiness, checkpoint mismatch, output amplification, and later-slice scope creep.
- [ ] For every confirmed Critical/Important finding, add a failing regression test, verify RED, implement the smallest fix, and re-run focused tests; repeat review until none remain.
- [ ] Inspect `git diff`, run `git diff --check`, and write only the narrow Slice D closure with exact Windows/WSL/full/focused results and review resolutions.
- [ ] Run final focused/full verification and prove zero residual `aos-task-*` scopes/cgroups/processes.
- [ ] Commit implementation, tests, plan, and closure as one exact tested Slice D commit on the WSL authoring branch.
- [ ] Fast-forward WSL `main`, push normally; only if that push times out, use the approved exact-commit bundle fallback without recreating the commit.
- [ ] Verify live GitHub with `git ls-remote`, fast-forward Windows from GitHub, fetch WSL, and prove identical SHA, clean trees, divergence `0/0`, zero unpushed commits, zero unexplained untracked files, and zero stashes.
- [ ] Hard stop without beginning Slice E.
