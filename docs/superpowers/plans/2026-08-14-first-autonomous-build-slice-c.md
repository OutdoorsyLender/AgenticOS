# First Autonomous Build Slice C Implementation Plan

Status: implemented and independently reviewed on 2026-08-14; publication is
recorded by the repository history containing the accompanying closure.

> **For AgenticOS implementers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Apply superpowers:test-driven-development for every behavior change and superpowers:verification-before-completion before publication.

**Goal:** Execute one deterministic synthetic builder inside a controller-owned M5 workspace through a controller-selected, split-phase M4A containment, while preserving exclusive fenced workspace authority, durable process binding, fail-closed recovery, and stable terminal checkpoint evidence.

**Architecture:** Extend the existing M4A runner at its authenticated pre-exec gate with a controller-selected containment reservation and a prepared handle. Add two narrow orchestration authorities: an append-only, locked workspace-lease ledger and an append-only execution ledger/controller that binds board dispatch identity, lease, prepared-process receipt, cancellation, recovery, and terminal checkpoint capture. Add an out-of-process synthetic builder using the existing exact provider-neutral ABI; it may mutate only deterministic fixture paths under `/workspace`, while M4A/Landlock and M5 remain the actual enforcement and observation layers.

**Tech Stack:** Python 3.11+, pytest, Linux systemd user scopes, cgroup v2, Bubblewrap, Landlock native launcher, existing AgenticOS canonical JSON/board/protocol/M5 worktree primitives, Windows PowerShell regression clone, Ubuntu WSL authoring clone.

---

## Scope and authority gates

- [ ] Begin only from exact baseline `cc6a1b8efb7c14b7df43c60d7b84136be62a970b` with Windows HEAD == WSL HEAD == origin/main == live GitHub main, both clones clean, divergence 0/0, stashes 0.
- [ ] Implement only Slice C: synthetic builder execution and the minimum trusted execution/lease/recovery substrate it requires.
- [ ] Do not add verifier, reviewer, repair, scheduler, provider, authentication, network, Codex, deployment, UI, or Slice D behavior.
- [ ] Preserve `NamespaceLandlockRunner.run()` as a compatibility composition of `prepare()` -> `release()` -> `wait()`.
- [ ] Keep WSL `/home/brand/src/AgenticOS` as the sole authoring clone. Use Windows `C:\AgenticOS` only after publication for synchronization and regression.

## Task 1: Split M4A at the authenticated pre-exec gate

**Files:**

- Modify: `src/agenticos/sandbox/models.py`
- Modify: `src/agenticos/sandbox/m4a_runner.py`
- Test: `tests/conformance/test_m4a_split_phase.py`
- Test: `tests/conformance/test_m4a_integration.py`

- [ ] Write failing unit tests for controller-selected containment scope validation, a measured prepared receipt, no worker entry before release, exact receipt/release-token binding, stale/forged/double release rejection, pre-release cancellation, timeout cancellation, recursive cgroup drain, and one-shot compatibility.
- [ ] Run `python3 -m pytest tests/conformance/test_m4a_split_phase.py -q` and confirm the new tests fail for missing split-phase interfaces.
- [ ] Add immutable `ContainmentReservation` and `PreparedProcessReceipt` models. Bind project/task generation/attempt/controller epoch/lease epoch/nonce, exact unit/scope, measured PID/process-group/start ticks/boot ID/cgroup, verified namespace evidence, policy digest, workspace identity, intended executable, and argv.
- [ ] Add a single-owner `PreparedM4AExecution` handle exposing `receipt`, `release(expected_receipt, release_nonce)`, `wait(timeout)`, and `cancel()`. Every failure path must cancel, recursively drain, stop the exact scope, and fail closed if termination is not proven.
- [ ] Refactor `NamespaceLandlockRunner.prepare(...)` to stop after authenticated namespace/Landlock evidence and before the existing `X` exec release. Accept the exact controller reservation before spawn; do not generate containment identity inside the runner.
- [ ] Refactor `run()` into the compatibility composition without weakening existing gate ordering or evidence.
- [ ] Run focused split-phase unit and M4A integration tests to green.

## Task 2: Add exclusive fenced project-workspace leases

**Files:**

- Create: `src/agenticos/orchestration/workspace.py`
- Modify: `src/agenticos/orchestration/__init__.py`
- Test: `tests/orchestration/test_workspace_lease.py`

- [ ] Write failing tests for one ACTIVE lease per project workspace, monotonic lease epoch, exact project/task/generation/attempt/controller epoch/workspace/dispatch nonce/precheckpoint binding, stale-controller and stale-lease rejection, duplicate acquire rejection, forged release rejection, bounded records, concurrent acquisition, durable recovery, and the states ACTIVE/RELEASED/CANCELLED/STALE/RECOVERY_REQUIRED.
- [ ] Run `python3 -m pytest tests/orchestration/test_workspace_lease.py -q` and confirm RED.
- [ ] Implement strict `WorkspaceLeaseIdentity`, `WorkspaceLeaseRecord`, `WorkspaceLeaseState`, `WorkspaceLeaseError`, and `WorkspaceLeaseLedger` models.
- [ ] Use a per-project cross-process lock and immutable canonical JSON records with fsync plus no-replace publication. Validate the complete hash chain and exact fields during every recovery/mutation. Never infer release or silently repair a corrupt/dangling ledger.
- [ ] Implement `acquire`, `recover`, `release`, `cancel`, `mark_stale`, and `require_active` as exact fenced operations; only the current identity may mutate the current ACTIVE record.
- [ ] Run lease tests to green on Windows and WSL.

## Task 3: Add durable execution binding and fail-closed recovery

**Files:**

- Create: `src/agenticos/orchestration/execution.py`
- Modify: `src/agenticos/orchestration/__init__.py`
- Test: `tests/orchestration/test_execution.py`

- [ ] Write failing tests for the ordering `board IN_PROGRESS + lease ACTIVE -> M4A PREPARE -> durable PROCESS_STARTED -> RELEASE -> WAIT/CANCEL/DRAIN`, receipt-persistence failure before release, no release without durable receipt, exact receipt/lease/dispatch/workspace binding, no redispatch on restart, PID reuse/boot ID/start-ticks/cgroup mismatch, missing cgroup, ambiguous liveness, recovery cancellation, cancellation winning over late success, and bounded diagnostics.
- [ ] Run `python3 -m pytest tests/orchestration/test_execution.py -q` and confirm RED.
- [ ] Add strict `ExecutionState`, `ExecutionRecord`, `ExecutionOutcome`, `ExecutionError`, and append-only `ExecutionLedger` models. Persist a hash-chained canonical `PROCESS_STARTED` record before calling `release()`.
- [ ] Add `SyntheticBuildController.execute(...)` that accepts an already durable IN_PROGRESS board snapshot, exact `DispatchIdentity`, active workspace lease, pre-checkpoint, controller-selected reservation, M4A runner, and M5 manager. Reject any mismatch before spawn.
- [ ] On receipt persistence failure, call prepared `cancel()`, prove recursive containment drain, revalidate workspace identity, capture a second checkpoint, and require pre == post; otherwise return/raise a typed fail-closed outcome.
- [ ] Add `recover(...)` that inspects only the recorded exact PID + boot ID + start ticks + cgroup/scope and never redispatches. Ambiguity or mismatch becomes RECOVERY_REQUIRED/FAILED, not success.
- [ ] Add a durable cancellation-intent record and ensure it dominates any subsequently observed success result.
- [ ] Run execution tests to green on Windows with fakes and on WSL with applicable native primitives.

## Task 4: Execute the deterministic synthetic builder through real M5/M4A

**Files:**

- Modify: `src/agenticos/orchestration/synthetic.py`
- Create: `src/agenticos/orchestration/synthetic_worker.py`
- Test: `tests/orchestration/test_synthetic_execution.py`
- Test: `tests/conformance/test_slice_c_integration.py`

- [ ] Write failing tests for exact provider-neutral request/result/event binding and all required scenarios: `SUCCESSFUL_EDIT`, `NO_OP`, `INVALID_PATH_ATTEMPT`, `DOT_GIT_ATTEMPT`, `CRASH_AFTER_EDIT`, `TIMEOUT_AFTER_EDIT`, `CHILD_PROCESS_CASE`, and `POST_TERMINAL_MUTATION_ATTEMPT`.
- [ ] Run the new synthetic unit tests and confirm RED.
- [ ] Extend `SyntheticScenario` only with Slice C scenarios. Implement a standalone worker that reads one bounded canonical request file from private task tmp, emits bounded canonical AgentEvent frames plus one AgentResult, and performs only deterministic scenario actions.
- [ ] For `SUCCESSFUL_EDIT`, modify a fixed tracked fixture and create a fixed untracked fixture under `/workspace`. For `NO_OP`, do not mutate. For invalid and `.git` attempts, attempt the action and emit a terminal result consistent with the observed denial. For crash/timeout/child/post-terminal cases, expose deterministic bounded behavior for controller enforcement tests.
- [ ] The controller must validate stdout with `AgentStreamValidator`, classify malformed/extra/late output fail closed, and never trust worker claims as workspace evidence.
- [ ] After process death/cancellation and proven recursive cgroup emptiness, revalidate the M5 workspace identity and take two immediate complete/reusable checkpoints. Terminal success is eligible only when both checkpoint digests and complete checkpoint objects are identical. Capture disagreement, incomplete evidence, or workspace identity mismatch is fail closed.
- [ ] Add an Ubuntu WSL integration test using a real temporary Git repository, real M5 task worktree, real split-phase M4A, and the real synthetic worker. Assert exact pre/post checkpoint changes for successful edit and no-op plus denial/drain behavior for adversarial scenarios.
- [ ] Run the real Slice C WSL integration suite to green; Windows must run all platform-neutral models, leases, recovery, protocol, and applicable M5 tests.

## Task 5: Adversarial review, closure evidence, and exact-commit publication

**Files:**

- Create: `docs/phase-zero/first-autonomous-build-slice-c-closure.md`
- Modify only files required by review findings.

- [ ] Run the focused Windows and WSL matrices, then the full suite in both clones where applicable. Preserve exact commands/counts and classify skips honestly.
- [ ] Request an independent adversarial code review over the frozen candidate. Require Critical/Important findings, exact files/lines, and an explicit readiness verdict.
- [ ] Use superpowers:receiving-code-review for every finding. Resolve and retest all Critical and Important findings; rerun review if material execution/security code changes.
- [ ] Inspect the complete diff and run `git diff --check` before commit.
- [ ] Write the closure artifact with exact baseline/head, scope, design/implementation mapping, containment receipt fields, release ordering evidence, lease/recovery semantics, scenario matrix, terminal double-checkpoint proof, boundedness, tests, review verdict, limitations, and explicit deferred Slice D authority.
- [ ] Run superpowers:verification-before-completion and record fresh final evidence.
- [ ] Commit the complete Slice C candidate in WSL. Push the exact commit, or if WSL lacks credentials use the approved exact-commit `git bundle -> Windows fetch -> Windows push` publication path without authoring in Windows.
- [ ] Verify live GitHub `refs/heads/main` independently with `git ls-remote`, fetch in both clones, fast-forward only, and prove Windows HEAD == WSL HEAD == origin/main == live GitHub, both worktrees clean, divergence 0/0, unpushed commits 0, stashes 0.
- [ ] Stop before Slice D.

## Required completion output

- [ ] Report the 18 requested Slice C closure items from the authorization contract, including exact SHAs, test/review evidence, remaining limitations, and repository preservation proof.
- [ ] End with `FIRST_AUTONOMOUS_BUILD_SLICE_C=COMPLETE` only if every gate is earned; otherwise use an honest blocked/failed value.
- [ ] Do not begin Slice D.
