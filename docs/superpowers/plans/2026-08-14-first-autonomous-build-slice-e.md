# First Autonomous Build Slice E Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver one bounded, restartable, deterministic Demo 0 command that composes the earned Slice A-D authority into a real M5/M4A autonomous build, repair, review, dependency, and terminal-project loop.

**Architecture:** `scheduler.py` owns only controller policy: bootstrap, deterministic selection, bounded continuation, terminal classification, and presentation events. It persists no second copy of task state; `BoardAuthority` and its transaction journal remain authoritative, while immutable digest-bound stage evidence makes completed synthetic results and real executions replay-safe. `demo0.py` adapts the scheduler to existing M5 worktrees and Slice C/D stage controllers; `cli.py` is a presentation-only entry point.

**Tech Stack:** Python 3.12 standard library, pytest 8, existing AgenticOS orchestration ABI, M5 `WorktreeManager`, M4A `NamespaceLandlockRunner`, native Ubuntu WSL systemd/cgroup/Landlock/Bubblewrap.

**Spec:** `docs/superpowers/specs/2026-08-14-first-autonomous-build-design.md`

## Global Constraints

- Implement Slice E only; real providers, authentication, credentials, networking, UI, deployment, concurrency, G2, and G1 remain forbidden.
- `BoardAuthority`/`TransactionJournal` are the sole authoritative project/task state; evidence and traces never become an alternate scheduler state store.
- READY selection is exactly descending priority, then ascending creation sequence, then ascending task ID.
- Every loop has a controller-owned maximum step count and project deadline; no unbounded polling exists.
- All mutating BUILD/REPAIR/DOCUMENT work uses the existing real Slice C M5/M4A L2 path; VERIFY and REVIEW use existing Slice D M4A L1 paths.
- Worker/model output cannot assign IDs, choose work, change priority/state/limits/deadline, bypass dependencies/verification/review, or declare project completion.
- Normal and representative restart runs must produce the same logical authoritative outcome without duplicate dispatch, repair, satisfaction, or DONE transitions.
- Demo 0 leaves zero task scopes, cgroups, or worker processes and preserves a complete stable final workspace checkpoint.
- Runtime dependencies remain standard-library only.
- Author only in native WSL `~/src/AgenticOS`; publish and synchronize exactly through the standing repository-preservation contract.

---

### Task 1: Journal-Bound Bootstrap Stage Results

**Files:**
- Modify: `src/agenticos/orchestration/models.py`
- Modify: `src/agenticos/orchestration/board.py`
- Modify: `src/agenticos/orchestration/proposals.py`
- Modify: `schemas/orchestration-board.schema.json`
- Modify: `tests/orchestration/test_models.py`
- Modify: `tests/orchestration/test_board.py`
- Modify: `tests/orchestration/test_proposals.py`

**Interfaces:**
- Produces: optional `BoardTask.stage_result_digest: str | None`.
- Produces: `BoardAuthority.record_stage_success(...)` for one journaled `IN_PROGRESS -> DONE` bootstrap result.
- Produces: optional plan-stage arguments to `compile_planner_proposal(...)` so proposed tasks and PLAN completion publish in one board transaction.

- [ ] **Step 1: Write failing model and board tests**

Add literal digest tests proving malformed stage digests fail, valid stage results round-trip, replay is typed, and only RESEARCH/PLAN `IN_PROGRESS` tasks may record a bootstrap result. Add a planner test asserting one transaction atomically adds the compiled DAG and completes PLAN with the exact proposal digest.

- [ ] **Step 2: Run RED tests**

Run: `python3 -m pytest tests/orchestration/test_models.py tests/orchestration/test_board.py tests/orchestration/test_proposals.py -q`

Expected: FAIL because `stage_result_digest`, `record_stage_success`, and atomic plan completion do not exist.

- [ ] **Step 3: Implement the minimal authoritative mutation**

Add the optional digest at the end of `BoardTask`, validate/serialize it, and extend the strict schema. Implement a pure engine mutation that requires the exact expected revision, task type, `IN_PROGRESS` state, and result digest. Extend planner compilation with explicit `plan_task_id` and `stage_result_digest` arguments; preserve the old add-only call path for Slice A callers.

- [ ] **Step 4: Run GREEN tests and regressions**

Run: `python3 -m pytest tests/orchestration/test_models.py tests/orchestration/test_board.py tests/orchestration/test_proposals.py tests/orchestration/test_schemas.py -q`

Expected: PASS.

### Task 2: Bounded Scheduler Authority and Recovery State Machine

**Files:**
- Create: `src/agenticos/orchestration/scheduler.py`
- Create: `tests/orchestration/test_scheduler.py`
- Modify: `src/agenticos/orchestration/__init__.py`

**Interfaces:**
- Produces: `SchedulerLimits(max_steps: int)` and typed project terminal/failure values.
- Produces: `create_project(...) -> BoardAuthority` with controller-owned RESEARCH and dependent PLAN bootstrap tasks.
- Produces: `select_next_ready(snapshot) -> BoardTask | None` using `(-priority, creation_sequence, task_id)`.
- Produces: `AutonomousScheduler.run(stop_after: str | None = None) -> SchedulerResult`.
- Consumes: a narrow stage-driver protocol whose methods return validated research, planning, build, verification, review, recovery, checkpoint, and containment facts; driver output never mutates the board directly.

- [ ] **Step 1: Write failing bootstrap/selection/authority tests**

Cover bounded goal handling, immutable baseline/workspace/limits/deadline, RESEARCH -> PLAN dependencies, multiple READY ordering, proposed priority/ID/state/limit smuggling, dependency bypass, and cancellation.

- [ ] **Step 2: Run RED tests**

Run: `python3 -m pytest tests/orchestration/test_scheduler.py -q`

Expected: collection/import failure because the scheduler module does not exist.

- [ ] **Step 3: Implement bootstrap and deterministic continuation**

Implement controller-generated transaction IDs, exact board revisions, ready derivation, selection, and stage dispatch. RESEARCH validates/stores its bounded artifact before journaling DONE; PLAN validates the whole proposal then atomically completes PLAN and publishes the DAG. BUILD/DOCUMENT/REPAIR transitions and acceptance are driven only by typed existing stage results.

- [ ] **Step 4: Add failing lifecycle/terminal tests**

Cover verifier fail -> one repair, verifier infrastructure error -> no repair, review block -> one repair, malformed review -> no repair, recursive satisfaction, downstream release exactly once, DONE/FAILED/CANCELLED, no-ready deadlock, deadline, total-attempt limit, max-step exhaustion, and no busy loop.

- [ ] **Step 5: Implement the bounded loop and terminal classifier**

At each step recover known execution first, derive READY state, continue an authoritative active stage, select one READY task, or classify terminal/no-ready state. Project DONE requires every required task effectively DONE, no active lease/execution, stable equal final captures, and residue absence.

- [ ] **Step 6: Add failing replay/restart tests**

Reconstruct the scheduler from the same journal/evidence at research complete, plan commit, build terminalization, verifier failure, repair creation, repair completion, review block, and pre-DONE. Assert the final board and dispatch counts match uninterrupted execution.

- [ ] **Step 7: Implement immutable evidence and idempotent recovery**

Write canonical digest-bound evidence before its board effect. On restart, validate the journal first, reuse an exact accepted stage result, reconcile an existing Slice C ledger/lease instead of redispatching, discover repair tasks only from board state, and make repeated satisfaction/DONE operations no-ops.

- [ ] **Step 8: Run GREEN scheduler tests**

Run: `python3 -m pytest tests/orchestration/test_scheduler.py tests/orchestration/test_journal.py tests/orchestration/test_repair.py -q`

Expected: PASS.

### Task 3: Deterministic Demo Fixture and Real A-D Driver

**Files:**
- Modify: `src/agenticos/orchestration/synthetic.py`
- Modify: `src/agenticos/orchestration/synthetic_worker.py`
- Create: `src/agenticos/orchestration/demo0.py`
- Modify: `tests/orchestration/test_synthetic.py`
- Create: `tests/orchestration/test_demo0_linux.py`

**Interfaces:**
- Produces: a Demo planner proposal with `feature` BUILD and dependent `follow-up` DOCUMENT tasks.
- Produces: `Demo0Runtime.create(run_root, goal)` implementing the scheduler stage-driver protocol with real M5/M4A and Slice C/D controllers.
- Produces: `Demo0Runtime.resume(run_root)` using the same M5 workspace, board journal, evidence, lease, and execution ledgers.

- [ ] **Step 1: Write the failing deterministic-plan test**

Assert the validated proposal has two tasks, the second depends on the first, and all IDs/statuses/acceptance/roles are assigned or replaced by controller policy rather than model authority.

- [ ] **Step 2: Run RED synthetic tests**

Run: `python3 -m pytest tests/orchestration/test_synthetic.py tests/orchestration/test_proposals.py -q`

Expected: FAIL because the Demo plan fixture does not exist.

- [ ] **Step 3: Add the minimal Demo fixture scenarios**

Keep Slice A scenarios stable; add only a Demo multi-task planner artifact and a dependent follow-up workspace edit. Do not add provider clients, network calls, generalized fixture databases, or dynamic scheduling.

- [ ] **Step 4: Write the failing native Linux acceptance test**

Name the test `test_DEMO_0_SYNTHETIC_AUTONOMOUS_LOOP`. It must initialize a real Git fixture, reserve one real M5 worktree, run broken BUILD under L2, fail real L1 verification, execute feature REPAIR under L2, pass verification, block real independent L1 review, execute review REPAIR under L2, pass verification/review, recursively satisfy the feature, release and execute the dependent task, and reach authoritative DONE.

- [ ] **Step 5: Implement the real stage driver by composing A-D**

Use `WorktreeManager`, `WorkspaceLeaseLedger`, `ExecutionLedger`, `SyntheticBuildController`, `VerificationController`, `ReviewController`, `RepairController`, and `SyntheticRepairAdapter`. Create fixed runners with scrubbed homes/tmp, exact worker paths, the existing git mask, and controller reservations. Persist accepted completion evidence before board advancement and prove each scope absent after each stage.

- [ ] **Step 6: Run the real acceptance test GREEN**

Run: `python3 -m pytest tests/orchestration/test_demo0_linux.py::test_DEMO_0_SYNTHETIC_AUTONOMOUS_LOOP -vv -s`

Expected: PASS with the required build/verify/repair/review/dependency/DONE trace and zero residual scope.

### Task 4: Fault Corpus, Repeatability, and Representative Crash Recovery

**Files:**
- Modify: `tests/orchestration/test_scheduler.py`
- Modify: `tests/orchestration/test_demo0_linux.py`

- [ ] **Step 1: Add failing fault-corpus tests**

Cover successful/malformed research, valid/rejected DAG, build success/crash/timeout, verifier fail/infrastructure error, reviewer block/malformed, repair success/repeated fingerprint, cancellation, stale result, deadlock, max steps, deadline, and restart. Assert infrastructure/malformed/stale cases never create code repair.

- [ ] **Step 2: Add failing authority and idempotency tests**

Replay research, plan, build, verifier, reviewer, repair creation/completion, satisfaction, and project DONE. Assert no duplicate authoritative effect and no output can reset attempts/budgets/failure, extend deadlines, or request looping.

- [ ] **Step 3: Implement only missing typed classifications/idempotency guards**

Add no new architecture. Each fix must be the smallest controller check that makes the corresponding failing behavior test pass.

- [ ] **Step 4: Add repeatability and restart acceptance tests**

Run Demo 0 from two clean independent fixture repositories and compare normalized logical traces/final boards. Run one representative end-to-end restart schedule spanning at least research, planning, verifier failure, repair creation, review block, and pre-DONE boundaries; assert dispatch and repair counts are unchanged.

- [ ] **Step 5: Run the focused native suite**

Run: `python3 -m pytest tests/orchestration/test_scheduler.py tests/orchestration/test_demo0_linux.py tests/orchestration/test_slice_d_linux.py -q`

Expected: PASS.

### Task 5: Minimal One-Command CLI and Status View

**Files:**
- Create: `src/agenticos/orchestration/cli.py`
- Create: `tests/orchestration/test_cli.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Produces: `python -m agenticos.orchestration.cli demo0 [--run-root PATH]` and `agenticos-demo demo0`.
- Exit `0` only for authoritative DONE; non-DONE returns nonzero.

- [ ] **Step 1: Write failing CLI tests**

Assert argument bounds, one owner goal as inert text, bounded trace lines, final status/counts/checkpoint/evidence IDs, and exit status derived from the final board. Assert CLI text cannot mutate scheduler state.

- [ ] **Step 2: Run RED CLI tests**

Run: `python3 -m pytest tests/orchestration/test_cli.py -q`

Expected: FAIL because the CLI module/entry point does not exist.

- [ ] **Step 3: Implement the presentation-only CLI**

Use `argparse`, a caller-supplied or securely created run root, and `Demo0Runtime`. Print only bounded events and a fixed status summary derived from the final authoritative snapshot/evidence. Do not add prompts, dashboards, servers, provider controls, or interactive editing.

- [ ] **Step 4: Run the one-command demo**

Run: `python3 -m agenticos.orchestration.cli demo0`

Expected: the exact required logical sequence ending in `PROJECT DONE`, stable checkpoint/evidence identifiers, and exit `0`.

### Task 6: Review, Qualification, Closure, and Exact Publication

**Files:**
- Create: `docs/phase-zero/first-autonomous-build-slice-e-closure.md`
- Modify only files required by resolved Critical/Important review findings.

- [ ] **Step 1: Inspect the complete diff and run static hygiene**

Run: `git diff --check && git diff --stat && git status --short`

- [ ] **Step 2: Perform focused adversarial review**

Review livelock, duplicate dispatch, READY/dependency errors, early parent release, stale advancement, duplicate repair, restart redispatch, terminal-with-active-containment, premature DONE, owner-block misclassification, limit/deadline bypass, CLI authority, journal divergence, checkpoint mismatch, verify/review bypass, accidental concurrent mutation, and accidental Slice F work. Resolve every Critical and Important finding test-first.

- [ ] **Step 3: Run repeat Demo 0 and focused Windows/native WSL tests**

Run the one-command demo at least twice in independent run roots. Run platform-neutral orchestration tests on Windows and all orchestration/M4A/M5 focused tests natively in WSL.

- [ ] **Step 4: Run full regressions on exact candidate trees**

Run native WSL/Linux full pytest in an exact Git-backed candidate and full Windows pytest in an exact Git-backed candidate. Record exact passed/skipped counts and any environment-only diagnosis honestly.

- [ ] **Step 5: Write closure documentation**

Record Demo 0 trace, acceptance/restart/repeatability evidence, final stable checkpoint and residue proof, `REAL_PROVIDER_EXECUTION=NO`, `DEMO_0_STATUS=PASSED`, and `FIRST_AUTONOMOUS_BUILD_COMPLETE=NO`.

- [ ] **Step 6: Commit and publish the exact tested WSL commit**

Commit once the slice is green, push from WSL, verify `git ls-remote`. If and only if direct WSL push times out, use the approved exact-commit bundle fallback without changing the commit SHA.

- [ ] **Step 7: Synchronize and prove the stable boundary**

Fast-forward Windows from verified GitHub, fetch WSL, and prove Windows HEAD = WSL HEAD = fetched origin/main = live GitHub main; both trees clean, divergence `0/0`, unpushed commits `0`, unexplained untracked files `0`, stashes `0`, and residual scopes/cgroups/workers `0`.

- [ ] **Step 8: Hard stop before F1**

Report the requested 24-part final record and do not begin provider work without `AUTHORIZE_FIRST_AUTONOMOUS_BUILD_SLICE_F1=YES`.
