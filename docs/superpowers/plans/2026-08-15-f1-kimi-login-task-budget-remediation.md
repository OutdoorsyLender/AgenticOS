# F1 Kimi Login Task-Budget Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the under-sized Kimi owner-login task ceiling with one measured finite bound and fail closed before provider traffic when the scope does not match the qualified budget.

**Architecture:** Preserve the existing login namespace, relay, DNS worker, TLS/SNI gates, credential mount, and recursive drain. Add a cgroup-v2 preflight that requires the exact qualified scope budget before passive runtime validation, convert task-creation exhaustion into stable content-free relay errors, and qualify the 21-task ceiling with pinned-runtime and synthetic TLS fixtures under real systemd scopes.

**Tech Stack:** Python 3.14, pytest, systemd 259 user scopes, cgroup v2 pids controller, Bubblewrap 0.11.1, pinned Kimi Code CLI 0.36.1.

**Spec:** `docs/phase-zero/first-autonomous-build-slice-f1-kimi-login-ceremony-preparation.md` plus the binding owner authorization `REMEDIATE_F1_KIMI_LOGIN_TASK_BUDGET=YES`.

## Global Constraints

- Never perform real OAuth, real `auth.kimi.com` traffic, model inference, a real prompt, credential-content access, API-key use, version change, F2, G2, or G1.
- Preserve exact login allowlist `auth.kimi.com:443`; deny `api.kimi.com:443`, `code.kimi.com:443`, IP literals, and every other destination.
- Preserve the bounded resolver worker and all DNS special-address, TLS ClientHello, exact-SNI, ECH, and second-ClientHello controls.
- Preserve `MemoryMax=1G`, `KillMode=control-group`, `TimeoutStopSec=5s`, one active auth connection, connection limit, credential isolation, empty workspace, and recursive drain.
- Measured old topology: 4 processes, 16 tasks before resolver creation; component task counts were `bwrap=2`, `kimi-code=11`, and `python3=3`.
- Measured required peak: 17 tasks, repeated four times with resolver-worker success and zero `pids.events max` events.
- Candidate finite bound: `QUALIFIED_LOGIN_TASKS_MAX=21`, calculated as measured peak 17 plus fixed headroom 4.

---

### Task 1: Exact cgroup task-budget preflight

**Files:**
- Modify: `src/agenticos/providers/kimi_login.py`
- Modify: `tests/providers/test_kimi_login.py`

**Interfaces:**
- Produces constants `MEASURED_LOGIN_TASK_PEAK`, `LOGIN_TASK_HEADROOM`, and `QUALIFIED_LOGIN_TASKS_MAX`.
- Produces `validate_login_task_budget(cgroup_text: str, *, cgroup_root: Path = Path("/sys/fs/cgroup")) -> None`.
- `cli_main()` consumes the preflight after exact-scope validation and before repository, passive-runtime, credential-mount, or login activity.

- [ ] **Step 1: Write failing unit tests**

Add real filesystem fixtures for cgroup `pids.max`, `pids.current`, and `pids.events`. Require exact max 21, current 1, and zero prior max events; reject 16 as `LOGIN_TASK_BUDGET_INSUFFICIENT`, `max` or values above 21 as `LOGIN_TASK_BUDGET_UNQUALIFIED`, malformed counters as `LOGIN_TASK_BUDGET_INVALID`, and a nonempty/exhausted scope as a typed failure.

Add a `cli_main()` ordering test that injects an insufficient preflight and uses bomb functions for repository validation, runtime validation, and `run_owner_login`; assert the only output is the stable budget error and none of the bomb functions run.

- [ ] **Step 2: Run tests and verify RED**

Run the exact new test nodes with `python3 -m pytest -q`. Expected failure: missing constants/function and owner command still contains `TasksMax=16`.

- [ ] **Step 3: Implement the minimal preflight**

Parse the already-validated unified cgroup-v2 membership, resolve only its literal `/sys/fs/cgroup` directory, read only pids-controller counters, and reject every unqualified shape. Change `owner_systemd_command()` to emit `TasksMax=21`. Invoke preflight immediately after `validate_scope_membership()`.

- [ ] **Step 4: Run tests and verify GREEN**

Run the new nodes and the complete `test_kimi_login.py` unit file.

---

### Task 2: Typed task-exhaustion handling and real cgroup fixtures

**Files:**
- Modify: `src/agenticos/providers/kimi_login.py`
- Create: `tests/providers/fixtures/kimi_task_budget_fixture.py`
- Modify: `tests/providers/test_kimi_login_linux.py`

**Interfaces:**
- Relay thread creation reports `TASK_BUDGET_EXHAUSTED` rather than emitting an unhandled traceback.
- Native fixture modes return bounded JSON containing only pids counters, process/thread counts, component names, typed results, and cleanup state.

- [ ] **Step 1: Write failing native tests**

Add tests that run the fixture through real systemd scopes and synthetic/local sockets only:

1. `TasksMax=16` reaches `pids.current=16`, increments `pids.events max`, and reports resolver task-start exhaustion with zero external connect.
2. `TasksMax=21` starts the resolver worker, completes a synthetic TLS relay exchange, peaks at or below 17 for the pinned topology and below 21 overall, and retains four tasks of headroom.
3. Thread explosion under 21 is denied at the cgroup ceiling with `pids.peak=21` and a max event.
4. Success and failure scopes are collected with no residual unit, cgroup, process, or listener.

- [ ] **Step 2: Run native tests and verify RED**

Expected failure: old owner budget 16, no preflight qualification, and raw `RuntimeError: can't start new thread` from relay/resolver thread creation.

- [ ] **Step 3: Implement minimal typed handling and fixture**

Catch only task-start `RuntimeError` at relay thread boundaries, emit stable content-free observations, and preserve all existing cleanup. Keep the shared resolver implementation unchanged so its timeout worker and special-address policy are not weakened.

- [ ] **Step 4: Run native tests and verify GREEN**

Run the new native test nodes, all ceremony tests, M4B DNS/address/TLS suites, and Demo 0.

---

### Task 3: Amendment, review, verification, and publication

**Files:**
- Create: `docs/phase-zero/first-autonomous-build-slice-f1-kimi-login-task-budget-amendment.md`
- Modify only if final measured evidence requires it: `docs/phase-zero/first-autonomous-build-slice-f1-kimi-login-ceremony-preparation.md`

**Interfaces:**
- Records root cause `CGROUP_TASK_LIMIT_EXHAUSTED`, old/effective task counters, measured topology, exact 17+4 calculation, test evidence, and owner-action state without OAuth or credential content.

- [ ] **Step 1: Write the content-free amendment**

Record the failed owner attempt only as pre-TLS task exhaustion; do not include authorization codes, URLs with state, tokens, credential bytes/hashes, or OAuth payloads.

- [ ] **Step 2: Adversarial self-review**

Review for unlimited budget, preflight race, unexpected Kimi children, DNS timeout weakening, cgroup escape, relay amplification, cleanup with extra threads, provider traffic before preflight, and accidental credential access. Resolve every Critical and Important finding with TDD.

- [ ] **Step 3: Fresh verification**

Run ceremony/native tests, focused provider/M4B/Demo 0 tests, full native WSL pytest, compileall, secret/host scans, `git diff --check`, and scope/cgroup/process/socket/credential structural census.

- [ ] **Step 4: Preserve exact candidate**

Commit the exact tested WSL worktree candidate, fast-forward WSL `main`, rerun final main-path qualification, push directly once or use the approved exact-SHA bundle fallback, verify live GitHub with `git ls-remote`, fast-forward Windows, and prove both clones clean at `0/0` with zero stashes/residue.

- [ ] **Step 5: Return the new owner command and hard stop**

Emit exactly one command containing `TasksMax=21`, report `F1_KIMI_LOGIN_CEREMONY_STATE=OWNER_ACTION_REQUIRED`, and never execute it.
