# Milestone 5 — Controlled Git Worktree Execution Plan

Status: Slice 0 Design & Specification Checkpoint
Governing principle: **Models reason; AgenticOS guarantees.**

---

## 1. Verified Starting Repository State

At session start, both local clones and the GitHub remote were independently verified against the standing repository preservation contract (`AGENTS.md` and `docs/engineering/repository-preservation.md`).

| Target | Expected SHA | Observed SHA | Working Tree |
|---|---|---|---|
| Windows HEAD (`C:\AgenticOS`) | `e468269965866407614c3d5e98e15167176c56de` | `e468269965866407614c3d5e98e15167176c56de` | Clean |
| WSL HEAD (`~/src/AgenticOS`) | `e468269965866407614c3d5e98e15167176c56de` | `e468269965866407614c3d5e98e15167176c56de` | Clean |
| `origin/main` (after `fetch --prune`) | `e468269965866407614c3d5e98e15167176c56de` | `e468269965866407614c3d5e98e15167176c56de` | N/A |
| GitHub `main` (`git ls-remote`) | `e468269965866407614c3d5e98e15167176c56de` | `e468269965866407614c3d5e98e15167176c56de` | N/A |

- **Unpushed commits:** `0`
- **Unexplained untracked files:** `0`
- **Stash entries:** `0`

---

## 2. Existing Code Paths Involved

The M5 controlled worktree execution substrate integrates directly into the existing M4A/M4B execution path without redesigning earned security primitives:

- `src/agenticos/sandbox/runtime_boundary.py`: `build_runtime_plan`, `AuthorizedMount`, `M4AProfile.BUILD`. The `/workspace` mount source will be bound to the controller-managed task worktree path.
- `src/agenticos/sandbox/m4a_runner.py`: `NamespaceLandlockRunner`. Enforces process, mount, and Landlock boundaries.
- `src/agenticos/sandbox/launcher.py`: `NativeLandlockRunner`, `prepare_launch_request`. Protocol v1/v2/v3 launch request generation and binary boundary execution.
- `src/agenticos/sandbox/containment.py`: `CgroupProcessRunner`, `cancel_contained`. Transient systemd scope process hierarchy control and populated-0 verification.
- `src/agenticos/sandbox/m4b_runner.py`: `HttpsBrokerRunner`. Task-scoped authenticated network grants (if Connected Build is explicitly authorized).
- `src/agenticos/sandbox/models.py`: Typed models (`ProcessIdentity`, `ProcessResult`, `EvidenceRecord`). Will be extended with worktree and preservation models.
- `src/agenticos/sandbox/evidence.py`: `EvidenceCollector`. Records cryptographic task worktree identity and lifecycle events.
- **[NEW] `src/agenticos/sandbox/worktree.py`**: Will implement task identity binding, worktree creation/validation, isolated Git view construction, preservation state machine, and teardown logic.

---

## 3. Git / Worktree Host Behavior Findings

Empirical investigation of Git 2.53.0 worktree mechanics on the host system revealed key structural behaviors:

1. **Linked Worktree Pointer (`.git` file)**:
   A linked worktree created via `git worktree add <path> <commit>` contains a single-line `.git` file:
   ```text
   gitdir: <path-to-main-repo>/.git/worktrees/<task-name>
   ```
2. **Worktree Directory Metadata**:
   Inside `<main-repo>/.git/worktrees/<task-name>/`:
   - `HEAD`: Points to `refs/heads/<task-branch>`
   - `gitdir`: Points back to `<worktree-path>/.git`
   - `commondir`: Contains relative path `../..` pointing to the main repository's `.git` directory
   - `index`: Task-specific staging index
   - `logs/`: Task-specific reflog
3. **Shared Object and Config Authority**:
   Git resolves `commondir` to access the main repository's `.git/` directory for `objects/`, `config`, `hooks/`, `refs/`, and `info/`.
   - Read/write access to `.git/objects/` is required by standard `git add` and `git commit` to write new blob and tree objects.
   - Read access to `.git/config` and `.git/hooks/` is used by Git during command execution.

---

## 4. Git Metadata Threat Model

If a hostile worker process receives raw filesystem access to the main repository's `.git` directory or direct authority over Git topology, the worker can execute authority-escalation attacks:

| Attack Vector | Hostile Worker Action | Impact | Mitigated In M5 Design |
|---|---|---|---|
| **Authoritative Ref Tampering** | Overwrites `refs/heads/main` or `.git/HEAD` directly | Destroys authoritative checkout state | Yes (main `.git` unmounted) |
| **Hook Injection** | Writes executable scripts into `.git/hooks/` | Host code execution on host/controller Git runs | Yes (hooks unmounted / disallowed) |
| **Config Mutation** | Modifies `.git/config` (`core.fsmonitor`, `core.editor`) | Command execution when controller runs Git | Yes (config unmounted / read-only synthetic) |
| **Cross-Task Worktree Tampering** | Modifies `.git/worktrees/<other-task>` | Mutates or corrupts concurrent worker tasks | Yes (worktrees unmounted) |
| **Object Database Corruption** | Deletes or overwrites objects in `.git/objects/` | Corrupts main repository Git graph | Yes (main repo unmounted; object cache read-only) |
| **Unauthorized Git Push** | Executes `git push` using ambient SSH/HTTP credentials | Exposes unreviewed code or secret leak to GitHub | Yes (credentials absent; push denied) |

---

## 5. Architectural Evaluation

We evaluated five candidate architectures against AgenticOS security principles:

| Architecture | Security Boundary | Compatibility | Object Efficiency | Implementation Complexity | Recommendation |
|---|---|---|---|---|---|
| **A. Standard Linked Worktree** | Low (exposes main `.git` via `commondir`) | High | High | Low | **REJECTED** (violates isolation) |
| **B. Synthetic Git View** | High (main `.git` hidden; synthetic index) | Medium | Medium | High | Complex fallback |
| **C. Shared Local Clone** | Medium (`.git/objects/info/alternates` link) | High | Medium | Medium | **REJECTED** (requires mounting host path) |
| **D. Controller-Only Git** | Maximum (worker gets no `.git` directory) | High for models | High | Low | **RECOMMENDED BASE** |
| **E. Controlled Dual-Boundary Hybrid** | Maximum (Controller owns ref/preservation; worker gets isolated worktree) | Maximum | High | Medium | **RECOMMENDED ARCHITECTURE** |

### Recommended Architecture: E (Controlled Dual-Boundary Hybrid)

- **Controller Ownership**: AgenticOS controller creates worktrees, names branches, runs baseline checks, captures diffs, manages lifecycle, and executes commits/preservation.
- **Worker Workspace**: Hostile worker receives `/workspace` backed *only* by the task-specific worktree directory. Main repository `.git`, root checkout, other worktrees, and ambient Git credentials are completely unmounted and invisible in the worker sandbox.
- **Git Metadata View**: Inside the worker sandbox, `/workspace` operates cleanly for file inspection, creation, modification, building, and testing. If worker toolchain requires `git` status/diff inspectability, a task-scoped read-only synthetic `.git` view is provided, with object writes routed to a task-isolated directory.

---

## 6. Exact Authority Split

```text
+-----------------------------------------------------------------------------------+
|                            AGENTICOS CONTROLLER (Trusted)                         |
|  - Verifies baseline SHA (e.g. e468269...)                                        |
|  - Validates branch name (aos/<task_id>/g<gen>)                                   |
|  - Creates host worktree at <state>/worktrees/<task_identity>/                    |
|  - Constructs bwrap runtime plan mounting task worktree to /workspace             |
|  - Evaluates test results, computes diff evidence, manages preservation state     |
|  - Performs final git commit / publish operations when authorized                |
+-----------------------------------------------------------------------------------+
                                          |
                                          | (Mounts ONLY task worktree to /workspace)
                                          v
+-----------------------------------------------------------------------------------+
|                             HOSTILE WORKER (Sandbox)                              |
|  - Can inspect, edit, create, and delete files inside /workspace                  |
|  - Can run builds and test suites in /workspace                                   |
|  - Can use M4B-3 Connected Build HTTPS if explicitly granted                      |
|  - CANNOT see main .git, main checkout, or other tasks' worktrees                 |
|  - CANNOT run git push, git branch, git checkout outside worktree                 |
|  - CANNOT access ambient SSH/GitHub credentials                                  |
+-----------------------------------------------------------------------------------+
```

---

## 7. Task Identity Model

Every task worktree is bound to a deterministic, cryptographically auditable task identity tuple:

```python
@dataclass(frozen=True)
class TaskWorktreeIdentity:
    task_id: str             # Bounded alphanumeric string [A-Za-z0-9_-]{1,64}
    generation: int          # Positive integer (1, 2, ...)
    nonce: str               # 32-char lowercase hex nonce
    repository_id: str       # Canonical repository identity string
    baseline_commit_sha: str # Exact 40-char SHA-1 hex of starting baseline
    policy_digest: str       # SHA-256 digest of sandbox policy
```

- **Branch Name**: `aos/<task_id>/g<generation>`
- **Worktree Directory**: `<agenticos_state>/worktrees/<task_id>_g<generation>_<nonce_prefix>/`
- **Identity Hash**: SHA-256 digest of `json.dumps(identity_tuple)`.

---

## 8. Branch Naming & Validation Policy

- **Allowed Format**: `aos/<task_id>/g<generation>`
- **Validation Rules**:
  1. Must match strict regex: `^aos/[A-Za-z0-9_-]{1,64}/g[0-9]{1,16}\Z`.
  2. Reject path traversal elements (`..`, `./`, `//`).
  3. Reject ref wildcards (`*`, `?`, `[`, `~`, `^`, `:`, `@`, `@{`).
  4. Reject leading/trailing slashes or dots.
- **Collision Policy**:
  - Check if ref `refs/heads/aos/<task_id>/g<generation>` exists.
  - If ref exists: **Fail closed** unless proven byte-identical task identity.
  - Never force-overwrite (`git branch -f` is forbidden).

---

## 9. Worktree Path Policy

- **Root Directory**: `<agenticos_state>/worktrees/` (Controller owned, mode `0700`).
- **Path Resolution**:
  - Constructed strictly as `Path(root) / f"{task_id}_g{generation}_{nonce[:8]}"`.
  - Resolved using `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`.
  - Symlink substitution attacks on any path component fail closed.
- **Mount Integration**:
  - `AuthorizedMount(task_worktree_source, "/workspace", MountRole.WORKSPACE, "--bind-fd", "w")`.
  - Main repository checkout is never mounted in the sandbox.

---

## 10. Git Command Authority Matrix

| Git Command | Classification | Enforced Boundary / Reason |
|---|---|---|
| `git status` | `WORKER_ALLOWED` (read-only) | Reads task index/worktree state |
| `git diff` / `git diff --cached` | `WORKER_ALLOWED` (read-only) | Reads task diff state |
| `git log` / `git show` / `git rev-parse` | `WORKER_ALLOWED` (read-only) | Inspects commit history |
| `git add` / `git restore` | `WORKER_ALLOWED` | Operates within `/workspace` |
| `git checkout` / `git switch` | `WORKER_RESTRICTED` | Cannot switch off assigned task branch |
| `git reset` / `git clean` | `WORKER_RESTRICTED` | Scoped to `/workspace`; cannot touch host |
| `git commit` | `CONTROLLER_ONLY` | Controller owns commit authorship & ref state |
| `git branch` / `git worktree` | `CONTROLLER_ONLY` | Worker cannot alter ref topology |
| `git config` / `git remote` | `CONTROLLER_ONLY` | Worker cannot alter Git settings or remotes |
| `git fetch` / `git pull` | `CONTROLLER_ONLY` (or M4B-3 HTTPS) | Bounded to approved acquisition |
| `git push` | `NOT_SUPPORTED` | Worker push authority is strictly out of scope |
| `git gc` / `git prune` / `git reflog` | `CONTROLLER_ONLY` | Maintenance functions owned by controller |

---

## 11. Preservation State Machine

The task worktree lifecycle follows a strict state transition machine:

```text
REQUESTED
   ↓
BASELINE_VERIFIED
   ↓
TASK_REF_RESERVED
   ↓
WORKTREE_CREATED
   ↓
WORKTREE_IDENTITY_VERIFIED
   ↓
SANDBOX_LAUNCH_READY
   ↓
WORKER_RUNNING
   ↓
WORKER_EXITED
   ↓
RESULT_CAPTURED
   ↓
TESTED
   ↓
PRESERVED
```

### Terminal & Failure States

- `SETUP_FAILED`: Baseline check or worktree creation failed.
- `WORKER_FAILED`: Worker process exited non-zero or timed out.
- `TEST_FAILED`: Worker produced changes but verification tests failed.
- `CANCELLED_PRESERVED`: Task cancelled; uncommitted/dirty worktree preserved.
- `ABANDONED_PRESERVED`: Controller restarted; orphaned task worktree preserved.
- `CLEANUP_FAILED`: Worktree removal failed; flagged for admin review.

**Governing Invariant**: *Worker failure, crash, or cancellation MUST NOT cause silent deletion of uncommitted work.*

---

## 12. Preservation & Crash-Recovery Policy

1. **State Persistence**: Every state transition emits a signed `EvidenceRecord` written to the task log and persistent state database.
2. **Crash Recovery**: Upon controller initialization, the controller scans `<agenticos_state>/worktrees/`. Any directory missing an active process is reconciled against the evidence ledger:
   - If the task reached `PRESERVED` and was clean, it is safely cleaned.
   - If the task contains uncommitted changes or un-captured diffs, the task branch `aos/<task_id>/g<generation>` and worktree are preserved as `ABANDONED_PRESERVED`.
3. **No Automatic Deletion**: Unexplained or dirty task worktrees are never automatically deleted (`git clean -fd` and `rm -rf` over dirty worktrees are prohibited).

---

## 13. Cleanup Policy

- **Disposable Residue**: Sandbox `/tmp` and `/home/tool` are temporary and cleaned post-execution.
- **Worktree Teardown Requirements**:
  - Worktree identity verified before removal.
  - Branch ref verified owned by task identity before removal.
  - Diff captured and recorded in evidence ledger before removal.
  - Deletion uses `git worktree remove` (without `--force` unless diff is fully preserved in evidence).

---

## 14. Typed Task Result / Evidence Model

```python
@dataclass(frozen=True)
class TaskWorktreeResult:
    task_id: str
    generation: int
    baseline_commit_sha: str
    task_branch: str
    worktree_path: str
    worker_exit_code: Optional[int]
    worker_timed_out: bool
    git_status_summary: str
    changed_files: tuple[str, ...]
    diff_sha256: str
    diff_evidence_path: str
    test_command: Optional[str]
    test_passed: Optional[bool]
    preservation_state: str
    evidence_run_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
```

---

## 15. Self-Hosting Requirement Target

The M5 design targets the first concrete self-hosting workflow:

```text
Issue submitted for AgenticOS
   ↓
AgenticOS Controller verifies HEAD SHA e468269...
   ↓
Controller reserves branch aos/self-host-1/g1 and creates worktree
   ↓
Coding model launched in M4A/M4B sandbox with /workspace = worktree
   ↓
Model modifies AgenticOS code & runs pytest inside sandbox
   ↓
Controller captures diff, verifies tests, records evidence
   ↓
Work preserved in branch aos/self-host-1/g1 for human review
```

---

## 16. Proposed Implementation Files

- `src/agenticos/sandbox/worktree.py`: Core worktree lifecycle, task identity, branch validation, and preservation logic.
- `src/agenticos/sandbox/models.py`: Worktree data classes, state enums, and evidence models.
- `src/agenticos/sandbox/runtime_boundary.py`: Updated workspace mount validation.
- `docs/phase-zero/controlled-git-worktree.md`: This milestone specification.
- `tests/test_worktree.py`: Verification test suite.

---

## 17. Proposed Test Corpus

The future test suite (`tests/test_worktree.py`) will cover:

1. `test_baseline_sha_verification_success`
2. `test_baseline_sha_mismatch_fails_closed`
3. `test_dirty_authoritative_checkout_fails_closed`
4. `test_branch_name_validation_valid`
5. `test_branch_name_validation_invalid_syntax` (spaces, control chars, path traversal)
6. `test_branch_collision_fails_closed`
7. `test_worktree_path_creation_under_root`
8. `test_worktree_path_symlink_attack_rejected`
9. `test_concurrent_worktree_creations_isolated`
10. `test_worker_edit_file_in_worktree`
11. `test_worker_create_file_in_worktree`
12. `test_worker_delete_file_in_worktree`
13. `test_worker_cannot_access_main_repo_git`
14. `test_worker_cannot_access_sibling_worktree`
15. `test_worker_git_push_denied`
16. `test_worker_git_config_mutation_denied`
17. `test_worker_git_hook_injection_denied`
18. `test_worker_ssh_key_access_denied`
19. `test_worker_cancellation_preserves_dirty_worktree`
20. `test_worker_crash_preserves_dirty_worktree`
21. `test_failed_test_run_preserves_work`
22. `test_controller_restart_discovers_orphaned_worktree`
23. `test_safe_clean_disposable_worktree`
24. `test_refusal_to_delete_unexplained_worktree`
25. `test_m4a_m4b_regression_suite`

---

## 18. Security Stop Conditions

The future implementation MUST hard-stop if any of the following conditions occur:

1. Worker can modify authoritative checkout.
2. Worker can modify another task's worktree.
3. Worker can alter shared main/ref state outside its authority.
4. Worker can rewrite or delete unrelated refs.
5. Worker can alter Git remotes, config, or hooks to widen authority.
6. Worker receives GitHub credentials (tokens, SSH keys, credential helpers).
7. Worker can push without a separate controller capability.
8. Cleanup deletes dirty or unexplained task work.
9. Task identity cannot be bound to exact worktree identity.
10. Worktree path collision can overwrite existing work.
11. Controller crash renders valid task work indistinguishable from garbage.
12. Worker requires broader filesystem/network authority than M4A/M4B-3 provide.
13. Earlier security milestone regressions appear.

---

## 19. Recommended Implementation Slices

- **Slice 0**: Design & Specification Checkpoint (`docs/phase-zero/controlled-git-worktree.md`) — **THIS TASK**.
- **Slice 1**: Task Identity & Ref Validation (`src/agenticos/sandbox/worktree.py` core models & ref validation).
- **Slice 2**: Worktree Lifecycle Manager (Creation, path binding, isolated Git metadata view setup, teardown).
- **Slice 3**: Sandbox Integration & Mount Authorization (Wiring `worktree.py` with `runtime_boundary.py` & `M4AProfile.BUILD`).
- **Slice 4**: Evidence Capture, Preservation State Machine, & Crash Recovery.
- **Slice 5**: End-to-End Self-Hosting Dry Run & Multi-Task Concurrency Qualification.

---

## 20. Earned & Unearned Claims

### Claims M5 Could Earn
- Task-bound, isolated Git worktree creation from exact verified baseline SHA.
- Hostile worker execution confined to `/workspace` backed by task worktree.
- Complete isolation of authoritative repository, main branch, hooks, config, and sibling task worktrees.
- Typed task diff and status evidence capture.
- Guaranteed preservation of dirty worktrees on worker cancellation, failure, or controller restart.

### Claims Explicitly NOT Earned
- Automated worker `git push` or GitHub publication authority (remains controller-only).
- Multi-repository / multi-remote worktree orchestration (single local repository only).
- Non-Git VCS support.
- Live internet network access during git operations (remains subject to M4B-3 exact-host grants).
