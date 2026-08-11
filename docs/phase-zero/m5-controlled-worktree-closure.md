# Milestone 5 — Controlled Git Worktree Execution Closure and Handoff Contract

Status: **M5 Complete & Authoritatively Closed**
Authoritative Repository Checkpoint: `3e3c34b0a54e20dfddd56fce278bfcac0aaf45ca`
Governing Principle: **Models reason; AgenticOS guarantees.**

---

## 1. Verified Repository State at M5 Closure

The repository state across both local clones and GitHub remote was verified prior to handoff:

| Target | Verified Commit SHA | Working Tree State |
|---|---|---|
| Windows HEAD (`C:\AgenticOS`) | `3e3c34b0a54e20dfddd56fce278bfcac0aaf45ca` | Clean |
| WSL HEAD (`~/src/AgenticOS`) | `3e3c34b0a54e20dfddd56fce278bfcac0aaf45ca` | Clean |
| `origin/main` (after `fetch --prune`) | `3e3c34b0a54e20dfddd56fce278bfcac0aaf45ca` | N/A |
| GitHub `main` (`git ls-remote`) | `3e3c34b0a54e20dfddd56fce278bfcac0aaf45ca` | N/A |

- **Unpushed commits:** `0`
- **Unexplained untracked files:** `0`
- **Stash entries:** `0`

---

## 2. Earned M5 Execution Pipeline Architecture

M5 implements a trusted, controller-owned Git worktree substrate operating outside the main repository checkout.

```text
    trusted task request
        ↓
    exact repository identity (SHA-1 / SHA-256 detection)
        ↓
    exact immutable baseline commit (Plumbing validation)
        ↓
    WorktreeReservation (nonce, policy_digest, state_root)
        ↓
    controller-owned Git ref/worktree creation (git worktree add -b refs/agenticos/task-id/g1)
        ↓
    durable controller ownership/lifecycle state (lifecycle.json & atomic state root)
        ↓
    filesystem/Git identity verification (fstat st_dev/st_ino kernel identity check)
        ↓
    M4A Landlock sandbox launch (NamespaceLandlockRunner)
        ↓
    task worktree mounted RW at /workspace
        ↓
    /workspace/.git masked (read-only empty file or mount mask)
        ↓
    hostile worker edits ordinary source files
        ↓
    optional already-qualified Connected Build (M4B-3 HTTPS proxy & TLS certs)
        ↓
    worker exits / fails / cancels
        ↓
    trusted controller Git & filesystem inspection (openat2 / lstat / porcelain -z / git diff)
        ↓
    bounded TaskWorktreeResult (diff SHA-256, byte count, 64 KiB evidence limits, renamed_paths)
        ↓
    useful work preserved (DIRTY_PRESERVED / COMMITTED_WORK_PRESERVED / CLEAN_BASELINE_DISPOSABLE)
```

Every stage in this pipeline is backed by current implementation (`src/agenticos/sandbox/worktree.py`, `src/agenticos/sandbox/runtime_boundary.py`, `src/agenticos/sandbox/m4a_runner.py`, `src/agenticos/sandbox/containment.py`) and verified by tests.

---

## 3. Normative Security Authority Split

### Controller Authority (Trusted Domain)
The trusted AgenticOS controller exclusively owns:
- Repository identity and baseline commit SHA strict validation.
- Task identity, task generation, and `refs/agenticos/*` ref creation/deletion.
- Worktree reservation, lifecycle state machine (`lifecycle.json`, `result.json`), and durable state root storage.
- Real Git plumbing operations (`git worktree add`, `git rev-parse`, `git status --porcelain=v1 -z`, `git diff HEAD`).
- Filesystem descriptor verification (`openat2`, `fstat` kernel device/inode checks).
- Cryptographic evidence collection, diff SHA-256 computation, and evidence truncation/bounds enforcement.
- Worktree lifecycle classification (`CLEAN_BASELINE_DISPOSABLE`, `DIRTY_PRESERVED`, `COMMITTED_WORK_PRESERVED`).
- Cleanup eligibility and future commit/branch publication decisions.

### Hostile Worker Authority (Sandboxed Execution Domain)
The hostile worker process (and future model adapters executing inside it) owns ONLY:
- Reading files within authorized `/workspace` and runtime paths permitted by M4A Landlock policy.
- Modifying, creating, deleting, and renaming ordinary source files inside `/workspace`.
- Executing build, test, and formatting processes permitted by the sandbox profile.
- Utilizing allocated temporary files inside task-scoped `/tmp`.
- Performing network requests strictly through controller-authorized M4B Connected Build proxies.

### Hostile Worker Prohibitions
The worker process MUST NOT own or access:
- Authoritative root repository checkout or main `.git` directory.
- Shared Git refs, objects, reflogs, or git config files.
- Git credentials, SSH keys, or ambient network identity.
- Git ref mutation, branch creation, or commit creation.
- Git push capabilities or GitHub remote access.
- Controller lifecycle metadata, state root directory, or other task worktrees.
- Sandbox mount configuration, Landlock rules, or systemd scope cgroup settings.

---

## 4. Gitless Worker Contract

The first model adapter MUST NOT depend on worker Git access.

Inside `/workspace`:
- Ordinary source files are fully accessible for reading, writing, creation, deletion, and directory traversal.
- The `.git` path is masked (e.g. read-only empty file / Landlock restricted) to prevent repository authority smuggling.

The model adapter MUST NOT invoke or require:
- `git status`
- `git diff`
- `git add`
- `git commit`
- `git branch`
- `git checkout`
- `git reset`
- `git clean`
- `git fetch`
- `git push`

If a model requires repository history or diff context, the trusted controller MUST provide that information explicitly via typed input APIs. AgenticOS will not expose raw `.git` access merely for provider compatibility.

---

## 5. First Model Adapter Input Contract

The first model adapter must consume a provider-neutral typed request constructed by the controller:

```python
@dataclass(frozen=True)
class ModelTaskRequest:
    """Provider-neutral task definition supplied by the trusted controller to a model adapter."""

    # Correlation & Identity
    repository_id: str
    task_id: str
    generation: int
    attempt_id: str

    # User Intent & Constraints
    user_prompt: str
    acceptance_criteria: tuple[str, ...]
    file_constraints: tuple[str, ...]

    # Workspace Context
    workspace_path: str = "/workspace"  # Always relative to worker sandbox root
    cwd: str = "/workspace"
    runtime_profile: str = "L2_BUILD"

    # Limits & Execution Controls
    timeout_seconds: float = 300.0
    allowed_command_patterns: tuple[str, ...] = ()
    network_mode: str = "DENIED"  # "DENIED" or "CONNECTED_BUILD"
    connected_build_grants: tuple[str, ...] = ()

    # Provided Repository Context
    selected_context_files: tuple[tuple[str, str], ...] = ()  # (relative_path, content_snippet)
    repository_summary: str = ""
    previous_attempt_summary: str = ""
```

**Security Invariants for Inputs:**
- The request contains NO host filesystem paths (e.g. `/home/brand/...` or `C:\AgenticOS`).
- The request contains NO `.git` directory paths, Git credentials, or state root locations.
- The model is informed that its workspace is `/workspace`.

---

## 6. First Model Adapter Output Contract

The handoff separates **Model Claims** from **AgenticOS Guaranteed Evidence**.

```python
@dataclass(frozen=True)
class ModelTaskResponse:
    """Raw response returned by a model adapter containing unverified model claims."""

    model_summary: str
    claimed_files_modified: tuple[str, ...]
    claimed_tests_run: tuple[str, ...]
    claimed_status: str  # "COMPLETED", "BLOCKED", "NEEDS_CLARIFICATION"
    requested_followup: str = ""


@dataclass(frozen=True)
class GuaranteedExecutionResult:
    """Authoritative execution result compiled by AgenticOS after worker completion."""

    # Model Claims (Unverified Prose)
    model_response: Optional[ModelTaskResponse]

    # Cryptographic & Trusted Worktree Evidence (Guaranteed by Controller)
    worktree_result: TaskWorktreeResult  # Baseline SHA, current HEAD, modified/added/deleted/renamed paths, diff SHA-256
    worker_exit_code: Optional[int]
    worker_signal: Optional[int]
    worker_timed_out: bool
    cgroup_evidence: dict[str, Any]
    connected_build_evidence: dict[str, Any]
    preservation_classification: str  # CLEAN_BASELINE_DISPOSABLE, DIRTY_PRESERVED, COMMITTED_WORK_PRESERVED
```

Model prose claims are recorded for user inspection but NEVER used by the controller to make repository or security decisions.

---

## 7. Model Execution Envelope & Provider Client Architecture

The high-level execution envelope for provider clients is defined as:

```text
    controller builds trusted ModelTaskRequest
        ↓
    adapter converts ModelTaskRequest to provider invocation
        ↓
    provider client executes inside M4A hostile worker containment (or approved client sidecar)
        ↓
    model sees /workspace and performs source modifications
        ↓
    provider client returns raw response
        ↓
    AgenticOS inspects worktree using trusted plumbing and captures GuaranteedExecutionResult
```

### Next Adapter Milestone Architectural Question
> **Where does the official provider client run, and what authority does it require?**

For subscription-first model execution (e.g. Codex / Claude / Kimi API clients):
1. **Option A (Worker-Local Client)**: Provider API client runs inside the M4A sandbox, making outbound TLS calls via M4B Connected Build proxy.
2. **Option B (Controller-Side Sidecar)**: Provider API client runs in a controller-side sidecar process, streaming tool calls into the sandboxed worker.

The choice between Option A and Option B will be evaluated and proven in the first Model Adapter milestone.

---

## 8. Sandboxed Adapter Control Flow (No Bypass of M4A/M4B)

The future model adapter is a translation layer, NOT a second controller.

The adapter MUST NOT:
- Launch host processes outside M4A Landlock containment.
- Directly select host filesystem paths or bypass `/workspace` bounds.
- Access main `.git` or controller state root directories.
- Open raw network sockets outside M4B Connected Build proxy policy.
- Inherit ambient host environment variables or credentials.
- Mutate `refs/agenticos/*` refs or execute `git commit`/`git push`.
- Mark a task worktree disposable or execute cleanup.

---

## 9. Connected Build Composition with M5

When a task requires network access for package downloads or API inspection:
1. Controller policy evaluates task requirements and generates exact Connected Build grants (`_two_grant_specs()`, HTTPS proxy port, CA certificate).
2. `_validate_extra_worker_env()` validates environment extensions, permitting `GIT_SSL_CAINFO`, `SSL_CERT_FILE`, `HTTPS_PROXY` while rejecting repository authority overrides (`GIT_DIR`, `GIT_WORK_TREE`).
3. M4B HTTPS broker filters traffic against exact hostname policies, verifying TLS ClientHello SNI and capping connection/byte budgets.
4. Model process executes network operations safely through the broker proxy.

Existing M4B limitations remain strictly in force: HTTP/1.1 qualified scope, exact-host grants, zero ambient credential delegation, and fixture-qualified test boundaries.

---

## 10. Failure and Cancellation Semantics

If the worker process or model adapter:
- Exits with code 0;
- Exits with non-zero exit code;
- Crashes (SIGSEGV, SIGKILL);
- Times out;
- Is cancelled by controller or user;
- Emits oversized diff output (> 64 KiB untracked / > 1 MB diff);
- Emits malformed JSON or invalid prose;

AgenticOS enforces fail-closed preservation:
1. Drains and terminates systemd cgroup process hierarchy (`cancel_contained`).
2. Performs trusted controller inspection (`openat2`, `lstat`, `git status -z`, `git diff HEAD`).
3. If worktree contains modified, added, deleted, or renamed files, classifies state as `DIRTY_PRESERVED`.
4. If worktree contains committed work beyond baseline, classifies state as `COMMITTED_WORK_PRESERVED`.
5. Only classifies state as `CLEAN_BASELINE_DISPOSABLE` if worktree matches baseline commit SHA exactly with zero uncommitted changes.
6. Worker failures or errors NEVER trigger automatic repository cleanup or data destruction.

---

## 11. Normative List of Earned M5 Claims

The following 17 claims are authoritatively earned by current M5 implementation and verified by automated tests:

1. **Exact Repository Identity**: Deterministic detection of repository SHA-1 and SHA-256 object formats.
2. **Immutable Baseline Selection**: Plumbing verification (`git rev-parse --verify`) of baseline commit SHAs.
3. **Task-Specific Refs**: Isolation of worker worktrees under controller refs (`refs/agenticos/<task_id>/g<gen>`).
4. **Durable Controller Ownership**: Atomic state root tracking (`lifecycle.json`, `result.json`, `reservation.json`).
5. **Linked Worktree Lifecycle**: Controller creation, transaction tracking, and kernel-identity guarded verification.
6. **Committed & Uncommitted Preservation**: Strict classification (`CLEAN_BASELINE_DISPOSABLE`, `DIRTY_PRESERVED`, `COMMITTED_WORK_PRESERVED`).
7. **Identity-Guarded Cleanup**: Verification of `st_dev` and `st_ino` before any worktree deletion or ref updates.
8. **Gitless Hostile Worker**: Complete execution of source edits, builds, and tests without worker Git access.
9. **`/workspace` Task Isolation**: Mounting task worktree exclusively at `/workspace` with host paths concealed.
10. **`.git` Masking**: Masking `/workspace/.git` to block repository authority smuggling inside the sandbox.
11. **Authoritative Checkout Isolation**: Main repository working tree and `.git` directory strictly unmounted and inaccessible.
12. **Cross-Task Isolation**: Complete filesystem and Landlock separation between concurrent worker tasks.
13. **M4A Composition**: Seamless integration with Landlock profiles (`L1_INSPECT`, `L2_BUILD`), cgroup scopes, and unshare namespaces.
14. **M4B Composition**: Secure environment extension validation (`GIT_SSL_CAINFO` allowed, `GIT_DIR` blocked) over HTTPS proxy broker.
15. **Bounded Result Capture**: Memory-bounded streaming of `git diff HEAD` (64 KiB chunking, byte & SHA-256 calculation).
16. **Porcelain `-z` Rename Evidence**: Safe parsing of NUL-delimited rename records (`renamed_paths`) without status desynchronization.
17. **Hostile Untracked Evidence Bounds**: Safe `lstat` inspection of untracked files capping text at 64 KiB and summarizing binary/large files and symlinks.

---

## 12. Explicit List of Non-Earned M5 Claims

M5 DOES NOT claim or support the following capabilities (which are reserved for future milestones):

1. **Worker Git Operations**: Hostile workers cannot run `git commit`, `git add`, or `git status`.
2. **Worker Commit Creation**: Worker processes cannot create Git commit objects.
3. **Automated Git Push**: No automated pushing of task branches to GitHub.
4. **Automatic Branch Merging**: No automatic merging of task refs into `main`.
5. **Pull Request Creation**: No automated PR creation on GitHub.
6. **Provider API Integration**: No direct integration with OpenAI, Anthropic, or Moonshot APIs yet built.
7. **Codex / Claude Adapter**: Model adapters are not yet implemented.
8. **Multi-Model Routing**: No routing or switching between multiple AI providers.
9. **Autonomous Task Decomposition**: No automatic splitting of user prompts into sub-tasks.
10. **Reviewer / Evaluator Loops**: No secondary agent evaluation loop yet wired.
11. **Automatic Repair Loops**: No multi-turn self-repair loop built into controller.
12. **Unrestricted Internet Access**: No raw outbound socket access allowed to workers.
13. **Authenticated Registry Access**: No credentials for private npm/pip/cargo registries.
14. **Windows Hostile Sandbox Execution**: Landlock/bwrap containment remains Linux-only.
15. **Full Provider Credential Management**: Credential storage and rotation not yet implemented.
16. **Self-Hosting Execution**: AgenticOS does not yet modify its own codebase autonomously.
17. **Multi-Agent Swarm Orchestration**: Concurrent tasks execute independently, not in swarms.
18. **Arbitrary Git Repository Operations**: No support for rebase, cherry-pick, or submodule mutation inside worker.

---

## 13. First Model Adapter Success Criteria

The success condition for the next milestone (Milestone 6: First Model Adapter) is strictly bounded:

> **Given a synthetic coding task against a test repository:**
> 1. AgenticOS creates a controlled worktree at an exact baseline commit.
> 2. AgenticOS launches the first supported model provider using its official client inside contained sandbox bounds.
> 3. The model modifies `/workspace` source files without Git access.
> 4. AgenticOS captures trusted execution evidence (`TaskWorktreeResult`, process exit code, diff SHA-256).
> 5. AgenticOS executes deterministic verification (unit tests / linter).
> 6. AgenticOS preserves the resulting worktree for human review.

The first adapter milestone does NOT need to push, merge, open PRs, route multiple models, or self-host.

---

## 14. First Self-Hosting Gate

Before AgenticOS is permitted to modify its own codebase (`AgenticOS` repository), the following 10-point gate must be passed:

1. **Proven Adapter on Synthetic Repos**: Model adapter successfully completes 50+ synthetic coding tasks with 0 escape attempts.
2. **Proven Provider Identity & Evidence**: Cryptographic verification of model invocation logs and prompt hashes.
3. **Session & Credential Isolation**: Proven isolation of provider API keys from sandboxed worker processes.
4. **Unchanged Sandbox Boundary**: M4A Landlock and namespace containment verified with 0 regressions.
5. **Zero Authority Bypass**: Proved model cannot access host filesystem or ungranted network paths.
6. **Green Result Capture**: 100% reliable capture of diffs, renames, and binary/large file bounds.
7. **Green Cancellation & Teardown**: 100% reliable process hierarchy termination and dirty work preservation.
8. **Green Deterministic Verification**: Automated test suite passes 100% on modified synthetic repositories.
9. **Independent Adversarial Review**: Security review confirms no repository hijacking or code injection vectors.
10. **Repository Preservation Contract**: Full compliance with `AGENTS.md` and dual-clone SHA identity.

---

## 15. Recommended Next Milestone

**Milestone 6 — First Provider/Model Adapter (Codex / Claude Integration)**

Focus: Implement a minimal, typed `ModelTaskRequest` -> sandboxed provider client execution -> `ModelTaskResponse` translation layer to run the first official coding model client against synthetic repositories under M5 controlled worktree guarantees.
