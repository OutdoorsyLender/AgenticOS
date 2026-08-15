# First Autonomous Build Slice F1 Kimi Passive Qualification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Passively qualify the exact official Kimi Code CLI 0.36.1 Linux x64 artifact as a credential-free, checkout-free, tool-free future AgenticOS Planner, or fail closed with a precise structural blocker.

**Architecture:** A pinned policy bundle and controller-owned Python harness launch the absolute Kimi executable in a minimal Bubblewrap domain with an allowlisted environment, empty workspace, synthetic data root, no external network, and bounded stdio. A strict ACP v1 state machine maps only the approved Planner surface into the existing `AOSAGENT/1` ABI; authentication and real provider execution stay disabled. Black-box tests use synthetic OAuth and loopback model fixtures only.

**Tech Stack:** Python 3.12+, pytest, Linux x86-64/WSL2, Bubblewrap 0.11.1, cgroup v2/systemd user scopes, ACP v1 NDJSON, official Kimi Code CLI 0.36.1 Linux x64 ELF.

**Spec:** `docs/phase-zero/first-autonomous-build-slice-f1-kimi-selection.md`

## Global Constraints

- Tag `@moonshot-ai/kimi-code@0.36.1`; archive SHA-256 `c5af089d5ad34c27f2f26d5f93588ba3f656bf771911e5d43c85be95d3e1cbd4`; ELF SHA-256 `78c07b255e0bdc8dfe90d0cbd3204a3d862957394a08ca99c6e31144732451c7`.
- Require `KIMI_CODE_NO_AUTO_UPDATE=1`, `KIMI_DISABLE_TELEMETRY=1`, and `KIMI_DISABLE_CRON=1`.
- No login, device authorization, real credential access, API key, subscription use, real prompt/inference/Kimi traffic, checkout mount, Builder, F2, G2, or G1.
- Runtime remains `REAL_PROVIDER_DISABLED` and `NOT_AUTHENTICATED`.
- Native WSL is the only writer. Publish one reviewed/tested slice commit to `main`.

### Task 1: Freeze Artifact, Profile, and Environment Policy

**Files:** Create `qualification/kimi-code/0.36.1/{artifact.json,config.toml,agents/agent.md}`, `src/agenticos/providers/{__init__.py,kimi_policy.py}`, and `tests/providers/{__init__.py,test_kimi_policy.py}`.

**Interfaces:** Produce `KimiPinnedArtifact`, `build_kimi_environment()`, and `verify_pinned_runtime()`.

- [ ] Write failing tests for wrong version/hash/mode/owner, profile drift, update suppression, inherited variables, and API-key fallback names; run RED.
- [ ] Implement exact metadata/hash/mode checks and a literal environment allowlist. Because pinned ACP does not forward `--agent-file`, require the official discovered `agent` override with `override: true`, `tools: []`, `subagents: []`, and no template expansion.
- [ ] Run policy tests GREEN and scan qualification files; only the explicitly empty managed-provider `api_key = ""` may appear.

### Task 2: Implement Strict ACP v1 and Disabled Adapter

**Files:** Create `src/agenticos/providers/kimi_acp.py` and `tests/providers/test_kimi_acp.py`.

**Interfaces:** Consume existing `AgentTaskRequest`, `AgentEvent`, `AgentResult`, `AgentStreamValidator`, and `PlannerProposal`; produce `KimiAcpSession`, `KimiPassiveAdapter`, and `RealProviderDisabledError`.

- [ ] Write failing tests for malformed JSON/UTF-8, duplicate keys/IDs/terminals, wrong IDs/sessions, bounds, ordering, unknown/forbidden callbacks, cancellation races, crash/timeout, and real execution; run RED.
- [ ] Implement bounded NDJSON and a closed state machine accepting only initialize, exact login auth shape, one session/new, one session/prompt, and session/cancel.
- [ ] Require one canonical `AOSPLAN/1` proposal and existing controller authority over IDs, limits, providers, paths, commands, states, acceptance, and completion.
- [ ] Emit only controller-owned STARTED, PROPOSAL, and one terminal event; validate with `AgentStreamValidator`; run GREEN.

### Task 3: Build the Minimal Network-Denied Runtime

**Files:** Create `src/agenticos/providers/kimi_runtime.py` and `tests/providers/{test_kimi_runtime.py,test_kimi_runtime_linux.py}`.

**Interfaces:** Produce `KimiRuntimeSpec`, `KimiRuntimeObservation`, and `run_passive_kimi()`.

- [ ] Write failing tests for paths, forbidden mounts, inherited environment/FDs, network, unknown children, and writable immutable runtime; run RED.
- [ ] Implement Bubblewrap with tmpfs root, selective libraries, exact ELF, immutable config/profile, private state, empty `/workspace`, new network/PID/IPC/UTS namespaces, no ambient home or `/mnt/c`, and stdio-only FDs.
- [ ] Add bounded process, environment-name, FD, mount, file-write, and socket observations; unknown state fails closed.
- [ ] Run unit/native tests against `/home/brand/.local/share/agenticos/provider-qualification/kimi-code/0.36.1/runtime/bin/kimi` GREEN.

### Task 4: Black-Box ACP and Effective Profile Qualification

**Files:** Create `tests/providers/fixtures/kimi_loopback_fixture.py` and `tests/providers/test_kimi_acp_linux.py`.

- [ ] Write a failing native test for ACP v1, exact `Kimi Code CLI` 0.36.1 identity, and login-only auth; run RED.
- [ ] Add a same-namespace loopback fixture with synthetic OAuth only. Assert no ambient key canary, capture tools, and script text, forbidden tools, malformed streaming, delay, and cancellation.
- [ ] Prove empty `mcpServers`, no checkout, overridden `agent` with empty tools/subagents, zero upstream tools, and no local shell/subagent/MCP/plugin/skill/hook/background dispatch.
- [ ] Cover initialize, session/new/prompt/cancel, ordering, terminal, malformed/unknown/duplicate/oversized/truncated/wrong-identity/crash/timeout/race cases. Any surviving execution makes status BLOCKED.
- [ ] Run native ACP tests GREEN against the pinned ELF.

### Task 5: Characterize Data, Filesystem, Credential, and Census Boundaries

**Files:** Create `tests/providers/test_kimi_boundaries_linux.py` and `qualification/kimi-code/0.36.1/data-root-policy.json`.

- [ ] Write failing tests proving ambient config/skills/MCP/plugins/hooks/sessions/API keys/checkout/controller state/secret FDs are invisible.
- [ ] Classify immutable runtime, mutable nonsecret state, future credential state, log, cache, or unknown; unknown secret-capable state blocks.
- [ ] Characterize ACP text callbacks separately from local metadata/directory/glob/mkdir/binary/process bypass. Planner gets no filesystem authority; surviving model-controlled local paths block.
- [ ] Prove a synthetic future credential submount is absent from workspace, tools, child env/FD/argv, board, manifest, ACP events, result, logs, and evidence.
- [ ] Run native boundary tests and remove only validated temporary fixtures.

### Task 6: Regression and Independent Adversarial Review

- [ ] Run focused orchestration/provider/Kimi tests and `test_DEMO_0_SYNTHETIC_AUTONOMOUS_LOOP`.
- [ ] Run the full native WSL pytest suite; inspect diff, `git diff --check`, status, and residue.
- [ ] Dispatch an independent read-only reviewer over baseline `35d457ae02e019bad1d6956b761685f3bc978373` to candidate for provenance/update, ambient credentials/API keys, tools/shell/subagents/MCP, filesystem/checkout/canaries, process/FD/network, ACP/AOSPLAN authority, scheduler wiring, and accidental real traffic/use.
- [ ] Resolve every Critical and Important finding with TDD; unresolved findings make status BLOCKED.

### Task 7: Closure, Exact Publication, and Hard Stop

**Files:** Create `docs/phase-zero/first-autonomous-build-slice-f1-kimi-passive-closure.md`.

- [ ] Write all 28 final evidence items and exactly one status: COMPLETE/QUALIFIED or BLOCKED/BLOCKED.
- [ ] Freshly run secret/canary scans, full tests, Demo 0, `git diff --check`, and residue census.
- [ ] Commit intended qualification/policy/runtime/tests/plan/closure as `Qualify Kimi planner runtime passively`.
- [ ] Push exact WSL commit; use bundle fallback only after direct timeout; verify GitHub with `git ls-remote`.
- [ ] Fast-forward Windows and prove both trees clean/SHA-identical/0-0, with zero unpushed/untracked/stashes/residue.
- [ ] If qualified, request only `AUTHORIZE_F1_KIMI_OWNER_LOGIN_CEREMONY=YES`; do not login, prompt, access subscription, or begin F2.
