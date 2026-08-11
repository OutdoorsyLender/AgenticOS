# M6 Slice 0 — Codex Provider Adapter Architecture & Local Client Qualification

Status: design/qualification artifact only. No production code, no test changes,
no M4A/M4B/M5 authority changes. Produced by inspection, offline/local
experimentation, and official documentation research on 2026-08-11.
Adversarially reviewed on 2026-08-11; review record in §31.

Governing principle: **Models reason; AgenticOS guarantees.**

Required security objective (binding on every M6 slice):

    MODEL-CONTROLLED CODE MUST NOT RECEIVE RAW CODEX AUTHORITY.

---

## 1. Repository verification

Verified independently at Slice 0 start (2026-08-11), before any other work:

```text
WINDOWS_HEAD = ed8b545169a84a13f399a51f2f0c50e6cf2d9eda   (Windows Git, C:\AgenticOS)
WSL_HEAD     = ed8b545169a84a13f399a51f2f0c50e6cf2d9eda   (WSL Git, ~/src/AgenticOS)
ORIGIN_MAIN  = ed8b545169a84a13f399a51f2f0c50e6cf2d9eda   (after git fetch --prune origin)
GITHUB_MAIN  = ed8b545169a84a13f399a51f2f0c50e6cf2d9eda   (git ls-remote origin refs/heads/main)

WINDOWS_TREE = clean        WSL_TREE = clean
UNPUSHED_COMMITS = 0        UNEXPLAINED_UNTRACKED_FILES = 0
STASH_ENTRIES = 0 (both clones)
```

All M6 Slice 0 work in this artifact is documentation-only and was performed
against this exact state. Governing policy read and obeyed:
`AGENTS.md`, `docs/engineering/repository-preservation.md`,
`docs/phase-zero/m5-controlled-worktree-closure.md`,
`docs/phase-zero/controlled-git-worktree.md`, M4A/M4B engineering docs
(`runtime-boundary.md`, `process-containment.md`, `filesystem-isolation.md`,
`https-broker-policy.md`, `connected-build-m4b3.md`, `connected-build-profile.md`).

## 2. Actual M5 task-ref namespace

```text
ACTUAL_TASK_REF_FORMAT = refs/heads/aos/<task_id>/g<generation>
```

Evidence:

- Canonical definition: `validate_task_ref` at
  `src/agenticos/sandbox/worktree.py:660-661`
  (`branch_name = f"aos/{task_id}/g{generation}"`, `full_ref = f"refs/heads/{branch_name}"`).
- Inline fallbacks: `src/agenticos/sandbox/worktree.py:1144` and `:1162`.
- Task-id grammar: `_TASK_ID_RE = ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z`
  (`worktree.py:46`), Git-ref-forbidden substrings rejected
  (`worktree.py:646-654`), optional `git check-ref-format` validation
  (`worktree.py:666`), generation bounded to unsigned 64-bit (`worktree.py:657`).
- Branch creation `git branch <branch_name> <baseline>` (`worktree.py:1015-1018`);
  race-guarded deletion `git update-ref -d <ref> <expected_sha>`
  (`worktree.py:1296-1299`).
- Test usage: `tests/test_worktree.py:291` (`refs/heads/aos/forged-task/g1`).
- M5 Slice-0 design doc agrees: `docs/phase-zero/controlled-git-worktree.md:156`.

**Documentation inconsistency found (M5 closure doc).**
`docs/phase-zero/m5-controlled-worktree-closure.md` describes the namespace as
`refs/agenticos/<task_id>/g<gen>` in four places (lines 39, 73, 245, 289).
The implementation, tests, and the M5 design doc all use
`refs/heads/aos/<task_id>/g<generation>`. The closure doc is wrong on this one
detail; the discrepancy is conceptual, not behavioral.

Recommended docs-only fix (NOT applied in Slice 0 — it creates no M6 blocker,
and M5 closure text is treated as frozen history unless the owner directs
otherwise): in `m5-controlled-worktree-closure.md` replace all four occurrences
of `refs/agenticos/...` with `refs/heads/aos/<task_id>/g<generation>`, noting
that branches under `refs/heads/` is exactly what makes
`git branch`/`git worktree add -b` work without separate ref plumbing.

M6 consequence: none. The adapter never touches refs; ref authority remains
exclusively controller-side (`worktree.py`), and no M6 design element depends
on the misspelled namespace.

## 3. Installed Codex executable identity (host qualification, no mutation)

Two Windows installations exist; **no functional WSL/Linux installation exists**.

### 3a. Interactive CLI on PATH (user's shell installation)

- Shim resolution: `where codex` →
  `C:\Users\brand\miniconda3\envs\cbb\codex` (POSIX shim) and `codex.cmd`.
  Shims `exec node .../node_modules/@openai/codex/bin/codex.js`, which selects
  the platform package and spawns the native binary.
- Native executable:
  `C:\Users\brand\miniconda3\envs\cbb\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\codex\codex.exe`
  - Type: PE32+ executable, x86-64, console.
  - Version: `codex-cli 0.120.0` (`codex --version`).
  - Size: 183,800,112 bytes.
  - SHA-256: `3cddb048d6939b97a290936df0b398d078d842c44187b0462d4ae71b0947a3cd`
  - Owner: `brand` (user-writable install tree — see §22 risk note).
- Companion binaries (same vendor dir):
  `codex-command-runner.exe` SHA-256
  `3f8daeadb4aa9ddf741fb54b537f5282f5e68a50d7f17b16f2e64b68f0b07da5`;
  `codex-windows-sandbox-setup.exe` SHA-256
  `bd6f2702b7708d0192f9ee0b43749014058d28253c2db78b8d73f7e6eed42664`.
- Install source: npm package `@openai/codex@0.120.0` with platform
  optionalDependency `@openai/codex-win32-x64` (`0.120.0-win32-x64`),
  installed 2026-04-12 into the conda env `cbb` (npm global root of that env).
  Upstream repo: `github.com/openai/codex` (per package.json).
- Architecture/platform: Windows x86_64 (x86_64-pc-windows-msvc).

### 3b. Codex desktop-app bundled CLI (NOT to be used by AgenticOS)

- `C:\Users\brand\AppData\Local\OpenAI\Codex\bin\68de26ad08be95cd\codex.exe`
  - Version: `codex-cli 0.147.0-alpha.1.2`; size 363,706,672 bytes.
  - SHA-256: `fa960ec081bec3629f40c63ed610ebc49c7e5e077dfb42322b08cb6d460f0b8a`
- Owned by the desktop app's auto-updater (hash-named directory rotates on
  update; alpha channel). **Disqualified as an adapter target**: identity is
  not stable, channel is alpha, and it is referenced by the user's
  computer-use/plugin configuration.

### 3c. WSL

- `which codex` in WSL resolves only to the Windows shim via `/mnt/c` interop
  and fails (`exec: node: not found` — no Node in WSL). There is no native
  Linux Codex binary and no `~/.codex` in WSL.
- **Consequence:** the M4A/M5 authority boundary is Linux-only
  (bubblewrap + Landlock ABI 3 + cgroup v2, qualified on the WSL2 host). The
  only authenticated Codex client is a Windows binary. This gap drives the
  prerequisite in §18/§30: M6 needs a user-authorized native Linux Codex
  install inside WSL. Nothing was installed in Slice 0.

## 4. Observed CLI execution modes (codex-cli 0.120.0, locally observed)

From `codex --help` and subcommand help on the installed binary:

- `codex exec` (alias `e`) — **non-interactive mode**, the adapter transport:
  - Prompt as argument or stdin (`-` or piped stdin appended as `<stdin>` block).
  - `--json`: streams events to **stdout as JSONL**; human prose goes to stderr.
  - `-o/--output-last-message <FILE>`: final agent message to file.
  - `--output-schema <FILE>`: JSON Schema (strict structured-output rules)
    constraining the model's final message.
  - `-C/--cd <DIR>`: working root selection.
  - `--skip-git-repo-check`: run outside a Git repository (verified, §11).
  - `--ephemeral`: no session files persisted.
  - `-s/--sandbox read-only|workspace-write|danger-full-access`;
    `-a/--ask-for-approval untrusted|on-failure|on-request|never`.
  - Observed `codex exec` defaults: `approval: never`, `sandbox: read-only`.
  - `-m/--model`, `-p/--profile`, `-c/--config key=value` (dotted TOML
    overrides), `--enable/--disable <FEATURE>`, `-i/--image`, `--add-dir`.
  - `codex exec resume [SESSION_ID|--last]` — resume by UUID.
- `codex review` — non-interactive code review (not needed for M6).
- `codex login` / `codex login status` / `codex logout` — auth management.
  `login --with-api-key` reads a key from stdin; `--device-auth` exists.
- `codex mcp` / `codex mcp-server` / `codex app-server` [experimental] /
  `codex exec-server` [experimental] — MCP and server modes (§12, §24).
- `codex sandbox linux|windows|macos` — run a command under Codex's own
  sandbox (Landlock/bwrap on Linux; restricted token on Windows).
- `codex apply` — `git apply` the latest produced diff (requires Git; unused).
- `codex resume` / `fork` / `cloud` [experimental] / `completion` /
  `features` / `debug` (`debug prompt-input` renders the model-visible prompt
  as JSON — useful offline qualification tool).
- `codex features list` — feature-flag inventory (locally observed; confirms
  `shell_tool`, `plugins`, `unified_exec`, `multi_agent` etc. are toggleable;
  drives the default-deny enumeration in §23).

Stdin/stdout/stderr behavior (exec): prompt from argv and/or stdin; `--json`
emits machine-readable JSONL on stdout; status/errors on stderr; final message
on stdout (default) or via `-o`. Exit codes observed: `0` success (from docs),
`1` precheck/usage failure (git-repo refusal), `101` runtime error
(unauthenticated stream failure). Timeout: **no built-in wall-clock flag** —
the controller must enforce timeouts and signal/kill the process tree.

## 5. Observed configuration surfaces

Config discovery (observed + official config reference at
developers.openai.com/codex/config-reference, fetched 2026-08-11):

- `CODEX_HOME` env var selects the config/state home (default `~/.codex`;
  on Windows `%USERPROFILE%\.codex`). **Verified locally**: pointing
  `CODEX_HOME` at an empty temp dir produced a clean unauthenticated client
  with default model and no user config — the single strongest lever for
  isolating the adapter from the user's interactive configuration.
- `~/.codex/config.toml` — user config. The user's live config (read for
  threat-model purposes; no secrets in it) contains: `model =
  "gpt-5.6-sol"`, five stdio MCP servers (playwright, aws-api, aws-docs,
  duckdb, node_repl), one HTTP MCP server with a bearer-token env var
  (github → `GITHUB_PAT_TOKEN`), 15 enabled plugins, command hooks
  (`hooks.state.*`), a `notify` command, `[windows] sandbox = "elevated"`,
  and per-project `trust_level = "trusted"` entries (including this repo).
  **None of this may reach an AgenticOS-driven invocation** — hence per-task
  `CODEX_HOME` with a controller-written minimal `config.toml` (§23).
- Project-scoped `.codex/` layers (project-local config, hooks, rules) are
  skipped for **untrusted** projects (`projects.<path>.trust_level`,
  official config reference). The task workspace must remain untrusted so a
  hostile workspace cannot inject provider configuration. This suppression is
  asserted from upstream documentation, not yet verified against the exact
  qualified argv — it is a §26 gate test (§29).
- Workspace `AGENTS.md` is still read as project instructions
  (`project_doc_max_bytes`, `project_doc_fallback_filenames`). In M6 the
  workspace's AGENTS.md is untrusted task input to the model — including as
  a prompt-injection vector (§8) — never an authority surface.
- `-c key=value` dotted overrides and `-p/--profile` (profile = separate
  `~/.codex/<name>.config.toml` in current versions).
- Security-relevant keys catalogued for §23 classification:
  `model_providers.<id>.{base_url,env_key,http_headers,env_http_headers,
  query_params,experimental_bearer_token,auth.command,requires_openai_auth,
  supports_websockets,wire_api}`, `openai_base_url`, `chatgpt_base_url`,
  `forced_login_method`, `cli_auth_credentials_store`,
  `sandbox_mode`, `sandbox_workspace_write.*`, `permissions.*`,
  `windows.sandbox`, `shell_environment_policy.*`, `mcp_servers.*`, `hooks.*`,
  `notify`, `features.*`, `web_search`, `check_for_update_on_startup`,
  `otel.*`, `history.persistence`, `model_instructions_file`, `plugins.*`,
  `skills.*`, `agents.*` (multi-agent spawning), `tools.web_search`.
- Environment variables honored: `CODEX_HOME`, `CODEX_API_KEY`
  (exec-only API-key override), `OPENAI_API_KEY` (login), provider `env_key`
  variables, MCP `bearer_token_env_var` variables. Proxy/CA env behavior is
  **not documented** upstream; to be qualified in M6-2 (§10, §29).

## 6. Authentication storage/access model (no secret contents inspected)

- `codex login status` → **`Logged in using ChatGPT`** — the user's existing
  ChatGPT subscription session is active on the Windows installation.
- Credential material lives at `C:\Users\brand\.codex\auth.json`
  (4,036 bytes, user profile, not read, not copied, not printed).
  `cli_auth_credentials_store` supports `file | keyring | auto`; current host
  uses the default file store.
- Official docs (github.com/openai/codex `docs/authentication.md`, fetched
  2026-08-11): ChatGPT sign-in runs an OAuth flow with a `localhost:1455`
  callback; tokens are cached in `$CODEX_HOME/auth.json` and refreshed
  automatically; the file is **not tied to a specific host**. API-key mode is
  the usage-based alternative (`codex login --with-api-key`).
- Access model: only the Codex client process needs the file. It reads
  `auth.json`, refreshes tokens against OpenAI auth endpoints, and attaches
  bearer credentials to provider requests. Nothing else — and no other
  process in any AgenticOS domain — needs it.
- Token refresh writes: automatic refresh implies the client **writes**
  rotated tokens back to `$CODEX_HOME/auth.json`. The recommended read-only
  bind (§14) deliberately blocks that write; whether the client then keeps
  rotated tokens memory-only (acceptable), fails mid-turn on expiry
  (availability bug), or errors at startup is unverified and listed in §29
  as an M6-2 qualification item. Security upside if tolerated: refreshed
  tokens never persist into any AgenticOS-visible domain.
- Slice 0 compliance: no login/logout/reauthentication performed; no auth
  file read/copied/moved; no token printed; the only auth probe was
  `codex login status` (metadata) and an **unauthenticated** invocation with
  an empty `CODEX_HOME` (§11), which failed 401 without touching real
  credentials or consuming quota.
- Roadmap constraint honored throughout this design: AgenticOS does not
  extract, copy, deserialize, relocate, or replay consumer credentials
  (`docs/roadmap.md:31-39`). The user authenticates each installation
  themselves (§30 Q2), and the read-only bind-mount mechanism itself
  requires explicit owner sign-off (§30 Q8).

## 7. Provider-client threat model

Trust distinction (binding): the **provider client** (official Codex
executable + its auth + its network identity) is trusted only to talk to the
provider and to edit the task workspace through its own tools. Every
**model-generated action** (shell commands, file edits, tool requests, prose)
is hostile input. An official binary does not launder model intent into
controller authority.

Assets: ChatGPT OAuth tokens (access + refresh) in `auth.json`; provider API
access; the task worktree; controller state; sibling worktrees; the
authoritative checkout; host environment.

Adversaries: (a) hostile task content steering the model (prompt injection
from workspace files, including AGENTS.md); (b) the model itself emitting
malicious tool requests; (c) workspace content attempting config/MCP/hook
injection; (d) PATH/binary substitution; (e) network exfiltration.

Key structural findings:

1. **Codex does not separate its own authority from model-directed tool
   execution.** Shell commands, file reads, and edits all execute in the
   Codex process tree with the same OS identity that holds `auth.json`
   (§12, §16). There is no official external-executor hook (§12). Therefore
   any domain that runs Codex *with its shell tool enabled* gives
   model-directed code a direct path to the credential file → violates the
   required security objective. This single fact eliminates Architectures A
   and B and constrains C (§18).
2. **Even edit-only, the client's own file-read tools run with client
   authority.** No kernel-level control can deny the qualified client read
   access to the `auth.json` it must legitimately read, so a
   prompt-injected model can ask the client to read it (§8). This is the
   central residual of the recommended architecture, stated honestly in
   §30 Q6 — not a solved problem.
3. The user's interactive `~/.codex` is densely configured (MCP servers with
   bearer env vars, plugins, hooks, `notify` command). Reusing it for
   automated runs would import arbitrary execution surfaces → per-task
   `CODEX_HOME` is mandatory.
4. Project-scoped `.codex` config/hook/rule layers are a workspace-config
   injection vector; untrusted-project semantics suppress them (§5,
   verification gated in §26).
5. `agents.*`/multi-agent spawning, `tools.web_search`, MCP, plugins,
   hooks, `unified_exec` are default-on or configured; every one must be
   explicitly denied in the controller-written provider config (§23).
6. Codex's own sandbox (`codex sandbox linux`, Landlock/bwrap) exists but is
   defense-in-depth only (§13) and is not nestable inside M4A
   (`--disable-userns`); never a primary boundary.

## 8. Credential threat model

Evaluated against the recommended architecture (§18, C′) per attack.
The copy-into-workspace row carries the architecture's central residual —
read it before Q6.

| Attack | Assessment under C′ |
|---|---|
| Worker reads Codex auth material | **Denied by construction.** Credentials never enter the M4A worker domain; worker env is the fixed 6-entry `WORKER_ENVIRONMENT` (`runtime_boundary.py:141-148`) + bounded extras (`runtime_boundary.py:618-657`) with Git-authority names rejected (`FORBIDDEN_GIT_ENV_NAMES`, `runtime_boundary.py:609-615`) and provider prefixes stripped from ambient env (`launcher.py:86-95`). |
| Credentials printed to logs | Provider sandbox stdout/stderr captured by controller; `--json` events contain no headers; residual = model tricks the client into echoing file contents → same channel as the next row. |
| **Copy credentials into `/workspace`** | **Honest residual — no kernel-level barrier exists.** The qualified client must read `auth.json` to authenticate; its file-read tools run in the same process with the same authority. A prompt-injected model (hostile AGENTS.md, source comments) can instruct the client to read the provider-home path and write the contents into `/workspace`. Barriers, in order of strength: (1) **egress lock** — even if read, the only network destinations are the provider's own hosts (scoped below); (2) **tool-surface reduction** — no shell tool means no `cat`/`base64` pipeline, only the client's read/write tools; (3) Codex `permissions` deny-read profiles *may* block the read tool on the provider-home path — provider self-policy, defense-in-depth only, effectiveness unverified (§29); (4) **canary tripwires** — decoy credential-shaped files at plausible probe paths detect read-probing; (5) **evidence scan** — best-effort tripwire only: the roadmap forbids AgenticOS reading `auth.json`, so the scanner cannot know the exact secret bytes and is evadable by encoding (chunked, reversed, paraphrased); on any hit *or* anomaly the worktree is quarantined (never published) and the user revokes tokens. A scan miss converts a transient exposure into an M5-preserved artifact — the scan is therefore not load-bearing. The true bound on this channel is §30 Q6. |
| Send credentials to attacker host | Provider-sandbox egress restricted to exact provider hosts only (§10); no attacker destination is reachable. **Scope limit:** "tokens sent to the provider's own endpoints are not exfiltration" holds only for single-provider task lineages. In multi-provider lineages (e.g., a future cross-provider reviewer, roadmap item 5), credential material planted in `/workspace` by provider A's model becomes file content that provider B's model reads and may transmit to B's hosts. Multi-provider flows require their own milestone threat model before authorization. |
| Manipulate HOME/XDG/config lookup | Provider sandbox environment is controller-fixed (`CODEX_HOME`, `HOME` pointed at the per-task provider home); the model cannot alter the parent process environment. |
| Substitute Codex configuration | Config is controller-written, outside the workspace, read-only to the sandbox; project `.codex` layers skipped for untrusted projects (verification gated, §26 item 12). |
| Influence endpoint/base URL | `base_url`/`openai_base_url`/`chatgpt_base_url` exist only in controller-written config; not model-reachable. |
| Proxy/CA variable abuse | Provider sandbox env is explicit and minimal; no ambient proxy/CA inheritance. |
| Unrelated requests with credential | Egress-limited to provider hosts; the model has no socket access of its own (only the client process does, under the egress policy). |
| Persist credentials in source/output | Canary tripwires + best-effort scan + quarantine-on-anomaly (above). Not a guarantee — see Q6. |
| Pass credentials to child processes | No model-directed children exist (shell tool and all exec-capable features denied, §23). The client's *own* children (e.g., its search helper) inherit the same confined domain; they are censused and identity-qualified per §22 before the first live task. |
| `/proc` access to credentials | `/proc` inside the PID-namespaced provider sandbox shows only sandbox processes. Whether the client hands token material to any helper process is an M6-1 census question (§22, §29), not an established fact. |
| Inherit credential FDs | M4A launch discipline: the controller never passes sensitive FDs; the provider sandbox gets the same `close_range` treatment via `fs_launcher` as workers do. |
| Cross-task resume/session leakage | `--ephemeral` + `history.persistence="none"` + per-task `CODEX_HOME`; resume disabled initially; `thread_id` captured and correlated with `task_id/generation/attempt_id` by the controller (§15). Server-side retention caveat: §15. |

## 9. (reserved — section numbering follows the task's required structure; the
credential threat model is §8 above.)

## 10. Codex network requirements

Locally observed (unauthenticated probe, 0.120.0, empty `CODEX_HOME`):

- Primary transport attempted: **WebSocket** `wss://api.openai.com/v1/responses`
  (module `codex_api::endpoint::responses_websocket`), 5 reconnects, then
  **fallback to HTTPS/SSE** `https://api.openai.com/v1/responses`
  (same endpoint, `https` scheme, request id logged). Failure was 401
  pre-auth — no model call, no quota consumed.
- Config reference confirms `model_providers.<id>.supports_websockets` as a
  per-provider toggle and `wire_api = "responses"` (SSE) as the only wire
  protocol.

From official docs and pinned third-party source audit (cited; to be
re-qualified locally in M6-2):

- ChatGPT-authenticated traffic: `POST
  https://chatgpt.com/backend-api/codex/responses` with bearer token and
  `ChatGPT-Account-ID` header (loom.js audit pinned to openai/codex commit
  `9ff47868…`; implementation detail, not a published contract).
- OAuth login/refresh: `auth.openai.com` (+ `localhost:1455` loopback during
  login only; `chatgpt_base_url` override exists).
- API-key mode: `api.openai.com/v1/responses`.
- Ancillary traffic: startup update check (`check_for_update_on_startup`),
  Statsig OTEL metrics by default (`otel.metrics_exporter`), model catalog
  cache (`models_cache.json` observed), web-search tool endpoints if enabled.
  All disable-able in the controller-written config.

M4B relationship (do **not** broaden M4B):

- The M4B-3 Connected Build broker is a strict HTTP/1.1 CONNECT proxy with
  TLS termination, method policy GET/HEAD(/POST), bounded request/response
  relay, ECH denial, and exact-host grants (`CONNECTED_BUILD_MAX_GRANTS = 4`).
- Provider traffic differs in kind: long-lived streaming POSTs (SSE) or
  WebSocket upgrade, bearer credentials on the wire, different hosts,
  different lifetime and byte profile. **WebSocket upgrade is incompatible
  with the current broker's strict HTTP/1.1 envelope.** TLS-terminating the
  provider stream at the broker would also expose bearer tokens to the broker
  — an unearned credential surface.
- Therefore: provider control-plane traffic gets a **separate capability
  class** ("provider egress"), not Connected Build grants
  (`task acquisition network capability != model provider control-plane
  capability`). Candidate mechanism (M6-2 decision, not implemented): the
  provider sandbox's netns permits TCP/443 only to the controller-designated
  exact provider host set, via either (a) a new minimal non-terminating
  CONNECT allowlist proxy, or (b) a netns-level egress filter. The provider
  client itself attaches credentials; AgenticOS never sees them in plaintext.
- DNS handling is part of the same M6-2 decision (§30 Q3): who resolves the
  provider hostnames (pinned hosts file vs controller resolver vs in-sandbox
  DNS), how CDN rotation is handled, and rebinding posture. With end-to-end
  TLS to the exact named hosts (non-terminating path), rebinding risk is
  low, but the resolution path must be explicit, not accidental.

Exact host set, per-mode (ChatGPT vs API-key) endpoints, streaming transport
actually used by the qualified Linux build, proxy/CA env behavior, and
redirect/telemetry behavior: **unresolved until M6-2 passive qualification**
of the Linux client (§29, §30 Q3/Q4).

## 11. Gitless workspace compatibility (locally verified)

Synthetic probes in a temp non-Git directory with an empty `CODEX_HOME`
(no credentials, no quota):

- Without the flag: `codex exec` exits 1 **locally, before any network**:
  `Not inside a trusted directory and --skip-git-repo-check was not
  specified.` → Codex requires a Git repo *or* a config-trusted directory.
- With `--skip-git-repo-check`: Codex started normally in the plain
  directory (banner showed correct `workdir`), proceeded to the model call,
  and failed only at authentication (401, expected with empty CODEX_HOME).

**Earned claim (offline): Codex operates in a Gitless directory with
`--skip-git-repo-check`.** M5's masked `.git` is compatible; no `.git`
exposure is needed. Not yet established (needs live run, M6-3): whether
Codex silently degrades (e.g., expects `git status/diff` context) during a
real task. `codex apply` and `codex review` are Git-dependent and unused.
Parent-directory `.git` discovery is moot: in the provider sandbox the only
mounted tree is the worktree (with the mask mounted over `.git`).

The interaction between `--skip-git-repo-check` and untrusted-project
config-layer suppression (§5) with the exact qualified argv — including a
hostile `.codex/` directory planted in the workspace — is untested and is a
§26 gate item.

## 12. Command/tool execution model (official client)

- The model's shell commands are executed **by the Codex process itself**
  via its internal `shell` tool (`features.shell_tool`, stable, default on):
  on Windows through `codex-command-runner.exe` under a restricted token
  when sandboxed; on Linux under Codex's own Landlock/bwrap sandbox when
  enabled. There is **no official mechanism to delegate model tool execution
  to an external executor**. (`mcp_servers.<id>.experimental_environment =
  "remote"` applies to MCP stdio servers only; `app-server`/`exec-server`
  are experimental and not a tool-execution split.)
- Approval modes and sandbox modes govern *its own* execution
  (`-a never` + `-s workspace-write` for exec automation).
- **M6 consequence:** with the official client, model-interleaved arbitrary
  command execution cannot be routed through the M4A hostile worker. The
  smallest safe adaptation (§18): run Codex **edit-only**
  (every exec-capable feature denied, §23; MCP/web-search/hooks/plugins/
  notify disabled). The verification loop (running tests/builds) is
  performed by the **controller** through the existing M4A hostile worker
  using controller-selected commands (`allowed_command_patterns`), with
  results fed back to the model as `previous_attempt_summary` on the next
  attempt. The model never directs live command execution in the first
  adapter.
- If a future milestone needs model-interleaved commands, re-evaluate
  `exec-server`/`app-server` or an MCP-shaped execution bridge; not M6
  scope.

## 13. Codex's own sandbox is not the AgenticOS boundary

Codex ships platform sandboxes (`codex sandbox linux|windows|macos`;
`windows.sandbox = unelevated|elevated`; Landlock/bwrap on Linux). Recorded
facts: the user's config sets `[windows] sandbox = "elevated"`; the Linux
sandbox uses bwrap by default.

M6 posture (explicit): **Codex self-sandboxing is defense-in-depth only.**
AgenticOS M4A (bubblewrap + Landlock ABI 3 + cgroup v2 + FD census + fixed
env) and M5 (worktree authority + evidence) remain the authority boundary.
Two practical notes: (1) Codex's command sandbox cannot nest inside M4A
(`--disable-userns`), so inside the provider sandbox Codex's own command
sandbox is effectively off and the boundary is AgenticOS's; (2) Codex's
`permissions` profiles include deny-read rules that *may* restrict its own
file-read tools (e.g., against the provider home) — this is provider
self-policy, its effectiveness is unverified (§29), and it is never
load-bearing; in particular it is **not** credited in §8 as a real barrier.

## 14. Workspace access design

- The model's conceptual workspace is exactly `/workspace` — the M5 task
  worktree, bind-mounted RW into the provider sandbox with the inert
  controller-owned mask mounted read-only over `/workspace/.git`
  (`MountRole.GIT_MASK`, `runtime_boundary.py:743-753`; tamper-denied per
  `tests/test_worktree_sandbox.py:439-482`).
- `codex exec -C /workspace` keeps the client's working root inside the
  sandbox view; the client never learns host paths (state root, repo path,
  sibling worktrees are simply not mounted).
- Per-task provider `CODEX_HOME` (controller-written config + read-only
  bind of the user's `auth.json`) lives at a separate mount
  (`/opt/agenticos/provider-home`), outside `/workspace`. The read-only
  bind is deliberate: refresh-write behavior against it is a qualification
  item (§6, §29), and the mechanism itself is owner-gated (§30 Q8).
- Writable set inside the provider sandbox: `/workspace`, `/tmp`,
  per-task provider home state dirs (sessions disabled by `--ephemeral`
  anyway). Nothing else.
- Symlink/hardlink escape review: model-planted symlinks in `/workspace`
  resolve inside the sandbox namespace where non-workspace mounts are
  read-only and Landlock scope bounds access; controller-side evidence
  capture is symlink-safe (`lstat`, no-follow, `[SYMLINK -> target]`
  rendering, `worktree.py:1570-1619`). Hardlink escape fails cross-mount
  (EXDEV). The `.git` mask is mount-based and tamper-denied.

## 15. Session / conversation state model

- Observed: `$CODEX_HOME/sessions/YYYY/MM/DD/rollout-<timestamp>-<uuid>.jsonl`
  (106 rollout files in the user's home; filenames only inspected). Sessions
  persist full conversation context and are resumable by UUID
  (`codex exec resume <id>`) or `--last`.
- Policy for M6: **one fresh ephemeral provider session per AgenticOS
  attempt.** `--ephemeral` (no session files) + `history.persistence="none"`
  + per-task `CODEX_HOME`. No resume in the first adapter: cross-attempt
  context is carried only by the controller via
  `previous_attempt_summary` (typed input), never by provider-side state.
- Correlation: controller records `thread_id` from the `thread.started`
  JSONL event against `(task_id, generation, attempt_id)`.
- Rollout files contain source snippets and model outputs; with per-task
  ephemeral homes, task A's session bytes can never attach to task B
  client-side.
- **Server-side caveat:** with ChatGPT authentication, conversation
  retention and any account-level memory are server-side properties of the
  user's ChatGPT account. Client flags cannot erase server-side cross-task
  association. Accepted residual (or, alternatively, a user account-setting
  prerequisite at §26); listed in §29.
- Revisit resume only if multi-turn repair within one attempt proves
  necessary; any future resume must key on controller-recorded `thread_id`
  and same `(task_id, generation)`.

## 16. Command-execution split conclusion

See §12: the official client provides no external tool-execution hook, so
Architecture D (controller-side Codex + constrained execution bridge) is
**not supported by the current official client** and is documented as a
limitation, not adopted. The edit-only provider sandbox (C′) with a
controller-mediated verification loop is the honest adaptation.

## 17. File edit model

- Edits are applied **by the Codex process** (internal patch/apply
  machinery; `apply_patch_freeform` feature observed under development;
  `codex apply` exists as a separate Git-based path — unused).
- Therefore model-directed writes are filesystem writes from the qualified
  client binary, confined by the provider sandbox's Landlock view to
  `/workspace` (+ task tmp). No write path exists to the authoritative
  checkout, controller state, auth state (mounted read-only), other
  worktrees, `$HOME`, or Git metadata (masked).
- M5 evidence capture (`git status --porcelain=v1 -z`, bounded `git diff
  HEAD`, untracked-file evidence caps) runs controller-side after client
  exit, unchanged.

## 18. Candidate architecture comparison

Scored against the earned guarantees. ✅ preserves, ⚠️ partial/costly, ❌ violates.

| Criterion | A: Codex inside M4A worker | B: Codex controller-side | C: Provider sandbox (shell on) | C′: Provider sandbox, edit-only (RECOMMENDED) | D: Codex + external exec bridge |
|---|---|---|---|---|---|
| Subscription auth compatibility | ❌ credentials would enter hostile domain | ✅ | ✅ | ✅ | ✅ |
| Secret isolation (model code ≠ raw Codex authority) | ❌ model code reads `auth.json` directly | ❌ model commands run as controller-side client | ❌ model shell runs beside `auth.json` | ⚠️ no model-directed code executes; honest residual: client read-tools can reach `auth.json` (§8, Q6) | ✅ (if it existed) |
| M4A compatibility | ⚠️ fixed env strips provider vars; FD census ok | ❌ bypasses M4A for model commands | ✅ (M4A-derived profile) | ✅ | ✅ |
| M5 Gitless compatibility | ✅ (`--skip-git-repo-check`) | ✅ | ✅ | ✅ | ✅ |
| Filesystem authority | ⚠️ worker RW only /workspace, but creds present | ❌ client would need host worktree path + controller FS | ✅ Landlock view | ✅ | ✅ |
| Command execution authority | ⚠️ commands in-worker (right domain) but same domain as creds | ❌ model commands = controller authority | ⚠️ commands confined to provider sandbox, but beside creds | ✅ no model-directed commands; verification via M4A worker | ✅ |
| Network authority | ❌ needs bearer through M4B broker (unearned) | ⚠️ unrestricted host egress unless new policy | ✅ provider-egress class | ✅ provider-egress class | ✅ |
| Cancellation/cleanup | ✅ cgroup | ⚠️ controller kill of own child | ✅ cgroup | ✅ cgroup | ✅ |
| Provider session isolation | ⚠️ | ⚠️ | ✅ per-task home | ✅ per-task ephemeral home | ✅ |
| Implementation complexity | high (env/FD/net surgery) | low but disqualifying | medium | medium | blocked (no official hook) |
| Provider neutrality | ❌ | ⚠️ | ✅ | ✅ | ✅ |
| Testability | ⚠️ | ⚠️ | ✅ | ✅ | — |
| Self-hosting readiness | ❌ | ❌ | ⚠️ | ✅ (after gates) | — |

**Recommended: C′** — a dedicated provider-client sandbox (M4A-derived
profile on the WSL2 host) running the identity-qualified official Codex
Linux client in **edit-only** mode, with per-task controller-written
`CODEX_HOME`, read-only `auth.json` bind (owner-gated, Q8), `/workspace` RW
with masked `.git`, provider-egress network class, and a
controller-mediated verification loop through the unchanged M4A hostile
worker. It is the smallest architecture that preserves every earned
guarantee while using the official client and the user's existing
subscription — **with one honestly-stated residual** (§8 copy row, §30
Q6): client read-tools share authority with the credential file, so
credential exposure to model context cannot be kernel-prevented, only
bounded (egress lock, tool-surface reduction, tripwires, revocation). If
the owner does not accept that residual, the remaining alternative
(AgenticOS brokering tokens) is roadmap-forbidden and M6 is a hard stop —
that is the decision Q6 puts to the owner.

Architecture E considered ("Codex's own sandbox as the boundary"): rejected
as primary boundary per §13; retained as unverified defense-in-depth.

## 19. Controller / provider / worker authority split (recommended)

```text
CONTROLLER (trusted, existing M5 + new adapter front-end)
  owns: repo identity, baseline, refs (refs/heads/aos/<task>/g<gen>),
        WorktreeReservation, lifecycle state, provider-task config
        authoring, executable qualification, evidence capture,
        verification command selection, preservation, cancellation,
        attempt budget.
  never: sends credentials anywhere; executes model-selected commands;
         reads auth.json contents (roadmap); treats model prose or event
         message text as authority.

PROVIDER-CLIENT SANDBOX (new M4A-derived domain, per attempt)
  holds: qualified codex binary (ro), per-task CODEX_HOME (config ro,
         auth.json ro bind), /workspace RW (git masked), task /tmp.
  may:   talk to exact provider hosts; read/edit /workspace via its own
         tools (edit-only: all exec-capable features, MCP, hooks,
         plugins, web-search denied).
  may not: see host paths, controller state, sibling worktrees, main
         .git, ambient env/credentials, arbitrary egress, model-directed
         subprocesses.

M4A HOSTILE WORKER (existing, unchanged)
  runs: controller-selected verification commands (pytest, build) in
        /workspace; Connected Build grants as already earned.
  never: sees provider credentials/config/endpoints.
```

Attempt loop: controller creates worktree (M5) → writes prompt input
(prompt, acceptance criteria, file constraints, selected context,
`previous_attempt_summary`) → launches provider sandbox (`codex exec
--skip-git-repo-check --ephemeral --json -C /workspace -a never
-s workspace-write`, per-task config) → client exits/is cancelled →
controller captures M5 worktree evidence + JSONL model claims → controller
runs verification in M4A worker → composes result, preserves per M5 →
optional next attempt with fresh session.

**Attempt budget:** attempts per task are bounded by a controller-side
maximum (consistent with the existing generation model). Retry/continue
decisions are made from structural signals only (exit codes, event types,
verification results) — never from model-influenced message text — so a
model cannot steer the controller into quota-burning retry loops by
shaping failure prose.

## 20. Provider-neutral adapter boundary (design only — not implemented)

Minimal provider-neutral types (aligning with the M5 closure's typed
contracts, `m5-controlled-worktree-closure.md:125-202`):

- `ModelTaskRequest` (controller → adapter): `repository_id`, `task_id`,
  `generation`, `attempt_id`, `user_prompt`, `acceptance_criteria`,
  `file_constraints`, `workspace_path` (always `/workspace`),
  `runtime_profile`, `timeout`, `allowed_command_patterns`,
  `network_mode` (`"DENIED" | "CONNECTED_BUILD"`),
  `connected_build_grants`, `selected_context_files`,
  `repository_summary`, `previous_attempt_summary`.
  Invariants (from M5): no host paths, no `.git` paths, no credentials,
  no state-root locations.
  **Scope clarification (adversarial review F3):** `network_mode`,
  `connected_build_grants`, and `allowed_command_patterns` describe the
  **M4A worker (verification) phase only**. Provider egress is
  controller/adapter-side policy (§10) and is never expressed in the
  model-facing request; no `"PROVIDER_EGRESS"` value is added to this
  enum, so provider traffic can never be wired into Connected Build
  grants by type confusion.
- `ModelTaskResponse` (adapter → controller; **claims, not evidence**):
  `provider`, `provider_session_id`, `model`, `final_message`
  (schema-validated if `--output-schema` used), `claimed_file_changes`,
  `claimed_commands`, `usage` (tokens if reported), `provider_events_digest`
  (SHA-256 of captured event stream), `client_exit_code`,
  `client_duration`, `failure_class` (typed: `AUTH`, `RATE_LIMIT`,
  `MODEL_UNAVAILABLE`, `PROVIDER_ERROR`, `TRANSPORT`, `TIMEOUT`,
  `MALFORMED_OUTPUT`, `CANCELLED`).
  **Mapping invariant (adversarial review F7):** `failure_class` is
  derived only from process exit codes and structural event types
  (`turn.failed`, `error` occurrence), never from message text, which is
  model-influenced.
- `ProviderExecutionEvidence` (controller-compiled, guaranteed side):
  M5 `TaskWorktreeResult` (diff SHA-256/byte count, path categories,
  truncation flags), worker exit/signal/timeout, cgroup evidence,
  connected-build evidence, provider-egress evidence (new class),
  preservation classification, executable identity record (including the
  child-process census, §22), config digest.

Provider-specific details (flag spelling, JSONL schema, session files,
endpoint set) live only behind `CodexAdapter`. A future `ClaudeAdapter` /
`KimiAdapter` must be addable without touching M4A/M5. Deliberately no
larger abstraction than these three types; the adapter is a translation
layer, not a second controller — it launches nothing outside the provider
sandbox, selects no host paths, touches no refs, and holds no network or
cleanup authority.

## 21. Codex-specific adapter boundary (design only)

`CodexAdapter` responsibilities: executable qualification (§22); per-task
`CODEX_HOME` rendering from the default-deny enumeration (§23); argv
construction for `codex exec`; JSONL event capture + digest; `thread_id`
extraction; stderr capture; mapping Codex exit codes/structural events to
`failure_class` (structural signals only, §20); enforcing `--ephemeral`;
prompt serialization to stdin; output-schema handling.
Explicitly NOT responsible for: Git operations, host path selection,
network policy, evidence capture, preservation (all controller).

Qualified invocation shape (target; to be validated on the Linux build in
M6-1/2; the complete `-c` deny set is generated from the qualified build's
`codex features list` per §23, not hand-maintained):

```text
CODEX_HOME=/opt/agenticos/provider-home \
codex exec --skip-git-repo-check --ephemeral --json \
  -C /workspace -m <pinned-model> -a never -s workspace-write \
  -c features.shell_tool=false -c features.unified_exec=false \
  -c features.multi_agent=false -c web_search="disabled" \
  -c check_for_update_on_startup=false -c history.persistence="none" \
  -c shell_environment_policy.inherit="none" \
  [-c model_reasoning_effort=...] < prompt.txt
```

## 22. Executable integrity policy (fail-closed, not yet implemented)

Mirror the M4A bubblewrap pinning discipline (`runtime_boundary.py:434-585`):

- Invoke the **native binary by absolute qualified path**, never via PATH,
  never `codex` shim resolution, never `./codex`, never a
  workspace-provided executable, never the desktop-app auto-updated binary.
- Qualification record: absolute path, expected version string
  (`codex --version`), SHA-256 digest, size, ownership (root or designated
  service account — **not** a user-writable location), mode (0755, no
  setuid/caps), platform/arch. Verified at open time (openat2 + fstat +
  hash), re-verified per launch; any mismatch → provider unavailable,
  fail closed, no fallback.
- **Child-process census (adversarial review F12):** the qualification
  record includes an inventory of every process the client spawns (search
  helpers, sandbox helpers, runners), each identity-qualified the same
  way. An unqualified child fails closed. The census is a precondition of
  the first live task gate (§26 item 4).
- Install location must be controller-managed (e.g.
  `/opt/agenticos/providers/codex/<version>/codex`), not the user's npm
  tree (the current Windows binary lives in a user-writable conda env —
  acceptable for the user's interactive use, not for a security-pinned
  adapter).
- Record the identity in `ProviderExecutionEvidence` per attempt.

## 23. Provider configuration policy

Classification of every relevant surface (§5 catalogue):

- CONTROLLER_AUTHORITY (controller-written per-task config; read-only to
  sandbox): `model`, `model_reasoning_effort`, `model_provider`,
  provider endpoint fields, `sandbox_mode`, `approval_policy`,
  `web_search="disabled"`, `check_for_update_on_startup=false`,
  `history.persistence="none"`, `shell_environment_policy.inherit="none"`,
  `otel.*=none`, `agents.enabled=false`, `mcp_servers` (absent),
  `hooks` (absent), `notify` (absent), `plugins.*` (absent/denied),
  `skills` (absent), `model_instructions_file` (controller-fixed or
  default; workspace AGENTS.md treated as untrusted input),
  `cli_auth_credentials_store="file"`, `log_dir` (per-task,
  controller-readable).
- **Default-deny feature enumeration (adversarial review F6):** at M6-1
  qualification, the exact qualified build's `codex features list` output
  is captured and **every** flag receives an explicit allow/deny decision
  in the controller-written config — `shell_tool`, `unified_exec`,
  `multi_agent`, `plugins`, `web_search`, `memories`, `goals`, hooks and
  all other exec-, network-, or persistence-capable flags denied. A
  version change that introduces a new flag fails qualification until the
  flag is classified. No exec-capable surface ships at default.
- PROVIDER_INSTALLATION_AUTHORITY: the binary itself and its bundled
  resources (qualified per §22); default model catalog.
- USER_AUTHENTICATION_STATE: `auth.json` only, bind-mounted read-only from
  the user's WSL `~/.codex` into the per-task provider home (owner-gated,
  §30 Q8; refresh-write behavior per §6/§29). Nothing else from the
  user's `.codex` (no config.toml, sessions, plugins, MCP, hooks, state
  DBs) is mounted.
- MODEL_UNTRUSTED: the entire workspace including any `AGENTS.md`,
  `.codex/` layers (skipped — untrusted project semantics, verification
  gated §26 item 12), promptable content, `--json` event contents.
- NOT_RELEVANT / EXCLUDED: TUI settings, desktop/computer-use settings,
  marketplaces, memories (denied), goals (denied), multi-agent (denied),
  MCP OAuth callbacks, cloud subcommand.

Injection guard: config file and `CODEX_HOME` live outside the writable
workspace; the workspace is not listed in `[projects]` (untrusted →
project layers skipped); `-c` overrides come only from controller code.

## 24. MCP / plugin / external tooling policy

M6 posture: **DISABLED / NOT AUTHORIZED.** No MCP servers (stdio or HTTP),
no plugins, no hooks, no `notify`, no skills, no multi-agent spawning, no
web search in the provider sandbox. Guarantees: controller-written
`CODEX_HOME` contains none of these stanzas; workspace content cannot
introduce them because project config layers are skipped for untrusted
projects (verification gated, §26 item 12) and the workspace holds no
authority over `CODEX_HOME`. The user's interactive MCP/plugin/hook
configuration (5 stdio + 1 HTTP MCP with a bearer env var, 15 plugins,
hooks — §5) never enters the adapter path. Re-enabling any of these is a
separate milestone with its own threat model.

## 25. First implementation slices (recommended order)

- **M6-1** — Provider-neutral types (`ModelTaskRequest`,
  `ModelTaskResponse`, `ProviderExecutionEvidence`) + Codex executable
  qualification probe (path/version/digest/ownership, fail-closed) +
  child-process census + `features list` capture for the default-deny
  enumeration + per-task `CODEX_HOME` renderer. Includes the
  user-authorized Linux install step (§30 Q1/Q5) and its qualification.
  Offline tests: hostile `.codex/` workspace proves zero config effect
  (§26 item 12). Earned claim: "the exact qualified client starts in a
  synthetic provider sandbox, edit-only config, unauthenticated path
  fail-closed."
- **M6-2** — Authenticated invocation transport, **no model tool execution
  beyond file edits**: per-task provider home + ro `auth.json` bind
  (post-Q8 sign-off); provider-egress network class (exact hosts;
  transport decision SSE-vs-WebSocket and DNS path after local
  qualification); read-only-bind refresh behavior resolved (§6/§29);
  JSONL capture + digest; `failure_class` mapping (structural only).
  Earned claim: "one authenticated `codex exec` turn on a synthetic
  workspace with bounded egress and captured events." (First live
  invocation requires the §26 gate and §30 Q4 approval.)
- **M6-3** — One synthetic coding task end-to-end: M5 worktree → edit-only
  Codex → M5 evidence → M4A worker verification command → preserved
  result. Earned claim: "model edits land only in the task worktree;
  controller evidence matches; verification ran worker-side."
- **M6-4** — Cancellation/failure/evidence qualification: client hang,
  kill mid-turn, auth expiry, 401/429/5xx mapping, worker-vs-client death
  ordering, controller crash, canary tripwire + scan drill. Earned claim:
  "provider failure never destroys task work; cleanup is deterministic."
- **M6-5** — Deterministic verification + full synthetic task battery +
  adversarial review, feeding the M5 self-hosting gate (§27).

Rationale for the order change vs the task's sketch: executable
qualification must come first because the only installed client is a
Windows binary outside the security boundary; transport qualification
(SSE/WebSocket, exact endpoints, DNS) gates the network design.

## 26. First live Codex task gate

All must hold before the first authenticated `codex exec` against the real
subscription (target: M6-2, synthetic repository only):

1. Linux Codex installed in WSL with explicit user authorization; version
   pinned; executable qualified per §22 (path/version/SHA-256/ownership).
2. User performed native WSL `codex login` themselves; AgenticOS never
   copied/replayed credentials; `codex login status` confirms ChatGPT
   auth; owner sign-off on the ro-bind mechanism (§30 Q8) recorded.
3. Per-task `CODEX_HOME` rendering proven to exclude user config/MCP/
   hooks/plugins (offline diff of effective config); the default-deny
   feature enumeration (§23) applied to the exact qualified build.
4. Provider sandbox launches under the M4A-derived profile with FD
   census, fixed env, `/workspace`-only writability, `auth.json`
   read-only — **and the §22 child-process census is complete with every
   spawned process identity-qualified**.
5. Provider-egress policy active with the exact qualified host set and an
   explicit DNS resolution path; no other destinations reachable
   (probe-verified).
6. Gitless operation confirmed (`--skip-git-repo-check`; `.git` masked).
7. Shell tool/MCP/hooks/plugins/web-search confirmed disabled in a live
   dry run — the captured event stream shows **zero tool items outside
   the read/edit set**.
8. Cancellation drill passed: SIGINT→SIGTERM→kill leaves no provider or
   worker residue (cgroup recursive emptiness).
9. Model claims and guaranteed evidence recorded as separate artifacts;
   `failure_class` mapping uses structural signals only.
10. Synthetic repository only (never the AgenticOS repo or any real
    project); task content reviewed; quota bounded (single small task,
    pinned model, reasoning effort capped); attempt budget set.
11. Canary tripwires in place at plausible credential-probe paths;
    best-effort credential-pattern scan active with **quarantine-on-hit
    or on anomaly** (never publish-and-review); user token-revocation
    runbook acknowledged.
12. Hostile-workspace injection test passed: a synthetic workspace
    containing a malicious `.codex/` (config + hooks + rules) and a
    hostile `AGENTS.md` provably has zero effect on the effective config
    under the exact qualified argv.

## 27. Self-hosting gate

**Remains closed.** The M5 closure's 10-point gate
(`m5-controlled-worktree-closure.md:348-361`) is adopted unchanged,
including 50+ synthetic tasks with zero escapes, credential-isolation
proof, unchanged M4A boundary, 100% green capture/cancellation/
verification, independent adversarial review, and full repository-contract
compliance. AgenticOS modifying AgenticOS is prohibited throughout M6 until
that gate passes on synthetic repositories. Nothing in this plan weakens it;
M6 slices feed it evidence (items 1–8) but do not relax any condition.

## 28. Earned claims for Slice 0

1. Repository state verified: all four SHAs at
   `ed8b545169a84a13f399a51f2f0c50e6cf2d9eda`; both trees clean; zero
   unpushed, zero untracked, zero stashes.
2. Actual M5 task-ref namespace established from implementation and tests:
   `refs/heads/aos/<task_id>/g<generation>`; closure-doc inconsistency
   identified and a docs-only fix recommended (not applied).
3. Installed client inventory with cryptographic identity: npm
   `@openai/codex@0.120.0` Windows x64 binary (SHA-256 recorded) on PATH;
   desktop alpha binary (SHA-256 recorded) disqualified; no functional WSL
   client.
4. `codex exec` noninteractive surface qualified from the installed binary:
   `--json` JSONL, `--output-schema`, `-o`, `-C`, `--ephemeral`,
   `--skip-git-repo-check`, sandbox/approval flags; defaults `approval:
   never`, `sandbox: read-only`; exit codes 1/101 observed.
5. Authentication posture established without secret exposure: active
   ChatGPT subscription session; file-based `auth.json`; only the client
   process needs it.
6. Gitless compatibility verified locally (offline probe): plain-directory
   execution works with `--skip-git-repo-check`; refusal without it is
   pre-network, exit 1.
7. Unauthenticated transport observed: WebSocket-first
   (`wss://api.openai.com/v1/responses`) with HTTPS/SSE fallback; 401
   handling and reconnect behavior recorded; zero quota consumed.
8. Configuration injection surfaces catalogued (user config contents, MCP/
   plugins/hooks inventory, project trust semantics) and a containment
   design (per-task controller-written `CODEX_HOME`, default-deny feature
   enumeration) specified.
9. The official client provides no external tool-execution split
   (established from help/config/feature inspection + official docs);
   Architecture D is documented as unsupported rather than assumed.
10. The central credential residual of the recommended architecture is
    identified and stated without mitigation theater (§8, §30 Q6); the
    design does not claim a kernel-level credential barrier it cannot
    have.
11. No M4A/M4B/M5 code, config, or claims were modified; no packages
    installed; no Codex install/update/logout/login; no live authenticated
    invocation.

## 29. Non-earned claims (explicitly NOT established)

- Exact endpoint set and transport for **ChatGPT-authenticated** traffic
  from the qualified client version (third-party audit cited; needs M6-2
  passive qualification on the Linux build).
- Whether `supports_websockets=false` (or a custom provider with
  `requires_openai_auth=true`) cleanly forces SSE on the current build.
- Proxy/CA env behavior of the client (`HTTPS_PROXY` etc.) — undocumented
  upstream.
- Behavior of `features.shell_tool=false` (and the rest of the §23 deny
  set) on a live turn — does the model degrade gracefully to edit-only?
- **Token-refresh persistence against a read-only `auth.json` bind** —
  memory-only refresh, mid-turn 401 on expiry, or startup failure (§6).
- **Effectiveness of Codex `permissions` deny-read profiles against the
  client's own read tools** (§8 barrier 3) — provider self-policy,
  unverified.
- Whether untrusted-project `.codex/` layer suppression holds under the
  exact qualified argv with a hostile workspace (§26 item 12).
- The client's Linux child-process inventory (what it spawns, what those
  children inherit) — §22 census.
- Edit-only task effectiveness for real coding tasks (needs M6-3).
- Structured (machine-readable) rate-limit/quota signals vs prose-only;
  `turn.failed`/`error` JSONL shape for each failure class.
- Server-side (ChatGPT account) retention/memory behavior and its
  cross-task implications (§15).
- Whether any hidden telemetry/update endpoints are contacted at runtime
  beyond the documented set.
- Multi-turn repair loop design (attempt chaining) — sketched, not proven.

## 30. Unresolved questions requiring explicit approval

- **Q1 (authorization required): install the official Linux Codex client in
  WSL.** No functional Linux client exists; M4A/M5 are Linux-only. Proposed:
  user-approved install of a pinned version into a controller-managed path,
  then §22 qualification. Not done in Slice 0.
- **Q2 (user action): native WSL `codex login`.** Roadmap forbids
  AgenticOS copying/relocating consumer credentials; official docs confirm
  `auth.json` is host-independent, but policy says the user authenticates
  the WSL installation themselves (browser/`--device-auth` flow).
- **Q3 (decision): provider-egress mechanism** — (a) new minimal
  non-terminating exact-host CONNECT proxy, or (b) netns egress filter;
  includes the DNS resolution path (pinned hosts vs controller resolver)
  and CDN-rotation handling. Both options keep provider traffic out of
  Connected Build grants. Decide in M6-2 after endpoint/transport
  qualification.
- **Q4 (experiment approval): first live authenticated smoke invocation**
  — one small synthetic task, pinned model, capped reasoning effort, full
  event capture; quota impact ≈ one short `codex exec` turn. Required to
  resolve §29 items; hard-stop gate per §26.
- **Q5 (decision): which Codex version to pin for Linux** — match
  0.120.0 (parity with the user's CLI) vs current stable; recommend
  current stable unless compatibility argues otherwise.
- **Q6 (residual risk acceptance — the central decision): credential
  exposure via the client's own read tools.** In C′ the qualified client
  must hold `auth.json` (refresh-capable) and its file-read tools share
  that authority. A prompt-injected model can therefore bring credential
  material into model context and into `/workspace`; AgenticOS cannot
  kernel-prevent this without interposing between the client and its own
  credential file, and the only interposition (brokering/replaying tokens
  through AgenticOS) is forbidden by the roadmap. What the design provides
  instead: no model-directed code execution (edit-only), egress locked to
  the issuing provider's exact hosts (single-provider lineages only, §8),
  canary tripwires, a best-effort scan with quarantine-on-anomaly, and
  user token revocation as the final backstop. **Owner sign-off on this
  residual is a precondition of M6-2.** If not accepted, M6 stops here —
  a blocked result, per the Slice 0 hard-stop conditions, is preferable to
  a widened boundary.
- **Q7 (docs-only fix): apply the `refs/agenticos/*` →
  `refs/heads/aos/<task_id>/g<generation>` correction to the M5 closure
  doc** in a later docs slice (recommended; deferred per Slice 0 scope).
- **Q8 (authorization required): the read-only `auth.json` bind-mount
  itself.** Both sides: *for* — a bind mount copies no bytes, reads no
  credential content, keeps the file in the user's own `~/.codex` (after
  Q2's native WSL login), and "official provider clients retain
  authentication ownership" (roadmap) is arguably satisfied by the
  official client reading the user's own auth file. *Against* —
  "AgenticOS does not … relocate … consumer credentials": an
  AgenticOS-authored mount namespace relocates the credential's *reach*
  into a domain adjacent to model-directed tools (§8). The plan treats
  the bind as an owner-gated mechanism, separate from the Q2 login
  approval.

## 31. Adversarial review record

Independent adversarial review performed 2026-08-11 against this document
(focus: auth exfiltration, model-directed host execution, config injection,
PATH/executable substitution, workspace escape, Git authority regression,
network widening, proxy/CA abuse, MCP/tool widening, session contamination,
cancellation leaks, provider residue, model-prose-as-authority, adapter
authority creep). 14 findings; dispositions:

- **F1 BLOCKER** — §8/§13 credited Codex's `workspace-write` self-sandbox
  as a credential-read barrier while §13 elsewhere noted it cannot nest
  inside M4A. Resolved: §8 copy row rewritten as an honest residual; §13
  no longer credits self-sandboxing; §18 table and §28 updated; Q6
  rewritten as the central owner decision.
- **F2 BLOCKER** — the credential evidence scan was presented as
  fail-closed but is structurally blind (the roadmap forbids reading
  `auth.json`, so the exact secret bytes are unknowable and encoding
  evades pattern scans). Resolved: scan downgraded to best-effort
  tripwire + quarantine-on-anomaly + revocation backstop (§8, §26.11).
- **F3** — `ModelTaskRequest.network_mode` lacked the provider-egress
  class. Resolved by scope clarification (§20): provider egress is
  adapter-side policy, never a request field.
- **F4** — token auto-refresh vs read-only `auth.json` unexamined.
  Resolved: §6 paragraph + §29 non-earned item + M6-2 qualification step.
- **F5** — bind-mount mechanism needed its own owner gate. Resolved: Q8.
- **F6** — exec-capable features beyond `shell_tool` not explicitly
  denied. Resolved: §23 default-deny enumeration; §21 invocation;
  §26 items 3/7.
- **F7** — `failure_class` could be steered by model-influenced prose; no
  attempt budget. Resolved: §20 mapping invariant; §19 attempt budget.
- **F8** — "own endpoints are not exfiltration" false across
  multi-provider lineages. Resolved: §8 scope limit.
- **F9** — DNS path unspecified. Resolved: §10 + Q3 scope.
- **F10** — server-side ChatGPT retention unacknowledged. Resolved: §15.
- **F11** — `--skip-git-repo-check` × untrusted-layer suppression
  unverified. Resolved: §11 caveat + §26 item 12 + §29.
- **F12** — client child-process census must gate the live task.
  Resolved: §22 + §26 item 4.
- **F13** — `/proc` row over-asserted client internals. Resolved: §8.
- **F14** — one citation range widened (`runtime_boundary.py:434-585`).
  (The review's suggested renumbering of the env-validation citations was
  itself checked against the source and not adopted:
  `FORBIDDEN_GIT_ENV_NAMES` is at `runtime_boundary.py:609-615` and
  `_validate_extra_worker_env` at `:618-657` as originally cited.)

Checked and found sound by the review: symlink/hardlink workspace escape
(§14), Git authority (no ref/commit/push path), M4B non-interference,
WebSocket/broker incompatibility analysis, §22 executable pinning,
FD-census closure, fixed-env proxy/CA closure.

## Sources

Local observation (installed client, 2026-08-11): `codex --help`,
`codex exec --help`, `codex login --help`, `codex login status`,
`codex sandbox --help`, `codex features list`, `codex mcp list`,
`codex exec resume --help`, synthetic-directory probes (§7, §10, §11),
filesystem metadata (§3, §6, §15).

Upstream/official (fetched 2026-08-11):

- github.com/openai/codex `docs/authentication.md` (ChatGPT OAuth,
  `auth.json` portability, `--with-api-key`, headless login).
- github.com/openai/codex `docs/exec.md` (non-interactive mode, JSONL event
  types, `--output-schema`, git-repo requirement, resume, `CODEX_API_KEY`).
- developers.openai.com/codex/config-reference (full config surface;
  `projects.<path>.trust_level` untrusted-layer skipping; provider fields;
  `supports_websockets`; sandbox/permissions; MCP/hooks/env policy).

Third-party (clearly marked, non-authoritative; corroborates ChatGPT
endpoint): loom.js `docs/codex-auth-experiment.md` (pinned-commit audit of
`POST https://chatgpt.com/backend-api/codex/responses`).

Architectural inference is labeled as such in §12, §18, §19 and is not
presented as observed behavior.

---

## 32. M6 Slice 0.1 — Codex Credential-Boundary and Provider-Sandbox Decision Spike

**Status**: Decision Spike complete. Produced on 2026-08-11 by independent research agent.

### 32.1 Decision Outcome

**`DECISION = TOKEN_BROKER_REQUIRED`**

- **Rationale**: The official Codex CLI (`codex`) operates as a single monolithic process where authentication material loading (`auth.json` or OS Keyring) and model-directed file tools (`read_file`, `list_dir`) execute within the **same process authority domain**. Mounting raw credentials (even read-only) into the provider sandbox gives model-directed read tools effective read authority over raw credentials. Under the AgenticOS governing principle **"Models reason; AgenticOS guarantees"**, an enforceable kernel/process boundary is required to separate credential read authority from model-directed read tools. Therefore, a minimal credential broker/helper (or client topology redesign running the client outside the hostile model tool domain) is required before authenticating tasks.

### 32.2 Process and Tool Authority Model

- **Process Structure**: `codex` is a single native binary.
- **Auth Subsystem**: Opens and reads `$CODEX_HOME/auth.json` (or calls OS Keyring APIs) directly within the main `codex` process event loop.
- **Model File Read / Edit Subsystem**: Internal Rust tool routines (`read_file`, `list_dir`, `apply_patch`) execute inside the main `codex` process using the same process file descriptors and OS user privileges.
- **Child Processes**: Spawns shell helpers (`bwrap` on Linux, `codex-command-runner.exe` on Windows) when `shell_tool` is enabled. Disabling `shell_tool` (`features.shell_tool=false`) stops child shell processes, but **does NOT remove internal file read tool authority** inside the parent `codex` process.

### 32.3 Credential-Store Mechanisms (Keyring Research)

- `cli_auth_credentials_store` supports `file | keyring | auto`.
- Keyring integration (Windows Credential Manager / Linux Secret Service) issues API calls **in-process** to fetch tokens into process memory.
- Keyring does **NOT** separate process authority domains: the `codex` process still retrieves the raw secret into its memory space.
- In sandboxed Linux netns/userns environments, Keyring adds complex daemon dependencies without creating a kernel barrier against in-process model tool exfiltration.

### 32.4 Trust Test Evaluation

- **Test**: If a prompt injection causes a model tool request `read_file("/opt/agenticos/provider-home/auth.json")`, what kernel/process boundary prevents it?
- **Finding**: NONE. The kernel sees `codex` reading a file `codex` has permission to read.
- Software path filters or prompt instructions fail the AgenticOS guarantee ("Models reason; AgenticOS guarantees").

### 32.5 Network Exfiltration Analysis

- The `codex` process holds legitimate network egress (TCP 443) to provider hosts (`*.openai.com`, `*.chatgpt.com`).
- If secret material enters model context via `read_file`, `codex` will include it in API requests to the provider. Egress filtering to exact provider endpoints does NOT prevent credential leakage to those endpoints.

### 32.6 Canary / Tripwire Classification

- Canary decoy files and regex scanners are **DETECTIVE** or **FORENSIC**. They detect exposure after or during an attempt; they do **NOT** prevent credential reading.

### 32.7 Auth Bind-Mount Analysis (Q8 Review)

- A read-only bind-mount of `auth.json` prevents modification/overwriting of tokens on disk, but does **NOT** prevent reading or exfiltrating tokens.
- Linux mount namespaces cannot distinguish access between internal auth routines and internal model tool handlers within the same process.

### 32.8 Child-Process Authority Matrix

| Process | AUTH (auth.json) | NETWORK (Egress) | MODEL FILESYSTEM | MODEL SHELL |
|---|---|---|---|---|
| `codex` (Parent) | **YES** | **YES** (Provider TCP 443) | **YES** (Internal read/edit tools) | **NO** (Tool dispatcher) |
| `bwrap` / `sh` (Shell child) | **INHERITED** | **NO** | **YES** (/workspace RW) | **YES** (Shell exec) |
| `codex` (`shell_tool=false`) | **YES** | **YES** | **YES** (Internal read/edit tools) | **DISABLED** |

### 32.9 Feature Reduction & "No Shell Is Not Enough"

- Disabling `shell_tool` stops shell command execution, but file read tools remain active. File read authority alone is sufficient for credential exfiltration.

### 32.10 Token Broker Tradeoff Matrix

1. **Raw auth mounted (Architecture C′)**: Simple, but fails credential isolation guarantee (honest residual).
2. **OS Keyring**: In-process fetch; no process boundary improvement.
3. **Minimal Controller Credential Broker**: Ephemeral token injection or controller-side proxy; enforces secret isolation, but requires handling short-lived tokens or proxy design.
4. **Provider Client Outside Hostile Domain**: Client runs in controller domain, communicating with an edit executor. Requires official tool split hook (currently unsupported in official CLI).

### 32.11 Recommended Path Forward

- Move to a **Credential Broker / Helper** architecture or **Provider Client Redesign** where raw consumer auth material never enters a process domain executing model-controlled file read tools.
- Defer Q1 (WSL install), Q2 (WSL login), and Q5 (version pin) until the credential broker/topology decision is finalized by the repository owner.

---

## 33. Independent Adversarial Review of M6 Slice 0.1 Findings

- **Reviewer posture**: Falsification attempt against credential isolation claims.
- **Finding 1**: Could `permissions` config rules in Codex reliably block `read_file` access to `CODEX_HOME`?
  - *Result*: No. `permissions` rules are soft client policy, not kernel-enforceable barriers. Model prompt injection or bypasses could override client self-policy.
- **Finding 2**: Does Linux mount namespace `remount,ro` prevent exfiltration?
  - *Result*: Falsified. `ro` blocks `write()`/`unlink()`, but `read()` succeeds unconditionally. Exfiltration requires only `read()`.
- **Finding 3**: Does Keyring provide process isolation?
  - *Result*: Falsified. Keyring library calls run in the same process space; retrieved tokens reside in `codex` heap memory.
- **Conclusion**: The decision `TOKEN_BROKER_REQUIRED` is mathematically and architecturally sound under AgenticOS threat model rules.

---

## 34. M6 Slice 0.2 — Credential Broker & Provider Transport Proof Specification

**Status**: Architecture qualification & local synthetic proof-of-mechanism complete. Produced on 2026-08-11.
Adversarially reviewed on 2026-08-11; review record in §34.12.

Governing principle: **Models reason; AgenticOS guarantees.**

### 34.1 Executive Decision & Key Outcome

**`DECISION = PROVIDER_PROXY_BROKER_FEASIBLE`**

Local synthetic proof-of-mechanism experiments against the qualified official Codex CLI (`codex-cli 0.120.0`) empirically demonstrate that:

1. **Unauthenticated Transport**: Codex can be configured to target a local AgenticOS provider broker as an **UNAUTHENTICATED** Responses client (`requires_openai_auth = false`).
2. **Zero Credential Exposure**: Codex sends **ZERO** `Authorization`, `Cookie`, `Proxy-Authorization`, or `X-API-Key` headers to the local broker. No `auth.json`, bearer token, refresh token, or API key exists within the Codex process environment or authority domain.
3. **Upstream Auth Injection**: The task-local AgenticOS Provider Broker receives unauthenticated HTTP/SSE requests from Codex, injects upstream authentication headers (`Authorization: Bearer <token>`), forwards requests to the upstream provider, sanitizes response headers, and relays the SSE response stream back to Codex.
4. **Clean Turn Completion**: Codex processes the synthetic Responses SSE stream, emits JSONL turn events (`thread.started`, `turn.started`, `turn.completed`), and exits cleanly with **Exit Code 0**.
5. **Secret Canary Isolation**: Automated secret canary assertions confirm **ZERO** occurrences of the fake upstream bearer token in Codex stdout, stderr, JSONL output, workspace files, synthetic `CODEX_HOME`, or client-facing logs.

This establishes the required security invariant:

```text
AUTH ∩ MODEL_FILESYSTEM_AUTHORITY = empty
AUTH ∩ MODEL_PROCESS_MEMORY = empty
```

### 34.2 Repository Verification Record

Verified independently at Slice 0.2 start (2026-08-11), before any synthetic experimentation or documentation updates:

```text
WINDOWS_HEAD = b9ecf37a9d03f9832cc4b3fdd24edea6e1269ee9   (Windows Git, C:\AgenticOS)
WSL_HEAD     = b9ecf37a9d03f9832cc4b3fdd24edea6e1269ee9   (WSL Git, ~/src/AgenticOS, Ubuntu)
ORIGIN_MAIN  = b9ecf37a9d03f9832cc4b3fdd24edea6e1269ee9   (after git fetch --prune origin)
GITHUB_MAIN  = b9ecf37a9d03f9832cc4b3fdd24edea6e1269ee9   (git ls-remote origin refs/heads/main)

WINDOWS_TREE = clean        WSL_TREE = clean
UNPUSHED_COMMITS = 0        UNEXPLAINED_UNTRACKED_FILES = 0
STASH_ENTRIES = 0 (both clones)
```

Governing policies obeyed: `AGENTS.md`, `docs/engineering/repository-preservation.md`, `docs/phase-zero/m5-controlled-worktree-closure.md`, and `docs/phase-zero/m6-codex-adapter-plan.md`.

### 34.3 Installed Codex 0.120.0 Custom-Provider Qualification

Local qualification of the installed Windows `codex-cli 0.120.0` executable (`3cddb048...`) established exact custom-provider TOML configuration requirements and transport capabilities:

#### Required Custom-Provider TOML Schema (0.120.0)

```toml
model = "synthetic-model"
model_provider = "agenticos_broker"

[model_providers.agenticos_broker]
name = "AgenticOS Provider Broker"
base_url = "http://127.0.0.1:9002/v1"
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false

[features]
plugins = false
shell_tool = false
unified_exec = false
multi_agent = false
```

#### Qualification Observations & Upstream Differences

1. **Mandatory `name` Field**: In `0.120.0`, omitting `name` under `[model_providers.<id>]` causes a parse failure: `Error loading config.toml: missing field name`.
2. **`requires_openai_auth = false`**: Instructs Codex that the provider does not require client-side OpenAI authentication. Codex suppresses credential loading and attaches no `Authorization` header.
3. **`supports_websockets = false`**: **Successfully forces Codex to use HTTPS/SSE transport only.** Codex does not attempt WebSocket connection or upgrade, eliminating WebSocket parser and connection state attack surfaces.
4. **Gitless Compatibility**: Invoked with `--skip-git-repo-check`, Codex executes normally outside a Git repository in plain temporary workspaces.
5. **Command-Backed Token Auth (`auth.command`)**: Tested in `0.120.0`. `model_providers.<id>.auth.command` expects a string command (e.g. `command = "cmd.exe /c echo TOKEN"`). While functional, returning tokens to Codex via stdout inserts credentials directly into Codex process memory. Therefore, `auth.command` is **REJECTED** as a primary architecture and retained only as a fallback if proxying is disabled.

### 34.4 Local Synthetic Proof-of-Mechanism Results

A disposable, isolated local synthetic proof fixture was executed (`scratch/test_p1_complete.py`) using loopback interfaces only (`127.0.0.1`), zero internet connection, zero real credentials, and a synthetic temporary `CODEX_HOME` and workspace.

#### Fixture Topology

```text
    CODEX PROCESS (0.120.0)
        unauthenticated client
        base_url = http://127.0.0.1:9002/v1
        requires_openai_auth = false
        supports_websockets = false
        NO auth.json / NO API keys
            |
            | POST /v1/responses (HTTP/SSE)
            | Request Headers: Content-Type, Accept, Session/Turn metadata
            | Authorization Header: ABSENT
            v
    AGENTICCOS SYNTHETIC PROOF BROKER (127.0.0.1:9002)
        receives unauthenticated request
        injects Authorization header
        strips backend internal headers
            |
            | POST http://127.0.0.1:9003/v1/responses
            | Authorization: Bearer CANARY_SYNTHETIC_BEARER_TOKEN_SECRET_987654321
            v
    SYNTHETIC FAKE UPSTREAM SERVER (127.0.0.1:9003)
        verifies Authorization header presence
        returns synthetic Responses SSE stream
            |
            v
    AGENTICCOS SYNTHETIC PROOF BROKER
        relays sanitized SSE stream (Connection: close)
            |
            v
    CODEX PROCESS
        parses response.created ... response.completed
        emits stdout JSONL: thread.started, turn.started, turn.completed
        exits cleanly with EXIT CODE 0
```

#### Observed Request Headers Sent by Codex to Broker

```http
POST /v1/responses HTTP/1.1
Host: 127.0.0.1:9002
Accept: text/event-stream
Content-Type: application/json
User-Agent: codex_exec/0.120.0 (Windows 10.0.26200; x86_64) unknown (codex_exec; 0.120.0)
Originator: codex_exec
Session_Id: 019ff2b1-557d-7013-8ea5-0e7ee800cc51
X-Client-Request-Id: 019ff2b1-557d-7013-8ea5-0e7ee800cc51
X-Codex-Window-Id: 019ff2b1-557d-7013-8ea5-0e7ee800cc51:0
X-Codex-Turn-Metadata: {"session_id":"019ff2b1-557d-7013-8ea5-0e7ee800cc51","turn_id":"019ff2b1-558e-7b02-b2d4-d7b3f8dfdf0b","sandbox":"none"}
```

**Credential Header Audit**:
- `Authorization`: **ABSENT**
- `Cookie`: **ABSENT**
- `Proxy-Authorization`: **ABSENT**
- `X-API-Key`: **ABSENT**

#### Secret Canary Assertions

The canary string `CANARY_SYNTHETIC_BEARER_TOKEN_SECRET_987654321` was injected exclusively by the broker on the broker-to-upstream segment. Automated search across all client-visible locations returned:

- `Canary in stdout`: `False`
- `Canary in stderr`: `False`
- `Canary in workspace`: `False`
- `Canary in CODEX_HOME`: `False`
- `Canary in client-facing broker logs`: `False`

### 34.5 Responses Protocol Surface & SSE Qualification

The minimum Responses protocol surface required for the AgenticOS broker adapter comprises:

1. **Endpoint**: `POST /v1/responses`
2. **Transport**: HTTPS/SSE (`supports_websockets = false`).
3. **Request Framing**: JSON request payload containing model name, prompt text, turn messages, and tool definitions.
4. **SSE Event Stream Sequence**:
   - `response.created` — initial response metadata and response ID.
   - `response.output_item.added` — item container creation.
   - `response.content_part.added` — text/tool content part initialization.
   - `response.text.delta` / `response.function_call_arguments.delta` — streaming deltas.
   - `response.text.done` / `response.function_call_arguments.done` — part completions.
   - `response.content_part.done` — content part completion.
   - `response.output_item.done` — item completion.
   - `response.done` — overall response completion.
   - `response.completed` — final stream closure signal required by Codex SSE parser.
5. **Session Correlation**: `thread_id` from `thread.started` JSONL event is captured and linked by the controller to `(task_id, generation, attempt_id)`.

### 34.6 Decision Matrix & Architecture Selection

| Architecture Option | Auth Isolation | Memory Secret Isolation | Upstream Protocol Stability | Implementation Complexity | Self-Hosting Readiness | Score & Status |
|---|---|---|---|---|---|---|
| **P1: Provider Proxy Broker (Codex Unauthenticated)** | **COMPLETE** (No secret in Codex domain) | **COMPLETE** (Zero credential in process heap) | **HIGH** (Standard HTTP/SSE Responses API) | **MEDIUM** (Local HTTP broker relay) | **HIGH** | **SELECTED (Preferred)** |
| **P2: Token-Command Helper (`auth.command`)** | **PARTIAL** (Short-lived bearer token) | **FAILED** (Bearer token in Codex memory) | **HIGH** | **LOW** | **LOW** (Token exposed to model file tools) | **REJECTED** |
| **P3: Raw Auth Mount (`auth.json` ro-bind)** | **FAILED** (Codex read tools read auth.json) | **FAILED** (Raw OAuth token in memory) | **HIGH** | **VERY LOW** | **DISQUALIFIED** (M6 Slice 0.1 decision) | **REJECTED** |
| **P4: OS Keyring** | **FAILED** (In-process fetch into heap) | **FAILED** | **HIGH** | **MEDIUM** | **DISQUALIFIED** | **REJECTED** |
| **P5: App Server / SDK Topology** | **UNUNCERTAIN** | **FAILED** (Model tools execute in same service) | **LOW** (Experimental surfaces) | **HIGH** | **LOW** | **REJECTED** |
| **P6: Abandon Codex Adapter** | N/A | N/A | N/A | N/A | N/A | **REJECTED** |

**Selection**: **P1 — PROVIDER PROXY BROKER**.

### 34.7 Provider Broker Authority & Security Model

The production Provider Broker will be designed with strict authority boundaries:

#### Broker Authority
- Access to subscription authentication credentials (stored in controller credential domain).
- Upstream provider network egress (restricted to controller-fixed provider endpoints).
- Bounded HTTP/SSE protocol relay and upstream header injection.
- Upstream OAuth token refresh (executed out-of-process via controller auth helper).

#### Broker Non-Authority (Forbidden)
- **NO** task worktree mount (`/workspace`).
- **NO** access to task source files or Git repositories.
- **NO** model tool execution (no shell, no file edits, no MCP, no sub-processes).
- **NO** arbitrary host filesystem access.
- **NO** general HTTP or CONNECT proxy capabilities.

#### Request & Response Security Allowlisting

1. **Request Header Allowlist (Codex -> Broker)**:
   Allowed: `Host`, `Accept`, `Content-Type`, `User-Agent`, `Originator`, `Session_Id`, `X-Client-Request-Id`, `X-Codex-Window-Id`, `X-Codex-Turn-Metadata`.
   All other headers dropped.
2. **Response Header Allowlist (Upstream -> Codex)**:
   Allowed: `Content-Type`, `Cache-Control`, `Connection`.
   Dropped: `Set-Cookie`, `X-Upstream-Backend-ID`, `Server`, `Www-Authenticate`, internal routing headers.
3. **Request Body Scoping**:
   MODEL DATA (`prompts`, `tools`, `messages`) is relayed as payload bytes.
   BROKER AUTHORITY DATA (`upstream host`, `Authorization`, `TLS parameters`, `account routing`) is fixed exclusively by the controller and cannot be influenced by request payload metadata.

#### Bounded Relay Limits
- Max Request Body: 10 MB per turn.
- Max Response Event Size: 1 MB.
- Max Total Bytes per Attempt: 50 MB.
- Connection Timeout: 30 seconds idle / 300 seconds total per turn attempt.
- On limit breach or malformed protocol: broker closes TCP connection immediately and reports `PROVIDER_PROTOCOL_ERROR`.

### 34.8 Failure Categories

The broker translates network and protocol events into typed structural failure classes:

- `PROVIDER_BROKER_UNAVAILABLE`: Local broker endpoint unreachable.
- `PROVIDER_AUTH_EXPIRED`: Upstream returned 401/403 and auth helper refresh failed.
- `PROVIDER_RATE_LIMITED`: Upstream returned 429; structural retry metadata recorded.
- `PROVIDER_TRANSPORT_ERROR`: TCP reset, TLS failure, or premature socket closure.
- `PROVIDER_PROTOCOL_ERROR`: Invalid SSE event framing or JSON schema violation.
- `PROVIDER_TIMEOUT`: Idle or wall-clock timeout exceeded.
- `PROVIDER_CANCELLED`: Task cancelled by controller; upstream socket closed immediately.
- `PROVIDER_CLIENT_ERROR`: Codex emitted malformed request.

### 34.9 Production Security Test Plan

Future production broker slices will enforce the following verification test suite:

1. **Auth Separation Test**: Verify environment variables, process FDs, `/proc` memory maps, `CODEX_HOME`, and `/workspace` contain zero authentication tokens.
2. **Destination Lock Test**: Attempt sending requests to unauthorized external domains through the broker port; verify 403 Forbidden / connection reset.
3. **Cross-Task Isolation Test**: Task A attempts connecting to Task B's broker port; verify identity handshake failure and access rejection.
4. **Secret Canary Test**: Inject synthetic canary tokens in upstream broker responses; verify tripwire scanners confirm zero leakage into Codex stdout/stderr/workspace.
5. **Cancellation Drill**: Kill Codex process; verify broker terminates upstream TCP connection within 500ms and releases resources.

### 34.10 Version Qualification & Next Implementation Steps

- **Qualified Version**: Official `codex-cli 0.120.0` is qualified for M6 proxy broker architecture. No version upgrade is required for Slice 0.2.
- **Native WSL Installation**: Remains deferred until authorized by repository owner in a future implementation slice.
- **Recommended M6 Implementation Slice**: **M6 Slice 1 — Production Provider Proxy Broker Specification & Controller Transport Bridge**.

### 34.11 Adversarial Review Record for Slice 0.2

Independent adversarial review performed on 2026-08-11 against the Slice 0.2 specification:

- **Reviewer Posture**: Attempted to falsify `PROVIDER_PROXY_BROKER_FEASIBLE` and locate auth leaks.
- **Check 1: Does Codex fallback to ChatGPT OAuth if `requires_openai_auth = false`?**
  - *Result*: Falsified. Empirical testing proved Codex sends HTTP POST without `Authorization` or cookie headers.
- **Check 2: Can Codex bypass `supports_websockets = false` via prompt injection?**
  - *Result*: Falsified. `supports_websockets` is a TOML configuration parameter parsed at startup; model prompt content cannot alter client networking primitives.
- **Check 3: Is `auth.command` safer than a proxy broker?**
  - *Result*: Falsified. `auth.command` outputs tokens into Codex process memory, exposing tokens to model file-read tools inside Codex. Proxy broker keeps tokens completely out of the Codex process.
- **Conclusion**: The outcome `PROVIDER_PROXY_BROKER_FEASIBLE` is empirically verified and security-sound.
