# First Autonomous Build Slice F1 — Kimi Provider Selection

Status: `ADMISSIBLE_IN_PRINCIPLE` for one tool-free `PLANNER` role only.
Kimi is not admitted for execution, login, or any workspace-mutating role by
this checkpoint.

## Authorization and hard stop

This checkpoint performs only the authorized F1 provider-selection work:
repository orientation, official-source research, passive architecture
qualification, exact boundary design, and an adversarially reviewable test
plan. It does not install or upgrade Kimi Code CLI, perform login or OAuth,
read or create credentials, use an API key, send a prompt, contact a model,
consume a subscription, edit a workspace through Kimi, or begin F2, G2, or G1.

The verified common Windows, WSL, fetched `origin/main`, and live GitHub
starting baseline was:

```text
87e583f515f914fbf8149cc14f9eea1c7565bd26
```

Both authoritative clones were clean at divergence `0/0`, both stash lists
were empty, and no residual `aos-task-*` scope, cgroup, or process existed.

## Decision

Kimi Code CLI is selected as the first provider candidate, subject to an exact
pinned-artifact installation and passive host-qualification gate. Its first
eligible role is `PLANNER`: bounded research synthesis and plan proposal from
controller-supplied context, with an empty model-callable tool surface and no
project checkout mounted into the provider-client domain.

This is an architectural selection, not runtime admission. The first real
request remains forbidden until later gates establish the executable facts and
the owner separately authorizes and completes a subscription OAuth ceremony.

The selection rejects Kimi as a `BUILDER` at the researched version. When the
ACP client advertises the matching filesystem capabilities, the official ACP
adapter routes text reads and writes through ACP, but delegates
path metadata, directory iteration, globbing, directory creation, binary reads,
and command execution to the local process. ACP terminal callbacks are not
connected and shell commands execute locally. Configuration-level tool denial
does not turn those local implementation paths into a kernel security boundary.

```text
F1_KIMI_SELECTION_STATUS=ADMISSIBLE_IN_PRINCIPLE
FIRST_ROLE=PLANNER
KIMI_BUILDER_ADMISSION=BLOCKED
REAL_PROVIDER_EXECUTION=NO
```

## Official-source facts and pinned research reference

The research reference is the official `@moonshot-ai/kimi-code@0.36.1`
release, published 2026-08-14. Its package declares Node.js `>=22.19`, the ACP
adapter package is version `0.3.9`, and that adapter depends on
`@agentclientprotocol/sdk` `^0.23.0`. ACP uses stable wire
`protocolVersion: 1`. The next gate must replace these source facts with the
exact installed Linux artifact, its complete provenance, and a cryptographic
digest; no package or asset has been downloaded here.

References explicitly labeled `0.36.1` below are tag-pinned; the remaining Kimi
documentation links are live official documentation observed on 2026-08-14.
The next gate must capture and hash the exact release source/documentation used
for every load-bearing config, auth, storage, update, and network claim; a
mismatch blocks qualification.

The current official Kimi ACP reference documents JSON-RPC over stdio, with
initialization first; authentication and session create/prompt/cancel methods;
client-side session updates, permission requests, and text file read/write; no
connected terminal reverse-RPC methods; unsupported session close and logout;
and arbitrary MCP HTTP, stdio, or SSE servers at session creation.

Therefore the admitted profile must use one top-level launch/containment scope
and one new session per attempt, send `mcpServers: []`, refuse load/resume/list,
and make every tool,
filesystem, permission, terminal, MCP, plugin, skill, cron, background-agent,
and web interaction a policy violation.

Official configuration documentation establishes that `KIMI_CODE_HOME`
relocates Kimi configuration and most data; project-local
`.kimi-code/local.toml` is otherwise read; credentials, sessions, logs, managed
binaries, plugins, skills, history, and update state can persist; and generic
`.agents` state remains relative to the ordinary home directory. It also
documents tool allow/deny configuration, `KIMI_CODE_NO_AUTO_UPDATE=1`,
`KIMI_DISABLE_TELEMETRY=1`, `KIMI_DISABLE_CRON=1`, API-key/provider override
channels under `KIMI_MODEL_*`, and standard proxy variables.

Under that root, the documented paths include `config.toml`, `tui.toml`,
`credentials/`, `sessions/`, `session_index.jsonl`, managed tools, plugins,
skills, logs, and update state. Credential directories/files use modes
`0700`/`0600` and updates use an atomic temporary-file, fsync, rename flow;
normal managed-provider operation may therefore require credential-directory
writes for refresh. Session `wire.jsonl` data contains the conversation and a
request trace, including tool schemas and request parameters, so it is treated
as task-sensitive ephemeral material rather than harmless diagnostics.

The official login command uses OAuth 2.0 device authorization: it prints a
verification URL and user code, polls, and writes managed credentials. Kimi's
managed subscription endpoint defaults to `https://api.kimi.com/coding/v1` and
the OAuth host to `https://auth.kimi.com`. These are candidate host facts, not
an approved allowlist; passive and later authorized active census must prove
the exact endpoint set for the pinned artifact.

Primary references:

- [Kimi ACP reference](https://www.kimi.com/code/docs/en/kimi-code-cli/reference/kimi-acp)
- [Kimi Code CLI 0.36.1 release](https://github.com/MoonshotAI/kimi-code/releases/tag/@moonshot-ai/kimi-code@0.36.1)
- [0.36.1 CLI package manifest](https://raw.githubusercontent.com/MoonshotAI/kimi-code/%40moonshot-ai%2Fkimi-code%400.36.1/apps/kimi-code/package.json)
- [0.36.1 ACP adapter manifest](https://raw.githubusercontent.com/MoonshotAI/kimi-code/%40moonshot-ai%2Fkimi-code%400.36.1/packages/acp-adapter/package.json)
- [0.36.1 ACP filesystem/process adapter](https://github.com/MoonshotAI/kimi-code/blob/%40moonshot-ai/kimi-code%400.36.1/packages/acp-adapter/src/kaos-acp.ts)
- [0.36.1 configuration reference](https://github.com/MoonshotAI/kimi-code/blob/%40moonshot-ai%2Fkimi-code%400.36.1/docs/en/configuration/config-files.md)
- [0.36.1 environment reference](https://github.com/MoonshotAI/kimi-code/blob/%40moonshot-ai%2Fkimi-code%400.36.1/docs/en/configuration/env-vars.md)
- [0.36.1 data-location reference](https://github.com/MoonshotAI/kimi-code/blob/%40moonshot-ai%2Fkimi-code%400.36.1/docs/en/configuration/data-locations.md)
- [0.36.1 agent/profile reference](https://github.com/MoonshotAI/kimi-code/blob/%40moonshot-ai/kimi-code%400.36.1/docs/en/customization/agents.md)
- [Official Kimi ACP provider-error report](https://github.com/MoonshotAI/kimi-code/issues/1813)
- [ACP protocol repository](https://github.com/agentclientprotocol/agent-client-protocol)
- [Kimi configuration files](https://www.kimi.com/code/docs/en/kimi-code-cli/configuration/config-files)
- [Kimi data locations](https://www.kimi.com/code/docs/en/kimi-code-cli/configuration/data-locations)
- [Kimi environment variables](https://www.kimi.com/code/docs/en/kimi-code-cli/configuration/env-vars)
- [Kimi command reference](https://www.kimi.com/code/docs/en/kimi-code-cli/reference/kimi-command)
- [Kimi provider configuration](https://www.kimi.com/code/docs/en/kimi-code-cli/configuration/providers)
- [Kimi tool reference at 0.36.1](https://github.com/MoonshotAI/kimi-code/blob/%40moonshot-ai/kimi-code%400.36.1/docs/en/reference/tools.md)
- [Kimi agent/profile reference](https://www.kimi.com/code/docs/en/kimi-code-cli/customization/agents)

## Alternatives considered

1. **Kimi Builder over ACP now — rejected.** Local filesystem/process bypasses
   prevent the current ACP layer from being a complete mediation boundary.
2. **Tool-free Kimi Planner over ACP — selected in principle.** It can satisfy
   Demo 1's need for one real provider to perform bounded research/planning
   while keeping the checkout and mutation authority outside its domain.
3. **Kimi print mode — rejected.** It provides a weaker explicit session,
   cancellation, message-validation, and callback-denial surface than ACP.

The `PLANNER` choice is intentionally narrow. It does not assert that Kimi is a
general-purpose AgenticOS provider or that ACP is itself a sandbox.

## Exact provider-client and credential boundary

The provider adapter is a controller-owned translator around a dedicated,
kernel-confined provider-client sidecar. It is not an M4A hostile worker and it
must not share a process, home, credentials, network namespace, mount namespace,
or containment scope with a builder/reviewer worker.

Only controller-selected, digest- and size-bound context bytes enter the Kimi
domain and service; the checkout itself is never mounted. That deliberate
confidentiality exposure is bounded but not eliminated.

The selected boundary has four domains:

1. **Controller.** Owns board authority, dispatch identity, context selection,
   budgets, ABI validation, result admission, retry classification,
   cancellation, evidence, and final state changes. It never reads credential
   contents.
2. **Adapter.** Owns ACP framing, bounded request correlation,
   Kimi-session-to-dispatch mapping, limits, and `AOSAGENT/1` conversion.
   Provider bytes are always untrusted.
3. **Provider client/auth.** Runs one pinned top-level Kimi launch and
   containment scope for one attempt. It
   may hold and refresh its managed OAuth token because the supported client
   requires that; the exact client is part of the trusted computing base. It
   receives no project checkout and no model-callable tool/subprocess authority.
4. **Egress mediator.** Owns the only network route. The client has no direct
   route or DNS and receives only an identity-bound local proxy/listener. Every
   connection is correlated to the dispatch using content-free evidence.

This design does not claim the OAuth token can be kept out of Kimi process
memory. It keeps that trusted credential-holding process out of every hostile,
model-controlled execution domain. If policy later requires out-of-process
token custody, Kimi is blocked until an official supported broker interface is
qualified; TLS interception or undocumented credential injection is not an
acceptable substitute.

### Filesystem and state layout

The provider client receives a sterile synthetic `HOME` and task-scoped
`KIMI_CODE_HOME`, never the owner's normal Kimi directories. The root contains
immutable controller-generated config, a narrowly writable managed OAuth
credential directory only after a separate owner-login gate, quota-bounded
per-attempt session/log directories on private ephemeral storage, and an empty
synthetic `/workspace`. Ephemeral state is unmounted after evidence collection
and cannot be reused by a later dispatch. The root contains
no `.git`, project config, `AGENTS.md`, source, controller state, evidence,
`mcp.json`, skills, plugins, hooks, shell startup state, or generic `.agents`.

The mount/state contract is:

| State | Visibility and lifetime | Access |
| --- | --- | --- |
| pinned executable/dependencies | immutable provider store, common only by exact digest | read/execute |
| `config.toml`, `tui.toml`, main-agent file | immutable per-version profile, re-hashed before launch | read-only |
| `credentials/` | dedicated owner-login volume, shared only across this provider identity | client read/write for documented atomic refresh; controller metadata-only |
| `sessions/`, `session_index.jsonl`, `logs/`, `user-history/`, `updates/` | fresh private tmpfs for one attempt, destroyed after bounded redacted evidence extraction | client read/write |
| `bin/`, plugins, skills, agents, MCP, hooks | absent; managed download/install paths denied | none |
| synthetic `/workspace` and temporary files | fresh private tmpfs for one attempt | client only, no project bytes |

Every mount source and target is resolved before launch; symlinks, hard links,
binds crossing these rows, device files, and credential-directory traversal are
rejected. The credential volume is never a writable parent of config or
ephemeral state. After recursive process drain, evidence extraction is
content-bounded and secret-scanned, all ephemeral mounts are destroyed, and a
fresh process must prove that no prior session/index/log/history byte is visible.

The exact environment is allowlisted. It includes the three disable variables
above, sterile home/temp/runtime paths, and only mediated proxy variables. All
`KIMI_MODEL_*`, API-key, ambient proxy, cloud, Git, SSH-agent, editor, and
inherited secret variables are absent.

### Exact zero-tool and OAuth-only profile

The future immutable main-agent file is selected by an exact, hash-bound launch
argument and contains a minimal fixed prompt plus this frontmatter:

```yaml
---
name: aos-f1-planner
description: Emit one bounded AOSPLAN/1 proposal from supplied context.
tools: []
subagents: []
---
```

It contains no `${base_prompt}`, `${plugin_sections}`, `${agents_md}`, or
`${skills}` expansion. The official agent format defines `tools: []` as no
tools and rechecks the allowlist before execution. The corresponding immutable
config also sets `merge_all_available_skills = false`,
`builtin_product_skills = false`, empty extra skill/agent directories,
`telemetry = false`, `[thinking].enabled = false`, finite loop/background
bounds, and the global intersection
`enabled = ["Read"]`, `disabled = ["Read"]`, using an exact tool name present
in the pinned reference. A global empty `enabled`
list is explicitly forbidden because it means unconstrained. There are no
services, hooks, secondary model, permissions that allow work, plugins,
`SYSTEM.md`, `AGENTS.md`, MCP files, or discovery directories.

The exact executable must prove that `kimi acp` accepts and binds the
hash-qualified `--agent-file` profile for `session/new`; if that invocation is
not officially supported by the pinned parser, the gate must identify another
official exact-selection mechanism and prove the same bytes. Otherwise F1 is
blocked. No fallback to the default main agent is allowed. A local scripted
model fixture must request every registered tool name and prove denial before
local dispatch, in addition to proving that no tool schema is sent upstream.

The runtime config contains exactly one managed Kimi OAuth provider reference
and one allowlisted model alias. The provider may contain only `type = "kimi"`,
the official managed base URL, and login-created OAuth reference metadata. It
must not contain a nonempty `api_key`, provider `env`, custom headers, services,
alternate providers/models, endpoint overrides, secondary models, or tool-use
capability additions. Absence of `api_key` is preferred; if the pinned
login-generated schema requires the documented empty-string field, exact empty
is allowed only after proving it cannot authorize a request when OAuth is
missing. The adapter verifies the effective provider, model, and auth method
before every prompt. Missing OAuth is terminal. Because the provider schema can
carry `api_key` and `env` alongside an OAuth reference, every possible fallback
channel must be proven absent or inert.

Both profile and config canonical bytes and SHA-256 values are frozen in the
future executable checkpoint. Every permission request is rejected as a policy
violation. Kernel isolation and absence of project bytes remain load-bearing;
configuration alone is never credited as containment. This profile cannot
support Builder.

### Subscription-only OAuth ceremony (future gate)

Login is not authorized by F1 selection or the next installation gate. A later
owner-login approval must require the owner personally to invoke the pinned
`kimi login` inside a login-only provider scope and follow the verification URL
in the owner's browser. That scope has no workspace, prompt, task session, or
API-key variable. It may reach only the exact device-authorization, token,
refresh, and any post-token catalog/enrollment endpoints proven necessary for
the pinned artifact; every prompt/chat path and other destination stays denied.
The device code, token, credential file, and credential-derived values must
never be pasted into chat
or captured by controller input, logs, or evidence.

The login scope uses a layout distinct from runtime. Its `config.toml`, session
index, logs, history, updates, and temporary files are mutable private tmpfs;
only the dedicated `credentials/` submount persists. Kimi may provision its
managed provider/model/OAuth-reference config there as part of the official
flow. After success, a credential-blind validator may read only an exact
allowlist of non-secret config metadata—provider/model identifiers plus OAuth
storage/key references—and compare it with tag-pinned expected constants. It
must not open the credential directory or read, hash, copy, deserialize,
relocate, or report any credential content.

The mutable login config is then destroyed. The controller separately generates
the canonical immutable runtime config from the pinned non-secret constants; it
does not copy the login config. The credential directory is mounted at the
source-verified runtime path, and successful `authenticate(login)` is the only
proof that the reference resolves. Any unexpected metadata or required secret
inspection blocks the gate.

After success or cancellation the scope is recursively drained. The controller
may record content-free status such as `OWNER_OAUTH_LOGIN_PRESENT` plus safe
permission metadata, but never credential bytes or hashes. Another explicit
gate is required before the first model request. Missing, expired, or revoked
OAuth is a typed provider-auth failure, never permission to inspect credentials,
request an API key, or silently change providers.

## Network and process boundary

M6/M4B primitives may be reused—dedicated namespace/cgroup, exact environment
and FD census, identity-bound listener, mediated egress, cancellation, and
recursive drain—but an existing shared broker must not be reused unchanged.
This is a separate provider-client trust and credential domain.

The provisional destinations are `auth.kimi.com:443` for managed OAuth and
`api.kimi.com:443` for managed subscription requests. The documented update
host `code.kimi.com:443` is denied because auto-update is disabled; telemetry,
web, MCP, plugin, skill, cron, and
arbitrary destinations are denied. A later login/request gate must derive the
exact allowlist from pinned official facts and observed connections, then fail
closed on direct sockets, IP literals, out-of-set redirects, DNS/proxy bypass,
or child-process egress.

The exact process tree is unknown until passive installation qualification. It
must be frozen for the pinned artifact, with all descendants in one dedicated
cgroup/namespace. Unexpected children, detached/background work, terminal
execution, native-helper drift, open FDs, or post-cancel residue are terminal.

## Composition with M4A, M5, and Demo 0

F1 adds a provider adapter behind the existing stage-driver boundary; it does
not redesign the scheduler, board, M4A, or M5. The controller retains project,
task, lease, dispatch, repository, Git, verifier, reviewer, retry, and final
checkpoint authority. Kimi receives only the bounded context selected for one
Planner attempt and never a controlled worktree, workspace lease, repository
credential, checkpoint mutation right, or commit/ref/push capability.

The accepted proposal goes through the existing compiler and atomic board
publication path. Later BUILD, VERIFY, REVIEW, and repair stages continue to use
their already-earned M4A/M5 boundaries and the Slice B checkpoint; Kimi cannot
skip or satisfy them. Demo 0 behavior remains the regression oracle. Kimi
Builder, controlled workspace file callbacks, and every mutating-provider
composition remain blocked and outside this checkpoint.

## Normative ACP-to-`AOSAGENT/1` mapping

The adapter uses the existing strict controller contract; it does not weaken
or replace it. On accepting the dispatch, it emits canonical `STARTED` as
sequence 1 with the request's full `DispatchIdentity`. Provider messages never
set AOS sequence, identity, event kind, terminal status, retryability, or
evidence fields.

| Kimi ACP exchange | Controller-owned interpretation |
| --- | --- |
| `initialize`, ACP `protocolVersion: 1` | Verify exact name, version, capabilities, and auth methods against the pinned profile; confer no authority. |
| `authenticate`, `method_id: login` | Observe only success/failure; expose no token and accept no API-key fallback. |
| `session/new` | Use sterile `/workspace`, `mcpServers: []`, and bind the untrusted session ID to the full `DispatchIdentity`. |
| `session/prompt` | Send one bounded envelope containing role, goal, criteria, limits, and controller-approved context from the exact `ContextManifest`. |
| `session/update` with matching session and `agent_message_chunk` containing text | Append decoded text in arrival order to one UTF-8 accumulator; enforce per-chunk, accumulated-output, event-count, and wall-time limits before append. It produces no AOS event by itself. |
| exact frozen `available_commands_update`, `config_option_update`, or `agent_thought_chunk` | Validate schema/session/size/count, charge every byte to the provider-output budget, then discard without AOS event, evidence, authority, or persistence. Thinking is configured off; a thought chunk is tolerated only as bounded non-authoritative output. |
| any other `session/update` variant or content type | Policy failure before proposal compilation, including tool-call/status, plan, usage, or unknown updates. |
| `session/prompt` response with exact `stopReason = "end_turn"` | Require one nonempty accumulator containing only canonical `AOSPLAN/1` JSONL; parse with `PlannerProposal.from_dict`, canonicalize again, and require byte equality. |
| `session/prompt` response with exact `stopReason = "cancelled"` after controller cancellation | Emit the unique `CANCELLED` terminal event. |
| any other or unknown stop reason | Emit the unique `TERMINAL_FAILURE`; an incomplete/truncated proposal is never success or no-op. |
| `session/cancel` | Begin bounded cancellation; never treat acknowledgement as proof of termination. |
| filesystem, terminal, permission, MCP, tool, load/resume/list, or unknown callback | Reject, stop the exact scope, recursively drain, and emit controller-owned terminal failure. |

On accepted `end_turn`, the controller stores exactly
`canonical_json_line(PlannerProposal.to_dict())` as the proposal artifact. It
creates a controller ID and `EvidenceRef` whose byte size and SHA-256 cover those
exact bytes, emits sequence 2 `PROPOSAL` referencing it, then sequence 3
`SUCCEEDED` referencing it. The proposal still passes
`compile_planner_proposal`; the provider cannot choose authoritative task IDs.
There is no workspace handoff for this role.

The result mapping is closed:

| Condition | Terminal event | `AgentResult` status / exit / retryability |
| --- | --- | --- |
| canonical proposal accepted | `SUCCEEDED` | `SUCCEEDED / SUCCESS / NOT_RETRYABLE` |
| controller cancellation and zero-residue drain | `CANCELLED` | `CANCELLED / CANCELLED / NOT_RETRYABLE` |
| supported machine-readable ACP transport/429/5xx error within budget | `RETRYABLE_FAILURE` | `RETRYABLE_FAILURE / RETRYABLE / RETRYABLE` |
| qualified controller timeout within retry policy | `RETRYABLE_FAILURE` | `RETRYABLE_FAILURE / TIMEOUT / RETRYABLE` |
| malformed JSON-RPC, invalid proposal, limit/identity/session violation | `TERMINAL_FAILURE` | `TERMINAL_FAILURE / MALFORMED / NOT_RETRYABLE` |
| auth/quota refusal, forbidden callback, drift, escape, leak, or residue | `TERMINAL_FAILURE` | `TERMINAL_FAILURE / TERMINAL / NOT_RETRYABLE` |

F1 never synthesizes `NO_OP` or `BLOCKED`. `event_count`, `byte_count`, and
`stream_digest` are computed over the exact accepted canonical AOS event lines;
the result carries the proposal evidence reference, `workspace_handoff_ref =
null`, and only strictly validated bounded usage counters (otherwise usage is
null or the response is malformed). `AgentStreamValidator.accept_result` must
accept the result before controller admission.

ACP stdout is protocol-only. The prompt response is terminal metadata, while
proposal text is streamed in `agent_message_chunk` notifications. Stderr and
logs are bounded, separately captured,
secret-scanned, and never authority. Malformed/oversized JSON, wrong JSON-RPC
version, duplicate/reused IDs, unknown methods, out-of-order responses,
session mismatch, unexpected EOF, post-terminal output, or callback spoofing
terminates and drains the exact scope with only bounded redacted evidence.

Cancellation sends `session/cancel`, waits a fixed grace period, closes stdin,
terminates the exact scope, and proves zero remaining processes, cgroups,
sockets, and mounts. Because `session/close` is unsupported, process-per-attempt
is mandatory.

## Failure and retry taxonomy

- **Boundedly retryable:** transient mediated transport loss or service
  `429`/`5xx` only when a supported machine-readable ACP error exposes that
  classification, no policy/protocol violation occurred, and the existing
  controller budget permits it.
- **Typed non-retryable provider/auth:** absent subscription authorization,
  missing/expired/revoked OAuth, quota/account refusal, unsupported auth, or an
  API-key request. Runtime never becomes an owner-interaction loop.
- **Terminal provider-policy:** version/capability drift, malformed/oversized
  protocol, forbidden callback/tool/MCP/filesystem/terminal action, direct
  egress, canary disclosure, unexpected child, residue, or session mismatch.
- **Timeout/cancellation:** controller-owned bounded termination and drain;
  never an unbounded code-repair retry.

Stderr, diagnostic logs, and free-form model text are never parsed to recover a
provider HTTP or quota classification. If Kimi collapses such a failure into
`stopReason = "end_turn"`, an empty or invalid proposal is a non-retryable
provider-protocol failure. Qualification must pin the 0.36.1 behavior and record
any lost distinction explicitly; it may reduce availability but not authority.

## Required executable qualification before admission

The installation/passive gate must pin one official Linux x64 artifact by
version, URL, release/tag/commit provenance, size, SHA-256, runtime dependency
closure, and signature or publisher evidence when available. It must install
into a dedicated immutable provider store without PATH fallback or auto-update,
and run only passive commands that cannot log in, read credentials, send
prompts, or contact a model.

Qualification is split into non-overlapping approvals:

1. **Next gate — passive installation.** Version/help and ACP startup/initialize
   probes use a synthetic empty home, no credential mount, and a network-denied
   namespace. They stop before authenticate/session/prompt and cannot consume a
   subscription.
2. **Later synthetic active gate.** A loopback-only OAuth/model fixture inside
   the isolated namespace uses the documented `KIMI_CODE_OAUTH_HOST` and
   `KIMI_CODE_BASE_URL` test endpoint overrides, synthetic tokens/canaries, and
   scripted model responses. External egress is kernel-denied. It exercises
   refresh, every tool request, streaming, malformed traffic, and cancellation
   without an owner credential or provider service.
3. **Later owner-login gate.** The owner performs the ceremony above; there is
   still no prompt.
4. **Later real-request gate.** Only after all prior evidence is frozen may one
   bounded Planner prompt use the managed subscription.

The synthetic fixture is test infrastructure, not an unofficial Kimi service
or credential-reuse path. Its exact request/response scripts, endpoint override
environment, canaries, and zero-external-egress proof are checkpoint evidence.

Before any real provider request, a later qualification checkpoint must prove:

1. exact executable/dependency identity and version/capability drift rejection;
2. environment, FD, mount, process-tree, cgroup, namespace, socket, DNS, and
   egress census;
3. sterile `HOME`/`KIMI_CODE_HOME`, no ambient project config, and no owner
   Kimi, `.agents`, Git, SSH, cloud, proxy, editor, or API-key state;
4. zero updater, telemetry, cron, plugin, skill, MCP, web, background-agent,
   terminal, shell, or arbitrary tool activity;
5. exact agent-profile/config hashes, main-agent selection, empty tool/schema
   advertisement, and enforcement, including scripted attempts to invoke every
   registered tool name before local dispatch;
6. one process/session per dispatch, exact `mcpServers: []`, no session reuse,
   and no cross-task state recovery;
7. valid, malformed, oversized, duplicate-ID, wrong-session, unknown-method,
   callback-spoof, post-terminal, and truncated ACP cases;
8. request/context/result byte, item, event, time, retry, and token limits at
   and just beyond every boundary;
9. controller ownership of full dispatch identity, sequencing, proposal
   compilation, terminal status, retryability, and evidence digests;
10. cancellation during initialize, auth, session creation, prompt, streaming,
    and provider backoff, followed by zero-residue recursive drain;
11. denial of project paths, `.git`, controller state, credential paths from
    provider output, and all paths outside the sterile root;
12. synthetic credential canaries in files, environment, arguments,
    memory-adjacent diagnostics, stderr, logs, sessions, crash reports, child
    processes, network destinations, AOS events/results, and final evidence;
13. no API-key fallback and no auth header, device code, token, cookie, or
    credential-derived material in controller-visible artifacts;
14. proxy-only candidate egress with redirect, DNS, IP-literal, IPv6, direct
    socket, inherited-proxy, child-process, and post-cancel escape tests;
15. service, auth, quota, protocol, policy, timeout, and cancellation failures
    mapped only from supported machine-readable ACP signals, with hidden-signal
    limitations recorded and logs never treated as authority;
16. no prior-attempt session/index/log/history visibility and verified
    destruction of private ephemeral state;
17. after owner login, content-free `authenticate(login)` success and managed
    subscription-session availability with no API-key fallback and no prompt;
18. at the separately authorized first-request gate, exactly one bounded
    Planner prompt with streamed chunk parsing and bounded proposal admission;
    and
19. unchanged Demo 0 behavior and the final Slice B checkpoint invariant.

Filesystem mediation has two distinct tracks. For the admitted Planner, any
filesystem/tool callback is rejected and no project is mounted. Separately,
synthetic no-secret ACP probes must confirm documented text callbacks and
demonstrate the local metadata/glob/mkdir/binary-read/exec paths. Those bypasses
keep Builder blocked; observing them is not authority to run a mutating provider.

All qualification uses synthetic credentials and canaries until the separately
approved owner-login ceremony. A real owner token is never used to discover
whether the boundary works.

## F1 blocker versus post-Demo-1 scope

`F1_BLOCKER`:

- exact pinned artifact and dependency provenance;
- passive startup/version/capability/process/data-location qualification;
- tool-free ACP adapter and strict `AOSAGENT/1` translation;
- sterile provider-client/auth domain and task-state lifecycle;
- exact empty tool/MCP/plugin/skill/cron/web surface;
- provider-specific egress mediation and endpoint proof;
- owner-login ceremony design, secret non-observation, and no API-key fallback;
- malformed/cancellation/residue/canary test corpus; and
- preservation of Demo 0 and the final Slice B checkpoint.

`POST_DEMO_1`:

- a generic ACP framework or provider marketplace;
- provider scoring, cost/quota prediction, and dynamic routing;
- generalized OAuth brokerage or multi-account rotation;
- dashboards, auto-update, generic MCP/plugin/skill admission;
- Kimi Builder admission unless Demo 1 explicitly requires it; and
- every F2, G2, G1, UI, deployment, distributed scheduling, and generated
  project publication concern.

## Independent adversarial review

Independent read-only review found and this design resolved:

1. ambiguous empty-list tool semantics and missing main-agent/subagent/skill
   suppression;
2. a descriptive rather than normative ACP-to-`AOSAGENT/1` mapping;
3. incomplete API-key fallback exclusion;
4. insufficient separation of persistent OAuth state from attempt state;
5. mutable-documentation claims and no synthetic active-qualification fixture;
6. rejection of benign bounded ACP metadata updates;
7. retry/quota classifications not guaranteed to be exposed through ACP; and
8. conflict between official login's mutable config writes and immutable
   runtime configuration.

The reviewer confirmed all Critical and Important findings resolved without
weakening the admission invariant:

```text
F1_ADVERSARIAL_REVIEW=GO
UNRESOLVED_CRITICAL=0
UNRESOLVED_IMPORTANT=0
```

## Residual risks and stop conditions

The main residual risks are configuration/version drift, incomplete tool
gating, ambient project/home discovery, token-refresh persistence, session/log
leakage, child/direct-network escape, unexpected native helpers, protocol/SDK
drift, local filesystem/process bypass, and compromise of the trusted
credential-holding Kimi client. None is claimed closed by source inspection.

Missing artifact provenance, unexplained process/network/data access, a
nonempty tool surface, credential observation, API-key request, updater,
ambient-state access, unexpected callback, boundary residue, or inability to
bind output to the exact dispatch is a hard stop. It yields `BLOCKED`, not a
weaker sandbox or inferred exception.

## Gate result

This checkpoint authorizes no Kimi operation. The only next approval is:

```text
AUTHORIZE_F1_KIMI_INSTALLATION_AND_PASSIVE_HOST_QUALIFICATION=YES
```

That gate permits only exact pinned installation and passive host probes. It
still forbids login, OAuth completion, credential access, prompts, model or
provider traffic, subscription use, workspace edits, and F2/G2/G1 work.

```text
FIRST_AUTONOMOUS_BUILD_SLICE_F1_SELECTION=COMPLETE
F1_KIMI_SELECTION_STATUS=ADMISSIBLE_IN_PRINCIPLE
```
