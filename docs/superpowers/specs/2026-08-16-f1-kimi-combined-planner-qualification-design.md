# F1 Kimi Combined Single-Real Planner Qualification Design

## Status and authorization boundary

```text
F1_KIMI_PLANNER_QUALIFICATION_DESIGN=BLOCKED
DESIGN_WORK_AUTHORIZED=YES
WRITTEN_SPEC_APPROVED=NO
BLOCKING_FINDING=OPAQUE_SAME_ORIGIN_REDIRECT_REQUEST_MULTIPLICATION
IMPLEMENTATION_AUTHORIZED=NO
REAL_PLANNER_REQUEST_AUTHORIZED=NO
REAL_LEVEL1_RETRY_AUTHORIZED=NO
REAL_LEVEL1_ATTEMPT_AUTHORIZED=NO
HISTORICAL_LEVEL1_REAL_ATTEMPT_COUNT=1
REAL_ATTEMPT_COUNT=1
CURRENT_PLANNER_QUALIFICATION_ATTEMPT_COUNT=0
REAL_CREDENTIAL_ACCESS_AUTHORIZED=NO
PROVIDER_NETWORK_AUTHORIZED=NO
MODEL_INFERENCE_AUTHORIZED=NO
F2_AUTHORIZED=NO
AUTHORITATIVE_BASELINE=e4912a883bdb959528497ac2144a4cf449819299
KIMI_VERSION=0.36.1
KIMI_SOURCE_COMMIT=13d86f8b7bb2443a3b8222e7d94deb0a66429f8e
KIMI_EXECUTABLE_SHA256=78c07b255e0bdc8dfe90d0cbd3204a3d862957394a08ca99c6e31144732451c7
KIMI_NAMESPACE_LAUNCHER_SHA256=800dbc83e1d1dc7efd127151d257025b4160ae92dfc23d13ed175f09778d15dc
```

This document designs a new qualification generation whose purpose is one
future, tightly bounded, subscription-backed Kimi Planner turn. It does not
authorize implementation or execution. It does not create an attempt marker,
read or mount the real credential, inspect credential metadata, contact Kimi,
authenticate against real state, create a real session, send a prompt, consume
quota, perform inference, or begin F2.

The historical Level-1 result is immutable:

```text
F1_KIMI_LEVEL1_LOCAL_AUTH_QUALIFICATION=BLOCKED
F1_KIMI_LOCAL_CREDENTIAL_STATE=BLOCKED
HISTORICAL_REASON=AUTH_METHOD_SHAPE
HISTORICAL_LEVEL1_REAL_ATTEMPT_COUNT=1
REAL_LEVEL1_RETRY_AUTHORIZED=NO
```

The subsequent launcher and validator remediation proves that an AgenticOS
infrastructure defect was corrected. It does not retroactively change what
the historical attempt observed or earn any authentication, server, or model
claim.

## Decision

Retain **B: combined single-real Planner qualification** as the product target,
but mark its current exact-binary architecture **blocked**. The pinned client
does not expose a source-enforced redirect-deny policy, while opaque TLS keeps
same-origin redirects invisible to the mediator. The required one-wire-request
claim is therefore not currently enforceable or observable.

| Strategy | Decision | Reason |
| --- | --- | --- |
| A. Level-1 generation 2 | Reject | Repeating a local-only checkpoint spends real-credential authority without advancing the product to a Planner result and risks confusing immutable history. |
| B. Combined Planner qualification | Target, currently blocked | It advances the product directly, but implementation and real authority remain blocked until redirects are made fail-closed without exposing credential or prompt content. |
| C. Abandon Kimi F1 | Reserve, now a live alternative | Choose this if the owner declines a separately reviewed pinned-client or transport change capable of closing the redirect gap. |

### Blocking exact-source finding

The exact 0.36.1 OAuth `postForm()` in `packages/oauth/src/oauth.ts` calls the
global `fetch(url, {method, headers, body, signal})` without `redirect:
"manual"` or `redirect: "error"`. Its `maxRetries ?? 3` loop therefore bounds
three top-level fetch calls, not necessarily three wire HTTP requests.

The exact OpenAI wrapper in
`packages/agent-core-v2/src/kosong/provider/bases/openai/openai-legacy.ts`
sets `baseURL` and `maxRetries: 0`, then delegates to
`openai@6.34.0` `chat.completions.create(...).withResponse()`. It supplies no
redirect-deny override. Standard fetch semantics follow HTTP redirects unless
overridden. A same-origin 301, 302, 303, 307, or 308 can therefore cause a
second wire request inside the same admitted TLS tunnel. A different-host
redirect is denied by the CONNECT/SNI gate, but the opaque mediator cannot see
or stop a same-host path redirect.

One prompt, one loop step, zero SDK retries, no auth replay, and one model
tunnel are all necessary but do not close this gap. Exact-binary synthetic
redirect tests can characterize the behavior; they cannot substitute for a
live enforcement control if the binary follows a same-origin redirect.

Before Strategy B can become ready, a separately reviewed resolution must do
one of the following:

1. establish with exact-binary 301/302/303/307/308 tests that both OAuth and
   model transports fail redirects closed under the exact production config;
2. qualify a new pinned official-client build or other owner-approved client
   change that sets redirect handling to `error` before any secret-bearing
   request, with a new artifact identity and full passive/synthetic review; or
3. replace opaque transport with a separately authorized design that can
   enforce requests without exposing credentials, Authorization, prompt, or
   response content.

If none is acceptable, select Strategy C. This design does not authorize any
of those resolution paths.

The new gate is not “Level-1 attempt 2.” Authentication is a prerequisite
inside a different, higher-level qualification. A future successful result
would be represented as:

```text
HISTORICAL_LEVEL1=BLOCKED
HISTORICAL_LEVEL1_REASON=AUTH_METHOD_SHAPE
CURRENT_REMEDIATED_RUNTIME=QUALIFIED
PLANNER_QUALIFICATION=COMPLETE
LOCAL_CREDENTIAL_RECOGNIZED_DURING_PLANNER_RUN=YES
SERVER_AUTH_ACCEPTED_DURING_PLANNER_RUN=YES
INFERENCE_SUCCEEDED=YES
```

## Exact pinned-source trace

The source basis is the official annotated tag
`@moonshot-ai/kimi-code@0.36.1`, tag object
`336fed3b5f265c986d4f43808da98f3c6b4bbd16`, peeled to commit
`13d86f8b7bb2443a3b8222e7d94deb0a66429f8e`. The installed executable is the
already-qualified 0.36.1 Linux x64 artifact with SHA-256
`78c07b255e0bdc8dfe90d0cbd3204a3d862957394a08ca99c6e31144732451c7`.

The source-derived future call chain is:

```text
apps/kimi-code/src/cli/sub/acp-native.ts
  -> packages/acp-server/src/start.ts
     -> stdio NDJSON ACP server

packages/acp-server/src/server.ts
  initialize
    -> strict agent capabilities and terminal auth method
  authenticate(methodId="login")
    -> ensureAuthed()
       -> AuthSummaryService.ensureReady()
  newSession
    -> klient.global.sessions.create(workDir, mcpServers)
    -> activateSession()
    -> wireSession()
       -> bindDefaultModel()
          -> config defaultModel
          -> agent.setModel(...)
  prompt
    -> AcpSession.prompt(...)
       -> agent.prompt(...)
```

The exact observations that constrain this design are:

| Concern | Exact 0.36.1 source conclusion |
| --- | --- |
| ACP initialization | Native ACP v2 starts on stdio NDJSON. `initialize` returns one terminal authentication method. |
| Authentication | Only `methodId="login"` is accepted. `ensureAuthed()` calls `AuthSummaryService.ensureReady()`. |
| Local recognition | `ensureReady()` reloads local configuration and calls the OAuth manager's cached-token lookup. It does not itself refresh or contact the provider. |
| Session creation | `newSession` creates and activates a session, then binds the immutable configured default model. |
| Prompt | A non-command prompt is prepared as content and passed once to `agent.prompt`. |
| Credential storage | `packages/oauth/src/storage.ts` loads storage name `kimi-code` from `$KIMI_CODE_HOME/credentials/kimi-code.json`; in the qualified sandbox this is `/home/aos/kimi/credentials/kimi-code.json`. |
| Refresh decision | `OAuthManager.ensureFresh()` refreshes when forced, or when nonzero expiry remaining is less than `max(300 seconds, expires_in * 0.5)`. `expires_at == 0` does not trigger a time-based refresh. |
| Refresh endpoint | The official OAuth client sends form-encoded `POST https://auth.kimi.com/api/oauth/token` with the refresh-token grant. No device grant belongs to this flow. |
| OAuth redirects | `postForm()` uses global fetch without a redirect override. The three-attempt loop bounds fetch calls, not redirect-generated wire requests. |
| Refresh persistence | Success is written by the official client using a same-directory temporary file, `fsync`, and rename. AgenticOS does not parse or copy token values. |
| Model selection | Immutable config selects provider `managed:kimi-code`, model namespace `kimi-code/kimi-for-coding`, wire model `kimi-for-coding`, provider type `kimi`, and OpenAI base protocol. |
| Model base URL | `https://api.kimi.com/coding/v1`. |
| Model request | The OpenAI-compatible legacy adapter invokes `client.chat.completions.create`; the resulting application request is `POST /coding/v1/chat/completions`. |
| SDK | The pinned dependency graph resolves `openai@6.34.0`; the adapter constructs the client with `maxRetries: 0`. |
| Model redirects | The exact wrapper supplies no redirect-deny option. Same-origin redirect behavior is unresolved until exact-binary testing and, if follow occurs, a separately authorized enforcement change. |
| Streaming | `stream=true` and `stream_options.include_usage=true`; the response is consumed as an SSE-backed async iterable. |
| HTTP version | The source does not require HTTP/2. HTTPS, origin certificate validation, streaming, and the exact client's negotiated protocol must be proven synthetically. |
| Step retry | The agent engine can retry retryable step failures; immutable qualification config must set `[loop_control] max_attempts_per_step=1`. |
| Steps per turn | `LoopService.run()` may execute multiple model steps for one ACP prompt. Its pre-step guard stops when `runtime.steps >= maxSteps`; immutable qualification config must also set `[loop_control] max_steps_per_turn=1`. |
| Auth-recovery replay | `modelRequesterImpl` can force a token refresh after a model HTTP 401 and then replay the model request once. The network state machine below makes that replay unreachable. |
| Update path | `KIMI_CODE_NO_AUTO_UPDATE=1` prevents the `code.kimi.com` update preflight. |
| Telemetry/background | `telemetry=false`, no TUI path, background keep-alive disabled, product skills disabled, merged skills disabled, empty MCP list, `tools: []`, and `subagents: []` suppress non-qualification work. |

### Host census

Only two external destinations are source-required for the bounded flow:

| Purpose | Exact destination | Admission |
| --- | --- | --- |
| Optional official-client refresh | `auth.kimi.com:443`, `POST /api/oauth/token` inside end-to-end TLS | Available only in `AUTH_WINDOW`; no login or device grant. |
| Single model turn | `api.kimi.com:443`, `POST /coding/v1/chat/completions` inside end-to-end TLS | Available only once in `MODEL_ONCE`. |

`code.kimi.com`, `cdn.kimi.com`, `telemetry-logs.kimi.com`,
`www.kimi.com`, Moonshot open-platform hosts, GitHub, different-host
redirects, IP literals, alternate ports, and every unclassified host remain
denied. Same-host redirects are not denied by this candidate and block it.
Source drift or a new required host returns the design to owner review; it
never widens the allowlist automatically.

## Earned and unearned authority

| Actor or component | May | Must not |
| --- | --- | --- |
| Owner | Separately authorize implementation and later one exact real run | Have intent inferred from this design approval |
| Controller | Validate pinned public artifacts/config, drive ACP, enforce bounds, store content-free evidence, kill and census | Read credential bytes, receive tokens, interpret model text as authority, grant general Internet |
| Exact Kimi 0.36.1 process | Read its one mounted credential leaf; use official cached-token/refresh machinery; make the one admitted model request | See the checkout, other credentials, controller state, tools, shell, ambient network, a fallback provider, or a second prompt |
| Egress mediator | Validate task authority, CONNECT authority, ClientHello SNI, state, connection limits, byte/time limits; relay opaque bytes | Terminate TLS, see HTTP headers/body, inject credentials, parse tokens, log prompt/output, or become M4B authority |
| Model output | Supply untrusted bounded candidate JSON | Assign authoritative IDs, providers, paths, commands, limits, verification, status, or completion |
| Evidence writer | Persist canonical content-free facts and digests | Persist credential metadata/content, tokens, cookies, Authorization, raw prompts, raw model output, or provider payloads |

No authority from M5 or a build worktree enters this gate. The Planner has an
empty synthetic workspace and no `.git`, project source, board database,
controller state, or other provider state.

## Selected architecture

The existing M4B HTTPS broker is not reused or weakened. M4B terminates worker
TLS, parses HTTP/1.1, and originates a second TLS connection. Its published
claim is one host per task and explicitly excludes provider credential
handling. The existing application-level provider broker also terminates and
interprets HTTP, rejects client Authorization, and is designed to inject a
controller-held credential capability. Both conflict with the official
client-owned, credential-blind boundary.

Implement, only after separate authorization, a dedicated opaque
`KimiPlannerEgressMediator`. It is a sibling process outside the provider
sandbox, reachable only on a private loopback proxy socket. The Kimi namespace
has no default route and no DNS configuration. The mediator performs bounded
DNS resolution under the existing public-address/SSRF policy and connects by
validated numeric sockaddr; Kimi supplies the TLS SNI and validates the
origin certificate end to end.

The host sibling is not assumed to be reachable through the worker's isolated
loopback. The future Planner namespace launcher must reuse the qualified
listener-capability pattern from `kimi_login_namespace.py`: after entering the
Kimi network namespace it creates the one exact `AF_INET/SOCK_STREAM` listener
at `127.0.0.1:18080`, then transfers exactly that accepting socket with one
versioned marker and one `SCM_RIGHTS` descriptor over the controller-created
Unix handoff socket. The outer mediator validates family, type, local address,
port, listening state, marker, ancillary count, truncation flags, and task
binding before readiness. The launcher closes its listener and handoff copies
before `execve` of the absolute pinned Kimi ACP vector.

The exact cleared environment contains only lowercase
`https_proxy=http://127.0.0.1:18080` as proxy authority; uppercase/alternate
proxy variables and `no_proxy` are absent. Native exact-binary tests must prove
both the OAuth and OpenAI model stacks use this listener, that all synthetic
requests are observed there, and that no direct or alternate proxy path can
bypass it. Route-less direct attempts fail closed and cannot become evidence
of successful transport.

The mediator is Kimi-specific, task-scoped, exact-version-bound, and unusable
by M4B workers or other providers. It accepts strict HTTP CONNECT framing only
long enough to establish an opaque tunnel. It never sees decrypted HTTP.

### Identity chain

For each admitted tunnel the mediator proves:

```text
sealed task grant
  = strict CONNECT hostname and port
  = first ClientHello SNI and port
  = frozen destination policy derived from that hostname
```

The exact Kimi client proves certificate-host equality through ordinary
origin certificate validation. The initial HTTP authority and path are not
visible to an opaque mediator; they are source-bound by immutable config,
pinned executable/source identity, a sterile environment with no alternate
base URL, and exact-binary synthetic capture of the decrypted fixture request.
That binding does not control a same-origin redirect target. Evidence must
state this split honestly. It must not claim that the live mediator parsed
certificate SANs, HTTP authority, headers, paths, status, or redirects.

ECH is denied until a separately reviewed mechanism can prove the hidden name.
An IP-literal CONNECT, missing or second ClientHello, mismatched SNI,
different-host redirect, or alternate port is blocked before new external
authority is relayed. Same-host redirects are the unresolved blocker above.

## Network state machine

```text
START
  -> AUTH_WINDOW
       admitted host: auth.kimi.com:443 only
       zero or one active auth tunnel at a time
       no more than three auth tunnels for the task lifetime
       api.kimi.com attempt triggers sealed transition request
  -> AUTH_DRAINING
       revoke auth admission
       interrupt both directions of every auth tunnel
       join all auth workers against one deadline
       prove active-auth set empty and auth listener unavailable
  -> MODEL_ONCE
       admit exactly one api.kimi.com:443 CONNECT/SNI tunnel
       never reopen auth authority
  -> MODEL_SPENT
       deny every subsequent CONNECT, including api.kimi.com
  -> REVOKING
  -> DRAINED
```

The transition from `AUTH_WINDOW` to `MODEL_ONCE` is atomic from Kimi's point
of view: the pending model CONNECT receives no success response until auth
admission is revoked, every auth origin/client socket has been interrupted,
all auth workers have joined, and emptiness is proven. If drain does not
complete, the model tunnel is never admitted.

This ordering closes the pinned client's explicit model-401 refresh/replay
path. After the
first model request starts, a forced refresh cannot reach `auth.kimi.com`.
`modelRequesterImpl` therefore fails during refresh and cannot issue its
second model request. The model grant is also spent at first admission, SDK
retries are zero, attempts for the single step are one, total steps for the
turn are one, and ACP permits one prompt total.

An auth tunnel may exist only before the model tunnel. A refresh can contain
source-owned transport retries. Exact 0.36.1 evaluates
`maxRetries ?? 3` as the total loop-attempt bound (`attempt < maxRetries`), so
the refresh-token request has at most three total attempts for retryable
network, 429, or 5xx outcomes. Therefore:

- `REQUIRED_REAL_MODEL_REQUEST_COUNT` is one, but the current opaque design
  cannot prove it when same-origin redirects are possible;
- `AUTH_TUNNEL_COUNT` and the source-proven refresh-fetch-call upper bound are
  distinct evidence fields; the opaque mediator does not claim to observe
  individual HTTP requests inside a tunnel;
- exact-binary synthetic qualification must establish the total refresh bound
  and terminal conditions; and
- the later real-run authorization must explicitly approve that bound.

The public source/config identity establishes an upper bound of three
top-level refresh-token fetch calls. It does not bound redirect-generated wire
requests inside any call. Live evidence can record the fetch-call source bound
and opaque auth-tunnel count, not a fabricated HTTP request count. The
separately chosen three-tunnel lifetime cap is defense in depth, not a claim
that one fetch call or HTTP request equals one tunnel. Until redirect behavior
is fail-closed, the qualification is `BLOCKED` before implementation or real
authority. No
login/device-code request, refresh-host widening, or model request follows a
terminal refresh failure.

### Transport limits

Implementation must choose finite constants and prove them before review:

- one concurrent tunnel;
- no more than three total auth tunnels as an independent transport cap (not
  an observation of encrypted HTTP attempt count);
- at most one model tunnel for the task lifetime;
- bounded CONNECT and ClientHello bytes;
- bounded DNS answers and only public unicast destinations;
- bounded connect, handshake-idle, streaming-idle, and total task deadlines;
- bounded bytes in both directions;
- no half-open tunnel after task termination; and
- one deadline shared by socket interruption, worker joins, provider process
  drain, and final census so cleanup cannot hang indefinitely.

The candidate transport permits connection reuse inside the single admitted
model tunnel. That is precisely why a same-origin automatic redirect can evade
tunnel accounting. No real run may use this candidate until the redirect
blocker is resolved. HTTP/2 is neither required nor claimed. The synthetic
exact-binary matrix must record the negotiated protocol and block unreviewed
drift.

## Credential and refresh state machine

AgenticOS reuses the qualified descriptor-based credential mount design but
does not inspect credential content or current metadata as part of this design
slice.

```text
UNTOUCHED
  -> MOUNTED_FOR_EXACT_CLIENT          future authorized run only
  -> LOCAL_AUTH_CHECK
       authenticate(methodId="login")
       -> LOCAL_RECOGNIZED
       -> LOCAL_REJECTED -> BLOCKED
  -> TOKEN_PREPARATION
       cached token sufficient -> TOKEN_READY
       source requires refresh -> REFRESHING_IN_AUTH_WINDOW
         -> REFRESH_SUCCEEDED -> TOKEN_READY
         -> REFRESH_FAILED -> BLOCKED
  -> MODEL_SERVICE_CHECK
       first model response accepted -> SERVER_ACCEPTED
       401/403/rate limit/other failure -> BLOCKED, no replay
  -> CREDENTIAL_UNMOUNTED
```

Only the exact pinned process may open `/home/aos/kimi/credentials/kimi-code.json`.
The controller and mediator receive no credential FD. The credential root is
not in the empty workspace, evidence directory, or controller output. The
official client may create its documented same-directory temporary file and
atomically replace the credential only if refresh is source-required. The
mount and private writable state must preserve the qualified owner, mode,
link, symlink, inode, mount-source, and transient-entry protections.

AgenticOS must never parse tokens, cookies, expiry, Authorization, refresh
payloads, or credential JSON. It must not log, hash, copy, deserialize, or
compare credential bytes. No login fallback exists. If local recognition or
refresh fails, the typed Planner qualification result is `BLOCKED` and the
historical Level-1 files remain untouched.

## ACP state machine

The current passive transcript adapter is not real-execution authority. A
future dedicated qualification controller must preserve its strict parsing
and add the authenticated states explicitly:

```text
NEW
  -> INITIALIZE_SENT
  -> INITIALIZED_UNAUTHENTICATED
  -> AUTHENTICATE_SENT
  -> AUTHENTICATED
  -> SESSION_NEW_SENT
  -> READY
  -> PROMPT_SENT                  exactly once for controller lifetime
  -> STREAMING
  -> FINISHED | BLOCKED
  -> CLEANING
  -> CLEANED | CLEANUP_FAILED
```

The exact request sequence is:

1. Send `initialize` and require the complete packaged 0.36.1 response,
   including exact terminal login metadata and the remediated absolute legacy
   command.
2. Send `authenticate` with exactly `methodId="login"`; require success before
   session creation.
3. Send one `session/new` with the empty workspace, no MCP servers, and the
   immutable Planner profile.
4. Require the configured model/provider binding to match the pinned values.
5. Send exactly one bounded `session/prompt`.
6. Accept only qualified bounded session updates, require terminal
   `stopReason="end_turn"`, parse one proposal, and enter a terminal state.
7. Revoke egress, close ACP stdin, terminate and drain the entire process
   group/cgroup, unmount state, and census residue.

Any duplicate, out-of-order, unknown-id, oversized, malformed, or
post-terminal frame blocks. Any filesystem, terminal, permission, elicitation,
tool, MCP, plugin, skill, hook, subagent, shell, or background callback blocks.
There is no second prompt, session, model, provider, summarization, repair, or
fallback path.

## Deterministic model identity

The future runner must revalidate before release:

```text
default_model = kimi-code/kimi-for-coding
provider = managed:kimi-code
provider_type = kimi
wire_model = kimi-for-coding
base_url = https://api.kimi.com/coding/v1
protocol_adapter = openai legacy chat completions
sdk = openai@6.34.0
sdk_max_retries = 0
loop_control.max_attempts_per_step = 1
loop_control.max_steps_per_turn = 1
```

The config, Planner profile, artifact manifest, executable, namespace
launcher, and future mediator policy are digest-bound to the controller's
sealed launch authority. Environment variables that can override provider,
base URL, model, proxy, CA trust, Node options, home, config, or credentials
are cleared and replaced by an exact allowlist. Any drift is `BLOCKED`.

## Required one-request accounting and current blocker

The required future claim is application-level, but it is not earned by this
design:

```text
REQUIRED_REAL_MODEL_REQUEST_COUNT=1
ENFORCED_REAL_MODEL_REQUEST_COUNT=UNKNOWN_BLOCKED
REAL_PROMPT_COUNT=1
REAL_SESSION_COUNT=1
MODEL_TUNNEL_COUNT=1
MODEL_RETRY_COUNT=0
MODEL_FALLBACK_COUNT=0
BACKGROUND_MODEL_REQUEST_COUNT=0
```

The following independently enforced facts are necessary:

1. the ACP controller admits one session and one prompt for its lifetime;
2. exact immutable config admits one model and one provider;
3. the SDK is constructed with `maxRetries: 0`;
4. the `LoopService.run()` pre-step guard is digest-bound with
   `max_steps_per_turn=1`, so the ACP turn can start one model step total;
5. attempts for that one step are exactly one;
6. the model-401 refresh/replay path is cut by irreversible auth revocation;
7. the mediator admits one model tunnel and no other external host; and
8. the exact binary against a decryptable synthetic fixture must demonstrate
   exactly one `POST /coding/v1/chat/completions`, no background inference,
   and no second request for all terminal cases.

These facts still cannot distinguish an origin-directed same-host redirect
inside the opaque tunnel. Exact-binary fixture success characterizes known
responses but does not constrain a future provider response. A tunnel count
must never be reported as a direct observation of encrypted HTTP request
count. Until redirect-follow behavior is source-disabled or independently
enforced, the real gate is not built or run.

## Planner prompt and workspace

The real prompt input is fixed, public, synthetic, and canonical JSON no
larger than 4 KiB. Its semantic shape is:

```json
{
  "schema": "AOS_KIMI_PLANNER_PROMPT/1",
  "owner_goal": "Propose one documentation task that records a synthetic controller invariant.",
  "research_evidence": [
    "Synthetic qualification input. No repository access is required."
  ],
  "context_manifest": [
    {
      "path": "synthetic/invariant.txt",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "size": 0
    }
  ],
  "acceptance_criteria": [
    "The proposed task states that the controller, not the model, assigns authoritative task identifiers."
  ]
}
```

The prompt requests exactly one `DOCUMENT` task and requires no file, shell,
tool, subagent, network search, plugin, skill, hook, or private data. The
workspace is an empty synthetic tmpfs. It contains no file corresponding to
the manifest entry; the manifest is untrusted context, not filesystem
authority.

## Output boundary

ACP frames retain the existing 65,536-byte per-frame bound and 1,024-frame
transcript ceiling, while this qualification imposes a stricter 16-KiB total
model-text bound and exactly one proposed task. The accumulator accepts only
message text from qualified session updates. Raw output remains memory-only
until strict validation finishes and is then discarded.

The only admissible object is exact-field canonical `AOSPLAN/1`:

```text
{
  schema: "AOSPLAN/1",
  tasks: [{
    local_id,
    title,
    description,
    task_type,
    dependencies,
    acceptance_criteria,
    preferred_role,
    priority
  }]
}
```

`PlannerProposal.from_dict` enforces types and limits. Canonical re-encoding
must equal the accepted canonical bytes. The existing controller compiler
rechecks the DAG and policy, replaces local IDs with authoritative IDs,
replaces acceptance criteria and role with controller policy, and alone may
mutate the board. Qualification does not perform that board mutation; it
proves only that compilation would accept the synthetic proposal.

Malformed JSON, duplicate keys, extra fields, prose wrappers, Markdown
fences, empty/multiple tasks, invalid enums, oversized text, invalid DAG, or
compiler rejection produces `BLOCKED` with no retry. Retained evidence may
contain only proposal byte count and SHA-256 of the canonical accepted
proposal, not raw provider output.

## Evidence namespace and schemas

The existing directory
`.../controller-evidence/kimi-code/0.36.1/level1-local-auth` and its
`attempt.json` and `result.json` are immutable and are never opened for write
by this gate.

The future implementation may define, but this design does not create:

```text
/home/brand/.local/share/agenticos/controller-evidence/
  kimi-code/0.36.1/planner-qualification-v1/
    attempt.json
    result.json
```

The following schemas are provisional design shapes only. They must not be
implemented until the redirect blocker is closed and a revised spec is
independently reviewed. They remain distinct from Level 1:

```text
AOS_KIMI_PLANNER_QUALIFICATION_ATTEMPT/1
AOS_KIMI_PLANNER_QUALIFICATION_RESULT/1
```

The attempt marker is created atomically only after a later owner authorization
is validated and immediately before any real credential mount or provider
authority. Its exact fields are:

```text
schema
planner_attempt                         # 1 within this new namespace
candidate_commit
authorization_digest                   # digest of public authority packet
kimi_version
kimi_source_commit
kimi_executable_sha256
namespace_launcher_sha256
config_sha256
planner_profile_sha256
mediator_policy_sha256
prompt_sha256
historical_level1_result                # BLOCKED
historical_level1_reason                # AUTH_METHOD_SHAPE
historical_level1_real_attempt_count    # 1
claimed_at_utc
```

The result file uses exact fields:

```text
schema
planner_attempt
candidate_commit
qualification_state                    # COMPLETE | BLOCKED
primary_failure_code                    # null only for COMPLETE
local_credential_recognized             # true | false | unknown
refresh_state                           # NO_AUTH_TUNNEL | SUCCEEDED_INFERRED | FAILED_BEFORE_MODEL | UNKNOWN
auth_tunnel_count
auth_refresh_fetch_call_upper_bound      # source bound; 3 for exact 0.36.1
auth_refresh_fetch_call_observation      # SOURCE_BOUND_NOT_WIRE_OBSERVED
auth_refresh_wire_request_observation    # OPAQUE_UNKNOWN
server_auth_accepted                     # true | false | unknown
inference_succeeded                      # true | false
aosplan_validated                        # true | false
real_session_count
real_prompt_count
real_model_request_count                 # unknown while redirect gap remains
model_request_count_observation          # UNESTABLISHED_REDIRECT_GAP
model_tunnel_count
model_retry_count
model_fallback_count
background_model_request_count
model_host
model_path_source_binding
auth_host
auth_path_source_binding
negotiated_transport
prompt_bytes
prompt_sha256
model_output_bytes
canonical_proposal_sha256                # null unless accepted
acp_terminal_state
network_terminal_state
cleanup_state                            # COMPLETE | FAILED
cleanup_failure_code                     # independent from primary
process_residue_count
socket_residue_count
scope_residue_count
cgroup_residue_count
credential_non_leak_observation          # NOT_OBSERVABLE_LIVE
started_at_utc
finished_at_utc
```

Canonical JSON, exact keys, strict scalar types, `O_NOFOLLOW` descriptor-bound
directories, atomic exclusive creation, `fsync`, and no-overwrite semantics
apply. Cleanup failure cannot replace the primary result and a primary failure
cannot become success. Failure to persist trustworthy evidence is itself a
terminal blocked outcome reported outside the untrusted file.

`SUCCEEDED_INFERRED` means at least one auth tunnel occurred and the official
client subsequently began the model request; exact source plus synthetic
qualification establishes that refresh is the only auth-host operation in
this flow. `NO_AUTH_TUNNEL` means only that no auth tunnel was observed; it
does not claim that credential expiry or token contents were inspected.
`UNESTABLISHED_REDIRECT_GAP` means the one-prompt controller state,
digest-bound `max_steps_per_turn=1`, `max_attempts_per_step=1`, zero-SDK-retry,
no-refresh-replay, one-model-tunnel controls, and exact-binary synthetic
request capture still do not constrain a same-origin redirect chosen by a live
origin. Only after a separately reviewed redirect-deny control exists may a
later schema revision define a composed-enforcement observation. The current
provisional schema must not encode that stronger claim.

`NOT_OBSERVABLE_LIVE` is not a credential non-leak proof. Real execution never
knows the credential/token bytes needed to construct a canary comparison.
Credential/token canary counts belong only to synthetic evidence. A generic
live scan may check retained artifacts for forbidden field names and known
test markers, but it must be labeled as a generic policy scan rather than a
secret non-leak measurement.

No evidence field contains credential paths beyond the already-public
sandbox-relative policy path, credential metadata, expiry, token/cookie/header
values, raw prompt, raw provider output, response bodies, DNS payloads, or
provider request identifiers that could carry secrets.

## Failure classification

The first primary failure is immutable; cleanup is recorded independently.
Stable classes include:

| Class | Examples | Result |
| --- | --- | --- |
| `PRECONDITION_BLOCKED` | repository/config/artifact/launcher/policy drift; stale or absent owner authorization | No marker before authority; no real launch |
| `LOCAL_AUTH_REJECTED` | exact authenticate failure or malformed response | `BLOCKED`; no session/model authority |
| `REFRESH_BLOCKED` | refresh unavailable, denied, exhausted, revoked, or attempts unbounded | `BLOCKED`; no model request |
| `NETWORK_POLICY_BLOCKED` | unexpected CONNECT/SNI/port/address/ECH/different-host redirect; auth drain failure; second tunnel | `BLOCKED`; revoke all egress |
| `REDIRECT_POLICY_UNENFORCEABLE` | same-host OAuth or model redirect cannot be denied or counted under opaque TLS | Design/implementation `BLOCKED`; no real authority |
| `MODEL_IDENTITY_BLOCKED` | provider/model/base URL/protocol/SDK/config drift | `BLOCKED`; no model request |
| `MODEL_SERVICE_REJECTED` | 401/403/404 or provider authentication rejection | `BLOCKED`; no replay |
| `MODEL_RATE_LIMITED` | 429 | `BLOCKED`; no retry |
| `MODEL_TIMEOUT` | connect, idle, stream, or total deadline | `BLOCKED`; no retry |
| `MODEL_UPSTREAM_FAILED` | 5xx, transport reset, malformed TLS/SSE | `BLOCKED`; no retry |
| `ACP_PROTOCOL_BLOCKED` | frame/order/id/shape/callback violation | `BLOCKED`; no second ACP operation after terminal failure |
| `MODEL_OUTPUT_BLOCKED` | oversized/malformed/noncanonical output | `BLOCKED`; no retry |
| `AOSPLAN_REJECTED` | parser, DAG, or compiler-policy rejection | `BLOCKED`; no board mutation |
| `RESOURCE_LIMIT_BLOCKED` | pids, memory, fd, bytes, transcript, or concurrency bound | `BLOCKED`; kill and drain |
| `CLEANUP_FAILED` | process/socket/thread/scope/cgroup/mount residue | Primary result preserved; overall qualification not complete |
| `EVIDENCE_FAILED` | marker/result canonicalization or persistence failure | Overall qualification blocked |

Diagnostics are bounded, typed, content-free, and never include provider body
text or exception representations that might embed headers or tokens.

## Credential-free synthetic qualification matrix

All implementation tests precede any request for real authority. Synthetic
state roots, disjoint zero-byte credential canaries, local TLS origins, fake
DNS, and fixture certificates must be structurally incapable of selecting the
real credential or public Kimi endpoints.

| # | Required proof |
| --- | --- |
| 1 | Exact binary initialize through production Bubblewrap and namespace launcher. |
| 2 | Exact strict packaged initialize validation, including remediated absolute legacy command; all shape mutations reject. |
| 3 | Synthetic authenticate success and local rejection with no model traffic after rejection. |
| 4 | Exact `session/new` ordering, empty workspace, no MCP servers, and deterministic model binding. |
| 5 | Exactly one `session/prompt` and one decrypted fixture model request. |
| 6 | Second prompt, second session, post-terminal operation, and concurrent prompt reject. |
| 7 | `max_steps_per_turn=1` pre-step enforcement, SDK retry, step retry, queued follow-on, tool-call continuation, malformed/nonterminal stop, 401-refresh-replay, rate-limit, timeout, and transport paths cannot produce a second model request. |
| 8 | Model allowlist admits only `api.kimi.com:443` with exact CONNECT/SNI. |
| 9 | Auth allowlist admits only `auth.kimi.com:443` while in `AUTH_WINDOW`. |
| 10 | Alternate host, IP literal, port, SNI, ECH, second ClientHello, DNS-special address, new host, and different-host redirects reject; exact OAuth and model fixtures exercise 301/302/303/307/308 same-host redirects, and any automatic follow keeps Strategy B blocked. |
| 11 | Refresh-not-needed and refresh-required fixtures exercise official-client behavior with exact bounded fetch-call accounting and explicitly unknown opaque wire-request count. |
| 12 | Refresh failure/exhaustion stops before model service and cannot invoke login/device flow. |
| 13 | Model 401 proves auth already revoked and no forced-refresh replay reaches either external fixture. |
| 14 | Model 403/404/429/5xx/connect reset/idle timeout/total timeout each terminate without retry. |
| 15 | Valid SSE split across arbitrary chunks yields one terminal `end_turn`; malformed, truncated, duplicate-terminal, post-terminal, and oversized streams reject. |
| 16 | Frame, transcript, prompt, output, byte, fd, pid, memory, connection, and time limits fail closed. |
| 17 | Every forbidden ACP filesystem, terminal, permission, elicitation, tool, MCP, skill, plugin, hook, subagent, and background callback rejects. |
| 18 | Canonical prompt is byte-stable, under 4 KiB, public, and free of credential/private/repository data. |
| 19 | One canonical one-task `AOSPLAN/1` output parses and passes compilation dry-run. |
| 20 | Duplicate keys, extra fields, prose/fence wrappers, multiple tasks, invalid DAG/enums/limits, and compiler-policy failures reject. |
| 21 | Auth-to-model transition interrupts both relay directions, joins once against one deadline, proves empty auth workers, then releases model CONNECT. |
| 22 | Overlapping auth tunnels deny; sequential source-required auth behavior stays within the approved bound; fifty denial/drain repetitions remain stable. |
| 23 | Provider process, descendants, relay threads, sockets, scopes, cgroups, mounts, temp files, and namespace workers drain on every exit path. |
| 24 | Controller crash, mediator crash, Kimi crash, parent death, SIGTERM, SIGKILL, EOF, and stuck half-close leave no reachable provider or residue. |
| 25 | Credential canaries never enter ACP, logs, evidence, mediator buffers, prompt/output, exceptions, or fixture observations. |
| 26 | Authorization, cookie, access-token, and refresh-token canaries are absent from all controller/mediator/evidence/log output. |
| 27 | Empty workspace cannot reach checkout, `.git`, board/controller data, other provider state, ambient home, API keys, SSH, cloud, or proxy state. |
| 28 | Attempt/result namespace cannot overlap, read, replace, link to, or mutate historical Level-1 evidence. |
| 29 | Exact request identity is `POST /coding/v1/chat/completions`, wire model `kimi-for-coding`, streaming enabled, usage requested, and recorded transport source-qualified. |
| 30 | Auto-update, telemetry, tips, usage polling, background tasks, fallback providers, and hidden inference produce zero requests. |
| 31 | No session or model request occurs after the first terminal failure, including failures raised during cleanup or evidence writing. |
| 32 | Exact candidate commit passes the focused native WSL suites, broader Kimi/M4/provider/Demo 0 regressions, full native WSL suite, Windows portable regressions, compile/static checks, secret scans, and `git diff --check`. |

The exact-binary fixture is authoritative for client behavior. Pure protocol
fixtures are necessary but cannot substitute for native packaged-runtime
proof. Synthetic TLS termination is permitted only inside tests with synthetic
credentials and local origins; production mediator code remains opaque.
Fixture behavior cannot guarantee that a live origin will not send a redirect,
so following a same-host redirect is a design blocker, not an accepted test
observation.

## Future real-run acceptance criteria

No owner may authorize the run described here while
`BLOCKING_FINDING=OPAQUE_SAME_ORIGIN_REDIRECT_REQUEST_MULTIPLICATION` remains.
After a separately authorized resolution, revised design, implementation, and
review have been preserved on GitHub with both clones clean and exact, a later
owner may consider one run. The pre-real packet must name the exact candidate
commit and every digest/bound above.

`COMPLETE` requires all of the following in the same run:

1. preflight repository, host, artifact, launcher, config, profile, policy,
   namespace, scope, and residue checks pass;
2. new Planner attempt marker 1 is atomically consumed exactly once;
3. the historical Level-1 evidence is unchanged byte-for-byte;
4. exact initialize response validates;
5. exact `authenticate(methodId="login")` succeeds locally;
6. token preparation either uses cached state without an auth tunnel or
   succeeds only through `auth.kimi.com:443` within the separately approved
   source-proven upper bound; evidence distinguishes direct tunnel observation
   from source-bound inference;
7. one session binds the exact provider/model/base URL/protocol;
8. one canonical prompt is sent;
9. one and only one application model request reaches
   `api.kimi.com:443` and no other host;
10. one terminal SSE turn completes without retry, fallback, tool, callback,
    background inference, or second prompt;
11. output is within bounds and passes exact `AOSPLAN/1` parsing plus
    controller compilation dry-run;
12. content-free evidence persists canonically;
13. all egress is revoked and all provider/relay processes, threads, sockets,
    namespaces, scopes, cgroups, mounts, and temporary entries are gone; and
14. cleanup completes without masking the primary result.

Any unmet or unknown criterion yields `BLOCKED`, never partial success.
Credential recognition, refresh success, server acceptance, inference, and
`AOSPLAN/1` validity remain separate typed facts; one cannot imply another.

## Cleanup and residue contract

Cleanup begins on the first terminal success or failure and is idempotent:

1. atomically revoke mediator admission;
2. interrupt both directions of every active tunnel before joining workers;
3. close the CONNECT listener and ACP input;
4. terminate the exact provider process group and workload cgroup;
5. wait against one bounded cleanup deadline;
6. kill any remaining descendant through the qualified freezer/cgroup path;
7. unmount the private provider state and destroy synthetic workspace/tmpfs;
8. prove zero provider, mediator, namespace, relay-thread, listener, external
   socket, scope, cgroup, frozen-process, mount, and temp-file residue; and
9. persist cleanup status independently from the primary classification.

An incomplete census is not zero. Cleanup failure makes the overall
qualification non-complete even if a valid proposal was already received.
No cleanup action may reopen ACP, credential, auth, model, evidence, or
network authority.

## Conditional resolution and implementation outline — not authorized

The current next step is not implementation. It is a separate owner decision
about whether to investigate or remediate redirect handling:

1. **Redirect characterization authority.** If separately authorized, run
   credential-free exact-binary OAuth and model fixtures for same- and
   different-host 301/302/303/307/308 behavior. This characterizes the blocker
   but cannot authorize a real run.
2. **Resolution decision.** If either transport follows a same-host redirect,
   stop and ask whether to qualify a new pinned client/transport design or
   select Strategy C. No opaque-mediator implementation begins.
3. **Revised design and independent review.** A proposed redirect-deny control
   receives a new artifact/policy identity, threat model, synthetic plan, and
   independent review. Only a reviewed fail-closed resolution may change this
   design from `BLOCKED`.
4. **New implementation-plan gate.** Only after the revised design is approved
   may a detailed implementation plan be written and separately authorized.

If and only if that gate is later earned, likely implementation slices would
use the WSL clone as sole writer and preserve each completed slice before the
next:

1. **Pure policy and protocol types.** Add exact enums, revised schemas, state
   machines, limits, canonical prompt, and pure tests. Reuse strict ACP and
   `AOSPLAN/1` types without enabling real execution.
2. **Opaque egress mediator.** Implement sealed task policy, strict CONNECT
   and ClientHello/SNI gate, DNS/SSRF controls, `AUTH_WINDOW -> AUTH_DRAINING
   -> MODEL_ONCE`, typed evidence, and complete synthetic socket tests.
3. **Planner namespace/runtime.** Extend the qualified descriptor, Bubblewrap,
   launcher, freezer, cgroup, environment, and cleanup boundaries for the new
   disjoint gate. Do not modify the historical runner's semantics or files.
4. **Exact-binary synthetic integration.** Run pinned Kimi 0.36.1 against
   local OAuth/model TLS fixtures; prove refresh, endpoint, streaming,
   request count, forbidden replay/callbacks, output admission, and residue.
5. **Evidence and conditional entry point.** Add the disjoint new namespace,
   no-overwrite marker/result logic, exact candidate/authorization binding,
   and a CLI that refuses to run without a future explicit owner packet.
6. **Pre-real qualification and independent review.** Run all matrices and
   regressions, inspect the diff, resolve every Critical/Important finding,
   publish the exact tested commit, synchronize both clones, and produce a
   content-free pre-real closure.
7. **Hard stop.** Request a separate explicit authorization for one Planner
   attempt. Implementation authorization never implies real-run authority.

Likely new modules should remain focused (`kimi_planner_qualification.py`,
`kimi_planner_egress.py`, `kimi_planner_runtime.py`, a canonical runner,
fixtures, tests, and a pre-real closure). Final file names and slice contents
belong in a later implementation plan only after the redirect blocker is
resolved and the owner approves a revised written spec; they are not created
by this design slice.

Every implementation slice follows:

```text
implement -> test -> relevant/adversarial review -> inspect diff
-> git diff --check -> commit -> push -> git ls-remote verification
-> fast-forward the other clone -> prove both clones clean and exact
```

## Threat model summary

The design fails closed against:

- a compromised or surprising model response attempting to acquire authority;
- exact-client drift, config overrides, hidden fallback, automatic retries,
  background inference, update, telemetry, or new hosts;
- credential exfiltration through controller state, mediator logs, ACP,
  evidence, prompt, model output, exceptions, or fixtures;
- TLS destination confusion through CONNECT/SNI mismatch, ECH, DNS rebinding,
  special addresses, different-host redirects, IP literals, or alternate
  ports;
- refresh-to-model race and 401 refresh/replay;
- malformed/oversized ACP, SSE, JSON, or AOSPLAN data;
- duplicate attempts, evidence replacement, symlink/hard-link races, and
  historical Level-1 mutation;
- provider, relay, namespace, scope, cgroup, socket, mount, or frozen-process
  residue; and
- cleanup or evidence failures masking the primary result.

Out of scope remain malicious kernel/root, provider-side behavior after an
accepted request, traffic-analysis secrecy, quota prediction, generalized
provider infrastructure, Builder authority, M5 worktrees, scheduler
admission, F2, deployment, and automatic recovery/login.

Same-host redirects are not listed as mitigated: they are the explicit blocker
that prevents implementation and real execution under the current design.

## Review and next gates

This design earns only a reviewable blocked documentation checkpoint. The next
valid owner decision after repository publication is whether to authorize a
credential-free redirect characterization or choose Strategy C. It is not an
implementation-plan or implementation gate.

Required sequence from here:

```text
written-spec owner review
  -> separate redirect-characterization or resolution-path authority
  -> exact-client/transport qualification with no real credential/provider
  -> revised design plus fresh independent architectural/security review
  -> if and only if the redirect blocker is closed:
       separate implementation-plan authorization
       -> implementation plan
       -> separate implementation authorization
       -> implementation plus credential-free synthetic qualification
       -> fresh independent architectural/security review
       -> exact-commit publication and clone synchronization
       -> separate one-run real Planner authorization
       -> at most one new Planner qualification attempt
  -> otherwise: Strategy C decision
```

No step inherits authority from an earlier step. In particular:

```text
REAL_PLANNER_REQUEST_AUTHORIZED=NO
REAL_LEVEL1_RETRY_AUTHORIZED=NO
REAL_LEVEL1_ATTEMPT_AUTHORIZED=NO
HISTORICAL_LEVEL1_REAL_ATTEMPT_COUNT=1
REAL_ATTEMPT_COUNT=1
CURRENT_PLANNER_QUALIFICATION_ATTEMPT_COUNT=0
REAL_CREDENTIAL_ACCESS_AUTHORIZED=NO
PROVIDER_NETWORK_AUTHORIZED=NO
MODEL_INFERENCE_AUTHORIZED=NO
F2_AUTHORIZED=NO
```

Models reason. AgenticOS guarantees.
