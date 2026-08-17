# F1 Kimi Combined Single-Real Planner Qualification Design

## Status and authorization boundary

```text
F1_KIMI_PLANNER_QUALIFICATION_DESIGN=READY_FOR_FINAL_REVIEW
DESIGN_WORK_AUTHORIZED=YES
WRITTEN_SPEC_APPROVED=NO
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
AUTHORITATIVE_BASELINE=b08a6ddf2955f56dce50a86b03c8b9bf2824b48e
KIMI_VERSION=0.36.1
KIMI_SOURCE_COMMIT=13d86f8b7bb2443a3b8222e7d94deb0a66429f8e
KIMI_EXECUTABLE_SHA256=78c07b255e0bdc8dfe90d0cbd3204a3d862957394a08ca99c6e31144732451c7
KIMI_NAMESPACE_LAUNCHER_SHA256=800dbc83e1d1dc7efd127151d257025b4160ae92dfc23d13ed175f09778d15dc
```

This document specifies the Level-A architectural design for the first bounded,
subscription-backed Kimi Planner qualification turn in AgenticOS. This is
documentation and design work only. It does not authorize implementation or
execution. It does not create an attempt marker, read or mount the real
credential, inspect credential metadata, contact Kimi endpoints, authenticate
against live server state, create a real session, send a real prompt, consume
quota, perform model inference, or begin F2.

The historical Level-1 qualification result is immutable:

```text
HISTORICAL_F1_KIMI_LEVEL1_RESULT=BLOCKED
HISTORICAL_REASON=AUTH_METHOD_SHAPE
HISTORICAL_REAL_ATTEMPT_COUNT=1
REAL_LEVEL1_RETRY_AUTHORIZED=NO
```

The subsequent launcher and validator remediation proved that an AgenticOS
infrastructure defect was corrected. It does not retroactively alter what the
historical attempt observed, and it does not earn any server authentication or
model inference claim. Future Planner qualification success must never rewrite
or obscure that historical record.

## Specification authoring metadata

- **Role:** New Specification Remediation Agent (not the independent reviewer)
- **Active Model:** OpenAI GPT-5 (Codex). The runtime exposed no finer service
  point-version identifier; no unexposed version is inferred.
- **Task Scope:** Level-A design remediation for F1 Kimi Planner Qualification
  (Strategy B) against the completed independent review
- **Work Mode:** Pure design and documentation (no source code implementation, no network egress, no credential access)

## Strategy decision

Strategy B is the approved strategy for the F1 Kimi qualification milestone:

```text
STRATEGY_A_LEVEL1_GENERATION_2=REJECTED
STRATEGY_B_COMBINED_SINGLE_REAL_PLANNER_QUALIFICATION=SELECTED
STRATEGY_C_ABANDON_KIMI=DEFERRED
```

| Strategy | Decision | Rationale |
| --- | --- | --- |
| **A. Level-1 generation 2** | **REJECTED** | Does not directly advance the First Autonomous Build milestone; repeats a lower-level local authentication proof whose infrastructure defect is already understood and remediated, consuming real credential authority without yielding a Planner proposal. |
| **B. Combined Planner qualification** | **SELECTED** | Directly proves the subscription-backed Planner capability required by Milestone F1 while preserving strict credential blindness, one-prompt/one-model-tunnel authority, and fail-closed egress mediation. |
| **C. Abandon Kimi F1** | **DEFERRED** | No current evidence establishes an intrinsic Kimi-specific security or protocol blocker requiring provider replacement. |

Under Strategy B, authentication is a prerequisite checkpoint inside the
higher-level Planner qualification rather than a separate isolated attempt. A
future successful Planner qualification will be represented as:

```text
F1_KIMI_PLANNER_QUALIFICATION=COMPLETE
HISTORICAL_F1_KIMI_LEVEL1_RESULT=BLOCKED
HISTORICAL_REASON=AUTH_METHOD_SHAPE
HISTORICAL_REAL_ATTEMPT_COUNT=1
LOCAL_CREDENTIAL_RECOGNIZED_DURING_PLANNER=YES
CREDENTIAL_REFRESH_STATE=NOT_REQUIRED|COMPLETED_AND_PERSISTED
MODEL_TUNNEL_ADMISSION_COUNT=1
ACP_REAL_PROMPT_COUNT=1
PLANNER_PROPOSAL_COUNT=1
AOSPLAN_VALID=YES
NO_SECOND_MODEL_TUNNEL=YES
AUTH_EGRESS_REVOKED_BEFORE_MODEL=YES
NO_GENERAL_PROVIDER_INTERNET=YES
CREDENTIAL_CONTENT_ACCESSED_BY_AGENTICOS=NO
```

This remains `STRATEGY_B=VIABLE_WITH_CORRECTIONS`; the corrections in this
document make the selected strategy internally consistent but do not authorize
implementation or a real run.

## Exact-source findings that constrain the design

The source statements below are bound to Kimi Code CLI `0.36.1`, source commit
`13d86f8b7bb2443a3b8222e7d94deb0a66429f8e`, its pinned dependency graph,
and the exact production configuration. They are not live-provider evidence.

| Concern | Source-bound conclusion |
| --- | --- |
| OAuth transport | `packages/oauth/src/oauth.ts::postForm()` calls global `fetch()` without `redirect: "manual"` or another explicit redirect-deny policy. |
| OAuth retry loop | `refreshAccessToken()` uses `maxRetries ?? 3` as the total top-level fetch-call loop bound. It does not bound requests produced inside one fetch by redirects. |
| Credential storage | `FileTokenStorage` selects `credentials/kimi-code.json`. `save()` creates `kimi-code.json.tmp.<decimal-pid>.<8-lowercase-hex>`, writes the complete JSON, calls file `fsync`, closes, `chmod(0600)`, and renames over the leaf. It does not fsync the parent directory. |
| Refresh lock | Production passes the Kimi home as `configDir`. On Linux the OAuth manager prepares task-local `oauth/kimi-code`, and `proper-lockfile` transiently creates `oauth/kimi-code.lock`; failure to prepare or acquire the lock fails refresh. |
| Model transport | The OpenAI legacy adapter constructs pinned `openai@6.34.0` with `maxRetries: 0`, but supplies no explicit redirect-deny policy. |
| Model 401 recovery | `KimiForCodingProvider.resolveAuth()` may force one refresh and replay after a structured in-process `APIStatusError` 401. The live opaque mediator cannot see that status; revoking auth and consuming the model-tunnel allowance makes the replay unreachable on the network. |
| Proxy installation | The exact CLI installs its global proxy dispatcher before constructing clients and recognizes lowercase `https_proxy`; exact-binary testing must still prove both OAuth and model traffic use only the admitted proxy. |

Therefore a single admitted end-to-end TLS tunnel is not proof of one HTTP
request. The same-origin `301`, `302`, `303`, `307`, or `308` behavior of both
transports is compatibility evidence to characterize, not a mediator-enforced
request-count invariant.

## Normative request accounting

The six counts are distinct and must never be collapsed into a generic
"request count."

| Metric | Bound | Authority / provenance |
| --- | --- | --- |
| `ACP_REAL_PROMPT_COUNT` | `<= 1` | `DIRECT_CONTROLLER_ENFORCEMENT` |
| `MODEL_ALLOWANCE_CLAIM_COUNT` | `<= 1` | `DIRECT_MEDIATOR_ENFORCEMENT`; remains consumed after any post-claim failure |
| `MODEL_TUNNEL_ADMISSION_COUNT` | `<= 1` | `DIRECT_MEDIATOR_ENFORCEMENT` |
| `AUTH_TUNNEL_ADMISSION_COUNT` | `<= 3` | `DIRECT_MEDIATOR_ENFORCEMENT`; three is the separately approved defense-in-depth tunnel bound |
| `MODEL_HTTP_REQUEST_COUNT` | No live exact bound | `NOT_DIRECTLY_OBSERVABLE_UNDER_OPAQUE_TLS` |
| `AUTH_HTTP_REQUEST_COUNT` | No live exact bound | `NOT_DIRECTLY_OBSERVABLE_UNDER_OPAQUE_TLS` |
| `PLANNER_PROPOSAL_COUNT` | `<= 1` | `DIRECT_CONTROLLER_ENFORCEMENT` |
| `SDK_RETRY_CONFIGURATION` | `0` for the model SDK | `SOURCE_BOUND_CONFIGURATION` |
| `OAUTH_TOP_LEVEL_FETCH_CALL_BOUND` | `<= 3` when refresh runs | `SOURCE_BOUND_CONFIGURATION`, not a wire-request observation |
| `LOOP_ATTEMPT_COUNT` | `<= 1` | `DIRECT_CONTROLLER_OBSERVATION` plus `SOURCE_BOUND_CONFIGURATION` |
| `LOOP_STEP_COUNT` | `<= 1` | `DIRECT_CONTROLLER_OBSERVATION` plus `SOURCE_BOUND_CONFIGURATION` |

The earned live security claim is limited to one controller prompt, one model
tunnel admission, no second model tunnel, no cross-host redirect egress, no
auth reopening after model admission, model SDK retries configured to zero,
one loop attempt, one loop step, and at most one accepted proposal. Same-origin
HTTP request multiplication remains not directly observable by AgenticOS under
opaque TLS.

```text
ACP_REAL_PROMPT_COUNT<=1
MODEL_TUNNEL_ADMISSION_COUNT<=1
NO_SECOND_MODEL_TUNNEL=GUARANTEED
NO_CROSS_HOST_REDIRECT_EGRESS=GUARANTEED
NO_AUTH_REOPEN_AFTER_MODEL_ADMISSION=GUARANTEED
SDK_CONFIGURED_RETRIES=0
LOOP_ATTEMPTS=1
LOOP_STEPS=1
MODEL_HTTP_REQUEST_COUNT=NOT_DIRECTLY_OBSERVABLE_UNDER_OPAQUE_TLS
AUTH_HTTP_REQUEST_COUNT=NOT_DIRECTLY_OBSERVABLE_UNDER_OPAQUE_TLS
```

## Component trust boundaries and non-reuse rationale

AgenticOS enforces strict separation between tasks, providers, and egress
channels. The design explicitly avoids reusing existing egress brokers:

### Why M4B Connected Build HTTPS Broker is NOT reused

The M4B Connected Build broker (`M4B HTTPS broker`) terminates worker TLS inside
the broker, inspects and parses application HTTP/1.1, and originates a separate
upstream TLS connection to external package registries. Its published security
claim is strictly one external host per task, designed for artifact fetching,
and it explicitly excludes provider credential handling. Terminating TLS would
expose provider secrets to the broker, violating the official-client credential
boundary.

### Why the existing Application-Level Provider Broker is NOT reused

The existing application-level provider broker terminates HTTP requests from
workers, strips client Authorization headers, and injects a controller-held
API key or bearer token into the upstream request. This mechanism was designed
for headless API integrations where AgenticOS manages credentials directly. For
subscription-backed Kimi execution, the official client owns the OAuth token
lifecycle and refresh credentials. Reusing the provider broker would require
AgenticOS to inspect, parse, or inject credentials, directly violating the
credential-blindness invariant.

### Summary of earned and unearned authority

| Actor / Component | May | Must NOT |
| --- | --- | --- |
| **Owner** | Authorize written specification review; separately authorize future implementation; separately authorize single real qualification run | Have intent inferred or assumed without explicit authorization packets |
| **Controller** | Validate pinned public artifacts/config; drive stdio ACP protocol; enforce execution bounds; persist content-free evidence; kill and census processes | Read credential bytes; inspect tokens/cookies; treat model output as authority; grant general Internet |
| **Exact Kimi 0.36.1 Client** | Read the mounted credential namespace; perform official cached-token checks and OAuth refresh; use the sole admitted model tunnel | Access checkout or repository files; access other credentials; access controller state; use shell, tools, or MCP; reach ambient networks |
| **Opaque Egress Mediator** | Authenticate task capability; enforce state transitions; verify exact hostname; reuse the qualified address classifier; verify ClientHello SNI equality; relay encrypted bytes; enforce tunnel bounds | Terminate TLS; decrypt traffic; parse HTTP headers/bodies/statuses; count same-tunnel HTTP requests; inspect Authorization/Cookie headers; inspect prompts/responses/SSE; follow redirects; retry requests |
| **Model Output** | Supply untrusted bounded candidate JSON text | Assign authoritative task IDs; assign roles/priorities; mutate board state; execute shell commands; bypass compiler checks |
| **Evidence Writer** | Persist canonical, content-free metrics, SHA-256 digests, and typed status flags | Persist tokens, cookies, Authorization headers, raw prompts, raw responses, raw SSE chunks, or TLS secrets |

## Dedicated opaque task-scoped provider egress mediator

To enforce network boundaries while maintaining end-to-end TLS encryption
between the official Kimi client and Moonshot origins, AgenticOS introduces a
new, dedicated component: the `KimiPlannerEgressMediator`.

### Precise definition of "Opaque"

The egress mediator is strictly an opaque byte relay with capability-bound
filtering. Its capabilities and prohibitions are formally defined:

#### The mediator MAY:
1. Authenticate the AgenticOS task capability over a dedicated Unix control socket;
2. Enforce task identity, generation identity, and invocation limits;
3. Enforce the normative network state machine (`AUTH_WINDOW -> MODEL_ONCE -> CLOSED`);
4. Enforce exact requested destination hostname and port (`auth.kimi.com:443` or `api.kimi.com:443`);
5. Resolve approved hostnames using a bounded, fail-closed DNS policy;
6. Reject every destination prohibited by the directly reused `AOSADDR/1` classifier;
7. Inspect the initial pre-TLS bytes of the connection solely to extract and verify the TLS `ClientHello` Server Name Indication (SNI);
8. Verify exact positive equality between the CONNECT request hostname and the `ClientHello` SNI;
9. Relay encrypted TLS byte streams bidirectionally between the sandboxed client and the verified origin;
10. Enforce strict tunnel-admission counts, idle timeouts, byte quotas, and lifecycle deadlines;
11. Collect and record content-free lifecycle evidence (timestamps, byte counts, connection counts, transition states).

#### The mediator MUST NOT:
1. Terminate TLS or establish a TLS endpoint with the client or origin;
2. Possess, generate, or inspect TLS private keys, certificates, or session secrets;
3. Decrypt or inspect application-layer plaintext traffic;
4. Parse HTTP request or response lines, headers, or bodies;
5. Inspect `Authorization`, `Cookie`, `Set-Cookie`, or any authentication header;
6. Inspect request bodies, model prompts, model completions, or SSE event data;
7. Rewrite, inject, or modify HTTP payloads or headers;
8. Inject provider authentication tokens or API keys;
9. Follow HTTP redirects (301, 302, 303, 307, 308) or initiate secondary requests;
10. Retry failed provider requests or re-establish severed connections.

### Client network view and namespace isolation

The Kimi provider sandbox operates in a strictly isolated Linux network namespace:
- **No Default Route:** The sandbox network namespace contains no default gateway and no external network interfaces (`eth0`, `wlan0`, etc.).
- **No Ambient DNS:** The sandbox has no `/etc/resolv.conf` and cannot perform direct DNS resolution.
- **Single Loopback Listener:** The sandbox contains only a loopback interface (`lo`) with a single TCP listener at `127.0.0.1:18080`.
- **Handoff Mechanism:** The listener socket is created inside the sandboxed network namespace by the namespace launcher, which transfers the listening file descriptor over a private Unix control socket using `SCM_RIGHTS` to the host-side mediator. The launcher closes its descriptor copies prior to executing the Kimi binary.
- **Environment Scrubbing:** The execution environment contains only lowercase `https_proxy=http://127.0.0.1:18080`. All uppercase proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`), `no_proxy`, and ambient networking variables are removed.
- **No Bypass:** No ambient proxy, SOCKS proxy, inherited socket, or direct IP connection can bypass the mediator.

Before implementation review, credential-free exact-binary tests must run both
the Kimi OAuth transport and the Kimi/OpenAI model transport with the exact
pinned executable, production config, proxy installation path, and sterile
environment. They must prove that lowercase
`https_proxy=http://127.0.0.1:18080` is the only admitted proxy authority; no
default route or ambient DNS exists; uppercase proxy variables, `ALL_PROXY`,
SOCKS authority, `no_proxy`, and inherited network file descriptors are absent;
a direct external-IP attempt fails; and every synthetic provider connection
arrives at the task mediator. An invalid proxy configuration must fail the
preflight rather than exercise the pinned CLI's source behavior of warning and
connecting directly.

### Host and SNI binding positive equality chain

Every outbound connection through the mediator must satisfy positive equality
across five distinct layers before any byte is relayed:

```text
Sealed Task Policy Grant
  == Strict CONNECT Request Hostname:Port
  == Bounded DNS Query Hostname
  == TLS ClientHello SNI
  == Approved Moonshot Provider Hostname
```

If any mismatch, missing SNI, second `ClientHello`, Encrypted Client Hello
(ECH), or unapproved hostname is observed, the mediator immediately terminates
the connection and enters `CLOSED`.

### Approved destination census

Only two external destinations are permitted for the entire qualification:

| Purpose | Exact Hostname & Port | Permitted State | Protocol Policy |
| --- | --- | --- | --- |
| **OAuth Token Refresh** | `auth.kimi.com:443` | `AUTH_WINDOW` only | Source-bound top-level form-encoded `POST /api/oauth/token` fetch calls via end-to-end TLS; at most 3 tunnels lifetime; redirect-generated HTTP count opaque |
| **Model Inference Turn** | `api.kimi.com:443` | `MODEL_ONCE` only | Source-bound initial `POST /coding/v1/chat/completions` via end-to-end TLS; exactly 1 tunnel lifetime; same-origin HTTP count opaque |

All other hosts (`code.kimi.com`, `cdn.kimi.com`, `telemetry-logs.kimi.com`,
`www.kimi.com`, Moonshot open-platform endpoints, GitHub, IP literals, alternate
ports) are denied and cause immediate qualification failure.

### Bounded fail-closed DNS / SSRF resolver policy

The mediator must directly compose the already-qualified
`agenticos.sandbox.special_addresses.validate_address` implementation and its
versioned `AOSADDR/1` semantics. The Kimi policy may impose more restrictions,
but it must not own a smaller parallel table or copy a hand-written subset.

The fail-closed DNS policy is:
1. **Exact Hostname Only:** Queries only the exact approved ASCII hostname (`auth.kimi.com` or `api.kimi.com`).
2. **Deadline Bound:** Bounded resolution timeout of 2.0 seconds.
3. **Record Count Bound:** Caps DNS answer processing at a maximum of 8 records.
4. **Qualified Address Verdict:** Every answer is parsed to an IP address and
   passed directly to `validate_address`; only an `ALLOWED` verdict may reach
   numeric connect. The existing classifier rejects all applicable
   unspecified, loopback, private, link-local, shared/CGNAT, multicast,
   broadcast, documentation, benchmarking, reserved/future-use, protocol
   assignment, mapped/compatible IPv6, NAT64, 6to4, Teredo, and other
   `AOSADDR/1` special-purpose classes.
5. **Numeric Sockaddr Binding:** Outbound origin connection is established strictly by validated numeric IP sockaddr; the hostname is never passed to ambient OS routing.

Any classifier version drift, exception, invalid type, incomplete answer set,
or non-`ALLOWED` verdict yields `DNS_POLICY_FAILED`; there is no fallback table.

### End-to-end TLS integrity

TLS operates strictly end-to-end between the pinned Kimi binary and Moonshot
servers:
- `MAX_CLIENT_HELLO_BYTES=4096` is the proposed bounded production limit. The
  mediator incrementally buffers only until one complete initial ClientHello is
  available. More than 4096 bytes fails closed; bytes are never truncated and
  relayed as if validation succeeded.
- The mediator validates handshake type `0x01`, requires one visible exact SNI,
  and checks exact equality with the CONNECT hostname before origin relay.
- ClientHello extension `0xfe0d`, or any other separately qualified ECH form
  that prevents trustworthy visible-SNI enforcement, yields `BLOCKED`; CONNECT
  authority alone is never trusted as a fallback.
- Any second ClientHello after the first accepted ClientHello, including a
  HelloRetryRequest-driven re-handshake, yields `BLOCKED` and closes the tunnel.
  Renegotiation or re-handshake cannot obtain a second SNI decision.
- The mediator does not modify, intercept, or resign TLS certificates.
- The Kimi client independently verifies the Moonshot origin X.509 certificate
  against the bundled CA trust store.
- Raw `ClientHello` bytes, TLS records, and encrypted payload bytes are never
  persisted to disk or logged.

Writing 4096 into this design does not earn the bound. A credential-free
exact-binary test with exact production TLS/config/proxy conditions must prove
that the normal pinned-client ClientHello fits. Negotiated TLS version and
certificate acceptance are not directly visible to the live opaque mediator.

## Network state machine

The normative network state machine governs all egress authority:

```text
             +-----------------------+
             |         START         |
             +-----------------------+
                         |
                         v
             +-----------------------+
             |      AUTH_WINDOW      |  <--- auth.kimi.com:443 admitted
             +-----------------------+       (0-1 active, max 3 total)
                         |
           CONNECT api.kimi.com:443
           (Atomic Claim; Gated Admission)
                         |
                         v
             +-----------------------+
             |     AUTH_DRAINING     |  <--- auth.kimi.com admission REVOKED;
             +-----------------------+       active auth tunnels interrupted
                         |
                         v
             +-----------------------+
             |      MODEL_ONCE       |  <--- api.kimi.com:443 admitted
             +-----------------------+       (exactly 1 tunnel lifetime)
                         |
            Model Tunnel Terminated
            (or any failure/EOF)
                         |
                         v
             +-----------------------+
             |        CLOSED         |  <--- All egress permanently DENIED
             +-----------------------+
```

### State definitions and transition rules

#### 1. START
- Initial state prior to client launch.
- No network tunnels active; proxy listener ready.

#### 2. AUTH_WINDOW
- Admitted destination: `auth.kimi.com:443` only.
- Purpose: Permits the official Kimi client to perform its own OAuth refresh machinery (`POST /api/oauth/token`) if the cached token is expired or approaching expiry.
- Concurrency limit: Exactly zero or one active auth tunnel at any given moment.
- Lifetime allowance: At most 3 auth tunnels permitted for the task lifetime (`AUTH_TUNNEL_ADMISSION_COUNT <= 3`).
- Rejection of Model Host: Any attempt to connect to `api.kimi.com:443` initiates an immediate atomic transition to `AUTH_DRAINING`.

#### 3. AUTH_DRAINING and Atomic Model Transition
- Trigger: The arrival of the first `CONNECT api.kimi.com:443` request.
- **Single synchronization authority:** One mediator-owned transition lock and
  state record govern the entire `AUTH_WINDOW -> AUTH_DRAINING -> MODEL_ONCE`
  operation. No relay worker, controller callback, or cleanup path may mutate
  admission state independently.
- **Normative transition order:** While the first model CONNECT remains pending,
  the synchronization authority must:
  1. atomically claim the sole model allowance exactly once;
  2. set auth admission permanently revoked;
  3. reject every new auth admission;
  4. cancel pending auth DNS and origin-connect work;
  5. interrupt both directions of every active auth relay socket;
  6. join all auth workers against one bounded deadline;
  7. verify the active-auth registry is empty;
  8. verify no accepted auth connection remains queued;
  9. compose the qualified freezer to stabilize the exact workload and obtain a
     content-blind credential-directory attestation that
     `AUTH_REFRESH_STATE` is `NOT_REQUIRED` or
     `COMPLETED_AND_PERSISTED`; and
  10. only then send CONNECT success, thaw as required, admit the single model
      tunnel, and transition to `MODEL_ONCE`.
- **Crash and failure semantics:** The allowance is spent when step 1 succeeds,
  even if the controller, mediator, or provider crashes before step 10. Any
  drain, freeze, revalidation, attestation, or thaw failure leaves the model
  tunnel unadmitted, revokes all egress, and yields `BLOCKED`. No rollback may
  restore the allowance or auth authority.

#### 4. MODEL_ONCE
- Admitted destination: `api.kimi.com:443` only.
- Allowance: Exactly one model tunnel admitted (`MODEL_TUNNEL_ADMISSION_COUNT <= 1`).
- Permanent Revocation of Auth: `auth.kimi.com` is permanently `DENIED`. It cannot reopen under any circumstances.
- **Suppression of source-owned authorization recovery:** If the pinned client
  enters its source-proven forced-refresh/replay path after a model
  authorization failure, auth admission is denied and no second model tunnel
  can be admitted. AgenticOS does not claim to observe the encrypted status as
  HTTP 401.
- **No Secondary Tunnels:** No second model tunnel may be admitted after any outcome, including:
  - TLS handshake failure;
  - a provider/client inference failure;
  - ACP stream malformation or truncation;
  - Connection timeout or reset;
  - Model refusal or invalid proposal output.
- Any termination of the model tunnel immediately transitions the state to `CLOSED`.

#### 5. CLOSED (MODEL_SPENT / REVOKING / DRAINED)
- All network egress is permanently denied.
- Any subsequent CONNECT request is immediately rejected with HTTP 503.
- All relay workers and proxy listeners are terminated and drained.

### Transport limits and deadlines

| Parameter | Value | Enforcement Mechanism |
| --- | --- | --- |
| **Max Concurrent Tunnels** | 1 | Semaphore / active connection registry |
| **Max Auth Tunnels (Lifetime)** | 3 | Atomic counter in `AUTH_WINDOW` |
| **Max Model Allowance Claims (Lifetime)** | 1 | Atomic counter consumed before drain/revalidation |
| **Max Model Tunnel Admissions (Lifetime)** | 1 | Incremented only when gated admission succeeds |
| **CONNECT Header Buffer Max** | 4,096 bytes | Pre-relay buffer limit |
| **ClientHello Buffer Max** | 4,096 bytes | Incremental fail-closed SNI/ECH inspection; exact-binary qualification required |
| **DNS Resolution Timeout** | 2.0 seconds | Async DNS deadline |
| **Origin Connect Timeout** | 5.0 seconds | TCP handshake deadline |
| **Handshake Idle Timeout** | 5.0 seconds | Post-CONNECT TLS handshake deadline |
| **Encrypted Relay Idle Timeout** | 30.0 seconds | Byte-inactivity deadline; mediator does not parse SSE |
| **Max Upstream Model Bytes** | 65,536 bytes (64 KiB) | Bidirectional stream byte counter |
| **Max Downstream Model Bytes** | 262,144 bytes (256 KiB) | Bidirectional stream byte counter |
| **Total Task Execution Timeout** | 60.0 seconds | Global controller process deadline |

## Credential and authentication boundary

### Credential blindness invariant

`AGENTICOS_CREDENTIAL_CONTENT_ACCESS=NONE` is invariant throughout the Planner
qualification workflow:
- The controller, mediator, evidence store, and every non-client AgenticOS
  process never receive, read, log, or parse access tokens, refresh tokens,
  bearer headers, cookies, credential JSON, or token-derived cryptographic keys.
- No credential data is passed via environment variables, command-line arguments,
  standard input, or IPC payloads.
- AgenticOS may inspect only pathname-independent filesystem metadata needed to
  validate the mount and post-refresh state. It must not open credential bytes
  readably, hash or copy content, parse JSON, deserialize token material, or
  compare secrets.

### Least-authority credential refresh filesystem

The persistent authority is a descriptor/kernel-identity-bound dedicated
credential directory mounted read-write only at
`/home/aos/kimi/credentials`. A single-leaf bind is forbidden because rename
replacement requires parent-directory authority. The host directory contains
only the admitted credential namespace.

Before passing an `O_PATH|O_DIRECTORY|O_NOFOLLOW` descriptor to the namespace
launcher, AgenticOS validates metadata only:

1. the configured root and credential directory are absolute real directories
   beneath the qualified trusted root, with safe ancestry and no symlink in any
   component;
2. every ancestor and the directory have the expected uid, exact private mode,
   and no group/world-writable authority;
3. the credential directory's `st_dev` and `st_ino` are captured and remain
   stable through mount, pre-model revalidation, and unmount;
4. the only persistent leaf is exactly `kimi-code.json`;
5. the leaf is a regular file owned by the expected uid with mode `0600` and
   `nlink == 1`;
6. no unknown persistent file, transient file, symlink, socket, device, FIFO,
   or subdirectory exists; and
7. the descriptor-resolved mount source is the validated directory identity,
   not a later pathname lookup.

The exact pinned source permits only this credential-save shape:

```text
target = kimi-code.json
temp   = kimi-code.json.tmp.<decimal-pid>.<8-lowercase-hex>
open temp for write with requested mode 0600
write complete serialized token document
fsync temp file
close temp file
chmod temp file to 0600
rename temp over target in the same directory
```

The source does not fsync the parent directory, and this design does not invent
that claim. Preflight requires no transient object. During execution only an
exact-client-created name matching the source shape is compatible evidence;
any other entry is detected as an ambiguity and blocks. Kernel policy must deny
directory escape, cross-directory rename, symlink creation/substitution, and
writes outside this directory while allowing only the regular-file,
same-directory operations the exact client needs, including cleanup unlink of
its own failed temp. Post-refresh validation
requires the final leaf to be regular, expected-uid, `0600`, `nlink == 1`, with
no transient or unexpected entry.

The production OAuth manager separately needs its cross-process refresh lock.
`/home/aos/kimi/oauth` is therefore a private task-local tmpfs, not a host
persistent mount. It may contain only the source-required `kimi-code` sentinel
and transient `kimi-code.lock` lock directory. Exact-binary tests must establish
the actual complete lock-directory shape; no guessed child-name pattern is
authorized. The tmpfs is destroyed during cleanup. No config, session, log,
plugin, tool, or other persistent provider state is writable.

### Refresh state and prompt/model gate

`AUTH_REFRESH_STATE` is one of:

```text
NOT_REQUIRED
IN_PROGRESS
COMPLETED_AND_PERSISTED
FAILED
INTERRUPTED
AMBIGUOUS
```

When the first model CONNECT is pending, zero auth-tunnel admissions plus
source-bound exact-client behavior can support `NOT_REQUIRED`. A refresh may
become `COMPLETED_AND_PERSISTED` only when the pending model CONNECT establishes
the source-bound transition past `ensureFresh()`, auth relay work is drained,
the OAuth lock is no longer active, and the content-blind directory
postcondition above validates. In this schema, "persisted" means the exact
pinned save returned after file fsync and rename and the postcondition passed;
it does not overclaim parent-directory-fsync or power-loss durability that the
source does not provide.
An in-progress, failed, interrupted, or uncertain save; any unexpected temp or
lock object; or any inability to revalidate yields `AMBIGUOUS` or another
terminal failure state.

```text
AUTH_REFRESH_STATE=IN_PROGRESS|FAILED|INTERRUPTED|AMBIGUOUS
MODEL_ADMISSION=DENIED
QUALIFICATION=BLOCKED
```

No model tunnel is admitted unless the state is `NOT_REQUIRED` or
`COMPLETED_AND_PERSISTED`. The controller never sends a session or prompt after
refresh state becomes ambiguous, and it never sends a second session or prompt
to recover. If refresh becomes ambiguous only while the already-authorized
single prompt is being processed, that prompt fails, model admission remains
denied, and no later ACP operation is sent. There is no automatic repair,
login, credential rewrite, or retry. The exact client is never knowingly
interrupted while refresh is in progress and then allowed to continue to model
inference.

Interactive/device-code login is disabled. Failure to recognize or refresh the
stored credential yields `LOCAL_AUTH_REJECTED` or `AUTH_REFRESH_FAILED` and
blocks before model admission.

## Planner ACP sequence, model identity, and callback policy

### ACP protocol flow

The AgenticOS controller communicates with the sandboxed Kimi process via stdio
NDJSON ACP Protocol Version 1 (`protocolVersion=1`). Package or implementation
generations may be described separately, but the negotiated wire protocol must
never be called "ACP v2."

```text
Controller                                             Kimi 0.36.1 Client
    |                                                          |
    | --- initialize (protocolVersion=1) ------------------->  |
    | <--- initialize result (capabilities, authMethods) ----  |
    |                                                          |
    | --- authenticate (methodId="login") ------------------>  |
    | <--- authenticate result (success) --------------------  |
    |                                                          |
    | --- session/new (workDir="/workspace", mcpServers=[]) ->  |
    | <--- session/new result (sessionId) -------------------  |
    |                                                          |
    | --- session/prompt (promptId, message) --------------->  |
    | <--- session/update (bounded message chunks) ----------  |
    | <--- session/update (stopReason="end_turn") -----------  |
    |                                                          |
    | --- Process Exit / Cleanup --------------------------->  |
```

### Protocol state validation rules

1. **`initialize`:** The controller validates the returned capabilities,
   ensuring version matches `0.36.1` and the legacy absolute command vector is
   preserved. Any capability mutation fails closed.
2. **`authenticate`:** The controller sends `methodId="login"`. The Kimi client
   validates local credentials. If authentication fails, the controller halts
   immediately before any session or network model request is attempted.
3. **`session/new`:** Sent with `workDir="/workspace"` and `mcpServers=[]`. The
   controller verifies that the session binds the immutable default model.
4. **`session/prompt`:** Exactly one prompt is sent for the lifetime of the
   controller (`ACP_REAL_PROMPT_COUNT <= 1`).
5. **Terminal Result:** The controller accumulates streaming message chunks
   until a terminal `stopReason="end_turn"` notification is received.

### Allowed ACP callback policy

The intended qualification set is below. Before implementation, exact pinned
source review and credential-free exact-binary tests must establish the complete
actual notification/callback set and bind it into the reviewed policy. The
table may be narrowed or made more precise by that evidence but must never be
dynamically widened at runtime:

| ACP Method / Event | Direction | Policy | Action on Receipt |
| --- | --- | --- | --- |
| `session/update` (content chunks) | Client -> Controller | **ALLOWED** | Accumulate text into bounded buffer (max 16 KiB) |
| `session/update` (`stopReason="end_turn"`) | Client -> Controller | **ALLOWED** | Mark turn complete; initiate AOSPLAN parsing |
| `session/update` (tool calls) | Client -> Controller | **BLOCKED** | Reject immediately; fail with `ACP_PROTOCOL_FAILED` |
| `fs/readFile` / `fs/writeFile` | Client -> Controller | **BLOCKED** | Reject immediately; fail with `ACP_PROTOCOL_FAILED` |
| `terminal/create` / `terminal/exec` | Client -> Controller | **BLOCKED** | Reject immediately; fail with `ACP_PROTOCOL_FAILED` |
| `permission/request` | Client -> Controller | **BLOCKED** | Reject immediately; fail with `ACP_PROTOCOL_FAILED` |
| `elicitation/request` | Client -> Controller | **BLOCKED** | Reject immediately; fail with `ACP_PROTOCOL_FAILED` |
| Any MCP / Tool / Subagent Call | Client -> Controller | **BLOCKED** | Reject immediately; fail with `ACP_PROTOCOL_FAILED` |

Any callback outside the exact allowed set immediately terminates the process
and marks the qualification `BLOCKED`.

### Deterministic model identity

To prevent silent model drift, the qualification binds exact configuration
parameters:

```text
default_model = kimi-code/kimi-for-coding
provider = managed:kimi-code
provider_type = kimi
wire_model = kimi-for-coding
base_url = https://api.kimi.com/coding/v1
protocol_adapter = openai-legacy
sdk = openai@6.34.0
sdk_max_retries = 0
loop_control.max_attempts_per_step = 1
loop_control.max_steps_per_turn = 1
```

- **Zero SDK Retries:** `openai@6.34.0` is instantiated with `maxRetries: 0`.
- **Single Step Turn:** `LoopService.run()` is constrained to
  `max_steps_per_turn=1` and `max_attempts_per_step=1`.
- **No Fallback Provider:** No secondary or fallback model configurations exist.

## Planner runtime, prompt, and output boundary

### Planner runtime environment

- **Sterile Workspace:** The provider operates inside an empty synthetic tmpfs
  mount at `/workspace`.
- **No Repository Data:** The sandbox contains no checkout files, `.git`
  directories, M5 worktrees, board state, or controller databases.
- **Disabled Subsystems:** `tools: []`, `subagents: []`, `mcpServers: []`,
  skills disabled, plugins disabled, hooks disabled, background telemetry
  disabled, auto-update disabled (`KIMI_CODE_NO_AUTO_UPDATE=1`).

### Qualification prompt definition

The qualification uses a single, public, non-sensitive prompt conforming to
schema `AOS_KIMI_PLANNER_PROMPT/1` (< 4 KiB):

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

### Output boundary and AOSPLAN/1 validation

- **Buffer Ceilings:** Individual ACP frames capped at 65,536 bytes; ACP
  transcript capped at 1,024 frames; total accumulated model text capped at
  16,384 bytes (16 KiB).
- **AOSPLAN/1 Schema:** The model output must parse as a strict `AOSPLAN/1` JSON
  object:
  ```json
  {
    "schema": "AOSPLAN/1",
    "tasks": [
      {
        "local_id": "task-1",
        "title": "Document Controller Task ID Authority Invariant",
        "description": "Record that the controller, not the model, assigns authoritative task identifiers.",
        "task_type": "DOCUMENT",
        "dependencies": [],
        "acceptance_criteria": [
          "The proposed task states that the controller, not the model, assigns authoritative task identifiers."
        ],
        "preferred_role": "DOCUMENTATION",
        "priority": "HIGH"
      }
    ]
  }
  ```
- **Validation Pipeline:**
  1. Strict JSON parsing (no trailing commas, no duplicate keys, no markdown fences);
  2. `PlannerProposal.from_dict` schema validation;
  3. DAG compiler dry-run (validates dependencies and policy bounds);
  4. Authoritative task ID assignment check.
- **No Direct Board Mutation:** Qualification proves compiler acceptance only; no live board state is modified.

## Evidence architecture and versioned schemas

### Dedicated qualification namespace

Evidence is stored in a completely separate, versioned namespace:

```text
/home/brand/.local/share/agenticos/controller-evidence/
  kimi-code/0.36.1/planner-qualification-v1/
    attempt.json
    result.json
```

The historical Level-1 evidence directory (`.../level1-local-auth/`) is
immutable and never modified.

### Versioned schemas

#### Attempt schema: `AOS_KIMI_PLANNER_QUALIFICATION_ATTEMPT/1`

The immutable attempt record contains the planner-attempt number; exact future
implementation commit; authorization digest; Kimi version, source commit,
executable and launcher identities; exact config, profile, mediator-policy, and
prompt digests; the immutable historical Level-1 result/reason/count; and the
claim timestamp. It is created only by a future real-run authorization. This
design remediation creates no attempt marker.

#### Result schema: `AOS_KIMI_PLANNER_QUALIFICATION_RESULT/1`

Every field has one of these provenance values:

```text
DIRECT_CONTROLLER_OBSERVATION
DIRECT_MEDIATOR_OBSERVATION
DIRECT_ACP_OBSERVATION
SOURCE_BOUND_CONFIGURATION
SYNTHETIC_QUALIFICATION_ONLY
INFERRED_FROM_SUCCESSFUL_PLANNER_RESULT
```

The result includes at least the following fields and provenance. Stronger
source-bound or inferred facts must never be serialized as direct mediator
observations.

| Result field | Meaning | Provenance |
| --- | --- | --- |
| `qualification_state`, `primary_failure_code` | Typed overall and first-failure result | `DIRECT_CONTROLLER_OBSERVATION` |
| `local_credential_recognized` | Exact ACP authentication result | `DIRECT_ACP_OBSERVATION` |
| `credential_refresh_state` | `NOT_REQUIRED`, `COMPLETED_AND_PERSISTED`, or terminal failure state | `DIRECT_CONTROLLER_OBSERVATION` combined with `DIRECT_MEDIATOR_OBSERVATION` and `SOURCE_BOUND_CONFIGURATION` |
| `acp_real_prompt_count` | Controller prompt admissions | `DIRECT_CONTROLLER_OBSERVATION` |
| `planner_proposal_count`, `aosplan_validated` | Accepted bounded proposals and validator result | `DIRECT_CONTROLLER_OBSERVATION` |
| `model_allowance_claim_count` | Irreversible model allowance claims, including failed post-claim transitions | `DIRECT_MEDIATOR_OBSERVATION` |
| `model_tunnel_admission_count`, `auth_tunnel_admission_count` | Opaque tunnel admissions; admission is distinct from allowance claim | `DIRECT_MEDIATOR_OBSERVATION` |
| `model_http_request_count`, `auth_http_request_count` | Literal value `NOT_DIRECTLY_OBSERVABLE_UNDER_OPAQUE_TLS` | `SOURCE_BOUND_CONFIGURATION` explanation, never a numeric live observation |
| `sdk_retry_configuration`, `loop_attempt_limit`, `loop_step_limit` | Exact pinned config values | `SOURCE_BOUND_CONFIGURATION` |
| `model_host`, `auth_host`, source-bound paths and wire model | Exact config/source bindings | `SOURCE_BOUND_CONFIGURATION` |
| `tls_transport_policy` | Literal `END_TO_END_ORIGIN_TLS` | `SOURCE_BOUND_CONFIGURATION` plus `DIRECT_MEDIATOR_OBSERVATION` of opaque relay |
| `server_auth_accepted_inferred_from_successful_model_turn` | Conservative inference permitted only after a valid completed turn | `INFERRED_FROM_SUCCESSFUL_PLANNER_RESULT` |
| prompt/output byte counts and canonical digests | Bounded controller-held artifacts | `DIRECT_CONTROLLER_OBSERVATION` |
| ACP and network terminal states | State-machine outcomes | `DIRECT_ACP_OBSERVATION` / `DIRECT_MEDIATOR_OBSERVATION` |
| cleanup and residue counts | Qualified lifecycle census | `DIRECT_CONTROLLER_OBSERVATION` |

Exact negotiated TLS version may appear only in credential-free synthetic
fixture evidence where the synthetic origin can observe it. The live result
must not contain `negotiated_transport = TLSv1.3`, direct server-auth acceptance,
numeric live HTTP request counts, or mediator-observed HTTP statuses.

### Content-free evidence invariant

Evidence files are cryptographically bound, canonical JSON objects. Under no
circumstances may evidence files contain:
- Access tokens, refresh tokens, or bearer credentials;
- `Authorization` or `Cookie` header values;
- Full prompt text (only length and SHA-256 digest are retained);
- Raw model completion text or SSE event stream chunks;
- TLS session tickets, master keys, or decrypted byte streams.

## Failure classification taxonomy

The first directly supported failure class is immutable. The live opaque
mediator cannot classify encrypted HTTP status. No code may parse free-form ACP
error strings to recover `401`, `403`, `429`, or `5xx`. The current exact ACP
path has no separately qualified structured status subset, so provider/client
inference failures use the conservative class below.

| Failure Code | Description | Next Action |
| --- | --- | --- |
| `LOCAL_AUTH_REJECTED` | Sandboxed client failed local cached credential recognition | Halt immediately; fail closed; no network requests |
| `AUTH_REFRESH_FAILED` | Refresh failed or did not reach an unambiguous persisted state | Halt immediately; fail closed; no model admission |
| `AUTH_EGRESS_POLICY_FAILED` | Auth tunnel exceeded quota (>3), attempted unapproved host, or failed DNS/SSRF | Terminate all egress; fail closed |
| `MODEL_EGRESS_POLICY_FAILED` | Model CONNECT attempted unapproved host, port, or failed DNS/SSRF | Terminate all egress; fail closed |
| `MODEL_TUNNEL_ALREADY_CONSUMED` | Client attempted a second model tunnel after allowance spent | Deny immediately; fail closed |
| `TLS_OR_TUNNEL_FAILED` | Opaque relay, handshake deadline, connection, or tunnel failed | Consumes model allowance if claimed; fail closed; no retry |
| `SNI_MISMATCH` | `ClientHello` SNI does not equal the requested CONNECT hostname | Terminate connection immediately; fail closed |
| `DNS_POLICY_FAILED` | Hostname resolution timed out or resolved to non-public/private IP | Reject connection; fail closed |
| `ACP_PROTOCOL_FAILED` | ACP frame malformed, out-of-order, or attempted forbidden callback | Invoke the qualified freezer/cgroup lifecycle; fail closed |
| `PROVIDER_INFERENCE_FAILED` | Provider/client inference failed without a safely structured, qualified status at the ACP boundary | Model allowance spent; auth remains closed; no retry or status guess |
| `MODEL_OUTPUT_INVALID` | Model text exceeded 16 KiB or failed JSON parsing | Fail closed; no retry |
| `AOSPLAN_INVALID` | JSON parsed but failed `PlannerProposal` validation or DAG checks | Fail closed; no retry |
| `TIMEOUT` | Operation exceeded connect, stream, or global execution deadline | Invoke the qualified lifecycle for provider and mediator; fail closed |
| `CLEANUP_FAILED` | Process, socket, cgroup, or mount residue remained after task exit | Retain primary result; mark overall run non-complete |
| `EVIDENCE_FAILED` | Failed to atomically write canonical attempt or result JSON | Mark qualification blocked |

## Crash handling, teardown, and residue contract

Planner lifecycle must compose the already-qualified
`agenticos.providers.kimi_local_auth_freezer` controller-excluding
systemd/cgroup-v2 design. The independent review called this subsystem
`KimiLocalAuthFreezer`; at the authorized baseline its concrete lifecycle API
is the module's identity-bound `WorkloadCgroup` and associated controller APIs.
Implementation must reuse that qualified behavior, not invent a parallel
process-group cleanup design or weaken it behind a new wrapper.

Cleanup is idempotent and triggered on every terminal state, signal, or error:

```text
Terminal State Reached (Success, Failure, or Crash)
  |
  +---> 1. Atomically Revoke Mediator Egress Authority
  |
  +---> 2. Interrupt Active Socket Relays & Join Worker Threads (2.0s deadline)
  |
  +---> 3. Close ACP Stdio Descriptors & Proxy Listener
  |
  +---> 4. Revoke ACP and provider execution authority
  |
  +---> 5. Reuse bounded freeze/thaw and recursive cgroup task termination
  |
  +---> 6. Unmount Sandbox Bubblewrap Mounts & Destroy tmpfs Workspace
  |
  +---> 7. Execute Post-Execution Residue Census
  |
  v
Clean State Verified (0 processes, 0 sockets, 0 scopes, 0 cgroups)
```

The composed lifecycle preserves controller exclusion, exact workload
membership, cgroup descriptor/identity validation, bounded freeze/thaw, no
descendant escape, recursive task termination, one bounded cleanup deadline,
zero frozen orphan, zero residual cgroup or unit/scope, zero provider or
mediator process, and zero task socket/tunnel. Cleanup failure never causes the
controller to re-open ACP, credential, auth, model, or network authority.

### Zero-residue acceptance invariant

Qualification acceptance strictly requires zero residue across all subsystems:
- `process_residue_count == 0`
- `mediator_process_count == 0`
- `task_scope_count == 0`
- `task_cgroup_count == 0`
- `network_namespace_count == 0`
- `open_tunnel_count == 0`
- `active_listener_count == 0`
- `unix_socket_count == 0`
- `frozen_orphan_count == 0`

## Credential-free exact-binary synthetic qualification matrix

All tests use the exact pinned Kimi 0.36.1 executable, exact production config,
exact proxy path, synthetic credentials, loopback-only DNS/origins,
end-to-end synthetic TLS, no external network, and no real credential. The
fixture origins may decrypt their own synthetic TLS and measure HTTP requests;
the production mediator remains opaque. Compatibility measurements never turn
HTTP request count into a mediator-enforced invariant.

| # | Required proof |
| --- | --- |
| 1 | Exact binary initializes through the production Bubblewrap, namespace, listener handoff, and ACP Protocol Version 1 path. |
| 2 | Every initialize capability, command, version, ordering, or shape mutation fails closed. |
| 3 | Synthetic local credential recognition succeeds without an auth tunnel when refresh is not required. |
| 4 | Synthetic local recognition failure yields `LOCAL_AUTH_REJECTED` with no session, prompt, auth, or model admission. |
| 5 | Exact threshold behavior distinguishes no-refresh and source-required refresh. |
| 6 | Exact OAuth request is form-encoded `POST /api/oauth/token` at the synthetic auth origin. |
| 7 | Auth 301 behavior is characterized: followed or not, connection reuse, HTTP request count, method/body semantics, and additional tunnel attempts. |
| 8 | Auth 302 behavior is characterized on the same dimensions. |
| 9 | Auth 303 behavior is characterized on the same dimensions. |
| 10 | Auth 307 behavior is characterized on the same dimensions. |
| 11 | Auth 308 behavior is characterized on the same dimensions. |
| 12 | Model 301 behavior is characterized: followed or not, connection reuse, HTTP request count, method/body semantics, and additional tunnel attempts. |
| 13 | Model 302 behavior is characterized on the same dimensions. |
| 14 | Model 303 behavior is characterized on the same dimensions. |
| 15 | Model 307 behavior is characterized on the same dimensions. |
| 16 | Model 308 behavior is characterized on the same dimensions. |
| 17 | A same-origin model redirect that reuses one tunnel demonstrates synthetic request multiplication without changing the live tunnel claim. |
| 18 | Every cross-host redirect requires a new CONNECT/SNI decision and is denied. |
| 19 | Synthetic fixture HTTP counts are labeled `SYNTHETIC_QUALIFICATION_ONLY`; live result schemas reject numeric HTTP counts. |
| 20 | Credential sibling-temp creation uses only `kimi-code.json.tmp.<decimal-pid>.<8-lowercase-hex>`. |
| 21 | Complete temp write and file `fsync` succeed under the exact mount policy. |
| 22 | Same-directory rename succeeds and leaves one regular `0600`, expected-uid, `nlink==1` leaf. |
| 23 | The source-required task-local OAuth lock sentinel and lock directory succeed in private tmpfs and leave no lock directory after release. |
| 24 | Any unexpected credential-directory filename or object type fails preflight or is detected before model admission. |
| 25 | Preexisting credential or temp symlink substitution fails closed without touching its target. |
| 26 | Credential-directory escape and symlink ancestry fail closed. |
| 27 | Rename outside the credential directory fails. |
| 28 | Config, sessions, logs, plugins, tools, other credentials, and all other persistent provider state remain non-writable. |
| 29 | Refresh interruption before write, during write, after fsync, and before/after rename yields a terminal state; ambiguous state blocks model admission and any later prompt. |
| 30 | Refresh failure, leftover temp, leftover lock, metadata drift, or indeterminate postcondition causes no automatic repair, login, or retry. |
| 31 | `AUTH_REFRESH_STATE` must be `NOT_REQUIRED` or `COMPLETED_AND_PERSISTED` before model admission. |
| 32 | The mediator directly calls the qualified `validate_address`; no parallel Kimi special-address table is accepted. |
| 33 | Every applicable `AOSADDR/1` unspecified, loopback, private, link-local, CGNAT, multicast, documentation, benchmarking, reserved/future-use, mapped/compatible IPv6, NAT64, 6to4, Teredo, and other special-purpose case rejects. |
| 34 | Exact hostnames, ASCII form, ports, DNS deadline, answer cap, numeric sockaddr, and CONNECT/DNS/SNI equality are enforced. |
| 35 | IP literals, wildcard/model-supplied names, malformed DNS, and classifier failure reject. |
| 36 | A valid exact-client ClientHello of at most 4096 bytes is accepted under exact production TLS/config. |
| 37 | A ClientHello larger than 4096 bytes is rejected without truncation or relay. |
| 38 | ECH extension `0xfe0d`, hidden/missing SNI, and every qualified obscuring ECH form reject. |
| 39 | Any second ClientHello, renegotiation, re-handshake, or HelloRetryRequest path blocks and closes the tunnel. |
| 40 | Exact lowercase `https_proxy=http://127.0.0.1:18080` is honored by OAuth. |
| 41 | The same exact lowercase proxy is honored by the Kimi/OpenAI model stack. |
| 42 | No default route, ambient DNS, uppercase proxy, `ALL_PROXY`, SOCKS, `no_proxy`, or inherited network FD exists. |
| 43 | Direct external-IP and alternate-proxy bypass attempts fail; all synthetic provider traffic reaches the task mediator. |
| 44 | Invalid proxy configuration fails preflight and cannot fall back to direct connection. |
| 45 | Auth concurrency and the three-tunnel lifetime cap enforce independently of HTTP/fetch counts. |
| 46 | Under one synchronization authority, model allowance claim permanently revokes auth and rejects new auth admissions. |
| 47 | Pending auth DNS/connect work is cancelled, active relays are interrupted, workers join by deadline, registry empties, and queued accepts are absent before model admission. |
| 48 | Failure or crash after model allowance claim but before admission leaves the allowance spent, auth revoked, model unadmitted, and qualification blocked. |
| 49 | A source-owned model authorization recovery attempt cannot reopen auth or obtain a second model tunnel. |
| 50 | Exactly one `session/new` binds the exact immutable provider/model/base URL with empty workspace and no MCP. |
| 51 | Exactly one controller `session/prompt` is admitted; duplicate, concurrent, or post-terminal prompts reject. |
| 52 | Exactly one bounded Planner proposal may be accepted; a second candidate rejects. |
| 53 | Model SDK retries are zero, loop attempts are one, loop steps are one, and no fallback/background inference obtains another tunnel. |
| 54 | Valid ACP updates produce one terminal `end_turn`; malformed, truncated, duplicate-terminal, post-terminal, and oversized streams reject. |
| 55 | Exact pinned source and runtime testing establish the allowed ACP callback/event set; every unknown, tool, filesystem, terminal, permission, elicitation, MCP, skill, plugin, hook, or subagent callback blocks. |
| 56 | ACP frame/transcript, prompt, output, byte, fd, pid, memory, connection, idle, and total-time bounds fail closed. |
| 57 | The canonical public prompt is byte-stable, under 4 KiB, and contains no secret, repository, or user-private data. |
| 58 | One strict one-task `AOSPLAN/1` object validates and compilation dry-run assigns authority only in the controller. |
| 59 | Duplicate keys, extra fields, prose/fences, multiple tasks, invalid DAG/enums/limits, and compiler-policy failures reject with no board mutation. |
| 60 | Credential, Authorization, Cookie, prompt, response, and TLS synthetic canaries are absent from controller, mediator, ACP, evidence, exceptions, and logs. |
| 61 | The live evidence schema records each field's observation/inference provenance and rejects direct TLS-version, HTTP-status, server-auth, and HTTP-count overclaims. |
| 62 | The existing qualified freezer/cgroup lifecycle is composed without a parallel process-group path. |
| 63 | Controller exclusion, exact workload membership, descriptor identity, bounded freeze/thaw, recursive kill, and no descendant escape remain intact. |
| 64 | Provider, mediator, relay, namespace, listener, socket/tunnel, scope/unit, cgroup, mount, credential temp, OAuth lock, and frozen-orphan residue are all zero. |
| 65 | Controller, mediator, provider, and launcher crashes are injected at every network and refresh state transition. |
| 66 | SIGTERM, SIGKILL, parent death, EOF, stuck half-close, cleanup deadline, and evidence-write failure all fail closed without restored authority. |
| 67 | Historical `level1-local-auth` evidence remains byte-for-byte unchanged and disjoint from `planner-qualification-v1`. |
| 68 | Exact candidate passes focused native WSL tests, broader regressions, Windows portable regressions, static/compile checks, secret scan, complete diff review, and `git diff --check`. |

## Conditional implementation outline (not authorized)

Execution and implementation remain strictly unauthorized. When future
implementation is separately authorized, work will follow 7 discrete slices:

1. **Slice 1: Protocol Types and State Machine Core** (`kimi_planner_types.py`, pure state machine, schemas, canonical prompt, unit tests);
2. **Slice 2: Opaque Task Egress Mediator** (`kimi_planner_egress.py`, socket relay, ClientHello SNI parser, DNS/SSRF filter, state machine integration);
3. **Slice 3: Planner Namespace and Sandbox Launcher** (`kimi_planner_runtime.py`, Bubblewrap config, descriptor mounts, cgroup isolation);
4. **Slice 4: ACP Controller and Output Compiler** (`kimi_planner_controller.py`, ACP stdio driver, callback gate, `AOSPLAN/1` validator);
5. **Slice 5: Synthetic Fixtures and Test Suite** (Complete expanded credential-free exact-binary matrix against local OAuth/model TLS origins);
6. **Slice 6: Evidence Persistence and CLI Harness** (`kimi_planner_qualification.py`, atomic evidence writing, preflight checks, residue census);
7. **Slice 7: Repository Qualification and Verification** (Cross-clone validation, diff check, static analysis, pre-real closure).

## Future success and prohibited claims

A later separately authorized real qualification's transport/output summary may
include:

```text
ONE_REAL_ACP_PROMPT=YES
ONE_MODEL_TUNNEL_ADMITTED=YES
NO_SECOND_MODEL_TUNNEL=YES
NO_CROSS_HOST_PROVIDER_EGRESS=YES
ONE_VALID_AOSPLAN_PROPOSAL=YES
```

It must not claim any of the following unless a future separately qualified
enforcement mechanism proves them:

```text
EXACTLY_ONE_WIRE_HTTP_REQUEST=YES
REAL_MODEL_HTTP_REQUEST_COUNT=1
AUTH_HTTP_REQUEST_COUNT=ANY_EXACT_NUMERIC_VALUE
HTTP_STATUS_401_OBSERVED_BY_MEDIATOR
HTTP_STATUS_403_OBSERVED_BY_MEDIATOR
HTTP_STATUS_429_OBSERVED_BY_MEDIATOR
HTTP_STATUS_5XX_OBSERVED_BY_MEDIATOR
TLS_VERSION_OBSERVED_BY_MEDIATOR
SERVER_AUTH_DIRECTLY_OBSERVED_BY_MEDIATOR
```

## Permanent design-history note

Checkpoint `741a3b50` correctly identified
`OPAQUE_SAME_ORIGIN_REDIRECT_REQUEST_MULTIPLICATION`: one opaque TLS tunnel can
carry more than one same-origin HTTP request. Checkpoint `b08a6ddf` removed the
blocker text without resolving that protocol fact. This remediation does not
rewrite either commit. It resolves the specification error by separating
tunnel and HTTP accounting, requiring exact-binary redirect characterization,
preserving one-prompt and one-model-tunnel enforcement, and retaining
end-to-end TLS plus credential blindness. Redirect characterization is
compatibility evidence, not a new live HTTP-count guarantee.

## Self-review against the independent findings

| Severity | Independent finding | Result | Specification resolution |
| --- | --- | --- | --- |
| Critical 1 | Opaque TLS does not prove one HTTP request | `RESOLVED` | Six distinct counts, normative authority table, redirect reality, ten exact-binary redirect cases, earned/prohibited claims, and permanent history note. |
| Critical 2 | Credential refresh requires directory write authority | `RESOLVED` | Descriptor/kernel-identity-bound dedicated credential directory, exact temp/save behavior, ephemeral OAuth lock tmpfs, metadata-only validation, refresh-state gate, and interruption/ambiguity rules. |
| Important 1 | Opaque mediator cannot directly classify HTTP status | `RESOLVED` | Status-derived live classes removed; `PROVIDER_INFERENCE_FAILED` added; free-form parsing prohibited; no structured subset claimed. |
| Important 2 | Reuse the qualified M4B address classifier | `RESOLVED` | Direct composition of `validate_address` and `AOSADDR/1`; parallel table forbidden; complete applicable class coverage required. |
| Important 3 | Correct ClientHello, ECH, and second-ClientHello handling | `RESOLVED` | Proposed 4096-byte qualified bound, fail-closed oversize, explicit `0xfe0d`/ECH rejection, and second-ClientHello closure. |
| Important 4 | Reuse the qualified process/cgroup lifecycle | `RESOLVED` | Existing `kimi_local_auth_freezer`/`WorkloadCgroup` behavior is normative; parallel process-group cleanup is forbidden. |
| Minor 1 | ACP terminology was ambiguous | `RESOLVED` | Negotiated wire protocol is ACP Protocol Version 1 (`protocolVersion=1`); "ACP v2" is forbidden for the wire protocol. |
| Minor 2 | Evidence confused observation and inference | `RESOLVED` | Per-field provenance, `END_TO_END_ORIGIN_TLS`, synthetic-only negotiated version, and inferred server-auth wording replace direct overclaims. |

```text
CRITICAL_UNRESOLVED=0
IMPORTANT_UNRESOLVED=0
MINOR_UNRESOLVED=0
```

## Next gate

```text
F1_KIMI_PLANNER_QUALIFICATION_DESIGN=READY_FOR_FINAL_REVIEW
STRATEGY_B_COMBINED_SINGLE_REAL_PLANNER_QUALIFICATION=SELECTED
STRATEGY_B=VIABLE_WITH_CORRECTIONS
IMPLEMENTATION_AUTHORIZED=NO
REAL_PLANNER_REQUEST_AUTHORIZED=NO
REAL_LEVEL1_RETRY_AUTHORIZED=NO
HISTORICAL_REAL_ATTEMPT_COUNT=1
CRITICAL_UNRESOLVED=0
IMPORTANT_UNRESOLVED=0
MINOR_UNRESOLVED=0
NEXT_GATE=FINAL_INDEPENDENT_ARCHITECTURAL_REVIEW_REQUIRED
```

HARD STOP.

DO NOT IMPLEMENT.
DO NOT ACCESS THE REAL CREDENTIAL.
DO NOT CONTACT KIMI.
DO NOT CREATE A REAL SESSION.
DO NOT SEND A REAL PROMPT.
DO NOT PERFORM INFERENCE.
DO NOT BEGIN F2.
