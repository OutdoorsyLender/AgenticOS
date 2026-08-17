# F1 Kimi Combined Single-Real Planner Qualification Design

## Status and authorization boundary

```text
F1_KIMI_PLANNER_QUALIFICATION_DESIGN=READY_FOR_REVIEW
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
AUTHORITATIVE_BASELINE=741a3b5089cc76c1a34c0f0bdc2a3f25faca118a
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

- **Role:** Specification Authoring Agent
- **Active Model:** Gemini 3.7 Flash
- **Task Scope:** Level-A Architectural Specification Authoring for F1 Kimi Planner Qualification (Strategy B)
- **Work Mode:** Pure design and documentation (no source code implementation, no network egress, no credential access)

## Strategy decision

Strategy B is the approved strategy for the F1 Kimi qualification milestone:

```text
STRATEGY_A_LEVEL1_GENERATION_2=REJECTED
STRATEGY_B_COMBINED_PLANNER_QUALIFICATION=SELECTED
STRATEGY_C_ABANDON_KIMI=DEFERRED
```

| Strategy | Decision | Rationale |
| --- | --- | --- |
| **A. Level-1 generation 2** | **REJECTED** | Does not directly advance the First Autonomous Build milestone; repeats a lower-level local authentication proof whose infrastructure defect is already understood and remediated, consuming real credential authority without yielding a Planner proposal. |
| **B. Combined Planner qualification** | **SELECTED** | Directly proves the subscription-backed Planner capability required by Milestone F1 while preserving strict credential blindness, one-request authority, and fail-closed egress mediation. |
| **C. Abandon Kimi F1** | **DEFERRED** | No current evidence establishes an intrinsic Kimi-specific security or protocol blocker requiring provider replacement. |

Under Strategy B, authentication is a prerequisite checkpoint inside the
higher-level Planner qualification rather than a separate isolated attempt. A
future successful Planner qualification will be represented as:

```text
HISTORICAL_LEVEL1=BLOCKED
HISTORICAL_LEVEL1_REASON=AUTH_METHOD_SHAPE
HISTORICAL_REAL_ATTEMPT_COUNT=1
PLANNER_QUALIFICATION=COMPLETE
LOCAL_CREDENTIAL_RECOGNIZED_DURING_PLANNER=YES
SERVER_AUTH_ACCEPTED_DURING_PLANNER=YES
REAL_MODEL_REQUEST_SUCCEEDED=YES
AOSPLAN_VALID=YES
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
| **Exact Kimi 0.36.1 Client** | Read mounted credential leaf via descriptor; perform official cached-token checks and OAuth refresh; make exactly one admitted model request | Access checkout or repository files; access other credentials; access controller state; use shell, tools, or MCP; reach ambient networks |
| **Opaque Egress Mediator** | Authenticate task capability; enforce state machine transitions; verify exact hostname; resolve public DNS; verify ClientHello SNI equality; relay encrypted bytes; enforce tunnel bounds | Terminate TLS; decrypt traffic; parse HTTP headers/bodies; inspect Authorization/Cookie headers; inspect prompts/responses/SSE; follow redirects; retry requests |
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
6. Reject private, loopback, link-local, carrier-grade, documentation, and non-routable destination IP addresses;
7. Inspect the initial pre-TLS bytes of the connection solely to extract and verify the TLS `ClientHello` Server Name Indication (SNI);
8. Verify exact positive equality between the CONNECT request hostname and the `ClientHello` SNI;
9. Relay encrypted TLS byte streams bidirectionally between the sandboxed client and the verified origin;
10. Enforce strict connection counts, idle timeouts, byte quotas, and lifecycle deadlines;
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
| **OAuth Token Refresh** | `auth.kimi.com:443` | `AUTH_WINDOW` only | Form-encoded `POST /api/oauth/token` via end-to-end TLS; at most 3 tunnels lifetime |
| **Model Inference Turn** | `api.kimi.com:443` | `MODEL_ONCE` only | Single `POST /coding/v1/chat/completions` via end-to-end TLS; exactly 1 tunnel lifetime |

All other hosts (`code.kimi.com`, `cdn.kimi.com`, `telemetry-logs.kimi.com`,
`www.kimi.com`, Moonshot open-platform endpoints, GitHub, IP literals, alternate
ports) are denied and cause immediate qualification failure.

### Bounded fail-closed DNS / SSRF resolver policy

The mediator implements a dedicated, fail-closed DNS resolver derived from
AgenticOS M4B SSRF security controls:
1. **Exact Hostname Only:** Queries only the exact approved ASCII hostname (`auth.kimi.com` or `api.kimi.com`).
2. **Deadline Bound:** Bounded resolution timeout of 2.0 seconds.
3. **Record Count Bound:** Caps DNS answer processing at a maximum of 8 records.
4. **Public Unicast Verification:** Every resolved IP address is validated against an exhaustive blocklist before connection:
   - Loopback (`127.0.0.0/8`, `::1`);
   - Private IPv4 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`);
   - Link-Local (`169.254.0.0/16`, `fe80::/10`);
   - Carrier-Grade NAT (`100.64.0.0/10`);
   - Broadcast / Multicast (`255.255.255.255`, `224.0.0.0/4`, `ff00::/8`);
   - Documentation IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`);
   - Unique Local IPv6 (`fc00::/7`);
   - IPv4-Mapped IPv6 (`::ffff:0:0/96`) and IPv4-Compatible IPv6 (`::/96`).
5. **Numeric Sockaddr Binding:** Outbound origin connection is established strictly by validated numeric IP sockaddr; the hostname is never passed to ambient OS routing.

### End-to-end TLS integrity

TLS operates strictly end-to-end between the pinned Kimi binary and Moonshot
servers:
- The mediator extracts the first 1024 bytes of the client stream, parses the
  `ClientHello` record, validates the TLS handshake type (`0x01`), verifies the
  SNI extension, and checks exact equality with the requested host.
- The mediator does not modify, intercept, or resign TLS certificates.
- The Kimi client independently verifies the Moonshot origin X.509 certificate
  against the bundled CA trust store.
- Raw `ClientHello` bytes, TLS records, and encrypted payload bytes are never
  persisted to disk or logged.

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
           (Atomic Tunnel Admission)
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
- Lifetime allowance: At most 3 auth tunnels permitted for the task lifetime (`AUTH_TUNNEL_COUNT <= 3`).
- Rejection of Model Host: Any attempt to connect to `api.kimi.com:443` initiates an immediate atomic transition to `AUTH_DRAINING`.

#### 3. AUTH_DRAINING and Atomic Model Transition
- Trigger: The arrival of the first `CONNECT api.kimi.com:443` request.
- Atomic Transition Contract:
  1. Consumes the sole model tunnel allowance (`MODEL_TUNNEL_ADMISSION_COUNT = 1`);
  2. Permanently revokes `auth.kimi.com:443` egress authority;
  3. Interrupts both read and write directions on any active auth tunnel sockets;
  4. Waits for all auth relay worker threads to join against a strict 2.0s deadline;
  5. Verifies that the active auth connection set is completely empty;
  6. Admits the single `api.kimi.com:443` model tunnel and transitions to `MODEL_ONCE`.
- **Tunnel Admission Spending:** The model allowance is consumed immediately upon CONNECT admission. The mediator does NOT wait for TLS handshake completion, HTTP status, first SSE byte, or inference output. Once admitted, the allowance is spent forever.

#### 4. MODEL_ONCE
- Admitted destination: `api.kimi.com:443` only.
- Allowance: Exactly one model tunnel admitted (`MODEL_TUNNEL_ADMISSION_COUNT <= 1`).
- Permanent Revocation of Auth: `auth.kimi.com` is permanently `DENIED`. It cannot reopen under any circumstances.
- **Suppression of 401 Replay:** If the Moonshot model endpoint returns HTTP 401 (Unauthorized), the official client cannot refresh its token and replay the model request, because `auth.kimi.com` is permanently closed.
- **No Secondary Tunnels:** No second model tunnel may be admitted after any outcome, including:
  - TLS handshake failure;
  - HTTP 401 / 403 / 404 / 429 / 5xx;
  - SSE stream malformation or truncation;
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
| **Max Model Tunnels (Lifetime)** | 1 | Atomic counter consumed at admission |
| **CONNECT Header Buffer Max** | 4,096 bytes | Pre-relay buffer limit |
| **ClientHello Buffer Max** | 1,024 bytes | SNI inspection buffer limit |
| **DNS Resolution Timeout** | 2.0 seconds | Async DNS deadline |
| **Origin Connect Timeout** | 5.0 seconds | TCP handshake deadline |
| **Handshake Idle Timeout** | 5.0 seconds | Post-CONNECT TLS handshake deadline |
| **Streaming Chunk Idle Timeout** | 30.0 seconds | Inactivity deadline on model SSE relay |
| **Max Upstream Model Bytes** | 65,536 bytes (64 KiB) | Bidirectional stream byte counter |
| **Max Downstream Model Bytes** | 262,144 bytes (256 KiB) | Bidirectional stream byte counter |
| **Total Task Execution Timeout** | 60.0 seconds | Global controller process deadline |

## Credential and authentication boundary

### Credential blindness invariant

AgenticOS maintains absolute credential blindness throughout the entire Planner
qualification workflow:
- The controller, mediator, host environment, and evidence store never receive,
  read, log, or parse access tokens, refresh tokens, bearer headers, cookies,
  credential JSON, or token-derived cryptographic keys.
- No credential data is passed via environment variables, command-line arguments,
  standard input, or IPC payloads.

### Pinned client credential access

- **Storage Location:** `/home/aos/kimi/credentials/kimi-code.json` inside the
  sandboxed container.
- **Descriptor-Only Mount:** The credential file is mounted via a dedicated,
  read-write file descriptor using Bubblewrap, restricted to the sandboxed Kimi
  user (`uid=1000`).
- **Local Token Validation:** The official Kimi client executes
  `AuthSummaryService.ensureReady()` on startup, reading the cached token from
  disk. If the token is valid and unexpired, the client proceeds directly
  without initiating any network requests.
- **Official Refresh Machinery:** If the token requires refresh, the official
  client executes `OAuthManager.ensureFresh()`, formatting a form-encoded `POST
  https://auth.kimi.com/api/oauth/token` request within `AUTH_WINDOW`. Upon
  receiving a valid token response, the official client atomically writes the
  updated credentials to disk using a temporary file (`.tmp`) and `rename()`.
- **No Interactive / Device Code Flow:** The qualification runner explicitly
  disables device-code flows and browser logins. If stored credentials cannot
  locally authenticate or refresh through `auth.kimi.com:443`, the
  qualification fails closed with `LOCAL_AUTH_REJECTED` or
  `AUTH_REFRESH_FAILED`.

## Planner ACP sequence, model identity, and callback policy

### ACP protocol flow

The AgenticOS controller communicates with the sandboxed Kimi process via stdio
NDJSON Agent Client Protocol (ACP) v2:

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
    | <--- session/update (message chunks, SSE) -------------  |
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

During this qualification turn, the allowed set of ACP notifications and
callbacks is strictly enumerated:

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

#### 1. Attempt Schema: `AOS_KIMI_PLANNER_QUALIFICATION_ATTEMPT/1`

```json
{
  "schema": "AOS_KIMI_PLANNER_QUALIFICATION_ATTEMPT/1",
  "planner_attempt": 1,
  "candidate_commit": "741a3b5089cc76c1a34c0f0bdc2a3f25faca118a",
  "authorization_digest": "sha256:...",
  "kimi_version": "0.36.1",
  "kimi_source_commit": "13d86f8b7bb2443a3b8222e7d94deb0a66429f8e",
  "kimi_executable_sha256": "78c07b255e0bdc8dfe90d0cbd3204a3d862957394a08ca99c6e31144732451c7",
  "namespace_launcher_sha256": "800dbc83e1d1dc7efd127151d257025b4160ae92dfc23d13ed175f09778d15dc",
  "config_sha256": "sha256:...",
  "planner_profile_sha256": "sha256:...",
  "mediator_policy_sha256": "sha256:...",
  "prompt_sha256": "sha256:...",
  "historical_level1_result": "BLOCKED",
  "historical_level1_reason": "AUTH_METHOD_SHAPE",
  "historical_level1_real_attempt_count": 1,
  "claimed_at_utc": "2026-08-16T18:00:00Z"
}
```

#### 2. Result Schema: `AOS_KIMI_PLANNER_QUALIFICATION_RESULT/1`

```json
{
  "schema": "AOS_KIMI_PLANNER_QUALIFICATION_RESULT/1",
  "planner_attempt": 1,
  "candidate_commit": "741a3b5089cc76c1a34c0f0bdc2a3f25faca118a",
  "qualification_state": "COMPLETE",
  "primary_failure_code": null,
  "local_credential_recognized": true,
  "refresh_state": "NO_AUTH_TUNNEL",
  "auth_tunnel_count": 0,
  "auth_refresh_fetch_call_upper_bound": 3,
  "auth_refresh_fetch_call_observation": "SOURCE_BOUND_NOT_WIRE_OBSERVED",
  "server_auth_accepted": true,
  "inference_succeeded": true,
  "aosplan_validated": true,
  "real_session_count": 1,
  "real_prompt_count": 1,
  "model_tunnel_count": 1,
  "model_retry_count": 0,
  "model_fallback_count": 0,
  "background_model_request_count": 0,
  "model_host": "api.kimi.com",
  "model_path_source_binding": "POST /coding/v1/chat/completions",
  "auth_host": "auth.kimi.com",
  "auth_path_source_binding": "POST /api/oauth/token",
  "negotiated_transport": "TLSv1.3",
  "prompt_bytes": 482,
  "prompt_sha256": "sha256:...",
  "model_output_bytes": 612,
  "canonical_proposal_sha256": "sha256:...",
  "acp_terminal_state": "FINISHED",
  "network_terminal_state": "CLOSED",
  "cleanup_state": "COMPLETE",
  "cleanup_failure_code": null,
  "process_residue_count": 0,
  "socket_residue_count": 0,
  "scope_residue_count": 0,
  "cgroup_residue_count": 0,
  "started_at_utc": "2026-08-16T18:00:01Z",
  "finished_at_utc": "2026-08-16T18:00:15Z"
}
```

### Content-free evidence invariant

Evidence files are cryptographically bound, canonical JSON objects. Under no
circumstances may evidence files contain:
- Access tokens, refresh tokens, or bearer credentials;
- `Authorization` or `Cookie` header values;
- Full prompt text (only length and SHA-256 digest are retained);
- Raw model completion text or SSE event stream chunks;
- TLS session tickets, master keys, or decrypted byte streams.

## Failure classification taxonomy

All qualification outcomes map to an exhaustive, typed failure taxonomy:

| Failure Code | Description | Next Action |
| --- | --- | --- |
| `LOCAL_AUTH_REJECTED` | Sandboxed client failed local cached credential recognition | Halt immediately; fail closed; no network requests |
| `AUTH_REFRESH_FAILED` | OAuth token refresh rejected by `auth.kimi.com:443` | Halt immediately; fail closed; no model request |
| `AUTH_EGRESS_POLICY_FAILED` | Auth tunnel exceeded quota (>3), attempted unapproved host, or failed DNS/SSRF | Terminate all egress; fail closed |
| `MODEL_EGRESS_POLICY_FAILED` | Model CONNECT attempted unapproved host, port, or failed DNS/SSRF | Terminate all egress; fail closed |
| `MODEL_TUNNEL_ALREADY_CONSUMED` | Client attempted a second model tunnel after allowance spent | Deny immediately; fail closed |
| `TLS_FAILED` | TLS handshake failure, invalid origin certificate, or protocol error | Consumes model allowance; fail closed; no retry |
| `SNI_MISMATCH` | `ClientHello` SNI does not equal the requested CONNECT hostname | Terminate connection immediately; fail closed |
| `DNS_POLICY_FAILED` | Hostname resolution timed out or resolved to non-public/private IP | Reject connection; fail closed |
| `MODEL_AUTH_REJECTED` | Moonshot model endpoint returned HTTP 401/403 | Model allowance spent; auth closed; no refresh replay |
| `RATE_LIMITED` | Moonshot model endpoint returned HTTP 429 | Model allowance spent; fail closed; no retry |
| `UPSTREAM_FAILED` | Moonshot model endpoint returned HTTP 5xx or connection reset | Model allowance spent; fail closed; no retry |
| `STREAM_FAILED` | SSE stream truncated, malformed, or timed out | Model allowance spent; fail closed; no retry |
| `ACP_PROTOCOL_FAILED` | ACP frame malformed, out-of-order, or attempted forbidden callback | Terminate process group; fail closed |
| `MODEL_OUTPUT_INVALID` | Model text exceeded 16 KiB or failed JSON parsing | Fail closed; no retry |
| `AOSPLAN_INVALID` | JSON parsed but failed `PlannerProposal` validation or DAG checks | Fail closed; no retry |
| `TIMEOUT` | Operation exceeded connect, stream, or global execution deadline | Terminate process group and mediator; fail closed |
| `CLEANUP_FAILED` | Process, socket, cgroup, or mount residue remained after task exit | Retain primary result; mark overall run non-complete |
| `EVIDENCE_FAILED` | Failed to atomically write canonical attempt or result JSON | Mark qualification blocked |

## Crash handling, teardown, and residue contract

Cleanup is fully idempotent and triggered on any terminal state, signal, or
error:

```text
Terminal State Reached (Success, Failure, or Crash)
  |
  +---> 1. Atomically Revoke Mediator Egress Authority
  |
  +---> 2. Interrupt Active Socket Relays & Join Worker Threads (2.0s deadline)
  |
  +---> 3. Close ACP Stdio Descriptors & Proxy Listener
  |
  +---> 4. Send SIGTERM to Provider Process Group
  |
  +---> 5. Freeze & SIGKILL Workload Cgroup via systemd / cgroup v2 path
  |
  +---> 6. Unmount Sandbox Bubblewrap Mounts & Destroy tmpfs Workspace
  |
  +---> 7. Execute Post-Execution Residue Census
  |
  v
Clean State Verified (0 processes, 0 sockets, 0 scopes, 0 cgroups)
```

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

## 46-item credential-free synthetic qualification matrix

Implementation must pass the complete 46-item synthetic test matrix before any
request for real qualification authority:

| # | Test Case Description | Expected Result |
| --- | --- | --- |
| 1 | Exact binary `initialize` through Bubblewrap and namespace launcher | `0.36.1` capabilities and terminal login method accepted |
| 2 | Strict initialize validation rejecting any capability or command mutation | Malformed initialize rejected with `ACP_PROTOCOL_FAILED` |
| 3 | Local cached authenticate success (synthetic valid token) | Authentication succeeds; session proceeds |
| 4 | Local cached authenticate rejection (synthetic invalid token) | Fails with `LOCAL_AUTH_REJECTED`; no model traffic attempted |
| 5 | Token refresh not required (valid token with >50% lifetime remaining) | No connection to `auth.kimi.com`; proceeds directly |
| 6 | Token refresh required (<300s remaining or forced refresh) | Initiates form-encoded `POST https://auth.kimi.com/api/oauth/token` |
| 7 | Synthetic OAuth refresh success through mediator relay | Token refreshed and saved; credentials updated atomically |
| 8 | Synthetic OAuth refresh failure (HTTP 400/401 on auth host) | Fails with `AUTH_REFRESH_FAILED`; no model request |
| 9 | `auth.kimi.com:443` allowed while in `AUTH_WINDOW` | CONNECT and SNI accepted; TLS relay active |
| 10 | `api.kimi.com:443` allowed once; transitions state to `MODEL_ONCE` | CONNECT and SNI accepted; model allowance spent |
| 11 | Unexpected hostname (e.g. `code.kimi.com`, `google.com`) denied | CONNECT rejected with HTTP 403 / `NETWORK_POLICY_BLOCKED` |
| 12 | Private, loopback, or link-local IP resolution denied | CONNECT rejected with `DNS_POLICY_FAILED` |
| 13 | SNI mismatch (`CONNECT auth.kimi.com` vs `SNI evil.com`) denied | Connection reset immediately; `SNI_MISMATCH` |
| 14 | Malformed `ClientHello` or missing SNI extension denied | Connection reset immediately; `SNI_MISMATCH` |
| 15 | Up to 3 sequential auth connections permitted within `AUTH_WINDOW` | Sequential auth tunnels succeed up to cap (3) |
| 16 | First model tunnel atomically closes `auth.kimi.com` egress | Auth admission revoked; active auth sockets interrupted |
| 17 | Connection to `auth.kimi.com` after model tunnel admission denied | CONNECT rejected with HTTP 503 / `AUTH_EGRESS_POLICY_FAILED` |
| 18 | Second model tunnel connection denied | CONNECT rejected with HTTP 503 / `MODEL_TUNNEL_ALREADY_CONSUMED` |
| 19 | TLS handshake failure consumes single model allowance | Qualification fails with `TLS_FAILED`; no retry |
| 20 | Model HTTP 401 cannot trigger refresh and replay | Auth closed; client cannot refresh; fails with `MODEL_AUTH_REJECTED` |
| 21 | Model HTTP 429 rate limit terminates without retry | Fails with `RATE_LIMITED`; allowance spent |
| 22 | Model HTTP 5xx upstream failure terminates without retry | Fails with `UPSTREAM_FAILED`; allowance spent |
| 23 | Model connection or stream timeout terminates without retry | Fails with `TIMEOUT`; allowance spent |
| 24 | Valid model SSE stream completes through opaque relay | Full completion received; `stopReason="end_turn"` |
| 25 | Truncated or malformed SSE stream causes terminal failure | Fails with `STREAM_FAILED`; allowance spent |
| 26 | `session/new` succeeds with empty workspace and no MCP servers | Session created; default model bound |
| 27 | Exactly one `session/prompt` sent | Single prompt accepted and processed |
| 28 | Second prompt attempt rejected | Controller rejects second prompt; `ACP_PROTOCOL_FAILED` |
| 29 | Forbidden ACP callback (tool, fs, terminal, elicitation) rejected | Process terminated immediately; `ACP_PROTOCOL_FAILED` |
| 30 | Oversized ACP frame (>64 KiB) rejected | Controller closes connection; `ACP_PROTOCOL_FAILED` |
| 31 | Oversized model output (>16 KiB total text) rejected | Accumulator rejects output; `MODEL_OUTPUT_INVALID` |
| 32 | Valid single-task `AOSPLAN/1` output succeeds | Proposal validated and compiled successfully |
| 33 | Malformed JSON, markdown fences, or extra fields rejected | Proposal rejected with `AOSPLAN_INVALID` |
| 34 | Synthetic credential canary absent from evidence and logs | Zero canary bytes found in evidence or transcripts |
| 35 | Synthetic Authorization / Cookie canaries absent from evidence | Zero auth canaries found in evidence or transcripts |
| 36 | Synthetic prompt canary absent from mediator evidence | Mediator logs contain zero prompt content bytes |
| 37 | Synthetic response canary absent from mediator evidence | Mediator logs contain zero response content bytes |
| 38 | Provider sandbox isolated from host filesystem and state | Cannot access host `/home`, `/etc/shadow`, or `/root` |
| 39 | Mediator possesses no workspace or repository authority | Mediator runs in separate sandbox with zero workspace FDs |
| 40 | Provider sandbox possesses no ambient Internet path | Direct socket connection to external IP fails with `ENETUNREACH` |
| 41 | Mediator cleanup terminates listeners and worker threads | Zero mediator threads or sockets remain after exit |
| 42 | Provider cleanup kills all child processes and cgroup tasks | Zero provider processes remain after exit |
| 43 | Zero sockets, listeners, or cgroups remain after run | Full post-run residue census passes with count 0 |
| 44 | Simulated crash at every state transition cleanly recovers | Idempotent cleanup runs; leaves zero orphaned state |
| 45 | Evidence persistence failure fails closed | Attempt/result failure marks qualification `BLOCKED` |
| 46 | No state transition may restore previously revoked authority | Revoked auth authority cannot be re-enabled |

## Conditional implementation outline (not authorized)

Execution and implementation remain strictly unauthorized. When future
implementation is separately authorized, work will follow 7 discrete slices:

1. **Slice 1: Protocol Types and State Machine Core** (`kimi_planner_types.py`, pure state machine, schemas, canonical prompt, unit tests);
2. **Slice 2: Opaque Task Egress Mediator** (`kimi_planner_egress.py`, socket relay, ClientHello SNI parser, DNS/SSRF filter, state machine integration);
3. **Slice 3: Planner Namespace and Sandbox Launcher** (`kimi_planner_runtime.py`, Bubblewrap config, descriptor mounts, cgroup isolation);
4. **Slice 4: ACP Controller and Output Compiler** (`kimi_planner_controller.py`, ACP stdio driver, callback gate, `AOSPLAN/1` validator);
5. **Slice 5: Synthetic Fixtures and Test Suite** (Complete 46-item synthetic test suite against local mock OAuth/model TLS servers);
6. **Slice 6: Evidence Persistence and CLI Harness** (`kimi_planner_qualification.py`, atomic evidence writing, preflight checks, residue census);
7. **Slice 7: Repository Qualification and Verification** (Cross-clone validation, diff check, static analysis, pre-real closure).

## Self-review findings

A rigorous architectural self-review was conducted against the Level-A
specification:

### Critical Findings: None
- The credential boundary is completely blind and end-to-end TLS is preserved.
- The network state machine (`AUTH_WINDOW -> MODEL_ONCE -> CLOSED`) guarantees
  that the model allowance is consumed atomically at tunnel admission and that
  auth authority is permanently revoked before the model request begins.
- Egress is strictly bounded: `auth.kimi.com:443` (max 3 tunnels) and
  `api.kimi.com:443` (max 1 tunnel). All other hostnames and private IPs fail
  closed.

### Important Findings: Resolved in Specification
- **Finding:** Clarified that the model allowance is consumed at *tunnel
  admission*, not at successful HTTP or inference completion. If the TLS
  handshake or HTTP request fails, the allowance is spent, preventing any
  hidden retry or replay.
- **Finding:** Explicitly enumerated allowed ACP callbacks for Kimi 0.36.1 to
  ensure no unexpected tool or elicitation requests can be processed.
- **Finding:** Added strict public unicast address validation to the mediator
  DNS resolver to prevent DNS rebinding and SSRF attacks against internal
  networks.

### Minor Findings: Resolved in Specification
- Specified exact buffer caps for `ClientHello` inspection (1,024 bytes) and
  accumulated model text (16 KiB).
- Formatted all schemas canonically with versioning markers.

## Next gate

```text
F1_KIMI_PLANNER_QUALIFICATION_DESIGN=READY_FOR_REVIEW
STRATEGY=B_COMBINED_SINGLE_REAL_PLANNER_QUALIFICATION
REAL_PLANNER_REQUEST_AUTHORIZED=NO
REAL_LEVEL1_RETRY_AUTHORIZED=NO
HISTORICAL_REAL_ATTEMPT_COUNT=1
NEXT_GATE=INDEPENDENT_ARCHITECTURAL_REVIEW_REQUIRED
```

HARD STOP.

DO NOT IMPLEMENT.
DO NOT ACCESS THE REAL CREDENTIAL.
DO NOT CONTACT KIMI.
DO NOT CREATE A REAL SESSION.
DO NOT SEND A REAL PROMPT.
DO NOT PERFORM INFERENCE.
DO NOT BEGIN F2.
