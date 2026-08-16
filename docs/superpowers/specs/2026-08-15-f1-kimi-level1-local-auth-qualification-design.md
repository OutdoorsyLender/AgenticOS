# F1 Kimi Level-1 Local-Auth Qualification Design

## Status and authorization boundary

```text
DESIGN_STATUS=APPROVED
IMPLEMENTATION_AUTHORIZED=YES
AUTHORITATIVE_BASELINE=84ad833006e850b900a14526b381a0db10d82fb1
CURRENT_CREDENTIAL_STATE=PRESENT
CURRENT_AUTHENTICATION_STATUS=UNQUALIFIED
TARGET_EVIDENCE=LOCAL_CREDENTIAL_LOADABLE
EXTERNAL_NETWORK_AUTHORITY=NONE
REAL_LOGIN_AUTHORIZED=NO
SERVER_AUTH_VALIDATION_AUTHORIZED=NO
MODEL_INFERENCE_AUTHORIZED=NO
F2_AUTHORIZED=NO
```

This checkpoint may prove only that the exact pinned official Kimi Code CLI
0.36.1 locally recognizes and loads the already-present credential. It must
not claim current server acceptance, membership, token validity, quota, model
availability, or inference readiness.

AgenticOS may validate credential metadata but must never open the credential
for content, read it, hash it, deserialize it, copy it, grep it, print it,
parse expiry fields, inspect tokens, or use any credential bytes as evidence.
No design or implementation decision below broadens that boundary.

## Evidence ladder

| Level | Meaning | State in this slice |
| --- | --- | --- |
| 0 | `CREDENTIAL_STRUCTURALLY_PRESENT` | Already earned |
| 1 | `LOCAL_CREDENTIAL_LOADABLE` | Sole target |
| 2 | `SERVER_AUTH_ACCEPTED_NON_INFERENCE` | `BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT` |
| 3 | `REAL_MODEL_INFERENCE` | Out of scope |

A successful ACP authentication response is Level 1 only. The controller must
encode the Level-2 blocked result independently so no success path can promote
Level 1 to Level 2.

## Verified pinned-source basis

The source basis is the annotated official tag
`@moonshot-ai/kimi-code@0.36.1`, tag object
`336fed3b5f265c986d4f43808da98f3c6b4bbd16`, peeled to commit
`13d86f8b7bb2443a3b8222e7d94deb0a66429f8e`.

The exact relevant source paths and call chain are:

```text
packages/acp-server/src/server.ts
  initialize(...)
  authenticate({ methodId: "login" })
    -> ensureAuthed()

packages/agent-core-v2/src/app/auth/authService.ts
  ensureReady()
    -> reload local auth configuration
    -> oauth.getCachedAccessToken()
  summarize()
    -> local auth status

packages/oauth/src/oauth-manager.ts
  getCachedAccessToken()       # local cache path used by ACP authentication
  ensureFresh()                # distinct refresh-capable path, not admitted

packages/oauth/src/storage.ts
  load()                       # local credential read
  save()                       # temp, fsync, rename; not used by admitted flow
```

`apps/kimi-code/src/cli/sub/login.ts` is an interactive login flow and is
forbidden here. `session/new`, `session/prompt`, `/usage`, `/models`, the
general TUI, source-built helpers, patched binaries, and direct AgenticOS HTTP
calls are also outside the admitted path.

The implementation must preserve these source-derived conclusions with
synthetic execution before granting the read-only real credential mount. If
the pinned executable attempts a credential write or network access during
the admitted sequence, the real gate does not gain more authority; it stops.

## Reused qualified security domain

The new runner extends the already-qualified Kimi Planner domain without
redesigning it. It retains:

- the exact 0.36.1 executable, artifact manifest, executable hash, mode, and
  Bubblewrap identity checks;
- immutable config and the tool-free Planner profile with `tools: []` and
  `subagents: []`;
- an empty tmpfs `/workspace` with no checkout, Git metadata, controller
  state, board state, hostile worker, or other provider state;
- cleared and exactly allowlisted environment variables, disabled telemetry,
  cron, auto-update, skills, plugins, hooks, MCP, and API-key fallback;
- new user, PID, mount, network, IPC, UTS, and cgroup namespaces;
- finite cgroup, process, time, transcript, stdout, stderr, and FD bounds; and
- recursive termination, drain, and post-run residue census.

The runtime receives no DNS configuration, proxy, provider relay, external
host allowlist, or default route. It may use only stdin/stdout for ACP.

## Components and boundaries

### Local-auth policy and result model

A focused provider module will define immutable request/result types and
stable failure codes. The result surface contains only:

```text
F1_KIMI_LEVEL1_LOCAL_AUTH_QUALIFICATION=<COMPLETE|BLOCKED>
F1_KIMI_LOCAL_CREDENTIAL_STATE=<LOADABLE|REJECTED|BLOCKED>
F1_KIMI_AUTH_STATE=LOCAL_ONLY
F1_KIMI_LEVEL2_NON_INFERENCE_STATUS=
  BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT
```

No raw ACP frame, stderr text, credential path, token-like value, credential
digest, credential size, expiry, OAuth payload, or client error detail enters
the persisted result. Stable typed reason codes are sufficient.

### Metadata-only credential validator

The trusted launcher validates the fixed provider-state ancestry and exact
credential directory without reading file content. Validation requires:

- absolute expected ancestry with no symlink at any component;
- private, expected-UID directories with no group/world write authority;
- exactly one directory entry, with the expected final leaf name;
- no temporary or unknown entry;
- a non-symlink regular leaf owned by the expected UID;
- exact mode `0600` and link count `1`; and
- stable device/inode/type/UID/mode/link metadata through mount setup.

The launcher obtains an `O_PATH | O_NOFOLLOW` descriptor for the leaf and
uses `fstat` only. It never obtains a readable descriptor. Bubblewrap binds
the descriptor-pinned inode through `/proc/self/fd/<n>` as read-only at the
exact sandbox credential leaf. The descriptor is passed only as long as
Bubblewrap needs it to construct the mount and is not exposed to the Kimi
process after setup. This prevents path substitution between validation and
mounting without granting AgenticOS content authority.

Only the single credential file is imported. The host credential directory is
not mounted. Its sandbox parent is read-only, so the client cannot create a
temporary file, replace the leaf, or update another provider-state object.
An attempted write is a qualification failure, not a reason to remount the
directory writable.

### Route-less ACP runner

The runner launches only:

```text
/opt/agenticos/kimi/bin/kimi acp
```

inside the qualified Bubblewrap domain. `--unshare-net` creates a private
network namespace with no external interface, route, DNS configuration,
proxy, relay, or passed network FD. The outer launcher creates no listener and
performs no provider connection. Continuous namespace/socket census and the
post-run census treat any unexpected external endpoint or listener as a
policy failure. No network authority may be added to make the sequence pass.

### Closed ACP Level-1 state machine

The controller sends exactly two bounded JSON-RPC requests over stdio:

```text
1. initialize(protocolVersion=1, bounded empty capabilities)
2. authenticate(methodId="login")
```

The second request is sent only after one valid, correlated initialize
response. The state machine accepts exactly one correlated authentication
terminal response and then terminates the client. It never sends
`session/new`, `session/prompt`, another request, or a notification that can
create a model session.

It fails closed on malformed or duplicate JSON, duplicate response IDs,
unknown messages or callbacks, wrong method shape, invalid UTF-8, excess
bytes/frames, out-of-order responses, process crash, timeout, pipe-drain
failure, or cleanup failure. Stdout and stderr are bounded concurrently. Raw
content remains ephemeral and is reduced to typed results before reporting.

### One-shot real-attempt gate

The real path is unavailable until all required synthetic, regression,
adversarial, diff, secret-scan, and residue gates pass in the same candidate.
Immediately before launch it repeats all artifact, runtime, profile, config,
credential metadata, namespace, cgroup, environment, FD, process, and
pre-residue checks.

A private non-secret attempt marker is created atomically before the Kimi
process starts. Its schema records only candidate commit identity, pinned
runtime identity, monotonic attempt number `1`, and typed lifecycle state. It
contains no credential locator or content-derived value. Existing or
ambiguous marker state blocks launch. The marker is preserved as one-shot
evidence; it is not classified as unexplained residue and must never be
removed to enable a retry.

There is no retry loop. Any launch ambiguity, timeout, crash, malformed ACP,
write attempt, network-policy violation, census gap, cleanup failure, or
evidence-write failure produces `BLOCKED`.

## Synthetic qualification

Synthetic tests use private temporary state roots and synthetic fixtures only.
They must be demonstrably disjoint from the real provider-state root. Tests
that exercise client parsing use synthetic credentials whose contents may be
known to the test fixture; production code remains incapable of reading
credential content.

The minimum matrix is:

| Case | Required observation |
| --- | --- |
| No credential | Structural/local rejection; no network or mutation |
| Structurally valid synthetic credential | Local authenticate success can map only to Level 1 |
| Malformed credential | Stable rejection or blocked ambiguity, never success by structure alone |
| Expired credential | Exercise only if pinned client classifies expiry locally; never refresh |
| Revoked/tombstone state | Local rejection where represented; no rewrite |
| Initialize success | Does not imply authentication |
| Authenticate success | `LOADABLE` plus `LOCAL_ONLY`, Level 2 remains blocked |
| Authenticate rejection | `REJECTED`; credential remains unchanged |
| Malformed ACP | `BLOCKED` with bounded drain |
| Wrong `methodId` | Rejected by controller/fixture; not admitted to real flow |
| Duplicate response | `BLOCKED` |
| Timeout | Kill, recursive drain, `BLOCKED` |
| Crash | Drain and `BLOCKED` |
| Network attempt | Kernel-denied and policy-failed; no external traffic |
| Credential write attempt | Read-only mount denies it; no authority expansion |
| Cleanup/residue | Zero process, scope, cgroup, listener, socket, and temp residue |
| Non-promotion | Level-1 success cannot set or imply Level 2 |

Synthetic canaries cover credential bytes, API keys, provider paths, host
paths, controller state, workspace state, environment, argv, ACP output,
stderr, FDs, result objects, evidence, and cleanup reports. Synthetic success
is never accepted as evidence about the real credential.

## Classification rules

The controller uses the following total mapping:

| Observation | Level-1 state | Qualification |
| --- | --- | --- |
| One valid initialize response followed by one valid successful `authenticate("login")` response | `LOADABLE` | `COMPLETE` |
| One valid initialize response followed by a recognized local credential rejection | `REJECTED` | `BLOCKED` |
| Any other behavior or incomplete evidence | `BLOCKED` | `BLOCKED` |

Every row reports `F1_KIMI_AUTH_STATE=LOCAL_ONLY` and
`F1_KIMI_LEVEL2_NON_INFERENCE_STATUS=BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT`.
Local rejection must not delete, rewrite, refresh, replace, or repair the
credential. It is a completed observation but does not earn the requested
`LOCAL_CREDENTIAL_LOADABLE` qualification.

## Adversarial review gate

Before the real attempt, a fresh adversarial review must resolve every
Critical and Important finding concerning:

- Level 1 mislabeled or transitively consumed as Level 2;
- hidden DNS, proxy, relay, inherited socket, or external network authority;
- `authenticate` reaching refresh, login, server-validation, or save paths;
- credential mutation or controller content access;
- credential or secret content entering output, logs, evidence, or errors;
- implicit session creation, prompt, model request, or inference;
- API-key or ambient-provider fallback;
- synthetic-real path, mount, marker, or state crossover; and
- process, scope, cgroup, FD, socket, listener, mount, or temporary residue.

An unresolved Critical or Important finding blocks the real attempt.

## Implementation and test surface

The implementation plan may refine filenames but not authority. Expected
focused changes are:

```text
src/agenticos/providers/kimi_local_auth.py
src/agenticos/providers/kimi_runtime.py
tests/providers/test_kimi_local_auth.py
tests/providers/test_kimi_local_auth_linux.py
tests/providers/fixtures/kimi_local_auth_fixture.py
docs/phase-zero/first-autonomous-build-slice-f1-kimi-local-auth-closure.md
```

The test gate includes new local-auth tests, all Kimi passive tests, Kimi
login/remediation tests, provider-protocol tests, Demo 0, relevant M4/M5
security regressions, the full native WSL suite, `compileall`,
`git diff --check`, a secret-pattern scan, and pre/post process, environment,
FD, network, scope, cgroup, socket, listener, and filesystem censuses.
No test may use real provider traffic.

## Closure and publication

If all conditional gates are satisfied, perform at most one real Level-1
attempt and publish a narrow closure containing the required four result
fields and sixteen numbered evidence sections. The closure must state the
exact pinned source path and protocol sequence, zero external network
authority, metadata-only AgenticOS credential handling, synthetic results,
the single real result, the Level-1/Level-2 distinction, censuses, absence of
session/prompt/inference, test and review evidence, final commit, clone/ref
synchronization, and the next architectural decision.

Publication follows the standing preservation contract: exact tested WSL
commit, review, diff inspection, `git diff --check`, commit, direct push or
approved exact-SHA bundle fallback, independent GitHub `ls-remote`, native
fast-forward synchronization, clean Windows and WSL trees at divergence
`0/0`, zero stashes, zero unexplained files, and zero runtime residue.

The slice then hard-stops. It does not log in, validate server auth, send a
model prompt, perform inference, begin F2, or choose a Level-2 workaround.
