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
FREEZER_AMENDMENT_STATUS=READY_FOR_REVIEW
FREEZER_AMENDMENT_IMPLEMENTATION_AUTHORIZED=NO
TASK4_RESUME_AUTHORIZED=NO
PTRACE_AUTHORIZED=NO
PUBLISHED_PRE_AMENDMENT_BASELINE=c75d2af3ec9d31a770a2be24f24009ea4bb31acc
PRESERVED_UNPUBLISHED_TASK4_BASELINE=3eca6bffc019df91142e668bbf5d7c3700cd7dde
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

## Task-4 controller-excluding cgroup-v2 freezer amendment

This section narrowly supersedes the Task-4 process-group/SIGSTOP quiescence
design. It does not authorize implementation, publication of the preserved
unpublished Task-4 branch, credential access, or a real attempt. Tasks 1-3 at
`c75d2af3ec9d31a770a2be24f24009ea4bb31acc` remain the published baseline;
the clean, unpublished Task-4 checkpoint
`3eca6bffc019df91142e668bbf5d7c3700cd7dde` remains preserved evidence.

The blocker is architectural: the real Bubblewrap topology has an evidence
controller, an outer supervisor, an inner supervisor, and the pinned Kimi
process. The inner supervisor and provider are not members of the outer
process group. SIGSTOP/SIGCONT also causes wrapper-observable SIGCHLD state,
so pending-signal inspection cannot distinguish controller quiescence from a
clean provider lifecycle. Ptrace would avoid that symptom only by granting
forbidden provider-memory authority. The replacement primitive is the
hierarchical cgroup-v2 freezer.

### Workload topology and bounded cgroup authority

The sole admitted topology is:

```text
transient AgenticOS user service (TasksMax=21, MemoryMax=1G)
  controller/evidence coordinator       # service MainPID; never frozen
  workload cgroup                        # controller-created, domain type
    outer Bubblewrap supervisor
      inner Bubblewrap supervisor
        exact pinned Kimi Code 0.36.1
          any provider descendant
```

The service unit, rather than a host-wide cgroup root, is the delegation
boundary. It uses `Delegate=yes`, `KillMode=control-group`,
`SendSIGKILL=yes`, `TimeoutStopSec=5s`, no restart, and direct pipe transport
that does not journal raw ACP/stdout/stderr. The controller may create and
control only the fixed workload child beneath its own delegated unit. The
parent unit retains the existing `TasksMax=21`, `MemoryMax=1G`, and
`pids.events max=0` requirements; those limits apply hierarchically to the
controller and workload together.

This slice admits no workload-created child cgroup. Every outer supervisor,
inner supervisor, provider process, provider thread, and descendant must stay
in the single workload cgroup. Bubblewrap/Kimi receive neither cgroupfs nor a
cgroup control descriptor. An unexpected child cgroup, a task outside the
workload cgroup, a task entering from elsewhere, or an admitted task leaving
it is a terminal security failure.

The controller creates the outer supervisor directly in the workload cgroup
with `clone3(CLONE_INTO_CGROUP)` and the validated workload-cgroup descriptor.
There is no migrate-after-fork window and no in-workload evidence helper.
Every descendant then inherits the workload membership across fork and exec.
If `CLONE_INTO_CGROUP`, service delegation, or the fixed pipe/FD behavior is
not positively qualified on the exact host, the outcome is `BLOCKED`; the
design must not fall back to path migration or widen cgroup authority.

### Identity-first cgroup binding and controller exclusion

The unit cgroup is resolved from the controller's unified-cgroup membership
inside the exact transient service. The controller creates the fixed child
with anchored `*at` operations, opens it once with
`O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`, and validates cgroup-v2
filesystem type, normal `domain` type, owner, mode, empty initial membership,
and absence of child cgroups. It pre-opens the exact `cgroup.freeze`,
`cgroup.events`, `cgroup.procs`, `cgroup.threads`, and `cgroup.kill` controls
relative to that directory descriptor. No later security decision reopens a
cgroup control by an untrusted path string.

The immutable identity record contains the open directory descriptor plus
mount ID where `statx` exposes it, device, inode, and the fixed relationship
to the already-validated unit cgroup. A kernel generation token is added only
if the qualified cgroup filesystem exposes one; it is never synthesized from
a pathname. Before spawn, freeze, capture, thaw, kill, and removal, descriptor
identity and anchored-path identity must still agree. Deletion, a dying
cgroup, recreation at the same name, a changed mount, or any control-file
replacement blocks the run. A new path object can never inherit authority
from the old record.

The controller's PID and every controller TID are bound through pidfds and
stable `/proc` metadata to the validated unit-root identity. They must remain
outside the workload child for the entire lifecycle. Stable, duplicate-free
`cgroup.procs` and `cgroup.threads` snapshots prove the admitted workload
topology is wholly inside the workload child; the controller set must be
disjoint. Path spelling alone is never proof. Controller migration, task-set
churn across a required stable snapshot, or an unclassifiable PID/TID blocks.

### Freezer protocol and positive frozen-state proof

The cgroup freezer is the only quiescence authority. SIGSTOP and SIGCONT are
forbidden for capture quiescence. Ordinary already-qualified fatal signals
may still be used for bounded termination, but never as frozen-state proof.

After the exact terminal ACP authentication response has been processed, the
controller closes protocol input and performs this sequence under the one
non-resetting monotonic run deadline:

1. Revalidate workload-cgroup identity, controller exclusion, stable exact
   workload process/thread membership, expected role topology, resource
   limits, and absence of prior failure.
2. Write exactly `1\n` through the pre-opened `cgroup.freeze` control.
3. Mark `freeze_requested=true`; do not infer that tasks are frozen.
4. Poll the pre-opened `cgroup.events` under a bounded monotonic deadline
   until a strict total parse observes both `populated 1` and `frozen 1`.
5. Revalidate the same cgroup identity, controller exclusion, no child
   cgroup, exact stable membership, expected live roles, and zero escape.
6. Only then grant the single bounded post-terminal evidence capture.
7. After that capture is consumed, write exactly `0\n` to `cgroup.freeze`
   and wait for a strict `frozen 0` observation when normal continuation is
   still possible.
8. Continue to the already-authorized termination/drain state. If thaw cannot
   be confirmed, do not continue the provider; kill the frozen workload and
   prove recursive emptiness.

`frozen 1` is necessary but not sufficient: the post-freeze identity,
membership, topology, controller-exclusion, and prior-failure checks must all
pass. Failure to establish any element yields `BLOCKED` and authorizes no
evidence capture. The design relies on the kernel guarantee that freezing a
cgroup freezes its descendants and that `cgroup.events` reports `frozen 1`
only after the transition completes; it does not assume an instantaneous
write.

### Capture-authority state machine

The exact state is monotonic:

```text
NOT_YET_GRANTED -> GRANTED -> CONSUMED
        |             |
        +-----------> REVOKED
```

`NOT_YET_GRANTED -> GRANTED` occurs exactly once and only after the complete
post-`frozen 1` proof above and all exact capture preconditions. `GRANTED ->
CONSUMED` occurs after one bounded post-terminal capture. Every failure before
consumption transitions atomically to `REVOKED`. `REVOKED` and `CONSUMED` are
terminal; neither permits another capture.

The normal two-request ACP protocol necessarily performs bounded protocol I/O
before quiescence. That protocol I/O is not the post-terminal evidence
capture and remains governed by the closed ACP state machine. Nevertheless,
the same failure latch owns both surfaces: the first terminal protocol,
process, timeout, cgroup, census, or capture failure scrubs transient raw
buffers, revokes capture authority, and disables all subsequent capture
reads/writes. After a terminal authentication response, the only raw-pipe I/O
that can remain is the single GRANTED evidence-capture operation.

Once revoked, `finally`, context-manager exit, cleanup callbacks, evidence
serialization, error reporting, drain, and recovery paths may perform only
already-authorized lifecycle cleanup and content-free metadata checks. They
must not call capture `read`, `write`, `select`, `finish`, retry, or an alias
that can reach them. Failure precedence is explicit: the first pre-capture
failure dominates later cleanup results, while a cleanup failure may make the
overall result more conservative but never regrant capture authority.

### Freeze races and fail-closed lifecycle

- **Fork or descendant creation during freeze:** descendants inherit the
  workload cgroup and are frozen by the hierarchical operation. The stable
  post-`frozen 1` membership/topology proof must classify them; an unexpected
  task blocks before capture.
- **Migration or task entry/exit:** the workload lacks migration authority,
  and `CLONE_INTO_CGROUP` avoids initial migration. Any observed membership
  change, missing pidfd identity, entry, exit, or escape blocks. An external
  actor capable of overriding delegation is not normalized into success.
- **Exit or supervisor crash while freezing:** loss of an expected live role,
  `populated 0`, pidfd exit, or changed membership blocks. No empty frozen
  cgroup can earn capture authority.
- **Freeze timeout:** expiry of the absolute deadline before strict
  `frozen 1` revokes capture, kills the workload cgroup, and requires recursive
  `populated 0`.
- **Kill while frozen:** a fatal kill remains effective for frozen tasks.
  Cleanup prefers `cgroup.kill=1` for the whole workload subtree, then proves
  `cgroup.events populated 0`; it never thaws merely to make cleanup easier.
- **Thaw failure:** capture is already consumed, no second capture occurs,
  and the frozen workload is killed and drained. Failure to prove emptiness is
  `LOCAL_AUTH_CLEANUP_FAILED` and blocks qualification.
- **Deletion/recreation:** live descriptor identity, anchored revalidation,
  populated-cgroup rules, and final removal checks prevent a same-name cgroup
  from inheriting authority. Ambiguity is terminal.

The transient service makes the controller its exact MainPID. Normal cleanup
uses workload `cgroup.kill`, confirms recursive `populated 0`, removes the
empty workload child by identity, and then confirms the collected unit and
cgroup are gone. If the controller crashes while the workload is frozen,
systemd remains outside the unit and applies `KillMode=control-group` with a
bounded stop timeout and SIGKILL fallback to the entire service cgroup,
including the frozen child. Native qualification must prove controller death
cannot leave a frozen or credential-bearing orphan; otherwise the amendment
is `BLOCKED`. No unbounded watchdog is introduced.

### Unchanged credential, memory, network, and evidence boundaries

The controller receives no readable credential descriptor and no credential
bytes. The O_PATH descriptor-pinned, single-leaf, read-only credential mount
is unchanged. Cgroup directory/control descriptors are `CLOEXEC`, are not
passed into Bubblewrap or Kimi, and confer no credential authority.

```text
PTRACE_AUTHORIZED=NO
CONTROLLER_PROCESS_MEMORY_AUTHORITY
INTERSECT CREDENTIAL_DERIVED_PROVIDER_MEMORY
= EMPTY
EXTERNAL_NETWORK_AUTHORITY=NONE
```

`PTRACE_ATTACH`, ptrace seize/interrupt, `process_vm_readv`,
`/proc/<pid>/mem`, debugger attachment, core dumps, and equivalent
process-memory inspection are forbidden. The freezer amendment adds no DNS,
proxy, relay, listener, inherited network FD, provider endpoint, route, or
network namespace authority.

Only typed, bounded, content-free facts may persist: validated cgroup identity
class, controller-excluded boolean, expected-membership boolean, freeze/thaw
requested and observed booleans, capture-state transitions, typed failure
reason, and residue result. Raw cgroup files, PID/TID lists, process memory,
credential-derived content, ACP, stdout, and stderr do not persist.

The normative kernel basis is the Linux cgroup-v2 definition of hierarchical
`cgroup.freeze`, recursive `cgroup.events`, delegation containment, and
`cgroup.kill`, plus `clone3(CLONE_INTO_CGROUP)` direct placement:
[kernel cgroup-v2 documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
and [clone3 manual](https://man7.org/linux/man-pages/man2/clone.2.html).

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

The freezer amendment adds the following mandatory synthetic/native matrix.
Every test uses a fixed synthetic provider and disjoint temporary roots; none
may mount the real credential or launch real Kimi authentication.

| Group | Case | Required observation |
| --- | --- | --- |
| A | Controller exclusion | Controller PID/TIDs remain in the service root while outer supervisor, inner supervisor, provider, every thread, and every descendant are in the identity-bound workload cgroup. |
| A | Direct placement | Outer supervisor is born with `CLONE_INTO_CGROUP`; instrumentation proves no pre-exec membership in the controller cgroup. |
| A | Inheritance | Synthetic children and threads remain in the workload cgroup without migration. |
| A | Escape/entry | Escaped, externally entered, migrated, missing, duplicate, or unclassifiable PID/TID blocks before capture. |
| A | Unexpected child cgroup | Any descendant cgroup blocks before capture. |
| B | Freeze request | Exact `1\n` write occurs through the validated control FD; capture remains `NOT_YET_GRANTED` while `frozen 0`. |
| B | Positive freeze | Strict `cgroup.events frozen 1` plus stable identity/membership grants capture once; a synthetic counter ceases advancing. |
| B | Thaw | Exact `0\n` write and strict `frozen 0` allow normal termination; workload execution resumes only after confirmation. |
| C | Fork during freeze | Child inherits the workload boundary and is included in the kernel freeze; unexpected topology revokes capture. |
| C | Exit/crash during freeze | Expected-role loss, pidfd exit, or `populated 0` revokes capture and drains. |
| C | Freeze timeout | One absolute deadline expires, capture is never called, and recursive emptiness is proven. |
| C | Kill while frozen | Workload `cgroup.kill` removes all tasks without thaw; `populated 0` and no residue are proven. |
| C | Identity replacement | Delete/recreate, dying cgroup, mount change, path swap, or stale control FD blocks. |
| C | Thaw failure | No continuation or second capture; kill/drain and blocked cleanup result. |
| D | Signal cleanliness | Clean full Bubblewrap topology reaches frozen/thawed states without the SIGSTOP/SIGCONT-induced wrapper SIGCHLD contamination. Claim only this observed contrast, not general signal invisibility. |
| D | Pending fatal event | Independent crash or SIGSYS still produces its typed failure and cannot be masked by freeze, thaw, or cleanup. |
| E | Credential blindness | Freezer code has no readable credential FD, ptrace/process-memory/core/debugger surface, raw provider memory, or credential-derived evidence. |
| E | Network blindness | Route-less namespace, seccomp, FD, socket, listener, and endpoint proofs remain unchanged with zero external network authority. |
| E | Cgroup authority bound | Controller can operate only within its delegated service subtree; host root, siblings, ancestors, and unrelated units are denied. |
| F | Capture transitions | Exhaustively cover the four states and every admitted edge; all invalid/repeated edges fail closed. |
| F | Revocation instrumentation | Each protocol, process, timeout, freezer, membership, census, evidence, and cleanup pre-capture failure latches `REVOKED`; bomb functions prove no later select/read/write/finish/retry path. |
| F | Failure precedence | `finally`, context-manager exit, drain, serialization, and recovery cannot re-enter capture or replace the first typed failure with success. |
| F | Controller crash | Native service test kills the controller while workload is frozen and proves bounded systemd kill, recursive `populated 0`, unit collection, and no orphan. |

Native proof must run on the exact qualified WSL kernel/systemd/Bubblewrap
stack and exercise the full outer-supervisor/inner-supervisor/provider shape.
Fake-file tests alone cannot qualify freezer, direct-placement, controller
crash, or recursive-kill semantics.

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
- process, scope, cgroup, FD, socket, listener, mount, or temporary residue;
- controller membership in the workload cgroup or workload escape from it;
- cgroup identity accepted from path text, stale identity, or recreation;
- capture before positive `frozen 1`, after revocation, or more than once;
- signal-based or ptrace-based quiescence reintroduced by alias or fallback;
- controller crash leaving a frozen or credential-bearing orphan; and
- freezer authority broadening to unrelated host cgroups.

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

Publication of this freezer amendment is a design/specification checkpoint
only. It must be committed and synchronized under the preservation contract,
then hard-stop with Task 4 still unauthorized. A later explicit architectural
approval is required before an implementation plan may be amended or any
Task-4 production/test implementation resumes. The amendment itself never
claims the one-shot marker, mounts the real credential, or launches Kimi.
