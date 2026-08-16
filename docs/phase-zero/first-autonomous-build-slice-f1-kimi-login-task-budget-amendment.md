# F1 Kimi Owner Login Ceremony — Task-Budget Amendment

```text
F1_KIMI_LOGIN_RESOURCE_REMEDIATION=COMPLETE
ROOT_CAUSE=CGROUP_TASK_LIMIT_EXHAUSTED
QUALIFIED_TASKS_MAX=21
F1_KIMI_LOGIN_CEREMONY_STATE=OWNER_ACTION_REQUIRED
```

This amendment narrows the resource correction to the owner-login task budget
described by
`first-autonomous-build-slice-f1-kimi-login-ceremony-preparation.md`. It does
not perform login, OAuth/device authorization, credential-content access, a
real provider connection, a model prompt, inference, or any later F1/F2/G2/G1
activity.

## 1. Failed owner attempt and cleanup

The first owner-run command used a finite systemd `TasksMax=16` scope. The
official pinned client reached its initial authentication request, but the
relay failed before establishing provider TLS when the bounded DNS resolver
attempted to start its worker thread. The content-free terminal error was
`RuntimeError: can't start new thread` at `resolve_all_once()`.

Post-failure structural checks found no Kimi process, relay process/thread,
owner-login scope, cgroup, or auth listener/socket. The approved external state
root and `credentials/` directory retained uid 1000 and mode `0700`; the
credential state remained structurally `EMPTY`, with no unexpected transient
entry. No credential content was opened, read, hashed, copied, parsed, or
recorded.

## 2. Conclusive synthetic reproduction

A native synthetic fixture reproduced the pinned Kimi 0.36.1 process topology
inside the same Bubblewrap layout and a real systemd scope with the same
`KillMode=control-group`, `TimeoutStopSec=5s`, and `MemoryMax=1G` controls. The
relay used only local/synthetic TLS and an injected fixed-address resolver; it
stopped before any origin connection and attempted no external network access.

Immediately before resolver-worker creation under `TasksMax=16`, the cgroup
reported:

```text
pids.current=16
pids.max=16
process_count=4
thread_or_task_count=16
threads_by_component=bwrap:2,kimi-code:11,python3:3
```

The next `worker.start()` failed with `can't start new thread`, and
`pids.events` recorded one `max` event. This proves
`CGROUP_TASK_LIMIT_EXHAUSTED`; it is not a DNS, address-policy, TLS, SNI,
credential, or provider failure.

Four independent synthetic measurements at `TasksMax=17` admitted the same
resolver worker, reached `pids.peak=17`, retained `pids.events max 0`, and
drained to the fixture controller alone. The measured required peak is
therefore 17 tasks.

## 3. Qualified finite budget

The remediated bound is:

```text
QUALIFIED_TASKS_MAX = MEASURED_REQUIRED_PEAK + EXPLICIT_FIXED_HEADROOM
                    = 17 + 4
                    = 21
```

The four-task margin is finite and explicit: at most two transient trusted
runtime threads plus two process/exec-overlap tasks. It does not authorize
unbounded child creation. Native pressure qualification starts waiting threads
until the cgroup rejects the next task, proves `pids.peak=21` and a max event,
then releases and joins every worker. The cgroup ceiling therefore remains a
hard kernel-enforced limit.

The normal pinned topology still allows one active relay connection at a time,
a total connection limit of 32 sequential connections, four observed
processes, 16 steady tasks before resolver creation, and a measured peak of 17.

## 4. Preflight and typed failure

Before repository validation, runtime validation, credential mounting, or
provider launch, the owner wrapper now reads only the exact scope's cgroup-v2
`pids.max`, `pids.current`, and `pids.events` files. It requires:

- exact scope name `aos-kimi-owner-login.scope`;
- exact finite `pids.max=21`;
- `pids.current=1`, proving no other task already occupies the new scope; and
- `pids.events max 0`, proving the scope was not previously exhausted.

A lower budget fails as `LOGIN_TASK_BUDGET_INSUFFICIENT`; a higher or unlimited
budget fails as `LOGIN_TASK_BUDGET_UNQUALIFIED`; malformed, occupied, or
previously exhausted scopes fail with stable content-free codes. Native
preflight tests prove 16 is rejected and exact 21 is accepted without launching
the provider or attempting external network traffic.

Resolver, relay-service, and relay-connection task-start exhaustion now becomes
the typed content-free code `TASK_BUDGET_EXHAUSTED`. Accepted sockets and relay
state are closed and drained instead of emitting an unhandled worker traceback.
Only the exact CPython task-start error is translated; unrelated runtime errors
still propagate.

## 5. Preserved security envelope

This amendment does not change the provider version, executable pin,
qualification bundle, credential policy, namespace/mount layout, resolver
thread or timeout, DNS special-address policy, TLS ClientHello parsing, exact
visible SNI, ECH denial, second-ClientHello denial, or cleanup behavior.

The relay remains an opaque TLS relay. It does not terminate provider TLS or
inspect OAuth bodies, authorization codes, tokens, device codes, verification
URLs, or encrypted application records. The only admitted destination remains
exact CONNECT authority `auth.kimi.com:443` with exact SNI `auth.kimi.com` and
fresh qualified DNS/address checks. `api.kimi.com:443`, `code.kimi.com:443`, IP
literals, redirects to alternate hosts, and every other destination remain
denied.

## 6. Qualification evidence

The native task-budget tests prove:

1. exact 16-task preflight denial before provider launch;
2. deterministic 16-task exhaustion at resolver-worker creation;
3. exact 21-task preflight admission;
4. the pinned topology's 17-task peak and four-task margin;
5. complete opaque synthetic TLS relay behavior with no external connection;
6. kernel denial of deliberate task explosion at 21; and
7. scope, cgroup, process, thread, listener, and temporary credential drain
   after success and failure.

The complete owner-login suite passes 56 tests. The focused pinned-Kimi, M4B
DNS/address/TLS/egress, and Demo 0 regression corpus passes without a failure.
The final full-suite count and exact published commit are reported in the
post-publication handoff because those facts bind the final tested repository
object.

## 7. Review verdict and remaining boundary

Adversarial review covers unlimited task authority, preflight ordering and
scope occupancy, runtime-count drift, unexpected child creation, resolver
timeout weakening, cgroup escape, relay concurrency amplification, cleanup
with extra tasks, accidental provider traffic, and credential access. The
finite exact-match preflight, native topology measurement, pressure fixture,
unchanged resolver/TLS policy, and control-group drain resolve the identified
resource failure without widening provider authority.

```text
F1_KIMI_LOGIN_TASK_BUDGET_ADVERSARIAL_REVIEW=GO
UNRESOLVED_CRITICAL=0
UNRESOLVED_IMPORTANT=0
REAL_KIMI_LOGIN_RETRIED=NO
REAL_KIMI_PROMPT_EXECUTED=NO
REAL_KIMI_INFERENCE_EXECUTED=NO
```

The owner must personally run the new exact post-publication command. The
agent must not execute it. The browser/device step remains outside AgenticOS,
and no real login, model request, scheduler integration, F2, G2, or G1 is
authorized by this amendment.

```text
F1_KIMI_LOGIN_CEREMONY_STATE=OWNER_ACTION_REQUIRED
```
