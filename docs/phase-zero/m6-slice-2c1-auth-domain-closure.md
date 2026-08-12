# M6 Slice 2C.1 — Auth Domain Kernel Isolation Closure

Status: **EARNED_LEVEL_A** on the recorded Linux host

Earned claim: `AUTH_SECRET_ISOLATED_FROM_CODEX_DOMAIN`

Qualification implementation checkpoint: `5f95356032914c9ba999b706bc06cd693503cfbb`

This closure is deliberately an unprivileged Level A result. The trusted,
same-UID AgenticOS controller remains in the trusted computing base and retains
OS authority to obtain the persistent authentication state. This document does
not claim whole-system separation between refresh-secret authority and hostile
workspace authority.

## 1. Approved lineage and scope

| Identity | SHA |
|---|---|
| Design | `43196fca78a92d819aa1b3f117f964ecdd1659ea` |
| Reviewed plan | `72dedf962c20acbdddb4ec3930ab67f2daef8380` |
| Final amended plan | `57188a97a00f625264fc0c5997d53342a0996bfe` |
| Owner-designated implementation base | `8added9a21feb9d9f7afd2a881a4bdff0fa3cc48` |
| Qualified implementation checkpoint | `5f95356032914c9ba999b706bc06cd693503cfbb` |

All authentication material used by this slice was synthetic. Qualification
did not install native Codex, read a real provider `auth.json`, use a real
refresh token, access token, or API key, contact an OpenAI/ChatGPT endpoint,
consume provider quota, or begin self-hosting.

## 2. Authority model

| Domain | Refresh-secret authority | Result |
|---|---:|---|
| Trusted AgenticOS controller | Yes | Explicit Level A residual |
| Auth helper | Yes | Intended terminating auth domain |
| Provider broker | No | Receives only task/provider/upstream-bound short-lived capability material |
| Codex/provider-client domain | No | Kernel/namespace denied and receives no refresh secret |
| Hostile workspace | No | Kernel/namespace denied and receives no refresh secret |

Normative result:

```text
CONTROLLER_REFRESH_SECRET_AUTHORITY=yes
AUTH_HELPER_REFRESH_SECRET_AUTHORITY=yes
BROKER_REFRESH_SECRET_AUTHORITY=no
CODEX_REFRESH_SECRET_AUTHORITY=no
```

The following stronger Level B statement is not made:

```text
AUTHORITY_TO_REFRESH_SECRET
INTERSECT
AUTHORITY_TO_HOSTILE_WORKSPACE
= empty
```

The controller residual prevents that whole-system authority claim. A
dedicated auth-service OS identity and one-time privileged provisioning remain
a future Level B hardening milestone, not a Level A dependency.

## 3. Qualified Linux helper boundary

The real helper starts as an isolated Python entrypoint and reaches READY only
after the approved ordering: minimal environment and non-repository working
directory; core limit 0/0; non-dumpability; exact FD sanitation; authenticated
setup; no-follow identity-bound auth-root open; `PR_SET_NO_NEW_PRIVS`; Landlock
ABI qualification and enforcement; rule-construction FD closure; real negative
kernel probes; constrained `auth.json` resolution/read; replay-state
initialization; authenticated READY.

The final live READY attestation recorded:

| Property | Observed value |
|---|---|
| Interpreter | `/usr/bin/python3.14` |
| Interpreter SHA-256 | `b8d8288faefdd300201f43fcf00f6f539a27218eeed3a3dff5ab10b9c4c99700` |
| Interpreter kernel identity | device `2096`, inode `11399` |
| Trusted entrypoint | `/home/brand/src/AgenticOS/src/agenticos/sandbox/auth_helper_daemon.py` |
| Entrypoint SHA-256 | `eea80dcf266290a18f6ba3851fdd422f615561cb2d5ca094b0cb7fcd610225f2` |
| Entrypoint kernel identity | device `2096`, inode `80537` |
| Environment keys | `LC_CTYPE` only |
| Python import paths | stdlib zip, stdlib, and stdlib dynamic modules only |
| Core soft/hard limits | `0 / 0` |
| Dumpable | `0` |
| No new privileges | `1` |
| Landlock ABI | `3` |
| Landlock handled filesystem mask | `0x7fff` |
| Linux READY FDs | exactly `0,1,2,3` |
| IPC FD | `3`, `AF_UNIX/SOCK_SEQPACKET` |
| Peer authentication | `SO_PASSCRED/SCM_CREDENTIALS` |
| Protocol | `AOSAUTH/1` |

The auth root is opened with no-follow directory semantics before Landlock
construction. Its `st_dev`/`st_ino` identity is bound into setup and READY
evidence, reverified, and the exact opened object supplies the Landlock rule.
The helper resolves `auth.json` relative to that root with the qualified
`openat2()` constraints. Persistent sources must be owner-only regular files,
and private storage is rejected if it overlaps a repository, worktree, or any
declared hostile root.

Python ambient import authority is stripped (`-I -S`; no `PYTHONPATH`, user
site, workspace, or repository import path). READY binds both the interpreter
and actual helper entrypoint digest and kernel identity.

## 4. Bounded authenticated IPC and capability transport

Linux uses one unnamed connected `AF_UNIX/SOCK_SEQPACKET` socketpair. There is
no pathname, listener, or accept loop. `SO_PEERCRED` is only creation-time
sanity evidence; every packet must carry exactly one `SCM_CREDENTIALS` record
whose PID/UID/GID binds the process-creation PID and protocol identity.

The strict codec rejects zero-length, oversized, truncated, malformed UTF-8,
malformed or duplicate-key JSON, unknown fields, wrong types/version,
`MSG_TRUNC`, `MSG_CTRUNC`, missing/duplicate/wrong credentials, `SCM_RIGHTS`,
and all unexpected ancillary records. Every descriptor delivered by a rejected
`SCM_RIGHTS` packet is closed before the error returns, and the helper
re-sanitizes its exact FD allowlist after ancillary failure.

```text
IPC_MAX_REQUEST_BYTES=16384
IPC_MAX_RESPONSE_BYTES=16384
IPC_REQUEST_TIMEOUT_SECONDS=2.0
IPC_RESPONSE_TIMEOUT_SECONDS=2.0
IPC_MAX_MESSAGES_PER_HELPER=4096
IPC_MAX_REPLAY_ENTRIES=4096
IPC_MAX_CAPABILITIES_PER_ATTEMPT=8
```

Capabilities bind task ID, generation, attempt, launch nonce, provider,
upstream scheme/host/port, provider purpose, helper epoch, request nonce,
capability nonce, monotonic issuance sequence, issued time, expiry, and
cancellation state. Request nonces are single-use; the complete attempt tuple
is not permanently single-use. At most eight short-lived replacement
capabilities may be issued for one active attempt.

The broker owns a synchronized immutable capability slot, coordinated with the
shared helper-epoch issuance authority. The slot lock covers active/cancelled
state and the current sequence/capability; subscription consumption then holds
the issuance-authority transaction through expiry/policy validation, header
extraction, and bounded upstream injection. The successful upstream send is
the injection linearization point. Replacement or cancellation uses the same
ordered synchronization boundary, so after either operation returns a
superseded capability cannot subsequently inject credentials. Deterministic
race tests cover replacement during validation, cancellation during
validation, replacement immediately before injection, concurrent replacement,
and stale sequence after replacement.

## 5. Negative kernel and hostile-domain proof

Real helper-side Landlock tests used known paths and proved kernel denial for
the authoritative checkout, repositories/worktrees, `.git`, hostile workspace,
controller state, unrelated home paths, model/build artifacts, and prohibited
process paths. Inherited repository files, directories, worktrees, workspace,
`.git`, controller-state and socket descriptors were deliberately supplied and
were all absent at READY. The exact FD census and process-surface probes did
not recover authority.

The reverse proof ran the actual M4A-derived `AUTH-01` hostile worker rather
than a mock. It disclosed the auth root, `auth.json`, controller-state path,
and helper PID, then attacked the paths, live FD set (including any inherited
socket), environment, and `/proc/<helper>/{fd,environ,mem,root,cwd}`. The
hostile worker retained exactly FDs `0,1,2`, no sockets, no auth capability,
and no synthetic refresh canary. Policy evaluation and cgroup drain evidence
completed the reverse-boundary result.

## 6. Canary and adversarial review result

The final audit used synthetic refresh-token, access-token, account, and cookie
canaries. It covered client stdout/stderr/environment and `CODEX_HOME`, hostile
workspace, controller/broker/helper logs, evidence, exceptions, argv,
environment, IPC errors, temporary files, process identity, crash/core
artifacts, test artifacts, tracked diff content, untracked content, and Git
status. Provider configuration explicitly disabled ambient fallback.

```text
REFRESH_SECRET_VISIBLE_OUTSIDE_APPROVED_AUTH_DOMAIN=0
```

Fresh adversarial review received the design, reviewed-plan, final-plan,
implementation-base and candidate identities, full diff, authority table, and
test evidence. It attacked path and symlink escapes, auth-root identity/races,
inherited FDs and `/proc/self/fd`, sender substitution, descriptor/ancillary
leaks, exhaustion, replay and sequence races, provider/upstream substitution,
READY ordering, exception/evidence leakage, ambient fallback, and helper-epoch
reuse.

Two Important finding families were remediated through successive review
rounds, with regressions for every accepted subfinding:

1. Capability lifecycle and linearization: materialized stale/cancelled
   capabilities could initialize a new broker; state-free broker
   reconstruction could bypass issuance state; cancellation could race after
   validation; the initial lock order could deadlock; and helper crash/restart
   could permit old-epoch reuse. The final design uses mandatory per-context
   issuance state, a controller-wide helper-epoch issuance authority,
   consistent lock ordering, and epoch retirement on authenticated replacement
   helper READY.
2. Auth-storage separation: storage could overlap the hostile workspace and
   later an arbitrary non-Git hostile root. Persistent storage now requires
   explicit forbidden-root identities and rejects overlap with repositories,
   worktrees, and every declared hostile root.

The final reviewer verdict was **READY — no unresolved Critical or Important
findings**. Subsequent schema integration and M4B fixed-FD test-harness changes
were each independently reviewed READY and did not alter the approved auth
architecture.

## 7. Verification evidence

All counts below are from the qualified implementation checkpoint. The closure
document is the only subsequent repository content change.

| Gate | Result |
|---|---|
| Final targeted auth/helper, IPC/capability, provider broker, Landlock, reverse boundary, canary, and M4A corpus | `315 passed, 1 skipped in 55.75s` |
| Complete Linux run 1 | `2168 passed, 2 skipped, 12 warnings in 410.62s (0:06:50)` |
| Complete Linux run 2 | `2168 passed, 2 skipped, 12 warnings in 376.67s (0:06:16)` |
| Complete Linux run 3 | `2168 passed, 2 skipped, 12 warnings in 383.66s (0:06:23)` |
| Complete Windows regression | `901 passed, 234 skipped in 107.36s (0:01:47)` |
| Post-residue lifecycle regression | `6 passed in 0.63s` |

The three Linux runs were consecutive after the earlier streak was reset and
the independently reviewed fixed-FD/connection-reset test harness correction
was published. The Windows run is functional regression evidence only. Its
bounded one-use bootstrap nonce may temporarily use inherited stdin; that
channel is consumed once and closed immediately. Windows does not satisfy or
claim the Linux READY FD census or equivalent kernel isolation.

## 8. Residue and preservation audit

The final runtime audit observed:

```text
AUTH_HELPER_PROCESSES=0
AUTH_IPC_RESOURCES=0
AUTH_TEMP_ROOTS=0
CORE_OR_CRASH_ARTIFACTS=0
AGENTICOS_SYSTEMD_UNITS=0
AGENTICOS_CGROUPS=0
WORKSPACE_CANARY_LEAKS=0
UNEXPLAINED_UNTRACKED_FILES=0
STASH_ENTRIES=0
```

Seventy-eight verified legacy synthetic-test roots were found under the exact
`/tmp/aos-auth-private-*` prefix: 75 were empty and three contained only
synthetic fixture `auth.json` files. All were owned by the WSL test user and
were removed; the cleanup/fail-closed lifecycle regressions then passed and a
repeat audit found zero roots. No credential-free external `spec.bundle` was
removed or targeted.

Repository preservation SHAs and clean-tree results are reported in the final
handoff footer. A Git commit cannot embed its own SHA, so the closure commit
identity is intentionally recorded there rather than self-referentially here.

## 9. Earned and non-earned claims

Earned on the recorded Linux host:

```text
M6_SLICE2C1_STATUS=EARNED_LEVEL_A
AUTH_SECRET_ISOLATED_FROM_CODEX_DOMAIN
```

Explicitly not earned:

```text
LEVEL_B=not_earned
WINDOWS_EQUIVALENT_KERNEL_ISOLATION=not_earned
REAL_SUBSCRIPTION_AUTHENTICATION=not_earned
NATIVE_CODEX_EXECUTION=not_earned
SELF_HOSTING=not_earned
```

The smallest safe next M6 slice is synthetic native-client/provider protocol
integration through this already-qualified capability boundary, still without
real subscription credentials. Level B service identity/provisioning remains
a separate later hardening milestone.
