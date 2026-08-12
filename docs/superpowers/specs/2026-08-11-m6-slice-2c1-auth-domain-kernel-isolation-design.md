# M6 Slice 2C.1 Auth Domain Kernel Isolation Design

## Status and scope

This design advances the synthetic subscription-auth path from process
separation to an unprivileged, kernel-enforced Level A boundary on the recorded
Linux host. The exact target claim is:

```text
AUTH_SECRET_ISOLATED_FROM_CODEX_DOMAIN
```

The trusted AgenticOS controller remains in the trusted computing base and
retains operating-system authority to create and read persistent provider-auth
state. This slice therefore does not claim the whole-system Level B invariant:

```text
AUTHORITY_TO_REFRESH_SECRET
∩
AUTHORITY_TO_HOSTILE_WORKSPACE
=
empty
```

The work remains synthetic. It installs no Codex binary, uses no real OpenAI or
ChatGPT credential, contacts no live provider, and consumes no provider quota.

## Design choice

The auth helper applies Landlock to itself before it loads authentication
state or reports readiness. This helper-side policy composes with the existing
M4A-derived bubblewrap, PID-namespace, descriptor, and Landlock boundary around
the hostile Codex/provider-client process.

This is narrower than creating a second long-lived M4A lifecycle for trusted
helper code. A dedicated auth-service operating-system identity could remove
the controller residual and pursue Level B, but it requires privileged host
provisioning and is deferred.

## Domain architecture

```text
owner-login domain
    provisions synthetic auth state through the trusted controller
              |
              v
trusted AgenticOS controller
    workspace/orchestration authority
    persistent auth-state authority (accepted Level A residual)
              |
              | one inherited AF_UNIX endpoint
              v
auth helper
    refresh-secret processing
    Landlock-confined from repositories, worktrees, and arbitrary home state
              |
              | attempt-bound short-lived access capability
              v
task provider broker
    exact provider-transport authority
    no refresh-secret authority and no workspace authority
              |
              v
Codex/provider client
    hostile /workspace authority
    no provider credential, auth-state, or auth-IPC authority
```

### Authority table

"Possesses" means secret bytes exist in the domain. "Kernel-authorized" means
the operating system would permit the domain to obtain the state even if the
normal application path does not. A convention-only omission is not treated as
a security boundary.

| Domain | Refresh secret: possesses | Refresh secret: kernel-authorized | Access token | Workspace |
|---|---:|---:|---:|---:|
| owner-login domain | yes during provisioning | yes | optional | no |
| trusted controller | yes during synthetic fixture creation | yes (accepted residual) | transient capability transport | yes |
| auth helper | yes | yes, only within auth-private root | yes | no, kernel denied |
| provider broker | no | no | yes, short-lived and attempt-bound | no |
| Codex/provider client | no | no | no | yes |

The controller's application code should still avoid unnecessary secret
serialization, but that hygiene does not change its `yes` authority result.

## Fail-closed startup sequence

Linux startup is ordered as follows:

1. The controller creates the private auth root with owner-only permissions,
   creates one `AF_UNIX SOCK_SEQPACKET` socketpair, and launches an absolute
   Python interpreter with `shell=False`, `close_fds=True`, a minimal explicit
   environment, a non-repository working directory, and only the child socket
   endpoint inherited. The environment omits `PYTHONPATH`, `PYTHONHOME`, user
   site configuration, workspace/repository import roots, and ambient Python
   startup hooks. Python isolated-mode flags disable user-site and environment
   import authority.
2. The helper immediately sets `RLIMIT_CORE` soft and hard limits to zero and
   calls `prctl(PR_SET_DUMPABLE, 0)`.
3. The helper moves its socket endpoint to the fixed descriptor and closes
   every other descriptor above standard input/output/error. It enumerates and
   validates the retained set before proceeding.
4. The helper receives one bounded, non-secret setup record over the inherited
   endpoint. Kernel credentials must identify the expected parent controller.
   The record supplies the auth-private root, the controller-observed root
   device/inode identity, and optional pre-READY denial probes; neither secrets
   nor private paths appear in argv or the environment. The helper opens the
   root as a directory with no-follow resolution from a trusted root FD and
   verifies the exact device/inode identity before using it as authority.
5. The helper calls `prctl(PR_SET_NO_NEW_PRIVS, 1)` and verifies the observed
   value with `PR_GET_NO_NEW_PRIVS`.
6. The helper requires Landlock ABI 3 or newer, creates a ruleset handling all
   ABI-3 filesystem rights, adds only the approved auth-private grant using the
   verified opened root object, calls `landlock_restrict_self()`, and closes the
   ruleset and no-longer-required construction descriptors.
7. The real helper process performs configured pre-READY filesystem probes,
   resolves `auth.json` relative to the verified auth-root FD under the active
   policy, opens and parses it, validates its schema, closes the auth file and
   root FD, and initializes bounded replay state.
8. The helper sends a credential-authenticated READY record containing its
   process identity and confinement evidence. Only then may the controller
   request a task provider capability.

Failure at any step terminates the helper without READY. There is no fallback
to ambient credentials, normal Codex login, a weaker filesystem policy, or a
different IPC server.

Windows keeps functional protocol compatibility and full-suite regression
coverage, but does not earn or advertise the Linux Landlock claim.

## Helper implementation identity

The launch contract identity-binds two independent executable inputs:

1. the absolute Python interpreter, recorded by kernel file identity and a
   SHA-256 content digest; and
2. the actual trusted auth-helper entrypoint/module artifact, recorded by its
   canonical location, kernel file identity, and SHA-256 content digest before
   launch.

The helper is launched as an absolute, identity-bound standalone entrypoint
under Python isolated mode, not resolved as `-m` through ambient import search.
It remains standard-library-only so no AgenticOS package or repository root is
needed on `sys.path`. The helper verifies its own opened entrypoint identity
before confinement. Repository, workspace, current-directory, user-site,
`PYTHONPATH`, `.pth`, and startup-hook injection must not influence module
selection.

READY includes both interpreter and helper-entrypoint identities and the fixed
protocol implementation version. The controller compares them with its
pre-launch observations and binds the process-creation PID to that attestation.
Attesting only `sys.executable` is insufficient.

## Landlock policy

The recorded host must report a working Landlock ABI of at least 3. The
ruleset's handled mask is every ABI-3 filesystem right (`0x7fff`): execute,
read/write file, read directory, remove file/directory, create all node types,
refer, and truncate.

The initial grant set contains only the existing auth-private root. It permits
the regular-file and directory operations required to read and atomically
maintain authentication state: read file/directory, write file, remove file,
make regular file, refer, and truncate. It grants no execute, device-node,
socket-node, FIFO, symlink-creation, or unrelated directory authority.

The controller first records the approved root's `st_dev`/`st_ino` identity.
The helper opens that root with `openat2(O_PATH|O_DIRECTORY|O_CLOEXEC)` from a
trusted `/` directory FD using
`RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS`. The recorded host
must provide this already-qualified `openat2()` mechanism; its absence fails
startup closed rather than selecting a string-based or newly invented fallback.
`fstat()` must match the controller's identity record. The resulting FD—not a
second pathname lookup—is the `LANDLOCK_RULE_PATH_BENEATH` parent object and
its identity is included in READY confinement evidence.

After restriction, `auth.json` is opened relative to that verified root with a
constrained `openat2()` resolution that rejects symlinks, magic links, absolute
paths, and parent escape. The root FD remains open only through this read and
the pre-READY allowed-root probes, then closes before the fixed READY census.

No repository, worktree, `/workspace`, `.git`, controller-state, provider
`CODEX_HOME`, model-output, build-artifact, arbitrary home, `/proc`, or broad
runtime root is granted. The trusted Python helper imports all required code
before enforcement. If fresh tests prove a lazy runtime read is unavoidable,
only the exact identity-bound read-only object needed may be added; broad
`/usr`, repository, home, or `/proc` grants are prohibited.

The helper's pre-READY evidence probes attempt real opens after
`landlock_restrict_self()`. They return only path labels, operation classes,
and errno classifications, never file content. They are setup evidence, not a
generic post-READY filesystem API.

## Descriptor authority

The expected retained descriptor set at READY is exactly:

```text
0  standard input, bound to null
1  standard output, bound to null
2  standard error, bound to null
3  connected AF_UNIX SOCK_SEQPACKET endpoint
```

The controller passes no repository, worktree, workspace, `.git`, controller
state, auth-file, or auth-directory descriptor. The helper-created verified
auth-root FD is the only temporary directory authority. Landlock ruleset and
temporary path FDs close before auth loading; the auth-root FD closes after
constrained relative loading and before READY. The auth file closes after
parsing.

Linux sanitation uses fixed-FD duplication plus `close_range()` where
available and a bounded fallback only when the kernel reports the syscall
unavailable. The helper validates the exact open-FD census. Tests deliberately
offer outside file and directory FDs and prove they are closed before READY.
Because `/proc` is not granted, reopening an inherited descriptor through
`/proc/self/fd` is independently kernel denied.

## IPC transport and identity

The Linux transport is one connected `AF_UNIX SOCK_SEQPACKET` socketpair. It
has no listener, pathname, port, accept loop, or connection race. Endpoint
cardinality and connection count are exactly one.

The child records `SO_PEERCRED` only as creation/connection-time sanity evidence
for the controller UID, GID, and parent PID. A pre-spawn socketpair's
controller-side `SO_PEERCRED` observation is explicitly not treated as proof of
the process that later inherits the child endpoint.

Both sides enable `SO_PASSCRED` and require exactly one kernel-generated
`SCM_CREDENTIALS` record on every packet. Per-packet credentials are the
current-sender identity check: the helper accepts only the expected controller
PID/UID/GID, and the controller requires the SCM PID to equal the exact PID
returned by helper process creation as well as the expected UID/GID. READY's
protocol identity, parent PID, helper epoch, interpreter identity, helper
entrypoint identity, and SCM sender identity must all agree before the process
is accepted. `SCM_RIGHTS`, extra ancillary records, truncated credentials, or
missing credentials fail closed.

Fixed resource limits are:

```text
IPC_MAX_REQUEST_BYTES=16384
IPC_MAX_RESPONSE_BYTES=16384
IPC_ENDPOINT_CARDINALITY=1
IPC_MAX_IN_FLIGHT_REQUESTS=1
IPC_REQUEST_TIMEOUT_SECONDS=2.0
IPC_RESPONSE_TIMEOUT_SECONDS=2.0
IPC_MAX_MESSAGES_PER_HELPER=4096
IPC_MAX_REPLAY_ENTRIES=4096
IPC_MAX_CAPABILITIES_PER_ATTEMPT=8
```

Each `recvmsg()` provides one record boundary. The receiver allocates only its
fixed maximum plus one detection byte and rejects `MSG_TRUNC`, zero-length
records, malformed UTF-8/JSON, non-object JSON, duplicate keys, unknown fields,
wrong types, wrong protocol version, missing credentials, unexpected ancillary
data, and packets received after the lifetime budget. There is no
line-delimited buffer and no delimiter search.

On Windows, functional compatibility retains one loopback TCP listener with a
single accepted connection. A controller-generated 256-bit one-use bootstrap
nonce is delivered through the child's inherited standard-input pipe, never
argv or environment, and must authenticate the only connection before any
request is processed. The listener closes immediately after that connection.
The same schemas, byte limits, timeouts, replay rules, and no-ambient-auth
behavior apply. This Windows transport, peer identity, and filesystem behavior
are regression-only and are not included in the Level A kernel claim.

## Typed protocol

The protocol version is a fixed ASCII identifier. Requests and responses use
strict schemas with no ignored fields and duplicate-key rejection.

The only credential-producing operation is
`GET_TASK_PROVIDER_CAPABILITY`. Its request binds:

```text
protocol_version
request_nonce
task_id
generation
attempt_id
launch_nonce
provider_id
upstream_scheme
upstream_host
upstream_port
provider_purpose
```

The minimum success response contains:

```text
protocol_version
request_nonce
task_id
generation
attempt_id
launch_nonce
provider_id
upstream_scheme
upstream_host
upstream_port
provider_purpose
capability_nonce
capability_sequence
issued_at
expires_at
access_token
optional account_id
```

The refresh token never appears in a response. There are no
`GET_REFRESH_TOKEN`, `GET_ACCESS_TOKEN`, `DUMP_AUTH_STATE`, `SHOW_AUTH_JSON`,
generic refresh, or generic filesystem operations. Administrative cancellation
and shutdown records are separately typed, authenticated, bounded, and return
no credentials.

Error responses contain only stable error codes and request identity needed for
correlation. They never include exception text, rejected payload fragments,
paths, tokens, auth objects, or tracebacks.

## Capability semantics and consumption

Every issued capability is bound to task ID, generation, attempt, launch nonce,
provider, upstream scheme/host/port, provider purpose, helper instance epoch,
request nonce, capability nonce, monotonically increasing per-attempt
capability sequence, issue time, expiration, and revocation state. Its expiry
is the earlier of the synthetic access-token expiry and five minutes after
issue.

Each request nonce is single-use within a helper epoch. The complete
task/generation/attempt binding is an active issuance context, not a permanently
single-use key. An active attempt may receive at most eight sequential
short-lived capabilities so a trusted broker can replace an expiring access
capability without changing task identity. The helper assigns sequence 1 on
first issuance and increments it exactly once per accepted replacement request.
Only the newest issued sequence remains current; presenting an older sequence
is stale and fails closed. A duplicate request nonce, skipped or repeated
sequence, ninth issuance, expired attempt context, or changed binding field is
rejected.

Replay caches are fixed at 4096 entries and fail closed when full. Cancellation
revokes the complete task generation/attempt context and every sequence issued
from it. Helper restart changes the instance epoch, so capabilities from the
prior epoch are rejected even when every task field and sequence match.

`SubscriptionAuthCapability` retains the complete binding and validates it at
the provider-broker consumption point. The broker receives only the
short-lived access credential and optional account identifier for its existing
exact destination policy. Cross-task, cross-generation, cross-attempt, wrong
launch nonce, provider substitution, upstream substitution, expiration,
cancellation, request replay, stale capability sequence, over-issuance, and
restart-epoch reuse all fail before header injection.

The broker never receives the refresh token, `auth.json`, the auth-private root,
owner-login state, or a generic refresh operation. The Codex/provider-client
receives none of those and remains `requires_openai_auth=false` and
`supports_websockets=false`.

## Process-memory boundary characterization

The Linux helper proves core limits are zero, dumpability is zero,
`NO_NEW_PRIVS` is one, argv and environment contain no secret or auth path, and
the fixed descriptor census is exact. Tests characterize `/proc/<pid>/fd`,
`/proc/<pid>/environ`, `/proc/<pid>/mem`, ptrace, and `process_vm_readv` from the
actual hostile provider-client sandbox.

The Codex sandbox's PID/mount namespace and Landlock policy must prevent it from
discovering or opening helper process surfaces. No helper or controller IPC FD
is inherited by that sandbox. A test that merely omits or hides the PID/path is
insufficient; the hostile process attempts known host identities and records
kernel denial.

The trusted same-UID controller may retain inspection authority as part of the
accepted Level A residual. This slice does not claim same-UID protection from
the trusted controller or malicious-kernel resistance.

## Filesystem adversarial proof

The real auth-helper process, after Landlock and before READY, attempts known
sentinels in:

- `/workspace`;
- a managed worktree;
- the authoritative repository;
- the repository's `.git` hierarchy;
- unrelated controller state;
- the user's home outside the auth-private root;
- provider-client `CODEX_HOME`, model output, and build-artifact roots.

Tests cover absolute paths, `..` traversal, cwd traversal, environment-provided
paths, symlinks from the allowed root to denied targets, hardlink/link/rename
behavior where applicable, inherited file and directory descriptors, and
`/proc/self/fd`. Expected results are kernel `EACCES`, `EPERM`, `EXDEV`, or a
namespace-mediated `ENOENT` classified as `KERNEL_DENIED`; ordinary
application refusal or path omission does not pass. Allowed auth-private
sentinel access and synthetic refresh must continue to work.

## Reverse-boundary proof

An actual M4A-derived hostile provider-client sandbox receives the known auth
root and helper identity as attack inputs and attempts to access:

- the auth root and `auth.json`;
- refresh-token storage and unrelated controller auth files;
- helper/controller IPC descriptors;
- helper `/proc` memory, environment, FD, root, and cwd surfaces.

The test also inventories its own inherited descriptors and environment. It
must demonstrate kernel denial and absence of capability authority, not merely
failure to guess a pathname. No test contacts an external provider.

## Canary audit

Synthetic fixtures retain refresh, access, account, and cookie canaries. The
approved auth domain for byte-visibility is the auth helper plus the explicit
fixture-provisioning boundary in the trusted controller. The controller's
accepted OS authority does not authorize unnecessary copies in operational
artifacts.

The audit scans Codex/client stdout, stderr, environment, synthetic
`CODEX_HOME`, workspace, controller/broker/helper logs, evidence, exception
strings, argv, environments, IPC errors, temporary files, process identity
records, crash/core artifacts, test artifacts, Git diff, and Git status. It
must report:

```text
REFRESH_SECRET_VISIBLE_OUTSIDE_APPROVED_AUTH_DOMAIN=0
```

Access-token and account canaries may exist only at their explicitly approved
short-lived transport points and must remain absent from Codex-facing output,
workspace state, evidence, errors, and Git artifacts.

## Adversarial IPC corpus

The corpus covers malformed and oversized records, zero-length and truncated
packets, duplicate keys, unexpected versions/fields/ancillary data/FDs/peers,
timeouts, disconnects, helper crashes, high-frequency traffic, message-budget
exhaustion, cancellation, helper restart, and every task/provider/upstream
substitution or replay dimension. Every case fails closed with a stable
non-secret error and no ambient-auth fallback.

## Independent review and closure

Before closure, an independent adversarial reviewer receives the exact
requirements, base SHA, candidate SHA, authority table, and test evidence. The
reviewer's purpose is to invalidate Level A by finding path/FD/proc/IPC/replay,
identity-substitution, secret-output, setup-ordering, or fallback gaps. Critical
and important findings are fixed with regression tests before publication.

Verification includes targeted auth, IPC, capability, provider-broker,
Landlock, reverse-boundary, and canary suites; native warning-clean builds if a
native component changes; three consecutive complete Linux suites under the
existing security-closure policy; and one complete Windows suite. Counts and
durations are recorded separately. Residue checks cover helper processes,
descriptors, sockets, temporary auth roots, cgroups/units, workspace canaries,
Git state, unpushed commits, unexplained files, and stashes.

The exact tested commit is pushed and independently verified on GitHub before
the non-authoring clone is synchronized with fast-forward-only operations.

## Earned and deferred claims

Successful evidence earns only:

```text
Linux recorded host:
    AUTH_SECRET_ISOLATED_FROM_CODEX_DOMAIN
    M6_SLICE2C1_STATUS=EARNED_LEVEL_A

Windows:
    protocol and functional regression only
```

It does not earn Level B, an equivalent Windows kernel boundary, protection
from the trusted controller, arbitrary-host portability, or malicious-kernel
resistance. If real kernel-denial evidence cannot establish Level A without
privilege, closure reports `PARTIAL` or `BLOCKED`; the policy is never weakened
to manufacture success.
