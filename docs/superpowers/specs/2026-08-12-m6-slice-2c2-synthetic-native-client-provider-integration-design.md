# M6 Slice 2C.2 Synthetic Native-Client Provider Integration Design

## Status and authorization boundary

```text
M6_SLICE2C2_DESIGN_STATUS=IMPLEMENTATION_READY
NATIVE_CLIENT_QUALIFICATION=BLOCKED_OWNER_AUTHORIZATION
M6_SLICE2C1_STATUS=EARNED_LEVEL_A
```

This is a documentation-only specification. It authorizes no artifact
acquisition, installation, upgrade, authentication, provider access, or
production implementation. Those actions require separate owner authorization.

The design preserves the M6 Slice 2C.1 Level A result and defines the smallest
safe next runtime slice: an exact native Linux Codex client, if separately
authorized and qualified, performs one synthetic coding task through the
existing controller/auth-helper/provider-capability boundary without receiving
the synthetic refresh secret or upstream bearer credential and without direct
provider egress.

All authentication and provider responses remain synthetic. No real
subscription credential, provider endpoint, quota, or model execution is in
scope.

## Verified starting state and blocker

Inspection on 2026-08-12 established:

```text
WINDOWS_HEAD=f51dde54aa514e7dc3eb33b9472bd9ed436f4c9d
WSL_HEAD=f51dde54aa514e7dc3eb33b9472bd9ed436f4c9d
ORIGIN_MAIN=f51dde54aa514e7dc3eb33b9472bd9ed436f4c9d
GITHUB_MAIN=f51dde54aa514e7dc3eb33b9472bd9ed436f4c9d

WINDOWS_TREE=clean
WSL_TREE=clean
UNPUSHED_COMMITS=0
STASH_ENTRIES=0
```

The recorded Ubuntu WSL host has no authorized native Linux Codex installation:

- `command -v codex` resolves only to the Windows shim under `/mnt/c`, which is
  not a native Linux client and is not usable in the Linux security boundary;
- `/opt/agenticos/providers/codex` is absent;
- `~/.codex` is absent; and
- repository history contains no later native-client authorization or Linux
  executable qualification after the M6 Slice 0/0.2 Windows transport spike.

The prior Windows `codex-cli 0.120.0` proof qualifies the custom-provider
mechanism only. It does not qualify a Linux artifact or earn native execution.
Production work therefore stops at this design and its qualification gate.

## Design decision

Use a provider-specific extension of the already-earned M4B listener-FD
handoff pattern without using or widening Connected Build authority.

The trusted launcher creates a fixed loopback listener inside the task's
isolated network namespace and transfers that exact kernel socket to a
dedicated, filesystem- and network-confined provider-broker process. Native
Codex sees only the loopback endpoint. The broker receives only one-use,
already-connected synthetic-upstream socket capabilities and injects the
short-lived synthetic bearer received through the existing auth capability
path.

Rejected alternatives:

1. A veth or host networking bridge adds privileged routing, address, firewall,
   DNS, cleanup, and host-qualification authority not needed by the proof.
2. Generalizing M4B Connected Build conflates acquisition traffic with provider
   control-plane authority and weakens the already-earned separation between
   those capability classes.
3. A host-loopback listener is unreachable from the isolated client namespace
   without adding a bridge and would not be task-scoped by namespace identity.
4. A Unix-domain client endpoint is not an already-qualified Codex
   custom-provider transport and would require an extra forwarder.
5. A mock, Windows client, newly downloaded binary, or unqualified native
   binary cannot substitute for the required native-client proof.

The fixed provider endpoint candidate is `127.0.0.1:18081`. It is distinct from
M4B's fixed `127.0.0.1:18080` ABI. Each task namespace may reuse the numeric
address only because listener identity and reachability are namespace-scoped.

The isolated network namespace, authenticated identity-bound listener handoff,
task-scoped policy, bounded hostile-client protocol handling, and one-use
broker lifecycle prevent reuse across tasks, generations, attempts, or
launches. The loopback endpoint is authority available to the hostile sandbox
domain, not an identity-authenticated Codex process; therefore the broker
treats every accepted connection and request as hostile.

## Domain and process topology

```text
trusted controller
  |-- M5 worktree lifecycle, config, qualification, evidence, verification
  |-- synthetic auth fixture provisioning (accepted Level A residual)
  |-- exact reciprocal AF_INET socket-pair construction on host loopback
  |
  |  AF_UNIX/SOCK_SEQPACKET AOSAUTH/1
  v
auth helper (existing M6 Slice 2C.1 boundary)
  |-- refresh secret and synthetic access-token derivation
  |-- no workspace or provider-network authority
  |
  |  task/generation/attempt/launch/upstream-bound capability
  v
controller capability slot
  |
  |  controller-only authenticated AOSPROVCAP/1
  |  (upstream FD duplicate + synthetic access value)
  v
provider broker (new dedicated mount namespace and cgroup)
  |-- adopted task-sandbox listener FD
  |-- one-use controller-connected synthetic-upstream FD capability
  |-- access canary may remain in memory until verified broker death
  |-- no workspace, CODEX_HOME, auth root, Git, or controller-state mount
  |
  |  hostile HTTP/Responses/SSE on task-scoped loopback capability
  v
native Codex process tree (new M4A-derived sandbox and cgroup)
  |-- /workspace ordinary files RW; /workspace/.git masked RO
  |-- immutable non-secret config; bounded client state
  |-- no refresh/access credential and no direct upstream route
  v
hostile workspace/model-directed file operations

trusted controller
  |
  |  credential-free AOSPROVANCHOR/1 (anchor FD + deadline/control)
  v
network-disconnected task supervisor
  |-- no refresh/access credential
  |-- exact connected-upstream anchor authority; policy uses it only for shutdown
  |-- exact broker/client/fixture unit identities and controller-EOF cleanup

trusted controller
  |
  |  authenticated AOSFIXTURE/1 (accepted endpoint; expected-header digest)
  v
network-disconnected synthetic fixture (one process per request)
  |-- fixed SSE response and exact authorization-header digest verification
  |-- access canary visible only when the broker request arrives
  |-- no origin socket, workspace, client home, auth root, Git, or persistence
```

The loopback endpoint belongs to the complete hostile task sandbox domain, not
to an identity-authenticated Codex process. Any process in that network
namespace may race Codex, consume connections, or send malformed traffic. The
broker treats every accepted connection and request as hostile.

## Authority matrix

"Kernel-authorized" means that the process could obtain the object despite
cooperative application behavior. Path omission, a separate PID, an empty
environment, or a different working directory is not a boundary.

| Domain | Refresh secret | Access bearer | Workspace | `CODEX_HOME` | Network | Lifecycle/Git |
|---|---|---|---|---|---|---|
| trusted controller | yes, accepted Level A residual | transient capability transport | controller authority | creates and verifies | host authority | exclusive |
| auth helper | yes, within qualified auth root | yes | kernel denied | kernel denied | none | none |
| task supervisor | no | no | absent from mount namespace | absent from mount namespace | credential-free exact connected-upstream anchor socket authority, including kernel I/O authority; no origin-socket authority | exact client/broker/fixture termination and drain; no Git authority |
| provider broker | no; auth root absent from mount namespace | yes from first authenticated `GRANTED` receipt until verified broker death; no memory-erasure claim | absent from mount namespace | absent from mount namespace | adopted task listener plus one-use already-connected upstream FD; no origin-socket authority | no Git; own bounded process lifecycle only |
| synthetic upstream fixture | no | yes, only from received authorization header until verified per-request fixture death; no memory-erasure claim | absent from mount namespace | absent from mount namespace | one adopted already-connected server endpoint; no listener or origin-socket authority | no Git; one bounded per-request lifecycle |
| native Codex process tree | no | no | exact task workspace RW | immutable config plus bounded state | task-namespace loopback only | no Git metadata or controller lifecycle |
| hostile workspace/model actions | no | no | ordinary task files RW | no authority over immutable configuration | may attack loopback broker as hostile client | no Git/lifecycle authority |

The provider broker's filesystem non-authority is a production requirement,
not a claim about the current in-controller `TaskProviderBroker`. The existing
class cannot be used unchanged because it shares the controller process and
therefore the controller's filesystem authority.

## Dedicated provider-broker kernel boundary

The production broker runs as an identity-verified child in its own Bubblewrap
mount, PID, user, network, IPC, and UTS namespaces and a dedicated transient
systemd scope. Its network namespace has no routable interface, route, DNS, or
origin service. The broker cannot create a connection to the host, LAN,
Internet, or synthetic fixture. Its only usable network objects are the
adopted task listener FD and one controller-created, already-connected upstream
FD per authorized request. Its boundary is modeled on the existing M4B broker
process, but uses provider-specific policy and protocol code.

Its filesystem view contains only:

- the exact read-only runtime required by the qualified interpreter;
- exact read-only provider broker, model, identity, and protocol modules;
- an empty synthetic `/home/broker`, `/tmp`, and `/run`; and
- `/proc` for bounded self-observation inside its PID namespace.

The view contains no `/workspace`, provider client home, auth root, repository,
worktree, `.git`, controller state, user home, SSH material, Git credentials,
or arbitrary host path. Before READY, the broker verifies the exact directory
inventory, mounted code identities, interpreter identity, environment, working
directory, namespace identities, cgroup membership, `PR_SET_NO_NEW_PRIVS=1`,
core limit `0/0`, non-dumpability, and exact FD allowlist. Negative probes use
known disclosed paths and must demonstrate namespace/kernel denial rather than
path ignorance.

Only fixed authenticated control, listener-handoff, status, policy, and
one-use adopted-upstream descriptors are permitted. Workspace, client-home, auth-root,
repository, directory, file, socket, and controller-state descriptor leakage
fails startup before READY.

The broker receives a sealed, canonical provider policy and returns a bounded
READY record bound to its PID, start-time ticks, boot ID, executable and code
identities, namespace/cgroup identity, policy digest, and control-channel peer
identity. The controller releases neither listener adoption nor native Codex
until this READY record is authenticated.

## Cross-PID-namespace channel authentication

Linux reports `SCM_CREDENTIALS.pid` in the receiver's PID namespace. A child
inside a new PID namespace therefore cannot compare the controller's reported
PID with the controller's host-namespace PID. This design does not make that
invalid equality claim.

Every newly introduced cross-PID-namespace channel uses `AOSCHAN/1` and has the
trusted controller as one endpoint; no child-to-child channel is permitted.
Before launch, the controller creates a separate random 256-bit channel key for
that exact peer in a fresh
`memfd_create(MFD_ALLOW_SEALING|MFD_CLOEXEC)` object, writes exactly 32 bytes
once, and applies and verifies
`F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL`. The controller and child
independently verify regular-memfd type, exact size, complete seal set, fixed
descriptor number, and absence of extra aliases. Each loads the bounded key,
immediately closes its key FD, and proves through the pre-READY FD census that
the key descriptor cannot reach later exec or descendants. The controller
closes every transfer duplicate. Any wrong type/size/seal, mutation, duplicate,
or inherited alias fails startup. The child launch path permits exactly one
explicitly numbered, intentionally non-CLOEXEC duplicate across only the
initial identity-qualified exec; the first trusted startup action verifies,
loads, and closes it. Runtime FD receipt uses `MSG_CMSG_CLOEXEC`. No key FD may
cross any subsequent exec. The key
never appears in argv, environment, the filesystem, logs, or evidence. The
initial authenticated READY exchange binds the role and protocol, channel
socket identity including `SO_COOKIE`, task/generation/attempt/launch and
policy digests, controller host PID/start time/boot ID, child host PID/start
time/boot ID/UID/GID, a launch nonce, and initial sequence.

Each later frame has a canonical direction, protocol, type, sequence, nonce,
complete attempt binding, payload digest, and HMAC-SHA-256 over the complete
record. The receiver rejects an invalid MAC, wrong direction/role, unexpected
sequence, replay, extra field, or changed binding before acting on payload or
FDs. `SO_PASSCRED` remains enabled: the host controller verifies the exact
child host PID/UID/GID on every received packet; the namespaced child verifies
the controller by the per-channel MAC, the already-bound peer endpoint,
UID/GID, and the kernel-reported translated PID as supporting evidence, not by
equating it to the host PID. Startup proves through an FD census that neither
endpoint nor channel-key descriptor leaked to another process. Channel keys
are process-lifetime capabilities and are retired only by verified peer death
and descriptor closure; no memory-erasure claim is made.

The existing same-boundary `AOSAUTH/1` authentication remains an earned M6
Slice 2C.1 property. `AOSCHAN/1` governs every new cross-PID-namespace channel:
the launcher-to-controller `AOSPROVLISTENLAUNCH/1`, controller-to-broker
`AOSPROVLISTEN/1`, `AOSPROVCAP/1`, `AOSPROVANCHOR/1`, and `AOSFIXTURE/1`.

## Synthetic fixture boundary and connected-pair identity

The synthetic fixture is an explicit trusted, identity-qualified, per-request
process, not an unspecified endpoint. It runs in its own Bubblewrap mount,
PID, user, network, IPC, and UTS namespaces and dedicated transient cgroup.
Its network namespace has no interfaces, routes, or DNS. Its exact executable,
interpreter, dependency closure, code identities, namespace and cgroup
identities, environment, working directory, limits, and FD allowlist are
verified before READY. Its mount view has only the exact read-only runtime and
fixture code plus empty bounded temporary roots; it has no workspace,
`CODEX_HOME`, auth root, repository, controller state, user home, or persistent
output path. The temporary roots are private tmpfs mounts with the fixed byte
and inode caps below; its cgroup and rlimits use the fixed fixture limits.

For each authorized request the controller creates a fresh host-loopback
listener on kernel-assigned `127.0.0.1:0`, connects one client endpoint,
accepts exactly one server endpoint, and records reciprocal local/peer tuples,
family, type, connected state, `SO_COOKIE`, `SO_NETNS_COOKIE`, and supporting
device/inode evidence for both endpoints. It then closes the listener. The
pair identity is bound to the fixture identity, task/generation/attempt/launch,
policy digest, request/anchor/fixture nonces, and one-use state.

Fixture launch is supervisor-registered before request-capable execution. The
controller first records `CREATING`, starts the exact fixture in a READY gate
that cannot receive an endpoint or process a request, and verifies its unit,
PID/start-time/boot identity, namespaces, cgroup, code, and channel. It sends
that complete identity and fixture nonce to the supervisor in an authenticated,
credential-free `REGISTER_FIXTURE` record over `AOSPROVANCHOR/1`. The supervisor
independently verifies the unit/process identity, records its kill/drain
authority, and returns `FIXTURE_REGISTERED`. Only then may the controller
release the fixture READY gate or transfer an endpoint. The fixture also treats
authenticated controller-channel EOF or verified parent death as terminal and
closes its endpoint, exits, and permits its scope to be recursively drained.

The controller passes the accepted server endpoint exactly once to the fixture
over authenticated `AOSFIXTURE/1`, together with the binding, deadline, fixed
response identity, and a digest of the exact expected canonical synthetic
Authorization header. That digest is a sensitive verifier: it is confined to
the authenticated channel and fixture memory and is prohibited from every
persistent artifact or diagnostic. The fixture independently observes the FD,
verifies reciprocal socket evidence and all bindings, adopts it, and returns
authenticated `FIXTURE_ADOPTED`. Only after that acknowledgement may the
controller duplicate the connected client endpoint for the supervisor and
broker.

The fixture accepts no destination or response content from the broker or
client. It performs a constant-time comparison of the received canonical
Authorization header's digest, enforces fixed request bounds, emits only the
policy-selected fixed synthetic SSE response, and records content-free
structural evidence. There is one fixture process, one server endpoint, and
one response script per request. Retirement requires server-endpoint close,
fixture EOF or bounded abort, verified recursive cgroup drain and process
death, closure of `AOSFIXTURE/1` and its channel-key capability, temporary-root
identity checks, and permanent fixture/socket/channel-nonce retirement. The
supervisor owns the exact fixture unit identity and shuts it down on controller
EOF; durable restart reconciliation handles any survivor.

## Native client sandbox and filesystem view

The native client runs under a new provider-client profile derived from the
existing M4A/M5 boundary:

- a new mount, PID, user, network, IPC, and UTS namespace;
- a dedicated recursively drained systemd scope;
- the qualified client and exact dependencies mounted read-only;
- the M5 task worktree mounted RW at `/workspace`;
- the controller-owned inert mask mounted read-only over `/workspace/.git`;
- the authoritative checkout, main `.git`, sibling worktrees, controller state,
  auth root, broker filesystem, and real user home absent;
- a task-scoped temporary root and bounded client state only; and
- Landlock ABI 3 enforcing the exact authorized roots after namespace setup.

Client writable state is a private tmpfs mounted inside the client namespace
with `size=4MiB`, `nr_inodes=64`, and mode `0700`. The launcher creates it
before dropping namespace mount authority; failure to establish and verify the
exact mount options blocks startup. The client scope also applies fixed
`MemoryMax`, `TasksMax`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE`, and core-limit
controls. The tmpfs and process memory are charged to the same bounded cgroup.

The environment is constructed from an exact allowlist and never merged with
ambient controller state. It contains `CODEX_HOME`, `HOME`, `PATH`, locale,
`TMPDIR`, and `PWD` only if the qualified client requires them. It contains no
OpenAI, ChatGPT, provider, proxy, CA, Git, SSH, MCP, plugin, hook, keyring,
credential-store, tracing, telemetry, or user configuration variables.
Unknown or newly required variables fail qualification until classified.

The launcher applies the existing authenticated namespace and Landlock gates
before exec. It executes the already-opened qualified binary FD with
`execveat(..., AT_EMPTY_PATH)` rather than resolving the path again. The ELF
interpreter and complete dynamic dependency closure are separately
identity-qualified, mounted read-only at fixed destinations, and re-observed
inside the namespace before exec. PATH, shims, workspace binaries, and
auto-updated desktop artifacts are never executable authority.

## Immutable `CODEX_HOME` and bounded client state

`CODEX_HOME` is task/generation/attempt/launch scoped and contains no secret.
Its configuration and writable state are separate mount authorities:

1. The controller renders `config.toml` into an owner-only staging root,
   opens and identity-verifies it, and mounts that exact file read-only at the
   fixed config destination.
2. Only explicitly named state directories proven necessary by native
   qualification exist on the size- and inode-capped private tmpfs. Per-file
   growth is limited by `RLIMIT_FSIZE`; aggregate storage and object creation
   are bounded by the tmpfs byte/inode limits and client cgroup.
3. A writable file or directory may not replace, rename, shadow, symlink to,
   or overmount `config.toml` or any parent used for configuration discovery.
4. The entire root is outside `/workspace`; workspace `.codex`, configuration,
   rules, hooks, plugins, skills, MCP declarations, and hostile `AGENTS.md`
   remain untrusted model input and cannot change process authority.

The immutable configuration fixes:

- the exact synthetic model and custom provider identifier;
- `base_url = "http://127.0.0.1:18081/v1"` or the exact qualified equivalent;
- `wire_api = "responses"`;
- `requires_openai_auth = false`;
- `supports_websockets = false`;
- ephemeral execution and no history persistence;
- no ambient environment inheritance;
- update checks, telemetry/export, web search, MCP, plugins, hooks, notify,
  skills, memories, goals, multi-agent, shell, unified exec, and every other
  exec-, network-, auth-, or persistence-capable feature disabled; and
- the exact approval/sandbox behavior qualified for edit-only operation.

The complete `codex features list` output of the exact candidate is classified.
An unknown feature or a version change fails qualification. No client default
is credited as a security control.

## Native Linux client qualification gate

Qualification has two authorization-separated phases:

1. **Passive artifact qualification** may begin only after the owner authorizes
   acquisition/use of one exact artifact or designates an already installed
   artifact. It never executes candidate code. It performs filesystem/kernel
   identity, hashing, provenance, ELF/static dependency and string/section
   inspection, package-manifest verification, and static file analysis only.
2. **Active qualification-only execution** requires explicit owner
   authorization to run that exact artifact. It is bounded to synthetic
   loopback fixtures, contains no credential, performs no provider call, and
   cannot modify a production repository. Every candidate invocation,
   including `--version`, `--help`, `exec --help`, configuration parsing,
   `features list`, and child/runtime observation, belongs to this phase. It may
   run before production implementation solely to establish the execution
   facts required by the gate.

Production implementation and production task execution remain blocked until
both phases, design review, and the written implementation plan pass. This
design grants neither phase's authorization. The complete gate is:

1. The owner authorizes acquisition or identifies an already installed exact
   official Linux artifact and authorizes its use. This design grants no such
   authorization.
2. The artifact is installed in a controller-managed, non-workspace,
   non-user-writable version directory. No PATH or desktop-managed artifact is
   eligible.
3. Qualification records absolute path, version, SHA-256, size, mode,
   owner/group, device/inode, architecture, file capabilities, setuid/setgid
   state, provenance, and dependency closure.
4. Every child process and helper the client spawns under the exact invocation
   is censused and identity-qualified. An unclassified child fails closed.
5. Passive metadata, hash, provenance, ELF/dependency, package-manifest, and
   static-file facts are captured without executing the candidate. Active
   version/help/configuration/features/environment/config-discovery,
   writable-state, child-process, and runtime observations use only the
   separately authorized synthetic qualification fixture.
6. The custom provider is proven locally with
   `requires_openai_auth=false`, `supports_websockets=false`, no `auth.json`,
   no keyring, and no API-key/provider environment variable.
7. The exact Responses request schema, tool names/arguments needed for one
   bounded file edit, SSE event sequence, connection count, JSONL event schema,
   and exit behavior are captured against synthetic loopback fixtures only.
8. Hostile workspace `.codex`, `AGENTS.md`, paths, files, and symlinks have zero
   effect on effective provider, endpoint, auth mode, feature policy, or
   executable identity.
9. Read-only configuration plus the size/inode-capped tmpfs state and fixed
   cgroup/resource limits works. If
   the client requires writable configuration authority or a broader home,
   qualification fails and the design returns for review.
10. Direct synthetic-upstream connection, non-loopback connection, DNS,
    inherited socket, and ambient proxy attempts fail inside the exact sandbox.
11. Cancellation and forced client death leave no descendants, namespaces,
    cgroups, sockets, temporary state, or client-home residue.
12. The exact fixed protocol and resource limits below are sufficient. A failure does not
    authorize dynamic widening; it requires a design amendment and review.

The earlier Windows 0.120.0 result is useful as a compatibility hypothesis.
It neither selects nor qualifies the Linux version. If the owner later selects
a different version, every version-specific item above is repeated.

## Identity-bound listener capability

The client launcher receives a provider-specific, versioned launch record; it
does not reinterpret the M4B Connected Build record. The candidate ABI is
`AOSPROVLISTENLAUNCH/1` for launcher-to-controller transfer and
`AOSPROVLISTEN/1` for controller-to-broker adoption, each under `AOSCHAN/1`.

After the client namespaces exist and before native Codex exec, the trusted
launcher and controller perform a two-hop, controller-mediated handoff; the
launcher and broker never share a channel. The launcher:

1. brings up only task-namespace loopback;
2. creates one non-inheritable `AF_INET/SOCK_STREAM` listener at exactly
   `127.0.0.1:18081` with `SO_REUSEADDR=0` and `SO_REUSEPORT=0`;
3. records and validates socket family, type, bound address, fixed port,
   accepting state, `SO_COOKIE`, `SO_NETNS_COOKIE`, device, inode, and file
   type;
4. binds the launch frame to task ID, generation, attempt ID, launch nonce,
   provider-policy digest, controller identity, and a one-use launch-handoff
   nonce;
5. sends exactly one FD plus the canonical bounded frame to the controller over
   pre-created `AOSPROVLISTENLAUNCH/1`, authenticated and bound under
   `AOSCHAN/1`; and
6. after authenticated controller receipt, closes its source and channel
   descriptors and proves no extra record or FD remains before client exec.

The controller independently observes the received listener, compares all
launcher evidence, binds it to the already-verified broker
PID/start-time/boot identity and a distinct one-use adoption nonce, and sends
exactly one duplicate to that broker over controller-to-broker
`AOSPROVLISTEN/1`. After authenticated broker adoption, the controller closes
its listener source and channel transfer duplicate. Missing acknowledgement or
any failure closes all retained copies and makes the listener permanently
unusable for that attempt.

`SO_COOKIE` is mandatory on the recorded host (`SO_COOKIE=57`). If a future
supported host lacks it, the host is unqualified until an explicitly reviewed
equivalent is defined. Device/inode evidence supplements but never replaces
the socket and network-namespace cookies.

The confined broker requires exactly one `SCM_RIGHTS` descriptor and one
kernel credential record, validates the controller through the channel MAC,
bound endpoint, translated-credential rules, and every frame field, observes
the received FD independently, and requires byte-for-byte evidence equality.
Missing, duplicate, extra, truncated, replayed, already-adopted, wrong-peer,
wrong-broker, wrong-task/generation/attempt/launch, or changed socket evidence
closes every received descriptor and fails startup. The adoption channel is
one-shot and drained to authenticated EOF.

The controller compares launcher, broker, and its own listener evidence before
releasing native Codex. Both one-use handoff states are retired
on success or any failure and cannot be reconstructed from frame bytes.

## Auth capability and broker injection transaction

The auth helper continues to use the earned `AOSAUTH/1` protocol and existing
task/generation/attempt/launch/provider/upstream/purpose/epoch/nonce/sequence/
expiry binding. The refresh secret never leaves the controller/auth-helper
domain. No new auth-helper filesystem or network authority is added.

Two distinct pre-created connected `AF_UNIX/SOCK_SEQPACKET` channels prevent
credential-bearing and credential-free supervision roles from being confused:

1. `AOSPROVCAP/1` connects the trusted controller directly to the broker. The
   controller authenticated under `AOSCHAN/1` is the only accepted
   `INJECT_AUTH`, cancellation, or shutdown sender; the exact broker host
   PID/UID/GID plus its channel MAC is required for `AUTHORIZE_INJECTION`,
   acknowledgement, or structural-evidence packets. The only packet permitted
   to carry `SCM_RIGHTS` is controller-sent
   `INJECT_AUTH`, which carries exactly one already-connected upstream
   duplicate plus the synthetic access value.
2. `AOSPROVANCHOR/1` connects the trusted controller directly to the
   network-disconnected task supervisor. It is credential-free. The exact
   `AOSCHAN/1` controller peer is the only accepted command/FD sender; the exact
   supervisor host PID/UID/GID plus its channel MAC is required for
   acknowledgements. `ADOPT_UPSTREAM_ANCHOR` carries exactly one anchor
   duplicate; deadline/retirement messages carry no FDs.

Both channels enable `SO_PASSCRED`; every packet carries exactly one matching
`SCM_CREDENTIALS` record and an `AOSCHAN/1` MAC. Credentials are interpreted
under the explicit cross-PID-namespace rules above. Both use strict versioned schemas, duplicate-key
rejection, fixed record sizes, one in-flight request, timeouts, message/replay
budgets, one-use nonces, and no pathname/listener. Unexpected `SCM_RIGHTS` or
ancillary records are closed and rejected. The supervisor never receives a
bearer value or capability object; the broker never receives a supervisor
control message.

For each accepted Responses request:

1. The broker fully validates the hostile request without opening an origin
   socket and enters `PREPARED` for one request nonce.
2. The broker sends a credential-free `AUTHORIZE_INJECTION` record containing
   the complete attempt binding, request nonce, current capability sequence,
   and requested fixed upstream policy identity.
3. After validating the current auth capability, the controller derives an
   authenticated monotonic `send_deadline_ns` that is conservatively earlier
   than both bearer expiry and attempt expiry by the fixed expiry safety
   margin. Insufficient remaining lifetime rejects the request before any
   per-request upstream FD, verifier, or bearer transfer.
4. The controller creates the gated exact per-request fixture and records it in
   the durable ledger. It sends `REGISTER_FIXTURE` to the supervisor and
   requires authenticated `FIXTURE_REGISTERED` before releasing the fixture to
   return READY. Failure closes the fixture channel and drains the exact scope.
5. The controller creates the reciprocal host-loopback connected pair
   described above without DNS. No generic destination field comes from the
   broker or client. It passes the accepted server endpoint,
   `send_deadline_ns`, expected-header digest, and complete fixture binding over
   `AOSFIXTURE/1`; only authenticated `FIXTURE_ADOPTED` permits the flow to
   continue. The controller retains the client source FD until both of its
   duplicate adoptions are resolved.
6. The controller duplicates the connected client endpoint and sends the duplicate,
   request/anchor nonce, complete attempt binding, canonical socket evidence,
   and `send_deadline_ns` to the supervisor over `AOSPROVANCHOR/1`. The
   supervisor independently verifies the FD and binding, arms its monotonic
   deadline timer, adopts the anchor, and returns authenticated
   `ANCHOR_ADOPTED`. The controller does not send a bearer before this
   acknowledgement.
7. The controller holds the existing capability consumption transaction,
   revalidates expiry/revocation/current sequence and every policy field,
   duplicates the same client endpoint again, and sends one `INJECT_AUTH` record directly
   to the broker over `AOSPROVCAP/1`. It contains the duplicate, synthetic
   access value, optional synthetic account identifier, complete binding,
   request/injection/anchor nonce, `send_deadline_ns`, and canonical socket
   evidence. The refresh secret is never returned. Authenticated receipt moves
   the request to `GRANTED`; the controller closes its source FD only after the
   broker receipt and supervisor anchor are both proven.
8. The broker independently verifies the received FD and every binding. It
   serializes the complete authorization-bearing header block before sending,
   checks `CLOCK_MONOTONIC` immediately before every bounded nonblocking send,
   and aborts at or after `send_deadline_ns`. The successful-send linearization
   point is the kernel accepting the final byte of that header block before the
   deadline. The supervisor independently calls `shutdown(SHUT_RDWR)` at the
   deadline and begins broker drain unless prior authenticated retirement
   completed.
9. Immediately after the successful-send linearization point, the broker
   returns a content-free `INJECTION_COMMITTED` record with nonce, sequence,
   structural byte counts, socket identity, and the monotonic linearization
   timestamp, then enters `RESPONSE_ACTIVE`. The controller accepts it only if
   the timestamp precedes the authenticated deadline and the anchor remains
   active; otherwise it forces abort. Independently, the fixture validates the
   complete fixed request and expected-header digest, then emits only the fixed
   policy-bound SSE response.
10. The controller holds the capability transaction through authenticated
   `COMMITTED` or proven `ABORTED`. A later request may reuse the same still-
   current sequence only after the current upstream lifecycle reaches
   `RETIRED`. Expiry, cancellation, or a requested capability replacement is
   attempt-terminal: the broker/client are shut down and drained, and no new
   sequence is installed in the same process lifetime.

The combined injection/upstream state machine is:

```text
EMPTY -> PREPARED -> FIXTURE_REGISTERED -> FIXTURE_ADOPTED
                                              |
                                       ANCHOR_ADOPTED
                                              |
                                          GRANTED -> COMMITTED
                                                        |
                                                 RESPONSE_ACTIVE
                                                        |
                                               RESPONSE_TERMINAL
                                                        |
                                                   RETIRING
                                                        |
                                                    RETIRED -> EMPTY

PREPARED / FIXTURE_REGISTERED / FIXTURE_ADOPTED / ANCHOR_ADOPTED /
GRANTED / COMMITTED / RESPONSE_ACTIVE
                         \-> ABORTING -> ABORTED
```

`PREPARED` contains no bearer or upstream FD. `FIXTURE_REGISTERED` records the
supervisor's exact kill/drain authority but releases neither endpoint nor
verifier. `FIXTURE_ADOPTED` gives the fixture only its exact server endpoint,
fixed response policy, deadline, and expected-header verifier.
`ANCHOR_ADOPTED` gives only the credential-free supervisor exact-socket
authority. `GRANTED` is conservatively
treated as possibly injected even if no commit arrives. `COMMITTED` records
only the send boundary; it does not retire the socket while the response is
active.

Normal per-request retirement requires: valid terminal SSE and upstream EOF;
broker closure of its upstream FD; authenticated `RESPONSE_TERMINAL`; supervisor
`shutdown(SHUT_RDWR)` and closure of the exact anchor; synthetic fixture EOF or
a bounded abort result, verified fixture process death and cgroup drain;
authenticated `ANCHOR_RETIRED`; controller closure of
any remaining duplicate; and permanent retirement of request, injection,
anchor, and socket cookies in bounded replay state. A later request receives no
upstream FD and no authorization until all those conditions produce `RETIRED`.

If cancellation, replacement, expiry, timeout, malformed acknowledgement, or
channel death occurs in any outstanding or ambiguous state, the operation does
not return and no later request/sequence is authorized until the surviving
supervisor calls `shutdown(SHUT_RDWR)` on its exact anchor, closes the task
listener and client connection, terminates the broker scope, verifies recursive
cgroup drain, closes the anchor, terminates and recursively drains the exact
fixture scope, and observes fixture EOF or bounded fixture abort. `shutdown()` applies to the shared socket object even if the broker
duplicated its FD; cgroup drain removes every remaining broker copy.

Reaching `ABORTED` from `FIXTURE_REGISTERED` or any later state additionally
requires closure of the fixture server endpoint and `AOSFIXTURE/1`, retirement
of its channel-key capability and fixture/socket/channel nonces, recursive
fixture cgroup drain, and verified fixture process death. No next request may
begin while any registered fixture remains live or ambiguous.

The broker is trusted transport code and is authorized to possess the
synthetic access value. Broker process memory may contain the access canary from
the first authenticated `GRANTED` receipt until verified broker death and
recursive cgroup drain. Logical references are dropped after use, but no
forensic memory-erasure claim is made. The synthetic fixture may likewise
retain the canary in process memory until verified fixture death; it writes no
persistent artifact. Tests attack disconnect, replacement, cancellation,
expiry/deadline, replay, duplicate commit/retirement, wrong socket, broker or
fixture death, helper death, controller/supervisor-channel death, and
credential-bearing error paths. Any ambiguity follows the mandatory
anchor-shutdown and broker-drain path, retires every nonce/socket identity,
revokes the broker slot, and fails closed.

## Hostile client and strict Responses boundary

The listener is a task-scoped sandbox capability, not Codex authentication.
One hostile process may race another. The broker policy therefore enforces:

- at most four accepted connections for the complete attempt;
- at most four requests and four authorization injections for the attempt;
- at most one active client connection and one upstream request at a time;
- exactly one request per connection, mandatory `Connection: close`, no
  keep-alive, pipelining, or bytes after the declared request body;
- fixed `POST /v1/responses` after version qualification;
- origin-form request targets only;
- HTTP/1.1 with strict CRLF framing;
- exact header-name/value grammar, no obs-fold, no duplicate singleton headers,
  and no conflicting length/transfer framing;
- an allowlist of qualified client metadata headers;
- rejection of `Authorization`, cookies, proxy authorization, API keys,
  endpoint/host overrides, forwarding headers, upgrade/websocket headers,
  trailers, and unclassified headers;
- canonical JSON parsing with UTF-8, duplicate-key, depth, item-count, string,
  numeric, and total-size bounds;
- a version-specific top-level Responses request schema and tool schema;
- no client-controlled upstream scheme, host, port, path class, TLS policy,
  authorization, account routing, retry policy, or redirect handling; and
- stable content-free errors that never echo rejected bytes or exception text.

Connection metadata such as Codex session or request IDs is bounded and may be
held consistent across the attempt, but it is evidence only. A hostile process
can forge it and it is never used as authority.

The four-connection/request allowance is a qualification hypothesis for one
bounded tool/edit exchange. It is not authority to widen dynamically. A
competing connection consumes the same fixed budget and receives deterministic
service or rejection according to the single-active-connection state machine.
An SSE terminal event ends one response; it does not itself end the attempt,
because a qualified tool result may require a later request. Only the trusted
controller declares attempt completion after structural client/fixture state
agrees. The listener closes after controller-declared completion, exhaustion of
either connection or request budget, cancellation, expiry, or malformed
terminal state, and every later connection fails.

## Fixed protocol and evidence limits

```text
PROVIDER_MAX_CONNECTIONS_PER_ATTEMPT=4
PROVIDER_MAX_CONCURRENT_CONNECTIONS=1
PROVIDER_MAX_REQUESTS_PER_ATTEMPT=4
PROVIDER_MAX_INJECTIONS_PER_ATTEMPT=4
PROVIDER_MAX_HEADER_COUNT=32
PROVIDER_MAX_HEADER_BYTES=16384
PROVIDER_MAX_REQUEST_BYTES=2097152
PROVIDER_MAX_AGGREGATE_REQUEST_BYTES=4194304
PROVIDER_MAX_AGGREGATE_RESPONSE_BYTES=8388608
PROVIDER_MAX_SSE_EVENT_BYTES=262144
PROVIDER_MAX_SSE_EVENTS=4096
PROVIDER_HEADER_TIMEOUT_SECONDS=2.0
PROVIDER_IDLE_TIMEOUT_SECONDS=5.0
PROVIDER_ATTEMPT_LIFETIME_SECONDS=60.0
PROVIDER_EXPIRY_SAFETY_MARGIN_SECONDS=1.0
PROVIDER_CONTROL_PACKET_BYTES=16384
PROVIDER_CONTROL_TIMEOUT_SECONDS=2.0
PROVIDER_MAX_CONTROL_MESSAGES=128
PROVIDER_MAX_ANCHOR_MESSAGES=128
PROVIDER_MAX_FIXTURE_MESSAGES=32
PROVIDER_CHANNEL_KEY_BYTES=32
PROVIDER_CHANNEL_MAC_BYTES=32
FIXTURE_SCOPE_MEMORY_MAX_BYTES=67108864
FIXTURE_SCOPE_TASKS_MAX=4
FIXTURE_RLIMIT_NOFILE=16
FIXTURE_TMPFS_BYTES=1048576
FIXTURE_TMPFS_INODES=16
CLIENT_STDOUT_MAX_BYTES=1048576
CLIENT_STDERR_MAX_BYTES=1048576
CLIENT_JSONL_EVENT_MAX_BYTES=262144
CLIENT_JSONL_MAX_EVENTS=4096
CLIENT_STATE_TMPFS_BYTES=4194304
CLIENT_STATE_TMPFS_INODES=64
CLIENT_STATE_MAX_FILE_BYTES=1048576
CLIENT_STATE_EVIDENCE_MAX_OBJECTS=64
CLIENT_STATE_EVIDENCE_MAX_DEPTH=4
CLIENT_SCOPE_MEMORY_MAX_BYTES=268435456
CLIENT_SCOPE_TASKS_MAX=32
CLIENT_RLIMIT_NOFILE=64
BROKER_SCOPE_MEMORY_MAX_BYTES=134217728
BROKER_SCOPE_TASKS_MAX=8
BROKER_RLIMIT_NOFILE=32
```

The 4 MiB aggregate request and 8 MiB aggregate response limits override the
larger theoretical products of per-request/per-event and count limits. The
tmpfs size and inode limits are kernel-enforced resource bounds. Per-file size
is enforced by `RLIMIT_FSIZE`; object count and path depth are also bounded for
retained evidence and qualification by the smaller evidence limits. Every
allocator and retained artifact uses the smallest applicable bound.

The SSE parser uses an explicit qualified event allowlist and transition
machine per response. It rejects malformed UTF-8, malformed/duplicate-key JSON,
unknown events, invalid order, event after that response's terminal completion,
oversized partial frames, premature EOF, multiple terminal events, redirects,
unexpected status classes, and response headers outside the allowlist. A new
response state may begin only on the next non-pipelined connection within the
request budget. Response headers never carry `Set-Cookie`, authentication
challenges, server identity, or internal routing metadata to the client.

## Synthetic native edit proof

After qualification and separate implementation authorization, the required
positive proof is:

1. The controller creates an M5 worktree from a tiny synthetic repository and
   records its exact baseline.
2. It writes immutable non-secret Codex configuration and a bounded prompt
   requesting one deterministic ordinary-file edit.
3. The qualified native process starts inside the provider-client sandbox with
   the expected executable, process tree, environment, mounts, Landlock policy,
   namespaces, cgroup, and descriptor census.
4. Codex sends an unauthenticated Responses request only to the task-scoped
   loopback capability.
5. The trusted controller creates and identity-binds one exact already-
   connected synthetic-upstream FD, transfers a credential-free shutdown anchor
   to the supervisor, then transfers a separate duplicate with short-lived
   synthetic access authority to the broker through the existing auth
   capability. The broker injects the access canary only on that socket.
6. The synthetic upstream returns the exact qualified SSE function/tool-call
   sequence that causes the client's internal edit mechanism to modify one
   allowed workspace file. Shell, MCP, plugins, hooks, web search, and every
   other execution surface remain disabled.
7. Any qualified follow-up request stays within the same attempt policy and
   fixed four-connection budget. The synthetic upstream returns a terminal
   completion.
8. The client exits deterministically. The controller performs
   controller-mediated M5 evidence capture and independent verification under
   the existing M4A/M5 boundary.
9. The observed diff, file identity, content, verification result, client and
   broker structural evidence, and policy digests agree. Model prose is never
   treated as verification evidence.
10. The complete canary and residue matrices pass.

The exact tool name, arguments, request shape, event sequence, and connection
count are intentionally qualification outputs rather than guessed protocol
facts. Failure to establish them with the authorized native artifact blocks
implementation.

## Evidence returned to the controller

Evidence is typed, versioned, canonical, bounded, and separates model claims
from controller guarantees. It contains:

- task, generation, attempt, launch nonce, baseline, and policy digests;
- native executable path, version, digest, size, ownership/mode,
  device/inode, dependency identities, and child-process census;
- immutable config digest and the complete classified feature-policy digest;
- client environment names, descriptor census, namespace identities, cgroup,
  Landlock ABI/mask, mount identities, start/exit/signal/timeout state, and
  bounded stdout/stderr/JSONL structural records plus stream digests;
- broker executable/code/filesystem/environment/FD/namespace/cgroup identity;
- supervisor executable/code/filesystem/environment/FD/namespace/cgroup
  identity and exact controller/broker/client process authority records;
- fixture executable/code/filesystem/environment/FD/namespace/cgroup identity,
  response-policy digest, `FIXTURE_REGISTERED`/READY/adoption ordering,
  start/exit/drain state, and exact supervisor authority record for every
  request;
- each `AOSCHAN/1` channel's protocol role, endpoint `SO_COOKIE`, peer identity,
  launch nonce, sequence/retirement state, and MAC-validation result, excluding
  channel keys and MAC input containing sensitive verifier material;
- listener family/type/address/port/accepting state, `SO_COOKIE`,
  `SO_NETNS_COOKIE`, device/inode, launcher-to-controller and
  controller-to-broker handoff nonces, acknowledgement order, and one-use
  states;
- each upstream capability's family/type/local and peer address/port,
  `SO_COOKIE`, `SO_NETNS_COOKIE`, device/inode, request/injection nonce,
  monotonic send deadline and linearization timestamp, supervisor anchor state,
  response/retirement transition, and one-use adoption/closure result;
- each fixture server endpoint's reciprocal socket identity,
  fixture/adoption nonce, authenticated adoption, structural header-match
  result, EOF/abort result, verified process death, and permanent retirement;
- accepted/rejected/active connection counts, request/response/event byte
  counts, structural upstream status, injection sequence, cancellation state,
  and stable terminal failure class;
- M5 `TaskWorktreeResult`, bounded diff digest/content evidence, path classes,
  preservation classification, and independent verification result under the
  existing M4A/M5 boundary;
- per-surface canary results; and
- cleanup and residue observations for success and failure.

Evidence excludes credential bytes, request/response bodies except separately
bounded non-secret structural fixtures, rejected payload fragments, arbitrary
exception text, host workspace paths exposed to the client, and model prose as
an authority signal.

## Canary visibility matrix

The synthetic values are known test canaries, allowing exact byte searches.
"Allowed" describes deliberate runtime authority, not retained evidence.

| Surface/domain | Refresh-secret canary | Access canary |
|---|---:|---:|
| trusted controller fixture/provisioning boundary | allowed Level A residual | allowed transient capability transport |
| auth-helper memory/private auth root | allowed | allowed |
| every byte of `AOSAUTH/1` requests, responses, errors, cancellation, shutdown, and transport metadata | prohibited | allowed only in the existing bounded capability success response |
| task-supervisor memory/control traffic | prohibited | prohibited; it receives socket/deadline authority but no bearer bytes |
| provider-broker process memory from first `GRANTED` until verified process death and cgroup drain | prohibited | allowed; no forensic memory-erasure claim |
| broker-to-synthetic-upstream request | prohibited | allowed only in the injected authorization header |
| synthetic upstream fixture process memory until verified fixture death | prohibited | allowed only for exact header verification; no forensic memory-erasure claim |
| synthetic upstream fixture persistent output/artifacts | prohibited | prohibited |
| native Codex memory/environment/argv/FDs/output | prohibited | prohibited |
| broker client-facing request/response/error traffic | prohibited | prohibited |
| workspace, filenames, patches, tool output | prohibited | prohibited |
| immutable config and writable client state | prohibited | prohibited |
| controller-visible client/broker/helper logs | prohibited | prohibited |
| evidence, reports, exceptions, pytest output, retained artifacts | prohibited | prohibited |
| process metadata, core/crash files, temporary roots, Git diff/status | prohibited | prohibited |

Normative results:

```text
REFRESH_SECRET_VISIBLE_OUTSIDE_CONTROLLER_AUTH_HELPER_DOMAIN=0
ACCESS_CANARY_VISIBLE_OUTSIDE_AUTHORIZED_INJECTION_PATH=0
```

The access canary is expected inside broker memory from first authenticated
`GRANTED` until verified broker death/drain, on the broker-to-synthetic-upstream
request, and in fixture memory until verified fixture death. Its absence is
required only across prohibited surfaces; logical reference deletion is not
memory-erasure evidence. The refresh-secret canary must remain absent
everywhere outside the controller/auth-helper domain.

## Lifecycle, revocation, failure, and cleanup

Before creating a resource, the controller atomically records an
identity-bound `CREATING` entry in a durable task resource ledger. After
creation it records the exact PID/start-time/boot ID, FD/socket cookies,
device/inode, namespace/cgroup/unit, path identity, and lifecycle state as
applicable. Deterministic unit/root names include the task launch nonce. A
resource absent from the ledger cannot be deleted merely because its name
looks related.

Startup order is fail closed:

1. reconcile repository state and run restart reconciliation before accepting
   new work;
2. create the durable task ledger and controller-owned native task supervisor
   with an authenticated controller control channel;
3. qualify host/client identities, create the synthetic auth root, and accept
   authenticated auth-helper READY;
4. reserve and identity-verify the M5 worktree and Git mask;
5. create the size/inode-capped state tmpfs policy, bounded task tmp, immutable
   configuration, and fixed cgroup/resource policies;
6. create provider policy, helper capability context, one-use listener and
   upstream/fixture adoption states, and connected authenticated
   control/handoff channels;
7. launch the confined broker and authenticate broker READY;
8. create and verify the client namespaces/cgroup/Landlock boundary while the
   native exec gate remains closed;
9. create, transfer, independently verify, and one-use adopt the listener;
10. prove broker/listener/policy/client binding agreement; and
11. release native Codex.

No step falls back to host networking, a host listener, ambient config/auth,
an unconfined broker, a different client, a mock, weaker Landlock, broader
mounts, or a reissued listener.

While the controller is alive, normal completion and failures use this terminal
coordinator:

1. stop accepting client connections and close the listener;
2. call `shutdown(SHUT_RDWR)` on every retained upstream anchor and close active
   client/upstream sockets, then stop and recursively drain every exact active
   per-request fixture scope;
3. complete the injection-state abort rule, cancel the exact auth-helper
   attempt, and revoke the broker capability slot through the shared ordering
   boundary;
4. close and drain authenticated control/handoff channels and retire every
   adoption/injection nonce;
5. cancel and recursively drain native-client and broker cgroups, verifying
   `populated=0` before stopping their units;
6. capture M5 worktree evidence regardless of client/broker/helper outcome;
7. run independent verification only when policy and evidence permit it;
8. preserve dirty or committed work under existing M5 rules and remove only a
   clean baseline worktree through identity-guarded Git-aware cleanup;
9. retire the helper epoch, request authenticated helper shutdown, close its
   IPC, wait for the exact PID to die, and if necessary terminate/kill and
   reverify that exact process identity;
10. only after helper death and every applicable fixture's verified death,
   identity-check and remove known task tmp, client state, synthetic auth, and
   fixture roots after canary/evidence capture; and
11. prove no process, FD, socket, namespace, unit, cgroup, listener/upstream
    adoption,
    temporary auth root, task tmp, client home, or unexplained artifact remains.

Controller death cannot invoke that coordinator. The native task supervisor
therefore owns controller-control EOF handling. It retains no credential but
holds shutdown anchors and exact child/unit identities. On authenticated
control EOF or parent death it immediately shuts down every upstream anchor,
closes listener/control FDs, signals the client, broker, and every recorded
fixture, and drains all their process trees before exiting. The auth helper
independently treats controller
IPC EOF/parent death as terminal, retires its epoch, closes auth FDs, and exits.
These behaviors are READY-gated and adversarially tested; they are not inferred
from ordinary parent/child relationships.

On controller restart, reconciliation consumes the durable ledger before any
new provider task. It verifies that supervisor, client, broker, and helper PIDs
and every ledger-recorded fixture PID are dead; drains or stops every exact
surviving unit, including fixture units; closes/retires recorded socket,
channel-key, and capability state; verifies namespace/cgroup absence; captures delayed M5
worktree evidence; preserves dirty work; removes synthetic auth/client/tmp
roots only after exact identity, helper-death proof, and fixture-death proof for
each affected fixture root; and marks every ledger entry terminal. Unknown or
mismatched resources are preserved and reported.

Expiry, cancellation, malformed/competing traffic, client death, broker death,
auth-helper death, controller-channel death, upstream death, partial startup at
every boundary, timeout, signal, and cleanup race each have a stable structural
failure class. Cleanup errors never delete or reclassify dirty work and never
cause credential-bearing diagnostics.

| Resource | Creation/authority owner | Normal terminal action | Controller-death/restart action |
|---|---|---|---|
| durable task ledger | controller | mark terminal after evidence | authoritative reconciliation input |
| auth helper/auth root | controller + helper | retire epoch, stop/wait helper, then remove root | helper exits on EOF; restart proves death before removal |
| M5 worktree/ref/Git mask | controller | capture, verify, preserve or identity-safe remove | delayed capture; dirty/unknown work preserved |
| task supervisor/control channel | controller/systemd | authenticated stop after child drain | EOF shutdown, then exact-unit reconciliation |
| client-state tmpfs/task tmp | client namespace/controller | inventory/canary check, unmount, identity-safe removal | disappears with namespace; backing roots reconciled by identity |
| broker/client processes and scopes | supervisor/controller | signal, recursive drain, stop exact units | supervisor EOF drain; restart verifies/stops exact units |
| listener and `AOSPROVLISTENLAUNCH/1`/`AOSPROVLISTEN/1` | launcher creates; controller verifies and mediates; broker adopts | close both channels and all FD copies; retire both one-use nonces | supervisor closes listener; ledger proves both handoffs terminal |
| fixture process/server endpoint/`AOSFIXTURE/1` | controller registers fixture with supervisor, releases READY gate, then sends accepted endpoint; fixture authenticates adoption | fixed response, endpoint/channel close, authenticated EOF/abort, recursive drain and verified death, permanent key/nonce/cookie retirement | fixture exits on control EOF; supervisor stops/drains exact unit; restart reconciles identity and residue |
| upstream client source/duplicates/anchor | controller creates exact connected pair; supervisor adopts credential-free client-endpoint anchor; broker adopts credential-bearing client-endpoint duplicate | terminal SSE, broker close, supervisor shutdown/close, fixture EOF/death, authenticated retirement of every nonce/cookie before reuse | supervisor shuts anchor and drains broker/fixture; restart verifies fixture/socket terminal state |
| `AOSPROVANCHOR/1` | controller sends; supervisor acknowledges | credential-free anchor adoption/deadline/retirement and EOF drain | controller EOF triggers anchor shutdown and child drain |
| `AOSPROVCAP/1` | controller sends; broker acknowledges | credential-bearing grant/commit/response evidence and EOF drain | controller EOF is ambiguous/terminal and triggers supervisor drain |
| `AOSCHAN/1` sealed key memfds and in-memory slots | controller creates one immutable key per exact peer; each endpoint verifies | close key FDs before READY; retire logical slot with exact channel/peer lifecycle | peer EOF/death and ledger reconciliation retire channel; no memory-erasure claim |
| `AOSAUTH/1` | controller sends; helper acknowledges | authenticated cancellation/shutdown and EOF drain | helper treats controller EOF/parent death as terminal and retires epoch |

## Test and adversarial qualification corpus

Implementation uses test-driven development. Each behavior begins with a
failing test observed for the expected missing behavior before production code.

Focused unit and integration tests cover:

- client FD-bound `execveat`, ELF interpreter/dependency identity,
  child-process, config, feature, environment, size/inode-capped tmpfs,
  cgroup/resource-limit, and writable-state qualification;
- provider policy and evidence schemas, canonical digests, strict types, and
  fixed numerical limits;
- listener and already-connected upstream `SO_COOKIE`, `SO_NETNS_COOKIE`,
  reciprocal local/peer socket parameters, disconnected broker and fixture
  network namespaces, broker/fixture identity, one-use adoption, wrong peer,
  mismatched endpoint pair, pre-acknowledgement duplication, wrong context, replay,
  duplicated/truncated/oversized frames, extra FDs, and identity races;
- strict separation of credential-free `AOSPROVANCHOR/1`, controller-only
  credential-bearing `AOSPROVCAP/1`, and verifier-bearing `AOSFIXTURE/1`;
  cross-PID-namespace `AOSCHAN/1` direction/role/MAC/sequence/binding checks;
  exact memfd type/size/seals, mutation and alias rejection, immediate key-FD
  closure, no-exec inheritance, and key/channel retirement;
  exact child credentials at the host controller; translated controller PID
  treatment inside children; controller-mediated launcher/listener/broker
  transfer with no child-to-child channel; endpoint/key FD non-leakage;
  supervisor `FIXTURE_REGISTERED` before fixture release; and supervisor and
  fixture adoption acknowledgements before `GRANTED`; and bearer absence from
  every supervisor surface;
- strict HTTP request, JSON, tool-schema, response-header, per-response SSE
  event/terminal ordering, attempt completion, one-request-per-connection,
  no-pipelining, request/injection/connection/byte/event/concurrency/idle, and
  lifetime enforcement;
- authorization/cookie/API-key/endpoint/host/redirect/websocket/absolute-form/
  transfer-smuggling attempts;
- hostile same-netns processes racing Codex, consuming the connection budget,
  sending malformed requests, and attempting service after terminal state;
- cross-task, cross-generation, cross-attempt, cross-launch, stale sequence,
  expired capability, helper epoch, listener, broker, and config reuse;
- access/refresh canary exfiltration through prompts, `AGENTS.md`, `.codex`,
  tool output, filenames, file content, patches, JSONL, stdout/stderr, logs,
  errors, exception paths, protocol fields, evidence, and retained reports;
- broker/client direct upstream, non-loopback, DNS, raw origin socket, proxy,
  unauthorized or reused upstream FD, inherited descriptor,
  `/proc`, environment, auth-root, client-home, broker-root, authoritative
  checkout, sibling worktree, `.git`, SSH, Git credential, and controller-state
  attacks;
- symlink, hardlink, rename, replacement, directory identity, config shadowing,
  mount, FD reuse, socket reuse, and time-of-check/time-of-use races;
- client, child, broker, helper, upstream, controller, supervisor, and every
  control-channel death, including control EOF without controller cleanup;
- cancellation/replacement/expiry during validation and immediately before,
  during, and after `PREPARED`, `FIXTURE_REGISTERED`, `FIXTURE_ADOPTED`,
  `ANCHOR_ADOPTED`, `GRANTED`, monotonic send deadline, successful-send
  linearization, `COMMITTED`, `RESPONSE_ACTIVE`,
  `RESPONSE_TERMINAL`, and retirement, with mandatory anchor shutdown and
  ambiguous-state drain;
- per-request terminal SSE, broker-FD close, supervisor anchor retirement,
  fixture EOF/bounded abort, authenticated closure evidence, permanent socket/
  channel-key/nonce retirement, verified fixture death, and prohibition on the
  next request before `RETIRED`;
- conservative broker/fixture access-canary visibility through verified
  process death, with no logical-reference or forensic memory-erasure claim;
- partial startup failure at every created resource and process boundary;
- tmpfs byte/inode exhaustion, per-file/core/FD/process/memory limit behavior;
- success/failure/controller-restart cleanup races, durable-ledger
  reconciliation, delayed M5 capture, helper-death-before-auth-root-removal,
  and exact residue audits; and
- a real authorized native-client synthetic edit followed by
  controller-mediated M5 evidence capture and independent verification under
  the existing M4A/M5 boundary.

Final closure requires:

1. all focused and adversarial suites green;
2. native warning-clean builds and host qualification where native code changes;
3. three consecutive complete Linux suite passes after the final
   security-critical change;
4. one complete Windows regression suite with explicit platform non-claims;
5. residue checks after successful and deliberately failed executions;
6. a fresh adversarial review of authority composition, hostile loopback
   clients, listener/socket identity, credential visibility, protocol parsing,
   filesystem/network isolation, lifecycle, and cleanup;
7. resolution of every Critical and Important finding, followed by affected
   focused and complete reruns; and
8. exact repository-preservation publication and dual-clone synchronization.

Assertions, limits, exceptions, policy, or platform gates are never weakened to
obtain a green result.

## Planned implementation boundaries

The later implementation plan should prefer focused provider-specific modules
so M4A, M4B, M5, and M6 Slice 2C.1 remain byte-for-byte stable unless an
explicitly reviewed interface extension is required:

- `src/agenticos/sandbox/provider_models.py`: strict provider task, listener,
  broker, client, evidence, and failure types;
- `src/agenticos/sandbox/provider_identity.py`: provider listener and
  reciprocal already-connected upstream socket identity and one-use adoption,
  including `SO_COOKIE` and `SO_NETNS_COOKIE`, plus authenticated `AOSCHAN/1`
  channel bindings;
- `src/agenticos/sandbox/provider_boundary.py`: dedicated broker and client
  mount/network/namespace/FD/environment/resource policies;
- `src/agenticos/sandbox/provider_broker.py`: adopted-listener hostile-client
  HTTP/JSON/SSE state machine and bounded relay;
- `src/agenticos/sandbox/provider_fixture.py`: exact per-request synthetic
  fixture identity, accepted-endpoint adoption, header-verifier check, fixed
  SSE response, and authenticated retirement;
- `src/agenticos/sandbox/provider_client.py`: exact client qualification,
  immutable config rendering, argv construction, and JSONL capture;
- `src/agenticos/sandbox/provider_runner.py`: startup gates, capability
  and upstream-FD transaction coordination, durable resource ledger, M5
  capture/verification composition, cancellation, restart reconciliation, and
  cleanup;
- `native/fs_launcher/fs_launcher.c`: a provider-specific authenticated
  listener creation/handoff, capped state-tmpfs, and FD-bound client exec
  protocol revision, without changing M4B's ABI;
- `native/task_supervisor/task_supervisor.c`: provider control-EOF,
  upstream-anchor shutdown, child termination, and recursive-drain extension;
- focused unit tests for every module above; and
- Linux native-client integration/adversarial tests plus existing Windows
  regression coverage.

The detailed plan may change file decomposition after verifying current module
responsibilities, but it may not merge provider control into Connected Build,
put the broker back into the controller process, or weaken an authority claim.

## Earned claims and explicit non-claims

This documentation slice earns only:

```text
M6_SLICE2C2_DESIGN_STATUS=IMPLEMENTATION_READY
NATIVE_CLIENT_QUALIFICATION=BLOCKED_OWNER_AUTHORIZATION
M6_SLICE2C1_STATUS=EARNED_LEVEL_A
```

It does not earn native client startup, a synthetic edit, provider integration,
or any new runtime security property.

If separately authorized implementation and every gate above later pass, the
narrow candidate claim is:

```text
On the recorded qualified Linux host, one exact qualified native Codex version
can complete a bounded synthetic Responses edit through a task-scoped provider
capability while receiving no refresh secret or upstream bearer, possessing no
direct synthetic-upstream egress, preserving M5 Gitless worktree authority, and
leaving bounded controller-verifiable evidence with deterministic cleanup.
```

Even a successful implementation does not earn:

- Level B or removal of the trusted same-UID controller residual;
- real subscription authentication, auth migration, login, or token refresh;
- real OpenAI/ChatGPT/provider access or quota use;
- general native Codex, other-version, other-host, or arbitrary-provider support;
- equivalent Windows kernel isolation;
- model correctness or trust in model prose;
- shell, unified exec, MCP, plugins, hooks, notify, skills, web search,
  memories, goals, multi-agent, or arbitrary client subprocess authority;
- Connected Build widening or provider traffic through M4B grants;
- worker Git metadata, Git commit/push, PR, merge, or authoritative checkout
  access;
- multi-provider lineages, concurrent clients, resume, repair loops, or
  self-hosting; or
- permission to acquire, install, authenticate, or execute a client before
  explicit owner authorization and qualification.

## Smallest safe next action

Stop. Request explicit owner authorization for one exact native Linux Codex
artifact or an already-installed candidate and its passive qualification. If
passive qualification succeeds, request separate authorization for bounded
active qualification-only execution against synthetic local fixtures.
Production implementation begins only if both phases pass without real
credentials or provider access and the written implementation plan receives
review.
