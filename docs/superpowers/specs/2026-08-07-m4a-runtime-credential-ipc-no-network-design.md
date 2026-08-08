# Milestone 4A Runtime, Credential, IPC, and No-Network Closure

**Status:** Approved design, amended 2026-08-07
**Baseline:** `main` at `dcf24fe4a50f82761dc6ab8eeb34ae9b33ecba88`
**Scope:** Linux/WSL2 L1 INSPECT and L2 BUILD tool execution only

## Purpose

Milestone 4A composes the proven systemd/cgroup-v2 process boundary and native
Landlock ABI-v3 filesystem boundary with an independently verified namespace and
minimal runtime-view boundary. On the recorded Linux/WSL2 host, L1 and L2 workers
must run without provider credentials, host or external network connectivity,
host pathname or abstract Unix-socket reachability, or visibility of ungranted
host filesystem trees.

This remains a narrow, host-specific claim. M4A does not implement provider
integration, connected-build networking, a network broker, seccomp, native
Windows isolation, or a general container runtime.

The governing principles are:

> Models reason. AgenticOS guarantees.

> Host path strings are locators. Opened object identity is authority.

> `/workspace` is the worker-facing AgenticOS ABI.

## Preserved invariants

M4A must not weaken the M2B/M3B boundary:

- The transient systemd task scope and host cgroup v2 hierarchy remain the
  authoritative process-containment mechanism.
- No hostile code executes before exact cgroup containment is verified.
- No hostile code executes before unexpected descriptors are removed, trusted
  roots are identity-verified, `PR_SET_NO_NEW_PRIVS` succeeds, Landlock is
  applied, and the controller authenticates the complete security transcript.
- The worker inherits exactly file descriptors 0, 1, and 2.
- The trusted C launcher remains single-threaded and invokes no shell, fork,
  subprocess, plugin, or hostile code before restriction.
- Cancellation remains bounded and authoritative through cgroup cleanup,
  `cgroup.kill` when required, recursive `cgroup.events populated=0`, and
  transient-scope removal.
- Every setup or evidence failure fails closed. There is no Landlock-only,
  namespace-only, or unsandboxed fallback.

## Recorded Bubblewrap capability

The recorded host has a usable Bubblewrap backend with this identity:

| Property | Observed value |
| --- | --- |
| Executable | `/usr/bin/bwrap` |
| Version | `bubblewrap 0.11.1` |
| SHA-256 | `8e19e40e7d5f7a7e8b488c7926feb040eab6ed10c58fa360e266d2f70670e92b` |
| Owner | uid 0, gid 0 |
| Mode | `0755` (`-rwxr-xr-x`) |
| setuid | absent |
| setgid | absent |
| File capabilities | absent (`getcap` produced no record) |
| Size | 80424 bytes |
| Device/inode | 2128 / 1507 at probe time |

The installation is accepted only as a normal, non-setuid executable using
unprivileged user namespaces. M4A must re-probe the executable path, version,
hash, ownership, mode, setuid/setgid state, file capabilities, user-namespace
creation, and required option behavior. A mismatch is an unavailable backend,
not permission to downgrade. M4A does not automatically upgrade the package.

Upstream Bubblewrap 0.11.2 documents a security fix affecting setuid-mode
0.11.x installations. The recorded non-setuid mode and exact runtime probes are
therefore part of the acceptance evidence, not assumptions derived from the
version string alone.

References:

- <https://github.com/containers/bubblewrap/tree/v0.11.1>
- <https://github.com/containers/bubblewrap/blob/v0.11.1/bubblewrap.c>
- <https://github.com/containers/bubblewrap/releases/tag/v0.11.2>

## Chosen composition

Bubblewrap is the outer namespace/runtime-view mechanism. The existing native
`fs_launcher` remains the inner Landlock and final-exec mechanism.

```text
AgenticOS controller
  -> securely open and fstat fixed authorized host sources
  -> systemd-run transient task scope
  -> Bubblewrap namespace setup, blocked on namespace gate
  -> controller verifies exact cgroup and namespace evidence
  -> controller releases namespace gate
  -> native fs_launcher enters and reports trusted-entry marker
  -> native launcher normalizes and sanitizes descriptors
  -> native launcher opens sandbox destinations with openat2
  -> native launcher verifies destination type/dev/inode
  -> native launcher fchdir(/workspace FD)
  -> PR_SET_NO_NEW_PRIVS + Landlock ABI-v3 restriction
  -> authenticated combined-policy acknowledgement
  -> controller releases final hostile-exec gate
  -> direct execve of the worker
```

FD sanitation intentionally remains before opening and authorizing sandbox
roots. This preserves M3B's stricter setup ordering while still proving the
required source-to-destination identity relationship before NNP, Landlock, or
hostile execution.

The rejected alternatives are:

- Pathname-based source binds followed by an identity check. They can fail
  safely but unnecessarily reintroduce pathname resolution into namespace
  construction.
- A new custom native namespace/mount launcher. It would duplicate Bubblewrap
  machinery and materially enlarge AgenticOS's native trusted computing base.
- Running Bubblewrap after the Landlock launcher. It would invalidate the
  existing exec-evidence semantics and complicate runtime-root authorization.

## Namespace policy

M4A uses an explicit argument vector generated by AgenticOS. It does not use
`--unshare-all` and does not use a shell-generated command string.

Required namespace and hardening options are:

```text
--unshare-user
--unshare-pid
--unshare-net
--unshare-ipc
--unshare-uts
--disable-userns
--new-session
--die-with-parent
--clearenv
```

A private mount namespace/root is inherent in Bubblewrap's construction. M4A
does not request `--unshare-cgroup`: the host cgroup hierarchy and existing
M2B/M3B `/proc/<pid>/cgroup` evidence retain their established meaning.

`--disable-userns` is mandatory. On the recorded host, the explicit namespace
configuration succeeds and a nested `unshare --user` inside it fails with
`No space left on device`. Tests assert denial without generalizing that exact
error text to every Linux host. If the option is absent or incompatible, M4A is
blocked.

`--new-session` removes an unnecessary controlling-terminal injection surface.
`--die-with-parent` is defense in depth only. Neither replaces cgroup-backed
cancellation and recursive cleanup.

## Identity-bound source mappings

M4A exposes only fixed, policy-defined mappings. It does not implement an
arbitrary mount language.

Each source mapping contains controller-only locator data plus:

```text
opened O_PATH descriptor
expected st_dev
expected st_ino
expected filesystem object type
fixed sandbox destination
fixed access role
```

The Linux controller opens a source beneath a trusted `/` descriptor using a
narrow `openat2()` wrapper with:

```text
O_PATH | O_CLOEXEC | O_NOFOLLOW
RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS
```

It retries only bounded `EAGAIN`. Unsupported syscalls, missing or wrong-type
objects, unsafe resolution, and every other error fail closed. There is no
`realpath()` or pathname-bind fallback.

Bubblewrap receives the already-open descriptor through `--bind-fd` or
`--ro-bind-fd`. The source pathname is absent from the Bubblewrap argument
vector and from the inner launch request. Setup descriptors are allocated away
from the launcher's reserved descriptors and passed through an explicit
`pass_fds` set.

The native launcher then securely opens each fixed sandbox destination from `/`
with the existing `openat2()` rules, calls `fstat()`, and requires exact type,
device, and inode equality with the authorized record. The opened destination
FD is the Landlock policy root. The verified `/workspace` FD is also used by
`fchdir()`.

The policy digest commits to synthetic destinations, identities, types, access
roles, namespace policy, environment policy, network policy, and the Landlock
configuration. It does not contain host locators.

The recorded WSL probe established that an authorized directory opened by FD,
renamed, and replaced at its former pathname is still mounted by
`--ro-bind-fd` as the original authorized device/inode. A permanent real-host
test will prove this dependency and the corresponding inner-launcher identity
check.

Required mapping attacks are:

- Authorized source bound to `/workspace`: accepted.
- Different FD substituted for the authorized source: rejected before hostile
  execution.
- Source pathname replaced after authorization: the authorized opened object is
  mounted, or setup fails safely; the replacement is never authorized.
- Destination changed or omitted: rejected.
- `/workspace` wrong identity or object type: rejected.
- Existing M3B symlink and concurrent path-race cases remain fail-closed.

## Stable worker ABI and profiles

Host paths are not preserved merely for compatibility. Worker argv, cwd,
environment, evidence, and policy use sandbox destinations.

The fixed profiles are:

- **L1 INSPECT:** `/workspace` is a read-only bind and a Landlock read-only
  root.
- **L2 BUILD:** `/workspace` is a read-write bind and a Landlock read-write
  root.

Both profiles deny host/external network access. Both set worker cwd to the
opened `/workspace` object and expose `PWD=/workspace`.

## Minimal runtime view

The root is a fresh tmpfs. Only measured runtime dependencies are added:

```text
/
|-- workspace                 fixed L1 RO or L2 RW mapping
|-- usr                       fixed host runtime, read-only
|-- bin -> usr/bin            synthetic symlink
|-- sbin -> usr/sbin          synthetic symlink
|-- lib -> usr/lib            synthetic symlink
|-- lib64 -> usr/lib64        synthetic symlink
|-- opt/agenticos/
|   |-- fs_launcher           exact file, read/execute
|   `-- worker.py             exact synthetic worker, read-only
|-- tmp                       private per-task RW mapping
|-- home/tool                 private synthetic RW home
|-- run                       empty synthetic hierarchy
|-- proc                      new procfs for the task PID namespace
`-- dev                       Bubblewrap synthetic minimal device view
```

The recorded Ubuntu host is merged-`/usr`: `/bin`, `/sbin`, `/lib`, and
`/lib64` resolve to the corresponding `usr/*` locations. A real probe ran the
installed Python interpreter with only `/usr` bound read-only plus those
synthetic symlinks. M4A therefore starts with a single `/usr` runtime-tree bind.
It does not bind host `/etc`, `/run`, `/proc`, `/dev`, a repository root, or a
Windows drive.

The exact native launcher and synthetic worker files are mounted individually;
the AgenticOS source tree is not exposed. `/tmp` and `/home/tool` are fresh,
controller-owned per-task directories with recorded identities. `/run` is
empty. `/proc` is explicitly new rather than inherited. Device exposure is
measured and documented; Landlock grants only required synthetic device nodes.

The sandbox-local pathname Unix-socket positive control is created under the
private `/tmp`, whose fixed policy role alone receives `MAKE_SOCK`. M4A does not
grant socket-node creation broadly across all writable roots.

## Environment and credential boundary

The controller never forwards its ambient environment. Bubblewrap receives
`--clearenv`; only bounded launcher setup values are added explicitly. The
native launcher uses a separately constructed worker environment for `execve()`.

The default worker environment is exactly:

```text
HOME=/home/tool
PATH=/usr/bin:/bin
LANG=C.UTF-8
LC_ALL=C.UTF-8
TMPDIR=/tmp
PWD=/workspace
```

Any future task variable requires an explicit allowlisted contract entry.
Credential-shaped, socket-routing, bus-routing, provider, cloud, Git credential,
and runtime-directory variables are never eligible in M4A.

Tests place synthetic canaries in the controller context for OpenAI-like,
Anthropic-like, generic cloud, Git credential, `SSH_AUTH_SOCK`,
`XDG_RUNTIME_DIR`, and provider-config variables. They inspect no real secret
store. Evidence records canary presence booleans and variable names, never
values. The production expectation is zero provider credentials in the worker.

## Network and Unix-socket boundary

L1 and L2 use a new network namespace and fixed policy `DENY`. No interface,
proxy, broker, DNS policy, destination allowlist, or public endpoint is added.

Fixture-controlled tests prove:

- A host TCP listener is unreachable.
- A host UDP fixture receives no datagram and the worker receives no response;
  `sendto()` success alone is not accepted as connectivity evidence.
- A host abstract Unix socket is unreachable because it belongs to another
  network namespace.
- A host pathname Unix socket is absent because its hierarchy is not mounted.
- A pathname Unix socket created under sandbox-private `/tmp` works as a
  positive control.
- Child, grandchild, setsid, new-process-group, parent-exit, and double-fork
  attempts retain the same network and filesystem boundaries.

A negative-control launch deliberately passes an already-connected synthetic
socket FD and demonstrates that the capability can survive namespace isolation.
The production path then passes the same class of descriptor to trusted setup
and proves that the native launcher's sanitation removes it before worker exec.
The live worker descriptor census must be exactly `{0, 1, 2}`.

## Final capability state

Bubblewrap may require capabilities temporarily inside its setup user namespace,
but none may reach hostile code. The worker records Linux capability and
privilege state from `/proc/self/status`.

M4A requires:

```text
CapInh = 0
CapPrm = 0
CapEff = 0
CapAmb = 0
NoNewPrivs = 1
```

`CapBnd` is also recorded and expected to be empty on the proven host. No
capability is added for compatibility without a separately reviewed design
change.

## Staged launch and independent evidence

Bubblewrap's JSON stream is bounded, parsed as a sequence of JSON objects, and
used as transport rather than sole authority. The parser requires known setup
fields, rejects malformed values, duplicate or contradictory setup records, and
missing required evidence, while tolerating bounded unknown future fields and
unrelated future object types.

The setup record supplies a host-visible child PID. While `--block-fd` still
holds the namespace gate, the controller independently reads:

```text
/proc/<child>/ns/user
/proc/<child>/ns/mnt
/proc/<child>/ns/net
/proc/<child>/ns/pid
/proc/<child>/ns/ipc
/proc/<child>/ns/uts
/proc/<child>/cgroup
/proc/<child>/uid_map
```

It verifies required namespace separation against controller identities, checks
Bubblewrap fields against `/proc` where fields exist, confirms unprivileged user
namespace mapping, and proves exact membership in the established task cgroup.
No cgroup-namespace comparison is expected because M4A does not create one.

The launch transcript is versioned for M4A while retaining M3B compatibility.
Its logical order is:

```text
namespace JSON available
controller cgroup + namespace verification
namespace gate release
R:<nonce>             trusted fs_launcher entry
G                     existing trusted-setup release
S                     descriptor set sanitized
I                     sandbox destination identities verified; cwd bound
P                     Landlock policy prepared
N                     no_new_privs set
A:<...>:<digest>      Landlock applied + combined-policy commitment
X                     final controller exec release
status-FD EOF         direct exec attempted
```

`R` is the harmless launcher-entry marker. Before namespace-gate release the
controller must have namespace status but observe no `R` and no hostile-worker
marker. After release it must observe `R`, then `S/I/P/N/A`, while the worker
marker remains absent. Only after the controller authenticates the nonce,
ordering, ABI, handled mask, and combined digest may it send `X`.

The real regression test must prove this ordering on the recorded host; source
inspection alone is insufficient. Bubblewrap's status descriptor and every
FD-bound source may reach the trusted launcher, so they are setup-only
descriptors and must be removed by the native `close_range()` boundary.

## Evidence model

Normalized evidence records, without secret values or host source paths:

- Backend name, exact version, executable hash, owner/mode, privilege mode, and
  option/capability probe results.
- Host-visible sandbox PID and independently verified user, mount, network, PID,
  IPC, and UTS namespace identities.
- Exact task cgroup identity and verification result.
- Filesystem-view and combined-policy digests.
- Environment-policy digest and `network_policy=DENY`.
- Synthetic destination identities and roles, without host locators.
- Unexpected inherited FD count and final live FD set.
- Controller/worker credential-canary presence booleans.
- Host TCP, UDP, pathname-socket, and abstract-socket outcomes.
- Final capability masks and `NoNewPrivs` state.
- Landlock ABI, handled mask, NNP and restriction evidence.
- Gate ordering, hostile-exec observation, and failure stage.
- Recursive `populated=0` and scope cleanup on normal exit, failure, exception,
  and cancellation.

## Fail-closed behavior

Hostile execution is forbidden on any of the following:

- Bubblewrap missing, changed, privileged unexpectedly, unsupported, or unable
  to create every required namespace.
- `--disable-userns`, `--new-session`, `--die-with-parent`, FD binds, status JSON,
  or `--block-fd` unavailable or behaviorally incompatible.
- Required source resolution/open/type/identity failure.
- Missing runtime root or any source/destination substitution.
- Malformed, contradictory, missing, mismatched, or timed-out namespace evidence.
- Child not in the exact verified systemd task cgroup.
- Required namespace identity not separated from the controller.
- Launcher entry before namespace-gate release.
- Unexpected setup/worker FD, capability, credential, filesystem, socket, or
  network observation.
- Invalid request/transcript/digest, Landlock setup failure, NNP failure,
  restriction failure, or final-gate failure.

Every post-launch failure invokes the existing verified cgroup cancellation and
drain lifecycle. Bubblewrap exit or parent-death behavior is never sufficient
cleanup evidence by itself.

## Adversarial and regression proof

The committed M4A suite will cover:

- Both L1 read-only and L2 read-write `/workspace` behavior.
- Worker cwd/PWD `/workspace`; host source path, sibling worktree, AgenticOS
  state, real/synthetic host `/run`, real home, and Windows mounts absent.
- Private `/tmp`, synthetic home, minimal runtime execution, new `/proc`, and
  measured `/dev` contents.
- FD-bind identity preservation, wrong FD, pathname replacement, wrong
  destination, wrong type, wrong identity, and M3B path-race regression.
- Explicit environment allowlist and every required synthetic credential
  canary.
- TCP, UDP, pathname and abstract Unix sockets, sandbox-local positive control,
  deliberately inherited connected-socket negative control, and production FD
  sanitation.
- Nested user-namespace denial and zero final capability sets.
- Namespace setup fault, malformed policy, missing runtime root, namespace
  evidence mismatch, policy-digest mismatch, post-namespace Landlock failure,
  and forged/missing acknowledgement.
- Child/grandchild, setsid, new process group, parent exit, double fork,
  signal-ignoring descendants, controller exception, cancellation, and normal
  completion.
- Warning-clean native builds; existing M2B and M3B suites unchanged; the full
  Linux suite three consecutive times; Windows regression behavior.

Real systemd-scope tests remain serialized because their global cleanup
assertions are intentionally incompatible with concurrent execution.

## Documentation and roadmap

M4A completion updates the phase-zero capability, process-containment,
filesystem/runtime-isolation, and conformance documents with only measured
claims. A durable roadmap records, without implementing:

1. M4B Connected Build network broker and explicit destination allowlists.
2. Git worktree manager.
3. Codex, Claude, Kimi ACP, and Antigravity LIMITED adapters.
4. Provider-neutral progressive context envelopes and immutable handoffs.
5. Deterministic evaluation, independent cross-provider review, bounded repair,
   quota-aware routing, and empirical provider scorecards.

Official provider clients retain authentication ownership. AgenticOS does not
extract, replay, or relocate consumer credentials; APIs may later be optional
overflow capacity.

## Security claim on success

On the recorded Linux/WSL2 host, AgenticOS may claim that it composes its proven
cgroup and Landlock barriers with an independently verified namespace and
minimal runtime-view boundary such that L1/L2 tool workers execute without
provider credentials, without visibility of ungranted host filesystem/runtime
socket paths, and without host/external network connectivity, while preserving
fail-closed startup and recursive process cleanup.

It may not claim complete sandbox security, malicious-kernel protection,
arbitrary Linux-host equivalence, native Windows isolation, L3 networking,
provider safety, seccomp enforcement, or protection from capabilities
deliberately passed by trusted policy.

If implementation contradicts any approved assumption, work stops for design
review instead of weakening this boundary.
