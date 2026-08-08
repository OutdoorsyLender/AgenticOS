# Milestone 4A — Runtime, Credential, IPC, and No-Network Boundary

## Earned claim

On the recorded Ubuntu 26.04/WSL2 host, AgenticOS composes its cgroup-v2
lifecycle and Landlock ABI-v3 filesystem policy with an independently verified
Bubblewrap namespace/runtime view. L1 and L2 workers run at `/workspace` with
no provider credentials, no ungranted host filesystem or runtime-socket paths,
and no host/external network connectivity. Startup fails closed before hostile
exec and completion/cancellation ends only after recursive cgroup emptiness.

This is a host-specific L1/L2 tool-execution result, not a complete sandbox,
native-Windows claim, provider-safety claim, seccomp claim, malicious-kernel
defense, arbitrary-Linux equivalence, or L3 network-allowlisting result.

## Trust and launch order

Host path strings are locators. Opened object identity is authority.
`/workspace` is the worker-facing ABI.

```text
controller securely opens fixed host sources with openat2 + fstat
  -> systemd transient scope starts exact Bubblewrap binary
  -> Bubblewrap constructs explicit user/mount/PID/net/IPC/UTS namespaces
  -> --block-fd holds the trusted launcher
  -> JSON child PID is checked against host /proc and exact task cgroup
  -> controller sends the v2 request containing synthetic destinations
     and authorized device/inode identities
  -> namespace gate releases
  -> native launcher enters and sanitizes descriptors
  -> launcher opens /workspace and every policy destination with openat2
  -> fstat identity/type checks; fchdir through opened /workspace
  -> NNP + Landlock ABI-v3 full handled mask
  -> authenticated nonce/ABI/mask/combined-digest acknowledgement
  -> controller releases final exec gate
  -> hostile worker execs with cwd=/workspace
  -> cgroup recursive populated=0 is required before terminal evidence
```

The real ordering regression observes Bubblewrap status and independent
namespace/cgroup proof while both launcher and worker markers are absent. It
observes launcher entry only after namespace release, and worker entry only
after the authenticated Landlock acknowledgement and final exec release.

## Bubblewrap acceptance record

The accepted host binary is `/usr/bin/bwrap` 0.11.1, root-owned mode 0755,
without setuid/setgid bits or file capabilities. Its measured SHA-256 is
`8e19e40e7d5f7a7e8b488c7926feb040eab6ed10c58fa360e266d2f70670e92b`.
The runtime probe requires unprivileged user namespaces, the fixed explicit
namespace set, FD binds, JSON status, `--block-fd`, `--disable-userns`,
`--new-session`, and `--die-with-parent`. It also proves nested user namespace
creation is denied. A path/version/hash/ownership/mode/capability or behavioral
mismatch makes M4A unavailable; there is no weaker fallback.

M4A uses `--unshare-user`, `--unshare-pid`, `--unshare-net`, `--unshare-ipc`,
and `--unshare-uts`. It deliberately does not create a cgroup namespace. The
host-visible systemd/cgroup-v2 scope remains lifecycle authority.

## Fixed runtime ABI

AgenticOS generates one narrow policy; workers cannot request mount mappings.

| Destination | Construction | L1 Inspect | L2 Build |
|---|---|---:|---:|
| `/workspace` | authorized worktree FD; exact identity rechecked | RO | RW |
| `/usr` | authorized runtime FD | RO+execute | RO+execute |
| `/bin`, `/sbin`, `/lib`, `/lib64` | measured merged-`/usr` symlinks | RO | RO |
| `/opt/agenticos/fs_launcher` | exact authorized file FD | RO+execute | RO+execute |
| `/opt/agenticos/worker.py` | exact authorized file FD | RO | RO |
| `/tmp` | task-private authorized directory FD | RW + socket nodes | RW + socket nodes |
| `/home/tool` | synthetic task home FD | RW | RW |
| `/dev` | Bubblewrap synthetic device tree; only fixed `/dev/null` is Landlock-granted | minimal | minimal |
| `/proc` | new namespace procfs; not Landlock-readable by the worker | new | new |
| `/run` | empty synthetic directory | empty | empty |

The host workspace path, sibling worktree, AgenticOS private state, host home,
host `/run`, Windows mounts, and host root do not appear in the worker view.
Real-host tests compare `/workspace` device/inode with the authorized source,
reject a different FD, changed destination, and wrong type before hostile exec,
and show that renaming/replacing the locator after authorization still mounts
the already-opened object safely.

The worker environment is generated exactly as follows; caller input is ignored:

```text
HOME=/home/tool
PATH=/usr/bin:/bin
LANG=C.UTF-8
LC_ALL=C.UTF-8
TMPDIR=/tmp
PWD=/workspace
```

Synthetic OpenAI-, Anthropic-, cloud-, SSH-agent-, XDG-runtime-, provider-config-,
and Git-credential canaries present at the controller are absent in the worker.

## Measured adversarial matrix

| Property | Observation |
|---|---|
| authorized source at `/workspace` | accepted; exact device/inode observed |
| substituted source FD | rejected before hostile exec |
| locator replaced after authorization | opened identity mounted; replacement not used |
| changed destination / wrong object type | rejected or safe setup failure before hostile exec |
| L1 workspace write | denied |
| L2 workspace write | allowed |
| private tmp/home writes and merged-`/usr` Python | allowed |
| host/sibling/private/home/Windows paths | absent |
| controller credential canaries | absent; exact six-entry environment |
| inherited outside file and connected socket FDs | removed; worker census `{0,1,2}` |
| final capabilities | inheritable/permitted/effective/bounding/ambient all zero |
| final NNP / nested userns | `NoNewPrivs=1`; nested userns denied |
| host TCP | connection fails; host endpoint accepts none |
| host UDP | no response and host endpoint receives no datagram |
| host pathname and abstract Unix sockets | unreachable; host endpoints accept none |
| sandbox-private `/tmp` Unix socket | local exchange succeeds |
| namespace-only connected-socket control | exchange succeeds, proving FD hygiene is necessary |
| child/grandchild/setsid/new-pgroup/parent-exit/double-fork/rapid-spawn | same boundary; scope recursively drained |
| namespace/Landlock/controller/source/exec faults | no weaker fallback; no hostile marker; no active scope |
| timeout and signal resistance | cgroup cancellation drains recursively |

UDP denial is based on host receipt/response, not `sendto()` success. Network
and socket targets are fixture-controlled loopback/Unix endpoints; the suite
does not contact the public Internet or inspect real credentials.

## Evidence

Successful runs emit `RUNTIME_BOUNDARY_VERIFIED` only after recursive cleanup.
It contains the profile, `/workspace` identity and destination, six namespace
identities, relative task cgroup, filesystem/environment/combined policy
digests, fixed environment names, network policy `DENY`, gate observations,
Landlock ABI/mask/identity acknowledgement, exec result, and terminal cgroup
state. It excludes source locators, caller environment, credential values, and
socket canary contents. Capability and endpoint observations remain bounded
hostile-fixture results rather than ambient host enumeration.

## Limitations

- Single recorded WSL2 host and pinned Bubblewrap binary; every run re-probes.
- No seccomp, AppArmor, LSM stacking analysis, kernel-compromise defense, or
  denial-of-service/resource-quota claim.
- No L3 networking, DNS broker, destination allowlist, package download, or
  provider integration.
- The worker can create sandbox-local sockets where policy permits. This does
  not imply communication with host namespaces.
- `/dev/null` is the sole fixed synthetic-device identity sentinel accepted by
  protocol v2. The launcher resolves it without symlinks and requires a
  character device; no arbitrary synthetic-root language exists.
- Capability evidence uses `capget()`/`prctl()` because Landlock intentionally
  denies hostile procfs reads.

Models reason. AgenticOS guarantees.
