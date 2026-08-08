# Phase Zero — Process Containment (EXPERIMENTAL)

> **MILESTONE 2B PROVES PROCESS CONTAINMENT ONLY.** Milestone 3B composes a
> separately evidenced Landlock boundary with it. Neither proves network
> isolation, Windows-host isolation, credential
> isolation, Unix-socket isolation, provider safety, or complete AgenticOS
> sandbox security.

`CgroupProcessRunner` (`agenticos.sandbox.containment`) is an EXPERIMENTAL
`SandboxRunner` backend that runs the hostile worker inside a task-owned
transient systemd scope on cgroup v2. `UnsafeLocalRunner` remains the
baseline; the identical scenario corpus runs through both.

## 1. Architecture

```
AgenticOS
  └─ transient task scope  (systemd-run --user --scope --quiet --collect --unit=aos-task-<rand>)
       └─ cgroup v2 hierarchy  (discovered dynamically via `systemctl show -p ControlGroup`)
            └─ hostile worker → children → grandchildren
```

- Documented systemd/cgroup mechanisms only; no manual mutation of global
  cgroup state, no persistent units (`--collect` garbage-collects).
- The cgroup path is **discovered per run** (`ControlGroup` property), never
  assumed from a distro-specific hierarchy layout.
- Signals target the task unit (`systemctl --user kill --signal=... <unit>`)
  — never `pkill`/`killall`/process-name searches.

## 2. Process identity

PID alone is not durable (PID reuse). `ProcessIdentity` combines:

- PID
- process group ID (POSIX)
- process start time in clock ticks (`/proc/<pid>/stat` field 22, parsed
  after the final `)` so weird `comm` values can't break it)
- kernel boot id (`/proc/sys/kernel/random/boot_id`)

`ProcessIdentity.matches_current()` re-reads procfs and only confirms a PID
when start time and boot id match. Every `ProcessResult` now carries an
`identity` plus `containment_unit` / `containment_cgroup` /
`containment_state` when a containment backend produced it. pidfd support is
capability-detected (`pidfd_available`) for future use.

## 3. Cancellation state machine

```
RUNNING
  → CANCEL_REQUESTED
  → SIGINT        (systemctl kill --signal=SIGINT <unit>)
  → grace         (configurable; tests use fractions of a second)
  → SIGTERM
  → grace
  → FORCED KILL   (write 1 to <cgroup>/cgroup.kill; fallback: systemctl
                   SIGKILL on the unit — documented, reported as
                   NOT equivalent when cgroup.kill is unavailable)
  → VERIFY EMPTY  (cgroup.events → populated 0)
  → TERMINATED    | FAILED (loud)
```

Implemented in `cancel_contained(backend, unit, cgroup_path, config,
collector)`. Timing lives in `CancellationConfig` — no hard-coded production
values. The logic is host-independent and fully unit-tested against scripted
fake backends; `SystemdScopeBackend` is the thin real adapter.

## 4. The termination invariant

A contained task is **not** terminated when:

- the root process exits, or
- the process group disappears, or
- one level of `cgroup.procs` is empty.

It is terminated only when the task cgroup's **recursive** population state
says so: `cgroup.events` → `populated 0`. A cgroup that has been removed
counts as empty (an unpopulated `--collect` scope is garbage-collected).
If the hierarchy is still populated after the final forced kill, the run is
`FAILED`, evidence is preserved, cleanup is attempted, and tests fail loudly.
Even after a *clean* worker exit the runner reaps any descendants left
inside the boundary (PROC-05/06/08 leave lingering children by design).

## 5. Baseline vs containment

Same scenario, both backends — semantics unchanged:

| Scenario | UnsafeLocalRunner | CgroupProcessRunner |
|---|---|---|
| PROC-03 (ignores SIGTERM) | child ignores SIGTERM; worker SIGKILLs it itself | same, inside the scope; tree killed via unit |
| PROC-05 (lingering child) | child outlives worker until harness kills it | child stays in the task cgroup, removed during cancellation; `populated 0` verified |
| PROC-06 (double-fork daemon) | orphaned daemon survives worker | daemon remains in the scope and dies with it |
| PROC-08 (new process group) | escapes the worker's process group | still inside the cgroup; killed by boundary kill |

New scenarios added in this milestone (all bounded, never fork bombs):
PROC-06 double-fork/daemon detachment, PROC-07 rapid spawn with a strict
finite cap (5) and guaranteed reaping, PROC-08 child in a new process group.

## 6. Evidence

With an `EvidenceCollector` attached, the runner emits:
`CONTAINMENT_CREATED`, `PROCESS_STARTED`, `SIGNAL_SENT`,
`FORCED_KILL_REQUESTED`, `CGROUP_EMPTY_VERIFIED`, `CONTAINMENT_DESTROYED`,
`CONTAINMENT_FAILURE` (plus `HOST_CAPABILITY_OBSERVED` where reports are
recorded). Fixture paths are normalized to `<TEMP_ROOT>/...`; no host
environment, no secrets.

## 7. Host support matrix

See `host-capabilities.md`. On hosts without cgroup v2 + systemd user
scopes, `check_support()` returns concrete reasons, `run()` raises
`ContainmentUnavailableError`, and integration tests skip with reasons —
nothing is faked.

## 7a. Real-host verification record (Milestone 2B, observed)

Tested environment: Ubuntu 26.04 LTS on WSL2, kernel
`6.6.87.2-microsoft-standard-WSL2`, systemd 259 (PID 1), systemd user
manager + bus operational, unified cgroup v2, Python 3.14.4.

Observed on this environment:

- Transient user scopes (`systemd-run --user --scope --collect`) created
  and collected successfully, both manually and through
  `CgroupProcessRunner.probe()`.
- Task cgroup membership is proven from `/proc/<pid>/cgroup` of the scope
  process (suffix match on the exact scope name), with the unit's
  `ControlGroup` property as fallback. Unit lookups use the full
  `<name>.scope` name — a bare name resolves to `<name>.service` and finds
  nothing (defect found and fixed during real-host verification).
- Real cancellation escalation executed: a child ignoring both SIGINT and
  SIGTERM was terminated by the full sequence SIGINT → grace → SIGTERM →
  grace → **`cgroup.kill`** → recursive `cgroup.events populated 0` →
  `CONTAINMENT_DESTROYED`.
- `cgroup.kill`: present in non-root cgroups, usable by the current user on
  AgenticOS-created task scopes, and genuinely exercised (no fallback was
  needed on this host; the systemd-SIGKILL fallback remains documented as
  NOT equivalent).
- Hostile scenarios PROC-01 through PROC-08 executed through
  `CgroupProcessRunner`; session changes (PROC-04), new process groups
  (PROC-08), parent exit (PROC-05), and double-fork reparenting (PROC-06)
  all remained inside the task cgroup and were removed during cancellation.
  PROC-07 stayed within its strict finite bound (5 children, all reaped).
- After every run: no surviving task-attributable descendant PIDs, no
  populated task cgroups, no persistent `aos-*` units.
- Full Linux suite: 100 passed, 1 skipped, stable across three consecutive
  runs.

One evidence cosmetic: after a timeout cancellation, `CGROUP_EMPTY_VERIFIED`
may be recorded twice (once after the forced kill, once re-verified after
reaping). Both records are accurate.

These results describe the tested environment only; they are not a claim
about arbitrary Linux hosts.

## 8. What remains unproven

- Process containment by itself proves no filesystem, network, socket, or
  credential isolation. The separately tested Milestone 3B Landlock claim is
  documented in `filesystem-isolation.md`.
- Whether `cgroup.kill` is permitted on any host other than the recorded
  target (capability-detected; fallback is explicitly reported).
- Behavior under WSL kernel updates / distro variations.
- Provider safety of any kind.

## 9. Historical next step

Milestone 3A evaluated mount namespaces and Landlock by re-running the
FS/WRITE corpus. Milestone 3B then implemented the selected Landlock-first
boundary described below.

## 10. Milestone 3B composition record

`NativeLandlockRunner` reuses the same transient-scope discovery,
membership verification, cancellation escalation, recursive `populated 0`
check, and scope cleanup. Only the trusted native launcher exists before the
cgroup gate. Event-order tests prove:

```
CONTAINMENT_VERIFIED
  -> FD_SET_SANITIZED
  -> FILESYSTEM_POLICY_PREPARED
  -> NO_NEW_PRIVS_SET
  -> FILESYSTEM_POLICY_APPLIED
  -> controller validates acknowledgement and releases exec
  -> worker exec
```

The filesystem suite exercises children, grandchildren, new sessions, new
process groups, parent-exit descendants, and double-forked descendants. Each
records its own `/proc/self/cgroup` membership, retains Landlock denial, and
remains attributable to the exact task scope until the existing lifecycle
observes recursive `populated 0`. Cancellation of a task
that ignores SIGINT and SIGTERM still reaches forced cgroup kill and empty
verification. Filesystem setup failures and post-restriction exec failures
use the same drain-and-cleanup path.
An injected controller exception after exec release also spawns a
signal-ignoring child; the exception path runs the same bounded escalation,
records `CGROUP_EMPTY_VERIFIED`, confirms the child PID is gone, and verifies
the transient unit is inactive.

This composition does not turn either component into a complete sandbox: the
cgroup controls process-tree lifecycle, while Landlock ABI 3 mediates only
its documented filesystem operations.

## 11. Milestone 4A lifecycle composition

Bubblewrap intentionally does not create a cgroup namespace. Its explicit PID,
network, mount, user, IPC, and UTS namespaces are independently checked from
host `/proc`, including exact task-cgroup membership, before the namespace gate
releases. `--die-with-parent` is defense in depth only.

The established transient scope, cancellation escalation, `cgroup.kill`, and
recursive `populated 0` proof remain authoritative. M4A runs all existing
descendant shapes plus namespace/Landlock/controller/timeout faults through
that lifecycle and requires no active `aos-*` scope afterward. See
[runtime-boundary.md](runtime-boundary.md) for the composed event order and
the narrow earned claim.
