# Phase Zero — Process Containment (EXPERIMENTAL)

> **THIS MILESTONE PROVES PROCESS CONTAINMENT ONLY.** It does NOT prove
> filesystem isolation, network isolation, Windows-host isolation, credential
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

## 8. What remains unproven

- Any filesystem, network, socket, or credential isolation.
- Whether `cgroup.kill` is permitted for the current user on the target host
  (capability-detected; fallback is explicitly reported).
- Behavior under WSL kernel updates / distro variations.
- Provider safety of any kind.

## 9. Next milestone

Filesystem isolation experiments (read-only bind of the assigned worktree,
denied sibling/private paths) behind a third `SandboxRunner` backend —
evaluating mount namespaces vs. Landlock (already capability-detected) —
measured by re-running the FS/WRITE attack corpus through the new backend.
