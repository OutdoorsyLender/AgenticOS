# Phase Zero — Filesystem Isolation Architecture (Milestone 3A)

> **EXPERIMENTAL. This milestone does NOT make AgenticOS secure.** It answers
> one question with real-host evidence: which filesystem-isolation mechanism
> gives AgenticOS the smallest, testable, composable workspace boundary under
> the proven cgroup process-containment lifecycle?

## 1. Threat model

A hostile or compromised worker process tree (children, grandchildren,
new sessions, double-forked daemons) attempts to reach filesystem resources
outside its assigned workspace: denied sibling worktrees, AgenticOS private
state, credential-shaped files, and anything else on the host. Attacks:
direct read/write, `../` traversal, symlink escape (read and write),
rename/move across the boundary, writes to read-only resources, descendant
inheritance of access, and access through pre-opened inherited FDs.

## 2. Synthetic fixture model

All attacks target the synthetic `FixtureLayout` (Milestone 1), extended in
3A with a `readonly/` area (`readonly-canary.txt`, canary tag `readonly`).
Denied paths live outside the workspace but inside the disposable fixture
root. No real secrets are ever used.

## 3. Existing corpus + 3A additions

Unchanged semantics: FS-01 allowed read, FS-02 denied read, FS-03 denied
write, FS-04 `../` traversal, FS-05 symlink read, WRITE-01 allowed write,
WRITE-02 outside write. Added (additive only):

| ID | Attack | Expected |
|---|---|---|
| FS-06 | write THROUGH a symlink to a denied file | DENY |
| FS-07 | rename/move a denied file into the workspace | DENY |
| FS-08 | read a denied resource via an inherited pre-opened fd | DENY (see §12) |
| FS-09 | descendant (child/grandchild/setsid/doublefork) attempts denied read | DENY |
| FS-10 | read an explicitly read-only file | ALLOW |
| FS-11 | write an explicitly read-only file | DENY |

## 4. Baseline (control group)

Measured on the tested host: under `UnsafeLocalRunner` AND under
`CgroupProcessRunner`, FS-02/FS-04 **succeed**. Process containment is not
filesystem isolation — the new layer supplies a distinct property.

## 5. Candidates and host capabilities (observed, Ubuntu 26.04 WSL2, kernel 6.6)

- **Landlock**: ABI v3 detected; real enforcement probe (deny-all ruleset →
  EACCES on a synthetic file) **SUPPORTED, unprivileged**.
- **User/mount namespaces**: `max_user_namespaces=126945`; bounded probe
  `unshare --user --map-root-user --mount true` **SUPPORTED, unprivileged**.
  Privileged mount ns (`unshare --mount`) correctly denied.
- **Bubblewrap**: `bwrap` present on PATH (pre-existing; nothing installed).
- Availability ≠ usability: `bubblewrap_available`/`unshare_available` are
  presence-only; usability comes from the bounded real probes
  (`probe_landlock_enforcement`, `probe_unprivileged_namespaces`).

## 6. Experiments

Both backends compose UNDER `CgroupProcessRunner` (same task scope,
cancellation, recursive `populated 0`):

- `LandlockIsolatedRunner` — wraps argv with a fail-closed standalone shim
  (`landlock_shim.py`): `no_new_privs` → ruleset (handled = all FS rights
  through ABI v3) → path-beneath rules → `restrict_self` → `exec`. Inherited
  across fork/exec by every descendant. Denials surface as `EACCES`.
- `BwrapIsolatedRunner` — wraps argv with `bwrap --tmpfs / --dev /dev`
  plus `--bind`/`--ro-bind` per policy path; everything else does not exist
  inside (denials surface as `ENOENT`). Namespaces vanish with the process.

Policy model (minimal): workspace rw · writable_paths rw (task-tmp, `/dev`)
· readonly_paths ro · runtime_paths ro (interpreter, venv, repo, `/usr`,
`/lib`, `/etc`, `/proc`) · everything else denied by omission.

## 7–11. Real-host results (all observed on the tested environment)

| Attack | Unsafe | Cgroup | Landlock | Bubblewrap |
|---|---|---|---|---|
| allowed read (FS-01) | allow | allow | allow | allow |
| allowed write (WRITE-01) | allow | allow | allow | allow |
| readonly read (FS-10) | allow | allow | allow | allow |
| outside read (FS-02) | **allow** | **allow** | **DENY EACCES** | **DENY ENOENT** |
| outside write (FS-03) | allow | allow | DENY EACCES | DENY ENOENT |
| traversal (FS-04) | allow | allow | DENY EACCES | DENY ENOENT |
| symlink read (FS-05) | allow | allow | DENY EACCES | DENY ENOENT |
| symlink write (FS-06) | allow | allow | DENY EACCES | — |
| rename boundary (FS-07) | allow | allow | DENY EACCES (no REFER grant) | — |
| readonly write (FS-11) | allow | allow | DENY EACCES | — |
| child (FS-09) | allow | allow | DENY EACCES | DENY |
| grandchild (FS-09) | allow | allow | DENY EACCES | — |
| setsid (FS-09) | allow | allow | DENY EACCES | — |
| double fork (FS-09) | allow | allow | DENY EACCES | — |
| pre-opened fd (FS-08) | allow | allow | **ALLOW (limitation)** | — |

Conformance flip: FS-01/FS-02 now evaluate PASS against the default policy
under the Landlock backend. Composition proven: FS-09 (doublefork) is both
filesystem-denied AND process-containment `TERMINATED` (`populated 0`).

## 12. Pre-opened FD limitation (experimentally confirmed)

With a Landlock policy applied, opening the denied file by PATH fails
(EACCES) while reading an inherited pre-opened fd to the same file
**succeeds** (canary recovered). Landlock restricts path-based access; it
cannot revoke existing descriptors. Architectural requirement:

> Restrictions must be established before untrusted worker code receives
> sensitive FDs — AgenticOS must never pass sensitive FDs into a worker.

## 13. Other limitations observed

- Landlock `/dev` cannot be scoped by device type; the experiment grants
  `/dev` rw (needed for `/dev/null`). Bubblewrap instead synthesizes a
  minimal `/dev`.
- Landlock ABI v3 has no network scoping (network rules are ABI v4+) —
  irrelevant now, relevant later.
- Landlock is path/inode-based; it does not hide `/proc` or virtualize the
  view — bubblewrap's mount view is strictly stronger for "does not exist"
  semantics.
- Bubblewrap is an external binary dependency (present on this host by
  chance, not guaranteed elsewhere).

## 14. Mechanism comparison (summary of the 20 criteria)

Unprivileged: both ✓. Deny read/write/traversal/symlink/rename: Landlock ✓
(all measured), bwrap ✓ (core measured). Descendant inheritance: Landlock ✓
(all four shapes measured), bwrap ✓ (child measured; namespace is
process-tree-scoped). Pre-opened FD: neither revokes (Landlock measured).
Read-only resources: both ✓. Cgroup composition: both ✓. Cleanup: Landlock
trivial (nothing to clean); bwrap trivial (namespaces die with process).
Host config: both none. External deps: Landlock none (stdlib ctypes);
bwrap binary required. Fail-closed: both (shim exits 2 / bwrap failure =
run failure, both surfaced). Evidence quality: Landlock EACCES (clear);
bwrap ENOENT (denied ≈ nonexistent — good semantics, weaker signal). WSL:
both work on WSL2 kernel 6.6. Known bypass classes: Landlock — FD
inheritance, `/dev` breadth; bwrap — setuid binary risks if ever installed
setuid (not here), userns kernel attack surface.

## 15. Architecture recommendation

**LANDLOCK_FIRST.**

It is the smallest testable boundary that composes under the proven
cgroup lifecycle: zero external dependencies, stdlib-only, unprivileged,
fail-closed, inherited by every descendant shape we measured, with clear
EACCES semantics and no cleanup surface. Bubblewrap remains the documented
alternative if a future milestone needs view virtualization ("denied paths
do not exist") or a synthesized minimal `/dev`; hand-rolling mount
namespaces via `unshare` would mean re-implementing bubblewrap and was
rejected on maintenance-cost grounds (probe results recorded, no custom
namespace runner built).

## 16. What remains unproven

Network isolation, Unix-socket isolation, environment-secret isolation,
credential brokering, seccomp, anything on Windows hosts, malicious-kernel
resistance, and any complete-sandbox claim. The pre-opened-FD hole is
documented, not closed (it is a construction rule for the runtime).
Single-host evidence only.
