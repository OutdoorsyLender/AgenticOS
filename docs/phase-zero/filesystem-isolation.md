# Phase Zero — Filesystem Isolation Architecture (Milestones 3A and 3B)

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

## 17. Milestone 3B production boundary

Milestone 3B promotes the Landlock-first result into a fail-closed native
launch boundary. The controller starts only a small, single-threaded C
launcher in the existing transient systemd scope. The launcher blocks at a
nonce-bearing gate. The controller positively identifies the launcher's
cgroup, records `CONTAINMENT_VERIFIED`, and only then releases setup. The
launcher closes ambient descriptors, resolves policy roots, creates the
ruleset, calls `PR_SET_NO_NEW_PRIVS`, calls `landlock_restrict_self()`, and
acknowledges the authenticated policy digest. It then blocks a second time;
only after the controller validates the complete transcript and sends the
exec-release byte may it call `execve()` on the worker.

There is no shell, fork, thread, subprocess, Python `preexec_fn`, or degraded
fallback in the trusted pre-exec path. A missing launcher, unsupported or
disabled Landlock, ABI below 3, unsafe root, protocol error, setup failure,
or failed containment proof prevents hostile exec.

The native binary is intentionally not tracked. From the repository root on
the target Linux host, reproduce the warning-clean build with installed GCC
and Linux UAPI headers:

```sh
gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 \
  native/fs_launcher/fs_launcher.c -o native/fs_launcher/fs_launcher
```

`NativeLandlockRunner` fails closed when this binary is absent. The tested
Ubuntu host required the `gcc`, `libc6-dev`, and `linux-libc-dev` packages.

## 18. Capability and ruleset contract

Support is determined by the documented version query
`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`, not by
kernel or distribution version. ABI 3 is the minimum. On the tested host the
query returned 3, and a separate deny-all enforcement probe confirmed that
an unprivileged domain produces `EACCES`.

The native launcher uses the installed Linux UAPI headers. Its handled mask
is every ABI-v3 filesystem right (numeric mask `0x7fff`): execute, read and
write file, read directory, remove directory/file, make char/directory/
regular/socket/FIFO/block/symlink, refer, and truncate. Grants are narrower:

- read-only: read file and read directory;
- read-execute: read file, read directory, and execute;
- read-write: read/write file, read directory, truncate, remove file/
  directory, make regular/directory/symlink, and refer;
- make FIFO/socket: opt-in policy flags only;
- make character/block device: never granted.

The fixture policy grants the assigned worktree and task temporary directory
read-write; the interpreter/repository/runtime hierarchy read-execute; the
fixture read-only directory read-only; and only `/dev/null` (write),
`/dev/zero` (write), `/dev/random` (read), and `/dev/urandom` (read). It does
not grant the whole `/dev` hierarchy.

Because Landlock rules in one layer union their rights, policy construction
rejects a same-object mode conflict and any ancestor/descendant overlap where
the ancestor grants a right omitted by the descendant. A read-only ancestor
with an explicit writable descendant remains valid; a writable workspace
containing a nominally read-only child does not.

## 19. Descriptor and path authority

The Python parent uses `close_fds=True` and passes only explicit protocol
descriptors. The launcher independently sanitizes with `close_range()` and
closes its setup descriptors before exec. The observed persistent worker FD
set is exactly `0, 1, 2`, even when the test deliberately passes an outside
file FD into the launcher process.

The existing-FD negative control remains important: a file opened before
Landlock can still be read through that descriptor after restriction while a
new pathname open is denied. This is a documented Landlock property and the
reason descriptor sanitation is part of the security boundary.

Controller strings are locators, never authority. It canonicalizes and binds
each configured root to `(st_dev, st_ino)` in the authenticated request. The
launcher opens `/` as a trusted directory FD and resolves the locator with
`openat2(O_PATH|O_CLOEXEC, RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|
RESOLVE_NO_SYMLINKS)`, then verifies the opened object's identity with
`fstat()`. Documented `EAGAIN` races receive at most three retries; every
other failure, identity change, or exhausted retry fails closed. There is no
`realpath()` or string-prefix authorization fallback. `fchdir()` uses the
already opened workspace FD.

## 20. Adversarial evidence on the tested host

The real native-launcher suite observed:

| Operation | Observation |
|---|---|
| workspace/read-only reads; workspace write/rename | allowed |
| outside read/write and parent traversal | denied, `EACCES` |
| symlink escape read/write | denied, `EACCES` |
| read-only write | denied, `EACCES` |
| `truncate()` and `open(O_TRUNC)` outside | denied, `EACCES`; content intact |
| outside hardlink into workspace | denied, `EXDEV` |
| read-only-to-workspace rename | denied, `EACCES` |
| child, grandchild, setsid, new process group, parent-exit, double fork | pathname access denied, `EACCES`; cgroup drained |
| concurrent policy-root replacement | intended inode opened or safe failure; never replacement |
| injected setup failures | no hostile marker; scope drained |
| exec failure after restriction | policy-applied evidence retained; separate exec-failed evidence |

The policy acknowledgement contains the request nonce, ABI, handled mask,
and SHA-256 policy digest. The controller authenticates those fields before
emitting `FILESYSTEM_POLICY_APPLIED`. A forged digest produces
`FILESYSTEM_POLICY_FAILED`, never policy-applied evidence, never an exec
release, and therefore no hostile worker execution.

## 21. Boundary characterization and claim

Observed ABI-v3 gaps are deliberately tests, not promises: metadata calls
such as `stat`, `chmod`, and `setxattr` can succeed outside the granted roots;
connecting to an already-created pathname Unix socket can succeed; and an
already-open descriptor remains usable. Landlock does not virtualize `/proc`,
hide the filesystem, broker credentials, mediate network access at ABI 3, or
provide mount/device isolation. Readable runtime roots (including `/proc`)
are compatibility grants, not proof that their contents are harmless.

The earned claim is narrow: on the recorded Ubuntu/WSL2 host, AgenticOS
demonstrated a fail-closed ABI-v3 Landlock content/hierarchy boundary for new
mediated operations, inherited by the tested descendant shapes and composed
with deterministic cgroup-v2 termination. This is not a complete sandbox or
a claim about native Windows execution, credentials, networks, sockets,
mounts, devices, arbitrary Linux hosts, or a malicious kernel.

## 22. Milestone 3B verification record (2026-08-07)

Observed host: Ubuntu 26.04 LTS (Resolute) on WSL2, kernel
`6.6.87.2-microsoft-standard-WSL2` x86_64, systemd 259
(`259.5-0ubuntu3`), Python 3.14.4, pytest 8.4.2, unified cgroup v2, and
Landlock ABI 3.

Commands and final counts after code review fixes:

```sh
gcc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 \
  native/fs_launcher/fs_launcher.c -o native/fs_launcher/fs_launcher
# exit 0, no diagnostics

.venv/bin/pytest -o addopts= -q \
  tests/conformance/test_native_landlock_unit.py \
  tests/conformance/test_native_landlock_integration.py
# 62 passed

.venv/bin/pytest -o addopts= -q \
  tests/conformance/test_filesystem_isolation.py
# 16 passed

.venv/bin/pytest -o addopts= -q \
  tests/conformance/test_cgroup_integration.py
# 13 passed

.venv/bin/pytest -o addopts= -q
# repetition 1: 180 passed, 1 skipped
# repetition 2: 180 passed, 1 skipped
# repetition 3: 180 passed, 1 skipped
```

The sole skip is the intentional non-Linux gating assertion. After each full
run, `systemctl --user list-units --all 'aos-*'` returned no units and no
`aos-*` cgroup reported `populated 1`. Native-Windows pytest is a portability
regression only and is reported separately from Linux enforcement evidence.

Windows portability regression after fast-forwarding the same Git commit:

```powershell
python -m pytest -o addopts= -q
# 87 passed, 94 skipped in 21.13s
```

This was observed on Microsoft Windows NT `10.0.26200.0`, Python 3.13.9,
pytest 8.3.5. The skips are Linux-only enforcement tests. This result proves
cross-platform imports and non-Linux behavior only; it is not Windows
filesystem isolation evidence.
