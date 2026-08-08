# Milestone 3B Landlock Filesystem Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce and prove a fail-closed Landlock ABI-v3 filesystem boundary after verified cgroup containment and before hostile worker execution.

**Architecture:** `NativeLandlockRunner` starts only a bounded, single-threaded C launcher inside the established transient systemd scope. The controller verifies launcher membership, releases a one-byte setup gate, and the launcher sanitizes FDs, safely resolves identity-bound roots with `openat2()`, and applies the full ABI-v3 ruleset plus `no_new_privs`. The launcher then acknowledges enforcement and blocks at a second gate; only after the controller authenticates the transcript and releases exec does it directly `execve()` the worker.

**Tech Stack:** Python 3.14 stdlib, pytest 8.4, ISO C11, Linux UAPI headers, systemd 259 user scopes, cgroup v2, Landlock ABI 3, WSL2 kernel 6.6.87.2.

## Global Constraints

- Preserve the committed `9fa265dc51b2fbdee172d257edca8ac2c760fabb` baseline and all authorized takeover work.
- Never run hostile code before both cgroup membership verification and `landlock_restrict_self()` success.
- Require Landlock ABI >= 3; ABI 1/2, disabled support, and unknown probe errors fail closed.
- Use no Python `preexec_fn`, shell intermediary, string-prefix authorization, or realpath-only authorization.
- Handle all filesystem rights through ABI v3; grant `MAKE_FIFO` and `MAKE_SOCK` only when explicitly requested; never grant `MAKE_CHAR` or `MAKE_BLOCK`.
- The ordinary worker contract contains only FDs 0, 1, and 2; setup/status/root descriptors must close before or atomically on `execve()`.
- Preserve the Milestone 2B systemd/cgroup-v2 lifecycle, bounded cancellation, `cgroup.kill`, recursive `populated 0`, and scope cleanup.
- Run real-scope suites serially because their global `aos-*` cleanup assertions intentionally conflict under concurrent execution.
- Do not commit until focused, repeated Linux, cleanup, and Windows proof is complete.

---

### Task 1: Freeze controller and protocol contracts with unit tests

**Files:**
- Create: `tests/conformance/test_native_landlock_unit.py`
- Modify: `src/agenticos/sandbox/launcher.py`
- Modify: `src/agenticos/sandbox/isolation.py`

**Interfaces:**
- Consumes: `FilesystemPolicy`, `build_launch_request()`, `parse_launcher_status()`, `sanitize_env()`.
- Produces: `PolicyRoot(path, mode, dev, ino)`, `LaunchRequest`, authenticated status records, and a correct repository-root `DEFAULT_LAUNCHER_PATH`.

- [ ] **Step 1: Write failing tests for launcher location, bounded protocol validation, credential-shaped environment removal, duplicate-field rejection, and status parsing.**

```python
def test_default_launcher_path_is_repository_native_directory():
    assert DEFAULT_LAUNCHER_PATH.parts[-3:] == ("native", "fs_launcher", "fs_launcher")
    assert DEFAULT_LAUNCHER_PATH.parent.name == "fs_launcher"

def test_status_requires_matching_nonce_and_policy_digest():
    parsed = parse_launcher_status(
        b"R:nonce\nS\nP\nN\nA:3:7fff:digest\n", nonce="nonce", policy_digest="digest"
    )
    assert parsed["abi"] == 3
    assert parsed["handled_access_fs"] == 0x7FFF
    assert parsed["policy_applied"] is True
```

- [ ] **Step 2: Run the focused tests and confirm RED.**

Run: `.venv/bin/python -m pytest tests/conformance/test_native_landlock_unit.py -v`

Expected: failures identify the wrong `src/native` path and absent structured status/identity fields.

- [ ] **Step 3: Implement immutable protocol records and strict serialization/parsing.**

```python
@dataclass(frozen=True)
class PolicyRoot:
    path: str
    mode: str
    dev: int
    ino: int

def policy_digest(cwd: PolicyRoot, roots: Sequence[PolicyRoot]) -> str:
    payload = json.dumps([asdict(cwd), *map(asdict, roots)], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()
```

The parser must reject unknown, duplicate, truncated, mismatched-nonce, and mismatched-digest records. Evidence fields contain the digest and masks, never raw policy paths.

- [ ] **Step 4: Run focused tests and confirm GREEN.**

Run: `.venv/bin/python -m pytest tests/conformance/test_native_landlock_unit.py -v`

---

### Task 2: Harden the native launcher against FD and UAPI defects

**Files:**
- Modify: `native/fs_launcher/fs_launcher.c`
- Modify: `.gitignore`
- Test: `tests/conformance/test_native_landlock_unit.py`

**Interfaces:**
- Consumes: `AOSLAUNCH/1` request records from Task 1 and installed Linux UAPI headers.
- Produces: warning-clean native binary, `R/S/P/N/A` status records, and guaranteed `FD_CLOEXEC` on status FD 3.

- [ ] **Step 1: Add failing build and runtime tests proving header compatibility and close-on-exec status behavior.**

```python
def test_native_launcher_builds_warning_clean(repo_root, tmp_path):
    subprocess.run([
        "cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror", "-O2",
        str(repo_root / "native/fs_launcher/fs_launcher.c"), "-o", str(tmp_path / "fs_launcher"),
    ], check=True)

def test_status_channel_reaches_eof_while_execed_worker_is_alive(direct_launcher):
    launch = direct_launcher(worker_argv=[sys.executable, "-c", "import time; time.sleep(5)"])
    assert launch.wait_for_policy_applied(timeout=2.0)
    assert launch.wait_for_status_eof(timeout=1.0)
    assert launch.process.poll() is None
```

- [ ] **Step 2: Run the build test and confirm RED.**

Expected: C compilation fails on the locally redefined `struct open_how`; after that is fixed, the runtime test times out because FD 3 survives `execve()`.

- [ ] **Step 3: Replace guessed syscall/rights structures with `<linux/landlock.h>`, `<linux/openat2.h>`, `<linux/close_range.h>`, and `SYS_*`; use `dup3(..., O_CLOEXEC)` or `fcntl(F_SETFD, FD_CLOEXEC)` when FD 3 is already the source.**

```c
#include <linux/close_range.h>
#include <linux/landlock.h>
#include <linux/openat2.h>

if (g_status_fd != 3) {
    if (dup3(g_status_fd, 3, O_CLOEXEC) < 0)
        fail_closed("fdsanitize", errno);
    g_status_fd = 3;
} else if (fcntl(3, F_SETFD, FD_CLOEXEC) < 0) {
    fail_closed("fdsanitize", errno);
}
```

- [ ] **Step 4: Compile with `-Werror` and run unit tests.**

Run: `cc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 native/fs_launcher/fs_launcher.c -o native/fs_launcher/fs_launcher`

Run: `.venv/bin/python -m pytest tests/conformance/test_native_landlock_unit.py -v`

Expected: both pass; `.gitignore` excludes only `/native/fs_launcher/fs_launcher`.

---

### Task 3: Bind safe path resolution to kernel object identity

**Files:**
- Modify: `src/agenticos/sandbox/isolation.py`
- Modify: `src/agenticos/sandbox/launcher.py`
- Modify: `native/fs_launcher/fs_launcher.c`
- Test: `tests/conformance/test_native_landlock_unit.py`
- Create: `tests/conformance/test_native_landlock_integration.py`

**Interfaces:**
- Consumes: canonical locator plus `(st_dev, st_ino)` from the trusted controller.
- Produces: `openat2(root_fd, relative_path, RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_SYMLINKS)` with bounded `EAGAIN` retry and `fstat()` identity/type verification.

- [ ] **Step 1: Write failing tests for missing/wrong-type roots, symlinked components, object replacement, and bounded race outcomes.**

```python
def test_swapped_policy_root_is_intended_inode_or_fails_closed(native_runner, root_swapper):
    result = native_runner.run_probe(root_swapper.config)
    assert result.opened_identity == root_swapper.expected_identity or result.failed_stage == "resolve"
    assert result.opened_identity != root_swapper.outside_identity
```

- [ ] **Step 2: Confirm tests fail against absolute `AT_FDCWD` resolution.**

- [ ] **Step 3: Open `/` as the trusted base dirfd, require absolute canonical locators, strip the leading slash, resolve beneath the base with all three flags, and compare `st_dev`, `st_ino`, and directory type before adding a rule or changing cwd. Never fall back.**

```c
how.flags = O_PATH | O_CLOEXEC;
how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS;
fd = syscall(SYS_openat2, root_fd, relative_path, &how, sizeof(how));
if (fstat(fd, &st) != 0 || st.st_dev != expected_dev || st.st_ino != expected_ino)
    fail_closed("resolve_identity", ESTALE);
```

- [ ] **Step 4: Run unit and race integration tests repeatedly.**

Run: `for i in 1 2 3; do .venv/bin/python -m pytest tests/conformance/test_native_landlock_integration.py -k 'resolve or race' -q || exit 1; done`

---

### Task 4: Prove the launch gates and fail-closed state machine

**Files:**
- Modify: `src/agenticos/sandbox/launcher.py`
- Modify: `native/fs_launcher/fs_launcher.c`
- Test: `tests/conformance/test_native_landlock_integration.py`
- Modify: `tests/conformance/test_evidence.py`

**Interfaces:**
- Consumes: cgroup discovery from `CgroupProcessRunner._discover_cgroup()` and native status protocol.
- Produces: evidence-ordered `CONTAINMENT_VERIFIED -> FD_SET_SANITIZED -> FILESYSTEM_POLICY_PREPARED -> NO_NEW_PRIVS_SET -> FILESYSTEM_POLICY_APPLIED -> WORKER_EXEC_ATTEMPTED`.

- [ ] **Step 1: Write failing fault-injection tests for gate denial, ABI <3, parse failure, resolution failure, ruleset/rule/NNP/restrict failure, and post-policy exec failure.**

```python
@pytest.mark.parametrize("fault,expected_stage", [
    ("skip_nnp", "restrict"),
    ("fail_rule", "rule"),
    ("fail_restrict", "restrict"),
])
def test_setup_fault_never_executes_worker(native_runner, marker, fault, expected_stage):
    result = native_runner.run_marker(marker, fault=fault)
    assert not marker.exists()
    assert result.failed_stage == expected_stage
```

- [ ] **Step 2: Confirm RED with precise missing fault/result behavior.**

- [ ] **Step 3: Make the status protocol line-oriented and nonce-bound; emit `A` only after real `landlock_restrict_self()` success; require a second controller release after acknowledgement validation; represent subsequent `execve()` failure only as `E:<errno>`. Ensure every exception path kills/drains the scope and verifies cleanup.**

- [ ] **Step 4: Run focused tests serially and inspect evidence ordering.**

Run: `.venv/bin/python -m pytest tests/conformance/test_native_landlock_integration.py -k 'gate or fault or exec or evidence' -v`

---

### Task 5: Complete FD hygiene and the intentional negative control

**Files:**
- Modify: `tests/fixtures/hostile_worker.py`
- Modify: `src/agenticos/sandbox/launcher.py`
- Test: `tests/conformance/test_native_landlock_integration.py`

**Interfaces:**
- Consumes: `_leak_fds` test hook and `FS-08`/`FS-12` worker scenarios.
- Produces: live worker census exactly `{0,1,2}`, plus a separate direct-Landlock negative control where a deliberately pre-opened outside FD remains readable.

- [ ] **Step 1: Write failing tests that pass an outside FD to the launcher, validate worker liveness of each enumerated FD with `fcntl(F_GETFD)`, and separately bypass production sanitation for the documented negative control.**

```python
def test_production_launcher_drops_deliberately_passed_outside_fd(native_runner, outside_fd):
    result = native_runner.run_scenario("FS-12", leak_fds=(outside_fd,))
    assert result.details["live_fds"] == [0, 1, 2]

def test_landlock_does_not_revoke_preopened_fd(landlock_negative_control):
    assert landlock_negative_control.path_opened is False
    assert landlock_negative_control.fd_read is True
```

- [ ] **Step 2: Confirm RED because FD 3 survives `execve()` and census includes transient descriptors.**

- [ ] **Step 3: Keep status FD CLOEXEC, close all setup FDs, set stdin to `/dev/null`, and report only descriptors still live after enumeration.**

- [ ] **Step 4: Run FD tests three times and assert status EOF arrives without waiting for worker exit.**

---

### Task 6: Complete adversarial ABI-v3 filesystem coverage

**Files:**
- Modify: `tests/fixtures/hostile_worker.py`
- Modify: `src/agenticos/sandbox/policy.py`
- Test: `tests/conformance/test_native_landlock_integration.py`

**Interfaces:**
- Consumes: `NativeLandlockRunner` and synthetic fixture resources only.
- Produces: observed results for allowed read/write/rename; denied read/write/traversal/symlink/hardlink/reparent/cross-rights rename/truncate/O_TRUNC; explicit errno assertions.

- [ ] **Step 1: Add one failing test per attack, including independent `truncate()` and `open(O_TRUNC)` probes and a valid in-workspace rename control.**

```python
@pytest.mark.parametrize("method", ["truncate", "open_trunc"])
def test_outside_truncation_is_eacces(native_runner, outside_file, method):
    result = native_runner.run_scenario("FS-TRUNCATE", target=outside_file, base=method)
    assert result.succeeded is False
    assert result.details["errno"] == errno.EACCES
```

- [ ] **Step 2: Confirm each new test fails because the scenario or native proof is absent.**

- [ ] **Step 3: Add the smallest worker handlers/catalog records required; preserve READ_ONLY, READ_EXECUTE, and READ_WRITE grants exactly.**

- [ ] **Step 4: Run the complete native filesystem matrix.**

Run: `.venv/bin/python -m pytest tests/conformance/test_native_landlock_integration.py -k filesystem -v`

---

### Task 7: Prove descendant inheritance and cgroup composition

**Files:**
- Modify: `tests/fixtures/hostile_worker.py`
- Test: `tests/conformance/test_native_landlock_integration.py`

**Interfaces:**
- Consumes: existing bounded descendant shapes and `NativeLandlockRunner`.
- Produces: simultaneous Landlock denial and cgroup containment for child, grandchild, `setsid`, new process group, parent-exit descendant, and double fork.

- [ ] **Step 1: Write parametrized failing composition tests that assert denied filesystem access, task cgroup identity, `TERMINATED`, recursive empty evidence, and no surviving PID.**

```python
@pytest.mark.parametrize("mode", ["child", "grandchild", "setsid", "newpgroup", "parentexit", "doublefork"])
def test_descendant_keeps_both_boundaries(native_runner, mode):
    result = native_runner.run_scenario("FS-09", base=mode)
    assert result.details["descendant_opened"] is False
    assert result.process.containment_state == "TERMINATED"
```

- [ ] **Step 2: Confirm RED for unimplemented shapes/evidence.**

- [ ] **Step 3: Reuse existing bounded worker lifecycle helpers; do not fork or redesign containment in the launcher.**

- [ ] **Step 4: Run composition and original cgroup suites serially.**

Run: `.venv/bin/python -m pytest tests/conformance/test_native_landlock_integration.py -k descendant -v`

Run: `.venv/bin/python -m pytest tests/conformance/test_cgroup_integration.py -v`

---

### Task 8: Characterize ABI-v3 gaps without widening claims

**Files:**
- Modify: `tests/fixtures/hostile_worker.py`
- Test: `tests/conformance/test_native_landlock_integration.py`
- Modify: `docs/phase-zero/filesystem-isolation.md`

**Interfaces:**
- Consumes: `FS-13` metadata and pathname Unix-socket probes.
- Produces: explicit observed characterization of `stat`, `chmod`, `setxattr`, pathname socket connection, existing FDs, `/proc`, devices, credentials, and networks.

- [ ] **Step 1: Write characterization tests that record observations without mapping non-mediated operations to false conformance failures.**

- [ ] **Step 2: Run on the real host and record exact errno/results.**

- [ ] **Step 3: Update docs with only observed ABI-v3 behavior and kernel-documented limitations.**

---

### Task 9: Earn the Linux, cleanup, and Windows proof

**Files:**
- Modify: `docs/phase-zero/filesystem-isolation.md`
- Modify: `docs/phase-zero/host-capabilities.md`
- Modify: `docs/phase-zero/process-containment.md` only if composition evidence changes its existing statement.

**Interfaces:**
- Consumes: all focused tests and evidence.
- Produces: exact environment/test record and narrow security claim.

- [ ] **Step 1: Run warning-clean build, diff checks, and focused suites.**

```text
git diff --check
cc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 native/fs_launcher/fs_launcher.c -o native/fs_launcher/fs_launcher
.venv/bin/python -m pytest tests/conformance/test_native_landlock_unit.py tests/conformance/test_native_landlock_integration.py -v
```

- [ ] **Step 2: Run the full Linux suite three consecutive times, serially.**

Run: `for i in 1 2 3; do .venv/bin/python -m pytest || exit 1; done`

- [ ] **Step 3: Audit `systemctl --user list-units 'aos-*' --all`, attributable PIDs, task cgroups, and recursive `populated 0` evidence after tests.**

- [ ] **Step 4: Fast-forward the clean Windows repository from the intentional WSL commit, run Windows pytest, and state explicitly that this is regression-only evidence.**

- [ ] **Step 5: Inspect final `git status`, `git diff --stat`, full diff, generated artifacts, and documentation; commit once as `phase-zero: enforce Landlock filesystem boundary`, push without force, and verify both repositories and actual `origin/main` are clean and equal.**
