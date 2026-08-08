# Milestone 4A Runtime, Credential, IPC, and No-Network Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compose the proven cgroup and Landlock barriers with an independently verified Bubblewrap namespace/runtime boundary that exposes the assigned worktree only at `/workspace`, passes no provider credentials, denies host/external networking and host Unix sockets, and preserves fail-closed startup and recursive cleanup.

**Architecture:** A Linux-only controller layer securely opens fixed host sources with `openat2()` and gives Bubblewrap only authorized FDs plus fixed synthetic destinations. Bubblewrap constructs explicit user, mount, PID, network, IPC, and UTS namespaces while blocked; the controller verifies its child through host `/proc`, then releases the existing native launcher, which sanitizes FDs, verifies sandbox-visible identities, applies NNP and Landlock, and waits for the authenticated final exec gate.

**Tech Stack:** Python 3.14 stdlib, pytest 8.4, ISO C11, Linux `openat2`/namespace/Landlock UAPI, Bubblewrap 0.11.1 non-setuid, systemd 259 user scopes, cgroup v2, Landlock ABI 3, Ubuntu WSL2.

## Global Constraints

- Preserve the M3B baseline `dcf24fe4a50f82761dc6ab8eeb34ae9b33ecba88` and approved M4A design checkpoint `6ff839f`.
- `/workspace` is the stable worker-facing ABI; host source path strings never enter the worker environment, argv, runtime view, or inner launch request.
- Use only `--bind-fd` and `--ro-bind-fd` for host source mappings. There is no pathname-bind fallback and no arbitrary user mount language.
- Use explicit `--unshare-user`, `--unshare-pid`, `--unshare-net`, `--unshare-ipc`, and `--unshare-uts`; never use `--unshare-all` or `--unshare-cgroup`.
- Require `--disable-userns`, `--new-session`, `--die-with-parent`, `--clearenv`, `--block-fd`, JSON status, and FD binds to pass real behavior probes.
- Accept `/usr/bin/bwrap` 0.11.1 only when path, hash, owner/mode, absent setuid/setgid bits, absent file capabilities, and unprivileged-userns operation match verified evidence.
- Preserve the systemd/cgroup-v2 lifecycle as authoritative. Bubblewrap parent-death behavior is defense in depth only.
- Preserve the native M3B two-gate boundary, warning-clean C build, ABI-v3 handled mask, identity-bound `openat2()`, FD census `{0,1,2}`, and authenticated policy evidence.
- Sanitize setup descriptors before opening sandbox-visible roots; verify every destination's type, device, and inode before NNP or Landlock.
- L1 mounts and grants `/workspace` read-only; L2 mounts and grants it read-write. Both use `network_policy=DENY`.
- The worker receives an exact generated environment and zero provider credentials or ambient controller variables.
- Do not inspect real credentials, contact public endpoints, implement seccomp, implement M4B, or add provider adapters.
- Real systemd-scope suites run serially; final Linux proof runs the full suite three consecutive times and Windows regression once.
- If an approved host or ordering assumption is false, stop for design review instead of weakening the boundary.

## File and interface map

- Create `src/agenticos/sandbox/runtime_boundary.py`: Linux `openat2()` source authority, Bubblewrap installation probe, fixed runtime mappings/argv, worker environment, bounded JSON parsing, `/proc` namespace verification, and digest records.
- Create `src/agenticos/sandbox/m4a_runner.py`: `NamespaceLandlockRunner`, staged namespace/native launch state machine, evidence emission, and cgroup-backed failure cleanup.
- Modify `src/agenticos/sandbox/launcher.py`: versioned M4A native request/status support while retaining M3B protocol behavior and helpers reusable by the composed runner.
- Modify `native/fs_launcher/fs_launcher.c`: accept `AOSLAUNCH/2`, emit sandbox-identity evidence, preserve `AOSLAUNCH/1`, and retain FD-first setup.
- Modify `tests/fixtures/hostile_worker.py`: bounded M4A probes for namespace, capabilities, runtime view, credentials, sockets, network, and descendant attempts against synthetic fixtures only.
- Create `tests/conformance/test_m4a_unit.py`: deterministic policy, parser, digest, environment, and fault tests that do not require live systemd scopes.
- Create `tests/conformance/test_m4a_integration.py`: serialized real-host ordering, mapping, filesystem-view, credentials, IPC/network, descendant, startup-failure, and cleanup proof.
- Modify `src/agenticos/sandbox/policy.py`: register only the new synthetic attack IDs needed by the conformance report.
- Modify `pyproject.toml`: add the `m4a_linux` marker.
- Create `docs/phase-zero/runtime-boundary.md`: measured M4A architecture, matrices, evidence, limitations, and narrow claim.
- Create `docs/roadmap.md`: durable post-M4A milestones and authentication-ownership principle.
- Modify `docs/phase-zero/host-capabilities.md`, `filesystem-isolation.md`, `process-containment.md`, and `sandbox-conformance.md`: composition evidence without weakening existing claims.

---

### Task 1: Freeze source authority and Bubblewrap installation acceptance

**Files:**
- Create: `src/agenticos/sandbox/runtime_boundary.py`
- Create: `tests/conformance/test_m4a_unit.py`

**Interfaces:**
- Consumes: Linux absolute source locators and expected `stat.S_IF*` type.
- Produces: `RuntimeBoundaryUnavailable`, `FileIdentity`, `AuthorizedSource`,
  `BubblewrapCapability`, `secure_open_source()`, and `probe_bubblewrap()`.

- [ ] **Step 1: Write failing tests for immutable identities, safe opens, wrong types, symlinks, missing `openat2`, and privileged Bubblewrap metadata.**

```python
def test_secure_open_source_returns_authoritative_fd_and_identity(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    opened = secure_open_source(source, expected_type=stat.S_IFDIR)
    try:
        observed = os.fstat(opened.fd)
        assert (observed.st_dev, observed.st_ino) == (
            opened.identity.device, opened.identity.inode,
        )
        assert opened.locator == source.resolve()
    finally:
        os.close(opened.fd)

def test_bubblewrap_probe_rejects_setuid(monkeypatch, fake_bwrap_stat):
    fake_bwrap_stat.st_mode |= stat.S_ISUID
    result = probe_bubblewrap(Path("/usr/bin/bwrap"))
    assert result.supported is False
    assert "setuid" in result.reasons
```

- [ ] **Step 2: Run the focused unit tests and verify RED.**

Run: `python -m pytest tests/conformance/test_m4a_unit.py -k 'secure_open or bubblewrap_probe' -v`

Expected: collection fails because `runtime_boundary` and its records do not exist.

- [ ] **Step 3: Implement the exact records and Linux-only `openat2()` wrapper.**

```python
@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    file_type: int

    @classmethod
    def from_stat(cls, observed: os.stat_result) -> "FileIdentity":
        return cls(observed.st_dev, observed.st_ino, stat.S_IFMT(observed.st_mode))

@dataclass(frozen=True)
class AuthorizedSource:
    locator: Path
    fd: int
    identity: FileIdentity

def secure_open_source(locator: Path, *, expected_type: int) -> AuthorizedSource:
    canonical = locator.resolve(strict=True)
    fd = _openat2_from_root(canonical, O_PATH_FLAGS, RESOLVE_FLAGS, retries=3)
    observed = os.fstat(fd)
    if stat.S_IFMT(observed.st_mode) != expected_type:
        os.close(fd)
        raise RuntimeBoundaryUnavailable("authorized source has wrong type")
    return AuthorizedSource(canonical, fd, FileIdentity.from_stat(observed))
```

Use `ctypes.CDLL(None, use_errno=True).syscall()` with a local `OpenHow`
structure. M4A supports the recorded `x86_64`/`AMD64` Linux host and uses its
installed UAPI syscall number `SYS_openat2=437`; every other architecture,
platform, or missing syscall fails closed. Define `O_PATH_FLAGS` as
`O_PATH|O_CLOEXEC|O_NOFOLLOW` and `RESOLVE_FLAGS` as
`RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_SYMLINKS`. Every error except
bounded `EAGAIN` fails closed. Never call `os.open()` or pathname Bubblewrap
binds as fallback.

- [ ] **Step 4: Implement `probe_bubblewrap()` with independently injectable command/stat/hash/capability readers.**

The production probe must require `/usr/bin/bwrap`, parse exactly one version
line, hash the executable through an opened descriptor, require uid/gid 0/0 and
mode 0755, reject setuid/setgid or non-empty `getcap`, then run a bounded
explicit-namespace behavior probe that confirms a different user namespace.

- [ ] **Step 5: Run the focused tests and verify GREEN.**

Run: `python -m pytest tests/conformance/test_m4a_unit.py -k 'secure_open or bubblewrap_probe' -v`

- [ ] **Step 6: Commit the source-authority boundary.**

```bash
git add src/agenticos/sandbox/runtime_boundary.py tests/conformance/test_m4a_unit.py
git commit -m "security: authorize M4A runtime sources by file identity"
```

---

### Task 2: Build the fixed runtime, environment, and digest policies

**Files:**
- Modify: `src/agenticos/sandbox/runtime_boundary.py`
- Test: `tests/conformance/test_m4a_unit.py`

**Interfaces:**
- Consumes: `M4AProfile`, authorized workspace/tmp/home/runtime/launcher/worker sources.
- Produces: `MountRole`, `AuthorizedMount`, `RuntimeBoundaryPlan`, `build_worker_env()`, `build_runtime_plan()`, and `build_bwrap_argv()`.

- [ ] **Step 1: Write failing tests for fixed destinations, L1/L2 modes, merged-`/usr` symlinks, exact environment, no host paths, deterministic digests, explicit namespace flags, and prohibited flags.**

```python
@pytest.mark.parametrize(
    ("profile", "bind_option", "landlock_mode"),
    [(M4AProfile.INSPECT, "--ro-bind-fd", "r"),
     (M4AProfile.BUILD, "--bind-fd", "w")],
)
def test_workspace_is_fixed_and_profiled(runtime_sources, profile, bind_option, landlock_mode):
    plan = build_runtime_plan(profile=profile, **runtime_sources)
    workspace = plan.mount_for("/workspace")
    assert workspace.bind_option == bind_option
    assert workspace.landlock_mode == landlock_mode
    assert plan.cwd == "/workspace"

def test_bwrap_argv_uses_only_explicit_namespaces(plan):
    argv = build_bwrap_argv(plan, namespace_gate_fd=20, json_status_fd=21)
    assert "--unshare-all" not in argv
    assert "--unshare-cgroup" not in argv
    for flag in ("--unshare-user", "--unshare-pid", "--unshare-net",
                 "--unshare-ipc", "--unshare-uts", "--disable-userns",
                 "--new-session", "--die-with-parent", "--clearenv"):
        assert flag in argv
```

- [ ] **Step 2: Run policy tests and verify RED.**

Run: `python -m pytest tests/conformance/test_m4a_unit.py -k 'workspace_is_fixed or bwrap_argv or worker_env or policy_digest' -v`

- [ ] **Step 3: Implement fixed enums and immutable policy records.**

```python
class M4AProfile(str, Enum):
    INSPECT = "L1_INSPECT"
    BUILD = "L2_BUILD"

class MountRole(str, Enum):
    WORKSPACE = "workspace"
    RUNTIME = "runtime"
    LAUNCHER = "launcher"
    WORKER = "worker"
    TASK_TMP = "task_tmp"
    SYNTHETIC_HOME = "synthetic_home"

WORKER_ENV = {
    "HOME": "/home/tool", "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
    "TMPDIR": "/tmp", "PWD": "/workspace",
}
```

Only `/tmp` receives the Landlock socket-node creation flag. The workspace,
runtime, launcher, worker, home, proc, dev, and run policies are fixed by role.

- [ ] **Step 4: Implement canonical JSON digests and the deterministic Bubblewrap argument vector.**

The digest payload contains destination, device, inode, type, role, bind mode,
Landlock mode, explicit namespace policy, `DENY` network policy, and environment
names/values. It excludes source locators and FD numbers. The argument vector
starts from tmpfs `/`, binds `/usr` read-only by FD, creates the measured merged-
`/usr` symlinks, mounts exact launcher/worker files, adds private tmp/home, empty
run, new proc, synthetic dev, fixed cwd, gates, and direct launcher argv.

- [ ] **Step 5: Run policy tests and verify GREEN.**

Run: `python -m pytest tests/conformance/test_m4a_unit.py -k 'runtime_plan or workspace or bwrap_argv or worker_env or digest' -v`

- [ ] **Step 6: Commit deterministic runtime policy.**

```bash
git add src/agenticos/sandbox/runtime_boundary.py tests/conformance/test_m4a_unit.py
git commit -m "security: define fixed M4A runtime and environment policies"
```

---

### Task 3: Parse Bubblewrap status and verify namespaces independently

**Files:**
- Modify: `src/agenticos/sandbox/runtime_boundary.py`
- Test: `tests/conformance/test_m4a_unit.py`

**Interfaces:**
- Consumes: bounded Bubblewrap JSON documents, controller namespace snapshot, host-visible child PID, and expected cgroup path.
- Produces: `NamespaceEvidenceError`, `BwrapSetupStatus`, `NamespaceSnapshot`,
  `NamespaceEvidence`, `read_bwrap_setup_status()`,
  `read_namespace_snapshot()`, and `verify_namespace_evidence()`.

- [ ] **Step 1: Write failing parser tests for required fields, unknown fields/objects, malformed JSON, contradictory setup records, excessive bytes/objects, and exit-status separation.**

```python
def test_status_parser_tolerates_unknown_future_objects():
    stream = io.BytesIO(
        b'{"future-event":"x"}\n'
        b'{"child-pid":42,"mnt-namespace":2,"net-namespace":3,'
        b'"pid-namespace":4,"ipc-namespace":5,"uts-namespace":6,"extra":7}\n'
    )
    parsed = read_bwrap_setup_status(stream.fileno(), timeout=1.0)
    assert parsed.child_pid == 42

def test_status_parser_rejects_contradictory_setup_records():
    with pytest.raises(NamespaceEvidenceError, match="contradictory"):
        parse_bwrap_documents([valid_setup(child_pid=42), valid_setup(child_pid=43)])
```

- [ ] **Step 2: Run parser tests and verify RED.**

Run: `python -m pytest tests/conformance/test_m4a_unit.py -k 'status_parser or namespace_evidence' -v`

- [ ] **Step 3: Implement bounded streaming parsing.**

Limit each line, total bytes, object count, integer range, and deadline. Require
`child-pid`, mount, network, PID, IPC, and UTS identifiers in the setup object;
do not require a user-namespace field Bubblewrap does not provide. Ignore bounded
unknown fields and unrelated object types, but reject a second different setup
record.

- [ ] **Step 4: Implement independent host `/proc` verification.**

```python
NAMESPACE_NAMES = ("user", "mnt", "net", "pid", "ipc", "uts")

def read_namespace_snapshot(pid: int) -> NamespaceSnapshot:
    return NamespaceSnapshot(
        pid=pid,
        identities={name: _parse_ns_link(os.readlink(f"/proc/{pid}/ns/{name}"))
                    for name in NAMESPACE_NAMES},
        cgroup=parse_proc_cgroup(Path(f"/proc/{pid}/cgroup").read_text()),
        uid_map=Path(f"/proc/{pid}/uid_map").read_text(),
    )
```

Verify all six identities differ from the controller snapshot, Bubblewrap's five
reported namespace IDs match `/proc`, the uid map proves unprivileged mapping,
and the host cgroup record equals the already discovered task cgroup. PID reuse,
missing `/proc`, mismatch, or process exit fails closed.

- [ ] **Step 5: Run parser/verifier tests and verify GREEN.**

Run: `python -m pytest tests/conformance/test_m4a_unit.py -k 'status_parser or namespace_evidence' -v`

- [ ] **Step 6: Commit namespace evidence verification.**

```bash
git add src/agenticos/sandbox/runtime_boundary.py tests/conformance/test_m4a_unit.py
git commit -m "security: verify M4A namespaces through host proc"
```

---

### Task 4: Version the native transcript and expose identity verification

**Files:**
- Modify: `native/fs_launcher/fs_launcher.c`
- Modify: `src/agenticos/sandbox/launcher.py`
- Modify: `tests/conformance/test_native_landlock_unit.py`
- Test: `tests/conformance/test_m4a_unit.py`

**Interfaces:**
- Consumes: `AOSLAUNCH/1` M3B requests and `AOSLAUNCH/2` M4A requests using synthetic paths plus expected identities.
- Produces: unchanged v1 transcript and v2 `R,S,I,P,N,A` transcript authenticated by nonce and combined-policy digest.

- [ ] **Step 1: Write failing compatibility and v2 transcript tests.**

```python
def test_v2_status_requires_identity_between_sanitize_and_policy():
    parsed = parse_launcher_status(
        b"R:nonce\nS\nI\nP\nN\nA:3:7fff:digest\n",
        expected_nonce="nonce", expected_policy_digest="digest",
        protocol_version=2,
    )
    assert parsed["identity_verified"] is True
    assert parsed["policy_applied"] is True

def test_v1_transcript_remains_accepted():
    parsed = parse_launcher_status(
        b"R:nonce\nS\nP\nN\nA:3:7fff:digest\n",
        expected_nonce="nonce", expected_policy_digest="digest",
        protocol_version=1,
    )
    assert parsed["policy_applied"] is True
```

- [ ] **Step 2: Run native unit tests and verify RED only for v2 behavior.**

Run: `python -m pytest tests/conformance/test_native_landlock_unit.py tests/conformance/test_m4a_unit.py -k 'transcript or protocol' -v`

- [ ] **Step 3: Extend request serialization/parsing with an explicit protocol version.**

`prepare_launch_request(..., protocol_version=1)` retains existing wire output.
M4A passes `protocol_version=2`, synthetic `cwd=/workspace`, sandbox destinations,
expected identities, and the combined digest. Duplicate or incompatible version
records fail before setup.

- [ ] **Step 4: Extend the C launcher without changing v1 semantics.**

The launcher records v1/v2 while parsing. For v2 it emits `I` only after all
root/cwd `openat2()` and `fstat()` checks succeed and after `fchdir()` succeeds.
FD normalization and `close_range(5, ~0u, 0)` remain before these opens. Fault
hooks `fail_identity` and `bad_identity_order` exist only under the established
test-only fault environment.

- [ ] **Step 5: Compile warning-clean and run both protocol suites GREEN.**

Run: `cc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 native/fs_launcher/fs_launcher.c -o native/fs_launcher/fs_launcher`

Run: `python -m pytest tests/conformance/test_native_landlock_unit.py tests/conformance/test_m4a_unit.py -k 'transcript or protocol or compiles' -v`

- [ ] **Step 6: Commit the versioned native barrier.**

```bash
git add native/fs_launcher/fs_launcher.c src/agenticos/sandbox/launcher.py tests/conformance/test_native_landlock_unit.py tests/conformance/test_m4a_unit.py
git commit -m "security: authenticate M4A sandbox identity evidence"
```

---

### Task 5: Compose the namespace and Landlock launch gates

**Files:**
- Create: `src/agenticos/sandbox/m4a_runner.py`
- Modify: `src/agenticos/sandbox/__init__.py`
- Modify: `pyproject.toml`
- Test: `tests/conformance/test_m4a_unit.py`
- Create: `tests/conformance/test_m4a_integration.py`

**Interfaces:**
- Consumes: `RuntimeBoundaryPlan`, Bubblewrap capability/evidence helpers,
  `prepare_launch_request(protocol_version=2)`, `parse_launcher_status()`, and
  `CgroupProcessRunner` discovery/cancellation primitives.
- Produces: `NamespaceLandlockRunner.run()`, M4A outcome records, and ordered
  namespace/filesystem evidence events.

- [ ] **Step 1: Write failing fake-process unit tests for the complete state machine and every pre-release failure.**

```python
def test_runner_never_releases_namespace_before_independent_evidence(fake_launch):
    fake_launch.queue_json(valid_setup(child_pid=42))
    fake_launch.proc_snapshot = mismatched_net_namespace()
    with pytest.raises(ContainmentUnavailableError):
        fake_launch.runner.run(
            ["/usr/bin/python3", "/opt/agenticos/worker.py"],
            cwd="/workspace", env={},
        )
    assert fake_launch.namespace_gate_writes == []
    assert fake_launch.exec_gate_writes == []

def test_runner_releases_exec_only_after_combined_ack(fake_launch):
    fake_launch.queue_valid_namespace_and_transcript("R:nonce\nS\nI\nP\nN\nA:3:7fff:digest\n")
    fake_launch.runner.run(fake_launch.argv, cwd="/workspace", env={})
    assert fake_launch.ordered_writes == [("namespace", b"G"), ("setup", b"G"), ("exec", b"X")]
```

- [ ] **Step 2: Run state-machine tests and verify RED.**

Run: `python -m pytest tests/conformance/test_m4a_unit.py -k runner -v`

- [ ] **Step 3: Implement `NamespaceLandlockRunner` with explicit descriptor ownership.**

The runner opens sources, allocates namespace/status/native-status pipes at FDs
above 4, writes the bounded native request to stdin, and launches only:

```python
[systemd_run, "--user", "--scope", "--quiet", "--collect", f"--unit={unit}",
 "--", *build_bwrap_argv(plan, namespace_gate_r, json_status_w)]
```

Use `shell=False`, `start_new_session=True`, the controller's minimal control
environment, and one explicit `pass_fds` tuple. Close every parent/child pipe end
at deterministic ownership transitions.

- [ ] **Step 4: Implement the staged verification order.**

1. Read setup JSON while Bubblewrap is blocked.
2. Discover the exact systemd scope cgroup and verify the JSON child in it.
3. Independently verify six namespace identities and the unprivileged uid map.
4. Prove native status has no `R` and the hostile marker is absent.
5. Release the namespace gate.
6. Require authenticated `R`, then send the existing setup `G`.
7. Require ordered `S/I/P/N/A` and validate the combined digest.
8. Prove the hostile marker remains absent, then send `X`.
9. Require native status EOF as the direct-exec observation.

Every exception closes gates, invokes `_cancel(scope, cgroup_path, proc)`, waits
for recursive emptiness, stops the unit, closes source FDs/private directories,
and raises if cleanup cannot be proven.

- [ ] **Step 5: Write and run the real `--block-fd` ordering regression.**

Run: `.venv/bin/python -m pytest tests/conformance/test_m4a_integration.py -k block_fd_ordering -v`

Expected after implementation: namespace JSON and independent evidence arrive
with launcher/worker markers absent; `R` arrives only after namespace release;
worker marker remains absent through `A`; worker runs only after `X`.

- [ ] **Step 6: Run state-machine and ordering tests GREEN.**

Run: `python -m pytest tests/conformance/test_m4a_unit.py -k runner -v`

Run: `.venv/bin/python -m pytest tests/conformance/test_m4a_integration.py -k 'block_fd_ordering or normal_exit' -v`

- [ ] **Step 7: Commit the composed launch boundary.**

```bash
git add src/agenticos/sandbox/m4a_runner.py src/agenticos/sandbox/__init__.py pyproject.toml tests/conformance/test_m4a_unit.py tests/conformance/test_m4a_integration.py
git commit -m "security: compose Bubblewrap and Landlock launch gates"
```

---

### Task 6: Prove `/workspace` mapping and the minimal filesystem view

**Files:**
- Modify: `tests/fixtures/hostile_worker.py`
- Modify: `tests/conformance/test_m4a_integration.py`
- Modify: `src/agenticos/sandbox/policy.py`

**Interfaces:**
- Consumes: L1/L2 runner fixtures and only synthetic fixture resources.
- Produces: runtime-view scenarios and identity/path-race proof for fixed sandbox destinations.

- [ ] **Step 1: Add bounded worker scenarios for cwd, path existence/type, directory listing, file read/write, and runtime execution using sandbox paths.**

```python
def scenario_runtime_view(args):
    return make_result(
        args.scenario, args.target, utc_now_iso(), succeeded=True,
        details={
            "cwd": os.getcwd(),
            "pwd": os.environ.get("PWD"),
            "workspace_identity": _identity("/workspace"),
            "root_entries": sorted(os.listdir("/")),
        },
    )
```

Never enumerate real host credential paths; targets are synthetic fixture
canaries or fixed sandbox paths.

- [ ] **Step 2: Write failing integration tests for L1/L2 behavior and every mapping attack.**

Cover authorized FD acceptance, deliberately substituted source FD, replacement
after authorization, changed destination, wrong object/type, host absolute path
absence, sibling absence, cwd/PWD `/workspace`, M3B symlink/race regression,
private tmp/home, empty run, absent Windows mount, new proc, measured dev, and
runtime execution through merged-`/usr` symlinks.

- [ ] **Step 3: Run mapping/view tests and verify RED for missing scenarios or policy behavior.**

Run: `.venv/bin/python -m pytest tests/conformance/test_m4a_integration.py -k 'workspace or runtime_view or identity or race' -v`

- [ ] **Step 4: Implement only the missing fixed-role policy and worker handlers.**

Do not add user-selected destinations or broad runtime binds. L1 uses both
read-only mount enforcement and Landlock read-only rights; L2 uses the writable
pair. Map exact launcher and worker files instead of their repository directory.

- [ ] **Step 5: Run mapping/view tests and existing M3B path tests GREEN.**

Run: `.venv/bin/python -m pytest tests/conformance/test_m4a_integration.py -k 'workspace or runtime_view or identity or race' -v`

Run: `.venv/bin/python -m pytest tests/conformance/test_native_landlock_integration.py -k 'resolve or race or symlink' -v`

- [ ] **Step 6: Commit stable workspace and runtime-view proof.**

```bash
git add tests/fixtures/hostile_worker.py tests/conformance/test_m4a_integration.py src/agenticos/sandbox/policy.py
git commit -m "test: prove M4A workspace and runtime view"
```

---

### Task 7: Close credentials, nested namespaces, capabilities, and inherited FDs

**Files:**
- Modify: `tests/fixtures/hostile_worker.py`
- Modify: `tests/conformance/test_m4a_integration.py`
- Modify: `src/agenticos/sandbox/runtime_boundary.py`

**Interfaces:**
- Consumes: exact worker environment and test-only deliberately inherited FDs.
- Produces: credential-canary evidence, nested-userns denial, final capability-state evidence, and production FD census `{0,1,2}`.

- [ ] **Step 1: Write failing environment tests with all required synthetic canaries present in the controller input.**

```python
FAKE_CREDENTIAL_ENV = {
    "OPENAI_API_KEY": "AOS_CANARY_openai",
    "ANTHROPIC_API_KEY": "AOS_CANARY_anthropic",
    "AWS_ACCESS_KEY_ID": "AOS_CANARY_cloud",
    "SSH_AUTH_SOCK": "/synthetic-host-run/ssh.sock",
    "XDG_RUNTIME_DIR": "/synthetic-host-run",
    "AOS_PROVIDER_CONFIG": "/synthetic-host-home/provider.json",
    "GIT_ASKPASS": "/synthetic-host-bin/askpass",
}

def test_worker_has_no_controller_credential_canaries(m4a_runner):
    result = m4a_runner.run_environment_probe(FAKE_CREDENTIAL_ENV)
    assert result.controller_canaries_present is True
    assert result.worker_canaries_present is False
    assert result.worker_environment == WORKER_ENV
```

- [ ] **Step 2: Write failing nested-userns, capability, and leaked-FD tests.**

Require nested `unshare --user` failure; `CapInh`, `CapPrm`, `CapEff`, and
`CapAmb` zero; `NoNewPrivs=1`; recorded empty `CapBnd` on this host; and live
worker FDs exactly 0,1,2 even when source, JSON-status, and synthetic outside
file/socket descriptors were deliberately inherited into trusted setup.

- [ ] **Step 3: Run the focused tests and verify RED.**

Run: `.venv/bin/python -m pytest tests/conformance/test_m4a_integration.py -k 'credential or userns or capability or inherited_fd' -v`

- [ ] **Step 4: Add the smallest worker probes and evidence normalization needed.**

Capability parsing accepts fixed hexadecimal fields from `/proc/self/status`;
environment results record names/presence only. The runtime policy never adds a
capability or forwards a caller environment entry.

- [ ] **Step 5: Run the focused tests GREEN three times.**

Run: `for i in 1 2 3; do .venv/bin/python -m pytest tests/conformance/test_m4a_integration.py -k 'credential or userns or capability or inherited_fd' -q || exit 1; done`

- [ ] **Step 6: Commit credential/capability/FD closure.**

```bash
git add src/agenticos/sandbox/runtime_boundary.py tests/fixtures/hostile_worker.py tests/conformance/test_m4a_integration.py
git commit -m "security: close M4A credentials capabilities and inherited fds"
```

---

### Task 8: Prove host network and Unix-socket isolation

**Files:**
- Modify: `tests/fixtures/hostile_worker.py`
- Modify: `tests/conformance/test_m4a_integration.py`
- Modify: `src/agenticos/sandbox/policy.py`

**Interfaces:**
- Consumes: fixture-owned TCP, UDP, pathname Unix, abstract Unix, and connected-socket endpoints.
- Produces: endpoint receipt/response observations for root worker and every descendant shape.

- [ ] **Step 1: Add fixture-controlled endpoint helpers with bounded deadlines and explicit receipt logs.**

TCP/UDP bind only host loopback with ephemeral ports. Unix socket names and paths
contain randomized synthetic fixture identifiers. Every server thread has a
bounded accept/receive deadline and joins before fixture cleanup.

- [ ] **Step 2: Write failing root-worker network/IPC tests.**

Assert host TCP connection denied/unreachable; host UDP fixture receives zero
datagrams and worker receives no response; abstract socket denied/unreachable;
pathname host socket absent; and a sandbox-private `/tmp` pathname socket works.
Do not infer UDP connectivity from the worker's `sendto()` return value.

- [ ] **Step 3: Write the connected-socket negative control and production comparison.**

The low-level negative control intentionally bypasses the native FD sanitation
stage and proves an already-connected synthetic socket can exchange one canary
message despite namespace isolation. The production runner deliberately receives
the same FD class and proves the hostile worker has no descriptor beyond 2 and
the endpoint receives no worker message.

- [ ] **Step 4: Run network/IPC tests and verify RED.**

Run: `.venv/bin/python -m pytest tests/conformance/test_m4a_integration.py -k 'tcp or udp or unix_socket or connected_socket' -v`

- [ ] **Step 5: Implement bounded worker attacks and only the `/tmp` `MAKE_SOCK` grant.**

Worker network targets must be supplied by the synthetic fixture; reject
non-loopback test targets in the fixture helper. No DNS lookup or Internet route
is used.

- [ ] **Step 6: Run root and descendant network/IPC tests GREEN.**

Run: `.venv/bin/python -m pytest tests/conformance/test_m4a_integration.py -k 'tcp or udp or unix_socket or connected_socket' -v`

- [ ] **Step 7: Commit no-network and socket proof.**

```bash
git add tests/fixtures/hostile_worker.py tests/conformance/test_m4a_integration.py src/agenticos/sandbox/policy.py
git commit -m "test: prove M4A network and Unix socket isolation"
```

---

### Task 9: Prove descendant inheritance, failures, and authoritative cleanup

**Files:**
- Modify: `src/agenticos/sandbox/m4a_runner.py`
- Modify: `tests/fixtures/hostile_worker.py`
- Modify: `tests/conformance/test_m4a_integration.py`

**Interfaces:**
- Consumes: existing cgroup cancellation helpers and M4A test-only fault hooks.
- Produces: fail-closed stage outcomes and recursive cleanup evidence for every hostile process shape.

- [ ] **Step 1: Write failing descendant tests for child, grandchild, setsid, new process group, parent-exit descendant, double fork, rapid spawn, and signal-ignoring child.**

Each test combines an unavailable host endpoint or filesystem object with host-
side exact cgroup membership, then asserts termination, recursive empty evidence,
no attributable PID, and no active `aos-*` scope.

- [ ] **Step 2: Write failing startup-fault tests.**

Cover namespace command failure, malformed Bubblewrap policy, missing runtime
root, wrong executable identity, malformed/contradictory/missing JSON, namespace
mismatch, cgroup mismatch, early launcher marker, wrong mapping identity/type,
combined-digest mismatch, post-namespace Landlock failure, forged/missing `A`,
and failed worker exec after a valid `A`.

- [ ] **Step 3: Write controller-exception, cancellation, and parent-death tests.**

Inject exceptions before and after each gate. Confirm `--die-with-parent` kills
its direct command as defense in depth, then independently require the existing
cgroup cancellation result, recursive `populated=0`, and scope removal.

- [ ] **Step 4: Run lifecycle tests and verify RED.**

Run: `.venv/bin/python -m pytest tests/conformance/test_m4a_integration.py -k 'descendant or fault or cancellation or controller_exception or cleanup' -v`

- [ ] **Step 5: Implement missing bounded fault and cleanup paths without changing cgroup semantics.**

One `finally`/exception path owns gate closure, child termination, cgroup drain,
scope stop, source-FD closure, private-directory removal, and error promotion when
cleanup proof fails. Do not kill by process name or treat Bubblewrap exit as
recursive cleanup.

- [ ] **Step 6: Run lifecycle plus existing cgroup/Landlock suites GREEN.**

Run: `.venv/bin/python -m pytest tests/conformance/test_m4a_integration.py -k 'descendant or fault or cancellation or controller_exception or cleanup' -v`

Run: `.venv/bin/python -m pytest tests/conformance/test_cgroup_integration.py tests/conformance/test_native_landlock_integration.py -v`

- [ ] **Step 7: Commit composition and cleanup proof.**

```bash
git add src/agenticos/sandbox/m4a_runner.py tests/fixtures/hostile_worker.py tests/conformance/test_m4a_integration.py
git commit -m "security: prove M4A descendant and cleanup composition"
```

---

### Task 10: Normalize evidence and document the earned boundary

**Files:**
- Modify: `src/agenticos/sandbox/m4a_runner.py`
- Modify: `tests/conformance/test_m4a_unit.py`
- Modify: `tests/conformance/test_m4a_integration.py`
- Create: `docs/phase-zero/runtime-boundary.md`
- Create: `docs/roadmap.md`
- Modify: `docs/phase-zero/host-capabilities.md`
- Modify: `docs/phase-zero/filesystem-isolation.md`
- Modify: `docs/phase-zero/process-containment.md`
- Modify: `docs/phase-zero/sandbox-conformance.md`

**Interfaces:**
- Consumes: all verified M4A observations.
- Produces: normalized evidence with no secrets/host locators and the approved narrow claim/roadmap.

- [ ] **Step 1: Write failing evidence tests for required fields and forbidden content.**

```python
def test_m4a_evidence_has_required_digests_without_host_locator(m4a_run, layout):
    payload = m4a_run.event("RUNTIME_BOUNDARY_VERIFIED").payload
    assert payload["network_policy"] == "DENY"
    assert len(payload["filesystem_view_digest"]) == 64
    assert len(payload["environment_policy_digest"]) == 64
    assert str(layout.assigned_worktree) not in json.dumps(payload)
```

Require backend identity, six namespaces, cgroup, mapping/environment/network
digests, FD count, canary booleans, endpoint outcomes, capabilities, Landlock,
gate ordering, and recursive cleanup.

- [ ] **Step 2: Run evidence tests and verify RED.**

Run: `python -m pytest tests/conformance/test_m4a_unit.py tests/conformance/test_m4a_integration.py -k evidence -v`

- [ ] **Step 3: Emit normalized events and pass evidence tests GREEN.**

Record source roles/destinations/identities but never source locators, environment
values, socket canary contents, or real host usernames/home paths.

- [ ] **Step 4: Write runtime-boundary and roadmap documentation from measured results.**

`runtime-boundary.md` includes launch ordering, runtime tree, installation mode,
namespace/capability evidence, filesystem/credential/IPC/network matrices,
failure/cleanup proof, limitations, and the approved narrow claim. `roadmap.md`
starts with M4B, then the approved provider/worktree/evaluator sequence and both
authentication-ownership principles.

- [ ] **Step 5: Update existing phase-zero documents without rewriting prior evidence.**

Retain M2B/M3B standalone claims and add the M4A composition result. Windows
results remain regression-only and do not become a native Windows isolation
claim.

- [ ] **Step 6: Run docs/evidence checks and commit.**

Run: `git diff --check`

Run: `python -m pytest tests/conformance/test_m4a_unit.py tests/conformance/test_m4a_integration.py -k evidence -v`

```bash
git add src/agenticos/sandbox/m4a_runner.py tests/conformance/test_m4a_unit.py tests/conformance/test_m4a_integration.py docs/phase-zero docs/roadmap.md
git commit -m "docs: record M4A runtime boundary evidence"
```

---

### Task 11: Earn the final Linux and Windows checkpoint

**Files:**
- Verify all milestone files; modify only to correct defects exposed by verification.

**Interfaces:**
- Consumes: all M2B, M3B, and M4A code/tests/docs.
- Produces: repeatable Linux proof, Windows regression, clean synchronized repositories, pushed `main`, and exact final SHA.

- [ ] **Step 1: Inspect the complete milestone diff and scan for forbidden material.**

Run: `git diff dcf24fe4a50f82761dc6ab8eeb34ae9b33ecba88 --check`

Run: `git diff --stat dcf24fe4a50f82761dc6ab8eeb34ae9b33ecba88`

Run: `git grep -nE '(OPENAI_API_KEY|ANTHROPIC_API_KEY|BEGIN .*PRIVATE KEY)' -- ':!tests/**' ':!docs/**'`

Inspect every diff and confirm no credential value, native binary, temporary
runtime directory, socket, log, cache, or evidence artifact is tracked.

- [ ] **Step 2: Build the native launcher warning-clean.**

Run: `cc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 native/fs_launcher/fs_launcher.c -o native/fs_launcher/fs_launcher`

Confirm `.gitignore` excludes the binary and `git status --short` shows no build artifact.

- [ ] **Step 3: Run focused Linux suites serially.**

Run: `.venv/bin/python -m pytest tests/conformance/test_m4a_unit.py tests/conformance/test_m4a_integration.py -v`

Run: `.venv/bin/python -m pytest tests/conformance/test_native_landlock_unit.py tests/conformance/test_native_landlock_integration.py -v`

Run: `.venv/bin/python -m pytest tests/conformance/test_cgroup_integration.py -v`

- [ ] **Step 4: Run the full Linux suite three consecutive times.**

Run: `for i in 1 2 3; do .venv/bin/python -m pytest || exit 1; done`

Expected: all runnable tests pass each time; skips are only documented platform/capability skips.

- [ ] **Step 5: Audit cleanup after the repeated suite.**

Run: `systemctl --user list-units 'aos-*' --all --no-legend`

Run: `find /sys/fs/cgroup/user.slice -maxdepth 8 -type d -name 'aos-*' -print 2>/dev/null`

Expected: no active task unit, attributable process, populated task hierarchy, or private task directory remains.

- [ ] **Step 6: Synchronize the clean Windows checkout and run regression tests.**

Run on Windows: `python -m pytest`

Expected: all Windows-runnable tests pass; Linux containment/isolation tests skip for explicit platform reasons.

- [ ] **Step 7: Apply the verification-before-completion checklist, commit any verification-only correction, and push normally.**

```bash
git status --short
git log --oneline --decorate -12
git push origin main
git ls-remote origin main
```

Verify Windows HEAD, WSL HEAD, local `main`, and actual `origin/main` all equal
the reported final SHA and both working trees are clean. Never force push.
