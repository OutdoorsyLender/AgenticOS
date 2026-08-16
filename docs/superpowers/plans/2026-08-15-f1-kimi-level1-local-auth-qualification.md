# F1 Kimi Level-1 Local-Auth Qualification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove only `LOCAL_CREDENTIAL_LOADABLE` by sending `initialize` and `authenticate(methodId="login")` to the exact pinned official Kimi Code CLI 0.36.1 inside a route-less, read-only, metadata-bound security domain.

**Architecture:** Add a closed Level-1 ACP state machine, metadata-only O_PATH credential-leaf boundary, route-less Bubblewrap runtime with an exec-time FD/network guard, and one-shot controller evidence gate. Qualify every behavior against disjoint synthetic roots before one conditional real attempt; persist only typed results and never create a model session.

**Tech Stack:** Python 3.14, pytest, Bubblewrap 0.11.1, Linux O_PATH, cgroup v2/systemd user scopes, seccomp classic BPF through `ctypes`, ACP v1 JSON-RPC, native Windows Git, native Ubuntu WSL Git.

**Spec:** `docs/superpowers/specs/2026-08-15-f1-kimi-level1-local-auth-qualification-design.md`

## Global constraints

- Evidence ladder is immutable: Level 0 `CREDENTIAL_STRUCTURALLY_PRESENT`; Level 1 `LOCAL_CREDENTIAL_LOADABLE`; Level 2 `BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT`; Level 3 `OUT OF SCOPE`.
- The real runtime has `EXTERNAL_NETWORK_AUTHORITY=NONE`: no DNS, proxy, relay, provider hostname, default route, inherited network FD, telemetry endpoint, or Internet authority.
- The only ACP requests are `initialize(protocolVersion=1, clientCapabilities={})` and `authenticate(methodId="login")`, in that order.
- Never send `session/new`, `session/prompt`, a cancellation notification, a model request, or another session operation.
- AgenticOS may inspect credential ancestry, names, type, UID, mode, link count, device, and inode only. It never receives a readable credential descriptor or credential bytes.
- Bind only the descriptor-pinned `kimi-code.json` inode with Bubblewrap `--ro-bind-fd`; never bind the host credential directory.
- Remount the sandbox credential parent read-only and prove the mount descriptor is closed before the Kimi exec.
- Preserve executable SHA-256 `78c07b255e0bdc8dfe90d0cbd3204a3d862957394a08ca99c6e31144732451c7`, exact 0.36.1 bundle, immutable config/profile, `tools: []`, `subagents: []`, empty `/workspace`, and the cleared environment.
- Use exact finite `TasksMax=21`, `MemoryMax=1G`, `KillMode=control-group`, and `TimeoutStopSec=5s`; fail unless the fresh scope has `pids.current=1` and `pids.events max 0`.
- Real controller evidence lives at `/home/brand/.local/share/agenticos/controller-evidence/kimi-code/0.36.1/level1-local-auth`; it is never mounted into Kimi or `/workspace`.
- Synthetic roots must resolve outside the real provider-state and controller-evidence roots.
- Raw ACP/stdout/stderr bytes are bounded and transient. Persist only the four required fields, stable reason, and content-free census counts.
- No real attempt occurs until Tasks 1-7 are implemented, green, reviewed with zero unresolved Critical/Important findings, published, synchronized, and residue-clean.
- The three existing tests that require `.git` to be a directory run on canonical WSL `main`, never the linked worktree; do not weaken them for worktree compatibility.
- If pinned behavior attempts networking, credential mutation, session creation, inference, or provider/API-key fallback, classify `BLOCKED`, stop, and do not widen authority.
- No login, refresh, server validation, prompt, inference, F2, source-built auth helper, patched binary, TUI, `/usage`, or `/models` execution is authorized.

## File map

| File | Responsibility |
| --- | --- |
| `src/agenticos/providers/kimi_acp.py` | Shared strict ACP request encoding and initialize-result validation. |
| `src/agenticos/providers/kimi_local_auth.py` | Level-1 evidence types, exact two-request state machine, total classification. |
| `src/agenticos/providers/kimi_local_auth_runtime.py` | O_PATH handling, evidence, Bubblewrap argv, scope preflight, process lifecycle, censuses, CLI. |
| `src/agenticos/providers/kimi_local_auth_namespace.py` | In-sandbox inode/FD checks, IPv4/IPv6 seccomp, exact `kimi-code acp` exec. |
| `scripts/run_kimi_local_auth.py` | Fixed canonical-main entry point for the conditional real attempt. |
| `tests/providers/test_kimi_local_auth.py` | Pure protocol, classification, metadata, marker, argv, and fake-process tests. |
| `tests/providers/test_kimi_local_auth_linux.py` | Native Bubblewrap, seccomp, cgroup, pinned-client, census, and residue tests. |
| `tests/providers/fixtures/kimi_local_auth_fixture.py` | Hostile synthetic ACP executable. |
| `docs/phase-zero/first-autonomous-build-slice-f1-kimi-local-auth-pre-real.md` | Source, synthetic, regression, review, and pre-real evidence. |
| `docs/phase-zero/first-autonomous-build-slice-f1-kimi-local-auth-closure.md` | Conditional real result and sixteen-section closure. |

## Synthetic qualification matrix

Every row is mandatory before the real marker may be claimed.

| ID | Scenario | Required oracle |
| --- | --- | --- |
| `LA-P01` | Initialize request | Exact ID 1, method, protocol 1, and empty capabilities. |
| `LA-P02` | Initialize success only | Pinned identity/auth-method accepted; qualification remains blocked. |
| `LA-P03` | Authenticate request | Exact ID 2 and only `authenticate` with `methodId=login`. |
| `LA-P04` | Authenticate success | `null` or exact `{}` maps to `LOADABLE`, `LOCAL_ONLY`, Level 2 blocked. |
| `LA-P05` | Authenticate rejection | Exact error `-32000` maps to `REJECTED`; qualification blocked. |
| `LA-P06` | Wrong method | Production cannot encode another method; hostile input is rejected. |
| `LA-P07` | Malformed ACP | Invalid UTF-8/JSON/RPC, duplicate keys, truncation, excess bytes block. |
| `LA-P08` | Ordering/correlation | Wrong ID/order, duplicate terminal, callback, or extra frame blocks. |
| `LA-P09` | Forbidden session surface | No session, prompt, cancel, or model operation exists in request census. |
| `LA-P10` | Non-promotion | Every outcome fixes local-only auth and blocked Level 2. |
| `LA-C01` | Missing synthetic credential | Pinned client returns auth-required; no network/write/session artifact. |
| `LA-C02` | Valid synthetic credential | Pinned client succeeds under one read-only leaf mount. |
| `LA-C03` | Malformed JSON | Pinned client rejects; bytes remain unchanged. |
| `LA-C04` | Expired token | Nonempty access token succeeds locally, proving no freshness claim. |
| `LA-C05` | Revoked tombstone | Empty-token tombstone rejects and remains unchanged. |
| `LA-C06` | Unknown/temp entry | Validator blocks before launch. |
| `LA-C07` | Symlink/nonregular leaf | Validator blocks before launch. |
| `LA-C08` | Hard link | Link count other than one blocks. |
| `LA-C09` | Wrong UID/mode | Non-owner or mode other than `0600` blocks. |
| `LA-C10` | O_PATH unreadability | `os.read(fd, 1)` fails `EBADF`. |
| `LA-C11` | Path-swap race | Mounted device/inode remains the opened identity. |
| `LA-C12` | Mount scope | One leaf only; sibling/temp writes fail read-only. |
| `LA-C13` | FD lifetime | Trusted launcher sees no FD above 2 before exec. |
| `LA-N01` | Namespace layout | No route, resolver, proxy, relay, listener, socket FD, or external interface. |
| `LA-N02` | IPv4 attempt | `socket(AF_INET)` traps with SIGSYS and typed network failure. |
| `LA-N03` | IPv6 attempt | `socket(AF_INET6)` traps with SIGSYS and typed network failure. |
| `LA-N04` | Provider/API fallback | Empty API key, cleared env, and network trap prevent fallback. |
| `LA-R01` | Timeout | 30-second deadline kills/drains process group; blocked. |
| `LA-R02` | Crash | Nonzero/SIGSYS/unexpected exit gets typed reason and drain. |
| `LA-R03` | Output bounds | More than 4 frames, 65,536 bytes/frame, or 65,536 stderr bytes blocks. |
| `LA-R04` | Raw retention | Canaries never reach result, marker, evidence, exception, or report. |
| `LA-R05` | Process/env/FD census | Exact executable/argv/env; no Kimi child, hostile FD, or external socket. |
| `LA-R06` | Session residue | Live metadata census finds no session/history/model artifact. |
| `LA-R07` | Cleanup | Zero process, scope, cgroup, listener, socket, and synthetic residue. |
| `LA-E01` | One-shot claim | First O_EXCL succeeds; existing/symlink/malformed/second claim blocks. |
| `LA-E02` | Marker isolation | Evidence root is outside every Kimi/workspace mount. |
| `LA-E03` | Typed result | Only schema, identities, four fields, reason, and census counts persist. |
| `LA-E04` | Synthetic crossover | Roots equal to/inside/resolving through real roots block. |
| `LA-G01` | Full gate | Matrix, regressions, review, publication, sync, and residue all pass. |

## Preservation gate after every task

Each task is one implementation slice. After its tests and review pass, commit in the isolated WSL worktree, fast-forward canonical WSL `main`, rerun the task tests on canonical main, push once, verify live GitHub with `git ls-remote`, and fast-forward native Windows. If the single WSL push fails at the known credential helper, stop edits and use the approved exact-SHA bundle procedure without retrying.

Stable output requires Windows HEAD, WSL HEAD, both fetched `origin/main` refs, and live GitHub main at one SHA; both main trees clean at `0/0`; zero stashes; and no unexplained runtime residue. Only then begin the next task.

### Task 1: Closed Level-1 ACP protocol and evidence ladder

**Files:**
- Modify: `src/agenticos/providers/kimi_acp.py:49-176`
- Create: `src/agenticos/providers/kimi_local_auth.py`
- Create: `tests/providers/test_kimi_local_auth.py`
- Modify: `tests/providers/test_kimi_acp.py:151-255`

**Interfaces:**
- Produces `encode_acp_request(method: str, request_id: int, params: dict[str, object]) -> bytes`.
- Produces `validate_kimi_initialize_result(result: object) -> dict[str, object]`.
- Produces `KimiLocalAuthError`, `QualificationState`, `LocalCredentialState`, `LocalAuthProtocolOutcome`, and `KimiLocalAuthSession`.
- Consumes `decode_acp_line()` and the current pinned identity/auth-method checks.

- [ ] **Step 1: Write protocol tests LA-P01 through LA-P10**

```python
def test_exact_two_request_surface_and_no_level2_promotion() -> None:
    session = KimiLocalAuthSession()
    assert json.loads(session.initialize_request()) == {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": 1, "clientCapabilities": {}},
    }
    session.accept(INITIALIZE_SUCCESS)
    assert json.loads(session.authenticate_request()) == {
        "jsonrpc": "2.0", "id": 2, "method": "authenticate",
        "params": {"methodId": "login"},
    }
    session.accept(b'{"jsonrpc":"2.0","id":2,"result":null}\n')
    outcome = session.finish()
    assert outcome.credential_state is LocalCredentialState.LOADABLE
    assert outcome.auth_state == "LOCAL_ONLY"
    assert outcome.level2_status == "BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT"
```

Add exact tests for `result: {}`, `error.code == -32000`, wrong IDs, duplicate terminals, callbacks, malformed/oversized frames, wrong method construction, and initialize-only incompleteness.

- [ ] **Step 2: Run the new tests and verify RED**

Run: `python3 -m pytest -q tests/providers/test_kimi_local_auth.py tests/providers/test_kimi_acp.py`

Expected: import/attribute failures for the new interfaces; existing passive ACP tests remain collectible.

- [ ] **Step 3: Extract shared strict ACP helpers**

```python
def encode_acp_request(method: str, request_id: int, params: dict[str, object]) -> bytes:
    if type(method) is not str or type(request_id) is not int or type(params) is not dict:
        raise KimiAcpError("OUTBOUND_REQUEST_SHAPE")
    return _encode({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
```

Move the exact current `protocolVersion`, `agentInfo`, `authMethods`, terminal-auth, and `agentCapabilities` validation into `validate_kimi_initialize_result()`. Keep every current error code. Make `KimiAcpSession._accept_initialize()` call it so passive semantics do not change.

- [ ] **Step 4: Implement the Level-1-only state machine**

```python
class KimiLocalAuthError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

class LocalCredentialState(str, Enum):
    LOADABLE = "LOADABLE"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"

class QualificationState(str, Enum):
    COMPLETE = "COMPLETE"
    BLOCKED = "BLOCKED"

@dataclass(frozen=True, slots=True)
class LocalAuthProtocolOutcome:
    qualification: QualificationState
    credential_state: LocalCredentialState
    auth_state: str = "LOCAL_ONLY"
    level2_status: str = "BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT"
    reason_code: str = "ACP_LOCAL_AUTH_SUCCESS"
```

Expose only `initialize_request()`, `authenticate_request()`, `accept()`, and `finish()`. Accept success bodies `None` or `{}`; map only exact `-32000` to `REJECTED`; every other error/ambiguity raises `KimiLocalAuthError` for runner mapping to `BLOCKED`.

- [ ] **Step 5: Run protocol and passive tests and verify GREEN**

Run: `python3 -m pytest -q tests/providers/test_kimi_local_auth.py tests/providers/test_kimi_acp.py`

Expected: all pass; source scan finds no session request, prompt, hostname, proxy, API key, refresh, or model operation in the new module.

- [ ] **Step 6: Review, inspect, commit, and preserve**

Review outbound bytes, total classification, passive compatibility, and Level-2 non-promotion. Commit `feat: add Kimi Level-1 ACP state machine`, then run the preservation gate.

### Task 2: Metadata-only credential leaf and controller evidence

**Files:**
- Create: `src/agenticos/providers/kimi_local_auth_runtime.py`
- Modify: `tests/providers/test_kimi_local_auth.py`

**Interfaces:**
- Produces `KimiLocalAuthRuntimeError`, `CredentialLeafHandle`, `open_validated_credential_leaf()`, and `close()`.
- Produces `claim_real_attempt(evidence_root: Path, *, candidate_commit: str, expected_uid: int) -> None`.
- Produces `persist_typed_result(evidence_root: Path, protocol: LocalAuthProtocolOutcome, census_counts: Mapping[str, int | bool], *, candidate_commit: str, expected_uid: int) -> None`.
- Consumes `validate_future_credential_directory()` and `PINNED_EXECUTABLE_SHA256`.

- [ ] **Step 1: Write LA-C06 through LA-C11 and LA-E01 through LA-E04 tests**

```python
def test_validated_leaf_is_opath_not_read_authority(tmp_path: Path) -> None:
    state_root = make_structurally_valid_synthetic_state(tmp_path)
    handle = open_validated_credential_leaf(
        state_root, trusted_state_root=state_root, expected_uid=os.getuid()
    )
    try:
        with pytest.raises(OSError) as rejected:
            os.read(handle.descriptor, 1)
        assert rejected.value.errno == errno.EBADF
        leaf = (state_root / "credentials" / "kimi-code.json").lstat()
        assert (handle.device, handle.inode) == (leaf.st_dev, leaf.st_ino)
    finally:
        handle.close()
```

Add table cases for name, unknown/temp sibling, symlink, directory/FIFO, mode, UID, link count, ancestry, path replacement after open, real/synthetic crossover, marker symlink/malformed/second claim, and result field allowlisting.

- [ ] **Step 2: Run selected tests and verify RED**

Run: `python3 -m pytest -q tests/providers/test_kimi_local_auth.py -k 'credential or opath or marker or evidence or crossover'`

Expected: missing runtime interfaces.

- [ ] **Step 3: Implement strict O_PATH leaf acquisition**

```python
class KimiLocalAuthRuntimeError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
descriptor = os.open(credential_root / "kimi-code.json", flags)
opened = os.fstat(descriptor)
lexical = (credential_root / "kimi-code.json").lstat()
if (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino):
    os.close(descriptor)
    raise KimiLocalAuthRuntimeError("CREDENTIAL_INODE_CHANGED")
```

Require Linux `os.O_PATH` with no readable fallback. Return only descriptor plus device, inode, UID, mode, and link count. Exclude path/size from `repr`, typed result, and evidence.

- [ ] **Step 4: Implement immutable claim and separate typed result**

```python
claim = {
    "schema": "AOS_KIMI_LEVEL1_ATTEMPT/1",
    "attempt": 1,
    "candidate_commit": candidate_commit,
    "pinned_executable_sha256": PINNED_EXECUTABLE_SHA256,
    "lifecycle": "CLAIMED_BEFORE_LAUNCH",
}
fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
```

Write canonical JSON, fsync file and parent, close, and never modify/delete it. Persist result to a different O_EXCL file containing only allowed typed fields. Validate private UID-owned non-symlink ancestry and exact modes.

- [ ] **Step 5: Run selected tests and verify GREEN**

Run: `python3 -m pytest -q tests/providers/test_kimi_local_auth.py -k 'credential or opath or marker or evidence or crossover'`

Expected: all pass, including byte-preserved synthetic fixtures and no content reads in production code.

- [ ] **Step 6: Review, inspect, commit, and preserve**

Review TOCTOU, descriptor cleanup, O_EXCL durability, root disjointness, and evidence fields. Commit `feat: bind Kimi credential metadata and attempt evidence`, then run the preservation gate.

### Task 3: Route-less read-only Bubblewrap and exec guard

**Files:**
- Create: `src/agenticos/providers/kimi_local_auth_namespace.py`
- Modify: `src/agenticos/providers/kimi_local_auth_runtime.py`
- Modify: `tests/providers/test_kimi_local_auth.py`
- Create: `tests/providers/test_kimi_local_auth_linux.py`

**Interfaces:**
- Produces `KimiLocalAuthSpec`, `default_local_auth_spec()`, and `build_local_auth_bwrap_argv()`.
- Produces `assert_mount_identity()`, `assert_no_inherited_descriptors()`, `install_no_inet_seccomp()`, and `exec_official_acp()`.
- Consumes `CredentialLeafHandle`, pinned runtime/bundle checks, and `build_kimi_environment()`.

- [ ] **Step 1: Write LA-C12, LA-C13, and LA-N01 through LA-N04 tests**

Assert one `--ro-bind-fd` leaf, no host credential path, `--remount-ro` parent, no `/etc`, no proxy, `--unshare-net`, empty workspace, and launcher arguments containing only device/inode metadata.

- [ ] **Step 2: Run selected tests and verify RED**

Run: `python3 -m pytest -q tests/providers/test_kimi_local_auth.py tests/providers/test_kimi_local_auth_linux.py -k 'argv or mount or descriptor or seccomp or network'`

Expected: missing spec, launcher, and seccomp interfaces.

- [ ] **Step 3: Build the single-leaf vector**

```python
@dataclass(frozen=True, slots=True)
class KimiLocalAuthSpec:
    executable: Path
    bundle: Path
    namespace_launcher: Path
    state_root: Path
    evidence_root: Path
```

```python
argv.extend((
    "--dir", "/home/aos/kimi/credentials",
    "--ro-bind-fd", str(credential.descriptor),
    "/home/aos/kimi/credentials/kimi-code.json",
    "--remount-ro", "/home/aos/kimi/credentials",
))
```

Reuse pinned executable/config/agents, qualified namespaces, clear environment, and tmpfs home/tmp/workspace. Bind the trusted launcher read-only. Pass no resolver, proxy, relay, socket, checkout, controller/evidence root, or host state directory.

- [ ] **Step 4: Implement inode/FD checks and IPv4/IPv6 socket trap**

Launcher validates sandbox leaf device/inode, mode `0600`, and link count one; probes FDs 3 through the soft `RLIMIT_NOFILE` cap with `fcntl(F_GETFD)`; installs `PR_SET_NO_NEW_PRIVS`; installs this x86-64 seccomp policy:

```text
load arch; if arch != AUDIT_ARCH_X86_64 -> KILL_PROCESS
load syscall; if syscall != socket -> ALLOW
load socket domain; if AF_INET or AF_INET6 -> TRAP
ALLOW
```

Then exec `/opt/agenticos/kimi/bin/kimi` with argv `['kimi-code', 'acp']` and exact `build_kimi_environment()`.

- [ ] **Step 5: Prove native kernel boundary and passive regressions**

Run:

```bash
python3 -m pytest -q tests/providers/test_kimi_local_auth_linux.py -k 'mount or descriptor or seccomp or network'
python3 -m pytest -q tests/providers/test_kimi_runtime.py tests/providers/test_kimi_runtime_linux.py tests/providers/test_kimi_policy.py
```

Expected: inode identity, sibling-write denial, FDs 0/1/2 only, SIGSYS for inet probes, no external socket/listener, and unchanged passive behavior.

- [ ] **Step 6: Review, inspect, commit, and preserve**

Review BPF jumps, architecture gate, FD scan, bind ordering, read-only remount, exact exec/env, and zero network authority. Commit `feat: isolate Kimi local auth runtime`, then run the preservation gate.

### Task 4: Bounded runner, cgroup preflight, census, and CLI

**Files:**
- Modify: `src/agenticos/providers/kimi_local_auth_runtime.py`
- Create: `scripts/run_kimi_local_auth.py`
- Modify: `tests/providers/test_kimi_local_auth.py`
- Modify: `tests/providers/test_kimi_local_auth_linux.py`

**Interfaces:**
- Produces `LocalAuthCensus`, `LocalAuthRunOutcome`, `run_local_auth()`, `validate_local_auth_scope()`, `local_auth_systemd_command()`, and `cli_main()`.
- Consumes `KimiLocalAuthSession`, credential handle, evidence writers, repository identity validation, and process-group drain behavior.

- [ ] **Step 1: Write LA-R01 through LA-R07 fake-process/scope/CLI tests**

Cover success, `-32000`, wrong response, timeout, crash, SIGSYS, stdout/stderr overflow, stuck reader, extra callback, descendant residue, evidence failure, and bomb functions proving scope/repository/runtime/gate checks precede marker/credential launch.

- [ ] **Step 2: Run selected tests and verify RED**

Run: `python3 -m pytest -q tests/providers/test_kimi_local_auth.py -k 'runner or timeout or crash or overflow or scope or cli or cleanup or census'`

Expected: missing runner and CLI interfaces.

- [ ] **Step 3: Implement exact finite scope admission**

```python
QUALIFIED_LOCAL_AUTH_TASKS_MAX: Final = 21
LOCAL_AUTH_MEMORY_MAX_BYTES: Final = 1_073_741_824
LOCAL_AUTH_TIMEOUT_SECONDS: Final = 30.0
LOCAL_AUTH_MAX_FRAMES: Final = 4
```

Require scope suffix `/aos-kimi-level1-local-auth.scope`, `pids.max=21`, `pids.current=1`, `pids.events max 0`, and `memory.max=1073741824`. Systemd vector uses `--user --scope --collect --quiet`, exact unit, control-group kill, five-second stop timeout, and canonical script.

- [ ] **Step 4: Implement bounded ACP/stderr processing**

Launch with `env={}`, `close_fds=True`, only credential FD passed, and a new process group. Close parent FD after `Popen`. Send two requests only. Bound 4 frames, 65,536 bytes/frame, 65,536 stderr bytes, and non-resetting 30 seconds. Close stdin after auth, sample final metadata while alive, then terminate/drain.

- [ ] **Step 5: Implement content-free census**

```python
@dataclass(frozen=True, slots=True)
class LocalAuthCensus:
    process_count: int
    descendant_count: int
    environment_names: tuple[str, ...]
    fd_classes: tuple[str, ...]
    network_namespace: str
    external_endpoint_count: int
    session_artifact_count: int
    cleanup_complete: bool

@dataclass(frozen=True, slots=True)
class LocalAuthRunOutcome:
    protocol: LocalAuthProtocolOutcome
    census: LocalAuthCensus
    reason_code: str
```

Store counts, booleans, namespace IDs, environment names, classified FD kinds, exact executable/argv verdict, and stable codes only. Persist no `/proc` raw text/path target. Monitor error, child, inet socket, external endpoint, session/model artifact, or cleanup uncertainty maps to `BLOCKED`.

- [ ] **Step 6: Implement fail-closed CLI order**

```text
parse expected commit -> validate scope/cgroup -> validate published main
-> validate pin/config/profile -> validate pre-real gate
-> validate/open credential O_PATH -> claim marker -> launch once
-> persist typed result once -> print typed fields only
```

Script verifies its canonical path. No flag selects command, path, network mode, credential/evidence root, retry, or model operation.

- [ ] **Step 7: Run selected tests and verify GREEN**

Run: `python3 -m pytest -q tests/providers/test_kimi_local_auth.py tests/providers/test_kimi_local_auth_linux.py -k 'runner or timeout or crash or overflow or scope or cli or cleanup or census'`

Expected: all pass and every failure drains without second launch.

- [ ] **Step 8: Review, inspect, commit, and preserve**

Review ordering, one-shot placement, reader races, signal mapping, result allowlist, cgroup escape, and cleanup uncertainty. Commit `feat: run Kimi local auth once with bounded evidence`, then run the preservation gate.

### Task 5: Hostile synthetic ACP and policy-violation fixture

**Files:**
- Create: `tests/providers/fixtures/kimi_local_auth_fixture.py`
- Modify: `tests/providers/test_kimi_local_auth.py`
- Modify: `tests/providers/test_kimi_local_auth_linux.py`

**Interfaces:**
- Produces modes `success-null`, `success-empty`, `reject`, `malformed`, `duplicate`, `wrong-id`, `callback`, `timeout`, `crash`, `network-v4`, `network-v6`, `credential-write`, and `residual-child`.
- Consumes the production mount/launcher boundary through a test-only executable substitution that rejects the real state root.
- Produces test helper `build_synthetic_fixture_argv(mode: str, synthetic_root: Path) -> list[str]`; production modules do not export it.

- [ ] **Step 1: Write fixture safety and hostile-mode tests**

Require a fixed mode enum, synthetic root under pytest temp, exact canaries, no real provider-state/evidence reference, and one bounded JSON report. Prove `default_local_auth_spec()` cannot select the fixture executable.

- [ ] **Step 2: Run fixture tests and verify RED**

Run: `python3 -m pytest -q tests/providers/test_kimi_local_auth.py tests/providers/test_kimi_local_auth_linux.py -k 'fixture or malformed or duplicate or callback or network or credential_write or residual'`

Expected: missing fixture/modes.

- [ ] **Step 3: Implement deterministic hostile modes**

The fixture reads synthetic credential content only. It emits exact ACP frames for protocol modes, sleeps beyond injected timeout, exits nonzero for crash, calls IPv4/IPv6 socket creation, tries target and sibling writes, and forks one bounded child for drain qualification. Replace synthetic canaries with `<synthetic-canary-redacted>` before emitting its report.

- [ ] **Step 4: Prove every hostile behavior blocks and drains**

Run: `python3 -m pytest -q tests/providers/test_kimi_local_auth.py tests/providers/test_kimi_local_auth_linux.py -k 'fixture or malformed or duplicate or callback or network or credential_write or residual'`

Expected: ambiguity blocks; network traps; writes cannot alter leaf/create sibling; descendants drain; canaries never persist.

- [ ] **Step 5: Review, inspect, commit, and preserve**

Review fixture/production crossover, canary handling, test-only executable selection, and false-success paths. Commit `test: qualify hostile Kimi local auth behavior`, then run the preservation gate.

### Task 6: Exact pinned-client synthetic credential matrix

**Files:**
- Modify: `tests/providers/test_kimi_local_auth_linux.py`
- Modify: `tests/providers/fixtures/kimi_local_auth_fixture.py`
- Modify: `src/agenticos/providers/kimi_local_auth_runtime.py` only for a narrower observed local rejection code backed by a new failing test

**Interfaces:**
- Consumes exact pinned Kimi 0.36.1, production read-only leaf mount, production state machine, and disjoint synthetic roots.
- Produces executable evidence for LA-C01 through LA-C05, LA-R05 through LA-R07, and task peak below 21.
- Produces test helper `run_pinned_synthetic_state(state: str) -> tuple[LocalAuthRunOutcome, bytes, bytes]`, confined to synthetic files.

- [ ] **Step 1: Write exact pinned synthetic-state tests**

```python
@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ("valid", LocalCredentialState.LOADABLE),
        ("expired-nonempty-access", LocalCredentialState.LOADABLE),
        ("malformed-json", LocalCredentialState.REJECTED),
        ("revoked-tombstone", LocalCredentialState.REJECTED),
    ],
)
def test_exact_pinned_client_classifies_synthetic_state(state: str, expected: LocalCredentialState) -> None:
    outcome, before_bytes, after_bytes = run_pinned_synthetic_state(state)
    assert outcome.credential_state is expected
    assert before_bytes == after_bytes
    assert outcome.auth_state == "LOCAL_ONLY"
    assert outcome.level2_status == "BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT"
```

Add empty-directory no-credential case. Every case snapshots synthetic bytes, censuses process/env/FD/network/session metadata, and proves zero external endpoint/residue.

- [ ] **Step 2: Run exact pinned tests and verify RED or fail-closed mismatch**

Run: `python3 -m pytest -q tests/providers/test_kimi_local_auth_linux.py -k 'exact_pinned or synthetic_state or no_credential'`

Expected from pinned source: valid and expired-nonempty succeed locally; malformed, tombstone, and missing reject with `-32000`. Network, write requirement, session artifact, or ambiguous response is a stop condition.

- [ ] **Step 3: Permit only narrow observed classifier corrections**

Allowed: map an exact content-free pinned local error shape to `REJECTED` after a failing test. Forbidden: DNS, proxy, relay, writable credential state, session/prompt, API key, endpoint, refresh, or broader success shape.

- [ ] **Step 4: Run complete synthetic and passive matrices**

```bash
python3 -m pytest -q tests/providers/test_kimi_local_auth.py tests/providers/test_kimi_local_auth_linux.py
python3 -m pytest -q tests/providers/test_kimi_runtime.py tests/providers/test_kimi_runtime_linux.py tests/providers/test_kimi_policy.py
```

Expected: every matrix row through LA-E04 passes; peak stays below 21; deliberate pressure is denied at 21; scopes/cgroups/processes/listeners drain.

- [ ] **Step 5: Review, inspect, commit, and preserve**

Review source agreement, expired semantics, read-only success, mutation snapshots, session absence, task ceiling, and non-promotion. Commit `test: qualify pinned Kimi local credential loading`, then run the preservation gate.

### Task 7: Adversarial review, regressions, and published pre-real gate

**Files:**
- Create: `docs/phase-zero/first-autonomous-build-slice-f1-kimi-local-auth-pre-real.md`
- Modify implementation/tests only for findings resolved through a fresh failing test

**Interfaces:**
- Produces content-free `PRE_REAL_GATE=GO` bound to source paths, matrix, regressions, review, and published candidate.
- Consumes all matrix tests and repository/runtime preservation rules.

- [ ] **Step 1: Perform adversarial review**

Review Level labeling, hidden network authority, seccomp bypass, inherited sockets, refresh/save reachability, readable descriptors, inode substitution, mutation, raw persistence, session/model operations, API fallback, crossover, one-shot races, marker visibility, output races, cgroup escape, and residue. Every Critical/Important finding gets a failing test and narrow fix.

- [ ] **Step 2: Run required focused regressions on published canonical WSL main**

Start from the synchronized Task 6 commit in `~/src/AgenticOS`. This avoids the known linked-worktree `.git` shape without changing tests.

```bash
python3 -m pytest -q tests/providers/test_kimi_local_auth.py tests/providers/test_kimi_local_auth_linux.py
python3 -m pytest -q tests/providers/test_kimi_acp.py tests/providers/test_kimi_acp_linux.py
python3 -m pytest -q tests/providers/test_kimi_runtime.py tests/providers/test_kimi_runtime_linux.py tests/providers/test_kimi_policy.py
python3 -m pytest -q tests/providers/test_kimi_login.py tests/providers/test_kimi_login_linux.py tests/providers/test_kimi_fixture_safety.py
python3 -m pytest -q tests/orchestration/test_demo0_linux.py tests/orchestration/test_workspace_lease.py
python3 -m pytest -q tests/conformance/test_provider_auth_kernel_boundary.py tests/conformance/test_provider_auth_process_boundary.py
python3 -m pytest -q tests/conformance/test_m4a_unit.py tests/conformance/test_m4a_split_phase.py tests/conformance/test_m4a_integration.py
python3 -m pytest -q tests/test_worktree.py tests/test_worktree_checkpoint.py tests/test_worktree_sandbox.py
```

- [ ] **Step 3: Run full verification and scans on the same canonical commit**

```bash
python3 -m pytest -q
python3 -m compileall -q src tests scripts
git diff --check
grep -RInE 'sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|Bearer[[:space:]]+[A-Za-z0-9._~-]{20,}' src tests scripts docs qualification
```

Secret scan must find no real secret. Synthetic canaries stay in fixture/test files and never appear in runtime output/evidence/docs.

- [ ] **Step 4: Prove pre-real state without credential content access**

Verify runtime/bundle/Bubblewrap identities, metadata-only `PRESENT`, clean published main, live GitHub equality, 0/0, zero stashes, zero Kimi processes/units/cgroups/sockets/listeners, and absent real marker. Never open/hash/copy/parse/print credential content.

- [ ] **Step 5: Write pre-real checkpoint**

Record exact source paths `packages/acp-server/src/server.ts`, `packages/agent-core-v2/src/app/auth/authService.ts`, `packages/oauth/src/oauth-manager.ts`, and `packages/oauth/src/storage.ts`; exact sequence; matrix/test results; review findings; fixed Level 2; and:

```text
F1_KIMI_LEVEL1_PRE_REAL_GATE=GO
UNRESOLVED_CRITICAL=0
UNRESOLVED_IMPORTANT=0
REAL_ATTEMPT_COUNT=0
REAL_LOGIN_EXECUTED=NO
REAL_PROMPT_EXECUTED=NO
REAL_INFERENCE_EXECUTED=NO
```

- [ ] **Step 6: Commit, publish, synchronize, and rerun final gate**

Commit `qualify Kimi Level-1 local auth pre-real gate`. Run preservation, then rerun local-auth suites, full WSL suite, compileall, diff check, scan, and residue census on exact published canonical main. Do not claim marker or launch Kimi.

### Task 8: At-most-one real Level-1 attempt and closure

**Files:**
- Create: `docs/phase-zero/first-autonomous-build-slice-f1-kimi-local-auth-closure.md`
- Do not modify runtime code after claiming the real-attempt marker

**Interfaces:**
- Consumes exact published Task 7 commit, real structurally present credential, systemd vector, immutable marker, and typed result writer.
- Produces four final fields, sixteen evidence sections, published closure, and hard stop.

- [ ] **Step 1: Reverify exact pre-real gate immediately before launch**

Verify Windows/WSL/origin/live GitHub at Task 7 SHA; clean 0/0; zero stashes/residue; marker absent; credential metadata `PRESENT`; pinned identities unchanged. Mismatch blocks before marker.

- [ ] **Step 2: Materialize and inspect exact command**

`local_auth_systemd_command(candidate_commit)` must contain exact unit, TasksMax 21, MemoryMax 1G, control-group kill, five-second stop timeout, canonical script, and exact commit. It contains no shell, retry, redirect, tee, proxy, hostname, credential path, or model argument.

- [ ] **Step 3: Execute once**

Run the inspected vector once. CLI claims marker before launch. Never rerun regardless of exit, timeout, ambiguity, output, or persistence failure. Capture typed bounded lines only.

- [ ] **Step 4: Apply total classification**

```text
success -> QUALIFICATION=COMPLETE, CREDENTIAL_STATE=LOADABLE
exact -32000 -> QUALIFICATION=BLOCKED, CREDENTIAL_STATE=REJECTED
other -> QUALIFICATION=BLOCKED, CREDENTIAL_STATE=BLOCKED
AUTH_STATE=LOCAL_ONLY always
LEVEL2=BLOCKED_NO_SAFE_QUALIFIED_OFFICIAL_ENTRYPOINT always
```

Never delete/rewrite/refresh/repair/retry credential state.

- [ ] **Step 5: Run immediate post-attempt censuses**

Prove zero Kimi process, provider scope/cgroup/socket/listener, inherited FD, session/model artifact, crossover, and unexplained file. Validate credential metadata remains `PRESENT`. Preserve claim/result as explained controller evidence.

- [ ] **Step 6: Write sixteen-section closure**

Include four fields then repository proof; pinned source; sequence; zero network; credential inaccessibility; synthetic evidence; one real result; ACP classification; Level distinction; censuses; no session/prompt/inference; tests; review; final commit; sync/residue; next architectural decision.

- [ ] **Step 7: Verify and publish closure-only commit**

Run local-auth tests, regressions, full WSL pytest, compileall, scan, diff check, and residue. Commit `close Kimi Level-1 local auth qualification`, push exact tested SHA, verify GitHub, synchronize clones, and prove clean 0/0 with zero stashes/unexplained residue.

- [ ] **Step 8: Return final report and hard stop**

Return exact fields and sixteen items. Do not login, validate server auth, prompt, infer, begin F2, or choose Level-2 workaround.
