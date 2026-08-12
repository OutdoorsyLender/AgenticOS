# M6 Slice 2C.1 Auth Domain Kernel Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Earn the Linux-host `AUTH_SECRET_ISOLATED_FROM_CODEX_DOMAIN` Level A claim with real Landlock, descriptor, process-surface, authenticated IPC, capability-binding, reverse-boundary, and canary evidence while retaining the trusted-controller residual.

**Architecture:** The trusted controller launches an identity-bound, standalone Python auth-helper entrypoint over one inherited Linux `AF_UNIX SOCK_SEQPACKET` endpoint. The helper hardens itself, verifies an identity-bound auth root, installs Landlock before reading `auth.json`, and returns only bounded task/provider/upstream capabilities; the existing M4A-derived sandbox supplies the reverse Codex boundary. Windows retains bounded functional compatibility but earns no kernel-isolation claim.

**Tech Stack:** Python 3.14 stdlib, pytest 8.4, Linux 6.6 WSL2, Landlock ABI 3, `openat2`, `close_range`, `prctl`, AF_UNIX `SOCK_SEQPACKET`, `SO_PEERCRED`, `SO_PASSCRED`/`SCM_CREDENTIALS`, existing bubblewrap 0.11.1 and M4A native launcher.

## Global Constraints

- Preserve these distinct review identities throughout implementation and closure:

  ```text
  DESIGN_SHA=43196fca78a92d819aa1b3f117f964ecdd1659ea
  PLAN_SHA=72dedf962c20acbdddb4ec3930ab67f2daef8380
  IMPLEMENTATION_BASE_SHA=72dedf962c20acbdddb4ec3930ab67f2daef8380
  ```

- Begin implementation history from `IMPLEMENTATION_BASE_SHA`, with Windows, WSL, `origin/main`, and GitHub SHA-identical and clean. The subsequent amended-plan publication commit is documentation-only; Task 8 still compares the owner-designated implementation base with the candidate.
- Author Linux security changes only in `/home/brand/src/AgenticOS`; synchronize `C:\AgenticOS` only through verified GitHub fast-forward operations.
- Do not install native Codex, use a real OpenAI/ChatGPT credential, contact a live provider endpoint, or consume provider quota.
- Target only `M6_SLICE2C1_STATUS=EARNED_LEVEL_A`; never claim whole-system Level B while the trusted same-UID controller can read persistent auth state.
- Linux is the only kernel-isolation qualification. Windows is protocol and functional regression only.
- Require Landlock ABI >= 3 and the already-qualified `openat2()` resolution mechanism; absence or failure is fail-closed.
- READY must follow core-disable, non-dumpability, FD sanitation, `NO_NEW_PRIVS`, Landlock enforcement, constrained auth loading, identity verification, and replay-state initialization.
- Linux IPC limits are exactly 16,384 request bytes, 16,384 response bytes, one endpoint, one in-flight request, 2.0-second request/response timeouts, 4,096 messages/helper, 4,096 replay entries, and eight capability issuances/attempt.
- Refresh-secret visibility outside the approved fixture-provisioning/auth-helper domain must remain zero.
- Every behavior change follows red-green-refactor. Run each named test first and confirm the expected failure before production edits.
- At every task boundary: inspect the diff, run `git diff --check`, commit, publish the exact SHA, verify GitHub with `git ls-remote`, fast-forward the Windows clone, and verify both clones clean/SHA-identical before the next task.
- When a task changes cross-platform code, create the WSL candidate commit only after its Linux checks, transfer/fetch that exact SHA into Windows, qualify it in an explicitly owned disposable Windows test worktree, and push only after the targeted Windows check passes. A Windows failure blocks publication and is fixed in WSL before a replacement candidate is tested.
- Never use `git clean`, `git checkout -- .`, `git restore .`, `git reset --hard`, rebase shared `main`, force push, or delete unexplained files.

## Planned file structure

- Modify `src/agenticos/sandbox/provider_models.py`: immutable capability binding and policy validation; no unsynchronized mutable lease integer.
- Modify `src/agenticos/sandbox/provider_broker.py`: broker-owned, lock-protected atomic capability slot that validates/replaces/cancels and holds the same synchronization boundary through auth-header injection.
- Rewrite `src/agenticos/sandbox/auth_helper_daemon.py`: standalone stdlib entrypoint, strict codec, bounded transports, Linux peer credentials, kernel hardening, Landlock, constrained auth loading, typed issuance state, and sanitized errors.
- Rewrite `src/agenticos/sandbox/controller_auth_helper.py`: identity-bound launch, strict setup/READY validation, Linux socketpair, bounded Windows fallback, immutable capability construction, and deterministic cleanup.
- Modify `src/agenticos/sandbox/provider_models.py` `AuthHelperProcessIdentity`: interpreter, entrypoint, root, hardening, FD, IPC, and helper-epoch evidence.
- Modify `tests/conformance/test_provider_auth_helper_unit.py`: binding/model, strict codec, schema, Windows-compatible behavior, and identity unit contracts.
- Modify `tests/conformance/test_provider_auth_process_boundary.py`: real process, peer, lifecycle, replay, issuance, hardening, and cleanup contracts.
- Create `tests/conformance/test_provider_auth_kernel_boundary.py`: real Linux Landlock/openat2/FD/proc negative tests.
- Modify `tests/fixtures/hostile_worker.py`: bounded `AUTH-01` reverse-boundary attack scenario.
- Create `tests/conformance/test_provider_auth_reverse_boundary.py`: actual M4A-derived Codex-domain denial proof.
- Modify `tests/conformance/test_provider_auth_canary_integration.py`: complete allowed/prohibited canary-surface audit and broker binding.
- Modify `tests/conformance/test_provider_broker_unit.py`: subscription binding rejection at the exact consumption point.
- Create `docs/phase-zero/m6-slice-2c1-auth-domain-closure.md`: exact authority table, mechanisms, adversarial findings, test counts/durations, residue, earned/non-earned claims, and repository proof.

---

### Task 1: Bind subscription capabilities to the exact provider policy

**Files:**
- Modify: `src/agenticos/sandbox/provider_models.py:65-108`
- Modify: `src/agenticos/sandbox/provider_broker.py:69-99,394-405`
- Modify: `tests/conformance/test_provider_auth_helper_unit.py:10-27`
- Modify: `tests/conformance/test_provider_broker_unit.py`

**Interfaces:**
- Produces: `ProviderAuthBinding`, `ProviderAuthCapability.validate_for_policy(policy, now=None)`, an immutable fully bound `SubscriptionAuthCapability`, broker-private `_AtomicCapabilitySlot`, `TaskProviderBroker.replace_auth_capability(candidate, expected_sequence)`, and `TaskProviderBroker.cancel_auth_capability()`.
- Consumes: existing `ProviderBrokerPolicy` task, generation, attempt, launch nonce, provider, upstream, and lifetime fields.
- Invariant: `SyntheticBearerAuth` remains usable for pre-subscription synthetic tests, while every `SubscriptionAuthCapability` has an exact immutable binding. The broker's slot—not a shared mutable integer—owns current capability, current sequence, helper epoch, expiry validation, and active/cancelled state under one lock.

- [ ] **Step 1: Write failing model tests for complete binding and expiration.**

Add tests that construct a policy and the following exact object:

```python
binding = ProviderAuthBinding(
    task_id=policy.task_id,
    generation=policy.generation,
    attempt_id=policy.attempt_id,
    launch_nonce=policy.launch_nonce,
    provider_id=policy.upstream_provider_id,
    upstream_scheme=policy.upstream_scheme,
    upstream_host=policy.upstream_host,
    upstream_port=policy.upstream_port,
    provider_purpose="responses_sse",
    helper_epoch="0123456789abcdef0123456789abcdef",
    request_nonce="11111111111111111111111111111111",
    capability_nonce="22222222222222222222222222222222",
    capability_sequence=1,
    issued_at=1_800_000_000,
    expires_at=1_800_000_300,
)
capability = SubscriptionAuthCapability(
    access_token="SYNTHETIC_ACCESS_123",
    account_id="acct_synthetic_456",
    binding=binding,
)
capability.validate_for_policy(policy, now=1_800_000_001)
```

Assert that altered task, generation, attempt, launch nonce, provider, scheme,
host, or port and `now == expires_at` each raise a stable
`ProviderAuthBindingError` without embedding any secret. Slot-level tests below
cover sequence, cancellation, and helper-epoch invalidation.

- [ ] **Step 2: Run the new model tests and confirm RED.**

Run:

```bash
.venv/bin/python -m pytest tests/conformance/test_provider_auth_helper_unit.py -k "binding or capability" -v
```

Expected: collection/import failure because `ProviderAuthBinding` does not
exist.

- [ ] **Step 3: Implement the minimal immutable binding type.**

Add validated dataclasses with these fields and methods:

```python
class ProviderAuthBindingError(RuntimeError):
    pass

@dataclass(frozen=True)
class ProviderAuthBinding:
    task_id: str
    generation: int
    attempt_id: int
    launch_nonce: str
    provider_id: str
    upstream_scheme: str
    upstream_host: str
    upstream_port: int
    provider_purpose: str
    helper_epoch: str
    request_nonce: str
    capability_nonce: str
    capability_sequence: int
    issued_at: int
    expires_at: int
```

Give `ProviderAuthCapability` a default `validate_for_policy()` implementation
for `SyntheticBearerAuth`. Require `SubscriptionAuthCapability` to compare every
binding field with `ProviderBrokerPolicy` and check wall-clock expiry. Keep
`SecretValue.__repr__` and `__str__` redacted and export the new public binding
and error names from `provider_models.__all__`.

- [ ] **Step 4: Add failing broker-consumption and atomic-replacement tests.**

Assert `TaskProviderBroker(policy, wrong_capability)` raises
`ProviderAuthBindingError` before opening a listener. Then exercise these exact
races with `threading.Barrier`-controlled test hooks around validation and
injection:

```text
replacement during validation
cancellation during validation
replacement immediately before injection
two concurrent replacement attempts with the same expected sequence
stale sequence after a completed replacement
```

Assert one concurrent compare-and-swap replacement succeeds and the other gets
`ProviderAuthBindingError`; cancellation wins permanently; and after
replacement or cancellation returns, the superseded access token can never be
observed by the fake upstream.

- [ ] **Step 5: Run broker tests and confirm RED at the missing validation call.**

Run:

```bash
.venv/bin/python -m pytest tests/conformance/test_provider_broker_unit.py -k "subscription or binding or replacement or cancellation or sequence" -v
```

Expected: the wrong capability is accepted by the current constructor and no
atomic replacement/cancellation API exists.

- [ ] **Step 6: Implement one atomic slot and define its linearization rule.**

`_AtomicCapabilitySlot` owns an `RLock`, current immutable capability, current
sequence, helper epoch, and active/cancelled state. It exposes:

```python
def replace(
    self,
    candidate: ProviderAuthCapability,
    *,
    policy: ProviderBrokerPolicy,
    expected_sequence: int,
) -> None: ...

def cancel(self) -> None: ...

def validate_extract_and_send(
    self,
    *,
    policy: ProviderBrokerPolicy,
    sender: Callable[[SecretValue, dict[str, SecretValue]], None],
) -> None: ...
```

`replace()` acquires the lock, requires the slot active, validates every policy
field/epoch/expiry, requires `expected_sequence == current_sequence` and
`candidate.sequence == current_sequence + 1`, then swaps current capability and
sequence as one critical section. `cancel()` acquires the same lock, marks the
slot cancelled, and clears its current capability before returning.

`validate_extract_and_send()` acquires that same lock and holds it continuously
while checking active state, helper epoch, current sequence, expiry, and policy;
extracting the authorization/account headers; and invoking the bounded sender
that completes the upstream `sendall()`. Its successful `sendall()` completion
is the credential-injection linearization point. Replacement/cancellation
linearizes at its state mutation while holding the same lock. Therefore, if an
old injection acquired the lock first, replacement/cancellation cannot return
until that bounded send completes; if replacement/cancellation returns first,
the old capability cannot later validate or inject. Socket timeouts bound lock
hold time. No secret-bearing header escapes the critical section for later use.

`TaskProviderBroker.replace_auth_capability()` and
`cancel_auth_capability()` delegate to the slot. Broker `stop()` cancels the
slot before returning. Map slot validation/race failures to
`PROVIDER_AUTH_UNAVAILABLE` without returning exception text.

The capability-slot lock and existing broker lifecycle lock have a fixed
non-nesting rule: the bounded sender callback may use the already-selected
upstream socket but must not acquire the broker lifecycle lock, and `stop()`
must cancel the slot before acquiring the lifecycle lock for socket teardown.
No path holds one lock while waiting for the other, preventing replacement or
cancellation from deadlocking behind an in-flight injection.

- [ ] **Step 7: Verify GREEN and focused regressions.**

Run:

```bash
.venv/bin/python -m pytest tests/conformance/test_provider_auth_helper_unit.py tests/conformance/test_provider_broker_unit.py -v
```

Expected: all selected tests pass with zero warnings.

- [ ] **Step 8: Inspect, commit, publish, and synchronize checkpoint 1.**

Run `git diff`, `git diff --check`, commit with
`security: bind provider auth capabilities to broker policy`, publish the exact
WSL SHA through the repository-approved route, verify GitHub `refs/heads/main`,
fast-forward Windows, and prove both clones clean and SHA-identical.

---

### Task 2: Replace unbounded line IPC with strict bounded packet transports

**Files:**
- Modify: `src/agenticos/sandbox/auth_helper_daemon.py`
- Modify: `src/agenticos/sandbox/controller_auth_helper.py:77-181`
- Modify: `tests/conformance/test_provider_auth_helper_unit.py`
- Modify: `tests/conformance/test_provider_auth_process_boundary.py`

**Interfaces:**
- Produces in the standalone helper: `IPC_PROTOCOL_VERSION`, fixed limits,
  `_strict_json_loads`, `_encode_packet`, `_recv_linux_packet`,
  `_send_linux_packet`, and stable `AuthProtocolError` codes.
- Produces in the controller: one Linux `AF_UNIX SOCK_SEQPACKET` endpoint and
  a Windows one-connection loopback fallback with stdin-delivered bootstrap
  nonce.
- Invariant: no listener/path exists on Linux; no newline accumulation exists
  on either platform; every failure is bounded and secret-free.

- [ ] **Step 1: Write failing strict-codec tests.**

Test the fixed protocol identifier and exact limits. Feed valid JSON plus these
records into `_strict_json_loads`: empty bytes, 16,385 bytes, invalid UTF-8,
arrays, duplicate keys, unknown keys, missing keys, wrong types, and an
unexpected protocol version. Assert stable codes such as
`IPC_EMPTY`, `IPC_OVERSIZED`, `IPC_BAD_ENCODING`, `IPC_BAD_JSON`,
`IPC_DUPLICATE_FIELD`, `IPC_UNKNOWN_FIELD`, and `IPC_VERSION` and assert the
input fragment never appears in `str(exc)`.

- [ ] **Step 2: Run codec tests and confirm RED.**

Run:

```bash
.venv/bin/python -m pytest tests/conformance/test_provider_auth_helper_unit.py -k "ipc_codec or duplicate or oversized" -v
```

Expected: failure because the strict codec and constants do not exist.

- [ ] **Step 3: Implement one strict JSON object codec in the standalone helper.**

Use `json.loads(..., object_pairs_hook=...)` to reject duplicate keys and a
schema helper that compares the exact key set. Encode with ASCII-compatible
UTF-8 and `sort_keys=True, separators=(",", ":")`; reject an encoded response
over 16,384 bytes before sending. `AuthProtocolError` stores only a fixed code.

- [ ] **Step 4: Write failing Linux packet/credential tests.**

On Linux, create `socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)`,
enable `SO_PASSCRED`, and assert the receiver obtains exactly one
`SCM_CREDENTIALS` record matching the actual sender PID/UID/GID. Separately
send a 16,385-byte packet, a zero-length packet, duplicate credential records,
and one/multiple `SCM_RIGHTS` FDs. Assert `MSG_TRUNC`, synthetic `MSG_CTRUNC`,
empty input, non-exact credential cardinality, and unexpected ancillary data
all fail closed.

For the `SCM_RIGHTS` attack, census the receiver's live FDs before and after
the rejected packet with bounded `fcntl(F_GETFD)` probes. Assert every
received descriptor is closed, its sentinel is unreadable, and the helper's
allowed FD census is unchanged. Include a case combining valid
`SCM_CREDENTIALS` with `SCM_RIGHTS` so valid sender identity cannot smuggle
descriptor authority.
Fork a bounded child to send on a deliberately inherited controller endpoint
and assert its different SCM PID is rejected.

- [ ] **Step 5: Run Linux packet tests and confirm RED.**

Run in WSL:

```bash
.venv/bin/python -m pytest tests/conformance/test_provider_auth_helper_unit.py -k "seqpacket or scm or ancillary or peer" -v
```

Expected: failure because packet receive/send and credential validation are
not implemented.

- [ ] **Step 6: Implement fixed-buffer `recvmsg()` and credential validation.**

Use a fixed ancillary buffer large enough for one credentials record plus the
Linux `SCM_MAX_FD` bound of 253 integer descriptors:

```python
ancillary_bytes = (
    socket.CMSG_SPACE(struct.calcsize("3i"))
    + socket.CMSG_SPACE(253 * array.array("i").itemsize)
)
payload, ancillary, flags, _ = sock.recvmsg(limit + 1, ancillary_bytes)
```

Before validating credentials or raising any protocol error, walk every
ancillary record. Decode every complete integer in every `SCM_RIGHTS` payload
into a quarantine list. In one `finally` block, close every quarantined FD,
including FDs delivered alongside otherwise-valid credentials. Reject both
`MSG_TRUNC` and `MSG_CTRUNC`; reject malformed/truncated rights payloads; require
exactly one `(SOL_SOCKET, SCM_CREDENTIALS)` record; and reject every other or
additional record. Descriptor cleanup precedes returning the fail-closed
`IPC_UNEXPECTED_ANCILLARY`/`IPC_ANCILLARY_TRUNCATED` error. Compare the three
credential integers with expected PID/UID/GID and set a 2.0-second socket
timeout. Count packets and fail at message 4,097. Use `sendmsg([encoded])` for
one record.

On every ancillary failure—including `MSG_CTRUNC`, where a record may be only
partially exposed—re-run bounded allowlist sanitation after closing decoded
rights, retaining only standard streams and the current authenticated IPC FD,
then revalidate that task's allowed census before sending the stable error or
terminating. Task 3 normalizes the IPC FD to 3 and implements this as
`close_range(4, UINT_MAX, 0)` plus exact `(0,1,2,3)` validation. Thus even a
kernel-installed descriptor that cannot be safely attributed from truncated
metadata is removed before the helper processes another request.

- [ ] **Step 7: Implement the bounded Windows fallback without changing its claim level.**

Retain one loopback TCP listener only on Windows. Deliver a 32-byte random
bootstrap nonce through inherited stdin. The helper applies a 2.0-second
deadline, reads exactly 32 bytes with no delimiter or growth, rejects early EOF
or any 33rd byte in the bounded bootstrap frame, consumes the nonce once, and
immediately closes the inherited stdin/bootstrap handle (or rebinds FD 0 to
null before normal protocol processing). Authenticate the only accepted
connection, close the listener immediately, and use a four-byte big-endian
length prefix with the same 16,384-byte limits and 2.0-second timeouts. The
Windows bootstrap channel is functional-regression behavior only; it is not
part of the Linux Level A FD or kernel claim.

- [ ] **Step 8: Remove Linux TCP/line-delimited behavior and verify GREEN.**

Run:

```bash
.venv/bin/python -m pytest tests/conformance/test_provider_auth_helper_unit.py tests/conformance/test_provider_auth_process_boundary.py -k "ipc or packet or peer or message or timeout" -v
```

Expected: Linux packet tests pass. The exact candidate commit receives the
same-file Windows codec/fallback check in the owned disposable worktree during
the checkpoint step; Windows skips only Linux credential assertions.

- [ ] **Step 9: Inspect, commit, publish, and synchronize checkpoint 2.**

Run `git diff`, `git diff --check`, commit with
`security: bound and authenticate auth helper IPC`, publish/verify the exact
SHA, fast-forward Windows, and prove both authoritative clones clean and equal.

---

### Task 3: Identity-bind and harden the helper before READY

**Files:**
- Modify: `src/agenticos/sandbox/auth_helper_daemon.py`
- Modify: `src/agenticos/sandbox/controller_auth_helper.py`
- Modify: `src/agenticos/sandbox/provider_models.py:241-268`
- Modify: `tests/conformance/test_provider_auth_helper_unit.py`
- Modify: `tests/conformance/test_provider_auth_process_boundary.py`

**Interfaces:**
- Produces: expanded `AuthHelperProcessIdentity` with interpreter and entrypoint
  device/inode/digest, helper epoch, controller/helper UID/GID/PID evidence,
  core/dumpability/NNP state, exact FD tuple, socket type, and protocol version.
- Produces: absolute `python -I -S <entrypoint>` launch with no ambient Python
  import variables or repository/user-site search authority.
- Invariant: controller-created PID, per-packet SCM PID, protocol identity, and
  implementation identities all agree before READY is accepted.
- Linux-only invariant: READY's exact live descriptor set is `(0, 1, 2, 3)`,
  with `0/1/2` bound to null and FD 3 the connected `SOCK_SEQPACKET` endpoint.
  This exact census is not asserted as a Windows kernel property.

The expanded frozen evidence model retains existing names where compatible and
uses this exact field set:

```python
class AuthHelperProcessIdentity:
    pid: int
    parent_pid: int
    uid: int
    gid: int
    controller_uid: int
    controller_gid: int
    executable: str
    executable_device: int
    executable_inode: int
    executable_digest: str
    entrypoint: str
    entrypoint_device: int
    entrypoint_inode: int
    entrypoint_digest: str
    cwd: str
    env_keys: tuple[str, ...]
    import_paths: tuple[str, ...]
    open_fds: tuple[int, ...]  # exact (0,1,2,3) only in qualified Linux READY
    ipc_endpoint: str
    ipc_type: str
    ipc_peer_auth: str
    helper_epoch: str
    protocol_version: str
    core_soft_limit: int
    core_hard_limit: int
    dumpable: int | None
    no_new_privs: int | None
    landlock_abi: int | None
    landlock_handled_access_fs: int | None
    auth_root_device: int | None
    auth_root_inode: int | None
    started_at_monotonic_ns: int
```

Linux requires non-optional hardening/Landlock values; Windows uses `None` only
for properties this slice explicitly does not qualify.

- [ ] **Step 1: Write failing launch-identity and import-hygiene tests.**

Assert the observed helper argv uses the absolute interpreter, `-I`, `-S`, and
the absolute entrypoint rather than `-m`; the environment keys exclude
`PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, and user-site controls; `sys.path`
evidence excludes workspace, repository root, current directory, and user site;
and READY includes distinct 64-hex interpreter and entrypoint digests plus
device/inode pairs. Set hostile ambient Python variables in the controller test
environment and prove they do not appear or affect the helper.

- [ ] **Step 2: Run identity tests and confirm RED.**

Run:

```bash
.venv/bin/python -m pytest tests/conformance/test_provider_auth_process_boundary.py -k "identity or import or argv or environment" -v
```

Expected: current `-m` launch, ambient `PYTHONPATH`, and interpreter-only
identity fail the new assertions.

- [ ] **Step 3: Implement pre-launch file identity and isolated entrypoint launch.**

In the controller, open the interpreter and entrypoint with no-follow regular
file checks, capture `st_dev`, `st_ino`, and SHA-256 from the opened objects,
then launch:

```python
argv = [
    str(interpreter_path),
    "-I",
    "-S",
    str(entrypoint_path),
    "--ipc-fd",
    str(child_fd),
    "--parent-pid",
    str(os.getpid()),
]
```

Use `env={}` on Linux and only required OS bootstrap keys on Windows. Never
include the auth path or any secret in argv/environment. In the helper, hash
`sys.executable` and `__file__` and capture their device/inode identities before
Landlock.

- [ ] **Step 4: Write failing hardening/FD tests.**

On Linux, launch with deliberate inherited repository file, repository directory,
workspace, `.git`, unrelated-controller, and connected-socket FDs through a
test-only constructor argument. Assert READY reports exactly `(0, 1, 2, 3)`,
stdin/stdout/stderr target null, core soft/hard limits zero, dumpable zero,
`NO_NEW_PRIVS` one, and every deliberate descriptor unusable with `EBADF`.
Inject failures for core limit, dumpability, FD sanitation, and NNP; assert the
controller never accepts READY.

On Windows, separately assert the inherited stdin bootstrap contains only the
bounded one-use nonce, is fully consumed once under its deadline, and is closed
or rebound to null before READY/normal protocol processing. Do not require the
Linux `(0,1,2,3)` census or infer a Windows kernel-isolation claim.

- [ ] **Step 5: Run hardening tests and confirm RED.**

Run:

```bash
.venv/bin/python -m pytest tests/conformance/test_provider_auth_process_boundary.py -k "core or dumpable or no_new_privs or inherited_fd or ready_order" -v
```

Expected: current helper does not prove the requested process state or exact FD
set.

- [ ] **Step 6: Implement hardening and exact census.**

On Linux before setup processing, call `setrlimit(RLIMIT_CORE, (0, 0))`,
`prctl(PR_SET_DUMPABLE, 0)`, duplicate the IPC socket to FD 3, and use
`close_range(4, UINT_MAX, 0)`. Close original duplicates and validate live FDs
with bounded `fcntl(F_GETFD)` probes without relying on `/proc`. After receiving
the authenticated non-secret setup record, call and verify
`PR_SET_NO_NEW_PRIVS`. Bind standard streams to null and return all hardening
state only in authenticated READY. The Windows path follows Task 2's separate
consume-once-and-close stdin bootstrap contract and reports functional evidence
without claiming the Linux descriptor layout.

- [ ] **Step 7: Bind READY to process creation and per-packet credentials.**

The controller must require:

```text
Popen.pid == READY.pid == READY SCM_CREDENTIALS.pid
controller pid/uid/gid == helper-observed parent and packet sender
expected interpreter identity == READY interpreter identity
expected entrypoint identity == READY entrypoint identity
expected protocol version == READY protocol version
```

Treat `SO_PEERCRED` only as socket creation/connection sanity evidence. Add a
negative test showing controller-side `SO_PEERCRED` on the pre-spawn socketpair
does not substitute for the helper SCM PID check.

- [ ] **Step 8: Verify GREEN and cleanup on Linux.**

Run both auth unit/process files on Linux. After every case, assert the helper
PID is gone, no child endpoint remains open, and temporary auth roots are
absent. During checkpoint 3, test the exact candidate commit with Windows
Python in the owned disposable Windows worktree before publication.

- [ ] **Step 9: Inspect, commit, publish, and synchronize checkpoint 3.**

Commit with `security: identity-bind and harden auth helper startup`, publish
and verify the exact SHA, fast-forward Windows, and prove clean/equal clones.

---

### Task 4: Install identity-bound Landlock before constrained auth loading

**Files:**
- Modify: `src/agenticos/sandbox/auth_helper_daemon.py`
- Modify: `src/agenticos/sandbox/controller_auth_helper.py`
- Modify: `src/agenticos/sandbox/provider_models.py`
- Create: `tests/conformance/test_provider_auth_kernel_boundary.py`

**Interfaces:**
- Produces in the standalone helper: `_openat2_auth_root`,
  `_openat2_auth_json`, `_apply_auth_landlock`, `AuthRootIdentity`, and
  pre-READY `FilesystemProbeResult` evidence.
- Consumes: controller-recorded auth-root path plus exact `st_dev`/`st_ino`.
- Invariant: the exact opened root object is the Landlock rule parent; no
  repository/runtime/home/proc root is granted; auth state is first read after
  policy enforcement.

- [ ] **Step 1: Write failing auth-root identity/race tests.**

Create an owner-only auth root and record its device/inode. Verify normal launch
succeeds. Then replace the path with another directory or symlink between the
controller observation and helper open through a bounded test hook and assert
startup fails before READY. Test non-directory, symlinked ancestor, wrong inode,
and `openat2` fault injection.

The controller's creation test also requires root mode `0700` and creates
`auth.json` with `os.open(..., O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC, 0o600)` so
process umask cannot accidentally broaden persistent-state permissions.

- [ ] **Step 2: Run root identity tests and confirm RED.**

Run:

```bash
.venv/bin/python -m pytest tests/conformance/test_provider_auth_kernel_boundary.py -k "auth_root or inode or symlink or race or openat2" -v
```

Expected: tests fail because no identity-bound root open or Landlock evidence
exists.

- [ ] **Step 3: Implement exact `openat2()` root and file resolution.**

Define the stdlib `ctypes` `open_how` structure and require syscall 437 on the
recorded x86_64 host. Open `/` as trusted `O_PATH|O_DIRECTORY|O_CLOEXEC`, resolve
the auth root relative to it with:

```text
O_PATH|O_DIRECTORY|O_CLOEXEC
RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS
```

Compare `fstat()` device/inode with the controller setup record. After
Landlock, resolve only `auth.json` relative to that root FD with
`O_RDONLY|O_CLOEXEC` and
`RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS`; require a regular
file, owner UID, mode no broader than `0600`, and link count one.

- [ ] **Step 4: Write failing Landlock setup-order and allowed-access tests.**

Assert READY evidence records ABI >= 3, handled mask `0x7fff`, the exact root
device/inode, policy installed before auth open, and ruleset/root/auth FDs closed
at READY. Put an allowed sentinel beside `auth.json` and prove the real helper
can read it only after policy application. Inject ABI query, ruleset creation,
rule add, restriction, auth open, and JSON parse failures and assert no READY.

- [ ] **Step 5: Run Landlock tests and confirm RED.**

Run:

```bash
.venv/bin/python -m pytest tests/conformance/test_provider_auth_kernel_boundary.py -k "landlock or allowed or startup_order or fail_closed" -v
```

Expected: missing Landlock evidence and current pre-confinement auth load fail.

- [ ] **Step 6: Implement the minimal Landlock policy.**

Import `ctypes` before confinement. Require the Landlock version query to return
at least 3. Create a ruleset handling `0x7fff`. Add one
`LANDLOCK_RULE_PATH_BENEATH` using the already-opened auth-root FD and only:

```text
READ_FILE | READ_DIR | WRITE_FILE | REMOVE_FILE | MAKE_REG | REFER | TRUNCATE
```

Call `landlock_restrict_self()`, close the ruleset/trusted-root construction
FDs, run post-policy denial probes, open `auth.json` relative to the verified
root, parse/validate it, close auth/root FDs, and only then construct READY.
There is no runtime, repository, `/proc`, `/usr`, home, or workspace grant.

- [ ] **Step 7: Measure lazy runtime needs without weakening the default.**

Exercise JSON decode/encode, hashing, token generation, time, socket messaging,
refresh simulation, cancellation, shutdown, and sanitized failure responses
after Landlock. If any operation attempts a new runtime open, capture the exact
path and determine whether eager import/state initialization removes it. A
broad runtime grant is not an acceptable fix; any exact exception requires a
spec amendment and user review before implementation.

- [ ] **Step 8: Verify GREEN and focused Landlock regressions.**

Run:

```bash
.venv/bin/python -m pytest tests/conformance/test_provider_auth_kernel_boundary.py tests/conformance/test_native_landlock_unit.py -v
```

Expected: auth policy and existing native Landlock contracts pass.

- [ ] **Step 9: Inspect, commit, publish, and synchronize checkpoint 4.**

Commit with `security: confine auth helper with identity-bound Landlock`,
publish/verify the exact SHA, fast-forward Windows, and prove clean/equal clones.

---

### Task 5: Implement bounded typed issuance, replacement, replay, and cancellation

**Files:**
- Modify: `src/agenticos/sandbox/auth_helper_daemon.py`
- Modify: `src/agenticos/sandbox/controller_auth_helper.py`
- Modify: `src/agenticos/sandbox/provider_models.py`
- Modify: `tests/conformance/test_provider_auth_helper_unit.py`
- Modify: `tests/conformance/test_provider_auth_process_boundary.py`

**Interfaces:**
- Produces: strict `GET_TASK_PROVIDER_CAPABILITY`, `CANCEL_ATTEMPT`, and
  `SHUTDOWN` records; `capability_sequence`; eight-issuance bound; 4,096-entry
  nonce cache; helper epoch; stable sanitized errors.
- Consumes: exact broker policy identity supplied by the trusted controller.
- Invariant: task tuple is reusable only for bounded replacement issuance;
  request nonce is never reusable; only newest sequence is current.

- [ ] **Step 1: Write failing strict-schema and substitution tests.**

Build valid requests containing protocol version, request nonce, task,
generation, attempt, launch nonce, provider, upstream scheme/host/port, and
`responses_sse` purpose. Alter each field independently; add unknown and
duplicate fields; use invalid types/bounds. Assert stable errors and no access
credential in the response.

- [ ] **Step 2: Write failing replacement-issuance tests.**

For one active attempt, send eight requests with unique 32-hex request nonces.
Assert response sequences `1..8`, distinct capability nonces, matching helper
epoch, and expiry no later than `issued_at + 300`. Install each replacement
through `TaskProviderBroker.replace_auth_capability()` and assert the atomic
slot rejects every prior sequence after the replacement returns. Assert the
ninth request,
duplicate nonce, expired capability, stale sequence, cancelled context, and old
helper epoch fail closed. Assert another task/generation/attempt has an
independent sequence starting at one.

- [ ] **Step 3: Run issuance tests and confirm RED.**

Run:

```bash
.venv/bin/python -m pytest tests/conformance/test_provider_auth_process_boundary.py -k "capability or sequence or replay or cancel or epoch or substitution" -v
```

Expected: current tuple-wide replay rule rejects the second legitimate
issuance and response objects lack full binding/sequence.

- [ ] **Step 4: Implement bounded request and issuance state.**

Use fixed dictionaries capped at 4,096 request nonces and active attempt
contexts. The context key is the complete task/generation/attempt/launch/
provider/upstream/purpose tuple and stores next sequence, current sequence,
cancellation, and issuance count. Accepted issuance consumes the unique request
nonce, increments sequence by one, generates a 32-hex capability nonce, and
returns the complete binding. Reject cache/context exhaustion rather than
evicting replay evidence silently.

- [ ] **Step 5: Remove ambient auth operations.**

Delete `REFRESH_TOKENS` and generic refresh mutation from the helper protocol.
Keep synthetic expiry-triggered refresh entirely inside the auth domain. Ensure
`GET_REFRESH_TOKEN`, `GET_ACCESS_TOKEN`, `DUMP_AUTH_STATE`, `SHOW_AUTH_JSON`,
and unknown actions receive `IPC_UNKNOWN_OPERATION` with no echoed input.

- [ ] **Step 6: Update controller capability construction and broker replacement integration.**

Generate a new request nonce per issuance, validate every echoed field, build
`ProviderAuthBinding`, and return an immutable `SubscriptionAuthCapability`.
The trusted orchestration path passes a newly issued candidate and the
previously observed sequence into
`TaskProviderBroker.replace_auth_capability(candidate, expected_sequence=...)`;
it never assigns broker internals directly. Cancellation first sends the exact
helper context and then calls `broker.cancel_auth_capability()`; helper stop
cancels every broker slot registered to that helper epoch. Add an integration
test proving a running broker adopts sequence two and injects only sequence
two's access token after the replacement call returns.

- [ ] **Step 7: Add crash, timeout, disconnect, flood, and cleanup tests.**

Boundedly exercise helper exit before response, controller endpoint close,
silent peer timeout, 4,096-message budget, replay-cache exhaustion through a
reduced test-only bound, rapid sequential requests, and cancellation during an
active request. Assert no ambient credential/login fallback and deterministic
helper/auth-root cleanup.

- [ ] **Step 8: Verify GREEN plus broker/auth corpus.**

Run:

```bash
.venv/bin/python -m pytest \
  tests/conformance/test_provider_auth_helper_unit.py \
  tests/conformance/test_provider_auth_process_boundary.py \
  tests/conformance/test_provider_broker_unit.py \
  tests/conformance/test_provider_auth_canary_integration.py -v
```

Expected: all pass with no warnings or secret-bearing errors.

- [ ] **Step 9: Inspect, commit, publish, and synchronize checkpoint 5.**

Commit with `security: bind and bound auth capability issuance`, publish/verify
the exact SHA, fast-forward Windows, and prove clean/equal clones.

---

### Task 6: Prove real helper-side filesystem and process-surface denial

**Files:**
- Modify: `src/agenticos/sandbox/auth_helper_daemon.py` only for regression
  defects demonstrated by a failing test.
- Modify: `src/agenticos/sandbox/controller_auth_helper.py` only for regression
  defects demonstrated by a failing test.
- Expand: `tests/conformance/test_provider_auth_kernel_boundary.py`

**Interfaces:**
- Consumes: setup-only labeled denial probes; no post-READY generic open API.
- Produces: `FilesystemProbeResult(label, operation, outcome, errno_name)` with
  no content/path/token field.
- Invariant: every prohibited object is known to exist before policy activation
  and is denied by the real helper after Landlock.

- [ ] **Step 1: Create real prohibited and allowed sentinels.**

In an owned test root, create managed-worktree, unrelated-controller,
provider-`CODEX_HOME`, model-output, build-artifact, and outside-home sentinels.
Use the authoritative WSL repository and `.git` for repository sentinels without
modifying them. Put allowed data in the auth-private root. For literal
`/workspace`, launch the real helper through a test-only verified bubblewrap
prefix that bind-mounts an owned sentinel directory at `/workspace`; record that
the sentinel exists before Landlock and require post-Landlock `EACCES`.

- [ ] **Step 2: Write failing pathname/escape tests.**

Have the real helper probe absolute paths, `..` and cwd traversal, an
environment-supplied denied path, a symlink inside auth root to an outside
sentinel, authoritative repo and `.git`, literal `/workspace`, managed
worktree, controller state, home, `CODEX_HOME`, model output, and build output.
Assert `KERNEL_DENIED` with `EACCES`, `EPERM`, or `EXDEV`, never application
refusal. Assert the allowed auth sentinel and synthetic refresh still work.

- [ ] **Step 3: Write failing descriptor and `/proc/self/fd` tests.**

Deliberately offer file and directory FDs for each prohibited root through the
test-only inheritance hook. Require pre-sanitization observation, post-sanitize
`EBADF`, exact READY FDs `(0,1,2,3)`, and post-Landlock denial opening
`/proc/self/fd/<number>`. Include a connected socket FD. Assert no descriptor
target names or sentinel content enter READY/errors.

- [ ] **Step 4: Characterize symlink, hardlink, rename, and link limits.**

Prove symlink targets outside the allowed hierarchy are Landlock-denied. Prove
the hostile domain cannot create a hardlink into auth root. Verify `auth.json`
must be owner-owned, regular, mode <= `0600`, no symlink, and link count one.
Record that a pre-existing hardlink deliberately substituted by the trusted
controller for `auth.json` is controller-supplied authority and is rejected by
the required `st_nlink == 1` auth-file check rather than misreported as a
Landlock guarantee.

- [ ] **Step 5: Run negative tests and confirm RED before each defect fix.**

Run:

```bash
.venv/bin/python -m pytest tests/conformance/test_provider_auth_kernel_boundary.py -k "denied or traversal or symlink or workspace or fd or proc or hardlink" -v
```

Each production adjustment must have a single reproducing failure first.

- [ ] **Step 6: Add same-UID process-surface characterization from an untrusted child.**

From a bounded same-UID non-controller test process, attempt
`/proc/<helper>/fd`, `/environ`, `/mem`, `/root`, `/cwd`, `ptrace(PTRACE_ATTACH)`,
and `process_vm_readv`. Record exact errno. Distinguish `PR_SET_DUMPABLE=0`/Yama
denial from the stronger Codex PID-namespace proof in Task 7. Do not claim the
trusted controller lacks persistent-auth authority.

- [ ] **Step 7: Verify the complete helper kernel corpus repeatedly.**

Run:

```bash
for i in 1 2 3; do
  .venv/bin/python -m pytest tests/conformance/test_provider_auth_kernel_boundary.py -q || exit 1
done
```

Expected: three clean runs, no lingering helpers, sockets, auth roots, or test
mounts.

- [ ] **Step 8: Inspect, commit, publish, and synchronize checkpoint 6.**

Commit with `test: prove auth helper kernel isolation`, publish/verify the exact
SHA, fast-forward Windows, and prove clean/equal clones.

---

### Task 7: Prove the reverse Codex boundary and complete the canary audit

**Files:**
- Modify: `tests/fixtures/hostile_worker.py`
- Create: `tests/conformance/test_provider_auth_reverse_boundary.py`
- Modify: `tests/conformance/test_provider_auth_canary_integration.py`
- Modify: `src/agenticos/sandbox/controller_auth_helper.py` and related code
  only for defects first reproduced by failing tests.

**Interfaces:**
- Produces hostile scenario `AUTH-01` with bounded path, proc-surface, FD, env,
  and Unix endpoint attempts and a content-free JSON result.
- Consumes existing `NamespaceLandlockRunner`, native M4A launcher, runtime
  boundary, and fixed hostile-worker environment.
- Invariant: actual Codex-style sandbox receives known attack locators but no
  auth IPC capability and cannot obtain refresh bytes or helper process state.

- [ ] **Step 1: Add the failing `AUTH-01` hostile-worker scenario and schema.**

Accept explicit targets for auth root, `auth.json`, controller auth state, and
known helper PID. Attempt open/read on each, `/proc/<pid>/{fd,environ,mem,root,cwd}`,
scan the bounded live FD set, attempt sends on every socket FD, and inspect the
fixed environment. Return only operation, success boolean, and errno name;
apply `_canary_details` so content never appears in worker output.

- [ ] **Step 2: Run fixture/unit validation and confirm RED.**

Run:

```bash
.venv/bin/python -m pytest tests/conformance/test_hostile_worker.py -k "auth_01 or auth" -v
```

Expected: scenario is unknown until registered and implemented.

- [ ] **Step 3: Write the actual M4A-derived reverse-boundary integration test.**

Start a real confined helper, then launch `AUTH-01` with
`NamespaceLandlockRunner` using the existing L1 inspect profile and native
launcher. Pass known host locators as arguments so path secrecy cannot explain
failure. Assert auth/controller paths and helper proc surfaces are kernel
denied/namespace absent, the worker FD set contains no helper/controller IPC
endpoint, no environment entry contains auth authority, and no canary appears
in stdout/stderr/evidence/workspace. Verify the M4A cgroup drains.

- [ ] **Step 4: Run the reverse test and confirm RED before any boundary fix.**

Run:

```bash
.venv/bin/python -m pytest tests/conformance/test_provider_auth_reverse_boundary.py -v
```

Expected initial failures must identify a real leaked path, FD, proc surface,
or missing test contract; fix production behavior only after a reproducer.

- [ ] **Step 5: Expand the end-to-end canary audit.**

Scan refresh/access/account/cookie canaries across client stdout/stderr/env,
synthetic `CODEX_HOME`, workspace, controller/broker/helper operational logs,
evidence, exception strings, argv, `/proc` metadata visible to Codex, IPC error
records, temp roots, crash/core artifacts, test artifacts, `git diff`, and
`git status`. Assert:

```text
REFRESH_SECRET_VISIBLE_OUTSIDE_APPROVED_AUTH_DOMAIN=0
```

Also assert `requires_openai_auth=false` and `supports_websockets=false` remain
fixed in the synthetic provider configuration and no ambient-auth fallback
occurs after helper failure.

- [ ] **Step 6: Run the complete targeted provider/auth corpus.**

Run:

```bash
.venv/bin/python -m pytest \
  tests/conformance/test_provider_auth_helper_unit.py \
  tests/conformance/test_provider_auth_process_boundary.py \
  tests/conformance/test_provider_auth_kernel_boundary.py \
  tests/conformance/test_provider_auth_reverse_boundary.py \
  tests/conformance/test_provider_auth_canary_integration.py \
  tests/conformance/test_provider_broker_unit.py -v
```

Expected: zero failures; platform-specific Windows kernel assertions use
explicit Linux-only skips.

- [ ] **Step 7: Inspect, commit, publish, and synchronize checkpoint 7.**

Commit with `test: prove Codex cannot reach auth domain`, publish/verify the
exact SHA, fast-forward Windows, and prove clean/equal clones.

---

### Task 8: Independent adversarial review, full-suite closure, and final report

**Files:**
- Create: `docs/phase-zero/m6-slice-2c1-auth-domain-closure.md`
- Modify production/tests only for independently reproduced review findings.

**Interfaces:**
- Consumes: exact approved design SHA, reviewed plan SHA, owner-designated
  implementation-base SHA, candidate SHA, implementation diff, authority table,
  targeted evidence, full-suite outputs, and residue audit.
- Produces: independent review findings, exact test counts/durations, final
  Level A report, exact tested/pushed SHA, and preservation proof.

- [ ] **Step 1: Run a fresh independent adversarial review before closure.**

Invoke `superpowers:requesting-code-review` and give the reviewer the approved
design and implementation plan as distinct review artifacts, with:

```text
DESIGN_SHA=43196fca78a92d819aa1b3f117f964ecdd1659ea
PLAN_SHA=72dedf962c20acbdddb4ec3930ab67f2daef8380
IMPLEMENTATION_BASE_SHA=72dedf962c20acbdddb4ec3930ab67f2daef8380
CANDIDATE_SHA=$(git rev-parse HEAD)
```

Give the reviewer the implementation diff from `IMPLEMENTATION_BASE_SHA` to
`CANDIDATE_SHA` and explicit invalidation questions covering absolute paths,
symlinks, `/proc/self/fd`, inherited directories, auth-root replacement,
implementation identity, SCM sender binding, unexpected same-UID peers, IPC
memory/time bounds, `MSG_CTRUNC`, SCM_RIGHTS cleanup/FD residue,
nonce/sequence replay, atomic replacement/cancellation races, cross-policy
reuse, exceptions, evidence, READY ordering, Windows bootstrap closure, and
ambient-auth fallback.

- [ ] **Step 2: Resolve every critical/important finding test-first.**

For each valid finding, add one failing regression test, confirm RED, implement
the smallest fix, run focused GREEN, and rerun the reviewer-relevant corpus.
Record minor residuals explicitly; do not proceed with unresolved critical or
important findings.

- [ ] **Step 3: Inspect the complete candidate diff and run static checks.**

Run:

```bash
git diff 72dedf962c20acbdddb4ec3930ab67f2daef8380...HEAD
git diff --check 72dedf962c20acbdddb4ec3930ab67f2daef8380...HEAD
```

If native code changed, run the repository's warning-clean GCC command and
native unit/integration corpus. Confirm no real credential/provider endpoint is
present in the diff.

- [ ] **Step 4: Run final targeted auth/kernel/reverse tests and record pytest summaries.**

Use the Task 7 targeted command plus the native Landlock and M4A integration
files. Capture collected/passed/failed/skipped counts and duration directly
from pytest output.

- [ ] **Step 5: Run three consecutive complete Linux suites.**

Run in WSL from the authoring clone:

```bash
for i in 1 2 3; do
  .venv/bin/python -m pytest || exit 1
done
```

Record each run's collected/passed/failed/skipped counts and duration
separately. Do not replace these with targeted suites.

- [ ] **Step 6: Run one complete Windows suite.**

After the exact candidate SHA is available in the Windows clone through the
preservation workflow, run:

```powershell
python -m pytest
```

Record collected/passed/failed/skipped counts and duration. State explicitly
that this is protocol/functional regression only.

- [ ] **Step 7: Audit runtime and repository residue.**

Prove no helper process, IPC socket/listener, temporary auth root, core file,
workspace canary, unexpected cgroup/systemd unit, unpushed commit, unexplained
untracked file, or stash remains. The documented credential-free external
spec bundles may remain only as benign outside-repository residue if command
safety still blocks deletion.

- [ ] **Step 8: Write the closure report from observed evidence.**

Include the exact final architecture, startup ordering, Landlock ABI/mask/root
identity/grants, FD census, interpreter/entrypoint identities, IPC type/peer
mechanisms/limits/timeouts, capability sequence/replay semantics, filesystem
and reverse denials, canary surfaces, adversarial findings/remediation, Linux
and Windows counts/durations, residue, authority table, earned Level A wording,
controller residual, Windows non-claim, and deferred dedicated-identity Level B
milestone.

- [ ] **Step 9: Verify completion evidence before the closure commit.**

Invoke `superpowers:verification-before-completion`. Re-run the exact commands
that prove every success claim, read their complete outputs, and compare every
design requirement with an implementation/test/report location.

- [ ] **Step 10: Commit, publish, synchronize, and prove final preservation.**

Commit the exact tested closure state with
`security: close M6 auth domain Level A boundary`. Push the exact SHA (using the
approved WSL bundle to Windows route if required), verify actual GitHub
`refs/heads/main`, fetch/fast-forward both clones, and prove:

```text
WINDOWS_HEAD == WSL_HEAD == ORIGIN_MAIN == GITHUB_MAIN
WINDOWS_TREE=clean
WSL_TREE=clean
UNPUSHED_COMMITS=0
UNEXPLAINED_UNTRACKED_FILES=0
STASH_ENTRIES=0
```

- [ ] **Step 11: Return the exact final report and stop.**

Use the owner's required key/value footer, set status to `EARNED_LEVEL_A` only
if every kernel and closure proof passed, state the trusted-controller residual,
and recommend the smallest next M6 slice. If evidence is incomplete, report
`PARTIAL` or `BLOCKED` without weakening the boundary.
