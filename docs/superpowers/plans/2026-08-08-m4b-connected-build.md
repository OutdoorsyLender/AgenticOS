# Milestone 4B Connected Build Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add task-bound exact-hostname HTTPS build egress while preserving the M4A route-less, DNS-less worker namespace and every existing filesystem, FD, capability, gate-ordering, and cgroup-lifecycle guarantee.

**Architecture:** A trusted native task supervisor starts a least-authority per-task broker and the existing worker Bubblewrap inside one authoritative systemd scope. The trusted native launcher creates `127.0.0.1:18080` inside the verified worker network namespace, passes that exact listener FD to the host-netns broker with `SCM_RIGHTS`, and remains blocked until the controller authenticates `NETWORK_BROKER_READY`; M4A sanitation, NNP, Landlock, combined evidence, and final exec then proceed. M4B-1 proves only this transport/lifecycle path, M4B-2 adds exact-hostname authenticated HTTPS, and M4B-3 qualifies identity-bound build tools without changing network authority.

**Tech Stack:** Python 3.12, C11 native helpers, Linux 6.6/WSL2, Bubblewrap 0.11.1, systemd user scopes/cgroup v2, Landlock ABI v3, Linux `AF_UNIX`/`SCM_RIGHTS`/`SO_NETNS_COOKIE`, pytest; M4B-2 HTTP/TLS/IDNA/certificate dependencies remain behind the explicit dependency gate in Task 9.

## Global Constraints

- Baseline is `fd90db6ec51f2d0d3103f636c50e2684c7bee796`; begin each sub-milestone from a clean synchronized checkpoint.
- Preserve `/workspace`, `PWD=/workspace`, identity-bound mounts, M4A namespaces, zero worker capabilities, hostile FD set `{0,1,2}`, exact environment construction, NNP, Landlock, authenticated final exec, and recursive cgroup cleanup.
- Worker network namespace remains loopback-only with no route and no usable DNS.
- Fixed worker network ABI is `127.0.0.1:18080`; M4B-2 task CA path is `/opt/agenticos/network-ca.pem`.
- Do not add pasta, passt, slirp4netns, veth, TAP, nftables, general IP networking, generic TCP, UDP, QUIC, SSH, SOCKS, opaque CONNECT, or worker DNS.
- Broker is per-task, stays in the host network namespace, shares the authoritative task cgroup, has zero capabilities and `NoNewPrivs=1`, and receives no workspace, real home, provider state, runtime sockets, or ambient controller environment.
- `NETWORK_BROKER_READY` is mandatory authenticated pre-exec evidence; broker death before release denies exec, and broker death after release cancels the task.
- Task identity is exact task ID + generation + launch nonce + immutable policy digest; never accept a worker-supplied task identity.
- M4B-1 adds no TLS, HTTP, IDNA, certificate, or DNS dependency and earns no Connected Build claim.
- M4B-2 supports exact-hostname anonymous HTTPS over TCP/443 and HTTP/1.1 only; every new origin connection resolves from scratch and connects one validated sockaddr without a second resolution.
- Missing, mismatching, or ECH-hidden worker SNI is denied; same-IP hostname confusion must be proven impossible.
- Per-task CA private material stays broker-only and preferably memory-only; never modify host or general sandbox trust stores.
- Redirect responses are not rewritten by default; a followed cross-authority redirect receives a fresh grant check. HTTPS-to-HTTP remains unsupported.
- No provider credential may enter worker or broker.
- All conformance endpoints are synthetic/local; no public service is required.
- Stop at every design stop condition instead of weakening the claim.

---

## M4B-1 — Capability Transport and Lifecycle Proof

### Task 1: Define the immutable transport policy and evidence types

**Files:**
- Create: `src/agenticos/sandbox/network_models.py`
- Create: `tests/conformance/test_m4b_unit.py`
- Modify: `src/agenticos/sandbox/__init__.py`

**Interfaces:**
- Produces: `TransportPolicy`, `ListenerEvidence`, `BrokerProcessEvidence`, `BrokerReadyEvidence`, `canonical_policy_bytes()`, and `policy_digest()`.
- Consumes: existing ISO timestamp and evidence conventions from `src/agenticos/sandbox/models.py` and `src/agenticos/sandbox/evidence.py`.

- [ ] **Step 1: Write failing canonicalization and validation tests.**

```python
def test_transport_policy_digest_binds_generation_nonce_and_fixed_proxy():
    policy = TransportPolicy(
        version="AOSNET/1",
        task_id="task-7",
        task_generation=3,
        launch_nonce="ab" * 16,
        mode=TransportMode.SYNTHETIC_FIXTURE_FD,
        proxy_host="127.0.0.1",
        proxy_port=18080,
        expires_at_monotonic_ns=9_000_000_000,
        connection_limit=1,
        byte_limit=4096,
    )
    assert len(policy_digest(policy)) == 64
    assert b"task-7" in canonical_policy_bytes(policy)


@pytest.mark.parametrize("host,port", [("0.0.0.0", 18080), ("::1", 18080), ("127.0.0.1", 443)])
def test_transport_policy_rejects_non_abi_listener(valid_policy, host, port):
    with pytest.raises(ValueError):
        dataclasses.replace(valid_policy, proxy_host=host, proxy_port=port)
```

Also require positive integer generation/limits, 16-byte lowercase-hex-encoded nonce,
monotonic expiry after activation, exact protocol version, and modes limited to
`DENY` and test-only `SYNTHETIC_FIXTURE_FD`.

- [ ] **Step 2: Run the tests and verify RED.**

Run: `python -m pytest tests/conformance/test_m4b_unit.py -v`

Expected: collection fails because `agenticos.sandbox.network_models` does not exist.

- [ ] **Step 3: Implement frozen bounded dataclasses and canonical JSON.**

```python
class TransportMode(str, Enum):
    DENY = "DENY"
    SYNTHETIC_FIXTURE_FD = "SYNTHETIC_FIXTURE_FD"


@dataclass(frozen=True)
class TransportPolicy:
    version: str
    task_id: str
    task_generation: int
    launch_nonce: str
    mode: TransportMode
    proxy_host: str
    proxy_port: int
    activated_at_monotonic_ns: int
    expires_at_monotonic_ns: int
    connection_limit: int
    byte_limit: int


@dataclass(frozen=True)
class ListenerEvidence:
    family: int
    socket_type: int
    address: str
    port: int
    device: int
    inode: int
    file_type: int
    netns_cookie: int
    accepting: bool
```

`canonical_policy_bytes()` uses sorted compact JSON, rejects unknown types and
unbounded strings, and never serializes a host locator or FD number. The SHA-256
digest covers every dataclass field.

- [ ] **Step 4: Run the unit tests GREEN.**

Run: `python -m pytest tests/conformance/test_m4b_unit.py -v`

- [ ] **Step 5: Commit the policy contract.**

```bash
git add src/agenticos/sandbox/network_models.py src/agenticos/sandbox/__init__.py tests/conformance/test_m4b_unit.py
git commit -m "security: define M4B transport capability contract"
```

### Task 2: Prove sealed immutable policy and socket identity primitives

**Files:**
- Create: `src/agenticos/sandbox/network_identity.py`
- Modify: `tests/conformance/test_m4b_unit.py`
- Create: `tests/conformance/test_m4b_integration.py`

**Interfaces:**
- Consumes: `TransportPolicy`, `ListenerEvidence`, and canonical policy bytes.
- Produces: `VerifiedSealedPolicy`, `ListenerAdoptionFrame`, `AdoptedListener`,
  `NetworkIdentityError`, `create_sealed_policy_fd()`, `read_sealed_policy_fd()`,
  `listener_evidence()`, `send_listener_fd()`, and `recv_listener_fd()`.

- [ ] **Step 1: Write failing sealed-memfd and ancillary-message tests.**

```python
def test_policy_memfd_is_fully_sealed(policy):
    fd = create_sealed_policy_fd(policy)
    try:
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        assert seals & required == required
        with pytest.raises(OSError):
            os.write(fd, b"x")
        verified = read_sealed_policy_fd(fd)
        assert verified.policy == policy
        assert verified.digest == policy_digest(policy)
    finally:
        os.close(fd)


def test_listener_receive_rejects_two_scm_rights_fds(seqpacket_pair, listeners):
    send_two_fds_for_negative_control(seqpacket_pair[0], listeners)
    with pytest.raises(NetworkIdentityError):
        recv_listener_fd(seqpacket_pair[1], expected_policy_digest="00" * 32)
```

Cover missing seals, mutable FD substitution, oversized/truncated control frame,
zero/two FDs, unknown ancillary data, wrong digest/nonce/generation, wrong socket
family/type/address/port/listening state, and duplicate adoption.

- [ ] **Step 2: Run the focused tests and verify RED.**

Run: `python -m pytest tests/conformance/test_m4b_unit.py -k 'sealed or listener or ancillary' -v`

- [ ] **Step 3: Implement the exact Linux primitives with no fallback.**

```python
def create_sealed_policy_fd(policy: TransportPolicy) -> int:
    payload = canonical_policy_bytes(policy)
    fd = os.memfd_create("aos-network-policy", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    _write_exact(fd, payload)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, REQUIRED_POLICY_SEALS)
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


def listener_evidence(fd: int) -> ListenerEvidence:
    observed = socket.socket(fileno=os.dup(fd))
    try:
        stat_result = os.fstat(observed.fileno())
        address, port = observed.getsockname()
        cookie = struct.unpack("=Q", observed.getsockopt(socket.SOL_SOCKET, SO_NETNS_COOKIE, 8))[0]
        return ListenerEvidence(
            family=observed.family,
            socket_type=observed.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE),
            address=address,
            port=port,
            device=stat_result.st_dev,
            inode=stat_result.st_ino,
            file_type=stat.S_IFMT(stat_result.st_mode),
            netns_cookie=cookie,
            accepting=bool(observed.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)),
        )
    finally:
        observed.close()


def send_listener_fd(channel: socket.socket, fd: int, frame: ListenerAdoptionFrame) -> None:
    payload = frame.to_bytes()
    rights = array.array("i", [fd])
    if channel.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]) != len(payload):
        raise NetworkIdentityError("listener adoption frame was not sent atomically")

def recv_listener_fd(
    channel: socket.socket,
    *,
    expected_task_id: str,
    expected_generation: int,
    expected_nonce: str,
    expected_policy_digest: str,
) -> AdoptedListener:
    payload, ancillary, flags, _address = channel.recvmsg(
        MAX_ADOPTION_FRAME,
        socket.CMSG_SPACE(array.array("i").itemsize),
        socket.MSG_CMSG_CLOEXEC,
    )
    frame, received_fd = validate_single_listener_message(payload, ancillary, flags)
    return authenticate_adopted_listener(
        frame,
        received_fd,
        expected_task_id=expected_task_id,
        expected_generation=expected_generation,
        expected_nonce=expected_nonce,
        expected_policy_digest=expected_policy_digest,
    )
```

Use `os.memfd_create("aos-network-policy", MFD_CLOEXEC | MFD_ALLOW_SEALING)`, all four immutable
seals, `AF_UNIX SOCK_SEQPACKET | SOCK_CLOEXEC`, one `SCM_RIGHTS` FD, `MSG_CMSG_CLOEXEC`,
and reject `MSG_TRUNC`/`MSG_CTRUNC`. Obtain the network namespace cookie with
`getsockopt(SOL_SOCKET, SO_NETNS_COOKIE)` and stop on `ENOPROTOOPT`; do not infer
it from a port or pathname.

- [ ] **Step 4: Add a real-host cross-netns identity integration test.**

The child uses `unshare -Urn`, receives Bubblewrap-equivalent loopback state,
creates `127.0.0.1:18080`, reports its evidence, and exports the FD. The parent
requires equal fstat identity and netns cookie on the adopted FD and requires a
different cookie on a newly created host-netns socket.

Run: `.venv/bin/python -m pytest tests/conformance/test_m4b_integration.py -k listener_identity -v`

- [ ] **Step 5: Run all new primitive tests GREEN.**

Run: `python -m pytest tests/conformance/test_m4b_unit.py -v`

Run: `.venv/bin/python -m pytest tests/conformance/test_m4b_integration.py -k listener_identity -v`

- [ ] **Step 6: Commit immutable policy and listener identity primitives.**

```bash
git add src/agenticos/sandbox/network_identity.py tests/conformance/test_m4b_unit.py tests/conformance/test_m4b_integration.py
git commit -m "security: bind M4B policy and listener kernel identity"
```

### Task 3: Extend the native launcher with the pre-sanitization listener handoff

**Files:**
- Modify: `native/fs_launcher/fs_launcher.c`
- Modify: `src/agenticos/sandbox/launcher.py`
- Modify: `tests/conformance/test_native_landlock_unit.py`
- Modify: `tests/conformance/test_m4b_unit.py`

**Interfaces:**
- Consumes: `AOSLAUNCH/3` request fields and an inherited fixed handoff FD.
- Produces: authenticated `R`, `L`, `S`, `I`, `P`, `N`, `A` launcher transcript; passes one listener FD before sanitation.
- Preserves: unchanged protocol-v1 and protocol-v2 behavior.

- [ ] **Step 1: Write failing protocol-v3 serialization/parser tests.**

```python
prepared = prepare_launch_request(
    argv,
    worker_env,
    "/workspace",
    [],
    protocol_version=3,
    cwd_record=cwd_record,
    root_records=root_records,
    policy_digest_override=combined_digest,
    network_record=NetworkLaunchRecord(
        task_id="task-7",
        task_generation=3,
        launch_nonce="ab" * 16,
        network_policy_digest=network_digest,
        handoff_fd=35,
        proxy_host="127.0.0.1",
        proxy_port=18080,
    ),
)
assert prepared.wire.startswith(b"AOSLAUNCH/3\n")
```

Require v3 to reject a missing/duplicate network record, FD below 5, wrong proxy
ABI, malformed generation/digest, newline injection, and network fields in v1/v2.
Require v2 expected progress to remain exactly `R,S,I,P,N,A`.

- [ ] **Step 2: Run the protocol tests and verify RED.**

Run: `python -m pytest tests/conformance/test_m4b_unit.py tests/conformance/test_native_landlock_unit.py -k 'protocol or launch_request' -v`

- [ ] **Step 3: Implement bounded `AOSLAUNCH/3` parsing in C and Python.**

Add fixed-size storage for task ID, generation, network digest, handoff FD,
loopback address, and port. Accept only the exact values produced by the Python
serializer. The C launcher obtains its status FD and handoff FD from validated
v3 request data; it does not trust an ambient worker environment value.

- [ ] **Step 4: Implement the v3 gate order in the native launcher.**

After `R:<nonce>` and controller setup byte `G`:

1. Create `AF_INET SOCK_STREAM | SOCK_CLOEXEC`.
2. Bind exactly `127.0.0.1:18080` and call `listen()` with the fixed bounded backlog.
3. Collect fstat, socket properties, and `SO_NETNS_COOKIE`.
4. Send one bounded adoption frame and the listener FD over the handoff seqpacket.
5. Emit `L:<network_digest>:<bounded listener evidence>`.
6. Close the launcher's listener copy.
7. Wait for controller byte `C`.
8. Close the handoff FD, then execute the existing status-FD/gate-FD normalization
   and `close_range(5, ~0u, 0)`.
9. Emit `S` and continue unchanged through `I,P,N,A` and `X`.

All socket/bind/listen/getsockopt/sendmsg/gate errors call `fail_closed()` with a
distinct bounded stage. Protocol v1/v2 execute their existing code path.

- [ ] **Step 5: Prove the native red/green behavior.**

Run: `cc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 native/fs_launcher/fs_launcher.c -o native/fs_launcher/fs_launcher`

Run: `python -m pytest tests/conformance/test_native_landlock_unit.py tests/conformance/test_m4b_unit.py -k 'launcher or protocol' -v`

Add a negative harness that withholds `C` and proves `S`/hostile exec never occurs,
then provides `C` and observes `R,L,S,I,P,N,A` in exact order.

- [ ] **Step 6: Commit the listener-producing trusted launcher.**

```bash
git add native/fs_launcher/fs_launcher.c src/agenticos/sandbox/launcher.py tests/conformance/test_native_landlock_unit.py tests/conformance/test_m4b_unit.py
git commit -m "security: export M4B listener before launcher sanitation"
```

### Task 4: Add the authoritative same-scope supervisor and least-authority broker boundary

**Files:**
- Create: `native/task_supervisor/task_supervisor.c`
- Create: `src/agenticos/sandbox/network_boundary.py`
- Create: `src/agenticos/sandbox/network_broker.py`
- Modify: `tests/conformance/test_m4b_unit.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Consumes: identity-opened supervisor, Bubblewrap, Python/runtime, broker-code,
  sealed-policy, broker-control, broker-status, listener-handoff, and optional
  synthetic-fixture FDs.
- Produces: exact broker outer PID/status, broker Bubblewrap JSON, broker readiness,
  and worker Bubblewrap execution in one inherited scope cgroup.

- [ ] **Step 1: Write failing supervisor argv/FD-contract tests.**

```python
plan = build_network_boundary_plan(
    transport_policy=policy,
    runtime_usr=authorized_usr,
    broker_code=authorized_broker,
    supervisor=authorized_supervisor,
)
assert plan.broker_environment == BROKER_ENVIRONMENT
assert "/workspace" not in plan.broker_bwrap_argv
assert "--unshare-net" not in plan.broker_bwrap_argv
assert "--clearenv" in plan.broker_bwrap_argv
assert ("--cap-drop", "ALL") in adjacent_pairs(plan.broker_bwrap_argv)
```

Require fixed broker root entries only, empty synthetic home/run/tmp, new proc/dev,
read-only `/usr` and exact broker code, no `/workspace`, no real `/home`, and no
host `/run`. M4B-1 must not mount CA or resolver material.

- [ ] **Step 2: Run the boundary tests and verify RED.**

Run: `python -m pytest tests/conformance/test_m4b_unit.py -k 'supervisor or broker_boundary' -v`

- [ ] **Step 3: Implement the native supervisor's single fixed operation.**

The C11 supervisor validates a fixed versioned FD-number contract, forks once,
execs the broker Bubblewrap command in the child through the already-open
Bubblewrap FD, reports that outer PID on a CLOEXEC status pipe, and execs the
worker Bubblewrap command in the parent. It uses no shell, PATH lookup, dynamic
configuration file, network call, or extra process. Any fork/write/exec error is
reported on the bounded status pipe and exits nonzero.

- [ ] **Step 4: Implement the M4B-1 broker boundary and deny-by-default relay.**

```python
def broker_main(contract: BrokerContract) -> NoReturn:
    sealed = read_sealed_policy_fd(contract.policy_fd)
    policy = sealed.policy
    assert_minimal_process_boundary(contract, policy)
    adopted = recv_listener_fd(
        contract.handoff_socket,
        expected_task_id=policy.task_id,
        expected_generation=policy.task_generation,
        expected_nonce=policy.launch_nonce,
        expected_policy_digest=sealed.digest,
    )
    emit_network_broker_ready(contract.status_socket, policy, adopted.evidence)
    serve_transport(policy, adopted.fd, contract.fixture_fd, contract.control_socket)
```

Before readiness, the broker verifies zero capability fields, sets and verifies
`NoNewPrivs=1`, verifies its fixed environment and synthetic filesystem view,
verifies the sealed policy, and reports code/runtime identities. In `DENY` mode
it accepts no relay. In `SYNTHETIC_FIXTURE_FD` mode it relays only the inherited
fixture socket with nonblocking bounded buffers and no call to `connect()` or
`getaddrinfo()`.

- [ ] **Step 5: Build and run supervisor/broker unit tests GREEN.**

Run: `cc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 native/task_supervisor/task_supervisor.c -o native/task_supervisor/task_supervisor`

Run: `python -m pytest tests/conformance/test_m4b_unit.py -k 'supervisor or broker' -v`

Confirm `git status --short` does not show compiled binaries; add only binary
paths, not source paths, to `.gitignore` if the new output is not already covered.
The only M4B-1 `pyproject.toml` change is registration of an `m4b_linux` pytest
marker; the runtime dependency list remains empty.

- [ ] **Step 6: Commit the same-scope supervisor and broker boundary.**

```bash
git add native/task_supervisor/task_supervisor.c src/agenticos/sandbox/network_boundary.py src/agenticos/sandbox/network_broker.py tests/conformance/test_m4b_unit.py pyproject.toml .gitignore
git commit -m "security: place M4B broker inside authoritative task scope"
```

### Task 5: Compose the broker readiness barrier with the M4A runner

**Files:**
- Create: `src/agenticos/sandbox/m4b_runner.py`
- Modify: `src/agenticos/sandbox/m4a_runner.py`
- Modify: `src/agenticos/sandbox/runtime_boundary.py`
- Modify: `src/agenticos/sandbox/__init__.py`
- Modify: `tests/conformance/test_m4b_unit.py`

**Interfaces:**
- Consumes: M4A namespace/cgroup helpers, protocol-v3 launcher, supervisor plan,
  broker status/control channels, and immutable transport policy.
- Produces: `CapabilityTransportRunner` and authenticated combined launch evidence.
- Preserves: `NamespaceLandlockRunner` protocol-v2 behavior byte-for-byte at its
  external gate/evidence contract.

- [ ] **Step 1: Write failing state-machine tests for the required barrier order.**

```python
assert fake_launch.events == [
    "CONTAINMENT_VERIFIED",
    "NAMESPACE_BOUNDARY_VERIFIED",
    "BROKER_PROCESS_VERIFIED",
    "TRUSTED_LAUNCHER_ENTERED",
    "NETWORK_LISTENER_EXPORTED",
    "NETWORK_BROKER_READY",
    "FD_SET_SANITIZED",
    "SANDBOX_IDENTITIES_VERIFIED",
    "FILESYSTEM_POLICY_PREPARED",
    "NO_NEW_PRIVS_SET",
    "FILESYSTEM_POLICY_APPLIED",
    "WORKER_EXEC_ATTEMPTED",
]
assert fake_launch.controller_writes == [
    ("namespace_gate", b"G"),
    ("launcher_setup_gate", b"G"),
    ("network_close_gate", b"C"),
    ("final_exec_gate", b"X"),
]
```

Add one fault at every transition: missing/duplicate/malformed supervisor status,
wrong broker PID/process start time, wrong executable/code identity, wrong host
netns, wrong cgroup, early broker readiness, wrong listener evidence, wrong task
identity/generation/nonce/digest, readiness lost before `C`, `S` before readiness,
and worker marker before `X`.

- [ ] **Step 2: Run state-machine tests and verify RED.**

Run: `python -m pytest tests/conformance/test_m4b_unit.py -k 'runner or readiness or ordering' -v`

- [ ] **Step 3: Extract only reusable M4A launch helpers without changing M4A semantics.**

Move bounded pipe creation, source-FD closure, cgroup-relative calculation,
process cleanup, status reading, and final result assembly into private helpers
called by both runners. Keep `NamespaceLandlockRunner.run()` on protocol v2 and
prove its existing events, controller writes, policy digest, and transcript are
unchanged in unit tests.

- [ ] **Step 4: Implement `CapabilityTransportRunner`.**

It opens/verifies the supervisor and broker sources by device/inode/type, creates
the sealed policy and private socketpairs/pipes, builds broker and worker bwrap
argv, launches the supervisor through `systemd-run --user --scope`, reads both
Bubblewrap status streams, discovers the authoritative cgroup, and verifies:

```text
supervisor PID -> exact scope cgroup
broker outer child PID -> same exact cgroup + host netns + expected executable
worker outer child PID -> same exact cgroup + six M4A namespaces
broker and worker netns -> distinct
```

Only after broker process evidence and M4A namespace evidence pass does it release
the namespace gate. It authenticates launcher `R,L`, compares launcher listener
evidence with broker adoption evidence, authenticates `NETWORK_BROKER_READY`,
rechecks broker liveness/process identity/cgroup, writes `C`, then authenticates
`S,I,P,N,A` and writes `X`.

- [ ] **Step 5: Run state-machine and complete M4A unit tests GREEN.**

Run: `python -m pytest tests/conformance/test_m4b_unit.py -v`

Run: `python -m pytest tests/conformance/test_m4a_unit.py -v`

- [ ] **Step 6: Commit the composed pre-exec readiness barrier.**

```bash
git add src/agenticos/sandbox/m4b_runner.py src/agenticos/sandbox/m4a_runner.py src/agenticos/sandbox/runtime_boundary.py src/agenticos/sandbox/__init__.py tests/conformance/test_m4b_unit.py
git commit -m "security: gate hostile exec on authenticated broker readiness"
```

### Task 6: Prove M4B-1 transport, revocation, and cleanup on the recorded host

**Files:**
- Modify: `tests/fixtures/hostile_worker.py`
- Modify: `tests/conformance/test_m4b_integration.py`
- Modify: `src/agenticos/sandbox/network_broker.py`
- Modify: `src/agenticos/sandbox/m4b_runner.py`

**Interfaces:**
- Consumes: `CapabilityTransportRunner`, synthetic connected fixture sockets,
  hostile descendant scenarios, and existing cgroup cleanup helpers.
- Produces: fixture-controlled M4B-1 proof and terminal transport evidence.

- [ ] **Step 1: Add bounded hostile-worker proxy/route/DNS/FD scenarios.**

```python
def scenario_m4b_transport(args):
    before = sorted(int(name) for name in os.listdir("/proc/self/fd") if name.isdigit())
    with socket.create_connection(("127.0.0.1", 18080), timeout=args.timeout) as stream:
        stream.sendall(args.canary.encode("ascii"))
        reply = stream.recv(256).decode("ascii")
    return make_result(args.scenario, args.target, utc_now_iso(), succeeded=True,
                       details={"reply": reply, "fds_before": before})
```

Separate scenarios inspect `/proc/net/route`, `/proc/net/ipv6_route`, resolv.conf
visibility, direct host/Windows/LAN fixture reachability, and live FDs without
enumerating unrelated host data.

- [ ] **Step 2: Write failing positive and identity/adoption integration tests.**

Prove exact fixed proxy relay, broker/worker same cgroup, broker host netns,
worker isolated netns, matching listener fstat/netns cookie, fixed worker ABI,
and hostile FDs exactly `{0,1,2}`. Inject substituted listener, wrong socket type,
wrong address/port, stale policy, second FD, second adoption, and mismatched cookie.

- [ ] **Step 3: Write failing readiness and lifecycle tests.**

Kill broker before readiness, after readiness but before `C`, after `C` but before
`X`, and after hostile exec. Inject controller exceptions at each gate. Revoke
and expire an active relay and prove the fixture receives no bytes after the
terminal boundary. Cancel with an open half-closed connection.

- [ ] **Step 4: Write descendant and M4A non-regression tests.**

Run approved and denied transport attempts from root, child, grandchild, setsid,
new process group, parent-exit, double-fork, rapid-spawn, and signal-ignoring
shapes. Require recursive empty cgroup, stopped scope, no attributable PID, no
listener/control/private artifact, `/workspace` invariants, zero credentials,
zero capabilities, and M4A filesystem/network/Unix-socket denials.

- [ ] **Step 5: Run the focused suite and verify RED.**

Run: `.venv/bin/python -m pytest tests/conformance/test_m4b_integration.py -v`

- [ ] **Step 6: Implement bounded relay/revocation and cleanup until GREEN.**

Use nonblocking selectors, fixed buffer caps, absolute monotonic deadlines, one
connection in M4B-1, byte accounting before each write, and abortive close on
expiry/revocation. Broker EOF/crash is never treated as readiness or graceful
success. The controller's failure path closes every gate/control FD and calls the
existing authoritative `_cancel`/recursive-drain logic.

- [ ] **Step 7: Run M4B-1 and M4A integration suites GREEN.**

Run: `.venv/bin/python -m pytest tests/conformance/test_m4b_integration.py -v`

Run: `.venv/bin/python -m pytest tests/conformance/test_m4a_integration.py -v`

- [ ] **Step 8: Commit the real-host M4B-1 proof.**

```bash
git add src/agenticos/sandbox/network_broker.py src/agenticos/sandbox/m4b_runner.py tests/fixtures/hostile_worker.py tests/conformance/test_m4b_integration.py
git commit -m "security: prove M4B capability transport lifecycle"
```

### Task 7: Normalize M4B-1 evidence and record the no-Connected-Build claim

**Files:**
- Modify: `src/agenticos/sandbox/m4b_runner.py`
- Modify: `tests/conformance/test_m4b_unit.py`
- Modify: `tests/conformance/test_m4b_integration.py`
- Create: `docs/phase-zero/connected-build-boundary.md`
- Modify: `docs/roadmap.md`
- Modify: `docs/phase-zero/runtime-boundary.md`
- Modify: `docs/phase-zero/sandbox-conformance.md`

**Interfaces:**
- Consumes: all verified M4B-1 observations.
- Produces: normalized M4B-1 events, documentation, and an explicit statement
  that M4B-1 earns no Connected Build security claim.

- [ ] **Step 1: Write failing evidence inclusion/exclusion tests.**

```python
payload = run.event("NETWORK_TRANSPORT_BOUNDARY_VERIFIED").payload
assert payload["milestone"] == "M4B-1"
assert payload["connected_build_authorized"] is False
assert payload["proxy_abi"] == "127.0.0.1:18080"
assert payload["broker_cgroup_verified"] is True
assert payload["listener_evidence_match"] is True
serialized = json.dumps(payload)
assert str(layout.assigned_worktree) not in serialized
assert "AOS_CANARY_" not in serialized
```

Require exact supervisor/broker identities, namespaces, cgroup, capability/NNP,
policy digest, listener evidence, readiness order, relay totals, terminal reason,
recursive emptiness, and no host locators or canary payloads.

- [ ] **Step 2: Run evidence tests and verify RED.**

Run: `python -m pytest tests/conformance/test_m4b_unit.py tests/conformance/test_m4b_integration.py -k evidence -v`

- [ ] **Step 3: Emit normalized events and write measured M4B-1 documentation.**

Document exact host capabilities, transcript, broker boundary, fixture relay,
failure matrix, cleanup proof, limitations, and the absence of a Connected Build
claim. Mark M4B-2 as unavailable until its dependency/ECH gate passes.

- [ ] **Step 4: Run evidence and documentation checks GREEN.**

Run: `git diff --check`

Run: `python -m pytest tests/conformance/test_m4b_unit.py tests/conformance/test_m4b_integration.py -k evidence -v`

- [ ] **Step 5: Commit M4B-1 evidence and documentation.**

```bash
git add src/agenticos/sandbox/m4b_runner.py tests/conformance/test_m4b_unit.py tests/conformance/test_m4b_integration.py docs/phase-zero/connected-build-boundary.md docs/phase-zero/runtime-boundary.md docs/phase-zero/sandbox-conformance.md docs/roadmap.md
git commit -m "docs: record M4B-1 transport boundary evidence"
```

### Task 8: Earn the M4B-1 checkpoint

**Files:**
- Verify all M4B-1 and prior milestone files; modify only to correct defects exposed by verification.

**Interfaces:**
- Consumes: all M2B/M3B/M4A/M4B-1 tests and documentation.
- Produces: independently reviewed, repeatable, synchronized M4B-1 checkpoint.

- [ ] **Step 1: Inspect the complete milestone diff and forbidden-material scan.**

Run: `git diff fd90db6ec51f2d0d3103f636c50e2684c7bee796 --check`

Run: `git diff --stat fd90db6ec51f2d0d3103f636c50e2684c7bee796`

Run: `git grep -nE '(OPENAI_API_KEY|ANTHROPIC_API_KEY|BEGIN .*PRIVATE KEY)' -- ':!tests/**' ':!docs/**'`

- [ ] **Step 2: Build native components warning-clean.**

Run: `cc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 native/fs_launcher/fs_launcher.c -o native/fs_launcher/fs_launcher`

Run: `cc -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 native/task_supervisor/task_supervisor.c -o native/task_supervisor/task_supervisor`

- [ ] **Step 3: Run focused Linux suites serially.**

Run: `.venv/bin/python -m pytest tests/conformance/test_m4b_unit.py tests/conformance/test_m4b_integration.py -v`

Run: `.venv/bin/python -m pytest tests/conformance/test_m4a_unit.py tests/conformance/test_m4a_integration.py -v`

Run: `.venv/bin/python -m pytest tests/conformance/test_native_landlock_unit.py tests/conformance/test_native_landlock_integration.py tests/conformance/test_cgroup_integration.py -v`

- [ ] **Step 4: Obtain an independent security review and resolve every critical/important finding.**

The reviewer checks listener authority, supervisor/cgroup inheritance, broker
least authority, readiness ordering, FD closure, lifecycle, evidence, and M4A
regression. Re-run the focused test containing each correction.

- [ ] **Step 5: Run the complete Linux suite three consecutive times.**

Run: `for i in 1 2 3; do .venv/bin/python -m pytest || exit 1; done`

- [ ] **Step 6: Audit residual task state.**

Run: `systemctl --user list-units 'aos-*' --all --no-legend`

Run: `find /sys/fs/cgroup/user.slice -maxdepth 8 -type d -name 'aos-*' -print 2>/dev/null`

Run the project fixture cleanup probe and require no broker PID, listener/control
socket, private task directory, or populated task hierarchy.

- [ ] **Step 7: Run Windows regression and synchronize the checkpoint.**

Run on Windows: `python -m pytest`

Then run:

```bash
git status --short
git push origin main
git ls-remote origin main
```

Record the exact local/WSL/Windows/origin SHA. M4B-2 begins only after explicit
approval of the M4B-1 checkpoint and Task 9 dependency report.

---

## M4B-2 — Authenticated HTTPS Policy

### Task 9: Complete the security-critical dependency and ECH feasibility gate

**Files:**
- Create: `docs/phase-zero/m4b-https-dependency-review.md`
- Create: `tests/research/test_m4b_tls_stack_probe.py`
- Modify: `docs/phase-zero/host-capabilities.md`

**Interfaces:**
- Consumes: authoritative upstream metadata/source for candidate HTTP/1.1, TLS,
  ECH inspection, IDNA, and certificate-generation components.
- Produces: an exact approved stack proposal and a fixture proof that it can
  reject offered ECH before accepting worker hostname identity.

- [ ] **Step 1: Inventory the recorded Linux runtime without installing anything.**

Record exact Python/OpenSSL versions, `_ssl` linkage, system CA layout, compiler,
available build toolchain, and installed candidate packages using import metadata,
`openssl version -a`, `ldd`, `dpkg-query`, and hashes of exact artifacts.

- [ ] **Step 2: Evaluate exact candidates against one fixed table.**

For each candidate record exact version, authoritative source URL, license,
archive/wheel hash, transitive/native dependencies, Python/OpenSSL compatibility,
published advisories, parser limits, deterministic pin, and runtime closure.
Evaluate at minimum:

```text
HTTP/1.1 state machine: h11 0.16.0 candidate
IDNA normalization: idna 3.10 candidate
certificate generation: cryptography 46.0.2 candidate
TLS/ECH inspection: OpenSSL ClientHello callback or a separately reviewed equivalent
```

Versions are candidates, not installation authorization; replace a candidate only
when the report cites authoritative newer metadata and explains the security impact.

- [ ] **Step 3: Write and run a disposable synthetic ECH probe outside production code.**

The fixture sends ordinary matching SNI, mismatching SNI, missing SNI, GREASE ECH,
and a syntactically valid ECH extension. The candidate stack must expose the
ClientHello extension before accepting TLS and return an explicit deny result for
both ECH cases. It must not infer the hidden name from CONNECT.

Run: `.venv/bin/python -m pytest tests/research/test_m4b_tls_stack_probe.py -v`

- [ ] **Step 4: Prove candidate curl/Git ECH and proxy controls.**

Record the exact installed curl/Git versions and TLS backend. Prove curl's
explicit `--ech false` behavior when supported and identify the exact Git/libcurl
configuration used by the fixture. Client configuration is defense in depth;
the broker ECH deny test remains required.

- [ ] **Step 5: Stop for explicit dependency approval.**

Do not edit `pyproject.toml`, install a package, vendor source, or modify production
broker code in this task. If no stack exposes reliable ECH inspection and strict
HTTP/1.1 semantics, mark M4B-2 blocked and return the evidence rather than
weakening exact-hostname authorization.

- [ ] **Step 6: Commit and push only the research report/probe checkpoint after review.**

```bash
git add docs/phase-zero/m4b-https-dependency-review.md docs/phase-zero/host-capabilities.md tests/research/test_m4b_tls_stack_probe.py
git commit -m "docs: evaluate M4B HTTPS security dependencies"
git push origin main
```

### Task 10: Implement exact HTTPS grants and hostname normalization

**Files:**
- Create: `src/agenticos/sandbox/network_policy.py`
- Create: `tests/conformance/test_m4b_https_unit.py`
- Create: `requirements/m4b-https.lock`
- Modify: `src/agenticos/sandbox/network_models.py`
- Modify: `src/agenticos/sandbox/runtime_boundary.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Produces: `NetworkGrant`, `NetworkPolicy`, `NormalizedAuthority`,
  `normalize_https_authority()`, `authorize_grant()`, and canonical policy digest.
- Consumes: only the explicitly approved IDNA implementation from Task 9.

- [ ] **Step 1: Write failing grant and authority tests.**

```python
assert normalize_https_authority("approved.example.test") == NormalizedAuthority(
    hostname_alabel="approved.example.test", port=443
)
assert normalize_https_authority("approved.example.test:443") == NormalizedAuthority(
    hostname_alabel="approved.example.test", port=443
)

@pytest.mark.parametrize("value", [
    "approved.example.test.", "*.example.test", "user@approved.example.test",
    "127.0.0.1", "[::1]", "approved.example.test:444", "approved..example.test",
])
def test_invalid_or_ambiguous_authority_is_rejected(value):
    with pytest.raises(NetworkPolicyError):
        normalize_https_authority(value)
```

Add Unicode/IDNA valid and confusion cases, percent/control/whitespace forms,
duplicate grants, invalid methods, expiry before activation, wildcard/suffix
grants, wrong protocol/port, and task/generation/nonce mismatch.

- [ ] **Step 2: Run unit tests and verify RED.**

Run: `python -m pytest tests/conformance/test_m4b_https_unit.py -k 'grant or authority' -v`

- [ ] **Step 3: Apply only the separately approved dependency pins.**

Copy the exact approved Task 9 names and versions into `pyproject.toml` and write
`requirements/m4b-https.lock` with exact artifact URLs/hashes and transitive/native
identity notes. Install only from those pins in the controlled Linux development
environment. Re-run the Task 9 identity/version probe and require exact equality;
an unapproved resolver, parser, TLS, IDNA, or certificate package stops execution.

- [ ] **Step 4: Implement frozen grants and canonical normalization.**

```python
@dataclass(frozen=True)
class NetworkGrant:
    grant_id: str
    hostname_alabel: str
    port: int
    allowed_methods: tuple[str, ...]
    purpose: str
    expires_at_monotonic_ns: int
    connection_limit: int
    byte_limit: int

def authorize_grant(
    policy: NetworkPolicy,
    authority: NormalizedAuthority,
    method: str,
    now_ns: int,
) -> NetworkGrant:
    matches = [
        grant
        for grant in policy.grants
        if NormalizedAuthority(grant.hostname_alabel, grant.port) == authority
    ]
    if len(matches) != 1:
        raise NetworkPolicyError("exactly one active grant is required")
    grant = matches[0]
    if now_ns >= grant.expires_at_monotonic_ns or method not in grant.allowed_methods:
        raise NetworkPolicyError("grant is expired or method is unauthorized")
    return grant
```

The canonical policy includes versioned resolver/special-address/broker protocols,
approval source/reference, wall audit times, and monotonic lifetime. No host
locator, FD number, CA private material, or unnormalized hostname enters it.
The M4B-2 policy also includes `task_ca_certificate_digest`; trusted setup
generates the CA before canonicalizing and sealing the final policy.

- [ ] **Step 5: Extend only the connected worker environment/mount plan.**

Add the read-only identity-bound public CA mount at
`/opt/agenticos/network-ca.pem` for M4B-2 profiles. Do not modify the M4A plan or
host/general sandbox trust stores. Tool invocations receive explicit proxy and CA
arguments in their qualification tasks rather than ambient controller config.

- [ ] **Step 6: Run authority and M4A policy tests GREEN.**

Run: `python -m pytest tests/conformance/test_m4b_https_unit.py -k 'grant or authority' -v`

Run: `python -m pytest tests/conformance/test_m4a_unit.py -k 'environment or runtime_plan or digest' -v`

- [ ] **Step 7: Commit the HTTPS capability model.**

```bash
git add src/agenticos/sandbox/network_policy.py src/agenticos/sandbox/network_models.py src/agenticos/sandbox/runtime_boundary.py tests/conformance/test_m4b_https_unit.py pyproject.toml requirements/m4b-https.lock
git commit -m "security: define exact-hostname HTTPS grants"
```

### Task 11: Implement broker-owned resolution and special-address denial

**Files:**
- Create: `src/agenticos/sandbox/network_resolution.py`
- Create: `src/agenticos/sandbox/special_addresses.py`
- Modify: `src/agenticos/sandbox/network_boundary.py`
- Modify: `tests/conformance/test_m4b_https_unit.py`
- Create: `tests/fixtures/synthetic_resolver.py`

**Interfaces:**
- Consumes: one normalized approved hostname and versioned host-topology snapshot.
- Produces: `ResolutionDecision`, `ValidatedSockaddr`, `resolve_all_once()`,
  `validate_all_addresses()`, and `connect_validated_sockaddr()`.

- [ ] **Step 1: Write failing all-address and topology-policy tests.**

```python
decision = validate_all_addresses(
    hostname="approved.example.test",
    results=[public_ipv4_result, private_ipv4_result],
    topology=recorded_topology,
)
assert decision.allowed is False
assert decision.reason == "PROHIBITED_ADDRESS_IN_COMPLETE_RESULT_SET"
```

Cover duplicate A/AAAA, unexpected family/type/protocol, loopback, private, CGNAT,
link-local, metadata, multicast, documentation, benchmarking, ULA, mapped IPv6,
NAT64, WSL resolver/gateway/interface/subnet, Windows host fixture, LAN route,
public IPv6 when the certified host lacks an IPv6 default route, empty results,
and resolver failure.

- [ ] **Step 2: Run resolver tests and verify RED.**

Run: `python -m pytest tests/conformance/test_m4b_https_unit.py -k 'resolution or address or topology' -v`

- [ ] **Step 3: Implement one-shot `getaddrinfo` collection.**

Call `socket.getaddrinfo(hostname, 443, family=AF_UNSPEC, type=SOCK_STREAM,
proto=IPPROTO_TCP)` exactly once per origin connection. Convert results to immutable
numeric sockaddrs, deduplicate canonically, reject ambiguity, validate every entry,
and discard the resolver hostname from the connect call.

`connect_validated_sockaddr()` receives only `ValidatedSockaddr` and calls
`socket.socket(family, SOCK_STREAM)` plus `connect(sockaddr)`; its signature has
no hostname parameter, making accidental re-resolution impossible.

For public-service-free conformance, define a private `FixtureFdConnector` used
only when `CapabilityTransportRunner` receives test-only inherited origin FDs.
It returns the exact connected fixture FD while recording the synthetic logical
sockaddr. It is not selectable from `NetworkPolicy`, worker input, environment,
or a production runner constructor. Production uses only
`ValidatedSockaddrConnector`.

- [ ] **Step 4: Build the versioned special-address/topology snapshot.**

Use current IANA registry data committed in deterministic normalized form plus a
trusted controller snapshot of `/proc/net/route`, IPv6 routes, interface addresses,
gateway, and resolver endpoint. The broker receives only the normalized sealed
snapshot/digest. Reject a host topology that differs from the certified mode in
an unsupported way, including a newly usable IPv6 default route.

- [ ] **Step 5: Prove no dedicated DNS parser/cache was added.**

Tests monkeypatch `socket.getaddrinfo` with a call counter and require one call
per new origin connection, zero broker cache entries, no TTL/CNAME dependency,
and no call from `connect_validated_sockaddr()`.

- [ ] **Step 6: Run resolver/address tests GREEN and commit.**

Run: `python -m pytest tests/conformance/test_m4b_https_unit.py -k 'resolution or address or topology' -v`

```bash
git add src/agenticos/sandbox/network_resolution.py src/agenticos/sandbox/special_addresses.py src/agenticos/sandbox/network_boundary.py tests/conformance/test_m4b_https_unit.py tests/fixtures/synthetic_resolver.py
git commit -m "security: make broker DNS and address validation authoritative"
```

### Task 12: Implement task-scoped CA, TLS hostname consistency, and ECH denial

**Files:**
- Create: `src/agenticos/sandbox/network_tls.py`
- Modify: `src/agenticos/sandbox/network_broker.py`
- Modify: `tests/conformance/test_m4b_https_unit.py`
- Create: `tests/fixtures/synthetic_tls_origin.py`
- Create: `tests/fixtures/tls_client_hello.py`

**Interfaces:**
- Consumes: approved Task 9 TLS/certificate stack, `NetworkGrant`, and one
  `ValidatedSockaddr`.
- Produces: `TaskCertificateAuthority`, `WorkerTlsDecision`, `OriginTlsDecision`,
  and independently authenticated worker/origin TLS channels.

- [ ] **Step 1: Write failing per-task CA lifecycle tests.**

Create two task generations and require distinct CA keys/certificates. Require the
worker mount input to contain only PEM certificate blocks, never a private-key
block. Search broker-visible temporary roots after normal exit, failure, and
cancellation and require no key artifact.

- [ ] **Step 2: Write failing ClientHello/SNI/ECH tests.**

```python
@pytest.mark.parametrize("case,allowed", [
    ("matching_sni", True),
    ("mismatching_sni", False),
    ("missing_sni", False),
    ("grease_ech", False),
    ("valid_ech_extension", False),
])
def test_worker_clienthello_policy(tls_fixture, case, allowed):
    assert tls_fixture.evaluate(case).allowed is allowed
```

Cover fragmented ClientHello within the approved bounded implementation, oversized
or malformed records, TLS below the supported floor, unsupported ALPN, HTTP/2
offer without `http/1.1`, and post-CONNECT non-TLS bytes.

- [ ] **Step 3: Implement sealed setup-time per-task CA transfer and exact leaf issuance.**

Before launching the supervisor, the trusted controller setup creates the CA in
memory, writes the private key to a fully sealed broker-only memfd, writes the
public certificate to a separate fully sealed memfd, and includes the public
certificate digest in the immutable policy. Only the public FD enters the worker
Bubblewrap mount plan. Only the private FD enters the broker boundary. The broker
loads the key, proves its public key matches the committed certificate, closes
the private memfd, retains key material only in process memory, and issues
bounded-lifetime leaves only for active exact grants. The controller closes every
private-key FD copy, overwrites mutable serialization buffers where the approved
implementation permits, releases all private-key references before hostile
release, and never writes a key file. The security claim is absence from
worker-visible or persistent storage, not forensic erasure of trusted-process
memory.

- [ ] **Step 4: Implement worker-side TLS and ECH rejection.**

Use the Task 9 approved pre-ClientHello mechanism to inspect the offered extension
set before accepting the handshake. Reject ECH presence, require ordinary SNI
equal to CONNECT's normalized grant, and advertise only `http/1.1`. A Python
`sni_callback` alone is insufficient unless Task 9 proved an independent raw ECH
inspection layer.

- [ ] **Step 5: Implement origin TLS without re-resolution.**

Wrap the already connected numeric-address socket using the original approved
hostname as `server_hostname`, system trust roots, certificate verification,
hostname verification, and ALPN `http/1.1`. Reject certificate, hostname, ALPN,
or handshake failure. Do not pass the hostname to a connector after resolution.

- [ ] **Step 6: Run TLS tests GREEN and commit.**

Run: `python -m pytest tests/conformance/test_m4b_https_unit.py -k 'tls or sni or ech or certificate' -v`

```bash
git add src/agenticos/sandbox/network_tls.py src/agenticos/sandbox/network_broker.py tests/conformance/test_m4b_https_unit.py tests/fixtures/synthetic_tls_origin.py tests/fixtures/tls_client_hello.py
git commit -m "security: authenticate M4B worker and origin TLS hostnames"
```

### Task 13: Implement strict HTTP/1.1, method policy, and redirect reauthorization

**Files:**
- Create: `src/agenticos/sandbox/network_http.py`
- Modify: `src/agenticos/sandbox/network_broker.py`
- Modify: `tests/conformance/test_m4b_https_unit.py`
- Create: `tests/fixtures/synthetic_https_service.py`

**Interfaces:**
- Consumes: approved strict parser from Task 9, worker TLS stream, origin TLS stream,
  and active exact grant.
- Produces: bounded `HttpRequestDecision`, `RedirectObservation`, and streamed
  request/response relay.

- [ ] **Step 1: Write failing strict parser and smuggling tests.**

Cover conflicting Content-Length, Content-Length plus Transfer-Encoding,
unsupported transfer coding, obs-fold, invalid header names/values, bare LF,
oversized start line/header block/field count/field, duplicate or missing Host,
absolute-form mismatch, authority-form after TLS, nested CONNECT, Upgrade,
HTTP/2 preface, extra bytes after terminal parser error, and slowloris deadlines.

- [ ] **Step 2: Write failing authority/method/persistence tests.**

Require Host normalized equality with CONNECT and SNI for every request. Prove
`GET`/`HEAD` general fetch, approved Git `POST`, denied mutation methods, grant
expiry between persistent requests, and reauthorization of every request.

- [ ] **Step 3: Write failing redirect tests without response rewriting.**

The synthetic origin returns same-origin, cross-authority, and HTTPS-to-HTTP
Location headers containing secret-looking paths/queries. Require the response
to reach the worker unchanged, evidence to contain only normalized
scheme/hostname/port, and a followed cross-authority request to receive a fresh
grant decision. Strip only Alt-Svc; do not rewrite Location.

- [ ] **Step 4: Run HTTP tests and verify RED.**

Run: `python -m pytest tests/conformance/test_m4b_https_unit.py -k 'http or smuggling or redirect or method' -v`

- [ ] **Step 5: Implement the bounded HTTP/1.1 state machine and streaming relay.**

Feed bounded chunks into the approved parser, enforce explicit per-state byte and
time caps, authorize before forwarding headers/body, strip hop-by-hop proxy fields
and Alt-Svc, never log header values/path/query/body, and abort both directions on
parser/policy/expiry failure. Disable nested CONNECT and Upgrade unconditionally.

- [ ] **Step 6: Run HTTP tests GREEN and commit.**

Run: `python -m pytest tests/conformance/test_m4b_https_unit.py -k 'http or smuggling or redirect or method' -v`

```bash
git add src/agenticos/sandbox/network_http.py src/agenticos/sandbox/network_broker.py tests/conformance/test_m4b_https_unit.py tests/fixtures/synthetic_https_service.py
git commit -m "security: enforce strict M4B HTTP authority policy"
```

### Task 14: Prove same-IP hostname separation, limits, revocation, and evidence

**Files:**
- Modify: `src/agenticos/sandbox/m4b_runner.py`
- Modify: `src/agenticos/sandbox/network_broker.py`
- Modify: `tests/conformance/test_m4b_integration.py`
- Create: `tests/conformance/test_m4b_https_integration.py`
- Modify: `tests/fixtures/synthetic_https_service.py`

**Interfaces:**
- Consumes: complete M4B-2 broker and two virtual synthetic origins on one IP.
- Produces: real-host exact-hostname, lifecycle, and secret-free evidence proof.

- [ ] **Step 1: Implement one-IP/two-host synthetic fixtures.**

Both `approved.example.test` and `evil.example.test` resolve through the synthetic
resolver to the same logical permitted fixture address. The private conformance
runner supplies already-connected origin FDs, so the end-to-end suite uses no
public service and creates no production special-address exception. The TLS/HTTP
service selects distinct observable behavior by SNI/Host and has certificates
covering only the intended synthetic identities. Separate tests require
production mode to reject every inherited fixture FD and require real
loopback/private/LAN destinations to remain prohibited.

- [ ] **Step 2: Write the required confusion matrix.**

Prove allowed approved/approved/approved and deny approved/evil/approved,
approved/approved/evil, evil/approved/approved, and direct-IP cases. Add explicit
default-port equivalence and rejection of trailing dot, userinfo, wildcard, and
IDNA-confusion forms.

- [ ] **Step 3: Write limits and lifecycle tests.**

Exercise connection, byte, header, body-stream, idle, and absolute grant limits.
Expire/revoke before resolution, between resolution/connect, during worker TLS,
during origin TLS, between persistent requests, and mid-body. Kill broker at each
launch/runtime stage and require whole-task cancellation.

- [ ] **Step 4: Write authenticated evidence inclusion/exclusion tests.**

Require task/generation/nonce/policy/grant, process/cgroup/netns/listener identities,
resolver results/selected sockaddr, CONNECT/SNI/Host/ECH/ALPN decisions, origin TLS
result, redirect authorities, method, byte totals, terminal reason, and recursive
cleanup. Require absence of paths, queries, header values, bodies, canaries,
private keys, provider data, and host source locators.

- [ ] **Step 5: Run the focused integration suite and resolve failures.**

Run: `.venv/bin/python -m pytest tests/conformance/test_m4b_https_integration.py -v`

- [ ] **Step 6: Commit exact-hostname and lifecycle proof.**

```bash
git add src/agenticos/sandbox/m4b_runner.py src/agenticos/sandbox/network_broker.py tests/conformance/test_m4b_integration.py tests/conformance/test_m4b_https_integration.py tests/fixtures/synthetic_https_service.py
git commit -m "security: prove M4B exact-hostname HTTPS boundary"
```

### Task 15: Qualify curl and Git smart HTTPS on synthetic infrastructure

**Files:**
- Create: `tests/fixtures/synthetic_git_https.py`
- Modify: `tests/conformance/test_m4b_https_integration.py`
- Modify: `docs/phase-zero/connected-build-boundary.md`
- Modify: `docs/phase-zero/host-capabilities.md`

**Interfaces:**
- Consumes: exact recorded curl/Git binaries, fixed proxy ABI, task CA certificate,
  and synthetic HTTPS/Git origins.
- Produces: version-specific curl and Git smart-fetch qualification.

- [ ] **Step 1: Record and identity-bind exact tool binaries/runtime closure.**

Capture path, open-FD identity, SHA-256, owner/mode/capabilities, version, linked
TLS/libcurl dependencies, and required runtime files. Reject unexpected identity
or configuration files. Do not expose real Git config, credential helpers, or HOME.

- [ ] **Step 2: Write failing curl qualification tests.**

Invoke curl with explicit proxy, task CA, HTTPS-only protocol/redirect restrictions,
and `--ech false` when supported. Prove exact approved download, cross-host redirect
with/without a second grant, wrong CA, unapproved host, direct IP, and attempts to
override proxy/CA/ECH settings. Direct fallback fails because the worker has no route.

- [ ] **Step 3: Write failing Git smart-HTTPS qualification tests.**

Use a synthetic bare repository and smart-HTTP fixture. Invoke Git with explicit
`http.proxy`, `http.sslCAInfo`, disabled credential helpers, synthetic HOME, and
HTTPS URL. Prove clone/fetch GET+POST behavior, unapproved redirect denial,
credential absence, and no SSH/native-Git fallback.

- [ ] **Step 4: Run qualification tests and resolve failures without broadening authority.**

Run: `.venv/bin/python -m pytest tests/conformance/test_m4b_https_integration.py -k 'curl or git' -v`

If a measured tool requires HTTP/2, ECH, an unapproved method, private credentials,
or a direct route, stop and report it as unsupported rather than changing M4B-2.

- [ ] **Step 5: Record exact supported versions and commit.**

```bash
git add tests/fixtures/synthetic_git_https.py tests/conformance/test_m4b_https_integration.py docs/phase-zero/connected-build-boundary.md docs/phase-zero/host-capabilities.md
git commit -m "test: qualify curl and Git over M4B HTTPS"
```

### Task 16: Earn the first Connected Build security checkpoint

**Files:**
- Verify all M4B-2 and prior milestone files; modify only for defects exposed by verification.
- Modify: `docs/phase-zero/connected-build-boundary.md`
- Modify: `docs/roadmap.md`
- Modify: `docs/phase-zero/sandbox-conformance.md`

**Interfaces:**
- Consumes: complete M4B-2 implementation/evidence and approved dependency report.
- Produces: independently reviewed first Connected Build claim and synchronized checkpoint.

- [ ] **Step 1: Update the earned-claim documentation from measured evidence.**

State exact-hostname anonymous HTTPS only, measured curl/Git versions, route-less
worker, broker DNS/special-address/TLS/HTTP/redirect/expiry properties, dependency
identities, limitations, and claims still unavailable.

- [ ] **Step 2: Run dependency, secret, CA-key, and diff audits.**

Run: `git diff <M4B-1-SHA> --check`

Run: `git grep -nE '(OPENAI_API_KEY|ANTHROPIC_API_KEY|BEGIN .*PRIVATE KEY)' -- ':!tests/**' ':!docs/**'`

Run the task-artifact audit and require no CA private-key file or untracked broker
state after success, failure, and cancellation.

- [ ] **Step 3: Build all native components warning-clean and run focused suites.**

Run the Task 8 C build commands.

Run: `.venv/bin/python -m pytest tests/conformance/test_m4b_unit.py tests/conformance/test_m4b_https_unit.py tests/conformance/test_m4b_integration.py tests/conformance/test_m4b_https_integration.py -v`

Run: `.venv/bin/python -m pytest tests/conformance/test_m4a_unit.py tests/conformance/test_m4a_integration.py tests/conformance/test_native_landlock_unit.py tests/conformance/test_native_landlock_integration.py tests/conformance/test_cgroup_integration.py -v`

- [ ] **Step 4: Obtain independent M4B-2 security review.**

Review dependency provenance/pins, ECH proof, CA lifecycle, strict parser behavior,
same-IP confusion, DNS/all-address enforcement, origin TLS, redirects, evidence,
broker least authority, cancellation, and all M4A invariants. Resolve every
critical/important finding and re-run its focused suite.

- [ ] **Step 5: Run the complete Linux suite three consecutive times and audit cleanup.**

Run: `for i in 1 2 3; do .venv/bin/python -m pytest || exit 1; done`

Run the Task 8 systemd/cgroup cleanup commands plus the CA/private-state audit.

- [ ] **Step 6: Run Windows regression and push the synchronized checkpoint.**

Run on Windows: `python -m pytest`

Then run:

```bash
git status --short
git push origin main
git ls-remote origin main
```

Record equal Windows/WSL/local/origin SHA and only then mark M4B-2 complete.

---

## M4B-3 — Build Ecosystem Qualification

### Task 17: Add an identity-bound pip runtime and synthetic package index

**Files:**
- Create: `src/agenticos/sandbox/build_tool_profiles.py`
- Create: `tests/fixtures/synthetic_python_index.py`
- Create: `tests/conformance/test_m4b_tools_integration.py`
- Modify: `src/agenticos/sandbox/runtime_boundary.py`
- Modify: `docs/phase-zero/connected-build-boundary.md`

**Interfaces:**
- Consumes: unchanged M4B-2 network grants and exact approved Python/pip runtime objects.
- Produces: `BuildToolProfile`, `PipToolProfile`, and version-qualified synthetic
  pip fetch/install evidence.

- [ ] **Step 1: Inventory and propose the exact Linux pip runtime closure.**

Record interpreter, pip, packaging libraries, native dependencies, CA/proxy
configuration mechanism, hashes/identities, and only the required runtime files.
Stop for approval before installing or exposing a new runtime tree.

- [ ] **Step 2: Write failing profile tests.**

Require fixed identity-bound runtime sources/destinations, synthetic HOME/cache,
explicit proxy and task CA arguments, disabled version checks, no real pip config,
no keyring/credential helper, no host site-packages outside the approved closure,
and unchanged exact network grant semantics.

- [ ] **Step 3: Build a deterministic synthetic simple-index fixture.**

Serve a local TLS index, wheel, sdist, checksum, same-origin and separately granted
artifact host, plus unauthorized redirect and dependency-confusion cases. Packages
contain only fixture canaries and bounded build hooks.

- [ ] **Step 4: Run pip qualification tests.**

Prove index query, wheel download/install, sdist build isolation behavior, separate
artifact-host grant, wrong hash, unapproved host, direct route failure, proxy-ignore
failure, lifecycle-hook descendant containment, expiry/revocation, and cleanup.

Run: `.venv/bin/python -m pytest tests/conformance/test_m4b_tools_integration.py -k pip -v`

- [ ] **Step 5: Commit only after the runtime and tests preserve M4B-2 authority.**

```bash
git add src/agenticos/sandbox/build_tool_profiles.py src/agenticos/sandbox/runtime_boundary.py tests/fixtures/synthetic_python_index.py tests/conformance/test_m4b_tools_integration.py docs/phase-zero/connected-build-boundary.md
git commit -m "test: qualify pip within M4B HTTPS authority"
```

### Task 18: Add an identity-bound npm runtime and synthetic registry

**Files:**
- Modify: `src/agenticos/sandbox/build_tool_profiles.py`
- Create: `tests/fixtures/synthetic_npm_registry.py`
- Modify: `tests/conformance/test_m4b_tools_integration.py`
- Modify: `src/agenticos/sandbox/runtime_boundary.py`
- Modify: `docs/phase-zero/connected-build-boundary.md`

**Interfaces:**
- Consumes: unchanged M4B-2 grants and exact approved Linux Node/npm runtime objects.
- Produces: `NpmToolProfile` and version-qualified synthetic npm evidence.

- [ ] **Step 1: Inventory and approve the exact Linux Node/npm runtime closure.**

Record binary/module identities, linked libraries, CA/proxy configuration, default
registry behavior, lifecycle scripts, cache paths, and config lookup rules. Do not
use the Windows npm shim or expose a broad host runtime tree.

- [ ] **Step 2: Write failing npm profile tests.**

Require synthetic HOME/cache, explicit proxy/task-CA/registry configuration,
disabled user/global npmrc lookup, no tokens, no audit/telemetry endpoint unless
separately granted, no Git SSH fallback, and fixed identity-bound runtime mounts.

- [ ] **Step 3: Build a deterministic synthetic npm registry/tarball fixture.**

Include exact package metadata, tarball integrity, separately granted tarball
authority, unauthorized redirect, dependency script, optional Git+HTTPS case,
and attempts to contact audit/telemetry/unapproved endpoints.

- [ ] **Step 4: Run npm qualification tests without changing the broker authority.**

Prove metadata/tarball install, integrity, redirect grants, denied audit/telemetry,
denied direct network, lifecycle descendant containment, expiry/revocation, and
cleanup.

Run: `.venv/bin/python -m pytest tests/conformance/test_m4b_tools_integration.py -k npm -v`

- [ ] **Step 5: Commit measured npm support.**

```bash
git add src/agenticos/sandbox/build_tool_profiles.py src/agenticos/sandbox/runtime_boundary.py tests/fixtures/synthetic_npm_registry.py tests/conformance/test_m4b_tools_integration.py docs/phase-zero/connected-build-boundary.md
git commit -m "test: qualify npm within M4B HTTPS authority"
```

### Task 19: Define the gate for every additional build tool

**Files:**
- Modify: `src/agenticos/sandbox/build_tool_profiles.py`
- Modify: `tests/conformance/test_m4b_tools_integration.py`
- Modify: `docs/phase-zero/connected-build-boundary.md`
- Modify: `docs/roadmap.md`

**Interfaces:**
- Consumes: exact `BuildToolProfile` contract and M4B-2 HTTPS capability.
- Produces: an allowlisted profile registry that cannot weaken network authority.

- [ ] **Step 1: Write failing closed-registry tests.**

```python
with pytest.raises(UnsupportedBuildTool):
    build_tool_profile("arbitrary-tool")

assert build_tool_profile("pip").network_protocol == "https/http1.1"
assert build_tool_profile("npm").proxy_abi == "127.0.0.1:18080"
```

Require each profile to declare exact runtime identities, synthetic paths,
proxy/CA arguments, permitted HTTP methods, required hostname grants, fixture
suite, evidence fields, and unsupported feature set.

- [ ] **Step 2: Implement the fixed profile registry.**

The registry contains only individually reviewed tool/version profiles. It has no
user-defined command-to-mount or command-to-network mapping and cannot request
generic TCP/UDP, new ports, wildcard hosts, host HOME, runtime sockets, or provider
credentials.

- [ ] **Step 3: Add a rejection test for a tool requiring weaker networking.**

Use a synthetic client that requires UDP or opaque TCP. Require profile creation
and execution to fail with `WEAKER_NETWORK_CAPABILITY_REQUIRES_REVIEW`, leaving
the worker route-less and the existing HTTPS broker unchanged.

- [ ] **Step 4: Run the complete tool suite and commit.**

Run: `.venv/bin/python -m pytest tests/conformance/test_m4b_tools_integration.py -v`

```bash
git add src/agenticos/sandbox/build_tool_profiles.py tests/conformance/test_m4b_tools_integration.py docs/phase-zero/connected-build-boundary.md docs/roadmap.md
git commit -m "security: gate M4B build tools without network widening"
```

### Task 20: Earn the M4B-3 and complete M4B checkpoint

**Files:**
- Verify all M4B and prior milestone files; modify only for defects exposed by verification.
- Modify: `docs/phase-zero/connected-build-boundary.md`
- Modify: `docs/phase-zero/sandbox-conformance.md`
- Modify: `docs/roadmap.md`

**Interfaces:**
- Consumes: exact pip/npm profiles and the unchanged M4B-2 broker authority.
- Produces: independently reviewed, version-qualified M4B completion checkpoint.

- [ ] **Step 1: Document the exact qualified tools and unchanged authority.**

List exact runtime/tool hashes and versions, fixture scenarios, required exact
hostname grants/methods, unsupported behaviors, and the statement that M4B-3
does not broaden M4B-2 networking.

- [ ] **Step 2: Audit complete diff, dependencies, secrets, artifacts, and runtime trees.**

Run `git diff <M4B-2-SHA> --check`, dependency lock/hash verification, secret scan,
CA-private-key scan, broad-mount scan, and residual task-state audit. Inspect every
new runtime mapping and reject unmeasured host-tree exposure.

- [ ] **Step 3: Run all focused suites and native warning-clean builds.**

Run M4B-1, M4B-2, M4B-3, M4A, Landlock, and cgroup focused commands from prior
checkpoint tasks, including the complete `test_m4b_tools_integration.py` suite.

- [ ] **Step 4: Obtain independent final M4B security review.**

Review runtime identity, tool configuration lookup, credential absence, proxy/CA
enforcement, lifecycle hooks/descendants, evidence, cleanup, and proof that no
M4B-2 networking rule changed. Resolve every critical/important finding.

- [ ] **Step 5: Run three consecutive complete Linux suites and cleanup audit.**

Run: `for i in 1 2 3; do .venv/bin/python -m pytest || exit 1; done`

Require no active `aos-*` units, populated cgroups, broker/worker PIDs, listener
or control sockets, task directories, caches outside authorized task paths, or
CA private artifacts.

- [ ] **Step 6: Run Windows regression and synchronize final M4B checkpoint.**

Run on Windows: `python -m pytest`

Then run:

```bash
git status --short
git log --oneline --decorate -20
git push origin main
git ls-remote origin main
```

Record equal Windows/WSL/local/origin SHA, clean worktrees, exact Linux results,
documented Windows/Linux-only skips, independent review disposition, and the
earned/uneared claim boundary.

---

## Execution handoff

Execute only one sub-milestone at a time:

1. M4B-1 Tasks 1–8, then stop for checkpoint review.
2. M4B-2 Task 9 dependency/ECH report, then stop for explicit dependency approval.
3. M4B-2 Tasks 10–16, then stop for the first Connected Build claim review.
4. M4B-3 Tasks 17–20, with separate runtime approval before pip and npm additions.

Every execution session must use either `superpowers:subagent-driven-development`
or `superpowers:executing-plans`, apply test-driven development, and invoke
`superpowers:verification-before-completion` before any checkpoint claim or push.
