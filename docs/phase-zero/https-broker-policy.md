# Milestone 4B-2 — Authenticated HTTPS Broker Policy

M4B-2 extends the M4B-1 capability-transport substrate
([connected-build-boundary.md](connected-build-boundary.md)) with an
authenticated, task-scoped HTTPS policy served by the same least-authority
broker. Host qualification is documented in
[host-capabilities.md](host-capabilities.md) §10; the frozen destination
address policy in §11; the pinned dependency review in
[dependency-review-m4b2.md](dependency-review-m4b2.md).

## Earned claim

On the recorded, host-qualified Ubuntu 26.04/WSL2 host, AgenticOS can give an
M4A-isolated worker authenticated HTTPS access to **exactly one
controller-approved exact hostname per task**, through the M4B-1 sibling
broker, over this pipeline:

```text
CONNECT authority parse (strict, raw bytes)
  -> grant authorization (canonical byte equality, monotonic activity window)
  -> ClientHello gate (ECH extension 0xfe0d denied pre-trust; byte-verbatim replay)
  -> worker TLS termination (fresh exact-hostname SNI policy per connection,
     any second ClientHello aborts; TLS>=1.2; OP_NO_RENEGOTIATION;
     mandatory post-handshake ALPN == http/1.1)
  -> strict HTTP/1.1 parse (Host re-verified, per-request reauthorization)
  -> bounded DNS resolution + IANA special-address/SSRF policy
  -> numeric-sockaddr origin connect (no hostname on the connect path)
  -> authenticated origin TLS (CERT_REQUIRED, check_hostname, ALPN http/1.1 only)
  -> bounded verbatim relay (h11 CLIENT used for framing only)
```

Every stage emits canonical `AOSHTTPEV/1` evidence (one record per accepted
connection, one aggregate terminal), authenticated by the controller against
the launch authority (task id, generation, nonce, both policy digests).

This is a **narrow** claim. It is **not** a Connected Build claim. See
[What is not earned](#what-is-not-earned).

## Trust transitions

1. **Host qualification (explicit, per host change).**
   `qualify_host_for_https(state_dir)` computes the nine-component host
   manifest (fail-closed probes; ECH acceptance machinery must be absent from
   the loaded libssl) and records it, digest-committed, under the controller
   state dir. The operator reviews the diff against any previous record.
2. **Launch-time host gate.** Every HTTPS-flavor launch re-runs
   `verify_https_host(state_dir)`: the live manifest is recomputed and ANY
   divergence fails closed before the cert helper is even spawned.
3. **Short-lived cert helper, run to EXIT.** `generate_task_material` spawns
   the helper, which generates a per-task CA and leaf, writes all four
   material objects (CA cert, leaf cert, leaf key, binding) into fully sealed
   memfds, and EXITS. Material assembly completes before the broker launch
   chain starts — therefore before any hostile exec. See
   [CA-key lifetime](#cert-helper-ca-key-lifetime).
4. **Sealed NetworkPolicy.** The controller seals the `AOSHTTPS/1`
   NetworkPolicy — task context, CA certificate digest, the grant set, and
   the **OpenSSL runtime identity** (`python_ssl.upstream_version`) taken
   from the verified manifest — into a fully sealed memfd. This is how the
   expected OpenSSL identity reaches the broker over an authenticated
   channel: kernel-sealed, task-context-bound, digest-chained into every
   evidence record. The broker never trusts an argv string for it.
5. **Broker adoption (fail closed).** The HTTPS-flavor broker re-verifies the
   sealed transport policy and the sealed NetworkPolicy (kernel identity,
   seals, size, canonical re-encoding equality), cross-checks task
   id/generation/nonce against the transport authority, authenticates the
   cert material against the sealed binding (payload digests + task context),
   loads the leaf `SSLContext` — whose self-audit handshake proves the leaf
   chains to the sealed task CA with a SAN set of exactly the approved
   hostname — then runs the FUNCTIONAL sealed-memfd check
   (`verify_memfd_sealed`: all four immutable seals present AND writes
   denied) on every material source descriptor before closing it, and proves
   every source descriptor closed (EBADF). The post-readiness descriptor
   census contains no certificate, key, or policy source.
6. **Fail-closed startup probe.** After adoption and BEFORE the ready record,
   the broker runs `_run_https_startup_probe`:
   - the TLS startup self-test (never duplicated:
     `network_tls.run_tls_startup_self_test`) — a synthetic ECH-bearing
     ClientHello must REJECT (because of 0xfe0d), a synthetic clean
     ClientHello must ACCEPT with byte-verbatim replay (the enforcement path
     is live in THIS process); `ssl.OPENSSL_VERSION` must equal the SEALED
     expected identity; `OP_NO_RENEGOTIATION` must be exposed and verifiably
     settable; host behavior probes (MemoryBIO/SSLObject, ALPN set/get) must
     pass; the loaded libssl must export no ECH acceptance machinery;
   - the adopted worker context must harden (fresh exact-hostname SNI policy,
     TLS>=1.2) and carry `OP_NO_RENEGOTIATION` in its effective options, and
     its ALPN behavior is proven functional
     (`network_tls.run_worker_context_startup_probe`): a real MemoryBIO
     handshake offering `http/1.1` must select exactly `http/1.1`; an
     h2-only offer must select nothing (the mandatory post-handshake check
     in `terminate_worker_tls` is the enforcement for live connections);
   - the adoption proofs held in the material state must be present: the leaf
     loading self-audit ran, the functional sealed-memfd check ran on every
     material source, and the recorded network-policy seals are complete.

   Any probe failure raises `BrokerBoundaryError`: the broker exits non-zero
   WITHOUT emitting readiness, the controller's readiness channel sees EOF
   (`broker readiness channel closed before readiness`), and the existing
   liveness/ordering gates fail the launch closed before hostile exec. This
   path is proven end-to-end by tampering the sealed OpenSSL identity in a
   real launch (`test_tampered_openssl_identity_fails_closed_before_exec`).
7. **Readiness and release ordering.** Only after every verification does the
   broker emit its one canonical ready record; the M4B-1 controller gates
   (process/namespace/cgroup/FD-census/boundary comparison, fixed release
   order, liveness re-checks) are unchanged.
8. **Per-connection enforcement.** As in the pipeline above. Authorization
   failures are denied before the 200 response; the 200 is sent only after
   policy permits the TLS attempt; the gate runs before any TLS object
   exists; worker disconnects mid-handshake or mid-request terminate the
   connection with typed reasons (`worker_tls_handshake_failed`,
   `worker_closed`); origin connect/TLS stalls are bounded by the origin
   socket deadlines (connect 10 s, handshake 10 s) and end as typed
   `origin_*` denials — never hangs, never bare exceptions.
9. **Teardown and evidence.** Terminal accounting invariants mirror M4B-1
   (`total = worker_to_origin + origin_to_worker`,
   `accounted = total + discarded_unsent`, limits enforced). Revoke/expiry
   abort buffered unsent bytes. See
   [Broker reap at worker exit](#broker-reap-at-worker-exit-evidence-synthesis).

## Dual TLS stacks

On the qualified host, curl HTTPS and Git HTTPS are two independent TLS
client stacks: curl links `libcurl.so.4`/OpenSSL, `git-remote-https` links
`libcurl-gnutls.so.4`/GnuTLS. They are qualified as SEPARATE manifest
components (`curl` vs `git_https` + `gnutls`); qualifying one never qualifies
the other. The broker itself terminates and originates TLS only through
Python's `ssl` (OpenSSL), the stack the startup probe pins by identity.

## Cert-helper CA-key lifetime

The per-task CA private key exists ONLY inside the short-lived cert-helper
process: it is generated there, signs the CA and leaf certificates, is
explicitly deleted (`del` + `gc.collect()`), and the helper EXITS before the
broker launch chain starts. Only the sealed CA CERTIFICATE (public) crosses
to the broker and worker. A later broker or worker compromise therefore
cannot mint new leaves under the task CA — the signing key no longer exists
anywhere by the time hostile code can run.

## Concurrency posture

The broker's main selector thread owns the listener and the control channel;
each accepted connection is served on its own bounded daemon thread.
Simultaneous ClientHello gates are bounded by `BoundedGateGuard`;
per-connection worker-TLS termination is serialized broker-wide on one mutex
because the exact-hostname SNI policy installs on the shared task-leaf
context (a FRESH policy per connection — every firing is a fresh
authorization decision, and any second firing aborts the handshake, which
makes ECH-in-CH2 structurally unreachable); post-handshake relay runs
concurrently per connection. Aggregate byte and connection authority is
enforced across all threads by one locked accountant. Exceeding the
connection limit terminates the broker (`CONNECTION_LIMIT`), mirroring M4B-1.

## Fixture connector — non-production marking

The fixture origin path (`FixtureFdConnector`, one SCM_RIGHTS fd + bounded
JSON on the control channel) is a CONFORMANCE mechanism, never production
network authority: it is accepted at most once and only before the first
accepted connection (late, multi-fd, oversized, truncated, or malformed
fixture messages are `MALFORMED_CONTROL`), its declared addresses are
validated against the special-address policy, it is spent exactly once, and
every evidence record for the whole launch is marked `synthetic_origin=true`.
The production path resolves real DNS and connects numeric origin addresses.

## Broker reap at worker exit: evidence synthesis

A clean worker exit reaps the broker with it (unchanged M4B-1 death
semantics), so the control channel can end at EOF WITHOUT a terminal packet;
the eagerly emitted per-connection records survive the broker's death. In
that case the runner synthesizes the aggregate terminal itself from the
authenticated per-connection records only, flagged as synthesized
(`last_https_terminal_source`), never as broker-emitted. This is safe
because the launch-time liveness gates prove the broker could only have died
at or after worker exit: a mid-run broker death fails the output pump closed
before the evidence reader runs. Records after the terminal, wrong
authority, non-contiguous connection indexes, or accounting that disagrees
with the aggregate are rejected.

## Zero-grant deny-all posture

Broker-side defense in depth: a sealed NetworkPolicy with ZERO grants is the
deny-all posture. Adoption still authenticates the material (with no grant to
commit a hostname, the sealed binding's own committed hostname is adopted
after task-context authentication), the startup probe still runs, the broker
becomes ready, and every CONNECT is denied at authorization
(`authorization_no_match`, identity chain `no_grant`) before any trust stage.
The controller's own launch validation still requires exactly one grant; the
zero-grant path guarantees the broker serves nothing rather than failing
ambiguously if one is ever presented.

## Residual risks (accepted, documented)

Adversarial review of this slice surfaced the following residual risks.
Each is accepted deliberately; none crosses the earned claim.

- **Controller-resident leaf-key memfd lifetime.** The controller pins the
  sealed `leaf_key_fd` from helper return until the broker launch dups it
  into role 39; the controller never re-reads it afterwards, so the fd
  COULD be dropped immediately after the dup to shrink the exposure
  window. It is retained for the launch span by design: the memfd is
  sealed read-only, the controller is the trusted side of the boundary,
  and the worker/hostile side never sees the fd. Accepted as-is.
- **Staged-CA-dir SIGKILL persistence.** The helper stages the task CA in
  a private directory; a SIGKILL mid-launch can strand that directory on
  disk until cleanup. Only PUBLIC material (certificates, never the CA
  private key — that lives solely in helper memory and sealed memfds) can
  persist this way, so the residue is not secret-bearing.
- **ISATAP / operator-NAT64 embedded-v4 limits.** The special-address
  policy evaluates embedded IPv4 forms (6to4, Teredo/ISATAP, NAT64
  well-known and operator-defined prefixes) at the frozen IANA-registry
  level; an operator-run NAT64 or ISATAP deployment can map those ranges
  onto reachability the registry alone cannot express. Inherent to any
  registry-frozen policy; documented, not hidden.
- **Handshake-byte bound excludes replayed gate bytes.** The per-connection
  handshake byte bound does not count the ClientHello bytes the gate
  replays into the TLS handshake (they are bounded separately by the
  gate's own cap). The two bounds compose; neither is unbounded.
- **Census admits fds 0-2 by number.** The runtime fd census admits the
  standard descriptors 0-2 by number alone (they cannot be sealed or
  re-proven from inside the broker); every other descriptor is census-
  exact. A broker that starts with a hostile fd on 0-2 inherits it — the
  launch path controls all three.
- **Synthesized-terminal pre-exit sliver, hardcoded REVOKED reason.** The
  runner-synthesized aggregate (broker reaped at clean worker exit before
  emitting a terminal) covers evidence up to worker exit; a broker that
  died in the sliver between its last record and worker exit contributes
  only its already-emitted per-connection records, and the synthesized
  terminal reason is the hardcoded REVOKED rather than an observed broker
  verdict. The liveness gates bound the sliver to post-record-processing;
  no accepted connection can be lost from evidence.
- **Helper-exit-before-launch is structural, not temporal.** The CA-key
  lifetime guarantee rests on process STRUCTURE (the helper exits before
  the broker launch chain starts and before any hostile worker code can
  run), not on a measured wall-clock interlock; there is no runtime
  assertion that the helper has already exited at broker main(). The
  structural argument is total: the key exists only inside the helper's
  address space, which is gone before exposure is possible.

## What is not earned

- **No Connected Build claim.** This is task-scoped HTTPS broker policy on
  one qualified host, not build-ecosystem authorization.
- **No ECH-capable stacks.** The claim rests on the measured ABSENCE of ECH
  acceptance machinery in the qualified libssl plus the CH-gate denial of
  extension 0xfe0d. Any ECH-capable stack fails qualification/probe closed.
- **No HTTP/2.** Exactly `http/1.1` is offered and accepted, worker side and
  origin side; h2-only peers are refused.
- **No IDNA / internationalized names.** Exact canonical lowercase ASCII
  DNS names only.
- **No response-side envelope.** Origin responses are relayed byte-exact;
  h11 is used for framing delimitation only, not content policy.
- **No general browsing.** One approved exact hostname per task, one grant,
  port 443 only, strict method policy per grant purpose.
- **No multi-host authority.** A second hostname is a different task.
- **No build-ecosystem qualification** (package managers, registries,
  provider endpoints): that is M4B-3.
- No seccomp, AppArmor/LSM-stacking, malicious-kernel, traffic-analysis,
  remote-side-effect revocation, or denial-of-service claim (mirrors M4B-1).

Models reason. AgenticOS guarantees.
