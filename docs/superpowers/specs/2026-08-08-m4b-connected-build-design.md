# Milestone 4B Connected Build Capability Architecture

**Status:** Approved design, amended 2026-08-08

**Baseline:** `main` at `fd90db6ec51f2d0d3103f636c50e2684c7bee796`

**Scope:** Linux/WSL2 L3 Connected Build, subdivided into M4B-1, M4B-2, and M4B-3

## Purpose

Milestone 4B adds explicitly authorized build egress without giving hostile
workers ambient Internet, host, Windows, LAN, DNS, or general transport access.
The M4A worker network namespace remains isolated, route-less, and DNS-less.
The only worker-facing network ABI is a fixed loopback HTTPS proxy endpoint.

The governing principles remain:

> Models reason. AgenticOS guarantees.

> Path strings are locators. Opened kernel objects are authority.

> Connected Build is a set of task-bound capabilities, not Internet access.

M4B is deliberately divided into three separately reviewable milestones:

- **M4B-1 — Capability transport and lifecycle proof.** Proves only the
  listener-FD capability path, broker readiness barrier, cgroup composition,
  bounded synthetic byte relay, revocation, cleanup, and M4A non-regression.
  It earns no Connected Build claim.
- **M4B-2 — Authenticated HTTPS policy.** Adds the first Connected Build
  security claim: exact-hostname HTTPS using broker-owned DNS, worker-side TLS
  authentication/interception, separately validated origin TLS, strict HTTP/1.1,
  special-address denial, redirect reauthorization, expiry, quotas, and evidence.
- **M4B-3 — Build ecosystem qualification.** Adds identity-bound runtimes and
  synthetic qualification for pip, npm, and individually approved tools without
  weakening the M4B-2 authority model.

## Explicit non-goals

The initial M4B boundary does not provide:

- A worker veth, TAP device, default route, or general IP connectivity.
- pasta, passt, slirp4netns, nftables, or a privileged network helper.
- Worker DNS, DNS-over-TLS, DNS-over-HTTPS, or arbitrary DNS queries.
- Generic TCP, opaque CONNECT, SOCKS, UDP, QUIC, SSH, native Git protocol, or
  HTTP/3.
- Provider credentials, provider sessions, provider OAuth files, or provider
  control-plane access.
- Private-registry credentials or authenticated publication in the initial
  security claim.
- A user-defined proxy, mount, route, or destination-policy language.
- A claim that an approved remote service cannot relay or exfiltrate data.
- Native Windows isolation or support for an unmeasured Linux/WSL topology.

## Preserved M4A invariants

M4B must preserve every M4A guarantee:

- `/workspace` is the assigned worktree and worker PWD.
- Host absolute workspace paths and sibling worktrees are absent.
- Fixed host sources are opened and authorized by device/inode/type before use.
- Sandbox destinations are independently opened and identity-verified.
- The worker has separate user, mount, PID, network, IPC, and UTS namespaces,
  but no cgroup namespace.
- The host systemd task scope and cgroup-v2 hierarchy remain authoritative.
- No hostile code executes before exact cgroup and namespace evidence is proven.
- The worker receives zero Linux capabilities and `NoNewPrivs=1`.
- The worker inherits exactly file descriptors 0, 1, and 2.
- The controller environment is never forwarded; worker environment is fixed.
- The worker has no host pathname or abstract Unix-socket reachability.
- Landlock uses identity-verified sandbox objects as policy roots.
- Every failure before hostile exec prevents hostile exec and invokes bounded
  authoritative cgroup cleanup.
- Normal exit, cancellation, controller exceptions, descendant shapes, and
  cleanup races end only with recursively proven `cgroup.events populated=0`.

M4B extends the combined policy digest. It does not replace or weaken the M4A
filesystem, environment, namespace, capability, FD, or lifecycle commitments.

## Recorded feasibility evidence

The approved host is Ubuntu 26.04 LTS under WSL 2.6.3.0 with kernel
`6.6.87.2-microsoft-standard-WSL2`, Bubblewrap 0.11.1, and WSL NAT networking.
The worker-facing design does not depend on the WSL default route; only the
trusted broker remains in the host network namespace.

An ephemeral real-host probe established:

1. A process in `unshare -Urn` could not connect to a host-loopback fixture.
2. The process created a TCP listener on its isolated loopback interface.
3. It passed the listener FD over an `AF_UNIX` socketpair with `SCM_RIGHTS`.
4. A process remaining in the host network namespace accepted on that FD and
   relayed bytes to a host fixture.
5. The fixture received the exact worker canary and the worker received the
   fixture response.

The exact result was:

```json
{
  "child": {"child_reply": "fixture-reply"},
  "child_rc": 0,
  "child_stderr": "",
  "fd_export": {
    "direct_host_loopback_rc": 111,
    "listener_port": 33295
  },
  "fixture_seen": ["worker-request"]
}
```

A second ephemeral probe called `getsockopt(SOL_SOCKET, SO_NETNS_COOKIE)` on a
host socket and a socket created by `unshare -Urn`. The recorded values were:

```text
host_netns_cookie=1
child_netns_cookie=16558
```

These values are observations, not constants. M4B-1 must re-probe the exact
production path and must stop if the listener's kernel identity and network
namespace association cannot be positively established.

Linux records a network-namespace reference in socket state, and cgroup-v2
children inherit the parent's cgroup. Relevant primary sources are:

- <https://man7.org/linux/man-pages/man7/network_namespaces.7.html>
- <https://github.com/torvalds/linux/blob/master/include/net/sock.h>
- <https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html>
- <https://github.com/containers/bubblewrap/tree/v0.11.1>

## Chosen architecture

```text
AgenticOS controller
  -> create immutable task/network policy and launch nonce
  -> for M4B-2, create one task CA in trusted setup memory and split it into
     broker-only sealed private-key FD + worker-visible sealed public-cert FD
  -> securely open exact runtime/supervisor/broker/launcher objects
  -> systemd-run authoritative task scope
  -> trusted task supervisor begins inside that scope
       -> broker boundary remains in host network namespace
       -> worker Bubblewrap creates the M4A namespaces
  -> controller verifies exact scope/cgroup and M4A namespace evidence
  -> controller verifies exact broker PID, executable identity, host netns,
     zero capabilities, minimal environment/view, and exact cgroup membership
  -> controller releases only the namespace gate
  -> trusted native launcher enters inside the verified worker netns
  -> launcher creates fixed 127.0.0.1 listener
  -> launcher exports that exact listener FD over a private seqpacket channel
  -> broker authenticates task/generation/nonce/policy and adopts listener
  -> launcher and broker independently report listener identity/netns cookie
  -> controller authenticates NETWORK_BROKER_READY
  -> controller authorizes launcher to close network/control setup FDs
  -> existing M4A FD sanitation proves only the trusted gates remain
  -> sandbox destination identities verified
  -> NNP + Landlock applied
  -> authenticated combined filesystem/environment/network acknowledgement
  -> controller releases final hostile-exec gate
  -> hostile worker receives only FDs 0,1,2
```

### Fixed worker-facing ABI

The M4B proxy ABI is:

```text
TCP listener: 127.0.0.1:18080
Task CA certificate: /opt/agenticos/network-ca.pem  (M4B-2 and later only)
```

Every task has a distinct network namespace, listener object, broker, task ID,
generation, launch nonce, policy digest, and CA. Reusing the same numeric
loopback port across separate network namespaces is intentional. The address
string is a stable locator; the adopted listener FD and authenticated policy
are authority.

The worker receives no listener FD, broker control socket, namespace FD, policy
FD, CA private key, host socket, or upstream socket.

## Authoritative task supervisor

The current M4A scope directly executes Bubblewrap. Starting a broker from the
controller would place it outside the scope and invalidate recursive cleanup.
M4B therefore introduces a small, identity-verified supervisor as the initial
scope process.

The supervisor has one fixed function:

1. Start the broker boundary while still in the host network namespace.
2. Report the exact broker PID over a bounded controller-owned status channel.
3. Execute the worker Bubblewrap process without creating a second scope.

The broker and Bubblewrap descendants are consequently born in the same exact
cgroup. The controller must independently verify this through `/proc/<pid>/cgroup`
for both the broker and the Bubblewrap-reported worker child. Worker-supplied
identity fields are never accepted.

The supervisor receives only identity-opened executable/code FDs, fixed control
FDs, a minimal environment, and a bounded fixed argument contract. It does not
receive provider credentials or arbitrary controller state. The implementation
plan must choose the smallest practical supervisor form and verify its exact
binary/interpreter/code identity before hostile release.

## Identity-bound listener capability

The native launcher creates the listener before its existing FD sanitation
stage, while it is still trusted and before hostile execution. Bubblewrap's
isolated network namespace provides loopback only. No routable interface or
route is added.

The listener contract is fixed:

```text
family       AF_INET
type         SOCK_STREAM | SOCK_CLOEXEC
address      127.0.0.1
port         18080
accepting    true
reuse flags  false unless a later measured requirement is approved
```

The launcher passes the listener only through a controller-created private
`AF_UNIX SOCK_SEQPACKET | SOCK_CLOEXEC` socketpair using one `SCM_RIGHTS`
message. The message is bounded and commits to:

```text
protocol version
task_id
task_generation
launch_nonce
network_policy_digest
listener family/type/address/port
listener fstat device/inode/type
SO_NETNS_COOKIE
```

The broker independently performs `fstat`, `getsockname`, `getsockopt(SO_TYPE)`,
`getsockopt(SO_ACCEPTCONN)`, and `getsockopt(SO_NETNS_COOKIE)` on the received FD
and requires exact equality. The trusted launcher reports the same observations
over its authenticated status channel. The controller already proved that this
launcher PID occupies the expected M4A network namespace. This composes:

```text
verified launcher PID -> verified worker netns
verified launcher status -> listener identity + netns cookie
SCM_RIGHTS possession -> exact adopted listener object
broker independent observation -> same listener identity + netns cookie
```

Any missing field, duplicate FD, ancillary truncation, unexpected ancillary
message, mismatched object, wrong address/type, extra adoption attempt, or
unsupported kernel option fails closed.

The broker adopts exactly one listener generation. It never accepts a pathname,
port number, task header, or worker request as authority for listener adoption.

## Network broker readiness barrier

`NETWORK_BROKER_READY` is an authenticated pre-exec security barrier, not a
health-check convenience.

The controller may recognize readiness only after positively verifying:

- Authoritative task scope and cgroup.
- Complete M4A namespace evidence.
- Exact listener identity and network-namespace cookie.
- Exact per-task broker PID and process identity.
- Broker exact cgroup membership.
- Broker executable, code, runtime, and dependency identity required by the
  current milestone.
- Broker host network namespace and worker listener's distinct network namespace.
- Broker zero capabilities and minimal environment/filesystem view.
- Task ID, generation, and launch nonce.
- Immutable network-policy digest.
- One-time listener adoption.
- Expected milestone policy and readiness state.

The authenticated launch order is:

```text
cgroup verified
  -> namespaces verified
  -> broker process identity/boundary verified
  -> namespace gate released
  -> trusted launcher entry authenticated
  -> loopback listener created and exported
  -> broker listener adoption authenticated
  -> NETWORK_BROKER_READY authenticated
  -> controller releases network-setup close gate
  -> launcher closes listener/control/setup FDs
  -> M4A FD sanitation
  -> sandbox identities
  -> NNP
  -> Landlock
  -> authenticated combined policy evidence
  -> final exec gate
  -> hostile worker
```

Readiness loss before final hostile release prevents hostile exec and cancels
the authoritative scope. Broker death after hostile release cancels the entire
task. There is no broker restart or network fallback within a task generation.

## Launcher protocol composition

M4B requires a new bounded launch-protocol version while retaining M3B/M4A
compatibility. Conceptually, the M4B transcript is:

```text
R:<launch_nonce>                         trusted launcher entered
L:<listener evidence>                    listener created/exported
B:<network_policy_digest>:<evidence>      broker adoption/readiness authenticated
C                                         controller permits setup-FD closure
S                                         launcher FD sanitation complete
I                                         sandbox identities verified; cwd bound
P                                         Landlock policy prepared
N                                         no_new_privs set
A:<abi>:<mask>:<combined_policy_digest>   combined policy applied
X                                         final hostile-exec release
status EOF                                direct exec attempted
```

The exact wire encoding must remain length-bounded, reject unknown mandatory
records, reject duplicates/reordering, and authenticate the task generation,
nonce, network digest, and combined digest. M4A protocol v2 remains accepted for
M4A and must produce its unchanged `R,S,I,P,N,A` order.

## Broker least-authority boundary

The broker is trusted data-plane infrastructure, not an unsandboxed controller
subprocess. Its boundary requires:

- Same authoritative task cgroup as the worker.
- Host network namespace, because only the broker creates origin sockets.
- A distinct mount/PID/IPC/UTS boundary where supported without changing the
  required host network namespace.
- Zero effective, permitted, inheritable, ambient, and bounding capabilities.
- `NoNewPrivs=1` before readiness.
- Minimal fixed environment, with no ambient controller variables.
- No real user HOME, `.ssh`, Git credentials, provider files, session stores,
  Docker/container sockets, D-Bus sockets, workspace, sibling worktrees, or
  arbitrary AgenticOS state.
- Read-only exact broker code/runtime.
- Read-only system CA material only when M4B-2 requires it.
- Only the task policy/control/status/listener capabilities for its generation.
- Bounded connection, byte, memory, FD, header, and time limits.
- A private empty runtime view and no worker-writable executable/config source.

The controller independently records the broker's process identity, executable
and code identities, namespace identities, cgroup, capability fields,
`NoNewPrivs`, environment names, and fixed filesystem observations before
accepting readiness.

M4B-2 should keep the per-task CA private key in broker memory. If an unavoidable
temporary filesystem artifact is proposed, implementation must stop for review;
it may exist only in broker-private ephemeral storage and must have a positive
post-cleanup absence proof.

## M4B-1 transport policy

M4B-1 proves the production capability transport without granting Connected
Build.

The M4B-1 broker does not parse DNS, HTTP, TLS, hostnames, URLs, or destination
addresses and does not create arbitrary outbound connections. It supports:

- Listener adoption and authenticated readiness.
- A test-only, controller-provided synthetic fixture socket FD as the sole
  upstream capability.
- Bounded bidirectional byte relay between one worker connection and that exact
  fixture FD.
- Monotonic expiry, revocation, connection/byte limits, and abortive teardown.
- Deny mode when no synthetic fixture FD is present.

No TLS, certificate-generation, IDNA, HTTP-parser, or DNS dependency is permitted
in M4B-1. Passing M4B-1 proves only that the future broker channel composes with
M4A and the cgroup lifecycle.

## M4B-2 immutable HTTPS grant

The M4B-2 policy is canonicalized and digested before process creation:

```text
NetworkPolicy:
    version
    task_id
    task_generation
    containment_unit
    launch_nonce
    activated_at_monotonic
    policy_digest
    resolver_policy_version
    special_address_policy_version
    broker_protocol_version
    grants[]

NetworkGrant:
    grant_id
    scheme = "https"
    transport = "tcp"
    application = "http/1.1"
    hostname_alabel
    port = 443
    allowed_methods[]
    purpose
    granted_at_wall
    expires_at_wall
    expires_at_monotonic
    approval_source
    approval_reference
    connection_limit
    byte_limit
```

The model may request a grant. Only the trusted approval authority creates or
activates one. A grant cannot outlive its task, generation, broker, or cgroup.
Monotonic time controls activation and expiry; wall time is evidence only.

MVP grants use exact hostnames only. Wildcards, suffix grants, user-controlled
CIDRs, direct IPs, userinfo, and arbitrary ports are invalid.

## Hostname normalization

Before digesting or authorizing a grant, M4B-2 requires one canonical hostname:

- Parse an authority using a strict bounded grammar, not a permissive URL split.
- Require an exact DNS hostname, not an IP literal.
- Reject userinfo, percent-encoded authority delimiters, control characters,
  whitespace, empty labels, leading/trailing hyphens, multiple textual ports,
  IPv6 zone IDs, and ambiguous colon forms.
- Normalize Unicode through the approved IDNA implementation to lowercase
  A-label form.
- Reject trailing dots and wildcard labels rather than silently changing their
  semantics.
- Treat an omitted HTTPS port and explicit `:443` as equivalent.
- Reject every other port in the initial policy.

`approved.example.test` and `approved.example.test:443` normalize to the same
grant key. `approved.example.test.`, IP literals, wildcard names, userinfo forms,
and IDNA-confusable alternatives do not.

## DNS ownership and all-address policy

M4B-2 initially uses the trusted host `getaddrinfo` path rather than adding a
DNS parser merely to obtain TTL or CNAME evidence.

For each new origin connection the broker must:

1. Normalize and authorize the exact hostname.
2. Call the host resolver once for `SOCK_STREAM`/TCP results.
3. Collect and deduplicate every returned IPv4 and IPv6 sockaddr.
4. Reject unexpected families, socket types, protocols, malformed results, and
   policy ambiguity.
5. Validate every returned address against the complete special-address,
   host-interface, WSL, Windows, gateway, resolver, and LAN policy.
6. Deny the complete resolution if any returned result violates policy.
7. Select one validated sockaddr.
8. Connect directly to that exact sockaddr without another hostname resolution.
9. Preserve the independently approved hostname for upstream TLS SNI and
   certificate verification.
10. Discard all results after the connection attempt.

There is no AgenticOS DNS cache in the MVP. DNS TTL is therefore not part of
grant lifetime enforcement. Every new origin connection re-resolves from
scratch, and the active grant's monotonic expiry remains authoritative.

If the platform resolver cannot expose all usable A/AAAA results needed for the
all-address fail-closed rule, M4B-2 stops and records the deficiency. A dedicated
resolver dependency requires a separate dependency review and approval before
installation.

The worker receives no resolver configuration that provides a usable network
path. Exact grants and no wildcards prevent worker-selected DNS-query contents;
resolution rate is bounded per grant.

## Synthetic origin conformance capability

Conformance must not require a public service, but a positive production address
cannot safely be represented by host loopback/private/LAN without weakening the
special-address rule. M4B therefore keeps test transport separate from production
authorization:

- Resolver and address-policy unit tests supply complete synthetic A/AAAA result
  sets and prove the exact numeric sockaddr passed to the connector.
- Real-host negative tests use actual host/WSL/Windows/LAN endpoints and require
  categorical denial.
- End-to-end TLS/HTTP/Git tests use controller-created, already-connected
  synthetic origin FDs. A trusted test-only connector consumes those exact FDs
  instead of calling production `connect()`.
- The test connector is selected only by a private conformance-runner capability,
  never by worker input or a production `NetworkGrant`. Its presence, connection
  ID, and synthetic result are committed to evidence as non-production fixture
  mode.
- Production Connected Build mode accepts no fixture FD and must use only
  `resolve_all_once()` -> `validate_all_addresses()` ->
  `connect_validated_sockaddr()`.

The synthetic resolver can assign two hostnames the same logical permitted
address for hostname-confusion tests while the fixture FD supplies local bytes.
There is no loopback/private-range exception in production address policy.

## Special-address and SSRF policy

The broker rejects the whole resolution if any result is:

- IPv4 or IPv6 loopback or unspecified.
- RFC1918 private, IPv6 ULA, carrier-grade NAT, or link-local.
- Multicast, broadcast, documentation, benchmarking, discard-only, reserved,
  or otherwise non-global under the current IANA special-purpose registries.
- A metadata-service-style destination.
- IPv4-mapped IPv6 whose embedded address is prohibited.
- NAT64/DNS64 synthetic space in the MVP.
- A WSL resolver, WSL gateway, WSL interface address, Windows host interface,
  directly connected subnet, discovered LAN route, or host-local service.
- Reached through an unexpected address family, interface, or route.

The policy combines versioned IANA registry data with a trusted launch-time
snapshot of host addresses, gateways, resolver endpoints, and routes. A public
hostname resolving to a prohibited result is denied; no public alternative from
the same answer set rescues it.

Primary registries:

- <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml>
- <https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml>

## Worker-side TLS and exact hostname proof

An opaque CONNECT tunnel is insufficient because the broker could not prove the
application protocol or hostname after returning `200 Connection Established`.
M4B-2 therefore terminates worker-side TLS and establishes a separate origin TLS
connection.

The worker-side sequence is:

1. Strictly parse CONNECT authority and require an active exact grant.
2. Return a successful CONNECT response only after policy state permits the
   worker-side TLS attempt.
3. Require a bounded TLS ClientHello with ordinary observable SNI.
4. Reject missing SNI, mismatching SNI, malformed ClientHello, unsupported TLS,
   unsupported ALPN, or an offered ECH extension that prevents independent SNI
   validation.
5. Present a task-scoped leaf certificate for that exact approved hostname.
6. Negotiate only `http/1.1`.
7. Strictly parse inner HTTP and require Host/authority equality with the same
   normalized grant.

The broker separately connects the selected validated sockaddr and performs
ordinary server-authenticated TLS using the approved hostname for SNI and
certificate verification. Certificate failure, hostname failure, ALPN mismatch,
or a second resolution fails closed.

OpenSSL provides an early ClientHello callback and raw extension inspection via
`SSL_CTX_set_client_hello_cb` and `SSL_client_hello_get0_ext`:
<https://docs.openssl.org/3.4/man3/SSL_CTX_set_client_hello_cb/>. Python's standard
`ssl.SSLContext.sni_callback` exposes the observed server name but not an
equivalent raw extension list. Therefore M4B-2 begins with an explicit dependency
and ECH-feasibility gate. No production TLS stack is accepted until it proves
ECH detection/denial on the recorded host without relying only on CONNECT.

Qualified curl invocations must explicitly use `--ech false` where the measured
curl build supports ECH. Broker-side denial remains mandatory even when a tool is
configured not to offer ECH. Curl documents `false` as the no-ECH setting:
<https://curl.se/docs/manpage.html#--ech>.

## Same-IP hostname confusion proof

Synthetic `approved.example.test` and `evil.example.test` must resolve to the
same permitted fixture IP. With only the first hostname granted:

```text
CONNECT approved + SNI approved + Host approved -> allowed
CONNECT approved + SNI evil     + Host approved -> denied
CONNECT approved + SNI approved + Host evil     -> denied
CONNECT evil     + SNI approved + Host approved -> denied
direct fixture IP request                        -> denied
```

The origin fixture must also present distinct certificates/virtual-host behavior
so that success cannot accidentally derive from the shared IP.

## Per-task CA boundary

M4B-2 creates a new CA for every task generation during trusted setup, before
the worker Bubblewrap constructs its immutable mount view.

- The trusted controller-side setup component generates the CA in memory and
  immediately separates it into a broker-only sealed private-key memfd and a
  sealed public-certificate memfd.
- Only the public-certificate FD is passed to the worker Bubblewrap for the fixed
  read-only mount. Only the private-key FD is passed to the broker boundary.
- The broker loads and retains the CA private key in memory, proves it corresponds
  to the public certificate, and closes the key memfd before readiness.
- The worker receives only the public CA certificate at the fixed read-only
  synthetic path `/opt/agenticos/network-ca.pem`.
- The controller closes every private-key FD copy, overwrites mutable
  serialization buffers where supported, and releases private-key references
  after broker setup and before hostile release. The claim is absence from
  worker-visible or persistent storage, not forensic erasure of trusted-process
  memory.
- The host/global CA store is never modified.
- The general sandbox runtime trust store is never modified.
- Each qualified tool is explicitly pointed at the task CA.
- The CA and leaf certificates cannot outlive the task generation.
- Cleanup proves no worker-visible private-key artifact existed or remains.

The CA is a compatibility/security capability for this task, not an ambient
trust root.

## Strict HTTP/1.1 policy

The M4B-2 broker uses a strict, bounded, reviewed HTTP/1.1 parser. It must not
hand-roll a permissive parser. The parser, TLS implementation, hostname
normalizer, and certificate generator are security-critical dependencies.

The broker rejects:

- Conflicting or duplicate Content-Length with different values.
- Transfer-Encoding ambiguity or unsupported transfer codings.
- Content-Length plus Transfer-Encoding ambiguity.
- Oversized start lines, headers, header count, or individual fields.
- Invalid field names/values, obs-fold, control characters, or bare line feeds.
- Absolute/authority forms inconsistent with the active state.
- Malformed or duplicate Host.
- Nested CONNECT.
- Upgrade and WebSocket negotiation.
- Unsupported ALPN, HTTP/2 preface, and HTTP/3/QUIC alternatives.
- Request-smuggling forms and bytes remaining in an invalid parser state.

Every request on a persistent connection is reauthorized. Method grants are
purpose-specific: general downloads start with `GET` and `HEAD`; Git smart fetch
may add the required `POST`. Publication and mutation methods remain denied.

## Redirect policy

The broker does not rewrite redirect responses by default.

- Same-origin HTTPS redirects remain within the current grant.
- A cross-authority `Location` response may be delivered to the worker.
- The broker may record only the normalized redirect scheme/authority/port and
  policy observation, never its path or query.
- If the client follows a cross-authority redirect, the new CONNECT and request
  return through the broker and receive a fresh grant check.
- The redirect does not create or widen a grant.
- HTTPS-to-HTTP is unsupported and denied when followed.
- Alt-Svc is removed because it advertises an unsupported alternate transport;
  this is header sanitization, not redirect rewriting.

If a concrete security requirement later appears to require rewriting Location,
implementation stops for architectural review before adding that behavior.

## Provider credential separation

Neither worker nor broker receives:

- OpenAI, Anthropic, Kimi, Google, or other provider credentials.
- Provider OAuth files, session stores, official-client state, or provider
  control sockets.
- Real user home, `.ssh`, Git credential helpers, cloud credentials, Docker
  configuration, runtime sockets, or ambient controller secrets.

M4B-2 initially qualifies anonymous public fetches. Private registries and
authorization-bearing build requests require a separate credential-domain and
logging review. The broker never logs Authorization, Cookie, Proxy-Authorization,
request bodies, or response bodies.

## Evidence model

The authenticated M4B transcript records only normalized non-secret evidence:

- Task ID, generation, containment unit, launch nonce, and policy digest.
- Exact supervisor and broker process identities.
- Broker executable/code/runtime/dependency identities.
- Broker and worker namespace identities and exact cgroup membership.
- Broker capability masks, `NoNewPrivs`, environment names, and boundary profile.
- Listener fstat identity, socket properties, address, and netns cookie observed
  independently by launcher and broker.
- Readiness record and launch-gate ordering.
- Grant ID, normalized hostname, scheme, application protocol, port, method,
  approval source/reference, and monotonic lifetime.
- Resolver invocation timestamp, deduplicated A/AAAA results, per-address policy
  decisions, and selected sockaddr.
- Worker SNI, CONNECT authority, HTTP authority consistency, ECH observation,
  ALPN, and origin certificate-verification result.
- Redirect scheme/authority/port observation and subsequent grant decision.
- Connection ID, bounded byte totals, timestamps, expiry/revocation, and denial
  reason.
- Broker/worker termination, recursive cgroup emptiness, and scope removal.

Evidence never contains:

- Host source locators.
- Secret values or private keys.
- Authorization/Cookie/proxy-auth values.
- URL paths or query strings.
- Request or response bodies.
- Downloaded content.

No terminal Connected Build verification record is emitted until the broker and
all worker descendants are gone and recursive cgroup emptiness is proven.

## Expiry, revocation, and lifecycle

Each broker has a registry of listener, accepted worker, and origin FDs indexed
by task generation, grant, and connection ID.

Expiry and revocation:

1. Mark the generation or grant closed using the host monotonic clock.
2. Stop accepting new worker connections/requests.
3. Abort both directions of every matching active stream.
4. Discard buffered unsent bytes rather than gracefully draining past expiry.
5. Record the terminal reason without payload contents.

Bytes already transmitted and remote side effects cannot be revoked.

Broker death before hostile release denies release. Broker death after release,
controller exception, worker cancellation, timeout, or any evidence failure
closes gates and invokes the existing authoritative cgroup cancellation path.
There is no per-task broker restart: restart would create a new process/listener
identity and therefore requires a new task generation.

The listener socket retains its worker network-namespace association while open.
Cleanup must close broker-held listener/accepted FDs, kill all scope processes,
prove recursive cgroup emptiness, stop the scope, and prove that no task-private
CA or socket artifact remains.

## Adversarial proof matrix

All conformance endpoints are synthetic/local fixtures. Public services are not
required.

### M4B-1

- Exact production Bubblewrap/native-launcher listener handoff succeeds.
- Listener substitution, second FD, wrong family/type/address/port, non-listener,
  stale generation, wrong nonce/digest, ancillary truncation, and mismatched
  netns cookie fail before hostile exec.
- Broker PID, executable identity, host netns, cgroup, capability, environment,
  or boundary mismatch fails before hostile exec.
- Broker readiness arrives only after listener adoption and before FD sanitation.
- Worker has loopback only, no default route, no resolver, no extra FDs, and no
  direct host/Windows/LAN connection.
- Synthetic fixture-FD relay transfers bounded bytes; absent fixture capability
  denies relay.
- Revocation/expiry closes active relay and prevents further bytes.
- Broker death before release prevents exec; death after release cancels task.
- Controller exception, cancellation, timeout, and connection-open teardown end
  with recursive empty cgroup and no residual scope.
- Child, grandchild, setsid, new process group, parent-exit, double-fork, rapid
  spawn, and signal-ignoring shapes cannot escape the task capability/lifecycle.
- Every M4A filesystem, credential, FD, namespace, capability, no-network, and
  cleanup regression remains green.

### M4B-2

- Exact approved synthetic HTTPS and Git smart-HTTPS fixtures succeed.
- Unapproved hostname, wrong port, direct IP, wildcard, userinfo, trailing dot,
  malformed authority, and IDNA-confusion cases fail.
- Matching, mismatching, missing, and ECH-hidden SNI cases produce the required
  allow/deny outcomes.
- Same-IP approved/evil fixture combinations prove hostname rather than IP
  authorization.
- Mixed public/private A/AAAA, loopback, link-local, private, metadata, mapped
  IPv6, NAT64, WSL resolver/gateway/interface, Windows host, and LAN results deny
  the whole resolution.
- A selected sockaddr is connected without a second resolution.
- Same-origin redirect continues; cross-authority follow requires a separate
  active grant; HTTPS-to-HTTP follow fails.
- Conflicting Content-Length, Transfer-Encoding ambiguity, oversized lines and
  headers, invalid syntax, smuggling, nested CONNECT, Upgrade, unsupported ALPN,
  HTTP/2 preface, and QUIC fail closed.
- Expiry and revocation before DNS, between DNS/connect, during TLS, between
  requests, and midstream abort active work.
- Task CA is unique, read-only to worker, explicitly configured for each tool,
  never globally installed, and leaves no private-key artifact.
- Evidence includes required authority/decision fields and excludes paths,
  queries, headers, bodies, source locators, and secrets.

### M4B-3

- Each runtime tree is identity-bound and contains no broadened host tree.
- pip/npm synthetic index, artifact, redirect, lifecycle-hook, proxy/CA, and
  failure cases are version-qualified.
- Tools that ignore proxy/CA configuration fail closed because no direct route
  exists.
- A tool requiring a weaker capability stops for separate architectural review.

## Security claims by milestone

### After M4B-1

AgenticOS may claim only that the fixed loopback listener capability, per-task
host-netns broker, readiness gate, lifecycle, revocation transport, and M4A
boundary compose correctly on the recorded host. It may not claim Connected
Build or approved Internet access.

### After M4B-2

After independent review and the established repeated Linux plus Windows
regression discipline, AgenticOS may claim that the hostile task has no ambient
network and can perform only exact-grant, anonymous HTTPS through the verified
per-task broker, with broker-owned resolution, special-address denial,
CONNECT/SNI/HTTP-authority consistency, independently validated origin TLS,
redirect reauthorization, bounded lifetime, revocation, and authenticated
evidence.

### After M4B-3

AgenticOS may additionally claim compatibility only for the exact measured tool
and runtime versions whose synthetic conformance suites pass. M4B-3 does not
broaden the networking authority.

## Exact stop conditions

Implementation stops for review rather than weakening the claim if:

- The exact production listener-FD handoff or `SO_NETNS_COOKIE` relationship
  cannot be positively verified.
- The listener becomes host-address reachable instead of FD-capability reachable.
- Broker and worker cannot occupy the same exact authoritative cgroup while
  retaining required distinct network namespaces.
- Broker readiness cannot be authenticated before M4A sanitation/NNP/Landlock
  and final exec.
- The worker receives any route, DNS path, namespace/control/listener/upstream FD,
  or non-stdio hostile descriptor.
- The broker requires workspace, real home, provider state, runtime sockets,
  arbitrary AgenticOS state, capabilities, or unbounded controller authority.
- Task identity or policy authority depends on a worker-supplied field.
- The host resolver cannot return enough information for the all-address
  fail-closed policy.
- Any second hostname resolution occurs between validation and connect.
- A TLS stack cannot independently reject ECH, missing/mismatching SNI, or
  unsupported ALPN before accepting the HTTPS hostname claim.
- CONNECT, SNI, HTTP authority, and origin certificate identity cannot be made
  mutually consistent.
- A strict bounded HTTP parser or hostname/certificate implementation cannot be
  identified, pinned, and reviewed.
- Direct IP, shared-IP hostname confusion, IPv6/mapped/NAT64, redirects, Alt-Svc,
  Upgrade, smuggling, expiry, or revocation bypasses policy.
- Broker failure permits fallback networking or the broker survives task cleanup.
- The task CA private key becomes worker-visible, enters a global trust store, or
  leaves an unproven artifact.
- Provider credentials enter worker or broker.
- pip/npm/tool support requires broader filesystem or network authority.
- Any M4A invariant or regression fails.

## Dependency gates

M4B-1 remains standard-library/native-system-call only and adds no TLS, HTTP,
IDNA, certificate, or DNS dependency.

Before M4B-2 adds or installs any dependency, a review must record:

```text
exact name and version
authoritative provenance
license
source/wheel/archive hash
transitive and native dependencies
supported Python/OpenSSL/platform versions
known security posture and advisories
deterministic pinning and offline reproduction approach
runtime filesystem closure
behavioral conformance result
```

The initial candidate classes are a strict HTTP/1.1 state machine, IDNA
normalizer, certificate generator, and TLS stack with pre-handshake ECH extension
inspection. No candidate is accepted merely because it is already present in a
developer environment. The current project declaration that production runtime
code is standard-library-only must not be changed until this dependency review
is separately approved.

## Implementation checkpoint discipline

Each sub-milestone follows the established pattern:

1. Test-driven implementation with synthetic fixtures.
2. Focused unit and real-host integration tests.
3. M4A non-regression suite.
4. Independent security review.
5. Three consecutive complete Linux runs.
6. Warning-clean native builds where native code changes.
7. Windows regression with explicit Linux-only skips.
8. No residual `aos-*` scopes, cgroups, processes, private directories, sockets,
   or CA artifacts.
9. Clean synchronized Windows/WSL/origin checkpoint with the exact SHA recorded.

M4B-1, M4B-2, and M4B-3 are committed and reviewed independently. No later
milestone may retroactively broaden an earlier security claim.
