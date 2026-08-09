# Milestone 4B-1 — Capability Transport Boundary

## Earned claim

On the recorded Ubuntu 26.04/WSL2 host, AgenticOS can give an M4A-isolated
worker one fixed loopback listener capability at `127.0.0.1:18080`, transfer
that exact listener to a least-authority sibling broker, and relay one bounded
full-duplex stream to a controller-provided synthetic fixture FD. Release is
conditional on authenticated listener, process, namespace, cgroup, policy,
capability, NNP, filesystem, and readiness evidence. Revocation, expiry,
limits, errors, and timeout remain bounded by the authoritative task cgroup.
Terminal verification occurs only after recursive cgroup emptiness and the
scope is stopped and confirmed inactive.

This is M4B-1 capability-transport evidence. It earns **no Connected Build
claim**. No DNS, hostname/IP policy, HTTP CONNECT, TLS, certificate validation,
redirect handling, package-manager qualification, public download, or provider
access is implemented. M4B-2 is unavailable until its dependency and ECH gate
passes and is separately approved.

## Recorded host and transport

The measured host is Ubuntu 26.04 LTS under WSL 2.6.3.0, kernel
`6.6.87.2-microsoft-standard-WSL2`, Bubblewrap 0.11.1, systemd user scopes, and
cgroup v2. The production test path re-probes required host behavior and fails
closed; these versions are observations, not portable constants.

M4B-1 supports exactly two policy modes:

- `DENY`, with no fixture capability and an immutable zero-count terminal
  observation.
- `SYNTHETIC_FIXTURE_FD`, with one already-connected, controller-provided Unix
  stream socket as the broker's only upstream data capability.

The proxy ABI is fixed at `127.0.0.1:18080`. Workers cannot choose mounts,
listeners, destinations, protocols, or fixture FDs. The synthetic fixture is a
conformance mechanism, not production network authority.

## Boundary composition and release transcript

```text
controller seals exact transport policy and opens measured code/runtime objects
  -> authoritative systemd scope starts native supervisor
  -> supervisor starts worker and broker Bubblewrap children in the same cgroup
  -> worker gets M4A namespaces; broker keeps host netns and a minimal mount view
  -> controller proves worker namespace/cgroup and broker process/cgroup identity
  -> namespace gate releases the trusted launcher, not hostile code
  -> launcher creates fixed isolated-loopback listener and exports its exact FD
  -> broker adopts that one FD through authenticated SCM_RIGHTS framing
  -> broker proves exact process, namespace, cgroup, code, policy, FD, env, caps/NNP
  -> controller matches launcher and broker listener evidence
  -> network-close gate closes setup authority
  -> launcher sanitizes FDs, verifies identities, sets NNP, applies Landlock
  -> authenticated filesystem-policy acknowledgement
  -> final exec gate releases hostile worker at /workspace
  -> broker emits one canonical terminal transport observation on control channel
  -> worker/broker descendants terminate; recursive cgroup populated=0 is proven
  -> scope is stopped and confirmed inactive
  -> NETWORK_TRANSPORT_BOUNDARY_VERIFIED may be emitted
```

The dedicated readiness channel remains exactly one canonical readiness record
followed by authenticated EOF. It is never reused for terminal evidence. The
existing bidirectional `SOCK_SEQPACKET` control capability carries one canonical
broker-to-controller terminal observation in its opposite direction. The
controller rejects missing, duplicate, oversized, noncanonical, mismatched,
ancillary-bearing, zero-length-record, or no-EOF transcripts.

## Broker boundary

The broker runs in the worker's authoritative task cgroup and host network
namespace, but in a separate Bubblewrap mount/PID/IPC/UTS boundary. Its root is
an explicit minimal runtime/code view; home, run, and tmp are empty synthetic
directories. Its inherited FD set is fixed to stdio, sealed policy, listener
handoff, readiness status, control, and—only in synthetic mode—the fixture FD.

Authenticated readiness proves:

- exact broker process start identity and interpreter identity;
- exact runtime, broker, identity-module, and model-module filesystem objects;
- exact namespace identities and cgroup equality;
- all inheritable, permitted, effective, bounding, and ambient capability masks
  are zero;
- `NoNewPrivs=1`;
- fixed environment names and an environment digest, without exporting values;
- exact sealed-policy identity, size, seals, and canonical policy digest;
- exact listener fstat identity, family/type/address/port, accepting state, and
  network-namespace cookie.

The broker has no DNS resolver, outbound connector, URL/HTTP/TLS parser,
credential surface, arbitrary filesystem language, or ambient configuration.

## Relay accounting and lifecycle

The broker owns accounting. The terminal observation binds to the sealed task
generation and policy without logging payloads. It reports one monotonic
timestamp, accepted connection count, policy-accounted ingress bytes,
successfully forwarded worker-to-fixture and fixture-to-worker bytes, forwarded
total, discarded-unsent bytes, and terminal reason. Invariants require:

```text
forwarded_total = worker_to_fixture + fixture_to_worker
accounted = forwarded_total + discarded_unsent
forwarded_total <= accounted <= policy byte limit
connection_count <= policy connection limit
```

Normal full-duplex EOF produces `COMPLETED`; the broker then remains alive until
controller revocation. Active revoke and expiry abort buffered unsent data.
Byte/connection limits and peer/control errors terminate fail closed. `DENY`
emits `DENY_NO_RELAY` with all counters zero. Timeout uses one shared absolute
terminal grace of at most one second, and authoritative cgroup cancellation
runs even if terminal evidence is missing or malformed.

## Adversarial proof matrix

| Property | Measured result |
|---|---|
| exact isolated-loopback listener exported/adopted | accepted; launcher and broker evidence match |
| substituted/tampered listener or readiness identity | rejected before hostile exec |
| readiness before prerequisite release, duplicate, truncation, or delayed data | rejected |
| broker PID reuse, executable, parent, cgroup, namespace, or code mismatch | rejected |
| broker death at release boundaries | task cancelled; no weaker fallback |
| worker host loopback/TCP/UDP and pathname/abstract Unix reachability | denied by the combined M4A network, mount, and IPC boundary; connected FDs are separately sanitized |
| one synthetic full-duplex fixture relay | exact request/response and directional totals observed |
| second connection or byte-limit overflow | terminated at fixed policy bound |
| revoke/expiry during active or half-closed relay | buffered unsent bytes discarded; no late canary |
| terminal record missing/duplicate/tampered/zero-record/no EOF | rejected; cleanup remains authoritative |
| task timeout with unresponsive terminal channel | cancellation begins within the one shared bounded grace |
| recursive descendants and broker/worker termination | cgroup recursively empty; scope stopped and inactive |
| M4A filesystem, environment, FD, namespace, and Landlock behavior | unchanged by M4B-1 composition |

All positive endpoints and contents are synthetic local fixtures. The suite does
not contact the public Internet or use real credentials.

## Normalized evidence

Successful verified runs emit exactly one
`NETWORK_TRANSPORT_BOUNDARY_VERIFIED` event after recursive cgroup emptiness and
confirmed inactive scope. It records M4B-1, `connected_build_authorized=false`, the fixed
proxy ABI, policy and domain-separated authority binding digests, measured
process/start and filesystem identities, namespace/socket identities, broker
security state, readiness order, Landlock outcome, exact terminal accounting,
and cleanup proof.

Raw task IDs, launch nonces, boot IDs, cgroup paths, source locators, workspace
host paths, environment values, credentials, canaries, request/response bytes,
stdout, and stderr are excluded. Boot, cgroup, and task bindings use
domain-separated digests plus exact equality/membership booleans.

## Limitations and next gate

- The claim is specific to the recorded WSL2 topology and repeatedly measured
  binaries/kernel behavior.
- M4B-1 has no general Internet destination authorization and no production
  upstream connector.
- There is no seccomp, AppArmor/LSM-stacking, malicious-kernel, traffic-analysis,
  remote-side-effect revocation, or denial-of-service claim.
- The worker can reach only its fixed isolated-loopback listener; this says
  nothing about whether arbitrary external content is safe.
- Private registries, bearer credentials, provider authentication, package
  managers, Git smart-HTTPS, DNS, TLS, ECH, redirects, and content provenance
  remain out of scope.

M4B-2 remains unavailable. Before implementation it requires an approved,
pinned dependency report and an ECH policy gate capable of proving that the
authorized authority remains observable and enforceable. Only a separately
reviewed later milestone may earn a Connected Build claim.

Models reason. AgenticOS guarantees.
