# M4B-3 Connected Build — Bounded Grant Set and Worker Profile (Slice 1)

Status: implemented design record for M4B-3 Slice 1. This is not yet a
Connected Build boundary claim; ecosystem qualification (Git, pip, generic
artifact fetch) lands in later slices and the claim is earned only when the
full M4B-3 verification completes.

## 1. What Slice 1 adds

Two generalizations on top of the unchanged M4B-2 broker pipeline:

1. **Bounded explicit exact-host grant set.** A task's HTTPS network policy
   may carry 1..`CONNECTED_BUILD_MAX_GRANTS` (= 4) exact-host grants
   (`network_https.CONNECTED_BUILD_MAX_GRANTS`, enforced at controller
   launch validation, broker adoption, and broker serve). Zero grants
   remains the legal deny-all posture. `_MAX_GRANTS = 64` stays the
   type-level container cap and is NOT the Connected Build authority limit.
2. **Deterministic Connected Build worker profile.** An optional
   controller-fixed environment extension
   (`m4b_runner.CONNECTED_BUILD_WORKER_EXTRA_ENV`): lowercase
   `https_proxy=http://127.0.0.1:18080` plus per-tool CA variables
   (`SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`,
   `REQUESTS_CA_BUNDLE`) pointing at the read-only
   `/opt/agenticos/network-ca.pem`. It flows through
   `build_runtime_plan(extra_worker_env=...)` into the same
   environment/combined policy digests; passing `None` keeps every
   pre-M4B-3 plan byte-identical. Ambient proxy/credential/trust variables
   are absent STRUCTURALLY (the worker environment is exactly
   `WORKER_ENVIRONMENT` plus this tuple), never filtered. Proxy env is
   routing configuration; the security boundary remains M4A netns
   isolation plus the sealed M4B policy. `HTTPS_PROXY`, `HTTP_PROXY`,
   `ALL_PROXY`, `no_proxy`/`NO_PROXY`, and `GIT_SSL_NO_VERIFY` are
   deliberately unset.

## 2. Authority model

- Grants are exact-host only. `canonicalize_hostname` remains the single
  normalization point; the grammar has no wildcard, suffix, IDNA,
  trailing-dot, or numeric forms, so no grant can widen authority beyond
  its own canonical hostname.
- Hostnames are unique across a policy's grant set. Two grants naming one
  canonical hostname (the only AMBIGUOUS_GRANTS shape) reject at runner
  validation (`_validate_grant_specs`) and at `validate_grant_set`, before
  any launch or adoption.
- Each granted hostname independently traverses the full M4B-2 identity
  chain: CONNECT authority -> worker TLS SNI -> HTTP Host -> origin TLS
  name -> evidence name, canonical byte equality at every stage. The
  broker selects the connection's grant ONCE at CONNECT authorization and
  binds every later stage (per-connection SNI policy, HTTP method policy
  from the grant's purpose, Host re-verification, origin establishment,
  identity chain, evidence) to exactly that grant.
- A multi-grant capability is a small set of independently authorized
  exact hosts, not one broader network authority: per-grant
  `connection_limit`/`byte_limit` are enforced per grant AND the transport
  policy's aggregate limits are enforced across all grants. Per-grant byte
  accounting is reserve-by-decrement under a lock (the reservation is the
  commit, refunded on short/failed reads), so concurrent same-grant
  connections can never exceed a grant's byte authority even transiently;
  overflow/underflow tripwires raise `BrokerBoundaryError` fail-loud.
  Grant exhaustion terminates that connection (`grant_connection_limit` /
  `grant_byte_limit`) without tripping the policy-aggregate posture other
  grants live under.

## 3. Certificate model decision: multi-SAN single leaf

The per-task leaf certificate's SAN set is exactly the granted hostname
set (sorted ascending, byte-exact), committed in the AOSCERT/1
`CertBinding.hostnames` field (replacing `hostname`; sorted/unique/
canonical enforced at construction and at decode) and audited at adoption:
the self-audit handshake plus exact ordered SAN-tuple comparison proves
the leaf serves no name outside the committed set, and the broker requires
sorted-set byte equality between the binding's committed set and the
policy's grant hostname set.

Rejected alternative: per-host leaves with SNI dispatch. It would have
multiplied the sealed-material FD vectors, supervisor contract, and
adoption path for no authority gain — the broker holds all leaf keys
either way, and per-connection exact-host enforcement lives in the SNI
policy/identity chain, not in the SAN count. The generalized invariant
("SAN set == granted set") preserves the M4B-2 audit strength; the
single-host case is a 1-tuple and behaves exactly as before.

## 4. Redirect semantics (unchanged trust boundary, now stated)

The broker never follows redirects and contains no redirect parser. A 3xx
response is relayed byte-exact to the worker. Any redirect target — same
host or different — is fetched by the client as a NEW request that
re-enters the complete authorization chain: same granted host means
authorized; a different host means authorized only if that exact host
holds its own grant, otherwise fail-closed (`authorization_no_match`).
HTTPS-to-HTTP downgrade is structurally impossible (CONNECT accepts port
443 only; relay exists only inside TLS). The broker never autonomously
authorizes a redirect destination.

## 5. Evidence

The AOSHTTPEV/1 record schema is unchanged. Because duplicate hostnames
are rejected, each connection record's `approved_hostname` uniquely
identifies the authorizing grant. Connections denied before grant
selection record `identity_chain="no_grant"` / `approved_hostname=None`
under a multi-grant policy (with exactly one grant, the `sole_grant`
fallback preserves the M4B-2 evidence shape byte-for-byte); this cannot
mask an authorized connection, which always has its grant selected before
any later denial.

## 6. Conformance-only plumbing

The broker's synthetic fixture origin now arms a bounded queue
(`HTTPS_FIXTURE_MAX_ORIGINS = 4`, consumed in arming order) so each
granted hostname can reach its own scripted origin in tests. Arming
remains possible only via the authenticated control channel before the
first connection, each arm validated exactly as in M4B-2
(`synthetic_origin=true` on every record). Worker and policy input cannot
reach it; production launches (no connectors) are byte-identical. A
hostile worker CAN spend queued fixtures out of order (fail-closed,
conformance-only, no production impact).

## 7. Accepted behavior notes (reviewed, documented, no action)

- When a grant's limits equal the policy limits (the M4B-2 single-host
  form), single-grant behavior is byte-identical to M4B-2. When an
  explicit per-grant limit is tighter (M4B-3 only), grant exhaustion
  terminates the connection without setting the serve-wide
  `byte_limit_reached` posture; this is deliberate two-level semantics.
- Grant ids are minted as `g<nonce12>x<index>` (unique and deterministic
  per launch); the single-host minted policy digest therefore differs from
  M4B-2's `g<nonce16>` form. No authority depends on the id string; all
  digest comparisons are computed from the same minted policy.

## 8. Verification state at Slice 1 closure

- New adversarial corpus: `tests/conformance/test_m4b3_grants_unit.py`
  (79 tests: cardinality 0/1/4/5, duplicates, conflicting purposes,
  wildcard/suffix/IP-literal unbuildability, expired-grant isolation,
  cross-grant identity mismatch at every stage, ordering/digest
  determinism, sealed 4-grant round-trip under the 16 KiB cap, runner
  validation matrix, env profile exactness and digest behavior, per-grant
  connection/byte limits incl. exact-boundary and concurrent same-grant
  hard-bound tests, 4-grant serve flow).
- `tests/conformance/test_m4b3_connected_build_integration.py` (7
  real-host tests: two-grant full path with per-grant verified evidence,
  per-grant method policy, cross-grant SNI mismatch, ungranted redirect
  target fail-closed, worker env census, per-grant connection limit,
  ALPN h2-offer fallback to http/1.1).
- Independent adversarial review: FIX-FIRST verdict addressed (M1 grant
  byte-limit atomicity, M2 grant byte-limit coverage, L2 type discipline,
  L3 env-name bound); no HIGH findings; all other invariants verified
  unbypassable by the reviewer.
- Full Linux suite at closure: 1919 passed, 1 skipped (baseline was
  1833 passed, 1 skipped).
- Later slices: Slice 2 git qualification
  (`docs/phase-zero/connected-build-git.md`), Slice 3 artifact fetch
  (`docs/phase-zero/connected-build-fetch.md`), Slice 4 pip
  qualification (`docs/phase-zero/connected-build-pip.md`), Slice 5
  lifecycle matrix and acquisition evidence
  (`docs/phase-zero/connected-build-lifecycle.md`,
  `docs/phase-zero/connected-build-evidence.md`). The final record of
  the milestone is the closure doc:
  `docs/phase-zero/connected-build-m4b3.md`.
