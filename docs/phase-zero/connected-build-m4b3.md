# Milestone 4B-3 — Connected Build (earned claim and boundary statement)

M4B-3 generalizes the M4B-2 authenticated HTTPS broker
([https-broker-policy.md](https-broker-policy.md)) to a bounded exact-host
grant set and qualifies three build/dependency-acquisition workflows
through it. Host qualification: [host-capabilities.md](host-capabilities.md);
dependency pins: [dependency-review-m4b3.md](dependency-review-m4b3.md);
the governing plan was
[m4b3-qualification-plan.md](m4b3-qualification-plan.md).

## Earned claim

On the qualified host (Ubuntu WSL2, recorded toolchain: **git 2.53.0 /
libcurl-gnutls, curl 8.18.0 / OpenSSL 3.5.5, python 3.14.4, pip
26.2.1**), AgenticOS Connected Build allows approved
build/dependency-acquisition workflows — **Git HTTPS** (ls-remote, clone,
fetch, pinned ref, shallow, branch; smart-HTTP v2 and v0), **pip**
(hash-pinned binary wheels, `--require-hashes --only-binary=:all:`, two
exact hosts), and **generic digest-gated artifact fetch** — to perform
explicitly authorized outbound HTTPS through the M4B task-scoped
authenticated broker while preserving worker network isolation, exact-host
authorization, TLS authentication, broker-side DNS/SSRF validation,
filesystem/process/FD/secret boundaries, and bounded resource use, with
per-acquisition authority evidence.

This is a **narrow** claim, earned as scoped: **git HTTPS + pip two-host +
generic curl fetch, public/pinned-only, fixture-qualified**. See
[What is not earned](#what-is-not-earned).

## Scope qualifiers that travel with the claim

- **Fixture-qualified.** All workflow qualification ran against controlled
  local fixture origins; every such record is marked
  `synthetic_origin=true`. The production origin path (real DNS, special-
  address/SSRF validation, numeric connect, authenticated origin TLS) is
  the **unchanged M4B-2 code** — diff-verified untouched by this
  milestone's production changes.
- **Bounded grant set.** 1–4 explicit exact-host grants per task
  (`CONNECTED_BUILD_MAX_GRANTS = 4`). No wildcards, no suffixes, no
  IDNA, no numeric/IP-literal forms; duplicate hostnames are
  unbuildable; each granted hostname carries the full M4B-2
  authorization chain independently. Zero grants remains the deny-all
  posture.
- **HTTP/1.1 only.** Worker and origin ALPN are exactly `http/1.1`; h2
  offers fall back (proven with the real git and curl stacks), never
  upgrade.
- **Public, unauthenticated acquisition only.** No credentials exist in
  the worker by construction (structural env control; no netrc, no
  keyring, no credential helpers, no PIP_INDEX_URL family).
- **Pinned artifacts only.** Git SHAs/refs, `--require-hashes` for pip,
  explicit SHA-256 for generic fetches.
- **Artifact integrity is the build script's explicit digest gate.**
  Transport authenticity (a verified broker identity chain) never implies
  artifact identity — the trojaned-complete-download test is the
  canonical proof.
- **Acquisition evidence is a demonstrated conformance pattern**, not a
  shipped controller artifact: the AOSACQ/1 composer
  ([connected-build-evidence.md](connected-build-evidence.md)) joins
  broker authority records with build-script artifact truth in the test
  harness, with a recursive no-secrets invariant.

## What is not earned

- **npm/Node** (absent on the qualified host), **Cargo/Go**, and every
  other package ecosystem.
- **Git LFS, submodules, bundles.** Absolute-URL submodules to unapproved
  hosts are proven DENIED; same-host submodules are unqualified.
- **Release-asset redirect chains** (e.g. CDN hops beyond one
  inside-grant-set redirect).
- **HTTP/2 or HTTP/3** anywhere.
- **Credentials, authenticated registries, keyring, netrc.**
- **Source distributions / build isolation** (`--only-binary=:all:` is
  the qualified pip shape; no sdist, no PEP 517 builds).
- **Windows Connected Build.** The qualification is Linux-only; Windows
  runs the regression suite only (see Tests).
- **Live-Internet qualification.** Fixture origins only.
- **General multi-host** beyond the bounded exact-host set; a fifth host
  is a different task.
- **General browsing, IDNA, seccomp/LSM-stacking, malicious-kernel,
  traffic-analysis, remote-side-effect revocation, or DoS claims**
  (mirrors M4B-1/M4B-2).

## Architecture pointers (per-slice records)

- **Profile and grant set** —
  [connected-build-profile.md](connected-build-profile.md): the bounded
  exact-host grant set (multi-SAN task leaf, per-connection grant
  selection, per-grant accounting) and the deterministic
  AgenticOS-controlled worker environment (lowercase `https_proxy` plus
  task-CA variables; ambient variables stripped structurally).
- **Git** — [connected-build-git.md](connected-build-git.md): real
  git-http-backend fixture origins, protocol-v2 negotiation by default,
  redirect semantics, credential isolation, ALPN fallback with the real
  binary.
- **Fetch** — [connected-build-fetch.md](connected-build-fetch.md): the
  fetch → verify → atomic-rename contract, adversarial origin corpus,
  measured bounds, and the typed `response_remote_unframeable`
  fail-closed detail landed for remote framing violations.
- **pip** — [connected-build-pip.md](connected-build-pip.md):
  hash-verified wheel staging into the worktree, pip-from-wheel-zip
  execution, two-host index+artifact flow, measured pip behavior
  (retries, version check, cache confinement).
- **Lifecycle** —
  [connected-build-lifecycle.md](connected-build-lifecycle.md): the
  cancellation/expiry/revoke matrix with per-cell proof pointers and the
  post-teardown authority-hygiene assertions.
- **Evidence** —
  [connected-build-evidence.md](connected-build-evidence.md): the
  Option-A acquisition-evidence model, per-ecosystem question table,
  no-secrets invariant, and the transport-authenticity vs
  artifact-identity vs reproducibility distinction.
- **Dependency review** —
  [dependency-review-m4b3.md](dependency-review-m4b3.md): the pip wheel
  addition and the pre-existing pycparser ground truth.

## Security properties proven

- **Per-grant independent identity chains.** Every granted hostname
  carries CONNECT authority → SNI → HTTP Host → origin TLS name →
  evidence equality independently; cross-grant mixing fails closed at
  every stage; single-leaf multi-SAN context with per-connection fresh
  SNI policies.
- **Per-grant hard accounting.** Reserve-by-decrement per-grant byte
  authority under one lock (concurrent same-grant connections can never
  observe overlapping budget; overflow fails loud), per-grant connection
  limits with deterministic `grant_connection_limit` /
  `grant_byte_limit` details, policy-aggregate limits unchanged.
- **Redirect authority semantics.** Redirects are relayed byte-exact and
  never followed by the broker; the target re-enters full authorization:
  ungranted targets denied, same-grant-set targets succeed.
- **Structural proxy/CA control.** The worker environment is the fixed
  base tuple plus the Connected Build extension, nothing else: no
  HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/no_proxy/GIT_SSL_NO_VERIFY; CA
  overrides and GIT_SSL_NO_VERIFY cannot widen authority; custom proxy
  values cannot escape; no_proxy bypass dies on direct egress.
- **DNS/SSRF non-regression.** Worker-side `getaddrinfo` fails in every
  ecosystem while broker-side bounded resolution + special-address
  policy completes the operation.
- **Credential absence.** No credential helpers, askpass, netrc,
  keyring, or ambient index/proxy configuration in any ecosystem
  (census-proven).
- **Lifecycle and revocation hygiene.** Cancellation mid-git-clone and
  mid-pip-download leaves no partial trusted output; REVOKED broker
  terminals on cancellation; post-teardown authority hygiene (broker
  reaped, `/tmp/aos-m4b2-ca-*` removed, zero `aos-task` memfds, zero
  `aos-*` units); serialized conformance fixture rotation.
- **Typed response-framing violations.** Origin framing violations
  (duplicate Content-Length, malformed chunks, oversized header blocks)
  terminate fail-closed with the deterministic
  `response_remote_unframeable` detail and zero post-violation bytes
  relayed.

## Reviews

- **Slice 1 (grant set + profile)** — adversarial review FIX-FIRST:
  M1 per-grant byte-limit atomicity (fixed: reserve-by-decrement),
  M2 grant byte-limit coverage (fixed: five tests), L2 type discipline,
  L3 env-name bound (both fixed). Re-reviewed: clean.
- **Slice 2 (git)** — review SHIP with LOWs: L1 protocol-v2 fidelity
  (fixed: `HTTP_GIT_PROTOCOL` mapping + end-to-end v2 test — and the
  corpus moved to v2-by-default), L2 ALPN offer-side proof (fixed:
  GIT_CURL_VERBOSE step), L3 no_proxy + submodule loops (both fixed).
- **Slice 3 (fetch)** — review FIX-FIRST: code sound, stale doc labels
  (fixed: per-case table records `response_remote_unframeable`; the
  "zero production changes" line corrected to record the one bounded
  broker evidence-label change this slice landed).
- **Slice 4 (pip)** — review SHIP with one LOW: HTTP-index refusal
  attribution corrected to the two independent refusal layers (pip's
  pre-connection `is_secure_origin` gate, then absent `http_proxy`), in
  test comment and doc.
- **Slice 5 (lifecycle + evidence)** — review SHIP with LOWs: positive
  mid-pack-stream proof, `basic ` secret scan, curl no-partial citation
  (all fixed). Fixture-rotation race (LOW, conformance-only) fixed by
  serializing the claim decision under `grant_lock`, with a concurrency
  regression test.
- **Final security review** — **EARNED** as scoped (git HTTPS + pip
  two-host + generic curl fetch, public/pinned only, fixture-qualified).
- **Final evidence review** — **COMPLETE**, with the closure-doc tasks
  discharged by this document.

## Tests

- Baseline at 2c285b7 (this session's measured baseline, matching the
  M4B-2 final numbers recorded in session evidence): **1833 passed,
  1 skipped**.
- Slice 1: +86 → **1919 passed, 1 skipped** (79 grant unit tests + 7
  connected-build integration tests; review fixes included).
- Slice 2: +19 (17 corpus + 2 review-added) → **1938 passed, 1 skipped**.
- Slice 3: +20 → **1958 passed, 1 skipped**.
- Slice 4: +14 → **1972 passed, 1 skipped**.
- Slice 5: +6 → **1978 passed, 1 skipped**.
- Fixture-rotation fix: +1 grant unit test → **1979 passed, 1 skipped**.
- **Final verification, full Linux suites: four consecutive green runs —
  1979 passed, 1 skipped each** (335 s, 336 s, 322 s in the closing
  triple; 341 s in the preceding isolated run), no flakes. Disclosure:
  one single-test failure occurred in an earlier triple attempt whose
  run-2 window overlapped concurrent WSL shell activity by the operator
  (a native-build compile and scratch cleanup against session policy);
  the failure did not reproduce in four subsequent fully isolated runs
  (~7900 test executions), residue checks were clean, and the episode is
  attributed to that environmental perturbation, not to the code.
- Windows regression clone (Windows host, regression-only): **777
  passed**, skipped 164 (baseline) → **168** across slices (new
  Linux-gated tests).

## Dependencies added

- `requirements/wheelhouse/pip-26.2.1-py3-none-any.whl`, SHA-256
  `71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e`,
  cross-verified against PyPI's official metadata at staging; pinned in
  `requirements/m4b3-pip.txt`; **test/harness-staged build tooling only**
  (never enters any AgenticOS runtime closure). Review record:
  [dependency-review-m4b3.md](dependency-review-m4b3.md). The served
  pycparser wheel is pre-existing repo ground truth
  (`requirements/m4b2-cert-helper.txt`).

## Residue and lifecycle

Proven sweeps after every flow: zero `aos-*` systemd units
(`_assert_no_m4b_residue` everywhere), worker fd censuses at the fixed
stdio set, pip cache confined to task roots (worker census + host-side
worktree diff), no partial trusted artifacts on any kill path, and the
post-teardown authority hygiene assertions (broker process reaped,
`/tmp/aos-m4b2-ca-*` staging dirs removed, zero `aos-task-*` sealed
memfds in the controller). Full matrix:
[connected-build-lifecycle.md](connected-build-lifecycle.md).
