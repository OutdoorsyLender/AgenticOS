# M4B-3 Connected Build — Ecosystem Qualification Plan

Status: Slice 0 deliverable (qualification plan). Not a boundary claim.
Milestone: M4B-3. Baseline commit: `2c285b73514a3075fd326d9dc72b841e5a7433c9`.

## 1. Purpose

M4B-2 earned authenticated, task-scoped, single-approved-host HTTPS brokering.
M4B-3 determines whether real build ecosystems can consume that primitive
without the worker regaining general network authority, and proves it with
conformance evidence. This document records the starting baseline, the
behavior-probed facts about candidate clients, the qualification matrix, and
the slice plan. It is the required initial deliverable before implementation.

## 2. Starting baseline (independently verified this session)

```text
WINDOWS_HEAD=2c285b73514a3075fd326d9dc72b841e5a7433c9
WSL_HEAD=2c285b73514a3075fd326d9dc72b841e5a7433c9
ORIGIN_MAIN=2c285b73514a3075fd326d9dc72b841e5a7433c9
GITHUB_MAIN=2c285b73514a3075fd326d9dc72b841e5a7433c9  (git ls-remote)
WINDOWS_TREE=clean
WSL_TREE=clean
UNPUSHED_COMMITS=0
STASH_ENTRIES=0
```

Linux baseline test run (WSL, this session, on the baseline commit):
`1833 passed, 1 skipped, 9 warnings in 161.16s` — identical to the recorded
M4B-2 final numbers. Windows regression baseline to be recorded before the
first code-changing slice closure.

## 3. Repository evidence reviewed

- `docs/phase-zero/runtime-boundary.md` (M4A earned claim)
- `docs/phase-zero/connected-build-boundary.md` (M4B-1 earned claim; the name
  predates the milestone split)
- `docs/phase-zero/https-broker-policy.md` (M4B-2 earned claim)
- `docs/phase-zero/host-capabilities.md`, `dependency-review-m4b2.md`,
  `sandbox-conformance.md`, `docs/roadmap.md`
- `src/agenticos/sandbox/`: `network_broker.py`, `network_https.py`,
  `network_http.py`, `network_tls.py`, `network_clienthello.py`,
  `network_identity.py`, `network_origin.py`, `network_resolution.py`,
  `network_models.py`, `cert_helper.py`, `host_qualification.py`,
  `m4b_runner.py`, `runtime_boundary.py`, `special_addresses.py`
- `tests/conformance/test_m4b*.py`, `test_m4a*.py`, `test_m4b2_*_regression.py`

Established prior guarantees that M4B-3 must not weaken: M4A namespace /
Landlock / FD / no-network / cgroup lifecycle isolation; M4B-1 sealed
task-scoped transport policy and least-authority broker boundary; M4B-2
exact-host identity chain (CONNECT authority == worker SNI == HTTP Host ==
origin TLS name == evidence name), ECH rejected pre-trust, no second
ClientHello, no renegotiation, ALPN `http/1.1` only, strict raw HTTP/1.1
envelope, bounded single-shot DNS with IANA-derived SSRF rejection, numeric
origin connect, origin TLS authenticated against the approved hostname,
fail-closed startup probes, short-lived cert helper with sealed per-task
material, host qualification re-verified at every launch.

## 4. Host facts (behavior-probed this session, qualified host = Ubuntu WSL2)

| Tool | Version | TLS backend | Notes |
|---|---|---|---|
| git | 2.53.0 | libcurl-gnutls 8.18.0 / GnuTLS 3.x | `ldd /usr/lib/git-core/git-remote-https` confirms libcurl-gnutls; matches host-qualification manifest split |
| curl | 8.18.0 | libcurl / OpenSSL 3.5.5 | standalone curl uses OpenSSL, distinct from git stack |
| python3 (system) | 3.14.4 | OpenSSL 3.5.5 | no pip module on system python |
| pip | 26.2.1 | OpenSSL 3.5.5 (via project `.venv`, Python 3.14) | worker-side pip provisioning is a Slice 4 problem |
| node / npm | **absent** on the qualified host | n/a | only a Windows miniconda shim leaks through PATH; not a Linux toolchain |

Ambient config state on the host: no `~/.gitconfig`, no `~/.npmrc`,
no `~/.netrc`. This is the desired posture and must be preserved.

### 4.1 CONNECT-behavior probes (local capture listener, no Internet)

A local TCP capture stood in for the broker at `127.0.0.1:<port>`; each
client ran with `env -i` (clean environment) plus only `https_proxy`:

- **git ls-remote https://git.example.com/repo.git** — one connection;
  `CONNECT git.example.com:443 HTTP/1.1` with `Host`, `User-Agent: git/2.53.0`,
  `Proxy-Connection: Keep-Alive`; after `200`, a TLS ClientHello (0x16) with
  SNI `git.example.com` and ALPN offering `h2` + `http/1.1`.
- **curl https://dl.example.com/artifact.tar.gz** — identical CONNECT shape;
  ClientHello SNI `dl.example.com`, ALPN `h2` + `http/1.1`.
- **pip download --index-url https://pypi.example.com/simple/ six** — three
  CONNECTs (pip self version-check plus one retry); ClientHello SNI
  `pypi.example.com`, ALPN offering **`http/1.1` only**.

Conclusions: all three clients natively speak the exact M4B-2 broker ABI
(plaintext CONNECT, then TLS with correct SNI through the tunnel). None
requires DNS in the worker when a proxy is configured. git/curl offer `h2`
in ALPN but the broker terminates worker TLS and negotiates only
`http/1.1`; HTTP/1.1 fallback under ALPN is standard libcurl behavior and
must be conformance-tested, not assumed. pip already offers only
`http/1.1`. No protocol redesign is indicated.

## 5. Ecosystem qualification matrix

Classification legend: `QUALIFIABLE_UNCHANGED`, `QUALIFIABLE_WITH_CONTROLLED_CONFIGURATION`,
`REQUIRES_SMALL_AGENTICOS_CHANGE`, `REQUIRES_SECURITY_DESIGN_CHANGE`, `OUT_OF_SCOPE`.

| Ecosystem | Classification | Rationale |
|---|---|---|
| Git HTTPS (ls-remote/clone/fetch, public, pinned refs) | REQUIRES_SMALL_AGENTICOS_CHANGE | Protocol shape already matches the broker ABI (section 4.1). Needs: deterministic Connected Build worker profile (proxy + CA env), worker access to a `git` binary, and conformance corpus. The `GIT_SMART_FETCH` grant purpose and GET/HEAD/POST method policy already exist. |
| pip (public index, pinned + hash-checked, binary wheels) | REQUIRES_SMALL_AGENTICOS_CHANGE | Real PyPI needs two exact hosts (`pypi.org` index + `files.pythonhosted.org` artifacts). M4B-2 launch validation enforces exactly one grant; a bounded explicit exact-host grant set is the smallest change that avoids wildcards. Also needs the Connected Build profile and worker-side pip provisioning. The offline wheelhouse path remains preferred where determinism allows. |
| Generic artifact fetch (curl-style, known URL + known digest) | REQUIRES_SMALL_AGENTICOS_CHANGE | The `GENERAL_DOWNLOAD` purpose and GET/HEAD policy already exist; needs the same profile plumbing plus an AgenticOS-owned bounded fetch/digest verification path inside the worker so artifact identity, not just transport authenticity, is proven. |
| npm / Node | OUT_OF_SCOPE | No Node.js on the qualified host; no current AgenticOS goal requires Node package acquisition. Qualifying npm would require qualifying an entire toolchain first. Revisit only with evidence of need. |
| Cargo, Go modules | OUT_OF_SCOPE | No toolchains on the qualified host; no current goal requires them. |
| Git LFS | OUT_OF_SCOPE (useful later) | LFS contacts separate object-storage hosts with signed URLs; needs its own authority model. Plain same-host submodules remain possible under the Git profile but are not separately qualified in M4B-3. |
| GitHub release assets | OUT_OF_SCOPE (useful later) | Multi-host with redirect chains to `objects.githubusercontent.com`; the bounded grant-set model would cover it, but no current goal requires it. |
| CMake FetchContent / Meson wrap / toolchain bootstraps | OUT_OF_SCOPE | Decompose to generic artifact fetch when needed later. |
| SSH/`git://` transports, HTTP/2, HTTP/3, private registries, credential brokering | OUT_OF_SCOPE | Explicitly excluded by milestone scope and M4B-2 boundary docs. |

## 6. Authority model decisions (design constraints for implementation slices)

1. **Exact-host only, bounded grant set.** Replace the controller-side
   exactly-one-grant restriction with a small explicit maximum (target: no
   more than 4) of controller-approved, canonical exact hostnames, each with
   its own purpose, methods, connection and byte limits. No wildcard,
   suffix, or pattern authorization. The broker-side per-request
   `authorize_grant` exact-match machinery already handles multiple grants
   fail-closed; uniqueness of canonical hostnames in the set is validated
   controller-side.
2. **Redirects are not broker-followed.** The broker relays responses
   byte-exact; a 3xx is delivered to the client. Any redirect target —
   same host or different — is fetched by the client as a new request that
   undergoes the full identity chain again: same approved host means
   authorized; a different host means authorized only if that exact host
   holds its own grant, otherwise fail-closed with no match. HTTPS to HTTP
   downgrade is structurally impossible (the broker accepts CONNECT on port
   443 only and relays only inside TLS). This preserves exact-host
   authority with no redirect parser in the trusted path.
3. **Deterministic Connected Build worker profile.** A profile is a fixed,
   controller-constructed extension of the worker environment/mount plan:
   proxy routing env (`https_proxy=http://127.0.0.1:18080`, lowercase form
   only, `no_proxy` unset), per-tool CA wiring to the read-only
   `/opt/agenticos/network-ca.pem` (`SSL_CERT_FILE`, `GIT_SSL_CAINFO`,
   `REQUESTS_CA_BUNDLE`/`PIP_CERT` as each tool requires — resolved from
   probes, not documentation), controlled `HOME` inside the task-owned
   writable root, and explicit absence of every ambient credential/proxy/
   trust variable. Proxy env is routing configuration; the security boundary
   remains M4A netns isolation plus the M4B sealed policy. Worker DNS stays
   unavailable; resolution remains broker-side.
4. **Artifact integrity is separate from transport authenticity.** Qualified
   workflows must pin: Git by commit SHA, pip by `--require-hashes` and
   `--only-binary=:all:`, generic fetch by explicit SHA-256 verified
   worker-side before the artifact is trusted build input.
5. **Credentials stay out of scope.** Public unauthenticated acquisition
   only. No tokens, netrc, keyring, credential helpers, SSH keys/agent in
   the worker. The profile actively strips them.
6. **HTTP/1.1 only, bounded everything.** ALPN remains `http/1.1` only; if a
   qualified client proves unable to operate under ALPN-selected HTTP/1.1
   that is a stop condition, not a reason to add HTTP/2. All existing M4B-2
   bounds remain; M4B-3 adds per-grant-set aggregate bounds only where real
   client measurements justify them (git/pip connection counts measured
   during qualification).

## 7. Slice plan

- **Slice 0 (this document):** baseline, probes, matrix, plan. Docs-only.
- **Slice 1 — Connected Build profile plumbing:** deterministic worker
  profile (env/CA/HOME) plus bounded multi-grant policy validation with
  per-grant purposes/limits; unit and integration tests; zero behavior
  change for existing single-grant launches beyond the generalized
  validation.
- **Slice 2 — Git qualification:** conformance corpus (approved
  ls-remote/clone/fetch/pinned ref via controlled local fixture origin;
  wrong host, direct bypass, unapproved proxy, `GIT_SSL_NO_VERIFY`,
  unapproved CA override, downgrade, redirect corpus, credential-helper
  absence, SSH unavailable, DNS absent, FD census, M4A/M4B regressions).
- **Slice 3 — Generic bounded artifact fetch:** worker-side fetch helper
  with digest verification, size bounds, atomic staging; adversarial
  download corpus (short/long bodies, chunked malformation, premature EOF,
  slow drip, oversized headers/body, mid-transfer broker death).
- **Slice 4 — pip qualification:** worker-side pip provisioning, two-grant
  PyPI-shaped local fixture, corpus including hash-pinned install,
  trusted-host/extra-index resistance, cache confinement, corrupt-artifact
  rejection.
- **Slice 5 — Lifecycle/cancellation and evidence closure:** cancellation
  during git/pip acquisition, residue/FD/secret sweeps, supply-chain
  evidence fields (no secrets), final adversarial reviews.
- **Slice 6 — Final verification:** three consecutive full Linux suites,
  Windows regression suite, native builds warning-clean, independent final
  security and evidence reviews, milestone closure per the preservation
  contract.

Every slice closes with the repository preservation procedure (commit, push,
`git ls-remote` verification, sync both clones, verify SHA-identical clean
trees) before the next slice begins.

## 8. Deferred / not claimed

Multi-host workflows beyond a bounded explicit exact-host grant set;
broker-side redirect following; HTTP/2; npm; LFS; private registries and any
credential capability; Windows Connected Build qualification. Live-Internet
compatibility tests, if run, are supplemental evidence only, never the sole
proof of the boundary.
