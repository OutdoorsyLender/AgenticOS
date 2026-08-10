# M4B-3 Slice 2 — Connected Build: Git HTTPS qualification

Status: qualified against controlled local fixture origins, 2026-08-10.
Proof corpus: `tests/conformance/test_m4b3_git_integration.py` (19 tests,
`m4b_linux`, all passing), worker scenario `M4B3-GIT-01` in
`tests/fixtures/hostile_worker.py`.

## Toolchain under test (exact)

- `git version 2.53.0` (`/usr/bin/git`), `/usr/lib/git-core/git-http-backend`.
- `git-remote-http` links `libcurl-gnutls.so.4` (8.18.0-era) with
  `libgnutls.so.30` and `libnghttp2.so.14` — the ALPN-relevant stack.
- Fixture origin: stdlib-only TLS HTTP/1.1 CGI bridge in front of the real
  `git-http-backend`, serving a bare per-test repository
  (`git init` + 3 commits + branch `dev` + annotated tag `v1.0`,
  `git-daemon-export-ok`). In-process CA per origin; broker-side origin TLS
  authenticates the approved hostname against the fixture trust roots. The
  bridge maps the `Git-Protocol` request header to the CGI variable
  `HTTP_GIT_PROTOCOL`, so protocol negotiation matches real hosting.
- Worker routing: the deterministic Connected Build profile
  (`https_proxy=http://127.0.0.1:18080`, `GIT_SSL_CAINFO`/`SSL_CERT_FILE`/
  `CURL_CA_BUNDLE`/`REQUESTS_CA_BUNDLE` = `/opt/agenticos/network-ca.pem`),
  grant purpose `GIT_SMART_FETCH` (GET/HEAD/POST) for `git.example.com`.

## Protocol version qualification

- **Protocol v2 is qualified and is the negotiated default**: git 2.53 sends
  `Git-Protocol: version=2` on every smart-HTTP `info/refs` request by
  default (verified by header capture); the bridge forwards it to
  `HTTP_GIT_PROTOCOL` and `git-http-backend` answers with the v2
  advertisement (`000eversion 2`). End-to-end v2 negotiation through the
  broker is asserted in `test_git_protocol_v2_negotiated_and_v0_kept`,
  and every other corpus test now runs over v2 exactly as against real
  hosting (e.g. GitHub).
- **Protocol v0 remains qualified**: a forced `-c protocol.version=0`
  ls-remote leg sends no `Git-Protocol` header, is served the v0
  advertisement (`001e# service=git-upload-pack`), and succeeds.

## What was proven (corpus map)

1. **Approved `git ls-remote` succeeds** — real refs (`HEAD`, `refs/heads/main`,
   `refs/heads/dev`, `refs/tags/v1.0` + peel) returned; broker evidence shows
   the verified identity chain for the granted hostname.
2. **Wrong host fails** — ls-remote to `other.example.com` fails;
   `authorization_no_match` recorded (sole-grant fallback records the observed
   divergent CONNECT authority).
3. **Direct bypass fails** — scrubbing `https_proxy` from the git subprocess
   environment fails with zero broker connections; additionally setting
   `no_proxy=<granted-host>` while `https_proxy` remains also fails with zero
   broker connections (curl bypasses the proxy for the named host and direct
   egress is dead). There is no environment shape that routes around the
   broker.
4. **`git clone` succeeds** — `rev-parse HEAD` == expected SHA;
   `git fsck --strict` clean.
5. **`git fetch` retrieves a mid-run origin commit** — commit pushed to the
   bare origin between clone and fetch (host/worktree marker
   synchronization); `origin/main` advances to the new SHA.
6. **Pinned ref retrieval** — `git checkout v1.0` lands `HEAD` exactly on the
   annotated tag's commit SHA.
7. **Custom proxy cannot escape** — both `https_proxy=http://127.0.0.1:9`
   (env) and `git -c http.proxy=http://127.0.0.1:9` fail with zero broker
   connections.
8. **`GIT_SSL_NO_VERIFY=1` cannot widen authority** — the unapproved host
   still fails broker-side; the approved host succeeds (the worker merely
   skips verifying the task CA — its own trust decision; broker-side
   authorization and origin TLS authentication are unchanged).
9. **CA override cannot widen authority** — `GIT_SSL_CAINFO`/`SSL_CERT_FILE`
   pointed at a nonexistent PEM: unapproved still fails broker-side
   (`authorization_no_match`); approved fails only worker-side
   (worker_tls denial). Nothing escapes either way.
10. **HTTP downgrade fails** — a plain `http://` URL consults `http_proxy`,
    which is absent from the fixed profile by construction; the attempt
    tries direct egress (impossible) and never reaches the broker.
11. **Unapproved redirect fails** — origin 302 to an ungranted host: the 302
    is relayed byte-exact (never followed by the broker); git follows and the
    re-CONNECT is denied (`authorization_no_match`).
12. **Same-host redirect characterized** — 302 to a different path on the
    SAME granted host: curl reuses the existing tunnel (1 broker connection,
    3 requests under v2) and the operation succeeds. Same-approved-host
    redirects stay inside authority.
12b. **Absolute-URL submodule to an unapproved host fails at its fetch** —
    a `.gitmodules` absolute URL naming an ungranted host: the parent repo
    clones clean through the broker, then every submodule fetch CONNECT is
    denied at authorization. The same-host submodule case is the same-host
    grant class (covered by items 1/12), not separately implemented.
13. **Credential leakage absent** — env census: no `GIT_ASKPASS`/
    `SSH_ASKPASS`; `$HOME` has no `.gitconfig`/`.git-credentials`;
    `git config --list --show-origin` shows no `credential.*` or `http.proxy`.
    This evidence rests on STRUCTURAL environment control: the worker
    environment is exactly the fixed base tuple plus the Connected Build
    extension, so ambient credential machinery cannot exist by construction.
14. **SSH transport unavailable** — `ssh://git@host/...` and `git@host:...`
    both fail with zero broker connections. The exact cause is intentionally
    ambiguous (no resolvable hostname vs. absent/usable ssh binary in the
    worker's `/usr` view); the security property — no SSH path ever reaches
    the network — is what the test pins.
15. **Worker DNS remains unavailable** — `socket.getaddrinfo` on the granted
    host fails (`gaierror`) while the git operation succeeds (resolution is
    broker-side).
16. **No unexpected worker FDs** — post-operation census contains only the
    worker's fixed stdio descriptors; the git subprocess's descriptors are
    fully reaped.
17. **ALPN fallback with the real binary** — corpus-backed: the ls-remote
    test captures `GIT_CURL_VERBOSE=1` stderr through the worker scenario
    (`stderr_filter=["ALPN"]`) and asserts `ALPN: curl offers h2,http/1.1`
    and `ALPN: server accepted http/1.1`; broker evidence independently
    records `worker_alpn == origin_alpn == "http/1.1"`.
18. **Shallow and branch clones** — `--depth 1` (`rev-list --count` == 1 at
    the expected SHA) and `--branch dev` (HEAD == dev-tip SHA,
    `branch --show-current` == `dev`) succeed.

## Measured connection/byte behavior (this libcurl stack, fixture repo, protocol v2)

- `ls-remote`: 1 broker connection, 2 requests
  (`GET /repo.git/info/refs?service=git-upload-pack` plus the v2 ls-refs
  `POST /repo.git/git-upload-pack` on the same reused tunnel).
- `clone` / `fetch`: 1 broker connection, 3 requests — libcurl REUSES one
  CONNECT tunnel for the v2 advertisement GET, the ls-refs POST, and the
  fetch POST. Small fixture repo: 3289 total relayed bytes for the full
  clone under v2 (1350 worker→origin, 1939 origin→worker).
- Same-host redirect hop: 1 broker connection, 3 requests (1870 bytes).
- Test policy limits are therefore generous-but-explicit:
  `connection_limit=8`, `byte_limit=1 MiB`; grant purposes default to the
  TransportPolicy limits. `POST` bodies use `Content-Length` framing;
  no `Expect: 100-continue` observed from this stack (the CGI bridge
  handles it defensively).

## Redirect semantics

The broker never follows redirects. A 302 is relayed byte-exact; the
redirect TARGET re-enters the full authorization chain on its own CONNECT.
Ungranted targets are denied; same-approved-host redirects succeed and (with
this curl) reuse the existing tunnel.

## Limitations

- Smart HTTP/1.1 only. `git://`, `ssh://`, and scp-style transports are out
  of scope (proven unavailable, item 14).
- LFS and authenticated (credential-bearing) remotes are NOT qualified.
  Submodules are qualified only in the negative: absolute-URL submodules
  naming unapproved hosts fail at their fetch (item 12b); same-host
  submodules are the same-host grant class and are not separately
  implemented. Bundle/MTLS client certs are out of scope.
- Qualification is against controlled fixture origins via the conformance
  fixture path (`synthetic_origin=True` evidence); production origin
  TLS/DNS/SSRF posture is the M4B-2 path, unchanged by this slice.
