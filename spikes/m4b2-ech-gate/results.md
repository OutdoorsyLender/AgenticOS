# M4B-2 ECH enforcement spike — measured evidence

SPIKE — not production code, not integrated anywhere. All fixtures are
synthetic and local (AF_UNIX socketpair / 127.0.0.1). No packages installed,
no host configuration changed, no production files modified.

Recorded host: Ubuntu 26.04 WSL2, kernel 6.6.87.2-microsoft-standard-WSL2,
Python 3.14.4, OpenSSL 3.5.5 (27 Jan 2026), gcc 15.2.0, bubblewrap 0.11.1.

## Host capability facts

- `libssl.so.3`/`libcrypto.so.3` present and export the documented
  ClientHello API (`SSL_CTX_set_client_hello_cb`, `SSL_client_hello_get0_ext`,
  `SSL_client_hello_get1_extensions_present`,
  `SSL_client_hello_get_extension_order`, `SSL_client_hello_isv2`).
- `/usr/include/openssl` is ABSENT (no libssl-dev). No `Python.h`
  (no python3-dev). No `make`, no `pkg-config`. gcc/cc present.
- This OpenSSL build has ECH compiled out: no `SSL_ech_*` symbols exported;
  curl 8.18.0 CLI knows `--ech` but libcurl reports "the installed libcurl
  version does not support this". No stock host client can emit real ECH;
  synthetic wire fixtures are necessary and were used throughout.
- Python `ssl` exposes `OP_NO_RENEGOTIATION`; measured effective (E4 below).
- Repo native helpers (fs_launcher, task_supervisor) are built by direct
  `cc` invocations with no build system; a native ECH component would
  additionally need OpenSSL headers (absent) or hand-declared ABI prototypes
  (used by this spike's probes).

## Candidate A — native OpenSSL callback shim: measured results

Probe: `ech_cb_probe.c` (hand-declared prototypes against the documented
OpenSSL 3.x ABI; builds warning-clean with `-Wall -Wextra -Werror`).

A1. `client_hello_cb` + `SSL_client_hello_get0_ext(0xfe0d)` — the mechanism
    named in the approved M4B design doc — **cannot see ECH on this host.**
    With a wire-verified ECH-bearing ClientHello, `get0_ext` returns
    "not present", `get1_extensions_present` omits it, and
    `get_extension_order` omits it. Same for an arbitrary unknown extension
    (0xCAFE). Root cause (OpenSSL 3.5 source, `ssl/statem/extensions.c`,
    `tls_collect_extensions`): unrecognized extension types hit
    `if (thisex == NULL) continue;` and are never recorded; the
    `SSL_client_hello_*` accessors only expose extensions the stack
    *recognizes*. The man page does not state this restriction. The
    design-doc mechanism is empirically dead on the recorded host.

A2. Registering 0xfe0d as a *custom extension* (`SSL_CTX_add_custom_ext`;
    only the original 6-arg callback ABI is exported by this build) makes
    it "recognized", and then any ClientHello containing 0xfe0d is fatally
    rejected during extension collection with `illegal_parameter`, BEFORE
    the servername callback and BEFORE `client_hello_cb`, for the first
    ClientHello AND the post-HRR second ClientHello. Non-ECH ClientHellos
    pass normally. So as a *mechanism* this works deterministically and
    fail-closed on this host. Caveats honestly recorded: the rejection
    fires even when the registered parse callback returns success (the
    parse callback is never invoked; the exact internal branch was not
    identified and diverges from upstream documentation), the same behavior
    reproduces for a registered 0xCAFE, and it yields no positive ECH
    observation for evidence records.

A3. Integration — the disqualifier. Python's `ssl.SSLContext` exposes
    neither `client_hello_cb` nor custom-extension registration. Attaching
    either to CPython's internal `PySSLContext->ctx` pointer would be
    unsupported CPython-internal coupling (a stated stop condition). The
    only sound Candidate A integration is therefore: the native component
    owns the worker-facing TLS endpoint entirely (accept, handshake,
    SNI/ALPN/ECH policy, per-task leaf presentation, CA private key in
    native code) and hands Python a post-TLS plaintext stream. That
    contradicts the M4B-1-derived boundary discipline: a new native TCB
    class holding the per-task CA key, a split of broker security policy
    across two languages, and a native build dependency on OpenSSL headers
    the approved host does not have. Candidate A is rejected on integration
    grounds, not because the callback mechanism failed.

## Candidate B — bounded ClientHello gate: measured results

Implementation: `ech_gate.py` (feed parser, ~200 lines, stdlib-only) +
`gate_driver.py` (bounded socket driver + verbatim replay into
`ssl.MemoryBIO`/`SSLObject` server side). The gate reassembles exactly one
ClientHello handshake message from bounded TLS records, strictly validates
every length field, enumerates extension IDs, rejects 0xfe0d, and returns
the exact original bytes (including coalesced trailing bytes) for replay.
It never normalizes or rewrites the byte stream.

Conformance corpus: `run_corpus.py`, **50 cases**, each driven against up
to four targets: T1 gate+Python-ssl pipeline, T2 bare Python-ssl
(permissive SNI logging), T3 native probe (log), T4 native probe
(deny-ech). Machine-readable output: `results.json`; console log:
`full-run.log`. Final run: **50/50 as expected, zero critical findings,
zero parser differentials.**

Key measured behaviors:

- ECH denial (e08–e17): every ECH case (valid payload, zero-length,
  arbitrary, duplicate, approved/unapproved outer SNI, TLS1.2 CH carrying
  ECH, ECH without SNI, extension split across records and across
  transport writes, ECH at extension index 256 and 257) is rejected with
  zero SNI-callback firings — the decision precedes any SNI trust.
- The gap the gate closes is real: bare Python/OpenSSL (T2) accepts the
  well-formed ECH ClientHello and proceeds with the outer SNI
  (`ch_accepted`, `sni_fires=['approved.example.test']`).
- Positives: TLS1.2/TLS1.3 CHs, record-fragmented, byte-drip delivery,
  coalesced records, CH+CCS coalesced, mixed record versions across
  fragments (0301/0303), unknown non-ECH extensions, GREASE extensions —
  all accepted by gate AND OpenSSL with identical SNI observations.
- Differential: for every gate-accept case, the gate's extension list
  restricted to OpenSSL-visible IDs equals OpenSSL's own wire-order list,
  and gate SNI == Python sni_callback SNI == native probe SNI. Caveat:
  the differential oracle registers 0xfe0d in the probe, so OpenSSL's
  ECH visibility there is a modified-parser view; the comparison spans
  gate-accept (ECH-free) cases. The load-bearing safety argument is
  structural: verbatim replay of an unambiguous length-prefixed format,
  with every gate/OpenSSL divergence measured to be in the safe
  (gate-stricter) direction.
- Malformed inputs (bad record/handshake/extension lengths, truncation,
  overrun, excessive records/bytes, timeout, EOF, wrong content type,
  random bytes, SSLv3 record version, zero-length records mid-fragment,
  CCS before CH, session-id/compression length lies, duplicate unknown
  extensions, extension-count and CH-size boundaries at 16384/16385) all
  reject fail-closed.
- SSLv2-style ClientHello: gate rejects (first byte 0x80). Bare OpenSSL
  3.5 still accepts the *format* (`isv2=1`) but it cannot carry SNI or
  extensions, so no hostname trust can derive from it. Safe-direction
  differential only.
- Second ClientHello coalesced or in a second flight (x27, g02, g03):
  gate accepts the first and forwards verbatim; OpenSSL itself rejects
  the second. No SNI trust beyond the first CH.
- Missing SNI (p_missing_sni, g01, g10): gate accepts (not its job);
  the SNI policy callback observes `None` and the handshake fails.
- HelloRetryRequest (forced via key_share/supported_groups mismatch):
  * Python's `sni_callback` fires **again** for the post-HRR second
    ClientHello — an independent policy enforcement point.
  * Bare OpenSSL does **not** enforce CH1==CH2 SNI equality (x28b T2:
    permissive callback, SNI swap accepted). Exact-hostname policy MUST
    re-verify on every firing. The spec must not assume TLS-stack SNI
    consistency enforcement.
  * x28c proves the closure: with `abort_on_second_sni_fire` policy, the
    second firing aborts the handshake (CALLBACK_FAILED) and no server
    flight follows CH2. ECH-in-CH2 never reaches a trusting component.
  * Without that policy (x28), ECH appearing only in CH2 passes the
    gate's first-CH inspection. It is inert on this host (no ECH keys or
    machinery anywhere in the stack), but that inertness is an
    environmental fact. Two controls convert it into a structural one:
    mandatory refusal of any second ClientHello, and the startup probe
    below.
- TLS1.2 renegotiation: `OP_NO_RENEGOTIATION` set; a real
  `SSL_renegotiate` C client measured: `RENEGOTIATION_REFUSED` /
  "no renegotiation", server sees handshake-failure alert (E4).
- End-to-end (`e2e_tests.py`): real Python TLS1.3 and TLS1.2 clients
  complete through the gate with ALPN `http/1.1` (E1, E2); an h2-only
  client completes with selected ALPN `None`, so M4B-2 MUST post-check
  `selected_alpn_protocol() == "http/1.1"` (E3); system curl cannot emit
  ECH (E5).
- Startup probe (`startup_probe.py`): gate self-test (synthetic ECH CH
  must reject; clean CH must accept; replay must be verbatim) + pinned
  `ssl.OPENSSL_VERSION` + ctypes check that the loaded libssl exports no
  ECH machinery symbols. All pass on the recorded host; any failure is
  fail-closed. This is the production pattern for pinning the
  environment-dependent leg of the CH2 argument.

## Bounds (enforced in `ech_gate.py` / `gate_driver.py`)

- record payload ≤ 16384 (RFC 8446 §5.1 max plaintext fragment)
- record-layer version 0x0301–0x0303 only
- accumulated ClientHello handshake bytes ≤ 16384 (boundary-tested at
  16384 accept / 16385 reject)
- record count ≤ 64; extension count ≤ 256 (boundary-tested at 256/257)
- transport read calls ≤ 4096 (subordinate to byte and time bounds)
- wall-clock gate timeout 5 s (corpus uses shorter)
- zero-length handshake records rejected; first handshake message must be
  ClientHello; duplicate extensions rejected (RFC 8446 §4.2; OpenSSL
  tolerates duplicates of unrecognized extensions — safe-direction
  difference)

Measured compatible clients (Python ssl, openssl s_client, curl): one
record, ≤ ~1.5 KB, ≤ ~30 extensions. Bounds are ≥10x generous per axis.

## Lifecycle interaction (handoff items 31–40)

The gate runs inside the existing broker process on the already-accepted
worker connection; it adds no worker-visible FD, process, file, or cgroup.
Worker cancellation/death mid-parse manifests as EOF/timeout → reject
(m23/m24). Broker cancellation, expiry, death, descriptor and cgroup
cleanup remain the untouched M4B-1 machinery. The spike modifies no
production code; M4B-1 non-regression is by construction, and the suites
were re-run on this host: `test_m4b_unit.py` 442 passed,
`test_m4b_integration.py` 59 passed.

## Independent adversarial review — findings and resolutions

Two independent reviewers attacked the spike. Resolutions:

- "Post-HRR CH2 ECH residual is under-closed" → x28c added: HRR flows are
  refused by policy (abort on second sni firing); measured abort. The
  refusal is a REQUIRED element of the recommended architecture, not an
  option.
- "Environment leg unpinned" → `startup_probe.py` prototype added
  (gate self-test + version pin + ECH-machinery symbol absence).
- "Candidate A dismissal leaned on unexplained branch" → reframed: A2
  mechanism measured working; A rejected on integration grounds (A3).
- "Unasserted state-case invariants" → x27/x28/x28b/x30/g02/g03 now
  assert exact OpenSSL outcomes and SNI firing counts.
- "Dead ECH differential oracle" → acknowledged and documented above as
  a modified-parser caveat; the structural argument carries the proof.
- "Untested gate branches" → g01–g11 added (no-extensions block, two
  messages in one record, TLS1.2 second-flight CH, extension-count and
  CH-size boundaries, length-lies, zero-length record, CCS-before-CH,
  mixed record versions, empty extension vector, duplicate unknown ext).
- "Case-count drift" → corpus is 50 cases; this document matches.

## Exact security claim this evidence supports

On the recorded host (Ubuntu 26.04 WSL2, Python 3.14.4, OpenSSL 3.5.5
with ECH machinery absent), a bounded pre-TLS ClientHello gate rejects
every initial ClientHello carrying extension 0xfe0d before any SNI trust
decision, with verbatim byte replay into OpenSSL and zero measured parser
differential across a 50-case adversarial corpus spanning TLS1.2/1.3,
fragmentation, coalescing, GREASE, and malformed inputs. Combined with
(a) mandatory refusal of any second ClientHello (measured: abort on the
second SNI callback firing), (b) exact-hostname re-verification on every
SNI callback firing, (c) OP_NO_RENEGOTIATION (measured effective), and
(d) a fail-closed broker startup probe (gate self-test + pinned OpenSSL
version + libssl ECH-symbol absence), the broker can deterministically
guarantee that no ECH-bearing ClientHello is ever acted upon and every
hostname the broker acts on is independently verified.

## Claims NOT earned by this spike

- No claim against an ECH-capable TLS stack (none exists on this host;
  real ECH decryption semantics were never exercised — the fixtures prove
  extension-ID detection and pre-SNI rejection, not ECH protocol
  behavior).
- No claim about concurrency/DoS under many simultaneous gated
  connections (corpus is sequential; the 5 s gate window per connection
  needs a broker-level concurrency bound in the M4B-2 design).
- No production integration claim: the gate is spike code; the broker
  integration boundary is specified, not implemented.
- No Connected Build claim of any kind.
