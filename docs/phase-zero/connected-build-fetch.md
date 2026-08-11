# M4B-3 Slice 3 — Connected Build: bounded artifact acquisition

Status: qualified against adversarial local fixture origins, 2026-08-10.
Proof corpus: `tests/conformance/test_m4b3_fetch_integration.py` (20 tests,
`m4b_linux`, all passing), worker scenario `M4B3-FETCH-01` in
`tests/fixtures/hostile_worker.py`. Slice 3 required exactly one bounded
production change: a typed fail-closed evidence detail
(`response_remote_unframeable`) for remote-side response framing
violations in `network_broker.py` — semantics unchanged, evidence label
only.

## Client under test (exact)

- `curl 8.18.0 (x86_64-pc-linux-gnu) libcurl/8.18.0 OpenSSL/3.5.5` —
  `/usr/bin/curl`, driven through the committed Connected Build profile
  (`https_proxy=http://127.0.0.1:18080`, `CURL_CA_BUNDLE`/`SSL_CERT_FILE`/
  `REQUESTS_CA_BUNDLE`/`GIT_SSL_CAINFO` = `/opt/agenticos/network-ca.pem`),
  grant purpose `GENERAL_DOWNLOAD` (GET/HEAD) for `cdn.example.com`.
- ALPN measured: `worker_alpn == origin_alpn == "http/1.1"` on every record.

## The qualified fetch → verify → rename contract

Artifact identity is the build script's explicit digest gate, NOT the
transport. The broker proves the bytes came from an authorized host; only
the script's SHA-256 check proves they are the intended artifact. The
qualified pattern (executed literally by the scenario's `fetch_artifact`
step and recommended verbatim for controller build scripts):

```sh
# 1. Fetch to a staging name NEXT TO the destination (same filesystem).
curl -fsS --proto '=https' --tlsv1.2 -o "$DEST.partial" "$URL" || exit 1
# 2. Verify the explicit expected digest over the staged bytes.
echo "$EXPECTED_SHA256  $DEST.partial" | sha256sum -c - || exit 1
# 3. Atomically rename into place — only ever on digest match.
mv -T "$DEST.partial" "$DEST"
```

Contract invariants proven by the corpus: curl writes only to
`$DEST.partial`; the digest gate runs over whatever was staged (including
after curl failure — a partial file cannot match an honest digest); the
rename happens only on `exit 0` + digest match + non-empty artifact;
`$DEST` can never contain partial, truncated, padded, or trojaned content.

Hardening note: the qualified contract has NO caller-influenced curl
flags. The scenario's `curl_extra` parameter is a test-harness escape
hatch only (the redirect corpus needs `-L`) — curl applies
last-occurrence-wins semantics, so any extra flag could override
`--proto '=https'` and must never reach a real build script.

## Per-case behavior (all measured end-to-end)

| Origin behavior | curl result | Broker evidence | Artifact outcome |
| --- | --- | --- | --- |
| Valid Content-Length body | exit 0 | verified chain; wire bytes == head+body | digest verified, renamed |
| 4 MiB body within limits | exit 0 | 1 conn; 4 MiB+head relayed | digest verified, renamed |
| Short body (CL > delivered, EOF) | exit 56 | verified chain | partial staged, gate rejects, no rename |
| Long body (bytes > CL) | exit 0 (truncates at CL) | verified chain | gate rejects vs full-body digest, no rename |
| Duplicate/conflicting Content-Length | exit != 0 | h11 RemoteProtocolError → `response_remote_unframeable`, peer_error; zero post-violation bytes relayed | nothing staged |
| Valid chunked | exit 0 | verified chain (h11 frames it) | digest over DE-CHUNKED bytes verified, renamed |
| Malformed chunk-size line | exit != 0 | `response_remote_unframeable`; only the valid pre-violation head relayed | nothing staged |
| 20 KiB response headers | exit 0 | verified chain (see bound note) | digest verified, renamed |
| 40 KiB response headers | exit != 0 | `response_remote_unframeable`; exactly one 16384 B chunk relayed pre-trip | nothing staged |
| Body > grant byte_limit | exit != 0 | `grant_byte_limit`, byte_limit; policy aggregate untripped | partial staged, gate rejects, no rename |
| Drip 0.4 s gaps (< 30 s idle bound) | exit 0 | verified chain | renamed |
| Drip 35 s gap (> 30 s idle bound) | exit != 0 | broker gives up first: `origin_response_timeout`, peer_error | partial staged, no rename |
| Policy expiry mid-download | exit != 0 | terminal EXPIRED | partial staged, no rename, no residue |
| Worker cancellation mid-download | scope killed | terminal records intact | no artifact, no residue |
| 302 same granted host (`-L`) | exit 0 | 1 conn (tunnel reuse), 2 requests | renamed |
| 302 to ungranted host (`-L`) | exit != 0 | 302 relayed verified + re-CONNECT `authorization_no_match` | no artifact |
| 302 HTTPS→HTTP downgrade (`-L`) | exit != 0 | only the relayed 302 (`http_proxy` absent; direct egress dead) | no artifact |
| Fetch from ungranted host | exit != 0 | `authorization_no_match` (sole-grant fallback records divergent authority) | no artifact |
| Direct egress (proxy env scrubbed) | exit != 0 | zero broker connections | no artifact |
| Complete but WRONG bytes (trojan) | exit 0 | verified chain | **digest gate rejects, no rename** |
| HEAD / 204 / 304 | exit 0, no body | verified chain | N/A (nothing staged; documented) |

## Measured bounds (this stack)

- `ls`-style small artifacts: 1 broker connection, 1 GET.
- Response-head bound: h11's incomplete-event limit is 16384 bytes per
  buffered event and the broker relays in exactly 16384-byte chunks
  (`RELAY_CHUNK_BYTES`), so a head of up to ~32 KiB can pass on chunk
  alignment (measured: 20 KiB passes; 40 KiB trips). Beyond the trip the
  connection terminates fail-closed; at most one chunk is ever relayed
  before the framer sees the violation.
- Origin idle bound: `HTTPS_RESPONSE_IDLE_TIMEOUT_SECONDS = 30` counts only
  byte-progress gaps, not total transfer time (0.4 s-gap drip of any length
  succeeds; one 35 s gap terminates).
- Test policy limits for large artifacts: `connection_limit=8`,
  `byte_limit=8 MiB` for the 4 MiB case (measured usage ≈ 4.1 MiB);
  per-grant `byte_limit=64 KiB` for the grant-bound case.

## Security-relevant observations

- **Response-framing violations are typed fail-closed**: origin-side h11
  violations (duplicate/conflicting Content-Length, malformed chunk-size,
  oversized header block) raise h11.RemoteProtocolError and are caught
  distinctly in the broker's relay, emitting the deterministic typed
  detail `response_remote_unframeable` with unchanged fail-closed
  semantics (connection terminated, nothing after the violation relayed —
  proven at zero bytes for head violations — curl fails, no artifact).
  Local-side seed/framing issues keep the pre-existing
  `response_unframeable` label.
- **The digest gate is indispensable**: long bodies and trojaned complete
  downloads both traverse the transport with a fully verified identity
  chain; only the explicit SHA-256 check separates artifact identity from
  transport authenticity. This is the contract's headline property.

## Limitations

- GET/HEAD smart-HTTP/1.1 downloads only; no POST/upload workflow, no
  ranged/resumed downloads (`curl -C -` re-runs the full request under a
  fresh CONNECT and is out of scope for this qualification).
- The qualified contract covers single-file artifacts with an explicit
  out-of-band SHA-256. Signature schemes (PGP/signature-over-digest) and
  package-manager metadata flows are not qualified here.
- Qualification uses the conformance fixture path (`synthetic_origin=True`
  evidence); production origin TLS/DNS/SSRF posture is the M4B-2 path,
  unchanged by this slice.
