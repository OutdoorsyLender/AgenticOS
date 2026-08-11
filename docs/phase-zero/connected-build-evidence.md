# M4B-3 Slice 5 — Connected Build: supply-chain acquisition evidence

Status: architecture decided and implemented, 2026-08-10.
Implementation: `_compose_acquisition_evidence` +
`_assert_no_secrets` in `tests/conformance/test_m4b3_lifecycle_integration.py`
(proven by the three `test_evidence_*_acquisition` tests).

## Decision: Option A — controller-side composition (no broker change)

The milestone asks every network acquisition to answer: which tool, which
exact hostname was authorized, which policy digest, what path, redirect?,
status, bytes accepted, artifact digest, package/ref used — without
logging secrets. The broker's `HttpsConnectionRecord` deliberately
records authority minimalism (hostnames, stages, bytes, requests, ALPN —
never request paths or artifact digests).

Two sources already carry the complete answer, so nothing in production
had to change:

1. **Broker authority evidence** (AOSHTTPEV/1): authorized hostname per
   connection, identity-chain verdict, stage/termination detail, request
   counts, per-direction bytes, policy digest and network-policy digest
   (via the terminal record). This is the AUTHORITY proof.
2. **Build-script / fixture truth**: the qualified workflow itself knows
   the request path, the scripted response status, the artifact digest it
   verified, and the package/ref it used. This is the ARTIFACT proof.

Option A composes the two into one per-acquisition evidence JSON
(`evidence_version: "AOSACQ/1"`). **Option B (adding request paths to the
broker schema) was rejected**: the milestone's questions are fully
answerable by composition, and broker minimalism is a security property
(the broker never needs to log URL paths, which can carry sensitive
query components).

## Composed shape

```json
{
  "evidence_version": "AOSACQ/1",
  "tool": "git/2.53.0 (libcurl-gnutls)",
  "authorized_hostnames": ["git.example.com"],
  "policy_digest": "<sha256>",
  "network_policy_digest": "<sha256>",
  "connection_count": 1,
  "bytes_accepted": 3289,
  "operations": [
    {
      "path": "/repo.git/info/refs",
      "status": 200,
      "redirect": false,
      "package_or_ref": "refs/heads/main",
      "artifact_digest": {"algorithm": "git-sha1", "value": "<sha1>"}
    }
  ],
  "broker_records": ["<compacted AOSHTTPEV/1 fields per connection>"]
}
```

Per ecosystem:

| Question | git | pip | curl fetch |
| --- | --- | --- | --- |
| tool | `git/2.53.0 (libcurl-gnutls)` | `pip/26.2.1 (OpenSSL, from hash-pinned wheel)` | `curl/8.18.0 (OpenSSL)` |
| authorized hostname(s) | `git.example.com` | `pypi.example`, `files.example` | `cdn.example.com` |
| path | `/repo.git/info/refs`, `/repo.git/git-upload-pack` | `/simple/pycparser/`, `/packages/…whl` | `/artifact.bin` |
| status | 200/200 | 200/200 | 200 |
| redirect | covered by Slice 2 redirect corpus (same-host succeeds, ungranted denied) | Slice 4 redirect tests | Slice 3 redirect tests |
| bytes accepted | sum of `origin_to_worker_bytes` (== broker records) | idem | idem |
| artifact digest | git-sha1 of the checked-out ref (self-verifying object graph) | sha256 of the wheel (the `--require-hashes` pin) | sha256 verified by the digest gate |
| package/ref used | `refs/heads/main@<sha1>` | `pycparser==3.0` | exact URL |

## No-secrets invariant

`_assert_no_secrets` recursively proves the composed evidence contains no
`authorization`/`cookie`/`token`/`secret`/`password`/`credential` key at
any depth and no `Authorization:`/`Bearer ` value string. Broker records
carry none of these by schema; build-script truth carries none because
the qualified flows use no credentials (proven by the credential-isolation
censuses in Slices 2 and 4). The composed JSON also round-trips loss-free.

## Transport authenticity, artifact identity, reproducibility (in evidence terms)

(The three-way distinction the M4B-3 milestone task specification —
session-governing prompt — draws between what the transport proves and
what the artifact proves.)

- **Transport authenticity** (broker): the bytes came from an
  authorized exact host through the verified identity chain
  (`identity_chain == "verified"`, per-host `approved_hostname`).
- **Artifact identity** (build script): the bytes are the intended
  content (explicit SHA-256 gate for pip/curl; the git object graph's
  own content addressing for git). The Slice 3 trojan test is the
  canonical proof that the first never implies the second.
- **Resolution reproducibility**: the composed record pins the exact
  tool, path, status, bytes, and digest per acquisition, so an auditor
  can replay what the build consumed and verify it against independent
  ground truth (the repo wheelhouse pins).
