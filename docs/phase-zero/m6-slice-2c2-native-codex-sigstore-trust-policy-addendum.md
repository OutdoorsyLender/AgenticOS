# M6 Slice 2C.2 — Native Codex Sigstore Verifier and Trust-Policy Addendum

Status: documentation-only trust decision, prepared 2026-08-12.

```text
DECISION_OUTCOME=INDEPENDENT_OWNER_DIGEST_REQUIRED
RESEARCH_STATUS=BLOCKED_NO_APPROVED_PREEXISTING_OWNER_DIGEST_AUTHORITY
SIGSTORE_AUTHORITY_SELECTED=NO
SIGSTORE_SWITCH_REVIEWED=YES
SIGSTORE_SWITCH_DECISION=REJECTED_BLOCKED_MISSING_TARGET_ARCHIVE_MEMBER_BINDING
OWNER_DIGEST_BRANCH_APPROVED=YES
OWNER_DIGEST_BRANCH_STATUS=BLOCKED_NO_APPROVED_PREEXISTING_AUTHORITY
OWNER_DIGEST_DELIVERY_MODE_SELECTED=NO
OWNER_KEY_GENERATED=YES
OWNER_PRIVATE_KEY_ACCESSED_BY_AGENT=NO
OWNER_PUBLIC_KEY_ENROLLED=YES
OWNER_PUBLIC_KEY_ENROLLMENT_COMMIT=3214251452e85549dedb0e97b0aeddc3df251e95
OWNER_FINGERPRINT_APPROVED=YES
OWNER_FINGERPRINT=SHA256:LQBNgC3HqdwfSWZr/7mvLlSUBwhodPOM0tFDdKZpIs4
OWNER_DIGEST_RECEIVED=NO
OWNER_DIGEST_STATEMENT_SIGNED=NO
OWNER_DIGEST_STATEMENT_VALIDATED=NO
GATE_A_APPROVED=YES
GATE_B_APPROVED=NO
ARTIFACT_ACQUIRED=NO
SIGSTORE_EVIDENCE_ACQUIRED=NO
VERIFIER_ACQUIRED_OR_EXECUTED=NO
ARTIFACT_INSTALLED_OR_EXECUTED=NO
REAL_AUTHENTICATION_OR_PROVIDER_ACCESS=NO
ARTIFACT_ACQUIRED_OR_EXECUTED=NO
CODEX_OR_SIGSTORE_ACQUIRED_OR_EXECUTED=NO
```

This addendum closes the verifier/trust-policy research blocker in
[the artifact-authorization packet](m6-slice-2c2-native-codex-artifact-authorization.md).
Except for the later Gate A selection and owner-digest policy approval recorded
below, it does not authorize acquisition, installation, execution,
authentication, provider access, production integration, self-hosting, or any
artifact, version, target, host, verifier, or trust-policy widening.

Owner decision received 2026-08-12: Gate A and this addendum's independent-
owner-digest branch are approved for only the exact artifact in §1. The owner
did not supply the digest or select its authenticated delivery mode and did not
authorize Gate B or any acquisition, installation, execution, authentication,
provider access, production integration, self-hosting, artifact, or version
widening. Those boundaries remain blocked.

Documentation-only reconciliation approved on 2026-08-14 records completed
owner-only key generation and generation-1 public enrollment at commit
`3214251452e85549dedb0e97b0aeddc3df251e95`, with separately approved
fingerprint `SHA256:LQBNgC3HqdwfSWZr/7mvLlSUBwhodPOM0tFDdKZpIs4`. No agent, model, or
controller accessed private-key material. No owner digest exists. Branch O
remains selected but blocked because no approved pre-existing independent
OpenAI raw-member digest authority exists. The proposed Branch S switch was
reviewed and rejected/blocked because the existing raw-byte signature does not
cryptographically bind the exact target, archive, and member identity. Gate B
remains unapproved.

## 1. Scope and hard prohibitions

The only selected candidate remains:

| Field | Exact value |
|---|---|
| Project | OpenAI Codex CLI |
| Repository | `openai/codex` |
| Version and tag | `0.120.0`; `rust-v0.120.0` |
| Tagged source commit | `65319eb1400cbd2890c43d572263dabd25f18ba9` |
| Target | `x86_64-unknown-linux-musl` |
| Archive | `codex-x86_64-unknown-linux-musl.tar.gz` |
| Archive asset | release `307789275`; asset `393784170` |
| Archive consistency values | 65,976,072 bytes; SHA-256 `21b08cca7784be53d33c6f46cf897cd2b440cda58dc7912563dbc676b4d17017` |
| Sidecar | `codex-x86_64-unknown-linux-musl.sigstore`; asset `393784168` |
| Sidecar consistency values | 8,305 bytes; SHA-256 `1edd5da34ce243862108bb9014b988fb9eb9bad279b28e99cf0d5b2ca47d27cb` |
| Expected archive member | one regular file, `codex-x86_64-unknown-linux-musl` |

This research did not fetch the archive, sidecar bytes, signatures, verifier
binaries, or trust-root payloads. It did not install or run Cosign or Codex,
read credentials, authenticate, or contact a provider. GitHub JSON metadata,
tag-pinned source, workflow/run metadata, and official Sigstore/GitHub
documentation were inspected only as primary-source research.

## 2. Evidence taxonomy

The terms below are normative throughout this addendum.

- **Authoritative-source fact**: observed in OpenAI's tag-pinned repository,
  GitHub's official API/documentation, or Sigstore's official source,
  specification, release, advisory, or documentation.
- **Repository record**: a prior AgenticOS observation or earned claim. It is
  not silently upgraded to an upstream or cryptographic fact.
- **Proposed policy**: a fail-closed requirement for a later separately
  authorized acquisition.
- **Acquisition-time unknown**: a value that cannot be established without
  acquiring prohibited bytes or executing a separately qualified verifier.
  An unknown never becomes an allow value; it blocks.

GitHub's asset digest and size are consistency values delivered by the same
release system as the asset. They do **not** independently authenticate bytes
downloaded from that system and are not a trust root.

## 3. Authoritative evidence inventory

### 3.1 Release objects

GitHub's official API reported on 2026-08-12:

| Object | ID | Media type | Size | GitHub-recorded SHA-256 | Immutable metadata URL |
|---|---:|---|---:|---|---|
| selected archive | `393784170` | `application/gzip` | 65,976,072 | `21b08cca7784be53d33c6f46cf897cd2b440cda58dc7912563dbc676b4d17017` | `https://api.github.com/repos/openai/codex/releases/assets/393784170` |
| selected sidecar | `393784168` | `application/octet-stream` | 8,305 | `1edd5da34ce243862108bb9014b988fb9eb9bad279b28e99cf0d5b2ca47d27cb` | `https://api.github.com/repos/openai/codex/releases/assets/393784168` |
| alternate `.zst` packaging for the same target (not selected) | `393784173` | `application/octet-stream` | 47,988,547 | `068799e3bab9bedc5c79a145ff1998c258fac52d4f458a912c371e6b1cf44097` | `https://api.github.com/repos/openai/codex/releases/assets/393784173` |

All three objects were created at `2026-04-11T02:53:31Z`; the archive metadata was
updated at `02:53:44Z`, and the release was published at `02:53:49Z`. The
release is neither draft nor prerelease.

The release inventory contains a per-Linux-target `.sigstore` sidecar beside
each `codex-<target>.tar.gz` and `.zst`. No separately named checksum manifest,
SBOM, DSSE/in-toto provenance, SLSA attestation, or GitHub artifact-attestation
asset was present. Asset adjacency and matching names are release metadata,
not signed filename-to-byte bindings.

The annotated tag object
`84b1753e16766434a86ec29ab7a23984fd0f61fe` resolves to commit
`65319eb1400cbd2890c43d572263dabd25f18ba9`; GitHub reports both tag and commit
as unsigned.

Primary sources:

- `https://github.com/openai/codex/releases/tag/rust-v0.120.0`
- `https://api.github.com/repos/openai/codex/releases/tags/rust-v0.120.0`
- `https://api.github.com/repos/openai/codex/git/ref/tags/rust-v0.120.0`
- `https://api.github.com/repos/openai/codex/git/tags/84b1753e16766434a86ec29ab7a23984fd0f61fe`
- `https://api.github.com/repos/openai/codex/commits/65319eb1400cbd2890c43d572263dabd25f18ba9`

### 3.2 Build and signing path

The tag-pinned workflow
`.github/workflows/rust-release.yml` is named `rust-release` and triggers only
on pushes of `rust-v*.*.*` tags. Its build job has `contents: read` and
`id-token: write`; the `x86_64-unknown-linux-musl` matrix entry uses the
`ubuntu-24.04` GitHub-hosted label. Checkout and several build actions are
commit-pinned, but the runner label, APT repositories, build inputs, and every
transitive build input are not thereby reproducible or independently
authenticated by the sidecar.

Run `24272061399` completed successfully for event `push`, repository and head
repository `openai/codex`, ref/tag `rust-v0.120.0`, head SHA
`65319eb1400cbd2890c43d572263dabd25f18ba9`, attempt 1. Job `70878898104`,
`Build - ubuntu-24.04 - x86_64-unknown-linux-musl`, completed successfully on
the GitHub Actions runner group with label `ubuntu-24.04`.

The tag-pinned composite signing action:

1. invokes `sigstore/cosign-installer@v3.7.0` without a version override;
2. that action's tag-pinned default and bootstrap are Cosign `v2.4.1`;
3. runs `cosign sign-blob --yes --bundle "${artifact}.sigstore" "$artifact"`
   separately for `codex` and `codex-responses-api-proxy`;
4. copies `release/codex.sigstore` to
   `dist/<target>/codex-<target>.sigstore`;
5. copies the uncompressed `release/codex` to
   `dist/<target>/codex-<target>`; and only afterward
6. creates `codex-<target>.tar.gz` and `.zst` from that renamed binary.

Primary sources:

- `https://github.com/openai/codex/blob/rust-v0.120.0/.github/workflows/rust-release.yml`
- `https://github.com/openai/codex/blob/rust-v0.120.0/.github/actions/linux-code-sign/action.yml`
- `https://github.com/sigstore/cosign-installer/blob/v3.7.0/action.yml`
- `https://github.com/openai/codex/actions/runs/24272061399`
- `https://github.com/openai/codex/actions/runs/24272061399/job/70878898104`

### 3.3 Actual evidence shape established without sidecar bytes

Cosign 2.4.1's `--new-bundle-format` flag defaults false, and OpenAI did not
pass it. The sidecar is therefore expected to be the **legacy Cosign JSON blob
bundle**, not the standardized Sigstore protobuf bundle and not an
attestation. Its signed object is the raw uncompressed `codex` file.

The tag-pinned legacy `RekorBundle` type contains a signed entry timestamp and
a payload with `body`, `integratedTime`, `logIndex`, and `logID`. It contains no
Merkle inclusion proof, signed checkpoint, witness signature, or consistency
proof. Cosign 2.4.1 defaults `--tlog-upload=true`, but the actual entry and
certificate remain acquisition-time facts.

| Question | Established answer |
|---|---|
| Evidence granularity | one sidecar produced for one uncompressed binary in each Linux matrix job |
| Signing mechanism | keyless `cosign sign-blob`; a Fulcio-issued short-lived X.509 leaf is expected from that mechanism, but the actual leaf, chain, issuer, and claims are unknown |
| Signed subject | raw bytes of `target/<triple>/release/codex` |
| Archive covered | no; `.tar.gz` is made after signing |
| Filename covered | no signed filename claim established |
| Target triple covered | no; the raw blob payload and GitHub OIDC identity do not contain the matrix target |
| Manifest/archive set covered | no |
| Attestation/predicate | none; this is `sign-blob`, not DSSE/in-toto/SLSA attestation |
| Expected Rekor kind | legacy `hashedrekord`; exact kind/version/body must be checked later and any other type rejected |
| Digest algorithm | Cosign 2.4.1's blob/keyless default is SHA-256; the actual hashedrekord subject must be checked later |
| Ephemeral signing algorithm | Cosign's default is ECDSA P-256 with SHA-256; actual leaf and signature algorithms must be checked later |
| Transparency material in legacy shape | signed-entry promise, body, integrated time, log index, log ID |
| Embedded inclusion proof/checkpoint | absent from the tag-pinned legacy type |
| Complete offline proof under this policy | no; the policy requires inclusion/checkpoint/consistency evidence the legacy sidecar cannot retain by itself |

Official Sigstore sources:

- `https://github.com/sigstore/cosign/blob/v2.4.1/doc/cosign_sign-blob.md`
- `https://github.com/sigstore/cosign/blob/v2.4.1/pkg/cosign/bundle/rekor.go`
- `https://github.com/sigstore/architecture-docs/blob/main/client-spec.md`
- `https://docs.sigstore.dev/cosign/verifying/verify/`

### 3.4 Claims that remain unknown

Because the sidecar bytes were prohibited, none of these are asserted as
facts: internal JSON field inventory, duplicate-key posture, leaf certificate,
chain, exact SAN/subject, Fulcio issuer extension, repository/workflow/ref/SHA/
event extensions, runner-environment extension, validity interval, SCT, raw
artifact digest, signature bytes/algorithm, Rekor kind/version/body, entry UUID,
log ID/index, integrated time, or signed entry timestamp.

GitHub Actions OIDC can supply `repository`, `workflow`, `workflow_ref`,
`workflow_sha`, `ref`, `sha`, `event_name`, `runner_environment`, run IDs, and
related claims. Availability in an OIDC token does not prove presence in this
certificate. A future policy may require an extension only after authoritative
Fulcio mapping and the acquired certificate establish that it is
cryptographically present.

Official GitHub OIDC documentation describes the token claim vocabulary, but
neither an issuer value nor a workflow-SAN value is adopted as an authorization
pin here: the certificate bytes were not inspected, and the signing action also
sets interactive OIDC environment defaults. An acquired bundle must not choose
its own accepted identity.

Primary source:

- `https://docs.github.com/en/actions/reference/security/oidc`

## 4. Repository-derived facts and constraints

- The Windows `codex-cli 0.120.0` custom-provider proof establishes only a
  compatibility hypothesis; it does not qualify Linux bytes.
- M6 Slice 2C.1 earned Level A auth-domain isolation on the recorded Linux
  host. This addendum does not alter it.
- M4B-3 Connected Build distinguishes transport authenticity from artifact
  identity and requires an explicit out-of-band SHA-256 for generic fetches.
- The qualified generic fetch covers one exact host and digest-gated content,
  but GitHub release-asset CDN redirect chains are explicitly not an earned
  M4B-3 claim. A later acquisition therefore needs an already-authorized exact
  release-asset path or a separately reviewed extension; this addendum does
  not widen Connected Build.
- The recorded host has no qualified Cosign binary, Sigstore library, native
  Linux Codex installation, or pinned Sigstore trust-root snapshot.
- Existing dependency gates use exact versions, hashes, offline wheelhouses,
  bounded runtime closures, and host requalification. A verifier must meet at
  least the same discipline.

## 5. Trust and threat model

The policy must resist:

- release-asset substitution, mutable metadata, redirect manipulation, replay,
  and same-origin circular trust;
- a correct signature from the wrong repository, fork, owner, tag, commit,
  workflow, event, job class, artifact, target, or time;
- broad or ambiguous identities, regex identities, multiple acceptable
  issuers, and valid signatures from an unexpected identity;
- tag movement, workflow modification, older valid releases, and mixing an
  archive with another valid sidecar or another matrix target's signed binary;
- verifier compromise, dependency/toolchain substitution, vulnerable legacy
  parsing, mutable trust roots, and silent trust-root rotation;
- Rekor split views, stale checkpoints, absent inclusion/consistency proofs,
  and treating a signed-entry promise as witnessed consistency;
- OIDC, Fulcio, Rekor, CT-log, GitHub Actions, signing-action, or build-runner
  compromise;
- malformed/oversized/duplicate JSON, duplicate subjects or identities,
  parser differentials, unknown security-relevant fields, and fail-open CLI
  exit/output handling;
- a signature that binds exact bytes but not the selected filename, archive,
  target triple, or release mapping; and
- gzip/tar bombs, concatenated streams, traversal, links, devices, sparse/PAX
  ambiguity, duplicate names, unsafe permissions, and extraction races after
  successful byte authentication.

Sigstore narrows a compromise from arbitrary unsigned substitution to a
signature issued to an accepted identity and logged under accepted trust
material. It does not prove source correctness, reproducibility, benign build
inputs, runner integrity, target identity absent from the signed statement, or
safe archive extraction.

## 6. Fail-closed trust policy

### 6.1 Global rules

1. Policy values are fixed before network acquisition. No downloaded object,
   redirect, certificate, bundle, metadata response, or verifier output may
   add or relax an allow value.
2. Every schema is exact, versioned, UTF-8, duplicate-key rejecting,
   depth/count/size bounded, and rejects unknown, missing, duplicated,
   conflicting, stale, or extra security-relevant claims.
3. There is exactly one selected archive, one expected member, one selected
   target, one authority branch, and one terminal decision. No fallback from
   Sigstore to owner digest or vice versa occurs in one acquisition.
4. Filename and exact bytes must both be bound by the selected authority.
   A raw-byte signature without a target/filename binding is insufficient for
   this multi-target release.
5. GitHub metadata values in §1 remain mandatory consistency checks but never
   satisfy the independent-authentication rule.

### 6.2 Selected authority branch: owner digest

The owner-digest branch is approved, but no approved pre-existing independent
OpenAI raw-member digest authority, owner digest, or authenticated delivery
mode exists, so this policy is incomplete and gate B remains blocked. Before B
can be reviewed, the owner must deliver one canonical
`AOSCODEXOWNERDIGEST/1` statement through an authenticated authority
independent of GitHub release hosting and the OpenAI sidecar:

```json
{
  "schema": "AOSCODEXOWNERDIGEST/1",
  "publisher": "OpenAI",
  "repository": "openai/codex",
  "version": "0.120.0",
  "tag": "rust-v0.120.0",
  "source_commit": "65319eb1400cbd2890c43d572263dabd25f18ba9",
  "target": "x86_64-unknown-linux-musl",
  "archive_asset_id": 393784170,
  "archive_name": "codex-x86_64-unknown-linux-musl.tar.gz",
  "member_name": "codex-x86_64-unknown-linux-musl",
  "uncompressed_sha256": "<64 lowercase hex characters>",
  "owner_decision_id": "<bounded non-secret identifier>"
}
```

The statement is ASCII canonical JSON, at most 4,096 bytes, one line, exact
keys/types, no extensions, no control characters, and one SHA-256 value. It
must be signed by a pre-recorded owner key or delivered in an already-approved
authenticated owner channel whose identity and transcript digest are recorded.
The owner decision approving this branch must select exactly one of those two
delivery modes and name its pre-existing key or channel identity; there is no
fallback between them. The angle-bracketed values above are blocking inputs,
not values that the release system or later acquisition may fill.
The authority must not derive from the release page, release API digest,
sidecar, Rekor query, verifier output, or bytes acquired in the same operation.
If no independent owner authority is available, acquisition remains blocked.

After safe extraction, SHA-256 over the exact uncompressed member must equal
`uncompressed_sha256`. This statement binds the target, archive/member names,
and exact binary bytes. A mismatch is terminal; the sidecar is not acquired or
used in this branch.

### 6.3 Sigstore branch requirements and blocker

The Sigstore branch is **not selected**. The 2026-08-14 reconsideration was
rejected and remains blocked: it cannot be made authoritative by merely
filling values from the acquired sidecar, and verifier qualification cannot
create the missing target/archive/member assertion. Any future reconsideration
would require new evidence and a new pre-acquisition owner review and must, at
minimum, pin and enforce:

| Constraint | Required policy | Current state |
|---|---|---|
| bundle object | asset `393784168`, exact name/size/GitHub digest as consistency only | metadata known; bytes unknown |
| bundle syntax | one legacy Cosign blob bundle; no DSSE, in-toto statement, SLSA predicate, detached alternate, or multiple bundle | expected from tag-pinned command; bytes unknown |
| artifact payload | raw uncompressed binary; SHA-256 subject equals independently computed extracted bytes | enforceable later |
| filename/archive/target | exact archive, member name, and `x86_64-unknown-linux-musl` must be cryptographically asserted | **not asserted by available evidence; blocking** |
| repository | exact `openai/codex` extension | expected but unobserved |
| tag/ref | exact `refs/tags/rust-v0.120.0` | expected but unobserved |
| source commit | exact `65319eb1400cbd2890c43d572263dabd25f18ba9` if certificate extension exists | expected but unobserved |
| workflow | exact `.github/workflows/rust-release.yml`; name `rust-release` only if separately present | expected but unobserved |
| trigger | exact `push` | expected but unobserved |
| identity/SAN | one exact URI SAN; no regex, wildcard, alternate SAN, or second identity | exact value unobserved |
| OIDC issuer | one exact issuer; no issuer regex or fallback | exact value unobserved |
| runner | require `github-hosted` if signed; exact `ubuntu-24.04` is API/job metadata only | target/OS not signed |
| Rekor body | exactly one supported legacy `hashedrekord`; body signature/key/artifact digest must equal bundle/leaf/artifact | bytes unknown |
| transparency | valid SET, exact pinned Rekor log ID/key, online inclusion proof against a signed checkpoint, checkpoint witness/gossip or independently retained checkpoint, and consistency from the retained prior checkpoint | legacy bundle alone lacks proof/checkpoint |
| certificate time | verify chain and SCT; integrated time must fall within leaf/chain and trust-material validity; never use current time as a substitute for a verified signing time | trust snapshot and bytes absent |
| trusted roots | pre-acquired TUF initial root with pinned digest/version/threshold; expiry/rollback/freeze checks; pinned `trusted_root.json` target digest and exact Fulcio intermediate/root, CT-log and Rekor keys plus validity ranges | absent |
| algorithms | explicit allowlist fixed from reviewed trust material; candidate artifact digest SHA-256 and ECDSA P-256/SHA-256; reject SHA-1, unknown algorithms, implicit downgrade, and algorithms absent from the policy | full trust-material algorithms absent |

The target/filename gap is structural: every Linux matrix job signs a raw file
named `codex` under the same repository/workflow/ref/commit/event identity.
Neither the raw blob signature nor GitHub Actions certificate identity includes
the matrix target. A valid binary and sidecar from another Linux target could
therefore satisfy the same signer policy if release mapping were substituted.
GitHub's same-origin asset metadata cannot close that gap. This alone prevents
a ready Sigstore-policy outcome.

## 7. Verifier-bootstrap comparison

### 7.1 Pinned official Cosign binary

Reviewed patched candidate: official Cosign `v3.1.3`, Linux amd64 asset ID
`503286005`, 141,178,250 bytes, GitHub-recorded SHA-256
`4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71`.
Its sibling bundle is asset `503286953`, 6,406 bytes, GitHub-recorded SHA-256
`e16547fbee348eb23bd7e5a4d542b540395faea2e7bb1d18da01bbc3cc74d57d`.

This candidate is the minimum patched v3 release for the August 2026 high-
severity legacy-bundle identity-bypass advisory `GHSA-fx35-mq7g-6g98`, which
affects Cosign through `v3.1.2`; the corresponding patched v2 floor is `v2.6.5`.
The previously recorded `v3.0.6` candidate is affected and is disqualified.
Earlier advisory `GHSA-whqx-f9j3-ch6m` separately requires at least 2.6.2 or
3.0.4 for Rekor-entry association. Version 3.1.3 includes Sigstore/Cosign's
large compiled feature and dependency closure and must be
invoked with explicit legacy-bundle, offline/online, identity, issuer, workflow
claim, Fulcio/CT/Rekor trust-material, and output bounds. Its legacy blob path
does not accept `--trusted-root`, which is reserved for the standardized-bundle
path, so an exact separately qualified legacy trust-material procedure would
be required. It must not auto-update TUF,
select ambient roots, consult ambient network, or accept insecure-ignore flags.
It is a single-executable distribution candidate, but its exact ELF linkage and
host-runtime closure are acquisition-time unknowns. This policy's stronger
transparency requirements would also require a controlled online Rekor/
checkpoint path because the legacy sidecar contains no inclusion proof or
checkpoint. Every version or trust-root rotation would require a new pin,
advisory review, host qualification, and owner decision.

Bootstrap remains circular: the binary, its GitHub digest, checksum manifest,
and its Sigstore bundle are hosted by the same GitHub release system, and no
independent verifier digest or qualified preinstallation exists. Its own
sidecar cannot bootstrap itself. Host qualification, exact executable/dependency
identity, parser adversarial tests, retained invocation/output, and controlled
trust-root acquisition would all be required.

The August 2026 advisory demonstrates that a legacy bundle containing an
attacker-controlled raw public key could bypass X.509 chain, identity, and OIDC
issuer enforcement and even overwrite an explicitly supplied verification key.
Therefore `Verified OK` is never sufficient, legacy `cert` must parse as
exactly one Fulcio X.509 certificate, and every bare-key, key-overwrite, and
identity-bypass negative case must fail. Updating the verifier does not repair
the structural target/archive/member gap, so Branch S remains rejected.

Primary sources:

- `https://api.github.com/repos/sigstore/cosign/releases/tags/v3.1.3`
- `https://api.github.com/repos/sigstore/cosign/releases/assets/503286005`
- `https://api.github.com/repos/sigstore/cosign/releases/assets/503286953`
- `https://github.com/sigstore/cosign/security/advisories/GHSA-fx35-mq7g-6g98`
- `https://github.com/sigstore/cosign/security/advisories/GHSA-whqx-f9j3-ch6m`

### 7.2 Vendored or source-built verifier/library

No source-built verifier is approved. A candidate based on Cosign source
`v3.1.3` would require an independently pinned Go toolchain and the exact
module graph in its `go.mod` and `go.sum`. A genuinely minimal verifier would
still need X.509/Fulcio/SCT validation, legacy Cosign
bundle parsing, RFC 8785 SET verification, hashedrekord parsing and equality
checks, Rekor inclusion/checkpoint/consistency validation, TUF rollback/freeze
protection, GitHub certificate-extension policy, and strict JSON/bounds.

This path replaces one unqualified executable with a Go compiler/toolchain,
vendored module closure, build flags, source archives, generated protobufs, and
custom policy/parser code. Each source and toolchain object needs an independent
digest, license/advisory review, reproducible or double-build evidence, and
host qualification. The broad Cosign module graph is materially larger than
the selected Codex trust problem; a hand-minimized implementation has a smaller
runtime but a higher parser/cryptography correctness burden. It does not solve
the missing target binding.

No Cosign `v3.1.3` source tag, toolchain, module, or generated-source authority
is independently pinned in AgenticOS, and GitHub-generated source archives
have no independently approved digest here.
Network would be needed to acquire every source/toolchain object and, under the
future transparency policy, controlled Rekor/checkpoint material. Audit evidence
would need every source/module/toolchain digest, build invocation, produced
binary digest, trust snapshot, policy input/output, and host qualification.
Any source, module, toolchain, or trust-root update is a new qualification.

Primary sources:

- `https://github.com/sigstore/cosign/blob/v3.1.3/go.mod`
- `https://github.com/sigstore/cosign/blob/v3.1.3/go.sum`

### 7.3 Independent owner digest

This option uses no Sigstore verifier and adds no new executable dependency.
It requires the exact §6.2 statement delivered through an independent owner
authority and uses the controller's already-qualified SHA-256 facility during
later passive qualification. Network is needed only for the separately
authorized archive acquisition. Audit evidence retains the owner decision
identifier, statement digest, channel class, archive/member identity, and
computed binary digest.

This is the only option whose new bootstrap authority is narrower than the
problem and that binds the otherwise unauthenticated target/filename mapping.
It is selected. The missing owner digest is a deliberate blocking input, not a
placeholder that acquisition may discover.

## 8. Later acquisition-time algorithm — not authorized here

1. Reconcile Windows, WSL, `origin/main`, and GitHub; require SHA equality,
   clean trees, 0/0 divergence, and zero stashes.
2. Revalidate the recorded explicit owner approval for gate A and the owner-
   digest policy; authenticate, validate, and record the complete §6.2
   statement before any network grant. A missing/invalid statement stops.
3. Obtain a separate owner decision B for one exact acquisition. B must name an
   already-authorized exact-host, redirect-controlled, digest-gated mechanism.
   Existing M4B-3 does not by itself authorize GitHub release-asset redirects.
4. Revalidate the controller-owned staging ancestry and create a fresh
   root-owned `0700` same-filesystem staging directory through trusted
   directory FDs. Use no ambient proxy, credential, cookie, `.netrc`, Git/SSH
   credential, user CA, PATH lookup, or environment-derived destination.
5. Acquire release and archive metadata from exact pinned API URLs. Record the
   bounded public response body plus only allowlisted non-secret response
   fields and canonical redirect metadata; never record request headers,
   cookies, authentication material, or unreviewed response headers. Require
   repository, release ID/state/tag, asset ID, name, media type, size, digest,
   timestamps, and browser URL to match.
6. Acquire only archive asset `393784170` through the approved asset-ID API.
   Permit at most one HTTPS/443 redirect to exact host
   `release-assets.githubusercontent.com` as fixed by B; reject
   credentials/userinfo, fragments, queries
   not supplied by the trusted response parser, suffix tricks, downgrade,
   port changes, relative ambiguity, loops, or a second redirect. Never forward
   authorization/cookies across origins.
7. Stream into a new `O_CREAT|O_EXCL|O_NOFOLLOW` mode-`0600` file with exact
   byte/time limits, SHA-256, `fsync`, and parent `fsync`. Require exactly
   65,976,072 bytes and the recorded archive SHA-256 as consistency checks.
   Do not acquire the Sigstore sidecar in the selected owner-digest branch.
8. Inspect without extraction. Require one gzip member, bounded optional
   fields, legal flags, CRC32 and ISIZE, no trailing stream/data, and a maximum
   expanded size of 268,435,456 bytes (ratio below 4.07 for the exact input).
9. Require one normalized POSIX tar member named exactly
   `codex-x86_64-unknown-linux-musl`, type regular file, mode `0755`, and no
   setuid/setgid/sticky bits. Reject absolute/backslash/dot/dot-dot/NUL names,
   PAX/GNU rewrites, sparse data, alternate streams, symlink, hardlink,
   directory, FIFO, socket, device, duplicate raw or normalized name,
   overlapping extents, size disagreement, extra entry, and trailing archive.
10. Extract by streaming the one member to a controller-chosen fixed filename
    through the staging directory FD with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode
    `0500`, byte/count/decompression bounds, `fsync`, and no path reuse. Never
    invoke archive content, `ldd`, a loader, installer, or shell script.
11. Compute the extracted binary SHA-256 and require exact equality with the
    independently authenticated owner value. A mismatch is terminal and has no
    Sigstore fallback. Record size, owner/group, mode, device/inode, mount and
    filesystem identities, xattrs, capabilities, setuid/setgid, timestamps,
    ELF class/machine/program/dynamic headers, interpreter, `DT_NEEDED`, build
    ID, notes, and executable-stack state using non-executing parsers.
12. Perform only Gate 1A passive qualification from the authorization packet.
    Dynamic or unresolved dependencies, wrong architecture, malformed ELF,
    unexpected privilege metadata, or policy mismatch blocks.
13. Stop before installation. Gate C requires a separate owner decision after
    passive qualification. Gate D and all authentication/provider access remain
    blocked.
14. On success or known failure, close all FDs/network grants and remove only
    identity-recorded known staging files after the retention decision. On
    unknown/mismatched content or identity, quarantine and report; never use a
    recursive unresolved delete. Record residue and cleanup results.

In the selected owner-digest branch, authenticity cannot complete until step
11 because the independently authenticated subject is the uncompressed member.
Steps 7–10 therefore treat both archive and member as hostile, keep them in
non-public staging, use non-executing bounded parsers, and grant no installation
or execution authority. This ordering is not a claim that the archive digest
authenticated the archive.

## 9. Failure matrix

| Condition | Decision | Retention/next action |
|---|---|---|
| owner statement missing, unauthenticated, noncanonical, wrong context, or GitHub-derived | fail before network | retain content-free decision evidence |
| A or B absent | fail before network | no acquisition |
| repository/release/tag/asset metadata drift | fail | retain bounded metadata response/digest |
| redirect outside exact policy, second redirect, downgrade, userinfo, or secret-forward risk | fail | retain sanitized redirect structure |
| archive size/hash mismatch | fail | quarantine exact partial/staged identity per B |
| sidecar present or fetched in owner-digest branch | fail policy audit | do not parse or use it |
| gzip/tar malformed, duplicate, oversized, linked, special, traversal, permission, or ratio violation | fail before extraction/publication | quarantine exact staged identity |
| extracted digest differs from owner value | fail; no Sigstore fallback | retain digests and decision reason |
| ELF target/dependency/privilege/format mismatch | fail passive qualification | no installation |
| unknown file, FD, process, unit, network grant, or cleanup identity | fail and preserve | report for owner review |
| any parser/verifier crash, timeout, truncation, ambiguous output, unknown claim, or duplicate field | fail | never infer success from partial output |
| future Sigstore identity/issuer/workflow/ref/SHA/event mismatch | fail | no alternative identity |
| future Rekor SET/body/key/digest/signature mismatch or missing proof/checkpoint/consistency | fail | no offline downgrade |
| future trust-root expiry/rollback/freeze/rotation mismatch | fail | separate trust-policy review required |
| correct Sigstore signature but no target/filename cryptographic binding | fail | independent owner digest still required |

## 10. Canonical audit record

The later controller emits one ASCII canonical JSON record, schema
`AOSCODEXACQ/1`, at most 65,536 bytes. It uses fixed keys, sorted compact
serialization, duplicate-key rejection, integers for byte counts, lowercase
hex digests, RFC 3339 UTC plus monotonic durations, and bounded arrays. It
contains:

- repository, release/tag/commit, asset/member/target, policy and owner-decision
  identities;
- for every authorized acquired object: exact initial URL, at most one
  sanitized redirect hop, final host/scheme/port/path class, status, media
  type, declared/observed size, SHA-256, start/end timestamps, and outcome;
- owner statement SHA-256, authenticated channel class, signer/key or session
  identity, and validation result, but no secret/authenticator;
- verifier identity/invocation/trust-root identities only if a future policy
  separately authorizes Sigstore; never raw unbounded stdout/stderr;
- certificate, SCT, Rekor SET/log/index/time/proof/checkpoint/consistency and
  evaluated-claim results only if actually verified;
- archive member count, names as bounded escaped UTF-8, types, sizes, modes,
  gzip/tar checks, expanded bytes and ratio;
- extracted SHA-256/size, filesystem and ELF/dependency identities, passive
  qualification decision, and explicit stable success/failure code;
- retained, deleted, and quarantined object identities plus FD/process/unit/
  network/filesystem residue results; and
- host qualification digest, boot/session/task identifiers in bounded
  domain-separated form.

Limits: at most 8 acquired-object records, 1 redirect per object, 4 trust-root
objects, 8 certificate-chain objects, 4 transparency entries, 32 evaluated
claims, 16 archive entries even though policy accepts only 1, and 64 cleanup
objects. Each string is at most 1,024 bytes; URLs 2,048; failure detail 512;
no arbitrary response body, exception text, terminal escape, CR/LF-bearing
field, credential header, cookie, bearer, query secret, environment value,
file content, or verifier diagnostic is retained. Attacker-controlled strings
are JSON-escaped, length-bounded, single-line, and paired with a digest where
needed. Truncation is an explicit failure, never a passing record.

## 11. Remaining risks and non-claims

- No selected bytes, sidecar claims, binary digest, archive layout, ELF facts,
  or runtime behavior were verified.
- The legacy sidecar may authenticate an OpenAI workflow-signed uncompressed
  blob after a complete qualified verification, but it cannot by itself bind
  that blob to this release filename, archive, or target matrix entry.
- A valid owner digest authenticates identity chosen by the owner, not source
  reproducibility, build-runner integrity, source correctness, absence of
  malicious code, SBOM completeness, or safe runtime behavior.
- Fulcio/OIDC or signing-workflow compromise can issue a policy-shaped valid
  signature; Rekor/CT compromise or split view affects transparency evidence;
  TUF root compromise affects verifier trust. Owner digest independence is the
  selected compensating authority for exact bytes, not a claim those systems
  are uncompromised.
- No verifier or trust-root snapshot is approved. Cosign `v3.1.3` is only the
  reviewed patched comparison candidate; it has not been acquired, executed,
  bootstrapped, or qualified.
- Existing Connected Build does not automatically authorize the release CDN
  redirect. Gate B must close that host/protocol qualification separately.
- Successful acquisition and passive qualification would not authorize
  installation, execution, login, credential access, live provider access,
  production integration, self-hosting, other artifacts/targets/versions, or
  any new runtime security property.

## 12. Adversarial review record

A fresh documentation-only adversarial review was performed against the
requirements in this addendum and the authorization packet. It reviewed
circular trust, claim overreach, identity-policy ambiguity, verifier compromise,
mutable trust material, transparency verification, byte-to-identity binding,
archive/evidence mix-and-match, extraction, fail-open paths, and audit evidence.

Findings and resolutions:

| Severity | Finding | Resolution |
|---|---|---|
| Important | The first draft named the unselected ready-outcome token while explaining the blocker, making the “exactly one outcome” requirement ambiguous. | Removed that token; only the selected outcome is named. |
| Important | The first draft omitted the alternate `.zst` object from the exact same-target release inventory. | Added its immutable asset ID, media type, size, digest, and metadata URL, explicitly marked unselected. |
| Important | “CDN host class” could permit unintended host widening. | Replaced it with exact `release-assets.githubusercontent.com`, consistent with the authorization packet. |
| Important | “Raw response” language could be read to retain secret-bearing headers. | Limited retention to the bounded public body and allowlisted non-secret response fields; explicitly excluded request/auth/cookie/unreviewed headers. |
| Important | Owner-digest verification occurs after bounded extraction, unlike signature verification over an already available raw subject. | Made the ordering and hostile-staging controls explicit; no archive authenticity or execution authority is inferred before the extracted digest matches. |
| Minor | Verifier comparison lacked adjacent official release/source URLs. | Added immutable API asset URLs, advisory, `go.mod`, and `sigstore-go` source references. |

After those resolutions, the review found zero unresolved Critical and zero
unresolved Important findings. Any attempt to populate the unknown certificate,
bundle, Rekor, or trust-root values would require prohibited byte acquisition;
the policy therefore keeps that branch blocked instead of inventing pins.

A second fresh documentation-only adversarial review was performed on
2026-08-14 against the exact state-reconciliation diff. It found and resolved:

| Severity | Finding | Resolution |
|---|---|---|
| Critical | The available raw-byte signature authenticates bytes under a shared Linux workflow identity but does not cryptographically bind the selected target, archive, or member. | Rejected and blocked the proposed Branch S switch; Branch O remains the sole selected branch. |
| Critical | The prior Cosign `v3.0.6` candidate is affected by the August 2026 legacy-bundle identity-bypass advisory. | Disqualified `v3.0.6`; recorded unapproved `v3.1.3` as the minimum patched v3 comparison candidate and retained all bootstrap/qualification blockers. |
| Important | `OWNER_PRIVATE_KEY_ACCESSED=NO` could falsely imply that the owner never handled the generated key. | Replaced it with explicit owner-only offline-ceremony handling and `OWNER_PRIVATE_KEY_ACCESSED_BY_AGENT=NO`; prose also excludes model and controller access. |
| Important | Gate 2-4 and public-enrollment state text remained stale after publication. | Recorded completed owner-only generation, generation-1 enrollment commit and fingerprint approval while preserving every digest, signing, validation, acquisition, execution, authentication, and Gate B denial. |

After those resolutions, the second review found zero unresolved Critical and
zero unresolved Important findings. No finding was waived or converted into
authority.

## 13. Decision and exact next owner action

```text
INDEPENDENT_OWNER_DIGEST_REQUIRED
```

The available Sigstore evidence shape and verifier bootstrap are insufficient
to authenticate the selected target mapping under a precise pre-acquisition
fail-closed policy. Gate A and the §6.2 owner-digest authority branch were
approved on 2026-08-12, but Branch O remains blocked because no approved
pre-existing independent OpenAI raw-member digest authority currently exists.
No `AOSCODEXOWNERDIGEST/1` statement may be created or signed unless such an
authority first exists and the owner separately approves the exact Gate 5
procedure and delivery identity in a new decision.

Gate B remains unapproved after that input and requires a later separate owner
decision authorizing the exact GitHub/CDN acquisition path.

Do not approve a Sigstore verifier, gate B, installation, or execution on the
basis of this addendum.
