# M6 Slice 2C.2 — Native Codex Artifact Owner Authorization Packet

Status: documentation-only owner decision packet, prepared 2026-08-12.

```text
M6_SLICE2C2_DESIGN_STATUS=IMPLEMENTATION_READY
NATIVE_CLIENT_QUALIFICATION=BLOCKED_OWNER_AUTHORIZATION
M6_SLICE2C1_STATUS=EARNED_LEVEL_A
ARTIFACT_ACQUIRED=NO
ARTIFACT_INSTALLED=NO
ARTIFACT_EXECUTED=NO
REAL_AUTHENTICATION_USED=NO
LIVE_PROVIDER_ACCESS_USED=NO
ACQUISITION_RECOMMENDATION=BLOCKED_VERIFIER_TRUST_POLICY
```

This packet requests narrowly separated owner permissions for one exact
official native Linux artifact. It does not itself authorize or perform
acquisition, installation, execution, authentication, provider access,
production integration, or version widening.

## 1. Exact requested artifact

| Field | Exact value |
|---|---|
| Project | OpenAI Codex, official repository `openai/codex` |
| Publisher | OpenAI |
| Version | Codex CLI `0.120.0` |
| Release | `0.120.0`, tag `rust-v0.120.0` |
| Release date | `2026-04-11T02:53:49Z` |
| Tag object | `84b1753e16766434a86ec29ab7a23984fd0f61fe` (annotated, unsigned) |
| Tagged commit | `65319eb1400cbd2890c43d572263dabd25f18ba9` (unsigned) |
| Target | `x86_64-unknown-linux-musl` |
| Archive | `codex-x86_64-unknown-linux-musl.tar.gz` |
| GitHub release asset ID | `393784170` |
| Archive size | `65,976,072` bytes |
| Expected archive SHA-256 | `21b08cca7784be53d33c6f46cf897cd2b440cda58dc7912563dbc676b4d17017` |
| Expected archive entry | exactly one regular file named `codex-x86_64-unknown-linux-musl` |
| Expected installed name | `codex` |
| License | Apache License 2.0 |
| Signature bundle | `codex-x86_64-unknown-linux-musl.sigstore`, asset ID `393784168`, 8,305 bytes |
| Signature-bundle SHA-256 | `1edd5da34ce243862108bb9014b988fb9eb9bad279b28e99cf0d5b2ca47d27cb` |

Official release URL:

`https://github.com/openai/codex/releases/tag/rust-v0.120.0`

Exact archive URL:

`https://github.com/openai/codex/releases/download/rust-v0.120.0/codex-x86_64-unknown-linux-musl.tar.gz`

Immutable asset-metadata URL and identifier:

`https://api.github.com/repos/openai/codex/releases/assets/393784170`

Exact Sigstore-bundle URL and immutable metadata identifier:

`https://github.com/openai/codex/releases/download/rust-v0.120.0/codex-x86_64-unknown-linux-musl.sigstore`

`https://api.github.com/repos/openai/codex/releases/assets/393784168`

The requested object is the `.tar.gz` archive with the exact asset ID, size,
and SHA-256 above. A same-named replacement, a GNU build, an ARM build, a
`.zst`, an npm package, an installer script, a desktop-managed binary, a newer
version, or a rebuilt binary is a different artifact and is not authorized by
this packet.

## 2. Why this artifact is selected

The previously qualified Windows client is `codex-cli 0.120.0`. Selecting the
same upstream version preserves the strongest available behavioral
compatibility hypothesis for the already-observed custom-provider TOML,
unauthenticated Responses/SSE transport, Gitless execution, JSONL output, and
feature controls. It does not claim Windows and Linux binaries are identical
or that the Linux binary is qualified.

The recorded WSL host is Ubuntu 26.04 on `x86_64`. OpenAI's tagged README names
`codex-x86_64-unknown-linux-musl.tar.gz` as the ordinary x86_64 Linux download,
states that the archive has one target-named entry, and describes the Rust CLI
as a standalone zero-dependency executable. The musl build is therefore the
smallest candidate dependency surface. The same release also contains a GNU
build, but no repository constraint requires it.

The selected target is expected to be statically linked and to require no
user-space shared libraries. That expectation follows from the musl target and
the upstream zero-dependency description; it is not a fact established about
the selected bytes. Passive post-acquisition ELF inspection must prove the
absence of `PT_INTERP` and `DT_NEEDED`. Any dynamic loader or shared-library
dependency blocks qualification until every dependency is separately pinned,
mounted read-only, and reviewed; it does not silently switch the selection to
the GNU build.

Expected platform requirements are Linux on x86_64 plus the kernel interfaces
used by the exact invocation. No glibc ABI is expected. Exact minimum kernel,
CPU-feature, `/proc`, certificate-store, timezone, locale, terminal, and other
runtime requirements remain execution-time qualification facts.

Known process behavior is security-relevant. Prior repository qualification
found that Codex may spawn sandbox/shell helpers such as Bubblewrap and a shell
when command execution is enabled, and the exact tagged source exposes other
spawn surfaces such as notifications. The qualification configuration disables
shell, unified exec, multi-agent, MCP, plugins, hooks, notify, web search, and
other unneeded execution or network features. Internal file read/edit behavior
still occurs in the Codex process. An exact descendant census is mandatory;
any unclassified child or helper fails qualification.

## 3. Provenance and byte-authentication evidence

### Externally verified primary-source facts

| Fact | Primary source |
|---|---|
| OpenAI published stable release `0.120.0` under tag `rust-v0.120.0` on 2026-04-11 | `https://github.com/openai/codex/releases/tag/rust-v0.120.0` and `https://api.github.com/repos/openai/codex/releases/tags/rust-v0.120.0` |
| The annotated tag resolves to commit `65319eb1400cbd2890c43d572263dabd25f18ba9`; neither tag nor commit carries a Git signature | `https://api.github.com/repos/openai/codex/git/ref/tags/rust-v0.120.0`, `https://api.github.com/repos/openai/codex/git/tags/84b1753e16766434a86ec29ab7a23984fd0f61fe`, and `https://github.com/openai/codex/commit/65319eb1400cbd2890c43d572263dabd25f18ba9` |
| Asset ID `393784170` has the exact archive name, size, and GitHub-computed SHA-256 recorded in §1 | `https://api.github.com/repos/openai/codex/releases/assets/393784170` |
| The sibling Sigstore bundle is asset ID `393784168` with the exact size and digest in §1 | `https://api.github.com/repos/openai/codex/releases/assets/393784168` |
| Official workflow run `24272061399` completed successfully for tag commit `65319eb...`; its x86_64 musl build job and Cosign step succeeded | `https://github.com/openai/codex/actions/runs/24272061399` and `https://github.com/openai/codex/actions/runs/24272061399/job/70878898104` |
| The tag-pinned workflow builds `x86_64-unknown-linux-musl`, signs the uncompressed `codex` binary, stages the `.sigstore` bundle, and then creates the tar archive | `https://github.com/openai/codex/blob/rust-v0.120.0/.github/workflows/rust-release.yml` |
| The tag-pinned signing action uses `cosign sign-blob --bundle` | `https://github.com/openai/codex/blob/rust-v0.120.0/.github/actions/linux-code-sign/action.yml` |
| The official README identifies the Linux archive, its single entry, expected rename, standalone distribution, and Apache-2.0 license | `https://github.com/openai/codex/tree/rust-v0.120.0` and `https://raw.githubusercontent.com/openai/codex/rust-v0.120.0/LICENSE` |
| Current official configuration documentation supports a custom provider base URL, `requires_openai_auth`, `supports_websockets`, and `wire_api = "responses"` | `https://learn.chatgpt.com/docs/config-file/config-reference` |

No separately named checksum manifest, SBOM, or provenance manifest was
observed in the release asset inventory fetched on 2026-08-12. GitHub's
release-asset metadata supplies the archive digest. The sibling Sigstore bundle
signs the uncompressed binary, not the `.tar.gz` container.

### Repository-derived facts

- [`docs/phase-zero/m6-codex-adapter-plan.md`](m6-codex-adapter-plan.md),
  especially §§3–5 and 34.3–34.5 as present at baseline `be3dd625...`, records
  the prior Windows `codex-cli 0.120.0` proof. It observed successful local custom
  provider use with `base_url = "http://127.0.0.1:9002/v1"`,
  `wire_api = "responses"`, `requires_openai_auth = false`, and
  `supports_websockets = false`.
- That proof observed Responses/SSE, no client `Authorization`, cookie,
  proxy-authorization, or API-key headers, no `auth.json`, clean JSONL turn
  completion, and Gitless operation with `--skip-git-repo-check`.
- It qualifies only the installed Windows binary's behavior. It is a Linux
  compatibility hypothesis, not Linux evidence.
- [`docs/superpowers/specs/2026-08-12-m6-slice-2c2-synthetic-native-client-provider-integration-design.md`](../superpowers/specs/2026-08-12-m6-slice-2c2-synthetic-native-client-provider-integration-design.md)
  records the native-client blocker and complete qualification boundary.
- [`docs/phase-zero/m6-slice-2c1-auth-domain-closure.md`](m6-slice-2c1-auth-domain-closure.md)
  records the preserved M6 Slice 2C.1 Level A result.
- Both repository clones, both `origin/main` refs, and GitHub `main` were
  verified at `be3dd62510d14ca9f36491066ae5625f038511b6` before this packet;
  both trees were clean and 0/0 divergent with zero stashes.
- The recorded WSL host has no native Linux Codex installation, no WSL
  `~/.codex`, and no `/opt/agenticos/providers/codex`.

### What authenticates the selected bytes

The release page name alone does not authenticate bytes. The fail-closed chain
is:

1. Pin the official repository, release ID `307789275`, asset ID `393784170`,
   tag, filename, exact size, and GitHub-published archive SHA-256 from the
   GitHub API over authenticated TLS.
2. Acquire only that asset and require its bytes to hash to the pinned archive
   SHA-256 before parsing or extraction.
3. Apply exactly one independently authorized binary-byte branch. Branch S
   acquires asset ID `393784168`, requires its pinned size and SHA-256, and uses
   a pre-qualified Sigstore verifier and trusted root to verify the extracted
   binary. Its prior addendum must pin the verifier/dependency digests,
   trusted-root snapshot digest, expected certificate issuer, complete
   certificate identity/SAN, repository, workflow path/ref, and required
   transparency-log identifiers. The acquired bundle may be checked against
   that policy but may not define it. Branch O does not acquire or trust the
   bundle; it requires the extracted binary to match a SHA-256 supplied through
   a separately authenticated owner authority.
4. Record the extracted-binary SHA-256 and selected authority branch. No bundle
   or binary was fetched in this documentation task, so this packet does not
   invent an expected binary digest or signer claim.

The host currently has no established `cosign` executable or Python Sigstore
package, and the exact signer claims have not been independently pinned.
Therefore this packet does **not** recommend or request permission B yet. A
reviewed addendum must select exactly one mutually exclusive binary-byte
authority:

- **Branch S — Sigstore:** pin the complete verifier/trusted-root/signer policy
  above, acquire both asset IDs, and verify the extracted binary against it; or
- **Branch O — owner digest:** receive an independent expected SHA-256 for the
  uncompressed binary through a separately authenticated owner authority,
  acquire only archive asset ID `393784170`, and require the extracted binary
  to match that digest. The release Sigstore bundle remains recorded but is not
  treated as verified evidence in this branch.

GitHub archive-digest equality remains mandatory in both branches. The addendum
may not combine the branches, discover a trust value from acquired bytes, or
fall back from one branch to the other.

## 4. Exact fail-closed acquisition procedure

This procedure is proposed, not executed.

1. Require explicit owner decision A and a later, separately reviewed decision
   B after the §3 verifier/trust-policy blocker is closed. Reconcile both
   repository clones and GitHub first. Require a clean, SHA-identical baseline
   and an empty stash in each clone.
2. Require an already-authorized controller-mediated Connected Build path, or
   a separately reviewed equivalent, with no ambient proxy, credential,
   cookie, `.netrc`, Git credential, SSH, user CA, or PATH authority. Require
   the reviewed addendum to select Branch S or Branch O. For Branch S, absence
   of the exact qualified verifier/trusted root blocks before network access;
   for Branch O, absence of the independently authenticated expected binary
   digest blocks before network access.
3. Begin at existing trusted anchor `/opt`, observed in the host mount namespace
   as numeric UID/GID `0:0`, mode `0755`. Revalidate that identity and record
   device/inode, mount ID, filesystem type/ID, and idmapped-mount state. Through
   trusted directory FDs, create each missing component `agenticos`,
   `providers`, `codex`, and `.staging` one at a time with
   `mkdirat` no-replace semantics; immediately open with
   `O_DIRECTORY|O_NOFOLLOW`, set and verify the exact approved numeric
   ownership `0:0` and mode `0755`, `fsync` the new directory and its parent, and retain the
   trusted child FD for the next step. If a component already exists, require
   the same identity and no group/other write. Reject symlinks, unexpected
   entries, idmapped mounts, or mount crossing outside the approved filesystem.
   Require final version path `/opt/agenticos/providers/codex/0.120.0` to be
   absent. Then create a fresh controller-owned staging directory beneath
   `/opt/agenticos/providers/codex/.staging/` on the same filesystem as the
   final destination. Open it by trusted parent directory FD, require owner
   `root:root`, mode `0700`, no pre-existing entries, no symlink traversal, and
   record device, inode, mount ID, filesystem type, and filesystem ID. Files in
   staging begin mode `0600` with no execute bit.
4. Permit HTTPS on port 443 only to `api.github.com`, `github.com`, and
   `release-assets.githubusercontent.com`. Resolve through the already-qualified
   controller resolver. Require TLS 1.2 or later, hostname verification, the
   controller-approved public trust store, SNI equal to the requested host, no
   certificate exception, and no scheme downgrade or non-443 port.
5. GET the release and asset metadata from `api.github.com`. Require release ID,
   repository owner/name, non-draft/non-prerelease state, tag, asset IDs, names,
   sizes, digests, and browser URLs to equal this packet. A changed or missing
   field is a hard failure; it does not update the pin.
6. Acquire the archive through the asset-ID API with
   `Accept: application/octet-stream`. Allow at most one HTTP redirect, only
   from `api.github.com` or `github.com` to HTTPS
   `release-assets.githubusercontent.com:443`. Reject relative ambiguity,
   credentials in URLs, fragments, a second redirect, host suffix tricks,
   redirects back to an origin, and any response that exceeds or differs from
   exactly `65,976,072` bytes. Send no authorization header to the redirected
   host.
7. In Branch S only, acquire the Sigstore bundle under the same rules for asset
   ID `393784168`, exact size 8,305, and its pinned digest. In Branch O, do not
   acquire the bundle or any substitute sidecar. No other release asset is
   allowed in either branch.
8. Stream every branch-authorized object to a new
   `O_CREAT|O_EXCL|O_NOFOLLOW` file through the staging directory FD. Enforce
   response and wall-clock bounds, `fsync` each
   file, and calculate SHA-256 while receiving. On truncation, excess bytes,
   timeout, metadata drift, or digest mismatch: close, quarantine the exact
   staging identity for evidence, and publish nothing.
9. Before extraction, parse the gzip/tar structure with a memory- and
   count-bounded library. Require exactly one gzip member; bounded optional
   header fields; valid gzip header flags; mandatory CRC32 and ISIZE trailer
   validation; and no concatenated member, trailing compressed stream, or
   bytes after the one member. Require exactly one normalized POSIX tar entry
   named `codex-x86_64-unknown-linux-musl`; type regular file; no absolute path,
   separator variant, `.` or `..`, NUL, sparse extent, PAX/GNU path rewrite,
   alternate data, symlink, hardlink, directory, FIFO, socket, device, duplicate
   raw name, duplicate normalized name, or trailing second archive. Limit
   entries to 1, compressed input to the exact archive size, and aggregate
   uncompressed output to 268,435,456 bytes. Reject malformed headers,
   overlapping extents, size disagreement, and decompression-ratio or resource
   bound breach.
10. Extract through the staging directory FD to a new fixed filename, never by
    trusting an archive path. Use `O_CREAT|O_EXCL|O_NOFOLLOW`, mode `0500`, a
    bounded streaming write, and `fsync`. Do not run the candidate, its dynamic
    loader, `ldd`, installer scripts, or archive content.
11. Apply exactly the selected §3 byte-authentication branch. Branch S verifies
    the extracted binary with the pinned Sigstore bundle using the separately
    qualified offline verifier/trusted root and exact signer/workflow/ref
    policy. Branch O hashes the extracted binary and requires equality with the
    independently authenticated owner-supplied expected digest. Any failure is
    terminal; neither branch may fall back to the other. Then record SHA-256,
    size, owner/group, mode,
    device/inode, mount ID, filesystem type/ID, ELF class, machine, program and
    dynamic headers, build ID if present, capabilities, xattrs, setuid/setgid,
    and timestamps. Use a non-executing ELF parser; do not use `ldd` on
    untrusted bytes.
12. Require A, the later approved B, and C before publication. Beneath the
    staging directory, assemble a new publication tree rooted at `0.120.0`,
    with child `x86_64-unknown-linux-musl` containing only `codex` and
    `artifact.json`. Write the canonical provenance manifest mode `0444`,
    change the binary to `root:root` mode `0555` with no
    capabilities/setuid/setgid, and `fsync` both files and every staged
    directory bottom-up. Revalidate the absent final version root, then
    atomically rename the complete staged `0.120.0` tree to the exact absent
    `/opt/agenticos/providers/codex/0.120.0` path with same-filesystem
    `renameat2(RENAME_NOREPLACE)`. `fsync` the trusted `codex` parent and
    revalidate the complete published ancestry and object identities. Any
    existing destination blocks; it is never created early, overwritten,
    populated in place, or merged.
13. Final destination:
    `/opt/agenticos/providers/codex/0.120.0/x86_64-unknown-linux-musl/codex`.
    Do not create `current`, a shell shim, a PATH entry, an npm link, or any
    workspace/user-home reference. Launches later use an already-opened exact
    FD, per-launch identity checks, and `execveat(AT_EMPTY_PATH)`.
14. Default retention is removal of the downloaded archive, the Sigstore bundle
    when Branch S acquired it, and extraction staging files only after the
    installed binary and manifest are durable and their identities revalidate.
    Preserve only content-free acquisition evidence and digests. A retained
    archive cache needs a separate owner decision.

## 5. Proposed installation destination

```text
/opt/agenticos/providers/codex/
  0.120.0/
    x86_64-unknown-linux-musl/
      codex          root:root 0555
      artifact.json  root:root 0444
```

All parent directories are controller-owned, non-workspace, non-user-writable,
and absent from ambient PATH. The manifest records the complete acquisition,
signature, binary, filesystem, and publication identities but no credential or
network bearer. No mutable alias selects the version.

## 6. Authority added by acquisition and installation

| Permission | Authority added | Bound |
|---|---|---|
| A — select | Records one acceptable candidate identity | No bytes, files, execution, or network |
| B — acquire | Not presently approvable; after a reviewed trust-policy addendum, one bounded controller transfer of the archive and, only in Branch S, its exact bundle asset | Exact branch, names, IDs, sizes, digests, redirect and TLS policy; staging only |
| C — install | Adds one root-owned executable and a non-secret manifest under the exact `/opt` version path | No PATH alias, auto-update, workspace write, user config, or execution permission |
| D — qualify | Allows the exact installed FD to execute in the synthetic qualification sandbox | Loopback synthetic provider only; empty bounded `CODEX_HOME`; no real auth/provider route |

Installation adds executable bytes to the host and persistent read/execute
authority for the controller. It does not grant a task authority to choose the
path, replace the bytes, widen dependencies, contact the Internet, read a user
home, or authenticate. The later launcher must independently revalidate the
exact object on every launch; installation success is not runtime trust.

## 7. Post-acquisition qualification plan and success criteria

Authorization is phased. A later A+B permits only acquisition and pre-C passive
staged-artifact checks, including archive hashing/parsing, the selected §3
binary-byte authentication branch, and non-executing ELF/dependency inspection
in Gate 1A. C permits atomic publication only after Gate 1A passes and then
requires the post-publication passive checks in Gate 1B. D alone permits
executable probes and Gates 2–6 against the exact revalidated installed FD.
All provider traffic and credentials in active qualification are synthetic
canaries.

### Gate 1A — pre-C staged passive identity and dependency closure

- Parse ELF without execution. Require x86-64 Linux. Record every segment,
  interpreter, `DT_NEEDED`, RPATH/RUNPATH, build ID, notes, and executable-stack
  state. Expected result is no interpreter and no shared-library dependency.
- If dynamic, identify and hash the loader and full recursive shared-library
  closure without trusting ambient loader search. Any unpinned, writable,
  workspace-selected, environment-selected, or late-loaded library fails.
- Inventory strings/resources and package layout only as supporting evidence;
  they never replace signed byte identity.

### Gate 1B — post-C installed-object revalidation before D

- Re-open the exact installed path and manifest through trusted parent FDs with
  no symlink traversal. Compare SHA-256, size, numeric owner/group, mode,
  capabilities, setuid/setgid, device/inode, mount ID, filesystem type/ID,
  selected byte-authentication branch, and manifest against Gate 1A and the
  publication record.
- Repeat the complete installed-object, ancestry, manifest, ELF, loader, and
  dependency-closure identity check before every D-authorized invocation. A
  mismatch blocks before exec and never selects a fallback path or version.

### Gate 2 — bounded active identity and feature classification

- Execute only the already-opened qualified FD under the final sandbox for
  `--version`, `--help`, `exec --help`, configuration-parse probes, and
  `features list`. Expected version output is exactly `codex-cli 0.120.0`.
- Record complete argv, exit status, stdout/stderr, filesystem accesses,
  network attempts, process/descendant tree, executable identities, and FDs for
  every probe. An unknown option, feature, helper, write, or destination fails.
- Classify every command, option, feature, config key, tool, plugin/skill/MCP,
  hook/notify, update, telemetry, memory/history, resume, multi-agent, shell,
  unified-exec, web-search, login, and server surface as required, denied, or
  unavailable. New or unclassified surfaces fail closed.

### Gate 3 — immutable configuration and bounded state

- The controller writes the complete config outside the workspace, seals its
  content identity, and exposes it read-only. Required provider block:

  ```toml
  model = "synthetic-model"
  model_provider = "agenticos_broker"

  [model_providers.agenticos_broker]
  name = "AgenticOS Provider Broker"
  base_url = "http://127.0.0.1:18081/v1"
  wire_api = "responses"
  requires_openai_auth = false
  supports_websockets = false
  ```

- Deny all nonessential features explicitly. Do not rely on defaults. A
  feature-list/config mismatch or project-layer override fails.
- Use a fresh task-scoped `CODEX_HOME`/`HOME` tmpfs limited to 4 MiB and 64
  inodes, with per-file, object-count, path-depth, stdout, stderr, JSONL, FD,
  process, memory, and wall-clock limits from the M6 Slice 2C.2 design.
- Start with no `auth.json`, credentials database, keyring/D-Bus socket,
  sessions, plugins, skills, MCP config, hooks, user config, or copied state.
  Prove that login and `auth.json` are unnecessary by successful completion
  plus file-open, environment, FD, IPC, and network evidence showing no auth
  store access.

### Gate 4 — hostile workspace and authority sanitation

- Run from a Gitless M5 synthetic worktree with `/workspace/.git` masked and
  `--skip-git-repo-check`. Include hostile parent paths, `.codex` config,
  `AGENTS.md`, symlinks, filenames, file contents, prompts, fake shims, and
  executable lookalikes. None may change provider, base URL, auth mode,
  features, binary/dependency identity, or controller configuration.
- Construct environment from an exact allowlist. Remove provider/OpenAI/
  ChatGPT keys, proxy and CA variables, Git/SSH variables, dynamic-loader
  variables, tracing/telemetry, keyring, MCP/plugin/hook, runtime injection,
  and user-home state. Use a controller-fixed PATH that cannot name workspace,
  staging, install, or user-writable binaries.
- Close every inherited FD except the exact launch/control/standard streams
  authorized by policy. Census before exec and in every descendant. Reject
  extra sockets, directories, files, memfds, pidfds, or descriptor aliases.

### Gate 5 — network and synthetic Responses/SSE behavior

- Give the client network namespace only loopback and the exact broker
  listener at `127.0.0.1:18081`. There is no default route, DNS, proxy, raw
  origin socket, inherited connected socket, or host/provider interface.
- Record every socket syscall and attempted destination. Attempts to use DNS,
  non-loopback, IPv6 escape, Unix proxy sockets, update/telemetry/login hosts,
  WebSocket upgrade, redirect, or a real provider must be denied and fail the
  case.
- Against a synthetic fixture, prove exact `POST /v1/responses`, Responses wire
  schema, SSE event ordering, connection/request count, tool name/arguments for
  the bounded edit, JSONL schema, and deterministic exit. The client-facing
  request must contain no authorization, cookie, proxy authorization, API key,
  real account ID, or credential-derived value.
- Search synthetic refresh/access canaries across process environments,
  argv/FDs, client memory evidence permitted by policy, stdout/stderr/JSONL,
  config/state, workspace/diff, logs, errors, exceptions, filenames, fixture
  artifacts, and retained evidence. Enforce the M6 canary matrix exactly.
- Never provide a real key, token, auth store, account identifier, provider
  endpoint, DNS route, or live egress. A test that cannot be expressed with
  synthetic traffic is out of scope, not skipped into success.

### Gate 6 — lifecycle, bounds, and negative cases

- Census the complete child and descendant tree for every probe and task. Each
  executable, interpreter, library, argv, environment, FD, namespace, cgroup,
  and exit path must be classified and pinned. Expected production-profile
  result is no unclassified child; any child widens the dependency closure and
  requires review.
- Exercise normal completion, client/broker/fixture exit, cancellation,
  timeout, SIGTERM, SIGKILL, crash, malformed/truncated/oversized SSE and JSON,
  connection reset, stalled stream, output/file/inode/FD/process/memory
  exhaustion, and controller-control EOF. Require bounded termination and
  recursive process/cgroup drain.
- Exercise invalid TOML; missing/duplicate/unknown provider fields; auth=true;
  websocket=true; non-loopback, alternate-port, redirecting, or credentialed
  base URLs; writable/replaced config; hostile project overrides; polluted
  environment/PATH/FDs; dynamic-loader injection; archive/binary replacement;
  and identity changes between open, verify, and exec. Every case must fail
  before added authority is used and must not fall back.
- Bound stdout and stderr to 1 MiB each, each JSONL event to 256 KiB, total
  events to 4,096, individual client-state files to 1 MiB, and the complete
  attempt to 60 seconds, plus every smaller applicable M6 protocol bound.
  Truncation is explicit evidence and cannot be treated as a passing run.
- After each success and deliberate failure, prove no descendant, socket,
  namespace, cgroup, unit, task tmp, writable client state, auth path, lock,
  session, log, crash/core file, or unexplained filesystem object remains.
  Repeat the complete final matrix three consecutive times after the last
  policy change with identical structural results.

### Qualification success

Qualification passes only if every gate passes without a widened assertion,
limit, dependency, feature, destination, credential surface, or cleanup rule;
the final adversarial review has no unresolved Critical or Important finding;
and the exact qualification evidence is committed, pushed, GitHub-observed,
and synchronized cleanly into both repository clones. Failure preserves the
M6 Slice 2C.1 Level A result and leaves native execution blocked.

## 8. Cleanup and rollback

Acquisition failure closes network capabilities, records content-free failure
evidence, and quarantines only the exact staging directory identity. Cleanup
reopens the trusted staging parent, revalidates device/inode/mount/filesystem
identity and the exact child inventory, unlinks only the known non-symlink
files, and removes the now-empty exact directory. It never follows links,
matches a broad glob, or recursively deletes an unresolved path. Unknown or
mismatched content is preserved and reported.

Installation publication is atomic and no-replace, so a pre-publication
failure leaves the final path absent. Rollback of a published candidate first
disables new launches, proves no open FD/process/cgroup references the object,
revalidates the complete final directory manifest, and atomically renames that
exact directory into a controller-owned quarantine under the same filesystem.
The launcher has no mutable alias and therefore cannot fall back to it or to
another version. Final removal, if separately approved, unlinks only the known
manifest and binary after identity revalidation and removes the empty version
directories. No other installed version is selected or deleted.

Qualification cleanup follows the M6 Slice 2C.2 terminal coordinator and
durable-ledger reconciliation. Dirty or unexplained workspace content is
preserved under M5 rules. A cleanup ambiguity is a failure and blocks later
native launches.

## 9. Remaining risks and explicit non-claims

- The archive itself was not acquired or inspected. Its binary SHA-256, ELF
  linkage, loader/library closure, exact runtime dependencies, CPU/kernel
  minimums, file capabilities, build ID, and child census remain unknown.
- The Sigstore bundle was identified but not downloaded or verified. For
  Branch S, its exact certificate issuer/identity and signed binary digest are
  not independently pinned; a reviewed primary-source trust-policy addendum
  must fix the verifier, trusted root, and signer policy before B is approvable.
  For Branch O, no independently authenticated owner-supplied uncompressed-
  binary SHA-256 presently exists; that digest must be supplied before B is
  approvable, and the branch earns no Sigstore signer/provenance claim. Neither
  branch may learn its authority from acquired bytes. The tag and tagged commit
  are unsigned.
- GitHub release metadata authenticates the pinned archive digest through the
  official repository and TLS, but it is not a reproducible-build proof. No
  reproducible comparison, SBOM, or separately published checksum manifest was
  found.
- Current official config documentation and the prior Windows proof support the
  required fields, but only the selected Linux bytes can prove exact 0.120.0
  parsing and runtime behavior.
- Static linkage, zero children, absence of auth discovery, Gitless hostile
  workspace behavior, bounded state, and deterministic cleanup are proposed
  success criteria, not earned claims.
- Selection, acquisition, installation, and qualification do not authorize
  real authentication, an existing auth store, subscription use, API keys,
  real provider access, production integration, self-hosting, another host,
  another architecture/libc build, another version, auto-update, or a fallback
  artifact.
- Even a successful synthetic qualification does not earn Level B, equivalent
  Windows kernel isolation, model correctness, general Codex support,
  production readiness, or permission to implement the M6 runtime slice.

## 10. Narrow owner decision requested

Please decide each permission independently. Only A is ready for approval in
this packet; B–D remain explicitly blocked:

- [ ] **A — Exact selection.** Approve only OpenAI Codex CLI `0.120.0`, release
  `rust-v0.120.0`, asset ID `393784170`,
  `codex-x86_64-unknown-linux-musl.tar.gz`, size `65,976,072`, SHA-256
  `21b08cca7784be53d33c6f46cf897cd2b440cda58dc7912563dbc676b4d17017`,
  together with verification bundle asset ID `393784168`.
- [ ] **B — Exact acquisition — DO NOT APPROVE YET.** Blocked pending a
  separately reviewed addendum that selects exactly one §3 branch: either pin
  the verifier/dependency digests, trusted-root snapshot digest, complete
  expected signer certificate policy, and transparency-log identifiers; or pin
  an owner-supplied independently authenticated uncompressed-binary SHA-256.
  After that remediation, B may authorize only the branch-specific exact-host,
  redirect-bounded, size/digest-pinned procedure in §4, with no fallback.
- [ ] **C — Exact installation — BLOCKED ON B AND PASSIVE QUALIFICATION.** The
  eventual permission would approve atomic installation only at
  `/opt/agenticos/providers/codex/0.120.0/x86_64-unknown-linux-musl/codex`
  with the ownership, mode, manifest, no-PATH, and rollback controls in §§4–8.
- [ ] **D — Synthetic qualification execution — BLOCKED ON C.** The eventual
  permission would approve execution only of the
  exact revalidated installed FD under the complete credential-free,
  provider-disconnected, loopback-synthetic qualification gates in §7.
- [x] **E — Explicitly not approved.** No real login or authentication; no
  reading or mounting an existing auth store; no real key/token/account; no
  live provider or subscription access; no production integration or task; no
  self-hosting; no installer script; no artifact, host, target, or version
  widening; and no further implementation without a separate reviewed owner
  decision.

Until A–D are explicitly approved, the required state remains:

```text
NATIVE_CLIENT_QUALIFICATION=BLOCKED_OWNER_AUTHORIZATION
```
