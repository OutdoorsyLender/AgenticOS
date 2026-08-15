# First Autonomous Build Slice F1 — Kimi Passive Qualification Closure

```text
FIRST_AUTONOMOUS_BUILD_F1_KIMI_PASSIVE=COMPLETE
F1_KIMI_PASSIVE_STATUS=QUALIFIED
```

This checkpoint qualifies one exact official Kimi Code CLI 0.36.1 binary for a
future tool-free AgenticOS `PLANNER` login ceremony. It does not authenticate,
use a subscription or API key, send a real Kimi prompt, admit a real provider,
admit Kimi Builder, or begin F2, G2, or G1.

## 1. Starting baseline proof

The common native Windows, native WSL, fetched `origin/main`, and independently
observed GitHub `refs/heads/main` baseline was:

```text
35d457ae02e019bad1d6956b761685f3bc978373
```

Both clones were clean at divergence `0/0`, both stash lists were empty, and
the residue census found no AgenticOS task scope, cgroup, or worker. The
pre-change full native WSL suite passed `2526` tests with `2` skips.

## 2. Exact acquisition source and version

Only the official GitHub release asset
`kimi-code-linux-x64.zip` for tag `@moonshot-ai/kimi-code@0.36.1` was acquired:

```text
release  https://github.com/MoonshotAI/kimi-code/releases/tag/%40moonshot-ai%2Fkimi-code%400.36.1
asset    https://github.com/MoonshotAI/kimi-code/releases/download/%40moonshot-ai/kimi-code%400.36.1/kimi-code-linux-x64.zip
version  0.36.1
size     64621491 bytes
```

The archive was installed only in the dedicated WSL qualification store at
`/home/brand/.local/share/agenticos/provider-qualification/kimi-code/0.36.1/runtime`.
The owner's ordinary Kimi installation and configuration were not modified.

## 3. Artifact SHA-256 and provenance

The archive SHA-256 is
`c5af089d5ad34c27f2f26d5f93588ba3f656bf771911e5d43c85be95d3e1cbd4`.
It matches the official release sidecar, whose independently captured SHA-256
is `428ca7c07c64fa266d86ee372a2689ceeb063ab5724221e8e1e729b1f96748b5`.
The official release manifest SHA-256 is
`b1c89cc44b3e4401125ac86a5ac4c9cc324f856e902c7b859049fc3578c2af66`.

The annotated tag object is
`336fed3b5f265c986d4f43808da98f3c6b4bbd16`, peeled to source commit
`13d86f8b7bb2443a3b8222e7d94deb0a66429f8e`; the release timestamp is
`2026-08-14T12:53:36Z`. Exact URLs and digests are fail-closed fields in
`artifact.json`; a duplicate key, changed URL, version, size, hash, tag, or
source identity is rejected.

## 4. Installed runtime identity

The installed executable is the 180,948,160-byte x86-64 dynamically linked ELF
at
`/home/brand/.local/share/agenticos/provider-qualification/kimi-code/0.36.1/runtime/bin/kimi`.
Its SHA-256 is
`78c07b255e0bdc8dfe90d0cbd3204a3d862957394a08ca99c6e31144732451c7`,
GNU Build ID is `5e67bdf95c7646325b62decd0ca8d375d325ea19`, owner is WSL user
`brand` (`uid 1000`), and mode is `0555`. Its passive, contained `--version`
execution returned exactly `0.36.1` with exit zero and empty stderr.

The host dependencies are `/lib64/ld-linux-x86-64.so.2`, glibc, libstdc++, and
libgcc_s. The launcher also pins `/usr/bin/bwrap` as `bubblewrap 0.11.1`, SHA-256
`8e19e40e7d5f7a7e8b488c7926feb040eab6ed10c58fa360e266d2f70670e92b`.
The bundle, executable, owner/mode, and Bubblewrap identities are rechecked
immediately before every launch.

## 5. Auto-update control

The exact supported `KIMI_CODE_NO_AUTO_UPDATE=1` control is present in the
allowlisted environment. `KIMI_DISABLE_TELEMETRY=1` and
`KIMI_DISABLE_CRON=1` are also fixed. There is no writable update store, no
managed binary directory, no default route, and no scheduler wiring. The
qualified result is:

```text
AUTO_UPDATE=DISABLED_BY_SUPPORTED_CONFIGURATION
```

## 6. Isolated config and data-root behavior

Bubblewrap creates new user, PID, mount, network, IPC, UTS, and cgroup
namespaces; an empty tmpfs root, `/home/aos/kimi`, `/tmp`, and `/workspace`; and
read-only binds for the pinned binary, config, and profile. `HOME`,
`KIMI_CODE_HOME`, `PWD`, `PATH`, and temp paths are literal controlled values.
There is no real checkout, `/mnt/c`, ordinary home, project-local config,
`.agents`, shell startup file, skill, plugin, hook, MCP file, prior session, or
ambient provider state in the mount graph. Ambient Kimi/API-key/proxy/Git/SSH
and controller-state canaries were absent from the child and output.

The future authenticated root
`/home/brand/.local/share/agenticos/provider-state/kimi-code/0.36.1` was not
created. All credential material in testing was synthetic and ephemeral.

## 7. Effective Planner profile proof

The immutable `agent` override used as the F1 Planner profile contains
`tools: []` and `subagents: []`, a fixed AgenticOS Planner prompt, and no
template expansion.
The config disables merged and product skills, telemetry, detached background
survival, and plan mutation authority. Strict parsers reject unknown or
duplicate JSON, TOML, and profile front-matter keys, including duplicate
`tools` or `subagents` fields.

The native pinned client identified itself as `Kimi Code CLI` version `0.36.1`,
observed the fixed profile prompt, advertised zero upstream tools, and returned
one synthetic `AOSPLAN/1` proposal from bounded controller context.

## 8. Tools, subagents, and shell denial proof

A malicious local model fixture attempted `Bash`, `CommandExecution`,
`ReadFile`, `WriteFile`, `Glob`, `ListDirectory`, `ReadBinary`, `Subagent`,
`MCP`, `Plugin`, `Skill`, `Hook`, and `BackgroundTask`. The upstream tool list
was empty; the strict adapter rejected tool updates; no shell or write marker
appeared; no filesystem-read canary escaped; and continuous process monitoring
observed no descendant. Permission, filesystem, terminal, MCP, plugin, skill,
hook, subagent, and background callbacks are policy violations.

## 9. ACP v1 qualification

The closed ACP state machine covers initialization first, protocol version 1,
the unauthenticated login-method shape, session creation, one prompt, cancel,
strict session and request-ID correlation, event ordering, exactly one terminal
result, and a 1,024-frame transcript bound. It rejects malformed JSON-RPC,
unknown callbacks, duplicate responses and terminals, oversized/truncated
frames, invalid UTF-8, identity mismatch, out-of-order events, crash, timeout,
and cancellation races.

The native cancellation fixture ended `cancelled` before a delayed provider
response. A killed pinned process admitted no plan and left no child. Pinned
0.36.1 does not terminally answer the deliberately malformed upstream SSE;
the controller timed it out, terminated the contained Kimi process, and returned exact
`ACP_TIMEOUT` with no proposal. Stdout and stderr are read concurrently into
bounded buffers; an actual overproducing child is killed at the first byte over
quota.

## 10. Filesystem and local-bypass characterization

ACP text read/write callbacks are identified as ACP-mediated behavior and are
rejected by this Planner adapter. Pinned-source metadata, directory iteration,
glob, directory creation, binary-read, and command paths are local/bypass
behavior and are not treated as mediated. Kernel containment, an empty
workspace, no checkout, zero tools, and callback rejection therefore supply
the F1 boundary. This limitation keeps `KIMI_BUILDER_ADMISSION=BLOCKED`.

## 11. No-checkout Planner proof

The only workspace is a fresh empty `/workspace` tmpfs. Native observations
showed no entries and no `/.git` or `/workspace/.git`. The synthetic plan was
produced solely from bounded controller-supplied goal/context bytes. No
repository, worktree, M5 path, main checkout, Windows mount, board storage, or
evidence path was visible.

## 12. Provider data-root classification

Observed synthetic state was fully classified with no `UNKNOWN` entry:

| Category | Observed paths or role |
| --- | --- |
| `IMMUTABLE_RUNTIME` | `config.toml`, `agents/agent.md`, pinned executable |
| `FUTURE_CREDENTIAL_STATE` | synthetic `credentials/kimi-code-env-*.json` |
| `MUTABLE_NONSECRET_STATE` | session index/state/wire, workspaces, migrations |
| `LOG` | root and per-session `kimi-code.log` |
| `CACHE` | query-store metadata, indexes, WAL and locks |

Sessions, logs, cache, history, indexes, temporary files, and all synthetic
credentials are private per-launch tmpfs state and are destroyed on exit.

## 13. Future credential-submount design

The minimum persistent future mount is the dedicated `credentials/` directory,
mode `0700`, not a single file. The only permitted final entry is
`kimi-code.json`, mode `0600`; the only transient name is exact
`kimi-code.json.tmp.<pid>.<8-lowercase-hex>`. This matches the pinned official
atomic write/fsync/rename behavior. A synthetic atomic replace/persistence test
passes, while stray, symlinked, incorrectly named, or incorrectly permissioned
entries fail closed under the credential-directory validator. The validator
also requires the absolute lexical mount source to be exactly
`trusted_state_root/credentials`, requires strict resolution to preserve both
paths, and rejects a symlinked state-root ancestor. Sessions, logs, and cache
remain ephemeral. No real mount or credential exists in this checkpoint.

## 14. Process-tree census

During native plan, malicious-tool, cancellation, and crash hostile windows,
2 ms polling continuously observed exactly one provider process and no child or
grandchild. Its redacted argv was `['kimi-code']`, executable was the immutable
`/opt/agenticos/kimi/bin/kimi`, parent class was
`python3:kimi_loopback_fixture.py`, and it remained in one new process group and
the isolated namespace set. Monitoring errors fail closed; each asserted
window had post-prompt samples, and monitors stopped cleanly after drain.

## 15. Environment census

The exact child variable names were:

```text
HOME KIMI_CODE_HOME KIMI_CODE_NO_AUTO_UPDATE KIMI_DISABLE_CRON
KIMI_DISABLE_TELEMETRY LANG LC_ALL PATH PWD TMPDIR
```

The outer launcher uses `--clearenv` and never copies the host/controller
environment wholesale. The native fixture forwards only the already-cleared
sandbox allowlist to the contained Kimi process. No API key, SSH agent, Git
credential helper, cloud credential, proxy, other provider credential,
controller path, project path, or ambient Kimi path survived.

## 16. FD census

Inherited descriptors were exactly stdin/stdout/stderr pipes. Runtime-open
descriptors were continuously constrained to pipes, sockets, anonymous inodes,
`/dev/null`, private Kimi state, and the pinned runtime. A deliberately open
synthetic secret FD was not inherited; no host/controller/credential-authority
descriptor appeared. `close_fds=True`, an empty `pass_fds`, and bounded
concurrent pipe readers enforce the controller side.

## 17. Egress census

The provider namespace had no default route. Continuous TCP/UDP sampling saw
only the local synthetic model listener and its loopback connection; it saw no
non-loopback endpoint and no startup, authentication, telemetry, cron, or
update connection. The only executed model request was the fixture's local
`/v1/chat/completions` request.

Pinned-source expectations for a later gate remain `auth.kimi.com:443` for
official OAuth and `api.kimi.com:443` for the managed model service.
`code.kimi.com:443` is the update endpoint and must remain denied. No hostname
is promoted to a real allowlist by this passive gate, and the namespace/no-route
boundary guarantees denial even between sampling instants.

## 18. Synthetic auth and canary results

The local fixture installed fake managed access and refresh values, exercised
the auth-success header shape against a loopback model server, created an ACP
session, and returned one synthetic plan. The refresh storage/atomic replace
shape was tested without invoking real OAuth. Both synthetic credential values
were scanned and redacted across transcript, stderr, provider bodies, state,
argv, environment, FDs, workspace, board/result representations, evidence, and
normal and early-failure reports. Credential, filesystem, workspace,
controller-state, API-key, and host-authority canaries had zero forbidden
leakage.

## 19. AOSPLAN/1 and controller mapping

Provider bytes remain untrusted. The narrow parser accepts only a bounded
`AOSPLAN/1` proposal and maps it through the existing provider-neutral
`AgentTaskRequest`, `AgentEvent`, and `AgentResult` boundary. The existing Slice
A planner compiler remains authoritative for IDs, dependencies, run limits,
provider choice, status, verification commands, host paths, and project
completion. There is no Kimi-specific board or scheduler authority path.

## 20. Adapter and runtime code changed

The checkpoint adds only the pinned-bundle validator, closed ACP parser/state
machine, Bubblewrap passive runtime, synthetic fixture, narrow provider package
exports, exact metadata/config/profile/data-root policy, and their tests. Real
execution fails closed as `REAL_PROVIDER_DISABLED: NOT_AUTHENTICATED`.
Kimi is not registered with `AutonomousScheduler`, and existing A–E semantics
are unchanged.

## 21. Demo 0 regression

The named native
`test_DEMO_0_SYNTHETIC_AUTONOMOUS_LOOP` remains green. The qualification store
does not alter the host PATH, Demo 0 selection, network policy, sandbox policy,
provider-neutral protocol, or any M4/M5 authority.

## 22. Focused and full test results

The final focused WSL suite covering all orchestration, all provider tests, and
the provider broker/auth conformance security corpus collected `546` tests,
passing `545` with one existing platform-conditioned skip. The exact named
Demo 0 acceptance passed separately. `compileall`, secret/canary
scans, `git diff --check`, strict bundle validation, native fixture scenarios,
and wrong-version/hash/mode/symlink/duplicate-key/overflow negative tests pass.

The final full candidate collects `2623` tests and passes `2621` with the same
`2` existing skips. An earlier full run hit the pre-existing M4b test race in
`test_serve_revoke_mid_connection_tears_down`: revocation raced synthetic
origin TLS classification, then its failed teardown temporarily held fixed
port 18080 and caused a cascade. The exact test reproduced intermittently in
a fresh process; no changed file touches M4b. The subsequent uninterrupted
full run completed green. This race is disclosed, not counted as Kimi evidence.

## 23. Adversarial review findings and resolutions

Independent review found and the implementation resolved:

1. a file-only future credential mount incompatible with atomic sibling rename;
2. unbounded post-exit stdout/stderr capture;
3. refresh-canary omissions and unredacted early failure paths;
4. no pinned-process mid-turn crash fixture;
5. postmortem-only process/FD/socket census and monitor coverage gaps;
6. duplicate profile-frontmatter ambiguity;
7. stale runtime/bundle identity after runtime-spec construction; and
8. insufficient ACP frame-count bounding.

Executable credential-directory anchor/resolution/entry/type/link/owner/mode
rules, concurrent quota-kill readers, all-canary fail-path redaction, crash
tests, continuous fail-closed hostile-window monitoring, duplicate-key
rejection, launch-time pin rechecks, and the transcript bound close these
findings. The final independent verdict was:

```text
UNRESOLVED_CRITICAL=0
UNRESOLVED_IMPORTANT=0
```

## 24. Residual risks

`/proc` socket/process/FD evidence is high-frequency sampling rather than
syscall tracing; no-route namespace confinement proves denial, not absence of
an unobserved attempted hostname. Some controls are declarative pinned-source
facts combined with executable boundary observations rather than a real-login
run. The packaged ELF dynamically depends on qualified host libraries. Real
OAuth/device behavior, refresh under an actual account, real endpoint census,
subscription membership, quota behavior, model quality, and real inference
remain deliberately unqualified. Kimi's local filesystem bypass keeps Builder
blocked. None of these residuals grants authority.

## 25. Final commit SHA

The exact tested closure commit cannot self-contain its own SHA. Its immutable
SHA and independently observed GitHub `refs/heads/main` value are recorded in
the final publication report for this checkpoint.

## 26. Repository synchronization proof

Publication is complete only after the exact tested WSL-authored commit is
pushed, independently observed with `git ls-remote`, fast-forwarded into the
native Windows clone, and both native clones prove the same SHA, clean trees,
divergence `0/0`, zero stashes, zero unexplained files, and zero AgenticOS task,
cgroup, or worker residue. The final report records those post-publication
values; this document does not predict them.

## 27. Exact future owner-login ceremony

Only after a separate owner approval, the controller may start the same
hash-qualified runtime in a login-only containment mode with the isolated
future credential directory mounted. The owner personally runs the official
Kimi login flow, reads the official verification URL and device code in that
terminal, opens the official URL in their own browser, enters the code, and
approves the intended membership. The owner must never paste a password, OAuth
token, device code, cookie, session value, credential file, or API key into
chat. The controller retains only content-free success/failure and boundary
metadata, verifies storage isolation, and stops before any inference prompt.

## 28. Exact next authorization requested

The only next authorization is:

```text
AUTHORIZE_F1_KIMI_OWNER_LOGIN_CEREMONY=YES
```

Hard stop: do not login, do not send a real Kimi prompt, do not access the
owner's subscription, do not admit Kimi as a real provider, and do not begin
F2.
