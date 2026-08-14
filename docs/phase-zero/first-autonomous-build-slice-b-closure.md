# First Autonomous Build Slice B Closure

Status: complete and independently reviewed on 2026-08-14.

## Authorization and scope

This checkpoint implements only the approved First Autonomous Build Slice B:

- complete M5 workspace status capture;
- deterministic complete status manifests and category counts;
- bounded presentation separated from authoritative evidence;
- fail-closed untracked-entry and complete diff capture;
- canonical orchestration-ready workspace checkpoint identity; and
- an explicit controller-owned reuse decision.

It performs no agent execution, M4A split-phase launch, workspace leasing,
verifier or reviewer execution, repair execution, scheduling, provider
integration, authentication, network operation, native Codex admission, UI,
deployment, or generated-project publication.

The implementation began from the verified common Windows, WSL, origin, and
live GitHub baseline:

```text
fa69baf765f563333fb5c536a1dc6aeadc9ae2e7
```

## Complete status authority

The controller streams exactly:

```text
git status --porcelain=v1 -z --untracked-files=all
```

Status stdout, diagnostics, entry count, and path length are bounded. Nonzero
exit, timeout, incomplete NUL framing, invalid UTF-8, non-normalized paths,
unsupported XY codes, duplicate primary records, self-referential rename/copy
records, and impossible canonicalization fail closed. Rename/copy destinations
and sources remain distinct, while valid source reuse by multiple copies or a
recreated rename source is preserved. Only the seven valid unmerged XY codes
are accepted, and every unmerged state is explicitly non-reusable.

Each complete status tuple is represented in a deterministic manifest. The
manifest uses strict UTF-8 JSON, sorted keys, compact separators, no NaN, no
newline, and deterministic path/code ordering. Its SHA-256 covers status code,
categories, primary and optional second path, typed anomaly, and earned
untracked evidence. Complete category counts come from the same manifest
entries. Bounded inline lists expose exact truncation and omission metadata but
do not alter complete counts, manifest identity, or reuse authority.

## Untracked and filesystem evidence

Regular untracked files are opened no-follow and hashed incrementally. On
Linux, parent directories and filesystem auditing use descriptor-relative,
no-follow traversal; directory replacement cannot redirect capture outside the
owned worktree. Device, inode, type, size, and modification metadata are checked
before, during, and after hashing, with Linux ctime additionally bound. Windows
omits ctime because path-stat and descriptor-stat expose incompatible ctime
semantics, while retaining device, inode, mode, size, and modification-time
checks.

Per-file and aggregate hash bytes, filesystem entry count, cumulative path
bytes, traversal depth, inline evidence, and the overall capture deadline are
bounded. A file may consume only its descriptor-verified reservation; growth is
detected with at most a one-byte probe and is never hashed as authorized
content. Unreadable, unhashable, symlink, non-regular, and bound-exceeded
entries are explicit and prevent reuse. One bounded index observation replaces
per-entry Git subprocesses. Every indexed gitlink is forbidden, including a
clean or dirty submodule hidden by `submodule.*.ignore=all`.

## Complete diff and checkpoint identity

The authoritative tracked diff streams exactly:

```text
git diff --binary --full-index --no-ext-diff --no-textconv HEAD --
```

The controller records the complete SHA-256 and byte count while retaining only
bounded inline presentation. Nonzero exit, timeout, diagnostic/output bounds,
and incomplete capture fail closed. Binary content is embedded, object IDs are
full length, textconv is disabled, and gitlinks are independently forbidden.

The `AOSWORKSPACECHECKPOINT/1` digest uses strict UTF-8 compact sorted-key JSON
with no newline or timestamp. It binds repository, ownership and reservation,
task/generation/ref, baseline and current commit, worktree device/inode,
complete status counts and manifest digest, complete diff size/digest,
anomalies, and authoritative completeness/truncation state. Host paths and the
observation timestamp are outside portable state identity.

Capture repeats status and diff observations, revalidates every hashed pathname,
and re-observes filesystem, symbolic-ref, task-ref, and HEAD identity before it
returns. Callers receive exactly one typed `REUSABLE`, `NOT_REUSABLE`, or
`CAPTURE_FAILED` result rather than inferring authority from presentation
fields. Two unchanged immediate captures therefore compare equal, while a
relevant change alters or invalidates the checkpoint.

## Verification and independent review

Final focused Ubuntu WSL/Linux result:

```text
60 passed
```

Final full Ubuntu WSL/Linux result:

```text
2293 passed, 2 skipped
```

Final focused Windows result on the exact candidate Git tree:

```text
47 passed, 13 skipped
```

Final full Windows result on the exact candidate Git tree:

```text
1018 passed, 242 skipped
```

The independent adversarial review found and drove closure of one initial
Critical and five Important issues: invariant binary diff identity, strict
unmerged handling, valid rename/copy source reuse, end-to-end TOCTOU checks,
aggregate work bounds, and typed identity-execution failures. A second pass
found one Critical and two Important residuals: ignored gitlinks, hash-size
growth beyond reservations, and failed-stat entries escaping early accounting.
All were corrected with focused fault-injection coverage.

Final review verdict:

```text
SLICE_B_ADVERSARIAL_REVIEW=GO
UNRESOLVED_CRITICAL=0
UNRESOLVED_IMPORTANT=0
```

## Deliberately deferred

The following remain later-slice work:

- Slice C: fenced split-phase M4A execution and workspace leases;
- Slice D: verifier/reviewer execution and repair lineage operation;
- Slice E: scheduler and Demo 0 acceptance;
- Slices F1/F2: separately authorized official subscription-backed adapters;
- G2: synthetic owner-blocked behavior qualification; and
- G1: real autonomous DONE acceptance.

No Slice C work begins from this checkpoint. The only next implementation gate
is:

```text
AUTHORIZE_FIRST_AUTONOMOUS_BUILD_SLICE_C=YES
```
