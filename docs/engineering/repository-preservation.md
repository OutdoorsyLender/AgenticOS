# Repository Preservation Contract (Standing Policy)

Status: standing rule for every AgenticOS implementation milestone, effective
M4B-3 onward unless explicitly superseded. The operational summary is the root
[`AGENTS.md`](../../AGENTS.md); this document is the full procedure.

## Why this rule exists

AgenticOS lost implementation continuity more than once when valid work
existed locally but had not been committed and pushed. A later agent then
worked from GitHub's older state and recreated or duplicated that work, and
the local and remote histories drifted.

Repository state is part of AgenticOS **evidence integrity**:

> A security property that has been tested locally but not preserved in the
> authoritative repository cannot safely be assumed by the next agent.

Therefore preservation is part of the task-completion contract, not a
courtesy step. A slice is not complete when tests pass locally; it is
complete when the tested commit is provably on GitHub and both local clones
match it.

## The two clones and the remote

| Location | Path | Authoritative Git |
|---|---|---|
| Windows clone | `C:\AgenticOS` | Windows Git |
| WSL clone | `~/src/AgenticOS` | WSL Git (inside the distro) |
| Remote | `origin` = GitHub `main` | `git ls-remote` |

**Git authority rule.** Judge each clone only with its own Git. Do not run
WSL Git against `/mnt/c/AgenticOS` to assess the Windows tree: CRLF/autocrlf
differences have previously made that view report all-files-modified on a
clean tree.

## Start-of-session reconciliation

Before changing any file, independently inspect all three sources.

In each local clone (with its own Git):

```bash
git status --short            # unexpected modifications/untracked files?
git status                    # branch state, upstream state
git branch --show-current     # must be main for milestone work
git stash list                # must be empty at stable boundaries
git fetch --prune origin      # never trust a stale origin/main
git rev-parse HEAD
git rev-parse origin/main
git rev-list --left-right --count HEAD...origin/main   # ahead / behind
git log -5 --oneline --decorate
```

Then the independent remote check (this is the authoritative GitHub view;
a local `origin/main` ref alone is not sufficient):

```bash
git ls-remote origin refs/heads/main
```

Expected steady state: `HEAD == origin/main == ls-remote main`,
`rev-list` reports `0  0`, both trees clean, stash empty.

## One-writer rule

For each implementation slice there is exactly one authoring clone. For
Linux security work this is normally `~/src/AgenticOS`. The other clone is a
synchronization and regression target — never a second authoring location.
Do not independently recreate or manually copy an implementation into the
second clone; synchronize it from GitHub with fast-forward only.

## Publishing the tested commit

Normal case: `git push origin main` from the authoring clone.

When the authoring clone lacks push credentials (the recorded WSL case),
publish the **exact tested commit** through the other clone without changing
its SHA:

```bash
# WSL (authoring clone), after local commit:
git bundle create /mnt/c/<tmpdir>/slice.bundle origin/main..main

# Windows clone:
git fetch C:/<tmpdir>/slice.bundle main
git push origin <committed-sha>:refs/heads/main

# verify the actual GitHub tip (mandatory):
git ls-remote origin refs/heads/main

# Windows clone fast-forwards; remove the temporary bundle:
git pull --ff-only
rm C:/<tmpdir>/slice.bundle

# WSL clone re-synchronizes its remote view:
git fetch --prune origin
git rev-parse origin/main   # == HEAD
```

GitHub must become the rendezvous point before any further implementation
begins. If a push fails: **STOP new implementation** — do not build another
slice on top of an unpublished security checkpoint; resolve publication
first.

## Synchronizing the other clone

Only fast-forward synchronization is allowed at slice and milestone
boundaries:

```bash
git fetch --prune origin
git pull --ff-only
```

Never create an incidental merge or rebase of shared `main` merely to
synchronize. If the pull reports that local changes or untracked files would
be overwritten, that is a dirty-tree situation — handle it per the next
section, not by forcing the pull.

## Dirty-tree and divergence handling (provenance first)

If either clone contains unexpected modified tracked files, unexpected
untracked files, local commits not on GitHub, or diverged history:

1. **STOP.** Do not start new implementation.
2. **Inspect.** `git status`, `git diff`, `git log`, file hashes. Determine
   whether the content is valid prior AgenticOS work (e.g. an interrupted
   agent's uncommitted slice, a research spike awaiting commit).
3. **Preserve valid work.** If it is valid: test/verify it, commit it
   intentionally, push, verify GitHub, synchronize. If identical content is
   already committed and pushed (byte-identical, modulo documented
   line-ending conversions), the local duplicates may be removed after that
   identity is proven — record the proof in the session report.
4. **Unknown work: STOP and report.** If provenance or correctness cannot be
   established, preserve everything and report the discrepancy. Do not build
   on top of ambiguous local-only work.

Never use the following to make a problem disappear (forbidden without
explicit user authorization and demonstrated necessity):

```text
git reset --hard
git clean -fd
git push --force
git push --force-with-lease
blind checkout over dirty files
rebasing shared main
deleting unexplained untracked directories
overwriting unexplained local files
```

Repository cleanliness must result from understanding and preserving work,
not destroying it.

## Stash policy

`git stash` must not become hidden long-term project state. If a temporary
stash is absolutely necessary during a repair: document it, resolve it during
the same work session, and end with `git stash list` empty.
`STASH_ENTRIES=0` at every stable slice and milestone boundary.

## Slice closure proof (after every substantial slice)

Report explicitly before beginning the next slice:

```text
SLICE_COMMIT=<sha>
ORIGIN_MAIN=<sha>          # after fetch
GITHUB_MAIN=<sha>          # from git ls-remote

AUTHORITATIVE_TREE=clean
OTHER_TREE=clean

UNPUSHED_COMMITS=0
```

## Milestone closure proof (end of every final report)

```text
WINDOWS_HEAD=<sha>
WSL_HEAD=<sha>
ORIGIN_MAIN=<sha>
GITHUB_MAIN=<sha>

WINDOWS_TREE=clean
WSL_TREE=clean

UNPUSHED_COMMITS=0
UNEXPLAINED_UNTRACKED_FILES=0
STASH_ENTRIES=0
```

All four SHAs must be identical. If they are not identical, the milestone is
not complete — do not report it complete.

## Anti-loophole notes (from adversarial review of this policy)

- A **failed push** blocks all further implementation, not just the current
  slice's closure.
- A local `origin/main` ref is never authoritative without a fresh
  `git fetch --prune origin`; the GitHub tip is established only by
  `git ls-remote`.
- Synchronization is incomplete until the **second** clone has fast-forwarded
  and both trees are verified clean and SHA-identical; claiming completion
  between push and second-clone sync is a violation.
- Editing the same slice in both clones is a violation even if the edits
  "look identical" — the second clone receives work only via GitHub.
- "Clean tree" achieved by deleting or overwriting unexplained files is not
  clean; it is destroyed evidence. Provenance first, always.
- A slice that exists only as working-tree changes (uncommitted) is unpushed
  work in the strongest sense; commit-or-explain before anything else.
