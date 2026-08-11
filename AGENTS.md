# AgenticOS — Agent Operating Rules

## Standing Repository Preservation Contract

This contract governs **every** AgenticOS implementation milestone. The full
policy, rationale, and command-level procedures live in
[`docs/engineering/repository-preservation.md`](docs/engineering/repository-preservation.md).
Read it before your first commit in this repository.

### The invariant

At every completed implementation-slice boundary:

```text
Windows HEAD == WSL HEAD == origin/main (after fetch) == actual GitHub refs/heads/main
```

and both working trees must be clean, with no unpushed commits and no stash
entries.

### Slice workflow (in order, no skipping)

```text
implement → test → relevant/adversarial review → inspect diff
→ git diff --check → commit → push → verify GitHub with git ls-remote
→ synchronize the other clone with git pull --ff-only
→ verify both clones clean and SHA-identical → only then begin the next slice
```

- **No unpushed work.** Never begin a new implementation slice while a valid
  local commit remains unpushed. If a push fails: STOP new implementation and
  resolve publication first.
- **One writer.** `~/src/AgenticOS` (WSL) is the authoring clone for Linux
  security work; `C:\AgenticOS` (Windows) is the regression/synchronization
  clone. Never independently author the same implementation in both clones.
  Publishing the exact tested WSL commit via `git bundle` → Windows fetch →
  Windows push of the same SHA → `git ls-remote` verification → WSL fetch is
  the approved path when WSL lacks push credentials; GitHub is the rendezvous
  before further work.
- **Git authority.** Use Windows Git for `C:\AgenticOS` and WSL Git for
  `~/src/AgenticOS`. Never judge the Windows tree through WSL Git at
  `/mnt/c/AgenticOS` — CRLF/autocrlf differences make that view lie.
- **Cross-clone synchronization.** Cross-clone synchronization must strictly use verified fast-forward operations (`git fetch --prune origin && git merge --ff-only origin/main` or `git pull --ff-only origin main`). Never use `git reset --hard` to synchronize clones.
- **Existing work wins over recreation.** Modified files, untracked
  source/evidence, spikes, or local commits: establish provenance first,
  preserve valid work through an intentional commit, never recreate work
  merely because GitHub lacks it.
- **Unknown work: STOP.** If provenance cannot be established, do not destroy
  anything to manufacture a clean tree. Report it.
- **Forbidden shortcuts** (without explicit user authorization):
  `git reset --hard`, `git clean -fd`, `git push --force`,
  `git push --force-with-lease`, blind checkout over dirty files, rebasing
  shared `main`, deleting unexplained untracked directories, overwriting
  unexplained local files.
- **Stash is not storage.** `STASH_ENTRIES=0` at every stable boundary; a
  temporary repair stash must be documented and resolved in the same session.

### Completion rule

> No AgenticOS security work is considered preserved until the exact tested
> commit is committed, pushed, independently observed on GitHub
> (`git ls-remote`), synchronized into both local clones, and left with clean
> working trees. No new implementation slice begins while valid prior work is
> unpushed or unexplained.

Repository state is part of AgenticOS evidence integrity: a security property
tested locally but not preserved in the authoritative repository cannot safely
be assumed by the next agent.
