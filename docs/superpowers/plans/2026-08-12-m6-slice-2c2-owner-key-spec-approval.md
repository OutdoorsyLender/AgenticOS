# M6 Slice 2C.2 Owner-Key Specification Approval Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record the owner's approval of the exact owner-key enrollment specification at commit `a9bbbedc9104f59170268e3870b6de3bd11e5376` without performing or authorizing any later gate.

**Architecture:** Amend only the normative enrollment specification to add a bounded owner-decision record and advance Gate 1 from unapproved to approved. Preserve every private-key, public-enrollment, digest, signature, Gate B, acquisition, installation, execution, authentication, provider, and runtime state as `NO`, unperformed, or blocked.

**Tech Stack:** Markdown and native WSL/Windows Git under the repository-preservation contract.

## Global Constraints

- Author from exact commit `a9bbbedc9104f59170268e3870b6de3bd11e5376` in the isolated WSL worktree.
- Record `OWNER_KEY_ENROLLMENT_SPEC_APPROVED=YES` only for the exact specification committed at that SHA.
- Do not generate or access a private key, passphrase, backup, recovery material, or public-key evidence.
- Do not acquire or execute Codex or Sigstore; do not install, authenticate, contact a provider, approve Gate B, implement runtime behavior, or widen authority.
- Gate 2 is a later manual owner-only action outside every agent/model/controller session.
- Resolve every Critical and Important review finding before commit.
- Publish the exact reviewed commit and end with Windows, WSL, `origin/main`, and GitHub `main` SHA-identical, clean, 0/0 divergent, unpushed-count zero, untracked-count zero, and stash-count zero.

---

### Task 1: Record the bounded Gate 1 decision

**Files:**

- Modify: `docs/phase-zero/m6-slice-2c2-owner-key-enrollment-specification.md`
- Create: `docs/superpowers/plans/2026-08-12-m6-slice-2c2-owner-key-spec-approval.md`

**Interfaces:**

- Consumes: the owner's explicit approval text and the exact approved specification commit.
- Produces: a repository record that Gate 1 alone is approved and that Gate 2 is now the next manual owner action.

- [ ] **Step 1: Update the normative state and decision record**

Set `OWNER_KEY_ENROLLMENT_SPEC_APPROVED=YES`, identify the approved commit, record the date and bounded purpose, and preserve every later state as `NO`.

- [ ] **Step 2: Update the seven-gate ledger and next action**

Mark Gate 1 approved at the exact commit; leave Gate 2 and Gate 3 unperformed; make Gates 4, 5, 6, and 7 blocked on their remaining predecessors; keep Gate B separately unapproved. State that the owner must stop all agent/model/controller processes before manually running the exact §5 ceremony.

- [ ] **Step 3: Self-review the complete diff**

Run:

```bash
git diff -- docs/phase-zero/m6-slice-2c2-owner-key-enrollment-specification.md
git diff --no-index -- /dev/null docs/superpowers/plans/2026-08-12-m6-slice-2c2-owner-key-spec-approval.md
rg -n "OWNER_KEY_ENROLLMENT_SPEC_APPROVED|OWNER_KEY_GENERATED|OWNER_PRIVATE_KEY_ACCESSED|OWNER_PUBLIC_KEY_ENROLLED|OWNER_DIGEST_RECEIVED|OWNER_DIGEST_STATEMENT_SIGNED|OWNER_DIGEST_STATEMENT_VALIDATED|GATE_B_APPROVED|Current state|exact next" docs/phase-zero/m6-slice-2c2-owner-key-enrollment-specification.md
```

Expected: only Gate 1 changes to approved; all later state and hard prohibitions remain explicit.

- [ ] **Step 4: Obtain fresh independent adversarial review**

Review the exact diff for approval overreach, ambiguity about the approved commit, accidental later-gate advancement, private-key ceremony execution, authority widening, and preservation-contract violations. Resolve all Critical and Important findings and re-review any changed bytes.

- [ ] **Step 5: Verify and stage exact reviewed documentation**

Run:

```bash
git diff --check
git status --short
git add -- docs/phase-zero/m6-slice-2c2-owner-key-enrollment-specification.md docs/superpowers/plans/2026-08-12-m6-slice-2c2-owner-key-spec-approval.md
git diff --cached --check
git diff --cached --name-status
git diff --cached --stat
git diff --cached
```

Expected: exactly the modified specification and new plan are staged, with no whitespace errors or unreviewed content.

### Task 2: Preserve the approval record

**Files:**

- Commit: `docs/phase-zero/m6-slice-2c2-owner-key-enrollment-specification.md`
- Commit: `docs/superpowers/plans/2026-08-12-m6-slice-2c2-owner-key-spec-approval.md`

**Interfaces:**

- Consumes: the exact reviewed Task 1 bytes.
- Produces: one immutable approval-record commit synchronized across all repository authorities.

- [ ] **Step 1: Commit the reviewed bytes**

Commit with message:

```bash
git commit -m "docs: record owner key specification approval"
```

- [ ] **Step 2: Fast-forward WSL main and publish the exact SHA**

Use fast-forward-only operations. If WSL cannot push noninteractively, relay the exact commit through a verified Git bundle to Windows and push that unchanged SHA.

- [ ] **Step 3: Verify GitHub and synchronize Windows**

Independently observe `refs/heads/main` with `git ls-remote`, then fast-forward the Windows clone from `origin/main`.

- [ ] **Step 4: Prove the stable boundary**

Freshly fetch both clones and prove identical Windows HEAD, WSL HEAD, `origin/main`, and GitHub `main`; clean trees; `0 0` divergence; zero unpushed commits; zero unexplained untracked files; and zero stash entries.
