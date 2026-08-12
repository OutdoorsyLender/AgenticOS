# M6 Slice 2C.2 Owner-Key Enrollment Specification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish one documentation-only specification for enrolling a dedicated owner Ed25519 SSHSIG key before any `AOSCODEXOWNERDIGEST/1` statement is delivered.

**Architecture:** The specification fixes a Windows-only manual key ceremony, a narrowly scoped SSHSIG identity and namespace, bounded public enrollment evidence, byte-exact statement signing and verification, lifecycle controls, and fail-closed adversarial tests. It records passive host-tool facts but creates no key, enrollment, signature, runtime, network grant, or Gate B authority.

**Tech Stack:** Markdown, Windows OpenSSH `ssh-keygen.exe`, OpenSSH SSHSIG/allowed-signers formats, Git repository-preservation commands.

## Global Constraints

- Start from exact commit `153e4b33a2e043b5bb4ba48ac9adf7c587f19ff0` with Windows, WSL, `origin/main`, and GitHub `main` clean and SHA-identical.
- Documentation only: no key generation, private-key access, Codex or Sigstore acquisition, installation, authentication, provider access, Gate B approval, runtime implementation, or authority widening.
- The key design is dedicated passphrase-protected Ed25519 using existing Windows OpenSSH and SSHSIG namespace and identity `agenticos-owner-digest-v1`.
- Owner commands are examples for a later owner-only session and must not be executed in this slice.
- Resolve every Critical and Important adversarial-review finding before the single documentation commit.
- Finish with the exact tested commit on GitHub and both authoritative clones clean, 0/0 divergent, SHA-identical, and stash-free.

---

### Task 1: Write and review the enrollment specification

**Files:**

- Create: `docs/phase-zero/m6-slice-2c2-owner-key-enrollment-specification.md`

**Interfaces:**

- Consumes: the exact `AOSCODEXOWNERDIGEST/1` schema and Branch O boundaries in the artifact-authorization packet and trust-policy addendum.
- Produces: the normative, owner-reviewable enrollment and later-signing procedure; it does not produce an enrolled key or approval.

- [ ] **Step 1: Draft the complete normative specification**

Cover every requested algorithm, storage, ACL, passphrase, ceremony, fingerprint, enrollment, SSHSIG, canonical-byte, signature-bound, lifecycle, public-evidence, adversarial-test, gate, and non-claim requirement. Mark all command blocks `DO NOT RUN DURING THIS DOCUMENTATION SLICE` and ensure generation and signing prompt interactively for the passphrase.

- [ ] **Step 2: Run documentation self-review**

Run:

```bash
rg -n "TBD|TODO|<64 lowercase|<bounded|PLACEHOLDER|Gate B.*APPROVED" docs/phase-zero/m6-slice-2c2-owner-key-enrollment-specification.md
git diff --no-index -- /dev/null docs/phase-zero/m6-slice-2c2-owner-key-enrollment-specification.md
git diff --no-index -- /dev/null docs/superpowers/plans/2026-08-12-m6-slice-2c2-owner-key-enrollment-specification.md
```

Expected: no unresolved placeholder or approval text; each no-index command
prints the complete new file and exits `1` only because the file differs from
`/dev/null`. Any other nonzero result is failure.

- [ ] **Step 3: Obtain a fresh independent adversarial review**

Review against the user requirements, the two governing M6 documents, SSHSIG confusion/mix-and-match risks, rollback/revocation behavior, copyable command safety, and authority boundaries. Classify findings as Critical, Important, or Minor.

- [ ] **Step 4: Resolve blocking findings and re-review**

Amend the draft until zero Critical and zero Important findings remain. Record findings and resolutions in the specification without claiming that any command, key ceremony, enrollment, signature, or Gate B action occurred.

- [ ] **Step 5: Verify the final documentation tree**

Run:

```bash
git status --short
git add -- docs/phase-zero/m6-slice-2c2-owner-key-enrollment-specification.md docs/superpowers/plans/2026-08-12-m6-slice-2c2-owner-key-enrollment-specification.md
git diff --cached --check
git diff --cached --stat
git diff --cached
```

Expected: exactly the two reviewed Markdown files are staged, no whitespace
errors exist, and the complete cached diff is inspected before commit.

### Task 2: Preserve and synchronize the reviewed documentation slice

**Files:**

- Commit: `docs/phase-zero/m6-slice-2c2-owner-key-enrollment-specification.md`
- Commit: `docs/superpowers/plans/2026-08-12-m6-slice-2c2-owner-key-enrollment-specification.md`

**Interfaces:**

- Consumes: the reviewed Task 1 diff with zero unresolved Critical or Important findings.
- Produces: one exact Git commit observed on GitHub and synchronized into both authoritative clones.

- [ ] **Step 1: Commit only reviewed documentation**

Run native WSL Git from the authoring worktree, re-run `git diff --cached`,
confirm only the two exact reviewed files are staged, and commit with message:

```bash
docs: specify owner digest signing key enrollment
```

- [ ] **Step 2: Fast-forward WSL main and publish the exact SHA**

Fast-forward the authoritative WSL `main` only. Push that exact SHA to `refs/heads/main`; if WSL credentials are unavailable, use the repository contract's exact-commit bundle path through Windows. Never recreate the change in Windows.

- [ ] **Step 3: Prove GitHub and synchronize Windows**

Use `git ls-remote origin refs/heads/main`, then native Windows Git `git pull --ff-only origin main`.

- [ ] **Step 4: Prove the stable boundary**

Freshly fetch both clones and report identical Windows HEAD, WSL HEAD, `origin/main`, and GitHub `main`; clean working trees; `0 0` divergence; zero unpushed commits; zero unexplained untracked files; and zero stash entries.
