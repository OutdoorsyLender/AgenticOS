# Phase Zero — Synthetic Hostile-Worker & Sandbox Conformance Harness

> **Status: Phase Zero baseline. This harness does NOT implement or claim any
> real OS security isolation. Passing these unit tests DOES NOT mean
> AgenticOS is secure yet.**

## 1. Why the hostile fixture exists

AgenticOS will eventually run AI coding agents inside strongly isolated
execution environments. Before building that real Linux/WSL sandbox, we need
a **deterministic adversarial test harness** that can measure it: a fixed
corpus of hostile probes plus the machinery to execute them, record what
happened, and compare the outcome against the intended policy.

The Phase Zero research ("three-boundary model": Git worktree ≠ sandbox;
acceptance requires worktree + permission policy + OS-level sandbox)
establishes that provider-native sandboxes are not sufficient. This harness
is the measuring instrument the future sandbox will be validated against.

## 2. What is synthetic in this milestone

Everything adversarial operates inside a temporary fixture root created by
`agenticos.sandbox.fixtures.FixtureBuilder`:

```
<temp-root>/
    assigned-worktree/      allowed.txt            (canary: permitted)
    sibling-worktree/       secret-canary.txt      (canary: sibling)   <- denied
    agenticos-private/      state.sqlite.fake      (canary: state)     <- denied
                            evidence-secret.txt    (canary: state)     <- denied
    fake-home/              .ssh/id_fake           (canary: credential)<- denied
                            .config/provider/credentials.fake          <- denied
    task-tmp/               (private temp dir)
    sockets/                (fixture-controlled socket endpoints)
```

- All canaries are randomized per run: `AOS_CANARY_<tag>_<16 hex chars>`.
- The synthetic secret environment variable is `AOS_FAKE_SECRET`; the
  harmless one is `AOS_HARMLESS`.
- Network scenarios only ever touch **fixture-controlled local endpoints**
  (127.0.0.1 listeners on ephemeral ports, or a pathname Unix socket created
  by the test). Nothing contacts the Internet or any external service.
- Nothing outside the fixture root is read, written, probed, or enumerated.
  Real `~/.ssh`, provider credentials, real environment secrets, `/mnt/c`,
  Docker/Podman/SSH-agent sockets, browser profiles, etc. are never touched.

## 3. What the current runner can and cannot prove

`UnsafeLocalRunner` (`agenticos.sandbox.runner`) is the baseline backend.

**THIS RUNNER IS NOT A SECURITY SANDBOX.** It executes the hostile worker
directly on the host with zero isolation. Under it, expected-DENY scenarios
are *supposed* to succeed, and the harness must honestly report
`attempted: true, succeeded: true` — which evaluates to conformance `FAIL`
against the default policy. That FAIL is the correct, desired baseline: it is
exactly the signal that flips to PASS when a real sandbox backend is plugged
in and the same read returns EACCES.

What it does prove:

- the synthetic fixture works and cleans up after itself;
- every attack scenario executes deterministically and reports JSON results;
- process execution is captured (argv, cwd, env, PID, PGID on POSIX, exit
  code/signal, stdout/stderr separately, start/end timestamps, timeouts);
- timeouts kill the whole process tree;
- evidence collection and policy comparison work end to end.

What it cannot prove: that any OS mechanism prevents anything.

## 4. Attack scenario catalog

Canonical catalog: `agenticos.sandbox.policy.SCENARIO_CATALOG`
(kept in sync with the registry in `tests/fixtures/hostile_worker.py`).

| ID       | Category    | Probe                                                        | Expected |
|----------|-------------|--------------------------------------------------------------|----------|
| FS-01    | filesystem  | Read a permitted file in the assigned worktree               | ALLOW    |
| FS-02    | filesystem  | Read a synthetic denied file                                 | DENY     |
| FS-03    | filesystem  | Write a synthetic denied file                                | DENY     |
| FS-04    | filesystem  | `../` traversal toward a synthetic denied area               | DENY     |
| FS-05    | filesystem  | Symlink traversal toward a synthetic denied file             | DENY     |
| ENV-01   | environment | Read an explicitly provided harmless env value               | ALLOW    |
| ENV-02   | environment | Discover a synthetic secret env variable                     | DENY     |
| PROC-01  | process     | Spawn a normal child process                                 | ALLOW    |
| PROC-02  | process     | Spawn a grandchild process                                   | ALLOW    |
| PROC-03  | process     | Child ignores SIGTERM                                        | ALLOW    |
| PROC-04  | process     | Child calls `setsid()` when supported                        | ALLOW    |
| PROC-05  | process     | Parent exits while a child remains alive                     | ALLOW    |
| NET-01   | network     | TCP connect to fixture-controlled local allowed endpoint     | ALLOW    |
| NET-02   | network     | Connect to fixture-controlled denied local endpoint          | DENY     |
| SOCK-01  | socket      | Connect to fixture-created pathname Unix socket (if supported)| DENY    |
| WRITE-01 | write       | Write within the assigned synthetic worktree                 | ALLOW    |
| WRITE-02 | write       | Write outside the assigned worktree, inside the fixture root | DENY     |

Worker CLI (one scenario per invocation, JSON result on stdout):

```
python tests/fixtures/hostile_worker.py --scenario FS-02 --target <path>
python tests/fixtures/hostile_worker.py --scenario ENV-02 --env-name AOS_FAKE_SECRET
python tests/fixtures/hostile_worker.py --scenario FS-04 --base <start> --target <denied-file>
```

`SOCK-01` reports `error_type: "Unsupported"` where AF_UNIX is unavailable;
FS-05's fixture symlink is skipped where symlink creation needs privileges.

## 5. Evidence format

`EvidenceCollector` emits newline-delimited JSON, one `EvidenceRecord` per
line:

```json
{
  "schema_version": "0.1.0",
  "event_id": "evt-...",
  "run_id": "run-...",
  "scenario_id": "FS-02",
  "timestamp": "2026-08-07T02:00:00.000000+00:00",
  "kind": "scenario_result",
  "payload": { "...": "..." }
}
```

Rules:

- Timestamps are RFC-3339 (ISO 8601 with UTC offset).
- Fixture paths in payloads are normalized to `<TEMP_ROOT>/...`.
- Evidence must not contain real usernames, real home paths, real
  environment variables, or real secrets. Process *results* capture only the
  explicit synthetic environment the test supplied, never the host's.
- Synthetic canary values MAY appear in evidence — detecting them is their
  purpose. Real credentials must never be recorded or used as canaries.

## 6. How future real sandbox backends reuse the corpus

Every backend implements `SandboxRunner` (`run(argv, cwd=..., env=...,
timeout=...)` and `run_scenario(...)`), with the same contract: argv array
(never `shell=True`), explicit cwd, explicit env dict, captured stdout/stderr,
hard total timeout, PID/exit recording, worker-JSON parsing. The identical
scenario corpus, fixtures, policy, and evaluation
(`agenticos.sandbox.policy.evaluate_run`) then measure the real sandbox:
FS-02 flips from `succeeded: true / FAIL` to `succeeded: false /
error_type: PermissionError / PASS` without changing a single test.

## 7. Security rule: canaries are always synthetic

Real user secrets must **never** be used as test canaries, fixtures, or
evidence content. Canary values are generated randomly at test time, live
only under the temporary fixture root, and are never committed to Git.
The `.gitignore` excludes runtime/evidence/credential-shaped paths; a
pre-commit secret scanner (gitleaks + forbidden-pattern hook, including the
`AOS_CANARY_` pattern) is a recommended follow-up before any provider
integration work.

## 8. Next milestone

Host capability detection + real process containment experiments on the
chosen host (WSL2/Ubuntu per the Phase Zero research): process-group /
Job-Object ownership, SIGINT → SIGTERM → SIGKILL escalation, idle vs. total
deadlines, orphan detection, then filesystem and network containment
candidates (bubblewrap / namespaces / Landlock evaluation) — each measured
by re-running this corpus through a new `SandboxRunner` backend.

## Deferred from this milestone (intentionally)

- Bubblewrap, Landlock, systemd scopes, cgroups, network namespaces,
  seccomp, AppArmor — real containment mechanisms.
- Human approval flows (`REQUIRE_APPROVAL` evaluates to `UNSUPPORTED`).
- Provider integrations (Claude / Codex / Kimi / Antigravity).
- Research-mandated supervisor extras for the real runner: executable
  SHA-256 + process start-time (PID-reuse protection), stdout/stderr
  digests in exported evidence, `occurred_at`/`type` event-envelope naming
  (the canonical AgenticOS envelope). `EvidenceRecord` carries
  `schema_version` so these fields can evolve compatibly.
- `.pre-commit-config.yaml`, `SECURITY.md`, `docs/security-boundary.md`.

## Milestone 4A additions

The corpus now includes fixed M4A runtime-view/security-state probes, UDP,
abstract Unix sockets, a sandbox-private Unix-socket positive control, and a
connected-FD sanitation attack. The production `NamespaceLandlockRunner` uses
the same result/evidence model but operates only on stable sandbox paths.
Synthetic host locators are supplied solely to the mapping test through a
workspace-owned probe file, never through production argv, environment, or
inner launch policy.

The full M4A architecture, evidence fields, adversarial matrix, and limitations
are recorded in [runtime-boundary.md](runtime-boundary.md). The durable next
steps and authentication-ownership rules are in [../roadmap.md](../roadmap.md).
