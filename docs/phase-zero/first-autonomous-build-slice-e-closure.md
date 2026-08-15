# First Autonomous Build Slice E Closure

Status: complete and independently adversarially reviewed on 2026-08-14.

## Authorization and baseline

This checkpoint implements only the authorized First Autonomous Build Slice E
(Demo 0). The verified common Windows, WSL, fetched `origin/main`, and live
GitHub starting baseline was:

```text
664f65a89ce2f7986f81f1de927b3a4ba5a02e90
```

Both authoritative clones were clean, divergence was `0/0`, both stash lists
were empty, and no residual `aos-task-*` scope, cgroup, or worker existed before
implementation.

Real providers, provider networking, subscription login, API keys, Codex,
Claude, Kimi, UI, deployment, distributed scheduling, concurrent mutating
builders, G2 owner-block qualification, and G1 real-provider acceptance remain
absent.

## Runnable Demo 0

From native WSL/Linux at the repository root:

```bash
PYTHONPATH=src python3 -m agenticos.orchestration.cli demo0
```

The command creates an independent temporary fixture repository and one M5
controlled worktree, compiles the existing native filesystem launcher, runs the
real M4A boundaries, prints bounded controller-derived events, and returns zero
only after the authoritative project reaches `DONE`.

A representative bounded trace is:

```text
Project demo-001 created
bootstrap-research RESEARCH started
Research completed
bootstrap-plan READY
bootstrap-plan PLAN started
Planning completed; board created with 2 tasks
task-000003 READY
task-000003 BUILD started
task-000003 BUILD completed
task-000003 VERIFY failed
repair-... automatically created
repair-... REPAIR started
repair-... BUILD completed
repair-... VERIFY passed
repair-... REVIEW blocked
repair-... automatically created
repair-... REPAIR started
repair-... BUILD completed
repair-... VERIFY passed
repair-... REVIEW passed
task-000003 satisfied by repair-...
task-000004 READY
task-000004 DOCUMENT started
task-000004 BUILD completed
task-000004 VERIFY passed
task-000004 REVIEW passed
PROJECT DONE
```

Repair IDs, containment units, nonces, and checkpoint digests vary. The
authoritative logical event sequence and terminal task graph do not.

## Controller authority

`AutonomousScheduler` is one serialized, per-project locked continuation loop
over `BoardAuthority`; it does not maintain a second task store. It derives
READY state from authoritative dependencies, selects by descending priority,
then creation sequence, then task ID, and dispatches by controller-owned task
type. Adapter/model output cannot select work, assign authoritative task IDs,
change limits, extend the deadline, skip verification/review, or declare the
project complete.

The loop enforces the project deadline, total attempt limit, task and repair
limits inherited from Slice A/D, and a hard bounded scheduler-step limit. A
nonterminal board with no active or READY work fails once as invalid controller
state; it never polls without a bound. One kernel-held controller lock prevents
two schedulers from advancing the same project concurrently.

## Research, planning, and board compilation

The controller creates fixed RESEARCH and PLAN bootstrap tasks from one bounded
owner goal. The existing synthetic ABI produces a canonical bounded research
artifact, which is durably stored by digest. Planning receives bounded goal and
research manifest entries, and the existing compiler validates the complete
proposal before one atomic journal transaction both completes PLAN and publishes
controller-owned `BoardTask` identities and creation sequences. The Demo plan
contains a feature BUILD and a dependent DOCUMENT task.

Non-workspace RESEARCH/PLAN attempts do not consume the mutating workspace
lease epoch. BUILD, REPAIR, and DOCUMENT attempts do.

## Real A-D execution and continuation

Normal BUILD and DOCUMENT tasks use the Slice C `SyntheticBuildController`
through real M4A L2 and the M5 worktree. Repairs use Slice D's
`SyntheticRepairAdapter` through the same real L2 boundary. Verification uses a
controller-registered deterministic verifier under real M4A L1, and review uses
a separate M4A L1 process with independent adapter/session/dispatch/scope
identity.

BUILD-to-VERIFYING is one authoritative mutation that binds the accepted stable
execution checkpoint and terminal evidence digest. Verification and review
must observe that exact checkpoint before fresh dispatch or persisted-result
replay. A semantic verifier failure creates one idempotent repair child; a
validated blocking review creates the next repair. Infrastructure, malformed,
stale, timeout, cancellation, or checkpoint failures do not create arbitrary
code-repair loops.

Successful review recursively satisfies the repair lineage while preserving
the original failure evidence. Only then does ordinary READY derivation release
the dependent task, exactly once.

## Recovery and finalization

Controller restart reconstructs the board, worktree ownership, lease ledger,
execution ledger, research/planning artifacts, verification results, builder
identity, review results, and observed containment scopes from durable local
state. Before dispatch, the scheduler asks the stage driver to reconcile an
existing execution. A controller-owned terminal receipt closes the crash window
between worker terminalization and board commit without a second dispatch.

Persisted verification and review results are exact-bound and reused after a
crash; changed workspace state fails closed before replay. One valid current
dangling journal PREPARE is verified and completed by `BoardAuthority.recover`,
so a crash between PREPARE and COMMIT does not permanently wedge scheduling.
Deadline handling reconciles an existing execution first and leaves no active
task inside a terminal project.

Project `DONE` is an atomic board transaction that requires every task DONE,
two equal complete final checkpoints, no active lease/execution, and absence of
every durably observed containment scope. The project journal retains both the
final checkpoint digest and finalization-evidence digest, so restart after DONE
returns the same identifiers.

## Deterministic acceptance and fault corpus

The named native acceptance test
`test_DEMO_0_SYNTHETIC_AUTONOMOUS_LOOP` proves the full required flow without a
mocked execution boundary. Additional native tests prove process-style restart
at required board boundaries, terminal-receipt reuse with one execution-ledger
dispatch, persisted verification/review replay, post-build and post-review
checkpoint tamper rejection, logical equivalence across independent runs, and
zero final residue.

The platform-neutral scheduler corpus covers malformed research, rejected DAG,
build crash, build timeout, verifier infrastructure failure, reviewer malformed
output, verifier and reviewer repair paths, repeated-fingerprint exhaustion,
cancellation, stale execution results, no-READY deadlock, max-step exhaustion,
deadline exhaustion, exclusive controller ownership, checkpoint mismatch,
active-execution reconciliation, final-evidence recovery, and dangling PREPARE
completion. Existing A-D tests continue to cover lower-level idempotency and
attack cases.

## Adversarial review

Independent review initially found and the implementation resolved:

1. accepted execution checkpoints were not authoritative inputs to verification;
2. persisted verification/review results could redispatch after a crash;
3. a dangling PREPARE could wedge later mutations;
4. DONE did not retain final checkpoint/evidence identifiers;
5. deadline handling could leave an active task in a terminal project; and
6. persisted PASS review replay did not first validate the live checkpoint.

Regression tests cover every finding. The frozen final verdict is:

```text
SLICE_E_ADVERSARIAL_REVIEW=GO
UNRESOLVED_CRITICAL=0
UNRESOLVED_IMPORTANT=0
```

## Qualification

Final native WSL/Linux orchestration result, including all real Demo 0 paths:

```text
292 passed
```

Final full native WSL/Linux result:

```text
2526 passed, 2 skipped
```

One earlier full run encountered the pre-existing M4B transient-scope teardown
race in `test_cancel_mid_pip_download_no_partial_artifact`: its scope
self-collected immediately after the assertion. The exact test then passed in
a fresh process, and the clean complete rerun produced the result above. No
Slice E file changes M4B networking or teardown.

Exact-candidate Windows results and final repository synchronization evidence
are recorded in the final Slice E report after publication verification.

## Deliberately deferred

- all real provider adapters and provider networking;
- subscription login, API-key, Codex, Claude, and Kimi admission;
- provider quota/cost routing and generated-project publication;
- UI, deployment, distributed scheduling, and concurrent mutating builders;
- F1, F2, G2, and G1 behavior.

Slice E sets:

```text
DEMO_0_STATUS=PASSED
FIRST_AUTONOMOUS_BUILD_COMPLETE=NO
REAL_PROVIDER_EXECUTION=NO
SUBSCRIPTION_LOGIN=NO
API_KEY_USAGE=NO
CODEX_ADMISSION=NO
CLAUDE_ADMISSION=NO
KIMI_ADMISSION=NO
```

The only next implementation gate is:

```text
AUTHORIZE_FIRST_AUTONOMOUS_BUILD_SLICE_F1=YES
```
