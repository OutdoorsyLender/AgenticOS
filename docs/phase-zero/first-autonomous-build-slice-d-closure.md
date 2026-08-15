# First Autonomous Build Slice D Closure

Status: complete and independently adversarially reviewed on 2026-08-14.

## Authorization and baseline

This checkpoint implements only the authorized First Autonomous Build Slice D.
The verified common Windows, WSL, fetched `origin/main`, and live GitHub starting
baseline was:

```text
5e92bf41d2f10fa9e775ab3cf5d20ef154e37551
```

Both authoritative clones were clean, divergence was `0/0`, both stash lists
were empty, and no residual `aos-task-*` scope, cgroup, or process existed
before implementation.

No autonomous scheduler, task-selection loop, provider adapter, subscription
login, real AI/provider networking, UI, deployment, multi-workspace
concurrency, parallel builder, Codex admission, or Slice E behavior is present.

## Deterministic verification

`VerifierSpec` and `VerifierRegistry` make verification policy controller-owned.
A registered verifier binds an absolute executable, exact argv, `/workspace`,
timeout, independent stdout/stderr bounds, disjoint PASS/FAIL exit policies,
and optional fixture identity. Shell executables, interpreter command flags,
empty or relative executables, unknown fields, oversized argv, and ambiguous
exit policies fail closed. No planner, builder, reviewer, `AgentResult`, or model
prose supplies the command.

`VerificationController` runs one explicitly requested registered verifier
under real M4A L1 `INSPECT`. Its typed result binds the verifier and spec digest,
project/task/generation/attempt/controller epoch, exact complete Slice B
checkpoint, measured receipt and containment identity, exit classification and
code, bounded output counts/digests/inline evidence, timeout/cancellation, and
an optional normalized semantic-failure fingerprint. PASS and FAIL derive only
from the registered exit policy. Cancellation, timeout, output overflow,
receipt/containment disagreement, unexpected exit, or checkpoint instability
is infrastructure failure and cannot create code repair.

Two complete post-verifier captures must equal each other and the input
checkpoint. Native WSL tests attempt create, write, rename, delete, `.git`, host,
controller-state, and credential-sentinel access. Every attack is denied or
fails closed, the exact checkpoint remains unchanged, and the scope is absent
after recursive drain.

## Independent review

`ReviewController.build_request()` constructs and exact-compares the complete
bounded reviewer request from controller state: identity, task description,
acceptance criteria, verification result digest, checkpoint digest, context
manifest, fixed synthetic reviewer provider/model identity, instructions,
capabilities, and project limits. A caller cannot expand context or add write,
command, provider, Git, controller, or credential authority.

The reviewer is a separate provider-neutral ABI execution with a distinct
adapter instance, session, dispatch nonce, M4A L1 process/cgroup, and receipt.
Reuse of any builder adapter/session/dispatch/scope identity is rejected before
launch. Review is bound to the exact successful verification result and its
checkpoint; a changed checkpoint or non-PASS verification cannot be overridden.

Only one strictly validated advisory `ReviewerProposal` is accepted. Unknown
authority fields, direct DONE claims, task IDs, board revisions, commands,
provider selection, malformed/duplicate terminal output, output overflow,
non-success terminal results, and stale identity fail closed. Cancellation
wins over late structural PASS. Native reviewer attacks against workspace,
`.git`, host, controller, and credential paths prove denial plus unchanged
checkpoint and absent scopes.

## Repair creation, execution, and satisfaction

Eligible semantic verification failure or validated blocking review creates
one atomic controller-owned repair child keyed by the root task and normalized
failure fingerprint. The durable transaction records the result digest, moves
the parent to `WAITING_REPAIR`, and adds a READY child with explicit parent/root
lineage, deterministic controller task ID, inherited already-satisfied
dependencies, fixed acceptance criteria, and no dependency edge to its parent.
Replay before or after restart returns the same authoritative child without a
new board revision. Infrastructure, malformed, stale, mutation, timeout,
cancellation, containment, or checkpoint failures are ineligible.

Every mutating attempt now advances the project workspace lease epoch and the
selected task's matching fence. This permits a repair task identity and
generation to remain distinct from the persistent M5 project-workspace owner.
Slice C admission and terminal capture bind checkpoints to explicit workspace
identity while board/dispatch/lease authority remains bound to the repair task.

`SyntheticRepairAdapter` constructs one fixed provider-neutral builder request,
fresh fenced workspace lease, containment reservation, and real Slice C L2
execution. It modifies only `/workspace`, recursively drains, and yields two
equal complete post-repair checkpoints. `record_execution_success()` requires
exact live task/epoch/attempt/workspace binding, a measured `SUCCEEDED`
termination, accepted ABI result, released containment, equal stable captures,
and a checkpoint changed from the pre-repair input before advancing to
verification. Stale, failed, cancelled, duplicate, or late evidence cannot
advance authority.

After controller verification PASS is durably recorded, independent review
PASS atomically marks the successful repair DONE and recursively marks every
waiting ancestor DONE with `satisfying_descendant_id`. Ancestors retain their
original verification/review failure digests. Dependents remain BACKLOG until
that atomic satisfaction and require the ordinary explicit READY derivation.

## Root-lineage budgets and failure classification

Repair policy accounts across the full root lineage: prospective total
attempts, repair depth, repair-task count, distinct fingerprints, repeated
identical fingerprint count, consecutive failures, project task cap, and
overall deadline. Child creation does not reset any limit. Protocol output,
event, context, process, and runtime bounds continue to apply to every attempt.

Exhaustion creates no child and atomically fails the current repair plus all
waiting ancestors as `FAILED` / `RESOURCE_LIMIT`; it never maps provider/test
failure to `OWNER_BLOCKED` and cannot leave a root stuck in `WAITING_REPAIR`.

The typed failure taxonomy distinguishes:

```text
VERIFICATION_FAILURE
REVIEW_BLOCKING_FINDING
RETRYABLE_INFRASTRUCTURE_FAILURE
TERMINAL_INFRASTRUCTURE_FAILURE
MALFORMED_AGENT_OUTPUT
STALE_IDENTITY
CHECKPOINT_MISMATCH
WORKSPACE_MUTATION_DURING_READONLY_STAGE
TIMEOUT
CANCELLED
CONTAINMENT_FAILURE
REPAIR_BUDGET_EXHAUSTED
```

## Required demonstrations

The native WSL end-to-end tests explicitly invoke stages without selecting or
looping over work.

Flow 1 proves:

```text
real L2 broken build
-> stable checkpoint
-> real L1 verifier FAIL
-> exactly one verification repair
-> real L2 repair writes feature.txt = fixed
-> new stable checkpoint
-> real L1 verifier PASS
-> separate real L1 reviewer PASS
-> repair DONE
-> original task DONE by satisfying descendant
```

Flow 2 proves:

```text
real L2 build
-> real L1 verifier PASS
-> separate real L1 reviewer BLOCKING
-> exactly one review repair
-> real L2 repair writes review-remediation.txt
-> new stable checkpoint
-> real L1 verifier PASS
-> new separate real L1 reviewer PASS
-> repair DONE
-> original task DONE by satisfying descendant
```

Both flows preserve the original failure evidence, reject replay duplicates,
prove stable double checkpoints, and leave no residual task scope.

## Qualification and adversarial review

Final focused Ubuntu WSL/Linux result, including orchestration, real Slice C,
M4A integration/split phase, and M5 worktree suites:

```text
365 passed
```

Final focused Windows platform-neutral result on an exact Git-backed candidate:

```text
224 passed, 23 skipped
```

Final full Ubuntu WSL/Linux result in an exact standalone Git clone:

```text
2481 passed, 2 skipped
```

The first standalone full Linux attempt encountered one unrelated pre-existing
M4B concurrent HTTPS close race; its fixed-port residue cascaded into four
later M4B failures. Those exact five tests passed `5/5` in a fresh process and
the next complete standalone run produced the clean result above. No Slice D
file touches M4B networking.

Final full Windows result in an exact Git-backed candidate clone:

```text
1172 passed, 276 skipped
```

Independent adversarial review found and resolved these Important issues:

1. a terminal reviewer result could carry a PASS proposal;
2. caller-assembled reviewer context/capabilities were not exact policy;
3. repair-budget exhaustion could leave waiting ancestors nonterminal;
4. a repair could be advanced through generic status transition without exact
   successful execution evidence;
5. non-UTF-8 verifier output could violate inline evidence construction; and
6. mutating attempts did not advance the project workspace fence.

Regression tests were added for every finding. The frozen review verdict is:

```text
SLICE_D_ADVERSARIAL_REVIEW=GO
UNRESOLVED_CRITICAL=0
UNRESOLVED_IMPORTANT=0
```

## Deliberately deferred

- Slice E autonomous scheduling and task selection;
- project-wide continuous execution and multi-workspace concurrency;
- real provider adapters, subscription authentication, networking, and quota
  routing;
- UI, deployment, parallel builders, Codex admission, and generated-project
  publication; and
- later F1, F2, G2, and G1 acceptance work.

The only next implementation gate is:

```text
AUTHORIZE_FIRST_AUTONOMOUS_BUILD_SLICE_E=YES
```
