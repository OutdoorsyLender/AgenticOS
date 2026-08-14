# AgenticOS First Autonomous Build Design

## Status and authorization boundary

```text
DESIGN_STATUS=APPROVED
DESIGN_PUBLICATION_AUTHORIZED=YES
PRODUCTION_IMPLEMENTATION_AUTHORIZED=NO
DEMO_0_STATUS=DESIGN_READY
DEMO_1_STATUS=DESIGN_READY_PROVIDER_SELECTION_NOT_AUTHORIZED
FIRST_AUTONOMOUS_BUILD_COMPLETE=NO
SUBSCRIPTION_FIRST=YES
API_KEYS_DEFAULT=NO
UNOFFICIAL_CREDENTIAL_REUSE=FORBIDDEN
MODELS_REASON_AGENTICOS_GUARANTEES=YES
```

This checkpoint defines the shortest direct path from the earned M4/M5/M6
substrate to the first real autonomous build. It authorizes no production
code, provider selection, acquisition, installation, login, subscription
access, network access, or real provider execution.

The native Codex admission path remains parked. This design neither reopens
nor changes its artifact, owner-digest, login, credential-isolation, or Gate B
requirements.

## Verified starting point

The repository was reconciled before this document was prepared:

```text
WINDOWS_HEAD=7360f855186e399c890575d5cdb8dd5c90a5f3ad
WSL_HEAD=7360f855186e399c890575d5cdb8dd5c90a5f3ad
ORIGIN_MAIN=7360f855186e399c890575d5cdb8dd5c90a5f3ad
GITHUB_MAIN=7360f855186e399c890575d5cdb8dd5c90a5f3ad

WINDOWS_TREE=clean
WSL_TREE=clean
DIVERGENCE=0/0
UNPUSHED_COMMITS=0
UNEXPLAINED_UNTRACKED_FILES=0
STASH_ENTRIES=0
```

Focused M5 worktree tests passed on Windows and native Ubuntu WSL. Windows
skipped five Linux-only cases; WSL ran all 25 cases.

## Milestone terminology

### Demo 0: Synthetic Autonomous Loop

Demo 0 is the deterministic engineering proof implemented by Slices A-E. It
must prove the entire controller loop with synthetic adapters:

```text
goal
  -> authoritative board
  -> research and planning
  -> task scheduling
  -> controlled workspace edit
  -> deterministic verification failure
  -> automatic repair task
  -> deterministic verification pass
  -> independent review failure
  -> automatic repair task
  -> independent review pass
  -> dependent work
  -> project DONE
```

Demo 0 is mandatory. It does not complete the First Autonomous Build because
no real AI provider is required.

### Demo 1: First Autonomous Build

Demo 1 applies the same controller path to two independently qualified real
official subscription-backed provider clients. It is implemented by Slices
F1, F2, and G after Demo 0 is green.

First Autonomous Build is earned only by the positive real-provider
acceptance run `G1_REAL_AUTONOMOUS_DONE`. A separate test proves legitimate
owner blocking, but an `OWNER_BLOCKED` outcome cannot substitute for the
successful DONE run.

Two working providers are sufficient. A third provider is not required.

## Scope classification

Every proposed addition is classified as either:

- `DEMO_BLOCKER`: directly required for Demo 0 or Demo 1; or
- `POST_DEMO_BACKLOG`: useful later but not required to earn the first real
  autonomous build.

The milestone remains single-machine and uses one serialized mutable project
workspace. It does not introduce distributed consensus, multi-node
orchestration, a generalized workflow engine, a generalized database,
arbitrary concurrent mutating workers, or production-scale event
infrastructure.

## Earned components reused

### M4A runtime boundary

- `NamespaceLandlockRunner` supplies L2 writable BUILD and L1 read-only
  INSPECT profiles.
- The runtime has a fixed environment, namespace evidence, process identity,
  cgroup containment, cancellation, recursive drain, and bounded output.
- Model-generated processes receive no controller, repository, or provider
  credential authority.

### M4B Connected Build

- Existing Connected Build guarantees remain unchanged.
- Provider egress is not represented as a Connected Build grant and is not
  added to the model-facing request.
- Demo 0 requires no external provider or Internet access.

### M5 controlled worktree

- The controller owns repository identity, baseline selection, task refs,
  worktree reservation, lifecycle metadata, `.git` masking, kernel identity
  checks, result capture, preservation, and cleanup decisions.
- Workers edit ordinary files only through `/workspace`.
- Demo 0 uses one M5 worktree for the project run and serializes all BUILD and
  REPAIR mutations through exclusive controller leases.
- The worktree remains `DIRTY_PRESERVED`; Demo 0 creates no candidate commit,
  merge, main-ref update, push, or publication operation.

### M6 provider security substrate

- Existing provider broker and authentication-boundary work remains earned as
  scoped.
- Slices A-E do not depend on or import the M6 provider authentication runtime.
- Each real provider receives its own later admission decision and proof.

## Demo 0 architecture

The trusted orchestration package is separate from provider and sandbox
internals:

```text
src/agenticos/orchestration/
    models.py
    board.py
    journal.py
    adapters.py
    synthetic.py
    workspace.py
    execution.py
    verification.py
    review.py
    repair.py
    scheduler.py
    cli.py
```

The orchestration layer depends inward on measured sandbox/worktree results.
It does not duplicate or absorb M4A, M4B, M5, or M6 authority.

## Authoritative project and board model

### Project record

The controller-owned `ProjectRecord` contains:

- schema version, project ID, and bounded owner goal;
- repository identity and exact baseline commit;
- project status and typed terminal reason;
- immutable M5 project-workspace identity;
- board revision, controller epoch, and lease epoch;
- run limits, start time, and deadline;
- current full-workspace checkpoint digest; and
- transition-log sequence and head digest.

Project terminal states are `DONE`, `FAILED`, `CANCELLED`, and
`OWNER_BLOCKED`. `OWNER_BLOCKED` is terminal for autonomous execution and may
be resumed only after an explicit owner action creates a new controller epoch.

`OWNER_BLOCKED` is allowed only for a fixed reason requiring a real owner
decision, permission, credential, payment, or safety/resource-limit action.
Provider timeout, quota, authentication, transport, or availability failures;
verification or review failures; exhausted retry or repair budgets; malformed
adapter output; and scheduler failures never map to `OWNER_BLOCKED`.

### Board task

Each `BoardTask` contains:

- task ID, project ID, title, description, task type, and bounded priority;
- dependencies and controller-owned acceptance criteria;
- preferred role and validated assignment;
- state, attempt count, maximum attempts, and creation sequence;
- creator, optional parent task, and root repair-lineage task;
- task generation;
- separate workspace ID, workspace generation, and lease epoch;
- verification and review results;
- optional repair failure fingerprint and satisfying descendant; and
- typed block or terminal reason.

Task states are:

```text
BACKLOG
READY
IN_PROGRESS
VERIFYING
REVIEW
WAITING_REPAIR
BLOCKED
DONE
FAILED
CANCELLED
```

`WAITING_REPAIR` is not owner `BLOCKED`. Repair-parent links are lineage edges,
not dependency edges. A repair inherits the original task's already-satisfied
dependencies and cannot introduce a dependency cycle.

### Model proposals are not commands

Research and planning output is untrusted input. Controller compilers:

- assign authoritative task IDs;
- validate the complete proposed graph transactionally;
- reject unknown fields, duplicate keys, unknown dependencies, self-edges,
  cross-project edges, cycles, excessive graph size, and invalid encoding;
- own priority bounds, roles, capabilities, allowed paths, acceptance policy,
  and verification commands; and
- prevent planner output from changing bootstrap RESEARCH/PLAN authority.

Model prose cannot select commands, paths, providers, capabilities, task
states, retries, acceptance, or terminal results.

## Provider-neutral agent ABI

### AgentTaskRequest

Each request binds:

- project ID, task ID, task generation, and attempt;
- controller epoch, lease epoch, and dispatch nonce;
- role and provider/model identifiers;
- repository, M5 workspace, baseline, reservation, and pre-launch checkpoint
  identities;
- `/workspace` as the only workspace ABI;
- bounded instructions and controller-owned acceptance criteria;
- a controller-created context manifest containing per-item type, digest, and
  byte size;
- enumerated capabilities; and
- time, event, output, context, and process limits.

It contains no host path, `.git` path, credential, session data, credential
locator, controller state-root path, provider endpoint, or secret-bearing
environment reference.

### AgentEvent

Each event binds the complete request/lease identity and has:

- strict schema and event kind;
- monotonically increasing per-lease sequence;
- bounded typed payload;
- maximum nesting and string lengths; and
- a unique terminal-event rule.

Framing is validated incrementally before buffering. Malformed or oversized
raw payload is discarded or quarantined by digest and never embedded in the
board or trusted transition log.

### AgentResult

The result contains structural facts and bounded claims:

- typed terminal status and exit classification;
- event count, byte count, and stream digest;
- bounded evidence references;
- measured workspace-handoff reference;
- optional bounded usage/accounting; and
- typed retryability.

It cannot directly mutate controller state. A result is accepted at most once
and only for the active controller/task/workspace lease identity.

## Durable board transactions and recovery

The controller uses a small single-project transaction journal, not a
database or distributed log.

Each immutable, atomically renamed transaction record contains:

- schema, project ID, transaction ID, and controller epoch;
- prior/new board revision and event sequence;
- prior-record digest and canonical payload digest; and
- `PREPARE` or `COMMIT` state.

Files and parent directories are fsynced. `board.json` is a derived atomic
snapshot keyed to the last committed transaction digest; the transaction
chain is authoritative. Bounded segment rotation preserves the chain and
never truncates the only audit record.

Restart validates the chain before dispatch. An active execution is never
redispatched merely because the controller restarted.

## Fenced split-phase execution

Before spawn, one transaction commits:

- `READY -> IN_PROGRESS`;
- controller epoch, lease epoch, and random dispatch nonce;
- a controller-selected cryptographically unique expected containment unit;
- the exact M5 workspace identity; and
- the pre-launch checkpoint digest.

The narrow M4A split-launch API then:

1. creates the exact named containment scope and sandbox;
2. holds the existing namespace/exec gates closed so no agent code runs;
3. returns measured PID, process start ticks, boot ID, process group, cgroup,
   launch-policy digest, and executable/argv digest;
4. lets the controller durably commit the `PROCESS_STARTED` receipt; and
5. releases execution only after that commit succeeds.

If receipt persistence fails, the controller cancels and drains without
releasing execution. Recovery can address the precommitted scope, prove it
absent or drain it, and compare the M5 workspace to the pre-launch checkpoint.
Only an unchanged workspace plus positively empty/absent cgroup can be
requeued. Any mismatch or unprovable state preserves the workspace and enters
`FAILED` by default. It may enter `OWNER_BLOCKED` only through the fixed
`CONTAINMENT_UNCERTAINTY_REQUIRES_OWNER_SAFETY_DECISION` reason when the
controller can name the exact safety decision required from the owner; generic
or unclassified uncertainty cannot become `OWNER_BLOCKED`.

The existing one-shot M4A `run()` remains compatible by composing
prepare/receipt/release/wait internally.

## M5 checkpoint completeness

Before repeated dirty-worktree reuse, Slice B narrowly hardens controller
capture to:

- use `git status --porcelain=v1 -z --untracked-files=all`;
- fail closed on nonzero status or diff operations;
- record complete per-category counts;
- expose path-list truncation and capture anomaly flags;
- compute a canonical manifest digest over every observed status/path tuple,
  independent of bounded presentation lists; and
- surface unreadable or unhashable untracked entries explicitly.

The orchestration checkpoint digest binds workspace identity, baseline/ref,
device/inode, complete counts, manifest digest, diff byte count, and diff
SHA-256. Inline diff evidence remains bounded. Truncation, unexpected path,
symlink/non-regular file, or unreadable evidence cannot become a reusable
checkpoint.

Every execution is terminal only after:

1. recursive cgroup-empty proof;
2. M5 ref/device/inode revalidation;
3. complete result capture; and
4. an immediate second capture with the same checkpoint digest.

Cancellation wins over late success. A late result is evidence only and
cannot create repair work or advance the board.

## Scheduler, verification, review, and repair

Ready work is selected deterministically by priority, creation sequence, then
task ID. One durable controller lock and one workspace lease exist per
project. Demo 0 permits no concurrent mutating workspace execution.

The deterministic verifier uses controller-registered exact argv under M4A
L1 INSPECT. It receives a read-only workspace, uses no shell interpolation,
and redirects writable caches to task `/tmp`.

The reviewer uses a separate read-only execution, adapter instance, session,
identity, and cgroup. Its proposal can block fail-closed after schema,
identity, generation, independence, and checkpoint validation. A reviewer
PASS cannot override failed deterministic verification or missing measured
evidence.

Verification or review failure atomically creates one repair task keyed by a
concrete evidence fingerprint. Repair budgets apply to the root lineage:
total attempts, repair depth, distinct fingerprints, consecutive failures,
task cap, output/event caps, and deadline. Infrastructure, malformed-output,
provider, or inconclusive-review failures use typed retry/failure policy and
never create code-repair loops.

No-ready plus nonterminal state either waits for one known live fenced lease
until its deadline or transitions once to a typed blocked/failed condition. It
never spins.

## Synthetic adapter qualification

Synthetic agents implement the same ABI intended for real providers.
Workspace-mutating cases run out of process through M4A/M5 with a scrubbed
environment and synthetic canaries.

The corpus covers:

- research and planning success;
- successful edit and no-op;
- reviewer pass/fail and repair recommendation;
- retryable and terminal failure;
- malformed output, timeout, cancellation, crash, and oversized output;
- invalid workspace edit and `.git` access attempt;
- synthetic credential-access attempt;
- unexpected child process;
- duplicate terminal result; and
- workspace modification after terminal emission.

## Demo 0 implementation slices

### Slice A: Controller authority core

- Project, board, task, result, limit, and terminal-reason types.
- Total transition table and proposal compilers.
- Durable transaction journal and crash/recovery tests.
- Provider-neutral request/event/result ABI.
- Non-workspace synthetic researcher/planner fixtures.

### Slice B: Complete workspace checkpoints

- Narrow M5 capture hardening.
- Full status-manifest digest, counts, truncation, and anomaly evidence.
- Fail-closed tests for status/diff failures and untracked directory content.

### Slice C: Fenced controlled execution

- Controller-selected split-phase M4A containment identity.
- Prepare/receipt/release and restart/cancellation reconciliation.
- Exclusive project-workspace leases.
- L2 synthetic mutation under the real M5/M4A envelope.

### Slice D: Verification, review, and repair

- L1 deterministic verifier.
- Independent read-only reviewer.
- Idempotent repair creation and recursive satisfaction.
- Root-lineage budgets and failure classification.

### Slice E: Autonomous scheduler and Demo 0 acceptance

- Autonomous continuation loop and bounded CLI/status view.
- Complete synthetic fault corpus.
- Deterministic Demo 0 end-to-end acceptance.

Every slice follows the repository-preservation contract before the next
slice begins.

## Demo 0 acceptance

Given a temporary fixture repository and a high-level feature goal, Demo 0
must prove:

1. The controller creates a project and authoritative bootstrap board.
2. A synthetic researcher produces bounded notes.
3. A synthetic planner proposes multiple dependent tasks.
4. The controller validates the full DAG and assigns authoritative IDs.
5. A synthetic builder edits only the controlled M5 workspace.
6. Deterministic verification fails on the first candidate.
7. The controller creates one repair task automatically.
8. Synthetic repair modifies the preserved workspace.
9. Deterministic verification passes.
10. A distinct read-only reviewer produces a defined blocking finding.
11. The controller creates a second repair task automatically.
12. Repair, verification, and independent review pass.
13. The original task becomes effectively DONE.
14. Dependent work becomes ready and completes.
15. The project reaches DONE without a human prompt between normal tasks.
16. Final evidence binds the complete board, lease, process, and workspace
    checkpoint chain.
17. No worker obtains Git, main-ref, controller-state, credential, or provider
    authority.
18. No commit, push, deployment, provider authentication, or provider network
    access occurs.

Passing Demo 0 sets:

```text
DEMO_0_STATUS=PASSED
FIRST_AUTONOMOUS_BUILD_COMPLETE=NO
```

## Demo 1 provider admission

### Independent provider definition

An independent provider is a distinct official client implementation with a
distinct subscription-authentication domain and separately qualified
adapter. Two model names, accounts, profiles, or sessions of one official
client do not count as two providers.

Two independently admitted providers are sufficient for Demo 1. Both must be
used in the same positive acceptance run.

### Slice F1: First official subscription-backed adapter

- Select one official monthly-subscription-authenticated client under a
  separate owner approval.
- Implement the exact Demo 0 `AgentTaskRequest` / `AgentEvent` /
  `AgentResult` ABI.
- Keep provider-specific flags, event parsing, session lifecycle, endpoint
  policy, and failure mapping behind the adapter.
- Require the official client to own its login/session.
- Prohibit unofficial OAuth/token reuse and API-key fallback by default.
- Qualify executable identity, effective configuration, child-process
  topology, egress, cancellation, event bounds, and evidence mapping.
- Prove credential/session authority is absent from the model-controlled
  execution domain.

### Slice F2: Second independent subscription-backed adapter

- Select and separately qualify a second independent official client.
- Implement the same controller ABI without changing A-E semantics.
- Add only the narrow controller-mediated multi-provider handoff policy.
- Prove actual cross-provider operation with synthetic session/credential
  canaries before real G execution.

Candidate providers may include the official Claude Code or Kimi Code clients.
Codex may be considered only after its separate parked admission blockers are
resolved. Codex is not required, preferred by default, or an automatic
fallback for Demo 1.

### Provider credential-isolation admission gate

For each F1/F2 provider, real execution is forbidden until executable evidence
proves that the model-controlled execution domain has no credential or session
authority through:

- files or configuration;
- environment variables;
- inherited file descriptors;
- sockets or direct auth-helper channels;
- child processes; or
- process-memory visibility.

The official client may own subscription authentication only in the qualified
separate provider-client domain. Hostile workspace commands and
model-generated children receive none of that authority. If the official
client architecture cannot prove this split, the provider is not admitted.
AgenticOS never extracts, copies, deserializes, relocates, scrapes, replays, or
impersonates subscription credentials.

Provider selection, passive qualification, installation, owner-performed
login, and real execution are separate approval gates for each provider. This
design grants none of them.

### Cross-provider handoff boundary

F2 reuses the A-E typed context-manifest ABI. The controller creates the only
allowed handoff, containing:

- enumerated workspace paths selected by controller policy;
- the exact workspace checkpoint digest;
- selected bounded research, planning, verification, or review objects; and
- per-item type, digest, byte size, and an aggregate size cap.

The handoff prohibits:

- direct client-to-client communication;
- shared client homes, sessions, authentication domains, or process memory;
- credential locators or endpoint/configuration data;
- ambient context or raw prior-client session state; and
- provider-written commands becoming controller authority.

F2 qualification uses synthetic credential/session canaries. Slice G records
content-free evidence of which digests and sizes crossed the handoff, not the
provider credentials or private session state.

Real research/planning is bounded reasoning over owner/controller-selected
task context. It does not authorize web search, browser automation, arbitrary
Internet access, MCP/plugins, or Connected Build widening.

## Demo 1 acceptance slices

### Slice G2: G2_REAL_OWNER_BLOCKED

G2 is a narrow Demo 1 safety prerequisite that runs after both provider
adapters are qualified and before any G1 real-provider autonomous acceptance.
It uses one controller-created synthetic owner-decision condition and proves:

1. The affected project/task enters the exact authoritative `OWNER_BLOCKED`
   state.
2. No further dependent work launches.
3. Active work is handled through the defined cancellation and recursive
   drain policy.
4. Workspace and board evidence is preserved.
5. The scheduler neither spins nor livelocks.
6. The controller reports one clear, bounded owner-decision reason.
7. No model or provider output can bypass or clear the owner block.

The trigger uses synthetic data and requires no provider login, credential,
payment, network request, or other real external action. G2 adds no generalized
approval workflow, notification platform, policy engine, UI subsystem, or new
infrastructure. Resumption requires explicit owner action and a new controller
epoch.

G2 proves bounded stop behavior. It cannot earn Demo 1 or replace G1.

### Slice G1: G1_REAL_AUTONOMOUS_DONE

This is the completion gate. One project run must prove:

1. The owner supplies one project goal.
2. At least one real subscription-backed agent performs bounded research or
   planning.
3. The controller creates and owns the authoritative board.
4. Both independently qualified F1 and F2 adapters each perform at least one
   real task in the same run.
5. Controller evidence records at least one bounded cross-provider handoff.
6. A real subscription-backed builder edits only the controlled M5 workspace.
7. Deterministic verification runs from controller-owned policy.
8. A different real logical execution/session performs review and cannot
   review its own execution. Cross-provider builder/reviewer is preferred;
   if provider role limits require another allocation, cross-provider
   participation remains mandatory elsewhere in the run.
9. A defined verification or review failure creates repair work automatically.
10. A real agent executes the repair.
11. Verification and independent review pass after repair.
12. The board continues without manual prompts between normal tasks.
13. The project reaches DONE.
14. Provider credentials never enter the hostile workspace, other provider,
    typed handoff, board, request, event log, or evidence.
15. Models never receive Git, ref, controller-state, acceptance, or cleanup
    authority.
16. API keys are not required by default.

Passing G1 sets:

```text
DEMO_1_STATUS=PASSED
FIRST_AUTONOMOUS_BUILD_COMPLETE=YES
```

## Direct-path slice sequence

```text
Design checkpoint
  -> A controller authority core
  -> B complete workspace checkpoints
  -> C fenced controlled execution
  -> D verifier/reviewer/repair
  -> E scheduler + Demo 0
  -> F1 first real subscription provider
  -> F2 second independent real subscription provider
  -> G2 owner-blocked behavior qualification
  -> G1 real autonomous DONE acceptance
  -> First Autonomous Build complete
```

F1, F2, and G are `DEMO_BLOCKER` for the actual First Autonomous Build. They
are not generic post-demo expansion.

## Additional infrastructure decision

The roadmap correction adds no shared orchestration subsystem. It requires
only:

- provider-local F1/F2 admission evidence;
- one controller-owned bounded handoff policy using the existing ABI; and
- the fixed `OWNER_BLOCKED` terminal rule and separate G1/G2 acceptance.

No third provider, distributed consensus, generalized database, generalized
workflow engine, parallel mutator, or provider-optimization platform is
needed.

## POST_DEMO_BACKLOG

- Third, fourth, and later provider adapters.
- Sophisticated quota prediction and routing optimization.
- Provider scorecards and benchmarking platform.
- Parallel mutating builders and merge/conflict resolution.
- Web UI and mobile UI.
- Distributed or cloud scheduler.
- Generalized RAG and long-term semantic memory.
- Automatic deployment and autonomous spending.
- Broad MCP/plugin ecosystems and generalized browser automation.
- Production observability and billing platforms.
- Self-hosting against the AgenticOS repository.

## Security invariants preserved

- Models reason; the controller guarantees and decides.
- M4A sandbox, M4B Connected Build, M5 worktree ownership, and earned M6
  credential-boundary claims are not weakened.
- A model cannot commit, push, control refs, access main `.git`, decide
  acceptance, or clean up a worktree.
- The controller validates every state transition and measured result.
- Provider sessions remain outside hostile workspace authority.
- Cross-provider context is explicit, bounded, digest-bound, and
  controller-mediated.
- Synthetic proof remains mandatory before real-provider integration.
- Codex admission remains parked and independent from Demo 1.
- Uncertain containment or credential isolation fails closed.

## Independent design review record

The original A-E architecture received a focused adversarial review and was
amended until it had zero unresolved Critical or Important findings.

The Demo 0/Demo 1 roadmap correction received a separate focused review. That
review required:

1. actual use of both providers in the G1 run;
2. a positive DONE gate separate from owner-blocked behavior;
3. executable credential-isolation admission for each real client; and
4. an allowlisted controller-created cross-provider handoff.

Those requirements are incorporated above. Final correction verdict:

```text
ROADMAP_CORRECTION_REVIEW=GO
UNRESOLVED_CRITICAL=0
UNRESOLVED_IMPORTANT=0
```

## Approval record and exact next boundary

The owner approved this revised design and authorized publication of this
documentation checkpoint only:

```text
APPROVE_REVISED_FIRST_AUTONOMOUS_BUILD_DESIGN=YES
AUTHORIZE_DESIGN_CHECKPOINT_PUBLICATION=YES
```

That approval permits only applying the G2-before-G1 correction, final focused
review, committing, pushing, independently verifying GitHub, and synchronizing
this documentation checkpoint under the repository-preservation contract.

It does not authorize an implementation plan, Slice A, production code,
provider selection, installation, login, credential access, real provider
execution, Codex admission, Gate B, deployment, or generated-project
publication.

After publication the only next implementation decision is:

```text
AUTHORIZE_FIRST_AUTONOMOUS_BUILD_SLICE_A=YES
```
