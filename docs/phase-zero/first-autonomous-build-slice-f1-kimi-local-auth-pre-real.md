# F1 Kimi Level-1 Task-4 pre-real gate

Date: 2026-08-16

This record closes the implementation and synthetic/native qualification gate
only. It grants no authority for the single real Level-1 attempt.

```text
F1_KIMI_LEVEL1_PRE_REAL_GATE=GO
F1_KIMI_LEVEL1_TASK4_FREEZER_IMPLEMENTATION=COMPLETE
REAL_LEVEL1_ATTEMPT_AUTHORIZED=NO
REAL_ATTEMPT_COUNT=0
REAL_LOGIN_EXECUTED=NO
REAL_PROMPT_EXECUTED=NO
REAL_INFERENCE_EXECUTED=NO
UNRESOLVED_CRITICAL=0
UNRESOLVED_IMPORTANT=0
```

## Authority and provenance

- Approved specification: `dd5b6a08609cd1db6f3ac2aa7075d3215ee0e05e`.
- Preserved Task-4 checkpoint: `3eca6bffc019df91142e668bbf5d7c3700cd7dde`.
- The five preserved commits were reconciled change-by-change as KEEP, REWORK,
  or DROP in the Task-4 implementation plan. No destructive reset was used.
- The final implementation commit is the Git commit containing this record;
  publication evidence must name its exact SHA after creation.

## Qualified controller and cgroup boundary

- WSL kernel `6.6.87.2-microsoft-standard-WSL2`, systemd `259`, Bubblewrap
  `0.11.1`, and unified cgroup v2 were qualified natively.
- The controller is the sole TID and MainPID of the exact transient service,
  stays outside `workload`, and is bound with one ordinary process pidfd.
- The live unit must prove `Delegate=yes`, `KillMode=control-group`,
  `SendSIGKILL=yes`, `TimeoutStopUSec=5s`, `Restart=no`, `TasksMax=21`, and
  `MemoryMax=1073741824`.
- `ProtectControlGroups=yes` makes the host cgroup hierarchy read-only inside
  the service mount namespace. One exact `BindPaths=` exposes only the
  transient service cgroup as writable. Native probes denied direct and
  `/proc/<peer>/root` alias access to cgroup roots, ancestors, peer locations,
  and unrelated units.
- The fixed identity-bound `workload` domain cgroup is the only admitted child.
  The outer supervisor is created directly with
  `clone3(CLONE_INTO_CGROUP)`; there is no migration fallback or child cgroup.

## Protocol, capture, and cleanup proof

The executable trace proves:

```text
terminal authenticate response
-> all ACP writes structurally disabled while stdin remains open
-> freeze request -> populated 1 -> frozen 1
-> cgroup identity, exact membership, and live roles revalidated
-> exactly one capture -> thaw -> frozen 0
-> live roles revalidated -> stdin EOF -> bounded drain -> zero residue
```

ACP state is monotonic:

```text
ACTIVE -> TERMINAL_RESPONSE_ACCEPTED -> CLOSED
```

Capture state is monotonic:

```text
NOT_YET_GRANTED -> GRANTED -> CONSUMED
```

Every failure before consumption instead reaches `REVOKED`; capture aliases
are sealed and perform no later I/O. A pre-authenticate terminal response is
rejected before the authenticate request. Cleanup uses the bound
`cgroup.kill`, proves recursive `populated 0`, removes the same cgroup, and
relies on systemd control-group cleanup if the controller dies while frozen.

## Synthetic and native evidence

- Amended A-F local-auth matrix: 223 passed, including 16 native cases.
- Native coverage includes direct placement and inherited topology, a frozen
  counter, fork racing freeze, controller-thread injection, inner/provider
  death while frozen, freeze timeout, identity drift, workload entry/escape,
  EOF-sensitive thaw ordering, late output, exit 42, SIGSYS, frozen
  `cgroup.kill`, controller death, cgroup authority denial, and zero residue.
- Required broader focused regressions passed before the final exact-commit
  verification. The exact committed candidate must additionally pass the full
  native WSL suite from a standalone clone with a real `.git` directory.
- Fresh adversarial review: Critical 0, Important 0, Minor 0; ready to merge.

## Excluded authority

- External network authority remains `NONE`.
- No real credential was opened, mounted, read, hashed, or supplied.
- No real attempt marker was claimed.
- No Kimi authentication, provider contact, model request, prompt, session,
  inference, or F2 work occurred.
- No ptrace, `process_vm_readv`, `/proc/<pid>/mem`, debugger, core-dump, or
  provider-memory authority exists.
- SIGSTOP/SIGCONT quiescence is absent; ordinary fatal signals are cleanup
  only and never frozen-state evidence.

## Remaining gate

The owner must separately authorize the one real Level-1 attempt after the
exact tested commit is published to GitHub and both Windows and WSL clones are
clean, synchronized, and residue-free. Until then:

```text
REAL_LEVEL1_ATTEMPT_AUTHORIZED=NO
```
