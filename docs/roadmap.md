# AgenticOS Roadmap

M4A closes the measured L1/L2 tool-execution boundary. M4B-1 now proves the
fixed capability-transport and lifecycle substrate described in
[phase-zero/connected-build-boundary.md](phase-zero/connected-build-boundary.md).
M4B-1 does not authorize Connected Build.

## P0 next

1. **M4B-2 Connected Build policy** — the narrow task-scoped HTTPS broker
   policy has landed ([phase-zero/https-broker-policy.md](phase-zero/https-broker-policy.md)):
   one approved exact hostname per task on the qualified host, with an
   authenticated startup probe gating broker readiness. It deliberately earns
   NO Connected Build claim; build-ecosystem qualification (package managers,
   registries, provider endpoints) remains M4B-3 scope, pending separate
   architecture approval.
2. **Git worktree manager** — identity-bound assignment, lifecycle, cleanup,
   and the `/workspace` mapping contract.
3. **Provider adapters** — Codex, Claude, Kimi ACP, then Antigravity in a
   deliberately LIMITED role.
4. **Provider-neutral context and handoffs** — progressive context envelope
   plus typed immutable agent handoffs.
5. **Evaluation and repair** — deterministic evaluator, independent
   cross-provider reviewer, and bounded repair loop.
6. **Operations** — quota-aware routing and empirical provider scorecards.

## Authentication ownership

- Official provider clients retain authentication ownership.
- Monthly subscriptions are used first; APIs may later be optional overflow
  capacity.
- AgenticOS does not extract, copy, deserialize, relocate, or replay consumer
  credentials.
- Provider authentication never enters the L1/L2 tool execution domain;
  future brokers expose bounded capabilities, not bearer credentials.

## Governing principle

Models reason. AgenticOS guarantees.
