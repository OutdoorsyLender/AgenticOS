# AgenticOS Roadmap

M4A closes the measured L1/L2 tool-execution boundary. M4B-1 now proves the
fixed capability-transport and lifecycle substrate described in
[phase-zero/connected-build-boundary.md](phase-zero/connected-build-boundary.md).
M4B-1 does not authorize Connected Build.

## P0 next

1. **M4B-2 Connected Build policy** — unavailable until its pinned dependency
   report and ECH gate pass, followed by separate architecture approval. Future
   scope includes explicit destination allowlists, protocol/host/port approval,
   DNS/IP policy, TLS verification, redirects, and auditable package access.
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
