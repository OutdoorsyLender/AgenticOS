# AgenticOS Roadmap

M4A closes the measured L1/L2 tool-execution boundary. The following work is
ordered but intentionally not implemented by M4A.

## P0 next

1. **M4B Connected Build** — explicit destination allowlists, protocol/host/
   port approval, DNS policy, network broker, and auditable L3 package access.
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
