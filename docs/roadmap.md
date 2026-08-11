# AgenticOS Roadmap

M4A closes the measured L1/L2 tool-execution boundary. M4B-1 proves the
fixed capability-transport and lifecycle substrate. M4B-2 earns the
task-scoped authenticated HTTPS broker policy
([phase-zero/https-broker-policy.md](phase-zero/https-broker-policy.md)).
M4B-3 earns Connected Build, scoped
([phase-zero/connected-build-m4b3.md](phase-zero/connected-build-m4b3.md)).

## P0 next

1. **M4B-3 Connected Build — earned as scoped.** On the qualified host,
   git HTTPS (smart-HTTP v2+v0), pip hash-pinned binary wheels (two exact
   hosts), and generic digest-gated artifact fetch run through the M4B
   broker inside a bounded 1–4 exact-host grant set — fixture-qualified
   (`synthetic_origin=true` evidence; the production origin path is the
   unchanged M4B-2 code). Not earned: npm/Cargo/Go, LFS, HTTP/2/3,
   credentials, sdists, live-Internet, Windows. Records:
   [phase-zero/connected-build-m4b3.md](phase-zero/connected-build-m4b3.md)
   and the per-slice docs linked there.
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
