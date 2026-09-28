# ADR 024: Migrate to loco-rs in Stages

## Status

Accepted

**Extends/Supersedes in part:** [ADR 009 — PostgreSQL Over SQLite](009-postgresql-over-sqlite.md) (the "no ORM abstraction layer" clause only; PostgreSQL-only storage stands)

## Date

2026-09-28

## Context

prefixd is assembled from libraries rather than a framework: axum 0.8 with a hand-written route table, sqlx with compile-time checked SQL behind a `Repository` trait plus a `MockRepository` for tests, `axum-login` + `tower-sessions` for session auth with roles, utoipa for OpenAPI, bespoke middleware for request IDs, metrics and rate limiting, a custom WebSocket route, and a `prefixd-cli`-style companion binary (`prefixdctl`).

[loco-rs](https://loco.rs) is a Rails-inspired framework that orchestrates the same crates prefixd already uses — axum is its HTTP layer, SeaORM 2.0 (on sqlx) its ORM — and adds project structure, generators, tasks, background workers, a job queue, mailers and test fixtures. Version 1.2.0 (2026-09-24) is the current release.

A 2026-09-28 evaluation (captured in Linear LAN-1946) found the following, which shapes *how* the migration is done rather than whether:

- loco requires **Rust 1.94** (SeaORM 2.0's MSRV) against prefixd's declared 1.85, and **SeaORM 2.0 / sqlx 0.9** against prefixd's sqlx 0.8.
- loco ships **no session/role auth** (JWT + API key only), **no WebSocket/SSE layer**, **no Prometheus metrics**, **no rate limiter**, and **no core OpenAPI** (the official `loco-openapi` still targets `loco-rs ^0.16`). Configuration is loaded once at boot, so playbook/alerting/correlation hot reload is a prefixd concern.
- loco's own guidance is opinionated against a `repositories/` + `services/` shape, which is precisely prefixd's current architecture.
- loco's documented "literal drop-in path" is `Hooks::after_routes`, which mounts an existing `axum::Router` unchanged.
- Both 1.1.0 and 1.2.0 shipped breaking changes; there is no published stability policy.
- The orthodox full migration was estimated at **100-170 person-days**, dominated by the repository → SeaORM rewrite, the handler → controller rewrite and the test-harness rewrite.

The owner's decision is to migrate to loco as the eventual framework and to accept the MSRV bump. This ADR records that decision, the costs accepted with it, and the staged path that avoids a big-bang rewrite while the rustbgpd speaker swap (ADR 023) is in flight.

## Decision

Adopt loco-rs as prefixd's target framework and migrate **incrementally**, never as a single cut-over:

1. **Phase 0 — prerequisites.** Raise the workspace MSRV to loco's (`rust-version`, `CONTRIBUTING.md`, Dockerfile, CI docs) and pin an exact `loco-rs` version with an explicit upgrade cadence (its CHANGELOG is part of the checklist, as with rustbgpd in ADR 023).
2. **Phase 1 — loco shell, existing router.** Stand up the loco application (boot via `Hooks`, `AppContext`, `cargo loco` CLI, `config/{env}.yaml`) and mount prefixd's existing `axum::Router` through `after_routes`. Behaviour, routes, OpenAPI and the whole test suite stay as they are; loco owns boot, configuration plumbing and the CLI.
3. **Phase 2 — data layer, resource by resource.** Migrate repositories to SeaORM models the same way each resource is migrated, keeping `Repository` as the seam during the transition so unconverted resources keep working and `MockRepository` keeps driving unit tests until its replacement exists.
4. **Phase 3 — handlers to controllers.** Convert handlers to loco controllers per resource, preserving utoipa annotations on the new signatures.
5. **Phase 4 — batteries.** Move alert delivery to loco's Postgres-backed job queue (the one capability prefixd genuinely lacks), adopt background workers/tasks where they replace hand-rolled loops, and evaluate loco's test fixtures against the existing integration harness.
6. **Phase 5 — cleanup.** Retire the transitional seams, re-decide OpenAPI tooling, and fold the remaining bespoke middleware into loco's middleware stack where that is a real simplification.

Parity decisions to keep while migrating (each is a deliberate "no" to a loco default):

- **Auth stays `axum-login` + `tower-sessions`** (ADR 008) rather than loco's JWT/API-key auth — prefixd needs sessions, roles and the `/v1/auth/*` surface.
- **The WebSocket feed stays a prefixd route**; loco has no WS layer.
- **Metrics, rate limiting and request IDs stay prefixd middleware** until a loco equivalent actually exists.
- **Configuration keeps its five-file loader and hot-reload invariant**; only the immutable core is exposed through loco's settings.
- **`prefixdctl` stays a standalone binary** (it is a remote control for the API, not a database-backed task runner).
- **The reconciliation loop stays a `tokio` interval task**; loco's scheduler shells out per firing and cannot reach the announcer, repository or WebSocket broadcast.

## Consequences

**Positive:**
- A single convention for the next features (controllers, models, migrations, tasks, workers) instead of the layers prefixd maintains by hand today.
- A durable job queue for alerting, with retry/dead-letter semantics, replacing today's fire-and-forget webhooks.
- Generators and fixtures for new models/controllers, and a documented upgrade procedure to follow instead of ad-hoc dependency bumps.
- Project structure that a new contributor (or agent) can navigate without first reverse-engineering this repo's conventions.

**Negative:**
- **MSRV 1.85 → 1.94** for the whole workspace: `Cargo.toml`, `CONTRIBUTING.md`, Docker image and any CI toolchain pin move forward, and builds get slower to reproduce on older toolchains.
- A second database stack during the transition (sqlx directly plus SeaORM/sqlx 0.9), including a second connection pool wherever a loco feature (the job queue) is used before Phase 2 completes.
- The test harness is the largest single risk: the current `create_test_router` + `MockRepository` + `oneshot` pattern (fast, parallel, 400+ tests) has no direct loco analogue, and loco advises `#[serial]` for shared state.
- Framework churn: breaking changes landed in both 1.1 and 1.2, and the framework is maintained by a small team with no published stability policy.
- Long-running dual maintenance: unconverted resources keep the old idioms, so reviewers must know which side of the line a file is on.

**Mitigation:**
- Phase 1 delivers value (boot, config, CLI) with **zero** behaviour change and the existing suite green — it is a safe first step, not a leap.
- One resource per migration, each landing with its tests converted; no phase starts before the previous one is green on `main`.
- Pin `loco-rs` exactly; upgrade deliberately with the upgrade guide, never by an automated bump.
- Keep the parity decisions above as explicit, documented deviations rather than accidental gaps.
- Do not start Phases 2-3 while the rustbgpd speaker swap (ADR 023) is mid-flight: both touch the core data path, and the speaker swap is the one with an external deadline.

## References

- Evaluation: Linear LAN-1946 (workstream estimates, capability conflicts, loco 1.2.0 profile)
- [loco.rs](https://loco.rs) — framework documentation, upgrade guides
- [ADR 008](008-session-auth-plus-bearer.md) — hybrid session + bearer auth that Phase 1 must preserve
- [ADR 009](009-postgresql-over-sqlite.md) — PostgreSQL-only storage; its "no ORM abstraction layer" clause is superseded by Phase 2
