# ADR 026: Defer Framework Migration During the Facelift

## Status

Accepted; implementation context refreshed 2026-10-18. Amended 2026-11-14 to
[cancel the planned Loco migration](#amendment-cancel-the-planned-loco-migration);
the amendment replaces the eventual-adoption intent this decision preserved.
Withdraws [ADR 024](024-loco-staged-migration.md).

## Date

2026-10-17

## Context

The facelift makes rustbgpd the primary speaker, retains selectable GoBGP,
and gives operators a clear mitigation workflow. ExaBGP and other write-only
adapters remain future work. Existing adapters, configuration, authentication,
PostgreSQL repositories and reconciliation already
provide seams for this work.

New mitigation intent is now persisted before announcement. Durable withdrawal
requests preserve the original rule, actor, reason and operation ID for cleanup.
The complete desired/acknowledged announcement ledger still has no runtime
implementation. A write-only speaker needs that state and verified restart replay
before it can be supported safely.

Adding framework boot, configuration and ORM migrations at the same time would
change those boundaries without resolving a speaker requirement. Historical
framework estimates and dependency versions in ADR 024 are not a current
compatibility assessment.

## Decision

Defer Loco adoption throughout this facelift. Preserve the earlier eventual
adoption decision as recorded intent; this changes its scheduling rather than
silently cancelling it.

- Keep axum, sqlx, PostgreSQL, `RepositoryTrait`, current authentication,
  configuration loading and reconciliation as the runtime baseline.
- Add no Loco dependency, ORM migration or framework-driven MSRV change in
  this work. Establish the actual supported Rust baseline independently.
- Split oversized handlers only through behavior-preserving resource modules,
  separately from changes to persistence or speaker semantics.
- Implement required durable announcement recovery and, when justified,
  durable alert delivery through the existing storage boundary.
- Keep [ADR 009](009-postgresql-over-sqlite.md) operative, including its current
  storage abstraction decision; the deferred ORM migration has not superseded it.

Before resuming framework adoption, require a separate proposal identifying a
concrete unmet requirement, verified release/dependency/MSRV choices, bounded
scope, and parity checks for API routes, sessions/roles, WebSockets, metrics,
configuration reload, the CLI and recovery.

## Consequences

Speaker portability, engineering gates and the operator UI can be delivered
without a simultaneous runtime rewrite. The existing architecture still needs
smaller modules, explicit errors and reliable durable mutations; deferral does
not remove those obligations.

Framework conveniences remain unavailable until separately justified. Shipped
speaker defaults, transports, profiles and their qualification are recorded in
[speaker backends](../reference/speaker-backends.md). They do not establish the
generic write-only ledger or router traffic enforcement.

## Amendment: cancel the planned Loco migration

**Status:** Accepted 2026-11-14. It replaces the second sentence of the
decision above and withdraws [ADR 024](024-loco-staged-migration.md). The
rest of the decision stands.

### Context

The deferral kept Loco as prefixd's eventual framework, so the migration stayed
a standing commitment with no requirement behind it. The runtime baseline above
has carried speaker portability, durable withdrawal, the operator UI and the
release process since then. ADR 024's estimates, versions and MSRV assumptions
are still unrevalidated.

### Decision

Cancel the commitment to migrate to Loco. prefixd has no target framework.

- axum, sqlx, PostgreSQL behind `RepositoryTrait`, the current authentication
  modes, configuration loading and reconciliation remain the runtime, not a
  transitional baseline.
- [ADR 009](009-postgresql-over-sqlite.md) remains operative. No ORM migration
  is planned.
- Reconsider a framework only for a concrete requirement the current stack
  can't meet. That proposal is a new ADR and must meet the conditions in the
  decision above: verified release, dependency and MSRV choices, bounded scope,
  and parity checks for API routes, sessions and roles, WebSockets, metrics,
  configuration reload, the CLI and recovery. ADR 024 is historical context
  for it, not an approved plan.

### Consequences

No phase of ADR 024 is queued, and no work waits on a framework. The Rust
minimum is set by the project's own needs, not by a framework's. Smaller
modules, explicit errors and durable mutations remain obligations of the
current architecture.
