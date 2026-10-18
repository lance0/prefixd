# ADR 009: PostgreSQL Over SQLite

## Status

Accepted

## Date

2026-01-20

## Context

prefixd originally used SQLite for state storage. This worked for single-instance development but had fundamental limitations:

1. **Multi-POP deployment** -- Multiple prefixd instances (IAD, FRA, SIN) need to share state for cross-POP visibility and coordinated quotas
2. **Concurrent writes** -- SQLite's single-writer lock caused contention under sustained event volume
3. **Operational tooling** -- Teams already know PostgreSQL: backups, monitoring, replication, pgAdmin

SQLite advantages (zero-dependency, embedded, simple) didn't outweigh the multi-POP requirement.

## Decision

Use PostgreSQL as the sole storage backend. Remove SQLite support entirely.

All queries use `sqlx` with compile-time checked SQL against a real PostgreSQL database. No ORM abstraction layer.

New mitigation creation checks active customer, POP and global quotas and inserts
intent in one READ COMMITTED transaction on one connection. A fixed advisory
transaction lock serializes admissions across controllers; counts occur after the
lock is acquired. The transaction commits before a speaker RPC. Admission has a
five-second admission deadline covering pool waits through the insert, with
transaction-local server timeouts. Preflight checks precede this deadline. Dropping an
unfinished transaction queues rollback. COMMIT runs outside the deadline, so the
deadline cannot report failure for intent that may have committed. A connection lost
while awaiting COMMIT can still return an error for committed intent; that request
sends no announcement, but later reconciliation can announce the retained intent. Raw repository inserts are reserved for
fixtures/imports and bypass admission. Withdrawals do not take this advisory lock;
a controller's local lifecycle mutex can still delay its own lifecycle operations
while it waits for admission.

## Consequences

**Positive:**
- Multi-POP coordination via shared database (cross-POP mitigation visibility, global quotas)
- Concurrent read/write without contention
- Mature ecosystem for HA (streaming replication, Patroni, RDS)
- `sqlx` compile-time query checking catches SQL bugs before runtime
- Operational teams already know how to run, monitor, and back up Postgres

**Negative:**
- Requires a running PostgreSQL instance even for development (mitigated by docker-compose)
- Integration tests need testcontainers or a real database
- Slightly higher latency than embedded SQLite for single-instance use
- `sqlx` compile-time checks require `DATABASE_URL` at build time (or offline mode with `sqlx-data.json`)

**Alternatives rejected:**
- SQLite with Litestream replication -- still single-writer, doesn't solve multi-POP
- CockroachDB/TiKV -- over-engineered for the write volume we handle
- Redis -- no ACID, poor fit for mitigation state that must survive restarts
