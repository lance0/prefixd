# ADR 007: Trait-Based BGP Abstraction for Testing

## Status

Accepted

## Date

2026-01-15

## Context

The policy engine and reconciliation loop need to announce and withdraw FlowSpec rules via BGP. Testing these components against a real GoBGP instance would make tests slow, flaky, and require a running GoBGP container.

## Decision

Define a `FlowSpecAnnouncer` trait that abstracts BGP operations:

```rust
#[async_trait]
pub trait FlowSpecAnnouncer: Send + Sync {
    async fn announce(&self, rule: &FlowSpecRule) -> Result<()>;
    async fn withdraw(&self, rule: &FlowSpecRule) -> Result<()>;
    async fn list_active(&self) -> Result<Vec<FlowSpecRule>>;
    async fn session_status(&self) -> Result<Vec<PeerStatus>>;
}
```

(The trait is defined in `src/bgp/announcer.rs`; `Result` is `crate::error::Result`.)

Three implementations (the last named one lands with ADR 023):
- `GoBgpAnnouncer` — GoBGP gRPC client (the shipped backend, ADR 001)
- `RustBgpdAnnouncer` — rustbgpd gRPC client ([ADR 023](023-rustbgpd-over-grpc.md))
- `MockAnnouncer` — in-memory store for tests, records all calls

## Consequences

**Positive:**
- Unit tests run in milliseconds without any external dependencies
- Can verify exact announcement/withdrawal sequences
- Policy engine tests don't depend on BGP protocol details
- Integration tests can use the real `GoBgpAnnouncer` against GoBGP in Docker
- Easy to add future implementations (native speaker, BIRD adapter)

**Negative:**
- Mock may not capture all GoBGP quirks (e.g., NLRI encoding edge cases)
- Must keep trait interface in sync with what GoBGP actually supports
- Two code paths means bugs could exist in `GoBgpAnnouncer` that `MockAnnouncer` doesn't surface

**Mitigation:**
- Lab testing with real routers (FRR, cJunosEvolved) validates the full path
- Integration tests in CI use testcontainers for GoBGP
