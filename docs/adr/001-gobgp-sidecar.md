# ADR 001: Use GoBGP as a Sidecar Instead of Native BGP

## Status

Superseded by [ADR 023 — Drive rustbgpd over gRPC Instead of Embedding Its Crates](023-rustbgpd-over-grpc.md) (2026-09-28). The reasoning below is kept as the historical record: GoBGP remains the shipped backend until the rustbgpd path passes interop re-validation.

## Date

2026-01-15

## Context

prefixd needs to announce FlowSpec NLRI to edge routers. We had three options:

1. **Implement a native BGP speaker in Rust** (e.g., using `bgp-rs` or writing from scratch)
2. **Use GoBGP as a sidecar** and control it via gRPC
3. **Use BIRD or OpenBGPd** and control via config file rewrites

A native speaker gives full control but is a massive undertaking -- BGP is a complex protocol with dozens of RFCs, and FlowSpec (RFC 5575/8955) adds NLRI encoding complexity. Getting this wrong in production means black-holing traffic.

## Decision

Use GoBGP as a sidecar process, controlled via its gRPC API (tonic client).

## Consequences

**Positive:**
- GoBGP is battle-tested and handles the full BGP state machine, capability negotiation, and peer management
- gRPC API gives us programmatic control over RIB entries with sub-second latency
- We can focus on policy logic instead of protocol implementation
- Reconciliation loop can diff desired state against GoBGP's actual RIB
- Supports FlowSpec, IPv4/IPv6, and extended communities out of the box

**Negative:**
- Extra process to deploy and monitor (mitigated by docker-compose sidecar pattern)
- gRPC dependency adds ~5ms per announcement (acceptable for our use case)
- GoBGP's FlowSpec implementation has quirks (e.g., NLRI encoding for multi-component rules)
- Tied to GoBGP's release cycle for bug fixes

**Risks:**
- If GoBGP is abandoned, we'd need to fork or build a native speaker
- GoBGP's gRPC API has breaking changes between major versions (mitigated by pinning proto files)
