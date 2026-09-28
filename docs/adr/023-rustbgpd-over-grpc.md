# ADR 023: Drive rustbgpd over gRPC Instead of Embedding Its Crates

## Status

Accepted

**Supersedes:** [ADR 001 — Use GoBGP as a Sidecar Instead of Native BGP](001-gobgp-sidecar.md)

## Date

2026-09-28

## Context

ADR 001 chose GoBGP as a sidecar controlled over gRPC, and listed the escape hatch explicitly: *"If GoBGP is abandoned, we'd need to fork or build a native speaker."* That speaker now exists as a first-party project — `rustbgpd` (v0.73.0, 2026-09-27), which is in field validation and already carries a full RFC 8955/8956 FlowSpec surface.

`ROADMAP.md` planned the replacement as **crate embedding**: depend on `rustbgpd-rib` + `rustbgpd-transport` and speak BGP in-process, deleting the GoBGP proto, the gRPC client and the sidecar container. That plan is not available:

- `crates/rib/Cargo.toml:2` and `crates/transport/Cargo.toml:2` are `publish = false`, as are `api`, `telemetry`, `policy`, `evpn`, `event-history`, `bmp`, `mrt`, `cli` and `bfd`.
- `docs/reference/embedding.md:579` states the policy directly: *"Never publish as a library: transport, api, evpn, evpn-linux, the daemon binary"*; line 577 says `rib` *"is not ready to be a stable external API in alpha."*
- The orchestration that joins rib + transport into a working speaker — `PeerManager`, `RibManager::run`, the listener and config/reload wiring — lives in the daemon binary's private modules; `src/lib.rs` exports nothing outside a `bench-internals` feature.
- The same document names the supported shape: *"Shape A — drive the daemon over gRPC (no codec) … This is the recommended production embedding"* (`docs/reference/embedding.md:325-326`, restated at `:688-689`).

There is also a safety argument independent of publication policy. ADR 003's fail-open property works because prefixd dying removes the BGP speaker too: the session drops, the peer's hold timer expires, and the routers age the FlowSpec rules out. An in-process speaker makes prefixd's own RIB authoritative, so a crash mid-mitigation could leave announcements that only a router-side timeout clears.

prefixd's BGP usage is already behind a four-method trait (`FlowSpecAnnouncer` in `src/bgp/announcer.rs:43-53`, per ADR 007), consumed everywhere as `Arc<dyn FlowSpecAnnouncer>` (`src/state.rs:23`). The only GoBGP-aware code is `GoBgpAnnouncer` and one integration test file.

## Decision

Replace the GoBGP sidecar with a **rustbgpd sidecar driven over gRPC** (rustbgpd's Shape A). `RustBgpdAnnouncer` implements the existing trait; no call site, policy rule, guardrail or reconciliation semantic changes.

Mapping from trait method to rustbgpd RPC (pinned v0.73.0):

| `FlowSpecAnnouncer` | rustbgpd |
|---|---|
| `announce` | `InjectionService.AddFlowSpec` (`proto/rustbgpd.proto:3329-3402`) |
| `withdraw` | `InjectionService.DeleteFlowSpec` |
| `list_active` | `RibService.ListFlowSpecRoutes` (`proto:3404-3439`) — Loc-RIB view; per-peer received view available for diagnostics |
| `session_status` | `NeighborService.ListNeighbors` / `GetNeighborState` (`proto:470-496`) — its `SessionState` maps 1:1 onto prefixd's |

FlowSpec construction uses `FlowSpecComponent::DestinationPrefix` + `::IpProtocol` + `::DestinationPort` and `FlowSpecAction::TrafficRateBytes{asn, rate}`, where `rate = 0.0` is the RFC 8955 §7.1/§7.2 encoding of discard.

The backend becomes a config choice (`bgp.mode: gobgp | rustbgpd | mock`) so the swap can be validated against a live rustbgpd before GoBGP is removed; ADR 001's GoBGP path is deleted once interop re-validation passes. rustbgpd is pinned to an exact version and its CHANGELOG is tracked on upgrade.

Reconciliation stays the poll-and-converge loop of ADR 011: it reads the FlowSpec view every `timers.reconciliation_interval_seconds` (default 30) and corrects drift, unchanged in shape from today. Nothing in prefixd consumes a pushed BGP event stream, so rustbgpd's event history (unicast-only at the time of writing) is not on the critical path — an event subscription would only shorten the window for detecting out-of-band withdrawals, and can be revisited as an optimisation rather than a dependency.

## Consequences

**Positive:**
- Keeps the battle-tested protocol path (peer FSM, capability negotiation, GR/LLGR, TCP-AO) in a process that already has interop receipts, instead of prefixd re-implementing ~4k lines of daemon wiring against unpublished crates.
- Preserves the fail-open property of ADR 003, which depends on the speaker being a separate process.
- Removes prefixd's own BGP proto maintenance: the GoBGP proto, generated `apipb` re-export and proto build step go away, replaced by a client generated from rustbgpd's self-contained proto.
- Gains native mTLS gRPC and a token/principal auth model, plus its own Prometheus surface on a separate listener.
- rustbgpd documents the controller contract being relied on: `AddFlowSpec` is an upsert that always succeeds (so prefixd's reconciliation re-announce is safe), while deleting an absent rule returns `NOT_FOUND` — which prefixd must treat as drift, not failure.
- rustbgpd ships `examples/ddos-mitigation/config.toml` describing exactly this integration ("Detection → Mitigation platform → rustbgpd (gRPC) → Edge routers"), naming prefixd as the mitigation platform.

**Negative:**
- Still two processes and a gRPC hop per announcement (ADR 001's original trade-off, unchanged).
- `InjectionService.AddFlowSpec` / `DeleteFlowSpec` / `RibService.ListFlowSpecRoutes` are classified `explicitly_outside_v1` (`docs/reference/v1-stable-surface.json:180`; `Config.flowspec` is `outside_v1` at `:152`). They are functional and documented, but carry no compatibility promise — only a 2-minor / 90-day deprecation floor.
- Coupling to rustbgpd's release cadence replaces coupling to GoBGP's.

**Mitigation:**
- Pin an exact rustbgpd version; treat its CHANGELOG as part of the upgrade checklist.
- Mirror `tests/integration_gobgp.rs` against a pinned rustbgpd container (announce visible in `rbgp rib flowspec`, withdraw clears it, TTL expiry reconciles).
- Re-run the Juniper cJunosEvolved and FRR interop receipts, then Arista cEOS / Cisco XRd, before deleting the GoBGP path.
- If rustbgpd later publishes a supported embedding API, revisit this decision — the trait boundary means switching again is contained.

## Follow-ups

Tracked in the `prefixd` Linear project: LAN-1945 (this decision), LAN-1947 (`RustBgpdAnnouncer`), LAN-1948 (config, health JSON, docs, labs).
