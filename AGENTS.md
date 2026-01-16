# AGENTS.md - AI Agent Context for prefixd

This document provides context for AI agents working on prefixd.

## Project Overview

**prefixd** is a BGP FlowSpec routing policy daemon for automated DDoS mitigation. It receives attack events from detectors, applies policy-driven playbooks, and announces FlowSpec rules via GoBGP to enforcement points (Juniper, Arista, Cisco, Nokia routers).

## Architecture

```
Detector → HTTP API → Policy Engine → Guardrails → FlowSpec Manager → GoBGP → Routers
                                           ↑
                                   Reconciliation Loop
                                           ↓
                                     SQLite (state)
```

## Directory Structure

```
src/
├── api/           # HTTP handlers, auth, rate limiting
├── bgp/           # FlowSpecAnnouncer trait, GoBGP client, mock
├── config/        # Settings, Inventory, Playbooks (YAML parsing)
├── db/            # SQLite repository with sqlx
├── domain/        # Core types: AttackEvent, Mitigation, FlowSpecRule
├── guardrails/    # Validation, quotas, safelist protection
├── observability/ # Tracing, Prometheus metrics
├── policy/        # Policy engine, playbook evaluation
├── scheduler/     # Reconciliation loop, TTL expiry
├── error.rs       # PrefixdError enum with thiserror
├── state.rs       # Arc<AppState> with shutdown coordination
├── lib.rs         # Public module exports
└── main.rs        # CLI, daemon startup
```

## Key Design Decisions

1. **Rust 2024 edition** - Modern Rust with latest features
2. **sqlx** - Compile-time checked SQL queries
3. **axum** - Async HTTP framework
4. **tonic** - gRPC client for GoBGP
5. **Trait-based BGP abstraction** - `FlowSpecAnnouncer` with `GoBgpAnnouncer` and `MockAnnouncer`
6. **Fail-open** - If prefixd dies, mitigations expire via TTL (no permanent rules)

## Data Flow

1. **Event Ingestion** (`POST /v1/events`)
   - Validate input, check duplicates
   - Lookup IP context from inventory
   - Evaluate playbook for vector
   - Check guardrails (TTL, /32, quotas, safelist)
   - Create or extend mitigation
   - Announce via GoBGP (if not dry-run)

2. **Reconciliation Loop** (every 30s)
   - Find expired mitigations → withdraw
   - Compare desired (SQLite) vs actual (GoBGP RIB)
   - Re-announce missing rules

## Important Constraints

- **Destination prefix must be /32** - No broader prefixes allowed (blast radius)
- **Max 8 destination ports** - Router memory protection
- **TTL always required** - No permanent rules
- **Safelist protection** - Infrastructure IPs never mitigated
- **Source prefix matching disabled** - Too dangerous for MVP

## Testing

```bash
cargo test                    # Run all tests
cargo run -- --config ./configs  # Run with example configs
```

## Configuration Files

- `configs/prefixd.yaml` - Main daemon config
- `configs/inventory.yaml` - Customer/service/IP mapping
- `configs/playbooks.yaml` - Vector → action policies

## Current State (v0.2)

Completed:
- HTTP API with auth and rate limiting
- GoBGP gRPC client
- Policy engine with playbooks
- Guardrails and quotas
- SQLite state store
- Prometheus metrics
- Dry-run mode

## Next Up (v0.3)

- Escalation logic (police → discard)
- Improved event correlation
- Audit log file writer
- Alerting webhooks

## Code Conventions

- Use `thiserror` for error types
- Use `tracing` for structured logging
- Keep handlers thin, logic in domain/policy modules
- Prefer `Arc<AppState>` pattern for shared state
- All database queries via `Repository` struct

## Common Tasks

### Adding a new API endpoint
1. Add handler in `src/api/handlers.rs`
2. Add route in `src/api/routes.rs`
3. Add to protected or public routes as appropriate

### Adding a new metric
1. Define in `src/observability/metrics.rs` using `Lazy<CounterVec>` etc.
2. Add to `init_metrics()` function
3. Increment in relevant code paths

### Adding a new guardrail
1. Add error variant to `GuardrailError` in `src/error.rs`
2. Add validation method in `src/guardrails/mod.rs`
3. Call from `validate()` method

### Modifying FlowSpec NLRI
1. Update `build_flowspec_nlri()` in `src/bgp/gobgp.rs`
2. Add new FlowSpecComponent types as needed
3. Test against GoBGP in lab

## GoBGP Proto

Proto files are in `proto/` and compiled via `build.rs`. Generated code is in `target/debug/build/prefixd-*/out/apipb.rs`.

## CLI (prefixdctl)

Separate binary for controlling the daemon via API:

```bash
# Status and health
prefixdctl status
prefixdctl peers

# Mitigations
prefixdctl mitigations list
prefixdctl mitigations list --status active --customer cust_123
prefixdctl mitigations get <id>
prefixdctl mitigations withdraw <id> --reason "false positive" --operator jsmith

# Safelist
prefixdctl safelist list
prefixdctl safelist add 10.0.0.1/32 --reason "router loopback" --operator jsmith
prefixdctl safelist remove 10.0.0.1/32

# Options
prefixdctl -a http://localhost:8080  # API endpoint
prefixdctl -t <token>                 # Bearer token
prefixdctl -f json                    # JSON output

# Configuration
prefixdctl reload                     # Hot-reload inventory & playbooks
```

## Environment Variables

- `PREFIXD_API` - API endpoint for prefixdctl (default: http://127.0.0.1:8080)
- `PREFIXD_API_TOKEN` - Bearer token for API auth (when mode=bearer)
- `RUST_LOG` - Log level override (e.g., `RUST_LOG=debug`)
- `USER` - Default operator ID for CLI commands
