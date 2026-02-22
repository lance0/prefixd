# AGENTS.md - AI Agent Context for prefixd

This document provides context for AI agents working on prefixd.

## Project Overview

**prefixd** is a BGP FlowSpec routing policy daemon for automated DDoS mitigation. It receives attack events from detectors, applies policy-driven playbooks, and announces FlowSpec rules via GoBGP to enforcement points (Juniper, Arista, Cisco, Nokia routers).

## Architecture

```
                    ┌─────────────┐
                    │   nginx:80  │  ← single entrypoint
                    └──────┬──────┘
                     ╱            ╲
          ┌─────────┘              └──────────┐
          ▼                                   ▼
   dashboard:3000                      prefixd:8080
   (Next.js App Router)              (Rust/axum API)
                                          │
                          ┌───────────────┼───────────────┐
                          ▼               ▼               ▼
                   PostgreSQL:5432   GoBGP:50051    Prometheus:9090
                   (state store)    (FlowSpec BGP)  (metrics)
```

```
Detector → HTTP API → Policy Engine → Guardrails → FlowSpec Manager → GoBGP → Routers
                                           ↑
                                   Reconciliation Loop
                                           ↓
                                     PostgreSQL (state)
```

## Directory Structure

```
src/
├── alerting/          # Webhook alerting: Slack, Discord, Teams, Telegram, PagerDuty, OpsGenie, generic
├── api/
│   ├── handlers.rs    # All HTTP handlers (health, events, mitigations, config, safelist, operators, alerting)
│   ├── routes.rs      # Route definitions: public_routes(), session_routes(), api_routes(), common_layers()
│   ├── openapi.rs     # utoipa OpenAPI spec registration
│   └── metrics.rs     # HTTP request metrics middleware
├── auth/              # AuthBackend (axum-login), session + bearer hybrid auth
├── bgp/               # FlowSpecAnnouncer trait, GoBGP gRPC client, mock
├── config/            # Settings, Inventory, Playbooks (YAML parsing)
├── db/                # PostgreSQL repository with sqlx + MockRepository for testing
├── domain/            # Core types: AttackEvent, Mitigation, FlowSpecRule
├── guardrails/        # Validation, quotas, safelist protection
├── observability/     # Tracing, Prometheus metrics
├── policy/            # Policy engine, playbook evaluation
├── scheduler/         # Reconciliation loop, TTL expiry
├── error.rs           # PrefixdError enum with thiserror
├── state.rs           # Arc<AppState> with shutdown coordination, RwLock for inventory/playbooks
├── lib.rs             # Public module exports
├── main.rs            # CLI, daemon startup
└── bin/prefixdctl.rs  # CLI tool for controlling the daemon

frontend/
├── app/
│   ├── (dashboard)/           # Route group with RequireAuth + ErrorBoundary layout wrapper
│   │   ├── layout.tsx         # Auth guard + WebSocket + ErrorBoundary for all dashboard pages
│   │   ├── page.tsx           # Overview
│   │   ├── mitigations/       # Mitigations list with inline withdraw
│   │   ├── mitigations/[id]/  # Mitigation detail (full-page, timeline, customer context)
│   │   ├── mitigations/create/# Manual "Mitigate Now" form
│   │   ├── events/            # Event log
│   │   ├── inventory/         # Searchable customer/service/IP browser
│   │   ├── audit-log/         # Audit trail
│   │   ├── config/            # Settings (JSON) + Playbooks (cards) + hot-reload
│   │   └── admin/             # Tabbed: System Status, Safelist CRUD, User management
│   ├── login/                 # Login page (outside auth guard)
│   ├── globals.css            # Light + dark theme variables
│   └── layout.tsx             # Root layout with ThemeProvider + Toaster
├── components/
│   ├── dashboard/             # Sidebar, top-bar, BGP status, command palette, detail panels
│   ├── ui/                    # shadcn/ui components (button, card, dialog, alert-dialog, etc.)
│   ├── error-boundary.tsx     # React class ErrorBoundary with retry button
│   ├── websocket-provider.tsx # Centralized WebSocket context (SWR invalidation + toasts)
│   ├── require-auth.tsx       # Auth-mode-aware guard with deny-by-default
│   └── swr-provider.tsx       # SWR config with 401 retry suppression
├── hooks/
│   ├── use-api.ts             # SWR hooks for all endpoints
│   ├── use-auth.tsx           # AuthProvider with session expiry listener
│   └── use-permissions.ts     # Role-based permissions (deny-by-default, settled flag)
├── lib/
│   ├── api.ts                 # Fetch wrapper, all API functions, 401 debounce dispatch
│   └── mock-api-data.ts       # Mock data for development
├── __tests__/                 # Vitest tests
├── vitest.config.ts           # Vitest config (jsdom, react plugin, @ alias)
└── vitest.setup.ts            # jest-dom matchers

configs/                       # prefixd.yaml, inventory.yaml, playbooks.yaml, nginx.conf, gobgp.conf
docs/
├── api.md                     # Full API reference with examples
├── deployment.md              # Docker + nginx deployment guide
└── adr/                       # 15 Architecture Decision Records (001-015)
grafana/                       # Prometheus config, Grafana provisioning, dashboard JSON
tests/
└── integration.rs             # 12 integration tests (health, config, mitigations, events)
```

## Key Design Decisions

1. **Rust 2024 edition** - Modern Rust with latest features
2. **sqlx** - Compile-time checked SQL queries
3. **axum** - Async HTTP framework
4. **tonic** - gRPC client for GoBGP
5. **Trait-based BGP abstraction** - `FlowSpecAnnouncer` with `GoBgpAnnouncer` and `MockAnnouncer`
6. **Fail-open** - If prefixd dies, mitigations expire via TTL (no permanent rules)
7. **Allowlist config redaction** - Only explicitly safe fields exposed via API (ADR 014)
8. **Health endpoint split** - Public liveness vs authenticated detail (ADR 015)
9. **Nginx single-origin** - All traffic through port 80, no split-origin CORS issues (ADR 005)
10. **Route-group auth guard** - Next.js `(dashboard)/layout.tsx` wraps all protected pages
11. **Hybrid auth** - Session cookies (browser) + bearer tokens (CLI/detectors) on same endpoints

See `docs/adr/` for all 15 Architecture Decision Records.

## API Endpoints

### Public (no auth)
- `GET /v1/health` - Lightweight liveness check (`{status, version, auth_mode}`)
- `POST /v1/auth/login` - Session login
- `GET /metrics` - Prometheus metrics
- `GET /openapi.json` - OpenAPI spec

### Authenticated
- `GET /v1/health/detail` - Full operational status (BGP peers, DB, uptime, active mitigations)
- `POST /v1/events` - Ingest attack event
- `GET /v1/mitigations` - List mitigations (supports `?status=active&customer=cust_123`)
- `GET /v1/mitigations/{id}` - Get mitigation detail
- `POST /v1/mitigations/{id}/withdraw` - Withdraw mitigation
- `GET/POST /v1/safelist` - List/add safelist entries
- `DELETE /v1/safelist/{prefix}` - Remove safelist entry
- `GET /v1/config/settings` - Running config (allowlist-redacted)
- `GET /v1/config/inventory` - Customer/service/IP data
- `GET /v1/config/playbooks` - Playbook definitions
- `PUT /v1/config/playbooks` - Update playbooks (admin only, writes YAML + hot-reload)
- `POST /v1/config/reload` - Hot-reload inventory + playbooks
- `GET /v1/config/alerting` - Alerting config (secrets redacted)
- `PUT /v1/config/alerting` - Update alerting config (admin only, writes YAML + hot-reload)
- `POST /v1/config/alerting/test` - Send test alert to all destinations (admin only)
- `GET /v1/stats` - Global statistics
- `GET /v1/stats/timeseries` - Time-series data for charts
- `GET /v1/ip/{ip}/history` - IP history (events + mitigations + context)
- `GET /v1/pops` - Points of presence
- `GET /v1/audit` - Audit log
- `GET/POST /v1/operators` - User management (admin only)
- `DELETE /v1/operators/{id}` - Delete user (admin only)
- `PUT /v1/operators/{id}/password` - Change password (admin only)

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
   - Compare desired (PostgreSQL) vs actual (GoBGP RIB)
   - Re-announce missing rules

## Important Constraints

- **Destination prefix must be /32** - No broader prefixes allowed (blast radius)
- **Max 8 destination ports** - Router memory protection
- **TTL always required** - No permanent rules
- **Safelist protection** - Infrastructure IPs never mitigated
- **Source prefix matching disabled** - Too dangerous for MVP

## Testing

```bash
# Backend unit tests (93 tests)
cargo test

# All backend tests including integration (105 runnable: 93 unit + 12 integration; 14 ignored requiring GoBGP/Docker)
cargo test --features test-utils

# Lint
cargo fmt --check
cargo clippy -- -D warnings

# Frontend build
cd frontend && bun run build

# Frontend tests (Vitest + Testing Library)
cd frontend && bun run test          # single run
cd frontend && bun run test:watch    # watch mode

# Run locally
cargo run -- --config ./configs
```

## Configuration Files

- `configs/prefixd.yaml` - Main daemon config
- `configs/inventory.yaml` - Customer/service/IP mapping
- `configs/playbooks.yaml` - Vector → action policies
- `configs/nginx.conf` - Reverse proxy config
- `configs/gobgp.conf` - GoBGP BGP config

## Docker Compose

```bash
docker compose up -d          # Start full stack
docker compose build          # Rebuild after code changes
docker compose ps             # Check health
docker compose logs prefixd   # View daemon logs
```

Services: nginx (80), prefixd (8080), dashboard (3000), postgres (5432), gobgp (50051/179), prometheus (9091), grafana (3001)

## Current State (v0.9.1)

Completed:
- HTTP API with hybrid auth (session + bearer) and rate limiting
- GoBGP gRPC client with FlowSpec announce/withdraw
- Policy engine with playbook evaluation and escalation
- Guardrails, quotas, and safelist protection
- PostgreSQL state store with reconciliation loop
- Prometheus metrics + Grafana dashboards
- Next.js dashboard with real-time WebSocket updates and toast notifications
- Config/inventory read-only pages with allowlist redaction
- Safelist management and user management on admin page (tabbed layout)
- Mitigation detail full-page view with timeline and customer context
- Manual "Mitigate Now" form (POST /v1/events from dashboard)
- Inline withdraw button on mitigations table
- Light/dark mode with next-themes
- Nginx reverse proxy (single-origin deployment)
- ErrorBoundary wrapping all dashboard pages
- Cross-entity navigation (command palette → detail pages, event↔mitigation linking, audit log → mitigations, clickable stat cards)
- 15 Architecture Decision Records
- CLI tool (prefixdctl) for all API operations
- OpenAPI spec with utoipa annotations
- 93 backend unit tests + 12 integration tests (+ 14 ignored requiring GoBGP/Docker)
- Vitest + Testing Library frontend test infrastructure (25 tests)

## Code Conventions

- Use `thiserror` for error types
- Use `tracing` for structured logging
- Keep handlers thin, logic in domain/policy modules
- Prefer `Arc<AppState>` pattern for shared state
- All database queries via `Repository` trait (with `MockRepository` for tests)
- Frontend: shadcn/ui components, SWR for data fetching, Tailwind CSS with theme variables
- Route definitions: add to shared `api_routes()` in `routes.rs` (defined once, used by both production and test routers)
- Config redaction: allowlist approach — new fields hidden by default

## Common Tasks

### Adding a new API endpoint
1. Add handler in `src/api/handlers.rs`
2. Add route to the appropriate shared function in `src/api/routes.rs` (`public_routes()`, `session_routes()`, or `api_routes()`)
3. Add `#[utoipa::path]` annotation and register in `src/api/openapi.rs`
4. Add integration test in `tests/integration.rs`
5. Document in `docs/api.md`

### Adding a new frontend page
1. Create `frontend/app/(dashboard)/your-page/page.tsx` (auto-guarded by route group)
2. Add SWR hook in `frontend/hooks/use-api.ts`
3. Add API function in `frontend/lib/api.ts`
4. Add to sidebar nav in `frontend/components/dashboard/sidebar.tsx`
5. Add to command palette in `frontend/components/dashboard/command-palette.tsx`

### Adding a frontend test
1. Create `frontend/__tests__/your-test.test.ts` (pure logic) or `.test.tsx` (component)
2. Use `vitest` globals (`describe`, `it`, `expect`) and `@testing-library/react` for components
3. Run with `cd frontend && bun run test`

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
prefixdctl -a http://localhost       # API endpoint
prefixdctl -t <token>                 # Bearer token
prefixdctl -f json                    # JSON output

# Configuration
prefixdctl reload                     # Hot-reload inventory & playbooks
```

## Environment Variables

- `PREFIXD_API` - API endpoint for prefixdctl (default: http://127.0.0.1)
- `PREFIXD_API_TOKEN` - Bearer token for API auth (when mode=bearer)
- `RUST_LOG` - Log level override (e.g., `RUST_LOG=debug`)
- `USER` - Default operator ID for CLI commands
- `DATABASE_URL` - PostgreSQL connection string
- `POSTGRES_PASSWORD` - PostgreSQL password (docker-compose)
