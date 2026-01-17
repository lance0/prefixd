# Changelog

All notable changes to prefixd will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **WebSocket Real-Time Updates**
  - WebSocket endpoint at `/v1/ws/feed` for live mitigation/event updates
  - Message types: MitigationCreated, MitigationUpdated, MitigationExpired, MitigationWithdrawn, EventIngested, ResyncRequired
  - Broadcast channel integration in handlers and reconciliation loop
  - Lag detection with ResyncRequired message for client cache invalidation

- **Session-Based Authentication**
  - Operators table with argon2 password hashing
  - PostgreSQL session store via tower-sessions-sqlx-store
  - Login/logout/me endpoints (`/v1/auth/login`, `/v1/auth/logout`, `/v1/auth/me`)
  - Hybrid auth model: session cookies for browser, bearer tokens for API/CLI
  - `prefixdctl operators create` command for seeding operators

- **Frontend Authentication & Real-Time**
  - Login page with form validation and error handling
  - `useAuth` hook with AuthProvider context (memoized per React best practices)
  - `useWebSocket` hook with reconnection, SWR cache invalidation
  - `RequireAuth` component for protected routes
  - `ConnectionStatus` indicator in top bar
  - `UserMenu` dropdown with logout

- **Observability**
  - `prefixd_config_reload_total` counter metric (success/error)
  - `prefixd_escalations_total` counter metric
  - `prefixd_db_row_parse_errors_total` counter metric (tracks corrupted DB rows)
  - HTTP metrics via middleware:
    - `prefixd_http_requests_total{method,route,status_class}` counter
    - `prefixd_http_request_duration_seconds{method,route,status_class}` histogram
    - `prefixd_http_in_flight_requests{method,route}` gauge
  - Database connectivity status in `/v1/health` endpoint
  - GoBGP connectivity status in `/v1/health` endpoint (now structured: `{status, error}`)
  - Health endpoint now returns `"degraded"` status on DB or GoBGP failure
  - Warning logs for FlowSpec path parse failures in reconciliation

- **Security**
  - Request body size limit (1MB) via tower-http
  - Fix SQL injection in `list_mitigations` queries (now uses parameterized queries)

- **Reliability**
  - GoBGP gRPC timeout handling (10s connect, 30s request)
  - GoBGP retry with exponential backoff (3 retries, 100ms-400ms)

- **API Validation**
  - Reject unknown protocol values (was silently converting to None)
  - Require `rate_bps` for `police` action type
  - Improved error messages with valid options listed

- **CI/CD**
  - GitHub Actions workflow (`.github/workflows/ci.yml`)
    - Test job (unit + integration with testcontainers)
    - Lint job (cargo fmt, clippy)
    - Build job (release binary artifact)
    - Docker job (build and push to ghcr.io)
    - Security audit job (cargo-audit)

- **Testing**
  - Integration tests with testcontainers (8 tests)
    - Full event → mitigation flow
    - Mitigation withdrawal via API
    - Duplicate event TTL extension
    - Pagination queries
    - Safelist blocking
    - Migration verification
    - TTL expiry via reconciliation
    - Configuration hot-reload (inventory + playbooks)

- **DevOps**
  - Dependabot configuration for Cargo, GitHub Actions, and npm
  - Pre-commit hooks configuration (fmt, clippy, test)

- **Guardrails**
  - Max TTL enforcement via `guardrails.max_ttl_seconds` config
  - Min TTL enforcement via `guardrails.min_ttl_seconds` config

### Fixed

- **Startup validation** - `auth.mode=bearer` without token now fails fast at startup (was returning 500 on every request)

- IPv6 prefix validation uses proper `IpAddr` parsing (was using contains(':') heuristic)
- `compute_scope_hash()` now deduplicates ports before hashing for consistency
- Bearer token cached at startup (was reading env var on every request)
- `Mitigation::from_row` now returns `Result` with error logging (was silently defaulting on parse failures)
- List queries now skip corrupted rows instead of failing entirely (with metric + log)
- Guardrails TTL bounds now fall back to `timers.min/max_ttl_seconds` if not set in guardrails config

- IPv6 support in `is_safelisted()` - now handles both IPv4 and IPv6 prefixes
- `is_safelisted()` performance - uses PostgreSQL inet operators instead of loading all entries

### Changed

- **Pagination**
  - Added `MAX_PAGE_LIMIT` (1000) - requests for larger pages are clamped
  - `list_events` now returns `EventsListResponse` with `count` (consistency with mitigations)

- **API Response** (breaking for clients parsing `total`)
  - Renamed `total` to `count` in `MitigationsListResponse`
  - Clarifies this is page size, not total count

- **Health Response** (breaking for clients parsing `gobgp` as string)
  - `gobgp` field now returns `{status: string, error?: string}` object
  - `database` field unchanged (string) for backward compatibility

- **Code Quality**
  - Consolidated duplicate route registrations in `routes.rs`

- **PostgreSQL-only storage** (breaking change)
  - Removed SQLite support entirely (~800 lines removed)
  - Simplified `StorageConfig`: `driver` removed, `path` → `connection_string`
  - Extracted `RepositoryTrait` for testability
  - Added `MockRepository` for fast unit tests
  - Tests now use `MockRepository` instead of SQLite in-memory

### Removed

- SQLite storage driver and all related code
- `StorageDriver` enum from configuration
- `storage.driver` config option

---

## [0.6.0] - 2026-01-17

### Added

- **Security & Authentication**
  - mTLS authentication with client certificate verification (rustls 0.23)
  - Security headers: X-Content-Type-Options, X-Frame-Options, Cache-Control
  - 5 auth integration tests (bearer flows, security headers validation)

- **Documentation**
  - `docs/configuration.md` - Complete YAML reference for all config options
  - `docs/deployment.md` - Docker, bare metal, GoBGP, router config, mTLS setup
  - `docs/troubleshooting.md` - Operational runbook with common issues
  - `docs/benchmarks.md` - Performance analysis with optimization recommendations

- **Benchmark Suite** (criterion)
  - Inventory lookup benchmarks (hit/miss/is_owned)
  - Database operation benchmarks (insert/get/list/count)
  - Serialization benchmarks (JSON serialize/deserialize)
  - Scaling benchmarks (DB list, inventory lookup by size)
  - Results: ~6K events/sec throughput, sub-ms API queries

- **Frontend Polish**
  - Live activity feed (replaces mock data with real API)
  - Config page with system status, BGP session, quotas, safelist viewer
  - Loading states with spinners, error states with icons
  - Empty state handling throughout dashboard

- Comprehensive unit test suite (84 tests total)
  - Guardrails tests: prefix validation, TTL, port count, IPv6 detection (18 tests)
  - BGP/GoBGP tests: NLRI construction, path attributes, RFC constants (16 tests)
  - Repository tests: CRUD, queries, pagination, safelist, multi-POP (18 tests)
  - Policy engine tests: evaluation, port intersection, protocols, TTL (13 tests)
- Next.js frontend dashboard (`frontend/`)
  - Dashboard overview with live stats, BGP status, quota gauges
  - Mitigations list with filtering, sorting, pagination (live API)
  - Events list with filtering, sorting, pagination (live API)
  - Audit log viewer with filtering (live API)
  - Dark mode support, keyboard shortcuts, command palette
  - SWR for data fetching with 5s refresh interval
  - Follows Vercel React best practices (deferred analytics, parallel fetching)
- New API endpoints
  - `GET /v1/events` - list events with pagination
  - `GET /v1/audit` - list audit log entries with pagination
- Audit log database storage (in addition to file-based logging)
- Docker support for frontend
  - `frontend/Dockerfile` using oven/bun image
  - Dashboard service in docker-compose.yml (port 3000)
- Bun package manager for frontend (faster installs)

### Changed

- **2026 Stable Dependencies**
  - axum 0.7 → 0.8, tower 0.4 → 0.5, tower-http 0.5 → 0.6
  - tonic 0.11 → 0.14, prost 0.12 → 0.14
  - sqlx 0.7 → 0.8, reqwest 0.11 → 0.12
  - utoipa 4 → 5, prometheus 0.13 → 0.14, thiserror 1 → 2

### Fixed

- Security vulnerabilities: sqlx 0.7.4 (RUSTSEC-2024-0363), protobuf 2.28.0
- `list_mitigations_all_pops_sqlite` query using wrong column names

## [0.5.0] - 2026-01-16

### Added

- PostgreSQL backend support
  - Runtime-configurable storage driver (`storage.driver: postgres`)
  - PostgreSQL-specific migrations
  - Connection string support (`storage.path: "postgres://..."`)
- Docker deployment
  - Multi-stage Dockerfile for optimized builds
  - docker-compose.yml with prefixd, postgres, gobgp services
  - `configs/prefixd-postgres.yaml` example config
  - `configs/gobgp.conf` for FlowSpec BGP sidecar
  - `.dockerignore` for efficient builds

### Changed

- Repository refactored to support both SQLite and PostgreSQL
- `db::init_pool_from_config()` for runtime driver selection

## [0.4.0] - 2026-01-16

### Added

- `prefixdctl` CLI binary for controlling the daemon
  - `prefixdctl status` - show daemon health and BGP sessions
  - `prefixdctl mitigations list/get/withdraw` - manage mitigations
  - `prefixdctl safelist list/add/remove` - manage safelist
  - `prefixdctl peers` - show BGP peer status
  - `prefixdctl reload` - hot-reload configuration
  - Table and JSON output formats
  - Environment variable support (PREFIXD_API, PREFIXD_API_TOKEN)
- Configuration hot-reload via `POST /v1/config/reload`
  - Reloads inventory.yaml and playbooks.yaml without restart
  - Validates config before applying (fail-safe)
- Graceful shutdown improvements
  - Configurable drain timeout (default 30s)
  - Announcement preservation option (mitigations not withdrawn on shutdown)
  - Shutdown state tracking (new events return 503)
  - Enhanced shutdown logging with mitigation counts

### Changed

- AppState now uses RwLock for inventory and playbooks (hot-reload support)
- Event ingestion checks shutdown state before processing

## [0.3.0] - 2026-01-16

### Added

- Escalation logic for police → discard transitions
  - Persistence tracking (configurable min duration)
  - Confidence threshold checking
  - Policy profile support (strict blocks escalation)
  - Max escalated duration guard
- Event correlation engine
  - Exact scope matching for TTL extension
  - Port relationship detection (superset/subset/overlap/disjoint)
  - Smart action decisions (replace, keep, create parallel)
- Audit log writer (JSON Lines format)
  - Event ingestion logging
  - Mitigation lifecycle logging
  - Safelist change logging
  - Guardrail rejection logging
- Alerting webhooks
  - Slack integration with colored attachments
  - PagerDuty Events API v2 integration
  - Generic webhook support with custom headers
  - Alert severity levels (info, warning, critical)
- AGENTS.md for AI agent context

### Changed

- Policy module now exports escalation and correlation submodules
- Observability module includes audit and alerting

## [0.2.0] - 2026-01-16

### Added

- GoBGP gRPC client implementation
  - Full FlowSpec NLRI construction (destination prefix, protocol, ports)
  - Traffic-rate extended community for police/discard actions
  - AddPath/DeletePath for announce/withdraw
  - ListPath for active routes
  - ListPeer for session status
- Bearer token authentication middleware
  - Configurable via `PREFIXD_API_TOKEN` environment variable
  - Constant-time token comparison
- Token bucket rate limiter for API endpoints
- Prometheus metrics endpoint (`/metrics`)
  - `prefixd_events_ingested_total`
  - `prefixd_events_rejected_total`
  - `prefixd_mitigations_active`
  - `prefixd_mitigations_created_total`
  - `prefixd_mitigations_expired_total`
  - `prefixd_mitigations_withdrawn_total`
  - `prefixd_announcements_total`
  - `prefixd_announcements_latency_seconds`
  - `prefixd_bgp_session_up`
  - `prefixd_guardrail_rejections_total`
  - `prefixd_reconciliation_runs_total`

### Changed

- Health and metrics endpoints now public (no auth required)
- Protected routes require authentication when bearer mode enabled

## [0.1.0] - 2026-01-16

### Added

- Initial release of prefixd BGP FlowSpec routing policy daemon
- HTTP API for attack event ingestion (`POST /v1/events`)
- Mitigation management endpoints (`GET/POST /v1/mitigations`, withdraw)
- Safelist management (`GET/POST/DELETE /v1/safelist`)
- Health endpoint (`GET /v1/health`)
- Policy engine with YAML playbook configuration
- Support for attack vectors: `udp_flood`, `syn_flood`, `ack_flood`, `icmp_flood`, `unknown`
- Guardrails system:
  - TTL required on all mitigations
  - /32 destination prefix enforcement
  - Customer ownership validation
  - Safelist protection
  - Port count limits (max 8)
  - Quota enforcement (per-customer, per-POP, global)
- Mitigation lifecycle management:
  - States: pending, active, escalated, expired, withdrawn, rejected
  - Automatic TTL expiry
  - Scope-based deduplication
  - TTL extension on repeated events
- SQLite state store with sqlx (compile-time checked queries)
- FlowSpecAnnouncer trait abstraction:
  - MockAnnouncer for testing and dry-run mode
  - GoBgpAnnouncer stub for production (gRPC client pending)
- Reconciliation loop:
  - Periodic TTL expiry checks
  - Desired vs actual state synchronization
  - Re-announcement of missing rules
- Configuration system:
  - `prefixd.yaml` - daemon settings
  - `inventory.yaml` - customer/service/asset mapping
  - `playbooks.yaml` - vector-to-action policies
- Structured logging with tracing (JSON or pretty format)
- Dry-run mode for safe rollout
- Integration and unit tests

### Security

- No secrets logged or exposed in API responses
- Safelist prevents mitigation of protected infrastructure
- Guardrails block overly broad mitigations

[Unreleased]: https://github.com/lance0/prefixd/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lance0/prefixd/releases/tag/v0.1.0
