# Changelog

All notable changes to prefixd will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Inline withdraw button on mitigations table** - XCircle button on active/escalated rows with confirmation dialog
  - Optional reason field, permission-gated (operator + admin only)
  - Tooltips on view and withdraw action buttons
- **Per-peer BGP session detail on admin page** - Shows each peer name and session state (established/down) instead of a single boolean

### Fixed

- **Admin health status badge** - Was checking for `"healthy"` but API returns `"ok"`, so the badge always showed destructive red
- **Dark mode hover on admin reload button** - Added explicit dark mode hover classes for proper contrast

## [0.8.3] - 2026-02-18

### Added

- **Config Page** - Read-only view of running daemon configuration
  - Settings tab with allowlist-redacted JSON view (sensitive fields never exposed)
  - Playbooks tab with escalation step visualization (action, rate, TTL, confidence thresholds)
  - Hot-reload button (triggers `POST /v1/config/reload`) with auto-clearing feedback
  - Gated behind `canReloadConfig` permission for admin users
- **Inventory Page** - Searchable customer/service/IP asset browser
  - Expandable customer cards with policy profile badges
  - Service listings with allowed port display (TCP/UDP)
  - Search covers customer ID, name, policy profile, service, IP, role, and port numbers
  - Stats bar showing total customers, services, and IPs
- **`GET /v1/health/detail`** - Authenticated health endpoint with full operational data
  - BGP session states, database status, GoBGP connectivity, uptime, active mitigations
  - Replaces the old public health endpoint for operational monitoring
- **`GET /v1/config/settings`** - Running config with allowlist redaction
- **`GET /v1/config/inventory`** - Customer/service/IP data with load timestamps
- **`GET /v1/config/playbooks`** - Playbook definitions with load timestamps
- **Auth-disabled indicator** - Sidebar shows "Auth disabled" badge when running with `auth: none`
- **Session expiry handling** - 401 responses trigger automatic redirect to login page
  - Debounced `prefixd:auth-expired` event (2s window) prevents redirect storms
  - SWR retries suppressed on 401 to avoid noisy retry loops

### Changed

- **Route guard architecture** - Auth guard moved from `DashboardLayout` component to `app/(dashboard)/layout.tsx` route group
  - All dashboard pages automatically protected; new pages added to the group are guarded by default
  - Login page remains outside the guard at `app/login/page.tsx`
- **Public health endpoint slimmed** - `GET /v1/health` now returns only `{status, version, auth_mode}`
  - No database or GoBGP calls (lightweight liveness check)
  - Reduces unauthenticated attack surface
- **Settings redaction switched to allowlist** - Only explicitly safe fields are exposed
  - Previously used denylist (new fields leaked by default)
  - Omits: TLS paths, LDAP/RADIUS configs, bearer token env vars, BGP passwords, gRPC endpoints, router ID, audit log path, safelist prefixes
- **`loaded_at` timestamps are now accurate** - Settings shows startup time, inventory/playbooks show actual load/reload time
  - Previously showed request time (`Utc::now()`) which was misleading
- **Login page redirects** - Already-authenticated users and auth:none users redirected to `/` instead of showing login form
- **prefixdctl** - `status` and `peers` commands now use `/v1/health/detail`
- **RwLock guards dropped early** - Inventory and playbooks handlers clone data and release locks before building JSON response
- **Route definitions deduplicated** - `create_router()` and `create_test_router()` now share `public_routes()`, `session_routes()`, `api_routes()`, and `common_layers()` helpers (eliminates ~80 lines of duplication)
- **OpenAPI spec updated** - All new endpoints (`health_detail`, `config/settings`, `config/inventory`, `config/playbooks`) registered with utoipa annotations and `PublicHealthResponse` schema
- **API documentation** - `docs/api.md` updated with config endpoint documentation, example payloads, and health endpoint migration note
- **Integration test coverage** - 4 new tests: `health_detail` (validates full operational response), `config_settings` (verifies allowlist redaction of sensitive fields), `config_inventory`, `config_playbooks` (12 integration tests total, up from 8)

### Security

- Allowlist redaction prevents accidental exposure of new sensitive config fields
- Public health endpoint no longer exposes BGP peer IPs, database status, or mitigation counts
- Deny-by-default permission model: no permissions granted until both auth and health state resolve
- Frontend permissions derived from backend `auth_mode` field (not inferred from missing session)

## [0.8.2] - 2026-02-18

### Fixed

- **Dashboard BGP Status** - Health indicator now checks actual BGP peer session state (`established`) instead of just GoBGP gRPC connectivity (contributed by @bswinnerton)
- **Dashboard POP Selector** - POP dropdown in TopBar now loads dynamically from the backend API (contributed by @bswinnerton)
  - Replaced hardcoded POP list with `usePops()` and `useHealth()` hooks
  - Current POP from health endpoint used as default selection
- **`GET /v1/pops` Endpoint** - Current instance POP now always included in response (contributed by @bswinnerton)
  - Newly deployed POPs with no mitigations are no longer invisible to the API
- **Lab Setup** - Fixed unreliable lab networking and stale instructions
  - FRR lab now assigns deterministic IP to GoBGP (`--ip 172.30.30.10`)
  - Fixed FRR bgpd.conf peer address to match
  - Fixed stale `gobgp neighbor add` comment in cJunos lab (neighbor is pre-configured)
  - Removed orphaned `gobgp-cjunos.conf` (wrong AS/IPs, not referenced)
  - Fixed vJunos comment: works on AMD bare metal too, issue is nested virt not CPU vendor

### Added

- **Juniper cJunosEvolved FlowSpec Lab** - End-to-end verified with real Junos router
  - cJunosEvolved PTX10002-36QDD (Junos Evolved 25.4R1.13-EVO) containerlab topology
  - Full lifecycle tested: event ingestion → policy engine → GoBGP → Juniper inetflow.0
  - FlowSpec discard, rate-limit (police), multi-port rules, and TTL-based withdrawal confirmed
  - cJunos peers directly with prefixd docker-compose GoBGP (no separate lab GoBGP)
  - Documented vendor quirks: FlowSpec-only AFI-SAFI required, FXP0ADDR token, BGP license warning
  - Updated lab/README.md with cJunos quick start and troubleshooting
  - Added cJunosEvolved neighbor config to configs/gobgp.conf
- **Lab Test Script** - `lab/test-flowspec.sh` for automated end-to-end FlowSpec verification
  - Checks prefixd health, GoBGP, BGP neighbors, sends test event, verifies RIB
  - Optional `--withdraw` flag to test full announce/withdraw lifecycle
- **WebSocket Runtime URL** - WS connection now derived from `window.location` at runtime
  - No build-time env var needed; works behind any reverse proxy (nginx, caddy, etc.)
  - Removed `NEXT_PUBLIC_PREFIXD_WS` build arg from Dockerfile
- **Favicon** - Replaced Vercel placeholder with prefixd shield icon (dark/light mode PNGs + SVG)
- **Light/Dark Mode Toggle** - Dashboard now supports light mode with a theme toggle in the top bar
  - Uses `next-themes` with system preference detection
  - Defaults to dark mode, persists user preference
- **Nginx Reverse Proxy** - Single-origin deployment via nginx in docker-compose
  - All traffic (API, WebSocket, dashboard) served through port 80
  - No build-time URL configuration needed
  - WebSocket upgrade handled transparently
- **Grafana Dashboards** - Provisioned Grafana and Prometheus in docker-compose
  - Operations dashboard: active mitigations, BGP sessions, HTTP latency, reconciliation
  - Security dashboard: events by source/vector, guardrail rejections, escalations
  - Auto-provisioned datasource and dashboards on startup

### Changed

- Lab documentation rewritten to reflect cJunos as recommended Juniper test option
- vJunos-router documented as bare-metal only (cannot run in VMs per Juniper docs)
- Nokia SR Linux confirmed as lacking FlowSpec support (SR OS only)
- Removed Vercel Analytics (`@vercel/analytics`) - self-hosted tool shouldn't phone home
- Removed duplicate lowercase PR template (case collision on macOS/Windows)
- Docker Compose now uses nginx as single entrypoint (port 80) instead of exposing individual service ports
- CI security audit switched from manual `cargo-audit` install to `actions-rust-lang/audit@v1` (3 min faster)
- CORS origin is now configurable via `cors_origin` in `prefixd.yaml` (omit when behind a reverse proxy)
- Removed hardcoded `localhost:3000` CORS origin
- Architecture Decision Records (ADRs) added to `docs/adr/`

### Security

- Fixed `bytes` integer overflow in `BytesMut::reserve` (RUSTSEC-2026-0007, updated 1.11.0 → 1.11.1)
- Fixed `time` crate DoS via stack exhaustion (RUSTSEC-2026-0009, updated 0.3.45 → 0.3.47)

## [0.8.1] - 2026-02-01

### Fixed

- **Frontend API Proxy** - Dashboard now works on remote servers without hardcoded URLs
  - Added `/api/prefixd/[...path]` Next.js API route to proxy requests to backend
  - Removed `NEXT_PUBLIC_PREFIXD_API` build-time env var (was baked into bundle)
  - Added `PREFIXD_API` server-side env var for backend URL
  - Browser only talks to dashboard on port 3000, never directly to API

- **Session Table Schema** - Fixed `tower_sessions.session` table creation
  - Migration now creates correct schema/table name for `tower-sessions-sqlx-store`
  - Users no longer need to manually create the session table

- **Bun Lockfile** - Removed `--frozen-lockfile` from frontend Dockerfile
  - Fixes build failures on systems with different bun versions

- **Security** - Fixed Next.js DoS vulnerability via Image Optimizer (npm audit fix)

### Changed

- Removed obsolete `version: '3.8'` from docker-compose.yml
- Updated dependencies: tonic 0.14.3, clap 4.5.56, Radix UI components

## [0.8.0] - 2026-01-28

### Added

- **Three-Role RBAC System**
  - `viewer` role: read-only access to dashboard and API
  - `operator` role: can withdraw mitigations
  - `admin` role: full access including user management
  - `require_role()` RBAC helper with hierarchical permission checks
  - Operator CRUD API: `GET/POST /v1/operators`, `DELETE /v1/operators/{id}`, `PUT /v1/operators/{id}/password`
  - `AuthMode::Credentials` for session-based authentication
  - LDAP config placeholder struct for future implementation

- **User Management UI**
  - Admin page User Management section (admin only)
  - Create operator form with username, password, role selection
  - Delete operator with confirmation dialog (prevents self-delete)
  - Change password dialog (admin can change any, users can change own)
  - Role badges with color coding (admin=red, operator=blue, viewer=gray)
  - `usePermissions()` hook for frontend role checks
  - Admin nav link hidden for non-admin users
  - Withdraw button hidden for viewers in mitigation detail panel

- **Unified Detector Events API**
  - `POST /v1/events` now accepts `action` field: `"ban"` (default) or `"unban"`
  - Unban events find original event by `external_event_id` and withdraw mitigation
  - `raw_details` JSONB field for storing forensic data from detectors
  - Deterministic withdrawal via event correlation (no guessing by IP)

- **FastNetMon Integration**
  - `scripts/prefixd-fastnetmon.sh` notify script for FastNetMon Community
  - Computes stable `event_id` for idempotency and ban/unban matching
  - Auto-detects vector from attack details (UDP/SYN/ACK/ICMP)
  - `docs/detectors/fastnetmon.md` setup guide

- **API/Frontend Contract Fixes**
  - Health endpoint now returns `version`, `pop`, `uptime_seconds`
  - mTLS auth mode now works correctly (was returning 401)
  - Fixed `operator_id` payload names in withdraw/safelist API calls

- **Frontend Animations**
  - Detail panels slide in from right (150ms, ease-out)
  - Activity feed items with staggered entrance
  - Status badge pulse animation on active items
  - BGP status breathing animation when session UP
  - All animations respect `prefers-reduced-motion`
  - Custom webkit scrollbars matching theme

- **FRR FlowSpec Lab**
  - Containerlab topology with FRR 10.3.1 as FlowSpec receiver
  - Works on any Linux host (no nested virtualization required)
  - Full end-to-end testing: event ingestion → policy → GoBGP → FRR
  - Documented Juniper labs for Intel VMX users

- **GoBGP Connection Fix**
  - Call `connect()` on GoBGP announcer at startup
  - Fixed BGP showing "not connected" in dashboard

- **Docker Compose Integration**
  - prefixd now connects to GoBGP and PostgreSQL via service names
  - BGP mode changed from `mock` to `sidecar` for real FlowSpec

### Fixed

- `confidence` field type mismatch: changed from `f64` to `f32` to match PostgreSQL `REAL`
- Events API was returning 500 due to sqlx type deserialization error

### Changed

- Default mode changed to `enforced` for lab testing (was `dry-run`)
- Removed dual-router lab configs for simplicity
- Updated lab README with Intel VMX requirements for Juniper

---

## [0.7.0] - 2026-01-18

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
  - Hybrid auth on all API routes (session OR bearer token)
  - Secure cookies configurable based on TLS presence

- **CORS Support**
  - CORS headers for dashboard cross-origin requests
  - Credentials support for session cookies

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

- **Frontend API Integration**
  - Fix API response unwrapping (mitigations/events return `{items, count}` wrapper)
  - Fix Stats type to match backend (`total_active` instead of `active_mitigations`)
  - Fix HealthResponse type to match backend (structured `bgp_sessions`, `gobgp` object)
  - Fix PopInfo type (`{pop, active_mitigations}` objects instead of strings)
  - Fix SWR cache invalidation keys in WebSocket hook
  - Fix status filter query param (comma-separated instead of repeated)

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
