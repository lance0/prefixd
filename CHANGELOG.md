# Changelog

All notable changes to prefixd will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Comprehensive unit test suite (84 tests total)
  - Guardrails tests: prefix validation, TTL, port count, IPv6 detection (18 tests)
  - BGP/GoBGP tests: NLRI construction, path attributes, RFC constants (16 tests)
  - Repository tests: CRUD, queries, pagination, safelist, multi-POP (18 tests)
  - Policy engine tests: evaluation, port intersection, protocols, TTL (13 tests)
- Next.js frontend scaffolding (`frontend/`)
  - Dashboard layout with sidebar navigation
  - Mitigations page (mock data)
  - Events page (mock data)
  - Audit log page (mock data)
  - Dark mode support

### Fixed

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
