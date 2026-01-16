# Changelog

All notable changes to prefixd will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
