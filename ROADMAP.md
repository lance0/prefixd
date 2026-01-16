# Roadmap

## v0.1 - MVP (Current)

- [x] HTTP API with event ingestion
- [x] Policy engine with YAML playbooks
- [x] Guardrails (TTL, /32, quotas, safelist)
- [x] SQLite state store
- [x] MockAnnouncer for testing
- [x] Reconciliation loop
- [x] Dry-run mode
- [x] Structured logging

## v0.2 - Production BGP

- [ ] GoBGP gRPC client implementation
  - [ ] Generate protos from gobgp/api
  - [ ] Implement `announce()` with FlowSpec NLRI construction
  - [ ] Implement `withdraw()` with exact NLRI matching
  - [ ] Implement `list_active()` for RIB queries
  - [ ] Session status monitoring
- [ ] Bearer token authentication middleware
- [ ] mTLS authentication option
- [ ] API rate limiting (tower middleware)
- [ ] Prometheus metrics endpoint
  - [ ] `prefixd_events_ingested_total`
  - [ ] `prefixd_mitigations_active`
  - [ ] `prefixd_announcements_total`
  - [ ] `prefixd_bgp_session_up`
  - [ ] `prefixd_guardrail_rejections_total`

## v0.3 - Escalation & Correlation

- [ ] Escalation logic (police → discard)
  - [ ] Persistence tracking
  - [ ] Confidence thresholds
  - [ ] Policy profile support (strict/normal/relaxed)
- [ ] Improved event correlation
  - [ ] Port superset/subset handling
  - [ ] Parallel mitigation for disjoint ports
- [ ] Audit log file writer (JSON Lines)
- [ ] Alerting webhooks (PagerDuty, Slack)

## v0.4 - Operational Tooling

- [ ] CLI subcommands
  - [ ] `prefixd status` - show active mitigations
  - [ ] `prefixd withdraw <id>` - manual withdrawal
  - [ ] `prefixd safelist add/remove`
  - [ ] `prefixd peers` - BGP session status
- [ ] Read-only web dashboard
- [ ] Configuration hot-reload (inventory, playbooks)
- [ ] Graceful shutdown with announcement preservation

## v1.0 - Production Ready

- [ ] PostgreSQL backend option
- [ ] Multi-POP coordination
- [ ] IPv6 FlowSpec support
- [ ] API versioning and stability guarantees
- [ ] Comprehensive documentation
- [ ] Performance benchmarks
- [ ] Security audit

## v2.0+ - Advanced Features

- [ ] Redirect/diversion actions (redirect-to-IP, redirect-to-VRF)
- [ ] Scrubber integration
- [ ] Packet length matching
- [ ] TCP flags matching
- [ ] Fragment matching
- [ ] NetBox integration for inventory
- [ ] Advanced correlation with ML-assisted confidence
- [ ] Multi-vendor support (beyond Juniper)

---

## Non-Goals

These are explicitly out of scope:

- Inline packet scrubbing
- L7/WAF analysis
- FlowSpec "match everything" rules (blocked by guardrails)
- Tbps-scale scrubbing without upstream support
- Competing with commercial DDoS platforms (Arbor, Corero)
