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

## v0.2 - Production BGP (Done)

- [x] GoBGP gRPC client implementation
  - [x] Generate protos from gobgp/api
  - [x] Implement `announce()` with FlowSpec NLRI construction
  - [x] Implement `withdraw()` with exact NLRI matching
  - [x] Implement `list_active()` for RIB queries
  - [x] Session status monitoring
- [x] Bearer token authentication middleware
- [ ] mTLS authentication option
- [x] API rate limiting (token bucket)
- [x] Prometheus metrics endpoint
  - [x] `prefixd_events_ingested_total`
  - [x] `prefixd_mitigations_active`
  - [x] `prefixd_announcements_total`
  - [x] `prefixd_bgp_session_up`
  - [x] `prefixd_guardrail_rejections_total`

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

## v1.5 - Multi-Vendor Support

- [ ] Vendor capability profiles
  - [ ] Define per-vendor match/action support matrix
  - [ ] Graceful degradation for unsupported features
- [ ] Arista EOS support
  - [ ] Validation with EOS 4.20+
  - [ ] Reference import policy documentation
- [ ] Cisco IOS-XR support
  - [ ] Validation with XR 6.x/7.x
  - [ ] Reference `flowspec` address-family config
- [ ] Nokia SR OS support
  - [ ] Validation with SR OS 19+
  - [ ] Reference policy documentation
- [ ] FRR support (receive-only enforcement)
  - [ ] iptables/nftables integration for Linux enforcement
  - [ ] Alternative: XDP/eBPF enforcement
- [ ] Vendor-specific guardrails (ASIC limits, action support)

## v2.0+ - Advanced Features

- [ ] Redirect/diversion actions (redirect-to-IP, redirect-to-VRF)
- [ ] Scrubber integration
- [ ] Packet length matching
- [ ] TCP flags matching
- [ ] Fragment matching
- [ ] NetBox integration for inventory
- [ ] Advanced correlation with ML-assisted confidence
- [ ] Per-peer vendor profiles in config

---

## Non-Goals

These are explicitly out of scope:

- Inline packet scrubbing
- L7/WAF analysis
- FlowSpec "match everything" rules (blocked by guardrails)
- Tbps-scale scrubbing without upstream support
- Competing with commercial DDoS platforms (Arbor, Corero)
