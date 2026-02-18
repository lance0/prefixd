# Roadmap

What's next for prefixd.

---

## Current Status: v0.8.2

Core functionality is stable:

- Event ingestion and policy engine
- GoBGP v4.x FlowSpec (IPv4/IPv6)
- Reconciliation loop with drift detection
- PostgreSQL state storage
- Session auth + bearer tokens
- WebSocket real-time dashboard
- CLI tool (prefixdctl)

See [CHANGELOG](CHANGELOG.md) for version history.

---

## Ship Blockers (Before v1.0)

### Real Router Testing

- [x] FRR FlowSpec lab (containerlab) - fully working
- [x] Juniper cJunosEvolved (PTX10002) - end-to-end verified
  - Event ingestion → policy → GoBGP → cJunos inetflow.0
  - Announce, rate-limit, withdraw, TTL expiry all confirmed
  - Documented vendor quirks (FlowSpec-only AFI-SAFI, FXP0ADDR token, license warning)
- [ ] Test with Arista cEOS
- [ ] Test with Cisco XRd
- [x] Document vendor-specific quirks and import policies

### Documentation Polish

- [ ] Review all docs for accuracy
- [x] Add example Grafana dashboards
- [ ] Record demo video: attack → detection → mitigation → recovery

### Frontend

- [x] Derive WebSocket URL from `window.location` at runtime (removed `NEXT_PUBLIC_PREFIXD_WS` build-time env var; nginx reverse proxy is the proper solution for single-origin deployment)
- [x] Light/dark mode toggle
- [ ] Vitest setup
- [ ] Component tests
- [ ] Hook tests
- [ ] Error boundaries
- [ ] Upgrade lucide-react (0.454 -> latest, verify all ~30 icon imports)
- [ ] Upgrade react-resizable-panels (2.x -> 4.x, major version)
- [ ] Upgrade tower-sessions (0.14 -> 0.15, blocked on axum-login 0.18 compatibility)

### Authentication

- [x] Credentials auth mode (username/password)
  - Users table in PostgreSQL
  - Argon2id password hashing
  - Session cookies (HttpOnly, Secure, SameSite=Strict)
  - Roles: admin, operator, viewer
- [x] User management UI in Admin page
- [x] Real login form (replace placeholder)
- [ ] LDAP/AD support (optional, config placeholder ready)
- [ ] RADIUS/ISE support (optional, map attributes to roles)

---

## v1.0: Production Ready

Target: Stable API, comprehensive testing, production-proven.

### Stability

- [ ] API versioning and deprecation policy
- [ ] Database migration tooling
- [ ] Upgrade path documentation

### Hardening

- [ ] Chaos testing (kill GoBGP mid-mitigation, kill Postgres during ingestion)
- [ ] Load testing (sustained event volume)
- [ ] Security audit (dependencies, input validation)
- [ ] Reconciliation loop pagination (currently limited to 1000 mitigations)

### Observability

- [ ] Database metrics (query latency, connection pool)
- [ ] Request tracing with correlation IDs
- [x] Grafana dashboard templates

---

## v1.5: Multi-Signal Correlation

**The killer feature.** Combine weak signals from multiple detectors into high-confidence decisions.

Example: FastNetMon says UDP flood at 0.6 confidence + router CPU spiking + host conntrack exhaustion = **high-confidence mitigation**.

### Signal Adapters

- [ ] Enhanced FastNetMon adapter (configurable confidence mapping)
- [ ] Prometheus/Alertmanager adapter (metric queries, webhook receiver)
- [ ] Router telemetry adapter (JTI, gNMI)

### Correlation Engine

- [ ] Time-windowed event grouping
- [ ] Source weighting and reliability scoring
- [ ] Corroboration requirements ("require 2+ sources")

### Confidence Model

- [ ] Derived confidence from traffic patterns
- [ ] Confidence decay over time
- [ ] Per-playbook thresholds

---

## v2.0: Multi-Vendor Validation

Validated FlowSpec with major router vendors.

### Vendor Testing

- [x] Juniper PTX (cJunosEvolved 25.4R1.13-EVO) - verified
- [ ] Arista 7xxx (EOS 4.20+)
- [ ] Cisco IOS-XR (ASR 9000, NCS)
- [ ] Nokia SR OS (7750, not SR Linux - SR Linux lacks FlowSpec)

### Vendor Profiles

- [x] Juniper quirks documented (FlowSpec-only AFI-SAFI, import policy, no-validate)
- [ ] Capability matrix per vendor
- [ ] Graceful degradation for unsupported features
- [ ] Reference import policies per vendor

---

## Future Ideas

Not committed, but on the radar:

### Advanced FlowSpec

- Redirect actions (redirect-to-IP, redirect-to-VRF)
- Extended match criteria (packet length, TCP flags, DSCP)
- Scrubber integration with diversion orchestration

### Integrations

- NetBox inventory sync
- Customer self-service portal
- Native BGP speaker (replace GoBGP dependency)

### Scale

- Event batching for high-volume detectors
- Distributed coordination for multi-region

---

## Non-Goals

Explicitly out of scope:

- **Inline packet scrubbing** - Control-plane only
- **L7/WAF analysis** - Focus is L3/L4 volumetric
- **Detection algorithms** - Use existing detectors
- **Tbps-scale scrubbing** - Requires upstream integration
- **FlowSpec "match everything" rules** - Blocked by guardrails

---

## Contributing

Want to help? Check:

1. [Issues](https://github.com/lance0/prefixd/issues) labeled `good first issue`
2. Items in this roadmap
3. [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines
