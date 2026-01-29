# Roadmap

What's next for prefixd.

---

## Current Status: v0.8.0

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
- [ ] Test with Juniper vMX (requires Intel VMX)
- [ ] Test with Arista cEOS
- [ ] Test with Cisco XRd
- [ ] Document vendor-specific quirks and import policies

### Documentation Polish

- [ ] Review all docs for accuracy
- [ ] Add example Grafana dashboards
- [ ] Record demo video: attack → detection → mitigation → recovery

### Frontend Testing

- [ ] Vitest setup
- [ ] Component tests
- [ ] Hook tests
- [ ] Error boundaries

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
- [ ] Grafana dashboard templates

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

- [ ] Juniper MX/PTX (primary target)
- [ ] Arista 7xxx (EOS 4.20+)
- [ ] Cisco IOS-XR (ASR 9000, NCS)
- [ ] Nokia SR OS

### Vendor Profiles

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
