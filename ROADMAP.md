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

## v0.3 - Escalation & Correlation (Done)

- [x] Escalation logic (police → discard)
  - [x] Persistence tracking
  - [x] Confidence thresholds
  - [x] Policy profile support (strict/normal/relaxed)
- [x] Improved event correlation
  - [x] Port superset/subset handling
  - [x] Parallel mitigation for disjoint ports
- [x] Audit log file writer (JSON Lines)
- [x] Alerting webhooks (PagerDuty, Slack)

## v0.4 - Operational Tooling (Done)

- [x] CLI subcommands (prefixdctl binary)
  - [x] `prefixdctl status` - show active mitigations
  - [x] `prefixdctl mitigations withdraw <id>` - manual withdrawal
  - [x] `prefixdctl safelist add/remove`
  - [x] `prefixdctl peers` - BGP session status
  - [x] `prefixdctl reload` - hot-reload config
- [ ] Read-only web dashboard (frontend scaffolding in progress)
- [x] Configuration hot-reload (inventory, playbooks)
- [x] Graceful shutdown with announcement preservation

## v0.5 - Docker & PostgreSQL (Done)

- [x] PostgreSQL backend option
  - [x] Runtime-configurable storage driver (sqlite/postgres)
  - [x] Postgres migrations
  - [x] Connection pooling
- [x] Docker deployment
  - [x] Multi-stage Dockerfile
  - [x] docker-compose.yml (prefixd, postgres, gobgp)
  - [x] Example postgres config

## v1.0 - Production Ready

**Goal:** Enterprise-ready foundation with comprehensive testing, documentation, and security.

### Features (Done)
- [x] IPv6 FlowSpec support
  - [x] IpVersion detection for IPv4/IPv6 prefixes
  - [x] IPv6 FlowSpec NLRI construction (AFI=2, SAFI=133)
  - [x] IPv6-aware guardrails (configurable prefix lengths)
  - [x] IPv6 customer prefix/asset support in inventory
- [x] Multi-POP coordination (shared PostgreSQL approach)
  - [x] `GET /v1/stats` - aggregate stats across all POPs
  - [x] `GET /v1/pops` - list known POPs from database
  - [x] `GET /v1/mitigations?pop=all` - cross-POP visibility
  - See "Multi-POP Architecture" section below for evolution path
- [x] OpenAPI spec generation (`/openapi.json`)

### Testing (In Progress)
- [ ] Unit tests for BGP logic (`gobgp.rs`)
  - [ ] NLRI construction (IPv4/IPv6)
  - [ ] Path attribute building
  - [ ] Withdraw logic
- [ ] Unit tests for guardrails (`guardrails/mod.rs`)
  - [ ] Prefix validation
  - [ ] Quota enforcement
  - [ ] Safelist checking
- [ ] Unit tests for repository (`repository.rs`)
  - [ ] CRUD operations
  - [ ] Query filtering
  - [ ] Multi-POP queries
- [ ] Unit tests for policy engine
  - [ ] Playbook evaluation
  - [ ] Escalation logic

### Security & Auth
- [ ] mTLS authentication option (deferred from v0.2)
- [ ] Security audit
  - [ ] Input validation review
  - [ ] SQL injection prevention verification
  - [ ] Auth bypass testing
  - [ ] Rate limiting effectiveness

### Documentation
- [ ] Configuration guide (all YAML options)
- [ ] Deployment guide (Docker, bare metal)
- [ ] Troubleshooting runbook
- [ ] API stability guarantees

### Performance
- [ ] Benchmark suite (criterion)
  - [ ] Event ingestion throughput
  - [ ] BGP announcement latency
  - [ ] Database query performance

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

## Multi-POP Architecture

### v1.0 Approach: Shared PostgreSQL

Multiple prefixd instances share a single PostgreSQL database. Each instance:
- Filters mitigations by its own `pop` field
- Announces FlowSpec rules to its local GoBGP peer
- Has visibility into all POPs via `/v1/stats`, `/v1/pops`, and `?pop=all`

**Pros:**
- Simple to deploy and operate
- No new infrastructure required
- Cross-POP visibility for free
- Each POP operates independently (resilient)

**Cons:**
- Single database = potential single region latency
- Database becomes SPOF (mitigated by Postgres HA)

### Future Evolution Paths

**Option A: Event Replication (for global deployment)**
- Each POP has local database
- Publish mitigation events to message bus (NATS, Kafka, Redis Streams)
- Other POPs subscribe and replicate state
- Good for: Global deployment, eventual consistency OK

**Option B: Leader-Based Coordination**
- One POP is "leader" for a given victim IP or customer
- Leader makes decisions, replicates to followers
- Good for: Consistent policy enforcement across POPs

**Option C: API Federation**
- POPs expose APIs to each other
- Coordinator service aggregates state
- Good for: Heterogeneous deployments, multi-tenant

**Migration Path:**
1. Start with shared PostgreSQL (v1.0)
2. Add message bus for real-time sync when needed
3. Keep `pop` field on all records (already done)
4. APIs designed to be compatible with future coordination modes

---

## Non-Goals

These are explicitly out of scope:

- Inline packet scrubbing
- L7/WAF analysis
- FlowSpec "match everything" rules (blocked by guardrails)
- Tbps-scale scrubbing without upstream support
- Competing with commercial DDoS platforms (Arbor, Corero)
