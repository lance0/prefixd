# Roadmap

## v0.1 - MVP (Current)

- [x] HTTP API with event ingestion
- [x] Policy engine with YAML playbooks
- [x] Guardrails (TTL, /32, quotas, safelist)
- [x] PostgreSQL state store
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
- [x] mTLS authentication option (moved to v1.0, now complete)
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
- [x] Configuration hot-reload (inventory, playbooks)
- [x] Graceful shutdown with announcement preservation

## v0.5 - Docker & PostgreSQL (Done)

- [x] PostgreSQL backend option
  - [x] Postgres migrations
  - [x] Connection pooling
- [x] Docker deployment
  - [x] Multi-stage Dockerfile
  - [x] docker-compose.yml (prefixd, postgres, gobgp)
  - [x] Example postgres config

## v0.6 - PostgreSQL-Only & Test Infrastructure (Done)

- [x] Remove SQLite support (PostgreSQL-only)
  - [x] Extract `RepositoryTrait` from `Repository`
  - [x] Remove all SQLite code paths (~800 lines removed)
  - [x] Remove `DbPool` enum, use `PgPool` directly
  - [x] Remove `StorageDriver` enum from config
  - [x] Update `storage.path` → `storage.connection_string`
- [x] Mock repository for testing
  - [x] Create `MockRepository` implementing `RepositoryTrait`
  - [x] Migrate unit tests to use `MockRepository`
  - [x] Add testcontainers dev-dependencies
- [x] Update documentation (remove SQLite references)

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

### Testing (Done)
- [x] Unit tests for BGP logic (`gobgp.rs`) - 16 tests
  - [x] NLRI construction (IPv4/IPv6)
  - [x] Path attribute building
  - [x] RFC constant validation
- [x] Unit tests for guardrails (`guardrails/mod.rs`) - 18 tests
  - [x] Prefix validation
  - [x] TTL validation
  - [x] Port count limits
  - [x] IPv6 detection
- [x] Unit tests for repository (`repository.rs`) - 18 tests
  - [x] CRUD operations
  - [x] Query filtering
  - [x] Multi-POP queries
  - [x] Safelist operations
- [x] Unit tests for policy engine - 13 tests
  - [x] Playbook evaluation
  - [x] Port intersection logic
  - [x] Protocol detection
  - [x] TTL handling

**Total: 84 unit tests**

### Security & Auth (Done)
- [x] mTLS authentication option (rustls 0.23, client cert verification)
- [x] Security headers (X-Content-Type-Options, X-Frame-Options, Cache-Control)
- [x] Security audit
  - [x] Dependency audit with cargo-audit (2 CVEs fixed)
  - [x] 2026 stable dependency upgrades
  - [x] Auth integration tests (5 tests)
- [ ] Formal penetration testing (future)

### Documentation (Done)
- [x] Configuration guide (`docs/configuration.md` - all YAML options)
- [x] Deployment guide (`docs/deployment.md` - Docker, bare metal, mTLS)
- [x] Troubleshooting runbook (`docs/troubleshooting.md`)
- [ ] API stability guarantees (defer to v1.0 release)

### Performance (Done)
- [x] Benchmark suite (criterion)
  - [x] Inventory lookup throughput (~5.6M ops/sec)
  - [x] Database query performance (~6K ops/sec)
  - [x] Serialization benchmarks (~1M ops/sec)
  - [x] Scaling analysis (DB list, inventory lookup)
- [x] Benchmark documentation (`docs/benchmarks.md`)

### Web Dashboard (Done)
- [x] Next.js frontend (`frontend/`)
  - [x] Dashboard overview (stats, BGP status, quota gauges)
  - [x] Mitigations list with filtering, sorting, pagination
  - [x] Events list with filtering, sorting, pagination
  - [x] Audit log viewer with filtering
  - [x] Real-time updates (SWR with 5s polling)
  - [x] Docker deployment support
- [x] API integration
  - [x] Connect to prefixd REST API
  - [x] `GET /v1/events` endpoint
  - [x] `GET /v1/audit` endpoint
- [x] Frontend polish
  - [x] Live activity feed (replaces mock data)
  - [x] Config page (system status, BGP, quotas, safelist viewer)
  - [x] Loading/error states throughout

## v1.1 - Integration Tests & Bug Fixes

**Goal:** Comprehensive integration test coverage and critical bug fixes.

### Integration Tests (using testcontainers)
- [ ] Full event ingestion flow (event → policy → mitigation → BGP)
- [ ] Mitigation withdrawal via API
- [ ] TTL expiry via reconciliation loop
- [ ] Configuration hot-reload
- [ ] Pagination and filtering queries
- [ ] Migration verification (clean Postgres → migrations)

### Bug Fixes (Done)
- [x] Fix `is_safelisted()` performance
  - [x] Replace load-all with PostgreSQL inet operators (`<<=`)
- [x] Add IPv6 support in `is_safelisted()`
- [x] Add timeout handling for GoBGP gRPC calls (10s connect, 30s request)
- [x] Add retry logic for transient BGP failures
  - [x] Exponential backoff (3 retries, 100ms-400ms)
- [x] Fix SQL injection in list_mitigations queries
  - [x] Use parameterized queries for status/customer filters

### Security Hardening
- [x] Request body size limit (1MB via tower-http)
- [ ] Request header count limits
- [ ] API key rotation support (multiple valid tokens)
- [ ] Audit log for authentication failures

## v1.2 - Observability & DevOps

**Goal:** Production-grade observability and CI/CD infrastructure.

### Observability
- [ ] HTTP metrics
  - [ ] `prefixd_http_request_duration_seconds` histogram
  - [ ] `prefixd_http_requests_total` counter (by endpoint, status)
- [ ] Database metrics
  - [ ] `prefixd_db_query_duration_seconds` histogram
  - [ ] `prefixd_db_connections_active` gauge
- [x] Operational metrics
  - [x] `prefixd_config_reload_total` counter
  - [x] `prefixd_escalations_total` counter
- [ ] Tracing
  - [ ] Request correlation with trace IDs
  - [ ] Span instrumentation for key operations
- [x] Health checks
  - [x] Database connectivity check in `/v1/health`
  - [ ] GoBGP connectivity check
  - [x] Detailed `/v1/health` response (status: healthy/degraded)

### DevOps
- [ ] GitHub Actions CI
  - [ ] Test (unit + integration with testcontainers)
  - [ ] Lint (clippy, rustfmt)
  - [ ] Build (release binary, Docker image)
  - [ ] Security audit (cargo-audit)
- [ ] Kubernetes manifests
  - [ ] Deployment, Service, ConfigMap, Secret
  - [ ] PodDisruptionBudget
  - [ ] HorizontalPodAutoscaler
- [ ] Helm chart
- [ ] Pre-commit hooks configuration
- [ ] Dependabot configuration

## v1.3 - Frontend Maturity & API Polish

**Goal:** Production-quality frontend and API refinements.

### Frontend Testing & Features
- [ ] Vitest test setup
- [ ] API client tests
- [ ] React hooks tests
- [ ] Error boundaries throughout
- [ ] WebSocket support (replace 5s polling)
  - [ ] Real-time mitigation updates
  - [ ] Live event stream

### API Polish
- [ ] OpenAPI enhancements
  - [ ] Descriptions for all endpoints
  - [ ] Request/response examples
  - [ ] Error response schemas
- [ ] Bulk operations
  - [ ] `POST /v1/mitigations/bulk-withdraw`
  - [ ] `POST /v1/safelist/bulk-add`
- [ ] API validation improvements
  - [ ] Tighten `create_mitigation` validation (protocol/action/rate)
  - [ ] Clarify `total` semantics (page size vs total count)
  - [ ] Add max TTL enforcement in guardrails (config-driven)

### BGP Improvements
- [ ] Implement `parse_flowspec_path()` for reconciliation
  - [ ] Decode FlowSpec NLRI from GoBGP RIB
  - [ ] Enable desired vs actual state comparison
  - [ ] Document limitation if not implemented

### Documentation
- [ ] Inline code documentation
  - [ ] BGP NLRI construction comments
  - [ ] Escalation logic comments
- [ ] Operations guides
  - [ ] Connection pool tuning
  - [ ] PostgreSQL performance tuning
- [ ] Architecture Decision Records (ADRs)

## v1.5 - Multi-Signal Correlation

**Goal:** Combine weak signals from multiple sources into high-confidence mitigation decisions.

### Signal Source Adapters
- [ ] FastNetMon adapter (current HTTP webhook, enhanced)
  - [ ] Configurable confidence mapping
  - [ ] Threshold-based confidence derivation
- [ ] Prometheus/VictoriaMetrics adapter
  - [ ] Pull-based metric queries
  - [ ] Alertmanager webhook receiver
  - [ ] Host metrics → synthetic events (SYN backlog, conntrack exhaustion)
- [ ] Router telemetry adapter
  - [ ] Junos JTI/streaming telemetry
  - [ ] Control-plane stress signals (CPU, memory, flow table pressure)
  - [ ] gNMI support for multi-vendor

### Correlation Engine
- [ ] Time-windowed event correlation
  - [ ] Group events for same victim within N seconds
  - [ ] Aggregate confidence across sources
- [ ] Source weighting configuration
  - [ ] Per-source confidence multipliers
  - [ ] Source reliability scoring
- [ ] Corroboration requirements
  - [ ] "Require 2+ sources" mode for low-confidence signals
  - [ ] Escalation requires corroborating signal

### Enhanced Confidence Model
- [ ] Derived confidence calculation
  - [ ] BPS/PPS ratio to baseline
  - [ ] Port entropy analysis
  - [ ] Traffic pattern scoring
- [ ] Confidence decay over time
- [ ] Per-playbook confidence thresholds

## v2.0 - Multi-Vendor Support

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

## v2.5+ - Advanced Features

- [ ] Redirect/diversion actions (redirect-to-IP, redirect-to-VRF)
- [ ] Scrubber integration with diversion orchestration
- [ ] Extended match criteria
  - [ ] Packet length matching
  - [ ] TCP flags matching
  - [ ] Fragment matching
  - [ ] DSCP/traffic class
- [ ] NetBox integration for inventory sync
- [ ] Customer self-service portal
  - [ ] Read-only mitigation visibility
  - [ ] Manual mitigation requests (with approval workflow)

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

---

## Signal-Driven Architecture

prefixd implements a **signal-driven** architecture where detection is decoupled from enforcement:

```
[ Signal Sources ]          [ prefixd ]                    [ Enforcement ]
                                 |
  FastNetMon ─────────┐          v
  Prometheus/Alerts ──┼──► Signal Ingest ──► Policy Engine ──► GoBGP ──► Routers
  Router Telemetry ───┤          │                │
  Host Metrics ───────┘          v                v
                          Guardrails        FlowSpec NLRI
                               │
                               v
                         Audit + State
```

**Key Principles:**
- Detection systems signal intent, not enforce mitigation
- No detector ever speaks BGP directly
- Multiple weak signals can combine into high-confidence actions
- Mitigation scope derived from inventory, not detector guesses
- prefixd is authoritative for rule lifecycle (create, escalate, withdraw)

**Supported Signal Sources (v1.0):**
- HTTP POST webhook (FastNetMon, custom scripts)
- Any system that can emit the `AttackEvent` schema

**Future Signal Sources (v1.5+):**
- Prometheus/Alertmanager
- Router streaming telemetry (JTI, gNMI)
- Host kernel metrics (node_exporter)
- Load balancer metrics (HAProxy, Envoy)

---

## Non-Goals

These are explicitly out of scope:

- **Inline packet scrubbing** - prefixd is control-plane only
- **L7/WAF analysis** - focus is L3/L4 volumetric attacks
- **FlowSpec "match everything" rules** - blocked by guardrails
- **Tbps-scale scrubbing** - requires upstream/scrubber integration
- **Competing with commercial platforms** - prefixd is infrastructure glue, not a product
- **Detection algorithm development** - use existing detectors, prefixd handles policy
