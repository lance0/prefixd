# Roadmap

What's next for prefixd.

---

## Current Status: v0.10.1

Core functionality is stable:

- Event ingestion and policy engine
- GoBGP v4.x FlowSpec (IPv4/IPv6)
- Reconciliation loop with drift detection
- PostgreSQL state storage
- Mode-aware auth (none, credentials, bearer, mtls)
- WebSocket real-time dashboard
- CLI tool (prefixdctl)

See [CHANGELOG](CHANGELOG.md) for version history.

---

## Ship Blockers (Before v1.0)

These blockers map directly to the `v1.0` release gates below. Keep both sections in sync when statuses change.

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

- [ ] Review all docs for accuracy (release-candidate freeze)
- [x] Add example Grafana dashboards
- [ ] Record demo video: attack → detection → mitigation → recovery

### Frontend

- [x] Derive WebSocket URL from `window.location` at runtime (removed `NEXT_PUBLIC_PREFIXD_WS` build-time env var; nginx reverse proxy is the proper solution for single-origin deployment)
- [x] Light/dark mode toggle
- [x] Config page (Phase 1)
  - Read-only view of running config (allowlist-redacted settings, playbook visualization)
  - Hot-reload button (triggers `POST /v1/config/reload`)
  - Inventory browser (searchable customer/service/IP table)
  - Route-group auth guard, session expiry handling, deny-by-default permissions
- [x] **Withdraw button on mitigations** (P0 — all competitors have this)
  - Inline XCircle button on active/escalated rows + confirm dialog in detail panel
  - Calls `POST /v1/mitigations/{id}/withdraw`, permission-gated (operator+admin)
  - Real-time list update via SWR mutate
- [x] **Safelist management on admin page** (P0 — FastNetMon/Wanguard have whitelist UI)
  - Full CRUD: add with prefix + reason, remove with confirm dialog
  - Calls `GET/POST /v1/safelist`, `DELETE /v1/safelist/{prefix}`
  - Shows prefix, reason, added_by, timestamp per entry
- [x] **Mitigation detail view** (P1 — drill-down page)
  - Full-page dedicated view (`/mitigations/{id}`)
  - FlowSpec rule JSON preview and timeline (created → escalated → withdrawn/expired)
  - Embedded customer and service context looking up from inventory
  - Inline withdraw capabilities
- [x] **Manual mitigation/event creation** (P1 — "mitigate now" from UI)
  - Form at `/mitigations/create` submitting `POST /v1/events` with `action: "ban"`
  - Fields: destination IP, vector, bps/pps, ports (max 8), confidence slider
  - Permission-gated (operator + admin), "Mitigate Now" button in mitigations toolbar + command palette
- [x] **Toast notifications from WebSocket feed** (P1 — Wanguard/Kentik have real-time alerts)
  - Surface WS events as toast notifications (new mitigation, escalation, expiry)
  - Refactored `use-websocket` into a `WebSocketProvider` Context to prevent duplicate connections
  - Centralized connection management and SWR cache invalidation
- [x] **Embedded time-series charts** (P2 — reduces context-switching to Grafana)
  - 24h area chart on overview: mitigations + events per hour
  - PostgreSQL-backed via `GET /v1/stats/timeseries` with gap-filled `generate_series` buckets
  - recharts AreaChart with gradient fill, 30s auto-refresh
- [x] **Filtering and pagination on list pages** (P1 — client-side)
  - Mitigations: status toggle pills, IP search, column sorting, 20/page pagination
  - Events: source filter, vector filter, IP search, column sorting, 20/page pagination
  - Audit log: action filter, actor filter, text search, column sorting, 20/page pagination
  - Server-side cursor pagination tracked as future item
- [x] **Mitigation history per IP** (P2 — "what happened to this IP")
  - Dedicated `/ip-history?ip=X` page with search bar and vertical timeline
  - Events + mitigations interleaved chronologically, customer/service context
  - All victim_ip cells across UI link to IP history page
  - `GET /v1/ip/{ip}/history` backend endpoint with inventory lookup
- [x] **Alerting/webhook config UI** (P1 — full editor + test alert)
  - "Alerting" tab on Config page: add/edit/remove destinations, event filters, redacted secrets, admin-only test alert
- [x] **Audit log detail expansion** (P1 — click-to-expand)
  - Click truncated details to expand full JSON inline; extracted AuditRow sub-component
- [x] **Customer/POP filter on mitigations** (P1 — dropdown filters)
  - Customer and POP dropdown filters using existing backend `?customer_id=` and `?pop=` params
- [x] **Timeseries range selector** (P1 — 4 range options)
  - 1h/6h/24h/7d toggle buttons above activity chart with appropriate bucket sizes (5m/30m/1h/6h)
- [x] **Active count badge on sidebar** (P1 — live count)
  - Active mitigation count badge on Mitigations nav item via `useStats()` hook
- [x] **Severity badges on mitigations** (P1 — color-coded)
  - Severity column derived from status + action_type (critical/high/medium/low)
- [x] **Dark mode refinement** (P1 — audited, no issues)
  - All hardcoded colors are semantic accents (status green/red/yellow) with good contrast in both themes
  - Admin reload button already has explicit `dark:` hover variants
- [x] **Page layout cleanup** (P1 — admin tabs shipped)
  - Admin page uses Tabs component: Status, Safelist, Users (conditionally rendered)
  - Config page already tabbed: Settings, Playbooks, Alerting
- [x] **Config page editing (Phase 2 shipped)**
  - Playbook editor shipped: form tab + raw YAML tab backed by `PUT /v1/config/playbooks`
  - Alerting editor shipped: destination CRUD + event filters backed by `PUT /v1/config/alerting`
  - Atomic YAML writes, `.bak` backups, and hot-reload on save
- [x] Vitest setup (vitest.config.ts, jsdom, @testing-library/react, bun run test)
- [x] Component tests (ErrorBoundary test with 3 cases)
- [x] Hook tests (usePermissions 5 tests, useAuth 5 tests)
- [x] Error boundaries (ErrorBoundary component wrapping dashboard layout)
- [x] **Event → mitigation linking** (P1 — connects the operator workflow)
  - Mitigation detail page links back to triggering event via `?id=` param
  - Audit log target_id links to mitigation detail when target_type is mitigation
  - Command palette search links directly to `/mitigations/{id}`
  - Overview stat cards link to mitigations/events pages
  - Events "View Mitigations for IP" pre-fills search via `?ip=` param
- [x] **CSV export for list pages** (P1 — operators need data for reports/tooling)
  - Download button on mitigations, events, and audit log tables
  - Exports current filtered view as CSV (client-side generation, no backend)
  - Includes all visible columns plus IDs, date-stamped filename
- [x] **Keyboard shortcuts** (P1 — DX, command palette already exists)
  - `g o/m/e/i/h/a/c` navigation, `n` for Mitigate Now, `?` toggles help modal
  - `Cmd+K` command palette, `Cmd+B` sidebar toggle
  - Hints shown in command palette and keyboard shortcuts modal
- [x] Upgrade lucide-react (0.454 → 0.575, all ~40 icon imports verified)
- [x] Upgrade react-resizable-panels (2.1 → 4.6, major version)
- [ ] Upgrade tower-sessions (0.14 -> 0.15, blocked on axum-login 0.18 compatibility)

### Authentication

- [x] Credentials auth mode (username/password)
  - Users table in PostgreSQL
  - Argon2id password hashing
  - Session cookies (HttpOnly, Secure when TLS is enabled, SameSite=Lax)
  - Roles: admin, operator, viewer
- [x] User management UI in Admin page
- [x] Real login form (replace placeholder)

---

## v1.0: Production Ready (Interop + Stability)

Target: Validated with real routers, stable API, production-proven. Operators trust prefixd before we build new features.

### Release Gates (must all be true before tagging v1.0.0)

- [ ] Arista + Cisco XR interop scenarios pass end-to-end in lab
- [ ] Vendor capability matrix + reference import policy docs published
- [ ] CVE gate + SBOM generation enabled in CI and green on `main`
- [ ] Documentation accuracy review + demo video complete

### Vendor Interop (Priority)

- [x] Juniper PTX (cJunosEvolved 25.4R1.13-EVO) - verified
- [ ] Arista cEOS / 7xxx (EOS 4.20+) — validate FlowSpec announce/withdraw/reconcile
- [ ] Cisco XRd / IOS-XR (ASR 9000, NCS) — known FlowSpec quirks to document
- [x] Juniper quirks documented (FlowSpec-only AFI-SAFI, import policy, no-validate)
- [ ] Vendor capability matrix (what works, what doesn't, per vendor)
- [ ] Reference import policies per vendor (copy-paste ready)
- [ ] Graceful degradation for unsupported features

### Dependency Security Cadence

- [ ] Monthly GoBGP baseline bump policy (track upstream releases, especially parser hardening like v3.35.0)
- [ ] CVE gate in CI (fail build on known vulnerabilities in dependency tree)
- [ ] SBOM generation (CycloneDX or SPDX, published with releases)
- [ ] FlowSpec NLRI parser fuzz/regression tests (protect against malformed BGP update edge cases)

### Stability (Done)

- [x] API versioning and deprecation policy (`docs/api-versioning.md`)
- [x] Database migration tooling (`schema_migrations` table, `prefixdctl migrations`)
- [x] Upgrade path documentation (`docs/upgrading.md`)

### Hardening (Done)

- [x] Config API allowlist redaction (prevent accidental secret exposure)
- [x] Public health endpoint slimmed (no DB/GoBGP calls, no operational data)
- [x] Frontend deny-by-default permissions with auth-mode awareness
- [x] Session expiry handling (401 interceptor, debounced redirect)
- [x] Route-group auth guard (structural, not opt-in per page)
- [x] Route definition deduplication (shared helpers for production + test routers)
- [x] OpenAPI spec covers all endpoints (health split, config read-only)
- [x] Integration tests for config/health endpoints (25 integration tests)
- [x] Event ingestion endpoint auth enforcement (require_auth on POST /v1/events)
- [x] Chaos testing — 17 tests across 4 categories (Postgres, GoBGP, prefixd, network), all passing
- [x] Load testing — 7 HTTP load tests with hey (~4,700 events/sec, ~8,000 health req/s)
- [x] Security audit — 20 backend + 9 frontend findings, actionable items fixed
- [x] Reconciliation loop pagination (pages through all active mitigations, no cap)
- [x] SSRF protection on webhook URLs (HTTPS required, private IPs rejected)

### Observability (Done)

- [x] Database metrics (connection pool: active, idle, total via `prefixd_db_pool_connections`)
- [x] Request tracing with correlation IDs (`x-request-id` header, tracing span, nginx forwarding)
- [x] Grafana dashboard templates

### Documentation Polish

- [ ] Review all docs for accuracy (release-candidate freeze)
- [ ] Record demo video: attack → detection → mitigation → recovery
- [x] Vendor quirks documented

---

## v1.1: Operator Ergonomics

Target: Quality-of-life for operators during active incidents. These are the features that reduce time-to-action during attack waves.

### Bulk Operations

- [ ] **Bulk withdraw** — Multi-select mitigations and withdraw all at once (critical during false-positive waves)
- [ ] **Bulk acknowledge** — Mark mitigations as reviewed without withdrawing

### Investigation UX

- [ ] **Date range filtering** — Time picker on events and audit log pages for incident investigation
- [ ] **Post-attack incident reports** — Formatted PDF/markdown summary (timeline, peak traffic, actions taken)
- [ ] **FlowSpec rule preview** — Human-readable display of announced NLRI on mitigation detail page

### Notification Tuning

- [ ] **Notification preferences** — Mute/filter WebSocket toasts, quiet hours (reduce alert fatigue)
- [ ] **Per-destination event routing** — Route different event types to different alerting destinations

### Pagination + Performance

- [ ] **Server-side cursor pagination** — Replace client-side limit (~1000 rows) with proper cursor-based pagination
- [ ] **Event batching** — Batch ingest endpoint for high-volume detectors

---

## v1.2: Multi-Signal Correlation

**The killer feature.** Combine weak signals from multiple detectors into high-confidence decisions. Start with one high-value adapter.

Example: FastNetMon says UDP flood at 0.6 confidence + router CPU spiking + host conntrack exhaustion = **high-confidence mitigation**.

### Signal Adapters (start with one)

- [ ] Prometheus/Alertmanager adapter (metric queries, webhook receiver) — most universal, many operators already have this
- [ ] Enhanced FastNetMon adapter (configurable confidence mapping) — common pairing for self-hosted
- [ ] Router telemetry adapter (JTI, gNMI)

### Correlation Engine

- [ ] Time-windowed event grouping
- [ ] Source weighting and reliability scoring
- [ ] Corroboration requirements ("require 2+ sources")
- [ ] Correlation explainability (`why` details in API/UI for each mitigation decision)
- [ ] Replay mode for tuning (simulate historical incidents without announcing FlowSpec rules)

### Confidence Model

- [ ] Derived confidence from traffic patterns
- [ ] Confidence decay over time
- [ ] Per-playbook thresholds

---

## v1.5+: Integrations + Advanced FlowSpec

Broader ecosystem integration and advanced capabilities for large-scale deployments.

### Integrations

- [ ] NetBox inventory sync (replace YAML inventory with NetBox as source-of-truth)
- [ ] FastNetMon native adapter (common pairing for self-hosted deployments)
- [ ] Scrubber vendor integrations (complement cloud/hardware mitigation with policy automation)
- [ ] LDAP/AD auth backend (group-to-role mapping)
- [ ] RADIUS/ISE auth backend (attribute mapping to roles)
- [ ] Customer self-service portal (per-customer dashboards for MSSPs)
- [ ] Native BGP speaker (replace GoBGP dependency)

### Advanced FlowSpec

- [ ] Redirect actions (redirect-to-IP, redirect-to-VRF)
- [ ] Extended match criteria (packet length, TCP flags, DSCP)
- [ ] Scrubber integration with diversion orchestration

### Scale

- [ ] Distributed coordination for multi-region
- [ ] POP-level drill-down dashboard with geographic view

### Dashboard Enhancements

- [ ] Real-time bps/pps sparklines per mitigation (query Prometheus or internal metrics)
- [ ] OpenAPI/Swagger viewer embedded in dashboard
- [ ] GeoIP / ASN / IX enrichment at ingest

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
