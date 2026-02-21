# Roadmap

What's next for prefixd.

---

## Current Status: v0.9.0

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
- [ ] **Alerting/webhook config UI** (P2 — backend done, frontend remaining)
  - Backend: 7 destinations (Slack, Discord, Teams, Telegram, PagerDuty, OpsGenie, generic), `GET /v1/config/alerting`, `POST /v1/config/alerting/test`
  - Frontend: configure destinations from dashboard, test notification button
- [x] **Dark mode refinement** (P1 — audited, no issues)
  - All hardcoded colors are semantic accents (status green/red/yellow) with good contrast in both themes
  - Admin reload button already has explicit `dark:` hover variants
- [x] **Page layout cleanup** (P1 — admin tabs shipped)
  - Admin page uses Tabs component: Status, Safelist, Users (conditionally rendered)
  - Config page already tabbed: Settings, Playbooks
- [ ] Config page (Phase 2)
  - Playbook editor (form-based, with validation)
  - Requires `PUT /v1/config/playbooks` endpoint, file persistence, rollback
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

- [x] API versioning and deprecation policy (`docs/api-versioning.md`)
- [x] Database migration tooling (`schema_migrations` table, `prefixdctl migrations`)
- [x] Upgrade path documentation (`docs/upgrading.md`)

### Hardening

- [x] Config API allowlist redaction (prevent accidental secret exposure)
- [x] Public health endpoint slimmed (no DB/GoBGP calls, no operational data)
- [x] Frontend deny-by-default permissions with auth-mode awareness
- [x] Session expiry handling (401 interceptor, debounced redirect)
- [x] Route-group auth guard (structural, not opt-in per page)
- [x] Route definition deduplication (shared helpers for production + test routers)
- [x] OpenAPI spec covers all endpoints (health split, config read-only)
- [x] Integration tests for config/health endpoints (12 tests, up from 8)
- [x] Event ingestion endpoint auth enforcement (require_auth on POST /v1/events)
- [x] Chaos testing — 17 tests across 4 categories (Postgres, GoBGP, prefixd, network), all passing
- [x] Load testing — 7 HTTP load tests with hey (~4,700 events/sec, ~8,000 health req/s)
- [x] Security audit — 20 backend + 9 frontend findings, actionable items fixed (login throttle, input validation, CSV injection, client token removal)
- [x] Reconciliation loop pagination (pages through all active mitigations, no cap)

### Observability

- [x] Database metrics (connection pool: active, idle, total via `prefixd_db_pool_connections`)
- [x] Request tracing with correlation IDs (`x-request-id` header, tracing span, nginx forwarding)
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

Not committed, but on the radar.

### Dashboard

- **Embedded traffic charts** — Real-time bps/pps sparklines on the overview page (query Prometheus or internal metrics endpoint, reduce context-switching to Grafana)
- **Attack timeline / history per IP** — Unified "what happened to this IP" view combining events, mitigations, and escalations
- **Incident reports** — Formatted PDF/Excel post-attack reports (building on existing CSV export)
- **Webhook/alerting config UI** — Configure alert destinations from dashboard (backend supports Slack, Discord, Teams, Telegram, PagerDuty, OpsGenie, generic webhook; frontend UI not yet built)
- **GeoIP / ASN / IX enrichment** — Enrich attack events at ingest with source country, ASN, and IX presence. Same pattern as our `ttl` project: `maxminddb` crate with local GeoLite2-City.mmdb, Team Cymru DNS for ASN, PeeringDB REST API for IX detection. In-memory caches with 1h TTL, PeeringDB disk-cached at 24h. Fields added to AttackEvent before policy evaluation.

### Advanced FlowSpec

- Redirect actions (redirect-to-IP, redirect-to-VRF)
- Extended match criteria (packet length, TCP flags, DSCP)
- Scrubber integration with diversion orchestration

### Integrations

- NetBox inventory sync (replace YAML inventory with NetBox as source-of-truth)
- Customer self-service portal (per-customer dashboards for MSSPs)
- Native BGP speaker (replace GoBGP dependency)
- Prometheus/Alertmanager as event source (bidirectional: we push metrics, they push alerts)
- FastNetMon native adapter (common pairing for self-hosted deployments)
- Scrubber vendor integrations (complement cloud/hardware mitigation with policy automation)

### Scale

- Event batching for high-volume detectors
- Distributed coordination for multi-region
- Server-side cursor pagination (current client-side limit: ~1000 rows)

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
