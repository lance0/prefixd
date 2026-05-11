# Changelog

All notable changes to prefixd will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.17.1] - 2026-05-11

### Changed

- **Dependency bump bundle.** Bumps `hmac 0.12 → 0.13`, `sha2 0.10 → 0.11`, `clap 4.6.0 → 4.6.1`, `rand 0.10.0 → 0.10.1`. The `hmac`/`sha2` bumps are coupled (hmac 0.13 pulls digest 0.11, locking it to sha2 0.11) and required importing `hmac::KeyInit` explicitly in `src/correlation/webhook.rs` and `src/alerting/generic.rs` — `new_from_slice` moved off the `Mac` trait in 0.13. No runtime behavior change. Closes #106, #118, #119, #120.

### Deferred

- **`password-hash 0.5 → 0.6` (#116).** Not bumped. `argon2 0.6` is still RC (latest stable: 0.6.0-rc.8) and `argon2 0.5` (current stable) still depends on `password-hash 0.5`, so bumping `password-hash` alone would create a dual-version transitive with no security gain. Will revisit when argon2 0.6 stabilizes.

## [0.17.0] - 2026-04-29

### Added

- **Corroborating signals v2 (PR B)** — Follow-up to ADR 021's initial ship that addresses the four review-deferred items as a coordinated set:
  - **Playbook-aware late finalization.** Migration `012_signal_groups_playbook.sql` adds nullable `signal_groups.playbook_name`, populated by the daemon on the next primary event for each group via `COALESCE`. The corroborator-side aggregate recompute now re-resolves the playbook by name from live state and is allowed to flip `corroboration_met=true` using the override min_sources/threshold. Conservative fallback is preserved: a NULL or stale `playbook_name` still keeps the v0.16.0 no-flip behavior (the next primary event picks up the flag).
  - **Per-source attribution on `prefixd_corroborator_expired_total`.** The counter regains its `{source}` label set, with `delete_expired_corroborating_signals` collecting attribution in the same `DELETE … RETURNING` query that performs the delete. **Operator note:** this is a label change. PromQL queries written against the v0.16.0 unlabelled counter must add a `sum()` to recover the previous shape.
  - **New gauge `prefixd_corroborator_cache_size{source}`** updated by the reconcile loop after each sweep. Operators can alert on caches growing without bound (e.g. a source posting heavily while no matching primary event ever lands). Stale labels are explicitly zeroed when a source's cache drains between ticks.
  - **Cached-corroborators admin endpoint and dashboard panel.** `GET /v1/signals/corroborator/cache` (admin-only) returns `{ now, total, by_source[], signals[] }` filtered to unattached + unexpired rows, with optional `?source=` and `?limit=` (clamped to 1..1000). New "Cache" tab on the Correlation page renders per-source counts plus a dense table of cached signals with relative ingested/expires timestamps and dimension chips. Backed by a new `useCachedCorroborators` SWR hook (30s refresh).
  - **`CorroboratorResponse.cached` removed** in favor of the existing `status ∈ {attached, cached}` discriminator. The boolean was always `true` and added no information; status fully describes the outcome. Coordinated minor breaking change — bump to v0.17.0 — since the endpoint is new in this release line.

## [0.16.0] - 2026-04-19

### Added

- **Corroborating signals (ADR 021)** — New class of correlation signals that strengthen open signal groups without ever triggering mitigations on their own. Targets coarse telemetry (router CPU, interface utilization, per-customer NetFlow, PoP-level metrics) that shouldn't name a victim IP but is valuable alongside a real detector.
  - Configure via `mode: corroborating` + `match_dimensions: [pop, customer_id, service_id, interface]` on any entry in `correlation.yaml`'s `sources` map. Declared dimensions are **authoritative**: a source declared for `[pop]` can never attach via an undeclared `customer_id`/`service_id`/`interface`, even if those values happen to match an open group. Validator rejects misconfiguration on both `PUT /v1/config/correlation` and on YAML load — the daemon refuses to boot with invalid correlation config.
  - New endpoint `POST /v1/signals/corroborator` accepts dimension-tagged signals (no `victim_ip`). Matches open signal groups using OR-semantics **across declared dimensions only**, with an optional `vector` narrower. Unmatched signals cache for up to `window_seconds` and drain when a matching primary event arrives.
  - Engine invariant enforced in two places: (a) `check_corroboration_with_primary` requires at least one primary event before `corroboration_met` can flip true, and (b) the corroborator-side aggregate recompute refuses to promote `corroboration_met` from false→true on its own — only the primary-ingest path (which has playbook-override context) can do that.
  - `POST /v1/events` rejects corroborating-only sources at handler entry, before any ban/unban branching and before any DB writes. Nothing persists from a rejected event.
  - New `interface` field on inventory `Asset` entries feeds into `IpContext.interface`, so interface-only corroborators (a common gNMI / SNMP shape) now have a real matchable dimension.
  - Reconciliation loop sweeps expired corroborators. Three new Prometheus metrics: `prefixd_corroborator_ingested_total{source}`, `_attached_total{source}`, `_expired_total` (unlabelled — per-source attribution deferred to PR B; see ROADMAP). `_expired_total` counts only *unattached* cache misses — signals that attached and then had their cache row GC'd no longer inflate the counter. Migrations 009, 010, and 011 (the last backfills `primary_dimensions` for pre-upgrade open signal groups from their mitigations so corroborators can attach to in-flight incidents immediately after upgrade).
  - New endpoint `GET /v1/signals/corroborator/activity?minutes=N` returns per-source `(last_seen, count)` aggregated across the live cache *and* attached `signal_group_events` rows. The frontend merges this into the Signal Sources tab so `mode: corroborating` sources no longer render as "never seen" simply because they don't post to `/v1/events`.
  - Dashboard: per-source mode + dimension picker in the Correlation Config tab (switching back to `primary` auto-clears declared dimensions); corroborating badge on signal group detail's contributing-events list; null-safe `ingested_at` rendering for corroborator rows.
  - New CLI: `prefixdctl send-corroborator --source router-cpu --pop iad1 ...`.
  - See [ADR 021](docs/adr/021-corroborating-signals.md) for rationale; migrations 009 + 010 for schema; [docs/detectors/corroborating-signals.md](docs/detectors/corroborating-signals.md) for operator quickstart.

## [0.15.0] - 2026-04-18

### Added

- **Generic webhook adapter** — Integrate any detector or telemetry source that can POST JSON without writing Rust. Configure a named adapter in `correlation.yaml` with JSONPath field mappings, HMAC/bearer/none auth, optional batching via `root_path`, vector normalization, and confidence scaling. Events flow through the standard correlation and policy pipeline. New endpoint: `POST /v1/signals/webhook/{name}`. See [ADR 020](docs/adr/020-generic-webhook-adapter.md) for design rationale, [docs/detectors/generic-webhook.md](docs/detectors/generic-webhook.md) for an end-to-end walkthrough, and `docs/configuration.md` / `docs/api.md` for schema reference.
- **Webhook adapter config validation** — `CorrelationConfig::validate()` now rejects `confidence_scale <= 0` or non-finite, empty `auth.secret_env` / `auth.header`, and non-`sha256` HMAC algorithms. Misconfiguration surfaces as a 400 on PUT/reload instead of runtime 500s.
- **Frontend CRUD editor** for webhook adapters on the Correlation Config tab (all three auth modes, JSONPath field mapping, vector normalization, HMAC secret env-var reference, endpoint copy button).

### Fixed

- **Rust 1.95 CI compatibility** — Addressed new clippy lints (`collapsible_match`, `cloned_ref_to_slice_refs`, `field_reassign_with_default`) and match-exhaustiveness in `gobgp.rs` guard patterns.
- **Webhook `action` validation** — Invalid `action` values (e.g. `"resolved"`, typos) now produce a per-event mapping error instead of silently defaulting to `"ban"`. Missing/null still defaults to `"ban"`.

### Changed

- **Security advisory bumps** — `rustls-webpki` 0.103.10 → 0.103.12 (RUSTSEC-2026-0098/0099). `RUSTSEC-2026-0097` (`rand`) added to `cargo-audit` ignore list pending upstream fix.
- **New dependencies** — `serde_json_path 0.7` (RFC 9535 JSONPath), `subtle 2` (constant-time compare for HMAC).

## [0.14.1] - 2026-04-03

### Fixed

- **Prometheus metrics wired up** — All event, mitigation, announcement, reconciliation, guardrail, and BGP session metrics were defined but never incremented. Now properly instrumented across all handler and reconciliation paths. (contributed by @bswinnerton)
- **ANNOUNCEMENTS_TOTAL label simplified** — Dropped unused `peer` label (handlers don't have peer context); ANNOUNCEMENTS_LATENCY changed from per-peer HistogramVec to a global Histogram
- **MITIGATIONS_ACTIVE gauge accuracy** — Reconciliation loop now resets and recomputes the active mitigations gauge with correct `action_type` and `pop` labels each tick
- **BGP_SESSION_UP gauge** — Now updated each reconciliation tick from actual peer session state

### Changed

- Bump uuid 1.21.0 → 1.22.0
- Bump rustls 0.23.36 → 0.23.37
- Bump ipnet 2.11.0 → 2.12.0
- Bump @radix-ui/react-popover 1.1.4 → 1.1.15
- Bump recharts 3.7.0 → 3.8.0
- Bump picomatch 4.0.0 → 4.0.4

### Security

- **aws-lc-sys** — Updated 0.36.0 → 0.39.1 fixing CRL scope check logic error (RUSTSEC-2026-0048, high), PKCS7 signature validation bypass (RUSTSEC-2026-0047, high), PKCS7 cert chain bypass (RUSTSEC-2026-0046, high), AES-CCM timing side-channel (RUSTSEC-2026-0045, medium), X.509 name constraints bypass (RUSTSEC-2026-0044)
- **rustls-webpki** — Updated 0.103.9 → 0.103.10 fixing CRL Distribution Point matching logic (RUSTSEC-2026-0049)
- **picomatch** — Updated to 4.0.4 fixing ReDoS via extglob quantifiers (GHSA-c2c7-rcm5-vvqj, high) and method injection in POSIX character classes (GHSA-3v7f-55p6-f55p, moderate)

## [0.14.0] - 2026-03-20

### Added

- **Multi-signal correlation engine** — Time-windowed grouping of related attack events by (victim_ip, vector) from multiple detection sources. Configurable source weights, corroboration thresholds, and per-playbook overrides. When `correlation.enabled` is true, events are grouped into signal groups and mitigation only triggers when corroboration requirements are met (configurable `min_sources` and `confidence_threshold`). Single-source behavior is preserved with `min_sources=1` (backward compatible). See [ADR 018](docs/adr/018-multi-signal-correlation-engine.md).
- **Signal groups API** — `GET /v1/signal-groups` (list with cursor pagination, status/vector/date filters) and `GET /v1/signal-groups/{id}` (detail with contributing events, source weights, and confidence). Both endpoints require authentication.
- **Correlation context on mitigations** — `GET /v1/mitigations` and `GET /v1/mitigations/{id}` responses include a `correlation` field for correlated mitigations, containing signal_group_id, derived_confidence, source_count, corroboration_met, contributing_sources, and a human-readable explanation.
- **Correlation engine metrics** — `prefixd_signal_groups_total`, `prefixd_signal_group_sources`, `prefixd_correlation_confidence`, `prefixd_corroboration_met_total`, `prefixd_corroboration_timeout_total` Prometheus counters and histograms.
- **Signal group expiry** — Reconciliation loop expires open signal groups whose time window has elapsed, transitioning them to `expired` status.
- **Database migration 007** — `signal_groups` and `signal_group_events` tables, `mitigations.signal_group_id` nullable FK column with indexes.
- **Correlation configuration** — New `correlation` section in `prefixd.yaml` with `enabled`, `window_seconds`, `min_sources`, `confidence_threshold`, `sources` (per-source weight/type), and `default_weight`. Per-playbook `correlation` overrides in `playbooks.yaml`. Hot-reloadable via `POST /v1/config/reload`.
- **Alertmanager webhook adapter** — `POST /v1/signals/alertmanager` accepts Alertmanager v4 webhook payloads. Maps labels/annotations to attack event fields (vector, victim_ip, bps/pps, severity→confidence). Handles batched alerts with per-alert results, resolved alerts (→ withdraw), fingerprint dedup. Returns 400 for malformed payloads (Alertmanager won't retry 4xx). See [ADR 019](docs/adr/019-signal-adapter-architecture.md).
- **FastNetMon webhook adapter** — `POST /v1/signals/fastnetmon` accepts FastNetMon's native JSON notify payload. Classifies attack vector from traffic breakdown (UDP/SYN/ICMP/TCP), maps action type to confidence (ban=0.9, partial_block=0.7, alert=0.5, configurable), uses `attack_uuid` for dedup. Returns `EventResponse` shape for script compatibility.
- **Correlation config API** — `GET /v1/config/correlation` (secrets redacted) and `PUT /v1/config/correlation` (admin only, validates, writes YAML, hot-reloads). Correlation config reloaded alongside inventory/playbooks/alerting on `POST /v1/config/reload`.
- **Signal adapter E2E tests** — 3 end-to-end tests in `tests/integration_e2e.rs` verifying full-stack signal adapter flows through real Postgres and GoBGP: Alertmanager→signal group→mitigation, FastNetMon→signal group→mitigation, multi-source corroboration (FastNetMon + Alertmanager → same group → mitigation with FlowSpec in RIB). Marked `#[ignore]` by default (require Docker).

### Changed

- Backend unit tests increased from 126 to 179 (correlation engine, config parsing, corroboration, explainability, signal adapters)
- Integration tests increased from 44 to 99 (signal group CRUD, correlation flow, concurrent event handling, Alertmanager adapter, FastNetMon adapter, correlation config API)
- Postgres integration tests increased from 9 to 16 (signal group operations)
- Frontend tests increased from 34 to 67 (correlation dashboard, signal group detail, mitigation detail correlation)

## [0.13.0] - 2026-03-19

### Added

- **Event batching** — `POST /v1/events/batch` accepts up to 100 events in a single request. Sequential processing through the full pipeline (validation, guardrails, policy, announce) with partial success semantics. Returns per-event results with `202 Accepted` (all succeeded) or `207 Multi-Status` (mixed).
- **FlowSpec NLRI fuzz/property tests** — 8 proptest property-based tests for prefix parsing, NLRI roundtrip, and action roundtrip. Two cargo-fuzz targets (`fuzz_prefix_parse`, `fuzz_nlri_decode`) for offline fuzzing with libFuzzer.
- **Post-attack incident reports** — `GET /v1/reports/incident?mitigation_id=X` or `?ip=X` generates a markdown incident report with summary, timeline, events, mitigations, and audit trail. "Generate Report" buttons on mitigation detail and IP history pages with copy/download dialog.

### Fixed

- **WebSocket rejected all connections when auth_mode is none** — `ws_handler` checked for an authenticated session unconditionally, returning 401 for every connection in no-auth deployments. Dashboard showed "Disconnected" permanently.
- **Mitigation detail page showed "Not Found" on Next.js 16** — Dynamic route `params` became a Promise in Next.js 15+. Page was destructuring synchronously, getting `undefined` for the ID.
- **Dark mode outline button hover invisible** — Export CSV, Refresh, and other outline-variant buttons had nearly invisible hover states in dark mode (`bg-input/50` at ~11% opacity). Changed to `bg-accent/20` with accent-foreground text for visible teal-tinted hover.

## [0.12.0] - 2026-03-18

### Added

- **Cursor-based pagination** — All list endpoints (`/v1/mitigations`, `/v1/events`, `/v1/audit`) now use cursor-based pagination (`?cursor=<opaque>&limit=N`). Responses include `next_cursor` and `has_more` fields. **Breaking:** `offset` parameter removed (see ADR 016).
- **Date range filtering** — All list endpoints accept `?start=<ISO8601>&end=<ISO8601>` for time-bounded queries. Supports incident investigation workflows.
- **Bulk acknowledge** — `POST /v1/mitigations/acknowledge` marks mitigations as reviewed by an operator (sets `acknowledged_at`/`acknowledged_by`) without changing status. Filterable via `?acknowledged=true|false`. Migration 005 adds columns.
- **Per-destination event routing** — Each alerting destination can now specify its own `events` list to override the global event filter. Empty/absent inherits global. Backward-compatible (see ADR 017).
- **Notification preferences** — `GET/PUT /v1/preferences` stores per-operator toast notification settings (muted event types, quiet hours in UTC). Migration 006 adds `notification_preferences` table. Dashboard WebSocket toasts respect preferences; quiet hours suppress non-critical events only.
- **Notification preferences dialog** — User menu dropdown now includes "Notifications" item opening a preferences dialog with event toggles and quiet hours selectors.

## [0.11.0] - 2026-03-18

### Added

- **Bulk withdraw** — `POST /v1/mitigations/withdraw` accepts up to 100 mitigation IDs with partial success semantics. Frontend adds checkbox selection on active/escalated rows, select-all, selection toolbar, and confirmation dialog.
- **FlowSpec rule preview** — Mitigation detail page shows a router-style one-liner (`match destination ... protocol ... then ...`) above the structured grid. Copy Rule button for quick comparison with router CLI output.
- **CVE gate in CI** — Security audit (`cargo audit` + `bun audit`) now gates Docker publishing. CycloneDX SBOM generated on version tags.
- **Vendor capability matrix** — `docs/vendors.md` with tested status for Juniper (verified), Arista (partially verified), Cisco IOS-XR, Nokia SR OS, and FRR. Reference import policies per vendor.

### Security

- **Next.js** — Updated to 16.1.7 (CSRF bypass, HTTP smuggling, disk cache DoS, postpone DoS)
- **undici** — Updated to 7.24.4 (WebSocket overflow, request smuggling, memory DoS, CRLF injection)
- **quinn-proto** — Updated to 0.11.14 (RUSTSEC-2026-0037, DoS in Quinn endpoints)
- **rollup** — Updated to 4.59.0 (GHSA-mw96-cpmx-2vgc, arbitrary file write)

### Fixed

- **Docs accuracy** — Fixed stale test counts, version strings, metrics port, SECURITY.md supported versions

## [0.10.1] - 2026-02-22

### Added

- **`victim_ip` filter on mitigations API** — `GET /v1/mitigations?victim_ip=X` filters by exact victim IP address. Supported in both single-POP and all-POPs queries. (#65)
- **FastNetMon integration guide** — New `docs/detectors/fastnetmon.md` with full setup, env vars, testing, and troubleshooting
- **Integration test** — `test_list_mitigations_filters_by_victim_ip` validates API filtering end-to-end

### Fixed

- **FastNetMon re-ban collision** — Deterministic `sha256(IP|direction)` event IDs caused permanent 409 duplicates after withdrawal. Script now uses UUID event IDs per ban occurrence, enabling re-ban and proper TTL extension. (#65)
- **FastNetMon unban flow** — Unban now queries active mitigations by `victim_ip` and withdraws directly, instead of relying on a shared event ID. Includes configurable retry window for ban/unban race timing. (#65)
- **FastNetMon withdraw missing `operator_id`** — Withdraw payload now includes `PREFIXD_OPERATOR` (default: `fastnetmon`) to satisfy API validation

## [0.10.0] - 2026-02-22

### Added

- **Playbook editor** — `PUT /v1/config/playbooks` endpoint (admin-only) with full validation, atomic YAML write with `.bak` backup, and hot-reload. Form-based editor and raw YAML editor on Config page frontend.
- **Interactive alerting config** — `PUT /v1/config/alerting` endpoint (admin-only) with validation, secret merge (`***` preserves existing secrets), atomic write to `alerting.yaml`, and hot-reload via `RwLock<Arc<AlertingService>>`. Frontend editor with type-specific forms for all 7 destination types, event filter checkboxes, save/discard controls.
- **Alerting config split** — Alerting configuration moved from `prefixd.yaml` to standalone `alerting.yaml` with backward-compatible fallback. Reloaded on `POST /v1/config/reload`.
- **Event cross-links** — Mitigation detail shows clickable triggering event and last event (TTL extend) links
- **GHCR Docker publishing** — CI publishes `prefixd` and `prefixd-dashboard` images to `ghcr.io` on push to main and version tags

### Security

- **SSRF protection** — Webhook URLs validated: HTTPS required, localhost and private/link-local IPs rejected
- **Secret merge ambiguity detection** — Errors on multiple same-type destinations instead of silent first-match
- **Atomic config writes** — Temp-file + `sync_all` + rename pattern for both playbooks and alerting; symlink targets rejected
- **Concurrent write serialization** — Both playbook and alerting PUT endpoints hold write locks across merge/validate/save/swap
- **reload_config() race fix** — Write locks held during load+swap to prevent stale overwrite from concurrent PUT
- **JSON parse rejection** — PUT endpoints return 400 on malformed JSON (not 500)
- **Event ID encoding** — All event ID query params in frontend links use `encodeURIComponent`
- **YAML boolean coercion fix** — Strict `=== true` check prevents `Boolean("false")` from being truthy
- **Stable React keys** — Playbook/step/destination editors use unique IDs instead of array indices

### Changed

- Backend unit tests: 93 → 116 (playbook validation, alerting validation, secret merge, SSRF, save/roundtrip, symlink rejection)
- Integration tests: 9 → 25 (playbook PUT, alerting PUT, SSRF rejection, hot-reload path, bearer auth)
- Frontend tests: 26 (unchanged)

## [0.9.1] - 2026-02-21

### Added

- **Webhook alerting backend** — 7 destination types: Slack (Block Kit), Discord (embeds), Microsoft Teams (Adaptive Card), Telegram (Bot API), PagerDuty (Events API v2 with auto-resolve on withdraw/expire), OpsGenie (Alert API v2), Generic webhook (HMAC-SHA256 signed). Fire-and-forget via tokio::spawn with 3 retries and exponential backoff. Configurable event type filtering. `prefixd_alerts_sent_total{destination,status}` Prometheus counter.
- **Alerting API endpoints** — `GET /v1/config/alerting` (secrets redacted) and `POST /v1/config/alerting/test` (sends test alert, returns per-destination pass/fail)
- **Chaos test suite** — `scripts/chaos-test.sh` with 17 resilience tests across 4 categories: Postgres chaos (kill during ingestion, restart recovery, state preservation), GoBGP chaos (kill during mitigations, reconciliation re-announce), prefixd chaos (restart, rapid restart, SIGKILL recovery), network chaos (nginx outage and recovery)
- **HTTP load test suite** — `scripts/load-test.sh` with 7 tests across 5 profiles (quick/default/sustained/burst/all), using `hey` for HTTP benchmarking. Baseline results: ~8,000 health req/s, ~4,700 ingestion req/s, P99 1.6ms
- **Benchmarks documentation rewrite** — `docs/benchmarks.md` updated with fresh criterion micro-benchmark numbers, HTTP load test baselines, chaos test summary, bottleneck analysis, and instructions for running all three test suites

### Security

- **Login brute-force protection** — Per-username rate limiting (5 attempts per 60-second window) on `POST /v1/auth/login`, returns 429 when exceeded
- **Input validation sweep** — victim_ip validated as real IP address in `ingest_event` and `create_mitigation`; safelist prefix validated as CIDR/IP; string length limits on all user input fields (1024 general, 64 username, 256 password); username format validation (alphanumeric, dash, underscore); max password length to prevent argon2 DoS
- **Audit pagination bounded** — `list_audit` endpoint now applies `clamp_limit()` (was unbounded)
- **Request ID hardened** — `x-request-id` header capped at 128 characters with character validation, removed `.expect()` panics
- **CSV formula injection fix** — CSV export now prefixes cells starting with `=`, `+`, `-`, `@`, `\t`, `\r` with a single quote to prevent spreadsheet formula injection
- **Client token exposure removed** — Removed `NEXT_PUBLIC_PREFIXD_TOKEN` from frontend bundle (session cookies are sufficient for browser auth)
- **Login throttle race condition fixed** — Merged separate check/record into atomic `check_and_record_login_attempt` (single lock scope), added TTL pruning and 10K tracked-user cap to prevent unbounded memory growth
- **Generic webhook header redaction** — `GET /v1/config/alerting` now masks all custom header values with `***` (previously leaked raw values)
- **CIDR validation hardened** — Safelist prefix validation now uses `ipnet::IpNet` parser, rejecting invalid masks like `/999`
- **Alerting test endpoint admin-only** — `POST /v1/config/alerting/test` now requires admin role; frontend button gated behind permissions
- **CSV formula regex hardened** — Catches leading whitespace/newline before formula characters (`=`, `+`, `-`, `@`)
- **Alert queue bounded** — Semaphore caps in-flight alert tasks at 64; excess alerts logged and dropped

### Frontend

- **Alerting config UI** — New "Alerting" tab on Config page showing configured destinations (read-only, secrets redacted) with "Send Test Alert" button reporting per-destination pass/fail
- **Audit log detail expansion** — Click truncated details cells to expand full JSON inline; extracted AuditRow sub-component
- **Customer/POP filter on mitigations** — Dropdown filters using existing backend `?customer_id=` and `?pop=` query params
- **Timeseries range selector** — 1h/6h/24h/7d toggle buttons on activity chart with appropriate bucket sizes (5m/30m/1h/6h)
- **Active count badge on sidebar** — Live mitigation count badge on Mitigations nav item (collapsed and expanded modes)
- **Severity badges on mitigations** — Color-coded severity column (critical/high/medium/low) derived from status + action_type

### Changed

- Backend unit tests increased from 73 to 93 (alerting formatters, HMAC, CIDR validation, login throttle, header redaction)
- Frontend tests increased from 25 to 26 (added CSV injection regression test)
- OpenAPI spec now includes alerting endpoints
- Load/chaos test scripts support optional `PREFIXD_API_TOKEN` for authenticated environments

## [0.9.0] - 2026-02-20

### Added

- **Embedded time-series charts on overview** — 24h area chart showing mitigations and events per hour, PostgreSQL-backed with gap-filled buckets via `GET /v1/stats/timeseries`
- **IP history page** (`/ip-history?ip=X`) — Unified timeline of all events and mitigations for an IP, with customer/service context from inventory, via `GET /v1/ip/{ip}/history`
- **Clickable IPs everywhere** — All victim_ip cells in mitigations table, events table, active mitigations mini, mitigation detail, and event detail panel link to IP history
- **IP History in navigation** — Added to sidebar, command palette (`g h`), keyboard shortcuts
- **Database pool metrics** — `prefixd_db_pool_connections{state=active|idle|total}` gauge exposed to Prometheus on each `/metrics` scrape
- **Request correlation IDs** — Every request gets an `x-request-id` (UUID), preserved if client-provided, echoed in response, added to tracing span. nginx config forwards it.
- **HTTPS via nginx production example** — Full TLS termination config with HSTS, HTTP→HTTPS redirect, Let's Encrypt note
- **Reconciliation loop pagination** — Pages through all active mitigations instead of capping at 1000; adds `prefixd_reconciliation_active_count` gauge metric
- **Database migration tracking** — `schema_migrations` table records applied migrations with version, name, and timestamp; `prefixdctl migrations` command to check status
- **API versioning policy** — `docs/api-versioning.md` documents backward compatibility guarantees, deprecation process, and `Sunset` header convention
- **Upgrade guide** — `docs/upgrading.md` covers Docker Compose and bare metal upgrade procedures, rollback guidance, and migration verification
- **IP validation on history endpoint** — Returns 400 on invalid IP input
- **4 new tests** — IP history rejects invalid IP, timeseries sub-hour bucket alignment, plus 2 timeseries/IP-history structure tests
- **CSV helper tests** (4 tests: headers/rows, comma escaping, quote escaping, null handling)

### Changed

- **Mitigate Now is now a modal dialog** - Opens over the mitigations list instead of navigating to a separate page; command palette and `n` shortcut open the modal directly
- **Removed `/mitigations/create` route** - Replaced by modal, no redirect needed
- **Upgraded recharts** 3.6.0 → 3.7.0
- **prefixdctl default endpoint** changed to `http://127.0.0.1` (nginx entrypoint, was `:8080`)
- **prefixdctl role validation** now includes `operator` role (was admin/viewer only)

### Fixed

- **Timeseries sub-hour bucketing** — `date_trunc('hour')` replaced with `date_bin()` for correct 5m/30m bucket alignment
- **Frontend TypeScript types** — chart.tsx recharts 3.7 tooltip/legend types, resizable.tsx API rename, badge component prop types widened to match backend values
- **CLI/docs drift** — Removed references to nonexistent `prefixdctl health` and `events` commands, fixed stale endpoint paths across all docs
- **CSV export crash on events page** - Was referencing `e.timestamp` which doesn't exist (correct field is `event_timestamp`); added null guard in CSV helper
- **Nested anchor in active-mitigations-mini** — Replaced with keyboard-accessible div+router.push wrapper
- **Activity chart loading states** — Merges buckets from both timeseries sources, shows loading/error/empty states

## [0.8.5] - 2026-02-19

### Added

- **Hook tests** - usePermissions (5 tests: auth disabled, admin, operator, viewer, deny-by-default) and useAuth (5 tests: provider guard, loading, login, logout, auth-expired event)
- **Activity feed clickable items** - Event entries link to `/events?id={id}`, mitigation-related audit entries link to `/mitigations/{id}`
- **Vector breakdown chart clickable** - Legend items link to mitigations filtered by vector
- **Inventory cross-links** - Customer IDs and asset IPs link to `/mitigations?ip={value}`
- **Mitigations search** - Now matches on vector, customer_id, and mitigation_id (was IP-only)
- **Dependency upgrades** - react-resizable-panels 2.1 → 4.6

## [0.8.4] - 2026-02-19

### Added

- **Manual mitigation creation** - "Mitigate Now" form at `/mitigations/create`
  - Fields: destination IP, attack vector, traffic metrics (bps/pps), ports, confidence slider
  - Submits `POST /v1/events` with `action: "ban"`, policy engine handles the rest
  - Permission-gated (operator + admin only), accessible from mitigations toolbar and command palette
- **Mitigation detail full-page view** - Dedicated drill-down page for mitigations (`/mitigations/{id}`) replacing the slide-over panel
  - Shows FlowSpec rule JSON preview and active configuration
  - Mitigation timeline visualizing Created → Escalated → Withdrawn/Expired events
  - Embedded Customer Context section querying the running inventory
  - Direct withdraw capabilities and status badges
- **Real-time toast notifications** - Operational events over WebSocket now surface as toast notifications in the UI:
  - Red/Error: New mitigation created
  - Yellow/Warning: Mitigation escalated
  - Green/Success: Mitigation withdrawn
  - Blue/Info: Mitigation expired or config reloaded
- **Inline withdraw button on mitigations table** - XCircle button on active/escalated rows with confirmation dialog
  - Optional reason field, permission-gated (operator + admin only)
  - Tooltips on view and withdraw action buttons
- **Per-peer BGP session detail on admin page** - Shows each peer name and session state (established/down) instead of a single boolean
- **ErrorBoundary for dashboard pages** - React class ErrorBoundary wraps all `(dashboard)/` routes; displays error message and "Try Again" button instead of blank screen
- **Admin page tabbed layout** - Refactored from long scroll to Tabs (Status, Safelist, Users); Users tab conditionally rendered for admins
- **Vitest + Testing Library** - Frontend test infrastructure with 11 tests (ErrorBoundary component, IP/port validation)
- **"Mitigate Now" in command palette** - Quick action entry to jump to manual mitigation form
- **CSV export** - Download button on mitigations, events, and audit log tables
  - Exports current filtered view as CSV (client-side, no backend)
  - Filename includes current date (e.g., `mitigations-2026-02-19.csv`)
- **Keyboard shortcuts** - `g i` (inventory), `n` (Mitigate Now), `?` toggles help modal
  - Removed phantom table navigation shortcuts (j/k/Enter) from help modal
- **Cross-entity navigation** - Wired up dead-end UI elements across dashboard:
  - Command palette mitigation search links directly to `/mitigations/{id}` (was broken `?id=` param)
  - Mitigation detail `triggering_event_id` links to events page with event auto-selected
  - Events page reads `?id=` param to auto-open detail panel
  - Mitigations page reads `?ip=` param to pre-fill search filter
  - Audit log `target_id` links to `/mitigations/{id}` when target_type is mitigation
  - Overview stat cards are clickable, linking to mitigations/events pages

### Security

- **`POST /v1/events` now requires authentication** - `ingest_event` handler was missing `require_auth()` call; direct API calls could bypass auth when enabled

### Fixed

- **Mitigation detail customer context crash** - Was accessing `inventory.inventory` instead of `inventory.customers` (correct API shape)
- **Missing `Check` icon import** on mitigation detail page caused runtime error on "Copy JSON"
- **IP validation on Mitigate Now form** - Replaced permissive regex with octet-validating function (rejects `999.1.1.1`, `256.0.0.1`)
- **ErrorBoundary no longer leaks internal error messages** - Raw `error.message` removed from UI, errors logged to console only
- **Admin health status badge** - Was checking for `"healthy"` but API returns `"ok"`, so the badge always showed destructive red
- **Dark mode hover on admin reload button** - Added explicit dark mode hover classes for proper contrast
- **Documentation sweep** - Fixed stale version strings, incorrect API field names, wrong endpoint paths, and missing changelog comparison links across api.md, deployment.md, AGENTS.md

## [0.8.3] - 2026-02-18

### Added

- **Config Page** - Read-only view of running daemon configuration
  - Settings tab with allowlist-redacted JSON view (sensitive fields never exposed)
  - Playbooks tab with escalation step visualization (action, rate, TTL, confidence thresholds)
  - Hot-reload button (triggers `POST /v1/config/reload`) with auto-clearing feedback
  - Gated behind `canReloadConfig` permission for admin users
- **Inventory Page** - Searchable customer/service/IP asset browser
  - Expandable customer cards with policy profile badges
  - Service listings with allowed port display (TCP/UDP)
  - Search covers customer ID, name, policy profile, service, IP, role, and port numbers
  - Stats bar showing total customers, services, and IPs
- **`GET /v1/health/detail`** - Authenticated health endpoint with full operational data
  - BGP session states, database status, GoBGP connectivity, uptime, active mitigations
  - Replaces the old public health endpoint for operational monitoring
- **`GET /v1/config/settings`** - Running config with allowlist redaction
- **`GET /v1/config/inventory`** - Customer/service/IP data with load timestamps
- **`GET /v1/config/playbooks`** - Playbook definitions with load timestamps
- **Auth-disabled indicator** - Sidebar shows "Auth disabled" badge when running with `auth: none`
- **Session expiry handling** - 401 responses trigger automatic redirect to login page
  - Debounced `prefixd:auth-expired` event (2s window) prevents redirect storms
  - SWR retries suppressed on 401 to avoid noisy retry loops

### Changed

- **Route guard architecture** - Auth guard moved from `DashboardLayout` component to `app/(dashboard)/layout.tsx` route group
  - All dashboard pages automatically protected; new pages added to the group are guarded by default
  - Login page remains outside the guard at `app/login/page.tsx`
- **Public health endpoint slimmed** - `GET /v1/health` now returns only `{status, version, auth_mode}`
  - No database or GoBGP calls (lightweight liveness check)
  - Reduces unauthenticated attack surface
- **Settings redaction switched to allowlist** - Only explicitly safe fields are exposed
  - Previously used denylist (new fields leaked by default)
  - Omits: TLS paths, LDAP/RADIUS configs, bearer token env vars, BGP passwords, gRPC endpoints, router ID, audit log path, safelist prefixes
- **`loaded_at` timestamps are now accurate** - Settings shows startup time, inventory/playbooks show actual load/reload time
  - Previously showed request time (`Utc::now()`) which was misleading
- **Login page redirects** - Already-authenticated users and auth:none users redirected to `/` instead of showing login form
- **prefixdctl** - `status` and `peers` commands now use `/v1/health/detail`
- **RwLock guards dropped early** - Inventory and playbooks handlers clone data and release locks before building JSON response
- **Route definitions deduplicated** - `create_router()` and `create_test_router()` now share `public_routes()`, `session_routes()`, `api_routes()`, and `common_layers()` helpers (eliminates ~80 lines of duplication)
- **OpenAPI spec updated** - All new endpoints (`health_detail`, `config/settings`, `config/inventory`, `config/playbooks`) registered with utoipa annotations and `PublicHealthResponse` schema
- **API documentation** - `docs/api.md` updated with config endpoint documentation, example payloads, and health endpoint migration note
- **Integration test coverage** - 4 new tests: `health_detail` (validates full operational response), `config_settings` (verifies allowlist redaction of sensitive fields), `config_inventory`, `config_playbooks` (12 integration tests total, up from 8)

### Security

- Allowlist redaction prevents accidental exposure of new sensitive config fields
- Public health endpoint no longer exposes BGP peer IPs, database status, or mitigation counts
- Deny-by-default permission model: no permissions granted until both auth and health state resolve
- Frontend permissions derived from backend `auth_mode` field (not inferred from missing session)

## [0.8.2] - 2026-02-18

### Fixed

- **Dashboard BGP Status** - Health indicator now checks actual BGP peer session state (`established`) instead of just GoBGP gRPC connectivity (contributed by @bswinnerton)
- **Dashboard POP Selector** - POP dropdown in TopBar now loads dynamically from the backend API (contributed by @bswinnerton)
  - Replaced hardcoded POP list with `usePops()` and `useHealth()` hooks
  - Current POP from health endpoint used as default selection
- **`GET /v1/pops` Endpoint** - Current instance POP now always included in response (contributed by @bswinnerton)
  - Newly deployed POPs with no mitigations are no longer invisible to the API
- **Lab Setup** - Fixed unreliable lab networking and stale instructions
  - FRR lab now assigns deterministic IP to GoBGP (`--ip 172.30.30.10`)
  - Fixed FRR bgpd.conf peer address to match
  - Fixed stale `gobgp neighbor add` comment in cJunos lab (neighbor is pre-configured)
  - Removed orphaned `gobgp-cjunos.conf` (wrong AS/IPs, not referenced)
  - Fixed vJunos comment: works on AMD bare metal too, issue is nested virt not CPU vendor

### Added

- **Juniper cJunosEvolved FlowSpec Lab** - End-to-end verified with real Junos router
  - cJunosEvolved PTX10002-36QDD (Junos Evolved 25.4R1.13-EVO) containerlab topology
  - Full lifecycle tested: event ingestion → policy engine → GoBGP → Juniper inetflow.0
  - FlowSpec discard, rate-limit (police), multi-port rules, and TTL-based withdrawal confirmed
  - cJunos peers directly with prefixd docker-compose GoBGP (no separate lab GoBGP)
  - Documented vendor quirks: FlowSpec-only AFI-SAFI required, FXP0ADDR token, BGP license warning
  - Updated lab/README.md with cJunos quick start and troubleshooting
  - Added cJunosEvolved neighbor config to configs/gobgp.conf
- **Lab Test Script** - `lab/test-flowspec.sh` for automated end-to-end FlowSpec verification
  - Checks prefixd health, GoBGP, BGP neighbors, sends test event, verifies RIB
  - Optional `--withdraw` flag to test full announce/withdraw lifecycle
- **WebSocket Runtime URL** - WS connection now derived from `window.location` at runtime
  - No build-time env var needed; works behind any reverse proxy (nginx, caddy, etc.)
  - Removed `NEXT_PUBLIC_PREFIXD_WS` build arg from Dockerfile
- **Favicon** - Replaced Vercel placeholder with prefixd shield icon (dark/light mode PNGs + SVG)
- **Light/Dark Mode Toggle** - Dashboard now supports light mode with a theme toggle in the top bar
  - Uses `next-themes` with system preference detection
  - Defaults to dark mode, persists user preference
- **Nginx Reverse Proxy** - Single-origin deployment via nginx in docker-compose
  - All traffic (API, WebSocket, dashboard) served through port 80
  - No build-time URL configuration needed
  - WebSocket upgrade handled transparently
- **Grafana Dashboards** - Provisioned Grafana and Prometheus in docker-compose
  - Operations dashboard: active mitigations, BGP sessions, HTTP latency, reconciliation
  - Security dashboard: events by source/vector, guardrail rejections, escalations
  - Auto-provisioned datasource and dashboards on startup

### Changed

- Lab documentation rewritten to reflect cJunos as recommended Juniper test option
- vJunos-router documented as bare-metal only (cannot run in VMs per Juniper docs)
- Nokia SR Linux confirmed as lacking FlowSpec support (SR OS only)
- Removed Vercel Analytics (`@vercel/analytics`) - self-hosted tool shouldn't phone home
- Removed duplicate lowercase PR template (case collision on macOS/Windows)
- Docker Compose now uses nginx as single entrypoint (port 80) instead of exposing individual service ports
- CI security audit switched from manual `cargo-audit` install to `actions-rust-lang/audit@v1` (3 min faster)
- CORS origin is now configurable via `cors_origin` in `prefixd.yaml` (omit when behind a reverse proxy)
- Removed hardcoded `localhost:3000` CORS origin
- Architecture Decision Records (ADRs) added to `docs/adr/`

### Security

- Fixed `bytes` integer overflow in `BytesMut::reserve` (RUSTSEC-2026-0007, updated 1.11.0 → 1.11.1)
- Fixed `time` crate DoS via stack exhaustion (RUSTSEC-2026-0009, updated 0.3.45 → 0.3.47)

## [0.8.1] - 2026-02-01

### Fixed

- **Frontend API Proxy** - Dashboard now works on remote servers without hardcoded URLs
  - Added `/api/prefixd/[...path]` Next.js API route to proxy requests to backend
  - Removed `NEXT_PUBLIC_PREFIXD_API` build-time env var (was baked into bundle)
  - Added `PREFIXD_API` server-side env var for backend URL
  - Browser only talks to dashboard on port 3000, never directly to API

- **Session Table Schema** - Fixed `tower_sessions.session` table creation
  - Migration now creates correct schema/table name for `tower-sessions-sqlx-store`
  - Users no longer need to manually create the session table

- **Bun Lockfile** - Removed `--frozen-lockfile` from frontend Dockerfile
  - Fixes build failures on systems with different bun versions

- **Security** - Fixed Next.js DoS vulnerability via Image Optimizer (npm audit fix)

### Changed

- Removed obsolete `version: '3.8'` from docker-compose.yml
- Updated dependencies: tonic 0.14.3, clap 4.5.56, Radix UI components

## [0.8.0] - 2026-01-28

### Added

- **Three-Role RBAC System**
  - `viewer` role: read-only access to dashboard and API
  - `operator` role: can withdraw mitigations
  - `admin` role: full access including user management
  - `require_role()` RBAC helper with hierarchical permission checks
  - Operator CRUD API: `GET/POST /v1/operators`, `DELETE /v1/operators/{id}`, `PUT /v1/operators/{id}/password`
  - `AuthMode::Credentials` for session-based authentication
  - LDAP config placeholder struct for future implementation

- **User Management UI**
  - Admin page User Management section (admin only)
  - Create operator form with username, password, role selection
  - Delete operator with confirmation dialog (prevents self-delete)
  - Change password dialog (admin can change any, users can change own)
  - Role badges with color coding (admin=red, operator=blue, viewer=gray)
  - `usePermissions()` hook for frontend role checks
  - Admin nav link hidden for non-admin users
  - Withdraw button hidden for viewers in mitigation detail panel

- **Unified Detector Events API**
  - `POST /v1/events` now accepts `action` field: `"ban"` (default) or `"unban"`
  - Unban events find original event by `external_event_id` and withdraw mitigation
  - `raw_details` JSONB field for storing forensic data from detectors
  - Deterministic withdrawal via event correlation (no guessing by IP)

- **FastNetMon Integration**
  - `scripts/prefixd-fastnetmon.sh` notify script for FastNetMon Community
  - Computes stable `event_id` for idempotency and ban/unban matching
  - Auto-detects vector from attack details (UDP/SYN/ACK/ICMP)
  - `docs/detectors/fastnetmon.md` setup guide

- **API/Frontend Contract Fixes**
  - Health endpoint now returns `version`, `pop`, `uptime_seconds`
  - mTLS auth mode now works correctly (was returning 401)
  - Fixed `operator_id` payload names in withdraw/safelist API calls

- **Frontend Animations**
  - Detail panels slide in from right (150ms, ease-out)
  - Activity feed items with staggered entrance
  - Status badge pulse animation on active items
  - BGP status breathing animation when session UP
  - All animations respect `prefers-reduced-motion`
  - Custom webkit scrollbars matching theme

- **FRR FlowSpec Lab**
  - Containerlab topology with FRR 10.3.1 as FlowSpec receiver
  - Works on any Linux host (no nested virtualization required)
  - Full end-to-end testing: event ingestion → policy → GoBGP → FRR
  - Documented Juniper labs for Intel VMX users

- **GoBGP Connection Fix**
  - Call `connect()` on GoBGP announcer at startup
  - Fixed BGP showing "not connected" in dashboard

- **Docker Compose Integration**
  - prefixd now connects to GoBGP and PostgreSQL via service names
  - BGP mode changed from `mock` to `sidecar` for real FlowSpec

### Fixed

- `confidence` field type mismatch: changed from `f64` to `f32` to match PostgreSQL `REAL`
- Events API was returning 500 due to sqlx type deserialization error

### Changed

- Default mode changed to `enforced` for lab testing (was `dry-run`)
- Removed dual-router lab configs for simplicity
- Updated lab README with Intel VMX requirements for Juniper

---

## [0.7.0] - 2026-01-18

### Added

- **WebSocket Real-Time Updates**
  - WebSocket endpoint at `/v1/ws/feed` for live mitigation/event updates
  - Message types: MitigationCreated, MitigationUpdated, MitigationExpired, MitigationWithdrawn, EventIngested, ResyncRequired
  - Broadcast channel integration in handlers and reconciliation loop
  - Lag detection with ResyncRequired message for client cache invalidation

- **Session-Based Authentication**
  - Operators table with argon2 password hashing
  - PostgreSQL session store via tower-sessions-sqlx-store
  - Login/logout/me endpoints (`/v1/auth/login`, `/v1/auth/logout`, `/v1/auth/me`)
  - Hybrid auth model: session cookies for browser, bearer tokens for API/CLI
  - `prefixdctl operators create` command for seeding operators

- **Frontend Authentication & Real-Time**
  - Login page with form validation and error handling
  - `useAuth` hook with AuthProvider context (memoized per React best practices)
  - `useWebSocket` hook with reconnection, SWR cache invalidation
  - `RequireAuth` component for protected routes
  - `ConnectionStatus` indicator in top bar
  - `UserMenu` dropdown with logout

- **Observability**
  - `prefixd_config_reload_total` counter metric (success/error)
  - `prefixd_escalations_total` counter metric
  - `prefixd_db_row_parse_errors_total` counter metric (tracks corrupted DB rows)
  - HTTP metrics via middleware:
    - `prefixd_http_requests_total{method,route,status_class}` counter
    - `prefixd_http_request_duration_seconds{method,route,status_class}` histogram
    - `prefixd_http_in_flight_requests{method,route}` gauge
  - Database connectivity status in `/v1/health` endpoint
  - GoBGP connectivity status in `/v1/health` endpoint (now structured: `{status, error}`)
  - Health endpoint now returns `"degraded"` status on DB or GoBGP failure
  - Warning logs for FlowSpec path parse failures in reconciliation

- **Security**
  - Request body size limit (1MB) via tower-http
  - Fix SQL injection in `list_mitigations` queries (now uses parameterized queries)
  - Hybrid auth on all API routes (session OR bearer token)
  - Secure cookies configurable based on TLS presence

- **CORS Support**
  - CORS headers for dashboard cross-origin requests
  - Credentials support for session cookies

- **Reliability**
  - GoBGP gRPC timeout handling (10s connect, 30s request)
  - GoBGP retry with exponential backoff (3 retries, 100ms-400ms)

- **API Validation**
  - Reject unknown protocol values (was silently converting to None)
  - Require `rate_bps` for `police` action type
  - Improved error messages with valid options listed

- **CI/CD**
  - GitHub Actions workflow (`.github/workflows/ci.yml`)
    - Test job (unit + integration with testcontainers)
    - Lint job (cargo fmt, clippy)
    - Build job (release binary artifact)
    - Docker job (build and push to ghcr.io)
    - Security audit job (cargo-audit)

- **Testing**
  - Integration tests with testcontainers (8 tests)
    - Full event → mitigation flow
    - Mitigation withdrawal via API
    - Duplicate event TTL extension
    - Pagination queries
    - Safelist blocking
    - Migration verification
    - TTL expiry via reconciliation
    - Configuration hot-reload (inventory + playbooks)

- **DevOps**
  - Dependabot configuration for Cargo, GitHub Actions, and npm
  - Pre-commit hooks configuration (fmt, clippy, test)

- **Guardrails**
  - Max TTL enforcement via `guardrails.max_ttl_seconds` config
  - Min TTL enforcement via `guardrails.min_ttl_seconds` config

### Fixed

- **Frontend API Integration**
  - Fix API response unwrapping (mitigations/events return `{items, count}` wrapper)
  - Fix Stats type to match backend (`total_active` instead of `active_mitigations`)
  - Fix HealthResponse type to match backend (structured `bgp_sessions`, `gobgp` object)
  - Fix PopInfo type (`{pop, active_mitigations}` objects instead of strings)
  - Fix SWR cache invalidation keys in WebSocket hook
  - Fix status filter query param (comma-separated instead of repeated)

- **Startup validation** - `auth.mode=bearer` without token now fails fast at startup (was returning 500 on every request)

- IPv6 prefix validation uses proper `IpAddr` parsing (was using contains(':') heuristic)
- `compute_scope_hash()` now deduplicates ports before hashing for consistency
- Bearer token cached at startup (was reading env var on every request)
- `Mitigation::from_row` now returns `Result` with error logging (was silently defaulting on parse failures)
- List queries now skip corrupted rows instead of failing entirely (with metric + log)
- Guardrails TTL bounds now fall back to `timers.min/max_ttl_seconds` if not set in guardrails config

- IPv6 support in `is_safelisted()` - now handles both IPv4 and IPv6 prefixes
- `is_safelisted()` performance - uses PostgreSQL inet operators instead of loading all entries

### Changed

- **Pagination**
  - Added `MAX_PAGE_LIMIT` (1000) - requests for larger pages are clamped
  - `list_events` now returns `EventsListResponse` with `count` (consistency with mitigations)

- **API Response** (breaking for clients parsing `total`)
  - Renamed `total` to `count` in `MitigationsListResponse`
  - Clarifies this is page size, not total count

- **Health Response** (breaking for clients parsing `gobgp` as string)
  - `gobgp` field now returns `{status: string, error?: string}` object
  - `database` field unchanged (string) for backward compatibility

- **Code Quality**
  - Consolidated duplicate route registrations in `routes.rs`

- **PostgreSQL-only storage** (breaking change)
  - Removed SQLite support entirely (~800 lines removed)
  - Simplified `StorageConfig`: `driver` removed, `path` → `connection_string`
  - Extracted `RepositoryTrait` for testability
  - Added `MockRepository` for fast unit tests
  - Tests now use `MockRepository` instead of SQLite in-memory

### Removed

- SQLite storage driver and all related code
- `StorageDriver` enum from configuration
- `storage.driver` config option

---

## [0.6.0] - 2026-01-17

### Added

- **Security & Authentication**
  - mTLS authentication with client certificate verification (rustls 0.23)
  - Security headers: X-Content-Type-Options, X-Frame-Options, Cache-Control
  - 5 auth integration tests (bearer flows, security headers validation)

- **Documentation**
  - `docs/configuration.md` - Complete YAML reference for all config options
  - `docs/deployment.md` - Docker, bare metal, GoBGP, router config, mTLS setup
  - `docs/troubleshooting.md` - Operational runbook with common issues
  - `docs/benchmarks.md` - Performance analysis with optimization recommendations

- **Benchmark Suite** (criterion)
  - Inventory lookup benchmarks (hit/miss/is_owned)
  - Database operation benchmarks (insert/get/list/count)
  - Serialization benchmarks (JSON serialize/deserialize)
  - Scaling benchmarks (DB list, inventory lookup by size)
  - Results: ~6K events/sec throughput, sub-ms API queries

- **Frontend Polish**
  - Live activity feed (replaces mock data with real API)
  - Config page with system status, BGP session, quotas, safelist viewer
  - Loading states with spinners, error states with icons
  - Empty state handling throughout dashboard

- Comprehensive unit test suite (84 tests total)
  - Guardrails tests: prefix validation, TTL, port count, IPv6 detection (18 tests)
  - BGP/GoBGP tests: NLRI construction, path attributes, RFC constants (16 tests)
  - Repository tests: CRUD, queries, pagination, safelist, multi-POP (18 tests)
  - Policy engine tests: evaluation, port intersection, protocols, TTL (13 tests)
- Next.js frontend dashboard (`frontend/`)
  - Dashboard overview with live stats, BGP status, quota gauges
  - Mitigations list with filtering, sorting, pagination (live API)
  - Events list with filtering, sorting, pagination (live API)
  - Audit log viewer with filtering (live API)
  - Dark mode support, keyboard shortcuts, command palette
  - SWR for data fetching with 5s refresh interval
  - Follows Vercel React best practices (deferred analytics, parallel fetching)
- New API endpoints
  - `GET /v1/events` - list events with pagination
  - `GET /v1/audit` - list audit log entries with pagination
- Audit log database storage (in addition to file-based logging)
- Docker support for frontend
  - `frontend/Dockerfile` using oven/bun image
  - Dashboard service in docker-compose.yml (port 3000)
- Bun package manager for frontend (faster installs)

### Changed

- **2026 Stable Dependencies**
  - axum 0.7 → 0.8, tower 0.4 → 0.5, tower-http 0.5 → 0.6
  - tonic 0.11 → 0.14, prost 0.12 → 0.14
  - sqlx 0.7 → 0.8, reqwest 0.11 → 0.12
  - utoipa 4 → 5, prometheus 0.13 → 0.14, thiserror 1 → 2

### Fixed

- Security vulnerabilities: sqlx 0.7.4 (RUSTSEC-2024-0363), protobuf 2.28.0
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

[Unreleased]: https://github.com/lance0/prefixd/compare/v0.17.1...HEAD
[0.17.1]: https://github.com/lance0/prefixd/compare/v0.17.0...v0.17.1
[0.17.0]: https://github.com/lance0/prefixd/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/lance0/prefixd/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/lance0/prefixd/compare/v0.14.1...v0.15.0
[0.14.1]: https://github.com/lance0/prefixd/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/lance0/prefixd/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/lance0/prefixd/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/lance0/prefixd/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/lance0/prefixd/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/lance0/prefixd/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/lance0/prefixd/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/lance0/prefixd/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/lance0/prefixd/compare/v0.8.5...v0.9.0
[0.8.5]: https://github.com/lance0/prefixd/compare/v0.8.4...v0.8.5
[0.8.4]: https://github.com/lance0/prefixd/compare/v0.8.3...v0.8.4
[0.8.3]: https://github.com/lance0/prefixd/compare/v0.8.2...v0.8.3
[0.8.2]: https://github.com/lance0/prefixd/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/lance0/prefixd/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/lance0/prefixd/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/lance0/prefixd/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/lance0/prefixd/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/lance0/prefixd/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/lance0/prefixd/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/lance0/prefixd/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/lance0/prefixd/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lance0/prefixd/releases/tag/v0.1.0
