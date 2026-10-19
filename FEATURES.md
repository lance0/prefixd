# Features

Implemented capabilities and operational limits. rustbgpd is the preferred
speaker integration and GoBGP remains selectable. For current build requirements,
backend selection and deployment defaults, use the
[speaker reference](docs/reference/speaker-backends.md) and
[quickstart](docs/tutorials/quickstart.md).

---

## Signal Ingestion

### HTTP Event API

- `POST /v1/events` accepts attack signals from any detector
- `POST /v1/events/batch` accepts up to 100 events per request with partial success semantics (202/207)
- Unified ban/unban: `action` field supports `"ban"` (default) or `"unban"`
- Schema: required timestamp, source, victim IP and vector; optional traffic,
  confidence and destination ports; automatic policy derives protocol from vector
- Deduplication: repeated source/external ban IDs return a conflict; a distinct
  event for an existing canonical owner can extend that mitigation's TTL
- Rate-limited: one configured token bucket shared by HTTP routes
- `raw_details`: JSONB field for storing forensic data from detectors

### Supported Detectors

Available ingestion paths (payloads must satisfy the selected adapter and authentication):

- **FastNetMon Community** - Notify script integration ([setup guide](docs/how-to/detectors/fastnetmon.md))
- **FastNetMon** (native webhook) - `POST /v1/signals/fastnetmon` accepts FastNetMon's JSON payload directly, classifies vector from traffic breakdown, configurable confidence mapping
- **Prometheus/Alertmanager** - `POST /v1/signals/alertmanager` accepts Alertmanager v4 webhook payloads, maps labels/annotations to event fields, handles batched alerts with per-alert results
- **Generic webhook adapter** - `POST /v1/signals/webhook/{name}` for detectors without a native adapter. Configured per-adapter in `correlation.yaml` with JSONPath field mappings, HMAC-SHA256 / bearer / none authentication, optional array batching via `root_path`, vector normalization, and confidence scaling. See ADR 020 and [docs/how-to/detectors/generic-webhook.md](docs/how-to/detectors/generic-webhook.md).
- **Corroborating signals** - `POST /v1/signals/corroborator` for coarse telemetry (router CPU, per-PoP interface utilization, customer NetFlow). Sources configured with `mode: corroborating` strengthen open signal groups without ever triggering mitigations on their own. See [ADR 021](docs/adr/021-corroborating-signals.md).
- **Custom scripts** - Simple curl calls to `POST /v1/events`

### Event Schema

```json
{
  "event_id": "stable-hash-for-idempotency",
  "timestamp": "2026-10-18T00:00:00Z",
  "source": "fastnetmon",
  "victim_ip": "203.0.113.10",
  "vector": "udp_flood",
  "bps": 1200000000,
  "pps": 800000,
  "confidence": 0.95,
  "top_dst_ports": [53, 123],
  "action": "ban",
  "raw_details": {"direction": "incoming"}
}
```

### Unban Flow

An unban matches the original source and external event ID. prefixd records
cleanup intent and retries deletion on the original speaker after uncertainty or
failure. See [withdrawal recovery](docs/reference/speaker-backends.md#withdrawal-recovery).

---

## Policy Engine

### YAML Playbooks

Define per-vector response policies:

```yaml
playbooks:
  - name: udp_flood
    match:
      vector: udp_flood
    steps:
      - action: police
        rate_bps: 10000000  # 10 Mbps policy rate
        ttl_seconds: 120
```

### Current Policy Execution

- The first matching playbook supplies its initial action and TTL.
- Optional multi-signal correlation applies source-count and confidence gates.
- A distinct event for the same canonical rule extends its existing owner.
- Automatic escalation is not implemented.

### Port Handling

Policy uses equality matches, not port exclusions. For UDP/TCP floods, explicit
nonempty event ports and service `allowed_ports` are intersected. Disjoint
nonempty lists are rejected with `422` / `NoAllowedPorts` before mitigation
creation or owner TTL extension. With no event ports, configured service ports
are used; with no service restriction, event ports are used. Deliberately
unconstrained inputs retain no destination-port restriction. The adapters do not
encode a rule such as "UDP except port 53".

### Supported Attack Vectors

| Vector | Automatic protocol |
| --- | --- |
| `udp_flood` | UDP (17) |
| `syn_flood`, `ack_flood` | TCP (6) |
| `icmp_flood` | ICMP (1) for IPv4, ICMPv6 (58) for IPv6 |
| `unknown` | No protocol constraint |

The selected playbook determines the action; a vector name does not imply a
built-in response. Detector-specific vector names need adapter normalization.

---

## Guardrails

Safety limits that prevent accidental broad impact.

### Prefix Restrictions

- **/32 only (IPv4)** - No broader prefixes allowed by default
- **/128 only (IPv6)** - Configurable via `dst_prefix_maxlen_v6`
- **Safelist protection** - Infrastructure IPs never mitigated

### TTL Enforcement

- **Mandatory TTL** - Every mitigation must have an expiration
- **Min/max bounds** - Configurable `min_ttl_seconds` and `max_ttl_seconds`
- **Auto-expiry** - The running reconciliation loop requests withdrawal and
  retries failed cleanup; the speaker has no controller TTL lease

### Quotas

- **Per-customer limit** - Max active mitigations per customer
- **Per-POP limit** - Max active mitigations per point of presence
- **Global limit** - Hard cap across all mitigations

### Port Limits

- **Max ports per rule** - Default 8 (router memory protection)
- **Port matching** - Lists of discrete destination-port equalities, not ranges

### Example Configuration

```yaml
guardrails:
  require_ttl: true
  min_ttl_seconds: 60
  max_ttl_seconds: 3600
  dst_prefix_maxlen: 32      # /32 only for IPv4
  dst_prefix_maxlen_v6: 128  # /128 only for IPv6
  max_ports: 8

quotas:
  max_active_per_customer: 10
  max_active_per_pop: 100
  max_active_global: 500
```

---

## BGP FlowSpec

### Selectable Speakers

rustbgpd is preferred; GoBGP remains supported and selectable through
configuration. Both use the same policy and lifecycle logic and support IPv4 and
IPv6 FlowSpec with discard or policing. Exact build, selection, transport and
observation details are in the [backend reference](docs/reference/speaker-backends.md).

The current rule scope is destination prefix, optional protocol and discrete
destination-port equalities. Policy rates use bits/sec; adapters convert wire
units. Automatic ICMP maps to protocol 1 for IPv4 and 58 for IPv6; the manual
API's `icmp` selector currently means protocol 1.

Saved intent, successful speaker acceptance and local read-back do not prove
router forwarding. The [backend checks](docs/reference/speaker-backends.md#readable-backend-qualification)
cover their stated RPC, restart and peer-receipt scope. Historical GoBGP-backed
router reports retain their original scope in the [vendor matrix](docs/reference/vendors.md).
ExaBGP and other production adapters remain planned.

### FlowSpec NLRI Fuzz Testing

- **proptest** — Property-based tests covering prefix parsing with arbitrary strings, NLRI v4/v6 build+decode roundtrip, full path roundtrip preserving nlri_hash, and action type roundtrip. Runs in CI with `cargo test`.
- **cargo-fuzz** — libFuzzer targets (`fuzz_prefix_parse`, `fuzz_nlri_decode`) for continuous offline fuzzing. Run with `cargo +nightly fuzz run <target>`.

---

## Blackhole Host Routes

### Manual Blackholes

An Admin can request a remotely triggered blackhole (RTBH) host route for an
owned victim from the dashboard or `POST /v1/mitigations` with
`"action": "blackhole"` ([ADR 027](docs/adr/027-blackhole-mitigations.md)). It
drops all traffic to the victim. Current limits:

- **Unleased.** A manual blackhole stays on the speaker if prefixd stops,
  until prefixd returns and expires it or an Admin deletes it on the speaker.
- **rustbgpd only.** GoBGP has no blackhole capability, and startup refuses
  `blackhole.enabled` without it or with an empty safelist.
- **Admin and typed confirmation.** Operators and bearer tokens get `403`; the
  victim IP must be typed twice and match exactly.
- **Stricter guardrails.** IPv4 `/32` or IPv6 `/128` only, a TTL capped at
  `blackhole.max_ttl_seconds` (3600 s by default), separate quotas, victim
  checks and a safelist recheck before every add.
- **Router qualification: FRR only.** prefixd records the route and the
  speaker's acceptance. Whether a router drops the traffic depends on its RTBH
  import policy. FRR 10.7.1 is qualified in the control plane and FIB; see the
  [FRR blackhole receipt](docs/reference/qualification/blackhole-frr-2026-10-19.md).

Blackholes are listed, shown and withdrawn by the existing dashboard views,
withdrawal endpoints and `prefixdctl mitigations` commands. See the
[manual blackhole API](docs/reference/api.md#manual-blackhole) and
[configuration](docs/reference/configuration.md#blackhole).

### Detector Blackholes

A playbook step with `action: blackhole` turns a detector ban, such as a
FastNetMon Community ban, into a blackhole for the victim
([FastNetMon guide](docs/how-to/detectors/fastnetmon.md#blackholes-rtbh)).

- **Source allowlist.** Only events whose `source` is listed in
  `blackhole.detector_sources` reach a blackhole step; others get `422`. The
  dashboard's mitigate-now dialog stays off this path unless listed.
- **Same guardrails as manual blackholes.** Ownership, safelist, quotas and the
  TTL cap apply. A repeated ban extends the blackhole to at most
  `blackhole.max_ttl_seconds` from now, and the FastNetMon unban withdraws it.
- **Dry-run first.** In dry-run mode a detector blackhole is recorded and
  audited and sends nothing.
- **Enforced without the injection lease.** The rustbgpd injection lease has
  not shipped, so enforced detector blackholes run unleased. They are refused
  unless `blackhole.detector_sources` is nonempty, and startup logs a warning,
  health detail reports `speaker.detector_unleased: true` and
  `prefixd_blackhole_detector_unleased` is `1`.
- **Remaining gap.** If prefixd is down for a long time while rustbgpd keeps
  running, detector blackholes stay announced until prefixd returns or an
  operator withdraws them. On return, reconciliation expires overdue
  blackholes and deletes routes that exactly match blackholes that already
  ended, audited as `orphaned after controller downtime`; unknown routes are
  only reported. The shipped
  [availability alerts](docs/how-to/grafana.md#availability-alerts) page when
  prefixd is down, has no active controller, or was holding blackholes when it
  stopped.

---

## Reconciliation

### Automatic State Management

Reconciliation runs at startup and at the configured interval. It retries pending
withdrawals and TTL cleanup, repairs missing eligible rules after a complete
successful local read, and repairs supported action differences under the
single-controller, exclusive-target contract. Unknown rules are preserved; a
failed read is not an empty RIB. See the
[backend reference](docs/reference/speaker-backends.md#rule-and-reconciliation-semantics).

### TTL and Recovery Limits

- The running controller enforces expiry; a separate speaker can retain rules
  past their deadline while prefixd is down. There is no router TTL lease.
- Lost local intent can be repaired after speaker restart; no fixed recovery
  time is promised.
- Dry-run cannot acknowledge deletion of previously enforced rules.

### WebSocket Notifications

Messages use snake_case `type` values:

- `mitigation_created` / `mitigation_updated`: desired mitigation state changed
- `mitigation_expired` / `mitigation_withdrawn`: terminal cleanup completed locally
- `event_ingested`: defined event-result shape; ingestion does not currently broadcast it
- `resync_required`: the client fell behind and must refresh

The feed is a notification channel, not a durable delivery log or enforcement
acknowledgement. See [WebSocket API](docs/reference/api.md#websocket).

---

## Multi-Signal Correlation

Combine weak signals from multiple detectors into high-confidence mitigation decisions. Example: FastNetMon reports a UDP flood at 0.6 confidence + Alertmanager fires a bandwidth alert = corroborated high-confidence mitigation.

### Signal Groups

Events targeting the same (victim_ip, vector) within a time window are grouped into a **signal group**. Each group tracks:

- Contributing events from multiple sources
- Derived confidence (weighted by source reliability)
- Corroboration status (whether the `min_sources` threshold is met)
- Source breakdown with per-source confidence and weight

### Corroboration Model

- **min_sources** - Minimum number of distinct sources required before mitigation triggers (default: 1 for backward compatibility)
- **confidence_threshold** - Minimum derived confidence to trigger mitigation
- **Per-playbook overrides** - Different thresholds per attack vector
- **Time-windowed** - Signal groups expire after `window_seconds` if corroboration is not met

### Source Weighting

Each detection source is assigned a weight reflecting its reliability:

```yaml
correlation:
  enabled: true
  window_seconds: 120
  min_sources: 2
  confidence_threshold: 0.7
  sources:
    fastnetmon:
      weight: 1.0
      type: detector
    alertmanager:
      weight: 0.8
      type: alert
  default_weight: 0.5
```

### Explainability

Every correlated mitigation includes a `correlation` field explaining the decision:

- Signal group ID and contributing sources
- Per-source confidence and weight
- Whether corroboration was met
- Human-readable explanation string

### Signal Groups API

- `GET /v1/signal-groups` - List groups with cursor pagination, status/vector/date filters
- `GET /v1/signal-groups/{id}` - Detail with contributing events, source weights, and confidence
- `GET /v1/config/correlation` - Current correlation config (secrets redacted)
- `PUT /v1/config/correlation` - Update config (admin only, validates, writes YAML, hot-reloads)

### Correlation Dashboard

- **Signals tab** - Recent events with source, confidence, and group assignment
- **Groups tab** - Signal groups with status, source count, confidence, corroboration status
- **Config tab** - Visual correlation config editor with source weights
- **Group detail page** - Contributing events, source breakdown, timeline
- **Mitigation detail integration** - Correlation context section on mitigated IPs

---

## Inventory

### Customer/IP Mapping

Map IPs to customers and services for context-aware policy:

```yaml
customers:
  - customer_id: acme
    name: "ACME Corporation"
    prefixes:
      - "203.0.113.0/24"
      - "2001:db8:100::/48"
    services:
      - service_id: dns
        name: "DNS Servers"
        assets:
          - ip: "203.0.113.10"
          - ip: "2001:db8:100::53"
        allowed_ports:
          udp: [53]
          tcp: [53]
      - service_id: web
        name: "Web Servers"
        assets:
          - ip: "203.0.113.20"
        allowed_ports:
          tcp: [80, 443]
```

### Context-Aware Mitigation

- **Service ports** - Participate in the equality-port selection described above
- **Service context** - Customer/service identifiers, names and port selection
- **Customer quotas** - Per-customer mitigation limits

### Hot Reload

- `prefixdctl reload` or `POST /v1/config/reload`
- Inventory, playbooks, correlation and alerting can reload without restart
- Reload preserves existing mitigation intent; it does not change the running
  POP, speaker target, main settings or controller mode

---

## Alerting / Webhooks

Push notifications to external systems on mitigation lifecycle events.

### Supported Destinations

| Destination | Format | Notes |
|---|---|---|
| **Slack** | Block Kit (header + sections + fields) | Incoming webhook URL |
| **Discord** | Rich embeds (title, color, fields, footer) | Webhook URL |
| **Microsoft Teams** | Adaptive Card via Power Automate webhook | Post-connector-deprecation format |
| **Telegram** | Bot API `sendMessage` with HTML formatting | Bot token + chat_id |
| **PagerDuty** | Events API v2 | Auto-resolve on withdraw/expire via dedup_key |
| **OpsGenie** | Alert API v2 | US and EU region support |
| **Generic Webhook** | Raw JSON payload | Optional HMAC-SHA256 signing (`X-Prefixd-Signature`) |

### Alert Event Formats

| Event Type | Severity | Trigger |
|---|---|---|
| `mitigation.created` | Warning | New desired mitigation persisted |
| `mitigation.escalated` | Critical | Escalation format; automatic escalation is not wired into the current event path |
| `mitigation.withdrawn` | Info | Manual or detector-driven cleanup completed locally |
| `mitigation.expired` | Info | TTL cleanup completed locally |

Creation alerts do not confirm enforcement. In dry-run, lifecycle notifications
describe local simulation, not a speaker mutation.

### Configuration

Use the [notification configuration reference](docs/reference/api.md#update-alerting-config) and the
administrator config API for destination settings, secrets and event filters.

### Design

- **Best-effort delivery** — Background tasks with bounded concurrency; no durable outbox
- **Retry with backoff** — Bounded retries per destination
- **Multiple destinations** — Multiple instances of same type supported (e.g., two Slack channels)
- **Event filtering** — Only send alerts for configured event types (default: all)
- **Secret redaction** — `GET /v1/config/alerting` never exposes webhook URLs or tokens
- **Test endpoint** — Administrator-only `POST /v1/config/alerting/test`

---

## Dashboard

### Next.js Web UI

Real-time visibility into mitigation state:

- **Overview** - Active mitigations, BGP session status, quota usage, 24h activity chart
- **Mitigations** - List with filtering, sorting, pagination, inline withdraw, bulk withdraw (multi-select), CSV export
- **Mitigate Now** - Operator modal (`n` shortcut, command palette action) posts policy-validated ban events
- **Events** - Attack event history with CSV export
- **IP History** - Unified timeline per IP (events + mitigations + customer context), with incident report generation
- **Audit Log** - Recorded operation history with actor attribution, CSV export
- **Incident Reports** - Generate markdown reports from mitigation detail or IP history pages (`GET /v1/reports/incident`). Summary, timeline, peak traffic, audit trail. Copy to clipboard or download .md
- **Config** - Settings viewer, playbook editor (form + YAML), alerting editor, hot-reload controls
- **Inventory** - Searchable customer/service/IP browser
- **Admin** - User management, safelist CRUD, system health (tabbed layout)
- **Embedded Charts** - 24h area chart on overview (PostgreSQL-backed timeseries with gap-filling)
- **Clickable IPs** - All victim_ip cells link to IP history page
- **Light/dark mode** - Theme toggle with system preference detection
- **Keyboard shortcuts** - `g o/m/e/i/h/a/c` navigation, `n` mitigate, `Cmd+K` palette, `?` help
- **Command palette** - Quick navigation and search (`Cmd+K`)

### Authentication

- **Session-based** - Login with username/password
- **Secure cookies** - HttpOnly, SameSite=Lax, optional Secure flag
- **Session expiry** - PostgreSQL-backed inactivity expiry

### Real-Time Updates

- **WebSocket connection** - `/v1/ws/feed`
- **Live refresh** - WebSocket messages invalidate cached API state; periodic refresh remains
- **Connection status** - Visual indicator in UI
- **Automatic reconnection** - Bounded linear backoff with jitter on disconnect

---

## CLI Tool

### prefixdctl

The CLI reads status/peers, lists and withdraws mitigations, manages the safelist
and reloads configuration. JSON and table output are available. Initial operator
setup uses direct database access. See the [CLI reference](docs/reference/cli.md)
for commands and mode-specific authentication.

---

## Authentication & Authorization

### Auth Modes

| Mode | Use Case | Configuration |
|------|----------|---------------|
| `none` | Development/testing | `http.auth.mode: none` |
| `bearer` | API/CLI access | `auth.mode: bearer` + `http.auth.bearer_token_env` |
| `credentials` | Dashboard login | `auth.mode: credentials` with operators table |
| `mtls` | Machine-to-machine | `auth.mode: mtls` + TLS client certs |

### Mode-Aware Model

- **Credentials mode** - Session cookies only
- **Bearer mode** - Bearer token accepted; existing dashboard session cookies also work
- **mTLS mode** - Native TLS client verification is required; accepted clients
  currently receive administrative API privileges, not per-certificate roles
- **WebSocket feed** - Requires a browser session unless auth is disabled;
  bearer authentication alone is not a WebSocket login

### Role-Based Access Control

| Role | Dashboard | Mitigations | Withdraw | Safelist | Users | Config |
|------|-----------|-------------|----------|----------|-------|--------|
| `viewer` | Read | Read | No | Read | No | No |
| `operator` | Read | Read | Yes | Read | No | No |
| `admin` | Read | Read | Yes | Full | Full | Full |

**Permission hierarchy:** `admin > operator > viewer`

Creating a [manual blackhole](#manual-blackholes) requires `admin`; bearer
tokens act as `operator` and cannot create one.

Account administration and self-service password changes are described in the
[operator API](docs/reference/api.md#operators-admin-only).

### Security Features

- **Argon2 password hashing** - Memory-hard, resistant to GPU attacks
- **Session storage** - PostgreSQL-backed, seven-day inactivity expiry
- **CORS configuration** - Whitelist dashboard origins
- **Request size limits** - 1MB body limit
- **Rate limiting** - Shared HTTP token bucket, plus login-attempt throttling

---

## Observability

### Prometheus Metrics

Exposed at `/metrics` on the private API listener: mitigation lifecycle/status,
events, speaker RPC outcomes, peer observation, guardrails, HTTP requests,
reconciliation, database and alerting metrics. Exact metric names and labels live in
[the definitions](src/observability/metrics.rs) and
[metrics reference](docs/reference/api.md#metrics).

Active gauges count database status and can include expired intent or pending
cleanup until terminal transition. Successful announcement counters acknowledge
local RPCs, not router enforcement. Unsupported or failed peer observations must
not be interpreted as confirmed absence.

### Request Correlation IDs

Requests use an `x-request-id` header. Client-provided IDs are preserved;
otherwise a UUID is generated. The ID is:
- Echoed in the response header
- Added to the tracing span for log correlation
- Forwarded through nginx

### Structured Logging

JSON format for log aggregation:

```json
{
  "timestamp": "2026-01-18T10:30:00Z",
  "level": "info",
  "target": "prefixd::api::handlers",
  "message": "mitigation created",
  "mitigation_id": "abc123",
  "customer_id": "acme",
  "dst_prefix": "203.0.113.10/32",
  "action": "police",
  "ttl_seconds": 120
}
```

### Audit Log

The audit API exposes actor, action, target and details. Completed withdrawals
retain their original actor, reason and operation ID; uncertain cleanup stays
pending. See the [audit API](docs/reference/api.md#audit-log).

### Health Endpoints

| Endpoint | Access | Meaning |
| --- | --- | --- |
| `GET /v1/health` | Public | Lightweight liveness, package version and auth mode |
| `GET /v1/ready` | Public | `200` only while this controller holds its POP's fence and is not draining; use for load balancers and detector routing |
| `GET /v1/health/detail` | Mode-aware authentication | Controller uptime, database/status counts, selected backend/capabilities, peer observation and separate daemon metadata |

Top-level uptime belongs to the controller. `speaker.daemon` separately reports
observed rustbgpd version, process uptime, readiness and observation time; GoBGP
process metadata is explicitly unsupported. Health does not confirm forwarding.
See the [health reference](docs/reference/api.md#operational-endpoints).

---

## Multi-POP Support

### Shared Database Model

Multiple prefixd instances share PostgreSQL:

- Each instance filters by its `pop` field
- Cross-POP visibility via `?pop=all` queries
- `/v1/stats` aggregates across all POPs
- `/v1/pops` lists known POPs

### Example Deployment

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  prefixd    │     │  prefixd    │     │  prefixd    │
│  (iad1)     │     │  (fra1)     │     │  (sin1)     │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                    ┌──────┴──────┐
                    │  PostgreSQL │
                    │   (shared)  │
                    └─────────────┘
```

Each POP binds to one registered backend/endpoint/namespace target, with a
separate speaker and one controller. Global visibility does not authorize
cross-POP mutations. Database loss prevents state-dependent operations; the
independent speaker may retain existing routes, but the controller does not
continue safely without PostgreSQL.

Bindings are startup consistency checks, not interprocess fencing or DNS-alias
detection. Pending withdrawals retain their original speaker target. A separate
PostgreSQL advisory-lock fence keeps a second controller for the same POP and
target in standby when both share the database.

---

## Performance

[Historical benchmarks](docs/perf/benchmarks.md) retain their original test
scope. They do not establish current production capacity or recovery deadlines.
New performance claims need dated inputs and retained results.

---

## What's Not Included

prefixd is focused on FlowSpec policy automation. These are explicitly out of scope:

- **Inline packet scrubbing** - prefixd is control-plane only
- **L7/WAF analysis** - Focus is L3/L4 volumetric attacks
- **Detection algorithms** - Use existing detectors (FastNetMon, etc.)
- **Tbps-scale scrubbing** - Requires upstream/scrubber integration
- **Source-based filtering** - Disabled by default (too dangerous)

See [ROADMAP](ROADMAP.md) for planned features.
