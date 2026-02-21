# Features

Comprehensive list of prefixd capabilities.

---

## Signal Ingestion

### HTTP Event API

- `POST /v1/events` accepts attack signals from any detector
- Unified ban/unban: `action` field supports `"ban"` (default) or `"unban"`
- Schema: victim IP, attack vector, confidence score, optional ports/protocol
- Idempotent: duplicate events extend TTL instead of creating new mitigations
- Rate-limited: configurable token bucket (default 100 req/s burst, 10 req/s sustained)
- `raw_details`: JSONB field for storing forensic data from detectors

### Supported Detectors

Any system that can POST JSON works. Tested with:

- **FastNetMon Community** - Notify script integration ([setup guide](docs/detectors/fastnetmon.md))
- **Prometheus/Alertmanager** - Via webhook receiver
- **Custom scripts** - Simple curl calls

### Event Schema

```json
{
  "event_id": "stable-hash-for-idempotency",
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

When detector sends `action: "unban"` with the same `event_id`:
1. prefixd finds the original ban event by `source` + `event_id`
2. Looks up the active mitigation created from that event
3. Withdraws the FlowSpec rule from GoBGP
4. Updates mitigation status to "withdrawn"

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
        rate_bps: 10000000  # 10 Mbps rate limit
        ttl_seconds: 120
      - action: discard     # Escalate if attack persists
        ttl_seconds: 300
        require_confidence_at_least: 0.8
```

### Escalation Logic

- **Police first** - Rate-limit before dropping (less collateral damage)
- **Confidence thresholds** - Require higher confidence for discard actions
- **Persistence tracking** - Escalate only if attack continues after initial mitigation
- **Policy profiles** - Strict/normal/relaxed modes per customer

### Port Handling

- **Allowed ports exclusion** - DNS server under UDP flood? Block UDP except port 53
- **Port intersection** - Multiple events for same victim merge intelligently
- **Disjoint ports** - Parallel mitigations when port sets don't overlap

### Supported Attack Vectors

| Vector | Protocol | Default Response |
|--------|----------|------------------|
| `udp_flood` | UDP | Police → Discard |
| `syn_flood` | TCP | Discard |
| `ack_flood` | TCP | Discard |
| `icmp_flood` | ICMP | Discard |
| `dns_amplification` | UDP/53 | Police |
| `ntp_amplification` | UDP/123 | Police |
| `memcached_amplification` | UDP/11211 | Police |
| `chargen_amplification` | UDP/19 | Police |
| `ssdp_amplification` | UDP/1900 | Police |
| `generic` | Any | Configurable |

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
- **Auto-expiry** - Reconciliation loop withdraws expired rules

### Quotas

- **Per-customer limit** - Max active mitigations per customer
- **Per-POP limit** - Max active mitigations per point of presence
- **Global limit** - Hard cap across all mitigations

### Port Limits

- **Max ports per rule** - Default 8 (router memory protection)
- **Port validation** - Must be valid TCP/UDP port range

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

### GoBGP Integration

- **gRPC client** - Native GoBGP v4.x API integration
- **IPv4 FlowSpec** - AFI=1, SAFI=133
- **IPv6 FlowSpec** - AFI=2, SAFI=133
- **Retry logic** - Exponential backoff on transient failures
- **Connection management** - Automatic reconnection with state sync

### Tested Routers

End-to-end verified with real router implementations:

| Router | Platform | Status | Notes |
|--------|----------|--------|-------|
| **Juniper cJunosEvolved** | PTX10002-36QDD (25.4R1.13-EVO) | Verified | Announce, rate-limit, withdraw, TTL expiry |
| **FRR** | 10.3.1 | Verified | Native container, works everywhere |
| Juniper vJunos-router | vMX | Untested | Bare metal only (no VM support) |
| Arista cEOS | 7xxx series | Planned | |
| Cisco XRd | IOS-XR | Planned | |

#### Juniper-Specific Notes

- GoBGP must advertise **only** `ipv4-flowspec` AFI-SAFI to Juniper - advertising `inet-unicast` alongside causes Open Message Error (subcode 7)
- `no-validate` with import policy required for FlowSpec route acceptance
- `routing-options flow validation` and `term-order standard` must be configured
- BGP license warning is cosmetic - FlowSpec works without a license on cJunosEvolved
- Nokia SR Linux does **not** support FlowSpec (only SR OS 7750 does)

### FlowSpec NLRI Construction

Supported match criteria (RFC 5575):

| Component | Description |
|-----------|-------------|
| Destination prefix | /32 or /128 victim IP |
| Protocol | TCP, UDP, ICMP |
| Destination port | Single ports or ranges |

### FlowSpec Actions

| Action | Extended Community | Effect |
|--------|-------------------|--------|
| `discard` | traffic-rate 0 | Drop all matching traffic |
| `police` | traffic-rate N | Rate-limit to N bps |

### Example Announcement

```
Route Distinguisher: 0:0
Destination: 203.0.113.10/32
Protocol: UDP
Destination Port: !=53
Extended Community: traffic-rate: 10000000 (10 Mbps)
```

---

## Reconciliation

### Automatic State Management

The reconciliation loop runs every 30 seconds:

1. **Expire mitigations** - Withdraw FlowSpec rules past TTL
2. **Detect drift** - Compare desired state (DB) vs actual state (GoBGP RIB)
3. **Repair missing** - Re-announce rules that should exist but don't
4. **Clean orphans** - Withdraw rules in RIB that aren't in desired state

### Fail-Open Design

- If prefixd crashes, mitigations auto-expire via router TTL
- No permanent rules, no operator intervention required
- GoBGP can restart independently; prefixd re-syncs on reconnect

### WebSocket Notifications

Real-time events pushed to dashboard:

- `MitigationCreated` - New mitigation announced
- `MitigationUpdated` - TTL extended or action changed
- `MitigationExpired` - TTL reached, rule withdrawn
- `MitigationWithdrawn` - Manual withdrawal via API
- `EventIngested` - New attack event received
- `ResyncRequired` - Client should refresh (lag detected)

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
      - "2001:db8:acme::/48"
    services:
      - service_id: dns
        name: "DNS Servers"
        assets:
          - ip: "203.0.113.10"
          - ip: "2001:db8:acme::53"
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

- **Allowed ports** - Excluded from FlowSpec rules (don't block legitimate traffic)
- **Service classification** - Different policies per service type
- **Customer quotas** - Per-customer mitigation limits

### Hot Reload

- `prefixdctl reload` or `POST /v1/config/reload`
- Inventory and playbooks reload without restart
- Active mitigations preserved

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

### Alert Events

| Event Type | Severity | Trigger |
|---|---|---|
| `mitigation.created` | Warning | New mitigation announced |
| `mitigation.escalated` | Critical | Mitigation escalated (police → discard) |
| `mitigation.withdrawn` | Info | Manual or detector-driven withdrawal |
| `mitigation.expired` | Info | TTL reached, rule removed |

### Configuration

```yaml
alerting:
  destinations:
    - type: slack
      webhook_url: "https://hooks.slack.com/services/..."
      channel: "#ddos-alerts"
    - type: pagerduty
      routing_key: "${PAGERDUTY_ROUTING_KEY}"
    - type: generic
      url: "https://example.com/webhook"
      secret: "${WEBHOOK_SECRET}"
  events:
    - mitigation.created
    - mitigation.escalated
```

### Design

- **Fire-and-forget** — Alerts spawned as background tasks, never block event processing
- **Retry with backoff** — 3 retries per destination (1s, 2s, 4s exponential)
- **Multiple destinations** — Multiple instances of same type supported (e.g., two Slack channels)
- **Event filtering** — Only send alerts for configured event types (default: all)
- **Secret redaction** — `GET /v1/config/alerting` never exposes webhook URLs or tokens
- **Test endpoint** — `POST /v1/config/alerting/test` sends a test alert to all destinations

---

## Dashboard

### Next.js Web UI

Real-time visibility into mitigation state:

- **Overview** - Active mitigations, BGP session status, quota usage, 24h activity chart
- **Mitigations** - List with filtering, sorting, pagination, inline withdraw, CSV export
- **Events** - Attack event history with CSV export
- **IP History** - Unified timeline per IP (events + mitigations + customer context)
- **Audit Log** - All actions with operator attribution, CSV export
- **Config** - System status, safelist viewer, hot-reload button
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
- **Auto-logout** - 7-day session expiry

### Real-Time Updates

- **WebSocket connection** - `/v1/ws/feed`
- **Live refresh** - Mitigations update without polling
- **Connection status** - Visual indicator in UI
- **Automatic reconnection** - Exponential backoff on disconnect

---

## CLI Tool

### prefixdctl

```bash
# Authentication
prefixdctl operators create --username admin --role admin
prefixdctl operators list

# Status
prefixdctl status              # Overview
prefixdctl peers               # BGP session status
prefixdctl status              # Detailed health check

# Mitigations
prefixdctl mitigations list
prefixdctl mitigations list --status active --customer acme
prefixdctl mitigations get <id>
prefixdctl mitigations withdraw <id> --reason "false positive"

# Safelist
prefixdctl safelist list
prefixdctl safelist add 10.0.0.1/32 --reason "router loopback"
prefixdctl safelist remove 10.0.0.1/32

# Operations
prefixdctl reload              # Hot-reload config
```

### Output Formats

```bash
prefixdctl -f json mitigations list  # JSON output
prefixdctl -f table mitigations list # Table output (default)
```

### Configuration

```bash
export PREFIXD_API=http://localhost
export PREFIXD_API_TOKEN=your-token-here
```

---

## Authentication & Authorization

### Auth Modes

| Mode | Use Case | Configuration |
|------|----------|---------------|
| `none` | Development/testing | `auth.mode: none` |
| `bearer` | API/CLI access | `auth.mode: bearer` + `auth.token` |
| `session` | Dashboard login | Automatic with operators table |

### Hybrid Model

- **Dashboard** - Session cookies (login form)
- **API/CLI** - Bearer token (Authorization header)
- **Both accepted** - Routes check session OR bearer token

### Operators

```sql
-- Created via CLI or Admin UI
prefixdctl operators create --username admin --password --role admin
```

### Role-Based Access Control

| Role | Dashboard | Mitigations | Withdraw | Safelist | Users | Config |
|------|-----------|-------------|----------|----------|-------|--------|
| `viewer` | Read | Read | No | Read | No | No |
| `operator` | Read | Read | Yes | Read | No | No |
| `admin` | Read | Read | Yes | Full | Full | Full |

**Permission hierarchy:** `admin > operator > viewer`

### User Management API (Admin Only)

```bash
# List all operators
GET /v1/operators

# Create operator
POST /v1/operators
{"username": "jsmith", "password": "...", "role": "operator"}

# Delete operator (cannot delete self)
DELETE /v1/operators/{id}

# Change password (self or admin)
PUT /v1/operators/{id}/password
{"new_password": "..."}
```

### Security Features

- **Argon2 password hashing** - Memory-hard, resistant to GPU attacks
- **Secure session storage** - PostgreSQL-backed, 7-day expiry
- **CORS configuration** - Whitelist dashboard origins
- **Request size limits** - 1MB body limit
- **Rate limiting** - Token bucket per endpoint

---

## Observability

### Prometheus Metrics

Exposed at `/metrics`:

```
# Mitigations
prefixd_mitigations_active{customer,pop}
prefixd_mitigations_created_total{customer,pop,action}
prefixd_mitigations_expired_total{customer,pop}
prefixd_mitigations_withdrawn_total{customer,pop,reason}

# Events
prefixd_events_ingested_total{source,vector}
prefixd_events_rejected_total{reason}

# BGP
prefixd_announcements_total{action,result}
prefixd_withdrawals_total{result}
prefixd_bgp_session_up{peer}

# Guardrails
prefixd_guardrail_rejections_total{reason}
prefixd_quota_usage{scope,customer}

# HTTP
prefixd_http_requests_total{method,route,status_class}
prefixd_http_request_duration_seconds{method,route,status_class}
prefixd_http_in_flight_requests{method,route}

# Operations
prefixd_config_reload_total{result}
prefixd_escalations_total{from_action,to_action}
prefixd_reconciliation_runs_total{result}
prefixd_reconciliation_active_count{pop}

# Database
prefixd_db_pool_connections{state=active|idle|total}

# Alerting
prefixd_alerts_sent_total{destination,status}
```

### Request Correlation IDs

Every request gets an `x-request-id` header (UUID). If the client provides one, it's preserved; otherwise a new one is generated. The ID is:
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

All state-changing operations logged:

```json
{
  "timestamp": "2026-01-18T10:30:00Z",
  "action": "mitigation_withdrawn",
  "operator_id": "jsmith",
  "mitigation_id": "abc123",
  "reason": "false positive",
  "ip": "10.0.0.50"
}
```

### Health Endpoints

`GET /v1/health` (public, lightweight liveness check):

```json
{
  "status": "ok",
  "version": "0.9.0",
  "auth_mode": "none"
}
```

`GET /v1/health/detail` (authenticated, full operational status):

```json
{
  "status": "ok",
  "version": "0.9.0",
  "pop": "iad1",
  "uptime_seconds": 86400,
  "active_mitigations": 3,
  "database": "ok",
  "gobgp": { "status": "ok" },
  "bgp_sessions": [{ "name": "edge1", "state": "established" }]
}
```

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

Each POP:
- Has its own GoBGP sidecar
- Announces to local routers
- Sees global state for visibility
- Operates independently if DB is partitioned

---

## Performance

Benchmarked on Docker Compose stack (see [benchmarks.md](docs/benchmarks.md)):

### HTTP Load Tests (end-to-end through nginx)

| Endpoint | Req/sec | Avg Latency | P99 Latency |
|----------|---------|-------------|-------------|
| `GET /v1/health` | ~8,000 | 1.3 ms | 2.6 ms |
| `GET /v1/mitigations` | ~4,800 | 2.1 ms | 3.1 ms |
| `POST /v1/events` (ingestion) | ~4,700 | 1.1 ms | 1.6 ms |
| Burst (50 concurrent) | ~4,930 | 8.1 ms | 53 ms |

### Micro-Benchmarks (criterion)

| Operation | Time | Throughput |
|-----------|------|------------|
| Inventory IP lookup | 156 ns | ~6.4M ops/sec |
| Scope hash (SHA-256) | 119 ns | ~8.4M ops/sec |
| JSON serialize mitigation | 880 ns | ~1.1M ops/sec |
| Mock DB insert | 1.36 µs | ~735K ops/sec |

### Resilience

- **Chaos tests:** 17/17 passing (Postgres kill, GoBGP kill, prefixd restart, nginx outage)
- **Load tests:** 7/7 passing across 5 profiles
- **Headroom:** ~100x over realistic DDoS detector event volume

### Resource Usage

Typical production deployment:

- **CPU:** <5% idle, <20% during event bursts
- **Memory:** ~50MB base, scales with active mitigations
- **Disk:** PostgreSQL storage only (no local state)
- **Network:** Minimal (gRPC to GoBGP, HTTP API)

---

## What's Not Included

prefixd is focused on FlowSpec policy automation. These are explicitly out of scope:

- **Inline packet scrubbing** - prefixd is control-plane only
- **L7/WAF analysis** - Focus is L3/L4 volumetric attacks
- **Detection algorithms** - Use existing detectors (FastNetMon, etc.)
- **Tbps-scale scrubbing** - Requires upstream/scrubber integration
- **Source-based filtering** - Disabled by default (too dangerous)

See [ROADMAP](ROADMAP.md) for planned features.
