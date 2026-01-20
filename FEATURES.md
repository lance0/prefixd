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

- `prefixdctl reload` or `POST /v1/admin/reload`
- Inventory and playbooks reload without restart
- Active mitigations preserved

---

## Dashboard

### Next.js Web UI

Real-time visibility into mitigation state:

- **Overview** - Active mitigations, BGP session status, quota usage
- **Mitigations** - List with filtering, sorting, pagination
- **Events** - Attack event history
- **Audit Log** - All actions with operator attribution
- **Config** - System status, safelist viewer

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
prefixdctl health              # Detailed health check

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
export PREFIXD_API=http://localhost:8080
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
-- Created via CLI or direct insert
prefixdctl operators create --username admin --password --role admin
```

Roles:
- `admin` - Full access
- `operator` - Read + withdraw mitigations
- `viewer` - Read-only

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
```

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

### Health Endpoint

`GET /v1/health` returns:

```json
{
  "status": "healthy",
  "version": "0.8.0",
  "pop": "iad1",
  "uptime_seconds": 86400,
  "database": {
    "status": "connected",
    "latency_ms": 2
  },
  "gobgp": {
    "status": "connected",
    "peers_established": 2
  }
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

Benchmarked on commodity hardware (see [benchmarks.md](docs/benchmarks.md)):

| Operation | Throughput | Latency |
|-----------|------------|---------|
| Event ingestion | ~6,000/sec | <1ms p99 |
| Inventory lookup | ~5.6M/sec | <1μs |
| Database queries | ~6,000/sec | <1ms p99 |
| FlowSpec announcement | ~100/sec | ~10ms |

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
