# API Reference

prefixd exposes a REST API for event ingestion, mitigation management, and operational tasks.

**Base URL:** `http://localhost:8080/v1`

> **Versioning:** All endpoints are under `/v1/`. See [API Versioning Policy](api-versioning.md) for backward compatibility guarantees and deprecation process.

## Authentication

### Bearer Token

For API and CLI access:

```bash
curl -H "Authorization: Bearer $PREFIXD_API_TOKEN" \
  http://localhost:8080/v1/mitigations
```

### Session Cookie

For dashboard access, authenticate via login:

```bash
# Login
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "secret"}' \
  -c cookies.txt

# Use session
curl -b cookies.txt http://localhost:8080/v1/mitigations
```

### Auth Modes

Configure in `prefixd.yaml`:

```yaml
http:
  auth:
    mode: bearer  # none, bearer, or hybrid
    token: "your-secret-token"
```

| Mode | Description |
|------|-------------|
| `none` | No authentication (development only) |
| `bearer` | Bearer token required |
| `hybrid` | Accept either session cookie or bearer token |

---

## Events

### Ingest Attack Event

```http
POST /v1/events
Content-Type: application/json
```

**Request:**

```json
{
  "timestamp": "2026-02-18T10:30:00Z",
  "source": "fastnetmon",
  "victim_ip": "203.0.113.10",
  "vector": "udp_flood",
  "bps": 1200000000,
  "pps": 800000,
  "confidence": 0.95,
  "top_dst_ports": [53, 123],
  "action": "ban"
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `timestamp` | datetime | yes | Event timestamp (ISO 8601) |
| `source` | string | yes | Detector identifier (e.g. "fastnetmon", "dashboard") |
| `victim_ip` | string | yes | IPv4 address under attack |
| `vector` | string | yes | Attack type: `udp_flood`, `syn_flood`, `ack_flood`, `icmp_flood`, `unknown` |
| `bps` | integer | no | Bits per second |
| `pps` | integer | no | Packets per second |
| `confidence` | float | no | 0.0-1.0, detection confidence |
| `top_dst_ports` | array | no | Destination ports involved (max 8) |
| `action` | string | no | `"ban"` (default) or `"unban"` |
| `event_id` | string | no | External event ID (for dedup / unban correlation) |
| `raw_details` | object | no | Raw detector payload for forensics |

**Response (202 Accepted):**

```json
{
  "event_id": "evt_abc123",
  "mitigation_id": "mit_def456",
  "status": "created"
}
```

Status values: `"created"`, `"extended"`, `"escalated"`, `"duplicate"`, `"unban_processed"`, `"unban_not_found"`.

**Error Responses:**

| Status | Reason |
|--------|--------|
| 400 | Invalid request body |
| 403 | Victim IP is safelisted |
| 422 | Guardrail rejection (quota, prefix length, etc.) |
| 429 | Rate limited |

### List Events

```http
GET /v1/events
```

**Query Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `source` | string | Filter by detector source |
| `victim_ip` | string | Filter by victim IP |
| `vector` | string | Filter by attack vector |
| `since` | datetime | Events after this time |
| `limit` | integer | Max results (default 50, max 1000) |
| `offset` | integer | Pagination offset |

**Response:**

```json
{
  "items": [
    {
      "id": "evt_abc123",
      "source": "fastnetmon",
      "victim_ip": "203.0.113.10",
      "vector": "udp_flood",
      "bps": 1200000000,
      "confidence": 0.95,
      "created_at": "2026-01-18T10:30:00Z"
    }
  ],
  "count": 1
}
```

---

## Mitigations

### List Mitigations

```http
GET /v1/mitigations
```

**Query Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `status` | string | Filter: active, expired, withdrawn, pending |
| `customer_id` | string | Filter by customer |
| `pop` | string | Filter by POP (or "all") |
| `limit` | integer | Max results (default 50, max 1000) |
| `offset` | integer | Pagination offset |

**Response:**

```json
{
  "items": [
    {
      "id": "mit_def456",
      "status": "active",
      "customer_id": "acme",
      "service_id": "dns",
      "dst_prefix": "203.0.113.10/32",
      "protocol": "udp",
      "dst_ports": [53],
      "dst_ports_excluded": true,
      "action": "police",
      "rate_bps": 10000000,
      "ttl_seconds": 120,
      "expires_at": "2026-01-18T10:32:00Z",
      "created_at": "2026-01-18T10:30:00Z",
      "pop": "iad1"
    }
  ],
  "count": 1
}
```

### Get Mitigation

```http
GET /v1/mitigations/{id}
```

**Response:** Same as list item.

### Withdraw Mitigation

```http
POST /v1/mitigations/{id}/withdraw
Content-Type: application/json
```

**Request:**

```json
{
  "reason": "false positive"
}
```

**Response (200 OK):**

```json
{
  "id": "mit_def456",
  "status": "withdrawn",
  "withdrawn_at": "2026-01-18T10:31:00Z",
  "withdrawn_reason": "false positive"
}
```

---

## Safelist

### List Safelist

```http
GET /v1/safelist
```

**Response:**

```json
{
  "items": [
    {
      "prefix": "10.0.0.1/32",
      "reason": "Router loopback",
      "created_by": "admin",
      "created_at": "2026-01-15T08:00:00Z"
    }
  ],
  "count": 1
}
```

### Add to Safelist

```http
POST /v1/safelist
Content-Type: application/json
```

**Request:**

```json
{
  "prefix": "10.0.0.1/32",
  "reason": "Router loopback"
}
```

**Response (201 Created):**

```json
{
  "prefix": "10.0.0.1/32",
  "reason": "Router loopback",
  "created_by": "admin",
  "created_at": "2026-01-18T10:30:00Z"
}
```

### Remove from Safelist

```http
DELETE /v1/safelist/{prefix}
```

**Response (204 No Content)**

---

## Authentication Endpoints

### Login

```http
POST /v1/auth/login
Content-Type: application/json
```

**Request:**

```json
{
  "username": "admin",
  "password": "secret"
}
```

**Response (200 OK):**

```json
{
  "username": "admin",
  "role": "admin"
}
```

Sets `session` cookie for subsequent requests.

### Logout

```http
POST /v1/auth/logout
```

**Response (200 OK)**

Clears session cookie.

### Current User

```http
GET /v1/auth/me
```

**Response (200 OK):**

```json
{
  "username": "admin",
  "role": "admin"
}
```

**Response (401 Unauthorized):** Not logged in.

---

## Operators (Admin Only)

### List Operators

```http
GET /v1/operators
```

**Response:**

```json
{
  "operators": [
    {
      "operator_id": "uuid",
      "username": "admin",
      "role": "admin",
      "created_at": "2026-01-15T08:00:00Z",
      "created_by": null,
      "last_login_at": "2026-01-18T10:30:00Z"
    }
  ],
  "count": 1
}
```

### Create Operator

```http
POST /v1/operators
Content-Type: application/json
```

**Request:**

```json
{
  "username": "jsmith",
  "password": "securepassword123",
  "role": "operator"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | yes | Unique username |
| `password` | string | yes | Minimum 8 characters |
| `role` | string | yes | `admin`, `operator`, or `viewer` |

**Response (201 Created):**

```json
{
  "operator_id": "uuid",
  "username": "jsmith",
  "role": "operator",
  "created_at": "2026-01-18T10:30:00Z",
  "created_by": "admin",
  "last_login_at": null
}
```

**Error Responses:**

| Status | Reason |
|--------|--------|
| 400 | Invalid role or password too short |
| 403 | Caller is not admin |
| 409 | Username already exists |

### Delete Operator

```http
DELETE /v1/operators/{id}
```

**Response (204 No Content)**

**Error Responses:**

| Status | Reason |
|--------|--------|
| 400 | Cannot delete self |
| 403 | Caller is not admin |
| 404 | Operator not found |

### Change Password

```http
PUT /v1/operators/{id}/password
Content-Type: application/json
```

**Request:**

```json
{
  "new_password": "newsecurepassword123"
}
```

Admins can change any password. Non-admins can only change their own.

**Response (204 No Content)**

**Error Responses:**

| Status | Reason |
|--------|--------|
| 400 | Password too short (min 8 chars) |
| 403 | Insufficient permissions |
| 404 | Operator not found |

---

## Operational Endpoints

### Health Check (Public)

```http
GET /v1/health
```

Lightweight liveness check. No authentication required. Does not query database or GoBGP.

**Response:**

```json
{
  "status": "ok",
  "version": "0.8.5",
  "auth_mode": "none"
}
```

| Field | Description |
|-------|-------------|
| `status` | Always `"ok"` if the daemon is running |
| `version` | Daemon version |
| `auth_mode` | Authentication mode: `none`, `bearer`, `credentials`, `mtls` |

### Health Detail (Authenticated)

```http
GET /v1/health/detail
Authorization: Bearer <token>
```

Full operational health. Requires authentication.

**Response:**

```json
{
  "status": "healthy",
  "version": "0.8.5",
  "pop": "iad1",
  "uptime_seconds": 86400,
  "bgp_sessions": {
    "172.30.30.3": "established",
    "172.30.31.3": "active"
  },
  "active_mitigations": 12,
  "database": "connected",
  "gobgp": {
    "status": "connected"
  },
  "auth_mode": "none"
}
```

| Status | Meaning |
|--------|---------|
| `healthy` | All systems operational |
| `degraded` | Partial functionality (DB or GoBGP issues) |

> **Migration note (v0.8.2 → v0.8.3):** The public `GET /v1/health` endpoint no longer returns BGP sessions, database status, or operational details. Monitoring systems and scripts that parse these fields must switch to `GET /v1/health/detail` with authentication. See [ADR 015](adr/015-health-endpoint-split.md).

### Stats

```http
GET /v1/stats
```

**Response:**

```json
{
  "total_active": 12,
  "total_expired": 1543,
  "total_withdrawn": 89,
  "by_customer": {
    "acme": 5,
    "contoso": 7
  },
  "by_pop": {
    "iad1": 8,
    "fra1": 4
  }
}
```

### Stats Timeseries

```http
GET /v1/stats/timeseries?metric=mitigations&range=24h&bucket=1h
Authorization: Bearer <token>
```

Returns gap-filled time buckets for charting. Supported metrics: `mitigations`, `events`. Range up to 7d, bucket minimum 5m.

**Response:**

```json
{
  "metric": "mitigations",
  "buckets": [
    { "bucket": "2026-02-20T00:00:00Z", "count": 0 },
    { "bucket": "2026-02-20T01:00:00Z", "count": 3 },
    { "bucket": "2026-02-20T02:00:00Z", "count": 1 }
  ]
}
```

### IP History

```http
GET /v1/ip/192.0.2.1/history?limit=100
Authorization: Bearer <token>
```

Returns all events and mitigations for a given IP, plus customer/service context from inventory.

**Response:**

```json
{
  "ip": "192.0.2.1",
  "customer": { "customer_id": "acme", "name": "ACME Corp", "policy_profile": "normal" },
  "service": { "service_id": "web", "name": "Web Frontend" },
  "events": [
    { "event_id": "...", "source": "fastnetmon", "event_timestamp": "...", "vector": "udp_flood", "bps": 5000000000, "pps": 1200000, "confidence": 0.95 }
  ],
  "mitigations": [
    { "mitigation_id": "...", "status": "active", "action_type": "police", "vector": "udp_flood", "created_at": "...", "expires_at": "..." }
  ]
}
```

### Config Settings

```http
GET /v1/config/settings
Authorization: Bearer <token>
```

Returns the running daemon configuration with sensitive fields redacted (allowlist approach). See [ADR 014](adr/014-allowlist-config-redaction.md).

**Response:**

```json
{
  "settings": {
    "pop": "iad1",
    "mode": "enforced",
    "http": { "listen": "0.0.0.0:8080", "auth": { "mode": "bearer" }, "rate_limit": { "events_per_second": 100, "burst": 500 } },
    "bgp": { "mode": "sidecar", "local_asn": 65010, "neighbors": [{ "name": "172.30.30.3", "address": "172.30.30.3", "peer_asn": 65001, "afi_safi": ["ipv4-flowspec"] }] },
    "guardrails": { "require_ttl": true, "dst_prefix_minlen": 32, "dst_prefix_maxlen": 32, "max_ports": 8 },
    "quotas": { "max_active_per_customer": 5, "max_active_global": 500 },
    "timers": { "default_ttl_seconds": 120, "reconciliation_interval_seconds": 30 },
    "escalation": { "enabled": true },
    "storage": { "connection_string": "[redacted]" },
    "observability": { "log_format": "json", "log_level": "info", "metrics_listen": "0.0.0.0:9090" },
    "safelist": { "count": 3 },
    "shutdown": { "drain_timeout_seconds": 30, "preserve_announcements": true }
  },
  "loaded_at": "2026-02-18T12:00:00Z"
}
```

> **Note:** TLS paths, LDAP/RADIUS configs, bearer token env vars, BGP passwords, gRPC endpoints, router ID, and safelist prefixes are omitted. New config fields are hidden by default.

### Config Inventory

```http
GET /v1/config/inventory
Authorization: Bearer <token>
```

Returns customer/service/IP asset data from `inventory.yaml`.

**Response:**

```json
{
  "customers": [
    {
      "customer_id": "cust_example",
      "name": "Example Customer",
      "prefixes": ["203.0.113.0/24"],
      "policy_profile": "normal",
      "services": [
        {
          "service_id": "svc_dns",
          "name": "DNS Service",
          "assets": [{ "ip": "203.0.113.10", "role": "dns" }],
          "allowed_ports": { "udp": [53], "tcp": [53] }
        }
      ]
    }
  ],
  "total_customers": 1,
  "total_services": 1,
  "total_assets": 1,
  "loaded_at": "2026-02-18T12:00:00Z"
}
```

### Config Playbooks

```http
GET /v1/config/playbooks
Authorization: Bearer <token>
```

Returns playbook definitions from `playbooks.yaml`.

**Response:**

```json
{
  "playbooks": [
    {
      "name": "udp_flood_police_first",
      "match": { "vector": "udp_flood", "require_top_ports": false },
      "steps": [
        { "action": "police", "rate_bps": 5000000, "ttl_seconds": 120 },
        { "action": "discard", "rate_bps": null, "ttl_seconds": 300, "require_confidence_at_least": 0.7, "require_persistence_seconds": 120 }
      ]
    }
  ],
  "total_playbooks": 1,
  "loaded_at": "2026-02-18T12:00:00Z"
}
```

### List POPs

```http
GET /v1/pops
```

**Response:**

```json
{
  "pops": [
    {
      "pop": "iad1",
      "active_mitigations": 8
    },
    {
      "pop": "fra1",
      "active_mitigations": 4
    }
  ]
}
```

### Reload Configuration

```http
POST /v1/config/reload
```

**Response (200 OK):**

```json
{
  "message": "Configuration reloaded",
  "inventory": {
    "customers": 150,
    "assets": 2340
  },
  "playbooks": 12
}
```

---

## WebSocket

### Real-Time Feed

```
WebSocket: ws://localhost:8080/v1/ws/feed
```

Requires session authentication (send session cookie).

**Message Types:**

```json
{"type": "MitigationCreated", "mitigation": {...}}
{"type": "MitigationUpdated", "mitigation": {...}}
{"type": "MitigationExpired", "mitigation_id": "mit_abc123"}
{"type": "MitigationWithdrawn", "mitigation_id": "mit_abc123"}
{"type": "EventIngested", "event": {...}}
{"type": "ResyncRequired"}
```

**ResyncRequired:** Sent when server detects client may have missed messages. Client should refresh data.

---

## Audit Log

### List Audit Entries

```http
GET /v1/audit
```

**Query Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `action` | string | Filter by action type |
| `operator_id` | string | Filter by operator |
| `since` | datetime | Entries after this time |
| `limit` | integer | Max results (default 50, max 1000) |
| `offset` | integer | Pagination offset |

**Response:**

```json
{
  "items": [
    {
      "id": "aud_xyz789",
      "timestamp": "2026-01-18T10:31:00Z",
      "action": "mitigation_withdrawn",
      "operator_id": "jsmith",
      "details": {
        "mitigation_id": "mit_def456",
        "reason": "false positive"
      },
      "ip_address": "10.0.0.50"
    }
  ],
  "count": 1
}
```

---

## Metrics

### Prometheus Metrics

```http
GET /metrics
```

Returns Prometheus text format:

```
# HELP prefixd_mitigations_active Current active mitigations
# TYPE prefixd_mitigations_active gauge
prefixd_mitigations_active{customer="acme",pop="iad1"} 5

# HELP prefixd_http_requests_total Total HTTP requests
# TYPE prefixd_http_requests_total counter
prefixd_http_requests_total{method="POST",route="/v1/events",status_class="2xx"} 1543
```

See [FEATURES.md](../FEATURES.md#prometheus-metrics) for full metric list.

---

## Error Responses

All errors follow this format:

```json
{
  "error": "validation_failed",
  "message": "Destination prefix must be /32 for IPv4",
  "details": {
    "field": "dst_prefix",
    "value": "203.0.113.0/24"
  }
}
```

### Common Error Codes

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `bad_request` | Malformed JSON or missing fields |
| 401 | `unauthorized` | Missing or invalid authentication |
| 403 | `forbidden` | Safelisted IP or insufficient permissions |
| 404 | `not_found` | Resource doesn't exist |
| 422 | `validation_failed` | Guardrail rejection |
| 429 | `rate_limited` | Too many requests |
| 500 | `internal_error` | Server error |
| 503 | `service_unavailable` | Database or GoBGP unavailable |

---

## Rate Limiting

Default limits (configurable):

| Endpoint | Limit |
|----------|-------|
| `POST /v1/events` | 100 burst, 10/s sustained |
| Other endpoints | 1000 burst, 100/s sustained |

**Response Headers:**

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705578600
```

**429 Response:**

```json
{
  "error": "rate_limited",
  "message": "Rate limit exceeded",
  "retry_after_seconds": 5
}
```
