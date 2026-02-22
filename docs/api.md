# API Reference

prefixd exposes a REST API for event ingestion, mitigation management, and operational tasks.

**Base URL:** `http://localhost/v1`

> In the default Docker Compose deployment, nginx is the only published entrypoint (`http://localhost`). Port `8080` is internal to the Docker network.

> **Versioning:** All endpoints are under `/v1/`. See [API Versioning Policy](api-versioning.md) for backward compatibility guarantees and deprecation process.

## Authentication

### Bearer Token

For API and CLI access:

```bash
curl -H "Authorization: Bearer $PREFIXD_API_TOKEN" \
  http://localhost/v1/mitigations
```

### Session Cookie

For dashboard access, authenticate via login:

```bash
# Login
curl -X POST http://localhost/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "secret"}' \
  -c cookies.txt

# Use session
curl -b cookies.txt http://localhost/v1/mitigations
```

### Auth Modes

Configure in `prefixd.yaml`:

```yaml
http:
  auth:
    mode: credentials  # none, bearer, credentials, or mtls
    bearer_token_env: "PREFIXD_API_TOKEN" # required for mode=bearer
```

| Mode | Description |
|------|-------------|
| `none` | No authentication (development only) |
| `bearer` | Bearer token auth for API/CLI; existing dashboard sessions remain valid |
| `credentials` | Username/password login with session cookies |
| `mtls` | Client certificate auth at TLS layer |

> Unless explicitly marked "Public", `/v1/*` endpoints require authentication.

---

## Events

### Ingest Attack Event

```http
POST /v1/events
Authorization: Bearer <token>
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
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "external_event_id": null,
  "mitigation_id": "7f72a903-63d1-4a4a-a5db-0517e0a7df1d",
  "status": "accepted"
}
```

Common status values:
- Ban path: `"accepted"`, `"extended"`, `"accepted_no_playbook"`, `"accepted_no_mitigation"`
- Unban path: `"withdrawn"`, `"ignored_no_event_id"`, `"not_found"`, `"no_active_mitigation"`

**Error Responses:**

| Status | Reason |
|--------|--------|
| 400 | Invalid request body |
| 401 | Authentication required |
| 409 | Duplicate event |
| 422 | Guardrail rejection (safelist, quotas, prefix length, etc.) |
| 429 | Rate limited |

### List Events

```http
GET /v1/events
Authorization: Bearer <token>
```

**Query Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `limit` | integer | Max results (default 100, max 1000) |
| `offset` | integer | Pagination offset |

**Response:**

```json
{
  "events": [
    {
      "event_id": "550e8400-e29b-41d4-a716-446655440000",
      "external_event_id": "fm-evt-1234",
      "source": "fastnetmon",
      "event_timestamp": "2026-01-18T10:29:58Z",
      "ingested_at": "2026-01-18T10:30:00Z",
      "victim_ip": "203.0.113.10",
      "vector": "udp_flood",
      "protocol": 17,
      "bps": 1200000000,
      "pps": 800000,
      "top_dst_ports_json": "[53,123]",
      "confidence": 0.95,
      "action": "ban"
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
Authorization: Bearer <token>
```

**Query Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `status` | string | Filter by one or more statuses (comma-separated): `pending`, `active`, `escalated`, `withdrawn`, `expired`, `rejected` |
| `customer_id` | string | Filter by customer |
| `victim_ip` | string | Filter by exact victim IP |
| `pop` | string | Filter by POP (or "all") |
| `limit` | integer | Max results (default 100, max 1000) |
| `offset` | integer | Pagination offset |

**Response:**

```json
{
  "mitigations": [
    {
      "mitigation_id": "7f72a903-63d1-4a4a-a5db-0517e0a7df1d",
      "scope_hash": "scope_abc123",
      "status": "active",
      "customer_id": "acme",
      "service_id": "dns",
      "pop": "iad1",
      "victim_ip": "203.0.113.10",
      "vector": "udp_flood",
      "action_type": "police",
      "rate_bps": 10000000,
      "dst_prefix": "203.0.113.10/32",
      "protocol": 17,
      "dst_ports": [53],
      "created_at": "2026-01-18T10:30:00Z",
      "updated_at": "2026-01-18T10:30:00Z",
      "expires_at": "2026-01-18T10:32:00Z",
      "withdrawn_at": null,
      "triggering_event_id": "550e8400-e29b-41d4-a716-446655440000",
      "last_event_id": "550e8400-e29b-41d4-a716-446655440000",
      "reason": "Vector policy: udp_flood"
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
Authorization: Bearer <token>
Content-Type: application/json
```

**Request:**

```json
{
  "operator_id": "jsmith",
  "reason": "false positive"
}
```

**Response (200 OK):**

```json
{
  "mitigation_id": "7f72a903-63d1-4a4a-a5db-0517e0a7df1d",
  "status": "withdrawn",
  "withdrawn_at": "2026-01-18T10:31:00Z"
}
```

---

## Safelist

### List Safelist

```http
GET /v1/safelist
Authorization: Bearer <token>
```

**Response:**

```json
[
  {
    "prefix": "10.0.0.1/32",
    "reason": "Router loopback",
    "added_by": "admin",
    "added_at": "2026-01-15T08:00:00Z",
    "expires_at": null
  }
]
```

### Add to Safelist

```http
POST /v1/safelist
Authorization: Bearer <token>
Content-Type: application/json
```

**Request:**

```json
{
  "operator_id": "admin",
  "prefix": "10.0.0.1/32",
  "reason": "Router loopback"
}
```

**Response (201 Created):** No body

### Remove from Safelist

```http
DELETE /v1/safelist/{prefix}
Authorization: Bearer <token>
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
  "operator_id": "550e8400-e29b-41d4-a716-446655440000",
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
  "version": "0.10.1",
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
  "version": "0.10.1",
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
  "total_mitigations": 1543,
  "total_events": 9821,
  "pops": [
    { "pop": "iad1", "active": 8, "total": 900 },
    { "pop": "fra1", "active": 4, "total": 643 }
  ]
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

### Update Playbooks

```http
PUT /v1/config/playbooks
Authorization: Bearer <token>
Content-Type: application/json

{
  "playbooks": [
    {
      "name": "udp_flood_police_first",
      "match": { "vector": "udp_flood", "require_top_ports": false },
      "steps": [
        { "action": "police", "rate_bps": 5000000, "ttl_seconds": 120 },
        { "action": "discard", "ttl_seconds": 300, "require_confidence_at_least": 0.7, "require_persistence_seconds": 120 }
      ]
    }
  ]
}
```

**Admin only.** Validates, writes to `playbooks.yaml` (with `.bak` backup), and hot-reloads. Returns the updated playbooks response on success.

**Validation rules:**
- Unique playbook names (max 128 chars)
- Valid vector (`udp_flood`, `syn_flood`, `ack_flood`, `icmp_flood`, `unknown`)
- At least one step per playbook
- `police` steps require `rate_bps > 0`
- `ttl_seconds` must be 1-86400
- `require_confidence_at_least` must be 0.0-1.0
- First step must not have escalation requirements

**Error response (400):**

```json
{
  "errors": ["playbook[0] (\"bad\"): police action requires rate_bps > 0"]
}
```

### Alerting Config

```http
GET /v1/config/alerting
Authorization: Bearer <token>
```

Returns configured alert destinations with secrets redacted.

**Response:**

```json
{
  "destinations": [
    {
      "type": "slack",
      "webhook_url": "***",
      "channel": "#ddos-alerts"
    },
    {
      "type": "pagerduty",
      "routing_key": "***",
      "events_url": "https://events.pagerduty.com/v2/enqueue"
    }
  ],
  "events": ["mitigation.created", "mitigation.escalated"]
}
```

### Update Alerting Config

```http
PUT /v1/config/alerting
Authorization: Bearer <token>
Content-Type: application/json

{
  "destinations": [
    {
      "type": "slack",
      "webhook_url": "https://hooks.slack.com/services/T.../B.../xxx",
      "channel": "#ddos-alerts"
    }
  ],
  "events": ["mitigation.created", "mitigation.withdrawn"]
}
```

**Admin only.** Validates, merges redacted secrets (`***`) with existing values, writes to `alerting.yaml` (with `.bak` backup), and hot-reloads the alerting service. Returns the updated config with secrets redacted.

**Secret merge:** If a secret field (e.g. `webhook_url`, `bot_token`, `routing_key`, `api_key`, `secret`) equals `"***"`, the server carries forward the real secret from the matching existing destination. New destinations must provide actual secrets.

**Validation rules:**
- Slack/Discord/Teams: `webhook_url` required, max 1024 chars, must be valid `https://` URL
- Telegram: `bot_token` and `chat_id` required
- PagerDuty: `routing_key` required, `events_url` max 1024 chars, must be valid `https://` URL
- OpsGenie: `api_key` required, `region` must be `us` or `eu`
- Generic: `url` required, max 1024 chars, must be valid `https://` URL
- URL host protections: `localhost`, `.localhost`, and literal private/local IPs (including `169.254.169.254`) are rejected

**Error response (400):**

```json
{
  "errors": ["destination[0] (slack): webhook_url is required"]
}
```

### Test Alerting

```http
POST /v1/config/alerting/test
Authorization: Bearer <token>
```

Sends a test alert to all configured destinations. Returns per-destination results.  
Requires admin role.

**Response:**

```json
{
  "results": [
    {"destination": "slack", "status": "ok", "error": null},
    {"destination": "pagerduty", "status": "error", "error": "pagerduty returned 403"}
  ]
}
```

### List POPs

```http
GET /v1/pops
Authorization: Bearer <token>
```

**Response:**

```json
[
  {
    "pop": "iad1",
    "active_mitigations": 8,
    "total_mitigations": 1321
  },
  {
    "pop": "fra1",
    "active_mitigations": 4,
    "total_mitigations": 942
  }
]
```

### Reload Configuration

```http
POST /v1/config/reload
```

**Response (200 OK):**

```json
{
  "reloaded": ["inventory", "playbooks", "alerting"],
  "timestamp": "2026-02-22T21:00:00Z"
}
```

---

## WebSocket

### Real-Time Feed

```
WebSocket: ws://localhost/v1/ws/feed
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
Authorization: Bearer <token>
```

**Query Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `limit` | integer | Max results (default 100, max 1000) |
| `offset` | integer | Pagination offset |

**Response:**

```json
[
  {
    "audit_id": "f4f0f8f1-d715-4ec3-ae8d-f695f5cd4e1a",
    "timestamp": "2026-01-18T10:31:00Z",
    "schema_version": 1,
    "actor_type": "operator",
    "actor_id": "jsmith",
    "action": "withdraw",
    "target_type": "mitigation",
    "target_id": "7f72a903-63d1-4a4a-a5db-0517e0a7df1d",
    "details": {
      "reason": "false positive"
    }
  }
]
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

Structured errors follow this format:

```json
{
  "error": "destination prefix must be /32",
  "retry_after_seconds": null
}
```

`retry_after_seconds` is only present for rate-limit responses.

Some handlers intentionally return status-only errors (no JSON body), especially for simple auth/CRUD failures.

### Common Error Codes

| Status | Description |
|--------|-------------|
| 400 | Invalid request payload or validation failure |
| 401 | Missing or invalid authentication |
| 403 | Insufficient permissions |
| 404 | Resource not found |
| 409 | Conflict (duplicate resource/event) |
| 422 | Guardrail rejection |
| 429 | Too many requests (includes `retry_after_seconds`) |
| 500 | Internal server error |
| 503 | Service unavailable |

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
  "error": "rate limited",
  "retry_after_seconds": 5
}
```
