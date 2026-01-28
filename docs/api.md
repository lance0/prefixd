# API Reference

prefixd exposes a REST API for event ingestion, mitigation management, and operational tasks.

**Base URL:** `http://localhost:8080/v1`

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
  "source": "fastnetmon",
  "victim_ip": "203.0.113.10",
  "vector": "udp_flood",
  "bps": 1200000000,
  "pps": 800000,
  "confidence": 0.95,
  "dst_ports": [53, 123],
  "protocol": "udp"
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source` | string | yes | Detector identifier |
| `victim_ip` | string | yes | IPv4 or IPv6 address under attack |
| `vector` | string | yes | Attack type (udp_flood, syn_flood, etc.) |
| `bps` | integer | no | Bits per second |
| `pps` | integer | no | Packets per second |
| `confidence` | float | no | 0.0-1.0, detection confidence |
| `dst_ports` | array | no | Destination ports involved |
| `protocol` | string | no | tcp, udp, icmp |

**Response (201 Created):**

```json
{
  "event_id": "evt_abc123",
  "mitigation_id": "mit_def456",
  "action_taken": "created",
  "message": "Mitigation created: police 10 Mbps for 120s"
}
```

**Response (200 OK - Extended):**

```json
{
  "event_id": "evt_abc124",
  "mitigation_id": "mit_def456",
  "action_taken": "extended",
  "message": "TTL extended by 120s"
}
```

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

### Health Check

```http
GET /v1/health
```

**Response:**

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

| Status | Meaning |
|--------|---------|
| `healthy` | All systems operational |
| `degraded` | Partial functionality (DB or GoBGP issues) |
| `unhealthy` | Critical failure |

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

### BGP Peers

```http
GET /v1/peers
```

**Response:**

```json
{
  "peers": [
    {
      "name": "10.0.0.1",
      "address": "10.0.0.1",
      "state": "established"
    }
  ]
}
```

### Reload Configuration

```http
POST /v1/admin/reload
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
