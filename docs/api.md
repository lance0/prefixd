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

### Batch Ingest Events

```http
POST /v1/events/batch
Authorization: Bearer <token>
Content-Type: application/json

{
  "events": [
    {
      "timestamp": "2026-01-15T14:32:00Z",
      "source": "fastnetmon",
      "victim_ip": "203.0.113.10",
      "vector": "udp_flood",
      "bps": 5000000000,
      "pps": 500000
    },
    {
      "timestamp": "2026-01-15T14:32:01Z",
      "source": "fastnetmon",
      "victim_ip": "203.0.113.11",
      "vector": "syn_flood",
      "bps": 2000000000
    }
  ]
}
```

Accepts up to 100 events in a single request. Each event is processed sequentially through the full pipeline (validation, guardrails, policy engine, FlowSpec announce). Partial success: if some events fail, the rest are still processed.

**Response (all accepted — 202):**

```json
{
  "accepted": 2,
  "rejected": 0,
  "results": [
    { "index": 0, "event_id": "550e8400-...", "status": "mitigation_created", "mitigation_id": "660e8400-..." },
    { "index": 1, "event_id": "770e8400-...", "status": "mitigation_created", "mitigation_id": "880e8400-..." }
  ]
}
```

**Response (partial success — 207):**

```json
{
  "accepted": 1,
  "rejected": 1,
  "results": [
    { "index": 0, "event_id": "550e8400-...", "status": "mitigation_created", "mitigation_id": "660e8400-..." },
    { "index": 1, "event_id": "00000000-...", "status": "rejected", "error": "invalid IP address" }
  ]
}
```

| Status | Meaning |
|--------|---------|
| 202 | All events accepted |
| 207 | Partial success (some rejected) |
| 400 | Empty batch or exceeds 100 event limit |
| 401 | Authentication required |

### List Events

```http
GET /v1/events
Authorization: Bearer <token>
```

**Query Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `limit` | integer | Max results (default 100, max 1000) |
| `cursor` | string | Cursor for pagination (from previous response `next_cursor`) |
| `start` | string | Start of date range (ISO 8601, inclusive) |
| `end` | string | End of date range (ISO 8601, exclusive) |

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
  "count": 1,
  "next_cursor": "MjAyNi0wMS0xOFQxMDozMDowMFo",
  "has_more": false
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
| `acknowledged` | boolean | Filter by acknowledged status (`true`/`false`) |
| `limit` | integer | Max results (default 100, max 1000) |
| `cursor` | string | Cursor for pagination (from previous response `next_cursor`) |
| `start` | string | Start of date range (ISO 8601, inclusive) |
| `end` | string | End of date range (ISO 8601, exclusive) |

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
      "reason": "Vector policy: udp_flood",
      "acknowledged_at": null,
      "acknowledged_by": null,
      "correlation": null
    }
  ],
  "count": 1,
  "next_cursor": null,
  "has_more": false
}
```

When a mitigation was created via multi-source corroboration (correlation engine enabled), the `correlation` field contains context about the decision:

```json
{
  "correlation": {
    "signal_group_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "derived_confidence": 0.75,
    "source_count": 2,
    "corroboration_met": true,
    "contributing_sources": ["fastnetmon", "alertmanager"],
    "explanation": "Corroboration met: 2 distinct source(s) (min=2) with derived confidence 0.75 (threshold=0.50). Sources: fastnetmon(conf=0.90, w=1.0), alertmanager(conf=0.60, w=0.8)"
  }
}
```

When correlation is disabled or the mitigation was created by a single source without corroboration, the `correlation` field is `null` or absent.

### Create Mitigation

```http
POST /v1/mitigations
Authorization: Bearer <token>
Content-Type: application/json
```

Directly create a mitigation (e.g. from the dashboard "Mitigate Now" form). Unlike `POST /v1/events`, this skips playbook evaluation and creates the mitigation with the exact parameters provided.

**Request:**

```json
{
  "operator_id": "jsmith",
  "reason": "Manual mitigation for ongoing attack",
  "victim_ip": "203.0.113.10",
  "protocol": "udp",
  "dst_ports": [53],
  "action": "police",
  "rate_bps": 10000000,
  "ttl_seconds": 300
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `operator_id` | string | yes | Operator creating the mitigation |
| `reason` | string | yes | Reason for the mitigation |
| `victim_ip` | string | yes | IPv4 address to protect |
| `protocol` | string | yes | `"udp"`, `"tcp"`, `"icmp"`, or `"any"` |
| `dst_ports` | array | no | Destination ports (default `[]`) |
| `action` | string | yes | `"discard"` or `"police"` |
| `rate_bps` | integer | conditional | Required when action is `"police"` |
| `ttl_seconds` | integer | yes | Time-to-live in seconds (1-86400) |

**Response (201 Created):**

Returns the full mitigation object (same shape as [Get Mitigation](#get-mitigation)).

**Error Responses:**

| Status | Reason |
|--------|--------|
| 400 | Invalid request (bad IP, invalid protocol, police without rate_bps, etc.) |
| 401 | Authentication required |
| 422 | Guardrail rejection (safelist, quotas, prefix length, etc.) |

### Get Mitigation

```http
GET /v1/mitigations/{id}
```

**Response:** Same as list item, including the `correlation` field when present. For correlated mitigations, the correlation object includes:

| Field | Type | Description |
|-------|------|-------------|
| `signal_group_id` | UUID | Signal group that triggered this mitigation |
| `derived_confidence` | float | Weighted average confidence from contributing events |
| `source_count` | integer | Number of distinct detection sources |
| `corroboration_met` | boolean | Whether corroboration threshold was met |
| `contributing_sources` | array | List of source names that contributed |
| `explanation` | string | Human-readable explanation of the correlation decision |

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

### Bulk Withdraw Mitigations

```http
POST /v1/mitigations/withdraw
Authorization: Bearer <token>
Content-Type: application/json
```

**Request:**

```json
{
  "mitigation_ids": [
    "7f72a903-63d1-4a4a-a5db-0517e0a7df1d",
    "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  ],
  "operator_id": "jsmith",
  "reason": "false positive wave"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `mitigation_ids` | array of UUIDs | yes | Up to 100 mitigation IDs to withdraw |
| `operator_id` | string | yes | Operator performing the withdrawal |
| `reason` | string | yes | Reason for withdrawal |

**Response (200 OK):**

```json
{
  "withdrawn": 2,
  "failed": 0,
  "results": [
    { "mitigation_id": "7f72a903-...", "status": "withdrawn" },
    { "mitigation_id": "a1b2c3d4-...", "status": "withdrawn" }
  ]
}
```

Partial success is supported — if some IDs are not found or not active, they appear with `"status": "error"` and an `"error"` field while the valid ones are still withdrawn.

### Bulk Acknowledge Mitigations

```http
POST /v1/mitigations/acknowledge
Authorization: Bearer <token>
Content-Type: application/json
```

**Request:**

```json
{
  "mitigation_ids": [
    "7f72a903-63d1-4a4a-a5db-0517e0a7df1d",
    "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  ],
  "operator_id": "jsmith"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `mitigation_ids` | array of UUIDs | yes | Up to 100 mitigation IDs to acknowledge |
| `operator_id` | string | yes | Operator acknowledging the mitigations |

**Response (200 OK):**

```json
{
  "acknowledged": 2,
  "failed": 0,
  "results": [
    { "mitigation_id": "7f72a903-...", "status": "acknowledged" },
    { "mitigation_id": "a1b2c3d4-...", "status": "acknowledged" }
  ]
}
```

Acknowledging marks a mitigation as reviewed by a human without changing its status. Re-acknowledging an already-acknowledged mitigation returns an error. Rejected mitigations cannot be acknowledged.

---

## Signal Groups

Signal groups are created by the correlation engine when `correlation.enabled` is true. They group related attack events by (victim_ip, vector) within a configurable time window, enabling multi-source corroboration.

### List Signal Groups

```http
GET /v1/signal-groups
Authorization: Bearer <token>
```

**Query Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `status` | string | Filter by status: `open`, `resolved`, `expired` |
| `vector` | string | Filter by attack vector |
| `limit` | integer | Max results (default 100, max 1000) |
| `cursor` | string | Cursor for pagination (from previous response `next_cursor`) |
| `start` | string | Start of date range (ISO 8601, inclusive) |
| `end` | string | End of date range (ISO 8601, exclusive) |

**Response:**

```json
{
  "groups": [
    {
      "group_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "victim_ip": "203.0.113.10",
      "vector": "udp_flood",
      "created_at": "2026-03-19T10:30:00Z",
      "window_expires_at": "2026-03-19T10:35:00Z",
      "derived_confidence": 0.75,
      "source_count": 2,
      "status": "resolved",
      "corroboration_met": true
    }
  ],
  "count": 1,
  "next_cursor": null,
  "has_more": false
}
```

**Signal Group Status:**

| Status | Description |
|--------|-------------|
| `open` | Accepting new events within the time window |
| `resolved` | Corroboration met and mitigation created |
| `expired` | Time window elapsed without sufficient corroboration |

### Get Signal Group Detail

```http
GET /v1/signal-groups/{id}
Authorization: Bearer <token>
```

Returns group metadata and all contributing events with source, confidence, and source weight.

**Response:**

```json
{
  "group_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "victim_ip": "203.0.113.10",
  "vector": "udp_flood",
  "created_at": "2026-03-19T10:30:00Z",
  "window_expires_at": "2026-03-19T10:35:00Z",
  "derived_confidence": 0.75,
  "source_count": 2,
  "status": "resolved",
  "corroboration_met": true,
  "events": [
    {
      "group_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "event_id": "550e8400-e29b-41d4-a716-446655440000",
      "source_weight": 1.0,
      "source": "fastnetmon",
      "confidence": 0.9,
      "ingested_at": "2026-03-19T10:30:01Z"
    },
    {
      "group_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "event_id": "660e8400-e29b-41d4-a716-446655440001",
      "source_weight": 0.8,
      "source": "alertmanager",
      "confidence": 0.6,
      "ingested_at": "2026-03-19T10:31:15Z"
    }
  ]
}
```

**Error Responses:**

| Status | Reason |
|--------|--------|
| 401 | Authentication required |
| 404 | Signal group not found |

---

## Signal Adapters

Signal adapter endpoints accept webhooks from external detection and telemetry systems, translate their payloads into `AttackEventInput`, and feed them into the standard event ingestion pipeline (including correlation, guardrails, and policy evaluation). See [ADR 019](adr/019-signal-adapter-architecture.md).

### Alertmanager Webhook

```http
POST /v1/signals/alertmanager
Authorization: Bearer <token>
Content-Type: application/json
```

Accepts an [Alertmanager v4 webhook payload](https://prometheus.io/docs/alerting/latest/configuration/#webhook_config). Each alert in the `alerts[]` array is processed independently.

**Request:**

```json
{
  "version": "4",
  "status": "firing",
  "alerts": [
    {
      "status": "firing",
      "labels": {
        "victim_ip": "203.0.113.10",
        "vector": "udp_flood",
        "severity": "critical",
        "alertname": "DDoS_Alert"
      },
      "annotations": {
        "bps": "500000000",
        "pps": "1000000"
      },
      "startsAt": "2026-03-19T10:30:00Z",
      "endsAt": "0001-01-01T00:00:00Z",
      "generatorURL": "http://prometheus:9090/graph",
      "fingerprint": "abc123def456"
    }
  ],
  "groupLabels": { "alertname": "DDoS_Alert" },
  "commonLabels": {},
  "commonAnnotations": {},
  "externalURL": "http://alertmanager.example.com"
}
```

**Label Mapping:**

| AttackEventInput field | Alertmanager source | Fallback |
|---|---|---|
| `vector` | `labels.vector` | `labels.alertname` |
| `victim_ip` | `labels.victim_ip` | `labels.instance` (port stripped) |
| `bps` | `annotations.bps` (parsed as i64) | None |
| `pps` | `annotations.pps` (parsed as i64) | None |
| `confidence` | `labels.severity` → `critical`=0.9, `warning`=0.7, `info`=0.5 | 0.5 |
| `action` | `alerts[].status` ("resolved" → "unban", else "ban") | "ban" |
| `event_id` (dedup) | `alerts[].fingerprint` | None |
| `source` | hardcoded `"alertmanager"` | — |

**Response (200):**

```json
{
  "processed": 1,
  "failed": 0,
  "results": [
    {
      "index": 0,
      "status": "accepted",
      "event_id": "550e8400-e29b-41d4-a716-446655440000",
      "mitigation_id": "660e8400-e29b-41d4-a716-446655440001"
    }
  ]
}
```

**Per-alert status values:**

| Status | Description |
|--------|-------------|
| `accepted` | Event created, mitigation may or may not be created |
| `extended` | Existing mitigation TTL extended |
| `duplicate` | Fingerprint already seen (dedup) |
| `withdrawn` | Resolved alert triggered mitigation withdrawal |
| `withdrawn_noop` | Resolved alert with no matching active mitigation |
| `error` | Processing failed for this alert (see `error` field) |

**Error Responses:**

| Status | Reason |
|--------|--------|
| 400 | Malformed payload (invalid JSON, wrong version, empty alerts) |
| 401 | Authentication required |

> **Note:** Alertmanager will not retry 4xx errors, so malformed payloads return 400 to prevent infinite retry loops.

**Alertmanager Configuration Snippet:**

To point Alertmanager at prefixd, add a webhook receiver to your `alertmanager.yml`:

```yaml
receivers:
  - name: 'prefixd'
    webhook_configs:
      - url: 'http://prefixd.example.com/v1/signals/alertmanager'
        http_config:
          authorization:
            type: Bearer
            credentials: '<your-api-token>'
        send_resolved: true
```

### FastNetMon Webhook

```http
POST /v1/signals/fastnetmon
Authorization: Bearer <token>
Content-Type: application/json
```

Accepts FastNetMon's native JSON notify payload. Extracts attack vector from traffic breakdown, maps the `action` field to confidence via configurable mapping, and feeds the event into the standard ingestion pipeline (including correlation, guardrails, and policy evaluation).

**Request:**

```json
{
  "action": "ban",
  "ip": "203.0.113.10",
  "alert_scope": "host",
  "attack_details": {
    "attack_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "attack_severity": "high",
    "attack_detection_source": "automatic",
    "incoming_udp_pps": 500000,
    "incoming_udp_traffic_bits": 4000000000,
    "incoming_tcp_pps": 100,
    "incoming_tcp_traffic_bits": 800000,
    "incoming_syn_tcp_pps": 0,
    "incoming_icmp_pps": 0,
    "total_incoming_pps": 500100,
    "total_incoming_traffic_bits": 4000800000,
    "total_incoming_flows": 12000
  }
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | yes | `"ban"`, `"unban"`, `"partial_block"`, or `"alert"` |
| `ip` | string | yes | Victim IPv4 address under attack |
| `alert_scope` | string | no | Scope: `"host"` or `"total"` |
| `attack_details` | object | no | Traffic metrics and classification (see below) |

**Attack Details Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `attack_uuid` | string | Unique attack ID (used as `external_event_id` for dedup) |
| `attack_severity` | string | Severity: `"low"`, `"middle"`, `"high"` |
| `attack_detection_source` | string | How detected: `"automatic"`, `"manual"` |
| `incoming_udp_pps` | integer | UDP packets per second |
| `incoming_udp_traffic_bits` | integer | UDP bits per second |
| `incoming_tcp_pps` | integer | TCP packets per second |
| `incoming_syn_tcp_pps` | integer | SYN TCP packets per second |
| `incoming_icmp_pps` | integer | ICMP packets per second |
| `total_incoming_pps` | integer | Total incoming packets per second |
| `total_incoming_traffic_bits` | integer | Total incoming bits per second |
| `total_incoming_flows` | integer | Total incoming flow count |

**Confidence Mapping:**

The `action` field maps to a confidence score (configurable in correlation config):

| Action | Default Confidence |
|--------|--------------------|
| `ban` | 0.9 |
| `partial_block` | 0.7 |
| `alert` | 0.5 |
| Other | 0.5 |

Override per-source confidence in `prefixd.yaml`:

```yaml
correlation:
  sources:
    fastnetmon:
      weight: 1.0
      type: detector
      confidence_mapping:
        ban: 0.95
        partial_block: 0.8
        alert: 0.4
```

**Vector Classification:**

The attack vector is automatically classified from the traffic breakdown in `attack_details`:

- **UDP dominant** → `udp_flood`
- **SYN TCP dominant** (>60% of TCP PPS) → `syn_flood`
- **ICMP dominant** → `icmp_flood`
- **Other TCP** → `ack_flood`
- **No details** → `unknown`

**Response (202 Accepted):**

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "external_event_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "accepted",
  "mitigation_id": "7f72a903-63d1-4a4a-a5db-0517e0a7df1d"
}
```

The response uses the same `EventResponse` shape as `POST /v1/events` for compatibility with existing scripts.

**Error Responses:**

| Status | Reason |
|--------|--------|
| 400 | Malformed payload (invalid JSON, missing `ip` or `action`, invalid IP) |
| 401 | Authentication required |
| 422 | Guardrail rejection (safelist, quotas, prefix length) |

**FastNetMon Configuration Snippet:**

To configure FastNetMon Community to use prefixd, set the notify script in `/etc/fastnetmon.conf`:

```
notify_script_path = /opt/prefixd/scripts/prefixd-fastnetmon.sh
```

Or configure FastNetMon Advanced to use the webhook endpoint directly:

```
notify_script_format = json
notify_script_path = /usr/bin/curl -s -X POST http://prefixd.example.com/v1/signals/fastnetmon -H 'Content-Type: application/json' -H 'Authorization: Bearer <token>' -d @-
```

See `docs/detectors/fastnetmon.md` for a complete integration guide.

### Generic Webhook Adapter

For detectors without a native adapter, configure a generic webhook adapter in
`correlation.yaml` and POST arbitrary JSON. Fields are extracted via JSONPath.

```http
POST /v1/signals/webhook/{name}
Content-Type: application/json
X-Signature-SHA256: <hex-encoded HMAC-SHA256 of request body>

<any JSON payload matching the adapter's field mappings>
```

**Path parameter:**

- `name` — Must match a `webhook_adapters[].name` entry in `correlation.yaml`. Names are restricted to `[a-z0-9-]{1,64}`.

**Authentication:**

- `hmac` — HMAC-SHA256 over the raw request body. Header name is configurable (default `X-Signature-SHA256`). The hex digest may be prefixed with `sha256=` (GitHub-style). Secret is read from the env var named in `auth.secret_env`.
- `bearer` — Reuses the global session/bearer auth backend.
- `none` — No auth enforced (intended for lab use only).

**Response:**

```json
{
  "processed": 2,
  "failed": 0,
  "results": [
    { "index": 0, "status": "mitigated", "event_id": "…", "mitigation_id": "…" },
    { "index": 1, "status": "duplicate" }
  ]
}
```

**Configuration example** (`configs/correlation.yaml`):

```yaml
webhook_adapters:
  - name: radware
    enabled: true
    auth:
      type: hmac
      secret_env: RADWARE_WEBHOOK_SECRET
      header: X-Signature-SHA256
      algorithm: sha256
    root_path: "$.alerts[*]"
    fields:
      victim_ip: "$.target.ip"
      vector: "$.alert_type"
      timestamp: "$.time"
      bps: "$.metrics.bps"
      pps: "$.metrics.pps"
      confidence: "$.score"
      source_id: "$.id"
    vector_map:
      UDP_FLOOD: udp_flood
      SYN_FLOOD: syn_flood
    default_vector: unknown
    confidence_scale: 100
    source_id_prefix: "radware-"
```

See `docs/configuration.md` for the complete schema.

### Corroborator Signal

Ingest a **corroborating signal** from a source configured with
`mode: corroborating` in `correlation.yaml`. Corroborators don't carry a
`victim_ip`; instead they match open signal groups on lighter dimensions
(`customer_id`, `pop`, `service_id`, `interface`) declared in the
source's `match_dimensions`. See [ADR 021](adr/021-corroborating-signals.md).

```http
POST /v1/signals/corroborator
Content-Type: application/json

{
  "source": "router-cpu",
  "vector": "udp_flood",
  "customer_id": "cust_42",
  "pop": "iad1",
  "service_id": "svc_web",
  "interface": "et-0/0/12",
  "confidence": 0.6
}
```

**Fields:**

- `source` — Must match a `sources` entry in `correlation.yaml` with
  `mode: corroborating`.
- `vector` *(optional)* — When set, only groups with a matching `vector`
  are eligible. When absent, any open group matching on dimensions is
  eligible.
- `customer_id`, `pop`, `service_id`, `interface` *(optional)* — At
  least one must be populated AND must appear in the source's
  `match_dimensions`. Matching is OR across **declared** dimensions
  only; undeclared fields are ignored even if populated. This prevents
  a source configured for `[pop]` from accidentally attaching to groups
  via a stray `customer_id`.
- `confidence` *(optional)* — 0.0–1.0. Contributes to the group's
  `derived_confidence` via the source's configured `weight`.

**Response:**

```json
{
  "signal_id": "a4f1b2c3-…",
  "status": "attached",
  "attached_group_ids": ["e2b9…-1f3c"]
}
```

- `status` = `attached` when at least one open signal group matched and
  was strengthened. `status` = `cached` when no group matched; the
  signal is held for up to `window_seconds` and drained on matching
  primary event arrival.
- `attached_group_ids` — UUIDs of signal groups this signal contributed
  to.

> **v0.17.0 breaking change:** the always-true `cached` field on this
> response was dropped. `status ∈ {attached, cached}` is the canonical
> discriminator. Update integrations that read `cached` to read
> `status === "cached"` instead.

**Error responses:**

- `400` — `source` is not configured, is configured as `mode=primary`,
  or none of its declared `match_dimensions` were populated on the
  signal.
- `400` — correlation engine is disabled.

**Invariant:** A signal group composed entirely of corroborating
signals never triggers a mitigation, regardless of how high its
`derived_confidence` climbs. Primary events are required.

### Get Corroborator Activity

```http
GET /v1/signals/corroborator/activity?minutes=60
```

Returns per-source corroborator activity aggregated across the live
cache (`corroborating_signals`) and attached corroborator rows on
signal groups (`signal_group_events WHERE is_corroborating`). Intended
for operator dashboards; corroborating-only sources never appear in
the primary `/v1/events` stream, so this endpoint is how the UI knows
they're alive.

**Query parameters:**

- `minutes` *(optional, default 60, range 1–1440)* — Lookback window.

**Response:**

```json
{
  "since": "2026-04-19T16:00:00Z",
  "sources": [
    {"source": "router-cpu",       "last_seen": "2026-04-19T16:59:21Z", "count": 42},
    {"source": "pop-utilization",  "last_seen": "2026-04-19T16:58:05Z", "count": 11}
  ]
}
```

Each source may be counted once per table if it both attached to a
group and kept its live cache row for late fan-out; the intent is
"activity volume", not "distinct signals".

---

### List Cached Corroborators (admin)

```http
GET /v1/signals/corroborator/cache?source=router-cpu&limit=200
```

**Admin-only.** Lists corroborating signals currently in the cache that
are unattached and unexpired — i.e., signals that posted before any
matching primary event landed and are still waiting inside the
`window_seconds` TTL. Use this to debug a `mode: corroborating` source
that ingests heavily but never seems to attach.

**Query parameters:**

- `limit` *(optional, default 100, range 1–1000)* — Page size.
- `source` *(optional)* — Filter by signal source name.

**Response:**

```json
{
  "now": "2026-04-29T18:23:00Z",
  "total": 17,
  "by_source": [
    {"source": "router-cpu",      "count": 11},
    {"source": "pop-utilization", "count": 6}
  ],
  "signals": [
    {
      "signal_id": "...",
      "source": "router-cpu",
      "vector": "udp_flood",
      "customer_id": null,
      "pop": "iad1",
      "service_id": null,
      "interface": null,
      "confidence": 0.7,
      "weight": 0.6,
      "ingested_at": "2026-04-29T18:22:55Z",
      "expires_at":  "2026-04-29T18:27:55Z",
      "raw_details": {...},
      "attached_group_ids": []
    }
  ]
}
```

- `total` and `by_source[]` summarize **unattached, unexpired** rows
  globally (not just the page).
- `signals[]` is paginated by `limit` and ordered by `ingested_at` desc.
- Pair this with the new `prefixd_corroborator_cache_size{source}`
  gauge for alerting on caches growing without bound.

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
  "operator_id": "550e8400-e29b-41d4-a716-446655440000",
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
  "version": "0.17.1",
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
  "version": "0.17.1",
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
      "events_url": "https://events.pagerduty.com/v2/enqueue",
      "events": ["mitigation.created"]
    }
  ],
  "events": ["mitigation.created", "mitigation.escalated"]
}
```

**Per-destination events:** Each destination may include an optional `events` array to override the global event filter. If present, only those event types are sent to that destination. If absent or empty, the destination inherits the global `events` list. See ADR 017.
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
{"type": "mitigation_created", "mitigation": {...}}
{"type": "mitigation_updated", "mitigation": {...}}
{"type": "mitigation_expired", "mitigation_id": "mit_abc123"}
{"type": "mitigation_withdrawn", "mitigation_id": "mit_abc123"}
{"type": "event_ingested", "event": {...}}
{"type": "resync_required"}
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
| `cursor` | string | Cursor for pagination (from previous response `next_cursor`) |
| `start` | string | Start of date range (ISO 8601, inclusive) |
| `end` | string | End of date range (ISO 8601, exclusive) |

**Response:**

```json
{
  "entries": [
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
  ],
  "count": 1,
  "next_cursor": null,
  "has_more": false
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

## Incident Reports

### Generate Incident Report

```http
GET /v1/reports/incident?mitigation_id=<uuid>
GET /v1/reports/incident?ip=<ip>
Authorization: Bearer <token>
```

Generates a markdown incident report for a specific mitigation or all activity for an IP address. Exactly one of `mitigation_id` or `ip` must be provided.

The report includes: summary table, chronological timeline, events table with peak traffic, mitigations table with durations, and audit trail. Customer and service context is included from inventory when available.

**Response:** `200 OK` with `Content-Type: text/markdown`

The response body is a markdown document suitable for pasting into Slack, email, or Jira.

| Status | Meaning |
|--------|---------|
| 200 | Report generated |
| 400 | Missing or invalid parameters (must provide exactly one of mitigation_id or ip) |
| 401 | Authentication required |
| 404 | Mitigation not found (when using mitigation_id) |

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

## Notification Preferences

### Get Notification Preferences

```http
GET /v1/preferences
Authorization: Bearer <token>
```

Returns the current operator's notification preferences. Defaults to all toasts enabled, no quiet hours. `quiet_hours_start` and `quiet_hours_end` are always present (as integers or `null`).

**Response (operator with preferences):**

```json
{
  "muted_events": ["mitigation.expired", "config.reloaded"],
  "quiet_hours_start": 2,
  "quiet_hours_end": 8
}
```

**Response (default / no preferences saved):**

```json
{
  "muted_events": [],
  "quiet_hours_start": null,
  "quiet_hours_end": null
}
```

### Update Notification Preferences

```http
PUT /v1/preferences
Authorization: Bearer <token>
Content-Type: application/json

{
  "muted_events": ["mitigation.expired"],
  "quiet_hours_start": null,
  "quiet_hours_end": null
}
```

Updates the current operator's notification preferences. `muted_events` contains event type strings that should not produce dashboard toast notifications. `quiet_hours_start`/`quiet_hours_end` are UTC hours (0-23); during quiet hours, only critical events (`mitigation.created`, `mitigation.escalated`) produce toasts. Set both to `null` to disable quiet hours.

**Response:** `200 OK` with no body on success.

**Validation:**
- `quiet_hours_start` and `quiet_hours_end` must both be present or both be `null` (no half-configured state)
- `quiet_hours_start`/`quiet_hours_end` must be 0-23 if present
- `muted_events` entries must be valid event types (`mitigation.created`, `mitigation.escalated`, `mitigation.withdrawn`, `mitigation.expired`, `config.reloaded`, `guardrail.rejected`)

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
