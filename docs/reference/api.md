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

## List Filters

Events, audit, mitigations and signal-group listings accept optional `start` and
`end` timestamps. Omit a bound to leave it unset. Empty or malformed supplied
values return `400` with a JSON `error`; date/status validation follows each
endpoint's existing authentication and role checks and precedes listing.

Use RFC3339 timestamps, including offsets; encode a query-string `+` as `%2B`.
Start is inclusive and end is exclusive. Equal or reversed valid bounds return
an empty page.

Mitigation status lists accept exact case-sensitive tokens separated by commas;
duplicates are accepted. Every component must be nonempty and known, without
surrounding whitespace. Signal-group status accepts one exact value. Invalid
status filters return `400` rather than being discarded. Unknown vector and
concrete POP names still match no rows.

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
| `victim_ip` | string | yes | IPv4 or IPv6 address under attack |
| `vector` | string | yes | Attack type: `udp_flood`, `syn_flood`, `ack_flood`, `icmp_flood`, `udp_amplification`, `unknown` |
| `bps` | integer | no | Bits per second |
| `pps` | integer | no | Packets per second |
| `confidence` | float | no | Finite 0.0–1.0 inclusive, or null; invalid values return 400 |
| `top_dst_ports` | array | no | Destination ports involved (max 8) |
| `top_src_ports` | array | no | UDP source ports, ranked by descending share by the detector; at most 64, otherwise 400. Used by `udp_amplification` playbooks |
| `action` | string | no | `"ban"` (default) or `"unban"` |
| `event_id` | string | no | External event ID (for dedup / unban correlation) |
| `raw_details` | object | no | Raw detector payload for forensics |

Confidence validation applies to ban and unban events, including adapter-mapped
events after their existing confidence normalization. Generic webhook adapters
retain their configured scaling and clamping to 0–1. Rejected confidence does not consume the external event ID; corrected
retries can use the same ID. Batch ingestion keeps per-item rejection results.

Automatic detector mitigation uses a canonical host destination: `/32` for IPv4
and `/128` for IPv6. `icmp_flood` selects protocol 1 for IPv4 and 58 for IPv6 in
both event metadata and mitigation intent. TCP and UDP remain 6 and 17. Normal
prefix, port, TTL, quota and safelist checks still apply.

**Response (202 Accepted):**

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "external_event_id": null,
  "mitigation_id": "7f72a903-63d1-4a4a-a5db-0517e0a7df1d",
  "mitigation_ids": ["7f72a903-63d1-4a4a-a5db-0517e0a7df1d"],
  "rules": [
    { "outcome": "created", "mitigation_id": "7f72a903-63d1-4a4a-a5db-0517e0a7df1d" }
  ],
  "status": "accepted"
}
```

`mitigation_ids` lists every mitigation the request created, extended or
withdrew, in admission priority order; it is `[]` when there are none.
`mitigation_id` is its first entry, kept for existing callers. `rules` reports
each rule a ban evaluated, in admission priority order, with `outcome` `created`,
`extended` or `rejected` (with a `reason`); it is omitted when no rule was
evaluated, for example on the unban path or with no playbook.

#### UDP amplification

A `udp_amplification` event carries the reflected service in `top_src_ports`:

```json
{
  "timestamp": "2026-10-19T10:30:00Z",
  "source": "fastnetmon",
  "victim_ip": "203.0.113.10",
  "vector": "udp_amplification",
  "top_src_ports": [123, 389, 4444],
  "action": "ban"
}
```

A playbook step with `rules` emits one mitigation per rule
([ADR 028](../adr/028-amplification-matches.md#4-one-response-several-rules)),
linked by `triggering_event_id`. A `src_ports: from_event` rule matches the
event's ports that are in the reflector-port library
([`amplification`](configuration.md#amplification)); others, such as 4444
above, are dropped and logged. The ports are sorted and split into rules of at
most `guardrails.max_ports` ports each, so a detector that reports the same set
again extends the same rules. A changed set is a new rule; the old one runs out
its TTL. Reflection rules match UDP to the victim host with no destination
ports.

Admission starts with the chunk containing the detector's highest-ranked
source port, then fragment rules, then the remaining chunks by their highest
ranked member. Other static rules retain their relative playbook order.
`mitigation_ids` and `rules` follow this admission order. Chunk contents and
scope identities remain unchanged when detector rankings change.

Each rule is admitted on its own: guardrails, quotas and the new-mitigation
rate apply per rule, so one rule can be created while another is rejected. The
response is `202` when at least one rule was created or extended; otherwise it
is the first rule's error, as for a single rule. Each rule outcome includes
`scope_hash`, the canonical `scope` and `action_type`; a quota refusal also
includes `quota_type` (`customer`, `pop`, `global`, `blackhole_pop` or
`blackhole_global`). `status` is `accepted` when any
rule was created and `extended` otherwise, and `announcement_outcome` is
`unconfirmed` when any created rule's announcement was.

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "external_event_id": null,
  "mitigation_id": "7f72a903-63d1-4a4a-a5db-0517e0a7df1d",
  "mitigation_ids": ["7f72a903-63d1-4a4a-a5db-0517e0a7df1d"],
  "rules": [
    {
      "outcome": "created",
      "scope_hash": "81d7d997c8cc5f1281d7d997c8cc5f12",
      "scope": { "dst_prefix": "203.0.113.10/32", "protocol": 17, "dst_ports": [], "src_ports": [123, 389] },
      "action_type": "discard",
      "mitigation_id": "7f72a903-63d1-4a4a-a5db-0517e0a7df1d"
    },
    {
      "outcome": "rejected",
      "scope_hash": "07453c9718eff9a007453c9718eff9a0",
      "scope": { "dst_prefix": "203.0.113.10/32", "protocol": 17, "dst_ports": [], "fragment": "non_first" },
      "action_type": "police",
      "quota_type": "pop",
      "reason": "quota exceeded: pop (200/200)"
    }
  ],
  "status": "accepted"
}
```

When no reported port is in the library, or no `udp_amplification` playbook is
configured, the event is evaluated exactly as `udp_flood`: the mitigation's
vector is `udp_flood` and its reason ends with
`[udp_amplification fallback: ...]`. An unban by `event_id` withdraws every
live mitigation the original ban created. The unban is stored as its own event
with `"action": "unban"` and the ban's source and `external_event_id`; the
response's `event_id` is that unban event. An unban with no active mitigation
stores nothing. Only bans are deduplicated by source and `event_id`.

When a new mitigation is needed, prefixd commits its Active desired row before
calling the speaker. A persistence failure sends no announcement. If intent
commits but the speaker call fails or times out, the response is still `202` and
includes the mitigation ID plus `"announcement_outcome": "unconfirmed"`.
The controller retains that intent for readable reconciliation and TTL/withdrawal
cleanup. This request did not receive a successful speaker reply; the rule may
already exist remotely.

`announcement_outcome` is optional and request-local. It is omitted for ordinary
success, dry-run, responses that did not create a rule, and subsequent list/detail
reads. Omission does not prove speaker acceptance or router enforcement. The
Active status, mitigation-created events and desired-intent counts describe
controller intent; announcement-success metrics require a successful local RPC.

Detector event storage still precedes mitigation preparation and correlation is
not one transaction with creation. A later preparation failure can return `500`
after consuming the external event ID; resubmitting the same source/ID can return
`409 DuplicateEvent` even though no mitigation exists. Prefixd does not delete or
replay those events automatically. This bounded creation fix does not provide
atomic detector ingestion.

Common status values:

- Ban path: `"accepted"`, `"extended"`, `"accepted_no_playbook"`, `"accepted_no_mitigation"`
- Unban path: `"withdrawn"`, `"ignored_no_event_id"`, `"not_found"`, `"no_active_mitigation"`

When the matching playbook's step is `action: blackhole`
([blackhole steps](configuration.md#blackhole-steps)), the ban creates or
extends a blackhole through the same admission as a
[manual blackhole](#manual-blackhole), recorded with the detector as actor. An
event whose `source` is not in `blackhole.detector_sources` gets `422` before
it is stored, whether it would create or extend the blackhole. An extension is
capped at now plus `blackhole.max_ttl_seconds`. In enforced mode an unconfirmed
add reports `"announcement_outcome": "unconfirmed"` as above.

**Error Responses:**

| Status | Reason |
|--------|--------|
| 400 | Invalid request body |
| 401 | Authentication required |
| 409 | Duplicate event, or in enforced mode the rule is owned by a dry-run mitigation (when every rule is refused before admission, the event is not stored); for a blackhole, a pending withdrawal or an untracked local route at the prefix; for a FlowSpec rule, another injection owner, or none, holding its match at the speaker |
| 422 | Missing required field, including `protocol` for `"discard"` or `"police"`; guardrail rejection (safelist, quotas, new mitigation rate, prefix length, blackhole source allowlist and victim checks, etc.) |
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

A result whose event created or extended several rules also lists them in
`mitigation_ids` (omitted when empty).

A result whose intent committed but whose announcement is unconfirmed includes
`announcement_outcome: "unconfirmed"` and its mitigation ID. It counts as accepted,
not rejected, and does not receive an `error` field. The same additive outcome is
preserved by Alertmanager and generic webhook result wrappers.

### List Events

```http
GET /v1/events
Authorization: Bearer <token>
```

**Query Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `limit` | integer | Max results (default 100, max 1000) |
| `cursor` | string | Opaque `e1` continuation from the previous `next_cursor` (maximum 128 bytes) |
| `start` | string | RFC3339 start (inclusive); see [list filters](#list-filters) |
| `end` | string | RFC3339 end (exclusive); see [list filters](#list-filters) |

Results order by `(ingested_at, event_id)` descending, including tied timestamps.
Copy `next_cursor` unchanged with the same filters; omit `cursor` to start a fresh
listing. Malformed, oversized, wrong-endpoint and superseded timestamp-only
cursors return `400` with a JSON `error`. Restart from the first page to obtain a
current event cursor. Filters apply before pagination. Undecodable eligible stored rows
cause `500`, including the lookahead row used for
`has_more`. Response fields are unchanged; terminal pages have `next_cursor: null`.

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
  "next_cursor": null,
  "has_more": false
}
```

`top_src_ports_json` appears only on events whose detector sent
`top_src_ports`, in the detector's order (`"[]"` when it sent an empty list).

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
| `status` | string | Filter by one or more statuses (comma-separated): `pending`, `active`, `withdrawn`, `expired`, `rejected`. Legacy `escalated` is still accepted for stored rows; no code path produces it |
| `customer_id` | string | Filter by customer |
| `victim_ip` | string | Filter by exact victim IP |
| `pop` | string | Exact case-sensitive POP identifier; omitted or literal `all` lists every POP |
| `acknowledged` | boolean | Filter by acknowledged status (`true`/`false`) |
| `limit` | integer | Max results (default 100, max 1000) |
| `cursor` | string | Opaque `m1` continuation from the previous `next_cursor` (maximum 128 bytes) |
| `start` | string | RFC3339 start (inclusive); see [list filters](#list-filters) |
| `end` | string | RFC3339 end (exclusive); see [list filters](#list-filters) |

A concrete `pop` filters rows before ordering, cursor continuation and page limits.
Identifiers match stored values exactly, including case, spaces and Unicode;
unknown identifiers return an empty page. Empty identifiers and identifiers containing
NUL return `400`. Omission and literal `all` both preserve the global listing scope.

Pages use descending `(created_at, mitigation_id)` order, so equal creation timestamps
remain complete across page boundaries. Copy `next_cursor` unchanged and keep the
same filters while paging; omit `cursor` to start a fresh listing. The cursor is
opaque: clients must not construct or interpret its contents.

Malformed, oversized and superseded timestamp-only mitigation cursors return
`400` with a JSON `error`; restart from the first page to obtain a current cursor.
The `mitigations`, `count`, `next_cursor` and `has_more` response fields are unchanged.
A persisted row that cannot be decoded fails the entire page with `500`, including
a corrupt lookahead row; it is never silently omitted or reported as end of history.

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
      "src_ports": [],
      "fragment": null,
      "packet_length": null,
      "created_at": "2026-01-18T10:30:00Z",
      "updated_at": "2026-01-18T10:30:00Z",
      "expires_at": "2026-01-18T10:32:00Z",
      "withdrawn_at": null,
      "triggering_event_id": "550e8400-e29b-41d4-a716-446655440000",
      "last_event_id": "550e8400-e29b-41d4-a716-446655440000",
      "reason": "Vector policy: udp_flood",
      "acknowledged_at": null,
      "acknowledged_by": null,
      "origin_mode": "enforced",
      "correlation": null
    }
  ],
  "count": 1,
  "next_cursor": null,
  "has_more": false
}
```

`action_type` is `discard`, `police` or `blackhole`. A blackhole also carries
the optional `blackhole` object described under
[manual blackhole](#manual-blackhole); FlowSpec rows omit it.

`src_ports`, `fragment` and `packet_length` are the
[ADR 028](../adr/028-amplification-matches.md) match components, in canonical
form. `src_ports` is a sorted, deduplicated list of UDP source ports (`[]` when
the rule does not match source ports). `fragment` is `"non_first"` for a rule
that matches non-first IP fragments, otherwise `null`. `packet_length` is an
inclusive total IP length range such as `{"min": 1000, "max": 65535}`, otherwise
`null`. The three fields are present in every mitigation response and WebSocket
message; controllers before this release omit them, which means none of the
components.

`origin_mode` records the operation mode that admitted the mitigation:
`dry-run` for a simulation that prefixd never announced, or `enforced`. It is
`null` for rows created before origin tracking that startup has not tagged;
treat `null` as unknown, never as enforced. The field is always present.

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

Directly create a mitigation with the exact parameters provided, skipping playbook
evaluation. The dashboard's "Rule" form posts here. Its "Mitigate Now" form
instead submits an attack event through `POST /v1/events`, which applies playbooks.

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
| `operator_id` | string | no | Legacy field, ignored; authenticated operator identity is authoritative |
| `reason` | string | yes | Reason for the mitigation |
| `victim_ip` | string | yes | IPv4 or IPv6 host address to protect (`/32` or `/128` scope) |
| `protocol` | string | conditional | Required for `"discard"` and `"police"`: `"udp"`, `"tcp"`, `"icmp"` (IPv4 protocol 1), `"icmpv6"` (IPv6 protocol 58), or `"any"`; `""` also selects any protocol. Omit for `"blackhole"` |
| `dst_ports` | array | no | Destination ports (default `[]`) |
| `src_prefix` | string | no | Same-family source CIDR; requires `guardrails.allow_src_prefix_match`. Host bits are cleared. Discard and police only; see [source-prefix matches](#source-prefix-matches) |
| `src_ports` | array | no | UDP source ports (default `[]`, which means not matched). Discard and police only; see [amplification matches](#amplification-matches) |
| `fragment` | string | no | `"non_first"` matches non-first IP fragments. Discard and police only |
| `packet_length` | object | no | `{"min": N, "max": M}`, an inclusive total IP packet length. Discard and police only |
| `action` | string | yes | `"discard"`, `"police"` or `"blackhole"` (Admin only, see [manual blackhole](#manual-blackhole)) |
| `confirm_victim_ip` | string | conditional | Required for `"blackhole"`: must exactly equal `victim_ip` |
| `rate_bps` | integer | conditional | Positive, exactly representable traffic rate for `"police"`; omit or use `null` for `"discard"` |
| `ttl_seconds` | integer | yes | Requested time-to-live; subject to configured minimum and maximum |
| `expires_at_cap` | RFC 3339 timestamp | no | Initial creation's absolute expiry ceiling, for maintenance recreation |

Reasons on manual creation, single/bulk withdrawal and safelist additions accept
up to 1,024 UTF-8 bytes, including an empty string. Manual creation and withdrawal
require a string `reason`; safelist additions also accept an omitted or `null`
reason. Authorized requests with an overlong reason return `400`; a missing or
non-string required reason returns `422`. Withdrawal records add the authenticated
actor prefix after checking the submitted reason's byte length.

Policing rates must round-trip exactly through the speaker's `f32` bytes/second
encoding. Rates of 1, 7, 8 and 9 bits/second are supported, including fractional
bytes/second. Zero, missing rates and values such as 16,777,217 bits/second or
`18446744073709551615` that lose precision are rejected with `400` before intent
is saved or the speaker is called. Discard requests must not carry a rate.

ICMP selectors must match the victim's address family: use `"icmp"` for IPv4
and `"icmpv6"` for IPv6. A mismatch returns `400` before intent is saved or the
speaker is called. For example, an IPv6 ICMP discard request is:

```json
{
  "reason": "Manual ICMPv6 mitigation",
  "victim_ip": "2001:db8::10",
  "protocol": "icmpv6",
  "action": "discard",
  "ttl_seconds": 120
}
```

When `expires_at_cap` is supplied, the saved expiry is the earlier of that cap
and the normal requested TTL deadline. Validation happens after awaited
preflight, under lifecycle serialization. An expired cap or remaining lifetime
below the configured minimum returns `422` without saving intent or announcing.
Remaining time is never rounded upward; the ordinary TTL guardrails still apply.
The cap applies to initial creation only. Subsequent detector events can extend
the stored expiry, so pause all creation and extension inputs during maintenance.

#### Source-prefix matches

Manual discard and police rules may include `src_prefix`, for example
`"198.51.100.99/24"` for an IPv4 victim, or `"2001:db8:1::/64"` for IPv6.
The response echoes the canonical network (`"198.51.100.0/24"` in the first
example), and mitigation list/detail responses expose `src_prefix: null` when
absent. The source and victim must have the same address family. Invalid CIDRs
are refused, and source-only rules are unavailable: `victim_ip` still selects
one destination host. An explicit `/0` matches all sources and has its own rule
identity; omit the field to leave the source component absent.

Set `guardrails.allow_src_prefix_match: true` before use. Otherwise creation
returns `422` before saving intent or calling the speaker, in either operation
mode. Source prefixes alone support every existing protocol selector. Adding
source ports, fragments or packet length keeps their UDP requirements below.
Blackholes refuse `src_prefix`. This manual match does not select a scrubber or
change the action to redirect; the supported actions remain discard and police.

The encodings follow [RFC 8955 section 4.2.2.2](https://www.rfc-editor.org/rfc/rfc8955.html#section-4.2.2.2)
and [RFC 8956 section 3.2](https://www.rfc-editor.org/rfc/rfc8956.html#section-3.2),
with IPv6 offset zero only. Both speakers expose `flowspec_match.source_prefix`;
speaker acceptance does not prove router installation or filtering. Sources may
be spoofed, so this field is chosen manually and is not derived from detector
samples. Follow the [downgrade procedure](../how-to/upgrading.md#source-prefix-matches-and-downgrade)
before running an older controller against these rules.

Older controllers may ignore unknown request fields. Clients must confirm
`speaker.capabilities.flowspec_match.source_prefix: true` from authenticated
health detail before submitting a source selector. The dashboard checks this
for each source-prefix creation and refuses if the read fails or support is
missing. Upgrade the controller before using a newer dashboard's source form.

#### Amplification matches

`src_ports`, `fragment` and `packet_length` narrow a FlowSpec rule to one part
of a reflection attack ([ADR 028](../adr/028-amplification-matches.md)). They
pass the same checks as `udp_amplification` playbook rules, in `dry-run` and
`enforced` modes alike, before anything is saved:

- All three need `"protocol": "udp"`.
- `src_ports` and `fragment` never share a rule: port matches never match a
  non-first fragment.
- `packet_length` needs `src_ports`, and `min` must be above the IP plus UDP
  header (28 bytes for IPv4, 48 for IPv6) with `min <= max <= 65535`.
- `src_ports` is capped by `guardrails.max_ports` separately from `dst_ports`.
  Duplicate ports count once.
- `fragment` needs `guardrails.allow_fragment_match: true`, and `packet_length`
  needs `guardrails.allow_packet_length_match: true`.

A refusal returns `422` with the reason, for example
`{"error": "guardrail violation: fragment matching not allowed (guardrails.allow_fragment_match=false)"}`,
and increments `prefixd_guardrail_rejections_total` with `reason`
`InvalidMatch`, `TooManySourcePorts`, `FragmentMatchNotAllowed` or
`PacketLengthMatchNotAllowed`. A component the selected speaker cannot encode
returns `400` (`the selected speaker cannot encode the source port match`).
Both bundled speakers encode all three; router support varies, so qualify your
platform ([vendor matrix](vendors.md)). The response echoes the canonical form:

```json
{
  "reason": "NTP and CLDAP reflection",
  "victim_ip": "203.0.113.10",
  "protocol": "udp",
  "src_ports": [389, 123, 123],
  "action": "discard",
  "ttl_seconds": 300
}
```

returns `201` with `"src_ports": [123, 389]`, `"fragment": null` and
`"packet_length": null`. A blackhole takes none of these fields; sending one
returns `400`.

**Response (201 Created):**

Returns the full mitigation object (same shape as [Get Mitigation](#get-mitigation)).
The desired row is committed before speaker mutation. Ordinary successful creation
and dry-run retain `201 Created`. If the speaker call fails or times out after
that commit, the response is `202 Accepted`, includes the same mitigation ID,
and adds `"announcement_outcome": "unconfirmed"`. Intent remains Active for
reconciliation and cleanup; do not blindly recreate it. This outcome belongs to
the creation request and is not stored or returned by later GET/list requests.
Neither Active status nor omission of the outcome proves router enforcement.
If the deadline passes during persistence, enforced creation retains the saved
intent and returns the same `202`/`unconfirmed` outcome without attempting an
announcement. Expiry cleanup retires it; reconciliation also rechecks expiry
after awaited reads before attempting a repair. This prevents starting a new RPC
after observed expiry, but cannot cancel a mutation already in flight or enforce
TTL while the controller is stopped.

**Error Responses:**

| Status | Reason |
|--------|--------|
| 400 | Invalid request (bad IP, invalid protocol or protocol/address-family mismatch, missing/zero/inexact police rate, discard with a rate, a match component the speaker cannot encode, blackhole confirmation mismatch or match fields, etc.) |
| 401 | Authentication required |
| 403 | A blackhole was requested without the Admin role, including every bearer token |
| 409 | Scope already has an active canonical owner or pending withdrawal, or an untracked local route holds a blackhole's prefix, or another injection owner, or none, holds a FlowSpec rule's match |
| 422 | Guardrail rejection (safelist, quotas, new mitigation rate, prefix length, amplification match invariants and opt-ins, blackhole disabled, victim, TTL and quota checks, etc.) |

Canonical ownership ignores equivalent IPv6 spelling and duplicate destination
ports. A duplicate manual request is rejected before speaker mutation, preserving
the original rule, action and TTL. Detector events extend a single existing owner;
ambiguous legacy ownership is rejected before consuming the external event ID.

#### Manual blackhole

`"action": "blackhole"` requests a remotely triggered blackhole (RTBH) host
route ([ADR 027](../adr/027-blackhole-mitigations.md)). It drops **all**
traffic to the victim, including legitimate traffic, so it has stricter rules
than FlowSpec:

- **Admin only.** Operator and Viewer sessions get `403`. Bearer tokens map to
  Operator, so `prefixdctl` and other token clients get `403` too. The role is
  checked before anything else.
- **Typed confirmation.** `confirm_victim_ip` must equal `victim_ip` exactly,
  character for character, and `reason` must be nonempty. Otherwise the request
  returns `400` without saving a row or audit entry.
- **Host route only.** Omit `protocol` (or send `"any"` or `""`),
  `dst_ports`, `src_prefix`, `src_ports`, `fragment`, `packet_length`, `rate_bps` and
  `expires_at_cap`; any of them returns `400`. The
  route is the victim's `/32` or `/128`.
- **Guardrails.** `blackhole.enabled` must be true, the victim must be owned in
  inventory and pass the [blackhole victim checks](configuration.md#blackhole),
  and the TTL must be nonzero and at most `blackhole.max_ttl_seconds`. These
  return `422`, as do the blackhole quotas.
- **Conflicts.** `409` when the victim already has a live blackhole, has a
  pending blackhole withdrawal, or (in enforced mode) the speaker holds a local
  route at the prefix that prefixd does not own.

```json
{
  "reason": "Volumetric attack saturating transit",
  "victim_ip": "203.0.113.10",
  "confirm_victim_ip": "203.0.113.10",
  "action": "blackhole",
  "ttl_seconds": 600
}
```

Dry-run saves and audits the blackhole and sends nothing. Enforced mode saves
it, rechecks the safelist and adds the route; the same `201`/`202`
`announcement_outcome` rules apply as above. Without `blackhole.leased`, a
manual blackhole is unleased: it stays on the speaker if prefixd stops, until
prefixd returns and expires it or an Admin deletes it on the speaker. With
[leased blackholes](configuration.md#leased-blackholes) the speaker removes it
within one lease, and a route held by another injection owner, or by none,
returns `409` with nothing added. The response carries the saved route:

```json
{
  "action_type": "blackhole",
  "dst_prefix": "203.0.113.10/32",
  "protocol": null,
  "dst_ports": [],
  "blackhole": {
    "next_hop": "192.0.2.66",
    "communities": ["64496:666", "65535:666"],
    "large_communities": []
  }
}
```

`blackhole` is present only on blackholes, in every mitigation response and
WebSocket message. It is the next hop and communities frozen at admission, not
evidence that a router installed or enforces the route. Withdraw a blackhole
with the ordinary [withdraw](#withdraw-mitigation) and
[bulk withdraw](#bulk-withdraw-mitigations) endpoints.

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

An active (or escalated) blackhole admitted in enforced mode also carries
`export_evidence`: per-peer export from the last reconciliation pass
([export evidence](speaker-backends.md#export-evidence)). It is absent from list
responses, FlowSpec rules, dry-run blackholes and terminal rows. The request reads
the controller's snapshot and never calls the speaker.

```json
"export_evidence": {
  "status": "observed",
  "historical": false,
  "observed_at": "2026-10-20T12:00:00Z",
  "peers": [
    {"peer_address": "192.0.2.10", "disposition": "committed", "reason": "",
     "explain_code": "", "detail": "in the peer's Adj-RIB-Out", "advertised_path_id": 0},
    {"peer_address": "192.0.2.11", "disposition": "withheld", "reason": "export_policy",
     "explain_code": "policy_denied", "detail": "export policy \"rtbh-out\" denied this route",
     "advertised_path_id": 0}
  ],
  "not_established_peers": [{"peer_address": "192.0.2.12", "state": "active"}],
  "counts": {"committed": 1, "withheld": 1, "pending": 0},
  "warning": null,
  "error": null
}
```

| Field | Meaning |
|-------|---------|
| `status` | `observed` (read to the last page), `no_local_route` (the speaker holds no local route at the key), `error` (the read failed or was partial: current export unknown), `unsupported` (GoBGP) or `not_observed` (no pass has read it yet) |
| `historical` | `true` when retained evidence predates the controller's last loss of ownership, including after ownership returns. Only a fresh complete read makes that route current again; this is independent of `status` |
| `observed_at` | Controller time of the read. Historical rows retain their original observation time even if a later refresh fails; `error` reports that new failure |
| `peers` | One row per Established peer. `disposition` is `committed` (in that peer's Adj-RIB-Out, not proof of receipt, installation or enforcement), `withheld` or `pending`; `reason` and `explain_code` are rustbgpd's bounded codes and `detail` its unstable text |
| `not_established_peers` | Configured peers without an Established session at the observation, which were sent nothing. `null` when that session read failed or is unsupported |
| `counts` | Peer rows by disposition |
| `warning` | Present when an observed blackhole is committed to no Established peer: a bounded `reason` (`no_established_peer`, `export_policy`, `family_suppressed`, `family_not_negotiated`, `not_selected`, `outbound_prefix_limit`, `exact_export_rejected`, `export_rule`, `pending`, `mixed` or `other`) and a `message`. `export_policy` means a speaker export policy denied the route. With `status` `error`, it is the last complete read's warning, kept so a transient read error does not clear degraded health |
| `error` | The read error when `status` is `error` |

An ordinary failed read has no peer rows. If a refresh after loss of controller
ownership fails, the response instead retains the historical peer rows, counts,
session observations and original timestamp with `historical: true` and
`status: "error"`. These rows do not establish current export. A successful
`no_local_route` read is a fresh observation and clears those old peer rows.
An in-flight observation spanning ownership loss is discarded, even if the
controller regains ownership before the RPC returns. HTTP reads never refresh
the snapshot themselves.

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

Withdrawal intent is saved before calling the speaker. An uncertain speaker
reply or database completion failure leaves cleanup pending; reconciliation
retries it, including after a controller restart. The mitigation keeps its
previous status until deletion and the terminal-state/audit transaction succeed.
Pending cleanup is excluded from announcement repair. The original principal
and reason are retained when the scheduler completes the request; the legacy
`operator_id` request field does not override the authenticated principal.

A withdrawal targeting another POP or a rule with another live owner returns
409 before deleting anything. A new event or manual request that would revive
a pending deletion also returns 409. Bulk requests report these conflicts in
their per-item errors.

Enforced-mode pending requests remain pending while the controller runs in
dry-run. No terminal state, success notification or completion audit is produced
until confirmed deletion after enforcement resumes. Requests originally created
in dry-run remain local simulations.

If an earlier TTL-expiry request is already pending, a successful retry completes
that original operation as `expired`. The single-withdraw response and mitigation
detail show the actual terminal status. Detector event processing and bulk
withdrawal results retain their legacy `withdrawn` success labels, which describe
successful deletion processing rather than overriding that terminal status.

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

Results preserve request order, including duplicate IDs. `acknowledged` and
`failed` count request entries, matching the corresponding result statuses.
A fresh ID repeated within one request produces a successful result for each
occurrence while its stored row is updated once. Subsequent requests for that
already-acknowledged ID produce an error for each occurrence. The 100-entry limit
includes duplicates.

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
| `cursor` | string | Opaque `s1` continuation from the previous `next_cursor` (maximum 128 bytes) |
| `start` | string | RFC3339 start (inclusive); see [list filters](#list-filters) |
| `end` | string | RFC3339 end (exclusive); see [list filters](#list-filters) |

Results order by `(created_at, group_id)` descending, including tied timestamps.
Copy `next_cursor` unchanged with the same filters; omit `cursor` to start a fresh
listing. Malformed, oversized, wrong-endpoint and superseded timestamp-only
cursors return `400` with a JSON `error`. Restart from the first page to obtain a
current signal-group cursor. Filters apply before pagination. Undecodable eligible stored rows
cause `500`, including the lookahead row used for
`has_more`. Response fields are unchanged; terminal pages have `next_cursor: null`.

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

Returns group metadata and all contributing events with source, confidence, and source weight. When `correlation.confidence_decay_half_life_seconds` (or the playbook override) is non-zero, `derived_confidence` is computed with exponential time decay applied — older events contribute proportionally less weight. See [ADR 022](../adr/022-confidence-decay.md). The `corroboration_met` flag is sticky: once set to `true` it never reverts to `false`, even if decay drives `derived_confidence` back under the threshold.

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

Signal adapter endpoints accept webhooks from external detection and telemetry systems, translate their payloads into `AttackEventInput`, and feed them into the standard event ingestion pipeline (including correlation, guardrails, and policy evaluation). See [ADR 019](../adr/019-signal-adapter-architecture.md).

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
| `top_src_ports` | `annotations.top_src_ports`, comma-separated ports such as `"123, 11211"`; read for firing alerts only | None |
| `confidence` | `labels.severity` → `critical`=0.9, `warning`=0.7, `info`=0.5 | 0.5 |
| `action` | `alerts[].status` ("resolved" → "unban", else "ban") | "ban" |
| `event_id` (dedup) | `alerts[].fingerprint` | None |
| `source` | hardcoded `"alertmanager"` | — |

For UDP reflection, set `labels.vector` to `udp_amplification` and list the
reflector source ports in `annotations.top_src_ports`. prefixd keeps only ports
in its [reflector-port library](configuration.md#amplification) and handles the
event as `udp_flood` when none remain. A `top_src_ports` annotation with an
empty or non-numeric entry, or a port above 65535, fails that alert with
`status: "error"` rather than becoming an empty list; more than 64 ports fails
it the same way. Resolved alerts ignore the annotation.

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
  },
  "packet_dump_detailed": [
    {
      "ip_version": "ipv4",
      "source_ip": "198.51.100.10",
      "destination_ip": "203.0.113.10",
      "source_port": 123,
      "destination_port": 40000,
      "protocol": "udp",
      "fragmentation": false,
      "packets": 1,
      "length": 486,
      "sample_ratio": 1024
    }
  ]
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | string | yes | `"ban"`, `"unban"`, `"partial_block"`, or `"alert"` |
| `ip` | string | yes | Victim IPv4 address under attack |
| `alert_scope` | string | no | Scope: `"host"` or `"total"` |
| `attack_details` | object | no | Traffic metrics and classification (see below) |
| `packet_dump_detailed` | array | no | Sampled packets as FastNetMon serializes them. prefixd reads `protocol`, `source_port` and `packets` of each entry and ignores entries it cannot read |

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

- **UDP dominant** → `udp_flood`, or `udp_amplification` when sampled packets
  show reflector source ports (below)
- **SYN TCP dominant** (>60% of TCP PPS) → `syn_flood`
- **ICMP dominant** → `icmp_flood`
- **Other TCP** → `ack_flood`
- **No details** → `unknown`

For a UDP-dominant attack, prefixd sums the UDP entries of
`packet_dump_detailed` per `source_port`, weighted by `packets`. Each
[reflector-port library](configuration.md#amplification) port whose share of
sampled UDP packets is at least `amplification.min_src_port_share` (default
0.2) is kept, ranked by share. If any port is kept, the event is
`udp_amplification` with those ports in `top_src_ports`. Otherwise, including
with no dump, an empty dump or entries that do not parse, the vector above
stands. TCP and ICMP attacks are never classified as amplification.

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
| 422 | Guardrail rejection (safelist, quotas, new mitigation rate, prefix length) |

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

See `docs/how-to/detectors/fastnetmon.md` for a complete integration guide.

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

See `docs/reference/configuration.md` for the complete schema.

### Corroborator Signal

Ingest a **corroborating signal** from a source configured with
`mode: corroborating` in `correlation.yaml`. Corroborators don't carry a
`victim_ip`; instead they match open signal groups on lighter dimensions
(`customer_id`, `pop`, `service_id`, `interface`) declared in the
source's `match_dimensions`. See [ADR 021](../adr/021-corroborating-signals.md).

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
- `confidence` *(optional)* — Finite 0.0–1.0 inclusive, or null. Invalid values
  return 400 before events, groups or cached signals change. Contributes to the group's
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

**Response (201 Created):**

```json
{
  "withdrawn_mitigation_ids": ["550e8400-e29b-41d4-a716-446655440000"]
}
```

Adding an entry also withdraws every live blackhole on this POP whose victim
falls inside the prefix, under the lifecycle mutex, with the system reason
`safelisted after admission` (ADR 027). `withdrawn_mitigation_ids` lists them
and is empty when none were covered. Dry-run blackholes are retired without a
speaker call. FlowSpec rules are not withdrawn.

When the covered blackholes could not be found or withdrawn, the entry is still
stored and the response adds `withdrawal_error`. A failed lookup withdraws
nothing; reconciliation withdraws covered enforced routes on its next pass.

```json
{
  "withdrawn_mitigation_ids": [],
  "withdrawal_error": "covered blackhole lookup failed; nothing was withdrawn"
}
```

### Remove from Safelist

```http
DELETE /v1/safelist/{prefix}
Authorization: Bearer <token>
```

`prefix` is the stored CIDR, e.g. `8.9.8.9/32`. Both a percent-encoded separator
(`/v1/safelist/8.9.8.9%2F32`) and a literal slash (`/v1/safelist/8.9.8.9/32`)
are accepted, so proxies that decode `%2F` work too.

**Response (204 No Content)**

**Response (404 Not Found)** — prefix is not in the safelist.

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

Sets a session cookie for subsequent requests.

**Response (401 Unauthorized):** Invalid credentials.

**Response (403 Forbidden):** `http.auth.mode: none` disables named login. The
request is rejected before operator lookup or the username login throttle.

### Logout

```http
POST /v1/auth/logout
```

**Response (200 OK)**

Deletes the stored session and clears its cookie. This endpoint remains available
in `none` mode so clients can remove a session retained from another mode.

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

**Response (401 Unauthorized):** Not logged in, or authentication mode is `none`.
Anonymous access does not create an authenticated operator profile.

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
| `password` | string | yes | 8–256 UTF-8 bytes |
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
| 400 | Invalid role or password outside 8–256 UTF-8 bytes |
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
  "current_password": "oldpassword123",
  "new_password": "newsecurepassword123"
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `current_password` | string | required for self-change, optional for admin reset | Current password. Must match the operator's existing password when changing own password. Ignored for admin resets of other operators. |
| `new_password` | string | yes | New password, 8–256 UTF-8 bytes. |

Admins can change any operator's password without supplying the current password (admin reset). Non-admins can only change their own password and must provide `current_password`, which is verified against the stored hash before the change is applied.

**Response (204 No Content)**

**Error Responses:**

| Status | Reason |
|--------|--------|
| 400 | New password outside 8–256 UTF-8 bytes or incorrect current password |
| 401 | Not authenticated |
| 403 | Insufficient permissions (non-admin attempting to change another operator's password) |
| 404 | Operator not found |

---

## Operational Endpoints

### Local FlowSpec Inventory

```http
GET /v1/speaker/routes
Authorization: Bearer <token>
```

Requires the configured authentication; viewer sessions may read it. This
read-only endpoint is available in dry-run and standby, without an active
controller fence or mitigation database query. It observes the selected
speaker directly, without a health preflight or a route mutation.

**Response (200):**

```json
{
  "backend": "rustbgpd",
  "observation_scope": "retained_local_flow_spec_intent",
  "routes": [
    {
      "nlri": {
        "dst_prefix": "203.0.113.10/32",
        "src_prefix": "198.51.100.0/24",
        "protocol": 17,
        "dst_ports": [443]
      },
      "actions": [{ "action_type": "police", "rate_bps": 125000 }],
      "owner": "<injection-owner>"
    }
  ]
}
```

This is the complete local **FlowSpec** inventory for IPv4 and IPv6, including
untracked rules. It excludes unicast routes and blackholes. The match, actions
and rate in bits per second are preserved; `owner` is present for owned rules
and omitted for unleased rules. Optional source-prefix, source-port, fragment
and packet-length matches retain their existing JSON representation.

| `observation_scope` | Meaning |
| --- | --- |
| `retained_local_flow_spec_intent` | rustbgpd's retained local injection intent |
| `accepted_local_flow_spec_rib` | GoBGP's accepted local RIB after import policy |
| `adapter_local_flow_spec` | Mock or custom adapter's local read-back |

None of these observations proves selected RIB state, export, router receipt
or enforcement. A successful empty observation returns `routes: []`. A failed
or partial inventory returns no routes, rather than presenting it as empty.

| Status | Meaning |
| --- | --- |
| 401 | Authentication required |
| 501 | Local FlowSpec observation is unsupported by this speaker |
| 502 | Local FlowSpec observation failed; inventory is unavailable |

The 501 and 502 responses use the [error format](#error-responses) and omit
upstream diagnostic details. See also
[`prefixdctl speaker list-routes`](cli.md#speaker-routes).

### Health Check (Public)

```http
GET /v1/health
```

Lightweight liveness check. No authentication required. Does not query the
database or selected speaker. In the examples below, `<prefixd-version>` is the
running controller's package version; `auth_mode` reflects its configured mode.

**Response:**

```json
{
  "status": "ok",
  "version": "<prefixd-version>",
  "auth_mode": "none"
}
```

| Field | Description |
|-------|-------------|
| `status` | Always `"ok"` if the daemon is running |
| `version` | Controller (prefixd) version |
| `auth_mode` | Authentication mode: `none`, `bearer`, `credentials`, `mtls` |

### Readiness (Public)

```http
GET /v1/ready
```

Public readiness for load balancers and detector routing. No authentication is
required, and it does not query the database or speaker. The response is
`{"status": "<status>"}`; the first matching row applies:

| Status | HTTP | Meaning |
|--------|------|---------|
| `standby` | 503 | Another controller holds this POP's fence ([ADR 027](../adr/027-blackhole-mitigations.md)) |
| `draining` | 503 | A shutdown signal arrived; the controller still holds the fence until it exits |
| `ready` | 200 | This controller holds the fence and accepts mutations |

Standby and draining controllers refuse detector events, so route detector
events and operator writes only to a ready controller. Draining begins before
any other shutdown step, so set the load balancer's readiness check interval
shorter than `shutdown.drain_timeout_seconds`. `GET /v1/health` stays liveness:
it returns `200` for standby and draining controllers too.

### Health Detail (Authenticated)

```http
GET /v1/health/detail
Authorization: Bearer <token>
```

Full operational health using the configured authentication mode. The request
and response below illustrate bearer mode. In credentials mode, send a session
cookie; native mTLS requires a client certificate. `none` requires no credentials.

**Illustrative response with rustbgpd:**

```json
{
  "status": "healthy",
  "version": "<prefixd-version>",
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
  "speaker": {
    "backend": "rustbgpd",
    "capabilities": {
      "rule_reader": true,
      "peer_observer": true,
      "daemon_health": true,
      "blackhole": true,
      "blackhole_lease": false,
      "blackhole_export": true,
      "flowspec_match": {
        "source_prefix": true,
        "source_ports": true,
        "fragment": true,
        "packet_length": true
      }
    },
    "detector_unleased": false,
    "lease": {
      "owner": "prefixd.iad1.3f9c2a7b1e04d5c6",
      "lease_seconds": 60,
      "state": "live",
      "generation": {"incarnation": 1311768467294899695, "sequence": 4},
      "last_renewal_at": "2026-10-18T12:00:00Z",
      "last_renewal_result": "success"
    },
    "blackhole_exports": {
      "historical": false,
      "observed_at": "2026-10-18T12:00:00Z",
      "blackholes": 2,
      "counts": {"committed": 3, "withheld": 1, "pending": 0},
      "errors": 0,
      "no_local_route": 0,
      "unexported": []
    },
    "daemon": {
      "status": "observed",
      "version": "<rustbgpd-version>",
      "uptime_seconds": 43200,
      "ready": true,
      "observed_at": "2026-10-18T12:00:00Z"
    }
  },
  "auth_mode": "bearer"
}
```

| Status | Meaning |
|--------|---------|
| `healthy` | Database and supported observations succeeded; observed daemon is ready |
| `degraded` | Database or supported observation failed, observed daemon is not ready, active blackhole export evidence is historical, or an active blackhole is committed to no Established peer |
| `standby` | Another controller holds this POP's fence; this one mutates nothing (overrides the other values) |

`speaker` is additive metadata: backend identity plus observation availability.
Older daemons may omit it. Capabilities do not report recent read success or
rule delivery. `blackhole` reports the unicast blackhole adapter and
`blackhole_lease` its owner-scoped injection lease
([ADR 027](../adr/027-blackhole-mitigations.md)); both are false when absent.
`flowspec_match` reports which match components the speaker encodes: source
prefixes and the [amplification matches](../adr/028-amplification-matches.md).
Each is false when absent. Manual requests can select all these components;
playbooks select amplification components only. `detector_unleased` is true
when enforced detector blackholes run without the injection lease
(`blackhole.enabled`, a nonempty `blackhole.detector_sources` and
`blackhole_lease` false): if prefixd stops while the speaker runs, they stay
announced until prefixd returns or an operator withdraws them. `lease` is
present only with `blackhole.leased`: `state` is `none` (no generation held
yet), `live`, `renewal_failing` (the last renewal failed but the lease may
still be live), `expired` (the speaker refused the generation, or no
renewal succeeded for a whole lease) or `not_renewing` (dry-run, which never
renews). `generation` is held in memory and
changes after a speaker restart. `last_renewal_result` is `success`,
`not_live` or `error`. Health performs no rule inventory probe.

`blackhole_exports` is present when `blackhole_export` is true (rustbgpd). It
summarizes the last reconciliation pass's
[export evidence](speaker-backends.md#export-evidence) for active enforced
blackholes, read from the controller's snapshot: `observed_at` (null before the
first pass), `blackholes`, peer `counts` by disposition, `errors` (reads that
failed, so export is unknown), `no_local_route`, and `unexported`. Each
`unexported` entry is an observed blackhole committed to no Established peer,
with `mitigation_id`, `prefix`, a bounded `reason` and a `message`; any entry
makes `status` `degraded`. A committed disposition is the peer's Adj-RIB-Out,
not router receipt or enforcement.

`historical` is true if any retained export evidence predates the controller's
last loss of ownership. The top-level status remains `standby` while ownership
is absent; after ownership returns, historical evidence makes it `degraded`
until a fresh complete observation replaces each retained route. Historical
counts and warnings describe the retained observation, not current export.

Top-level `version` and `uptime_seconds` describe prefixd. `speaker.daemon`
independently reports authenticated speaker process metadata: `observed`, `error`
or `unsupported`. Successful observations carry receipt time `observed_at`,
reported uptime (including zero), readiness and a nullable daemon version. Empty
versions remain unknown. Errors and unsupported observations carry null metadata.
GoBGP's current API lacks this process metadata; peer uptime is not substituted.
The additional health probe runs concurrently with existing checks, with a
two-second observation budget including retries. This may add latency. No rule
inventory or routing-enforcement probe is performed.

The compatibility field `gobgp.status` describes the selected speaker's peer
observation: `connected` means a successful read, including zero peers; `error`
includes an error string; `unsupported` omits `error` and leaves `bgp_sessions`
empty. Unsupported optional observation alone allows `healthy`. An empty peer
map must be interpreted together with that status. The public liveness response
is unchanged. None of these fields proves announcement or router enforcement.

> **Migration note (v0.8.2 → v0.8.3):** The public `GET /v1/health` endpoint no longer returns BGP sessions, database status, or operational details. Monitoring systems and scripts that parse these fields must switch to `GET /v1/health/detail` with authentication. See [ADR 015](../adr/015-health-endpoint-split.md).

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

Range accepts bare hours, `h` or `d`; bucket accepts bare minutes, `m` or `h`.
Outer whitespace is ignored. Invalid formats and quantities outside unsigned
32-bit range use the defaults (24 hours and 60 minutes). Unit conversions saturate
at the unsigned 32-bit maximum before the 168-hour range cap and 5-minute bucket
minimum are applied.

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

Returns events and mitigations for a given IP, plus customer/service context from
inventory. Each type is limited to the newest `limit` rows (default 100, maximum
1000). An undecodable mitigation within that selection returns `500`; the response
does not silently omit it. Rows for other IPs or outside the selected limit do not
affect this history request.

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

Returns the running daemon configuration with sensitive fields redacted (allowlist approach). See [ADR 014](../adr/014-allowlist-config-redaction.md).

**Response:**

```json
{
  "settings": {
    "pop": "iad1",
    "mode": "enforced",
    "http": { "listen": "0.0.0.0:8080", "auth": { "mode": "bearer" }, "rate_limit": { "events_per_second": 100, "burst": 500 } },
    "bgp": { "mode": "sidecar", "local_asn": 65010, "neighbors": [{ "name": "172.30.30.3", "address": "172.30.30.3", "peer_asn": 65001, "afi_safi": ["ipv4-flowspec"] }] },
    "guardrails": { "require_ttl": true, "dst_prefix_minlen": 32, "dst_prefix_maxlen": 32, "max_ports": 5 },
    "quotas": { "max_active_per_customer": 20, "max_active_global": 500 },
    "timers": { "default_ttl_seconds": 120, "reconciliation_interval_seconds": 30 },
    "storage": { "connection_string": "[redacted]" },
    "observability": { "log_format": "json", "log_level": "info" },
    "safelist": { "count": 3 },
    "shutdown": { "drain_timeout_seconds": 30 }
  },
  "loaded_at": "2026-02-18T12:00:00Z"
}
```

> **Note:** TLS paths, bearer token env vars, BGP passwords, gRPC endpoints, router ID, and safelist prefixes are omitted. New config fields are hidden by default.

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
- Unique playbook names (max 128 UTF-8 bytes)
- Valid vector (`udp_flood`, `udp_amplification`, `syn_flood`, `ack_flood`, `icmp_flood`, `unknown`)
- At least one step per playbook
- Each step has one `action` (`police`, `discard` or `blackhole`) or a `rules`
  list, never both. `rules` steps are valid only in `udp_amplification`
  playbooks ([multi-rule steps](configuration.md#multi-rule-steps-udp-amplification));
  [blackhole steps](configuration.md#blackhole-steps) are not
- `police` steps require `rate_bps > 0` exactly representable as an `f32` bytes/second traffic rate
- `discard` steps must omit `rate_bps` or set it to `null`
- `ttl_seconds` must be 1-86400
- `require_confidence_at_least` must be 0.0-1.0
- First step must not have escalation requirements

**Error response (400):**

```json
{
  "errors": ["playbook[0] (\"bad\") step[0]: action 'police' requires rate_bps > 0"]
}
```

A body that does not decode, such as an unknown key in a `rules` entry, also
returns `400` with the decoder's reason as the only entry in `errors`. The
dashboard's playbook editors show these entries verbatim.

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
  "events": ["mitigation.created", "mitigation.expired"]
}
```

**Per-destination events:** Each destination may include an optional `events` array to override the global event filter. If present, only those event types are sent to that destination. If absent or empty, the destination inherits the global `events` list. See ADR 017.

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
- Slack/Discord/Teams: `webhook_url` required, max 1024 UTF-8 bytes, must be valid `https://` URL
- Telegram: `bot_token` and `chat_id` required, `chat_id` max 64 UTF-8 bytes
- PagerDuty: `routing_key` required, `events_url` max 1024 UTF-8 bytes, must be valid `https://` URL
- OpsGenie: `api_key` required, `region` must be `us` or `eu`
- Generic: `url` required, max 1024 UTF-8 bytes, must be valid `https://` URL
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

### Correlation Config

```http
GET /v1/config/correlation
Authorization: Bearer <token>
```

Returns the correlation engine configuration with secrets redacted. See the [Correlation](configuration.md#correlation) section for field semantics.

**Response:**

```json
{
  "config": {
    "enabled": true,
    "window_seconds": 300,
    "min_sources": 1,
    "confidence_threshold": 0.5,
    "default_weight": 1.0,
    "confidence_decay_half_life_seconds": 0,
    "sources": {
      "fastnetmon": {
        "weight": 1.0,
        "type": "detector",
        "confidence_mapping": {},
        "mode": "primary",
        "match_dimensions": []
      }
    },
    "webhook_adapters": [
      {
        "name": "radware",
        "description": "Radware DefensePro",
        "enabled": true,
        "auth": {
          "type": "hmac",
          "secret_env": "RADWARE_WEBHOOK_SECRET",
          "header": "X-Signature-SHA256",
          "algorithm": "sha256"
        },
        "root_path": null,
        "fields": {
          "victim_ip": "$.target.ip",
          "vector": "$.alert_type"
        },
        "vector_map": {},
        "default_vector": "unknown",
        "confidence_scale": null,
        "source_id_prefix": null,
        "transforms": {}
      }
    ]
  },
  "loaded_at": "2026-02-22T21:00:00Z"
}
```

HMAC `secret_env` values are returned as-is (they name an environment variable, not a secret). No raw secret values are exposed.

### Update Correlation Config

```http
PUT /v1/config/correlation
Authorization: Bearer <token>
Content-Type: application/json

{
  "enabled": true,
  "window_seconds": 300,
  "min_sources": 2,
  "confidence_threshold": 0.7,
  "default_weight": 1.0,
  "sources": {
    "fastnetmon": { "weight": 1.0, "type": "detector", "mode": "primary" }
  }
}
```

**Admin only.** Validates the config, writes it to `correlation.yaml` (with `.bak` backup), and hot-reloads the in-memory correlation engine. Returns the updated config with secrets redacted.

Validation rules (rejected with 400 on failure):
- `window_seconds` must be > 0
- `min_sources` must be >= 1
- `confidence_threshold` must be between 0.0 and 1.0
- `default_weight` must be >= 0.0
- `confidence_decay_half_life_seconds` must be <= 10 × `window_seconds`
- Per-source `mode=corroborating` requires a non-empty `match_dimensions`; `mode=primary` requires empty `match_dimensions`
- Webhook adapter `name` must match `[a-z0-9-]{1,64}` and be unique

**Response:** Same shape as `GET /v1/config/correlation`, with `loaded_at` set to the update timestamp.

**Error response (400):**

```json
{
  "errors": ["source 'router-cpu': match_dimensions must be non-empty when mode=corroborating"]
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
  "reloaded": ["inventory", "playbooks", "correlation", "alerting"],
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

`mitigation` uses the [mitigation response](#get-mitigation) shape, including
the `blackhole` object for blackholes. A manual blackhole broadcasts
`mitigation_created`.

`event_ingested` is defined in the message schema but is not currently broadcast
by event ingestion. Event lists retain their periodic API refresh.

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
| `cursor` | string | Opaque `a1` continuation from the previous `next_cursor` (maximum 128 bytes) |
| `start` | string | RFC3339 start (inclusive); see [list filters](#list-filters) |
| `end` | string | RFC3339 end (exclusive); see [list filters](#list-filters) |

Results order by `(timestamp, audit_id)` descending, including tied timestamps.
Copy `next_cursor` unchanged with the same filters; omit `cursor` to start a fresh
listing. Malformed, oversized, wrong-endpoint and superseded timestamp-only
cursors return `400` with a JSON `error`. Restart from the first page to obtain a
current audit cursor. Filters apply before pagination. Undecodable eligible stored rows
cause `500`, including the lookahead row used for
`has_more`. Response fields are unchanged; terminal pages have `next_cursor: null`.

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

Every admitted mitigation writes one `create` entry in the same database
transaction as its row, so neither exists without the other. This covers manual
creation, `/v1/events`, `/v1/events/batch` and the Alertmanager, FastNetMon and
generic webhook adapters, in both enforced and dry-run modes. `target_id` is the
mitigation ID. A manual creation has `actor_type: "operator"` and the operator's
username. A detector creation has `actor_type: "detector"`, the event's `source`
as `actor_id` (the adapter name for a generic webhook) and the triggering
`event_id` in `details`:

```json
{
  "actor_type": "detector",
  "actor_id": "fastnetmon",
  "action": "create",
  "target_type": "mitigation",
  "target_id": "7f72a903-63d1-4a4a-a5db-0517e0a7df1d",
  "details": {
    "pop": "iad1",
    "customer_id": "cust_example",
    "victim_ip": "203.0.113.10",
    "scope": { "dst_prefix": "203.0.113.10/32", "protocol": 17, "dst_ports": [53] },
    "action_type": "police",
    "action_params": { "rate_bps": 5000000 },
    "ttl_seconds": 120,
    "expires_at": "2026-01-18T10:33:00Z",
    "origin_mode": "enforced",
    "reason": "udp_flood to DNS (playbook: udp_flood_police)",
    "event_id": "0b6a5d4e-8f0e-4d55-9a3c-6f1d2e7b9c10"
  }
}
```

A repeat event that extends an existing mitigation's TTL is not a creation and
writes no audit entry; the mitigation's `last_event_id` and `expires_at` record
it. Rejected admissions, including guardrail, quota and
`max_new_per_minute` rejections, write no `create` entry. Event rules refused
by an active quota write `reject_rule` entries targeting their event, with
`scope`, `scope_hash`, `action_type`, `quota_type`, `current`, `max` and
`reason`. These also cover refusals within a partially admitted event.
Audit write failures are logged; admitted rules remain visible in the response.

Every blackhole add the speaker accepts, at admission and on repair or leased
re-add, writes an `announce` entry targeting the mitigation, with
`actor_type: "system"`, `actor_id: "speaker"` and `details` `prefix`,
`next_hop`, `owner` and `outcome`. `outcome` is what the speaker reported
against its previous local route at the key: `created`, `replaced`, or
`unknown` when it reported none. An `unchanged` add, a re-add of a route the
speaker still held, changed nothing and is logged without an entry. It is
local acceptance only, not export or router enforcement. A failed add writes
no entry, and a failed audit write is logged without failing the add.

`prefixd_event_rule_quota_rejections_total{quota_type,rule_kind,action_type}`
counts each event rule refused by an active quota. `rule_kind` is
`source_ports`, `fragment` or `other`; exact scopes are in responses and audit
entries, avoiding per-victim metric labels.

---

## Metrics

### Prometheus Metrics

```http
GET /metrics
```

This endpoint is unauthenticated on the API listener, for trusted-network
scrapes. Default Compose does not publish that listener; nginx and the dashboard
proxy do not forward metrics. Prometheus scrapes `prefixd:8080` internally.
See [monitoring access](../how-to/deployment.md#monitoring).

Returns Prometheus text format:

```
# HELP prefixd_mitigations_active Current active mitigations
# TYPE prefixd_mitigations_active gauge
prefixd_mitigations_active{action_type="discard",pop="iad1"} 5

# HELP prefixd_http_requests_total Total HTTP requests
# TYPE prefixd_http_requests_total counter
prefixd_http_requests_total{method="POST",route="/v1/events",status_class="2xx"} 1543
```

### Speaker series

Speaker metrics keep their existing names and add a `backend` label. Its bounded
values are `rustbgpd`, `gobgp`, `mock`, and `other` for third-party adapters.
Endpoints, owners, targets and user-supplied backend names are never label values.
Update queries that depend on the previous label sets when upgrading.

| Metric | Labels | Meaning |
| --- | --- | --- |
| `prefixd_announcements_total` | `backend`, `status` | Successful local add (`announced`) or completed withdrawal (`withdrawn`), for FlowSpec and blackholes |
| `prefixd_announcements_latency_seconds` | `backend` (plus histogram `le`) | Latency recorded by the successful add and withdrawal paths |
| `prefixd_bgp_session_up` | `backend`, `peer` | Last complete peer observation: `1` for Established, `0` for another known state |
| `prefixd_speaker_capability` | `backend`, `capability` | `1` for an available capability, `0` for unavailable or unconfirmed |

The selected backend's announcement counters and histogram start at zero.
Every metrics scrape refreshes capabilities from local adapter state without a
speaker RPC. Capability values match health detail's `speaker.capabilities`:
`rule_reader`, `peer_observer`, `daemon_health`, `blackhole`, `blackhole_lease`,
`blackhole_export`, `flowspec_source_prefix`, `flowspec_source_ports`,
`flowspec_fragment` and `flowspec_packet_length` (the last four correspond to
`flowspec_match` fields). Lease capability is `0` until a successful runtime
probe confirms it, and returns to `0` if a lease RPC reports unsupported after
a speaker rollback. Zero alone cannot distinguish unprobed from unsupported.
Capability is availability, not current health, a live lease, export or router
installation; use the separate lease-state and export series for those stages.

A successful complete peer inventory retires samples for omitted peers; a
successful empty inventory removes every peer sample. Unsupported observations,
stream failures, malformed rows and other failed reads retain the last complete
snapshot. Retained `1` values can therefore be stale during observation failure;
an error is never converted to a successful empty result or a guessed down state.
The capability gauge identifies an unavailable observer, not freshness of a
supported observer. The Grafana session panel uses an instant query so retired
peers are not displayed from historical samples.

`prefixd_controller_fence_active` is `1` while this controller holds its POP's
fence and `0` in standby. Alert when no controller for a POP reports `1`.
`prefixd_blackhole_detector_unleased` is `1` when enforced detector blackholes
run without the rustbgpd injection lease, matching health detail's
`speaker.detector_unleased`. The shipped
[availability alerts](../how-to/grafana.md#availability-alerts) use these
gauges.

`prefixd_blackhole_replaced_total{pop}` counts unleased blackhole adds from
admissions and reconciliation repairs that returned `replaced`: the add
overwrote a different local route at the prefix. At admission, that route
appeared between the pre-read and add. It has only the configured POP label, and that series is
exported at `0` from startup. Created, unchanged, leased and failed adds
do not increment it. The counter records local RPC outcomes in this process,
not a current-conflict gauge or router enforcement. The shipped
[`PrefixdBlackholeReplaced`](../how-to/grafana.md#replacement-conflict-alert)
alert fires when it increased in the last hour and clears about an hour after
the last replacement. Audit and error logs identify the affected prefix.

With [leased blackholes](configuration.md#leased-blackholes),
`prefixd_injection_lease_renewals_total{result}` counts renewals by `success`,
`not_live` (the speaker refused the generation, which triggers a full
re-add) and `error`. `prefixd_injection_lease_state{state}` is `1` for the
current state (`none`, `live`, `renewal_failing`, `expired` or
`not_renewing`) and `0` for
the others, matching health detail's `speaker.lease.state` after each
renewal. Both series exist with zero values in every deployment.

Series labelled `action_type` (`prefixd_mitigations_active`,
`prefixd_mitigations_created_total`, `prefixd_mitigations_expired_total` and
`prefixd_mitigations_withdrawn_total`) use `blackhole` for blackholes. Blackhole
gauges count database state, not router enforcement. A refused
[manual blackhole](#manual-blackhole) or detector blackhole increments
`prefixd_guardrail_rejections_total` with one of these `reason` values:

| `reason` | Refusal |
| --- | --- |
| `BlackholeDisabled` | `blackhole.enabled` is false |
| `BlackholeQuotaExceeded` | `blackhole.max_active_per_pop` or `blackhole.max_active_global` is full |
| `BlackholeNotOwned` | The victim is not in inventory |
| `BlackholeSafelisted` | The victim is safelisted |
| `InvalidBlackhole` | The victim is not a usable host address or is a configured next hop, or its family has no next hop |
| `TtlRequired`, `TtlOutOfBounds` | The TTL is zero or above `blackhole.max_ttl_seconds` |
| `NewMitigationRateExceeded` | `quotas.max_new_per_minute` is reached |
| `BlackholeSourceNotAllowed` | A detector event matched a blackhole step, but its `source` is not in `blackhole.detector_sources` |

`prefixd_unknown_local_routes{kind}` counts local speaker routes prefixd does
not own, by `kind` (`blackhole` or `flowspec`), from the last successful read.

[Export evidence](speaker-backends.md#export-evidence) (rustbgpd) sets three
gauges after each reconciliation pass, with bounded labels only, never a peer
or prefix: `prefixd_blackhole_export_peers{disposition}` sums Established-peer
rows of active enforced blackholes by `committed`, `withheld` and `pending`;
`prefixd_blackhole_unexported{reason}` counts blackholes committed to no
Established peer by the `warning.reason` values above; and
`prefixd_blackhole_export_read_errors` counts blackholes whose read failed.
The peer and reason gauges count current evidence only: a blackhole whose
evidence is `historical` counts as a read error, while health and detail keep
its retained rows. `committed` is Adj-RIB-Out state, not enforcement. The shipped
[`PrefixdBlackholeNotExported`](../how-to/grafana.md#export-alerts) alert uses
the reason gauge.

See [FEATURES.md](../../FEATURES.md#prometheus-metrics) for full metric list.

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

The report selects the newest 100 mitigations for the IP. An undecodable mitigation
within that selection returns `500` rather than a successful report missing that
row. Mitigations for other IPs or outside that limit do not affect the selection.

**Response:** `200 OK` with `Content-Type: text/markdown`

The response body is a markdown document suitable for pasting into Slack, email, or Jira.

| Status | Meaning |
|--------|---------|
| 200 | Report generated |
| 400 | Missing or invalid parameters (must provide exactly one of mitigation_id or ip) |
| 401 | Authentication required |
| 404 | Mitigation not found (when using mitigation_id) |
| 500 | Report data could not be loaded or decoded |

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
| 503 | Service unavailable, including a standby controller |

### Standby controller

A controller that does not hold its POP's fence
([ADR 027](../adr/027-blackhole-mitigations.md)) is in standby. Every `POST`,
`PUT` and `DELETE` on the authenticated API routes, including event and signal
ingestion, mitigation creation, withdrawal and acknowledgement, safelist,
configuration and operator changes, returns `503` before authentication or
validation:

```json
{
  "error": "controller is in standby: another controller holds this POP's fence; retry against the active controller"
}
```

`GET` requests, login, logout, `GET /v1/health` and `/metrics` keep working,
`GET /v1/ready` returns `503` and `GET /v1/health/detail` reports
`"status": "standby"`. A withdrawal admitted
just before the controller lost its fence can also return `503`; its persisted
withdrawal intent stays pending for the active controller. A creation admitted
then reports an unconfirmed announcement. Retry against the active controller.
See
[controller fence and rolling deploys](../how-to/upgrading.md#controller-fence-and-rolling-deploys).

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

Updates the current operator's notification preferences. `muted_events` contains event type strings that should not produce dashboard toast notifications. `quiet_hours_start`/`quiet_hours_end` are UTC hours (0-23); during quiet hours, only critical events (`mitigation.created`) produce toasts. Set both to `null` to disable quiet hours.

**Response:** `200 OK` with no body on success.

**Validation:**
- `quiet_hours_start` and `quiet_hours_end` must both be present or both be `null` (no half-configured state)
- `quiet_hours_start`/`quiet_hours_end` must be 0-23 if present
- `muted_events` entries must be valid event types (`mitigation.created`, `mitigation.withdrawn`, `mitigation.expired`, `config.reloaded`, `guardrail.rejected`). Legacy `mitigation.escalated` is still accepted so saved preferences load; it is never emitted

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
