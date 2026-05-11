# Configuration Reference

prefixd uses three YAML configuration files in the config directory.

---

## prefixd.yaml

Main daemon configuration.

### Basic Settings

```yaml
# Point of presence identifier (for multi-POP deployments)
pop: iad1

# Operation mode
mode: enforced  # enforced (announce FlowSpec) or dry-run (log only)
```

### HTTP Server

```yaml
http:
  # API listen address
  listen: "0.0.0.0:8080"
  
  # Optional CORS origin when not fronted by nginx
  cors_origin: "http://localhost:3000"
```

### Authentication

```yaml
http:
  auth:
    # Mode: none, bearer, mtls, or credentials
    mode: credentials
    
    # Bearer token (use env var for security)
    bearer_token_env: "PREFIXD_API_TOKEN"
```

| Mode | Dashboard | API/CLI | Notes |
|------|-----------|---------|-------|
| `none` | No login | No auth | Development only |
| `bearer` | N/A | Bearer token | API-only access |
| `mtls` | N/A | Client certificates | Machine-to-machine |
| `credentials` | Session login | Session cookie | Recommended |

### LDAP/Active Directory (Placeholder)

> **Note:** LDAP authentication is not yet implemented. This schema is reserved for future use.

```yaml
http:
  auth:
    mode: credentials
    ldap:
      # LDAP server URL
      url: "ldaps://ldap.example.com:636"
      
      # Service account for LDAP queries
      bind_dn: "cn=prefixd,ou=services,dc=example,dc=com"
      bind_password_env: "LDAP_BIND_PASSWORD"
      
      # Where to search for users
      user_base_dn: "ou=users,dc=example,dc=com"
      
      # Filter to find user (use {username} placeholder)
      user_filter: "(&(objectClass=user)(sAMAccountName={username}))"
      
      # Map LDAP groups to prefixd roles
      role_mapping:
        "cn=prefixd-admins,ou=groups,dc=example,dc=com": "admin"
        "cn=noc-operators,ou=groups,dc=example,dc=com": "operator"
        "cn=noc-viewers,ou=groups,dc=example,dc=com": "viewer"
```

### RADIUS/ISE (Placeholder)

> **Note:** RADIUS authentication is not yet implemented. This schema is reserved for future use.

```yaml
http:
  auth:
    mode: credentials
    radius:
      # Primary RADIUS server
      server: "radius.example.com:1812"
      
      # Backup server for failover
      secondary_server: "radius-backup.example.com:1812"
      
      # Shared secret (from environment variable)
      secret_env: "RADIUS_SECRET"
      
      # Timeout and retries
      timeout_seconds: 5
      retries: 3
      
      # NAS identifier for audit logs
      nas_identifier: "prefixd-iad1"
      
      # Map RADIUS VSA or groups to prefixd roles
      role_mapping:
        "Prefixd-Admin": "admin"
        "NOC-Operator": "operator"
        "NOC-Viewer": "viewer"
```

### TLS

```yaml
http:
  tls:
    # Server certificate
    cert_path: "/etc/prefixd/server.crt"
    key_path: "/etc/prefixd/server.key"
    
    # Client CA for mTLS (optional)
    ca_path: "/etc/prefixd/ca.crt"
```

### Rate Limiting

```yaml
http:
  rate_limit:
    events_per_second: 100  # Sustained rate
    burst: 500              # Burst capacity
```

### BGP

```yaml
bgp:
  # Mode: sidecar (real GoBGP) or mock (testing)
  mode: sidecar
  
  # GoBGP gRPC endpoint
  gobgp_grpc: "gobgp:50051"
  
  # Local AS number
  local_asn: 65010
  
  # Router ID
  router_id: "10.10.0.10"
```

### Storage

```yaml
storage:
  # PostgreSQL connection string
  connection_string: "postgres://prefixd:password@postgres:5432/prefixd"
```

### Guardrails

```yaml
guardrails:
  # Require TTL on all mitigations
  require_ttl: true
  
  # IPv4 prefix length (32 = /32 only)
  dst_prefix_minlen: 32
  dst_prefix_maxlen: 32
  
  # IPv6 prefix length (128 = /128 only)
  dst_prefix_minlen_v6: 128
  dst_prefix_maxlen_v6: 128
  
  # Max ports per rule (router memory protection)
  max_ports: 8
  
  # TTL bounds (optional overrides; if omitted, uses timers.min/max_ttl_seconds)
  min_ttl_seconds: 30
  max_ttl_seconds: 1800
```

### Quotas

```yaml
quotas:
  # Max active mitigations per customer
  max_active_per_customer: 5
  
  # Max active mitigations per POP
  max_active_per_pop: 200
  
  # Max active mitigations globally
  max_active_global: 500
  
  # Max new mitigations created per minute (rate limiting)
  max_new_per_minute: 30
  
  # Max active FlowSpec announcements per BGP peer
  max_announcements_per_peer: 100
```

### Timers

```yaml
timers:
  # Default TTL for mitigations
  default_ttl_seconds: 120
  
  # TTL bounds
  min_ttl_seconds: 30
  max_ttl_seconds: 1800
  
  # Reconciliation loop interval
  reconciliation_interval_seconds: 30
  
  # Correlation window for duplicate events
  correlation_window_seconds: 300
  
  # Quiet period after withdraw before re-announcing the same destination
  quiet_period_after_withdraw_seconds: 120
```

### Escalation

```yaml
escalation:
  # Enable automatic escalation (police → discard)
  enabled: true
  
  # Minimum time before escalation eligible
  min_persistence_seconds: 120
  
  # Minimum confidence for escalation
  min_confidence: 0.7
```

### Observability

```yaml
observability:
  # Log format: json or pretty
  log_format: json
  
  # Log level: trace, debug, info, warn, error
  log_level: info
  
  # Audit log path
  audit_log_path: "/var/log/prefixd/audit.jsonl"
  
  # Prometheus metrics listen address
  metrics_listen: "0.0.0.0:9090"
```

### Safelist

```yaml
safelist:
  # Prefixes that should never be mitigated
  prefixes:
    - "10.0.0.0/8"       # RFC1918
    - "172.16.0.0/12"    # RFC1918
    - "192.168.0.0/16"   # RFC1918
```

### Correlation

The multi-signal correlation engine groups related attack events from multiple detection sources and uses corroboration to make high-confidence mitigation decisions.

When `enabled` is false (the default), the correlation engine is bypassed and events follow the direct path to policy evaluation — identical to pre-correlation behavior.

```yaml
correlation:
  # Enable the correlation engine
  enabled: true
  
  # Time window (seconds) for grouping signals by (victim_ip, vector).
  # Events arriving within this window are added to the same signal group.
  window_seconds: 300
  
  # Global minimum number of distinct sources required before a signal group
  # can trigger a mitigation. Set to 1 for backward-compatible single-source behavior.
  min_sources: 1
  
  # Global minimum derived confidence threshold (0.0-1.0).
  # A signal group must reach this threshold (in addition to min_sources) before triggering.
  confidence_threshold: 0.5

  # Exponential half-life applied to per-event confidence contributions when
  # computing derived_confidence. 0 disables decay (default). When set, an
  # event's effective weight is multiplied by 0.5^(age_seconds / H), so
  # older corroborating evidence smoothly loses influence. See ADR 022.
  # Must satisfy 0 <= H <= 10 * window_seconds.
  confidence_decay_half_life_seconds: 0
  
  # Default weight for sources not listed below
  default_weight: 1.0
  
  # Per-source configuration: weight and type for known detection sources.
  sources:
    fastnetmon:
      weight: 1.0
      type: detector
    alertmanager:
      weight: 0.8
      type: telemetry
    dashboard:
      weight: 1.0
      type: manual
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Whether the correlation engine is active |
| `window_seconds` | integer | `300` | Time window for grouping signals (seconds) |
| `min_sources` | integer | `1` | Minimum distinct sources to trigger mitigation |
| `confidence_threshold` | float | `0.5` | Minimum derived confidence to trigger |
| `confidence_decay_half_life_seconds` | integer | `0` | Exponential half-life (seconds) for time-decaying per-event confidence contributions; 0 disables decay. Bounded by `10 × window_seconds`. See [ADR 022](adr/022-confidence-decay.md). |
| `default_weight` | float | `1.0` | Weight for unknown/unconfigured sources |
| `sources` | map | `{}` | Per-source weight and type configuration |

**Source Configuration:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `weight` | float | `1.0` | Weight in derived confidence computation (higher = more influence) |
| `type` | string | `""` | Descriptive type (`detector`, `telemetry`, `manual`) |
| `mode` | string | `primary` | `primary` = can trigger mitigations; `corroborating` = only strengthens other sources (ADR 021) |
| `match_dimensions` | list | `[]` | Required when `mode=corroborating`. Drawn from `customer_id`, `pop`, `service_id`, `interface`. Must be empty when `mode=primary`. |

**Corroborating sources example:**

```yaml
sources:
  fastnetmon:
    mode: primary        # default; can trigger mitigations
    weight: 1.0
    type: detector
  router-cpu:
    mode: corroborating  # strengthens groups but never fires alone
    weight: 0.5
    type: telemetry
    match_dimensions: [pop, customer_id]
```

Corroborating sources post to `POST /v1/signals/corroborator` instead of
`/v1/events`. Each signal must populate at least one of its declared
`match_dimensions`. Matching against open signal groups uses OR across
**declared** dimensions only — a source declared for `[pop]` cannot
attach via an undeclared `customer_id`/`service_id`/`interface` even if
those values happen to match. A signal group must contain at least one
primary event before it can trigger a mitigation — corroborators alone
are never sufficient. Misconfiguration (`mode=corroborating` with empty
`match_dimensions`, or `mode=primary` with non-empty `match_dimensions`)
is rejected both on `PUT /v1/config/correlation` and on daemon boot.
See [ADR 021](adr/021-corroborating-signals.md) and
[docs/detectors/corroborating-signals.md](detectors/corroborating-signals.md).

**Derived confidence** is computed as a weighted average:

```
derived_confidence = sum(event_confidence_i × source_weight_i) / sum(source_weight_i)
```

Events with null or missing confidence are treated as 0.0.

#### Per-Playbook Correlation Overrides

Playbooks can override global `min_sources` and `confidence_threshold` for specific attack vectors. Add a `correlation` section to any playbook in `playbooks.yaml`:

```yaml
playbooks:
  - name: udp_flood_corroborated
    match:
      vector: udp_flood
    correlation:
      min_sources: 2           # Require corroboration for UDP floods
      confidence_threshold: 0.7
      confidence_decay_half_life_seconds: 60   # Faster decay for noisy vector
    steps:
      - action: police
        rate_bps: 5000000
        ttl_seconds: 120
```

When a playbook has no `correlation` override, the global defaults from `prefixd.yaml` are used.

| Override Field | Type | Description |
|----------------|------|-------------|
| `min_sources` | integer | Override global min_sources for this playbook |
| `confidence_threshold` | float | Override global confidence_threshold for this playbook |
| `confidence_decay_half_life_seconds` | integer (optional) | Override global half-life. `0` explicitly disables decay for this playbook even when the global is non-zero; omit to inherit the global value. |

#### Hot Reload

Correlation config changes take effect on `POST /v1/config/reload` without restart (same as inventory and playbooks).

#### Generic Webhook Adapters

For detection or telemetry systems without a native adapter (Alertmanager, FastNetMon), configure a generic webhook adapter. Each entry becomes a new endpoint at `POST /v1/signals/webhook/{name}` that accepts arbitrary JSON and maps it to an `AttackEvent` via JSONPath.

```yaml
correlation:
  webhook_adapters:
    - name: radware                       # URL-safe: [a-z0-9-]{1,64}
      description: "Radware DefensePro"
      enabled: true
      auth:
        type: hmac                        # hmac | bearer | none
        secret_env: RADWARE_WEBHOOK_SECRET
        header: X-Signature-SHA256
        algorithm: sha256                 # sha256 only in v1
      root_path: "$.alerts[*]"            # optional: iterate an array
      fields:
        victim_ip: "$.target.ip"          # REQUIRED
        vector: "$.alert_type"
        timestamp: "$.time"
        bps: "$.traffic.bps"
        pps: "$.traffic.pps"
        confidence: "$.score"
        source_id: "$.id"
        top_dst_ports: "$.ports"
        action: "$.action"                # "ban" (default) or "unban"
      vector_map:                         # normalize detector strings
        UDP_FLOOD: udp_flood
        SYN_FLOOD: syn_flood
      default_vector: unknown
      confidence_scale: 100               # divide extracted value by this
      source_id_prefix: "radware-"
```

**Adapter schema:**

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `name` | yes | string | URL path segment, `[a-z0-9-]{1,64}` |
| `description` | no | string | Human-readable label |
| `enabled` | no | boolean (default `true`) | Disabled adapters return 404 |
| `auth` | yes | object | Authentication scheme (see below) |
| `root_path` | no | JSONPath | When set, each match produces one event |
| `fields.victim_ip` | yes | JSONPath | String extraction; must parse as an IP |
| `fields.vector` | no | JSONPath | String; normalized via `vector_map` + `default_vector` |
| `fields.timestamp` | no | JSONPath | RFC 3339 string; defaults to receive time |
| `fields.bps` / `fields.pps` | no | JSONPath | Numbers |
| `fields.confidence` | no | JSONPath | Number; scaled via `confidence_scale`, clamped to `[0,1]` |
| `fields.source_id` | no | JSONPath | String/number; becomes `event_id` with optional prefix |
| `fields.top_dst_ports` | no | JSONPath | Array of port numbers |
| `fields.action` | no | JSONPath | `ban` (default) or `unban` |
| `vector_map` | no | map | Raw detector string → prefixd vector name |
| `default_vector` | no | string | Fallback when vector missing or not in map |
| `confidence_scale` | no | float | Divisor (e.g. `100` for 0–100 scales) |
| `source_id_prefix` | no | string | Prefix prepended to extracted `source_id` |

**Authentication:**

| `auth.type` | Meaning |
|-------------|---------|
| `hmac` | HMAC-SHA256 over the raw body. `auth.header` is the request header (default `X-Signature-SHA256`). `auth.secret_env` is the env var holding the secret. Comparison is constant-time. Hex digest may be prefixed with `sha256=`. |
| `bearer` | Reuses global session/bearer auth. |
| `none` | No auth (lab use only). |

**JSONPath quick reference** (RFC 9535 via `serde_json_path`):

- `$.field` — root field lookup
- `$.a.b.c` — nested lookup
- `$.items[0]` — array index
- `$.items[*]` — array iteration (only meaningful as `root_path`)
- `$.items[?(@.severity=="high")]` — filter expression

**Weighting:** To weight a webhook adapter's events in correlation, register its name in `sources:` alongside detector/alertmanager:

```yaml
sources:
  radware:
    weight: 1.2
    type: detector
```

Adapters not listed fall back to `default_weight`.

### Shutdown

```yaml
shutdown:
  # Seconds to wait for in-flight requests to complete during graceful shutdown
  drain_timeout_seconds: 30
  
  # Keep FlowSpec announcements active after shutdown (fail-open)
  preserve_announcements: true
```

---

## inventory.yaml

Maps IP addresses to customers and services.

### Basic Structure

```yaml
customers:
  - customer_id: acme
    name: "ACME Corporation"
    prefixes:
      - "203.0.113.0/24"
      - "2001:db8:acme::/48"
    policy_profile: normal
    services:
      - service_id: dns
        name: "DNS Servers"
        assets:
          - ip: "203.0.113.10"
        allowed_ports:
          udp: [53]
          tcp: [53]
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `customer_id` | string | Unique identifier |
| `name` | string | Display name |
| `prefixes` | list | Owned IP prefixes |
| `policy_profile` | string | Policy strictness: strict, normal, relaxed |
| `services` | list | Services within customer |

### Services

```yaml
services:
  - service_id: web
    name: "Web Servers"
    assets:
      - ip: "203.0.113.20"
        interface: "et-0/0/12"   # optional; see below
      - ip: "203.0.113.21"
    allowed_ports:
      tcp: [80, 443]
```

**Asset fields:**

| Field | Type | Description |
|-------|------|-------------|
| `ip` | string | Asset IPv4 or IPv6 address (exact match) |
| `role` | string | Optional free-form role tag (e.g. `web`, `db`) |
| `interface` | string | Optional router/switch interface name. When present, the interface is attached to the resolved `IpContext` on incoming events and flows into the signal group's `primary_dimensions`. Required if you want interface-only corroborating signals (see [ADR 021](adr/021-corroborating-signals.md)) to match this asset's groups. |

### Allowed Ports

Ports listed in `allowed_ports` are **excluded** from mitigation. For a DNS server under UDP flood, the FlowSpec rule will match "UDP except port 53".

```yaml
allowed_ports:
  udp: [53]        # DNS
  tcp: [80, 443]   # HTTP/HTTPS
```

### IP Ranges

```yaml
assets:
  - ip: "203.0.113.100"
    range_end: "203.0.113.110"  # 11 IPs
```

### Policy Profiles

| Profile | Thresholds | Escalation | TTLs |
|---------|------------|------------|------|
| `strict` | Lower | Faster | Longer |
| `normal` | Default | Default | Default |
| `relaxed` | Higher | Slower | Shorter |

---

## playbooks.yaml

Defines mitigation responses per attack vector.

### Basic Structure

```yaml
playbooks:
  - name: udp_flood
    match:
      vector: udp_flood
    steps:
      - action: police
        rate_bps: 10000000
        ttl_seconds: 120
      - action: discard
        ttl_seconds: 300
        require_confidence_at_least: 0.8
```

### Match Criteria

```yaml
match:
  vector: udp_flood     # Attack vector
  source: fastnetmon   # Optional: specific detector
  protocol: udp        # Optional: protocol filter
```

### Actions

| Action | Parameters | Description |
|--------|------------|-------------|
| `police` | `rate_bps`, `ttl_seconds` | Rate-limit to N bps |
| `discard` | `ttl_seconds` | Drop all matching traffic |

### Step Options

| Option | Type | Description |
|--------|------|-------------|
| `rate_bps` | integer | Rate limit in bits/second (police only) |
| `ttl_seconds` | integer | Mitigation duration |
| `require_confidence_at_least` | float | Min confidence for this step |

### Escalation

Steps are tried in order. If attack persists after step 1, step 2 is used:

```yaml
steps:
  - action: police        # Step 1: Rate limit
    rate_bps: 10000000
    ttl_seconds: 120
  - action: discard       # Step 2: Drop (if attack continues)
    ttl_seconds: 300
    require_confidence_at_least: 0.7
```

### Default Playbook

Fallback when no playbook matches:

```yaml
default_playbook:
  steps:
    - action: police
      rate_bps: 1000000
      ttl_seconds: 60
```

### Example Playbooks

```yaml
playbooks:
  # UDP flood: police first, escalate to discard
  - name: udp_flood
    match:
      vector: udp_flood
    steps:
      - action: police
        rate_bps: 10000000
        ttl_seconds: 120
      - action: discard
        ttl_seconds: 300
        require_confidence_at_least: 0.8

  # SYN flood: immediate discard
  - name: syn_flood
    match:
      vector: syn_flood
    steps:
      - action: discard
        ttl_seconds: 180

  # ICMP flood: discard (ICMP rarely critical)
  - name: icmp_flood
    match:
      vector: icmp_flood
    steps:
      - action: discard
        ttl_seconds: 300

  # Amplification attacks: police only
  - name: dns_amp
    match:
      vector: dns_amplification
    steps:
      - action: police
        rate_bps: 50000000
        ttl_seconds: 120

  # Conservative fallback
  - name: unknown
    match:
      vector: unknown
    steps:
      - action: police
        rate_bps: 1000000
        ttl_seconds: 60
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PREFIXD_API_TOKEN` | Bearer token for auth | Required if mode=bearer |
| `PREFIXD_API` | API URL for prefixdctl | `http://127.0.0.1` |
| `RUST_LOG` | Log level override | Config value |
| `DATABASE_URL` | PostgreSQL connection | Config value |

### Using Environment Variables in Config

```yaml
http:
  auth:
    bearer_token_env: "PREFIXD_API_TOKEN"

storage:
  connection_string: "${DATABASE_URL}"
```

---

## Hot Reload

Inventory and playbooks can be reloaded without restart:

```bash
# CLI
prefixdctl reload

# API
curl -X POST http://localhost/v1/config/reload
```

Note: `prefixd.yaml` changes require restart.

---

## Validation

prefixd validates configuration on startup:

```bash
# Check configuration
prefixd --config ./configs --check

# Verbose validation
RUST_LOG=debug prefixd --config ./configs --check
```

Common validation errors:

- `Invalid prefix length` - Check guardrails.dst_prefix_maxlen
- `Invalid TTL` - TTL outside min/max bounds
- `Missing required field` - Check YAML structure
- `Invalid customer_id` - Must be unique
