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
  
  # CORS origins for dashboard (comma-separated)
  cors_origins: "http://localhost:3000"
```

### Authentication

```yaml
http:
  auth:
    # Mode: none, bearer, or hybrid
    mode: bearer
    
    # Bearer token (use env var for security)
    token: "${PREFIXD_API_TOKEN}"
    
    # Secure cookies for dashboard sessions
    # auto: secure if TLS enabled
    # true: always secure (requires HTTPS)
    # false: never secure (development only)
    secure_cookies: auto
```

| Mode | Dashboard | API/CLI | Notes |
|------|-----------|---------|-------|
| `none` | No login | No auth | Development only |
| `bearer` | Session login | Bearer token | Recommended |
| `hybrid` | Session login | Session or bearer | Legacy support |

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
  
  # Connection pool size
  max_connections: 10
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
  
  # TTL bounds
  min_ttl_seconds: 60
  max_ttl_seconds: 3600
```

### Quotas

```yaml
quotas:
  # Max active mitigations per customer
  max_active_per_customer: 10
  
  # Max active mitigations per POP
  max_active_per_pop: 200
  
  # Max active mitigations globally
  max_active_global: 500
```

### Timers

```yaml
timers:
  # Default TTL for mitigations
  default_ttl_seconds: 120
  
  # Reconciliation loop interval
  reconciliation_interval_seconds: 30
  
  # Correlation window for duplicate events
  correlation_window_seconds: 300
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
      - ip: "203.0.113.21"
    allowed_ports:
      tcp: [80, 443]
```

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
| `PREFIXD_API` | API URL for prefixdctl | `http://127.0.0.1:8080` |
| `RUST_LOG` | Log level override | Config value |
| `DATABASE_URL` | PostgreSQL connection | Config value |

### Using Environment Variables in Config

```yaml
http:
  auth:
    token: "${PREFIXD_API_TOKEN}"

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
curl -X POST http://localhost:8080/v1/admin/reload
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
