# Configuration Reference

prefixd uses three YAML configuration files located in the config directory (default: `/etc/prefixd`).

## prefixd.yaml

Main daemon configuration.

```yaml
# POP identifier (used for multi-POP coordination)
pop: iad1

# Operation mode: dry-run (log only) or enforced (announce FlowSpec)
mode: dry-run  # or: enforced

http:
  # Listen address for HTTP API
  listen: "127.0.0.1:8080"
  
  auth:
    # Authentication mode: none, bearer, or mtls
    mode: bearer
    # Environment variable containing the bearer token (default: PREFIXD_API_TOKEN)
    bearer_token_env: "PREFIXD_API_TOKEN"
  
  rate_limit:
    # Max events per second (token bucket)
    events_per_second: 100  # default: 100
    # Burst capacity
    burst: 500  # default: 500
  
  # TLS configuration (required for mtls auth mode)
  tls:
    cert_path: "/etc/prefixd/server.crt"
    key_path: "/etc/prefixd/server.key"
    ca_path: "/etc/prefixd/ca.crt"  # CA for client cert validation

bgp:
  # BGP mode: sidecar (real GoBGP) or mock (testing)
  mode: sidecar  # or: mock
  # GoBGP gRPC endpoint
  gobgp_grpc: "127.0.0.1:50051"
  # Local ASN for FlowSpec announcements
  local_asn: 65010
  # Router ID
  router_id: "10.10.0.10"
  # BGP neighbors (informational, GoBGP manages sessions)
  neighbors:
    - name: "edge1"
      address: "10.0.0.1"
      peer_asn: 65000
      afi_safi: ["ipv4-flowspec", "ipv6-flowspec"]

guardrails:
  # Require TTL on all mitigations (highly recommended)
  require_ttl: true  # default: true
  
  # IPv4 destination prefix length limits
  dst_prefix_minlen: 32  # default: 32
  dst_prefix_maxlen: 32  # default: 32
  
  # IPv6 destination prefix length limits
  dst_prefix_minlen_v6: 128  # default: 128
  dst_prefix_maxlen_v6: 128  # default: 128
  
  # Maximum destination ports per rule (router memory protection)
  max_ports: 8  # default: 8
  
  # Allow source prefix matching (dangerous, disabled by default)
  allow_src_prefix_match: false  # default: false
  
  # Allow TCP flags matching
  allow_tcp_flags_match: false  # default: false
  
  # Allow fragment matching
  allow_fragment_match: false  # default: false
  
  # Allow packet length matching
  allow_packet_length_match: false  # default: false

quotas:
  # Max active mitigations per customer
  max_active_per_customer: 5  # default: 5
  # Max active mitigations per POP
  max_active_per_pop: 200  # default: 200
  # Max active mitigations globally
  max_active_global: 500  # default: 500
  # Max new mitigations per minute (rate limit)
  max_new_per_minute: 30  # default: 30
  # Max announcements per BGP peer
  max_announcements_per_peer: 100  # default: 100

timers:
  # Default TTL for mitigations (seconds)
  default_ttl_seconds: 120  # default: 120
  # Minimum allowed TTL
  min_ttl_seconds: 30  # default: 30
  # Maximum allowed TTL
  max_ttl_seconds: 1800  # default: 1800 (30 min)
  # Window for correlating events to same attack
  correlation_window_seconds: 300  # default: 300 (5 min)
  # How often to run reconciliation loop
  reconciliation_interval_seconds: 30  # default: 30
  # Quiet period after withdrawal before re-mitigating
  quiet_period_after_withdraw_seconds: 120  # default: 120

escalation:
  # Enable automatic escalation (police → discard)
  enabled: true  # default: true
  # Minimum time before escalation eligible
  min_persistence_seconds: 120  # default: 120
  # Minimum confidence to escalate
  min_confidence: 0.7  # default: 0.7
  # Maximum duration for escalated mitigations
  max_escalated_duration_seconds: 1800  # default: 1800

storage:
  # Storage driver: sqlite or postgres
  driver: sqlite  # or: postgres
  # SQLite: file path | Postgres: connection string
  path: "./data/prefixd.db"
  # path: "postgres://user:pass@localhost/prefixd"

observability:
  # Log format: json or pretty
  log_format: json  # default: json
  # Log level: trace, debug, info, warn, error
  log_level: info  # default: info
  # Path for JSON Lines audit log
  audit_log_path: "./data/audit.jsonl"
  # Prometheus metrics endpoint
  metrics_listen: "127.0.0.1:9090"

safelist:
  # Prefixes that should never be mitigated
  prefixes:
    - "10.0.0.0/8"      # RFC1918
    - "192.168.0.0/16"  # RFC1918
    - "172.16.0.0/12"   # RFC1918

shutdown:
  # Drain timeout for graceful shutdown
  drain_timeout_seconds: 30  # default: 30
  # Keep FlowSpec announcements on shutdown (rules expire via TTL)
  preserve_announcements: true  # default: true
```

## inventory.yaml

Maps IP addresses to customers and services. Used for policy lookup and port allowlisting.

```yaml
customers:
  - customer_id: cust_acme
    name: "Acme Corporation"
    # Customer-owned prefixes
    prefixes:
      - "203.0.113.0/24"
      - "2001:db8:acme::/48"
    # Policy profile: strict, normal, or relaxed
    policy_profile: normal  # default: normal
    
    services:
      - service_id: svc_dns
        name: "Public DNS"
        assets:
          - ip: "203.0.113.10"
          - ip: "2001:db8:acme::10"
        # Allowed destination ports (only these can be mitigated)
        allowed_ports:
          udp: [53]
          tcp: [53]
      
      - service_id: svc_web
        name: "Web Servers"
        assets:
          - ip: "203.0.113.20"
          - ip: "203.0.113.21"
        allowed_ports:
          tcp: [80, 443]
      
      - service_id: svc_game
        name: "Game Servers"
        assets:
          - ip: "203.0.113.100"
            range_end: "203.0.113.110"  # IP range
        allowed_ports:
          udp: [27015, 27016, 27017]

  - customer_id: cust_example
    name: "Example Inc"
    prefixes:
      - "198.51.100.0/24"
    policy_profile: strict  # More aggressive mitigation
    services: []
```

### Policy Profiles

| Profile | Description |
|---------|-------------|
| `strict` | Lower thresholds, faster escalation, longer TTLs |
| `normal` | Default balanced settings |
| `relaxed` | Higher thresholds, slower escalation, shorter TTLs |

## playbooks.yaml

Defines mitigation actions per attack vector.

```yaml
playbooks:
  # UDP flood - start with policing, escalate to discard
  - name: udp_flood_police_first
    match:
      vector: udp_flood
    steps:
      - action: police
        rate_bps: 5000000  # 5 Mbps
        ttl_seconds: 120
      - action: discard
        ttl_seconds: 300
        require_confidence_at_least: 0.7
  
  # SYN flood - immediate discard (high confidence attacks)
  - name: syn_flood_discard
    match:
      vector: syn_flood
    steps:
      - action: discard
        ttl_seconds: 180
  
  # ACK flood
  - name: ack_flood_police
    match:
      vector: ack_flood
    steps:
      - action: police
        rate_bps: 10000000
        ttl_seconds: 120
  
  # ICMP flood - always discard (ICMP rarely critical)
  - name: icmp_flood_discard
    match:
      vector: icmp_flood
    steps:
      - action: discard
        ttl_seconds: 300
  
  # Unknown vectors - conservative policing only
  - name: unknown_conservative
    match:
      vector: unknown
    steps:
      - action: police
        rate_bps: 1000000  # 1 Mbps
        ttl_seconds: 60

# Default playbook if no match found
default_playbook:
  steps:
    - action: police
      rate_bps: 1000000
      ttl_seconds: 60
```

### Playbook Actions

| Action | Parameters | Description |
|--------|------------|-------------|
| `police` | `rate_bps`, `ttl_seconds` | Rate-limit traffic to specified BPS |
| `discard` | `ttl_seconds` | Drop all matching traffic |

### Step Options

| Option | Type | Description |
|--------|------|-------------|
| `require_confidence_at_least` | float | Only use this step if event confidence >= value |
| `ttl_seconds` | int | Time-to-live for the mitigation |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PREFIXD_API_TOKEN` | Bearer token for API authentication | (required if auth.mode=bearer) |
| `PREFIXD_API` | API endpoint for prefixdctl | `http://127.0.0.1:8080` |
| `RUST_LOG` | Override log level | Uses config value |
| `USER` | Default operator ID for CLI commands | (system user) |

## Configuration Precedence

1. Command-line arguments (highest)
2. Environment variables
3. Configuration files
4. Built-in defaults (lowest)
