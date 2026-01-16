# prefixd

A routing policy daemon that automates **BGP FlowSpec** mitigations for L3/L4 DDoS events in bare-metal and colocation environments.

## Overview

prefixd accepts attack events from detectors (FastNetMon, custom telemetry, NOC tooling), maps them to mitigations using configurable playbooks, and announces FlowSpec rules via a GoBGP sidecar to Juniper routers.

### Design Principles

- **Juniper-first** enforcement (Junos routers import and apply FlowSpec)
- **Policy-driven** with configurable playbooks per attack vector
- **Guardrail-heavy** to prevent accidental broad impact
- **Detector-agnostic** - any system can submit events via HTTP API
- **Fail-open** - if prefixd dies, existing mitigations expire via TTL

## Features

- HTTP API for event ingestion and operator actions
- Policy engine with YAML playbooks
- Guardrails: TTL required, /32-only, quotas, safelist protection
- Mitigation lifecycle with automatic TTL expiry
- Scope-based deduplication and TTL extension
- Reconciliation loop syncs desired state with BGP RIB
- Structured JSON logging and audit trail

## Quick Start

```bash
# Build
cargo build --release

# Run with example configs
./target/release/prefixd --config ./configs

# Or in development
cargo run -- --config ./configs
```

## Configuration

prefixd uses three YAML configuration files:

### prefixd.yaml

Main daemon configuration including HTTP listener, BGP settings, guardrails, quotas, and timers.

```yaml
pop: iad1
mode: dry-run  # or enforced

http:
  listen: "127.0.0.1:8080"
  auth:
    mode: bearer  # or mtls, none

bgp:
  mode: sidecar  # or mock
  gobgp_grpc: "127.0.0.1:50051"
  local_asn: 65010
  router_id: "10.10.0.10"
```

### inventory.yaml

Maps victim IPs to customers and services with allowed ports.

```yaml
customers:
  - customer_id: cust_example
    name: "Example Customer"
    prefixes:
      - "203.0.113.0/24"
    services:
      - service_id: svc_dns
        name: "DNS Service"
        assets:
          - ip: "203.0.113.10"
        allowed_ports:
          udp: [53]
          tcp: [53]
```

### playbooks.yaml

Defines mitigation actions per attack vector.

```yaml
playbooks:
  - name: udp_flood_police_first
    match:
      vector: udp_flood
    steps:
      - action: police
        rate_bps: 5000000
        ttl_seconds: 120
      - action: discard
        ttl_seconds: 300
        require_confidence_at_least: 0.7
```

## API

### Submit Attack Event

```bash
curl -X POST http://localhost:8080/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-01-16T14:00:00Z",
    "source": "fastnetmon",
    "victim_ip": "203.0.113.10",
    "vector": "udp_flood",
    "bps": 123456789,
    "top_dst_ports": [53],
    "confidence": 0.85
  }'
```

### List Mitigations

```bash
curl http://localhost:8080/v1/mitigations
```

### Withdraw Mitigation

```bash
curl -X POST http://localhost:8080/v1/mitigations/{id}/withdraw \
  -H "Content-Type: application/json" \
  -d '{"operator_id": "jsmith", "reason": "False positive"}'
```

### Health Check

```bash
curl http://localhost:8080/v1/health
```

## Architecture

```
Detector(s) → prefixd API → Policy Engine → Guardrails → FlowSpec Manager → GoBGP → Juniper
                                                              ↑
                                                    Reconciliation Loop
                                                              ↓
                                                        SQLite (state)
```

## Supported Attack Vectors

- `udp_flood` - UDP volumetric floods
- `syn_flood` - TCP SYN floods
- `ack_flood` - TCP ACK floods  
- `icmp_flood` - ICMP floods
- `unknown` - Unclassified attacks (conservative handling)

## FlowSpec Constraints (MVP)

| Constraint | Value |
|------------|-------|
| Destination prefix | /32 only |
| Source prefix match | Disabled |
| Protocol | UDP, TCP, ICMP |
| Destination ports | Max 8 |
| Actions | `traffic-rate` (police), `discard` |

## License

MIT
