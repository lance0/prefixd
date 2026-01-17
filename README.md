# prefixd

[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A **BGP FlowSpec** routing policy daemon for automated L3/L4 DDoS mitigation. Receives attack signals from detectors, applies policy-driven playbooks, and announces FlowSpec rules to routers via GoBGP.

![Dashboard](docs/dashboard-preview.png)

## Why prefixd?

**The killer feature (v1.5):** Multi-signal correlation. FastNetMon says UDP flood at 0.6 confidence + router CPU spiking + host conntrack exhaustion = **high-confidence mitigation**. No single detector should have that power, but correlated signals can. This is what differentiates prefixd from "just let FastNetMon announce directly."

- **Signal-driven** - Detectors signal intent, prefixd decides policy. Multiple weak signals combine into high-confidence actions
- **Detector-agnostic** - Works with FastNetMon, Prometheus alerts, router telemetry, or any system that can POST JSON
- **Policy-driven** - YAML playbooks define responses per attack vector (rate-limit first, then drop)
- **Guardrail-heavy** - Quotas, safelists, /32-only rules, mandatory TTLs prevent accidental broad impact
- **Fail-open** - If prefixd dies, mitigations auto-expire via TTL (no permanent rules)
- **Multi-vendor** - FlowSpec works with Juniper, Arista, Cisco, Nokia routers

## Features

| Category | Features |
|----------|----------|
| **Core** | Event ingestion API, policy engine, escalation logic, TTL-based expiry |
| **BGP** | GoBGP gRPC integration, FlowSpec NLRI (IPv4/IPv6), traffic-rate & discard actions |
| **Safety** | Quotas (per-customer/POP/global), safelist protection, /32-only enforcement |
| **Operations** | CLI tool (`prefixdctl`), hot-reload config, graceful shutdown |
| **Observability** | Prometheus metrics, structured audit log, JSON/pretty logging |
| **Security** | Bearer token auth, mTLS, security headers |
| **Storage** | PostgreSQL |
| **Dashboard** | Next.js web UI with live stats, mitigations, events, audit log |

## Quick Start

### Docker (Recommended)

```bash
# Clone and start
git clone https://github.com/lance0/prefixd.git
cd prefixd
docker compose up -d

# Check status
curl http://localhost:8080/v1/health

# View dashboard
open http://localhost:3000
```

### From Source

```bash
# Build
cargo build --release

# Run with example configs
./target/release/prefixd --config ./configs

# CLI tool
./target/release/prefixdctl status
```

## Architecture

```
┌─────────────┐     ┌─────────────────────────────────────────────────┐     ┌─────────┐
│  Detectors  │     │                    prefixd                      │     │ Routers │
│             │     │                                                 │     │         │
│ FastNetMon  │────▶│  HTTP API ──▶ Policy Engine ──▶ Guardrails     │     │ Juniper │
│ Prometheus  │     │      │              │               │          │     │ Arista  │
│ Custom      │     │      ▼              ▼               ▼          │     │ Cisco   │
└─────────────┘     │  Events DB    Playbooks      Quotas/Safelist   │     │ Nokia   │
                    │                     │                          │     │         │
                    │                     ▼                          │     │         │
                    │              FlowSpec Manager ─────────────────│────▶│  (BGP)  │
                    │                     │               gRPC       │     │         │
                    │                     ▼                          │     └─────────┘
                    │              Reconciliation ◀──▶ GoBGP         │
                    │                     │                          │
                    │                     ▼                          │
                    │                  PostgreSQL                     │
                    └─────────────────────────────────────────────────┘
```

## How It Works

1. **Detector sends event** - Attack signal arrives via `POST /v1/events`
2. **Inventory lookup** - Find customer/service context for victim IP
3. **Playbook evaluation** - Match vector to policy, determine action (police/discard)
4. **Guardrails check** - Validate quotas, safelist, prefix length, TTL
5. **FlowSpec announcement** - Build NLRI, send to GoBGP via gRPC
6. **Router enforcement** - Juniper/Arista/Cisco applies traffic filtering
7. **Auto-expiry** - Reconciliation loop withdraws rules when TTL expires

## Configuration

prefixd uses three YAML files in the config directory:

### prefixd.yaml - Daemon settings

```yaml
pop: iad1
mode: enforced  # or dry-run

http:
  listen: "0.0.0.0:8080"
  auth:
    mode: bearer  # none, bearer, or mtls

bgp:
  mode: sidecar
  gobgp_grpc: "gobgp:50051"
  local_asn: 65010

guardrails:
  require_ttl: true
  dst_prefix_maxlen: 32  # /32 only
  max_ports: 8

quotas:
  max_active_per_customer: 10
  max_active_global: 500
```

### inventory.yaml - Customer/IP mapping

```yaml
customers:
  - customer_id: acme
    name: "ACME Corp"
    prefixes: ["203.0.113.0/24"]
    services:
      - service_id: dns
        name: "DNS Servers"
        assets:
          - ip: "203.0.113.10"
        allowed_ports:
          udp: [53]
          tcp: [53]
```

### playbooks.yaml - Attack response policies

```yaml
playbooks:
  - name: udp_flood
    match:
      vector: udp_flood
    steps:
      - action: police
        rate_bps: 10000000  # 10 Mbps
        ttl_seconds: 120
      - action: discard      # Escalate if attack persists
        ttl_seconds: 300
        require_confidence_at_least: 0.8
```

## API Examples

```bash
# Submit attack event
curl -X POST http://localhost:8080/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "source": "fastnetmon",
    "victim_ip": "203.0.113.10",
    "vector": "udp_flood",
    "bps": 1200000000,
    "confidence": 0.95
  }'

# List active mitigations
curl http://localhost:8080/v1/mitigations?status=active

# Withdraw mitigation
curl -X POST http://localhost:8080/v1/mitigations/{id}/withdraw \
  -d '{"operator_id": "jsmith", "reason": "False positive"}'

# Add to safelist
curl -X POST http://localhost:8080/v1/safelist \
  -d '{"prefix": "10.0.0.1/32", "reason": "Router loopback"}'
```

## CLI Tool

```bash
# Daemon status
prefixdctl status

# List mitigations
prefixdctl mitigations list
prefixdctl mitigations list --status active --customer acme

# Withdraw mitigation
prefixdctl mitigations withdraw <id> --reason "resolved"

# Manage safelist
prefixdctl safelist list
prefixdctl safelist add 10.0.0.1/32 --reason "infrastructure"

# Hot-reload config
prefixdctl reload
```

## Dashboard

The web dashboard provides real-time visibility into:

- Active mitigations with TTL countdown
- BGP session status
- Event history and audit log
- Quota usage gauges
- Safelist management

Run in mock mode for demos:
```bash
cd frontend
NEXT_PUBLIC_MOCK_MODE=true npm run dev
```

## Supported Attack Vectors

| Vector | Protocol | Default Action |
|--------|----------|----------------|
| `udp_flood` | UDP | Police → Discard |
| `syn_flood` | TCP | Discard |
| `ack_flood` | TCP | Discard |
| `icmp_flood` | ICMP | Discard |
| `dns_amplification` | UDP/53 | Police |
| `ntp_amplification` | UDP/123 | Police |
| `memcached_amplification` | UDP/11211 | Police |

## Documentation

| Document | Description |
|----------|-------------|
| [Configuration Guide](docs/configuration.md) | All YAML options explained |
| [Deployment Guide](docs/deployment.md) | Docker, bare metal, GoBGP, router setup |
| [Troubleshooting](docs/troubleshooting.md) | Common issues and solutions |
| [Benchmarks](docs/benchmarks.md) | Performance analysis |
| [CHANGELOG](CHANGELOG.md) | Version history |
| [ROADMAP](ROADMAP.md) | Future plans |

## Performance

Benchmarked on commodity hardware:

| Operation | Throughput |
|-----------|------------|
| Event ingestion | ~6,000/sec |
| Inventory lookup | ~5.6M/sec |
| API queries | <1ms |

See [benchmarks.md](docs/benchmarks.md) for details.

## Requirements

- Rust 1.85+ (for building)
- GoBGP (FlowSpec announcements)
- PostgreSQL 14+
- Routers with FlowSpec support (Juniper, Arista, Cisco, Nokia)

## License

MIT - See [LICENSE](LICENSE) for details.

## Contributing

Issues and PRs welcome. See [AGENTS.md](AGENTS.md) for codebase context.
