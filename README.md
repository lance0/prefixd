# prefixd

[![Build](https://github.com/lance0/prefixd/actions/workflows/ci.yml/badge.svg)](https://github.com/lance0/prefixd/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

prefixd is a BGP FlowSpec policy daemon for automated DDoS mitigation. It receives attack signals from detectors, applies policy-driven playbooks, and announces FlowSpec rules to routers via GoBGP.

```
Detector ──► prefixd ──► GoBGP ──► Routers
   │            │
   │            ├── Policy Engine (playbooks)
   │            ├── Guardrails (quotas, safelist, /32-only)
   │            └── Reconciliation (auto-expire, drift repair)
   │
   └── FastNetMon, Kentik, Prometheus alerts, custom scripts
```

**Detector integrations:** [FastNetMon](docs/detectors/fastnetmon.md) | More coming soon

**Key idea:** Detectors signal intent, prefixd decides policy. No detector ever speaks BGP directly.

---

## Install

### Docker (recommended)

```bash
git clone https://github.com/lance0/prefixd.git
cd prefixd
docker compose up -d

# Check health
curl http://localhost:8080/v1/health

# Open dashboard
open http://localhost:3000
```

### From source

```bash
cargo build --release
./target/release/prefixd --config ./configs
./target/release/prefixdctl status
```

### Binary releases

See [Releases](https://github.com/lance0/prefixd/releases) for pre-built binaries.

---

## Documentation

### Getting Started

- [Quick Start](docs/deployment.md#quick-start) - Docker Compose setup
- [Configuration Guide](docs/configuration.md) - All YAML options explained
- [Deployment Guide](docs/deployment.md) - Docker, bare metal, GoBGP, router setup

### Using prefixd

- [CLI Reference](docs/cli.md) - `prefixdctl` commands
- [API Reference](docs/api.md) - REST endpoints
- [Playbooks](docs/configuration.md#playbooks) - Attack response policies
- [Guardrails](docs/configuration.md#guardrails) - Safety limits and quotas

### Operations

- [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions
- [Router Setup](docs/deployment.md#router-configuration) - Juniper, Arista, Cisco FlowSpec import
- [Monitoring](docs/deployment.md#monitoring) - Prometheus metrics, Grafana

### Reference

- [Architecture](docs/architecture.md) - Design decisions and data flow
- [Benchmarks](docs/benchmarks.md) - Performance analysis
- [CHANGELOG](CHANGELOG.md) - Version history
- [ROADMAP](ROADMAP.md) - Future plans

---

## Features

| Category | What it does |
|----------|--------------|
| **Signal Ingestion** | HTTP API accepts attack events from any detector (FastNetMon, Prometheus, custom) |
| **Policy Engine** | YAML playbooks define per-vector responses (rate-limit, then escalate to drop) |
| **Guardrails** | Quotas, safelist protection, /32-only enforcement, mandatory TTLs |
| **BGP FlowSpec** | Announces IPv4/IPv6 FlowSpec via GoBGP gRPC (traffic-rate, discard actions) |
| **Reconciliation** | Auto-expires mitigations, detects RIB drift, re-announces missing rules |
| **Dashboard** | Next.js web UI with real-time WebSocket updates |
| **Authentication** | Session-based auth for dashboard, bearer tokens for API/CLI |
| **Observability** | Prometheus metrics, structured JSON logging, audit trail |

---

## How it works

1. **Detector sends attack event** → `POST /v1/events` with victim IP, vector, confidence
2. **Inventory lookup** → Find customer/service context for the victim
3. **Playbook evaluation** → Match vector to policy, determine action (police/discard)
4. **Guardrails check** → Validate quotas, safelist, prefix length, TTL bounds
5. **FlowSpec announcement** → Build NLRI, send to GoBGP via gRPC
6. **Router enforcement** → Juniper/Arista/Cisco applies traffic filtering at line rate
7. **Auto-expiry** → Reconciliation loop withdraws rules when TTL expires

**Fail-open design:** If prefixd dies, mitigations auto-expire via TTL. No permanent rules, no operator intervention required.

---

## Example

### Submit an attack event

```bash
curl -X POST http://localhost:8080/v1/events \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $PREFIXD_API_TOKEN" \
  -d '{
    "source": "fastnetmon",
    "victim_ip": "203.0.113.10",
    "vector": "udp_flood",
    "bps": 1200000000,
    "confidence": 0.95
  }'
```

### What happens

prefixd looks up `203.0.113.10` in inventory, finds it belongs to customer `acme` with allowed UDP ports `[53]`. The `udp_flood` playbook says: police to 10 Mbps for 2 minutes, escalate to discard if attack persists.

GoBGP announces:
```
FlowSpec: dst 203.0.113.10/32, proto UDP, dport !53
Action: traffic-rate 10000000 (10 Mbps)
```

The router drops UDP traffic to that IP except DNS. After 2 minutes, if no new events arrive, the rule auto-withdraws.

---

## Supported routers

FlowSpec is a standard (RFC 5575, RFC 8955) supported by:

| Vendor | Platform | Notes |
|--------|----------|-------|
| Juniper | MX, PTX, SRX | Full FlowSpec support |
| Arista | 7xxx | EOS 4.20+ |
| Cisco | IOS-XR | ASR 9000, NCS |
| Nokia | SR OS | 19.x+ |

See [Router Setup](docs/deployment.md#router-configuration) for import policy examples.

---

## Requirements

- **Rust 1.85+** (for building from source)
- **GoBGP v4.x** (FlowSpec route server)
- **PostgreSQL 14+** (state storage)
- **Docker** (recommended deployment)

---

## Project status

prefixd is under active development. Current version: **v0.8.0**

- Core functionality is stable and tested
- Used internally, preparing for public release
- API may change before v1.0

See [ROADMAP](ROADMAP.md) for planned features.

---

## Community

- **Issues:** Bug reports and feature requests welcome
- **Pull requests:** See [CONTRIBUTING.md](CONTRIBUTING.md)
- **Questions:** Open a discussion or issue

---

## License

MIT - See [LICENSE](LICENSE) for details.
