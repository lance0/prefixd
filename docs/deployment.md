# Deployment Guide

## Overview

prefixd requires:

- **prefixd** daemon
- **GoBGP v4.x** sidecar for BGP FlowSpec
- **PostgreSQL 14+**
- **Routers** with FlowSpec support

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Detector   │────▶│   prefixd   │────▶│   GoBGP     │
│ (FastNetMon)│     │   :8080     │     │   :50051    │
└─────────────┘     └──────┬──────┘     └──────┬──────┘
                           │                   │
                           ▼                   ▼
                    ┌─────────────┐     ┌─────────────┐
                    │  PostgreSQL │     │   Routers   │
                    └─────────────┘     └─────────────┘
```

---

## Quick Start

### Docker Compose (Recommended)

```bash
# Clone
git clone https://github.com/lance0/prefixd.git
cd prefixd

# Configure
cp configs/prefixd.yaml.example configs/prefixd.yaml
# Edit configs/prefixd.yaml, inventory.yaml, playbooks.yaml

# Generate API token
export PREFIXD_API_TOKEN=$(openssl rand -hex 32)
echo "PREFIXD_API_TOKEN=$PREFIXD_API_TOKEN" >> .env

# Start
docker compose up -d

# Create admin operator (for dashboard login)
docker compose exec prefixd prefixdctl operators create \
  --username admin --role admin --password

# Verify
curl http://localhost/v1/health
open http://localhost
```

### Services

| Service | Port | Description |
|---------|------|-------------|
| nginx | 80 | Reverse proxy (single entrypoint) |
| grafana | 3001 | Monitoring dashboards |
| prometheus | 9091 | Metrics storage |
| gobgp | 179 | BGP (to routers) |
| gobgp | 50051 | gRPC (internal) |
| postgres | 5432 | Database |

> **Note:** The dashboard and API are not exposed directly. All HTTP and WebSocket traffic goes through nginx on port 80.

---

## Authentication Setup

### Create Operators

Operators are users who can log into the dashboard:

```bash
# Create admin (full access)
prefixdctl operators create --username admin --role admin --password

# Create operator (read + withdraw)
prefixdctl operators create --username oncall --role operator --password

# Create viewer (read-only)
prefixdctl operators create --username readonly --role viewer --password

# List operators
prefixdctl operators list
```

### Auth Modes

Configure in `prefixd.yaml`:

```yaml
http:
  auth:
    mode: bearer           # API/CLI: bearer token required
    token: "${PREFIXD_API_TOKEN}"
    secure_cookies: auto   # auto, true, false
```

| Mode | Dashboard | API/CLI |
|------|-----------|---------|
| `none` | No login | No auth |
| `bearer` | Session login | Bearer token |
| `hybrid` | Session login | Session or bearer |

### Secure Cookies

- `auto` - Secure cookies if TLS detected (recommended)
- `true` - Always secure (requires HTTPS)
- `false` - Never secure (development only)

---

## Dashboard Setup

The Next.js dashboard communicates with the prefixd API through a server-side proxy. This allows the dashboard to work on any host without hardcoded URLs.

### Docker Compose

The dashboard container uses the `PREFIXD_API` environment variable to locate the backend:

```yaml
dashboard:
  build: ./frontend
  environment:
    - PREFIXD_API=http://prefixd:8080  # Docker service name (internal)
```

### Remote Deployment

When deploying to a remote server, ensure:

1. The dashboard container can reach the prefixd container (same Docker network)
2. Users access the dashboard via the server's IP/hostname on port 80 (through nginx)
3. The browser never connects directly to the backend - all API calls are proxied through nginx

```bash
# Access dashboard from your workstation
open http://your-server
```

### Local Development (Outside Docker)

For frontend development without Docker:

```bash
cd frontend
export PREFIXD_API=http://localhost:8080
bun run dev
```

---

## GoBGP v4.x Setup

prefixd requires GoBGP v4.0.0 or later.

### Docker (Included)

The `docker-compose.yml` includes GoBGP v4.x:

```yaml
gobgp:
  image: jauderho/gobgp:latest  # v4.2.0+
  volumes:
    - ./configs/gobgp.conf:/etc/gobgp/gobgp.conf
  ports:
    - "179:179"
    - "50051:50051"
```

### GoBGP Configuration

`configs/gobgp.conf`:

```toml
[global.config]
  as = 65010
  router-id = "10.10.0.10"
  port = 179

# Peer with edge router
[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.0.1"
    peer-as = 65000
  
  # IPv4 FlowSpec
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-flowspec"
  
  # IPv6 FlowSpec (optional)
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv6-flowspec"
```

### Verify GoBGP

```bash
# Check peer status
docker compose exec gobgp gobgp neighbor

# Check FlowSpec RIB
docker compose exec gobgp gobgp global rib -a ipv4-flowspec
docker compose exec gobgp gobgp global rib -a ipv6-flowspec
```

### Bare Metal GoBGP

```bash
# Download GoBGP v4.x
wget https://github.com/osrg/gobgp/releases/download/v4.2.0/gobgp_4.2.0_linux_amd64.tar.gz
tar xzf gobgp_4.2.0_linux_amd64.tar.gz
sudo mv gobgp gobgpd /usr/local/bin/

# Verify version
gobgpd --version  # Should show v4.x

# Start
sudo gobgpd -f /etc/gobgp/gobgp.conf
```

---

## Router Configuration

### Juniper Junos (MX/PTX)

Tested with cJunosEvolved 25.4R1.13-EVO (PTX10002). Works with both classic Junos (MX) and Junos Evolved (PTX).

```junos
# Import policy - must be configured first
set policy-options policy-statement FLOWSPEC-IMPORT term accept-all then accept

# Enable FlowSpec forwarding
set routing-options flow validation
set routing-options flow term-order standard

# BGP group for FlowSpec (eBGP example)
set protocols bgp group FLOWSPEC type external
set protocols bgp group FLOWSPEC import FLOWSPEC-IMPORT
set protocols bgp group FLOWSPEC peer-as 65010
set protocols bgp group FLOWSPEC neighbor 10.10.0.10 family inet flow no-validate FLOWSPEC-IMPORT
```

> **Important**: The GoBGP neighbor config must advertise **only** `ipv4-flowspec` AFI-SAFI.
> If GoBGP also advertises `inet-unicast`, Junos will reject the session with
> Open Message Error subcode 7 (unsupported capability). Configure the neighbor
> in `gobgp.conf` with only the `ipv4-flowspec` address family.

### Verify on Juniper

```junos
# BGP session
show bgp neighbor 10.10.0.10

# FlowSpec routes (this is where prefixd rules appear)
show route table inetflow.0

# Detailed FlowSpec with actions
show route table inetflow.0 extensive

# BGP summary
show bgp summary
```

### Arista EOS (7xxx)

```eos
! BGP configuration
router bgp 65000
  neighbor 10.10.0.10 remote-as 65010
  !
  address-family flow-spec ipv4
    neighbor 10.10.0.10 activate
  !
  address-family flow-spec ipv6
    neighbor 10.10.0.10 activate
```

### Cisco IOS-XR (ASR 9000, NCS)

```cisco
router bgp 65000
  neighbor 10.10.0.10
    remote-as 65010
    address-family ipv4 flowspec
    address-family ipv6 flowspec
  !
  flowspec
    address-family ipv4
      service-policy type pbr FLOWSPEC-POLICY
```

---

## PostgreSQL Setup

### Docker (Included)

The `docker-compose.yml` includes PostgreSQL:

```yaml
postgres:
  image: postgres:16-alpine
  environment:
    POSTGRES_DB: prefixd
    POSTGRES_USER: prefixd
    POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-prefixd_secret}
  volumes:
    - postgres_data:/var/lib/postgresql/data
```

### External PostgreSQL

```sql
-- Create database
CREATE DATABASE prefixd;
CREATE USER prefixd WITH PASSWORD 'secure-password';
GRANT ALL PRIVILEGES ON DATABASE prefixd TO prefixd;
```

Configure in `prefixd.yaml`:

```yaml
storage:
  connection_string: "postgres://prefixd:secure-password@postgres.internal:5432/prefixd"
  max_connections: 10
```

### High Availability

For production:

1. Use PostgreSQL with streaming replication
2. Configure connection pooling (PgBouncer)
3. Regular backups
4. Monitor replication lag

---

## Bare Metal Deployment

### Build from Source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build --release

# Install
sudo cp target/release/prefixd /usr/local/bin/
sudo cp target/release/prefixdctl /usr/local/bin/
```

### Directory Structure

```bash
sudo mkdir -p /etc/prefixd /var/lib/prefixd /var/log/prefixd
sudo cp configs/*.yaml /etc/prefixd/
sudo useradd -r -s /bin/false prefixd
sudo chown -R prefixd:prefixd /etc/prefixd /var/lib/prefixd /var/log/prefixd
```

### Systemd Service

`/etc/systemd/system/prefixd.service`:

```ini
[Unit]
Description=prefixd BGP FlowSpec policy daemon
After=network.target postgresql.service gobgpd.service
Wants=gobgpd.service

[Service]
Type=simple
User=prefixd
Group=prefixd
ExecStart=/usr/local/bin/prefixd --config /etc/prefixd
Restart=on-failure
RestartSec=5

# Security
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/prefixd /var/log/prefixd
PrivateTmp=yes

# Environment
Environment=RUST_LOG=info
EnvironmentFile=-/etc/prefixd/env

[Install]
WantedBy=multi-user.target
```

`/etc/prefixd/env`:

```bash
PREFIXD_API_TOKEN=your-secret-token
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable prefixd
sudo systemctl start prefixd
```

---

## TLS Configuration

### Self-Signed Certificates

```bash
# Generate CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -out ca.crt -subj "/CN=prefixd-ca"

# Generate server cert
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=prefixd"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -sha256
```

### Configure TLS

```yaml
http:
  listen: "0.0.0.0:8443"
  tls:
    cert_path: "/etc/prefixd/server.crt"
    key_path: "/etc/prefixd/server.key"
  auth:
    secure_cookies: true  # Required for HTTPS
```

### mTLS (Mutual TLS)

For zero-trust environments:

```yaml
http:
  auth:
    mode: mtls
  tls:
    cert_path: "/etc/prefixd/server.crt"
    key_path: "/etc/prefixd/server.key"
    ca_path: "/etc/prefixd/ca.crt"  # Client CA
```

---

## Multi-POP Deployment

Multiple prefixd instances share one PostgreSQL:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  prefixd    │     │  prefixd    │     │  prefixd    │
│  (iad1)     │     │  (fra1)     │     │  (sin1)     │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                    ┌──────┴──────┐
                    │  PostgreSQL │
                    └─────────────┘
```

### Configure POP Identity

Each instance uses a unique `pop` value:

```yaml
# iad1
pop: iad1

# fra1
pop: fra1
```

### Cross-POP Visibility

```bash
# List all mitigations across POPs
curl "http://localhost/v1/mitigations?pop=all"

# Get stats per POP
curl "http://localhost/v1/stats"
curl "http://localhost/v1/pops"
```

---

## Monitoring

### Prometheus

Scrape config:

```yaml
scrape_configs:
  - job_name: 'prefixd'
    metrics_path: /metrics
    static_configs:
      - targets: ['prefixd:8080']
```

### Key Metrics

| Metric | Description |
|--------|-------------|
| `prefixd_mitigations_active` | Active mitigations |
| `prefixd_events_ingested_total` | Events received |
| `prefixd_announcements_total` | FlowSpec announcements |
| `prefixd_bgp_session_up` | BGP session status |
| `prefixd_guardrail_rejections_total` | Rejected events |
| `prefixd_http_requests_total` | HTTP requests |

### Alerting

```yaml
groups:
  - name: prefixd
    rules:
      - alert: PrefixdBGPDown
        expr: prefixd_bgp_session_up == 0
        for: 1m
        labels:
          severity: critical
      
      - alert: PrefixdHighRejections
        expr: rate(prefixd_guardrail_rejections_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
```

### Health Checks

```bash
# Liveness check (public, lightweight - no DB/GoBGP calls)
curl http://localhost/v1/health
# Returns: {"status":"ok","version":"0.8.3","auth_mode":"none"}

# Full operational health (authenticated)
curl -H "Authorization: Bearer $TOKEN" http://localhost/v1/health/detail
# Returns: BGP sessions, database status, GoBGP connectivity, uptime, active mitigations

# CLI status (uses /v1/health/detail)
prefixdctl status
prefixdctl health
prefixdctl peers
```

---

## Production Checklist

### Security

- [ ] Generate strong API token
- [ ] Create operators with appropriate roles
- [ ] Enable TLS (or use reverse proxy)
- [ ] Configure secure_cookies for HTTPS
- [ ] Network isolation (prefixd ↔ GoBGP on private network)
- [ ] Firewall rules (only allow trusted detectors)

### Reliability

- [ ] PostgreSQL high availability
- [ ] Systemd restart policies
- [ ] Log rotation
- [ ] Backup strategy for database

### Monitoring

- [ ] Prometheus scraping metrics
- [ ] Alerting rules configured
- [ ] Dashboard for visibility
- [ ] BGP session monitoring

### Configuration

- [ ] Inventory reflects actual network
- [ ] Playbooks match security policy
- [ ] Quotas set appropriately
- [ ] Safelist populated with infrastructure IPs

### Testing

- [ ] Test event ingestion
- [ ] Verify FlowSpec reaches routers
- [ ] Test mitigation withdrawal
- [ ] Verify TTL expiry works
- [ ] Test dashboard login

---

## Lab Environment

For testing FlowSpec without production routers, see the [lab/](../lab/) directory:

| Lab | Router | Requirements | Status |
|-----|--------|--------------|--------|
| `cjunos-flowspec.clab.yml` | cJunosEvolved (PTX) | KVM (Intel or AMD) | **Verified** |
| `frr-flowspec.clab.yml` | FRR | Any Linux | **Verified** |
| `vjunos-flowspec.clab.yml` | vJunos-router (MX) | Bare metal only | Untested |

### cJunosEvolved (Recommended for Juniper Testing)

Full end-to-end tested: event → prefixd → GoBGP → Junos `inetflow.0`.

```bash
# Load image (download free from Juniper)
docker load -i cJunosEvolved-25.4R1.13-EVO.tar.gz

# Deploy
cd lab
sudo clab deploy -t cjunos-flowspec.clab.yml

# Connect prefixd-gobgp to clab network
docker network connect clab-mgmt-evo prefixd-gobgp --ip 172.30.31.10

# Restart GoBGP to load cJunos neighbor
docker restart prefixd-gobgp

# Verify (wait ~3-5 min for cJunos to boot)
docker exec prefixd-gobgp gobgp neighbor
# 172.30.31.3 should show Established

# Test with a real event
curl -X POST http://localhost/v1/events \
  -H "Content-Type: application/json" \
  -d '{"source":"test","victim_ip":"203.0.113.10","vector":"udp_flood","bps":1000000000,"pps":1000000,"top_dst_ports":[53],"confidence":0.9}'

# Verify on cJunos (admin/admin@123)
ssh admin@172.30.31.3
show route table inetflow.0
```

### FRR (No Special Hardware)

```bash
cd lab
sudo clab deploy -t frr-flowspec.clab.yml
docker network connect clab-mgmt prefixd-gobgp --ip 172.30.30.10
docker restart prefixd-gobgp
docker exec prefixd-gobgp gobgp neighbor
```

See [lab/README.md](../lab/README.md) for full instructions.
