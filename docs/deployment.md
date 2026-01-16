# Deployment Guide

## Overview

prefixd requires:
- **prefixd** daemon (this software)
- **GoBGP** sidecar for BGP FlowSpec announcements
- **Database** (SQLite for single-node, PostgreSQL for multi-POP)
- **Edge routers** configured to receive and apply FlowSpec

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Detector   │────▶│   prefixd   │────▶│   GoBGP     │
│ (FastNetMon)│     │   :8080     │     │   :50051    │
└─────────────┘     └──────┬──────┘     └──────┬──────┘
                           │                   │
                           ▼                   ▼
                    ┌─────────────┐     ┌─────────────┐
                    │  Database   │     │   Routers   │
                    │ (SQLite/PG) │     │  (Juniper)  │
                    └─────────────┘     └─────────────┘
```

## Docker Compose (Recommended)

The easiest deployment method using the included `docker-compose.yml`.

### Prerequisites

- Docker Engine 20.10+
- Docker Compose v2

### Quick Start

```bash
# Clone and enter directory
git clone https://github.com/yourorg/prefixd.git
cd prefixd

# Create data directory
mkdir -p data

# Copy and edit configs
cp configs/prefixd-postgres.yaml configs/prefixd.yaml
# Edit configs/prefixd.yaml, inventory.yaml, playbooks.yaml

# Set API token
export PREFIXD_API_TOKEN=$(openssl rand -hex 32)
echo "PREFIXD_API_TOKEN=$PREFIXD_API_TOKEN" > .env

# Start stack
docker compose up -d

# Check status
docker compose ps
docker compose logs -f prefixd
```

### docker-compose.yml Services

| Service | Port | Description |
|---------|------|-------------|
| `prefixd` | 8080 | HTTP API |
| `prefixd` | 9090 | Prometheus metrics |
| `gobgp` | 50051 | gRPC (internal) |
| `gobgp` | 179 | BGP (to routers) |
| `postgres` | 5432 | Database |
| `dashboard` | 3000 | Web UI |

### Production Considerations

```yaml
# docker-compose.override.yml for production
services:
  prefixd:
    restart: always
    environment:
      - RUST_LOG=info
    deploy:
      resources:
        limits:
          memory: 512M
  
  postgres:
    restart: always
    volumes:
      - postgres_data:/var/lib/postgresql/data
    deploy:
      resources:
        limits:
          memory: 1G

volumes:
  postgres_data:
```

## Bare Metal Deployment

### Build from Source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Build release binary
cargo build --release

# Install binaries
sudo cp target/release/prefixd /usr/local/bin/
sudo cp target/release/prefixdctl /usr/local/bin/
```

### Directory Structure

```bash
sudo mkdir -p /etc/prefixd
sudo mkdir -p /var/lib/prefixd
sudo mkdir -p /var/log/prefixd

# Copy configs
sudo cp configs/*.yaml /etc/prefixd/

# Set permissions
sudo chown -R prefixd:prefixd /etc/prefixd /var/lib/prefixd /var/log/prefixd
```

### Systemd Service

Create `/etc/systemd/system/prefixd.service`:

```ini
[Unit]
Description=prefixd BGP FlowSpec routing policy daemon
After=network.target gobgpd.service
Wants=gobgpd.service

[Service]
Type=simple
User=prefixd
Group=prefixd
ExecStart=/usr/local/bin/prefixd --config /etc/prefixd
Restart=on-failure
RestartSec=5

# Security hardening
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

Create `/etc/prefixd/env`:

```bash
PREFIXD_API_TOKEN=your-secret-token-here
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable prefixd
sudo systemctl start prefixd
sudo systemctl status prefixd
```

## GoBGP Configuration

### Install GoBGP

```bash
# Download latest release
wget https://github.com/osrg/gobgp/releases/download/v3.25.0/gobgp_3.25.0_linux_amd64.tar.gz
tar xzf gobgp_3.25.0_linux_amd64.tar.gz
sudo mv gobgp gobgpd /usr/local/bin/
```

### GoBGP Config (`/etc/gobgp/gobgp.conf`)

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
  
  # Enable IPv4 FlowSpec
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-flowspec"
  
  # Enable IPv6 FlowSpec (optional)
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv6-flowspec"

# Second peer (if applicable)
[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.0.2"
    peer-as = 65000
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-flowspec"
```

### GoBGP Systemd Service

Create `/etc/systemd/system/gobgpd.service`:

```ini
[Unit]
Description=GoBGP Routing Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gobgpd -f /etc/gobgp/gobgp.conf
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Router Configuration

### Juniper Junos

```junos
# Enable FlowSpec
set protocols bgp group FLOWSPEC type internal
set protocols bgp group FLOWSPEC local-address 10.0.0.1
set protocols bgp group FLOWSPEC neighbor 10.10.0.10 family inet flow no-validate FLOWSPEC-IMPORT

# Import policy to accept FlowSpec routes
set policy-options policy-statement FLOWSPEC-IMPORT term accept-flowspec from family inet-flow
set policy-options policy-statement FLOWSPEC-IMPORT term accept-flowspec then accept

# Apply to forwarding table
set routing-options flow term-order standard
set routing-options forwarding-table export FLOWSPEC-EXPORT
```

### Juniper FlowSpec Validation (Important)

```junos
# Disable validation for lab/testing
set protocols bgp group FLOWSPEC neighbor 10.10.0.10 family inet flow no-validate FLOWSPEC-IMPORT

# For production, consider:
# - Prefix filters on what destinations can be mitigated
# - Rate limiting on FlowSpec updates
# - Monitoring for unexpected rules
```

### Verify FlowSpec on Router

```junos
# Show received FlowSpec routes
show route table inetflow.0

# Show FlowSpec details
show route table inetflow.0 extensive

# Monitor FlowSpec updates
monitor traffic interface xe-0/0/0 matching "port 179"
```

## PostgreSQL Setup (Multi-POP)

### Create Database

```sql
CREATE DATABASE prefixd;
CREATE USER prefixd WITH PASSWORD 'secure-password';
GRANT ALL PRIVILEGES ON DATABASE prefixd TO prefixd;
```

### Configure prefixd

```yaml
# prefixd.yaml
storage:
  driver: postgres
  path: "postgres://prefixd:secure-password@postgres.internal:5432/prefixd"
```

### High Availability

For production multi-POP deployments:

1. Use PostgreSQL with streaming replication
2. Consider PgBouncer for connection pooling
3. Each POP runs its own prefixd instance
4. All instances share the same PostgreSQL cluster

## TLS/mTLS Setup

### Generate Certificates

```bash
# Create CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -out ca.crt -subj "/CN=prefixd-ca"

# Create server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/CN=prefixd.internal"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -sha256

# Create client certificate (for mTLS)
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
  -subj "/CN=detector-1"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days 365 -sha256
```

### Configure mTLS

```yaml
# prefixd.yaml
http:
  listen: "0.0.0.0:8443"
  auth:
    mode: mtls
  tls:
    cert_path: "/etc/prefixd/server.crt"
    key_path: "/etc/prefixd/server.key"
    ca_path: "/etc/prefixd/ca.crt"
```

### Test mTLS Connection

```bash
curl --cert client.crt --key client.key --cacert ca.crt \
  https://prefixd.internal:8443/v1/health
```

## Monitoring

### Prometheus Metrics

Add to your Prometheus config:

```yaml
scrape_configs:
  - job_name: 'prefixd'
    static_configs:
      - targets: ['prefixd:9090']
```

### Key Metrics

| Metric | Description |
|--------|-------------|
| `prefixd_events_ingested_total` | Total events received |
| `prefixd_mitigations_active` | Current active mitigations |
| `prefixd_announcements_total` | FlowSpec announcements made |
| `prefixd_bgp_session_up` | BGP session status (1=up) |
| `prefixd_guardrail_rejections_total` | Rejected by guardrails |

### Alerting Rules

```yaml
groups:
  - name: prefixd
    rules:
      - alert: PrefixdBGPDown
        expr: prefixd_bgp_session_up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "prefixd BGP session down"
      
      - alert: PrefixdHighRejectionRate
        expr: rate(prefixd_guardrail_rejections_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High guardrail rejection rate"
```

## Health Checks

```bash
# API health
curl http://localhost:8080/v1/health

# BGP session status
prefixdctl peers

# Active mitigations
prefixdctl mitigations list --status active

# Metrics endpoint
curl http://localhost:9090/metrics
```
