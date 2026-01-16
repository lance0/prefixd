# Troubleshooting Guide

## Quick Diagnostics

```bash
# Check prefixd status
systemctl status prefixd
prefixdctl status

# Check BGP sessions
prefixdctl peers

# Check logs
journalctl -u prefixd -f
tail -f /var/log/prefixd/audit.jsonl | jq

# Check metrics
curl -s localhost:9090/metrics | grep prefixd_
```

## Common Issues

### 1. Events Not Creating Mitigations

**Symptoms:** Events accepted (202) but no mitigations created.

**Check audit log:**
```bash
tail -100 /var/log/prefixd/audit.jsonl | jq 'select(.action == "event_rejected")'
```

**Common causes:**

| Cause | Solution |
|-------|----------|
| IP not in inventory | Add customer/prefix to `inventory.yaml` |
| IP is safelisted | Check safelist: `prefixdctl safelist list` |
| Quota exceeded | Check quotas: `prefixdctl status` |
| Guardrail rejection | Check logs for specific guardrail error |
| Duplicate event | Same external_event_id within correlation window |

**Debug:**
```bash
# Check if IP is in inventory
curl -s localhost:8080/v1/health | jq

# Check if IP is safelisted
prefixdctl safelist list | grep "203.0.113.10"

# Check current quotas
curl -s localhost:8080/v1/stats | jq
```

### 2. BGP Session Not Established

**Symptoms:** `prefixdctl peers` shows session down.

**Check GoBGP:**
```bash
# GoBGP status
gobgp global
gobgp neighbor

# GoBGP logs
journalctl -u gobgpd -f
```

**Common causes:**

| Cause | Solution |
|-------|----------|
| Firewall blocking port 179 | Allow TCP 179 between GoBGP and router |
| ASN mismatch | Verify ASN in gobgp.conf matches router config |
| Router ID conflict | Ensure unique router-id |
| Router not configured | Add FlowSpec neighbor config on router |
| TCP MD5 password mismatch | Check password configuration both sides |

**Debug:**
```bash
# Test connectivity
telnet 10.0.0.1 179

# Check BGP on router (Juniper)
show bgp neighbor 10.10.0.10

# Force GoBGP to retry
gobgp neighbor 10.0.0.1 reset
```

### 3. FlowSpec Rules Not Applied on Router

**Symptoms:** Mitigation active in prefixd but traffic not filtered.

**Check router:**
```junos
# Juniper - show received FlowSpec
show route table inetflow.0
show route table inetflow.0 extensive

# Check if FlowSpec is being validated/rejected
show bgp neighbor 10.10.0.10 | match "FlowSpec"
```

**Common causes:**

| Cause | Solution |
|-------|----------|
| FlowSpec validation rejecting | Disable validation or configure properly |
| No import policy | Add FlowSpec import policy |
| TCAM full | Check `show pfe statistics traffic` |
| Wrong AFI/SAFI | Ensure ipv4-flowspec or ipv6-flowspec enabled |

**Debug:**
```bash
# Check what prefixd thinks is announced
prefixdctl mitigations list --status active

# Compare with GoBGP RIB
gobgp global rib -a ipv4-flowspec
```

### 4. High Memory Usage

**Symptoms:** prefixd using excessive memory.

**Check:**
```bash
# Process memory
ps aux | grep prefixd

# Active mitigations count
curl -s localhost:8080/v1/stats | jq '.active_mitigations'

# Database size
ls -lh /var/lib/prefixd/prefixd.db
```

**Solutions:**

1. **Reduce quotas** - Lower `max_active_global` in config
2. **Shorter TTLs** - Reduce `max_ttl_seconds`
3. **Database cleanup** - Old data accumulates
   ```sql
   -- SQLite: vacuum old data
   DELETE FROM events WHERE ingested_at < datetime('now', '-7 days');
   DELETE FROM mitigations WHERE status = 'expired' AND updated_at < datetime('now', '-7 days');
   VACUUM;
   ```

### 5. Reconciliation Loop Errors

**Symptoms:** Logs show reconciliation failures.

**Check logs:**
```bash
journalctl -u prefixd | grep -i reconcil
```

**Common causes:**

| Cause | Solution |
|-------|----------|
| GoBGP unreachable | Check GoBGP gRPC endpoint (port 50051) |
| Database locked | Restart prefixd, check disk space |
| Stale announcements | Will self-heal on next reconciliation |

### 6. Authentication Failures

**Symptoms:** 401 Unauthorized responses.

**Bearer token issues:**
```bash
# Check token is set
echo $PREFIXD_API_TOKEN

# Test with explicit token
curl -H "Authorization: Bearer $PREFIXD_API_TOKEN" \
  http://localhost:8080/v1/health
```

**mTLS issues:**
```bash
# Test certificate
openssl x509 -in client.crt -text -noout

# Test connection
openssl s_client -connect localhost:8443 \
  -cert client.crt -key client.key -CAfile ca.crt
```

### 7. Slow Event Processing

**Symptoms:** High latency on event ingestion.

**Check:**
```bash
# Event processing time in metrics
curl -s localhost:9090/metrics | grep prefixd_event_processing

# Database performance
sqlite3 /var/lib/prefixd/prefixd.db "PRAGMA integrity_check;"
```

**Solutions:**

1. **Index check** - Ensure database has proper indexes
2. **Connection pool** - Increase pool size for PostgreSQL
3. **Rate limiting** - May be hitting rate limits

## Log Analysis

### Log Levels

| Level | When to Use |
|-------|-------------|
| `error` | Something failed, needs attention |
| `warn` | Potential issue, guardrail rejection |
| `info` | Normal operations (default) |
| `debug` | Detailed flow, useful for debugging |
| `trace` | Very verbose, includes all data |

### Enable Debug Logging

```bash
# Temporarily via environment
RUST_LOG=debug prefixd --config /etc/prefixd

# Or in config
observability:
  log_level: debug
```

### Key Log Messages

**Event accepted:**
```json
{"level":"INFO","msg":"event accepted","event_id":"...","victim_ip":"203.0.113.10"}
```

**Mitigation created:**
```json
{"level":"INFO","msg":"created mitigation","mitigation_id":"...","victim_ip":"203.0.113.10","action":"police"}
```

**Guardrail rejection:**
```json
{"level":"WARN","msg":"guardrail rejected mitigation","error":"prefix too broad: /24 (max /32)"}
```

**BGP announcement:**
```json
{"level":"INFO","msg":"announced flowspec","mitigation_id":"...","nlri":"..."}
```

### Audit Log Queries

```bash
# All mitigations created today
cat audit.jsonl | jq 'select(.action == "mitigation_created" and .timestamp > "2026-01-16")'

# All withdrawals by operator
cat audit.jsonl | jq 'select(.action == "mitigation_withdrawn" and .actor_type == "operator")'

# Events from specific source
cat audit.jsonl | jq 'select(.details.source == "fastnetmon")'
```

## Metrics Reference

### Counters

| Metric | Labels | Description |
|--------|--------|-------------|
| `prefixd_events_ingested_total` | `source`, `vector` | Events received |
| `prefixd_announcements_total` | `action` | FlowSpec announcements |
| `prefixd_withdrawals_total` | `reason` | FlowSpec withdrawals |
| `prefixd_guardrail_rejections_total` | `reason` | Rejected events |

### Gauges

| Metric | Labels | Description |
|--------|--------|-------------|
| `prefixd_mitigations_active` | `action`, `customer` | Active mitigations |
| `prefixd_bgp_session_up` | `peer` | BGP session status |

### Histograms

| Metric | Description |
|--------|-------------|
| `prefixd_event_processing_seconds` | Event processing latency |
| `prefixd_bgp_announcement_seconds` | BGP announcement latency |

## Recovery Procedures

### Database Corruption (SQLite)

```bash
# Stop prefixd
systemctl stop prefixd

# Backup corrupted database
cp /var/lib/prefixd/prefixd.db /var/lib/prefixd/prefixd.db.corrupt

# Attempt recovery
sqlite3 /var/lib/prefixd/prefixd.db ".recover" | sqlite3 /var/lib/prefixd/prefixd.db.recovered

# Replace if successful
mv /var/lib/prefixd/prefixd.db.recovered /var/lib/prefixd/prefixd.db

# Restart
systemctl start prefixd
```

### Emergency Withdrawal of All Rules

```bash
# Via CLI
prefixdctl mitigations list --status active | \
  jq -r '.[].mitigation_id' | \
  xargs -I{} prefixdctl mitigations withdraw {} --reason "emergency"

# Or directly via GoBGP
gobgp global rib -a ipv4-flowspec del all
```

### Force Reconciliation

```bash
# Restart prefixd (reconciliation runs on startup)
systemctl restart prefixd

# Or wait for next reconciliation interval (default 30s)
```

## Getting Help

1. **Check logs** - Most issues are visible in logs
2. **Enable debug logging** - More detail when needed
3. **Check metrics** - Prometheus metrics show trends
4. **Audit log** - Full history of all actions
5. **GitHub Issues** - Report bugs with logs attached
