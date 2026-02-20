# Troubleshooting Guide

## Quick Diagnostics

```bash
# Check health
curl http://localhost/v1/health | jq

# Check status
prefixdctl status
prefixdctl peers

# Check logs
docker compose logs -f prefixd
journalctl -u prefixd -f

# Check metrics
curl -s localhost:9090/metrics | grep prefixd_
```

---

## Event Ingestion Issues

### Events Not Creating Mitigations

**Symptoms:** Events return 202 but no mitigations appear.

**Check the response:**
```bash
curl -v -X POST http://localhost/v1/events \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $PREFIXD_API_TOKEN" \
  -d '{"source":"test","victim_ip":"203.0.113.10","vector":"udp_flood"}'
```

**Common causes:**

| Response | Cause | Fix |
|----------|-------|-----|
| 403 Forbidden | IP is safelisted | `prefixdctl safelist list` |
| 422 Unprocessable | Guardrail rejection | Check error message |
| 201 but no mitigation | IP not in inventory | Add to `inventory.yaml` |
| 429 Too Many Requests | Rate limited | Wait or increase limits |

**Debug inventory lookup:**
```bash
# Check if IP is in inventory
grep -r "203.0.113" configs/inventory.yaml

# Check safelist
prefixdctl safelist list
```

### Guardrail Rejections

**Symptoms:** Events rejected with 422 status.

**Common rejections:**

| Error | Cause | Fix |
|-------|-------|-----|
| `prefix too broad` | Not a /32 | Detector must send specific IPs |
| `TTL too short/long` | Outside bounds | Check `guardrails.min_ttl_seconds` |
| `quota exceeded` | Too many mitigations | Increase quota or wait for expiry |
| `too many ports` | >8 ports | Reduce ports in event |

---

## BGP Issues

### Session Not Established

**Check GoBGP:**
```bash
# Docker
docker compose exec gobgp gobgp neighbor

# Bare metal
gobgp neighbor
```

**Expected output:**
```
Peer            AS  Up/Down State       |#Received  Accepted
10.0.0.1     65000 01:23:45 Establ      |        0         0
```

**If State is not "Establ":**

| State | Cause | Fix |
|-------|-------|-----|
| Idle | No route to peer | Check network/firewall |
| Active | TCP connection failing | Firewall, wrong IP |
| OpenSent | Capability mismatch | Check AFI/SAFI config |
| OpenConfirm | Authentication failed | Check MD5 password |

**Debug connectivity:**
```bash
# Test TCP 179
telnet 10.0.0.1 179
nc -zv 10.0.0.1 179

# Check firewall
iptables -L -n | grep 179
```

### FlowSpec Not Reaching Router

**Check GoBGP RIB:**
```bash
# IPv4 FlowSpec
docker compose exec gobgp gobgp global rib -a ipv4-flowspec

# IPv6 FlowSpec
docker compose exec gobgp gobgp global rib -a ipv6-flowspec
```

**If rules are in GoBGP but not on router:**

1. Check BGP session includes FlowSpec AFI/SAFI
2. Check router import policy accepts FlowSpec
3. Check FlowSpec validation settings

---

## Router-Specific Issues

### Juniper (Junos / Junos Evolved)

Verified with cJunosEvolved 25.4R1.13-EVO (PTX10002-36QDD).

#### Check FlowSpec Routes

```junos
# Show FlowSpec table (this is where prefixd rules appear)
show route table inetflow.0

# Detailed view with actions
show route table inetflow.0 extensive

# Show specific prefix
show route table inetflow.0 match-prefix 203.0.113.10
```

#### Check BGP Session

```junos
# Session status
show bgp neighbor 10.10.0.10

# FlowSpec-specific
show bgp neighbor 10.10.0.10 | match "NLRI|flowspec"

# Received routes
show route receive-protocol bgp 10.10.0.10 table inetflow.0
```

#### Common Juniper Issues

**Open Message Error (subcode 7) - session won't establish:**

This is the most common issue. Junos rejects the BGP session because GoBGP advertises
`inet-unicast` alongside `inet-flow`. Junos sees the unicast capability as unsupported
and sends a NOTIFICATION.

```
show log messages | match bgp
# BGP_NLRI_MISMATCH: mismatch NLRI: peer: <inet-unicast> us: <inet-flow>
# NOTIFICATION sent: code 2 subcode 7 (unsupported capability)
```

**Fix:** Configure the GoBGP neighbor with **only** `ipv4-flowspec`:

```toml
# configs/gobgp.conf - neighbor must have ONLY flowspec family
[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.0.1"
    peer-as = 65000
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-flowspec"
  # Do NOT add ipv4-unicast here
```

Restart GoBGP after changing the config: `docker restart prefixd-gobgp`

**"License key missing; requires 'BGP' license":**

This warning appears on cJunosEvolved but FlowSpec still works. It's cosmetic only.

**FlowSpec validation rejecting routes:**
```junos
# Check validation status
show route table inetflow.0 extensive | match "validation"

# Disable validation (required for eBGP FlowSpec)
set protocols bgp group FLOWSPEC neighbor 10.10.0.10 family inet flow no-validate FLOWSPEC-IMPORT
```

**No import policy:**
```junos
# Add FlowSpec import policy
set policy-options policy-statement FLOWSPEC-IMPORT term accept-all then accept
set protocols bgp group FLOWSPEC import FLOWSPEC-IMPORT
```

**FlowSpec not applied to forwarding:**
```junos
# Enable FlowSpec forwarding
set routing-options flow validation
set routing-options flow term-order standard
commit
```

#### cJunosEvolved Lab Issues

**ZTP running / config not applied:**

The startup config must use `FXP0ADDR` (not `FXP0ADDRESS`) for the management IP token.
Check boot log: `docker exec <container> cat /home/evo/boot.log`

**"System is not yet ready" on `docker exec cli`:**

The outer container's `cli` is not the Junos CLI. Connect via serial console instead:
```bash
docker exec <container> bash -c '(echo "admin"; sleep 1; echo "admin@123"; sleep 3; echo "show bgp summary"; sleep 3) | telnet 127.0.0.1 8601'
```

Or SSH once the router is fully booted: `ssh admin@<mgmt-ip>` (password: `admin@123`)

**vJunos-router won't boot in a VM:**

This is a documented Juniper limitation - vJunos cannot run inside a VM (no nested virtualization).
Use cJunosEvolved instead, which works on any host with KVM.

#### Debug FlowSpec Processing

```junos
# Trace BGP updates
set protocols bgp traceoptions file bgp-trace
set protocols bgp traceoptions flag update detail
commit

# View trace
show log bgp-trace | match flowspec

# Clean up
deactivate protocols bgp traceoptions
commit
```

### Arista (EOS)

#### Check FlowSpec Routes

```eos
! Show FlowSpec table
show bgp flow-spec ipv4

! Detailed view
show bgp flow-spec ipv4 detail

! Check counters
show flow-spec ipv4 counters
```

#### Check BGP Session

```eos
! Session status
show bgp neighbor 10.10.0.10

! FlowSpec capability
show bgp neighbor 10.10.0.10 | include flow-spec
```

#### Common Arista Issues

**FlowSpec not enabled:**
```eos
router bgp 65000
  address-family flow-spec ipv4
    neighbor 10.10.0.10 activate
```

**TCAM exhausted:**
```eos
! Check TCAM usage
show hardware capacity

! May need to adjust TCAM profile
```

### Cisco IOS-XR

#### Check FlowSpec Routes

```cisco
! Show FlowSpec table
show bgp ipv4 flowspec

! Detailed view
show bgp ipv4 flowspec detail

! Check applied rules
show flowspec summary
```

#### Check BGP Session

```cisco
! Session status
show bgp ipv4 flowspec neighbor 10.10.0.10

! Capability exchange
show bgp ipv4 flowspec neighbor 10.10.0.10 | include capability
```

#### Common IOS-XR Issues

**FlowSpec not enabled:**
```cisco
router bgp 65000
  neighbor 10.10.0.10
    address-family ipv4 flowspec
```

**No service policy:**
```cisco
flowspec
  address-family ipv4
    service-policy type pbr FLOWSPEC-POLICY
```

---

## Authentication Issues

### Dashboard Login Fails

**Check operators exist:**
```bash
prefixdctl operators list
```

**Create operator:**
```bash
prefixdctl operators create --username admin --role admin --password
```

**Check session cookies:**
- Browser: Check Developer Tools > Application > Cookies
- Ensure `session` cookie is set after login
- If using HTTPS, ensure `secure_cookies: true` in config

### API Bearer Token Rejected

**Check token is set:**
```bash
echo $PREFIXD_API_TOKEN
```

**Test authentication:**
```bash
curl -v -H "Authorization: Bearer $PREFIXD_API_TOKEN" \
  http://localhost/v1/health
```

**Check config:**
```yaml
http:
  auth:
    mode: bearer
    token: "${PREFIXD_API_TOKEN}"
```

### CORS Errors (Dashboard)

**Symptoms:** Browser console shows CORS errors.

**Fix:** Add dashboard origin to config:
```yaml
http:
  cors_origins: "http://localhost:3000"
```

---

## Performance Issues

### Slow Event Processing

**Check metrics:**
```bash
curl -s localhost:9090/metrics | grep prefixd_http_request_duration
```

**Common causes:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| High DB latency | Slow queries | Add indexes, vacuum |
| High GoBGP latency | Network issues | Check connectivity |
| Rate limiting | Too many events | Increase limits |

### High Memory Usage

**Check active mitigations:**
```bash
curl -s http://localhost/v1/stats | jq '.total_active'
```

**Reduce memory:**
1. Lower `quotas.max_active_global`
2. Reduce TTLs
3. Clean old data from database

### Database Growth

**Check table sizes (PostgreSQL):**
```sql
SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_stat_user_tables
ORDER BY pg_total_relation_size(relid) DESC;
```

**Clean old data:**
```sql
DELETE FROM events WHERE created_at < NOW() - INTERVAL '7 days';
DELETE FROM mitigations WHERE status IN ('expired', 'withdrawn')
  AND updated_at < NOW() - INTERVAL '7 days';
VACUUM ANALYZE;
```

---

## Reconciliation Issues

### Reconciliation Loop Errors

**Check logs:**
```bash
docker compose logs prefixd 2>&1 | grep -i reconcil
```

**Common causes:**

| Error | Cause | Fix |
|-------|-------|-----|
| GoBGP unreachable | Container/service down | Restart GoBGP |
| Database error | Connection issue | Check PostgreSQL |
| Parse error | Unknown FlowSpec format | Check GoBGP version |

### Orphan Rules in GoBGP

**Symptoms:** Rules in GoBGP RIB that aren't in prefixd database.

**Check:**
```bash
# GoBGP RIB
docker compose exec gobgp gobgp global rib -a ipv4-flowspec

# prefixd active mitigations
prefixdctl mitigations list --status active
```

**Fix:** Reconciliation will clean orphans on next run (30s default).

**Manual cleanup:**
```bash
docker compose exec gobgp gobgp global rib -a ipv4-flowspec del all
```

---

## WebSocket Issues

### Dashboard Not Updating in Real-Time

**Check WebSocket connection:**
- Browser: Developer Tools > Network > WS
- Look for connection to `/v1/ws/feed`

**Common causes:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| No WS connection | Not logged in | Login first |
| Connection drops | Network issues | Check for proxies |
| No updates | Backend not emitting | Check prefixd logs |

**Test WebSocket manually:**
```bash
# Requires wscat (npm install -g wscat)
wscat -c ws://localhost/v1/ws/feed -H "Cookie: session=..."
```

---

## Log Analysis

### Enable Debug Logging

```bash
# Environment variable
RUST_LOG=debug docker compose up prefixd

# Or in config
observability:
  log_level: debug
```

### Key Log Messages

**Successful flow:**
```
INFO event accepted event_id=... victim_ip=203.0.113.10
INFO mitigation created mitigation_id=... action=police
INFO flowspec announced nlri_hash=...
```

**Rejection:**
```
WARN guardrail rejected error="quota exceeded: customer acme has 10 active"
```

**BGP issue:**
```
ERROR GoBGP announcement failed error="connection refused"
```

### Audit Log Queries

```bash
# All events today
cat audit.jsonl | jq 'select(.timestamp > "2026-01-18")'

# Withdrawals by operator
cat audit.jsonl | jq 'select(.action == "mitigation_withdrawn")'

# Events from FastNetMon
cat audit.jsonl | jq 'select(.details.source == "fastnetmon")'
```

---

## Emergency Procedures

### Withdraw All Mitigations

```bash
# Via CLI
prefixdctl mitigations list --status active -f json | \
  jq -r '.[].id' | \
  xargs -I{} prefixdctl mitigations withdraw {} --reason "emergency"

# Direct GoBGP (nuclear option)
docker compose exec gobgp gobgp global rib -a ipv4-flowspec del all
docker compose exec gobgp gobgp global rib -a ipv6-flowspec del all
```

### Stop All New Mitigations

```bash
# Switch to dry-run mode (edit config)
mode: dry-run

# Restart
docker compose restart prefixd
```

### Force Database Reconnection

```bash
# Restart prefixd
docker compose restart prefixd
```

---

## Getting Help

1. **Check logs first** - Most issues are visible in logs
2. **Enable debug logging** - More detail when needed
3. **Check metrics** - `/metrics` endpoint shows trends
4. **Audit log** - Complete history of all actions
5. **GitHub Issues** - Report bugs with:
   - prefixd version
   - GoBGP version
   - Router vendor/version
   - Relevant logs
   - Steps to reproduce
