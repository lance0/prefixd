# Troubleshooting Guide

Compose examples use the primary `rustbgpd` profile and controller service
`prefixd-rustbgpd`. For the GoBGP profile, use `gobgp` and
`prefixd-gobgp`; do not enable both. Follow the [quickstart](../tutorials/quickstart.md)
to start a fresh stack. Bare `docker compose up -d` does not start a controller.
Profile selection does not change the database's
[speaker ownership binding](upgrading.md#speaker-ownership-upgrade).

The dashboard and API share `http://localhost` through nginx; the controller's
port 8080 is not published. Protected curl examples below assume a deployment
configured for bearer authentication with `PREFIXD_API_TOKEN` set. The shipped
credentials-mode stack uses a logged-in browser session instead; see
[authentication setup](deployment.md#authentication-setup).

## Quick Diagnostics

```bash
# Check health
curl http://localhost/v1/health | jq

# Check status
prefixdctl status
prefixdctl peers

# Check logs
docker compose logs -f prefixd-rustbgpd
journalctl -u prefixd -f

# Check metrics from the trusted container/management network
curl -s http://prefixd:8080/metrics | grep prefixd_
```

Default Compose does not publish the API listener, and nginx and the dashboard
proxy block metrics. From the host, use Prometheus at `127.0.0.1:9091` or Grafana
at `127.0.0.1:3001` instead.

---

## Event Ingestion Issues

### Events Not Creating Mitigations

**Symptoms:** Events return 202 but no mitigations appear.

**Check the response:**
```bash
curl --fail-with-body --silent --show-error -X POST http://localhost/v1/events \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $PREFIXD_API_TOKEN" \
  -d "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"source\":\"test\",\"victim_ip\":\"203.0.113.10\",\"vector\":\"udp_flood\",\"bps\":5000000000,\"confidence\":0.95}"
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
| `new mitigation rate exceeded` | `quotas.max_new_per_minute` mitigations already created at this POP in the last 60 seconds | Wait for the window to pass or raise the limit |
| `too many ports` | >8 ports | Reduce ports in event |

---

## BGP Issues

### Session Not Established

**Check rustbgpd:**

```bash
docker compose exec rustbgpd rbgp --addr unix:///run/rustbgpd/grpc.sock health
docker compose exec rustbgpd rbgp --addr unix:///run/rustbgpd/grpc.sock neighbor
```

**GoBGP compatibility profile:**
```bash
# Docker
docker compose exec gobgp gobgp neighbor

# Bare metal
gobgp neighbor
```

**GoBGP output example:**
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

**Check rustbgpd's retained local intent:**

```bash
docker compose exec rustbgpd rbgp --addr unix:///run/rustbgpd/grpc.sock \
  --json flowspec received 0.0.0.0 --family ipv4_flowspec
docker compose exec rustbgpd rbgp --addr unix:///run/rustbgpd/grpc.sock \
  --json flowspec received 0.0.0.0 --family ipv6_flowspec
```

**GoBGP compatibility profile's accepted local RIB:**
```bash
# IPv4 FlowSpec
docker compose exec gobgp gobgp global rib -a ipv4-flowspec

# IPv6 FlowSpec
docker compose exec gobgp gobgp global rib -a ipv6-flowspec
```

Neither local inventory proves export or router enforcement. If a local rule is
absent on the receiving router:

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

For the compatibility profile, restart GoBGP after changing the config:
`docker compose --profile gobgp restart gobgp`. If you recreate its container,
recreate the namespace-sharing controller together as described in the
[upgrade guide](upgrading.md#controller-restart).

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
docker compose exec prefixd-rustbgpd prefixdctl operators list
```

**Create operator** (the password prompt hides input):
```bash
docker compose exec prefixd-rustbgpd prefixdctl operators create --username admin --role admin
```

These setup commands use the container's `DATABASE_URL` directly. Native
installations must set that variable for the deployment's database.

**Check session cookies:**
- Browser: Check Developer Tools > Application > Cookies
- Ensure `session` cookie is set after login
- If using HTTPS, ensure TLS is correctly terminated and requests include the `Secure` session cookie flag

### API Bearer Token Rejected

**Check token is set:**
```bash
test -n "$PREFIXD_API_TOKEN" && echo "token is set"
```

**Test authentication:**
```bash
curl --fail-with-body --silent --show-error -H "Authorization: Bearer $PREFIXD_API_TOKEN" \
  http://localhost/v1/health/detail
```

**Check config:**
```yaml
http:
  auth:
    mode: bearer
    bearer_token_env: "PREFIXD_API_TOKEN"
```

### CORS Errors (Dashboard)

**Symptoms:** Browser console shows CORS errors.

Open the dashboard through nginx at `http://localhost` so API requests and
WebSockets use the same origin. Port 3000 is an internal service, not a second
public entrypoint in the supplied Compose stack. For a custom split-origin
deployment, review the [HTTP configuration](../reference/configuration.md)
and ingress rather than bypassing the proxy.

---

## Performance Issues

### Slow Event Processing

**Check metrics:**
```bash
# Run from the trusted container/management network
curl -s http://prefixd:8080/metrics | grep prefixd_http_request_duration
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

This keeps active mitigations, pending withdrawals, recent history and audit logs.
Old terminal mitigations referenced by the announcement ledger remain for review.
Events referenced by retained mitigations or signal groups remain available for
correlation, detector unbans and incident history.

<!-- database-retention-prune -->
```sql
BEGIN;
DELETE FROM withdrawal_requests AS request
USING mitigations AS mitigation
WHERE request.mitigation_id = mitigation.mitigation_id
  AND request.completed_at < NOW() - INTERVAL '7 days'
  AND mitigation.status IN ('expired', 'withdrawn')
  AND mitigation.updated_at < NOW() - INTERVAL '7 days';

DELETE FROM mitigations AS mitigation
WHERE mitigation.status IN ('expired', 'withdrawn')
  AND mitigation.updated_at < NOW() - INTERVAL '7 days'
  AND NOT EXISTS (
    SELECT 1 FROM withdrawal_requests AS request
    WHERE request.mitigation_id = mitigation.mitigation_id
  )
  AND NOT EXISTS (
    SELECT 1 FROM flowspec_announcements AS announcement
    WHERE announcement.mitigation_id = mitigation.mitigation_id
  );

DELETE FROM events AS event
WHERE event.ingested_at < NOW() - INTERVAL '7 days'
  AND NOT EXISTS (
    SELECT 1 FROM mitigations AS mitigation
    WHERE mitigation.triggering_event_id = event.event_id
       OR mitigation.last_event_id = event.event_id
  )
  AND NOT EXISTS (
    SELECT 1 FROM signal_group_events AS membership
    WHERE membership.event_id = event.event_id
  );
COMMIT;
```

Run vacuum separately after the transaction has committed:

```sql
VACUUM ANALYZE;
```

---

## Reconciliation Issues

### Reconciliation Loop Errors

**Check logs:**
```bash
docker compose logs prefixd-rustbgpd 2>&1 | grep -i reconcil
```

**Common causes:**

| Error | Cause | Fix |
|-------|-------|-----|
| Speaker unreachable | Selected service/socket down | Check selected speaker logs and endpoint |
| Database error | Connection issue | Check PostgreSQL |
| Parse error | Unsupported FlowSpec format | Check selected backend, version and local rules |

### Unknown Local Rules

**Symptoms:** Speaker-local rules are absent from prefixd's desired inventory.

Compare the selected speaker's local inventory above with all relevant mitigation
pages, statuses, POP ownership and pending cleanup. Reconciliation reports unknown
rules; it does not delete them because it cannot establish their owner. Another
controller or operator may have installed them. Do not clear the RIB wholesale.
Check [speaker ownership](upgrading.md#speaker-ownership-upgrade) and verify
individual removals on the original speaker and receiving router.

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

In Compose, change `environment.RUST_LOG` to `debug` for the selected controller
in `docker-compose.yml`, then recreate that controller:

```bash
docker compose --profile rustbgpd up -d --no-deps --no-build prefixd-rustbgpd
```

For a native service, set `RUST_LOG=debug` in its environment or use the config
below when `RUST_LOG` is unset. The Compose file's explicit environment takes
precedence over this setting:

```yaml
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

Audit entries are stored in PostgreSQL. Use the dashboard Audit Log or
`GET /v1/audit` with an authorized session or bearer token. For bearer mode:

```bash
curl -fsS -H "Authorization: Bearer $PREFIXD_API_TOKEN" \
  'http://localhost/v1/audit?limit=100' | jq '.entries[]'
```

Use `next_cursor` to retrieve additional pages; see the
[audit API reference](../reference/api.md#list-audit-entries).

---

## Emergency Procedures

### Withdraw All Mitigations

Pause detector input first. Use the authenticated dashboard or CLI to withdraw
the affected mitigations with an explicit reason, reviewing every page and any
pending or escalated intent. Check durable pending cleanup and verify removal
on the selected speaker and receiving routers before declaring the incident
cleared. Check [pending cleanup](upgrading.md#pending-withdrawals-and-rollback); clearing
the speaker's RIB directly bypasses withdrawal intent and allows the controller
to reannounce eligible desired rules.

### Stop All New Mitigations

Pause detector input. Before changing an enforced deployment to `mode: dry-run`,
withdraw active intent, drain pending cleanup on the original speaker and verify
its local state. Dry-run does not delete previously enforced rules or acknowledge
their pending deletions. Follow the [mode-change guidance](upgrading.md#pending-withdrawals-and-rollback),
then restart the selected controller after updating its main configuration.

### Force Database Reconnection

```bash
# Restart prefixd
docker compose --profile rustbgpd restart prefixd-rustbgpd
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
