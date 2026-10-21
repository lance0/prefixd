# Grafana Dashboards

prefixd includes pre-built Grafana dashboards for monitoring operations and security.

## Prerequisites

- Grafana 9.0+ (tested with 10.x)
- Prometheus datasource configured
- prefixd `/metrics` endpoint scraped by Prometheus

Default Compose scrapes `prefixd:8080` on its private network. The API listener is
not published, and nginx and the dashboard proxy do not expose `/metrics`.
Prometheus (`127.0.0.1:9091`) and Grafana (`127.0.0.1:3001`) bind host loopback;
use an operator-controlled tunnel or authenticated proxy for remote access.

## Import Dashboards

### Via Grafana UI

1. Go to **Dashboards** → **Import**
2. Upload JSON file or paste contents from:
   - `grafana/prefixd-operations.json`
   - `grafana/prefixd-security.json`
3. Select your Prometheus datasource
4. Click **Import**

### Via Grafana API

```bash
# Import operations dashboard
curl -X POST http://admin:admin@localhost:3001/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @grafana/prefixd-operations.json

# Import security dashboard
curl -X POST http://admin:admin@localhost:3001/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @grafana/prefixd-security.json
```

## Dashboards

### Operations Dashboard

**UID:** `prefixd-operations`

Monitor system health and performance:

| Panel | Description |
|-------|-------------|
| Active Mitigations | Current count with threshold colors |
| BGP Session | UP/DOWN status indicator |
| HTTP Request Rate | Requests per second |
| In-Flight Requests | Concurrent request count |
| Active Mitigations by POP | Time series breakdown |
| Mitigation Lifecycle | Created/expired/withdrawn rates |
| BGP Announcement Latency | p50/p95/p99 histogram |
| HTTP Request Latency | p50/p95/p99 histogram |
| HTTP Response Codes | 2xx/4xx/5xx breakdown |
| Reconciliation Runs | Success/failure rates |

### Security Dashboard

**UID:** `prefixd-security`

Monitor attack events and policy enforcement:

| Panel | Description |
|-------|-------------|
| Events (24h) | Total events ingested |
| Rejected Events (24h) | Events rejected by policy |
| Guardrail Rejections (24h) | Safety limit triggers |
| Escalations (24h) | Always zero; escalation is not implemented |
| Events by Source | Breakdown by detector |
| Events by Vector | Breakdown by attack type |
| Guardrail Rejections by Reason | TTL, quota, prefix, safelist |
| Event Rejections by Reason | Duplicate, rate limit, etc. |
| Escalations | Always zero; escalation is not implemented |
| System Events | Config reloads, DB errors |

## Prometheus Configuration

Add prefixd to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'prefixd'
    static_configs:
      - targets: ['prefixd:8080']
    metrics_path: /metrics
    scrape_interval: 15s
```

## Alert Rules

### Availability alerts

[`grafana/prometheus-alerts.yml`](../../grafana/prometheus-alerts.yml) ships
availability, [export](#export-alerts) and
[replacement-conflict](#replacement-conflict-alert) rules, loaded by the Compose
Prometheus through `rule_files` in
`grafana/prometheus.yml`. They expect the scrape job to be named `prefixd`.
TTL expiry, withdrawals and reconciliation need a running controller that
holds its POP's fence, so monitor it independently of BGP health:

| Alert | Fires when | Why it matters |
| --- | --- | --- |
| `PrefixdDown` | `up{job="prefixd"} == 0` for 2 minutes | Nothing expires or withdraws; announced routes stay on the speaker |
| `PrefixdNotReady` | Every scraped process reports `prefixd_controller_fence_active` 0 for 2 minutes | All controllers are in standby, so none mutates the speaker |
| `PrefixdBlackholesWhileDegraded` | No controller is up and active for 2 minutes, and `prefixd_mitigations_active{action_type="blackhole"}` was above zero when the last active controller was last seen (within 3 days, at 5-minute resolution) | Blackholes, including unleased detector blackholes, stay announced until prefixd returns or an operator withdraws them |

The blackhole gauge counts database state, not routes on the speaker. Route
these alerts to whoever can restart prefixd or withdraw a blackhole on the
speaker. Restarting prefixd expires overdue blackholes, and startup
reconciliation removes routes left behind by terminal rows. A blackhole
withdrawn by hand on the speaker must also be withdrawn in prefixd once it
returns, or reconciliation re-announces it until its TTL passes. Check the
rules and their unit tests with a pinned Prometheus image. `just alerts`, part
of `just gate` and CI, runs the same commands:

```bash
docker run --rm -v "$PWD/grafana:/rules:ro" --entrypoint promtool \
  prom/prometheus:v3.15.0 check rules /rules/prometheus-alerts.yml
docker run --rm -v "$PWD/grafana:/rules:ro" --entrypoint promtool \
  prom/prometheus:v3.15.0 test rules /rules/prometheus-alerts.test.yml
```

### Export alerts

The `prefixd-blackhole-export` group in the same file has one rule, for
rustbgpd deployments:

| Alert | Fires when | Why it matters |
| --- | --- | --- |
| `PrefixdBlackholeNotExported` | `prefixd_blackhole_unexported{reason}` is above zero for 5 minutes | An active blackhole is committed to no Established peer, so no router is sent it. The `reason` label says why; `export_policy` is a speaker export filter that denies the route. At rustbgpd 0.79.0 an RPKI-Invalid filter does not cause it, because prefixd's blackholes validate NotFound there; a downstream router's RPKI filter never shows here |

Health detail lists each such blackhole under `speaker.blackhole_exports`, and
its mitigation detail shows every peer. The rule detects missing export only:
a committed route is in a peer's Adj-RIB-Out, which does not prove the router
installed or enforces it. See
[export evidence](../reference/speaker-backends.md#export-evidence).

### Replacement conflict alert

The `prefixd-blackhole-conflicts` group reports an unleased admission that
replaced an untracked local route after its pre-read:

| Alert | Fires when | Why it matters |
| --- | --- | --- |
| `PrefixdBlackholeReplaced` | `prefixd_blackhole_replaced_total{pop}` is above zero, including its first observed sample | An unleased add replaced a route that appeared between the ownership pre-read and add; another writer may be using this speaker |

This is historical local-replacement evidence, not proof that a conflict
remains active or that a router enforced the route. The counter is local to
this process. The alert stays firing until it resets, normally on restart;
it does not clear merely because no more replacements occur. Inspect the
error log and `announce` audit entries for the affected prefix, check the
speaker's current routes and other writers, and use normal Alertmanager
triage or silencing. Do not restart just to clear this alert. Leased adds,
created or unchanged outcomes and failed adds do not increment the counter.

### Example rules

More example Prometheus alerting rules:

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
          summary: "BGP session down"
          description: "prefixd BGP session has been down for 1 minute"

      - alert: PrefixdHighMitigations
        expr: sum(prefixd_mitigations_active) > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High mitigation count"
          description: "{{ $value }} active mitigations for 5+ minutes"

      - alert: PrefixdHighErrorRate
        expr: sum(rate(prefixd_http_requests_total{status_class="5xx"}[5m])) > 1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High HTTP error rate"
          description: "{{ $value }} 5xx errors per second"

      - alert: PrefixdGuardrailRejections
        expr: sum(rate(prefixd_guardrail_rejections_total[5m])) > 0.1
        for: 5m
        labels:
          severity: info
        annotations:
          summary: "Guardrail rejections detected"
          description: "Policy violations being blocked"
```

## Customization

Dashboards use a `${datasource}` variable for flexibility. To modify:

1. Edit the JSON file
2. Adjust panel queries, thresholds, or layout
3. Re-import to Grafana

## Metrics Reference

See [FEATURES.md](../../FEATURES.md#prometheus-metrics) for the full list of available metrics.
