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
three rules, loaded by the Compose Prometheus through `rule_files` in
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
speaker. Check the rules and their unit tests with a pinned Prometheus image:

```bash
docker run --rm -v "$PWD/grafana:/rules:ro" --entrypoint promtool \
  prom/prometheus:v3.15.0 check rules /rules/prometheus-alerts.yml
docker run --rm -v "$PWD/grafana:/rules:ro" --entrypoint promtool \
  prom/prometheus:v3.15.0 test rules /rules/prometheus-alerts.test.yml
```

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
