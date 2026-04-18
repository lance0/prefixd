# Generic Webhook Adapter

The generic webhook adapter lets you integrate any detector or telemetry system that can POST JSON, without writing Rust code. You declare one or more named adapters in `correlation.yaml`, and each becomes a fully-authenticated endpoint at `POST /v1/signals/webhook/{name}` that feeds events into the standard correlation and mitigation pipeline.

> For integrations that prefixd ships natively — Alertmanager, FastNetMon — use the dedicated endpoints (`/v1/signals/alertmanager`, `/v1/signals/fastnetmon`). The generic adapter is for everything else.

## When to use it

- Commercial DDoS appliances (Radware DefensePro, NETSCOUT Arbor, A10 Thunder)
- Cloud alerting (GCP Cloud Armor, AWS Shield Advanced events, Cloudflare)
- Internal abuse / anomaly-detection platforms that emit JSON webhooks
- Quick prototyping of new signal sources before deciding whether they warrant a native adapter

See ADR 020 for design rationale.

## End-to-end example: Radware DefensePro

This walkthrough integrates a hypothetical Radware DefensePro alert stream. Radware posts signed JSON with an HMAC-SHA256 signature in the `X-Signature-SHA256` header.

### 1. Create the shared secret

Generate a random HMAC key, store it wherever you already store prefixd secrets (Docker Compose env file, Kubernetes `Secret`, systemd `EnvironmentFile`, etc.), and export it as the environment variable you'll reference from `correlation.yaml`:

```bash
openssl rand -hex 32   # 64-character hex string
# export RADWARE_WEBHOOK_SECRET="<paste>"
```

The secret must be present at prefixd startup; it is read from the environment, **not** from YAML. The API will never return it.

### 2. Add the adapter to `correlation.yaml`

```yaml
correlation:
  enabled: true
  # … your existing correlation settings …

  sources:
    radware:
      weight: 1.2
      type: detector

  webhook_adapters:
    - name: radware
      description: "Radware DefensePro alert stream"
      enabled: true
      auth:
        type: hmac
        secret_env: RADWARE_WEBHOOK_SECRET
        header: X-Signature-SHA256
        algorithm: sha256
      root_path: "$.alerts[*]"
      fields:
        victim_ip: "$.target.ip"
        vector: "$.alert_type"
        timestamp: "$.time"
        bps: "$.traffic.bps"
        pps: "$.traffic.pps"
        confidence: "$.score"
        source_id: "$.id"
        top_dst_ports: "$.ports"
        action: "$.action"
      vector_map:
        UDP_FLOOD: udp_flood
        SYN_FLOOD: syn_flood
        DNS_AMP: dns_amp
        NTP_AMP: ntp_amp
      default_vector: unknown
      confidence_scale: 100
      source_id_prefix: "radware-"
```

Reload the config (no restart required):

```bash
curl -X POST -H "Authorization: Bearer $PREFIXD_API_TOKEN" http://prefixd.example.com/v1/config/reload
```

### 3. Configure Radware to POST

Point Radware at:

```
POST https://prefixd.example.com/v1/signals/webhook/radware
Content-Type: application/json
X-Signature-SHA256: <hex HMAC-SHA256 of the raw body, computed with RADWARE_WEBHOOK_SECRET>
```

A sample payload, after Radware-side HMAC:

```json
{
  "alerts": [
    {
      "id": "alert-12345",
      "time": "2026-04-18T19:23:00Z",
      "alert_type": "UDP_FLOOD",
      "target": { "ip": "203.0.113.10" },
      "traffic": { "bps": 1800000000, "pps": 1200000 },
      "ports": [53, 123],
      "score": 87,
      "action": "ban"
    }
  ]
}
```

prefixd resolves the mapping in order:

1. **`root_path: "$.alerts[*]"`** iterates the array, producing one `AttackEventInput` per alert.
2. **`fields.victim_ip: "$.target.ip"`** extracts the victim IP (relative to each alert node).
3. **`vector_map`** translates `UDP_FLOOD` → `udp_flood` (falls back to `default_vector: unknown` if missing).
4. **`confidence_scale: 100`** divides the extracted `score` (87) to produce `0.87`.
5. **`source_id_prefix`** prepends `radware-` to `alert-12345` for the event ID.

The adapter then calls the standard `handle_ban` path, which runs guardrails, correlation, and FlowSpec announcement exactly as if the event had come from the native API.

### 4. Verify

Tail the logs and look for `ingest_webhook` entries:

```bash
docker compose logs -f prefixd | grep webhook
```

Check the dashboard → Correlation → Signals tab. Events should appear with `source: radware`. If you've configured correlation weights, the adapter contributes at weight 1.2 per the `sources.radware` entry.

## Schema reference

See [configuration.md § Generic Webhook Adapters](../configuration.md#generic-webhook-adapters) for the complete field reference.

## JSONPath cheat sheet

The adapter uses RFC 9535 JSONPath (`serde_json_path`):

| Expression | Meaning |
|---|---|
| `$.field` | Root-level field |
| `$.a.b.c` | Nested field |
| `$.items[0]` | Array index |
| `$.items[*]` | Array iteration (use as `root_path`) |
| `$.items[?(@.severity=="critical")]` | Filter expression |
| `$.value \|\| 0` | ⚠️ Not supported — no fallback operator. Use `default_vector` / omit the field instead. |

## Security

- **HMAC is the default.** Bearer and none modes are offered for existing infrastructure where HMAC isn't available, but HMAC is strongly preferred for internet-reachable endpoints.
- **Constant-time comparison.** Signature verification uses `subtle::ConstantTimeEq` to prevent timing oracles.
- **Secrets never leave the environment.** The YAML carries the env-var name, not the value. `GET /v1/config/correlation` returns the env-var name only.
- **Path validation.** The adapter name is validated against `[a-z0-9-]{1,64}` on every request, so path traversal and injection are not possible via the URL.
- **Lab-only mode.** `auth.type: none` is allowed for lab setups but emits a warning at config-load time.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| HTTP 404 | Adapter name mismatch, or `enabled: false` |
| HTTP 401 with `"signature mismatch"` | Shared secret differs between sender and `RADWARE_WEBHOOK_SECRET`, or the sender hashed a different byte range (e.g. after `Content-Encoding: gzip`) — ensure HMAC is computed over the raw request body prefixd receives |
| HTTP 400 with `"victim_ip not found"` | JSONPath didn't match; verify with `jq` locally against a real payload |
| Events appear but `vector: unknown` | Raw vector string isn't in `vector_map`; add it, or accept `default_vector` |
| Confidence always 1.0 | `confidence_scale` missing or mis-set; detectors that emit 0–100 need `confidence_scale: 100` |

## Promoting to a native adapter

If a generic-adapter integration becomes critical and you need source-specific semantics (stateful unban logic, non-JSON payloads, per-detector validation), consider writing a native adapter — see ADR 019 for the architecture and `src/correlation/fastnetmon.rs` for a reference implementation.
