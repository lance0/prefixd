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
# export PREFIXD_WEBHOOK_RADWARE_SECRET="<paste>"
```

The secret must be present at prefixd startup; it is read from the environment, **not** from YAML. The API will never return it. The variable must start with `PREFIXD_WEBHOOK_` and hold at least 32 bytes; startup, reload and the correlation editor refuse anything else, so a configuration change cannot point an adapter at a guessable variable such as `PATH`.

### 2. Add the adapter to the correlation config

Put correlation configuration in the controller's `correlation.yaml` with
top-level keys. Do not wrap it in `correlation:`. The inline section in
`prefixd.yaml` is only a fallback for installations without a standalone file;
Compose always seeds `correlation.yaml` into `prefixd-config`, so an inline
adapter is never read there.

**Standalone `configs/correlation.yaml`:**

```yaml
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
      secret_env: PREFIXD_WEBHOOK_RADWARE_SECRET
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
      top_src_ports: "$.reflectors.ports"
      action: "$.action"
    vector_map:
      UDP_FLOOD: udp_flood
      SYN_FLOOD: syn_flood
      DNS_AMP: udp_amplification
      NTP_AMP: udp_amplification
    default_vector: unknown
    confidence_scale: 100
    source_id_prefix: "radware-"
```

In Compose the live file is `/etc/prefixd/correlation.yaml` in the
`prefixd-config` volume; editing `configs/correlation.yaml` in the checkout has
no effect. Apply the change with **Config → Correlation** in the dashboard, or
send the complete configuration as JSON:

```bash
printf 'header = "Authorization: Bearer %s"\n' "$PREFIXD_TOKEN" |
curl -K - -X PUT http://prefixd.example.com/v1/config/correlation \
  -H 'Content-Type: application/json' \
  --data-binary @correlation.json
```

The route needs an Admin session or an admin API token in `PREFIXD_TOKEN`.

No restart is required, and the request replaces the whole file rather than
merging with it. If you edit the file in the volume directly,
`POST /v1/config/reload` re-reads it.

### 3. Configure Radware to POST

Point Radware at:

```
POST https://prefixd.example.com/v1/signals/webhook/radware
Content-Type: application/json
X-Signature-SHA256: <hex HMAC-SHA256 of the raw body, computed with PREFIXD_WEBHOOK_RADWARE_SECRET>
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
    },
    {
      "id": "alert-12346",
      "time": "2026-04-18T19:24:00Z",
      "alert_type": "NTP_AMP",
      "target": { "ip": "203.0.113.11" },
      "traffic": { "bps": 9600000000, "pps": 2500000 },
      "reflectors": { "ports": [123] },
      "score": 92,
      "action": "ban"
    }
  ]
}
```

prefixd resolves the mapping in order:

1. **`root_path: "$.alerts[*]"`** iterates the array, producing one `AttackEventInput` per alert.
2. **`fields.victim_ip: "$.target.ip"`** extracts the victim IP (relative to each alert node).
3. **`vector_map`** translates `UDP_FLOOD` → `udp_flood` and `NTP_AMP` → `udp_amplification` (falls back to `default_vector: unknown` if missing). Vector names must be ones prefixd accepts; an unknown name such as `ntp_amp` falls back to `default_vector`.
4. **`fields.top_src_ports`** copies the reflector source ports (`[123]`) into the second event's `top_src_ports`. prefixd keeps only ports in its [reflector-port library](../../reference/configuration.md#amplification), and handles the event as `udp_flood` when none remain or no `udp_amplification` playbook exists. The default library includes 53, so a source-port rule containing it also drops the victim's replies from external DNS resolvers. The field is read on bans only, and anything other than an array of ports 0–65535 is a per-event error.
5. **`confidence_scale: 100`** divides the extracted `score` (87) to produce `0.87`.
6. **`source_id_prefix`** prepends `radware-` to `alert-12345` for the event ID.

The adapter then calls the standard `handle_ban` path, which runs guardrails, correlation, and FlowSpec announcement exactly as if the event had come from the native API.

### 4. Verify

Tail the logs and look for `ingest_webhook` entries:

```bash
docker compose logs -f prefixd-rustbgpd | grep webhook
```

Check the dashboard → Correlation → Signals tab. Events should appear with `source: radware`. If you've configured correlation weights, the adapter contributes at weight 1.2 per the `sources.radware` entry.

## Schema reference

See [configuration.md § Generic Webhook Adapters](../../reference/configuration.md#generic-webhook-adapters) for the complete field reference.

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

- **The credential binds the source.** Every event an adapter maps is stored under the adapter's name as its `source`, so the blackhole and prefix allowlists, correlation weights and `min_sources` read a source the credential proves ([ADR 034](../../adr/034-source-bound-api-tokens.md)). With `auth.type: hmac` the verified signature is the credential, `Authorization` is ignored, and audit rows name `webhook:<adapter>`. With `auth.type: bearer` the sender needs an ingest token bound to the adapter's name (`prefixdctl tokens create --scope ingest --source radware ...`); a token bound to another source, or an operator token, gets 403, and audit rows name `token:<name>`.
- **HMAC is the default.** Bearer is offered for senders that cannot sign. HMAC carries no timestamp or nonce, so an adapter named in `blackhole.detector_sources` or `guardrails.detector_prefix_sources` must map `fields.source_id`: a replayed signed ban then reuses its event ID and gets 409 instead of recreating the mitigation.
- **Constant-time comparison.** Signature verification uses `subtle::ConstantTimeEq` to prevent timing oracles.
- **Secrets never leave the environment.** The YAML carries the env-var name, not the value. `GET /v1/config/correlation` returns the env-var name only.
- **Path validation.** The adapter name is validated against `[a-z0-9-]{1,64}` on every request, so path traversal and injection are not possible via the URL.
- **Names are sources.** The adapter name must match `^[a-z0-9][a-z0-9-]{0,63}$`, so a token can be bound to it.
- **Unbans report their outcome.** An unban result is `withdrawn` or `no_active_mitigation`. One that failed on the controller's side is an `error` counted in `failed`, and the response is `503` so the sender resends; the withdrawal intent is pending, and a resend reuses it.
- **No unauthenticated adapters.** `auth.type: none` would let anyone who reaches the controller claim the adapter's source, so it is refused unless `http.auth.mode` is `none`.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| HTTP 404 | Adapter name mismatch, or `enabled: false` |
| HTTP 401 with `"missing HMAC signature header"` | Sender didn't include the signature header named in `auth.header` |
| HTTP 403 with `"is not bound to this credential"` | A bearer adapter's token is bound to another source, or is an operator token; mint an ingest token bound to the adapter name |
| HTTP 401 with `"HMAC signature verification failed"` | Shared secret differs between sender and `PREFIXD_WEBHOOK_RADWARE_SECRET`, or the sender hashed a different byte range (e.g. after `Content-Encoding: gzip`) — ensure HMAC is computed over the raw request body prefixd receives |
| HTTP 400 with `"invalid JSON"` | Payload isn't valid JSON at all |
| HTTP 400 with `"no events extracted from payload"` | `root_path` matched zero nodes — verify the expression against a real payload |
| HTTP 200 with per-event `results[].status="error"` and `"required field 'victim_ip' missing from payload"` | JSONPath for `victim_ip` didn't match; verify with `jq` locally |
| HTTP 200 with per-event `results[].status="error"` and `"invalid IP address"` | `victim_ip` extracted but didn't parse as an IP — check for port suffixes or extra whitespace |
| HTTP 200 with per-event `results[].status="error"` and `"invalid value for field 'action'"` | Payload contained an `action` field with something other than `"ban"` or `"unban"` |
| Events appear but `vector: unknown` | Raw vector string isn't in `vector_map`; add it, or accept `default_vector` |
| HTTP 200 with per-event `results[].status="error"` and `"field 'top_src_ports' has wrong type"` | The `top_src_ports` JSONPath matched something other than an array of integers 0–65535 |
| Confidence always 1.0 | `confidence_scale` missing or mis-set; detectors that emit 0–100 need `confidence_scale: 100` |

Mapping failures never fail the whole batch — they produce per-event `status: "error"` entries with the error message inline, and the overall HTTP status stays `200` so the sender doesn't retry valid events in the same payload.

## Promoting to a native adapter

If a generic-adapter integration becomes critical and you need source-specific semantics (stateful unban logic, non-JSON payloads, per-detector validation), consider writing a native adapter — see ADR 019 for the architecture and `src/correlation/fastnetmon.rs` for a reference implementation.
