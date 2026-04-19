# Corroborating Signals Quickstart

This guide walks through adding a **corroborating-only telemetry
source** to prefixd — a source whose job is to strengthen ongoing signal
groups without ever being allowed to trigger a mitigation on its own.

Typical use cases:

- Router CPU / control-plane pressure alerts.
- Per-PoP interface utilization spikes.
- Per-customer NetFlow aggregate volumes.
- SNMP traps that don't carry a victim `/32`.

See [ADR 021](../adr/021-corroborating-signals.md) for the full design.

---

## 1. Declare the source

Edit `configs/correlation.yaml`:

```yaml
sources:
  # Your existing primary detectors stay as they are.
  fastnetmon:
    mode: primary     # default; can trigger mitigations
    weight: 1.0
    type: detector
    confidence_mapping: {}

  # New corroborating source.
  router-cpu:
    mode: corroborating     # strengthens, never triggers
    weight: 0.4             # lower than primaries
    type: telemetry
    confidence_mapping: {}
    match_dimensions:
      - pop            # Match any group whose primary events are in this PoP
      - customer_id    # Or any group for this customer
```

Apply the change:

```bash
curl -X PUT https://prefixd.example.com/v1/config/correlation \
     -H 'Authorization: Bearer $PREFIXD_API_TOKEN' \
     -H 'Content-Type: application/json' \
     -d '@configs/correlation.yaml'
```

The validator rejects:

- `mode: corroborating` with an empty `match_dimensions`.
- `mode: primary` (or omitted) with a non-empty `match_dimensions`.

---

## 2. Emit a signal

Corroborators POST to a different endpoint from primary events:

```bash
curl -X POST https://prefixd.example.com/v1/signals/corroborator \
     -H 'Authorization: Bearer $PREFIXD_API_TOKEN' \
     -H 'Content-Type: application/json' \
     -d '{
           "source": "router-cpu",
           "vector": "udp_flood",
           "pop": "iad1",
           "customer_id": "cust_42",
           "confidence": 0.6
         }'
```

Required: `source`. The signal must also populate at least one of the
source's declared `match_dimensions` (`pop` or `customer_id` here), or
the API returns `400`.

Response:

```json
{
  "signal_id": "…",
  "status": "attached",
  "attached_group_ids": ["…"],
  "cached": true
}
```

- `attached` — at least one open signal group matched and was
  strengthened.
- `cached` — no matching group yet; the signal is held for up to
  `correlation.window_seconds` and drained if a matching primary event
  arrives in that window.

## 3. From the CLI

```bash
prefixdctl send-corroborator \
  --source router-cpu \
  --pop iad1 \
  --customer-id cust_42 \
  --confidence 0.6 \
  --vector udp_flood
```

## 4. Writing a pusher

Minimal Python example (typical use case: a cron loop that scrapes an
SNMP/Prometheus source and forwards high-signal samples):

```python
import os, requests, datetime

API   = os.environ["PREFIXD_API"]
TOKEN = os.environ["PREFIXD_API_TOKEN"]

def post_cpu_alert(pop: str, utilization: float):
    if utilization < 0.85:
        return   # not alarming enough; skip
    payload = {
        "source":      "router-cpu",
        "pop":         pop,
        "confidence":  min(1.0, utilization),
    }
    r = requests.post(
        f"{API}/v1/signals/corroborator",
        json=payload,
        headers={"Authorization": f"Bearer {TOKEN}"},
        timeout=5,
    )
    r.raise_for_status()
    print(datetime.datetime.utcnow(), r.json())
```

## 5. Verify

- Dashboard ▸ Correlation ▸ Signals — shows incoming signals.
- Dashboard ▸ Correlation ▸ Groups ▸ *<group>* — contributing events
  now render with a `corroborating` badge when sourced from a
  corroborating signal.
- Metrics: `prefixd_corroborator_ingested_total{source="router-cpu"}`,
  `prefixd_corroborator_attached_total{source="router-cpu"}`,
  `prefixd_corroborator_expired_total{source="router-cpu"}`.

## 6. Invariants to remember

- **A group without a primary event will not mitigate.** Even if you
  send 10 corroborators and `min_sources=1`, the engine refuses to flip
  `corroboration_met=true` without at least one `/v1/events` post.
- **Declared dimensions are authoritative.** If a source declares
  `match_dimensions: [pop]`, a signal from that source that happens to
  carry a `customer_id` will *not* match groups on customer. Populate
  whatever you like; only declared dimensions are consulted. This keeps
  accidental cross-customer matches from leaking out of a source that
  should only match on PoP.
- **Dimensions match with OR semantics.** Across *declared* dimensions
  only: a source declaring `[pop, customer_id]` matches any group
  sharing its `pop` **or** its `customer_id`, not just both.
- **Vector is optional.** Omitting `vector` lets the signal corroborate
  groups for any attack type in the matching dimensions.
- **Per-source weight still governs derived confidence.** Set a
  conservative weight (e.g. 0.3–0.5) so a single corroborator can't
  single-handedly cross a threshold that should require a targeted
  primary event.

## 7. Known limits

See the ADR 021 "Known limits / deferred to PR B" section for the
authoritative list. Most operator-visible one right now:

- A corroborator that arrives *after* a primary event and pushes
  aggregates past the threshold does **not** immediately trigger the
  mitigation. Finalization happens on the next primary-ingest path. In
  practice this means: if two primary events fire inside the window,
  the corroborator's contribution is picked up. If only one primary
  fires and a corroborator arrives later, the mitigation waits on
  another primary signal (or on the cache drain when the next primary
  for the same dimensions lands). Tracked as PR B work item
  *Playbook-override-aware corroborator finalization*.

## Troubleshooting

| Symptom | Likely cause |
| ------- | ------------ |
| `400 source 'X' is not configured as mode=corroborating` | The source exists in `correlation.yaml` but with `mode=primary` (or no mode). |
| `400 source 'X' requires at least one of its declared match_dimensions` | None of the declared dimensions (`customer_id`/`pop`/`service_id`/`interface`) were populated on the request. |
| `status: cached` but never attaches | No primary event for a matching dimension lands inside `window_seconds`. This is expected when the telemetry fires ahead of the detector; the cache will drain if a primary event arrives in time. |

## See also

- [ADR 021 — Corroborating Signals](../adr/021-corroborating-signals.md)
- [ADR 018 — Multi-Signal Correlation Engine](../adr/018-multi-signal-correlation-engine.md)
- `docs/api.md#corroborator-signal` — full API reference.
- `docs/configuration.md` — `sources`/`mode`/`match_dimensions` schema.
