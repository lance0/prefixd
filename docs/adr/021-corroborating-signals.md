# ADR 021: Corroborating Signals

**Status:** Accepted
**Date:** 2026-04-19
**Supersedes/Extends:** [ADR 018 — Multi-Signal Correlation Engine](018-multi-signal-correlation-engine.md)

## Context

The correlation engine introduced in ADR 018 operates on `AttackEvent`s
keyed by `(victim_ip, vector)`. Each event carries:

- A victim IP (the destination being mitigated).
- A vector (`udp_flood`, `syn_flood`, …).
- A source name used to look up weight + confidence mapping.

Every ingested event has **equal standing**: it can create a signal group
and, if the group reaches `min_sources` / `confidence_threshold`, the event
triggers a mitigation via the normal playbook flow.

This works well when every detector can identify the victim IP (e.g.
Alertmanager firing on a per-host metric, FastNetMon emitting attacker
→ victim flows). It breaks down when operators want to add
**coarser-grained telemetry** that *corroborates* an ongoing incident but
doesn't on its own name a victim:

- Router interface utilization spike on the PoP's upstream link.
- Per-customer BGP ECMP load imbalance.
- PoP-level CPU / session pressure.
- NetFlow aggregate for a service (not an IP).

These sources are strong evidence when combined with a targeted detector
but are dangerous as primary triggers — they don't carry a `/32` to act
on, and they can fire on totally benign events (a backup job, a capacity
test).

Operators today work around this by dropping those signals entirely or
by writing brittle "shim" detectors that guess a victim IP. Neither is
acceptable for production.

## Decision

Introduce a second class of correlation signals, **corroborating
signals**, alongside the existing primary events. The two classes are
distinguished by a `mode` field on each entry in `correlation.yaml`'s
`sources` map:

```yaml
sources:
  fastnetmon:
    mode: primary       # default; can trigger mitigations
    weight: 1.0
    type: detector
  router-cpu:
    mode: corroborating # strengthens groups but never fires alone
    weight: 0.5
    type: telemetry
    match_dimensions: [pop, customer_id]
```

### Configuration schema

- `mode`: `primary` (default) or `corroborating`.
- `match_dimensions`: list drawn from
  `{customer_id, pop, service_id, interface}`. Must be non-empty when
  `mode=corroborating`, must be empty when `mode=primary`. Validated
  server-side on `PUT /v1/config/correlation`.

### New endpoint

`POST /v1/signals/corroborator` (authenticated) accepts:

```json
{
  "source": "router-cpu",
  "vector": "udp_flood",         // optional narrower
  "customer_id": "cust_42",
  "pop": "iad1",
  "service_id": "svc_web",       // optional
  "interface": "et-0/0/12",      // optional
  "confidence": 0.6              // optional
}
```

The handler:

1. Verifies the source is configured with `mode=corroborating`.
2. Verifies at least one of the source's declared `match_dimensions`
   is populated on the signal (so an operator can't
   accidentally attach to everything).
3. Searches open signal groups whose `primary_dimensions` (aggregated
   over the group's primary events) overlap with the signal's populated
   dimensions, filtered by `vector` if supplied.
4. Attaches to each matching group (denormalizing `source`/`confidence`
   into the junction row so the UI can render it without a second join).
5. Caches the signal in `corroborating_signals` with a TTL equal to
   `correlation.window_seconds`. Late-arriving primary events drain this
   cache on ingest, so the *order* of arrival doesn't matter inside the
   window.

### Cache sweep

The reconciliation loop calls
`delete_expired_corroborating_signals(now)` on each cycle and increments
`prefixd_corroborator_expired_total` per row removed.

### Invariant: corroborators alone cannot mitigate

Even if `min_sources=1` and a single corroborating signal lands, the
engine uses `check_corroboration_with_primary(source_count, confidence,
has_primary_event, …)` which requires at least one `is_corroborating=
false` row in `signal_group_events` before `corroboration_met` can flip
true. This is the guard that makes corroborators safe to add to a live
deployment.

## Consequences

### Positive

- Operators can onboard PoP- and customer-level telemetry without risking
  spurious `/32` drops.
- Coarse signals can still **escalate confidence** and help cross the
  `confidence_threshold` faster, shortening time-to-mitigate.
- The decision to "use primary or corroborating" is purely a config
  change; no source code edits needed when adding a new telemetry pipe.
- The invariant is enforced at the engine level, not just at the UI, so
  it holds even when operators override thresholds per-playbook.

### Negative

- Two DB changes: a JSONB column on `signal_groups` and a new cache
  table. Migration 009 handles both, with `IF NOT EXISTS` guards.
- Matching is OR-across-dimensions; this is intentionally permissive so
  routers emitting "something bad in iad1" can attach to any matching
  group in that PoP. Operators who want stricter matching can narrow via
  `vector`.
- The cache can grow unbounded in theory. Mitigated by the reconcile
  sweep + the `expires_at` index.

### Neutral

- The alternate design — making primaries optional by introducing
  "lightweight" signal groups keyed on dimensions — was rejected because
  it invites mitigations for groups without a concrete `/32`.

## Alternatives considered

1. **Carry an optional `victim_ip` on corroborators, skip when absent.**
   Rejected: exposes a footgun. Operators would pass a router loopback
   or a customer gateway as victim_ip and mitigate it.
2. **Separate `corroboration_engine` process.** Rejected: doubles the
   deployment surface for a feature that's fundamentally an event-flow
   branch, not a new system.
3. **Dimension matching = AND across populated fields.** Rejected: too
   strict for the real use cases (router-cpu only knows `pop`; netflow
   only knows `customer_id`).

## Rollout

- Feature-flag-free. Existing configs default every source to
  `mode=primary` and behave exactly as in v0.15.0.
- Operators opt into corroborating signals by setting `mode:
  corroborating` on a source and pointing the detector at
  `/v1/signals/corroborator`.
- Metrics (`prefixd_corroborator_ingested_total`, `_attached_total`,
  `_expired_total`) surface cache health for SRE dashboards.

## References

- `migrations/009_corroborating_signals.sql`
- `src/correlation/engine.rs` — `CorroboratingSignal`, `EventDimensions`,
  `check_corroboration_with_primary`, `corroborator_matches`.
- `src/api/handlers.rs` — `ingest_corroborator`, cache drain in event
  ingest.
- `src/scheduler/reconcile.rs` — `sweep_corroborator_cache`.
- ADR 018 — the underlying correlation engine this builds on.
