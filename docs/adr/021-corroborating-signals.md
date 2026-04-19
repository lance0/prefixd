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

## Review remediations (merged into the shipping revision)

The first review pass surfaced several bugs between the design and the
initial implementation. All were fixed before merge. Notable ones:

1. **Primary-event rejection moved to handler entry.** The check for
   `mode=corroborating` sources posting to `/v1/events` originally lived
   inside `handle_ban`, leaving `unban` and the validation path able to
   persist state before rejection. It now fires in `ingest_event` before
   any branching or DB writes.
2. **Declared dimensions are authoritative.** Matching originally only
   checked that a signal had *some* populated dimension, then fell
   through to compare all four against the group. A source declared for
   `[pop]` could therefore attach via an undeclared `customer_id`. Both
   the ingest path and the cache-drain path now filter strictly against
   the source's declared `match_dimensions` via
   `corroborator_matches_declared`.
3. **Interface dimension is wired end-to-end.** `Asset.interface` was
   added to inventory and is now carried through `IpContext` into
   `primary_dimensions` on primary ingest. Interface-only corroborators
   can now actually match.
4. **Config validation on load.** `CorrelationConfig::load` and
   `Settings::load` now run `validate()` on YAML parsing. A
   misconfigured `mode=corroborating` source can no longer boot the
   daemon; `PUT /v1/config/correlation` already enforced this.
5. **Corroborator rows carry their own timestamp.** Migration 010 adds
   `signal_group_events.corroborator_ingested_at`; the
   `list_signal_group_events` query is fully `CASE`-split on
   `is_corroborating` so the frontend never sees a `null` ingest time
   for a corroborator row masquerading as a missing event. Frontend
   `SignalGroupEvent.ingested_at` is typed `string | null` defensively.
6. **Cached-corroborator counting matches trait docs.** Both Postgres
   and Mock implementations now return only unattached, unexpired rows.
7. **`recompute_group_aggregates` no longer flips
   `corroboration_met=true` alone.** Only the primary-ingest path has
   the resolved playbook override and is allowed to promote the flag.
   Corroborator ingest still updates `derived_confidence` and
   `source_count`.
8. **Expiry metric simplified.** `prefixd_corroborator_expired_total`
   was labelled by source but only ever emitted `source="unknown"`. It's
   now an unlabelled counter incremented by sweep count. Per-source
   attribution is tracked as a follow-up (PR B).

## Known limits / deferred to PR B

- A corroborator that lands late in the window and pushes a group over
  its threshold does not immediately fire the mitigation; it waits for
  the next primary-path event (if any) to re-evaluate. This is a
  product choice, not a correctness gap — implementing playbook-
  override-aware finalization on the corroborator path is scheduled for
  PR B (see ROADMAP).
- `prefixd_corroborator_expired_total` has no source label. PR B will
  restore per-source attribution by collecting rows before delete.
- `CorroboratorResponse.cached` is always `true`; the field is
  redundant given `status ∈ {attached, cached}` and is flagged for
  removal in PR B.

## References

- `migrations/009_corroborating_signals.sql`,
  `migrations/010_corroborator_ingested_at.sql`
- `src/correlation/engine.rs` — `CorroboratingSignal`,
  `EventDimensions`, `PrimaryDimensions`,
  `check_corroboration_with_primary`, `corroborator_matches_declared`.
- `src/api/handlers.rs` — `ingest_event` early-rejection,
  `ingest_corroborator`, declared-dimension filter, cache drain.
- `src/config/inventory.rs` — `Asset.interface`, `IpContext.interface`.
- `src/config/settings.rs` — boot-time validation.
- `src/scheduler/reconcile.rs` — `sweep_corroborator_cache`.
- `src/observability/metrics.rs` — corroborator metrics.
- ADR 018 — the underlying correlation engine this builds on.
