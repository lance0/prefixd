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
8. **Expiry metric simplified and narrowed to true cache misses.**
   `prefixd_corroborator_expired_total` was labelled by source but only
   ever emitted `source="unknown"`. It's now an unlabelled counter. The
   sweep path also no longer inflates it with attached rows: the
   repository now splits the delete into `(unattached_expired,
   attached_expired)` and the scheduler only increments the counter by
   the first. Attached rows are still cleaned from the cache for GC,
   but their deletion is bookkeeping rather than a cache miss.
   Per-source attribution is still deferred to PR B.
9. **Pre-upgrade open groups are matchable immediately.** Migration
   009 defaulted `signal_groups.primary_dimensions` to `{}`, which
   meant groups that existed before the upgrade could never be matched
   by corroborators until another primary event happened to populate
   them. Migration 011 backfills dimensions best-effort from each
   group's existing mitigations (`customer_id`, `pop`, `service_id`
   are denormalized there). Interface is left empty pre-upgrade since
   it's a brand-new inventory field.
10. **Signal Sources dashboard reflects corroborator traffic.**
    `getSignalSources()` on the frontend combined correlation config
    with the `/v1/events` stream, which meant `mode: corroborating`
    sources always rendered as `last_seen: null` / unhealthy even while
    actively posting. A new backend endpoint
    `GET /v1/signals/corroborator/activity?minutes=N` aggregates per-
    source activity across the live cache and attached
    `signal_group_events` rows, and the frontend merges that result in.

## Known limits / deferred to PR B

(All five PR B items shipped in v0.17.0 — see CHANGELOG and the
"PR B addenda" section below for design notes on each.)

## PR B addenda (v0.17.0)

- **Late corroborator finalization is now playbook-aware.** Migration
  `012_signal_groups_playbook.sql` adds nullable
  `signal_groups.playbook_name`. The daemon writes it on group create
  and `COALESCE`-backfills it on the next primary event for any
  pre-upgrade group. The corroborator-side aggregate recompute
  re-resolves the playbook by name from live state; if the playbook
  exists, it applies the override min_sources/threshold and is now
  allowed to flip `corroboration_met` from false → true. If the stored
  name is NULL or no longer resolves (admin removed the playbook), the
  conservative v0.16.0 behavior is preserved: aggregates update but the
  flag is not flipped — the next primary event picks it up. This
  decouples late corroborator finalization from "another primary event
  must fire within the window" without weakening the
  primary-required-once invariant.

  Mitigation actuation deliberately stays single-sourced through
  `handle_ban`; corroborator-path recompute updates state but does not
  fire FlowSpec. The next primary event reads the now-true flag and
  triggers normally. This keeps the actuation surface narrow and
  preserves the existing test/audit surface for mitigations.

- **Per-source attribution on the expired counter.**
  `delete_expired_corroborating_signals` now uses a single
  `DELETE … RETURNING source` with `GROUP BY source` so attribution is
  collected in the same query that performs the delete (no
  read-then-delete race). `CORROBORATOR_EXPIRED_TOTAL` regains its
  `&["source"]` label set. Operator note: this is a label change.
  PromQL queries written against the v0.16.0 unlabelled counter must
  add `sum()` to recover the previous shape.

- **`prefixd_corroborator_cache_size{source}` gauge.** Updated by the
  reconcile loop after each sweep using the new
  `count_cached_corroborators_by_source(now)` repository method. The
  scheduler keeps an in-process `last_cache_sources` set so labels
  whose source drained between ticks are explicitly zeroed (Prometheus
  would otherwise keep stale non-zero values forever).

- **`/v1/signals/corroborator/cache` admin endpoint.** Returns
  `{ now, total, by_source[], signals[] }` filtered to
  unattached + unexpired rows. Optional `?source=` and `?limit=`
  (clamped to 1..1000). Dashboard-side, the new Cache tab on the
  Correlation page renders per-source badges and a dense table of
  cached signals.

- **`CorroboratorResponse.cached` removed.** Always-true booleans add
  no information. `status ∈ {attached, cached}` is the canonical
  discriminator. v0.17.0 minor breaking change since the endpoint is
  new in this release line.

## References

- `migrations/009_corroborating_signals.sql`,
  `migrations/010_corroborator_ingested_at.sql`,
  `migrations/011_backfill_primary_dimensions.sql`
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
