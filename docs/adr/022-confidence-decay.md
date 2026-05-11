# ADR 022: Confidence Decay for Signal Groups

**Status:** Accepted
**Date:** 2026-05-11
**Extends:** [ADR 018 — Multi-Signal Correlation Engine](018-multi-signal-correlation-engine.md), [ADR 021 — Corroborating Signals](021-corroborating-signals.md)

## Context

The correlation engine (ADR 018) computes a signal group's
`derived_confidence` as the source-weighted average of per-event
confidence values:

```
derived = Σ(confidence_i · weight_i) / Σ(weight_i)
```

Once a group's `derived_confidence` clears the configured
`confidence_threshold` and `min_sources` is satisfied,
`corroboration_met` is flipped to `true` and the group is allowed to
trigger mitigations (or, in the ADR 021 corroborating-only flow,
strengthen open groups).

This works well during an active attack — fresh telemetry keeps arriving
and the weighted average reflects current reality. It is less honest
once an incident winds down:

1. **Long correlation windows hold stale evidence.** Operators routinely
   configure `window_seconds: 3600` to absorb burst-and-recover patterns.
   A high-confidence event ingested 50 minutes ago still contributes to
   the average at full weight, even though everything since has been
   benign.
2. **Corroborating sources from ADR 021 amplify the problem.** A
   `mode: corroborating` source that fired hours ago continues to inflate
   `derived_confidence` long after its operational signal has gone
   silent.
3. **Operators cannot express "fresh evidence matters more"** without
   abandoning windowed correlation entirely.

The result: groups whose underlying attack has already abated continue
to read as "highly corroborated" for the remainder of the window. Any
ADR-021 corroborator that fires in that window — even on totally
unrelated telemetry — sees a green light from the cached confidence and
nudges the group toward (re-)mitigation.

A naive fix ("drop events older than X seconds from the average") loses
useful history and produces step-function discontinuities in the score.

## Decision

Introduce **exponential confidence decay** on the
weighted-average computation. Each event's contribution is multiplied by
`0.5 ^ (age_seconds / half_life_seconds)` before being summed, so older
events smoothly lose weight without ever being discarded outright:

```
weight_eff_i = weight_i · 0.5 ^ (age_i / H)
derived = Σ(confidence_i · weight_eff_i) / Σ(weight_eff_i)
```

Where:

- `age_i = now - ingested_at_i` (clamped to ≥ 0)
- `H = effective_decay_half_life_seconds` (resolved per-playbook, see below)
- `H = 0` disables decay (default; preserves ADR 018 behavior)

### Configuration

A new global field on `CorrelationConfig`:

```yaml
correlation:
  enabled: true
  window_seconds: 3600
  min_sources: 2
  confidence_threshold: 0.7
  confidence_decay_half_life_seconds: 300  # 5-minute half-life
```

Per-playbook override on `PlaybookCorrelationOverride`:

```yaml
playbooks:
  - vector: udp_flood
    correlation_override:
      confidence_decay_half_life_seconds: 60   # faster decay for noisy vector
  - vector: dns_amplification
    correlation_override:
      confidence_decay_half_life_seconds: 0    # explicitly disable for this playbook
```

Override resolution (`effective_decay_half_life()`):

- `Some(0)` ⇒ decay explicitly disabled for this playbook
- `Some(n)` ⇒ use `n`
- `None` ⇒ fall through to global `confidence_decay_half_life_seconds`

Validation: `0 ≤ H ≤ 10 × window_seconds`. The upper bound prevents
configuration mistakes where a half-life longer than the correlation
window would render decay effectively a no-op.

### Compute Paths

Two recompute paths use the decayed variant:

1. **`POST /v1/events` ingestion.** Every event that lands in an open
   group recomputes `derived_confidence` with decay applied.
2. **Reconcile loop (every tick, 30 s).** A new
   `refresh_decayed_confidence` step iterates every open signal group
   (`list_open_signal_groups`) and recomputes `derived_confidence` from
   the current event set. This is what actually delivers the decay to
   groups that aren't receiving fresh events.

The reconcile step is a no-op when `confidence_decay_half_life_seconds`
is 0 (so users not opting in pay no extra DB cost).

### One-Shot Corroboration (Sticky `corroboration_met`)

When `derived_confidence` falls below `confidence_threshold` due to
decay, `corroboration_met` **must not** flap back to `false`. The flag
is sticky once set:

```rust
corroboration_met = met_now || was_met
```

This preserves the operational invariant that "once mitigation was
authorized for this group, it stays authorized for the lifetime of the
group" — decay only shapes future authorizations on *other* groups,
never revokes one already granted.

### Observability

- **Metric:** `prefixd_signal_group_decay_refreshes_total` counter,
  ticks once per `refresh_decayed_confidence` invocation (whether or not
  any groups were refreshed). Lets operators alert on "decay loop not
  running".
- **UI:** The group detail page surfaces "decayed, half-life Ns" next to
  the `derived_confidence` value when decay is active for the group's
  effective playbook, so operators can interpret the score correctly.

## Consequences

### Positive

- Stale corroboration evidence loses weight smoothly without
  discontinuities.
- ADR-021 corroborating sources from earlier in the window no longer
  hold groups at artificially high confidence.
- Per-playbook tuning lets operators dial decay speed per vector (e.g.
  faster decay for noisy UDP floods, slower for slow-and-low credential
  stuffing).
- Sticky `corroboration_met` prevents flap-back of authorized
  mitigations even under aggressive decay configs.
- Defaults to disabled (`H = 0`) — zero behavior change for existing
  deployments.

### Negative

- Reconcile loop now does O(open_groups · events_per_group) DB reads
  per tick when decay is enabled. For typical deployments (< 100 open
  groups, < 10 events each) this is negligible, but pathological
  configurations would notice.
- `derived_confidence` is no longer a pure function of "events on the
  group" — it now also depends on wall-clock time. This complicates
  reproducing a group's score offline; the trade-off is acceptable
  given the operational gain.
- Decay does not change `source_count` (still a raw distinct-source
  count). Operators relying on `source_count` for thresholding will not
  see decay affect their gate; only `confidence_threshold` benefits.

### Single-Event Math Note

For a group with exactly one event, `derived_confidence` is unaffected
by decay (the decay factor cancels in `Σ(c·w_eff) / Σ(w_eff)`). Decay
only meaningfully shifts the score when a group has events at different
ages. This is mathematically correct and matches operator intuition:
"one piece of evidence is one piece of evidence, regardless of how old".

## Alternatives Considered

1. **Hard cutoff (drop events older than X).** Rejected: step-function
   discontinuities in score, and loses useful history for slow-attack
   detection.
2. **Linear decay.** Considered. Rejected in favor of exponential
   because half-life is the unit operators reason about intuitively
   ("after 5 minutes, evidence is worth half what it was") and matches
   industry convention for time-decayed metrics.
3. **Per-source decay rates.** Considered. Deferred: introduces another
   tuning knob whose value isn't obvious to operators and overlaps with
   per-source `weight`. Global + per-playbook covers the immediate
   need.
4. **Decay only on corroborating signals.** Considered. Rejected
   because primary detectors also produce stale evidence (a firing
   Prometheus alert that has been resolved for 40 minutes shouldn't
   keep contributing at full weight either).

## Migration

No migration required. Default `confidence_decay_half_life_seconds: 0`
preserves ADR 018 behavior bit-for-bit. Operators opt in by setting a
non-zero value in `correlation.yaml`.
