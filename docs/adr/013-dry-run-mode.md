# ADR 013: Dry-Run Mode

## Status

Accepted

## Date

2026-01-15

## Context

Deploying a system that automatically announces BGP FlowSpec rules to production routers is inherently risky. A misconfigured playbook, bad inventory data, or unexpected detector behavior could cause unintended traffic drops.

Operators need a way to:
1. Validate the full pipeline (event → policy → guardrails → FlowSpec rule) without affecting production traffic
2. Onboard new detectors and tune confidence thresholds safely
3. Test playbook changes before going live

## Decision

prefixd supports a global `mode` setting with two values:

- **`dry-run`** -- Full pipeline executes, mitigations are created in the database, metrics are emitted, audit logs are written, but **no BGP announcements are made**. GoBGP is never contacted.
- **`enforced`** -- Full pipeline including BGP announcements to GoBGP.

```yaml
# configs/prefixd.yaml
mode: dry-run   # or: enforced
```

The mode is visible in the health endpoint, dashboard, and logs so operators always know whether rules are being announced.

### Amendment: dry-run intent stays local

Each mitigation records the mode that admitted it (migration 015, `origin_mode`). A dry-run mitigation is a simulation, never desired speaker state:

- Reconciliation never announces it, and its withdrawal or TTL expiry never deletes speaker state, in either mode.
- Enforced startup refuses to run while the POP has unexpired dry-run mitigations. The one-shot `prefixd --retire-dry-run-intent` retires them through audited, local-only withdrawals without connecting to the speaker.
- In enforced mode a detector event does not extend a dry-run mitigation; it returns a conflict and stays retryable.

Before this amendment, the first enforced reconciliation after a restart announced every unexpired dry-run mitigation. Rows from before migration 015 are tagged with the startup mode on first start, so upgrades must not change the mode at the same time. See [mitigation origin mode](../how-to/upgrading.md#mitigation-origin-mode).

## Consequences

**Positive:**
- Safe onboarding: run dry-run in production for days/weeks before enabling enforcement
- Playbook testing: validate new policies against real traffic patterns without risk
- Detector tuning: see what mitigations would be created without affecting traffic
- Incident response: switch to dry-run to pause all announcements without shutting down
- Full observability in both modes: metrics, audit log, and dashboard work identically

**Negative:**
- Dry-run doesn't exercise the GoBGP code path (a bug in announcement logic won't surface)
- No per-playbook or per-customer dry-run (it's global only)
- Switching modes requires a config change and restart; config reload does not change the mode (no API toggle)
- Switching from dry-run to enforced first requires retiring unexpired dry-run mitigations; a simulation never graduates into an announcement

**Future:**
- Per-playbook dry-run override (new playbooks start in dry-run; enforcing a playbook applies to new mitigations only)
- API endpoint to toggle mode without config file edit
