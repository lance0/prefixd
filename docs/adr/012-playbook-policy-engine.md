# ADR 012: Playbook-Based Policy Engine

## Status

Accepted

## Date

2026-01-15

## Context

When a detector reports an attack, prefixd needs to decide: what action to take (police or discard), what rate limit to apply, what TTL to set, and whether to escalate if the attack persists.

These decisions could be:
1. **Hardcoded** -- Simple but inflexible, every change requires a code deploy
2. **Rule-engine** -- Powerful but complex (Drools, OPA), steep learning curve for network engineers
3. **Playbook-based** -- YAML config files that map attack vectors to response steps, familiar to anyone who's used Ansible

Network engineers write YAML configs daily (router configs, automation playbooks). A YAML-based policy system meets them where they are.

## Decision

Policy is defined in `playbooks.yaml` as a list of playbooks. Each playbook matches an attack vector and defines ordered response steps with escalation thresholds:

```yaml
playbooks:
  - name: udp_flood
    match:
      vector: udp_flood
    steps:
      - action: police
        rate_bps: 10000000
        ttl_seconds: 120
      - action: discard
        ttl_seconds: 300
        require_confidence_at_least: 0.8
```

*Correction, 2026-11-15.* The controller runs only the first step of a
playbook. Later steps and their `require_confidence_at_least` thresholds are
accepted and validated but not executed, and startup, reload and
`PUT /v1/config/playbooks` log a warning for each playbook with more than one
step.

Playbooks are hot-reloadable via `POST /v1/config/reload` or `prefixdctl reload` without restarting the daemon.

## Consequences

**Positive:**
- Network engineers can define policy without writing code
- Hot-reload means policy changes don't require downtime
- Escalation logic is declarative (confidence thresholds, step ordering)
- Easy to audit: `git diff playbooks.yaml` shows exactly what changed
- Playbooks can be version-controlled alongside router configs

**Negative:**
- YAML is error-prone (indentation, type coercion) -- mitigated by validation at load time
- Complex logic (time-of-day rules, customer-specific overrides) would need YAML extensions
- No playbook dependency graph or composition -- each playbook is independent
- Hot-reload doesn't validate against running state (a bad playbook could affect active mitigations on next event)

**Future:**
- Customer-specific playbook overrides (via inventory.yaml)
- Time-based rules (different thresholds during maintenance windows)
- Playbook editor UX enhancements (current UI supports both form and raw YAML editing via `PUT /v1/config/playbooks`)

## Amendment: detector events without destination ports

Amended 2026-11-16.

Service `allowed_ports` filters destination ports a detector reports. It is
not evidence of the attack's ports and never supplies missing event ports.
Two nonempty lists with no intersection refuse admission.

A UDP or TCP `police` event without destination ports produces a victim and
protocol match without a destination-port component. This covers attacks to
unknown ports, including the bundled FastNetMon script's UDP events. It also
rate-limits legitimate traffic of that protocol to the victim: service ports
are not exceptions to the policer. Set `require_top_ports: true` when that
collateral effect is unacceptable; a portless event then matches no playbook.

A UDP or TCP detector `discard` without destination ports is refused. Removing
an inferred service-port list must not silently broaden a discard to all
traffic of that protocol. ICMP, explicit multi-rule matches, blackholes and
operator-specified manual rules keep their existing selection rules.
The same guard applies before a detector extends a saved rule: matching a
manual protocol-only discard does not authorize prolonging that discard.

[ADR 033](033-detector-prefix-mitigations.md) still requires destination ports
for prefix discard and TCP prefix police. Its UDP prefix-police exception
continues to permit protocol-only matches. Both address families and speaker
backends use the same policy result. Persisted rules keep their saved matches
until withdrawn or expired; this change affects new admission.
