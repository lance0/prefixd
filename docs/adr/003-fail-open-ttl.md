# ADR 003: Fail-Open Design with Mandatory TTLs

## Status

Accepted

## Date

2026-01-15

## Context

A DDoS mitigation system that fails closed (leaves rules permanently installed) is more dangerous than one that fails open (rules expire). If prefixd crashes, loses its database, or has a bug in rule management, permanent FlowSpec rules could:

- Block legitimate traffic indefinitely
- Cause customer outages that outlast the original attack
- Require manual router intervention to clear

## Decision

All mitigations **must** have a TTL. The running reconciliation loop enforces
expiry by asking the speaker to withdraw the rule. The TTL is application
state; it is not a lease encoded in the FlowSpec rule.

Corrected 2026-10-17: prefixd and its BGP speaker are separate processes.
prefixd exiting does not close GoBGP's or rustbgpd's router sessions. Rules can
remain installed while the controller is down. Automatic cleanup after a
controller crash requires an explicit lease or coupled-lifecycle mechanism;
neither is provided by the current deployment.

The safety chain:
1. **Application TTL** - prefixd expires mitigations and sends withdrawals
2. **Speaker session loss** - A speaker failure can clear routes through BGP
   session teardown; configured Graceful Restart retention can delay removal.
   This does not cover an independent controller failure.
3. **Operator withdrawal** - `prefixdctl mitigations withdraw <id>` for manual override

### Amendment: leased FlowSpec in the default install

Amended 2026-11-15: the shipped `configs/prefixd.yaml`, which the rustbgpd
Compose profile mounts, sets `bgp.rustbgpd.leased_flowspec: true`. New
enforced FlowSpec rules are added under the controller's rustbgpd injection
lease ([ADR 027](027-blackhole-mitigations.md#amendment-leased-flowspec)). If
prefixd stops while rustbgpd keeps running, rustbgpd withdraws them within
`blackhole.lease_seconds` (60 by default) plus its RIB queue lag. When prefixd
returns, reconciliation re-adds the rules that are still desired. For the
rustbgpd profile, this supersedes the correction's statement that the current
deployment provides no lease.

The lease gives the default rustbgpd install the fail-open behavior this ADR
asks for. It also means a controller outage longer than one lease removes
active mitigations while the attack may continue. Operators who want rules to
survive a controller outage set `leased_flowspec: false`.

The lease does not cover:

- **The code default.** A config that omits `leased_flowspec` stays unleased.
- **GoBGP.** It has no lease, so the GoBGP profile keeps unleased rules.
- **Rules added unleased.** They stay unleased until they are withdrawn or
  expire.
- **State beyond rustbgpd.** Expiry removes rustbgpd's local rule only. A
  received rule with the same match keeps filtering, and routers acting as
  Graceful Restart helpers retain it for their stale timers.

## Consequences

**Positive:**
- Active reconciliation withdraws mitigations whose TTL has elapsed
- Speaker and controller failures have separate recovery requirements
- Running reconciliation attempts TTL withdrawals; failed cleanup needs explicit recovery and tests

**Negative:**
- Long-running mitigations need periodic extension (detectors must re-send events)
- Short TTLs increase event volume; long TTLs delay cleanup
- No "permanent safelist via FlowSpec" use case (use router static config instead)
- Controller downtime suspends application TTL enforcement; restore
  reconciliation or explicitly withdraw rules from the speaker.
