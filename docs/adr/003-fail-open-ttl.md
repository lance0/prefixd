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

### Amendment: the lease is bounded by leased TTLs

Amended 2026-11-15: renewal is independent of PostgreSQL and of the controller
fence so that a database outage shorter than the leased routes' TTLs does not
drop them. That independence cannot be unbounded, or the TTL guarantee in this
ADR would be suspended for the length of the outage.

The lease keeper therefore keeps `renew_until`: the latest `expires_at` among
the leased routes this owner holds. Leased FlowSpec rules and leased
blackholes (`blackhole.leased`) count alike, because one lease covers both.
Two things refresh it:

- **Reads.** A successful read of active intent at the start of every
  reconciliation pass, before expiry runs, replaces it. A failed read leaves
  the previous bound standing (fail-closed), and an empty leased set bounds
  renewal to the read itself.
- **Writes.** Every committed leased admission and TTL extension (a detector
  re-send, `POST /v1/mitigations/{id}/extend` and a blackhole extension)
  raises it to that row's `expires_at` at once. A later read never lowers it
  below a leased write committed since the previous read, so a row added after
  a read cannot lapse inside its TTL while the next read is late.

Renewal stops at the cutoff, `renew_until + margin`, where the margin is
`max(blackhole.lease_seconds, timers.reconciliation_interval_seconds +
blackhole.lease_seconds / 3)`. A renewal is sent only if its own deadline ends
by the cutoff, so no accepted renewal lands after it, and rustbgpd removes the
owner's leased routes within one lease of the cutoff. A row past its TTL but
not yet withdrawn keeps its past `expires_at`, so rereading it never grants a
fresh margin. A read or write that refreshes the bound after a stop
renews at once, including for a rule still inside its TTL.

The lease is owner-wide, so the bound is too. During an outage, every leased
route of this owner is renewed until the latest leased `expires_at` among them,
plus the margin, and lapses within one more lease. A route is therefore bounded
by the latest leased TTL among the owner's routes, not by its own: a 60-second
rule next to an 1800-second rule can stay installed for about 1800 seconds
plus the margin and one lease of outage. Once the database returns, expiry
withdraws the shorter rule as usual.

Details:

- **Margin.** One lease would be enough for an outage, but with
  `lease_seconds` shorter than the reconciliation interval a healthy
  controller could stop renewing between passes. The margin covers one
  interval plus a third of a lease, so a healthy controller always reads, and
  withdraws an expired row, before renewal would stop. It lengthens the outage
  tail by at most one reconciliation interval.
- **Startup.** Before any read or write, renewal is bounded to one margin
  after startup. A freshly started controller that cannot read the database
  lets the adopted lease lapse; it never renews it indefinitely without
  evidence of the TTLs.
- **Standby.** A standby mutates nothing, but it reads active intent on the
  reconciliation interval, so its unfenced renewal follows the same bound as
  the active controller and a live lease stays live through a failover. A
  standby that cannot read stops at its own bound and reports the lease as
  `standby`, not `expired`, because the active controller may still keep it
  live.
- **Not a failure.** A stop at the bound is reported as a lease TTL bound
  (`renewal_stopped: "ttl_bound"` in health), not as a failed renewal. The
  lease state reports `expired` once one more lease has passed after the stop,
  since by then the speaker holds none of the routes.
- **No resurrection.** The bound only stops and resumes renewal. It never
  adds, re-adds or resurrects a route: adds stay fenced and database-gated,
  expiry withdraws an expired row before any re-add, and dry-run still never
  renews.

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
