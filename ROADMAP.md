# Roadmap

prefixd's priority is reliable mitigation through a separate BGP speaker and a
clear operator workflow. Main may contain unreleased work; see the
[changelog](CHANGELOG.md) for release history and [features](FEATURES.md) for the
current product surface.

## Current baseline

Normal builds and the example deployment prefer rustbgpd. GoBGP remains an
explicit choice in the same controller image. Both adapters use the shared
writer and optional rule/peer observation boundary, with released-daemon CI,
dual-family peer tests and secure Compose profiles. See
[speaker backends](docs/reference/speaker-backends.md) and the
[dated profile qualification](docs/reference/qualification/speaker-profiles-2026-10-18.md)
for exact versions, checks and limits.

Desired mitigation intent is persisted before announcement; failed withdrawals
retain their original rule, actor and reason for retry. PostgreSQL, axum/sqlx,
the existing authentication modes and the repository boundary remain the runtime
baseline. The operator overview puts active mitigations, signals, observation
limits and expiry ahead of historical activity.

Polling reconciliation repairs missing rules and supported discard/policing action
drift for uniquely owned intent. This assumes one running controller per POP and
exclusive administration of its physical speaker target.

These controller and peer results do not establish vendor forwarding. TTL expiry
requires the running controller; a separate speaker can continue advertising
after prefixd stops. For leased routes, the planned rustbgpd injection lease is
the remedy: the speaker would remove them when the controller stops renewing.

## Near-term work

- Add blackhole (RTBH) host routes as a second mitigation kind, as decided in
  [ADR 027](docs/adr/027-blackhole-mitigations.md). The design is accepted and
  manual and detector blackholes have merged, unleased, behind stricter
  guardrails than FlowSpec. Enforced detector blackholes are an explicit
  opt-in; until the rustbgpd owner-scoped injection lease ships, a controller
  stopped for a long time leaves them announced, mitigated by orphan cleanup
  on return and down alerts. The lease is the later hardening step.
  Qualification is at FRR in the containerlab harness. FastNetMon Community
  users mostly mitigate with blackholes.
- Fence duplicate controllers with a PostgreSQL advisory lock keyed on the
  controller's owner. When controllers share a database, one is active per
  owner and the others wait in standby to take over. The fence protects
  FlowSpec as well as blackholes. Controllers with separate databases are
  outside the lock.
- Add stronger announcement acknowledgements and a complete desired/acknowledged
  ledger. Shared targets also need ownership evidence that distinguishes another
  controller's local rule with the same match. That evidence is planned to
  arrive through the owner-scoped injection lease proposed upstream as rustbgpd
  ADR-0141. The controller fence covers duplicate controllers on one database;
  it does not make shared targets supported.
- Qualify router receipt and traffic enforcement separately for each tested
  backend, vendor, software version and topology. Preserve historical GoBGP
  results; qualify rustbgpd against FRR/Juniper and Arista/Cisco independently.
- Finish complete-list pagination and tied-timestamp cursor correctness, then
  verify the operator workflow at the tested scale and accessibility settings.
- Keep input validation, authentication, dependency audits and native lint gates
  strict. Address concrete findings without adding speculative configuration.
- Keep documentation and release guidance aligned with source. Exercise the
  quickstart from a clean environment and record its actual prerequisites and
  timing; retain failed runs and scope performance claims to dated receipts.

## Later work

ExaBGP and other write-only adapters need durable desired/acknowledged state and
verified restart replay before support can be claimed. An empty observed RIB
cannot stand in for unavailable observation. Additional integrations, match or
action types, telemetry and distributed coordination need a concrete operator
requirement and their own qualification.

Diverting attack traffic to an external scrubber is later work. prefixd would
orchestrate BGP diversion routes or FlowSpec redirect so the victim stays
reachable while traffic is scrubbed elsewhere. It depends on the blackhole
unicast contract, the injection lease and the controller fence, and needs its
own design, including scrubber health and leak prevention.

[ADR 026](docs/adr/026-facelift-framework-scope.md) defers framework adoption.
Loco or an ORM migration is not a prerequisite for these changes.

prefixd remains a control-plane policy controller: packet scrubbing, detection
algorithms and L7/WAF analysis belong to other systems. Diversion would be
control-plane orchestration; the scrubbing itself, the return path and detection
stay external. Default guardrails reject broad match-everything rules.

See [contributing](CONTRIBUTING.md) and the
[public issues](https://github.com/lance0/prefixd/issues) for ways to help.
