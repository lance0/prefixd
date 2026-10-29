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

Manual and detector blackholes have shipped on rustbgpd behind the stricter
guardrails in [ADR 027](docs/adr/027-blackhole-mitigations.md). Detector-driven
blackholes remain an explicit opt-in. A PostgreSQL
advisory-lock fence keeps a second controller for the same owner in standby when
both share the database. Separate databases are outside that fence.

TTL expiry requires the running controller for unleased rules; a separate
speaker can continue advertising after prefixd stops. With rustbgpd 0.79.0 or
later, opt-in [leased blackholes](docs/reference/configuration.md#leased-blackholes)
(`blackhole.leased`) and [leased FlowSpec](docs/reference/configuration.md#leased-flowspec)
(`bgp.rustbgpd.leased_flowspec`) let the speaker remove leased intent within one
lease after renewal stops. Existing unleased rules stay unleased until withdrawn
or expired. Neither local intent nor peer health establishes vendor forwarding.

Per-peer export observation covers blackholes and FlowSpec on rustbgpd, sharing
one rotating pass budget. It distinguishes current, retained, unsupported and
failed evidence; committed means Adj-RIB-Out, not router installation or traffic
enforcement. Complete export walks identify configured addressed peers without
a session independently of optional FSM observation; unbound interfaces still
use the session snapshot. Complete desired/acknowledged state and router
qualification remain separate work.

Controller inventory enumeration and the public mitigation, event, audit and
signal-group cursors preserve tied timestamps. The mitigation list uses
server-backed search, filters and cursor navigation; event/audit lists and the
command palette still need complete pagination.

## Near-term work

- Add stronger announcement acknowledgements and a complete desired/acknowledged
  ledger, including unleased and GoBGP paths. Opt-in rustbgpd injection owners
  and lease recovery do not complete that ledger or make shared targets
  supported. The controller fence covers duplicate controllers on one database;
  it does not fence other writers to the physical speaker.
- Qualify router receipt and traffic enforcement separately for each tested
  backend, vendor, software version and topology. Preserve historical GoBGP
  results; qualify rustbgpd against FRR/Juniper and Arista/Cisco independently.
- Replace the remaining bounded event/audit and command-palette subsets with
  complete server-backed filtering and pagination. Verify the operator workflow
  at the tested scale and accessibility settings, including large-history memory
  and cache growth; mitigation navigation alone does not complete that
  qualification.
- Keep input validation, authentication, dependency audits and native lint gates
  strict. Address concrete findings without adding speculative configuration.
- Keep documentation and release guidance aligned with source. Exercise the
  quickstart from a clean environment and record its actual prerequisites and
  timing; retain failed runs and scope performance claims to dated receipts.

## Later work

Provider-scoped upstream RTBH for saturated transit or exchange ports is
an accepted design in [ADR 029](docs/adr/029-upstream-blackholing.md), with no
upstream runtime support yet. It requires
owner-leased injection, explicit per-provider export policy and separate
transit/route-server qualification before enforcement can be enabled.

ExaBGP and other write-only adapters need durable desired/acknowledged state and
verified restart replay before support can be claimed. An empty observed RIB
cannot stand in for unavailable observation. Additional integrations, match or
action types, telemetry and distributed coordination need a concrete operator
requirement and their own qualification.

Diverting attack traffic to an external scrubber is later work. prefixd would
orchestrate BGP diversion routes or FlowSpec redirect so the victim stays
reachable while traffic is scrubbed elsewhere.
[ADR 030](docs/adr/030-scrubber-diversion.md) proposes guarded redirect-to-IP,
with fresh scrubber readiness, independent profile leases, export isolation,
clean-return prerequisites and separate router/data-path qualification. It
builds on the shipped blackhole unicast contract, injection lease and controller
fence; the redirect action and scrubber workflow remain unimplemented. VRF
redirect, whole-victim unicast diversion and automatic escalation are later
slices, each requiring its own qualification.
The [speaker contract plan](docs/project/scrubber-diversion-contract.md) records
the released API gaps, exact action vectors and queued-mutation controls needed
before the first runtime slice.

[ADR 026](docs/adr/026-facelift-framework-scope.md) defers framework adoption.
Loco or an ORM migration is not a prerequisite for these changes.

prefixd remains a control-plane policy controller: packet scrubbing, detection
algorithms and L7/WAF analysis belong to other systems. Diversion would be
control-plane orchestration; the scrubbing itself, the return path and detection
stay external. Default guardrails reject broad match-everything rules.

See [contributing](CONTRIBUTING.md) and the
[public issues](https://github.com/lance0/prefixd/issues) for ways to help.
