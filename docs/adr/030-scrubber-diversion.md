# ADR 030: Guarded Diversion to an External Scrubber

## Status

Proposed 2026-10-22. Design only; the actions, profiles, readiness monitor and
qualification below are not implemented. Addresses
[the redirect-to-IP request](https://github.com/lance0/prefixd/issues/305).
Extends [ADR 025](025-pluggable-speaker-backends.md) and
[ADR 027](027-blackhole-mitigations.md); complements
[ADR 029](029-upstream-blackholing.md).

## Context and research

An operator with a scrubber wants matching attack traffic sent through it while
legitimate traffic reaches the victim. Discard and blackhole cannot provide
that behavior. Diversion also sends legitimate traffic matching the rule through
the scrubber: a source prefix selects traffic, not whether it is malicious.
prefixd owns mitigation intent; packet filtering, tunnel provisioning, clean
return routing and detection remain external.

The following primary sources were checked on 2026-10-22. Documentation and
source inspection establish protocol and API shape, not tested forwarding.

### Three different meanings of redirect

| Mechanism | Encoding and meaning | Implication |
| --- | --- | --- |
| Redirect to VRF | RFC 8955 §7.4, formerly RFC 7674: `0x8008`, `0x8108` or `0x8208` identifies a route target in its original administrator format | An IPv4 address inside a route target is an administrator, not a scrubber next hop |
| Redirect to IP | `draft-ietf-idr-flowspec-redirect-ip-16`: `0x010c` carries an IPv4 target in an eight-byte community; `0x000c` carries an IPv6 target in a twenty-byte IPv6-specific community | This is the requested target-address action; `C=0` diverts and `C=1` copies |
| Legacy redirect to next hop | Older `0x0800` redirect/mirror community, with the target taken from MP_REACH_NLRI | A different encoding and contract; changing the ordinary FlowSpec next hop does not produce the current redirect-to-IP action |

[RFC 7674](https://www.rfc-editor.org/rfc/rfc7674.html) clarified VRF route-target
formats and was obsoleted by
[RFC 8955](https://www.rfc-editor.org/rfc/rfc8955.html#section-7.4).
[RFC 8956 §6.1](https://www.rfc-editor.org/rfc/rfc8956.html#section-6.1)
adds IPv6-address-specific **VRF** redirect (`0x000d`), also distinct from
redirect-to-IPv6. The
[IANA registry](https://www.iana.org/assignments/bgp-extended-communities)
lists the target-address code points separately from both VRF and legacy forms.
The [current draft's status](https://datatracker.ietf.org/doc/draft-ietf-idr-flowspec-redirect-ip/)
is RFC Editor Queue, revision 16, rather than a published RFC as of this check.

The [draft's forwarding and validation rules](https://datatracker.ietf.org/doc/html/draft-ietf-idr-flowspec-redirect-ip-16#section-2)
resolve the target in the router's next-hop database. Unreachable or invalid
targets cause the action community to be ignored; ECMP can distribute traffic
over multiple next hops. Redirection terminates rule evaluation; combining it
with policing does not establish policing of redirected traffic. These details
require platform qualification and prevent treating redirect as another rate
value. The first implementation must emit exactly one target, `C=0`, no copy,
cross-family target, combined policing, marking or VRF action.

### Current speaker and controller boundary

This inspection uses prefixd main at `87a225c` and its pinned rustbgpd 0.79.0
contract; GoBGP released-daemon CI uses 4.10.0. It does not assume newer releases
have the same surface.

- prefixd's `src/bgp/rustbgpd.rs::encode` and
  `src/bgp/gobgp.rs::build_path_attributes` require one traffic-rate action.
  Neither adapter currently implements redirect. Action-preserving decoding,
  reconciliation, immutable withdrawal snapshots and public action parameters
  must change together before redirect can be enabled.
- The [rustbgpd 0.79.0 injection implementation](https://github.com/lance0/rustbgpd/blob/v0.79.0/crates/api/src/injection_service.rs)
  accepts all three VRF route-target formats, rather than only a two-octet ASN.
  `FlowSpecRedirect.route_target` in `proto/rustbgpd.proto` still has no typed
  target-IP action. `AddFlowSpec.extended_communities` accepts raw `uint64`
  communities, also through `AddLeasedFlowSpec`, so an IPv4 target could be
  carried opaquely today. This is not an absolute IPv4 wire blocker. That field
  cannot carry the twenty-byte IPv6-specific target form; it also supplies no
  typed target/copy validation or typed action read-back. Prefer an upstream
  typed, lossless, leased contract before product enablement. Do not silently
  substitute a VRF route target or legacy next hop.
- [GoBGP 4.10.0's protobuf](https://github.com/osrg/gobgp/blob/v4.10.0/proto/api/extcom.proto)
  includes separate `FlowSpecRedirectToIPv4Extended` and
  `FlowSpecRedirectToIPv6Extended` messages. Its
  [API conversion](https://github.com/osrg/gobgp/blob/v4.10.0/pkg/apiutil/attribute.go)
  and [wire codec](https://github.com/osrg/gobgp/blob/v4.10.0/pkg/packet/bgp/bgp.go)
  implement target/copy encoding, and its
  [FlowSpec guide](https://github.com/osrg/gobgp/blob/v4.10.0/docs/sources/flowspec.md#example---redirect-to-ip)
  distinguishes target-IP from VRF redirect. prefixd's vendored GoBGP 4.2.0
  messages lack those target-IP types, and its GoBGP adapter provides no
  owner-scoped injection lease. GoBGP support therefore needs its own contract
  and qualification; the new types alone do not meet this ADR's safety gates.

The unicast writer, controller fence and opt-in leased blackhole/FlowSpec paths
from ADR 027 have now shipped. They are prerequisites to reuse, not evidence
that scrubber diversion is ready. Existing FlowSpec and blackhole leases share
one owner; any add or renewal extends that owner's routes
([configuration reference](../reference/configuration.md#leased-flowspec)).
An unhealthy scrubber cannot safely share that renewal domain.

### Router and scrubber prerequisites vary

- [FRR 10.4's FlowSpec guide](https://docs.frrouting.org/en/stable-10.4/bgp.html#flowspec)
  describes a receiving client, default-VRF configuration and Linux policy
  routing. It references redirect draft -02 and documents install limitations,
  including a missing Netfilter driver and unsupported match combinations.
  A received FlowSpec route is therefore insufficient evidence of forwarding.
  The proposed FRR lab must supply and identify a working installation path;
  if it cannot, report control-plane-only results and keep enforcement gated.
- [Cisco NCS 560 IOS XR 24.x's action table](https://www.cisco.com/c/en/us/td/docs/iosxr/ncs560/routing/24xx/b-bgp-cg-24xx-ncs560/bgp-overview.html)
  describes legacy `0x0800` and MP_REACH next-hop redirection, with precedence
  different from the current draft. That evidence does not qualify `0x010c`
  on Cisco, or any other Cisco platform/release.
- [Junos's redirect guide](https://www.juniper.net/documentation/us/en/software/junos/bgp/topics/topic-map/multiprotocol-bgp.html#id-configuring-bgp-flow-specification-action-redirect-to-ip-to-filter-ddos-traffic)
  documents the newer IPv4 encoding and a separate legacy mode. Its detailed
  IPv6 caveat limits IPv6 to legacy next-hop encoding. The broader guide's
  IPv4/IPv6 overview must not be read as parity for both wire encodings.
  [Junos also exposes unresolved-target discard behavior](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/flow-edit-routing-options.html),
  so local failure policy cannot be inferred solely from the draft.
- [Tempesta xFW's deployment documentation](https://tempesta-tech.com/tempesta-escudo/knowledge-base/XFW/#modes-of-operation)
  describes scrubbing mode as receiving redirected victim traffic, including
  legitimate packets, while unaffected destinations bypass it. Direct server
  return can be used. Gateway mode instead requires both directions, Linux IP
  forwarding, routing, interface and firewall configuration. Its
  [scrubbing configuration example](https://github.com/tempesta-tech/xFW/blob/main/examples/xfw-native-scrubbing.json)
  selects attached devices and `deployment-mode: scrubbing`. Neither example
  is a BGP receiver contract or a prefixd integration receipt. Operators must
  configure xFW's normal traffic profiles and filtration rules externally;
  this ADR does not add an xFW configuration client.

## Proposed decision

### 1. Select a configured scrubber, never an arbitrary request next hop

Add a disabled-by-default `redirect_ip` FlowSpec action referencing one named
per-POP scrubber profile. The first release supports manual requests only,
host destinations only (`/32` or `/128`), and a same-family unicast literal
target. Reject zero, multicast, loopback, link-local/scoped, mapped and
operator-reserved infrastructure targets. Private addressing is valid when
explicitly configured and qualified. A detector cannot supply an address,
community, route target, owner, health URL or export selector.

Profiles record the target per enabled family, inventory-owned destination
space, authorized ingress router peers/interfaces, a fixed current-draft wire
encoding, immutable speaker-policy binding, readiness source, maximum TTL,
nonzero active caps and admission rate, and a dated qualification receipt.
They also record expected target resolution/ECMP behavior, clean-path topology
and the operator's attestation that the scrubber filters are installed and have
capacity. Bounds may narrow existing guardrails but never widen the host-only
first release. Include customer, POP, global and profile quotas in serialized
admission; estimate traffic against a configured capacity ceiling when fresh
telemetry exists and otherwise report capacity as unverified.

Both manual and later playbook admission require inventory ownership, the
existing prefix/port/source guardrails and safelist checks, mandatory bounded
TTL and a fresh safelist check before every add or repair. Source-prefix match
support is an independent feature: retain its canonical match in identity,
read-back and withdrawal; do not accept source-only diversion without a victim.

Snapshot the profile revision, target, full action/match, policy selector,
resolved peer identities, owner and expiry in persisted intent before the RPC.
Reload affects new intent only. Refuse removal or retargeting of a profile or
policy binding while its active or pending withdrawal intent exists. Retain
external export-policy revisions until they drain; a database snapshot cannot
freeze independently changed speaker policy. Drift blocks new adds and repairs
and raises an alert.

### 2. Prevent leaks and clean-traffic loops

Speaker export policy defaults to deny and permits only the profile's frozen
router peer set. Install matching import policy and ingress interface scope on
those routers; reject export to transit, other tenants or route servers.
External provider diversion is a separate future qualification and explicit
opt-in, not an implicit extension of the first release.

Do not add `NO_EXPORT` blindly at injection: as ADR 027 records, it can prevent
an eBGP router from receiving the route. Use explicit export isolation plus
receiver import policy and propagation communities appropriate to the tested
session. A qualification negative control must prove a non-target peer receives
no diversion. Merely observing `NO_EXPORT` does not establish isolation.

The operator supplies routable target reachability, scrubber forwarding,
capacity, clean-return VRF/interface/tunnel, MTU/PMTUD and anti-spoofing rules.
Clean traffic must re-enter beyond the redirect's ingress scope or in a distinct
clean routing domain, so it cannot match the diversion repeatedly. The target
route must not resolve back through the victim diversion. DSR is permitted only
for a qualified scrubber mode; bidirectional gateway features need a different
return-path receipt. prefixd does not provision GRE, MPLS, VPNs, routes on the
scrubber, or asymmetric TCP protection and cannot prove those prerequisites
from BGP session state.

### 3. Require fresh readiness and withdraw on loss

Enforced diversion requires a configured authenticated readiness source from an
external monitor. Operator assertion alone is allowed only for dry-run. The
monitor must check scrubber process/filter readiness, target reachability,
capacity admission and a canary's dirty-to-clean data path. The configured
profile identifies the expected monitor and profile revision. Reports carry a
bounded validity period and probe time; reject stale/future-skewed reports,
wrong revision, malformed or unauthenticated responses. Use bounded TLS HTTP
calls to a configuration-owned endpoint, no redirects or request-supplied URLs,
and keep credentials out of logs and APIs. A healthy canary is limited evidence
for that tested path, not proof every victim or packet is scrubbed.

Model readiness as `ready`, `not_ready` or `unknown`, with timestamp and reason.
At startup, after reload, on monitor failure or on stale evidence, it is
`unknown` until a fresh successful check. Only `ready` admits, refreshes or
repairs diversion. A BGP session or ping alone never sets it. Bound poll period,
response timeout and validity in configuration; the receipt must record the
resulting worst-case detection time.

On `not_ready` or `unknown`, first latch the affected profile into withdrawal,
then persist withdrawal for every live diversion under it with the original
actor, rule, reason and operation ID. Retry deletes under the recorded owner;
ambiguous responses remain pending and never become fresh adds. Stop renewal
and all leased adds for that profile immediately, even if the database write
fails. Once storage recovers, record the latched reason before any replay.
Automatic recovery cannot clear the latch: after confirmed absence and fresh
readiness, an operator must explicitly re-arm the profile and create new intent.
Restart must not erase an unpersisted latch: a new controller starts unarmed
for profiles with outstanding diversion, drains that intent and requires re-arm.
This prevents a flapping scrubber from repeatedly attracting traffic.

The first release returns to ordinary routing after diversion is removed. It
does not automatically discard, blackhole, switch scrubbers or escalate to
whole-prefix diversion. Withdrawal may expose the victim to attack again; the
UI must state that tradeoff. A future fallback requires an explicitly approved
playbook transition and its own guardrails and qualification.

### 4. Isolate lease owners and preserve failure intent

All enforced diversion, including manual requests, requires owner-scoped leased
injection. No unleased override or fallback is allowed. Keep each scrubber
profile's lease owner disjoint from ordinary FlowSpec, blackholes and other
profiles. Persist the exact owner and policy revision; adopt it only after a
complete local inventory agrees with durable desired/pending state. Refuse
unknown or foreign-owned routes at a desired key and never override or delete
them. Enforce the speaker's per-owner key cap.

The existing controller fence gates adds, deletes and repairs; continue the
one-controller-per-POP/speaker deployment rule. A separate database remains
outside that fence. A standby cannot add or repair. Any profile renewer that
runs through loss of leadership must obey the same readiness/latch gates;
renewal must also stop if durable current intent and TTL/withdrawal obligations
cannot be established. This is deliberately stricter than existing ordinary
mitigation renewal during a database outage.

For each profile, serialize readiness transitions, admission, add, renewal and
withdrawal eligibility. Recheck the latched state immediately before dispatch.
A last in-flight leased add can extend the profile owner's deadline. A client
RPC timeout does not cancel an already-enqueued mutation: rustbgpd 0.79.0's
[leased-add handler](https://github.com/lance0/rustbgpd/blob/v0.79.0/crates/api/src/injection_service.rs#L688-L700)
enqueues RIB work before awaiting its reply. Qualification must establish a
server-side expiry/cancellation or bounded mutation-age guarantee that prevents
arbitrarily delayed adds from extending or recreating the lease after shutdown.
Until that guarantee or confirmed server-side quiescence exists, the last
possible lease extension is unknown; do not derive a withdrawal deadline from
the client timeout. Record and expose that uncertainty. On lease
loss or speaker restart, re-add only unexpired, still-authorized desired intent
under a fresh owner generation, after a complete inventory and fresh readiness;
never replay withdrawn or latched diversion.

Application TTL still requires a running controller. The speaker lease bounds
retention after renewal stops by the last possible lease extension plus RIB
queue lag. Router convergence, graceful-restart retention and stale PBR/FIB
state can extend actual forwarding beyond local removal and need separate
failure qualification. Do not report lease expiry or an unavailable inventory
as confirmed end-to-end withdrawal. A dry-run controller performs no add,
renewal or deletion; dry-run intent never acquires an enforced route owner.

### 5. Make action conflicts and evidence explicit

`redirect_ip` remains a FlowSpec action with a canonical match; the scrubber
profile is an action parameter, never part of the speaker NLRI key. A second
action or different target for the same live match conflicts instead of
replacing another actor's route. For the first release, refuse any diversion
when another live or pending mitigation affects the same victim in the POP,
and refuse those admissions while diversion owns the victim. This conservative
victim-level exclusion covers discard/police, blackhole and overlapping source
matches without guessing router action precedence. Unaffected victims remain
independent. Changing the action requires confirmed withdrawal before a new
admission. More permissive coexistence needs explicit overlap analysis and
router qualification.

Future playbook steps can name the same profile and readiness requirement;
detector sources need explicit authorization. Multi-step escalation and
FlowSpec-to-full-prefix diversion remain deferred. Do not imply the existing
first-step policy evaluation implements escalation.

API/OpenAPI, CLI, WebSocket events and UI expose the action, profile revision,
match, victim/customer, expiry, readiness age/reason, withdrawal latch and each
available evidence layer. Keep unsupported observation, failed observation and
a successful empty result distinct. Preserve old JSON defaults and immutable
withdrawal snapshots when extending persisted action variants. A mitigation
must never deserialize an unknown redirect action as discard or police.

Display separately: desired intent; local RPC acceptance; retained local rule
under its owner; selected/accepted local RIB state where available; committed
export to each target router; externally observed router action/FIB state;
and timestamped scrubber/canary traffic evidence. `active` or `ready` alone
must not be labeled installed, scrubbing, or recovered. GoBGP local accepted
RIB is not pre-policy retained intent. Observation failures block repair rather
than becoming an empty RIB.

The operator reviews target and match before admission and confirms withdrawal
with a warning about attack traffic returning to ordinary routing. Audit
admission, readiness loss/re-arm, refused conflicts, local outcomes, lease
generation changes and withdrawal reasons. Metrics use bounded action/profile
and reason labels for active/pending counts, readiness, lease renewal and
withdrawal failures; victim addresses and operation IDs belong in audit/detail
responses. Authenticated health summarizes degraded profiles; public liveness
does not expose target addresses, monitor credentials or router details.

## Alternatives considered

1. **BGP unicast diversion.** Reuse the unicast injection boundary for an owned
   victim host route with a scrubber next hop or explicit scrubbing-policy
   selector. It must be a separate typed diversion intent, without mandatory
   BLACKHOLE or the discard next hop. It moves all traffic to the victim and
   competes with the blackhole route's prefix/path key. Defer until redirect-IP
   safety and health are qualified; broader prefixes, upstream announcements
   and automatic escalation need a separate accepted design.
2. **VRF redirect.** Valid where a preinstalled scrubbing VRF and route-target
   contract exist, and current rustbgpd already supports the RT formats.
   It has different configuration and resolution requirements and does not
   satisfy a request for direct IP targeting. Add only as an explicitly named
   later action with its own profile and qualification.
3. **Raw IPv4 community immediately.** Transport is possible in rustbgpd
   0.79.0, but enabling only that encoder leaves action validation, lossless
   observation, lease isolation, health, export isolation and failure behavior
   unresolved. A later decision could qualify a canonical raw IPv4 adapter;
   do not present an encoding limitation as the sole blocker.
4. **Keep diverting after health loss or fall back to blackhole.** Both can
   prolong a victim outage. The initial policy explicitly withdraws and latches;
   alternative operator policies require reviewed transitions and evidence.

## Qualification and slices

These are acceptance gates for future implementation, not results of this PR.
Each slice is independently reviewable; the feature remains disabled until the
required gates for its family/backend/profile pass.

The [speaker contract and qualification plan](../project/scrubber-diversion-contract.md)
records the 2026-10-23 released-contract audit, canonical target-action vectors,
rollback refusal and concrete queued-mutation acceptance cases for slice 1.
It remains a proposal; it supplies no runtime or forwarding qualification.

| Slice | Deliverable and acceptance |
| --- | --- |
| 1. Speaker contract | Agree and pin typed redirect-to-IP add/read-back for both target families, owner-scoped leased mutation and lossless action preservation; test exact bytes, copy/reserved-bit refusal, incompatible actions, idempotent owner-checked delete and restart/generation behavior. A qualified IPv4-only alternative must be described explicitly if chosen. |
| 2. Durable model and profiles | Add the action/profile snapshot and independent profile lease owners; replay existing migrations/rows, retain pending withdrawal data, refuse conflicts and configuration changes with outstanding intent. Prove concurrent admission cannot replace a live action. |
| 3. Readiness and failure | Add the bounded monitor, profile latch and serialized health/add/renew/delete path. Test startup unknown, stale/replayed/wrong-revision reports, failed writes, database loss, monitor loss during an in-flight add, delayed queue execution after client timeout, controller death, foreign owner and speaker restart. A healthy unrelated profile must not renew a failed profile's routes. |
| 4. Operator workflow | Add manual API/OpenAPI, CLI, UI, audit and metrics with dry-run and expiry behavior. Exercise preview, conflict, confirmation, readiness loss/re-arm and observation failure. No detector/playbook enablement yet. |
| 5. FRR receipt | Use an isolated pinned FRR router plus Linux scrubber/canary host, identified installation driver, kernel/netfilter tools, backend digest and full topology. Qualify each target family independently; record unsupported cases rather than inventing a working driver. |
| 6. Additional platforms and policy | Qualify exact vendor/software/hardware, encoding, ingress scope and scrubber mode before adding profile support. Only then consider detector playbooks, fallback, VRF or whole-victim unicast diversion. |

The FRR receipt must retain route/action bytes received, selected RIB state,
installed PBR/FIB/rules and counters, dirty and clean packet captures, and
unaffected traffic controls. Demonstrate matching source/protocol/port traffic
traversing the dummy scrubber and reaching the original victim without a loop;
nonmatching source/destination traffic follows ordinary routing. A dummy host
proves diversion and return routing only, not malicious-traffic filtering by
xFW. An xFW claim additionally needs pinned xFW configuration, selected mode,
loaded filters and packet evidence of attack rejection and legitimate delivery.

Run manual withdrawal, application TTL expiry, readiness loss, controller stop,
speaker stop/restart, unresolved next hop, export-policy denial and foreign-owner
negative controls. Timestamp local removal and router/PBR removal separately.
Prove lease expiry while ordinary FlowSpec/blackhole and another scrubber profile
continue renewing. Confirm a non-target router never receives diversion.
Exercise stale router state after BGP/zebra crashes and record any required
operator cleanup. No FRR result is a Cisco, Juniper, arbitrary GRE, capacity,
failure-time or production-scrubbing guarantee.

## Consequences

Direct target-address diversion has a concrete delivery path but remains later
work. The first product slice is manual and narrow; it cannot be shipped as a
small action-enum extension. Health and lease isolation add real implementation
work, while the existing writer, ownership, fence and immutable withdrawal
patterns provide reusable foundations. A stopped controller can eventually stop
attracting traffic only when the speaker lease and router cleanup both work as
qualified. Scrubbing effectiveness and clean delivery remain separately measured
operator evidence.
