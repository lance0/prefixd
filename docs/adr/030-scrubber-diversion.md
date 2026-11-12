# ADR 030: Guarded Diversion to an External Scrubber

## Status

Accepted 2026-11-02, with the decision recorded below. Proposed 2026-10-22;
manual runtime implemented 2026-11-01 behind disabled-by-default
profiles. rustbgpd v0.81.0 supplies the guarded speaker contract. The controller
implements persisted admission snapshots, independent owners, authenticated
readiness, withdrawal latching and manual re-arm. Exact router/scrubber forwarding
qualification remains a separate gate. See the
[operator workflow](../how-to/scrubber-diversion.md). Addresses
[the redirect-to-IP request](https://github.com/lance0/prefixd/issues/305).
Extends [ADR 025](025-pluggable-speaker-backends.md) and
[ADR 027](027-blackhole-mitigations.md); complements
[ADR 029](029-upstream-blackholing.md).

The [symmetric return-leg amendment](#amendment-symmetric-return-leg) was
accepted on 2026-11-12 and implemented behind the optional profile `return_leg`.
Its speaker and controller gates pass on rustbgpd v0.81.0 and v0.82.0; its
forwarding gate remains open.

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

## Decision

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
Confirmed absence requires the
[pending-mutation barrier](../project/scrubber-diversion-contract.md#finalize-withdrawal-behind-a-pending-mutation-barrier):
prevent outstanding adds from committing, then complete a final recorded-owner
and admission-revision delete and complete inventory read. A delayed delete
must not remove a newer admission using the same match and owner. An initial
delete acknowledgment or absence read cannot release victim exclusion or
authorize re-arm while an old add is
still permitted to recreate the rule.
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

Carry the same pending-mutation barrier through explicit withdrawal, TTL expiry,
target/profile changes, configuration drain and rollback. Keep durable pending
intent and victim exclusion until outstanding adds are invalidated or their
authorization expires, then confirm final local absence. Add/read/delete carry
an immutable admission revision distinct from the shared owner lease generation;
deletion compares it at commit, so old retries cannot delete a newer rule at the
same key and owner. An upstream drain alternative must prove every outstanding
delete is server-invalidated or otherwise unable to commit before key reuse.
Preserve each withdrawal's original intent and revision. Do not terminate a
legitimate same-owner sibling merely to establish these per-rule barriers.

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

These are the acceptance gates for each slice. Slices 1 to 4 are implemented
for rustbgpd v0.81.0 behind disabled-by-default profiles. Slices 5 and 6 remain
open. The feature stays disabled until the required gates for its
family/backend/profile pass.

The [speaker contract and qualification plan](../project/scrubber-diversion-contract.md)
records the 2026-10-23 released-contract audit, canonical target-action vectors,
rollback refusal and concrete queued-mutation acceptance cases for slice 1.
Its [coverage table](../project/scrubber-diversion-contract.md#qualification-coverage)
records which cases prefixd and rustbgpd tests cover and which remain open. It
supplies no forwarding qualification.

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

## Amendment: symmetric return leg

**Status:** Accepted 2026-11-12. Implemented for global IP-target profiles;
the R9 speaker and controller gates pass and the forwarding gate is open. It
extends the decision above and changes none of it for profiles without a
return leg. Four choices are settled:

- The return leg is tagged with a required `export_community`, and the speaker
  contract does not change.
- A return leg may overlap other hosts' destination rules, provided the
  forwarding receipt includes a router-precedence control.
- A pair counts as two rules against quotas.
- A profile with a return leg refuses a request that omits the protocol.

### Context

A stateful scrubber that validates TCP handshakes must see both directions of
a connection. Section 2 keeps clean return traffic outside the redirect's
ingress scope, so the scrubber sees the client's SYN and ACK but not the
victim's SYN-ACK. An operator then needs two rules for the same victim:

| Router | Rule |
| --- | --- |
| A, internet ingress | `destination 203.0.113.1/32 → redirect 192.0.2.99` |
| B, client side | `source 203.0.113.1/32, tcp-flags syn-ack → redirect 192.0.2.99` |

UDP and other protocols need only the inbound leg. This amendment adds the
second rule as an optional **return leg**. Both legs belong to one diversion
and use the lifecycle in sections 3 and 4. The optional flags selector uses
the canonical TCP-flags match from the FlowSpec match model. That match is
defined separately, and this amendment does not fix its field name or
encoding.

The amendment stays in this ADR because the return leg adds no separate
mechanism. It reuses this ADR's profile, readiness, owner, window, latch and
drain rules, and adds the rules that apply to a pair. ADRs
[004](004-destination-prefix-32-only.md), [027](027-blackhole-mitigations.md)
and [028](028-amplification-matches.md) record amendments in the same way.

### R1. Configure the return leg on the profile

A global IP-target profile can carry an optional `return_leg`:

```yaml
    - id: scrubber-a
      revision: qualified-v2
      ipv4_target: 192.0.2.99
      router_peers: [192.0.2.2]        # router A
      policy_binding: ingress-only-v2
      # ...other fields as in the manual workflow
      return_leg:
        router_peers: [192.0.2.3]      # router B
        policy_binding: client-side-only-v1
        export_community: "64496:100"
        tcp_flags: syn_ack             # optional
```

- **Target.** The return leg uses the profile's existing `ipv4_target` or
  `ipv6_target`. It has no target field of its own, because one scrubber must
  see both directions.
- **Router peers.** `router_peers` lists the routers that receive return-leg
  rules. It is non-empty and validated like the inbound peer list. The two
  lists may overlap when one router carries both legs on different
  interfaces. prefixd cannot observe interface scope, so the qualification
  receipt must cover that topology.
- **Policy binding.** `policy_binding` names the operator's speaker export
  policy revision for the return leg. The monitor echoes it, as for the
  inbound binding.
- **Export community.** `export_community` is a required standard community
  (`ASN:VALUE`) that prefixd attaches to every return-leg rule. The speaker's
  export policy can match communities on FlowSpec routes, but it cannot match
  NLRI shape or owner. The community is therefore what lets the policy send
  return-leg rules only to the return peers and deny them toward the inbound
  peers. Inbound-leg rules carry no new attribute, so their bytes do not
  change. The community must not be a well-known community, and it must
  differ from any community the profile's scope or ordinary FlowSpec
  attaches.
- **TCP flags.** `tcp_flags` is optional. When set, it accepts only
  `syn_ack`: a SYN+ACK selector expressed with the canonical TCP-flags match
  from the FlowSpec match model. When omitted, the return leg matches all of the victim's TCP
  traffic from the mirrored ports. This is gateway-style symmetry and puts more
  load on the scrubber. No request, detector or playbook supplies or widens
  this selector, so it does not depend on whether request-supplied TCP-flags
  matches are enabled.

`return_leg` is refused on VPN-scoped and redirect-to-VRF profiles. VPN return
legs are out of scope.

`ProfileSnapshot` gains an optional `return_leg` holding all four fields. It
is serialized only when present, so snapshots without a return leg compare
equal to existing rows. Every admission freezes this snapshot. Adding,
removing or changing `return_leg` requires a new profile `revision`. Startup
refuses the change while the profile has outstanding diversion, as for any
other change to the frozen snapshot.

### R2. Rule shape

The controller derives the return leg from a validated inbound leg. A request
never names it, and it is never admitted alone. For an inbound match with
victim `V`:

| Inbound leg | Return leg |
| --- | --- |
| `dst_prefix` `V/32` or `V/128` | `src_prefix` `V/32` or `V/128` |
| no `src_prefix` | no destination component |
| `protocol 6` | `protocol 6` |
| `dst_ports P` | `src_ports P`, the same canonical list; absent when `P` is absent |
| | the profile's `tcp_flags`, when set |
| target `T`, owner `O`, revision `r` | target `T`, owner `O`, revision `r`, plus `export_community` |

- **Protocol decides whether a pair is created.** When a profile has a return
  leg, an inbound request with `protocol: 6` always creates a pair, because a
  stateful scrubber drops a TCP connection it can see in only one direction.
  Any other explicit protocol creates the inbound leg alone. A request that
  omits the protocol is refused, because an any-protocol inbound leg carries
  TCP without its return path.
- **Ports are mirrored exactly.** The return leg's ports are never wider or
  narrower than the inbound leg's. A wider return leg would send the scrubber
  SYN-ACKs for connections it never saw, and it would drop them.
- **Source-selected inbound legs are refused.** For a pair, the inbound leg
  must not carry `src_prefix`. Mirroring it would give the return leg a
  non-owned destination. Leaving it out would divert responses to clients the
  scrubber never saw. Source-selected pairs are deferred.
- **The destination is omitted, not `/0`.** The return leg has no destination
  component. That omission is distinct from an explicit `/0`, as ADR 031
  requires.

This shape breaks rules that stay in force everywhere else. ADR 028 permits
source ports only with UDP and defers TCP flags. ADR 004 and section 1
require a host destination. ADR 032 refuses global source-only rules and
source-only redirects. The exception is limited to diversion:

- `GuardedRule` validation accepts one additional shape, the return leg
  exactly as described above, with a host source and every other component
  absent. The domain invariant function in ADR 028 does not change. Manual
  mitigation, playbook and detector paths never produce this shape.
- The guarded read-back decoder accepts the return shape only under a
  scrubber profile owner, with exactly the configured community and the same
  admission revision as a durable row's return leg. An unexplained rule of
  that shape is untracked intent under the owner and follows section 4.
- Requests for global source-only rules stay refused under ADR 032.

Each leg's identity is its canonical NLRI hash, so the two legs never share a
speaker key. Receivers validate destination-less rules differently
([RFC 8955 §6](https://www.rfc-editor.org/rfc/rfc8955.html#section-6),
[RFC 9117](https://www.rfc-editor.org/rfc/rfc9117.html)). Router B's
acceptance is a qualification item, not a controller guarantee.

### R3. Admit, renew and withdraw a pair as one unit

**One row, one owner and one revision.** A pair is one `Diversion` row. The
row gains an optional `return_rule`, which is part of the immutable snapshot.
Both legs use the profile's existing owner. A second owner would allow one
leg's lease to outlive the other's, and it would double the profile's window
and renewal traffic. With one owner, the legs share the window, the lease
generation and the deadline, so a lost lease or a stopped controller removes
both together. Both legs carry the row's single admission revision. [rustbgpd ADR-0144](https://github.com/lance0/rustbgpd/blob/v0.82.0/docs/adr/0144-guarded-flowspec-mutations.md)
fences a revision per key, and the two keys differ, so one value cannot
delete a newer admission at either key. The existing unique
`admission_revision` column and the revision check in `save_diversion` keep
working unchanged.

**Admission.** The controller runs the existing serialized checks once for
the pair, then persists the row with both legs in `pending`. In one lifecycle
pass, it records the window durably and then sends both guarded adds under
that window: the return leg first, then the inbound leg. Adds for a pair are
never split across windows or passes. The row becomes `active` only when one
read-back shows both keys at the row's revision and owner, with the same live
generation. A pair is never partially active.

**Partial add.** If either add is refused or its outcome is unknown, the pass
records a failure for the whole row. As for any failed admission, the profile
latches and the row moves to `withdrawing` with its original actor, reason and
operation. The controller deletes both legs early and then waits on the drain
barrier: 30 seconds for this process's admissions or 120 seconds for any
other's. After the barrier, it deletes each leg again with the recorded owner
and revision, and requires one complete inventory read that shows both keys
absent. A leg that was never added returns `NOT_PRESENT`, which counts as
success for that leg. A row in `withdrawing` never enters the add path, so an
ambiguous add or delete is never resent as a fresh announcement. A partial
pair cannot resume: after the drain completes, an operator re-arms the profile
and admits the pair again with a new revision.

**Renewal and per-pass budget.** These do not change. Each pass reads the
guarded inventory once, uses at most one window and one renewal per owner,
and reads back once. The 12-second window-reuse margin is unchanged. The
renewal covers both legs because they share the generation. Each pass
re-checks the pair invariant. If one leg is missing, has a different revision
or generation, or has zero lease time remaining while the other leg is live,
the row fails, the profile latches and both legs drain. An operator using the
speaker's break-glass override on one leg therefore withdraws the pair.

**Withdrawal.** Explicit withdrawal, TTL expiry, loss of readiness,
configuration drain and rollback all withdraw the row, and therefore both
legs. The controller deletes the inbound leg first, then the return leg, in
the same pass. The first withdrawal reason and actor stay immutable for the
pair, and the immutable snapshot keeps each leg's exact rule, owner, target,
community and revision. The audit records both matches. If one leg's delete
is ambiguous, the row stays `withdrawing` and the controller retries that
delete with the same rule and revision. The other leg's repeated delete
returns `NOT_PRESENT`. Victim exclusion stays in place until the barrier has
passed and both keys are confirmed absent.

**Restart with one leg outstanding.** A new controller starts unarmed, and the
row belongs to a different controller incarnation. The controller therefore
waits the 120-second barrier and runs the same final exact delete and absence
read for both keys. The row's state decides what happens. Which leg survived
does not.

**Foreign and ordinary rules.** If another owner, or no owner, holds the
return key at admission, the admission is refused and nothing is deleted. All
deletes name the recorded owner and revision, so they cannot remove a foreign
rule. A foreign rule at a leg's key keeps withdrawal pending and visible. The
controller never finalizes the withdrawal by deleting that rule.

**Quotas.** Quotas budget rules on routers. A pair therefore counts as two
against `max_active` and the customer, POP and global caps. Creation rate
counts one admission. The speaker's per-owner key cap also counts two keys
for each pair.

**Dry-run.** Dry-run simulates both legs and sends nothing, as in section 4.

### R4. Export scope and evidence per leg

Each leg keeps its own export evidence. The row gains
`return_export_observation` next to `export_observation`. Both are mutable
lifecycle fields: they are excluded from the immutable-snapshot comparison
in Rust and in SQL. A committed export of the inbound leg to a peer outside
`router_peers` is a conflict. A committed export of the return leg to a peer
outside `return_leg.router_peers` is also a conflict. Either conflict fails
the row, latches the profile and drains both legs.

Export reads stay within the three-second budget, and each read is capped at
two seconds. A pair costs two reads. New pairs read both legs first, and
established legs rotate across passes. A slow or failed read leaves that
leg's evidence historical without latching the profile, as today. The
evidence layers in section 5 apply to each leg separately. `active` means
both legs were confirmed locally. It does not mean that either router
installed or forwarded either leg.

### R5. Victim exclusion and conflicts

Victim exclusion covers both legs. The live-victim unique index already
allows only one outstanding diversion per victim.

**Victim as destination.** The inbound leg keeps section 5's victim-level
exclusion unchanged.

**Victim as source.** This check is new. A pair is refused while any live or
pending mitigation, diversion or observed local rule has a source component
that contains `V`. Destination-less rules whose source contains `V` are
included. While a pair is outstanding, the same rules are refused admission.
Ordinary mitigation admission gains this check against outstanding pairs.

**Other destinations.** The return leg has no destination, so it overlaps every
destination-keyed rule for packets that `V` sends to that destination.
Refusing all of them would allow one pair per POP, so this overlap is accepted
on purpose, with these limits:

- It covers only `V`'s TCP traffic from the mirrored ports. With the `syn_ack`
  selector, it covers only `V`'s SYN-ACK responses.
- RFC 8955 §5.1 orders a rule that has a destination component ahead of one
  that does not, so another host's destination rule should take precedence.
  This ADR does not assume routers follow that order. The forwarding receipt
  must record it with an overlapping destination-keyed discard for another
  host as a control, before the return leg is enabled on that router.
- The local-inventory overlap index classifies the controller's own return
  legs by their source host, but only when owner, key, community and revision
  match a durable row. Every other destination-less rule keeps today's
  conservative treatment as affecting every victim of its family, so a
  foreign source-only rule still blocks diversion.

**Safelist.** The safelist check on `V`, run before every add and repair,
covers both legs. A safelist entry for `V` withdraws the pair. Safelisted
destinations do not block a return leg, because it selects `V`'s responses,
not traffic to the safelisted host's own services. Configuring `return_leg` on
the profile is the explicit authorization for that scope. Preview and
confirmation show the return leg as `destination: any`, together with its
ports, flags, peers and community. The confirmation string covers both legs
exactly.

### R6. Loop avoidance and readiness

Each leg follows section 2's rule. The scrubber's clean output for a leg must
re-enter outside that leg's FlowSpec ingress scope, or in a separate clean
routing domain. Clean return-leg output still has source `V` and the selected
flags. If it re-entered router B within the return leg's ingress scope, it
would be redirected again. The target route must not resolve through either
leg's ingress scope. The two legs cannot capture each other's clean output:
the inbound leg matches destination `V`, and the return leg matches source
`V`. prefixd provisions none of this routing and cannot prove it from BGP
state.

For a profile with a return leg, the monitor's report adds one required
object:

```json
"return_leg": {
  "policy_binding": "client-side-only-v1",
  "export_isolated": true,
  "canary_passed": true
}
```

- `policy_binding` must equal the frozen snapshot.
- `export_isolated` attests that return-leg rules reach only the return peers
  and inbound rules never reach them, unless a peer is configured in both
  lists.
- `canary_passed` attests that a canary TCP connection to a host behind the
  return routers completed its handshake through both legs, and that the
  scrubber saw each canary packet exactly once in each direction. Seeing a
  packet more than once indicates a loop.

The existing fields keep their meaning for the inbound leg and the shared
scrubber. A report that lacks the object for a return-leg profile is invalid.
So is a report that includes the object for a profile without a return leg.
Both make the profile `unknown`. Any failed check makes the whole profile
`not_ready`. The pair shares one readiness state and one latch, because a
stateful scrubber that keeps only one leg breaks the victim's TCP sessions.
Losing either leg's readiness drains both legs.

### R7. Migration and compatibility

- **Schema.** No migration. The return leg, its frozen profile fields and its
  export evidence live in `snapshot_json`. The `victim`, `admission_revision`
  and status columns keep their meaning. Admission and mitigation conflict
  queries gain the victim-as-source check against the JSON snapshot. The
  live-row bound is 1,000, so that check needs no index.
- **Older rows and profiles.** A row without `return_rule`, or a profile
  without `return_leg`, behaves exactly as it does today, with unchanged wire
  bytes, identities, snapshots and drain.
- **API and other surfaces.** `CreateDiversion` is unchanged. Diversion
  responses, `diversion_updated` events, profile listings, CLI output and the
  dashboard gain optional return-leg fields. When the fields are absent, the
  row has no return leg. The dashboard must show both legs and their separate
  evidence before the feature is enabled. Audit details add the return match
  and community. Metric labels do not change. `prefixd_scrubber_intents`
  keeps counting rows. OpenAPI, the API reference, the configuration reference
  and release notes change with the implementation.
- **Speaker.** The speaker contract does not change. In rustbgpd v0.82.0,
  `AddGuardedFlowSpecRequest.rule` is an `AddFlowSpecRequest`, which carries
  standard `communities`. The request requires only non-empty components in
  ascending order, so a rule without a destination is valid. FlowSpec export
  policy evaluates standard communities, and a rule without a destination has
  no prefix in the policy context. This is established from the contract, not
  from a live test, so the speaker gate in R9 must prove exact add, read-back
  and export in a live fixture. If that fixture fails on the pinned release,
  the minimum release is raised rather than gated by version. GoBGP stays
  unsupported for diversion.
- **Downgrade and rollback.** `Diversion`, `ProfileSnapshot` and the profile
  configuration all deny unknown fields. An older controller therefore
  refuses a configuration that contains `return_leg`, and it cannot read an
  outstanding pair row. An unreadable row latches every profile and blocks
  draining. Before downgrading:
  1. Withdraw every pair and wait for `withdrawn`, which means confirmed local
     absence of both legs.
  2. Remove `return_leg` from the configuration with a new revision.
  3. Verify router removal on both routers separately.

  Withdrawn pair rows stay in the table for audit. An older controller's
  outstanding-row queries skip them. Its detail endpoint cannot decode them.
  If an older controller starts with a pair still outstanding, it cannot renew
  the pair. The speaker lease removes both legs within the lease bound from
  section 4. The older controller treats the destination-less return leg as
  affecting every victim, which fails closed.

### R8. Out of scope

- Detector- and playbook-triggered diversion, which is tracked separately.
- VPN-scoped and redirect-to-VRF return legs.
- Return legs for UDP, ICMP or other protocols.
- Source-selected pairs.
- TCP-flags selectors other than `syn_ack`.
- Separate targets or scrubbers for each leg.

### R9. Qualification

The return leg stays disabled until all three gates pass for the exact
backend, router and scrubber:

| Gate | Acceptance |
| --- | --- |
| Speaker | A live released-daemon fixture proves guarded add, read-back, revision-fenced delete and peer receipt of the return shape, with exact component and community bytes, for each target family. It also proves that export policy matching the community sends the return leg only to its peers. An older daemon refuses the shape without changing state. |
| Controller | The fake speaker and the released-daemon tests cover these cases: both legs confirmed before `active`; refusal and unknown outcome of each add, in each order; ambiguous delete of each leg; restart with each single leg outstanding; a foreign rule at the return key; export outside each leg's peer set; one leg removed by the break-glass override; quotas counted per leg; victim-as-source conflicts in both admission paths; the return-leg overlap index; and a negative control showing that today's inventory index treats the return leg as overlapping every victim. |
| Forwarding | The section 5 receipt for both routers: router B's acceptance of the destination-less rule; installed rules and counters on each router; dirty and clean captures in both directions; handshake completion through a stateful scrubber; a loop negative control that re-enters clean return output inside router B's ingress scope; precedence against an overlapping destination-keyed discard for another host; a UDP diversion that creates no return leg; and removal timing for each leg on withdrawal, TTL expiry, readiness loss and controller stop. |

## Consequences

Manual direct target-address diversion is implemented behind disabled-by-default
profiles; router forwarding qualification remains a separate gate. The first
product slice is manual and narrow; it could not ship as a small action-enum
extension. Health and lease isolation add real implementation
work, while the existing writer, ownership, fence and immutable withdrawal
patterns provide reusable foundations. A stopped controller can eventually stop
attracting traffic only when the speaker lease and router cleanup both work as
qualified. Scrubbing effectiveness and clean delivery remain separately measured
operator evidence.
