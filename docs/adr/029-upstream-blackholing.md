# ADR 029: Provider-Scoped Upstream Blackholing

## Status

Accepted 2026-10-24, with the decisions recorded below. Proposed
2026-10-20. Design only; upstream profiles and the API fields described below
are not implemented. Extends [ADR 027](027-blackhole-mitigations.md).
The existing unleased local blackhole opt-in remains as documented there.
This design requires owner-scoped leased injection for every enforced
upstream blackhole, including manual actions, before it can ship.

## Context

An operator with a saturated transit or exchange port needs filtering before
traffic traverses that port. Filtering only at their own edge cannot recover
that capacity. Upstream RTBH trades reachability of one victim for capacity
for the rest of the network. It drops legitimate traffic to that victim too;
it is not a clean-pipe service. Other ingress paths may remain attacked.

Commercial DDoS controllers commonly separate router filtering, upstream
blackholing and diversion to scrubbers, with per-target prefix restrictions,
capacity limits and an announcement archive. The useful pattern for prefixd is
an explicit, auditable choice of mitigation and target, with bounded scope.
Scrubbing and detection stay external.

The service contract differs between upstreams:

- [RFC 7999](https://www.rfc-editor.org/rfc/rfc7999.html) defines BLACKHOLE
  (`65535:666`). Its sections 3 and 6 leave honoring it to each operator,
  require prior agreement on a bilateral session, and have the receiver check
  that the announcer is authorized for a covering prefix and limit
  propagation, normally by adding `NO_EXPORT` or `NO_ADVERTISE` itself.
- [NTT's routing policy](https://www.gin.ntt.net/support-center/policies-procedures/routing/)
  documents `2914:666` for host routes covered by the customer's ingress
  filter. The service is not enabled by default.
- The [DE-CIX blackholing guide](https://docs.de-cix.net/article/ulhsfuqe47)
  uses `65535:666` at its route servers and says not to send `NO_EXPORT` or
  `NO_ADVERTISE`: either prevents redistribution. The route servers add
  `NO_EXPORT` themselves. Bilateral peering has a different next-hop procedure.

These are examples, checked 2026-10-20, not built-in provider presets or proof
that a particular account has service. The design must express those
differences without widening the victim prefix or leaking to other peers.

The [existing FRR receipt](../reference/qualification/blackhole-frr-2026-10-19.md)
already separates local RPC success from router discard, demonstrates eBGP
next-hop rewriting and records stale blackholes while the controller is down.
It does not qualify provider selection, a route-server topology or leased
expiry. Local blackholes now support owner-leased injection as ADR 027
describes; that foundation does not qualify the upstream lifecycle.

## Decision

### 1. One immutable upstream target set per victim and POP

Keep `blackhole` as the action. Add an explicit upstream scope and a required,
nonempty set of named profiles to a future manual request or playbook step.
No profile is selected by default, by detector-supplied communities, or just
because a peer is established. Existing requests retain local semantics.

Within a POP, one live blackhole row owns a victim host route, whether local
or upstream. A second request with a different scope or target set returns a
conflict and names the existing mitigation. It must not overwrite the route,
merge targets or shorten another actor's protection implicitly. Identical
targets may use the existing refresh path within TTL bounds. Changing targets
requires withdrawing the old mitigation, confirming absence and creating a new
one. This creates a protection gap that the operator must review deliberately;
there is no automatic retargeting. Local FlowSpec may coexist and keeps its
independent expiry.

At admission, persist the scope, sorted target profile IDs, profile revision,
resolved peer identities, provider community sets and export-policy selectors
alongside the existing owner, next hop and withdrawal intent. Configuration
reload changes new admissions only. Removing or repointing a profile with
outstanding intent is refused until that intent is drained. Per-provider
withdrawal from an active target set is deferred; the initial API withdraws
the complete snapshotted set.

Selectors and speaker policy bindings are revision-specific. Retain the old
selector, resolved peer set and export chain until every active route and
pending withdrawal using that revision has drained. Never repoint a live
selector to a new community set or peer group: storing the revision in the
database alone cannot freeze an external speaker's behavior. Coordinated
speaker reloads must preserve those bindings, and policy observation must
compare them with the recorded revision. An operator changing speaker policy
outside this procedure can alter live exports before prefixd detects it;
snapshots do not prevent that. Restrict policy-write access, alert on drift
and refuse new upstream adds while it is unresolved.

### 2. Per-POP profiles describe contracts; speaker policy selects peers

Each profile records:

| Field | Required meaning |
| --- | --- |
| Targets | Explicit peer addresses or a peer group resolved to a frozen peer set, expected remote ASN and session role (transit, bilateral or route server) |
| Authorized space | Inventory-owned covering prefixes that the upstream has agreed to accept; no detector can expand them |
| Prefix bounds | Minimum and maximum length per family; the first implementation still requires `/32` or `/128` |
| Communities | Provider-specific standard/large communities and explicit handling of propagation communities at egress |
| Next hop | Operator-reviewed egress rewrite or next-hop-self behavior and its tested family/transport combinations; the injected next hop stays ADR 027's nonzero discard address |
| Policy binding | A unique internal selector and a separately installed speaker export policy revision |
| Limits | Profile active cap, maximum TTL and new-admission rate, all nonzero; the cap must fit within the provider session's agreed max-prefix headroom |
| Qualification | Service activation reference, dated policy verification and lab receipt for that profile's topology |

A provider accepting only `/24` or `/48` is incompatible with this host-only
feature. Refuse it; never aggregate the victim and sacrifice unrelated hosts.
ROA/IRR and upstream authorization checks need an agreed blackhole exception
where appropriate. Do not recommend broadly increasing ROA `maxLength` to make
host blackholes pass; [RFC 9319 section 6](https://www.rfc-editor.org/rfc/rfc9319.html#section-6)
says not to create non-minimal ROAs for RTBH routes. See also the
[RPKI export-filter warning](../reference/speaker-backends.md#router-and-speaker-requirements).

prefixd must not mutate speaker policy on each attack. Inject one owner-leased
host route with internal selectors for its frozen target set. Each peer's
preinstalled export chain must:

1. Deny upstream blackholes unless the peer is an explicit target and the
   owner, family and victim-prefix constraints match the qualified policy.
2. Remove every internal selector and replace the trigger communities with
   exactly this profile's agreed set. This includes removing generic BLACKHOLE
   (`65535:666`) unless that profile explicitly lists it.
3. Apply the qualified next-hop and propagation behavior for this peer.
4. Deny these routes to all other peers, including customers, other POPs and
   ordinary transit peers. An unmatched selector must fail closed.

For example, a profile for [NTT's published blackhole service](https://www.gin.ntt.net/support-center/policies-procedures/routing/)
can select exactly `2914:666`, while a
[DE-CIX route-server profile](https://docs.de-cix.net/article/ulhsfuqe47)
explicitly selects `65535:666`. These remain operator-configured profiles,
with no hardcoded provider presets.

Host routes count toward the provider's maximum-prefix limit on that session,
and exceeding it usually tears the session down, dropping all transit or
peering traffic on it. Record the provider's configured limit in the profile
and refuse a profile whose active cap plus the session's normal announcement
count would not stay below it with agreed margin.

Profiles may not overlap on a peer in the first version. Reserve selectors
outside every public trigger set and prevent other injectors from supplying
them. A marker is a policy selector, not authentication: the exclusive speaker
target, authenticated injection owner and inventory checks remain mandatory.
If released speaker policy cannot enforce this contract, upstream admission
is unavailable; do not substitute a global permit policy.

The single injected route must not carry a union of provider trigger
communities or injection-time `NO_EXPORT`, `NO_EXPORT_SUBCONFED` or
`NO_ADVERTISE`. Providers needing a propagation restriction get it in their
own egress policy, after qualification. For a DE-CIX-style route server, the
profile intentionally leaves these communities for the receiver to add.
Never disable RFC 1997 interpretation globally to make one profile work.
Import-to-speaker and export-to-provider scoping must both be checked when an
intermediate edge router exists; no single-hop policy proof covers that path.

This policy boundary follows ADR 027 rather than introducing per-attack daemon
configuration. rustbgpd's
[configuration reference](https://github.com/lance0/rustbgpd/blob/1e0424918c39eb92a12a9c9c749d410eba3434d5/docs/reference/configuration.md)
documents RFC 1997 egress suppression and receiver BLACKHOLE scoping. Those
behaviors and export transformations need tests on the released version used;
this ADR does not claim a working policy configuration.

### 3. Bound the reachability tradeoff

Manual upstream RTBH requires Admin. The confirmation identifies the victim,
all target providers, affected POP, expiry and the fact that legitimate traffic
to the victim will be discarded on those paths. Detector use requires an
explicit upstream playbook step and an allowed source, in addition to existing
credential and corroboration checks. No automatic escalation is introduced.

Keep the existing lifecycle mutex, database controller fence, immutable
withdrawal operations and target ownership. Recheck inventory and safelist
immediately before every add or repair. Unknown or foreign routes are reported
and never overwritten or deleted. A policy mismatch or unreadable inventory
refuses new adds without abandoning pending withdrawals.

Upstream routes count toward blackhole quotas and stricter profile caps, not
FlowSpec filter capacity. Initial profile defaults are two active
victims, ten new admissions per minute and a 600-second maximum TTL; these
are conservative operator risk budgets, not measured capacity or provider
limits. They do not raise the existing POP/global blackhole limits. A
multi-provider route consumes one
blackhole slot and one slot in each selected profile, reserved atomically.
Refuse the complete upstream request if any profile cannot admit it; partial
provider coverage must not look like complete admission. Refreshes cannot
bypass the TTL cap or consume a new slot, and pending withdrawals retain slots.

Detector lifetimes must fit the configured cap. In the inspected FastNetMon
Community source snapshot `2436f447` (checked 2026-10-24), the
[configuration](https://github.com/pavel-odintsov/fastnetmon/blob/2436f447b9c2ba959eb3392bd3cf3c9efb14c94d/src/fastnetmon.conf)
defaults to a 1900-second ban and defers IPv4 unban while an attack continues.
Its [ban logic](https://github.com/pavel-odintsov/fastnetmon/blob/2436f447b9c2ba959eb3392bd3cf3c9efb14c94d/src/fastnetmon_logic.cpp)
does not periodically repeat a ban for an already banned IPv4 host. A reviewed
longer profile TTL (within the existing blackhole cap) or shorter detector ban
therefore does not establish compatibility by itself. Qualify sustained attacks,
each address family, watchdog timing and ban/unban callbacks against the actual
detector configuration. Conditional unban may outlast any fixed route TTL;
that needs a separately qualified refresh or operator-review workflow. Refuse
an incompatible playbook TTL and leave unqualified detector workflows disabled.
Never silently truncate the TTL or automatically re-ban after expiry: either
can leave the detector and route lifecycle disagreeing. Qualify the deployed
detector version rather than assuming every release matches this snapshot.

Require a nonzero TTL and a healthy, owner-scoped injection lease on manual
and detector paths. Probe the connected daemon's capability and make the leased
RPC authoritative; never fall back to unleased injection. The lease covers
controller liveness, not individual mitigation TTLs: the controller must still
expire each route through its normal TTL worker. Keep ADR 027's independent
renewal task; a database stall must not create an accidental withdrawal storm.
The stable owner, absolute expiry and withdrawal state survive restart. Lease
generation stays in memory and is recovered from the live daemon, as ADR 027
requires; a restarted speaker may have a new generation. Drain expired and
pending-withdrawal intent before replaying desired upstream routes on recovery.

An owner-wide lease is not a hard per-route lifetime bound while the controller
is alive. Both renewal and an unrelated leased add can extend the owner's
deadline. A stuck TTL worker can therefore leave an expired route advertised;
checking freshness only in the renewal task would not fix that. Surface expiry
backlog and controller-task failure separately from lease health, and include a
stalled-TTL-worker control in qualification. A hard speaker-enforced per-route
deadline would require a separate upstream contract and is not claimed here.

Remote expiry is not bounded by the injection lease alone. Graceful Restart or
LLGR can retain a stale route downstream after session loss. Each profile must
record a bounded provider contract or configuration and qualify the retention
behavior on its path, including the receiving member behind a route server.
State the bound's clock origin and measure failure detection, owner-lease
expiry, local removal and downstream removal separately. A stale-retention
timer measured from detected session loss is not an expiry bound measured
from the controller's stop or the mitigation's TTL.
Unknown or unbounded retention blocks that profile's enforcement qualification.
Prefer disabling GR/LLGR for a dedicated RTBH session or family when supported.
[RFC 4724 section 4.2](https://www.rfc-editor.org/rfc/rfc4724.html#section-4.2)
and [RFC 9494 section 4.2](https://www.rfc-editor.org/rfc/rfc9494.html#section-4.2)
make the restart timer alone insufficient: reconnection without End-of-RIB and
LLGR need separate bounds. `NO_LLGR` does not disable ordinary GR. A stale host
route can still override the covering aggregate despite a lower preference.
Qualification covers session loss, reconnection and missing End-of-RIB; a lab
receipt alone does not prove commercial-provider behavior. An operator can
withdraw early without relaxing any safelist or ownership check.

### 4. Tell the operator what is known

Show one row per selected provider under the mitigation, with observation time
and separate states for intended, locally accepted, locally exported, unknown
and failed. `ListAdvertisedRoutes` is local post-policy Adj-RIB-Out evidence;
it is not a remote acknowledgement. Paginate to completion and match prefix,
family, owner and expected attributes for that exact peer. A failed or partial
read is unknown, never a successful empty inventory. Session-up is separate.

The public wording is “export observed to provider”, not “provider is dropping
traffic”. Provider looking-glass or router evidence, if obtained separately,
gets its own source and timestamp. Even a remote BGP RIB entry does not prove
discard in its FIB or recovered customer traffic. Verify uplink utilization and
reachability independently; a decrease in traffic could be a detector outage.

Record the actor/source, victim, frozen target set, policy revision, quota
refusal, lease/TTL deadlines and all lifecycle transitions in the existing
audit path. Count admissions/refusals and export observation by bounded profile
and outcome labels. Avoid victim, arbitrary detector strings or operation IDs
as metric labels. If export is missing, surface an operational error and alert;
do not silently widen the prefix, select another provider or remove surviving
FlowSpec protection.

### 5. Qualification before enabling enforcement

Extend the isolated interop harness with two FRR provider receivers and an
unselected/customer receiver. A separate route-server leg must forward to a
member; a transit-only test cannot validate route-server semantics. Keep both
families and test IPv6 NLRI over the intended transport explicitly.

| Test | Required evidence and failing control |
| --- | --- |
| Target isolation | Only selected receivers learn the exact host; missing/wrong selector and a non-owned victim are refused or absent everywhere |
| Community isolation | Each provider sees exactly its own triggers, no internal selectors or other provider triggers; inspect raw Adj-RIB-Out and receiver JSON |
| Discard | Selected FRR import policy produces a blackhole kernel route; removing that policy makes the discard oracle fail |
| Route server | Member receives the host without injection-time propagation blockers; deliberately adding a blocker makes receipt fail |
| Admission | Test exhausted profile/global caps, concurrent controllers and full FlowSpec capacity without bypassing blackhole caps |
| Authorization | Non-Admin, unapproved source, safelisted victim, unsupported prefix lengths and missing lease produce no speaker mutation |
| Withdrawal | Explicit withdrawal, TTL, safelist addition, speaker restart and controller crash drain only owned state; inject RPC failures to prove immutable retries |
| Lease and staleness | Stop renewal with speaker alive, then lose the session with GR/LLGR enabled; test reconnection without End-of-RIB and measure local removal and qualified downstream retention separately |

Record dated versions, policy revisions, raw RIB/FIB evidence and negative
controls. Add a bounded packet test through FRR to distinguish control-plane
discard from forwarding, including an unaffected destination and recovery
after withdrawal. No FRR result claims commercial-provider acceptance.

## Decisions recorded — 2026-10-24

These decisions follow review of the operational tradeoffs:

1. **Profile defaults.** Use two active victims, a 600-second maximum TTL and
   ten new admissions per minute as conservative defaults. Provider limits
   and detector lifetime behavior still require explicit qualification;
   a FastNetMon TTL override alone is insufficient.
2. **Generic BLACKHOLE on transit.** The injected route still carries
   `65535:666`, as ADR 027 requires. The profile's community set replaces the
   generic one at egress; retain `65535:666` only when explicitly listed.
3. **First-version scope.** Withdrawal covers the whole target set only, and
   profiles may not overlap on a peer. Per-provider withdrawal and overlap
   are deferred. Changing targets requires deliberate review of the gap
   between withdrawal and new admission.
4. **Stale-route bound.** Require a documented, qualified bound for the
   profile's provider path, including its route-server member where applicable.
   Unknown bounds block that profile; a lease, restart timer or lab result
   alone does not prove the provider has removed stale state.

## Consequences and delivery

This gives operators a deliberate escape hatch for uplink saturation while
keeping provider behavior reviewable. It adds configuration and qualification
work, stricter admission and a complete-target withdrawal restriction. Losing
one target cannot be hidden behind the health of another.

The local unicast and owner-lease foundations have shipped under ADR 027.
Upstream implementation slices are: (1) qualification of those foundations and
revision-specific export policy on each upstream topology; (2) persisted
profiles, atomic reservations and immutable target-set lifecycle;
(3) authenticated manual API and operator confirmation;
(4) per-target export evidence, audits and alerts; (5) explicit detector
playbooks; (6) transit and route-server interop receipts. Every slice updates
its compatibility surfaces and downgrade procedure. Enforced upstream use
stays unavailable until the complete lifecycle and isolation tests pass.

External scrubbing diversion remains separate work: choosing RTBH never
promises to preserve service availability for the victim.
