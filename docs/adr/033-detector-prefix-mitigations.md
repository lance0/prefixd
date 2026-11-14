# ADR 033: Guarded Detector-Driven Prefix Mitigations

## Status

Accepted. Detector-driven prefix mitigation remains opt-in. Router installation, traffic matching, policing behavior and withdrawal/restoration require platform-specific qualification.

Proposed 2026-11-13 and accepted 2026-11-14. Amends
[ADR 004](004-destination-prefix-32-only.md) and extends
[ADR 010](010-signal-driven-architecture.md),
[ADR 012](012-playbook-policy-engine.md) and
[ADR 028](028-amplification-matches.md). This decision adds no detector,
built-in aggregation, prefix RTBH or automatic playbook escalation.

## Context

Carpet bombing spreads attack traffic across many addresses in a prefix. Each
host stays below its per-host threshold, while the aggregate saturates the link
and defeats host-only mitigation. One rule per victim address also risks
FlowSpec table exhaustion, so the useful response is one rule for the covering
prefix with a narrow Layer 4 match.

prefixd already permits manual destination CIDRs under [ADR 004](004-destination-prefix-32-only.md):
the caller supplies an exact, network-aligned CIDR, the whole prefix must belong
to one customer, any safelist overlap refuses it, and the rule consumes one
quota slot. Detector events and playbooks still construct host destinations.
The controller therefore cannot currently accept the prefix-level event that a
carpet-bombing detector must produce.

Detection remains external ([ADR 010](010-signal-driven-architecture.md)).
FastNetMon Advanced can detect traffic for a network/hostgroup and alert, but
its per-network hostgroup mode does not make a standalone BGP announcement;
total hostgroups and whole-subnet diversion are separate modes. prefixd must
not infer a prefix by merging unrelated host events, and it must not silently
turn an unowned or ambiguous address range into a broad discard.

## Decision

### 1. Opt-in detector prefix scope

Add `guardrails.allow_detector_prefix: false` and
`guardrails.detector_prefix_sources: []`. Both must be explicitly configured
before a detector may send a non-host destination. The allowlist is an exact
match against the event's `source` field; an empty list refuses all prefix
events.

`detector_prefix_sources` filters a label; it does not authenticate a detector.
The event endpoint authenticates the caller, and the caller then supplies
`source` in the request body. Every caller authorized to ingest events is
therefore trusted to supply that label honestly: any of them can send a prefix
event under an allowlisted `source`. The allowlist limits which labels may
request a prefix, not who sends them. This decision does not bind an
authenticated caller to a source label; deployments that need that separation
must restrict who holds event-ingestion credentials.

A prefix event cannot select an action, rate, owner,
community, VPN scope or speaker. The detector supplies the destination and
traffic attributes only. The controller's automatic `bgp.default_scope` (VPN)
still applies to a prefix rule exactly as it does to a host rule.

The existing `/v1/events` and batch event `victim_ip` field accepts an exact
IPv4 or IPv6 CIDR only when both controls permit it. A bare address keeps its
existing host meaning. A CIDR with host bits set is refused with the canonical
network named in the error; it is never silently widened. IPv4 and IPv6 use the
same field and the existing prefix bounds.

This is an additive API extension. Older controllers reject the CIDR as an
invalid IP; they do not reinterpret it as a host or install a wider global
rule. A detector that needs this feature must target a controller whose
authenticated `GET /v1/config/settings` response reports
`guardrails.allow_detector_prefix: true`, and must not retry a rejected prefix
event as a host event.

`unban` continues to correlate by external event ID and withdraws what the
original event created. A prefix ban and its unban must use the same source
and event ID; matching a new host address to a prefix mitigation is not
supported. An unban for an unknown prefix event ID returns 202 `not_found`,
as it does for a host.

### 2. Scope-specific playbooks

Add `match.scope: host | prefix` to playbook matching. Omission means `host`,
so existing playbooks and host events are unchanged. A prefix event selects
only a `scope: prefix` playbook; a host event selects only a `scope: host`
playbook. There is no fallback from one scope to the other.

A prefix playbook has exactly one step in this slice; a prefix playbook with
more steps is refused at load. The step must be `police` or `discard` with a
nonzero rate where required. The first slice refuses `blackhole` steps and
multi-rule `rules` steps for prefix playbooks. Prefix playbooks are accepted
only for `udp_flood`, `syn_flood` and `ack_flood`; every other vector,
including `icmp_flood`, `unknown` and `udp_amplification`, is refused at load.
A `udp_amplification` prefix event follows the existing amplification fallback
([ADR 028](028-amplification-matches.md)) and selects the `udp_flood` prefix
playbook. An unsupported step is a configuration error, not a runtime fallback.

A prefix `discard` requires at least one destination port and therefore
`require_top_ports: true`. `syn_flood` and `ack_flood` prefix police also
requires `require_top_ports: true`. Those vectors translate to TCP matches
without TCP-flag filters, so a portless rule would police all TCP to the
prefix, and even with a port the rule affects all matching TCP to that port.
TCP prefix police without a port is revisited only with a concrete required
rule and qualification evidence, possibly using TCP flags or another narrower
match. A bare `dest=<prefix> -> discard` is never installed.

A `udp_flood` prefix `police` may match protocol only, without a destination
port. This is an explicit exception the project approves; it is not an
operator-confirmed requirement. The recorded operator requirement was
protocol plus a port for prefix police and discard, and a playbook that sets
`require_top_ports: true` meets it. When ports are present, the resulting FlowSpec match is the
canonical destination prefix plus the event's protocol and destination-port
list. If an event cannot produce the port a playbook requires, no rule is
installed and the existing `accepted_no_playbook` response is returned;
prefixd does not substitute a broader rule or an RTBH action.

The exception has a collateral effect. A protocol-only UDP police rule is one
shared rate bucket for all UDP traffic to the whole prefix, legitimate traffic
included: DNS, QUIC and any other UDP service in the prefix are rate-limited
with the attack. Every host competes for the configured rate, so the rate must
reflect the prefix's normal aggregate UDP traffic, not one host's. Whether the
router allocates the policer per interface, per line card or per system is
router-specific and must be measured during qualification before any operator
relies on it.

A more-specific rule wins. RFC 8955 §5.1 orders FlowSpec rules by destination
prefix specificity, so a host rule for an address inside an active prefix rule
takes precedence for that host. prefixd admits host and prefix rules
independently and does not reconcile the overlap: a host event inside an
active prefix creates its own host rule, and that host's traffic then follows
the host rule's action instead of the prefix rule's.

### 3. Admission sequence

Every detector prefix event passes these checks before persistence or any
speaker mutation, in both dry-run and enforced mode:

1. Parse and canonicalize the destination; reject host bits, mixed forms and
   malformed families.
2. Require `allow_detector_prefix` and an allowlisted source for a prefix
   `ban`. A prefix `unban` correlates by source and event ID like a host
   unban; an unknown event ID returns 202 `not_found`.
3. Apply the existing destination bounds: the prefix length must be within
   `guardrails.dst_prefix_minlen`/`dst_prefix_maxlen` (and the IPv6 variants).
   These default to host-only, so relaxing them is a deliberate operator act.
4. Attribute the entire CIDR through `Inventory::lookup_prefix`. It must be
   contained in one customer prefix and must not contain or overlap another
   customer's configured prefix or asset. An ambiguous or partial inventory
   read refuses admission.
5. Refuse every safelist overlap, including a protected host inside the
   destination. A failed safelist read refuses admission.
6. Require a protocol. For `discard`, and for `syn_flood` or `ack_flood`
   `police`, require at least one destination port after the existing
   allowed-port intersection. For `udp_flood` `police`, an empty port set
   produces a protocol-only, rate-limited prefix match.
7. Apply the existing TTL, action, rate, source-prefix, fragment,
   packet-length, authorization, operation-mode, duplicate and immutable
   withdrawal rules. A prefix rule consumes one existing quota slot and one
   creation-rate slot.
8. In addition, enforce `quotas.max_active_prefix_per_customer` for
   detector-created prefix rules. This is a separate budget from the total
   per-customer quota; the default is five and zero is invalid. Manual CIDRs
   neither check nor consume it. The existing customer, POP and global quotas
   still apply to both.

Reconciliation and repair keep the saved destination scope and recheck
whole-prefix inventory ownership and safelist overlap. A later safelist or
ownership change withdraws the whole affected rule through the existing
durable withdrawal path; it does not split or replace the prefix with host
rules. Reconciliation never restores a prefix rule that no longer passes
ownership or safelist checks. It does not recheck prefix-length bounds:
tightening them refuses new admissions and extensions, while an active rule
runs until it expires or is withdrawn.

### 4. Aggregation remains the detector's responsibility

The detector must send the most-specific covering prefix it has evidence for,
for example the attacked `/26` or `/24` rather than a whole `/22`. prefixd
does not merge host events into a prefix, maintain a sweep-merge parent, or
split a prefix back into host rules. In-controller aggregation would need a
stable parent identity, merge/unmerge rules, overlapping-owner handling and a
withdrawal model for a rule that never existed as a single admission; that is
outside this decision.

FastNetMon Advanced's published total-hostgroup payload carries no port list,
so it can only reach a portless `udp_flood` police playbook. A native
FastNetMon hostgroup adapter is separate follow-up work; this decision and its
first implementation accept the controller event shape but do not complete the
FastNetMon integration.

A detector that only reports individual hosts may still send host events under
the existing host path. Operators must configure detector-side hostgroup or
network aggregation before expecting prefix mitigation. Correlation keeps its
existing `(victim_ip, vector)` key, so a prefix event forms its own signal group;
it does not join or corroborate a group for a host inside that prefix.

### 5. Explicit non-goals

- **Prefix RTBH and upstream propagation.** Blackholes remain host-only.
  Provider-scoped upstream blackholing is design-only in
  [ADR 029](029-upstream-blackholing.md) and cannot be reused as a fallback.
- **Redirect or scrubber diversion.** Detector events cannot select a scrubber
  profile or action target.
- **Automatic escalation.** Only the first playbook step is selected.
  `require_confidence_at_least` and `require_persistence_seconds` remain
  accepted configuration but do not drive progression.
- **Source-prefix selection.** Detector payloads still cannot select a source
  prefix; that remains a manual, opt-in match.
- **A new speaker contract.** The rule uses the existing global FlowSpec
  encoders. GoBGP and rustbgpd capability checks remain as before.
- **Reflection and amplification prefixes.** A `udp_amplification` prefix
  event that would match a reflector source port against random destination
  ports is not covered; it falls back to the `udp_flood` prefix playbook. A
  source-port prefix match for reflection is the obvious next slice.
- **Router qualification.** A local RPC acknowledgement or read-back does not
  establish prefix matching or installed forwarding on a router.

## Consequences

A detector can now produce one guarded prefix FlowSpec rule, avoiding a
per-host rule explosion while retaining inventory, safelist, quota, TTL and
withdrawal controls. Host-only deployments are unchanged because the feature
requires three explicit opt-ins: the guardrail flag, a source allowlist entry
and a relaxed prefix minimum. The source allowlist is a label filter, so every
authorized ingestion caller is trusted with prefix events under an allowlisted
label.

The first slice deliberately refuses cases that have no safe narrow match:
prefix discard without a destination port, TCP prefix police without a
destination port, ICMP/unknown vectors, RTBH and controller-side aggregation.
Prefix police without a port is allowed only for `udp_flood`.
Those refusals are visible at admission rather than being hidden behind a
broader rule. The detector must supply a useful prefix and port signal.

Prefix rules are a compatibility surface. Older controllers reject CIDRs;
older dashboards display the stored CIDR but do not create them. Document the
capability before detector onboarding and never fall back to a host event.

## Qualification

No router platform is qualified by this decision. Each claimed platform and
software version must show, in a dated receipt for the exact component
combination:

- the installed rules, as the router reports them;
- that matching traffic is affected and nonmatching traffic is not;
- the effective policing scope (per interface, line card or system);
- restoration of traffic after withdrawal.

FRR evidence cannot qualify ASR9900, and neither platform may be claimed from
another's results.

Unit and integration tests cover both families, canonicalization, host-bit
rejection, the guardrail and source allowlist, whole-prefix ownership,
safelist overlap, missing ports, blackhole/rules refusal, dry-run parity,
quota and creation-rate behavior, batch ingestion, duplicate events, unban by
event ID, immutable withdrawal and reconciliation after a safety change.

Speaker fixtures must show the exact prefix + protocol + port rule through
add, local read-back, export observation and delete. A speaker fixture does not
establish router installation or traffic matching.
