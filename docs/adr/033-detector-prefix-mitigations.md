# ADR 033: Guarded Detector-Driven Prefix Mitigations

## Status

Proposed 2026-11-13. Extends [ADR 004](004-destination-prefix-32-only.md),
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
before a detector may send a non-host destination. The source allowlist is an
exact match against the authenticated event's `source`; an empty list refuses
all prefix events. A prefix event cannot select an action, rate, owner,
community, VPN scope or speaker. The detector supplies the destination and
traffic attributes only.

The existing `/v1/events` and batch event `victim_ip` field accepts an exact
IPv4 or IPv6 CIDR only when both controls permit it. A bare address keeps its
existing host meaning. A CIDR with host bits set is refused with the canonical
network named in the error; it is never silently widened. IPv4 and IPv6 use the
same field and the existing prefix bounds.

This is an additive API extension. Older controllers reject the CIDR as an
invalid IP; they do not reinterpret it as a host or install a wider global
rule. A detector that needs this feature must target a controller that
advertises the capability in its authenticated health/documentation and must
not retry a rejected prefix event as a host event.

`unban` continues to correlate by external event ID and withdraws what the
original event created. A prefix ban and its unban must use the same source
and event ID; matching a new host address to a prefix mitigation is not
supported.

### 2. Scope-specific playbooks

Add `match.scope: host | prefix` to playbook matching. Omission means `host`,
so existing playbooks and host events are unchanged. A prefix event selects
only a `scope: prefix` playbook; a host event selects only a `scope: host`
playbook. There is no fallback from one scope to the other.

A prefix playbook must set `require_top_ports: true` and its first step must be
`police` or `discard` with a nonzero rate where required. The first slice
refuses `blackhole` steps and multi-rule `rules` steps for prefix playbooks.
It also refuses prefix playbooks for vectors that cannot produce a port match
in this model (`icmp_flood` and `unknown`). An unsupported step is a
configuration error, not a runtime fallback.

A prefix event must contain at least one destination port. The resulting
FlowSpec match is the canonical destination prefix plus the event's protocol
and destination-port list. A protocol-only prefix rule and a bare
`dest=<prefix> -> discard` are refused. If the detector or playbook cannot
produce a port, the event is rejected; prefixd does not substitute a broader
rule or an RTBH action.

### 3. Admission sequence

Every detector prefix event passes these checks before persistence or any
speaker mutation, in both dry-run and enforced mode:

1. Parse and canonicalize the destination; reject host bits, mixed forms and
   malformed families.
2. Require `allow_detector_prefix`, an allowlisted source and the event action
   `ban`. Reject a prefix `unban` without a matching original event ID.
3. Apply the existing destination bounds: the prefix length must be within
   `guardrails.dst_prefix_minlen`/`dst_prefix_maxlen` (and the IPv6 variants).
   These default to host-only, so relaxing them is a deliberate operator act.
4. Attribute the entire CIDR through `Inventory::lookup_prefix`. It must be
   contained in one customer prefix and must not contain or overlap another
   customer's configured prefix or asset. An ambiguous or partial inventory
   read refuses admission.
5. Refuse every safelist overlap, including a protected host inside the
   destination. A failed safelist read refuses admission.
6. Require a protocol and at least one destination port after the existing
   allowed-port intersection. Reject an empty or non-canonical port set.
7. Apply the existing TTL, action, rate, source-prefix, fragment,
   packet-length, authorization, operation-mode, duplicate and immutable
   withdrawal rules. A prefix rule consumes one existing quota slot and one
   creation-rate slot.
8. In addition, enforce `quotas.max_active_prefix_per_customer` for non-host
   FlowSpec rules. This is a separate budget from the total per-customer
   quota; the default is five and zero is invalid. The existing POP and global
   quotas still apply.

The same checks run on reconciliation and repair. A later safelist or
ownership change withdraws the whole affected rule through the existing
durable withdrawal path; it does not split or replace the prefix with host
rules. Reconciliation must never restore a broad rule that no longer passes
ownership, safelist or prefix-length checks.

### 4. Aggregation remains the detector's responsibility

The detector must send the most-specific covering prefix it has evidence for,
for example the attacked `/26` or `/24` rather than a whole `/22`. prefixd
does not merge host events into a prefix, maintain a sweep-merge parent, or
split a prefix back into host rules. In-controller aggregation would need a
stable parent identity, merge/unmerge rules, overlapping-owner handling and a
withdrawal model for a rule that never existed as a single admission; that is
outside this decision.

A detector that only reports individual hosts may still send host events under
the existing host path. Operators must configure detector-side hostgroup or
network aggregation before expecting prefix mitigation.

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
- **Router qualification.** A local RPC acknowledgement or read-back does not
  establish prefix matching or installed forwarding on a router.

## Consequences

A detector can now produce one guarded prefix FlowSpec rule, avoiding a
per-host rule explosion while retaining inventory, safelist, quota, TTL and
withdrawal controls. Host-only deployments are unchanged because the feature
requires three explicit opt-ins: the guardrail flag, a source allowlist entry
and a relaxed prefix minimum.

The first slice deliberately refuses cases that have no safe narrow match:
protocol-only prefixes, ICMP/unknown vectors, RTBH and detector aggregation.
Those refusals are visible at admission rather than being hidden behind a
broader rule. The detector must supply a useful prefix and port signal.

Prefix rules are a compatibility surface. Older controllers reject CIDRs;
older dashboards display the stored CIDR but do not create them. Document the
capability before detector onboarding and never fall back to a host event.

## Qualification

Unit and integration tests cover both families, canonicalization, host-bit
rejection, the guardrail and source allowlist, whole-prefix ownership,
safelist overlap, missing ports, blackhole/rules refusal, dry-run parity,
quota and creation-rate behavior, batch ingestion, duplicate events, unban by
event ID, immutable withdrawal and reconciliation after a safety change.

Speaker fixtures must show the exact prefix + protocol + port rule through
add, local read-back, export observation and delete. Router installation and
traffic matching still require dated FRR and ASR9900 receipts for the exact
component combination. Do not claim ASR9900 support from FRR results.
