# ADR 004: Guard FlowSpec Destination Prefixes

## Status

Accepted; amended 2026-10-23 to permit explicit manual destination CIDRs.
The original 2026-01-15 decision required a single IPv4 host.

## Context

FlowSpec can match destination networks. IPv4 uses component type 1 in
[RFC 8955 section 4.2.2.1](https://www.rfc-editor.org/rfc/rfc8955.html#section-4.2.2.1);
[RFC 8956 section 3.1](https://www.rfc-editor.org/rfc/rfc8956.html#section-3.1)
extends that component to IPv6. A destination prefix and a destination port
can express one flow covering an attacked subnet. This differs from RTBH,
which discards all traffic to a host in prefixd's supported model.

Broad destination matches increase collateral impact. Automatic widening or
ownership inferred from the network's first address would make a subnet rule
unsafe, especially where customers or protected infrastructure share space.

## Decision

Keep default destination bounds at IPv4 `/32` and IPv6 `/128`. Detector events
and playbooks continue to construct host destinations. RTBH stays host-only.

Manual discard and police requests accept either a bare IP or an aligned CIDR
in the existing `victim_ip` string. An operator must deliberately relax the
existing `guardrails.dst_prefix_minlen` or `dst_prefix_minlen_v6` (and retain
appropriate maximum bounds) before a non-host destination can pass. No new
configuration flag, detector aggregation or route splitting is introduced.

- Reject destination host bits with a suggested network; never silently widen
  a supplied address. Canonicalize accepted CIDRs before computing new identity.
  Existing saved identities remain unchanged.
- Require the entire CIDR to fit inside one configured customer prefix. Refuse
  conflicting ownership within the range. Do not assemble ownership from a
  union of smaller allocations or infer a service from a base-address asset.
- Refuse every safelist overlap, including a protected host inside the CIDR.
  Failed safety reads fail admission. Adding a safelist entry withdraws the
  entire affected owned rule through durable withdrawal; it creates no split
  replacement. Reconciliation must not restore an unsafe broad rule.
- Preserve protocol, ports, source prefix and the optional components in
  [ADR 028](028-amplification-matches.md) and
  [ADR 031](031-source-prefix-matches.md), with their existing family,
  capability and opt-in requirements. Keep TTL, quota, authorization, operation
  mode, ownership and immutable withdrawal checks.
- Count rules for quota admission. One subnet rule consumes one slot; its
  policing rate applies to the matching flow across the destination, rather
  than granting the configured rate separately to every address.
- Display the complete prefix and match. CIDR reports select the exact stored
  destination and do not aggregate host events or link to base-IP history.

## Consequences

A manual port-specific mitigation can cover an owned subnet with one rule.
Deployments retain host-only behavior unless they change prefix bounds.
Relaxed bounds increase the possible blast radius, so operators must choose
scope and rate using their own evidence. Router receipt, matching, policing
and enforcement still require platform qualification; local RPC acceptance or
read-back establishes only the corresponding local speaker state.

TTL expiry needs the running controller. Drain CIDR rules and pending
withdrawals before downgrading to a controller that cannot preserve their
admission and repair checks.
