# ADR 028: Amplification-Aware FlowSpec Matches

## Status

Accepted 2026-10-19, with the owner decisions recorded below. Slices 1 to 6
are implemented: the match model and identity, speaker encoding and
capability, guardrails, the vector and multi-rule policy, detector adapters,
and operator surfaces (manual API fields, dashboard, playbook editors and CLI).
Slice 7 is done: the
[FRR amplification receipt](../reference/qualification/amplification-frr-2026-10-19.md)
qualifies FRR 10.7.1's control plane for both speakers and families. It found
that FRR accepts at most five values per component and resets the session on
more, which the default `max_ports: 8` can produce. Extends
[ADR 012](012-playbook-policy-engine.md),
[ADR 019](019-signal-adapter-architecture.md) and
[ADR 025](025-pluggable-speaker-backends.md). It follows the identity
conventions of [ADR 027](027-blackhole-mitigations.md), and it leaves
[ADR 004](004-destination-prefix-32-only.md) unchanged: every rule still
matches one victim host.

## Date

2026-10-19

## Context

Reflection and amplification attacks are among the most common volumetric
attacks. An attacker spoofs the victim's address in small requests to
open UDP services, which then send larger responses to the victim. Two
properties make them hard to match with the rule shape prefixd has today:

- The attack is identified by the **UDP source port** of the abused service.
  The destination port is whatever the spoofed request used, so it is
  effectively random.
- Large responses arrive as **IP fragments**. RFC 8955 §4.2.2.4 says a port
  component "never matches" a fragment that is not the first, so a
  source-port rule cannot match the fragment tail of the same attack.

The current code limits mitigation to a coarser shape:

- `MatchCriteria` has only `dst_prefix`, `protocol` and `dst_ports`
  (`src/domain/mitigation.rs`). `FlowSpecNlri` mirrors it
  (`src/domain/flowspec.rs`).
- Policy builds a host prefix, derives the protocol from the vector, and uses
  event destination ports intersected with service ports (`src/policy/mod.rs`).
  For a reflection attack the only useful rule is therefore "police or drop all
  UDP to the victim". That rule also hits legitimate inbound UDP: DNS replies,
  QUIC, VoIP, gaming and VPN traffic.
- `AttackVector` has five values (`src/domain/event.rs`). Nothing in the event
  schema carries source ports.
- The rustbgpd encoder emits component types 1, 3 and 5 and caps destination
  ports at eight (`encode_match` in `src/bgp/rustbgpd.rs`). The GoBGP encoder
  emits the same three (`build_flowspec_nlri_v4`/`_v6` in `src/bgp/gobgp.rs`).
  Both decoders reject any other component, which fails the whole read rather
  than returning a partial inventory.
- `GuardrailsConfig` already has `allow_src_prefix_match`,
  `allow_tcp_flags_match`, `allow_fragment_match` and
  `allow_packet_length_match`, all defaulting to false
  (`src/config/settings.rs`). Nothing enforces them. `Guardrails::with_timers`
  only logs at debug level that they are "configured but not yet enforced"
  (`src/guardrails/mod.rs`), and the configuration reference says the same.
- Identity has three hashes. `MatchCriteria::compute_scope_hash` hashes the raw
  prefix string, the protocol byte and sorted, deduplicated port bytes.
  `FlowSpecNlri::compute_hash` uses the canonical prefix and sorted ports
  without deduplication. `ownership_key` deduplicates them
  (`src/domain/withdrawal.rs`). ADR 027 slice 1 pinned golden values for all
  three in `flowspec_identity_is_byte_for_byte_unchanged`. Reconciliation
  indexes observed rules by `nlri_hash` and confirms with
  `FlowSpecWriter::matches_nlri` (`src/scheduler/reconcile.rs`). The default
  `matches_nlri` compares only prefix, protocol and destination ports
  (`src/bgp/announcer.rs`).
- Playbook structs do not deny unknown fields (`src/config/playbooks.rs`).
  Neither does `MatchCriteria`. An older binary silently ignores keys it does
  not know, and ignoring a match key widens the rule, so any new key must make
  older binaries fail instead.
- FEATURES.md lists "Source-based filtering" as out of scope, and
  `allow_src_prefix_match` stays false in every shipped configuration.

## Decision

Add three optional match components (source ports, non-first fragments and a
packet-length range) and one generic vector, `udp_amplification`. A playbook
step can emit several single-rule mitigations from one event. Existing FlowSpec
identity, persisted rows and behavior do not change. TCP flags and source
prefixes stay out of scope.

### 1. Components

| Component | RFC type | Operator form | Canonical form | Decision |
|-----------|----------|---------------|----------------|----------|
| Source ports | 6 | `src_ports: [123, 389]` | Sorted, deduplicated equality list | In scope |
| Fragments | 12 | `fragment: non_first` | IsF bit with the match bit set | In scope, opt-in |
| Packet length | 10 | `packet_length: {min: 468, max: 65535}` | One inclusive range, `>=min & <=max` | In scope, opt-in |
| TCP flags | 9 | none | none | Deferred |
| Source prefix | 2 | none | none | Stays excluded |

**Source ports: an equality list, not ranges.** Reflector services listen on
discrete well-known ports, so the matched set is a short list. Equality terms
share one canonical form on both speakers, and the existing destination-port
code already uses that form. *Alternatives:* operator ranges (rejected: no
reflector in the library needs one, and a range is easy to widen by mistake,
for example `>=1` matching every source port); destination-port style
exclusions (rejected: FEATURES.md already records that adapters do not encode
"except" rules).

**Fragments: only `non_first` (IsF).** RFC 8955 §4.2.2.12 defines four bits:
DF (bit 0x01, Don't Fragment set), IsF (0x02, fragment offset is not 0), FF
(0x04, offset 0 with MF set) and LF (0x08, offset not 0 with MF clear). RFC
8956 §3.6 keeps LF, FF and IsF for IPv6 at the same positions and makes bit
0x01 reserved: it "MUST be set to 0". The reasons for the choice:

- The first fragment carries the UDP header, so the source-port rule already
  matches it. Only the tail needs its own rule, and IsF is exactly the tail.
- LF is a subset of IsF and would miss middle fragments.
- FF alone selects the half the port rule already covers.
- "Any fragment" (IsF or FF, with the match bit clear) would also catch the
  first fragment of legitimate traffic, which carries ports and does not need
  this rule.
- DF says nothing about amplification. It is invalid for IPv6, and some
  routers do not support it (see section 7).

The bitmask is encoded with the match bit set (`(data AND 0x02) == 0x02`). For
one bit, this is the same as the any-bit form. It is the only form rustbgpd's
injection parser emits (`parse_bitmask_value` always sets `match_bit`), so both
speakers send the same NLRI. prefixd never encodes bit 0x01, so the IPv6
reserved bit cannot be set. Neither speaker checks it.

**Packet length: one inclusive range.** RFC 8955 §4.2.2.10 measures "total IP
packet length (excluding Layer 2 but including IP header)". RFC 8956 applies
that definition to IPv6 without restating it. A lower bound helps against
protocols whose responses are large, such as memcached or CLDAP. It is only
allowed together with source ports. Length alone is a poor discriminator:
QUIC Initial datagrams are padded to at least 1200 bytes (RFC 9000 §14.1),
and EDNS0 DNS responses are often large, so "UDP of at least N bytes" hits
legitimate traffic. *Alternative:* several ranges per rule (rejected: one range
covers the use case, and routers limit range terms, see section 7).

**TCP flags: deferred.** SYN and ACK floods are not reflection attacks.
Matching SYN alone drops legitimate connection attempts, and router support is
partial (section 7). TCP reflection, such as SYN-ACK floods, needs its own
decision with evidence. `allow_tcp_flags_match` stays reserved.

**Rule invariants.** Policy, the manual API and playbook validation all apply
the same invariants, enforced in one domain function:

- Source ports, fragments and packet length all require `protocol = 17` (UDP).
- Source ports and `fragment` never share a rule. RFC 8955 §4.2.2.4 says port
  components never match a non-first fragment, so the combination matches
  nothing, and a rule that silently matches nothing is a failed mitigation.
  Some routers also refuse the combination (section 7).
- `packet_length` requires `src_ports`. The range must be well formed:
  `min <= max <= 65535`, and `min` must be larger than the smallest IP plus UDP
  header (28 bytes for IPv4, 48 for IPv6).
- An empty `src_ports` list means the component is absent. Policy never
  produces an empty list from nonempty detector input, as it already does for
  destination ports (`NoAllowedPorts`).
- The destination prefix stays an IPv4 `/32` or IPv6 `/128` victim.

**IPv6.** RFC 8956 §3.3 matches type 3 on "the first Next Header value octet
in IPv6 packets that is not an extension header", and its §7 notes that
implementations may fail to locate the upper-layer header. Whether a router
matches `protocol = 17` on an IPv6 non-first fragment is therefore
implementation-dependent. prefixd emits the same rule shape for both families
and treats this as a router qualification item. It does not drop the protocol
component, because that would widen the rule.

### 2. Per-speaker encoding

These were checked against the rustbgpd source at version 0.78.0 (and the
injection parser at the `v0.76.0` tag), the vendored `proto/rustbgpd.proto`,
and the GoBGP `v4.10.0` tag source (`pkg/apiutil/attribute.go`,
`pkg/packet/bgp/bgp.go`).

| Component | rustbgpd `AddFlowSpec` / `DeleteFlowSpec` | rustbgpd read-back (`ListFlowSpecRoutes`) | GoBGP 4.10.0 `AddPath`/`DeletePath` | prefixd today |
|-----------|---------------------------------------|-------------------------------------------|-----------------------------------|---------------|
| Source ports (6) | `FlowSpecComponent{type: 6, value: "=53, =123"}`. Parsed by `parse_numeric_value` (comma means OR, `&` means AND) into `SourcePort` | `"==53, ==123"` (`format_numeric_ops`) | `FlowSpecComponent{type: 6, items: [{op: 0x01, value: 53}, {op: 0x01, value: 123}]}`. `UnmarshalFlowSpecRules` builds a generic `NewFlowSpecComponent` for any numeric type and sets end-of-list itself | Not encoded; both decoders reject it |
| Packet length (10) | `value: ">=468 & <=65535"` into `PacketLength` | `">=468 & <=65535"` | items `[{op: 0x03 (gt, eq), value: 468}, {op: 0x45 (and, lt, eq), value: 65535}]`. `NewFlowSpecComponentItem` picks the value width | Not encoded |
| Fragment (12) | `value: "0x02"` into `Fragment`, always with `match_bit` set | `"0x0002/match"` (`format_bitmask_ops`) | items `[{op: 0x01 (match), value: 0x02}]` | Not encoded |
| TCP flags (9) | Encodable (`parse_bitmask_value`) | `0x....` bitmask form | Encodable (raw op byte) | Deferred |
| Component order | Must be strictly ascending, and the daemon does not reorder (proto comment on `AddFlowSpecRequest.components`) | Ascending | `NewFlowSpecUnicast` sorts components by type | Emits 1, 3, 5, 6, 10, 12 in order |
| IPv6 fragment bit 0x01 | Not validated | n/a | Not validated | Never emitted |
| Size bound | Rules over 4095 NLRI bytes are refused (`validate_encoded_len`) | n/a | n/a | Port lists bounded by guardrails |

Both bundled speakers can therefore encode all three in-scope components, in
both families. GoBGP read-back reports raw operator bytes, including the
end-of-list and length bits, so its decoder masks the length bits as it already
does for destination ports. The rustbgpd decoder accepts only the exact
canonical strings above. Each decoder accepts only the forms prefixd emits. Any
other operator, term count or bit fails the whole read, as today. GoBGP's
read-back is its accepted local RIB after import policy, not retained intent
(ADR 025).

**Capability gate, never a silent drop.** Dropping a component widens the rule,
so an adapter that cannot encode a component must refuse it. The existing
capability model is `SpeakerCapabilities` in `src/bgp/announcer.rs`: optional
observation booleans with `#[serde(default)]`, derived from
`FlowSpecAnnouncer` accessors and extended by ADR 027 with `blackhole`.
Extend it the same way:

- `FlowSpecAnnouncer::match_support() -> FlowSpecMatchSupport` returns
  `{source_ports, fragment, packet_length}` booleans. The trait default is all
  false, so a future adapter refuses until it opts in.
- `SpeakerCapabilities` gains a `flowspec_match` object with those three
  fields, all serde-defaulting to false. It reports availability, not success.
- Startup, playbook load or save, and manual creation refuse a playbook step
  or request that uses a component the selected speaker does not support. The
  check runs in dry-run and enforced modes, so a dry run predicts enforcement.
- Every encoder also refuses an unsupported component before any RPC
  (defense in depth). A daemon that does not know a type fails loudly:
  rustbgpd's parser returns `INVALID_ARGUMENT` for an unknown component type.

rustbgpd, GoBGP and the mock speaker report all three as true once slice 2
lands. A detected capability does not prove router support (section 7).

### 3. Identity

**Legacy rules keep their hashes byte for byte.** A rule with none of the new
components hashes exactly as today through all three functions. The slice 1
golden test from ADR 027 must pass unchanged.

**Extended rules use a domain-separated hash.** If any new component is present,
the scope hash, NLRI hash and ownership key all become one value: SHA-256,
truncated to 16 bytes as today, over the following input.

1. The tag `prefixd:flowspec-match:v2\0`.
2. The canonical prefix (`ipnet` display form) and `\0`.
3. Tagged, length-prefixed fields in RFC type order: `[3, protocol]`,
   `[5, n, ports...]`, `[6, n, ports...]`, `[10, min, max]` and `[12, mask]`.
   Each field appears only when present. Ports and lengths are big-endian
   `u16`.

Legacy hash input starts with the prefix string, and a valid prefix never
starts with `prefixd`, so no extended input equals a legacy one. This is the
same argument ADR 027 makes for `blackhole_identity`. It also avoids a subtler
problem: plain appended bytes would be ambiguous, because legacy port bytes
are themselves an unbounded sequence of `u16` values.

**Canonicalisation.** Port lists are sorted and deduplicated before hashing and
encoding. The packet-length range is stored as two required bounds, with no
open-ended form, so every range has exactly one representation. The fragment
component is an enum with one value. The manual API and playbooks accept these
forms, and the API echoes back the canonical one.

**`matches_nlri`.** The default implementation and the rustbgpd override must
compare every component in the same slice that adds the fields. Otherwise two
rules that differ only in source ports would be treated as the same route
during reconciliation and withdrawal. That slice adds a test showing two such
rules are distinct.

**Persisted data.**

- `MatchCriteria` and `FlowSpecNlri` gain `src_ports` (serde default empty,
  skipped when empty), `fragment` and `packet_length` (default `None`, skipped
  when `None`). Existing `match_json` and `withdrawal_requests.rule_json` rows
  parse unchanged. A legacy rule serializes to the same JSON bytes, which a
  round-trip test pins. No mitigation or withdrawal row is rewritten, and
  `match_json` needs no migration.
- Both structs gain `#[serde(deny_unknown_fields)]` in slice 1, so any later
  key fails closed on that binary and every newer one.
- Binaries older than slice 1 still ignore unknown keys. For them, protection
  comes from three places. Rows with the new vector fail `Mitigation::from_row`
  (`invalid vector`). Their decoders reject the new components, which fails
  the read instead of repairing. And the upgrade guide gets a downgrade
  procedure: withdraw every extended mitigation, drain its withdrawal requests,
  then downgrade. Without the procedure, such a binary would withdraw a
  pending request using the key without its new components. The speaker
  would answer `NOT_FOUND` (absent), and the real rule would be orphaned on the
  speaker.
- Events gain a nullable `top_src_ports_json` column (migration 017). `NULL`
  means the detector sent nothing, and `[]` means it sent an empty list.
  Replay rewrites no row, and the migration creates no announcement.

### 4. One response, several rules

A typical response is two rules for one victim: UDP from reflector source ports,
and UDP non-first fragments. The options:

| | (a) One mitigation, N rules | (b) N mitigations sharing a new group ID | (c) One rule per mitigation; the playbook emits several |
|---|---|---|---|
| Reconciliation | Breaks the row-to-rule mapping that `nlri_hash`, `ownership_key` and repair rely on | Unchanged | Unchanged |
| Immutable withdrawal | `rule_json` would hold N rules, with partial completion states | Unchanged | Unchanged, one request per rule |
| Ownership and scope index | `idx_mitigations_active_scope` would need a per-rule key | Unchanged | Unchanged |
| TTL extension | All or nothing | Per rule | Per rule, by scope, as today |
| Quotas | Undercounts router rules | Each rule counts | Each rule counts, which is the honest TCAM budget |
| API and UI | New nested shape everywhere | New column and filter | Additive `mitigation_ids`; rows linked by the existing `triggering_event_id` |
| Audit | One entry hides N changes | Per rule | Per rule, as today |

**Decision: (c).** Every rule keeps every invariant ADR 011, 025 and 027 depend
on. Rules from one event already share `triggering_event_id`, and
`signal_group_id` when correlated, so a new group column (b) duplicates
existing data. *Rejected:* (a) for the reasons in the table; (b) as redundant.

Consequences of (c):

- **Admission.** Each rule goes through guardrails and `admit_mitigation`
  independently, in playbook order. Admission is per rule, not all or
  nothing. Partial admission is accepted: every
  admitted rule is narrower than the all-UDP alternative and stands on its
  own. The event response lists the outcome of each rule (created, extended
  or rejected with a reason) and returns `202` when at least one rule was
  created or extended. If none was, it returns the first rule's error, as
  today. `EventResponse` gains `mitigation_ids`. `mitigation_id` remains the
  first created or extended rule, for existing callers.
- **Extension.** A refresh event extends whichever rules it reproduces exactly.
  If the reported port set changes, the new set is a new scope and becomes a
  new mitigation; the old rule runs out its TTL. Quotas and `max_new_per_minute`
  bound that churn. Identity is never mutated in place.
- **Withdrawal.** Rules are withdrawn individually. The FastNetMon unban path
  already withdraws every live mitigation for the victim. The dashboard shows
  sibling rules from the same event, but a combined "withdraw this response"
  action is out of scope.
- **Coexistence.** RFC 8955 §5.1 gives precedence to the rule with the lower
  component type at the first difference. Its Appendix A reference code gives
  precedence to the rule with more components when all shared components are
  equal. An amplification rule (types 1, 3, 6)
  therefore outranks a broader `udp_flood` rule (1, 3) for the same victim, and
  outranks the fragment rule (1, 3, 12). Rule ordering on a router is still a
  router behavior and is part of qualification.

### 5. Vectors, playbooks and the port library

**One generic vector.** Add `udp_amplification`, which carries source ports in
the event. *Alternative:* one vector per protocol (`ntp_amplification`, and so
on). It is rejected: `AttackVector` is a closed enum stored in the database, so
every new reflector would need a release, older binaries would reject the
value, and detectors do not agree on protocol names. The generic vector plus a
port library lets operators add a reflector by editing configuration. A
playbook that wants a single protocol uses a static port list (below).

`udp_amplification` maps to protocol 17 in both families. It is a new value in
the API enum, database text, metrics labels, the correlation grouping key and
the frontend union. Older binaries reject it, which is intended (section 3).

**Port library.** A new `amplification` section in `prefixd.yaml`:

```yaml
amplification:
  # Minimum share of sampled UDP packets for a source port to count,
  # where an adapter has samples (FastNetMon).
  min_src_port_share: 0.2
  # Optional. When absent, the built-in default below is used.
  # An explicit empty list disables event-derived source ports.
  reflector_ports:
    - { port: 123, name: ntp }
    - { port: 11211, name: memcached }
```

Policy intersects event source ports with the library. Ports outside it are
dropped and logged, because the library is the operator's statement of which
source ports are safe to match. Changes to the built-in default are release
notes. The section is exposed through the configuration allowlist.

Default library (each entry cites a public source that names it as a
reflection or amplification vector):

| Port | Service | Source |
|------|---------|--------|
| 17 | QOTD | [Rossow], Shadowserver [open QOTD](https://www.shadowserver.org/what-we-do/network-reporting/open-qotd-report/) |
| 19 | CharGen | [Rossow], Shadowserver [open CharGen](https://www.shadowserver.org/what-we-do/network-reporting/open-chargen-report/) |
| 53 | DNS | [Rossow], [CISA], Shadowserver [open resolvers](https://www.shadowserver.org/what-we-do/network-reporting/dns-open-resolvers-report/) |
| 111 | Portmap (rpcbind) | [CISA], Shadowserver [open portmapper](https://www.shadowserver.org/what-we-do/network-reporting/open-portmapper-report/) |
| 123 | NTP | [Rossow], [CISA] (CVE-2013-5211) |
| 137 | NetBIOS name service | [Rossow], [CISA], Shadowserver [open NetBIOS](https://www.shadowserver.org/what-we-do/network-reporting/open-netbios-report/) |
| 161 | SNMP | [Rossow], [CISA], Shadowserver [open SNMP](https://www.shadowserver.org/what-we-do/network-reporting/open-snmp-report/) |
| 389 | CLDAP | [CISA], Shadowserver [open LDAP](https://www.shadowserver.org/what-we-do/network-reporting/open-ldap-report/) |
| 427 | SLP | [CVE-2023-29552](https://nvd.nist.gov/vuln/detail/CVE-2023-29552), Shadowserver [accessible SLP](https://www.shadowserver.org/what-we-do/network-reporting/accessible-slp-service-report/) |
| 520 | RIPv1 | [CISA] (RIPv1 row); RFC 1058 §3.1 fixes the port |
| 1434 | MS-SQL resolution | Shadowserver [open MS-SQL resolution](https://www.shadowserver.org/what-we-do/network-reporting/open-ms-sql-server-resolution-service-report/) |
| 1900 | SSDP | [Rossow], [CISA], Shadowserver [open SSDP](https://www.shadowserver.org/what-we-do/network-reporting/open-ssdp-report/) |
| 3283 | Apple Remote Desktop | Shadowserver [accessible ARD](https://www.shadowserver.org/what-we-do/network-reporting/accessible-apple-remote-desktop-ard-report/) |
| 3702 | WS-Discovery | [CISA], Shadowserver [accessible WS-Discovery](https://www.shadowserver.org/what-we-do/network-reporting/accessible-ws-discovery-service-report/) |
| 5353 | mDNS | [CISA], [CERT/CC VU#550620](https://kb.cert.org/vuls/id/550620) |
| 5683 | CoAP | RFC 7252 §11.3, Shadowserver [accessible CoAP](https://www.shadowserver.org/what-we-do/network-reporting/accessible-coap-report/) |
| 10001 | Ubiquiti discovery | Shadowserver [open Ubiquiti](https://www.shadowserver.org/what-we-do/network-reporting/open-ubiquiti-report/) |
| 11211 | memcached | [CISA], [CVE-2018-1000115](https://nvd.nist.gov/vuln/detail/CVE-2018-1000115) |
| 33848 | Jenkins discovery | [CVE-2020-2100](https://nvd.nist.gov/vuln/detail/CVE-2020-2100) |
| 37810 | DVR DHCPDiscover | Shadowserver [open DVR DHCPDiscover](https://www.shadowserver.org/what-we-do/network-reporting/open-dvr-dhcpdiscover-report/) |

[Rossow]: https://www.christian-rossow.de/publications/amplification-ndss2014.pdf
[CISA]: https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks

[Rossow] is "Amplification Hell" (NDSS 2014), whose Table I lists ports per
protocol. The CISA alert names protocols and amplification factors but gives
ports only for memcached and WS-Discovery, so ports come from the other
sources.

Ports some proposals include but this default leaves out:

- **443 (DTLS).** It is also QUIC, so a source-443 rule drops the victim's
  HTTP/3 replies. The vendor advisory for DTLS amplification gives no port.
- **1194 (OpenVPN).** Small factor, and it hits VPN clients' own sessions.
- **69 (TFTP).** Replies come from ephemeral ports (Shadowserver), so the rule
  would not match.
- **27015 (Steam), 27960 (Quake 3), 3478 (STUN), 3389 (RDP over UDP).** They are
  sourced vectors, but legitimate game, WebRTC and remote-desktop replies come
  from the same ports.
- **BitTorrent and Kad.** No fixed port.
- **10074 (TP-240), 5351 (NAT-PMP), 30718, 5678, 623, 2362.** No neutral source
  ties the port to abuse. Operators can still add any of them.

DNS (53) is in the default even though its collateral is real. A victim that
resolves names through external resolvers loses those replies while a
source-port rule containing 53 lives. The configuration reference, the
detector guides and the shipped playbook example state this. An operator who
cannot accept it can police the source-port rule instead of discarding it,
remove 53 from the library, or safelist the victim. The shipped example polices
the fragment rule and discards only the source-port rule.

**Playbooks.** A step may carry `rules:` instead of a top-level action. Each rule
has its own `match` and `action`, and the step's TTL applies to all of them.
Narrowing components are valid only in playbooks whose vector is
`udp_amplification`. Older binaries fail closed twice on such a playbook: they
reject the vector, and they reject a step that has no `action`.

```yaml
playbooks:
  - name: udp_amplification
    match:
      vector: udp_amplification
    steps:
      - ttl_seconds: 300
        rules:
          - match:
              src_ports: from_event       # event ports intersected with the library
            # If 53 is reported, the victim's DNS replies from external
            # resolvers are dropped too until the TTL ends. Use police here,
            # or remove 53 from the library, if that is unacceptable.
            action: discard
          - match:
              fragment: non_first         # needs guardrails.allow_fragment_match
            action: police
            rate_bps: 20000000

  - name: memcached_reflection
    match:
      vector: udp_amplification
    steps:
      - ttl_seconds: 600
        rules:
          - match:
              src_ports: [11211]          # static list for one protocol
              packet_length: { min: 1000, max: 65535 }  # needs allow_packet_length_match
            action: discard
```

`src_ports` is either `from_event` or a static list. A static list need not be
in the library, because the operator wrote it, but it is still subject to the
guardrails.

**No usable ports falls back to `udp_flood`.** If a `from_event` rule ends up
with no ports, because the event had none or none were in the library, the
event is evaluated exactly as `udp_flood` today. The mitigation's vector is
`udp_flood`, and its reason records the fallback. An amplification event then
never leaves the attack less mitigated than today. *Alternative:* reject with
`422` like `NoAllowedPorts` (rejected: it would leave an attack unmitigated
because of a library gap). Escalation is still unreachable (ADR 027), so only
the first step is evaluated.

**Detector paths.** Event schema additions are compatibility surfaces and are
documented in the API reference.

- **`POST /v1/events`.** Optional `top_src_ports: [u16]`, at most 64 entries
  (otherwise `400`), ordered as the detector ranks them, plus
  `vector: udp_amplification`.
- **FastNetMon native JSON (`/v1/signals/fastnetmon`).** Its payload carries
  per-protocol counters, which `FastNetMonAttackDetails` already parses, and,
  when packets were sampled, `packet_dump_detailed`. That is an array of
  sampled packets with `source_port`, `protocol`, `fragmentation`, `length` and
  `packets` fields (`serialize_simple_packet_to_json` in FastNetMon's
  `fast_library.cpp`). prefixd ignores it today. The adapter adds:
  - Weight UDP samples by `packets`.
  - Select library ports whose share of sampled UDP packets is at least
    `min_src_port_share`.
  - If UDP is the dominant protocol and at least one port qualifies, classify
    the event as `udp_amplification` with those ports, ranked by share.
  - Otherwise keep the existing `classify_fastnetmon_vector` result.
  - With no dump, nothing changes.
- **FastNetMon Community notify script.** On ban, FastNetMon writes this to the
  script's stdin: `IP: ...`, the serialized attack description, then
  `Attack traffic dump` with one line per sampled packet, then `Flow dump`
  (`fastnetmon_logic.cpp`). Each packet line has the form
  `src:sport > dst:dport protocol: udp ... frag: N ... packets: P size: L bytes`
  (`print_simple_packet`). The number of lines is bounded by
  `ban_details_records_count`, which is 20 in the shipped `fastnetmon.conf`
  and 50 in the code default. These are samples, not a ranked attack summary.
  `scripts/prefixd-fastnetmon.sh` adds:
  - Sum sampled UDP packets per source port.
  - Send ports whose share meets `PREFIXD_SRC_PORT_MIN_SHARE` (default 0.2) as
    `top_src_ports`, with `vector: udp_amplification`. The script does not know
    the library: prefixd intersects, and the fallback covers an empty result.
  - Change nothing when the dump has no UDP lines.
  - On unban, FastNetMon sends no details, and the script already withdraws
    every live mitigation for the victim.
- **Alertmanager.** An optional `top_src_ports` annotation holds
  comma-separated ports. `labels.vector: udp_amplification` selects the vector.
  An unparseable annotation is a per-alert error, never an empty list.
- **Generic webhook.** An optional `fields.top_src_ports` JSONPath, extracted
  like `top_dst_ports`. A `vector_map` entry such as `NTP_AMP:
  udp_amplification` routes detector labels. The generic webhook guide's
  current example maps to `dns_amp` and `ntp_amp`, which are not vectors and
  fall back to `default_vector`. Slice 5 corrects it.

### 6. Guardrails

- **Port count.** `max_ports` (default 8) applies to each port list
  separately. A source-port list above it is rejected, never truncated. The
  rustbgpd encoder's eight-port cap applies to source ports too until a larger
  value is qualified on routers.
- **Packet-length sanity.** Section 1 invariants. A range that cannot match
  anything is rejected, not installed.
- **Fragments need opt-in.** `allow_fragment_match` (default false) becomes
  enforced. A playbook or request with `fragment` is refused when it is false.
  Discarding fragments hits legitimate traffic: large DNS/EDNS0 responses,
  UDP-encapsulated VPNs, and IPv6 paths that rely on fragmentation. Shipped
  examples therefore *police* fragments. Discard stays available, because the
  operator writes it explicitly.
- **Packet length needs opt-in.** `allow_packet_length_match` (default false)
  becomes enforced in the same way.
- **Source ports need no new flag.** They are allowed only under
  `udp_amplification` playbooks or explicit manual requests. Both are already
  operator opt-in, and the library bounds what detectors can supply.
- **Reserved flags.** `allow_src_prefix_match` and `allow_tcp_flags_match`
  stay parsed so existing configurations still load. Setting either to true
  logs a startup warning that the flag has no effect. The configuration
  reference says they are reserved. Renaming or removing keys would break
  configurations with no safety gain.
- **Source prefixes stay disabled.** Source ports are a different risk class
  from the "Source-based filtering" exclusion:
  - A source *prefix* names other networks' hosts. Spoofing lets an attacker
    choose which sources prefixd would block, for example the victim's own
    resolvers, partners or a CDN. Reflection uses thousands of real
    reflectors, so prefix lists are unbounded and outrun rule budgets.
  - A source *port* names a protocol role. It is drawn from a bounded,
    operator-owned library. It is always combined with the victim `/32` or
    `/128` and with UDP, and it is limited by `max_ports` and the TTL.
  - Collateral is bounded too: the victim loses replies from that service port
    while the rule lives.
  - The induced-collateral risk remains. An attacker can spoof sport-53 traffic
    so that prefixd blocks the victim's DNS replies. This is why the
    collateral is documented, the rule is bounded by its TTL, and the library
    is editable.
- **Dry run.** Preserved as in [ADR 013](013-dry-run-mode.md). Extended rules
  are persisted with their components and `origin_mode = dry-run`, and are
  audited, but no RPC is sent. Capability and opt-in checks run in both modes.
- **Unchanged guardrails.** Safelist, TTL bounds, quotas, the host-prefix
  bounds, owned-victim checks, lifecycle serialization and immutable
  withdrawal intent apply to every rule as today.

### 7. Router reality

FlowSpec enforcement is a router decision. This table summarizes vendor
documentation as cited. None of it is prefixd qualification. "Unknown" means
no vendor document was found.

| Platform | Source port v4 / v6 | Packet length v4 / v6 | Fragment v4 / v6 | TCP flags | Validation toward a controller |
|----------|---------------------|-----------------------|------------------|-----------|-------------------------------|
| Junos / Junos Evolved | Yes / Yes [J1, J2] | Yes / Yes, "total IP packet length" [J1, J2] | DF, IsF, FF, LF / no DF; enhanced-ip MPCs only [J1, J2] | Yes [J1] | `no-validate <policy>` under `family inet flow` [J3]; IPv6 unknown |
| IOS-XR (ASR 9000) | Yes / Yes [C1] | Yes / Yes, includes IP header [C1] | Yes / guide contradicts itself; treat as unsupported [C1] | No Reserved/NS bits [C1] | `flowspec validation disable` [C1] |
| IOS-XR (NCS 5500) | Unknown (search extracts only) [C2] | Unknown [C2] | Unknown; IPv6 type 12 reported unsupported [C2] | Unknown | Unknown |
| Arista EOS | Yes, all RFC 5575 components except listed caveats [A1] | Yes (4.23.1 / 4.23.2), needs a TCAM length field [A1] | IsF only, IPv4 only [A1] | No ECE, CWR, NS [A1] | No validation implemented [A1] |
| Nokia SR OS | Yes / Yes [N1] | Yes / Yes [N1] | IsF only / no LF [N1] | SYN and ACK only on some platforms [N1] | Off by default; `validate-dest-prefix` enables it [N2] |
| FRR | Decoded; installs one value or one range [F1] | Decoded [F1] | Decoded; install path unknown | Decoded; install path unknown | Not implemented [F1] |

Consequences for this design:

- Separate source-port and fragment rules are required, not just tidy. EOS
  documents that "Combining source and destination ports and the Fragment
  flags in the same rule [is] not supported" [A1].
- IsF is the one fragment bit every documented platform supports for IPv4.
- IPv6 fragment matching is weaker. IOS-XR and EOS document no IPv6 support,
  so operators on those platforms should expect the IPv6 fragment rule to be
  rejected or ignored by the router, whatever prefixd accepts.
- FRR installs filters only for discard (`rate 0`) or redirect actions [F1].
  The lab FRR is control-plane only.

FlowSpec validation (RFC 8955 §6) checks that the originator of the flow
matches the best unicast route for its destination. A controller-originated
rule fails that check unless validation is relaxed for the session. The
existing [vendor matrix](../reference/vendors.md) records Junos `no-validate` and
IOS-XR `flowspec validation disable`. The lab FRR receives prefixd rules without
covering unicast routes. The new components do not change validation, which
depends only on the destination prefix, but the vendor guide gains the
per-platform notes above.

Sources:

- [J1] [Junos: Understanding flow routes](https://www.juniper.net/documentation/en_US/junos/topics/concept/flow-routes-understanding.html)
- [J2] [Junos: `flow` (IPv6)](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/flow-ipv6-edit-routing-options.html)
- [J3] [Junos: `no-validate`](https://www.juniper.net/documentation/us/en/software/junos/bgp/topics/ref/statement/no-validate-edit-protocols-bgp.html)
- [C1] [IOS-XR ASR 9000 7.9.x: Implementing BGP Flowspec](https://www.cisco.com/c/en/us/td/docs/routers/asr9000/software/asr9k-r7-8/routing/configuration/guide/b-routing-cg-asr9000-79x/implementing-bgp-flowspec.html)
- [C2] [IOS-XR NCS 5500 24.x BGP guide](https://www.cisco.com/c/en/us/td/docs/iosxr/ncs5500/bgp/24xx/configuration/guide/b-bgp-cg-ncs5500-24xx/implementing-bgp.html); only search extracts were readable
- [A1] [Arista EOS: BGP FlowSpec](https://www.arista.com/en/um-eos/eos-border-gateway-protocol-bgp)
- [N1] [Nokia 7750 SR 22.7: BGP FlowSpec](https://infocenter.nokia.com/public/7750SR227R1A/topic/com.nokia.Unicast_Guide/bgp_flowspec-ai9exj5yj3.html)
- [N2] [Nokia 7750 SR 22.5: Validating received FlowSpec routes](https://infocenter.nokia.com/public/7750SR225R1A/topic/com.nokia.Unicast_Guide/validating_rece-d497e10932.html)
- [F1] [FRR: BGP FlowSpec](https://docs.frrouting.org/en/latest/bgp.html#flowspec)

**Qualification.** Use FRR in the existing
[`lab/interop/`](../../lab/interop/) containerlab harness, for both speakers and
both families (slice 7). SR Linux has no FlowSpec family (vendor matrix), so it
cannot serve. Junos, IOS-XR, EOS and SR OS stay "Expected" for these components
until someone supplies a dated receipt.

## Failure modes

- **A speaker or router drops a component.** prefixd refuses unsupported
  components before the RPC, and both bundled speakers encode all three.
  Read-back proves only the speaker stage. A router that ignores or rejects a
  component is outside prefixd's evidence, which is why routers need their own
  qualification.
- **Port-set churn.** A detector reporting a different set each time creates
  new rules rather than extending old ones. Quotas and the per-minute cap bound
  it, and old rules expire at their TTL.
- **Library gaps.** An unknown reflector port falls back to today's `udp_flood`
  behavior, not to no mitigation.
- **Downgrade.** Covered in section 3. Binaries before slice 1 must not run
  against live extended rules or pending extended withdrawals.
- **Controller stopped.** Unchanged from ADR 003: rules persist on the speaker
  until the controller returns.

## Implementation slices

Each slice is a separate draft PR that passes `just gate`.

1. **Match model and identity, with no behavior change.**
   - Add the optional fields, the domain-separated v2 hash, `matches_nlri` for
     every component, `deny_unknown_fields`, and the invariant validator.
   - *Accept:* the ADR 027 golden test passes unchanged. New v2 golden values
     are pinned. Legacy `match_json` and `rule_json` round-trip byte for byte.
     No extended rule shares a hash with a legacy rule. Two rules differing
     only in source ports are distinct in `matches_nlri` and in every hash.
     Each invariant has a rejection test with a passing control.
2. **Speaker encoding and capability.**
   - Add strict rustbgpd and GoBGP encoders and decoders for types 6, 10 and
     12, `match_support`, `SpeakerCapabilities.flowspec_match`, the mock, and
     shared contract tests.
   - *Accept:* codec round trips in both families. Unknown operator forms and
     extra bits fail the read. Bit 0x01 is never emitted for IPv6. An adapter
     reporting no support refuses before any RPC (negative control).
     Released-daemon tests for rustbgpd (`scripts/test-rustbgpd.sh`, default
     and `PREFIXD_RUSTBGPD_TEST_VERSION=0.76.0`) and GoBGP 4.10.0 inject,
     read and delete each component.
3. **Guardrails and settings.**
   - Enforce `allow_fragment_match` and `allow_packet_length_match`, add
     per-list `max_ports`, packet-length sanity, startup and playbook-save
     capability checks in both modes, and warnings for the reserved flags.
   - *Accept:* each refusal has a test, with an accepting control when the
     flag is true. Dry run persists and sends no RPC.
4. **Vector, event schema, library and multi-rule policy.**
   - Add `udp_amplification`, `top_src_ports` with migration 017, the
     `amplification` settings and default library, step `rules`, per-rule
     admission, `mitigation_ids` and the `udp_flood` fallback.
   - *Accept:*
     - Library intersection drops foreign ports.
     - An empty intersection falls back to `udp_flood`.
     - Partial admission reports per-rule outcomes.
     - A refresh extends both rules.
     - A changed set creates a new rule.
     - Migration replay on a populated database leaves every existing event's
       `top_src_ports_json` as `NULL`.
     - Older-binary fixtures confirm that a playbook with `rules` or the new
       vector fails to load.
5. **Detector adapters.**
   - Add FastNetMon native `packet_dump_detailed` classification, notify
     script parsing, Alertmanager `top_src_ports`, and generic webhook
     `fields.top_src_ports`. Update the detector guides.
   - *Accept:*
     - Fixtures from FastNetMon's documented output formats classify
       reflection only above `min_src_port_share`.
     - A random-source-port UDP flood stays `udp_flood`.
     - Script tests cover zero-UDP, mixed and IPv6 dumps.
     - A malformed annotation errors rather than producing an empty list.
6. **Operator surfaces.**
   - Add the manual API fields with the same invariants, OpenAPI,
     `docs/reference/api.md`, configuration reference, frontend types and match
     display, sibling-rule linking by `triggering_event_id`, CLI display,
     metrics label values and new guardrail rejection reasons.
   - Also add the upgrade guide's downgrade procedure, FEATURES.md, and the
     vendor matrix notes.
   - *Accept:* frontend `bun run test` and `bun run build` pass. Docs links
     resolve. An API test shows the canonical form echoed back.
7. **FRR qualification receipt.**
   - Extend `lab/interop/flowspec_frr.py` and its matcher with FRR's source
     port, packet-length and fragment fields, and add an amplification step
     for both speakers and both families.
   - *Accept:*
     - A dated receipt shows FRR receiving the source-port rule (with and
       without length) and the IsF fragment rule with the expected actions.
     - It also shows withdrawal, TTL expiry, and repair after a speaker
       restart.
     - Negative control: a playbook with fragments is refused when
       `allow_fragment_match` is false.
   - This qualifies FRR's control plane only.
8. **Later, each with its own decision:** TCP flags, vendor router receipts,
   source-port ranges if a reflector ever needs one, and a combined
   "withdraw response" action.

## Consequences

Operators can mitigate the most common reflection attacks without dropping all
of a victim's UDP. The cost is a larger match model, a second identity
namespace for extended rules, a new vector and event field, and a
configuration-owned port library that needs upkeep. Fragment matching stays an
explicit opt-in because its collateral is real. Router support for these
components varies more than for destination ports, so operators must qualify
their platform. Downgrades past slice 1 need a documented drain.

## Decisions recorded

The owner decided the following on 2026-10-19:

1. **Fragment action.** Shipped examples police the non-first-fragment rule;
   they do not discard it. Discard remains available when an operator writes it
   explicitly, behind `allow_fragment_match`.
2. **DNS in the library.** Port 53 is in the default reflector-port library.
   Its collateral (the victim's replies from external resolvers) is documented
   in the configuration reference, the detector guides and the shipped
   playbook example.
3. **Admission.** Rules emitted by one step are admitted per rule, not all or
   nothing. The event response reports each rule's outcome.
4. **Sample threshold.** `min_src_port_share` defaults to 0.2.
5. **No source-port flag.** There is no `allow_src_port_match`. Source ports
   are opt-in through the `udp_amplification` playbook or an explicit manual
   request, and they are bounded by the library and `max_ports`.
