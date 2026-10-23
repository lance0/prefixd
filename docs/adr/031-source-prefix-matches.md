# 031: Manual source-prefix FlowSpec matches

- Status: Proposed
- Date: 2026-10-22

## Context

[Issue #305](https://github.com/lance0/prefixd/issues/305) asks for scrubber
redirection and source-prefix matching. These are independent protocol
features. Source matching narrows which packets match a rule; the existing
discard and police actions can use it without adding a forwarding action.

[RFC 8955 section 4.2.2.2](https://www.rfc-editor.org/rfc/rfc8955.html#section-4.2.2.2)
assigns source prefixes component type 2, using conventional IPv4 prefix
encoding. [RFC 8956 sections 3.1 and 3.2](https://www.rfc-editor.org/rfc/rfc8956.html#section-3.2)
add an IPv6 bit offset. Offset zero represents a conventional network CIDR;
nonzero offsets match address bits that a CIDR field cannot represent.

The pinned rustbgpd 0.79.0 and GoBGP 4.10.0 RPC contracts already represent
source components. prefixd previously rejected them in read-back and offered
no source match in the public model. `allow_src_prefix_match` parsed as a
reserved flag. Source addresses in attack samples may be spoofed, so automatic
selection would let the attacker influence filtering scope.

## Decision

Add optional `src_prefix` to manual discard and police creation, guarded by
`guardrails.allow_src_prefix_match` (default false). It must be a same-family
CIDR and is stored with host bits cleared. The destination follows
[ADR 004](004-destination-prefix-32-only.md): a host by default, or an aligned
manual CIDR after deliberate prefix-bound relaxation and whole-prefix ownership
checks. Safelist, TTL, quota, ownership and mode rules apply to the full match.
Source matching does not require UDP. Combined amplification components retain
all [ADR 028](028-amplification-matches.md) restrictions.

An omitted or null field creates no source component. An explicit `/0` is
supported and matches every source. Keep it a distinct identity from omission:
the speaker identifies routes by their encoded components. Empty strings,
invalid CIDRs, mixed families and source-only rules fail. IPv6 offset is always
zero; readers refuse nonzero offsets or unrepresentable components rather than
claim a wider inventory. Blackholes refuse source fields.

Source-prefix rules use a domain-separated v3 identity containing canonical
source and destination and every other match component. Source-free v1 and v2
hashes remain byte for byte unchanged. Source participates in speaker matching,
owner lookup, immutable withdrawal snapshots, retry and reconciliation. Deleting
one source scope must leave other sources and a source-free rule untouched.

The API exposes canonical source scope, and the dashboard form, list, detail,
copyable rule preview and CLI show it. `flowspec_match.source_prefix` reports
adapter encoding capability, not router enforcement. The dashboard confirms this
capability before posting each source selector; older controllers can otherwise
ignore the unknown field and install a wider rule. No detector or playbook
chooses a source prefix in this slice. No migration or new dependency is needed.

## Alternatives

- **Derive sources from detector samples:** rejected because source addresses
  can be forged and no source-prefix confidence/aggregation contract exists.
- **Implement arbitrary IPv6 offsets:** deferred; a CIDR cannot express them,
  and a new pattern model would affect every identity and lifecycle surface.
- **Normalize `/0` to absent:** rejected because it would merge distinct
  speaker route keys and could withdraw the wrong intent.
- **Enable redirect in this change:** deferred to the separately researched
  scrubber-diversion design. A source selector does not establish scrubber
  readiness, a clean return path or a compatible redirect encoding.

## Qualification and limits

Unit and contract tests cover canonicalization, same-family validation,
source-free golden identities, source/no-source ownership separation, both
speaker encodings, malformed read-back and explicit refusal without capability.
API controls cover both families and operation modes, opt-in refusal before
persistence/RPC and independent withdrawal. Released speaker fixtures exercise
source routes through add, local read and delete.

These checks establish controller and speaker behavior. Router matching and
traffic filtering require a dated receipt for the receiving platform; no new
router or scrubber qualification is claimed. [The downgrade procedure](../how-to/upgrading.md#source-prefix-matches-and-downgrade)
requires draining source rules and pending withdrawals on the original target
before starting a controller that cannot preserve this field.

## Primary implementation references

- [rustbgpd 0.79.0 RPC schema](https://github.com/lance0/rustbgpd/blob/v0.79.0/proto/rustbgpd.proto), `FlowSpecComponent`.
- [GoBGP 4.10.0 NLRI schema](https://github.com/osrg/gobgp/blob/v4.10.0/proto/api/nlri.proto), `FlowSpecIPPrefix`.
- [GoBGP FlowSpec documentation](https://github.com/osrg/gobgp/blob/v4.10.0/docs/sources/flowspec.md), source matches.
