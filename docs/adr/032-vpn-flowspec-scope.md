# ADR 032: Scoped IPv4 VPN FlowSpec Origination

## Status

Accepted 2026-11-08 with the revisions below. Runtime implementation and
qualification are in progress; acceptance does not establish VPN support.
Extends [ADR 025](025-pluggable-speaker-backends.md),
[ADR 030](030-scrubber-diversion.md) and
[ADR 031](031-source-prefix-matches.md).

## Context

An operator needs prefixd to inject mitigation rules into one receiver VRF,
TRANSIT, using RD `44407:40` and scope RT `44407:777`. prefixd currently
originates global FlowSpec. Its match hashes, inventory readers and guarded
occupancy checks do not distinguish VPN identities. Adding RD/RT fields to
an RPC alone would leave cross-scope deduplication and withdrawal hazards.

rustbgpd main provides scoped plain, leased and guarded injection. Its
controller owns no VRF objects: the receiving PE imports the route targets.
The pilot receiver is an ASR9901; router installation and traffic enforcement
remain separate qualification work. This design covers IPv4 VPN origination.
IPv6 VPN, receiving/reflection and VRF provisioning are outside this slice.

## Decision

### Selection and admission

Configure named VPN scopes under the existing speaker target. Each name
resolves to a family enum, an RD and a nonempty list of scope RTs.
Persist the family enum in scope snapshots and identity so adding family 14
requires validation/configuration work without a storage migration. This slice
accepts IPv4 VPN scope only; refuse IPv6 VPN configuration for now.
For example, the proposed configuration is:

```yaml
bgp:
  default_scope: TRANSIT
  vpn_scopes:
    TRANSIT:
      family: ipv4
      allow_source_only: false
      rd: "44407:40"
      route_targets: ["44407:777"]
```

Reserve `global` as the existing default. Manual creation and preview accept
an optional scope name; omission retains global behavior. Unknown names,
missing scope fields and IPv6 matches in an IPv4 scope fail before persistence
or speaker mutation. Preview and dry-run use the same validation. Raw RD/RT
input belongs in operator configuration, not detector payloads.

Use scope-aware endpoints for VPN admission/preview and guarded creation so
older controllers reject the route instead of ignoring a new JSON selector
and injecting globally. CLI/dashboard clients require controller VPN capability
before submission; they never retry through a global endpoint or drop scope.
Keep existing global endpoints compatible. Reject unknown scope fields in the
new request types.

Manual admission selects a scope; configured scrubber profiles select their
scope. An operator-configured `default_scope` on the speaker target selects
scope for automatic FlowSpec mitigation. Omission retains global automation.
Detector payloads cannot select or override scope, and an unknown default is
a configuration error. Automatic admission uses the same immutable snapshot
and identity as manual admission; default changes affect new admissions only.
Include default scope in this slice through the shared automatic admission
path before ownership/deduplication. BGP settings, including this default,
require restart under the current configuration model. Do not infer a VRF from an IP address. Existing inventory
ownership rules still authorize destination matches; this slice does not add
independent customer ownership of overlapping address space in different VRFs.

Persist the resolved family, exact RD encoding, RT payload and display name
at admission. Recovery and withdrawal use that snapshot. Configuration edits
apply to new admissions; they cannot change active payloads or pending deletes.
Refuse removal or RD/RT edits of a scope with outstanding intent until drained.
Keep one controller per POP/speaker target. Rule scope does not create another
speaker binding or controller fence; preserve existing target IDs and immutable
withdrawal references. Document the existing `GLOBAL` target namespace as the
legacy controller-target identifier rather than reusing it as a rule selector.

### Identity, storage and recovery

Store family and RD with `FlowSpecNlri`; store RTs as `FlowSpecRule` attributes.
Validate and canonicalize supported RD types 0, 1 and 2 by their encoded bytes;
retain AS2 versus AS4 encoding for both RD and RT. A VPN identity consists of
`(family, RD, components)`. Neither the display name nor RTs belong in the key.
Global NLRIs carry no RD or typed scope RTs.

Preserve existing global hashes and serialized defaults. Introduce a domain-
separated VPN hash over the complete identity and use it for mitigation dedupe,
NLRI hashes, ownership, lease keys, reconciliation and export-evidence caches.
Existing `(scope_hash, pop)` mitigation uniqueness can remain. Retain the
guarded `(pop, victim)` live index and cross-scope exclusion for conflicting
discard/diversion intent, including pending operations: different RDs can
carry the same RT and enter the same receiver VRF. Separate domains require
verified receiver import bindings; neither RD inequality nor distinct RTs
establish disjointness. Add scope to snapshot identity without weakening the
existing victim exclusion. Legacy rows and pending
snapshots remain global; migration replay must preserve operations and audit
history without inventing remote acknowledgement.

List every configured or persisted VPN family, including scopes retained only
by pending operations. Preserve RD/RT through ordinary and guarded decoder
normalization. Refuse malformed or partial inventory; do not convert it to an
empty successful read. Unknown VPN rows stay scoped and untouched. Adoption,
orphan deletion and fresh ownership checks compare the complete key and target.

Keep owner-wide lease renewal and its 16,384-key speaker cap across all RDs
and families. Preserve separate guarded scrubber owners and their readiness
fences. Do not create an independent lease deadline per RD. A daemon downgrade
must retain VPN intent and failed-operation evidence while refusing its replay;
require draining VPN intent and pending withdrawals before controller downgrade.

### Backends and payload updates

rustbgpd implements scoped plain, leased and guarded add/delete, local read-back,
lease-key inventory and export dispositions. Use family 13 with an RD on every
VPN key; use existing global families with no RD. Never retry VPN as global.
GoBGP explicitly refuses VPN scope with a typed unsupported-scope error before
an RPC. Mock behavior must exercise refusal, malformed inventory and isolation.

Plain and same-owner leased RT changes replace attributes on the same key.
Guarded RT changes require persisted withdrawal of the held revision, confirmed
absence, then admission under a new revision. Preserve the old withdrawal
payload through ambiguous outcomes and retries. Changing RD creates a new key
and requires explicit retirement of the old rule; no implicit retargeting API.

For controller-originated payloads, send typed scope RTs and remove their raw
twins from extended communities. Preserve other attributes and keep actions in
one representation too. Lossless raw replay of an external row uses raw RTs
with typed RTs empty, including raw duplicates. Do not deduplicate a held guarded
payload during recovery: that changes its revision-bound contents. Redirect-to-
VRF action RTs remain distinct from scope RTs.

### Capabilities and release compatibility

Keep the global daemon minimum at **0.81.0**. VPN is opt-in and requires the
read-only `ListFlowSpecRoutes` probe with `afi_safi: 13` and
`received_peer_address: "0.0.0.0"`, acknowledging `received_view: true`.
`INVALID_ARGUMENT` means unsupported for that probe; transport and auth errors
remain errors. Version strings alone cannot authorize a VPN mutation.
Probe configured and persisted families at startup, including pending
withdrawals, and probe before VPN mutations and recovery replay. Do not cache
support for a channel lifetime: gRPC can reconnect to a downgraded daemon
without replacing the channel. Fail closed when support cannot be established.
Refuse configured VPN on unsupported backends at startup and expose actual
capability/error state in authenticated health.

The VPN contract ships in **v0.82.0**, commit
`608dcaea0902272474bd2a25bcf30bff3dd3153b`. Vendor its release proto and checksum
and add the immutable image pin immediately:
`ghcr.io/lance0/rustbgpd:0.82.0@sha256:807dcb90c8d0234d5c0c39bdde62f8a2ee24a9525bcd60ca4c95c2773e56f609`.
Test both 0.81.0 refusal and 0.82.0 VPN behavior. Leave the global minimum
unchanged; daemon version alone remains insufficient evidence of capability.

### Actions and source-only rules

Support each communicated action separately: discard, rate-limit, marking,
redirect-to-VRF and redirect-to-IP. Extend the typed FlowSpec action model and
its persisted/API representation; preserve existing action spellings and global
behavior. Validate action parameters before admission and decode them losslessly.
Do not add arbitrary action combinations in this slice. Redirects use configured
target profiles and guarded admission, retaining scrubber readiness, lease,
withdrawal and manual re-arm rules from ADR 030. A scope RT does not authorize
a redirect target. Scope support must not bypass those controls.

Source-plus-destination keeps the existing opt-in and destination ownership,
prefix, port, safelist, TTL and quota checks. Source-only is a distinct manual
VPN operation. The scope's `allow_source_only: true` is the operator's explicit
authorization to affect traffic to every destination in that VRF, including
safelisted destinations. Require source-match opt-in and preview/confirmation
showing `destination: any`; a host used for audit context cannot substitute
for the omitted destination.

Apply safelist and infrastructure protection to the source prefix: refuse
any overlap with the safelist or configured own/infrastructure ranges. Require
a configurable minimum source prefix length, default IPv4 `/24`, an explicit
TTL with a short maximum, and a separate source-only quota. Initial policy
defaults are a 60-second maximum TTL and 10 active source-only rules per POP,
with stricter existing limits still applying. Allow discard and rate-limit
only; refuse source-only marking and redirects pending separate qualification.
Keep global source-only refused and omitted destination distinct from explicit
`/0`. Receiver validation of destination-less rules under RFC 8955 section 6
and RFC 9117 varies by platform; pilot qualification must establish receiver
acceptance. Controller encoding cannot establish it.

### Operator surfaces and qualification

Show global or VPN family/RD/RT in API responses, CLI, dashboard forms, previews,
local inventory, mitigation details, audit events and operational logs. Update
OpenAPI and generated frontend types together. Add bounded family/scope-kind
metric labels; keep arbitrary RD/RT strings out of metric labels. Publish a
TRANSIT controller/speaker example and upgrade/drain instructions. Describe
local intent, speaker acceptance, peer export and enforcement separately.

Acceptance requires the following evidence; none is established by this ADR:

| Requirement | Required implementation evidence |
| --- | --- |
| Global compatibility | Existing suites; golden global hashes and no RD on global RPCs |
| Global/RD A/RD B isolation | Add/list/delete, TTL and lease expiry, retry and restart tests with identical components |
| RT and RD updates | Plain/leased replacement; guarded delete/new revision; lossless single-representation replay |
| Unsupported speaker | Released 0.81.0 refusal across VPN paths with unchanged global inventory; separate transport/auth controls |
| Older controller | New clients refuse absent VPN capability; scope-aware endpoints refuse on an older controller without changing global inventory |
| Backend safety | GoBGP pre-RPC typed refusal; mock negative and malformed-inventory controls |
| Wire behavior | Isolated prefixd to rustbgpd to GoBGP 4.11.0 peer; exact AFI 1/SAFI 134, RD/RT/actions and withdrawal; global-only peer control |
| Actions and sources | All five actions; source+destination and source-only; admission negatives and round-trip evidence |
| Regression proof | Remove each identity/scope fix and show its targeted test fails |
| Release readiness | Tagged proto/checksum, immutable image pin, required gate and both released fixtures |

Reuse the existing isolated fixtures and lab harness. Preserve failed controls
and raw receipts. The upstream wire receipt establishes comparator behavior,
not prefixd integration. Run `just gate` before an implementation PR. Update
configuration/API/CLI/backend references, changelog and roadmap when behavior
ships. This design adds no runtime release note or roadmap completion claim.

## Consequences

Existing global users retain their daemon floor and rule identities. VPN work
reaches admission, persistence, guarded diversion and operator views as well as
the adapter. GoBGP VPN remains refused. Automatic scope comes from operator
configuration; detectors cannot choose it. Source-only opt-in authorizes all
VRF destinations while protecting safelisted and infrastructure sources.
Router support claims require a separate platform, release
and action receipt; this work does not qualify IOS XR installation or traffic.

## Contract references

The design uses rustbgpd v0.82.0 at `608dcaea0902272474bd2a25bcf30bff3dd3153b`:

- [VPN controller API](https://github.com/lance0/rustbgpd/blob/608dcaea0902272474bd2a25bcf30bff3dd3153b/docs/reference/api.md#vpn-flowspec-controller-api)
- [ADR 0146](https://github.com/lance0/rustbgpd/blob/608dcaea0902272474bd2a25bcf30bff3dd3153b/docs/adr/0146-vpn-flowspec.md)
- [RPC schema](https://github.com/lance0/rustbgpd/blob/608dcaea0902272474bd2a25bcf30bff3dd3153b/proto/rustbgpd.proto)
- [Controller example](https://github.com/lance0/rustbgpd/blob/608dcaea0902272474bd2a25bcf30bff3dd3153b/examples/vpn-flowspec-controller/config.toml)
- [Wire qualification and limits](https://github.com/lance0/rustbgpd/blob/608dcaea0902272474bd2a25bcf30bff3dd3153b/docs/artifacts/interop/vpn-flowspec-qualification-20261106/README.md)
