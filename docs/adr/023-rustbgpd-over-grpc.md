# ADR 023: Drive rustbgpd over gRPC Instead of Embedding Its Crates

## Status

Accepted; refreshed 2026-10-18. Updates [ADR 001](001-gobgp-sidecar.md).
GoBGP remains supported under [ADR 025](025-pluggable-speaker-backends.md).

## Date

2026-09-28

## Context

The roadmap proposed embedding rustbgpd's RIB and transport crates into
prefixd. Those runtime crates are private, unpublished implementation details;
peer orchestration is daemon-owned. rustbgpd's embedding guidance recommends
controlling the separate daemon through its gRPC API (Shape A).

The existing `FlowSpecAnnouncer` boundary isolates policy callers. Backend
selection, configuration, health naming, CLI/frontend consumers, deployment
assets and tests must agree on the selected backend. Changing the adapter does
not erase those callers.

Controller and speaker failures are independent. A separate speaker can keep
advertising after prefixd exits. Application TTL enforcement needs running
reconciliation; neither injection API supplies a controller expiry lease.
Speaker session loss can clear routes, subject to configured restart retention.
See the corrected [ADR 003](003-fail-open-ttl.md).

## Decision

Add a rustbgpd daemon adapter over gRPC behind `FlowSpecAnnouncer`. rustbgpd is
the preferred integration target; GoBGP remains a maintained choice. Normal
builds and example deployment now prefer rustbgpd, with GoBGP selectable in the
same controller image. Do not embed private runtime crates or remove GoBGP code.

The relevant controller message fields were checked against `v0.79.0`:

| Trait operation | rustbgpd API and required semantics |
|-----------------|------------------------------------|
| `announce` | `InjectionService.AddFlowSpec`: upsert with created/replaced/unchanged outcomes |
| `withdraw` | `InjectionService.DeleteFlowSpec`: opt into `allow_missing` and check the outcome |
| `list_active` | `RibService.ListFlowSpecRoutes`: select `received_peer_address = "0.0.0.0"` and require `received_view`, including empty tables |
| `session_status` | `NeighborService.ListNeighbors`: map observed states and reject stale observations |

Read retained local injection intent rather than selected Loc-RIB rows: a
received candidate can out-select a local rule without deleting it. Build
protobuf match components in destination/protocol/destination-port order.
Traffic rate is floating-point bytes/sec, while prefixd policy uses bits/sec;
zero encodes discard. Malformed or unsupported fields must not be dropped.

Authentication, validation and transport failures remain errors. A successful
mutation acknowledges the documented local stage. An advertised view describes
outbound admission, not router receipt, installation or enforcement.

Reconciliation remains polling-based (ADR 011). Pushed event subscriptions and
batch injection are not prerequisites. Generic write-only speakers require the
capability and durable-ledger work in ADR 025 before they can be enabled safely.

## Controller contract and qualification

rustbgpd's ADR 0139 inventories the scoped IPv4/IPv6 controller boundary:
Add/DeleteFlowSpec and selected, retained local-intent and committed advertised
listing modes. Existing pre-v1 compatibility rules apply during 0.x. This does
not promote receive-side diagnostics/validation, `Config.flowspec`, or general
GR/LLGR guarantees into that controller contract.

The release gate for the controller promotion is resolved: v0.76.0, v0.77.0,
v0.78.0 and v0.79.0 contain ADR 0139. The minimum controller version is v0.76.0;
the current qualification pin is v0.79.0. Immutable image identities live in
[the release fixture](../../tests/fixtures/rustbgpd/releases.json), and CI runs
local lifecycle/TTL/restart checks on each release. Owner-only UDS and verified
client-certificate mTLS are implemented. Both secure deployment profiles have
[dated qualification](../reference/qualification/speaker-profiles-2026-10-18.md).
This does not qualify router enforcement.

Pin the exact released daemon used for deployment qualification and review its
contract and changelog on upgrade. The proto, generated clients, tonic/prost,
GoBGP tests and public compatibility exports remain maintained while both
backends are supported.

Qualification requires real-daemon lifecycle, TTL withdrawal and restart recovery.
Router evidence is separately attributed. Unit/fake-RPC tests do not establish
router enforcement. Supported transports and their bounds are documented in
[speaker backends](../reference/speaker-backends.md).

## Consequences

prefixd gains another speaker without taking ownership of a BGP runtime. It
also takes on a second adapter and protocol pin to maintain. Preferring rustbgpd
preserves operator choice.

Framework migration is deferred under
[ADR 026](026-facelift-framework-scope.md); it must not obscure adapter
qualification or change authentication/configuration behavior here.

## Follow-ups

Polling reconciliation repairs missing rules and supported discard/policing action
drift under the single-controller, exclusively administered target contract.
Stronger announcement acknowledgements, a full desired/acknowledged ledger, and
ownership of indistinguishable external same-match rules remain separate work.
The [roadmap](../../ROADMAP.md) also retains separately qualified router enforcement
and durable write-only recovery.
