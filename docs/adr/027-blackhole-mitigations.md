# ADR 027: Remotely Triggered Blackhole Host Routes as a Second Mitigation Kind

## Status

Proposed. Nothing in this ADR is implemented. Extends
[ADR 004](004-destination-prefix-32-only.md),
[ADR 012](012-playbook-policy-engine.md) and
[ADR 025](025-pluggable-speaker-backends.md); qualifies the unicast caveat in
[ADR 002](002-flowspec-only-afi-safi.md).

## Date

2026-10-19

## Context

FastNetMon Community users mostly mitigate with remotely triggered blackhole
(RTBH) host routes. They reach prefixd through `scripts/prefixd-fastnetmon.sh`,
which posts `ban` events to `POST /v1/events` and, on `unban`, withdraws every
pending or active mitigation for the victim
([FastNetMon guide](../how-to/detectors/fastnetmon.md)). prefixd only produces
FlowSpec police/discard rules today: `ActionType` has two values
(`src/domain/mitigation.rs`), playbook steps map only to FlowSpec actions
(`src/config/playbooks.rs`), and both adapters implement only FlowSpec writes
and reads (`src/bgp/announcer.rs`).

A blackhole drops all traffic to the victim. A wrong one completes the attack,
and a stale one outlives it. The current code shapes the guardrails this ADR
must tighten:

- Policy builds IPv4 `/32` and IPv6 `/128` host matches (`src/policy/mod.rs`),
  but guardrail prefix bounds remain configurable through
  `dst_prefix_minlen`/`dst_prefix_maxlen` (`src/guardrails/mod.rs`).
- The safelist is checked once, at admission, in `handle_ban` and
  `create_mitigation` (`src/api/handlers.rs`). Reconciliation repairs in
  `sync_announcements` (`src/scheduler/reconcile.rs`) re-announce without
  rechecking it.
- Quotas count every active mitigation, whatever its action, inside
  `admit_mitigation` under a PostgreSQL advisory lock (`src/db/repository.rs`).
- Detector bans require the victim to be in inventory (`is_owned` in
  `handle_ban`). Manual creation only looks up the customer.
- The dashboard's mitigate-now dialog posts an event with
  `source: "dashboard"` (`frontend/components/dashboard/mitigate-now-dialog.tsx`),
  so it reaches playbooks through the detector path.
- Escalation is not reachable. Policy evaluates only a playbook's first step
  (`get_initial_step` in `src/policy/mod.rs`). The `escalation` setting is a
  removed key (`REMOVED_KEYS` in `src/config/settings.rs`). No code path
  produces `MitigationStatus::Escalated` or `mitigation.escalated`.
  `prefixd_escalations_total` is always zero.
- Identity is FlowSpec-shaped. `MatchCriteria::compute_scope_hash` hashes
  prefix, protocol and ports. The partial unique index
  `idx_mitigations_active_scope` (`migrations/001_initial.sql`) enforces one
  live owner per scope and POP. `withdrawal_requests.rule_json`
  (`migrations/013_withdrawal_requests.sql`) stores a serialized
  `FlowSpecRule`, and `ownership_key` and `mitigation_rule`
  (`src/domain/withdrawal.rs`) assume one.
- Reconciliation reports unknown local rules and never deletes them. Failed
  reads skip repair. Pending withdrawals block re-announcement of their key.
  These properties carry over unchanged.

The example speakers are FlowSpec-only. `configs/rustbgpd.toml` negotiates only
`ipv4_flowspec` and `ipv6_flowspec` and permits every export. The GoBGP router
peers follow ADR 002, which records that some routers reject mixed
unicast/FlowSpec sessions.

The rustbgpd source (version line 0.78.0, checked 2026-10-19) already has the
unicast primitives. `InjectionService.AddPath` and `DeletePath` key a local path
on prefix and `path_id`. `RibService.ListReceivedRoutes` with
`neighbor_address = "0.0.0.0"` lists retained local injections. All three are
in rustbgpd's v1 stable-surface inventory, and its v1.0 feature freeze is
2026-11-20.

## Decision

Add `blackhole` as a second mitigation kind. It is disabled by default,
rustbgpd-only at first, host-route-only, and has stricter guardrails than
FlowSpec. Everything below applies to blackhole only. FlowSpec behavior,
identity hashes and persisted rows do not change.

### 1. Route shape

**Prefix length.** Exactly IPv4 `/32` or IPv6 `/128`, fixed in code with no
setting. The existing `dst_prefix_*` bounds do not apply to blackholes.
*Alternatives:* a configurable maximum (rejected: a `/24` blackhole is an
outage, and ADR 004's future-tier note requires approval and audit, not a
setting); reusing the FlowSpec bounds (rejected: they can be widened).

**Communities.** Every blackhole carries RFC 7999 BLACKHOLE (`65535:666`),
which configuration cannot remove. Operators may add standard and large
communities in the `blackhole` settings, for example a provider's own RTBH
trigger. Configuration is per controller, so each POP sets its own. Per-peer
community or next-hop differences belong to speaker export policy, because
ADR 025 leaves peer and routing policy to the daemon. prefixd rejects
`NO_EXPORT` and `NO_ADVERTISE` in its configuration. The rustbgpd configuration
reference states that a route carrying `NO_EXPORT` is suppressed toward eBGP
neighbors with `interpret_rfc1997` (on by default), and rustbgpd's RFC 7999 ADR
makes `NO_ADVERTISE` pre-export ineligibility for unicast. Either community set
at injection could keep the route from reaching the router. Scoping goes
in the receiving router's import policy, as RFC 7999 recommends, or in speaker
export policy, which rustbgpd documents as delivering an export-added
`NO_EXPORT`. *Alternatives:* a per-peer community map in prefixd (rejected:
it duplicates daemon policy); `NO_EXPORT` at injection (rejected: it can
suppress the route).

**Next hop.** Require an explicit per-family discard next hop in configuration
(an IPv4 address for IPv4 victims, an IPv6 address for IPv6 victims). It must be
unicast and nonzero. With iBGP RTBH, every router keeps a static discard route
for that address. With eBGP, the router's import policy matches BLACKHOLE and
rewrites the next hop to discard. rustbgpd's configuration reference describes
preserving the original unicast next hop as a route-server-client exception and
allows export `set_next_hop` rewrites. An eBGP router must therefore not rely on
seeing the injected value. *Alternatives:* `0.0.0.0`/`::` (rustbgpd's
`parse_unicast_nexthop` rejects both today); next-hop-self (needs upstream
semantics, see requirement (c); deferred until it ships and is qualified).

The route has ORIGIN IGP, an empty AS_PATH, no LOCAL_PREF or MED, and
`path_id = 0`. The resolved next hop and communities are snapshotted into the
mitigation's action parameters at admission. A configuration reload affects only
new mitigations, never live routes.

### 2. Guardrails

- **Enablement.** `blackhole.enabled` defaults to false. Startup refuses
  blackhole playbook steps or the manual blackhole action when the feature is
  disabled, the selected backend lacks the blackhole capability, or the
  safelist is empty. The same validation runs in dry-run and enforced modes, so
  a dry run validates the configuration that enforcement will use.
- **Separate quota.** Add `max_active_per_pop` and `max_active_global` for
  blackholes, with small defaults. They are checked inside the existing
  `admit_mitigation` transaction and advisory lock, in addition to the existing
  per-customer/POP/global quotas and `max_new_per_minute`. Concurrent
  admissions therefore cannot overshoot.
- **Mandatory, capped TTL.** A nonzero TTL is required. `blackhole.max_ttl_seconds`
  is tighter than the FlowSpec bound. Detector extensions (`extend_ttl`) are
  capped at `now + max_ttl_seconds`. An ongoing attack keeps the route alive only
  while the detector keeps re-sending. Neither an absolute lifetime cap nor a
  speaker lease is in this ADR (see open questions and requirement (f)).
- **Safelist at announce time.** Recheck the safelist under the lifecycle mutex
  immediately before every blackhole `AddPath`: on admission and before each
  reconciliation repair. If the lookup fails, nothing is sent. If the victim is
  now safelisted, prefixd sends nothing and records a system withdrawal with
  the reason `safelisted after admission` through the normal immutable
  withdrawal path. FlowSpec repair behavior is unchanged by this ADR.
- **First action or escalation.** Allow blackhole as a playbook's first step,
  since that is the FastNetMon Community workflow and escalation is unreachable
  today. Restrict blackhole steps to events whose `source` is listed in
  `blackhole.detector_sources`. Other sources matching a blackhole playbook are
  rejected as guardrail violations. This keeps dashboard events and other
  adapters off the blackhole path. `source` is asserted by the caller, so this
  is a routing guard, not authorization. Escalation from FlowSpec to blackhole
  needs its own ADR once escalation exists. The unused `escalated_from_id`
  column stays available for it.
  *Alternative:* allowing blackhole only as an escalation step (rejected: there
  is no step progression to attach it to, and building escalation first would
  delay the main use case).
- **Victim checks.** The victim must parse as a host address that is not
  unspecified, loopback, multicast, link-local, IPv4 broadcast or IPv4-mapped
  IPv6. It must not equal a configured blackhole next hop and must be owned in
  inventory. Ownership is required for manual blackholes too, unlike manual
  FlowSpec today. Infrastructure addresses (router loopbacks, peering
  addresses, speaker, resolvers) belong in the safelist, which is why an empty
  safelist blocks enablement.
- **Dry-run.** Preserved exactly as in [ADR 013](013-dry-run-mode.md). A
  dry-run blackhole is persisted with `origin_mode = dry-run` and audited, sends
  no RPC, and is never desired speaker state. It is never extended in enforced
  mode and is retired only locally. Pending enforced-mode blackhole withdrawals
  stay pending in dry-run.
- **Manual blackholes.** `POST /v1/mitigations` accepts `action: "blackhole"`
  with Operator role. It additionally requires a nonempty `reason` and a
  `confirm_victim_ip` that exactly equals `victim_ip`. A mismatch returns `400`
  before persistence. Creation and withdrawal use the existing audit entries
  committed with the row (`admit_mitigation`, `finish_withdrawal`). The
  dashboard requires the operator to type the victim address before submission.

### 3. Model

- **Action type.** Add `blackhole` as a third `ActionType` value in the existing
  `action_type` column, API field and metric label rather than adding a new
  column. Blackhole `match_json` holds only the host prefix, with no protocol
  and no ports. In Rust, a `MitigationRoute::{FlowSpec, Blackhole}` value is
  derived from a row. Every FlowSpec-only path (`mitigation_rule`,
  `build_flowspec_rule`, `wire_action`, `find_mitigation_owner`) matches on it
  and fails closed on the other kind, never coercing a blackhole into an
  any-protocol FlowSpec discard.
- **Identity.** Blackhole scope hashes and ownership keys include a kind
  discriminator. FlowSpec hashes are byte-for-byte unchanged, so existing rows
  and the unique index stay valid. A blackhole and an any-protocol FlowSpec rule
  for the same host have distinct identities.
- **Schema.** Migration 016 adds `withdrawal_requests.rule_kind TEXT NOT NULL
  DEFAULT 'flowspec' CHECK (rule_kind IN ('flowspec', 'blackhole'))`. Every
  existing request is FlowSpec, so the default is a fact, not an inference.
  Replay creates no announcement or acknowledgement. Blackhole `rule_json`
  holds the immutable route: prefix, next hop and communities. No mitigation row
  is rewritten.
- **Coexistence.** One victim may hold a FlowSpec mitigation and a blackhole at
  once. They are independent rows with independent TTLs and withdrawals. A
  blackhole does not withdraw the FlowSpec rule: if the blackhole fails or
  expires first, the FlowSpec rule still mitigates. The FastNetMon unban
  already withdraws all live mitigations for the victim.
- **Playbooks.** `PlaybookAction` gains `blackhole`, and it rejects `rate_bps`.
  Older binaries reject the value, so rollback removes blackhole steps first.
- **API, WebSocket, CLI and alerts.** `MitigationResponse` gains an optional
  `blackhole` object (`next_hop`, `communities`). WebSocket messages carry it
  unchanged, and `SpeakerCapabilities` gains `blackhole` (serde default false).
  OpenAPI, `docs/reference/api.md`, the frontend union in `frontend/lib/api.ts`
  and `ActionBadge` (danger tone) are updated. `prefixdctl mitigations
  list/get/withdraw` show and withdraw blackholes by ID. The CLI has no create
  command today and gains none here.
- **Metrics.** Existing series gain the `action_type="blackhole"` label value.
  Add guardrail rejection reasons for blackhole quota, source and victim
  checks, and an unknown-local-route gauge per kind. Blackhole gauges count
  database state, not enforcement.

All of these are compatibility surfaces. Each slice that changes one updates its
reference documentation and release notes per CONTRIBUTING.md.

### 4. Speaker contract

Add an optional blackhole capability alongside the FlowSpec writer:
`FlowSpecAnnouncer::blackhole() -> Option<&dyn BlackholeSpeaker>`, where the
blackhole speaker provides upsert, idempotent delete and complete local-route
read-back for both families. Reading is mandatory: there is no write-only
blackhole backend, because an unreadable speaker cannot prove absence (ADR 025).
`SpeakerCapabilities.blackhole` reports availability, which is not success.

Ship rustbgpd first. GoBGP returns `None` until it has its own decision and
qualification. GoBGP's `ListPath` read-back of the global table is its accepted
local RIB after import policy. It is not retained pre-policy intent, and the
GoBGP example peers are FlowSpec-only (ADR 002).

The rustbgpd mapping is:

| Operation | rustbgpd call and semantics |
|-----------|-----------------------------|
| upsert | `AddPath(prefix, prefix_length, next_hop, origin=0, communities, large_communities, path_id=0)` |
| delete | `DeletePath(prefix, prefix_length, path_id=0)`; `NOT_FOUND` means absent until `allow_missing` exists |
| read | `ListReceivedRoutes(neighbor_address="0.0.0.0")` per unicast family, following `next_page_token` to the end |

Stages stay distinct:

1. **Desired intent.** An active, enforced-origin, unexpired blackhole row
   without pending withdrawal.
2. **RPC acceptance.** `AddPath` returned OK. In the rustbgpd source,
   `handle_inject_route` inserts into the `0.0.0.0` Adj-RIB-In and runs best-path
   recomputation and distribution before replying.
3. **Retained local intent.** A `ListReceivedRoutes` row for `0.0.0.0` with the
   saved prefix, next hop and communities. Reconciliation compares against this
   stage.
4. **Selected RIB.** `ListBestRoutes`. A received route can out-select the local
   one, so this is diagnostic only.
5. **Export.** `ListAdvertisedRoutes` for a peer, showing post-policy Adj-RIB-Out
   admission. It is optional evidence for a later API field.
6. **Router enforcement.** Router RIB/FIB discard and dropped traffic. This
   comes only from router-side evidence and is never inferred.

Decoding is strict, as in the FlowSpec adapter. Unexpected attributes, a
nonzero `path_id` on a desired key or a family mismatch fail the whole read.

### 5. Reconciliation and ownership

- **Proof of ownership.** No speaker field proves ownership today: every local
  route shows peer `0.0.0.0` with no owner. prefixd treats a route as its own
  only through its persisted ledger, meaning a desired row or pending
  withdrawal intent for this POP and verified target. That proof rests on the
  existing single-controller, exclusive-target contract
  ([speaker backends](../reference/speaker-backends.md#persistent-target-ownership)).
  Before the first `AddPath` for a new blackhole, prefixd reads the exact prefix.
  If a local row exists that the ledger does not own, admission returns `409`
  and nothing is sent. Once requirement (a) exists, a `replaced` outcome on a
  create is an alerted conflict.
- **Never delete unknown or foreign routes.** Unknown local routes, other
  `path_id`s and other POPs' rows are reported, never deleted or overwritten.
  Deletion happens only from persisted withdrawal intent bound to this POP's
  target.
- **Immutable withdrawal intent.** Detector unban, operator withdrawal, TTL
  expiry and the safelist withdrawal reuse `request_withdrawal` and
  `execute_withdrawal`. The original route, actor, reason and operation ID are
  persisted before the RPC and retried unchanged on the same target.
- **An ambiguous delete is never a re-announce.** A pending withdrawal's
  ownership key blocks repair (`pending_ownership_keys`). A new ban for that
  victim gets the existing `409` "pending withdrawal" conflict and stays
  retryable. Adapter retries after an ambiguous delete accept `NOT_FOUND`
  as absence.
- **A failed or partial inventory is never empty.** A read succeeds only after
  both families page to an empty `next_page_token` with a consistent
  `page_version`. `ABORTED`, a missing family, a transport error or a decode
  error fails the stage: no repairs and no unknown-route verdicts. Withdrawal
  cleanup continues independently, as it does for FlowSpec. An empty, complete
  `0.0.0.0` listing is a valid empty result, because rustbgpd treats the
  synthetic local peer as always known.

## rustbgpd requirements before the v1.0 freeze

Each item was checked against the rustbgpd source and the vendored
`proto/rustbgpd.proto`. "Must-have" means prefixd will not enable enforced
blackholes without it.

| Ask | Exact requirement | Verified today | Need |
|-----|-------------------|----------------|------|
| (a) AddPath outcome | `AddPathResponse.outcome` on a new field number (field 1 is `reserved`): `CREATED`, `REPLACED`, `UNCHANGED`, with `UNSPECIFIED` treated as an error, mirroring `FlowSpecInjectOutcome` | `AddPathResponse` has only `reserved 1`. The RIB's `insert` already knows whether it replaced a path, but the reply is `Ok(())` | **Must-have.** A non-atomic pre-read plus upsert can silently replace a foreign route for the victim; the outcome is the only evidence |
| (b) Delete `allow_missing` | `DeletePathRequest.allow_missing` and `DeletePathResponse.outcome` (`DELETED`, `NOT_PRESENT`) | Missing paths return `NOT_FOUND` from `handle_withdraw_injected`. `DeletePathResponse` is empty | Nice-to-have. That `NOT_FOUND` is the only one the RPC produces, so mapping it to absent is safe, as the FlowSpec adapter already does for older daemons |
| (c) Next-hop-self | A documented self marker on `AddPath`, resolved per egress session, for both families | `parse_unicast_nexthop` rejects `0.0.0.0`, `::`, multicast and broadcast. IPv6 prefixes require IPv6 next hops | Nice-to-have. An explicit discard next hop works today |
| (d) Owner tag | An opaque owner (at most 64 bytes, never sent on the wire) on `AddPath` and `AddFlowSpec`, returned on `0.0.0.0` rows and filterable. `expected_owner` on add and delete returns `FAILED_PRECONDITION` on mismatch | `Route` and `FlowSpecRouteEntry` have no owner. Every local row shows peer `0.0.0.0` | Nice-to-have for the exclusive-target contract. Must-have before shared speakers or multiple controllers can be claimed |
| (e) Vendored proto | Re-vendor at the first release containing (a) and bump the qualification pin | Unicast injection messages match upstream, but the vendored file is behind (it lacks, for example, `ComparePolicy` and `GetLastSighupReload`) | Must-have. This work is prefixd-side and mechanical |
| (f) Injection lease | An optional per-route lease on `AddPath`, removed by the daemon if not refreshed | No such field exists | Nice-to-have, strongly recommended. It is the only remedy for a stopped controller (see below) |

Items (a)–(c) are reported as in progress upstream but were not in the source
checked. Because the surface is already in rustbgpd's v1 inventory, (a), (b),
(d) and (f) are additive features that should land before the freeze.

## Failure modes

- **Speaker restart.** Injected paths live in rustbgpd's in-memory `0.0.0.0`
  Adj-RIB-In and are lost on restart, and router sessions drop. The blackhole
  lifts and attack traffic resumes until reconciliation re-injects live,
  unexpired, non-safelisted intent on its next pass. Graceful Restart on the
  router can retain the stale route meanwhile. Qualification must measure this
  interval.
- **Controller stopped, speaker up.** TTL expiry needs the running controller
  ([ADR 003](003-fail-open-ttl.md)). The blackhole stays advertised indefinitely,
  which is the most dangerous case. Mitigations: the tighter TTL cap,
  monitoring controller availability independently of BGP health, a documented
  speaker-side manual `DeletePath`, and requirement (f). Nothing here claims
  crash cleanup.
- **Split brain.** The lifecycle mutex is in-process, and target registration is
  not a lease. Two controllers on one speaker cannot distinguish each other's
  routes. Upserts can overwrite, and one controller's withdrawal can delete the
  other's same-prefix route, which the other then re-injects. The result is
  flapping, not safety. This configuration is unsupported until (d) exists; the
  [upgrade guide](../how-to/upgrading.md) procedures still apply.

## Implementation slices

Each slice is a separate draft PR that passes `just gate`.

1. **Kind-aware identity and schema, without behavior.** Add the
   `ActionType::Blackhole` parse path, `MitigationRoute`, kind-discriminated
   hashes, migration 016, and fail-closed FlowSpec paths. *Accept:* existing
   FlowSpec hashes are unchanged (golden test). Migration replay on a populated
   database keeps every request `flowspec`. A blackhole and an any-protocol
   FlowSpec rule on one host have distinct keys. A blackhole row reaching a
   FlowSpec path errors with no RPC.
2. **Speaker capability and rustbgpd adapter.** Add the trait, mock, rustbgpd
   implementation and capability JSON. GoBGP returns `None`. *Accept:*
   fake-RPC tests show paging to completion, `ABORTED` mid-walk as an error, an
   empty view as success, unexpected attributes as an error, delete
   `NOT_FOUND` as absent, and other codes as errors. Released-daemon tests
   through `scripts/test-rustbgpd.sh` cover inject, read, delete and loss on
   daemon restart for both families.
3. **Configuration, guardrails and playbooks.** Add the `blackhole` settings,
   startup validation, `PlaybookAction::Blackhole`, the source allowlist,
   victim checks, quotas inside `admit_mitigation` and the TTL cap on extension.
   *Accept:* a rejection test for each guardrail with a negative control. A
   concurrent-admission PostgreSQL test cannot exceed the blackhole quota. Dry
   run persists and sends no RPC.
4. **Lifecycle and reconciliation.** Add announce with the safelist recheck,
   kind-aware withdrawal and expiry, repair, unknown-route reporting and the
   safelist withdrawal. *Accept:* tests mirroring the FlowSpec reconciliation
   tests show that an ambiguous delete stays pending and is never re-announced,
   a failed or partial read causes no repair, a foreign POP and unknown routes
   are untouched, an already safelisted victim is withdrawn rather than
   repaired, and a pre-existing unowned local route returns `409`.
5. **Operator surfaces.** Update manual creation with confirmation, the API and
   OpenAPI, WebSocket, the frontend (type, badge, typed confirmation), CLI
   display, metrics, references and the FastNetMon guide. *Accept:* a
   confirmation mismatch returns `400` with no row or audit entry. The
   frontend `bun run test` and `bun run build` pass. Docs links resolve.
6. **FRR interop qualification.** Extend the `lab/interop/` containerlab
   harness with an FRR IPv4/IPv6 unicast session and an import route-map that
   rewrites BLACKHOLE routes to a discard next hop. *Accept:* a dated receipt
   showing FRR receives both host routes with the expected communities and
   installs them as discard, then removes them on withdrawal and TTL expiry. It
   also records the route returning after a speaker restart and persisting
   after a controller stop, recorded as the negative case. SR Linux has no
   FlowSpec but could serve as an optional second unicast receiver. This
   qualifies FRR only.
7. **Later, each with its own decision:** GoBGP blackhole, owner tags once (d)
   ships, next-hop-self once (c) ships, and FlowSpec-to-blackhole escalation.

## Consequences

FastNetMon Community users gain the mitigation they already use, behind
guardrails stricter than FlowSpec's. prefixd also takes on a unicast speaker
contract, a second identity namespace and a router-policy dependency: the
receiving router must turn the community or next hop into a discard. That
dependency is outside prefixd's evidence. Operators must add unicast families
to the speaker, separately from FlowSpec where the router requires it, and
restrict unicast export to BLACKHOLE host routes. A stopped controller can leave
a blackhole in place until (f) or an equivalent exists.

## Open questions for the owner

1. Should enforced detector-driven blackholes wait for (f) or another
   controller-down remedy?
2. Should manual blackholes require Admin? Bearer tokens currently map to
   Operator.
3. What should the default caps be? This ADR proposes a TTL cap of 600 seconds
   and quotas of 10 per POP and 50 globally.
4. Is the allowlist of caller-asserted `source` values acceptable as a routing
   guard?
5. Should (d) become a must-have before the first enforced release instead of
   only before shared-speaker support?
