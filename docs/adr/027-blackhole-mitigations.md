# ADR 027: Remotely Triggered Blackhole Host Routes as a Second Mitigation Kind

## Status

Accepted 2026-10-19, with the owner decisions recorded below. Nothing in this
ADR is implemented yet. Extends
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
  safelist is empty. These checks run in dry-run and enforced modes alike.
- **Injection lease gate.** In enforced mode, startup and playbook reload or
  save refuse any playbook containing a `blackhole` step unless
  `SpeakerCapabilities.blackhole_lease` is true. The error names the missing
  rustbgpd injection lease. The capability is true only when the adapter has
  verified that the connected daemon supports the owner-scoped lease
  (requirement (d)) and the renewal task holds a live lease. Enforced detector
  blackholes are injected under the controller's owner and lease (see
  [Owner and lease](#owner-and-lease)). If the controller dies, the speaker
  withdraws them within one lease period. Dry-run detector blackholes and
  manual blackholes are not gated. The controller mode can only change at
  restart, so switching to enforced re-runs this check.
- **Separate quota.** Add `max_active_per_pop` (default 10) and
  `max_active_global` (default 50) for blackholes. They are checked inside the
  existing `admit_mitigation` transaction and advisory lock, in addition to the
  existing per-customer/POP/global quotas and `max_new_per_minute`. Concurrent
  admissions therefore cannot overshoot.
- **Mandatory, capped TTL.** A nonzero TTL is required.
  `blackhole.max_ttl_seconds` defaults to 3600 and bounds playbook steps, manual
  requests and detector extensions (`extend_ttl` is capped at
  `now + max_ttl_seconds`). The cap must cover FastNetMon Community's ban
  lifetime. Its shipped `src/fastnetmon.conf` sets `ban_time = 1900`. It calls
  the notify script once on ban and once on unban, with no refresh in between,
  and it skips detection for a host that is already banned. If prefixd
  expired the blackhole first, FastNetMon would still consider the host banned
  and would not ban it again. Operators keep `ban_time` at or below the
  playbook step TTL, which is itself at or below the cap. FastNetMon's default
  `unban_only_if_attack_finished = on` can also delay an IPv4 unban past
  `ban_time` while the attack continues, without calling the script again. In
  that case prefixd still expires the blackhole at its TTL. That remaining gap
  is accepted rather than allowing uncapped blackholes.
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
  is a routing guard that works alongside detector credentials, not
  authorization. Escalation from FlowSpec to blackhole
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
  only with the Admin role. Bearer tokens map to Operator
  (`src/api/auth.rs`), so they cannot create one. The request also requires a
  nonempty `reason` and a
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
`SpeakerCapabilities.blackhole` and `blackhole_lease` report availability,
which is not success.

Ship rustbgpd first. GoBGP returns `None` until it has its own decision and
qualification. GoBGP's `ListPath` read-back of the global table is its accepted
local RIB after import policy. It is not retained pre-policy intent, and the
GoBGP example peers are FlowSpec-only (ADR 002).

The rustbgpd mapping is:

| Operation | rustbgpd call and semantics |
|-----------|-----------------------------|
| upsert | `AddPath(prefix, prefix_length, next_hop, origin=0, communities, large_communities, path_id=0)`, plus `owner` and `lease_seconds` once (d) exists |
| renew | `RenewLease(owner)` from the renewal task once (d) exists |
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
  route shows peer `0.0.0.0` with no owner. Until requirement (d) ships,
  prefixd treats a route as its own only through its persisted ledger, meaning
  a desired row or pending withdrawal intent for this POP and verified target.
  That proof rests on the existing single-controller, exclusive-target contract
  ([speaker backends](../reference/speaker-backends.md#persistent-target-ownership)).
  Once (d) ships, a route must also carry this controller's owner (see
  [Owner and lease](#owner-and-lease)).
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

### Owner and lease

This applies once the rustbgpd injection lease, requirement (d), ships. It is
required for enforced detector blackholes.

- **Owner identity.** Each controller has one stable owner, derived from its
  POP and the UUID of its verified speaker target, and unchanged across
  restarts. Within one database, a target belongs to exactly one POP, so two
  owners cannot collide. A collision across databases means two controllers are
  configured with the same POP against one speaker, which is a
  misconfiguration. Startup refuses when it can detect one: the speaker holds
  routes under this owner that the ledger neither desires nor is withdrawing,
  or the lease generation advances without this process renewing it.
- **Renewal task.** A dedicated task calls `RenewLease(owner)` about every
  `lease_seconds / 3` with its own deadline. It never takes the lifecycle mutex,
  touches the database or waits for reconciliation. `blackhole.lease_seconds`
  must fall within the daemon's minimum and maximum lease lengths. A
  controller stall longer than the lease withdraws the routes. That is a
  fail-open, the safe direction for blackholes.
- **Visibility.** The lease state (live, renewal failing or expired) and the
  last renewal result appear in authenticated operational health. A renewal
  result counter and a lease-state gauge appear in metrics. Public liveness is
  unchanged.
- **Adoption and re-add.** After a prefixd restart within the lease, prefixd
  re-adds every active enforced blackhole under the same owner, with the
  safelist recheck. Unchanged outcomes from (a) make this cheap, and renewal
  then resumes. If `RenewLease` reports that the lease had already expired, or
  if the speaker restarted, the routes are gone. Reconciliation then re-adds the
  active intents immediately, not on its next poll, and a late renewal is
  never counted as success.
- **Read-back.** Reconciliation compares only rows carrying this owner. Rows of
  other owners and rows without an owner are still reported as unknown and are
  never modified.
- **Manual blackholes.** Once the lease is available, enforced manual
  blackholes use the same owner and lease. Before it ships they are unleased.
- **FlowSpec.** Leasing FlowSpec rules too would close the AGENTS.md gap that
  rules can persist if prefixd stops. That is a later decision and is outside
  every slice below.

## rustbgpd requirements before the v1.0 freeze

Each item was checked against the rustbgpd source and the vendored
`proto/rustbgpd.proto`. Items (a) and (e) are must-haves for any enforced
blackhole. Item (d) is a must-have for enforced detector-driven blackholes.

| Ask | Exact requirement | Verified today | Need |
|-----|-------------------|----------------|------|
| (a) AddPath outcome | `AddPathResponse.outcome` on a new field number (field 1 is `reserved`): `CREATED`, `REPLACED`, `UNCHANGED`, with `UNSPECIFIED` treated as an error, mirroring `FlowSpecInjectOutcome` | `AddPathResponse` has only `reserved 1`. The RIB's `insert` already knows whether it replaced a path, but the reply is `Ok(())` | **Must-have.** A non-atomic pre-read plus upsert can silently replace a foreign route for the victim; the outcome is the only evidence |
| (b) Delete `allow_missing` | `DeletePathRequest.allow_missing` and `DeletePathResponse.outcome` (`DELETED`, `NOT_PRESENT`) | Missing paths return `NOT_FOUND` from `handle_withdraw_injected`. `DeletePathResponse` is empty | Nice-to-have. That `NOT_FOUND` is the only one the RPC produces, so mapping it to absent is safe, as the FlowSpec adapter already does for older daemons |
| (c) Next-hop-self | A documented self marker on `AddPath`, resolved per egress session, for both families | `parse_unicast_nexthop` rejects `0.0.0.0`, `::`, multicast and broadcast. IPv6 prefixes require IPv6 next hops | Nice-to-have. An explicit discard next hop works today |
| (d) The rustbgpd injection lease (owner-scoped) | Described below | No owner or lease exists. `Route` and `FlowSpecRouteEntry` have no owner, and every local row shows peer `0.0.0.0` | **Must-have for enforced detector-driven blackholes** (the lease gate). Manual and dry-run blackholes do not need it. It is the only remedy for a stopped controller, and it is also the ownership evidence needed before shared-speaker support |
| (e) Vendored proto | Re-vendor at the first release containing (a), then at the release containing (d), and bump the qualification pin each time | Unicast injection messages match upstream, but the vendored file is behind (it lacks, for example, `ComparePolicy` and `GetLastSighupReload`) | **Must-have.** This work is prefixd-side and mechanical |

Requirement (d), as designed upstream on 2026-10-19:

- **Owner-scoped.** The lease belongs to a controller as a whole, like a
  dead-man's switch. It is not a per-route timer: per-route expiry stays with
  prefixd's TTLs.
- **Add calls.** `AddPath` and `AddFlowSpec` take an optional opaque `owner`,
  never sent on the wire, and an optional `lease_seconds`.
- **Renewal.** `RenewLease(owner)` keeps everything that owner added alive with
  no per-route work. Renewals never wait behind RIB work, and lease time uses a
  monotonic clock.
- **Expiry.** The daemon withdraws everything the owner added in one batch,
  with a warning log and a metric. Withdrawal fails open, the safe direction
  for blackholes.
- **Ownership.** Retained local-intent rows report their owner and can be
  filtered by it. Without admin rights, one owner cannot renew or delete
  another owner's routes. prefixd also requires that an add which would
  replace another owner's path is refused rather than applied.
- **Bounds.** The daemon enforces a minimum and maximum lease length and a cap
  on the number of owners.
- **Expired-lease signal.** `RenewLease` must report that the lease had
  already expired, through a distinct status or an epoch/generation that
  changes when a lease is recreated. prefixd then re-adds at once instead of
  renewing an empty lease. Without this, a late renewal could look successful
  while the routes are gone.
- **Detectability.** An older daemon must be detectable, for example because
  `RenewLease` returns `UNIMPLEMENTED`, rather than silently ignoring `owner`
  and `lease_seconds`.
- **Interop proof.** Kill the controller, and the route disappears at FRR
  within the lease time.
- **Rejected upstream alternatives.** Renewing by re-adding every route was
  rejected for its RIB cost and because it cannot express "controller dead". A
  stream-scoped lease was rejected because a proxy timeout or a stall would
  drop everything.

Items (a)–(c) are reported as in progress upstream, and (d) is tracked
upstream; none of them was in the source checked. Because the surface is
already in rustbgpd's v1 inventory, (a), (b) and (d) are additive features that
should land before the freeze.

## Failure modes

- **Speaker restart.** Injected paths live in rustbgpd's in-memory `0.0.0.0`
  Adj-RIB-In and are lost on restart, and router sessions drop. The blackhole
  lifts and attack traffic resumes until reconciliation re-injects live,
  unexpired, non-safelisted intent under the same owner. Once (d) ships, that
  happens as soon as renewal or a read sees the loss. Graceful Restart on the
  router can retain the stale route meanwhile. Qualification must measure this
  interval.
- **Controller stopped, speaker up.** TTL expiry needs the running controller
  ([ADR 003](003-fail-open-ttl.md)). Enforced detector blackholes exist only
  behind the lease gate. When renewals stop, the speaker withdraws all of this
  owner's routes within `lease_seconds`. Before (d) ships, a manual blackhole
  is unleased. It stays advertised until the controller returns or an Admin
  removes it with a speaker-side `DeletePath`, which is the most dangerous
  remaining case. Monitor controller availability independently of BGP health.
  Lease expiry is daemon cleanup, not proof of router withdrawal.
- **Split brain.** The lifecycle mutex is in-process, and target registration is
  not a lease. Without owners, two controllers on one speaker cannot
  distinguish each other's routes. Upserts can overwrite, and one controller's
  withdrawal can delete the other's same-prefix route, which the other then
  re-injects. The result is flapping, not safety. Requirement (d) makes
  distinct owners unable to renew, delete or replace each other's routes. Two
  controllers deriving the same owner are a misconfiguration that startup
  refuses when it can detect one. Shared speakers stay unsupported until that
  work is qualified, and the [upgrade guide](../how-to/upgrading.md) procedures
  still apply.

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
   implementation and capability JSON, with `blackhole_lease` reported false
   until slice 7. GoBGP returns `None`. Manual blackholes need no lease and ship
   through slices 1 to 6. *Accept:*
   fake-RPC tests show paging to completion, `ABORTED` mid-walk as an error, an
   empty view as success, unexpected attributes as an error, delete
   `NOT_FOUND` as absent, and other codes as errors. Released-daemon tests
   through `scripts/test-rustbgpd.sh` cover inject, read, delete and loss on
   daemon restart for both families.
3. **Configuration and guardrails for manual blackholes.** Add the
   `blackhole` settings (TTL cap 3600, quotas 10 per POP and 50 globally),
   startup validation, victim checks, quotas inside `admit_mitigation` and the
   TTL cap. There is no playbook path yet. *Accept:* a rejection test for each
   guardrail with a negative control. A concurrent-admission PostgreSQL test
   cannot exceed the blackhole quota. Dry run persists and sends no RPC.
4. **Lifecycle and reconciliation.** Add announce with the safelist recheck,
   kind-aware withdrawal and expiry, repair, unknown-route reporting and the
   safelist withdrawal. *Accept:* tests mirroring the FlowSpec reconciliation
   tests show that an ambiguous delete stays pending and is never re-announced,
   a failed or partial read causes no repair, a foreign POP and unknown routes
   are untouched, an already safelisted victim is withdrawn rather than
   repaired, and a pre-existing unowned local route returns `409`.
5. **Operator surfaces.** Update Admin-only manual creation with
   confirmation, the API and OpenAPI, WebSocket, the frontend (type, badge,
   typed confirmation), CLI display, metrics and references. Update the
   FastNetMon guide to state that `ban_time` must be at or below the playbook
   step TTL, which is at or below the blackhole TTL cap, and to explain the
   `unban_only_if_attack_finished` gap, for use once slice 7 enables detector
   blackholes. *Accept:* a confirmation mismatch
   returns `400` with no row or audit entry. Operator and bearer-token callers
   get `403`. The frontend `bun run test` and `bun run build` pass. Docs links
   resolve.
6. **FRR interop qualification.** Extend the `lab/interop/` containerlab
   harness with an FRR IPv4/IPv6 unicast session and an import route-map that
   rewrites BLACKHOLE routes to a discard next hop. *Accept:* a dated receipt
   showing FRR receives both host routes with the expected communities and
   installs them as discard, then removes them on withdrawal and TTL expiry. It
   also records the route returning after a speaker restart and, for an
   unleased manual blackhole, persisting after a controller stop, recorded as
   the negative case. SR Linux has no FlowSpec but could serve as an optional
   second unicast receiver. This qualifies FRR only.
7. **Detector blackholes with owner and lease.** Add
   `PlaybookAction::Blackhole`, the source allowlist and the extension cap.
   Also add the enforced-mode lease gate at startup and on playbook reload or
   save, the owner identity and collision checks, the independent renewal
   task, lease health and metrics, restart adoption, immediate re-add on an
   expired lease, and owner-filtered read-back. The gate and plumbing can merge
   against the mock before the upstream release. Enforced detector blackholes
   become available only after re-vendoring a rustbgpd release that contains
   (d). *Accept:*
   - Enforced startup and playbook save are refused with a blackhole step when
     `blackhole_lease` is false, and accepted when it is true; dry-run accepts
     and sends no RPC.
   - Renewal proceeds while the lifecycle mutex and database are blocked.
   - An expired-lease report triggers a re-add, never a reported success.
   - Rows of other owners and rows without an owner are untouched.
   - A released-daemon test removes the routes once renewals stop.
   - An FRR receipt shows a killed controller's route disappearing at the
     router within the lease time.
8. **Later, each with its own decision:** GoBGP blackhole, next-hop-self once
   (c) ships, leasing FlowSpec rules, shared-speaker support on owner evidence,
   and FlowSpec-to-blackhole escalation.

## Consequences

FastNetMon Community users gain the mitigation they already use, behind
guardrails stricter than FlowSpec's. prefixd also takes on a unicast speaker
contract, a second identity namespace and a router-policy dependency: the
receiving router must turn the community or next hop into a discard. That
dependency is outside prefixd's evidence. Operators must add unicast families
to the speaker, separately from FlowSpec where the router requires it, and
restrict unicast export to BLACKHOLE host routes. Enforced detector blackholes
depend on an upstream feature (the rustbgpd injection lease) and cannot ship
before it. An unleased manual blackhole can outlive a stopped controller.

## Decisions recorded

The owner decided the following on 2026-10-19:

1. **Detector-driven enforced blackholes wait for the injection lease.**
   The owner-scoped lease, requirement (d), is a must-have for them. It is
   enforced by the `SpeakerCapabilities.blackhole_lease` gate at enforced
   startup and on playbook reload or save. Manual and dry-run blackholes may
   ship before it. The lease is per controller, renewed by `RenewLease(owner)`,
   and withdraws everything the owner added when it expires; per-route expiry
   stays with prefixd's TTLs.
2. **Manual blackholes require Admin.** Operator is not enough, so bearer
   tokens, which map to Operator, cannot create one.
3. **Default caps:** a TTL cap of 3600 seconds, and quotas of 10 per POP and 50
   globally. The cap covers FastNetMon Community's default `ban_time` of 1900
   seconds, because FastNetMon neither refreshes a ban nor bans a banned host
   again. Slice 5 documents the requirement that `ban_time` stays at or below
   the cap.
4. **The `source` allowlist is accepted** as a routing guard alongside detector
   credentials, not as authorization.
5. **Ownership arrives with the lease.** A separate owner tag is not required
   before the first enforced release: the one-controller-per-speaker rule
   covers manual blackholes. The owner-scoped lease gives enforced detector
   blackholes an owner as well. Owner evidence remains a must-have before
   shared-speaker support, and the combined lease and owner work is requested
   upstream before the freeze.
