# ADR 027: Remotely Triggered Blackhole Host Routes as a Second Mitigation Kind

## Status

Accepted 2026-10-19, with the owner decisions recorded below. Nothing in this
ADR is implemented yet. Extends
[ADR 004](004-destination-prefix-32-only.md),
[ADR 012](012-playbook-policy-engine.md) and
[ADR 025](025-pluggable-speaker-backends.md); qualifies the unicast caveat in
[ADR 002](002-flowspec-only-afi-safi.md).

Amended 2026-10-19: aligned with the rustbgpd injection lease contract,
proposed upstream as rustbgpd ADR-0141. Leased injection uses new RPCs, a
failed leased add never falls back to an unleased one, the owner is persisted
per route, and the leased and unleased transition is decided below. A
PostgreSQL advisory lock fences duplicate controllers.

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
`NO_EXPORT`, `NO_EXPORT_SUBCONFED` and `NO_ADVERTISE` in its configuration. The
rustbgpd configuration reference states that a route carrying `NO_EXPORT` or
`NO_EXPORT_SUBCONFED` is suppressed toward eBGP neighbors with
`interpret_rfc1997` (on by default), and rustbgpd's RFC 7999 ADR makes
`NO_ADVERTISE` pre-export ineligibility for unicast. Any of these communities
set at injection could keep the route from reaching the router. Scoping goes
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
`path_id = 0`. The resolved next hop, communities and injection owner (see
[Owner and lease](#owner-and-lease)) are snapshotted into the mitigation's
action parameters at admission. A configuration reload affects only
new mitigations, never live routes.

### 2. Guardrails

- **Enablement.** `blackhole.enabled` defaults to false. Startup refuses
  blackhole playbook steps or the manual blackhole action when the feature is
  disabled, the selected backend lacks the blackhole capability, or the
  safelist is empty. These checks run in dry-run and enforced modes alike.
- **Injection lease gate.** In enforced mode, startup and playbook reload or
  save refuse any playbook containing a `blackhole` step unless
  `SpeakerCapabilities.blackhole_lease` is true. The error names the missing
  rustbgpd injection lease. The capability is true only when
  `blackhole.leased` is enabled and the adapter's `ListInjectionLeases` call
  to the connected daemon succeeded; an older daemon answers `UNIMPLEMENTED`.
  The capability is the startup and playbook gate and the UI signal, but
  correctness does not depend on it: a daemon rolled back after the check
  answers the leased add itself with `UNIMPLEMENTED` and creates nothing
  (rustbgpd ADR-0141 §3, §11). Enforced detector blackholes are injected under
  the controller's owner and lease (see [Owner and lease](#owner-and-lease)).
  If the controller dies, the speaker removes them within one lease period.
  Dry-run detector blackholes and manual blackholes are not gated. The
  controller mode can only change at restart, so switching to enforced re-runs
  this check.
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
  immediately before every blackhole add (`AddPath` or `AddLeasedPath`): on
  admission and before each
  reconciliation repair. If the lookup fails, nothing is sent. If the victim is
  now safelisted, prefixd sends nothing and records a system withdrawal with
  the reason `safelisted after admission` through the normal immutable
  withdrawal path. Adding a safelist entry, and each reconciliation pass for
  routes already present, withdraws covered live blackholes the same way.
  FlowSpec repair behavior is unchanged by this ADR.
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
  holds the immutable route: prefix, next hop, communities and the injection
  owner the route was added under (`""` for an unleased route). No mitigation
  row is rewritten.
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
| upsert, unleased | `AddPath(prefix, prefix_length, next_hop, origin=0, communities, large_communities, path_id=0)` |
| upsert, leased | `AddLeasedPath(path=<the same AddPathRequest>, lease=InjectionLease{owner, lease_seconds})`, returning the owner's `LeaseGeneration` (rustbgpd ADR-0141 §3) |
| renew | `RenewLease(owner, generation, lease_seconds)` from the renewal task (ADR-0141 §2) |
| delete | `DeletePath(prefix, prefix_length, path_id=0, owner=<owner recorded in rule_json>)`, never with `override_owner`; `NOT_FOUND` means absent until `allow_missing` exists |
| read | `ListReceivedRoutes(neighbor_address="0.0.0.0")` per unicast family, following `next_page_token` to the end; rows carry `injection_owner`, `lease_generation` and `lease_remaining_ms` (ADR-0141 §3) |
| lease | `ListInjectionLeases(owner)` (`sensitive_read`) for the capability check and to learn the live generation after a prefixd restart (ADR-0141 §3, §8) |

Stages stay distinct:

1. **Desired intent.** An active, enforced-origin, unexpired blackhole row
   without pending withdrawal.
2. **RPC acceptance.** `AddPath` or `AddLeasedPath` returned OK. In the
   rustbgpd source,
   `handle_inject_route` inserts into the `0.0.0.0` Adj-RIB-In and runs best-path
   recomputation and distribution before replying.
3. **Retained local intent.** A `ListReceivedRoutes` row for `0.0.0.0` with the
   saved prefix, next hop, communities and owner. Reconciliation compares
   against this stage.
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
  Once (d) ships, a route must also carry the owner recorded for it (see
  [Owner and lease](#owner-and-lease)).
  - **Unleased path.** Before the first `AddPath` for a new unleased
    blackhole, prefixd reads the exact prefix. If a local row exists that the
    ledger does not own, admission returns `409` (untracked route) and nothing
    is sent. Once requirement (a) exists, a `replaced` outcome on a create is
    an alerted conflict.
  - **Leased path.** The daemon checks ownership atomically in the RIB turn
    that commits the add: a leased add on a key held by another owner or by no
    owner returns `FAILED_PRECONDITION` and changes nothing (rustbgpd ADR-0141
    §3, §4). prefixd maps that to the same `409` untracked-route response,
    retires the just-committed desired row locally with an audit entry and no
    delete RPC, and skips the pre-read. In reconciliation the same status is
    a repair failure, reported with the unknown route and never retried
    unleased.
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
  as absence. Every delete passes the owner recorded in `rule_json`. A
  `FAILED_PRECONDITION` reply means the key now belongs to a different owner
  (ADR-0141 §3); the withdrawal stays pending and is alerted, and prefixd
  never sets `override_owner`.
- **A failed or partial inventory is never empty.** A read succeeds only after
  both families page to an empty `next_page_token` with a consistent
  `page_version`. `ABORTED`, a missing family, a transport error or a decode
  error fails the stage: no repairs and no unknown-route verdicts. Withdrawal
  cleanup continues independently, as it does for FlowSpec. An empty, complete
  `0.0.0.0` listing is a valid empty result, because rustbgpd treats the
  synthetic local peer as always known.

### Owner and lease

This applies once the rustbgpd injection lease, requirement (d), ships as
specified in rustbgpd ADR-0141. It is required for enforced detector
blackholes. The owner identity also keys the
[controller fence](#controller-fence), which does not wait for the lease.

- **Owner identity.** Each controller has one stable owner, derived from its
  POP and the UUID of its verified speaker target, and unchanged across
  restarts. The owner is `prefixd.` + a sanitized POP prefix + `.` + the first
  16 lowercase hex characters of SHA-256 over the POP, a NUL byte and the
  target UUID in canonical lowercase hyphenated form. The POP prefix keeps
  `[A-Za-z0-9_-]`, maps every other character to `-`, and is truncated so the
  whole owner is at most 64 bytes. For example, POP `fra1` gives an owner of
  the form `prefixd.fra1.3f9c2a7b1e04d5c6`. The owner is deterministic across
  restarts, always valid under ADR-0141's 1 to 64 bytes of `[A-Za-z0-9._-]`
  (§3), and readable as a metric label. The hash keeps two POPs distinct even
  when sanitizing or truncation makes their prefixes identical. Changing the
  POP or the speaker target changes the owner, so both follow the
  [upgrade guide](../how-to/upgrading.md#drained-target-transfer). Within one
  database, a target belongs to exactly one POP, so two owners cannot collide,
  and the [controller fence](#controller-fence) allows one active process per
  owner. A collision across databases means two controllers are configured
  with the same POP against one speaker, which is a misconfiguration. Startup
  refuses when it can detect one: the speaker holds routes under this owner
  that the ledger neither desires nor is withdrawing. A generation change is
  not a collision signal: a second process with the same owner joins the live
  generation rather than starting a new one, and a changed generation is
  handled as lost state below.
- **Leased RPCs.** Leased injection uses `AddLeasedPath`, which wraps the
  existing `AddPathRequest` with `InjectionLease { owner, lease_seconds }`.
  `AddPath` and `AddFlowSpec` are unchanged, and an older daemon answers the
  leased RPCs with `UNIMPLEMENTED` and creates nothing (ADR-0141 §3, §11).
  Every leased add joins the owner's live lease and renews it, setting the
  deadline to now + `lease_seconds`, or starts a new generation when none is
  live. Ownership is enforced atomically by the daemon: a leased add on a key
  held by another owner or by no owner, and an unowned add on an owned key,
  both return `FAILED_PRECONDITION` with no change (ADR-0141 §3). prefixd
  therefore needs no extra refusal of its own. Moving a key between owners
  takes a delete followed by an add.
- **Never fall back.** A blackhole whose leased add fails for any reason,
  including `UNIMPLEMENTED`, is not enforced. It goes to the existing
  unconfirmed-announcement handling: the desired row stays, the request
  reports `announcement_outcome: "unconfirmed"`, repair errors appear in
  health and metrics, and reconciliation retries through `AddLeasedPath`
  only. It is never retried through plain `AddPath`, which the ADR-0141
  contract forbids (§3). Whether a route is leased or unleased is decided by
  configuration and mitigation kind at admission, never by an error path.
  `SpeakerCapabilities.blackhole_lease` remains the startup and playbook gate
  and the UI signal, but correctness no longer depends on it. Upstream
  rejected a mandatory capability probe because the daemon can be rolled back
  between the probe and the add, and rejected deleting whatever comes back
  unleased because the controller can die before the delete (ADR-0141 §3).
- **Owner persisted per route.** The owner a route was added under is
  snapshotted at admission and kept in the immutable blackhole `rule_json`,
  `""` for an unleased route. Repair, renewal and deletion use the recorded
  owner, not the current configuration. Every `DeletePath` passes it, and
  prefixd never sets `override_owner`. Startup refuses to disable
  `blackhole.leased` while leased intent is active or awaiting withdrawal.
- **Lease length.** `blackhole.leased` (default false) enables the leased
  path. `blackhole.lease_seconds` defaults to 60 and is validated at startup
  to 5..=3600, the daemon's bounds (ADR-0141 §7). Sixty seconds bounds a dead
  controller's blackholes to about a minute plus RIB queue lag, while renewal
  at `lease_seconds / 3` (20 s) survives one lost renewal with 20 s to spare and
  keeps successful renewals, which rustbgpd audits at `INFO`, to three per
  minute (ADR-0141 §8). Every leased add and every renewal uses this one value,
  because any leased add resets the owner's whole deadline: a shorter value on
  one add would shorten the lease for every route the owner holds.
- **Generation.** The daemon returns a `LeaseGeneration { incarnation,
  sequence }` from every leased add and renewal; the incarnation is random per
  daemon boot (ADR-0141 §2). prefixd holds the generation in memory only.
  After a prefixd restart it learns the generation from its first leased add
  or from `ListInjectionLeases(owner)`.
- **Renewal task.** A dedicated task calls `RenewLease(owner, generation,
  lease_seconds)` about every `lease_seconds / 3` with its own deadline, while
  it holds a generation. It never takes the lifecycle mutex, touches the
  database or waits for reconciliation. Renewal never resurrects a lease. A
  generation that is not live returns `FAILED_PRECONDITION` (ADR-0141 §2). A
  controller stall longer than the lease removes rustbgpd's routes. Whether
  traffic then reaches the victim depends on the other routes the network
  holds (ADR-0141 §5).
- **Visibility.** The lease state (live, renewal failing or expired) and the
  last renewal result appear in authenticated operational health. A renewal
  result counter and a lease-state gauge appear in metrics. Public liveness is
  unchanged.
- **Adoption and re-add.** After a prefixd restart within the lease, prefixd
  re-adds every active enforced leased blackhole under its recorded owner,
  with the safelist recheck. Each add joins the live lease, and renewal then
  resumes with the returned generation. When a renewal returns
  `FAILED_PRECONDITION`, or a leased add returns a generation other than the
  one held, prefixd assumes the owner's state is gone and runs a full leased
  re-add of the active intent immediately, not on its next poll (ADR-0141
  §2). A late renewal is never counted as success. The speaker restarting
  produces the same signal (ADR-0141 §9).
- **Read-back.** A desired route matches only a row whose `injection_owner`
  equals the owner recorded for it, unset for an unleased route. A leased row
  with `lease_remaining_ms` of 0 is expired with its withdrawal pending
  (ADR-0141 §3); prefixd treats it as lost and triggers the full re-add. Rows
  of other owners, and unowned rows the ledger does not hold, are still
  reported as unknown and are never modified.
- **Manual blackholes.** Once `blackhole.leased` is enabled, new enforced
  manual blackholes use the same owner and lease. Before then they are
  unleased.
- **Leased and unleased transition.** A blackhole added unleased, such as a
  manual one from before the lease shipped, stays unleased until it is
  withdrawn or expires. Extending it does not convert it, because conversion
  takes a delete followed by an add, which reopens traffic to the victim in
  between. New blackholes use the leased path once it is enabled. A leased add
  on a key that holds prefixd's own unleased route would return
  `FAILED_PRECONDITION`, but the existing rules prevent it. The partial unique
  index `idx_mitigations_active_scope` allows one pending or active blackhole
  per victim and POP, and an extension of that row sends no add. A pending
  withdrawal of the unleased route blocks a new ban with the existing `409`,
  and the route is gone once the withdrawal completes. If the status occurs
  anyway, it is handled as an untracked route: the leased add is not retried
  unleased and the unleased route is not deleted.
- **FlowSpec.** Leasing FlowSpec rules too, through `AddLeasedFlowSpec`, would
  close the AGENTS.md gap that rules can persist if prefixd stops. That is a
  later decision and is outside every slice below.

### Controller fence

The lifecycle mutex is in-process, so it cannot stop a second controller
process. Each controller therefore fences itself with a PostgreSQL session
advisory lock keyed on its owner name (see
[Owner and lease](#owner-and-lease)). The fence covers every speaker mutation,
FlowSpec included, and does not depend on the lease or on blackholes being
enabled. The owner name is derived as above in every deployment.

- **Lock key.** A stable `i64`: the first 8 bytes, read big-endian, of
  SHA-256 over the fixed tag `prefixd-controller-fence\0` followed by the
  owner. The tag keeps the key away from other advisory-lock users. The fence
  uses PostgreSQL's single 64-bit key form, which does not overlap the
  two-integer key space of the existing quota lock in `admit_mitigation`.
- **Acquisition.** After target registration and before any speaker
  connection, the controller calls `pg_try_advisory_lock(key)`. It never runs
  active without the lock. When the database is shared, exactly one controller
  per owner is active. A clean restart needs no lease wait: the old process's
  session ends, PostgreSQL releases the lock, and the new process takes it and
  announces at once. In a rolling deploy, the overlapping process waits in
  standby instead of competing. A crashed host holds the lock until
  PostgreSQL ends its session, so the deployment sets TCP keepalives on the
  fence connection or the server to bound that delay.
- **Dedicated connection.** The lock is held on one connection opened outside
  the sqlx pool, because the pool recycles connections and a session lock
  would follow the recycled session. Transaction-mode poolers such as
  PgBouncer transaction pooling break session advisory locks. The fence
  connection must be direct or use a session-mode pooler, and the deployment
  documentation must say so.
- **Standby.** Without the lock, the controller runs no scheduler, expiry,
  reconciliation, announcement, withdrawal or lease renewal, and refuses
  mutation requests with `503`. Public liveness stays up, and authenticated
  operational health reports `standby` with a fence-state metric. Standby
  retries `pg_try_advisory_lock` every 5 seconds rather than blocking in
  `pg_advisory_lock`, so it stays observable and responsive to shutdown.
- **Losing the lock.** A failed fence check, a dropped fence connection or a
  database restart means the lock may be gone. The controller stops starting
  speaker mutations at once, returns to standby and polls to reacquire on a
  new connection. An RPC already in flight runs to its own deadline. Its
  result is recorded only if the database write succeeds; otherwise the
  announcement stays unconfirmed, or the withdrawal stays pending with its
  original rule, actor, reason and operation ID. Whichever process next holds
  the lock reconciles that durable intent; an ambiguous delete still never
  becomes an announcement. The fence connection runs a health query every 2
  seconds with a 2-second timeout. A process that lost its lock without
  seeing it can therefore keep issuing RPCs for up to about 4 seconds plus one
  RPC deadline, overlapping a new holder under the same owner. That window is
  well under the 60-second default lease, and the overlap is the existing
  flapping risk, bounded in time. The daemon's ownership checks do not
  separate the two processes, because they share an owner.
- **Lease interaction.** A restarted process that takes the lock adopts the
  existing lease under the same owner. It learns the generation from
  `ListInjectionLeases(owner)` or its first leased add, so restarts and
  deploys have no lease-length gap. Standby never renews, so a lease outlives
  a fenced-out process only until its deadline.
- **Startup check stays.** Startup still refuses when the speaker holds
  routes under this owner that the ledger neither desires nor is withdrawing.
  It is the only check for two controllers with separate databases, which the
  lock cannot see.
- **Rejected:** a holder or takeover check in rustbgpd. A holder check would
  block a restarted controller until the old lease runs out, up to the lease
  length of no new mitigation on every restart or deploy. Fixing that needs a
  takeover option, which brings the duplicate back. A lease guards against a
  dead controller and cannot choose between two live ones. A "last renewing
  credential" field in `ListInjectionLeases` is not requested now; it remains
  possible future diagnostics.

## rustbgpd requirements before the v1.0 freeze

Each item was checked against the rustbgpd source and the vendored
`proto/rustbgpd.proto`. Items (a) and (e) are must-haves for any enforced
blackhole. Item (d) is a must-have for enforced detector-driven blackholes.

| Ask | Exact requirement | Verified today | Need |
|-----|-------------------|----------------|------|
| (a) AddPath outcome | `AddPathResponse.outcome` on a new field number (field 1 is `reserved`): `CREATED`, `REPLACED`, `UNCHANGED`, with `UNSPECIFIED` treated as an error, mirroring `FlowSpecInjectOutcome` | `AddPathResponse` has only `reserved 1`. The RIB's `insert` already knows whether it replaced a path, but the reply is `Ok(())` | **Must-have for the unleased manual path.** A non-atomic pre-read plus upsert can silently replace a foreign unowned route for the victim; the outcome is the only evidence. Leased adds get atomic ownership checks from the daemon instead (rustbgpd ADR-0141 §3) |
| (b) Delete `allow_missing` | `DeletePathRequest.allow_missing` and `DeletePathResponse.outcome` (`DELETED`, `NOT_PRESENT`) | Missing paths return `NOT_FOUND` from `handle_withdraw_injected`. `DeletePathResponse` is empty | Nice-to-have. That `NOT_FOUND` is the only one the RPC produces, so mapping it to absent is safe, as the FlowSpec adapter already does for older daemons |
| (c) Next-hop-self | A documented self marker on `AddPath`, resolved per egress session, for both families | `parse_unicast_nexthop` rejects `0.0.0.0`, `::`, multicast and broadcast. IPv6 prefixes require IPv6 next hops | Nice-to-have. An explicit discard next hop works today |
| (d) The rustbgpd injection lease (owner-scoped) | rustbgpd ADR-0141, summarized below | No owner or lease exists. `Route` and `FlowSpecRouteEntry` have no owner, and every local row shows peer `0.0.0.0` | **Must-have for enforced detector-driven blackholes** (the lease gate). Manual and dry-run blackholes do not need it. It is the only remedy for a stopped controller, and it is also the ownership evidence needed before shared-speaker support |
| (e) Vendored proto | Re-vendor at the first release containing (a), then at the release containing ADR-0141, and bump the qualification pin each time | Unicast injection messages match upstream, but the vendored file is behind (it lacks, for example, `ComparePolicy` and `GetLastSighupReload`) | **Must-have.** This work is prefixd-side and mechanical |

Requirement (d), as proposed upstream in rustbgpd ADR-0141 on 2026-10-19:

- **Owner-scoped.** The lease belongs to a controller as a whole, like a
  dead-man's switch. It is not a per-route timer: per-route expiry stays with
  prefixd's TTLs (ADR-0141 §1).
- **Leased RPCs.** `AddLeasedPath` and `AddLeasedFlowSpec` wrap the existing
  request messages with `InjectionLease { owner, lease_seconds }`. `AddPath`
  and `AddFlowSpec` are unchanged. An older daemon answers `UNIMPLEMENTED` and
  creates nothing, and the contract forbids retrying a failed leased add
  through `AddPath` or `AddFlowSpec` (ADR-0141 §3).
- **Lease length.** `lease_seconds` must be 5..=3600. Any leased add joins the
  owner's live lease and renews it, with deadline = now + `lease_seconds`
  (ADR-0141 §3, §7). The owner is never sent in BGP.
- **Renewal and generation.** Each live lease has a `LeaseGeneration
  { incarnation, sequence }`, with the incarnation random per boot.
  `RenewLease(owner, generation, lease_seconds)` returns
  `FAILED_PRECONDITION` when that generation is not live and never resurrects
  a lease. After that status, or a leased add returning a different
  generation, the controller re-adds its full desired state. Renewals are
  served from the lease table and never wait behind RIB work, and lease time
  uses a monotonic clock (ADR-0141 §2, §4, §6). `ListInjectionLeases`
  (`sensitive_read`) reports owner, generation and remaining time.
- **Expiry.** The daemon withdraws everything the owner added in one batch,
  with a warning log and a metric (ADR-0141 §4, §10). Expiry removes
  rustbgpd's own local intent. It does not promise that traffic flows again:
  another source's equal or better route, or a received FlowSpec rule, can
  still apply (ADR-0141 §5). If the expiry task dies unexpectedly, rustbgpd
  shuts down rather than silently stop expiring leases (ADR-0141 §9).
- **Ownership.** The daemon enforces ownership atomically. A leased add on a
  key held by another owner or by no owner, an unowned add on an owned key,
  and a delete whose `owner` (`""` for unowned) does not match the entry all
  return `FAILED_PRECONDITION` with no change. `DeletePath` and
  `DeleteFlowSpec` also gain `override_owner`, which prefixd never uses.
  Local-intent rows from `0.0.0.0` report `injection_owner`,
  `lease_generation` and `lease_remaining_ms`, where 0 means expired with the
  withdrawal pending (ADR-0141 §3).
- **Authorization.** `RenewLease` and the leased adds are `operator_only`, the
  same tier as today's adds. A successful renewal is audited at `INFO`. The
  owner is a label, not a security boundary: the audit line records the
  caller's principal beside it (ADR-0141 §8).
- **Bounds.** At most 64 live owners; a leased add that would create one more
  returns `RESOURCE_EXHAUSTED` (ADR-0141 §3, §7).
- **Interop proof.** Kill the controller, and the route disappears at FRR
  within the lease time (ADR-0141 §12).
- **Rejected upstream alternatives.** Renewing by re-adding every route was
  rejected for its RIB cost and because it cannot express "controller dead". A
  stream-scoped lease was rejected because a proxy timeout or a stall would
  drop everything (ADR-0141 §1). A mandatory capability probe and deleting
  whatever comes back unleased were rejected in favor of separate RPCs
  (ADR-0141 §3).

Items (a)–(c) are reported as in progress upstream, and (d) is proposed as
rustbgpd ADR-0141; none of them was in the source checked. Because the surface
is already in rustbgpd's v1 inventory, (a), (b) and (d) are additive features
that should land before the freeze.

## Failure modes

- **Speaker restart.** Injected paths live in rustbgpd's in-memory `0.0.0.0`
  Adj-RIB-In and are lost on restart, and router sessions drop. The blackhole
  lifts and attack traffic resumes until reconciliation re-injects live,
  unexpired, non-safelisted intent under its recorded owner. Once (d) ships,
  that happens as soon as a renewal returns `FAILED_PRECONDITION` or a read
  sees the loss (rustbgpd ADR-0141 §9). Graceful Restart on the router can
  retain the stale route meanwhile. Qualification must measure this interval.
- **Speaker expiry task dies.** rustbgpd shuts down rather than silently stop
  expiring leases (ADR-0141 §9). prefixd sees a speaker restart, and
  reconciliation re-adds as above.
- **Controller stopped, speaker up.** TTL expiry needs the running controller
  ([ADR 003](003-fail-open-ttl.md)). Enforced detector blackholes exist only
  behind the lease gate. When renewals stop, the speaker removes all of this
  owner's routes within `lease_seconds` plus its RIB queue lag (ADR-0141 §4).
  Expiry removes rustbgpd's route; whether traffic then reaches the victim
  depends on the other routes the network holds (ADR-0141 §5). Before (d)
  ships, and afterwards for a blackhole added before the leased path was
  enabled, a manual blackhole is unleased. It stays advertised until the
  controller returns or an Admin removes it with a speaker-side `DeletePath`,
  which is the most dangerous remaining case. Monitor controller availability
  independently of BGP health. Lease expiry is daemon cleanup, not proof of
  router withdrawal.
- **Split brain.** The lifecycle mutex is in-process, and target registration is
  not a lease. Two controllers sharing a database are fenced: only the holder
  of the owner's advisory lock mutates the speaker (see
  [Controller fence](#controller-fence)), apart from the bounded window after
  an unnoticed lock loss. With separate databases the lock cannot see the
  other process. Without owners, two controllers on one speaker cannot
  distinguish each other's routes. Upserts can overwrite, and one controller's
  withdrawal can delete the other's same-prefix route, which the other then
  re-injects. The result is flapping, not safety. Requirement (d) stops
  distinct owners from deleting or replacing each other's routes by mistake
  (ADR-0141 §3). The owner is a label, not a security boundary (ADR-0141
  §8). Two controllers with separate databases deriving the same owner are a
  misconfiguration that only the startup check catches, and only partly: it
  sees the other controller's routes once they exist, not a second controller
  that has not yet added any. Shared speakers stay unsupported
  until that work is qualified, and the
  [upgrade guide](../how-to/upgrading.md) procedures still apply.

## Implementation slices

Each slice is a separate draft PR that passes `just gate`.

1. **Controller fence.** Add the owner derivation, the advisory-lock key,
   the dedicated fence connection, acquisition before any speaker connection,
   standby, the fence health check, lock loss and reacquisition, and the
   health and metric surfaces (see [Controller fence](#controller-fence)). It
   protects FlowSpec today, depends on no other slice and no upstream
   release, and ships first. Slices 2 to 7 do not depend on it. Slice 8
   requires it, because lease adoption assumes one active process per owner.
   The deployment documentation states that the fence connection needs a
   direct or session-mode connection. *Accept:*
   - Two processes against one PostgreSQL instance: exactly one is active and
     the other reports standby, and the fake records no mutation RPC from the
     standby.
   - Killing the active process lets the standby take over within the poll
     interval.
   - Dropping the fence connection forces standby, with no further mutation
     RPCs after the loss is noticed.
   - A unit test pins one owner derivation, covering a POP name that needs
     sanitizing and checking that every derived owner is at most 64 bytes of
     `[A-Za-z0-9._-]`. A unit test pins the lock key derivation.
   - Negative control: with the lock acquisition removed, the two-process test
     shows both processes sending mutation RPCs.
2. **Kind-aware identity and schema, without behavior.** Add the
   `ActionType::Blackhole` parse path, `MitigationRoute`, kind-discriminated
   hashes, migration 016, and fail-closed FlowSpec paths. *Accept:* existing
   FlowSpec hashes are unchanged (golden test). Migration replay on a populated
   database keeps every request `flowspec`. A blackhole and an any-protocol
   FlowSpec rule on one host have distinct keys. A blackhole row reaching a
   FlowSpec path errors with no RPC.
3. **Speaker capability and rustbgpd adapter.** Add the trait, mock, rustbgpd
   implementation and capability JSON, with `blackhole_lease` reported false
   until slice 8. GoBGP returns `None`. Manual blackholes need no lease and ship
   through slices 2 to 7. *Accept:*
   fake-RPC tests show paging to completion, `ABORTED` mid-walk as an error, an
   empty view as success, unexpected attributes as an error, delete
   `NOT_FOUND` as absent, and other codes as errors. Released-daemon tests
   through `scripts/test-rustbgpd.sh` cover inject, read, delete and loss on
   daemon restart for both families.
4. **Configuration and guardrails for manual blackholes.** Add the
   `blackhole` settings (TTL cap 3600, quotas 10 per POP and 50 globally),
   startup validation, victim checks, quotas inside `admit_mitigation` and the
   TTL cap. There is no playbook path yet. *Accept:* a rejection test for each
   guardrail with a negative control. A concurrent-admission PostgreSQL test
   cannot exceed the blackhole quota. Dry run persists and sends no RPC.
5. **Lifecycle and reconciliation.** Add announce with the safelist recheck,
   kind-aware withdrawal and expiry, repair, unknown-route reporting and the
   safelist withdrawal. *Accept:* tests mirroring the FlowSpec reconciliation
   tests show that an ambiguous delete stays pending and is never re-announced,
   a failed or partial read causes no repair, a foreign POP and unknown routes
   are untouched, an already safelisted victim is withdrawn rather than
   repaired, and a pre-existing unowned local route returns `409`.
6. **Operator surfaces.** Update Admin-only manual creation with
   confirmation, the API and OpenAPI, WebSocket, the frontend (type, badge,
   typed confirmation), CLI display, metrics and references. Update the
   FastNetMon guide to state that `ban_time` must be at or below the playbook
   step TTL, which is at or below the blackhole TTL cap, and to explain the
   `unban_only_if_attack_finished` gap, for use once slice 8 enables detector
   blackholes. *Accept:* a confirmation mismatch
   returns `400` with no row or audit entry. Operator and bearer-token callers
   get `403`. The frontend `bun run test` and `bun run build` pass. Docs links
   resolve.
7. **FRR interop qualification.** Extend the `lab/interop/` containerlab
   harness with an FRR IPv4/IPv6 unicast session and an import route-map that
   rewrites BLACKHOLE routes to a discard next hop. *Accept:* a dated receipt
   showing FRR receives both host routes with the expected communities and
   installs them as discard, then removes them on withdrawal and TTL expiry. It
   also records the route returning after a speaker restart and, for an
   unleased manual blackhole, persisting after a controller stop, recorded as
   the negative case. SR Linux has no FlowSpec but could serve as an optional
   second unicast receiver. This qualifies FRR only.
8. **Detector blackholes with owner and lease.** Add
   `PlaybookAction::Blackhole`, the source allowlist and the extension cap.
   Also add the `blackhole.leased` and `blackhole.lease_seconds` settings,
   the enforced-mode lease gate at startup and on playbook reload or save, the
   owner collision checks, the per-route owner in `rule_json`,
   `AddLeasedPath` with no unleased fallback, the independent renewal task,
   lease health and metrics, restart adoption, the full re-add on a lost
   lease, and owner-filtered read-back. The gate and plumbing can merge
   against the mock before the upstream release. Enforced detector blackholes
   become available only after re-vendoring the proto at the rustbgpd release
   that contains ADR-0141 and bumping the qualification pin. *Accept:*
   - Enforced startup and playbook save are refused with a blackhole step when
     `blackhole_lease` is false, and accepted when it is true; dry-run accepts
     and sends no RPC.
   - Renewal proceeds while the lifecycle mutex and database are blocked.
   - `UNIMPLEMENTED` from an older daemon on the leased add leaves nothing
     installed and makes no plain `AddPath` call: the fake records zero
     `AddPath` calls, and the mitigation stays unconfirmed.
   - `FAILED_PRECONDITION` from a renewal, and a leased add returning a
     different generation, each trigger a full leased re-add of the active
     intent, never a reported success.
   - Every delete passes the owner recorded in the request's `rule_json`, and
     none sets `override_owner`.
   - `blackhole.lease_seconds` outside 5..=3600 is refused at startup, and
     every leased add and renewal in the fake carries the configured value.
   - Rows of other owners and rows without an owner are untouched.
   - A released-daemon test removes the routes once renewals stop.
   - An FRR receipt shows a killed controller's route disappearing at the
     router within the lease time.
9. **Later, each with its own decision:** GoBGP blackhole, next-hop-self once
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
   ship before it. The lease is per controller, renewed by `RenewLease`,
   and withdraws everything the owner added when it expires; per-route expiry
   stays with prefixd's TTLs.
2. **Manual blackholes require Admin.** Operator is not enough, so bearer
   tokens, which map to Operator, cannot create one.
3. **Default caps:** a TTL cap of 3600 seconds, and quotas of 10 per POP and 50
   globally. The cap covers FastNetMon Community's default `ban_time` of 1900
   seconds, because FastNetMon neither refreshes a ban nor bans a banned host
   again. Slice 6 documents the requirement that `ban_time` stays at or below
   the cap.
4. **The `source` allowlist is accepted** as a routing guard alongside detector
   credentials, not as authorization.
5. **Ownership arrives with the lease.** A separate owner tag is not required
   before the first enforced release: the one-controller-per-speaker rule
   covers manual blackholes. The owner-scoped lease gives enforced detector
   blackholes an owner as well. Owner evidence remains a must-have before
   shared-speaker support, and the combined lease and owner work is requested
   upstream before the freeze.
6. **prefixd fences duplicate controllers itself.** Each controller holds a
   PostgreSQL session advisory lock keyed on its owner before it mutates the
   speaker, and stays in standby without it; the fence covers FlowSpec too.
   rustbgpd gets no holder or takeover check: a holder check would block every
   restart or deploy for up to one lease, and a takeover option would
   reintroduce the duplicate. A lease guards against a dead controller and
   cannot choose between two live ones. The startup check for unexplained
   routes under this owner stays, for controllers with separate databases. A
   "last renewing credential" field in `ListInjectionLeases` is possible
   future diagnostics, not a current request.
