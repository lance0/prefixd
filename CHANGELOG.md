# Changelog

All notable changes to prefixd will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Update the build-time Markdown parser `pulldown-cmark` to 0.13.5 in both
  lockfiles for RUSTSEC-2026-0414. It is used by protobuf code generation;
  no advisory exception or runtime behavior change is introduced.

### Changed

- The event dashboard now uses 20-row server cursor navigation, literal search
  across IP and event UUID, and exact source/vector filters. Ordering
  is fixed by ingestion time. CSV export traverses every matching page and
  refuses incomplete, duplicate or nonadvancing results. Exports are live and
  retained in browser memory; large-history memory qualification remains open.
  `GET /v1/events` accepts bounded `q`, `source` and `vector` parameters while
  preserving unfiltered behavior and the existing tuple cursor format.
- Dashboard CSV exports now quote carriage returns inside fields, preserving
  detector and audit text as one field instead of creating extra CSV records.

- The dashboard mitigation list now uses complete server cursor navigation and
  server-side search, customer, POP and status filters instead of filtering only
  the newest 100 rows. Pages stay in newest-first order; column sorting of a
  bounded subset is removed. Selection is page-scoped, and CSV export walks all
  matching pages, refusing a partial download on failure. Exports are live
  traversals and retain matching rows in browser memory. Only one page is
  rendered at a time; standard SWR caching retains visited pages for the app
  lifetime, and large-history memory qualification remains open. Search drafts
  that exceed the UTF-8 byte limit or contain null characters retain the last
  valid results without submitting the invalid query. Empty filter choices are
  omitted and identifiers named `All` remain selectable.
- `GET /v1/mitigations` accepts bounded literal substring search through `q`,
  covering target, vector, customer ID and mitigation UUID before pagination.
- rustbgpd ownership refusals now distinguish `owner_mismatch` from
  `key_unowned` in admission `409` bodies, retirement audit reasons and
  operational logs. Missing, malformed, conflicting or unrecognized rich-status
  details use `unspecified`; prefixd still changes no speaker route and never
  falls back to an unleased add. Refused lease renewals still trigger a full
  leased re-add and retain the existing `not_live` health result, with a typed
  `generation_not_live` diagnostic when the speaker supplies it.

### Added

- CI runs the authenticated browser withdrawal smoke against disposable
  PostgreSQL and pinned rustbgpd, reusing the candidate controller binaries and
  production dashboard build. It checks pending confirmation, persisted/rendered
  audit and fresh local speaker intent before and after withdrawal, retains
  protected failure evidence, and removes its owned stack. No router enforcement
  qualification is implied.

- FastNetMon guidance distinguishes its source-build native rustbgpd RTBH
  action from the prefixd notify path, and explains the exclusive speaker-target
  requirement and leased/unleased route conflicts.
- Per-peer FlowSpec export evidence on rustbgpd, keyed by the full canonical
  match and shown on mitigation detail, authenticated health and the dashboard.
  Separate bounded FlowSpec metrics preserve the existing blackhole metrics.
  Both kinds share one fair, rotating 10-second observation budget. Failed and
  historical reads remain distinct from empty or unsupported observation;
  committed means the peer's Adj-RIB-Out, not router enforcement. No configuration
  or schema migration is required, and the existing blackhole alert stays scoped
  to blackholes.

- An optional `docker-compose.inventory.yml` overlay reads
  `configs/inventory.yaml` directly from the host for either speaker profile.
  Existing volume-managed inventories remain the default. The quickstart covers
  switching workflows, reloading edits and recreating stale file mounts.

### Fixed

- A controller running in dry-run continues to observe export for active
  FlowSpec rules retained from an earlier run, while excluding rows recorded
  as dry-run. Observation sends no announcement, withdrawal or lease renewal,
  and never infers an unknown legacy admission mode.

- Export metric scrapes now exclude peer dispositions and unexported warnings
  from before the controller lost ownership, including during standby and after
  regain before the next observation pass. Read-error metrics still describe
  attempted reads; ownership loss alone does not count as a failed RPC.

## [0.23.1] - 2026-10-26

prefixd 0.23.1 makes planned rustbgpd restarts clearer and shorter. A
blackhole that the speaker holds from selection after its restart now reports
the unexported reason `selection_deferred`, and the example rustbgpd
configuration disables Graceful Restart on its placeholder neighbor, so in
the Compose quickstart replayed rules are selected as soon as reconciliation
re-adds them instead of after the 120-second restart window. There is no migration and no
configuration change; copy the updated alert rules.

### Upgrade notes

- Follow
  [v0.23.0 → 0.23.1](https://github.com/lance0/prefixd/blob/v0.23.1/docs/how-to/upgrading.md#v0230--0231)
  in the upgrade guide: replace the controller and dashboard, then copy
  `grafana/prometheus-alerts.yml`. No migration, adoption step or
  configuration change is required, and rustbgpd stays at 0.80.1.

- `selection_deferred` is a new value of the `reason` label on
  `prefixd_blackhole_unexported` and of the blackhole export warning. Check
  your own queries and silences that match `reason="pending"`.

- If you based your rustbgpd configuration on the shipped example, set
  `graceful_restart = false` on any neighbor that never comes up, or remove
  that neighbor. See
  [speaker upgrade notes](https://github.com/lance0/prefixd/blob/v0.23.1/docs/how-to/upgrading.md#rustbgpd-v080).

### Known limitations

- After a planned speaker restart, rustbgpd v0.80.x holds injected routes,
  blackholes included, from selection while any Graceful Restart peer is
  down, until that peer sends End-of-RIB or `gr_restart_time` expires (120
  seconds by default). `MarkReplayComplete` does not end the hold. Disable
  Graceful Restart on peers that never come up. The example configuration
  change removes only its placeholder neighbor's hold. prefixd reports a held
  blackhole as `selection_deferred` and cannot end the hold.
- The 0.23.0 known limitations otherwise still apply.

### Changed

- A blackhole that every Established peer reports as pending with rustbgpd's
  `selection_deferred` reason now carries the unexported reason
  `selection_deferred` instead of `pending`, in detail, health and
  `prefixd_blackhole_unexported{reason}`. The speaker accepted the route but
  holds route selection after its restart until Graceful Restart peers send
  End-of-RIB or the restart window expires. Health stays `degraded` while the
  route is exported to no peer. A mix of pending reasons stays `pending`.
  `PrefixdBlackholeNotExported` adds a hint for the new reason and keeps its
  five-minute window, which outlasts the default 120-second hold.

### Fixed

- The example `configs/rustbgpd.toml` disables Graceful Restart on its
  placeholder neighbor. That neighbor never connects, so after each planned
  rustbgpd restart in the Compose quickstart, replayed FlowSpec rules were
  held from selection until the restart window (`gr_restart_time`, 120
  seconds by default) expired. They are now selected as soon as
  reconciliation re-adds them. Enable Graceful Restart on real peers that
  support it.

## [0.23.0] - 2026-10-26

prefixd 0.23.0 lets manual FlowSpec rules target guarded destination CIDRs
and same-family source prefixes, previews manual admission without side
effects, and extends an active rule's lifetime with an audit trail, optionally
bounded by a new total lifetime cap. The Inventory page,
`prefixdctl speaker list-routes` and `GET /v1/speaker/routes` show the
speaker's local FlowSpec routes. rustbgpd v0.80.0 or later is now required:
upgrade it before prefixd. There is no migration; check the destination prefix
bounds and `inventory.yaml` before upgrading.

### Upgrade notes

- Follow
  [v0.22.1 → 0.23.0](https://github.com/lance0/prefixd/blob/v0.23.0/docs/how-to/upgrading.md#v0221--0230)
  in the upgrade guide: upgrade rustbgpd first, then replace the controller
  and dashboard. No migration or adoption step runs, and
  `grafana/prometheus-alerts.yml` is unchanged.

- prefixd now requires rustbgpd v0.80.0 or later and refuses to start against
  an older daemon; upgrade the speaker first. Compose and the default speaker
  fixture pin v0.80.1. Scoped peer observations preserve their interface, and
  interface-only peers report discovery without aliasing another neighbor.
  Exact peer metric labels can change. See
  [speaker upgrade notes](https://github.com/lance0/prefixd/blob/v0.23.0/docs/how-to/upgrading.md#rustbgpd-v080).

- Check `guardrails.dst_prefix_minlen` and `dst_prefix_minlen_v6` before
  upgrading. Earlier releases ignored values below 32 and 128; this release
  admits manual destination CIDRs down to those lengths. Set them to 32 and 128
  first if you do not want CIDRs. See
  [manual destination CIDRs and downgrade](https://github.com/lance0/prefixd/blob/v0.23.0/docs/how-to/upgrading.md#manual-destination-cidrs-and-downgrade).

- Inventory load and reload now reject an unparseable customer prefix or asset
  IP. Startup fails on one, and a failed reload keeps the previous inventory;
  validate `inventory.yaml` before upgrading.

### Known limitations

- TTL expiry needs the running controller. Unleased FlowSpec rules and
  blackholes stay announced if prefixd stops while the speaker stays up; the
  leased modes, which bound that to one lease, are opt-in and rustbgpd-only.
- `guardrails.max_lifetime_seconds` bounds ordinary FlowSpec intent in prefixd.
  It does not cap blackholes or set a deadline on the speaker, and a
  controller downgrade removes it.
- Admission preview reserves no capacity, and creation rechecks it. Preview,
  the local route view and lifetime extension observe neither export nor
  router enforcement.
- prefixd does not yet use rustbgpd v0.80's FlowSpec and batch export reads or
  replay-complete signaling. Do not list prefixd in
  `global.gr_eor_replay_owners`.
- Leave `guardrails.allow_src_prefix_match` false until the receiving routers
  are qualified for source-prefix matches.
- The 0.21.0 known limitations otherwise still apply, except that
  `allow_src_prefix_match` is no longer reserved; `allow_tcp_flags_match`
  still is.

### Security

- **ctutils** — Updated 0.4.2 → 0.4.4, which removes secret-dependent branches
  from constant-time mask generation and `u128` comparisons
  (RUSTSEC-2026-0385). The crate reaches the HMAC signing and verification
  used for signal webhooks and alert delivery through `hmac` and `sha2`.
- **tokio** — Updated 1.52.3 → 1.53.3, which deprecates the `AsyncFd`
  constructors that let safe code register file descriptors it does not own
  (RUSTSEC-2026-0386). prefixd does not call `AsyncFd` directly.

### Added

- Optional nonzero `guardrails.max_lifetime_seconds` caps each ordinary FlowSpec
  rule's lifetime from original creation across admission, detector refreshes and
  operator extensions. Over-cap requests are refused without changing expiry or
  extension audit; unset preserves existing behavior. Existing rows are never
  retroactively shortened. Blackhole policy is separate.

- Authenticated `POST /v1/mitigations/preview` and the manual rule form's optional
  **Check admission** action evaluate the same FlowSpec preparation and safety
  policy as creation without saving intent or calling the speaker. Results show
  the complete candidate, owner attribution, requested lifetime, mode and check
  time, distinguish refusal from unavailable reads, and clear on edits. Capacity
  is not reserved; creation rechecks. Speaker-side state and router enforcement
  remain unobserved. Blackhole preview is unavailable.
  Preview does not take the lifecycle mutex, so it never delays detector ingest,
  expiry or withdrawal. Its preparation and safety reads have a five-second
  deadline; timeout returns an unavailable result without saving intent,
  preserving the prepared candidate when available. Each preview database read
  runs in a read-only transaction with a transaction-local server deadline,
  releasing blocked queries and returning its connection to the pool.

- Operators can extend an active enforced FlowSpec rule from its detail page or
  `POST /v1/mitigations/{id}/extend`, with a required reason and atomic old/new
  expiry audit. Remaining lifetime stays bounded and never shortens the saved
  horizon; an unchanged horizon writes no revision or audit. Fresh ownership,
  safelist, binding and match-policy checks protect the exact existing rule,
  without creating another mitigation, consuming a quota slot or mutating the
  speaker. Blackholes, simulations, pending and expired intent are refused.
  Each read-only preparation read runs in a read-only transaction with a
  transaction-local server deadline, so timed-out checks release blocked queries
  and return their connections to the shared database pool.

- `prefixdctl mitigations extend` requests a guarded FlowSpec lifetime extension
  with a required TTL and reason. Table and JSON output distinguish a saved
  extension from an unchanged horizon and include the previous and saved expiry.

- Manual FlowSpec discard and police rules accept aligned IPv4/IPv6 destination
  CIDRs in `victim_ip` when operators deliberately relax existing prefix bounds.
  Whole-prefix customer ownership, all safelist overlaps and fresh repair checks
  protect admission; new safelist entries withdraw affected owned rules in full.
  The dashboard previews the complete match and expiry, keeps CIDRs on their
  mitigation detail pages, and generates exact-target reports without implying
  host aggregation. Defaults, detectors, playbooks and RTBH remain host-only.

- The Inventory page shows the selected speaker's local IPv4/IPv6 FlowSpec
  routes, complete matches, actions and injection owners. Observation scope
  distinguishes rustbgpd retained intent from GoBGP accepted local RIB;
  unsupported or failed reads stay unknown and never appear as an empty table.
  Customer inventory remains independently available. This view does not prove
  export or router enforcement and does not include blackholes.

- Nightly and manually triggered smoke checks execute the existing benchmark
  bodies once and run both parser fuzz targets with bounded input, time and
  memory budgets. Logs and fuzz artifacts are retained after failures; these
  checks make no performance claim. Release preparation keeps the fuzz
  lockfile's package version aligned with the controller.

- `prefixd_speaker_capability{backend,capability}` exposes the selected speaker's
  runtime capabilities without probing on scrape. An unprobed lease is
  unconfirmed, distinct from current health or router installation.

- `prefixdctl speaker list-routes` and authenticated `GET /v1/speaker/routes`
  expose the selected speaker's complete local IPv4/IPv6 FlowSpec inventory,
  including match, action, rate and injection owner. Backend and observation
  scope distinguish rustbgpd retained intent from GoBGP accepted local RIB.
  Unsupported and failed observations return errors, never an empty inventory.
  These reads also work in dry-run and standby; they do not list blackholes or
  prove router enforcement.

- Manual FlowSpec discard and police rules accept a same-family `src_prefix`
  CIDR through the API and dashboard. Both speakers encode and read IPv4 and
  offset-zero IPv6 source prefixes; list/detail, CLI and rule previews show the
  source scope. `speaker.capabilities.flowspec_match` adds `source_prefix`.

### Changed

- `prefixd_blackhole_replaced_total{pop}` and the `PrefixdBlackholeReplaced`
  alert now count unleased blackhole reconciliation repairs that replaced a
  different local route at the prefix, as well as admissions. The repair also
  logs an error. Leased adds still do not increment the counter.

- Announcement counters, announcement latency histograms and BGP session gauges
  add a bounded `backend` label. The operations dashboard identifies backend and
  peer, preserves backend latency groups and shows capability availability.

- `guardrails.allow_src_prefix_match` now enables manual source-prefix matches
  instead of logging that it has no effect. It still defaults to false. Rules
  without a source prefix keep their existing identity and JSON storage. Before
  downgrading, drain source-prefix rules and their pending withdrawals as
  described in the upgrade guide. No database migration is required.

- A blackhole export read that rustbgpd aborts because the route, its
  Established peers or their export settings changed between pages now
  restarts once from the first page. A second abort is an observation error.

### Removed

- The HTTP load helper and its report-parser regression suite. Local verification
  and CI no longer require `hey`.

- The obsolete GoBGP-only lab helper and standalone FRR topology. Use
  `just interop-frr` for maintained rustbgpd and GoBGP router receipt tests with
  isolated fixtures and dated results. The Juniper topologies remain available.

### Fixed

- Operator configuration forms connect visible labels to their controls, keep
  quiet-hour selections named, and expose webhook field hints and validation
  errors to assistive technology.

- Unfocused text inputs, text areas, selects and checkboxes have a boundary of
  at least 3:1 against page, card, muted and dialog surfaces in light and dark
  themes. The "Using global events" hint is no longer dimmed. Per-destination
  event, match dimension and playbook step controls are named groups.
  Correlation and playbook validation errors are announced, and correlation
  errors describe the field they concern.

- Events, mitigations and audit log filters return to the first matching page.
  Refreshed events keep pagination within the available pages instead of falsely
  showing an empty list.

- The event detail panel is a modal dialog named "Event details". Opening it
  moves focus to its close button and keeps Tab inside the panel. Escape closes
  it and returns focus to the button that opened it. The panel closes when its
  event leaves the live list. Without a remaining opener, such as after a direct
  link, focus returns to the events list.

- Routine PostgreSQL NOTICE messages are quiet by default in native, Compose
  and systemd deployments. Warnings, errors and controller INFO remain enabled;
  custom logging filters retain their chosen levels and can restore notice
  diagnostics.

- GoBGP FlowSpec paths now carry their injection timestamp, so route age starts
  at announcement instead of Unix epoch.

- The separate fuzz lockfile now follows the current controller dependencies
  and includes compatible fixes for its outdated vulnerable dependencies.
  Local and CI advisory checks now audit both locked graphs.

- A successful complete peer observation retires deleted-peer metrics, including
  after an empty inventory, while keeping retained peers registered during
  scrapes. Failed or unsupported reads retain prior samples; malformed GoBGP
  peer rows fail the whole observation instead of appearing empty or inventing
  an Idle state.

- The operator menu now waits for authentication and health to resolve before
  showing controls, avoiding a flash of anonymous browser preferences for
  signed-in operators. Browser preferences remain available when health fails,
  and a retry keeps the signed-in dashboard and open preferences mounted.

### Documentation

- Historical benchmark claims state their missing qualification and distinguish
  HTTP request throughput from mitigation enforcement.

- The dry-run rollout cookbook and upgrade guide describe Compose recovery
  after enforced startup refuses remaining dry-run intent, keeping PostgreSQL
  and the original speaker running.

- ADR 029 accepts the provider-scoped upstream blackholing decisions, and
  ADR 030 with its speaker contract proposes guarded diversion to an external
  scrubber. Both are designs only; neither ships in this release.

## [0.22.1] - 2026-10-22

prefixd 0.22.1 makes `PrefixdBlackholeReplaced` clear an hour after the last
replacement instead of latching until prefixd restarts, and exports the
pre-registered metric series at zero from startup, as the metrics reference
already described. It adds no migration, keeps rustbgpd 0.79.0 and loads an
unchanged 0.22.0 configuration.

### Upgrade notes

- Follow
  [v0.22.0 → 0.22.1](https://github.com/lance0/prefixd/blob/v0.22.1/docs/how-to/upgrading.md#v0220--0221)
  in the upgrade guide: replace the controller and dashboard, then copy the
  new `grafana/prometheus-alerts.yml` to your Prometheus or recreate the
  Compose Prometheus. No migration or adoption step runs, the configuration is
  unchanged and rustbgpd stays at 0.79.0.

### Known limitations

- TTL expiry needs the running controller. Unleased FlowSpec rules and
  blackholes stay announced if prefixd stops while the speaker stays up; the
  leased modes, which bound that to one lease, are opt-in and rustbgpd-only.
- The replacement counter is local to the process. A restart resets it
  without firing or clearing a replacement still inside the alert's hour, and
  a replacement before Prometheus first scrapes the process is not alerted.
- The 0.22.0 known limitations otherwise still apply, except that
  `PrefixdBlackholeReplaced` no longer latches.

### Changed

- `PrefixdBlackholeReplaced` no longer latches until prefixd restarts. It fires
  on a replacement within the last hour and clears an hour after the last
  one. prefixd exports `prefixd_blackhole_replaced_total{pop}` for its
  configured POP at zero from startup, so the first replacement fires the
  alert. Copy the new `grafana/prometheus-alerts.yml` to your Prometheus.

### Fixed

- The controller now exports the pre-registered metric series, such as lease
  renewal and state, export disposition, unexported reason and reconciliation
  status, at zero from startup, as the metrics reference already described.
  Before, each series appeared only at its first event.

## [0.22.0] - 2026-10-22

prefixd 0.22.0 lets operators choose the dashboard's display timezone, counts
and alerts on unleased blackhole admissions that replaced an untracked local
route, and marks blackhole export evidence retained from before a lost
controller fence as historical so health, metrics and the interface no longer
present it as current. It adds no migration, keeps rustbgpd 0.79.0 and loads an
unchanged 0.21.0 configuration.

### Upgrade notes

- Follow
  [v0.21.0 → 0.22.0](https://github.com/lance0/prefixd/blob/v0.22.0/docs/how-to/upgrading.md#v0210--0220)
  in the upgrade guide: replace the controller and dashboard. No migration or
  adoption step runs, the configuration is unchanged and rustbgpd stays at
  0.79.0.
- Copy the new `grafana/prometheus-alerts.yml` to your Prometheus, or recreate
  the Compose Prometheus. It adds `PrefixdBlackholeReplaced` on the new
  `prefixd_blackhole_replaced_total{pop}` counter and rewords the
  `export_policy` text of `PrefixdBlackholeNotExported`.
- With rustbgpd, mitigation `export_evidence` and health detail's
  `speaker.blackhole_exports` add `historical`. After the controller loses and
  regains its fence, `GET /v1/health/detail` reports `degraded` until a fresh
  complete read replaces each retained blackhole's evidence. Automation that
  treats `degraded` as a database or speaker fault should read
  `speaker.blackhole_exports.historical`. `/v1/ready` is unchanged.

### Known limitations

- TTL expiry needs the running controller. Unleased FlowSpec rules and
  blackholes stay announced if prefixd stops while the speaker stays up; the
  leased modes, which bound that to one lease, are opt-in and rustbgpd-only.
- `PrefixdBlackholeReplaced` latches: the counter is local to the process, so
  the alert keeps firing until prefixd restarts or the alert is silenced. It
  records a past replacement, not an active conflict.
- The 0.21.0 known limitations otherwise still apply.

### Added

- Choose a dashboard display timezone in Preferences. The browser-local choice
  updates absolute times, charts and tooltips; UTC remains the default, and API
  timestamps, exports, TTLs and notification quiet hours stay unchanged.
- Count unleased blackhole admissions that replace an untracked local route
  with `prefixd_blackhole_replaced_total{pop}` and alert with
  `PrefixdBlackholeReplaced`. The alert latches historical replacement
  evidence until the process counter resets; admission and leased ownership
  behavior are unchanged.

### Changed

- Check the Prometheus alert rules and run their promtool unit tests with
  pinned Prometheus v3.15.0 in `just alerts`, `just gate` and a CI job. Nightly
  and main-push Interop runs no longer cancel each other; a newer PR commit
  still cancels its superseded Interop run.
- Run the FRR blackhole scenario with rustbgpd and amplification scenarios with
  both speakers in Interop CI alongside FlowSpec, retaining separate receipts
  for each speaker, scenario and workflow attempt, including failed runs.

### Fixed

- Retained blackhole export evidence is explicitly historical after controller
  ownership is lost, including after ownership returns until a fresh complete
  read. Mitigation `export_evidence` and `speaker.blackhole_exports` report it
  with `historical: true`, and health detail is `degraded` while it remains
  after ownership returns. Detail preserves historical peer rows and their
  timestamp on a failed refresh; health and the interface no longer present
  them as current export. An observation that spans an ownership loss is
  discarded.
- Historical blackhole export evidence no longer feeds
  `prefixd_blackhole_export_peers` or `prefixd_blackhole_unexported`, so a
  failed refresh after ownership returns cannot report the previous owner's
  committed peers or keep `PrefixdBlackholeNotExported` firing; it counts as a
  read error until a fresh complete read.
- Rotate blackhole export reads between reconciliation passes so the shared
  observation budget does not repeatedly leave the same mitigations unread.
  Each pass resumes at the first read the budget cut off, so every blackhole
  is read within as many passes as it takes the budget to cover the set.
- Blackhole export-policy warnings now direct operators to the speaker's export
  policy without guessing that RPKI validation caused the denial.

## [0.21.0] - 2026-10-21

prefixd 0.21.0 adds blackhole host routes on rustbgpd, created by Admins or by
allowlisted detectors, with frozen routes, separate quotas, safelist rechecks,
per-peer export evidence and optional injection leases that let rustbgpd
remove prefixd's routes when the controller stops. It adds amplification-aware
FlowSpec matches on source ports, non-first fragments and packet length,
driven by a new `udp_amplification` vector and detector source-port reports.
A PostgreSQL advisory lock keeps a second controller for the same POP in
standby, and the new `GET /v1/ready` tells load balancers which controller
holds it. rustbgpd 0.79.0 is now required: upgrade it before prefixd.
Startup now refuses the configuration keys removed in 0.20.0, and requires
`bgp.backend` whenever `bgp.gobgp_grpc` is set.

### Upgrade notes

- Follow
  [v0.20.0 → 0.21.0](https://github.com/lance0/prefixd/blob/v0.21.0/docs/how-to/upgrading.md#v0200--0210)
  in the upgrade guide: upgrade rustbgpd first, then replace the controller.
  Migrations 016–018 apply on first start, and no adoption step is needed.
  Leased modes stay off until you set them.
- `prefixd.yaml` now fails to load if it contains a key removed in 0.20.0, or
  sets `bgp.gobgp_grpc` without `bgp.backend` (or `bgp.mode`). 0.20.0 ignored
  both with a warning. Before upgrading, delete the removed keys and add
  `bgp.backend: gobgp` where needed; see
  [removed keys](https://github.com/lance0/prefixd/blob/v0.21.0/docs/reference/configuration.md#removed-keys).
- rustbgpd 0.79.0 is now the minimum speaker version. Upgrade rustbgpd to
  0.79.0 before upgrading prefixd: with the rustbgpd backend, startup reads
  the daemon version and refuses an older or unreadable one ("upgrade the
  speaker first"). CI and `just speakers` test only 0.79.0. GoBGP is
  unchanged. See
  [rustbgpd minimum version](https://github.com/lance0/prefixd/blob/v0.21.0/docs/how-to/upgrading.md#rustbgpd-minimum-version).
- With rustbgpd, `GET /v1/health/detail` now also reports `degraded` while an
  active blackhole is committed to no Established peer, including when the
  speaker has no Established peer at all. Automation that treats `degraded`
  as a database or speaker fault should read `speaker.blackhole_exports`.
  `/v1/ready` and the fence are unchanged. A failed export read keeps the
  last complete read's result, so it neither raises nor clears `degraded`.
- `blackhole.leased: true` is now accepted with rustbgpd 0.79.0 or later.
  New enforced blackholes are then added under the controller's owner-scoped
  injection lease, and rustbgpd removes them within `blackhole.lease_seconds`
  if prefixd stops. Blackholes added before the change stay unleased until
  they are withdrawn or expire. Once leased blackholes exist, startup refuses
  `blackhole.leased: false` until they are withdrawn or expire. The vendored
  rustbgpd proto is now the 0.79.0 release.
- The default and shipped `quotas.max_active_per_customer` rise from 5 to 20;
  explicit configured limits are preserved. Active customer/POP/global quotas
  now count only FlowSpec rules. Blackholes use their independent POP/global
  caps, while `max_new_per_minute` remains shared by both route kinds.
- Multi-rule event results now follow admission priority: the chunk containing
  the detector's highest-ranked source port, fragment coverage, remaining
  chunks by rank, then other static rules in their relative playbook order.
  Chunk contents and rule identities are unchanged. Event outcomes include
  canonical scopes and quota names for refusals, backed by `reject_rule`
  audits and `prefixd_event_rule_quota_rejections_total` metrics.
- A second controller for the same POP and speaker target that shares the
  database now starts in standby instead of mutating the speaker. The
  database connection must be direct or through a session-mode pooler:
  PgBouncer transaction pooling breaks the session advisory lock. Point load
  balancers and detector routing at `GET /v1/ready`, not `GET /v1/health`.
  `--adopt-legacy-speaker` and `--retire-dry-run-intent` now refuse while a
  controller for the POP holds the fence; stop it first. See
  [controller fence and rolling deploys](https://github.com/lance0/prefixd/blob/v0.21.0/docs/how-to/upgrading.md#controller-fence-and-rolling-deploys).
- With the rustbgpd backend, a `guardrails.max_ports` above 8, the encoder's
  per-list limit, now fails configuration load at startup and names both
  values. Before, rules over 8 ports were saved and then refused at
  announcement. Lower `max_ports` to 8 or less before upgrading. Shipped
  configurations use 5, and GoBGP is unaffected.
- The `guardrails.max_ports` default drops from 8 to 5, and the shipped
  configurations now set 5. FRR 10.7.1 accepts at most five values in one
  FlowSpec component and resets the whole session on a rule with more,
  dropping every route on it; see the
  [FRR amplification receipt](https://github.com/lance0/prefixd/blob/v0.21.0/docs/reference/qualification/amplification-frr-2026-10-19.md).
  Where `max_ports` is unset, manual and API requests with six to eight ports
  in one list now return `422`, and a detector's `from_event` source ports
  split into rules of at most five: a 20-port amplification report becomes
  four source-port rules instead of three, each counting toward quotas. A
  configuration that sets `max_ports: 8`, as earlier shipped files did, keeps
  it. Raise it only for routers known to accept longer lists. Existing rules
  are unaffected: the cap applies only to new admissions, so stored rules with
  six to eight ports stay announced, are repaired after a speaker restart,
  expire and are withdrawn as before. A detector re-report after the upgrade
  splits at five, so it creates new rules instead of extending the stored
  ones, which leave at their TTL.
- Migration 016 adds `withdrawal_requests.rule_kind`, `flowspec` or
  `blackhole`. Existing requests become `flowspec`, which every earlier
  request was; replay rewrites no mitigation row.
- Migration 017 adds the nullable `events.top_src_ports_json` column. Replay
  leaves every existing event's value `NULL` and rewrites no other row.
- Migration 018 replaces the `events` constraint
  `UNIQUE(source, external_event_id)` with a unique index over ban events
  only, so an unban can share its ban's external ID. Existing rows already
  satisfy the index, and replay rewrites no row. Earlier releases run with the
  index and do not restore the constraint.
- Earlier releases refuse a playbooks.yaml with a `udp_amplification`
  playbook or a multi-rule step, by design: a release that ignored the step
  would widen the rule. Before downgrading, remove such playbooks and withdraw
  every `udp_amplification` mitigation; earlier releases also refuse rows with
  that vector. The shipped `configs/playbooks.yaml` carries the new playbooks
  as commented examples only.
- Before downgrading to 0.20.0 or earlier, withdraw every rule with a
  source-port, fragment or packet-length match and drain its withdrawals.
  Those releases ignore the new keys and would withdraw with the wider rule,
  orphaning the real one on the speaker. See
  [amplification matches and downgrade](https://github.com/lance0/prefixd/blob/v0.21.0/docs/how-to/upgrading.md#amplification-matches-and-downgrade).
- Before downgrading to 0.20.0 or earlier, also withdraw every blackhole and
  every leased FlowSpec rule and drain their withdrawals. Those releases
  understand neither blackhole rows nor injection owners. See
  [downgrading to 0.20.0](https://github.com/lance0/prefixd/blob/v0.21.0/docs/how-to/upgrading.md#downgrading-to-0200).
- Before enabling blackholes, check the receiving routers' import policy. A
  `/32` or `/128` blackhole is RPKI-Invalid wherever it is validated with an
  origin AS, so a policy that drops RPKI-Invalid before it matches BLACKHOLE
  drops every blackhole silently. See
  [RPKI filters](https://github.com/lance0/prefixd/blob/v0.21.0/docs/reference/configuration.md#blackhole).
- A `PUT /v1/config/playbooks` body that does not decode now returns `400`
  with `{"errors": [reason]}` instead of an empty body.

### Known limitations

- A `201` means prefixd saved intent and the speaker accepted the local
  request. Blackhole export evidence `committed` means the peer's
  Adj-RIB-Out, not router receipt or enforcement, and FlowSpec rules have no
  export evidence. Router enforcement of a blackhole depends on the router's
  RTBH policy, which prefixd does not verify.
- TTL expiry needs the running controller. Unleased FlowSpec rules and
  blackholes stay announced if prefixd stops while the speaker stays up. The
  leased modes, which bound that to one lease, are opt-in and rustbgpd-only.
- Blackholes and injection leases need rustbgpd; GoBGP reports both as
  unsupported.
- The controller fence sees only controllers that share one database and
  needs a direct or session-mode connection. It does not stop other tools
  writing to the speaker.
- FRR 10.7.1 received the amplification rules but installed none of them as
  a filter, and accepts at most five values per FlowSpec component. Vendor
  forwarding qualification remains open.
- `guardrails.allow_src_prefix_match` and `guardrails.allow_tcp_flags_match`
  are reserved and have no effect.
- Unsupported unrelated local rules on a GoBGP speaker fail the complete
  observation and block reconciliation until an operator removes them. GoBGP
  process metadata is unsupported in health detail.
- Release binaries are Linux amd64 only.

### Security

- **rustls-webpki** — Updated 0.103.15 → 0.103.16, which rejects certificate
  paths through distrusted emSign intermediates (RUSTSEC-2026-0382).
- **webpki-roots**, **webpki-root-certs** — Updated 1.0.5 → 1.0.10, which drop
  the `emSign ECC Root CA - G3` root (RUSTSEC-2026-0381, RUSTSEC-2026-0383).

### Added

- Blackhole export evidence (rustbgpd): once per reconciliation pass, prefixd
  reads `ListPathExportDispositions` for each active enforced blackhole, to
  the last page, and joins it with `ListNeighbors`. Mitigation detail adds
  `export_evidence` (each Established peer's `committed`, `withheld` or
  `pending` disposition with `reason` and `explain_code`, plus configured
  peers that are not Established), and the dashboard shows it first on a
  blackhole's page. Health detail adds `speaker.capabilities.blackhole_export`
  and `speaker.blackhole_exports`, and reports `degraded` while an active
  blackhole is committed to no Established peer. Metrics add
  `prefixd_blackhole_export_peers{disposition}`,
  `prefixd_blackhole_unexported{reason}` and
  `prefixd_blackhole_export_read_errors`, and the shipped alerts add
  `PrefixdBlackholeNotExported`. A speaker export policy that denies the
  route shows as reason `export_policy`. `committed` means the peer's
  Adj-RIB-Out, not router receipt or enforcement. A failed or partial read is
  reported as unknown export, never as no peers. The reads mutate nothing,
  and FlowSpec rules have no export evidence. See
  [export evidence](https://github.com/lance0/prefixd/blob/v0.21.0/docs/reference/speaker-backends.md#export-evidence).
- Leased FlowSpec (ADR 027 amendment): with `bgp.rustbgpd.leased_flowspec`
  (off by default, rustbgpd 0.79.0 or later), new enforced FlowSpec rules use
  `AddLeasedFlowSpec` under the same injection owner, lease and renewal as
  leased blackholes, so rustbgpd removes them within one lease if prefixd
  stops. The owner is recorded per rule, deletes pass it, read-back matches
  it, and a failed leased add never falls back to `AddFlowSpec`. Existing
  unleased rules stay unleased. Startup refuses the setting without the
  speaker's lease, refuses turning it off while leased rules are outstanding,
  and refuses owned rules the database cannot explain. Unleased rules are
  stored and sent exactly as before. When the speaker refuses a new rule
  because another owner, or none, holds its match, the rule gets `409` and
  its row is withdrawn locally with the audit reason `untracked local route
  at admission`, as for blackholes; nothing is deleted.
- Leased blackholes (ADR 027): with `blackhole.leased`, enforced manual and
  detector blackholes use `AddLeasedPath` under the controller's injection
  owner and never fall back to `AddPath`. A renewal task sends `RenewLease`
  about every `lease_seconds / 3`. A refused renewal, a changed lease
  generation or an expired row triggers an immediate full leased re-add, and a
  restarted prefixd adopts the live lease through `ListInjectionLeases`.
  Deletes pass the recorded owner. A route held by another owner, or by none,
  returns `409` and the new row is withdrawn locally with the audit reason
  `untracked local route at admission`. Health detail adds `speaker.lease`,
  and metrics add `prefixd_injection_lease_renewals_total{result}` and
  `prefixd_injection_lease_state{state}`. Startup refuses routes under this
  controller's owner that the database neither desires nor is withdrawing.
  Renewal needs neither the database nor the controller fence, so a
  PostgreSQL outage does not drop leased blackholes; a dry-run controller
  never renews, so its health reports `not_renewing` and leased routes from
  an enforced run lapse within one lease. A refused withdrawal of a key
  another owner holds stays pending until an operator resolves it.
- `POST /v1/mitigations` accepts optional `src_ports`, `fragment` and
  `packet_length` for discard and police rules (ADR 028). They pass the same
  invariants, `max_ports`, `allow_fragment_match` and
  `allow_packet_length_match` guardrails and speaker capability check as
  playbook rules. Refusals return `422` with the reason, or `400` when the
  speaker cannot encode a component. Every mitigation response and WebSocket
  message now includes `src_ports` (`[]` when absent), `fragment` and
  `packet_length` (`null` when absent), in canonical form.
- The dashboard shows source ports, non-first fragments and packet length in
  the mitigation list, detail page and FlowSpec rule preview, lists the other
  rules one event produced, and shows an event's top source ports. A new Rule
  form creates a manual FlowSpec rule with these fields; its checks mirror the
  controller's and name the guardrail.
- The playbook editors support `udp_amplification` playbooks, `rules` steps
  and `blackhole` steps. The YAML view round-trips every field, including keys
  it does not know. The form shows `rules` read-only and keeps them unchanged.
  Both views show the controller's validation errors verbatim.
- `prefixdctl mitigations list` adds a `MATCH` column and `get` adds a
  `Match:` line with the protocol, source and destination ports, fragment and
  packet length. JSON output adds `protocol`, `dst_ports`, `src_ports`,
  `fragment` and `packet_length`.

- The rustbgpd adapter can inject, delete and read back unicast blackhole
  host routes (ADR 027), and health detail reports
  `speaker.capabilities.blackhole` and `blackhole_lease`. GoBGP reports the
  capability as unsupported. `blackhole_lease` is true only for rustbgpd 0.79.0
  or later with a leased mode configured, since prefixd probes the lease only
  then.
- An optional `blackhole` block in `prefixd.yaml` configures RTBH host routes
  (ADR 027): `enabled` (default `false`), `next_hop_ipv4`, `next_hop_ipv6`,
  `communities`, `large_communities`, `max_ttl_seconds` (default 3600),
  `max_active_per_pop` (default 10) and `max_active_global` (default 50).
  Every key is validated at load. Wrong-family or non-unicast next hops,
  malformed communities, `NO_EXPORT`, `NO_EXPORT_SUBCONFED`, `NO_ADVERTISE`
  and unknown keys are refused. Startup refuses `enabled: true` when the speaker backend lacks the
  blackhole capability (GoBGP) or the safelist is empty, in dry-run and
  enforced modes. Omitting the block keeps every existing configuration valid. Older binaries
  ignore the block.
- The rustbgpd and GoBGP adapters encode and strictly read back UDP source
  port, non-first fragment and packet-length FlowSpec matches in both
  families (ADR 028). Health detail reports
  `speaker.capabilities.flowspec_match` with `source_ports`, `fragment` and
  `packet_length`; all three are true for rustbgpd, GoBGP and the mock. The controller refuses a rule with a component the selected
  speaker cannot encode before persisting it or sending any RPC, in dry-run
  too.
- Blackhole lifecycle and reconciliation (ADR 027), used by the manual
  creation path below. Enforced admission freezes the
  next hop and communities into the row, returns `409` for a live owner, a
  pending withdrawal or an untracked local route at the prefix, persists, then
  adds the route. The safelist is rechecked before every add: a failed lookup
  sends nothing, and a victim safelisted since admission is withdrawn with the
  reason `safelisted after admission` and counted in
  `prefixd_mitigations_withdrawn_total{reason="safelisted"}`. Withdrawal,
  TTL expiry and repair use the frozen route; withdrawal intent records
  `rule_kind` `blackhole`. Reconciliation repairs missing blackholes in a
  stage separate from FlowSpec and reports, without touching, local routes it
  does not own in the new `prefixd_unknown_local_routes{kind}` gauge
  (`blackhole` and `flowspec`). Blackhole and FlowSpec pending withdrawals
  and read failures do not block each other.
- Admins can create manual blackholes (ADR 027) with `POST /v1/mitigations`
  and `"action": "blackhole"`, or from the dashboard's Blackhole dialog. The
  request needs the Admin role (Operator and Viewer sessions and every bearer
  token get `403`), a nonempty `reason`, and `confirm_victim_ip` exactly equal
  to `victim_ip` (`400` otherwise, with no row or audit entry). It takes no
  protocol, ports, rate or `expires_at_cap`. Manual blackholes are
  rustbgpd-only and, unless `blackhole.leased` is set, unleased: one stays on
  the speaker if prefixd stops. Router
  enforcement depends on the router's RTBH policy, which prefixd does not
  verify; FRR 10.7.1 is qualified below. Mitigation responses and WebSocket
  messages gain an optional `blackhole` object (`next_hop`, `communities`,
  `large_communities`), present only for blackholes. A manual blackhole
  broadcasts `mitigation_created`. The dashboard shows blackholes with a danger
  badge and their saved route, and asks Admins to type the victim IP twice.
  `prefixdctl mitigations list/get/withdraw` show and withdraw blackholes by
  ID; the CLI cannot create one. `action_type`-labelled metrics report
  `blackhole`, and refused manual blackholes add
  `prefixd_guardrail_rejections_total` reasons `BlackholeDisabled`,
  `BlackholeQuotaExceeded`, `BlackholeNotOwned`, `BlackholeSafelisted` and
  `InvalidBlackhole`.
- `just interop-frr-blackhole` qualifies manual blackholes at FRR 10.7.1
  through rustbgpd 0.78.0 over IPv4 and IPv6 unicast, with an import
  route-map that rewrites BLACKHOLE routes to a static discard next hop. The
  [dated receipt](https://github.com/lance0/prefixd/blob/v0.21.0/docs/reference/qualification/blackhole-frr-2026-10-19.md)
  shows receipt with the expected communities, discard installation in zebra
  and the container kernel, removal on withdrawal and TTL expiry, and return
  through prefixd repair after a speaker restart. It also records that a
  blackhole persists past its TTL while prefixd is stopped. The interop lab's
  rustbgpd peer now also negotiates unicast and sets `local_ipv6_nexthop`,
  which rustbgpd needs to send IPv6 routes over IPv4 transport.
- `just interop-frr-amplification` qualifies amplification rules at FRR
  10.7.1 through rustbgpd 0.78.0 and GoBGP 4.10.0, over IPv4 and IPv6
  FlowSpec. The
  [dated receipt](https://github.com/lance0/prefixd/blob/v0.21.0/docs/reference/qualification/amplification-frr-2026-10-19.md)
  shows FRR receiving source-port discard rules, with and without a
  packet-length range, and the IsF fragment police rule with exactly the
  expected components, then removal on detector unban and TTL expiry and
  return through prefixd repair after a speaker restart. FRR installed none of
  them as a filter. It also records that FRR accepts at most five values per
  component and resets the session on a rule with more, which the earlier
  default `guardrails.max_ports: 8` allowed. The default is now 5; see the
  upgrade notes.

- Fence duplicate controllers with a PostgreSQL session advisory lock (ADR
  027). Each controller derives an owner from its POP and registered speaker
  target and takes the lock on a dedicated connection before connecting to the
  speaker. Without it the controller stays in standby: no scheduler, expiry,
  reconciliation, announcement or withdrawal; `POST`, `PUT` and `DELETE`
  requests on authenticated API routes return `503`; `GET /v1/health` stays
  `ok`; `GET /v1/health/detail` reports `"status": "standby"`; and the new
  `prefixd_controller_fence_active` gauge is `0`. Standby retries every 5
  seconds. The holder checks its fence session every 2 seconds and, on a
  failed check, stops starting speaker mutations at once, enters standby and
  reacquires on a new connection. Rolling deploys wait in standby and take over
  when the old process exits.

- Add public `GET /v1/ready`: `200` with `{"status":"ready"}` while the
  controller holds its fence, otherwise `503` with `{"status":"standby"}`,
  or `{"status":"draining"}` from the moment a shutdown signal arrives. The
  fence stays held through the drain. Set the load balancer's readiness
  interval shorter than `shutdown.drain_timeout_seconds`.

- Fence the `--adopt-legacy-speaker` and `--retire-dry-run-intent` one-shot
  modes: each takes the controller's fence once, refuses while another process
  holds it, and releases it on exit.

- Detectors can trigger blackholes (ADR 027). A playbook step with
  `action: blackhole` (`ttl_seconds`, no `rate_bps`) creates or extends a
  blackhole through the manual path's admission, for events whose `source` is
  listed in the new `blackhole.detector_sources` (default `[]`). Other sources
  get `422` and count under `prefixd_guardrail_rejections_total` reason
  `BlackholeSourceNotAllowed`. A blackhole step carries no `rules`, a rule
  cannot use `action: blackhole`, and a blackhole step in a
  `udp_amplification` playbook is refused. A repeated ban extends the blackhole to at most
  `blackhole.max_ttl_seconds` from now, and the FastNetMon unban withdraws it.
  Startup, playbook reload and `PUT /v1/config/playbooks` refuse a blackhole
  step when `blackhole.enabled` is false or the step TTL exceeds the cap, and
  in enforced mode unless the speaker provides the rustbgpd injection lease or
  `detector_sources` is nonempty. Dry-run is not gated. Without the lease
  (`blackhole.leased`, below), enforced detector blackholes run unleased:
  startup logs a warning, health detail reports the new
  `speaker.detector_unleased` and the new `prefixd_blackhole_detector_unleased`
  gauge is `1`. If prefixd stays down while rustbgpd keeps running, these
  blackholes stay announced until prefixd returns or an operator withdraws
  them.
- `blackhole.leased` (default `false`) and `blackhole.lease_seconds`
  (default `60`, `5..=3600`) configure the injection lease described above.
  Startup refuses `leased: true` while the speaker lacks the lease, and a
  route recorded under a lease owner is never added through the unleased
  `AddPath`.
- Blackhole reconciliation, at startup and on every pass, deletes a local
  route that exactly matches the frozen route of a terminal, enforced-origin
  blackhole of this POP with no live row or pending withdrawal, and audits it
  with the reason `orphaned after controller downtime`. Every other unknown
  route is still only reported. Overdue blackholes keep expiring through the
  normal withdrawal path.
- `grafana/prometheus-alerts.yml`, loaded by the Compose Prometheus, adds
  `PrefixdDown`, `PrefixdNotReady` and `PrefixdBlackholesWhileDegraded`, with
  promtool unit tests in `grafana/prometheus-alerts.test.yml`.
  `PrefixdBlackholesWhileDegraded` carries the recovery steps: restart
  prefixd, or withdraw on the speaker and then in prefixd.

- `scripts/prefixd-fastnetmon.sh` retries a ban `POST /v1/events` with the same
  event ID on a connection error or `503`, up to `BAN_POST_ATTEMPTS` (default 3)
  attempts `BAN_POST_DELAY_SECONDS` (default 1) apart. It never retries a `4xx`.

- The `udp_amplification` vector, the `top_src_ports` event field and
  multi-rule playbook steps (ADR 028). `POST /v1/events` accepts
  `top_src_ports` (at most 64, otherwise `400`), stored as `top_src_ports_json`.
  In a `udp_amplification` playbook a step may carry `rules`, each with its own
  `match` (`src_ports`, `fragment`, `packet_length`) and action; every rule
  becomes its own mitigation for UDP to the victim, admitted on its own.
  `src_ports: from_event` matches the event's ports that are in the new
  `amplification.reflector_ports` library (20 cited ports by default,
  including 53, whose collateral the configuration reference documents),
  sorted and split into rules of at most `guardrails.max_ports` ports, so a
  repeated port set extends the same rules. With no library port, or no
  `udp_amplification` playbook, the event is handled exactly as `udp_flood`.
  Startup, reload and playbook edits refuse rules that need
  `allow_fragment_match` or `allow_packet_length_match` while it is false,
  static source-port lists over `max_ports`, and components the speaker cannot
  encode, in both modes. The `amplification` section (also
  `min_src_port_share`, default 0.2) is exposed by `GET /v1/config/settings`.
- Detector adapters report UDP reflection (ADR 028). `POST
  /v1/signals/fastnetmon` reads the optional `packet_dump_detailed` sample:
  for a UDP-dominant attack, reflector-library ports whose share of sampled UDP
  packets meets `amplification.min_src_port_share` make the event
  `udp_amplification` with those ports in `top_src_ports`.
  `scripts/prefixd-fastnetmon.sh` does the same from the Community
  `Attack traffic dump` lines, with the new `PREFIXD_SRC_PORT_MIN_SHARE`
  (default 0.2) and at most 64 ports; prefixd intersects them with the
  library. Alertmanager reads an optional `top_src_ports` annotation of
  comma-separated ports, and a malformed one fails that alert. Generic
  webhook adapters gain `fields.top_src_ports`, where a value that is not an
  array of ports fails that event. Annotations and fields are read on bans
  only. Without a sample, a qualifying port or a UDP-dominant attack, events
  are classified as before, and TCP and ICMP attacks are never
  `udp_amplification`. The generic webhook guide's example no longer maps to
  the nonexistent vectors `dns_amp` and `ntp_amp`.
- Event responses add `mitigation_ids`, every mitigation the request created,
  extended or withdrew, and `rules`, each evaluated rule's outcome (`created`,
  `extended` or `rejected` with a `reason`). `mitigation_id` stays the first of
  them. A ban returns `202` when any rule was created or extended, otherwise
  the first rule's error as before. Batch results add `mitigation_ids` when
  nonempty.

### Changed

- Reject the configuration keys removed in 0.20.0 (`escalation`,
  `http.auth.ldap`, `http.auth.radius`, `timers.correlation_window_seconds`,
  `observability.audit_log_path`, `observability.metrics_listen` and
  `shutdown.preserve_announcements`) instead of ignoring them with a warning.
  Startup and reload fail with an error that names each key present, for
  example ``remove `escalation`: configuration keys removed in 0.20.0 are no
  longer accepted``, without its value. Startup log lines with
  `rejected_in: "0.21.0"` no longer appear. Rust library users:
  `Settings::load_with_deprecations`, `ConfigDeprecation`,
  `DEPRECATED_CONFIG_REJECTED_IN` and `AppConfig::deprecations` are removed;
  use `Settings::load`.

- Require `bgp.backend` whenever `bgp.gobgp_grpc` is set. A configuration with
  `bgp.gobgp_grpc` and neither `bgp.backend` nor `bgp.mode` now fails to load
  with `bgp.backend is required when bgp.gobgp_grpc is set; add bgp.backend:
  gobgp to keep the GoBGP speaker`, instead of resolving to GoBGP with a
  warning. An empty or absent `bgp.gobgp_grpc` still resolves to rustbgpd.

- Qualify rustbgpd 0.79.0: Compose and the interop lab pin it, and it is now
  the minimum and the only version CI tests. Every controller field prefixd
  reads or writes is unchanged in 0.79.0.

- rustbgpd 0.79.0 changes for operators: it validates an injected route
  against RPKI when it is added, but prefixd's blackholes carry no AS_PATH,
  so rustbgpd rates them NotFound and its own Invalid export filters pass
  them. A router that validates them rates them Invalid with the speaker's AS
  as origin; see the
  [RPKI blackhole receipt](https://github.com/lance0/prefixd/blob/v0.21.0/docs/reference/qualification/blackhole-rpki-frr-2026-10-20.md).
  Its Prometheus series rename the `afi_safi`
  and `scope` labels to `family` (plus `stage` on max-prefix series) with no
  overlap, so update your own rustbgpd dashboards and alerts with the
  upgrade. A rustbgpd config with an `[event_history]` section no longer
  loads.

- The rustbgpd controller stubs are now generated from the unmodified
  `rustbgpd.proto` asset of the rustbgpd v0.79.0 release, pinned by its
  published sha256, instead of an unversioned copy. `just proto`, part of
  `just gate` and CI lint, checks the file offline.

- Blackholes adopt rustbgpd 0.79.0's unicast injection contract. `DeletePath`
  sets `allow_missing`, so `NOT_PRESENT` completes a withdrawal that a retry,
  a controller restart or a speaker restart already overtook, with its
  original actor, reason and operation ID; `NOT_FOUND` from the speaker is now
  an error instead of absence. Each accepted `AddPath` or `AddLeasedPath`
  logs the speaker's outcome (`created`, `replaced`, `unchanged`, or `unknown`
  when none is reported) and, unless it is `unchanged`, writes an `announce`
  audit entry with it, so a leased re-add of routes the speaker still holds,
  as after a controller restart or on each retry of a partial re-add, adds no
  audit entries. A `replaced` outcome on an unleased admission is logged as an
  error. `0.0.0.0` and `::`, which rustbgpd now reads as next-hop self, stay
  refused as blackhole next hops.

- `POST /v1/safelist` now withdraws every live blackhole on this POP whose
  victim falls inside the new entry, under the lifecycle mutex, with the
  audited system reason `safelisted after admission`. Dry-run blackholes are
  retired locally without a speaker call, and foreign-POP rows are untouched.
  The `201` response gains a JSON body listing `withdrawn_mitigation_ids`,
  plus `withdrawal_error` when the covered blackholes could not be found or
  withdrawn; the entry is stored either way. Each reconciliation pass also
  withdraws present, owned, live blackholes that the safelist now covers, so
  entries seeded from configuration or written to the database converge. A
  failed safelist lookup withdraws nothing. FlowSpec rules are unchanged.

- A detector unban by `event_id` withdraws every live mitigation the original
  ban created, not one of them. Bans before multi-rule steps created one, so
  their unbans behave as before.

- Guardrails enforce the ADR 028 match settings before a rule is saved, in
  dry-run and enforced modes. `guardrails.allow_fragment_match` and
  `guardrails.allow_packet_length_match` now admit or refuse rules with a
  fragment or packet-length match, `max_ports` caps the source-port list as
  well as the destination-port list, and rules with these components must meet
  the ADR 028 rule invariants. Refusals return `422` with the new
  `prefixd_guardrail_rejections_total` reasons `FragmentMatchNotAllowed`,
  `PacketLengthMatchNotAllowed`, `InvalidMatch` and `TooManySourcePorts`.
  `guardrails.allow_src_prefix_match` and `guardrails.allow_tcp_flags_match`
  are reserved: setting either to `true` logs a startup warning and has no
  effect. Rules without these components and shipped configurations behave
  as before.

- Releases publish themselves. Once `ci.yml` passes on the `main` commit that
  sets a new Cargo.toml version with a dated CHANGELOG section, the release
  workflow tags that commit `vX.Y.Z` and publishes the GitHub Release, which
  is no longer a draft. The body is the CHANGELOG section, the artifacts and
  a compare link to the previous release. `just release-prepare X.Y.Z`
  prepares the release PR. A manually pushed tag still releases, and a
  dispatch is still a dry run.

### Fixed

- The dashboard labels an unavailable realtime feed as **Polling**, explains
  the same-origin WebSocket proxy requirement and the limits of HTTP fallback,
  and keeps the update mode visible on small screens. Next.js development,
  production and standalone servers retain polling without claiming that live
  event toasts work. Stalled handshakes time out, retries retire stale sockets,
  and paginated signal groups now refresh every five seconds like other live
  lists. The supplied nginx deployment continues to provide the live feed.
- `scripts/prefixd-fastnetmon.sh` now takes the vector from FastNetMon's own
  `Attack protocol:` line (the protocol with the most packets) before looking
  for tokens. `udp` gives `udp_flood`, then the amplification refinement;
  `icmp` gives `icmp_flood`; `tcp` keeps the SYN and ACK checks, and is
  `unknown` without either. Before, a nonzero SYN counter or a TCP ACK sample
  in the dump sent a UDP flood as `syn_flood` or `ack_flood`, so the
  mitigation was a TCP rule that missed the attack. Without a usable
  protocol line, the script infers the vector from tokens as before.
- A detector unban is now stored in event history as its own `unban` event,
  with the ban's source and external event ID. Before, every unban from any
  source logged `failed to insert unban event` and was dropped, although the
  withdrawal succeeded. A repeated identical ban is still rejected with
  `409 DuplicateEvent`.

### Documentation

- The FastNetMon guide drops `notify_script_pass_details`, which FastNetMon
  Community does not have: `notify_script_path` is its only notify-script
  setting, and the script must exist when FastNetMon starts.
- ADR 027 (blackhole mitigations and the controller fence) and ADR 028
  (amplification matches) record the design behind this release. ADR 029
  proposes provider-scoped upstream blackholing; nothing implements it yet.

## [0.20.0] - 2026-10-19

### Upgrade notes

- Upgrading from v0.19.1 is one maintenance step: back up PostgreSQL, keep
  `pop`, `mode` and the GoBGP endpoint unchanged, run
  `prefixd --adopt-legacy-speaker` once, then start normally. Migrations
  013–015 apply on first start. Follow
  [v0.19.1 → 0.20.0](https://github.com/lance0/prefixd/blob/v0.20.0/docs/how-to/upgrading.md#v0191--0200),
  which includes a route that keeps the v0.19.1 Compose layout and pins the
  0.20.0 images.
- An unchanged v0.19.1 `prefixd.yaml` loads and stays on GoBGP. Its removed
  keys are ignored with one warning each; 0.21.0 rejects them, so delete them
  during the upgrade. See Removed below.
- Switching a POP from `mode: dry-run` to `enforced` now needs
  `prefixd --retire-dry-run-intent` first while unexpired dry-run mitigations
  remain. Enforced startup refuses to run until they are retired.
- Review Breaking below before upgrading: API and detector clients see
  new `202`, `400`, `409` and `422` responses, saved pagination cursors stop
  working, and Compose commands need a speaker profile.
- Source builds need Rust 1.89 or later.

### Known limitations

- A `201` means prefixd saved intent and the speaker accepted the local
  request. It doesn't prove export or that a router installed the rule. GoBGP
  read-back is its accepted local RIB after import policy, not retained intent,
  and peer health alone doesn't prove a mitigation is installed.
- TTL expiry needs the running controller. If prefixd stops while the speaker
  stays up, rules stay announced.
- Run one controller per POP and speaker target. The lifecycle lock doesn't
  fence controllers in other processes.
- Unsupported unrelated local rules on a GoBGP speaker fail the complete
  observation and block reconciliation until an operator removes them.
- GoBGP process metadata is unsupported in health detail.
- Vendor forwarding qualification and a desired/acknowledged announcement
  ledger remain open; write-only speaker backends, ExaBGP, an HTTP shim, exec
  transport and runtime plugins aren't supported.
- Downgrading to v0.19.1 removes dry-run origin protection and ignores pending
  withdrawal cleanup. Retire dry-run intent and drain cleanup first.
- Release binaries are Linux amd64 only.

### Breaking

- Make rustbgpd the default speaker. `bgp.backend` selects `rustbgpd` or
  `gobgp`; `bgp.mode: sidecar` remains a GoBGP spelling. When `bgp.backend` is
  unset, a configuration with only `bgp.gobgp_grpc` resolves to GoBGP and
  warns, one with both `bgp.gobgp_grpc` and `bgp.rustbgpd` fails to load until
  `bgp.backend` is set, and one without `bgp.gobgp_grpc` resolves to rustbgpd.
  Shipped configurations set `bgp.backend` explicitly. 0.21.0 will require
  `bgp.backend` whenever `bgp.gobgp_grpc` is set.

- Bind each POP to an immutable, credential-free speaker target before
  connecting. Migration 014 adds the targets and retains target IDs on
  withdrawal requests; lifecycle guards reject missing or mismatched ownership,
  and startup rejects a target that differs from the bound one. A database with
  v0.19.1 speaker history needs the one-shot `prefixd --adopt-legacy-speaker`,
  which binds the configured target, audits the adoption and exits without
  connecting to the speaker. Credential rotation preserves the binding;
  changing speakers needs the drained target transfer in the upgrade guide.

- Refuse enforced startup while the POP has unexpired dry-run mitigations, and
  return `409` without storing the event when a detector event would extend
  one in enforced mode. Retire them with `prefixd --retire-dry-run-intent`.
  See Security below.

- Reject ban events from `mode: corroborating` sources on `/v1/events/batch`
  and the Alertmanager, FastNetMon and generic webhook adapters, as `/v1/events`
  already did. See Security below.

- Return accepted intent with a request-local
  `announcement_outcome: "unconfirmed"` and mitigation ID after speaker errors,
  including batch and signal wrappers. Manual creation uses HTTP `202` for this
  case; ordinary success and dry-run keep `201`. The dashboard warns that
  announcement is unconfirmed and opens the saved intent.

- Enforce the documented `quotas.max_new_per_minute` limit, which was parsed
  but never applied. Admission now rejects a new mitigation with `422` when the
  POP already has that many mitigations created in the trailing 60 seconds,
  checked in the same serialised transaction as the active quotas, so
  controllers sharing the database cannot both take the last slot. A rejected
  request saves nothing, announces nothing and uses no quota slot, and
  increments `prefixd_guardrail_rejections_total{reason="NewMitigationRateExceeded"}`.
  Dry-run creations count; TTL extensions by repeat events do not. `0` admits no
  new mitigations, as for the active quotas. The shipped configs set 30, so a
  burst above 30 new mitigations a minute at one POP is now rejected; raise the
  limit before upgrading if you rely on larger bursts.

- Reject duplicate map keys in YAML configuration, which the previous parser
  could silently replace with the later value. Unknown keys in `observability`
  and `shutdown` other than the removed keys listed below now fail loading.

- Return structured `400` errors instead of silently dropping or ignoring
  input: malformed or empty date filters on event, audit, mitigation and
  signal-group listings; invalid mitigation and signal-group status tokens;
  empty or NUL POP filters; and malformed, oversized, wrong-endpoint or
  superseded pagination cursors.

- Reject `http.auth.mode: mtls` at startup without native TLS and nonempty
  server certificate, key and client-CA paths. See Security below.

- Replace the Compose layout. `docker-compose.yml` now has `rustbgpd` and
  `gobgp` profiles in one controller image, named volumes seeded from image
  defaults, and prebuilt `main` images, in place of `build: .` and the
  `./configs` bind mount. Every Compose command selects a profile. The
  controller runs as UID 999, and Prometheus and Grafana publish on host
  loopback only.

- Require Rust 1.89 or later to build.

- Rust library users: `RustBgpdConfig` literals need the new optional identity
  fields or `..Default::default()`. Removed library items are listed under
  Removed.

### Removed

- Remove the ineffective configuration keys `escalation`, `http.auth.ldap`,
  `http.auth.radius`, `timers.correlation_window_seconds`,
  `observability.audit_log_path`, `observability.metrics_listen` and
  `shutdown.preserve_announcements`. 0.20.0 still loads them, ignores them and
  logs one warning per key with `rejected_in: "0.21.0"`; 0.21.0 rejects them.
  Settings JSON drops `escalation`, `timers.correlation_window_seconds` and
  `shutdown.preserve_announcements`, and the shutdown log drops its
  preserve-announcements attribute. Playbooks select their first step,
  credentials authentication uses PostgreSQL operators, the correlation engine
  uses `correlation.window_seconds`, metrics stay on the private API listener
  and shutdown still leaves speaker rules in place.

- Remove timestamp-only pagination cursors. Mitigation listings use versioned
  opaque cursors ordered by creation time and mitigation ID; event, audit and
  signal-group listings use endpoint-specific `e1`, `a1` and `s1` cursors with
  timestamp/UUID continuation, so timestamp ties no longer omit rows. Cursors
  saved from v0.19.1 return `400`; restart from the first page. Filters and
  response fields are unchanged. Undecodable stored rows fail the whole page,
  including lookahead, rather than silently truncating results or
  manufacturing audit actors or group dimensions; signal-group detail,
  open/expired reads and existing-group insert results use the same fallible
  conversion.

- Hide the escalated mitigation state and the `mitigation.escalated` alert
  event; no code path produces either. The dashboard drops the Escalated status
  filter, command-palette shortcut and alert/notification options, and the
  references stop listing them. Stored `escalated` rows, the `status=escalated`
  API filter and saved alert filters or notification mutes that name
  `mitigation.escalated` still parse. Dashboard toasts for TTL extensions
  (`mitigation_updated`) now follow the `mitigation.created` mute instead of the
  hidden escalated one.

- Retire dashboard mock mode, unused legacy toast and CSS files, unused UI
  scaffolding with its 23 exclusive direct dependencies, the stale npm lock and
  the obsolete `next lint` command. Real API behavior and Sonner notifications
  are unchanged.

- Remove from the Rust library: `RepositoryTrait::find_active_by_victim` and
  its PostgreSQL and mock implementations; `Settings.escalation`,
  `AuthConfig.ldap` and `AuthConfig.radius`; the types `EscalationConfig`,
  `EscalationEvaluator`, `EscalationDecision`, `LdapConfig` and `RadiusConfig`;
  `Playbooks::get_escalation_step`; and the unused policy correlation
  prototype. Historical escalated state and the playbook step schema are
  retained.

### Security

- Keep dry-run mitigations local after a switch to `mode: enforced`. Before
  this fix, the first enforced reconciliation after a restart announced every
  unexpired dry-run mitigation. Migration 015 records each mitigation's
  admitting mode. Reconciliation never announces a dry-run mitigation, and its
  withdrawal or TTL expiry never deletes speaker state. In enforced mode, a
  detector event no longer extends one; it returns `409` without storing the
  event. Enforced startup now refuses to run while the POP has unexpired dry-run
  mitigations. The new one-shot `prefixd --retire-dry-run-intent` withdraws
  them locally, writes an audit entry for each and exits without contacting the
  speaker. On first start, live rows from before the migration take the
  configured mode, with one system audit entry, so upgrade without changing
  `mode`. Downgrading removes this protection; retire dry-run intent first.

- Reject ban events from `mode: corroborating` sources on `/v1/events/batch`
  and the Alertmanager, FastNetMon and generic webhook adapters, as single
  `/v1/events` already did, so such a source can no longer create a mitigation
  alone. Batch rejects only the offending item; adapter unban and resolved
  alerts still reach withdrawal.

- Reject `http.auth.mode: mtls` without native TLS and nonempty server
  certificate, key and client-CA paths before database, speaker or listener
  startup. Programmatic application-state construction enforces the same
  validation. Configure all three TLS paths, or use bearer/credentials
  authentication when a proxy forwards plaintext to prefixd; forwarded identity
  headers do not authenticate mTLS clients.

- Reject local and documentation IPv6 literals in alert destination URL edits,
  including IPv4-mapped forms of blocked IPv4 addresses, and reject absolute
  `localhost.` names and their subdomains. Rejected saves preserve
  the running configuration and saved secrets; DNS and redirect targets are not
  checked by this literal-address validation.

- Return controlled database decode errors for PostgreSQL timestamps outside
  Chrono's supported finite range, including infinity, instead of unwinding
  application-owned reads. Preserve ordinary timestamp precision and nullability.

- Reject non-finite or out-of-range signal confidence before primary event or
  corroborator ingestion changes state. Preserve optional confidence, inclusive
  zero/one boundaries and corrected retries with the same external event ID.

- Preserve exact policing rates through both speaker encoders, including 1–7 bps
  instead of turning them into discard. Reject missing, zero or inexact police
  rates and rates on discard before saving or extending intent, and when loading
  or editing playbooks. Keep historical malformed actions withdrawable by their
  exact local match.

- Hide interactive operator-password entry in `prefixdctl` and restore terminal
  echo after input. Fail explicitly when a controlling terminal is unavailable.

- Check backend dependency licenses, sources and advisories with cargo-deny in
  the existing security job. Reject unapproved licenses, sources and wildcard
  requirements while retaining duplicate warnings and the separate full-lock
  audit's explicit RSA exception.

- Refresh the audit baseline: `rustls` 0.23.46, `quinn-proto` 0.11.18, `h2`
  0.4.19 and non-yanked `chacha20` 0.10.2 address current lockfile findings.
  Patch both `rand` branches to 0.8.6/0.9.3 and remove the now-obsolete
  RUSTSEC-2026-0097 exception. Replace unmaintained `rustls-pemfile` with
  `rustls-pki-types` for certificate, CA and private-key loading, removing its
  exception while preserving mandatory mTLS client verification. The
  maintained YAML parser (see Changed) removes the former YAML
  maintenance warning. The only remaining vulnerability exception is `rsa`
  (RUSTSEC-2023-0071), present through sqlx's optional, uncompiled MySQL driver
  with no patched release.

- Raise dashboard dependencies to Next.js 16.4.2 and Undici 8.12.2, and patch
  affected frontend transitive dependencies including sharp, source-map-js,
  js-yaml, Vitest and nanoid. `bun audit` reports no vulnerabilities.

### Added

- Include the rustbgpd speaker adapter in normal builds through the default
  `bgp-rustbgpd` feature, with authenticated gRPC, local-rule read-back and
  IPv4/IPv6 discard and policing support. Connect through an owner-only Unix
  socket or verified native client-certificate mTLS; loopback bearer and
  verified HTTPS configurations remain supported. Unix reconnects validate
  ownership and permissions, and certificate and token rotation keep the same
  speaker target identity. Reject non-root HTTP endpoint paths, because gRPC
  does not use those prefixes to distinguish speaker targets. Bound initial
  connections and TLS handshakes to ten seconds.

- Add `rustbgpd` and `gobgp` Compose profiles in one controller image, with
  private owner-authenticated speaker management and persistent writable
  configuration seeding that preserves operator edits. The quickstart leads
  with the prebuilt `main` controller and dashboard images and keeps a local
  source-build option. Docker copy-up no longer resets private empty-volume
  ownership or modes, and unused GoBGP profiling and metrics HTTP listeners are
  disabled.

- Add `origin_mode` (`dry-run`, `enforced` or `null` when unknown) to
  mitigation API responses and WebSocket mitigation messages. The dashboard
  marks dry-run-origin mitigations with a neutral "Simulation" tag on the
  Overview, list and detail pages; the detail page shows "Origin unknown" for
  rows that predate origin tracking.

- Audit mitigation creation. Each admitted mitigation writes one `create`
  audit entry in the same transaction as its row, from manual creation, single
  and batch events and the Alertmanager, FastNetMon and generic webhook
  adapters. The entry records the operator, or the detector source and event
  ID, plus the POP, scope, action and parameters, TTL, origin mode and the
  mitigation ID as `target_id`. TTL extensions by repeat events and rejected
  admissions write no entry. The audit log page and its action filter show the
  new action.

- Show authenticated rustbgpd daemon version, process uptime, readiness and
  observation time in health detail, CLI status and the existing speaker strip.
  Keep controller metadata separate and failed, stale or unsupported observations
  explicit; GoBGP process metadata remains unsupported.

- Add an optional `expires_at_cap` to manual mitigation creation for maintenance
  recreation without extending the original deadline. Existing TTL guardrails
  apply to remaining lifetime. Expired intent is not announced after a database
  wait, including reconciliation's final pending-cleanup check.

- Split required speaker writes from optional rule and peer observation while
  retaining the selected-speaker facade. Health reports backend and
  availability; CLI and dashboard distinguish unsupported, failed and empty
  peer reads. All existing adapters retain both observations. Write-only
  reconciliation skips repairs while preserving desired counts, TTL expiry and
  pending cleanup; production write-only backends remain gated on a durable
  announcement ledger.

- Add reconciliation repair outcome counters and operator recovery and alert
  guidance.

- Add `prefixd --version`. `/openapi.json` now reports the package version as
  `info.version` instead of a fixed `1.0.0`.

- Publish releases through a tag-triggered workflow: version-tagged controller
  and dashboard images, a Linux amd64 tarball with `prefixd` and `prefixdctl`,
  a CycloneDX SBOM, `SHA256SUMS` and image digests in a draft GitHub Release,
  followed by an install-contract check of the published assets. `ci.yml` no
  longer runs on version tags; it keeps publishing `main`, `latest` and
  commit images.

- Qualify the speakers in CI with isolated, pinned fixtures: shared
  readable-speaker lifecycle checks across Mock, rustbgpd and GoBGP;
  digest-pinned rustbgpd 0.76.0 and 0.77.0 coverage for local lifecycle, TTL
  withdrawal and recovery through the same client after a speaker restart;
  GoBGP API, peer and restart qualification; and a rustbgpd↔GoBGP FlowSpec peer
  test for exact dual-family receipt, withdrawal and re-announcement and
  retained nonselected local intent. Backend fixture logs are retained.

- Add an FRR FlowSpec interop workflow and `just interop-frr`. Each leg drives
  prefixd's HTTP API with rustbgpd 0.78.0 or GoBGP 4.10.0 peered to FRR 10.7.1
  in containerlab. It asserts the exact rules in FRR's received IPv4 and IPv6
  FlowSpec tables through discard, police, detector, withdrawal, TTL expiry
  and speaker-restart steps, and uploads a dated receipt. This is control-plane
  evidence only. An SR Linux 25.10.1 probe found no FlowSpec support there.

### Changed

- Qualify rustbgpd 0.78.0: Compose and the interop lab pin it; CI tests 0.76.0
  (minimum), 0.77.0 and 0.78.0.

- rustbgpd 0.78.0 changes for operators: `bgp_outbound_route_drops_total` now
  counts FlowSpec writer-channel deferrals, a new
  `bgp_outbound_commit_refusals_total` metric exists, the
  `BgpOutboundRouteDrops` alert drops from critical to warning, and rustls
  0.23.46 security fixes cover its gRPC TLS listener.

- Put active mitigation intent, signal evidence, expiry and honest router-observation
  limits first in the operator workspace. Refresh the light/dark theme, Geist
  typography and navigation; preserve user zoom and remove decorative pulses,
  hardcoded quota caps and sampled action totals presented as global counts.

- Give dashboard status its own colour scale, separate from the interaction accent:
  active mitigations and healthy services are green, pending and degraded states
  amber, and escalated or failed states red. Keep one dashboard shell mounted
  across navigation, tighten card spacing, lift dialogs and menus above page
  surfaces in dark mode, and match the browser theme colour to each theme.
  Bandwidth labels drop trailing zeros, such as "5 Mbps".

- Adopt the prefixd brand palette: neutral grey surfaces and text with the
  brand green as the single accent for actions, focus and links, replacing the
  teal accent. Success states share the green hue; each theme keeps 4.5:1 text
  contrast for status colours and primary buttons.

- Remove the Severity column from the mitigations list; it was derived from
  status and action and repeated them. Every dashboard page now has one titled
  header, shared tables, status pills and empty, loading and error states, with
  sentence-case labels, UTC timestamps and monospace only for identifiers. On
  narrow screens, mitigation and event rows stack so target, action, expiry and
  Withdraw stay visible. The audit log search placeholder is now "Search target
  or details…".

- Chart the overview activity in UTC hours to match the top-bar clock, with UTC
  tooltips, 12px ticks and an inset last tick; the chart now stays inside its
  column. Mitigation, corroborator-cache and signal-group expiry show the
  absolute UTC deadline beside the countdown. Correlation source weights use a
  neutral ramp with a matching legend. Configuration editors, Administration and
  notification preferences use the shared empty, loading and error states, and
  each failed read offers Retry. The Configuration, Administration and
  Correlation tabs are kept in `?tab=`, so links and refresh reopen the same tab.

- Replace unmaintained backend YAML parsing with `serde-saphyr` 2.0.0. Keep
  strict booleans, unexpanded merge keys and snippet-free parse errors;
  duplicate map keys are now rejected (see Breaking).

- Refresh the dashboard toolchain to Bun 1.4.3, native Node.js 26.12.0 tests,
  React 19.3.1 and current Radix and test dependencies, with frozen Bun lock
  installs in CI and containers. Enforce TypeScript errors in production
  dashboard builds and add a standalone type check. Update the playbook YAML
  editor to js-yaml 5 with bundled TypeScript declarations while preserving
  YAML merge keys.

- Enforce the vendored anti-slop Oxlint rules on the dashboard: `bun run lint`
  now runs in `just frontend`, and so in `just gate` and the CI Frontend job.
  Dashboard tests drive components through a scripted controller behind the
  real fetch path instead of module mocks. The playbook YAML editor now reports
  an unknown step action as a parse error.

- `prefixd_reconciliation_active_count` now carries the controller's
  configured POP as its `pop` label instead of a hard-coded `pop="local"`.
  Update any queries that select `pop="local"`.

- Development and CI: add a sequential `just gate` verification bar and focused
  recipes, with optional non-mutating commit and push hooks; check Rust 1.89
  and locked Linux builds for production binaries with rustbgpd, all
  targets/features and no default features; forbid unsafe code in the library,
  both binaries and the integration-test crate, and require explained lint
  exemptions; isolate integration-test HMAC secrets in bounded child processes;
  run pull-request CI for stacked topic branches; build both Docker images on
  pull requests without publishing; tolerate Docker cache export failures; and
  refresh compatible Rust patches (futures 0.3.33, prost 0.14.4, serde_json
  1.0.151, async-trait 0.1.92, base64 0.23.1 with only its standard-library
  feature).

### Fixed

- Admit new mitigations atomically against shared PostgreSQL customer, POP and
  global quotas. Competing controllers cannot consume the same last slot; quota
  rejection or a bounded database admission failure sends no announcement from that
  request. The 5-second admission deadline covers only the work before COMMIT,
  so a slow COMMIT can no longer return `500` for a mitigation it stored.

- Persist new detector and manual mitigation intent before speaker announcement,
  preventing a failed insert or interrupted request from leaving an unowned rule.
  Retain committed intent after speaker errors so readable reconciliation and
  TTL/withdrawal cleanup can recover it.

- Persist withdrawal intent before speaker RPCs (migration 013) so ambiguous
  replies and database failures cannot restore a requested deletion. Retry
  across controller restarts, preserve the original actor/reason in an atomic
  audit transaction, and reject foreign-POP, shared-owner and stale-operation
  deletions. New mutations conflicting with pending cleanup return `409`. Drain
  cleanup before changing speaker targets or downgrading to a binary that
  ignores the queue.

- Keep expired mitigations eligible for withdrawal retry when the speaker call
  fails. Successful expiry state and notifications now require a confirmed
  withdrawal; other expired mitigations are still processed during a failure.

- Detector unban and bulk withdrawal now report speaker failures and preserve
  active state instead of reporting successful removal. Operators can retry.

- Preserve enforced-mode withdrawal requests across dry-run restarts. Reject
  canonical duplicate creation before RPC, extend a single canonical detector
  owner, and let expired legacy duplicate owners complete TTL cleanup once no
  live owner remains.

- Repair discard/policing action drift as well as missing FlowSpec matches on
  exclusively administered speaker targets. Reject ambiguous owners and invalid
  observed inventories, preserve unknown rules, and recheck lifecycle state before
  each upsert. Converged polls do not repeat announcements; this adds no fence
  against another controller writing the same local match.

- Recover every eligible desired rule when creation timestamps tie. Reconciliation
  reads a strict complete owner inventory scoped to the controller's POP; pending
  creation rows remain excluded from repairs and active-status gauges.

- Isolate expiry inventory to the controller's POP before decoding and fail on
  corrupt owned rows instead of silently skipping them. Durable withdrawal
  retries and independent reconciliation stages continue after enumeration fails.

- Failed announcement repairs now make reconciliation fail while other repairs
  continue. Continue independent reconciliation housekeeping and peer
  observations after mutation failures, and release the lifecycle lock between
  scheduler rules. Startup performs one immediate pass, then waits for the
  interval.

- Require complete dual-family GoBGP local read-back. Received paths are excluded;
  malformed or unsupported local rules and stream failures fail observation.
  Bound full inventory and peer streams to 30 seconds, and reject lossy action
  decoding instead of inventing discard or truncating policing rates.

- Bound complete GoBGP and rustbgpd mutation responses, including stalled bodies
  and trailers, to 30 seconds per attempt with at most three attempts.

- Select the Rustls crypto provider before TLS startup.

- Canonicalize prefix spelling when computing FlowSpec rule identity so
  equivalent IPv6 addresses do not trigger repeated reconciliation injections.

- Keep pending or failed-expiry rows in status-active mitigation gauges. Use
  rustbgpd peer addresses for unique session names and skip unnecessary locked
  database reads for already-observed announcement candidates.

- Grafana reconciliation runs and configuration reloads now group and label
  the actual `status` series.

- Preserve host scope for automatic IPv6 mitigations with canonical `/128`
  destinations, including when prefix guardrails are relaxed. Use ICMPv6 protocol
  58 in IPv6 event metadata and policy intent; IPv4 retains `/32` and ICMP protocol
  1, with TCP/UDP behavior unchanged.

- Accept explicit `icmpv6` in manual mitigation requests as IPv6 protocol 58.
  Keep `icmp` as IPv4 protocol 1 and reject cross-family ICMP choices before
  saving intent or calling the speaker.

- Reject disjoint detector/service destination-port selections before they become
  protocol-wide FlowSpec rules or extend an existing wildcard owner. Intentional
  unconstrained port matches remain supported.

- Apply concrete POP filters before mitigation pagination and match identifiers
  exactly, preserving omitted/`all` global listings.

- Fail IP history and incident reports when a selected mitigation cannot be decoded,
  instead of returning successful partial history. Preserve existing IP filters
  and SQL limits.

- Count successful entries in bulk acknowledgement responses so duplicate IDs
  agree with the ordered per-entry results while each stored row is updated once.

- Saturate large timeseries day/hour conversions before applying the existing
  range maximum and bucket minimum, preserving invalid-input defaults.

- Report string-length validation limits in bytes, matching the existing UTF-8
  byte checks, including playbook names and alert destinations in both
  dashboard editors; document reason limits without changing accepted input
  lengths.

- Preserve exact untransformed webhook `bps` and `pps` integers and reject
  nonfinite or out-of-range floating-point results instead of rounding or
  saturating them. Fractional rates still truncate toward zero; floating-point
  endpoints are rejected because JSON parsing can lose the original range.

- Avoid overflow when classifying FastNetMon SYN percentages from large valid
  integer counters, preserving the existing integer threshold and protocol rules.

- **FastNetMon SYN floods labelled `udp_flood`.** Vector detection matched the
  first protocol word anywhere in the attack details, so an idle line such as
  `outgoing udp traffic: 0 mbps` won over `syn_flood`. Zero-metric lines,
  including `0 packets per second`, are ignored; TCP flag vectors are matched
  before `udp`; and protocol token boundaries keep `ack` out of `packets` and
  `Attack_type`.

- Reject non-finite correlation confidence thresholds and source/default weights
  on YAML loading and API edits, including numeric overflow.
  Preserve the active correlation configuration after a rejected reload or edit.

- Load saved standalone `correlation.yaml` at startup so correlation editor
  changes survive restart. Reject invalid or unreadable files instead of silently
  reverting to inline settings.

- Keep disabled authentication consistently anonymous: reject named login with
  HTTP 403, ignore retained operator sessions before request tracing, and hide
  named dashboard controls. Logout still deletes retained sessions. Wait for a
  known authentication mode before presenting the login form.

- Fix `prefixdctl operators list` against the shipped operator schema while
  preserving its JSON fields, table output and exclusion of password hashes.

- **Safelist removal from the dashboard returned 404.** The Next.js API proxy
  joins percent-decoded route segments, so `DELETE /v1/safelist/8.9.8.9%2F32`
  reached the backend as `/v1/safelist/8.9.8.9/32` and missed the
  single-segment route. The proxy now re-encodes each segment, and the route
  accepts a literal slash form (`{*prefix}`) for proxies that decode `%2F`.

- **Dashboard had no sign-out (and no role-based permissions).**
  `/v1/auth/login` and `/v1/auth/me` return a flat operator (`operator_id`), but
  the client read `data.operator`, leaving `operator` as `undefined`. The user
  menu (and therefore sign-out) never rendered, and role checks denied admin
  actions to authenticated admins. Auth responses are now mapped to the client
  `Operator` shape and `isAuthenticated` is a strict boolean.

- **Copy buttons failed silently on plain-HTTP deployments.**
  `navigator.clipboard` only exists in secure contexts, so the incident report,
  FlowSpec rule, and webhook endpoint copy actions threw and reported nothing
  when the dashboard was served over HTTP. The copy helper now falls back to a
  hidden textarea, checks `clipboard-write` permission, and surfaces a "Copy
  failed — clipboard unavailable" toast instead of claiming success. Chrome
  ignores clipboard writes entirely for plain-HTTP origins (other than
  `localhost`), so production dashboards need HTTPS for clipboard actions —
  documented in `docs/how-to/deployment.md`.

- Stop the Playbooks form showing "Unsaved changes" on load. The form dropped
  each playbook's `correlation` field, so it never matched the loaded playbooks,
  and saving from either playbook editor erased per-playbook correlation
  overrides. Both editors now keep them, and Correlation shows each override.

- Show a failed request as a retryable error, not as "not found" or as default
  values, on the mitigation and signal-group detail pages and in notification
  preferences, where saving the defaults would have overwritten stored settings.

- Show a healthy controller as healthy on the Administration page. The daemon
  status pill treated the reported `healthy` value as an error and `degraded` as
  normal.

- Display confidence fractions consistently as percentages across event, mitigation
  and correlation views. Preserve zero, distinguish missing and invalid values, and
  avoid implying that confidence confirms mitigation or router installation.

- Keep withdrawal confirmations open during requests and failures, preserve
  failed bulk selections and reasons for retry, and report local completion
  without claiming downstream router convergence.

- Restore dashboard live cache refresh and notification muting by matching the
  server's WebSocket event names. Label ordinary updates and feed resynchronization
  accurately.

- Restore immediate dashboard retries after failed GET requests while continuing
  to share requests that are still pending, and stop handled failed GET requests
  from also producing unhandled browser rejections during cache cleanup.

- The command palette finds mitigations and events by ID, and rows that load
  while a search is already typed are no longer hidden.

### Documentation

- Add the [v0.19.1 → 0.20.0 upgrade guide](https://github.com/lance0/prefixd/blob/v0.20.0/docs/how-to/upgrading.md#v0191--0200)
  and a [release checklist](https://github.com/lance0/prefixd/blob/v0.20.0/docs/project/release-checklist.md).

- Publish the [speaker profile qualification record](https://github.com/lance0/prefixd/blob/v0.20.0/docs/reference/qualification/speaker-profiles-2026-10-18.md)
  for both Compose profiles, and refresh the operator guides and example
  dashboard image against it.

- Rebuild the README around reader paths, the rustbgpd profile and the
  guardrails that run before any speaker call. Move setup next steps into the
  quickstart, add cookbook recipes for manual mitigation and dry-run rollout,
  and route the documentation index by task.

- Organize guides, references, explanations and historical evidence with a
  documentation index and local-stack tutorial; retain ADR identifiers.

- Replace the historical roadmap checklist with current remaining work and
  reconcile speaker/framework decisions with shipped defaults, transports and
  durable intent. Remove the unusable duplicate PostgreSQL example; use the
  maintained rustbgpd or GoBGP configuration instead.

- Record the rustbgpd-first, pluggable-speaker rollout while retaining GoBGP.
  Correct the controller-crash claim: a separate BGP daemon can keep advertising
  while prefixd is down; TTL enforcement requires running reconciliation.

- Refresh the security support policy and the authentication and audit
  guidance. Correct the documented history-pruning transaction to retire
  completed withdrawals safely and retain pending cleanup, recent history and
  referenced detector/correlation events; audit records are preserved and
  vacuum runs separately.

- The local development guide notes that the dashboard dev server can't serve
  the live feed; use the nginx origin to test it.

- `prefixdctl mitigations list` help and the CLI reference now say it lists
  every status, newest first, unless `--status` is given. The dry-run cookbook
  covers both no-mitigation cases: an event for an address no customer owns
  returns `202` `accepted_no_mitigation`, and an owned, safelisted address
  returns `422`.

## [0.19.1] - 2026-08-06

### Changed
- **Next.js upgraded 16.1.7 → 16.3.0.** Fixes Docker build failure with Turbopack catch-all route page data collection.
- **Bun Docker image upgraded 1.3.10 → 1.3.14.** Resolves Turbopack runtime module loading issue in Docker builds.

### Fixed
- **Docker dashboard build.** Frontend Dockerfile now uses Bun 1.3.14 (compatible with Next.js 16.3 Turbopack). The `force-dynamic` export added to the catch-all API proxy route prevents build-time page data collection errors.
- **Docker Compose port conflict.** Nginx port mapped to 8088 to avoid conflict with host nginx on port 80.


### Security

- **Rate limiting middleware activated.** The `RateLimiter` implementation (previously dead code) is now wired into the router via `common_layers`. All API endpoints are rate-limited using a global token bucket (configurable via `http.rate_limit.events_per_second` and `burst`, always-on with defaults).
- **Login timing attack mitigated.** `AuthBackend::authenticate()` now runs a dummy Argon2 password verification when the operator is not found, eliminating the timing side-channel that enabled username enumeration.
- **Operator ID IDOR fixed.** Five mutation handlers (`create_mitigation`, `withdraw_mitigation`, `bulk_withdraw`, `bulk_acknowledge`, `add_safelist`) now derive `operator_id` from the authenticated session (`operator.username`) instead of trusting the client-supplied request body field. The `operator_id` field remains in request structs with `#[serde(default)]` for backward compatibility but is ignored.
- **Safelist operations require Admin role.** `add_safelist` and `remove_safelist` now use `require_role(Admin)` instead of `require_auth()`. Viewers can no longer disable DDoS protection for arbitrary IPs.
- **`reload_config` requires Admin role.** Any authenticated user could previously trigger a config reload from disk.
- **`list_audit` requires Operator role.** Audit logs are no longer accessible to Viewer-role users.
- **`change_password` verifies current password for self-change.** Admin resets of other users' passwords skip the check, preserving the admin password-reset flow. Frontend updated to send `current_password` for self-change.
- **CORS invalid-origin handling.** Invalid `cors_origin` config no longer panics; instead disables CORS with an error log (previously panicked via `.expect()`, then regressed to a wildcard+credentials panic, now graceful).
- **Generic alerting URL redacted.** `DestinationConfig::Generic` redacted view now masks the webhook URL (same as Slack/Discord/Teams).
- **Correlation HMAC `secret_env` redacted.** The env var name is no longer exposed in the redacted correlation config API response.
- **Dead auth middleware removed.** `auth_middleware`, `hybrid_auth_middleware`, and `validate_bearer_token` (never wired into the router) have been removed. All auth flows through `require_auth()` / `require_role()`.

### Fixed

- **`doFetch()` empty-body crash.** The frontend API client unconditionally called `res.json()` on all responses, causing `SyntaxError` on 201/204 empty-body responses from safelist, password, and notification mutations. Now uses `res.text()` + conditional `JSON.parse`.
- **TOCTOU race in `handle_ban`.** `find_active_by_scope` + `insert_mitigation` were non-atomic; concurrent ban events for the same victim created duplicate FlowSpec announcements. Added `mitigation_lock: Mutex<()>` to serialize the find+insert critical section. Lock is dropped before the BGP announce call to avoid blocking.
- **Safelist check fail-open.** `is_safelisted()` used `.unwrap_or(false)`, allowing mitigations for safelisted IPs on DB errors. Now fails closed via `.map_err(AppError)?`.
- **WebSocket permanent death after 10 reconnects.** Added `visibilitychange` listener that resets the reconnect counter and reconnects when the tab becomes visible.
- **Auth-expired redirect.** 401 events now call `router.push('/login')` instead of only clearing the operator, preventing RequireAuth from hanging on a spinner.
- **SWR thundering herd on ResyncRequired.** `mutate(() => true)` scoped to volatile keys (mitigations, events, stats, dashboard, signal-groups) and now handles both string and array SWR keys.
- **Bulk withdraw error display.** Dialog stays open on partial failure so the error message remains visible.
- **IPv6 `/32` prefix in `create_mitigation`.** Now uses `/128` for IPv6 victims (was hardcoded `/32`).
- **Silent error swallowing.** Unban event insertion and signal group resolution now log warnings on DB errors instead of silently discarding them.
- **Guardrails warning log level.** Unenforced `allow_*` flag warning changed from `warn!` to `debug!` to prevent log spam under attack load.
- **Rate limiter division by zero.** `events_per_second=0` no longer panics (guarded with `.max(1)`).

### Changed

- **Dependency bumps.** `rustls 0.23.37→0.23.40`, `regex 1.12.2→1.12.3`, `tower-http 0.6.8→0.6.10`, `tokio 1.52.1→1.52.3`, `reqwest 0.13.2→0.13.3`, `actions/checkout 6→7`, `actions/cache 5→6`, `vite 7→8.2.0`, `@vitejs/plugin-react 5→6`, `typescript 5→7.0.2`, `jsdom 28→29`, `lucide-react 0.575→1.28`.

### Added

- **22 integration tests** for previously untested API endpoints: operators CRUD (6), safelist CRUD (5), manual mitigate (5), audit log (2), stats (1), auth (2), single withdraw (2), event edge cases (3). Plus 1 admin-reset-without-password test. Total: 427 tests (250 unit + 161 integration + 16 postgres; 17 ignored requiring GoBGP/Docker).
- **Documentation.** Added API docs for `GET/PUT /v1/config/correlation`. Updated AGENTS.md endpoint list (7 missing endpoints added) and ADR count (19→22). Documented `max_escalated_duration_seconds`, guardrails `allow_*` flags, and rate limiting middleware behavior.
- **OpenAPI spec.** Registered 9 missing handlers (change_password, login, logout, get_me, create_operator, delete_operator, list_operators, add_safelist, remove_safelist) in the OpenAPI `paths()` array.

### Documentation

- Annotated 4 phantom config fields as unimplemented (`range_end`, `match.source`, `match.protocol`, `default_playbook`).
- Fixed reload response example (missing "correlation").
- Fixed playbook example vector (`dns_amplification` → `udp_flood`).
- Added `transforms` field to correlation config redacted output.
- Updated `change_password` API docs with `current_password` field and admin-reset behavior.

## [0.18.1] - 2026-05-11

### Added

- **Generic webhook adapter transforms.** Per-field transforms applied after JSONPath extraction in the generic webhook adapter (ADR 020). Three variants cover the common shapes:
  - `unit_conversion` — multiply an extracted numeric value (`bps`, `pps`, `confidence`) by a constant. Useful for `Mbps→bps`, `kpps→pps`, percentage → ratio.
  - `regex_extract` — pull a capture group out of an extracted `vector` string. Lets operators map free-form alert descriptions ("Detected: udp_flood at 250Gbps") onto prefixd vector names without writing a shim.
  - `computed` — replace a numeric field's value with `scale * Π(extract(path_i))`. Lets operators derive fields not directly present in the payload (e.g. `bps = packets × avg_size × 8`).
  - All transforms are validated at config load (regex compiles, multipliers are finite, transform shape matches field type) so misconfigurations fail fast on `POST /v1/config/reload` rather than silently producing zero events.
  - 17 new tests (14 unit + 3 end-to-end integration) covering each variant, compile-time validation, type-mismatch rejection, missing-value passthrough, and interaction with the existing `confidence_scale` clamp pipeline.

## [0.18.0] - 2026-05-11

### Added

- **Confidence decay for signal groups (ADR 022).** Exponential time decay applied to per-event confidence contributions when computing `derived_confidence`. Each event's effective weight is multiplied by `0.5 ^ (age_seconds / half_life_seconds)`, so older corroborating evidence smoothly loses influence without ever being discarded. Default is disabled (`confidence_decay_half_life_seconds: 0`); zero behavior change for existing deployments.
  - **Global config:** `correlation.confidence_decay_half_life_seconds: u32` (default 0). Validated to `0 ≤ H ≤ 10 × window_seconds`.
  - **Per-playbook override:** `correlation_override.confidence_decay_half_life_seconds: Option<u32>`. `Some(0)` explicitly disables decay for the playbook; `None` falls through to global.
  - **Reconcile loop step.** New `refresh_decayed_confidence` step iterates every open signal group each tick (default 30 s) and recomputes `derived_confidence` from current events with decay applied. No-op when decay is disabled.
  - **One-shot `corroboration_met`.** When `derived_confidence` falls below the threshold due to decay, `corroboration_met` is now sticky (`met_now || was_met`) — once a group has authorized mitigation, decay never revokes that authorization for the group's lifetime.
  - **Metric:** `prefixd_signal_group_decay_refreshes_total` counter ticks once per `refresh_decayed_confidence` invocation. Alert on "decay loop not running" by watching for the counter going flat.
  - **UI:** Group detail page surfaces "decayed, half-life Ns" next to `derived_confidence` when decay is active for the group's effective playbook.
  - 17 new tests (7 engine unit + 7 config unit + 3 integration) covering decay math, override resolution, validation, disabled paths, and one-shot stickiness.

## [0.17.1] - 2026-05-11

### Changed

- **Dependency bump bundle.** Bumps `hmac 0.12 → 0.13`, `sha2 0.10 → 0.11`, `clap 4.6.0 → 4.6.1`, `rand 0.10.0 → 0.10.1`. The `hmac`/`sha2` bumps are coupled (hmac 0.13 pulls digest 0.11, locking it to sha2 0.11) and required importing `hmac::KeyInit` explicitly in `src/correlation/webhook.rs` and `src/alerting/generic.rs` — `new_from_slice` moved off the `Mac` trait in 0.13. No runtime behavior change. Closes #106, #118, #119, #120.

### Deferred

- **`password-hash 0.5 → 0.6` (#116).** Not bumped. `argon2 0.6` is still RC (latest stable: 0.6.0-rc.8) and `argon2 0.5` (current stable) still depends on `password-hash 0.5`, so bumping `password-hash` alone would create a dual-version transitive with no security gain. Will revisit when argon2 0.6 stabilizes.

## [0.17.0] - 2026-04-29

### Added

- **Corroborating signals v2 (PR B)** — Follow-up to ADR 021's initial ship that addresses the four review-deferred items as a coordinated set:
  - **Playbook-aware late finalization.** Migration `012_signal_groups_playbook.sql` adds nullable `signal_groups.playbook_name`, populated by the daemon on the next primary event for each group via `COALESCE`. The corroborator-side aggregate recompute now re-resolves the playbook by name from live state and is allowed to flip `corroboration_met=true` using the override min_sources/threshold. Conservative fallback is preserved: a NULL or stale `playbook_name` still keeps the v0.16.0 no-flip behavior (the next primary event picks up the flag).
  - **Per-source attribution on `prefixd_corroborator_expired_total`.** The counter regains its `{source}` label set, with `delete_expired_corroborating_signals` collecting attribution in the same `DELETE … RETURNING` query that performs the delete. **Operator note:** this is a label change. PromQL queries written against the v0.16.0 unlabelled counter must add a `sum()` to recover the previous shape.
  - **New gauge `prefixd_corroborator_cache_size{source}`** updated by the reconcile loop after each sweep. Operators can alert on caches growing without bound (e.g. a source posting heavily while no matching primary event ever lands). Stale labels are explicitly zeroed when a source's cache drains between ticks.
  - **Cached-corroborators admin endpoint and dashboard panel.** `GET /v1/signals/corroborator/cache` (admin-only) returns `{ now, total, by_source[], signals[] }` filtered to unattached + unexpired rows, with optional `?source=` and `?limit=` (clamped to 1..1000). New "Cache" tab on the Correlation page renders per-source counts plus a dense table of cached signals with relative ingested/expires timestamps and dimension chips. Backed by a new `useCachedCorroborators` SWR hook (30s refresh).
  - **`CorroboratorResponse.cached` removed** in favor of the existing `status ∈ {attached, cached}` discriminator. The boolean was always `true` and added no information; status fully describes the outcome. Coordinated minor breaking change — bump to v0.17.0 — since the endpoint is new in this release line.

## [0.16.0] - 2026-04-19

### Added

- **Corroborating signals (ADR 021)** — New class of correlation signals that strengthen open signal groups without ever triggering mitigations on their own. Targets coarse telemetry (router CPU, interface utilization, per-customer NetFlow, PoP-level metrics) that shouldn't name a victim IP but is valuable alongside a real detector.
  - Configure via `mode: corroborating` + `match_dimensions: [pop, customer_id, service_id, interface]` on any entry in `correlation.yaml`'s `sources` map. Declared dimensions are **authoritative**: a source declared for `[pop]` can never attach via an undeclared `customer_id`/`service_id`/`interface`, even if those values happen to match an open group. Validator rejects misconfiguration on both `PUT /v1/config/correlation` and on YAML load — the daemon refuses to boot with invalid correlation config.
  - New endpoint `POST /v1/signals/corroborator` accepts dimension-tagged signals (no `victim_ip`). Matches open signal groups using OR-semantics **across declared dimensions only**, with an optional `vector` narrower. Unmatched signals cache for up to `window_seconds` and drain when a matching primary event arrives.
  - Engine invariant enforced in two places: (a) `check_corroboration_with_primary` requires at least one primary event before `corroboration_met` can flip true, and (b) the corroborator-side aggregate recompute refuses to promote `corroboration_met` from false→true on its own — only the primary-ingest path (which has playbook-override context) can do that.
  - `POST /v1/events` rejects corroborating-only sources at handler entry, before any ban/unban branching and before any DB writes. Nothing persists from a rejected event.
  - New `interface` field on inventory `Asset` entries feeds into `IpContext.interface`, so interface-only corroborators (a common gNMI / SNMP shape) now have a real matchable dimension.
  - Reconciliation loop sweeps expired corroborators. Three new Prometheus metrics: `prefixd_corroborator_ingested_total{source}`, `_attached_total{source}`, `_expired_total` (unlabelled — per-source attribution deferred to PR B; see ROADMAP). `_expired_total` counts only *unattached* cache misses — signals that attached and then had their cache row GC'd no longer inflate the counter. Migrations 009, 010, and 011 (the last backfills `primary_dimensions` for pre-upgrade open signal groups from their mitigations so corroborators can attach to in-flight incidents immediately after upgrade).
  - New endpoint `GET /v1/signals/corroborator/activity?minutes=N` returns per-source `(last_seen, count)` aggregated across the live cache *and* attached `signal_group_events` rows. The frontend merges this into the Signal Sources tab so `mode: corroborating` sources no longer render as "never seen" simply because they don't post to `/v1/events`.
  - Dashboard: per-source mode + dimension picker in the Correlation Config tab (switching back to `primary` auto-clears declared dimensions); corroborating badge on signal group detail's contributing-events list; null-safe `ingested_at` rendering for corroborator rows.
  - New CLI: `prefixdctl send-corroborator --source router-cpu --pop iad1 ...`.
  - See [ADR 021](docs/adr/021-corroborating-signals.md) for rationale; migrations 009 + 010 for schema; [docs/how-to/detectors/corroborating-signals.md](docs/how-to/detectors/corroborating-signals.md) for operator quickstart.

## [0.15.0] - 2026-04-18

### Added

- **Generic webhook adapter** — Integrate any detector or telemetry source that can POST JSON without writing Rust. Configure a named adapter in `correlation.yaml` with JSONPath field mappings, HMAC/bearer/none auth, optional batching via `root_path`, vector normalization, and confidence scaling. Events flow through the standard correlation and policy pipeline. New endpoint: `POST /v1/signals/webhook/{name}`. See [ADR 020](docs/adr/020-generic-webhook-adapter.md) for design rationale, [docs/how-to/detectors/generic-webhook.md](docs/how-to/detectors/generic-webhook.md) for an end-to-end walkthrough, and `docs/reference/configuration.md` / `docs/reference/api.md` for schema reference.
- **Webhook adapter config validation** — `CorrelationConfig::validate()` now rejects `confidence_scale <= 0` or non-finite, empty `auth.secret_env` / `auth.header`, and non-`sha256` HMAC algorithms. Misconfiguration surfaces as a 400 on PUT/reload instead of runtime 500s.
- **Frontend CRUD editor** for webhook adapters on the Correlation Config tab (all three auth modes, JSONPath field mapping, vector normalization, HMAC secret env-var reference, endpoint copy button).

### Fixed

- **Rust 1.95 CI compatibility** — Addressed new clippy lints (`collapsible_match`, `cloned_ref_to_slice_refs`, `field_reassign_with_default`) and match-exhaustiveness in `gobgp.rs` guard patterns.
- **Webhook `action` validation** — Invalid `action` values (e.g. `"resolved"`, typos) now produce a per-event mapping error instead of silently defaulting to `"ban"`. Missing/null still defaults to `"ban"`.

### Changed

- **Security advisory bumps** — `rustls-webpki` 0.103.10 → 0.103.12 (RUSTSEC-2026-0098/0099). `RUSTSEC-2026-0097` (`rand`) added to `cargo-audit` ignore list pending upstream fix.
- **New dependencies** — `serde_json_path 0.7` (RFC 9535 JSONPath), `subtle 2` (constant-time compare for HMAC).

## [0.14.1] - 2026-04-03

### Fixed

- **Prometheus metrics wired up** — All event, mitigation, announcement, reconciliation, guardrail, and BGP session metrics were defined but never incremented. Now properly instrumented across all handler and reconciliation paths. (contributed by @bswinnerton)
- **ANNOUNCEMENTS_TOTAL label simplified** — Dropped unused `peer` label (handlers don't have peer context); ANNOUNCEMENTS_LATENCY changed from per-peer HistogramVec to a global Histogram
- **MITIGATIONS_ACTIVE gauge accuracy** — Reconciliation loop now resets and recomputes the active mitigations gauge with correct `action_type` and `pop` labels each tick
- **BGP_SESSION_UP gauge** — Now updated each reconciliation tick from actual peer session state

### Changed

- Bump uuid 1.21.0 → 1.22.0
- Bump rustls 0.23.36 → 0.23.37
- Bump ipnet 2.11.0 → 2.12.0
- Bump @radix-ui/react-popover 1.1.4 → 1.1.15
- Bump recharts 3.7.0 → 3.8.0
- Bump picomatch 4.0.0 → 4.0.4

### Security

- **aws-lc-sys** — Updated 0.36.0 → 0.39.1 fixing CRL scope check logic error (RUSTSEC-2026-0048, high), PKCS7 signature validation bypass (RUSTSEC-2026-0047, high), PKCS7 cert chain bypass (RUSTSEC-2026-0046, high), AES-CCM timing side-channel (RUSTSEC-2026-0045, medium), X.509 name constraints bypass (RUSTSEC-2026-0044)
- **rustls-webpki** — Updated 0.103.9 → 0.103.10 fixing CRL Distribution Point matching logic (RUSTSEC-2026-0049)
- **picomatch** — Updated to 4.0.4 fixing ReDoS via extglob quantifiers (GHSA-c2c7-rcm5-vvqj, high) and method injection in POSIX character classes (GHSA-3v7f-55p6-f55p, moderate)

## [0.14.0] - 2026-03-20

### Added

- **Multi-signal correlation engine** — Time-windowed grouping of related attack events by (victim_ip, vector) from multiple detection sources. Configurable source weights, corroboration thresholds, and per-playbook overrides. When `correlation.enabled` is true, events are grouped into signal groups and mitigation only triggers when corroboration requirements are met (configurable `min_sources` and `confidence_threshold`). Single-source behavior is preserved with `min_sources=1` (backward compatible). See [ADR 018](docs/adr/018-multi-signal-correlation-engine.md).
- **Signal groups API** — `GET /v1/signal-groups` (list with cursor pagination, status/vector/date filters) and `GET /v1/signal-groups/{id}` (detail with contributing events, source weights, and confidence). Both endpoints require authentication.
- **Correlation context on mitigations** — `GET /v1/mitigations` and `GET /v1/mitigations/{id}` responses include a `correlation` field for correlated mitigations, containing signal_group_id, derived_confidence, source_count, corroboration_met, contributing_sources, and a human-readable explanation.
- **Correlation engine metrics** — `prefixd_signal_groups_total`, `prefixd_signal_group_sources`, `prefixd_correlation_confidence`, `prefixd_corroboration_met_total`, `prefixd_corroboration_timeout_total` Prometheus counters and histograms.
- **Signal group expiry** — Reconciliation loop expires open signal groups whose time window has elapsed, transitioning them to `expired` status.
- **Database migration 007** — `signal_groups` and `signal_group_events` tables, `mitigations.signal_group_id` nullable FK column with indexes.
- **Correlation configuration** — New `correlation` section in `prefixd.yaml` with `enabled`, `window_seconds`, `min_sources`, `confidence_threshold`, `sources` (per-source weight/type), and `default_weight`. Per-playbook `correlation` overrides in `playbooks.yaml`. Hot-reloadable via `POST /v1/config/reload`.
- **Alertmanager webhook adapter** — `POST /v1/signals/alertmanager` accepts Alertmanager v4 webhook payloads. Maps labels/annotations to attack event fields (vector, victim_ip, bps/pps, severity→confidence). Handles batched alerts with per-alert results, resolved alerts (→ withdraw), fingerprint dedup. Returns 400 for malformed payloads (Alertmanager won't retry 4xx). See [ADR 019](docs/adr/019-signal-adapter-architecture.md).
- **FastNetMon webhook adapter** — `POST /v1/signals/fastnetmon` accepts FastNetMon's native JSON notify payload. Classifies attack vector from traffic breakdown (UDP/SYN/ICMP/TCP), maps action type to confidence (ban=0.9, partial_block=0.7, alert=0.5, configurable), uses `attack_uuid` for dedup. Returns `EventResponse` shape for script compatibility.
- **Correlation config API** — `GET /v1/config/correlation` (secrets redacted) and `PUT /v1/config/correlation` (admin only, validates, writes YAML, hot-reloads). Correlation config reloaded alongside inventory/playbooks/alerting on `POST /v1/config/reload`.
- **Signal adapter E2E tests** — 3 end-to-end tests in `tests/integration_e2e.rs` verifying full-stack signal adapter flows through real Postgres and GoBGP: Alertmanager→signal group→mitigation, FastNetMon→signal group→mitigation, multi-source corroboration (FastNetMon + Alertmanager → same group → mitigation with FlowSpec in RIB). Marked `#[ignore]` by default (require Docker).

### Changed

- Backend unit tests increased from 126 to 179 (correlation engine, config parsing, corroboration, explainability, signal adapters)
- Integration tests increased from 44 to 99 (signal group CRUD, correlation flow, concurrent event handling, Alertmanager adapter, FastNetMon adapter, correlation config API)
- Postgres integration tests increased from 9 to 16 (signal group operations)
- Frontend tests increased from 34 to 67 (correlation dashboard, signal group detail, mitigation detail correlation)

## [0.13.0] - 2026-03-19

### Added

- **Event batching** — `POST /v1/events/batch` accepts up to 100 events in a single request. Sequential processing through the full pipeline (validation, guardrails, policy, announce) with partial success semantics. Returns per-event results with `202 Accepted` (all succeeded) or `207 Multi-Status` (mixed).
- **FlowSpec NLRI fuzz/property tests** — 8 proptest property-based tests for prefix parsing, NLRI roundtrip, and action roundtrip. Two cargo-fuzz targets (`fuzz_prefix_parse`, `fuzz_nlri_decode`) for offline fuzzing with libFuzzer.
- **Post-attack incident reports** — `GET /v1/reports/incident?mitigation_id=X` or `?ip=X` generates a markdown incident report with summary, timeline, events, mitigations, and audit trail. "Generate Report" buttons on mitigation detail and IP history pages with copy/download dialog.

### Fixed

- **WebSocket rejected all connections when auth_mode is none** — `ws_handler` checked for an authenticated session unconditionally, returning 401 for every connection in no-auth deployments. Dashboard showed "Disconnected" permanently.
- **Mitigation detail page showed "Not Found" on Next.js 16** — Dynamic route `params` became a Promise in Next.js 15+. Page was destructuring synchronously, getting `undefined` for the ID.
- **Dark mode outline button hover invisible** — Export CSV, Refresh, and other outline-variant buttons had nearly invisible hover states in dark mode (`bg-input/50` at ~11% opacity). Changed to `bg-accent/20` with accent-foreground text for visible teal-tinted hover.

## [0.12.0] - 2026-03-18

### Added

- **Cursor-based pagination** — All list endpoints (`/v1/mitigations`, `/v1/events`, `/v1/audit`) now use cursor-based pagination (`?cursor=<opaque>&limit=N`). Responses include `next_cursor` and `has_more` fields. **Breaking:** `offset` parameter removed (see ADR 016).
- **Date range filtering** — All list endpoints accept `?start=<ISO8601>&end=<ISO8601>` for time-bounded queries. Supports incident investigation workflows.
- **Bulk acknowledge** — `POST /v1/mitigations/acknowledge` marks mitigations as reviewed by an operator (sets `acknowledged_at`/`acknowledged_by`) without changing status. Filterable via `?acknowledged=true|false`. Migration 005 adds columns.
- **Per-destination event routing** — Each alerting destination can now specify its own `events` list to override the global event filter. Empty/absent inherits global. Backward-compatible (see ADR 017).
- **Notification preferences** — `GET/PUT /v1/preferences` stores per-operator toast notification settings (muted event types, quiet hours in UTC). Migration 006 adds `notification_preferences` table. Dashboard WebSocket toasts respect preferences; quiet hours suppress non-critical events only.
- **Notification preferences dialog** — User menu dropdown now includes "Notifications" item opening a preferences dialog with event toggles and quiet hours selectors.

## [0.11.0] - 2026-03-18

### Added

- **Bulk withdraw** — `POST /v1/mitigations/withdraw` accepts up to 100 mitigation IDs with partial success semantics. Frontend adds checkbox selection on active/escalated rows, select-all, selection toolbar, and confirmation dialog.
- **FlowSpec rule preview** — Mitigation detail page shows a router-style one-liner (`match destination ... protocol ... then ...`) above the structured grid. Copy Rule button for quick comparison with router CLI output.
- **CVE gate in CI** — Security audit (`cargo audit` + `bun audit`) now gates Docker publishing. CycloneDX SBOM generated on version tags.
- **Vendor capability matrix** — `docs/reference/vendors.md` with tested status for Juniper (verified), Arista (partially verified), Cisco IOS-XR, Nokia SR OS, and FRR. Reference import policies per vendor.

### Security

- **Next.js** — Updated to 16.1.7 (CSRF bypass, HTTP smuggling, disk cache DoS, postpone DoS)
- **undici** — Updated to 7.24.4 (WebSocket overflow, request smuggling, memory DoS, CRLF injection)
- **quinn-proto** — Updated to 0.11.14 (RUSTSEC-2026-0037, DoS in Quinn endpoints)
- **rollup** — Updated to 4.59.0 (GHSA-mw96-cpmx-2vgc, arbitrary file write)

### Fixed

- **Docs accuracy** — Fixed stale test counts, version strings, metrics port, SECURITY.md supported versions

## [0.10.1] - 2026-02-22

### Added

- **`victim_ip` filter on mitigations API** — `GET /v1/mitigations?victim_ip=X` filters by exact victim IP address. Supported in both single-POP and all-POPs queries. (#65)
- **FastNetMon integration guide** — New `docs/how-to/detectors/fastnetmon.md` with full setup, env vars, testing, and troubleshooting
- **Integration test** — `test_list_mitigations_filters_by_victim_ip` validates API filtering end-to-end

### Fixed

- **FastNetMon re-ban collision** — Deterministic `sha256(IP|direction)` event IDs caused permanent 409 duplicates after withdrawal. Script now uses UUID event IDs per ban occurrence, enabling re-ban and proper TTL extension. (#65)
- **FastNetMon unban flow** — Unban now queries active mitigations by `victim_ip` and withdraws directly, instead of relying on a shared event ID. Includes configurable retry window for ban/unban race timing. (#65)
- **FastNetMon withdraw missing `operator_id`** — Withdraw payload now includes `PREFIXD_OPERATOR` (default: `fastnetmon`) to satisfy API validation

## [0.10.0] - 2026-02-22

### Added

- **Playbook editor** — `PUT /v1/config/playbooks` endpoint (admin-only) with full validation, atomic YAML write with `.bak` backup, and hot-reload. Form-based editor and raw YAML editor on Config page frontend.
- **Interactive alerting config** — `PUT /v1/config/alerting` endpoint (admin-only) with validation, secret merge (`***` preserves existing secrets), atomic write to `alerting.yaml`, and hot-reload via `RwLock<Arc<AlertingService>>`. Frontend editor with type-specific forms for all 7 destination types, event filter checkboxes, save/discard controls.
- **Alerting config split** — Alerting configuration moved from `prefixd.yaml` to standalone `alerting.yaml` with backward-compatible fallback. Reloaded on `POST /v1/config/reload`.
- **Event cross-links** — Mitigation detail shows clickable triggering event and last event (TTL extend) links
- **GHCR Docker publishing** — CI publishes `prefixd` and `prefixd-dashboard` images to `ghcr.io` on push to main and version tags

### Security

- **SSRF protection** — Webhook URLs validated: HTTPS required, localhost and private/link-local IPs rejected
- **Secret merge ambiguity detection** — Errors on multiple same-type destinations instead of silent first-match
- **Atomic config writes** — Temp-file + `sync_all` + rename pattern for both playbooks and alerting; symlink targets rejected
- **Concurrent write serialization** — Both playbook and alerting PUT endpoints hold write locks across merge/validate/save/swap
- **reload_config() race fix** — Write locks held during load+swap to prevent stale overwrite from concurrent PUT
- **JSON parse rejection** — PUT endpoints return 400 on malformed JSON (not 500)
- **Event ID encoding** — All event ID query params in frontend links use `encodeURIComponent`
- **YAML boolean coercion fix** — Strict `=== true` check prevents `Boolean("false")` from being truthy
- **Stable React keys** — Playbook/step/destination editors use unique IDs instead of array indices

### Changed

- Backend unit tests: 93 → 116 (playbook validation, alerting validation, secret merge, SSRF, save/roundtrip, symlink rejection)
- Integration tests: 9 → 25 (playbook PUT, alerting PUT, SSRF rejection, hot-reload path, bearer auth)
- Frontend tests: 26 (unchanged)

## [0.9.1] - 2026-02-21

### Added

- **Webhook alerting backend** — 7 destination types: Slack (Block Kit), Discord (embeds), Microsoft Teams (Adaptive Card), Telegram (Bot API), PagerDuty (Events API v2 with auto-resolve on withdraw/expire), OpsGenie (Alert API v2), Generic webhook (HMAC-SHA256 signed). Fire-and-forget via tokio::spawn with 3 retries and exponential backoff. Configurable event type filtering. `prefixd_alerts_sent_total{destination,status}` Prometheus counter.
- **Alerting API endpoints** — `GET /v1/config/alerting` (secrets redacted) and `POST /v1/config/alerting/test` (sends test alert, returns per-destination pass/fail)
- **Chaos test suite** — `scripts/chaos-test.sh` with 17 resilience tests across 4 categories: Postgres chaos (kill during ingestion, restart recovery, state preservation), GoBGP chaos (kill during mitigations, reconciliation re-announce), prefixd chaos (restart, rapid restart, SIGKILL recovery), network chaos (nginx outage and recovery)
- **HTTP load test suite** — `scripts/load-test.sh` with 7 tests across 5 profiles (quick/default/sustained/burst/all), using `hey` for HTTP benchmarking. Baseline results: ~8,000 health req/s, ~4,700 ingestion req/s, P99 1.6ms
- **Benchmarks documentation rewrite** — `docs/perf/benchmarks.md` updated with fresh criterion micro-benchmark numbers, HTTP load test baselines, chaos test summary, bottleneck analysis, and instructions for running all three test suites

### Security

- **Login brute-force protection** — Per-username rate limiting (5 attempts per 60-second window) on `POST /v1/auth/login`, returns 429 when exceeded
- **Input validation sweep** — victim_ip validated as real IP address in `ingest_event` and `create_mitigation`; safelist prefix validated as CIDR/IP; string length limits on all user input fields (1024 general, 64 username, 256 password); username format validation (alphanumeric, dash, underscore); max password length to prevent argon2 DoS
- **Audit pagination bounded** — `list_audit` endpoint now applies `clamp_limit()` (was unbounded)
- **Request ID hardened** — `x-request-id` header capped at 128 characters with character validation, removed `.expect()` panics
- **CSV formula injection fix** — CSV export now prefixes cells starting with `=`, `+`, `-`, `@`, `\t`, `\r` with a single quote to prevent spreadsheet formula injection
- **Client token exposure removed** — Removed `NEXT_PUBLIC_PREFIXD_TOKEN` from frontend bundle (session cookies are sufficient for browser auth)
- **Login throttle race condition fixed** — Merged separate check/record into atomic `check_and_record_login_attempt` (single lock scope), added TTL pruning and 10K tracked-user cap to prevent unbounded memory growth
- **Generic webhook header redaction** — `GET /v1/config/alerting` now masks all custom header values with `***` (previously leaked raw values)
- **CIDR validation hardened** — Safelist prefix validation now uses `ipnet::IpNet` parser, rejecting invalid masks like `/999`
- **Alerting test endpoint admin-only** — `POST /v1/config/alerting/test` now requires admin role; frontend button gated behind permissions
- **CSV formula regex hardened** — Catches leading whitespace/newline before formula characters (`=`, `+`, `-`, `@`)
- **Alert queue bounded** — Semaphore caps in-flight alert tasks at 64; excess alerts logged and dropped

### Frontend

- **Alerting config UI** — New "Alerting" tab on Config page showing configured destinations (read-only, secrets redacted) with "Send Test Alert" button reporting per-destination pass/fail
- **Audit log detail expansion** — Click truncated details cells to expand full JSON inline; extracted AuditRow sub-component
- **Customer/POP filter on mitigations** — Dropdown filters using existing backend `?customer_id=` and `?pop=` query params
- **Timeseries range selector** — 1h/6h/24h/7d toggle buttons on activity chart with appropriate bucket sizes (5m/30m/1h/6h)
- **Active count badge on sidebar** — Live mitigation count badge on Mitigations nav item (collapsed and expanded modes)
- **Severity badges on mitigations** — Color-coded severity column (critical/high/medium/low) derived from status + action_type

### Changed

- Backend unit tests increased from 73 to 93 (alerting formatters, HMAC, CIDR validation, login throttle, header redaction)
- Frontend tests increased from 25 to 26 (added CSV injection regression test)
- OpenAPI spec now includes alerting endpoints
- Load/chaos test scripts support optional `PREFIXD_API_TOKEN` for authenticated environments

## [0.9.0] - 2026-02-20

### Added

- **Embedded time-series charts on overview** — 24h area chart showing mitigations and events per hour, PostgreSQL-backed with gap-filled buckets via `GET /v1/stats/timeseries`
- **IP history page** (`/ip-history?ip=X`) — Unified timeline of all events and mitigations for an IP, with customer/service context from inventory, via `GET /v1/ip/{ip}/history`
- **Clickable IPs everywhere** — All victim_ip cells in mitigations table, events table, active mitigations mini, mitigation detail, and event detail panel link to IP history
- **IP History in navigation** — Added to sidebar, command palette (`g h`), keyboard shortcuts
- **Database pool metrics** — `prefixd_db_pool_connections{state=active|idle|total}` gauge exposed to Prometheus on each `/metrics` scrape
- **Request correlation IDs** — Every request gets an `x-request-id` (UUID), preserved if client-provided, echoed in response, added to tracing span. nginx config forwards it.
- **HTTPS via nginx production example** — Full TLS termination config with HSTS, HTTP→HTTPS redirect, Let's Encrypt note
- **Reconciliation loop pagination** — Pages through all active mitigations instead of capping at 1000; adds `prefixd_reconciliation_active_count` gauge metric
- **Database migration tracking** — `schema_migrations` table records applied migrations with version, name, and timestamp; `prefixdctl migrations` command to check status
- **API versioning policy** — `docs/reference/api-versioning.md` documents backward compatibility guarantees, deprecation process, and `Sunset` header convention
- **Upgrade guide** — `docs/how-to/upgrading.md` covers Docker Compose and bare metal upgrade procedures, rollback guidance, and migration verification
- **IP validation on history endpoint** — Returns 400 on invalid IP input
- **4 new tests** — IP history rejects invalid IP, timeseries sub-hour bucket alignment, plus 2 timeseries/IP-history structure tests
- **CSV helper tests** (4 tests: headers/rows, comma escaping, quote escaping, null handling)

### Changed

- **Mitigate Now is now a modal dialog** - Opens over the mitigations list instead of navigating to a separate page; command palette and `n` shortcut open the modal directly
- **Removed `/mitigations/create` route** - Replaced by modal, no redirect needed
- **Upgraded recharts** 3.6.0 → 3.7.0
- **prefixdctl default endpoint** changed to `http://127.0.0.1` (nginx entrypoint, was `:8080`)
- **prefixdctl role validation** now includes `operator` role (was admin/viewer only)

### Fixed

- **Timeseries sub-hour bucketing** — `date_trunc('hour')` replaced with `date_bin()` for correct 5m/30m bucket alignment
- **Frontend TypeScript types** — chart.tsx recharts 3.7 tooltip/legend types, resizable.tsx API rename, badge component prop types widened to match backend values
- **CLI/docs drift** — Removed references to nonexistent `prefixdctl health` and `events` commands, fixed stale endpoint paths across all docs
- **CSV export crash on events page** - Was referencing `e.timestamp` which doesn't exist (correct field is `event_timestamp`); added null guard in CSV helper
- **Nested anchor in active-mitigations-mini** — Replaced with keyboard-accessible div+router.push wrapper
- **Activity chart loading states** — Merges buckets from both timeseries sources, shows loading/error/empty states

## [0.8.5] - 2026-02-19

### Added

- **Hook tests** - usePermissions (5 tests: auth disabled, admin, operator, viewer, deny-by-default) and useAuth (5 tests: provider guard, loading, login, logout, auth-expired event)
- **Activity feed clickable items** - Event entries link to `/events?id={id}`, mitigation-related audit entries link to `/mitigations/{id}`
- **Vector breakdown chart clickable** - Legend items link to mitigations filtered by vector
- **Inventory cross-links** - Customer IDs and asset IPs link to `/mitigations?ip={value}`
- **Mitigations search** - Now matches on vector, customer_id, and mitigation_id (was IP-only)
- **Dependency upgrades** - react-resizable-panels 2.1 → 4.6

## [0.8.4] - 2026-02-19

### Added

- **Manual mitigation creation** - "Mitigate Now" form at `/mitigations/create`
  - Fields: destination IP, attack vector, traffic metrics (bps/pps), ports, confidence slider
  - Submits `POST /v1/events` with `action: "ban"`, policy engine handles the rest
  - Permission-gated (operator + admin only), accessible from mitigations toolbar and command palette
- **Mitigation detail full-page view** - Dedicated drill-down page for mitigations (`/mitigations/{id}`) replacing the slide-over panel
  - Shows FlowSpec rule JSON preview and active configuration
  - Mitigation timeline visualizing Created → Escalated → Withdrawn/Expired events
  - Embedded Customer Context section querying the running inventory
  - Direct withdraw capabilities and status badges
- **Real-time toast notifications** - Operational events over WebSocket now surface as toast notifications in the UI:
  - Red/Error: New mitigation created
  - Yellow/Warning: Mitigation escalated
  - Green/Success: Mitigation withdrawn
  - Blue/Info: Mitigation expired or config reloaded
- **Inline withdraw button on mitigations table** - XCircle button on active/escalated rows with confirmation dialog
  - Optional reason field, permission-gated (operator + admin only)
  - Tooltips on view and withdraw action buttons
- **Per-peer BGP session detail on admin page** - Shows each peer name and session state (established/down) instead of a single boolean
- **ErrorBoundary for dashboard pages** - React class ErrorBoundary wraps all `(dashboard)/` routes; displays error message and "Try Again" button instead of blank screen
- **Admin page tabbed layout** - Refactored from long scroll to Tabs (Status, Safelist, Users); Users tab conditionally rendered for admins
- **Vitest + Testing Library** - Frontend test infrastructure with 11 tests (ErrorBoundary component, IP/port validation)
- **"Mitigate Now" in command palette** - Quick action entry to jump to manual mitigation form
- **CSV export** - Download button on mitigations, events, and audit log tables
  - Exports current filtered view as CSV (client-side, no backend)
  - Filename includes current date (e.g., `mitigations-2026-02-19.csv`)
- **Keyboard shortcuts** - `g i` (inventory), `n` (Mitigate Now), `?` toggles help modal
  - Removed phantom table navigation shortcuts (j/k/Enter) from help modal
- **Cross-entity navigation** - Wired up dead-end UI elements across dashboard:
  - Command palette mitigation search links directly to `/mitigations/{id}` (was broken `?id=` param)
  - Mitigation detail `triggering_event_id` links to events page with event auto-selected
  - Events page reads `?id=` param to auto-open detail panel
  - Mitigations page reads `?ip=` param to pre-fill search filter
  - Audit log `target_id` links to `/mitigations/{id}` when target_type is mitigation
  - Overview stat cards are clickable, linking to mitigations/events pages

### Security

- **`POST /v1/events` now requires authentication** - `ingest_event` handler was missing `require_auth()` call; direct API calls could bypass auth when enabled

### Fixed

- **Mitigation detail customer context crash** - Was accessing `inventory.inventory` instead of `inventory.customers` (correct API shape)
- **Missing `Check` icon import** on mitigation detail page caused runtime error on "Copy JSON"
- **IP validation on Mitigate Now form** - Replaced permissive regex with octet-validating function (rejects `999.1.1.1`, `256.0.0.1`)
- **ErrorBoundary no longer leaks internal error messages** - Raw `error.message` removed from UI, errors logged to console only
- **Admin health status badge** - Was checking for `"healthy"` but API returns `"ok"`, so the badge always showed destructive red
- **Dark mode hover on admin reload button** - Added explicit dark mode hover classes for proper contrast
- **Documentation sweep** - Fixed stale version strings, incorrect API field names, wrong endpoint paths, and missing changelog comparison links across api.md, deployment.md, AGENTS.md

## [0.8.3] - 2026-02-18

### Added

- **Config Page** - Read-only view of running daemon configuration
  - Settings tab with allowlist-redacted JSON view (sensitive fields never exposed)
  - Playbooks tab with escalation step visualization (action, rate, TTL, confidence thresholds)
  - Hot-reload button (triggers `POST /v1/config/reload`) with auto-clearing feedback
  - Gated behind `canReloadConfig` permission for admin users
- **Inventory Page** - Searchable customer/service/IP asset browser
  - Expandable customer cards with policy profile badges
  - Service listings with allowed port display (TCP/UDP)
  - Search covers customer ID, name, policy profile, service, IP, role, and port numbers
  - Stats bar showing total customers, services, and IPs
- **`GET /v1/health/detail`** - Authenticated health endpoint with full operational data
  - BGP session states, database status, GoBGP connectivity, uptime, active mitigations
  - Replaces the old public health endpoint for operational monitoring
- **`GET /v1/config/settings`** - Running config with allowlist redaction
- **`GET /v1/config/inventory`** - Customer/service/IP data with load timestamps
- **`GET /v1/config/playbooks`** - Playbook definitions with load timestamps
- **Auth-disabled indicator** - Sidebar shows "Auth disabled" badge when running with `auth: none`
- **Session expiry handling** - 401 responses trigger automatic redirect to login page
  - Debounced `prefixd:auth-expired` event (2s window) prevents redirect storms
  - SWR retries suppressed on 401 to avoid noisy retry loops

### Changed

- **Route guard architecture** - Auth guard moved from `DashboardLayout` component to `app/(dashboard)/layout.tsx` route group
  - All dashboard pages automatically protected; new pages added to the group are guarded by default
  - Login page remains outside the guard at `app/login/page.tsx`
- **Public health endpoint slimmed** - `GET /v1/health` now returns only `{status, version, auth_mode}`
  - No database or GoBGP calls (lightweight liveness check)
  - Reduces unauthenticated attack surface
- **Settings redaction switched to allowlist** - Only explicitly safe fields are exposed
  - Previously used denylist (new fields leaked by default)
  - Omits: TLS paths, LDAP/RADIUS configs, bearer token env vars, BGP passwords, gRPC endpoints, router ID, audit log path, safelist prefixes
- **`loaded_at` timestamps are now accurate** - Settings shows startup time, inventory/playbooks show actual load/reload time
  - Previously showed request time (`Utc::now()`) which was misleading
- **Login page redirects** - Already-authenticated users and auth:none users redirected to `/` instead of showing login form
- **prefixdctl** - `status` and `peers` commands now use `/v1/health/detail`
- **RwLock guards dropped early** - Inventory and playbooks handlers clone data and release locks before building JSON response
- **Route definitions deduplicated** - `create_router()` and `create_test_router()` now share `public_routes()`, `session_routes()`, `api_routes()`, and `common_layers()` helpers (eliminates ~80 lines of duplication)
- **OpenAPI spec updated** - All new endpoints (`health_detail`, `config/settings`, `config/inventory`, `config/playbooks`) registered with utoipa annotations and `PublicHealthResponse` schema
- **API documentation** - `docs/reference/api.md` updated with config endpoint documentation, example payloads, and health endpoint migration note
- **Integration test coverage** - 4 new tests: `health_detail` (validates full operational response), `config_settings` (verifies allowlist redaction of sensitive fields), `config_inventory`, `config_playbooks` (12 integration tests total, up from 8)

### Security

- Allowlist redaction prevents accidental exposure of new sensitive config fields
- Public health endpoint no longer exposes BGP peer IPs, database status, or mitigation counts
- Deny-by-default permission model: no permissions granted until both auth and health state resolve
- Frontend permissions derived from backend `auth_mode` field (not inferred from missing session)

## [0.8.2] - 2026-02-18

### Fixed

- **Dashboard BGP Status** - Health indicator now checks actual BGP peer session state (`established`) instead of just GoBGP gRPC connectivity (contributed by @bswinnerton)
- **Dashboard POP Selector** - POP dropdown in TopBar now loads dynamically from the backend API (contributed by @bswinnerton)
  - Replaced hardcoded POP list with `usePops()` and `useHealth()` hooks
  - Current POP from health endpoint used as default selection
- **`GET /v1/pops` Endpoint** - Current instance POP now always included in response (contributed by @bswinnerton)
  - Newly deployed POPs with no mitigations are no longer invisible to the API
- **Lab Setup** - Fixed unreliable lab networking and stale instructions
  - FRR lab now assigns deterministic IP to GoBGP (`--ip 172.30.30.10`)
  - Fixed FRR bgpd.conf peer address to match
  - Fixed stale `gobgp neighbor add` comment in cJunos lab (neighbor is pre-configured)
  - Removed orphaned `gobgp-cjunos.conf` (wrong AS/IPs, not referenced)
  - Fixed vJunos comment: works on AMD bare metal too, issue is nested virt not CPU vendor

### Added

- **Juniper cJunosEvolved FlowSpec Lab** - End-to-end verified with real Junos router
  - cJunosEvolved PTX10002-36QDD (Junos Evolved 25.4R1.13-EVO) containerlab topology
  - Full lifecycle tested: event ingestion → policy engine → GoBGP → Juniper inetflow.0
  - FlowSpec discard, rate-limit (police), multi-port rules, and TTL-based withdrawal confirmed
  - cJunos peers directly with prefixd docker-compose GoBGP (no separate lab GoBGP)
  - Documented vendor quirks: FlowSpec-only AFI-SAFI required, FXP0ADDR token, BGP license warning
  - Updated lab/README.md with cJunos quick start and troubleshooting
  - Added cJunosEvolved neighbor config to configs/gobgp.conf
- **Lab Test Script** - `lab/test-flowspec.sh` for automated end-to-end FlowSpec verification
  - Checks prefixd health, GoBGP, BGP neighbors, sends test event, verifies RIB
  - Optional `--withdraw` flag to test full announce/withdraw lifecycle
- **WebSocket Runtime URL** - WS connection now derived from `window.location` at runtime
  - No build-time env var needed; works behind any reverse proxy (nginx, caddy, etc.)
  - Removed `NEXT_PUBLIC_PREFIXD_WS` build arg from Dockerfile
- **Favicon** - Replaced Vercel placeholder with prefixd shield icon (dark/light mode PNGs + SVG)
- **Light/Dark Mode Toggle** - Dashboard now supports light mode with a theme toggle in the top bar
  - Uses `next-themes` with system preference detection
  - Defaults to dark mode, persists user preference
- **Nginx Reverse Proxy** - Single-origin deployment via nginx in docker-compose
  - All traffic (API, WebSocket, dashboard) served through port 80
  - No build-time URL configuration needed
  - WebSocket upgrade handled transparently
- **Grafana Dashboards** - Provisioned Grafana and Prometheus in docker-compose
  - Operations dashboard: active mitigations, BGP sessions, HTTP latency, reconciliation
  - Security dashboard: events by source/vector, guardrail rejections, escalations
  - Auto-provisioned datasource and dashboards on startup

### Changed

- Lab documentation rewritten to reflect cJunos as recommended Juniper test option
- vJunos-router documented as bare-metal only (cannot run in VMs per Juniper docs)
- Nokia SR Linux confirmed as lacking FlowSpec support (SR OS only)
- Removed Vercel Analytics (`@vercel/analytics`) - self-hosted tool shouldn't phone home
- Removed duplicate lowercase PR template (case collision on macOS/Windows)
- Docker Compose now uses nginx as single entrypoint (port 80) instead of exposing individual service ports
- CI security audit switched from manual `cargo-audit` install to `actions-rust-lang/audit@v1` (3 min faster)
- CORS origin is now configurable via `cors_origin` in `prefixd.yaml` (omit when behind a reverse proxy)
- Removed hardcoded `localhost:3000` CORS origin
- Architecture Decision Records (ADRs) added to `docs/adr/`

### Security

- Fixed `bytes` integer overflow in `BytesMut::reserve` (RUSTSEC-2026-0007, updated 1.11.0 → 1.11.1)
- Fixed `time` crate DoS via stack exhaustion (RUSTSEC-2026-0009, updated 0.3.45 → 0.3.47)

## [0.8.1] - 2026-02-01

### Fixed

- **Frontend API Proxy** - Dashboard now works on remote servers without hardcoded URLs
  - Added `/api/prefixd/[...path]` Next.js API route to proxy requests to backend
  - Removed `NEXT_PUBLIC_PREFIXD_API` build-time env var (was baked into bundle)
  - Added `PREFIXD_API` server-side env var for backend URL
  - Browser only talks to dashboard on port 3000, never directly to API

- **Session Table Schema** - Fixed `tower_sessions.session` table creation
  - Migration now creates correct schema/table name for `tower-sessions-sqlx-store`
  - Users no longer need to manually create the session table

- **Bun Lockfile** - Removed `--frozen-lockfile` from frontend Dockerfile
  - Fixes build failures on systems with different bun versions

- **Security** - Fixed Next.js DoS vulnerability via Image Optimizer (npm audit fix)

### Changed

- Removed obsolete `version: '3.8'` from docker-compose.yml
- Updated dependencies: tonic 0.14.3, clap 4.5.56, Radix UI components

## [0.8.0] - 2026-01-28

### Added

- **Three-Role RBAC System**
  - `viewer` role: read-only access to dashboard and API
  - `operator` role: can withdraw mitigations
  - `admin` role: full access including user management
  - `require_role()` RBAC helper with hierarchical permission checks
  - Operator CRUD API: `GET/POST /v1/operators`, `DELETE /v1/operators/{id}`, `PUT /v1/operators/{id}/password`
  - `AuthMode::Credentials` for session-based authentication
  - LDAP config placeholder struct for future implementation

- **User Management UI**
  - Admin page User Management section (admin only)
  - Create operator form with username, password, role selection
  - Delete operator with confirmation dialog (prevents self-delete)
  - Change password dialog (admin can change any, users can change own)
  - Role badges with color coding (admin=red, operator=blue, viewer=gray)
  - `usePermissions()` hook for frontend role checks
  - Admin nav link hidden for non-admin users
  - Withdraw button hidden for viewers in mitigation detail panel

- **Unified Detector Events API**
  - `POST /v1/events` now accepts `action` field: `"ban"` (default) or `"unban"`
  - Unban events find original event by `external_event_id` and withdraw mitigation
  - `raw_details` JSONB field for storing forensic data from detectors
  - Deterministic withdrawal via event correlation (no guessing by IP)

- **FastNetMon Integration**
  - `scripts/prefixd-fastnetmon.sh` notify script for FastNetMon Community
  - Computes stable `event_id` for idempotency and ban/unban matching
  - Auto-detects vector from attack details (UDP/SYN/ACK/ICMP)
  - `docs/how-to/detectors/fastnetmon.md` setup guide

- **API/Frontend Contract Fixes**
  - Health endpoint now returns `version`, `pop`, `uptime_seconds`
  - mTLS auth mode now works correctly (was returning 401)
  - Fixed `operator_id` payload names in withdraw/safelist API calls

- **Frontend Animations**
  - Detail panels slide in from right (150ms, ease-out)
  - Activity feed items with staggered entrance
  - Status badge pulse animation on active items
  - BGP status breathing animation when session UP
  - All animations respect `prefers-reduced-motion`
  - Custom webkit scrollbars matching theme

- **FRR FlowSpec Lab**
  - Containerlab topology with FRR 10.3.1 as FlowSpec receiver
  - Works on any Linux host (no nested virtualization required)
  - Full end-to-end testing: event ingestion → policy → GoBGP → FRR
  - Documented Juniper labs for Intel VMX users

- **GoBGP Connection Fix**
  - Call `connect()` on GoBGP announcer at startup
  - Fixed BGP showing "not connected" in dashboard

- **Docker Compose Integration**
  - prefixd now connects to GoBGP and PostgreSQL via service names
  - BGP mode changed from `mock` to `sidecar` for real FlowSpec

### Fixed

- `confidence` field type mismatch: changed from `f64` to `f32` to match PostgreSQL `REAL`
- Events API was returning 500 due to sqlx type deserialization error

### Changed

- Default mode changed to `enforced` for lab testing (was `dry-run`)
- Removed dual-router lab configs for simplicity
- Updated lab README with Intel VMX requirements for Juniper

---

## [0.7.0] - 2026-01-18

### Added

- **WebSocket Real-Time Updates**
  - WebSocket endpoint at `/v1/ws/feed` for live mitigation/event updates
  - Message types: MitigationCreated, MitigationUpdated, MitigationExpired, MitigationWithdrawn, EventIngested, ResyncRequired
  - Broadcast channel integration in handlers and reconciliation loop
  - Lag detection with ResyncRequired message for client cache invalidation

- **Session-Based Authentication**
  - Operators table with argon2 password hashing
  - PostgreSQL session store via tower-sessions-sqlx-store
  - Login/logout/me endpoints (`/v1/auth/login`, `/v1/auth/logout`, `/v1/auth/me`)
  - Hybrid auth model: session cookies for browser, bearer tokens for API/CLI
  - `prefixdctl operators create` command for seeding operators

- **Frontend Authentication & Real-Time**
  - Login page with form validation and error handling
  - `useAuth` hook with AuthProvider context (memoized per React best practices)
  - `useWebSocket` hook with reconnection, SWR cache invalidation
  - `RequireAuth` component for protected routes
  - `ConnectionStatus` indicator in top bar
  - `UserMenu` dropdown with logout

- **Observability**
  - `prefixd_config_reload_total` counter metric (success/error)
  - `prefixd_escalations_total` counter metric
  - `prefixd_db_row_parse_errors_total` counter metric (tracks corrupted DB rows)
  - HTTP metrics via middleware:
    - `prefixd_http_requests_total{method,route,status_class}` counter
    - `prefixd_http_request_duration_seconds{method,route,status_class}` histogram
    - `prefixd_http_in_flight_requests{method,route}` gauge
  - Database connectivity status in `/v1/health` endpoint
  - GoBGP connectivity status in `/v1/health` endpoint (now structured: `{status, error}`)
  - Health endpoint now returns `"degraded"` status on DB or GoBGP failure
  - Warning logs for FlowSpec path parse failures in reconciliation

- **Security**
  - Request body size limit (1MB) via tower-http
  - Fix SQL injection in `list_mitigations` queries (now uses parameterized queries)
  - Hybrid auth on all API routes (session OR bearer token)
  - Secure cookies configurable based on TLS presence

- **CORS Support**
  - CORS headers for dashboard cross-origin requests
  - Credentials support for session cookies

- **Reliability**
  - GoBGP gRPC timeout handling (10s connect, 30s request)
  - GoBGP retry with exponential backoff (3 retries, 100ms-400ms)

- **API Validation**
  - Reject unknown protocol values (was silently converting to None)
  - Require `rate_bps` for `police` action type
  - Improved error messages with valid options listed

- **CI/CD**
  - GitHub Actions workflow (`.github/workflows/ci.yml`)
    - Test job (unit + integration with testcontainers)
    - Lint job (cargo fmt, clippy)
    - Build job (release binary artifact)
    - Docker job (build and push to ghcr.io)
    - Security audit job (cargo-audit)

- **Testing**
  - Integration tests with testcontainers (8 tests)
    - Full event → mitigation flow
    - Mitigation withdrawal via API
    - Duplicate event TTL extension
    - Pagination queries
    - Safelist blocking
    - Migration verification
    - TTL expiry via reconciliation
    - Configuration hot-reload (inventory + playbooks)

- **DevOps**
  - Dependabot configuration for Cargo, GitHub Actions, and npm
  - Pre-commit hooks configuration (fmt, clippy, test)

- **Guardrails**
  - Max TTL enforcement via `guardrails.max_ttl_seconds` config
  - Min TTL enforcement via `guardrails.min_ttl_seconds` config

### Fixed

- **Frontend API Integration**
  - Fix API response unwrapping (mitigations/events return `{items, count}` wrapper)
  - Fix Stats type to match backend (`total_active` instead of `active_mitigations`)
  - Fix HealthResponse type to match backend (structured `bgp_sessions`, `gobgp` object)
  - Fix PopInfo type (`{pop, active_mitigations}` objects instead of strings)
  - Fix SWR cache invalidation keys in WebSocket hook
  - Fix status filter query param (comma-separated instead of repeated)

- **Startup validation** - `auth.mode=bearer` without token now fails fast at startup (was returning 500 on every request)

- IPv6 prefix validation uses proper `IpAddr` parsing (was using contains(':') heuristic)
- `compute_scope_hash()` now deduplicates ports before hashing for consistency
- Bearer token cached at startup (was reading env var on every request)
- `Mitigation::from_row` now returns `Result` with error logging (was silently defaulting on parse failures)
- List queries now skip corrupted rows instead of failing entirely (with metric + log)
- Guardrails TTL bounds now fall back to `timers.min/max_ttl_seconds` if not set in guardrails config

- IPv6 support in `is_safelisted()` - now handles both IPv4 and IPv6 prefixes
- `is_safelisted()` performance - uses PostgreSQL inet operators instead of loading all entries

### Changed

- **Pagination**
  - Added `MAX_PAGE_LIMIT` (1000) - requests for larger pages are clamped
  - `list_events` now returns `EventsListResponse` with `count` (consistency with mitigations)

- **API Response** (breaking for clients parsing `total`)
  - Renamed `total` to `count` in `MitigationsListResponse`
  - Clarifies this is page size, not total count

- **Health Response** (breaking for clients parsing `gobgp` as string)
  - `gobgp` field now returns `{status: string, error?: string}` object
  - `database` field unchanged (string) for backward compatibility

- **Code Quality**
  - Consolidated duplicate route registrations in `routes.rs`

- **PostgreSQL-only storage** (breaking change)
  - Removed SQLite support entirely (~800 lines removed)
  - Simplified `StorageConfig`: `driver` removed, `path` → `connection_string`
  - Extracted `RepositoryTrait` for testability
  - Added `MockRepository` for fast unit tests
  - Tests now use `MockRepository` instead of SQLite in-memory

### Removed

- SQLite storage driver and all related code
- `StorageDriver` enum from configuration
- `storage.driver` config option

---

## [0.6.0] - 2026-01-17

### Added

- **Security & Authentication**
  - mTLS authentication with client certificate verification (rustls 0.23)
  - Security headers: X-Content-Type-Options, X-Frame-Options, Cache-Control
  - 5 auth integration tests (bearer flows, security headers validation)

- **Documentation**
  - `docs/reference/configuration.md` - Complete YAML reference for all config options
  - `docs/how-to/deployment.md` - Docker, bare metal, GoBGP, router config, mTLS setup
  - `docs/how-to/troubleshooting.md` - Operational runbook with common issues
  - `docs/perf/benchmarks.md` - Performance analysis with optimization recommendations

- **Benchmark Suite** (criterion)
  - Inventory lookup benchmarks (hit/miss/is_owned)
  - Database operation benchmarks (insert/get/list/count)
  - Serialization benchmarks (JSON serialize/deserialize)
  - Scaling benchmarks (DB list, inventory lookup by size)
  - Results: ~6K events/sec throughput, sub-ms API queries

- **Frontend Polish**
  - Live activity feed (replaces mock data with real API)
  - Config page with system status, BGP session, quotas, safelist viewer
  - Loading states with spinners, error states with icons
  - Empty state handling throughout dashboard

- Comprehensive unit test suite (84 tests total)
  - Guardrails tests: prefix validation, TTL, port count, IPv6 detection (18 tests)
  - BGP/GoBGP tests: NLRI construction, path attributes, RFC constants (16 tests)
  - Repository tests: CRUD, queries, pagination, safelist, multi-POP (18 tests)
  - Policy engine tests: evaluation, port intersection, protocols, TTL (13 tests)
- Next.js frontend dashboard (`frontend/`)
  - Dashboard overview with live stats, BGP status, quota gauges
  - Mitigations list with filtering, sorting, pagination (live API)
  - Events list with filtering, sorting, pagination (live API)
  - Audit log viewer with filtering (live API)
  - Dark mode support, keyboard shortcuts, command palette
  - SWR for data fetching with 5s refresh interval
  - Follows Vercel React best practices (deferred analytics, parallel fetching)
- New API endpoints
  - `GET /v1/events` - list events with pagination
  - `GET /v1/audit` - list audit log entries with pagination
- Audit log database storage (in addition to file-based logging)
- Docker support for frontend
  - `frontend/Dockerfile` using oven/bun image
  - Dashboard service in docker-compose.yml (port 3000)
- Bun package manager for frontend (faster installs)

### Changed

- **2026 Stable Dependencies**
  - axum 0.7 → 0.8, tower 0.4 → 0.5, tower-http 0.5 → 0.6
  - tonic 0.11 → 0.14, prost 0.12 → 0.14
  - sqlx 0.7 → 0.8, reqwest 0.11 → 0.12
  - utoipa 4 → 5, prometheus 0.13 → 0.14, thiserror 1 → 2

### Fixed

- Security vulnerabilities: sqlx 0.7.4 (RUSTSEC-2024-0363), protobuf 2.28.0
- `list_mitigations_all_pops_sqlite` query using wrong column names

## [0.5.0] - 2026-01-16

### Added

- PostgreSQL backend support
  - Runtime-configurable storage driver (`storage.driver: postgres`)
  - PostgreSQL-specific migrations
  - Connection string support (`storage.path: "postgres://..."`)
- Docker deployment
  - Multi-stage Dockerfile for optimized builds
  - docker-compose.yml with prefixd, postgres, gobgp services
  - `configs/prefixd-postgres.yaml` example config
  - `configs/gobgp.conf` for FlowSpec BGP sidecar
  - `.dockerignore` for efficient builds

### Changed

- Repository refactored to support both SQLite and PostgreSQL
- `db::init_pool_from_config()` for runtime driver selection

## [0.4.0] - 2026-01-16

### Added

- `prefixdctl` CLI binary for controlling the daemon
  - `prefixdctl status` - show daemon health and BGP sessions
  - `prefixdctl mitigations list/get/withdraw` - manage mitigations
  - `prefixdctl safelist list/add/remove` - manage safelist
  - `prefixdctl peers` - show BGP peer status
  - `prefixdctl reload` - hot-reload configuration
  - Table and JSON output formats
  - Environment variable support (PREFIXD_API, PREFIXD_API_TOKEN)
- Configuration hot-reload via `POST /v1/config/reload`
  - Reloads inventory.yaml and playbooks.yaml without restart
  - Validates config before applying (fail-safe)
- Graceful shutdown improvements
  - Configurable drain timeout (default 30s)
  - Announcement preservation option (mitigations not withdrawn on shutdown)
  - Shutdown state tracking (new events return 503)
  - Enhanced shutdown logging with mitigation counts

### Changed

- AppState now uses RwLock for inventory and playbooks (hot-reload support)
- Event ingestion checks shutdown state before processing

## [0.3.0] - 2026-01-16

### Added

- Escalation logic for police → discard transitions
  - Persistence tracking (configurable min duration)
  - Confidence threshold checking
  - Policy profile support (strict blocks escalation)
  - Max escalated duration guard
- Event correlation engine
  - Exact scope matching for TTL extension
  - Port relationship detection (superset/subset/overlap/disjoint)
  - Smart action decisions (replace, keep, create parallel)
- Audit log writer (JSON Lines format)
  - Event ingestion logging
  - Mitigation lifecycle logging
  - Safelist change logging
  - Guardrail rejection logging
- Alerting webhooks
  - Slack integration with colored attachments
  - PagerDuty Events API v2 integration
  - Generic webhook support with custom headers
  - Alert severity levels (info, warning, critical)
- AGENTS.md for AI agent context

### Changed

- Policy module now exports escalation and correlation submodules
- Observability module includes audit and alerting

## [0.2.0] - 2026-01-16

### Added

- GoBGP gRPC client implementation
  - Full FlowSpec NLRI construction (destination prefix, protocol, ports)
  - Traffic-rate extended community for police/discard actions
  - AddPath/DeletePath for announce/withdraw
  - ListPath for active routes
  - ListPeer for session status
- Bearer token authentication middleware
  - Configurable via `PREFIXD_API_TOKEN` environment variable
  - Constant-time token comparison
- Token bucket rate limiter for API endpoints
- Prometheus metrics endpoint (`/metrics`)
  - `prefixd_events_ingested_total`
  - `prefixd_events_rejected_total`
  - `prefixd_mitigations_active`
  - `prefixd_mitigations_created_total`
  - `prefixd_mitigations_expired_total`
  - `prefixd_mitigations_withdrawn_total`
  - `prefixd_announcements_total`
  - `prefixd_announcements_latency_seconds`
  - `prefixd_bgp_session_up`
  - `prefixd_guardrail_rejections_total`
  - `prefixd_reconciliation_runs_total`

### Changed

- Health and metrics endpoints now public (no auth required)
- Protected routes require authentication when bearer mode enabled

## [0.1.0] - 2026-01-16

### Added

- Initial release of prefixd BGP FlowSpec routing policy daemon
- HTTP API for attack event ingestion (`POST /v1/events`)
- Mitigation management endpoints (`GET/POST /v1/mitigations`, withdraw)
- Safelist management (`GET/POST/DELETE /v1/safelist`)
- Health endpoint (`GET /v1/health`)
- Policy engine with YAML playbook configuration
- Support for attack vectors: `udp_flood`, `syn_flood`, `ack_flood`, `icmp_flood`, `unknown`
- Guardrails system:
  - TTL required on all mitigations
  - /32 destination prefix enforcement
  - Customer ownership validation
  - Safelist protection
  - Port count limits (max 8)
  - Quota enforcement (per-customer, per-POP, global)
- Mitigation lifecycle management:
  - States: pending, active, escalated, expired, withdrawn, rejected
  - Automatic TTL expiry
  - Scope-based deduplication
  - TTL extension on repeated events
- SQLite state store with sqlx (compile-time checked queries)
- FlowSpecAnnouncer trait abstraction:
  - MockAnnouncer for testing and dry-run mode
  - GoBgpAnnouncer stub for production (gRPC client pending)
- Reconciliation loop:
  - Periodic TTL expiry checks
  - Desired vs actual state synchronization
  - Re-announcement of missing rules
- Configuration system:
  - `prefixd.yaml` - daemon settings
  - `inventory.yaml` - customer/service/asset mapping
  - `playbooks.yaml` - vector-to-action policies
- Structured logging with tracing (JSON or pretty format)
- Dry-run mode for safe rollout
- Integration and unit tests

### Security

- No secrets logged or exposed in API responses
- Safelist prevents mitigation of protected infrastructure
- Guardrails block overly broad mitigations

[Unreleased]: https://github.com/lance0/prefixd/compare/v0.23.1...HEAD
[0.23.1]: https://github.com/lance0/prefixd/compare/v0.23.0...v0.23.1
[0.23.0]: https://github.com/lance0/prefixd/compare/v0.22.1...v0.23.0
[0.22.1]: https://github.com/lance0/prefixd/compare/v0.22.0...v0.22.1
[0.22.0]: https://github.com/lance0/prefixd/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/lance0/prefixd/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/lance0/prefixd/compare/v0.19.1...v0.20.0
[0.19.1]: https://github.com/lance0/prefixd/compare/v0.19.0...v0.19.1
[0.19.0]: https://github.com/lance0/prefixd/compare/v0.18.1...v0.19.0
[0.18.1]: https://github.com/lance0/prefixd/compare/v0.18.0...v0.18.1
[0.18.0]: https://github.com/lance0/prefixd/compare/v0.17.1...v0.18.0
[0.17.1]: https://github.com/lance0/prefixd/compare/v0.17.0...v0.17.1
[0.17.0]: https://github.com/lance0/prefixd/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/lance0/prefixd/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/lance0/prefixd/compare/v0.14.1...v0.15.0
[0.14.1]: https://github.com/lance0/prefixd/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/lance0/prefixd/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/lance0/prefixd/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/lance0/prefixd/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/lance0/prefixd/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/lance0/prefixd/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/lance0/prefixd/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/lance0/prefixd/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/lance0/prefixd/compare/v0.8.5...v0.9.0
[0.8.5]: https://github.com/lance0/prefixd/compare/v0.8.4...v0.8.5
[0.8.4]: https://github.com/lance0/prefixd/compare/v0.8.3...v0.8.4
[0.8.3]: https://github.com/lance0/prefixd/compare/v0.8.2...v0.8.3
[0.8.2]: https://github.com/lance0/prefixd/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/lance0/prefixd/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/lance0/prefixd/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/lance0/prefixd/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/lance0/prefixd/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/lance0/prefixd/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/lance0/prefixd/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/lance0/prefixd/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/lance0/prefixd/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lance0/prefixd/releases/tag/v0.1.0
