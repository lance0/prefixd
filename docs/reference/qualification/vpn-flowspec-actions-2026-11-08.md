# VPN FlowSpec actions and recovery — 2026-11-08

This receipt extends the [core receipt](vpn-flowspec-core-2026-11-08.md).
The runtime source is `7a917ae4f0c12c385fc71e344f79b1c3eb7d3ef9`.
It establishes controller behavior and received software-peer routes, not
router installation, VRF import isolation or traffic enforcement.

## Pinned setup

| Component | Version and identity |
| --- | --- |
| rustbgpd | 0.82.0, source `608dcaea0902272474bd2a25bcf30bff3dd3153b`, image index `sha256:807dcb90c8d0234d5c0c39bdde62f8a2ee24a9525bcd60ca4c95c2773e56f609` |
| Negative control speaker | Pinned rustbgpd 0.81.0 from the fixture manifest; global minimum remains 0.81.0 |
| Receiving peer | GoBGP 4.11.0, source `53ceb78fe284018ce83a92f3039198f0a86dc823`, image `sha256:cddb09fba72ee2d64d216aaff08a2bed74844fce292b3bfcf6859bd8df39f0f0` |
| Topology | Owned speaker, VPN-negotiating receiver and global-only receiver; isolated PostgreSQL and an authenticated HTTPS readiness fixture |
| Driver | Real API authentication/session, arm, preview, confirmation, admission, read-back and withdrawal through the test router; production reconciliation for database recovery |

The [retained receiver attributes](vpn-flowspec-actions-2026-11-08-wire.json)
contain 18 snapshots and 71 route observations. Hex strings losslessly encode
GoBGP Adj-In `pattrs_binary`, including serialized BGP attribute headers and
MP_REACH NLRI. This is receiver API evidence, not a packet capture. The independent
oracle also checks typed NLRI, RD, source, destination, protocol and ports; it
does not derive expected action bytes from prefixd's encoder.

## Results

| Acceptance | IPv4 VPN / family 13 | IPv6 VPN / family 14 | Evidence and limit |
| --- | --- | --- | --- |
| Discard | PASS | PASS | Authenticated HTTP admission, exact `0x8006` zero-rate action, received scoped route and independent withdrawal |
| Police | PASS | PASS | 8 Mbps request, exact 1,000,000 bytes/s rate, scope RTs and withdrawal |
| Mark | PASS | PASS | DSCP 46 through HTTP/peer path; released plain/leased matrices additionally cover DSCP 0 and 63, invalid parameters and exact read-back |
| Redirect-to-IP | PASS | PASS | Guarded HTTP preview/confirmation/arm path; IPv4 eight-byte action and IPv6 RFC 5701 twenty-byte action are checked independently |
| Redirect-to-VRF | PASS | PASS | Guarded configured RT `44407:888`, distinct from scope RTs; separate released tests exercise AS2, IPv4-administrator and AS4 forms |
| Source plus destination | PASS | PASS | All five actions use explicit source and destination components, TCP and destination port 443 |
| Source-only | PASS in core receipt | PASS in core receipt | Discard/police only, destination omitted; explicit whole-VRF/source opt-in, source protection, short TTL and quota remain required |
| Global isolation | PASS | PASS | Same-match global/RD-A/RD-B coexistence, targeted deletion and selective owner lease expiry; the action test keeps a global control and a global-only peer |
| RT replacement and guarded revisions | PASS | PASS | Plain/same-owner leased RT replacement verified by state; held guarded payload changes refuse until delete/new revision, and stale deletion refuses |
| Speaker restart replay | PASS | PASS | Exact saved typed snapshots replay after real speaker restart; fresh incarnation observed. This test's snapshots are in memory. |
| PostgreSQL/controller recovery | PASS | PASS | Six HTTP-created rows, original controller/router/client references dropped, speaker restarted, fresh repository/controller, changed B defaults, startup probes and production reconciliation restore exact saved global/A/B payloads. Saved-A withdrawal preserves B/global and the stored target/rule/actor/reason. This is controller-state reconstruction, not process-kill/soak qualification. |
| Older speaker | PASS refusal | PASS refusal | 0.81.0 rejects required families/startup while PostgreSQL/global speaker controls remain unchanged; no global retry |

The five-action run with periodic readiness passed in 50.17 seconds. Its owned
scrubber worker uses the production five-second cadence and four-second pass
budget, with missed ticks skipped. A nine-second pause exceeds the HTTPS
monitor's eight-second report lifetime; authenticated refreshes keep all four
profiles ready and armed and all four original guarded intents active. The
worker stays alive throughout peer polling and pending-window drain, then
aborts and joins before HTTPS monitor and peer teardown.

Each guarded withdrawal reads a held lease above 11 seconds inside one 10-second
budget covering that read, the HTTP withdrawal and peer absence. Lease expiry
therefore cannot satisfy the withdrawal proof. The test waits for pending-window
drain and final exact local absence; the core delayed-add/barrier tests supply
the lower-bound exclusion checks. A successful
manual withdrawal preserves healthy profile arming; failures still latch.
The HTTPS fixture verifies authentication and readiness gates; its asserted
canary/readiness values do not prove a real scrubbing path.

The three-key replacement/expiry/restart run passed in 21.21 seconds on 0.82.0;
the 0.81.0 refusal branch passed separately. Both released versions also passed
the PostgreSQL recovery test (2.16 seconds on 0.82.0 and 1.96 seconds on 0.81.0). The writer API returns no replacement outcome enum,
so those assertions establish state replacement rather than exposing `REPLACED`.
The expiry wait requires RD A to disappear from the daemon's raw received view,
while RD B retains its exact payload and owner generation with a positive lease
and the raw unleased global control remains unchanged. Normalized inventory
alone hides zero-remaining leases; the earlier 21.04-second run is diagnostic
for daemon removal. The fixed lease and expiry deadline are unchanged.

## Controls and reproduction

Retained production fix-removal controls fail, then pass after byte restoration:

- Removing RD bytes breaks the identity golden test.
- Dropping the snapshot-to-NLRI scope mapping yields the global hash for RD-A.
- Removing either RD or typed RT fields from foreign normalization independently
  breaks the no-global-occupancy regression.
- Removing the probe loop fails the probe-count assertion (`0` versus `3`). That
  negative run stops at the count check; the restored positive run exercises the
  later refusal, transport/authentication and mutation-count assertions.

The first marking gate also caught historical invalid actions blocking exact
withdrawal. Add-only action validation and scoped cleanup coverage fix that
regression. The first full wire attempt was INVALID because its test expected a
healthy manual withdrawal to unarm the profile; the existing controller preserves
arming. The corrected test asserts both healthy arming and pending-window state,
without increasing deadlines or relaxing lease preconditions. Evidence review
then tightened the budget to include the held-rule read and HTTP request as well
as peer removal; the earlier 43.06-second run remains diagnostic for that timing
claim. Review also found that manual lifecycle ticks left the earlier
42.39-second run unable to establish readiness continuity across a slow peer
read. The periodic worker and nine-second survival control resolve that fixture
gap; the earlier run remains diagnostic for readiness continuity. Report TTLs,
pass budgets, withdrawal deadlines and held-lease preconditions are unchanged.
The initial database recovery assertion similarly omitted the API's existing
actor prefix; the corrected check requires the full reason and actor fields. Failed receipts were retained.

Runtime review also bounded VPN capability probes by the existing guarded RPC
deadline and normalized dashboard destination whitespace before submission.
Separate focused tests cover stalled probes and padded IPv4/IPv6 input. The live
action receipt uses responsive local speakers and valid HTTP payloads; it does
not measure stalled-probe latency or frontend behavior. Historical invalid-action
cleanup also has separate key-only withdrawal coverage; the five-action fixture
uses valid admitted action payloads.

Use Docker and the repository's pinned toolchains:

```sh
PREFIXD_RUSTBGPD_TEST_VERSION=0.81.0 scripts/test-rustbgpd.sh
PREFIXD_RUSTBGPD_TEST_VERSION=0.82.0 scripts/test-rustbgpd.sh
```

For focused runs, the ignored test names are
`released_vpn_five_actions_use_authenticated_admission_and_exact_peer_bytes`,
`live_vpn_three_key_replacement_expiry_and_restart_preserve_scope`, and
`released_vpn_postgres_fresh_controller_recovers_saved_scopes_and_withdraws_original_a`.
The binary oracle's unit controls reject malformed attributes, duplicate types,
missing binary data, wrong actions and wrong RTs. IPv6 prefix offsets are zero.

Local runtime gates passed both Rust feature suites, PostgreSQL, strict lint,
MSRV, release build and frontend checks; the updated stack has 697 frontend tests.
Cargo-deny fails on RUSTSEC-2026-0440/0441 on unchanged main and this stack; no new
exception was added. Qualification PR checks and review state must be read on
its actual head; this receipt does not assert hosted CI or review approval.

The ASR9901 pilot still needs platform/release/action-specific acceptance,
installation, wrong-RT isolation, traffic effect and restoration evidence.
Destination-less validation under RFC 8955/9117 is platform-specific. Marking and
redirects on source-only rules remain refused. No VRFs are created by prefixd.
