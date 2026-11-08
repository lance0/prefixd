# VPN FlowSpec controller core — 2026-11-08

This receipt covers IPv4 and IPv6 VPN origination through prefixd and rustbgpd,
with a software receiving peer. It does not qualify router installation,
RT import isolation or traffic enforcement. Marking and redirect-to-VRF are
separate action slices; complete five-action acceptance remains open.

## Versions and reproduction

The core runtime source is commit `4ebb867f2b73de126534ab3846121052f043731e`.
The CLI follow-up in this PR adds strict VPN diversion envelopes and fresh
scope-aware preview confirmation; its focused tests run separately below.

| Component | Pin |
| --- | --- |
| rustbgpd VPN contract | 0.82.0, source `608dcaea0902272474bd2a25bcf30bff3dd3153b`, image index `sha256:807dcb90c8d0234d5c0c39bdde62f8a2ee24a9525bcd60ca4c95c2773e56f609` |
| Global compatibility control | rustbgpd 0.81.0, source `eb1749d7018cd9691e4f4c9adef3b9adb830e9a8`, image index `sha256:f8a6d62ced049e415d702e31c43cbd6dac62fa9bcfdd0f410938f3c6cc418a64` |
| VPN receiving peer | GoBGP 4.11.0, source `53ceb78fe284018ce83a92f3039198f0a86dc823`, image `sha256:cddb09fba72ee2d64d216aaff08a2bed74844fce292b3bfcf6859bd8df39f0f0` |
| Existing global GoBGP backend | Pinned 4.10.0 fixture; unchanged production backend policy |
| Frontend tools | Node 26.12.0, Bun 1.4.3 |

The proto checksum asset is vendored from the 0.82.0 tag. `just proto` verifies
SHA-256 `8746bd8d17528c34c96e11fa769ab09dc4340cba55fe5ed014ac18400e8e5008`.
The global daemon floor remains 0.81.0. VPN authorization comes from a fresh
read-only family 13/14 probe, not the daemon's version string.

Run from the repository root with Docker and the documented toolchains:

```sh
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4 just gate
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4 just speakers
cargo test --locked --all-features --bin prefixdctl
```

The local gate passed formatting, Python, alert rules, proto, strict Clippy,
both Rust feature suites, PostgreSQL tests, all three MSRV configurations,
release build, frontend lint/typecheck/684 tests/production build and dependency
audits under the existing policy. Library totals were 617 without default
features and 682 with all features. The final CLI suite has 12 passing tests.
The gate then failed cargo-deny for unmaintained transitive dependencies
RUSTSEC-2026-0440 and RUSTSEC-2026-0441, independently reproduced on unchanged
main with the same lockfile. No dependency policy exception was added.
Speaker fixtures run separately because the gate stops at that failure.

## Acceptance evidence

| Requirement | Evidence | Boundary |
| --- | --- | --- |
| Global compatibility and separate VPN keys | `vpn_identity_golden_keys_separate_global_and_rds_without_rt_or_name`, `flowspec_identity_is_byte_for_byte_unchanged`, mock/backend and broad global suites | Legacy hashes/JSON remain unchanged; family and exact RD bytes distinguish VPN keys. RTs and display names are attributes, not identity. |
| Saved scope survives withdrawal and recovery | `vpn_withdrawal_freezes_scope_and_rt_snapshot`, `source_only_recovery_requires_policy_and_expiry_keeps_other_rd`, `automatic_family_defaults_snapshot_and_unban_original_scope_after_restart` | Controller tests cover frozen identity, expiry and automatic-default changes. They do not establish the full live three-key lease-expiry/restart matrix. |
| RT replacement and guarded revisions | `route_target_drift_repairs_only_the_saved_rd_and_preserves_global`, `raw_duplicate_scope_targets_replay_without_typed_twins`, released `guarded_vpn_scope_keeps_rd_targets_and_held_revision` | Both AFIs preserve exact scope RTs; guarded RT edits refuse under the held revision, then succeed after deletion/new revision. Stale deletion cannot remove the replacement. Complete live plain/leased REPLACED outcome coverage remains open. |
| Old daemon cannot mutate a global twin | Released `live_vpn_release_matrix_never_mutates_identical_global_keys` and `guarded_vpn_scope_keeps_rd_targets_and_held_revision`, run on both 0.81.0 and 0.82.0 | Both AFIs refuse plain/leased/guarded adds, deletes and ordinary export queries on 0.81.0 while preserving global payload/owner/generation. Lease remaining time may decrease but cannot renew. Required unsupported inventory fails instead of returning partial global rows. |
| Probe/retry errors stay truthful | `vpn_probe_refuses_before_mutation_and_is_not_cached_across_calls` | Mock gRPC fault controls distinguish unsupported family from authentication/transport failure and require fresh probes. |
| GoBGP controller backend refuses VPN | `vpn_is_refused_before_connecting_or_mutating_global_rules` | Typed refusal before RPC. GoBGP's separate receiving-peer role does not make its controller backend VPN-capable. |
| Exact software-peer receipt and withdrawal | Released `released_vpn_http_rules_reach_only_negotiated_peers_with_exact_scope` | HTTP admission through prefixd and rustbgpd 0.82.0 reaches GoBGP 4.11.0 with exact family/RD/RT/action. Eight VPN rules coexist with one global control; independent withdrawals preserve the control. A global-only peer receives no VPN rules. |
| Source-only and source+destination | Same wire test; `vpn_source_only_refuses_unsafe_scope_source_ttl_actions_and_confirmation`, `source_only_extension_keeps_short_ceiling_and_rechecks_source_safelist`, atomic PostgreSQL/mock quota tests | Both VPN AFIs cover discard/police. Source-only explicitly authorizes every destination in the VRF, including safelisted destinations; protects SOURCE; requires floor, short TTL, separate quota and confirmation. Omitted destination differs from explicit /0. |
| Automatic scope is operator-owned | Four `integration_vpn_scope` tests | String and explicit family-map defaults snapshot scope. Detectors cannot choose selectors; mismatches refuse instead of falling back. |
| Older controllers and changed confirmations fail closed | CLI tests `old_controller_acknowledgement_never_causes_unscoped_retry_or_creation`, `diversion_cli_refuses_missing_acknowledgements_changed_confirmation_and_http_errors`, transport-failure test; frontend VPN/guarded client tests | Dedicated endpoints and acknowledged previews; no global retry. Guarded confirmation binds scope RTs. |
| Documentation/operator visibility | [Procedure](../../how-to/vpn-flowspec.md), API/CLI/config/backend/upgrade references, example, changelog and roadmap | Display distinguishes family/RD/RT. Metrics have four bounded family labels and represent desired intent, not installed rules. |

The focused released matrix passed all four runs: ordinary and guarded tests
on 0.81.0 and 0.82.0, each covering VPNv4 and VPNv6. Full speaker sweep results
are recorded with the PR's validation status rather than inferred from ignored
tests in the normal Rust gate.

## Negative controls and limits

Removing RD bytes from the production identity hash makes the golden-key test
fail; restoring the bytes makes it pass. Removing either the RD or typed RT
field from foreign-inventory normalization independently makes
`foreign_match_never_normalizes_scoped_fields_into_global_occupancy` fail;
both fields restored pass. The first family-map integration run also failed
against the unfixed automatic caller, then passed after that caller selected
the victim's family. These are retained failing controls, not passing fixtures.
Other identity/lifecycle cases have positive regression coverage; a complete
fix-removal matrix remains open.

The receiving peer proves received BGP routes only. It does not create VRFs,
exercise import policy, install forwarding filters or send attack traffic.
IPv6 uses offset-zero CIDRs; nonzero offsets remain outside prefixd's model.
Destination-less receiver validation under RFC 8955/9117 is platform-specific.
The ASR9901 pilot must qualify source-only acceptance and each action separately.
Guarded redirect-to-IP has controller/released-speaker coverage here; its peer
wire receipt, marking and redirect-to-VRF remain subsequent action qualification.
