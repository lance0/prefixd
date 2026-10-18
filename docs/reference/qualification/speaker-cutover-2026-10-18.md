# Speaker maintenance qualification — 2026-10-18

The [maintenance procedure](../../how-to/speaker-cutover.md) passed one real
GoBGP→rustbgpd→GoBGP cycle for each pinned rustbgpd release below. This is a
small control-plane qualification with a mitigation gap, not seamless migration
or router forwarding evidence.

## Measured inputs

The controller source base was `55351a5e113476cf926d66a9c99dcb58a7a54148`,
with the new maintenance test and guide. The later minimum-compiler metadata and
equivalent fixture-readiness syntax change are qualified separately; these runs
do not establish a future PR or main result.

- Rust compiler: 1.99.1; Linux x86_64, CPUs 32–63, three Cargo build jobs.
- PostgreSQL: 16.15, disposable `postgres:16-alpine` fixture. This database tag is
  mutable; the observed server version is recorded here.
- GoBGP: 4.10.0,
  `jauderho/gobgp@sha256:42b8d0017237e388c55936efe1f23632365b24a31751f6e8815f93e12c4d18c2`.
- rustbgpd 0.76.0: source `c4824ad930711eb9f5dd60de48ab7b7166aa653b`,
  image digest `sha256:5c14434416d951a3293e44197ef9272fd2634dec3a040940a29df340d5b5e53a`.
- rustbgpd 0.77.0: source `77fb3ef14b3724a8faa84258930ead80cf2c5291`,
  image digest `sha256:6dbfa42c47aa1d063f119f3eff9524aac4585665c0a9c79167ec8d20244bc6c2`.

Both speakers use separate containers on one uniquely owned bridge. BGP179 is
internal; only authenticated RPC reaches ephemeral host-loopback ports. The
fixture inspects actual addresses/publications and removes its own resources.
It does not use the production Compose profile or UID999 deployment.

## Checks and results

| rustbgpd | Result | Single test duration |
| --- | --- | --- |
| 0.76.0 | Pass, 1 case | 33.92 s |
| 0.77.0 | Pass, 1 case | 34.18 s |

Durations describe these individual runs and are not a recovery-time guarantee.
Each case exercises:

- Authenticated API creation/withdrawal, with anonymous rejection and audit actor
  derived from authentication rather than a supplied operator name.
- Four exact host rules: IPv4/IPv6 × discard/8 Mbps police, UDP ports53/123.
- A complete seven-row source snapshot, including expired/below-minimum cases and
  an Active row with a pre-existing pending cancellation. ID and canonical-rule
  checks exclude that cancellation from recreation and rollback.
- Source drain and immutable pending-cleanup recovery, verified on the original
  local RIB and receiving peer before the actual documented target-transfer SQL.
- Two target transfers and their audits; eight new-ID mapping entries across
  forward migration and rollback, without extending original absolute expiries.
  Flooring remaining TTL can make a recreated deadline slightly earlier.
- Successful Add/Delete reply loss, fsynced request/response/mapping journal,
  quiet resumption/reconciliation and preserved original history/unknown intent.
- Terminal mapping recovery and a stop-without-retry control when a lost new ID
  cannot be resolved from a mutable reason marker.

Raw GoBGP Adj-RIB-In contains the four owned received rules **and** the preserved
unknown rule reflected Go→Rust→Go. The latter has AS_PATH `[64512,65010]` and is
absent from GoBGP's accepted global RIB, which retains its original local path.
Independent raw assertions check that distinction and that all four owned paths
are best accepted global routes from AS64512. Adj-RIB-In receipt is not accepted
intent or enforcement.

## Reproduce and retain evidence

From the repository root, with Docker available:

```bash
RUSTUP_AUTO_INSTALL=0 CARGO_BUILD_JOBS=3 PREFIXD_TEST_CPUSET=32-63 \
  PREFIXD_RUSTBGPD_TEST_VERSION=0.77.0 \
  taskset -c 32-63 scripts/test-speaker-cutover.sh
RUSTUP_AUTO_INSTALL=0 CARGO_BUILD_JOBS=3 PREFIXD_TEST_CPUSET=32-63 \
  PREFIXD_RUSTBGPD_TEST_VERSION=0.76.0 \
  taskset -c 32-63 scripts/test-speaker-cutover.sh
```

The runner prints its retained artifact directory. Each successful run keeps
three raw complete snapshots and hashes, the fsynced journal and an unresolved
marker control journal. CI runs the case in both released-speaker lanes and
retains logs and generated artifacts even on failure. Preserve a failed run and
diagnose it before another attempt.

Measured source hashes:

| File | SHA256 |
| --- | --- |
| `tests/integration_speaker_cutover.rs` | `45b533014f2960d76eb579bb430b5f23701f03504009ed6058e66640b4679a48` |
| `scripts/test-speaker-cutover.sh` | `7c0eb8e24d0183675e3f444820db6f950c401cace6ea490822628639f95e6c3e` |
| `docs/how-to/speaker-cutover.md` | `cfd7badc9a9950bafea39a12d0ac17bb0f846aed7365f3c04b32fd81248b5598` |

Measured raw artifact hashes:

| rustbgpd | Artifact | SHA256 |
| --- | --- | --- |
| 0.76.0 | `go-source.json` | `80092f6aedd502ceac61f1053117f5f430553a591b41e0511a8e29ffa85b944c` |
| 0.76.0 | `rust-source.json` | `fcdd53dba336f1f3bffbcb96c27d27ff7fb96fc0f7946f9ffb12cb0f32a28f83` |
| 0.76.0 | `rollback-source.json` | `ab53f611c4963e71f3a25ee2e374f2fff94479b076ba04f8313726cf87ea8ba8` |
| 0.76.0 | `journal.jsonl` | `0a172a71017a3e26094f59f40f0de655cf5a229383ad77c2f1287331f735bafe` |
| 0.76.0 | `unresolved-journal.jsonl` | `57fe9ea3958ed820df369bb0832a3af2f3f1c93134036fa69fdc5ab537ed2128` |
| 0.77.0 | `go-source.json` | `4e2d9191e23ceb864e70c37ff86e34a36f0d568d5321fd05022f85a7151794f6` |
| 0.77.0 | `rust-source.json` | `69edd21a06a7cb64e8e965e3912a0f8cce6aa49da79073149566507fb040146d` |
| 0.77.0 | `rollback-source.json` | `72e92cc131bfa41fab4120aa00ed5826154660aa72cce0f193d967239b478ce8` |
| 0.77.0 | `journal.jsonl` | `249a3af2e74bf3576bf02e745ca1326b3da0aa430922424324cfd63b960b1798` |
| 0.77.0 | `unresolved-journal.jsonl` | `426333e2db39dc2d2e17e0ade848d84905912e4012664a918e29f540c1a75380` |

## Earlier attempts and limits

The first compile was interrupted before the test or containers ran, when the
previous peer fixture's host-port isolation issue was found. Its exit143 log
remains retained and is not a runtime result.

The first actual 0.77 run failed after44.16s at a raw received-set assertion.
A diagnostic run failed after44.05s with the original ten-second oracle
unchanged. It established actual cardinality5 versus expected4: all four owned
rules arrived, plus the reflected unknown rule described above. The correction
expects the complete observed set and adds raw provenance/global-RIB assertions;
it does not filter results, delete unknown state or increase the deadline.
Both failures remain failures, not convergence passes.

Evidence covers real PostgreSQL, actual adapter RPCs and local/received RIBs.
Controller interruptions reconstruct AppState and the HTTP router logically;
they are not OS-process-kill or crash-consistency proof. Vendor forwarding,
ExaBGP, a full announcement ledger, multi-controller fencing, remote restart
epochs and zero-downtime migration are outside this qualification.
