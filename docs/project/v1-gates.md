# v1.0 release gates

prefixd 1.0 ships when the five gates below are met. Each gate names its owner,
the evidence it requires and its current status. Work outside these gates is
not a 1.0 dependency. Every release, including 1.0, also follows the
[release checklist](release-checklist.md); gate 5 relies on it rather than
repeating it.

A gate is met only when every required item links to evidence: a dated receipt,
a CI run, a published release or the source that implements it. A checkbox or a
plan is not evidence. Failed and superseded runs stay recorded with their
limits. Controller tests, speaker read-back, router receipt and traffic
enforcement are separate claims, and no item here treats one as another.

## Status

Status as of 2026-11-14. No gate is met.

| Gate | Owner | Status | Next action |
| --- | --- | --- | --- |
| [1. Compatibility](#1-compatibility) | maintainer | Partial | 2026-11-14: write the promise for each surface not yet covered. |
| [2. Lifecycle and security](#2-lifecycle-and-security) | maintainer | Partial | 2026-11-14: map each behavior and failure case to its tests and receipts, and list the gaps. |
| [3. Router evidence](#3-router-evidence) | maintainer | Partial | 2026-11-14: choose the exact deployment to qualify, including a router that enforces FlowSpec. |
| [4. Operator experience](#4-operator-experience) | maintainer | Partial | 2026-11-14: record a cold-environment install and an attack-to-recovery run on the default speaker. |
| [5. Release readiness](#5-release-readiness) | maintainer | Partial | 2026-11-14: define the operating limits to measure and the command that measures each. |

Statuses are **Not started**, **Partial** (some evidence exists, but not all
that the gate requires) and **Met**. Update this table and the gate's section
in the same change that adds or retires its evidence.

## 1. Compatibility

Define what each public surface promises at 1.0 and from when.

**Evidence required:**

- A written promise for each surface: the HTTP API and its OpenAPI document,
  configuration files and keys, `prefixdctl` commands and `--format json`
  output, detector event input and WebSocket messages, and Prometheus metric
  names and labels. Each states what a minor release can change, what needs a
  major release, and the deprecation process.
- The API versioning policy and the README agree; see
  [API stability conflict](#api-stability-conflict).
- The freeze point: from the first `1.0.0-rc.N` release, these surfaces take no
  breaking change. A breaking change found necessary after that ships in a new
  release candidate, under that release's Upgrade notes.
- Tests that hold the frozen shape where a test can, such as route and OpenAPI
  parity.

**Existing evidence:**

- [API versioning policy](../reference/api-versioning.md): the HTTP compatibility
  and deprecation rules, and a pointer to the pre-1.0 rule below. It covers no
  other surface.
- `openapi_documents_every_v1_route` in
  [`src/api/openapi.rs`](../../src/api/openapi.rs) fails when a `/v1/` route has
  no OpenAPI entry.
- The [release checklist](release-checklist.md#changelog-section) requires a
  CHANGELOG entry for every change to configuration, API JSON, WebSocket
  messages, CLI output, metrics and log fields, with operator action under
  Upgrade notes.

**Status:** Partial. The HTTP policy exists, and the rule below reconciles it
with the README. Configuration, CLI, event, WebSocket and metric promises are
not written.

**Next action (2026-11-14):** write the promise for each surface not yet
covered.

### API stability conflict

The two pages disagreed about the API:

- The [API versioning policy](../reference/api-versioning.md#current-status)
  marks v1 **Stable**, and its compatibility rules say removing or renaming a field needs a new major
  version.
- The [README](../../README.md) status says prefixd is pre-1.0 and the API can
  change before 1.0.

Releases have followed the README. v0.17.0 removed a field under `/v1/`
(see the [API reference](../reference/api.md)), cursor pagination removed the
`offset` parameter ([ADR 016](../adr/016-cursor-pagination.md)), and the
unreleased playbook change rejects keys that `PUT /v1/config/playbooks` used to
ignore ([changelog](../../CHANGELOG.md)).

**Resolution rule:** until 1.0.0, the README governs. `/v1/` is the URL
version, not a freeze. A minor release can make a breaking change under `/v1/`
when its CHANGELOG lists the change under Upgrade notes and the API reference
marks it. From 1.0.0, the API versioning policy applies in full: a breaking
change needs a new major API version, and removals follow its deprecation
process.

## 2. Lifecycle and security

Demonstrate the mitigation lifecycle, including its failure cases, on the
deployment that gate 3 qualifies.

**Evidence required:**

- **Admission:** accepted requests, and rejection by each guardrail: safelist,
  prefix length, ports, TTL, quotas and source matching.
- **Expiry:** TTL withdrawal by the running controller, and the documented
  behavior while the controller is stopped and the speaker stays up.
- **Withdrawal and retry:** a failed withdrawal keeps its original rule, actor,
  reason and operation ID, and the retry uses them. Ambiguous deletion never
  becomes a fresh announcement.
- **Restart and reconciliation:** controller and speaker restarts restore
  intent and repair missing rules. Unknown and foreign-POP rules stay untouched,
  and a failed or partial inventory never counts as an empty RIB.
- **Upgrade:** previous release to candidate with outstanding intent, and the
  documented downgrade refusals.
- **Security:** authorization denies by default, secrets stay out of logs,
  errors and responses, and speaker transports authenticate.
- A dated table maps each item above to the tests and receipts that cover it.

**Existing evidence:**

- Controller integration tests against disposable PostgreSQL:
  [admission](../../tests/integration_admission.rs),
  [expiry caps](../../tests/integration_expiry_cap.rs),
  [lifetime changes](../../tests/integration_lifetime.rs),
  [controller fence](../../tests/integration_fence.rs) and
  [repository and withdrawal storage](../../tests/integration_postgres.rs).
- Released-speaker suites in [CI](../../.github/workflows/ci.yml):
  [rustbgpd](../../tests/integration_rustbgpd.rs) TTL, restart recovery and
  secure transports, and [GoBGP](../../tests/integration_gobgp.rs). See
  [released controller qualification](../reference/speaker-backends.md#released-controller-qualification).
- [Withdrawal recovery](../reference/speaker-backends.md#withdrawal-recovery)
  documents the retained-intent contract.
- The [speaker profile qualification](../reference/qualification/speaker-profiles-2026-10-18.md)
  of 2026-10-18 covers login, protected health, exact local rules, withdrawal
  audit and recreation for both profiles, at the versions it names.
- The [upgrade guide](../how-to/upgrading.md) and the upgrade proof that each
  release PR records; see gate 4.

**Status:** Partial. Most behaviors have controller tests, and the profile
qualification is dated 2026-10-18 against older versions. No current
demonstration maps every behavior and failure case to evidence.

**Next action (2026-11-14):** build the coverage table and list the behaviors
with no test or receipt.

## 3. Router evidence

Qualify at least one exact deployment for the core advertised behavior, and
label every other combination individually.

**Evidence required:**

- One exact deployment: prefixd version, speaker and version, router platform
  and software version, address families and actions.
- A dated receipt on that deployment showing that the router accepted and
  enforced discard and policing rules, removed them on withdrawal and expiry,
  and regained them after reconciliation. Enforcement means an installed filter
  or a measured traffic effect, not BGP receipt alone.
- Every other speaker, router and action combination in
  [vendor compatibility](../reference/vendors.md) carries its own label, such as
  verified, control plane only, expected or not supported, with its receipt and
  date.

**Existing evidence:**

- The [Interop workflow](../../.github/workflows/interop.yml) runs FlowSpec,
  blackhole and amplification scenarios against FRR 10.7.1 with rustbgpd 0.81.0
  and GoBGP on every change to runtime paths and nightly. Its receipts check
  FRR's received rules, and for blackholes its zebra and kernel discard state.
  [Run 43631309138](https://github.com/lance0/prefixd/actions/runs/43631309138)
  passed all five legs on `main` on 2026-11-14.
- [FRR receipts](../reference/vendors.md#frr--verified-control-plane) and the
  [amplification](../reference/qualification/amplification-frr-2026-10-19.md),
  [blackhole](../reference/qualification/blackhole-frr-2026-10-19.md) and
  [RPKI blackhole](../reference/qualification/blackhole-rpki-frr-2026-10-20.md)
  receipts, each with its versions and limits.
- Juniper and Arista results in [vendor compatibility](../reference/vendors.md)
  used GoBGP, not the default rustbgpd speaker.

**Status:** Partial. FRR evidence is control plane only, and FRR installed none
of the amplification rules as filters. No deployment has a forwarding or
enforcement receipt for the core behavior.

**Next action (2026-11-14):** choose the deployment to qualify, including a
router that enforces FlowSpec, and the receipt format for enforcement.

## 4. Operator experience

Verify that an operator can install, sign in, run a mitigation from attack to
recovery and upgrade.

**Evidence required:**

- A fresh install from the published release in a cold environment, following
  the [quickstart](../tutorials/quickstart.md) as written, with its timing.
- Authentication: operator creation, sign-in, roles and bearer access.
- One recorded run from attack to recovery on the default speaker: a detector
  signal, the resulting mitigation and its evidence in the dashboard, expiry or
  confirmed withdrawal, and the audit trail.
- An upgrade from the previous release that follows the
  [upgrade guide](../how-to/upgrading.md) and the release checklist's upgrade
  proof.

**Existing evidence:**

- CI's [browser smoke](../../scripts/test-browser.py) signs in, opens an active
  mitigation, confirms its withdrawal and checks the persisted and rendered
  audit, against disposable PostgreSQL and pinned rustbgpd.
- The [manual mitigation recipe](../cookbook/manual-mitigation.md) and its
  evidence in the [cookbook index](../cookbook/README.md).
- The v0.25.0 to v0.26.0 upgrade proof in the
  [v0.26.0 release PR](https://github.com/lance0/prefixd/pull/417): migrations,
  health, the first reconciliation, mitigation IDs and both RIBs unchanged.

**Status:** Partial. The profile qualification marks the cold quickstart
unqualified, and the quickstart pulls the `main` build rather than a release.
Detector flows have no end-to-end receipt, and no attack-to-recovery run is
recorded.

**Next action (2026-11-14):** record a cold-environment install and an
attack-to-recovery run on the default speaker.

## 5. Release readiness

Ship 1.0 through the existing release process, verify what it publishes and
state measured limits.

**Evidence required:**

- The 1.0.0 release PR passes every item in the
  [release checklist](release-checklist.md), including `just gate`, the speaker
  fixture pins and the upgrade proof.
- The release run's install contract passes on the published assets and
  images, and the image digests match the release.
- Published operating limits, each measured with a dated command, its inputs
  and a retained receipt: for example active rules per speaker, event
  ingestion rate, reconciliation time and recovery after a restart.

**Existing evidence:**

- The [release checklist](release-checklist.md) and the
  [release workflow](../../.github/workflows/release.yml), with its
  [install contract](../../.github/workflows/release-install-contract.yml).
- v0.26.0 shipped through that process; its
  [release run](https://github.com/lance0/prefixd/actions/runs/43330064487)
  passed every job, including the install contract.
- The [benchmark snapshot](../perf/benchmarks.md) is a historical v0.15.0
  report and is not a current measurement.

**Status:** Partial. The release process and artifact verification run on
every release. No current operating limit is measured or published.

**Next action (2026-11-14):** define the operating limits to measure and the
command that measures each.
