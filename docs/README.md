# prefixd documentation

Find the guide, reference or evidence for the task at hand.

Pages keep their own scope. Local controller tests and dated profile receipts
cover prefixd and its speaker; they don't establish router enforcement. prefixd's
preferred speaker is [rustbgpd](https://github.com/lance0/rustbgpd); its own
[documentation](https://github.com/lance0/rustbgpd/blob/main/docs/README.md)
covers the daemon.

## Contents

[Start by task](#start-by-task) · [Tutorials](#tutorials) · [Cookbook](#cookbook) ·
[How-to](#how-to) · [Reference](#reference) · [Explanation](#explanation) ·
[Evidence](#evidence) · [Project](#project)

## Start by task

| I want to… | Read this |
|------------|-----------|
| Run prefixd and rustbgpd on my machine | [Quickstart](tutorials/quickstart.md) |
| Mitigate a target by hand and withdraw it | [Manual mitigation and withdrawal](cookbook/manual-mitigation.md) |
| Keep an existing FlowSpec rule for longer | [Extend a mitigation](how-to/extending-mitigations.md) |
| See what policy would do before it announces | [Dry-run rollout](cookbook/dry-run-rollout.md) |
| Connect FastNetMon | [FastNetMon](how-to/detectors/fastnetmon.md) |
| Connect a detector without a native adapter | [Generic webhooks](how-to/detectors/generic-webhook.md) |
| Add supporting telemetry to correlation | [Corroborating signals](how-to/detectors/corroborating-signals.md) |
| Deploy beyond the local stack | [Deployment](how-to/deployment.md) |
| Change speaker, POP or version safely | [Upgrading and rollback](how-to/upgrading.md) |
| Find why a mitigation didn't reach the router | [Troubleshooting](how-to/troubleshooting.md) |
| Script against prefixd | [HTTP API](reference/api.md) · [CLI](reference/cli.md) |
| Choose between rustbgpd and GoBGP | [Speaker backends](reference/speaker-backends.md) |

## Tutorials

Learn by running the local stack.

| Page | Scope |
|------|-------|
| [Quickstart](tutorials/quickstart.md) | Start the rustbgpd profile, or select GoBGP, sign in and verify the API. |

## Cookbook

Follow a complete procedure for a flow with recorded evidence.

| Page | Scope |
|------|-------|
| [Cookbook index](cookbook/README.md) | Recipes, the evidence behind each, and flows without a recipe yet. |
| [Manual mitigation and withdrawal](cookbook/manual-mitigation.md) | Guardrail rejection, creation, speaker read-back, withdrawal and audit. |
| [Dry-run rollout](cookbook/dry-run-rollout.md) | Rehearse policy without speaker calls, clear the rehearsal and enforce. |

## How-to

Follow a procedure for a specific task.

| Page | Scope |
|------|-------|
| [Deployment](how-to/deployment.md) | Configure authentication, peers, TLS, databases and deployment. |
| [Upgrading and rollback](how-to/upgrading.md) | Back up state and apply version-specific upgrade procedures. |
| [Troubleshooting](how-to/troubleshooting.md) | Diagnose API, mitigation and BGP problems. |
| [Grafana and monitoring](how-to/grafana.md) | Set up dashboards and investigate operational metrics. |
| [FastNetMon](how-to/detectors/fastnetmon.md) | Connect the detector notify script. |
| [Generic webhooks](how-to/detectors/generic-webhook.md) | Map detector payloads into attack events. |
| [Corroborating signals](how-to/detectors/corroborating-signals.md) | Add supporting telemetry to signal correlation. |

## Reference

Look up settings, interfaces and support boundaries.

| Page | Scope |
|------|-------|
| [Configuration](reference/configuration.md) | Settings, inventory, playbooks and correlation fields. |
| [HTTP API](reference/api.md) | Endpoints, payloads and responses. |
| [API versioning](reference/api-versioning.md) | Compatibility and deprecation policy. |
| [CLI](reference/cli.md) | prefixdctl commands and options. |
| [Speaker backends](reference/speaker-backends.md) | Supported choices, pins, controller tests and operational limits. |
| [Vendor compatibility](reference/vendors.md) | Router support and explicitly scoped lab receipts. |

## Explanation

Understand the design.

| Page | Scope |
|------|-------|
| [Architecture](explanation/architecture.md) | Daemon boundaries and the event/reconciliation flow. |
| [Architecture decisions](adr/README.md) | Numbered decisions and their historical context. |
| [rustbgpd over gRPC](adr/023-rustbgpd-over-grpc.md) | Why prefixd drives rustbgpd as a separate daemon. |

## Evidence

Inspect the receipts behind a claim, with their dates and limits.

| Page | Scope |
|------|-------|
| [Speaker profile qualification](reference/qualification/speaker-profiles-2026-10-18.md) | Dated shared-image rustbgpd/GoBGP runtime, security, persistence and local-rule evidence. |
| [Benchmark snapshot](perf/benchmarks.md) | Historical v0.15.0 measurements and instructions; not a current performance qualification. |
| [Router lab](../lab/README.md) | Lab setup and topology-specific checks. |
| [Pinned controller images](../tests/fixtures/rustbgpd/releases.json) | Immutable released images used by the controller test suite. |

## Project

Follow development plans, contribution guidance and release history.

| Page | Scope |
|------|-------|
| [Roadmap](../ROADMAP.md) | Remaining work and qualification gates. |
| [Features](../FEATURES.md) | Feature inventory and limitations. |
| [Changelog](../CHANGELOG.md) | Release history and unreleased changes. |
| [Contributing](../CONTRIBUTING.md) | Development workflow and checks. |
| [Release checklist](project/release-checklist.md) | Release preconditions, version bump and publication steps. |
| [Redirect-to-IP contract plan](project/scrubber-diversion-contract.md) | Proposed speaker dependency, action vectors and failure qualification for guarded scrubber diversion. |
| [Security](../SECURITY.md) | Reporting and security guidance. |

Flat guide and reference paths moved into these categories. ADR identifiers and
the image directory are unchanged.
