# prefixd documentation

Choose a walkthrough, operating procedure, reference, or design explanation.
The structure follows rustbgpd's documentation. Pages retain their own scope;
local controller tests and historical GoBGP lab results do not establish
rustbgpd router enforcement.

## Tutorials

| Guide | Scope |
|---|---|
| [Run the local stack](tutorials/quickstart.md) | Start the default GoBGP stack and verify the API. |

## How-to

| Guide | Scope |
|---|---|
| [Deployment](how-to/deployment.md) | Configure authentication, peers, TLS, databases and deployment. |
| [Upgrading and rollback](how-to/upgrading.md) | Back up state and apply version-specific upgrade procedures. |
| [Troubleshooting](how-to/troubleshooting.md) | Diagnose API, mitigation and BGP problems. |
| [Grafana and monitoring](how-to/grafana.md) | Set up dashboards and investigate operational metrics. |
| [FastNetMon](how-to/detectors/fastnetmon.md) | Connect the detector notify script. |
| [Generic webhooks](how-to/detectors/generic-webhook.md) | Map detector payloads into attack events. |
| [Corroborating signals](how-to/detectors/corroborating-signals.md) | Add supporting telemetry to signal correlation. |

## Reference

| Page | Scope |
|---|---|
| [Configuration](reference/configuration.md) | Settings, inventory, playbooks and correlation fields. |
| [HTTP API](reference/api.md) | Endpoints, payloads and responses. |
| [API versioning](reference/api-versioning.md) | Compatibility and deprecation policy. |
| [Stability](reference/stability.md) | Configuration, API/CLI, metrics, log events and state compatibility. |
| [CLI](reference/cli.md) | prefixdctl commands and options. |
| [Speaker backends](reference/speaker-backends.md) | Supported choices, pins, controller tests and operational limits. |
| [Vendor compatibility](reference/vendors.md) | Router support and explicitly scoped lab receipts. |

## Explanation

| Page | Scope |
|---|---|
| [Architecture](explanation/architecture.md) | Daemon boundaries and the event/reconciliation flow. |
| [Architecture decisions](adr/README.md) | Numbered decisions and their historical context. |

## Evidence

| Page | Scope |
|---|---|
| [Benchmark snapshot](perf/benchmarks.md) | Historical v0.15.0 measurements and instructions; not a current performance qualification. |
| [Router lab](../lab/README.md) | Lab setup and topology-specific checks. |
| [Pinned controller images](../tests/fixtures/rustbgpd/releases.json) | Immutable released images used by the controller test suite. |

## Project

| Page | Scope |
|---|---|
| [Roadmap](../ROADMAP.md) | Remaining work and qualification gates. |
| [Features](../FEATURES.md) | Feature inventory and limitations. |
| [Changelog](../CHANGELOG.md) | Release history and unreleased changes. |
| [Contributing](../CONTRIBUTING.md) | Development workflow and checks. |
| [Security](../SECURITY.md) | Reporting and security guidance. |

Flat guide/reference paths have moved into these categories. ADR identifiers
and the image directory are retained; use this index for canonical page paths.
