<p align="center">
  <img src="docs/images/prefixd-logo.svg#gh-light-mode-only" alt="prefixd" width="300">
  <img src="docs/images/prefixd-logo-dark.svg#gh-dark-mode-only" alt="prefixd" width="300">
</p>

# prefixd

[![Build](https://github.com/lance0/prefixd/actions/workflows/ci.yml/badge.svg)](https://github.com/lance0/prefixd/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Turn DDoS detector signals into guarded BGP FlowSpec mitigations.**

Detectors post attack events over HTTP. prefixd maps the target to your
inventory, picks a playbook, checks guardrails, and asks a separate BGP speaker
to announce a FlowSpec rule with a mandatory TTL. No detector speaks BGP.

[Documentation](docs/README.md) · [Quickstart](docs/tutorials/quickstart.md) ·
[Cookbook](docs/cookbook/README.md) · [Releases](https://github.com/lance0/prefixd/releases)

> **Preferred speaker: [rustbgpd](https://github.com/lance0/rustbgpd)**, "an
> API-first BGP daemon in Rust for route servers, route reflectors, and network
> automation." prefixd drives it over gRPC, and the `rustbgpd` Compose profile
> is the default path. GoBGP stays maintained and selectable.
> [Why rustbgpd](#pairs-with-rustbgpd)

**Status:** pre-1.0, and the API can change before 1.0. The latest release,
[v0.22.1](https://github.com/lance0/prefixd/releases/tag/v0.22.1), makes the
blackhole replacement alert clear an hour after the last replacement and
exports the pre-registered metric series at zero from startup. v0.22.0 added a
dashboard display timezone and marked blackhole export evidence from before a
lost controller fence as historical. It needs rustbgpd 0.79.0 and no
migration; follow the [upgrade guide](docs/how-to/upgrading.md#v0220--0221).

## Choose your path

### NOC with a detector

FastNetMon, Prometheus Alertmanager or any JSON webhook sends attack events.
prefixd groups signals per target, weighs corroborating sources and applies the
matching playbook. Controller integration tests cover these adapters; the dated
profile qualification covers manual mitigation, not detector traffic.

[FastNetMon](docs/how-to/detectors/fastnetmon.md) · [Generic webhook](docs/how-to/detectors/generic-webhook.md) ·
[Corroborating signals](docs/how-to/detectors/corroborating-signals.md)

### Operator during an attack

Mitigate a target by hand from the dashboard or API inside the same guardrails,
then withdraw it with a reason that the audit log keeps. Rehearse policy in
dry-run before you let it announce.

[Manual mitigation](docs/cookbook/manual-mitigation.md) · [Dry-run rollout](docs/cookbook/dry-run-rollout.md) ·
[Troubleshooting](docs/how-to/troubleshooting.md)

### Automation and integration

Drive events, mitigations, the safelist and configuration through the HTTP API
or `prefixdctl`. The controller serves its OpenAPI document at `/openapi.json`.

[HTTP API](docs/reference/api.md) · [CLI](docs/reference/cli.md) ·
[Authentication](docs/how-to/deployment.md#authentication-setup)

prefixd stops at the speaker. Router receipt and enforcement depend on your
router software, address family and import policy. Existing router receipts are
scoped to GoBGP; rustbgpd has local and peer tests but no vendor router receipt
yet. See [vendor compatibility](docs/reference/vendors.md).

## Try it locally

With Git and Docker Compose installed, start the controller, dashboard,
PostgreSQL and rustbgpd from published images. Nothing compiles locally.

```bash
git clone https://github.com/lance0/prefixd.git
cd prefixd
docker compose --profile rustbgpd up -d --pull always --no-build
```

Create the first administrator at the hidden password prompt, then check
liveness:

```bash
docker compose exec prefixd-rustbgpd prefixdctl operators create \
  --username admin --role admin
curl http://localhost/v1/health
```

Open `http://localhost` and sign in. nginx serves the dashboard and API on port
80, and rustbgpd publishes BGP on 179. Prometheus (9091) and Grafana (3001) bind
host loopback only. The sample peer uses a documentation address, so it stays
Idle until you configure your edge router in `configs/rustbgpd.toml`.

The dashboard shows **Live** through nginx and **Polling** when the realtime
feed is unavailable, including direct Next.js servers. See
[realtime and polling](docs/how-to/deployment.md#realtime-and-polling) for refresh
intervals and ingress requirements.

<img src="docs/images/dashboard-overview.png#gh-light-mode-only" alt="Dashboard overview">
<img src="docs/images/dashboard-overview-dark.png#gh-dark-mode-only" alt="Dashboard overview">

<img src="docs/images/dashboard-mitigations.png#gh-light-mode-only" alt="Mitigations list">
<img src="docs/images/dashboard-mitigations-dark.png#gh-dark-mode-only" alt="Mitigations list">

*Synthetic data; router installation is unobserved.*

For GoBGP, start a fresh deployment with
`docker compose --profile gobgp up -d --pull always --no-build` and run
controller commands in `prefixd-gobgp`. Run one profile at a time: switching
doesn't move active rules or the database's speaker binding. The
[quickstart](docs/tutorials/quickstart.md) covers configuration storage,
building from source and troubleshooting.

## Guardrails run before the speaker sees a rule

Detector events and manual requests pass the same checks before prefixd saves
intent or calls the speaker. A rejection returns `422` with its reason and sends
nothing to BGP. With the shipped [`configs/prefixd.yaml`](configs/prefixd.yaml),
sign in and request a mitigation for a safelisted address:

```bash
curl -sS -c cookies.txt -X POST http://localhost/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"your_password_here"}'
curl -sS -b cookies.txt -X POST http://localhost/v1/mitigations \
  -H 'Content-Type: application/json' \
  -d '{"reason":"guardrail check","victim_ip":"10.0.0.5","protocol":"udp",
       "dst_ports":[53],"action":"discard","ttl_seconds":120}'
```

```json
{"error":"guardrail violation: IP 10.0.0.5/32 is safelisted"}
```

The other limits in the shipped configuration reject requests the same way:

| Guardrail | Shipped setting | Example rejection |
|-----------|-----------------|-------------------|
| Safelist | `10.0.0.0/8`, `192.168.0.0/16`, plus API entries | `IP 10.0.0.5/32 is safelisted` |
| TTL | Required, 30 to 1800 seconds | `TTL 7200s out of bounds (min=30, max=1800)` |
| Ports | At most 8 destination ports | `too many ports: 9 (max=8)` |
| Active quotas | 5 per customer, 200 per POP, 500 global | `quota exceeded: customer (5/5)` |
| New mitigation rate | 30 per POP in any 60 seconds; TTL extensions don't count | `new mitigation rate exceeded: 30 created at this POP in the last 60s (max_new_per_minute=30)` |
| Destination | IPv4 `/32` and IPv6 `/128` by default | Manual subnets require [explicit prefix bounds and whole-prefix ownership](docs/reference/api.md#destination-cidrs) |

Two more rules protect routing state:

- **Dry-run:** `mode: dry-run` runs the full pipeline and records mitigations,
  metrics and audit entries, but never calls the speaker. Those mitigations stay
  simulations after a switch to enforced. The shipped config sets
  `mode: enforced`; a config that omits `mode` runs in dry-run.
- **Immutable withdrawal intent:** an operator withdrawal, detector unban or
  TTL expiry saves its rule, actor and reason before the speaker call. A failed
  or uncertain delete stays pending and retries against the same speaker; it
  can't turn back into an announcement.

A `201` means prefixd saved intent and the speaker accepted the local request.
It doesn't prove that a router installed the rule. The running controller
enforces TTLs: if prefixd stops while the speaker stays up, rules stay announced.

[Guardrail settings](docs/reference/configuration.md#guardrails) ·
[Withdrawal recovery](docs/reference/speaker-backends.md#withdrawal-recovery) ·
[Dry-run rollout](docs/cookbook/dry-run-rollout.md)

## Install

CI publishes the controller and dashboard images to `ghcr.io/lance0/prefixd`
and `ghcr.io/lance0/prefixd-dashboard`. Pin a controller and dashboard built
from the same revision.

- **Run the containers:** follow [image selection](docs/how-to/deployment.md#image-publication-and-selection)
  and the [deployment guide](docs/how-to/deployment.md).
- **Build from source:** Rust 1.89 or later and PostgreSQL 14 or later.
  `cargo build --release` builds `prefixd` and `prefixdctl` with both speaker
  adapters; see [bare-metal deployment](docs/how-to/deployment.md#bare-metal-deployment)
  and [contributing](CONTRIBUTING.md#setup).
- **Before production:** set up [authentication](docs/how-to/deployment.md#authentication-setup),
  [TLS](docs/how-to/deployment.md#tls-configuration) and
  [router import policy](docs/how-to/deployment.md#router-configuration). Run one
  controller per POP and speaker target, and read the
  [upgrade guide](docs/how-to/upgrading.md) before changing either.

## Pairs with rustbgpd

prefixd decides what to mitigate; [rustbgpd](https://github.com/lance0/rustbgpd)
owns the BGP sessions. The two meet at a narrow, tested boundary:

- **Typed gRPC calls:** prefixd adds, deletes and lists FlowSpec rules through
  rustbgpd's injection and RIB services, on an owner-only Unix socket locally
  or verified mTLS remotely. Every mutation returns an explicit outcome.
- **Reconciliation restores lost rules:** rustbgpd holds injected rules in its
  process. After a speaker restart, prefixd's database still holds the desired
  state, and the next reconciliation poll (every 30 seconds in the shipped
  config) re-adds missing rules.
- **Qualified versions:** v0.80.0 is the minimum controller contract;
  Compose pins v0.80.1. prefixd refuses to start against an older daemon. CI
  runs the lifecycle, TTL and restart suite against both immutable images.

This qualifies the controller-to-speaker boundary on Linux amd64. It says
nothing about router enforcement.

[rustbgpd README](https://github.com/lance0/rustbgpd#readme) ·
[rustbgpd docs](https://github.com/lance0/rustbgpd/blob/main/docs/README.md) ·
[Speaker backends](docs/reference/speaker-backends.md) ·
[ADR 023](docs/adr/023-rustbgpd-over-grpc.md)

## Documentation

Start with the [documentation index](docs/README.md), or go to your task:

| Task | Guide |
|------|-------|
| Run it for the first time | [Quickstart](docs/tutorials/quickstart.md) · [Cookbook](docs/cookbook/README.md) |
| Connect a detector | [FastNetMon](docs/how-to/detectors/fastnetmon.md) · [Generic webhook](docs/how-to/detectors/generic-webhook.md) · [Correlation](docs/reference/configuration.md#correlation) |
| Configure, deploy or upgrade | [Configuration](docs/reference/configuration.md) · [Deployment](docs/how-to/deployment.md) · [Upgrading](docs/how-to/upgrading.md) |
| Automate | [HTTP API](docs/reference/api.md) · [CLI](docs/reference/cli.md) · [API versioning](docs/reference/api-versioning.md) |
| Choose or operate a speaker | [Speaker backends](docs/reference/speaker-backends.md) · [Vendors](docs/reference/vendors.md) · [Troubleshooting](docs/how-to/troubleshooting.md) |
| Check the evidence | [Profile qualification](docs/reference/qualification/speaker-profiles-2026-10-18.md) · [Benchmarks (historical)](docs/perf/benchmarks.md) |
| Understand or contribute | [Architecture](docs/explanation/architecture.md) · [Decisions](docs/adr/README.md) · [Contributing](CONTRIBUTING.md) · [Roadmap](ROADMAP.md) |
| Report a problem | [Issues](https://github.com/lance0/prefixd/issues) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md) |

## License

MIT. See [LICENSE](LICENSE).
