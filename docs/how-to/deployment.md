# Deployment Guide

## Overview

prefixd requires:

- **prefixd** daemon
- **rustbgpd** as the primary speaker, or the GoBGP profile
  described in [speaker backends](../reference/speaker-backends.md)
- **PostgreSQL 14+**
- **Routers** with FlowSpec support

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Detector   │────▶│   prefixd   │────▶│   Speaker   │
│ (FastNetMon)│     │   :8080     │     │ UDS / RPC   │
└─────────────┘     └──────┬──────┘     └──────┬──────┘
                           │                   │
                           ▼                   ▼
                    ┌─────────────┐     ┌─────────────┐
                    │  PostgreSQL │     │   Routers   │
                    └─────────────┘     └─────────────┘
```

---

## Select a speaker deployment

The [quickstart](../tutorials/quickstart.md) uses
`docker compose --profile rustbgpd up -d --pull always --no-build`. The standard controller image
includes both adapters; use `--profile gobgp` for the GoBGP profile.
Exactly one profile may run. Both selected controller services have the same
container name so Compose rejects a conflicting model before startup.

The application has the stable internal DNS name `prefixd` in either profile.
rustbgpd management uses an owner-only Unix socket, with UID/GID 999 shared by
the two processes. GoBGP management binds only `127.0.0.1:50051` in the shared
GoBGP/controller namespace. Management RPC and PostgreSQL are not published.
The pinned speaker image references are in `docker-compose.yml`; do not replace
them with moving tags without qualification.

A short-lived root initializer seeds only missing mutable YAML files into a
named config volume and assigns the named volumes to UID 999. The selected main
config is a separate read-only overlay. Administrator saves retain their
existing atomic rename and backup behavior. Do not replace these named volumes
with a host-checkout bind mount: the initializer owns their contents. See the
[configuration storage procedure](../tutorials/quickstart.md#configuration-and-persistence)
for edits and persistence.

Configure both FlowSpec families and your actual edge peers before expecting
session establishment. The rustbgpd example adapts its released DDoS config,
removes unicast/RTBH, rejects edge imports and explicitly permits mitigation
exports. [Verified remote mTLS](../reference/speaker-backends.md#remote-mtls)
is available when controller and speaker cannot share a private local socket.

The running controller enforces TTLs. Stopping prefixd alone does not terminate
the speaker's BGP sessions. The shipped rustbgpd config sets
[`bgp.rustbgpd.leased_flowspec`](../reference/configuration.md#leased-flowspec),
so rustbgpd removes the FlowSpec rules added under the lease within one lease
after renewal stops; [`blackhole.leased`](../reference/configuration.md#leased-blackholes)
does the same for blackholes. The code default is unleased, rules added before
the lease was turned on stay unleased, and GoBGP has no lease. Restore
reconciliation or explicitly withdraw unleased rules after controller failure;
monitor controller availability independently from BGP session health.

For isolated released-container lifecycle, TTL and restart validation, run
`scripts/test-rustbgpd.sh`; the [backend runbook](../reference/speaker-backends.md#released-controller-qualification)
records the version floor, immutable pins, recovery behavior and alert queries.
With a locally built controller,
`PREFIXD_IMAGE=prefixd:local python3 scripts/test-compose.py` checks
profile isolation, duplicate-profile rejection, private management, missing-only
config seeding across initializer recreation and the optional host-inventory mount.

Controller RPC acceptance, peer receipt and vendor-router enforcement remain
different evidence. Follow the [upgrade guide](upgrading.md) before changing
backend or rolling back an existing database.

## Image publication and selection

CI publishes `ghcr.io/lance0/prefixd` and `ghcr.io/lance0/prefixd-dashboard`.
Main pushes publish `main`, `latest` and the short commit tag; the controller is
published only after `scripts/test-compose.py` passes against the built image.
The release workflow publishes the version and major.minor tags, and the GitHub
Release records each image's digest. Pull requests build the images without
publishing them. Select the controller/dashboard pair from the same source
revision.

Compose uses the prebuilt `main` tags by default. `PREFIXD_IMAGE` overrides both
the controller and its initializer; `PREFIXD_DASHBOARD_IMAGE` overrides the
frontend. `PREFIXD_RUSTBGPD_IMAGE` overrides the pinned speaker image; leave it
unset to use the tested rustbgpd 0.83.0 digest. Supply already-published matching
references when pinning a deployment.
No new release tag or immutable controller digest is implied by this guide.
The quickstart uses `--pull always --no-build`; the explicit
[local build option](../tutorials/quickstart.md#build-from-source) uses local tags
and a separate `compose build`, then `up -d --pull missing --no-build`, so
fresh runtime dependency images are fetched without replacing local builds.

## Dashboard dependency and development baseline

Bun 1.4.3 and `frontend/bun.lock` define the dashboard install used by CI and
the container builder. The runner copies standalone output and uses the same
Bun version. Use `bun install --frozen-lockfile` when validating a
checkout; do not create an npm lockfile. The current lock resolves Next.js
16.4.2, matching the manifest minimum. Native frontend tests use Node.js 26.12.0.

Application-level `NEXT_PUBLIC_MOCK_MODE` has been retired. Development uses the
normal API client; component tests keep their own controlled API fixtures.
The removed `next lint` command is no longer advertised. Run `bun run lint`,
`bun run typecheck`, `bun run test` and `bun run build` before deployment;
production builds enforce TypeScript checks. Automated browser CI remains
frontend tooling work.

## Quick Start

Start with the [local-stack walkthrough](../tutorials/quickstart.md), then use the
procedures below for authentication, peers, TLS and production deployment.

## Authentication Setup

### Create Operators

Operators are users who can log into the dashboard. These CLI commands connect
directly to PostgreSQL and require `DATABASE_URL`; Compose already sets it in the
prefixd container. Omit `--password` for a hidden terminal prompt (use
`docker compose exec` with its default TTY allocation). Without a controlling
terminal, supply an explicit value; it can appear in shell history and process
arguments:

```bash
# Create admin (full access)
prefixdctl operators create --username admin --role admin

# Create operator (read + withdraw)
prefixdctl operators create --username oncall --role operator

# Create viewer (read-only)
prefixdctl operators create --username readonly --role viewer

# List operators
prefixdctl operators list
```

Usernames match `^[A-Za-z0-9_-]{1,64}$`.

An Admin signed in to the dashboard can also create and delete accounts and set
passwords under **Administration → Users**. That needs a signed-in session: with
`mtls` or `none` mode the tab lists accounts only, so manage them with
`prefixdctl operators`.

### Create API Tokens

Detectors and automation authenticate with named API tokens, created the same
way after the first start. Each secret is printed once; there is no shared or
default token:

```bash
# A detector: ingest only, bound to its source and POP
prefixdctl tokens create --name fnm-pop1 --scope ingest --source fastnetmon --pop iad1

# Automation that manages mitigations
prefixdctl tokens create --name ci-deploy --scope operator
```

See [API tokens](../reference/cli.md#api-tokens) for listing, revocation and
rotation.

An Admin signed in to the dashboard can manage tokens under
**Administration → API tokens**: the table shows each token's scope, bound
source, POP, creator, creation, last use, expiry and revocation, active tokens
first, and can be filtered by creator. **Create token** takes a name, a scope, a
source for an ingest token (it suggests `fastnetmon`, `fastnetmon-hostgroup`,
`alertmanager`, the enabled bearer webhook adapters and the configured
correlation sources), an optional POP and an optional expiry. The new token is
shown once, with a copy button and ready-to-paste client setup. The setup stores
the token in `/etc/prefixd/<name>.token`, owned by the client's account with
mode 0400, and reads it from there: the FastNetMon script's
`/etc/default/prefixd` lines, a FastNetMon hostgroup shim, an Alertmanager
receiver with `credentials_file`, a webhook or Grafana header, or `prefixdctl`
with `PREFIXD_TOKEN`, plus a `curl -K -` test that keeps the token off the
command line. The snippets use the dialog's **Controller API URL**, prefilled with
the page origin: set it to an address that reaches the controller API, such as
the nginx ingress or the controller on port 8080, when the dashboard is served
without nginx. The dashboard keeps the secret only while that dialog is
open and asks before closing it uncopied. Revoking asks for confirmation naming
the token, its source and its last use. The tab needs a signed-in Admin
session; it is not shown to other roles, mTLS clients or `none` mode, and the
controller refuses them.

### Auth Modes

Configure in `prefixd.yaml`:

```yaml
http:
  auth:
    mode: credentials      # credentials, mtls or none
```

| Mode | Dashboard | API/CLI |
|------|-----------|---------|
| `credentials` | Session login | API tokens or a session cookie |
| `mtls` | Client-certificate trusted browser/API access | Client certificate |
| `none` | No login | No auth |

---

## Dashboard Setup

The Next.js dashboard communicates with the prefixd API through a server-side proxy. This allows the dashboard to work on any host without hardcoded URLs.
The proxy forwards only normalized `/v1/` API paths; it does not expose the
private metrics scrape endpoint. The OpenAPI spec remains available directly
through nginx at `/openapi.json`.

### Realtime and polling

The browser opens the feed at `/v1/ws/feed` on the dashboard's own origin,
using `wss:` for HTTPS and `ws:` for HTTP, with the same session cookies.
The supplied nginx configuration forwards WebSocket upgrades to the controller.
Access the Compose stack through nginx (port 80, or your HTTPS ingress) for
realtime updates. A custom ingress must forward `/v1/ws/feed` upgrades and
preserve authentication; see [the nginx example](../../configs/nginx.conf).

Next.js by itself cannot upgrade this connection: this includes `bun run dev`,
`bun run start` and the standalone dashboard container accessed without nginx.
`PREFIXD_API` configures the server-side HTTP API proxy, not a browser WebSocket
destination. Setting it does not add a feed upgrade route to Next.js.

The top bar combines the feed with the age of the last successful API
response, measured from browser receipt:

| Status | Meaning |
| --- | --- |
| **Connecting** | No API response yet, for up to 15 seconds after the page opens. |
| **Live** | The feed is connected and an API response arrived within 15 seconds. |
| **Polling (Ns ago)** | The feed is unavailable and an API response arrived within 15 seconds. |
| **Stale (Ns ago)** | No API response for more than 15 seconds, for example while requests hang. |
| **Offline (Ns ago)** | No API response for more than 15 seconds and the latest request failed. |

While the status is **Stale** or **Offline**, every dashboard page also shows
a notice with the time of the last update, because lists, counts and expiry
times on screen have not refreshed. A connected feed never shows **Live** over
failing requests for more than 15 seconds: a failure after a recent success
keeps the current status until that success is 15 seconds old, so **Live** and
**Polling** do not prove that the latest request succeeded. Focus or hover the status for the feed requirements and
fallback details. Failed handshakes, including ones pending
for 10 seconds, switch to polling while the feed retries up to ten times with
backoff. Returning to the tab starts another attempt. Network and authentication
failures can also interrupt a correctly proxied feed; browsers do not expose
the failed handshake's HTTP status to the dashboard.

HTTP polling remains active in both modes. While the tab is visible and the API
is reachable, mitigations (list and detail), events, stats, health and signal
groups (including loaded paginated groups) refresh every 5 seconds. POPs,
time series and signal sources refresh every 30 seconds; configuration and
operator pages refresh on focus or explicit actions. Hidden or offline tabs
pause periodic refresh, and failed API requests retain their page's error state.
A fresh status reflects only the dashboard's API responses; it does not prove
router enforcement. Live event toasts are unavailable without the feed, and
polling does not replay missed notifications.

### Docker Compose

The dashboard container uses the `PREFIXD_API` environment variable to locate the backend:

```yaml
dashboard:
  build: ./frontend
  environment:
    - PREFIXD_API=http://prefixd:8080  # Docker service name (internal)
```

The controller services set `PREFIXD_API=http://127.0.0.1:8080` too, so
`prefixdctl` run with `docker compose exec` reaches the controller's own
listener without `--api`.

### Remote Deployment

When deploying to a remote server, ensure:

1. The dashboard container can reach the prefixd container (same Docker network)
2. Users access the dashboard via the server's IP/hostname on port 80 (through nginx)
3. The browser never connects directly to the backend - all API calls are proxied through nginx

The shipped `configs/prefixd.yaml` and `configs/prefixd-gobgp.yaml` set
`http.secure_cookies: false` because this quickstart serves plain HTTP on port
80, and browsers do not send a Secure cookie over HTTP. Remove that line once
browsers use HTTPS; see [HTTPS via nginx](#https-via-nginx-recommended-for-production).

```bash
# Access dashboard from your workstation
open http://your-server
```

### Clipboard on Plain HTTP

Browsers only allow clipboard writes from a **secure context**. Chrome reports
`clipboard-write: denied` for plain-HTTP origins other than `localhost` and
ignores the copy request, so the dashboard's copy buttons (incident report,
FlowSpec rule, webhook endpoint) fail there — they show a "Copy failed —
clipboard unavailable" toast rather than pretending to succeed.

Serve the dashboard over HTTPS (see `configs/nginx.conf` and `docs/adr/005-*.md`)
to enable clipboard actions in production. `http://localhost` also works for
local development.

### Local Development (Outside Docker)

For frontend development without Docker:

```bash
cd frontend
export PREFIXD_API=http://localhost:8080
bun run dev
```

The dev server uses the **Polling** fallback described above because Next.js
cannot upgrade `/v1/ws/feed`. To test the live feed, open the Compose stack
through nginx at `http://localhost` (port 80).

---

## Signal Adapters (Detector Integration)

prefixd accepts signals five ways:

1. **Generic API** (`POST /v1/events`, or `POST /v1/events/batch`) — any detector that can POST JSON
2. **Alertmanager webhook** (`POST /v1/signals/alertmanager`) — native Alertmanager v4 payload
3. **FastNetMon webhook** (`POST /v1/signals/fastnetmon`) — native FastNetMon JSON payload
4. **Named webhook adapters** (`POST /v1/signals/webhook/{name}`) — arbitrary JSON mapped by a `webhook_adapters` entry in `correlation.yaml`; see [generic webhooks](detectors/generic-webhook.md)
5. **Corroborating signals** (`POST /v1/signals/corroborator`) — sources without a victim IP that only corroborate open signal groups; see [corroborating signals](detectors/corroborating-signals.md)

The detector adapters translate detector-native payloads into prefixd events and feed them through the full pipeline (correlation → policy → guardrails → announce). Corroborating signals create no event; they only add confidence to open signal groups.

### Alertmanager Setup

Add a webhook receiver to your Alertmanager config:

```yaml
# alertmanager.yml
receivers:
  - name: prefixd
    webhook_configs:
      - url: "http://prefixd.internal/v1/signals/alertmanager"
        send_resolved: true   # Enables auto-withdraw on resolve
        http_config:
          authorization:
            type: Bearer
            # An ingest token bound to `alertmanager`, mode 0400
            credentials_file: /etc/alertmanager/prefixd.token

route:
  routes:
    - match:
        severity: critical
      receiver: prefixd
```

The adapter maps Alertmanager fields to prefixd events:

| Alertmanager Field | Maps To | Notes |
|--------------------|---------|-------|
| `labels.instance` or `annotations.victim_ip` | `victim_ip` | Required — alert is skipped without it |
| `labels.vector` or `annotations.vector` | `vector` | Falls back to `unknown` |
| `labels.severity` | `confidence` | critical=0.9, warning=0.7, info=0.5 |
| `annotations.bps`, `annotations.pps` | Traffic metrics | Optional |
| `fingerprint` and `startsAt` | Dedup key | Both required; one key per firing, shared by firing and resolved notifications |

Resolved alerts (status=`resolved`) withdraw mitigations whose last creating or
extending event belongs to that firing. A delayed resolve leaves a newer
firing's mitigation intact. See the [API reference](../reference/api.md#alertmanager-webhook)
for validation and replay behavior.

### FastNetMon Setup

Install the bundled notify script, `scripts/prefixd-fastnetmon.sh`, with an
ingest token bound to `fastnetmon` in a 0400 token file; see
[FastNetMon](detectors/fastnetmon.md). The script posts each ban and unban to
`/v1/events` and passes the token to curl on stdin, so it never appears on a
command line. An unban names the victim, so the ingest token needs no read or
withdraw access. Never put a token in `notify_script_args`, where any local
user can read it from the process list. A sender that posts to
`/v1/signals/fastnetmon` directly needs an ingest token bound to `fastnetmon`
(`fastnetmon-hostgroup` for hostgroup alerts) in `Authorization: Bearer`.
FastNetMon Advanced's native web callback cannot send one, so it needs a
localhost relay that adds the token; see
[credential delivery per detector](../adr/034-source-bound-api-tokens.md#13-credential-delivery-per-detector).

The adapter classifies the attack vector from the traffic breakdown (UDP/SYN/ICMP/TCP) and maps `action` to confidence:

| FastNetMon Action | Confidence |
|-------------------|------------|
| `ban` | 0.9 |
| `partial_block` | 0.7 |
| `alert` | 0.5 |
| `unban` | Withdraws mitigation |

### Multi-Signal Correlation

When [correlation](../reference/configuration.md#correlation) is enabled, events from multiple adapters targeting the same (victim_ip, vector) within a time window are grouped into a signal group. Set `min_sources: 2` to require corroboration before triggering mitigation:

```yaml
# configs/correlation.yaml
enabled: true
min_sources: 2
window_seconds: 300
sources:
  fastnetmon:
    weight: 1.0
  alertmanager:
    weight: 0.8
```

See [ADR 018](../adr/018-multi-signal-correlation-engine.md) and [ADR 019](../adr/019-signal-adapter-architecture.md) for design rationale.

---

## GoBGP 4.10.0 Setup

The GoBGP controller contract is qualified against the pinned 4.10.0 image
below. Other versions require their own lifecycle, read-back and restart checks.

### Docker GoBGP profile

`docker compose --profile gobgp up -d --pull always --no-build` selects the pinned GoBGP image
in `docker-compose.yml`. Its binary reports 4.10.0; the third-party OCI image
revision identifies its image-build repository, not an upstream source
attestation. The controller shares its network namespace and uses only the
loopback management listener. BGP port 179 is published; management port 50051
is not. Recreate both services together when replacing GoBGP:

```bash
docker compose --profile gobgp up -d --force-recreate gobgp prefixd-gobgp
```

### GoBGP Configuration

`configs/gobgp.conf`:

```toml
[global.config]
  as = 65010
  router-id = "10.11.0.10"
  port = 179

# Peer with edge router
[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.0.1"
    peer-as = 65000
  
  # IPv4 FlowSpec
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv4-flowspec"
  
  # IPv6 FlowSpec (optional)
  [[neighbors.afi-safis]]
    [neighbors.afi-safis.config]
      afi-safi-name = "ipv6-flowspec"
```

### Verify GoBGP

```bash
# Check peer status
docker compose exec gobgp gobgp neighbor

# Check FlowSpec RIB
docker compose exec gobgp gobgp global rib -a ipv4-flowspec
docker compose exec gobgp gobgp global rib -a ipv6-flowspec
```

### Bare Metal GoBGP

Install a verified upstream release and check its published checksums. The
container receipt does not qualify a separately installed binary.

```bash
# Verify the separately installed binary before qualification.
gobgpd --version  # This guide's pinned container reports 4.10.0.

# Keep unauthenticated management confined to the controller's local namespace.
sudo gobgpd -f /etc/gobgp/gobgp.conf --api-hosts=127.0.0.1:50051 \
  --pprof-disable --metrics-path=
```

---

## Router Configuration

### Juniper Junos (MX/PTX)

Tested with cJunosEvolved 25.4R1.13-EVO (PTX10002). Works with both classic Junos (MX) and Junos Evolved (PTX).

```junos
# Import policy - must be configured first
set policy-options policy-statement FLOWSPEC-IMPORT term accept-all then accept

# Enable FlowSpec forwarding
set routing-options flow validation
set routing-options flow term-order standard

# BGP group for FlowSpec (eBGP example)
set protocols bgp group FLOWSPEC type external
set protocols bgp group FLOWSPEC import FLOWSPEC-IMPORT
set protocols bgp group FLOWSPEC peer-as 65010
set protocols bgp group FLOWSPEC neighbor 10.11.0.10 family inet flow no-validate FLOWSPEC-IMPORT
```

> **Important**: The GoBGP neighbor config must advertise **only** `ipv4-flowspec` AFI-SAFI.
> If GoBGP also advertises `inet-unicast`, Junos will reject the session with
> Open Message Error subcode 7 (unsupported capability). Configure the neighbor
> in `gobgp.conf` with only the `ipv4-flowspec` address family.

### Verify on Juniper

```junos
# BGP session
show bgp neighbor 10.11.0.10

# FlowSpec routes (this is where prefixd rules appear)
show route table inetflow.0

# Detailed FlowSpec with actions
show route table inetflow.0 extensive

# BGP summary
show bgp summary
```

### Arista EOS (7xxx)

```eos
! BGP configuration
router bgp 65000
  neighbor 10.11.0.10 remote-as 65010
  !
  address-family flow-spec ipv4
    neighbor 10.11.0.10 activate
  !
  address-family flow-spec ipv6
    neighbor 10.11.0.10 activate
```

### Cisco IOS-XR (ASR 9000, NCS)

```cisco
router bgp 65000
  neighbor 10.11.0.10
    remote-as 65010
    address-family ipv4 flowspec
    address-family ipv6 flowspec
  !
  flowspec
    address-family ipv4
      service-policy type pbr FLOWSPEC-POLICY
```

---

## PostgreSQL Setup

### Docker (Included)

The `docker-compose.yml` includes PostgreSQL:

```yaml
postgres:
  image: postgres:16-alpine
  environment:
    POSTGRES_DB: prefixd
    POSTGRES_USER: prefixd
    POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD in .env; scripts/compose-bootstrap.sh env generates one}
  volumes:
    - postgres-data:/var/lib/postgresql/data
```

There is no default password: Compose refuses to start until `.env` sets
`POSTGRES_PASSWORD`. `scripts/compose-bootstrap.sh env` writes a random one,
mode 0600, on a fresh checkout. PostgreSQL keeps the password its data volume
was created with, so changing the variable later locks the controller out
until you also change it in the database.

### External PostgreSQL

```sql
-- Create database
CREATE DATABASE prefixd;
CREATE USER prefixd WITH PASSWORD 'secure-password';
GRANT ALL PRIVILEGES ON DATABASE prefixd TO prefixd;
```

Configure in `prefixd.yaml`:

```yaml
storage:
  connection_string: "postgres://prefixd:secure-password@postgres.internal:5432/prefixd"
  max_connections: 10
```

### High Availability

For production:

1. Use PostgreSQL with streaming replication
2. If you pool connections (PgBouncer), use session mode; see below
3. Regular backups
4. Monitor replication lag

### Controller fence connection

Each controller holds a PostgreSQL session advisory lock on one dedicated
connection, opened from the same connection string as its pool, so that a
second controller for the same POP and speaker target stays in standby. Session
locks belong to the server session. **Connect directly or through a session-mode
pooler.** PgBouncer transaction pooling hands the session to other clients and
breaks the lock. The fence session sets server-side TCP keepalives so
PostgreSQL releases a crashed host's lock within about 25 seconds; keep
keepalive probes open between the controller and the database. See
[controller fence and rolling deploys](upgrading.md#controller-fence-and-rolling-deploys).

Load balancers and detector routing must health-check `GET /v1/ready`, which
returns `200` only on the controller that holds the fence, and `503` in standby
or while draining after a shutdown signal. Set the readiness check interval
shorter than `shutdown.drain_timeout_seconds` so traffic moves off a draining
controller before it exits. `GET /v1/health` is liveness and stays `200` on a
standby or draining controller, so routing by it can deliver detector events to
a controller that refuses them with `503`.

---

## Database Migrations

### How Migrations Work

prefixd applies database migrations automatically on startup. A start reads the
versions recorded in `schema_migrations` and applies only the ones the database
is missing, so startup cost does not grow with the migration history and a
restart never re-runs a recorded backfill.

- The check-and-apply sequence holds a PostgreSQL advisory lock. Two controllers
  starting at once migrate once; the second waits for the first and then finds
  nothing to do. A start that waits more than 5 minutes fails instead of
  hanging, and reports that another instance is migrating.
- Each missing version runs in its own transaction together with its tracking
  row, with `lock_timeout` set to 2 seconds per attempt, so queries queued
  behind its `ACCESS EXCLUSIVE` request wait a bounded time. A migration still
  blocked after 5 attempts with backoff, about 20 seconds, rolls back and fails
  the start with its version and name; see
  [database schema version and downgrade](upgrading.md#database-schema-version-and-downgrade)
  for finding the blocking session.
- A database recording a version newer than the binary knows refuses to start.
  An older binary can reannounce a requested deletion against a newer schema.
  Releases up to 0.27.0 have no such check; a release that adds a migration
  states in its upgrade notes whether a rolling replacement is safe.
- A database created before version tracking existed, whose
  `schema_migrations` is absent or empty, replays migrations 1-3, whose
  statements are all `IF NOT EXISTS`, and then applies the rest. Stored
  events, mitigations, pending withdrawals and audit history are not rewritten.

Migration files keep their `IF NOT EXISTS` guards so a retried or replayed
version stays safe, but a recorded version is not run again.

Applied migrations are tracked in the `schema_migrations` table:

```sql
SELECT * FROM schema_migrations ORDER BY version;
-- version | name                | applied_at
-- --------+---------------------+---------------------
--       1 | initial                  | 2026-01-15 10:00:00
--       2 | operators_sessions       | 2026-01-15 10:00:00
--       3 | raw_details              | 2026-01-28 12:00:00
--       4 | schema_migrations        | 2026-02-20 10:00:00
--       5 | acknowledge              | 2026-03-18 14:37:00
--       6 | notification_preferences | 2026-03-18 14:37:00
--       7 | signal_groups            | 2026-03-19 18:00:00
```

### Check Migration Status

```bash
# Via CLI
DATABASE_URL=postgres://prefixd:pass@localhost:5432/prefixd prefixdctl migrations

# Via SQL
docker compose exec postgres psql -U prefixd -c \
  "SELECT version, name, applied_at FROM schema_migrations ORDER BY version"
```

### Adding New Migrations

1. Create `migrations/NNN_description.sql` with `IF NOT EXISTS` guards
2. Add it, with its version and name, to the list in `src/db/migrate.rs`
3. The next prefixd startup will apply and record it

Keep the list append-only: a released entry keeps its version and SQL text,
because databases have already recorded it.

### Rollback

Migrations are forward-only. A database that recorded a newer version refuses
an older binary that carries the check, but releases up to 0.27.0 do not, so
after a release that added a migration, do not start the previous binary
against the migrated database. To roll back:

1. Stop prefixd
2. Restore from a database backup taken before the upgrade
3. Start the previous prefixd version

Always take a database backup before upgrading. See [Upgrade Guide](upgrading.md).

---

## Bare Metal Deployment

### Build from Source

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build --release

# Install
sudo cp target/release/prefixd /usr/local/bin/
sudo cp target/release/prefixdctl /usr/local/bin/
```

### Directory Structure

The shipped unit runs prefixd as the `rustbgpd` user, the account rustbgpd's
own `examples/systemd/rustbgpd.service` uses. Create that user as its unit
describes, then:

```bash
sudo mkdir -p /etc/prefixd
sudo cp configs/*.yaml /etc/prefixd/
sudo chown -R rustbgpd:rustbgpd /etc/prefixd
```

prefixd accepts rustbgpd's socket only in a directory that is mode 0700 and
owned by its UID. rustbgpd's unit creates `/var/lib/rustbgpd` with
`StateDirectory=`, and systemd resets it to `StateDirectoryMode=` (0755 by
default) on every start, so a `chmod` does not last. Install the shipped
[`prefixd.conf`](../../dist/systemd/rustbgpd.service.d/prefixd.conf) drop-in for
rustbgpd, which sets `StateDirectoryMode=0700`:

```bash
sudo install -D -m 0644 dist/systemd/rustbgpd.service.d/prefixd.conf \
  /etc/systemd/system/rustbgpd.service.d/prefixd.conf
```

### Systemd Service

The repository ships the unit as
[`dist/systemd/prefixd.service`](../../dist/systemd/prefixd.service):

```bash
sudo install -m 0644 dist/systemd/prefixd.service /etc/systemd/system/prefixd.service
```

It starts after `network-online.target`, `postgresql.service` and
`rustbgpd.service`. The speaker is ordered, not pulled in, so enable
`rustbgpd.service` as well. The unit keeps `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome` and `PrivateTmp`. Only `/etc/prefixd` is
writable, because dashboard and API saves rewrite `playbooks.yaml`,
`alerting.yaml` and `correlation.yaml` there.

rustbgpd's shipped unit uses `--runtime-state-dir /var/lib/rustbgpd`, so its
implicit owner-only gRPC socket is `/var/lib/rustbgpd/grpc.sock`. Point prefixd
at it before the first start; changing the socket path later changes the
persistent speaker target (see the [upgrade guide](upgrading.md)):

```yaml
bgp:
  backend: rustbgpd
  rustbgpd:
    endpoint: "unix:///var/lib/rustbgpd/grpc.sock"
```

The [UDS client](../reference/speaker-backends.md#rustbgpd-configuration)
requires the socket and its directory to belong to the controller's own UID and
the server to run as that UID, so the unit sets `User=rustbgpd`. A shared group
does not pass these checks. Running as the same user means prefixd can read
rustbgpd's configuration, state and credentials; `ProtectSystem=strict` only
keeps them read-only. Operators who need the two isolated should use the
[remote mTLS](../reference/speaker-backends.md#remote-mtls) endpoint instead of
the socket. The implicit socket needs no bearer
token; a listener that declares `token_file` also needs `bearer_token_env` in
prefixd.

Secrets go in `/etc/default/prefixd`, outside the writable `/etc/prefixd`, so
the service user cannot replace them. systemd reads the file as root before it
drops privileges, so it can stay root-only. Create it empty; API tokens are
minted in the database after the first start, not passed through the
environment:

```bash
sudo sh -c 'umask 077; touch /etc/default/prefixd'
```

Alert destination variables named by `*_env` keys go in the same file; see
[alerting](alerting.md#pass-variables-with-systemd).

```bash
sudo chown root:root /etc/default/prefixd
sudo chmod 0600 /etc/default/prefixd
sudo systemctl daemon-reload
sudo systemctl enable --now rustbgpd prefixd
```

For [GoBGP](#bare-metal-gobgp) (`bgp.backend: gobgp`), add the shipped
[`gobgp.conf`](../../dist/systemd/prefixd.service.d/gobgp.conf) drop-in. It
orders prefixd after `gobgpd.service` and runs it as a separate `prefixd`
user, which then owns `/etc/prefixd`:

```bash
sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin prefixd
sudo chown -R prefixd:prefixd /etc/prefixd
sudo install -D -m 0644 dist/systemd/prefixd.service.d/gobgp.conf \
  /etc/systemd/system/prefixd.service.d/gobgp.conf
sudo systemctl daemon-reload
sudo systemctl enable prefixd
# restart, not start: a running prefixd keeps its old user until restarted.
sudo systemctl restart prefixd
```

#### Restart behavior

`Restart=on-failure` restarts prefixd five seconds after a crash or failed
start. A `systemctl stop` stays stopped. While prefixd is down, nothing expires:
TTL expiry, withdrawal and reconciliation need the running controller, and
stopping prefixd does not withdraw speaker rules. When prefixd returns,
reconciliation expires overdue mitigations.

Leased rules are the exception. With
[`bgp.rustbgpd.leased_flowspec`](../reference/configuration.md#leased-flowspec)
or [`blackhole.leased`](../reference/configuration.md#leased-blackholes),
rustbgpd removes the controller's leased FlowSpec rules and blackholes within
`blackhole.lease_seconds` (60 by default) plus its RIB queue lag when prefixd
dies and the speaker keeps running. Unleased rules stay announced until prefixd
returns or an operator withdraws them. Monitor controller availability
separately from BGP session health.

---

## TLS Configuration

### Self-Signed Certificates

```bash
# Generate CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -out ca.crt -subj "/CN=prefixd-ca"

# Generate server cert
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=prefixd"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -sha256
```

### Configure TLS

```yaml
http:
  listen: "0.0.0.0:8443"
  tls:
    cert_path: "/etc/prefixd/server.crt"
    key_path: "/etc/prefixd/server.key"
    ca_path: "/etc/prefixd/ca.crt"  # Required for auth.mode: mtls
  auth:
    mode: mtls
```

### HTTPS via nginx (Recommended for Production)

The most common production setup terminates TLS at nginx. This keeps certificate management in one place and the internal Docker network unencrypted:

```nginx
server {
    listen 443 ssl http2;
    server_name prefixd.example.com;

    ssl_certificate     /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # HSTS - enforce HTTPS for browsers
    add_header Strict-Transport-Security "max-age=63072000" always;

    resolver 127.0.0.11 valid=10s;
    set $dashboard dashboard:3000;
    set $api prefixd:8080;

    location /v1/ {
        proxy_pass http://$api;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Request-ID $request_id;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 86400s;
    }

    location / {
        proxy_pass http://$dashboard;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Request-ID $request_id;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name prefixd.example.com;
    return 301 https://$host$request_uri;
}
```

Mount your certificates into the nginx container:

```yaml
# docker-compose.yml override
nginx:
  volumes:
    - ./configs/nginx.conf:/etc/nginx/conf.d/default.conf
    - ./certs/server.crt:/etc/nginx/ssl/server.crt:ro
    - ./certs/server.key:/etc/nginx/ssl/server.key:ro
  ports:
    - "443:443"
    - "80:80"
```

Once browsers reach prefixd over HTTPS, delete `secure_cookies: false` from
`configs/prefixd.yaml` (or `configs/prefixd-gobgp.yaml` for the GoBGP profile)
and restart the controller, so session cookies carry the `Secure` attribute.

> **Let's Encrypt**: For automated certificate renewal, use certbot with the nginx plugin or mount certificates from an external certbot container.

### mTLS (Mutual TLS)

For zero-trust environments:

```yaml
http:
  auth:
    mode: mtls
  tls:
    cert_path: "/etc/prefixd/server.crt"
    key_path: "/etc/prefixd/server.key"
    ca_path: "/etc/prefixd/ca.crt"  # Client CA
```

All three paths must be nonempty. Missing native TLS or missing/blank certificate,
key or client-CA paths stop startup before database or speaker connections. The
TLS listener requires a client certificate trusted by this CA; trusted clients
retain administrator access.

Do not select `mtls` when nginx terminates client TLS and forwards plaintext to
prefixd: proxy identity headers are not authentication. Use credentials
authentication (sessions and API tokens) for that internal connection, or
configure native mTLS on prefixd.

Do not let an identity proxy forward an `Authorization: Bearer` header to
prefixd (oauth2-proxy `--set-authorization-header`, nginx `auth_request`
forwarding `Authorization`, Traefik forward-auth passing `Authorization`). A
Bearer header replaces the dashboard session, so the dashboard signs in and
then gets 401 on every request. A proxy that adds `Authorization: Basic` cannot
carry an API token either: two `Authorization` headers get 401. See
[Bearer headers from identity proxies](upgrading.md#bearer-headers-from-identity-proxies).

---

## Multi-POP Deployment

Multiple prefixd instances share one PostgreSQL:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  prefixd    │     │  prefixd    │     │  prefixd    │
│  (iad1)     │     │  (fra1)     │     │  (sin1)     │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                    ┌──────┴──────┐
                    │  PostgreSQL │
                    └─────────────┘
```

### Configure POP Identity

Each instance uses a unique `pop` value:

```yaml
# iad1
pop: iad1

# fra1
pop: fra1
```

### Cross-POP Visibility

```bash
# List all mitigations across POPs
curl "http://localhost/v1/mitigations?pop=all"

# Get stats per POP
curl "http://localhost/v1/stats"
curl "http://localhost/v1/pops"
```

---

## Monitoring

The API listener serves unauthenticated `/metrics` for trusted-network scrapes;
it does not bind a second monitoring port. Default Compose does not publish the
API listener, and both nginx and the dashboard proxy reject metrics requests.
This is a network boundary, not per-route authentication: anyone with direct
access to the API listener can scrape it.

Prometheus at `127.0.0.1:9091` and Grafana at `127.0.0.1:3001` are published only
on host loopback by default. For remote monitoring access, use an
operator-controlled tunnel or an authenticated reverse proxy rather than
publishing these management interfaces directly. Keep direct API scrapes on the
trusted management network when deploying outside Compose.

### Prometheus

Scrape config:

```yaml
scrape_configs:
  - job_name: 'prefixd'
    metrics_path: /metrics
    static_configs:
      - targets: ['prefixd:8080']
```

### Key Metrics

| Metric | Description |
|--------|-------------|
| `prefixd_mitigations_active` | Active mitigations |
| `prefixd_events_ingested_total` | Events received |
| `prefixd_announcements_total` | FlowSpec announcements |
| `prefixd_bgp_session_up` | BGP session status |
| `prefixd_guardrail_rejections_total` | Rejected events |
| `prefixd_http_requests_total` | HTTP requests |
| `prefixd_http_request_duration_seconds` | Request latency histogram |
| `prefixd_db_pool_connections` | DB pool stats (active, idle, total) |
| `prefixd_db_row_parse_errors_total` | Corrupted row parse errors |
| `prefixd_signal_groups_total` | Signal groups created (correlation) |
| `prefixd_corroboration_met_total` | Groups that met corroboration threshold |
| `prefixd_corroboration_timeout_total` | Groups that expired without corroboration |
| `prefixd_correlation_confidence` | Derived confidence distribution |

### Alerting

```yaml
groups:
  - name: prefixd
    rules:
      - alert: PrefixdBGPDown
        expr: prefixd_bgp_session_up == 0
        for: 1m
        labels:
          severity: critical
      
      - alert: PrefixdHighRejections
        expr: rate(prefixd_guardrail_rejections_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
```

### Health Checks

`<prefixd-version>` below stands for the running controller's package version.
The public response reports the configured authentication mode.

```bash
# Liveness check (public, lightweight - no database or speaker calls)
curl http://localhost/v1/health
# Example: {"status":"ok","version":"<prefixd-version>","auth_mode":"credentials"}

# Full health in the default credentials mode (cookies saved by session login)
curl -b cookies.txt http://localhost/v1/health/detail

# Or with an operator API token, kept off the command line
printf 'header = "Authorization: Bearer %s"\n' "$PREFIXD_TOKEN" |
  curl -K - http://localhost/v1/health/detail
# Reports database, peer observation, selected speaker/daemon metadata,
# controller uptime and active mitigations; not router enforcement.

# CLI status, with an operator token in PREFIXD_TOKEN
prefixdctl status
prefixdctl peers
```

### Request Tracing

Every request is assigned an `x-request-id` header (UUID). If the client sends one, it is preserved; otherwise prefixd generates it. The ID is:

- Added to the tracing span (visible in structured logs)
- Echoed back in the response `x-request-id` header
- Forwarded by nginx when using the included config

Use it to correlate a user's action through nginx → prefixd → database:

```bash
# Send a request with a custom ID
curl -H "x-request-id: debug-123" http://localhost/v1/health

# Check the response header
curl -v http://localhost/v1/health 2>&1 | grep x-request-id
# < x-request-id: 550e8400-e29b-41d4-a716-446655440000
```

---

## Production Checklist

### Security

- [ ] Generate strong API token
- [ ] Create operators with appropriate roles
- [ ] Enable TLS (or use reverse proxy)
- [ ] Private management between prefixd and the selected speaker
- [ ] Firewall rules (only allow trusted detectors)

### Reliability

- [ ] PostgreSQL high availability
- [ ] prefixd unit installed and enabled, with the [restart behavior](#restart-behavior) understood
- [ ] Log rotation
- [ ] Backup strategy for database (required for rollback, see [Upgrade Guide](upgrading.md))

### Monitoring

- [ ] Prometheus scraping metrics
- [ ] Alerting rules configured
- [ ] [Alert destinations](alerting.md) configured and a test alert received
- [ ] Dashboard for visibility
- [ ] BGP session monitoring

### Configuration

- [ ] Inventory reflects actual network
- [ ] Playbooks match security policy
- [ ] Quotas set appropriately
- [ ] Safelist populated with infrastructure IPs
- [ ] Correlation config tuned (if enabled): `min_sources`, `confidence_threshold`, source weights

### Testing

- [ ] Test event ingestion
- [ ] Verify FlowSpec reaches routers
- [ ] Test mitigation withdrawal
- [ ] Verify TTL expiry works
- [ ] Test dashboard login
- [ ] Test signal adapters (if using Alertmanager/FastNetMon)
- [ ] Verify corroboration behavior with `min_sources` > 1 (if enabled)

---

## Lab Environment

Use the [maintained FRR interop lab](../../lab/README.md#flowspec-interop-lab-maintained)
to test prefixd's API through a speaker to a receiving router. From the
repository root, with Docker and containerlab installed:

```bash
just interop-frr          # rustbgpd and GoBGP
just interop-frr gobgp    # GoBGP only
# Set CLAB="sudo containerlab" if required by your containerlab installation.
```

The runner owns its isolated containers and network, checks exact IPv4 and IPv6
FlowSpec receipt, withdrawal, TTL expiry and speaker restart, and retains dated
receipts. It does not attach to the Compose stack. FRR FlowSpec receipt is
control-plane evidence; it does not prove packet filtering.

Juniper-specific setup remains in the
[legacy topology instructions](../../lab/README.md#legacy-topologies), including
cJunosEvolved and the untested, bare-metal vJunos-router lab. Historical Juniper
results used GoBGP; see the [vendor matrix](../reference/vendors.md) for their
scope and the dated FRR results.
