# Upgrade Guide

Upgrading a v0.20.0 deployment? Follow [v0.20.0 → 0.21.0](#v0200--0210).
From v0.19.1, follow [v0.19.1 → 0.20.0](#v0191--0200) first.

## General Principles

- **Database migrations run automatically** on startup. Legacy speaker state also
  requires the explicit ownership adoption below before the upgraded daemon starts.
- Review configuration and ownership changes before upgrading; new defaults do
  not establish downgrade compatibility.
- PostgreSQL retains mitigation intent. Reconciliation checks eligible intent
  after restart; stored Active status does not prove router enforcement.
- The independent speaker can retain rules while prefixd is stopped. Application
  TTL cleanup pauses until the controller resumes.
- **Upgrade without changing `mode`.** Start the upgraded binary in the mode the
  old one ran, and switch modes only in a later restart; see
  [mitigation origin mode](#mitigation-origin-mode).
- **Always back up the database** before upgrading.

## Speaker ownership upgrade

Migration 014 adds immutable `speaker_targets`, one-to-one `speaker_pop_bindings`,
and a target reference on withdrawal requests. Startup validates the configured
POP and speaker target before connecting to the speaker. A POP with no mitigation,
withdrawal or announcement history binds automatically; events and safelist rows
alone do not require adoption.

For an existing deployment, back up PostgreSQL and stop the controller. Keep its
**original POP, backend and speaker endpoint** configured, then run the new binary
once:

```bash
prefixd --config /etc/prefixd --adopt-legacy-speaker
```

Choose the command for your installation, then start the controller normally.
The one-shot command applies migrations, records the original target assignment,
attaches previously unbound withdrawal requests, writes an adoption audit and
exits. It never connects to the speaker or starts the API or reconciliation loop.
It preserves each request's rule, actor, reason, timestamps, operation ID,
completion state and enforced/dry-run mode. Adoption does not acknowledge an
announcement or prove that the configured target is the original speaker; the
operator must verify that identity. Repeating it with the same configuration is
safe and does not duplicate the adoption audit.

`--adopt-legacy-speaker` cannot force an existing binding to a different target,
take another POP's target, or repair mismatched pending request ownership. Normal
startup also rejects unadopted legacy requests, even when all mitigations have
expired. Do not delete history or clear target IDs to make startup pass.

The identity includes the normalized backend, HTTP(S) or absolute Unix-socket endpoint and fixed `GLOBAL`
routing namespace. `sidecar` and `gobgp`, bare and explicit HTTP addresses, host
case, equivalent IPv6 spelling and default ports normalize consistently. Token
environment names/values, CA paths, timeouts and controller operation mode are
excluded. Endpoints containing userinfo, a query or fragment are rejected.
HTTP(S) path prefixes are rejected; a root slash is normalized. Rotating credentials therefore preserves ownership; changing the endpoint does
not. Config reload continues to leave the running POP, BGP settings and mode
unchanged. Restarting with a different target fails before any speaker connection.

Run one controller per POP and use each physical speaker target exclusively.
The binding does not recognize DNS aliases or prevent another tool from changing
the speaker. The [controller fence](#controller-fence-and-rolling-deploys) keeps
a second controller that shares the database in standby, but it cannot see a
controller using another database. Endpoint descriptors stay out of
health/settings responses, WebSocket messages and ownership errors.

### Drained target transfer

Changing the target is a separate maintenance operation. Back up the database.
While the original controller and speaker are still available, stop detector
input, withdraw all active intent and drain pending cleanup. Verify directly on
the original speaker that no owned rules remain, then **stop the controller**.
Do not run two controllers during this procedure. The database checks below cannot
prove remote deletion. The controller fence is keyed on the POP and target, so it
cannot fence a controller still running against the original target.

Inspect the existing binding with an administrative database connection:

```sql
SELECT b.pop, b.target_id, t.backend, t.endpoint, t.routing_namespace
FROM speaker_pop_bindings b JOIN speaker_targets t USING (target_id);
```

For a transfer that keeps the same POP, edit the values in this block: the POP,
expected old target UUID, normalized new backend/endpoint and operator name.
Use `gobgp` for either GoBGP mode spelling and an explicit HTTP(S) URL with the
trailing `/` for an endpoint without a path. Use the same address in the new
configuration. The block is one transaction and takes the same registration lock
as startup. It rejects active/pending mitigations, pending cleanup, unadopted
legacy requests, unresolved announcements and another POP's assigned target.

<!-- speaker-transfer-sql -->
```sql
DO $$
DECLARE
    transfer_pop TEXT := 'iad1';
    expected_old UUID := '00000000-0000-0000-0000-000000000001';
    new_backend TEXT := 'gobgp';
    new_endpoint TEXT := 'http://new-speaker.example:50051/';
    operator_name TEXT := 'jsmith';
    new_target UUID;
BEGIN
    LOCK TABLE speaker_pop_bindings IN SHARE ROW EXCLUSIVE MODE;
    IF NOT EXISTS (SELECT 1 FROM speaker_pop_bindings
                   WHERE pop = transfer_pop AND target_id = expected_old) THEN
        RAISE EXCEPTION 'original speaker binding changed or is missing';
    END IF;
    IF EXISTS (SELECT 1 FROM mitigations WHERE pop = transfer_pop
               AND status IN ('pending', 'active', 'escalated'))
       OR EXISTS (SELECT 1 FROM withdrawal_requests WHERE pop = transfer_pop
                  AND (completed_at IS NULL OR target_id IS NULL))
       OR EXISTS (SELECT 1 FROM flowspec_announcements WHERE pop = transfer_pop
                  AND status <> 'withdrawn') THEN
        RAISE EXCEPTION 'speaker state must be fully drained and adopted first';
    END IF;
    INSERT INTO speaker_targets (target_id, backend, endpoint, routing_namespace)
    VALUES (gen_random_uuid(), new_backend, new_endpoint, 'GLOBAL')
    ON CONFLICT (backend, endpoint, routing_namespace) DO NOTHING;
    SELECT target_id INTO STRICT new_target FROM speaker_targets
    WHERE backend = new_backend AND endpoint = new_endpoint
      AND routing_namespace = 'GLOBAL';
    IF EXISTS (SELECT 1 FROM speaker_pop_bindings
               WHERE target_id = new_target AND pop <> transfer_pop) THEN
        RAISE EXCEPTION 'new speaker target belongs to another POP';
    END IF;
    UPDATE speaker_pop_bindings SET target_id = new_target
    WHERE pop = transfer_pop AND target_id = expected_old;
    INSERT INTO audit_log
        (audit_id, timestamp, actor_type, actor_id, action, target_type, target_id, details_json)
    VALUES
        (gen_random_uuid(), now(), 'operator', operator_name, 'transfer_speaker_target',
         'speaker_target', new_target::text,
         json_build_object('pop', transfer_pop, 'old_target_id', expected_old,
                           'new_target_id', new_target)::text);
END;
$$;
```
<!-- /speaker-transfer-sql -->

Set the stopped controller's configuration to the new target and start normally;
no adoption flag is needed. Verify startup, the selected speaker and the first
reconciliation pass before resuming detector input. The original target identity
and completed withdrawal rows remain unchanged. Completed history may reference
the old target; a pending request referencing a different target always blocks
startup and execution. Do not rewrite old target rows, rebind completed requests,
or delete audit/history to perform a transfer. Changing the POP itself needs a
separately reviewed state migration; this procedure keeps its identity intact.

## Speaker capability metadata

Health detail now includes additive `speaker.backend` and
`speaker.capabilities.{rule_reader,peer_observer}` metadata. Keep accepting the
legacy `gobgp` and `bgp_sessions` fields; the component name does not select the
backend. Treat `gobgp.status: unsupported` as unavailable optional observation,
`error` as a failed supported read, and `connected` with an empty peer map as a
successful read with no peers. Updated CLI/dashboard clients accept responses
from older daemons that omit `speaker`.

All selectable adapters still support both observations. Normal builds include
rustbgpd and GoBGP; set `bgp.backend` explicitly. An unset backend
[resolves from the configured endpoint](../reference/configuration.md#bgp).
External Rust implementations must implement `FlowSpecWriter` and
`FlowSpecAnnouncer`, then opt into `FlowSpecReader` and `PeerObserver` through the
facade accessors where supported. Import those traits for concrete adapter calls.
A production write-only backend remains gated on a durable announcement ledger.

## rustbgpd minimum version

prefixd requires rustbgpd 0.79.0 or later. At startup it reads the version
that rustbgpd's `GetHealth` reports and exits before reading or writing any
intent if the daemon is older or reports no readable version:

```text
rustbgpd 0.78.0 is older than the minimum 0.79.0; upgrade the speaker first
```

Upgrade rustbgpd before prefixd. A rustbgpd restart drops its injected rules;
the running controller re-adds desired rules on its next reconciliation poll.
Then upgrade prefixd as usual. Don't roll rustbgpd back below 0.79.0 under a
newer prefixd: the next start refuses, and a running controller treats the
lease RPCs as unsupported, so leased adds fail and create nothing. GoBGP is
unaffected.

## Controller fence and rolling deploys

Each controller derives a stable owner, `prefixd.<pop>.<hash>`, from its POP and
registered speaker target, and holds a PostgreSQL session advisory lock keyed on
it ([ADR 027](../adr/027-blackhole-mitigations.md)). The lock lives on one
dedicated connection outside the pool, named `prefixd-controller-fence` in
`pg_stat_activity`. The controller tries it after target registration and before
connecting to the speaker.

- **Standby.** A controller without the lock runs no scheduler, expiry,
  reconciliation, announcement or withdrawal. `POST`, `PUT` and `DELETE`
  requests on authenticated API routes return `503`; reads still work.
  `GET /v1/health` stays `ok`, `GET /v1/ready` returns `503`,
  `GET /v1/health/detail` reports `"status": "standby"` and
  `prefixd_controller_fence_active` is `0`. It retries the lock every 5
  seconds.
- **Routing.** Load balancers and detector routing must use `GET /v1/ready`,
  which returns `200` only on the controller holding the fence and not
  draining. `GET /v1/health` stays liveness and is `200` on a standby or
  draining controller, so routing by it would send detector events to a
  controller that refuses them. Set the readiness check interval shorter than
  `shutdown.drain_timeout_seconds`.
- **One-shot maintenance.** `--adopt-legacy-speaker` and
  `--retire-dry-run-intent` take the same lock once and refuse with "another
  controller holds the fence for owner …; stop it first" while a controller
  holds it. Stop the controller, run the command, then start the controller.
- **Restarts and rolling deploys.** Process exit closes the fence session and
  releases the lock; the old process keeps it through its shutdown drain, but
  `GET /v1/ready` returns `503` with `"draining"` from the moment the shutdown
  signal arrives. A replacement started while the old process runs waits in
  standby, takes over within one poll interval of the old process exiting, and
  reconciles at once.
- **Lock loss.** The holder checks its fence session every 2 seconds with a
  2-second timeout. After a failed check or a PostgreSQL restart it stops
  starting speaker mutations, enters standby and reacquires on a new
  connection. An RPC already in flight runs to its own deadline; its result is
  recorded only if the database write succeeds, otherwise the announcement
  stays unconfirmed or the withdrawal stays pending with its original rule,
  actor, reason and operation ID. A process that lost the lock without seeing
  it can keep issuing RPCs for up to about 4 seconds plus one RPC deadline.
- **Crashed hosts.** PostgreSQL holds a crashed host's lock until it ends that
  session. The fence session sets server-side TCP keepalives (10 seconds idle,
  then three probes 5 seconds apart) to bound the delay; do not block them
  between the controller and PostgreSQL.
- **Connection.** The connection must be direct or through a session-mode
  pooler. See [deployment](deployment.md#controller-fence-connection).

The fence does not replace the one-controller rule. It sees only controllers
that share one database, it is keyed on the POP and target so changing either
changes the lock, and it does not stop other tools writing to the speaker. Keep
one controller per POP and speaker target, and follow the
[drained target transfer](#drained-target-transfer) before changing the POP or
target.

## Pending withdrawals and rollback

Migration 013 adds durable withdrawal requests. A failed or uncertain deletion
is retried against the same speaker without waiting for the mitigation TTL.
Restarting the controller preserves the original operation, actor and reason.
Requests also retain whether they require a real speaker deletion. Switching to
dry-run leaves enforced-mode requests pending; returning to enforced mode retries
them. Requests originally made in dry-run remain local simulations. Existing
queue rows conservatively require a real deletion.

Run one controller per POP/speaker target. The in-process lifecycle mutex
releases between scheduler rules so operator requests can proceed between
repairs. Across processes, the
[controller fence](#controller-fence-and-rolling-deploys) keeps a second
controller that shares the database in standby.

Before changing the POP, backend, speaker endpoint or controller ownership, or
downgrading to a binary that does not understand this queue, drain pending
requests on the original target. Check PostgreSQL:

```sql
SELECT pop, count(*) AS pending
FROM withdrawal_requests
WHERE completed_at IS NULL
GROUP BY pop;
```

No rows means there are no pending requests. Keep the current controller and
original target available until cleanup succeeds, then verify that speaker's
local intent before proceeding. Do not delete queue rows to bypass cleanup.
An older binary ignores the queue and could reannounce a requested deletion;
a different target cannot confirm cleanup on the original speaker.

Before switching an enforced deployment to dry-run, withdraw its active rules
and drain pending cleanup on the original speaker. A mitigation records the mode
that admitted it, not whether the speaker accepted it; dry-run cannot infer or
remove that speaker state. Verify the original speaker's local intent before
changing modes.

Legacy rows can share a canonical rule despite different IPv6 spelling. A live
owner prevents deletion by an expired sibling. Once all owners have expired,
ordinary idempotent TTL cleanup retires each row. New manual creation rejects
an owned canonical scope before RPC; detector events extend exactly one owner
and reject ambiguous ownership without consuming their external event ID.

## Amplification matches and downgrade

Releases after 0.20.0 can install FlowSpec rules with source-port,
non-first-fragment and packet-length matches
([ADR 028](../adr/028-amplification-matches.md)), from `udp_amplification`
playbooks or manual `POST /v1/mitigations` requests. Their saved rule and
pending withdrawal JSON carries `src_ports`, `fragment` or `packet_length`.

0.20.0 and earlier silently ignore those keys. Such a binary would withdraw a
pending amplification rule using the wider key without them. The speaker
answers that the wider rule is absent, the older binary records the withdrawal
as done, and the real rule stays on the speaker with no owner. Never run 0.20.0
or earlier while any of these rules or their withdrawals are outstanding.

Before downgrading to 0.20.0 or earlier:

1. Pause detectors and remove `udp_amplification` playbooks and `rules` steps,
   so no new amplification rule is created.
2. Withdraw every live amplification rule on the current release. This lists
   them:

   ```sql
   SELECT mitigation_id, pop, victim_ip
   FROM mitigations
   WHERE status IN ('pending', 'active', 'escalated')
     AND match_json::jsonb ?| array['src_ports', 'fragment', 'packet_length'];
   ```

3. Drain their withdrawals on the original speaker target with the current
   release still running. This must return no rows:

   ```sql
   SELECT pop, count(*) AS pending
   FROM withdrawal_requests
   WHERE completed_at IS NULL
     AND rule_json::jsonb -> 'nlri' ?| array['src_ports', 'fragment', 'packet_length']
   GROUP BY pop;
   ```

4. Verify the speaker's local FlowSpec intent holds no rule with a source
   port, fragment or packet-length component, then follow the general
   [rollback](#rollback) steps. Do not delete rows to bypass cleanup.

Withdrawn and expired rows are safe for the speaker. Manual amplification
rules use the `unknown` vector, which older releases decode, so step 2 selects
rules by match rather than by vector. Older releases refuse to decode rows with
the `udp_amplification` vector, so pages that include them fail closed there.

## Mitigation origin mode

Migration 015 adds `origin_mode` to mitigations. Each new mitigation records the
mode that admitted it, `dry-run` or `enforced`. The value describes intent, not
speaker acceptance, and the migration writes no announcement records.

Rows created before the migration have no recorded origin. On the first start
after it, prefixd tags this POP's pending, active and escalated rows with the
configured `mode` and writes one system `tag_origin_mode` audit entry with the
count. Withdrawn, expired and rejected rows keep an unknown origin, and tagging
doesn't change a row's revision, so pending withdrawals still complete. The tag
assumes those rows were created in the mode you start with. That's why you
upgrade without changing `mode`. If you can't, withdraw live rehearsal
mitigations with the old binary first.

A dry-run mitigation is never desired speaker state:

- Reconciliation never announces it, in either mode.
- Its withdrawal or TTL expiry completes locally, with no speaker deletion.
- In enforced mode, a detector event for its rule returns `409` instead of
  extending the simulation. The event isn't stored, so the detector can retry it.

Enforced startup refuses to run while this POP has an unexpired dry-run
mitigation without a pending withdrawal. The error names the count and the flag.
Keep the configuration, stop the controller and run the new binary once:

```bash
prefixd --config /etc/prefixd --retire-dry-run-intent
```

The one-shot command applies migrations, then saves and completes a local-only
withdrawal for each such mitigation, with the system actor
`retire-dry-run-intent` and a fixed reason. Each one writes the usual `withdraw`
audit entry. It exits without connecting to the speaker or starting the API or
reconciliation loop. Repeating it retires nothing new. Then start normally.
Expired dry-run rows and pending dry-run withdrawals don't block startup; the
scheduler completes them locally.

prefixd reads `mode` only at startup. `POST /v1/config/reload` doesn't change
it, so every mode switch passes through this check.

With [leased blackholes](../reference/configuration.md#leased-blackholes), a
dry-run controller never renews the injection lease, because renewal is a
speaker mutation. Switching an enforced leased controller to dry-run
therefore lets its leased blackholes lapse at the speaker within
`blackhole.lease_seconds`, while the enforced rows stay in the database.
Withdraw them first, then switch the mode.

Downgrading below this release removes the protection: an older binary ignores
`origin_mode`, and in enforced mode its reconciliation announces unexpired
dry-run mitigations. Retire dry-run intent before you downgrade. Rows an older
binary creates have no origin and are tagged at the next start.

This queue covers withdrawals. Durable create/replace intent and target/process
generation fencing remain separate work; it is not a complete announcement
ledger or an active-active controller protocol.

---

## Docker Compose Upgrade

These commands update a deployment already using the profiles and named volumes
below. An earlier stack with the `prefixd` service and `./configs` bind mount is
outside this procedure: its configuration is not imported, and its container
name conflicts with the new controller. Keep that deployment intact; do not run
these commands against it. Upgrade it with the
[v0.19.1 Compose route](#compose-keep-your-file-and-pin-the-image) instead.

Select exactly one profile and its matching controller service:

| Backend | Profile | Controller service | Main configuration |
| --- | --- | --- | --- |
| rustbgpd | `rustbgpd` | `prefixd-rustbgpd` | `configs/prefixd.yaml` |
| GoBGP | `gobgp` | `prefixd-gobgp` | `configs/prefixd-gobgp.yaml` |

The examples below use rustbgpd. For GoBGP, substitute both the profile and
controller service. Bare `docker compose up -d` does not select a controller.
Do not enable both profiles. Profile selection does not change an existing
database's speaker ownership binding.

Keep your existing configuration and image references before pulling code. The
checkout's main-config examples select different immutable targets; retain your
deployment's settings when updating them. Named configuration volumes are seeded
only when files are missing; updating a checkout does not replace persisted
inventory or playbooks. Never use `down -v` during an upgrade.

For published images, select the controller and dashboard references you have
qualified. The same `PREFIXD_IMAGE` also selects the initializer. Without explicit
overrides Compose uses moving `main` tags; see
[image selection](deployment.md#image-publication-and-selection).

```bash
# 1. Back up the database
docker compose exec -T postgres pg_dump -U prefixd prefixd > backup-$(date +%F).sql

# 2. Pull latest code
git pull origin main

# 3. Pull selected published images; do not build local source
docker compose --profile rustbgpd pull

# 4. Restart (prefixd applies migrations on startup)
docker compose --profile rustbgpd up -d --no-build

# 5. Verify
curl --fail http://localhost/v1/health
docker compose logs prefixd-rustbgpd
docker compose exec prefixd-rustbgpd prefixdctl migrations
```

Verify authenticated health, ownership, peer observation and reconciliation
before resuming inputs. Public liveness alone does not establish routing health.

For a source build, replace steps 3–4 with local image overrides. Keep these
values set for subsequent Compose commands:

```bash
export PREFIXD_IMAGE=prefixd:local
export PREFIXD_DASHBOARD_IMAGE=prefixd-dashboard:local
docker compose --profile rustbgpd build
docker compose --profile rustbgpd up -d --pull missing --no-build
```

The build supplies the local controller/initializer and dashboard tags; startup
can still pull missing speaker and infrastructure images.

### Controller restart

Replacing only the controller can preserve the independent speaker's sessions:

1. Pull the selected published image, or build it with the local overrides above,
   while the old controller is running.
2. Run `docker compose --profile rustbgpd up -d --no-deps --no-build prefixd-rustbgpd`
   to replace only the controller. For GoBGP, use profile `gobgp` and service
   `prefixd-gobgp`. If GoBGP itself is recreated, recreate both the namespace
   owner and controller together:
   `docker compose --profile gobgp up -d --no-build --force-recreate gobgp prefixd-gobgp`.
3. Verify API availability, ownership, speaker observation and reconciliation
   after startup; no fixed recovery time is guaranteed.
4. The speaker may retain announcements while prefixd restarts. Application TTL
   expiry pauses during controller downtime and resumes with reconciliation.

The API is unavailable during replacement and rules can outlive their deadlines
until cleanup resumes. This is not a zero-downtime or automatic fail-open promise.

---

## Bare Metal Upgrade

```bash
# 1. Back up the database
pg_dump -U prefixd prefixd > backup-$(date +%F).sql

# 2. Build new version
git pull origin main
cargo build --release

# 3. Stop the daemon
sudo systemctl stop prefixd

# 4. Install new binary
sudo cp target/release/prefixd /usr/local/bin/
sudo cp target/release/prefixdctl /usr/local/bin/

# 5. Start (migrations run automatically)
sudo systemctl start prefixd

# 6. Verify
prefixdctl status
prefixdctl migrations
```

---

## Rollback

Keep the previous binaries/images and configuration before upgrading. A downgrade
needs explicit compatibility with the current schema, desired intent, durable
withdrawal queue and speaker ownership rules. An additive migration or
`IF NOT EXISTS` does not establish that compatibility: an old binary can ignore
new cleanup state and reannounce a requested deletion.

Pause inputs, drain pending cleanup on the original target, verify local and
receiving-peer state, and stop the controller before any supported downgrade.
Keep history and immutable target references when changing backend or endpoint.

A database restore does not undo speaker mutations. It can resurrect older
Active rows or lose pending withdrawals. Treat database disaster recovery as a
separate coordinated restoration of controller and speaker state, with an
explicitly reviewed version/state recovery plan; do not restore a backup as the
routine undo step for a speaker switch.

---

## Checking Migration Status

After an upgrade, confirm all migrations applied. This CLI command connects
directly to PostgreSQL using `DATABASE_URL`; it does not query the HTTP API:

```bash
# DATABASE_URL must point to this deployment's database.
prefixdctl migrations
```

---

## Version-Specific Notes

### v0.20.0 → 0.21.0

This upgrade needs rustbgpd 0.79.0 and applies migrations 016–018. It needs
no adoption step. Keep the POP, speaker target and `mode` unchanged, and
upgrade rustbgpd before prefixd. GoBGP deployments skip the rustbgpd step.

#### Before you start

1. **Back up PostgreSQL** and keep the 0.20.0 image or binaries and a copy of
   the configuration for the [rollback rules](#rollback).
2. **Review the configuration.** An unchanged 0.20.0 `prefixd.yaml` loads,
   with these exceptions and changed defaults:
   - With rustbgpd, `guardrails.max_ports` above 8 fails startup. The default
     is now 5, because FRR resets the session on a FlowSpec component with
     more than five values; an explicit value is kept.
   - The default `quotas.max_active_per_customer` rises from 5 to 20; an
     explicit value is kept. Active quotas now count only FlowSpec rules, and
     blackholes have their own `blackhole.max_active_per_pop` and
     `max_active_global`.
   - The new `blackhole` and `amplification` sections are optional. Blackholes
     stay off until `blackhole.enabled: true`.
   - The leased modes, `blackhole.leased` and `bgp.rustbgpd.leased_flowspec`,
     are off by default. Turn them on as a separate change after this upgrade
     is verified; see [leased blackholes](../reference/configuration.md#leased-blackholes)
     and [leased FlowSpec](../reference/configuration.md#leased-flowspec).
     Rules added before the change stay unleased.
3. **Prepare for the controller fence.** The database connection must be
   direct or through a session-mode pooler, and load balancers and detector
   routing should use `GET /v1/ready`; see
   [controller fence and rolling deploys](#controller-fence-and-rolling-deploys).
4. **Prepare rustbgpd.** Remove any `[event_history]` section from its
   configuration, which 0.79.0 no longer loads, and update your own rustbgpd
   dashboards and alerts for its renamed `family` labels. If you will use
   blackholes, check the receiving routers' RPKI policy first; see the
   [RPKI filters](../reference/configuration.md#blackhole) warning.

#### Compose

Run these in the deployment's checkout, keeping your configuration files and
image references. Step 3 leaves the 0.20.0 controller running:

```bash
# 1. Back up the database
docker compose exec -T postgres pg_dump -U prefixd prefixd > backup-$(date +%F).sql

# 2. Update the checkout; it pins rustbgpd 0.79.0
git fetch --tags && git checkout v0.21.0

# 3. Upgrade only rustbgpd
docker compose --profile rustbgpd pull rustbgpd
docker compose --profile rustbgpd up -d --no-deps rustbgpd
```

The new rustbgpd process starts with an empty local RIB. The running 0.20.0
controller repairs every active rule on its next reconciliation pass, within
`timers.reconciliation_interval_seconds` (30 by default), and logs
`repairing local announcement` for each. Rules are not announced until then.
Wait for that pass and check that the local RIB holds your active rules
([commands below](#check-the-upgrade)) before you continue:

```bash
# 4. Pin and pull the 0.21.0 controller and dashboard
export PREFIXD_IMAGE=ghcr.io/lance0/prefixd:0.21.0
export PREFIXD_DASHBOARD_IMAGE=ghcr.io/lance0/prefixd-dashboard:0.21.0
docker compose --profile rustbgpd pull prefixd-rustbgpd dashboard

# 5. Replace the controller and dashboard; rustbgpd keeps its routes
docker compose --profile rustbgpd up -d --no-deps --no-build prefixd-rustbgpd dashboard
```

Keep both variables set for later Compose commands, or put them in `.env`.
Recreate Prometheus as well to load the new alert rules.

#### Bare metal

Upgrade rustbgpd to 0.79.0 as its release notes describe and wait for one
reconciliation pass of the running 0.20.0 controller, as above. Then:

```bash
pg_dump -U prefixd prefixd > backup-$(date +%F).sql
git fetch --tags && git checkout v0.21.0
cargo build --release --locked
sudo systemctl stop prefixd
sudo cp target/release/prefixd target/release/prefixdctl /usr/local/bin/
sudo systemctl start prefixd
```

#### Check the upgrade

Check these before you resume detector input. Compose commands are shown; on
bare metal, run `prefixdctl`, `psql` and `rbgp` directly.

```bash
# Startup: migrations applied, fence held, no errors
docker compose logs prefixd-rustbgpd
# Expect: database migrations applied, versions: [1, ..., 18]
#         controller fence acquired

# Migrations 016-018 are listed
docker compose exec prefixd-rustbgpd prefixdctl migrations

# Health: status healthy, not standby; daemon version 0.79.0;
# peer observation connected
docker compose exec prefixd-rustbgpd prefixdctl --api http://127.0.0.1:8080 status

# The same mitigation IDs are still active
docker compose exec -T postgres psql -U prefixd -d prefixd -c \
  "SELECT mitigation_id, victim_ip, status FROM mitigations WHERE status IN ('pending', 'active', 'escalated');"

# Reconciliation: after one interval, no repairs and no failures
docker compose logs prefixd-rustbgpd | grep -E 'repairing local announcement|reconciliation (stage )?failed'

# rustbgpd's local FlowSpec intent matches the active mitigations
docker compose exec rustbgpd rbgp --addr unix:///run/rustbgpd/grpc.sock \
  --json flowspec received 0.0.0.0 --family ipv4_flowspec
```

The grep should print nothing from the 0.21.0 controller. `prefixdctl status`
needs `auth.mode: none` or a bearer token in `PREFIXD_API_TOKEN`, as before.

#### Downgrading to 0.20.0

0.20.0 understands neither blackhole rows, injection owners nor amplification
matches. Before you downgrade, pause detectors, remove blackhole and
`udp_amplification` playbooks, withdraw every blackhole, every leased
FlowSpec rule and every
[amplification rule](#amplification-matches-and-downgrade), and drain their
withdrawals on the original speaker target with 0.21.0 still running. This
must return no rows:

```sql
SELECT mitigation_id, action_type, status
FROM mitigations
WHERE status IN ('pending', 'active', 'escalated')
  AND (action_type = 'blackhole' OR match_json::jsonb ?| array['src_ports', 'fragment', 'packet_length']);
```

Turn the leased modes off, then follow the [rollback](#rollback) steps. A
downgraded controller needs rustbgpd 0.78.0 or later; 0.20.0 does not check
the version and works with 0.79.0.

### v0.19.1 → 0.20.0

This upgrade applies migrations 013–015, needs a one-time speaker ownership
adoption and changes how the configuration is read. Run it as one maintenance
step: keep the same POP, speaker, endpoint and `mode`, and change nothing else.

#### Before you start

1. **Back up PostgreSQL** (commands below). Keep the v0.19.1 binary or image and
   a copy of the configuration directory for the
   [rollback rules](#rollback).
2. **Keep `mode` unchanged.** Migration 015 tags live mitigations with the mode
   of the first start; see [mitigation origin mode](#mitigation-origin-mode).
3. **Keep the speaker.** v0.19.1 always used GoBGP (`bgp.mode: sidecar`, or no
   `bgp.mode` at all). Keep `bgp.gobgp_grpc` exactly as it is: ownership
   adoption records that endpoint as this POP's speaker.
4. API clients must drop saved pagination cursors. Mitigation, event, audit
   and signal-group cursors from v0.19.1 now return `400`; request the first page
   again without `cursor`. Settings JSON no longer includes the removed keys.
5. Source builds need Rust 1.89 or later and `protoc`. The container build pins
   its own toolchain.

#### Configuration changes

An unchanged v0.19.1 `prefixd.yaml` loads. The upgraded controller stays on
GoBGP, logs one warning per [removed key](../reference/configuration.md#removed-keys)
with `rejected_in: "0.21.0"`, then stops before contacting the speaker:

```text
WARN prefixd: deprecated configuration: removed configuration key is ignored; delete it, key: "observability.audit_log_path", rejected_in: "0.21.0"
Error: conflict: legacy speaker state requires explicit original-target adoption with --adopt-legacy-speaker
```

Edit the file before adoption so that 0.21.0 also loads it:

- Delete `escalation`, `http.auth.ldap`, `http.auth.radius`,
  `timers.correlation_window_seconds`, `observability.audit_log_path`,
  `observability.metrics_listen` and `shutdown.preserve_announcements`.
- Replace `bgp.mode: sidecar` with `bgp.backend: gobgp`, or add
  `backend: gobgp` if `bgp` has no `mode`. Both spellings are the same speaker
  identity. Without either, a file with `gobgp_grpc` still resolves to GoBGP,
  with a `bgp.backend` warning; see [backend resolution](../reference/configuration.md#bgp).
- Leave `pop`, `mode`, `bgp.gobgp_grpc` and everything else as they are.

For the shipped v0.19.1 file the change is:

```diff
 bgp:
-  mode: sidecar
+  backend: gobgp
   gobgp_grpc: "gobgp:50051"
@@ timers
-  correlation_window_seconds: 300
-escalation:
-  enabled: true
-  min_persistence_seconds: 120
-  min_confidence: 0.7
@@ observability
-  audit_log_path: "./data/audit.jsonl"
-  metrics_listen: "0.0.0.0:9090"
@@ shutdown
-  preserve_announcements: true
```

#### Compose: keep your file and pin the image

A v0.19.1 checkout runs the `prefixd` service from `build: .` with `./configs`
bind-mounted at `/etc/prefixd`. The 0.20.0 `docker-compose.yml` replaces that
layout with profiles and named volumes, so keep the v0.19.1 checkout and its
`docker-compose.yml`. Don't pull the new checkout into this directory yet. Run
these commands in the v0.19.1 checkout:

```bash
# 1. Back up the database and the configuration
docker compose exec -T postgres pg_dump -U prefixd prefixd > backup-$(date +%F).sql
cp -a configs configs-v0.19.1

# 2. Pin the 0.20.0 controller and dashboard images
cat > docker-compose.override.yml <<'EOF'
services:
  prefixd:
    image: ghcr.io/lance0/prefixd:0.20.0
  dashboard:
    image: ghcr.io/lance0/prefixd-dashboard:0.20.0
EOF
docker compose pull prefixd dashboard

# 3. Stop only the controller; GoBGP keeps running with its routes
docker compose stop prefixd

# 4. Edit configs/prefixd.yaml as described above, then adopt the speaker once
docker compose run --rm --no-deps prefixd --config /etc/prefixd --adopt-legacy-speaker

# 5. Start the controller and dashboard on the pinned images
docker compose up -d --no-deps --no-build prefixd dashboard
```

To build the images from source instead, build them from a 0.20.0 checkout in
another directory, use those tags in the override and skip `docker compose pull`:

```bash
docker build -t prefixd:0.20.0 /path/to/prefixd-0.20.0
docker build -t prefixd-dashboard:0.20.0 /path/to/prefixd-0.20.0/frontend
```

The 0.20.0 image runs as UID 999 instead of root. The controller must be able
to read `./configs`; the default `0644` file mode is enough. Dashboard
configuration saves also need write access to the directory, for example
`sudo chown -R 999:999 configs`. Otherwise saves fail and leave the files
unchanged.

Adoption applies the migrations, binds the POP to `http://gobgp:50051/`, writes
an `adopt_speaker_target` audit entry and exits without connecting to GoBGP.
Don't run `docker compose down`, and don't recreate the `gobgp` service. A new
GoBGP process starts with an empty RIB.

#### Bare metal

```bash
pg_dump -U prefixd prefixd > backup-$(date +%F).sql
sudo cp -a /etc/prefixd /etc/prefixd.v0.19.1
git fetch --tags && git checkout v0.20.0
cargo build --release --locked
sudo systemctl stop prefixd
sudo cp target/release/prefixd target/release/prefixdctl /usr/local/bin/
# Edit /etc/prefixd/prefixd.yaml as described above, then adopt the speaker once,
# as the service user and with the service's DATABASE_URL:
prefixd --config /etc/prefixd --adopt-legacy-speaker
sudo systemctl start prefixd
```

#### Verify

Check these before you resume detector input. Compose commands are shown; on
bare metal, run `prefixdctl` and `psql` directly.

```bash
# Startup: migrations applied, GoBGP selected, origin tagging, no errors
docker compose logs prefixd
# Expect: database migrations applied, versions: [1, ..., 15]
#         tagged live mitigations of unknown origin with the startup mode
#         selecting BGP speaker, mode: Gobgp

# Migrations 013-015 are listed
docker compose exec prefixd prefixdctl migrations

# Health: status healthy, Speaker: gobgp, peer observation connected
docker compose exec prefixd prefixdctl --api http://127.0.0.1:8080 status

# Ownership: one binding for your POP, backend gobgp, your original endpoint
docker compose exec -T postgres psql -U prefixd -d prefixd -c \
  "SELECT b.pop, t.backend, t.endpoint FROM speaker_pop_bindings b JOIN speaker_targets t USING (target_id);"

# Live mitigations are intact and tagged with your mode
docker compose exec -T postgres psql -U prefixd -d prefixd -c \
  "SELECT mitigation_id, victim_ip, status, origin_mode FROM mitigations WHERE status IN ('pending', 'active', 'escalated');"

# Reconciliation: after one interval, no failures are logged
docker compose logs prefixd | grep -E 'reconciliation (stage )?failed'
```

The last command should print nothing. `prefixdctl status` reads authenticated
health detail: it needs `auth.mode: none` or a bearer token in
`PREFIXD_API_TOKEN`. In `credentials` mode, check health in the dashboard
instead. If Prometheus scrapes the controller,
`prefixd_reconciliation_runs_total{status="success"}` increases. Compare the
GoBGP RIB with the active mitigations:

```bash
docker compose exec -T gobgp gobgp global rib -a ipv4-flowspec
```

Remove the deprecated keys now if you haven't already, since 0.21.0 rejects
them.

#### Switching to rustbgpd later

Switching speakers changes the POP's speaker target, so it's a separate
maintenance window. Run 0.20.0 on GoBGP first. Then:

1. Follow the [drained target transfer](#drained-target-transfer) on the
   original GoBGP target: stop detector input, withdraw all active intent, drain
   pending cleanup, verify the GoBGP RIB has no owned rules and stop the
   controller.
2. In the transfer block, set `new_backend` to `rustbgpd` and `new_endpoint` to
   the new configuration's normalized endpoint. For the Compose `rustbgpd`
   profile, that's `unix:///run/rustbgpd/grpc.sock`.
3. Configure `bgp.backend: rustbgpd` with that endpoint and start normally. No
   adoption flag is needed. For Compose, this is also the move to the
   [profile layout](#docker-compose-upgrade). Copy your current files out of
   the checkout with `cp -a configs ../prefixd-configs`. Run
   `docker compose down` (never `-v`; the same project keeps its
   `postgres-data` volume) and delete `docker-compose.override.yml`. Then
   update the checkout and set your settings in `configs/prefixd.yaml`, the
   `rustbgpd` profile's main file. The profile's named configuration volume is
   seeded from image defaults and doesn't import `./configs`, so import your
   files before you start the controller. Add `alerting.yaml` if you have one:

   ```bash
   docker compose --profile rustbgpd run --rm --no-deps init
   docker compose --profile rustbgpd run --rm --no-deps \
     -v "$PWD/../prefixd-configs:/import:ro" --entrypoint install init \
     -m 0600 -o 999 -g 999 /import/inventory.yaml /import/playbooks.yaml \
     /import/correlation.yaml /etc/prefixd/
   ```

Don't point a v0.19.1 configuration at rustbgpd, or change the GoBGP endpoint,
as part of this upgrade. Startup rejects a target that differs from the bound
one.

### v0.13.0 -> v0.14.0

#### New: Multi-Signal Correlation Engine

This release adds the correlation engine, signal adapters, and correlation dashboard. **No breaking changes** — correlation is opt-in.

##### New config file: `correlation.yaml`

Create `configs/correlation.yaml` (or add a `correlation:` section to `prefixd.yaml`). If the file is absent, correlation is disabled and behavior is identical to v0.13.0.

```yaml
# configs/correlation.yaml
enabled: true
window_seconds: 300
min_sources: 1          # Set to 2+ to require corroboration
confidence_threshold: 0.5
default_weight: 1.0
sources:
  fastnetmon:
    weight: 1.0
    type: detector
  alertmanager:
    weight: 0.8
    type: telemetry
```

With `min_sources: 1`, events flow through the correlation engine but mitigate immediately on the first signal — identical to pre-correlation behavior. Increase to 2+ to require corroboration from multiple detectors.

See [configuration.md#correlation](../reference/configuration.md#correlation) for full reference.

##### New database migration (007)

Migration 007 (`signal_groups`) runs automatically on startup. It adds:

- `signal_groups` table (group_id, victim_ip, vector, window, confidence, status)
- `signal_group_events` junction table
- `mitigations.signal_group_id` nullable FK column
- Two indexes for performance (victim/vector lookup, expiry sweep)

This historical migration adds tables and a nullable column. Current downgrade
safety still depends on every later migration and runtime contract; this entry
does not authorize running an old controller against current routing state.

##### New API endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /v1/signal-groups` | Yes | List signal groups (cursor pagination, status/vector/date filters) |
| `GET /v1/signal-groups/{id}` | Yes | Signal group detail with contributing events |
| `POST /v1/signals/alertmanager` | Yes | Alertmanager v4 webhook adapter |
| `POST /v1/signals/fastnetmon` | Yes | FastNetMon native JSON webhook adapter |
| `GET /v1/config/correlation` | Yes | Correlation config (secrets redacted) |
| `PUT /v1/config/correlation` | Admin | Update correlation config (validates, writes YAML, hot-reloads) |

##### New API response fields

- `GET /v1/mitigations` and `GET /v1/mitigations/{id}` responses now include an optional `correlation` field on correlated mitigations. Contains `signal_group_id`, `derived_confidence`, `source_count`, `corroboration_met`, `contributing_sources`, and `explanation`. This field is `null` for mitigations created without correlation. **Backward-compatible** — clients that don't read this field are unaffected.

##### Signal adapter integration

If you use **Alertmanager**, point a webhook receiver at `POST /v1/signals/alertmanager`. The adapter maps Alertmanager labels/annotations to attack event fields:

| Alertmanager Field | Maps To |
|--------------------|---------|
| `labels.instance` or `annotations.victim_ip` | `victim_ip` |
| `labels.vector` or `annotations.vector` | `vector` |
| `labels.severity` (critical/warning/info) | `confidence` (0.9/0.7/0.5) |
| `annotations.bps`, `annotations.pps` | Traffic metrics |
| `fingerprint` | Dedup key (idempotent) |

If you use **FastNetMon**, point the webhook notify URL at `POST /v1/signals/fastnetmon`. The adapter classifies vector from the traffic breakdown and maps `action` to confidence (ban=0.9, partial_block=0.7, alert=0.5).

Both adapters feed events through the full pipeline (correlation → policy → guardrails → announce).

##### New Prometheus metrics

| Metric | Type | Description |
|--------|------|-------------|
| `prefixd_signal_groups_total` | Counter | Total signal groups created |
| `prefixd_signal_group_sources` | Histogram | Source count distribution per group |
| `prefixd_correlation_confidence` | Histogram | Derived confidence distribution |
| `prefixd_corroboration_met_total` | Counter | Groups that met corroboration threshold |
| `prefixd_corroboration_timeout_total` | Counter | Groups that expired without corroboration |

##### Dashboard: Correlation page

The dashboard adds a `/correlation` page with three tabs:

- **Signals** — Recent events with source, confidence, and group assignment
- **Groups** — Signal groups with status, source count, confidence, corroboration
- **Config** — Visual correlation configuration editor

Plus a signal group detail page at `/correlation/groups/[id]` and a correlation context section on the mitigation detail page.

##### Historical Docker change: writable configuration

That release changed the checkout bind mount to writable so dashboard config
editors could save. Current profiles instead use a writable named directory with
a read-only main-file overlay. Follow the [current Compose procedure](#docker-compose-upgrade)
for selected-profile operations.

##### Upgrade steps

1. Back up the database (as always)
2. Add `configs/correlation.yaml` if you want correlation (optional — omit to keep existing behavior)
3. Rebuild and restart using the [current profile procedure](#docker-compose-upgrade).
4. Migration 007 runs automatically
5. Verify the correlation configuration using an authenticated operator session.
6. If using Alertmanager/FastNetMon, point webhook URLs at the new adapter endpoints
7. Tune `min_sources` and `confidence_threshold` to taste

### v0.11.0 -> v0.12.0

#### Breaking: Offset pagination removed

`GET /v1/mitigations`, `GET /v1/events`, and `GET /v1/audit` no longer accept the `offset` query parameter. Use cursor-based pagination instead. See [ADR 016](../adr/016-cursor-pagination.md) for rationale.

**Before (v0.11.0):**

```bash
# Page 1
curl '/v1/mitigations?limit=50&offset=0'
# Page 2
curl '/v1/mitigations?limit=50&offset=50'
```

**After (v0.12.0):**

```bash
# Page 1 (no cursor = first page)
curl '/v1/mitigations?limit=50'
# Response includes: {"mitigations": [...], "next_cursor": "MjAyNi0w...", "has_more": true}

# Page 2 (pass next_cursor from previous response)
curl '/v1/mitigations?limit=50&cursor=MjAyNi0w...'
```

If you use **prefixdctl**, replace `--offset` with `--cursor` or omit it for the first page.

If you have **custom scripts or integrations** that page through results with `offset`, update them to use the `next_cursor` value from each response. The cursor is an opaque base64 string — do not construct it manually.

#### Breaking: Audit response shape changed

`GET /v1/audit` now returns a wrapped object instead of a bare array:

```json
// Before: [{"id": "...", "action": "...", ...}, ...]
// After:  {"entries": [...], "count": 5, "next_cursor": "...", "has_more": false}
```

#### Other changes

- **New migration (005):** Adds `acknowledged_at` and `acknowledged_by` columns to mitigations table. Runs automatically on startup. Uses `IF NOT EXISTS` so safe to re-run.
- **New migration (006):** Adds `notification_preferences` table for per-operator toast settings. Runs automatically. FK to `operators` table.
- **New endpoint:** `POST /v1/mitigations/acknowledge` for bulk acknowledging mitigations.
- **New endpoint:** `GET/PUT /v1/preferences` for notification preferences (muted events, quiet hours). Quiet hours require both `start` and `end` or both `null` — partial configuration is rejected (400).
- **New query params:** `?start=`, `?end=` (ISO 8601) for date range filtering on all list endpoints. `?acknowledged=true|false` on mitigations.
- **Per-destination event routing:** Alerting destinations now accept an optional `events` array to override the global event filter. Existing configs without per-destination events are unaffected (backward-compatible, see [ADR 017](../adr/017-notification-routing-preferences.md)).
- **Frontend:** API hooks now return response objects (`{mitigations, count, next_cursor, has_more}`) instead of bare arrays. If you have custom frontend code consuming these hooks, update accordingly.
- No config file changes required. Existing `alerting.yaml` files work as-is.

### v0.10.1 -> v0.11.0

- **CVE gate in CI:** `cargo audit` and `bun audit` now gate Docker publishing. CycloneDX SBOM generated on version tags.
- **Vendor capability matrix:** New `docs/reference/vendors.md`.
- **Security fixes:** Next.js 16.1.7, undici 7.24.4, quinn-proto 0.11.14, rollup 4.59.0.
- **New features:** Bulk withdraw (`POST /v1/mitigations/withdraw`), FlowSpec rule preview on mitigation detail page.
- No database migrations required.
- No breaking API changes.

### v0.10.0 -> v0.10.1

- **FastNetMon integration fix:** Deterministic event IDs replaced with UUIDs. Unban now queries `GET /v1/mitigations?victim_ip=X` then withdraws, instead of constructing a deterministic ID.
- **New query param:** `victim_ip` on `GET /v1/mitigations`.
- No database migrations required.

### v0.9.1 -> v0.10.0

- **Playbook editor:** New `PUT /v1/config/playbooks` endpoint (admin-only). Config page now has form-based and raw YAML editors for playbooks. Playbooks are saved with atomic write + `.bak` backup.
- **Interactive alerting config:** New `PUT /v1/config/alerting` endpoint (admin-only). Alerting configuration moved from `prefixd.yaml` to standalone `alerting.yaml` (backward-compatible fallback). Config page alerting tab now supports add/edit/remove destinations with type-specific forms. Secrets preserved via `***` sentinel on update.
- **SSRF protection:** Webhook destination URLs now require HTTPS and reject localhost/private IPs.
- **Event cross-links:** Mitigation detail page shows clickable triggering and last event links.
- **GHCR publishing:** CI publishes Docker images to `ghcr.io` on push to main and version tags.
- No database migrations required
- No breaking API changes

### v0.9.0 -> v0.9.1

- **Security fixes:** Login brute-force throttle hardened (atomic check, bounded state), CIDR validation uses `ipnet::IpNet`, generic webhook headers redacted in API, alerting test endpoint admin-only, CSV formula regex strengthened
- **Webhook alerting:** New `src/alerting/` module with 7 destination types (Slack, Discord, Teams, Telegram, PagerDuty, OpsGenie, generic). Fire-and-forget dispatch with bounded concurrency (64 tasks). New endpoints: `GET /v1/config/alerting`, `POST /v1/config/alerting/test`
- **Dashboard:** Alerting config tab, audit log detail expansion, customer/POP filters, timeseries range selector (1h/6h/24h/7d), active count sidebar badge, severity badges
- **New config section:** Optional `alerting:` in prefixd.yaml (see example in config file)
- No database migrations required
- No breaking API changes

### v0.8.5 -> v0.9.0

- **New table:** `schema_migrations` (migration 004) -- tracks applied migrations
- **Reconciliation loop** now pages through all active mitigations (previously capped at 1000)
- **New metrics:** `prefixd_reconciliation_active_count`, `prefixd_db_pool_connections`
- **New endpoints:** `GET /v1/stats/timeseries`, `GET /v1/ip/{ip}/history`
- **prefixdctl default endpoint** changed from `http://127.0.0.1:8080` to `http://127.0.0.1` (nginx)
- **Timeseries bucketing fix** -- sub-hour buckets now align correctly
- No config file changes required
