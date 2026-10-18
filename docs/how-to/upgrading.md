# Upgrade Guide

## General Principles

- **Database migrations run automatically** on startup. Legacy speaker state also
  requires the explicit ownership adoption below before the upgraded daemon starts.
- Review configuration and ownership changes before upgrading; new defaults do
  not establish downgrade compatibility.
- PostgreSQL retains mitigation intent. Reconciliation checks eligible intent
  after restart; stored Active status does not prove router enforcement.
- The independent speaker can retain rules while prefixd is stopped. Application
  TTL cleanup pauses until the controller resumes.
- **Always back up the database** before upgrading.

For GoBGP↔rustbgpd changes with active intent, follow the
[maintenance cutover and rollback procedure](speaker-cutover.md).

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
# Compose: run the newly built image with the same config and database environment
docker compose run --rm --no-deps prefixd --config /etc/prefixd --adopt-legacy-speaker
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
This database binding does not fence another process, recognize DNS aliases or
prevent another tool from changing the speaker. Endpoint descriptors stay out of
health/settings responses, WebSocket messages and ownership errors.

### Drained target transfer

Changing the target is a separate maintenance operation. Back up the database.
While the original controller and speaker are still available, stop detector
input, withdraw all active intent and drain pending cleanup. Verify directly on
the original speaker that no owned rules remain, then **stop the controller**.
Do not run two controllers during this procedure. The database checks below cannot
prove remote deletion or fence a controller that is still running.

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

All selectable adapters still support both observations, and defaults are
unchanged. External Rust implementations must implement `FlowSpecWriter` and
`FlowSpecAnnouncer`, then opt into `FlowSpecReader` and `PeerObserver` through the
facade accessors where supported. Import those traits for concrete adapter calls.
A production write-only backend remains gated on a durable announcement ledger.

## Pending withdrawals and rollback

Migration 013 adds durable withdrawal requests. A failed or uncertain deletion
is retried against the same speaker without waiting for the mitigation TTL.
Restarting the controller preserves the original operation, actor and reason.
Requests also retain whether they require a real speaker deletion. Switching to
dry-run leaves enforced-mode requests pending; returning to enforced mode retries
them. Requests originally made in dry-run remain local simulations. Existing
queue rows conservatively require a real deletion.

Run one controller per POP/speaker target. The in-process lifecycle mutex does
not fence multiple controller processes. It releases between scheduler rules so
operator requests can proceed between repairs.

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
and drain pending cleanup on the original speaker. Older active mitigation rows
do not record whether they were announced in enforced mode; dry-run cannot infer
or remove that speaker state. Verify the original speaker's local intent before
changing modes.

Legacy rows can share a canonical rule despite different IPv6 spelling. A live
owner prevents deletion by an expired sibling. Once all owners have expired,
ordinary idempotent TTL cleanup retires each row. New manual creation rejects
an owned canonical scope before RPC; detector events extend exactly one owner
and reject ambiguous ownership without consuming their external event ID.

This queue covers withdrawals. Durable create/replace intent and target/process
generation fencing remain separate work; it is not a complete announcement
ledger or an active-active controller protocol.

---

## Docker Compose Upgrade

```bash
# 1. Back up the database
docker compose exec postgres pg_dump -U prefixd prefixd > backup-$(date +%F).sql

# 2. Pull latest code
git pull origin main

# 3. Rebuild containers
docker compose build

# 4. Restart (prefixd applies migrations on startup)
docker compose up -d

# 5. Verify
curl http://localhost/v1/health
docker compose logs prefixd | grep "database migrations applied"
```

### Controller restart

Replacing only the controller can preserve the independent speaker's sessions:

1. Build the new image while the old one is running
2. Run `docker compose up -d --no-deps prefixd` to replace only the prefixd container
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
Follow the [speaker maintenance procedure](speaker-cutover.md) when changing
backend or endpoint. Keep history and immutable target references.

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

##### Docker: Config volume now writable by default

The default `docker-compose.yml` now mounts `./configs:/etc/prefixd` (writable) so the dashboard config editors work out of the box. Previously it was `:ro`. If you have a customized `docker-compose.yml` with `:ro`, the `PUT /v1/config/correlation` endpoint (and playbooks/alerting PUT) will return 500. Either remove `:ro` or edit configs on the host and use `POST /v1/config/reload`.

##### Upgrade steps

1. Back up the database (as always)
2. Add `configs/correlation.yaml` if you want correlation (optional — omit to keep existing behavior)
3. Rebuild and restart: `docker compose build && docker compose up -d`
4. Migration 007 runs automatically
5. Verify: `curl http://localhost/v1/config/correlation` should return config (or defaults if no file)
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
