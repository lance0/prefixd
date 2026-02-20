# Upgrade Guide

## General Principles

- **Database migrations run automatically** on startup. No manual SQL required.
- **Config files are backward compatible.** New fields have sensible defaults; old configs continue to work.
- **Mitigations survive restarts.** Active mitigations are stored in PostgreSQL and re-announced by the reconciliation loop after startup.
- **Always back up the database** before upgrading.

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

### Zero-Downtime Upgrade

For environments where downtime is unacceptable:

1. Build the new image while the old one is running
2. Run `docker compose up -d --no-deps prefixd` to replace only the prefixd container
3. The reconciliation loop will re-announce any rules within 30 seconds
4. Active mitigations are not affected (fail-open: GoBGP retains routes until explicitly withdrawn)

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

If an upgrade causes issues:

### Docker Compose

```bash
# Check out the previous version
git checkout v0.8.5  # or whatever the previous tag was

# Restore database (if migration changed schema)
docker compose exec -T postgres psql -U prefixd prefixd < backup-2026-02-20.sql

# Rebuild and restart
docker compose build
docker compose up -d
```

### Bare Metal

```bash
# Stop
sudo systemctl stop prefixd

# Restore database backup
psql -U prefixd prefixd < backup-2026-02-20.sql

# Install previous binary
sudo cp /path/to/previous/prefixd /usr/local/bin/

# Start
sudo systemctl start prefixd
```

> **Important:** Database migrations are forward-only. If a migration altered the schema, you must restore from backup to roll back. Migrations that only add tables or columns (using `IF NOT EXISTS`) are safe to roll back without a restore.

---

## Checking Migration Status

After an upgrade, confirm all migrations applied:

```bash
# CLI
prefixdctl migrations

# Expected output:
# VERSION   NAME                            APPLIED AT
# -----------------------------------------------------------------
# 1         initial                         2026-01-15 10:00:00
# 2         operators_sessions              2026-01-15 10:00:00
# 3         raw_details                     2026-01-28 12:00:00
# 4         schema_migrations               2026-02-20 10:00:00
#
# 4 migration(s) applied
```

---

## Version-Specific Notes

### v0.8.5 -> v1.0

- **New table:** `schema_migrations` (migration 004) -- tracks applied migrations
- **Reconciliation loop** now pages through all active mitigations (previously capped at 1000)
- **New metric:** `prefixd_reconciliation_active_count` gauge
- No config file changes required
