//! Startup migration bootstrap.
//!
//! `schema_migrations` is authoritative: a start applies only the versions the
//! database does not record. Each version runs in its own transaction together
//! with its tracking row, so an interrupted start resumes at that version
//! instead of replaying the history and its backfills. A session advisory lock
//! serializes concurrent controllers, and each migration sets a short
//! `lock_timeout` so it aborts and rolls back instead of parking
//! `ACCESS EXCLUSIVE` DDL, and every query behind it, while live traffic
//! drains.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use sqlx::{Connection, PgConnection, PgPool};

use crate::error::{PrefixdError, Result};

/// Embedded migrations in ascending version order.
///
/// Append-only: a released entry keeps its version and SQL text, because
/// databases already recorded it. Add a file and an entry instead of editing.
pub const MIGRATIONS: &[(i32, &str, &str)] = &[
    (
        1,
        "initial",
        include_str!("../../migrations/001_initial.sql"),
    ),
    (
        2,
        "operators_sessions",
        include_str!("../../migrations/002_operators_sessions.sql"),
    ),
    (
        3,
        "raw_details",
        include_str!("../../migrations/003_raw_details.sql"),
    ),
    (
        4,
        "schema_migrations",
        include_str!("../../migrations/004_schema_migrations.sql"),
    ),
    (
        5,
        "acknowledge",
        include_str!("../../migrations/005_acknowledge.sql"),
    ),
    (
        6,
        "notification_preferences",
        include_str!("../../migrations/006_notification_preferences.sql"),
    ),
    (
        7,
        "signal_groups",
        include_str!("../../migrations/007_signal_groups.sql"),
    ),
    (
        8,
        "signal_groups_open_unique",
        include_str!("../../migrations/008_signal_groups_open_unique.sql"),
    ),
    (
        9,
        "corroborating_signals",
        include_str!("../../migrations/009_corroborating_signals.sql"),
    ),
    (
        10,
        "corroborator_ingested_at",
        include_str!("../../migrations/010_corroborator_ingested_at.sql"),
    ),
    (
        11,
        "backfill_primary_dimensions",
        include_str!("../../migrations/011_backfill_primary_dimensions.sql"),
    ),
    (
        12,
        "signal_groups_playbook",
        include_str!("../../migrations/012_signal_groups_playbook.sql"),
    ),
    (
        13,
        "withdrawal_requests",
        include_str!("../../migrations/013_withdrawal_requests.sql"),
    ),
    (
        14,
        "speaker_targets",
        include_str!("../../migrations/014_speaker_targets.sql"),
    ),
    (
        15,
        "mitigation_origin_mode",
        include_str!("../../migrations/015_mitigation_origin_mode.sql"),
    ),
    (
        16,
        "withdrawal_rule_kind",
        include_str!("../../migrations/016_withdrawal_rule_kind.sql"),
    ),
    (
        17,
        "event_top_src_ports",
        include_str!("../../migrations/017_event_top_src_ports.sql"),
    ),
    (
        18,
        "event_ban_dedup_index",
        include_str!("../../migrations/018_event_ban_dedup_index.sql"),
    ),
    (
        19,
        "scrubber_diversions",
        include_str!("../../migrations/019_scrubber_diversions.sql"),
    ),
    (
        20,
        "event_outcomes",
        include_str!("../../migrations/020_event_outcomes.sql"),
    ),
];

/// The highest version this binary knows. A database recording a higher
/// version was migrated by a newer release, which this one refuses to run
/// against.
pub const LATEST_VERSION: i32 = MIGRATIONS[MIGRATIONS.len() - 1].0;

/// The migration that creates `schema_migrations` itself. It runs up front when
/// the table is absent, so every version can record itself in its own
/// transaction.
const TRACKING_VERSION: i32 = 4;

/// `pg_advisory_lock` key for the bootstrap: `prefixdm` in the single-bigint
/// form, which cannot collide with the two-integer repository quota lock or a
/// per-owner fence key.
const LOCK_KEY: i64 = 0x7072_6566_6978_646d;

/// How long a start waits for another instance's bootstrap before failing
/// instead of hanging. A crashed instance releases the lock with its session,
/// so the wait only covers a migration that is genuinely running.
const LOCK_WAIT: Duration = Duration::from_secs(300);
const LOCK_POLL: Duration = Duration::from_millis(200);

/// Bound a migration's wait for its own table locks. It covers the wait, not
/// the statement's work, so a long backfill still finishes while a migration
/// that cannot take `ACCESS EXCLUSIVE` promptly aborts and retries next start.
const LOCK_TIMEOUT: &str = "5s";

/// Catalog probes for the three migrations that predate version tracking.
///
/// Migration 004 created `schema_migrations`, so a database last started by an
/// older binary holds 001..003 with nothing recorded. Recording those versions
/// is safe only when their effects are visible in the catalog, so each is
/// probed directly; anything unproven is applied instead, which is always safe
/// because those files are idempotent. Later versions need no probe: the
/// tracking table records them, and re-running an unrecorded one is the
/// intended path.
const PRE_TRACKING_PROBES: &[(i32, &str)] = &[
    (
        1,
        "SELECT to_regclass('events') IS NOT NULL \
             AND to_regclass('mitigations') IS NOT NULL \
             AND to_regclass('flowspec_announcements') IS NOT NULL \
             AND to_regclass('audit_log') IS NOT NULL \
             AND to_regclass('safelist') IS NOT NULL \
             AND to_regclass('config_snapshots') IS NOT NULL",
    ),
    (
        2,
        "SELECT to_regclass('operators') IS NOT NULL \
             AND to_regclass('tower_sessions.session') IS NOT NULL",
    ),
    (
        3,
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = current_schema() AND table_name = 'events' \
                   AND column_name = 'raw_details') \
             AND EXISTS (SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = current_schema() AND table_name = 'events' \
                   AND column_name = 'action')",
    ),
];

/// Apply every embedded migration this database has not recorded yet.
pub async fn run(pool: &PgPool) -> Result<()> {
    debug_assert!(
        MIGRATIONS.windows(2).all(|pair| pair[1].0 == pair[0].0 + 1),
        "embedded migration versions are contiguous from 1"
    );
    let mut connection = pool.acquire().await?;
    acquire_lock(&mut connection).await?;
    let result = reconcile(&mut connection).await;
    release_lock(connection).await;
    result
}

/// Wait for the bootstrap lock a bounded time, then give up with an operator
/// action; a lock a live session holds never expires on its own.
async fn acquire_lock(connection: &mut PgConnection) -> Result<()> {
    let deadline = Instant::now() + LOCK_WAIT;
    let mut waiting = false;
    loop {
        let held: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(LOCK_KEY)
            .fetch_one(&mut *connection)
            .await?;
        if held {
            if waiting {
                tracing::info!("acquired the database migration lock");
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(PrefixdError::MigrationInProgress);
        }
        if !waiting {
            waiting = true;
            tracing::info!("another instance is migrating the database; waiting for it");
        }
        tokio::time::sleep(LOCK_POLL).await;
    }
}

/// Release the session lock before the pooled connection is reused. A session
/// that cannot release it is discarded, so the lock never leaks into later use.
async fn release_lock(mut connection: sqlx::pool::PoolConnection<sqlx::Postgres>) {
    let released = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
        .bind(LOCK_KEY)
        .fetch_one(&mut *connection)
        .await;
    match released {
        Ok(true) => {}
        Ok(false) => {
            tracing::error!("the database migration lock was not held at release");
            let _ = connection.close().await;
        }
        Err(error) => {
            tracing::error!(error = %error, "failed to release the database migration lock");
            let _ = connection.close().await;
        }
    }
}

/// Refuse an unknown-newer schema, adopt a pre-tracking schema, then apply the
/// remaining versions in ascending order.
async fn reconcile(connection: &mut PgConnection) -> Result<()> {
    // Every version records itself in its own transaction, so the table those
    // rows go into has to exist first. An existing table is left untouched,
    // which is why an up-to-date start runs no DDL at all.
    ensure_tracking_table(connection).await?;
    let mut recorded = recorded_versions(connection).await?;

    if let Some((&found, _)) = recorded.last_key_value() {
        if found > LATEST_VERSION {
            tracing::error!(
                recorded = found,
                known = LATEST_VERSION,
                "database schema is newer than this binary"
            );
            return Err(PrefixdError::SchemaNewerThanBinary {
                found,
                known: LATEST_VERSION,
            });
        }
    }
    for (version, name, _) in MIGRATIONS {
        match recorded.get(version) {
            Some(recorded_name) if recorded_name == name => {}
            Some(recorded_name) => tracing::warn!(
                version,
                recorded = %recorded_name,
                embedded = name,
                "recorded migration name differs from this binary's; the applied statement may differ"
            ),
            None => {}
        }
    }
    for version in recorded.keys() {
        if embedded(*version).is_none() {
            tracing::warn!(
                version,
                "database records a migration version this binary does not embed"
            );
        }
    }

    // Adopt a schema that predates tracking rather than replaying it.
    let mut adopted = Vec::new();
    for (version, probe) in PRE_TRACKING_PROBES {
        if recorded.contains_key(version) {
            continue;
        }
        let present: bool = sqlx::query_scalar(probe)
            .fetch_one(&mut *connection)
            .await?;
        if present {
            adopted.push(*version);
        }
    }

    let missing: Vec<(i32, &str, &str)> = MIGRATIONS
        .iter()
        .filter(|(version, _, _)| !recorded.contains_key(version) && !adopted.contains(version))
        .copied()
        .collect();

    for (version, name, sql) in &missing {
        apply(connection, *version, name, sql).await?;
    }

    // Migration 004 has now created the tracking table, if it was absent.
    for version in &adopted {
        let name = embedded(*version).map_or("pre_tracking", |entry| entry.1);
        record(connection, *version, name).await?;
        recorded.insert(*version, name.to_string());
        tracing::info!(
            version,
            name,
            "recorded a migration this database already had"
        );
    }

    for (version, name, _) in &missing {
        recorded.insert(*version, (*name).to_string());
    }

    tracing::info!(
        applied = missing.len(),
        adopted = adopted.len(),
        versions = ?recorded.keys().copied().collect::<Vec<_>>(),
        latest = LATEST_VERSION,
        "database migrations checked"
    );
    Ok(())
}

/// Create the empty tracking table when it is absent, so every version can
/// record itself in the transaction that applies it. Migration 004 owns the
/// statement; an existing table is left alone.
async fn ensure_tracking_table(connection: &mut PgConnection) -> Result<()> {
    let tracked: bool = sqlx::query_scalar("SELECT to_regclass('schema_migrations') IS NOT NULL")
        .fetch_one(&mut *connection)
        .await?;
    if tracked {
        return Ok(());
    }
    let sql = embedded(TRACKING_VERSION)
        .expect("the tracking migration is embedded")
        .2;
    let mut transaction = connection.begin().await?;
    sqlx::query(&format!("SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(sql).execute(&mut *transaction).await?;
    transaction.commit().await?;
    tracing::info!(
        version = TRACKING_VERSION,
        "created the migration tracking table"
    );
    Ok(())
}

/// The versions the database records.
async fn recorded_versions(connection: &mut PgConnection) -> Result<BTreeMap<i32, String>> {
    let rows: Vec<(i32, String)> =
        sqlx::query_as("SELECT version, name FROM schema_migrations ORDER BY version")
            .fetch_all(&mut *connection)
            .await?;
    Ok(rows.into_iter().collect())
}

/// Apply one migration and record it in the same transaction: either both
/// happen or the next start retries the version from its saved state.
async fn apply(connection: &mut PgConnection, version: i32, name: &str, sql: &str) -> Result<()> {
    let mut transaction = connection.begin().await?;
    sqlx::query(&format!("SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(sql).execute(&mut *transaction).await?;
    sqlx::query("INSERT INTO schema_migrations (version, name) VALUES ($1, $2)")
        .bind(version)
        .bind(name)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    tracing::info!(version, name, "applied database migration");
    Ok(())
}

async fn record(connection: &mut PgConnection, version: i32, name: &str) -> Result<()> {
    sqlx::query("INSERT INTO schema_migrations (version, name) VALUES ($1, $2)")
        .bind(version)
        .bind(name)
        .execute(connection)
        .await?;
    Ok(())
}

fn embedded(version: i32) -> Option<&'static (i32, &'static str, &'static str)> {
    MIGRATIONS.iter().find(|entry| entry.0 == version)
}
