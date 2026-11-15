//! Startup migration bootstrap.
//!
//! `schema_migrations` is authoritative: a start applies only the versions the
//! database does not record. Each version runs in its own transaction together
//! with its tracking row, so an interrupted start resumes at that version
//! instead of replaying the history and its backfills. A session advisory lock
//! serializes concurrent controllers. Each migration attempt sets a short
//! `lock_timeout`, so `ACCESS EXCLUSIVE` DDL, and every query queued behind it,
//! waits a bounded time for a busy table; a few attempts with backoff ride out
//! a transient blocker before the start fails.

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

/// Bound one attempt's wait for its own table locks. It covers the wait, not
/// the statement's work, so a long backfill still finishes, while queries that
/// queue behind the pending `ACCESS EXCLUSIVE` request wait at most this long.
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(2);

/// Attempts per migration while another session holds a conflicting table
/// lock. With the backoff below, a start gives up after about 20 seconds.
pub const LOCK_ATTEMPTS: u32 = 5;
const RETRY_BASE: Duration = Duration::from_millis(250);

/// SQLSTATE `lock_not_available`, raised when `lock_timeout` expires.
const LOCK_NOT_AVAILABLE: &str = "55P03";
const LOCK_NOT_AVAILABLE_HINT: &str = "; another session held a conflicting lock on a table this migration alters on every attempt. While a start is retrying, `SELECT pid, pg_blocking_pids(pid), state, query FROM pg_stat_activity WHERE wait_event_type = 'Lock'` names the blocking sessions; let them finish or end them, then start again";

/// Apply every embedded migration this database has not recorded yet.
pub async fn run(pool: &PgPool) -> Result<()> {
    let mut connection = pool.acquire().await?;
    // The session lock lives as long as this session. Closing it on drop, never
    // returning it to the pool, keeps a cancelled start from leaving the lock
    // held by a pooled connection.
    connection.close_on_drop();
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

/// Release the session lock promptly. The connection closes when it drops, so
/// a failed release still ends with the session.
async fn release_lock(mut connection: sqlx::pool::PoolConnection<sqlx::Postgres>) {
    let released = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
        .bind(LOCK_KEY)
        .fetch_one(&mut *connection)
        .await;
    match released {
        Ok(true) => {}
        Ok(false) => tracing::error!("the database migration lock was not held at release"),
        Err(error) => {
            tracing::error!(error = %error, "failed to release the database migration lock");
        }
    }
}

/// Refuse an unknown-newer schema, then apply the unrecorded versions in
/// ascending order.
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

    // A database last started before version tracking holds 001..003 with
    // nothing recorded, so those replay here. Every statement in them is
    // `IF NOT EXISTS`, which leaves existing tables, columns, indexes and rows
    // as they are.
    let missing: Vec<&(i32, &str, &str)> = MIGRATIONS
        .iter()
        .filter(|(version, _, _)| !recorded.contains_key(version))
        .collect();
    for (version, name, sql) in &missing {
        apply(connection, *version, name, sql).await?;
        recorded.insert(*version, (*name).to_string());
    }

    tracing::info!(
        applied = missing.len(),
        versions = ?recorded.keys().copied().collect::<Vec<_>>(),
        latest = LATEST_VERSION,
        "database migrations checked"
    );
    Ok(())
}

/// Create the tracking table when it is absent, so every later version can
/// record itself in the transaction that applies it. An existing table is left
/// alone.
async fn ensure_tracking_table(connection: &mut PgConnection) -> Result<()> {
    let tracked: bool = sqlx::query_scalar("SELECT to_regclass('schema_migrations') IS NOT NULL")
        .fetch_one(&mut *connection)
        .await?;
    if tracked {
        return Ok(());
    }
    let (version, name, sql) =
        embedded(TRACKING_VERSION).expect("the tracking migration is embedded");
    apply(connection, *version, name, sql).await
}

/// The versions the database records.
async fn recorded_versions(connection: &mut PgConnection) -> Result<BTreeMap<i32, String>> {
    let rows: Vec<(i32, String)> =
        sqlx::query_as("SELECT version, name FROM schema_migrations ORDER BY version")
            .fetch_all(&mut *connection)
            .await?;
    Ok(rows.into_iter().collect())
}

/// Apply one migration, retrying a bounded number of times while its table
/// locks are busy. Every failed attempt rolls back completely.
async fn apply(
    connection: &mut PgConnection,
    version: i32,
    name: &'static str,
    sql: &str,
) -> Result<()> {
    let mut attempt = 1;
    loop {
        match apply_once(connection, version, name, sql).await {
            Ok(()) => {
                tracing::info!(version, name, attempt, "applied database migration");
                return Ok(());
            }
            Err(error) if is_lock_timeout(&error) && attempt < LOCK_ATTEMPTS => {
                let delay = retry_delay(attempt);
                tracing::warn!(
                    version,
                    name,
                    attempt,
                    retry_in_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                    "database migration could not take its table locks within lock_timeout; retrying"
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
            Err(source) => {
                let hint = if is_lock_timeout(&source) {
                    LOCK_NOT_AVAILABLE_HINT
                } else {
                    ""
                };
                let error = PrefixdError::MigrationFailed {
                    version,
                    name,
                    hint,
                    source,
                };
                tracing::error!(version, name, attempt, error = %error, "database migration failed");
                return Err(error);
            }
        }
    }
}

/// Run the migration and record it in the same transaction: either both
/// happen or the next attempt starts from the saved state.
async fn apply_once(
    connection: &mut PgConnection,
    version: i32,
    name: &str,
    sql: &str,
) -> std::result::Result<(), sqlx::Error> {
    let mut transaction = connection.begin().await?;
    sqlx::query(&format!(
        "SET LOCAL lock_timeout = '{}ms'",
        LOCK_TIMEOUT.as_millis()
    ))
    .execute(&mut *transaction)
    .await?;
    sqlx::raw_sql(sql).execute(&mut *transaction).await?;
    sqlx::query("INSERT INTO schema_migrations (version, name) VALUES ($1, $2)")
        .bind(version)
        .bind(name)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await
}

fn is_lock_timeout(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|database| database.code())
        .is_some_and(|code| code == LOCK_NOT_AVAILABLE)
}

/// Exponential backoff with up to 100% jitter, so controllers retrying against
/// the same blocker do not line up.
fn retry_delay(attempt: u32) -> Duration {
    let base = RETRY_BASE * 2u32.pow(attempt - 1);
    let jitter = (uuid::Uuid::new_v4().as_u128() % 1000) as u32;
    base + base * jitter / 1000
}

fn embedded(version: i32) -> Option<&'static (i32, &'static str, &'static str)> {
    MIGRATIONS.iter().find(|entry| entry.0 == version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_contiguous_from_one() {
        for (index, (version, _, _)) in MIGRATIONS.iter().enumerate() {
            assert_eq!(
                usize::try_from(*version).ok(),
                Some(index + 1),
                "migration list is not contiguous at index {index}"
            );
        }
        assert_eq!(
            embedded(TRACKING_VERSION).map(|entry| entry.1),
            Some("schema_migrations")
        );
    }

    #[test]
    fn every_migration_file_is_embedded_and_every_entry_has_its_file() {
        let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations");
        let mut files: Vec<(i32, String, String)> = std::fs::read_dir(directory)
            .expect("read the migrations directory")
            .map(|entry| entry.expect("read a migrations entry").path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
            .map(|path| {
                let stem = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .expect("UTF-8 file name");
                let (version, name) = stem.split_once('_').expect("NNN_name.sql");
                (
                    version.parse().expect("numeric migration version"),
                    name.to_string(),
                    std::fs::read_to_string(&path).expect("read a migration file"),
                )
            })
            .collect();
        files.sort();
        let embedded: Vec<(i32, String, String)> = MIGRATIONS
            .iter()
            .map(|(version, name, sql)| (*version, (*name).to_string(), (*sql).to_string()))
            .collect();
        assert_eq!(files, embedded, "migrations/*.sql and MIGRATIONS differ");
    }

    #[test]
    fn retry_delay_is_bounded_exponential_backoff() {
        for attempt in 1..LOCK_ATTEMPTS {
            let base = RETRY_BASE * 2u32.pow(attempt - 1);
            let delay = retry_delay(attempt);
            assert!(
                delay >= base && delay < base * 2,
                "attempt {attempt}: {delay:?}"
            );
        }
    }
}
