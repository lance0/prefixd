//! Startup migration bootstrap: what a start applies, what it replays, what it
//! retries and what it refuses. These tests use disposable PostgreSQL containers.

use std::time::{Duration, Instant};

use prefixd::db::migrate::{LATEST_VERSION, MIGRATIONS};
use prefixd::error::PrefixdError;
use sqlx::PgPool;
use testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};
use testcontainers_modules::postgres::Postgres;

struct Fixture {
    _container: ContainerAsync<Postgres>,
    url: String,
}

async fn start_postgres() -> Fixture {
    let container = Postgres::default()
        .with_tag("16-alpine")
        .with_host_config_modifier(|config| {
            config.cpuset_cpus = std::env::var("PREFIXD_TEST_CPUSET").ok();
        })
        .start()
        .await
        .expect("start the PostgreSQL container");
    let host = container.get_host().await.expect("container host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("container port");
    Fixture {
        _container: container,
        url: format!("postgres://postgres:postgres@{host}:{port}/postgres"),
    }
}

async fn connect(fixture: &Fixture) -> PgPool {
    PgPool::connect(&fixture.url)
        .await
        .expect("connect to the test database")
}

/// Record every DDL command server-side, so a test can prove what ran instead
/// of inferring it from the resulting catalog.
async fn install_ddl_probe(pool: &PgPool) {
    sqlx::raw_sql(
        r#"
        CREATE TABLE ddl_probe (
            tag TEXT NOT NULL,
            statement TEXT NOT NULL,
            backend_pid INTEGER NOT NULL
        );
        CREATE FUNCTION record_ddl() RETURNS event_trigger LANGUAGE plpgsql AS $$
        BEGIN
            INSERT INTO ddl_probe (tag, statement, backend_pid)
            VALUES (tg_tag, current_query(), pg_backend_pid());
        END;
        $$;
        CREATE EVENT TRIGGER ddl_probe ON ddl_command_end EXECUTE FUNCTION record_ddl();
        "#,
    )
    .execute(pool)
    .await
    .expect("install the DDL probe");
}

async fn recorded(pool: &PgPool) -> Vec<(i32, String, String)> {
    sqlx::query_as("SELECT version, name, applied_at::text FROM schema_migrations ORDER BY version")
        .fetch_all(pool)
        .await
        .expect("read schema_migrations")
}

async fn ddl_statements(pool: &PgPool) -> Vec<(String, i32)> {
    sqlx::query_as("SELECT statement, backend_pid FROM ddl_probe")
        .fetch_all(pool)
        .await
        .expect("read the DDL probe")
}

async fn ddl_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM ddl_probe")
        .fetch_one(pool)
        .await
        .expect("count the DDL probe")
}

fn embedded() -> Vec<(i32, String)> {
    MIGRATIONS
        .iter()
        .map(|(version, name, _)| (*version, (*name).to_string()))
        .collect()
}

#[tokio::test]
async fn fresh_database_records_every_embedded_migration() {
    let fixture = start_postgres().await;
    let setup = connect(&fixture).await;
    install_ddl_probe(&setup).await;

    let pool = prefixd::db::init_postgres_pool(&fixture.url)
        .await
        .expect("migrate a fresh database");

    let rows = recorded(&pool).await;
    assert_eq!(
        rows.iter()
            .map(|(version, name, _)| (*version, name.clone()))
            .collect::<Vec<_>>(),
        embedded(),
        "every embedded migration is recorded once, in order"
    );
    assert_eq!(
        rows.last().map(|(version, _, _)| *version),
        Some(LATEST_VERSION)
    );

    // Control for the no-DDL assertions below: a real run does execute DDL, so
    // an empty probe means "nothing ran", not "the probe never fired".
    let statements = ddl_statements(&pool).await;
    assert!(
        statements
            .iter()
            .any(|(statement, _)| statement.contains("CREATE TABLE IF NOT EXISTS events")),
        "the probe missed the initial migration"
    );
    assert!(
        statements.iter().any(
            |(statement, _)| statement.contains("CREATE TABLE IF NOT EXISTS schema_migrations")
        ),
        "the probe missed the tracking table"
    );
    let mut pids: Vec<i32> = statements.iter().map(|(_, pid)| *pid).collect();
    pids.sort_unstable();
    pids.dedup();
    assert_eq!(pids.len(), 1, "one session applies the whole bootstrap");
}

#[tokio::test]
async fn up_to_date_database_replays_nothing() {
    let fixture = start_postgres().await;
    let setup = connect(&fixture).await;
    install_ddl_probe(&setup).await;
    let first = prefixd::db::init_postgres_pool(&fixture.url)
        .await
        .expect("first start");
    let rows_before = recorded(&first).await;
    let ddl_before = ddl_count(&first).await;
    assert!(ddl_before > 0, "the first start applies the schema");

    // Operator state that a replay must not rewrite: a pending withdrawal, its
    // mitigation and the audit entry that requested it.
    sqlx::raw_sql(
        r#"
        INSERT INTO mitigations (mitigation_id, scope_hash, pop, victim_ip, vector,
            match_json, action_type, status, created_at, updated_at, expires_at,
            triggering_event_id, last_event_id, reason)
        VALUES ('11111111-1111-4111-8111-111111111111', 'scope-pending', 'test-pop',
            '203.0.113.77', 'udp_flood', '{}', 'discard', 'pending', now(), now(),
            now() + interval '30 minutes', gen_random_uuid(), gen_random_uuid(),
            'pending deletion under test');
        INSERT INTO withdrawal_requests (operation_id, mitigation_id, pop, nlri_hash,
            rule_json, mitigation_updated_at, terminal_status, actor_type, actor,
            reason, requested_at)
        VALUES ('22222222-2222-4222-8222-222222222222',
            '11111111-1111-4111-8111-111111111111', 'test-pop', 'nlri-hash', '{}',
            now(), 'withdrawn', 'operator', 'operator-under-test',
            'operator requested deletion', now());
        INSERT INTO audit_log (audit_id, timestamp, actor_type, actor_id, action,
            details_json)
        VALUES ('33333333-3333-4333-8333-333333333333', now(), 'operator',
            'operator-under-test', 'withdrawal_requested',
            '{"reason":"operator requested deletion"}');
        "#,
    )
    .execute(&first)
    .await
    .expect("seed operator state");

    let second = prefixd::db::init_postgres_pool(&fixture.url)
        .await
        .expect("restart against an up-to-date database");

    assert_eq!(
        ddl_count(&second).await,
        ddl_before,
        "a restart ran migration DDL"
    );
    assert_eq!(
        recorded(&second).await,
        rows_before,
        "a restart rewrote schema_migrations"
    );

    let pending: (String, bool) =
        sqlx::query_as("SELECT reason, completed_at IS NULL FROM withdrawal_requests")
            .fetch_one(&second)
            .await
            .expect("read the pending withdrawal");
    assert_eq!(
        pending,
        ("operator requested deletion".to_string(), true),
        "a restart changed the pending withdrawal"
    );
    let mitigation: (String, String) = sqlx::query_as("SELECT status, reason FROM mitigations")
        .fetch_one(&second)
        .await
        .expect("read the mitigation");
    assert_eq!(
        mitigation,
        (
            "pending".to_string(),
            "pending deletion under test".to_string()
        ),
        "a restart changed the mitigation"
    );
    let audit: (String, String) = sqlx::query_as("SELECT action, details_json FROM audit_log")
        .fetch_one(&second)
        .await
        .expect("read the audit entry");
    assert_eq!(audit.0, "withdrawal_requested");
    assert!(audit.1.contains("operator requested deletion"));

    // Negative control: the probe does observe DDL on this database, so the
    // equality above means "nothing ran", not "nothing is observed".
    sqlx::raw_sql("CREATE TABLE ddl_control (id INTEGER)")
        .execute(&second)
        .await
        .expect("run control DDL");
    assert!(
        ddl_count(&second).await > ddl_before,
        "the DDL probe missed the control statement"
    );
}

#[tokio::test]
async fn concurrent_starts_apply_migrations_once() {
    let fixture = start_postgres().await;
    let setup = connect(&fixture).await;
    install_ddl_probe(&setup).await;

    let (first, second) = tokio::time::timeout(Duration::from_secs(180), async {
        tokio::join!(
            prefixd::db::init_postgres_pool(&fixture.url),
            prefixd::db::init_postgres_pool(&fixture.url),
        )
    })
    .await
    .expect("two concurrent starts finish within 180 seconds");
    let first = first.expect("the first controller migrates");
    second.expect("the second controller waits and reuses the applied schema");

    let versions: Vec<i32> = recorded(&first)
        .await
        .into_iter()
        .map(|(v, _, _)| v)
        .collect();
    assert_eq!(
        versions,
        embedded().into_iter().map(|(v, _)| v).collect::<Vec<_>>()
    );

    // Both pools use different sessions. Two sessions in the probe mean both
    // controllers ran DDL, so the lock did not serialize them.
    let mut pids: Vec<i32> = ddl_statements(&first)
        .await
        .into_iter()
        .map(|(_, pid)| pid)
        .collect();
    pids.sort_unstable();
    pids.dedup();
    assert_eq!(pids.len(), 1, "both starts ran migration DDL: {pids:?}");
}

#[tokio::test]
async fn newer_database_schema_refuses_the_older_binary() {
    let fixture = start_postgres().await;
    let setup = connect(&fixture).await;
    install_ddl_probe(&setup).await;
    prefixd::db::init_postgres_pool(&fixture.url)
        .await
        .expect("bring the database to this binary's schema");
    let future = LATEST_VERSION + 7;
    sqlx::query("INSERT INTO schema_migrations (version, name) VALUES ($1, $2)")
        .bind(future)
        .bind("from_a_newer_release")
        .execute(&setup)
        .await
        .expect("record a newer migration version");
    let ddl_before = ddl_count(&setup).await;

    let error = prefixd::db::init_postgres_pool(&fixture.url)
        .await
        .expect_err("an older binary must refuse a newer schema");
    match &error {
        PrefixdError::SchemaNewerThanBinary { found, known } => {
            assert_eq!(*found, future);
            assert_eq!(*known, LATEST_VERSION);
        }
        other => panic!("expected a newer-schema refusal, got {other}"),
    }
    let message = error.to_string();
    assert!(
        message.contains(&format!("records migration {future}")),
        "{message}"
    );
    assert!(
        message.contains(&format!("knows up to {LATEST_VERSION}")),
        "{message}"
    );
    assert_eq!(
        ddl_count(&setup).await,
        ddl_before,
        "the refusal ran migration DDL"
    );
}

/// A database last started before version tracking existed: 001..003 applied,
/// operator state in place and no recorded version. `tracking_table` also
/// creates the empty table, as a start interrupted right after 004 leaves it.
async fn seed_pre_tracking(fixture: &Fixture, tracking_table: bool) {
    let pool = connect(fixture).await;
    for sql in [
        include_str!("../migrations/001_initial.sql"),
        include_str!("../migrations/002_operators_sessions.sql"),
        include_str!("../migrations/003_raw_details.sql"),
    ] {
        sqlx::raw_sql(sql)
            .execute(&pool)
            .await
            .expect("seed a pre-tracking migration");
    }
    if tracking_table {
        sqlx::raw_sql(include_str!("../migrations/004_schema_migrations.sql"))
            .execute(&pool)
            .await
            .expect("seed the empty tracking table");
    }
    sqlx::raw_sql(
        r#"
        INSERT INTO events (event_id, source, event_timestamp, ingested_at, victim_ip,
            vector)
        VALUES (gen_random_uuid(), 'detector', '2026-01-01T00:00:00Z',
            '2026-01-01T00:00:00Z', '203.0.113.9', 'udp_flood');
        INSERT INTO audit_log (audit_id, timestamp, actor_type, action, details_json)
        VALUES (gen_random_uuid(), '2026-01-01T00:00:00Z', 'system',
            'withdrawal_requested', '{}');
        "#,
    )
    .execute(&pool)
    .await
    .expect("seed operator state");
}

async fn assert_replayed(fixture: &Fixture) {
    let pool = prefixd::db::init_postgres_pool(&fixture.url)
        .await
        .expect("migrate a database that predates version tracking");

    let rows = recorded(&pool).await;
    assert_eq!(
        rows.iter()
            .map(|(version, name, _)| (*version, name.clone()))
            .collect::<Vec<_>>(),
        embedded(),
        "every version is recorded, including the replayed pre-tracking ones"
    );

    let victims: Vec<String> = sqlx::query_scalar("SELECT victim_ip FROM events")
        .fetch_all(&pool)
        .await
        .expect("read the seeded event");
    assert_eq!(victims, ["203.0.113.9"], "the replay dropped stored events");
    let audits: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_log")
        .fetch_all(&pool)
        .await
        .expect("read the seeded audit entry");
    assert_eq!(
        audits,
        ["withdrawal_requested"],
        "the replay dropped audit history"
    );
}

#[tokio::test]
async fn pre_tracking_database_replays_idempotent_history() {
    let fixture = start_postgres().await;
    seed_pre_tracking(&fixture, false).await;
    assert_replayed(&fixture).await;
}

#[tokio::test]
async fn empty_tracking_table_replays_idempotent_history() {
    let fixture = start_postgres().await;
    seed_pre_tracking(&fixture, true).await;
    assert_replayed(&fixture).await;
}

/// Migration 020, made pending again: its columns dropped and its row removed,
/// as on a database that has not applied it.
const PENDING: i32 = 20;

async fn make_latest_pending(pool: &PgPool) {
    sqlx::raw_sql(
        "ALTER TABLE events DROP COLUMN outcome, DROP COLUMN outcome_reason,
             DROP COLUMN outcome_mitigation_ids;
         DELETE FROM schema_migrations WHERE version = 20;",
    )
    .execute(pool)
    .await
    .expect("make the newest migration pending");
}

async fn pending_state(pool: &PgPool) -> (bool, bool) {
    sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1),
                EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'events' AND column_name = 'outcome')",
    )
    .bind(PENDING)
    .fetch_one(pool)
    .await
    .expect("read the pending migration's state")
}

async fn advisory_locks(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'")
        .fetch_one(pool)
        .await
        .expect("count advisory locks")
}

/// Every attempt waits `LOCK_TIMEOUT`; the backoff between them adds at most
/// twice the base per gap. Allow generous headroom for a loaded CI host.
fn retry_bound() -> Duration {
    prefixd::db::migrate::LOCK_TIMEOUT * prefixd::db::migrate::LOCK_ATTEMPTS
        + Duration::from_secs(30)
}

#[tokio::test]
async fn blocked_migration_rolls_back_and_releases_the_bootstrap_lock() {
    use prefixd::db::migrate::{LOCK_ATTEMPTS, LOCK_TIMEOUT};

    let fixture = start_postgres().await;
    let setup = connect(&fixture).await;
    prefixd::db::init_postgres_pool(&fixture.url)
        .await
        .expect("bring the database to this binary's schema");
    make_latest_pending(&setup).await;

    // A long reader: ACCESS SHARE conflicts with the ACCESS EXCLUSIVE that
    // ALTER TABLE needs, for as long as this transaction stays open.
    let mut reader = setup.begin().await.expect("open the reader");
    sqlx::query("LOCK TABLE events IN ACCESS SHARE MODE")
        .execute(&mut *reader)
        .await
        .expect("hold ACCESS SHARE on events");

    let started = Instant::now();
    let error = tokio::time::timeout(retry_bound(), prefixd::db::init_postgres_pool(&fixture.url))
        .await
        .expect("a blocked start fails within its retry bound")
        .expect_err("a migration blocked on every attempt fails the start");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= LOCK_TIMEOUT * LOCK_ATTEMPTS,
        "the start gave up before retrying: {elapsed:?}"
    );
    match &error {
        PrefixdError::MigrationFailed { version, name, .. } => {
            assert_eq!(*version, PENDING);
            assert_eq!(*name, "event_outcomes");
        }
        other => panic!("expected a migration failure, got {other}"),
    }
    let message = error.to_string();
    assert!(
        message.contains("migration 20 (event_outcomes)"),
        "{message}"
    );
    assert!(message.contains("pg_blocking_pids"), "{message}");
    assert!(message.contains("pg_locks"), "{message}");
    // The PostgreSQL error is the source, not repeated in the message.
    assert!(!message.contains("lock timeout"), "{message}");
    let source = std::error::Error::source(&error).map(ToString::to_string);
    assert!(
        source
            .as_deref()
            .is_some_and(|cause| cause.contains("lock timeout")),
        "{source:?}"
    );

    assert_eq!(
        pending_state(&setup).await,
        (false, false),
        "the failed migration left its row or its columns behind"
    );
    assert_eq!(
        advisory_locks(&setup).await,
        0,
        "the failed start leaked the bootstrap lock"
    );

    reader.rollback().await.expect("release the reader");
    // A leaked bootstrap lock would park this start for minutes.
    tokio::time::timeout(
        Duration::from_secs(30),
        prefixd::db::init_postgres_pool(&fixture.url),
    )
    .await
    .expect("the next start does not wait on a leaked bootstrap lock")
    .expect("the next start applies the migration");
    assert_eq!(pending_state(&setup).await, (true, true));
}

#[tokio::test]
async fn transient_blocker_released_mid_retry_lets_the_start_succeed() {
    use prefixd::db::migrate::LOCK_TIMEOUT;

    let fixture = start_postgres().await;
    let setup = connect(&fixture).await;
    prefixd::db::init_postgres_pool(&fixture.url)
        .await
        .expect("bring the database to this binary's schema");
    make_latest_pending(&setup).await;

    let mut reader = setup.begin().await.expect("open the reader");
    sqlx::query("LOCK TABLE events IN ACCESS SHARE MODE")
        .execute(&mut *reader)
        .await
        .expect("hold ACCESS SHARE on events");

    let started = Instant::now();
    // Past the first attempt's lock_timeout, so only a retry can succeed.
    let hold = LOCK_TIMEOUT + Duration::from_millis(500);
    let (result, ()) = tokio::time::timeout(retry_bound(), async {
        tokio::join!(prefixd::db::init_postgres_pool(&fixture.url), async {
            tokio::time::sleep(hold).await;
            reader.rollback().await.expect("release the reader");
        })
    })
    .await
    .expect("the start finishes within its retry bound");
    result.expect("a retry after the blocker ends applies the migration");
    assert!(
        started.elapsed() >= hold,
        "the start finished while the blocker was held"
    );
    assert_eq!(pending_state(&setup).await, (true, true));
}

async fn scope_index(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_mitigations_active_scope'",
    )
    .fetch_one(pool)
    .await
    .expect("read the scope index")
}

fn assert_live_scope_index(definition: &str) {
    assert!(
        definition.starts_with("CREATE UNIQUE INDEX"),
        "{definition}"
    );
    assert!(definition.contains("(scope_hash, pop)"), "{definition}");
    assert!(definition.contains("'active'"), "{definition}");
    assert!(definition.contains("'escalated'"), "{definition}");
    assert!(!definition.contains("'pending'"), "{definition}");
}

#[tokio::test]
async fn scope_index_covers_only_live_statuses_after_fresh_and_020_starts() {
    let fixture = start_postgres().await;
    let setup = connect(&fixture).await;
    prefixd::db::init_postgres_pool(&fixture.url)
        .await
        .expect("migrate a fresh database");
    assert_live_scope_index(&scope_index(&setup).await);

    // A database at 020: the index from migration 001 and no row for 021.
    sqlx::raw_sql(
        "DROP INDEX idx_mitigations_active_scope;
         CREATE UNIQUE INDEX idx_mitigations_active_scope ON mitigations(scope_hash, pop)
             WHERE status IN ('pending', 'active', 'escalated');
         DELETE FROM schema_migrations WHERE version = 21;",
    )
    .execute(&setup)
    .await
    .expect("put the database at 020");
    // Control: the 020 definition is the one the assertion refuses.
    assert!(scope_index(&setup).await.contains("'pending'"));
    prefixd::db::init_postgres_pool(&fixture.url)
        .await
        .expect("migrate a database at 020");
    assert_live_scope_index(&scope_index(&setup).await);
    assert_eq!(
        recorded(&setup)
            .await
            .last()
            .map(|(version, name, _)| (*version, name.clone())),
        Some((21, "live_scope_index".to_string()))
    );

    // 0.27.0 replays 001-020 on every start. Migration 001's IF NOT EXISTS
    // keeps the narrowed index, so starting it again is unaffected.
    for (version, _, sql) in MIGRATIONS.iter().filter(|(version, _, _)| *version <= 20) {
        sqlx::raw_sql(sql)
            .execute(&setup)
            .await
            .unwrap_or_else(|error| panic!("replay migration {version}: {error}"));
    }
    assert_live_scope_index(&scope_index(&setup).await);
}
