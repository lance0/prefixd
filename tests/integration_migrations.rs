//! Startup migration bootstrap: what a start applies, what it adopts, and what
//! it refuses. These tests use disposable PostgreSQL containers.

use std::time::Duration;

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
    install_ddl_probe(&pool).await;
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
    sqlx::query("DELETE FROM ddl_probe")
        .execute(&pool)
        .await
        .expect("clear the seed DDL");
}

async fn assert_adopted(fixture: &Fixture) {
    let pool = prefixd::db::init_postgres_pool(&fixture.url)
        .await
        .expect("adopt a database that predates version tracking");

    let rows = recorded(&pool).await;
    assert_eq!(
        rows.iter()
            .map(|(version, name, _)| (*version, name.clone()))
            .collect::<Vec<_>>(),
        embedded(),
        "adoption records the pre-tracking versions without skipping later ones"
    );

    let statements: Vec<String> = ddl_statements(&pool)
        .await
        .into_iter()
        .map(|(statement, _)| statement)
        .collect();
    for replayed in [
        "CREATE TABLE IF NOT EXISTS events",
        "CREATE TABLE IF NOT EXISTS operators",
        "ADD COLUMN IF NOT EXISTS raw_details",
    ] {
        assert!(
            !statements
                .iter()
                .any(|statement| statement.contains(replayed)),
            "the runner replayed a pre-tracking migration: {replayed}"
        );
    }
    assert!(
        statements
            .iter()
            .any(|statement| statement.contains("CREATE TABLE IF NOT EXISTS schema_migrations")),
        "the runner never created the tracking table"
    );

    let victims: Vec<String> = sqlx::query_scalar("SELECT victim_ip FROM events")
        .fetch_all(&pool)
        .await
        .expect("read the seeded event");
    assert_eq!(victims, ["203.0.113.9"], "adoption dropped stored events");
    let audits: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_log")
        .fetch_all(&pool)
        .await
        .expect("read the seeded audit entry");
    assert_eq!(
        audits,
        ["withdrawal_requested"],
        "adoption dropped audit history"
    );
}

#[tokio::test]
async fn pre_tracking_database_is_adopted_without_replay() {
    let fixture = start_postgres().await;
    seed_pre_tracking(&fixture, false).await;
    assert_adopted(&fixture).await;
}

#[tokio::test]
async fn empty_tracking_table_is_adopted_without_replay() {
    let fixture = start_postgres().await;
    seed_pre_tracking(&fixture, true).await;
    assert_adopted(&fixture).await;
}
