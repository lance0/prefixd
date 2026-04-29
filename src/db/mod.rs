pub mod mock;
pub mod repository;
pub mod traits;

pub use mock::*;
pub use repository::*;
pub use traits::*;

use crate::error::Result;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::str::FromStr;

pub async fn init_postgres_pool(connection_string: &str) -> Result<PgPool> {
    let options = PgConnectOptions::from_str(connection_string)?;

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?;

    run_migrations(&pool).await?;

    Ok(pool)
}

async fn run_migrations(pool: &PgPool) -> Result<()> {
    let migrations: &[(i32, &str, &str)] = &[
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
    ];

    // Bootstrap: run all migrations first (they use IF NOT EXISTS)
    for &(_, _, sql) in migrations {
        sqlx::raw_sql(sql).execute(pool).await?;
    }

    // Record any that aren't tracked yet
    for &(version, name, _) in migrations {
        sqlx::query(
            "INSERT INTO schema_migrations (version, name) VALUES ($1, $2) ON CONFLICT (version) DO NOTHING"
        )
        .bind(version)
        .bind(name)
        .execute(pool)
        .await?;
    }

    let applied: Vec<(i32,)> =
        sqlx::query_as("SELECT version FROM schema_migrations ORDER BY version")
            .fetch_all(pool)
            .await?;

    tracing::info!(
        versions = ?applied.iter().map(|r| r.0).collect::<Vec<_>>(),
        "database migrations applied"
    );

    Ok(())
}
