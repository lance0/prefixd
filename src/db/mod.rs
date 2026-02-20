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
        (1, "initial", include_str!("../../migrations/001_initial.sql")),
        (2, "operators_sessions", include_str!("../../migrations/002_operators_sessions.sql")),
        (3, "raw_details", include_str!("../../migrations/003_raw_details.sql")),
        (4, "schema_migrations", include_str!("../../migrations/004_schema_migrations.sql")),
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

    let applied: Vec<(i32,)> = sqlx::query_as(
        "SELECT version FROM schema_migrations ORDER BY version"
    )
    .fetch_all(pool)
    .await?;

    tracing::info!(
        versions = ?applied.iter().map(|r| r.0).collect::<Vec<_>>(),
        "database migrations applied"
    );

    Ok(())
}
