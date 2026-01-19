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
    let migration_sql = include_str!("../../migrations/001_initial.sql");
    sqlx::raw_sql(migration_sql).execute(pool).await?;
    Ok(())
}
