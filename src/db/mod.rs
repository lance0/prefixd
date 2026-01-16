mod repository;

pub use repository::*;

use crate::config::StorageDriver;
use crate::error::Result;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{PgPool, SqlitePool};
use std::path::Path;
use std::str::FromStr;

/// Database pool that supports both SQLite and PostgreSQL
#[derive(Clone)]
pub enum DbPool {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

/// Initialize database pool based on driver configuration
pub async fn init_pool_from_config(driver: StorageDriver, path: &str) -> Result<DbPool> {
    match driver {
        StorageDriver::Sqlite => {
            let pool = init_sqlite_pool(Path::new(path)).await?;
            Ok(DbPool::Sqlite(pool))
        }
        StorageDriver::Postgres => {
            let pool = init_postgres_pool(path).await?;
            Ok(DbPool::Postgres(pool))
        }
    }
}

pub async fn init_sqlite_pool(path: &Path) -> Result<SqlitePool> {
    let db_url = format!("sqlite:{}", path.display());

    let options = SqliteConnectOptions::from_str(&db_url)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}

pub async fn init_postgres_pool(connection_string: &str) -> Result<PgPool> {
    let options = PgConnectOptions::from_str(connection_string)?;

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await?;

    // Run postgres migrations manually (sqlx::migrate! uses sqlite folder by default)
    run_postgres_migrations(&pool).await?;

    Ok(pool)
}

async fn run_postgres_migrations(pool: &PgPool) -> Result<()> {
    let migration_sql = include_str!("../../migrations/postgres/001_initial.sql");
    sqlx::raw_sql(migration_sql).execute(pool).await?;
    Ok(())
}

// Legacy function for backward compatibility
pub async fn init_pool(path: &Path) -> Result<SqlitePool> {
    init_sqlite_pool(path).await
}

pub async fn init_memory_pool() -> Result<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}
