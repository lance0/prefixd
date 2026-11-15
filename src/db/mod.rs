mod timestamp;
#[doc(hidden)]
pub use timestamp::CheckedTimestamp;

pub mod migrate;
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

    migrate::run(&pool).await?;

    Ok(pool)
}
