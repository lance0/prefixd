mod backend;

pub use backend::{AuthBackend, Credentials};

use axum_login::AuthManagerLayerBuilder;
use sqlx::PgPool;
use std::sync::Arc;
use tower_sessions::ExpiredDeletion;
use tower_sessions_sqlx_store::PostgresStore;

use crate::db::RepositoryTrait;

pub type AuthSession = axum_login::AuthSession<AuthBackend>;

/// Create the auth manager layer for the router
pub async fn create_auth_layer(
    pool: PgPool,
    repo: Arc<dyn RepositoryTrait>,
) -> axum_login::AuthManagerLayer<AuthBackend, PostgresStore> {
    // Session store using PostgreSQL
    let session_store = PostgresStore::new(pool.clone());
    
    // Spawn task to clean up expired sessions (fire and forget)
    tokio::task::spawn(async move {
        if let Err(e) = session_store
            .clone()
            .continuously_delete_expired(tokio::time::Duration::from_secs(60))
            .await
        {
            tracing::error!(error = %e, "session cleanup task failed");
        }
    });

    // Session layer configuration
    let session_layer = tower_sessions::SessionManagerLayer::new(PostgresStore::new(pool))
        .with_secure(false) // Set to true in production with HTTPS
        .with_same_site(tower_sessions::cookie::SameSite::Lax)
        .with_http_only(true)
        .with_expiry(tower_sessions::Expiry::OnInactivity(
            tower_sessions::cookie::time::Duration::days(7),
        ));

    // Auth backend
    let backend = AuthBackend::new(repo);

    // Build the auth manager layer
    AuthManagerLayerBuilder::new(backend, session_layer).build()
}
