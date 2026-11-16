mod backend;

pub use backend::{AuthBackend, Credentials};

use axum_login::AuthManagerLayerBuilder;
use sqlx::PgPool;
use std::sync::Arc;
use tower_sessions::ExpiredDeletion;
use tower_sessions_sqlx_store::PostgresStore;

use crate::config::AuthMode;
use crate::db::RepositoryTrait;

pub type AuthSession = axum_login::AuthSession<AuthBackend>;

/// Session cookie attributes shared by production and test routers.
pub fn session_layer<S: tower_sessions::SessionStore>(
    store: S,
    secure: bool,
) -> tower_sessions::SessionManagerLayer<S> {
    tower_sessions::SessionManagerLayer::new(store)
        .with_secure(secure)
        .with_same_site(tower_sessions::cookie::SameSite::Lax)
        .with_http_only(true)
        .with_expiry(tower_sessions::Expiry::OnInactivity(
            tower_sessions::cookie::time::Duration::days(7),
        ))
}

/// Create the auth manager layer for the router
///
/// # Arguments
/// * `pool` - PostgreSQL connection pool for session storage
/// * `repo` - Repository for operator lookups
/// * `mode` - Authentication mode used for login and session restoration
/// * `secure_cookies` - Whether browsers see HTTPS, natively or at a proxy; see `http.secure_cookies`
pub async fn create_auth_layer(
    pool: PgPool,
    repo: Arc<dyn RepositoryTrait>,
    mode: AuthMode,
    secure_cookies: bool,
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

    let session_layer = session_layer(PostgresStore::new(pool), secure_cookies);

    // Auth backend
    let backend = AuthBackend::new(repo, mode);

    // Build the auth manager layer
    AuthManagerLayerBuilder::new(backend, session_layer).build()
}
