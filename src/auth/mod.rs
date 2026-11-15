mod backend;

pub use backend::{AuthBackend, Credentials};

use async_trait::async_trait;
use axum_login::AuthManagerLayerBuilder;
use sqlx::PgPool;
use std::sync::Arc;
use tower_sessions::session::{Id, Record};
use tower_sessions::{ExpiredDeletion, SessionStore, session_store};
use tower_sessions_sqlx_store::PostgresStore;

use crate::config::AuthMode;
use crate::db::RepositoryTrait;

pub type AuthSession = axum_login::AuthSession<AuthBackend>;

/// Postgres-backed auth manager layer installed on the production router.
pub type PostgresAuthLayer =
    axum_login::AuthManagerLayer<AuthBackend, AnonymousOnLoadError<PostgresStore>>;

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

/// Session store that treats a failed `load` as "no session".
///
/// The auth layer loads a presented session cookie from PostgreSQL before any
/// handler runs, and a store error used to fail the whole request with an empty
/// 500. That hid the operational health endpoint during a database outage,
/// rejected `Authorization: Bearer` requests carrying a stale cookie before the
/// token was ever checked, and turned unknown paths into 500 instead of 404.
///
/// A failed load cannot authenticate anyone: the request continues as
/// anonymous, so callers still need a valid bearer token or session, and
/// deny-by-default checks are unchanged.
#[derive(Debug, Clone)]
pub struct AnonymousOnLoadError<S> {
    inner: S,
}

impl<S> AnonymousOnLoadError<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<S: SessionStore> SessionStore for AnonymousOnLoadError<S> {
    async fn create(&self, session_record: &mut Record) -> session_store::Result<()> {
        self.inner.create(session_record).await
    }

    async fn save(&self, session_record: &Record) -> session_store::Result<()> {
        self.inner.save(session_record).await
    }

    async fn load(&self, session_id: &Id) -> session_store::Result<Option<Record>> {
        match self.inner.load(session_id).await {
            Ok(record) => Ok(record),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "session store load failed; treating the request as anonymous"
                );
                Ok(None)
            }
        }
    }

    async fn delete(&self, session_id: &Id) -> session_store::Result<()> {
        self.inner.delete(session_id).await
    }
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
) -> PostgresAuthLayer {
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

    // A session load failure must not become a 500 for the whole request.
    let session_layer = session_layer(
        AnonymousOnLoadError::new(PostgresStore::new(pool)),
        secure_cookies,
    );

    // Auth backend
    let backend = AuthBackend::new(repo, mode);

    // Build the auth manager layer
    AuthManagerLayerBuilder::new(backend, session_layer).build()
}
