use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum_login::{AuthUser, AuthnBackend, UserId};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::db::RepositoryTrait;
use crate::domain::Operator;

/// Credentials for login
#[derive(Clone, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// Auth backend for axum-login
#[derive(Clone)]
pub struct AuthBackend {
    repo: Arc<dyn RepositoryTrait>,
}

impl AuthBackend {
    pub fn new(repo: Arc<dyn RepositoryTrait>) -> Self {
        Self { repo }
    }
}

impl std::fmt::Debug for AuthBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthBackend").finish()
    }
}

impl AuthUser for Operator {
    type Id = Uuid;

    fn id(&self) -> Self::Id {
        self.operator_id
    }

    fn session_auth_hash(&self) -> &[u8] {
        self.password_hash.as_bytes()
    }
}

impl AuthnBackend for AuthBackend {
    type User = Operator;
    type Credentials = Credentials;
    type Error = std::convert::Infallible;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        // Look up operator by username
        let operator = match self.repo.get_operator_by_username(&creds.username).await {
            Ok(Some(op)) => op,
            Ok(None) => {
                tracing::debug!(username = %creds.username, "operator not found");
                return Ok(None);
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to lookup operator");
                return Ok(None);
            }
        };

        // Verify password with argon2
        let parsed_hash = match PasswordHash::new(&operator.password_hash) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(error = %e, "invalid password hash format");
                return Ok(None);
            }
        };

        if Argon2::default()
            .verify_password(creds.password.as_bytes(), &parsed_hash)
            .is_ok()
        {
            // Update last login time
            if let Err(e) = self
                .repo
                .update_operator_last_login(operator.operator_id)
                .await
            {
                tracing::warn!(error = %e, "failed to update last login time");
            }

            tracing::info!(username = %operator.username, "login successful");
            Ok(Some(operator))
        } else {
            tracing::debug!(username = %creds.username, "invalid password");
            Ok(None)
        }
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        match self.repo.get_operator_by_id(*user_id).await {
            Ok(op) => Ok(op),
            Err(e) => {
                tracing::error!(error = %e, "failed to get operator by id");
                Ok(None)
            }
        }
    }
}
