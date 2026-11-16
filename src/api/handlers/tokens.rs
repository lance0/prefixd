//! API token management (ADR 034 §9). Every route needs an Admin session: no
//! token, admin tokens included, can mint, list or revoke tokens.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

use super::AppError;
use crate::AppState;
use crate::api::auth::{AuthPrincipal, require_admin_session};
use crate::auth::token::NewToken;
use crate::domain::ApiToken;

/// The created token. `token` is the only time the plaintext appears.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedToken {
    #[serde(flatten)]
    pub record: ApiToken,
    /// The secret, shown once; store it now
    pub token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenListResponse {
    pub tokens: Vec<ApiToken>,
    pub count: usize,
}

/// Create an API token (Admin session only)
#[utoipa::path(
    post,
    path = "/v1/tokens",
    tag = "tokens",
    request_body = NewToken,
    responses(
        (status = 201, description = "Token created; the response is the only time the secret appears", body = CreatedToken),
        (status = 400, description = "Invalid name, scope, source, POP or expiry"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Requires an Admin session; every token is refused"),
        (status = 409, description = "Name already used; names are never reused"),
        (status = 503, description = "Controller is in standby")
    )
)]
pub async fn create_token(
    State(state): State<Arc<AppState>>,
    principal: AuthPrincipal,
    Json(request): Json<NewToken>,
) -> impl IntoResponse {
    let admin = require_admin_session(&principal).map_err(AppError)?;
    let (record, token) = crate::auth::token::create(
        state.repo.as_ref(),
        request,
        &admin.username,
        chrono::Utc::now(),
    )
    .await
    .map_err(AppError)?;
    Ok::<_, AppError>((StatusCode::CREATED, Json(CreatedToken { record, token })))
}

/// List API tokens, revoked ones included (Admin session only)
#[utoipa::path(
    get,
    path = "/v1/tokens",
    tag = "tokens",
    responses(
        (status = 200, description = "Every token without its secret or hash", body = TokenListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Requires an Admin session; every token is refused")
    )
)]
pub async fn list_tokens(
    State(state): State<Arc<AppState>>,
    principal: AuthPrincipal,
) -> impl IntoResponse {
    require_admin_session(&principal).map_err(AppError)?;
    let tokens = state.repo.list_api_tokens(None).await.map_err(AppError)?;
    Ok::<_, AppError>(Json(TokenListResponse {
        count: tokens.len(),
        tokens,
    }))
}

/// Revoke an API token (Admin session only)
#[utoipa::path(
    post,
    path = "/v1/tokens/{name}/revoke",
    tag = "tokens",
    params(("name" = String, Path, description = "Token name")),
    responses(
        (status = 200, description = "Revoked; revoking a revoked token returns the same record", body = ApiToken),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Requires an Admin session; every token is refused"),
        (status = 404, description = "No token has that name"),
        (status = 503, description = "Controller is in standby")
    )
)]
pub async fn revoke_token(
    State(state): State<Arc<AppState>>,
    principal: AuthPrincipal,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let admin = require_admin_session(&principal).map_err(AppError)?;
    let token = crate::auth::token::revoke(
        state.repo.as_ref(),
        &name,
        &admin.username,
        chrono::Utc::now(),
    )
    .await
    .map_err(AppError)?;
    Ok::<_, AppError>(Json(token))
}
