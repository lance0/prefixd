use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::api::auth::require_role;
use crate::auth::AuthSession;
use crate::db::NotificationPreferences;

use super::MAX_USERNAME_LEN;

const LOGIN_MAX_ATTEMPTS: u32 = 5;

const LOGIN_WINDOW_SECS: u64 = 60;

const LOGIN_MAX_TRACKED_USERS: usize = 10_000;

static LOGIN_ATTEMPTS: std::sync::LazyLock<Mutex<HashMap<String, (u32, Instant)>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn prune_login_attempts_locked(attempts: &mut HashMap<String, (u32, Instant)>) {
    attempts.retain(|_, (_, started)| started.elapsed().as_secs() < LOGIN_WINDOW_SECS);

    if attempts.len() > LOGIN_MAX_TRACKED_USERS {
        let mut by_age: Vec<_> = attempts
            .iter()
            .map(|(key, (_, started))| (key.clone(), *started))
            .collect();
        by_age.sort_by_key(|(_, started)| *started);

        let overflow = attempts.len() - LOGIN_MAX_TRACKED_USERS;
        for (key, _) in by_age.into_iter().take(overflow) {
            attempts.remove(&key);
        }
    }
}

async fn check_and_record_login_attempt(key: &str) -> Result<(), StatusCode> {
    let mut attempts = LOGIN_ATTEMPTS.lock().await;
    prune_login_attempts_locked(&mut attempts);

    let now = Instant::now();
    let entry = attempts.entry(key.to_string()).or_insert((0, now));

    if entry.1.elapsed().as_secs() >= LOGIN_WINDOW_SECS {
        *entry = (1, Instant::now());
        return Ok(());
    }

    if entry.0 >= LOGIN_MAX_ATTEMPTS {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    entry.0 += 1;
    Ok(())
}

async fn clear_login_attempts(key: &str) {
    let mut attempts = LOGIN_ATTEMPTS.lock().await;
    attempts.remove(key);
}

fn is_valid_username(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

const MAX_PASSWORD_LEN: usize = 256;

// Authentication handlers

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub operator_id: Uuid,
    pub username: String,
    pub role: String,
}

/// Login with username and password
#[utoipa::path(
    post,
    path = "/v1/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 401, description = "Invalid credentials"),
        (status = 403, description = "Login is disabled when authentication mode is none")
    )
)]
pub async fn login(
    State(state): State<Arc<AppState>>,
    mut auth_session: crate::auth::AuthSession,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    use crate::auth::Credentials;

    if matches!(state.settings.http.auth.mode, crate::config::AuthMode::None) {
        return Err(StatusCode::FORBIDDEN);
    }

    // Validate input lengths and username format
    if req.username.len() > MAX_USERNAME_LEN
        || !is_valid_username(&req.username)
        || req.password.is_empty()
        || req.password.len() > MAX_PASSWORD_LEN
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Per-username brute-force throttle
    check_and_record_login_attempt(&req.username).await?;

    let username = req.username.clone();

    let creds = Credentials {
        username: req.username,
        password: req.password,
    };

    let operator = match auth_session.authenticate(creds).await {
        Ok(Some(op)) => op,
        Ok(None) => return Err(StatusCode::UNAUTHORIZED),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    auth_session.login(&operator).await.map_err(|e| {
        tracing::error!(target: "prefixd::api::handlers", error = %e, "login failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    clear_login_attempts(&username).await;

    Ok(Json(LoginResponse {
        operator_id: operator.operator_id,
        username: operator.username,
        role: operator.role.to_string(),
    }))
}

/// Logout current session
#[utoipa::path(
    post,
    path = "/v1/auth/logout",
    tag = "auth",
    responses(
        (status = 200, description = "Logout successful")
    )
)]
pub async fn logout(mut auth_session: crate::auth::AuthSession) -> StatusCode {
    if let Err(e) = auth_session.logout().await {
        tracing::warn!(target: "prefixd::api::handlers", error = %e, "logout failed");
    }
    StatusCode::OK
}

/// Get current authenticated operator
#[utoipa::path(
    get,
    path = "/v1/auth/me",
    tag = "auth",
    responses(
        (status = 200, description = "Current operator", body = LoginResponse),
        (status = 401, description = "Not authenticated")
    )
)]
pub async fn get_me(
    auth_session: crate::auth::AuthSession,
) -> Result<Json<LoginResponse>, StatusCode> {
    let operator = auth_session.user.ok_or(StatusCode::UNAUTHORIZED)?;
    Ok(Json(LoginResponse {
        operator_id: operator.operator_id,
        username: operator.username,
        role: operator.role.to_string(),
    }))
}

// Operator management handlers (admin only)

#[derive(Debug, Serialize, ToSchema)]
pub struct OperatorListResponse {
    pub operators: Vec<OperatorInfo>,
    pub count: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OperatorInfo {
    pub operator_id: Uuid,
    pub username: String,
    pub role: String,
    pub created_at: String,
    pub created_by: Option<String>,
    pub last_login_at: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateOperatorRequest {
    pub username: String,
    pub password: String,
    pub role: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    /// Current password — required for self-change, optional for admin reset
    #[serde(default)]
    pub current_password: String,
    pub new_password: String,
}

/// List all operators (admin only)
#[utoipa::path(
    get,
    path = "/v1/operators",
    tag = "operators",
    responses(
        (status = 200, description = "List of operators", body = OperatorListResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions")
    )
)]
pub async fn list_operators(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    auth_session: crate::auth::AuthSession,
) -> Result<Json<OperatorListResponse>, StatusCode> {
    use crate::api::auth::require_role;
    use crate::domain::OperatorRole;

    let auth_header = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());

    require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    let operators = state
        .repo
        .list_operators()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let infos: Vec<OperatorInfo> = operators
        .into_iter()
        .map(|op| OperatorInfo {
            operator_id: op.operator_id,
            username: op.username,
            role: op.role.to_string(),
            created_at: op.created_at.to_rfc3339(),
            created_by: op.created_by,
            last_login_at: op.last_login_at.map(|t| t.to_rfc3339()),
        })
        .collect();

    Ok(Json(OperatorListResponse {
        count: infos.len(),
        operators: infos,
    }))
}

/// Create a new operator (admin only)
#[utoipa::path(
    post,
    path = "/v1/operators",
    tag = "operators",
    request_body = CreateOperatorRequest,
    responses(
        (status = 201, description = "Operator created", body = OperatorInfo),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 409, description = "Username already exists")
    )
)]
pub async fn create_operator(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    auth_session: crate::auth::AuthSession,
    Json(req): Json<CreateOperatorRequest>,
) -> Result<(StatusCode, Json<OperatorInfo>), StatusCode> {
    use crate::api::auth::require_role;
    use crate::domain::OperatorRole;
    use argon2::{Argon2, PasswordHasher};

    let auth_header = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());

    let admin = require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    // Validate role
    let role: OperatorRole = req.role.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

    // Validate username
    if req.username.len() > MAX_USERNAME_LEN || !is_valid_username(&req.username) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate password length
    if req.password.len() < 8 || req.password.len() > MAX_PASSWORD_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check if username exists
    if state
        .repo
        .get_operator_by_username(&req.username)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_some()
    {
        return Err(StatusCode::CONFLICT);
    }

    // Hash password
    let password_hash = Argon2::default()
        .hash_password(req.password.as_bytes())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    let operator = state
        .repo
        .create_operator(&req.username, &password_hash, role, Some(&admin.username))
        .await
        .map_err(|e| {
            tracing::error!(target: "prefixd::api::handlers", error = %e, "create_operator failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!(target: "prefixd::api::handlers",
        username = %operator.username,
        role = %operator.role,
        created_by = %admin.username,
        "operator created"
    );

    Ok((
        StatusCode::CREATED,
        Json(OperatorInfo {
            operator_id: operator.operator_id,
            username: operator.username,
            role: operator.role.to_string(),
            created_at: operator.created_at.to_rfc3339(),
            created_by: operator.created_by,
            last_login_at: None,
        }),
    ))
}

/// Delete an operator (admin only)
#[utoipa::path(
    delete,
    path = "/v1/operators/{id}",
    tag = "operators",
    params(
        ("id" = Uuid, Path, description = "Operator ID")
    ),
    responses(
        (status = 204, description = "Operator deleted"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Operator not found")
    )
)]
pub async fn delete_operator(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    auth_session: crate::auth::AuthSession,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    use crate::api::auth::require_role;
    use crate::domain::OperatorRole;

    let auth_header = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());

    let admin = require_role(&state, &auth_session, auth_header, OperatorRole::Admin)?;

    // Prevent self-deletion
    if admin.operator_id == id {
        tracing::warn!(target: "prefixd::api::handlers", operator_id = %id, "cannot delete self");
        return Err(StatusCode::BAD_REQUEST);
    }

    let deleted = state.repo.delete_operator(id).await.map_err(|e| {
        tracing::error!(target: "prefixd::api::handlers", error = %e, "delete_operator failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if deleted {
        tracing::info!(target: "prefixd::api::handlers", operator_id = %id, deleted_by = %admin.username, "operator deleted");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// Change operator password (admin or self)
#[utoipa::path(
    put,
    path = "/v1/operators/{id}/password",
    tag = "operators",
    params(
        ("id" = Uuid, Path, description = "Operator ID")
    ),
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "Password changed"),
        (status = 400, description = "Invalid password"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Operator not found")
    )
)]
pub async fn change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    auth_session: crate::auth::AuthSession,
    Path(id): Path<Uuid>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<StatusCode, StatusCode> {
    use crate::api::auth::require_role;
    use crate::domain::OperatorRole;
    use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

    let auth_header = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());

    // Allow self or admin to change password
    let caller = require_role(&state, &auth_session, auth_header, OperatorRole::Viewer)?;

    let is_self = caller.operator_id == id;
    let is_admin = caller.role == OperatorRole::Admin;

    if !is_self && !is_admin {
        return Err(StatusCode::FORBIDDEN);
    }

    // Validate password length
    if req.new_password.len() < 8 || req.new_password.len() > MAX_PASSWORD_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check operator exists
    let target = state
        .repo
        .get_operator_by_id(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(if is_self {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::NOT_FOUND
        })?;

    // Verify current password (required for self-change, skipped for admin reset of other users)
    if is_self {
        let parsed_hash = match PasswordHash::new(&target.password_hash) {
            Ok(h) => h,
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        };
        if Argon2::default()
            .verify_password(req.current_password.as_bytes(), &parsed_hash)
            .is_err()
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Hash new password
    let password_hash = Argon2::default()
        .hash_password(req.new_password.as_bytes())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    state
        .repo
        .update_operator_password(id, &password_hash)
        .await
        .map_err(|e| {
            tracing::error!(target: "prefixd::api::handlers", error = %e, "change_password failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!(target: "prefixd::api::handlers",
        operator_id = %id,
        username = %target.username,
        changed_by = %caller.username,
        "password changed"
    );

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Notification preferences
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/v1/preferences",
    responses(
        (status = 200, description = "Notification preferences", body = NotificationPreferences),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "preferences"
)]
pub async fn get_notification_preferences(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
) -> Result<Json<NotificationPreferences>, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    let operator = require_role(
        &state,
        &auth_session,
        auth_header,
        crate::domain::OperatorRole::Viewer,
    )?;

    let prefs = state
        .repo
        .get_notification_preferences(operator.operator_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or_default();

    Ok(Json(prefs))
}

#[utoipa::path(
    put,
    path = "/v1/preferences",
    request_body = NotificationPreferences,
    responses(
        (status = 200, description = "Preferences updated"),
        (status = 400, description = "Invalid preferences"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "preferences"
)]
pub async fn update_notification_preferences(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
    Json(prefs): Json<NotificationPreferences>,
) -> Result<StatusCode, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    let operator = require_role(
        &state,
        &auth_session,
        auth_header,
        crate::domain::OperatorRole::Viewer,
    )?;

    match (prefs.quiet_hours_start, prefs.quiet_hours_end) {
        (Some(_), None) | (None, Some(_)) => return Err(StatusCode::BAD_REQUEST),
        _ => {}
    }
    if let Some(start) = prefs.quiet_hours_start {
        if !(0..=23).contains(&start) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    if let Some(end) = prefs.quiet_hours_end {
        if !(0..=23).contains(&end) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    for evt in &prefs.muted_events {
        if !crate::alerting::AlertEventType::ALL_STRINGS.contains(&evt.as_str()) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    state
        .repo
        .upsert_notification_preferences(operator.operator_id, &prefs)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_is_valid_username() {
        assert!(super::is_valid_username("alice_1"));
        assert!(super::is_valid_username("ops-admin"));
        assert!(!super::is_valid_username(""));
        assert!(!super::is_valid_username("bad space"));
        assert!(!super::is_valid_username("no/slash"));
    }

    #[tokio::test]
    async fn test_login_throttle_blocks_after_limit() {
        let user = "throttle_test_user";
        super::clear_login_attempts(user).await;

        for _ in 0..super::LOGIN_MAX_ATTEMPTS {
            assert!(super::check_and_record_login_attempt(user).await.is_ok());
        }

        let blocked = super::check_and_record_login_attempt(user).await;
        assert_eq!(blocked, Err(axum::http::StatusCode::TOO_MANY_REQUESTS));

        super::clear_login_attempts(user).await;
    }
}
