use axum::http::StatusCode;

use crate::AppState;
use crate::config::AuthMode;
use crate::domain::{Operator, OperatorRole};

use crate::auth::AuthSession;

/// Check if request is authenticated via session cookie or bearer token (hybrid auth)
/// Returns Ok(()) if authenticated, Err(StatusCode) if not
/// When auth mode is None, always returns Ok
pub fn require_auth(
    state: &AppState,
    auth_session: &AuthSession,
    auth_header: Option<&str>,
) -> Result<(), StatusCode> {
    // If auth is disabled, allow all
    if matches!(state.settings.http.auth.mode, AuthMode::None) {
        return Ok(());
    }

    // mTLS is validated at transport layer - if request reached here, client is authenticated
    if matches!(state.settings.http.auth.mode, AuthMode::Mtls) {
        return Ok(());
    }

    // Session-based auth (Credentials mode or hybrid)
    if auth_session.user.is_some() {
        return Ok(());
    }

    // Credentials mode requires session auth only (no bearer fallback)
    if matches!(state.settings.http.auth.mode, AuthMode::Credentials) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Fall back to bearer token (CLI/detectors) for Bearer mode
    if let Some(header_str) = auth_header {
        if let Some(provided_token) = header_str.strip_prefix("Bearer ") {
            if let Some(ref expected_token) = state.bearer_token {
                if constant_time_eq(provided_token.as_bytes(), expected_token.as_bytes()) {
                    return Ok(());
                }
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Check if the authenticated user has the required role
/// Returns the operator if authorized, or UNAUTHORIZED/FORBIDDEN status
/// When auth mode is None, returns a synthetic admin operator
pub fn require_role(
    state: &AppState,
    auth_session: &AuthSession,
    auth_header: Option<&str>,
    required_role: OperatorRole,
) -> Result<Operator, StatusCode> {
    // If auth is disabled, return synthetic admin
    if matches!(state.settings.http.auth.mode, AuthMode::None) {
        return Ok(Operator {
            operator_id: uuid::Uuid::nil(),
            username: "anonymous".to_string(),
            password_hash: String::new(),
            role: OperatorRole::Admin,
            created_at: chrono::Utc::now(),
            created_by: None,
            last_login_at: None,
        });
    }

    // mTLS users get admin privileges (certificate-based trust)
    if matches!(state.settings.http.auth.mode, AuthMode::Mtls) {
        return Ok(Operator {
            operator_id: uuid::Uuid::nil(),
            username: "mtls-client".to_string(),
            password_hash: String::new(),
            role: OperatorRole::Admin,
            created_at: chrono::Utc::now(),
            created_by: None,
            last_login_at: None,
        });
    }

    // Check session cookie first (browser/dashboard)
    if let Some(ref operator) = auth_session.user {
        if operator.role.has_permission(&required_role) {
            return Ok(operator.clone());
        } else {
            tracing::warn!(
                username = %operator.username,
                role = %operator.role,
                required = %required_role,
                "insufficient permissions"
            );
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // Bearer token gets operator-level access (can view and withdraw, but not admin)
    if let Some(header_str) = auth_header {
        if let Some(provided_token) = header_str.strip_prefix("Bearer ") {
            if let Some(ref expected_token) = state.bearer_token {
                if constant_time_eq(provided_token.as_bytes(), expected_token.as_bytes()) {
                    // Bearer tokens get operator role (can withdraw but not manage users/safelist)
                    let bearer_role = OperatorRole::Operator;
                    if bearer_role.has_permission(&required_role) {
                        return Ok(Operator {
                            operator_id: uuid::Uuid::nil(),
                            username: "bearer-token".to_string(),
                            password_hash: String::new(),
                            role: bearer_role,
                            created_at: chrono::Utc::now(),
                            created_by: None,
                            last_login_at: None,
                        });
                    } else {
                        tracing::warn!(
                            role = %bearer_role,
                            required = %required_role,
                            "bearer token has insufficient permissions"
                        );
                        return Err(StatusCode::FORBIDDEN);
                    }
                }
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }
}
