use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::config::AuthMode;
use crate::AppState;

/// Bearer token authentication middleware
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    match state.settings.http.auth.mode {
        AuthMode::None => Ok(next.run(request).await),
        AuthMode::Bearer => validate_bearer_token(&state, request, next).await,
        AuthMode::Mtls => {
            // mTLS is handled at the transport layer, not here
            // If we reach this point with mTLS configured, connection was already validated
            Ok(next.run(request).await)
        }
    }
}

async fn validate_bearer_token(
    state: &AppState,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get expected token from environment variable
    let token_env_var = state
        .settings
        .http
        .auth
        .bearer_token_env
        .as_deref()
        .unwrap_or("PREFIXD_API_TOKEN");

    let expected_token = match std::env::var(token_env_var) {
        Ok(token) if !token.is_empty() => token,
        _ => {
            tracing::error!(
                env_var = token_env_var,
                "bearer auth enabled but token env var not set"
            );
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());

    let provided_token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => &header[7..],
        _ => {
            tracing::warn!("missing or invalid Authorization header");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Constant-time comparison to prevent timing attacks
    if !constant_time_eq(provided_token.as_bytes(), expected_token.as_bytes()) {
        tracing::warn!("invalid bearer token");
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
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
