use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::config::AuthMode;
use crate::AppState;

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

    // Check session cookie first (browser/dashboard)
    if auth_session.user.is_some() {
        return Ok(());
    }

    // Fall back to bearer token (CLI/detectors)
    if let Some(header_str) = auth_header {
        if header_str.starts_with("Bearer ") {
            let provided_token = &header_str[7..];
            if let Some(ref expected_token) = state.bearer_token {
                if constant_time_eq(provided_token.as_bytes(), expected_token.as_bytes()) {
                    return Ok(());
                }
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Bearer token authentication middleware (legacy, for CLI/detectors only)
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

/// Bearer token authentication middleware for API routes
/// Session-based auth is used only for WebSocket and /v1/auth/* endpoints
pub async fn hybrid_auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // If auth is disabled, allow all
    if matches!(state.settings.http.auth.mode, AuthMode::None) {
        return Ok(next.run(request).await);
    }

    // Check bearer token (CLI/detectors)
    if let Some(auth_header) = request.headers().get(header::AUTHORIZATION) {
        if let Ok(header_str) = auth_header.to_str() {
            if header_str.starts_with("Bearer ") {
                return validate_bearer_token(&state, request, next).await;
            }
        }
    }
    
    tracing::debug!("no valid session or bearer token");
    Err(StatusCode::UNAUTHORIZED)
}

async fn validate_bearer_token(
    state: &AppState,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Use cached token from startup (avoids per-request env lookups)
    let expected_token = match &state.bearer_token {
        Some(token) => token.as_str(),
        None => {
            // Token was not loaded at startup - this is a configuration error
            tracing::error!("bearer auth enabled but no token was loaded at startup");
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
