use axum::{
    Json, Router,
    http::{HeaderValue, Method, header},
    response::IntoResponse,
    routing::{any, get, post},
};
use axum_login::AuthManagerLayer;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_sessions_sqlx_store::PostgresStore;
use utoipa::OpenApi;

use super::{handlers, openapi::ApiDoc};
use crate::AppState;
use crate::auth::AuthBackend;
use crate::ws;

/// Create the router with auth layer
pub fn create_router(
    state: Arc<AppState>,
    auth_layer: AuthManagerLayer<AuthBackend, PostgresStore>,
) -> Router {
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/v1/health", get(handlers::health))
        .route("/v1/auth/login", post(handlers::login))
        .route("/metrics", get(handlers::metrics))
        .route("/openapi.json", get(openapi_json));

    // Session-only routes (browser only, requires session cookie)
    let session_routes = Router::new()
        .route("/v1/auth/logout", post(handlers::logout))
        .route("/v1/auth/me", get(handlers::get_me))
        .route("/v1/ws/feed", any(ws::ws_handler));

    // API routes - hybrid auth (session OR bearer) enforced via require_auth()
    // Browser dashboard uses session cookies, CLI/detectors use bearer tokens
    let api_routes = Router::new()
        .route(
            "/v1/events",
            get(handlers::list_events).post(handlers::ingest_event),
        )
        .route(
            "/v1/mitigations",
            get(handlers::list_mitigations).post(handlers::create_mitigation),
        )
        .route("/v1/mitigations/{id}", get(handlers::get_mitigation))
        .route(
            "/v1/mitigations/{id}/withdraw",
            post(handlers::withdraw_mitigation),
        )
        .route(
            "/v1/safelist",
            get(handlers::list_safelist).post(handlers::add_safelist),
        )
        .route(
            "/v1/safelist/{prefix}",
            axum::routing::delete(handlers::remove_safelist),
        )
        .route("/v1/config/reload", post(handlers::reload_config))
        .route("/v1/stats", get(handlers::get_stats))
        .route("/v1/pops", get(handlers::list_pops))
        .route("/v1/audit", get(handlers::list_audit));

    // Build router - auth layer provides AuthSession for all routes
    // Auth checking is done in individual handlers via require_auth() helper
    public_routes
        .merge(session_routes)
        .merge(api_routes)
        .layer(auth_layer)
        .with_state(state.clone())
        // HTTP metrics (outermost layer to capture all requests)
        .layer(axum::middleware::from_fn(super::metrics::http_metrics))
        // Security headers
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        // Request body size limit (1MB)
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        // CORS for dashboard
        .layer(
            CorsLayer::new()
                .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap())
                .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::COOKIE])
                .allow_credentials(true),
        )
}

async fn openapi_json() -> impl IntoResponse {
    Json(ApiDoc::openapi())
}

/// Create a router for testing without session management
/// Uses MemoryStore for session backend - suitable for unit tests
#[cfg(any(test, feature = "test-utils"))]
pub fn create_test_router(state: Arc<AppState>) -> Router {
    use tower_sessions::MemoryStore;

    let session_store = MemoryStore::default();
    let session_layer = tower_sessions::SessionManagerLayer::new(session_store).with_secure(false);
    let backend = crate::auth::AuthBackend::new(state.repo.clone());
    let auth_layer = axum_login::AuthManagerLayerBuilder::new(backend, session_layer).build();

    // Same routes structure as production but with MemoryStore
    let public_routes = Router::new()
        .route("/v1/health", get(handlers::health))
        .route("/v1/auth/login", post(handlers::login))
        .route("/metrics", get(handlers::metrics))
        .route("/openapi.json", get(openapi_json));

    let session_routes = Router::new()
        .route("/v1/auth/logout", post(handlers::logout))
        .route("/v1/auth/me", get(handlers::get_me))
        .route("/v1/ws/feed", any(ws::ws_handler));

    let api_routes = Router::new()
        .route(
            "/v1/events",
            get(handlers::list_events).post(handlers::ingest_event),
        )
        .route(
            "/v1/mitigations",
            get(handlers::list_mitigations).post(handlers::create_mitigation),
        )
        .route("/v1/mitigations/{id}", get(handlers::get_mitigation))
        .route(
            "/v1/mitigations/{id}/withdraw",
            post(handlers::withdraw_mitigation),
        )
        .route(
            "/v1/safelist",
            get(handlers::list_safelist).post(handlers::add_safelist),
        )
        .route(
            "/v1/safelist/{prefix}",
            axum::routing::delete(handlers::remove_safelist),
        )
        .route("/v1/config/reload", post(handlers::reload_config))
        .route("/v1/stats", get(handlers::get_stats))
        .route("/v1/pops", get(handlers::list_pops))
        .route("/v1/audit", get(handlers::list_audit));

    public_routes
        .merge(session_routes)
        .merge(api_routes)
        .layer(auth_layer)
        .with_state(state.clone())
        .layer(axum::middleware::from_fn(super::metrics::http_metrics))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
}
