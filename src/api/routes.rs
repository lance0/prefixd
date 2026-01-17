use axum::{
    http::{header, HeaderValue},
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use utoipa::OpenApi;

use super::{auth::auth_middleware, handlers, openapi::ApiDoc};
use crate::AppState;

pub fn create_router(state: Arc<AppState>) -> Router {
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/v1/health", get(handlers::health))
        .route("/metrics", get(handlers::metrics))
        .route("/openapi.json", get(openapi_json));

    // Protected routes (auth required)
    // Rate limiting is handled at the handler level via AppState
    let protected_routes = Router::new()
        .route("/v1/events", get(handlers::list_events).post(handlers::ingest_event))
        .route("/v1/mitigations", get(handlers::list_mitigations).post(handlers::create_mitigation))
        .route("/v1/mitigations/{id}", get(handlers::get_mitigation))
        .route("/v1/mitigations/{id}/withdraw", post(handlers::withdraw_mitigation))
        .route("/v1/safelist", get(handlers::list_safelist).post(handlers::add_safelist))
        .route("/v1/safelist/{prefix}", axum::routing::delete(handlers::remove_safelist))
        .route("/v1/config/reload", post(handlers::reload_config))
        // Multi-POP coordination
        .route("/v1/stats", get(handlers::get_stats))
        .route("/v1/pops", get(handlers::list_pops))
        // Audit log
        .route("/v1/audit", get(handlers::list_audit))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    public_routes
        .merge(protected_routes)
        .with_state(state)
        // HTTP metrics (outermost layer to capture all requests)
        .layer(middleware::from_fn(super::metrics::http_metrics))
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
}

async fn openapi_json() -> impl IntoResponse {
    Json(ApiDoc::openapi())
}
