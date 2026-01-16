use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use std::sync::Arc;

use super::{auth::auth_middleware, handlers};
use crate::AppState;

pub fn create_router(state: Arc<AppState>) -> Router {
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/v1/health", get(handlers::health))
        .route("/metrics", get(handlers::metrics));

    // Protected routes (auth required)
    // Rate limiting is handled at the handler level via AppState
    let protected_routes = Router::new()
        .route("/v1/events", post(handlers::ingest_event))
        .route("/v1/mitigations", get(handlers::list_mitigations))
        .route("/v1/mitigations", post(handlers::create_mitigation))
        .route("/v1/mitigations/{id}", get(handlers::get_mitigation))
        .route(
            "/v1/mitigations/{id}/withdraw",
            post(handlers::withdraw_mitigation),
        )
        .route("/v1/safelist", get(handlers::list_safelist))
        .route("/v1/safelist", post(handlers::add_safelist))
        .route("/v1/safelist/{prefix}", axum::routing::delete(handlers::remove_safelist))
        .route("/v1/config/reload", post(handlers::reload_config))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    public_routes
        .merge(protected_routes)
        .with_state(state)
}
