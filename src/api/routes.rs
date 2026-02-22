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

/// Public routes (no auth required)
fn public_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/health", get(handlers::health))
        .route("/v1/health/detail", get(handlers::health_detail))
        .route("/v1/auth/login", post(handlers::login))
        .route("/metrics", get(handlers::metrics))
        .route("/openapi.json", get(openapi_json))
}

/// Session-only routes (browser only, requires session cookie)
fn session_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/auth/logout", post(handlers::logout))
        .route("/v1/auth/me", get(handlers::get_me))
        .route("/v1/ws/feed", any(ws::ws_handler))
}

/// API routes - hybrid auth (session OR bearer) enforced via require_auth()
fn api_routes() -> Router<Arc<AppState>> {
    Router::new()
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
        .route("/v1/config/settings", get(handlers::get_config_settings))
        .route("/v1/config/inventory", get(handlers::get_config_inventory))
        .route(
            "/v1/config/playbooks",
            get(handlers::get_config_playbooks).put(handlers::update_playbooks),
        )
        .route("/v1/stats", get(handlers::get_stats))
        .route("/v1/stats/timeseries", get(handlers::get_timeseries))
        .route("/v1/ip/{ip}/history", get(handlers::get_ip_history))
        .route("/v1/pops", get(handlers::list_pops))
        .route("/v1/audit", get(handlers::list_audit))
        .route(
            "/v1/operators",
            get(handlers::list_operators).post(handlers::create_operator),
        )
        .route(
            "/v1/operators/{id}",
            axum::routing::delete(handlers::delete_operator),
        )
        .route(
            "/v1/operators/{id}/password",
            axum::routing::put(handlers::change_password),
        )
        .route(
            "/v1/config/alerting",
            get(handlers::get_alerting_config).put(handlers::update_alerting_config),
        )
        .route("/v1/config/alerting/test", post(handlers::test_alerting))
}

/// Common layers applied to both production and test routers
fn common_layers(router: Router) -> Router {
    router
        .layer(axum::middleware::from_fn(super::request_id::request_id))
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

/// Create the production router with PostgreSQL session store
pub fn create_router(
    state: Arc<AppState>,
    auth_layer: AuthManagerLayer<AuthBackend, PostgresStore>,
) -> Router {
    let router = public_routes()
        .merge(session_routes())
        .merge(api_routes())
        .layer(auth_layer)
        .with_state(state.clone());

    common_layers(router).layer(if let Some(ref origin) = state.settings.http.cors_origin {
        CorsLayer::new()
            .allow_origin(origin.parse::<HeaderValue>().expect("invalid cors_origin"))
            .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::COOKIE])
            .allow_credentials(true)
    } else {
        CorsLayer::new()
    })
}

async fn openapi_json() -> impl IntoResponse {
    Json(ApiDoc::openapi())
}

/// Create a router for testing with in-memory session store
pub fn create_test_router(state: Arc<AppState>) -> Router {
    use tower_sessions::MemoryStore;

    let session_store = MemoryStore::default();
    let session_layer = tower_sessions::SessionManagerLayer::new(session_store).with_secure(false);
    let backend = crate::auth::AuthBackend::new(state.repo.clone());
    let auth_layer = axum_login::AuthManagerLayerBuilder::new(backend, session_layer).build();

    let router = public_routes()
        .merge(session_routes())
        .merge(api_routes())
        .layer(auth_layer)
        .with_state(state.clone());

    common_layers(router)
}
