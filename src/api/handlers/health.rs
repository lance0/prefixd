use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
};
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

use crate::AppState;
use crate::api::auth::require_auth;
use crate::auth::AuthSession;

#[derive(Serialize, ToSchema)]
pub struct PublicHealthResponse {
    /// Health status (healthy, degraded)
    status: String,
    /// Controller (prefixd) version
    version: String,
    /// Authentication mode (none, bearer, credentials, mtls)
    auth_mode: String,
}

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    /// Health status (healthy, degraded, standby)
    status: String,
    /// Controller (prefixd) version
    version: String,
    /// POP identifier
    pop: String,
    /// Seconds since the controller (prefixd) started
    uptime_seconds: u64,
    /// BGP session states by peer name
    bgp_sessions: std::collections::HashMap<String, String>,
    /// Number of active mitigations
    active_mitigations: u32,
    /// Database connectivity status
    database: String,
    /// Peer observation status (legacy field name)
    gobgp: ComponentHealth,
    /// Selected backend, capabilities and independent daemon observation
    speaker: SpeakerHealth,
    /// Authentication mode (none, bearer, credentials, mtls)
    auth_mode: String,
}

#[derive(Serialize, ToSchema)]
pub struct SpeakerHealth {
    backend: &'static str,
    capabilities: crate::bgp::SpeakerCapabilities,
    /// Enforced detector blackholes run without the rustbgpd injection lease, so
    /// they stay announced if prefixd stops while the speaker runs.
    detector_unleased: bool,
    daemon: DaemonHealthObservation,
}

#[derive(Serialize, ToSchema)]
pub struct DaemonHealthObservation {
    /// observed, error, or unsupported; independent of peer session state.
    status: String,
    version: Option<String>,
    uptime_seconds: Option<u64>,
    ready: Option<bool>,
    /// Controller receipt time after a successful authenticated speaker RPC.
    observed_at: Option<chrono::DateTime<chrono::Utc>>,
}

async fn observe_daemon_health(state: &AppState) -> DaemonHealthObservation {
    let Some(observer) = state.announcer.daemon_health_observer() else {
        return DaemonHealthObservation {
            status: "unsupported".into(),
            version: None,
            uptime_seconds: None,
            ready: None,
            observed_at: None,
        };
    };
    // Bound the added operational probe, including any adapter retries.
    match tokio::time::timeout(std::time::Duration::from_secs(2), observer.daemon_health()).await {
        Ok(Ok(health)) => DaemonHealthObservation {
            status: "observed".into(),
            version: health.version,
            uptime_seconds: Some(health.uptime_seconds),
            ready: Some(health.ready),
            observed_at: Some(chrono::Utc::now()),
        },
        _ => DaemonHealthObservation {
            status: "error".into(),
            version: None,
            uptime_seconds: None,
            ready: None,
            observed_at: None,
        },
    }
}

#[derive(Serialize, ToSchema)]
pub struct ComponentHealth {
    /// Component status (connected, error, unsupported)
    status: String,
    /// Error message if status is error
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Health check endpoint
fn resolve_auth_mode(state: &AppState) -> String {
    serde_json::to_value(state.settings.http.auth.mode)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| "unknown".to_string())
}

async fn check_health_status(
    state: &AppState,
) -> (
    String,
    std::collections::HashMap<String, String>,
    u32,
    String,
    ComponentHealth,
) {
    let observation = match state.announcer.peer_observer() {
        Some(observer) => Some(observer.session_status().await),
        None => None,
    };
    let (sessions, gobgp_health) = match observation {
        None => (
            vec![],
            ComponentHealth {
                status: "unsupported".into(),
                error: None,
            },
        ),
        Some(Ok(s)) => (
            s,
            ComponentHealth {
                status: "connected".to_string(),
                error: None,
            },
        ),
        Some(Err(e)) => (
            vec![],
            ComponentHealth {
                status: "error".to_string(),
                error: Some(e.to_string()),
            },
        ),
    };

    let (active, db_status, db_error) = match state.repo.count_active_global().await {
        Ok(count) => (count, "connected".to_string(), false),
        Err(e) => {
            tracing::warn!(error = %e, "database health check failed");
            (0, format!("error: {}", e), true)
        }
    };

    let bgp_map: std::collections::HashMap<_, _> = sessions
        .into_iter()
        .map(|s| (s.name, s.state.to_string()))
        .collect();

    let status = if db_error || gobgp_health.status == "error" {
        "degraded"
    } else {
        "healthy"
    };

    (status.to_string(), bgp_map, active, db_status, gobgp_health)
}

/// Public health endpoint: minimal info safe for unauthenticated access
#[utoipa::path(
    get,
    path = "/v1/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = PublicHealthResponse)
    )
)]
pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Lightweight liveness check: no DB or GoBGP calls.
    // Use /v1/health/detail for full operational status.
    Json(PublicHealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        auth_mode: resolve_auth_mode(&state),
    })
}

/// Readiness, in precedence order: standby, then draining, then ready.
#[derive(Serialize, ToSchema, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReadinessStatus {
    /// Another controller holds this POP's fence.
    Standby,
    /// Shutdown has begun; the fence stays held until the process exits.
    Draining,
    /// This controller holds the fence and accepts mutations.
    Ready,
}

#[derive(Serialize, ToSchema)]
pub struct ReadinessResponse {
    status: ReadinessStatus,
}

/// Public readiness: route detectors and load balancers only to the controller
/// holding this POP's fence (ADR 027) and not draining. Liveness stays on `/v1/health`.
#[utoipa::path(
    get,
    path = "/v1/ready",
    tag = "health",
    responses(
        (status = 200, description = "This controller holds its POP's fence and accepts mutations", body = ReadinessResponse),
        (status = 503, description = "Standby (another controller holds this POP's fence) or draining after a shutdown signal", body = ReadinessResponse)
    )
)]
pub async fn ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let status = if !state.fence.is_active() {
        ReadinessStatus::Standby
    } else if state.is_shutting_down() {
        ReadinessStatus::Draining
    } else {
        ReadinessStatus::Ready
    };
    let code = if status == ReadinessStatus::Ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(ReadinessResponse { status }))
}

/// Authenticated health detail: full operational status
#[utoipa::path(
    get,
    path = "/v1/health/detail",
    tag = "health",
    responses(
        (status = 200, description = "Detailed health status", body = HealthResponse)
    )
)]
pub async fn health_detail(
    State(state): State<Arc<AppState>>,
    auth_session: AuthSession,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());
    require_auth(&state, &auth_session, auth_header)?;

    let ((mut status, bgp_map, active, db_status, gobgp_health), daemon) =
        tokio::join!(check_health_status(&state), observe_daemon_health(&state));
    if daemon.status == "error" || daemon.ready == Some(false) {
        status = "degraded".into();
    }
    // Another controller holds this POP's fence; this one mutates nothing.
    if !state.fence.is_active() {
        status = "standby".into();
    }

    Ok(Json(HealthResponse {
        status,
        version: env!("CARGO_PKG_VERSION").to_string(),
        pop: state.settings.pop.clone(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
        bgp_sessions: bgp_map,
        active_mitigations: active,
        database: db_status,
        gobgp: gobgp_health,
        speaker: SpeakerHealth {
            backend: state.announcer.backend(),
            capabilities: state.announcer.capabilities(),
            detector_unleased: crate::guardrails::detector_unleased(
                &state.settings,
                state.announcer.capabilities().blackhole_lease,
            ),
            daemon,
        },
        auth_mode: resolve_auth_mode(&state),
    }))
}
