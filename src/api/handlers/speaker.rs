use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

use crate::AppState;
use crate::api::auth::AuthPrincipal;
use crate::api::auth::require_auth;
use crate::domain::FlowSpecRule;

use super::ErrorResponse;

/// Local observation only; none of these views proves export or enforcement.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FlowSpecObservationScope {
    RetainedLocalFlowSpecIntent,
    AcceptedLocalFlowSpecRib,
    AdapterLocalFlowSpec,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SpeakerRoutesResponse {
    pub backend: String,
    pub observation_scope: FlowSpecObservationScope,
    /// Complete local FlowSpec inventory for both address families, not blackholes.
    pub routes: Vec<FlowSpecRule>,
}

/// Observe local FlowSpec rules without consulting controller intent or health.
#[utoipa::path(
    get,
    path = "/v1/speaker/routes",
    tag = "speaker",
    description = "Authenticated read-only local FlowSpec inventory. Uses the configured session, bearer or transport authentication, or permits access when authentication is disabled. Available in dry-run and standby. This is not the unicast/blackhole table, export or router enforcement.",
    responses(
        (status = 200, description = "Complete local FlowSpec observation, possibly empty", body = SpeakerRoutesResponse),
        (status = 401, description = "Authentication required"),
        (status = 501, description = "The speaker does not provide local FlowSpec observation", body = ErrorResponse),
        (status = 502, description = "Local FlowSpec observation failed; no inventory is returned", body = ErrorResponse)
    )
)]
pub async fn list_speaker_routes(
    State(state): State<Arc<AppState>>,
    principal: AuthPrincipal,
) -> Result<Response, StatusCode> {
    require_auth(&principal)?;

    let Some(reader) = state.announcer.reader() else {
        return Ok((
            StatusCode::NOT_IMPLEMENTED,
            Json(ErrorResponse {
                error: "Local FlowSpec observation is unsupported by this speaker".into(),
                retry_after_seconds: None,
            }),
        )
            .into_response());
    };
    let routes = match reader.list_active().await {
        Ok(routes) => routes,
        Err(_) => {
            tracing::warn!(
                backend = state.announcer.backend(),
                "local FlowSpec observation failed"
            );
            return Ok((
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    error: "Local FlowSpec observation failed; inventory is unavailable".into(),
                    retry_after_seconds: None,
                }),
            )
                .into_response());
        }
    };
    let backend = state.announcer.backend();
    let observation_scope = match backend {
        "rustbgpd" => FlowSpecObservationScope::RetainedLocalFlowSpecIntent,
        "gobgp" => FlowSpecObservationScope::AcceptedLocalFlowSpecRib,
        _ => FlowSpecObservationScope::AdapterLocalFlowSpec,
    };
    Ok(Json(SpeakerRoutesResponse {
        backend: backend.into(),
        observation_scope,
        routes,
    })
    .into_response())
}
